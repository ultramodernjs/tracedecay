//! Retires the records a rewritten file-byte source no longer offers.
//!
//! Admission records where each record sits in the newest layout that offered
//! it. A rewrite keeps the byte prefix it retained and re-offers the rest under
//! a new generation; once that generation has been read to the end of the
//! file, every record it did not offer again is retired from projection.

use std::future::Future;
use std::pin::Pin;

use tracedecay_domain::{
    CanonicalObservationIdV1, ObservationScopeV1, ObservationSourceGenerationV1,
    ObservationSourceIdentityV1,
};
use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};
use tracedecay_store::{ProjectionStoreError, ProjectionStoreResult};

use super::RegisteredGlobalDb;
use super::observation::bookkeeping::source_keys::SourceKey;
use super::observation_projection::retire_source_record;
use super::registered::JobExit;

/// Unoffered-record reads are keyset-paginated at this page size. The exact-
/// SQL engine refuses a query that materializes more rows than its hard cap,
/// and one long host session can hold more unoffered records than that cap,
/// which made rewrite completion fail deterministically for those sources.
const UNOFFERED_RECORD_PAGE_SIZE: i64 = 1_000;

/// One record a source layout offered, under the identity admission derived.
pub struct ObservationSourcePresenceV1 {
    pub observation_id: CanonicalObservationIdV1,
    pub generation: ObservationSourceGenerationV1,
    pub start_offset: u64,
}

fn storage(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> ProjectionStoreError {
    ProjectionStoreError::storage(operation, error)
}

fn offset(value: u64) -> ProjectionStoreResult<i64> {
    i64::try_from(value).map_err(|_| ProjectionStoreError::SequenceOverflow(value))
}

async fn pending_rewrite(
    conn: &impl QueryExecutor,
    key: &SourceKey,
) -> ProjectionStoreResult<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT DISTINCT generation FROM observation_source_rewrites WHERE source_key IN (?1, ?2)",
            params![key.compact.as_str(), key.legacy.as_str()],
        )
        .await
        .map_err(|error| storage("read pending source rewrite", error))?;
    let generation = rows
        .next()
        .await
        .map_err(|error| storage("read pending source rewrite", error))?
        .map(|row| {
            row.get::<String>(0)
                .map_err(|error| storage("read pending source rewrite", error))
        })
        .transpose()?;
    if rows
        .next()
        .await
        .map_err(|error| storage("read pending source rewrite", error))?
        .is_some()
    {
        return Err(ProjectionStoreError::ProvenanceCollision);
    }
    Ok(generation)
}

const UNOFFERED_SOURCE_RECORD_PAGE_SQL: &str =
    "SELECT observation_id FROM observation_source_presence
     WHERE source_key = ?1 AND generation <> ?2 AND observation_id > ?3
     ORDER BY observation_id LIMIT ?4";

async fn unoffered_source_record_page(
    conn: &impl QueryExecutor,
    key: &SourceKey,
    generation: &str,
    after_observation_id: &str,
) -> ProjectionStoreResult<Vec<String>> {
    // Each encoding streams its primary-key order and materializes at most one
    // page. A DISTINCT across IN keys sorts the entire remaining source on
    // every page, including stores that use only the new encoding.
    let mut page = std::collections::BTreeSet::new();
    for source_key in [&key.compact, &key.legacy] {
        let mut rows = conn
            .query(
                UNOFFERED_SOURCE_RECORD_PAGE_SQL,
                params![
                    source_key.compact.as_str(),
                    generation,
                    after_observation_id,
                    UNOFFERED_RECORD_PAGE_SIZE
                ],
            )
            .await
            .map_err(|error| storage("read unoffered source records", error))?;
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| storage("read unoffered source records", error))?
        {
            page.insert(
                row.get::<String>(0)
                    .map_err(|error| storage("read unoffered source records", error))?,
            );
        }
    }
    Ok(page
        .into_iter()
        .take(UNOFFERED_RECORD_PAGE_SIZE as usize)
        .collect())
}

impl RegisteredGlobalDb {
    /// Records that the source's current layout offers `records`.
    #[tracing::instrument(
        name = "global_db.registered.source_presence.persist",
        level = "trace",
        skip_all
    )]
    pub async fn record_observation_source_presence(
        &self,
        source: &ObservationSourceIdentityV1,
        scope: &ObservationScopeV1,
        records: &[ObservationSourcePresenceV1],
    ) -> ProjectionStoreResult<()> {
        if records.is_empty() {
            return Ok(());
        }
        let key = SourceKey::new(source, scope)?;
        let rows = records
            .iter()
            .map(|record| {
                Ok((
                    record.observation_id.as_str().to_owned(),
                    record.generation.generation_id().to_string(),
                    offset(record.start_offset)?,
                ))
            })
            .collect::<ProjectionStoreResult<Vec<_>>>()?;
        self.transact_or(
            |error| storage("run source presence transaction", error),
            async move |transaction| {
                key.ensure_descriptor(&transaction).await?;
                for (observation_id, generation, start_offset) in &rows {
                    transaction
                        .execute(
                            "INSERT INTO observation_source_presence (
                                source_key, observation_id, generation, start_offset
                             ) VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(source_key, observation_id) DO UPDATE SET
                                generation = excluded.generation,
                                start_offset = excluded.start_offset",
                            params![
                                key.compact.as_str(),
                                observation_id.as_str(),
                                generation.as_str(),
                                *start_offset,
                            ],
                        )
                        .await
                        .map_err(|error| storage("record source presence", error))?;
                    transaction.execute(
                        "DELETE FROM observation_source_presence WHERE source_key = ?1 AND observation_id = ?2",
                        params![key.legacy.as_str(), observation_id.as_str()],
                    ).await.map_err(|error| storage("settle legacy source presence", error))?;
                }
                Ok(())
            },
        )
        .await
    }

    /// Starts a rewrite of the source from `previous` to `generation`. The
    /// bytes before `retained_through` are the previous layout's, so the
    /// records there stay offered; every other record must be offered again
    /// before the rewrite completes.
    #[tracing::instrument(
        name = "global_db.registered.source_rewrite.begin",
        level = "trace",
        skip_all
    )]
    pub async fn begin_observation_source_rewrite(
        &self,
        source: &ObservationSourceIdentityV1,
        scope: &ObservationScopeV1,
        previous: ObservationSourceGenerationV1,
        generation: ObservationSourceGenerationV1,
        retained_through: u64,
    ) -> ProjectionStoreResult<()> {
        if previous == generation {
            return Ok(());
        }
        let key = SourceKey::new(source, scope)?;
        let generation = generation.generation_id().to_string();
        let retained_through = offset(retained_through)?;
        let previous = previous.generation_id().to_string();
        self.transact_or(
            |error| storage("run source rewrite transaction", error),
            async move |transaction| {
                key.ensure_descriptor(&transaction).await?;
                // A rewrite the previous generation never finished still names its
                // own layout: its retained prefix was relabeled to it.
                let unfinished = pending_rewrite(&transaction, &key).await?;
                transaction
                    .execute(
                        "UPDATE observation_source_presence SET generation = ?2
                         WHERE source_key IN (?1, ?6) AND start_offset < ?3
                           AND generation IN (?4, ?5)",
                        params![
                            key.compact.as_str(),
                            generation.as_str(),
                            retained_through,
                            previous.as_str(),
                            unfinished.as_deref(),
                            key.legacy.as_str(),
                        ],
                    )
                    .await
                    .map_err(|error| storage("retain source prefix", error))?;
                transaction
                    .execute(
                        "INSERT INTO observation_source_rewrites (
                            source_key, generation, retained_through
                         ) VALUES (?1, ?2, ?3)
                         ON CONFLICT(source_key) DO UPDATE SET
                            generation = excluded.generation,
                            retained_through = excluded.retained_through",
                        params![key.compact.as_str(), generation.as_str(), retained_through],
                    )
                    .await
                    .map_err(|error| storage("record source rewrite", error))?;
                transaction
                    .execute("DELETE FROM observation_source_rewrites WHERE source_key = ?1", params![key.legacy.as_str()])
                    .await
                    .map_err(|error| storage("settle legacy source rewrite", error))?;
                Ok(())
            },
        )
        .await
    }

    /// Completes a pending rewrite once `generation` was read to the end of
    /// the source, retiring every record it did not offer. Returns how many
    /// observations were retired.
    #[tracing::instrument(
        name = "global_db.registered.source_rewrite.complete",
        level = "trace",
        skip_all
    )]
    pub async fn complete_observation_source_rewrite(
        &self,
        source: &ObservationSourceIdentityV1,
        scope: &ObservationScopeV1,
        generation: ObservationSourceGenerationV1,
    ) -> ProjectionStoreResult<u64> {
        let key = SourceKey::new(source, scope)?;
        let generation = generation.generation_id().to_string();
        let snapshot = self
            .read_snapshot()
            .await
            .map_err(|error| storage("read pending source rewrite", error))?;
        if pending_rewrite(&snapshot, &key).await?.as_deref() != Some(generation.as_str()) {
            return Ok(0);
        }
        drop(snapshot);
        self.transact_or_rollback(
            |error| storage("run source rewrite completion", error),
            async move |transaction| {
                if pending_rewrite(&transaction, &key).await?.as_deref()
                    != Some(generation.as_str())
                {
                    return Err(JobExit::Rollback(0));
                }
                let mut retired = 0_u64;
                // Keyset-paginate the unoffered ids instead of materializing the whole
                // set in one statement: a single rewritten source can hold more
                // unoffered records than the engine's per-query materialization cap,
                // and one oversized read wedged every completion attempt forever.
                // `retire_source_record` never touches `observation_source_presence`,
                // so the ordered id cursor stays stable across pages; the settle
                // deletes below remain the authoritative cleanup.
                let mut after_observation_id = String::new();
                loop {
                    let page = unoffered_source_record_page(
                        &transaction,
                        &key,
                        generation.as_str(),
                        &after_observation_id,
                    ).await?;
                    if page.is_empty() {
                        break;
                    }
                    let page_len = page.len();
                    after_observation_id = page[page_len - 1].clone();
                    for observation_id in &page {
                        let retired_one: Pin<
                            Box<dyn Future<Output = ProjectionStoreResult<bool>> + Send + '_>,
                        > = Box::pin(retire_source_record(&transaction, observation_id));
                        if retired_one.await? {
                            retired += 1;
                        }
                    }
                    if (page_len as i64) < UNOFFERED_RECORD_PAGE_SIZE {
                        break;
                    }
                }
                for sql in [
                    "DELETE FROM observation_source_presence WHERE source_key IN (?1, ?3) AND generation <> ?2",
                    "DELETE FROM observation_source_rewrites WHERE source_key IN (?1, ?3) AND generation = ?2",
                ] {
                    transaction
                        .execute(sql, params![key.compact.as_str(), generation.as_str(), key.legacy.as_str()])
                        .await
                        .map_err(|error| storage("settle source rewrite", error))?;
                }
                Ok(retired)
            },
        )
        .await
    }
}

#[cfg(test)]
#[path = "registered_source_rewrite_pagination_tests.rs"]
mod pagination_tests;
