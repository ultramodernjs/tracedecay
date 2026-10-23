//! Bounded lossless migration of legacy presence keys and pending rewrites.

use serde::Serialize;
use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1, canonical_sha256};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_store::{ProjectionStoreError, ProjectionStoreResult};

use super::source_keys::SourceKey;
use crate::RegisteredGlobalDb;

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> ProjectionStoreError {
    ProjectionStoreError::storage("compact observation source keys", error)
}

#[derive(Clone, Debug, Serialize)]
struct Presence {
    id: String,
    generation: String,
    offset: i64,
}

/// One read-only page plan for an exact source/scope. Re-plan after every
/// committed page; removed legacy keys make interrupted passes naturally resumable.
#[derive(Clone, Debug)]
pub struct SourceKeyCompactionPlan {
    source: ObservationSourceIdentityV1,
    scope: ObservationScopeV1,
    max_rows: usize,
    max_bytes: usize,
    rows: Vec<Presence>,
    rewrite: Option<(String, i64)>,
    has_more: bool,
    digest: String,
}

impl SourceKeyCompactionPlan {
    pub fn rows(&self) -> usize {
        self.rows.len()
    }
    pub fn has_more(&self) -> bool {
        self.has_more
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

async fn page(
    conn: &impl QueryExecutor,
    path: &str,
    source: &ObservationSourceIdentityV1,
    scope: &ObservationScopeV1,
    max_rows: usize,
    max_bytes: usize,
) -> ProjectionStoreResult<SourceKeyCompactionPlan> {
    if max_rows == 0 || max_bytes == 0 {
        return Err(ProjectionStoreError::ProvenanceCollision);
    }
    let max_rows = max_rows.min(1_000);
    let max_bytes = max_bytes.min(4 * 1024 * 1024);
    let key = SourceKey::new(source, scope)?;
    let mut source_rows = conn.query("SELECT observation_id, generation, start_offset FROM observation_source_presence WHERE source_key = ?1 ORDER BY observation_id LIMIT ?2", params![key.legacy.as_str(), max_rows as i64 + 1]).await.map_err(storage)?;
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    let mut has_more = false;
    while let Some(row) = source_rows.next().await.map_err(storage)? {
        let presence = Presence {
            id: row.get(0).map_err(storage)?,
            generation: row.get(1).map_err(storage)?,
            offset: row.get(2).map_err(storage)?,
        };
        let size = key.legacy.len() + presence.id.len() + presence.generation.len() + 8;
        if rows.len() == max_rows || (!rows.is_empty() && bytes.saturating_add(size) > max_bytes) {
            has_more = true;
            break;
        }
        if size > max_bytes {
            return Err(ProjectionStoreError::ProvenanceCollision);
        }
        bytes += size;
        rows.push(presence);
    }
    drop(source_rows);
    let mut rewrites = conn.query("SELECT generation, retained_through FROM observation_source_rewrites WHERE source_key = ?1", params![key.legacy.as_str()]).await.map_err(storage)?;
    let rewrite: Option<(String, i64)> = rewrites
        .next()
        .await
        .map_err(storage)?
        .map(|row| -> ProjectionStoreResult<(String, i64)> {
            Ok((row.get(0).map_err(storage)?, row.get(1).map_err(storage)?))
        })
        .transpose()?;
    drop(rewrites);
    let mut schema = conn
        .query("PRAGMA schema_version", ())
        .await
        .map_err(storage)?;
    let schema: i64 = schema
        .next()
        .await
        .map_err(storage)?
        .ok_or(ProjectionStoreError::ProvenanceCollision)?
        .get(0)
        .map_err(storage)?;
    let digest = canonical_sha256(&(
        "tracedecay.source-key-compaction.v1",
        path,
        schema,
        &key.legacy,
        &rows,
        &rewrite,
        max_rows,
        max_bytes,
        has_more,
    ))
    .map_err(storage)?
    .as_str()
    .to_owned();
    Ok(SourceKeyCompactionPlan {
        source: source.clone(),
        scope: scope.clone(),
        max_rows,
        max_bytes,
        rows,
        rewrite,
        has_more,
        digest,
    })
}

impl RegisteredGlobalDb {
    /// Does not mutate schema, descriptors, markers or presence. Bounds apply to
    /// one source's page, not an unbounded whole-store scan.
    pub async fn plan_source_key_compaction(
        &self,
        source: &ObservationSourceIdentityV1,
        scope: &ObservationScopeV1,
        max_rows: usize,
        max_bytes: usize,
    ) -> ProjectionStoreResult<SourceKeyCompactionPlan> {
        let snapshot = self.read_snapshot().await.map_err(storage)?;
        page(
            &snapshot,
            &self.db_path().to_string_lossy(),
            source,
            scope,
            max_rows,
            max_bytes,
        )
        .await
    }

    /// Revalidates the page inside registered writer authority before any mutation.
    /// Conflicting duplicate keys are refused, never resolved by overwriting evidence.
    pub async fn apply_source_key_compaction(
        &self,
        plan: &SourceKeyCompactionPlan,
        confirmed_digest: &str,
    ) -> ProjectionStoreResult<usize> {
        if confirmed_digest != plan.digest {
            return Err(ProjectionStoreError::ProvenanceCollision);
        }
        let transaction = self.begin_write_transaction().await.map_err(storage)?;
        let current = page(
            &transaction,
            &self.db_path().to_string_lossy(),
            &plan.source,
            &plan.scope,
            plan.max_rows,
            plan.max_bytes,
        )
        .await?;
        if current.digest != plan.digest {
            return Err(ProjectionStoreError::ProvenanceCollision);
        }
        let key = SourceKey::new(&plan.source, &plan.scope)?;
        key.ensure_descriptor(&transaction).await?;
        for row in &current.rows {
            transaction.execute("INSERT INTO observation_source_presence(source_key, observation_id, generation, start_offset) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(source_key, observation_id) DO NOTHING", params![key.compact.as_str(), row.id.as_str(), row.generation.as_str(), row.offset]).await.map_err(storage)?;
            let mut existing = transaction.query("SELECT generation, start_offset FROM observation_source_presence WHERE source_key = ?1 AND observation_id = ?2", params![key.compact.as_str(), row.id.as_str()]).await.map_err(storage)?;
            let stored = existing
                .next()
                .await
                .map_err(storage)?
                .ok_or(ProjectionStoreError::ProvenanceCollision)?;
            if stored.get::<String>(0).map_err(storage)? != row.generation
                || stored.get::<i64>(1).map_err(storage)? != row.offset
            {
                return Err(ProjectionStoreError::ProvenanceCollision);
            }
            drop(existing);
            transaction.execute("DELETE FROM observation_source_presence WHERE source_key = ?1 AND observation_id = ?2", params![key.legacy.as_str(), row.id.as_str()]).await.map_err(storage)?;
        }
        if let Some((generation, retained)) = &current.rewrite {
            transaction.execute("INSERT INTO observation_source_rewrites(source_key, generation, retained_through) VALUES (?1, ?2, ?3) ON CONFLICT(source_key) DO NOTHING", params![key.compact.as_str(), generation.as_str(), *retained]).await.map_err(storage)?;
            let mut rows = transaction.query("SELECT generation, retained_through FROM observation_source_rewrites WHERE source_key = ?1", params![key.compact.as_str()]).await.map_err(storage)?;
            let stored = rows
                .next()
                .await
                .map_err(storage)?
                .ok_or(ProjectionStoreError::ProvenanceCollision)?;
            if stored.get::<String>(0).map_err(storage)? != *generation
                || stored.get::<i64>(1).map_err(storage)? != *retained
            {
                return Err(ProjectionStoreError::ProvenanceCollision);
            }
            drop(rows);
            transaction
                .execute(
                    "DELETE FROM observation_source_rewrites WHERE source_key = ?1",
                    params![key.legacy.as_str()],
                )
                .await
                .map_err(storage)?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(current.rows.len())
    }
}
