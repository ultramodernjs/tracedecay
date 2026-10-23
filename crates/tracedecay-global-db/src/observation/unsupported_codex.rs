//! Explicit, bounded inspection of historical unsupported-only Codex records.
//! Opening a store and installing schema are deliberately the caller's concern:
//! a dry-run must use an already admitted read-only authority.

use serde::{Deserialize, Serialize};
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationIdV1, ObservationSourceCursorV1,
};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_store::{
    ObservationProjection, ObservationStoreError, PROVIDER_USAGE_PROJECTOR_VERSION,
    ProjectionSkipReason, ProjectionStoreError, SESSION_MESSAGE_PROJECTOR_VERSION,
    codex_observation_policy::unsupported_codex_record, derive_canonical_projection,
};

use super::bookkeeping::retire::{
    CaptureBudget, ObservationRetirementAuthorization, ObservationRetirementOutcome,
    ObservationRetirementPlan,
};
use crate::RegisteredGlobalDb;

const OPERATION: &str = "plan unsupported Codex cleanup";
const MAX_PAGE_SIZE: usize = 128;

type Result<T> = std::result::Result<T, UnsupportedCodexCleanupError>;

#[derive(Debug, thiserror::Error)]
pub enum UnsupportedCodexCleanupError {
    #[error(transparent)]
    Store(#[from] ObservationStoreError),
    #[error("unsupported Codex cleanup page size must be between 1 and 128")]
    InvalidPageSize,
    #[error("unsupported Codex cleanup plan or store identity changed; run dry-run again")]
    StalePlan,
    #[error(transparent)]
    Retirement(#[from] ProjectionStoreError),
    #[error("observation dependencies pin this cleanup batch; no records were changed")]
    RetirementDeferred,
    #[error(
        "classification budget/integrity preflight refused observation sequence {sequence}; reduce --page-size or inspect a single oversized observation offline; nothing changed: {source}"
    )]
    ClassificationPreflight {
        sequence: i64,
        #[source]
        source: ProjectionStoreError,
    },
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> UnsupportedCodexCleanupError {
    super::codec::storage(OPERATION, error).into()
}

fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(storage)?;
    Ok(sha256_hex(&bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedCodexCleanupCursor {
    pub store_digest: String,
    pub after_sequence: i64,
    pub high_water_sequence: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedCodexCleanupCandidate {
    pub sequence: i64,
    pub observation_id: String,
    pub payload_digest: String,
    /// Inline observation JSON only; shared bodies and journals are not exclusive bytes.
    pub stored_observation_bytes: u64,
    pub retained_reasons: Vec<String>,
}

/// An opaque reviewed page, including its exact dependency closure. JSON is a
/// review view, not an importable authorization: after a process restart, run
/// dry-run again and confirm its digest before applying the new page.
#[derive(Clone, Debug, Serialize)]
pub struct UnsupportedCodexCleanupPlan {
    pub cursor: UnsupportedCodexCleanupCursor,
    pub next_cursor: Option<UnsupportedCodexCleanupCursor>,
    pub examined: u64,
    /// Classification candidates; kernel blockers can still defer the entire batch.
    pub candidates: Vec<UnsupportedCodexCleanupCandidate>,
    retirement: Option<ObservationRetirementPlan>,
    pub plan_digest: String,
}

impl PartialEq for UnsupportedCodexCleanupPlan {
    fn eq(&self, other: &Self) -> bool {
        self.cursor == other.cursor
            && self.next_cursor == other.next_cursor
            && self.examined == other.examined
            && self.candidates == other.candidates
            && self
                .retirement
                .as_ref()
                .map(ObservationRetirementPlan::digest)
                == other
                    .retirement
                    .as_ref()
                    .map(ObservationRetirementPlan::digest)
            && self.plan_digest == other.plan_digest
    }
}

impl Eq for UnsupportedCodexCleanupPlan {}

impl UnsupportedCodexCleanupPlan {
    /// Logical cascade sizes and retained dependencies are available for review.
    pub fn retirement(&self) -> Option<&ObservationRetirementPlan> {
        self.retirement.as_ref()
    }

    fn digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.plan_digest.clear();
        digest(&("unsupported-codex-cleanup-v2", unsigned))
    }
}

impl RegisteredGlobalDb {
    /// Read at most one keyset page, without schema installation or marker writes.
    pub async fn plan_unsupported_codex_cleanup(
        &self,
        cursor: Option<&UnsupportedCodexCleanupCursor>,
        page_size: usize,
    ) -> Result<UnsupportedCodexCleanupPlan> {
        let snapshot = self.read_snapshot().await.map_err(storage)?;
        let mut plan = plan_page(
            &snapshot,
            digest(&self.retirement_store_identity())?,
            cursor,
            page_size,
        )
        .await?;
        drop(snapshot);
        // The kernel reads and bounds the closure; it never installs indexes.
        // Removing a pinned candidate may expose another shared-owner pin, so
        // repeat only while the explicit, at-most-128-ID selection shrinks.
        loop {
            let ids = plan
                .candidates
                .iter()
                .filter(|candidate| candidate.retained_reasons.is_empty())
                .map(|candidate| {
                    CanonicalObservationIdV1::new(candidate.observation_id.clone()).map_err(storage)
                })
                .collect::<Result<Vec<_>>>()?;
            if ids.is_empty() {
                break;
            }
            let retirement = self
                .plan_observation_retirement(
                    &ids,
                    ObservationRetirementAuthorization::UnsupportedCodexRecord,
                )
                .await?;
            for current in retirement.candidates() {
                let candidate = plan
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.observation_id == current.observation_id.as_str())
                    .ok_or(UnsupportedCodexCleanupError::StalePlan)?;
                if candidate.payload_digest != current.payload_digest {
                    return Err(UnsupportedCodexCleanupError::StalePlan);
                }
                candidate.retained_reasons.extend(
                    current
                        .blockers
                        .iter()
                        .map(|blocker| format!("dependency:{blocker:?}")),
                );
            }
            if retirement.eligible() {
                plan.retirement = Some(retirement);
                break;
            }
        }
        plan.plan_digest = plan.digest()?;
        Ok(plan)
    }

    /// Confirm the entire reviewed page, then let the kernel revalidate and
    /// commit its exact selected closure in its own registered transaction.
    /// The kernel checks completion before revalidation, making retries safe
    /// even though a committed page no longer exists in the observation table.
    pub async fn apply_unsupported_codex_cleanup(
        &self,
        plan: &UnsupportedCodexCleanupPlan,
        confirmed_digest: &str,
    ) -> Result<u64> {
        if confirmed_digest != plan.plan_digest
            || plan.plan_digest != plan.digest()?
            || plan.cursor.store_digest != digest(&self.retirement_store_identity())?
        {
            return Err(UnsupportedCodexCleanupError::StalePlan);
        }
        let Some(retirement) = plan.retirement() else {
            return Ok(0);
        };
        match self
            .apply_observation_retirement(retirement, retirement.digest())
            .await
        {
            Ok(ObservationRetirementOutcome::Applied { observations }) => Ok(observations as u64),
            Ok(ObservationRetirementOutcome::AlreadyApplied) => Ok(0),
            Ok(ObservationRetirementOutcome::Deferred) => {
                Err(UnsupportedCodexCleanupError::RetirementDeferred)
            }
            Err(ProjectionStoreError::ProvenanceCollision) => {
                Err(UnsupportedCodexCleanupError::StalePlan)
            }
            Err(error) => Err(error.into()),
        }
    }
}

async fn scalar(conn: &impl QueryExecutor, sql: &str) -> Result<i64> {
    let mut rows = conn.query(sql, ()).await.map_err(storage)?;
    rows.next()
        .await
        .map_err(storage)?
        .ok_or(UnsupportedCodexCleanupError::StalePlan)?
        .get::<i64>(0)
        .map_err(storage)
}

async fn plan_page(
    conn: &impl QueryExecutor,
    store_digest: String,
    cursor: Option<&UnsupportedCodexCleanupCursor>,
    page_size: usize,
) -> Result<UnsupportedCodexCleanupPlan> {
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(UnsupportedCodexCleanupError::InvalidPageSize);
    }
    let cursor = match cursor {
        Some(cursor)
            if cursor.store_digest == store_digest
                && cursor.after_sequence >= 0
                && cursor.high_water_sequence >= cursor.after_sequence =>
        {
            cursor.clone()
        }
        Some(_) => return Err(UnsupportedCodexCleanupError::StalePlan),
        None => UnsupportedCodexCleanupCursor {
            store_digest,
            after_sequence: 0,
            high_water_sequence: scalar(
                conn,
                "SELECT COALESCE(MAX(sequence), 0) FROM observations",
            )
            .await?,
        },
    };
    let mut rows = conn
        .query(
            "SELECT sequence, observation_id, payload_digest,
                length(CAST(observation_json AS BLOB))
         FROM observations WHERE sequence > ?1 AND sequence <= ?2
         ORDER BY sequence LIMIT ?3",
            params![
                cursor.after_sequence,
                cursor.high_water_sequence,
                page_size as i64
            ],
        )
        .await
        .map_err(storage)?;
    let mut page = Vec::new();
    let mut budget = CaptureBudget::default();
    while let Some(row) = rows.next().await.map_err(storage)? {
        let sequence = row.get::<i64>(0).map_err(storage)?;
        let bytes = row.get::<u64>(3).map_err(storage)?;
        budget.charge(1, bytes).map_err(|source| {
            UnsupportedCodexCleanupError::ClassificationPreflight { sequence, source }
        })?;
        page.push((
            sequence,
            row.get::<String>(1).map_err(storage)?,
            row.get::<String>(2).map_err(storage)?,
            bytes,
        ));
    }
    drop(rows);
    let mut global_pins = Vec::new();
    if scalar(
        conn,
        "SELECT EXISTS (SELECT 1 FROM observation_projection_rebuilds)",
    )
    .await?
        != 0
    {
        global_pins.push("projection_rebuild".to_owned());
    }
    // The kernel checks external journals and historical outputs with indexed
    // candidate-local lookups; neither may pin unrelated observations.
    let mut candidates = Vec::new();
    // Inline work for the entire keyset page was authorized above. Fetch one
    // JSON row at a time; authorize every canonical expansion before decoding.
    for (sequence, id, payload_digest, bytes) in &page {
        let mut rows = conn
            .query(
                "SELECT observation_json FROM observations WHERE sequence=?1 AND observation_id=?2",
                params![*sequence, id.as_str()],
            )
            .await
            .map_err(storage)?;
        let json: String = rows
            .next()
            .await
            .map_err(storage)?
            .ok_or(UnsupportedCodexCleanupError::StalePlan)?
            .get(0)
            .map_err(storage)?;
        drop(rows);
        budget
            .preflight_hydration(conn, &json)
            .await
            .map_err(
                |source| UnsupportedCodexCleanupError::ClassificationPreflight {
                    sequence: *sequence,
                    source,
                },
            )?;
        let observation = super::decode_observation_json(conn, &json, OPERATION).await?;
        let envelope: CanonicalObservationEnvelopeV1 =
            serde_json::from_value(observation.payload().clone()).map_err(storage)?;
        if !unsupported_codex_record(&envelope) {
            continue;
        }
        let mut retained_reasons = global_pins.clone();
        if derive_canonical_projection(&observation).map_err(storage)?
            != ObservationProjection::Skipped(ProjectionSkipReason::NonConversationalRecord)
        {
            retained_reasons.push("current_derivation".to_owned());
        }
        let mut rows = conn.query(
            "SELECT
                EXISTS (SELECT 1 FROM observation_projection_provenance WHERE projector_version = ?2 AND observation_id = ?1)
                OR EXISTS (SELECT 1 FROM observation_projection_aliases WHERE projector_version = ?2 AND observation_id = ?1)
                OR EXISTS (SELECT 1 FROM observation_workflow_facts WHERE projector_version = ?2 AND observation_id = ?1)
                OR EXISTS (SELECT 1 FROM observation_provider_usage WHERE projector_version = ?3 AND observation_id = ?1),
                EXISTS (SELECT 1 FROM remote_observation_events WHERE observation_id = ?1)",
            params![id.as_str(), SESSION_MESSAGE_PROJECTOR_VERSION, PROVIDER_USAGE_PROJECTOR_VERSION],
        ).await.map_err(storage)?;
        let row = rows
            .next()
            .await
            .map_err(storage)?
            .ok_or(UnsupportedCodexCleanupError::StalePlan)?;
        if row.get::<i64>(0).map_err(storage)? != 0 {
            retained_reasons.push("projection_output".to_owned());
        }
        if row.get::<i64>(1).map_err(storage)? != 0 {
            retained_reasons.push("remote_consumer".to_owned());
        }
        drop(rows);
        let mut rows = conn
            .query(
                "SELECT cursor_json FROM source_cursors WHERE source_json = ?1 AND scope_json = ?2",
                params![
                    serde_json::to_string(observation.source()).map_err(storage)?,
                    serde_json::to_string(observation.scope()).map_err(storage)?
                ],
            )
            .await
            .map_err(storage)?;
        if let Some(row) = rows.next().await.map_err(storage)? {
            let current: ObservationSourceCursorV1 =
                serde_json::from_str(&row.get::<String>(0).map_err(storage)?).map_err(storage)?;
            if current.generation() == observation.identity().generation()
                && current.ordering_domain() == observation.identity().ordering_domain()
                && current.position() == observation.identity().position().end()
            {
                retained_reasons.push("source_frontier".to_owned());
            }
        }
        candidates.push(UnsupportedCodexCleanupCandidate {
            sequence: *sequence,
            observation_id: id.clone(),
            payload_digest: payload_digest.clone(),
            stored_observation_bytes: *bytes,
            retained_reasons,
        });
    }
    let after_sequence = page.last().map_or(cursor.high_water_sequence, |row| row.0);
    let next_cursor =
        (after_sequence < cursor.high_water_sequence).then(|| UnsupportedCodexCleanupCursor {
            after_sequence,
            ..cursor.clone()
        });
    Ok(UnsupportedCodexCleanupPlan {
        cursor,
        next_cursor,
        examined: page.len() as u64,
        candidates,
        retirement: None,
        plan_digest: String::new(),
    })
}

#[cfg(test)]
mod tests;
