//! Bounded expiry of internal startup receipts, separate from manual replay.
//!
//! Preview is read-only. Apply requires its digest, the existing admitted writer
//! and this daemon's project gate. An offline caller must first hold exclusive
//! profile maintenance authority; constructing another service is not a lock on
//! an already-running daemon. No service control or physical compaction occurs.

use std::sync::PoisonError;

use serde::{Deserialize, Serialize};
use tracedecay_contracts::session_sync::{
    SessionSyncJournalStatusV1, SessionSyncJournalV1, SessionSyncRequestV1, SessionSyncScopeV1,
};
use tracedecay_contracts::{RequestId, now_micros};
use tracedecay_domain::UtcMicros;
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_domain::errors::Result;
use tracedecay_global_db::{
    RegisteredGlobalDb, session_sync_retention::is_internal_startup_journal,
};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_sessions::runtime::registered_db::SessionQuery;
use tracedecay_store::StoreShardScopeV1;

use super::{
    DaemonSessionSyncService, contract_error, import_scope_key, journal_key, journal_prefix,
};

pub const STARTUP_JOURNAL_RETENTION_MICROS: i64 = 86_400_000_000;
const PAGE_ROWS: i64 = 8;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const PREFIX: &str = "session-sync.v1.";

// The frontier inventories never cross the query boundary. Large payloads are
// inspected one at a time, with at most one deletion per approved page.
const INSPECT_SQL: &str = r#"
WITH inspected AS (
    SELECT length(CAST(value AS BLOB)) AS bytes, updated_at,
        CASE WHEN length(CAST(value AS BLOB)) > 67108864 THEN NULL
             WHEN json_valid(value) THEN
                 CASE WHEN json_extract(value, '$.status') = 'complete'
                     AND json_type(value, '$.source_frontiers') = 'array'
                     AND json_type(value, '$.completion.source_frontiers') = 'array'
                 THEN json_set(value, '$.source_frontiers', json('[]'),
                     '$.completion.source_frontiers', json('[]')) END
        END AS metadata
    FROM session_backfill_meta WHERE key = ?1
)
SELECT bytes, updated_at,
    CASE WHEN length(CAST(metadata AS BLOB)) <= 32768 THEN metadata END
FROM inspected
"#;

#[path = "journal_dependencies.rs"]
pub(super) mod dependencies;
use dependencies::PINNED_SQL;
pub use dependencies::StartupJournalDependencyBackfillV1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupJournalRetentionCursorV1 {
    pub after_key: String,
    pub through_key: String,
    /// Frozen across a sweep, including when the caller supplies a newer clock.
    pub cutoff: UtcMicros,
    prefix: String,
    registry_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StartupJournalRetentionCandidateV1 {
    pub key: String,
    pub scope: SessionSyncScopeV1,
    pub payload_bytes: u64,
    // Binds control fields and timestamps, not the large frontier arrays.
    metadata_digest: String,
    operation_id: RequestId,
}

#[derive(Clone, Debug, Serialize)]
pub struct StartupJournalRetentionPlanV1 {
    pub digest: String,
    pub cutoff: UtcMicros,
    pub scanned: usize,
    pub skipped: usize,
    pub pinned: usize,
    pub oversized: usize,
    pub candidates: Vec<StartupJournalRetentionCandidateV1>,
    pub next: Option<StartupJournalRetentionCursorV1>,
    /// Apply and replan without advancing `next` until legacy certification ends.
    pub dependency_backfill: Option<StartupJournalDependencyBackfillV1>,
    registry_identity: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StartupJournalRetentionReceiptV1 {
    pub deleted: usize,
    pub stale: usize,
    pub busy: usize,
    pub dependency_rows_indexed: usize,
    pub dependency_backfill_applied: bool,
    /// Logical payload released; DELETE does not promise filesystem shrink.
    pub logical_bytes_released: u64,
}

fn digest(value: &impl Serialize) -> Result<String> {
    let encoded = serde_json::to_vec(value).map_err(contract_error)?;
    Ok(sha256_hex(&encoded))
}

fn plan_digest(plan: &StartupJournalRetentionPlanV1) -> Result<String> {
    digest(&(
        &plan.registry_identity,
        plan.cutoff,
        plan.scanned,
        plan.skipped,
        plan.pinned,
        plan.oversized,
        &plan.candidates,
        &plan.next,
        &plan.dependency_backfill,
    ))
}

fn registry_identity(registry: &RegisteredGlobalDb) -> Result<String> {
    let shard = &registry.binding().shard_id;
    if !matches!(&shard.scope, StoreShardScopeV1::Profile) {
        return Err(contract_error(
            "startup retention requires an existing profile registry",
        ));
    }
    digest(&(
        registry.db_path(),
        shard.brain_id.as_str(),
        shard.profile_id.as_str(),
    ))
}

async fn inspect(
    reader: &impl SessionQuery,
    key: &str,
    cutoff: UtcMicros,
) -> Result<(Option<StartupJournalRetentionCandidateV1>, bool)> {
    let mut rows = reader.query(INSPECT_SQL, params![key]).await?;
    let Some(row) = rows.next().await? else {
        return Ok((None, false));
    };
    let bytes: u64 = row.get(0)?;
    let updated_at: i64 = row.get(1)?;
    let metadata: Option<String> = row.get(2)?;
    if bytes > MAX_BYTES {
        return Ok((None, true));
    }
    let Some(metadata) = metadata else {
        return Ok((None, false));
    };
    let Ok(journal) = serde_json::from_str::<SessionSyncJournalV1>(&metadata) else {
        return Ok((None, false));
    };
    let Some(completion) = &journal.completion else {
        return Ok((None, false));
    };
    if !is_internal_startup_journal(&journal)
        || journal.status != SessionSyncJournalStatusV1::Complete
        || completion.admission != journal.admission
        || completion.coalesced_primary != journal.coalesced_primary
        || completion.completed_at.0 <= 0
        || journal.admission.accepted_at.0 < 0
        || journal.admission.accepted_at > completion.completed_at
        || completion.completed_at >= cutoff
        || key != journal_key(&journal.scope, &journal.admission.idempotency_key)
    {
        return Ok((None, false));
    }
    Ok((
        Some(StartupJournalRetentionCandidateV1 {
            key: key.to_owned(),
            scope: journal.scope,
            payload_bytes: bytes,
            metadata_digest: digest(&(metadata, updated_at, bytes))?,
            operation_id: journal.admission.operation_id,
        }),
        false,
    ))
}

async fn pinned(
    reader: &impl SessionQuery,
    candidate: &StartupJournalRetentionCandidateV1,
) -> Result<bool> {
    if dependencies::plan(reader).await?.is_some() {
        return Ok(true);
    }
    let prefix = journal_prefix(&candidate.scope);
    let id = candidate
        .key
        .strip_prefix(&prefix)
        .ok_or_else(|| contract_error("startup retention candidate scope mismatch"))?;
    let mut rows = reader
        .query(
            PINNED_SQL,
            params![prefix.as_str(), format!("{prefix}\u{10ffff}"), id,],
        )
        .await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| contract_error("missing startup retention dependency aggregate"))?;
    Ok(row.get::<i64>(0)? != 0)
}

impl DaemonSessionSyncService {
    /// Called only during project registration, while its admission gate is held.
    /// Replace an unreferenced terminal v2 receipt in place, never delete then
    /// insert: a crash leaves either the old receipt or recoverable queued work.
    /// False selects a separate per-run generation; it must not replay an old
    /// stable receipt merely because that evidence cannot safely be replaced.
    pub(super) async fn renew_startup_journal(
        &self,
        registry: &RegisteredGlobalDb,
        request: &SessionSyncRequestV1,
    ) -> Result<bool> {
        let queued = SessionSyncJournalV1::queued(request, now_micros());
        if !is_internal_startup_journal(&queued)
            || request.idempotency_key().as_str()
                != format!(
                    "session-sync.startup.v2.{}",
                    request.scope().project_id().as_str()
                )
            || self.retention_scope_busy(request.scope())
        {
            return Ok(false);
        }
        dependencies::ensure_installed(registry).await?;
        let encoded = serde_json::to_string(&queued).map_err(contract_error)?;
        let key = journal_key(request.scope(), request.idempotency_key());
        let transaction = registry.begin_write_transaction().await?;
        let (candidate, _) = inspect(&transaction, &key, UtcMicros(i64::MAX)).await?;
        let Some(candidate) = candidate else {
            let mut rows = transaction
                .query(
                    "SELECT EXISTS(SELECT 1 FROM session_backfill_meta WHERE key = ?1)",
                    params![key],
                )
                .await?;
            return Ok(rows
                .next()
                .await?
                .ok_or_else(|| contract_error("missing startup slot lookup"))?
                .get::<i64>(0)?
                == 0);
        };
        if candidate.scope != *request.scope() {
            return Ok(false);
        }
        if candidate.operation_id == *request.operation_id() {
            return Ok(true);
        }
        if candidate.payload_bytes.saturating_add(encoded.len() as u64) > MAX_BYTES
            || pinned(&transaction, &candidate).await?
        {
            return Ok(false);
        }
        transaction.execute(
            "UPDATE session_backfill_meta SET value = ?2, updated_at = unixepoch() WHERE key = ?1",
            params![key, encoded],
        ).await?;
        transaction.commit().await?;
        Ok(true)
    }

    fn retention_scope_busy(&self, scope: &SessionSyncScopeV1) -> bool {
        let prefix = journal_prefix(scope);
        let active = self
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .any(|key| key.starts_with(&prefix));
        let importing = self
            .active_imports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&import_scope_key(scope));
        active || importing
    }

    /// Preview one page of receipts strictly older than the default 24 hours.
    /// Works for unmounted projects too. Continue with `next` until exhausted,
    /// then start a fresh sweep to reconsider previously pinned/busy receipts.
    pub async fn plan_startup_journal_retention(
        &self,
        registry: &RegisteredGlobalDb,
        scope: Option<&SessionSyncScopeV1>,
        now: UtcMicros,
        cursor: Option<&StartupJournalRetentionCursorV1>,
    ) -> Result<StartupJournalRetentionPlanV1> {
        let identity = registry_identity(registry)?;
        if scope.is_some_and(|s| s.profile_id() != &registry.binding().shard_id.profile_id) {
            return Err(contract_error(
                "startup retention scope is outside this profile",
            ));
        }
        let prefix = scope.map_or_else(|| PREFIX.to_owned(), journal_prefix);
        let upper = format!("{prefix}\u{10ffff}");
        let snapshot = registry.read_snapshot().await?;
        let dependency_backfill = dependencies::plan(&snapshot).await?;
        let mut plan = StartupJournalRetentionPlanV1 {
            digest: String::new(),
            cutoff: cursor.map_or(
                UtcMicros(now.0.saturating_sub(STARTUP_JOURNAL_RETENTION_MICROS)),
                |c| c.cutoff,
            ),
            scanned: 0,
            skipped: 0,
            pinned: 0,
            oversized: 0,
            candidates: Vec::new(),
            next: None,
            dependency_backfill,
            registry_identity: identity.clone(),
        };
        let (through, cutoff) = if let Some(cursor) = cursor {
            if cursor.registry_identity != identity
                || cursor.prefix != prefix
                || !cursor.after_key.starts_with(&prefix)
                || !cursor.through_key.starts_with(&prefix)
                || cursor.after_key > cursor.through_key
                || cursor.after_key.len() > 8192
                || cursor.through_key.len() > 8192
                || cursor.cutoff > UtcMicros(now.0.saturating_sub(STARTUP_JOURNAL_RETENTION_MICROS))
            {
                return Err(contract_error(
                    "startup retention cursor scope, registry or retention horizon mismatch",
                ));
            }
            (cursor.through_key.clone(), cursor.cutoff)
        } else {
            if plan.dependency_backfill.is_some() {
                plan.digest = plan_digest(&plan)?;
                return Ok(plan);
            }
            let mut rows = snapshot.query(
                "SELECT MAX(key) FROM session_backfill_meta WHERE key >= ?1 AND key < ?2 AND length(CAST(key AS BLOB)) <= 8192",
                params![prefix.as_str(), upper.as_str()],
            ).await?;
            let row = rows
                .next()
                .await?
                .ok_or_else(|| contract_error("missing startup retention high-water aggregate"))?;
            (
                row.get::<Option<String>>(0)?.unwrap_or_default(),
                UtcMicros(now.0.saturating_sub(STARTUP_JOURNAL_RETENTION_MICROS)),
            )
        };
        if plan.dependency_backfill.is_some() {
            plan.next = cursor.cloned();
            plan.digest = plan_digest(&plan)?;
            return Ok(plan);
        }
        let mut rows = snapshot
            .query(
                "SELECT key FROM session_backfill_meta
             WHERE key >= ?1 AND key < ?2 AND key > ?3 AND key <= ?4
               AND length(CAST(key AS BLOB)) <= 8192 ORDER BY key LIMIT ?5",
                params![
                    prefix.as_str(),
                    upper.as_str(),
                    cursor.map_or("", |c| c.after_key.as_str()),
                    through.as_str(),
                    PAGE_ROWS
                ],
            )
            .await?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next().await? {
            keys.push(row.get::<String>(0)?);
        }
        drop(rows);
        plan.cutoff = cutoff;
        for key in keys {
            plan.scanned += 1;
            let (candidate, oversized) = inspect(&snapshot, &key, cutoff).await?;
            plan.oversized += usize::from(oversized);
            if let Some(candidate) = candidate {
                if candidate.scope.profile_id() != &registry.binding().shard_id.profile_id {
                    plan.skipped += 1;
                } else if self.retention_scope_busy(&candidate.scope)
                    || pinned(&snapshot, &candidate).await?
                {
                    plan.pinned += 1;
                } else {
                    plan.candidates.push(candidate);
                }
            } else {
                plan.skipped += 1;
            }
            plan.next = (key < through).then(|| StartupJournalRetentionCursorV1 {
                after_key: key,
                through_key: through.clone(),
                cutoff,
                prefix: prefix.clone(),
                registry_identity: plan.registry_identity.clone(),
            });
            if !plan.candidates.is_empty() {
                break;
            }
        }
        plan.digest = plan_digest(&plan)?;
        Ok(plan)
    }

    /// Apply a confirmed page with the admission gate held through commit.
    /// Busy or stale pages must be replanned, not treated as successful deletion.
    /// Recheck the exact scope's indexed references in the writer transaction;
    /// neither a concurrently admitted alias nor an active import loses evidence.
    pub async fn apply_startup_journal_retention(
        &self,
        registry: &RegisteredGlobalDb,
        plan: &StartupJournalRetentionPlanV1,
        approved_digest: &str,
    ) -> Result<StartupJournalRetentionReceiptV1> {
        if approved_digest != plan.digest
            || plan_digest(plan)? != plan.digest
            || registry_identity(registry)? != plan.registry_identity
            || plan.candidates.len() > 1
        {
            return Err(contract_error(
                "startup retention requires the unchanged registry preview digest",
            ));
        }
        let mut receipt = StartupJournalRetentionReceiptV1::default();
        if let Some(backfill) = &plan.dependency_backfill {
            if !plan.candidates.is_empty() {
                return Err(contract_error(
                    "dependency certification cannot delete receipts",
                ));
            }
            let transaction = registry.begin_write_transaction().await?;
            match dependencies::apply(&transaction, backfill).await? {
                Some(indexed) => {
                    receipt.dependency_rows_indexed = indexed;
                    receipt.dependency_backfill_applied = true;
                    transaction.commit().await?;
                }
                None => receipt.stale = 1,
            }
            return Ok(receipt);
        }
        let Some(candidate) = plan.candidates.first() else {
            return Ok(receipt);
        };
        let gate = self.project_gate(&candidate.scope);
        let Ok(_project) = gate.try_lock() else {
            receipt.busy = 1;
            return Ok(receipt);
        };
        if self.retention_scope_busy(&candidate.scope) {
            receipt.busy = 1;
            return Ok(receipt);
        }
        let transaction = registry.begin_write_transaction().await?;
        let (current, _) = inspect(&transaction, &candidate.key, plan.cutoff).await?;
        if current.as_ref() != Some(candidate) || pinned(&transaction, candidate).await? {
            receipt.stale = 1;
            return Ok(receipt);
        }
        let changed = transaction
            .execute(
                "DELETE FROM session_backfill_meta WHERE key = ?1",
                params![candidate.key.as_str()],
            )
            .await?;
        transaction.commit().await?;
        receipt.deleted = changed as usize;
        receipt.logical_bytes_released = candidate.payload_bytes.saturating_mul(changed);
        Ok(receipt)
    }
}

#[cfg(test)]
mod dependency_work_tests {
    use super::*;
    use rusqlite::{Connection, StatementStatus};

    #[test]
    fn startup_retention_dependency_work_is_independent_of_accumulated_history() {
        let mut costs = Vec::new();
        for count in [16, 128, 1024] {
            let db = Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE session_backfill_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);").unwrap();
            db.execute_batch(&dependencies::schema_sql()).unwrap();
            let prefix = "session-sync.v1.p7:profile.r7:project.";
            let payload = serde_json::json!({
                "scope": {"profile_id": "profile", "project_id": "project"},
                "status": "complete", "coalesced_primary": null,
                "source_frontiers": [],
                "completion": {"source_frontiers": [{"cursor": "x".repeat(16384)}], "coalesced_primary": null}
            }).to_string();
            for n in 0..count {
                db.execute(
                    "INSERT INTO session_backfill_meta VALUES (?1, ?2, 1)",
                    rusqlite::params![format!("{prefix}{n:08}"), payload],
                )
                .unwrap();
            }
            // This is the production dependency query shared by preview,
            // apply, and guarded startup renewal, not a substitute query.
            let mut query = db.prepare(PINNED_SQL).unwrap();
            let pinned: i64 = query
                .query_row(
                    rusqlite::params![prefix, format!("{prefix}\u{10ffff}"), "unreferenced"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(pinned, 0);
            costs.push(query.get_status(StatementStatus::VmStep));
        }
        eprintln!("dependency VM steps at 16/128/1024 journals: {costs:?}");
        assert!(
            costs.iter().all(|&steps| steps < 256),
            "one preview/apply/renewal must not scan accumulated journals: {costs:?}"
        );
    }
}
