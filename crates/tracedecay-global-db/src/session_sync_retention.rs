//! Bounded, dry-run-first normalization of legacy session-sync journals.
//!
//! Only redundant internal-startup terminal frontier arrays are removed.
//! Manual operations, incomplete work and unrelated metadata are never changed.
//! Reported savings are logical payload bytes, not physical file reclamation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracedecay_contracts::session_sync::{
    SessionSyncCommandV1, SessionSyncJournalStatusV1, SessionSyncJournalV1, SessionSyncScopeV1,
};
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_sessions::runtime::registered_db::SessionQuery;
use tracedecay_store::StoreShardScopeV1;

use crate::RegisteredGlobalDb;

pub const SESSION_SYNC_JOURNAL_GC_PAGE_ROWS: usize = 8;
pub const SESSION_SYNC_JOURNAL_GC_MAX_BYTES: u64 = 64 * 1024 * 1024;
const JOURNAL_PREFIX: &str = "session-sync.v1.";

// Frontier arrays stay inside SQLite, including during preview. Eight small
// projections fit comfortably under the exact-SQL materialization budget even
// when the original journals are tens of megabytes apiece.
const INSPECT_SQL: &str = r#"
WITH inspected AS (
    SELECT value, length(CAST(value AS BLOB)) AS bytes, updated_at,
        CASE WHEN length(CAST(value AS BLOB)) > 67108864 THEN 0
             WHEN json_valid(value) THEN
                 COALESCE(json_extract(value, '$.status') = 'complete'
                 AND json_type(value, '$.source_frontiers') = 'array'
                 AND json_type(value, '$.completion.source_frontiers') = 'array'
                 AND json_array_length(value, '$.source_frontiers') > 0
                 AND json_extract(value, '$.source_frontiers') =
                     json_extract(value, '$.completion.source_frontiers'), 0)
             ELSE 0 END AS eligible
    FROM session_backfill_meta
    WHERE key = ?1 AND key >= 'session-sync.v1.' AND key < 'session-sync.v1/'
), projected AS (
    SELECT bytes, updated_at,
        CASE WHEN eligible THEN json_set(value,
            '$.source_frontiers', json('[]'),
            '$.completion.source_frontiers', json('[]')) END AS metadata,
        CASE WHEN eligible THEN length(CAST(json_set(value,
            '$.source_frontiers', json('[]')) AS BLOB)) END AS compacted_bytes
    FROM inspected
)
SELECT bytes, updated_at,
       CASE WHEN length(CAST(metadata AS BLOB)) <= 32768 THEN metadata END,
       compacted_bytes
FROM projected
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSyncJournalGcCursorV1 {
    pub after_key: String,
    pub through_key: String,
    prefix: String,
    registry_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionSyncJournalGcCandidateV1 {
    pub key: String,
    pub scope: SessionSyncScopeV1,
    pub payload_bytes: u64,
    pub logical_bytes_released: u64,
    // Identifies the approved operation and its small control fields, not the
    // large receipt arrays. Apply rechecks equality of both arrays in SQLite.
    metadata_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionSyncJournalGcPlanV1 {
    pub digest: String,
    pub scanned: usize,
    pub skipped: usize,
    pub oversized: usize,
    /// At most one mutation, with old plus new payload within 64 MiB.
    pub candidates: Vec<SessionSyncJournalGcCandidateV1>,
    pub next: Option<SessionSyncJournalGcCursorV1>,
    registry_identity: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SessionSyncJournalGcReceiptV1 {
    pub compacted: usize,
    pub stale: usize,
    pub logical_bytes_released: u64,
}

fn journal_prefix(scope: &SessionSyncScopeV1) -> String {
    let profile = scope.profile_id().as_str();
    let project = scope.project_id().as_str();
    format!(
        "{JOURNAL_PREFIX}p{}:{profile}.r{}:{project}.",
        profile.len(),
        project.len()
    )
}

fn invalid_plan(message: &str) -> TraceDecayError {
    TraceDecayError::Config {
        message: message.to_owned(),
    }
}

fn registry_identity(registry: &RegisteredGlobalDb) -> Result<String> {
    let shard = &registry.binding().shard_id;
    if !matches!(shard.scope, StoreShardScopeV1::Profile) {
        return Err(invalid_plan(
            "journal compaction requires an existing profile registry",
        ));
    }
    let encoded = serde_json::to_vec(&(
        registry.db_path(),
        shard.brain_id.as_str(),
        shard.profile_id.as_str(),
    ))
    .map_err(|error| invalid_plan(&format!("encode journal registry identity: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn plan_digest(plan: &SessionSyncJournalGcPlanV1) -> Result<String> {
    // Excludes the digest itself; binds the approved action and continuation.
    let encoded = serde_json::to_vec(&(
        &plan.registry_identity,
        plan.scanned,
        plan.skipped,
        plan.oversized,
        &plan.candidates,
        &plan.next,
    ))
    .map_err(|error| invalid_plan(&format!("encode journal compaction plan: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// Recognize only runtime-minted startup identities, including the legacy
/// per-process format. The v2 key is stable per project; its operation ID still
/// identifies the daemon run so a same-process remount remains idempotent.
pub fn is_internal_startup_journal(journal: &SessionSyncJournalV1) -> bool {
    let suffix = format!(".{}", journal.scope.project_id().as_str());
    let operation = journal.admission.operation_id.as_str();
    let Some(run) = operation
        .strip_prefix("session-sync.startup.")
        .and_then(|id| id.strip_suffix(&suffix))
    else {
        return false;
    };
    let random_run = run.len() == 32
        && run
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let fallback_run = run
        .strip_prefix("mcp-")
        .and_then(|seconds| seconds.parse::<u64>().ok().map(|n| (seconds, n)))
        .is_some_and(|(seconds, n)| n.to_string() == seconds);
    let id = journal.admission.idempotency_key.as_str();
    (random_run || fallback_run)
        && (id == operation || id == format!("session-sync.startup.v2{suffix}"))
        && matches!(journal.source, SessionSyncCommandV1::ImportTranscripts(_))
}

async fn inspect(
    reader: &impl SessionQuery,
    key: &str,
) -> Result<(Option<SessionSyncJournalGcCandidateV1>, bool)> {
    let mut rows = reader.query(INSPECT_SQL, params![key]).await?;
    let Some(row) = rows.next().await? else {
        return Ok((None, false));
    };
    let bytes: u64 = row.get(0)?;
    let updated_at: i64 = row.get(1)?;
    let metadata: Option<String> = row.get(2)?;
    let compacted_bytes: Option<u64> = row.get(3)?;
    if bytes > SESSION_SYNC_JOURNAL_GC_MAX_BYTES {
        return Ok((None, true));
    }
    let (Some(metadata), Some(compacted_bytes)) = (metadata, compacted_bytes) else {
        return Ok((None, false));
    };
    if bytes.saturating_add(compacted_bytes) > SESSION_SYNC_JOURNAL_GC_MAX_BYTES {
        return Ok((None, true));
    }
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
        || key
            != format!(
                "{}{}",
                journal_prefix(&journal.scope),
                journal.admission.idempotency_key.as_str()
            )
        || compacted_bytes >= bytes
    {
        return Ok((None, false));
    }
    let mut digest = Sha256::new();
    digest.update(metadata.as_bytes());
    digest.update(updated_at.to_le_bytes());
    digest.update(bytes.to_le_bytes());
    digest.update(compacted_bytes.to_le_bytes());
    Ok((
        Some(SessionSyncJournalGcCandidateV1 {
            key: key.to_owned(),
            scope: journal.scope,
            payload_bytes: bytes,
            logical_bytes_released: bytes - compacted_bytes,
            metadata_digest: hex::encode(digest.finalize()),
        }),
        false,
    ))
}

/// Preview one bounded page on an existing admitted registry, without write
/// authority. Reuse `next` until exhausted; a new sweep starts with `None`.
/// The high-water key is frozen so concurrent admissions cannot extend a sweep.
pub async fn plan_session_sync_journal_gc(
    registry: &RegisteredGlobalDb,
    scope: Option<&SessionSyncScopeV1>,
    cursor: Option<&SessionSyncJournalGcCursorV1>,
) -> Result<SessionSyncJournalGcPlanV1> {
    let identity = registry_identity(registry)?;
    if scope.is_some_and(|s| s.profile_id() != &registry.binding().shard_id.profile_id) {
        return Err(invalid_plan(
            "journal compaction scope is outside this profile",
        ));
    }
    let prefix = scope.map_or_else(|| JOURNAL_PREFIX.to_owned(), journal_prefix);
    let upper = format!("{prefix}\u{10ffff}");
    let snapshot = registry.read_snapshot().await?;
    let through = if let Some(cursor) = cursor {
        if cursor.registry_identity != identity
            || cursor.prefix != prefix
            || !cursor.after_key.starts_with(&prefix)
            || !cursor.through_key.starts_with(&prefix)
            || cursor.after_key > cursor.through_key
            || cursor.after_key.len() > 8192
            || cursor.through_key.len() > 8192
        {
            return Err(invalid_plan(
                "journal compaction cursor is outside the selected scope",
            ));
        }
        cursor.through_key.clone()
    } else {
        let mut rows = snapshot
            .query(
                "SELECT MAX(key) FROM session_backfill_meta WHERE key >= ?1 AND key < ?2 AND length(CAST(key AS BLOB)) <= 8192",
                params![prefix.as_str(), upper.as_str()],
            )
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| invalid_plan("missing journal high-water aggregate"))?;
        row.get::<Option<String>>(0)?.unwrap_or_default()
    };
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
                SESSION_SYNC_JOURNAL_GC_PAGE_ROWS as i64
            ],
        )
        .await?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next().await? {
        keys.push(row.get::<String>(0)?);
    }
    drop(rows);
    let mut plan = SessionSyncJournalGcPlanV1 {
        digest: String::new(),
        scanned: 0,
        skipped: 0,
        oversized: 0,
        candidates: Vec::new(),
        next: None,
        registry_identity: identity,
    };
    for key in keys {
        plan.scanned += 1;
        let (candidate, oversized) = inspect(&snapshot, &key).await?;
        plan.oversized += usize::from(oversized);
        if let Some(candidate) = candidate.filter(|candidate| {
            candidate.scope.profile_id() == &registry.binding().shard_id.profile_id
        }) {
            plan.candidates.push(candidate);
        } else {
            plan.skipped += 1;
        }
        if key < through {
            plan.next = Some(SessionSyncJournalGcCursorV1 {
                after_key: key,
                through_key: through.clone(),
                prefix: prefix.clone(),
                registry_identity: plan.registry_identity.clone(),
            });
        } else {
            plan.next = None;
        }
        if !plan.candidates.is_empty() {
            break;
        }
    }
    // An empty page terminates even when its high-water row was deleted.
    if plan.scanned == 0 {
        plan.next = None;
    }
    plan.digest = plan_digest(&plan)?;
    Ok(plan)
}

/// Apply only an explicitly approved preview. Revalidate its identity, terminal
/// state, byte budget and duplicate arrays in one admitted writer transaction.
/// No DELETE, VACUUM, schema initialization or service-control operation occurs.
pub async fn apply_session_sync_journal_gc(
    registry: &RegisteredGlobalDb,
    plan: &SessionSyncJournalGcPlanV1,
    approved_digest: &str,
) -> Result<SessionSyncJournalGcReceiptV1> {
    if approved_digest != plan.digest
        || plan_digest(plan)? != plan.digest
        || registry_identity(registry)? != plan.registry_identity
        || plan.candidates.len() > 1
    {
        return Err(invalid_plan(
            "journal compaction requires the unchanged preview digest",
        ));
    }
    let mut receipt = SessionSyncJournalGcReceiptV1::default();
    let Some(candidate) = plan.candidates.first() else {
        return Ok(receipt);
    };
    let transaction = registry.begin_write_transaction().await?;
    let (current, _) = inspect(&transaction, &candidate.key).await?;
    if current.as_ref() != Some(candidate) {
        receipt.stale = 1;
        return Ok(receipt);
    }
    let changed = transaction.execute(
        "UPDATE session_backfill_meta SET value = json_set(value, '$.source_frontiers', json('[]')) WHERE key = ?1",
        params![candidate.key.as_str()],
    ).await?;
    transaction.commit().await?;
    receipt.compacted = changed as usize;
    receipt.logical_bytes_released = candidate.logical_bytes_released.saturating_mul(changed);
    Ok(receipt)
}

#[cfg(test)]
mod tests;
