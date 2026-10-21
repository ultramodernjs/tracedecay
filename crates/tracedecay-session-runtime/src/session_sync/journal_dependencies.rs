//! Small, transactionally maintained dependency facts. Installation never reads
//! journal values or rebuilds an index over history. Legacy values are certified
//! one at a time by explicitly approved retention pages, not by project startup.

use serde::Serialize;
use tracedecay_domain::errors::Result;
use tracedecay_global_db::RegisteredGlobalDb;
use tracedecay_runtime_core::db::engine::params;
use tracedecay_sessions::runtime::registered_db::{SessionExec, SessionQuery};

use super::super::contract_error;

const PRESENT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'session_sync_dependency_state_v1')";

// No frontier content is persisted in this table. Unknown, nonterminal,
// over-budget or wrong-namespace rows pin their key's scope conservatively.
// The exact key lookup also serves the migration; no scope-wide JSON query.
const PROJECT_SQL: &str = r#"
INSERT OR REPLACE INTO session_sync_dependencies_v1(key, unsafe, primary_id, completion_primary_id)
SELECT key, CASE
    WHEN length(CAST(value AS BLOB)) > 67108864 THEN 1
    WHEN NOT json_valid(value) THEN 1
    WHEN json_type(value, '$.scope.profile_id') IS NOT 'text' THEN 1
    WHEN json_type(value, '$.scope.project_id') IS NOT 'text' THEN 1
    WHEN substr(key, 1, length('session-sync.v1.p' ||
         length(CAST(json_extract(value, '$.scope.profile_id') AS BLOB)) || ':' ||
         json_extract(value, '$.scope.profile_id') || '.r' ||
         length(CAST(json_extract(value, '$.scope.project_id') AS BLOB)) || ':' ||
         json_extract(value, '$.scope.project_id') || '.')) IS NOT
         ('session-sync.v1.p' || length(CAST(json_extract(value, '$.scope.profile_id') AS BLOB)) || ':' ||
         json_extract(value, '$.scope.profile_id') || '.r' ||
         length(CAST(json_extract(value, '$.scope.project_id') AS BLOB)) || ':' ||
         json_extract(value, '$.scope.project_id') || '.') THEN 1
    WHEN json_extract(value, '$.status') IS NOT 'complete' THEN 1
    WHEN json_type(value, '$.completion') IS NOT 'object' THEN 1
    WHEN json_type(value, '$.source_frontiers') IS NOT 'array' THEN 1
    WHEN json_type(value, '$.completion.source_frontiers') IS NOT 'array' THEN 1
    WHEN COALESCE(json_type(value, '$.coalesced_primary') IN ('null', 'text'), 0) = 0 THEN 1
    WHEN COALESCE(json_type(value, '$.completion.coalesced_primary') IN ('null', 'text'), 0) = 0 THEN 1
    WHEN length(CAST(json_extract(value, '$.coalesced_primary') AS BLOB)) > 8192 THEN 1
    WHEN length(CAST(json_extract(value, '$.completion.coalesced_primary') AS BLOB)) > 8192 THEN 1
    ELSE 0 END,
    CASE WHEN length(CAST(value AS BLOB)) <= 67108864 AND json_valid(value) THEN
        CASE WHEN json_type(value, '$.coalesced_primary') = 'text'
             AND length(CAST(json_extract(value, '$.coalesced_primary') AS BLOB)) <= 8192
        THEN json_extract(value, '$.coalesced_primary') END END,
    CASE WHEN length(CAST(value AS BLOB)) <= 67108864 AND json_valid(value) THEN
        CASE WHEN json_type(value, '$.completion.coalesced_primary') = 'text'
             AND length(CAST(json_extract(value, '$.completion.coalesced_primary') AS BLOB)) <= 8192
        THEN json_extract(value, '$.completion.coalesced_primary') END END
FROM session_backfill_meta WHERE key = ?1
    AND key >= 'session-sync.v1.' AND key < 'session-sync.v1/'
"#;

// Each EXISTS seeks a covering index. Even the negative case touches no
// journal values and does not walk all of a project's dependency rows.
pub(super) const PINNED_SQL: &str = r#"
SELECT EXISTS(SELECT 1 FROM session_sync_dependencies_v1
    WHERE unsafe = 1 AND key >= ?1 AND key < ?2)
 OR EXISTS(SELECT 1 FROM session_sync_dependencies_v1
    WHERE primary_id = ?3 AND key >= ?1 AND key < ?2)
 OR EXISTS(SELECT 1 FROM session_sync_dependencies_v1
    WHERE completion_primary_id = ?3 AND key >= ?1 AND key < ?2)
"#;

pub(super) fn schema_sql() -> String {
    let project_new = PROJECT_SQL.replace("?1", "NEW.key");
    format!(
        r#"
CREATE TABLE IF NOT EXISTS session_sync_dependencies_v1 (
    key TEXT PRIMARY KEY, unsafe INTEGER NOT NULL,
    primary_id TEXT, completion_primary_id TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS session_sync_dependencies_unsafe_v1 ON session_sync_dependencies_v1(unsafe, key);
CREATE INDEX IF NOT EXISTS session_sync_dependencies_primary_v1 ON session_sync_dependencies_v1(primary_id, key);
CREATE INDEX IF NOT EXISTS session_sync_dependencies_completion_v1 ON session_sync_dependencies_v1(completion_primary_id, key);
CREATE TABLE IF NOT EXISTS session_sync_dependency_state_v1 (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    after_key TEXT NOT NULL, through_key TEXT NOT NULL, complete INTEGER NOT NULL
);
INSERT OR IGNORE INTO session_sync_dependency_state_v1
    SELECT 1, '', COALESCE(MAX(key), ''), MAX(key) IS NULL
    FROM session_backfill_meta WHERE key >= 'session-sync.v1.' AND key < 'session-sync.v1/';
CREATE TRIGGER IF NOT EXISTS session_sync_dependencies_insert_v1 AFTER INSERT ON session_backfill_meta
BEGIN {project_new}; END;
CREATE TRIGGER IF NOT EXISTS session_sync_dependencies_update_v1 AFTER UPDATE OF key, value ON session_backfill_meta
BEGIN
    DELETE FROM session_sync_dependencies_v1 WHERE key = OLD.key;
    {project_new};
END;
CREATE TRIGGER IF NOT EXISTS session_sync_dependencies_delete_v1 AFTER DELETE ON session_backfill_meta
BEGIN DELETE FROM session_sync_dependencies_v1 WHERE key = OLD.key; END;
"#
    )
}

/// `None` means certified. Otherwise apply this page, then replan without
/// advancing the receipt cursor. Bootstrap installs empty indexes and triggers;
/// subsequent pages index at most one legacy journal, retaining all originals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StartupJournalDependencyBackfillV1 {
    pub key: Option<String>,
    after_key: String,
    through_key: String,
    installed: bool,
}

pub(super) async fn plan(
    reader: &impl SessionQuery,
) -> Result<Option<StartupJournalDependencyBackfillV1>> {
    let mut rows = reader.query(PRESENT_SQL, ()).await?;
    let installed = rows
        .next()
        .await?
        .ok_or_else(|| contract_error("missing dependency schema lookup"))?
        .get::<i64>(0)?
        != 0;
    if !installed {
        return Ok(Some(StartupJournalDependencyBackfillV1 {
            key: None,
            after_key: String::new(),
            through_key: String::new(),
            installed: false,
        }));
    }
    let mut rows = reader.query("SELECT after_key, through_key, complete FROM session_sync_dependency_state_v1 WHERE singleton = 1", ()).await?;
    let row = rows
        .next()
        .await?
        .ok_or_else(|| contract_error("missing dependency certification state"))?;
    if row.get::<i64>(2)? != 0 {
        return Ok(None);
    }
    let after_key: String = row.get(0)?;
    let through_key: String = row.get(1)?;
    let mut rows = reader.query(
        "SELECT key FROM session_backfill_meta WHERE key >= 'session-sync.v1.' AND key < 'session-sync.v1/' AND key > ?1 AND key <= ?2 ORDER BY key LIMIT 1",
        params![after_key.as_str(), through_key.as_str()],
    ).await?;
    let key = match rows.next().await? {
        Some(row) => Some(row.get(0)?),
        None => None,
    };
    Ok(Some(StartupJournalDependencyBackfillV1 {
        key,
        after_key,
        through_key,
        installed,
    }))
}

/// Constant-size installation, safe during registration. No legacy row is
/// visited here. An uncertified profile uses a separate startup generation.
pub(in crate::session_sync) async fn ensure_installed(registry: &RegisteredGlobalDb) -> Result<()> {
    let transaction = registry.begin_write_transaction().await?;
    let mut rows = transaction.query(PRESENT_SQL, ()).await?;
    let installed = rows
        .next()
        .await?
        .ok_or_else(|| contract_error("missing dependency schema lookup"))?
        .get::<i64>(0)?
        != 0;
    drop(rows);
    if !installed {
        transaction.execute_batch(&schema_sql()).await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// Writer transaction serializes legacy certification with trigger updates and
/// with receipt deletion. Revalidate the exact persisted migration frontier;
/// candidate apply separately rechecks live references in the same transaction.
pub(super) async fn apply(
    writer: &impl SessionExec,
    approved: &StartupJournalDependencyBackfillV1,
) -> Result<Option<usize>> {
    if plan(writer).await?.as_ref() != Some(approved) {
        return Ok(None);
    }
    if !approved.installed {
        writer.execute_batch(&schema_sql()).await?;
        return Ok(Some(0));
    }
    if let Some(key) = &approved.key {
        writer.execute(PROJECT_SQL, params![key.as_str()]).await?;
    }
    writer.execute(
        "UPDATE session_sync_dependency_state_v1 SET after_key = ?1, complete = ?2 WHERE singleton = 1",
        params![approved.key.as_deref().unwrap_or(&approved.after_key), i64::from(approved.key.is_none() || approved.key.as_ref() == Some(&approved.through_key))],
    ).await?;
    Ok(Some(usize::from(approved.key.is_some())))
}
