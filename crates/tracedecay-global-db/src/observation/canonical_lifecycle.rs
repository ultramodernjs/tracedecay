//! Bounded reconstruction and collection of shared canonical session content.
//!
//! Reverse references are derived from retained owner rows. They never replace
//! canonical hydration or integrity checks, and GC waits for every historical
//! owner family to finish before deleting any resource.

use tracedecay_domain::errors::Result;
use tracedecay_runtime_core::db::Database;
use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};
use tracedecay_store::canonical_body::{
    CANONICAL_BODY_REFERENCES_INDEX_SQL, CANONICAL_BODY_REFERENCES_TABLE_SQL,
    INSERT_OBSERVATION_BODY_REFERENCE_SQL, RAW_CANONICAL_BODY_REFERENCE_TRIGGERS,
};
use tracedecay_store::collect_body_refs;

use super::super::{global_db_operation_error, global_db_operation_message};

const OPERATION: &str = "collect unreferenced canonical session content";
const PAGE: i64 = 64;
const OBSERVATIONS: &str = "canonical-reference-backfill-observations";
const RAW: &str = "canonical-reference-backfill-raw";
const CAPTURES: &str = "canonical-reference-backfill-captures";

pub(crate) const CAPTURE_REFERENCES_TABLE_SQL: &str =
    "CREATE TABLE IF NOT EXISTS observation_repository_capture_references (
        observation_id TEXT PRIMARY KEY,
        capture_id TEXT NOT NULL
    );";

pub(crate) const CAPTURE_REFERENCES_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_observation_repository_capture_references_capture
        ON observation_repository_capture_references(capture_id);";

pub(crate) const OBSERVATIONS_CANONICAL_REFS_UPDATE_SQL: &str =
    "CREATE TRIGGER IF NOT EXISTS observations_canonical_refs_update
    AFTER UPDATE OF observation_json ON observations BEGIN
        DELETE FROM session_canonical_body_references
        WHERE owner_kind = 'observation' AND owner_key = OLD.observation_id;
    END;";

pub(crate) const OBSERVATIONS_CANONICAL_REFS_DELETE_SQL: &str =
    "CREATE TRIGGER IF NOT EXISTS observations_canonical_refs_delete
    AFTER DELETE ON observations BEGIN
        DELETE FROM session_canonical_body_references
        WHERE owner_kind = 'observation' AND owner_key = OLD.observation_id;
    END;";

pub(crate) const OBSERVATION_REPOSITORY_CAPTURE_REFS_INSERT_SQL: &str =
    "CREATE TRIGGER IF NOT EXISTS observation_repository_capture_refs_insert
    AFTER INSERT ON observation_repository_provenance BEGIN
        INSERT OR IGNORE INTO observation_repository_capture_references
            (observation_id, capture_id)
        SELECT NEW.observation_id, json_extract(NEW.capture_json, '$.capture_id')
        WHERE json_extract(NEW.capture_json, '$.capture_id') IS NOT NULL;
    END;";

pub(crate) const OBSERVATION_REPOSITORY_CAPTURE_REFS_UPDATE_SQL: &str =
    "CREATE TRIGGER IF NOT EXISTS observation_repository_capture_refs_update
    AFTER UPDATE OF capture_json ON observation_repository_provenance BEGIN
        DELETE FROM observation_repository_capture_references
        WHERE observation_id = OLD.observation_id;
        INSERT OR IGNORE INTO observation_repository_capture_references
            (observation_id, capture_id)
        SELECT NEW.observation_id, json_extract(NEW.capture_json, '$.capture_id')
        WHERE json_extract(NEW.capture_json, '$.capture_id') IS NOT NULL;
    END;";

pub(crate) const OBSERVATION_REPOSITORY_CAPTURE_REFS_DELETE_SQL: &str =
    "CREATE TRIGGER IF NOT EXISTS observation_repository_capture_refs_delete
    AFTER DELETE ON observation_repository_provenance BEGIN
        DELETE FROM observation_repository_capture_references
        WHERE observation_id = OLD.observation_id;
    END;";

pub(crate) const OBSERVATION_REFERENCE_TRIGGERS: &[(&str, &str, &str)] = &[
    (
        "observations_canonical_refs_update",
        "observations",
        OBSERVATIONS_CANONICAL_REFS_UPDATE_SQL,
    ),
    (
        "observations_canonical_refs_delete",
        "observations",
        OBSERVATIONS_CANONICAL_REFS_DELETE_SQL,
    ),
    (
        "observation_repository_capture_refs_insert",
        "observation_repository_provenance",
        OBSERVATION_REPOSITORY_CAPTURE_REFS_INSERT_SQL,
    ),
    (
        "observation_repository_capture_refs_update",
        "observation_repository_provenance",
        OBSERVATION_REPOSITORY_CAPTURE_REFS_UPDATE_SQL,
    ),
    (
        "observation_repository_capture_refs_delete",
        "observation_repository_provenance",
        OBSERVATION_REPOSITORY_CAPTURE_REFS_DELETE_SQL,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalContentGcState {
    /// Owner history remains incomplete. No bodies or captures are deleted.
    Backfilling,
    Ready,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalContentGcReport {
    pub state: CanonicalContentGcState,
    /// More bounded reconstruction or collection pages remain in this pass.
    pub pending: bool,
    pub owner_rows_examined: u64,
    pub body_rows_examined: u64,
    pub capture_rows_examined: u64,
    pub bodies_deleted: u64,
    pub captures_deleted: u64,
    /// Removed BLOB bytes, once per canonical hash. SQLite can reuse the pages;
    /// this does not measure filesystem or APFS space recovered.
    pub stored_body_bytes_deleted: u64,
    pub decoded_body_bytes_deleted: u64,
    pub stored_capture_bytes_deleted: u64,
}

impl Default for CanonicalContentGcReport {
    fn default() -> Self {
        Self {
            state: CanonicalContentGcState::Backfilling,
            pending: true,
            owner_rows_examined: 0,
            body_rows_examined: 0,
            capture_rows_examined: 0,
            bodies_deleted: 0,
            captures_deleted: 0,
            stored_body_bytes_deleted: 0,
            decoded_body_bytes_deleted: 0,
            stored_capture_bytes_deleted: 0,
        }
    }
}

pub(crate) async fn ensure_schema(conn: &impl Executor) -> Result<()> {
    conn.execute_batch(CANONICAL_BODY_REFERENCES_TABLE_SQL)
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    conn.execute_batch(CANONICAL_BODY_REFERENCES_INDEX_SQL)
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    conn.execute_batch(CAPTURE_REFERENCES_TABLE_SQL)
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    conn.execute_batch(CAPTURE_REFERENCES_INDEX_SQL)
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    for (_, _, sql) in OBSERVATION_REFERENCE_TRIGGERS {
        conn.execute_batch(sql)
            .await
            .map_err(|error| global_db_operation_error(OPERATION, error))?;
    }
    Ok(())
}

pub(crate) async fn replace_observation_references(
    conn: &impl Executor,
    observation_id: &str,
    json: &str,
) -> Result<()> {
    let hashes =
        collect_body_refs(json).map_err(|error| global_db_operation_error(OPERATION, error))?;
    conn.execute(
        "DELETE FROM session_canonical_body_references
         WHERE owner_kind = 'observation' AND owner_key = ?1",
        params![observation_id],
    )
    .await
    .map_err(|error| global_db_operation_error(OPERATION, error))?;
    for hash in hashes {
        conn.execute(
            INSERT_OBSERVATION_BODY_REFERENCE_SQL,
            params![observation_id, hash],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    }
    Ok(())
}

/// The writer lease, lane cancellation and commit checks are provided by the
/// canonical Database transaction. One tick examines at most one page per
/// owner family and one page per resource family, including retained rows.
pub(crate) async fn run_tick(database: &Database) -> Result<CanonicalContentGcReport> {
    database
        .write_authority()?
        .require_active_write_scope(OPERATION)?;
    let transaction = database.begin_write_transaction(OPERATION).await?;
    let owners_intact =
        crate::schema_contract::authority_invariant_triggers_intact(&transaction).await?;
    let references_intact = reference_schema_intact(&transaction).await?;
    if !owners_intact || !references_intact {
        // A later in-place guard repair cannot make the projection trusted:
        // writes while that guard was absent may have missed their pins.
        transaction.execute(
            "DELETE FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-%' OR key LIKE 'canonical-gc-%'",
            (),
        ).await.map_err(|error| global_db_operation_error(OPERATION, error))?;
        database
            .write_authority()?
            .require_active_write_scope(OPERATION)?;
        transaction.commit().await?;
        return Err(global_db_operation_message(
            OPERATION,
            "canonical owner or reference authority guards are missing or incompatible",
        ));
    }
    let report = run_page(&transaction).await?;
    database
        .write_authority()?
        .require_active_write_scope(OPERATION)?;
    transaction.commit().await?;
    Ok(report)
}

async fn run_page(conn: &impl Executor) -> Result<CanonicalContentGcReport> {
    let mut report = CanonicalContentGcReport::default();
    if !reference_schema_intact(conn).await? {
        return Err(global_db_operation_message(
            OPERATION,
            "canonical reference schema is missing or incompatible",
        ));
    }
    if !reset_reference_pages(conn, &mut report).await? {
        return Ok(report);
    }
    let observations_done = backfill_observations(conn, &mut report).await?;
    let raw_done = backfill_raw(conn, &mut report).await?;
    let captures_done = backfill_captures(conn, &mut report).await?;
    if observations_done && raw_done && captures_done {
        report.state = CanonicalContentGcState::Ready;
        let bodies_exhausted = collect_bodies(conn, &mut report).await?;
        let captures_exhausted = collect_captures(conn, &mut report).await?;
        report.pending = !bodies_exhausted || !captures_exhausted;
        if !report.pending {
            conn.execute("DELETE FROM session_backfill_meta WHERE key IN ('canonical-gc-bodies-complete', 'canonical-gc-captures-complete')", ())
                .await.map_err(|error| global_db_operation_error(OPERATION, error))?;
        }
    }
    Ok(report)
}

/// Called before schema reconstruction. Exact SQL identity uses the same
/// maintained normalization as the admitted schema contract.
pub(crate) async fn reference_schema_intact(conn: &impl QueryExecutor) -> Result<bool> {
    let objects = [
        (
            "table",
            "session_canonical_body_references",
            CANONICAL_BODY_REFERENCES_TABLE_SQL,
        ),
        (
            "index",
            "idx_session_canonical_body_references_hash",
            CANONICAL_BODY_REFERENCES_INDEX_SQL,
        ),
        (
            "table",
            "observation_repository_capture_references",
            CAPTURE_REFERENCES_TABLE_SQL,
        ),
        (
            "index",
            "idx_observation_repository_capture_references_capture",
            CAPTURE_REFERENCES_INDEX_SQL,
        ),
    ];
    for (kind, name, sql) in objects {
        if !schema_object_intact(conn, kind, name, sql).await? {
            return Ok(false);
        }
    }
    for (name, _, sql) in OBSERVATION_REFERENCE_TRIGGERS
        .iter()
        .chain(RAW_CANONICAL_BODY_REFERENCE_TRIGGERS)
    {
        if !schema_object_intact(conn, "trigger", name, sql).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn schema_object_intact(
    conn: &impl QueryExecutor,
    kind: &str,
    name: &str,
    expected: &str,
) -> Result<bool> {
    let mut rows = conn
        .query(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2 COLLATE NOCASE",
            params![kind, name],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    else {
        return Ok(false);
    };
    let actual: String = row
        .get(0)
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let expected =
        crate::schema_contract::normalize_trigger_sql(expected).replacen(" if not exists ", " ", 1);
    Ok(crate::schema_contract::normalize_trigger_sql(&actual) == expected)
}

/// Reset old projections in pages before reconstructing owner history. This
/// also removes stale pins left by damaged delete/update triggers. Current
/// writers keep pinning throughout; GC remains barred until reconstruction.
async fn reset_reference_pages(
    conn: &impl Executor,
    report: &mut CanonicalContentGcReport,
) -> Result<bool> {
    const BODY_RESET: &str = "canonical-reference-backfill-reset-bodies";
    const CAPTURE_RESET: &str = "canonical-reference-backfill-reset-captures";
    let mut bodies_done = complete(conn, BODY_RESET).await?;
    if !bodies_done {
        let after: Option<(String, String, String)> =
            metadata(conn, &format!("{BODY_RESET}-cursor"))
                .await?
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
        let mut rows = match after {
            Some((kind, key, hash)) => conn.query("SELECT owner_kind, owner_key, content_hash FROM session_canonical_body_references
                WHERE (owner_kind, owner_key, content_hash) > (?1, ?2, ?3)
                ORDER BY owner_kind, owner_key, content_hash LIMIT ?4", params![kind, key, hash, PAGE]).await,
            None => conn.query("SELECT owner_kind, owner_key, content_hash FROM session_canonical_body_references
                ORDER BY owner_kind, owner_key, content_hash LIMIT ?1", params![PAGE]).await,
        }.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let mut page = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| global_db_operation_error(OPERATION, error))?
        {
            page.push((
                row.get::<String>(0),
                row.get::<String>(1),
                row.get::<String>(2),
            ));
        }
        drop(rows);
        bodies_done = page.len() < PAGE as usize;
        let mut next_cursor = None;
        for (kind, key, hash) in page {
            let kind = kind.map_err(|error| global_db_operation_error(OPERATION, error))?;
            let key = key.map_err(|error| global_db_operation_error(OPERATION, error))?;
            let hash = hash.map_err(|error| global_db_operation_error(OPERATION, error))?;
            conn.execute("DELETE FROM session_canonical_body_references WHERE owner_kind = ?1 AND owner_key = ?2 AND content_hash = ?3", params![kind.as_str(), key.as_str(), hash.as_str()])
                .await.map_err(|error| global_db_operation_error(OPERATION, error))?;
            let cursor = serde_json::to_string(&(kind, key, hash))
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
            next_cursor = Some(cursor);
            report.owner_rows_examined += 1;
        }
        if let Some(cursor) = next_cursor {
            set_metadata(conn, &format!("{BODY_RESET}-cursor"), &cursor).await?;
        }
        if bodies_done {
            set_metadata(conn, &format!("{BODY_RESET}-complete"), "1").await?;
        }
    }
    let mut captures_done = complete(conn, CAPTURE_RESET).await?;
    if !captures_done {
        let after = metadata(conn, &format!("{CAPTURE_RESET}-cursor")).await?;
        let mut rows = match after {
            Some(after) => conn.query("SELECT observation_id FROM observation_repository_capture_references WHERE observation_id > ?1 ORDER BY observation_id LIMIT ?2", params![after, PAGE]).await,
            None => conn.query("SELECT observation_id FROM observation_repository_capture_references ORDER BY observation_id LIMIT ?1", params![PAGE]).await,
        }.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let mut page = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| global_db_operation_error(OPERATION, error))?
        {
            page.push(
                row.get::<String>(0)
                    .map_err(|error| global_db_operation_error(OPERATION, error))?,
            );
        }
        drop(rows);
        captures_done = page.len() < PAGE as usize;
        let mut next_cursor = None;
        for id in page {
            conn.execute(
                "DELETE FROM observation_repository_capture_references WHERE observation_id = ?1",
                params![id.as_str()],
            )
            .await
            .map_err(|error| global_db_operation_error(OPERATION, error))?;
            next_cursor = Some(id);
            report.owner_rows_examined += 1;
        }
        if let Some(cursor) = next_cursor {
            set_metadata(conn, &format!("{CAPTURE_RESET}-cursor"), &cursor).await?;
        }
        if captures_done {
            set_metadata(conn, &format!("{CAPTURE_RESET}-complete"), "1").await?;
        }
    }
    Ok(bodies_done && captures_done)
}

async fn metadata(conn: &impl QueryExecutor, key: &str) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT value FROM session_backfill_meta WHERE key = ?1",
            params![key],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    rows.next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
        .map(|row| {
            row.get(0)
                .map_err(|error| global_db_operation_error(OPERATION, error))
        })
        .transpose()
}

async fn set_metadata(conn: &impl Executor, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO session_backfill_meta(key, value, updated_at) VALUES (?1, ?2, unixepoch())
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value],
    )
    .await
    .map_err(|error| global_db_operation_error(OPERATION, error))?;
    Ok(())
}

async fn complete(conn: &impl QueryExecutor, family: &str) -> Result<bool> {
    Ok(metadata(conn, &format!("{family}-complete"))
        .await?
        .as_deref()
        == Some("1"))
}

async fn numeric_cursor(conn: &impl QueryExecutor, family: &str) -> Result<i64> {
    let Some(value) = metadata(conn, &format!("{family}-cursor")).await? else {
        return Ok(0);
    };
    let cursor: i64 = value
        .parse()
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    if cursor < 0 {
        return Err(global_db_operation_message(
            OPERATION,
            "negative canonical reference cursor",
        ));
    }
    Ok(cursor)
}

async fn backfill_observations(
    conn: &impl Executor,
    report: &mut CanonicalContentGcReport,
) -> Result<bool> {
    if complete(conn, OBSERVATIONS).await? {
        return Ok(true);
    }
    let after = numeric_cursor(conn, OBSERVATIONS).await?;
    let mut rows = conn
        .query(
            "SELECT sequence, observation_id, observation_json FROM observations
         WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            params![after, PAGE],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    {
        page.push((
            row.get::<i64>(0),
            row.get::<String>(1),
            row.get::<String>(2),
        ));
    }
    drop(rows);
    let exhausted = page.len() < PAGE as usize;
    let mut next = None;
    for (sequence, id, json) in page {
        let sequence = sequence.map_err(|error| global_db_operation_error(OPERATION, error))?;
        replace_observation_references(
            conn,
            &id.map_err(|error| global_db_operation_error(OPERATION, error))?,
            &json.map_err(|error| global_db_operation_error(OPERATION, error))?,
        )
        .await?;
        next = Some(sequence);
        report.owner_rows_examined += 1;
    }
    if let Some(next) = next {
        set_metadata(conn, &format!("{OBSERVATIONS}-cursor"), &next.to_string()).await?;
    }
    if exhausted {
        set_metadata(conn, &format!("{OBSERVATIONS}-complete"), "1").await?;
    }
    Ok(exhausted)
}

async fn backfill_raw(conn: &impl Executor, report: &mut CanonicalContentGcReport) -> Result<bool> {
    if complete(conn, RAW).await? {
        return Ok(true);
    }
    let after = numeric_cursor(conn, RAW).await?;
    let mut rows = conn
        .query(
            "SELECT store_id, content_hash FROM lcm_raw_messages
        WHERE store_id > ?1 ORDER BY store_id LIMIT ?2",
            params![after, PAGE],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    {
        page.push((row.get::<i64>(0), row.get::<String>(1)));
    }
    drop(rows);
    let exhausted = page.len() < PAGE as usize;
    let mut next = None;
    for (id, hash) in page {
        let id = id.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let hash = hash.map_err(|error| global_db_operation_error(OPERATION, error))?;
        conn.execute(
            "INSERT OR IGNORE INTO session_canonical_body_references
            (owner_kind, owner_key, content_hash) VALUES ('raw', ?1, ?2)",
            params![id.to_string(), hash],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
        next = Some(id);
        report.owner_rows_examined += 1;
    }
    if let Some(next) = next {
        set_metadata(conn, &format!("{RAW}-cursor"), &next.to_string()).await?;
    }
    if exhausted {
        set_metadata(conn, &format!("{RAW}-complete"), "1").await?;
    }
    Ok(exhausted)
}

async fn backfill_captures(
    conn: &impl Executor,
    report: &mut CanonicalContentGcReport,
) -> Result<bool> {
    if complete(conn, CAPTURES).await? {
        return Ok(true);
    }
    let after = metadata(conn, &format!("{CAPTURES}-cursor")).await?;
    let mut rows = match after {
        Some(after) => {
            conn.query(
                "SELECT observation_id, json_extract(capture_json, '$.capture_id')
            FROM observation_repository_provenance WHERE observation_id > ?1
            ORDER BY observation_id LIMIT ?2",
                params![after, PAGE],
            )
            .await
        }
        None => {
            conn.query(
                "SELECT observation_id, json_extract(capture_json, '$.capture_id')
            FROM observation_repository_provenance ORDER BY observation_id LIMIT ?1",
                params![PAGE],
            )
            .await
        }
    }
    .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    {
        page.push((row.get::<String>(0), row.get::<Option<String>>(1)));
    }
    drop(rows);
    let exhausted = page.len() < PAGE as usize;
    let mut next = None;
    for (id, hash) in page {
        let id = id.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let hash = hash.map_err(|error| global_db_operation_error(OPERATION, error))?;
        conn.execute(
            "DELETE FROM observation_repository_capture_references WHERE observation_id = ?1",
            params![id.as_str()],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
        if let Some(hash) = hash {
            conn.execute("INSERT INTO observation_repository_capture_references(observation_id, capture_id) VALUES (?1, ?2)", params![id.as_str(), hash])
                .await.map_err(|error| global_db_operation_error(OPERATION, error))?;
        }
        next = Some(id);
        report.owner_rows_examined += 1;
    }
    if let Some(next) = next {
        set_metadata(conn, &format!("{CAPTURES}-cursor"), &next).await?;
    }
    if exhausted {
        set_metadata(conn, &format!("{CAPTURES}-complete"), "1").await?;
    }
    Ok(exhausted)
}

async fn collect_bodies(
    conn: &impl Executor,
    report: &mut CanonicalContentGcReport,
) -> Result<bool> {
    if complete(conn, "canonical-gc-bodies").await? {
        return Ok(true);
    }
    let cursor_key = "canonical-gc-bodies-cursor";
    let after = metadata(conn, cursor_key)
        .await?
        .filter(|value| !value.is_empty());
    let mut rows = match after {
        Some(after) => conn.query("SELECT content_hash, length(body), uncompressed_bytes FROM session_canonical_bodies
            WHERE content_hash > ?1 ORDER BY content_hash LIMIT ?2", params![after, PAGE]).await,
        None => conn.query("SELECT content_hash, length(body), uncompressed_bytes FROM session_canonical_bodies
            ORDER BY content_hash LIMIT ?1", params![PAGE]).await,
    }.map_err(|error| global_db_operation_error(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    {
        page.push((row.get::<String>(0), row.get::<i64>(1), row.get::<i64>(2)));
    }
    drop(rows);
    let exhausted = page.len() < PAGE as usize;
    let mut last = String::new();
    for (hash, stored, decoded) in page {
        let hash = hash.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let stored =
            u64::try_from(stored.map_err(|error| global_db_operation_error(OPERATION, error))?)
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
        let decoded =
            u64::try_from(decoded.map_err(|error| global_db_operation_error(OPERATION, error))?)
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
        let removed = conn.execute("DELETE FROM session_canonical_bodies WHERE content_hash = ?1
            AND NOT EXISTS(SELECT 1 FROM session_canonical_body_references WHERE content_hash = ?1)", params![hash.as_str()])
            .await.map_err(|error| global_db_operation_error(OPERATION, error))?;
        report.body_rows_examined += 1;
        if removed > 0 {
            report.bodies_deleted += 1;
            report.stored_body_bytes_deleted += stored;
            report.decoded_body_bytes_deleted += decoded;
        }
        last = hash;
    }
    set_metadata(conn, cursor_key, if exhausted { "" } else { &last }).await?;
    if exhausted {
        set_metadata(conn, "canonical-gc-bodies-complete", "1").await?;
    }
    Ok(exhausted)
}

async fn collect_captures(
    conn: &impl Executor,
    report: &mut CanonicalContentGcReport,
) -> Result<bool> {
    if complete(conn, "canonical-gc-captures").await? {
        return Ok(true);
    }
    let cursor_key = "canonical-gc-captures-cursor";
    let after = metadata(conn, cursor_key)
        .await?
        .filter(|value| !value.is_empty());
    let mut rows = match after {
        Some(after) => conn.query("SELECT capture_id, length(CAST(capture_json AS BLOB)) FROM observation_repository_captures
            WHERE capture_id > ?1 ORDER BY capture_id LIMIT ?2", params![after, PAGE]).await,
        None => conn.query("SELECT capture_id, length(CAST(capture_json AS BLOB)) FROM observation_repository_captures
            ORDER BY capture_id LIMIT ?1", params![PAGE]).await,
    }.map_err(|error| global_db_operation_error(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
    {
        page.push((row.get::<String>(0), row.get::<i64>(1)));
    }
    drop(rows);
    let exhausted = page.len() < PAGE as usize;
    let mut last = String::new();
    for (id, stored) in page {
        let id = id.map_err(|error| global_db_operation_error(OPERATION, error))?;
        let stored =
            u64::try_from(stored.map_err(|error| global_db_operation_error(OPERATION, error))?)
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
        let removed = conn.execute("DELETE FROM observation_repository_captures WHERE capture_id = ?1
            AND NOT EXISTS(SELECT 1 FROM observation_repository_capture_references WHERE capture_id = ?1)", params![id.as_str()])
            .await.map_err(|error| global_db_operation_error(OPERATION, error))?;
        report.capture_rows_examined += 1;
        if removed > 0 {
            report.captures_deleted += 1;
            report.stored_capture_bytes_deleted += stored;
        }
        last = id;
    }
    set_metadata(conn, cursor_key, if exhausted { "" } else { &last }).await?;
    if exhausted {
        set_metadata(conn, "canonical-gc-captures-complete", "1").await?;
    }
    Ok(exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracedecay_runtime_core::db::engine::TestConnection;
    use tracedecay_store::{
        BODY_REF_KEY, CANONICAL_BODIES_TABLE_SQL, StoredCanonicalBody, UPSERT_CANONICAL_BODY_SQL,
    };

    async fn fixture() -> (tempfile::TempDir, TestConnection) {
        let directory = tempfile::tempdir().unwrap();
        let conn = TestConnection::open(&directory.path().join("sessions.db"));
        conn.execute_batch("CREATE TABLE session_backfill_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT (unixepoch()));
            CREATE TABLE observations(sequence INTEGER PRIMARY KEY, observation_id TEXT UNIQUE, observation_json TEXT NOT NULL);
            CREATE TABLE observation_repository_captures(capture_id TEXT PRIMARY KEY, capture_json TEXT NOT NULL);
            CREATE TABLE observation_repository_provenance(observation_id TEXT PRIMARY KEY, capture_json TEXT);
            CREATE TABLE sessions(session_id TEXT PRIMARY KEY);
            CREATE TABLE lcm_raw_messages(store_id INTEGER PRIMARY KEY, session_id TEXT REFERENCES sessions(session_id) ON DELETE CASCADE, content_hash TEXT NOT NULL);").await.unwrap();
        conn.execute_batch(CANONICAL_BODIES_TABLE_SQL)
            .await
            .unwrap();
        ensure_schema(&conn).await.unwrap();
        for (_, _, sql) in RAW_CANONICAL_BODY_REFERENCE_TRIGGERS {
            conn.execute_batch(sql).await.unwrap();
        }
        (directory, conn)
    }

    async fn body(conn: &impl Executor, text: &str) -> StoredCanonicalBody {
        let body = StoredCanonicalBody::pack(text.as_bytes()).unwrap();
        conn.execute(
            UPSERT_CANONICAL_BODY_SQL,
            params![
                body.content_hash.as_str(),
                body.encoding,
                body.blob.as_slice(),
                body.uncompressed_bytes
            ],
        )
        .await
        .unwrap();
        body
    }

    async fn count(conn: &impl QueryExecutor, sql: &str) -> i64 {
        conn.query(sql, ())
            .await
            .unwrap()
            .next()
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap()
    }

    async fn finish(conn: &impl Executor) -> Vec<CanonicalContentGcReport> {
        let mut reports = Vec::new();
        for _ in 0..100 {
            let report = run_page(conn).await.unwrap();
            let pending = report.pending;
            assert!(report.owner_rows_examined <= 5 * PAGE as u64);
            assert!(report.body_rows_examined <= PAGE as u64);
            assert!(report.capture_rows_examined <= PAGE as u64);
            reports.push(report);
            if !pending {
                return reports;
            }
        }
        panic!("bounded fixture work must exhaust");
    }

    #[asupersync::test]
    async fn shared_bodies_and_captures_survive_until_every_owner_releases() {
        let (_directory, conn) = fixture().await;
        let original = "shared canonical text ".repeat(4096);
        let packed = body(&conn, &original).await;
        let json =
            serde_json::json!({"payload": null, (BODY_REF_KEY): {"/payload": packed.content_hash}})
                .to_string();
        for index in 1..=2 {
            conn.execute(
                "INSERT INTO observations VALUES (?1, ?2, ?3)",
                params![index, format!("obs.{index}"), json.as_str()],
            )
            .await
            .unwrap();
            conn.execute("INSERT INTO observation_repository_provenance VALUES (?1, '{\"capture_id\":\"capture.shared\"}')", params![format!("obs.{index}")]).await.unwrap();
        }
        conn.execute("INSERT INTO observation_repository_captures VALUES ('capture.shared', '{\"evidence\":\"shared\"}')", ()).await.unwrap();
        conn.execute("INSERT INTO sessions VALUES ('session.shared')", ())
            .await
            .unwrap();
        conn.execute(
            "INSERT INTO lcm_raw_messages VALUES (1, 'session.shared', ?1)",
            params![packed.content_hash.as_str()],
        )
        .await
        .unwrap();
        finish(&conn).await;
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
        conn.execute(
            "UPDATE observations SET observation_json = '{}' WHERE observation_id = 'obs.1'",
            (),
        )
        .await
        .unwrap();
        conn.execute("UPDATE observation_repository_provenance SET capture_json = '{}' WHERE observation_id = 'obs.1'", ()).await.unwrap();
        let first = run_page(&conn).await.unwrap();
        assert_eq!((first.bodies_deleted, first.captures_deleted), (0, 0));
        assert_eq!(
            super::super::canonical_bodies::load_canonical_body(&conn, &packed.content_hash)
                .await
                .unwrap(),
            original.as_bytes()
        );
        conn.execute(
            "DELETE FROM observations WHERE observation_id = 'obs.2'",
            (),
        )
        .await
        .unwrap();
        conn.execute(
            "DELETE FROM observation_repository_provenance WHERE observation_id = 'obs.2'",
            (),
        )
        .await
        .unwrap();
        let capture_release = run_page(&conn).await.unwrap();
        assert_eq!(
            (
                capture_release.bodies_deleted,
                capture_release.captures_deleted
            ),
            (0, 1)
        );
        conn.execute(
            "DELETE FROM sessions WHERE session_id = 'session.shared'",
            (),
        )
        .await
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM lcm_raw_messages").await,
            0
        );
        let final_release = run_page(&conn).await.unwrap();
        assert_eq!(
            (final_release.bodies_deleted, final_release.captures_deleted),
            (1, 0)
        );
        assert_eq!(
            final_release.stored_body_bytes_deleted,
            packed.blob.len() as u64
        );
        assert_eq!(
            final_release.decoded_body_bytes_deleted,
            original.len() as u64
        );
        assert!(final_release.stored_body_bytes_deleted < final_release.decoded_body_bytes_deleted);
    }

    #[asupersync::test]
    async fn root_map_precedence_and_typed_missing_corruption_survive_collection() {
        let (_directory, conn) = fixture().await;
        let live = body(&conn, "canonical root content").await;
        let metadata_body = body(&conn, "provider metadata is not a canonical reference").await;
        let json = serde_json::json!({
            "payload": {"text": null, "metadata": {"tracedecay.body_ref": metadata_body.content_hash}},
            (BODY_REF_KEY): {"/payload/text": live.content_hash},
        }).to_string();
        conn.execute(
            "INSERT INTO observations VALUES (1, 'root', ?1)",
            params![json.as_str()],
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO observations VALUES (2, 'missing', ?1)",
            params![serde_json::json!({"payload": {"tracedecay.body_ref":"missing"}}).to_string()],
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO observations VALUES (3, 'corrupt', ?1)",
            params![
                serde_json::json!({"payload": null, (BODY_REF_KEY): {"/payload":"corrupt"}})
                    .to_string()
            ],
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO session_canonical_bodies VALUES ('corrupt', 'identity', X'61', 1)",
            (),
        )
        .await
        .unwrap();
        let reports = finish(&conn).await;
        assert_eq!(
            reports
                .iter()
                .map(|report| report.bodies_deleted)
                .sum::<u64>(),
            1
        );
        let mut hydrated: serde_json::Value = serde_json::from_str(&json).unwrap();
        tracedecay_store::hydrate_json_value(&mut hydrated, |_| live.unpack()).unwrap();
        assert_eq!(hydrated["payload"]["text"], "canonical root content");
        assert_eq!(
            hydrated["payload"]["metadata"]["tracedecay.body_ref"],
            metadata_body.content_hash
        );
        for (hash, missing) in [("missing", true), ("corrupt", false)] {
            let error = super::super::canonical_bodies::load_canonical_body(&conn, hash)
                .await
                .unwrap_err();
            let tracedecay_store::ObservationStoreError::Storage { source, .. } = error else {
                panic!("typed body failure required");
            };
            assert!(if missing {
                matches!(
                    source.downcast_ref::<tracedecay_store::CanonicalBodyError>(),
                    Some(tracedecay_store::CanonicalBodyError::Missing { .. })
                )
            } else {
                matches!(
                    source.downcast_ref::<tracedecay_store::CanonicalBodyError>(),
                    Some(tracedecay_store::CanonicalBodyError::Corrupt { .. })
                )
            });
        }
    }

    #[asupersync::test]
    async fn raw_hash_replacement_releases_only_the_previous_hash() {
        let (_directory, conn) = fixture().await;
        let old = body(&conn, "old body").await;
        let new = body(&conn, "new body").await;
        conn.execute("INSERT INTO sessions VALUES ('session')", ())
            .await
            .unwrap();
        conn.execute(
            "INSERT INTO lcm_raw_messages VALUES (1, 'session', ?1)",
            params![old.content_hash.as_str()],
        )
        .await
        .unwrap();
        // Replacement during reconstruction is protected by the current row trigger.
        conn.execute(
            "UPDATE lcm_raw_messages SET content_hash = ?1 WHERE store_id = 1",
            params![new.content_hash.as_str()],
        )
        .await
        .unwrap();
        finish(&conn).await;
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
        assert_eq!(
            super::super::canonical_bodies::load_canonical_body(&conn, &new.content_hash)
                .await
                .unwrap(),
            b"new body"
        );
    }

    #[asupersync::test]
    async fn legacy_dangling_refs_and_lower_keys_added_during_backfill_stay_pinned() {
        let (_directory, conn) = fixture().await;
        for index in 1..=PAGE + 1 {
            conn.execute(
                "INSERT INTO observations VALUES (?1, ?2, '{}')",
                params![index, format!("z.{index:03}")],
            )
            .await
            .unwrap();
        }
        let late = body(&conn, "a body inserted after the first historical page").await;
        let first = run_page(&conn).await.unwrap();
        assert_eq!(first.state, CanonicalContentGcState::Backfilling);
        assert_eq!(first.bodies_deleted, 0);
        let legacy = serde_json::json!({"payload": {"tracedecay.body_ref": "missing"}}).to_string();
        conn.execute(
            "INSERT INTO observations VALUES (66, 'legacy', ?1)",
            params![legacy],
        )
        .await
        .unwrap();
        let json =
            serde_json::json!({"payload": null, (BODY_REF_KEY): {"/payload": late.content_hash}})
                .to_string();
        conn.execute(
            "INSERT INTO observations VALUES (67, 'a.lower-key', ?1)",
            params![json.as_str()],
        )
        .await
        .unwrap();
        // The production inserter pins in the insertion savepoint, including
        // lexical keys behind a prior sweep's key cursor.
        replace_observation_references(&conn, "a.lower-key", &json)
            .await
            .unwrap();
        finish(&conn).await;
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM session_canonical_body_references WHERE content_hash = 'missing'").await, 1);
        assert_eq!(
            super::super::canonical_bodies::load_canonical_body(&conn, &late.content_hash)
                .await
                .unwrap(),
            b"a body inserted after the first historical page"
        );
    }

    #[asupersync::test]
    async fn collection_bounds_retained_pages_resets_and_revisits_later_release() {
        let (_directory, conn) = fixture().await;
        for index in 1..=2 * PAGE + 1 {
            let hash = format!("{index:064x}");
            conn.execute(
                "INSERT INTO session_canonical_bodies VALUES (?1, 'identity', X'61', 1)",
                params![hash.as_str()],
            )
            .await
            .unwrap();
            let json = serde_json::json!({"payload": null, (BODY_REF_KEY): {"/payload": hash}})
                .to_string();
            conn.execute(
                "INSERT INTO observations VALUES (?1, ?2, ?3)",
                params![index, format!("obs.{index}"), json],
            )
            .await
            .unwrap();
        }
        let reports = finish(&conn).await;
        assert!(
            reports
                .iter()
                .any(|report| report.body_rows_examined == PAGE as u64 && report.pending)
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.body_rows_examined)
                .sum::<u64>(),
            (2 * PAGE + 1) as u64
        );
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            2 * PAGE + 1
        );
        conn.execute(
            "UPDATE observations SET observation_json = '{}' WHERE sequence = 1",
            (),
        )
        .await
        .unwrap();
        let next = run_page(&conn).await.unwrap();
        assert_eq!(
            next.bodies_deleted, 1,
            "the exhausted pass resets to the first resource key"
        );
    }

    #[asupersync::test]
    async fn resource_families_finish_independently_without_restarting_smaller_sweep() {
        let (_directory, conn) = fixture().await;
        for index in 1..=2 * PAGE {
            let hash = format!("{index:064x}");
            conn.execute(
                "INSERT INTO session_canonical_bodies VALUES (?1, 'identity', X'61', 1)",
                params![hash.as_str()],
            )
            .await
            .unwrap();
            let json = serde_json::json!({"payload": null, (BODY_REF_KEY): {"/payload": hash}})
                .to_string();
            conn.execute(
                "INSERT INTO observations VALUES (?1, ?2, ?3)",
                params![index, format!("obs.{index}"), json],
            )
            .await
            .unwrap();
        }
        for index in 1..=PAGE {
            conn.execute(
                "INSERT INTO observation_repository_captures VALUES (?1, '{}')",
                params![format!("capture.{index:03}")],
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO observation_repository_provenance VALUES (?1, ?2)",
                params![
                    format!("obs.{index}"),
                    serde_json::json!({"capture_id": format!("capture.{index:03}")}).to_string()
                ],
            )
            .await
            .unwrap();
        }
        let reports = finish(&conn).await;
        assert_eq!(
            reports
                .iter()
                .map(|report| report.body_rows_examined)
                .sum::<u64>(),
            (2 * PAGE) as u64
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.capture_rows_examined)
                .sum::<u64>(),
            PAGE as u64
        );
        assert_eq!(
            reports
                .iter()
                .filter(|report| report.state == CanonicalContentGcState::Ready)
                .count(),
            3
        );
    }

    #[asupersync::test]
    async fn malformed_legacy_backfill_and_missing_guards_bar_collection() {
        let (_directory, conn) = fixture().await;
        body(&conn, "unreferenced but unsafe to collect").await;
        conn.execute(
            "INSERT INTO observations VALUES (1, 'invalid', ?1)",
            params![format!("{{\"{BODY_REF_KEY}\":42}}")],
        )
        .await
        .unwrap();
        assert!(run_page(&conn).await.is_err());
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
        assert!(!complete(&conn, OBSERVATIONS).await.unwrap());
        conn.execute("DELETE FROM observations", ()).await.unwrap();
        finish(&conn).await;
        let guarded = body(&conn, "body behind a missing writer guard").await;
        conn.execute_batch("DROP TRIGGER lcm_raw_canonical_refs_insert")
            .await
            .unwrap();
        assert!(!reference_schema_intact(&conn).await.unwrap());
        conn.execute("INSERT INTO sessions VALUES ('session')", ())
            .await
            .unwrap();
        conn.execute(
            "INSERT INTO lcm_raw_messages VALUES (1, 'session', ?1)",
            params![guarded.content_hash.as_str()],
        )
        .await
        .unwrap();
        assert!(run_page(&conn).await.is_err());
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
    }

    async fn assert_reference_counts(conn: &impl QueryExecutor, expected: i64) {
        assert_eq!(
            count(
                conn,
                "SELECT COUNT(*) FROM session_canonical_body_references"
            )
            .await,
            expected
        );
        assert_eq!(
            count(
                conn,
                "SELECT COUNT(*) FROM observation_repository_capture_references"
            )
            .await,
            expected
        );
    }

    #[asupersync::test]
    async fn reference_reset_cursor_failure_rolls_back_both_owner_pages() {
        let harness = crate::tests::harness::RegisteredGlobalDbHarness::open(
            "canonical-reference-reset-rollback",
        )
        .await;
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        transaction
            .execute(
                "DELETE FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-%'",
                (),
            )
            .await
            .unwrap();
        for index in 0..=PAGE {
            let id = format!("historical-{index:03}");
            transaction.execute(
                "INSERT INTO session_canonical_body_references (owner_kind, owner_key, content_hash) VALUES ('observation', ?1, ?2)",
                params![id.as_str(), format!("body-{index:03}")],
            ).await.unwrap();
            transaction.execute(
                "INSERT INTO observation_repository_capture_references (observation_id, capture_id) VALUES (?1, ?2)",
                params![id.as_str(), format!("capture-{index:03}")],
            ).await.unwrap();
        }
        transaction
            .execute_batch(
                "CREATE TRIGGER reject_capture_reset_cursor BEFORE INSERT ON session_backfill_meta
             WHEN NEW.key = 'canonical-reference-backfill-reset-captures-cursor'
             BEGIN SELECT RAISE(ABORT, 'refuse capture reset cursor'); END;",
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        assert!(harness.registered.run_canonical_content_gc().await.is_err());
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_reference_counts(&snapshot, PAGE + 1).await;
        assert_eq!(count(&snapshot, "SELECT COUNT(*) FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-reset-%'").await, 0);
        drop(snapshot);

        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        transaction
            .execute_batch("DROP TRIGGER reject_capture_reset_cursor")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let report = harness.registered.run_canonical_content_gc().await.unwrap();
        assert_eq!(report.owner_rows_examined, u64::try_from(2 * PAGE).unwrap());
        assert_eq!(report.state, CanonicalContentGcState::Backfilling);
        assert!(report.pending);
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_reference_counts(&snapshot, 1).await;
        let body_cursor: (String, String, String) = serde_json::from_str(
            &metadata(
                &snapshot,
                "canonical-reference-backfill-reset-bodies-cursor",
            )
            .await
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body_cursor,
            (
                "observation".to_owned(),
                format!("historical-{:03}", PAGE - 1),
                format!("body-{:03}", PAGE - 1)
            )
        );
        assert_eq!(
            metadata(
                &snapshot,
                "canonical-reference-backfill-reset-captures-cursor"
            )
            .await
            .unwrap()
            .unwrap(),
            format!("historical-{:03}", PAGE - 1)
        );
        drop(snapshot);

        let report = harness.registered.run_canonical_content_gc().await.unwrap();
        assert_eq!(report.owner_rows_examined, 2);
        assert_eq!(report.state, CanonicalContentGcState::Ready);
        assert!(!report.pending);
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_reference_counts(&snapshot, 0).await;
    }

    #[asupersync::test]
    async fn registered_collector_refuses_damaged_observation_immutability_guard() {
        let harness = crate::tests::harness::RegisteredGlobalDbHarness::open(
            "canonical-immutable-owner-guard",
        )
        .await;
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        body(&transaction, "orphan behind an unsafe owner authority").await;
        transaction
            .execute_batch("DROP TRIGGER observations_immutable_update")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        assert!(harness.registered.run_canonical_content_gc().await.is_err());
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_eq!(
            count(&snapshot, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
        assert_eq!(
            count(
                &snapshot,
                "SELECT COUNT(*) FROM session_backfill_meta WHERE key LIKE 'canonical-gc-%'"
            )
            .await,
            0
        );
    }

    #[asupersync::test]
    async fn registered_guard_refusal_invalidates_trust_before_in_place_repair() {
        let harness =
            crate::tests::harness::RegisteredGlobalDbHarness::open("canonical-guard-repair").await;
        assert!(
            !harness
                .registered
                .run_canonical_content_gc()
                .await
                .unwrap()
                .pending
        );
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        transaction
            .execute_batch("DROP TRIGGER lcm_raw_canonical_refs_insert")
            .await
            .unwrap();
        let original = "canonical body inserted while its pin guard was absent".repeat(256);
        let packed = body(&transaction, &original).await;
        body(&transaction, "unowned body from the same damaged interval").await;
        transaction.execute("INSERT INTO sessions(provider, session_id, project_key, project_path) VALUES ('codex', 'guard-repair', 'profile', '/fixture')", ()).await.unwrap();
        transaction.execute(
            "INSERT INTO lcm_raw_messages(provider, message_id, session_id, role, ordinal, content_hash, storage_kind)
             VALUES ('codex', 'guard-repair-message', 'guard-repair', 'assistant', 1, ?1, 'inline')",
            params![packed.content_hash.as_str()],
        ).await.unwrap();
        transaction.commit().await.unwrap();
        assert!(harness.registered.run_canonical_content_gc().await.is_err());
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_eq!(count(&snapshot, "SELECT COUNT(*) FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-%' OR key LIKE 'canonical-gc-%'").await, 0);
        assert_eq!(
            count(&snapshot, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            2
        );
        drop(snapshot);
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        transaction
            .execute_batch(RAW_CANONICAL_BODY_REFERENCE_TRIGGERS[0].2)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let mut finished = false;
        for _ in 0..10 {
            if !harness
                .registered
                .run_canonical_content_gc()
                .await
                .unwrap()
                .pending
            {
                finished = true;
                break;
            }
        }
        assert!(finished, "the reconstructed bounded pass finishes");
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_eq!(
            count(&snapshot, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1,
            "the unowned body is collected after reconstruction"
        );
        assert_eq!(
            count(
                &snapshot,
                "SELECT COUNT(*) FROM session_canonical_body_references WHERE owner_kind = 'raw'"
            )
            .await,
            1,
            "reconstruction discovers the missed owner before collection"
        );
        assert_eq!(
            super::super::canonical_bodies::load_canonical_body(&snapshot, &packed.content_hash)
                .await
                .unwrap(),
            original.as_bytes()
        );
    }

    #[asupersync::test]
    async fn registered_readmission_invalidates_completed_reference_trust_before_reconstruction() {
        for damage in [
            "DROP TRIGGER lcm_raw_canonical_refs_insert",
            "DROP TABLE session_canonical_body_references",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("sessions.db");
            let (database, owner) = crate::tests::harness::open_registered_test_database_fixture(
                &path,
                tracedecay_runtime_core::db::TestDatabaseRuntimeScope::ProfileSessions,
            )
            .await
            .unwrap();
            let report = database.run_canonical_content_gc().await.unwrap();
            assert!(!report.pending);
            let transaction = database.begin_write_transaction().await.unwrap();
            transaction.execute("INSERT OR REPLACE INTO session_backfill_meta(key, value) VALUES ('canonical-reference-backfill-observations-cursor', '1000')", ()).await.unwrap();
            transaction.execute_batch(damage).await.unwrap();
            transaction.commit().await.unwrap();
            drop((database, owner));
            let (database, _owner) = crate::tests::harness::open_registered_test_database_fixture(
                &path,
                tracedecay_runtime_core::db::TestDatabaseRuntimeScope::ProfileSessions,
            )
            .await
            .unwrap();
            let snapshot = database.read_snapshot().await.unwrap();
            assert!(reference_schema_intact(&snapshot).await.unwrap());
            assert_eq!(count(&snapshot, "SELECT COUNT(*) FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-%' OR key LIKE 'canonical-gc-%'").await, 0, "reconstruction must not preserve a completed old projection's trust: {damage}");
            drop(snapshot);
            assert!(!database.run_canonical_content_gc().await.unwrap().pending);
        }
    }

    #[asupersync::test]
    async fn registered_observation_writer_pins_replay_and_rolls_back_collision() {
        use tracedecay_domain::{
            ComponentVersion, DurableObservationV1, PayloadReferenceV1, ProjectionGenerationId,
            SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1,
            SanitizerDispositionV1, SensitivityV1, UtcMicros,
        };
        use tracedecay_store::{
            AnchoredObservationWrite, ObservationStore, ObservationWrite,
            build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
        };
        let harness =
            crate::tests::harness::RegisteredGlobalDbHarness::open("canonical-observation-writer")
                .await;
        let store = harness.registered.observation_store();
        let (base, cursor) =
            crate::schema_contract::invariants::test_fixture::authority_fixture(0, "canonical");
        let text = "canonical production body ".repeat(4096);
        let mut payload = base.payload().clone();
        payload["native_record_kind"] = serde_json::json!("message");
        payload["facts"] = serde_json::json!([{ "kind": "message", "role": "assistant", "content": {"text": text}, "timestamp": 0 }]);
        let build = |payload: serde_json::Value| {
            let receipt = SanitizationReceiptV1::new(
                SanitizationReceiptRefV1::new(
                    SanitizationReceiptId::new("receipt.canonical").unwrap(),
                    ComponentVersion::new("sanitizer.canonical.v1").unwrap(),
                )
                .unwrap(),
                SanitizerDispositionV1::Accepted,
                SensitivityV1::NonSensitive,
                Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
            )
            .unwrap();
            let observation = DurableObservationV1::new(
                base.identity().clone(),
                receipt,
                base.retention_class().clone(),
                payload,
            )
            .unwrap();
            let write = ObservationWrite::new(observation.clone(), None, cursor.clone()).unwrap();
            let generation = ProjectionGenerationId::new("projection.canonical.v1").unwrap();
            let authorization =
                build_observation_resolution_authorization_v1(&observation, "canonical").unwrap();
            let anchor = build_observation_retrieval_anchor(
                &observation,
                generation.clone(),
                UtcMicros(1),
                authorization,
            )
            .unwrap();
            (
                observation,
                AnchoredObservationWrite::new(write, anchor, generation).unwrap(),
            )
        };
        let (original, write) = build(payload.clone());
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        body(&transaction, &text).await;
        transaction.commit().await.unwrap();
        // Whichever writer wins, collection and insertion share the canonical
        // lane. A later insert recreates a collected body and pins it atomically.
        let (collected, committed) = futures_util::join!(
            harness.registered.run_canonical_content_gc(),
            store.persist_observation(write.clone()),
        );
        collected.unwrap();
        committed.unwrap();
        store.persist_observation(write).await.unwrap();
        let mut changed = payload;
        changed["facts"][0]["content"]["text"] = serde_json::json!("colliding body ".repeat(4096));
        let (_, collision) = build(changed);
        assert!(store.persist_observation(collision).await.is_err());
        let gc = harness.registered.run_canonical_content_gc().await.unwrap();
        assert_eq!(
            gc.bodies_deleted, 0,
            "a failed collision leaves no committed orphan body"
        );
        let snapshot = harness.registered.read_snapshot().await.unwrap();
        assert_eq!(
            count(&snapshot, "SELECT COUNT(*) FROM session_canonical_bodies").await,
            1
        );
        assert_eq!(count(&snapshot, "SELECT COUNT(*) FROM session_canonical_body_references WHERE owner_kind = 'observation'").await, 1);
        drop(snapshot);
        assert_eq!(
            store
                .get_observation(original.observation_id())
                .await
                .unwrap()
                .unwrap()
                .observation(),
            &original
        );
        // A failed collector transaction must not commit partial checkpoint or deletion work.
        let transaction = harness.registered.begin_write_transaction().await.unwrap();
        transaction
            .execute_batch("DROP TRIGGER observations_immutable_update")
            .await
            .unwrap();
        transaction
            .execute(
                "UPDATE observations SET observation_json = ?1",
                params![format!("{{\"{BODY_REF_KEY}\":42}}")],
            )
            .await
            .unwrap();
        transaction
            .execute(
                "DELETE FROM session_backfill_meta WHERE key LIKE 'canonical-reference-backfill-%'",
                (),
            )
            .await
            .unwrap();
        assert!(run_page(&transaction).await.is_err());
        drop(transaction);
        assert_eq!(
            store
                .get_observation(original.observation_id())
                .await
                .unwrap()
                .unwrap()
                .observation(),
            &original
        );
    }
}
