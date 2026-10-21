//! Bounded historical conversion and orphan collection. All plans are read-only;
//! apply requires the matching digest and the caller's writer transaction.

use serde::Serialize;
use tracedecay_domain::canonical_sha256;
use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};

use super::{compact, normalize};
use crate::LcmError;

#[derive(Clone, Debug, Serialize)]
struct ReceiptRow {
    store_id: i64,
    original: Option<String>,
    compact: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReceiptCompactionPlan {
    digest: String,
    after: i64,
    max_rows: usize,
    max_bytes: usize,
    rows: Vec<ReceiptRow>,
    has_more: bool,
}

impl ReceiptCompactionPlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn scanned_rows(&self) -> usize {
        self.rows.len()
    }
    pub fn changed_rows(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.original != row.compact)
            .count()
    }
    pub fn next_cursor(&self) -> Option<i64> {
        self.rows.last().map(|row| row.store_id)
    }
    pub fn has_more(&self) -> bool {
        self.has_more
    }
}

async fn store_fingerprint(
    conn: &(impl QueryExecutor + ?Sized),
) -> Result<(String, i64), LcmError> {
    let mut rows = conn.query("PRAGMA database_list", ()).await?;
    let mut file = String::new();
    while let Some(row) = rows.next().await? {
        if row.get::<String>(1)? == "main" {
            file = row.get(2)?;
        }
    }
    drop(rows);
    let mut rows = conn.query("PRAGMA schema_version", ()).await?;
    let schema = rows
        .next()
        .await?
        .ok_or(LcmError::PayloadIntegrityMismatch)?
        .get(0)?;
    Ok((file, schema))
}

pub async fn plan_receipt_compaction(
    conn: &(impl QueryExecutor + ?Sized),
    after: i64,
    max_rows: usize,
    max_bytes: usize,
) -> Result<ReceiptCompactionPlan, LcmError> {
    if max_rows == 0 || max_bytes == 0 {
        return Err(LcmError::PayloadIntegrityMismatch);
    }
    let max_rows = max_rows.min(1_000);
    let max_bytes = max_bytes.min(4 * 1024 * 1024);
    // QueryExecutor eagerly materializes returned rows. Bound payload bytes in
    // SQL, before transport; the lookahead carries only IDs and byte lengths.
    let mut source = conn
        .query(
            "WITH candidates AS MATERIALIZED (
            SELECT store_id, COALESCE(length(CAST(metadata_json AS BLOB)), 0) + 8 AS bytes
            FROM lcm_raw_messages WHERE store_id > ?1 ORDER BY store_id LIMIT ?2
         ), sized AS (
            SELECT store_id, bytes, SUM(bytes) OVER (ORDER BY store_id) AS total_bytes
            FROM candidates
         )
         SELECT raw.store_id,
                CASE WHEN sized.total_bytes <= ?3 THEN raw.metadata_json END,
                sized.bytes, sized.total_bytes
         FROM sized JOIN lcm_raw_messages raw ON raw.store_id = sized.store_id
         ORDER BY sized.store_id",
            params![after, max_rows as i64 + 1, max_bytes as i64],
        )
        .await?;
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    let mut has_more = false;
    while let Some(row) = source.next().await? {
        let size =
            usize::try_from(row.get::<i64>(2)?).map_err(|_| LcmError::PayloadIntegrityMismatch)?;
        if rows.len() == max_rows || (!rows.is_empty() && bytes.saturating_add(size) > max_bytes) {
            has_more = true;
            break;
        }
        if size > max_bytes {
            return Err(LcmError::PayloadIntegrityMismatch);
        }
        let original: Option<String> = row.get(1)?;
        if original.as_ref().map_or(0, String::len) + 8 != size {
            return Err(LcmError::PayloadIntegrityMismatch);
        }
        let (compact, _) = compact(original.as_deref())?;
        rows.push(ReceiptRow {
            store_id: row.get(0)?,
            original,
            compact,
        });
        bytes += size;
    }
    drop(source);
    let fingerprint = store_fingerprint(conn).await?;
    let digest = canonical_sha256(&(
        "tracedecay.lcm.receipt-compaction.v1",
        fingerprint,
        after,
        max_rows,
        max_bytes,
        &rows,
        has_more,
    ))
    .map_err(|_| LcmError::PayloadIntegrityMismatch)?
    .as_str()
    .to_owned();
    Ok(ReceiptCompactionPlan {
        digest,
        after,
        max_rows,
        max_bytes,
        rows,
        has_more,
    })
}

/// An inner savepoint makes a failed page atomic even if the caller catches
/// the error and commits its outer transaction.
pub async fn apply_receipt_compaction(
    conn: &(impl Executor + ?Sized),
    plan: &ReceiptCompactionPlan,
    confirmed_digest: &str,
) -> Result<usize, LcmError> {
    if confirmed_digest != plan.digest {
        return Err(LcmError::PayloadIntegrityMismatch);
    }
    conn.execute_batch("SAVEPOINT lcm_receipt_compaction")
        .await?;
    let outcome = async {
        let current = plan_receipt_compaction(conn, plan.after, plan.max_rows, plan.max_bytes).await?;
        if current.digest != plan.digest {
            return Err(LcmError::PayloadIntegrityMismatch);
        }
        let mut triggers = Vec::new();
        if current.changed_rows() != 0 {
            let mut source = conn.query(
                "SELECT name, sql FROM sqlite_schema WHERE type = 'trigger' AND name IN (
                    'lcm_summary_convergence_raw_unprotected_update',
                    'lcm_raw_messages_fts_update',
                    'lcm_raw_messages_gc_candidate_update',
                    'projection_raw_audit_invalidate_update_v1'
                 ) ORDER BY name", (),
            ).await?;
            while let Some(row) = source.next().await? {
                triggers.push((row.get::<String>(0)?, row.get::<String>(1)?));
            }
            drop(source);
            for (name, _) in &triggers {
                conn.execute_batch(&format!("DROP TRIGGER {name}")).await?;
            }
        }
        let mut changed = 0;
        for row in &current.rows {
            if row.original == row.compact { continue; }
            let compact = normalize(conn, row.original.as_deref()).await?;
            // Projection digests bind the metadata string, not only parsed
            // JSON. Require byte-identical hydrated input before bypassing
            // convergence/index/audit work. Receipt owner triggers still run.
            let original = super::hydrate_metadata(conn, row.original.as_deref()).await?;
            let hydrated = super::hydrate_metadata(conn, compact.as_deref()).await?;
            if hydrated != original {
                return Err(LcmError::PayloadIntegrityMismatch);
            }
            let count = conn.execute("UPDATE lcm_raw_messages SET metadata_json = ?1 WHERE store_id = ?2 AND metadata_json IS ?3", params![compact.as_deref(), row.store_id, row.original.as_deref()]).await?;
            if count != 1 { return Err(LcmError::PayloadIntegrityMismatch); }
            changed += 1;
        }
        for (_, sql) in &triggers {
            conn.execute_batch(sql).await?;
        }
        Ok(changed)
    }.await;
    match outcome {
        Ok(changed) => {
            conn.execute_batch("RELEASE lcm_receipt_compaction").await?;
            Ok(changed)
        }
        Err(error) => {
            conn.execute_batch(
                "ROLLBACK TO lcm_receipt_compaction; RELEASE lcm_receipt_compaction",
            )
            .await?;
            Err(error)
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReceiptGcPlan {
    digest: String,
    max_rows: usize,
    keys: Vec<String>,
}
impl ReceiptGcPlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn rows(&self) -> usize {
        self.keys.len()
    }
}

pub async fn plan_receipt_gc(
    conn: &(impl QueryExecutor + ?Sized),
    max_rows: usize,
) -> Result<ReceiptGcPlan, LcmError> {
    if max_rows == 0 {
        return Err(LcmError::PayloadIntegrityMismatch);
    }
    let max_rows = max_rows.min(1_000);
    let mut rows = conn.query("SELECT receipt_key FROM lcm_sanitization_receipts_v1 WHERE owner_count = 0 ORDER BY receipt_key LIMIT ?1", params![max_rows as i64]).await?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next().await? {
        keys.push(row.get(0)?);
    }
    drop(rows);
    let digest = canonical_sha256(&(
        "tracedecay.lcm.receipt-gc.v1",
        store_fingerprint(conn).await?,
        max_rows,
        &keys,
    ))
    .map_err(|_| LcmError::PayloadIntegrityMismatch)?
    .as_str()
    .to_owned();
    Ok(ReceiptGcPlan {
        digest,
        max_rows,
        keys,
    })
}

pub async fn apply_receipt_gc(
    conn: &(impl Executor + ?Sized),
    plan: &ReceiptGcPlan,
    confirmed_digest: &str,
) -> Result<usize, LcmError> {
    if confirmed_digest != plan.digest
        || plan_receipt_gc(conn, plan.max_rows).await?.digest != plan.digest
    {
        return Err(LcmError::PayloadIntegrityMismatch);
    }
    conn.execute_batch("SAVEPOINT lcm_receipt_gc").await?;
    let outcome = async {
        for key in &plan.keys {
            if conn.execute("DELETE FROM lcm_sanitization_receipts_v1 WHERE receipt_key = ?1 AND owner_count = 0", params![key.as_str()]).await? != 1 { return Err(LcmError::PayloadIntegrityMismatch); }
        }
        Ok(plan.keys.len())
    }.await;
    match outcome {
        Ok(count) => {
            conn.execute_batch("RELEASE lcm_receipt_gc").await?;
            Ok(count)
        }
        Err(error) => {
            conn.execute_batch("ROLLBACK TO lcm_receipt_gc; RELEASE lcm_receipt_gc")
                .await?;
            Err(error)
        }
    }
}
