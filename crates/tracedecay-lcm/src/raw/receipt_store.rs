//! Content-addressed, LCM-owned receipt material. References stay in their raw owner row.

#[path = "receipt_compaction.rs"]
mod compaction;
pub use compaction::*;

use serde_json::{Value, json};
use tracedecay_domain::{SanitizationReceiptV1, canonical_sha256};
use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};

use crate::LcmError;

const FIELDS: [&str; 2] = ["sanitization_receipt", "metadata_sanitization_receipt"];
const REFERENCE: &str = "lcm_receipt_v1";

// Match serde_json::Value's canonical map order exactly: projection output
// digests bind the metadata string, not just its parsed JSON value.
pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS lcm_sanitization_receipts_v1 (
    receipt_key TEXT PRIMARY KEY NOT NULL,
    material_json TEXT NOT NULL CHECK(json_valid(material_json) AND json_type(material_json) = 'array' AND json_array_length(material_json) = 6),
    receipt_json TEXT GENERATED ALWAYS AS (json_object(
        'disposition', json_extract(material_json, '$[2]'),
        'payload', CASE WHEN json_extract(material_json, '$[4]') IS NULL THEN NULL ELSE json_object('byte_len', json_extract(material_json, '$[5]'), 'digest', json_extract(material_json, '$[4]')) END,
        'receipt', json_object('receipt_id', json_extract(material_json, '$[0]'), 'sanitizer_version', json_extract(material_json, '$[1]')),
        'sensitivity', json_extract(material_json, '$[3]')
    )) VIRTUAL,
    owner_count INTEGER NOT NULL DEFAULT 0 CHECK(owner_count >= 0)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS lcm_sanitization_receipts_immutable_update_v1
BEFORE UPDATE OF receipt_key, material_json ON lcm_sanitization_receipts_v1 BEGIN
    SELECT RAISE(ABORT, 'LCM sanitization receipts are immutable');
END;
CREATE TRIGGER IF NOT EXISTS lcm_sanitization_receipts_referenced_delete_v1
BEFORE DELETE ON lcm_sanitization_receipts_v1 WHEN OLD.owner_count <> 0 BEGIN
    SELECT RAISE(ABORT, 'LCM sanitization receipt still has owners');
END;
CREATE INDEX IF NOT EXISTS idx_lcm_receipts_unowned_v1
ON lcm_sanitization_receipts_v1(receipt_key) WHERE owner_count = 0;";

pub(crate) async fn ensure_schema(conn: &(impl Executor + ?Sized)) -> Result<(), LcmError> {
    conn.execute_batch(SCHEMA).await?;
    let component = "lcm-sanitization-receipts-v1";
    if tracedecay_runtime_core::db::schema_version::read_version(conn, component)
        .await
        .map_err(|error| LcmError::Db(error.to_string()))?
        .is_none()
    {
        tracedecay_runtime_core::db::schema_version::record_version(conn, component, 1)
            .await
            .map_err(|error| LcmError::Db(error.to_string()))?;
    }
    Ok(())
}

fn key(value: &Value) -> Result<String, LcmError> {
    // Domain decoding validates revision, disposition, sensitivity and payload shape.
    let receipt: SanitizationReceiptV1 =
        serde_json::from_value(value.clone()).map_err(|_| LcmError::PayloadIntegrityMismatch)?;
    canonical_sha256(&("tracedecay.lcm.sanitization-receipt.v1", receipt))
        .map(|digest| digest.as_str().to_owned())
        .map_err(|_| LcmError::PayloadIntegrityMismatch)
}

type CompactMetadata = (Option<String>, Vec<(String, Value)>);

pub(super) fn compact(metadata: Option<&str>) -> Result<CompactMetadata, LcmError> {
    let Some(metadata) = metadata else {
        return Ok((None, Vec::new()));
    };
    let mut value: Value =
        serde_json::from_str(metadata).map_err(|_| LcmError::PayloadIntegrityMismatch)?;
    let Some(protection) = value
        .get_mut("ingest_protection")
        .and_then(Value::as_object_mut)
    else {
        return Ok((Some(metadata.to_owned()), Vec::new()));
    };
    let mut receipts = Vec::new();
    for field in FIELDS {
        let Some(receipt) = protection.get(field) else {
            continue;
        };
        if let Some(reference) = receipt.get(REFERENCE) {
            if reference.as_str().is_none()
                || receipt.as_object().map(|object| object.len()) != Some(1)
            {
                return Err(LcmError::PayloadIntegrityMismatch);
            }
            continue;
        }
        let receipt_key = key(receipt)?;
        receipts.push((receipt_key.clone(), receipt.clone()));
        protection.insert(field.to_owned(), json!({REFERENCE: receipt_key}));
    }
    if receipts.is_empty() {
        return Ok((Some(metadata.to_owned()), receipts));
    }
    Ok((Some(value.to_string()), receipts))
}

pub(super) async fn normalize(
    conn: &(impl Executor + ?Sized),
    metadata: Option<&str>,
) -> Result<Option<String>, LcmError> {
    let (compact, receipts) = compact(metadata)?;
    for (receipt_key, receipt) in receipts {
        let encoded = json!([
            receipt["receipt"]["receipt_id"],
            receipt["receipt"]["sanitizer_version"],
            receipt["disposition"],
            receipt["sensitivity"],
            receipt["payload"]["digest"],
            receipt["payload"]["byte_len"]
        ])
        .to_string();
        conn.execute("INSERT INTO lcm_sanitization_receipts_v1(receipt_key, material_json) VALUES (?1, ?2) ON CONFLICT(receipt_key) DO NOTHING", params![receipt_key.as_str(), encoded.as_str()]).await?;
        let mut rows = conn
            .query(
                "SELECT receipt_json FROM lcm_sanitization_receipts_v1 WHERE receipt_key = ?1",
                params![receipt_key.as_str()],
            )
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or(LcmError::PayloadIntegrityMismatch)?;
        let stored: String = row.get(0)?;
        if serde_json::from_str::<Value>(&stored).map_err(|_| LcmError::PayloadIntegrityMismatch)?
            != receipt
        {
            return Err(LcmError::PayloadIntegrityMismatch);
        }
    }
    hydrate_metadata(conn, compact.as_deref()).await?;
    Ok(compact)
}

/// Resolves receipt references and verifies each content-addressed binding.
/// The returned document is for semantic reads; retain `metadata` itself for CAS.
pub async fn hydrate_metadata(
    conn: &(impl QueryExecutor + ?Sized),
    metadata: Option<&str>,
) -> Result<Option<String>, LcmError> {
    let mut rows = conn
        .query(
            &format!(
                "SELECT {} FROM (SELECT ?1 AS metadata_json) raw",
                stored_metadata_sql("raw")
            ),
            params![metadata],
        )
        .await?;
    let hydrated: Option<String> = rows
        .next()
        .await?
        .ok_or(LcmError::PayloadIntegrityMismatch)?
        .get(0)?;
    validate_hydration(metadata, hydrated.as_deref())?;
    Ok(hydrated)
}

// Owner counts live in the dictionary, not a second per-message binding table.
// No historical scan is needed: pre-migration owners carry inline receipts.
pub(crate) async fn ensure_owner_triggers(conn: &(impl Executor + ?Sized)) -> Result<(), LcmError> {
    for (event, old, new) in [
        ("INSERT", false, true),
        ("DELETE", true, false),
        ("UPDATE", true, true),
    ] {
        let mut body = String::new();
        for (enabled, alias, delta) in [(old, "OLD", "- 1"), (new, "NEW", "+ 1")] {
            if !enabled {
                continue;
            }
            for field in FIELDS {
                body.push_str(&format!("UPDATE lcm_sanitization_receipts_v1 SET owner_count = owner_count {delta} WHERE receipt_key = CASE WHEN json_valid({alias}.metadata_json) THEN json_extract({alias}.metadata_json, '$.ingest_protection.{field}.lcm_receipt_v1') END;"));
            }
        }
        let operation = if event == "UPDATE" {
            "UPDATE OF metadata_json"
        } else {
            event
        };
        let condition = if event == "UPDATE" {
            "WHEN OLD.metadata_json IS NOT NEW.metadata_json"
        } else {
            ""
        };
        conn.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS lcm_raw_receipt_owners_{}_v1 AFTER {operation} ON lcm_raw_messages {condition} BEGIN {body} END;", event.to_ascii_lowercase())).await?;
    }
    Ok(())
}

pub(super) fn validate_hydration(
    stored: Option<&str>,
    hydrated: Option<&str>,
) -> Result<(), LcmError> {
    let Some(stored) = stored else {
        return Ok(());
    };
    let stored: Value =
        serde_json::from_str(stored).map_err(|_| LcmError::PayloadIntegrityMismatch)?;
    let hydrated: Value = hydrated
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| LcmError::PayloadIntegrityMismatch)?
        .unwrap_or(Value::Null);
    for field in FIELDS {
        let original = &stored["ingest_protection"][field];
        if let Some(reference) = original.get(REFERENCE)
            && (original.as_object().map(|object| object.len()) != Some(1)
                || reference.as_str() != Some(key(&hydrated["ingest_protection"][field])?.as_str()))
        {
            return Err(LcmError::PayloadIntegrityMismatch);
        }
    }
    Ok(())
}

// SQL adapters hydrate receipts without changing the public stored-message shape.
macro_rules! hydrated_metadata {
    ($metadata:literal) => { concat!(
        "(WITH lcm_receipt_input AS (SELECT ", $metadata, " AS original),
        lcm_receipt_body AS (
            SELECT original, CASE WHEN json_valid(original) AND json_type(original, '$.ingest_protection.sanitization_receipt.lcm_receipt_v1') = 'text'
            THEN json_set(original, '$.ingest_protection.sanitization_receipt', json((
                SELECT receipt_json FROM lcm_sanitization_receipts_v1
                WHERE receipt_key = json_extract(original, '$.ingest_protection.sanitization_receipt.lcm_receipt_v1')
            ))) ELSE original END AS body FROM lcm_receipt_input
        ) SELECT CASE WHEN json_valid(original) AND json_type(original, '$.ingest_protection.metadata_sanitization_receipt.lcm_receipt_v1') = 'text'
            THEN json_set(body, '$.ingest_protection.metadata_sanitization_receipt', json((
                SELECT receipt_json FROM lcm_sanitization_receipts_v1
                WHERE receipt_key = json_extract(original, '$.ingest_protection.metadata_sanitization_receipt.lcm_receipt_v1')
            ))) ELSE body END FROM lcm_receipt_body)"
    ) };
}
pub(super) use hydrated_metadata;

pub(super) fn stored_metadata_sql(alias: &str) -> String {
    hydrated_metadata!("__RAW_METADATA__")
        .replace("__RAW_METADATA__", &format!("{alias}.metadata_json"))
}
