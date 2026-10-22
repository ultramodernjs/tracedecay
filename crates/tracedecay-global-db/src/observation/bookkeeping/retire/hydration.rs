//! Size-only authorization preflight. Never fetch a canonical blob here.

use std::collections::BTreeMap;

use super::*;
use tracedecay_store::canonical_body::{BODY_REF_KEY, stored_json_needs_hydrate};

// Count expansions, not unique hashes: the decoder loads each distinct body
// once but clones it into every referenced JSON string, including legacy rows.
fn legacy_references(value: &serde_json::Value, references: &mut BTreeMap<String, u64>) {
    match value {
        serde_json::Value::Object(object) => {
            if object.len() == 1
                && let Some(hash) = object
                    .get("tracedecay.body_ref")
                    .and_then(serde_json::Value::as_str)
            {
                *references.entry(hash.to_owned()).or_default() += 1;
                return;
            }
            for child in object.values() {
                legacy_references(child, references);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                legacy_references(child, references);
            }
        }
        _ => {}
    }
}

pub(super) async fn preflight(
    conn: &impl QueryExecutor,
    json: &str,
    evidence: &mut Vec<String>,
    budget: &mut CaptureBudget,
) -> ProjectionStoreResult<()> {
    if !stored_json_needs_hydrate(json) {
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(json).map_err(storage)?;
    let mut references = BTreeMap::<String, u64>::new();
    if let Some(root) = value.get(BODY_REF_KEY) {
        let paths: BTreeMap<String, String> =
            serde_json::from_value(root.clone()).map_err(storage)?;
        for hash in paths.into_values() {
            *references.entry(hash).or_default() += 1;
        }
    } else {
        legacy_references(&value, &mut references);
    }
    require_index(conn, "session_canonical_bodies", "content_hash", "").await?;
    for (body_hash, copies) in references {
        let mut rows = conn.query(
            "SELECT length(body), uncompressed_bytes FROM session_canonical_bodies WHERE content_hash=?1",
            params![body_hash.as_str()],
        ).await.map_err(storage)?;
        let row = rows
            .next()
            .await
            .map_err(storage)?
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        let compressed: u64 = row.get(0).map_err(storage)?;
        let expanded: u64 = row.get(1).map_err(storage)?;
        let charge = expanded
            .checked_mul(copies)
            .and_then(|bytes| bytes.checked_add(compressed))
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        budget.charge(1, charge)?;
        evidence.push(hash(&(
            "canonical-body-hydration.v1",
            body_hash,
            compressed,
            expanded,
            copies,
        ))?);
    }
    Ok(())
}
