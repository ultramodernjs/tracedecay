//! Read retained ownership evidence without decoding released ledger skeletons.

use tracedecay_domain::CanonicalObservationIdV1;
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_store::{ObservationCommitReceipt, ObservationStoreResult};

use super::codec::{decode_sequence, storage, storage_message};
use super::persist::read_by_observation_id;

const OPERATION: &str = "read session ownership evidence";

/// The caller holds one read snapshot across enumeration and hydration so a
/// concurrent retention pass cannot replace a checked payload with a tombstone.
pub(crate) async fn read_page(
    snapshot: &impl QueryExecutor,
    after_sequence: u64,
    limit: usize,
) -> ObservationStoreResult<Vec<(u64, Option<ObservationCommitReceipt>)>> {
    let after = i64::try_from(after_sequence).map_err(|error| storage(OPERATION, error))?;
    let limit = i64::try_from(limit).map_err(|error| storage(OPERATION, error))?;
    let mut rows = snapshot
        .query(
            "SELECT sequence, observation_id FROM observations
             WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            params![after, limit],
        )
        .await
        .map_err(|error| storage(OPERATION, error))?;
    let mut page = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| storage(OPERATION, error))?
    {
        page.push((
            decode_sequence(
                row.get::<i64>(0)
                    .map_err(|error| storage(OPERATION, error))?,
                OPERATION,
            )?,
            CanonicalObservationIdV1::new(
                row.get::<String>(1)
                    .map_err(|error| storage(OPERATION, error))?,
            )
            .map_err(|error| storage(OPERATION, error))?,
        ));
    }
    drop(rows);
    let mut records = Vec::with_capacity(page.len());
    for (sequence, id) in page {
        let receipt = read_retained(snapshot, &id).await?;
        records.push((sequence, receipt));
    }
    Ok(records)
}

/// Missing or normally released targets cannot prove ownership. Malformed live
/// evidence and storage failures still propagate instead of becoming a skip.
pub(crate) async fn read_retained(
    snapshot: &impl QueryExecutor,
    observation_id: &CanonicalObservationIdV1,
) -> ObservationStoreResult<Option<ObservationCommitReceipt>> {
    let mut rows = snapshot
        .query(
            "SELECT observation.sequence, observation.observation_json,
                    anchor.anchor_json, repository.availability_json,
                    repository.capture_json, repository_anchor.anchor_json,
                    repository.owner_json
             FROM observations AS observation
             LEFT JOIN observation_retrieval_anchors AS binding
               ON binding.observation_id = observation.observation_id
             LEFT JOIN retrieval_anchors AS anchor ON anchor.anchor_id = binding.anchor_id
             LEFT JOIN observation_repository_provenance AS repository
               ON repository.observation_id = observation.observation_id
             LEFT JOIN retrieval_anchors AS repository_anchor
               ON repository_anchor.anchor_id = repository.retrieval_anchor_id
             WHERE observation.observation_id = ?1",
            params![observation_id.as_str()],
        )
        .await
        .map_err(|error| storage(OPERATION, error))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|error| storage(OPERATION, error))?
    else {
        return Ok(None);
    };
    let sequence = decode_sequence(
        row.get::<i64>(0)
            .map_err(|error| storage(OPERATION, error))?,
        OPERATION,
    )?;
    let mut released = false;
    for (column, kind) in [
        (1, "observation"),
        (2, "anchor"),
        (3, "provenance"),
        (4, "provenance"),
        (5, "anchor"),
    ] {
        if let Some(json) = row
            .get::<Option<String>>(column)
            .map_err(|error| storage(OPERATION, error))?
        {
            let value: serde_json::Value =
                serde_json::from_str(&json).map_err(|error| storage(OPERATION, error))?;
            if let Some(marker) = value.get("__retention_released") {
                if marker.as_str() != Some(kind)
                    || value.as_object().is_none_or(|object| object.len() != 1)
                {
                    return Err(storage_message(OPERATION, "invalid retention tombstone"));
                }
                released = true;
            }
        }
    }
    let repository_owner = row
        .get::<Option<String>>(6)
        .map_err(|error| storage(OPERATION, error))?;
    drop(rows);
    if released {
        return Ok(None);
    }
    let receipt = read_by_observation_id(snapshot, observation_id)
        .await?
        .ok_or_else(|| storage_message(OPERATION, "live observation evidence is missing"))?;
    let observation = receipt.observation();
    let cursor = receipt.committed_cursor();
    if receipt.sequence() != sequence
        || observation.observation_id() != observation_id
        || observation.source() != cursor.source()
        || observation.scope() != cursor.scope()
        || observation.identity().generation() != cursor.generation()
        || observation.identity().ordering_domain() != cursor.ordering_domain()
        || observation.identity().position().end() != cursor.position()
    {
        return Err(storage_message(
            OPERATION,
            "observation row binding mismatch",
        ));
    }
    let expected_repository_owner = receipt
        .repository_provenance_attachment()
        .anchor()
        .map(|anchor| serde_json::to_string(anchor.owner()))
        .transpose()
        .map_err(|error| storage(OPERATION, error))?;
    if repository_owner != expected_repository_owner {
        return Err(storage_message(
            OPERATION,
            "repository owner binding mismatch",
        ));
    }
    Ok(Some(receipt))
}
