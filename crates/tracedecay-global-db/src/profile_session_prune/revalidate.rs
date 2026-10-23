//! Source-local apply validation. The lookup is prepared explicitly offline,
//! never by schema admission, planning, or a bounded apply page.

use super::{PruneSource, add_ownership, error};
use sha2::{Digest, Sha256};
use tracedecay_domain::errors::Result;
use tracedecay_domain::{ObservationScopeV1, ObservationSourceCursorV1};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_store::SESSION_MESSAGE_PROJECTOR_VERSION;

pub(super) const LOOKUP_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS idx_profile_prune_source
    ON observations (
        json_extract(committed_cursor_json, '$.source.provider'),
        json_extract(committed_cursor_json, '$.source.session_id'),
        coalesce(json_extract(committed_cursor_json, '$.source.source_key'), ''),
        json_extract(committed_cursor_json, '$.scope.kind'), sequence
    );";
const MAX_ROWS: usize = 4096;
const MAX_JSON_BYTES: u64 = 8 * 1024 * 1024;

const SOURCE_ROWS_SQL: &str = "SELECT o.sequence, o.observation_id, o.payload_digest, o.observation_json,
                (EXISTS (SELECT 1 FROM observation_projection_provenance p
                         WHERE p.projector_version=?6 AND p.observation_id=o.observation_id)
                 OR EXISTS (SELECT 1 FROM observation_projection_dispositions d
                         WHERE d.projector_version=?6 AND d.observation_id=o.observation_id))
                AND NOT EXISTS (SELECT 1 FROM projection_queue q WHERE q.observation_id=o.observation_id),
                o.committed_cursor_json
             FROM observations o INDEXED BY idx_profile_prune_source
             WHERE json_extract(committed_cursor_json, '$.source.provider')=?1
               AND json_extract(committed_cursor_json, '$.source.session_id')=?2
               AND coalesce(json_extract(committed_cursor_json, '$.source.source_key'), '')=?3
               AND json_extract(committed_cursor_json, '$.scope.kind')='profile'
               AND sequence>?4
             ORDER BY sequence LIMIT ?5";

pub(super) enum SourceValidation {
    Complete(Option<PruneSource>),
    BudgetExceeded,
}

/// The original passive census validates every committed cursor against its
/// hydrated observation identity. Both are immutable. This index therefore
/// enumerates authoritative membership, unlike optional source-presence rows.
/// An absent/misshaped index refuses before touching any candidate body.
pub(super) async fn source_evidence(
    read: &impl QueryExecutor,
    approved: &PruneSource,
) -> Result<SourceValidation> {
    if approved.scope != ObservationScopeV1::Profile {
        return Err(error("source revalidation requires profile ownership"));
    }
    let mut versions = read
        .query("PRAGMA schema_version", ())
        .await
        .map_err(error)?;
    let schema: i64 = versions
        .next()
        .await
        .map_err(error)?
        .ok_or_else(|| error("missing schema version"))?
        .get(0)
        .map_err(error)?;
    drop(versions);
    let mut explain = read
        .query(
            &format!("EXPLAIN QUERY PLAN {SOURCE_ROWS_SQL} /* schema {schema} */"),
            params![
                approved.source.provider().as_str(),
                approved.source.session_id().as_str(),
                approved
                    .source
                    .explicit_source_key()
                    .map_or("", |key| key.as_str()),
                0_i64,
                super::MAX_PAGE as i64,
                SESSION_MESSAGE_PROJECTOR_VERSION
            ],
        )
        .await
        .map_err(error)?;
    let mut indexed = false;
    while let Some(row) = explain.next().await.map_err(error)? {
        let detail: String = row.get(3).map_err(error)?;
        if detail.starts_with("SEARCH o USING INDEX idx_profile_prune_source")
            && detail.matches("<expr>=?").count() == 4
            && detail.contains("sequence>?")
        {
            indexed = true;
        }
        if detail.starts_with("SCAN ")
            || detail.contains("TEMP B-TREE")
            || detail.contains("AUTOMATIC")
        {
            return Err(error(
                "prune source validation requires indexed lookups without whole-store scans",
            ));
        }
    }
    drop(explain);
    if !indexed {
        return Err(error(
            "prune source lookup index must be explicitly prepared offline",
        ));
    }
    let mut source = approved.clone();
    source.project_roots.clear();
    source.locations.clear();
    source.observation_count = 0;
    source.observation_json_bytes = 0;
    source.pending = false;
    source.ambiguous = false;
    source.last_sequence = 0;
    let mut fingerprint = Sha256::new();
    loop {
        let mut rows = read
            .query(
                SOURCE_ROWS_SQL,
                params![
                    approved.source.provider().as_str(),
                    approved.source.session_id().as_str(),
                    approved
                        .source
                        .explicit_source_key()
                        .map_or("", |key| key.as_str()),
                    source.last_sequence,
                    super::MAX_PAGE as i64,
                    SESSION_MESSAGE_PROJECTOR_VERSION
                ],
            )
            .await
            .map_err(error)?;
        let mut page = Vec::new();
        while let Some(row) = rows.next().await.map_err(error)? {
            page.push((
                row.get::<i64>(0).map_err(error)?,
                row.get::<String>(1).map_err(error)?,
                row.get::<String>(2).map_err(error)?,
                row.get::<String>(3).map_err(error)?,
                row.get::<i64>(4).map_err(error)? != 0,
                row.get::<String>(5).map_err(error)?,
            ));
        }
        drop(rows);
        if page.is_empty() {
            break;
        }
        for (sequence, id, digest, json, settled, cursor_json) in page {
            source.observation_count += 1;
            source.observation_json_bytes += json.len() as u64;
            if source.observation_count > MAX_ROWS as u64
                || source.observation_json_bytes > MAX_JSON_BYTES
            {
                return Ok(SourceValidation::BudgetExceeded);
            }
            let observation =
                crate::observation::decode_observation_json(read, &json, super::OPERATION)
                    .await
                    .map_err(error)?;
            validate_cursor(&cursor_json, &observation)?;
            if observation.source() != &approved.source || observation.scope() != &approved.scope {
                return Err(error(
                    "indexed source identity disagrees with canonical ownership",
                ));
            }
            fingerprint
                .update(serde_json::to_vec(&(sequence, &id, &digest, settled)).map_err(error)?);
            source.last_sequence = sequence;
            source.pending |= !settled;
            add_ownership(&mut source, &observation);
        }
    }
    if source.observation_count == 0 {
        return Ok(SourceValidation::Complete(None));
    }
    source.evidence_digest = hex::encode(fingerprint.finalize());
    let mut rows = read
        .query(
            "SELECT 1 FROM sessions WHERE provider=?1 AND session_id=?2",
            params![
                source.source.provider().as_str(),
                source.source.session_id().as_str()
            ],
        )
        .await
        .map_err(error)?;
    source.has_session_row = rows.next().await.map_err(error)?.is_some();
    Ok(SourceValidation::Complete(Some(source)))
}

pub(super) fn validate_cursor(
    json: &str,
    observation: &tracedecay_domain::DurableObservationV1,
) -> Result<()> {
    let cursor: ObservationSourceCursorV1 = serde_json::from_str(json).map_err(error)?;
    if cursor.source() != observation.source() || cursor.scope() != observation.scope() {
        return Err(error(
            "committed cursor disagrees with canonical source ownership",
        ));
    }
    Ok(())
}
