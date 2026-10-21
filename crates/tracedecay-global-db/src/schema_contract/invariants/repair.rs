use std::collections::BTreeSet;

use tracedecay_domain::{ObservationOrderingDomainV1, ObservationSourceCursorV1};
use tracedecay_store::SESSION_MESSAGE_PROJECTOR_VERSION;
use tracedecay_store::observation::ObservationCoverageV1;

use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, params};
use tracedecay_rusqlite_runtime::repository::observation_cursor_authority::PRUNE_SUPERSEDED_CURSOR_ADVANCES_SQL;

use super::rows::{
    audit_read_error, authority_violation, decode_authority_json, encode_authority_json,
};
use super::{AUDIT_PAGE_ROWS, OBSERVATION_AUDIT_PAGE_ROWS};

struct CommittedCursorCandidate {
    source_json: String,
    scope_json: String,
    cursor_json: String,
    cursor: ObservationSourceCursorV1,
}

/// Reads the current observation frontier: `COALESCE(MAX(sequence), 0)` over
/// `observations`. The row cursor lives only inside this function, so it is
/// fully consumed and dropped before returning, see
/// `observation_projection::rebuild::read_observation_frontier` for why a
/// caller doing further reads or writes on the same connection depends on
/// that.
async fn read_observation_frontier(
    conn: &impl QueryExecutor,
) -> tracedecay_domain::errors::Result<i64> {
    let mut rows = conn
        .query("SELECT MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'observations'), 0), COALESCE(MAX(sequence), 0)) FROM observations", ())
        .await
        .map_err(audit_read_error)?;
    rows.next()
        .await
        .map_err(audit_read_error)?
        .ok_or_else(|| authority_violation("observation frontier query returned no row"))?
        .get::<i64>(0)
        .map_err(audit_read_error)
}

#[cfg(test)]
pub(super) async fn repair_projection_frontier(
    conn: &impl Executor,
    trusted_checkpoint: i64,
) -> tracedecay_domain::errors::Result<i64> {
    loop {
        if let Some(frontier) = repair_projection_frontier_page(conn, trusted_checkpoint).await? {
            return Ok(frontier);
        }
    }
}

/// Coverage, queue cleanup, and queue reconstruction each commit one keyset
/// page. The journal is work progress, never projection content authority.
pub(super) async fn repair_projection_frontier_page(
    conn: &impl Executor,
    trusted_checkpoint: i64,
) -> tracedecay_domain::errors::Result<Option<i64>> {
    let mut rows = conn
        .query(
            "SELECT COALESCE((SELECT last_sequence FROM observation_projection_checkpoints
         WHERE projector_version = ?1), 0)",
            params![SESSION_MESSAGE_PROJECTOR_VERSION],
        )
        .await
        .map_err(audit_read_error)?;
    let stored = rows
        .next()
        .await
        .map_err(audit_read_error)?
        .ok_or_else(|| authority_violation("projection checkpoint query returned no row"))?
        .get::<i64>(0)
        .map_err(audit_read_error)?;
    drop(rows);
    let mut rows = conn
        .query(
            "SELECT original_checkpoint, observation_frontier, scan_sequence, repaired_checkpoint,
                queue_rowid, enqueue_sequence, stage
         FROM authority_projection_repair_progress WHERE audit_name = ?1",
            params![SESSION_MESSAGE_PROJECTOR_VERSION],
        )
        .await
        .map_err(audit_read_error)?;
    let state = rows
        .next()
        .await
        .map_err(audit_read_error)?
        .map(|row| -> tracedecay_domain::errors::Result<_> {
            Ok((
                row.get::<i64>(0).map_err(audit_read_error)?,
                row.get::<i64>(1).map_err(audit_read_error)?,
                row.get::<i64>(2).map_err(audit_read_error)?,
                row.get::<i64>(3).map_err(audit_read_error)?,
                row.get::<i64>(4).map_err(audit_read_error)?,
                row.get::<i64>(5).map_err(audit_read_error)?,
                row.get::<String>(6).map_err(audit_read_error)?,
            ))
        })
        .transpose()?;
    drop(rows);
    let state = match state {
        Some(state) if state.0 == stored => state,
        _ => {
            // A projector may commit between repair pages. Rebase the repair
            // on its durable frontier rather than overwrite its newer result.
            let frontier = read_observation_frontier(conn).await?;
            let target = stored.min(frontier);
            let start = if target < trusted_checkpoint {
                0
            } else {
                trusted_checkpoint
            };
            conn.execute(
                "INSERT INTO authority_projection_repair_progress
                 (audit_name, original_checkpoint, observation_frontier, scan_sequence,
                  repaired_checkpoint, queue_rowid, enqueue_sequence, stage)
                 VALUES (?1, ?2, ?3, ?4, ?4, 0, ?4, 'coverage')
                 ON CONFLICT(audit_name) DO UPDATE SET
                  original_checkpoint = excluded.original_checkpoint,
                  observation_frontier = excluded.observation_frontier,
                  scan_sequence = excluded.scan_sequence,
                  repaired_checkpoint = excluded.repaired_checkpoint,
                  queue_rowid = 0, enqueue_sequence = excluded.enqueue_sequence, stage = 'coverage'",
                params![SESSION_MESSAGE_PROJECTOR_VERSION, stored, frontier, start],
            ).await.map_err(audit_read_error)?;
            return Ok(None);
        }
    };
    let (original, frontier, mut scan, mut repaired, queue_rowid, mut enqueue, stage) = state;
    if original < 0
        || frontier < 0
        || scan < 0
        || repaired < 0
        || queue_rowid < 0
        || enqueue < 0
        || scan > frontier
        || repaired > scan
        || enqueue > frontier
    {
        return Err(authority_violation(
            "projection repair journal contains invalid progress",
        ));
    }
    match stage.as_str() {
        "coverage" => {
            let mut rows = conn.query(
                "SELECT observation.sequence,
                    ((EXISTS(SELECT 1 FROM observation_projection_provenance AS provenance
                        WHERE provenance.projector_version = ?1 AND provenance.observation_id = observation.observation_id)
                      OR EXISTS(SELECT 1 FROM observation_workflow_facts AS workflow
                        WHERE workflow.projector_version = ?1 AND workflow.observation_id = observation.observation_id))
                      + EXISTS(SELECT 1 FROM observation_projection_dispositions AS disposition
                        WHERE disposition.projector_version = ?1 AND disposition.observation_id = observation.observation_id))
                 FROM observations AS observation WHERE sequence > ?2 AND sequence <= ?3
                 ORDER BY sequence LIMIT ?4",
                params![SESSION_MESSAGE_PROJECTOR_VERSION, scan, original.min(frontier), AUDIT_PAGE_ROWS],
            ).await.map_err(audit_read_error)?;
            let mut count = 0;
            let mut gap = false;
            while let Some(row) = rows.next().await.map_err(audit_read_error)? {
                scan = row.get(0).map_err(audit_read_error)?;
                count += 1;
                if row.get::<i64>(1).map_err(audit_read_error)? != 1 {
                    gap = true;
                    break;
                }
                repaired = scan;
            }
            drop(rows);
            if gap || count < AUDIT_PAGE_ROWS {
                if !gap {
                    // An absent identity below the allocated high-water was
                    // retired, not an uncovered retained observation.
                    repaired = original.min(frontier);
                    scan = scan.max(repaired);
                }
                conn.execute(
                    "UPDATE observation_projection_checkpoints SET last_sequence = ?2
                     WHERE projector_version = ?1 AND last_sequence = ?3",
                    params![SESSION_MESSAGE_PROJECTOR_VERSION, repaired, original],
                )
                .await
                .map_err(audit_read_error)?;
                conn.execute(
                    "UPDATE authority_projection_repair_progress SET original_checkpoint = ?2,
                     scan_sequence = ?3, repaired_checkpoint = ?2, stage = 'queue'
                     WHERE audit_name = ?1",
                    params![SESSION_MESSAGE_PROJECTOR_VERSION, repaired, scan],
                )
                .await
                .map_err(audit_read_error)?;
            } else {
                conn.execute(
                    "UPDATE authority_projection_repair_progress SET scan_sequence = ?2, repaired_checkpoint = ?3
                     WHERE audit_name = ?1", params![SESSION_MESSAGE_PROJECTOR_VERSION, scan, repaired],
                ).await.map_err(audit_read_error)?;
            }
        }
        "queue" => {
            let mut rows = conn.query(
                "SELECT queue.rowid, queue.observation_sequence,
                    EXISTS(SELECT 1 FROM observations AS observation
                        WHERE observation.observation_id = queue.observation_id AND observation.sequence = queue.observation_sequence)
                 FROM projection_queue AS queue WHERE queue.rowid > ?1 ORDER BY queue.rowid LIMIT ?2",
                params![queue_rowid, AUDIT_PAGE_ROWS],
            ).await.map_err(audit_read_error)?;
            let mut next = queue_rowid;
            let mut count = 0;
            let mut obsolete = Vec::new();
            while let Some(row) = rows.next().await.map_err(audit_read_error)? {
                next = row.get(0).map_err(audit_read_error)?;
                count += 1;
                if row.get::<i64>(1).map_err(audit_read_error)? <= repaired
                    || row.get::<i64>(2).map_err(audit_read_error)? == 0
                {
                    obsolete.push(next);
                }
            }
            drop(rows);
            for rowid in obsolete {
                conn.execute(
                    "DELETE FROM projection_queue WHERE rowid = ?1",
                    params![rowid],
                )
                .await
                .map_err(audit_read_error)?;
            }
            conn.execute(
                "UPDATE authority_projection_repair_progress SET queue_rowid = ?2,
                 enqueue_sequence = ?3, stage = ?4 WHERE audit_name = ?1",
                params![
                    SESSION_MESSAGE_PROJECTOR_VERSION,
                    next,
                    repaired,
                    if count < AUDIT_PAGE_ROWS {
                        "enqueue"
                    } else {
                        "queue"
                    }
                ],
            )
            .await
            .map_err(audit_read_error)?;
        }
        "enqueue" => {
            let mut rows = conn.query(
                "SELECT sequence, observation_id FROM observations WHERE sequence > ?1 AND sequence <= ?2
                 ORDER BY sequence LIMIT ?3", params![enqueue, frontier, AUDIT_PAGE_ROWS],
            ).await.map_err(audit_read_error)?;
            let mut pending = Vec::new();
            while let Some(row) = rows.next().await.map_err(audit_read_error)? {
                enqueue = row.get(0).map_err(audit_read_error)?;
                pending.push((enqueue, row.get::<String>(1).map_err(audit_read_error)?));
            }
            drop(rows);
            let complete = pending.len() < AUDIT_PAGE_ROWS as usize;
            for (sequence, id) in pending {
                conn.execute("INSERT OR IGNORE INTO projection_queue (observation_id, observation_sequence) VALUES (?1, ?2)",
                    params![id, sequence]).await.map_err(audit_read_error)?;
            }
            if complete {
                conn.execute(
                    "DELETE FROM authority_projection_repair_progress WHERE audit_name = ?1",
                    params![SESSION_MESSAGE_PROJECTOR_VERSION],
                )
                .await
                .map_err(audit_read_error)?;
                return Ok(Some(repaired));
            }
            conn.execute("UPDATE authority_projection_repair_progress SET enqueue_sequence = ?2 WHERE audit_name = ?1",
                params![SESSION_MESSAGE_PROJECTOR_VERSION, enqueue]).await.map_err(audit_read_error)?;
        }
        _ => {
            return Err(authority_violation(
                "projection repair journal contains unknown stage",
            ));
        }
    }
    Ok(None)
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.source_cursors",
    level = "trace",
    skip_all
)]
#[cfg(test)]
pub(super) async fn repair_committed_source_cursors(
    conn: &impl Executor,
    after_sequence: i64,
) -> tracedecay_domain::errors::Result<()> {
    let candidates = latest_committed_source_cursors(conn, after_sequence).await?;
    for candidate in candidates {
        repair_cursor_candidate(conn, &candidate).await?;
    }
    Ok(())
}

async fn repair_cursor_candidate(
    conn: &impl Executor,
    candidate: &CommittedCursorCandidate,
) -> tracedecay_domain::errors::Result<()> {
    let stored = read_source_cursor(conn, &candidate.source_json, &candidate.scope_json).await?;
    match stored {
        None => write_source_cursor(conn, candidate).await?,
        Some(stored) if stored == candidate.cursor => {}
        Some(stored)
            if stored.generation() == candidate.cursor.generation()
                && stored.ordering_domain() == candidate.cursor.ordering_domain()
                && stored.position() < candidate.cursor.position() =>
        {
            write_source_cursor(conn, candidate).await?;
        }
        Some(stored) if is_new_generation_frontier(&stored, &candidate.cursor) => {
            // A replacement generation may be recorded before its first
            // complete frame. Older committed observations must not pull
            // that zero frontier back into the previous generation.
        }
        Some(stored)
            if cursor_has_exact_advance_receipt(
                conn,
                &candidate.source_json,
                &candidate.scope_json,
                &stored,
            )
            .await? => {}
        Some(stored)
            if stored.generation() == candidate.cursor.generation()
                && stored.ordering_domain() == candidate.cursor.ordering_domain()
                && stored.position() > candidate.cursor.position() =>
        {
            // Older builds could advance this derived frontier without a
            // durable coverage receipt. Rewind to the last canonical
            // observation so replay can safely reconstruct the suffix.
            write_source_cursor(conn, candidate).await?;
        }
        Some(_) => {
            return Err(authority_violation(
                "source cursor cannot be reconciled with the latest committed observation",
            ));
        }
    }
    Ok(())
}

/// Removes obsolete temporary work in bounded pages when audit trust is lost.
pub(super) async fn clear_cursor_audit_pending_page(
    conn: &impl Executor,
) -> tracedecay_domain::errors::Result<bool> {
    conn.execute(
        "DELETE FROM authority_cursor_audit_pending WHERE rowid IN (
            SELECT rowid FROM authority_cursor_audit_pending ORDER BY rowid LIMIT ?1
         )",
        params![AUDIT_PAGE_ROWS],
    )
    .await
    .map_err(audit_read_error)?;
    let mut rows = conn
        .query("SELECT 1 FROM authority_cursor_audit_pending LIMIT 1", ())
        .await
        .map_err(audit_read_error)?;
    Ok(rows.next().await.map_err(audit_read_error)?.is_none())
}

pub(super) enum CursorAuditPage {
    ObservationsAppended,
    Continue,
    Complete,
}

/// Reconcile only candidates derived by the observation audit. A fresh commit
/// is audited first, so an older candidate cannot rewind a newer generation.
pub(super) async fn repair_pending_source_cursor_page(
    conn: &impl Executor,
    audited_sequence: i64,
) -> tracedecay_domain::errors::Result<CursorAuditPage> {
    // Cursor reconstruction scans retained payloads, not allocated identities.
    // A retired tail still exists in sqlite_sequence, but has no row to audit.
    let mut newest = conn
        .query("SELECT COALESCE(MAX(sequence), 0) FROM observations", ())
        .await
        .map_err(audit_read_error)?;
    let retained_frontier: i64 = newest
        .next()
        .await
        .map_err(audit_read_error)?
        .ok_or_else(|| authority_violation("retained frontier query returned no row"))?
        .get(0)
        .map_err(audit_read_error)?;
    drop(newest);
    if retained_frontier > audited_sequence {
        return Ok(CursorAuditPage::ObservationsAppended);
    }
    let mut rows = conn
        .query(
            "SELECT pending.rowid, pending.source_json, pending.scope_json,
                pending.observation_sequence, pending.cursor_json, observation.committed_cursor_json
         FROM authority_cursor_audit_pending AS pending LEFT JOIN observations AS observation
           ON observation.sequence = pending.observation_sequence
         ORDER BY pending.rowid LIMIT ?1",
            params![AUDIT_PAGE_ROWS],
        )
        .await
        .map_err(audit_read_error)?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().await.map_err(audit_read_error)? {
        let rowid = row.get::<i64>(0).map_err(audit_read_error)?;
        let source_json = row.get::<String>(1).map_err(audit_read_error)?;
        let scope_json = row.get::<String>(2).map_err(audit_read_error)?;
        let sequence = row.get::<i64>(3).map_err(audit_read_error)?;
        let cursor_json = row.get::<String>(4).map_err(audit_read_error)?;
        let cursor: ObservationSourceCursorV1 =
            decode_authority_json(&cursor_json, "pending committed cursor")?;
        let committed_json = row
            .get::<Option<String>>(5)
            .map_err(audit_read_error)?
            .ok_or_else(|| {
                authority_violation("pending cursor audit references a missing observation")
            })?;
        let committed: ObservationSourceCursorV1 =
            decode_authority_json(&committed_json, "audited committed cursor")?;
        if committed != cursor {
            return Err(authority_violation(
                "pending cursor audit disagrees with committed observation",
            ));
        }
        if sequence <= 0
            || sequence > audited_sequence
            || source_json != encode_authority_json(cursor.source(), "pending cursor source")?
            || scope_json != encode_authority_json(cursor.scope(), "pending cursor scope")?
        {
            return Err(authority_violation(
                "pending cursor audit contains invalid authority",
            ));
        }
        candidates.push((
            rowid,
            CommittedCursorCandidate {
                source_json,
                scope_json,
                cursor_json,
                cursor,
            },
        ));
    }
    drop(rows);
    if candidates.is_empty() {
        return Ok(CursorAuditPage::Complete);
    }
    for (rowid, candidate) in candidates {
        repair_cursor_candidate(conn, &candidate).await?;
        validate_cursor_candidate_coverage(conn, &candidate).await?;
        conn.execute(
            "DELETE FROM authority_cursor_audit_pending WHERE rowid = ?1",
            params![rowid],
        )
        .await
        .map_err(audit_read_error)?;
    }
    Ok(CursorAuditPage::Continue)
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.scan_committed",
    level = "trace",
    skip_all
)]
async fn latest_committed_source_cursors(
    conn: &impl QueryExecutor,
    after_sequence: i64,
) -> tracedecay_domain::errors::Result<Vec<CommittedCursorCandidate>> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    // Newest-first keyset cursor. `sequence` is the observations rowid, so an
    // exclusive upper bound walks the suffix backwards one page at a time.
    let mut scan_cursor = i64::MAX;
    loop {
        let mut rows = conn
            .query(
                "SELECT sequence, committed_cursor_json
             FROM observations WHERE sequence > ?1 AND sequence < ?2
             ORDER BY sequence DESC LIMIT ?3",
                params![after_sequence, scan_cursor, OBSERVATION_AUDIT_PAGE_ROWS],
            )
            .await
            .map_err(audit_read_error)?;
        let mut page_rows = 0_i64;
        while let Some(row) = rows.next().await.map_err(audit_read_error)? {
            page_rows += 1;
            scan_cursor = row.get::<i64>(0).map_err(audit_read_error)?;
            let cursor_json = row.get::<String>(1).map_err(audit_read_error)?;
            let cursor: ObservationSourceCursorV1 =
                decode_authority_json(&cursor_json, "committed source cursor authority JSON")?;
            let source_json = encode_authority_json(cursor.source(), "observation source JSON")?;
            let scope_json = encode_authority_json(cursor.scope(), "observation scope JSON")?;
            if seen.insert((source_json.clone(), scope_json.clone())) {
                candidates.push(CommittedCursorCandidate {
                    source_json,
                    scope_json,
                    cursor_json: encode_authority_json(&cursor, "committed source cursor JSON")?,
                    cursor,
                });
            }
        }
        drop(rows);
        if page_rows < OBSERVATION_AUDIT_PAGE_ROWS {
            return Ok(candidates);
        }
    }
}

fn is_new_generation_frontier(
    stored: &ObservationSourceCursorV1,
    committed: &ObservationSourceCursorV1,
) -> bool {
    stored.ordering_domain() == ObservationOrderingDomainV1::FileBytes
        && committed.ordering_domain() == ObservationOrderingDomainV1::FileBytes
        && stored.generation() != committed.generation()
        && stored.position() == 0
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.read_cursor",
    level = "trace",
    skip_all
)]
async fn read_source_cursor(
    conn: &impl QueryExecutor,
    source_json: &str,
    scope_json: &str,
) -> tracedecay_domain::errors::Result<Option<ObservationSourceCursorV1>> {
    let mut rows = conn
        .query(
            "SELECT cursor_json FROM source_cursors
             WHERE source_json = ?1 AND scope_json = ?2",
            params![source_json, scope_json],
        )
        .await
        .map_err(audit_read_error)?;
    let cursor_json = rows
        .next()
        .await
        .map_err(audit_read_error)?
        .map(|row| row.get::<String>(0))
        .transpose()
        .map_err(audit_read_error)?;
    cursor_json
        .map(|json| decode_authority_json(&json, "source cursor authority JSON"))
        .transpose()
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.write_cursor",
    level = "trace",
    skip_all
)]
async fn write_source_cursor(
    conn: &impl Executor,
    candidate: &CommittedCursorCandidate,
) -> tracedecay_domain::errors::Result<()> {
    conn.execute(
        "INSERT INTO source_cursors(source_json, scope_json, cursor_json)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(source_json, scope_json) DO UPDATE SET
            cursor_json = excluded.cursor_json",
        params![
            candidate.source_json.as_str(),
            candidate.scope_json.as_str(),
            candidate.cursor_json.as_str()
        ],
    )
    .await
    .map_err(audit_read_error)?;
    // Like every cursor commit, a repaired cursor drops the advances it now
    // strictly supersedes; no other pass reclaims them.
    conn.execute(
        PRUNE_SUPERSEDED_CURSOR_ADVANCES_SQL,
        params![
            candidate.source_json.as_str(),
            candidate.scope_json.as_str()
        ],
    )
    .await
    .map(|_| ())
    .map_err(audit_read_error)
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.check_advance_receipt",
    level = "trace",
    skip_all
)]
async fn cursor_has_exact_advance_receipt(
    conn: &impl QueryExecutor,
    source_json: &str,
    scope_json: &str,
    cursor: &ObservationSourceCursorV1,
) -> tracedecay_domain::errors::Result<bool> {
    let mut rows = conn
        .query(
            "SELECT coverage_json FROM source_cursor_advances
             WHERE source_json = ?1 AND scope_json = ?2
               AND json_extract(coverage_json, '$.generation') IS json_extract(?3, '$.generation')
               AND json_extract(coverage_json, '$.ordering_domain') IS COALESCE(json_extract(?3, '$.ordering_domain'), 'file_bytes')
               AND json_extract(coverage_json, '$.range.end') IS json_extract(?3, '$.byte_offset')
             LIMIT 1",
            params![source_json, scope_json, encode_authority_json(cursor, "cursor advance evidence")?],
        )
        .await
        .map_err(audit_read_error)?;
    while let Some(row) = rows.next().await.map_err(audit_read_error)? {
        let coverage_json = row.get::<String>(0).map_err(audit_read_error)?;
        let coverage: ObservationCoverageV1 =
            decode_authority_json(&coverage_json, "source cursor advance coverage JSON")?;
        if coverage.generation() == cursor.generation()
            && coverage.ordering_domain() == cursor.ordering_domain()
            && coverage.range().end() == cursor.position()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[tracing::instrument(
    name = "global_db.schema_contract.repair.cursor_coverage",
    level = "trace",
    skip_all
)]
pub(super) async fn validate_observation_cursor_coverage(
    conn: &impl QueryExecutor,
    after_sequence: i64,
) -> tracedecay_domain::errors::Result<()> {
    for candidate in latest_committed_source_cursors(conn, after_sequence).await? {
        validate_cursor_candidate_coverage(conn, &candidate).await?;
    }
    Ok(())
}

async fn validate_cursor_candidate_coverage(
    conn: &impl QueryExecutor,
    candidate: &CommittedCursorCandidate,
) -> tracedecay_domain::errors::Result<()> {
    let Some(stored) =
        read_source_cursor(conn, &candidate.source_json, &candidate.scope_json).await?
    else {
        return Err(authority_violation(
            "committed observation has no source cursor authority row",
        ));
    };
    if stored == candidate.cursor || is_new_generation_frontier(&stored, &candidate.cursor) {
        return Ok(());
    }
    if !cursor_has_exact_advance_receipt(
        conn,
        &candidate.source_json,
        &candidate.scope_json,
        &stored,
    )
    .await?
    {
        return Err(authority_violation(
            "source cursor does not exactly match committed or non-durable authority",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
