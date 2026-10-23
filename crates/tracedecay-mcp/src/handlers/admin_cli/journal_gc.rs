//! Daemon-owned, dry-run-first journal normalization. No schema install or store open.

use tracedecay_contracts::retrieval::{AdminCliJournalGcCandidateV1, AdminCliJournalGcV1};
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_global_db::{
    RegisteredGlobalDb,
    session_sync_retention::{
        SessionSyncJournalGcCursorV1, apply_session_sync_journal_gc, plan_session_sync_journal_gc,
    },
};

fn invalid(message: &str) -> TraceDecayError {
    TraceDecayError::Config {
        message: message.to_owned(),
    }
}

pub(super) async fn run(
    registry: &RegisteredGlobalDb,
    cursor: Option<String>,
    approved_digest: Option<&str>,
) -> Result<AdminCliJournalGcV1> {
    if cursor.as_ref().is_some_and(|value| value.len() > 32768) {
        return Err(invalid("journal GC cursor exceeds the bounded token size"));
    }
    let decoded: Option<SessionSyncJournalGcCursorV1> =
        cursor.as_deref().map(serde_json::from_str).transpose()?;
    let plan = plan_session_sync_journal_gc(registry, None, decoded.as_ref()).await?;
    let (compacted, logical_bytes_released) = if let Some(digest) = approved_digest {
        let receipt = apply_session_sync_journal_gc(registry, &plan, digest).await?;
        if receipt.stale > 0 {
            return Err(invalid(
                "journal GC preview became stale; preview the same cursor again",
            ));
        }
        (receipt.compacted, receipt.logical_bytes_released)
    } else {
        (
            0,
            plan.candidates
                .iter()
                .map(|candidate| candidate.logical_bytes_released)
                .sum(),
        )
    };
    Ok(AdminCliJournalGcV1 {
        digest: plan.digest,
        cursor,
        next_cursor: plan.next.as_ref().map(serde_json::to_string).transpose()?,
        scanned: plan.scanned,
        skipped: plan.skipped,
        oversized: plan.oversized,
        candidates: plan
            .candidates
            .into_iter()
            .map(|candidate| AdminCliJournalGcCandidateV1 {
                key: candidate.key,
                payload_bytes: candidate.payload_bytes,
                logical_bytes_released: candidate.logical_bytes_released,
            })
            .collect(),
        logical_bytes_released,
        applied: approved_digest.is_some(),
        compacted,
    })
}
