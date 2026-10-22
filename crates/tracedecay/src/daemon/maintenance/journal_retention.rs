//! One bounded journal page per phase, retained by the periodic maintenance owner.
//! Expiry drains before normalization so journals about to be deleted are not rewritten.

use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_global_db::{
    RegisteredGlobalDb,
    session_sync_retention::{
        SessionSyncJournalGcCursorV1, apply_session_sync_journal_gc, plan_session_sync_journal_gc,
    },
};
use tracedecay_runtime_core::{cancellation::CancellationToken, logging::log_daemon_event};
use tracedecay_session_runtime::session_sync::{
    DaemonSessionSyncService, journal_retention::StartupJournalRetentionCursorV1,
};

#[derive(Default)]
pub(super) struct JournalRetentionProgress {
    expiry_pending: bool,
    gc_pending: bool,
    expiry: Option<StartupJournalRetentionCursorV1>,
    gc: Option<SessionSyncJournalGcCursorV1>,
}

fn retry(message: &str) -> TraceDecayError {
    TraceDecayError::Config {
        message: message.to_owned(),
    }
}

impl JournalRetentionProgress {
    pub(super) fn pending(&self) -> bool {
        self.expiry_pending || self.gc_pending
    }

    pub(super) async fn tick(
        &mut self,
        database: &RegisteredGlobalDb,
        service: &DaemonSessionSyncService,
        cancellation: &CancellationToken,
        start_if_idle: bool,
    ) -> Result<bool> {
        if cancellation.is_cancelled() {
            return Ok(self.pending());
        }
        if !self.pending() && start_if_idle {
            self.expiry_pending = true;
            self.gc_pending = true;
        }
        if self.expiry_pending {
            let plan = service
                .plan_startup_journal_retention(
                    database,
                    None,
                    tracedecay_contracts::now_micros(),
                    self.expiry.as_ref(),
                )
                .await?;
            if cancellation.is_cancelled() {
                return Ok(true);
            }
            let receipt = service
                .apply_startup_journal_retention(database, &plan, &plan.digest)
                .await?;
            if receipt.stale > 0 || receipt.busy > 0 {
                return Err(retry(
                    "startup journal page stale or busy; retry unchanged cursor",
                ));
            }
            // A certification page does not advance the journal sweep. Its own
            // bounded, durable frontier is owned by the existing retention API.
            self.expiry_pending = plan.dependency_backfill.is_some() || plan.next.is_some();
            self.expiry = plan.next;
            if receipt.deleted > 0 {
                log_daemon_event(
                    "retention_startup_journals",
                    &[
                        ("deleted", receipt.deleted.to_string()),
                        (
                            "logical_bytes_released",
                            receipt.logical_bytes_released.to_string(),
                        ),
                    ],
                );
            }
        }
        if self.expiry_pending || cancellation.is_cancelled() {
            return Ok(self.pending());
        }
        if self.gc_pending {
            let plan = plan_session_sync_journal_gc(database, None, self.gc.as_ref()).await?;
            if cancellation.is_cancelled() {
                return Ok(true);
            }
            let receipt = apply_session_sync_journal_gc(database, &plan, &plan.digest).await?;
            if receipt.stale > 0 {
                return Err(retry("journal GC page stale; retry unchanged cursor"));
            }
            self.gc_pending = plan.next.is_some();
            self.gc = plan.next;
            if receipt.compacted > 0 {
                log_daemon_event(
                    "retention_journal_gc",
                    &[
                        ("compacted", receipt.compacted.to_string()),
                        (
                            "logical_bytes_released",
                            receipt.logical_bytes_released.to_string(),
                        ),
                    ],
                );
            }
        }
        Ok(self.pending())
    }
}
