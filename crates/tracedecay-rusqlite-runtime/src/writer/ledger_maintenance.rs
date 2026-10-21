//! Writer-owned, commit-independent ledger maintenance. The worker/owner must
//! include `next_due` in its idle wakeup and call `tick` on its pinned connection.
//! No timer opens another writer or manufactures a domain command.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use rusqlite::{Connection, TransactionBehavior};
use tracedecay_store::StoreRuntimeBindingV1;

use crate::{
    RuntimeWriteAuthority, RuntimeWriteAuthorityError, RuntimeWriteAuthorityStage,
    runtime_ledger::{
        MAX_WRITER_LEDGER_CLEANUP_ROWS, WriterLedgerMaintenanceError, WriterLedgerRetentionReport,
        WriterLedgerRetirementAuthority, WriterReplayWindow, WriterReplayWindowPolicy,
        WriterReplayWindowStatus, preview_retired_writer_ledger_cleanup,
        preview_writer_ledger_cleanup,
    },
};

pub const WRITER_LEDGER_DRAIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct WriterLedgerDrainOutcome {
    pub preview: WriterLedgerRetentionReport,
    pub deleted_rows: usize,
}

/// Explicit apply entry point for the exact writer/exclusive maintenance owner.
/// A preview is performed and the checkpoint revalidated in the same bounded
/// transaction. Cancellation or revoked authority before commit rolls it back.
/// The caller must retain its originating file and write capability throughout.
pub fn drain_writer_ledger_page(
    connection: &mut Connection,
    binding: &StoreRuntimeBindingV1,
    authority: &dyn RuntimeWriteAuthority,
    max_rows: usize,
) -> Result<WriterLedgerDrainOutcome, WriterLedgerMaintenanceError> {
    drain_page(connection, binding, authority, None, max_rows)
}

/// Drain an explicitly retired incarnation without a foreground submit. The
/// exact owner must hold both its write capability and the retirement fence
/// through commit. Both are rechecked after the delete, before it is durable.
pub fn drain_retired_writer_ledger_page(
    connection: &mut Connection,
    live: &StoreRuntimeBindingV1,
    retired: &StoreRuntimeBindingV1,
    authority: &dyn RuntimeWriteAuthority,
    retirement: &dyn WriterLedgerRetirementAuthority,
    max_rows: usize,
) -> Result<WriterLedgerDrainOutcome, WriterLedgerMaintenanceError> {
    drain_page(
        connection,
        live,
        authority,
        Some((retired, retirement)),
        max_rows,
    )
}

fn drain_page(
    connection: &mut Connection,
    binding: &StoreRuntimeBindingV1,
    authority: &dyn RuntimeWriteAuthority,
    retired: Option<(&StoreRuntimeBindingV1, &dyn WriterLedgerRetirementAuthority)>,
    max_rows: usize,
) -> Result<WriterLedgerDrainOutcome, WriterLedgerMaintenanceError> {
    verify(authority, RuntimeWriteAuthorityStage::BeforeAdmission)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify(authority, RuntimeWriteAuthorityStage::Dequeued)?;
    let plan = match retired {
        Some((retired, retirement)) => preview_retired_writer_ledger_cleanup(
            &transaction,
            binding,
            retired,
            retirement,
            max_rows,
        )?,
        None => preview_writer_ledger_cleanup(&transaction, binding, max_rows)?,
    };
    let preview = plan.report().clone();
    let deleted_rows = plan.apply(binding)?;
    verify(authority, RuntimeWriteAuthorityStage::BeforeCommit)?;
    if let Some((retired, retirement)) = retired {
        retirement
            .verify_retired(binding, retired)
            .map_err(|error| WriterLedgerMaintenanceError::RetirementDenied(error.to_string()))?;
    }
    transaction.commit()?;
    Ok(WriterLedgerDrainOutcome {
        preview,
        deleted_rows,
    })
}

fn verify(
    authority: &dyn RuntimeWriteAuthority,
    stage: RuntimeWriteAuthorityStage,
) -> Result<(), WriterLedgerMaintenanceError> {
    authority
        .verify(stage)
        .map_err(|error| WriterLedgerMaintenanceError::AuthorityDenied {
            stage,
            message: error.to_string(),
        })
}

#[derive(Clone, Debug)]
pub struct WriterLedgerMaintenanceReport {
    pub drain: WriterLedgerDrainOutcome,
    pub replay_window: WriterReplayWindowStatus,
    /// Never hide a rotation signal behind a successful historical cleanup.
    pub handover_blocker: Option<&'static str>,
}

/// One controller per exact writer. Each tick yields after one page; independent
/// writers/stores keep their own schedules instead of draining one store to
/// exhaustion. Errors also defer the next attempt, preventing an idle spin.
/// The controller is opt-in until the database-map owner supplies authority and
/// the worker wires its deadline into the wakeup path.
pub struct WriterLedgerMaintenance {
    binding: StoreRuntimeBindingV1,
    replay_window: WriterReplayWindow,
    max_rows: usize,
    next_due: Instant,
}

impl WriterLedgerMaintenance {
    pub fn new(
        binding: StoreRuntimeBindingV1,
        replay_policy: WriterReplayWindowPolicy,
        max_rows: usize,
        now: Instant,
    ) -> Result<Self, WriterLedgerMaintenanceError> {
        if !(1..=MAX_WRITER_LEDGER_CLEANUP_ROWS).contains(&max_rows) {
            return Err(WriterLedgerMaintenanceError::InvalidBudget);
        }
        Ok(Self {
            replay_window: WriterReplayWindow::new(binding.clone(), replay_policy),
            binding,
            max_rows,
            next_due: now,
        })
    }

    pub fn next_due(&self) -> Instant {
        self.next_due
    }

    pub fn tick(
        &mut self,
        connection: &mut Connection,
        authority: &dyn RuntimeWriteAuthority,
        cancelled: &AtomicBool,
        wall_now_micros: i64,
        now: Instant,
    ) -> Result<Option<WriterLedgerMaintenanceReport>, WriterLedgerMaintenanceError> {
        if now < self.next_due || cancelled.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.next_due = now + WRITER_LEDGER_DRAIN_INTERVAL;
        let authority = CancellableAuthority {
            authority,
            cancelled,
        };
        let drain = drain_writer_ledger_page(connection, &self.binding, &authority, self.max_rows)?;
        // Detection is read-only, separately bounded to policy.max_receipts+1.
        let transaction = connection.transaction()?;
        let replay_window = self
            .replay_window
            .inspect_at(&transaction, wall_now_micros, now)?;
        transaction.rollback()?;
        Ok(Some(WriterLedgerMaintenanceReport {
            handover_blocker: replay_window.rotation_required.then_some(
                "owner-coordinated consumer release, authority rotation and rebind required; live receipts retained",
            ),
            drain,
            replay_window,
        }))
    }
}

struct CancellableAuthority<'a> {
    authority: &'a dyn RuntimeWriteAuthority,
    cancelled: &'a AtomicBool,
}

impl RuntimeWriteAuthority for CancellableAuthority<'_> {
    fn verify(&self, stage: RuntimeWriteAuthorityStage) -> Result<(), RuntimeWriteAuthorityError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(RuntimeWriteAuthorityError::denied(
                "writer ledger drain cancelled",
            ));
        }
        self.authority.verify(stage)
    }
}
