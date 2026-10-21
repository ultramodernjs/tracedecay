//! Bundled SQLite storage runtime.

mod admission;
mod allocator;
mod authority;
mod checkpoint;
mod connection;
pub mod schema_version;
pub use connection::{
    ConnectionPolicyError, OpenedDatabaseFileError, VerifiedReader, VerifiedReaderError,
    default_vfs_max_pathname, open_immutable_reader, open_verified_immutable_reader,
    open_verified_read_snapshot,
};
#[doc(hidden)]
pub mod exact_sql;
pub mod handoff;
mod ledger;
/// Schema and transaction-bound maintenance for the runtime writer ledger.
/// Cleanup requires the exact writer or exclusive-maintenance connection;
/// replay-window detection never expires live receipts or rotates authority.
pub mod runtime_ledger {
    pub use crate::ledger::replay_window::{
        WriterReplayWindow, WriterReplayWindowPolicy, WriterReplayWindowStatus,
    };
    pub use crate::ledger::retention::{
        MAX_WRITER_LEDGER_CLEANUP_ROWS, WriterLedgerCleanupPlan, WriterLedgerMaintenanceError,
        WriterLedgerRetentionReport, WriterLedgerRetirementAuthority,
        preview_retired_writer_ledger_cleanup, preview_writer_ledger_cleanup,
    };
    pub use crate::ledger::{RETIRE_RUNTIME_EFFECTS_V1, RUNTIME_LEDGER_SCHEMA};
    pub use crate::writer::ledger_maintenance::{
        WRITER_LEDGER_DRAIN_INTERVAL, WriterLedgerDrainOutcome, WriterLedgerMaintenance,
        WriterLedgerMaintenanceReport, WriterLedgerMaintenanceStatus,
        drain_retired_writer_ledger_page, drain_writer_ledger_page,
    };
}
pub mod native_runtime;
#[cfg(test)]
mod native_runtime_wake_tests;
mod operation;
mod persistence;
pub mod reader;
pub mod remote;
pub mod repository;
pub mod runtime;
pub mod storage_pool;
mod telemetry;
#[cfg(test)]
mod test_support;
pub mod watermark;
pub mod work;
pub mod work_attempt;
pub mod work_placement;
pub mod work_product;
pub mod work_run_control;
pub mod workflow;
mod writer;

pub use allocator::{SqliteAllocatorMethodsV1, install_sqlite_allocator};
pub use authority::{
    RuntimeWriteAuthority, RuntimeWriteAuthorityError, RuntimeWriteAuthorityStage,
};
pub use checkpoint::{
    CheckpointBlocker, CheckpointBlockers, CheckpointFrameReport, CheckpointInterruption,
    CheckpointKind, CheckpointOutcome, CheckpointPressure, CheckpointStatus, CheckpointWal,
};
pub use operation::{
    ExactSqlOnlyStorageOperationV1, StorageOperationError, StorageOperationExecutor,
};
pub use telemetry::{
    ReaderAdmissionSnapshot, SqliteVmSnapshot, WalCheckpointSample, WalCheckpointSnapshot,
    WriterBatchMetrics, WriterBatchTotals, WriterClientServiceSnapshot, WriterCommitSnapshot,
    WriterLockWorkSnapshot, WriterOperationCounters, WriterQueueSnapshot, WriterServiceCounts,
    WriterTelemetrySnapshot, WriterTransactionMetrics, WriterTransactionOutcome,
    WriterTransactionTotals,
};
pub use writer::{
    CheckpointControlError, CheckpointHandle, CheckpointRequest, CheckpointTicket,
    ExistingWriterLocator, FILE_PROBE_INTERVAL, PersistentWriter, WriterActorError,
    WriterStartError, WriterState,
};
