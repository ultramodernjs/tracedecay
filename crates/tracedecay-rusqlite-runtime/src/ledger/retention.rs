//! Bounded, dry-run-first cleanup on the exact writer's transaction.
//!
//! These helpers never open a connection, install schema, advance a checkpoint,
//! or commit. The owner must validate its file/write authority and schedule one
//! page per store per tick, including ticks with no foreground submissions.

use rusqlite::{Transaction, params};
use tracedecay_store::{ShardWatermarkV1, StoreRuntimeBindingV1};

use crate::RuntimeWriteAuthorityError;

use super::{
    LedgerError, checkpoint,
    sqlite::{BindingKey, sqlite_u64},
};

pub const MAX_WRITER_LEDGER_CLEANUP_ROWS: usize = 4_096;

#[derive(Debug, thiserror::Error)]
pub enum WriterLedgerMaintenanceError {
    #[error("writer ledger maintenance failed: {0}")]
    Ledger(String),
    #[error("writer ledger cleanup binding does not match its preview")]
    BindingMismatch,
    #[error("writer ledger checkpoint changed after its preview")]
    CheckpointChanged,
    #[error("writer ledger page budget must be between 1 and 4096 rows")]
    InvalidBudget,
    #[error("writer replay window must have 1..=65536 receipts and an age in (0, 7 days]")]
    InvalidReplayWindow,
    #[error("writer incarnation retirement denied: {0}")]
    RetirementDenied(String),
    #[error("writer ledger maintenance authority denied at {stage:?}: {message}")]
    AuthorityDenied {
        stage: crate::RuntimeWriteAuthorityStage,
        message: String,
    },
}

impl From<LedgerError> for WriterLedgerMaintenanceError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error.to_string())
    }
}

impl From<rusqlite::Error> for WriterLedgerMaintenanceError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Ledger(error.to_string())
    }
}

/// Implemented by the exact database-map/profile owner, not inferred from a
/// quiet checkpoint. Verification must prove the retired incarnation cannot
/// issue or execute more work, and retain that fence through transaction commit.
/// It must not reacquire authority by path or change a checkpoint to fake it.
pub trait WriterLedgerRetirementAuthority: Send + Sync {
    fn verify_retired(
        &self,
        live: &StoreRuntimeBindingV1,
        retired: &StoreRuntimeBindingV1,
    ) -> Result<(), RuntimeWriteAuthorityError>;
}

/// One bounded page, not an unbounded census of the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterLedgerRetentionReport {
    /// The exact current writer that owns the transaction.
    pub live_binding: StoreRuntimeBindingV1,
    /// The incarnation whose unreachable receipts this page covers.
    pub binding: StoreRuntimeBindingV1,
    pub eligible_rows: usize,
    /// UTF-8 bytes in the selected rows' TEXT columns only. This is not page
    /// allocation, total backlog size, or bytes returned to the filesystem.
    pub eligible_payload_bytes: u64,
    pub has_more: bool,
}

/// An explicit apply capability tied to the preview's exact transaction.
/// Dropping it is a dry run. It cannot be moved to another connection or used
/// after commit/reopen; a subsequent transaction must preview again.
pub struct WriterLedgerCleanupPlan<'transaction, 'connection> {
    transaction: &'transaction Transaction<'connection>,
    report: WriterLedgerRetentionReport,
    checkpoint: Option<ShardWatermarkV1>,
    live_checkpoint: Option<ShardWatermarkV1>,
    retirement: Option<&'transaction dyn WriterLedgerRetirementAuthority>,
    through_epoch: i64,
}

const SELECT_PAGE: &str = "
SELECT length(CAST(shard_json AS BLOB)) + length(CAST(idempotency_key AS BLOB))
     + length(CAST(request_digest AS BLOB)) + length(CAST(operation_id AS BLOB))
     + length(CAST(transaction_id AS BLOB)) + length(CAST(durability_json AS BLOB))
     + length(CAST(priority_json AS BLOB))
FROM td_runtime_writer_idempotency_v2
WHERE shard_json = ?1 AND incarnation = ?2 AND authority_epoch <= ?3
ORDER BY authority_epoch, idempotency_key LIMIT ?4";

const DELETE_PAGE: &str = "
DELETE FROM td_runtime_writer_idempotency_v2
WHERE (shard_json, incarnation, authority_epoch, idempotency_key) IN (
    SELECT shard_json, incarnation, authority_epoch, idempotency_key
    FROM td_runtime_writer_idempotency_v2
    WHERE shard_json = ?1 AND incarnation = ?2 AND authority_epoch <= ?3
    ORDER BY authority_epoch, idempotency_key LIMIT ?4
)";

/// Preview superseded epochs of this incarnation only. The epoch fence comes
/// from the fully decoded checkpoint, never from a neighbouring raw scalar.
pub fn preview_writer_ledger_cleanup<'transaction, 'connection>(
    transaction: &'transaction Transaction<'connection>,
    binding: &StoreRuntimeBindingV1,
    max_rows: usize,
) -> Result<WriterLedgerCleanupPlan<'transaction, 'connection>, WriterLedgerMaintenanceError> {
    let checkpoint = validated_checkpoint(transaction, binding)?;
    let through_epoch = checkpoint
        .as_ref()
        .map(|checkpoint| {
            sqlite_u64(checkpoint.authority_epoch.get(), "authority epoch").map(|epoch| epoch - 1)
        })
        .transpose()?
        .unwrap_or(0);
    preview_page(
        transaction,
        binding,
        binding,
        checkpoint.clone(),
        checkpoint,
        None,
        through_epoch,
        max_rows,
    )
}

/// A different incarnation's standing epoch needs an explicit owner-held
/// retirement fence. Time alone is not proof, even after seven quiet days.
/// Preview and apply both verify that fence and decode both checkpoints.
pub fn preview_retired_writer_ledger_cleanup<'transaction, 'connection>(
    transaction: &'transaction Transaction<'connection>,
    live: &StoreRuntimeBindingV1,
    retired: &StoreRuntimeBindingV1,
    authority: &'transaction dyn WriterLedgerRetirementAuthority,
    max_rows: usize,
) -> Result<WriterLedgerCleanupPlan<'transaction, 'connection>, WriterLedgerMaintenanceError> {
    if live.shard_id != retired.shard_id || live.incarnation == retired.incarnation {
        return Err(WriterLedgerMaintenanceError::BindingMismatch);
    }
    authority
        .verify_retired(live, retired)
        .map_err(|error| WriterLedgerMaintenanceError::RetirementDenied(error.to_string()))?;
    let live_checkpoint = validated_checkpoint(transaction, live)?;
    let checkpoint = validated_checkpoint(transaction, retired)?;
    if checkpoint
        .as_ref()
        .is_none_or(|checkpoint| checkpoint.authority_epoch != retired.authority_epoch)
    {
        return Err(WriterLedgerMaintenanceError::CheckpointChanged);
    }
    let through_epoch = sqlite_u64(retired.authority_epoch.get(), "authority epoch")?;
    preview_page(
        transaction,
        live,
        retired,
        checkpoint,
        live_checkpoint,
        Some(authority),
        through_epoch,
        max_rows,
    )
}

pub(super) fn validated_checkpoint(
    transaction: &Transaction<'_>,
    binding: &StoreRuntimeBindingV1,
) -> Result<Option<ShardWatermarkV1>, WriterLedgerMaintenanceError> {
    let key = BindingKey::from_binding(binding)?;
    let checkpoint = checkpoint::load(transaction, &key)?.map(|row| row.watermark);
    if let Some(checkpoint) = &checkpoint
        && checkpoint.authority_epoch > binding.authority_epoch
    {
        return Err(LedgerError::StaleAuthority {
            persisted: checkpoint.authority_epoch,
            requested: binding.authority_epoch,
        }
        .into());
    }
    Ok(checkpoint)
}

#[allow(clippy::too_many_arguments)]
fn preview_page<'transaction, 'connection>(
    transaction: &'transaction Transaction<'connection>,
    live: &StoreRuntimeBindingV1,
    binding: &StoreRuntimeBindingV1,
    checkpoint: Option<ShardWatermarkV1>,
    live_checkpoint: Option<ShardWatermarkV1>,
    retirement: Option<&'transaction dyn WriterLedgerRetirementAuthority>,
    through_epoch: i64,
    max_rows: usize,
) -> Result<WriterLedgerCleanupPlan<'transaction, 'connection>, WriterLedgerMaintenanceError> {
    if !(1..=MAX_WRITER_LEDGER_CLEANUP_ROWS).contains(&max_rows) {
        return Err(WriterLedgerMaintenanceError::InvalidBudget);
    }
    let key = BindingKey::from_binding(binding)?;
    let mut statement = transaction.prepare_cached(SELECT_PAGE)?;
    let mut rows = statement.query(params![
        &key.shard_json,
        key.incarnation_sql,
        through_epoch,
        (max_rows + 1) as i64,
    ])?;
    let mut found = 0;
    let mut payload_bytes = 0_u64;
    while let Some(row) = rows.next()? {
        if found < max_rows {
            payload_bytes = payload_bytes.saturating_add(row.get::<_, i64>(0)? as u64);
        }
        found += 1;
    }
    Ok(WriterLedgerCleanupPlan {
        transaction,
        report: WriterLedgerRetentionReport {
            live_binding: live.clone(),
            binding: binding.clone(),
            eligible_rows: found.min(max_rows),
            eligible_payload_bytes: payload_bytes,
            has_more: found > max_rows,
        },
        checkpoint,
        live_checkpoint,
        retirement,
        through_epoch,
    })
}

impl WriterLedgerCleanupPlan<'_, '_> {
    pub fn report(&self) -> &WriterLedgerRetentionReport {
        &self.report
    }

    /// Explicit confirmation for this preview. The caller still owns commit
    /// and must roll back the transaction on any error or cancellation. Owner
    /// authority must remain fenced through that commit.
    pub fn apply(
        self,
        expected: &StoreRuntimeBindingV1,
    ) -> Result<usize, WriterLedgerMaintenanceError> {
        if expected != &self.report.live_binding {
            return Err(WriterLedgerMaintenanceError::BindingMismatch);
        }
        if let Some(authority) = self.retirement {
            authority
                .verify_retired(expected, &self.report.binding)
                .map_err(|error| {
                    WriterLedgerMaintenanceError::RetirementDenied(error.to_string())
                })?;
        }
        if validated_checkpoint(self.transaction, expected)? != self.live_checkpoint
            || validated_checkpoint(self.transaction, &self.report.binding)? != self.checkpoint
        {
            return Err(WriterLedgerMaintenanceError::CheckpointChanged);
        }
        let key = BindingKey::from_binding(&self.report.binding)?;
        Ok(self.transaction.execute(
            DELETE_PAGE,
            params![
                &key.shard_json,
                key.incarnation_sql,
                self.through_epoch,
                self.report.eligible_rows as i64,
            ],
        )?)
    }
}
