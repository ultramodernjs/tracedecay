//! Detection only: a full/old replay window requests an owner-coordinated
//! authority rotation. It never expires receipts or disables admission by
//! itself. Enforcing the window before consumer handover exists would turn
//! storage growth into a permanent ingestion outage.

use std::time::{Duration, Instant};

use rusqlite::{Transaction, params};
use tracedecay_store::StoreRuntimeBindingV1;

use super::{
    LedgerError, checkpoint,
    retention::WriterLedgerMaintenanceError,
    sqlite::{BindingKey, sqlite_u64},
};

const DEFAULT_MAX_RECEIPTS: usize = 65_536;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Copy, Debug)]
pub struct WriterReplayWindowPolicy {
    max_receipts: usize,
    max_age: Duration,
}

impl Default for WriterReplayWindowPolicy {
    fn default() -> Self {
        Self {
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_age: DEFAULT_MAX_AGE,
        }
    }
}

impl WriterReplayWindowPolicy {
    /// Budgets may be reduced for a deployment/test, but not made unbounded.
    pub fn new(
        max_receipts: usize,
        max_age: Duration,
    ) -> Result<Self, WriterLedgerMaintenanceError> {
        if !(1..=DEFAULT_MAX_RECEIPTS).contains(&max_receipts)
            || max_age.is_zero()
            || max_age > DEFAULT_MAX_AGE
        {
            return Err(WriterLedgerMaintenanceError::InvalidReplayWindow);
        }
        Ok(Self {
            max_receipts,
            max_age,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterReplayWindowStatus {
    pub binding: StoreRuntimeBindingV1,
    /// A lower bound when `scan_truncated` is true; never an unbounded COUNT.
    pub receipt_rows_at_least: usize,
    pub scan_truncated: bool,
    pub oldest_observed_commit_micros: Option<i64>,
    pub count_limit_reached: bool,
    pub age_limit_reached: bool,
    /// A scanned receipt is ahead of the reconstructed clock, so its age is
    /// uncertain after a physical-writer reopen. Conservatively rotate.
    pub clock_uncertain: bool,
    /// A signal, NOT permission to delete the live epoch or expire a key.
    pub rotation_required: bool,
}

pub struct WriterReplayWindow {
    binding: StoreRuntimeBindingV1,
    policy: WriterReplayWindowPolicy,
    last_clock: Option<(Instant, i64)>,
}

impl WriterReplayWindow {
    pub fn new(binding: StoreRuntimeBindingV1, policy: WriterReplayWindowPolicy) -> Self {
        Self {
            binding,
            policy,
            last_clock: None,
        }
    }

    /// Reconstructs the count and observed ages from a validated checkpoint and
    /// a bounded primary-key-prefix scan. Pass the writer's monotonic clock to
    /// preserve elapsed time within this monitor. After reopen, future receipt
    /// timestamps conservatively request rotation rather than imply young age.
    /// Elapsed time across reopen is not durably recorded; rollback that stays
    /// after every observed receipt cannot reconstruct previously observed expiry.
    pub fn inspect_at(
        &mut self,
        transaction: &Transaction<'_>,
        wall_now_micros: i64,
        monotonic_now: Instant,
    ) -> Result<WriterReplayWindowStatus, WriterLedgerMaintenanceError> {
        let key = BindingKey::from_binding(&self.binding)?;
        let checkpoint = checkpoint::load(transaction, &key)?;
        if let Some(checkpoint) = &checkpoint
            && checkpoint.watermark.authority_epoch > self.binding.authority_epoch
        {
            return Err(LedgerError::StaleAuthority {
                persisted: checkpoint.watermark.authority_epoch,
                requested: self.binding.authority_epoch,
            }
            .into());
        }
        let scan_limit = self.policy.max_receipts + 1;
        let mut statement = transaction.prepare_cached(
            "
            SELECT committed_at_micros FROM td_runtime_writer_idempotency_v2
            WHERE shard_json = ?1 AND incarnation = ?2 AND authority_epoch = ?3
            ORDER BY idempotency_key LIMIT ?4",
        )?;
        let mut rows = statement.query(params![
            &key.shard_json,
            key.incarnation_sql,
            sqlite_u64(self.binding.authority_epoch.get(), "authority epoch")?,
            scan_limit as i64,
        ])?;
        let mut count = 0;
        let mut oldest: Option<i64> = None;
        let mut newest: Option<i64> = None;
        while let Some(row) = rows.next()? {
            let committed_at: i64 = row.get(0)?;
            count += 1;
            oldest = Some(oldest.map_or(committed_at, |oldest| oldest.min(committed_at)));
            newest = Some(newest.map_or(committed_at, |newest| newest.max(committed_at)));
        }
        if count > 0
            && checkpoint.as_ref().is_none_or(|checkpoint| {
                checkpoint.watermark.authority_epoch != self.binding.authority_epoch
            })
        {
            return Err(LedgerError::Corrupt {
                table: "td_runtime_writer_checkpoint_v1",
                field: "missing replay authority",
            }
            .into());
        }
        let effective_now = self.last_clock.map_or(wall_now_micros, |(previous, wall)| {
            let elapsed = i64::try_from(
                monotonic_now
                    .saturating_duration_since(previous)
                    .as_micros(),
            )
            .unwrap_or(i64::MAX);
            wall_now_micros.max(wall.saturating_add(elapsed))
        });
        self.last_clock = Some((monotonic_now, effective_now));
        let count_limit_reached = count >= self.policy.max_receipts;
        let max_age_micros = i64::try_from(self.policy.max_age.as_micros()).unwrap_or(i64::MAX);
        let age_limit_reached =
            oldest.is_some_and(|oldest| effective_now.saturating_sub(oldest) >= max_age_micros);
        let clock_uncertain = newest.is_some_and(|newest| newest > effective_now);
        Ok(WriterReplayWindowStatus {
            binding: self.binding.clone(),
            receipt_rows_at_least: count,
            scan_truncated: count == scan_limit,
            oldest_observed_commit_micros: oldest,
            count_limit_reached,
            age_limit_reached,
            clock_uncertain,
            rotation_required: count_limit_reached || age_limit_reached || clock_uncertain,
        })
    }
}
