//! Fence lifecycle work must not wait for physical checkpoint retry backoff.

use super::{
    CheckpointError, Drain, EXPIRED_RETRY_MIN, FENCE_LIMIT, FENCE_READ_DEADLINE,
    RusqliteCheckpointError, WriterCheckpointController,
};
use crate::checkpoint::types::WalSample;
use std::time::Instant;

impl WriterCheckpointController {
    /// Wake for revocation and expiry even when a resource failure defers the
    /// next physical checkpoint. Once revocation is due, expiry is the next
    /// lifecycle deadline; the worker services revocation before waiting again.
    pub(crate) fn fence_deadline(&self, now: Instant) -> Option<Instant> {
        let Drain::Fenced { since } = self.drain else {
            return None;
        };
        let revocation = since + FENCE_READ_DEADLINE;
        Some(if now < revocation {
            revocation
        } else {
            since + FENCE_LIMIT
        })
    }

    /// Expiry is a policy transition, not another RESTART attempt. Sample the
    /// current WAL so dropping the fence never bypasses the twice-hard ceiling.
    /// If sampling fails, expire conservatively with writes still blocked until
    /// an ordinary backed-off checkpoint can establish the actual WAL size.
    pub(crate) fn expire_fence(
        &mut self,
        now: Instant,
    ) -> Result<Option<WalSample>, CheckpointError<RusqliteCheckpointError>> {
        let Drain::Fenced { since } = self.drain else {
            return Ok(None);
        };
        if now.saturating_duration_since(since) < FENCE_LIMIT {
            return Ok(None);
        }
        self.drain = Drain::Expired {
            retry_at: now + EXPIRED_RETRY_MIN,
            backoff: EXPIRED_RETRY_MIN,
            wal_bytes: u64::MAX,
        };
        let sample = self.driver.sample_wal().map_err(CheckpointError::Driver)?;
        self.drain = Drain::Expired {
            retry_at: now + EXPIRED_RETRY_MIN,
            backoff: EXPIRED_RETRY_MIN,
            wal_bytes: sample.bytes,
        };
        Ok(Some(sample))
    }
}
