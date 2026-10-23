//! Resource failures defer checkpointing, not the serialized writer's lifetime.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use crate::{
    RuntimeWriteAuthorityStage,
    checkpoint::{CheckpointDecision, CheckpointError, CheckpointResult, RusqliteCheckpointError},
};

type Failure = CheckpointError<RusqliteCheckpointError>;

const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(60);

/// One backoff shared by requested checkpoints, post-commit checkpoints and
/// idle timer retries. It never opens a connection or restores a terminal actor.
#[derive(Default)]
pub(super) struct CheckpointFailurePolicy {
    retry: Option<Retry>,
    backoff: Duration,
    first_failure: Option<String>,
}

struct Retry {
    at: Instant,
    error: RetryError,
}

impl CheckpointFailurePolicy {
    pub(super) fn defers(&self, now: Instant) -> bool {
        self.retry.as_ref().is_some_and(|retry| now < retry.at)
    }

    /// A drain and a resource failure must both permit a physical checkpoint.
    /// The worker schedules fence lifecycle deadlines separately from this wait.
    pub(super) fn retry_due(&self, drain_due: Option<Instant>) -> Option<Instant> {
        match (drain_due, self.retry.as_ref().map(|retry| retry.at)) {
            (Some(drain), Some(resource)) => Some(drain.max(resource)),
            (drain, resource) => drain.or(resource),
        }
    }

    pub(super) fn deferred_error(&self, now: Instant) -> Option<Failure> {
        self.retry
            .as_ref()
            .filter(|retry| now < retry.at)
            .map(|retry| retry.error.to_error())
    }

    /// Returns true only for failures which must close the writer permanently.
    pub(super) fn record_failure(
        &mut self,
        path: &Path,
        operation: &'static str,
        error: &Failure,
        now: Instant,
    ) -> bool {
        let diagnostic = format!(
            "{}: {operation}: {}",
            path.display(),
            failure_diagnostic(error)
        );
        let first_failure = self.first_failure.get_or_insert_with(|| diagnostic.clone());
        let Some(retry_error) = RetryError::from_error(error) else {
            tracing::error!(
                path = %path.display(), operation, error = %diagnostic,
                first_failure = %first_failure,
                "checkpoint failed; writer is now faulted"
            );
            return true;
        };
        self.backoff = if self.backoff.is_zero() {
            RETRY_MIN
        } else {
            self.backoff.saturating_mul(2).min(RETRY_MAX)
        };
        self.retry = Some(Retry {
            at: now + self.backoff,
            error: retry_error,
        });
        tracing::warn!(
            path = %path.display(), operation, error = %diagnostic,
            first_failure = %first_failure, retry_ms = self.backoff.as_millis() as u64,
            "checkpoint deferred; writer remains available"
        );
        false
    }

    pub(super) fn record_result(&mut self, result: &CheckpointResult) {
        match result {
            CheckpointResult::Decision {
                decision: CheckpointDecision::Complete { .. },
                ..
            } => *self = Self::default(),
            CheckpointResult::Decision {
                decision:
                    CheckpointDecision::BelowSoftLimit { .. } | CheckpointDecision::Pending { .. },
                ..
            } => {
                // The driver is responding again. Pending work now belongs to
                // the controller's drain policy, not an old resource failure.
                // Only completion resets the accumulated backoff and diagnostic.
                self.retry = None;
            }
            CheckpointResult::Interrupted { .. } => {}
        }
    }
}

enum RetryError {
    AuthorityDenied(RuntimeWriteAuthorityStage),
    Sqlite {
        extended_code: i32,
        message: Option<String>,
    },
}

impl RetryError {
    fn from_error(error: &Failure) -> Option<Self> {
        match error {
            CheckpointError::AuthorityDenied(stage) => Some(Self::AuthorityDenied(*stage)),
            CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
                rusqlite::Error::SqliteFailure(failure, message),
            )) if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
                    | rusqlite::ErrorCode::DiskFull
            ) =>
            {
                Some(Self::Sqlite {
                    extended_code: failure.extended_code,
                    message: message.clone(),
                })
            }
            CheckpointError::Driver(_) | CheckpointError::InvalidConfig(_) => None,
        }
    }

    fn to_error(&self) -> Failure {
        match self {
            Self::AuthorityDenied(stage) => CheckpointError::AuthorityDenied(*stage),
            Self::Sqlite {
                extended_code,
                message,
            } => CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(*extended_code),
                    message.clone(),
                ),
            )),
        }
    }
}

fn failure_diagnostic(error: &Failure) -> String {
    match error {
        CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
            rusqlite::Error::SqliteFailure(failure, _),
        )) => format!(
            "{error}; SQLite primary_code={}, extended_code={} ({:?})",
            failure.extended_code & 0xff,
            failure.extended_code,
            failure.code
        ),
        _ => format!("{error}; {error:?}"),
    }
}

/// The public checkpoint reply currently carries a diagnostic string. Keep
/// numeric codes there too instead of losing them in rusqlite's Display.
pub(super) fn with_sqlite_codes(mut error: Failure) -> Failure {
    if let CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
        rusqlite::Error::SqliteFailure(failure, message),
    )) = &mut error
    {
        let reason = message.take().unwrap_or_else(|| failure.to_string());
        *message = Some(format!(
            "{reason}; SQLite primary_code={}, extended_code={}",
            failure.extended_code & 0xff,
            failure.extended_code
        ));
    }
    error
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) use tests::injected_failure;
