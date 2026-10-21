use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use tempfile::TempDir;
use tracedecay_store::{AdmissionConfigV1, VerifiedStoreLocatorV1};

use crate::{
    ExactSqlOnlyStorageOperationV1, ExistingWriterLocator, PersistentWriter,
    checkpoint::{CheckpointError, RusqliteCheckpointError},
    exact_sql::ExactSqlHandle,
    reader::{ExactSqlOnlyReaderV1, ExistingReaderLocator, ReaderPool},
    test_support::{binding, metadata},
};

type Failure = CheckpointError<RusqliteCheckpointError>;

struct Injection {
    operation: &'static str,
    code: Option<i32>,
    attempts: usize,
    attempt_times: Vec<std::time::Instant>,
}

fn injections() -> &'static Mutex<HashMap<PathBuf, Injection>> {
    static INJECTIONS: OnceLock<Mutex<HashMap<PathBuf, Injection>>> = OnceLock::new();
    INJECTIONS.get_or_init(Mutex::default)
}

pub(in crate::writer::worker) fn injected_failure(
    path: &Path,
    operation: &'static str,
) -> Option<Failure> {
    let mut injections = injections().lock().unwrap();
    let injection = injections.get_mut(path)?;
    if injection.operation != operation {
        return None;
    }
    injection.attempts += 1;
    injection.attempt_times.push(std::time::Instant::now());
    injection.code.map(|code| {
        CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("injected checkpoint capacity failure".to_owned()),
            ),
        ))
    })
}

struct Fixture {
    writer: PersistentWriter,
    _readers: ReaderPool<ExactSqlOnlyReaderV1>,
    handle: ExactSqlHandle,
    path: PathBuf,
    _directory: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_checkpoint_blockers(
            AdmissionConfigV1::default(),
            Arc::new(crate::writer::NoCheckpointBlockers),
        )
    }

    fn with_checkpoint_blockers(
        config: AdmissionConfigV1,
        blockers: Arc<dyn crate::checkpoint::CheckpointBlockerSource>,
    ) -> Self {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("sessions.db");
        // Retention-shaped input: one old, eligible row and one live row.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE retention_evidence(id INTEGER PRIMARY KEY, eligible INTEGER);
                 INSERT INTO retention_evidence VALUES (1, 1), (2, 0);",
            )
            .unwrap();
        let path = path.canonicalize().unwrap();
        let binding = binding(&metadata("operation.retention", "key.retention", 'r'));
        let locator = VerifiedStoreLocatorV1::new(
            binding.shard_id.clone(),
            binding.incarnation,
            tracedecay_store::LocatorDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        );
        let writer = PersistentWriter::start_with_checkpoint_blockers(
            &crate::native_runtime::handle().unwrap(),
            ExistingWriterLocator::new(binding.clone(), locator.clone(), path.clone()).unwrap(),
            config.clone(),
            ExactSqlOnlyStorageOperationV1,
            blockers,
            None,
        )
        .unwrap();
        let readers = ReaderPool::start(
            ExistingReaderLocator::new(binding, locator, path.clone()).unwrap(),
            config.readers,
            ExactSqlOnlyReaderV1,
        )
        .unwrap();
        let handle = ExactSqlHandle::attach(&writer, &readers).unwrap();
        Self {
            writer,
            _readers: readers,
            handle,
            path,
            _directory: directory,
        }
    }

    fn inject(&self, operation: &'static str, code: i32) {
        injections().lock().unwrap().insert(
            self.path.clone(),
            Injection {
                operation,
                code: Some(code),
                attempts: 0,
                attempt_times: Vec::new(),
            },
        );
    }

    fn recover_capacity(&self) {
        injections()
            .lock()
            .unwrap()
            .get_mut(&self.path)
            .unwrap()
            .code = None;
    }

    async fn retain(&self) {
        let transaction = self.handle.begin_immediate_async().await.expect(
            "checkpoint capacity failure must not poison subsequent retention transactions",
        );
        transaction
            .execute_batch_async("DELETE FROM retention_evidence WHERE eligible = 1".to_owned())
            .await
            .unwrap();
        transaction.commit_async().await.unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        injections()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.path);
    }
}

struct Probe {
    cancellation: tracedecay_store::RuntimeCancellationIdentityV1,
    deadline: tracedecay_store::RuntimeDeadlineV1,
    interruption: Option<tracedecay_store::RuntimeInterruptionV1>,
}

impl tracedecay_store::RuntimeRequestProbeV1 for Probe {
    fn cancellation_identity(&self) -> &tracedecay_store::RuntimeCancellationIdentityV1 {
        &self.cancellation
    }

    fn deadline_identity(&self) -> &tracedecay_store::RuntimeDeadlineV1 {
        &self.deadline
    }

    fn interruption(&self) -> Option<tracedecay_store::RuntimeInterruptionV1> {
        self.interruption
    }

    fn try_begin_commit(&self) -> bool {
        true
    }
}

impl Fixture {
    async fn requested_checkpoint(
        &self,
    ) -> Result<crate::CheckpointOutcome, crate::CheckpointControlError> {
        self.checkpoint_with(None).await
    }

    async fn checkpoint_with(
        &self,
        interruption: Option<tracedecay_store::RuntimeInterruptionV1>,
    ) -> Result<crate::CheckpointOutcome, crate::CheckpointControlError> {
        let request =
            crate::test_support::request(metadata("operation.checkpoint", "key.checkpoint", 'c'));
        self.writer
            .checkpoint_handle()
            .trigger(crate::CheckpointRequest::new(
                crate::CheckpointBlockers::default(),
                Arc::new(Probe {
                    cancellation: request.control().cancellation.clone(),
                    deadline: request.control().deadline.clone(),
                    interruption,
                }),
            ))
            .unwrap()
            .wait(&crate::native_runtime::cx().unwrap())
            .await
    }
}

#[test]
fn requested_checkpoint_busy_does_not_poison_exact_sql_writer() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for code in [
                rusqlite::ffi::SQLITE_BUSY,
                rusqlite::ffi::SQLITE_LOCKED,
                rusqlite::ffi::SQLITE_FULL,
            ] {
                let fixture = Fixture::new();
                fixture.inject("requested_checkpoint", code);
                let error = fixture.requested_checkpoint().await.unwrap_err();
                assert!(matches!(error, crate::CheckpointControlError::Driver(_)));
                fixture.retain().await;
                for _ in 0..8 {
                    fixture.requested_checkpoint().await.unwrap_err();
                }
                assert_eq!(
                    injections().lock().unwrap()[&fixture.path].attempts,
                    1,
                    "requested checkpoints must share the scheduled retry backoff"
                );
                fixture.recover_capacity();
                let cancelled = fixture
                    .checkpoint_with(Some(tracedecay_store::RuntimeInterruptionV1::Cancelled))
                    .await
                    .unwrap();
                assert!(
                    matches!(
                        cancelled,
                        crate::CheckpointOutcome::Interrupted {
                            reason: crate::CheckpointInterruption::Cancelled,
                            ..
                        }
                    ),
                    "backoff must preserve request cancellation"
                );
                fixture.retain().await;
            }
        });
}

#[test]
fn scheduled_checkpoint_full_does_not_poison_exact_sql_writer() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let fixture = Fixture::new();
            fixture.inject("scheduled_checkpoint", rusqlite::ffi::SQLITE_FULL);
            fixture
                .handle
                .execute_batch_async("UPDATE retention_evidence SET eligible = eligible".to_owned())
                .await
                .unwrap();
            // The actor publishes its command reply before evaluating the
            // checkpoint. Wait for that boundary, not a fixed sleep.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if injections().lock().unwrap()[&fixture.path].attempts > 0 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            fixture.recover_capacity();
            fixture.retain().await;
            let remaining = fixture
                .handle
                .query_async(
                    crate::exact_sql::ExactSqlStatement::new(
                        "SELECT id FROM retention_evidence ORDER BY id".to_owned(),
                        vec![],
                    )
                    .unwrap(),
                    std::time::Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert_eq!(
                remaining.rows.len(),
                1,
                "live evidence must survive retention"
            );
            assert_eq!(
                remaining.rows[0].values,
                vec![crate::exact_sql::ExactSqlValue::Integer(2)]
            );
        });
}

fn sqlite_failure(code: i32) -> Failure {
    CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            Some("original checkpoint error".to_owned()),
        ),
    ))
}

#[test]
fn checkpoint_failure_backoff_is_capped_and_resets_only_after_completion() {
    use super::CheckpointFailurePolicy;
    use crate::checkpoint::{
        CheckpointDecision, CheckpointMode, CheckpointReport, CheckpointResult, WalPressure,
        WalSample,
    };
    use std::time::{Duration, Instant};

    let mut policy = CheckpointFailurePolicy::default();
    let mut now = Instant::now();
    let path = Path::new("/fixture/sessions.db");
    for seconds in [1, 2, 4, 8, 16, 32, 60, 60, 60] {
        assert!(!policy.record_failure(
            path,
            "scheduled_checkpoint",
            &sqlite_failure(rusqlite::ffi::SQLITE_FULL),
            now
        ));
        let due = now + Duration::from_secs(seconds);
        assert_eq!(policy.retry_due(None), Some(due));
        assert!(policy.defers(due - Duration::from_nanos(1)));
        assert!(!policy.defers(due));
        // Neither controller nor resource retry may bypass the other's wait.
        assert_eq!(
            policy.retry_due(Some(due + Duration::from_secs(7))),
            Some(due + Duration::from_secs(7))
        );
        assert_eq!(policy.retry_due(Some(now)), Some(due));
        now = due;
    }
    assert!(
        policy
            .first_failure
            .as_ref()
            .unwrap()
            .contains("/fixture/sessions.db: scheduled_checkpoint")
    );
    assert!(
        policy
            .first_failure
            .as_ref()
            .unwrap()
            .contains("primary_code=13, extended_code=13")
    );
    let pending = CheckpointResult::Decision {
        sample: WalSample::default(),
        decision: CheckpointDecision::Pending {
            mode: CheckpointMode::Restart,
            pressure: WalPressure::Hard,
            wal_bytes: 64 * 1024,
            report: CheckpointReport {
                busy: true,
                log_frames: 16,
                checkpointed_frames: 16,
            },
            snapshot_blockers: crate::CheckpointBlockers::default(),
            hard_drain_required: true,
            fence_expired: false,
            elapsed: Duration::ZERO,
        },
    };
    policy.record_result(&pending);
    assert_eq!(
        policy.retry_due(None),
        None,
        "Pending must release the resource deadline even without a drain deadline"
    );
    assert_eq!(
        policy.retry_due(Some(now + Duration::from_millis(100))),
        Some(now + Duration::from_millis(100)),
        "a responding driver hands Pending work back to the hard-fence policy"
    );
    assert!(!policy.record_failure(
        path,
        "scheduled_checkpoint",
        &sqlite_failure(rusqlite::ffi::SQLITE_FULL),
        now
    ));
    assert_eq!(
        policy.retry_due(None),
        Some(now + Duration::from_secs(60)),
        "Pending clears the retry deadline, not the accumulated failure backoff"
    );
    let below_soft = CheckpointResult::Decision {
        sample: WalSample::default(),
        decision: CheckpointDecision::BelowSoftLimit { wal_bytes: 0 },
    };
    policy.record_result(&below_soft);
    assert_eq!(
        policy.retry_due(None),
        None,
        "no work should leave an idle retry timer"
    );
    assert!(!policy.record_failure(
        path,
        "requested_checkpoint",
        &sqlite_failure(rusqlite::ffi::SQLITE_BUSY_SNAPSHOT),
        now
    ));
    assert_eq!(
        policy.retry_due(None),
        Some(now + Duration::from_secs(60)),
        "sampling is not checkpoint completion"
    );
    assert!(
        policy
            .first_failure
            .as_ref()
            .unwrap()
            .contains("primary_code=13, extended_code=13")
    );
    let complete = CheckpointResult::Decision {
        sample: WalSample::default(),
        decision: CheckpointDecision::Complete {
            mode: CheckpointMode::Restart,
            pressure: WalPressure::Soft,
            wal_bytes: 0,
            report: CheckpointReport {
                busy: false,
                log_frames: 0,
                checkpointed_frames: 0,
            },
            elapsed: Duration::ZERO,
        },
    };
    policy.record_result(&complete);
    assert_eq!(policy.retry_due(None), None);
    assert!(policy.first_failure.is_none());
    assert!(!policy.record_failure(
        path,
        "scheduled_checkpoint",
        &sqlite_failure(rusqlite::ffi::SQLITE_FULL),
        now
    ));
    assert_eq!(policy.retry_due(None), Some(now + Duration::from_secs(1)));
}

#[test]
fn checkpoint_resource_retry_is_bounded_and_recovers_without_new_writes() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let fixture = Fixture::new();
            fixture.inject("scheduled_checkpoint", rusqlite::ffi::SQLITE_FULL);
            fixture
                .handle
                .execute_batch_async("UPDATE retention_evidence SET eligible = eligible".to_owned())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                while injections().lock().unwrap()[&fixture.path].attempts == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // Every transaction would otherwise retry immediately after commit.
            for _ in 0..20 {
                fixture.retain().await;
            }
            {
                let injections = injections().lock().unwrap();
                for pair in injections[&fixture.path].attempt_times.windows(2) {
                    assert!(
                        pair[1].duration_since(pair[0]) >= super::RETRY_MIN,
                        "checkpoint retries must not follow each commit"
                    );
                }
            }
            fixture.recover_capacity();
            let attempts_before = injections().lock().unwrap()[&fixture.path].attempts;
            // No new transaction wakes the worker: recovery needs its idle timer.
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                loop {
                    if injections().lock().unwrap()[&fixture.path].attempts > attempts_before {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            fixture.retain().await;
        });
}

#[derive(Default)]
struct PinnedReaderBlockers {
    revocations: Mutex<Vec<std::time::Instant>>,
}

impl crate::checkpoint::CheckpointBlockerSource for PinnedReaderBlockers {
    fn checkpoint_blockers(&self) -> crate::CheckpointBlockers {
        crate::CheckpointBlockers {
            blockers: vec![crate::CheckpointBlocker::PhysicalReader {
                reader_id: 1,
                age: std::time::Duration::from_secs(30),
            }],
            omitted: 0,
        }
    }

    fn await_released_snapshots(&self) -> futures_util::future::BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn revoke_snapshots_older_than(&self, age: std::time::Duration) -> usize {
        assert_eq!(age, std::time::Duration::from_secs(5));
        self.revocations
            .lock()
            .unwrap()
            .push(std::time::Instant::now());
        // This raw SQLite reader deliberately stays pinned, like a holder
        // outside the runtime's revocable snapshot authority.
        0
    }
}

#[test]
fn accumulated_resource_backoff_does_not_delay_hard_fence_deadlines() {
    use std::time::{Duration, Instant};

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let blockers = Arc::new(PinnedReaderBlockers::default());
            let mut config = AdmissionConfigV1::default();
            config.wal.soft_limit_bytes = 16 * 1024;
            config.wal.hard_limit_bytes = 32 * 1024;
            let fixture = Fixture::with_checkpoint_blockers(config, blockers.clone());
            fixture.inject("scheduled_checkpoint", rusqlite::ffi::SQLITE_FULL);
            fixture
                .handle
                .execute_batch_async(
                    "CREATE TABLE wal_padding(payload BLOB);
                     INSERT INTO wal_padding VALUES(zeroblob(32768));"
                        .to_owned(),
                )
                .await
                .unwrap();
            // Four real timer attempts accumulate 1, 2, 4, then 8 seconds of
            // resource backoff, longer than either hard-fence deadline.
            tokio::time::timeout(Duration::from_secs(20), async {
                while injections().lock().unwrap()[&fixture.path].attempts < 4 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("idle retries must accumulate resource backoff");
            let pinned = rusqlite::Connection::open(&fixture.path).unwrap();
            pinned
                .execute_batch("BEGIN; SELECT * FROM retention_evidence;")
                .unwrap();
            fixture.recover_capacity();
            let checkpoint = fixture.writer.checkpoint_handle();
            tokio::time::timeout(Duration::from_secs(12), async {
                loop {
                    if let Some(crate::CheckpointOutcome::Pending {
                        wal,
                        hard_pressure: true,
                        ..
                    }) = checkpoint.status().latest
                    {
                        assert!(wal.bytes >= 32 * 1024);
                        assert!(
                            wal.bytes < 64 * 1024,
                            "fixture must be below the write ceiling"
                        );
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("recovered checkpoint must raise a hard-pressure fence");
            let fenced_at = Instant::now();
            // Capacity fails again during the fence. Revocation and expiry
            // must progress without bypassing the next resource retry (16s).
            fixture.inject("scheduled_checkpoint", rusqlite::ffi::SQLITE_FULL);
            tokio::time::timeout(Duration::from_secs(6), async {
                while blockers.revocations.lock().unwrap().is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect(
                "resource backoff must not postpone snapshot revocation past its read deadline",
            );
            tokio::time::timeout(
                Duration::from_millis(7500).saturating_sub(fenced_at.elapsed()),
                async {
                    while !matches!(
                        checkpoint.pressure(),
                        crate::CheckpointPressure::FenceExpired { .. }
                    ) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                },
            )
            .await
            .expect("resource backoff must not extend the hard fence");
            assert_eq!(
                injections().lock().unwrap()[&fixture.path].attempts,
                1,
                "fence lifecycle work must not bypass physical checkpoint backoff"
            );
            tokio::time::timeout(Duration::from_secs(2), fixture.retain())
                .await
                .expect("retention must resume below the twice-hard write ceiling");
            let remaining = fixture
                .handle
                .query_async(
                    crate::exact_sql::ExactSqlStatement::new(
                        "SELECT id FROM retention_evidence ORDER BY id".to_owned(),
                        vec![],
                    )
                    .unwrap(),
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert_eq!(remaining.rows.len(), 1);
            assert_eq!(
                remaining.rows[0].values,
                vec![crate::exact_sql::ExactSqlValue::Integer(2)]
            );
            drop(pinned);
        });
}

#[test]
fn terminal_checkpoint_fault_preserves_reason_and_stays_closed() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for code in [
                rusqlite::ffi::SQLITE_CORRUPT_INDEX,
                rusqlite::ffi::SQLITE_NOTADB,
                rusqlite::ffi::SQLITE_IOERR_READ,
                rusqlite::ffi::SQLITE_CANTOPEN_ISDIR,
            ] {
                let fixture = Fixture::new();
                fixture.inject("requested_checkpoint", code);
                let error = fixture
                    .requested_checkpoint()
                    .await
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("injected checkpoint capacity failure"));
                assert!(
                    error.contains(&format!("primary_code={}", code & 0xff)),
                    "{error}"
                );
                assert!(error.contains(&format!("extended_code={code}")), "{error}");
                fixture.recover_capacity();
                assert!(
                    matches!(
                        fixture.handle.begin_immediate_async().await,
                        Err(crate::exact_sql::ExactSqlError::WriterUnavailable)
                    ),
                    "capacity recovery cannot resurrect a terminal writer"
                );
            }
        });
}

#[test]
fn checkpoint_policy_keeps_invalid_policy_and_authority_distinct() {
    use super::CheckpointFailurePolicy;
    use crate::{RuntimeWriteAuthorityStage, checkpoint::CheckpointConfigError};
    let mut policy = CheckpointFailurePolicy::default();
    let now = std::time::Instant::now();
    let path = Path::new("/fixture/sessions.db");
    assert!(policy.record_failure(
        path,
        "scheduled_checkpoint",
        &CheckpointError::InvalidConfig(CheckpointConfigError::ZeroSoftLimit),
        now
    ));
    assert!(policy.record_failure(
        path,
        "scheduled_checkpoint",
        &CheckpointError::Driver(RusqliteCheckpointError::Sqlite(
            rusqlite::Error::InvalidQuery
        )),
        now
    ));
    assert!(!policy.record_failure(
        path,
        "scheduled_checkpoint",
        &CheckpointError::AuthorityDenied(RuntimeWriteAuthorityStage::Dequeued),
        now
    ));
    assert!(matches!(
        policy.deferred_error(now),
        Some(CheckpointError::AuthorityDenied(
            RuntimeWriteAuthorityStage::Dequeued
        ))
    ));
}
