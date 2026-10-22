//! Durable provider-source intent, revision policy, and restart regressions.

mod support;
use tracedecay_memory_observation::{
    ObservationRetentionPortV1, ProviderSourceDeletionIntentV1, ProviderSourceRevisionAdmissionV1,
    SqliteObservationJournal,
};
use tracedecay_memory_provider_api::contract::DeletionMode;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn deletion(mode: DeletionMode) -> ProviderSourceDeletionIntentV1<'static> {
    ProviderSourceDeletionIntentV1 {
        operation_id: "delete.original.1",
        provider_id: "ncm",
        original_source_sha256: SOURCE,
        expected_fence_revision: 0,
        mode,
        source_revision: Some("source_r1"),
        authority_ref: "host.control.1",
        accepted_at_utc_micros: 100,
    }
}

fn admission() -> ProviderSourceRevisionAdmissionV1<'static> {
    ProviderSourceRevisionAdmissionV1 {
        operation_id: "admit.original.2",
        provider_id: "ncm",
        original_source_sha256: SOURCE,
        expected_fence_revision: 1,
        source_revision: "source_r2",
        authority_ref: "host.canonical_revision.2",
        accepted_at_utc_micros: 200,
    }
}

#[test]
fn offline_intent_survives_three_lifetimes_and_retries_keep_original_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let original = {
        let journal = SqliteObservationJournal::open(&path, support::policy())?;
        let receipt = journal
            .record_provider_source_deletion_intent(&deletion(DeletionMode::RemoveInfluence))?;
        assert!(!receipt.provider_erasure_verified);
        assert!(receipt.fence.blocks_revision(Some("source_r1")));
        assert!(
            receipt
                .fence
                .blocks_revision(Some("arbitrary_new_bytes_revision"))
        );
        assert!(receipt.fence.blocks_revision(None));
        // Another provider owns independent advisory effects.
        assert!(
            journal
                .read_provider_source_fence("tracedecay.native", SOURCE)?
                .is_none()
        );
        receipt
    };
    {
        let journal = SqliteObservationJournal::open(&path, support::policy())?;
        assert_eq!(
            journal
                .read_provider_source_fence("ncm", SOURCE)?
                .ok_or("expected provider source fence or fixture JSON pointer")?,
            original.fence
        );
        let receipt = journal.admit_provider_source_revision(&admission())?;
        assert_eq!(receipt.fence.revision, 2);
        assert!(!receipt.fence.blocks_revision(Some("source_r2")));
        assert!(receipt.fence.blocks_revision(Some("source_r1")));
        assert_eq!(
            journal.admit_provider_source_revision(&admission())?,
            receipt
        );
        // Aging delivery audits never ages out a source privacy fence.
        journal.sweep_expired(i64::MAX / 2, 10)?;
    }
    {
        let journal = SqliteObservationJournal::open(&path, support::policy())?;
        let mut retry = deletion(DeletionMode::RemoveInfluence);
        retry.accepted_at_utc_micros = 999;
        assert_eq!(
            journal.record_provider_source_deletion_intent(&retry)?,
            original
        );
        let current = journal
            .read_provider_source_fence("ncm", SOURCE)?
            .ok_or("expected provider source fence or fixture JSON pointer")?;
        assert_eq!(current.revision, 2);
        assert!(!current.blocks_revision(Some("source_r2")));
        retry.source_revision = Some("other_revision");
        assert!(
            journal
                .record_provider_source_deletion_intent(&retry)
                .is_err()
        );
        assert_eq!(
            journal
                .read_provider_source_fence("ncm", SOURCE)?
                .ok_or("expected provider source fence or fixture JSON pointer")?,
            current
        );
    }
    Ok(())
}

#[test]
fn strong_privacy_modes_never_reopen_and_stale_or_unchanged_revisions_fail() -> TestResult {
    for mode in [DeletionMode::HardDelete, DeletionMode::Anonymize] {
        let journal = SqliteObservationJournal::open_in_memory(support::policy())?;
        journal.record_provider_source_deletion_intent(&deletion(mode))?;
        assert!(
            journal
                .admit_provider_source_revision(&admission())
                .is_err()
        );
        let mut weaker = deletion(DeletionMode::RemoveInfluence);
        weaker.operation_id = "new_weaker_intent";
        weaker.expected_fence_revision = 1;
        weaker.source_revision = Some("source_r2");
        let receipt = journal.record_provider_source_deletion_intent(&weaker)?;
        assert_eq!(receipt.fence.mode, mode.as_wire());
        assert!(receipt.fence.blocks_revision(Some("source_r2")));
    }
    let journal = SqliteObservationJournal::open_in_memory(support::policy())?;
    journal.record_provider_source_deletion_intent(&deletion(DeletionMode::RemoveInfluence))?;
    let mut request = admission();
    request.source_revision = "source_r1";
    assert!(journal.admit_provider_source_revision(&request).is_err());
    request.source_revision = "";
    assert!(journal.admit_provider_source_revision(&request).is_err());
    request.source_revision = "source_r2";
    request.expected_fence_revision = 0;
    assert!(journal.admit_provider_source_revision(&request).is_err());
    assert_eq!(
        journal
            .read_provider_source_fence("ncm", SOURCE)?
            .ok_or("expected provider source fence or fixture JSON pointer")?
            .revision,
        1
    );
    Ok(())
}

#[test]
fn fence_reads_do_not_mutate_the_journal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    journal.record_provider_source_deletion_intent(&deletion(DeletionMode::HardDelete))?;
    let observer = rusqlite::Connection::open(&path)?;
    let before: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert!(journal.read_provider_source_fence("ncm", SOURCE)?.is_some());
    assert!(
        journal
            .read_provider_source_fence("tracedecay.native", SOURCE)?
            .is_none()
    );
    let after: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn exact_admission_read_preserves_payload_receipt_and_never_mutates_delivery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    let admitted = support::Builder::default().build()?;
    let missing = support::Builder::at_sequence(2).build()?;
    journal.append_admitted_at(&admitted, support::T0)?;
    let observer = rusqlite::Connection::open(&path)?;
    let before: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert_eq!(
        journal.read_admitted_observation_by_idempotency(&admitted.idempotency_key)?,
        Some(admitted.clone())
    );
    assert!(
        journal
            .read_admitted_observation_by_idempotency(&missing.idempotency_key)?
            .is_none()
    );
    let after: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert_eq!(before, after);
    let (state, attempts, lease): (String, i64, Option<String>) = observer.query_row(
        "SELECT state, attempt_number, lease_id FROM tdmem_observation_delivery_v1 WHERE idempotency_key = ?1",
        [admitted.idempotency_key.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((state.as_str(), attempts, lease), ("pending", 0, None));
    Ok(())
}

#[test]
fn hard_delete_upgrades_anonymize_and_immutable_receipts_keep_each_intent() -> TestResult {
    let journal = SqliteObservationJournal::open_in_memory(support::policy())?;
    let original =
        journal.record_provider_source_deletion_intent(&deletion(DeletionMode::Anonymize))?;
    let mut upgrade = deletion(DeletionMode::HardDelete);
    upgrade.operation_id = "hard_delete_upgrade";
    upgrade.expected_fence_revision = 1;
    let stronger = journal.record_provider_source_deletion_intent(&upgrade)?;
    assert_eq!(stronger.fence.mode, "hard_delete");
    let mut weaker = deletion(DeletionMode::RemoveInfluence);
    weaker.operation_id = "weaker_after_upgrade";
    weaker.expected_fence_revision = 2;
    assert_eq!(
        journal
            .record_provider_source_deletion_intent(&weaker)?
            .fence
            .mode,
        "hard_delete"
    );
    assert_eq!(
        journal.record_provider_source_deletion_intent(&deletion(DeletionMode::Anonymize))?,
        original
    );
    assert_eq!(
        journal.record_provider_source_deletion_intent(&upgrade)?,
        stronger
    );
    assert_eq!(original.fence.mode, "anonymize");
    assert_eq!(
        journal
            .read_provider_source_fence("ncm", SOURCE)?
            .ok_or("expected provider source fence or fixture JSON pointer")?
            .mode,
        "hard_delete"
    );
    Ok(())
}

#[test]
fn bounded_intent_refuses_cancelled_or_spent_work_without_recording_intent() -> TestResult {
    use tracedecay_memory_observation::{ObservationJournalError, RecoveryTimeBudgetV1};
    use tracedecay_memory_provider_api::CancellationToken;
    let journal = SqliteObservationJournal::open_in_memory(support::policy())?;
    let request = deletion(DeletionMode::HardDelete);
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        journal.record_provider_source_deletion_intent_bounded(
            &request,
            RecoveryTimeBudgetV1 {
                remaining_micros: 1_000_000
            },
            &token,
        ),
        Err(ObservationJournalError::OperationCancelled { .. })
    ));
    assert!(matches!(
        journal.read_provider_source_deletion_intent_receipt_bounded(
            &request,
            RecoveryTimeBudgetV1 {
                remaining_micros: 1_000_000
            },
            &token,
        ),
        Err(ObservationJournalError::OperationCancelled { .. })
    ));
    let token = CancellationToken::new();
    assert!(matches!(
        journal.record_provider_source_deletion_intent_bounded(
            &request,
            RecoveryTimeBudgetV1 {
                remaining_micros: 0
            },
            &token,
        ),
        Err(ObservationJournalError::BudgetExhausted { .. })
    ));
    assert!(journal.read_provider_source_fence("ncm", SOURCE)?.is_none());
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(
                &request,
                RecoveryTimeBudgetV1 {
                    remaining_micros: 1_000_000
                },
                &token,
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn bounded_intent_and_receipt_lookup_keep_original_acceptance_after_later_revision() -> TestResult {
    use tracedecay_memory_observation::RecoveryTimeBudgetV1;
    use tracedecay_memory_provider_api::CancellationToken;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let request = deletion(DeletionMode::RemoveInfluence);
    let token = CancellationToken::new();
    let budget = || RecoveryTimeBudgetV1 {
        remaining_micros: 1_000_000,
    };
    let original = {
        let journal = SqliteObservationJournal::open(&path, support::policy())?;
        let receipt =
            journal.record_provider_source_deletion_intent_bounded(&request, budget(), &token)?;
        assert!(!receipt.provider_erasure_verified);
        journal.admit_provider_source_revision(&admission())?;
        receipt
    };
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    let observer = rusqlite::Connection::open(&path)?;
    let before: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    let mut retry = deletion(DeletionMode::RemoveInfluence);
    retry.accepted_at_utc_micros = 9_999;
    assert_eq!(
        journal.read_provider_source_deletion_intent_receipt_bounded(&retry, budget(), &token)?,
        Some(original.clone())
    );
    let after: i64 = observer.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    assert_eq!(before, after);
    assert_eq!(
        journal.record_provider_source_deletion_intent_bounded(&retry, budget(), &token)?,
        original
    );
    let current = journal
        .read_provider_source_fence("ncm", SOURCE)?
        .ok_or("expected provider source fence or fixture JSON pointer")?;
    assert_eq!(current.revision, 2);
    assert!(!current.blocks_revision(Some("source_r2")));
    retry.source_revision = Some("changed_retry");
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(&retry, budget(), &token)
            .is_err()
    );
    assert!(
        journal
            .record_provider_source_deletion_intent_bounded(&retry, budget(), &token)
            .is_err()
    );
    assert_eq!(
        journal
            .read_provider_source_fence("ncm", SOURCE)?
            .ok_or("expected provider source fence or fixture JSON pointer")?,
        current
    );
    Ok(())
}

#[test]
fn bounded_intent_refuses_a_busy_writer_without_leaving_either_atomic_row() -> TestResult {
    use tracedecay_memory_observation::{ObservationJournalError, RecoveryTimeBudgetV1};
    use tracedecay_memory_provider_api::CancellationToken;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    let writer = rusqlite::Connection::open(&path)?;
    writer.execute_batch("BEGIN IMMEDIATE")?;
    let token = CancellationToken::new();
    let request = deletion(DeletionMode::HardDelete);
    let started = std::time::Instant::now();
    let result = journal.record_provider_source_deletion_intent_bounded(
        &request,
        RecoveryTimeBudgetV1 {
            remaining_micros: 5_000_000,
        },
        &token,
    );
    assert!(matches!(
        result,
        Err(ObservationJournalError::BudgetExhausted { .. })
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    writer.execute_batch("ROLLBACK")?;
    assert!(journal.read_provider_source_fence("ncm", SOURCE)?.is_none());
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(
                &request,
                RecoveryTimeBudgetV1 {
                    remaining_micros: 1_000_000
                },
                &token,
            )?
            .is_none()
    );
    let receipt = journal.record_provider_source_deletion_intent_bounded(
        &request,
        RecoveryTimeBudgetV1 {
            remaining_micros: 1_000_000,
        },
        &token,
    )?;
    assert_eq!(receipt.fence.revision, 1);
    Ok(())
}

#[test]
fn immutable_receipt_lookup_refuses_corrupt_binding_and_oversized_json() -> TestResult {
    use tracedecay_memory_observation::RecoveryTimeBudgetV1;
    use tracedecay_memory_provider_api::CancellationToken;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    let request = deletion(DeletionMode::HardDelete);
    let original = journal.record_provider_source_deletion_intent(&request)?;
    let baseline = serde_json::to_value(&original)?;
    let observer = rusqlite::Connection::open(&path)?;
    let token = CancellationToken::new();
    let modifications = [
        ("/operation_id", serde_json::json!("another_operation")),
        ("/provider_erasure_verified", serde_json::json!(true)),
        ("/fence/provider_id", serde_json::json!("tracedecay.native")),
        (
            "/fence/original_source_sha256",
            serde_json::json!("f".repeat(64)),
        ),
        ("/fence/revision", serde_json::json!(99)),
        ("/fence/mode", serde_json::json!("remove_influence")),
        (
            "/fence/deleted_source_revision",
            serde_json::json!("changed"),
        ),
        ("/fence/admitted_source_revision", serde_json::json!("new")),
        ("/fence/authority_ref", serde_json::json!("changed")),
    ];
    for (pointer, replacement) in modifications {
        let mut corrupt = baseline.clone();
        *corrupt
            .pointer_mut(pointer)
            .ok_or("expected provider source fence or fixture JSON pointer")? = replacement;
        observer.execute(
            "UPDATE tdmem_provider_source_intent_receipt_v1 SET receipt_json = ?1
             WHERE provider_id = ?2 AND operation_id = ?3",
            rusqlite::params![
                serde_json::to_string(&corrupt)?,
                request.provider_id,
                request.operation_id
            ],
        )?;
        assert!(
            journal
                .read_provider_source_deletion_intent_receipt_bounded(
                    &request,
                    RecoveryTimeBudgetV1 {
                        remaining_micros: 1_000_000
                    },
                    &token,
                )
                .is_err(),
            "{pointer}"
        );
        assert!(
            journal
                .record_provider_source_deletion_intent_bounded(
                    &request,
                    RecoveryTimeBudgetV1 {
                        remaining_micros: 1_000_000
                    },
                    &token,
                )
                .is_err(),
            "{pointer}"
        );
        assert_eq!(
            journal
                .read_provider_source_fence("ncm", SOURCE)?
                .ok_or("expected provider source fence or fixture JSON pointer")?,
            original.fence
        );
    }
    observer.execute(
        "UPDATE tdmem_provider_source_intent_receipt_v1 SET receipt_json = ?1
         WHERE provider_id = ?2 AND operation_id = ?3",
        rusqlite::params![
            "x".repeat(16_385),
            request.provider_id,
            request.operation_id
        ],
    )?;
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(
                &request,
                RecoveryTimeBudgetV1 {
                    remaining_micros: 1_000_000
                },
                &token,
            )
            .is_err()
    );
    observer.execute(
        "UPDATE tdmem_provider_source_intent_receipt_v1 SET receipt_json = ?1, request_json = ?2
         WHERE provider_id = ?3 AND operation_id = ?4",
        rusqlite::params![
            serde_json::to_string(&original)?,
            "x".repeat(16_385),
            request.provider_id,
            request.operation_id
        ],
    )?;
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(
                &request,
                RecoveryTimeBudgetV1 {
                    remaining_micros: 1_000_000
                },
                &token,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn bounded_intent_rolls_back_fence_when_immutable_receipt_insert_fails() -> TestResult {
    use tracedecay_memory_observation::RecoveryTimeBudgetV1;
    use tracedecay_memory_provider_api::CancellationToken;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let journal = SqliteObservationJournal::open(&path, support::policy())?;
    let observer = rusqlite::Connection::open(&path)?;
    observer.execute_batch(
        "CREATE TRIGGER refuse_intent_receipt BEFORE INSERT
         ON tdmem_provider_source_intent_receipt_v1
         BEGIN SELECT RAISE(ABORT, 'test receipt refusal'); END",
    )?;
    let request = deletion(DeletionMode::HardDelete);
    let token = CancellationToken::new();
    let budget = || RecoveryTimeBudgetV1 {
        remaining_micros: 1_000_000,
    };
    assert!(
        journal
            .record_provider_source_deletion_intent_bounded(&request, budget(), &token,)
            .is_err()
    );
    assert!(journal.read_provider_source_fence("ncm", SOURCE)?.is_none());
    assert!(
        journal
            .read_provider_source_deletion_intent_receipt_bounded(&request, budget(), &token,)?
            .is_none()
    );
    observer.execute_batch("DROP TRIGGER refuse_intent_receipt")?;
    let receipt =
        journal.record_provider_source_deletion_intent_bounded(&request, budget(), &token)?;
    assert_eq!(receipt.fence.revision, 1);
    assert_eq!(
        journal.read_provider_source_deletion_intent_receipt_bounded(&request, budget(), &token,)?,
        Some(receipt)
    );
    Ok(())
}
