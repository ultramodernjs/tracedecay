use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::Connection;
use tracedecay_store::StoreRuntimeBindingV1;

use super::{
    at_authority, commit, current_watermark, idempotency_rows, initialize_schema, lookup_receipt,
};
use crate::runtime_ledger::{WriterLedgerMaintenance, WriterReplayWindowPolicy};
use crate::{
    RuntimeWriteAuthority, RuntimeWriteAuthorityError, RuntimeWriteAuthorityStage,
    runtime_ledger::{WriterLedgerRetirementAuthority, drain_retired_writer_ledger_page},
    test_support::binding,
};
use std::time::{Duration, Instant};

struct RetirementFence(AtomicBool);

impl WriterLedgerRetirementAuthority for RetirementFence {
    fn verify_retired(
        &self,
        _live: &StoreRuntimeBindingV1,
        _retired: &StoreRuntimeBindingV1,
    ) -> Result<(), RuntimeWriteAuthorityError> {
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RuntimeWriteAuthorityError::denied(
                "retirement fence revoked",
            ))
        }
    }
}

struct WriteAuthority<'a> {
    revoke_before_commit: Option<&'a RetirementFence>,
}

impl RuntimeWriteAuthority for WriteAuthority<'_> {
    fn verify(&self, stage: RuntimeWriteAuthorityStage) -> Result<(), RuntimeWriteAuthorityError> {
        if stage == RuntimeWriteAuthorityStage::BeforeCommit
            && let Some(fence) = self.revoke_before_commit
        {
            fence.0.store(false, Ordering::Release);
        }
        Ok(())
    }
}

#[test]
fn writer_owned_drain_keeps_reporting_rotation_after_historical_cleanup_finishes() {
    let directory = super::ledger_test_directory();
    let path = directory.path().join("sessions.db");
    let mut connection = Connection::open(&path).unwrap();
    let live = at_authority("operation.signal", "key.signal", 'b', 1, 8);
    let binding = binding(&live);
    let (receipt, watermark) = {
        let transaction = connection.transaction().unwrap();
        initialize_schema(&transaction).unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE domain_marker(value INTEGER); INSERT INTO domain_marker VALUES(42)",
            )
            .unwrap();
        // Three new commits each prune 256 rows, leaving five rows for the
        // independent drain. Keys match the snapshot's 71-byte receipt keys.
        for index in 0..773 {
            commit(
                &transaction,
                &at_authority(
                    &format!("operation.signal.old.{index}"),
                    &format!("sha256:{index:064x}"),
                    'a',
                    1,
                    7,
                ),
            );
        }
        let receipt = commit(&transaction, &live);
        for index in 0..2 {
            commit(
                &transaction,
                &at_authority(
                    &format!("operation.signal.live.{index}"),
                    &format!("key.signal.live.{index}"),
                    'b',
                    1,
                    8,
                ),
            );
        }
        let watermark = current_watermark(&transaction, &binding).unwrap();
        assert_eq!(idempotency_rows(&transaction).len(), 8);
        transaction.commit().unwrap();
        (receipt, watermark)
    };
    let now = Instant::now();
    let policy = WriterReplayWindowPolicy::new(2, Duration::from_secs(1)).unwrap();
    let mut maintenance = WriterLedgerMaintenance::new(binding.clone(), policy, 2, now).unwrap();
    let cancelled = AtomicBool::new(false);
    let authority = WriteAuthority {
        revoke_before_commit: None,
    };
    let mut deleted = Vec::new();
    for tick in 0..4 {
        let report = maintenance
            .tick(
                &mut connection,
                &authority,
                &cancelled,
                1,
                now + Duration::from_secs(tick * 60),
            )
            .unwrap()
            .unwrap();
        deleted.push(report.drain.deleted_rows);
        assert!(report.drain.preview.eligible_rows <= 2);
        assert_eq!(report.replay_window.receipt_rows_at_least, 3);
        assert!(report.replay_window.scan_truncated);
        assert!(report.replay_window.count_limit_reached);
        assert!(report.replay_window.rotation_required);
        assert!(
            report.handover_blocker.is_some(),
            "successful historical cleanup must not hide the owner handover blocker"
        );
        drop(connection);
        connection = Connection::open(&path).unwrap();
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            current_watermark(&transaction, &binding).unwrap(),
            watermark
        );
        assert_eq!(
            lookup_receipt(&transaction, &binding, &live.idempotency).unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            transaction
                .query_row("SELECT value FROM domain_marker", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            42
        );
    }
    assert_eq!(deleted, [2, 2, 1, 0]);
    let transaction = connection.transaction().unwrap();
    assert_eq!(idempotency_rows(&transaction), [(1, 8), (1, 8), (1, 8)]);
    assert_eq!(
        transaction
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn retired_drain_revalidates_owner_fence_before_commit_and_resumes_without_new_writes() {
    let directory = super::ledger_test_directory();
    let path = directory.path().join("sessions.db");
    let mut connection = Connection::open(&path).unwrap();
    let old = at_authority("operation.retired.0", "key.retired.0", 'a', 1, 7);
    let live = at_authority("operation.live", "key.live", 'b', 2, 7);
    let retired = binding(&old);
    let binding = binding(&live);
    let receipt =
        {
            let transaction = connection.transaction().unwrap();
            initialize_schema(&transaction).unwrap();
            transaction.execute_batch(
            "CREATE TABLE domain_marker(value INTEGER); INSERT INTO domain_marker VALUES(42)",
        ).unwrap();
            for index in 0..5 {
                commit(
                    &transaction,
                    &at_authority(
                        &format!("operation.retired.{index}"),
                        &format!("key.retired.{index}"),
                        'a',
                        1,
                        7,
                    ),
                );
            }
            let receipt = commit(&transaction, &live);
            transaction.commit().unwrap();
            receipt
        };
    let fence = RetirementFence(AtomicBool::new(true));
    let error = drain_retired_writer_ledger_page(
        &mut connection,
        &binding,
        &retired,
        &WriteAuthority {
            revoke_before_commit: Some(&fence),
        },
        &fence,
        2,
    )
    .unwrap_err();
    assert!(error.to_string().contains("retirement fence revoked"));
    drop(connection);
    let mut connection = Connection::open(&path).unwrap();
    {
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            idempotency_rows(&transaction).len(),
            6,
            "revoked fence rolls back the page"
        );
    }
    fence.0.store(true, Ordering::Release);
    let mut deleted = Vec::new();
    for _ in 0..4 {
        let outcome = drain_retired_writer_ledger_page(
            &mut connection,
            &binding,
            &retired,
            &WriteAuthority {
                revoke_before_commit: None,
            },
            &fence,
            2,
        )
        .unwrap();
        deleted.push(outcome.deleted_rows);
        assert!(outcome.preview.eligible_rows <= 2);
        drop(connection);
        connection = Connection::open(&path).unwrap();
    }
    assert_eq!(deleted, [2, 2, 1, 0]);
    let transaction = connection.transaction().unwrap();
    assert_eq!(idempotency_rows(&transaction), [(2, 7)]);
    assert!(current_watermark(&transaction, &retired).unwrap().is_some());
    assert_eq!(
        lookup_receipt(&transaction, &binding, &live.idempotency).unwrap(),
        Some(receipt)
    );
    assert_eq!(
        transaction
            .query_row("SELECT value FROM domain_marker", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        42
    );
    assert_eq!(
        transaction
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}
