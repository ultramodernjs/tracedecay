use rusqlite::Connection;

mod maintenance;

fn ledger_test_directory() -> tempfile::TempDir {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .or_else(|| std::env::var_os("TEST_TMPDIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&root).unwrap();
    tempfile::tempdir_in(root).unwrap()
}

#[test]
fn maintenance_drains_superseded_backlog_without_foreground_commits() {
    use crate::runtime_ledger::preview_writer_ledger_cleanup;

    let directory = ledger_test_directory();
    let mut connection = Connection::open(directory.path().join("sessions.db")).unwrap();
    let advanced = at_authority("operation.drain.advance", "key.drain.advance", 'b', 1, 8);
    let binding = binding(&advanced);
    let receipt = {
        let transaction = connection.transaction().unwrap();
        initialize_schema(&transaction).unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE domain_marker(value INTEGER); INSERT INTO domain_marker VALUES(42)",
            )
            .unwrap();
        for index in 0..279 {
            commit(
                &transaction,
                &at_authority(
                    &format!("operation.drain.{index}"),
                    &format!("key.drain.{index}"),
                    'a',
                    1,
                    7,
                ),
            );
        }
        let receipt = commit(&transaction, &advanced);
        transaction.commit().unwrap();
        receipt
    };
    let before = connection.total_changes();
    {
        let transaction = connection.transaction().unwrap();
        let plan = preview_writer_ledger_cleanup(&transaction, &binding, 10).unwrap();
        assert_eq!(plan.report().eligible_rows, 10);
        assert!(plan.report().has_more);
        transaction.rollback().unwrap();
    }
    assert_eq!(
        connection.total_changes(),
        before,
        "preview must be read-only"
    );
    let mut deleted = Vec::new();
    for _ in 0..4 {
        let transaction = connection.transaction().unwrap();
        let plan = preview_writer_ledger_cleanup(&transaction, &binding, 10).unwrap();
        deleted.push(plan.apply(&binding).unwrap());
        assert_eq!(
            current_watermark(&transaction, &binding)
                .unwrap()
                .unwrap()
                .commit_sequence,
            receipt.commit_sequence
        );
        assert_eq!(
            lookup_receipt(&transaction, &binding, &advanced.idempotency).unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            transaction
                .query_row("SELECT value FROM domain_marker", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            42
        );
        transaction.commit().unwrap();
    }
    assert_eq!(deleted, vec![10, 10, 3, 0]);
    assert_eq!(
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

use super::*;
use crate::test_support::{binding, metadata, scope};

fn commit(
    transaction: &rusqlite::Transaction<'_>,
    metadata: &tracedecay_store::StoreOperationMetadataV1,
) -> tracedecay_store::StoreCommitReceiptV1 {
    match record_commit(transaction, metadata, &scope(metadata)).unwrap() {
        LedgerDisposition::Committed(receipt) => receipt,
        disposition => panic!("expected commit, got {disposition:?}"),
    }
}

#[test]
fn ledger_records_share_the_callers_transaction_boundary() {
    let mut connection = Connection::open_in_memory().unwrap();
    let metadata = metadata("operation.rollback", "key.rollback", 'a');
    let binding = binding(&metadata);
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    transaction
        .execute_batch("CREATE TABLE domain_marker (value INTEGER NOT NULL)")
        .unwrap();
    transaction
        .execute("INSERT INTO domain_marker(value) VALUES (1)", [])
        .unwrap();
    assert!(matches!(
        record_commit(&transaction, &metadata, &scope(&metadata)).unwrap(),
        LedgerDisposition::Committed(_)
    ));
    transaction.rollback().unwrap();

    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let marker_exists: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'domain_marker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker_exists, 0);
    assert!(current_watermark(&transaction, &binding).unwrap().is_none());
    assert!(
        lookup_receipt(&transaction, &binding, &metadata.idempotency)
            .unwrap()
            .is_none()
    );
}

#[test]
fn commit_uses_one_replay_and_conflict_disposition() {
    let mut connection = Connection::open_in_memory().unwrap();
    let original = metadata("operation.original", "key.replay", 'a');
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let receipt = commit(&transaction, &original);
    transaction.commit().unwrap();

    let replay = metadata("operation.replay", "key.replay", 'a');
    let conflict = metadata("operation.conflict", "key.replay", 'b');
    let transaction = connection.transaction().unwrap();
    assert!(matches!(
        record_commit(&transaction, &replay, &scope(&replay)).unwrap(),
        LedgerDisposition::Replay(found) if found == receipt
    ));
    assert!(matches!(
        record_commit(&transaction, &conflict, &scope(&conflict)).unwrap(),
        LedgerDisposition::Conflict(found) if found == receipt
    ));
}

#[test]
fn malformed_canonical_json_fails_closed() {
    let mut connection = Connection::open_in_memory().unwrap();
    let metadata = metadata("operation.corrupt", "key.corrupt", 'a');
    let binding = binding(&metadata);
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    commit(&transaction, &metadata);
    transaction.commit().unwrap();
    connection
        .execute(
            "UPDATE td_runtime_writer_idempotency_v2 SET transaction_id = ''",
            [],
        )
        .unwrap();

    let transaction = connection.transaction().unwrap();
    assert!(matches!(
        lookup_receipt(&transaction, &binding, &metadata.idempotency),
        Err(LedgerError::Corrupt { .. })
    ));
}

fn at_authority(
    operation_id: &str,
    key: &str,
    digest_byte: char,
    incarnation: u64,
    authority_epoch: u64,
) -> tracedecay_store::StoreOperationMetadataV1 {
    let mut metadata = metadata(operation_id, key, digest_byte);
    metadata.incarnation = serde_json::from_value(serde_json::json!(incarnation)).unwrap();
    metadata.authority_epoch = serde_json::from_value(serde_json::json!(authority_epoch)).unwrap();
    metadata
}

fn idempotency_rows(transaction: &rusqlite::Transaction<'_>) -> Vec<(i64, i64)> {
    transaction
        .prepare(
            "SELECT incarnation, authority_epoch FROM td_runtime_writer_idempotency_v2
             ORDER BY incarnation, authority_epoch",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Advancing the authority epoch retires the records that no admissible
/// submission can match again, and leaves every still-reachable record alone.
#[test]
fn advancing_authority_prunes_only_the_superseded_records() {
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    for (index, key) in ["key.one", "key.two", "key.three"].iter().enumerate() {
        let metadata = at_authority(&format!("operation.epoch7.{index}"), key, 'a', 1, 7);
        commit(&transaction, &metadata);
    }
    // A second incarnation still sitting at epoch 7 must survive incarnation 1
    // advancing: supersession is per incarnation, not per shard.
    let other = at_authority("operation.other", "key.other", 'a', 2, 7);
    commit(&transaction, &other);
    assert_eq!(
        idempotency_rows(&transaction),
        vec![(1, 7), (1, 7), (1, 7), (2, 7)],
        "four records are reachable before any authority advance"
    );

    let advanced = at_authority("operation.epoch8", "key.four", 'a', 1, 8);
    commit(&transaction, &advanced);

    assert_eq!(
        idempotency_rows(&transaction),
        vec![(1, 8), (2, 7)],
        "the three superseded epoch-7 records for incarnation 1 are gone, the \
         new epoch-8 record and the untouched incarnation-2 record remain"
    );
}

/// The safety property that bounds the whole retention rule: a submission whose
/// idempotency record was pruned must still not be able to commit a second
/// time. It fails closed on stale authority instead of being admitted as new.
#[test]
fn a_pruned_record_fails_closed_rather_than_admitting_a_duplicate() {
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let original = at_authority("operation.original", "key.duplicate", 'a', 1, 7);
    let receipt = commit(&transaction, &original);

    let advanced = at_authority("operation.advance", "key.advance", 'a', 1, 8);
    commit(&transaction, &advanced);
    assert_eq!(
        idempotency_rows(&transaction),
        vec![(1, 8)],
        "the epoch-7 record backing the original receipt has been pruned"
    );

    // The exact same submission arrives again under its now-revoked authority.
    let duplicate = record_commit(&transaction, &original, &scope(&original));
    assert!(
        matches!(
            duplicate,
            Err(LedgerError::StaleAuthority {
                persisted,
                requested,
            }) if persisted == advanced.authority_epoch
                && requested == original.authority_epoch
        ),
        "a resubmission under superseded authority must be refused, got {duplicate:?}"
    );
    assert_eq!(
        idempotency_rows(&transaction),
        vec![(1, 8)],
        "the refused duplicate wrote no ledger record"
    );
    assert_eq!(
        current_watermark(&transaction, &binding(&advanced))
            .unwrap()
            .unwrap()
            .commit_sequence
            .0,
        receipt.commit_sequence.0 + 1,
        "the refused duplicate did not advance the commit sequence"
    );
}

/// Without an authority advance the ledger must retain everything: a replay has
/// to keep returning the original receipt.
#[test]
fn records_are_retained_while_their_authority_still_stands() {
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let original = at_authority("operation.stable", "key.stable", 'a', 1, 7);
    let receipt = commit(&transaction, &original);
    for index in 0..3 {
        let next = at_authority(&format!("operation.more.{index}"), "key.more", 'a', 1, 7);
        let _ = record_commit(&transaction, &next, &scope(&next)).unwrap();
    }
    assert_eq!(
        idempotency_rows(&transaction).len(),
        2,
        "the distinct keys are retained at the standing epoch"
    );
    assert!(
        matches!(
            record_commit(&transaction, &original, &scope(&original)).unwrap(),
            LedgerDisposition::Replay(found) if found == receipt
        ),
        "a replay under standing authority still returns the original receipt"
    );
}

/// Authority rotation can discover an arbitrarily large legacy backlog. The
/// foreground commit that discovers it must remove at most one bounded batch,
/// so the epoch advance commits on its own terms instead of dragging the whole
/// backlog into the user mutation's writer transaction.
#[test]
fn one_foreground_commit_prunes_at_most_one_bounded_batch() {
    let batch = usize::try_from(prune::MAX_PRUNED_ROWS_PER_COMMIT).unwrap();
    let seeded = batch + 2;
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    for index in 0..seeded {
        let metadata = at_authority(
            &format!("operation.bounded.{index}"),
            &format!("key.bounded.{index}"),
            'a',
            1,
            7,
        );
        commit(&transaction, &metadata);
    }

    let advanced = at_authority(
        "operation.bounded.advance",
        "key.bounded.advance",
        'b',
        1,
        8,
    );
    commit(&transaction, &advanced);

    let rows = idempotency_rows(&transaction);
    assert_eq!(
        rows.iter().filter(|(_, epoch)| *epoch == 7).count(),
        seeded - batch,
        "one foreground commit removes at most one bounded batch of superseded \
         records, never the whole backlog"
    );
    assert_eq!(
        rows.iter().filter(|(_, epoch)| *epoch == 8).count(),
        1,
        "the authority-advancing commit still records its own receipt"
    );
}

/// A bounded pass leaves a backlog, so cleanup cannot be tied to the transition
/// commit alone. Later commits at the standing epoch must keep draining it, or
/// the retention rule never converges.
#[test]
fn later_commits_drain_the_remaining_superseded_backlog() {
    let batch = usize::try_from(prune::MAX_PRUNED_ROWS_PER_COMMIT).unwrap();
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    for index in 0..batch + 1 {
        let metadata = at_authority(
            &format!("operation.converge.{index}"),
            &format!("key.converge.{index}"),
            'a',
            1,
            7,
        );
        commit(&transaction, &metadata);
    }

    let advanced = at_authority(
        "operation.converge.advance",
        "key.converge.advance",
        'b',
        1,
        8,
    );
    commit(&transaction, &advanced);
    assert_eq!(
        idempotency_rows(&transaction)
            .iter()
            .filter(|(_, epoch)| *epoch == 7)
            .count(),
        1,
        "the bounded transition pass leaves the remainder of the backlog"
    );

    let follow_up = at_authority(
        "operation.converge.follow-up",
        "key.converge.follow-up",
        'c',
        1,
        8,
    );
    commit(&transaction, &follow_up);

    let rows = idempotency_rows(&transaction);
    assert_eq!(
        rows.iter().filter(|(_, epoch)| *epoch == 7).count(),
        0,
        "a later commit at the standing epoch continues draining the backlog"
    );
    assert_eq!(
        rows.iter().filter(|(_, epoch)| *epoch == 8).count(),
        2,
        "both current-epoch commits remain replayable"
    );
}

/// Only the incarnation whose checkpoint this commit decoded and validated may
/// have its records retired. A neighbouring incarnation whose checkpoint row is
/// inconsistent must never have its receipts deleted on the strength of that
/// row's raw scalar: losing a receipt silently re-admits a duplicate write.
#[test]
fn a_corrupt_neighbouring_checkpoint_cannot_retire_its_receipts() {
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let neighbour = at_authority("operation.neighbour", "key.neighbour", 'a', 2, 7);
    let neighbour_binding = binding(&neighbour);
    commit(&transaction, &neighbour);
    let seed = at_authority("operation.seed", "key.seed", 'a', 1, 7);
    commit(&transaction, &seed);

    // Incarnation 2's checkpoint scalar now claims epoch 999 while its
    // watermark and receipt still encode 7. Loading that checkpoint fails
    // closed, so nothing may act on the raw scalar either.
    transaction
        .execute(
            "UPDATE td_runtime_writer_checkpoint_v1 SET authority_epoch = 999
             WHERE incarnation = 2",
            [],
        )
        .unwrap();
    assert!(
        matches!(
            current_watermark(&transaction, &neighbour_binding),
            Err(LedgerError::Corrupt { .. })
        ),
        "the neighbouring checkpoint is corrupt and fails closed when loaded"
    );

    // A completely unrelated, fully validated transition on incarnation 1.
    let advanced = at_authority("operation.unrelated", "key.unrelated", 'a', 1, 8);
    commit(&transaction, &advanced);

    assert!(
        idempotency_rows(&transaction).contains(&(2, 7)),
        "an unvalidated neighbouring checkpoint must not authorise deleting \
         that incarnation's receipts"
    );
}

fn admitted(
    mut metadata: tracedecay_store::StoreOperationMetadataV1,
    at_micros: i64,
) -> tracedecay_store::StoreOperationMetadataV1 {
    metadata.admitted_at = tracedecay_domain::UtcMicros(at_micros);
    metadata
}

/// Each daemon restart is a new incarnation, and no lookup by the new one can
/// match the old one's records. Once the old incarnation has been quiet on the
/// shard for longer than the retirement window, a commit retires its records.
#[test]
fn a_restarted_daemon_retires_the_previous_incarnations_records_after_a_quiet_week() {
    let week = prune::RETIRED_INCARNATION_QUIET_MICROS;
    let start = 1_000_000;
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    for index in 0..3 {
        let previous = at_authority(
            &format!("operation.old.{index}"),
            &format!("key.old.{index}"),
            'a',
            1,
            7,
        );
        commit(&transaction, &admitted(previous, start));
    }
    let restarted = at_authority("operation.new.0", "key.new.0", 'a', 2, 7);
    commit(&transaction, &admitted(restarted, start + week));
    assert_eq!(
        idempotency_rows(&transaction),
        vec![(1, 7), (1, 7), (1, 7), (2, 7)],
        "an incarnation quiet for exactly the window keeps its records"
    );

    let later = at_authority("operation.new.1", "key.new.1", 'a', 2, 7);
    commit(&transaction, &admitted(later, start + week + 1));
    assert_eq!(
        idempotency_rows(&transaction),
        vec![(2, 7), (2, 7)],
        "the previous incarnation's records are retired and the committing \
         incarnation keeps its own"
    );
}

/// A daemon that runs for longer than the retirement window keeps replaying
/// its own receipts: age alone never retires the live incarnation's records.
#[test]
fn the_live_incarnation_keeps_replaying_its_own_receipts_past_the_window() {
    let week = prune::RETIRED_INCARNATION_QUIET_MICROS;
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let original = admitted(
        at_authority("operation.first", "key.first", 'a', 1, 7),
        1_000_000,
    );
    let receipt = commit(&transaction, &original);
    let later = at_authority("operation.later", "key.later", 'a', 1, 7);
    commit(&transaction, &admitted(later, 1_000_000 + 2 * week));

    assert!(
        matches!(
            record_commit(&transaction, &original, &scope(&original)).unwrap(),
            LedgerDisposition::Replay(found) if found == receipt
        ),
        "a two-week-old receipt of the live incarnation still replays"
    );
}

#[test]
fn replay_window_requests_rotation_without_expiring_exact_once_receipts() {
    use crate::runtime_ledger::{WriterReplayWindow, WriterReplayWindowPolicy};
    use std::time::{Duration, Instant};

    let week = prune::RETIRED_INCARNATION_QUIET_MICROS;
    let original = admitted(metadata("operation.window", "key.window", 'a'), 100);
    let binding = binding(&original);
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let receipt = commit(&transaction, &original);
    let policy = WriterReplayWindowPolicy::new(2, Duration::from_secs(7 * 24 * 60 * 60)).unwrap();
    let now = Instant::now();
    let mut monitor = WriterReplayWindow::new(binding.clone(), policy);
    assert!(
        !monitor
            .inspect_at(&transaction, 100, now)
            .unwrap()
            .rotation_required
    );
    let aged = monitor
        .inspect_at(&transaction, 0, now + Duration::from_secs(7 * 24 * 60 * 60))
        .unwrap();
    assert!(
        aged.age_limit_reached,
        "clock rollback must not extend the in-process replay window"
    );
    assert!(aged.rotation_required);
    let fresh_retry = admitted(
        metadata("operation.window.retry", "key.window", 'a'),
        100 + 2 * week,
    );
    assert!(
        matches!(record_commit(&transaction, &fresh_retry, &scope(&fresh_retry)).unwrap(), LedgerDisposition::Replay(found) if found == receipt)
    );
    assert_eq!(
        lookup_receipt(&transaction, &binding, &original.idempotency).unwrap(),
        Some(receipt)
    );
    commit(
        &transaction,
        &admitted(
            metadata("operation.window.second", "key.window.second", 'b'),
            101,
        ),
    );
    let mut reopened = WriterReplayWindow::new(binding.clone(), policy);
    let standing = reopened.inspect_at(&transaction, 101, now).unwrap();
    assert_eq!(standing.receipt_rows_at_least, 2);
    assert!(
        standing.count_limit_reached,
        "recreating a writer must not reset the persisted allowance"
    );
    assert!(standing.rotation_required);
    let mut reopened = WriterReplayWindow::new(binding, policy);
    assert!(
        reopened
            .inspect_at(&transaction, 100 + week, now)
            .unwrap()
            .age_limit_reached,
        "an idle epoch must recover its oldest receipt age after reopen"
    );
    assert_eq!(
        idempotency_rows(&transaction).len(),
        2,
        "detection never deletes live receipts"
    );
}

#[test]
fn replay_window_reopen_requests_rotation_when_persisted_clock_is_ahead() {
    use crate::runtime_ledger::{WriterReplayWindow, WriterReplayWindowPolicy};
    use std::time::{Duration, Instant};

    let original = admitted(metadata("operation.clock", "key.clock", 'a'), 100);
    let binding = binding(&original);
    let mut connection = Connection::open_in_memory().unwrap();
    let receipt = {
        let transaction = connection.transaction().unwrap();
        initialize_schema(&transaction).unwrap();
        let receipt = commit(&transaction, &original);
        commit(
            &transaction,
            &admitted(
                metadata("operation.clock.second", "key.clock.second", 'b'),
                300,
            ),
        );
        transaction.commit().unwrap();
        receipt
    };
    let policy = WriterReplayWindowPolicy::new(3, Duration::from_secs(1)).unwrap();
    let now = Instant::now();
    {
        let transaction = connection.transaction().unwrap();
        let mut monitor = WriterReplayWindow::new(binding.clone(), policy);
        assert!(
            !monitor
                .inspect_at(&transaction, 300, now)
                .unwrap()
                .rotation_required
        );
        let exhausted = monitor
            .inspect_at(&transaction, 1_000_100, now + Duration::from_secs(1))
            .unwrap();
        assert!(exhausted.age_limit_reached);
        assert!(!exhausted.count_limit_reached);
        assert!(exhausted.rotation_required);
    }
    // Reconstruct the same binding with no retained in-process clock state.
    // Check rollback behind all receipts and behind only the newest receipt.
    for rolled_back_wall in [99, 200] {
        let transaction = connection.transaction().unwrap();
        let mut reopened = WriterReplayWindow::new(binding.clone(), policy);
        let standing = reopened
            .inspect_at(&transaction, rolled_back_wall, now + Duration::from_secs(2))
            .unwrap();
        assert!(!standing.count_limit_reached);
        assert!(!standing.age_limit_reached);
        assert!(standing.clock_uncertain);
        assert!(
            standing.rotation_required,
            "clock uncertainty after reopen must not clear an exhausted epoch's rotation signal"
        );
        let retry = admitted(
            metadata("operation.clock.retry", "key.clock", 'a'),
            1_000_101,
        );
        assert!(
            matches!(record_commit(&transaction, &retry, &scope(&retry)).unwrap(), LedgerDisposition::Replay(found) if found == receipt)
        );
        assert_eq!(
            lookup_receipt(&transaction, &binding, &original.idempotency).unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(idempotency_rows(&transaction).len(), 2);
    }
}

#[test]
fn retired_cleanup_requires_owner_fence_and_revalidates_checkpoint() {
    use crate::{
        RuntimeWriteAuthorityError,
        runtime_ledger::{
            WriterLedgerRetirementAuthority, preview_retired_writer_ledger_cleanup,
            preview_writer_ledger_cleanup,
        },
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    struct OwnerFence(AtomicBool);
    impl WriterLedgerRetirementAuthority for OwnerFence {
        fn verify_retired(
            &self,
            _live: &tracedecay_store::StoreRuntimeBindingV1,
            _retired: &tracedecay_store::StoreRuntimeBindingV1,
        ) -> Result<(), RuntimeWriteAuthorityError> {
            if self.0.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(RuntimeWriteAuthorityError::denied("retirement revoked"))
            }
        }
    }
    let mut connection = Connection::open_in_memory().unwrap();
    let transaction = connection.transaction().unwrap();
    initialize_schema(&transaction).unwrap();
    let old = at_authority("operation.retired", "key.retired", 'a', 1, 7);
    let live = at_authority("operation.live", "key.live", 'b', 2, 7);
    commit(&transaction, &old);
    commit(&transaction, &live);
    let retired = binding(&old);
    let live = binding(&live);
    let fence = OwnerFence(AtomicBool::new(true));
    assert_eq!(
        preview_writer_ledger_cleanup(&transaction, &live, 10)
            .unwrap()
            .report()
            .eligible_rows,
        0
    );
    let before = transaction.total_changes();
    let plan =
        preview_retired_writer_ledger_cleanup(&transaction, &live, &retired, &fence, 10).unwrap();
    assert_eq!(plan.report().eligible_rows, 1);
    assert!(plan.report().eligible_payload_bytes > 0);
    assert_eq!(transaction.total_changes(), before);
    fence.0.store(false, Ordering::Release);
    assert!(
        plan.apply(&live).is_err(),
        "an expired owner fence must fail before deleting"
    );
    assert_eq!(idempotency_rows(&transaction), vec![(1, 7), (2, 7)]);
    fence.0.store(true, Ordering::Release);
    transaction
        .execute(
            "UPDATE td_runtime_writer_checkpoint_v1 SET authority_epoch=999 WHERE incarnation=1",
            [],
        )
        .unwrap();
    assert!(
        preview_retired_writer_ledger_cleanup(&transaction, &live, &retired, &fence, 10).is_err(),
        "raw neighbouring checkpoint scalars are not authority"
    );
    transaction
        .execute(
            "UPDATE td_runtime_writer_checkpoint_v1 SET authority_epoch=7 WHERE incarnation=1",
            [],
        )
        .unwrap();
    assert!(
        preview_retired_writer_ledger_cleanup(&transaction, &live, &live, &fence, 10).is_err(),
        "the live incarnation cannot retire itself"
    );
    let plan =
        preview_retired_writer_ledger_cleanup(&transaction, &live, &retired, &fence, 10).unwrap();
    assert_eq!(plan.apply(&live).unwrap(), 1);
    assert_eq!(idempotency_rows(&transaction), vec![(2, 7)]);
    assert!(
        current_watermark(&transaction, &retired).unwrap().is_some(),
        "cleanup must preserve the old checkpoint fence"
    );
    assert_eq!(
        preview_retired_writer_ledger_cleanup(&transaction, &live, &retired, &fence, 10)
            .unwrap()
            .apply(&live)
            .unwrap(),
        0
    );
}

#[test]
fn interrupted_writer_owned_drain_rolls_back_and_resumes_after_reopen() {
    use crate::{
        RuntimeWriteAuthority, RuntimeWriteAuthorityError, RuntimeWriteAuthorityStage,
        runtime_ledger::{
            WriterLedgerMaintenance, WriterReplayWindowPolicy, drain_writer_ledger_page,
            preview_writer_ledger_cleanup,
        },
    };
    struct Authority(bool);
    impl RuntimeWriteAuthority for Authority {
        fn verify(
            &self,
            stage: RuntimeWriteAuthorityStage,
        ) -> Result<(), RuntimeWriteAuthorityError> {
            if !self.0 && stage == RuntimeWriteAuthorityStage::BeforeCommit {
                Err(RuntimeWriteAuthorityError::denied(
                    "fixture cancellation before commit",
                ))
            } else {
                Ok(())
            }
        }
    }
    let directory = ledger_test_directory();
    let path = directory.path().join("sessions.db");
    let mut connection = Connection::open(&path).unwrap();
    let live = at_authority("operation.resume.advance", "key.resume.advance", 'b', 1, 8);
    let binding = binding(&live);
    let receipt = {
        let transaction = connection.transaction().unwrap();
        initialize_schema(&transaction).unwrap();
        transaction
            .execute_batch(
                "CREATE TABLE domain_marker(value INTEGER); INSERT INTO domain_marker VALUES(42)",
            )
            .unwrap();
        for index in 0..261 {
            commit(
                &transaction,
                &at_authority(
                    &format!("operation.resume.{index}"),
                    &format!("key.resume.{index}"),
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
    let error =
        drain_writer_ledger_page(&mut connection, &binding, &Authority(false), 2).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixture cancellation before commit")
    );
    drop(connection);
    let mut connection = Connection::open(&path).unwrap();
    {
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            idempotency_rows(&transaction).len(),
            6,
            "cancelled page is rolled back"
        );
        let plan = preview_writer_ledger_cleanup(&transaction, &binding, 2).unwrap();
        let mut wrong = binding.clone();
        wrong.authority_epoch = serde_json::from_value(serde_json::json!(9)).unwrap();
        assert!(
            plan.apply(&wrong).is_err(),
            "apply requires the preview's exact binding"
        );
        let plan = preview_writer_ledger_cleanup(&transaction, &binding, 2).unwrap();
        commit(
            &transaction,
            &at_authority(
                "operation.invalidate.plan",
                "key.invalidate.plan",
                'c',
                1,
                8,
            ),
        );
        assert!(
            plan.apply(&binding).is_err(),
            "checkpoint progress invalidates an earlier plan"
        );
        transaction.rollback().unwrap();
    }
    let mut deleted = Vec::new();
    let now = std::time::Instant::now();
    let mut maintenance =
        WriterLedgerMaintenance::new(binding.clone(), WriterReplayWindowPolicy::default(), 2, now)
            .unwrap();
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    assert!(
        maintenance
            .tick(&mut connection, &Authority(true), &cancelled, 1, now)
            .unwrap()
            .is_none()
    );
    cancelled.store(false, std::sync::atomic::Ordering::Release);
    for tick in 0..4 {
        let due = now + std::time::Duration::from_secs(tick * 60);
        let report = maintenance
            .tick(&mut connection, &Authority(true), &cancelled, 1, due)
            .unwrap()
            .unwrap();
        deleted.push(report.drain.deleted_rows);
        assert!(!report.replay_window.rotation_required);
        assert!(
            maintenance
                .tick(&mut connection, &Authority(true), &cancelled, 1, due)
                .unwrap()
                .is_none(),
            "only one page is allowed per tick"
        );
        drop(connection);
        connection = Connection::open(&path).unwrap();
    }
    assert_eq!(deleted, vec![2, 2, 1, 0]);
    assert!(drain_writer_ledger_page(&mut connection, &binding, &Authority(true), 0).is_err());
    assert!(drain_writer_ledger_page(&mut connection, &binding, &Authority(true), 4097).is_err());
    let transaction = connection.transaction().unwrap();
    assert_eq!(
        current_watermark(&transaction, &binding)
            .unwrap()
            .unwrap()
            .commit_sequence,
        receipt.commit_sequence
    );
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
