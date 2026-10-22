use std::sync::Arc;

use tracedecay_contracts::session_sync::{
    SessionSyncCommandV1, SessionSyncCompletionReceiptV1, SessionSyncJournalStatusV1,
    SessionSyncJournalV1, SessionSyncRequestV1, SessionSyncScopeV1, SessionSyncSourceFrontierV1,
    SessionTranscriptImportV1,
};
use tracedecay_contracts::{
    CancellationSignal, Deadline, IdempotencyKey, OperationTermination, RequestId,
};
use tracedecay_domain::{ProjectId, UtcMicros};
use tracedecay_maintenance::tick::{MaintenanceContinuation, MaintenanceTickOutcome};

use super::MaintenanceCoordinator;

#[test]
fn journal_maintenance_tick_expires_resumes_and_cancels() {
    tracedecay_runtime_core::native_runtime::block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let profile = &temp.path().join("profile");
        tracedecay_runtime_core::storage::PrivateStoreIo::create_dir_all(profile).unwrap();
        let (db, _owner) =
            tracedecay_global_db::tests::harness::open_registered_test_database_fixture(
                &profile.join("global.db"),
                tracedecay_runtime_core::db::TestDatabaseRuntimeScope::Profile,
            )
            .await
            .unwrap();
        let now = tracedecay_contracts::now_micros();
        let scope = SessionSyncScopeV1::new(
            ProjectId::new("project.b9").unwrap(),
            db.binding().shard_id.profile_id.clone(),
        );
        let mut keys = Vec::new();
        for n in 0..16 {
            let id = if n == 14 {
                "manual.b9".to_owned()
            } else if n == 15 {
                format!("session-sync.startup.{n:032x}.project.active")
            } else {
                format!("session-sync.startup.{n:032x}.project.b9")
            };
            let completed = UtcMicros(
                now.0
                    - if n == 12 {
                        1_000_000
                    } else {
                        3 * 86_400_000_000
                    },
            );
            // A nonterminal receipt conservatively pins its entire project scope.
            let journal_scope = if n == 15 {
                SessionSyncScopeV1::new(
                    ProjectId::new("project.active").unwrap(),
                    scope.profile_id().clone(),
                )
            } else {
                scope.clone()
            };
            let request = SessionSyncRequestV1::new(
                RequestId::new(&id).unwrap(),
                IdempotencyKey::new(&id).unwrap(),
                journal_scope,
                Deadline::new(UtcMicros(now.0 + 60_000_000)).unwrap(),
                CancellationSignal::active(&id).unwrap(),
                SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
            );
            let mut journal = SessionSyncJournalV1::queued(&request, UtcMicros(completed.0 - 1));
            journal.status = SessionSyncJournalStatusV1::Complete;
            if n == 14 {
                journal.coalesced_primary = Some(
                    IdempotencyKey::new(
                        "session-sync.startup.0000000000000000000000000000000d.project.b9",
                    )
                    .unwrap(),
                );
            }
            journal.source_frontiers = vec![SessionSyncSourceFrontierV1 {
                store_scope: "profile".to_owned(),
                source_json: "{}".to_owned(),
                scope_json: "{}".to_owned(),
                committed_cursor_json: "{\"offset\":42}".to_owned(),
            }];
            journal.completion = Some(SessionSyncCompletionReceiptV1 {
                admission: journal.admission.clone(),
                coalesced_primary: journal.coalesced_primary.clone(),
                completed_at: completed,
                termination: OperationTermination::Completed,
                stats: Default::default(),
                coverage: Vec::new(),
                source_frontiers: journal.source_frontiers.clone(),
                failure_codes: Vec::new(),
            });
            if n == 15 {
                journal.status = SessionSyncJournalStatusV1::Queued;
                journal.completion = None;
            }
            let p = journal.scope.profile_id().as_str();
            let r = journal.scope.project_id().as_str();
            let key = format!("session-sync.v1.p{}:{p}.r{}:{r}.{id}", p.len(), r.len());
            db.insert_session_sync_journal(&key, &serde_json::to_string(&journal).unwrap())
                .await
                .unwrap();
            keys.push(key);
        }
        let administration = super::super::StoreAdministration::default().with_profile_identity(
            tracedecay_daemon_identity::profile_identity::load_or_create(profile).unwrap(),
        );
        let schedulers =
            tracedecay_code_index_runtime::code_index_scheduler::CodeIndexSchedulerRegistryV1::new(
                1,
            );
        let retention = tracedecay_configuration::RetentionConfig::default();
        let coordinator = MaintenanceCoordinator {
            background_cpu: Some(Arc::new(
                tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1::new(
                    std::num::NonZeroUsize::MIN,
                ),
            )),
            ..MaintenanceCoordinator::default()
        };
        // Cancellation with eligible work still present must not delete or normalize it.
        let cancelled = MaintenanceCoordinator {
            background_cpu: coordinator.background_cpu.clone(),
            ..MaintenanceCoordinator::default()
        };
        let mut original = Vec::new();
        for key in &keys {
            original.push(db.read_session_sync_journal(key).await.unwrap());
        }
        cancelled.cancel();
        cancelled
            .run_tick(
                profile,
                &db,
                &administration,
                &schedulers,
                &retention,
                super::super::BranchStoreGcCadenceV1 { branch_gc_days: 30 },
                None,
            )
            .await;
        for (key, before) in keys.iter().zip(&original) {
            assert_eq!(&db.read_session_sync_journal(key).await.unwrap(), before);
        }
        let mut previous_remaining = 12;
        let mut continuation = None;
        let mut ticks = 0;
        loop {
            let outcome = coordinator
                .run_tick(
                    profile,
                    &db,
                    &administration,
                    &schedulers,
                    &retention,
                    super::super::BranchStoreGcCadenceV1 { branch_gc_days: 30 },
                    continuation,
                )
                .await;
            let mut remaining = 0;
            for key in &keys[..12] {
                remaining +=
                    usize::from(db.read_session_sync_journal(key).await.unwrap().is_some());
            }
            assert!(
                previous_remaining - remaining <= 1,
                "at most one expiry per tick"
            );
            previous_remaining = remaining;
            ticks += 1;
            if ticks == 1 {
                let cpu = coordinator
                    .background_cpu
                    .as_ref()
                    .unwrap()
                    .try_acquire()
                    .unwrap();
                let blocked = coordinator
                    .run_tick(
                        profile,
                        &db,
                        &administration,
                        &schedulers,
                        &retention,
                        super::super::BranchStoreGcCadenceV1 { branch_gc_days: 30 },
                        Some(MaintenanceContinuation::SessionJournalRetention),
                    )
                    .await;
                assert_eq!(
                    blocked,
                    MaintenanceTickOutcome::Retry,
                    "journal continuation must respect exhausted background CPU admission"
                );
                drop(cpu);
                let blocked = administration
                    .try_with_writer(|| async {
                        coordinator
                            .run_tick(
                                profile,
                                &db,
                                &administration,
                                &schedulers,
                                &retention,
                                super::super::BranchStoreGcCadenceV1 { branch_gc_days: 30 },
                                Some(MaintenanceContinuation::SessionJournalRetention),
                            )
                            .await
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    blocked,
                    MaintenanceTickOutcome::Retry,
                    "busy writer must retry without losing the journal cursor"
                );
            }
            continuation = outcome.continuation();
            if outcome.is_complete() {
                break;
            }
            assert!(ticks < 100, "bounded sweep must converge: {outcome:?}");
        }
        assert!(
            ticks > 1,
            "journal backlog must use bounded continuation ticks"
        );
        for key in &keys[..12] {
            assert!(
                db.read_session_sync_journal(key).await.unwrap().is_none(),
                "eligible journal retained: {key}"
            );
        }
        for key in &keys[12..] {
            assert!(
                db.read_session_sync_journal(key).await.unwrap().is_some(),
                "recent, pinned, manual and unfinished receipts must survive"
            );
        }
        assert_eq!(
            db.read_session_sync_journal(&keys[15]).await.unwrap(),
            original[15],
            "unfinished work must not be normalized"
        );
        // Normalization keeps the completion's replay evidence, only the duplicate goes.
        let recent: SessionSyncJournalV1 = serde_json::from_str(
            &db.read_session_sync_journal(&keys[12])
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(recent.source_frontiers.is_empty());
        assert_eq!(recent.completion.unwrap().source_frontiers.len(), 1);
        coordinator.cancel();
        let before = db.read_session_sync_journal(&keys[14]).await.unwrap();
        coordinator
            .run_tick(
                profile,
                &db,
                &administration,
                &schedulers,
                &retention,
                super::super::BranchStoreGcCadenceV1 { branch_gc_days: 30 },
                None,
            )
            .await;
        assert_eq!(
            db.read_session_sync_journal(&keys[14]).await.unwrap(),
            before
        );
    })
    .unwrap();
}
