use super::*;
use std::num::NonZeroUsize;
use tracedecay_contracts::RequestId;
use tracedecay_contracts::session_sync::SessionTranscriptImportV1;
use tracedecay_global_db::tests::harness::{HostAdmissionScope, HostAdmissionTestRuntimeV1};
use tracedecay_runtime_core::config::ProfileRoot;

#[asupersync::test]
async fn terminal_journal_persists_frontiers_once_and_replays_exact_receipt() {
    let root = tempfile::tempdir().unwrap();
    let project_root = root.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let project_id = ProjectId::new("project.journal-retention").unwrap();
    let runtime =
        HostAdmissionTestRuntimeV1::project(root.path(), &project_root, project_id.clone())
            .await
            .unwrap();
    let project_sessions = runtime
        .registered_database_lease(HostAdmissionScope::Project)
        .unwrap();
    let registry = runtime
        .registered_database_lease(HostAdmissionScope::Profile)
        .unwrap();
    let profile_id = project_sessions.binding().shard_id.profile_id.clone();
    let scope = SessionSyncScopeV1::new(project_id.clone(), profile_id.clone());
    let service = DaemonSessionSyncService::default();
    service.register_project(DaemonSessionSyncConfig {
            brain_id: project_sessions.binding().shard_id.brain_id.clone(),
            profile_id, project_id,
            profile_root: root.path().to_path_buf(),
            project_root,
            transcript_source_profile: ProfileRoot::new(root.path().to_path_buf()),
            project_sessions,
            user_sessions: registry.clone(),
            registry: registry.clone(),
            background_cpu: Arc::new(ProcessBackgroundCpuV1::new(NonZeroUsize::MIN)),
            startup_import: false,
            project_refresh: crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
            user_refresh: crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
        }).await.unwrap();
    let context = service.context_for(&scope).unwrap();
    let request = SessionSyncRequestV1::new(
        RequestId::new("journal-retention").unwrap(),
        IdempotencyKey::new("journal-retention").unwrap(),
        scope.clone(),
        Deadline::new(UtcMicros(now_micros().0 + 60_000_000)).unwrap(),
        CancellationSignal::active("journal-retention").unwrap(),
        SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
    );
    let key = journal_key(&scope, request.idempotency_key());
    let queued = SessionSyncJournalV1::queued(&request, now_micros());
    registry
        .insert_session_sync_journal(&key, &serde_json::to_string(&queued).unwrap())
        .await
        .unwrap();
    let frontiers = vec![SessionSyncSourceFrontierV1 {
        store_scope: "profile".to_owned(),
        source_json: r#"{"provider":"codex","session_id":"fixture"}"#.to_owned(),
        scope_json: r#"{"kind":"profile"}"#.to_owned(),
        committed_cursor_json: r#"{"offset":123456}"#.to_owned(),
    }];
    for termination in [
        OperationTermination::Partial,
        OperationTermination::Cancelled,
        OperationTermination::TimedOut,
        OperationTermination::Failed,
        OperationTermination::Completed,
    ] {
        let mut journal = queued.clone();
        journal.status = SessionSyncJournalStatusV1::Running;
        journal.source_frontiers = frontiers.clone();
        let current = registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .unwrap();
        registry
            .compare_and_swap_session_sync_journal(
                &key,
                &current,
                &serde_json::to_string(&journal).unwrap(),
            )
            .await
            .unwrap();
        let terminal = service
            .persist_terminal(
                &context,
                &key,
                SessionSyncTerminalMaterial {
                    termination,
                    stats: SessionSyncStatsV1 {
                        sessions_imported: 7,
                        ..Default::default()
                    },
                    coverage: transcript_import_requested_coverage(),
                    source_frontiers: frontiers.clone(),
                    failure_codes: vec!["fixture_failure".to_owned()],
                },
            )
            .await
            .unwrap();
        let encoded = registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .unwrap();
        let persisted: SessionSyncJournalV1 = serde_json::from_str(&encoded).unwrap();
        assert!(
            persisted.source_frontiers.is_empty(),
            "terminal frontiers must only be stored in the completion receipt"
        );
        assert_eq!(
            persisted.completion.as_ref().unwrap().source_frontiers,
            frontiers
        );
        assert_eq!(
            persisted.completion.as_ref().unwrap().termination,
            termination
        );
        assert_eq!(
            SessionSyncServicePort::status(
                &service,
                SessionSyncControlV1::new(scope.clone(), request.idempotency_key().clone())
            )
            .await,
            terminal.outcome()
        );
        assert_eq!(
            decode_matching_journal(&encoded, &request)
                .unwrap()
                .outcome(),
            terminal.outcome()
        );
    }
}
