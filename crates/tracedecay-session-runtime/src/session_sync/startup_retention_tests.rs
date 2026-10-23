use super::*;
use tracedecay_contracts::RequestId;
use tracedecay_contracts::session_sync::SessionTranscriptImportV1;
use tracedecay_global_db::{RegisteredGlobalDb, tests::harness::HostAdmissionTestRuntimeV1};
use tracedecay_runtime_core::db::engine::params;

const NOW: UtcMicros = UtcMicros(1_790_000_000_000_000);
const DAY: i64 = 86_400_000_000;

fn fixture(
    registry: &RegisteredGlobalDb,
    id: &str,
    completed_at: UtcMicros,
) -> SessionSyncJournalV1 {
    let scope = SessionSyncScopeV1::new(
        ProjectId::new("project.retention").unwrap(),
        registry.binding().shard_id.profile_id.clone(),
    );
    let request = SessionSyncRequestV1::new(
        RequestId::new(id).unwrap(),
        IdempotencyKey::new(id).unwrap(),
        scope,
        Deadline::new(UtcMicros(completed_at.0 + 60_000_000)).unwrap(),
        CancellationSignal::active(id).unwrap(),
        SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
    );
    let mut journal = SessionSyncJournalV1::queued(&request, UtcMicros(completed_at.0 - 10));
    journal.status = SessionSyncJournalStatusV1::Complete;
    journal.updated_at = completed_at;
    journal.coverage = vec![SessionSyncSourceCoverageV1 {
        store_scope: "profile".to_owned(),
        coverage: SessionSyncCoverageV1::Complete,
    }];
    journal.completion = Some(SessionSyncCompletionReceiptV1 {
        admission: journal.admission.clone(),
        coalesced_primary: None,
        completed_at,
        termination: OperationTermination::Completed,
        stats: Default::default(),
        coverage: journal.coverage.clone(),
        source_frontiers: vec![SessionSyncSourceFrontierV1 {
            store_scope: "profile".to_owned(),
            source_json: r#"{"provider":"codex","session_id":"retention-fixture"}"#.to_owned(),
            scope_json: r#"{"kind":"profile"}"#.to_owned(),
            committed_cursor_json: r#"{"offset":123456}"#.to_owned(),
        }],
        failure_codes: Vec::new(),
    });
    journal
}

fn startup_id(run: u32) -> String {
    format!("session-sync.startup.{run:032x}.project.retention")
}

async fn seed(registry: &RegisteredGlobalDb, journal: &SessionSyncJournalV1) -> String {
    super::journal_retention::dependencies::ensure_installed(registry)
        .await
        .unwrap();
    let key = journal_key(&journal.scope, &journal.admission.idempotency_key);
    assert!(
        registry
            .insert_session_sync_journal(&key, &serde_json::to_string(journal).unwrap())
            .await
            .unwrap()
    );
    // Retention must use receipt microseconds, not this table's seconds clock.
    registry
        .writer_connection()
        .unwrap()
        .execute(
            "UPDATE session_backfill_meta SET updated_at = ?2 WHERE key = ?1",
            params![key.as_str(), NOW.0 / 1_000_000],
        )
        .await
        .unwrap();
    key
}

async fn sweep(
    service: &DaemonSessionSyncService,
    registry: &RegisteredGlobalDb,
    now: UtcMicros,
) -> usize {
    let mut cursor = None;
    let mut deleted = 0;
    for _ in 0..100 {
        let plan = service
            .plan_startup_journal_retention(registry, None, now, cursor.as_ref())
            .await
            .unwrap();
        assert!(plan.scanned <= 8);
        assert!(plan.candidates.len() <= 1);
        let receipt = service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap();
        deleted += receipt.deleted;
        cursor = plan.next;
        if cursor.is_none() {
            return deleted;
        }
    }
    panic!("bounded retention sweep failed to finish");
}

#[asupersync::test]
async fn startup_retention_restart_imports_while_manual_alias_keeps_previous_receipt() {
    use std::num::NonZeroUsize;
    use tracedecay_global_db::tests::harness::{
        RegisteredGlobalDbTestRuntime, open_registered_test_database_fixture,
    };
    use tracedecay_runtime_core::db::{TestDatabaseRuntimeScope, TestRuntimeProfileIdentityV1};
    use tracedecay_runtime_core::{config::ProfileRoot, native_runtime};

    let root = tempfile::tempdir().unwrap();
    let project_root = root.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let project_id = ProjectId::new("project.retention").unwrap();
    let (registry, _registry_owner) = open_registered_test_database_fixture(
        &root.path().join("global.db"),
        TestDatabaseRuntimeScope::Profile,
    )
    .await
    .unwrap();
    let identity = &registry.binding().shard_id;
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        root.path(),
        &project_root,
        project_id.clone(),
        TestRuntimeProfileIdentityV1::new(identity.brain_id.clone(), identity.profile_id.clone()),
    )
    .await
    .unwrap();
    let project_sessions = runtime.project_database_arc().unwrap();
    let user_sessions = runtime.profile_database_arc();
    let stable_id = "session-sync.startup.v2.project.retention";
    let mut previous = fixture(&registry, stable_id, UtcMicros(NOW.0 - 1));
    previous.admission.operation_id = RequestId::new(startup_id(1)).unwrap();
    previous.completion.as_mut().unwrap().admission = previous.admission.clone();
    let key = seed(&registry, &previous).await;
    let scope = previous.scope.clone();
    let mut alias = fixture(&registry, "manual-durable-startup-alias", NOW);
    alias.coalesced_primary = Some(previous.admission.idempotency_key.clone());
    alias.completion.as_mut().unwrap().coalesced_primary = alias.coalesced_primary.clone();
    let alias_key = seed(&registry, &alias).await;
    let previous_bytes = registry
        .read_session_sync_journal(&key)
        .await
        .unwrap()
        .unwrap();
    let alias_bytes = registry
        .read_session_sync_journal(&alias_key)
        .await
        .unwrap()
        .unwrap();
    let service = DaemonSessionSyncService::default();
    let mount = || DaemonSessionSyncConfig {
        brain_id: project_sessions.binding().shard_id.brain_id.clone(),
        profile_id: scope.profile_id().clone(),
        project_id: project_id.clone(),
        profile_root: root.path().to_path_buf(),
        project_root: project_root.clone(),
        transcript_source_profile: ProfileRoot::new(root.path().to_path_buf()),
        project_sessions: project_sessions.clone(),
        user_sessions: user_sessions.clone(),
        registry: registry.clone(),
        background_cpu: Arc::new(ProcessBackgroundCpuV1::new(NonZeroUsize::MIN)),
        startup_import: true,
        project_refresh:
            crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
        user_refresh:
            crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
    };
    service.register_project(mount()).await.unwrap();
    let fresh_id = format!(
        "session-sync.startup.{}.{}",
        tracedecay_runtime_core::runtime_identity::process_run_id(),
        project_id.as_str()
    );
    let control = SessionSyncControlV1::new(scope.clone(), IdempotencyKey::new(fresh_id).unwrap());
    let receipt = native_runtime::timeout(Duration::from_secs(10), async {
        loop {
            if let SessionSyncOutcomeV1::Complete { receipt, .. } =
                SessionSyncServicePort::status(&service, control.clone()).await
            {
                break receipt;
            }
            native_runtime::sleep_until(Instant::now() + Duration::from_millis(10))
                .await
                .unwrap();
        }
    })
    .await
    .expect("a pinned receipt must not suppress a fresh startup import");
    assert_ne!(
        receipt.admission.operation_id,
        previous.admission.operation_id
    );
    assert_eq!(
        registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .unwrap(),
        previous_bytes
    );
    assert_eq!(
        registry
            .read_session_sync_journal(&alias_key)
            .await
            .unwrap()
            .unwrap(),
        alias_bytes
    );
    service.register_project(mount()).await.unwrap();
    assert!(
        matches!(SessionSyncServicePort::status(&service, control).await,
        SessionSyncOutcomeV1::Complete { receipt: same, .. } if same == receipt),
        "same-run remount must replay the fresh generation"
    );
    assert_eq!(
        registry
            .list_session_sync_journals(&journal_prefix(&scope))
            .await
            .unwrap()
            .len(),
        3
    );
    SessionSyncServicePort::shutdown(&service).await;
}

#[asupersync::test]
async fn startup_retention_mount_replaces_previous_run_in_one_project_row() {
    use std::num::NonZeroUsize;
    use tracedecay_global_db::tests::harness::{
        RegisteredGlobalDbTestRuntime, open_registered_test_database_fixture,
    };
    use tracedecay_runtime_core::db::{TestDatabaseRuntimeScope, TestRuntimeProfileIdentityV1};
    use tracedecay_runtime_core::{config::ProfileRoot, native_runtime};

    let root = tempfile::tempdir().unwrap();
    let project_root = root.path().join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let project_id = ProjectId::new("project.retention").unwrap();
    let (registry, _registry_owner) = open_registered_test_database_fixture(
        &root.path().join("global.db"),
        TestDatabaseRuntimeScope::Profile,
    )
    .await
    .unwrap();
    let identity = &registry.binding().shard_id;
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        root.path(),
        &project_root,
        project_id.clone(),
        TestRuntimeProfileIdentityV1::new(identity.brain_id.clone(), identity.profile_id.clone()),
    )
    .await
    .unwrap();
    let project_sessions = runtime.project_database_arc().unwrap();
    let user_sessions = runtime.profile_database_arc();
    let stable_id = "session-sync.startup.v2.project.retention";
    let mut previous = fixture(&registry, stable_id, UtcMicros(NOW.0 - 1));
    previous.admission.operation_id = RequestId::new(startup_id(1)).unwrap();
    previous.completion.as_mut().unwrap().admission = previous.admission.clone();
    let key = seed(&registry, &previous).await;
    let scope = previous.scope.clone();
    for run in 2..=4 {
        let service = DaemonSessionSyncService::default();
        let mount = || DaemonSessionSyncConfig {
            brain_id: project_sessions.binding().shard_id.brain_id.clone(),
            profile_id: scope.profile_id().clone(),
            project_id: project_id.clone(),
            profile_root: root.path().to_path_buf(),
            project_root: project_root.clone(),
            transcript_source_profile: ProfileRoot::new(root.path().to_path_buf()),
            project_sessions: project_sessions.clone(),
            user_sessions: user_sessions.clone(),
            registry: registry.clone(),
            background_cpu: Arc::new(ProcessBackgroundCpuV1::new(NonZeroUsize::MIN)),
            startup_import: true,
            project_refresh:
                crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
            user_refresh:
                crate::session_temporal_refresh_scheduler::SessionTemporalRefreshWake::unavailable(),
        };
        service.register_project(mount()).await.unwrap();
        assert_eq!(
            registry
                .list_session_sync_journals(&journal_prefix(&scope))
                .await
                .unwrap()
                .len(),
            1,
            "startup must keep one row per project, not per process"
        );
        let control =
            SessionSyncControlV1::new(scope.clone(), IdempotencyKey::new(stable_id).unwrap());
        let receipt = native_runtime::timeout(Duration::from_secs(10), async {
            loop {
                if let SessionSyncOutcomeV1::Complete { receipt, .. } =
                    SessionSyncServicePort::status(&service, control.clone()).await
                    && receipt.admission.operation_id != previous.admission.operation_id
                {
                    break receipt;
                }
                native_runtime::sleep_until(Instant::now() + Duration::from_millis(10))
                    .await
                    .unwrap();
            }
        })
        .await
        .expect("a fresh daemon must renew the previous startup receipt");
        assert_ne!(receipt.admission, previous.admission);
        service.register_project(mount()).await.unwrap();
        assert!(
            matches!(SessionSyncServicePort::status(&service, control).await,
            SessionSyncOutcomeV1::Complete { receipt: ref same, .. } if same == &receipt),
            "remounting in the same daemon must replay, not renew"
        );
        SessionSyncServicePort::shutdown(&service).await;
        let rows = registry
            .list_session_sync_journals(&journal_prefix(&scope))
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "startup must keep one row per project, not per process"
        );
        assert_eq!(rows[0].0, key);
        previous = serde_json::from_str(&rows[0].1).unwrap();
        // Simulate another daemon identity without changing process-global state.
        let before = rows[0].1.clone();
        previous.admission.operation_id = RequestId::new(startup_id(run)).unwrap();
        previous.completion.as_mut().unwrap().admission = previous.admission.clone();
        assert!(
            registry
                .compare_and_swap_session_sync_journal(
                    &key,
                    &before,
                    &serde_json::to_string(&previous).unwrap()
                )
                .await
                .unwrap()
        );
    }
    let service = DaemonSessionSyncService::default();
    let completed_at = previous.completion.as_ref().unwrap().completed_at;
    assert_eq!(
        sweep(&service, &registry, UtcMicros(completed_at.0 + DAY)).await,
        0,
        "the stable startup slot gets the full 24-hour grace too"
    );
    assert_eq!(
        sweep(&service, &registry, UtcMicros(completed_at.0 + DAY + 1)).await,
        1
    );
    assert!(
        registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .is_none()
    );
}

#[asupersync::test]
async fn startup_retention_uses_24_hour_horizon_and_bounds_restarts() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    assert_eq!(registry.db_path().file_name().unwrap(), "global.db");
    let old = fixture(registry, &startup_id(1), UtcMicros(NOW.0 - DAY - 1));
    let old_key = seed(registry, &old).await;
    let boundary = seed(
        registry,
        &fixture(registry, &startup_id(2), UtcMicros(NOW.0 - DAY)),
    )
    .await;
    let recent = seed(registry, &fixture(registry, &startup_id(3), NOW)).await;
    let manual = fixture(registry, "manual-import", UtcMicros(NOW.0 - 10 * DAY));
    let manual_key = seed(registry, &manual).await;
    let service = DaemonSessionSyncService::default();
    let plan = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert_eq!(
        plan.candidates.len(),
        1,
        "old internal startup receipts must expire"
    );
    assert_eq!(plan.candidates[0].key, old_key);
    assert!(
        registry
            .read_session_sync_journal(&old_key)
            .await
            .unwrap()
            .is_some(),
        "preview must not delete"
    );
    assert!(
        service
            .apply_startup_journal_retention(registry, &plan, "not-approved")
            .await
            .is_err()
    );
    assert_eq!(sweep(&service, registry, NOW).await, 1);
    assert!(
        registry
            .read_session_sync_journal(&old_key)
            .await
            .unwrap()
            .is_none()
    );
    for key in [&boundary, &recent, &manual_key] {
        assert!(
            registry
                .read_session_sync_journal(key)
                .await
                .unwrap()
                .is_some()
        );
    }
    // Each newly constructed service represents a fresh daemon process over the
    // same durable registry, with a different generated startup run token.
    for day in 1..=6 {
        let now = UtcMicros(NOW.0 + day * 2 * DAY);
        let journal = fixture(registry, &startup_id(10 + day as u32), now);
        let key = seed(registry, &journal).await;
        let restarted = DaemonSessionSyncService::default();
        sweep(&restarted, registry, now).await;
        assert!(
            registry
                .read_session_sync_journal(&key)
                .await
                .unwrap()
                .is_some()
        );
        let rows = registry
            .list_session_sync_journals("session-sync.v1.")
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            2,
            "only the current startup and manual receipt should remain"
        );
        let retained: SessionSyncJournalV1 = serde_json::from_str(
            &registry
                .read_session_sync_journal(&manual_key)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(retained, manual);
    }
    assert_eq!(
        sweep(&service, registry, UtcMicros(NOW.0 + 12 * DAY)).await,
        0
    );
}

#[asupersync::test]
async fn startup_retention_rechecks_alias_evidence_and_active_imports_under_admission_gate() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let primary = fixture(registry, &startup_id(1), UtcMicros(NOW.0 - 2 * DAY));
    let primary_key = seed(registry, &primary).await;
    let plan = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    let gate = service.project_gate(&primary.scope);
    let admission = gate.lock().await;
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .busy,
        1
    );
    // Admission wins the gate after preview and persists a reference. Apply must
    // recheck durable dependencies, not trust the earlier snapshot.
    let mut alias = fixture(registry, "manual-alias", NOW);
    alias.coalesced_primary = Some(primary.admission.idempotency_key.clone());
    alias.status = SessionSyncJournalStatusV1::Queued;
    alias.completion = None;
    let alias_key = seed(registry, &alias).await;
    drop(admission);
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .stale,
        1
    );
    let pinned = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert!(pinned.candidates.is_empty());
    assert_eq!(pinned.pinned, 1);
    assert!(
        registry
            .read_session_sync_journal(&primary_key)
            .await
            .unwrap()
            .is_some()
    );

    // A completed manual alias is still referenced evidence and pins its primary.
    let encoded = registry
        .read_session_sync_journal(&alias_key)
        .await
        .unwrap()
        .unwrap();
    let mut terminal_alias = fixture(registry, "manual-alias", NOW);
    terminal_alias.coalesced_primary = alias.coalesced_primary.clone();
    terminal_alias
        .completion
        .as_mut()
        .unwrap()
        .coalesced_primary = alias.coalesced_primary;
    assert!(
        registry
            .compare_and_swap_session_sync_journal(
                &alias_key,
                &encoded,
                &serde_json::to_string(&terminal_alias).unwrap()
            )
            .await
            .unwrap()
    );
    assert_eq!(sweep(&service, registry, NOW).await, 0);
    let encoded = registry
        .read_session_sync_journal(&alias_key)
        .await
        .unwrap()
        .unwrap();
    assert!(
        registry
            .compare_and_delete_session_sync_journal(&alias_key, &encoded)
            .await
            .unwrap()
    );

    service.active_imports.lock().unwrap().insert(
        import_scope_key(&primary.scope),
        ActiveSessionImport {
            admission: primary.admission.clone(),
            journal_key: primary_key.clone(),
        },
    );
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .busy,
        1
    );
    service.active_imports.lock().unwrap().clear();
    service.active.lock().unwrap().insert(
        primary_key.clone(),
        CancellationSignal::active("active-retention-fixture").unwrap(),
    );
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .busy,
        1
    );
    service.active.lock().unwrap().clear();
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .deleted,
        1
    );
    assert!(
        registry
            .read_session_sync_journal(&primary_key)
            .await
            .unwrap()
            .is_none()
    );
}

#[asupersync::test]
async fn startup_retention_preserves_manual_lookalikes_nonterminal_and_malformed_rows() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let old = UtcMicros(NOW.0 - 2 * DAY);
    let base = fixture(registry, &startup_id(1), old);
    registry
        .insert_session_sync_journal("profile-project-prune.v1.fixture", "{unrelated}")
        .await
        .unwrap();
    let mut invalid = vec![
        fixture(registry, "manual-import", old),
        fixture(
            registry,
            "session-sync.startup.manual.project.retention",
            old,
        ),
        fixture(
            registry,
            "session-sync.startup.0123456789ABCDEF0123456789ABCDEF.project.retention",
            old,
        ),
        fixture(
            registry,
            "session-sync.startup.mcp-01790000000.project.retention",
            old,
        ),
        fixture(
            registry,
            "session-sync.startup.00000000000000000000000000000001.other-project",
            old,
        ),
    ];
    let mut wrong_operation = base.clone();
    wrong_operation.admission.operation_id = RequestId::new("manual-operation").unwrap();
    wrong_operation.completion.as_mut().unwrap().admission = wrong_operation.admission.clone();
    invalid.push(wrong_operation);
    let mut git = base.clone();
    git.source = SessionSyncCommandV1::SynchronizeGit(SessionGitSyncV1::new(0, 1, false).unwrap());
    invalid.push(git);
    let mut wrong_admission = base.clone();
    wrong_admission
        .completion
        .as_mut()
        .unwrap()
        .admission
        .idempotency_key = IdempotencyKey::new("other").unwrap();
    invalid.push(wrong_admission);
    let mut wrong_primary = base.clone();
    wrong_primary.completion.as_mut().unwrap().coalesced_primary =
        Some(IdempotencyKey::new("other").unwrap());
    invalid.push(wrong_primary);
    let mut no_receipt = base.clone();
    no_receipt.completion = None;
    invalid.push(no_receipt);
    for status in [
        SessionSyncJournalStatusV1::Queued,
        SessionSyncJournalStatusV1::Running,
    ] {
        let mut journal = base.clone();
        journal.status = status;
        journal.completion = None;
        invalid.push(journal);
    }
    for journal in invalid {
        let key = seed(registry, &journal).await;
        let before = registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sweep(&service, registry, NOW).await,
            0,
            "must preserve {}",
            journal.admission.idempotency_key.as_str()
        );
        assert_eq!(
            registry
                .read_session_sync_journal(&key)
                .await
                .unwrap()
                .unwrap(),
            before
        );
        assert!(
            registry
                .compare_and_delete_session_sync_journal(&key, &before)
                .await
                .unwrap()
        );
    }
    let old_key = seed(registry, &base).await;
    let malformed_key = format!("{}malformed", journal_prefix(&base.scope));
    for encoded in ["{broken-json", "{}"] {
        assert!(
            registry
                .insert_session_sync_journal(&malformed_key, encoded)
                .await
                .unwrap()
        );
        let plan = service
            .plan_startup_journal_retention(registry, None, NOW, None)
            .await
            .unwrap();
        assert!(
            plan.candidates.is_empty(),
            "unprovable scope evidence must pin old primary"
        );
        assert_eq!(plan.pinned, 1);
        assert!(
            registry
                .compare_and_delete_session_sync_journal(&malformed_key, encoded)
                .await
                .unwrap()
        );
    }
    // A nonterminal operation pins the whole scope, even without an alias edge.
    let mut running = fixture(registry, "running-import", NOW);
    running.status = SessionSyncJournalStatusV1::Running;
    running.completion = None;
    let running_key = seed(registry, &running).await;
    assert_eq!(sweep(&service, registry, NOW).await, 0);
    let encoded = registry
        .read_session_sync_journal(&running_key)
        .await
        .unwrap()
        .unwrap();
    assert!(
        registry
            .compare_and_delete_session_sync_journal(&running_key, &encoded)
            .await
            .unwrap()
    );
    assert_eq!(sweep(&service, registry, NOW).await, 1);
    assert!(
        registry
            .read_session_sync_journal(&old_key)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        registry
            .read_session_sync_journal("profile-project-prune.v1.fixture")
            .await
            .unwrap()
            .as_deref(),
        Some("{unrelated}")
    );
}

#[asupersync::test]
async fn startup_retention_expires_all_terminal_variants_and_fallback_run_tokens() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    for termination in [
        OperationTermination::Completed,
        OperationTermination::Partial,
        OperationTermination::Cancelled,
        OperationTermination::TimedOut,
        OperationTermination::Failed,
        OperationTermination::Unavailable,
    ] {
        let mut journal = fixture(
            registry,
            "session-sync.startup.mcp-1790000000.project.retention",
            UtcMicros(NOW.0 - 2 * DAY),
        );
        let completion = journal.completion.as_mut().unwrap();
        completion.termination = termination;
        completion.coverage.clear();
        let key = seed(registry, &journal).await;
        assert_eq!(
            sweep(&service, registry, NOW).await,
            1,
            "terminal status, not successful coverage, controls expiry"
        );
        assert!(
            registry
                .read_session_sync_journal(&key)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[asupersync::test]
async fn startup_retention_freezes_cutoff_and_high_water_and_rejects_changed_receipts() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let old = UtcMicros(NOW.0 - 2 * DAY);
    for run in 0..12 {
        seed(registry, &fixture(registry, &startup_id(run), old)).await;
    }
    let recent = seed(registry, &fixture(registry, &startup_id(12), NOW)).await;
    let first = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert_eq!(first.candidates.len(), 1);
    let mut cursor = first.next.clone();
    let frozen = cursor.as_ref().unwrap().clone();
    let appended = seed(registry, &fixture(registry, &startup_id(1000), old)).await;
    assert!(appended > frozen.through_key);
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &first, &first.digest)
            .await
            .unwrap()
            .deleted,
        1
    );
    let mut deleted = 1;
    while let Some(current) = cursor {
        let plan = service
            .plan_startup_journal_retention(
                registry,
                None,
                UtcMicros(NOW.0 + 10 * DAY),
                Some(&current),
            )
            .await
            .unwrap();
        assert_eq!(plan.cutoff, UtcMicros(NOW.0 - DAY));
        assert!(plan.scanned <= 8);
        assert!(plan.candidates.len() <= 1);
        if let Some(next) = &plan.next {
            assert_eq!(next.through_key, frozen.through_key);
        }
        deleted += service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .deleted;
        cursor = plan.next;
    }
    assert_eq!(deleted, 12);
    assert!(
        registry
            .read_session_sync_journal(&recent)
            .await
            .unwrap()
            .is_some(),
        "cutoff must not drift during a sweep"
    );
    assert!(
        registry
            .read_session_sync_journal(&appended)
            .await
            .unwrap()
            .is_some(),
        "later keys wait for a new sweep"
    );
    let scope = fixture(registry, &startup_id(1), old).scope;
    let mut future_cursor = frozen.clone();
    future_cursor.cutoff = NOW;
    assert!(
        service
            .plan_startup_journal_retention(registry, None, NOW, Some(&future_cursor))
            .await
            .is_err(),
        "a supplied cursor cannot shorten the 24-hour grace"
    );
    assert!(
        service
            .plan_startup_journal_retention(registry, Some(&scope), NOW, Some(&frozen))
            .await
            .is_err(),
        "a global cursor is not a scoped cursor"
    );
    let plan = service
        .plan_startup_journal_retention(registry, Some(&scope), NOW, None)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].key, appended);
    let before = registry
        .read_session_sync_journal(&appended)
        .await
        .unwrap()
        .unwrap();
    let mut changed: SessionSyncJournalV1 = serde_json::from_str(&before).unwrap();
    changed.completion.as_mut().unwrap().completed_at = NOW;
    assert!(
        registry
            .compare_and_swap_session_sync_journal(
                &appended,
                &before,
                &serde_json::to_string(&changed).unwrap()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .stale,
        1
    );
    assert!(
        registry
            .read_session_sync_journal(&appended)
            .await
            .unwrap()
            .is_some()
    );
    let mut tampered = plan.clone();
    tampered.cutoff = UtcMicros(NOW.0 + DAY);
    assert!(
        service
            .apply_startup_journal_retention(registry, &tampered, &plan.digest)
            .await
            .is_err()
    );
    // Applying a plan against a different existing registry is also refused.
    let other_root = tempfile::tempdir().unwrap();
    let other_runtime = HostAdmissionTestRuntimeV1::profile(other_root.path())
        .await
        .unwrap();
    assert!(
        service
            .apply_startup_journal_retention(other_runtime.profile_registry(), &plan, &plan.digest)
            .await
            .is_err()
    );
}

#[asupersync::test]
async fn startup_retention_is_scope_exact_for_unmounted_projects() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let old = UtcMicros(NOW.0 - 2 * DAY);
    let selected = fixture(registry, &startup_id(1), old);
    let selected_key = seed(registry, &selected).await;
    let mut other = fixture(
        registry,
        "session-sync.startup.11111111111111111111111111111111.project.other",
        old,
    );
    other.scope = SessionSyncScopeV1::new(
        ProjectId::new("project.other").unwrap(),
        selected.scope.profile_id().clone(),
    );
    let other_key = seed(registry, &other).await;
    let plan = service
        .plan_startup_journal_retention(registry, Some(&selected.scope), NOW, None)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].key, selected_key);
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .deleted,
        1
    );
    assert!(
        registry
            .read_session_sync_journal(&other_key)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        sweep(&service, registry, NOW).await,
        1,
        "unmounted scopes must also be eligible in a full sweep"
    );
    assert!(
        registry
            .read_session_sync_journal(&other_key)
            .await
            .unwrap()
            .is_none()
    );
    let foreign_scope = SessionSyncScopeV1::new(
        selected.scope.project_id().clone(),
        UserProfileId::new("foreign-profile").unwrap(),
    );
    assert!(
        service
            .plan_startup_journal_retention(registry, Some(&foreign_scope), NOW, None)
            .await
            .is_err()
    );
}

#[asupersync::test]
async fn startup_retention_bounds_large_payloads_without_materializing_frontiers() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let limit: usize = 64 * 1024 * 1024;
    for target in [
        22 * 1024 * 1024,
        37 * 1024 * 1024,
        limit - 4096,
        limit,
        limit + 1,
    ] {
        let mut journal = fixture(registry, &startup_id(1), UtcMicros(NOW.0 - 2 * DAY));
        journal.completion.as_mut().unwrap().source_frontiers[0].committed_cursor_json =
            r#"{"offset":123456,"padding":""}"#.to_owned();
        let baseline = serde_json::to_string(&journal).unwrap().len();
        let key = seed(registry, &journal).await;
        // Build the large legacy value inside SQLite too; oversized input
        // parameters would themselves exceed the exact-SQL command budget.
        let write = registry
            .writer_connection()
            .unwrap()
            .execute(
                r#"UPDATE session_backfill_meta SET value = json_set(value,
                '$.completion.source_frontiers[0].committed_cursor_json',
                '{"offset":123456,"padding":"' || printf('%.*c', ?2, 'x') || '"}')
                WHERE key = ?1"#,
                params![key.as_str(), (target - baseline) as i64],
            )
            .await;
        if target >= limit {
            // SQLite's 64 MiB ceiling includes key/row overhead, not just the
            // value. Such a row cannot be produced by the admitted writer.
            assert!(
                write
                    .unwrap_err()
                    .to_string()
                    .contains("string or blob too big")
            );
            assert_eq!(
                registry
                    .read_session_sync_journal(&key)
                    .await
                    .unwrap()
                    .unwrap(),
                serde_json::to_string(&journal).unwrap(),
                "failed oversized writes are atomic"
            );
            assert!(
                registry
                    .compare_and_delete_session_sync_journal(
                        &key,
                        &serde_json::to_string(&journal).unwrap()
                    )
                    .await
                    .unwrap()
            );
            continue;
        }
        write.unwrap();
        let snapshot = registry.read_snapshot().await.unwrap();
        let mut rows = snapshot
            .query(
                "SELECT length(CAST(value AS BLOB)) FROM session_backfill_meta WHERE key = ?1",
                params![key.as_str()],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<u64>(0).unwrap(),
            target as u64
        );
        drop(rows);
        drop(snapshot);
        let plan = service
            .plan_startup_journal_retention(registry, None, NOW, None)
            .await
            .unwrap();
        assert_eq!(plan.scanned, 1);
        assert!(
            serde_json::to_vec(&plan).unwrap().len() < 4096,
            "preview must not materialize the frontier inventory"
        );
        assert_eq!(plan.candidates.len(), 1);
        let receipt = service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap();
        assert_eq!(receipt.deleted, 1);
        assert_eq!(receipt.logical_bytes_released, target as u64);
    }
}

#[asupersync::test]
async fn startup_retention_legacy_dependency_backfill_is_read_only_until_approved_and_resumable() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let service = DaemonSessionSyncService::default();
    let mut originals = Vec::new();
    for run in 1..=17 {
        let journal = fixture(registry, &startup_id(run), UtcMicros(NOW.0 - 2 * DAY));
        let key = journal_key(&journal.scope, &journal.admission.idempotency_key);
        let bytes = serde_json::to_string(&journal).unwrap();
        registry
            .insert_session_sync_journal(&key, &bytes)
            .await
            .unwrap();
        originals.push((key, bytes));
    }
    let bootstrap = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert!(bootstrap.dependency_backfill.is_some());
    assert!(bootstrap.candidates.is_empty());
    let snapshot = registry.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'session_sync_dependency_state_v1'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0,
        "preview must not even install the dependency schema"
    );
    drop(rows);
    drop(snapshot);
    assert!(
        service
            .apply_startup_journal_retention(registry, &bootstrap, "unapproved")
            .await
            .is_err()
    );
    let installed = service
        .apply_startup_journal_retention(registry, &bootstrap, &bootstrap.digest)
        .await
        .unwrap();
    assert!(installed.dependency_backfill_applied);
    assert_eq!(
        installed.dependency_rows_indexed, 0,
        "installation must not parse legacy values"
    );
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &bootstrap, &bootstrap.digest)
            .await
            .unwrap()
            .stale,
        1
    );

    let first = service
        .plan_startup_journal_retention(registry, None, NOW, None)
        .await
        .unwrap();
    assert!(first.dependency_backfill.as_ref().unwrap().key.is_some());
    let first_receipt = service
        .apply_startup_journal_retention(registry, &first, &first.digest)
        .await
        .unwrap();
    assert_eq!(first_receipt.dependency_rows_indexed, 1);
    assert_eq!(
        service
            .apply_startup_journal_retention(registry, &first, &first.digest)
            .await
            .unwrap()
            .stale,
        1
    );
    // Add an alias behind the already-certified migration frontier. Its trigger
    // must index it even though no later migration page will visit this key.
    let mut alias = fixture(registry, "aaa-durable-alias", NOW);
    alias.coalesced_primary = Some(IdempotencyKey::new(startup_id(1)).unwrap());
    alias.completion.as_mut().unwrap().coalesced_primary = alias.coalesced_primary.clone();
    let alias_key = seed(registry, &alias).await;
    let mut indexed = 1;
    let mut finished = false;
    for _ in 0..20 {
        // A new service object stands for a later maintenance invocation; the
        // frontier is durable and is never an unbounded startup reconstruction.
        let resumed = DaemonSessionSyncService::default();
        let plan = resumed
            .plan_startup_journal_retention(registry, None, NOW, None)
            .await
            .unwrap();
        if plan.dependency_backfill.is_none() {
            finished = true;
            break;
        }
        assert!(plan.candidates.is_empty());
        let applied = resumed
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap();
        assert!(applied.dependency_backfill_applied);
        assert!(applied.dependency_rows_indexed <= 1);
        assert_eq!(applied.deleted, 0);
        indexed += applied.dependency_rows_indexed;
    }
    assert!(finished);
    assert_eq!(indexed, 17);
    for (key, bytes) in &originals {
        assert_eq!(
            registry
                .read_session_sync_journal(key)
                .await
                .unwrap()
                .as_ref(),
            Some(bytes),
            "index backfill must preserve legacy receipt bytes"
        );
    }
    assert_eq!(
        sweep(&service, registry, NOW).await,
        16,
        "the alias inserted behind the migration cursor still pins its primary"
    );
    assert_eq!(
        registry
            .read_session_sync_journal(&originals[0].0)
            .await
            .unwrap()
            .as_ref(),
        Some(&originals[0].1)
    );
    registry
        .compare_and_delete_session_sync_journal(
            &alias_key,
            &serde_json::to_string(&alias).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sweep(&service, registry, NOW).await, 1);
}

#[asupersync::test]
async fn startup_retention_apply_and_renewal_writer_work_does_not_scale_with_history() {
    use tracedecay_global_db::tests::harness::writer_telemetry;
    let mut costs = Vec::new();
    for count in [16, 1024] {
        let root = tempfile::tempdir().unwrap();
        let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
            .await
            .unwrap();
        let registry = runtime.profile_registry();
        let stable_id = "session-sync.startup.v2.project.retention";
        let mut previous = fixture(registry, stable_id, UtcMicros(NOW.0 - 2 * DAY));
        previous.admission.operation_id = RequestId::new(startup_id(1)).unwrap();
        previous.completion.as_mut().unwrap().admission = previous.admission.clone();
        seed(registry, &previous).await;
        let transaction = registry.begin_write_transaction().await.unwrap();
        for n in 0..count {
            let mut history = fixture(registry, &format!("zz-history-{n:08}"), NOW);
            history.completion.as_mut().unwrap().source_frontiers[0].committed_cursor_json =
                format!(r#"{{"cursor":"{}"}}"#, "x".repeat(16384));
            transaction
                .execute(
                    "INSERT INTO session_backfill_meta VALUES (?1, ?2, 1)",
                    params![
                        journal_key(&history.scope, &history.admission.idempotency_key),
                        serde_json::to_string(&history).unwrap()
                    ],
                )
                .await
                .unwrap();
        }
        transaction.commit().await.unwrap();
        let service = DaemonSessionSyncService::default();
        let plan = service
            .plan_startup_journal_retention(registry, Some(&previous.scope), NOW, None)
            .await
            .unwrap();
        assert_eq!(plan.scanned, 1);
        assert_eq!(plan.candidates.len(), 1);
        let before = writer_telemetry(registry).sqlite_vm.vm_steps;
        let receipt = service
            .apply_startup_journal_retention(registry, &plan, &plan.digest)
            .await
            .unwrap();
        let apply_steps = writer_telemetry(registry).sqlite_vm.vm_steps - before;
        assert_eq!(receipt.deleted, 1);
        seed(registry, &previous).await;
        let request = SessionSyncRequestV1::new(
            RequestId::new(startup_id(2)).unwrap(),
            IdempotencyKey::new(stable_id).unwrap(),
            previous.scope.clone(),
            Deadline::new(UtcMicros(i64::MAX)).unwrap(),
            CancellationSignal::active("renewal-cost").unwrap(),
            SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
        );
        let before = writer_telemetry(registry).sqlite_vm.vm_steps;
        assert!(
            service
                .renew_startup_journal(registry, &request)
                .await
                .unwrap()
        );
        let renewal_steps = writer_telemetry(registry).sqlite_vm.vm_steps - before;
        costs.push((apply_steps, renewal_steps));
    }
    eprintln!("apply/renewal VM steps at 16/1024 large journals: {costs:?}");
    for &(apply, renew) in &costs {
        assert!(
            apply > 0 && renew > 0,
            "the probe must measure real writer work"
        );
        assert!(
            apply < 12000 && renew < 12000,
            "one page/renewal must have bounded writer work: {costs:?}"
        );
    }
    assert!(
        costs[1].0 <= costs[0].0 + 64 && costs[1].1 <= costs[0].1 + 64,
        "accumulated history must not add writer query work: {costs:?}"
    );
}

#[asupersync::test]
async fn startup_retention_legacy_renewal_installs_no_history_sized_startup_work() {
    use tracedecay_global_db::tests::harness::writer_telemetry;
    let mut costs = Vec::new();
    for count in [16, 1024] {
        let root = tempfile::tempdir().unwrap();
        let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
            .await
            .unwrap();
        let registry = runtime.profile_registry();
        let stable_id = "session-sync.startup.v2.project.retention";
        let mut previous = fixture(registry, stable_id, UtcMicros(NOW.0 - 2 * DAY));
        previous.admission.operation_id = RequestId::new(startup_id(1)).unwrap();
        previous.completion.as_mut().unwrap().admission = previous.admission.clone();
        let key = journal_key(&previous.scope, &previous.admission.idempotency_key);
        let previous_bytes = serde_json::to_string(&previous).unwrap();
        // Raw insertion models a pre-upgrade registry: no dependency table,
        // no triggers and no pre-certified legacy values.
        registry
            .insert_session_sync_journal(&key, &previous_bytes)
            .await
            .unwrap();
        let transaction = registry.begin_write_transaction().await.unwrap();
        for n in 0..count {
            let mut history = fixture(registry, &format!("zz-history-{n:08}"), NOW);
            history.completion.as_mut().unwrap().source_frontiers[0].committed_cursor_json =
                format!(r#"{{"cursor":"{}"}}"#, "x".repeat(16384));
            transaction
                .execute(
                    "INSERT INTO session_backfill_meta VALUES (?1, ?2, 1)",
                    params![
                        journal_key(&history.scope, &history.admission.idempotency_key),
                        serde_json::to_string(&history).unwrap()
                    ],
                )
                .await
                .unwrap();
        }
        transaction.commit().await.unwrap();
        let service = DaemonSessionSyncService::default();
        let request = SessionSyncRequestV1::new(
            RequestId::new(startup_id(2)).unwrap(),
            IdempotencyKey::new(stable_id).unwrap(),
            previous.scope.clone(),
            Deadline::new(UtcMicros(i64::MAX)).unwrap(),
            CancellationSignal::active("legacy-renewal-cost").unwrap(),
            SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
        );
        let before = writer_telemetry(registry).sqlite_vm.vm_steps;
        assert!(
            !service
                .renew_startup_journal(registry, &request)
                .await
                .unwrap(),
            "uncertified history must select a separate startup generation"
        );
        costs.push(writer_telemetry(registry).sqlite_vm.vm_steps - before);
        assert_eq!(
            registry
                .read_session_sync_journal(&key)
                .await
                .unwrap()
                .unwrap(),
            previous_bytes
        );
        let snapshot = registry.read_snapshot().await.unwrap();
        let mut rows = snapshot
            .query("SELECT COUNT(*) FROM session_sync_dependencies_v1", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0,
            "startup must not certify any legacy journal"
        );
    }
    eprintln!("legacy startup bootstrap VM steps at 16/1024 journals: {costs:?}");
    assert!(costs[0] > 0 && costs[1] > 0);
    assert!(
        costs[1] <= costs[0] + 64,
        "legacy startup must not rebuild metadata over history: {costs:?}"
    );
}
