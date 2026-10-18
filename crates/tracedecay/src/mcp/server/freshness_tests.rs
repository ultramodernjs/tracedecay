use super::{DatabaseOwnerReconciler, McpServer, McpServerConstructionContext};
use crate::test_support::git::git;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tracedecay_application::observability::{
    BoundedObservabilityProducerV1, DeliverySettlementAuthorityV1, ObservabilityProducerIdentityV1,
};
use tracedecay_contracts::code_index_freshness::{
    CODE_INDEX_PUBLICATION_AUTHORITY_CORRUPT, CodeIndexConvergenceParkedV1,
};
use tracedecay_domain::{NativeHostIdentityV1, UtcMicros};
use tracedecay_global_db::RegisteredGlobalDbLeaseV1;
use tracedecay_hooks::{
    HOOK_EVENT_SCHEMA_VERSION, HookBoundaryV1, HookConfigurationFileReaderV1, HookEventEnvelopeV2,
    HookEventV2, HookOrderingV1, HookSpoolConfigV1, HookSpoolV1, hook_configuration_path,
    hook_v2_spool_root,
};
use tracedecay_mcp::tool_error_response;
use tracedecay_project::project::TraceDecay;
use tracedecay_sessions::admission::HostAdmissionScope;
use tracedecay_store_runtime::DaemonSessionRuntimeRegistryV1;

struct FreshnessRuntime {
    registry: DaemonSessionRuntimeRegistryV1,
    _scope: tracedecay_runtime_core::db::DaemonDatabaseScope,
}

impl FreshnessRuntime {
    async fn open(profile_root: &std::path::Path) -> Self {
        std::fs::create_dir_all(profile_root).expect("freshness profile root");
        tracedecay_runtime_core::storage::set_private_dir_permissions(profile_root)
            .expect("restrict freshness profile root");
        let identity = tracedecay_daemon_identity::profile_identity::load_or_create(profile_root)
            .expect("freshness profile identity");
        let scope = tracedecay_runtime_core::db::enter_daemon_database_scope(
            identity.profile_root(),
            1,
            "host-admission-test-runtime",
        )
        .expect("freshness daemon database scope");
        let registry = DaemonSessionRuntimeRegistryV1::open(identity)
            .await
            .expect("freshness session runtime registry");
        Self {
            registry,
            _scope: scope,
        }
    }

    async fn profile_database(&self) -> RegisteredGlobalDbLeaseV1 {
        self.registry
            .profile_database()
            .await
            .expect("registered freshness profile database")
    }
}

struct FreshnessFixtureAuthority {
    profile: TempDir,
    _runtime: Arc<tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1>,
}

async fn init_indexed_repo() -> (TraceDecay, TempDir, FreshnessFixtureAuthority) {
    let profile = TempDir::new().unwrap();
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t.com"]);
    git(root, &["config", "user.name", "T"]);
    std::fs::write(root.join(".gitignore"), ".tracedecay/\n").unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), "pub fn a() {}\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "initial"]);
    let (cg, runtime) = TraceDecay::init_test_fixture_with_registered_runtime(
        profile.path(),
        root,
        "project.mcp-freshness",
    )
    .await
    .expect("init");
    (
        cg,
        dir,
        FreshnessFixtureAuthority {
            profile,
            _runtime: runtime,
        },
    )
}

fn prepare_feature_branch(data_root: &std::path::Path, root: &std::path::Path) {
    let mut meta = tracedecay_runtime_core::branch_meta::BranchMeta::new("main");
    meta.add_branch("feature", "main");
    tracedecay_runtime_core::branch_meta::save_branch_meta(data_root, &meta).unwrap();
    // `add_branch` only admits the branch; until its exact graph source is
    // published the branch is still indexing and a reopen legitimately keeps
    // serving the nearest published ancestor (`main`). This test pins the
    // serve-old/await-new swap, so publish the feature provenance up front.
    let published = tracedecay_runtime_core::branch_meta::publish_graph_source(
        data_root,
        "feature",
        None,
        tracedecay_runtime_core::branch_meta::BranchGraphSourceDraftV1 {
            project_id: "project.mcp-freshness".to_owned(),
            repository_id: "repository.mcp-freshness".to_owned(),
            worktree_id: "worktree.mcp-freshness".to_owned(),
            worktree_root: root.to_string_lossy().into_owned(),
            reference: "refs/heads/feature".to_owned(),
            source_oid: "a".repeat(40),
        },
    )
    .unwrap();
    assert!(
        matches!(
            published,
            tracedecay_runtime_core::branch_meta::BranchGraphSourcePublishOutcomeV1::Published(_)
        ),
        "the feature branch must be query-eligible before the drift"
    );

    git(root, &["checkout", "-q", "-b", "feature"]);
    git(root, &["checkout", "-q", "main"]);
}

async fn open_branch_tracked_graph(
    graph: TraceDecay,
    root: &std::path::Path,
    fixture: &FreshnessFixtureAuthority,
) -> TraceDecay {
    graph.checkpoint().await.unwrap();
    let data_root = graph.store_layout().data_root.clone();
    drop(graph);
    // Init resolves provenance before bootstrapping metadata. Mount through
    // registered open after publication, as a long-lived project server does.
    prepare_feature_branch(&data_root, root);
    let graph = fixture
        ._runtime
        .open_project_graph_for_test(
            root,
            tracedecay_project::project::TraceDecayOpenOptions::for_profile(
                &tracedecay_runtime_core::config::ProfileRoot::new(fixture.profile.path()),
            ),
        )
        .await
        .unwrap();
    assert_eq!(graph.active_branch(), Some("main"));
    assert_eq!(graph.serving_branch(), Some("main"));
    graph
}

/// Serve-old/await-new: the request that notices the drift answers on the
/// snapshot it already had, and the reopen (plus its owner reconcile) lands
/// behind it.
#[tokio::test]
async fn branch_drift_serves_the_old_snapshot_until_the_swap_lands() {
    let (cg, dir, fixture_authority) = init_indexed_repo().await;
    let root = dir.path();
    let main = open_branch_tracked_graph(cg, root, &fixture_authority).await;
    let layout = main.store_layout().clone();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let block_reconcile = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reconcile_entered = Arc::new(tokio::sync::Notify::new());
    let callback: DatabaseOwnerReconciler = {
        let observed = Arc::clone(&observed);
        let block_reconcile = Arc::clone(&block_reconcile);
        let reconcile_entered = Arc::clone(&reconcile_entered);
        Arc::new(move |fresh| {
            let observed = Arc::clone(&observed);
            let block_reconcile = Arc::clone(&block_reconcile);
            let reconcile_entered = Arc::clone(&reconcile_entered);
            Box::pin(async move {
                observed.lock().unwrap().push(fresh.db_path());
                if block_reconcile.load(Ordering::Acquire) {
                    reconcile_entered.notify_one();
                    std::future::pending::<()>().await;
                }
            })
        })
    };
    let sessions = fixture_authority
        ._runtime
        .registered_database_lease(HostAdmissionScope::Project)
        .unwrap()
        .clone();
    let identity = ObservabilityProducerIdentityV1 {
        authorized_scope_ref: "project.mcp-freshness".to_owned(),
        process_boot_id: "boot:mcp-branch-reopen".to_owned(),
        producer_revision: "branch-reopen-producer.v1".to_owned(),
        configuration_revision: "branch-reopen-config.v1".to_owned(),
        policy_revision: "branch-reopen-policy.v1".to_owned(),
    };
    let producer = Arc::new(
        BoundedObservabilityProducerV1::start(sessions.clone(), identity.clone(), 8).unwrap(),
    );
    let delivery = Arc::new(
        DeliverySettlementAuthorityV1::new(sessions.clone(), Arc::clone(&producer), identity)
            .unwrap(),
    );
    let cpu = Arc::new(
        tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1::new(
            std::num::NonZeroUsize::new(1).unwrap(),
        ),
    );
    let mut context =
        McpServerConstructionContext::direct(main, None).with_database_owner_reconciler(callback);
    context.project_session_db = Some(sessions.clone());
    context.background_cpu = Some(Arc::clone(&cpu));
    let server = McpServer::new_with_context(context).await;
    let previous = server.cg().await;
    git(root, &["checkout", "-q", "feature"]);
    let before = server.branch_reopens_completed();
    let served = server.reopen_if_branch_drifted().await;

    // The caller is answered on the pre-drift snapshot: it never waits for the
    // full DB open the reopen performs.
    assert_eq!(
        served.serving_branch(),
        Some("main"),
        "the drifting request must serve the last complete snapshot"
    );
    assert!(
        observed.lock().unwrap().is_empty(),
        "the owner reconcile must not run inside the request"
    );

    assert!(
        server
            .wait_for_branch_reopen(before, std::time::Duration::from_secs(30))
            .await,
        "the detached reopen must land"
    );
    let fresh = server.reopen_if_branch_drifted().await;
    assert_eq!(fresh.serving_branch(), Some("feature"));
    assert_eq!(observed.lock().unwrap().as_slice(), &[fresh.db_path()]);
    assert!(
        !crate::daemon::hook_v2_replay_consumer::hook_v2_replay_consumer_registered(
            &layout.data_root
        ),
        "dependent replay ownership has not mounted yet"
    );
    assert!(
        server
            .register_hook_replay_owner(Arc::clone(&delivery), sessions, cpu)
            .await
    );
    // Owner setup began with `previous`, but mounts only after the swap.
    // The receipt must belong to the current graph so subsequent transfer
    // and final retirement both compare against the right owner.
    let core = McpServer::new_with_context(McpServerConstructionContext::direct(
        Arc::clone(&fresh),
        None,
    ))
    .await;
    core.shutdown().await;
    assert!(
        crate::daemon::hook_v2_replay_consumer::hook_v2_replay_consumer_registered(
            &layout.data_root
        ),
        "retiring Core must preserve Full's consumer over the same graph"
    );
    crate::daemon::hook_v2_replay_consumer::shutdown_hook_v2_replay_consumer_for_graph(&previous)
        .await;
    assert!(
        crate::daemon::hook_v2_replay_consumer::hook_v2_replay_consumer_registered(
            &layout.data_root
        )
    );
    let host = NativeHostIdentityV1::CursorDesktop;
    let worktree = tracedecay_agent_hosts::hooks::hook_worktree_id_for_layout(
        &crate::hook_runtime(tracedecay_runtime_core::config::ProfileRoot::new(
            fixture_authority.profile.path(),
        )),
        fresh.hook_store_layout(),
    )
    .unwrap();
    let publication = HookConfigurationFileReaderV1::new(hook_configuration_path(
        &layout.data_root,
        worktree,
        host,
    ));
    let snapshot = publication.load(host).unwrap().unwrap();
    let now = tracedecay_runtime_core::tracedecay::saturating_utc_now();
    let envelope = HookEventEnvelopeV2 {
        schema_version: HOOK_EVENT_SCHEMA_VERSION,
        event_id: [81; 16],
        producer: host,
        protected_session_id: [82; 32],
        project_id: snapshot.binding.project_id,
        repository_id: snapshot.binding.repository_id,
        worktree_id: snapshot.binding.worktree_id,
        worktree_epoch: snapshot.binding.worktree_epoch,
        binding_token: snapshot.binding.binding_token,
        ordering: HookOrderingV1::Unknown,
        observed_at: now,
        event: HookEventV2::SessionBoundary {
            boundary: HookBoundaryV1::Start,
        },
    };
    let spool_root = hook_v2_spool_root(&layout.data_root, host);
    let (mut spool, _) =
        HookSpoolV1::open(&spool_root, HookSpoolConfigV1::stock(host), now).unwrap();
    spool
        .append(envelope.clone(), &snapshot.binding, now)
        .unwrap();
    spool.commit().unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while HookSpoolV1::has_records(&spool_root).unwrap() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the branch successor must replay the queued envelope");
    let duplicate =
        tracedecay_mcp::handlers::hook_runtime::admit_hook_v2_replayed_envelope_with_lifecycle(
            &fresh,
            &envelope,
            None,
            None,
            server.project_session_db().unwrap().as_ref(),
            &server.background_cpu_authority().unwrap(),
            now,
        )
        .await;
    assert!(matches!(
        duplicate,
        tracedecay_mcp::handlers::hook_runtime::HookV2AdmissionOutcomeV1::ExactDuplicate { .. }
    ));
    let later = UtcMicros(snapshot.expires_at.0 + 1);
    assert_eq!(
        previous.renew_hook_bindings(later).unwrap().len(),
        tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS.len()
    );
    assert_eq!(fresh.renew_hook_bindings(later).unwrap(), vec![]);
    let renewed = publication.load(host).unwrap().unwrap();
    assert_eq!(renewed.binding, snapshot.binding);
    assert_eq!(renewed.revision, snapshot.revision);
    assert_eq!(renewed.published_at, later);
    block_reconcile.store(true, Ordering::Release);
    git(root, &["checkout", "-q", "main"]);
    let served = server.reopen_if_branch_drifted().await;
    assert!(Arc::ptr_eq(&served, &fresh));
    tokio::time::timeout(Duration::from_secs(30), reconcile_entered.notified())
        .await
        .expect("the second branch transfer must land before retirement");
    let retiring = server.cg().await;
    assert_eq!(retiring.active_branch(), Some("main"));
    assert!(!Arc::ptr_eq(&retiring, &fresh));
    // Reconciliation is still in flight. Shutdown must close transfer
    // admission and stop the graph actually swapped into this server.
    server.shutdown().await;
    assert!(
        !crate::daemon::hook_v2_replay_consumer::hook_v2_replay_consumer_registered(
            &layout.data_root
        )
    );
    drop(delivery);
    producer.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_branch_drift_preserves_a_revoked_peer_publication() {
    for revocation in ["missing", "corrupt", "foreign"] {
        let (graph, directory, fixture) = init_indexed_repo().await;
        let graph = open_branch_tracked_graph(graph, directory.path(), &fixture).await;
        let worktree = tracedecay_agent_hosts::hooks::hook_worktree_id_for_layout(
            &crate::hook_runtime(tracedecay_runtime_core::config::ProfileRoot::new(
                fixture.profile.path(),
            )),
            graph.hook_store_layout(),
        )
        .unwrap();
        let publications = tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS
            .iter()
            .map(|host| {
                let path =
                    hook_configuration_path(&graph.hook_store_layout().data_root, worktree, *host);
                (path.clone(), std::fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();
        let revoked = hook_configuration_path(
            &graph.hook_store_layout().data_root,
            worktree,
            NativeHostIdentityV1::Codex,
        );
        let expected = match revocation {
            "missing" => {
                std::fs::remove_file(&revoked).unwrap();
                None
            }
            "corrupt" => {
                let bytes = b"invalid hook publication".to_vec();
                std::fs::write(&revoked, &bytes).unwrap();
                Some(bytes)
            }
            "foreign" => {
                let mut snapshot = HookConfigurationFileReaderV1::new(revoked.clone())
                    .load(NativeHostIdentityV1::Codex)
                    .unwrap()
                    .unwrap();
                snapshot.binding.binding_token = [99; 32];
                let bytes = serde_json::to_vec(&snapshot).unwrap();
                std::fs::write(&revoked, &bytes).unwrap();
                Some(bytes)
            }
            _ => unreachable!(),
        };
        let server = McpServer::new(graph, None).await;
        let original = server.cg().await;
        git(directory.path(), &["checkout", "-q", "feature"]);
        assert!(
            original.branch_drifted(),
            "the checkout must trigger an actual reopen"
        );
        let before = server.branch_reopens_completed();
        let served = server.reopen_if_branch_drifted().await;
        assert!(Arc::ptr_eq(&served, &original));
        assert!(
            server
                .wait_for_branch_reopen(before, Duration::from_secs(30))
                .await
        );
        assert!(
            Arc::ptr_eq(&server.cg().await, &original),
            "{revocation} host publication must refuse the unattended successor"
        );
        assert_eq!(
            std::fs::read(&revoked).ok(),
            expected,
            "{revocation} publication must remain byte-exact"
        );
        for (path, expected) in publications {
            if path != revoked {
                assert_eq!(std::fs::read(path).unwrap(), expected);
            }
        }
        server.shutdown().await;
    }
}

#[tokio::test]
async fn dropping_the_last_server_cancels_a_blocked_branch_reconcile() {
    let (graph, directory, fixture) = init_indexed_repo().await;
    let graph = open_branch_tracked_graph(graph, directory.path(), &fixture).await;
    let (cancelled, cancellation) = tokio::sync::oneshot::channel::<()>();
    let cancellation_owner = Arc::new(Mutex::new(Some(cancelled)));
    let entered = Arc::new(tokio::sync::Notify::new());
    let callback: DatabaseOwnerReconciler = {
        let entered = Arc::clone(&entered);
        Arc::new(move |_| {
            let entered = Arc::clone(&entered);
            let cancellation_owner = Arc::clone(&cancellation_owner);
            Box::pin(async move {
                let _cancellation = cancellation_owner.lock().unwrap().take().unwrap();
                entered.notify_one();
                std::future::pending::<()>().await;
            })
        })
    };
    let server = McpServer::new_with_context(
        McpServerConstructionContext::direct(Arc::new(graph), None)
            .with_database_owner_reconciler(callback),
    )
    .await;
    let background_owner = Arc::downgrade(&server.background_tasks);
    git(directory.path(), &["checkout", "-q", "feature"]);
    assert!(
        server.cg().await.branch_drifted(),
        "the checkout must trigger an actual reopen"
    );
    server.reopen_if_branch_drifted().await;
    tokio::time::timeout(Duration::from_secs(30), entered.notified())
        .await
        .expect("the real branch reconcile must be blocked before dropping the server");
    drop(server);
    assert!(
        background_owner.upgrade().is_none(),
        "the retained task must not own its JoinSet"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(30), cancellation)
            .await
            .expect("dropping the last server must abort its pending branch task")
            .is_err()
    );
}

// ---- D1: startup catch-up runs exactly once (test b) --------------

#[tokio::test]
async fn startup_catch_up_spawned_once_per_server() {
    let (cg, _dir, _pin) = init_indexed_repo().await;
    let server = McpServer::new(cg, None).await;
    // The D1 spawn should have claimed the one-shot flag.
    assert!(
        !server.startup_catch_up.try_claim_dispatch(),
        "startup catch-up should have been dispatched by new_with_dbs"
    );
    assert!(
        server
            .wait_for_startup_catch_up(Duration::from_secs(30))
            .await,
        "startup catch-up should settle"
    );
    assert!(server.startup_catch_up_done());

    // The claim is one-shot for the life of the server: a hypothetical
    // second new_with_dbs-style dispatch is refused even now that the
    // machine has settled.
    assert!(
        !server.startup_catch_up.try_claim_dispatch(),
        "startup catch-up dispatch must stay claimed (runs at most once)"
    );
    // The refused claim must not have dragged the settled machine back into
    // a pending phase.
    assert!(server.startup_catch_up_done());
}

/// A dispatched catch-up must never read as settled before it runs. This is
/// the ordering hazard the old default-`true` completion flags carried: the
/// dispatch site had to pre-clear them in a separate store, and any waiter
/// that landed in between observed a false "ready".
#[tokio::test]
async fn a_claimed_dispatch_is_never_observed_as_settled() {
    use tracedecay_mcp::server::StartupCatchUpMachineV1;

    let machine = StartupCatchUpMachineV1::default();
    // Undispatched machines are ready: nothing will ever run.
    assert!(machine.settled());

    assert!(machine.try_claim_dispatch());
    assert!(!machine.try_claim_dispatch());
    // Claiming dispatch is itself the transition into `Syncing`.
    assert!(!machine.settled());

    machine.settle();
    assert!(machine.settled());
}

/// Shutdown must leave the startup sync readable as settled.
#[tokio::test]
async fn a_cancelled_machine_reads_as_settled_and_refuses_further_phases() {
    use tracedecay_mcp::server::StartupCatchUpMachineV1;

    let machine = StartupCatchUpMachineV1::default();
    assert!(machine.try_claim_dispatch());
    machine.mark_cancelled();
    assert!(machine.settled());

    // A late in-flight task settling after shutdown cannot resurrect it.
    machine.settle();
    assert!(machine.settled());
    assert!(!machine.try_claim_dispatch());
}

#[tokio::test]
async fn direct_server_keeps_configured_profile_root_with_overridden_registry_db() {
    let (cg, dir, fixture_authority) = init_indexed_repo().await;
    let profile =
        tracedecay_runtime_core::config::ProfileRoot::new(fixture_authority.profile.path());
    let override_root = dir.path().join("registry-override");
    let runtime = FreshnessRuntime::open(&override_root).await;
    let registry = runtime.profile_database().await;

    let server =
        McpServer::new_with_dbs(cg, None, None, Some(registry), Some(profile.clone())).await;

    assert_eq!(server.owner_profile(), Some(&profile));
    assert_ne!(
        server
            .owner_profile()
            .map(tracedecay_runtime_core::config::ProfileRoot::data_dir),
        server
            .registry_db
            .as_deref()
            .and_then(|db| db.db_path().parent())
    );
}

#[test]
fn project_route_error_messages_keep_retry_authority_when_clients_hide_error_data() {
    let error = tracedecay_domain::errors::TraceDecayError::ProjectRoute {
        reason_code: "code-graph-unavailable".to_owned(),
        retryable: true,
        detail: "the verified code graph is not ready for the exact project root".to_owned(),
        typed_detail: None,
    };

    let response = tool_error_response(serde_json::json!(9), "tracedecay_test_map", &error);
    let rpc_error = response.error.expect("JSON-RPC error");

    assert_eq!(
        rpc_error.message,
        "tool project route failed: reason_code=code-graph-unavailable retryable=true: the verified code graph is not ready for the exact project root"
    );
    let data = rpc_error.data.expect("structured project-route data");
    assert_eq!(data["reason_code"], "code-graph-unavailable");
    assert_eq!(data["retryable"], true);
}

#[test]
fn publication_corruption_keeps_park_facts_typed_at_the_rpc_boundary() {
    let error = CodeIndexConvergenceParkedV1 {
        reason: "source mode is not owner-private".to_owned(),
        blocked_reason: None,
        remediation: "restore mode 0600".to_owned(),
        parked_at_micros: 1,
        observed_passes: 2,
        retries_on_wake: true,
    }
    .publication_authority_corrupt_error();
    let response = tool_error_response(serde_json::json!(10), "tracedecay_sync", &error);
    let data = response
        .error
        .expect("JSON-RPC error")
        .data
        .expect("structured route data");

    assert_eq!(
        data["reason_code"],
        CODE_INDEX_PUBLICATION_AUTHORITY_CORRUPT
    );
    assert_eq!(
        data["detail"],
        serde_json::json!({
            "kind": "parked",
            "cause": "source mode is not owner-private",
            "remedy": "restore mode 0600",
            "retries_on_wake": true,
        })
    );
}

// ---- ledger settle is bounded when a recorder task wedges ---------

// A dedicated multi-thread runtime keeps the timer driver off the worker that
// parks the wedged ledger write, so the bound is honored promptly regardless
// of machine load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_writes_settled_is_bounded_when_a_write_wedges() {
    let (cg, _dir, _pin) = init_indexed_repo().await;
    // Startup catch-up is unrelated to ledger settlement; keep its admission
    // work out of the bound being measured.
    let mut context = McpServerConstructionContext::direct(cg, None);
    context.startup_catch_up_enabled = false;
    let server = McpServer::new_with_context(context).await;

    // Inject a never-completing observed ledger write via the same accounting
    // the production path uses. Without a bound, awaiting settlement would hang
    // forever (the defect this guards against).
    server.spawn_wedged_ledger_write_for_test();

    // Wrap in an outer wall-clock guard: if the bound were ever ignored the
    // call would hang, so an elapsed outer timeout is itself the failure
    // signal (a plain assertion could never fire on a hung await).
    let bounded = tokio::time::timeout(
        Duration::from_secs(30),
        server.ledger_writes_settled_within(Duration::from_millis(150)),
    )
    .await
    .expect("bounded settle must return, never hang on a wedged write");

    assert!(
        !bounded,
        "a wedged ledger write must be reported as un-settled"
    );
}

// ---- D4: sync-on-read never blocks + single-flight (tests a, d) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_refresh_is_non_blocking_and_single_flighted() {
    let (cg, dir, _pin) = init_indexed_repo().await;
    let root = dir.path().to_path_buf();
    // Startup catch-up drives the same background-refresh boundary this test
    // times; disable it so the explicit read refresh is the only claimant.
    let mut context = McpServerConstructionContext::direct(cg, None);
    context.startup_catch_up_enabled = false;
    let server = McpServer::new_with_context(context).await;
    // Reset the read cooldown so the next spawn is eligible regardless of
    // any startup timing.
    server
        .last_background_refresh_at
        .store(0, Ordering::Release);
    server
        .background_refresh_running
        .store(false, Ordering::Release);

    // Make the tree stale: a new committed source file, as the
    // diff-scoped refresh contract tracks git history.
    std::fs::write(root.join("src/b.rs"), "pub fn b() {}\n").unwrap();
    git(&root, &["add", "."]);
    git(&root, &["commit", "-q", "-m", "add b"]);

    let cg_snapshot = server.cg_snapshot().await;

    // First read-refresh: returns immediately (we never await the sync).
    // Assert it does not block by bounding the call duration well under a
    // real sync (~hundreds of ms); the spawn does the work off-thread.
    let start = std::time::Instant::now();
    server.maybe_spawn_read_refresh(&cg_snapshot, &cg_snapshot.branch_memo());
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "maybe_spawn_read_refresh must not block on the sync (took {elapsed:?})"
    );
    // The refresh should have been claimed (running flag set), proving a
    // task was spawned rather than run inline.
    // (It may already have finished on a very fast machine; in that case
    // the cooldown stamp still advanced, which we assert below.)
    assert_ne!(
        server.last_background_refresh_at.load(Ordering::Acquire),
        0,
        "cooldown stamp must advance when a refresh is kicked"
    );

    // Second immediate read-refresh: single-flighted. Because the cooldown
    // stamp just advanced (and/or a refresh is running), no second task is
    // spawned. We verify by confirming the stamp does not change to a new
    // value on a back-to-back call within the cooldown window.
    let stamp_after_first = server.last_background_refresh_at.load(Ordering::Acquire);
    server.maybe_spawn_read_refresh(&cg_snapshot, &cg_snapshot.branch_memo());
    let stamp_after_second = server.last_background_refresh_at.load(Ordering::Acquire);
    assert_eq!(
        stamp_after_first, stamp_after_second,
        "second read within cooldown must not re-kick (single-flight)"
    );
}
