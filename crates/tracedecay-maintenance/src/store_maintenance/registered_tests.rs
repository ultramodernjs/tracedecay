#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use crate::lease::ProjectStoreMaintenanceLeaseV1;
use tracedecay_code_index_retention::code_index_generations::fixture::write_generation_store_fixture;
use tracedecay_code_index_retention::code_index_generations::{
    code_generation_graph_replay_release_page, code_index_store_root, record_scope_root,
};
use tracedecay_code_index_runtime::code_index_scheduler::CodeIndexSchedulerRegistryV1;
use tracedecay_runtime_core::cancellation::CancellationToken;
use tracedecay_runtime_core::resident_memory::{
    DEFAULT_PROCESS_RESIDENT_MEMORY_LIMIT_V1, ProcessResidentMemoryV1,
};
use tracedecay_runtime_core::storage::profile_sharded_data_root;
use tracedecay_store_runtime::DaemonSessionRuntimeRegistryV1;

use super::{
    CodeGenerationRetentionOutcomeV1, RegisteredProjectStoreV1,
    run_registered_code_generation_retention,
};
use crate::telemetry::StoreTelemetrySamplingRegistry;

pub(crate) async fn maintenance_lease(
    profile_root: &Path,
    checkout: &Path,
    project_id: &str,
) -> (
    ProjectStoreMaintenanceLeaseV1,
    tracedecay_runtime_core::db::DaemonDatabaseScope,
    tracedecay_runtime_core::db::DatabaseOwnerV1,
) {
    let identity = tracedecay_daemon_identity::profile_identity::load_or_create(profile_root)
        .expect("fixture profile identity");
    let scope = tracedecay_runtime_core::db::enter_daemon_database_scope(
        profile_root,
        73,
        "registered replay maintenance fixture",
    )
    .expect("fixture daemon scope");
    let fixture_identity = tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
        identity.brain_id().clone(),
        identity.profile_id().clone(),
    );
    let registry = Arc::new(
        DaemonSessionRuntimeRegistryV1::open(identity)
            .await
            .expect("fixture registry"),
    );
    let id = tracedecay_domain::ProjectId::new(project_id).expect("project id");
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(checkout, project_id)
        .expect("fixture project enrollment");
    let layout = tracedecay_runtime_core::storage::profile_sharded_layout(
        checkout,
        profile_root,
        project_id,
    )
    .expect("fixture layout");
    tracedecay_runtime_core::storage::PrivateStoreIo::create_dir_all(&layout.data_root)
        .expect("fixture data root");
    let authority = tracedecay_runtime_core::db::DatabaseAuthority::acquire_test(
        &layout.graph_db_path,
        "initialize isolated graph SQL fixture",
    )
    .expect("isolated schema seed authority");
    let (seed, _) = tracedecay_runtime_core::db::Database::publish_registered_test_runtime_for_profile_identity(
        &layout.graph_db_path,
        &authority,
        tracedecay_runtime_core::db::TestDatabaseRuntimeMode::Initialize,
        fixture_identity,
        tracedecay_runtime_core::db::TestDatabaseRuntimeScope::Project { project_id: id.clone() },
    )
    .await
    .expect("initialize isolated SQL schema");
    drop(seed);
    drop(authority);
    let (owner, graph) = registry
        .admit_code_graph_maintenance_database(id, [checkout.to_path_buf()])
        .await
        .expect("admitted lazy maintenance database");
    let profile = registry.profile_database().await.expect("profile database");
    (
        ProjectStoreMaintenanceLeaseV1::new(
            checkout.to_path_buf(),
            layout,
            graph,
            registry,
            profile,
        ),
        scope,
        owner,
    )
}

/// A scheduler registry with nothing mounted, through the production
/// constructor.
pub(crate) fn unmounted_scheduler_registry() -> CodeIndexSchedulerRegistryV1 {
    CodeIndexSchedulerRegistryV1::with_resident_memory_and_progress_producer_incarnation(
        1,
        Arc::new(ProcessResidentMemoryV1::new(
            DEFAULT_PROCESS_RESIDENT_MEMORY_LIMIT_V1,
        )),
        1,
    )
}

#[asupersync::test]
async fn registered_pass_drains_collected_scope_using_its_recorded_root() {
    use tracedecay_code_index_retention::code_index_generations::{
        CodeGenerationRetentionModeV1, execute_code_generation_retention,
        plan_code_generation_retention,
    };
    let temp = tempfile::TempDir::new().expect("fixture root");
    let profile = temp.path().join("profile");
    let checkout = temp.path().join("checkout");
    let linked = temp.path().join("linked");
    std::fs::create_dir_all(&checkout).expect("checkout");
    std::fs::create_dir_all(&linked).expect("linked checkout");
    let checkout = checkout.canonicalize().expect("canonical checkout");
    let linked = linked.canonicalize().expect("canonical linked checkout");
    let (lease, _scope, _owner) = maintenance_lease(&profile, &checkout, "proj_release_only").await;
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(&linked, "proj_release_only")
        .expect("linked checkout repository identity");
    let data_root = lease.store_layout().data_root.clone();
    let primary = code_index_store_root(&data_root, &checkout);
    let scope_root = code_index_store_root(&data_root, &linked);
    write_generation_store_fixture(&primary, 1);
    write_generation_store_fixture(&scope_root, 3);
    record_scope_root(&scope_root, &linked).expect("record scope root");
    let pool = lease
        .graph_db()
        .database_path()
        .with_extension("graph-replay");
    let plan =
        plan_code_generation_retention(&scope_root, &BTreeSet::new()).expect("collection plan");
    execute_code_generation_retention(
        &scope_root,
        plan,
        CodeGenerationRetentionModeV1::Apply,
        tracedecay_domain::UtcMicros(1),
        Some(&pool),
    )
    .expect("durably queue real releases");
    assert_eq!(generation_file_count(&scope_root), 1);
    assert_eq!(
        code_generation_graph_replay_release_page(&scope_root, None)
            .expect("queued releases")
            .releases
            .len(),
        2
    );
    let observations = StoreTelemetrySamplingRegistry::default();
    // A primary checkout's backoff must not suppress the linked scope.
    observations.record_graph_replay_release_unhealthy(&checkout);
    let store = RegisteredProjectStoreV1 {
        data_root,
        canonical_root: checkout,
    };
    let outcome = run_registered_code_generation_retention(
        &store,
        &lease,
        &BTreeSet::from([primary]),
        &unmounted_scheduler_registry(),
        lease.profile_database(),
        &observations,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        outcome,
        CodeGenerationRetentionOutcomeV1::MoreWork,
        "released sources require the following segment census"
    );
    assert_eq!(
        code_generation_graph_replay_release_page(&scope_root, None)
            .expect("release queue after reconcile")
            .releases,
        Vec::new()
    );
    assert!(
        !lease
            .graph_db()
            .database_path()
            .with_extension("grafeo")
            .exists(),
        "no native staging engine was needed"
    );
}

fn generation_file_count(store_root: &Path) -> usize {
    std::fs::read_dir(store_root.join("code-generations-v1"))
        .expect("list generations")
        .count()
}

/// The unmounted primary scope is collected while the linked worktree's scope,
/// which a mounted graph owns, is left to that graph's own pass. Retired
/// generations release their real on-disk queue and pool links without a
/// mounted scheduler; the next census converges.
#[asupersync::test]
async fn registered_pass_collects_unmounted_scopes_and_leaves_mounted_ones() {
    let temp = tempfile::TempDir::new().expect("temp root");
    let profile_root = temp.path().join("profile");
    let checkout = temp.path().join("checkout");
    let linked = temp.path().join("linked");
    std::fs::create_dir_all(&checkout).expect("checkout");
    std::fs::create_dir_all(&linked).expect("linked worktree");
    let checkout = checkout.canonicalize().expect("canonical checkout");
    let linked = linked.canonicalize().expect("canonical linked worktree");
    let (lease, _scope, _owner) =
        maintenance_lease(&profile_root, &checkout, "proj_registered").await;
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(&linked, "proj_registered")
        .expect("linked checkout repository identity");
    let data_root = profile_sharded_data_root(&profile_root, "proj_registered");
    let primary = code_index_store_root(&data_root, &checkout);
    let mounted = code_index_store_root(&data_root, &linked);
    write_generation_store_fixture(&primary, 6);
    write_generation_store_fixture(&mounted, 4);
    record_scope_root(&mounted, &linked).expect("record linked scope root");
    let store = RegisteredProjectStoreV1 {
        data_root,
        canonical_root: checkout,
    };
    let schedulers = unmounted_scheduler_registry();
    let observations = StoreTelemetrySamplingRegistry::default();
    let mounted_store_roots = BTreeSet::from([mounted.clone()]);

    let first = run_registered_code_generation_retention(
        &store,
        &lease,
        &mounted_store_roots,
        &schedulers,
        lease.profile_database(),
        &observations,
        &CancellationToken::new(),
    )
    .await;

    assert_eq!(first, CodeGenerationRetentionOutcomeV1::MoreWork);
    assert_eq!(generation_file_count(&primary), 1);
    assert_eq!(generation_file_count(&mounted), 4);
    assert_eq!(
        code_generation_graph_replay_release_page(&primary, None)
            .expect("release queue")
            .releases
            .len(),
        0
    );
    assert!(
        !lease
            .graph_db()
            .database_path()
            .with_extension("grafeo")
            .exists(),
        "source release must not open native staging"
    );

    let second = run_registered_code_generation_retention(
        &store,
        &lease,
        &mounted_store_roots,
        &schedulers,
        lease.profile_database(),
        &observations,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(second, CodeGenerationRetentionOutcomeV1::Complete);

    let unmounted_everywhere = run_registered_code_generation_retention(
        &store,
        &lease,
        &BTreeSet::new(),
        &schedulers,
        lease.profile_database(),
        &observations,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        unmounted_everywhere,
        CodeGenerationRetentionOutcomeV1::MoreWork
    );
    assert_eq!(generation_file_count(&mounted), 1);
}
