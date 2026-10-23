//! Registered, writer-admitted graph source release. No offline deletion route.

use std::path::Path;

use tracedecay_contracts::retrieval::{AdminCliGraphReplayReleaseV1, AdminCliResultV1};
use tracedecay_domain::ProjectId;
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_runtime_core::cancellation::CancellationToken;

use super::super::StoreAdministration;

pub(super) async fn release(
    administration: &StoreAdministration,
    project_id: &str,
    checkout: &Path,
    after: Option<&str>,
    digest: Option<&str>,
    cancellation: &CancellationToken,
) -> Result<AdminCliResultV1> {
    let error = |message: &str| TraceDecayError::Config {
        message: message.to_owned(),
    };
    let id = ProjectId::new(project_id).map_err(|cause| error(&cause.to_string()))?;
    administration
        .try_with_writer(|| async {
            let _clients = administration
                .maintenance_store_clients()
                .try_lock()
                .map_err(|_| error("store retirement is active; retry this maintenance page"))?;
            if cancellation.is_cancelled() {
                return Err(error("graph replay release cancelled"));
            }
            let profile = administration.registered_profile_database().await?;
            let registered = profile.get_code_project(project_id).await?.ok_or_else(|| {
                error("graph replay release requires an existing registered project")
            })?;
            let identity = administration.profile_identity()?;
            let root = Path::new(&registered.canonical_root);
            let layout = tracedecay_runtime_core::storage::profile_sharded_layout(
                root,
                identity.profile_root(),
                project_id,
            )?;
            if digest.is_none() {
                let checkout = checkout.to_path_buf();
                let after = after.map(str::to_owned);
                let plan = tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
                    tracedecay_maintenance::store_maintenance::plan_project_graph_replay_releases(
                        &layout, &checkout, after.as_deref(),
                    )
                }).await.map_err(|cause| error(&format!("join release preview: {cause}")))??;
                return Ok(AdminCliResultV1::GraphReplayRelease(AdminCliGraphReplayReleaseV1 {
                    graph_replay_release: serde_json::to_value(
                        tracedecay_maintenance::store_maintenance::GraphReplayReleaseRunV1::DryRun { plan },
                    )?,
                }));
            }
            let registry = administration.registered_runtime_registry().await?;
            // Keep the exact SQL owner until all replay and segment work has joined.
            // Admission refuses a missing SQL store; it initializes no native engine.
            let (_owner, graph) = registry
                .admit_code_graph_maintenance_database(id, [root.to_path_buf()])
                .await?;
            let lease = tracedecay_maintenance::lease::ProjectStoreMaintenanceLeaseV1::new(
                root.to_path_buf(),
                layout,
                graph,
                registry,
                profile,
            );
            let result = tracedecay_maintenance::store_maintenance::release_graph_replays(
                &lease,
                checkout,
                after,
                digest,
                cancellation,
            )
            .await?;
            Ok(AdminCliResultV1::GraphReplayRelease(
                AdminCliGraphReplayReleaseV1 {
                    graph_replay_release: serde_json::to_value(result)?,
                },
            ))
        })
        .await
        .ok_or_else(|| error("daemon writer is busy; retry this maintenance page"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tracedecay_code_index_retention::code_index_generations::{
        CodeGenerationRetentionModeV1, code_index_store_root, execute_code_generation_retention,
        plan_code_generation_retention,
    };
    use tracedecay_contracts::{CancellationContext, Deadline};
    use tracedecay_tool_catalog::ApplicationSurfaceOperation;

    #[tokio::test]
    async fn graph_release_deadline_cancels_and_joins_the_owned_work() {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let settled = Arc::new(AtomicBool::new(false));
        let worker_settled = Arc::clone(&settled);
        let deadline = Deadline::new(tracedecay_domain::UtcMicros(
            tracedecay_contracts::clock::now_micros().0 + 20_000,
        ))
        .unwrap();
        let arguments = serde_json::json!({"action":"release_graph_replays", "project_id":"proj_fixture", "project_root":"/fixture"});
        super::super::answer_profile_owner_operation(
            "release-deadline".to_owned(),
            ApplicationSurfaceOperation::AdminCli,
            arguments.as_object().unwrap().clone(),
            deadline,
            CancellationContext::active("release-deadline").unwrap(),
            Some(cancellation.clone()),
            move |_| async move {
                worker_cancellation.cancelled().await;
                tokio::task::yield_now().await;
                worker_settled.store(true, Ordering::Release);
                Err(TraceDecayError::Config {
                    message: "cooperatively cancelled".to_owned(),
                })
            },
        )
        .await;
        assert!(
            cancellation.is_cancelled(),
            "deadline must signal cooperative cancellation"
        );
        assert!(
            settled.load(Ordering::Acquire),
            "request must join work before releasing writer authority"
        );
    }

    #[test]
    fn profile_preview_needs_no_graph_database_and_apply_does_not_create_one() {
        tracedecay_runtime_core::native_runtime::block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let profile_root = temp.path().join("profile");
            let checkout = temp.path().join("checkout");
            std::fs::create_dir_all(&checkout).unwrap();
            let checkout = checkout.canonicalize().unwrap();
            let administration = StoreAdministration::default().with_profile_identity(
                tracedecay_daemon_identity::profile_identity::load_or_create(&profile_root).unwrap(),
            );
            administration.retain_authenticated_profile_database_scope(&profile_root).await.unwrap();
            let profile = administration.registered_profile_database().await.unwrap();
            let project = profile.upsert_code_project("proj_preview", &checkout, None, None, None).await.unwrap();
            let layout = tracedecay_runtime_core::storage::profile_sharded_layout(
                &checkout, &profile_root, &project.project_id,
            ).unwrap();
            let root = code_index_store_root(&layout.data_root, &checkout);
            tracedecay_code_index_retention::code_index_generations::fixture::write_generation_store_fixture(&root, 3);
            let plan = plan_code_generation_retention(&root, &BTreeSet::new()).unwrap();
            execute_code_generation_retention(&root, plan, CodeGenerationRetentionModeV1::Apply,
                tracedecay_domain::UtcMicros(1), Some(&layout.graph_db_path.with_extension("graph-replay"))).unwrap();
            assert!(!layout.graph_db_path.exists());
            let cancellation = CancellationToken::new();
            let preview = release(&administration, &project.project_id, &checkout, None, None, &cancellation)
                .await.expect("filesystem preview must not need or create a graph SQL store");
            let AdminCliResultV1::GraphReplayRelease(preview) = preview else { panic!("release result") };
            let digest = preview.graph_replay_release["plan"]["plan_digest"].as_str().unwrap();
            assert_eq!(preview.graph_replay_release["mode"], "dry_run");
            assert_eq!(preview.graph_replay_release["plan"]["releases"].as_array().unwrap().len(), 2);
            assert!(!layout.graph_db_path.exists());
            assert!(release(&administration, &project.project_id, &checkout, None, Some(digest), &cancellation).await.is_err(),
                "apply still requires an existing admitted graph store");
            assert!(!layout.graph_db_path.exists(), "apply cannot initialize a missing graph store");
            let foreign_root = temp.path().join("foreign");
            assert!(release(&administration, &project.project_id, &foreign_root, None, None, &cancellation).await.is_err());
            assert!(release(&administration, "proj_unknown", &checkout, None, None, &cancellation).await.is_err());
        }).unwrap();
    }
}
