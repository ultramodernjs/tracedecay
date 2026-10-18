//! Branch provenance resolution and opening a tracked branch snapshot.

use std::path::Path;
use std::sync::Arc;

use crate::config::{
    install_usecase_runtime_configuration_authority,
    open_runtime_configuration_for_registered_database_read_only,
};
use tracedecay_configuration::ProjectConfigurationRuntime;
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_global_db::{RegisteredGlobalDbLeaseV1, registered_enrollment_roots};
use tracedecay_runtime_core::branch_meta;
use tracedecay_runtime_core::db::DatabaseAccessMode;
use tracedecay_runtime_core::storage::{self, StoreLayout};
use tracedecay_store_runtime::DaemonSessionRuntimeRegistryV1;

use super::{TraceDecay, TraceDecayOpenOptions};

impl TraceDecay {
    /// Resolves the serving-branch provenance for a given live branch.
    ///
    /// Returns `(serving_branch, fallback_warning)`: which tracked branch's
    /// provenance the open is scoped to and whether the caller must be warned
    /// about a fallback.
    #[tracing::instrument(name = "lifecycle.resolve_serving_branch", level = "trace", skip_all)]
    pub fn resolve_serving_branch(
        project_root: &Path,
        tracedecay_dir: &Path,
        branch: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        tracedecay_application::tracedecay::resolve_serving_branch(
            project_root,
            tracedecay_dir,
            branch,
        )
    }

    /// Opens a tracked branch through the canonical registered runtime while
    /// the caller holds the exact profile's exclusive maintenance lease.
    #[tracing::instrument(name = "lifecycle.open_branch.exclusive", level = "trace", skip_all)]
    pub async fn open_branch_with_exclusive_maintenance(
        project_root: &Path,
        branch_name: &str,
        open_options: TraceDecayOpenOptions,
        lifecycle_lease: &tracedecay_runtime_core::lifecycle_lease::LifecycleLease,
    ) -> Result<Self> {
        let profile_root = open_options.resolved_profile_root()?;
        if !lifecycle_lease.is_exclusive() || !lifecycle_lease.guards_profile(&profile_root) {
            return Err(TraceDecayError::Config {
                message:
                    "branch snapshot open requires the exact profile's exclusive lifecycle lease"
                        .to_owned(),
            });
        }
        let identity = tracedecay_daemon_identity::profile_identity::load_or_create(&profile_root)?;
        let runtime_registry =
            crate::project_store_runtime::join_standalone_session_registry(identity).await?;
        let profile_database = runtime_registry.profile_database().await?;
        let store_layout = Self::resolve_registered_configuration_layout(
            project_root,
            &open_options,
            profile_database.as_ref(),
        )
        .await?;
        let project_id = storage::registered_project_id(&store_layout)?;
        let enrollment_roots = registered_enrollment_roots(
            profile_database.as_ref(),
            project_root,
            &store_layout,
            &project_id,
        )
        .await?;
        let configuration_database = runtime_registry
            .project_session_store(project_id, enrollment_roots)
            .await?;
        Self::open_branch_with_registered_configuration(
            project_root,
            branch_name,
            open_options,
            store_layout,
            configuration_database,
            profile_database,
            runtime_registry,
        )
        .await
    }

    #[tracing::instrument(name = "lifecycle.open_branch.registered", level = "trace", skip_all)]
    pub async fn open_branch_with_registered_configuration(
        project_root: &Path,
        branch_name: &str,
        open_options: TraceDecayOpenOptions,
        store_layout: StoreLayout,
        configuration_database: RegisteredGlobalDbLeaseV1,
        profile_database: RegisteredGlobalDbLeaseV1,
        runtime_registry: Arc<DaemonSessionRuntimeRegistryV1>,
    ) -> Result<Self> {
        Self::open_branch_with_registered_configuration_access(
            project_root,
            branch_name,
            open_options,
            store_layout,
            configuration_database,
            profile_database,
            runtime_registry,
            DatabaseAccessMode::ReadOnly,
            "open branch snapshot",
            true,
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Branch opening keeps configuration and profile leases distinct from graph access mode and read-only policy."
    )]
    async fn open_branch_with_registered_configuration_access(
        project_root: &Path,
        branch_name: &str,
        open_options: TraceDecayOpenOptions,
        store_layout: StoreLayout,
        configuration_database: RegisteredGlobalDbLeaseV1,
        profile_database: RegisteredGlobalDbLeaseV1,
        runtime_registry: Arc<DaemonSessionRuntimeRegistryV1>,
        access_mode: DatabaseAccessMode,
        operation: &'static str,
        read_only: bool,
    ) -> Result<Self> {
        let meta = branch_meta::load_branch_meta(&store_layout.data_root).ok_or_else(|| {
            TraceDecayError::Config {
                message: "no branch tracking configured. Run `tracedecay branch add` first"
                    .to_string(),
            }
        })?;

        if !meta.is_tracked(branch_name) {
            return Err(TraceDecayError::Config {
                message: format!("branch '{branch_name}' is not tracked"),
            });
        }
        if !meta.is_query_eligible(branch_name) {
            return Err(TraceDecayError::Config {
                message: format!(
                    "branch '{branch_name}' is still indexing; exact provenance has not been published"
                ),
            });
        }
        let db_path = store_layout.graph_db_path.clone();

        if !db_path.exists() {
            return Err(TraceDecayError::not_found(format!(
                "project database for branch provenance '{branch_name}' not found at '{}'",
                db_path.display()
            )));
        }

        let db = Self::mount_project_graph(
            runtime_registry.as_ref(),
            project_root,
            &store_layout,
            operation,
            access_mode,
        )
        .await?;
        install_usecase_runtime_configuration_authority()?;
        let (config, opened) = open_runtime_configuration_for_registered_database_read_only(
            project_root,
            &store_layout,
            configuration_database,
        )
        .await?
        .into_parts();
        let (configuration_runtime, _) = ProjectConfigurationRuntime::open(opened)?;
        let configuration_runtime = Arc::new(configuration_runtime);
        let internal_detached_scope =
            tracedecay_runtime_core::worktree::detached_worktree_graph_scope(project_root)
                .as_deref()
                == Some(branch_name);
        let mut graph = Self {
            db,
            profile_database,
            store_runtime_registry: runtime_registry,
            config,
            configuration_runtime,
            project_root: project_root.to_path_buf(),
            store_layout,
            // A provenance snapshot is read-only and must not take the live
            // checkout's publication or renewal authority.
            hook_publications: std::sync::Mutex::new(Vec::new()),
            open_options,
            active_branch: (!internal_detached_scope).then(|| branch_name.to_string()),
            serving_branch: (!internal_detached_scope).then(|| branch_name.to_string()),
            fallback_warning: None,
            read_only,
            #[cfg(any(test, feature = "test-helpers"))]
            test_runtime_guard: None,
            context_scout_owner: None,
            _standalone_maintenance_scope: None,
        };
        if let Some(project_id) =
            tracedecay_agent_hosts::hooks::hook_project_id_for_layout(&graph.store_layout)
        {
            graph.context_scout_owner = tracedecay_agent_hosts::agents::context_scout::owner::ProjectContextScoutOwnerV1::startup(
                graph.db.clone(),
                project_id,
                tracedecay_runtime_core::tracedecay::utc_now_or_one(),
                None,
            )
            .await;
        }
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::TraceDecayOpenOptions;
    use tracedecay_agent_hosts::hooks::{NATIVE_HOOK_HOSTS, hook_worktree_id_for_layout};
    use tracedecay_domain::{ProjectId, UtcMicros};
    use tracedecay_hooks::{HookConfigurationFileReaderV1, hook_configuration_path};
    use tracedecay_runtime_core::{branch_meta, config::ProfileRoot};

    #[tokio::test]
    async fn read_only_branch_open_preserves_the_live_checkouts_publication_owner() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("profile");
        let project = directory.path().join("project");
        let runtime = crate::test_support::host_admission::HostAdmissionTestRuntimeV1::project(
            &profile,
            &project,
            ProjectId::new("project.branch-hook-owner").unwrap(),
        )
        .await
        .unwrap();
        let options = TraceDecayOpenOptions::for_profile(&ProfileRoot::new(&profile));
        let live = runtime
            .initialize_project_graph_for_test(&project, options.clone())
            .await
            .unwrap();
        branch_meta::save_branch_meta(
            &live.hook_store_layout().data_root,
            &branch_meta::BranchMeta::new("main"),
        )
        .unwrap();
        let hook_runtime = crate::runtime_ports::hook_runtime(ProfileRoot::new(&profile)).unwrap();
        let worktree =
            hook_worktree_id_for_layout(&hook_runtime, live.hook_store_layout()).unwrap();
        let publications = NATIVE_HOOK_HOSTS
            .iter()
            .map(|host| {
                let path =
                    hook_configuration_path(&live.hook_store_layout().data_root, worktree, *host);
                let snapshot = HookConfigurationFileReaderV1::new(&path)
                    .load(*host)
                    .unwrap()
                    .unwrap();
                (path.clone(), std::fs::read(path).unwrap(), snapshot)
            })
            .collect::<Vec<_>>();
        let branch = runtime
            .open_project_branch_for_test(&project, "main", options)
            .await
            .unwrap();
        assert!(branch.is_read_only());
        assert_eq!(
            branch.hook_store_layout().identity,
            live.hook_store_layout().identity
        );
        assert_eq!(
            branch.hook_store_layout().data_root,
            live.hook_store_layout().data_root
        );
        let later = UtcMicros(
            publications
                .iter()
                .map(|(_, _, snapshot)| snapshot.expires_at.0)
                .max()
                .unwrap()
                + 1,
        );
        assert_eq!(branch.renew_hook_bindings(later).unwrap(), vec![]);
        for (path, bytes, _) in &publications {
            assert_eq!(
                std::fs::read(path).unwrap(),
                *bytes,
                "branch open and renewal preserve {path:?}"
            );
        }
        assert_eq!(live.renew_hook_bindings(later).unwrap(), vec![]);
        for (path, _, expected) in publications {
            let renewed = HookConfigurationFileReaderV1::new(path)
                .load(expected.binding.host)
                .unwrap()
                .unwrap();
            assert_eq!(renewed.binding, expected.binding);
            assert_eq!(renewed.revision, expected.revision);
            assert_eq!(renewed.published_at, later);
        }
        tracedecay_agent_hosts::agents::context_scout::owner::unregister_registered_context_scout_owner(
            tracedecay_agent_hosts::hooks::hook_project_id_for_layout(live.hook_store_layout()).unwrap(),
            &live.db_path(),
        );
        drop((branch, live));
        runtime.shutdown().await.unwrap();
    }
}
