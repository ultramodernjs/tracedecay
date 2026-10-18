//! Opens registered projects whose hook spools hold events or delivery
//! receipts no running replay consumer will drain: at startup for every
//! project with spooled records or receipts, and afterwards for each append
//! or receipt the spool watch reports on a project that is not open. The Unix
//! daemon opens through its `DaemonEngine`; the portable daemon through the
//! project-server warmup a client request would take.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracedecay_daemon_service::shutdown::DaemonLifecycle;
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_hooks::{
    HookConfigurationFileReaderV1, HookDeliveryReceiptSpoolV1, HookSpoolConfigV1, HookSpoolV1,
    hook_configuration_path, hook_delivery_receipt_spool_root, hook_v2_spool_root,
};
use tracedecay_runtime_core::config::ProfileRoot;
use tracedecay_runtime_core::native_runtime::NativeTask;
use tracedecay_runtime_core::storage::StoreLayout;

use super::spool_watch::{SpooledProject, consumer_attached, install_opener, watch_project};
#[cfg(not(unix))]
use crate::daemon::DaemonInvocationState;
use crate::daemon::branch_admin::StoreAdministration;
#[cfg(unix)]
use crate::daemon::engine::DaemonEngine;
#[cfg(not(unix))]
use crate::daemon::project_open_admission::ProjectOpenGates;
#[cfg(unix)]
use crate::daemon::project_open_admission::ProjectOpenTaskClaim;
#[cfg(not(unix))]
use crate::daemon::project_open_orchestration::schedule_portable_project_server_warmup_with_hook_recovery;
use crate::daemon::project_routing::bind_authenticated_profile_identity;
#[cfg(unix)]
use crate::daemon::project_routing::project_open_task_capacity_error;

/// The owners a portable daemon needs to open a project for its spool: the
/// same bundle a client connection carries into
/// [`schedule_portable_project_server_warmup`], plus the lifecycle the opener
/// drains with.
#[cfg(not(unix))]
pub(in crate::daemon) struct PortableSpoolOpenerOwners {
    pub lifecycle: DaemonLifecycle,
    pub store_administration: StoreAdministration,
    pub project_open_gates: Arc<tokio::sync::Mutex<ProjectOpenGates>>,
    pub invocation: DaemonInvocationState,
    pub http_application_registry: crate::daemon::http_application::DaemonHttpApplicationRegistry,
}

/// How `open_for_spooled_hooks` mounts a project on this platform.
enum SpoolOpener {
    #[cfg(unix)]
    Engine(DaemonEngine),
    #[cfg(not(unix))]
    Portable(PortableSpoolOpenerOwners),
}

/// Whether any host spool holds records or receipts to drain. A spool that
/// cannot be read is reported and counted as holding work, so the project's
/// replay consumer surfaces the fault instead of the opener hiding it.
fn has_spooled_records(data_root: &Path) -> bool {
    tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS
        .iter()
        .any(|host| {
            let records = HookSpoolV1::has_records(&hook_v2_spool_root(data_root, *host))
                .map_err(|error| error.to_string());
            let receipts = HookDeliveryReceiptSpoolV1::has_receipts(
                &hook_delivery_receipt_spool_root(data_root, *host),
            )
            .map_err(|error| error.to_string());
            match (records, receipts) {
                (Ok(records), Ok(receipts)) => {
                    let pending = tracedecay_mcp::handlers::hook_runtime::hook_v2_pending_work_envelopes(data_root, *host, super::hook_replay_now());
                    records || receipts || match pending {
                        Ok(pending) => !pending.is_empty(),
                        Err(error) => { tracing::warn!(%error, "hook producer ledger could not be inspected; work stays owed"); true }
                    }
                },
                (Err(error), _) | (_, Err(error)) => {
                    tracing::warn!(
                        host = host.hook_key(),
                        %error,
                        data_root = %data_root.display(),
                        "hook spool could not be inspected at startup; opening its project to drain it"
                    );
                    true
                }
            }
        })
}

/// Starts the daemon's spooled-hook opener on Unix: watches every registered
/// project, opens the ones already holding spooled records, then opens each
/// project whose spool receives an append while it is not open. Runs until
/// the daemon drains.
#[cfg(unix)]
pub(in crate::daemon) fn spawn_spooled_hook_opener(
    engine: DaemonEngine,
    profile: ProfileRoot,
) -> Option<NativeTask<()>> {
    spawn_spool_opener(
        engine.store_administration.clone(),
        engine.lifecycle.clone(),
        SpoolOpener::Engine(engine),
        profile,
    )
}

/// Starts the daemon's spooled-hook opener on the portable daemon. Identical
/// to the Unix entry point except project opens go through the portable
/// project-server warmup instead of the engine.
#[cfg(not(unix))]
pub(in crate::daemon) fn spawn_spooled_hook_opener(
    owners: PortableSpoolOpenerOwners,
    profile: ProfileRoot,
) -> Option<NativeTask<()>> {
    spawn_spool_opener(
        owners.store_administration.clone(),
        owners.lifecycle.clone(),
        SpoolOpener::Portable(owners),
        profile,
    )
}

fn spawn_spool_opener(
    store_administration: StoreAdministration,
    lifecycle: DaemonLifecycle,
    opener: SpoolOpener,
    profile: ProfileRoot,
) -> Option<NativeTask<()>> {
    let (wakes, mut requests) = mpsc::unbounded_channel();
    install_opener(wakes.clone());
    // Without a runtime nothing opens for spooled hooks until a client opens
    // the project.
    let opener = NativeTask::spawn(async move {
        let work = async {
            match registered_projects(&store_administration, &profile, None).await {
                Ok(projects) => {
                    for (project, _) in projects {
                        watch_project(&project, None);
                        if has_spooled_records(&project.data_root) {
                            let _ = wakes.send(project);
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    %error,
                    "registered projects could not be read; spooled hook events wait until each project opens"
                ),
            }
            while let Some(project) = requests.recv().await {
                let mut waking_roots = BTreeSet::from([project.data_root]);
                for _ in 0..requests.len() {
                    let Ok(next) = requests.try_recv() else {
                        break;
                    };
                    waking_roots.insert(next.data_root);
                }
                // The watch gives a shared spool hint, never routing authority.
                // Refresh enrolled aliases so a newly registered sibling is found.
                match registered_projects(&store_administration, &profile, Some(&waking_roots))
                    .await
                {
                    Ok(candidates) => {
                        for (candidate, layout) in candidates
                            .into_iter()
                            .filter(|(candidate, _)| waking_roots.contains(&candidate.data_root))
                        {
                            if consumer_attached(&candidate.data_root, &candidate.project_root) {
                                continue;
                            }
                            let publications = match hook_recovery_publications_for_owed_scope(
                                &profile, &candidate, &layout,
                            )
                            .await
                            {
                                Ok(None) => continue,
                                Err(error) => {
                                    tracing::warn!(%error, project = %candidate.project_root.display(), "hook scope could not be validated for reopening; work stays owed");
                                    continue;
                                }
                                Ok(Some(publications)) => Arc::new(publications),
                            };
                            if let Err(error) =
                                open_for_spooled_hooks(&opener, &profile, &candidate, publications)
                                    .await
                            {
                                tracing::warn!(%error, project = %candidate.project_root.display(), "project holding spooled hook events could not be opened");
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "registered hook scopes could not be read; work stays owed");
                    }
                }
            }
        };
        tokio::select! {
            () = work => {}
            () = lifecycle.wait_for_draining() => {}
        }
    });
    opener
        .inspect_err(|error| tracing::warn!(%error, "spooled hook opener not admitted"))
        .ok()
}

async fn registered_projects(
    store_administration: &StoreAdministration,
    profile: &ProfileRoot,
    waking_roots: Option<&BTreeSet<std::path::PathBuf>>,
) -> Result<Vec<(SpooledProject, StoreLayout)>> {
    let registry = store_administration.registered_profile_database().await?;
    let mut roots: BTreeSet<_> = registry
        .try_list_code_project_paths(usize::MAX)
        .await?
        .into_iter()
        .collect();
    roots.extend(registry.try_list_project_alias_paths().await?);
    let mut projects = Vec::new();
    for project_root in roots {
        // A persisted layout is the same preferred input to registered layout
        // resolution. Use it only to exclude unrelated wake targets early; a
        // missing or unreadable marker still goes through registry authority.
        if let Some(waking_roots) = waking_roots
            && let Ok(Some(layout)) = tracedecay_runtime_core::storage::resolve_persisted_layout(
                &project_root,
                profile.data_dir(),
            )
            && !waking_roots.contains(&layout.data_root)
        {
            continue;
        }
        let Some(context) = registry
            .project_registry_context_by_alias(&project_root)
            .await?
        else {
            continue;
        };
        let handshake = crate::daemon::handshake_for_current_client(
            profile,
            Some(project_root.clone()),
            None,
            false,
            false,
        )?;
        match tracedecay_project::project::TraceDecay::resolve_registered_configuration_layout(
            &project_root,
            &crate::daemon::handshake_open_options(&handshake),
            registry.as_ref(),
        )
        .await
        {
            Ok(layout)
                if layout.identity.project_id.as_deref()
                    == Some(context.project.project_id.as_str())
                    && layout.data_root.is_dir() =>
            {
                projects.push((
                    SpooledProject {
                        project_root,
                        data_root: layout.data_root.clone(),
                    },
                    layout,
                ));
            }
            Ok(_) => {
                tracing::warn!(project = %project_root.display(), "registered hook scope no longer matches its enrolled store; work stays owed");
            }
            Err(error) => {
                tracing::warn!(%error, project = %project_root.display(), "registered hook scope layout is unavailable; work stays owed");
            }
        }
    }
    Ok(projects)
}

/// Enrollment selects candidate roots. Exact canonical scope and a surviving
/// publication select which candidate may be reopened for queued envelopes.
/// Lease expiry is allowed for this identity check; admission uses the normal
/// project open and its fresh publication. Missing or changed bindings cannot
/// recreate a revoked authority from an untrusted envelope.
async fn hook_recovery_publications_for_owed_scope(
    profile: &ProfileRoot,
    project: &SpooledProject,
    layout: &StoreLayout,
) -> Result<Option<Vec<tracedecay_hooks::HookConfigurationSnapshotV1>>> {
    let profile = profile.clone();
    let project = project.clone();
    let layout = layout.clone();
    tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
        let key = layout
            .identity
            .project_id
            .as_deref()
            .ok_or_else(|| TraceDecayError::Config {
                message: "registered hook scope has no project identity".to_owned(),
            })?;
        let project_id = tracedecay_domain::ProjectId::new(key.to_owned()).map_err(|error| {
            TraceDecayError::Config {
                message: error.to_string(),
            }
        })?;
        let runtime = crate::hook_runtime(profile);
        if layout.data_root != project.data_root {
            return Err(TraceDecayError::Config {
                message: "registered hook scope changed its enrolled store".to_owned(),
            });
        }
        let scope =
            (runtime.scope_resolver)(&layout.project_root, &project_id).map_err(|error| {
                TraceDecayError::Config {
                    message: error.clone(),
                }
            })?;
        let (project_id, worktree_id) = tracedecay_agent_hosts::hooks::hook_scope_locators(&scope);
        let repository_id =
            tracedecay_hooks::envelope_identity_hash16("repository", scope.repository_id.as_str());
        let now = super::hook_replay_now();
        let publications = load_hook_recovery_publications(
            &project.data_root,
            project_id,
            worktree_id,
            repository_id,
        )?;
        for snapshot in &publications {
            let host = &snapshot.binding.host;
            let pending = tracedecay_mcp::handlers::hook_runtime::hook_v2_pending_work_envelopes(
                &project.data_root,
                *host,
                now,
            )
            .map_err(|error| TraceDecayError::Config {
                message: error.to_string(),
            })?;
            if pending
                .iter()
                .any(|envelope| envelope.validate(&snapshot.binding).is_ok())
            {
                return Ok(Some(publications));
            }
            if HookDeliveryReceiptSpoolV1::has_receipts(&hook_delivery_receipt_spool_root(
                &project.data_root,
                *host,
            ))
            .map_err(|error| TraceDecayError::Config {
                message: error.to_string(),
            })? {
                return Ok(Some(publications));
            }
            let root = hook_v2_spool_root(&project.data_root, *host);
            if !HookSpoolV1::has_records(&root).map_err(|error| TraceDecayError::Config {
                message: error.to_string(),
            })? {
                continue;
            }
            let config = HookSpoolConfigV1::stock(*host);
            let (mut spool, _) = HookSpoolV1::open_within(root, config, now, config.writer_lease())
                .map_err(|error| TraceDecayError::Config {
                    message: error.to_string(),
                })?;
            if spool
                .pending_records_in_scope(project_id, worktree_id)
                .map_err(|error| TraceDecayError::Config {
                    message: error.to_string(),
                })?
                .iter()
                .any(|record| record.envelope.validate(&snapshot.binding).is_ok())
            {
                return Ok(Some(publications));
            }
        }
        Ok(None)
    })
    .await
    .map_err(|error| TraceDecayError::Config {
        message: format!("hook scope inspection failed: {error}"),
    })?
}

/// Validate every host publication before inspecting or opening any spool.
fn load_hook_recovery_publications(
    data_root: &Path,
    project_id: [u8; 16],
    worktree_id: [u8; 16],
    repository_id: [u8; 16],
) -> Result<Vec<tracedecay_hooks::HookConfigurationSnapshotV1>> {
    let mut publications = Vec::new();
    for host in tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS {
        let snapshot = HookConfigurationFileReaderV1::new(hook_configuration_path(
            data_root,
            worktree_id,
            *host,
        ))
        .load(*host)
        .map_err(|error| TraceDecayError::Config {
            message: format!("hook recovery publication unavailable: {error}"),
        })?
        .ok_or_else(|| TraceDecayError::Config {
            message: format!("{} hook recovery publication was revoked", host.hook_key()),
        })?;
        if snapshot.binding.project_id != project_id
            || snapshot.binding.worktree_id != worktree_id
            || snapshot.binding.repository_id != repository_id
            || snapshot.binding.host != *host
        {
            return Err(TraceDecayError::Config {
                message: "hook recovery publication changed its canonical scope".to_owned(),
            });
        }
        publications.push(snapshot);
    }
    Ok(publications)
}

/// Opens `project` with the daemon's own profile identity, exactly as a
/// client request for it would. Project composition registers the replay
/// consumer, whose first pass drains the spool.
async fn open_for_spooled_hooks(
    opener: &SpoolOpener,
    profile: &ProfileRoot,
    project: &SpooledProject,
    publications: Arc<Vec<tracedecay_hooks::HookConfigurationSnapshotV1>>,
) -> Result<()> {
    let mut handshake = crate::daemon::handshake_for_current_client(
        profile,
        Some(project.project_root.clone()),
        None,
        false,
        false,
    )?;
    match opener {
        #[cfg(unix)]
        SpoolOpener::Engine(engine) => {
            let administration =
                bind_authenticated_profile_identity(&mut handshake, &engine.store_administration)
                    .await?;
            let mut engine = engine.clone();
            engine.store_administration = administration;
            match engine
                .begin_project_open_for_hook_replay(handshake, publications)
                .await?
            {
                ProjectOpenTaskClaim::InFlight(_) => Ok(()),
                ProjectOpenTaskClaim::Failed(failure) => Err(failure.to_error()),
                ProjectOpenTaskClaim::Saturated => Err(project_open_task_capacity_error()),
            }
        }
        #[cfg(not(unix))]
        SpoolOpener::Portable(owners) => {
            let administration =
                bind_authenticated_profile_identity(&mut handshake, &owners.store_administration)
                    .await?;
            schedule_portable_project_server_warmup_with_hook_recovery(
                owners.lifecycle.clone(),
                administration,
                Arc::clone(&owners.project_open_gates),
                owners.invocation.clone(),
                owners.http_application_registry.clone(),
                handshake,
                None,
                Some(publications),
                #[cfg(test)]
                None,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracedecay_domain::{NativeHostIdentityV1, ProjectId};
    use tracedecay_hooks::{
        HOOK_EVENT_SCHEMA_VERSION, HookAdmissionLedgerLimitsV1, HookAdmissionLedgerV1,
        HookEventEnvelopeV2, HookEventV2, HookOrderingV1, PROJECT_HOOK_ADMISSIONS_DIR,
    };
    use tracedecay_project::project::TraceDecayOpenOptions;
    use tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1;

    #[tokio::test]
    async fn producer_only_work_reopens_its_exact_scope_and_revoked_publications_stay_revoked() {
        let directory = tempfile::tempdir().unwrap();
        let profile = ProfileRoot::new(directory.path().join("profile"));
        let project_root = directory.path().join("project");
        let runtime = HostAdmissionTestRuntimeV1::project(
            profile.data_dir(),
            &project_root,
            ProjectId::new("project.hook-producer-reopen").unwrap(),
        )
        .await
        .unwrap();
        let graph = runtime
            .initialize_project_graph_for_test(
                &project_root,
                TraceDecayOpenOptions::for_profile(&profile),
            )
            .await
            .unwrap();
        let project = SpooledProject {
            project_root: project_root.clone(),
            data_root: graph.hook_store_layout().data_root.clone(),
        };
        let host = NativeHostIdentityV1::CursorDesktop;
        let worktree_id = tracedecay_agent_hosts::hooks::hook_worktree_id_for_layout(
            &crate::hook_runtime(profile.clone()),
            graph.hook_store_layout(),
        )
        .unwrap();
        let publication_path = hook_configuration_path(&project.data_root, worktree_id, host);
        let snapshot = HookConfigurationFileReaderV1::new(&publication_path)
            .load(host)
            .unwrap()
            .unwrap();
        let binding = snapshot.binding;
        let now = super::super::hook_replay_now();
        let event = HookEventEnvelopeV2 {
            schema_version: HOOK_EVENT_SCHEMA_VERSION,
            event_id: [17; 16],
            producer: host,
            protected_session_id: [18; 32],
            project_id: binding.project_id,
            repository_id: binding.repository_id,
            worktree_id: binding.worktree_id,
            worktree_epoch: binding.worktree_epoch,
            binding_token: binding.binding_token,
            ordering: HookOrderingV1::ProviderSequence(1),
            observed_at: now,
            event: HookEventV2::SavedEdit {
                file_id: [19; 16],
                changed_range_count: 1,
            },
        };
        let ledger_root = project
            .data_root
            .join(PROJECT_HOOK_ADMISSIONS_DIR)
            .join(host.hook_key());
        let (mut ledger, _) = HookAdmissionLedgerV1::open(
            &ledger_root,
            host,
            HookAdmissionLedgerLimitsV1::stock(),
            now,
        )
        .unwrap();
        ledger
            .stage_admission(&event, Some(&event), now)
            .unwrap()
            .commit
            .wait()
            .unwrap();
        drop(ledger);
        let claude = NativeHostIdentityV1::ClaudeCode;
        let claude_binding = HookConfigurationFileReaderV1::new(hook_configuration_path(
            &project.data_root,
            worktree_id,
            claude,
        ))
        .load(claude)
        .unwrap()
        .unwrap()
        .binding;
        let mut claude_event = event.clone();
        claude_event.event_id = [22; 16];
        claude_event.producer = claude;
        claude_event.binding_token = claude_binding.binding_token;
        claude_event.worktree_epoch = claude_binding.worktree_epoch;
        claude_event.event = HookEventV2::SessionBoundary {
            boundary: tracedecay_hooks::HookBoundaryV1::Start,
        };
        let (mut ledger, _) = HookAdmissionLedgerV1::open(
            project
                .data_root
                .join(PROJECT_HOOK_ADMISSIONS_DIR)
                .join(claude.hook_key()),
            claude,
            HookAdmissionLedgerLimitsV1::stock(),
            now,
        )
        .unwrap();
        ledger
            .stage_admission(&claude_event, Some(&claude_event), now)
            .unwrap()
            .commit
            .wait()
            .unwrap();
        drop(ledger);
        assert!(!HookSpoolV1::has_records(&hook_v2_spool_root(&project.data_root, host)).unwrap());
        assert!(has_spooled_records(&project.data_root));
        assert!(
            hook_recovery_publications_for_owed_scope(
                &profile,
                &project,
                graph.hook_store_layout()
            )
            .await
            .unwrap()
            .is_some()
        );
        // Deletion is revocation. The opener cannot recreate its old snapshot
        // merely because this valid prior envelope remains in the work ledger.
        let publication_path =
            hook_configuration_path(&project.data_root, worktree_id, NativeHostIdentityV1::Codex);
        let original_codex = HookConfigurationFileReaderV1::new(&publication_path)
            .load(NativeHostIdentityV1::Codex)
            .unwrap()
            .unwrap();
        std::fs::remove_file(&publication_path).unwrap();
        assert!(
            hook_recovery_publications_for_owed_scope(
                &profile,
                &project,
                graph.hook_store_layout()
            )
            .await
            .is_err()
        );
        assert!(!publication_path.exists());
        std::fs::write(&publication_path, b"corrupt revoked publication").unwrap();
        assert!(
            hook_recovery_publications_for_owed_scope(
                &profile,
                &project,
                graph.hook_store_layout()
            )
            .await
            .is_err()
        );
        assert_eq!(
            std::fs::read(&publication_path).unwrap(),
            b"corrupt revoked publication"
        );
        let mut foreign = original_codex;
        foreign.binding.repository_id = [33; 16];
        let foreign_bytes = serde_json::to_vec(&foreign).unwrap();
        std::fs::write(&publication_path, &foreign_bytes).unwrap();
        assert!(
            hook_recovery_publications_for_owed_scope(
                &profile,
                &project,
                graph.hook_store_layout()
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&publication_path).unwrap(), foreign_bytes);
        tracedecay_agent_hosts::agents::context_scout::owner::unregister_registered_context_scout_owner(
            tracedecay_agent_hosts::hooks::hook_project_id_for_layout(graph.hook_store_layout()).unwrap(),
            &graph.db_path(),
        );
        drop(graph);
        runtime.shutdown().await.unwrap();
    }
}
