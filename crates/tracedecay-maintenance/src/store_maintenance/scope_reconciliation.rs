//! Collection of whole code-index scopes whose worktree is gone.
//!
//! Generation retention runs inside one scope and never enumerates its
//! siblings, so a removed linked worktree's scope, and every generation,
//! segment, and shared text artifact only it names, would stay on disk for
//! the life of the profile. This pass collects such scopes; the next
//! generation-retention pass then sweeps the shared files nothing names.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tracedecay_code_index_retention::code_index_generations::{
    CodeGenerationRetentionErrorV1, CodeGenerationRetentionModeV1,
    DEFAULT_STRANDED_SCOPE_MINIMUM_AGE_SECS, code_index_scope_store_root,
    execute_scope_root_retention, plan_scope_root_retention_with_liveness_proof,
    recover_scope_root_retention, scope_root_liveness_proof, scoped_code_index_store_root,
};
use tracedecay_code_index_runtime::code_index_scheduler::CodeIndexSchedulerRegistryV1;
use tracedecay_graph_db::GraphDbError;
use tracedecay_runtime_core::db::engine::params;
use tracedecay_runtime_core::logging::log_daemon_event;
use tracedecay_runtime_core::native_runtime;

use crate::clock::now_secs_i64;
use crate::lease::ProjectStoreMaintenanceLeaseV1;
use crate::telemetry::StoreTelemetrySamplingRegistry;
use crate::tick::{MaintenanceContinuation, MaintenanceTickOutcome};
use tracedecay_runtime_core::cancellation::CancellationToken;

/// Collect every scope of this project's `code-index-v1/` whose root is no
/// Git worktree of the repository and has no scheduler owner.
///
/// A scheduler writes into its scope for as long as it is mounted, whether or
/// not its root is still on disk, so the owner of each scope whose root is
/// gone is retired, and its worker joined, before any proof is derived. An
/// owner that does not drain in time fails the pass and stays live in the
/// proof until a later tick joins it.
///
/// The liveness proof is derived twice, once to plan and again immediately
/// before quarantine, and the executor requires both to match exactly. A
/// scope whose recorded root is gone is collected at once; one whose root
/// still exists waits out the stranding age. A collection continues on the
/// short cadence: the files only the collected scopes named are left for the
/// next generation-retention pass.
///
/// A lease whose own worktree was removed can prove nothing and has nothing
/// to collect: the leases of the repository's remaining worktrees share this
/// store and collect the removed worktree's scope.
#[tracing::instrument(
    name = "daemon.git.maintenance.scope_reconciliation",
    level = "trace",
    skip_all
)]
pub async fn run_code_index_scope_reconciliation(
    lease: &ProjectStoreMaintenanceLeaseV1,
    schedulers: &CodeIndexSchedulerRegistryV1,
    observations: &StoreTelemetrySamplingRegistry,
    cancellation: &CancellationToken,
) -> MaintenanceTickOutcome {
    let store_root = code_index_scope_store_root(&lease.store_layout().data_root);
    if cancellation.is_cancelled() {
        return MaintenanceTickOutcome::Retry;
    }
    if matches!(
        std::fs::symlink_metadata(lease.project_root()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return MaintenanceTickOutcome::Complete;
    }
    let now_secs = match now_secs_i64() {
        Ok(now) => now,
        Err(failure) => return scope_reconciliation_failed(failure, None),
    };
    let project_root = lease.project_root().to_path_buf();
    if !retire_removed_scope_owners(schedulers, &store_root).await {
        return scope_reconciliation_failed("scope_owner_retirement_pending", None);
    }

    let legacy = match reconcile_collected_scope_heads(
        lease,
        schedulers,
        observations,
        cancellation,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            log_daemon_event(
                "retention_degraded",
                &[
                    ("pass", "removed_scope_graph_heads".to_owned()),
                    ("error", error.to_string()),
                ],
            );
            MaintenanceTickOutcome::Retry
        }
    };
    if !store_root.is_dir() {
        return legacy;
    }
    let mounted = scheduler_owner_roots(schedulers).await;
    let plan_root = store_root.clone();
    let plan_project_root = project_root.clone();
    let planned = native_runtime::spawn_blocking(move || {
        recover_scope_root_retention(&plan_root)
            .map_err(|error| ("scope_recovery_failed", Some(error)))?;
        let proof = scope_root_liveness_proof(&plan_project_root, &mounted)
            .map_err(|failure| (failure, None))?;
        plan_scope_root_retention_with_liveness_proof(
            &plan_root,
            proof,
            DEFAULT_STRANDED_SCOPE_MINIMUM_AGE_SECS,
            now_secs,
        )
        .map_err(|error| ("scope_plan_failed", Some(error)))
    })
    .await;
    let plan = match planned {
        Ok(Ok(plan)) => plan,
        Ok(Err((failure, error))) => return scope_reconciliation_failed(failure, error),
        Err(_) => return scope_reconciliation_failed("scope_task_panicked", None),
    };
    if plan.collectable_scopes.is_empty()
        && !plan
            .refused_scopes
            .iter()
            .any(|refused| refused.scope.root_missing)
    {
        return legacy;
    }

    // Drain one vanished scope per unit before quarantine removes its root
    // record and release receipts. Open readers preserve that durable backlog.
    let mut progress = observations.scope_reconciliation_progress(lease.project_root());
    let missing = || {
        plan.collectable_scopes.iter().chain(plan.refused_scopes.iter()
            .filter(|refused| refused.refusal == tracedecay_code_index_retention::code_index_generations::StrandedScopeRefusalV1::PendingGenerationRetention)
            .map(|refused| &refused.scope)).filter(|scope| scope.root_missing)
    };
    let removed_scope = missing()
        .filter(|scope| {
            progress
                .scope_after
                .as_ref()
                .is_none_or(|after| scope.scope_hash > *after)
        })
        .min_by(|left, right| left.scope_hash.cmp(&right.scope_hash))
        .or_else(|| missing().min_by(|left, right| left.scope_hash.cmp(&right.scope_hash)))
        .map(|scope| scope.scope_hash.clone());
    progress.scope_after = removed_scope.clone();
    observations.record_scope_reconciliation_progress(lease.project_root(), progress.clone());
    if let Some(hash) = &removed_scope {
        let Some(project_id) = lease
            .store_layout()
            .identity
            .project_id
            .as_deref()
            .and_then(|id| tracedecay_domain::ProjectId::new(id).ok())
        else {
            return scope_reconciliation_failed("scope_project_identity_missing", None);
        };
        match lease
            .store_runtime()
            .reconcile_removed_code_scope_graph_replays(
                project_id,
                lease.graph_db(),
                &store_root.join(hash),
                &project_root,
                schedulers,
                cancellation,
                progress.release_after.get(hash).cloned(),
            )
            .await
        {
            Ok((drained, continuation)) => {
                if let Some(continuation) = continuation {
                    progress.release_after.insert(hash.clone(), continuation);
                } else {
                    progress.release_after.remove(hash);
                }
                observations.record_scope_reconciliation_progress(lease.project_root(), progress);
                if !drained {
                    return MaintenanceTickOutcome::Continue(
                        MaintenanceContinuation::CodeGenerationRetention,
                    );
                }
            }
            Err(error) => {
                log_daemon_event(
                    "retention_degraded",
                    &[
                        ("pass", "removed_scope_graph_heads".to_owned()),
                        ("error", error.to_string()),
                    ],
                );
                return MaintenanceTickOutcome::Retry;
            }
        }
    }

    let mounted = scheduler_owner_roots(schedulers).await;
    let completed_at = tracedecay_contracts::clock::now_micros();
    let cancellation = cancellation.clone();
    let executed = native_runtime::spawn_blocking(move || {
        if cancellation.is_cancelled() {
            return Err(("scope_cancelled", None));
        }
        let revalidated = scope_root_liveness_proof(&project_root, &mounted)
            .map_err(|failure| (failure, None))?;
        if plan.liveness_proof() != Some(&revalidated) {
            return Err(("scope_liveness_changed", None));
        }
        // Generation draining changed the scope's inventory. Re-plan after our
        // own journaled mutations, without widening the unit to another scope.
        let mut plan = plan_scope_root_retention_with_liveness_proof(
            &store_root,
            revalidated.clone(),
            DEFAULT_STRANDED_SCOPE_MINIMUM_AGE_SECS,
            now_secs,
        )
        .map_err(|error| ("scope_replan_failed", Some(error)))?;
        if let Some(hash) = removed_scope {
            plan.collectable_scopes
                .retain(|scope| scope.scope_hash == hash && scope.root_missing);
        }
        execute_scope_root_retention(
            &store_root,
            plan,
            &revalidated,
            CodeGenerationRetentionModeV1::Apply,
            now_secs,
            completed_at,
        )
        .map_err(|error| ("scope_collection_failed", Some(error)))
    })
    .await;
    legacy.combine(match executed {
        Ok(Ok(report)) if report.collected_scopes.is_empty() => MaintenanceTickOutcome::Complete,
        Ok(Ok(report)) => {
            log_daemon_event(
                "retention_code_index_scopes",
                &[
                    ("store", "code-index-v1".to_owned()),
                    ("live_scopes", report.plan.live_scope_count.to_string()),
                    (
                        "collected_scopes",
                        report.collected_scopes.len().to_string(),
                    ),
                    (
                        "retained_immature_scopes",
                        report.plan.retained_immature_scopes.len().to_string(),
                    ),
                    (
                        "bytes_reclaimed",
                        report
                            .receipt
                            .as_ref()
                            .map_or(0, |receipt| receipt.reclaimed_bytes)
                            .to_string(),
                    ),
                ],
            );
            MaintenanceTickOutcome::Continue(MaintenanceContinuation::CodeGenerationRetention)
        }
        Ok(Err((failure, error))) => scope_reconciliation_failed(failure, error),
        Err(_) => scope_reconciliation_failed("scope_task_panicked", None),
    })
}

/// Retire and join the scheduler of every scope in `store_root` whose root is
/// gone from disk. `false` when one did not drain in time.
async fn retire_removed_scope_owners(
    schedulers: &CodeIndexSchedulerRegistryV1,
    store_root: &Path,
) -> bool {
    let removed = scheduler_owner_roots(schedulers)
        .await
        .into_iter()
        .filter(|root| {
            matches!(
                std::fs::symlink_metadata(root),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ) && scoped_code_index_store_root(store_root, root).is_dir()
        })
        .collect::<BTreeSet<_>>();
    removed.is_empty() || schedulers.retire_project_roots(&removed).await
}

/// Every root with a scheduler owner: mounted, or retired but still draining.
pub async fn scheduler_owner_roots(schedulers: &CodeIndexSchedulerRegistryV1) -> BTreeSet<PathBuf> {
    let mut roots = schedulers.mounted_roots().await;
    roots.extend(schedulers.retiring.lock().await.keys().cloned());
    roots
}

/// A refusal names why, so a fail-closed pass never reads as "nothing was
/// stranded".
fn scope_reconciliation_failed(
    failure: &str,
    error: Option<CodeGenerationRetentionErrorV1>,
) -> MaintenanceTickOutcome {
    let mut fields = vec![
        ("pass", "code_index_scopes".to_owned()),
        ("failure", failure.to_owned()),
    ];
    if let Some(error) = error {
        fields.push(("error", error.to_string()));
    }
    log_daemon_event("retention_degraded", &fields);
    MaintenanceTickOutcome::Retry
}

/// One indexed alias page crossed with one graph projection per unit. SQLite's
/// (`project_id`, rowid) index walk requires no all-alias materialization or sort.
async fn reconcile_collected_scope_heads(
    lease: &ProjectStoreMaintenanceLeaseV1,
    schedulers: &CodeIndexSchedulerRegistryV1,
    observations: &StoreTelemetrySamplingRegistry,
    cancellation: &CancellationToken,
) -> Result<MaintenanceTickOutcome, GraphDbError> {
    let error = |error: String| GraphDbError::unavailable(error);
    let Some(project) = lease.store_layout().identity.project_id.as_deref() else {
        return Err(GraphDbError::invalid("scope project identity missing"));
    };
    let mut progress = observations.scope_reconciliation_progress(lease.project_root());
    let snapshot = lease
        .profile_database()
        .read_snapshot()
        .await
        .map_err(|e| error(e.to_string()))?;
    let mut rows = snapshot
        .query(
            "SELECT rowid, alias_path FROM project_aliases
         WHERE project_id = ?1 AND rowid > ?2 ORDER BY rowid LIMIT 33",
            params![project, progress.alias_after],
        )
        .await
        .map_err(|e| error(e.to_string()))?;
    let mut aliases = Vec::new();
    while let Some(row) = rows.next().await.map_err(|e| error(e.to_string()))? {
        aliases.push((
            row.get::<i64>(0).map_err(|e| error(e.to_string()))?,
            row.get::<String>(1).map_err(|e| error(e.to_string()))?,
        ));
    }
    drop(rows);
    drop(snapshot);
    let more_aliases = aliases.len() > 32;
    if more_aliases {
        aliases.pop();
    }
    let last_alias = aliases.last().map_or(progress.alias_after, |(row, _)| *row);
    let roots = aliases
        .into_iter()
        .map(|(_, path)| PathBuf::from(path))
        .filter(|path| path.is_absolute())
        .collect::<Vec<_>>();
    let (next, retained) = lease
        .store_runtime()
        .reconcile_removed_code_graph_head_page(
            tracedecay_domain::ProjectId::new(project).map_err(|e| error(e.to_string()))?,
            lease.graph_db(),
            &roots,
            lease.project_root(),
            schedulers,
            progress.projection_after,
            cancellation,
        )
        .await?;
    let more = next.is_some() || more_aliases;
    progress.retained_in_census |= retained;
    let retained = progress.retained_in_census;
    progress.projection_after = next;
    if progress.projection_after.is_none() {
        progress.alias_after = if more_aliases { last_alias } else { 0 };
        if !more_aliases {
            progress.retained_in_census = false;
        }
    }
    observations.record_scope_reconciliation_progress(lease.project_root(), progress);
    Ok(if more || retained {
        MaintenanceTickOutcome::Continue(MaintenanceContinuation::CodeGenerationRetention)
    } else {
        MaintenanceTickOutcome::Complete
    })
}
