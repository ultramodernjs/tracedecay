//! Daemon Hook V2 replay consumer.
//!
//! Owns the per-project sweep, delivery-receipt drain, and pending-work
//! admission. Host-spool replay itself lives in `tracedecay-hooks` and is
//! invoked with an already-admitted spool plus the project's wire identity.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use futures_util::FutureExt;
use tracedecay_contracts::ApplicationContractError;
use tracedecay_contracts::retrieval::{
    StatusHookReplayFailureV1, StatusHookReplaySpoolV1, StatusHookReplayV1,
};
use tracedecay_domain::NativeHostIdentityV1;
use tracedecay_domain::UtcMicros;
use tracedecay_domain::canonical_text::encode_lowercase_hex;
use tracedecay_global_db::DeliverySourceReceiptReadV1;
use tracedecay_hooks::{
    HookDeliveryReceiptSpoolV1, HookDeliverySourceReceiptV1, HookReplayAdmissionOutcomeV1,
    HookReplayPassReportV1, HookSpoolConfigV1, HookSpoolV1,
    admit_replayed_envelope_with_authoritative_session, drain_host_spool_once, hook_v2_spool_root,
    published_hook_scope_binding,
};

use tracedecay_mcp::handlers::hook_runtime::{
    HookV2AdmissionOutcomeV1, admit_hook_v2_envelope,
    admit_hook_v2_replayed_envelope_with_lifecycle, hook_v2_pending_work_count,
    hook_v2_pending_work_envelopes,
};

mod spool_opener;
mod spool_watch;

#[cfg(not(unix))]
pub(in crate::daemon) use spool_opener::PortableSpoolOpenerOwners;
pub(in crate::daemon) use spool_opener::spawn_spooled_hook_opener;

/// The longest a retained record or receipt waits for its next delivery
/// attempt. Every append and receipt publication wakes the drain, and startup
/// opens every project holding either, so this sweep only retries work a pass
/// retained (for example a settlement the authority refused), a spool a pass
/// could not drain, or a wake the spool watch could not deliver.
const REPLAY_INTERVAL: Duration = Duration::from_secs(30);

/// Whether a spool root is absent. Only a missing root is an empty spool;
/// any other unreadable state is the drain's failure to report.
fn spool_root_absent(root: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Windows collapses ENOTDIR into ERROR_PATH_NOT_FOUND, so a path
            // through a regular file also reports NotFound; absence is only
            // honest once no existing ancestor is a non-directory.
            let mut ancestor = root.parent();
            while let Some(path) = ancestor {
                match std::fs::symlink_metadata(path) {
                    Ok(meta) if !meta.is_dir() => {
                        return Err(format!(
                            "hook spool root could not be inspected: {} is not a directory",
                            path.display()
                        ));
                    }
                    Ok(_) => return Ok(true),
                    Err(_) => ancestor = path.parent(),
                }
            }
            Ok(true)
        }
        Err(error) => Err(format!("hook spool root could not be inspected: {error}")),
    }
}

/// The cause a pending-work redrive left its producer work owed, or `None`
/// when the producer work is known complete.
fn unresolved_pending_work(outcome: &HookV2AdmissionOutcomeV1) -> Option<&'static str> {
    match outcome {
        HookV2AdmissionOutcomeV1::Admitted { orchestration, .. } => Some(match orchestration {
            tracedecay_daemon_service::HookOrchestrationAdmissionV1::Enqueued => {
                "is queued for producer execution"
            }
            tracedecay_daemon_service::HookOrchestrationAdmissionV1::Backpressured => {
                "producer execution was backpressured"
            }
            tracedecay_daemon_service::HookOrchestrationAdmissionV1::Unavailable => {
                "producer execution was unavailable"
            }
            tracedecay_daemon_service::HookOrchestrationAdmissionV1::UnsupportedTrigger => {
                "producer execution has no supported trigger"
            }
        }),
        HookV2AdmissionOutcomeV1::ExactDuplicate { .. } => None,
        HookV2AdmissionOutcomeV1::Conflict => Some("conflicted with an earlier admission"),
        HookV2AdmissionOutcomeV1::CatchupRequired => Some("requires binding catch-up"),
        HookV2AdmissionOutcomeV1::Backpressured => Some("was backpressured"),
        HookV2AdmissionOutcomeV1::Unavailable => Some("was unavailable"),
    }
}

fn replay_admission_outcome(outcome: HookV2AdmissionOutcomeV1) -> HookReplayAdmissionOutcomeV1 {
    match outcome {
        HookV2AdmissionOutcomeV1::Admitted { .. } => HookReplayAdmissionOutcomeV1::Admitted,
        HookV2AdmissionOutcomeV1::ExactDuplicate { .. } => {
            HookReplayAdmissionOutcomeV1::ExactDuplicate
        }
        HookV2AdmissionOutcomeV1::Conflict => HookReplayAdmissionOutcomeV1::Conflict,
        HookV2AdmissionOutcomeV1::CatchupRequired => HookReplayAdmissionOutcomeV1::CatchupRequired,
        HookV2AdmissionOutcomeV1::Backpressured => HookReplayAdmissionOutcomeV1::Backpressured,
        HookV2AdmissionOutcomeV1::Unavailable => HookReplayAdmissionOutcomeV1::Unavailable,
    }
}

/// Settles and releases one host's delivery receipts. The drain shares the
/// spool with hook callbacks, which write it while the daemon is down; a
/// drain woken by a publication waits out the publishing writer. A receipt
/// that is not settled stays durable for the next sweep, and the failure
/// names its cause. `Ok(true)` means a full batch settled and receipts
/// remain behind it.
#[tracing::instrument(name = "daemon.hook_replay.receipt_drain", level = "trace", skip_all)]
async fn drain_hook_delivery_receipts(
    data_root: &Path,
    host: NativeHostIdentityV1,
    authority: &tracedecay_application::observability::DeliverySettlementAuthorityV1,
) -> Result<bool, String> {
    let root = tracedecay_hooks::hook_delivery_receipt_spool_root(data_root, host);
    if spool_root_absent(&root)? {
        return Ok(false);
    }
    let batch = usize::from(tracedecay_hooks::MAX_REPLAY_BATCH_RECORDS);
    let open = || {
        HookDeliveryReceiptSpoolV1::open(&root, tracedecay_hooks::HOOK_SYNCHRONOUS_BUDGET)
            .map_err(|error| error.to_string())
    };
    let receipts = open()?.pending(batch).map_err(|error| error.to_string())?;
    let full_batch = receipts.len() >= batch;

    let mut settled = Vec::new();
    let mut unsettled = None;
    for receipt in receipts {
        let receipt_hex = encode_lowercase_hex(&receipt.receipt_id);
        let source_receipt_ref = format!("hook:delivery:{receipt_hex}");
        let settlement = async {
            // A retry after spool acknowledgement has fresh wall-clock evidence
            // but the same logical key. Replay the durable settlement, keeping
            // exact database identity and its first timestamps authoritative.
            if let Some(DeliverySourceReceiptReadV1::Settled(stored)) =
                authority.attempt_for_receipt(&source_receipt_ref).await?
            {
                let stored = HookDeliverySourceReceiptV1::new(stored)
                    .map_err(|error| ApplicationContractError::Domain(error.to_string()))?;
                if !stored.same_identity(&receipt) {
                    return Err(ApplicationContractError::Domain(
                        "hook delivery source receipt identity conflict".to_owned(),
                    ));
                }
                return authority.settle(&stored.settlement).await.map(drop);
            }
            authority
                .begin_receipted(&receipt.settlement.attempt, &source_receipt_ref)
                .await?;
            authority.settle(&receipt.settlement).await.map(drop)
        }
        .await;
        match settlement {
            // A successful durable settlement is enough to release the source
            // receipt.  Early recipients legitimately return `observability: None`
            // while their fan-out census is partial; only the final recipient
            // emits the complete owner fact.  Retaining those partial files would
            // replay immutable attempts forever after the database already owns
            // them.
            Ok(()) => settled.push(receipt.receipt_id),
            Err(error) => {
                unsettled.get_or_insert_with(|| format!("delivery settlement failed: {error}"));
            }
        }
    }
    if !settled.is_empty() {
        open()?
            .acknowledge_many(&settled)
            .map_err(|error| error.to_string())?;
    }
    if let Some(cause) = unsettled {
        return Err(cause);
    }
    if !full_batch {
        return Ok(false);
    }
    HookDeliveryReceiptSpoolV1::has_receipts(&root).map_err(|error| error.to_string())
}

/// What one sweep over every host left behind.
#[derive(Default)]
struct HookReplaySweepV1 {
    /// A pass settled a full batch of records or receipts, so the next sweep
    /// runs at once.
    more_pending: bool,
    scope_pending: bool,
    failures: Vec<StatusHookReplayFailureV1>,
}

/// Hosts retained during this run of immediate bounded batches wait for the
/// interval or a fresh append, while healthy peers continue draining.
#[derive(Clone)]
struct DeferredHostReplay {
    failures: Vec<StatusHookReplayFailureV1>,
    scope_pending: bool,
}

impl DeferredHostReplay {
    fn defers_lane(&self, spool: StatusHookReplaySpoolV1) -> bool {
        self.failures.iter().any(|failure| failure.spool == spool)
    }
}

impl HookReplaySweepV1 {
    fn fail(&mut self, host: NativeHostIdentityV1, spool: StatusHookReplaySpoolV1, cause: String) {
        tracing::warn!(host = host.hook_key(), ?spool, %cause, "hook spool drain failed");
        self.failures
            .push(StatusHookReplayFailureV1 { host, spool, cause });
    }
}

#[tracing::instrument(name = "daemon.hook_replay.sweep", level = "trace", skip_all)]
async fn drain_all_hosts(
    graph: &Arc<tracedecay_project::project::TraceDecay>,
    data_root: &Path,
    delivery_settlements: &tracedecay_application::observability::DeliverySettlementAuthorityV1,
    project_sessions: &tracedecay_global_db::RegisteredGlobalDb,
    background_cpu: &Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
    deferred_hosts: &mut BTreeMap<NativeHostIdentityV1, DeferredHostReplay>,
) -> HookReplaySweepV1 {
    let mut sweep = HookReplaySweepV1::default();
    renew_replay_bindings(graph, &mut sweep).await;
    let project_id =
        tracedecay_agent_hosts::hooks::hook_project_id_for_layout(graph.hook_store_layout());
    // Worktree identity needs only the hook runtime's scope resolver; the
    // profile is the graph's own.
    let worktree_id = graph
        .profile_root()
        .map(tracedecay_runtime_core::config::ProfileRoot::new)
        .and_then(|profile| {
            tracedecay_agent_hosts::hooks::hook_worktree_id_for_layout(
                &crate::hook_runtime(profile),
                graph.hook_store_layout(),
            )
        })
        .map_err(|error| format!("hook worktree identity is unavailable: {error}"));
    for host in tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS {
        let deferred = deferred_hosts.get(host).cloned();
        if let Some(deferred) = &deferred {
            sweep.failures.extend(deferred.failures.iter().cloned());
            sweep.scope_pending |= deferred.scope_pending;
        }
        let lane_deferred = |spool| {
            deferred
                .as_ref()
                .is_some_and(|deferred| deferred.defers_lane(spool))
        };
        let now = hook_replay_now();
        if !lane_deferred(StatusHookReplaySpoolV1::DeliveryReceipts) {
            match drain_hook_delivery_receipts(data_root, *host, delivery_settlements).await {
                Ok(more) => sweep.more_pending |= more,
                Err(cause) => sweep.fail(*host, StatusHookReplaySpoolV1::DeliveryReceipts, cause),
            }
        }
        let pending_cause = if lane_deferred(StatusHookReplaySpoolV1::PendingWork) {
            None
        } else {
            match &worktree_id {
                Ok(worktree_id) => {
                    Box::pin(redrive_pending_work(
                        graph,
                        data_root,
                        *host,
                        project_id,
                        *worktree_id,
                        now,
                        &mut sweep,
                    ))
                    .await
                }
                Err(cause) => {
                    sweep.fail(*host, StatusHookReplaySpoolV1::PendingWork, cause.clone());
                    None
                }
            }
        };
        let report = if lane_deferred(StatusHookReplaySpoolV1::Records)
            || deferred
                .as_ref()
                .is_some_and(|deferred| deferred.scope_pending)
        {
            None
        } else {
            match Box::pin(drain_admitted_host_spool(
                *host,
                project_id,
                &worktree_id,
                now,
                graph,
                project_sessions,
                background_cpu,
            ))
            .await
            {
                Ok(report) => report,
                Err(cause) => {
                    sweep.fail(*host, StatusHookReplaySpoolV1::Records, cause);
                    None
                }
            }
        };
        if let Some(report) = report {
            note_host_replay_progress(&mut sweep, *host, &report, data_root, graph.project_root());
        }
        // Admission can acknowledge the transport while producer execution is
        // still queued. Only the durable work ledger proves completion.
        if let Ok(worktree_id) = &worktree_id {
            note_remaining_pending_work(
                data_root,
                *host,
                project_id,
                *worktree_id,
                hook_replay_now(),
                &mut sweep,
                pending_cause,
            );
        }
        update_deferred_host(deferred_hosts, *host, &sweep, report, deferred);
    }
    sweep
}

async fn renew_replay_bindings(
    graph: &Arc<tracedecay_project::project::TraceDecay>,
    sweep: &mut HookReplaySweepV1,
) {
    let graph = Arc::clone(graph);
    let renewed = tracedecay_runtime_core::native_runtime::spawn_owned_blocking(move || {
        graph.renew_hook_bindings(hook_replay_now())
    })
    .await
    .and_then(|result| result.map_err(|error| error.to_string()));
    match renewed {
        Ok(failures) => {
            for (host, cause) in failures {
                sweep.fail(
                    host,
                    StatusHookReplaySpoolV1::Records,
                    format!("Hook binding renewal failed: {cause}"),
                );
            }
        }
        Err(error) => {
            for host in tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS {
                sweep.fail(*host, StatusHookReplaySpoolV1::Records, error.to_string());
            }
        }
    }
}

fn note_host_replay_progress(
    sweep: &mut HookReplaySweepV1,
    host: NativeHostIdentityV1,
    report: &HookReplayPassReportV1,
    data_root: &Path,
    project_root: &Path,
) {
    sweep.scope_pending |= report.scope_deferred > 0;
    if report.committed > 0 || report.duplicates > 0 || report.tombstoned > 0 {
        spool_watch::wake_peer_consumers(data_root, project_root);
    }
    note_replay_report(sweep, host, report);
    match HookSpoolV1::has_records(&hook_v2_spool_root(data_root, host)) {
        Ok(true) if report.binding_unavailable || report.retained > 0 => {}
        Ok(true) if !report.more_in_scope && report.scope_deferred > 0 => {
            sweep.scope_pending = true;
        }
        Ok(true) if report.committed > 0 || report.duplicates > 0 || report.tombstoned > 0 => {
            sweep.more_pending = true;
        }
        Ok(true) => sweep.fail(
            host,
            StatusHookReplaySpoolV1::Records,
            "pending records await a replay batch".to_owned(),
        ),
        Ok(false) => {}
        Err(error) => {
            sweep.fail(host, StatusHookReplaySpoolV1::Records, error.to_string());
        }
    }
}

fn update_deferred_host(
    deferred_hosts: &mut BTreeMap<NativeHostIdentityV1, DeferredHostReplay>,
    host: NativeHostIdentityV1,
    sweep: &HookReplaySweepV1,
    report: Option<HookReplayPassReportV1>,
    deferred: Option<DeferredHostReplay>,
) {
    let failures = sweep
        .failures
        .iter()
        .filter(|failure| failure.host == host)
        .cloned()
        .collect::<Vec<_>>();
    let scope_pending = report
        .is_some_and(|report| report.scope_deferred > 0 && !report.more_in_scope)
        || deferred.is_some_and(|deferred| deferred.scope_pending);
    if !failures.is_empty() || scope_pending {
        deferred_hosts.insert(
            host,
            DeferredHostReplay {
                failures,
                scope_pending,
            },
        );
    } else {
        deferred_hosts.remove(&host);
    }
}

fn note_replay_report(
    sweep: &mut HookReplaySweepV1,
    host: NativeHostIdentityV1,
    report: &HookReplayPassReportV1,
) {
    if report.binding_unavailable {
        sweep.fail(
            host,
            StatusHookReplaySpoolV1::Records,
            "pending records have no current authorized Hook binding".to_owned(),
        );
    } else if report.retained > 0 {
        sweep.fail(
            host,
            StatusHookReplaySpoolV1::Records,
            format!(
                "{} record(s) retained after unavailable or backpressured admission",
                report.retained
            ),
        );
    }
}

fn note_remaining_pending_work(
    data_root: &Path,
    host: NativeHostIdentityV1,
    project_id: Option<[u8; 16]>,
    worktree_id: [u8; 16],
    now: UtcMicros,
    sweep: &mut HookReplaySweepV1,
    cause: Option<&str>,
) {
    sweep.failures.retain(|failure| {
        failure.host != host || failure.spool != StatusHookReplaySpoolV1::PendingWork
    });
    match hook_v2_pending_work_envelopes(data_root, host, now) {
        Ok(pending) => {
            sweep.scope_pending |= pending
                .iter()
                .any(|envelope| envelope.worktree_id != worktree_id);
            let owed = pending
                .into_iter()
                .filter(|envelope| {
                    project_id.is_none_or(|project_id| envelope.project_id == project_id)
                        && envelope.worktree_id == worktree_id
                })
                .count();
            if owed > 0 {
                sweep.fail(
                    host,
                    StatusHookReplaySpoolV1::PendingWork,
                    format!(
                        "{owed} pending producer work item(s) stayed owed; {}",
                        cause.unwrap_or("execution has not completed")
                    ),
                );
            }
        }
        Err(error) => sweep.fail(
            host,
            StatusHookReplaySpoolV1::PendingWork,
            error.to_string(),
        ),
    }
}

/// Redrives the producer work `host`'s admission ledger still owes. Work a
/// redrive cannot admit stays owed, and the sweep names it.
async fn redrive_pending_work(
    graph: &tracedecay_project::project::TraceDecay,
    data_root: &Path,
    host: NativeHostIdentityV1,
    project_id: Option<[u8; 16]>,
    worktree_id: [u8; 16],
    now: UtcMicros,
    sweep: &mut HookReplaySweepV1,
) -> Option<&'static str> {
    let pending_work = match hook_v2_pending_work_envelopes(data_root, host, now) {
        Ok(pending_work) => pending_work,
        Err(error) => {
            sweep.fail(
                host,
                StatusHookReplaySpoolV1::PendingWork,
                error.to_string(),
            );
            return None;
        }
    };
    let mut owed_cause = None;
    for envelope in pending_work {
        if project_id.is_some_and(|project_id| envelope.project_id != project_id)
            || envelope.worktree_id != worktree_id
        {
            continue;
        }
        // Owed work the daemon cannot admit now stays in the ledger and
        // is redriven by the next sweep.
        let outcome = admit_replayed_envelope_with_authoritative_session(
            envelope,
            None,
            |project_id, worktree_id, protected_session_id| async move {
                tracedecay_daemon_service::context_scout_lifecycle::lookup_registered_context_scout_native_session(
                    project_id,
                    worktree_id,
                    protected_session_id,
                )
                .await
            },
            |envelope, native_session_id| async move {
                admit_hook_v2_envelope(graph, &envelope, native_session_id, hook_replay_now())
                    .await
            },
        )
        .await;
        if let Some(cause) = unresolved_pending_work(&outcome) {
            owed_cause.get_or_insert(cause);
        }
    }
    owed_cause
}

/// Replays one host's spooled records, or `None` when it holds none.
async fn drain_admitted_host_spool(
    host: NativeHostIdentityV1,
    project_id: Option<[u8; 16]>,
    worktree_id: &Result<[u8; 16], String>,
    now: UtcMicros,
    graph: &tracedecay_project::project::TraceDecay,
    project_sessions: &tracedecay_global_db::RegisteredGlobalDb,
    background_cpu: &Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
) -> Result<Option<HookReplayPassReportV1>, String> {
    let data_root = &graph.hook_store_layout().data_root;
    let root = hook_v2_spool_root(data_root, host);
    // An absent/empty records file needs neither recovery nor replay, so do
    // not acquire the cross-process writer lease merely to prove it again.
    // A hook that appends after this observation publishes its record and
    // wakes the next sweep; non-empty spools still take the lease before
    // interpreting acknowledgement or recovery state.
    if spool_root_absent(&root)?
        || !HookSpoolV1::has_records(&root).map_err(|error| error.to_string())?
    {
        return Ok(None);
    }
    let project_id =
        project_id.ok_or_else(|| "the project layout has no hook project identity".to_owned())?;
    let worktree_id = worktree_id.clone()?;
    let binding = published_hook_scope_binding(data_root, worktree_id, host, now);
    let pass = Box::pin(drain_host_spool_once(
            &root,
            HookSpoolConfigV1::stock(host),
            project_id,
            binding.as_ref(),
            now,
            |envelope, native_lifecycle| async move {
                let lifecycle_for_admission = native_lifecycle.clone();
                replay_admission_outcome(
                    admit_replayed_envelope_with_authoritative_session(
                        envelope,
                        native_lifecycle,
                        |project_id, worktree_id, protected_session_id| async move {
                            tracedecay_daemon_service::context_scout_lifecycle::lookup_registered_context_scout_native_session(
                                project_id,
                                worktree_id,
                                protected_session_id,
                            )
                            .await
                        },
                        |envelope, native_session_id| async move {
                            admit_hook_v2_replayed_envelope_with_lifecycle(
                                graph,
                                &envelope,
                                native_session_id,
                                lifecycle_for_admission,
                                project_sessions,
                                background_cpu,
                                hook_replay_now(),
                            )
                            .await
                        },
                    )
                    .await,
                )
            },
        ))
        .await;
    pass.map(Some).map_err(|error| error.to_string())
}

fn hook_replay_now() -> UtcMicros {
    UtcMicros(
        tracedecay_runtime_core::tracedecay::saturating_utc_now()
            .0
            .max(1),
    )
}

struct RegisteredReplayConsumer {
    graph: Weak<tracedecay_project::project::TraceDecay>,
    delivery_settlements:
        Weak<tracedecay_application::observability::DeliverySettlementAuthorityV1>,
    wake: Arc<tokio::sync::Notify>,
    task: Option<tracedecay_runtime_core::native_runtime::NativeTask<()>>,
    /// The failures of the last finished sweep; `None` while batches remain.
    last_sweep: Option<Vec<StatusHookReplayFailureV1>>,
}

type ReplayScope = (PathBuf, PathBuf);

fn registered_replay_roots() -> &'static StdMutex<BTreeMap<ReplayScope, RegisteredReplayConsumer>> {
    static ROOTS: OnceLock<StdMutex<BTreeMap<ReplayScope, RegisteredReplayConsumer>>> =
        OnceLock::new();
    ROOTS.get_or_init(|| StdMutex::new(BTreeMap::new()))
}

/// Every registered worktree sharing this project's transport contributes its
/// latest replay state. One drained worktree cannot hide a peer's owed work.
pub(crate) fn hook_replay_status(data_root: &Path) -> StatusHookReplayV1 {
    let roots = registered_replay_roots()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut owned = false;
    let mut starting = false;
    let mut failures = Vec::new();
    for (_, consumer) in roots.iter().filter(|((root, _), _)| root == data_root) {
        owned = true;
        match &consumer.last_sweep {
            None => starting = true,
            Some(current) => failures.extend(current.iter().cloned()),
        }
    }
    drop(roots);
    if !owned {
        StatusHookReplayV1::Unowned
    } else if !failures.is_empty() {
        StatusHookReplayV1::Failed { failures }
    } else if starting {
        StatusHookReplayV1::Starting
    } else {
        current_hook_replay_work(data_root)
    }
}

/// A finished sweep cannot certify an append that arrived afterward. Verify
/// current canonical summaries before publishing an empty-success state.
fn current_hook_replay_work(data_root: &Path) -> StatusHookReplayV1 {
    let mut sweep = HookReplaySweepV1::default();
    let mut transport_pending = false;
    for host in tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS {
        match HookSpoolV1::has_records(&hook_v2_spool_root(data_root, *host)) {
            Ok(pending) => transport_pending |= pending,
            Err(error) => sweep.fail(*host, StatusHookReplaySpoolV1::Records, error.to_string()),
        }
        match HookDeliveryReceiptSpoolV1::has_receipts(
            &tracedecay_hooks::hook_delivery_receipt_spool_root(data_root, *host),
        ) {
            Ok(pending) => transport_pending |= pending,
            Err(error) => sweep.fail(
                *host,
                StatusHookReplaySpoolV1::DeliveryReceipts,
                error.to_string(),
            ),
        }
        match hook_v2_pending_work_count(data_root, *host) {
            Ok(pending) if pending > 0 => sweep.fail(
                *host,
                StatusHookReplaySpoolV1::PendingWork,
                format!(
                    "{pending} pending producer work item(s) stayed owed; execution has not completed"
                ),
            ),
            Ok(_) => {}
            Err(error) => sweep.fail(
                *host,
                StatusHookReplaySpoolV1::PendingWork,
                error.to_string(),
            ),
        }
    }
    if !sweep.failures.is_empty() {
        StatusHookReplayV1::Failed {
            failures: sweep.failures,
        }
    } else if transport_pending {
        StatusHookReplayV1::Starting
    } else {
        StatusHookReplayV1::Drained
    }
}

fn publish_sweep(
    scope: &ReplayScope,
    graph: &Weak<tracedecay_project::project::TraceDecay>,
    failures: Vec<StatusHookReplayFailureV1>,
    more_pending: bool,
) {
    let mut roots = registered_replay_roots()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Some(registered) = roots.get_mut(scope)
        && Weak::ptr_eq(&registered.graph, graph)
    {
        registered.last_sweep = if more_pending && failures.is_empty() {
            None
        } else {
            Some(failures)
        };
    }
}

#[cfg(test)]
pub(crate) fn hook_v2_replay_consumer_registered(data_root: &Path) -> bool {
    registered_replay_roots().lock().is_ok_and(|roots| {
        roots.iter().any(|((root, _), consumer)| {
            root == data_root
                && consumer.graph.upgrade().is_some()
                && consumer.delivery_settlements.upgrade().is_some()
        })
    })
}

/// Consume wakes at batch boundaries too, so a continuously busy healthy lane
/// cannot postpone a retained lane beyond its ordinary retry interval.
fn deferred_retry_due(wake: &tokio::sync::Notify, retry_at: &mut std::time::Instant) -> bool {
    if std::time::Instant::now() >= *retry_at || wake.notified().now_or_never().is_some() {
        *retry_at = std::time::Instant::now() + REPLAY_INTERVAL;
        true
    } else {
        false
    }
}

/// Start one consumer per exact project/worktree open, replacing only its
/// predecessor. Runtime refusal leaves that predecessor running.
pub(crate) fn register_hook_v2_replay_consumer(
    graph: Arc<tracedecay_project::project::TraceDecay>,
    delivery_settlements: Arc<tracedecay_application::observability::DeliverySettlementAuthorityV1>,
    project_sessions: tracedecay_global_db::RegisteredGlobalDbLeaseV1,
    background_cpu: Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
) -> ReplayConsumerStart {
    let Ok(mut roots) = registered_replay_roots().lock() else {
        return ReplayConsumerStart::RegistryPoisoned;
    };
    install_hook_v2_replay_consumer(
        &mut roots,
        graph,
        delivery_settlements,
        project_sessions,
        background_cpu,
    )
}

/// Transfer only the consumer owned by the graph this server actually replaced.
/// Existing readers may retain that graph; its retirement cannot detach the
/// successor's watch or reclaim the successor's publication receipts.
pub(crate) fn transfer_hook_v2_replay_consumer(
    previous: &Arc<tracedecay_project::project::TraceDecay>,
    successor: Arc<tracedecay_project::project::TraceDecay>,
    project_sessions: tracedecay_global_db::RegisteredGlobalDbLeaseV1,
    background_cpu: Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
) -> bool {
    if previous.is_read_only()
        || successor.is_read_only()
        || previous.project_root() != successor.project_root()
        || previous.hook_store_layout().data_root != successor.hook_store_layout().data_root
        || previous.hook_store_layout().identity.project_id
            != successor.hook_store_layout().identity.project_id
    {
        return false;
    }
    let scope = (
        previous.hook_store_layout().data_root.clone(),
        previous.project_root().to_path_buf(),
    );
    let Ok(mut roots) = registered_replay_roots().lock() else {
        return false;
    };
    let Some(consumer) = roots.get(&scope) else {
        return false;
    };
    if !Weak::ptr_eq(&consumer.graph, &Arc::downgrade(previous)) {
        return false;
    }
    let Some(delivery_settlements) = consumer.delivery_settlements.upgrade() else {
        return false;
    };
    matches!(
        install_hook_v2_replay_consumer(
            &mut roots,
            successor,
            delivery_settlements,
            project_sessions,
            background_cpu,
        ),
        ReplayConsumerStart::Started
    )
}

fn install_hook_v2_replay_consumer(
    roots: &mut BTreeMap<ReplayScope, RegisteredReplayConsumer>,
    graph: Arc<tracedecay_project::project::TraceDecay>,
    delivery_settlements: Arc<tracedecay_application::observability::DeliverySettlementAuthorityV1>,
    project_sessions: tracedecay_global_db::RegisteredGlobalDbLeaseV1,
    background_cpu: Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
) -> ReplayConsumerStart {
    let data_root = graph.hook_store_layout().data_root.clone();
    let project_root = graph.project_root().to_path_buf();
    let scope = (data_root.clone(), project_root.clone());
    let graph = Arc::downgrade(&graph);
    let delivery_settlements = Arc::downgrade(&delivery_settlements);
    if roots.get(&scope).is_some_and(|consumer| {
        Weak::ptr_eq(&consumer.graph, &graph)
            && consumer.graph.upgrade().is_some()
            && consumer.delivery_settlements.upgrade().is_some()
    }) {
        return ReplayConsumerStart::AlreadyRunning;
    }
    let wake = Arc::new(tokio::sync::Notify::new());
    let task_wake = Arc::clone(&wake);
    let (start, started) = tokio::sync::oneshot::channel::<()>();
    let task_scope = scope.clone();
    let task_graph = graph.clone();
    let task_delivery_settlements = delivery_settlements.clone();
    let task_project_sessions = project_sessions;
    let task_background_cpu = background_cpu;
    let consumer = async move {
        if started.await.is_err() {
            return;
        }
        let wake = task_wake;
        let mut deferred_hosts = BTreeMap::new();
        let mut retry_at = std::time::Instant::now() + REPLAY_INTERVAL;
        loop {
            if deferred_retry_due(&wake, &mut retry_at) {
                deferred_hosts.clear();
            }
            let (Some(graph_owner), Some(delivery_settlements)) =
                (task_graph.upgrade(), task_delivery_settlements.upgrade())
            else {
                break;
            };
            let sweep = Box::pin(drain_all_hosts(
                &graph_owner,
                &task_scope.0,
                delivery_settlements.as_ref(),
                &task_project_sessions,
                &task_background_cpu,
                &mut deferred_hosts,
            ))
            .await;
            drop(graph_owner);
            drop(delivery_settlements);
            let retry_immediately = sweep.more_pending;
            publish_sweep(
                &task_scope,
                &task_graph,
                sweep.failures,
                sweep.more_pending || sweep.scope_pending,
            );
            if retry_immediately {
                tokio::task::yield_now().await;
                continue;
            }
            // Retained records and failed spools wait at most this interval
            // for their next attempt; a hook append wakes the drain sooner. Keep
            // the pacing WAIT separate from sweep WORK.
            let timer = tracing::Instrument::instrument(
                async {
                    tokio::select! {
                        slept = tracedecay_runtime_core::native_runtime::sleep_until(retry_at) => slept,
                        () = wake.notified() => Ok(()),
                    }
                },
                tracing::trace_span!("daemon.hook_replay.interval_wait"),
            )
            .await;
            if let Err(error) = timer {
                tracing::error!(event = "hook_replay_timer_unavailable", %error);
                break;
            }
            deferred_hosts.clear();
            retry_at = std::time::Instant::now() + REPLAY_INTERVAL;
        }
        if let Ok(mut roots) = registered_replay_roots().lock()
            && roots
                .get(&task_scope)
                .is_some_and(|registered| Weak::ptr_eq(&registered.graph, &task_graph))
        {
            spool_watch::detach_consumer(&task_scope.0, &task_scope.1, &wake);
            roots.remove(&task_scope);
        }
    };
    let task = match tracedecay_runtime_core::native_runtime::NativeTask::spawn(consumer) {
        Ok(task) => task,
        Err(error) => {
            tracing::warn!(%error, data_root = %data_root.display(), "hook replay consumer not admitted");
            return ReplayConsumerStart::RuntimeUnavailable;
        }
    };
    if let Some(previous) = roots.remove(&scope) {
        if let Some(task) = previous.task {
            task.abort();
        }
        spool_watch::detach_consumer(&data_root, &project_root, &previous.wake);
    }
    spool_watch::attach_consumer(&data_root, &project_root, Arc::clone(&wake));
    roots.insert(
        scope,
        RegisteredReplayConsumer {
            graph,
            delivery_settlements,
            wake,
            task: Some(task),
            last_sweep: None,
        },
    );
    let _ = start.send(());
    ReplayConsumerStart::Started
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayConsumerStart {
    Started,
    AlreadyRunning,
    RuntimeUnavailable,
    RegistryPoisoned,
}

/// Stop and join the exact project replay consumer before releasing its graph.
pub(crate) async fn shutdown_hook_v2_replay_consumer(data_root: &Path) {
    let consumers = {
        let mut roots = registered_replay_roots()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let scopes = roots
            .keys()
            .filter(|(root, _)| root == data_root)
            .cloned()
            .collect::<Vec<_>>();
        scopes
            .into_iter()
            .filter_map(|scope| {
                roots.remove(&scope).inspect(|consumer| {
                    spool_watch::detach_consumer(&scope.0, &scope.1, &consumer.wake);
                })
            })
            .collect::<Vec<_>>()
    };
    for consumer in consumers {
        if let Some(task) = consumer.task {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Retiring an old server cannot stop a sibling or its reopened successor.
pub(crate) async fn shutdown_hook_v2_replay_consumer_for_graph(
    graph: &Arc<tracedecay_project::project::TraceDecay>,
) {
    let scope = (
        graph.hook_store_layout().data_root.clone(),
        graph.project_root().to_path_buf(),
    );
    let owner = Arc::downgrade(graph);
    let consumer = {
        let mut roots = registered_replay_roots()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if roots
            .get(&scope)
            .is_some_and(|consumer| Weak::ptr_eq(&consumer.graph, &owner))
        {
            roots.remove(&scope)
        } else {
            None
        }
    };
    if let Some(consumer) = consumer {
        spool_watch::detach_consumer(&scope.0, &scope.1, &consumer.wake);
        if let Some(task) = consumer.task {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Join only the retired graph's registration; a reopened successor and its
/// sibling worktrees keep their own wakes and session clients.
pub(crate) async fn retire_hook_v2_replay_consumer(
    data_root: &Path,
    owner: &Weak<tracedecay_project::project::TraceDecay>,
) {
    let retired = {
        let mut roots = registered_replay_roots()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let scope = roots.iter().find_map(|(scope, consumer)| {
            (scope.0 == data_root && Weak::ptr_eq(&consumer.graph, owner)).then(|| scope.clone())
        });
        scope.and_then(|scope| roots.remove(&scope).map(|consumer| (scope, consumer)))
    };
    if let Some((scope, consumer)) = retired {
        spool_watch::detach_consumer(&scope.0, &scope.1, &consumer.wake);
        if let Some(task) = consumer.task {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_lanes_retry_during_continuous_peer_batches_and_consume_fresh_wakes() {
        let wake = tokio::sync::Notify::new();
        let mut retry_at = std::time::Instant::now() + REPLAY_INTERVAL;
        assert!(!deferred_retry_due(&wake, &mut retry_at));
        retry_at = std::time::Instant::now();
        assert!(deferred_retry_due(&wake, &mut retry_at));
        assert!(!deferred_retry_due(&wake, &mut retry_at));
        wake.notify_one();
        assert!(deferred_retry_due(&wake, &mut retry_at));
        assert!(!deferred_retry_due(&wake, &mut retry_at));
    }

    #[test]
    fn completed_duplicates_and_unresolved_redrives_are_distinct() {
        let duplicate = HookV2AdmissionOutcomeV1::ExactDuplicate {
            context_scout_address: None,
            ready_guidance: serde_json::Value::Null,
        };
        assert_eq!(unresolved_pending_work(&duplicate), None);
        for (outcome, cause) in [
            (HookV2AdmissionOutcomeV1::Unavailable, "was unavailable"),
            (HookV2AdmissionOutcomeV1::Backpressured, "was backpressured"),
            (
                HookV2AdmissionOutcomeV1::CatchupRequired,
                "requires binding catch-up",
            ),
            (
                HookV2AdmissionOutcomeV1::Conflict,
                "conflicted with an earlier admission",
            ),
        ] {
            assert_eq!(unresolved_pending_work(&outcome), Some(cause));
        }
    }

    #[test]
    fn queued_orchestration_does_not_prove_producer_completion() {
        for (orchestration, cause) in [
            (
                tracedecay_daemon_service::HookOrchestrationAdmissionV1::Enqueued,
                "is queued for producer execution",
            ),
            (
                tracedecay_daemon_service::HookOrchestrationAdmissionV1::Backpressured,
                "producer execution was backpressured",
            ),
            (
                tracedecay_daemon_service::HookOrchestrationAdmissionV1::Unavailable,
                "producer execution was unavailable",
            ),
            (
                tracedecay_daemon_service::HookOrchestrationAdmissionV1::UnsupportedTrigger,
                "producer execution has no supported trigger",
            ),
        ] {
            let outcome = HookV2AdmissionOutcomeV1::Admitted {
                orchestration,
                context_scout_address: None,
                ready_guidance: serde_json::Value::Null,
                feedback_notice: serde_json::Value::Null,
                github_stack_signal_available: false,
            };
            assert_eq!(unresolved_pending_work(&outcome), Some(cause));
        }
    }

    #[test]
    fn retained_and_unbound_records_are_reported_without_hiding_peer_progress() {
        let mut sweep = HookReplaySweepV1::default();
        let unavailable = NativeHostIdentityV1::ClaudeCode;
        let healthy = NativeHostIdentityV1::Codex;
        note_replay_report(
            &mut sweep,
            unavailable,
            &HookReplayPassReportV1 {
                binding_unavailable: true,
                ..Default::default()
            },
        );
        note_replay_report(
            &mut sweep,
            healthy,
            &HookReplayPassReportV1 {
                committed: 1,
                ..Default::default()
            },
        );
        assert_eq!(sweep.failures.len(), 1);
        assert_eq!(sweep.failures[0].host, unavailable);
        assert!(sweep.failures[0].cause.contains("binding"));
        note_replay_report(
            &mut sweep,
            healthy,
            &HookReplayPassReportV1 {
                retained: 2,
                ..Default::default()
            },
        );
        assert_eq!(sweep.failures.len(), 2);
        assert!(sweep.failures[1].cause.contains("backpressured"));
        assert!(!sweep.more_pending);
    }

    #[tokio::test]
    async fn reopening_a_live_graph_transfers_replay_and_renewal_ownership() {
        use tracedecay_application::observability::{
            BoundedObservabilityProducerV1, DeliverySettlementAuthorityV1,
            ObservabilityProducerIdentityV1,
        };
        use tracedecay_project::project::TraceDecayOpenOptions;
        use tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1;
        use tracedecay_sessions::admission::HostAdmissionScope;

        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("profile");
        let project = directory.path().join("project");
        let project_id = tracedecay_domain::ProjectId::new("project.hook-reopen").unwrap();
        let runtime = HostAdmissionTestRuntimeV1::project(&profile, &project, project_id.clone())
            .await
            .unwrap();
        let options = TraceDecayOpenOptions::for_profile(
            &tracedecay_runtime_core::config::ProfileRoot::new(profile),
        );
        let first = Arc::new(
            runtime
                .initialize_project_graph_for_test(&project, options.clone())
                .await
                .unwrap(),
        );
        let sessions = runtime
            .registered_database_lease(HostAdmissionScope::Project)
            .unwrap()
            .clone();
        let identity = ObservabilityProducerIdentityV1 {
            authorized_scope_ref: project_id.as_str().to_owned(),
            process_boot_id: "boot:hook-reopen".to_owned(),
            producer_revision: "hook-reopen-producer.v1".to_owned(),
            configuration_revision: "hook-reopen-config.v1".to_owned(),
            policy_revision: "hook-reopen-policy.v1".to_owned(),
        };
        let producer = Arc::new(
            BoundedObservabilityProducerV1::start(sessions.clone(), identity.clone(), 8).unwrap(),
        );
        let authority = Arc::new(
            DeliverySettlementAuthorityV1::new(sessions.clone(), Arc::clone(&producer), identity)
                .unwrap(),
        );
        let cpu = Arc::new(
            tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1::new(
                std::num::NonZeroUsize::new(1).unwrap(),
            ),
        );
        assert_eq!(
            ReplayConsumerStart::Started,
            register_hook_v2_replay_consumer(
                Arc::clone(&first),
                Arc::clone(&authority),
                sessions.clone(),
                Arc::clone(&cpu)
            )
        );
        let scope = (first.hook_store_layout().data_root.clone(), project.clone());
        let first_publication = {
            let worktree = tracedecay_agent_hosts::hooks::hook_worktree_id_for_layout(
                &crate::hook_runtime(tracedecay_runtime_core::config::ProfileRoot::new(
                    first.profile_root().unwrap(),
                )),
                first.hook_store_layout(),
            )
            .unwrap();
            tracedecay_hooks::HookConfigurationFileReaderV1::new(
                tracedecay_hooks::hook_configuration_path(
                    &scope.0,
                    worktree,
                    NativeHostIdentityV1::Codex,
                ),
            )
            .load(NativeHostIdentityV1::Codex)
            .unwrap()
            .unwrap()
        };
        let successor = Arc::new(
            runtime
                .open_project_graph_for_test(&project, options)
                .await
                .unwrap(),
        );
        assert_eq!(
            ReplayConsumerStart::Started,
            register_hook_v2_replay_consumer(
                Arc::clone(&successor),
                Arc::clone(&authority),
                sessions.clone(),
                cpu
            )
        );
        assert_eq!(
            ReplayConsumerStart::AlreadyRunning,
            register_hook_v2_replay_consumer(
                Arc::clone(&successor),
                Arc::clone(&authority),
                sessions,
                Arc::new(
                    tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1::new(
                        std::num::NonZeroUsize::new(1).unwrap()
                    )
                )
            )
        );
        let later = UtcMicros(first_publication.expires_at.0 + 1);
        assert_eq!(
            first.renew_hook_bindings(later).unwrap().len(),
            tracedecay_agent_hosts::hooks::NATIVE_HOOK_HOSTS.len()
        );
        assert_eq!(successor.renew_hook_bindings(later).unwrap(), vec![]);
        shutdown_hook_v2_replay_consumer_for_graph(&first).await;
        assert!(
            registered_replay_roots()
                .lock()
                .unwrap()
                .get(&scope)
                .is_some_and(|consumer| Weak::ptr_eq(&consumer.graph, &Arc::downgrade(&successor)))
        );
        shutdown_hook_v2_replay_consumer_for_graph(&successor).await;
        assert!(!hook_v2_replay_consumer_registered(&scope.0));
        tracedecay_agent_hosts::agents::context_scout::owner::unregister_registered_context_scout_owner(
            tracedecay_agent_hosts::hooks::hook_project_id_for_layout(successor.hook_store_layout()).unwrap(),
            &successor.db_path(),
        );
        drop(first);
        drop(successor);
        drop(authority);
        producer.shutdown().await.unwrap();
        drop(producer);
        runtime.shutdown().await.unwrap();
    }

    #[test]
    fn observed_backlog_clears_an_earlier_drained_status() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let graph = Weak::new();
        let scope = (root.to_path_buf(), root.join("worktree"));
        registered_replay_roots().lock().unwrap().insert(
            scope.clone(),
            RegisteredReplayConsumer {
                graph: graph.clone(),
                delivery_settlements: Weak::new(),
                wake: Arc::new(tokio::sync::Notify::new()),
                task: None,
                last_sweep: None,
            },
        );
        publish_sweep(&scope, &graph, Vec::new(), false);
        assert!(matches!(
            hook_replay_status(root),
            StatusHookReplayV1::Drained
        ));
        publish_sweep(&scope, &graph, Vec::new(), true);
        assert!(matches!(
            hook_replay_status(root),
            StatusHookReplayV1::Starting
        ));
        let mut sweep = HookReplaySweepV1::default();
        note_replay_report(
            &mut sweep,
            NativeHostIdentityV1::Codex,
            &HookReplayPassReportV1 {
                retained: 1,
                ..Default::default()
            },
        );
        publish_sweep(&scope, &graph, sweep.failures, false);
        assert!(matches!(
            hook_replay_status(root),
            StatusHookReplayV1::Failed { .. }
        ));
        registered_replay_roots().lock().unwrap().remove(&scope);
    }

    fn status_envelope(now: UtcMicros) -> tracedecay_hooks::HookEventEnvelopeV2 {
        tracedecay_hooks::HookEventEnvelopeV2 {
            schema_version: tracedecay_hooks::HOOK_EVENT_SCHEMA_VERSION,
            event_id: [1; 16],
            producer: NativeHostIdentityV1::CursorDesktop,
            protected_session_id: [2; 32],
            project_id: [3; 16],
            repository_id: [4; 16],
            worktree_id: [5; 16],
            worktree_epoch: 1,
            binding_token: [6; 32],
            ordering: tracedecay_hooks::HookOrderingV1::Unknown,
            observed_at: now,
            event: tracedecay_hooks::HookEventV2::SessionBoundary {
                boundary: tracedecay_hooks::HookBoundaryV1::End,
            },
        }
    }

    #[test]
    fn records_appended_after_a_sweep_prevent_empty_success() {
        let directory = tempfile::tempdir().unwrap();
        let now = hook_replay_now();
        let envelope = status_envelope(now);
        let binding = tracedecay_hooks::HookScopeBindingV1 {
            host: envelope.producer,
            project_id: envelope.project_id,
            repository_id: envelope.repository_id,
            worktree_id: envelope.worktree_id,
            worktree_epoch: envelope.worktree_epoch,
            binding_token: envelope.binding_token,
            capabilities: vec![tracedecay_hooks::HookCapabilityV1 {
                family: tracedecay_hooks::HookEventFamily::SessionBoundary,
                support: tracedecay_hooks::HookEventSupportV1::Native,
            }],
        };
        assert!(matches!(
            current_hook_replay_work(directory.path()),
            StatusHookReplayV1::Drained
        ));
        let (mut spool, _) = HookSpoolV1::open(
            hook_v2_spool_root(directory.path(), envelope.producer),
            HookSpoolConfigV1::stock(envelope.producer),
            now,
        )
        .unwrap();
        spool.append(envelope, &binding, now).unwrap();
        spool.commit().unwrap();
        assert!(matches!(
            current_hook_replay_work(directory.path()),
            StatusHookReplayV1::Starting
        ));
    }

    #[test]
    fn a_new_receipt_or_an_unsafe_receipt_root_prevents_empty_success() {
        let directory = tempfile::tempdir().unwrap();
        let root = tracedecay_hooks::hook_delivery_receipt_spool_root(
            directory.path(),
            NativeHostIdentityV1::CursorDesktop,
        );
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(format!("{:032x}.delivery.v1.json", 1)),
            b"corrupt receipt",
        )
        .unwrap();
        assert!(matches!(
            current_hook_replay_work(directory.path()),
            StatusHookReplayV1::Starting
        ));
        let unsafe_directory = tempfile::tempdir().unwrap();
        let unsafe_root = tracedecay_hooks::hook_delivery_receipt_spool_root(
            unsafe_directory.path(),
            NativeHostIdentityV1::CursorDesktop,
        );
        std::fs::create_dir_all(unsafe_root.parent().unwrap()).unwrap();
        std::fs::write(&unsafe_root, b"not a directory").unwrap();
        let StatusHookReplayV1::Failed { failures } =
            current_hook_replay_work(unsafe_directory.path())
        else {
            panic!("unsafe receipt authority must be a typed failure");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].spool, StatusHookReplaySpoolV1::DeliveryReceipts);
    }

    #[test]
    fn producer_work_admitted_after_a_sweep_prevents_empty_success() {
        let directory = tempfile::tempdir().unwrap();
        let now = hook_replay_now();
        let envelope = status_envelope(now);
        let ledger_root = directory
            .path()
            .join(tracedecay_hooks::PROJECT_HOOK_ADMISSIONS_DIR)
            .join(envelope.producer.hook_key());
        let (mut ledger, _) = tracedecay_hooks::HookAdmissionLedgerV1::open(
            &ledger_root,
            envelope.producer,
            tracedecay_hooks::HookAdmissionLedgerLimitsV1::stock(),
            now,
        )
        .unwrap();
        ledger
            .stage_admission(&envelope, Some(&envelope), now)
            .unwrap()
            .commit
            .wait()
            .unwrap();
        drop(ledger);
        assert_eq!(
            hook_v2_pending_work_envelopes(directory.path(), envelope.producer, now).unwrap(),
            vec![envelope]
        );
        let StatusHookReplayV1::Failed { failures } = current_hook_replay_work(directory.path())
        else {
            panic!("durable producer work must stay visibly owed");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].spool, StatusHookReplaySpoolV1::PendingWork);
        assert!(
            failures[0]
                .cause
                .starts_with("1 pending producer work item(s) stayed owed;")
        );
    }

    #[cfg(unix)]
    #[test]
    fn substituted_empty_roots_cannot_preserve_drained_status() {
        let host = NativeHostIdentityV1::CursorDesktop;
        for spool_kind in [
            StatusHookReplaySpoolV1::Records,
            StatusHookReplaySpoolV1::DeliveryReceipts,
            StatusHookReplaySpoolV1::PendingWork,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let foreign = tempfile::tempdir().unwrap();
            let now = hook_replay_now();
            let root = match spool_kind {
                StatusHookReplaySpoolV1::Records => {
                    let root = hook_v2_spool_root(directory.path(), host);
                    let (spool, _) =
                        HookSpoolV1::open(&root, HookSpoolConfigV1::stock(host), now).unwrap();
                    spool.commit().unwrap();
                    root
                }
                StatusHookReplaySpoolV1::DeliveryReceipts => {
                    let root =
                        tracedecay_hooks::hook_delivery_receipt_spool_root(directory.path(), host);
                    drop(HookDeliveryReceiptSpoolV1::open(&root, Duration::ZERO).unwrap());
                    root
                }
                StatusHookReplaySpoolV1::PendingWork => {
                    let root = directory
                        .path()
                        .join(tracedecay_hooks::PROJECT_HOOK_ADMISSIONS_DIR)
                        .join(host.hook_key());
                    drop(
                        tracedecay_hooks::HookAdmissionLedgerV1::open(
                            &root,
                            host,
                            tracedecay_hooks::HookAdmissionLedgerLimitsV1::stock(),
                            now,
                        )
                        .unwrap(),
                    );
                    assert_eq!(
                        hook_v2_pending_work_envelopes(directory.path(), host, now).unwrap(),
                        vec![]
                    );
                    root
                }
            };
            assert!(matches!(
                current_hook_replay_work(directory.path()),
                StatusHookReplayV1::Drained
            ));
            std::fs::remove_dir_all(&root).unwrap();
            std::os::unix::fs::symlink(foreign.path(), &root).unwrap();
            let StatusHookReplayV1::Failed { failures } =
                current_hook_replay_work(directory.path())
            else {
                panic!("substituted empty root must remain a typed failure");
            };
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].spool, spool_kind);
            assert_eq!(std::fs::read_dir(foreign.path()).unwrap().count(), 0);
            assert!(
                std::fs::symlink_metadata(root)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }

    #[test]
    fn a_replaced_regular_owed_log_cannot_preserve_drained_status() {
        let directory = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let now = hook_replay_now();
        let envelope = status_envelope(now);
        let root = directory
            .path()
            .join(tracedecay_hooks::PROJECT_HOOK_ADMISSIONS_DIR)
            .join(envelope.producer.hook_key());
        drop(
            tracedecay_hooks::HookAdmissionLedgerV1::open(
                &root,
                envelope.producer,
                tracedecay_hooks::HookAdmissionLedgerLimitsV1::stock(),
                now,
            )
            .unwrap(),
        );
        assert_eq!(
            hook_v2_pending_work_envelopes(directory.path(), envelope.producer, now).unwrap(),
            vec![]
        );
        assert!(matches!(
            current_hook_replay_work(directory.path()),
            StatusHookReplayV1::Drained
        ));
        let (mut foreign_ledger, _) = tracedecay_hooks::HookAdmissionLedgerV1::open(
            foreign.path(),
            envelope.producer,
            tracedecay_hooks::HookAdmissionLedgerLimitsV1::stock(),
            now,
        )
        .unwrap();
        foreign_ledger
            .stage_admission(&envelope, Some(&envelope), now)
            .unwrap()
            .commit
            .wait()
            .unwrap();
        assert_eq!(foreign_ledger.pending_work_count().unwrap(), 1);
        drop(foreign_ledger);
        let foreign_log = foreign.path().join("admissions.v2.log");
        let bytes = std::fs::read(&foreign_log).unwrap();
        let target = root.join("admissions.v2.log");
        std::fs::rename(foreign_log, &target).unwrap();
        let StatusHookReplayV1::Failed { failures } = current_hook_replay_work(directory.path())
        else {
            panic!("a foreign owed log must never be certified empty");
        };
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].spool, StatusHookReplaySpoolV1::PendingWork);
        assert!(hook_v2_pending_work_envelopes(directory.path(), envelope.producer, now).is_err());
        assert_eq!(std::fs::read(target).unwrap(), bytes);
    }

    #[test]
    fn only_a_missing_spool_root_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(spool_root_absent(&dir.path().join("missing")), Ok(true));
        assert_eq!(spool_root_absent(dir.path()), Ok(false));
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(spool_root_absent(&file), Ok(false));
        assert!(spool_root_absent(&file.join("child")).is_err());
    }

    struct ReplayOwnerFixture {
        _temp: tempfile::TempDir,
        _settlement_runtime: tracedecay_global_db::tests::harness::RegisteredGlobalDbTestRuntime,
        project_sessions: tracedecay_global_db::RegisteredGlobalDbLeaseV1,
        settlements: Arc<tracedecay_application::observability::DeliverySettlementAuthorityV1>,
        background_cpu: Arc<tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1>,
    }

    type ProjectGraph = Arc<tracedecay_project::project::TraceDecay>;

    /// Two owners of one project, so both resolve the same hook data root.
    async fn replay_owner_fixture() -> (ReplayOwnerFixture, ProjectGraph, ProjectGraph) {
        let temp = tempfile::tempdir().expect("replay owner fixture");
        let project = temp.path().join("project");
        let profile = temp.path().join("profile");
        std::fs::create_dir_all(project.join("src")).expect("project source directory");
        std::fs::write(project.join("src/lib.rs"), "pub fn fixture() {}\n").expect("source");
        let options = tracedecay_project::project::TraceDecayOpenOptions {
            profile_root: Some(profile.clone()),
            global_db_path: Some(profile.join("global.db")),
        };
        let older = Arc::new(
            tracedecay_project::project::TraceDecay::init_with_options_for_test(
                &project,
                options.clone(),
            )
            .await
            .expect("older project owner"),
        );
        let newer = Arc::new(
            tracedecay_project::project::TraceDecay::open_with_options_for_test(&project, options)
                .await
                .expect("newer project owner"),
        );
        let project_id = tracedecay_domain::ProjectId::new("project.replay.owner").expect("id");
        let settlement_runtime =
            tracedecay_global_db::tests::harness::RegisteredGlobalDbTestRuntime::project(
                &temp.path().join("settlement-profile"),
                &project,
                project_id.clone(),
            )
            .await
            .expect("settlement runtime");
        let project_sessions = settlement_runtime
            .project_database_arc()
            .expect("project sessions database");
        let identity = tracedecay_application::observability::ObservabilityProducerIdentityV1 {
            authorized_scope_ref: project_id.as_str().to_owned(),
            process_boot_id: "boot:replay-owner".to_owned(),
            producer_revision: "replay-owner-producer.v1".to_owned(),
            configuration_revision: "replay-owner-config.v1".to_owned(),
            policy_revision: "replay-owner-policy.v1".to_owned(),
        };
        let producer = Arc::new(
            tracedecay_application::observability::BoundedObservabilityProducerV1::start(
                project_sessions.clone(),
                identity.clone(),
                8,
            )
            .expect("producer"),
        );
        let settlements = Arc::new(
            tracedecay_application::observability::DeliverySettlementAuthorityV1::new(
                project_sessions.clone(),
                producer,
                identity,
            )
            .expect("settlement authority"),
        );
        let fixture = ReplayOwnerFixture {
            _temp: temp,
            _settlement_runtime: settlement_runtime,
            project_sessions,
            settlements,
            background_cpu: Arc::new(
                tracedecay_runtime_core::background_cpu::ProcessBackgroundCpuV1::new(
                    std::num::NonZeroUsize::MIN,
                ),
            ),
        };
        (fixture, older, newer)
    }

    impl ReplayOwnerFixture {
        fn register(&self, graph: &ProjectGraph) -> ReplayConsumerStart {
            register_hook_v2_replay_consumer(
                Arc::clone(graph),
                Arc::clone(&self.settlements),
                self.project_sessions.clone(),
                Arc::clone(&self.background_cpu),
            )
        }
    }

    async fn assert_owner_keeps_replay(data_root: &Path, owner: &ProjectGraph) {
        let owner_task_running = registered_replay_roots()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(data_root.to_path_buf(), owner.project_root().to_path_buf()))
            .is_some_and(|registered| {
                Weak::ptr_eq(&registered.graph, &Arc::downgrade(owner))
                    && registered
                        .task
                        .as_ref()
                        .is_some_and(|task| !task.is_finished())
            });
        assert!(
            owner_task_running,
            "the owner must keep the data root's running replay consumer"
        );
        assert!(hook_v2_replay_consumer_registered(data_root));
        assert!(
            spool_watch::consumer_attached(data_root, owner.project_root()),
            "the owner's consumer must keep the spool wake"
        );
        shutdown_hook_v2_replay_consumer(data_root).await;
        assert!(!hook_v2_replay_consumer_registered(data_root));
    }

    /// The older owner's graph is gone by the time the project reopens, so
    /// the newer owner registers; the older owner's retirement then arrives.
    #[tokio::test]
    async fn a_late_retirement_leaves_the_newer_owners_replay_consumer_running() {
        let (fixture, older, newer) = replay_owner_fixture().await;
        let data_root = older.hook_store_layout().data_root.clone();
        assert_eq!(data_root, newer.hook_store_layout().data_root);
        assert_eq!(
            fixture.register(&older),
            ReplayConsumerStart::Started,
            "the older owner starts replay"
        );
        let older_owner = Arc::downgrade(&older);
        drop(older);
        assert_eq!(
            fixture.register(&newer),
            ReplayConsumerStart::Started,
            "the reopened owner starts replay"
        );

        retire_hook_v2_replay_consumer(&data_root, &older_owner).await;

        assert_owner_keeps_replay(&data_root, &newer).await;
    }

    /// The project reopens while its retiring owner's server still holds the
    /// older graph. The reopened owner must take over the data root, or the
    /// older graph's release leaves the project with no consumer at all.
    #[tokio::test]
    async fn a_reopen_takes_over_replay_from_an_owner_still_retiring() {
        let (fixture, older, newer) = replay_owner_fixture().await;
        let data_root = older.hook_store_layout().data_root.clone();
        assert_eq!(
            fixture.register(&older),
            ReplayConsumerStart::Started,
            "the older owner starts replay"
        );
        let newer_registered = fixture.register(&newer);

        retire_hook_v2_replay_consumer(&data_root, &Arc::downgrade(&older)).await;
        drop(older);

        assert_eq!(
            newer_registered,
            ReplayConsumerStart::Started,
            "the reopened owner's registration must be accepted"
        );
        assert_owner_keeps_replay(&data_root, &newer).await;
    }

    /// Project opens register from native workers, which have no Tokio
    /// runtime; the reopened owner must still take the data root over.
    #[tokio::test]
    async fn a_registration_off_tokio_takes_over_replay() {
        let (fixture, older, newer) = replay_owner_fixture().await;
        let data_root = older.hook_store_layout().data_root.clone();
        assert_eq!(fixture.register(&older), ReplayConsumerStart::Started);

        let registered = std::thread::scope(|scope| {
            scope
                .spawn(|| fixture.register(&newer))
                .join()
                .expect("registration thread")
        });

        assert_eq!(registered, ReplayConsumerStart::Started);
        assert_owner_keeps_replay(&data_root, &newer).await;
    }
}
