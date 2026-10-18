//! Capture-only hook callbacks append to the per-host spool, publish their
//! delivery receipts, and exit without contacting the daemon. These journeys
//! pin that a spooled event or receipt reaches the daemon promptly: while the
//! project is open, and after a daemon restart that left it behind, without
//! any other client opening the project.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use tracedecay_domain::NativeHostIdentityV1;
use tracedecay_hooks::{
    HOOK_SYNCHRONOUS_BUDGET, HookDeliveryReceiptWriterV1, HookDeliveryRetentionV1,
    HookDeliverySourceReceiptV1, hook_delivery_receipt_spool_root,
};
use tracedecay_private_fs::framed_log::{DirectorySyncPolicy, atomic_write};
use tracedecay_runtime_core::storage::default_profile_sharded_layout;

use crate::common::{git_program, spawn_tracedecay_daemon, tracedecay_command_with_home};

/// Well under the replay consumer's 30 s interval sweep, so a drain inside it
/// can only come from the append wake or the startup open.
const PROMPT_DRAIN: Duration = Duration::from_secs(10);

fn init_git_project(home: &Path) -> PathBuf {
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"spool-drain-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(project.join("src/lib.rs"), "pub fn drained() {}\n").unwrap();
    let git = git_program();
    for args in [
        &["init", "-q", "-b", "main"][..],
        &["config", "user.email", "test@tracedecay.dev"][..],
        &["config", "user.name", "TraceDecay Test"][..],
        &["add", "."][..],
        &["commit", "-q", "-m", "fixture"][..],
    ] {
        assert!(
            Command::new(&git)
                .args(args)
                .current_dir(&project)
                .status()
                .unwrap()
                .success()
        );
    }
    project
}

fn tracedecay(home: &Path, project: &Path, args: &[&str]) {
    let output = tracedecay_command_with_home(home)
        .args(args)
        .current_dir(project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tracedecay {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One Cursor `afterFileEdit` through the capture fast path, as the host
/// invokes it.
fn capture_edit(home: &Path, project: &Path, generation: &str) {
    let event = json!({
        "hook_event_name": "afterFileEdit",
        "conversation_id": "spool-drain-conversation",
        "generation_id": generation,
        "model": "auto",
        "session_id": "spool-drain-conversation",
        "cursor_version": "1.7.0",
        "transcript_path": project.join(".cursor-transcript.jsonl"),
        "file_path": project.join("src/lib.rs"),
        "edits": [{ "old_string": "pub fn drained() {}", "new_string": generation }],
        "workspace_roots": [project],
    });
    run_hook(home, project, "hook-cursor-after-file-edit", &event);
}

/// Runs `command` as the host invokes it and requires it to succeed.
fn run_hook(home: &Path, project: &Path, command: &str, event: &serde_json::Value) {
    let mut child = tracedecay_command_with_home(home)
        .arg(command)
        .current_dir(project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One Cursor `stop` through the capture fast path; it spools the event and
/// publishes the hook's delivery receipt.
fn capture_stop(home: &Path, project: &Path, generation: &str) {
    let event = json!({
        "conversation_id": "spool-drain-conversation",
        "generation_id": generation,
        "hook_event_name": "stop",
        "model": "auto",
        "status": "completed",
        "loop_count": 0,
        "workspace_roots": [project],
    });
    run_hook(home, project, "hook-cursor-stop", &event);
}

fn published_receipts(receipts: &Path) -> Vec<PathBuf> {
    let mut published = std::fs::read_dir(receipts).map_or_default(|entries| {
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".delivery.v1.json"))
            })
            .collect::<Vec<_>>()
    });
    published.sort();
    published
}

/// Seconds until the Cursor receipt spool is empty again, or `None` when it
/// still holds a receipt at `limit`.
fn receipt_drain_latency(receipts: &Path, limit: Duration) -> Option<Duration> {
    latency_until(limit, || published_receipts(receipts).is_empty())
}

fn publish(receipts: &Path, receipt: &HookDeliverySourceReceiptV1) {
    assert_eq!(
        HookDeliveryReceiptWriterV1::open_within(receipts, HOOK_SYNCHRONOUS_BUDGET)
            .unwrap()
            .retain(receipt),
        Ok(HookDeliveryRetentionV1::Published)
    );
}

fn spooled_bytes(records: &Path) -> u64 {
    std::fs::metadata(records).map_or(0, |metadata| metadata.len())
}

/// Seconds until the Cursor spool's records file is empty again, or `None`
/// when it is still holding records at `limit`.
fn drain_latency(records: &Path, limit: Duration) -> Option<Duration> {
    latency_until(limit, || spooled_bytes(records) == 0)
}

/// The project's `hook_replay` status section, read through the daemon as
/// an agent reads it.
fn hook_replay_status(home: &Path, project: &Path) -> serde_json::Value {
    let output = tracedecay_command_with_home(home)
        .args(["tool", "tracedecay_status", "--json"])
        .current_dir(project)
        .output()
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "tracedecay_status must answer JSON\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    envelope["structuredContent"]["hook_replay"].clone()
}

/// Waits for a semantic status condition without assuming transient producer
/// admission and execution failures have identical descriptions.
fn await_hook_replay_status(
    home: &Path,
    project: &Path,
    ready: impl Fn(&serde_json::Value) -> bool,
    limit: Duration,
) -> serde_json::Value {
    let started = Instant::now();
    loop {
        let status = hook_replay_status(home, project);
        if ready(&status) || started.elapsed() >= limit {
            return status;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn pending_producer_failure(status: &serde_json::Value) -> bool {
    status["status"] == "failed"
        && status["failures"].as_array().is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure["host"] == "cursor_desktop"
                    && failure["spool"] == "pending_work"
                    && failure["cause"].as_str().is_some_and(|cause| {
                        cause
                            .split_once(" pending producer work item(s) stayed owed; ")
                            .is_some_and(|(count, reason)| {
                                count.parse::<usize>().is_ok_and(|count| count > 0)
                                    && matches!(
                                        reason,
                                        "execution has not completed"
                                            | "is queued for producer execution"
                                            | "producer execution was unavailable"
                                    )
                            })
                    })
            })
        })
}

/// Transport settlement does not complete Cursor's native producer prerequisite.
/// These fixtures have no native conversation database to supply that work.
fn assert_only_producer_work_owed(home: &Path, project: &Path) {
    let status = await_hook_replay_status(
        home,
        project,
        |status| {
            pending_producer_failure(status)
                && status["failures"]
                    .as_array()
                    .is_some_and(|failures| failures.len() == 1)
        },
        PROMPT_DRAIN,
    );
    assert!(
        pending_producer_failure(&status),
        "producer work must remain truthfully owed: {status}"
    );
    assert_eq!(
        status["failures"].as_array().unwrap().len(),
        1,
        "settled transports must have no remaining failure: {status}"
    );
}

fn latency_until(limit: Duration, drained: impl Fn() -> bool) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if drained() {
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn spooled_capture_events_drain_promptly_while_open_and_after_a_restart() {
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let layout = default_profile_sharded_layout(&project, &home.join(".tracedecay")).unwrap();
    let records = layout
        .data_root
        .join("hook-v2-spool/cursor-desktop/records.v1.bin");

    // Open project: the consumer drains on the append wake, not the sweep.
    capture_edit(&home, &project, "open-1");
    capture_edit(&home, &project, "open-2");
    assert!(
        drain_latency(&records, PROMPT_DRAIN).is_some(),
        "spooled events on an open project must drain within {PROMPT_DRAIN:?}, not the 30 s sweep"
    );

    assert_only_producer_work_owed(&home, &project);

    // Daemon down: captures still land in the spool.
    drop(daemon);
    for index in 0..5 {
        capture_edit(&home, &project, &format!("restart-{index}"));
    }
    assert!(
        spooled_bytes(&records) > 0,
        "captures made while the daemon was down must spool"
    );

    // Restart with no client opening the project: the daemon opens it itself.
    let _daemon = spawn_tracedecay_daemon(&home);
    assert!(
        drain_latency(&records, PROMPT_DRAIN).is_some(),
        "records spooled across a restart must drain within {PROMPT_DRAIN:?} without another client"
    );

    assert_only_producer_work_owed(&home, &project);

    // The project the daemon opened for its spool keeps draining new appends.
    capture_edit(&home, &project, "after-restart");
    assert!(
        drain_latency(&records, PROMPT_DRAIN).is_some(),
        "an append after the restart must drain within {PROMPT_DRAIN:?}"
    );
    assert_only_producer_work_owed(&home, &project);
}

#[test]
fn a_failed_receipt_drain_is_reported_on_status_and_clears_when_the_spool_drains() {
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let _daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let layout = default_profile_sharded_layout(&project, &home.join(".tracedecay")).unwrap();
    let receipts =
        hook_delivery_receipt_spool_root(&layout.data_root, NativeHostIdentityV1::CursorDesktop);
    let writer =
        HookDeliveryReceiptWriterV1::open_within(&receipts, HOOK_SYNCHRONOUS_BUDGET).unwrap();
    let corrupt = receipts.join(format!("{:032x}.delivery.v1.json", 7));
    // The staging lease protects the live temporary; atomic publication keeps
    // the drain from reading an empty or partial file as an I/O failure.
    atomic_write(
        &corrupt,
        "corrupt-fixture",
        b"not a delivery receipt",
        DirectorySyncPolicy::Strict,
    )
    .unwrap();
    drop(writer);

    let failed = json!({
        "status": "failed",
        "failures": [{
            "host": "cursor_desktop",
            "spool": "delivery_receipts",
            "cause": "hook delivery receipt spool is corrupt",
        }],
    });
    assert_eq!(
        await_hook_replay_status(&home, &project, |status| status == &failed, PROMPT_DRAIN),
        failed
    );
    assert!(
        corrupt.is_file(),
        "a receipt the drain could not settle stays durable"
    );

    // Once the spool is readable again, the next publication drains it and
    // the failure clears.
    std::fs::remove_file(&corrupt).unwrap();
    capture_stop(&home, &project, "after-repair");
    assert!(receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some());
    assert_only_producer_work_owed(&home, &project);
    assert_eq!(published_receipts(&receipts), Vec::<PathBuf>::new());
}

#[test]
fn a_receipt_spool_root_that_is_not_a_directory_is_reported_on_status() {
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let _daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let layout = default_profile_sharded_layout(&project, &home.join(".tracedecay")).unwrap();
    let receipts =
        hook_delivery_receipt_spool_root(&layout.data_root, NativeHostIdentityV1::CursorDesktop);
    if receipts.exists() {
        std::fs::remove_dir_all(&receipts).unwrap();
    }
    std::fs::create_dir_all(receipts.parent().unwrap()).unwrap();
    std::fs::write(&receipts, b"not a receipt spool").unwrap();
    capture_edit(&home, &project, "after-unsafe-root");

    let failed = json!({
        "status": "failed",
        "failures": [{
            "host": "cursor_desktop",
            "spool": "delivery_receipts",
            "cause": "hook delivery receipt spool path is unsafe",
        }],
    });
    let status = await_hook_replay_status(
        &home,
        &project,
        |status| {
            pending_producer_failure(status)
                && status["failures"].as_array().is_some_and(|failures| {
                    failures.len() == 2 && failures.contains(&failed["failures"][0])
                })
        },
        PROMPT_DRAIN,
    );
    assert!(
        pending_producer_failure(&status),
        "the edit's producer prerequisite remains owed: {status}"
    );
    let failures = status["failures"].as_array().unwrap();
    assert_eq!(
        failures.len(),
        2,
        "both causal failures must be reported: {status}"
    );
    assert!(
        failures.contains(&failed["failures"][0]),
        "the unsafe receipt root must be reported: {status}"
    );
    assert!(
        receipts.is_file(),
        "the drain must not replace the unusable root"
    );
}

/// A receipt backlog larger than one drain batch settles in back-to-back
/// sweeps, while its unfinished native producer work remains visible.
#[test]
fn a_receipt_backlog_beyond_one_batch_drains_without_waiting_for_the_sweep() {
    const BACKLOG: usize = 65;
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let layout = default_profile_sharded_layout(&project, &home.join(".tracedecay")).unwrap();
    let records = layout
        .data_root
        .join("hook-v2-spool/cursor-desktop/records.v1.bin");
    let receipts =
        hook_delivery_receipt_spool_root(&layout.data_root, NativeHostIdentityV1::CursorDesktop);

    drop(daemon);
    for index in 0..BACKLOG {
        capture_stop(&home, &project, &format!("backlog-{index}"));
    }
    let held = published_receipts(&receipts)
        .into_iter()
        .map(|path| {
            let receipt = serde_json::from_slice::<HookDeliverySourceReceiptV1>(
                &std::fs::read(&path).unwrap(),
            )
            .unwrap();
            std::fs::remove_file(&path).unwrap();
            receipt
        })
        .collect::<Vec<_>>();
    assert_eq!(
        held.len(),
        BACKLOG,
        "each stop publishes one delivery receipt"
    );

    // Drain the stops' events first so only the receipt backlog remains.
    let daemon = spawn_tracedecay_daemon(&home);
    assert!(
        drain_latency(&records, PROMPT_DRAIN).is_some(),
        "the stops' events must drain within {PROMPT_DRAIN:?}"
    );
    drop(daemon);
    for receipt in &held {
        publish(&receipts, receipt);
    }

    let _daemon = spawn_tracedecay_daemon(&home);
    assert!(
        receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some(),
        "a {BACKLOG}-receipt backlog must drain within {PROMPT_DRAIN:?}, not one batch per 30 s sweep; {} left",
        published_receipts(&receipts).len()
    );
    assert_only_producer_work_owed(&home, &project);
}

#[test]
fn delivery_receipts_drain_promptly_after_the_last_append_and_after_a_restart() {
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let layout = default_profile_sharded_layout(&project, &home.join(".tracedecay")).unwrap();
    let records = layout
        .data_root
        .join("hook-v2-spool/cursor-desktop/records.v1.bin");
    let receipts =
        hook_delivery_receipt_spool_root(&layout.data_root, NativeHostIdentityV1::CursorDesktop);

    // Two real stops while the daemon is down; their receipts are held back
    // so each can be published when no capture append will follow it.
    drop(daemon);
    capture_stop(&home, &project, "receipt-open");
    capture_stop(&home, &project, "receipt-restart");
    let held = published_receipts(&receipts)
        .into_iter()
        .map(|path| {
            let receipt = serde_json::from_slice::<HookDeliverySourceReceiptV1>(
                &std::fs::read(&path).unwrap(),
            )
            .unwrap();
            std::fs::remove_file(&path).unwrap();
            receipt
        })
        .collect::<Vec<_>>();
    assert_eq!(held.len(), 2, "each stop publishes one delivery receipt");

    // The restart drains the stops' events; the consumer then idles.
    let daemon = spawn_tracedecay_daemon(&home);
    assert!(
        drain_latency(&records, PROMPT_DRAIN).is_some(),
        "the stops' events must drain within {PROMPT_DRAIN:?}"
    );
    std::thread::sleep(Duration::from_secs(1));

    // A receipt published after the last append wakes the drain itself.
    publish(&receipts, &held[0]);
    assert!(
        receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some(),
        "a receipt published after the last append must drain within {PROMPT_DRAIN:?}, not the 30 s sweep"
    );

    // A receipt left over a restart, with no spooled event beside it, opens
    // its project at startup.
    drop(daemon);
    publish(&receipts, &held[1]);
    let _daemon = spawn_tracedecay_daemon(&home);
    assert!(
        receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some(),
        "a receipt spooled across a restart must drain within {PROMPT_DRAIN:?} without another client"
    );

    // The native output writer can see the same event after its receipt was
    // acknowledged. Its logical key survives, while the new callback time
    // must not replace the durable settlement's first timestamps.
    let mut retry = held[0].settlement.clone();
    retry.attempt.valid_at.0 += 1;
    retry.attempt.attempted_at.0 += 1;
    retry.settled_at.0 += 1;
    let retry = HookDeliverySourceReceiptV1::new(retry).unwrap();
    assert_eq!(retry.receipt_id, held[0].receipt_id);
    publish(&receipts, &retry);
    assert!(
        receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some(),
        "an acknowledged exact output retry must replay its durable settlement"
    );
    assert_only_producer_work_owed(&home, &project);
}

/// The maintained daemon admission path mints the durable identity. Inspecting
/// the provider envelope directly in the ledger would check a different key.
fn assert_canonical_duplicate(
    home: &Path,
    project: &Path,
    envelope: &tracedecay_hooks::HookEventEnvelopeV2,
    native_session: &str,
) {
    let output = tracedecay_command_with_home(home)
        .args(["tool", "tracedecay_hook_runtime", "--json", "--args"])
        .arg(
            json!({
                "action": "hook_v2_admit",
                "envelope": envelope,
                "native_session_id": native_session,
            })
            .to_string(),
        )
        .current_dir(project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "canonical admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["structuredContent"]["status"], "exact_duplicate",
        "the exact native envelope must have been admitted, never tombstoned: {response}"
    );
    assert_eq!(response["structuredContent"]["disposition"], "accepted");
}

/// Both restart discovery and an append beside a mounted sibling must reopen
/// the exact enrolled linked checkout. A committed spool alone could conceal
/// a foreign-scope tombstone, so the durable admission ledger is checked too.
#[test]
fn linked_worktree_spooled_events_reopen_after_restart_and_beside_a_mounted_peer() {
    use tracedecay_domain::UtcMicros;
    use tracedecay_hooks::{
        HookBoundaryV1, HookConfigurationFileReaderV1, HookEventV2, HookSpoolConfigV1, HookSpoolV1,
        hook_configuration_path, hook_v2_spool_root,
    };

    let home = tempfile::TempDir::new().unwrap();
    let home = crate::common::canonicalize_test_dir(home.path());
    let primary = init_git_project(&home);
    let sibling = home.join("sibling");
    assert!(
        Command::new(git_program())
            .args(["worktree", "add", "-q", "-b", "sibling"])
            .arg(&sibling)
            .current_dir(&primary)
            .status()
            .unwrap()
            .success()
    );
    let sibling = crate::common::canonicalize_test_dir(&sibling);
    let daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &primary, &["init"]);
    // Normal registered open enrolls this linked alias in the same project.
    tracedecay(&home, &sibling, &["tool", "tracedecay_status", "--json"]);
    let layout = tracedecay_runtime_core::storage::resolve_persisted_layout(
        &sibling,
        &home.join(".tracedecay"),
    )
    .unwrap()
    .unwrap();
    let host = NativeHostIdentityV1::CursorDesktop;
    let spool_root = hook_v2_spool_root(&layout.data_root, host);
    let records = spool_root.join("records.v1.bin");
    drop(daemon);
    // Read the durable registry after the opening daemon has exited. A normal
    // profile mount does not enroll either project alias as a side effect.
    crate::common::register_process_runtime_ports();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let profile =
            tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1::profile(
                home.join(".tracedecay"),
            )
            .await
            .unwrap();
        let registry = profile.profile_database_for_test();
        let enrolled_primary = registry
            .resolve_project_store_by_alias(&primary)
            .await
            .unwrap();
        let enrolled_sibling = registry
            .resolve_project_store_by_alias(&sibling)
            .await
            .unwrap();
        assert_eq!(
            enrolled_sibling.project.project_id,
            enrolled_primary.project.project_id
        );
        assert_eq!(enrolled_sibling.store, enrolled_primary.store);
        assert_eq!(Path::new(&enrolled_sibling.project.canonical_root), primary);
    });
    let native_session = "sibling-restart-session";
    run_hook(
        &home,
        &sibling,
        "hook-cursor-session-start",
        &json!({
            "hook_event_name": "sessionStart",
            "conversation_id": native_session,
            "cwd": sibling,
            "workspace_roots": [sibling],
        }),
    );
    let now = UtcMicros(tracedecay_runtime_core::tracedecay::saturating_utc_now().0);
    let (mut spool, _) =
        HookSpoolV1::open(&spool_root, HookSpoolConfigV1::stock(host), now).unwrap();
    let queued = spool
        .pending_records()
        .unwrap()
        .into_iter()
        .map(|record| record.envelope)
        .collect::<Vec<_>>();
    drop(spool);
    assert_eq!(
        queued.len(),
        1,
        "the offline native callback must retain one exact envelope"
    );
    assert!(matches!(
        queued[0].event,
        HookEventV2::SessionBoundary {
            boundary: HookBoundaryV1::Start
        }
    ));
    let publication = HookConfigurationFileReaderV1::new(hook_configuration_path(
        &layout.data_root,
        queued[0].worktree_id,
        host,
    ));
    let before_restart = publication.load(host).unwrap().unwrap().revision;
    let daemon = spawn_tracedecay_daemon(&home);
    assert!(
        latency_until(PROMPT_DRAIN, || publication
            .load(host)
            .unwrap()
            .unwrap()
            .revision
            > before_restart)
        .is_some(),
        "startup must reopen the enrolled sibling without a request to that checkout"
    );
    assert!(drain_latency(&records, PROMPT_DRAIN).is_some());
    assert_canonical_duplicate(&home, &sibling, &queued[0], native_session);
    let receipts = hook_delivery_receipt_spool_root(&layout.data_root, host);
    assert!(receipt_drain_latency(&receipts, PROMPT_DRAIN).is_some());
    assert_eq!(
        await_hook_replay_status(
            &home,
            &sibling,
            |status| status == &json!({ "status": "drained" }),
            PROMPT_DRAIN
        ),
        json!({ "status": "drained" }),
        "a settled nonproducer callback leaves no native prerequisite"
    );
    drop(daemon);

    // No backlog exists at this restart, and only the primary is mounted.
    let _daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &primary, &["tool", "tracedecay_status", "--json"]);
    let before_append = publication.load(host).unwrap().unwrap().revision;
    // Decode a fresh native callback through the maintained capture authorities.
    // A live response hook would itself request B and hide an opener regression;
    // retrying the first admitted event could hide a second-phase tombstone.
    let now = UtcMicros(tracedecay_runtime_core::tracedecay::saturating_utc_now().0);
    let snapshot = publication.load(host).unwrap().unwrap();
    let appended_session = "sibling-beside-peer-session";
    let native_payload = json!({
        "hook_event_name": "sessionStart",
        "conversation_id": appended_session,
        "cwd": sibling,
        "workspace_roots": [sibling],
    })
    .to_string();
    let material = tracedecay_agent_hosts::hooks::native_capture_material(
        tracedecay_hooks::NativeHookCaptureSourceV1::Host(host),
        native_payload.as_bytes(),
        now,
    )
    .unwrap();
    let appended = tracedecay_hooks::decode_bound_native_hook_event(
        host,
        native_payload.as_bytes(),
        &snapshot.binding,
        material,
    )
    .unwrap();
    assert_ne!(appended.event_id, queued[0].event_id);
    assert_ne!(
        appended.protected_session_id,
        queued[0].protected_session_id
    );
    let (mut spool, _) =
        HookSpoolV1::open(&spool_root, HookSpoolConfigV1::stock(host), now).unwrap();
    spool
        .append(appended.clone(), &snapshot.binding, now)
        .unwrap();
    spool.commit().unwrap();
    assert!(
        latency_until(PROMPT_DRAIN, || publication
            .load(host)
            .unwrap()
            .unwrap()
            .revision
            > before_append)
        .is_some(),
        "a primary consumer must not suppress reopening an enrolled sibling"
    );
    assert!(drain_latency(&records, PROMPT_DRAIN).is_some());
    assert_canonical_duplicate(&home, &sibling, &appended, appended_session);
}

/// One Claude `PostToolUse` Write of `src/lib.rs` in `checkout`, as the host
/// invokes it, and the `hook_completed` disposition reason it recorded.
fn claude_edit(home: &Path, checkout: &Path, data_root: &Path, tool_use_id: &str) -> String {
    let mut event: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/tracedecay-hooks/fixtures/host_events/claude/post_tool_use_write.json"
    ))
    .unwrap();
    let file = checkout.join("src/lib.rs");
    event["cwd"] = json!(checkout);
    event["tool_use_id"] = json!(tool_use_id);
    event["prompt_id"] = json!(tool_use_id);
    event["tool_input"]["file_path"] = json!(file);
    event["tool_response"]["filePath"] = json!(file);
    run_hook(home, checkout, "hook-claude-post-tool-use", &event);
    let rows = std::fs::read_to_string(data_root.join("hook_analytics.jsonl")).unwrap();
    let completed = rows
        .lines()
        .rev()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["event"] == "hook_completed" && row["hook_name"] == "PostToolUse")
        .expect("the edit hook records its completion");
    completed["disposition"]["reason_code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn bound_worktrees(data_root: &Path) -> usize {
    std::fs::read_dir(data_root.join("hook-configurations")).map_or(0, Iterator::count)
}

#[test]
fn an_edit_in_a_never_opened_linked_worktree_binds_it_and_reaches_the_daemon() {
    let home = tempfile::TempDir::new().unwrap();
    let home = home.path().canonicalize().unwrap();
    let project = init_git_project(&home);
    let _daemon = spawn_tracedecay_daemon(&home);
    tracedecay(&home, &project, &["init"]);
    let data_root = default_profile_sharded_layout(&project, &home.join(".tracedecay"))
        .unwrap()
        .data_root;
    let worktree = project.join(".claude/worktrees/agent-x");
    assert!(
        Command::new(git_program())
            .args(["worktree", "add", "-q", "-b", "agent-x"])
            .arg(&worktree)
            .current_dir(&project)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        worktree.join("src/lib.rs"),
        "pub fn edited_in_worktree() {}\n",
    )
    .unwrap();
    assert_eq!(
        bound_worktrees(&data_root),
        1,
        "only the main checkout is bound"
    );

    assert_eq!(
        claude_edit(&home, &worktree, &data_root, "toolu_unbound_first"),
        "hook_v2_accepted",
        "the first edit in an unbound worktree must reach the daemon, not be dropped"
    );
    assert_eq!(
        bound_worktrees(&data_root),
        2,
        "delivering that edit opens the worktree and publishes its binding"
    );
    let next = claude_edit(&home, &worktree, &data_root, "toolu_unbound_next");
    assert!(
        matches!(next.as_str(), "hook_v2_accepted" | "hook_v2_spooled"),
        "later edits admit through the worktree's own binding, got {next}"
    );
}
