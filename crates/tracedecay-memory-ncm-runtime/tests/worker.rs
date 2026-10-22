#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![doc = "Process-level acceptance tests for the bounded NCM worker transport."]

use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::io::Cursor;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Barrier, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
#[cfg(unix)]
use tracedecay_memory_ncm_core::types::NcmConfig;
use tracedecay_memory_ncm_core::types::SourceId;
use tracedecay_memory_ncm_runtime::client::{ClientError, WorkerClient, WorkerOptions};
#[cfg(unix)]
use tracedecay_memory_ncm_runtime::embedding::doubles::HashEncoder;
#[cfg(unix)]
use tracedecay_memory_ncm_runtime::engine::FaultPoint;
#[cfg(unix)]
use tracedecay_memory_ncm_runtime::engine::NcmEngine;
use tracedecay_memory_ncm_runtime::engine::{ObserveRequest, Outcome, RejectReason};
use tracedecay_memory_ncm_runtime::platform::current_worker_platform_capability;
use tracedecay_memory_ncm_runtime::ports::Deadline;
#[cfg(unix)]
use tracedecay_memory_ncm_runtime::ports::StateRoot;
use tracedecay_memory_ncm_runtime::wire::{
    self, MAX_REPLY_BYTES, MAX_REQUEST_BYTES, Operation, PROTOCOL_IDENTITY, PROTOCOL_VERSION,
    Reply, Request,
};
#[cfg(unix)]
use tracedecay_memory_ncm_runtime::worker::{ServeOptions, serve_with_options};
use tracedecay_memory_ncm_runtime::worker_artifact::{
    WORKER_EXECUTABLE_NAME, WORKER_MANIFEST_NAME, current_target_triple, trusted_worker_manifest,
};

static WORKER_BINARY: OnceLock<PathBuf> = OnceLock::new();

fn worker_binary() -> PathBuf {
    WORKER_BINARY
        .get_or_init(|| {
            let path = std::env::var_os("CARGO_BIN_EXE_tracedecay-ncm-worker")
                .map(PathBuf::from)
                .expect("Bazel must supply the NCM worker executable");
            assert!(path.is_absolute(), "NCM worker executable must be absolute");
            assert!(path.is_file(), "NCM worker executable must exist");
            path
        })
        .clone()
}
const CALL_DEADLINE: Duration = Duration::from_secs(5);

fn namespace(index: u8) -> String {
    format!("{index:02x}{}", "0".repeat(62))
}

fn options() -> WorkerOptions {
    WorkerOptions {
        test_double: true,
        reconciliation_deadline: CALL_DEADLINE,
        ..WorkerOptions::default()
    }
}

fn client(root: &TempDir) -> WorkerClient {
    WorkerClient::spawn(worker_binary(), root.path(), options()).expect("worker client starts")
}

#[cfg(unix)]
fn test_config() -> NcmConfig {
    let mut config = NcmConfig {
        terrain_resolution: 3,
        ..NcmConfig::default()
    };
    config.stm.n_centers = 8;
    config.stm.top_k_read = 8;
    config.stm.top_k_write = 8;
    config.ltm.n_centers = 8;
    config.ltm.top_k_read = 8;
    config.ltm.top_k_write = 8;
    config.hybrid_candidates = 8;
    config
}

#[cfg(unix)]
fn direct_observe(
    engine: &NcmEngine,
    namespace: &str,
    source: &str,
    key: &str,
    value: &str,
    idempotency_key: &str,
) {
    let mut request = ObserveRequest {
        idempotency_key: idempotency_key.to_owned(),
        payload_sha256: String::new(),
        source: SourceId(source.to_owned()),
        key_text: key.to_owned(),
        value_text: value.to_owned(),
        affect: None,
        surprise: 0.4,
        intensity: 1.0,
        provenance: json!({"origin": "worker-restart-test"}),
        deadline: Deadline {
            remaining_ms: u64::MAX,
        },
    };
    request.payload_sha256 = request
        .canonical_payload_sha256()
        .expect("direct observe payload serializes");
    assert_eq!(engine.observe(namespace, request).outcome, Outcome::Success);
}

#[cfg(unix)]
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn opaque_id(namespace: &str, kind: &[u8], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.ncm.opaque-id.v1\0");
    for field in [namespace.as_bytes(), kind, value.as_bytes()] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn worker_key(namespace: &str, public_key: &str) -> String {
    opaque_id(namespace, b"idempotency-key", public_key)
}

fn observe_payload(idempotency_key: &str, key: &str, value: &str) -> Value {
    observe_payload_for_source(
        idempotency_key,
        &format!("source-{idempotency_key}"),
        key,
        value,
    )
}

fn observe_payload_for_source(
    idempotency_key: &str,
    source: &str,
    key: &str,
    value: &str,
) -> Value {
    observe_payload_with_provenance(
        idempotency_key,
        source,
        key,
        value,
        json!({"origin": "worker-test"}),
    )
}

#[cfg(unix)]
fn common_observe_payload(idempotency_key: &str, key: &str, value: &str) -> Value {
    let capsule = serde_json::to_vec(&json!({"origin": "common-maintenance-worker-test"}))
        .expect("common capsule serializes");
    observe_payload_with_provenance(
        idempotency_key,
        &format!("source-{idempotency_key}"),
        key,
        value,
        json!({
            "common_capsule": {
                "version": 1,
                "sha256": digest(&capsule),
                "bytes": capsule,
            }
        }),
    )
}

fn observe_payload_with_provenance(
    idempotency_key: &str,
    source: &str,
    key: &str,
    value: &str,
    provenance: Value,
) -> Value {
    let mut request = ObserveRequest {
        idempotency_key: idempotency_key.to_owned(),
        payload_sha256: String::new(),
        source: SourceId(source.to_owned()),
        key_text: key.to_owned(),
        value_text: value.to_owned(),
        affect: None,
        surprise: 0.4,
        intensity: 1.0,
        provenance,
        deadline: Deadline {
            remaining_ms: u64::MAX,
        },
    };
    request.payload_sha256 = request
        .canonical_payload_sha256()
        .expect("canonical observe payload serializes");
    json!({
        "idempotency_key": request.idempotency_key,
        "payload_sha256": request.payload_sha256,
        "source": request.source.0,
        "key_text": request.key_text,
        "value_text": request.value_text,
        "affect": request.affect,
        "surprise": request.surprise,
        "intensity": request.intensity,
        "provenance": request.provenance
    })
}

#[cfg(unix)]
fn common_maintenance_control(
    namespace: &str,
    idempotency_key: &str,
    operation_id: &str,
    expected_generation: u64,
) -> Value {
    common_maintenance_control_page(
        namespace,
        idempotency_key,
        operation_id,
        expected_generation,
        100,
        None,
    )
}

#[cfg(unix)]
fn common_maintenance_control_page(
    namespace: &str,
    public_idempotency_key: &str,
    operation_id: &str,
    expected_generation: u64,
    maximum_items: u64,
    resume_cursor: Option<&str>,
) -> Value {
    let idempotency_key = worker_key(namespace, public_idempotency_key);
    let mut control = json!({
        "action": "maintenance",
        "idempotency_key": idempotency_key,
        "expected_generation": expected_generation,
        "task": "repair",
        "maximum_items": maximum_items,
        "maximum_bytes": 1_048_576,
        "maximum_duration_millis": 60_000,
        "dry_run": false,
        "resume_cursor": resume_cursor,
        "policy_revision": 1,
        "extensions": [],
    });
    let semantics = json!({
        "action": "maintenance",
        "task": control["task"],
        "dry_run": control["dry_run"],
        "maximum_items": control["maximum_items"],
        "maximum_bytes": control["maximum_bytes"],
        "maximum_duration_millis": control["maximum_duration_millis"],
        "resume_cursor": control["resume_cursor"],
        "policy_revision": control["policy_revision"],
        "extensions": control["extensions"],
    });
    let admission = serde_json::to_vec(&json!({
        "namespace": namespace,
        "operation_id": operation_id,
        "idempotency_key": public_idempotency_key,
        "request_semantic_sha256": digest(
            &serde_json::to_vec(&semantics).expect("maintenance semantics serialize")
        ),
    }))
    .expect("maintenance admission serializes");
    control["maintenance_capsule"] = json!({
        "version": 1,
        "sha256": digest(&admission),
        "bytes": admission,
    });
    control
}

fn raw_worker(root: &Path) -> (Child, ChildStdin, ChildStdout) {
    let mut child = Command::new(worker_binary())
        .arg("--state-root")
        .arg(root)
        .arg("--test-double")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("raw worker starts");
    let stdin = child.stdin.take().expect("worker stdin is piped");
    let stdout = child.stdout.take().expect("worker stdout is piped");
    (child, stdin, stdout)
}

fn write_request(stdin: &mut ChildStdin, request: &Request) {
    stdin
        .write_all(&wire::encode_request(request).expect("request encodes"))
        .expect("request writes");
    stdin.flush().expect("request flushes");
}

fn read_reply(stdout: &mut ChildStdout) -> Reply {
    wire::read_reply(stdout)
        .expect("reply frame is valid")
        .expect("reply exists")
}

/// Forced, uncatchable termination on each platform.
fn force_kill(pid: u32) {
    let mut kill = if cfg!(windows) {
        let mut taskkill = Command::new("taskkill");
        taskkill.args(["/F", "/PID"]);
        taskkill
    } else {
        let mut kill = Command::new("kill");
        kill.arg("-9");
        kill
    };
    assert!(
        kill.arg(pid.to_string())
            .status()
            .expect("kill command runs")
            .success(),
        "force kill of worker {pid}"
    );
}

fn process_exists(pid: u32) -> bool {
    let mut inspection = if cfg!(windows) {
        let mut powershell = Command::new("powershell.exe");
        // Only the specific missing-PID result means exited. A failed query,
        // including access denial, must fail the reaping assertion.
        powershell.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
        powershell.arg(format!(
            "$ErrorActionPreference = 'Stop'; \
             try {{ $null = Get-Process -Id {pid}; exit 0 }} \
             catch {{ \
               if ($_.FullyQualifiedErrorId -eq \
                 'NoProcessFoundForGivenId,Microsoft.PowerShell.Commands.GetProcessCommand') \
               {{ exit 3 }}; throw \
             }}"
        ));
        powershell
    } else {
        let mut ps = Command::new("ps");
        ps.args(["-p", &pid.to_string(), "-o", "pid="]);
        ps
    };
    let output = inspection.output().expect("inspect worker process");
    let absent = if cfg!(windows) { 3 } else { 1 };
    match output.status.code() {
        Some(0) => true,
        Some(code)
            if code == absent
                && (cfg!(windows) || (output.stdout.is_empty() && output.stderr.is_empty())) =>
        {
            false
        }
        _ => panic!(
            "could not inspect worker {pid}: {}, stdout={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    }
}

fn install_trusted_worker_manifest(binary: &Path) {
    let destination = binary
        .parent()
        .expect("worker fixture has a parent")
        .join(WORKER_MANIFEST_NAME);
    fs::write(destination, trusted_worker_manifest()).expect("write trusted worker manifest");
}

fn current_target_is_pinned() -> bool {
    current_worker_platform_capability().is_supported()
}

#[test]
fn handshake_observe_and_recall_round_trip() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(1);

    let handshake = client
        .call(
            Request::new(1, 0, Operation::Handshake, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("handshake succeeds");
    assert_eq!(handshake.outcome, Outcome::Success);
    assert_eq!(handshake.payload.as_ref().unwrap()["ready"], true);
    let health = client
        .call(
            Request::new(4, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("health succeeds");
    assert_eq!(health.payload.as_ref().unwrap()["process_alive"], true);
    assert_eq!(health.payload.as_ref().unwrap()["encoder_ready"], true);

    let observe = client
        .call(
            Request::new(
                2,
                0,
                Operation::Observe,
                &ns,
                observe_payload("round-trip", "garden bird", "a robin arrived"),
            ),
            CALL_DEADLINE,
        )
        .expect("observe succeeds");
    assert_eq!(observe.outcome, Outcome::Success);
    assert_eq!(observe.payload.as_ref().unwrap()["replayed"], false);

    let recall = client
        .call(
            Request::new(
                3,
                0,
                Operation::Recall,
                &ns,
                json!({"query_text": "garden bird", "top_k": 4}),
            ),
            CALL_DEADLINE,
        )
        .expect("recall succeeds");
    assert_eq!(recall.outcome, Outcome::Success);
    assert!(recall.payload.is_some());
}

#[test]
fn raw_maintenance_requires_common_control() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let reply = client
        .call(
            Request::new(
                5,
                0,
                Operation::Maintenance,
                namespace(5),
                json!({
                    "idempotency_key": "raw-maintenance",
                    "kind": {"advance": {"ticks": 1}}
                }),
            ),
            CALL_DEADLINE,
        )
        .expect("raw maintenance rejection is returned");
    assert_eq!(
        reply.outcome,
        Outcome::Rejected(RejectReason::InvalidRequest(
            "maintenance requires common control".to_owned()
        ))
    );
    assert_eq!(reply.payload, None);
}

#[test]
fn snapshot_file_transport_crosses_bounded_frames_and_cleans_files() {
    let root = TempDir::new().expect("temp root");
    let source_client = client(&root);
    let ns = namespace(12);
    let observe = source_client
        .call(
            Request::new(
                1,
                0,
                Operation::Observe,
                &ns,
                observe_payload("snapshot-file", "large snapshot", "transport value"),
            ),
            CALL_DEADLINE,
        )
        .expect("observe succeeds");
    assert_eq!(observe.outcome, Outcome::Success);

    let exported = source_client
        .call(
            Request::new(2, 0, Operation::SnapshotExport, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("snapshot export succeeds through file transport");
    assert_eq!(exported.outcome, Outcome::Success);
    let payload = exported.payload.expect("hydrated snapshot payload");
    assert!(payload.get("snapshot_file").is_none());
    let snapshot = payload["bytes"]
        .as_array()
        .expect("snapshot byte array")
        .clone();
    assert!(
        snapshot.len() > MAX_REPLY_BYTES,
        "negative control: direct JSON bytes cannot fit the 1 MiB reply frame"
    );

    let target_root = TempDir::new().expect("target temp root");
    let target = client(&target_root);
    let restored = target
        .call(
            Request::new(
                3,
                0,
                Operation::SnapshotRestore,
                &ns,
                json!({"idempotency_key": "snapshot-file-restore", "snapshot": snapshot, "blocked_sources": []}),
            ),
            CALL_DEADLINE,
        )
        .expect("snapshot restore succeeds through file transport");
    assert_eq!(restored.outcome, Outcome::Success, "{restored:?}");
    let snapshot_dir = target_root
        .path()
        .join("namespaces")
        .join(&ns)
        .join("snapshots");
    let remaining = fs::read_dir(snapshot_dir)
        .expect("read snapshot transport directory")
        .count();
    assert_eq!(remaining, 0, "transport files must be consumed");
    let recall = target
        .call(
            Request::new(
                4,
                0,
                Operation::Recall,
                &ns,
                json!({"query_text": "large snapshot", "top_k": 4}),
            ),
            CALL_DEADLINE,
        )
        .expect("restored namespace recalls");
    assert_eq!(recall.outcome, Outcome::Success);
}

#[test]
fn snapshot_restore_requires_authority_and_scrubs_predelete_snapshot_on_fresh_worker() {
    let source_root = TempDir::new().expect("source temp root");
    let source = client(&source_root);
    let ns = namespace(13);
    let source_id = "source-predelete-worker";
    let observed = source
        .call(
            Request::new(
                1,
                0,
                Operation::Observe,
                &ns,
                observe_payload_for_source(
                    "predelete-worker",
                    source_id,
                    "private key",
                    "private value",
                ),
            ),
            CALL_DEADLINE,
        )
        .expect("observe succeeds");
    assert_eq!(observed.outcome, Outcome::Success, "{observed:?}");
    let exported = source
        .call(
            Request::new(2, 0, Operation::SnapshotExport, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("snapshot export succeeds");
    assert_eq!(exported.outcome, Outcome::Success, "{exported:?}");
    let snapshot: Vec<u8> = serde_json::from_value(exported.payload.unwrap()["bytes"].clone())
        .expect("snapshot bytes decode");
    let deleted = source
        .call(
            Request::new(
                3,
                0,
                Operation::DeleteBySource,
                &ns,
                json!({"idempotency_key":"delete-predelete-worker","source":source_id}),
            ),
            CALL_DEADLINE,
        )
        .expect("delete succeeds");
    assert_eq!(deleted.outcome, Outcome::Success, "{deleted:?}");

    let target_root = TempDir::new().expect("target temp root");
    let target = client(&target_root);
    let missing_authority = target
        .call(
            Request::new(
                4,
                0,
                Operation::SnapshotRestore,
                &ns,
                json!({"idempotency_key":"restore-without-authority","snapshot":snapshot.clone()}),
            ),
            CALL_DEADLINE,
        )
        .expect("missing authority is a request rejection");
    assert!(matches!(missing_authority.outcome, Outcome::Rejected(_)));
    let empty = target
        .call(
            Request::new(5, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("empty target inspection succeeds");
    assert_eq!(empty.outcome, Outcome::Empty, "{empty:?}");

    let restored = target
        .call(
            Request::new(
                6,
                0,
                Operation::SnapshotRestore,
                &ns,
                json!({"idempotency_key":"restore-with-authority","snapshot":snapshot,"blocked_sources":[source_id]}),
            ),
            CALL_DEADLINE,
        )
        .expect("restore with authority succeeds");
    assert_eq!(restored.outcome, Outcome::Success, "{restored:?}");
    let inspected = target
        .call(
            Request::new(7, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("restored inspection succeeds");
    assert_eq!(inspected.outcome, Outcome::Success, "{inspected:?}");
    assert_eq!(inspected.payload.unwrap()["records"], 0);
    drop(target);

    let reopened = client(&target_root);
    let restarted = reopened
        .call(
            Request::new(8, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("restarted inspection succeeds");
    assert_eq!(restarted.outcome, Outcome::Success, "{restarted:?}");
    assert_eq!(restarted.payload.unwrap()["records"], 0);
}

#[test]
fn oversized_header_is_rejected_before_body_allocation_and_worker_continues() {
    let root = TempDir::new().expect("temp root");
    let (mut child, mut stdin, mut stdout) = raw_worker(root.path());
    let oversized = u32::try_from(MAX_REQUEST_BYTES + 1).expect("bound fits u32");
    stdin
        .write_all(&oversized.to_be_bytes())
        .expect("oversized header writes");
    stdin.flush().expect("header flushes");

    let rejected = read_reply(&mut stdout);
    assert_eq!(rejected.id, 0);
    assert_eq!(rejected.error.as_ref().unwrap().kind, "oversized_frame");

    write_request(
        &mut stdin,
        &Request::new(9, 1000, Operation::Health, "", json!({})),
    );
    let health = read_reply(&mut stdout);
    assert_eq!(health.id, 9);
    assert_eq!(health.outcome, Outcome::Success);
    assert!(child.try_wait().expect("worker status").is_none());
    drop(stdin);
    assert!(child.wait().expect("worker exits").success());
}

#[test]
fn malformed_json_gets_typed_error_and_next_request_works() {
    let root = TempDir::new().expect("temp root");
    let (mut child, mut stdin, mut stdout) = raw_worker(root.path());
    let malformed = b"{not-json";
    stdin
        .write_all(&(malformed.len() as u32).to_be_bytes())
        .expect("malformed length writes");
    stdin.write_all(malformed).expect("malformed body writes");
    stdin.flush().expect("malformed frame flushes");
    let rejected = read_reply(&mut stdout);
    assert_eq!(rejected.error.as_ref().unwrap().kind, "malformed_json");

    write_request(
        &mut stdin,
        &Request::new(10, 1000, Operation::Health, "", json!({})),
    );
    assert_eq!(read_reply(&mut stdout).outcome, Outcome::Success);
    drop(stdin);
    assert!(child.wait().expect("worker exits").success());
}

#[test]
fn cancelled_queued_request_starts_no_child_and_owner_remains_usable() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = TempDir::new().unwrap();
    let client = client(&root);
    let checkpoints = Arc::new(AtomicUsize::new(0));
    let probe = Arc::clone(&checkpoints);
    // The caller's pre-enqueue check passes; every later queue/owner check
    // observes cancellation, so this proves the queued path, not just entry.
    let result = client.call_cancellable(
        Request::new(18, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
        Arc::new(move || probe.fetch_add(1, Ordering::AcqRel) != 0),
    );
    assert_eq!(result, Err(ClientError::Cancelled));
    assert!(client.pid().is_none());
    assert!(checkpoints.load(Ordering::Acquire) >= 2);
    let next = client
        .call(
            Request::new(19, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(next.outcome, Outcome::Success);
}

#[test]
fn cancellation_before_frame_keeps_live_child_and_owner_incarnation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = TempDir::new().unwrap();
    let client = client(&root);
    client
        .call(
            Request::new(180, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    let pid = client.pid();
    let incarnation = client.owner_incarnation();
    let owner_checks = Arc::new(AtomicUsize::new(0));
    let probe = Arc::clone(&owner_checks);
    let result = client.call_cancellable(
        Request::new(181, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
        Arc::new(move || {
            // The dequeue check passes. The owner cancels at execute's
            // pre-write check; caller polling cannot advance this boundary.
            thread::current().name() == Some("ncm-worker-owner")
                && probe.fetch_add(1, Ordering::AcqRel) >= 1
        }),
    );
    assert_eq!(result, Err(ClientError::Cancelled));
    assert!(owner_checks.load(Ordering::Acquire) >= 2);
    assert_eq!(client.pid(), pid);
    assert_eq!(client.owner_incarnation(), incarnation);
    let next = client
        .call(
            Request::new(182, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(next.outcome, Outcome::Success);
    assert_eq!(client.pid(), pid);
    assert_eq!(client.owner_incarnation(), incarnation);
}

#[test]
fn cancellation_after_ready_handshake_keeps_transport_and_has_no_unknown_effect() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = TempDir::new().unwrap();
    let client = client(&root);
    let ns = namespace(18);
    let ready = client
        .call(
            Request::new(183, 0, Operation::Handshake, &ns, json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(ready.outcome, Outcome::Success);
    let pid = client.pid();
    let incarnation = client.owner_incarnation();
    let owner_checks = Arc::new(AtomicUsize::new(0));
    let probe = Arc::clone(&owner_checks);
    let key = "cancelled-before-observe-frame";
    let result = client.call_cancellable(
        Request::new(
            184,
            0,
            Operation::Observe,
            &ns,
            observe_payload(key, "unwritten key", "unwritten value"),
        ),
        CALL_DEADLINE,
        Arc::new(move || {
            // Dequeue and reuse of the fully consumed namespace handshake
            // pass; cancellation arrives before the mutation's frame.
            thread::current().name() == Some("ncm-worker-owner")
                && probe.fetch_add(1, Ordering::AcqRel) >= 2
        }),
    );
    assert_eq!(result, Err(ClientError::Cancelled));
    assert!(owner_checks.load(Ordering::Acquire) >= 3);
    assert_eq!(client.pid(), pid);
    assert_eq!(client.owner_incarnation(), incarnation);
    assert_eq!(
        client.reconcile_unknown(&ns, key),
        Err(ClientError::UnknownIdempotencyKey)
    );
    let next = client
        .call(
            Request::new(185, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(next.outcome, Outcome::Success);
    assert_eq!(client.pid(), pid);
    assert_eq!(client.owner_incarnation(), incarnation);
}

#[test]
fn inflight_cancellation_reaps_child_and_next_request_recovers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = TempDir::new().unwrap();
    let client = client(&root);
    client
        .call(
            Request::new(15, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    let ready_incarnation = client.owner_incarnation().unwrap();
    let owner_checks = Arc::new(AtomicUsize::new(0));
    let probe = Arc::clone(&owner_checks);
    let started = Instant::now();
    let result = client.call_cancellable(
        Request::new(
            16,
            0,
            Operation::Handshake,
            namespace(1),
            json!({"test_sleep_before_ms": 1000}),
        ),
        CALL_DEADLINE,
        Arc::new(move || {
            // Dequeue and pre-write checks pass. The first ACK-wait check
            // occurs after handing the frame to the real worker's writer.
            thread::current().name() == Some("ncm-worker-owner")
                && probe.fetch_add(1, Ordering::AcqRel) >= 2
        }),
    );
    assert_eq!(result, Err(ClientError::Cancelled));
    assert!(owner_checks.load(Ordering::Acquire) >= 3);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(client.pid().is_none(), "cancelled child must be reaped");
    let next = client
        .call(
            Request::new(17, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(next.outcome, Outcome::Success);
    assert!(client.pid().is_some());
    assert_eq!(client.owner_incarnation(), Some(ready_incarnation + 1));
}

#[test]
fn deadline_kills_mutating_worker_and_next_call_respawns() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(2);
    // Readiness is a separate, non-mutating exchange. Prove it before the
    // mutation's deadline so a cold handshake cannot own the timeout.
    let ready = client
        .call(
            Request::new(19, 0, Operation::Handshake, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("namespace readiness succeeds before bounded mutation");
    assert_eq!(ready.outcome, Outcome::Success);
    let ready_incarnation = client
        .owner_incarnation()
        .expect("ready worker incarnation");
    let mut payload = json!({
        "idempotency_key": "slow-maintenance",
        "kind": {"advance": {"ticks": 10_000}}
    });
    payload["test_sleep_before_ms"] = json!(1000);
    let started = Instant::now();
    let result = client.call(
        Request::new(20, 0, Operation::Maintenance, &ns, payload),
        Duration::from_millis(30),
    );
    assert_eq!(result, Err(ClientError::EffectUnknown { op_id: 20 }));
    assert!(started.elapsed() <= Duration::from_millis(300));
    assert_eq!(client.pid(), None);

    let health = client
        .call(
            Request::new(21, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("next call respawns");
    assert_eq!(health.outcome, Outcome::Success);
    assert!(client.pid().is_some());
    assert_eq!(client.owner_incarnation(), Some(ready_incarnation + 1));
}

#[cfg(unix)]
#[test]
fn observe_killed_after_commit_reconciles_without_second_record() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(3);
    let mut payload = observe_payload("reconcile-observe", "stable key", "stable value");
    // This existing fault holds a successful, non-replayed mutation's reply
    // after commit. The ordinary request deadline kills the worker. Only the
    // durable replay assertion below proves that commit preceded the kill.
    payload["test_sleep_after_commit_ms"] = json!(CALL_DEADLINE.as_millis() as u64);
    let result = client.call(
        Request::new(30, 0, Operation::Observe, &ns, payload),
        CALL_DEADLINE,
    );
    if let Ok(reply) = &result {
        let outcome = match &reply.outcome {
            Outcome::Success => "success",
            Outcome::Empty => "empty",
            Outcome::Rejected(_) => "rejected",
            Outcome::Busy => "busy",
            Outcome::Cancelled => "cancelled",
            Outcome::EffectUnknown => "effect_unknown",
            Outcome::Incompatible => "incompatible",
            Outcome::Corrupt => "corrupt",
            Outcome::Unavailable(_) => "unavailable",
            Outcome::Unsupported => "unsupported",
            Outcome::BudgetExceeded => "budget_exceeded",
        };
        panic!("postcommit reply hold returned before the kill: outcome={outcome}");
    }
    assert_eq!(result, Err(ClientError::EffectUnknown { op_id: 30 }));
    assert_eq!(
        client.pid(),
        None,
        "deadline must reap the supervised child"
    );

    let replay = client
        .reconcile_unknown(&ns, "reconcile-observe")
        .expect("receipt replay succeeds after restart");
    assert_eq!(replay.outcome, Outcome::Success);
    assert_eq!(replay.state_generation, 1);
    assert_eq!(
        replay.payload.as_ref().unwrap()["replayed"],
        true,
        "the first attempt must have committed before it was killed",
    );
    let inspection = client
        .call(
            Request::new(31, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds");
    assert_eq!(inspection.outcome, Outcome::Success);
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 1);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 1);
    assert_eq!(inspection.payload.as_ref().unwrap()["tick"], 1);
}

#[cfg(unix)]
#[test]
fn observe_killed_before_commit_reopens_and_retries_without_replay() {
    let root = TempDir::new().expect("temp root");
    let worker = client(&root);
    let ns = namespace(17);
    worker
        .call(
            Request::new(170, 0, Operation::Handshake, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("namespace handshake succeeds before mutation");

    let key = "observe-before-commit";
    let mut payload = observe_payload(key, "before commit key", "before commit value");
    // The delay is before dispatching to the engine. A shorter caller deadline
    // therefore kills the child while no receipt can have been committed.
    payload["test_sleep_before_ms"] = json!(1_000);
    let interrupted = worker.call(
        Request::new(171, 0, Operation::Observe, &ns, payload.clone()),
        Duration::from_millis(50),
    );
    assert_eq!(
        interrupted,
        Err(ClientError::EffectUnknown { op_id: 171 }),
        "a sent mutating request must be retained for reconciliation"
    );
    assert_eq!(worker.pid(), None, "deadline must reap the child process");

    let retried = worker
        .reconcile_unknown(&ns, key)
        .expect("pre-commit request retries after the child is reopened");
    assert_eq!(retried.outcome, Outcome::Success, "{retried:?}");
    assert_eq!(retried.state_generation, 1);
    assert_eq!(retried.payload.as_ref().unwrap()["replayed"], false);

    drop(worker);
    let reopened = client(&root);
    let durable_retry = reopened
        .call(
            Request::new(172, 0, Operation::Observe, &ns, payload),
            CALL_DEADLINE,
        )
        .expect("durable retry succeeds after reopening the client");
    assert_eq!(durable_retry.outcome, Outcome::Success, "{durable_retry:?}");
    assert_eq!(durable_retry.state_generation, 1);
    assert_eq!(durable_retry.payload.as_ref().unwrap()["replayed"], true);

    let inspection = reopened
        .call(
            Request::new(173, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after the retry");
    assert_eq!(inspection.outcome, Outcome::Success);
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 1);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 1);
}

#[cfg(unix)]
#[test]
fn common_maintenance_killed_after_commit_reconciles_nested_idempotency_key() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(18);
    let observe = client
        .call(
            Request::new(
                200,
                0,
                Operation::Observe,
                &ns,
                common_observe_payload(
                    "common-maintenance-seed",
                    "common maintenance key",
                    "common maintenance value",
                ),
            ),
            CALL_DEADLINE,
        )
        .expect("common maintenance seed succeeds");
    assert_eq!(observe.outcome, Outcome::Success, "{observe:?}");
    assert_eq!(observe.state_generation, 1);

    let key = "common-maintenance-after-commit";
    let control = common_maintenance_control(&ns, key, "01993262-4d00-0000-8000-000000000018", 1);
    // The normal operation budget permits the mutation; the existing reply hold
    // outlasts that budget. The replay assertion below proves commit preceded death.
    let request = Request::new(
        201,
        0,
        Operation::Maintenance,
        &ns,
        json!({
            "common_control": control,
            "test_sleep_after_commit_ms": CALL_DEADLINE.as_millis() as u64,
        }),
    );
    let result = client.call(request, CALL_DEADLINE);
    assert_eq!(result, Err(ClientError::EffectUnknown { op_id: 201 }));
    assert_eq!(client.pid(), None, "deadline must reap the worker");

    let replay = client
        .reconcile_unknown(&ns, &worker_key(&ns, key))
        .expect("common maintenance receipt replays after restart");
    assert_eq!(replay.outcome, Outcome::Success, "{replay:?}");
    assert_eq!(replay.state_generation, 2);
    assert_eq!(replay.payload.as_ref().unwrap()["replayed"], true);

    let inspection = client
        .call(
            Request::new(202, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after maintenance reconciliation");
    assert_eq!(inspection.outcome, Outcome::Success, "{inspection:?}");
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 1);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 2);
    assert_eq!(
        client.reconcile_unknown(&ns, &worker_key(&ns, key)),
        Err(ClientError::UnknownIdempotencyKey)
    );
}

#[cfg(unix)]
#[test]
fn common_maintenance_killed_before_commit_retries_once() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(24);
    let observe = client
        .call(
            Request::new(
                240,
                0,
                Operation::Observe,
                &ns,
                common_observe_payload(
                    "common-maintenance-before-commit-seed",
                    "common maintenance before commit key",
                    "common maintenance before commit value",
                ),
            ),
            CALL_DEADLINE,
        )
        .expect("common maintenance before-commit seed succeeds");
    assert_eq!(observe.outcome, Outcome::Success, "{observe:?}");
    assert_eq!(observe.state_generation, 1);

    let public_key = "common-maintenance-before-commit";
    let control =
        common_maintenance_control(&ns, public_key, "01993262-4d00-0000-8000-000000000024", 1);
    let request = Request::new(
        241,
        0,
        Operation::Maintenance,
        &ns,
        json!({
            "common_control": control,
            "test_sleep_before_ms": 1_000,
        }),
    );
    let timed = client.call(request.clone(), Duration::from_millis(50));
    assert_eq!(timed, Err(ClientError::EffectUnknown { op_id: 241 }));
    assert_eq!(client.pid(), None, "deadline must reap the worker");

    let reconciled = client
        .reconcile_unknown(&ns, &worker_key(&ns, public_key))
        .expect("maintenance retries after death before the common commit");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    assert_eq!(reconciled.state_generation, 2);
    assert_eq!(reconciled.payload.as_ref().unwrap()["replayed"], false);

    // A second request with the same provider key observes the one retained
    // receipt and cannot advance the generation again.
    let duplicate = client
        .call(
            Request::new(
                242,
                0,
                Operation::Maintenance,
                &ns,
                json!({
                    "common_control": common_maintenance_control(
                        &ns,
                        public_key,
                        "01993262-4d00-0000-8000-000000000024",
                        2,
                    ),
                }),
            ),
            CALL_DEADLINE,
        )
        .expect("duplicate maintenance request replays");
    assert_eq!(duplicate.outcome, Outcome::Success, "{duplicate:?}");
    assert_eq!(duplicate.state_generation, 2);
    assert_eq!(duplicate.payload.as_ref().unwrap()["replayed"], true);

    let inspection = client
        .call(
            Request::new(243, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after before-commit recovery");
    assert_eq!(inspection.outcome, Outcome::Success, "{inspection:?}");
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 2);
}

#[cfg(unix)]
#[test]
fn common_maintenance_pages_restart_worker_between_continuations() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(22);
    for index in 0..3_u64 {
        let observe = client
            .call(
                Request::new(
                    220 + index,
                    0,
                    Operation::Observe,
                    &ns,
                    common_observe_payload(
                        &format!("common-maintenance-page-seed-{index}"),
                        &format!("page key {index}"),
                        &format!("page value {index}"),
                    ),
                ),
                CALL_DEADLINE,
            )
            .expect("common maintenance page seed succeeds");
        assert_eq!(observe.outcome, Outcome::Success, "{observe:?}");
    }
    let generation = 3;
    let key_prefix = "common-maintenance-restart-pages";
    let operation_prefix = "01993262-4d00-0000-8000-000000000022";
    let mut cursor = None;
    let mut final_identity = None;

    for (index, expected_partial) in [(0_u64, true), (1, true), (2, false)] {
        // A host continuation mints a fresh public key and operation ID for
        // every page. The cursor is the durable authorization boundary.
        let page_key = format!("{key_prefix}-{index}");
        let page_operation_id = format!("{operation_prefix}-{index}");
        let control = common_maintenance_control_page(
            &ns,
            &page_key,
            &page_operation_id,
            generation,
            1,
            cursor.as_deref(),
        );
        let reply = client
            .call(
                Request::new(
                    230 + index,
                    0,
                    Operation::Maintenance,
                    &ns,
                    json!({"common_control": control}),
                ),
                CALL_DEADLINE,
            )
            .expect("maintenance page succeeds after worker start or restart");
        assert_eq!(reply.outcome, Outcome::Success, "{reply:?}");
        assert_eq!(reply.payload.as_ref().unwrap()["partial"], expected_partial);
        if expected_partial {
            assert_eq!(reply.state_generation, generation);
            assert_eq!(reply.payload.as_ref().unwrap()["scanned_items"], 1);
            cursor = Some(
                reply.payload.as_ref().unwrap()["resume_cursor"]
                    .as_str()
                    .expect("partial page returns a resume cursor")
                    .to_owned(),
            );

            let pid = client.pid().expect("worker pid exists after page");
            force_kill(pid);
            let dead = client.call(
                Request::new(240 + index, 0, Operation::Health, "", json!({})),
                Duration::from_millis(500),
            );
            assert!(
                matches!(
                    dead,
                    Err(ClientError::MalformedReply(_))
                        | Err(ClientError::WorkerExited)
                        | Err(ClientError::Transport(_))
                ),
                "health must observe the killed worker: {dead:?}"
            );
            assert_eq!(client.pid(), None, "killed worker must be reaped");
        } else {
            assert_eq!(reply.payload.as_ref().unwrap()["scanned_items"], 1);
            assert_eq!(reply.state_generation, generation + 1);
            final_identity = Some((page_key, page_operation_id));
        }
    }

    let (final_key, final_operation_id) = final_identity.expect("final page identity is recorded");
    let replay_control = common_maintenance_control_page(
        &ns,
        &final_key,
        &final_operation_id,
        generation + 1,
        1,
        cursor.as_deref(),
    );
    let replay = client
        .call(
            Request::new(
                233,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": replay_control}),
            ),
            CALL_DEADLINE,
        )
        .expect("committed page retries after the final restart");
    assert_eq!(replay.outcome, Outcome::Success, "{replay:?}");
    assert_eq!(replay.state_generation, generation + 1);
    assert_eq!(replay.payload.as_ref().unwrap()["replayed"], true);

    let inspection = client
        .call(
            Request::new(234, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after paged maintenance");
    assert_eq!(inspection.outcome, Outcome::Success);
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 3);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 4);
}

#[cfg(unix)]
#[test]
fn common_maintenance_final_paged_commit_replays_after_worker_death() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(25);
    for index in 0..3_u64 {
        let observe = client
            .call(
                Request::new(
                    250 + index,
                    0,
                    Operation::Observe,
                    &ns,
                    common_observe_payload(
                        &format!("common-maintenance-final-page-seed-{index}"),
                        &format!("final page key {index}"),
                        &format!("final page value {index}"),
                    ),
                ),
                CALL_DEADLINE,
            )
            .expect("common maintenance final-page seed succeeds");
        assert_eq!(observe.outcome, Outcome::Success, "{observe:?}");
    }
    let generation = 3;
    let first = common_maintenance_control_page(
        &ns,
        "common-maintenance-final-page-1",
        "01993262-4d00-0000-8000-000000000025-1",
        generation,
        1,
        None,
    );
    let first = client
        .call(
            Request::new(
                253,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": first}),
            ),
            CALL_DEADLINE,
        )
        .expect("first final-page continuation succeeds");
    assert_eq!(first.outcome, Outcome::Success, "{first:?}");
    assert_eq!(first.payload.as_ref().unwrap()["partial"], true);
    let first_cursor = first.payload.as_ref().unwrap()["resume_cursor"]
        .as_str()
        .expect("first page returns a cursor")
        .to_owned();

    let second = common_maintenance_control_page(
        &ns,
        "common-maintenance-final-page-2",
        "01993262-4d00-0000-8000-000000000025-2",
        generation,
        1,
        Some(&first_cursor),
    );
    let second = client
        .call(
            Request::new(
                254,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": second}),
            ),
            CALL_DEADLINE,
        )
        .expect("second final-page continuation succeeds");
    assert_eq!(second.outcome, Outcome::Success, "{second:?}");
    assert_eq!(second.payload.as_ref().unwrap()["partial"], true);
    let second_cursor = second.payload.as_ref().unwrap()["resume_cursor"]
        .as_str()
        .expect("second page returns a cursor")
        .to_owned();

    let final_key = "common-maintenance-final-page-3";
    let final_operation_id = "01993262-4d00-0000-8000-000000000025-3";
    let final_control = common_maintenance_control_page(
        &ns,
        final_key,
        final_operation_id,
        generation,
        1,
        Some(&second_cursor),
    );
    // Hold the postcommit reply through the normal operation deadline; durable
    // replay below establishes that this final page committed before worker death.
    let final_request = Request::new(
        255,
        0,
        Operation::Maintenance,
        &ns,
        json!({
            "common_control": final_control,
            "test_sleep_after_commit_ms": CALL_DEADLINE.as_millis() as u64,
        }),
    );
    let timed = client.call(final_request, CALL_DEADLINE);
    assert_eq!(timed, Err(ClientError::EffectUnknown { op_id: 255 }));
    assert_eq!(client.pid(), None, "deadline must reap the worker");

    let reconciled = client
        .reconcile_unknown(&ns, &worker_key(&ns, final_key))
        .expect("final page receipt replays after worker death");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    assert_eq!(reconciled.state_generation, generation + 1);
    assert_eq!(reconciled.payload.as_ref().unwrap()["replayed"], true);

    // Reissuing the final page with the same key is an exact replay and must
    // not create a second event or advance the generation.
    let duplicate = client
        .call(
            Request::new(
                256,
                0,
                Operation::Maintenance,
                &ns,
                json!({
                    "common_control": common_maintenance_control_page(
                        &ns,
                        final_key,
                        final_operation_id,
                        generation + 1,
                        1,
                        Some(&second_cursor),
                    ),
                }),
            ),
            CALL_DEADLINE,
        )
        .expect("duplicate final page replays");
    assert_eq!(duplicate.outcome, Outcome::Success, "{duplicate:?}");
    assert_eq!(duplicate.state_generation, generation + 1);
    assert_eq!(duplicate.payload.as_ref().unwrap()["replayed"], true);

    let inspection = client
        .call(
            Request::new(257, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after final-page recovery");
    assert_eq!(inspection.outcome, Outcome::Success, "{inspection:?}");
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 3);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 4);
}

#[cfg(unix)]
#[test]
fn common_maintenance_partial_page_deadline_reconciles_and_resumes() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(23);
    for index in 0..3_u64 {
        let observe = client
            .call(
                Request::new(
                    250 + index,
                    0,
                    Operation::Observe,
                    &ns,
                    common_observe_payload(
                        &format!("common-maintenance-deadline-seed-{index}"),
                        &format!("deadline page key {index}"),
                        &format!("deadline page value {index}"),
                    ),
                ),
                CALL_DEADLINE,
            )
            .expect("common maintenance deadline seed succeeds");
        assert_eq!(observe.outcome, Outcome::Success, "{observe:?}");
    }
    let generation = 3;
    let first_key = "common-maintenance-deadline-page-1";
    let first_operation_id = "01993262-4d00-0000-8000-000000000023-1";

    let first_control =
        common_maintenance_control_page(&ns, first_key, first_operation_id, generation, 1, None);
    let first = client
        .call(
            Request::new(
                260,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": first_control}),
            ),
            CALL_DEADLINE,
        )
        .expect("first maintenance page succeeds");
    assert_eq!(first.outcome, Outcome::Success, "{first:?}");
    assert_eq!(first.state_generation, generation);
    assert_eq!(first.payload.as_ref().unwrap()["partial"], true);
    let first_cursor = first.payload.as_ref().unwrap()["resume_cursor"]
        .as_str()
        .expect("first page returns a resume cursor")
        .to_owned();

    let second_key = "common-maintenance-deadline-page-2";
    let second_operation_id = "01993262-4d00-0000-8000-000000000023-2";
    let second_control = common_maintenance_control_page(
        &ns,
        second_key,
        second_operation_id,
        generation,
        1,
        Some(&first_cursor),
    );
    // The page only grants the next cursor; the test-double holds the
    // successful response after that grant. A caller deadline may therefore
    // expire after authorization without losing the durable continuation.
    let timed = client.call(
        Request::new(
            261,
            0,
            Operation::Maintenance,
            &ns,
            json!({
                "common_control": second_control,
                "test_sleep_after_commit_ms": 1_000,
            }),
        ),
        Duration::from_millis(50),
    );
    assert_eq!(timed, Err(ClientError::EffectUnknown { op_id: 261 }));
    assert_eq!(client.pid(), None, "deadline must reap the worker");

    let reconciled = client
        .reconcile_unknown(&ns, &worker_key(&ns, second_key))
        .expect("partial page reply reconciles after worker restart");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    assert_eq!(reconciled.state_generation, generation);
    assert_eq!(reconciled.payload.as_ref().unwrap()["partial"], true);
    assert_eq!(reconciled.payload.as_ref().unwrap()["scanned_items"], 1);
    let second_cursor = reconciled.payload.as_ref().unwrap()["resume_cursor"]
        .as_str()
        .expect("reconciled partial page returns its next cursor")
        .to_owned();

    let final_key = "common-maintenance-deadline-page-3";
    let final_operation_id = "01993262-4d00-0000-8000-000000000023-3";
    let final_control = common_maintenance_control_page(
        &ns,
        final_key,
        final_operation_id,
        generation,
        1,
        Some(&second_cursor),
    );
    let completed = client
        .call(
            Request::new(
                262,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": final_control}),
            ),
            CALL_DEADLINE,
        )
        .expect("final page commits after cursor reconciliation");
    assert_eq!(completed.outcome, Outcome::Success, "{completed:?}");
    assert_eq!(completed.state_generation, generation + 1);
    assert_eq!(completed.payload.as_ref().unwrap()["partial"], false);
    assert_eq!(completed.payload.as_ref().unwrap()["scanned_items"], 1);

    let retry_control = common_maintenance_control_page(
        &ns,
        final_key,
        final_operation_id,
        generation + 1,
        1,
        Some(&second_cursor),
    );
    let retry = client
        .call(
            Request::new(
                263,
                0,
                Operation::Maintenance,
                &ns,
                json!({"common_control": retry_control}),
            ),
            CALL_DEADLINE,
        )
        .expect("completed page retries as a retained receipt");
    assert_eq!(retry.outcome, Outcome::Success, "{retry:?}");
    assert_eq!(retry.state_generation, generation + 1);
    assert_eq!(retry.payload.as_ref().unwrap()["replayed"], true);

    let inspection = client
        .call(
            Request::new(264, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("inspection succeeds after deadline resume");
    assert_eq!(inspection.outcome, Outcome::Success);
    assert_eq!(inspection.payload.as_ref().unwrap()["records"], 3);
    assert_eq!(inspection.payload.as_ref().unwrap()["commit_seq"], 4);
}

#[cfg(unix)]
#[test]
fn common_replay_killed_after_commit_reconciles_the_nested_delivery_key() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(18);
    let page_key = "18".repeat(32);
    let delivery_key = "19".repeat(32);
    let source = "20".repeat(32);
    let mut observation = ObserveRequest {
        idempotency_key: delivery_key.clone(),
        payload_sha256: String::new(),
        source: SourceId(source.clone()),
        key_text: "common replay retained key".to_owned(),
        value_text: "common replay retained value".to_owned(),
        affect: None,
        surprise: 0.4,
        intensity: 1.0,
        provenance: json!({"common_capsule":{"version":1,"bytes":[],"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"selection":{"observation_identity":"22".repeat(32),"revision_digest":"23".repeat(32)}}),
        deadline: Deadline {
            remaining_ms: u64::MAX,
        },
    };
    observation.payload_sha256 = observation.canonical_payload_sha256().unwrap();
    let observation = json!({"idempotency_key":observation.idempotency_key,"payload_sha256":observation.payload_sha256,"source":observation.source.0,"key_text":observation.key_text,"value_text":observation.value_text,"affect":observation.affect,"surprise":observation.surprise,"intensity":observation.intensity,"provenance":observation.provenance});
    let request = Request::new(
        180,
        0,
        Operation::Replay,
        &ns,
        json!({
            "common_portability":{"action":"replay","idempotency_key":page_key,"expected_generation":0,"first_source_sequence":1,"last_source_sequence":1,"expected_previous_acknowledged_sequence":0,
                "items":[{"source_sequence":1,"receipt_digest":"24".repeat(32),"delivery_key":delivery_key,"source":source,"admitted":true,"blocked":false,"observation":observation}]},
            "test_sleep_after_commit_ms":CALL_DEADLINE.as_millis() as u64
        }),
    );
    assert_eq!(
        client.call(request, CALL_DEADLINE),
        Err(ClientError::EffectUnknown { op_id: 180 })
    );
    assert_eq!(client.pid(), None);
    let reconciled = client
        .reconcile_unknown(&ns, &page_key)
        .expect("nested replay key is retained");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    let result = reconciled.payload.unwrap();
    assert_eq!(
        result["replayed"], true,
        "first page committed before its reply was interrupted"
    );
    assert_eq!(result["applied_observations"], 1);
    assert_eq!(result["acknowledged_sequence"], 1);
    let inspected = client
        .call(
            Request::new(181, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(inspected.payload.as_ref().unwrap()["records"], 1);
    assert_eq!(inspected.payload.as_ref().unwrap()["tick"], 1);
    assert_eq!(
        client.reconcile_unknown(&ns, &page_key),
        Err(ClientError::UnknownIdempotencyKey)
    );
}

#[cfg(unix)]
#[test]
fn common_restore_file_killed_after_commit_reconciles_client_owned_backup() {
    let source_root = TempDir::new().expect("source root");
    let source = client(&source_root);
    let ns = namespace(19);
    let observed = source
        .call(
            Request::new(
                190,
                0,
                Operation::Observe,
                &ns,
                observe_payload(
                    "common-restore",
                    "restore durable key",
                    "restore durable value",
                ),
            ),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(observed.outcome, Outcome::Success);
    let exported = source
        .call(
            Request::new(191, 0, Operation::SnapshotExport, &ns, json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(exported.outcome, Outcome::Success);
    let bytes: Vec<u8> =
        serde_json::from_value(exported.payload.unwrap()["bytes"].clone()).unwrap();
    assert!(
        bytes.len() > MAX_REQUEST_BYTES,
        "restore must use file transport"
    );
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let snapshot_id = format!("ncm-snapshot:{digest}");
    let caller_root = TempDir::new().expect("caller snapshot root");
    let caller_file = caller_root.path().join("common-restore.snapshot");
    fs::write(&caller_file, &bytes).expect("caller snapshot file writes");
    let target_root = TempDir::new().expect("destination root");
    let target = client(&target_root);
    let key = "25".repeat(32);
    let request = Request::new(
        192,
        0,
        Operation::SnapshotRestore,
        &ns,
        json!({
            "common_portability":{"action":"snapshot_restore","idempotency_key":key,"expected_generation":0,"snapshot_file":caller_file,"byte_length":bytes.len(),"content_sha256":digest,"blocked_sources":[],"snapshot_id":snapshot_id,"observation_sequence":1},
            "test_sleep_after_commit_ms":CALL_DEADLINE.as_millis() as u64
        }),
    );
    assert_eq!(
        target.call(request, CALL_DEADLINE),
        Err(ClientError::EffectUnknown { op_id: 192 })
    );
    assert_eq!(target.pid(), None);
    assert!(
        caller_file.exists(),
        "the worker must consume only the client-owned send copy"
    );
    let transport = target_root
        .path()
        .join("namespaces")
        .join(&ns)
        .join("snapshots");
    assert_eq!(
        fs::read_dir(&transport).unwrap().count(),
        1,
        "the consumed send copy leaves one durable reconciliation backup"
    );
    let reconciled = target
        .reconcile_unknown(&ns, &key)
        .expect("original inline bytes survive transport cleanup");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    assert_eq!(reconciled.payload.as_ref().unwrap()["replayed"], true);
    assert_eq!(fs::read_dir(&transport).unwrap().count(), 0);
    let inspected = target
        .call(
            Request::new(193, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .unwrap();
    assert_eq!(inspected.payload.as_ref().unwrap()["records"], 1);
    assert_eq!(
        target.reconcile_unknown(&ns, &key),
        Err(ClientError::UnknownIdempotencyKey)
    );
    assert!(caller_file.exists(), "caller-owned file remains untouched");
}

#[cfg(unix)]
#[test]
fn raw_restore_file_killed_after_commit_reconciles_client_owned_backup() {
    let source_root = TempDir::new().expect("source root");
    let source = client(&source_root);
    let ns = namespace(20);
    let observed = source
        .call(
            Request::new(
                200,
                0,
                Operation::Observe,
                &ns,
                observe_payload("raw-restore-file", "raw restore key", "raw restore value"),
            ),
            CALL_DEADLINE,
        )
        .expect("raw restore source observe succeeds");
    assert_eq!(observed.outcome, Outcome::Success, "{observed:?}");
    let exported = source
        .call(
            Request::new(201, 0, Operation::SnapshotExport, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("raw restore source export succeeds");
    assert_eq!(exported.outcome, Outcome::Success, "{exported:?}");
    let bytes: Vec<u8> = serde_json::from_value(exported.payload.unwrap()["bytes"].clone())
        .expect("raw restore snapshot bytes decode");
    let content_sha256 = digest(&bytes);
    let caller_root = TempDir::new().expect("caller snapshot root");
    let caller_file = caller_root.path().join("raw-restore.snapshot");
    fs::write(&caller_file, &bytes).expect("raw caller snapshot file writes");

    let target_root = TempDir::new().expect("destination root");
    let target = client(&target_root);
    let key = "raw-restore-file-key";
    let mut payload = json!({
        "idempotency_key": key,
        "snapshot_file": caller_file,
        "byte_length": bytes.len(),
        "content_sha256": content_sha256,
        "blocked_sources": [],
    });
    payload["test_sleep_after_commit_ms"] = json!(CALL_DEADLINE.as_millis() as u64);
    assert_eq!(
        target.call(
            Request::new(202, 0, Operation::SnapshotRestore, &ns, payload),
            CALL_DEADLINE,
        ),
        Err(ClientError::EffectUnknown { op_id: 202 })
    );
    assert_eq!(target.pid(), None, "deadline must reap the worker");
    assert!(
        caller_file.exists(),
        "the worker must consume only the client-owned send copy"
    );
    let transport = target_root
        .path()
        .join("namespaces")
        .join(&ns)
        .join("snapshots");
    assert_eq!(
        fs::read_dir(&transport).unwrap().count(),
        1,
        "only the durable reconciliation backup remains after commit"
    );

    let reconciled = target
        .reconcile_unknown(&ns, key)
        .expect("raw caller file restore reconciles");
    assert_eq!(reconciled.outcome, Outcome::Success, "{reconciled:?}");
    assert_eq!(reconciled.payload.as_ref().unwrap()["replayed"], true);
    assert_eq!(fs::read_dir(&transport).unwrap().count(), 0);
    assert!(caller_file.exists(), "caller-owned file remains untouched");
}

#[test]
fn bounded_mailbox_returns_busy_under_concurrent_backpressure() {
    let root = TempDir::new().expect("temp root");
    let client = Arc::new(client(&root));
    let barrier = Arc::new(Barrier::new(42));
    let mut handles = Vec::new();
    for index in 0..41_u64 {
        let client = Arc::clone(&client);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut payload = json!({});
            if index == 0 {
                payload["test_sleep_before_ms"] = json!(500);
            }
            client.call(
                Request::new(100 + index, 0, Operation::Health, "", payload),
                Duration::from_secs(2),
            )
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("call thread joins"))
        .collect();
    assert!(results.contains(&Err(ClientError::Busy)));
    assert!(results.iter().any(Result::is_ok));
}

#[test]
fn protocol_and_handshake_identity_mismatches_fail_closed() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    let ns = namespace(4);
    let mut wrong_protocol = Request::new(200, 0, Operation::Health, "", json!({}));
    wrong_protocol.protocol_version = PROTOCOL_VERSION + 1;
    let reply = client
        .call(wrong_protocol, CALL_DEADLINE)
        .expect("typed incompatibility reply");
    assert_eq!(reply.outcome, Outcome::Incompatible);

    let reply = client
        .call(
            Request::new(
                201,
                0,
                Operation::Handshake,
                ns,
                json!({"algorithm_profile": "wrong-profile"}),
            ),
            CALL_DEADLINE,
        )
        .expect("typed handshake reply");
    assert_eq!(reply.outcome, Outcome::Incompatible);

    let model = client
        .call(
            Request::new(
                202,
                0,
                Operation::Handshake,
                namespace(5),
                json!({"model": "wrong-model"}),
            ),
            CALL_DEADLINE,
        )
        .expect("typed model mismatch reply");
    assert_eq!(model.outcome, Outcome::Incompatible);

    let protocol_identity = client
        .call(
            Request::new(
                204,
                0,
                Operation::Handshake,
                namespace(7),
                json!({"protocol_identity": "wrong-worker"}),
            ),
            CALL_DEADLINE,
        )
        .expect("typed protocol identity reply");
    assert_eq!(protocol_identity.outcome, Outcome::Incompatible);

    let protocol_identity = client
        .call(
            Request::new(
                205,
                0,
                Operation::Handshake,
                namespace(8),
                json!({"protocol_identity": PROTOCOL_IDENTITY}),
            ),
            CALL_DEADLINE,
        )
        .expect("matching protocol identity reply");
    assert_eq!(protocol_identity.outcome, Outcome::Success);

    let epoch = client
        .call(
            Request::new(
                203,
                0,
                Operation::Handshake,
                namespace(6),
                json!({"epoch": 99}),
            ),
            CALL_DEADLINE,
        )
        .expect("typed epoch mismatch reply");
    assert_eq!(epoch.outcome, Outcome::Incompatible);
}

#[test]
fn production_worker_admission_rejects_unpinned_or_tampered_bytes_before_spawn() {
    let root = TempDir::new().expect("temp root");
    let tampered = root.path().join("tampered-worker");
    fs::copy(worker_binary(), &tampered).expect("copy worker for tampering");
    let mut permissions = fs::metadata(&tampered)
        .expect("copied worker metadata")
        .permissions();
    #[cfg(unix)]
    permissions.set_mode(permissions.mode() | 0o200);
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(&tampered, permissions).expect("make owned worker copy writable");
    install_trusted_worker_manifest(&tampered);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&tampered)
        .expect("open copied worker");
    file.write_all(b"tampered").expect("tamper worker bytes");

    let client = WorkerClient::spawn(&tampered, root.path(), WorkerOptions::default())
        .expect("client owner starts lazily");
    let result = client.call(
        Request::new(206, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
    );
    // A pinned target rejects the altered bytes; an unpinned target has no
    // admissible worker at all. Either way nothing is spawned.
    let expected = if current_target_is_pinned() {
        "mismatch".to_owned()
    } else {
        format!(
            "worker target is not supported: {}",
            current_target_triple()
        )
    };
    assert!(
        matches!(result, Err(ClientError::Unavailable(ref detail)) if detail.contains(&expected)),
        "unexpected result: {result:?}"
    );
    assert_eq!(client.pid(), None);
}

#[test]
fn installed_worker_manifest_must_be_sibling_and_ancestor_manifest_is_ignored() {
    let root = TempDir::new().expect("temp root");
    let bundle = root.path().join("bundle");
    let bin = bundle.join("bin").join(WORKER_EXECUTABLE_NAME);
    fs::create_dir_all(bundle.join("product/ncm/reference")).expect("create ancestor fixture");
    fs::create_dir_all(bin.parent().expect("fixture bin parent")).expect("create bin fixture");
    fs::copy(worker_binary(), &bin).expect("copy worker fixture");
    fs::write(
        bundle
            .join("product/ncm/reference")
            .join(WORKER_MANIFEST_NAME),
        trusted_worker_manifest(),
    )
    .expect("write decoy ancestor manifest");

    let client = WorkerClient::spawn(&bin, root.path(), WorkerOptions::default())
        .expect("client owner starts lazily");
    let result = client.call(
        Request::new(208, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
    );
    assert!(
        matches!(result, Err(ClientError::Unavailable(ref detail)) if detail.contains("beside the worker")),
        "unexpected result: {result:?}"
    );
    assert_eq!(client.pid(), None);
}

#[test]
fn installed_worker_manifest_stale_pin_is_unavailable_before_spawn() {
    let root = TempDir::new().expect("temp root");
    let binary = root.path().join(WORKER_EXECUTABLE_NAME);
    fs::copy(worker_binary(), &binary).expect("copy worker fixture");
    install_trusted_worker_manifest(&binary);
    let manifest_path = binary
        .parent()
        .expect("worker fixture has a parent")
        .join(WORKER_MANIFEST_NAME);
    let mut manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path).expect("read worker fixture manifest"),
    )
    .expect("decode worker fixture manifest");
    // A well-formed extra pin the build never trusted makes the sibling stale
    // whether or not the trust root pins any target.
    manifest["targets"]
        .as_array_mut()
        .expect("worker manifest targets")
        .push(json!({
            "triple": "stale-fixture-target",
            "os": "stale",
            "arch": "stale",
            "family": "stale",
            "bytes": 1,
            "sha256": "0".repeat(64),
        }));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("encode stale worker manifest"),
    )
    .expect("write stale worker manifest");

    let client = WorkerClient::spawn(&binary, root.path(), WorkerOptions::default())
        .expect("client owner starts lazily");
    let result = client.call(
        Request::new(209, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
    );
    assert!(
        matches!(result, Err(ClientError::Unavailable(ref detail)) if detail.contains("stale")),
        "unexpected result: {result:?}"
    );
    assert_eq!(client.pid(), None);
}

/// The host's generated trust root admits the production bundle's exact
/// worker. Runfiles are copied into a private fixture because production
/// admission intentionally rejects symlinked worker and manifest files.
#[test]
fn build_time_trust_root_admits_exactly_its_pinned_bundle_worker() {
    let root = TempDir::new().expect("temp root");
    assert!(
        current_target_is_pinned(),
        "build-time trust root does not pin {}",
        current_target_triple()
    );
    let source = std::env::var_os("TRACEDECAY_NCM_PRODUCTION_WORKER")
        .map(std::path::PathBuf::from)
        .expect("Bazel must supply the production worker bundle");
    assert!(
        source.is_absolute(),
        "production worker input must be absolute"
    );
    let source_manifest = source
        .parent()
        .expect("production worker has a bundle directory")
        .join(WORKER_MANIFEST_NAME);
    let bundle = root.path().join("bundle");
    fs::create_dir(&bundle).expect("create private bundle fixture");
    let worker = bundle.join(WORKER_EXECUTABLE_NAME);
    fs::copy(&source, &worker).expect("stage production worker runfile");
    fs::copy(source_manifest, bundle.join(WORKER_MANIFEST_NAME))
        .expect("stage production manifest runfile");
    let client = WorkerClient::spawn(&worker, root.path(), WorkerOptions::default())
        .expect("client owner starts lazily");
    let result = client.call(
        Request::new(207, 0, Operation::Health, "", json!({})),
        CALL_DEADLINE,
    );
    assert!(
        matches!(result, Ok(ref reply) if reply.outcome == Outcome::Success),
        "unexpected result: {result:?}"
    );
    assert!(client.pid().is_some());
}

#[test]
fn disabled_provider_never_launches_and_spawn_failures_exhaust_budget() {
    let root = TempDir::new().expect("temp root");
    let disabled = WorkerOptions {
        enabled: false,
        ..options()
    };
    assert!(matches!(
        WorkerClient::spawn(worker_binary(), root.path(), disabled),
        Err(ClientError::Disabled)
    ));

    let missing = WorkerOptions {
        max_restart_attempts: 1,
        ..options()
    };
    let client = WorkerClient::spawn(
        root.path().join("missing-worker-binary"),
        root.path(),
        missing,
    )
    .expect("owner thread starts lazily");
    let first = client.call(
        Request::new(210, 0, Operation::Health, "", json!({})),
        Duration::from_millis(100),
    );
    assert!(matches!(first, Err(ClientError::Spawn(_))));
    let second = client.call(
        Request::new(211, 0, Operation::Health, "", json!({})),
        Duration::from_millis(100),
    );
    assert_eq!(second, Err(ClientError::RestartExhausted));
    assert_eq!(client.pid(), None);
}

#[test]
fn process_death_is_detected_then_lazily_restarted() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    client
        .call(
            Request::new(220, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("initial worker starts");
    let first_pid = client.pid().expect("worker pid exists");
    force_kill(first_pid);
    let failed = client.call(
        Request::new(221, 0, Operation::Health, "", json!({})),
        Duration::from_millis(500),
    );
    assert!(matches!(
        failed,
        Err(ClientError::MalformedReply(_))
            | Err(ClientError::WorkerExited)
            | Err(ClientError::Transport(_))
    ));
    let restarted = client
        .call(
            Request::new(222, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("worker restarts on following call");
    assert_eq!(restarted.outcome, Outcome::Success);
    assert_ne!(client.pid(), Some(first_pid));
}

#[cfg(unix)]
#[test]
fn recall_after_worker_restart_reproves_namespace_and_recovers_privacy_fence() {
    let root = TempDir::new().expect("temp root");
    let ns = namespace(28);
    let client = client(&root);
    client
        .call(
            Request::new(260, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("initial health starts worker");
    client
        .call(
            Request::new(261, 0, Operation::Handshake, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("empty namespace handshake caches readiness");
    let first_pid = client.pid().expect("initial worker pid exists");

    let engine = NcmEngine::new(
        StateRoot::new(root.path()).expect("state root is absolute"),
        Arc::new(HashEncoder::new()),
        test_config(),
    );
    direct_observe(
        &engine,
        &ns,
        "worker-restart-kept",
        "worker restart retained key",
        "worker restart retained value",
        "worker-restart-kept-write",
    );
    direct_observe(
        &engine,
        &ns,
        "worker-restart-deleted",
        "worker restart deleted token",
        "worker restart deleted value",
        "worker-restart-deleted-write",
    );
    engine
        .inject_fault_once(FaultPoint::AfterDeletionFenceCommit)
        .expect("arm deletion fence fault");
    let fenced = engine.delete_by_source(
        &ns,
        &SourceId("worker-restart-deleted".to_owned()),
        "worker-restart-delete",
        Deadline {
            remaining_ms: u64::MAX,
        },
    );
    assert_eq!(fenced.outcome, Outcome::EffectUnknown);
    drop(engine);
    force_kill(first_pid);
    let recovered = client
        .call(
            Request::new(
                262,
                0,
                Operation::Recall,
                &ns,
                json!({"query_text": "worker restart retained key", "top_k": 16}),
            ),
            CALL_DEADLINE,
        )
        .expect("recall restarts worker and recovers privacy fence");
    assert_eq!(recovered.outcome, Outcome::Success, "{recovered:?}");
    let payload = recovered.payload.expect("recall payload").to_string();
    assert!(
        !payload.contains("worker restart deleted token")
            && !payload.contains("worker restart deleted value"),
        "deleted source must not resurrect after restart recovery: {payload}"
    );
    assert!(
        payload.contains("worker restart retained value"),
        "retained source must remain recallable after recovery: {payload}"
    );

    let inspection = client
        .call(
            Request::new(263, 0, Operation::Inspection, &ns, json!({})),
            CALL_DEADLINE,
        )
        .expect("recovered namespace can be inspected");
    assert_eq!(inspection.outcome, Outcome::Success);
    let inspection = inspection.payload.expect("inspection payload");
    assert_eq!(inspection["records"], 1);
    assert_eq!(inspection["epoch"], 2);
}

#[cfg(unix)]
#[test]
#[ignore = "subprocess fixture for malformed worker reply tests"]
fn malformed_reply_worker_fixture() {
    let root = std::env::var_os("TRACEDECAY_NCM_MALFORMED_FIXTURE_ROOT")
        .expect("malformed worker fixture requires its isolated state root");
    let engine = Arc::new(NcmEngine::new(
        StateRoot::new(root).expect("fixture state root"),
        Arc::new(HashEncoder::new()),
        Default::default(),
    ));
    let mut input = std::io::stdin().lock();
    // The launcher keeps libtest progress on stderr and the worker wire on fd 3.
    let mut output = fs::File::options()
        .write(true)
        .open("/dev/fd/3")
        .expect("worker reply descriptor");
    let readiness = wire::read_request(&mut input)
        .expect("read readiness frame")
        .expect("readiness request");
    assert_eq!(readiness.op, Operation::Health);
    serve_with_options(
        Cursor::new(wire::encode_request(&readiness).expect("encode readiness")),
        &mut output,
        engine,
        ServeOptions {
            allow_test_delays: false,
            encoder_ready: true,
            allow_legacy_identity: true,
        },
    )
    .expect("serve actual readiness reply");
    let request = wire::read_request(&mut input)
        .expect("read bounded health frame")
        .expect("bounded health request");
    assert_eq!(request.op, Operation::Health);
    output
        .write_all(&[0, 0, 0, 1, b'x'])
        .expect("write malformed JSON frame");
    output.flush().expect("flush malformed reply");
    std::io::copy(&mut input, &mut std::io::sink()).expect("drain until client retires worker");
}

#[cfg(unix)]
#[test]
fn malformed_worker_reply_is_detected_and_process_is_reaped() {
    let root = TempDir::new().expect("temp root");
    std::os::unix::fs::symlink(
        std::env::current_exe().expect("current test executable"),
        root.path().join("test-runner"),
    )
    .expect("link this test's fixture runner");
    let malformed = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Bazel crate runfiles directory"),
    )
    .join("tests/fixtures/malformed-worker.sh");
    assert!(malformed.is_absolute());
    assert!(malformed.is_file());
    let client =
        WorkerClient::spawn(&malformed, root.path(), options()).expect("client owner starts");
    let ready = client
        .call(
            Request::new(239, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("actual worker health succeeds before malformed reply");
    assert_eq!(ready.outcome, Outcome::Success);
    let pid = client.pid().expect("ready worker PID");
    assert!(process_exists(pid));
    let result = client.call(
        Request::new(240, 0, Operation::Health, "", json!({})),
        Duration::from_millis(500),
    );
    assert!(
        matches!(result, Err(ClientError::MalformedReply(_))),
        "invalid frame must be reported as a malformed reply: {result:?}"
    );
    assert_eq!(client.pid(), None);
    assert!(!process_exists(pid), "malformed worker must be reaped");
}

#[cfg(unix)]
#[test]
fn full_pipe_backpressure_is_hard_cancelled_without_orphan() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().expect("temp root");
    let sleeper = root.path().join("blocked-worker.sh");
    std::fs::write(&sleeper, "#!/bin/sh\nexec sleep 5\n").expect("write sleeper");
    let mut permissions = std::fs::metadata(&sleeper)
        .expect("sleeper metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&sleeper, permissions).expect("make sleeper executable");
    let client = WorkerClient::spawn(&sleeper, root.path(), options()).expect("client starts");
    let payload = json!({"padding": "x".repeat(240 * 1024)});
    let started = Instant::now();
    let result = client.call(
        Request::new(241, 0, Operation::Health, "", payload),
        Duration::from_millis(30),
    );
    assert_eq!(result, Err(ClientError::Cancelled));
    assert!(started.elapsed() <= Duration::from_millis(300));
    assert_eq!(client.pid(), None);
}

#[test]
fn client_drop_reaps_worker_and_stdin_eof_exits_zero() {
    let root = TempDir::new().expect("temp root");
    let client = client(&root);
    client
        .call(
            Request::new(230, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("worker starts");
    let pid = client.pid().expect("worker pid exists");
    assert!(process_exists(pid), "started worker must be observable");
    drop(client);
    let deadline = Instant::now() + Duration::from_millis(300);
    while process_exists(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(!process_exists(pid));

    let (mut child, stdin, _stdout) = raw_worker(root.path());
    drop(stdin);
    assert!(child.wait().expect("EOF worker exits").success());
}
