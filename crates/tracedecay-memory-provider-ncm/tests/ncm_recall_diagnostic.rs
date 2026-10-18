//! End-to-end tests for the opt-in NCM recall stage diagnostic seam.

#![allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::panic,
    clippy::unwrap_used
)]
#![doc = "NCM recall diagnostic seam tests."]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracedecay_memory_provider_api::contract::TerminalCode;
use tracedecay_memory_provider_api::{
    CancellationToken, CanonicalPayload, CommittedEffectEvidence, FallbackDirective,
    HandshakeRequest, HandshakeRequestParts, MemoryProvider, OperationControl, OwnedExactScope,
    OwnedProviderId, OwnedVersionedId, ProviderCall, ProviderCallParts, ProviderDescriptor,
    ProviderLimits, ProviderOperation, ProviderReply, TerminalRecord,
};
use tracedecay_memory_provider_ncm::{
    NCM_PROVIDER_ID, NcmCognitiveSurface, NcmNamespace, NcmProviderAdapter,
    NcmRecallDiagnosticEvent, NcmRecallDiagnosticKey, NcmRecallDiagnosticSink, NcmSurfaceCall,
    NcmSurfaceHandshakeRequest, NcmSurfaceHandshakeResponse,
};
use tracedecay_memory_provider_registry::recall_admission::{
    AdmittedTemporalQuery, RecallBudgetsV1, RecallRequestParts, build_recall_request_payload,
};

const ZERO_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const RESOLVED_SCOPE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn diagnostic_key() -> NcmRecallDiagnosticKey {
    NcmRecallDiagnosticKey::new([0x5a; 32])
}

#[derive(Clone, Copy)]
enum SurfaceMode {
    FourRows,
    ManyRows(usize),
    Malformed,
    CancelAfterDispatch,
    DelayAfterDispatch,
}

struct DiagnosticSurface {
    descriptor: ProviderDescriptor,
    mode: SurfaceMode,
}

impl DiagnosticSurface {
    fn new(mode: SurfaceMode) -> Self {
        let capabilities = [
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
        ]
        .into_iter()
        .map(|capability| OwnedVersionedId::new(capability).expect("capability"))
        .collect::<Vec<_>>();
        Self {
            descriptor: ProviderDescriptor::new(
                OwnedProviderId::new(NCM_PROVIDER_ID).expect("provider id"),
                ZERO_SHA,
                "ncm-diagnostic-state-v1",
                4,
                capabilities,
                limits(),
            )
            .expect("descriptor"),
            mode,
        }
    }

    fn terminal(
        &self,
        operation: ProviderOperation,
        operation_id: &str,
        namespace: &NcmNamespace,
        generation: Option<u64>,
    ) -> TerminalRecord {
        TerminalRecord::new(
            operation,
            self.descriptor.provider_id.clone(),
            TerminalCode::Success,
            CommittedEffectEvidence::none(generation),
            FallbackDirective::forbidden(),
            operation_id.to_owned(),
            namespace.as_str(),
            None,
        )
        .expect("surface terminal")
    }
}

impl NcmCognitiveSurface for DiagnosticSurface {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        let receipt = ONE_SHA.to_owned();
        NcmSurfaceHandshakeResponse {
            terminal: self.terminal(
                ProviderOperation::Handshake,
                &request.request_id,
                &request.namespace,
                None,
            ),
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some("ncm.instance.diagnostic".to_owned()),
            namespace: Some(request.namespace.clone()),
            effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
            ready_receipt_sha256: Some(receipt.clone()),
            challenge_response_sha256: Some(request.expected_challenge_response_sha256(
                &self.descriptor,
                "ncm.instance.diagnostic",
                &receipt,
            )),
            warnings: Vec::new(),
        }
    }

    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
        if matches!(self.mode, SurfaceMode::CancelAfterDispatch) {
            call.control.cancellation().cancel();
        }
        if matches!(self.mode, SurfaceMode::DelayAfterDispatch) {
            thread::sleep(Duration::from_millis(40));
        }
        let payload_value = match self.mode {
            SurfaceMode::Malformed => json!({
                "common_recall": {
                    "candidates": [{"malformed": true}],
                    "truncated": false,
                    "unknown_items": 0,
                    "excluded_items": 0,
                    "scanned_items": 1,
                    "score_upper_bound": 1.0
                }
            }),
            SurfaceMode::FourRows => worker_payload(call, 4),
            SurfaceMode::ManyRows(count) => worker_payload(call, count),
            SurfaceMode::CancelAfterDispatch | SurfaceMode::DelayAfterDispatch => {
                worker_payload(call, 1)
            }
        };
        let payload_bytes = serde_json::to_vec(&payload_value).expect("worker payload");
        let payload = CanonicalPayload::new(
            call.payload.contract_id.clone(),
            payload_bytes.clone(),
            hex_digest(&Sha256::digest(&payload_bytes)),
        )
        .expect("surface payload");
        ProviderReply {
            terminal: self.terminal(
                call.operation,
                &call.operation_id,
                &call.namespace,
                Some(call.expected_state_generation),
            ),
            payload: Some(payload),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }
}

fn limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 1_048_576,
        response_bytes: 1_048_576,
        observation_batch_items: 16,
        recall_candidates: 32,
        concurrent_operations: 8,
        operation_millis: 1_000,
        snapshot_bytes: 1_048_576,
        inspection_items: 64,
    }
}

fn scope() -> OwnedExactScope {
    OwnedExactScope::new(
        "profile-diagnostic",
        "project-diagnostic",
        "repository-diagnostic",
        "worktree-diagnostic",
        "refs/heads/diagnostic",
        "session-diagnostic",
        RESOLVED_SCOPE_DIGEST,
    )
    .expect("scope")
}

fn scope_value(exact: &OwnedExactScope) -> Value {
    json!({
        "profile_id": exact.profile_id,
        "project_id": exact.project_id,
        "repository_identity": exact.repository_identity,
        "worktree_identity": exact.worktree_identity,
        "branch_identity": exact.branch_identity,
        "agent_session_id": exact.agent_session_id,
        "resolved_scope_digest": exact.resolved_scope_digest
    })
}

fn opaque(namespace: &NcmNamespace, kind: &[u8], value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.ncm.opaque-id.v1");
    digest.update([0]);
    for field in [namespace.as_str().as_bytes(), kind, value.as_bytes()] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    hex_digest(&digest.finalize())
}

fn stable_reference(namespace: &NcmNamespace, record_id: u64, capsule: &str) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"tracedecay.ncm.memory-reference.v1".as_slice(),
        namespace.as_str().as_bytes(),
        &record_id.to_be_bytes(),
        capsule.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("ncm-memory:{}", hex_digest(&digest.finalize()))
}

fn source_ids(
    namespace: &NcmNamespace,
    exact: &OwnedExactScope,
    source_key: &str,
) -> (String, String) {
    let identity = serde_json::to_string(&json!([
        exact.profile_id,
        exact.project_id,
        "codex",
        "codex-session",
        source_key
    ]))
    .expect("source identity");
    (
        opaque(namespace, b"common-source-key-v1", &identity),
        opaque(namespace, b"forget-source-key", source_key),
    )
}

fn row(call: &NcmSurfaceCall, record_id: u64, content: &str, activation: f64) -> Value {
    let exact = scope();
    let namespace = call.namespace.clone();
    let source_key = format!("source-{record_id}");
    let (full_source_id, legacy_source_id) = source_ids(&namespace, &exact, &source_key);
    let original = json!({
        "source": {
            "canonical_provider_id": "codex",
            "canonical_session_id": "codex-session",
            "source_key": source_key,
            "stable_record_id": format!("record-{record_id}"),
            "observation_id": format!("observation-{record_id}"),
            "source_revision": format!("revision-{record_id}"),
            "content_sha256": "ab".repeat(32)
        },
        "origin_scope": {
            "state": "recorded",
            "exact_scope_identity": scope_value(&exact),
            "authority_ref": "diagnostic-authority"
        },
        "source_sequence": record_id + 1,
        "occurred_at": "2026-01-01T00:00:00Z",
        "ingested_at": "2026-01-01T00:00:00Z",
        "validity": {
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": null,
            "superseded_at": null,
            "superseded_by": null,
            "revoked_at": null
        }
    });
    let value_text = format!("assistant: {content}");
    let retained = json!({
        "original_source": original,
        "canonical_payload": {"role": "assistant", "content": content},
        "source_refs": [format!("record:{record_id}")],
        "delivery_scope": scope_value(&exact),
        "projection": {
            "key_text": content,
            "value_text": value_text,
            "observation_kind": "session.message_committed.v1"
        }
    });
    let retained_bytes = serde_json::to_vec(&retained).expect("retained capsule");
    let capsule_digest = hex_digest(&Sha256::digest(&retained_bytes));
    let stable = stable_reference(&namespace, record_id, &capsule_digest);
    let surface_payload: Value =
        serde_json::from_slice(&call.payload.bytes).expect("projected recall payload");
    let request_token = surface_payload["selection"]["request_token"]
        .as_str()
        .expect("opaque request token");
    let mut candidate_digest = Sha256::new();
    for field in [request_token.as_bytes(), stable.as_bytes()] {
        candidate_digest.update((field.len() as u64).to_be_bytes());
        candidate_digest.update(field);
    }
    json!({
        "record_id": record_id,
        "source": full_source_id,
        "stable_memory_ref": stable,
        "candidate_id": format!("ncm-candidate:{}", hex_digest(&candidate_digest.finalize())),
        "key_text": content,
        "value_text": value_text,
        "activation": activation,
        "provenance": {
            "source_binding": {
                "version": 1,
                "source_id": full_source_id,
                "legacy_source_id": legacy_source_id
            },
            "common_capsule": {
                "version": 1,
                "bytes": retained_bytes,
                "sha256": capsule_digest
            }
        }
    })
}

fn worker_payload(call: &NcmSurfaceCall, count: usize) -> Value {
    let candidates = (0..count)
        .map(|record_id| {
            row(
                call,
                record_id as u64,
                &format!("diagnostic-content-{record_id}"),
                1.0 - (record_id as f64 / 100.0),
            )
        })
        .collect::<Vec<_>>();
    json!({
        "common_recall": {
            "candidates": candidates,
            "truncated": false,
            "unknown_items": 0,
            "excluded_items": 0,
            "scanned_items": count,
            "score_upper_bound": 1.0
        }
    })
}

fn handshake_request() -> HandshakeRequest {
    HandshakeRequest::new(HandshakeRequestParts {
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("provider id"),
        registration_revision: 1,
        exact_scope: scope(),
        request_id: "ncm-diagnostic-handshake".to_owned(),
        required_capabilities: vec![
            OwnedVersionedId::new("provider.health.v1").expect("health capability"),
            OwnedVersionedId::new("observation.accept.v1").expect("observe capability"),
            OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
        ],
        host_limits: limits(),
        control: OperationControl::new(i64::MAX, 500, CancellationToken::new()),
        challenge_nonce: [7; 32],
    })
    .expect("handshake request")
}

fn recall_call(
    ready_receipt: &str,
    request_suffix: &str,
    maximum_candidates: u64,
    remaining_millis: u64,
    cancellation: CancellationToken,
) -> ProviderCall {
    let exact = scope();
    let request_id = format!("ncm-diagnostic-request-{request_suffix}");
    let payload = build_recall_request_payload(&RecallRequestParts {
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("provider id"),
        registration_revision: 1,
        ready_receipt_sha256: ready_receipt.to_owned(),
        exact_scope: exact.clone(),
        request_id: request_id.clone(),
        objective: "diagnostic recall".to_owned(),
        query: "diagnostic query".to_owned(),
        temporal: AdmittedTemporalQuery::current("2026-01-02T00:00:00Z")
            .expect("valid temporal query"),
        budgets: RecallBudgetsV1 {
            maximum_candidates,
            maximum_candidate_content_bytes: 256,
            maximum_total_content_bytes: 8192,
            maximum_source_refs_per_candidate: 4,
            maximum_trace_refs_per_candidate: 4,
            maximum_warnings: 4,
            maximum_extensions_per_candidate: 1,
        },
        policy_revision: 1,
        deadline_utc_micros: i64::MAX,
        remaining_millis,
    })
    .expect("canonical recall payload");
    ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("provider id"),
        registration_revision: 1,
        ready_receipt_sha256: ready_receipt.to_owned(),
        exact_scope: exact,
        request_id,
        operation_id: format!("ncm-diagnostic-operation-{request_suffix}"),
        expected_state_generation: 4,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, remaining_millis, cancellation),
        payload,
        required_capabilities: vec![
            OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
        ],
        extensions: Vec::new(),
    })
    .expect("recall call")
}

fn adapter(mode: SurfaceMode) -> (NcmProviderAdapter, String) {
    let surface = Arc::new(DiagnosticSurface::new(mode));
    let adapter = NcmProviderAdapter::new(surface).expect("adapter");
    let ready = adapter.handshake(&handshake_request());
    assert_eq!(
        ready.terminal.terminal_code(),
        TerminalCode::Success,
        "{ready:?}"
    );
    (adapter, ready.ready_receipt_sha256.expect("ready receipt"))
}

#[derive(Default)]
struct RecordingSink(Mutex<Vec<NcmRecallDiagnosticEvent>>);

impl RecordingSink {
    fn snapshot(&self) -> Vec<NcmRecallDiagnosticEvent> {
        self.0.lock().expect("diagnostic lock").clone()
    }
}

impl NcmRecallDiagnosticSink for RecordingSink {
    fn record(&self, event: NcmRecallDiagnosticEvent) {
        self.0.lock().expect("diagnostic lock").push(event);
    }
}

struct PanicSink;

impl NcmRecallDiagnosticSink for PanicSink {
    fn record(&self, _event: NcmRecallDiagnosticEvent) {
        panic!("diagnostic sink failure");
    }
}

#[test]
fn adapter_invoke_traces_four_worker_rows_to_two_partial_candidates() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::FourRows);
    let sink = Arc::new(RecordingSink::default());
    let adapter = adapter.with_recall_diagnostic_sink(sink.clone(), Some(diagnostic_key()));
    let call = recall_call(
        &ready_receipt,
        "four-to-two",
        2,
        500,
        CancellationToken::new(),
    );
    let reply = adapter.invoke(&call);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    let events = sink.snapshot();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(
        events[0].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::Worker
    );
    assert_eq!(events[0].candidate_count, 4);
    assert_eq!(events[0].scanned_items, 4);
    assert_eq!(
        events[1].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::PartialReply
    );
    assert_eq!(events[1].candidate_count, 2);
    assert_eq!(events[1].scanned_items, 4);
    assert_eq!(events[0].request_id_sha256, events[1].request_id_sha256);
    assert_eq!(events[0].query_sha256, events[1].query_sha256);
}

#[test]
fn default_adapter_has_no_diagnostic_events() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::FourRows);
    let sink = Arc::new(RecordingSink::default());
    let call = recall_call(&ready_receipt, "no-sink", 2, 500, CancellationToken::new());
    let reply = adapter.invoke(&call);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    assert!(sink.snapshot().is_empty());
}

#[test]
fn unkeyed_diagnostic_sink_omits_identity_fingerprints() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::FourRows);
    let sink = Arc::new(RecordingSink::default());
    let adapter = adapter.with_recall_diagnostic_sink(sink.clone(), None);
    let reply = adapter.invoke(&recall_call(
        &ready_receipt,
        "unkeyed",
        2,
        500,
        CancellationToken::new(),
    ));
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    let events = sink.snapshot();
    assert_eq!(events.len(), 2, "{events:?}");
    for event in events {
        assert!(event.request_id_sha256.is_none());
        assert!(event.operation_id_sha256.is_none());
        assert!(event.query_sha256.is_none());
        assert!(event.exact_scope_sha256.is_none());
        assert!(event.namespace_sha256.is_none());
        assert!(event.provider_instance_sha256.is_none());
    }
}

#[test]
fn panic_in_diagnostic_sink_does_not_change_provider_reply() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::FourRows);
    let adapter = adapter.with_recall_diagnostic_sink(Arc::new(PanicSink), Some(diagnostic_key()));
    let call = recall_call(
        &ready_receipt,
        "panic-sink",
        2,
        500,
        CancellationToken::new(),
    );
    let reply = adapter.invoke(&call);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    assert!(reply.payload.is_some());
}

#[test]
fn diagnostic_vectors_are_bounded_to_sixteen_items() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::ManyRows(24));
    let sink = Arc::new(RecordingSink::default());
    let adapter = adapter.with_recall_diagnostic_sink(sink.clone(), Some(diagnostic_key()));
    let call = recall_call(&ready_receipt, "bounded", 24, 500, CancellationToken::new());
    let reply = adapter.invoke(&call);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    let events = sink.snapshot();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].candidate_count, 24);
    assert_eq!(events[0].candidate_ranks.len(), 16);
    assert_eq!(events[0].candidate_content_bytes.len(), 16);
    assert_eq!(events[1].candidate_count, 16);
    assert_eq!(events[1].candidate_ranks.len(), 16);
}

#[test]
fn concurrent_invokes_keep_each_request_stage_pair_correlated() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::FourRows);
    let sink = Arc::new(RecordingSink::default());
    let adapter =
        Arc::new(adapter.with_recall_diagnostic_sink(sink.clone(), Some(diagnostic_key())));
    let calls = (0..4)
        .map(|index| {
            recall_call(
                &ready_receipt,
                &format!("concurrent-{index}"),
                2,
                500,
                CancellationToken::new(),
            )
        })
        .collect::<Vec<_>>();
    let handles = calls
        .into_iter()
        .map(|call| {
            let adapter = adapter.clone();
            thread::spawn(move || adapter.invoke(&call))
        })
        .collect::<Vec<_>>();
    for handle in handles {
        assert_eq!(
            handle
                .join()
                .expect("invoke thread")
                .terminal
                .terminal_code(),
            TerminalCode::Partial
        );
    }
    let events = sink.snapshot();
    assert_eq!(events.len(), 8, "{events:?}");
    for request_id in events
        .iter()
        .map(|event| event.request_id_sha256.clone())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let positions = events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.request_id_sha256 == request_id)
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 2, "request {request_id:?}: {events:?}");
        assert_eq!(
            events[positions[0]].stage,
            tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::Worker,
            "request {request_id:?}: {events:?}"
        );
        assert_eq!(
            events[positions[1]].stage,
            tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::PartialReply,
            "request {request_id:?}: {events:?}"
        );
    }
}

#[test]
fn post_dispatch_cancellation_and_deadline_are_typed_diagnostic_stages() {
    let (cancel_adapter, cancel_receipt) = adapter(SurfaceMode::CancelAfterDispatch);
    let cancel_sink = Arc::new(RecordingSink::default());
    let cancel_adapter =
        cancel_adapter.with_recall_diagnostic_sink(cancel_sink.clone(), Some(diagnostic_key()));
    let cancel_reply = cancel_adapter.invoke(&recall_call(
        &cancel_receipt,
        "post-cancel",
        2,
        500,
        CancellationToken::new(),
    ));
    assert_eq!(
        cancel_reply.terminal.terminal_code(),
        TerminalCode::Cancelled
    );
    assert_eq!(cancel_sink.snapshot().len(), 1);
    assert_eq!(
        cancel_sink.snapshot()[0].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::PostDispatchCancellation
    );

    let (deadline_adapter, deadline_receipt) = adapter(SurfaceMode::DelayAfterDispatch);
    let deadline_sink = Arc::new(RecordingSink::default());
    let deadline_adapter =
        deadline_adapter.with_recall_diagnostic_sink(deadline_sink.clone(), Some(diagnostic_key()));
    let deadline_reply = deadline_adapter.invoke(&recall_call(
        &deadline_receipt,
        "post-deadline",
        2,
        20,
        CancellationToken::new(),
    ));
    assert_eq!(
        deadline_reply.terminal.terminal_code(),
        TerminalCode::DeadlineExceeded
    );
    assert_eq!(deadline_sink.snapshot().len(), 1);
    assert_eq!(
        deadline_sink.snapshot()[0].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::PostDispatchDeadline
    );
}

#[test]
fn malformed_worker_reply_emits_reconstruction_failure_stage() {
    let (adapter, ready_receipt) = adapter(SurfaceMode::Malformed);
    let sink = Arc::new(RecordingSink::default());
    let adapter = adapter.with_recall_diagnostic_sink(sink.clone(), Some(diagnostic_key()));
    let reply = adapter.invoke(&recall_call(
        &ready_receipt,
        "reconstruction-failure",
        2,
        500,
        CancellationToken::new(),
    ));
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    let events = sink.snapshot();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(
        events[0].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::Worker
    );
    assert_eq!(
        events[1].stage,
        tracedecay_memory_provider_ncm::NcmRecallDiagnosticStage::ReconstructionFailure
    );
    assert_eq!(events[0].request_id_sha256, events[1].request_id_sha256);
    assert_eq!(events[1].candidate_count, 0);
}

fn hex_digest(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}
