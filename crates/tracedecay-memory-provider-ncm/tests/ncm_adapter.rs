//! Focused integration tests for the topology-neutral NCM adapter boundary.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use sha2::{Digest, Sha256};
use tracedecay_memory_provider_api::contract::{
    CommittedEffectState, FallbackEligibility, TerminalCode,
};
use tracedecay_memory_provider_api::{
    CancellationToken, CanonicalPayload, CommittedEffectEvidence, FallbackDirective,
    HandshakeRequest, HandshakeRequestParts, MemoryProvider, OperationControl, OwnedExactScope,
    OwnedOpaqueExtension, OwnedProviderId, OwnedVersionedId, PayloadSanitizationReceipt,
    PayloadSanitizationReceiptParts, ProviderCall, ProviderCallParts, ProviderDescriptor,
    ProviderLimits, ProviderOperation, ProviderReply, TerminalRecord,
    observation_extensions_digest,
};
use tracedecay_memory_provider_ncm::{
    NCM_PROVIDER_ID, NcmAdapterError, NcmCognitiveSurface, NcmNamespace, NcmNamespaceBinding,
    NcmProviderAdapter, NcmSurfaceCall, NcmSurfaceHandshakeRequest, NcmSurfaceHandshakeResponse,
};

const ZERO_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROVIDER_RECEIPT_SHA: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const VERIFICATION_SHA: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const EMPTY_OBJECT_SHA: &str = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const RESOLVED_SCOPE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const LARGE_EXTENSION_SHA: &str =
    "91e3faafd322bcdf160f3f0ce886acb092b9b9e2a1e8526b40f21a8898a8700b";

struct MockSurface {
    descriptor: Mutex<ProviderDescriptor>,
    handshake_calls: AtomicUsize,
    invoke_calls: AtomicUsize,
    last_handshake: Mutex<Option<NcmSurfaceHandshakeRequest>>,
    last_call: Mutex<Option<NcmSurfaceCall>>,
    malformed_reply_scope: bool,
    public_reply_operation_id: bool,
    malformed_handshake_scope: bool,
    reply_effect: Option<CommittedEffectState>,
    reply_code: Option<TerminalCode>,
    handshake_code: Option<TerminalCode>,
    corrupt_payload_digest: bool,
    warning_count: usize,
    handshake_warning_size: usize,
    leak_terminal_diagnostic_aliases: bool,
    leak_effect_metadata_aliases: bool,
    leak_provider_receipt_alias: bool,
    leak_verification_alias: bool,
    leak_warning_aliases: bool,
    malformed_handshake_proof: bool,
    malformed_handshake_proof_call: Option<usize>,
    reply_state_generation: Option<u64>,
    inject_extension: bool,
    large_response_payload: bool,
    leak_surface_payload_identity: bool,
    safe_response_payload: bool,
    block_handshake_call: Option<usize>,
    handshake_entered: Option<Arc<Barrier>>,
    handshake_release: Option<Arc<Barrier>>,
    block_invoke_call: Option<usize>,
    invoke_entered: Option<Arc<Barrier>>,
    invoke_release: Option<Arc<Barrier>>,
}

impl MockSurface {
    fn new(provider_id: &str, optional: &[&str], malformed_reply_scope: bool) -> Self {
        let mut capabilities = vec![
            OwnedVersionedId::new("provider.health.v1").expect("health"),
            OwnedVersionedId::new("observation.accept.v1").expect("observe"),
            OwnedVersionedId::new("recall.query.v1").expect("recall"),
        ];
        capabilities.extend(
            optional
                .iter()
                .map(|value| OwnedVersionedId::new(*value).expect("optional")),
        );
        Self {
            descriptor: Mutex::new(
                ProviderDescriptor::new(
                    OwnedProviderId::new(provider_id).expect("provider id"),
                    ZERO_SHA,
                    "ncm-state-v1",
                    4,
                    capabilities,
                    limits(),
                )
                .expect("descriptor"),
            ),
            handshake_calls: AtomicUsize::new(0),
            invoke_calls: AtomicUsize::new(0),
            last_handshake: Mutex::new(None),
            last_call: Mutex::new(None),
            malformed_reply_scope,
            public_reply_operation_id: false,
            malformed_handshake_scope: false,
            reply_effect: None,
            reply_code: None,
            handshake_code: None,
            corrupt_payload_digest: false,
            warning_count: 0,
            handshake_warning_size: 0,
            leak_terminal_diagnostic_aliases: false,
            leak_effect_metadata_aliases: false,
            leak_provider_receipt_alias: false,
            leak_verification_alias: false,
            leak_warning_aliases: false,
            malformed_handshake_proof: false,
            malformed_handshake_proof_call: None,
            reply_state_generation: None,
            inject_extension: false,
            large_response_payload: false,
            leak_surface_payload_identity: false,
            safe_response_payload: false,
            block_handshake_call: None,
            handshake_entered: None,
            handshake_release: None,
            block_invoke_call: None,
            invoke_entered: None,
            invoke_release: None,
        }
    }

    fn descriptor_snapshot(&self) -> ProviderDescriptor {
        self.descriptor.lock().expect("descriptor lock").clone()
    }

    fn with_descriptor_limits(mut self, limits: ProviderLimits) -> Self {
        self.descriptor.get_mut().expect("descriptor lock").limits = limits;
        self
    }

    fn change_implementation_identity(&self, identity_sha256: &str) {
        self.descriptor
            .lock()
            .expect("descriptor lock")
            .implementation_identity_sha256 = identity_sha256.to_owned();
    }

    fn change_state_generation(&self, state_generation: u64) {
        self.descriptor
            .lock()
            .expect("descriptor lock")
            .state_generation = state_generation;
    }

    fn with_reply_effect(mut self, effect: CommittedEffectState) -> Self {
        self.reply_effect = Some(effect);
        self
    }

    fn with_reply_code(mut self, code: TerminalCode) -> Self {
        self.reply_code = Some(code);
        self
    }

    fn with_public_reply_operation_id(mut self) -> Self {
        self.public_reply_operation_id = true;
        self
    }

    fn with_handshake_code(mut self, code: TerminalCode) -> Self {
        self.handshake_code = Some(code);
        self
    }

    fn with_corrupt_payload_digest(mut self) -> Self {
        self.corrupt_payload_digest = true;
        self
    }

    fn with_leaking_terminal_diagnostic(mut self) -> Self {
        self.leak_terminal_diagnostic_aliases = true;
        self
    }

    fn with_leaking_effect_metadata(mut self) -> Self {
        self.leak_effect_metadata_aliases = true;
        self
    }

    fn with_leaking_provider_receipt(mut self) -> Self {
        self.leak_provider_receipt_alias = true;
        self
    }

    fn with_leaking_verification(mut self) -> Self {
        self.leak_verification_alias = true;
        self
    }

    fn with_leaking_warnings(mut self) -> Self {
        self.leak_warning_aliases = true;
        self
    }

    fn with_warning_count(mut self, warning_count: usize) -> Self {
        self.warning_count = warning_count;
        self
    }

    fn with_handshake_warning_size(mut self, warning_size: usize) -> Self {
        self.handshake_warning_size = warning_size;
        self
    }

    fn with_malformed_handshake_proof(mut self) -> Self {
        self.malformed_handshake_proof = true;
        self
    }

    fn with_malformed_handshake_proof_call(mut self, call: usize) -> Self {
        self.malformed_handshake_proof_call = Some(call);
        self
    }

    fn with_blocking_handshake(
        mut self,
        call: usize,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    ) -> Self {
        self.block_handshake_call = Some(call);
        self.handshake_entered = Some(entered);
        self.handshake_release = Some(release);
        self
    }

    fn with_blocking_invoke(
        mut self,
        call: usize,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    ) -> Self {
        self.block_invoke_call = Some(call);
        self.invoke_entered = Some(entered);
        self.invoke_release = Some(release);
        self
    }

    fn with_malformed_handshake_scope(mut self) -> Self {
        self.malformed_handshake_scope = true;
        self
    }

    fn with_reply_state_generation(mut self, state_generation: u64) -> Self {
        self.reply_state_generation = Some(state_generation);
        self
    }

    fn with_injected_extension(mut self) -> Self {
        self.inject_extension = true;
        self
    }

    fn with_large_response_payload(mut self) -> Self {
        self.large_response_payload = true;
        self
    }

    fn with_surface_payload_identity_leak(mut self) -> Self {
        self.leak_surface_payload_identity = true;
        self
    }

    fn with_safe_response_payload(mut self) -> Self {
        self.safe_response_payload = true;
        self
    }

    fn reply_code_for(&self, operation: ProviderOperation, code: TerminalCode) -> TerminalCode {
        if operation == ProviderOperation::Handshake {
            self.handshake_code.unwrap_or(code)
        } else {
            self.reply_code.unwrap_or(code)
        }
    }

    fn effect_state_for(
        &self,
        operation: ProviderOperation,
        code: TerminalCode,
        surface_idempotency_key: Option<&str>,
    ) -> CommittedEffectState {
        let default_effect = if code == TerminalCode::Success && operation.mutates_provider_state()
        {
            CommittedEffectState::Committed
        } else {
            CommittedEffectState::None
        };
        if operation == ProviderOperation::Handshake {
            return default_effect;
        }
        match self.reply_effect.unwrap_or(default_effect) {
            // A duplicate needs a key to have deduplicated. A read-only call
            // never carries one, so the override degrades to the default rather
            // than fabricating a binding the surface could not have had.
            CommittedEffectState::Duplicate if surface_idempotency_key.is_none() => default_effect,
            state => state,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal(
        &self,
        operation_id: &str,
        namespace: &NcmNamespace,
        operation: ProviderOperation,
        code: TerminalCode,
        state_generation_before: Option<u64>,
        aliases: &[String],
        surface_idempotency_key: Option<&str>,
    ) -> TerminalRecord {
        let code = self.reply_code_for(operation, code);
        let effect_state = self.effect_state_for(operation, code, surface_idempotency_key);
        let effect = match effect_state {
            CommittedEffectState::None => CommittedEffectEvidence::none(state_generation_before),
            CommittedEffectState::Committed => {
                let before = state_generation_before.expect("committed generation before");
                let receipt_alias = aliases
                    .iter()
                    .find(|value| value.as_str() == ONE_SHA)
                    .map_or(ONE_SHA, String::as_str);
                CommittedEffectEvidence::committed(
                    before,
                    before.saturating_add(1),
                    if self.leak_effect_metadata_aliases {
                        aliases.to_vec()
                    } else {
                        vec!["ncm.item-committed".to_owned()]
                    },
                    if self.leak_provider_receipt_alias {
                        receipt_alias
                    } else {
                        PROVIDER_RECEIPT_SHA
                    },
                    if self.leak_verification_alias {
                        receipt_alias
                    } else {
                        VERIFICATION_SHA
                    },
                )
                .expect("committed effect")
            }
            CommittedEffectState::Partial => {
                let before = state_generation_before.expect("partial generation before");
                CommittedEffectEvidence::partial(
                    "after:ncm.item-committed",
                    before,
                    before.saturating_add(1),
                    vec!["ncm.item-committed".to_owned()],
                    vec!["ncm.item-uncommitted".to_owned()],
                    PROVIDER_RECEIPT_SHA,
                    "resume:ncm.item-uncommitted",
                    VERIFICATION_SHA,
                )
                .expect("partial effect")
            }
            CommittedEffectState::Duplicate => {
                let before = state_generation_before.expect("duplicate generation before");
                CommittedEffectEvidence::duplicate(
                    before,
                    surface_idempotency_key.expect("surface idempotency key"),
                    "ncm.surface.operation-original.v1",
                    PROVIDER_RECEIPT_SHA,
                )
                .expect("duplicate effect")
            }
            CommittedEffectState::Unknown => CommittedEffectEvidence::unknown(
                PROVIDER_RECEIPT_SHA,
                "ncm.surface.reconcile-operation.v1",
            )
            .expect("unknown effect"),
        };
        let malformed_scope = if operation == ProviderOperation::Handshake {
            self.malformed_handshake_scope
        } else {
            self.malformed_reply_scope
        };
        let scope = if malformed_scope {
            ONE_SHA
        } else {
            namespace.as_str()
        };
        let terminal_operation_id =
            if self.public_reply_operation_id && operation != ProviderOperation::Handshake {
                format!("operation-{}", operation.capability_id())
            } else {
                operation_id.to_owned()
            };
        let diagnostic_id =
            if operation != ProviderOperation::Handshake && self.leak_terminal_diagnostic_aliases {
                Some(format!("request-a|project-a|{operation_id}"))
            } else {
                (code != TerminalCode::Success).then(|| format!("ncm.{}", code.as_wire()))
            };
        TerminalRecord::new(
            operation,
            self.descriptor_snapshot().provider_id,
            code,
            effect,
            FallbackDirective::forbidden(),
            terminal_operation_id,
            scope,
            diagnostic_id,
        )
        .expect("terminal")
    }
}

impl NcmCognitiveSurface for MockSurface {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor_snapshot()
    }

    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        let call_number = self.handshake_calls.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_handshake.lock().expect("handshake lock") = Some(request.clone());
        if self.block_handshake_call == Some(call_number) {
            self.handshake_entered
                .as_ref()
                .expect("handshake entered barrier")
                .wait();
            self.handshake_release
                .as_ref()
                .expect("handshake release barrier")
                .wait();
        }
        let ready_receipt_sha256 = ONE_SHA.to_owned();
        let provider_instance_id = "ncm.instance-1";
        let descriptor = self.descriptor_snapshot();
        let challenge_response_sha256 = if self.malformed_handshake_proof
            || self.malformed_handshake_proof_call == Some(call_number)
        {
            ZERO_SHA.to_owned()
        } else {
            request.expected_challenge_response_sha256(
                &descriptor,
                provider_instance_id,
                &ready_receipt_sha256,
            )
        };
        NcmSurfaceHandshakeResponse {
            terminal: self.terminal(
                &request.request_id,
                &request.namespace,
                ProviderOperation::Handshake,
                TerminalCode::Success,
                None,
                &[],
                None,
            ),
            descriptor: Some(descriptor.clone()),
            provider_instance_id: Some(provider_instance_id.to_owned()),
            namespace: Some(request.namespace.clone()),
            effective_limits: Some(request.host_limits.minimum(descriptor.limits)),
            ready_receipt_sha256: Some(ready_receipt_sha256),
            challenge_response_sha256: Some(challenge_response_sha256),
            warnings: (self.handshake_warning_size > 0)
                .then(|| "w".repeat(self.handshake_warning_size))
                .into_iter()
                .collect(),
        }
    }

    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
        let call_number = self.invoke_calls.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_call.lock().expect("call lock") = Some(call.clone());
        if self.block_invoke_call == Some(call_number) {
            self.invoke_entered
                .as_ref()
                .expect("invoke entered barrier")
                .wait();
            self.invoke_release
                .as_ref()
                .expect("invoke release barrier")
                .wait();
        }
        let mut payload = call.payload.clone();
        if self.large_response_payload {
            payload.bytes = vec![b'x'; 16_384];
            payload.sha256 = hex_digest(&Sha256::digest(&payload.bytes));
        }
        if self.leak_surface_payload_identity {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "surface_namespace": call.namespace.as_str(),
                "safe": true
            }))
            .expect("surface leak fixture");
            payload = canonical_payload(call.operation, &bytes);
        }
        if self.safe_response_payload {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "safe": {"kind": "observation"}
            }))
            .expect("safe response fixture");
            payload = canonical_payload(call.operation, &bytes);
        }
        if self.corrupt_payload_digest {
            payload.sha256 = ZERO_SHA.to_owned();
        }
        let aliases = surface_reply_aliases(call);
        ProviderReply {
            terminal: self.terminal(
                &call.operation_id,
                &call.namespace,
                call.operation,
                TerminalCode::Success,
                Some(call.expected_state_generation),
                &aliases,
                call.idempotency_key.as_deref(),
            ),
            payload: Some(payload),
            warnings: if self.leak_warning_aliases {
                aliases
            } else {
                vec!["warning".to_owned(); self.warning_count]
            },
            extensions: self
                .inject_extension
                .then(optional_extension)
                .into_iter()
                .collect(),
            state_generation: self.reply_state_generation.unwrap_or_else(|| {
                // A duplicate acknowledges an effect that already landed, so
                // the generation it reports must not move.
                let acknowledges_prior_effect = self.effect_state_for(
                    call.operation,
                    self.reply_code_for(call.operation, TerminalCode::Success),
                    call.idempotency_key.as_deref(),
                ) == CommittedEffectState::Duplicate;
                if call.operation.mutates_provider_state() && !acknowledges_prior_effect {
                    call.expected_state_generation.saturating_add(1)
                } else {
                    call.expected_state_generation
                }
            }),
        }
    }
}

const IDENTITY_REFRESH_DIAGNOSTIC: &str = "ncm.rust.handshake_identity_refresh_required";

struct HandshakeRefreshSurface {
    inner: Arc<MockSurface>,
    handshake_calls: AtomicUsize,
    stale_forever: bool,
    cancel_after_stale: AtomicBool,
    malformed_retry_identity: bool,
    diagnostic: &'static str,
}

impl HandshakeRefreshSurface {
    fn new(inner: Arc<MockSurface>, stale_forever: bool) -> Self {
        Self {
            inner,
            handshake_calls: AtomicUsize::new(0),
            stale_forever,
            cancel_after_stale: AtomicBool::new(false),
            malformed_retry_identity: false,
            diagnostic: IDENTITY_REFRESH_DIAGNOSTIC,
        }
    }

    fn cancel_after_stale(self) -> Self {
        self.cancel_after_stale.store(true, Ordering::Release);
        self
    }

    fn malformed_retry_identity(mut self) -> Self {
        self.malformed_retry_identity = true;
        self
    }

    fn with_diagnostic(mut self, diagnostic: &'static str) -> Self {
        self.diagnostic = diagnostic;
        self
    }

    fn stale_response(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        self.inner.change_state_generation(5);
        let observed_generation = self.inner.descriptor_snapshot().state_generation;
        if self.cancel_after_stale.load(Ordering::Acquire) {
            request.control.cancellation().cancel();
        }
        NcmSurfaceHandshakeResponse {
            terminal: TerminalRecord::new(
                ProviderOperation::Handshake,
                OwnedProviderId::new(NCM_PROVIDER_ID).expect("provider id"),
                TerminalCode::StaleIdentity,
                CommittedEffectEvidence::none(Some(observed_generation)),
                FallbackDirective::forbidden(),
                request.request_id.clone(),
                request.namespace.as_str(),
                Some(self.diagnostic.to_owned()),
            )
            .expect("stale identity terminal"),
            descriptor: None,
            provider_instance_id: None,
            namespace: None,
            effective_limits: None,
            ready_receipt_sha256: None,
            challenge_response_sha256: None,
            warnings: Vec::new(),
        }
    }
}

impl NcmCognitiveSurface for HandshakeRefreshSurface {
    fn descriptor(&self) -> ProviderDescriptor {
        self.inner.descriptor()
    }

    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        let call = self.handshake_calls.fetch_add(1, Ordering::AcqRel);
        if self.stale_forever || call == 0 {
            return self.stale_response(request);
        }
        if self.malformed_retry_identity {
            self.inner.change_implementation_identity(ONE_SHA);
        }
        self.inner.handshake(request)
    }

    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
        self.inner.invoke(call)
    }
}

fn surface_reply_aliases(surface_call: &NcmSurfaceCall) -> Vec<String> {
    let exact_scope = scope();
    let public_call = call(NCM_PROVIDER_ID, surface_call.operation);
    let public_scope_digest = exact_scope.exact_scope_sha256();
    let mut aliases = BTreeSet::from([
        exact_scope.profile_id,
        exact_scope.project_id,
        exact_scope.repository_identity,
        exact_scope.worktree_identity,
        exact_scope.branch_identity,
        exact_scope.agent_session_id,
        public_scope_digest,
        public_call.ready_receipt_sha256,
        public_call.request_id,
        public_call.operation_id,
        surface_call.namespace.as_str().to_owned(),
        surface_call.ready_receipt_sha256.clone(),
        surface_call.request_id.clone(),
        surface_call.operation_id.clone(),
    ]);
    if let Some(value) = public_call.idempotency_key {
        aliases.insert(value);
    }
    if let Some(value) = &surface_call.idempotency_key {
        aliases.insert(value.clone());
    }
    aliases.into_iter().collect()
}

fn limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 4096,
        response_bytes: 8192,
        observation_batch_items: 16,
        recall_candidates: 32,
        concurrent_operations: 4,
        operation_millis: 1000,
        snapshot_bytes: 65536,
        inspection_items: 64,
    }
}

fn scope() -> OwnedExactScope {
    OwnedExactScope::new(
        "profile-a",
        "project-a",
        "repository-a",
        "worktree-a",
        "refs/heads/main",
        "session-a",
        RESOLVED_SCOPE_DIGEST,
    )
    .expect("scope")
}

fn handshake(provider_id: &str) -> HandshakeRequest {
    HandshakeRequest::new(HandshakeRequestParts {
        provider_id: OwnedProviderId::new(provider_id).expect("provider id"),
        registration_revision: 1,
        exact_scope: scope(),
        request_id: "handshake-a".to_owned(),
        required_capabilities: [
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
        ]
        .into_iter()
        .map(|value| OwnedVersionedId::new(value).expect("capability"))
        .collect::<Vec<_>>(),
        host_limits: limits(),
        control: OperationControl::new(i64::MAX, 500, CancellationToken::new()),
        challenge_nonce: [7; 32],
    })
    .expect("handshake")
}

fn call(provider_id: &str, operation: ProviderOperation) -> ProviderCall {
    ProviderCall::new(ProviderCallParts {
        operation,
        provider_id: OwnedProviderId::new(provider_id).expect("provider id"),
        registration_revision: 1,
        ready_receipt_sha256: ZERO_SHA.to_owned(),
        exact_scope: scope(),
        request_id: "request-a".to_owned(),
        operation_id: format!("operation-{}", operation.capability_id()),
        expected_state_generation: 4,
        idempotency_key: operation
            .mutates_provider_state()
            .then(|| "idempotency-a".to_owned()),
        control: OperationControl::new(i64::MAX, 500, CancellationToken::new()),
        payload: canonical_payload(operation, b"{}"),
        required_capabilities: [
            OwnedVersionedId::new(operation.capability_id()).expect("operation capability")
        ]
        .into_iter()
        .collect::<Vec<_>>(),
        extensions: Vec::new(),
    })
    .map(admitted)
    .expect("call")
}

/// Sanitizer revision this harness stands in for. The real revision is derived
/// by `tracedecay-memory-hygiene` from the canonical policy document.
const TEST_SANITIZER_REVISION: &str = "tracedecay.memory.observation.hygiene.v1+ncm-test";

/// Attaches the receipt the admitted hygiene pipeline mints for a payload and
/// extension set it read and left byte-identical. Observation dispatch fails
/// closed without one, and the receipt binds the extensions as well as the
/// payload, so a fixture that changes either has to re-admit the call.
fn admitted(call: ProviderCall) -> ProviderCall {
    if call.operation != ProviderOperation::Observe {
        return call;
    }
    let extensions_digest =
        observation_extensions_digest(&call.extensions).expect("admitted extension set");
    let receipt = PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts::accepted_unmodified_with_extensions(
            TEST_SANITIZER_REVISION,
            call.payload.sha256.clone(),
            extensions_digest,
        ),
    )
    .expect("accepted sanitization receipt");
    call.with_sanitization(receipt)
}

fn operation_contract_id(operation: ProviderOperation) -> &'static str {
    match operation {
        ProviderOperation::Handshake => "tracedecay.memory.provider.handshake.v1",
        ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
        ProviderOperation::Observe => "tracedecay.memory.provider.observation.v1",
        ProviderOperation::Recall => "tracedecay.memory.provider.recall.v1",
        ProviderOperation::Feedback => "tracedecay.memory.provider.feedback.v1",
        ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
        ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
        ProviderOperation::Correction => "tracedecay.memory.provider.correction.v1",
        ProviderOperation::DeleteBySource => "tracedecay.memory.provider.deletion-by-source.v1",
        ProviderOperation::SnapshotExport => "tracedecay.memory.provider.snapshot-export.v1",
        ProviderOperation::SnapshotRestore => "tracedecay.memory.provider.snapshot-restore.v1",
        ProviderOperation::Replay => "tracedecay.memory.provider.replay.v1",
    }
}

fn canonical_payload(operation: ProviderOperation, bytes: &[u8]) -> CanonicalPayload {
    CanonicalPayload::new(
        OwnedVersionedId::new(operation_contract_id(operation)).expect("payload contract"),
        bytes.to_vec(),
        hex_digest(&Sha256::digest(bytes)),
    )
    .expect("payload")
}

fn optional_extension() -> OwnedOpaqueExtension {
    opaque_extension(b"{}")
}

fn opaque_extension(bytes: &[u8]) -> OwnedOpaqueExtension {
    OwnedOpaqueExtension::new(
        OwnedVersionedId::new("vendor.optional.v1").expect("extension id"),
        1,
        false,
        hex_digest(&Sha256::digest(bytes)),
        bytes.to_vec(),
    )
    .expect("extension")
}

fn hex_digest(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonical_request_size(call: &ProviderCall) -> u64 {
    let mut total = framed_size(call.operation.capability_id());
    total = total.saturating_add(framed_size(call.provider_id.as_str()));
    total = total.saturating_add(8);
    total = total.saturating_add(framed_size(&call.ready_receipt_sha256));
    // Seven length-framed scope strings and no scalar, mirroring the
    // provider-API authority: the resolved digest replaced the fixed-width
    // revision counter.
    for value in [
        &call.exact_scope.profile_id,
        &call.exact_scope.project_id,
        &call.exact_scope.repository_identity,
        &call.exact_scope.worktree_identity,
        &call.exact_scope.branch_identity,
        &call.exact_scope.agent_session_id,
        &call.exact_scope.resolved_scope_digest,
    ] {
        total = total.saturating_add(framed_size(value));
    }
    total = total.saturating_add(framed_size(&call.request_id));
    total = total.saturating_add(framed_size(&call.operation_id));
    total = total.saturating_add(8);
    total = total.saturating_add(1);
    if let Some(idempotency_key) = &call.idempotency_key {
        total = total.saturating_add(framed_size(idempotency_key));
    }
    total = total.saturating_add(16);
    total = total.saturating_add(framed_size("live"));
    total = total.saturating_add(canonical_payload_size(&call.payload));
    total = total.saturating_add(8);
    for capability in &call.required_capabilities {
        total = total.saturating_add(framed_size(capability.as_str()));
    }
    total = total.saturating_add(8);
    for extension in &call.extensions {
        total = total.saturating_add(canonical_extension_size(extension));
    }
    total
}

fn canonical_surface_request_size(call: &ProviderCall) -> u64 {
    let mut total = framed_size(call.operation.capability_id());
    total = total.saturating_add(framed_size(
        NcmNamespace::from_exact_scope(&call.exact_scope).as_str(),
    ));
    total = total.saturating_add(8);
    total = total.saturating_add(framed_size(ONE_SHA));
    total = total.saturating_add(framed_size(ZERO_SHA));
    total = total.saturating_add(framed_size(ZERO_SHA));
    total = total.saturating_add(8);
    total = total.saturating_add(1);
    if call.idempotency_key.is_some() {
        total = total.saturating_add(framed_size(ZERO_SHA));
    }
    total = total.saturating_add(16);
    total = total.saturating_add(framed_size("live"));
    total = total.saturating_add(canonical_payload_size(&call.payload));
    total = total.saturating_add(8);
    for capability in &call.required_capabilities {
        total = total.saturating_add(framed_size(capability.as_str()));
    }
    total.saturating_add(8)
}

fn canonical_surface_handshake_request_size(request: &HandshakeRequest) -> u64 {
    let mut total = 8_u64;
    total = total.saturating_add(framed_size(
        NcmNamespace::from_exact_scope(&request.exact_scope).as_str(),
    ));
    total = total.saturating_add(framed_size(ZERO_SHA));
    total = total.saturating_add(8);
    for capability in &request.required_capabilities {
        total = total.saturating_add(framed_size(capability.as_str()));
    }
    total = total.saturating_add(8 * 8);
    total = total.saturating_add(16);
    total = total.saturating_add(framed_size("live"));
    total.saturating_add(32)
}

fn canonical_response_size(call: &ProviderCall, reply: &ProviderReply) -> u64 {
    let mut total = framed_size(reply.terminal.operation().as_wire());
    total = total.saturating_add(framed_size(reply.terminal.provider_id().as_str()));
    total = total.saturating_add(framed_size(reply.terminal.terminal_code().as_wire()));
    total = total.saturating_add(canonical_committed_effect_size(
        reply.terminal.committed_effect(),
    ));
    total = total.saturating_add(canonical_fallback_size(reply.terminal.fallback()));
    total = total.saturating_add(framed_size(&call.operation_id));
    total = total.saturating_add(framed_size(&call.exact_scope.exact_scope_sha256()));
    total = total.saturating_add(canonical_optional_str_size(reply.terminal.diagnostic_id()));
    total = total.saturating_add(1);
    if let Some(payload) = &reply.payload {
        total = total.saturating_add(canonical_payload_size(payload));
    }
    total = total.saturating_add(8);
    for warning in &reply.warnings {
        total = total.saturating_add(framed_size(warning));
    }
    total = total.saturating_add(8);
    for extension in &call.extensions {
        total = total.saturating_add(canonical_extension_size(extension));
    }
    total.saturating_add(8)
}

fn canonical_committed_effect_size(effect: &CommittedEffectEvidence) -> u64 {
    let mut total = framed_size(effect.state().as_wire());
    total = total.saturating_add(canonical_optional_str_size(effect.committed_boundary()));
    total = total.saturating_add(canonical_optional_u64_size(
        effect.state_generation_before(),
    ));
    total = total.saturating_add(canonical_optional_u64_size(effect.state_generation_after()));
    total = total.saturating_add(8);
    for item_ref in effect.committed_item_refs() {
        total = total.saturating_add(framed_size(item_ref));
    }
    total = total.saturating_add(8);
    for item_ref in effect.uncommitted_item_refs() {
        total = total.saturating_add(framed_size(item_ref));
    }
    total = total.saturating_add(canonical_optional_str_size(
        effect.provider_receipt_sha256(),
    ));
    total = total.saturating_add(canonical_optional_str_size(effect.reconciliation_action()));
    total = total.saturating_add(canonical_optional_str_size(effect.verification_sha256()));
    total = total.saturating_add(canonical_optional_str_size(
        effect.duplicate_of_idempotency_key(),
    ));
    total.saturating_add(canonical_optional_str_size(
        effect.duplicate_of_operation_id(),
    ))
}

fn canonical_fallback_size(fallback: &FallbackDirective) -> u64 {
    let mut total = framed_size(fallback.eligibility().as_wire());
    total = total.saturating_add(canonical_optional_str_size(
        fallback.source_provider_id().map(OwnedProviderId::as_str),
    ));
    total = total.saturating_add(1);
    if let Some(policy) = fallback.policy() {
        total = total.saturating_add(framed_size(policy.policy_id()));
        total = total.saturating_add(8);
        total = total.saturating_add(framed_size(policy.target_provider_id().as_str()));
    }
    total.saturating_add(canonical_optional_str_size(fallback.reason()))
}

fn canonical_optional_str_size(value: Option<&str>) -> u64 {
    1_u64.saturating_add(value.map_or(0, framed_size))
}

fn canonical_optional_u64_size(value: Option<u64>) -> u64 {
    1_u64.saturating_add(value.map_or(0, |_| 8))
}

fn canonical_payload_size(payload: &CanonicalPayload) -> u64 {
    framed_size(payload.contract_id.as_str())
        .saturating_add(framed_slice_size(&payload.bytes))
        .saturating_add(framed_size(&payload.sha256))
}

fn canonical_extension_size(extension: &OwnedOpaqueExtension) -> u64 {
    framed_size(extension.extension_id.as_str())
        .saturating_add(5)
        .saturating_add(framed_size(&extension.payload_sha256))
        .saturating_add(framed_slice_size(&extension.canonical_payload))
}

fn framed_size(value: &str) -> u64 {
    framed_slice_size(value.as_bytes())
}

fn framed_slice_size(value: &[u8]) -> u64 {
    8_u64.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
}

fn establish_readiness(provider: &NcmProviderAdapter, request: &HandshakeRequest) -> String {
    let response = provider.handshake(request);
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
    response
        .ready_receipt_sha256
        .expect("successful handshake receipt")
}

fn ready_call(provider: &NcmProviderAdapter, operation: ProviderOperation) -> ProviderCall {
    let handshake_request = handshake(NCM_PROVIDER_ID);
    let ready_receipt_sha256 = establish_readiness(provider, &handshake_request);
    let mut request = call(NCM_PROVIDER_ID, operation);
    request.registration_revision = handshake_request.registration_revision;
    request.exact_scope = handshake_request.exact_scope;
    request.ready_receipt_sha256 = ready_receipt_sha256;
    request
}

fn assert_post_dispatch_mutation_failure(reply: &ProviderReply, request: &ProviderCall) {
    assert_eq!(reply.terminal.operation(), request.operation);
    assert_eq!(reply.terminal.provider_id(), &request.provider_id);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::EffectUnknown);
    assert_eq!(reply.terminal.operation_id(), request.operation_id);
    assert_eq!(
        reply.terminal.exact_scope_sha256(),
        request.exact_scope.exact_scope_sha256()
    );
    let effect = reply.terminal.committed_effect();
    assert_eq!(effect.state(), CommittedEffectState::Unknown);
    assert!(effect.committed_boundary().is_none());
    assert!(effect.state_generation_before().is_none());
    assert!(effect.state_generation_after().is_none());
    assert!(effect.committed_item_refs().is_empty());
    assert!(effect.uncommitted_item_refs().is_empty());
    assert!(effect.verification_sha256().is_none());
    let receipt = effect
        .provider_receipt_sha256()
        .expect("adapter dispatch witness receipt");
    assert_eq!(receipt.len(), 64);
    assert!(
        receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_ne!(receipt, ZERO_SHA);
    assert_ne!(receipt, ONE_SHA);
    let expected_action = format!("ncm.adapter.reconcile-surface-dispatch.v1:{receipt}");
    assert_eq!(
        effect.reconciliation_action(),
        Some(expected_action.as_str())
    );
    let fallback = reply.terminal.fallback();
    assert_eq!(fallback.eligibility(), FallbackEligibility::Forbidden);
    assert!(fallback.source_provider_id().is_none());
    assert!(fallback.policy().is_none());
    assert!(fallback.reason().is_none());
    assert!(reply.payload.is_none());
    assert!(reply.warnings.is_empty());
    assert!(reply.extensions.is_empty());
}

fn assert_terminal_metadata_contains_no_aliases(reply: &ProviderReply, aliases: &[String]) {
    let captured = format!(
        "{:?}|{:?}|{:?}",
        reply.terminal.diagnostic_id(),
        reply.terminal.committed_effect(),
        reply.warnings
    );
    for alias in aliases {
        assert!(
            !captured.contains(alias),
            "terminal metadata leaked alias {alias:?}: {captured}"
        );
    }
}

fn assert_surface_alias_leak_is_rejected(
    surface: &MockSurface,
    reply: &ProviderReply,
    request: &ProviderCall,
) {
    assert_post_dispatch_mutation_failure(reply, request);
    let mapped = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_terminal_metadata_contains_no_aliases(reply, &surface_reply_aliases(&mapped));
}

#[test]
fn constructor_rejects_a_non_ncm_surface() {
    let surface = Arc::new(MockSurface::new("vendor.memory", &[], false));
    let result = NcmProviderAdapter::new(surface);
    assert_eq!(
        result.err(),
        Some(NcmAdapterError::ProviderIdMismatch {
            expected: NCM_PROVIDER_ID,
            declared: "vendor.memory".to_owned(),
        })
    );
}

fn checkout_namespace(scope: &OwnedExactScope) -> NcmNamespace {
    NcmNamespace::from_scope(scope, NcmNamespaceBinding::CheckoutObservationsV1)
}

#[test]
fn legacy_namespace_default_keeps_persisted_identity_bytes() {
    let exact = OwnedExactScope::new(
        "profile",
        "project",
        "repository",
        "worktree",
        "master",
        "session",
        format!("sha256:{}", "ab".repeat(32)),
    )
    .expect("scope");
    assert_eq!(
        NcmNamespaceBinding::default(),
        NcmNamespaceBinding::ExactSessionV1
    );
    assert_eq!(
        NcmNamespace::from_exact_scope(&exact).as_str(),
        "d3edecaca5ee5a69ae69f74669c509b38d71a10831583941baef6f9ae88bb64b"
    );
    assert_eq!(
        NcmNamespace::from_scope(&exact, NcmNamespaceBinding::default()),
        NcmNamespace::from_exact_scope(&exact)
    );
    assert_ne!(
        checkout_namespace(&exact),
        NcmNamespace::from_exact_scope(&exact)
    );
    let mut next = exact.clone();
    next.agent_session_id = "next-session".to_owned();
    assert_ne!(
        NcmNamespace::from_exact_scope(&next),
        NcmNamespace::from_exact_scope(&exact)
    );
    assert_eq!(checkout_namespace(&next), checkout_namespace(&exact));
}

#[test]
fn namespace_is_deterministic_and_opaque() {
    let first = NcmNamespace::from_exact_scope(&scope());
    let second = NcmNamespace::from_exact_scope(&scope());
    assert_eq!(first, second);
    assert_eq!(first.as_str().len(), 64);
    assert!(
        first
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(!first.as_str().contains("project-a"));
    assert!(!first.as_str().contains("worktree-a"));
}

#[test]
fn namespace_isolates_worktree_and_branch() {
    let original = scope();
    let mut changed_worktree = original.clone();
    changed_worktree.worktree_identity = "worktree-b".to_owned();
    let mut changed_branch = original.clone();
    changed_branch.branch_identity = "refs/heads/feature".to_owned();
    let mut changed_session = original.clone();
    changed_session.agent_session_id = "session-b".to_owned();
    let values = [
        checkout_namespace(&original),
        checkout_namespace(&changed_worktree),
        checkout_namespace(&changed_branch),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(values.len(), 3);
    assert_eq!(
        checkout_namespace(&original),
        checkout_namespace(&changed_session)
    );
}

#[test]
fn namespace_isolates_profile_project_and_repository() {
    let original = scope();
    let mut changed_profile = original.clone();
    changed_profile.profile_id = "profile-b".to_owned();
    let mut changed_project = original.clone();
    changed_project.project_id = "project-b".to_owned();
    let mut changed_repository = original.clone();
    changed_repository.repository_identity = "repository-b".to_owned();
    let mut changed_resolved_scope = original.clone();
    changed_resolved_scope.resolved_scope_digest = format!("sha256:{PROVIDER_RECEIPT_SHA}");
    let values = [
        checkout_namespace(&original),
        checkout_namespace(&changed_profile),
        checkout_namespace(&changed_project),
        checkout_namespace(&changed_repository),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(values.len(), 4);
    assert_eq!(
        checkout_namespace(&original),
        checkout_namespace(&changed_resolved_scope)
    );
}

#[test]
fn handshake_exposes_only_namespace_to_surface_and_reattaches_scope() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = handshake(NCM_PROVIDER_ID);
    request.request_id = format!("handshake-{}", request.exact_scope.project_id);
    let expected_namespace = NcmNamespace::from_exact_scope(&request.exact_scope);
    let response = provider.handshake(&request);
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(response.terminal.operation_id(), request.request_id);
    assert_eq!(
        response.terminal.exact_scope_sha256(),
        request.exact_scope.exact_scope_sha256()
    );
    assert_ne!(
        response.terminal.exact_scope_sha256(),
        expected_namespace.as_str()
    );
    assert_eq!(response.accepted_scope, Some(request.exact_scope.clone()));
    assert_eq!(
        response.state_namespace.as_deref(),
        Some(expected_namespace.as_str())
    );
    let mapped = surface
        .last_handshake
        .lock()
        .expect("handshake lock")
        .clone()
        .expect("mapped handshake");
    assert_eq!(mapped.namespace, expected_namespace);
    assert_ne!(mapped.request_id, request.request_id);
    assert_eq!(mapped.request_id.len(), 64);
    let captured = format!("{mapped:?}");
    for component in [
        &request.exact_scope.profile_id,
        &request.exact_scope.project_id,
        &request.exact_scope.repository_identity,
        &request.exact_scope.worktree_identity,
        &request.exact_scope.branch_identity,
        &request.exact_scope.agent_session_id,
        &request.exact_scope.resolved_scope_digest,
    ] {
        assert!(!captured.contains(component.as_str()));
    }
    assert_eq!(
        mapped.control.deadline_utc_micros(),
        request.control.deadline_utc_micros()
    );
    request.control.cancellation().cancel();
    assert_eq!(mapped.control.snapshot(), Err(TerminalCode::Cancelled));
}

#[test]
fn checkout_namespace_sharing_never_shares_exact_readiness() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone())
        .expect("adapter")
        .with_namespace_binding(NcmNamespaceBinding::CheckoutObservationsV1);
    let first = provider.handshake(&handshake(NCM_PROVIDER_ID));
    let mut first_call = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    first_call.ready_receipt_sha256 = first.ready_receipt_sha256.clone().expect("receipt");
    let mut other = first_call.clone();
    other.exact_scope.agent_session_id = "session-b".to_owned();
    other.exact_scope.resolved_scope_digest = format!("sha256:{PROVIDER_RECEIPT_SHA}");
    assert_eq!(
        provider.invoke(&other).terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Acquire), 0);
    let mut second_handshake = handshake(NCM_PROVIDER_ID);
    second_handshake.exact_scope = other.exact_scope.clone();
    let second = provider.handshake(&second_handshake);
    assert_eq!(second.state_namespace, first.state_namespace);
    assert_ne!(second.ready_receipt_sha256, first.ready_receipt_sha256);
    other.ready_receipt_sha256 = second.ready_receipt_sha256.expect("receipt");
    assert_eq!(
        provider.invoke(&other).terminal.terminal_code(),
        TerminalCode::Success
    );
    let second_mapped = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_eq!(
        provider.invoke(&first_call).terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    let refreshed = provider.handshake(&handshake(NCM_PROVIDER_ID));
    first_call.ready_receipt_sha256 = refreshed.ready_receipt_sha256.expect("receipt");
    assert_eq!(
        provider.invoke(&first_call).terminal.terminal_code(),
        TerminalCode::Success
    );
    let first_mapped = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_eq!(first_mapped.namespace, second_mapped.namespace);
    assert_ne!(first_mapped.request_id, second_mapped.request_id);
    assert_ne!(first_mapped.operation_id, second_mapped.operation_id);
    assert_eq!(surface.invoke_calls.load(Ordering::Acquire), 2);
}

#[test]
fn handshake_refreshes_one_generation_transition_before_public_recall() {
    let inner = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let surface = Arc::new(HandshakeRefreshSurface::new(inner.clone(), false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(surface.handshake_calls.load(Ordering::Acquire), 2);
    assert_eq!(inner.handshake_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        response
            .descriptor
            .as_ref()
            .expect("ready descriptor")
            .state_generation,
        5
    );

    let mut recall = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    recall.ready_receipt_sha256 = response.ready_receipt_sha256.expect("ready receipt");
    recall.expected_state_generation = 5;
    let reply = provider.invoke(&recall);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(inner.invoke_calls.load(Ordering::Acquire), 1);
}

#[test]
fn handshake_refresh_retry_is_strictly_bounded() {
    let inner = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let surface = Arc::new(HandshakeRefreshSurface::new(inner.clone(), true));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.handshake_calls.load(Ordering::Acquire), 2);
    assert_eq!(inner.handshake_calls.load(Ordering::Acquire), 0);
}

#[test]
fn handshake_does_not_retry_unrelated_stale_identity() {
    let inner = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let surface = Arc::new(
        HandshakeRefreshSurface::new(inner.clone(), false)
            .with_diagnostic("ncm.surface_identity_changed"),
    );
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.handshake_calls.load(Ordering::Acquire), 1);
    assert_eq!(inner.handshake_calls.load(Ordering::Acquire), 0);
}

#[test]
fn handshake_refresh_stops_before_retry_when_cancelled() {
    let inner = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let surface = Arc::new(HandshakeRefreshSurface::new(inner.clone(), false).cancel_after_stale());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Cancelled);
    assert_eq!(surface.handshake_calls.load(Ordering::Acquire), 1);
    assert_eq!(inner.handshake_calls.load(Ordering::Acquire), 0);
}

#[test]
fn handshake_refresh_still_rejects_changed_immutable_identity() {
    let inner = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let surface =
        Arc::new(HandshakeRefreshSurface::new(inner.clone(), false).malformed_retry_identity());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(surface.handshake_calls.load(Ordering::Acquire), 2);
    assert_eq!(inner.handshake_calls.load(Ordering::Acquire), 1);
}

#[test]
fn invoke_before_handshake_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ProviderUnavailable
    );
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.ready_session_missing")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn empty_health_idempotency_key_never_panics_or_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Health);
    request.idempotency_key = Some(String::new());

    let reply = provider.invoke(&request);

    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.call_envelope_invalid")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn empty_recall_idempotency_key_never_panics_or_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.idempotency_key = Some(String::new());

    let reply = provider.invoke(&request);

    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.call_envelope_invalid")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn wrong_ready_receipt_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.ready_receipt_sha256 = ZERO_SHA.to_owned();
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::StaleIdentity);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_replacement_handshakes_preserve_prior_readiness_without_contact() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let old_call = ready_call(&provider, ProviderOperation::Recall);
    let mut invalid_scope = handshake(NCM_PROVIDER_ID);
    invalid_scope.exact_scope.profile_id.clear();
    let mut invalid_revision = handshake(NCM_PROVIDER_ID);
    invalid_revision.registration_revision = 0;
    let mut invalid_request_id = handshake(NCM_PROVIDER_ID);
    invalid_request_id.request_id = " non-canonical".to_owned();

    for invalid in [invalid_scope, invalid_revision, invalid_request_id] {
        let response = provider.handshake(&invalid);
        assert_eq!(
            response.terminal.terminal_code(),
            TerminalCode::InvalidRequest
        );
        assert_eq!(
            response.terminal.diagnostic_id(),
            Some("ncm.handshake_request_invalid")
        );
    }
    assert_eq!(surface.handshake_calls.load(Ordering::Relaxed), 1);

    let reply = provider.invoke(&old_call);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn malformed_replacement_handshake_revokes_prior_readiness() {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_malformed_handshake_proof_call(2),
    );
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let old_call = ready_call(&provider, ProviderOperation::Recall);

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    let reply = provider.invoke(&old_call);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ProviderUnavailable
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn successful_replacement_uses_a_new_public_epoch_receipt() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let old_call = ready_call(&provider, ProviderOperation::Recall);
    let mut replacement = handshake(NCM_PROVIDER_ID);
    replacement.challenge_nonce = [9; 32];
    let response = provider.handshake(&replacement);
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
    let new_receipt = response
        .ready_receipt_sha256
        .expect("replacement ready receipt");
    assert_ne!(new_receipt, old_call.ready_receipt_sha256);

    let old_reply = provider.invoke(&old_call);
    assert_eq!(
        old_reply.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);

    let mut new_call = old_call;
    new_call.ready_receipt_sha256 = new_receipt;
    let new_reply = provider.invoke(&new_call);
    assert_eq!(new_reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn public_ready_receipt_binds_accepted_state_generation() {
    let first_surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let first_provider = NcmProviderAdapter::new(first_surface).expect("adapter");
    let first_receipt = establish_readiness(&first_provider, &handshake(NCM_PROVIDER_ID));

    let second_surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    second_surface.change_state_generation(5);
    let second_provider = NcmProviderAdapter::new(second_surface).expect("adapter");
    let second_receipt = establish_readiness(&second_provider, &handshake(NCM_PROVIDER_ID));

    assert_ne!(first_receipt, second_receipt);
}

#[test]
fn mutation_dispatch_retires_the_accepted_ready_receipt() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);

    let first_reply = provider.invoke(&request);
    assert_eq!(first_reply.terminal.terminal_code(), TerminalCode::Success);

    let stale_reply = provider.invoke(&request);
    assert_eq!(
        stale_reply.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn replacement_handshake_linearizes_before_old_receipt_invoke() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_malformed_handshake_proof_call(2)
            .with_blocking_handshake(2, entered.clone(), release.clone()),
    );
    let provider = Arc::new(NcmProviderAdapter::new(surface.clone()).expect("adapter"));
    let old_call = ready_call(provider.as_ref(), ProviderOperation::Recall);

    let replacement_provider = provider.clone();
    let replacement =
        std::thread::spawn(move || replacement_provider.handshake(&handshake(NCM_PROVIDER_ID)));
    entered.wait();

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let invoke_provider = provider.clone();
    let invoke = std::thread::spawn(move || {
        started_tx.send(()).expect("invoke start signal");
        let reply = invoke_provider.invoke(&old_call);
        done_tx
            .send(reply.terminal.terminal_code())
            .expect("invoke result signal");
    });
    started_rx.recv().expect("invoke started");
    assert_eq!(
        done_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);

    release.wait();
    let replacement_response = replacement.join().expect("replacement thread");
    assert_eq!(
        replacement_response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(
        done_rx.recv().expect("old invoke result"),
        TerminalCode::ProviderUnavailable
    );
    invoke.join().expect("invoke thread");
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn scope_and_registration_mismatches_never_reach_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);

    let mut wrong_scope = request.clone();
    wrong_scope.exact_scope.branch_identity = "refs/heads/other".to_owned();
    let scope_reply = provider.invoke(&wrong_scope);
    assert_eq!(
        scope_reply.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );

    let mut wrong_revision = request;
    wrong_revision.registration_revision = wrong_revision.registration_revision.saturating_add(1);
    let revision_reply = provider.invoke(&wrong_revision);
    assert_eq!(
        revision_reply.terminal.terminal_code(),
        TerminalCode::StaleIdentity
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn post_construction_invalid_exact_scope_never_reaches_invoke_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.exact_scope.agent_session_id.clear();

    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn descriptor_identity_change_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    surface.change_implementation_identity(ONE_SHA);
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::StaleIdentity);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn post_construction_invalid_descriptor_never_reaches_invoke_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    surface.change_implementation_identity("");

    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn post_construction_invalid_descriptor_never_reaches_handshake_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    surface.change_implementation_identity("");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(surface.handshake_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn post_construction_invalid_host_limits_never_reach_handshake_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let old_call = ready_call(&provider, ProviderOperation::Recall);
    let mut invalid = handshake(NCM_PROVIDER_ID);
    invalid.host_limits.concurrent_operations = 0;

    let response = provider.handshake(&invalid);
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::InvalidRequest
    );
    assert_eq!(surface.handshake_calls.load(Ordering::Relaxed), 1);
    let old_reply = provider.invoke(&old_call);
    assert_eq!(old_reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn handshake_only_accepts_exact_success_for_readiness() {
    for code in [TerminalCode::SuccessZeroResults, TerminalCode::Partial] {
        let surface =
            Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_handshake_code(code));
        let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
        let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
        assert_eq!(
            response.terminal.terminal_code(),
            TerminalCode::ContractViolation
        );
        assert!(response.ready_receipt_sha256.is_none());

        let invoke_reply = provider.invoke(&call(NCM_PROVIDER_ID, ProviderOperation::Recall));
        assert_eq!(
            invoke_reply.terminal.terminal_code(),
            TerminalCode::ProviderUnavailable
        );
        assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn mandatory_operation_uses_opaque_ids_and_scope_safe_payload() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(
        reply.terminal.exact_scope_sha256(),
        request.exact_scope.exact_scope_sha256()
    );
    assert_eq!(reply.payload, Some(request.payload.clone()));
    let mapped = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_eq!(
        mapped.namespace,
        NcmNamespace::from_exact_scope(&request.exact_scope)
    );
    assert_eq!(mapped.registration_revision, request.registration_revision);
    assert_eq!(mapped.ready_receipt_sha256, ONE_SHA);
    assert_ne!(mapped.ready_receipt_sha256, request.ready_receipt_sha256);
    assert_ne!(mapped.request_id, request.request_id);
    assert_ne!(mapped.operation_id, request.operation_id);
    assert_ne!(mapped.idempotency_key, request.idempotency_key);
    assert_eq!(mapped.payload, request.payload);
    assert!(mapped.extensions.is_empty());
    assert_eq!(
        mapped.control.deadline_utc_micros(),
        request.control.deadline_utc_micros()
    );
    let mapped_remaining = mapped.control.snapshot().expect("mapped control");
    let request_remaining = request.control.snapshot().expect("request control");
    assert_eq!(
        mapped_remaining.deadline_utc_micros,
        request_remaining.deadline_utc_micros
    );
    assert_eq!(
        mapped_remaining.cancellation,
        request_remaining.cancellation
    );
    assert!(mapped.control.remaining_millis() <= request.control.remaining_millis());
    assert!(request_remaining.remaining_millis <= mapped_remaining.remaining_millis);
}

#[test]
fn surface_capture_contains_no_public_ids_scope_or_extension_bytes() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_safe_response_payload());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Observe);
    let exact_scope = request.exact_scope.clone();
    request.request_id = format!(
        "request:{}:{}:{}",
        exact_scope.profile_id, exact_scope.project_id, exact_scope.repository_identity
    );
    request.operation_id = format!(
        "operation:{}:{}",
        exact_scope.worktree_identity, exact_scope.branch_identity
    );
    request.idempotency_key = Some(format!("idempotency:{}", exact_scope.agent_session_id));
    let payload = serde_json::json!({
        "exact_scope_identity": {
            "profile_id": exact_scope.profile_id.clone(),
            "project_id": exact_scope.project_id.clone(),
            "repository_identity": exact_scope.repository_identity.clone(),
            "worktree_identity": exact_scope.worktree_identity.clone(),
            "branch_identity": exact_scope.branch_identity.clone(),
            "agent_session_id": exact_scope.agent_session_id.clone(),
            "resolved_scope_digest": exact_scope.resolved_scope_digest.clone()
        },
        "safe": {"kind": "observation"},
        "request_identity": request.request_id.clone(),
        "operation_id": request.operation_id.clone(),
        "idempotency_key": request.idempotency_key.clone(),
        "nested": [{
            "exact_scope_identity": {
                "project_id": exact_scope.project_id.clone()
            }
        }]
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("fixture payload");
    request.payload = canonical_payload(ProviderOperation::Observe, &payload_bytes);
    let extension = opaque_extension(
        format!(
            "{{\"branch\":\"{}\",\"session\":\"{}\"}}",
            exact_scope.branch_identity, exact_scope.agent_session_id
        )
        .as_bytes(),
    );
    request.extensions.push(extension.clone());
    // Re-admit: the receipt binds the payload digest, so a replaced payload
    // needs a receipt for the bytes actually dispatched.
    let request = admitted(request);

    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(reply.terminal.operation_id(), request.operation_id);
    assert_eq!(reply.extensions, vec![extension.clone()]);

    let mapped = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_ne!(mapped.request_id, request.request_id);
    assert_ne!(mapped.operation_id, request.operation_id);
    assert_ne!(mapped.idempotency_key, request.idempotency_key);
    assert!(mapped.extensions.is_empty());
    let mapped_payload = serde_json::from_slice::<serde_json::Value>(&mapped.payload.bytes)
        .expect("mapped JSON payload");
    assert_eq!(
        mapped_payload,
        serde_json::json!({
            "idempotency_key": mapped.idempotency_key.clone(),
            "nested": [{}],
            "operation_id": mapped.operation_id.clone(),
            "request_identity": mapped.request_id.clone(),
            "safe": {"kind": "observation"}
        })
    );
    let captured_call = format!("{mapped:?}");
    let mapped_payload_text = String::from_utf8(mapped.payload.bytes).expect("mapped UTF-8 JSON");
    assert!(!captured_call.contains(request.request_id.as_str()));
    assert!(!captured_call.contains(request.operation_id.as_str()));
    assert!(!mapped_payload_text.contains(request.request_id.as_str()));
    assert!(!mapped_payload_text.contains(request.operation_id.as_str()));
    assert!(
        !mapped_payload_text.contains(request.idempotency_key.as_deref().expect("idempotency key"))
    );
    for component in [
        &request.exact_scope.profile_id,
        &request.exact_scope.project_id,
        &request.exact_scope.repository_identity,
        &request.exact_scope.worktree_identity,
        &request.exact_scope.branch_identity,
        &request.exact_scope.agent_session_id,
        &request.exact_scope.resolved_scope_digest,
    ] {
        assert!(!captured_call.contains(component.as_str()));
        assert!(!mapped_payload_text.contains(component.as_str()));
    }
}

#[test]
fn raw_scope_outside_exact_scope_subtree_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let base = ready_call(&provider, ProviderOperation::Recall);

    for leaked_identity in [
        &base.exact_scope.repository_identity,
        &base.exact_scope.resolved_scope_digest,
    ] {
        let mut request = base.clone();
        let payload = format!("{{\"query\":\"find {leaked_identity}\"}}");
        request.payload = canonical_payload(ProviderOperation::Recall, payload.as_bytes());

        let reply = provider.invoke(&request);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
        assert_eq!(
            reply.terminal.diagnostic_id(),
            Some("ncm.request_contract_or_scope_projection_invalid")
        );
    }
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn public_scope_digest_and_ready_receipt_never_reach_surface_payload() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let base = ready_call(&provider, ProviderOperation::Recall);
    let public_scope_digest = base.exact_scope.exact_scope_sha256();

    for leaked_identity in [&public_scope_digest, &base.ready_receipt_sha256] {
        let mut request = base.clone();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "query": leaked_identity
        }))
        .expect("leak fixture");
        request.payload = canonical_payload(ProviderOperation::Recall, &bytes);

        let reply = provider.invoke(&request);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    }
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn surface_payload_identity_never_leaks_back_to_public_reply() {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_surface_payload_identity_leak(),
    );
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);

    let reply = provider.invoke(&request);

    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(reply.payload.is_none());
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn wrong_contract_and_non_object_payloads_never_reach_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let base = ready_call(&provider, ProviderOperation::Recall);

    let mut wrong_contract = base.clone();
    wrong_contract.payload = canonical_payload(ProviderOperation::Observe, b"{}");
    let wrong_contract_reply = provider.invoke(&wrong_contract);
    assert_eq!(
        wrong_contract_reply.terminal.terminal_code(),
        TerminalCode::InvalidRequest
    );

    let mut inconsistent_identity = base.clone();
    inconsistent_identity.payload = canonical_payload(
        ProviderOperation::Recall,
        b"{\"request_identity\":\"different-request\"}",
    );
    let inconsistent_reply = provider.invoke(&inconsistent_identity);
    assert_eq!(
        inconsistent_reply.terminal.terminal_code(),
        TerminalCode::InvalidRequest
    );

    for bytes in [b"not-json".as_slice(), b"[]".as_slice()] {
        let mut invalid_json_shape = base.clone();
        invalid_json_shape.payload = canonical_payload(ProviderOperation::Recall, bytes);
        let reply = provider.invoke(&invalid_json_shape);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    }
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn undeclared_optional_capability_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Maintenance);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::CapabilityUnsupported
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn undeclared_additional_required_capability_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.required_capabilities.insert(
        OwnedVersionedId::new(ProviderOperation::Maintenance.capability_id())
            .expect("maintenance capability"),
    );
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::CapabilityUnsupported
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn advertised_unknown_capability_never_satisfies_admission() {
    let surface = Arc::new(MockSurface::new(
        NCM_PROVIDER_ID,
        &["vendor.secret.v1"],
        false,
    ));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.required_capabilities.insert(
        OwnedVersionedId::new("vendor.secret.v1").expect("syntactically valid opaque capability"),
    );
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::CapabilityUnsupported
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn wrong_target_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = call("vendor.memory", ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn invoke_rejects_handshake_operation() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = call(NCM_PROVIDER_ID, ProviderOperation::Handshake);
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn cancelled_request_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    request.control.cancellation().cancel();
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Cancelled);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn cancellation_after_read_dispatch_prevents_success_publication() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_blocking_invoke(
            1,
            entered.clone(),
            release.clone(),
        ),
    );
    let provider = Arc::new(NcmProviderAdapter::new(surface.clone()).expect("adapter"));
    let request = ready_call(provider.as_ref(), ProviderOperation::Recall);
    let cancellation = request.control.cancellation();

    let invoke_provider = provider.clone();
    let invoke = std::thread::spawn(move || invoke_provider.invoke(&request));
    entered.wait();
    cancellation.cancel();
    release.wait();
    let reply = invoke.join().expect("invoke thread");

    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Cancelled);
    assert!(reply.payload.is_none());
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn negotiated_operation_budget_caps_handshake_and_invoke_surface_controls() {
    let mut bounded_limits = limits();
    bounded_limits.operation_millis = 100;
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_descriptor_limits(bounded_limits),
    );
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let mapped_handshake = surface
        .last_handshake
        .lock()
        .expect("handshake lock")
        .clone()
        .expect("mapped handshake");
    assert_eq!(mapped_handshake.control.remaining_millis(), 100);

    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    let mapped_call = surface
        .last_call
        .lock()
        .expect("call lock")
        .clone()
        .expect("mapped call");
    assert_eq!(mapped_call.control.remaining_millis(), 100);
    let live = mapped_call.control.snapshot().expect("live capped control");
    assert!((1..=100).contains(&live.remaining_millis));
}

#[test]
fn negotiated_concurrency_limit_is_nonblocking_and_raii_released() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let mut bounded_limits = limits();
    bounded_limits.concurrent_operations = 1;
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_descriptor_limits(bounded_limits)
            .with_blocking_invoke(1, entered.clone(), release.clone()),
    );
    let provider = Arc::new(NcmProviderAdapter::new(surface.clone()).expect("adapter"));
    let request = ready_call(provider.as_ref(), ProviderOperation::Recall);
    let first_request = request.clone();
    let first_provider = provider.clone();
    let first = std::thread::spawn(move || first_provider.invoke(&first_request));
    entered.wait();

    let rejected = provider.invoke(&request);
    assert_eq!(
        rejected.terminal.terminal_code(),
        TerminalCode::CapacityExceeded
    );
    assert_eq!(
        rejected.terminal.diagnostic_id(),
        Some("ncm.concurrent_operation_limit")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);

    release.wait();
    let first_reply = first.join().expect("first invoke thread");
    assert_eq!(first_reply.terminal.terminal_code(), TerminalCode::Success);
    let after_release = provider.invoke(&request);
    assert_eq!(
        after_release.terminal.terminal_code(),
        TerminalCode::Success
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn malformed_read_reply_becomes_contract_violation() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], true));
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(
        reply.terminal.committed_effect().state(),
        CommittedEffectState::None
    );
    assert!(reply.payload.is_none());
}

#[test]
fn surface_terminal_using_public_operation_id_is_rejected() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_public_reply_operation_id());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(reply.terminal.operation_id(), request.operation_id);
    assert!(reply.payload.is_none());
}

#[test]
fn malformed_mutating_reply_reports_unknown_effect() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], true));
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_post_dispatch_mutation_failure(&reply, &request);
}

#[test]
fn malformed_handshake_challenge_is_rejected() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_malformed_handshake_proof());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(response.ready_receipt_sha256.is_none());
}

#[test]
fn projected_surface_handshake_accepts_exact_limit_and_rejects_one_byte_over() {
    let template = handshake(NCM_PROVIDER_ID);
    let encoded_bytes = canonical_surface_handshake_request_size(&template);
    assert!(encoded_bytes > 1);

    let exact_surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let exact_provider = NcmProviderAdapter::new(exact_surface.clone()).expect("adapter");
    let mut exact_request = template.clone();
    exact_request.host_limits.request_bytes = encoded_bytes;
    let exact_response = exact_provider.handshake(&exact_request);
    assert_eq!(
        exact_response.terminal.terminal_code(),
        TerminalCode::Success
    );
    assert_eq!(exact_surface.handshake_calls.load(Ordering::Relaxed), 1);

    let rejected_surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let rejected_provider = NcmProviderAdapter::new(rejected_surface.clone()).expect("adapter");
    let mut oversized_request = template;
    oversized_request.host_limits.request_bytes = encoded_bytes - 1;
    let rejected = rejected_provider.handshake(&oversized_request);
    assert_eq!(
        rejected.terminal.terminal_code(),
        TerminalCode::InvalidRequest
    );
    assert_eq!(
        rejected.terminal.diagnostic_id(),
        Some("ncm.projected_handshake_request_limit_exceeded")
    );
    assert_eq!(rejected_surface.handshake_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn oversized_handshake_response_is_rejected_without_installing_readiness() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_handshake_warning_size(9_000));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");

    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));

    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(
        response.terminal.diagnostic_id(),
        Some("ncm.surface_handshake_response_limit_exceeded")
    );
    assert!(response.ready_receipt_sha256.is_none());
    let reply = provider.invoke(&call(NCM_PROVIDER_ID, ProviderOperation::Recall));
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ProviderUnavailable
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn structured_terminal_api_prevents_a_read_reply_from_claiming_a_committed_effect() {
    let request = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    let effect = CommittedEffectEvidence::committed(
        request.expected_state_generation,
        request.expected_state_generation.saturating_add(1),
        vec!["ncm.item-committed".to_owned()],
        ONE_SHA,
        ONE_SHA,
    )
    .expect("committed effect");
    assert!(
        TerminalRecord::new(
            request.operation,
            request.provider_id.clone(),
            TerminalCode::Success,
            effect,
            FallbackDirective::forbidden(),
            request.operation_id.clone(),
            request.exact_scope.exact_scope_sha256(),
            None,
        )
        .is_err()
    );
}

#[test]
fn surface_duplicate_acknowledgement_is_rebound_to_the_hosts_own_idempotency_key() {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_reply_effect(CommittedEffectState::Duplicate),
    );
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    let effect = reply.terminal.committed_effect();

    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(effect.state(), CommittedEffectState::Duplicate);
    // The surface only ever saw the namespace-opaque key; the host-visible
    // envelope must name the caller's own key so the journal can match it.
    assert_eq!(
        effect.duplicate_of_idempotency_key(),
        request.idempotency_key.as_deref()
    );
    assert_eq!(
        effect.duplicate_of_operation_id(),
        Some("ncm.surface.operation-original.v1")
    );
    // A duplicate commits nothing, so the generation must not move.
    assert_eq!(
        effect.state_generation_before(),
        Some(request.expected_state_generation)
    );
    assert_eq!(
        effect.state_generation_after(),
        Some(request.expected_state_generation)
    );
}

#[test]
fn malformed_unknown_effect_reply_is_replaced_by_a_dispatch_witness() {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_public_reply_operation_id()
            .with_reply_code(TerminalCode::EffectUnknown)
            .with_reply_effect(CommittedEffectState::Unknown),
    );
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_post_dispatch_mutation_failure(&reply, &request);
}

#[test]
fn malformed_mutation_extension_is_replaced_by_a_dispatch_witness() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_injected_extension());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_post_dispatch_mutation_failure(&reply, &request);
}

#[test]
fn terminal_diagnostic_cannot_leak_public_scope_or_opaque_aliases() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_leaking_terminal_diagnostic());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_surface_alias_leak_is_rejected(surface.as_ref(), &reply, &request);
}

#[test]
fn committed_effect_metadata_cannot_leak_public_scope_or_opaque_aliases() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_leaking_effect_metadata());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_surface_alias_leak_is_rejected(surface.as_ref(), &reply, &request);
}

#[test]
fn provider_receipt_cannot_leak_public_scope_or_opaque_aliases() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_leaking_provider_receipt());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_surface_alias_leak_is_rejected(surface.as_ref(), &reply, &request);
}

#[test]
fn verification_digest_cannot_leak_public_scope_or_opaque_aliases() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_leaking_verification());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_surface_alias_leak_is_rejected(surface.as_ref(), &reply, &request);
}

#[test]
fn warnings_cannot_leak_public_scope_or_opaque_aliases() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_leaking_warnings());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Observe);
    let reply = provider.invoke(&request);
    assert_surface_alias_leak_is_rejected(surface.as_ref(), &reply, &request);
}

#[test]
fn corrupt_payload_digest_is_rejected() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_corrupt_payload_digest());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(reply.payload.is_none());
}

#[test]
fn warning_overflow_is_rejected() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_warning_count(33));
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(reply.warnings.is_empty());
}

#[test]
fn projected_surface_request_accepts_exact_limit_and_rejects_one_byte_over() {
    // The projection replaces every caller identity with a fixed-width opaque
    // digest, so a mutating call with minimal public identities is the shape
    // whose projected encoding is strictly larger than its public encoding.
    // That is what lets the projected limit, not the public one, decide.
    // The identities stay short but use a letter that occurs in no hex digest
    // and no reply vocabulary, so the alias-leak scan cannot match them by
    // accident inside unrelated text.
    let mut template = call(NCM_PROVIDER_ID, ProviderOperation::Observe);
    template.request_id = "q1".to_owned();
    template.operation_id = "q2".to_owned();
    template.idempotency_key = Some("q3".to_owned());
    let public_bytes = canonical_request_size(&template);
    let encoded_bytes = canonical_surface_request_size(&template);
    assert!(
        encoded_bytes > public_bytes,
        "projected {encoded_bytes} must exceed public {public_bytes}"
    );
    assert!(encoded_bytes > 1);

    let mut exact_limits = limits();
    exact_limits.request_bytes = encoded_bytes;
    let exact_surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_descriptor_limits(exact_limits),
    );
    let exact_provider = NcmProviderAdapter::new(exact_surface.clone()).expect("adapter");
    let mut exact_handshake = handshake(NCM_PROVIDER_ID);
    exact_handshake.host_limits = exact_limits;
    let exact_receipt = establish_readiness(&exact_provider, &exact_handshake);
    let mut exact_call = template.clone();
    exact_call.ready_receipt_sha256 = exact_receipt;
    let exact_reply = exact_provider.invoke(&exact_call);
    assert_eq!(
        exact_reply.terminal.terminal_code(),
        TerminalCode::Success,
        "exact-limit call refused: {:?}",
        exact_reply.terminal.diagnostic_id()
    );
    assert_eq!(exact_surface.invoke_calls.load(Ordering::Relaxed), 1);

    let mut one_byte_too_small = exact_limits;
    one_byte_too_small.request_bytes = encoded_bytes - 1;
    let rejected_surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_descriptor_limits(one_byte_too_small),
    );
    let rejected_provider = NcmProviderAdapter::new(rejected_surface.clone()).expect("adapter");
    let mut rejected_handshake = handshake(NCM_PROVIDER_ID);
    rejected_handshake.host_limits = one_byte_too_small;
    let rejected_receipt = establish_readiness(&rejected_provider, &rejected_handshake);
    let mut oversized_call = template;
    oversized_call.ready_receipt_sha256 = rejected_receipt;
    let rejected = rejected_provider.invoke(&oversized_call);
    assert_eq!(
        rejected.terminal.terminal_code(),
        TerminalCode::InvalidRequest
    );
    assert_eq!(
        rejected.terminal.diagnostic_id(),
        Some("ncm.projected_request_limit_exceeded")
    );
    assert_eq!(rejected_surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn canonical_response_envelope_accepts_exact_limit_and_rejects_one_byte_over() {
    let mut template = call(NCM_PROVIDER_ID, ProviderOperation::Observe);
    let large_extension_payload = vec![b'x'; 2_048];
    template
        .extensions
        .push(opaque_extension(&large_extension_payload));
    // The hygiene receipt binds the extension set, so the admitted call is the
    // one that carries this extension.
    let template = admitted(template);
    let state_generation_after = template.expected_state_generation.saturating_add(1);
    let expected_reply = ProviderReply {
        terminal: TerminalRecord::new(
            template.operation,
            template.provider_id.clone(),
            TerminalCode::Success,
            CommittedEffectEvidence::committed(
                template.expected_state_generation,
                state_generation_after,
                vec!["ncm.item-committed".to_owned()],
                PROVIDER_RECEIPT_SHA,
                VERIFICATION_SHA,
            )
            .expect("expected committed effect"),
            FallbackDirective::forbidden(),
            template.operation_id.clone(),
            template.exact_scope.exact_scope_sha256(),
            None,
        )
        .expect("expected terminal"),
        payload: Some(template.payload.clone()),
        warnings: vec!["warning".to_owned()],
        extensions: Vec::new(),
        state_generation: state_generation_after,
    };
    let encoded_bytes = canonical_response_size(&template, &expected_reply);
    assert!(encoded_bytes > 1);

    let mut exact_limits = limits();
    exact_limits.response_bytes = encoded_bytes;
    let exact_surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_descriptor_limits(exact_limits)
            .with_warning_count(1),
    );
    let exact_provider = NcmProviderAdapter::new(exact_surface.clone()).expect("adapter");
    let mut exact_handshake = handshake(NCM_PROVIDER_ID);
    exact_handshake.host_limits = exact_limits;
    let exact_receipt = establish_readiness(&exact_provider, &exact_handshake);
    let mut exact_call = template.clone();
    exact_call.ready_receipt_sha256 = exact_receipt;
    let exact_reply = exact_provider.invoke(&exact_call);
    assert_eq!(exact_reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(
        exact_reply.terminal.committed_effect().state(),
        CommittedEffectState::Committed
    );
    assert_eq!(
        exact_reply
            .terminal
            .committed_effect()
            .state_generation_after(),
        Some(state_generation_after)
    );
    assert_eq!(exact_surface.invoke_calls.load(Ordering::Relaxed), 1);

    let mut one_byte_too_small = exact_limits;
    one_byte_too_small.response_bytes = encoded_bytes - 1;
    let rejected_surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false)
            .with_descriptor_limits(one_byte_too_small)
            .with_warning_count(1),
    );
    let rejected_provider = NcmProviderAdapter::new(rejected_surface.clone()).expect("adapter");
    let mut rejected_handshake = handshake(NCM_PROVIDER_ID);
    rejected_handshake.host_limits = one_byte_too_small;
    let rejected_receipt = establish_readiness(&rejected_provider, &rejected_handshake);
    let mut oversized_reply_call = template;
    oversized_reply_call.ready_receipt_sha256 = rejected_receipt;
    let rejected = rejected_provider.invoke(&oversized_reply_call);
    assert_post_dispatch_mutation_failure(&rejected, &oversized_reply_call);
    assert_eq!(rejected_surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn negotiated_host_response_limit_rejects_oversized_surface_payload() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_large_response_payload());
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut handshake_request = handshake(NCM_PROVIDER_ID);
    handshake_request.host_limits.response_bytes = 4_096;
    let receipt = establish_readiness(&provider, &handshake_request);
    let mut request = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    request.ready_receipt_sha256 = receipt;
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(reply.payload.is_none());
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn response_limit_counts_payload_extensions_and_warning_bytes_together() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_warning_count(1));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut handshake_request = handshake(NCM_PROVIDER_ID);
    handshake_request.host_limits.response_bytes = 2_048;
    let receipt = establish_readiness(&provider, &handshake_request);
    let mut request = call(NCM_PROVIDER_ID, ProviderOperation::Recall);
    request.ready_receipt_sha256 = receipt;
    let extension_payload = vec![b'x'; 2_048];
    request
        .extensions
        .push(opaque_extension(&extension_payload));
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(reply.payload.is_none());
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn state_generation_cannot_move_backward() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_reply_state_generation(3));
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(reply.state_generation, 4);
}

#[test]
fn malformed_read_reply_cannot_publish_untrusted_state_generation() {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &[], false).with_reply_state_generation(u64::MAX),
    );
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let request = ready_call(&provider, ProviderOperation::Recall);

    let reply = provider.invoke(&request);

    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert_eq!(reply.state_generation, request.expected_state_generation);
}

#[test]
fn optional_extensions_round_trip_exactly() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    let extension = optional_extension();
    request.extensions.push(extension.clone());
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(reply.extensions, vec![extension]);
    assert!(
        surface
            .last_call
            .lock()
            .expect("call lock")
            .as_ref()
            .expect("mapped call")
            .extensions
            .is_empty()
    );
}

#[test]
fn surface_returned_extension_is_a_contract_violation() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_injected_extension());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Recall);
    request.extensions.push(optional_extension());
    let reply = provider.invoke(&request);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
}

#[test]
fn unknown_required_extension_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Observe);
    request.extensions.push(
        OwnedOpaqueExtension::new(
            OwnedVersionedId::new("vendor.required.v1").expect("extension id"),
            1,
            true,
            EMPTY_OBJECT_SHA,
            b"{}".to_vec(),
        )
        .expect("extension"),
    );
    // Admit the extension set so the rejection proves the adapter refuses a
    // required extension, not that the hygiene receipt failed to bind it.
    let request = admitted(request);
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.request_payload_or_extension_invalid")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn corrupt_request_payload_never_reaches_surface() {
    let surface = Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, ProviderOperation::Observe);
    request.payload.sha256 = ZERO_SHA.to_owned();
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn observation_total_extension_cap_is_enforced_before_dispatch() {
    let mut high_limits = limits();
    high_limits.request_bytes = 1_000_000;
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_descriptor_limits(high_limits));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut handshake_request = handshake(NCM_PROVIDER_ID);
    handshake_request.host_limits = high_limits;
    let receipt = establish_readiness(&provider, &handshake_request);
    let mut request = call(NCM_PROVIDER_ID, ProviderOperation::Observe);
    request.ready_receipt_sha256 = receipt;
    for index in 0..3 {
        request.extensions.push(
            OwnedOpaqueExtension::new(
                OwnedVersionedId::new(format!("vendor.large{index}.v1")).expect("extension id"),
                1,
                false,
                LARGE_EXTENSION_SHA,
                vec![b'x'; 200_000],
            )
            .expect("extension"),
        );
    }
    let reply = provider.invoke(&request);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn handshake_surface_contract_mismatch_is_fail_closed() {
    let surface =
        Arc::new(MockSurface::new(NCM_PROVIDER_ID, &[], false).with_malformed_handshake_scope());
    let provider = NcmProviderAdapter::new(surface).expect("adapter");
    let response = provider.handshake(&handshake(NCM_PROVIDER_ID));
    assert_eq!(
        response.terminal.terminal_code(),
        TerminalCode::ContractViolation
    );
    assert!(response.descriptor.is_none());
    assert!(response.accepted_scope.is_none());
}

/// A syntactically empty JSON object padded with interior whitespace to the
/// requested size, so a payload can cross a byte limit without changing shape.
fn padded_object(padding: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(padding + 2);
    bytes.push(b'{');
    bytes.resize(padding + 1, b' ');
    bytes.push(b'}');
    bytes
}

#[test]
fn snapshot_restore_request_is_measured_against_snapshot_bytes() {
    // SnapshotRestore uses `snapshot_bytes` before checking restore authority.
    // This empty object must reach the authority refusal without dispatching.
    // Every other request keeps `request_bytes`, and a snapshot above
    // `snapshot_bytes` still fails at the byte gate.
    let surface = Arc::new(MockSurface::new(
        NCM_PROVIDER_ID,
        &["snapshot.restore.v1"],
        false,
    ));
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let negotiated = limits();
    let between = padded_object(20_000);
    assert!(u64::try_from(between.len()).expect("len") > negotiated.request_bytes);
    assert!(u64::try_from(between.len()).expect("len") < negotiated.snapshot_bytes);

    let mut restore = ready_call(&provider, ProviderOperation::SnapshotRestore);
    restore.payload = canonical_payload(ProviderOperation::SnapshotRestore, &between);
    let reply = provider.invoke(&restore);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::ProviderUnavailable,
        "restore within snapshot_bytes must pass byte validation: {reply:?}"
    );
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.current_advisory_admission_refused")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);

    let mut observe = ready_call(&provider, ProviderOperation::Observe);
    observe.payload = canonical_payload(ProviderOperation::Observe, &between);
    let observe = admitted(observe);
    let reply = provider.invoke(&observe);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.request_payload_or_extension_invalid")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);

    let above = padded_object(70_000);
    assert!(u64::try_from(above.len()).expect("len") > negotiated.snapshot_bytes);
    let mut oversized = ready_call(&provider, ProviderOperation::SnapshotRestore);
    oversized.payload = canonical_payload(ProviderOperation::SnapshotRestore, &above);
    let reply = provider.invoke(&oversized);
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
    assert_eq!(
        reply.terminal.diagnostic_id(),
        Some("ncm.request_payload_or_extension_invalid")
    );
    assert_eq!(surface.invoke_calls.load(Ordering::Relaxed), 0);
}

fn canonical_message_payload(content: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "observation_kind": "session.message_committed.v1",
        "payload_contract": "tracedecay.memory.observation.session-message.v1",
        "canonical_payload": {
            "version": 1,
            "provider": "claude",
            "native_record_kind": "message",
            "stable_record_id": "project-a:private-record",
            "relations": {"session_id": "canonical-host-session", "project_id": "project-a"},
            "facts": [{"kind": "message", "role": "assistant", "content": content,
                "model": "private-model", "request_id": "private-request"}]
        }
    })
}

fn invoke_projected_payload(
    operation: ProviderOperation,
    payload: &serde_json::Value,
) -> (ProviderReply, Option<NcmSurfaceCall>) {
    let surface = Arc::new(
        MockSurface::new(NCM_PROVIDER_ID, &["deletion.by_source.v1"], false)
            .with_safe_response_payload(),
    );
    let provider = NcmProviderAdapter::new(surface.clone()).expect("adapter");
    let mut request = ready_call(&provider, operation);
    request.payload = canonical_payload(operation, &serde_json::to_vec(payload).expect("JSON"));
    let reply = provider.invoke(&admitted(request));
    let captured = surface.last_call.lock().expect("call lock").clone();
    (reply, captured)
}

#[test]
fn canonical_message_projects_text_and_strips_host_metadata() {
    for (content, expected) in [
        (serde_json::json!("safe message"), "safe message"),
        (
            serde_json::json!({"text": " safe message ", "ignored": "project-a"}),
            "safe message",
        ),
        (
            serde_json::json!(["first", {"type": "text", "text": "second"}]),
            "first\nsecond",
        ),
    ] {
        let (reply, captured) = invoke_projected_payload(
            ProviderOperation::Observe,
            &canonical_message_payload(content),
        );
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
        let captured = captured.expect("projected surface call");
        let payload: serde_json::Value =
            serde_json::from_slice(&captured.payload.bytes).expect("JSON");
        let projected = payload["canonical_payload"]
            .as_object()
            .expect("projection");
        assert_eq!(projected.len(), 3);
        assert_eq!(projected["role"], "assistant");
        assert_eq!(projected["content"], expected);
        assert_eq!(
            projected["forget_source_key"]
                .as_str()
                .expect("opaque source")
                .len(),
            64
        );
        let text = String::from_utf8(captured.payload.bytes).expect("UTF-8");
        for forbidden in [
            "canonical-host-session",
            "project-a",
            "private-record",
            "private-model",
            "private-request",
            "relations",
            "stable_record_id",
            "facts",
        ] {
            assert!(!text.contains(forbidden), "metadata leaked: {forbidden}");
        }
    }
}

#[test]
fn canonical_message_accepts_provider_native_record_labels() {
    for native_kind in ["message", "user", "assistant", "response_item", "event_msg"] {
        let mut payload =
            canonical_message_payload(serde_json::json!({"text": "visible normalized message"}));
        payload["canonical_payload"]["native_record_kind"] = serde_json::json!(native_kind);
        let (reply, captured) = invoke_projected_payload(ProviderOperation::Observe, &payload);
        assert_eq!(
            reply.terminal.terminal_code(),
            TerminalCode::Success,
            "native kind: {native_kind}"
        );
        let captured: serde_json::Value =
            serde_json::from_slice(&captured.expect("projected message").payload.bytes)
                .expect("JSON");
        assert_eq!(
            captured["canonical_payload"]["content"],
            "visible normalized message"
        );
    }
}

#[test]
fn canonical_message_refuses_malformed_shape_and_content_identity_leaks() {
    let original = canonical_message_payload(serde_json::json!("safe message"));
    let mut cases = Vec::new();
    for (field, replacement) in [
        ("version", serde_json::json!(2)),
        ("provider", serde_json::json!(null)),
        ("native_record_kind", serde_json::json!("")),
        ("native_record_kind", serde_json::json!(null)),
        ("stable_record_id", serde_json::json!("")),
        ("relations", serde_json::json!({"session_id": " "})),
        ("relations", serde_json::json!({})),
        ("relations", serde_json::json!({"session_id": 42})),
        ("facts", serde_json::json!([])),
        (
            "facts",
            serde_json::json!([{"kind": "message", "role": "assistant", "content": {"image": "opaque"}}]),
        ),
    ] {
        let mut payload = original.clone();
        payload["canonical_payload"][field] = replacement;
        cases.push(payload);
    }
    for content in [
        "actual project-a content",
        "actual request-a content",
        "actual session-a content",
        "actual operation-observation.accept.v1 content",
    ] {
        cases.push(canonical_message_payload(serde_json::json!(content)));
    }
    for payload in cases {
        let (reply, captured) = invoke_projected_payload(ProviderOperation::Observe, &payload);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::InvalidRequest);
        assert!(captured.is_none(), "refused payload never reaches surface");
    }
}

#[test]
fn observe_and_delete_source_aliases_share_one_restart_stable_opaque_key() {
    let session = "canonical-host-session";
    let raw_source = scope().session_forget_source_key(session);
    assert_eq!(
        raw_source,
        format!("session:{}:{session}", scope().exact_scope_sha256())
    );
    let (_, observed) = invoke_projected_payload(
        ProviderOperation::Observe,
        &canonical_message_payload(serde_json::json!("safe message")),
    );
    let observed: serde_json::Value =
        serde_json::from_slice(&observed.expect("observe").payload.bytes).expect("JSON");
    let expected = &observed["canonical_payload"]["forget_source_key"];
    // Each invocation constructs a fresh adapter: no process-local mapping is needed.
    for alias in ["source", "source_id", "forget_source_key"] {
        let payload = serde_json::json!({alias: raw_source});
        let (reply, deleted) =
            invoke_projected_payload(ProviderOperation::DeleteBySource, &payload);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
        let deleted: serde_json::Value =
            serde_json::from_slice(&deleted.expect("delete").payload.bytes).expect("JSON");
        assert_eq!(&deleted["source"], expected);
    }
    for source_identity in [
        serde_json::json!(raw_source),
        serde_json::json!({"forget_source_key": raw_source}),
        serde_json::json!({"source_event_sha256": raw_source}),
        serde_json::json!({"source_event_id": raw_source}),
    ] {
        let payload = serde_json::json!({
            "observation_kind": "tool.execution_settled.v1",
            "payload_contract": "tracedecay.memory.observation.tool-execution.v1",
            "source_identity": source_identity,
            "canonical_payload": {"command": "build", "outcome_summary": "passed"}
        });
        let (reply, captured) = invoke_projected_payload(ProviderOperation::Observe, &payload);
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
        let captured: serde_json::Value =
            serde_json::from_slice(&captured.expect("legacy observe").payload.bytes).expect("JSON");
        assert_eq!(
            &captured["canonical_payload"]["forget_source_key"],
            expected
        );
        assert!(captured.get("source_identity").is_none());
    }
}

#[test]
fn conflicting_or_malformed_source_aliases_fail_closed() {
    for payload in [
        serde_json::json!({"source": "first", "source_id": "second"}),
        serde_json::json!({"source": "first", "forget_source_key": 42}),
    ] {
        let (_, captured) = invoke_projected_payload(ProviderOperation::DeleteBySource, &payload);
        assert!(captured.is_none());
    }
    for source_identity in [
        serde_json::json!("different"),
        serde_json::json!({"source_event_id": "first", "source_event_sha256": "second"}),
    ] {
        let payload = serde_json::json!({"canonical_payload": {"forget_source_key": "first"},
            "source_identity": source_identity});
        let (_, captured) = invoke_projected_payload(ProviderOperation::Observe, &payload);
        assert!(captured.is_none());
    }
}

/// The runtime probes generation; the adapter supplies capability rows from its
/// actual accepted readiness. This surface never supplies capability rows.
struct CapabilityProbeSurface(MockSurface);

impl NcmCognitiveSurface for CapabilityProbeSurface {
    fn descriptor(&self) -> ProviderDescriptor {
        self.0.descriptor()
    }

    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        self.0.handshake(request)
    }

    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
        let projected: serde_json::Value =
            serde_json::from_slice(&call.payload.bytes).expect("projected capability request");
        assert_eq!(projected["common_control"]["view"], "capability_status");
        let mut reply = self.0.invoke(call);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "common_control": "inspection", "view": "capability_status",
            "state_generation": reply.state_generation
        }))
        .expect("generation probe");
        reply.payload = Some(canonical_payload(call.operation, &bytes));
        reply
    }
}

fn capability_inspection_call(
    ready: &str,
    cursor: serde_json::Value,
    maximum_items: u64,
    maximum_bytes: u64,
) -> ProviderCall {
    let mut request = call(NCM_PROVIDER_ID, ProviderOperation::Inspection);
    request.ready_receipt_sha256 = ready.to_owned();
    // Real returned extensions make reply framing significant while the
    // descriptor handshake remains much smaller than a single public page.
    request.extensions.push(opaque_extension(&vec![b'x'; 2048]));
    let exact = &request.exact_scope;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "common_request": {
            "provider_id": request.provider_id.as_str(),
            "registration_revision": request.registration_revision,
            "ready_receipt_digest": request.ready_receipt_sha256,
            "exact_scope_identity": {
                "profile_id": exact.profile_id, "project_id": exact.project_id,
                "repository_identity": exact.repository_identity, "worktree_identity": exact.worktree_identity,
                "branch_identity": exact.branch_identity, "agent_session_id": exact.agent_session_id,
                "resolved_scope_digest": exact.resolved_scope_digest
            },
            "operation_id": request.operation_id, "idempotency_key": null,
            "expected_state_generation": request.expected_state_generation,
            "request_identity": request.request_id, "policy_revision": 1,
            "deadline": {"deadline_utc_micros": i64::MAX, "remaining_millis": 500},
            "cancellation": "live", "extensions": []
        },
        "view": "capability_status", "selector": {}, "maximum_items": maximum_items,
        "maximum_bytes": maximum_bytes, "redaction_policy_revision": 1, "cursor": cursor
    }))
    .expect("common capability request");
    request.payload = canonical_payload(request.operation, &bytes);
    request
}

#[test]
fn capability_pages_obey_negotiated_reply_framing_and_item_limits_without_stalled_cursors() {
    use serde_json::{Value, json};

    let provider_for = |host_limits: ProviderLimits| {
        let surface = Arc::new(CapabilityProbeSurface(MockSurface::new(
            NCM_PROVIDER_ID,
            &[
                ProviderOperation::Inspection.capability_id(),
                ProviderOperation::Feedback.capability_id(),
                ProviderOperation::Correction.capability_id(),
                ProviderOperation::Maintenance.capability_id(),
            ],
            false,
        )));
        let provider = NcmProviderAdapter::new(surface).expect("capability adapter");
        let mut request = handshake(NCM_PROVIDER_ID);
        request.host_limits = host_limits;
        let response = provider.handshake(&request);
        assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(response.effective_limits, Some(host_limits));
        let ready = response.ready_receipt_sha256.expect("accepted readiness");
        (provider, ready)
    };
    let decode = |reply: &ProviderReply| -> Value {
        assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
        serde_json::from_slice(&reply.payload.as_ref().expect("capability page").bytes)
            .expect("capability page JSON")
    };
    let (baseline, ready) = provider_for(limits());
    let expected: Vec<Value> = baseline
        .descriptor()
        .capabilities
        .iter()
        .map(|capability| json!({"capability_id": capability.as_str(), "state": "available"}))
        .collect();
    assert!(expected.len() >= 7);
    let first_call = capability_inspection_call(&ready, Value::Null, 1, 65536);
    let first_reply = baseline.invoke(&first_call);
    let first = decode(&first_reply);
    let second_call = capability_inspection_call(&ready, first["next_cursor"].clone(), 1, 65536);
    let second_reply = baseline.invoke(&second_call);
    let second = decode(&second_reply);
    assert_eq!(first["items"], json!([expected[0]]));
    assert_eq!(second["items"], json!([expected[1]]));
    let first_size = canonical_response_size(&first_call, &first_reply);
    let second_size = canonical_response_size(&second_call, &second_reply);
    let boundary = first_size.max(second_size);
    assert!(
        (first_reply
            .payload
            .as_ref()
            .expect("first payload")
            .bytes
            .len() as u64)
            < boundary
    );
    first_reply
        .validate(boundary)
        .expect("actual first reply fits");
    second_reply
        .validate(boundary)
        .expect("actual second reply fits");

    let mut byte_limits = limits();
    byte_limits.response_bytes = boundary;
    let (bounded, bounded_ready) = provider_for(byte_limits);
    let bounded_first_call = capability_inspection_call(&bounded_ready, Value::Null, 64, 65536);
    let bounded_first_reply = bounded.invoke(&bounded_first_call);
    bounded_first_reply
        .validate(boundary)
        .expect("negotiated first reply framing");
    let bounded_first = decode(&bounded_first_reply);
    assert_eq!(bounded_first["items"], first["items"]);
    assert_eq!(bounded_first["coverage"], "partial");
    assert_eq!(
        bounded_first_reply.extensions,
        bounded_first_call.extensions
    );
    let bounded_second_call = capability_inspection_call(
        &bounded_ready,
        bounded_first["next_cursor"].clone(),
        64,
        65536,
    );
    let bounded_second_reply = bounded.invoke(&bounded_second_call);
    bounded_second_reply
        .validate(boundary)
        .expect("negotiated second reply framing");
    let bounded_second = decode(&bounded_second_reply);
    assert_eq!(bounded_second["items"], second["items"]);
    assert_ne!(bounded_second["next_cursor"], bounded_first["next_cursor"]);
    assert!(canonical_response_size(&bounded_first_call, &bounded_first_reply) <= boundary);
    assert!(canonical_response_size(&bounded_second_call, &bounded_second_reply) <= boundary);

    let first_payload_bytes = first_reply
        .payload
        .as_ref()
        .expect("first payload")
        .bytes
        .len() as u64;
    let payload_bounded = baseline.invoke(&capability_inspection_call(
        &ready,
        Value::Null,
        64,
        first_payload_bytes,
    ));
    assert_eq!(decode(&payload_bounded)["items"], first["items"]);
    assert!(
        payload_bounded
            .payload
            .as_ref()
            .expect("bounded payload")
            .bytes
            .len() as u64
            <= first_payload_bytes
    );
    let no_payload_room = baseline.invoke(&capability_inspection_call(&ready, Value::Null, 64, 1));
    assert_eq!(
        no_payload_room.terminal.terminal_code(),
        TerminalCode::CapacityExceeded
    );
    assert!(no_payload_room.payload.is_none());

    let mut item_limits = limits();
    item_limits.inspection_items = 1;
    let (item_bounded, item_ready) = provider_for(item_limits);
    let item_first = decode(&item_bounded.invoke(&capability_inspection_call(
        &item_ready,
        Value::Null,
        64,
        65536,
    )));
    let item_second = decode(&item_bounded.invoke(&capability_inspection_call(
        &item_ready,
        item_first["next_cursor"].clone(),
        64,
        65536,
    )));
    assert_eq!(item_first["items"], first["items"]);
    assert_eq!(item_second["items"], second["items"]);

    let mut insufficient_limits = limits();
    insufficient_limits.response_bytes = first_size - 1;
    let (insufficient, insufficient_ready) = provider_for(insufficient_limits);
    let refused = insufficient.invoke(&capability_inspection_call(
        &insufficient_ready,
        Value::Null,
        64,
        65536,
    ));
    assert_eq!(
        refused.terminal.terminal_code(),
        TerminalCode::CapacityExceeded
    );
    assert_eq!(
        refused.terminal.committed_effect().state(),
        CommittedEffectState::None
    );
    assert!(refused.payload.is_none());
    refused
        .validate(insufficient_limits.response_bytes)
        .expect("bounded capacity reply");
}
