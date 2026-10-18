#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(warnings)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
//! Topology-neutral TraceDecay adapter boundary for licensed NCM memory.
//!
//! This crate does not implement NCM, select an in-process or local-process
//! topology, open NCM state, or modify licensed behavior. It translates the
//! provider-neutral runtime contract into an opaque NCM surface contract. Raw
//! coding and caller identities never cross that surface: TraceDecay derives
//! one stable namespace digest from the exact admitted scope, projects payloads
//! conservatively, and retains responsibility for reattaching public identity
//! and inert extensions to validated responses.

#[cfg(feature = "rust-backend")]
pub mod rust_backend;
#[cfg(feature = "rust-backend")]
pub use rust_backend::{
    RustNcmConfig, RustNcmError, RustNcmSurface, RustNcmWorkerOwner, StateRoot, WorkerOptions,
};

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tracedecay_memory_provider_api::contract::{
    CAPABILITIES, CommittedEffectState, FallbackEligibility, RequestControl, TerminalCode,
};
use tracedecay_memory_provider_api::{
    AdvisoryAdmissionAuthority, AdvisoryAdmissionError, CanonicalPayload, CommittedEffectEvidence,
    CurrentAdvisoryAdmission, FallbackDirective, HandshakeRequest, HandshakeResponse,
    MemoryProvider, OperationControl, OwnedExactScope, OwnedOpaqueExtension, OwnedProviderId,
    OwnedVersionedId, ProviderCall, ProviderDescriptor, ProviderLimits, ProviderOperation,
    ProviderReply, TerminalRecord,
};

mod common;

/// Stable logical provider identity reserved for NCM.
pub const NCM_PROVIDER_ID: &str = "ncm";

/// Recall candidate scope bindings the host authorizes NCM to attest, in the
/// wire vocabulary of `tracedecay.memory.provider.recall.v1`
/// `candidate_scope_binding.bindings`. NCM memories are staged observations
/// of one checkout, shared by every session of it, so every candidate the
/// adapter re-asserts carries `scope_binding: "checkout_observations"`; the
/// registry records this declaration at registration and passes it to
/// admission with the admitted call, never from a reply.
pub const NCM_RECALL_SCOPE_BINDINGS: &[&str] = &["checkout_observations"];
const NAMESPACE_DOMAIN: &[u8] = b"tracedecay.ncm.checkout.v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"tracedecay.ncm.handshake-proof.v1\0";
const CHALLENGE_DOMAIN_V2: &[u8] = b"tracedecay.ncm.handshake-proof.v2\0";
const OPAQUE_ID_DOMAIN: &[u8] = b"tracedecay.ncm.opaque-id.v1\0";
const READY_RECEIPT_DOMAIN: &[u8] = b"tracedecay.ncm.adapter-ready-receipt.v1\0";
const READY_RECEIPT_DOMAIN_V2: &[u8] = b"tracedecay.ncm.adapter-ready-receipt.v2\0";
const UNKNOWN_EFFECT_RECEIPT_DOMAIN: &[u8] = b"tracedecay.ncm.adapter-unknown-effect-receipt.v1\0";
/// Adapter-owned reconciliation procedure for a surface dispatch whose
/// returned envelope cannot be trusted; the suffix binds the witness receipt.
const RECONCILE_SURFACE_DISPATCH_ACTION: &str = "ncm.adapter.reconcile-surface-dispatch.v1";
const MAX_WARNINGS: usize = 32;
const MAX_OBSERVATION_TOTAL_EXTENSION_BYTES: u64 = 524_288;
const SURFACE_IDENTITY_REFRESH_DIAGNOSTIC: &str = "ncm.rust.handshake_identity_refresh_required";

/// Construction failure before an NCM surface can be registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NcmAdapterError {
    /// The supplied surface did not expose the reserved NCM provider identity.
    ProviderIdMismatch {
        /// Required stable identity.
        expected: &'static str,
        /// Identity declared by the supplied surface.
        declared: String,
    },
}

impl fmt::Display for NcmAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderIdMismatch { expected, declared } => write!(
                formatter,
                "NCM surface declared provider {declared}, expected {expected}"
            ),
        }
    }
}

impl Error for NcmAdapterError {}

/// Opaque provider-local namespace derived from the checkout a TraceDecay
/// coding scope names.
///
/// NCM keeps one memory per checkout: every agent session of the same
/// profile, project, repository, worktree and branch shares it, so a later
/// session recalls what an earlier one observed from NCM's own state. The
/// agent-session binding and the resolved-scope digest stay on each delivery
/// and are checked at recall; they never partition the memory.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NcmNamespace(String);

impl NcmNamespace {
    /// Derives a stable namespace without exposing raw profile, project,
    /// repository, worktree, or branch identifiers to NCM.
    #[must_use]
    pub fn from_exact_scope(scope: &OwnedExactScope) -> Self {
        let mut digest = Sha256::new();
        digest.update(NAMESPACE_DOMAIN);
        for value in [
            scope.profile_id.as_bytes(),
            scope.project_id.as_bytes(),
            scope.repository_identity.as_bytes(),
            scope.worktree_identity.as_bytes(),
            scope.branch_identity.as_bytes(),
        ] {
            digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(value);
        }
        Self(hex_digest(&digest.finalize()))
    }

    /// Returns the lowercase SHA-256 namespace digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

struct OpaqueCallerIds {
    request_id: String,
    operation_id: String,
    idempotency_key: Option<String>,
}

impl OpaqueCallerIds {
    fn from_call(namespace: &NcmNamespace, call: &ProviderCall) -> Self {
        Self {
            request_id: opaque_surface_id(namespace, b"request-id", &call.request_id),
            operation_id: opaque_surface_id(namespace, b"operation-id", &call.operation_id),
            idempotency_key: call
                .idempotency_key
                .as_deref()
                .map(|value| opaque_surface_id(namespace, b"idempotency-key", value)),
        }
    }
}

/// Handshake request visible to the licensed NCM surface.
#[derive(Clone, Debug)]
pub struct NcmSurfaceHandshakeRequest {
    /// Accepted TraceDecay registration revision.
    pub registration_revision: u64,
    /// Opaque provider-local state namespace.
    pub namespace: NcmNamespace,
    /// Namespace-bound opaque request identity.
    pub request_id: String,
    /// Required provider-neutral capabilities.
    pub required_capabilities: BTreeSet<OwnedVersionedId>,
    /// Finite host ceilings.
    pub host_limits: ProviderLimits,
    /// Deadline and live cancellation.
    pub control: OperationControl,
    /// Challenge nonce for this handshake.
    pub challenge_nonce: [u8; 32],
}

impl NcmSurfaceHandshakeRequest {
    /// Derives the proof the surface must return to bind readiness to this
    /// challenge, namespace, implementation, and receipt.
    #[must_use]
    pub fn expected_challenge_response_sha256(
        &self,
        descriptor: &ProviderDescriptor,
        provider_instance_id: &str,
        ready_receipt_sha256: &str,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(
            if descriptor
                .state_schema_version
                .starts_with("ncm-biomem-rs.v2+")
            {
                CHALLENGE_DOMAIN_V2
            } else {
                CHALLENGE_DOMAIN
            },
        );
        digest_field(&mut digest, self.namespace.as_str().as_bytes());
        digest_field(&mut digest, self.request_id.as_bytes());
        digest.update(self.registration_revision.to_be_bytes());
        digest.update(self.challenge_nonce);
        digest.update(self.control.deadline_utc_micros().to_be_bytes());
        digest.update(self.control.remaining_millis().to_be_bytes());
        // Handshake reaches the surface only after a live preflight snapshot.
        digest.update([0]);
        digest.update(
            u64::try_from(self.required_capabilities.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for capability in &self.required_capabilities {
            digest_field(&mut digest, capability.as_str().as_bytes());
        }
        digest_limits(&mut digest, self.host_limits);
        digest_field(&mut digest, descriptor.provider_id.as_str().as_bytes());
        digest_field(&mut digest, provider_instance_id.as_bytes());
        digest_descriptor_details(&mut digest, descriptor);
        digest_limits(&mut digest, self.host_limits.minimum(descriptor.limits));
        digest_field(&mut digest, ready_receipt_sha256.as_bytes());
        hex_digest(&digest.finalize())
    }
}

/// Handshake response returned by the licensed NCM surface without raw coding
/// scope.
#[derive(Clone, Debug)]
pub struct NcmSurfaceHandshakeResponse {
    /// Typed provider terminal.
    pub terminal: TerminalRecord,
    /// Real NCM descriptor when ready.
    pub descriptor: Option<ProviderDescriptor>,
    /// Opaque runtime instance identity.
    pub provider_instance_id: Option<String>,
    /// Accepted opaque namespace.
    pub namespace: Option<NcmNamespace>,
    /// Effective finite limits.
    pub effective_limits: Option<ProviderLimits>,
    /// Scoped readiness receipt digest.
    pub ready_receipt_sha256: Option<String>,
    /// Proof bound to the request challenge and accepted ready identity.
    pub challenge_response_sha256: Option<String>,
    /// Bounded non-secret warnings.
    pub warnings: Vec<String>,
}

/// Provider operation visible to the licensed NCM surface.
#[derive(Clone, Debug)]
pub struct NcmSurfaceCall {
    /// Provider-neutral operation identity.
    pub operation: ProviderOperation,
    /// Opaque provider-local namespace.
    pub namespace: NcmNamespace,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Compatible readiness receipt digest.
    pub ready_receipt_sha256: String,
    /// Namespace-bound opaque request identity.
    pub request_id: String,
    /// Namespace-bound opaque effect identity.
    pub operation_id: String,
    /// Provider state generation expected by the caller.
    pub expected_state_generation: u64,
    /// Namespace-bound opaque deterministic key for mutating operations.
    pub idempotency_key: Option<String>,
    /// Deadline and live cancellation.
    pub control: OperationControl,
    /// Scope-safe JSON projection of the canonical provider-neutral payload.
    pub payload: CanonicalPayload,
    /// Required capabilities for this call.
    pub required_capabilities: BTreeSet<OwnedVersionedId>,
    /// Extensions visible to the surface. The adapter always leaves this empty
    /// because opaque extensions remain adapter-side.
    pub extensions: Vec<OwnedOpaqueExtension>,
}

impl NcmSurfaceCall {
    fn from_provider_call(
        call: &ProviderCall,
        payload: CanonicalPayload,
        control: OperationControl,
        surface_ready_receipt_sha256: &str,
    ) -> Self {
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let opaque_ids = OpaqueCallerIds::from_call(&namespace, call);
        Self {
            operation: call.operation,
            request_id: opaque_ids.request_id,
            operation_id: opaque_ids.operation_id,
            idempotency_key: opaque_ids.idempotency_key,
            namespace,
            registration_revision: call.registration_revision,
            ready_receipt_sha256: surface_ready_receipt_sha256.to_owned(),
            expected_state_generation: call.expected_state_generation,
            control,
            payload,
            required_capabilities: call.required_capabilities.clone(),
            extensions: Vec::new(),
        }
    }
}

/// Stage at which an opt-in recall diagnostic was captured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NcmRecallDiagnosticStage {
    /// Candidate rows exactly as returned by the worker surface.
    Worker,
    /// Candidate rows after the adapter validated and reconstructed them.
    Reconstructed,
    /// A valid recall reply was reconstructed with partial coverage.
    PartialReply,
    /// The caller cancelled after the surface had already returned.
    PostDispatchCancellation,
    /// The caller deadline elapsed after the surface had already returned.
    PostDispatchDeadline,
    /// The adapter could not reconstruct the worker reply.
    ReconstructionFailure,
}

/// Bounded, redacted evidence for comparing worker recall with adapter output.
///
/// The event deliberately contains no query, content, source, or candidate
/// identifiers. Identity fields are caller-keyed, namespace-bound HMAC
/// digests, and the two vectors of per-candidate values are capped at the
/// provider's recall limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NcmRecallDiagnosticEvent {
    /// Capture stage.
    pub stage: NcmRecallDiagnosticStage,
    /// Caller-keyed digest of the existing host request identity, omitted when
    /// no redaction key was supplied.
    pub request_id_sha256: Option<String>,
    /// Caller-keyed digest of the existing host operation identity, omitted
    /// when no redaction key was supplied.
    pub operation_id_sha256: Option<String>,
    /// Caller-keyed digest of the recall query text, omitted when no
    /// redaction key was supplied.
    pub query_sha256: Option<String>,
    /// Caller-keyed, namespace-bound digest of the admitted exact coding
    /// scope, omitted when no redaction key was supplied.
    pub exact_scope_sha256: Option<String>,
    /// Derived NCM namespace digest used as the diagnostic key context. It is
    /// omitted when no redaction key was supplied.
    pub namespace_sha256: Option<String>,
    /// Caller-keyed, namespace-bound digest of the proved provider instance
    /// identity, omitted when no redaction key was supplied.
    pub provider_instance_sha256: Option<String>,
    /// Provider state generation observed at capture.
    pub state_generation: u64,
    /// Number of items the worker scanned for this recall.
    pub scanned_items: u64,
    /// Number of candidates reported at this stage.
    pub candidate_count: u64,
    /// One-based ranks for the bounded candidate sample.
    pub candidate_ranks: Vec<u64>,
    /// Observed content byte counts aligned with `candidate_ranks`.
    pub candidate_content_bytes: Vec<u64>,
    /// Candidates excluded by the request or adapter.
    pub excluded_count: u64,
    /// Candidates truncated or omitted by a limit.
    pub truncated_count: u64,
    /// Candidates with incomplete validity/source evidence.
    pub unknown_count: u64,
    /// Candidates with no content bytes.
    pub empty_content_count: u64,
    /// Adjacent candidates whose finite scores tie exactly.
    pub score_tie_count: u64,
    /// Adjacent finite score margins at or below one millionth.
    pub score_margin_below_epsilon_count: u64,
    /// Remaining candidate slots at the request limit.
    pub remaining_candidate_slots: u64,
    /// Remaining content bytes after budget-eligible candidates at the request limit.
    pub remaining_content_bytes: u64,
}

/// Opt-in sink for bounded, redacted recall diagnostics.
///
/// The adapter never installs a sink by default. A sink is intended for an
/// explicitly owned test or diagnostic run and is best effort: sink failures
/// cannot change the provider reply.
pub trait NcmRecallDiagnosticSink: Send + Sync {
    /// Receives one redacted recall-stage event.
    fn record(&self, event: NcmRecallDiagnosticEvent);
}

/// Caller-owned secret used to MAC diagnostic identity fields.
///
/// The key is retained only by the adapter and is never included in a
/// diagnostic event. A caller that cannot provide a secret can pass `None` to
/// `with_recall_diagnostic_sink`; reversible fingerprints are then omitted.
#[derive(Clone)]
pub struct NcmRecallDiagnosticKey([u8; 32]);

impl NcmRecallDiagnosticKey {
    /// Wraps a caller-owned 256-bit secret without copying it into an event.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Licensed NCM behavior surface supplied after the M6 surface audit and
/// topology decision.
///
/// This trait is intentionally topology-neutral. An implementation may call a
/// Rust library or a supervised local process, but callers observe the same
/// bounded provider contract and opaque namespace.
pub trait NcmCognitiveSurface: Send + Sync + 'static {
    /// Returns the real NCM implementation/capability descriptor.
    fn descriptor(&self) -> ProviderDescriptor;

    /// Performs a read-only compatibility handshake for one opaque namespace.
    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse;

    /// Executes one provider-local operation using a scope-safe JSON projection
    /// and no raw coding, caller, or extension identities.
    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply;
}

struct AcceptedReadiness {
    registration_revision: u64,
    exact_scope: OwnedExactScope,
    public_ready_receipt_sha256: String,
    surface_ready_receipt_sha256: String,
    provider_instance_id: String,
    descriptor: ProviderDescriptor,
    effective_limits: ProviderLimits,
    valid: AtomicBool,
    active_operations: AtomicU64,
}

impl AcceptedReadiness {
    fn matches_call(&self, call: &ProviderCall, descriptor: &ProviderDescriptor) -> bool {
        self.registration_revision == call.registration_revision
            && self.exact_scope == call.exact_scope
            && self.public_ready_receipt_sha256 == call.ready_receipt_sha256
            && self.descriptor.state_generation == call.expected_state_generation
            && !self.provider_instance_id.is_empty()
            && self.descriptor == *descriptor
            && self.valid.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct ReadinessState {
    epoch: u64,
    accepted: Option<AcceptedReadiness>,
}

struct OperationAdmission<'a> {
    active_operations: &'a AtomicU64,
}

impl OperationAdmission<'_> {
    fn try_acquire<'a>(readiness: &'a AcceptedReadiness) -> Option<OperationAdmission<'a>> {
        readiness
            .active_operations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < readiness.effective_limits.concurrent_operations)
                    .then(|| active.saturating_add(1))
            })
            .ok()
            .map(|_| OperationAdmission {
                active_operations: &readiness.active_operations,
            })
    }
}

impl Drop for OperationAdmission<'_> {
    fn drop(&mut self) {
        self.active_operations.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Provider-neutral adapter over one audited licensed NCM surface.
pub struct NcmProviderAdapter {
    surface: Arc<dyn NcmCognitiveSurface>,
    readiness: RwLock<ReadinessState>,
    admission_authority: Option<Arc<dyn AdvisoryAdmissionAuthority>>,
    recall_diagnostic_sink: Option<Arc<dyn NcmRecallDiagnosticSink>>,
    recall_diagnostic_key: Option<NcmRecallDiagnosticKey>,
}

impl NcmProviderAdapter {
    /// Constructs an adapter only for a surface declaring the reserved NCM
    /// identity. This does not select an execution topology or open state.
    pub fn new(surface: Arc<dyn NcmCognitiveSurface>) -> Result<Self, NcmAdapterError> {
        let descriptor = surface.descriptor();
        if descriptor.provider_id.as_str() != NCM_PROVIDER_ID {
            return Err(NcmAdapterError::ProviderIdMismatch {
                expected: NCM_PROVIDER_ID,
                declared: descriptor.provider_id.as_str().to_owned(),
            });
        }
        Ok(Self {
            surface,
            readiness: RwLock::new(ReadinessState::default()),
            admission_authority: None,
            recall_diagnostic_sink: None,
            recall_diagnostic_key: None,
        })
    }

    /// Installs the trusted host authority used freshly for each invocation.
    /// Payload grants never substitute for this composition-owned port.
    #[must_use]
    pub fn with_admission_authority(
        mut self,
        authority: Arc<dyn AdvisoryAdmissionAuthority>,
    ) -> Self {
        self.admission_authority = Some(authority);
        self
    }

    /// Installs an explicitly owned, best-effort sink for redacted recall
    /// stage diagnostics. The default adapter has no sink and emits nothing.
    /// Passing `None` records only non-identifying counts and metrics.
    #[must_use]
    pub fn with_recall_diagnostic_sink(
        mut self,
        sink: Arc<dyn NcmRecallDiagnosticSink>,
        key: Option<NcmRecallDiagnosticKey>,
    ) -> Self {
        self.recall_diagnostic_sink = Some(sink);
        self.recall_diagnostic_key = key;
        self
    }

    fn supports_required_capabilities(
        descriptor: &ProviderDescriptor,
        required: &BTreeSet<OwnedVersionedId>,
    ) -> bool {
        required.iter().all(|capability| {
            CAPABILITIES
                .iter()
                .any(|known| known.capability_id == capability.as_str())
                && descriptor.supports(capability.as_str())
        })
    }

    fn valid_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn valid_payload(payload: &CanonicalPayload, response_bytes: u64) -> bool {
        u64::try_from(payload.bytes.len()).unwrap_or(u64::MAX) <= response_bytes
            && payload.sha256 == hex_digest(&Sha256::digest(&payload.bytes))
    }

    fn capped_control(
        control: &OperationControl,
        limits: ProviderLimits,
    ) -> Result<OperationControl, TerminalCode> {
        let snapshot = control.snapshot()?;
        let remaining_millis = snapshot.remaining_millis.min(limits.operation_millis);
        if remaining_millis == 0 {
            return Err(TerminalCode::DeadlineExceeded);
        }
        let surface_control = if control.remaining_millis() <= limits.operation_millis {
            control.clone()
        } else {
            OperationControl::new(
                snapshot.deadline_utc_micros,
                remaining_millis,
                control.cancellation(),
            )
        };
        Ok(surface_control)
    }

    fn operation_contract_id(operation: ProviderOperation) -> Option<&'static str> {
        match operation {
            ProviderOperation::Handshake => None,
            ProviderOperation::Health => Some("tracedecay.memory.provider.health.v1"),
            ProviderOperation::Observe => Some("tracedecay.memory.provider.observation.v1"),
            ProviderOperation::Recall => Some("tracedecay.memory.provider.recall.v1"),
            ProviderOperation::Feedback => Some("tracedecay.memory.provider.feedback.v1"),
            ProviderOperation::Maintenance => Some("tracedecay.memory.provider.maintenance.v1"),
            ProviderOperation::Inspection => Some("tracedecay.memory.provider.inspection.v1"),
            ProviderOperation::Correction => Some("tracedecay.memory.provider.correction.v1"),
            ProviderOperation::DeleteBySource => {
                Some("tracedecay.memory.provider.deletion-by-source.v1")
            }
            ProviderOperation::SnapshotExport => {
                Some("tracedecay.memory.provider.snapshot-export.v1")
            }
            ProviderOperation::SnapshotRestore => {
                Some("tracedecay.memory.provider.snapshot-restore.v1")
            }
            ProviderOperation::Replay => Some("tracedecay.memory.provider.replay.v1"),
        }
    }

    fn surface_payload(
        call: &ProviderCall,
        admission: Option<&CurrentAdvisoryAdmission>,
        descriptor: &ProviderDescriptor,
        limits: ProviderLimits,
    ) -> Option<CanonicalPayload> {
        if Self::operation_contract_id(call.operation) != Some(call.payload.contract_id.as_str()) {
            return None;
        }
        let mut value = serde_json::from_slice::<Value>(&call.payload.bytes).ok()?;
        if !value.is_object() {
            return None;
        }
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let opaque_ids = OpaqueCallerIds::from_call(&namespace, call);
        if let Some(projected) =
            common::project_portability(call, &value, &namespace, admission, descriptor, limits)?
        {
            value = projected;
        }
        if let Some(projected) = common::project_lifecycle(call, &value, &namespace, admission)? {
            value = projected;
        }
        if call.operation == ProviderOperation::Recall && value.get("temporal_query").is_some() {
            value = common::project_recall(call, &value, &namespace)?;
        }
        let retained = if call.operation == ProviderOperation::Observe {
            common::project_attribution(call, &value, &namespace)?
        } else {
            None
        };
        project_observation_sources(&mut value, call, &namespace)?;
        if let Some(retained) = retained {
            value
                .as_object_mut()?
                .insert("provenance".to_owned(), retained);
        }
        remove_exact_scope_identity(&mut value);
        if !rewrite_caller_identity_fields(&mut value, call, &opaque_ids)
            || json_contains_scope_component(&value, &call.exact_scope)
            || json_contains_public_caller_id(&value, call)
        {
            return None;
        }
        let bytes = serde_json::to_vec(&value).ok()?;
        if serialized_contains_scope_component(&bytes, &call.exact_scope)
            || serialized_contains_public_caller_id(&bytes, call)
        {
            return None;
        }
        let digest = hex_digest(&Sha256::digest(&bytes));
        CanonicalPayload::new(call.payload.contract_id.clone(), bytes, digest).ok()
    }

    fn maximum_extensions(operation: ProviderOperation) -> usize {
        if operation == ProviderOperation::Recall {
            16
        } else {
            32
        }
    }

    fn maximum_extension_bytes(operation: ProviderOperation) -> u64 {
        if operation == ProviderOperation::Recall {
            131_072
        } else {
            262_144
        }
    }

    /// Symmetric to `valid_surface_reply`: a snapshot travels inside the
    /// SnapshotRestore request the way it travels inside the SnapshotExport
    /// reply, so that one operation is measured against `snapshot_bytes`.
    fn request_limit(operation: ProviderOperation, limits: ProviderLimits) -> u64 {
        if operation == ProviderOperation::SnapshotRestore {
            limits.snapshot_bytes
        } else {
            limits.request_bytes
        }
    }

    fn valid_request(call: &ProviderCall, limits: ProviderLimits) -> bool {
        let request_limit = Self::request_limit(call.operation, limits);
        let extension_bytes = call.extensions.iter().fold(0_u64, |total, extension| {
            total.saturating_add(
                u64::try_from(extension.canonical_payload.len()).unwrap_or(u64::MAX),
            )
        });
        call.exact_scope.validate().is_ok()
            && !call.request_id.is_empty()
            && !call.operation_id.is_empty()
            && call
                .idempotency_key
                .as_deref()
                .is_none_or(|value| !value.is_empty())
            && (!call.operation.mutates_provider_state()
                || call
                    .idempotency_key
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()))
            && call
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == call.operation.capability_id())
            && Self::valid_sha256(&call.ready_receipt_sha256)
            && Self::valid_payload(&call.payload, request_limit)
            && call.extensions.len() <= Self::maximum_extensions(call.operation)
            && (call.operation != ProviderOperation::Observe
                || extension_bytes <= MAX_OBSERVATION_TOTAL_EXTENSION_BYTES)
            && u64::try_from(call.payload.bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_add(extension_bytes)
                <= request_limit
            && call.extensions.iter().all(|extension| {
                !extension.required
                    && extension.extension_version > 0
                    && !extension.canonical_payload.is_empty()
                    && u64::try_from(extension.canonical_payload.len()).unwrap_or(u64::MAX)
                        <= Self::maximum_extension_bytes(call.operation)
                    && extension.payload_sha256
                        == hex_digest(&Sha256::digest(&extension.canonical_payload))
            })
            // The public envelope is measured by the provider-API authority, not
            // by an adapter-local copy of it: the fabric admits a call against
            // exactly this count, so a private encoder that drifts from it would
            // reject an admitted call as an unexplained invalid request.
            && call.validate_request_bytes(request_limit).is_ok()
    }

    fn success_terminal(code: TerminalCode) -> bool {
        matches!(
            code,
            TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
        )
    }

    fn valid_maintenance_partial_payload(reply: &ProviderReply) -> bool {
        reply
            .payload
            .as_ref()
            .and_then(|payload| serde_json::from_slice::<Value>(&payload.bytes).ok())
            .is_some_and(|payload| {
                payload["common_control"].as_str() == Some("maintenance")
                    && payload["no_change"] == true
                    && payload["partial"] == true
                    && payload["state_generation_before"]
                        .as_u64()
                        .is_some_and(|generation| generation == reply.state_generation)
                    && payload["state_generation_after"]
                        .as_u64()
                        .is_some_and(|generation| generation == reply.state_generation)
                    && payload["resume_cursor"]
                        .as_str()
                        .is_some_and(|cursor| !cursor.is_empty())
            })
    }

    fn valid_maintenance_partial_cursor(
        payload: &Value,
        surface_call: &NcmSurfaceCall,
        state_generation: u64,
    ) -> bool {
        let Some(cursor) = payload["resume_cursor"].as_str() else {
            return false;
        };
        if cursor.is_empty() || cursor.len() > 1024 {
            return false;
        }
        let prefix = format!("ncm-maintenance:{}:", surface_call.namespace.as_str());
        let Some(remainder) = cursor.strip_prefix(&prefix) else {
            return false;
        };
        let mut parts = remainder.split(':');
        let Some(task) = parts.next() else {
            return false;
        };
        if !matches!(
            task,
            "consolidate" | "decay" | "prune_expired" | "validate_state" | "repair" | "compact"
        ) {
            return false;
        }
        let Some(generation_text) = parts.next() else {
            return false;
        };
        let Some(after_text) = parts.next() else {
            return false;
        };
        let Some(generation) = generation_text.parse::<u64>().ok() else {
            return false;
        };
        let Some(after) = after_text.parse::<u64>().ok() else {
            return false;
        };
        generation == state_generation
            && generation.to_string() == generation_text
            && after <= i64::MAX as u64
            && after.to_string() == after_text
            && parts.next().is_none()
    }

    fn valid_terminal_semantics(
        call: &ProviderCall,
        surface_call: &NcmSurfaceCall,
        reply: &ProviderReply,
    ) -> bool {
        let terminal = &reply.terminal;
        let terminal_code = terminal.terminal_code();
        let committed_effect = terminal.committed_effect();
        let success = Self::success_terminal(terminal_code);
        let replay_accounting = call.operation == ProviderOperation::Replay
            && common::valid_replay_payload(surface_call, reply);
        if call.operation == ProviderOperation::Replay
            && reply.payload.is_some()
            && !replay_accounting
        {
            return false;
        }
        if committed_effect
            .state_generation_before()
            .is_some_and(|generation| generation != call.expected_state_generation)
            || committed_effect
                .state_generation_after()
                .is_some_and(|generation| generation != reply.state_generation)
        {
            return false;
        }
        if !success
            && ((reply.payload.is_some() && !replay_accounting)
                || terminal.diagnostic_id().is_none_or(str::is_empty))
        {
            return false;
        }
        if !call.operation.mutates_provider_state() {
            return reply.state_generation == call.expected_state_generation
                && committed_effect.state() == CommittedEffectState::None
                && committed_effect.provider_receipt_sha256().is_none()
                && !matches!(
                    terminal_code,
                    TerminalCode::PartialEffect | TerminalCode::EffectUnknown
                );
        }
        if terminal_code == TerminalCode::SuccessZeroResults {
            return false;
        }
        if terminal_code == TerminalCode::Partial {
            return call.operation == ProviderOperation::Maintenance
                && reply.state_generation == call.expected_state_generation
                && committed_effect.state() == CommittedEffectState::None
                && committed_effect.provider_receipt_sha256().is_none()
                && Self::valid_maintenance_partial_payload(reply);
        }
        match committed_effect.state() {
            CommittedEffectState::None => {
                committed_effect.provider_receipt_sha256().is_none()
                    && !matches!(
                        terminal_code,
                        TerminalCode::PartialEffect | TerminalCode::EffectUnknown
                    )
            }
            CommittedEffectState::Committed => {
                terminal_code == TerminalCode::Success
                    && committed_effect
                        .provider_receipt_sha256()
                        .is_some_and(Self::valid_sha256)
            }
            // A redelivery the surface recognised: the effect exists, the
            // generation did not move, and the claim must name this call's own
            // idempotency key so it cannot acknowledge a different mutation.
            CommittedEffectState::Duplicate => {
                terminal_code == TerminalCode::Success
                    && committed_effect
                        .provider_receipt_sha256()
                        .is_some_and(Self::valid_sha256)
                    && committed_effect.state_generation_before()
                        == committed_effect.state_generation_after()
                    && reply.state_generation == call.expected_state_generation
                    && committed_effect.duplicate_of_idempotency_key()
                        == surface_call.idempotency_key.as_deref()
                    && surface_call.idempotency_key.is_some()
                    && call.idempotency_key.is_some()
                    && committed_effect
                        .duplicate_of_operation_id()
                        .is_some_and(|value| !value.is_empty())
            }
            CommittedEffectState::Partial => {
                matches!(
                    terminal_code,
                    TerminalCode::PartialEffect
                        | TerminalCode::Cancelled
                        | TerminalCode::DeadlineExceeded
                ) && committed_effect
                    .provider_receipt_sha256()
                    .is_some_and(Self::valid_sha256)
                    && (reply.payload.is_none() || replay_accounting)
            }
            CommittedEffectState::Unknown => {
                matches!(
                    terminal_code,
                    TerminalCode::EffectUnknown
                        | TerminalCode::Cancelled
                        | TerminalCode::DeadlineExceeded
                ) && committed_effect
                    .provider_receipt_sha256()
                    .is_some_and(Self::valid_sha256)
                    && (reply.payload.is_none() || replay_accounting)
            }
        }
    }

    fn surface_identity_refresh_generation(
        response: &NcmSurfaceHandshakeResponse,
        descriptor: &ProviderDescriptor,
    ) -> Option<u64> {
        let effect = response.terminal.committed_effect();
        let observed_generation = effect.state_generation_before()?;
        (response.terminal.terminal_code() == TerminalCode::StaleIdentity
            && response.terminal.diagnostic_id() == Some(SURFACE_IDENTITY_REFRESH_DIAGNOSTIC)
            && effect.state() == CommittedEffectState::None
            && Some(observed_generation) == effect.state_generation_after()
            && observed_generation != descriptor.state_generation
            && response.descriptor.is_none()
            && response.provider_instance_id.is_none()
            && response.namespace.is_none()
            && response.effective_limits.is_none()
            && response.ready_receipt_sha256.is_none()
            && response.challenge_response_sha256.is_none()
            && response.warnings.is_empty())
        .then_some(observed_generation)
    }

    fn surface_metadata_is_scope_safe(
        call: &ProviderCall,
        surface_call: &NcmSurfaceCall,
        reply: &ProviderReply,
    ) -> bool {
        let effect = reply.terminal.committed_effect();
        let public_scope_digest = call.exact_scope.exact_scope_sha256();
        let mut forbidden = surface_forbidden_identities(call, surface_call);
        forbidden.push(public_scope_digest.as_str());
        effect
            .committed_boundary()
            .is_none_or(|value| !text_contains_any(value, &forbidden))
            && effect
                .committed_item_refs()
                .iter()
                .all(|value| !text_contains_any(value, &forbidden))
            && effect
                .uncommitted_item_refs()
                .iter()
                .all(|value| !text_contains_any(value, &forbidden))
            && effect
                .reconciliation_action()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            && effect
                .provider_receipt_sha256()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            && effect
                .verification_sha256()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            // The deduplicated key is a TraceDecay-derived value the caller
            // already holds, but the operation the surface names is
            // provider-authored text and gets the same scope scan.
            && effect
                .duplicate_of_operation_id()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            && reply
                .terminal
                .diagnostic_id()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            && reply
                .warnings
                .iter()
                .all(|value| !text_contains_any(value, &forbidden))
            && reply
                .terminal
                .fallback()
                .source_provider_id()
                .is_none_or(|provider_id| !text_contains_any(provider_id.as_str(), &forbidden))
            && reply
                .terminal
                .fallback()
                .reason()
                .is_none_or(|value| !text_contains_any(value, &forbidden))
            && reply.terminal.fallback().policy().is_none_or(|policy| {
                !text_contains_any(policy.policy_id(), &forbidden)
                    && !text_contains_any(policy.target_provider_id().as_str(), &forbidden)
            })
    }

    fn rebind_terminal(
        terminal: &TerminalRecord,
        operation: ProviderOperation,
        provider_id: OwnedProviderId,
        operation_id: impl Into<String>,
        exact_scope_sha256: impl Into<String>,
        host_idempotency_key: Option<&str>,
    ) -> Option<TerminalRecord> {
        if terminal.operation() != operation || terminal.provider_id() != &provider_id {
            return None;
        }
        let effect = terminal.committed_effect();
        if effect.state() != CommittedEffectState::Duplicate {
            return terminal
                .clone()
                .try_with_identity(operation_id, exact_scope_sha256)
                .ok();
        }
        // The surface deduplicated against the namespace-opaque key it was
        // given. The host's journal matches the duplicate against the
        // observation it actually delivered, so the opaque key is replaced by
        // the caller's own key here — after `valid_terminal_semantics` has
        // already proved the surface named the opaque projection of exactly
        // that key. The committing operation stays opaque: it names the
        // surface's own prior operation, which has no host-side identity.
        let host_idempotency_key = host_idempotency_key?;
        let rebound_effect = CommittedEffectEvidence::duplicate(
            effect.state_generation_after()?,
            host_idempotency_key,
            effect.duplicate_of_operation_id()?,
            effect.provider_receipt_sha256()?,
        )
        .ok()?;
        TerminalRecord::new(
            terminal.operation(),
            provider_id,
            terminal.terminal_code(),
            rebound_effect,
            terminal.fallback().clone(),
            operation_id,
            exact_scope_sha256,
            terminal.diagnostic_id().map(str::to_owned),
        )
        .ok()
    }

    fn handshake_failure(
        request: &HandshakeRequest,
        code: TerminalCode,
        diagnostic_id: &'static str,
    ) -> HandshakeResponse {
        let terminal = TerminalRecord::failure_before_dispatch(
            ProviderOperation::Handshake,
            request.provider_id.clone(),
            code,
            &request.request_id,
            request.exact_scope.exact_scope_sha256(),
            None,
            diagnostic_id,
        );
        HandshakeResponse {
            terminal,
            descriptor: None,
            provider_instance_id: None,
            state_namespace: None,
            accepted_scope: None,
            effective_limits: None,
            ready_receipt_sha256: None,
            warnings: Vec::new(),
        }
    }

    fn invoke_failure(
        call: &ProviderCall,
        code: TerminalCode,
        diagnostic_id: &'static str,
    ) -> ProviderReply {
        let terminal = TerminalRecord::failure_before_dispatch(
            call.operation,
            call.provider_id.clone(),
            code,
            &call.operation_id,
            call.exact_scope.exact_scope_sha256(),
            // No state was touched, so the addressed generation is the
            // observed one; the fabric refuses replies that omit it.
            Some(call.expected_state_generation),
            diagnostic_id,
        );
        ProviderReply {
            terminal,
            payload: None,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }

    fn surface_contract_failure(
        call: &ProviderCall,
        surface_call: &NcmSurfaceCall,
        reply: &ProviderReply,
    ) -> ProviderReply {
        let terminal = if call.operation.mutates_provider_state() {
            let receipt = adapter_unknown_effect_receipt(call, surface_call, reply);
            let action = format!(
                "{RECONCILE_SURFACE_DISPATCH_ACTION}:{}",
                hex_digest(&receipt)
            );
            TerminalRecord::effect_unknown_for_call_with_action(
                call,
                receipt,
                &action,
                "ncm.adapter_unknown_effect_reconciliation_required",
            )
        } else {
            TerminalRecord::failure_before_dispatch(
                call.operation,
                call.provider_id.clone(),
                TerminalCode::ContractViolation,
                &call.operation_id,
                call.exact_scope.exact_scope_sha256(),
                Some(call.expected_state_generation),
                "ncm.surface_contract_violation",
            )
        };
        ProviderReply {
            terminal,
            payload: None,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }

    fn valid_surface_reply(
        call: &ProviderCall,
        surface_call: &NcmSurfaceCall,
        reply: &ProviderReply,
        limits: ProviderLimits,
    ) -> bool {
        let response_limit = if call.operation == ProviderOperation::SnapshotExport {
            limits.snapshot_bytes
        } else {
            limits.response_bytes
        };
        reply.terminal.operation() == call.operation
            && reply.terminal.provider_id().as_str() == NCM_PROVIDER_ID
            && reply.terminal.operation_id() == surface_call.operation_id
            && reply.terminal.exact_scope_sha256() == surface_call.namespace.as_str()
            && reply.terminal.fallback().eligibility() == FallbackEligibility::Forbidden
            && reply.warnings.len() <= MAX_WARNINGS
            && encoded_response_bytes(call, reply) <= response_limit
            && reply.state_generation >= call.expected_state_generation
            && reply.extensions.is_empty()
            && Self::surface_metadata_is_scope_safe(call, surface_call, reply)
            && reply.payload.as_ref().is_none_or(|payload| {
                Self::valid_payload(payload, response_limit)
                    && payload.contract_id == surface_call.payload.contract_id
                    && serde_json::from_slice::<Value>(&payload.bytes).is_ok_and(|mut value| {
                        if call.operation == ProviderOperation::Maintenance
                            && Self::valid_maintenance_partial_payload(reply)
                            && Self::valid_maintenance_partial_cursor(
                                &value,
                                surface_call,
                                reply.state_generation,
                            )
                        {
                            if let Some(object) = value.as_object_mut() {
                                object.remove("resume_cursor");
                            }
                        }
                        value.is_object()
                            && !json_has_exact_scope_identity(&value)
                            && !json_contains_scope_component(&value, &call.exact_scope)
                            && !json_contains_public_caller_id(&value, call)
                            && !json_contains_surface_identity(&value, surface_call)
                    })
            })
            && Self::valid_terminal_semantics(call, surface_call, reply)
    }
}

impl MemoryProvider for NcmProviderAdapter {
    fn descriptor(&self) -> ProviderDescriptor {
        self.surface.descriptor()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        if request.validate().is_err() {
            return Self::handshake_failure(
                request,
                TerminalCode::InvalidRequest,
                "ncm.handshake_request_invalid",
            );
        }
        if request.provider_id.as_str() != NCM_PROVIDER_ID {
            return Self::handshake_failure(
                request,
                TerminalCode::InvalidRequest,
                "ncm.provider_id_mismatch",
            );
        }
        let mut readiness = match self.readiness.write() {
            Ok(readiness) => readiness,
            Err(_) => {
                return Self::handshake_failure(
                    request,
                    TerminalCode::ProviderUnavailable,
                    "ncm.ready_session_unavailable",
                );
            }
        };
        let mut descriptor = self.surface.descriptor();
        if descriptor.validate().is_err() {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_descriptor_invalid",
            );
        }
        if descriptor.provider_id.as_str() != NCM_PROVIDER_ID {
            return Self::handshake_failure(
                request,
                TerminalCode::StaleIdentity,
                "ncm.surface_identity_changed",
            );
        }
        if !Self::supports_required_capabilities(&descriptor, &request.required_capabilities) {
            return Self::handshake_failure(
                request,
                TerminalCode::CapabilityUnsupported,
                "ncm.required_capability_missing",
            );
        }
        let effective_limits = request.host_limits.minimum(descriptor.limits);
        if effective_limits.validate().is_err() {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.effective_limits_invalid",
            );
        }
        let surface_control = match Self::capped_control(&request.control, effective_limits) {
            Ok(control) => control,
            Err(code) => {
                return Self::handshake_failure(request, code, "ncm.request_control_terminal");
            }
        };
        let namespace = NcmNamespace::from_exact_scope(&request.exact_scope);
        let surface_request = NcmSurfaceHandshakeRequest {
            registration_revision: request.registration_revision,
            namespace: namespace.clone(),
            request_id: opaque_surface_id(&namespace, b"handshake-request-id", &request.request_id),
            required_capabilities: request.required_capabilities.clone(),
            host_limits: request.host_limits,
            control: surface_control,
            challenge_nonce: request.challenge_nonce,
        };
        let projected_control = match surface_request.control.snapshot() {
            Ok(control) => control,
            Err(code) => {
                return Self::handshake_failure(request, code, "ncm.request_control_terminal");
            }
        };
        if encoded_surface_handshake_request_bytes(&surface_request, projected_control)
            > effective_limits.request_bytes
        {
            return Self::handshake_failure(
                request,
                TerminalCode::InvalidRequest,
                "ncm.projected_handshake_request_limit_exceeded",
            );
        }
        let Some(epoch) = readiness.epoch.checked_add(1) else {
            return Self::handshake_failure(
                request,
                TerminalCode::ProviderUnavailable,
                "ncm.ready_epoch_exhausted",
            );
        };
        readiness.accepted = None;
        readiness.epoch = epoch;
        let mut surface_response = self.surface.handshake(&surface_request);
        if surface_response.terminal.operation() != ProviderOperation::Handshake
            || surface_response.terminal.provider_id().as_str() != NCM_PROVIDER_ID
            || surface_response.terminal.operation_id() != surface_request.request_id
            || surface_response.terminal.exact_scope_sha256() != namespace.as_str()
            || surface_response.terminal.fallback().eligibility() != FallbackEligibility::Forbidden
            || surface_response.terminal.committed_effect().state() != CommittedEffectState::None
            || surface_response
                .terminal
                .committed_effect()
                .provider_receipt_sha256()
                .is_some()
            || surface_response.warnings.len() > MAX_WARNINGS
            || !handshake_metadata_is_scope_safe(request, &surface_request, &surface_response)
        {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_handshake_contract_violation",
            );
        }
        if let Some(refreshed_generation) =
            Self::surface_identity_refresh_generation(&surface_response, &descriptor)
        {
            if let Err(code) = surface_request.control.snapshot() {
                return Self::handshake_failure(request, code, "ncm.request_control_terminal");
            }
            // RustNcmSurface installs the worker generation before reporting
            // this bounded transition. One re-handshake can therefore bind
            // the new identity, while the final response still goes through
            // every normal scope, model, provider, and challenge check below.
            descriptor.state_generation = refreshed_generation;
            surface_response = self.surface.handshake(&surface_request);
        }
        let surface_success = surface_response.terminal.terminal_code() == TerminalCode::Success;
        if matches!(
            surface_response.terminal.terminal_code(),
            TerminalCode::SuccessZeroResults | TerminalCode::Partial
        ) {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_invalid_ready_terminal",
            );
        }
        if !surface_success
            && (surface_response.descriptor.is_some()
                || surface_response.provider_instance_id.is_some()
                || surface_response.namespace.is_some()
                || surface_response.effective_limits.is_some()
                || surface_response.ready_receipt_sha256.is_some()
                || surface_response.challenge_response_sha256.is_some()
                || surface_response
                    .terminal
                    .diagnostic_id()
                    .is_none_or(str::is_empty))
        {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_failure_contract_violation",
            );
        }
        let Some(public_terminal) = Self::rebind_terminal(
            &surface_response.terminal,
            ProviderOperation::Handshake,
            request.provider_id.clone(),
            request.request_id.clone(),
            request.exact_scope.exact_scope_sha256(),
            None,
        ) else {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_terminal_rebind_failed",
            );
        };
        surface_response.terminal = public_terminal;
        if !surface_success {
            let response = HandshakeResponse {
                terminal: surface_response.terminal,
                descriptor: None,
                provider_instance_id: None,
                state_namespace: None,
                accepted_scope: None,
                effective_limits: None,
                ready_receipt_sha256: None,
                warnings: surface_response.warnings,
            };
            if encoded_handshake_response_bytes(&response) > effective_limits.response_bytes {
                return Self::handshake_failure(
                    request,
                    TerminalCode::ContractViolation,
                    "ncm.surface_handshake_response_limit_exceeded",
                );
            }
            return response;
        }
        let Some(response_descriptor) = surface_response.descriptor else {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_missing_descriptor",
            );
        };
        let Some(surface_ready_receipt_sha256) = surface_response.ready_receipt_sha256.as_deref()
        else {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_missing_ready_receipt",
            );
        };
        let Some(provider_instance_id) = surface_response.provider_instance_id.as_deref() else {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_missing_instance_identity",
            );
        };
        let expected_challenge = surface_request.expected_challenge_response_sha256(
            &response_descriptor,
            provider_instance_id,
            surface_ready_receipt_sha256,
        );
        if response_descriptor.validate().is_err()
            || response_descriptor != descriptor
            || surface_response.namespace.as_ref() != Some(&namespace)
            || provider_instance_id.trim().is_empty()
            || surface_response
                .effective_limits
                .is_none_or(|limits| limits.validate().is_err())
            || surface_response.effective_limits != Some(effective_limits)
            || !Self::valid_sha256(surface_ready_receipt_sha256)
            || surface_response.challenge_response_sha256.as_deref()
                != Some(expected_challenge.as_str())
        {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_incomplete_ready_response",
            );
        }
        let surface_ready_receipt_sha256 = surface_ready_receipt_sha256.to_owned();
        let provider_instance_id = provider_instance_id.to_owned();
        let public_ready_receipt_sha256 = adapter_ready_receipt(
            epoch,
            request,
            &namespace,
            &surface_ready_receipt_sha256,
            &provider_instance_id,
            &response_descriptor,
            effective_limits,
        );
        surface_response.ready_receipt_sha256 = Some(public_ready_receipt_sha256.clone());
        let public_response = HandshakeResponse {
            terminal: surface_response.terminal,
            descriptor: Some(response_descriptor.clone()),
            provider_instance_id: Some(provider_instance_id.clone()),
            state_namespace: Some(namespace.0.clone()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: surface_response.effective_limits,
            ready_receipt_sha256: surface_response.ready_receipt_sha256,
            warnings: surface_response.warnings,
        };
        if encoded_handshake_response_bytes(&public_response) > effective_limits.response_bytes {
            return Self::handshake_failure(
                request,
                TerminalCode::ContractViolation,
                "ncm.surface_handshake_response_limit_exceeded",
            );
        }
        let accepted_readiness = AcceptedReadiness {
            registration_revision: request.registration_revision,
            exact_scope: request.exact_scope.clone(),
            public_ready_receipt_sha256: public_ready_receipt_sha256.clone(),
            surface_ready_receipt_sha256,
            provider_instance_id,
            descriptor: response_descriptor.clone(),
            effective_limits,
            valid: AtomicBool::new(true),
            active_operations: AtomicU64::new(0),
        };
        readiness.accepted = Some(accepted_readiness);
        public_response
    }

    fn invoke(&self, call: &ProviderCall) -> ProviderReply {
        if call.provider_id.as_str() != NCM_PROVIDER_ID {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.provider_id_mismatch",
            );
        }
        if call.operation == ProviderOperation::Handshake {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.handshake_requires_handshake_port",
            );
        }
        if call.validate().is_err() {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.call_envelope_invalid",
            );
        }
        if call.exact_scope.validate().is_err() {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.exact_scope_invalid",
            );
        }
        let readiness_state = match self.readiness.read() {
            Ok(readiness) => readiness,
            Err(_) => {
                return Self::invoke_failure(
                    call,
                    TerminalCode::ProviderUnavailable,
                    "ncm.ready_session_unavailable",
                );
            }
        };
        let Some(readiness) = readiness_state.accepted.as_ref() else {
            return Self::invoke_failure(
                call,
                TerminalCode::ProviderUnavailable,
                "ncm.ready_session_missing",
            );
        };
        let descriptor = self.surface.descriptor();
        if descriptor.validate().is_err()
            || readiness.descriptor.validate().is_err()
            || readiness.effective_limits.validate().is_err()
        {
            return Self::invoke_failure(
                call,
                TerminalCode::ContractViolation,
                "ncm.surface_descriptor_or_limits_invalid",
            );
        }
        if descriptor.provider_id.as_str() != NCM_PROVIDER_ID || descriptor != readiness.descriptor
        {
            return Self::invoke_failure(
                call,
                TerminalCode::StaleIdentity,
                "ncm.surface_identity_changed",
            );
        }
        if !readiness.matches_call(call, &descriptor) {
            return Self::invoke_failure(
                call,
                TerminalCode::StaleIdentity,
                "ncm.ready_session_mismatch",
            );
        }
        if !Self::supports_required_capabilities(&descriptor, &call.required_capabilities) {
            return Self::invoke_failure(
                call,
                TerminalCode::CapabilityUnsupported,
                "ncm.required_capability_missing",
            );
        }
        let surface_control = match Self::capped_control(&call.control, readiness.effective_limits)
        {
            Ok(control) => control,
            Err(code) => {
                return Self::invoke_failure(call, code, "ncm.request_control_terminal");
            }
        };
        if !Self::valid_request(call, readiness.effective_limits) {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.request_payload_or_extension_invalid",
            );
        }
        let current_admission = match &self.admission_authority {
            Some(authority) => match authority.admit(call).and_then(|admission| {
                admission.verify_for(call)?;
                call.control
                    .snapshot()
                    .map_err(AdvisoryAdmissionError::Control)?;
                Ok(admission)
            }) {
                Ok(admission) => Some(admission),
                Err(error) => {
                    return Self::invoke_failure(
                        call,
                        match error {
                            AdvisoryAdmissionError::Control(code) => code,
                            AdvisoryAdmissionError::Denied(_) => TerminalCode::Unauthorized,
                            AdvisoryAdmissionError::Unavailable(_) => {
                                TerminalCode::ProviderUnavailable
                            }
                            _ => TerminalCode::InvalidRequest,
                        },
                        "ncm.current_advisory_admission_refused",
                    );
                }
            },
            None => None,
        };
        let Some(surface_payload) = Self::surface_payload(
            call,
            current_admission.as_ref(),
            &readiness.descriptor,
            readiness.effective_limits,
        ) else {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.request_contract_or_scope_projection_invalid",
            );
        };
        let Some(_admission) = OperationAdmission::try_acquire(readiness) else {
            return Self::invoke_failure(
                call,
                TerminalCode::CapacityExceeded,
                "ncm.concurrent_operation_limit",
            );
        };
        let surface_call = NcmSurfaceCall::from_provider_call(
            call,
            surface_payload,
            surface_control,
            &readiness.surface_ready_receipt_sha256,
        );
        let projected_control = match surface_call.control.snapshot() {
            Ok(control) => control,
            Err(code) => {
                return Self::invoke_failure(call, code, "ncm.request_control_terminal");
            }
        };
        if encoded_surface_request_bytes(&surface_call, projected_control)
            > Self::request_limit(call.operation, readiness.effective_limits)
        {
            return Self::invoke_failure(
                call,
                TerminalCode::InvalidRequest,
                "ncm.projected_request_limit_exceeded",
            );
        }
        if call.operation.mutates_provider_state() {
            readiness.valid.store(false, Ordering::Release);
        }
        let mut reply = self.surface.invoke(&surface_call);
        if let Err(code) = call.control.snapshot() {
            if call.operation == ProviderOperation::Recall {
                common::emit_recall_post_dispatch_control_diagnostic(
                    call,
                    &readiness.provider_instance_id,
                    &reply,
                    code,
                    self.recall_diagnostic_sink.as_deref(),
                    self.recall_diagnostic_key
                        .as_ref()
                        .map(NcmRecallDiagnosticKey::as_bytes),
                );
            }
            return if call.operation.mutates_provider_state() {
                Self::surface_contract_failure(call, &surface_call, &reply)
            } else {
                Self::invoke_failure(call, code, "ncm.request_control_terminal_after_dispatch")
            };
        }
        if Self::valid_surface_reply(call, &surface_call, &reply, readiness.effective_limits) {
            let Some(public_terminal) = Self::rebind_terminal(
                &reply.terminal,
                call.operation,
                call.provider_id.clone(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                call.idempotency_key.as_deref(),
            ) else {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            };
            reply.terminal = public_terminal;
            if matches!(
                call.operation,
                ProviderOperation::SnapshotExport
                    | ProviderOperation::SnapshotRestore
                    | ProviderOperation::Replay
            ) && serde_json::from_slice::<Value>(&call.payload.bytes)
                .is_ok_and(|value| value.get("common_request").is_some())
                && reply.payload.is_some()
                && common::reconstruct_portability(
                    call,
                    &mut reply,
                    &readiness.descriptor,
                    readiness.effective_limits,
                )
                .is_none()
            {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            }
            if matches!(
                call.operation,
                ProviderOperation::Health
                    | ProviderOperation::Inspection
                    | ProviderOperation::Maintenance
                    | ProviderOperation::DeleteBySource
                    | ProviderOperation::Feedback
                    | ProviderOperation::Correction
            ) && serde_json::from_slice::<Value>(&call.payload.bytes)
                .is_ok_and(|value| value.get("common_request").is_some())
                && (reply.terminal.terminal_code() == TerminalCode::Success
                    || (call.operation == ProviderOperation::Maintenance
                        && reply.terminal.terminal_code() == TerminalCode::Partial))
                && common::reconstruct_lifecycle(call, &mut reply, readiness).is_none()
            {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            }
            if call.operation == ProviderOperation::Observe
                && serde_json::from_slice::<Value>(&call.payload.bytes)
                    .is_ok_and(|value| value.pointer("/source_identity/original_source").is_some())
                && reply.terminal.terminal_code() == TerminalCode::Success
                && common::reconstruct_observation(call, &mut reply).is_none()
            {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            }
            if call.operation == ProviderOperation::Recall
                && serde_json::from_slice::<Value>(&call.payload.bytes)
                    .is_ok_and(|value| value.get("temporal_query").is_some())
                && matches!(
                    reply.terminal.terminal_code(),
                    TerminalCode::Success | TerminalCode::SuccessZeroResults
                )
                && common::reconstruct_recall_with_diagnostics(
                    call,
                    &readiness.provider_instance_id,
                    &mut reply,
                    self.recall_diagnostic_sink.as_deref(),
                    self.recall_diagnostic_key
                        .as_ref()
                        .map(NcmRecallDiagnosticKey::as_bytes),
                )
                .is_none()
            {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            }
            reply.extensions.clone_from(&call.extensions);
            if encoded_response_bytes(call, &reply) > readiness.effective_limits.response_bytes
                && call.operation != ProviderOperation::SnapshotExport
            {
                return Self::surface_contract_failure(call, &surface_call, &reply);
            }
            reply
        } else {
            Self::surface_contract_failure(call, &surface_call, &reply)
        }
    }
}

fn adapter_ready_receipt(
    epoch: u64,
    request: &HandshakeRequest,
    namespace: &NcmNamespace,
    surface_ready_receipt_sha256: &str,
    provider_instance_id: &str,
    descriptor: &ProviderDescriptor,
    effective_limits: ProviderLimits,
) -> String {
    let mut digest = Sha256::new();
    digest.update(
        if descriptor
            .state_schema_version
            .starts_with("ncm-biomem-rs.v2+")
        {
            READY_RECEIPT_DOMAIN_V2
        } else {
            READY_RECEIPT_DOMAIN
        },
    );
    digest.update(epoch.to_be_bytes());
    digest.update(request.registration_revision.to_be_bytes());
    digest_field(&mut digest, namespace.as_str().as_bytes());
    digest_field(&mut digest, surface_ready_receipt_sha256.as_bytes());
    digest.update(request.challenge_nonce);
    digest_field(&mut digest, provider_instance_id.as_bytes());
    digest_field(&mut digest, descriptor.provider_id.as_str().as_bytes());
    digest_descriptor_details(&mut digest, descriptor);
    digest_limits(&mut digest, effective_limits);
    hex_digest(&digest.finalize())
}

/// Issues an adapter reconciliation receipt for an invoked mutation whose
/// returned surface envelope cannot be trusted as a provider terminal. The
/// digest proves the exact opaque dispatch and observed reply; it deliberately
/// does not claim that any provider effect committed.
fn adapter_unknown_effect_receipt(
    call: &ProviderCall,
    surface_call: &NcmSurfaceCall,
    reply: &ProviderReply,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(UNKNOWN_EFFECT_RECEIPT_DOMAIN);
    digest_public_call(&mut digest, call);
    digest_field(&mut digest, NCM_PROVIDER_ID.as_bytes());
    digest_field(
        &mut digest,
        surface_call.operation.capability_id().as_bytes(),
    );
    digest_field(&mut digest, surface_call.namespace.as_str().as_bytes());
    digest.update(surface_call.registration_revision.to_be_bytes());
    digest_field(&mut digest, surface_call.ready_receipt_sha256.as_bytes());
    digest_field(&mut digest, surface_call.request_id.as_bytes());
    digest_field(&mut digest, surface_call.operation_id.as_bytes());
    digest_optional_str(&mut digest, surface_call.idempotency_key.as_deref());
    digest.update(surface_call.expected_state_generation.to_be_bytes());
    digest.update(surface_call.control.deadline_utc_micros().to_be_bytes());
    digest.update(surface_call.control.remaining_millis().to_be_bytes());
    // Every surface dispatch passed a live preflight snapshot. The receipt
    // binds that dispatched state, not later cooperative cancellation.
    digest.update([0]);
    digest_payload(&mut digest, &surface_call.payload);
    digest.update(
        u64::try_from(surface_call.required_capabilities.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for capability in &surface_call.required_capabilities {
        digest_field(&mut digest, capability.as_str().as_bytes());
    }
    digest.update(
        u64::try_from(surface_call.extensions.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for extension in &surface_call.extensions {
        digest_extension(&mut digest, extension);
    }
    digest_reply(&mut digest, reply);
    digest.finalize().into()
}

fn encoded_surface_handshake_request_bytes(
    request: &NcmSurfaceHandshakeRequest,
    control: RequestControl,
) -> u64 {
    let mut total = 8_u64;
    total = total.saturating_add(framed_str_bytes(request.namespace.as_str()));
    total = total.saturating_add(framed_str_bytes(&request.request_id));
    total = total.saturating_add(8);
    for capability in &request.required_capabilities {
        total = total.saturating_add(framed_str_bytes(capability.as_str()));
    }
    total = total.saturating_add(8 * 8);
    total = total.saturating_add(8);
    total = total.saturating_add(8);
    total = total.saturating_add(match control.cancellation {
        tracedecay_memory_provider_api::contract::CancellationState::Live => {
            framed_str_bytes("live")
        }
        tracedecay_memory_provider_api::contract::CancellationState::Cancelled => {
            framed_str_bytes("cancelled")
        }
    });
    total.saturating_add(32)
}

fn encoded_handshake_response_bytes(response: &HandshakeResponse) -> u64 {
    let mut total = encoded_terminal_bytes(&response.terminal);
    total = total.saturating_add(1);
    if let Some(descriptor) = &response.descriptor {
        total = total.saturating_add(encoded_descriptor_bytes(descriptor));
    }
    total = total.saturating_add(encoded_optional_str_bytes(
        response.provider_instance_id.as_deref(),
    ));
    total = total.saturating_add(encoded_optional_str_bytes(
        response.state_namespace.as_deref(),
    ));
    total = total.saturating_add(1);
    if let Some(scope) = &response.accepted_scope {
        total = total.saturating_add(encoded_scope_bytes(scope));
    }
    total = total.saturating_add(1);
    if response.effective_limits.is_some() {
        total = total.saturating_add(8 * 8);
    }
    total = total.saturating_add(encoded_optional_str_bytes(
        response.ready_receipt_sha256.as_deref(),
    ));
    total.saturating_add(encoded_string_vector_bytes(&response.warnings))
}

fn encoded_terminal_bytes(terminal: &TerminalRecord) -> u64 {
    let mut total = framed_str_bytes(terminal.operation().as_wire());
    total = total.saturating_add(framed_str_bytes(terminal.provider_id().as_str()));
    total = total.saturating_add(framed_str_bytes(terminal.terminal_code().as_wire()));
    // Handshake terminals never answer a host mutation, so there is no host
    // idempotency key to reattach to a duplicate effect.
    total = total.saturating_add(encoded_committed_effect_bytes(
        terminal.committed_effect(),
        None,
    ));
    total = total.saturating_add(encoded_fallback_bytes(terminal.fallback()));
    total = total.saturating_add(framed_str_bytes(terminal.operation_id()));
    total = total.saturating_add(framed_str_bytes(terminal.exact_scope_sha256()));
    total.saturating_add(encoded_optional_str_bytes(terminal.diagnostic_id()))
}

fn encoded_descriptor_bytes(descriptor: &ProviderDescriptor) -> u64 {
    let mut total = framed_str_bytes(descriptor.provider_id.as_str());
    total = total.saturating_add(framed_str_bytes(&descriptor.implementation_identity_sha256));
    total = total.saturating_add(framed_str_bytes(&descriptor.state_schema_version));
    total = total.saturating_add(8);
    total = total.saturating_add(2);
    total = total.saturating_add(2);
    total = total.saturating_add(8);
    for capability in &descriptor.capabilities {
        total = total.saturating_add(framed_str_bytes(capability.as_str()));
    }
    total.saturating_add(8 * 8)
}

/// Counts the projected surface envelope, which has no serde wire type: every
/// fixed-width scalar at its wire width and every variable field as an unsigned
/// 64-bit length followed by its bytes, matching the provider-API framing the
/// public envelope is measured with.
fn encoded_surface_request_bytes(call: &NcmSurfaceCall, control: RequestControl) -> u64 {
    let mut total = framed_str_bytes(call.operation.capability_id());
    total = total.saturating_add(framed_str_bytes(call.namespace.as_str()));
    total = total.saturating_add(8);
    total = total.saturating_add(framed_str_bytes(&call.ready_receipt_sha256));
    total = total.saturating_add(framed_str_bytes(&call.request_id));
    total = total.saturating_add(framed_str_bytes(&call.operation_id));
    total = total.saturating_add(8);
    total = total.saturating_add(encoded_optional_str_bytes(call.idempotency_key.as_deref()));
    total = total.saturating_add(8);
    total = total.saturating_add(8);
    total = total.saturating_add(match control.cancellation {
        tracedecay_memory_provider_api::contract::CancellationState::Live => {
            framed_str_bytes("live")
        }
        tracedecay_memory_provider_api::contract::CancellationState::Cancelled => {
            framed_str_bytes("cancelled")
        }
    });
    total = total.saturating_add(encoded_payload_bytes(&call.payload));
    total = total.saturating_add(8);
    for capability in &call.required_capabilities {
        total = total.saturating_add(framed_str_bytes(capability.as_str()));
    }
    total = total.saturating_add(8);
    for extension in &call.extensions {
        total = total.saturating_add(encoded_extension_bytes(extension));
    }
    total
}

fn encoded_response_bytes(call: &ProviderCall, reply: &ProviderReply) -> u64 {
    // Account for the eventual public reply after identity and adapter-side
    // extensions are reattached, not only for the licensed-surface body.
    let mut total = framed_str_bytes(reply.terminal.operation().as_wire());
    total = total.saturating_add(framed_str_bytes(reply.terminal.provider_id().as_str()));
    total = total.saturating_add(framed_str_bytes(reply.terminal.terminal_code().as_wire()));
    total = total.saturating_add(encoded_committed_effect_bytes(
        reply.terminal.committed_effect(),
        call.idempotency_key.as_deref(),
    ));
    total = total.saturating_add(encoded_fallback_bytes(reply.terminal.fallback()));
    total = total.saturating_add(framed_str_bytes(&call.operation_id));
    total = total.saturating_add(framed_str_bytes(&call.exact_scope.exact_scope_sha256()));
    total = total.saturating_add(encoded_optional_str_bytes(reply.terminal.diagnostic_id()));
    total = total.saturating_add(1);
    if let Some(payload) = &reply.payload {
        total = total.saturating_add(encoded_payload_bytes(payload));
    }
    total = total.saturating_add(8);
    for warning in &reply.warnings {
        total = total.saturating_add(framed_str_bytes(warning));
    }
    total = total.saturating_add(8);
    for extension in &call.extensions {
        total = total.saturating_add(encoded_extension_bytes(extension));
    }
    total.saturating_add(8)
}

fn encoded_committed_effect_bytes(
    effect: &CommittedEffectEvidence,
    host_idempotency_key: Option<&str>,
) -> u64 {
    let mut total = framed_str_bytes(effect.state().as_wire());
    total = total.saturating_add(encoded_optional_str_bytes(effect.committed_boundary()));
    total = total.saturating_add(encoded_optional_u64_bytes(effect.state_generation_before()));
    total = total.saturating_add(encoded_optional_u64_bytes(effect.state_generation_after()));
    total = total.saturating_add(encoded_string_vector_bytes(effect.committed_item_refs()));
    total = total.saturating_add(encoded_string_vector_bytes(effect.uncommitted_item_refs()));
    total = total.saturating_add(encoded_optional_str_bytes(effect.provider_receipt_sha256()));
    total = total.saturating_add(encoded_optional_str_bytes(effect.reconciliation_action()));
    total = total.saturating_add(encoded_optional_str_bytes(effect.verification_sha256()));
    let duplicate_of_idempotency_key = if effect.state() == CommittedEffectState::Duplicate {
        host_idempotency_key
    } else {
        effect.duplicate_of_idempotency_key()
    };
    total = total.saturating_add(encoded_optional_str_bytes(duplicate_of_idempotency_key));
    total.saturating_add(encoded_optional_str_bytes(
        effect.duplicate_of_operation_id(),
    ))
}

fn encoded_fallback_bytes(fallback: &FallbackDirective) -> u64 {
    let mut total = framed_str_bytes(fallback.eligibility().as_wire());
    total = total.saturating_add(encoded_optional_str_bytes(
        fallback.source_provider_id().map(OwnedProviderId::as_str),
    ));
    total = total.saturating_add(1);
    if let Some(policy) = fallback.policy() {
        total = total.saturating_add(framed_str_bytes(policy.policy_id()));
        total = total.saturating_add(8);
        total = total.saturating_add(framed_str_bytes(policy.target_provider_id().as_str()));
    }
    total.saturating_add(encoded_optional_str_bytes(fallback.reason()))
}

fn encoded_optional_u64_bytes(value: Option<u64>) -> u64 {
    1_u64.saturating_add(value.map_or(0, |_| 8))
}

fn encoded_string_vector_bytes(values: &[String]) -> u64 {
    values.iter().fold(8_u64, |total, value| {
        total.saturating_add(framed_str_bytes(value))
    })
}

fn encoded_scope_bytes(scope: &OwnedExactScope) -> u64 {
    // Seven length-framed strings and no scalar: the scope carries a resolved
    // digest, not the fixed-width revision counter it replaced.
    let mut total = 0_u64;
    for value in [
        &scope.profile_id,
        &scope.project_id,
        &scope.repository_identity,
        &scope.worktree_identity,
        &scope.branch_identity,
        &scope.agent_session_id,
        &scope.resolved_scope_digest,
    ] {
        total = total.saturating_add(framed_str_bytes(value));
    }
    total
}

fn encoded_payload_bytes(payload: &CanonicalPayload) -> u64 {
    framed_str_bytes(payload.contract_id.as_str())
        .saturating_add(framed_slice_bytes(&payload.bytes))
        .saturating_add(framed_str_bytes(&payload.sha256))
}

fn encoded_extension_bytes(extension: &OwnedOpaqueExtension) -> u64 {
    framed_str_bytes(extension.extension_id.as_str())
        .saturating_add(4)
        .saturating_add(1)
        .saturating_add(framed_str_bytes(&extension.payload_sha256))
        .saturating_add(framed_slice_bytes(&extension.canonical_payload))
}

fn encoded_optional_str_bytes(value: Option<&str>) -> u64 {
    1_u64.saturating_add(value.map_or(0, framed_str_bytes))
}

fn framed_str_bytes(value: &str) -> u64 {
    framed_slice_bytes(value.as_bytes())
}

fn framed_slice_bytes(value: &[u8]) -> u64 {
    8_u64.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
}

fn opaque_surface_id(namespace: &NcmNamespace, kind: &[u8], public_value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(OPAQUE_ID_DOMAIN);
    digest_field(&mut digest, namespace.as_str().as_bytes());
    digest_field(&mut digest, kind);
    digest_field(&mut digest, public_value.as_bytes());
    hex_digest(&digest.finalize())
}

/// Projects host session metadata before the privacy gate. The admitted host
/// relation is the canonical source session; `agent_session_id` is a separately
/// derived checkout binding, so those two strings must not be compared directly.
fn project_observation_sources(
    value: &mut Value,
    call: &ProviderCall,
    namespace: &NcmNamespace,
) -> Option<()> {
    let object = value.as_object_mut()?;
    if call.operation == ProviderOperation::DeleteBySource {
        let Some(source) =
            unique_source_alias(object, &["source", "source_id", "forget_source_key"]).ok()?
        else {
            return Some(());
        };
        for alias in ["source", "source_id", "forget_source_key"] {
            object.remove(alias);
        }
        object.insert(
            "source".to_owned(),
            Value::String(opaque_surface_id(namespace, b"forget-source-key", &source)),
        );
        return Some(());
    }
    if call.operation != ProviderOperation::Observe {
        return Some(());
    }
    if let Some(original) = object
        .get("source_identity")
        .and_then(|value| value.get("original_source"))
    {
        let source_id = common::project_source_id(namespace, original)?;
        let kind = object.get("observation_kind").and_then(Value::as_str)?;
        let contract = object.get("payload_contract").and_then(Value::as_str)?;
        let (key_text, value_text) = common::evidence_text(kind, object.get("canonical_payload")?)?;
        *value = serde_json::json!({"observation_kind": kind, "payload_contract": contract,
            "canonical_payload": {"forget_source_key": source_id,
                "_ncm_key_text": key_text, "_ncm_value_text": value_text}});
        return Some(());
    }
    let source = observe_source_alias(object).ok()?;
    let is_session = object.get("observation_kind").and_then(Value::as_str)
        == Some("session.message_committed.v1");
    let canonical = object.get("canonical_payload").and_then(Value::as_object);
    let has_canonical_shape = canonical.is_some_and(|payload| {
        [
            "version",
            "provider",
            "native_record_kind",
            "stable_record_id",
            "relations",
            "facts",
        ]
        .iter()
        .any(|field| payload.contains_key(*field))
    });
    if is_session && has_canonical_shape {
        if object.get("payload_contract").and_then(Value::as_str)
            != Some("tracedecay.memory.observation.session-message.v1")
        {
            return None;
        }
        let canonical = canonical?;
        if canonical.get("version").and_then(Value::as_u64) != Some(1) {
            return None;
        }
        nonempty_json_string(canonical.get("native_record_kind")?)?;
        nonempty_json_string(canonical.get("provider")?)?;
        nonempty_json_string(canonical.get("stable_record_id")?)?;
        let session = nonempty_json_string(canonical.get("relations")?.get("session_id")?)?;
        let source_key = call.exact_scope.session_forget_source_key(session);
        if source.as_ref().is_some_and(|source| source != &source_key) {
            return None;
        }
        let mut roles = Vec::new();
        let mut contents = Vec::new();
        for fact in canonical.get("facts")?.as_array()? {
            let fact = fact.as_object()?;
            if fact.get("kind").and_then(Value::as_str) != Some("message") {
                continue;
            }
            roles.push(nonempty_json_string(fact.get("role")?)?.to_owned());
            contents.push(message_fact_text(fact.get("content")?)?);
        }
        if contents.is_empty() {
            return None;
        }
        *value = serde_json::json!({
            "observation_kind": "session.message_committed.v1",
            "payload_contract": "tracedecay.memory.observation.session-message.v1",
            "canonical_payload": {
                "role": roles.join("\n"),
                "content": contents.join("\n"),
                "forget_source_key": opaque_surface_id(namespace, b"forget-source-key", &source_key)
            }
        });
        return Some(());
    }
    if let Some(source) = source {
        object.remove("source_identity");
        let opaque = opaque_surface_id(namespace, b"forget-source-key", &source);
        if let Some(canonical) = object
            .get_mut("canonical_payload")
            .and_then(Value::as_object_mut)
        {
            canonical.insert("forget_source_key".to_owned(), Value::String(opaque));
        } else {
            object.insert("source_identity".to_owned(), Value::String(opaque));
        }
    }
    Some(())
}

fn nonempty_json_string(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.trim().is_empty())
}

/// Accepts only message text shapes, never a serialized metadata fallback.
fn message_fact_text(content: &Value) -> Option<String> {
    match content {
        Value::String(_) => Some(nonempty_json_string(content)?.trim().to_owned()),
        Value::Object(object) => Some(nonempty_json_string(object.get("text")?)?.trim().to_owned()),
        Value::Array(items) if !items.is_empty() => {
            let parts = items
                .iter()
                .map(message_fact_text)
                .collect::<Option<Vec<_>>>()?;
            Some(parts.join("\n"))
        }
        _ => None,
    }
}

fn unique_source_alias(
    object: &serde_json::Map<String, Value>,
    aliases: &[&str],
) -> Result<Option<String>, ()> {
    let mut source: Option<String> = None;
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            let candidate = nonempty_json_string(value).ok_or(())?;
            if source.as_ref().is_some_and(|source| source != candidate) {
                return Err(());
            }
            source = Some(candidate.to_owned());
        }
    }
    Ok(source)
}

fn observe_source_alias(object: &serde_json::Map<String, Value>) -> Result<Option<String>, ()> {
    if let Some(original) = object
        .get("source_identity")
        .and_then(|value| value.get("original_source"))
    {
        let source = original
            .pointer("/source/source_key")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(())?;
        return Ok(Some(source.to_owned()));
    }
    let canonical_source = object
        .get("canonical_payload")
        .and_then(Value::as_object)
        .map(|payload| unique_source_alias(payload, &["forget_source_key"]))
        .transpose()?
        .flatten();
    let envelope_source = match object.get("source_identity") {
        None => None,
        Some(Value::Object(source)) => unique_source_alias(
            source,
            &[
                "forget_source_key",
                "source_event_sha256",
                "source_event_id",
            ],
        )?,
        Some(value) => Some(nonempty_json_string(value).ok_or(())?.to_owned()),
    };
    match (canonical_source, envelope_source) {
        (Some(first), Some(second)) if first != second => Err(()),
        (Some(source), _) | (_, Some(source)) => Ok(Some(source)),
        (None, None) => Ok(None),
    }
}

fn remove_exact_scope_identity(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                remove_exact_scope_identity(value);
            }
        }
        Value::Object(values) => {
            values.remove("exact_scope_identity");
            for value in values.values_mut() {
                remove_exact_scope_identity(value);
            }
        }
        _ => {}
    }
}

fn rewrite_caller_identity_fields(
    value: &mut Value,
    call: &ProviderCall,
    opaque: &OpaqueCallerIds,
) -> bool {
    match value {
        Value::Array(values) => values
            .iter_mut()
            .all(|value| rewrite_caller_identity_fields(value, call, opaque)),
        Value::Object(values) => values.iter_mut().all(|(key, value)| match key.as_str() {
            "request_id" | "request_identity" => {
                replace_identity_value(value, &call.request_id, &opaque.request_id)
            }
            "operation_id" => {
                replace_identity_value(value, &call.operation_id, &opaque.operation_id)
            }
            "idempotency_key" => match (&call.idempotency_key, &opaque.idempotency_key) {
                (Some(public), Some(opaque)) => replace_identity_value(value, public, opaque),
                (None, None) => value.is_null(),
                _ => false,
            },
            _ => rewrite_caller_identity_fields(value, call, opaque),
        }),
        _ => true,
    }
}

fn replace_identity_value(value: &mut Value, public: &str, opaque: &str) -> bool {
    let Value::String(current) = value else {
        return false;
    };
    if current != public {
        return false;
    }
    current.clear();
    current.push_str(opaque);
    true
}

fn json_has_exact_scope_identity(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(json_has_exact_scope_identity),
        Value::Object(values) => {
            values.contains_key("exact_scope_identity")
                || values.values().any(json_has_exact_scope_identity)
        }
        _ => false,
    }
}

fn json_contains_scope_component(value: &Value, scope: &OwnedExactScope) -> bool {
    let components = [
        scope.profile_id.as_str(),
        scope.project_id.as_str(),
        scope.repository_identity.as_str(),
        scope.worktree_identity.as_str(),
        scope.branch_identity.as_str(),
        scope.agent_session_id.as_str(),
        scope.resolved_scope_digest.as_str(),
    ];
    json_contains_any(value, &components)
}

fn json_contains_public_caller_id(value: &Value, call: &ProviderCall) -> bool {
    let exact_scope_sha256 = call.exact_scope.exact_scope_sha256();
    if let Some(idempotency_key) = call.idempotency_key.as_deref() {
        json_contains_any(
            value,
            &[
                &call.request_id,
                &call.operation_id,
                idempotency_key,
                &call.ready_receipt_sha256,
                &exact_scope_sha256,
            ],
        )
    } else {
        json_contains_any(
            value,
            &[
                &call.request_id,
                &call.operation_id,
                &call.ready_receipt_sha256,
                &exact_scope_sha256,
            ],
        )
    }
}

fn json_contains_surface_identity(value: &Value, call: &NcmSurfaceCall) -> bool {
    if let Some(idempotency_key) = call.idempotency_key.as_deref() {
        json_contains_any(
            value,
            &[
                call.namespace.as_str(),
                &call.request_id,
                &call.operation_id,
                idempotency_key,
                &call.ready_receipt_sha256,
            ],
        )
    } else {
        json_contains_any(
            value,
            &[
                call.namespace.as_str(),
                &call.request_id,
                &call.operation_id,
                &call.ready_receipt_sha256,
            ],
        )
    }
}

fn serialized_contains_scope_component(bytes: &[u8], scope: &OwnedExactScope) -> bool {
    [
        scope.profile_id.as_bytes(),
        scope.project_id.as_bytes(),
        scope.repository_identity.as_bytes(),
        scope.worktree_identity.as_bytes(),
        scope.branch_identity.as_bytes(),
        scope.agent_session_id.as_bytes(),
        scope.resolved_scope_digest.as_bytes(),
    ]
    .into_iter()
    .any(|component| {
        !component.is_empty()
            && bytes
                .windows(component.len())
                .any(|window| window == component)
    })
}

fn serialized_contains_public_caller_id(bytes: &[u8], call: &ProviderCall) -> bool {
    let contains = |value: &str| {
        !value.is_empty()
            && bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
    };
    contains(&call.request_id)
        || contains(&call.operation_id)
        || call.idempotency_key.as_deref().is_some_and(contains)
}

fn json_contains_any(value: &Value, forbidden: &[&str]) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_any(value, forbidden)),
        Value::Object(values) => values.iter().any(|(key, value)| {
            forbidden
                .iter()
                .any(|item| !item.is_empty() && key.contains(item))
                || json_contains_any(value, forbidden)
        }),
        Value::String(value) => forbidden
            .iter()
            .any(|item| !item.is_empty() && value.contains(item)),
        _ => false,
    }
}

fn surface_forbidden_identities<'a>(
    call: &'a ProviderCall,
    surface_call: &'a NcmSurfaceCall,
) -> Vec<&'a str> {
    let mut forbidden = vec![
        call.exact_scope.profile_id.as_str(),
        call.exact_scope.project_id.as_str(),
        call.exact_scope.repository_identity.as_str(),
        call.exact_scope.worktree_identity.as_str(),
        call.exact_scope.branch_identity.as_str(),
        call.exact_scope.agent_session_id.as_str(),
        call.exact_scope.resolved_scope_digest.as_str(),
        call.request_id.as_str(),
        call.operation_id.as_str(),
        call.ready_receipt_sha256.as_str(),
        surface_call.namespace.as_str(),
        surface_call.request_id.as_str(),
        surface_call.operation_id.as_str(),
        surface_call.ready_receipt_sha256.as_str(),
    ];
    if let Some(value) = call.idempotency_key.as_deref() {
        forbidden.push(value);
    }
    if let Some(value) = surface_call.idempotency_key.as_deref() {
        forbidden.push(value);
    }
    forbidden
}

fn handshake_metadata_is_scope_safe(
    request: &HandshakeRequest,
    surface_request: &NcmSurfaceHandshakeRequest,
    response: &NcmSurfaceHandshakeResponse,
) -> bool {
    let public_scope_digest = request.exact_scope.exact_scope_sha256();
    let forbidden = [
        request.exact_scope.profile_id.as_str(),
        request.exact_scope.project_id.as_str(),
        request.exact_scope.repository_identity.as_str(),
        request.exact_scope.worktree_identity.as_str(),
        request.exact_scope.branch_identity.as_str(),
        request.exact_scope.agent_session_id.as_str(),
        request.exact_scope.resolved_scope_digest.as_str(),
        request.request_id.as_str(),
        public_scope_digest.as_str(),
        surface_request.namespace.as_str(),
        surface_request.request_id.as_str(),
    ];
    response
        .terminal
        .diagnostic_id()
        .is_none_or(|value| !text_contains_any(value, &forbidden))
        && response
            .warnings
            .iter()
            .all(|value| !text_contains_any(value, &forbidden))
}

fn text_contains_any(value: &str, forbidden: &[&str]) -> bool {
    forbidden
        .iter()
        .any(|identity| !identity.is_empty() && value.contains(identity))
}

fn digest_public_call(digest: &mut Sha256, call: &ProviderCall) {
    digest_field(digest, call.operation.as_wire().as_bytes());
    digest_field(digest, call.provider_id.as_str().as_bytes());
    digest.update(call.registration_revision.to_be_bytes());
    digest_field(digest, call.ready_receipt_sha256.as_bytes());
    for component in [
        &call.exact_scope.profile_id,
        &call.exact_scope.project_id,
        &call.exact_scope.repository_identity,
        &call.exact_scope.worktree_identity,
        &call.exact_scope.branch_identity,
        &call.exact_scope.agent_session_id,
        &call.exact_scope.resolved_scope_digest,
    ] {
        digest_field(digest, component.as_bytes());
    }
    digest_field(digest, call.exact_scope.exact_scope_sha256().as_bytes());
    digest_field(digest, call.request_id.as_bytes());
    digest_field(digest, call.operation_id.as_bytes());
    digest.update(call.expected_state_generation.to_be_bytes());
    digest_optional_str(digest, call.idempotency_key.as_deref());
    digest.update(call.control.deadline_utc_micros().to_be_bytes());
    digest.update(call.control.remaining_millis().to_be_bytes());
    // The adapter snapshots a live control immediately before dispatch.
    digest.update([0]);
    digest_payload(digest, &call.payload);
    digest.update(
        u64::try_from(call.required_capabilities.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for capability in &call.required_capabilities {
        digest_field(digest, capability.as_str().as_bytes());
    }
    digest.update(
        u64::try_from(call.extensions.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for extension in &call.extensions {
        digest_extension(digest, extension);
    }
}

fn digest_optional_str(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest_field(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn digest_optional_u64(digest: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn digest_payload(digest: &mut Sha256, payload: &CanonicalPayload) {
    digest_field(digest, payload.contract_id.as_str().as_bytes());
    digest_field(digest, &payload.bytes);
    digest_field(digest, payload.sha256.as_bytes());
}

fn digest_extension(digest: &mut Sha256, extension: &OwnedOpaqueExtension) {
    digest_field(digest, extension.extension_id.as_str().as_bytes());
    digest.update(extension.extension_version.to_be_bytes());
    digest.update([u8::from(extension.required)]);
    digest_field(digest, extension.payload_sha256.as_bytes());
    digest_field(digest, &extension.canonical_payload);
}

fn digest_effect(digest: &mut Sha256, effect: &CommittedEffectEvidence) {
    digest_field(digest, effect.state().as_wire().as_bytes());
    digest_optional_str(digest, effect.committed_boundary());
    digest_optional_u64(digest, effect.state_generation_before());
    digest_optional_u64(digest, effect.state_generation_after());
    digest.update(
        u64::try_from(effect.committed_item_refs().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for item_ref in effect.committed_item_refs() {
        digest_field(digest, item_ref.as_bytes());
    }
    digest.update(
        u64::try_from(effect.uncommitted_item_refs().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for item_ref in effect.uncommitted_item_refs() {
        digest_field(digest, item_ref.as_bytes());
    }
    digest_optional_str(digest, effect.provider_receipt_sha256());
    digest_optional_str(digest, effect.reconciliation_action());
    digest_optional_str(digest, effect.verification_sha256());
}

fn digest_fallback(digest: &mut Sha256, fallback: &FallbackDirective) {
    digest_field(digest, fallback.eligibility().as_wire().as_bytes());
    digest_optional_str(
        digest,
        fallback.source_provider_id().map(OwnedProviderId::as_str),
    );
    match fallback.policy() {
        Some(policy) => {
            digest.update([1]);
            digest_field(digest, policy.policy_id().as_bytes());
            digest.update(policy.policy_revision().to_be_bytes());
            digest_field(digest, policy.target_provider_id().as_str().as_bytes());
        }
        None => digest.update([0]),
    }
    digest_optional_str(digest, fallback.reason());
}

fn digest_reply(digest: &mut Sha256, reply: &ProviderReply) {
    digest_field(digest, reply.terminal.operation().as_wire().as_bytes());
    digest_field(digest, reply.terminal.provider_id().as_str().as_bytes());
    digest_field(digest, reply.terminal.terminal_code().as_wire().as_bytes());
    digest_effect(digest, reply.terminal.committed_effect());
    digest_fallback(digest, reply.terminal.fallback());
    digest_field(digest, reply.terminal.operation_id().as_bytes());
    digest_field(digest, reply.terminal.exact_scope_sha256().as_bytes());
    digest_optional_str(digest, reply.terminal.diagnostic_id());
    match &reply.payload {
        Some(payload) => {
            digest.update([1]);
            digest_payload(digest, payload);
        }
        None => digest.update([0]),
    }
    digest.update(
        u64::try_from(reply.warnings.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for warning in &reply.warnings {
        digest_field(digest, warning.as_bytes());
    }
    digest.update(
        u64::try_from(reply.extensions.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for extension in &reply.extensions {
        digest_extension(digest, extension);
    }
    digest.update(reply.state_generation.to_be_bytes());
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn digest_descriptor_details(digest: &mut Sha256, descriptor: &ProviderDescriptor) {
    digest_field(digest, descriptor.implementation_identity_sha256.as_bytes());
    digest_field(digest, descriptor.state_schema_version.as_bytes());
    digest.update(descriptor.state_generation.to_be_bytes());
    digest.update(descriptor.protocol_major.to_be_bytes());
    digest.update(descriptor.protocol_minor.to_be_bytes());
    digest.update(
        u64::try_from(descriptor.capabilities.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for capability in &descriptor.capabilities {
        digest_field(digest, capability.as_str().as_bytes());
    }
    digest_limits(digest, descriptor.limits);
}

fn digest_limits(digest: &mut Sha256, limits: ProviderLimits) {
    for limit in [
        limits.request_bytes,
        limits.response_bytes,
        limits.observation_batch_items,
        limits.recall_candidates,
        limits.concurrent_operations,
        limits.operation_millis,
        limits.snapshot_bytes,
        limits.inspection_items,
    ] {
        digest.update(limit.to_be_bytes());
    }
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
