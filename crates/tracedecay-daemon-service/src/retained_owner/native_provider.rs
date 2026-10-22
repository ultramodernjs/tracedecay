//! Project-owned Native application port.
//!
//! `tracedecay.native` is upstream `TraceDecay` memory inside the provider host.
//! Native owns no store, schema, score domain, ranking, validity logic,
//! staging, cursor format, or promotion path. Each recall is one call into one
//! upstream authority plus a lossless envelope mapping:
//!
//! * **Fact lane** (objectives `search`, `probe`, `related`, `reason`): the
//!   owner-bound [`MemoryApplication`] read for the project owner and then the
//!   profile owner, with the query built by the same `memory_mapping`
//!   helpers the `tracedecay_fact_store_*` tools use. Every hit is the
//!   upstream `FactSearchHitV1` with its `score_millionths` unchanged.
//!   Recall is a non-mutating provider operation, so it records no retrieval
//!   telemetry, exactly like the `tracedecay_context` memory lane.
//! * **Session lane** (objective `session_history`, explicit only): the
//!   upstream `tracedecay_message_search` temporal query over the mounted
//!   project session retrieval service. The kernel page (order, scores,
//!   freshness, partial/stale outcome, cursor) is carried verbatim.
//!
//! Only current-state recall exists upstream for facts and message search, so
//! `as_of`, `interval`, and `history` answer typed `capability_unsupported`.
//!
//! The provider API is synchronous while the upstream authorities are
//! asynchronous. One bounded actor owns a current-thread runtime for that
//! seam; every wait is bounded by the admitted operation control of the call.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracedecay_contracts::retained_surfaces::{
    FactCommitOwnerV1, FactReadOptionsV1, FactSearchHitV1, FactStoreSearchRequestV1, MemoryScopeV1,
    MessageSearchRequestV1,
};
use tracedecay_contracts::{
    CancellationSignal, CapabilityGrantId, CapabilityGrantSnapshot, Deadline, DisclosureClass,
    RequestContext, RequestId, RetainedSurfaceExecutionErrorV1, now_micros,
};
use tracedecay_domain::{
    ActorId, CursorBindingMismatchV1, FactOwnerV1, UtcMicros, canonical_sha256,
};
use tracedecay_memory_provider_registry::{
    ApiError, CanonicalPayload, CommittedEffectEvidence, FallbackDirective, HandshakeRequest,
    HandshakeResponse, NATIVE_PROVIDER_ID, NativeMemoryApplicationPort, OperationControl,
    OwnedProviderId, OwnedVersionedId, ProviderCall, ProviderDescriptor, ProviderLimits,
    ProviderOperation, ProviderReply, TerminalCode, TerminalRecord,
};
use tracedecay_session_memory::fact_store::DatabaseFactStore;
use tracedecay_session_memory::memory::MemoryApplication;
use tracedecay_session_memory::session::{SessionDataFreshness, SessionTemporalQuery};
use tracedecay_session_runtime::retained::session::message_search_temporal_query;
use tracedecay_session_runtime::session_retrieval::{
    APPLICATION_RETRIEVAL_MAX_BYTES, SessionApplicationRetrievalPortV1, SessionRetrievalPageView,
    SessionRetrievalServiceOutcome, SessionTemporalMetadataView,
};
use tracedecay_sessions::runtime::SessionMessageSearchResult;
use tracedecay_store::{FactReadControl, ProjectMemoryFactSearchKindV1};
use tracedecay_store_runtime::retained_memory::MemoryTargetAccessV1;

use super::memory_mapping;
use super::native_authority::NativeSessionRetrievalMountV1;
use super::open_project_retained_memory_target;
use tracedecay_project::project::TraceDecay;

#[cfg(test)]
#[path = "native_provider_tests.rs"]
mod tests;

pub(super) const IMPLEMENTATION_IDENTITY_SHA256: &str =
    "27127197fad9c8694790cc0b4439e943414a42387a4df120dca21c00fff5fca0";
pub(super) const STATE_SCHEMA_VERSION: &str = "native-application-port-v1";
pub(crate) const PROVIDER_INSTANCE_ID: &str = "tracedecay.native.project";
const STATE_NAMESPACE: &str = "tracedecay.native.project";
const READY_RECEIPT_DOMAIN: &[u8] = b"tracedecay.native.application-ready.v1\0";
const ACTOR_THREAD_NAME: &str = "tracedecay-native-memory-read";
const ACTOR_POLL_MILLIS: u64 = 10;

const PROVIDER_UNAVAILABLE_DIAGNOSTIC: &str = "native.application_port_unavailable";
const CANCELLED_DIAGNOSTIC: &str = "native.recall_cancelled";
const DEADLINE_DIAGNOSTIC: &str = "native.recall_deadline_exceeded";
const RECALL_INVALID_DIAGNOSTIC: &str = "native.recall_request_invalid";
const RECALL_UNSUPPORTED_DIAGNOSTIC: &str = "native.recall_semantics_unsupported";
const RECALL_SCOPE_MISMATCH_DIAGNOSTIC: &str = "native.recall_scope_mismatch";
const RECALL_EXTENSION_DIAGNOSTIC: &str = "native.recall_extension_unsupported";
const RECALL_HISTORY_GRANT_DIAGNOSTIC: &str = "native.recall_history_grant_unsupported";
const RECALL_PROJECTION_DIAGNOSTIC: &str = "native.recall_projection_invalid";
const RECALL_CAPACITY_DIAGNOSTIC: &str = "native.recall_capacity_exceeded";
const RECALL_NOT_AUTHORIZED_DIAGNOSTIC: &str = "native.recall_not_authorized";
const RECALL_RESET_DIAGNOSTIC: &str = "native.recall_reset_required";
const RECALL_CURSOR_STALE_DIAGNOSTIC: &str = "native.recall_cursor_stale";
const HEALTH_CONTRACT_ID: &str = "tracedecay.memory.provider.health.v1";
const RECALL_REQUEST_CONTRACT_ID: &str = "tracedecay.memory.provider.recall.v1";
const RECALL_RESULT_CONTRACT_ID: &str = "tracedecay.memory.recall.query.outcome.v1";
const HEALTH_INVALID_DIAGNOSTIC: &str = "native.health_request_invalid";
const HEALTH_PROJECTION_DIAGNOSTIC: &str = "native.health_projection_invalid";

/// Capabilities the Native port declares. Native observes nothing: upstream
/// has one capture authority (host admission, projection, `lcm_raw_messages`).
const NATIVE_CAPABILITY_IDS: [&str; 2] = ["provider.health.v1", "recall.query.v1"];

/// Objective selecting the explicit session-history lane.
pub(crate) const SESSION_HISTORY_OBJECTIVE: &str = "session_history";

/// Memory class of one upstream fact-search hit.
pub(crate) const FACT_MEMORY_CLASS: &str = "fact";
/// Memory class of one upstream message-search hit.
pub(crate) const SESSION_MESSAGE_MEMORY_CLASS: &str = "session_message";

/// Upstream fact-search score domain: `FactSearchScoresV1.score_millionths`.
const FACT_SCORE_DOMAIN: &str = "tracedecay.memory.fact_search.score_millionths.v1";
/// Upstream message-search score domain: the kernel's normalized score.
const SESSION_SCORE_DOMAIN: &str = "tracedecay.session.message_search.score.v1";

/// Upstream `tracedecay_message_search` page-size ceiling.
const MESSAGE_SEARCH_MAX_LIMIT: u64 = 50;

/// Construction failures for the project-owned Native application port.
#[derive(Debug)]
pub(crate) enum NativeMemoryApplicationPortBuildError {
    /// The fixed provider descriptor could not be assembled or validated.
    Descriptor(ApiError),
    /// The bounded actor runtime could not be constructed.
    Runtime(std::io::Error),
    /// The bounded actor thread could not be started.
    ActorThread(std::io::Error),
    /// The bounded actor construction task could not be joined.
    BlockingJoin(String),
}

impl fmt::Display for NativeMemoryApplicationPortBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(error) => {
                write!(
                    formatter,
                    "Native application-port descriptor is invalid: {error}"
                )
            }
            Self::Runtime(error) => {
                write!(
                    formatter,
                    "Native application-port actor runtime could not start: {error}"
                )
            }
            Self::ActorThread(error) => {
                write!(
                    formatter,
                    "Native application-port actor could not start: {error}"
                )
            }
            Self::BlockingJoin(error) => {
                write!(
                    formatter,
                    "Native application-port construction task could not be joined: {error}"
                )
            }
        }
    }
}

impl Error for NativeMemoryApplicationPortBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::ActorThread(error) => Some(error),
            Self::BlockingJoin(_) => None,
        }
    }
}

/// The project-owned Native application port used by product composition.
pub(crate) struct ProjectNativeMemoryApplicationPort {
    descriptor: ProviderDescriptor,
    actor: NativeReadActor,
}

/// Builds the Native port from an async composition context. Construction
/// only starts the bounded read actor; every durable state remains upstream.
pub(crate) async fn project_native_memory_application_port_off_runtime(
    cg: Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
    project_root: PathBuf,
    session_retrieval: Arc<NativeSessionRetrievalMountV1>,
) -> Result<Arc<dyn NativeMemoryApplicationPort>, NativeMemoryApplicationPortBuildError> {
    tokio::task::spawn_blocking(move || {
        ProjectNativeMemoryApplicationPort::new(cg, project_root, session_retrieval)
            .map(|port| Arc::new(port) as Arc<dyn NativeMemoryApplicationPort>)
    })
    .await
    .map_err(|error| NativeMemoryApplicationPortBuildError::BlockingJoin(error.to_string()))?
}

impl ProjectNativeMemoryApplicationPort {
    /// Creates one actor-backed Native port over the live project graph cell
    /// and the late-bound canonical session retrieval mount.
    pub(crate) fn new(
        cg: Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
        project_root: PathBuf,
        session_retrieval: Arc<NativeSessionRetrievalMountV1>,
    ) -> Result<Self, NativeMemoryApplicationPortBuildError> {
        let descriptor =
            native_descriptor().map_err(NativeMemoryApplicationPortBuildError::Descriptor)?;
        let actor = NativeReadActor::new(cg, project_root, session_retrieval)?;
        Ok(Self { descriptor, actor })
    }

    fn handshake_failure(
        &self,
        request: &HandshakeRequest,
        code: TerminalCode,
        diagnostic: &'static str,
    ) -> HandshakeResponse {
        HandshakeResponse {
            terminal: TerminalRecord::failure_before_dispatch(
                ProviderOperation::Handshake,
                self.descriptor.provider_id.clone(),
                code,
                &request.request_id,
                request_scope_digest(request),
                None,
                diagnostic,
            ),
            descriptor: None,
            provider_instance_id: None,
            state_namespace: None,
            accepted_scope: None,
            effective_limits: None,
            ready_receipt_sha256: None,
            warnings: Vec::new(),
        }
    }

    fn failure_reply(&self, call: &ProviderCall, failure: NativeReadFailure) -> ProviderReply {
        let (code, diagnostic) = failure.terminal();
        ProviderReply {
            terminal: terminal_for_call(call, code, Some(diagnostic)),
            payload: None,
            warnings: match failure {
                NativeReadFailure::RecallCursorRefused(mismatch) => vec![mismatch.message()],
                _ => Vec::new(),
            },
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }
}

impl NativeMemoryApplicationPort for ProjectNativeMemoryApplicationPort {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        if request.validate().is_err() {
            return self.handshake_failure(
                request,
                TerminalCode::InvalidRequest,
                "native.handshake_request_invalid",
            );
        }
        if request.provider_id.as_str() != NATIVE_PROVIDER_ID {
            return self.handshake_failure(
                request,
                TerminalCode::InvalidRequest,
                "native.provider_id_mismatch",
            );
        }
        if request
            .required_capabilities
            .iter()
            .any(|capability| !self.descriptor.supports(capability.as_str()))
        {
            return self.handshake_failure(
                request,
                TerminalCode::CapabilityUnsupported,
                "native.required_capability_missing",
            );
        }
        let effective_limits = request.host_limits.minimum(self.descriptor.limits);
        if let Err(code) = request.control.snapshot() {
            return self.handshake_failure(
                request,
                code,
                "native.handshake_request_control_terminal",
            );
        }
        let terminal = match TerminalRecord::new(
            ProviderOperation::Handshake,
            self.descriptor.provider_id.clone(),
            TerminalCode::Success,
            CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
            FallbackDirective::forbidden(),
            request.request_id.clone(),
            request.exact_scope.exact_scope_sha256(),
            None,
        ) {
            Ok(terminal) => terminal,
            Err(_) => {
                return self.handshake_failure(
                    request,
                    TerminalCode::ContractViolation,
                    "native.handshake_terminal_invalid",
                );
            }
        };
        HandshakeResponse {
            terminal,
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some(PROVIDER_INSTANCE_ID.to_owned()),
            state_namespace: Some(STATE_NAMESPACE.to_owned()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(effective_limits),
            ready_receipt_sha256: Some(ready_receipt(request, effective_limits)),
            warnings: Vec::new(),
        }
    }

    fn health(&self, call: &ProviderCall) -> ProviderReply {
        if let Err(failure) = control_failure(&call.control) {
            return self.failure_reply(call, failure);
        }
        if call.validate().is_err()
            || call.operation != ProviderOperation::Health
            || call.provider_id.as_str() != NATIVE_PROVIDER_ID
            || call.payload.contract_id.as_str() != HEALTH_CONTRACT_ID
        {
            return self.failure_reply(call, NativeReadFailure::HealthInvalidRequest);
        }
        let payload = match native_health_payload(call, self.descriptor.limits) {
            Ok(payload) => payload,
            Err(failure) => return self.failure_reply(call, failure),
        };
        ProviderReply {
            terminal: terminal_for_call(call, TerminalCode::Success, None),
            payload: Some(payload),
            warnings: Vec::new(),
            extensions: call.extensions.clone(),
            state_generation: call.expected_state_generation,
        }
    }

    fn recall(&self, call: &ProviderCall) -> ProviderReply {
        if let Err(failure) = control_failure(&call.control) {
            return self.failure_reply(call, failure);
        }
        if call.validate().is_err()
            || call.operation != ProviderOperation::Recall
            || call.provider_id.as_str() != NATIVE_PROVIDER_ID
            || call.payload.contract_id.as_str() != RECALL_REQUEST_CONTRACT_ID
        {
            return self.failure_reply(call, NativeReadFailure::RecallInvalidRequest);
        }
        let request = match parse_native_recall_request(call) {
            Ok(request) => request,
            Err(failure) => return self.failure_reply(call, failure),
        };
        let lane = match NativeRecallLane::select(&request) {
            Ok(lane) => lane,
            Err(failure) => return self.failure_reply(call, failure),
        };
        match self.actor.dispatch(call.clone(), request, lane) {
            Ok(reply) => reply,
            Err(failure) => self.failure_reply(call, failure),
        }
    }
}

fn native_descriptor() -> Result<ProviderDescriptor, ApiError> {
    let provider_id = OwnedProviderId::new(NATIVE_PROVIDER_ID)?;
    let capabilities = NATIVE_CAPABILITY_IDS
        .into_iter()
        .map(OwnedVersionedId::new)
        .collect::<Result<Vec<_>, _>>()?;
    ProviderDescriptor::new(
        provider_id,
        IMPLEMENTATION_IDENTITY_SHA256,
        STATE_SCHEMA_VERSION,
        0,
        capabilities,
        native_provider_limits(),
    )
}

/// Declared Native ceilings. They are contract declarations negotiated at
/// handshake; every actual wait is bounded by the admitted call control.
pub(crate) fn native_provider_limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 4_096,
        // One upstream message-search page is bounded by the admitted
        // application retrieval ceiling; the envelope around it stays well
        // inside four times that ceiling.
        response_bytes: APPLICATION_RETRIEVAL_MAX_BYTES * 4,
        observation_batch_items: 16,
        recall_candidates: MESSAGE_SEARCH_MAX_LIMIT,
        concurrent_operations: 4,
        operation_millis: 1_000,
        snapshot_bytes: 65_536,
        inspection_items: 64,
    }
}

fn request_scope_digest(request: &HandshakeRequest) -> String {
    if request.exact_scope.validate().is_ok() {
        request.exact_scope.exact_scope_sha256()
    } else {
        String::new()
    }
}

fn call_scope_digest(call: &ProviderCall) -> String {
    if call.exact_scope.validate().is_ok() {
        call.exact_scope.exact_scope_sha256()
    } else {
        String::new()
    }
}

fn terminal_for_call(
    call: &ProviderCall,
    code: TerminalCode,
    diagnostic: Option<&'static str>,
) -> TerminalRecord {
    if matches!(
        code,
        TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
    ) {
        if let Ok(terminal) = TerminalRecord::new(
            call.operation,
            call.provider_id.clone(),
            code,
            CommittedEffectEvidence::none(Some(call.expected_state_generation)),
            FallbackDirective::forbidden(),
            call.operation_id.clone(),
            call_scope_digest(call),
            None,
        ) {
            return terminal;
        }
        return TerminalRecord::failure_before_dispatch(
            call.operation,
            call.provider_id.clone(),
            TerminalCode::InternalFailure,
            &call.operation_id,
            call_scope_digest(call),
            Some(call.expected_state_generation),
            "native.success_terminal_invalid",
        );
    }
    TerminalRecord::failure_before_dispatch(
        call.operation,
        call.provider_id.clone(),
        code,
        &call.operation_id,
        call_scope_digest(call),
        Some(call.expected_state_generation),
        diagnostic.unwrap_or(PROVIDER_UNAVAILABLE_DIAGNOSTIC),
    )
}

fn ready_receipt(request: &HandshakeRequest, effective_limits: ProviderLimits) -> String {
    let mut digest = Sha256::new();
    digest.update(READY_RECEIPT_DOMAIN);
    digest.update(request.challenge_nonce);
    digest.update(request.registration_revision.to_be_bytes());
    digest.update(request.exact_scope.exact_scope_sha256().as_bytes());
    digest.update(request.request_id.as_bytes());
    digest.update(IMPLEMENTATION_IDENTITY_SHA256.as_bytes());
    digest.update(effective_limits.request_bytes.to_be_bytes());
    digest.update(effective_limits.response_bytes.to_be_bytes());
    digest.update(effective_limits.observation_batch_items.to_be_bytes());
    digest.update(effective_limits.recall_candidates.to_be_bytes());
    digest.update(effective_limits.concurrent_operations.to_be_bytes());
    digest.update(effective_limits.operation_millis.to_be_bytes());
    digest.update(effective_limits.snapshot_bytes.to_be_bytes());
    digest.update(effective_limits.inspection_items.to_be_bytes());
    hex::encode(digest.finalize())
}

/// Builds the operation-specific health result consumed by the provider
/// control projection. The provider call carries the host's common request
/// header, but that header is not itself a health result; echoing it would
/// make a provider appear healthy while leaving readiness identities absent.
fn native_health_payload(
    call: &ProviderCall,
    effective_limits: ProviderLimits,
) -> Result<CanonicalPayload, NativeReadFailure> {
    let request: Value = serde_json::from_slice(&call.payload.bytes)
        .map_err(|_| NativeReadFailure::HealthInvalidRequest)?;
    let request_object = request
        .as_object()
        .ok_or(NativeReadFailure::HealthInvalidRequest)?;
    if !request_object
        .get("requested_checks")
        .is_some_and(Value::is_array)
    {
        return Err(NativeReadFailure::HealthInvalidRequest);
    }

    let state_digest = sha256_hex(
        format!(
            "tracedecay.native.health-state.v1\0{}\0{}\0{}",
            call.exact_scope.exact_scope_sha256(),
            call.ready_receipt_sha256,
            call.expected_state_generation,
        )
        .as_bytes(),
    );
    let state_identity_digest = serde_json::to_vec(&serde_json::json!([
        state_digest,
        STATE_SCHEMA_VERSION,
        call.expected_state_generation,
    ]))
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| NativeReadFailure::HealthProjectionInvalid)?;
    let capability_states = NATIVE_CAPABILITY_IDS
        .into_iter()
        .map(|capability_id| {
            serde_json::json!({
                "capability_id": capability_id,
                "state": "available",
            })
        })
        .collect::<Vec<_>>();
    let response = serde_json::json!({
        "provider_id": call.provider_id.as_str(),
        "provider_instance_id": PROVIDER_INSTANCE_ID,
        "implementation_identity_digest": IMPLEMENTATION_IDENTITY_SHA256,
        "state_identity_digest": state_identity_digest,
        "state_generation": call.expected_state_generation,
        "scope_digest": call.exact_scope.exact_scope_sha256(),
        "readiness": "ready",
        "capability_states": capability_states,
        "effective_limits_digest": native_limits_digest(effective_limits),
        "backlog": 0,
        "recovery_state": "ready",
        "warnings": [],
    });
    let bytes =
        serde_json::to_vec(&response).map_err(|_| NativeReadFailure::HealthProjectionInvalid)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > effective_limits.response_bytes {
        return Err(NativeReadFailure::HealthProjectionInvalid);
    }
    CanonicalPayload::new(
        OwnedVersionedId::new(HEALTH_CONTRACT_ID)
            .map_err(|_| NativeReadFailure::HealthProjectionInvalid)?,
        bytes.clone(),
        sha256_hex(&bytes),
    )
    .map_err(|_| NativeReadFailure::HealthProjectionInvalid)
}

fn native_limits_digest(limits: ProviderLimits) -> String {
    let mut digest = Sha256::new();
    for value in [
        limits.request_bytes,
        limits.response_bytes,
        limits.observation_batch_items,
        limits.recall_candidates,
        limits.concurrent_operations,
        limits.operation_millis,
        limits.snapshot_bytes,
        limits.inspection_items,
    ] {
        digest.update(value.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

/// The strict, provider-neutral recall request envelope. Native reads the
/// objective, query, temporal mode, cursor, and candidate budget; the host's
/// admission owns exclusions and every per-candidate budget after the reply.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecallRequestV1 {
    provider_id: String,
    registration_revision: u64,
    ready_receipt_digest: String,
    exact_scope_identity: NativeRecallScopeV1,
    request_identity: String,
    objective: String,
    query: String,
    temporal_query: NativeRecallTemporalQueryV1,
    budgets: NativeRecallBudgetsV1,
    exclusions: NativeRecallExclusionsV1,
    /// Canonical history grants authorize observation-sourced candidates.
    /// Native observes nothing, so a present grant is refused, never used.
    #[serde(default)]
    history_grant: Option<Value>,
    required_capabilities: Vec<String>,
    policy_revision: u64,
    extensions: Vec<NativeRecallExtensionV1>,
    deadline: Value,
    cancellation: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativeRecallScopeV1 {
    profile_id: String,
    project_id: String,
    repository_identity: String,
    worktree_identity: String,
    branch_identity: String,
    agent_session_id: String,
    resolved_scope_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecallTemporalQueryV1 {
    mode: String,
    evaluation_time: String,
    as_of: Value,
    interval_start: Value,
    interval_end: Value,
    /// Opaque upstream message-search continuation, passed back unchanged.
    #[serde(default)]
    cursor: Option<String>,
    include_superseded: bool,
    include_revoked: bool,
    unknown_validity_policy: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecallBudgetsV1 {
    maximum_candidates: u64,
    maximum_candidate_content_bytes: u64,
    maximum_total_content_bytes: u64,
    maximum_source_refs_per_candidate: u64,
    maximum_trace_refs_per_candidate: u64,
    maximum_warnings: u64,
    maximum_extensions_per_candidate: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecallExclusionsV1 {
    stable_memory_refs: Vec<String>,
    candidate_ids: Vec<String>,
    source_refs: Vec<String>,
    trace_refs: Vec<String>,
    observation_ids: Vec<String>,
    content_sha256: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecallExtensionV1 {
    extension_id: String,
    extension_version: u32,
    criticality: String,
    canonical_payload: Value,
    payload_sha256: String,
}

/// One upstream read selected by the recall objective. The two lanes are
/// never fused: a call answers facts or session messages, never a blend.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NativeRecallLane {
    /// Upstream fact read of one `ProjectMemoryFactSearchKindV1`.
    Facts(NativeFactRead),
    /// Upstream `tracedecay_message_search`.
    SessionHistory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NativeFactRead {
    Search,
    Probe,
    Related,
    Reason { entities: Vec<String> },
}

impl NativeRecallLane {
    fn select(request: &NativeRecallRequestV1) -> Result<Self, NativeReadFailure> {
        // Fact search and message search are current-state reads upstream.
        // Every other mode is refused rather than served by a different read.
        if request.temporal_query.mode != "current"
            || request.temporal_query.include_superseded
            || request.temporal_query.include_revoked
        {
            return Err(NativeReadFailure::RecallUnsupported);
        }
        let facts = |read| {
            // Fact recall exposes no provider cursor; Native owns no cursor
            // format that could span the project and profile owners.
            if request.temporal_query.cursor.is_some() {
                Err(NativeReadFailure::RecallUnsupported)
            } else {
                Ok(Self::Facts(read))
            }
        };
        match request.objective.as_str() {
            "search" => facts(NativeFactRead::Search),
            "probe" => facts(NativeFactRead::Probe),
            "related" => facts(NativeFactRead::Related),
            "reason" => {
                let entities = request
                    .query
                    .split(',')
                    .map(str::trim)
                    .filter(|entity| !entity.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let entities = memory_mapping::normalize_reason_entities(&entities)
                    .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
                facts(NativeFactRead::Reason { entities })
            }
            SESSION_HISTORY_OBJECTIVE => Ok(Self::SessionHistory),
            _ => Err(NativeReadFailure::RecallUnsupported),
        }
    }
}

fn parse_native_recall_request(
    call: &ProviderCall,
) -> Result<NativeRecallRequestV1, NativeReadFailure> {
    let request = serde_json::from_slice::<NativeRecallRequestV1>(&call.payload.bytes)
        .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    if request.provider_id != NATIVE_PROVIDER_ID
        || request.registration_revision != call.registration_revision
        || request.ready_receipt_digest != call.ready_receipt_sha256
        || request.request_identity != call.request_id
        || request.required_capabilities.len() != 1
        || request.required_capabilities[0] != "recall.query.v1"
        || request.policy_revision == 0
    {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    if request.exact_scope_identity != native_recall_scope(call) {
        return Err(NativeReadFailure::RecallScopeMismatch);
    }
    if request.history_grant.is_some() || call.history_grant().is_some() {
        return Err(NativeReadFailure::RecallHistoryGrantUnsupported);
    }
    validate_recall_text(&request.objective, 8_192)
        .map_err(|()| NativeReadFailure::RecallInvalidRequest)?;
    validate_recall_text(&request.query, 32_768)
        .map_err(|()| NativeReadFailure::RecallInvalidRequest)?;
    validate_recall_temporal(&request.temporal_query)?;
    validate_recall_budgets(&request.budgets)?;
    validate_recall_exclusions(&request.exclusions)?;
    validate_recall_extensions(&request.extensions)?;
    validate_recall_control(call, &request.deadline, &request.cancellation)?;
    Ok(request)
}

fn native_recall_scope(call: &ProviderCall) -> NativeRecallScopeV1 {
    NativeRecallScopeV1 {
        profile_id: call.exact_scope.profile_id.clone(),
        project_id: call.exact_scope.project_id.clone(),
        repository_identity: call.exact_scope.repository_identity.clone(),
        worktree_identity: call.exact_scope.worktree_identity.clone(),
        branch_identity: call.exact_scope.branch_identity.clone(),
        agent_session_id: call.exact_scope.agent_session_id.clone(),
        resolved_scope_digest: call.exact_scope.resolved_scope_digest.clone(),
    }
}

fn validate_recall_text(value: &str, maximum_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

/// Validates the wire shape of every temporal mode. Supported semantics are
/// decided separately by [`NativeRecallLane::select`].
fn validate_recall_temporal(
    temporal: &NativeRecallTemporalQueryV1,
) -> Result<(), NativeReadFailure> {
    let Some(evaluation_micros) = parse_rfc3339_micros(&temporal.evaluation_time) else {
        return Err(NativeReadFailure::RecallInvalidRequest);
    };
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_micros()).ok())
        .unwrap_or(i64::MAX);
    if evaluation_micros > now_micros {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    if let Some(cursor) = temporal.cursor.as_deref() {
        validate_recall_text(cursor, 8_192)
            .map_err(|()| NativeReadFailure::RecallInvalidRequest)?;
    }
    match temporal.mode.as_str() {
        "current" | "history" => {
            if !temporal.as_of.is_null()
                || !temporal.interval_start.is_null()
                || !temporal.interval_end.is_null()
            {
                return Err(NativeReadFailure::RecallInvalidRequest);
            }
        }
        "as_of" => {
            let Some(as_of) = temporal.as_of.as_str().and_then(parse_rfc3339_micros) else {
                return Err(NativeReadFailure::RecallInvalidRequest);
            };
            if as_of > evaluation_micros
                || !temporal.interval_start.is_null()
                || !temporal.interval_end.is_null()
            {
                return Err(NativeReadFailure::RecallInvalidRequest);
            }
        }
        "interval" => {
            let Some(start) = temporal
                .interval_start
                .as_str()
                .and_then(parse_rfc3339_micros)
            else {
                return Err(NativeReadFailure::RecallInvalidRequest);
            };
            let Some(end) = temporal
                .interval_end
                .as_str()
                .and_then(parse_rfc3339_micros)
            else {
                return Err(NativeReadFailure::RecallInvalidRequest);
            };
            if start >= end || !temporal.as_of.is_null() {
                return Err(NativeReadFailure::RecallInvalidRequest);
            }
        }
        _ => return Err(NativeReadFailure::RecallInvalidRequest),
    }
    if !matches!(
        temporal.unknown_validity_policy.as_str(),
        "exclude" | "degrade" | "allow_with_warning"
    ) {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    Ok(())
}

fn parse_rfc3339_micros(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let year = parse_digits(&bytes[0..4])?;
    let month = parse_digits(&bytes[5..7])?;
    let day = parse_digits(&bytes[8..10])?;
    let hour = parse_digits(&bytes[11..13])?;
    let minute = parse_digits(&bytes[14..16])?;
    let second = parse_digits(&bytes[17..19])?;
    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
        || day == 0
        || day > days_in_month(year, month)
    {
        return None;
    }
    let mut index = 19;
    let mut micros = 0_i64;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        let fraction = bytes.get(start..index)?;
        if fraction.is_empty() || fraction.len() > 9 {
            return None;
        }
        let mut value = parse_digits(fraction)?;
        for _ in fraction.len()..6 {
            value = value.checked_mul(10)?;
        }
        for _ in 6..fraction.len() {
            value /= 10;
        }
        micros = i64::from(value);
    }
    let offset_minutes = match bytes.get(index..) {
        Some([b'Z']) => 0_i64,
        Some(
            [
                sign,
                hour_tz_tens,
                hour_tz_ones,
                b':',
                minute_tz_tens,
                minute_tz_ones,
            ],
        ) if *sign == b'+' || *sign == b'-' => {
            if !hour_tz_tens.is_ascii_digit()
                || !hour_tz_ones.is_ascii_digit()
                || !minute_tz_tens.is_ascii_digit()
                || !minute_tz_ones.is_ascii_digit()
            {
                return None;
            }
            let hour_tz = i64::from(*hour_tz_tens - b'0') * 10 + i64::from(*hour_tz_ones - b'0');
            let minute_tz =
                i64::from(*minute_tz_tens - b'0') * 10 + i64::from(*minute_tz_ones - b'0');
            if hour_tz > 23 || minute_tz > 59 {
                return None;
            }
            let signed = hour_tz.checked_mul(60)?.checked_add(minute_tz)?;
            if *sign == b'+' { signed } else { -signed }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour).checked_mul(3_600)?)?
        .checked_add(i64::from(minute).checked_mul(60)?)?
        .checked_add(i64::from(second))?
        .checked_sub(offset_minutes.checked_mul(60)?)?;
    seconds.checked_mul(1_000_000)?.checked_add(micros)
}

fn parse_digits(value: &[u8]) -> Option<u32> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    value.iter().try_fold(0_u32, |accumulator, byte| {
        accumulator
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || year.is_multiple_of(4) && !year.is_multiple_of(100) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: u32, month: u32, day: u32) -> Option<i64> {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn validate_recall_budgets(budgets: &NativeRecallBudgetsV1) -> Result<(), NativeReadFailure> {
    if [
        budgets.maximum_candidates,
        budgets.maximum_candidate_content_bytes,
        budgets.maximum_total_content_bytes,
        budgets.maximum_source_refs_per_candidate,
        budgets.maximum_trace_refs_per_candidate,
        budgets.maximum_warnings,
        budgets.maximum_extensions_per_candidate,
    ]
    .into_iter()
    .any(|value| value == 0)
    {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    Ok(())
}

fn validate_recall_exclusions(
    exclusions: &NativeRecallExclusionsV1,
) -> Result<(), NativeReadFailure> {
    for values in [
        &exclusions.stable_memory_refs,
        &exclusions.candidate_ids,
        &exclusions.source_refs,
        &exclusions.trace_refs,
        &exclusions.observation_ids,
        &exclusions.content_sha256,
    ] {
        if values.len() > 1_024 {
            return Err(NativeReadFailure::RecallInvalidRequest);
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value)) {
            return Err(NativeReadFailure::RecallInvalidRequest);
        }
    }
    Ok(())
}

fn validate_recall_extensions(
    extensions: &[NativeRecallExtensionV1],
) -> Result<(), NativeReadFailure> {
    if extensions.len() > 16 {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    let mut ids = BTreeSet::new();
    for extension in extensions {
        if extension.extension_version == 0
            || extension.extension_id.is_empty()
            || extension.criticality != "optional" && extension.criticality != "required"
            || !ids.insert((&extension.extension_id, extension.extension_version))
        {
            return Err(NativeReadFailure::RecallInvalidRequest);
        }
        let bytes = serde_json::to_vec(&extension.canonical_payload)
            .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
        if bytes.is_empty()
            || bytes.len() > 131_072
            || sha256_hex(&bytes) != extension.payload_sha256
        {
            return Err(NativeReadFailure::RecallInvalidRequest);
        }
        if extension.criticality == "required" {
            return Err(NativeReadFailure::RecallExtensionUnsupported);
        }
    }
    Ok(())
}

fn validate_recall_control(
    call: &ProviderCall,
    deadline: &Value,
    cancellation: &Value,
) -> Result<(), NativeReadFailure> {
    let deadline = deadline
        .as_object()
        .ok_or(NativeReadFailure::RecallInvalidRequest)?;
    if deadline.len() != 2
        || deadline
            .keys()
            .any(|key| key != "deadline_utc_micros" && key != "remaining_millis")
    {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    let deadline_utc_micros = deadline
        .get("deadline_utc_micros")
        .and_then(Value::as_i64)
        .ok_or(NativeReadFailure::RecallInvalidRequest)?;
    let remaining_millis = deadline
        .get("remaining_millis")
        .and_then(Value::as_u64)
        .ok_or(NativeReadFailure::RecallInvalidRequest)?;
    if deadline_utc_micros != call.control.deadline_utc_micros()
        || remaining_millis > call.control.remaining_millis()
    {
        return Err(NativeReadFailure::RecallInvalidRequest);
    }
    match cancellation {
        Value::String(state) if state == "live" => Ok(()),
        Value::Object(state)
            if state.len() == 1
                && state.get("state") == Some(&Value::String("live".to_owned())) =>
        {
            Ok(())
        }
        _ => Err(NativeReadFailure::RecallInvalidRequest),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn control_failure(control: &OperationControl) -> Result<(), NativeReadFailure> {
    control.snapshot().map(|_| ()).map_err(|code| match code {
        TerminalCode::Cancelled => NativeReadFailure::Cancelled,
        TerminalCode::DeadlineExceeded => NativeReadFailure::DeadlineExceeded,
        _ => NativeReadFailure::ProviderUnavailable,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeReadFailure {
    ProviderUnavailable,
    HealthInvalidRequest,
    HealthProjectionInvalid,
    Cancelled,
    DeadlineExceeded,
    RecallInvalidRequest,
    RecallUnsupported,
    RecallScopeMismatch,
    RecallExtensionUnsupported,
    RecallHistoryGrantUnsupported,
    RecallProjectionInvalid,
    RecallCapacityExceeded,
    RecallNotAuthorized,
    RecallResetRequired,
    RecallCursorStale,
    RecallCursorRefused(CursorBindingMismatchV1),
}

impl NativeReadFailure {
    fn terminal(self) -> (TerminalCode, &'static str) {
        match self {
            Self::ProviderUnavailable => (
                TerminalCode::ProviderUnavailable,
                PROVIDER_UNAVAILABLE_DIAGNOSTIC,
            ),
            Self::HealthInvalidRequest => (TerminalCode::InvalidRequest, HEALTH_INVALID_DIAGNOSTIC),
            Self::HealthProjectionInvalid => (
                TerminalCode::ContractViolation,
                HEALTH_PROJECTION_DIAGNOSTIC,
            ),
            Self::Cancelled => (TerminalCode::Cancelled, CANCELLED_DIAGNOSTIC),
            Self::DeadlineExceeded => (TerminalCode::DeadlineExceeded, DEADLINE_DIAGNOSTIC),
            Self::RecallInvalidRequest => (TerminalCode::InvalidRequest, RECALL_INVALID_DIAGNOSTIC),
            Self::RecallUnsupported => (
                TerminalCode::CapabilityUnsupported,
                RECALL_UNSUPPORTED_DIAGNOSTIC,
            ),
            Self::RecallScopeMismatch => (
                TerminalCode::ScopeMismatch,
                RECALL_SCOPE_MISMATCH_DIAGNOSTIC,
            ),
            Self::RecallExtensionUnsupported => (
                TerminalCode::CapabilityUnsupported,
                RECALL_EXTENSION_DIAGNOSTIC,
            ),
            Self::RecallHistoryGrantUnsupported => (
                TerminalCode::CapabilityUnsupported,
                RECALL_HISTORY_GRANT_DIAGNOSTIC,
            ),
            Self::RecallProjectionInvalid => (
                TerminalCode::ContractViolation,
                RECALL_PROJECTION_DIAGNOSTIC,
            ),
            Self::RecallCapacityExceeded => {
                (TerminalCode::CapacityExceeded, RECALL_CAPACITY_DIAGNOSTIC)
            }
            Self::RecallNotAuthorized => {
                (TerminalCode::Unauthorized, RECALL_NOT_AUTHORIZED_DIAGNOSTIC)
            }
            Self::RecallResetRequired => (TerminalCode::ResetRequired, RECALL_RESET_DIAGNOSTIC),
            Self::RecallCursorStale => {
                (TerminalCode::StaleIdentity, RECALL_CURSOR_STALE_DIAGNOSTIC)
            }
            Self::RecallCursorRefused(mismatch) => (TerminalCode::InvalidRequest, mismatch.code()),
        }
    }
}

type NativeRecallOutcome = Result<ProviderReply, NativeReadFailure>;

struct NativeRecallCommand {
    call: ProviderCall,
    request: NativeRecallRequestV1,
    lane: NativeRecallLane,
    reply: SyncSender<NativeRecallOutcome>,
}

struct NativeReadActor {
    sender: Mutex<Option<SyncSender<NativeRecallCommand>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl NativeReadActor {
    fn new(
        cg: Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
        project_root: PathBuf,
        session_retrieval: Arc<NativeSessionRetrievalMountV1>,
    ) -> Result<Self, NativeMemoryApplicationPortBuildError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(NativeMemoryApplicationPortBuildError::Runtime)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name(ACTOR_THREAD_NAME.to_owned())
            .spawn(move || {
                native_read_actor_main(receiver, cg, project_root, runtime, session_retrieval);
            })
            .map_err(NativeMemoryApplicationPortBuildError::ActorThread)?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            join: Mutex::new(Some(join)),
        })
    }

    fn dispatch(
        &self,
        call: ProviderCall,
        request: NativeRecallRequestV1,
        lane: NativeRecallLane,
    ) -> NativeRecallOutcome {
        let (reply, receiver) = mpsc::sync_channel(1);
        let control = call.control.clone();
        let command = NativeRecallCommand {
            call,
            request,
            lane,
            reply,
        };
        let sender = match self.sender.lock() {
            Ok(sender) => sender.as_ref().cloned(),
            Err(_) => None,
        };
        let Some(sender) = sender else {
            return Err(NativeReadFailure::ProviderUnavailable);
        };
        match sender.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                return Err(NativeReadFailure::ProviderUnavailable);
            }
        }
        receive_actor_reply(&control, receiver)?
    }
}

/// Waits for the actor under the admitted call control only.
fn receive_actor_reply<T>(
    control: &OperationControl,
    receiver: mpsc::Receiver<T>,
) -> Result<T, NativeReadFailure> {
    loop {
        let snapshot = control.snapshot().map_err(|code| match code {
            TerminalCode::Cancelled => NativeReadFailure::Cancelled,
            TerminalCode::DeadlineExceeded => NativeReadFailure::DeadlineExceeded,
            _ => NativeReadFailure::ProviderUnavailable,
        })?;
        let wait_millis = snapshot.remaining_millis.clamp(1, ACTOR_POLL_MILLIS);
        match receiver.recv_timeout(Duration::from_millis(wait_millis)) {
            Ok(outcome) => return Ok(outcome),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(NativeReadFailure::ProviderUnavailable);
            }
        }
    }
}

impl Drop for NativeReadActor {
    fn drop(&mut self) {
        let sender = match self.sender.lock() {
            Ok(mut sender) => sender.take(),
            Err(error) => error.into_inner().take(),
        };
        drop(sender);
        let join = match self.join.lock() {
            Ok(mut join) => join.take(),
            Err(error) => error.into_inner().take(),
        };
        if let Some(join) = join {
            let _ = join.join();
        }
    }
}

fn native_read_actor_main(
    receiver: mpsc::Receiver<NativeRecallCommand>,
    cg: Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
    project_root: PathBuf,
    runtime: tokio::runtime::Runtime,
    session_retrieval: Arc<NativeSessionRetrievalMountV1>,
) {
    while let Ok(command) = receiver.recv() {
        let NativeRecallCommand {
            call,
            request,
            lane,
            reply,
        } = command;
        let outcome = recall_with_runtime(
            &runtime,
            &cg,
            &project_root,
            &session_retrieval,
            &call,
            &request,
            &lane,
        );
        let _ = reply.send(outcome);
    }
}

/// Runs one upstream read inside the admitted call deadline. No private
/// timeout exists: the remaining budget of the call is the only bound.
fn recall_with_runtime(
    runtime: &tokio::runtime::Runtime,
    cg: &Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
    project_root: &Path,
    session_retrieval: &NativeSessionRetrievalMountV1,
    call: &ProviderCall,
    request: &NativeRecallRequestV1,
    lane: &NativeRecallLane,
) -> NativeRecallOutcome {
    let snapshot = call.control.snapshot().map_err(|code| match code {
        TerminalCode::Cancelled => NativeReadFailure::Cancelled,
        TerminalCode::DeadlineExceeded => NativeReadFailure::DeadlineExceeded,
        _ => NativeReadFailure::ProviderUnavailable,
    })?;
    let budget = Duration::from_millis(snapshot.remaining_millis);
    runtime.block_on(async {
        let read = async {
            match lane {
                NativeRecallLane::Facts(read) => {
                    recall_facts(cg, project_root, call, request, read).await
                }
                NativeRecallLane::SessionHistory => {
                    recall_session_history(session_retrieval, call, request).await
                }
            }
        };
        match tokio::time::timeout(budget, read).await {
            Ok(outcome) => outcome,
            Err(_) => Err(NativeReadFailure::DeadlineExceeded),
        }
    })
}

// ---------------------------------------------------------------------------
// Fact lane
// ---------------------------------------------------------------------------

/// Fact owners in their fixed recall order: the project owner, then the
/// profile owner. Each owner is one independent upstream read.
const FACT_OWNER_ORDER: [MemoryScopeV1; 2] = [MemoryScopeV1::Project, MemoryScopeV1::User];

/// Reads canonical facts through the owner-bound upstream application.
///
/// The project owner is read with the full candidate budget; the profile
/// owner is read with whatever budget remains, so the concatenation never
/// exceeds the admitted budget and no upstream hit is dropped or reordered.
/// Hits are deduplicated by `fact_id` and then by content, keeping the first
/// (project) occurrence, as the upstream Hermes recall does.
async fn recall_facts(
    cg: &Arc<tokio::sync::RwLock<Arc<TraceDecay>>>,
    project_root: &Path,
    call: &ProviderCall,
    request: &NativeRecallRequestV1,
    read: &NativeFactRead,
) -> NativeRecallOutcome {
    control_failure(&call.control)?;
    let current = Arc::clone(&*cg.read().await);
    let project_id = match current.project_memory_owner() {
        Ok(FactOwnerV1::Project { project_id }) => project_id,
        Ok(FactOwnerV1::Profile) | Err(_) => return Err(NativeReadFailure::ProviderUnavailable),
    };
    if project_id.as_str() != call.exact_scope.project_id {
        return Err(NativeReadFailure::RecallScopeMismatch);
    }
    let budget = request
        .budgets
        .maximum_candidates
        .min(native_provider_limits().recall_candidates);
    let read_control = native_fact_read_control(&call.control);
    let mut hits = Vec::<NativeFactHit>::new();
    let mut scanned_items = 0_usize;
    for scope in FACT_OWNER_ORDER {
        let remaining = budget.saturating_sub(u64::try_from(hits.len()).unwrap_or(u64::MAX));
        if remaining == 0 {
            break;
        }
        let page = read_owner_facts(
            &current,
            project_root,
            &project_id,
            scope,
            request,
            read,
            remaining,
            &read_control,
        )
        .await?;
        scanned_items = scanned_items.saturating_add(page.hits.len());
        for hit in page.hits {
            let duplicate = hits.iter().any(|existing| {
                existing.hit.fact.fact_id == hit.fact.fact_id
                    || existing.hit.fact.content == hit.fact.content
            });
            if !duplicate {
                hits.push(NativeFactHit { scope, hit });
            }
        }
        control_failure(&call.control)?;
    }
    let candidates = hits
        .iter()
        .map(|hit| fact_candidate(call, hit))
        .collect::<Result<Vec<_>, _>>()?;
    let coverage_state = if candidates.is_empty() {
        "zero_results"
    } else {
        "complete"
    };
    let coverage = serde_json::json!({
        "state": coverage_state,
        "searched_scope_digest": call.exact_scope.exact_scope_sha256(),
        "searched_temporal_digest": recall_temporal_digest(&request.temporal_query),
        "scanned_items": scanned_items,
        "matched_items": scanned_items,
        "returned_items": candidates.len(),
        "excluded_items": scanned_items.saturating_sub(candidates.len()),
        "truncated_items": 0,
        "next_cursor": Value::Null,
        "reasons": [],
    });
    let ordering = serde_json::json!({
        "provider_order": "upstream_fact_search_rank_per_owner_project_then_profile",
        "score_domain_id": FACT_SCORE_DOMAIN,
        "direction": "higher_is_better",
        "tie_breaker": "upstream_fact_search_order",
    });
    let terminal_code = if candidates.is_empty() {
        TerminalCode::SuccessZeroResults
    } else {
        TerminalCode::Success
    };
    recall_reply(call, request, candidates, coverage, ordering, terminal_code)
}

struct NativeFactHit {
    scope: MemoryScopeV1,
    hit: FactSearchHitV1,
}

/// One upstream owner read, built and mapped exactly as the matching
/// `tracedecay_fact_store_*` tool builds and maps it.
async fn read_owner_facts(
    graph: &TraceDecay,
    project_root: &Path,
    project_id: &tracedecay_domain::ProjectId,
    scope: MemoryScopeV1,
    request: &NativeRecallRequestV1,
    read: &NativeFactRead,
    limit: u64,
    read_control: &FactReadControl,
) -> Result<memory_mapping::MappedSearchPageV1, NativeReadFailure> {
    // Search and Related expand through the project memory graph and take
    // the recording lease exactly as the retained fact tools do.
    let access = match read {
        NativeFactRead::Search | NativeFactRead::Related => MemoryTargetAccessV1::RecordRetrieval,
        NativeFactRead::Probe | NativeFactRead::Reason { .. } => MemoryTargetAccessV1::Read,
    };
    let target = open_project_retained_memory_target(
        graph,
        project_root,
        project_id,
        Some(scope),
        None,
        access,
    )
    .await
    .map_err(map_retained_error)?;
    let owner = target.owner().clone();
    let memory = MemoryApplication::new(owner.clone(), DatabaseFactStore::new(target.database()))
        .map_err(|error| map_retained_error(memory_mapping::map_memory_error(error)))?;
    let options = FactReadOptionsV1 {
        memory_scope: Some(scope),
        category: None,
        min_trust: None,
        limit: Some(limit),
        project_selector: None,
    };
    let (page, binding) = match read {
        NativeFactRead::Search => {
            let search_request = FactStoreSearchRequestV1 {
                query: request.query.clone(),
                options,
                after: None,
            };
            let (query, binding) = memory_mapping::PreparedFactSearch::new(owner, &search_request)
                .map_err(map_retained_error)?
                .into_parts();
            (
                memory
                    .search_project_memory_facts(query, read_control)
                    .await,
                binding,
            )
        }
        NativeFactRead::Probe => {
            let binding = memory_mapping::fact_page_binding(
                memory_mapping::FactPageOperation::Probe,
                &request.query,
                &options,
                options.min_trust,
                memory_mapping::fact_limit(options.limit).map_err(map_retained_error)?,
            )
            .map_err(map_retained_error)?;
            let query = memory_mapping::search_query(
                owner,
                ProjectMemoryFactSearchKindV1::Probe,
                Some(request.query.clone()),
                &options,
                None,
                &binding,
            )
            .map_err(map_retained_error)?;
            (
                memory.probe_project_memory_facts(query, read_control).await,
                binding,
            )
        }
        NativeFactRead::Related => {
            let binding = memory_mapping::fact_page_binding(
                memory_mapping::FactPageOperation::Related,
                &request.query,
                &options,
                options.min_trust,
                memory_mapping::fact_limit(options.limit).map_err(map_retained_error)?,
            )
            .map_err(map_retained_error)?;
            let query = memory_mapping::search_query(
                owner,
                ProjectMemoryFactSearchKindV1::Related {
                    entity: request.query.clone(),
                },
                None,
                &options,
                None,
                &binding,
            )
            .map_err(map_retained_error)?;
            (
                memory
                    .related_project_memory_facts(query, read_control)
                    .await,
                binding,
            )
        }
        NativeFactRead::Reason { entities } => {
            let entities =
                memory_mapping::normalize_reason_entities(entities).map_err(map_retained_error)?;
            let binding = memory_mapping::fact_page_binding(
                memory_mapping::FactPageOperation::Reason,
                &entities,
                &options,
                options.min_trust,
                memory_mapping::fact_limit(options.limit).map_err(map_retained_error)?,
            )
            .map_err(map_retained_error)?;
            let query = memory_mapping::search_query(
                owner,
                ProjectMemoryFactSearchKindV1::Reason { entities },
                None,
                &options,
                None,
                &binding,
            )
            .map_err(map_retained_error)?;
            (
                memory
                    .reason_project_memory_facts(query, read_control)
                    .await,
                binding,
            )
        }
    };
    let page = page.map_err(|error| map_retained_error(memory_mapping::map_memory_error(error)))?;
    memory_mapping::search_page(&page, &binding).map_err(map_retained_error)
}

fn native_fact_read_control(control: &OperationControl) -> FactReadControl {
    let control = control.clone();
    FactReadControl::new(Arc::new(move || control.snapshot().is_err()))
}

/// Maps one upstream `FactSearchHitV1` into a provider candidate. The hit is
/// carried unchanged; the native score is `score_millionths` written as the
/// exact decimal it denotes. Projection time and source revision identify
/// observed lineage, not a content-validity interval.
fn fact_candidate(
    call: &ProviderCall,
    fact_hit: &NativeFactHit,
) -> Result<Value, NativeReadFailure> {
    let hit = &fact_hit.hit;
    let fact = &hit.fact;
    let fact_id = fact.fact_id.as_str();
    let record_ref = format!("record:{fact_id}");
    let exact_scope_identity = match (&fact.owner, fact_hit.scope) {
        (FactCommitOwnerV1::Project { project_id }, MemoryScopeV1::Project)
            if project_id.as_str() == call.exact_scope.project_id =>
        {
            owner_scope_value(call, "project_facts", true)
        }
        (FactCommitOwnerV1::Profile, MemoryScopeV1::User) => {
            owner_scope_value(call, "profile_facts", false)
        }
        _ => return Err(NativeReadFailure::RecallProjectionInvalid),
    };
    let upstream_hit =
        serde_json::to_value(hit).map_err(|_| NativeReadFailure::RecallProjectionInvalid)?;
    // Candidate identities are request-scoped; the fact identity is the
    // stable reference that survives across requests.
    let candidate_id = format!("{}:fact:{fact_id}", call.request_id);
    let observed_at = tracedecay_memory_provider_registry::recall_admission::rfc3339_utc_micros(
        fact.projected_as_of.0,
    );
    Ok(serde_json::json!({
        "candidate_id": candidate_id,
        "stable_memory_ref": fact_id,
        "content": fact.content,
        "content_ref": Value::Null,
        "content_sha256": sha256_hex(fact.content.as_bytes()),
        "native_score": {
            "score_domain_id": FACT_SCORE_DOMAIN,
            "score_domain_version": 1,
            "raw_value": millionths_decimal(u64::from(hit.scores.score_millionths)),
            "direction": "higher_is_better",
            "declared_minimum": "0.000000",
            "declared_maximum": "1.000000",
            "calibration_state": "uncalibrated",
            "semantics": "upstream fact search score_millionths",
            "components": {
                "score_millionths": hit.scores.score_millionths,
                "fts_score_millionths": hit.scores.fts_score_millionths,
                "jaccard_score_millionths": hit.scores.jaccard_score_millionths,
                "holographic_score_millionths": hit.scores.holographic_score_millionths,
                "trust_score_millionths": hit.scores.trust_score_millionths,
            },
        },
        "confidence": Value::Null,
        "exact_scope_identity": exact_scope_identity,
        "validity": {
            "observed_at": observed_at,
            "valid_from": Value::Null,
            "valid_until": Value::Null,
            "superseded_at": Value::Null,
            "superseded_by": Value::Null,
            "revoked_at": Value::Null,
            "source_revision": fact.last_event_id.as_str(),
            "temporal_state": "unknown",
        },
        "provenance": {
            "state": "available",
            "origin_refs": [record_ref],
            "observation_refs": [],
            "source_refs": [record_ref],
            "transform_chain": [],
            "provider_trace_refs": [],
            "redaction_reason": Value::Null,
            "fact_search_hit": upstream_hit,
        },
        "explanation": {
            "summary": hit.why.as_deref().unwrap_or("upstream canonical fact search hit"),
            "matched_features": [],
            "activation_trace_refs": [],
            "limitations": [],
        },
        "source_refs": [record_ref],
        "trace_refs": [],
        "sensitivity": "unknown",
        "memory_class": FACT_MEMORY_CLASS,
        "warnings": [],
        "extensions": [],
    }))
}

/// Owner-scoped identity: facts are project-wide (or profile-wide), so the
/// checkout, session, and resolved-scope fields are never attested.
fn owner_scope_value(call: &ProviderCall, binding: &str, project: bool) -> Value {
    let project_id = if project {
        call.exact_scope.project_id.as_str()
    } else {
        ""
    };
    serde_json::json!({
        "scope_binding": binding,
        "profile_id": call.exact_scope.profile_id,
        "project_id": project_id,
        "repository_identity": "",
        "worktree_identity": "",
        "branch_identity": "",
        "agent_session_id": "",
        "resolved_scope_digest": "",
    })
}

// ---------------------------------------------------------------------------
// Session lane
// ---------------------------------------------------------------------------

/// Uses the upstream message-search compiler with its default filters.
fn message_search_query(
    query: &str,
    cursor: Option<String>,
    limit: usize,
) -> Result<SessionTemporalQuery, NativeReadFailure> {
    let request = MessageSearchRequestV1 {
        query: Some(query.to_owned()),
        cursor,
        limit: Some(u64::try_from(limit).map_err(|_| NativeReadFailure::RecallInvalidRequest)?),
        ..MessageSearchRequestV1::default()
    };
    message_search_temporal_query(&request).map_err(map_retained_error)
}

/// Reads session history through the upstream message-search kernel and maps
/// its page verbatim. Reads never refresh or ingest.
async fn recall_session_history(
    session_retrieval: &NativeSessionRetrievalMountV1,
    call: &ProviderCall,
    request: &NativeRecallRequestV1,
) -> NativeRecallOutcome {
    control_failure(&call.control)?;
    let scope = session_retrieval.host_scope();
    if session_retrieval.host_profile_id().as_str() != call.exact_scope.profile_id
        || scope.project_id.as_str() != call.exact_scope.project_id
    {
        return Err(NativeReadFailure::RecallScopeMismatch);
    }
    let limit = usize::try_from(
        request
            .budgets
            .maximum_candidates
            .clamp(1, MESSAGE_SEARCH_MAX_LIMIT),
    )
    .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let query = message_search_query(&request.query, request.temporal_query.cursor.clone(), limit)?;
    let cancellation = CancellationSignal::active(format!(
        "native-session-recall.{}",
        sha256_hex(call.request_id.as_bytes())
    ))
    .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let context = native_recall_context(call, scope, &cancellation)?;
    let _cancellation_bridge = NativeCancellationBridge::start(&call.control, &cancellation);
    let outcome = session_retrieval
        .retrieve_admitted_with_cancellation(&context, &cancellation, query)
        .await;
    control_failure(&call.control)?;
    session_history_reply(call, request, outcome)
}

/// Maps one kernel outcome verbatim. Page order, scores, anchors, freshness,
/// omissions, and the cursor are the kernel's own; nothing is re-sorted,
/// rescaled, filtered, or clipped here.
fn session_history_reply(
    call: &ProviderCall,
    request: &NativeRecallRequestV1,
    outcome: SessionRetrievalServiceOutcome,
) -> NativeRecallOutcome {
    let (state, results, temporal, freshness, record_omitted) = match outcome {
        SessionRetrievalServiceOutcome::Complete { page, freshness } => {
            let SessionRetrievalPageView { results, temporal } = page;
            ("complete", results, Some(temporal), Some(freshness), 0)
        }
        SessionRetrievalServiceOutcome::CompleteZero {
            temporal,
            freshness,
        } => (
            "complete_zero",
            Vec::new(),
            Some(temporal),
            Some(freshness),
            0,
        ),
        SessionRetrievalServiceOutcome::Stale {
            temporal,
            freshness,
        } => ("stale", Vec::new(), Some(temporal), Some(freshness), 0),
        SessionRetrievalServiceOutcome::Partial {
            page,
            freshness,
            // The folded count includes projection lag, which is carried in
            // freshness below and must not be reported as truncated records.
            omitted: _,
            record_omitted,
        } => {
            let SessionRetrievalPageView { results, temporal } = page;
            (
                "partial",
                results,
                Some(temporal),
                Some(freshness),
                record_omitted,
            )
        }
        SessionRetrievalServiceOutcome::Redacted => ("redacted", Vec::new(), None, None, 0),
        SessionRetrievalServiceOutcome::Deleted => ("deleted", Vec::new(), None, None, 0),
        SessionRetrievalServiceOutcome::WrongScope | SessionRetrievalServiceOutcome::Denied => {
            return Err(NativeReadFailure::RecallNotAuthorized);
        }
        SessionRetrievalServiceOutcome::ResetRequired { .. } => {
            return Err(NativeReadFailure::RecallResetRequired);
        }
        SessionRetrievalServiceOutcome::Locked | SessionRetrievalServiceOutcome::Unavailable(_) => {
            return Err(NativeReadFailure::ProviderUnavailable);
        }
        SessionRetrievalServiceOutcome::CursorStale => {
            return Err(NativeReadFailure::RecallCursorStale);
        }
        SessionRetrievalServiceOutcome::CursorRefused(mismatch) => {
            return Err(NativeReadFailure::RecallCursorRefused(mismatch));
        }
        SessionRetrievalServiceOutcome::CursorManifestLimitExceeded { .. }
        | SessionRetrievalServiceOutcome::BudgetExhausted { .. } => {
            return Err(NativeReadFailure::RecallCapacityExceeded);
        }
        SessionRetrievalServiceOutcome::TimedOut => {
            return Err(NativeReadFailure::DeadlineExceeded);
        }
        SessionRetrievalServiceOutcome::Cancelled => return Err(NativeReadFailure::Cancelled),
    };
    let candidates = results
        .iter()
        .map(|result| session_message_candidate(call, result))
        .collect::<Result<Vec<_>, _>>()?;
    let partial = matches!(state, "partial" | "stale");
    let next_cursor = temporal
        .as_ref()
        .and_then(|temporal| temporal.cursor.clone());
    let coverage_state = if partial {
        "partial"
    } else if candidates.is_empty() {
        "zero_results"
    } else {
        "complete"
    };
    let reasons = if partial {
        vec![format!("session_projection_{state}")]
    } else {
        Vec::new()
    };
    let freshness = freshness.map(freshness_value);
    let session_temporal = temporal.as_ref().map(session_temporal_value);
    let coverage = serde_json::json!({
        "state": coverage_state,
        "searched_scope_digest": call.exact_scope.exact_scope_sha256(),
        "searched_temporal_digest": recall_temporal_digest(&request.temporal_query),
        "scanned_items": candidates.len(),
        "matched_items": candidates.len(),
        "returned_items": candidates.len(),
        "excluded_items": 0,
        "truncated_items": record_omitted,
        "next_cursor": next_cursor,
        "reasons": reasons,
        "message_search_outcome": state,
        "freshness": freshness,
        "session_temporal": session_temporal,
    });
    let ordering = serde_json::json!({
        "provider_order": "upstream_message_search_page_order",
        "score_domain_id": SESSION_SCORE_DOMAIN,
        "direction": "higher_is_better",
        "tie_breaker": "upstream_message_search_page_order",
    });
    let terminal_code = if partial {
        TerminalCode::Partial
    } else if candidates.is_empty() {
        TerminalCode::SuccessZeroResults
    } else {
        TerminalCode::Success
    };
    recall_reply(call, request, candidates, coverage, ordering, terminal_code)
}

fn freshness_value(freshness: SessionDataFreshness) -> Value {
    match freshness {
        SessionDataFreshness::Fresh => serde_json::json!({"state": "fresh"}),
        SessionDataFreshness::Stored { generation_lag } => {
            serde_json::json!({"state": "stored", "generation_lag": generation_lag})
        }
        SessionDataFreshness::Partial { generation_lag } => {
            serde_json::json!({"state": "partial", "generation_lag": generation_lag})
        }
    }
}

fn session_temporal_value(temporal: &SessionTemporalMetadataView) -> Value {
    serde_json::to_value(temporal).unwrap_or(Value::Null)
}

/// Maps one upstream message-search hit. The kernel score is its normalized
/// micro-score divided by one million, so writing it with six decimals is
/// the exact value, not a rescaling. A message timestamp records an
/// observation, not a content-validity interval.
fn session_message_candidate(
    call: &ProviderCall,
    result: &SessionMessageSearchResult,
) -> Result<Value, NativeReadFailure> {
    if !result.score.is_finite() || result.score < 0.0 {
        return Err(NativeReadFailure::RecallProjectionInvalid);
    }
    // The kernel publishes `normalized_score_micros / 1_000_000`, so this
    // recovers the exact integer it ranked with.
    let score_micros = (result.score * 1_000_000.0).round() as u64;
    let message = &result.message;
    let identity = sha256_hex(
        serde_json::to_vec(&(
            "tracedecay.native.session-message.v1",
            &message.provider,
            &message.session_id,
            &message.message_id,
        ))
        .map_err(|_| NativeReadFailure::RecallProjectionInvalid)?
        .as_slice(),
    );
    let stable_memory_ref = format!("session-message:{identity}");
    let candidate_id = format!("{}:{stable_memory_ref}", call.request_id);
    let session_ref = u64::try_from(message.ordinal)
        .ok()
        .map(|ordinal| format!("session:{}#{ordinal}-{ordinal}", message.session_id));
    let observed_at = message
        .timestamp
        .and_then(tracedecay_memory_provider_registry::recall_admission::rfc3339_utc_micros);
    let upstream_hit =
        serde_json::to_value(result).map_err(|_| NativeReadFailure::RecallProjectionInvalid)?;
    let session_refs = session_ref.into_iter().collect::<Vec<_>>();
    Ok(serde_json::json!({
        "candidate_id": candidate_id,
        "stable_memory_ref": stable_memory_ref,
        "content": message.text,
        "content_ref": Value::Null,
        "content_sha256": sha256_hex(message.text.as_bytes()),
        "native_score": {
            "score_domain_id": SESSION_SCORE_DOMAIN,
            "score_domain_version": 1,
            "raw_value": millionths_decimal(score_micros),
            "direction": "higher_is_better",
            "declared_minimum": "0.000000",
            "declared_maximum": "1.000000",
            "calibration_state": "uncalibrated",
            "semantics": "upstream message search normalized relevance score",
            "components": {
                "normalized_score_micros": score_micros,
            },
        },
        "confidence": Value::Null,
        "exact_scope_identity": owner_scope_value(call, "project_facts", true),
        "validity": {
            "observed_at": observed_at,
            "valid_from": Value::Null,
            "valid_until": Value::Null,
            "superseded_at": Value::Null,
            "superseded_by": Value::Null,
            "revoked_at": Value::Null,
            "source_revision": Value::Null,
            "temporal_state": "unknown",
        },
        "provenance": {
            "state": "available",
            "origin_refs": session_refs,
            "observation_refs": [],
            "source_refs": session_refs,
            "transform_chain": [],
            "provider_trace_refs": [],
            "redaction_reason": Value::Null,
            "message_search_hit": upstream_hit,
        },
        "explanation": {
            "summary": "upstream message search hit",
            "matched_features": [],
            "activation_trace_refs": [],
            "limitations": [],
        },
        "source_refs": session_refs,
        "trace_refs": [],
        "sensitivity": "unknown",
        "memory_class": SESSION_MESSAGE_MEMORY_CLASS,
        "warnings": [],
        "extensions": [],
    }))
}

fn native_recall_context(
    call: &ProviderCall,
    scope: &tracedecay_contracts::ResolvedScope,
    cancellation: &CancellationSignal,
) -> Result<RequestContext, NativeReadFailure> {
    let observed_at = now_micros();
    let expires_at = UtcMicros(call.control.deadline_utc_micros());
    if expires_at <= observed_at {
        return Err(NativeReadFailure::DeadlineExceeded);
    }
    let actor = ActorId::new("actor.tracedecay.native.recall")
        .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let capability = tracedecay_tool_catalog::CapabilityId::new("recall.query.v1")
        .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let use_case = tracedecay_tool_catalog::UseCaseId::new("memory.session-recall.v1")
        .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let grant_digest = canonical_sha256(&(
        "tracedecay.native.session-recall-grant.v3",
        call.exact_scope.exact_scope_sha256(),
        call.request_id.as_str(),
    ))
    .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let grant = CapabilityGrantSnapshot::new(
        CapabilityGrantId::new("grant.tracedecay.native.session-recall")
            .map_err(|_| NativeReadFailure::RecallInvalidRequest)?,
        1,
        grant_digest,
        actor.clone(),
        observed_at,
        expires_at,
        scope.clone(),
        BTreeSet::from([capability]),
        BTreeSet::from([use_case]),
        DisclosureClass::Sensitive,
    )
    .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    let request_id = RequestId::new(call.request_id.clone())
        .map_err(|_| NativeReadFailure::RecallInvalidRequest)?;
    RequestContext::new(
        actor,
        scope.clone(),
        grant,
        request_id,
        Deadline::new(expires_at).map_err(|_| NativeReadFailure::RecallInvalidRequest)?,
        cancellation.context(),
    )
    .map_err(|_| NativeReadFailure::RecallInvalidRequest)
}

/// Forwards the provider call's cancellation token to the kernel's signal.
struct NativeCancellationBridge {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NativeCancellationBridge {
    fn start(control: &OperationControl, cancellation: &CancellationSignal) -> Self {
        let provider_cancellation = control.cancellation();
        let cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            loop {
                if provider_cancellation.is_cancelled() {
                    cancellation.cancel(now_micros());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        Self { task: Some(task) }
    }
}

impl Drop for NativeCancellationBridge {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Shared envelope
// ---------------------------------------------------------------------------

fn recall_reply(
    call: &ProviderCall,
    request: &NativeRecallRequestV1,
    candidates: Vec<Value>,
    coverage: Value,
    ordering: Value,
    terminal_code: TerminalCode,
) -> NativeRecallOutcome {
    let response = serde_json::json!({
        "provider_id": NATIVE_PROVIDER_ID,
        "provider_instance_id": PROVIDER_INSTANCE_ID,
        "registration_revision": request.registration_revision,
        "ready_receipt_digest": request.ready_receipt_digest,
        "request_identity": request.request_identity,
        "exact_scope_identity": exact_scope_value(call),
        "provider_state_generation": call.expected_state_generation,
        "candidates": candidates,
        "coverage": coverage,
        "ordering": ordering,
        "terminal": {
            "terminal_code": terminal_code.as_wire(),
            "diagnostic_id": Value::Null,
        },
        "warnings": [],
    });
    let bytes =
        serde_json::to_vec(&response).map_err(|_| NativeReadFailure::RecallProjectionInvalid)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > native_provider_limits().response_bytes {
        return Err(NativeReadFailure::RecallCapacityExceeded);
    }
    let payload = CanonicalPayload::new(
        OwnedVersionedId::new(RECALL_RESULT_CONTRACT_ID)
            .map_err(|_| NativeReadFailure::RecallProjectionInvalid)?,
        bytes.clone(),
        sha256_hex(&bytes),
    )
    .map_err(|_| NativeReadFailure::RecallProjectionInvalid)?;
    Ok(ProviderReply {
        terminal: terminal_for_call(call, terminal_code, None),
        payload: Some(payload),
        warnings: Vec::new(),
        extensions: call.extensions.clone(),
        state_generation: call.expected_state_generation,
    })
}

fn exact_scope_value(call: &ProviderCall) -> Value {
    serde_json::json!({
        "profile_id": call.exact_scope.profile_id,
        "project_id": call.exact_scope.project_id,
        "repository_identity": call.exact_scope.repository_identity,
        "worktree_identity": call.exact_scope.worktree_identity,
        "branch_identity": call.exact_scope.branch_identity,
        "agent_session_id": call.exact_scope.agent_session_id,
        "resolved_scope_digest": call.exact_scope.resolved_scope_digest,
    })
}

fn millionths_decimal(millionths: u64) -> String {
    format!("{}.{:06}", millionths / 1_000_000, millionths % 1_000_000)
}

fn recall_temporal_digest(temporal: &NativeRecallTemporalQueryV1) -> String {
    let value = serde_json::json!({
        "mode": temporal.mode,
        "evaluation_time": temporal.evaluation_time,
        "as_of": temporal.as_of,
        "interval_start": temporal.interval_start,
        "interval_end": temporal.interval_end,
        "cursor": temporal.cursor,
        "include_superseded": temporal.include_superseded,
        "include_revoked": temporal.include_revoked,
        "unknown_validity_policy": temporal.unknown_validity_policy,
    });
    serde_json::to_vec(&value).map_or_else(|_| String::new(), |bytes| sha256_hex(&bytes))
}

fn map_retained_error(error: RetainedSurfaceExecutionErrorV1) -> NativeReadFailure {
    match error {
        RetainedSurfaceExecutionErrorV1::Cancelled(_) => NativeReadFailure::Cancelled,
        RetainedSurfaceExecutionErrorV1::TimedOut(_) => NativeReadFailure::DeadlineExceeded,
        RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized => {
            NativeReadFailure::RecallNotAuthorized
        }
        RetainedSurfaceExecutionErrorV1::InvalidRequest => NativeReadFailure::RecallInvalidRequest,
        RetainedSurfaceExecutionErrorV1::ProfileResetRequired
        | RetainedSurfaceExecutionErrorV1::ProjectResetRequired => {
            NativeReadFailure::RecallResetRequired
        }
        RetainedSurfaceExecutionErrorV1::Saturated => NativeReadFailure::RecallCapacityExceeded,
        RetainedSurfaceExecutionErrorV1::ApplicationProblem(_)
        | RetainedSurfaceExecutionErrorV1::StructuralRefusal(_)
        | RetainedSurfaceExecutionErrorV1::PartialEffect { .. }
        | RetainedSurfaceExecutionErrorV1::Conflict
        | RetainedSurfaceExecutionErrorV1::Stale
        | RetainedSurfaceExecutionErrorV1::Unsupported
        | RetainedSurfaceExecutionErrorV1::Unavailable { detail: _ } => {
            NativeReadFailure::ProviderUnavailable
        }
    }
}
