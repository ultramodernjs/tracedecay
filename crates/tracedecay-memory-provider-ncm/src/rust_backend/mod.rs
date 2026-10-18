//! Supervised Rust worker implementation of the topology-neutral NCM surface.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
pub use tracedecay_memory_ncm_runtime::client::WorkerOptions;
use tracedecay_memory_ncm_runtime::client::{ClientError, WorkerClient};
use tracedecay_memory_ncm_runtime::engine::{Outcome, RejectReason};
pub use tracedecay_memory_ncm_runtime::ports::StateRoot;
use tracedecay_memory_ncm_runtime::wire::{Operation, Reply, Request};
use tracedecay_memory_ncm_runtime::worker_artifact::{
    current_target_triple, trusted_worker_manifest,
};
use tracedecay_memory_provider_api::contract::TerminalCode;
use tracedecay_memory_provider_api::{
    CanonicalPayload, CommittedEffectEvidence, FallbackDirective, OwnedProviderId,
    OwnedVersionedId, ProviderDescriptor, ProviderLimits, ProviderOperation, ProviderReply,
    TerminalRecord,
};

use crate::{
    NCM_PROVIDER_ID, NcmCognitiveSurface, NcmSurfaceCall, NcmSurfaceHandshakeRequest,
    NcmSurfaceHandshakeResponse,
};

const ALGORITHM_PROFILE: &str = "ncm-biomem-rs.v1";
const PROVISIONAL_CONFIG_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const PREFLIGHT_NAMESPACE: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const RECEIPT_DOMAIN: &[u8] = b"tracedecay.ncm.rust-worker-receipt.v1\0";
const READY_DOMAIN: &[u8] = b"tracedecay.ncm.rust-worker-ready.v1\0";
const READY_DOMAIN_V2: &[u8] = b"tracedecay.ncm.rust-worker-ready.v2\0";
const IMPLEMENTATION_DOMAIN: &[u8] = b"tracedecay.ncm.rust-worker-implementation.v1\0";
const IMPLEMENTATION_DOMAIN_V2: &[u8] = b"tracedecay.ncm.rust-worker-implementation.v2\0";
const IDENTITY_REVISION_V1: u16 = 1;
const IDENTITY_REVISION_V2: u16 = 2;
const MODEL_REVISION_RECEIPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
));
const DEFAULT_PREFLIGHT_MILLIS: u64 = 5_000;

/// Configuration for the supervised Rust NCM surface.
#[derive(Clone, Debug)]
pub struct RustNcmConfig {
    /// Absolute worker executable path.
    pub worker_binary: PathBuf,
    /// Admitted absolute state root.
    pub state_root: StateRoot,
    /// Worker launch, restart, and test-double controls.
    pub worker_options: WorkerOptions,
}

/// Failure while constructing the Rust-backed surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustNcmError {
    /// The worker owner or executable could not be started.
    WorkerSpawn(String),
    /// The supplied state root did not remain an admitted absolute root.
    StateRoot(String),
    /// A successful preflight returned malformed or contradictory identity.
    HandshakeIdentity(String),
}

impl fmt::Display for RustNcmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerSpawn(detail) => write!(formatter, "NCM worker spawn failed: {detail}"),
            Self::StateRoot(detail) => write!(formatter, "NCM state root rejected: {detail}"),
            Self::HandshakeIdentity(detail) => {
                write!(formatter, "NCM handshake identity rejected: {detail}")
            }
        }
    }
}

impl Error for RustNcmError {}

/// A worker call can succeed only after proving it still reached the process
/// whose identity the surface last admitted. The owner client is allowed to
/// respawn a read-only request internally, so a successful reply alone cannot
/// preserve the surface's previous readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
enum WorkerCallError {
    /// The bounded worker client rejected or could not complete the call.
    Client(ClientError),
    /// The owner observed a different worker lifetime while serving this call.
    IncarnationChanged {
        previous: Option<u64>,
        current: Option<u64>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkerTargetIdentity {
    triple: String,
    os: String,
    arch: String,
    family: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkerIdentity {
    sha256: String,
    bytes: u64,
    target: WorkerTargetIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModelArtifactIdentity {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeIdentity {
    /// Revision of the provider identity wire and digest contract.
    identity_revision: u16,
    config_sha256: String,
    projection_sha256: String,
    worker: Option<WorkerIdentity>,
    encoder_model: String,
    encoder_artifact_sha256: String,
    encoder_repository: Option<String>,
    encoder_revision: Option<String>,
    encoder_revision_provenance: Option<String>,
    encoder_files: Vec<ModelArtifactIdentity>,
    encoder_max_length: Option<usize>,
    encoder_pooling: Option<String>,
    encoder_normalize: Option<bool>,
    epoch: u64,
}

struct SurfaceState {
    descriptor: ProviderDescriptor,
    identity: Option<RuntimeIdentity>,
    /// Namespace whose projection/epoch were last observed in `identity`.
    /// The preflight namespace is only a static identity probe; runtime state
    /// must be rebound when the first public namespace is handshaken.
    identity_namespace: Option<String>,
    /// Provider instance identity returned by the last successful proof.
    instance_id: Option<String>,
    /// Monotonic worker-owner incarnation bound by the last successful proof.
    worker_incarnation: Option<u64>,
    /// Last owner incarnation observed by this surface, retained across
    /// invalidation so a replacement cannot inherit predecessor readiness.
    last_worker_incarnation: Option<u64>,
}

/// One serialized worker client and request identity authority shared by surfaces.
///
/// Sharing the owner serializes namespace creation and loads one model per worker.
/// Adapter readiness and descriptor generations remain local to each surface.
/// The last strong owner drops the existing bounded worker client and its process.
pub struct RustNcmWorkerOwner {
    client: WorkerClient,
    next_request_id: AtomicU64,
    supports_v2_handshake: bool,
}

impl RustNcmWorkerOwner {
    /// Admits a lazy worker owner. No child or model is started until a surface
    /// performs its first preflight through the existing bounded client.
    pub fn new(config: RustNcmConfig) -> Result<Self, RustNcmError> {
        let checked_root = StateRoot::new(config.state_root.path().to_path_buf())
            .map_err(RustNcmError::StateRoot)?;
        if !config.worker_binary.is_absolute() {
            return Err(RustNcmError::WorkerSpawn(
                "worker binary path must be absolute".to_owned(),
            ));
        }
        #[cfg(feature = "test-transport")]
        let supports_v2_handshake = !config.worker_options.test_double;
        #[cfg(not(feature = "test-transport"))]
        let supports_v2_handshake = true;
        let client = WorkerClient::spawn(
            &config.worker_binary,
            checked_root.path(),
            config.worker_options,
        )
        .map_err(|error| RustNcmError::WorkerSpawn(error.to_string()))?;
        Ok(Self {
            client,
            next_request_id: AtomicU64::new(1),
            supports_v2_handshake,
        })
    }

    /// Current child process identity, absent before launch or after exit.
    #[must_use]
    pub fn worker_pid(&self) -> Option<u32> {
        self.client.pid()
    }

    /// Monotonic owner incarnation for the current or most recently spawned
    /// worker. The counter survives process exit and possible PID reuse.
    #[must_use]
    pub fn worker_incarnation(&self) -> Option<u64> {
        self.client.owner_incarnation()
    }

    /// Starts this owner's existing worker and proves readiness by deadline.
    pub fn start(&self, deadline: std::time::Instant) -> Result<(), ClientError> {
        self.client.start(deadline)
    }

    /// Requests termination; true confirms actual child reap and pipe cleanup.
    pub fn request_stop(&self, deadline: std::time::Instant) -> Result<bool, ClientError> {
        self.client.request_stop(deadline)
    }

    /// Forces termination and returns success only after confirmed cleanup.
    pub fn kill(&self, deadline: std::time::Instant) -> Result<(), ClientError> {
        self.client.kill(deadline)
    }

    fn request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// Project-local NCM identity over an owned or shared supervised worker process.
pub struct RustNcmSurface {
    worker: Arc<RustNcmWorkerOwner>,
    state: Mutex<SurfaceState>,
    fallback_descriptor: ProviderDescriptor,
    declared_identity: Option<RuntimeIdentity>,
}

impl RustNcmSurface {
    /// Constructs a standalone worker owner and a read-only identity preflight.
    ///
    /// An unavailable encoder or executable remains typed not-ready. Recreate
    /// the standalone owner, or restart its owning daemon, after installation.
    pub fn new(config: RustNcmConfig) -> Result<Self, RustNcmError> {
        Self::from_worker(Arc::new(RustNcmWorkerOwner::new(config)?))
    }

    /// Constructs fresh surface identity over an existing serialized worker.
    ///
    /// Every project wraps its own surface in its own adapter. Sharing this
    /// owner never shares descriptor generation or accepted adapter readiness.
    /// A worker started without its model must be recreated after installation.
    pub fn from_worker(worker: Arc<RustNcmWorkerOwner>) -> Result<Self, RustNcmError> {
        let fallback_descriptor = descriptor_for(
            &legacy_identity(PROVISIONAL_CONFIG_SHA256, "not-ready", "not-ready"),
            0,
        )?;
        let preflight = Request::new(
            worker.request_id(),
            DEFAULT_PREFLIGHT_MILLIS,
            Operation::Handshake,
            PREFLIGHT_NAMESPACE,
            json!({"algorithm_profile": ALGORITHM_PROFILE}),
        );
        let (descriptor, identity) = match worker
            .client
            .call(preflight, Duration::from_millis(DEFAULT_PREFLIGHT_MILLIS))
        {
            Ok(reply) if reply.outcome == Outcome::Success => {
                let identity = parse_runtime_identity_for_expected(
                    &reply,
                    None,
                    worker.supports_v2_handshake,
                )?;
                let descriptor = descriptor_from_identity(&identity, reply.state_generation)?;
                (descriptor, Some(identity))
            }
            Ok(reply) if matches!(reply.outcome, Outcome::Unavailable(_)) => {
                (fallback_descriptor.clone(), None)
            }
            Ok(reply) => {
                return Err(RustNcmError::HandshakeIdentity(format!(
                    "preflight outcome {:?}",
                    reply.outcome
                )));
            }
            // The owner exists and retries are already bounded by the
            // worker client. Retain its real surface when the executable
            // is absent or exits: handshakes report the existing typed
            // unavailable terminal, exactly as missing-model preflight does.
            Err(
                ClientError::Spawn(_)
                | ClientError::Unavailable(_)
                | ClientError::RestartExhausted
                | ClientError::WorkerExited,
            ) => (fallback_descriptor.clone(), None),
            Err(error) => {
                return Err(RustNcmError::HandshakeIdentity(error.to_string()));
            }
        };
        let worker_incarnation = identity.as_ref().and_then(|_| worker.worker_incarnation());
        let instance_id = match (identity.as_ref(), worker_incarnation) {
            (Some(identity), Some(_)) => Some(owner_bound_instance_id(
                &implementation_version(identity),
                worker_incarnation,
            )),
            _ => None,
        };
        let identity_namespace = identity.as_ref().map(|_| PREFLIGHT_NAMESPACE.to_owned());
        Ok(Self {
            worker,
            state: Mutex::new(SurfaceState {
                descriptor,
                identity,
                identity_namespace,
                instance_id,
                worker_incarnation,
                last_worker_incarnation: worker_incarnation,
            }),
            fallback_descriptor,
            declared_identity: None,
        })
    }

    /// Declares the pinned production surface over a shared lazy owner.
    /// No preflight runs here. The first supervised handshake must prove this
    /// immutable declaration before any instance identity or readiness exists.
    pub fn from_production_worker(worker: Arc<RustNcmWorkerOwner>) -> Result<Self, RustNcmError> {
        let identity = production_identity()?;
        let descriptor = descriptor_from_identity(&identity, 0)?;
        Ok(Self {
            worker,
            state: Mutex::new(SurfaceState {
                descriptor: descriptor.clone(),
                identity: None,
                identity_namespace: None,
                instance_id: None,
                worker_incarnation: None,
                last_worker_incarnation: None,
            }),
            fallback_descriptor: descriptor,
            declared_identity: Some(identity),
        })
    }

    /// Proves the worker's global implementation identity without changing
    /// any session's descriptor generation, projection, or accepted readiness.
    /// This read-only bootstrap is bounded by the caller and the existing
    /// preflight ceiling; cancellation applies only to this worker request.
    pub fn prove_provider_instance(
        &self,
        deadline: std::time::Instant,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Option<String>, TerminalCode> {
        if cancelled() {
            return Err(TerminalCode::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TerminalCode::DeadlineExceeded)?
            .min(Duration::from_millis(DEFAULT_PREFLIGHT_MILLIS));
        let millis = u64::try_from(remaining.as_millis()).unwrap_or(DEFAULT_PREFLIGHT_MILLIS);
        if millis == 0 {
            return Err(TerminalCode::DeadlineExceeded);
        }
        let expected_identity = self.expected_identity();
        let supports_v2_handshake = self.worker.supports_v2_handshake;
        let bind_runtime_state = self.bind_runtime_state(PREFLIGHT_NAMESPACE);
        let reply = self
            .worker_call(
                Operation::Handshake,
                PREFLIGHT_NAMESPACE,
                identity_request_payload_for_worker(
                    expected_identity.as_ref(),
                    supports_v2_handshake,
                    bind_runtime_state,
                ),
                millis,
                Arc::clone(&cancelled),
            )
            .map_err(|error| worker_terminal_code(&error))?;
        if cancelled() {
            return Err(TerminalCode::Cancelled);
        }
        if std::time::Instant::now() >= deadline {
            return Err(TerminalCode::DeadlineExceeded);
        }
        if matches!(reply.outcome, Outcome::Unavailable(_)) {
            return Ok(None);
        }
        if reply.outcome != Outcome::Success {
            return Err(outcome_terminal_code(&reply.outcome));
        }
        let identity = parse_runtime_identity_for_expected(
            &reply,
            expected_identity.as_ref(),
            supports_v2_handshake,
        )
        .map_err(|_| TerminalCode::StateIncompatible)?;
        let candidate = descriptor_from_identity(&identity, reply.state_generation)
            .map_err(|_| TerminalCode::StateIncompatible)?;
        if !same_immutable_descriptor(&self.descriptor_snapshot(), &candidate) {
            return Err(TerminalCode::StateIncompatible);
        }
        let base_instance_id = implementation_version(&identity);
        Ok(Some(owner_bound_instance_id(
            &base_instance_id,
            self.worker_incarnation(),
        )))
    }

    /// Instance identity proved by the real preflight, if the worker was ready.
    /// This is the same identity authority used by the successful handshake;
    /// state schema metadata never substitutes for an unproved instance.
    pub fn provider_instance_id(&self) -> Result<Option<String>, RustNcmError> {
        let state = self.state.lock().map_err(|_| {
            RustNcmError::HandshakeIdentity("surface identity lock poisoned".to_owned())
        })?;
        Ok(state.instance_id.clone())
    }

    /// Returns the shared worker process identifier, when the lazy worker is alive.
    #[must_use]
    pub fn worker_pid(&self) -> Option<u32> {
        self.worker.worker_pid()
    }

    /// Returns the monotonic worker-owner incarnation, when the owner has
    /// spawned a worker. This is the authoritative process-lifetime binding;
    /// the PID remains available only as a diagnostic.
    #[must_use]
    pub fn worker_incarnation(&self) -> Option<u64> {
        self.worker.worker_incarnation()
    }

    fn bound_worker_incarnation(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.worker_incarnation)
    }

    /// Invalidates all proof that was attached to the predecessor process.
    /// Keep the descriptor and the last owner counter so a subsequent
    /// handshake can identify the replacement without carrying old readiness.
    fn invalidate_worker_identity(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.identity = None;
            state.identity_namespace = None;
            state.instance_id = None;
            state.worker_incarnation = None;
        }
    }

    fn worker_process_is_current(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Some(bound) = state.worker_incarnation else {
            // A surface without a bound proof is still bootstrapping, or its
            // predecessor proof was invalidated. Either way, routing must
            // wait for a fresh handshake to establish the replacement.
            return false;
        };
        state.identity.is_some()
            && self.worker_incarnation() == Some(bound)
            && self.worker_pid().is_some()
    }

    fn descriptor_snapshot(&self) -> ProviderDescriptor {
        self.state
            .lock()
            .map(|state| state.descriptor.clone())
            .unwrap_or_else(|_| self.fallback_descriptor.clone())
    }

    fn expected_identity(&self) -> Option<RuntimeIdentity> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.identity.clone())
            .or_else(|| self.declared_identity.clone())
    }

    fn bind_runtime_state(&self, namespace: &str) -> bool {
        self.state.lock().ok().is_some_and(|state| {
            state.identity.is_some() && state.identity_namespace.as_deref() == Some(namespace)
        })
    }

    fn update_generation(&self, namespace: &str, generation: u64) {
        if let Ok(mut state) = self.state.lock() {
            if state.descriptor.state_generation != generation
                && state.identity_namespace.as_deref() == Some(namespace)
            {
                // A mutation advances the ledger, while projection epoch and
                // digest remain independently owned by the runtime. Reobserve
                // those fields at the next handshake instead of inventing them
                // from the ledger generation.
                state.identity_namespace = None;
            }
            state.descriptor.state_generation = generation;
        }
    }

    fn install_identity(
        &self,
        identity: RuntimeIdentity,
        generation: u64,
        worker_incarnation: u64,
        namespace: &str,
    ) -> Result<(), RustNcmError> {
        let descriptor = descriptor_from_identity(&identity, generation)?;
        let mut state = self.state.lock().map_err(|_| {
            RustNcmError::HandshakeIdentity("surface state lock poisoned".to_owned())
        })?;
        let base_instance_id = implementation_version(&identity);
        let same_owner_incarnation = state.worker_incarnation == Some(worker_incarnation)
            && state
                .identity
                .as_ref()
                .is_some_and(|prior| implementation_version(prior) == base_instance_id)
            && state.last_worker_incarnation == Some(worker_incarnation);
        let instance_id = if same_owner_incarnation {
            state.instance_id.clone().unwrap_or_else(|| {
                owner_bound_instance_id(&base_instance_id, Some(worker_incarnation))
            })
        } else {
            owner_bound_instance_id(&base_instance_id, Some(worker_incarnation))
        };
        state.descriptor = descriptor;
        state.identity = Some(identity);
        state.identity_namespace = Some(namespace.to_owned());
        state.worker_incarnation = Some(worker_incarnation);
        state.last_worker_incarnation = Some(worker_incarnation);
        state.instance_id = Some(instance_id);
        Ok(())
    }

    fn worker_call(
        &self,
        operation: Operation,
        namespace: &str,
        payload: Value,
        millis: u64,
        cancellation: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Reply, WorkerCallError> {
        let expected_incarnation = self.bound_worker_incarnation();
        let before_incarnation = self.worker_incarnation();
        let request = Request::new(
            self.worker.request_id(),
            millis,
            operation,
            namespace,
            payload,
        );
        let result = self.worker.client.call_cancellable(
            request,
            Duration::from_millis(millis),
            cancellation,
        );
        let after_pid = self.worker_pid();
        let after_incarnation = self.worker_incarnation();
        let changed = expected_incarnation.is_some_and(|expected| {
            before_incarnation != Some(expected)
                || after_incarnation != Some(expected)
                || after_pid.is_none()
        });
        if changed {
            self.invalidate_worker_identity();
            // A handshake is the proof that may establish the replacement
            // binding. Every other operation must fail closed until that
            // proof has completed, including read-only health and recall.
            if operation != Operation::Handshake
                && !matches!(result, Err(ClientError::EffectUnknown { .. }))
            {
                return Err(WorkerCallError::IncarnationChanged {
                    previous: expected_incarnation,
                    current: after_incarnation,
                });
            }
        }
        result.map_err(WorkerCallError::Client)
    }
}

impl NcmCognitiveSurface for RustNcmSurface {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor_snapshot()
    }

    fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
        let control = match request.control.snapshot() {
            Ok(control) => control,
            Err(code) => {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    code,
                    "ncm.rust.control_terminal",
                    None,
                );
            }
        };
        let expected_identity = self.expected_identity();
        let bind_runtime_state = self.bind_runtime_state(request.namespace.as_str());
        let payload = identity_request_payload_for_worker(
            expected_identity.as_ref(),
            self.worker.supports_v2_handshake,
            bind_runtime_state,
        );
        let reply = match self.worker_call(
            Operation::Handshake,
            request.namespace.as_str(),
            payload,
            control.remaining_millis,
            Arc::new({
                let cancellation = request.control.cancellation();
                move || cancellation.is_cancelled()
            }),
        ) {
            Ok(reply) => reply,
            Err(error) => {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    worker_terminal_code(&error),
                    worker_diagnostic_for_error(&error),
                    None,
                );
            }
        };
        if reply.outcome != Outcome::Success {
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                outcome_terminal_code(&reply.outcome),
                outcome_diagnostic(&reply.outcome),
                Some(reply.state_generation),
            );
        }
        let identity = match parse_runtime_identity_for_expected(
            &reply,
            expected_identity.as_ref(),
            self.worker.supports_v2_handshake,
        ) {
            Ok(identity) => identity,
            Err(error) => {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    TerminalCode::StateIncompatible,
                    error_diagnostic(&error),
                    Some(reply.state_generation),
                );
            }
        };
        let candidate = match descriptor_from_identity(&identity, reply.state_generation) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    TerminalCode::StateIncompatible,
                    error_diagnostic(&error),
                    Some(reply.state_generation),
                );
            }
        };
        let current = self.descriptor_snapshot();
        if !same_immutable_descriptor(&current, &candidate) {
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                TerminalCode::StateIncompatible,
                "ncm.rust.handshake_immutable_identity_mismatch",
                Some(reply.state_generation),
            );
        }
        if current.state_generation != candidate.state_generation {
            if self.worker_pid().is_none() {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    TerminalCode::ProviderUnavailable,
                    "ncm.rust.worker_not_alive",
                    Some(reply.state_generation),
                );
            }
            let Some(worker_incarnation) = self.worker_incarnation() else {
                return handshake_failure(
                    &self.fallback_descriptor.provider_id,
                    request,
                    TerminalCode::ProviderUnavailable,
                    "ncm.rust.worker_not_alive",
                    Some(reply.state_generation),
                );
            };
            let _ = self.install_identity(
                identity,
                reply.state_generation,
                worker_incarnation,
                request.namespace.as_str(),
            );
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                TerminalCode::StaleIdentity,
                "ncm.rust.handshake_identity_refresh_required",
                Some(reply.state_generation),
            );
        }
        if self.worker_pid().is_none() {
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                TerminalCode::ProviderUnavailable,
                "ncm.rust.worker_not_alive",
                Some(reply.state_generation),
            );
        }
        let Some(worker_incarnation) = self.worker_incarnation() else {
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                TerminalCode::ProviderUnavailable,
                "ncm.rust.worker_not_alive",
                Some(reply.state_generation),
            );
        };
        if self
            .install_identity(
                identity.clone(),
                reply.state_generation,
                worker_incarnation,
                request.namespace.as_str(),
            )
            .is_err()
        {
            return handshake_failure(
                &self.fallback_descriptor.provider_id,
                request,
                TerminalCode::ProviderUnavailable,
                "ncm.rust.surface_state_unavailable",
                Some(reply.state_generation),
            );
        }
        let descriptor = self.descriptor_snapshot();
        let ready_receipt =
            ready_receipt_for_worker(request.namespace.as_str(), &identity, worker_incarnation);
        let instance_id = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.instance_id.clone())
            .unwrap_or_else(|| implementation_version(&identity));
        let challenge =
            request.expected_challenge_response_sha256(&descriptor, &instance_id, &ready_receipt);
        let terminal = surface_terminal(
            &self.fallback_descriptor.provider_id,
            ProviderOperation::Handshake,
            &request.request_id,
            request.namespace.as_str(),
            TerminalCode::Success,
            // A handshake commits nothing, but its evidence anchors to the
            // descriptor generation the host is about to bind readiness to.
            CommittedEffectEvidence::none(Some(descriptor.state_generation)),
            None,
        );
        NcmSurfaceHandshakeResponse {
            terminal,
            descriptor: Some(descriptor.clone()),
            provider_instance_id: Some(instance_id),
            namespace: Some(request.namespace.clone()),
            effective_limits: Some(request.host_limits.minimum(descriptor.limits)),
            ready_receipt_sha256: Some(ready_receipt),
            challenge_response_sha256: Some(challenge),
            warnings: Vec::new(),
        }
    }

    fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
        let control = match call.control.snapshot() {
            Ok(control) => control,
            Err(code) => {
                return pre_dispatch_reply(
                    &self.fallback_descriptor.provider_id,
                    call,
                    code,
                    "ncm.rust.control_terminal",
                );
            }
        };
        if !self.worker_process_is_current() {
            self.invalidate_worker_identity();
            return pre_dispatch_reply(
                &self.fallback_descriptor.provider_id,
                call,
                TerminalCode::StaleIdentity,
                "ncm.rust.worker_incarnation_changed",
            );
        }
        let payload = match translate_payload(call) {
            Ok(payload) => payload,
            Err(diagnostic) => {
                return pre_dispatch_reply(
                    &self.fallback_descriptor.provider_id,
                    call,
                    TerminalCode::InvalidRequest,
                    diagnostic,
                );
            }
        };
        let operation = wire_operation(call.operation);
        let reply = match self.worker_call(
            operation,
            call.namespace.as_str(),
            payload,
            control.remaining_millis,
            Arc::new({
                let cancellation = call.control.cancellation();
                move || cancellation.is_cancelled()
            }),
        ) {
            Ok(reply) => reply,
            Err(error) => {
                return worker_error_reply(&self.fallback_descriptor.provider_id, call, &error);
            }
        };
        if call.operation.mutates_provider_state()
            && reply.state_generation >= call.expected_state_generation
        {
            self.update_generation(call.namespace.as_str(), reply.state_generation);
        }
        worker_reply(&self.fallback_descriptor.provider_id, call, reply)
    }
}

fn identity_request_payload_for_worker(
    identity: Option<&RuntimeIdentity>,
    include_v2_metadata: bool,
    bind_runtime_state: bool,
) -> Value {
    identity_request_payload_with_epoch(
        identity,
        include_v2_metadata,
        bind_runtime_state,
        bind_runtime_state,
    )
}

fn identity_request_payload_with_epoch(
    identity: Option<&RuntimeIdentity>,
    include_v2_metadata: bool,
    bind_runtime_epoch: bool,
    bind_runtime_projection: bool,
) -> Value {
    let mut payload = json!({
        "protocol_version": 1,
        "algorithm_profile": ALGORITHM_PROFILE,
    });
    let Some(identity) = identity else {
        return payload;
    };
    let Some(object) = payload.as_object_mut() else {
        return payload;
    };
    object.insert(
        "model".to_owned(),
        Value::String(identity.encoder_model.clone()),
    );
    if include_v2_metadata && identity.identity_revision == IDENTITY_REVISION_V2 {
        object.insert(
            "identity_revision".to_owned(),
            Value::from(u64::from(IDENTITY_REVISION_V2)),
        );
        object.insert(
            "algorithm".to_owned(),
            json!({
                "profile": ALGORITHM_PROFILE,
                "config_sha256": identity.config_sha256,
            }),
        );
        if bind_runtime_projection && !identity.projection_sha256.is_empty() {
            object.insert(
                "projection_sha256".to_owned(),
                Value::String(identity.projection_sha256.clone()),
            );
        }
        // A declaration with no projection has no namespace epoch to bind.
        // Omitting the field lets a first handshake observe a persisted
        // namespace's epoch instead of falsely declaring epoch zero. Once a
        // projection and epoch have been observed for this namespace, callers
        // explicitly bind runtime state and require the exact values.
        if bind_runtime_epoch && !identity.projection_sha256.is_empty() {
            object.insert("epoch".to_owned(), Value::from(identity.epoch));
        }
        if let Some(worker) = identity.worker.as_ref() {
            object.insert(
                "worker".to_owned(),
                json!({
                    "sha256": worker.sha256,
                    "bytes": worker.bytes,
                    "target": {
                        "triple": worker.target.triple,
                        "os": worker.target.os,
                        "arch": worker.target.arch,
                        "family": worker.target.family,
                    },
                }),
            );
        }
        let mut encoder = Map::new();
        encoder.insert(
            "model".to_owned(),
            Value::String(identity.encoder_model.clone()),
        );
        encoder.insert(
            "artifact_sha256".to_owned(),
            Value::String(identity.encoder_artifact_sha256.clone()),
        );
        if let Some(repository) = identity.encoder_repository.as_ref() {
            encoder.insert("repository".to_owned(), Value::String(repository.clone()));
        }
        if let Some(revision) = identity.encoder_revision.as_ref() {
            encoder.insert("revision".to_owned(), Value::String(revision.clone()));
        }
        if let Some(provenance) = identity.encoder_revision_provenance.as_ref() {
            encoder.insert(
                "revision_provenance".to_owned(),
                Value::String(provenance.clone()),
            );
        }
        encoder.insert(
            "files".to_owned(),
            Value::Array(
                identity
                    .encoder_files
                    .iter()
                    .map(|file| {
                        json!({
                            "path": file.path,
                            "sha256": file.sha256,
                            "bytes": file.bytes,
                        })
                    })
                    .collect(),
            ),
        );
        if let Some(max_length) = identity.encoder_max_length {
            encoder.insert("max_length".to_owned(), Value::from(max_length));
        }
        if let Some(pooling) = identity.encoder_pooling.as_ref() {
            encoder.insert("pooling".to_owned(), Value::String(pooling.clone()));
        }
        if let Some(normalize) = identity.encoder_normalize {
            encoder.insert("normalize".to_owned(), Value::Bool(normalize));
        }
        object.insert("encoder".to_owned(), Value::Object(encoder));
    }
    payload
}

#[cfg(test)]
fn identity_request_payload(identity: Option<&RuntimeIdentity>) -> Value {
    identity_request_payload_with_epoch(identity, true, true, true)
}

fn production_identity() -> Result<RuntimeIdentity, RustNcmError> {
    let (algorithm, encoder) =
        tracedecay_memory_ncm_runtime::engine::production_identity_declaration()
            .map_err(RustNcmError::HandshakeIdentity)?;
    if algorithm.profile != ALGORITHM_PROFILE {
        return Err(RustNcmError::HandshakeIdentity(
            "production algorithm profile does not match adapter".to_owned(),
        ));
    }
    let pinned = tracedecay_memory_ncm_runtime::embedding::PinnedEncoder::reference()
        .map_err(|error| RustNcmError::HandshakeIdentity(error.to_string()))?;
    verify_model_revision_provenance(&pinned)?;
    let artifact_sha256 = pinned
        .artifact_sha256()
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity(
                "reference encoder manifest omitted ONNX digest".to_owned(),
            )
        })
        .map(str::to_owned)?;
    if encoder.model != pinned.model
        || encoder.artifact_sha256 != artifact_sha256
        || encoder.max_length != pinned.max_length
    {
        return Err(RustNcmError::HandshakeIdentity(
            "production encoder declaration differs from the pinned manifest".to_owned(),
        ));
    }
    let encoder_files = pinned
        .files
        .iter()
        .map(|file| ModelArtifactIdentity {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
            bytes: file.bytes,
        })
        .collect();
    Ok(RuntimeIdentity {
        identity_revision: IDENTITY_REVISION_V2,
        config_sha256: algorithm.config_sha256,
        projection_sha256: String::new(),
        worker: Some(production_worker_identity()?),
        encoder_model: pinned.model,
        encoder_artifact_sha256: artifact_sha256,
        encoder_repository: Some(pinned.repository),
        encoder_revision: Some(pinned.revision),
        encoder_revision_provenance: Some(pinned.revision_provenance),
        encoder_files,
        encoder_max_length: Some(pinned.max_length),
        encoder_pooling: Some(pinned.pooling),
        encoder_normalize: Some(pinned.normalize),
        epoch: 0,
    })
}

fn verify_model_revision_provenance(
    manifest: &tracedecay_memory_ncm_runtime::embedding::PinnedEncoder,
) -> Result<(), RustNcmError> {
    let (path, pointer) = manifest
        .revision_provenance
        .split_once('#')
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity(
                "model revision provenance must include a JSON pointer".to_owned(),
            )
        })?;
    if path != "product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json" {
        return Err(RustNcmError::HandshakeIdentity(
            "model revision provenance points outside the pinned receipt".to_owned(),
        ));
    }
    let receipt: Value = serde_json::from_str(MODEL_REVISION_RECEIPT).map_err(|error| {
        RustNcmError::HandshakeIdentity(format!("parse model revision provenance: {error}"))
    })?;
    let observed = receipt.pointer(pointer).and_then(Value::as_str);
    if observed != Some(manifest.revision.as_str()) {
        return Err(RustNcmError::HandshakeIdentity(
            "model revision provenance does not attest the pinned revision".to_owned(),
        ));
    }
    Ok(())
}

fn production_worker_identity() -> Result<WorkerIdentity, RustNcmError> {
    let manifest: Value = serde_json::from_str(trusted_worker_manifest()).map_err(|error| {
        RustNcmError::HandshakeIdentity(format!("parse worker manifest: {error}"))
    })?;
    let current = current_target_identity();
    let target = manifest
        .get("targets")
        .and_then(Value::as_array)
        .and_then(|targets| {
            targets.iter().find(|target| {
                target.get("triple").and_then(Value::as_str) == Some(current.triple.as_str())
            })
        })
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity(format!(
                "worker manifest has no target {}",
                current.triple
            ))
        })?;
    let target_os = required_str(target.get("os"), "worker.target.os")?;
    let target_arch = required_str(target.get("arch"), "worker.target.arch")?;
    let target_family = required_str(target.get("family"), "worker.target.family")?;
    if target_os != current.os || target_arch != current.arch || target_family != current.family {
        return Err(RustNcmError::HandshakeIdentity(
            "worker manifest target metadata does not match the current target".to_owned(),
        ));
    }
    let bytes = required_nonzero_u64(target.get("bytes"), "worker.bytes")?;
    let sha256 = required_sha256(target.get("sha256"), "worker.sha256")?;
    Ok(WorkerIdentity {
        sha256,
        bytes,
        target: WorkerTargetIdentity {
            triple: current.triple,
            os: target_os,
            arch: target_arch,
            family: target_family,
        },
    })
}

fn current_target_identity() -> WorkerTargetIdentity {
    WorkerTargetIdentity {
        triple: current_target_triple().to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        family: std::env::consts::FAMILY.to_owned(),
    }
}

fn legacy_identity(
    config_sha256: &str,
    encoder_model: &str,
    encoder_artifact_sha256: &str,
) -> RuntimeIdentity {
    RuntimeIdentity {
        identity_revision: IDENTITY_REVISION_V1,
        config_sha256: config_sha256.to_owned(),
        projection_sha256: String::new(),
        worker: None,
        encoder_model: encoder_model.to_owned(),
        encoder_artifact_sha256: encoder_artifact_sha256.to_owned(),
        encoder_repository: None,
        encoder_revision: None,
        encoder_revision_provenance: None,
        encoder_files: Vec::new(),
        encoder_max_length: None,
        encoder_pooling: None,
        encoder_normalize: None,
        epoch: 0,
    }
}

fn descriptor_for(
    identity: &RuntimeIdentity,
    generation: u64,
) -> Result<ProviderDescriptor, RustNcmError> {
    validate_identity(identity)?;
    // Namespace epoch is live state and belongs in the provider instance and
    // ready receipt. The descriptor is the immutable implementation contract,
    // so normalize that runtime field before deriving its identity.
    let descriptor_identity = descriptor_identity(identity);
    let version = implementation_version(&descriptor_identity);
    let mut implementation = Sha256::new();
    implementation.update(
        if descriptor_identity.identity_revision == IDENTITY_REVISION_V2 {
            IMPLEMENTATION_DOMAIN_V2
        } else {
            IMPLEMENTATION_DOMAIN
        },
    );
    digest_field(&mut implementation, version.as_bytes());
    digest_identity(&mut implementation, &descriptor_identity);
    let identity_sha256 = hex_digest(&implementation.finalize());
    let provider_id = OwnedProviderId::new(NCM_PROVIDER_ID)
        .map_err(|error| RustNcmError::HandshakeIdentity(error.to_string()))?;
    let capabilities = capability_ids()?;
    ProviderDescriptor::new(
        provider_id,
        identity_sha256,
        version,
        generation,
        capabilities,
        provider_limits(),
    )
    .map_err(|error| RustNcmError::HandshakeIdentity(error.to_string()))
}

fn descriptor_identity(identity: &RuntimeIdentity) -> RuntimeIdentity {
    let mut descriptor_identity = identity.clone();
    descriptor_identity.epoch = 0;
    descriptor_identity
}

/// Copies the pinned production declaration without a worker, model, or state root.
///
/// The descriptor generation is its registration-time value, not live state.
/// The returned instance and eight-field limits digest must be matched against
/// a successful fresh health response before treating the limits as negotiated.
///
/// # Errors
/// Returns the same declaration/profile errors as the production surface.
#[cfg(feature = "test-helpers")]
pub fn production_provider_declaration_for_test()
-> Result<(ProviderDescriptor, String, String), RustNcmError> {
    let identity = production_identity()?;
    let descriptor = descriptor_from_identity(&identity, 0)?;
    let instance = implementation_version(&identity);
    let mut digest = Sha256::new();
    crate::digest_limits(&mut digest, descriptor.limits);
    let limits_digest = hex_digest(&digest.finalize());
    Ok((descriptor, instance, limits_digest))
}

fn descriptor_from_identity(
    identity: &RuntimeIdentity,
    generation: u64,
) -> Result<ProviderDescriptor, RustNcmError> {
    descriptor_for(identity, generation)
}

fn implementation_version(identity: &RuntimeIdentity) -> String {
    let prefix = identity
        .config_sha256
        .get(..12)
        .unwrap_or(&identity.config_sha256);
    if identity.identity_revision == IDENTITY_REVISION_V1 {
        return format!("ncm-biomem-rs.v1+{prefix}");
    }
    let mut digest = Sha256::new();
    digest.update(IMPLEMENTATION_DOMAIN_V2);
    digest_identity(&mut digest, identity);
    let identity_prefix = hex_digest(&digest.finalize());
    let identity_prefix = identity_prefix.get(..16).unwrap_or(&identity_prefix);
    format!(
        "ncm-biomem-rs.v{}+{prefix}.{identity_prefix}",
        identity.identity_revision
    )
}

fn owner_bound_instance_id(base: &str, worker_incarnation: Option<u64>) -> String {
    worker_incarnation
        .map(|incarnation| format!("{base}.i{incarnation}"))
        .unwrap_or_else(|| base.to_owned())
}

fn capability_ids() -> Result<BTreeSet<OwnedVersionedId>, RustNcmError> {
    [
        "provider.health.v1",
        "observation.accept.v1",
        "recall.query.v1",
        "recall.temporal.v1",
        "feedback.record.v1",
        "maintenance.run.v1",
        "inspection.read.v1",
        "correction.apply.v1",
        "deletion.by_source.v1",
        "snapshot.export.v1",
        "snapshot.restore.v1",
        "replay.apply.v1",
        "memory.advisory_common.v1",
    ]
    .into_iter()
    .map(|value| {
        OwnedVersionedId::new(value)
            .map_err(|error| RustNcmError::HandshakeIdentity(error.to_string()))
    })
    .collect()
}

const fn provider_limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 256 * 1024,
        response_bytes: 1024 * 1024,
        observation_batch_items: 16,
        recall_candidates: 16,
        concurrent_operations: 1,
        operation_millis: 30_000,
        snapshot_bytes: 256 * 1024 * 1024,
        inspection_items: 1_000,
    }
}

fn same_immutable_descriptor(left: &ProviderDescriptor, right: &ProviderDescriptor) -> bool {
    left.provider_id == right.provider_id
        && left.implementation_identity_sha256 == right.implementation_identity_sha256
        && left.state_schema_version == right.state_schema_version
        && left.protocol_major == right.protocol_major
        && left.protocol_minor == right.protocol_minor
        && left.capabilities == right.capabilities
        && left.limits == right.limits
}

fn parse_runtime_identity(reply: &Reply) -> Result<RuntimeIdentity, RustNcmError> {
    let payload = reply.payload.as_ref().ok_or_else(|| {
        RustNcmError::HandshakeIdentity("successful handshake omitted payload".to_owned())
    })?;
    let profile = required_str(payload.pointer("/algorithm/profile"), "algorithm.profile")?;
    if profile != ALGORITHM_PROFILE {
        return Err(RustNcmError::HandshakeIdentity(format!(
            "algorithm profile {profile}"
        )));
    }
    let config_sha256 = required_sha256(
        payload.pointer("/algorithm/config_sha256"),
        "algorithm.config_sha256",
    )?;
    let projection_sha256 = required_sha256(payload.get("projection_sha256"), "projection_sha256")?;
    let encoder_model = required_str(payload.pointer("/encoder/model"), "encoder.model")?;
    let encoder_artifact_sha256 = payload
        .pointer("/encoder/artifact_sha256")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let epoch = payload
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing epoch".to_owned()))?;
    let identity_revision = match payload.get("identity_revision").and_then(Value::as_u64) {
        None => IDENTITY_REVISION_V1,
        Some(revision) => u16::try_from(revision).map_err(|_| {
            RustNcmError::HandshakeIdentity("identity_revision exceeds u16".to_owned())
        })?,
    };
    if identity_revision == IDENTITY_REVISION_V1 {
        let encoder_artifact_sha256 = encoder_artifact_sha256.ok_or_else(|| {
            RustNcmError::HandshakeIdentity("missing encoder.artifact_sha256".to_owned())
        })?;
        return Ok(
            legacy_identity(&config_sha256, &encoder_model, &encoder_artifact_sha256)
                .with_runtime_state(projection_sha256, epoch),
        );
    }
    if identity_revision != IDENTITY_REVISION_V2 {
        return Err(RustNcmError::HandshakeIdentity(format!(
            "unsupported identity revision {identity_revision}"
        )));
    }
    let worker = parse_worker_identity(payload.pointer("/worker"))?;
    let encoder = payload
        .pointer("/encoder")
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing encoder identity".to_owned()))?;
    let encoder_repository = required_str(encoder.get("repository"), "encoder.repository")?;
    let encoder_revision =
        required_immutable_revision(encoder.get("revision"), "encoder.revision")?;
    let encoder_revision_provenance = required_str(
        encoder.get("revision_provenance"),
        "encoder.revision_provenance",
    )?;
    let encoder_max_length = required_nonzero_u64(encoder.get("max_length"), "encoder.max_length")?;
    let encoder_max_length = usize::try_from(encoder_max_length).map_err(|_| {
        RustNcmError::HandshakeIdentity("encoder.max_length exceeds usize".to_owned())
    })?;
    let encoder_pooling = required_str(encoder.get("pooling"), "encoder.pooling")?;
    let encoder_normalize = encoder
        .get("normalize")
        .and_then(Value::as_bool)
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing encoder.normalize".to_owned()))?;
    let encoder_files = parse_encoder_files(encoder.get("files"))?;
    let encoder_artifact_sha256 = encoder_artifact_sha256
        .or_else(|| {
            encoder
                .get("artifact_sha256")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .or_else(|| {
            encoder_files
                .iter()
                .find(|file| file.path == "onnx/model.onnx")
                .map(|file| file.sha256.clone())
        })
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity("missing encoder.artifact_sha256".to_owned())
        })?;
    let identity = RuntimeIdentity {
        identity_revision,
        config_sha256,
        projection_sha256,
        worker: Some(worker),
        encoder_model,
        encoder_artifact_sha256,
        encoder_repository: Some(encoder_repository),
        encoder_revision: Some(encoder_revision),
        encoder_revision_provenance: Some(encoder_revision_provenance),
        encoder_files,
        encoder_max_length: Some(encoder_max_length),
        encoder_pooling: Some(encoder_pooling),
        encoder_normalize: Some(encoder_normalize),
        epoch,
    };
    validate_identity(&identity)?;
    Ok(identity)
}

/// Parses a worker identity against the surface's declaration.
///
/// A test-double/legacy owner may reconcile a sparse V1 ready response with a
/// pinned V2 declaration. A production owner must prove the complete V2 wire
/// identity itself; upgrading a sparse response would let the declaration
/// stand in for fields the worker never attested.
fn parse_runtime_identity_for_expected(
    reply: &Reply,
    expected: Option<&RuntimeIdentity>,
    require_v2: bool,
) -> Result<RuntimeIdentity, RustNcmError> {
    let observed = parse_runtime_identity(reply)?;
    if require_v2 && observed.identity_revision != IDENTITY_REVISION_V2 {
        return Err(RustNcmError::HandshakeIdentity(
            "production worker did not prove a complete V2 identity".to_owned(),
        ));
    }
    let Some(expected) = expected else {
        return Ok(observed);
    };
    if expected.identity_revision == IDENTITY_REVISION_V2
        && observed.identity_revision == IDENTITY_REVISION_V1
    {
        if require_v2 {
            return Err(RustNcmError::HandshakeIdentity(
                "production worker returned a sparse V1 identity".to_owned(),
            ));
        }
        if observed.config_sha256 != expected.config_sha256
            || observed.encoder_model != expected.encoder_model
            || observed.encoder_artifact_sha256 != expected.encoder_artifact_sha256
        {
            return Err(RustNcmError::HandshakeIdentity(
                "legacy worker identity does not match the pinned V2 declaration".to_owned(),
            ));
        }
        let mut reconciled = expected.clone();
        reconciled.projection_sha256 = observed.projection_sha256;
        reconciled.epoch = observed.epoch;
        validate_identity(&reconciled)?;
        return Ok(reconciled);
    }
    if expected.identity_revision == IDENTITY_REVISION_V2
        && observed.identity_revision == IDENTITY_REVISION_V2
        && !runtime_identity_static_matches(&observed, expected)
    {
        return Err(RustNcmError::HandshakeIdentity(
            "worker V2 identity does not match the pinned declaration".to_owned(),
        ));
    }
    Ok(observed)
}

fn runtime_identity_static_matches(observed: &RuntimeIdentity, expected: &RuntimeIdentity) -> bool {
    observed.identity_revision == expected.identity_revision
        && observed.config_sha256 == expected.config_sha256
        && observed.encoder_model == expected.encoder_model
        && observed.encoder_artifact_sha256 == expected.encoder_artifact_sha256
        && observed.worker == expected.worker
        && observed.encoder_repository == expected.encoder_repository
        && observed.encoder_revision == expected.encoder_revision
        && observed.encoder_revision_provenance == expected.encoder_revision_provenance
        && observed.encoder_files == expected.encoder_files
        && observed.encoder_max_length == expected.encoder_max_length
        && observed.encoder_pooling == expected.encoder_pooling
        && observed.encoder_normalize == expected.encoder_normalize
}

impl RuntimeIdentity {
    fn with_runtime_state(mut self, projection_sha256: String, epoch: u64) -> Self {
        self.projection_sha256 = projection_sha256;
        self.epoch = epoch;
        self
    }
}

fn parse_worker_identity(value: Option<&Value>) -> Result<WorkerIdentity, RustNcmError> {
    let worker = value
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing worker identity".to_owned()))?;
    let target = worker
        .get("target")
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing worker.target".to_owned()))?;
    let identity = WorkerIdentity {
        sha256: required_sha256(
            worker
                .get("sha256")
                .or_else(|| worker.get("artifact_sha256")),
            "worker.sha256",
        )?,
        bytes: required_nonzero_u64(
            worker.get("bytes").or_else(|| worker.get("size")),
            "worker.bytes",
        )?,
        target: WorkerTargetIdentity {
            triple: required_str(target.get("triple"), "worker.target.triple")?,
            os: required_str(target.get("os"), "worker.target.os")?,
            arch: required_str(target.get("arch"), "worker.target.arch")?,
            family: required_str(target.get("family"), "worker.target.family")?,
        },
    };
    Ok(identity)
}

fn parse_encoder_files(value: Option<&Value>) -> Result<Vec<ModelArtifactIdentity>, RustNcmError> {
    let files = value
        .and_then(Value::as_array)
        .ok_or_else(|| RustNcmError::HandshakeIdentity("missing encoder.files".to_owned()))?;
    if files.len() != 5 {
        return Err(RustNcmError::HandshakeIdentity(
            "encoder.files must contain exactly five artifacts".to_owned(),
        ));
    }
    let parsed = files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            Ok(ModelArtifactIdentity {
                path: required_str(file.get("path"), &format!("encoder.files[{index}].path"))?,
                sha256: required_sha256(
                    file.get("sha256"),
                    &format!("encoder.files[{index}].sha256"),
                )?,
                bytes: required_nonzero_u64(
                    file.get("bytes").or_else(|| file.get("size")),
                    &format!("encoder.files[{index}].bytes"),
                )?,
            })
        })
        .collect::<Result<Vec<_>, RustNcmError>>()?;
    let paths = parsed
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let expected = [
        "onnx/model.onnx",
        "tokenizer.json",
        "config.json",
        "special_tokens_map.json",
        "tokenizer_config.json",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if paths != expected {
        return Err(RustNcmError::HandshakeIdentity(
            "encoder.files must identify the five pinned model artifacts".to_owned(),
        ));
    }
    Ok(parsed)
}

fn validate_identity(identity: &RuntimeIdentity) -> Result<(), RustNcmError> {
    if identity.identity_revision == IDENTITY_REVISION_V1 {
        return Ok(());
    }
    if identity.identity_revision != IDENTITY_REVISION_V2 {
        return Err(RustNcmError::HandshakeIdentity(format!(
            "unsupported identity revision {}",
            identity.identity_revision
        )));
    }
    let worker = identity.worker.as_ref().ok_or_else(|| {
        RustNcmError::HandshakeIdentity("revision 2 identity omitted worker".to_owned())
    })?;
    if !valid_sha256(&worker.sha256) || worker.bytes == 0 {
        return Err(RustNcmError::HandshakeIdentity(
            "revision 2 worker identity is invalid".to_owned(),
        ));
    }
    if worker.target.triple.is_empty()
        || worker.target.os.is_empty()
        || worker.target.arch.is_empty()
        || worker.target.family.is_empty()
    {
        return Err(RustNcmError::HandshakeIdentity(
            "revision 2 worker target is incomplete".to_owned(),
        ));
    }
    let repository = identity.encoder_repository.as_deref().ok_or_else(|| {
        RustNcmError::HandshakeIdentity("revision 2 encoder repository is missing".to_owned())
    })?;
    let revision = identity.encoder_revision.as_deref().ok_or_else(|| {
        RustNcmError::HandshakeIdentity("revision 2 encoder revision is missing".to_owned())
    })?;
    let provenance = identity
        .encoder_revision_provenance
        .as_deref()
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity(
                "revision 2 encoder revision provenance is missing".to_owned(),
            )
        })?;
    if repository.is_empty()
        || !is_immutable_revision(revision)
        || provenance.is_empty()
        || identity.encoder_files.len() != 5
        || identity.encoder_max_length.is_none()
        || identity
            .encoder_pooling
            .as_deref()
            .is_none_or(str::is_empty)
        || identity.encoder_normalize.is_none()
    {
        return Err(RustNcmError::HandshakeIdentity(
            "revision 2 encoder identity is incomplete".to_owned(),
        ));
    }
    if identity
        .encoder_files
        .iter()
        .any(|file| file.path.is_empty() || !valid_sha256(&file.sha256) || file.bytes == 0)
    {
        return Err(RustNcmError::HandshakeIdentity(
            "revision 2 encoder artifact identity is invalid".to_owned(),
        ));
    }
    let onnx = identity
        .encoder_files
        .iter()
        .find(|file| file.path == "onnx/model.onnx")
        .ok_or_else(|| {
            RustNcmError::HandshakeIdentity(
                "revision 2 encoder files omitted onnx/model.onnx".to_owned(),
            )
        })?;
    if onnx.sha256 != identity.encoder_artifact_sha256 {
        return Err(RustNcmError::HandshakeIdentity(
            "encoder artifact digest does not match its ONNX file".to_owned(),
        ));
    }
    Ok(())
}

fn is_immutable_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_immutable_revision(value: Option<&Value>, field: &str) -> Result<String, RustNcmError> {
    let revision = required_str(value, field)?;
    if is_immutable_revision(&revision) {
        Ok(revision)
    } else {
        Err(RustNcmError::HandshakeIdentity(format!("invalid {field}")))
    }
}

fn required_nonzero_u64(value: Option<&Value>, field: &str) -> Result<u64, RustNcmError> {
    let value = value
        .and_then(Value::as_u64)
        .filter(|value| *value != 0)
        .ok_or_else(|| RustNcmError::HandshakeIdentity(format!("missing or empty {field}")))?;
    Ok(value)
}

fn required_str(value: Option<&Value>, field: &str) -> Result<String, RustNcmError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| RustNcmError::HandshakeIdentity(format!("missing {field}")))
}

fn required_sha256(value: Option<&Value>, field: &str) -> Result<String, RustNcmError> {
    let value = required_str(value, field)?;
    if valid_sha256(&value) {
        Ok(value)
    } else {
        Err(RustNcmError::HandshakeIdentity(format!("invalid {field}")))
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_identity(digest: &mut Sha256, identity: &RuntimeIdentity) {
    digest.update(identity.identity_revision.to_be_bytes());
    digest_field(digest, identity.config_sha256.as_bytes());
    digest.update(identity.epoch.to_be_bytes());
    if identity.identity_revision == IDENTITY_REVISION_V1 {
        digest_field(digest, identity.encoder_model.as_bytes());
        digest_field(digest, identity.encoder_artifact_sha256.as_bytes());
        return;
    }
    if let Some(worker) = identity.worker.as_ref() {
        digest_field(digest, worker.sha256.as_bytes());
        digest.update(worker.bytes.to_be_bytes());
        digest_field(digest, worker.target.triple.as_bytes());
        digest_field(digest, worker.target.os.as_bytes());
        digest_field(digest, worker.target.arch.as_bytes());
        digest_field(digest, worker.target.family.as_bytes());
    }
    digest_field(digest, identity.encoder_model.as_bytes());
    digest_field(
        digest,
        identity
            .encoder_repository
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    digest_field(
        digest,
        identity
            .encoder_revision
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    digest_field(
        digest,
        identity
            .encoder_revision_provenance
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    digest.update(
        u64::try_from(identity.encoder_files.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for file in &identity.encoder_files {
        digest_field(digest, file.path.as_bytes());
        digest.update(file.bytes.to_be_bytes());
        digest_field(digest, file.sha256.as_bytes());
    }
    digest.update(
        u64::try_from(identity.encoder_max_length.unwrap_or_default())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest_field(
        digest,
        identity
            .encoder_pooling
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    digest.update([u8::from(identity.encoder_normalize.unwrap_or(false))]);
}

#[cfg(test)]
fn ready_receipt(namespace: &str, identity: &RuntimeIdentity) -> String {
    ready_receipt_with_incarnation(namespace, identity, None)
}

fn ready_receipt_for_worker(
    namespace: &str,
    identity: &RuntimeIdentity,
    worker_incarnation: u64,
) -> String {
    ready_receipt_with_incarnation(namespace, identity, Some(worker_incarnation))
}

fn ready_receipt_with_incarnation(
    namespace: &str,
    identity: &RuntimeIdentity,
    worker_incarnation: Option<u64>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(if identity.identity_revision == IDENTITY_REVISION_V2 {
        READY_DOMAIN_V2
    } else {
        READY_DOMAIN
    });
    digest_field(&mut digest, namespace.as_bytes());
    digest_field(&mut digest, ALGORITHM_PROFILE.as_bytes());
    digest_identity(&mut digest, identity);
    digest_field(&mut digest, identity.projection_sha256.as_bytes());
    digest.update(identity.epoch.to_be_bytes());
    if let Some(worker_incarnation) = worker_incarnation {
        digest.update(worker_incarnation.to_be_bytes());
    }
    hex_digest(&digest.finalize())
}

fn handshake_failure(
    provider: &OwnedProviderId,
    request: &NcmSurfaceHandshakeRequest,
    code: TerminalCode,
    diagnostic: &'static str,
    observed_generation: Option<u64>,
) -> NcmSurfaceHandshakeResponse {
    NcmSurfaceHandshakeResponse {
        terminal: surface_terminal(
            provider,
            ProviderOperation::Handshake,
            &request.request_id,
            request.namespace.as_str(),
            code,
            CommittedEffectEvidence::none(observed_generation),
            Some(diagnostic),
        ),
        descriptor: None,
        provider_instance_id: None,
        namespace: None,
        effective_limits: None,
        ready_receipt_sha256: None,
        challenge_response_sha256: None,
        warnings: Vec::new(),
    }
}

/// Builds a terminal record for the surface. The provider identity is the one
/// validated at construction, so no fallible re-parse of the literal is needed.
fn surface_terminal(
    provider: &OwnedProviderId,
    operation: ProviderOperation,
    operation_id: &str,
    namespace: &str,
    code: TerminalCode,
    effect: CommittedEffectEvidence,
    diagnostic: Option<&str>,
) -> TerminalRecord {
    let provider = provider.clone();
    match TerminalRecord::new(
        operation,
        provider.clone(),
        code,
        effect,
        FallbackDirective::forbidden(),
        operation_id,
        namespace,
        diagnostic.map(str::to_owned),
    ) {
        Ok(terminal) => terminal,
        Err(_) => TerminalRecord::failure_before_dispatch(
            operation,
            provider,
            TerminalCode::InternalFailure,
            operation_id,
            namespace,
            None,
            "ncm.rust.terminal_construction_failed",
        ),
    }
}

fn pre_dispatch_reply(
    provider: &OwnedProviderId,
    call: &NcmSurfaceCall,
    code: TerminalCode,
    diagnostic: &'static str,
) -> ProviderReply {
    ProviderReply {
        terminal: surface_terminal(
            provider,
            call.operation,
            &call.operation_id,
            call.namespace.as_str(),
            code,
            CommittedEffectEvidence::none(Some(call.expected_state_generation)),
            Some(diagnostic),
        ),
        payload: None,
        warnings: Vec::new(),
        extensions: Vec::new(),
        state_generation: call.expected_state_generation,
    }
}

fn worker_error_reply(
    provider: &OwnedProviderId,
    call: &NcmSurfaceCall,
    error: &WorkerCallError,
) -> ProviderReply {
    match error {
        WorkerCallError::IncarnationChanged { .. } => pre_dispatch_reply(
            provider,
            call,
            TerminalCode::StaleIdentity,
            "ncm.rust.worker_incarnation_changed",
        ),
        WorkerCallError::Client(error @ ClientError::EffectUnknown { .. })
            if call.operation.mutates_provider_state() =>
        {
            let receipt = unknown_receipt(call, error);
            let action = format!("ncm.worker.reconcile-idempotency.v1:{}", &receipt[..16]);
            let effect = CommittedEffectEvidence::unknown(receipt, action).unwrap_or_else(|_| {
                CommittedEffectEvidence::unknown_from_reconciliation_digest([0; 32])
            });
            ProviderReply {
                terminal: surface_terminal(
                    provider,
                    call.operation,
                    &call.operation_id,
                    call.namespace.as_str(),
                    TerminalCode::EffectUnknown,
                    effect,
                    Some("ncm.rust.worker_effect_unknown"),
                ),
                payload: None,
                warnings: Vec::new(),
                extensions: Vec::new(),
                state_generation: call.expected_state_generation,
            }
        }
        WorkerCallError::Client(error) => pre_dispatch_reply(
            provider,
            call,
            client_terminal_code(error),
            client_diagnostic(error),
        ),
    }
}

fn unknown_effect(receipt: &str, action: String) -> CommittedEffectEvidence {
    CommittedEffectEvidence::unknown(receipt, action).unwrap_or_else(|_| {
        let digest = Sha256::digest(receipt.as_bytes());
        CommittedEffectEvidence::unknown_from_reconciliation_digest(digest.into())
    })
}

/// Validates the metadata needed to construct a replay partial-effect
/// partition.  The adapter's full replay validator runs later, but the
/// partition is effect evidence and must never be built from malformed values.
fn valid_replay_partial_metadata(call: &NcmSurfaceCall, payload: &Value) -> bool {
    let request = serde_json::from_slice::<Value>(&call.payload.bytes).ok();
    let Some(request) = request else {
        return false;
    };
    let Some(request) = request.get("common_portability") else {
        return false;
    };
    let Some(request_items) = request.get("items").and_then(Value::as_array) else {
        return false;
    };
    let Some(response_items) = payload.get("items").and_then(Value::as_array) else {
        return false;
    };
    let Some(first) = request.get("first_source_sequence").and_then(Value::as_u64) else {
        return false;
    };
    let Some(last) = request.get("last_source_sequence").and_then(Value::as_u64) else {
        return false;
    };
    let Some(previous) = request
        .get("expected_previous_acknowledged_sequence")
        .and_then(Value::as_u64)
    else {
        return false;
    };
    let Some(acknowledged) = payload.get("acknowledged_sequence").and_then(Value::as_u64) else {
        return false;
    };
    let Some(expected_len) = last.checked_sub(first).and_then(|span| span.checked_add(1)) else {
        return false;
    };
    if first == 0
        || last < first
        || expected_len != request_items.len() as u64
        || request_items.is_empty()
        || response_items.len() != request_items.len()
        || payload.get("first_source_sequence").and_then(Value::as_u64) != Some(first)
        || payload.get("last_source_sequence").and_then(Value::as_u64) != Some(last)
        || acknowledged < previous
        || acknowledged > previous.max(last)
    {
        return false;
    }
    let mut sequences = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut delivery_keys = BTreeSet::new();
    for (index, (request_item, response_item)) in
        request_items.iter().zip(response_items).enumerate()
    {
        let Some(sequence) = response_item.get("source_sequence").and_then(Value::as_u64) else {
            return false;
        };
        let Some(receipt) = response_item.get("receipt_digest").and_then(Value::as_str) else {
            return false;
        };
        let Some(delivery_key) = request_item.get("delivery_key").and_then(Value::as_str) else {
            return false;
        };
        let Some(request_sequence) = request_item.get("source_sequence").and_then(Value::as_u64)
        else {
            return false;
        };
        let Some(request_receipt) = request_item.get("receipt_digest").and_then(Value::as_str)
        else {
            return false;
        };
        if sequence == 0
            || sequence != first.saturating_add(index as u64)
            || sequence != request_sequence
            || receipt != request_receipt
            || !valid_sha256(receipt)
            || delivery_key.is_empty()
            || !sequences.insert(sequence)
            || !receipts.insert(receipt.to_owned())
            || !delivery_keys.insert(delivery_key.to_owned())
        {
            return false;
        }
    }
    true
}

fn worker_reply(provider: &OwnedProviderId, call: &NcmSurfaceCall, reply: Reply) -> ProviderReply {
    let replay_accounting = call.operation == ProviderOperation::Replay
        && reply
            .payload
            .as_ref()
            .is_some_and(|payload| payload["common_portability"] == "replay");
    let replay_partial = replay_accounting
        && reply.outcome == Outcome::Success
        && reply
            .payload
            .as_ref()
            .is_some_and(|payload| payload["partial"] == true);
    let replay_partial_metadata_invalid = replay_partial
        && reply
            .payload
            .as_ref()
            .is_none_or(|payload| !valid_replay_partial_metadata(call, payload));
    let maintenance_partial = call.operation == ProviderOperation::Maintenance
        && reply.outcome == Outcome::Success
        && reply.payload.as_ref().is_some_and(|payload| {
            payload["common_control"] == "maintenance" && payload["partial"] == true
        });
    let terminal_code = if replay_partial_metadata_invalid {
        // A committed replay page cannot be partitioned safely when its
        // sequence, receipt, delivery reference, or acknowledgement metadata
        // is malformed. Report uncertainty with the worker receipt rather than
        // manufacturing an item reference from zero or an invalid digest.
        TerminalCode::EffectUnknown
    } else if replay_partial {
        TerminalCode::PartialEffect
    } else if maintenance_partial {
        // Common maintenance may have scanned only one bounded page.  This is
        // degraded coverage with a resumable cursor, not a committed partial
        // mutation and not a terminal no-op success.
        TerminalCode::Partial
    } else {
        outcome_terminal_code(&reply.outcome)
    };
    let success = matches!(reply.outcome, Outcome::Success | Outcome::Empty);
    let replayed = reply
        .payload
        .as_ref()
        .and_then(|payload| payload.get("replayed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let receipt = worker_receipt(call.operation, &reply);
    let effect = if call.operation.mutates_provider_state() {
        if replay_partial_metadata_invalid {
            unknown_effect(
                &receipt,
                format!("ncm.worker.reconcile-idempotency.v1:{}", &receipt[..16]),
            )
        } else if reply.outcome == Outcome::Success
            && reply
                .payload
                .as_ref()
                .is_some_and(|payload| payload["no_change"] == true)
        {
            CommittedEffectEvidence::none(Some(call.expected_state_generation))
        } else if replay_partial {
            let mut committed = Vec::new();
            let mut uncommitted = Vec::new();
            for item in reply
                .payload
                .as_ref()
                .and_then(|payload| payload["items"].as_array())
                .into_iter()
                .flatten()
            {
                let reference = format!(
                    "ncm.replay.item.{}.{}",
                    item["source_sequence"].as_u64().unwrap_or(0),
                    item["receipt_digest"].as_str().unwrap_or("invalid")
                );
                let acknowledged = reply
                    .payload
                    .as_ref()
                    .and_then(|payload| payload["acknowledged_sequence"].as_u64())
                    .unwrap_or(0);
                if item["source_sequence"]
                    .as_u64()
                    .is_some_and(|sequence| sequence <= acknowledged)
                {
                    committed.push(reference);
                } else {
                    uncommitted.push(reference);
                }
            }
            if uncommitted.is_empty() {
                uncommitted.push("ncm.replay.page_ack".to_owned());
            }
            CommittedEffectEvidence::partial(
                "ncm.replay.partition.v1",
                call.expected_state_generation,
                reply.state_generation,
                committed,
                uncommitted,
                &receipt,
                format!("ncm.worker.reconcile-idempotency.v1:{}", &receipt[..16]),
                &receipt,
            )
            .unwrap_or_else(|_| {
                unknown_effect(
                    &receipt,
                    format!("ncm.worker.reconcile-idempotency.v1:{}", &receipt[..16]),
                )
            })
        } else if reply.outcome == Outcome::Success && replayed {
            CommittedEffectEvidence::duplicate(
                call.expected_state_generation,
                call.idempotency_key.as_deref().unwrap_or("ncm-no-key"),
                format!("ncm.engine.operation.{}", &receipt[..16]),
                &receipt,
            )
            .unwrap_or_else(|_| {
                CommittedEffectEvidence::unknown_from_reconciliation_digest([0; 32])
            })
        } else if reply.outcome == Outcome::Success {
            CommittedEffectEvidence::committed(
                call.expected_state_generation,
                reply.state_generation,
                vec![format!("ncm.{}.committed", call.operation.as_wire())],
                &receipt,
                &receipt,
            )
            .unwrap_or_else(|_| {
                CommittedEffectEvidence::unknown_from_reconciliation_digest([0; 32])
            })
        } else if reply.outcome == Outcome::EffectUnknown {
            CommittedEffectEvidence::unknown(
                &receipt,
                format!("ncm.worker.reconcile-idempotency.v1:{}", &receipt[..16]),
            )
            .unwrap_or_else(|_| {
                CommittedEffectEvidence::unknown_from_reconciliation_digest([0; 32])
            })
        } else {
            CommittedEffectEvidence::none(Some(call.expected_state_generation))
        }
    } else {
        CommittedEffectEvidence::none(Some(call.expected_state_generation))
    };
    let payload = if !replay_partial_metadata_invalid
        && (success || (replay_accounting && reply.outcome == Outcome::EffectUnknown))
    {
        reply
            .payload
            .as_ref()
            .and_then(|payload| canonical_response_payload(call, payload).ok())
    } else {
        None
    };
    let diagnostic = if replay_partial_metadata_invalid {
        Some("ncm.rust.replay_partial_metadata_invalid")
    } else if replay_partial {
        Some("ncm.rust.replay_partial")
    } else {
        (!success).then(|| worker_diagnostic(&reply))
    };
    ProviderReply {
        terminal: surface_terminal(
            provider,
            call.operation,
            &call.operation_id,
            call.namespace.as_str(),
            terminal_code,
            effect,
            diagnostic,
        ),
        payload,
        warnings: Vec::new(),
        extensions: Vec::new(),
        state_generation: (if replayed {
            call.expected_state_generation
        } else {
            reply.state_generation
        })
        .max(if call.operation.mutates_provider_state() {
            0
        } else {
            call.expected_state_generation
        }),
    }
}

fn canonical_response_payload(
    call: &NcmSurfaceCall,
    value: &Value,
) -> Result<CanonicalPayload, ()> {
    let mut presentation = value.clone();
    if let Some(object) = presentation.as_object_mut() {
        // The receipt was computed from its immutable retained basis above.
        // That basis contains private delivery keys and belongs in the durable
        // journal, never in the scope-safe surface response.
        object.remove("_retained_receipt");
        if call.operation == ProviderOperation::Replay {
            object.remove("request_semantic_sha256");
        }
    }
    let bytes = serde_json::to_vec(&presentation).map_err(|_| ())?;
    let sha256 = hex_digest(&Sha256::digest(&bytes));
    CanonicalPayload::new(call.payload.contract_id.clone(), bytes, sha256).map_err(|_| ())
}

fn wire_operation(operation: ProviderOperation) -> Operation {
    match operation {
        ProviderOperation::Handshake => Operation::Handshake,
        ProviderOperation::Health => Operation::Health,
        ProviderOperation::Observe => Operation::Observe,
        ProviderOperation::Recall => Operation::Recall,
        ProviderOperation::Feedback => Operation::Feedback,
        ProviderOperation::Maintenance => Operation::Maintenance,
        ProviderOperation::Inspection => Operation::Inspection,
        ProviderOperation::Correction => Operation::Correction,
        ProviderOperation::DeleteBySource => Operation::DeleteBySource,
        ProviderOperation::SnapshotExport => Operation::SnapshotExport,
        ProviderOperation::SnapshotRestore => Operation::SnapshotRestore,
        ProviderOperation::Replay => Operation::Replay,
    }
}

fn translate_payload(call: &NcmSurfaceCall) -> Result<Value, &'static str> {
    let value: Value =
        serde_json::from_slice(&call.payload.bytes).map_err(|_| "ncm.rust.payload_invalid_json")?;
    let object = value.as_object().ok_or("ncm.rust.payload_not_object")?;
    if call.operation == ProviderOperation::Maintenance
        && (object.get("common_control").is_none() || object.get("common_portability").is_some())
    {
        return Err("ncm.rust.maintenance_requires_common_control");
    }
    if let Some(common) = object.get("common_portability") {
        let mut common = common.clone();
        if call.operation.mutates_provider_state() {
            common["idempotency_key"] = json!(required_key(call)?);
        }
        if call.operation == ProviderOperation::Replay {
            let items = common["items"]
                .as_array_mut()
                .ok_or("ncm.rust.replay_items_missing")?;
            for item in items {
                if item["observation"].is_null() {
                    continue;
                }
                let observation = item["observation"]
                    .as_object()
                    .ok_or("ncm.rust.replay_observation_missing")?;
                let mut translated = translate_observe(call, observation)?;
                translated["idempotency_key"] = item["delivery_key"].clone();
                item["observation"] = translated;
            }
        }
        return Ok(json!({"common_portability": common}));
    }
    if let Some(common) = object.get("common_control") {
        let mut common = common.clone();
        if call.operation.mutates_provider_state() {
            common["idempotency_key"] = json!(required_key(call)?);
        }
        if let Some(replacement) = common.get("replacement").and_then(Value::as_object) {
            let replacement = translate_observe(call, replacement)?;
            common["replacement"] = replacement;
        }
        return Ok(json!({"common_control": common}));
    }
    match call.operation {
        ProviderOperation::Handshake => Err("ncm.rust.handshake_wrong_port"),
        ProviderOperation::Health
        | ProviderOperation::Inspection
        | ProviderOperation::SnapshotExport => Ok(Value::Object(Map::new())),
        ProviderOperation::Observe => translate_observe(call, object),
        ProviderOperation::Recall => {
            let query = string_at(object, &["query_text", "query"])
                .ok_or("ncm.rust.recall_query_missing")?;
            let top_k = u64_at(object, &["top_k", "maximum_candidates"])
                .unwrap_or(5)
                .min(16);
            let mut payload = json!({"query_text": query, "top_k": top_k});
            if let Some(selection) = object.get("selection") {
                payload["selection"] = selection.clone();
            }
            Ok(payload)
        }
        ProviderOperation::Feedback => {
            let records = object
                .get("record_ids")
                .and_then(Value::as_array)
                .ok_or("ncm.rust.feedback_records_missing")?;
            Ok(json!({
                "idempotency_key": required_key(call)?,
                "record_ids": records
            }))
        }
        ProviderOperation::Correction => Ok(json!({
            "idempotency_key": required_key(call)?,
            "superseded": u64_at(object, &["superseded", "superseded_record_id"])
                .ok_or("ncm.rust.correction_superseded_missing")?,
            "superseding": u64_at(object, &["superseding", "superseding_record_id"])
                .ok_or("ncm.rust.correction_superseding_missing")?,
            "evidence": string_at(object, &["evidence", "evidence_sha256"])
                .ok_or("ncm.rust.correction_evidence_missing")?
        })),
        ProviderOperation::Maintenance => {
            // Maintenance is admitted by the common-control projector.  A raw
            // operation payload would bypass its admission capsule, cursor
            // binding, and expected-generation fence.
            Err("ncm.rust.maintenance_requires_common_control")
        }
        ProviderOperation::DeleteBySource => Ok(json!({
            "idempotency_key": required_key(call)?,
            "source": string_at(object, &["source", "source_id", "forget_source_key"])
                .ok_or("ncm.rust.delete_source_missing")?
        })),
        ProviderOperation::SnapshotRestore => {
            let snapshot = object
                .get("snapshot")
                .or_else(|| object.get("bytes"))
                .and_then(Value::as_array)
                .ok_or("ncm.rust.snapshot_bytes_missing")?;
            Ok(json!({"idempotency_key": required_key(call)?, "snapshot": snapshot}))
        }
        ProviderOperation::Replay => Ok(Value::Object(Map::new())),
    }
}

fn translate_observe(
    call: &NcmSurfaceCall,
    object: &Map<String, Value>,
) -> Result<Value, &'static str> {
    let kind =
        string_at(object, &["observation_kind"]).ok_or("ncm.rust.observation_kind_missing")?;
    let payload_contract =
        string_at(object, &["payload_contract"]).ok_or("ncm.rust.observation_contract_missing")?;
    if expected_observation_contract(&kind) != Some(payload_contract.as_str()) {
        return Err("ncm.rust.observation_contract_mismatch");
    }
    let canonical = object
        .get("canonical_payload")
        .and_then(Value::as_object)
        .ok_or("ncm.rust.observation_payload_missing")?;
    let source =
        observation_source(object, canonical).ok_or("ncm.rust.observation_source_missing")?;
    let (key_text, value_text) =
        observation_text(&kind, canonical).ok_or("ncm.rust.observation_text_missing")?;
    let affect = object
        .get("affect")
        .or_else(|| canonical.get("affect"))
        .cloned()
        .unwrap_or(Value::Null);
    let surprise = f32_at(object, canonical, "surprise").unwrap_or(0.0);
    let intensity = f32_at(object, canonical, "intensity").unwrap_or(1.0);
    let provenance = object
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| json!({"observation_kind": kind, "payload_contract": payload_contract}));
    let payload_sha256 = observe_digest(
        &source,
        &key_text,
        &value_text,
        &affect,
        surprise,
        intensity,
        &provenance,
    )
    .map_err(|_| "ncm.rust.observation_digest_failed")?;
    let mut translated = json!({
        "idempotency_key": required_key(call)?,
        "payload_sha256": payload_sha256,
        "source": source,
        "key_text": key_text,
        "value_text": value_text,
        "affect": affect,
        "surprise": surprise,
        "intensity": intensity,
        "provenance": provenance
    });
    for field in ["test_sleep_before_ms", "test_sleep_after_commit_ms"] {
        if let Some(value) = object.get(field)
            && let Some(target) = translated.as_object_mut()
        {
            target.insert(field.to_owned(), value.clone());
        }
    }
    Ok(translated)
}

fn expected_observation_contract(kind: &str) -> Option<&'static str> {
    match kind {
        "session.message_committed.v1" => Some("tracedecay.memory.observation.session-message.v1"),
        "tool.execution_settled.v1" => Some("tracedecay.memory.observation.tool-execution.v1"),
        "source.edit_settled.v1" => Some("tracedecay.memory.observation.source-edit.v1"),
        "test.execution_settled.v1" => Some("tracedecay.memory.observation.test-execution.v1"),
        "diagnostic.observed.v1" => Some("tracedecay.memory.observation.diagnostic.v1"),
        "git.evidence_observed.v1" => Some("tracedecay.memory.observation.git-evidence.v1"),
        "native.fact_promoted.v1" => Some("tracedecay.memory.observation.native-fact-promotion.v1"),
        "feedback.outcome_settled.v1" => Some("tracedecay.memory.observation.feedback-outcome.v1"),
        "automation.outcome_settled.v1" => {
            Some("tracedecay.memory.observation.automation-outcome.v1")
        }
        _ => None,
    }
}

fn observation_source(
    envelope: &Map<String, Value>,
    canonical: &Map<String, Value>,
) -> Option<String> {
    string_at(canonical, &["forget_source_key"])
        .or_else(|| string_at(envelope, &["source_identity"]))
        .or_else(|| {
            envelope
                .get("source_identity")
                .and_then(Value::as_object)
                .and_then(|source| {
                    string_at(
                        source,
                        &[
                            "forget_source_key",
                            "source_event_sha256",
                            "source_event_id",
                        ],
                    )
                })
        })
}

fn observation_text(kind: &str, payload: &Map<String, Value>) -> Option<(String, String)> {
    if let (Some(key), Some(value)) = (
        payload.get("_ncm_key_text").and_then(Value::as_str),
        payload.get("_ncm_value_text").and_then(Value::as_str),
    ) {
        return Some((key.to_owned(), value.to_owned()));
    }
    let nested = payload
        .get("payload")
        .and_then(Value::as_object)
        .unwrap_or(payload);
    let pair = match kind {
        "session.message_committed.v1" => {
            let content = string_at(nested, &["content", "message", "text", "summary"])?;
            let role = string_at(nested, &["role", "message_kind", "summary"])?;
            (Some(content.clone()), Some(format!("{role}: {content}")))
        }
        "tool.execution_settled.v1" => (
            string_at(nested, &["command", "tool_name", "tool", "summary"]),
            string_at(
                nested,
                &["outcome_summary", "result", "output", "outcome", "summary"],
            ),
        ),
        "source.edit_settled.v1" => (
            string_at(nested, &["change_summary", "path_summary", "summary"]),
            string_at(
                nested,
                &["result_summary", "diff_summary", "content", "summary"],
            ),
        ),
        "test.execution_settled.v1" => (
            string_at(nested, &["test_name", "command", "summary"]),
            string_at(nested, &["outcome_summary", "result", "outcome", "summary"]),
        ),
        "diagnostic.observed.v1" => (
            string_at(nested, &["code", "diagnostic", "summary"]),
            string_at(nested, &["message", "detail", "summary"]),
        ),
        "git.evidence_observed.v1" => (
            string_at(nested, &["commit", "ref", "summary"]),
            string_at(nested, &["message", "evidence", "summary"]),
        ),
        "native.fact_promoted.v1" => (
            string_at(nested, &["subject", "key", "summary"]),
            string_at(nested, &["fact", "value", "content", "summary"]),
        ),
        "feedback.outcome_settled.v1" | "automation.outcome_settled.v1" => (
            string_at(nested, &["action", "job", "summary"]),
            string_at(nested, &["outcome_summary", "result", "outcome", "summary"]),
        ),
        _ => (None, None),
    };
    match pair {
        (Some(key), Some(value)) if !key.trim().is_empty() && !value.trim().is_empty() => {
            Some((key, value))
        }
        _ => None,
    }
}

fn observe_digest(
    source: &str,
    key_text: &str,
    value_text: &str,
    affect: &Value,
    surprise: f32,
    intensity: f32,
    provenance: &Value,
) -> Result<String, serde_json::Error> {
    let source = serde_json::to_string(source)?;
    let key_text = serde_json::to_string(key_text)?;
    let value_text = serde_json::to_string(value_text)?;
    let affect = serde_json::to_string(affect)?;
    let surprise = serde_json::to_string(&surprise)?;
    let intensity = serde_json::to_string(&intensity)?;
    let mut effect_provenance = provenance.clone();
    if let Some(object) = effect_provenance.as_object_mut() {
        object.remove("delivery_capsule");
    }
    let provenance = serde_json::to_string(&effect_provenance)?;
    let bytes = format!(
        "{{\"source\":{source},\"key_text\":{key_text},\"value_text\":{value_text},\"affect\":{affect},\"surprise\":{surprise},\"intensity\":{intensity},\"provenance\":{provenance}}}"
    );
    Ok(hex_digest(&Sha256::digest(bytes.as_bytes())))
}

fn required_key(call: &NcmSurfaceCall) -> Result<&str, &'static str> {
    call.idempotency_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or("ncm.rust.idempotency_key_missing")
}

fn string_at(object: &Map<String, Value>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn u64_at(object: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(Value::as_u64))
}

fn f32_at(envelope: &Map<String, Value>, payload: &Map<String, Value>, field: &str) -> Option<f32> {
    envelope
        .get(field)
        .or_else(|| payload.get(field))
        .and_then(Value::as_f64)
        .map(|value| value as f32)
        .filter(|value| value.is_finite())
}

fn outcome_terminal_code(outcome: &Outcome) -> TerminalCode {
    match outcome {
        Outcome::Success => TerminalCode::Success,
        Outcome::Empty => TerminalCode::SuccessZeroResults,
        Outcome::Rejected(RejectReason::IdempotencyConflict) => TerminalCode::Conflict,
        Outcome::Rejected(RejectReason::SourceRevoked) => TerminalCode::Unauthorized,
        Outcome::Rejected(RejectReason::InvalidRequest(_) | RejectReason::UnknownRecord(_)) => {
            TerminalCode::InvalidRequest
        }
        Outcome::Busy | Outcome::BudgetExceeded => TerminalCode::CapacityExceeded,
        Outcome::Cancelled => TerminalCode::Cancelled,
        Outcome::EffectUnknown => TerminalCode::EffectUnknown,
        Outcome::Incompatible => TerminalCode::StateIncompatible,
        Outcome::Corrupt => TerminalCode::ResetRequired,
        Outcome::Unavailable(_) => TerminalCode::ProviderUnavailable,
        Outcome::Unsupported => TerminalCode::CapabilityUnsupported,
    }
}

fn worker_diagnostic(reply: &Reply) -> &'static str {
    match reply.error.as_ref().map(|error| error.kind.as_str()) {
        Some("oversized_reply" | "oversized_frame") => "ncm.rust.worker_reply_oversized",
        Some("malformed_json") => "ncm.rust.worker_reply_malformed",
        _ => outcome_diagnostic(&reply.outcome),
    }
}

fn outcome_diagnostic(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Success | Outcome::Empty => "ncm.rust.success",
        Outcome::Rejected(RejectReason::IdempotencyConflict) => "ncm.rust.idempotency_conflict",
        Outcome::Rejected(RejectReason::SourceRevoked) => "ncm.rust.source_revoked",
        Outcome::Rejected(_) => "ncm.rust.request_rejected",
        Outcome::Busy => "ncm.rust.worker_busy",
        Outcome::Cancelled => "ncm.rust.worker_cancelled",
        Outcome::EffectUnknown => "ncm.rust.worker_effect_unknown",
        Outcome::Incompatible => "ncm.rust.state_incompatible",
        Outcome::Corrupt => "ncm.rust.state_corrupt",
        Outcome::Unavailable(_) => "ncm.rust.worker_unavailable",
        Outcome::Unsupported => "ncm.rust.operation_unsupported",
        Outcome::BudgetExceeded => "ncm.rust.budget_exceeded",
    }
}

fn client_terminal_code(error: &ClientError) -> TerminalCode {
    match error {
        ClientError::Busy => TerminalCode::CapacityExceeded,
        ClientError::Cancelled => TerminalCode::Cancelled,
        ClientError::EffectUnknown { .. } => TerminalCode::EffectUnknown,
        ClientError::RequestTooLarge => TerminalCode::InvalidRequest,
        ClientError::Disabled
        | ClientError::Spawn(_)
        | ClientError::Unavailable(_)
        | ClientError::RestartExhausted
        | ClientError::Transport(_)
        | ClientError::MalformedReply(_)
        | ClientError::WorkerExited
        | ClientError::UnknownIdempotencyKey
        | ClientError::UnknownRetentionLimit { .. }
        | ClientError::UnknownRetentionConflict { .. }
        | ClientError::OwnerStopped => TerminalCode::ProviderUnavailable,
    }
}

fn client_diagnostic(error: &ClientError) -> &'static str {
    match error {
        ClientError::Disabled => "ncm.rust.worker_disabled",
        ClientError::Busy => "ncm.rust.worker_busy",
        ClientError::Cancelled => "ncm.rust.worker_cancelled",
        ClientError::EffectUnknown { .. } => "ncm.rust.worker_effect_unknown",
        ClientError::RequestTooLarge => "ncm.rust.request_too_large",
        ClientError::Spawn(_) => "ncm.rust.worker_spawn_failed",
        ClientError::Unavailable(_) => "ncm.rust.worker_unavailable",
        ClientError::RestartExhausted => "ncm.rust.worker_restart_exhausted",
        ClientError::Transport(_) => "ncm.rust.worker_transport_failed",
        ClientError::MalformedReply(_) => "ncm.rust.worker_reply_malformed",
        ClientError::WorkerExited => "ncm.rust.worker_exited",
        ClientError::UnknownIdempotencyKey => "ncm.rust.reconciliation_key_unknown",
        ClientError::UnknownRetentionLimit { .. } => "ncm.rust.worker_unknown_retention_limit",
        ClientError::UnknownRetentionConflict { .. } => {
            "ncm.rust.worker_unknown_retention_conflict"
        }
        ClientError::OwnerStopped => "ncm.rust.worker_owner_stopped",
    }
}

fn worker_terminal_code(error: &WorkerCallError) -> TerminalCode {
    match error {
        WorkerCallError::Client(error) => client_terminal_code(error),
        WorkerCallError::IncarnationChanged { .. } => TerminalCode::StaleIdentity,
    }
}

fn worker_diagnostic_for_error(error: &WorkerCallError) -> &'static str {
    match error {
        WorkerCallError::Client(error) => client_diagnostic(error),
        WorkerCallError::IncarnationChanged { .. } => "ncm.rust.worker_incarnation_changed",
    }
}

fn error_diagnostic(error: &RustNcmError) -> &'static str {
    match error {
        RustNcmError::WorkerSpawn(_) => "ncm.rust.worker_spawn_failed",
        RustNcmError::StateRoot(_) => "ncm.rust.state_root_invalid",
        RustNcmError::HandshakeIdentity(_) => "ncm.rust.handshake_identity_invalid",
    }
}

fn worker_receipt(operation: ProviderOperation, reply: &Reply) -> String {
    let mut payload = reply.payload.clone().unwrap_or(Value::Null);
    let mut generation = reply.state_generation;
    if matches!(
        operation,
        ProviderOperation::DeleteBySource
            | ProviderOperation::Maintenance
            | ProviderOperation::SnapshotRestore
    ) && let Some(basis) = payload.get("_retained_receipt").cloned()
        && let Some(original_generation) = basis["generation"].as_u64()
    {
        generation = original_generation;
        payload = basis["payload"].clone();
    }
    if let Some(object) = payload.as_object_mut() {
        object.remove("replayed");
        object.remove("common_observation");
    }
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest_field(&mut digest, operation.as_wire().as_bytes());
    digest.update(generation.to_be_bytes());
    digest_field(&mut digest, &payload_bytes);
    hex_digest(&digest.finalize())
}

fn unknown_receipt(call: &NcmSurfaceCall, error: &ClientError) -> String {
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest_field(&mut digest, call.operation.as_wire().as_bytes());
    digest.update(call.expected_state_generation.to_be_bytes());
    digest_field(&mut digest, error.to_string().as_bytes());
    hex_digest(&digest.finalize())
}

fn digest_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
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

#[cfg(test)]
mod source_revocation_tests {
    use super::*;

    #[test]
    fn revocation_is_unauthorized_without_reclassifying_invalid_requests() {
        let revoked = Outcome::Rejected(RejectReason::SourceRevoked);
        assert_eq!(outcome_terminal_code(&revoked), TerminalCode::Unauthorized);
        assert_eq!(outcome_diagnostic(&revoked), "ncm.rust.source_revoked");
        let malformed = Outcome::Rejected(RejectReason::InvalidRequest("invalid field".into()));
        assert_eq!(
            outcome_terminal_code(&malformed),
            TerminalCode::InvalidRequest
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod failed_handshake_generation_tests {
    use super::*;
    use crate::NcmNamespace;
    use tracedecay_memory_provider_api::CancellationToken;

    #[test]
    fn refusal_preserves_only_observed_generation_and_never_readiness() {
        let request = NcmSurfaceHandshakeRequest {
            registration_revision: 1,
            namespace: NcmNamespace("a1".repeat(32), crate::NcmNamespaceBinding::ExactSessionV1),
            request_id: "request".into(),
            required_capabilities: BTreeSet::new(),
            host_limits: ProviderLimits {
                request_bytes: 4096,
                response_bytes: 4096,
                observation_batch_items: 1,
                recall_candidates: 1,
                concurrent_operations: 1,
                operation_millis: 1000,
                snapshot_bytes: 4096,
                inspection_items: 1,
            },
            control: tracedecay_memory_provider_api::OperationControl::new(
                i64::MAX,
                1000,
                CancellationToken::default(),
            ),
            challenge_nonce: [0; 32],
        };
        for observed in [None, Some(0), Some(1), Some(9)] {
            let response = handshake_failure(
                &OwnedProviderId::new(NCM_PROVIDER_ID).unwrap(),
                &request,
                TerminalCode::ResetRequired,
                "ncm.rust.state_corrupt",
                observed,
            );
            assert_eq!(
                response.terminal.terminal_code(),
                TerminalCode::ResetRequired
            );
            let effect = response.terminal.committed_effect();
            assert_eq!(
                effect.state(),
                tracedecay_memory_provider_api::contract::CommittedEffectState::None
            );
            assert_eq!(effect.state_generation_before(), observed);
            assert_eq!(effect.state_generation_after(), observed);
            assert!(effect.provider_receipt_sha256().is_none());
            assert!(response.descriptor.is_none());
            assert!(response.provider_instance_id.is_none());
            assert!(response.namespace.is_none());
            assert!(response.effective_limits.is_none());
            assert!(response.ready_receipt_sha256.is_none());
            assert!(response.challenge_response_sha256.is_none());
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod identity_revision_tests {
    use super::*;

    fn identity() -> RuntimeIdentity {
        RuntimeIdentity {
            identity_revision: IDENTITY_REVISION_V2,
            config_sha256: "a".repeat(64),
            projection_sha256: "b".repeat(64),
            worker: Some(WorkerIdentity {
                sha256: "c".repeat(64),
                bytes: 38_396_840,
                target: WorkerTargetIdentity {
                    triple: "aarch64-apple-darwin".to_owned(),
                    os: "macos".to_owned(),
                    arch: "aarch64".to_owned(),
                    family: "unix".to_owned(),
                },
            }),
            encoder_model: "paraphrase-multilingual-MiniLM-L12-v2".to_owned(),
            encoder_artifact_sha256: "d".repeat(64),
            encoder_repository: Some("Xenova/paraphrase-multilingual-MiniLM-L12-v2".to_owned()),
            encoder_revision: Some("e".repeat(40)),
            encoder_revision_provenance: Some(
                "product/ncm/receipts/backend/receipt.json#/identities/model/revision".to_owned(),
            ),
            encoder_files: [
                ("onnx/model.onnx", "d", 470_268_510),
                ("tokenizer.json", "f", 17_082_913),
                ("config.json", "1", 673),
                ("special_tokens_map.json", "2", 280),
                ("tokenizer_config.json", "3", 496),
            ]
            .into_iter()
            .map(|(path, sha, bytes)| ModelArtifactIdentity {
                path: path.to_owned(),
                sha256: sha.repeat(64),
                bytes,
            })
            .collect(),
            encoder_max_length: Some(128),
            encoder_pooling: Some("mean".to_owned()),
            encoder_normalize: Some(true),
            epoch: 7,
        }
    }

    fn descriptor_digest(identity: &RuntimeIdentity) -> String {
        descriptor_for(identity, 0)
            .expect("identity fixture is valid")
            .implementation_identity_sha256
    }

    #[test]
    fn revision_two_descriptor_binds_worker_and_encoder_identity_fields() {
        let baseline = descriptor_digest(&identity());
        let mut worker_sha = identity();
        worker_sha.worker.as_mut().expect("worker").sha256 = "f".repeat(64);
        assert_ne!(descriptor_digest(&worker_sha), baseline);
        let mut worker_bytes = identity();
        worker_bytes.worker.as_mut().expect("worker").bytes += 1;
        assert_ne!(descriptor_digest(&worker_bytes), baseline);
        for field in ["triple", "os", "arch", "family"] {
            let mut changed = identity();
            let target = &mut changed.worker.as_mut().expect("worker").target;
            match field {
                "triple" => target.triple.push('x'),
                "os" => target.os.push('x'),
                "arch" => target.arch.push('x'),
                "family" => target.family.push('x'),
                _ => unreachable!(),
            }
            assert_ne!(
                descriptor_digest(&changed),
                baseline,
                "worker target {field}"
            );
        }
        for index in 0..5 {
            let mut changed = identity();
            changed.encoder_files[index].sha256 = "0".repeat(64);
            if index == 0 {
                changed.encoder_artifact_sha256 = "0".repeat(64);
            }
            assert_ne!(
                descriptor_digest(&changed),
                baseline,
                "model file {index} sha256"
            );
            let mut changed = identity();
            changed.encoder_files[index].bytes += 1;
            assert_ne!(
                descriptor_digest(&changed),
                baseline,
                "model file {index} bytes"
            );
        }
        let mut model_revision = identity();
        model_revision.encoder_revision = Some("f".repeat(40));
        assert_ne!(descriptor_digest(&model_revision), baseline);
        let mut repository = identity();
        repository.encoder_repository = Some("other/model".to_owned());
        assert_ne!(descriptor_digest(&repository), baseline);
        let mut provenance = identity();
        provenance.encoder_revision_provenance = Some("receipt.json#/revision".to_owned());
        assert_ne!(descriptor_digest(&provenance), baseline);
        let mut max_length = identity();
        max_length.encoder_max_length = Some(256);
        assert_ne!(descriptor_digest(&max_length), baseline);
        let mut pooling = identity();
        pooling.encoder_pooling = Some("cls".to_owned());
        assert_ne!(descriptor_digest(&pooling), baseline);
        let mut normalize = identity();
        normalize.encoder_normalize = Some(false);
        assert_ne!(descriptor_digest(&normalize), baseline);
    }

    #[test]
    fn revision_two_ready_receipt_binds_worker_and_model_digest_values() {
        let baseline = ready_receipt("1".repeat(64).as_str(), &identity());
        let mut changed = identity();
        changed.worker.as_mut().expect("worker").bytes += 1;
        assert_ne!(ready_receipt("1".repeat(64).as_str(), &changed), baseline);
        let mut changed = identity();
        changed.encoder_files[4].sha256 = "f".repeat(64);
        assert_ne!(ready_receipt("1".repeat(64).as_str(), &changed), baseline);
    }

    #[test]
    fn revision_two_implementation_id_binds_runtime_epoch_but_descriptor_does_not() {
        let baseline = identity();
        let mut changed = baseline.clone();
        changed.epoch = changed.epoch.saturating_add(1);
        assert_ne!(
            implementation_version(&baseline),
            implementation_version(&changed)
        );
        assert_eq!(descriptor_digest(&baseline), descriptor_digest(&changed));
    }

    #[test]
    fn legacy_owner_may_reconcile_sparse_runtime_identity_with_v2_declaration() {
        let expected = identity();
        let reply = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(json!({
                "algorithm": {
                    "profile": ALGORITHM_PROFILE,
                    "config_sha256": expected.config_sha256,
                },
                "projection_sha256": expected.projection_sha256,
                "encoder": {
                    "model": expected.encoder_model,
                    "artifact_sha256": expected.encoder_artifact_sha256,
                },
                "epoch": 11,
            })),
            error: None,
        };
        let reconciled = parse_runtime_identity_for_expected(&reply, Some(&expected), false)
            .expect("legacy V1 identity reconciliation");
        assert_eq!(reconciled.identity_revision, IDENTITY_REVISION_V2);
        assert_eq!(reconciled.worker, expected.worker);
        assert_eq!(reconciled.encoder_files, expected.encoder_files);
        assert_eq!(reconciled.projection_sha256, expected.projection_sha256);
        assert_eq!(reconciled.epoch, 11);
    }

    #[test]
    fn production_identity_proof_rejects_sparse_v1_ready_payload() {
        let expected = identity();
        let reply = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(json!({
                "algorithm": {
                    "profile": ALGORITHM_PROFILE,
                    "config_sha256": expected.config_sha256,
                },
                "projection_sha256": expected.projection_sha256,
                "encoder": {
                    "model": expected.encoder_model,
                    "artifact_sha256": expected.encoder_artifact_sha256,
                },
                "epoch": 11,
            })),
            error: None,
        };
        assert!(parse_runtime_identity_for_expected(&reply, Some(&expected), true).is_err());
    }

    #[test]
    fn production_identity_proof_rejects_tampered_v2_worker_or_model_fields() {
        let expected = identity();
        let mut payload = identity_request_payload(Some(&expected));
        payload["projection_sha256"] = Value::String(expected.projection_sha256.clone());

        payload["worker"]["sha256"] = Value::String("0".repeat(64));
        let tampered_worker = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(payload),
            error: None,
        };
        assert!(
            parse_runtime_identity_for_expected(&tampered_worker, Some(&expected), true).is_err(),
            "worker digest tampering must invalidate production proof"
        );

        let mut payload = identity_request_payload(Some(&expected));
        payload["encoder"]["revision"] = Value::String("f".repeat(40));
        let tampered_encoder = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(payload),
            error: None,
        };
        assert!(
            parse_runtime_identity_for_expected(&tampered_encoder, Some(&expected), true).is_err(),
            "encoder revision tampering must invalidate production proof"
        );

        let mut payload = identity_request_payload(Some(&expected));
        payload["worker"].as_object_mut().unwrap().remove("target");
        let missing_worker_target = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(payload),
            error: None,
        };
        assert!(
            parse_runtime_identity_for_expected(&missing_worker_target, Some(&expected), true,)
                .is_err(),
            "missing worker target metadata must invalidate production proof"
        );
    }

    #[test]
    fn v2_identity_request_carries_static_worker_and_encoder_metadata() {
        let expected = identity();
        let payload = identity_request_payload(Some(&expected));
        assert_eq!(
            payload["identity_revision"],
            Value::from(u64::from(IDENTITY_REVISION_V2))
        );
        assert_eq!(
            payload["algorithm"]["config_sha256"],
            Value::String(expected.config_sha256.clone())
        );
        assert_eq!(
            payload["worker"]["sha256"],
            expected.worker.as_ref().unwrap().sha256
        );
        assert_eq!(
            payload["encoder"]["revision"],
            Value::String(expected.encoder_revision.clone().unwrap())
        );
        assert_eq!(payload["epoch"], Value::from(expected.epoch));
    }

    #[test]
    fn v2_handshake_omits_unknown_namespace_runtime_state_until_observed() {
        let mut declaration = identity();
        declaration.projection_sha256.clear();
        declaration.epoch = 0;
        let direct = identity_request_payload(Some(&declaration));
        assert!(direct.get("projection_sha256").is_none());
        assert!(direct.get("epoch").is_none());
        let unknown = identity_request_payload_for_worker(Some(&declaration), true, false);
        assert!(unknown.get("projection_sha256").is_none());
        assert!(unknown.get("epoch").is_none());

        let observed = identity();
        let exact = identity_request_payload_for_worker(Some(&observed), true, true);
        assert_eq!(
            exact["projection_sha256"],
            Value::String(observed.projection_sha256.clone())
        );
        assert_eq!(exact["epoch"], Value::from(observed.epoch));
    }

    #[test]
    fn revision_two_wire_identity_round_trips_and_rejects_missing_artifacts() {
        let expected = identity();
        let mut payload = identity_request_payload(Some(&expected));
        payload["algorithm"] = json!({
            "profile": ALGORITHM_PROFILE,
            "config_sha256": expected.config_sha256,
        });
        payload["projection_sha256"] = Value::String(expected.projection_sha256.clone());
        payload["epoch"] = Value::from(expected.epoch);
        payload["identity_revision"] = Value::from(u64::from(IDENTITY_REVISION_V2));
        let worker = expected.worker.as_ref().expect("worker");
        payload["worker"] = json!({
            "sha256": worker.sha256,
            "bytes": worker.bytes,
            "target": {
                "triple": worker.target.triple,
                "os": worker.target.os,
                "arch": worker.target.arch,
                "family": worker.target.family,
            },
        });
        payload["encoder"] = json!({
            "model": expected.encoder_model,
            "artifact_sha256": expected.encoder_artifact_sha256,
            "repository": expected.encoder_repository,
            "revision": expected.encoder_revision,
            "revision_provenance": expected.encoder_revision_provenance,
            "files": expected
                .encoder_files
                .iter()
                .map(|file| json!({
                    "path": file.path,
                    "sha256": file.sha256,
                    "bytes": file.bytes,
                }))
                .collect::<Vec<_>>(),
            "max_length": expected.encoder_max_length,
            "pooling": expected.encoder_pooling,
            "normalize": expected.encoder_normalize,
        });
        let reply = Reply {
            id: 1,
            outcome: Outcome::Success,
            state_generation: 0,
            payload: Some(payload.clone()),
            error: None,
        };
        assert_eq!(
            parse_runtime_identity(&reply).expect("v2 identity"),
            expected
        );
        let mut missing = payload;
        missing["encoder"]["files"] = Value::Array(Vec::new());
        let reply = Reply {
            payload: Some(missing),
            ..reply
        };
        assert!(parse_runtime_identity(&reply).is_err());
    }

    #[test]
    fn model_revision_provenance_is_read_from_the_pinned_receipt() {
        let manifest = tracedecay_memory_ncm_runtime::embedding::PinnedEncoder::reference()
            .expect("checked-in model manifest");
        assert!(verify_model_revision_provenance(&manifest).is_ok());
        let mut altered = manifest;
        altered.revision_provenance =
            "product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json#/identities/model/model"
                .to_owned();
        assert!(verify_model_revision_provenance(&altered).is_err());
    }
}
