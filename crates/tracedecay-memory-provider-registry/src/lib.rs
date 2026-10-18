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
//! Product-owned composition for configured memory providers.
//!
//! Composition injects concrete adapters and their admitted registration metadata.
//! The legacy Native constructor remains a compatibility wrapper. All adapters
//! register in the existing bounded fabric under their validated identities.
//! The resulting registry exposes only provider-neutral status and call
//! operations; registration and mode mutation remain inside composition.
//! Handshake and active-call replies preserve the complete provider-neutral
//! terminal record. Observation delivery strips provider payloads, opaque
//! extensions, and warning text while retaining the same structured
//! committed-effect and fallback evidence in its observer receipt. Terminal
//! provider and operation identities stay bound to the selected route. The
//! registry never interprets a fallback directive as authority to dispatch
//! another provider.
//! Disabled composition carries no config or port and therefore creates no
//! fabric, provider adapter, storage, background work, or provider
//! registration.
//!
//! A successful handshake can additionally be reduced to
//! [`ProviderReadinessTargetV1`]: a provider-neutral identity built only from
//! the selected provider, its self-reported runtime instance, the
//! product-owned registration revision, and the fabric-validated
//! ready-receipt digest. This keeps the coupling to any root
//! observation-journal or retained-memory target authority one-way — this
//! crate returns the neutral identity and never imports the root's concrete
//! target type — and it cannot be produced from a disabled composition or an
//! unsuccessful handshake.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use tracedecay_memory_fabric::MemoryFabric;
use tracedecay_memory_provider_api::MemoryProvider;

mod observation_mount;
pub use observation_mount::{
    ObservationInstanceProofV1, ObservationProviderMountV1, ObservationStateNamespacePolicyV1,
};

pub mod provider_invocation;
pub mod recall_admission;
pub mod recall_context_pack;
pub mod recall_explain_trace;
pub mod recall_normalization;
pub mod recall_port;
pub mod recall_provenance_hydration;
pub mod recall_selection;
pub mod state_capability;
pub mod supervised_readiness;
pub mod supervisor;
pub use provider_invocation::{
    ProviderCancellationWaitV1, ProviderExecutionShapeV1, ProviderInvocationBoundaryV1,
    ProviderInvocationFaultV1, ProviderInvocationLimitsV1, ProviderInvocationRequestV1,
    ProviderWorkV1, ProviderWorkerCensusV1, ProviderWorkerHandleV1, ProviderWorkerIsolationV1,
    ProviderWorkerSpawnErrorV1, ProviderWorkerSpawnV1, ProviderWorkerTerminationV1,
    WorkerDispositionV1,
};
pub use recall_admission::{
    AdmittedRecallCandidate, AdmittedTemporalQuery, DeniedRecallCandidate,
    RECALL_QUERY_CAPABILITY_ID, RECALL_REQUEST_CONTRACT_ID, RecallAdmission, RecallAdmissionError,
    RecallAdmissionReport, RecallBudgetsV1, RecallCandidateContent, RecallCandidateV1,
    RecallConfidenceDefect, RecallDenialReason, RecallOutcomeScopeV1, RecallOutcomeV1,
    RecallRequestParts, RecallScopeBindingsV1, RecallScopeIdentityV1, RecallValidityV1,
    ScopeBinding, ScopeField, TemporalState, UnknownValidityPolicy, admit_recall_candidates,
    admit_recall_reply, build_recall_request_payload, decode_recall_outcome, parse_rfc3339_nanos,
    rfc3339_utc_micros,
};
pub use recall_context_pack::{
    ADVISORY_CONTEXT_PACK_JSON_KEY, AdvisoryLaneV1, CANONICAL_CONTEXT_TOKENIZER_ID,
    CANONICAL_CONTEXT_TOKENIZER_REVISION, ContextItemProvenanceV1, ContextPackError,
    ContextPackItemV1, ContextPackPolicyError, ContextPackPolicyV1, ContextPackReceiptV1,
    ContextPackRenderFormV1, ContextPackSectionV1, ContextPackV1, ContextSectionKind,
    ContextTokenizer, ExcludedProviderItemV1, HOST_CONTEXT_PACK_POLICY_ID,
    HOST_CONTEXT_PACK_POLICY_REVISION, HostContextItemV1, NATIVE_FACTS_HOST_AUTHORITY,
    O200kBaseContextTokenizer, ProviderContextItemV1, ProviderContributionV1,
    ProviderExclusionReason, ProviderItemProvenanceV1, ProviderMetadataFieldV1,
    compile_context_pack, uncontained_item_identity,
};
pub use recall_explain_trace::{
    ContainedExplanationRedactorV1, EXPLAIN_TRACE_BOUNDARY_LABEL, MAX_EXPLAIN_EXPLANATION_CHARS,
    RETAINED_CANDIDATE_ID_PREFIX, RecallExplainHostDecisionV1, RecallExplainHostWithholdingV1,
    RecallExplainItemV1, RecallExplainProviderExplanationV1, RecallExplainStageV1,
    RecallExplainTokenSummaryV1, RecallExplainTraceError, RecallExplainTraceInputsV1,
    RecallExplainTraceV1, RecallExplanationRedactorV1, build_recall_explain_trace,
    explanation_source_sha256, is_contained_explanation,
};
pub use recall_normalization::{
    HOST_NORMALIZATION_POLICY_ID, HOST_NORMALIZATION_POLICY_REVISION, HostNormalizedScoreV1,
    MAX_SCORE_COMPONENTS, NativeScoreDefect, NativeScoreV1, NormalizationUnavailableReason,
    NormalizedRecallCandidateV1, RecallConfidenceUnavailableReason, RecallConfidenceV1,
    RecallNormalizationError, RecallNormalizationPolicyV1, RecallNormalizationV1,
    RecallRelevanceV1, ScoreCalibrationEvidence, ScoreCalibrationState, ScoreDirection,
    ValidatedNativeScoreV1, normalize_admitted_candidates, normalize_native_score,
    validate_native_score,
};
pub use recall_port::{
    BoundCognitiveRecallPortV1, CognitiveRecallAdmittedOutcomeV1, CognitiveRecallPortError,
    CognitiveRecallPortInputsV1, ExactScopeBinding, ExactScopeBindingError,
    ProjectCognitiveRecallPortV1, RecallAdmissionAuditError, RecallAdmissionObserver,
    RecallRoutePlanError,
};
pub use recall_provenance_hydration::{
    DEFAULT_PROVENANCE_HYDRATION_MAX_ATTEMPTS, HostCanonicalRecordStore, HostEvidenceControlV1,
    HostEvidenceLookupErrorV1, HostEvidenceRefV1, HostEvidenceScopeError, HostEvidenceScopeV1,
    HostProvenanceAuthority, HostProviderLocalAttestationStore, HostSessionEvidenceStore,
    HostSourceEvidenceStore, MountedHostProvenanceAuthorityV1, ProvenanceHydrationDecisionV1,
    ProvenanceHydrationDegradationV1, ProvenanceHydrationError, ProvenanceHydrationOutcome,
    ProvenanceHydrationPassV1, ProvenanceHydrationPolicyError, ProvenanceHydrationPolicyV1,
};
pub use recall_selection::{
    BudgetExcludedCandidateV1, BudgetExclusionReason, DeduplicatedCandidateV1, DuplicateReason,
    HOST_SELECTION_POLICY_ID, HOST_SELECTION_POLICY_REVISION, RecallSelectionError,
    RecallSelectionPolicyError, RecallSelectionPolicyV1, RecallSelectionV1,
    select_recall_candidates,
};
pub use state_capability::{
    ProviderStateAccessError, ProviderStateAuthorityError, ProviderStateAuthorityV1,
    ProviderStateCapabilityV1,
};
pub use supervised_readiness::{
    BoundedCallRefusalV1, BoundedProviderCallV1, CompositionLifecycleAdapterV1,
    CompositionLifecycleError, ProviderHandshakeWorkV1, QuarantinedScopeV1,
    SupervisedProviderReadinessV1, SupervisedReadinessConfigV1, SupervisedReadinessDispatchV1,
    SupervisedReadinessError, SupervisedScopeReadinessV1,
};
pub use supervisor::{
    AdapterOperationV1, DegradationCauseV1, DegradationKindV1, DegradationRecordV1,
    PredecessorStateV1, ProviderAvailabilityV1, ProviderLifecycleAdapterV1, ProviderSupervisorV1,
    QuarantinePolicyV1, QuarantineRecordV1, QuarantineReleaseError, ReadinessDefectV1,
    ReadinessEvidenceV1, ReproveOutcomeV1, RestartBudgetV1, ScopeFieldV1, ShutdownBudgetV1,
    ShutdownReportV1, SupervisedScopeV1, SupervisorConfigError, SupervisorOutcomeV1,
};
pub use tracedecay_memory_fabric::{
    ActiveCallPlan, ActiveRoutingPolicy, DegradationCause, DegradationDecision,
    DegradationDeclinedReason, DegradationRule, FabricConfig, FabricError, FallbackDecision,
    FallbackDeclinedReason, FallbackRule, ObserverDeliveryResult, ObserverReceipt,
    PinnedDegradationPolicy, ProviderCapabilityAvailability, ProviderMode, ProviderReadiness,
    ProviderStatus, ReadyRouteTarget, RouteTarget, RoutedActiveReply, RoutedProviderIdentity,
    RoutingError, RoutingPolicyError,
};
pub use tracedecay_memory_provider_native::RECALL_RESULT_CONTRACT_ID;
// Re-export the narrow provider-neutral surface that product composition needs
// to implement an application port. The product crate deliberately depends on
// this registry crate only; concrete provider crates stay behind this boundary.
pub use tracedecay_memory_provider_api::contract::{
    COMMON_ADVISORY_OBSERVATION_KINDS, COMMON_ADVISORY_OPTIONAL_CAPABILITIES,
    COMMON_ADVISORY_OPTIONAL_OBSERVATION_KINDS, COMMON_ADVISORY_PROFILE_ID,
    COMMON_ADVISORY_REQUIRED_CAPABILITIES, CommittedEffectState, DeletionMode, HistoryRelation,
    SourceDisposition, TemporalMode, TerminalCode,
    UnknownValidityPolicy as CommonUnknownValidityPolicy,
};
pub use tracedecay_memory_provider_api::{
    AdvisoryAdmissionAuthority, AdvisoryAdmissionError, AdvisoryContractError, ApiError,
    CancellationToken, CanonicalPayload, CommittedEffectEvidence, CurrentAdvisoryAdmission,
    CurrentRestoreAdmission, CurrentSourceDisposition, FallbackDirective, GrantedHistorySource,
    HandshakeRequest, HandshakeRequestParts, HandshakeResponse, HistoryGrant, LifecycleTarget,
    LifecycleTargetReference, MAX_ADVISORY_ADMISSION_SOURCES, MemoryProvider as MemoryProviderV1,
    OperationControl, OriginScopeEvidence, OriginalSourceIdentity, OwnedExactScope,
    OwnedProviderId, OwnedRecallExclusions, OwnedTemporalQuery, OwnedVersionedId,
    PayloadSanitizationReceipt, PayloadSanitizationReceiptParts, PinnedFallbackPolicy,
    ProviderCall, ProviderCallParts, ProviderDescriptor, ProviderLimits, ProviderOperation,
    ProviderReply, RecordedValidity, RestoreDispositionCheckpoint, SanitizationDisposition,
    SourceAttribution, TemporalEligibility, TerminalRecord, WithheldReason,
};
pub use tracedecay_memory_provider_native::{
    NATIVE_PROVIDER_ID, NATIVE_RECALL_SCOPE_BINDINGS, NativeAdapterError,
    NativeMemoryApplicationPort, NativeProvider,
};

/// Legacy Native-constructor kind retained for callers of the compatibility API.
/// New composition resolves installed adapters at its own boundary and injects
/// [`ProviderRegistrationV1`]; this enum does not decide common-profile compatibility.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MountableProviderKindV1 {
    /// The TraceDecay Native adapter over the host's own memory authority.
    Native,
}

impl MountableProviderKindV1 {
    /// Returns the stable provider identity this kind registers under.
    #[must_use]
    pub const fn provider_id(self) -> &'static str {
        match self {
            Self::Native => NATIVE_PROVIDER_ID,
        }
    }

    /// Returns the recall scope bindings the adapter declares.
    #[must_use]
    pub const fn declared_recall_scope_bindings(self) -> &'static [&'static str] {
        match self {
            Self::Native => NATIVE_RECALL_SCOPE_BINDINGS,
        }
    }

    /// Returns the execution shape the host execution boundary admits this
    /// adapter under.
    ///
    /// Declaring it here, on the typed kind, is what keeps the decision out of
    /// the composition root: the boundary asks the composed registry, through
    /// [`ProjectMemoryProviderRegistry::selected_execution_shape`], what shape
    /// the adapter a recall route can actually enter was registered under, and
    /// never compares a provider name to decide it.
    #[must_use]
    pub const fn declared_execution_shape(self) -> ProviderExecutionShapeV1 {
        match self {
            // The Native adapter is compiled from this workspace, is held to
            // its cancellation contract by the conformance suite, and is the
            // host's own code to answer for.
            Self::Native => ProviderExecutionShapeV1::HostAuthoredInProcess,
        }
    }
}

/// Maps a configured active-provider name onto its admitted registration.
///
/// The composed registry is the source of truth for mountability. This keeps
/// the query provider-neutral: injected adapters such as NCM are recognized
/// from their validated registration, while an observer registration is never
/// promoted to an active route. `None` means the provider is malformed,
/// unknown to this registry, or not registered in active mode; callers must
/// refuse the configuration rather than substituting a provider.
#[must_use]
pub fn mountable_active_provider<'a>(
    registry: &'a ProjectMemoryProviderRegistry,
    provider: &str,
) -> Option<&'a ProviderRegistrationMetadataV1> {
    let provider_id = OwnedProviderId::new(provider).ok()?;
    registry
        .registration(&provider_id)
        .filter(|registration| registration.mode == EnabledProviderMode::Active)
}

/// Whether `registry` can mount `provider` as an *active* recall provider.
#[must_use]
pub fn is_mountable_active_provider(
    registry: &ProjectMemoryProviderRegistry,
    provider: &str,
) -> bool {
    mountable_active_provider(registry, provider).is_some()
}

/// A non-disabled provider participation mode.
///
/// Keeping `Disabled` out of this type prevents an enabled adapter from being
/// constructed only to receive a disabled fabric registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnabledProviderMode {
    /// Receive admitted observations without contributing active output.
    Observer,
    /// Receive admitted observations and explicitly routed active calls.
    Active,
}

impl EnabledProviderMode {
    fn fabric_mode(self) -> ProviderMode {
        match self {
            Self::Observer => ProviderMode::Observer,
            Self::Active => ProviderMode::Active,
        }
    }
}

/// Explicit Native provider selection for one product composition.
pub enum NativeProviderActivation {
    /// Do not construct any provider or fabric infrastructure.
    Disabled,
    /// Construct Native from the injected application port and register it.
    Enabled {
        /// Finite fabric limits used only by enabled composition.
        fabric_config: FabricConfig,
        /// Existing TraceDecay Native application authority.
        port: Arc<dyn NativeMemoryApplicationPort>,
        /// Positive product-owned registration revision.
        registration_revision: u64,
        /// Enabled observer or active participation.
        mode: EnabledProviderMode,
    },
}

/// Explicit selection of an injected adapter, observer-only participation, or
/// disabled composition. The Native variant preserves the legacy constructor.
pub enum SelectedProviderActivationV1 {
    /// Construct no provider, no fabric, and no state.
    Disabled,
    /// Mount an independently configured injected adapter.
    Injected {
        /// Finite fabric limits.
        fabric_config: FabricConfig,
        /// Selected adapter and its actual registration authority.
        registration: ProviderRegistrationV1,
    },
    /// Mount only independently enabled observers, with no active provider.
    ObserversOnly {
        /// Finite fabric limits.
        fabric_config: FabricConfig,
    },
    /// Register the TraceDecay Native adapter over the host's memory port.
    Native {
        /// Finite fabric limits used only by enabled composition.
        fabric_config: FabricConfig,
        /// Existing TraceDecay Native application authority.
        port: Arc<dyn NativeMemoryApplicationPort>,
        /// Positive product-owned registration revision.
        registration_revision: u64,
        /// Enabled observer or active participation.
        mode: EnabledProviderMode,
    },
}

impl From<NativeProviderActivation> for SelectedProviderActivationV1 {
    fn from(value: NativeProviderActivation) -> Self {
        match value {
            NativeProviderActivation::Disabled => Self::Disabled,
            NativeProviderActivation::Enabled {
                fabric_config,
                port,
                registration_revision,
                mode,
            } => Self::Native {
                fabric_config,
                port,
                registration_revision,
                mode,
            },
        }
    }
}

/// A configured adapter and the authority composition admits for it.
///
/// Identity recognition belongs to composition. The registry validates the
/// injected descriptor and common profile rather than granting compatibility
/// to a recognized provider name. Construction must remain lazy: registration
/// never starts a provider or invokes its lifecycle owner.
pub struct ProviderRegistrationV1 {
    /// Configured identity, checked against the injected descriptor.
    pub provider_id: OwnedProviderId,
    /// Concrete adapter constructed at the composition boundary.
    pub provider: Arc<dyn MemoryProvider>,
    /// Positive product-owned registration revision.
    pub registration_revision: u64,
    /// Independently admitted participation.
    pub mode: EnabledProviderMode,
    /// Actual code execution shape at the host invocation boundary.
    pub execution_shape: ProviderExecutionShapeV1,
    /// Host-admitted bindings declared by this adapter, never read from replies.
    pub recall_scope_bindings: RecallScopeBindingsV1,
    /// Existing runtime owner, shared with the adapter rather than duplicated.
    pub lifecycle: ProviderLifecycleOwnershipV1,
}

/// Lifecycle authority admitted for one provider registration.
#[derive(Clone)]
pub enum ProviderLifecycleOwnershipV1 {
    /// The adapter has no runtime incarnation separate from composition.
    /// Retiring readiness does not terminate its host invocation threads;
    /// the invocation boundary independently accounts for stranded work.
    CompositionBound,
    /// A bounded owner controls the existing adapter runtime. Its methods must
    /// serialize with that runtime's own cancellation/restart authority.
    Owned(Arc<dyn ProviderLifecycleOwnerV1>),
}

/// Lifecycle control over an already admitted runtime owner.
///
/// Implementations must use the adapter's existing owner and respect every
/// deadline. A cooperative wrapper thread is not proof of process termination.
/// Shared owners must serialize termination and replacement; creating another
/// worker owner for an exact-scope supervisor is forbidden.
pub trait ProviderLifecycleOwnerV1: Send + Sync {
    /// Requests startup without claiming readiness or replacing a live owner.
    fn start(&self, deadline_unix_micros: i64) -> Result<(), ProviderLifecycleOwnerErrorV1>;
    /// Returns true only after the existing runtime has confirmed termination.
    fn request_stop(
        &self,
        deadline_unix_micros: i64,
    ) -> Result<bool, ProviderLifecycleOwnerErrorV1>;
    /// Confirms termination before replacement is permitted.
    fn kill(&self, deadline_unix_micros: i64) -> Result<(), ProviderLifecycleOwnerErrorV1>;
}

/// A bounded runtime owner could not establish a lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderLifecycleOwnerErrorV1 {
    /// The requested transition has no remaining time.
    #[error("provider lifecycle deadline elapsed")]
    DeadlineElapsed,
    /// Runtime termination has not been proved; no replacement is authorized.
    #[error("provider runtime termination is unconfirmed")]
    TerminationUnconfirmed,
    /// The admitted owner is unavailable.
    #[error("provider lifecycle owner unavailable: {0}")]
    Unavailable(String),
}

/// Immutable registration evidence retained alongside the fabric route.
/// The fabric remains the sole mode, revision, health and dispatch authority.
pub struct ProviderRegistrationMetadataV1 {
    /// Registered configured identity.
    pub provider_id: OwnedProviderId,
    /// Product-owned registration revision.
    pub registration_revision: u64,
    /// Admitted participation mode.
    pub mode: EnabledProviderMode,
    /// Host composition's common-profile requirement, independent of provider
    /// identity and descriptor claims.
    pub requires_common_advisory_profile: bool,
    /// Actual validated descriptor limits.
    pub limits: ProviderLimits,
    /// Execution shape admitted by composition.
    pub execution_shape: ProviderExecutionShapeV1,
    lifecycle: ProviderLifecycleOwnershipV1,
}

/// Required delivery is explicit and independent of mount ordering or identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationMountRequirementV1 {
    /// Failure prevents the selected provider from becoming usable.
    Required,
    /// Failure is visible but cannot disable the independently selected provider.
    Optional,
}

/// When the already-owned observation journey may start delivery and replay.
/// This is independent of whether a mount or activation failure is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationMountActivationV1 {
    /// Bootstrap before publishing the full server, preserving an existing
    /// required startup path that does not depend on full host ingestion.
    BeforePublication,
    /// Construct a dormant journey first, then activate that same owner only
    /// after the full server can answer registered host ingestion.
    AfterPublication,
}

/// Observation mount with independent requirement and activation timing.
pub struct ConfiguredObservationProviderMountV1 {
    /// Existing observation namespace, limits and readiness proof.
    pub mount: ObservationProviderMountV1,
    /// Whether admission/replay failure fails this composition.
    pub requirement: ObservationMountRequirementV1,
    /// When delivery/replay may begin, independently of the failure policy.
    pub activation: ObservationMountActivationV1,
}

/// One Observer registration in a composed provider set.
///
/// The concrete adapter is *injected by the composition root*, which is the
/// only layer allowed to construct a concrete provider. This registry records
/// it under the identity its own descriptor declares, so nothing here — and
/// nothing in the daemon — branches on a provider name to decide that a
/// provider is an observer. Mode is carried by the registration itself, not
/// inferred.
///
/// An observer is registered with **no** `recall_scope_bindings` entry. Recall
/// admission accepts a candidate only against bindings this registry recorded
/// at registration, so an observer has no authorized scope binding to recall
/// under even if a route ever reached it. That is a second, independent
/// refusal behind the fabric's `ProviderMode::Observer` gate.
pub struct ObserverProviderRegistration {
    /// The concrete observer adapter the composition root constructed.
    pub provider: Arc<dyn MemoryProvider>,
    /// Positive product-owned registration revision for this observer.
    pub registration_revision: u64,
}

/// Explicit result of configured product provider composition.
pub enum ProjectMemoryProviderComposition {
    /// Provider infrastructure is absent.
    Disabled,
    /// Provider infrastructure was explicitly enabled and constructed.
    Enabled(ProjectMemoryProviderRegistry),
}

impl ProjectMemoryProviderComposition {
    /// Applies the explicit activation with no observer registrations.
    ///
    /// Equivalent to [`Self::compose_with_observers`] with an empty set.
    pub fn compose(native: NativeProviderActivation) -> Result<Self, RegistryError> {
        Self::compose_with_observers(native, Vec::new())
    }

    /// Applies the explicit activation as a **bounded provider set**: one
    /// separately selected Native provider in its configured mode, plus zero
    /// or more injected Observer registrations.
    ///
    /// The active provider and the observer set are chosen independently —
    /// the Native activation names the mode of the provider that may answer
    /// product calls, and each [`ObserverProviderRegistration`] is registered
    /// in [`ProviderMode::Observer`] and can never be selected for product
    /// output by any route this registry exposes. The set is refused before
    /// any registration when it does not fit the fabric's finite registry
    /// capacity, when an observer declares the Native identity, or when two
    /// observers declare the same identity, so a partially registered
    /// composition can never be observed.
    ///
    /// A disabled activation with a non-empty observer set is a configuration
    /// error, not a silently dropped set: observers exist only inside an
    /// enabled composition.
    pub fn compose_with_observers(
        native: NativeProviderActivation,
        observers: Vec<ObserverProviderRegistration>,
    ) -> Result<Self, RegistryError> {
        Self::compose_selected(native.into(), observers)
    }

    /// Applies a selection with legacy observer registrations.
    /// New composition should use [`Self::compose_registered`] to supply each
    /// observer's actual execution and lifecycle ownership metadata.
    pub fn compose_selected(
        selection: SelectedProviderActivationV1,
        observers: Vec<ObserverProviderRegistration>,
    ) -> Result<Self, RegistryError> {
        if !observers.is_empty() && matches!(selection, SelectedProviderActivationV1::Disabled) {
            return Err(RegistryError::ObserverWithoutEnabledComposition {
                observers: observers.len(),
            });
        }
        let observers = observers
            .into_iter()
            .map(|observer| {
                Ok(ProviderRegistrationV1 {
                    provider_id: observer.provider.descriptor().provider_id,
                    provider: observer.provider,
                    registration_revision: observer.registration_revision,
                    mode: EnabledProviderMode::Observer,
                    execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                    recall_scope_bindings: RecallScopeBindingsV1::from_wire(["exact_coding_scope"])
                        .map_err(RegistryError::RecallScopeBindings)?,
                    lifecycle: ProviderLifecycleOwnershipV1::CompositionBound,
                })
            })
            .collect::<Result<Vec<_>, RegistryError>>()?;
        Self::compose_registered(selection, observers)
    }

    /// Registers one selected adapter and independent observers in the existing
    /// fabric. Injected active providers must declare the common advisory profile.
    /// Observer-only composition needs no selected or Native adapter.
    pub fn compose_registered(
        selection: SelectedProviderActivationV1,
        observers: Vec<ProviderRegistrationV1>,
    ) -> Result<Self, RegistryError> {
        if matches!(selection, SelectedProviderActivationV1::Disabled) {
            return if observers.is_empty() {
                Ok(Self::Disabled)
            } else {
                Err(RegistryError::ObserverWithoutEnabledComposition {
                    observers: observers.len(),
                })
            };
        }
        let (fabric_config, selected, require_common_profile) = match selection {
            SelectedProviderActivationV1::Disabled => return Ok(Self::Disabled),
            SelectedProviderActivationV1::ObserversOnly { fabric_config } => {
                if observers.is_empty() {
                    return Ok(Self::Disabled);
                }
                (fabric_config, None, true)
            }
            SelectedProviderActivationV1::Injected {
                fabric_config,
                registration,
            } => (fabric_config, Some(registration), true),
            SelectedProviderActivationV1::Native {
                fabric_config,
                port,
                registration_revision,
                mode,
            } => {
                let provider = Arc::new(NativeProvider::new(port)?);
                let registration = ProviderRegistrationV1 {
                    provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID)?,
                    provider,
                    registration_revision,
                    mode,
                    execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                    recall_scope_bindings: RecallScopeBindingsV1::from_wire(
                        NATIVE_RECALL_SCOPE_BINDINGS.iter().copied(),
                    )
                    .map_err(RegistryError::RecallScopeBindings)?,
                    lifecycle: ProviderLifecycleOwnershipV1::CompositionBound,
                };
                (fabric_config, Some(registration), false)
            }
        };
        Ok(Self::Enabled(
            ProjectMemoryProviderRegistry::compose_provider_set(
                fabric_config,
                selected,
                observers,
                require_common_profile,
            )?,
        ))
    }

    /// Borrows the enabled registry, or returns `None` when disabled.
    #[must_use]
    pub fn registry(&self) -> Option<&ProjectMemoryProviderRegistry> {
        match self {
            Self::Disabled => None,
            Self::Enabled(registry) => Some(registry),
        }
    }
}

/// Provider-neutral identity produced by one validated readiness handshake.
///
/// Every field is copied unchanged from values the fabric itself already
/// requires to be present and mutually consistent before it returns a
/// successful [`HandshakeResponse`]: the selected provider identity bound to
/// the accepted terminal, the provider-reported runtime-instance identity,
/// the product-owned registration revision the handshake was admitted
/// under, and the fabric-validated ready-receipt digest. No field is
/// fabricated, defaulted, or read from configuration or test support — a
/// value can only be constructed by
/// [`ProjectMemoryProviderRegistry::readiness_target`] from a real,
/// successful handshake.
///
/// This is **readiness evidence, not a delivery address**. The durable
/// observation journal owns its own `ProviderTargetV1`, whose fields are
/// public because a persisted row has to be reconstructed on read; naming
/// this type after that one would put two differently-shaped structs with
/// one name on the composition root's import list. The root is the only
/// place both can exist. A production observation mount must map this value
/// into the journal's target: `provider_id`, `provider_instance_id`, and
/// `registration_revision` carry over unchanged, and
/// [`Self::ready_receipt_sha256`] is the bare lowercase 64-hex digest the
/// journal stores as `ready_receipt_digest`. Deriving the journal target any
/// other way would let a target exist without a successful handshake behind
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReadinessTargetV1 {
    provider_id: OwnedProviderId,
    provider_instance_id: String,
    registration_revision: u64,
    ready_receipt_sha256: String,
}

impl ProviderReadinessTargetV1 {
    /// Returns the selected provider identity the handshake was bound to.
    #[must_use]
    pub fn provider_id(&self) -> &OwnedProviderId {
        &self.provider_id
    }

    /// Returns the provider-reported runtime-instance identity.
    #[must_use]
    pub fn provider_instance_id(&self) -> &str {
        &self.provider_instance_id
    }

    /// Returns the product-owned registration revision this target was
    /// derived under.
    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    /// Returns the fabric-validated ready-receipt digest bound to this
    /// target.
    #[must_use]
    pub fn ready_receipt_sha256(&self) -> &str {
        &self.ready_receipt_sha256
    }
}

/// Failure deriving a [`ProviderReadinessTargetV1`] from a readiness handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadinessTargetError {
    /// The fabric rejected the handshake before any terminal existed.
    Fabric(FabricError),
    /// The handshake terminal was not successful, so no readiness target
    /// exists to derive.
    HandshakeNotReady,
}

impl fmt::Display for ReadinessTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fabric(error) => write!(formatter, "readiness handshake failed: {error}"),
            Self::HandshakeNotReady => {
                formatter.write_str("handshake did not reach a successful terminal")
            }
        }
    }
}

impl Error for ReadinessTargetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Fabric(error) => Some(error),
            Self::HandshakeNotReady => None,
        }
    }
}

impl From<FabricError> for ReadinessTargetError {
    fn from(value: FabricError) -> Self {
        Self::Fabric(value)
    }
}

/// Failure while composing or registering product-owned providers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// The product-owned stable provider identity was invalid.
    Api(ApiError),
    /// The injected Native application port could not construct an adapter.
    NativeAdapter(NativeAdapterError),
    /// The bounded fabric rejected construction or registration.
    Fabric(FabricError),
    /// A provider's declared recall scope bindings fall outside the closed
    /// contract vocabulary, so the host refuses to record any authorization.
    RecallScopeBindings(RecallAdmissionError),
    /// Observer registrations were supplied for a disabled composition.
    ObserverWithoutEnabledComposition {
        /// Observer registrations that were supplied.
        observers: usize,
    },
    /// The composed provider set does not fit the fabric's finite registry.
    ProviderSetExceedsRegistryCapacity {
        /// Providers the composition would register.
        providers: usize,
        /// Finite registry capacity the fabric configuration allows.
        maximum: usize,
    },
    /// An observer registration declared the separately selected provider's
    /// own identity, which would make one identity both active and observer.
    ObserverDuplicatesSelectedProvider(String),
    /// Active recall needs at least one admitted scope binding.
    ActiveRecallScopeBindingsMissing(String),
    /// A declared observer tried to enter the active registration role.
    ObserverModeRequired(String),
    /// Foreign code needs an admitted runtime owner; composition lifetime is insufficient.
    LifecycleOwnerRequired(String),
    /// Two observer registrations declared the same provider identity.
    DuplicateObserverProvider(String),
    /// The constructed adapter declared an identity other than the selected
    /// kind's own, so it was never registered.
    SelectedProviderIdentityMismatch {
        /// Identity the selected kind declares.
        expected: String,
        /// Identity the constructed adapter's descriptor declared.
        declared: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => write!(formatter, "provider registry API error: {error}"),
            Self::NativeAdapter(error) => {
                write!(formatter, "Native provider construction failed: {error}")
            }
            Self::Fabric(error) => write!(formatter, "memory fabric error: {error}"),
            Self::RecallScopeBindings(error) => {
                write!(formatter, "provider recall scope bindings invalid: {error}")
            }
            Self::ObserverWithoutEnabledComposition { observers } => write!(
                formatter,
                "{observers} observer registration(s) were supplied for a disabled composition"
            ),
            Self::ProviderSetExceedsRegistryCapacity { providers, maximum } => write!(
                formatter,
                "composed provider set of {providers} exceeds the finite registry capacity of \
                 {maximum}"
            ),
            Self::ObserverDuplicatesSelectedProvider(provider) => write!(
                formatter,
                "observer registration declares the selected provider identity {provider}"
            ),
            Self::ActiveRecallScopeBindingsMissing(provider) => write!(
                formatter,
                "active provider {provider} has no admitted recall scope binding"
            ),
            Self::ObserverModeRequired(provider) => {
                write!(formatter, "observer {provider} must use observer mode")
            }
            Self::LifecycleOwnerRequired(provider) => write!(
                formatter,
                "provider {provider} requires an admitted runtime lifecycle owner"
            ),
            Self::DuplicateObserverProvider(provider) => write!(
                formatter,
                "observer provider {provider} is registered more than once"
            ),
            Self::SelectedProviderIdentityMismatch { expected, declared } => write!(
                formatter,
                "selected provider adapter declared identity {declared}, expected {expected}"
            ),
        }
    }
}

impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Api(error) => Some(error),
            Self::NativeAdapter(error) => Some(error),
            Self::Fabric(error) => Some(error),
            Self::RecallScopeBindings(error) => Some(error),
            Self::ObserverWithoutEnabledComposition { .. }
            | Self::ProviderSetExceedsRegistryCapacity { .. }
            | Self::ObserverDuplicatesSelectedProvider(_)
            | Self::ActiveRecallScopeBindingsMissing(_)
            | Self::ObserverModeRequired(_)
            | Self::LifecycleOwnerRequired(_)
            | Self::DuplicateObserverProvider(_)
            | Self::SelectedProviderIdentityMismatch { .. } => None,
        }
    }
}

impl From<ApiError> for RegistryError {
    fn from(value: ApiError) -> Self {
        Self::Api(value)
    }
}

impl From<NativeAdapterError> for RegistryError {
    fn from(value: NativeAdapterError) -> Self {
        Self::NativeAdapter(value)
    }
}

impl From<FabricError> for RegistryError {
    fn from(value: FabricError) -> Self {
        Self::Fabric(value)
    }
}

/// Retained product-owned provider composition.
///
/// Values can only be produced through
/// [`ProjectMemoryProviderComposition::compose`]. Concrete adapter
/// registration and the mutable fabric surface are intentionally private.
///
/// ```compile_fail,E0624
/// use tracedecay_memory_provider_registry::ProjectMemoryProviderRegistry;
///
/// let _private_constructor = ProjectMemoryProviderRegistry::compose_provider_set;
/// ```
///
/// ```compile_fail,E0624
/// use tracedecay_memory_provider_registry::ProjectMemoryProviderRegistry;
///
/// let _private_registration = ProjectMemoryProviderRegistry::register_selected;
/// ```
///
/// ```compile_fail,E0624
/// use tracedecay_memory_provider_registry::ProjectMemoryProviderRegistry;
///
/// let _private_observer = ProjectMemoryProviderRegistry::register_observer;
/// ```
///
/// ```compile_fail,E0599
/// use tracedecay_memory_provider_registry::ProjectMemoryProviderRegistry;
///
/// fn cannot_escape_fabric(registry: &ProjectMemoryProviderRegistry) {
///     let _ = registry.fabric();
/// }
/// ```
pub struct ProjectMemoryProviderRegistry {
    fabric: Arc<MemoryFabric>,
    selected_provider_id: Option<OwnedProviderId>,
    registrations: BTreeMap<OwnedProviderId, ProviderRegistrationMetadataV1>,
    /// Recall scope bindings the host recorded per provider at registration,
    /// from the provider's declared `recall_scope_bindings` manifest attribute.
    /// Admission reads this record through the admitted call; a provider
    /// reply can never widen it.
    recall_scope_bindings: BTreeMap<OwnedProviderId, RecallScopeBindingsV1>,
}

impl ProjectMemoryProviderRegistry {
    fn compose_provider_set(
        fabric_config: FabricConfig,
        selected: Option<ProviderRegistrationV1>,
        observers: Vec<ProviderRegistrationV1>,
        require_common_profile: bool,
    ) -> Result<Self, RegistryError> {
        let fabric = Arc::new(MemoryFabric::new(fabric_config)?);
        let providers = observers
            .len()
            .saturating_add(usize::from(selected.is_some()));
        if providers > fabric_config.max_registered_providers {
            return Err(RegistryError::ProviderSetExceedsRegistryCapacity {
                providers,
                maximum: fabric_config.max_registered_providers,
            });
        }
        let selected_provider_id = selected.as_ref().map(|item| item.provider_id.clone());
        let mut declared = BTreeMap::new();
        for observer in &observers {
            if observer.mode != EnabledProviderMode::Observer {
                return Err(RegistryError::ObserverModeRequired(
                    observer.provider_id.as_str().to_owned(),
                ));
            }
            if Some(&observer.provider_id) == selected_provider_id.as_ref() {
                return Err(RegistryError::ObserverDuplicatesSelectedProvider(
                    observer.provider_id.as_str().to_owned(),
                ));
            }
            if declared.insert(observer.provider_id.clone(), ()).is_some() {
                return Err(RegistryError::DuplicateObserverProvider(
                    observer.provider_id.as_str().to_owned(),
                ));
            }
        }
        let mut registry = Self {
            fabric,
            selected_provider_id,
            registrations: BTreeMap::new(),
            recall_scope_bindings: BTreeMap::new(),
        };
        if let Some(selected) = selected {
            registry.register_selected(selected, require_common_profile)?;
        }
        for observer in observers {
            registry.register_observer(observer)?;
        }
        Ok(registry)
    }

    fn register_observer(&mut self, observer: ProviderRegistrationV1) -> Result<(), RegistryError> {
        self.register_selected(observer, false)
    }

    /// Returns selected registration metadata, or none for an observer-only set.
    #[must_use]
    pub fn selected_registration(&self) -> Option<&ProviderRegistrationMetadataV1> {
        self.selected_provider_id
            .as_ref()
            .and_then(|id| self.registrations.get(id))
    }

    /// Returns the immutable registration metadata for the bound provider.
    #[must_use]
    pub fn registration(
        &self,
        provider_id: &OwnedProviderId,
    ) -> Option<&ProviderRegistrationMetadataV1> {
        self.registrations.get(provider_id)
    }

    /// Returns the admitted registration for `provider` when it is the active
    /// route in this registry.
    ///
    /// Provider identity is looked up in the registrations captured at
    /// composition time. An invalid or unknown identity, and every observer
    /// registration, returns `None` so a caller cannot turn observation into
    /// active recall by name alone.
    #[must_use]
    pub fn mountable_active_provider(
        &self,
        provider: &str,
    ) -> Option<&ProviderRegistrationMetadataV1> {
        mountable_active_provider(self, provider)
    }

    /// Whether this registry has an admitted active registration for
    /// `provider`.
    #[must_use]
    pub fn is_mountable_active_provider(&self, provider: &str) -> bool {
        self.mountable_active_provider(provider).is_some()
    }

    /// Returns the selected adapter's admitted execution shape.
    /// An observer-only set has no active route; its unused compatibility shape
    /// does not authorize any provider for recall.
    #[must_use]
    pub fn selected_execution_shape(&self) -> ProviderExecutionShapeV1 {
        self.selected_registration().map_or(
            ProviderExecutionShapeV1::HostAuthoredInProcess,
            |registration| registration.execution_shape,
        )
    }

    /// Returns the recall scope bindings the host recorded for `provider_id`
    /// at registration, or `None` when the provider is not registered here.
    ///
    /// This is the only authorization source recall admission accepts.
    #[must_use]
    pub fn recall_scope_bindings(
        &self,
        provider_id: &OwnedProviderId,
    ) -> Option<&RecallScopeBindingsV1> {
        self.recall_scope_bindings.get(provider_id)
    }

    /// Returns deterministic status for every configured provider in
    /// canonical provider-ID order.
    pub fn statuses(&self) -> Result<Vec<ProviderStatus>, FabricError> {
        self.fabric.statuses()
    }

    /// Performs a bounded provider-neutral readiness handshake, preserving
    /// its complete structured terminal evidence.
    pub fn handshake(&self, request: &HandshakeRequest) -> Result<HandshakeResponse, FabricError> {
        self.fabric.handshake(request)
    }

    /// Performs a bounded provider-neutral readiness handshake and, only on
    /// a successful terminal, derives the [`ProviderReadinessTargetV1`] identity the
    /// root composition can map into its own target.
    ///
    /// This method never activates readiness for disabled composition: a
    /// [`ProjectMemoryProviderRegistry`] value exists only inside
    /// [`ProjectMemoryProviderComposition::Enabled`], so there is no
    /// receiver to call it on when composition chose
    /// [`NativeProviderActivation::Disabled`]. It also never weakens an
    /// active-mode safety gate — the derived target reuses exactly the
    /// fields the fabric already validated as present and mutually
    /// consistent before returning `Ok`; a rejected or unsuccessful
    /// handshake yields [`ReadinessTargetError`] and no target.
    pub fn readiness_target(
        &self,
        request: &HandshakeRequest,
    ) -> Result<ProviderReadinessTargetV1, ReadinessTargetError> {
        let response = self.fabric.handshake(request)?;
        if response.terminal.terminal_code() != TerminalCode::Success {
            return Err(ReadinessTargetError::HandshakeNotReady);
        }
        let provider_instance_id = response
            .provider_instance_id
            .ok_or(ReadinessTargetError::HandshakeNotReady)?;
        let ready_receipt_sha256 = response
            .ready_receipt_sha256
            .ok_or(ReadinessTargetError::HandshakeNotReady)?;
        Ok(ProviderReadinessTargetV1 {
            provider_id: response.terminal.provider_id().clone(),
            provider_instance_id,
            registration_revision: request.registration_revision,
            ready_receipt_sha256,
        })
    }

    /// Invokes one operation admitted to influence active product flow.
    ///
    /// The provider-neutral reply, including committed-effect and fallback
    /// evidence and provider/operation identity, is returned unchanged after
    /// fabric validation.
    pub fn invoke_active(&self, call: &ProviderCall) -> Result<ProviderReply, FabricError> {
        self.fabric.invoke_active(call)
    }

    /// Invokes a host-authorized lifecycle control against the original
    /// provider, registration revision and scope pinned by `call`.
    /// Active and observer registrations may receive controls; recall remains
    /// active-only. This route never consults selection or fallback policy.
    ///
    /// The caller must obtain and hold the target's supervised readiness
    /// dispatch guard through this call, including its quarantine checks.
    /// The fabric preserves all live receipt, capability and terminal checks.
    pub fn invoke_control(&self, call: &ProviderCall) -> Result<ProviderReply, FabricError> {
        self.fabric.invoke_control(call)
    }

    /// Routes one active call under an explicit host routing policy.
    ///
    /// The configured provider is refused before any contact unless it is
    /// registered under the pinned revision in active mode with the routed
    /// capability; observer and disabled registrations can never answer. A
    /// fallback directive on the reply is honoured only when the host rule
    /// pins the identical policy and the target is itself a registered active
    /// provider that passes a fresh handshake — otherwise the original
    /// provider's reply is returned with a typed declined reason. Every
    /// returned reply names the provider that produced it.
    pub fn route_active<P: ActiveCallPlan>(
        &self,
        policy: &ActiveRoutingPolicy,
        capability_id: &str,
        plan: &P,
    ) -> Result<RoutedActiveReply, RoutingError<P::Error>> {
        self.fabric.route_active(policy, capability_id, plan)
    }

    /// Delivers an observation while structurally stripping provider output.
    ///
    /// The observer receipt retains the complete validated terminal record,
    /// including its provider and observation-operation binding; it cannot
    /// carry a provider result payload, opaque extensions, or warning text.
    pub fn deliver_observation(&self, call: &ProviderCall) -> Result<ObserverReceipt, FabricError> {
        self.fabric.deliver_observation(call)
    }

    /// Delivers an observation while retaining a rejected provider terminal.
    pub fn deliver_observation_result(
        &self,
        call: &ProviderCall,
    ) -> Result<ObserverDeliveryResult, FabricError> {
        self.fabric.deliver_observation_result(call)
    }

    /// Registers an injected adapter without replacing the fabric's authority.
    fn register_selected(
        &mut self,
        registration: ProviderRegistrationV1,
        require_common_profile: bool,
    ) -> Result<(), RegistryError> {
        let descriptor = registration.provider.descriptor();
        if descriptor.provider_id != registration.provider_id {
            return Err(RegistryError::SelectedProviderIdentityMismatch {
                expected: registration.provider_id.as_str().to_owned(),
                declared: descriptor.provider_id.as_str().to_owned(),
            });
        }
        descriptor.validate()?;
        if require_common_profile && registration.mode == EnabledProviderMode::Active {
            descriptor.validate_common_advisory_profile()?;
        }
        if registration.mode == EnabledProviderMode::Active
            && registration.recall_scope_bindings.is_empty()
        {
            return Err(RegistryError::ActiveRecallScopeBindingsMissing(
                registration.provider_id.as_str().to_owned(),
            ));
        }
        if registration.execution_shape == ProviderExecutionShapeV1::Foreign
            && matches!(
                registration.lifecycle,
                ProviderLifecycleOwnershipV1::CompositionBound
            )
        {
            return Err(RegistryError::LifecycleOwnerRequired(
                registration.provider_id.as_str().to_owned(),
            ));
        }
        let provider_id = registration.provider_id;
        self.fabric.register(
            provider_id.clone(),
            registration.registration_revision,
            registration.mode.fabric_mode(),
            registration.provider,
        )?;
        // The fabric re-reads and retains the descriptor when it registers.
        // Derive metadata and verify the profile against that same authority,
        // so a descriptor changing between reads cannot substitute limits or
        // quietly drop the active profile. A failed composition is never published.
        let registered_descriptor = self
            .fabric
            .statuses()?
            .into_iter()
            .find(|status| status.provider_id == provider_id)
            .ok_or_else(|| FabricError::ProviderUnknown(provider_id.as_str().to_owned()))?
            .descriptor;
        if require_common_profile && registration.mode == EnabledProviderMode::Active {
            registered_descriptor.validate_common_advisory_profile()?;
        }
        if registration.mode == EnabledProviderMode::Active {
            self.recall_scope_bindings
                .insert(provider_id.clone(), registration.recall_scope_bindings);
        }
        self.registrations.insert(
            provider_id.clone(),
            ProviderRegistrationMetadataV1 {
                provider_id,
                registration_revision: registration.registration_revision,
                mode: registration.mode,
                requires_common_advisory_profile: require_common_profile,
                limits: registered_descriptor.limits,
                execution_shape: registration.execution_shape,
                lifecycle: registration.lifecycle,
            },
        );
        Ok(())
    }
}
