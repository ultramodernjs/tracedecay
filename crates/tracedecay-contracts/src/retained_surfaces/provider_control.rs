//! Retained provider-local controls, independent from canonical fact CRUD.
//!
//! Public requests carry retained lookup keys and bounded caller parameters.
//! The host resolves source attribution and the exact provider namespace, then
//! assembles operation identity, readiness, request controls, and history proof.
//! Constructing one of these values never grants provider or source authority.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracedecay_domain::UtcMicros;

use super::{CURRENT_SURFACES, RetainedSurfaceOperation, RetainedSurfaceSpec};
use crate::error::ApplicationContractError;
use tracedecay_tool_catalog::{EffectClass, ScopeDimension};

pub const MAX_PROVIDER_CONTROL_REFERENCE_BYTES: usize = 1024;
pub const MAX_PROVIDER_CONTROL_EVIDENCE_REFS: usize = 64;
pub const MAX_PROVIDER_CONTROL_REASON_BYTES: usize = 8192;
pub const MAX_PROVIDER_CONTROL_INSPECTION_ITEMS: usize = 100_000;
pub const MAX_PROVIDER_CONTROL_RESPONSE_BYTES: usize = 33_554_432;
pub const MAX_PROVIDER_CONTROL_SNAPSHOT_BYTES: u64 = 1_073_741_824;
pub const MAX_PROVIDER_CONTROL_REPLAY_REFS: usize = 4096;

/// An item and exact original-source member retained by the host's recall owner.
/// These lookup keys are never caller-supplied stable source authority.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSourceSelectorV1 {
    #[schemars(length(min = 1, max = 1024))]
    pub trace_ref: String,
    #[schemars(length(min = 1, max = 1024))]
    pub item_ref: String,
    /// Chooses exactly one original source within a potentially derived item.
    #[schemars(length(min = 1, max = 1024))]
    pub observation_id: String,
}

/// A request for host namespace resolution. These fields are untrusted lookup
/// keys; the host must authorize their exact provider, registration, and scope.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlStateSelectorV1 {
    CanonicalSession {
        #[schemars(length(min = 1, max = 1024))]
        provider_id: String,
        #[schemars(range(min = 1))]
        registration_revision: u64,
        /// Exact canonical transcript provider in the registered-session key.
        /// This is distinct from the selected advisory memory provider.
        #[schemars(length(min = 1, max = 1024))]
        canonical_provider_id: String,
        /// Untrusted canonical session address, resolved by the mounted host.
        #[schemars(length(min = 1, max = 1024))]
        session_id: String,
    },
    RecallScope {
        #[schemars(length(min = 1, max = 1024))]
        trace_ref: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlFeedbackSignalV1 {
    Helpful,
    Harmful,
    Ignored,
    Corrected,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlDeletionModeV1 {
    RemoveInfluence,
    HardDelete,
    Anonymize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlMaintenanceTaskV1 {
    Consolidate,
    Decay,
    PruneExpired,
    ValidateState,
    Repair,
    Compact,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlHealthCheckV1 {
    Protocol,
    State,
    Scope,
    Capacity,
    Persistence,
    Recovery,
    Privacy,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlCorrectionKindV1 {
    Supersede,
    RestrictScope,
    ChangeValidity,
    ReplaceContent,
    MarkIncorrect,
}

/// Replacement observations are point-read through existing retained source selectors.
/// Metadata changes remain requests for authorization, not admitted wire data.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlCorrectionV1 {
    Supersede {
        replacement_source: ProviderControlSourceSelectorV1,
    },
    ReplaceContent {
        replacement_source: ProviderControlSourceSelectorV1,
    },
    ChangeValidity {
        valid_from: UtcMicros,
        valid_until: Option<UtcMicros>,
    },
    MarkIncorrect {
        revoked_at: UtcMicros,
    },
    RestrictScope {
        destination: ProviderControlStateSelectorV1,
    },
}

impl ProviderControlCorrectionV1 {
    pub const fn kind(&self) -> ProviderControlCorrectionKindV1 {
        match self {
            Self::Supersede { .. } => ProviderControlCorrectionKindV1::Supersede,
            Self::ReplaceContent { .. } => ProviderControlCorrectionKindV1::ReplaceContent,
            Self::ChangeValidity { .. } => ProviderControlCorrectionKindV1::ChangeValidity,
            Self::MarkIncorrect { .. } => ProviderControlCorrectionKindV1::MarkIncorrect,
            Self::RestrictScope { .. } => ProviderControlCorrectionKindV1::RestrictScope,
        }
    }
}

/// An explicit caller feedback assertion. The host durably records the
/// authenticated assertion and supplies its real outcome receipt to the provider.
/// Acceptance does not establish objective usefulness or provider completion.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFeedbackRequestV1 {
    pub source: ProviderControlSourceSelectorV1,
    pub signal: ProviderControlFeedbackSignalV1,
    /// Canonical decimal text in the closed interval zero through one.
    #[schemars(length(min = 1, max = 64))]
    pub weight: String,
    /// Bounded caller evidence claims. These are not resolved as host authority
    /// and do not establish objective usefulness or provider completion.
    #[schemars(length(max = 64))]
    pub evidence_refs: Vec<String>,
    pub occurred_at: UtcMicros,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCorrectionRequestV1 {
    pub source: ProviderControlSourceSelectorV1,
    #[schemars(length(min = 1, max = 1024))]
    pub expected_source_revision: String,
    pub correction: ProviderControlCorrectionV1,
    #[schemars(length(min = 1, max = 8192))]
    pub reason: String,
    /// Bounded caller claims; target and replacement sources are independently authorized.
    #[schemars(length(max = 64))]
    pub evidence_refs: Vec<String>,
}

/// One source, one durable host fence compare-and-set, and one erasure action.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeleteBySourceRequestV1 {
    pub source: ProviderControlSourceSelectorV1,
    pub mode: ProviderControlDeletionModeV1,
    pub expected_fence_revision: u64,
    pub include_snapshots: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderHealthRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    #[schemars(length(min = 1, max = 7))]
    pub requested_checks: Vec<ProviderControlHealthCheckV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlInspectionViewV1 {
    StateSummary,
    SourceInfluence,
    Trace,
    DeliveryReceipt,
    MaintenanceReceipt,
    SnapshotMetadata,
    CapabilityStatus,
}

/// Receipt and snapshot references are untrusted keys looked up within the
/// separately authorized state namespace. Source views also require the host's
/// retained recall-item resolver; no provider stable reference is accepted.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "view", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlInspectionSelectorV1 {
    StateSummary,
    SourceInfluence {
        source: ProviderControlSourceSelectorV1,
    },
    Trace {
        source: ProviderControlSourceSelectorV1,
    },
    DeliveryReceipt {
        source: ProviderControlSourceSelectorV1,
    },
    /// Provider-reported outcome query using actual returned control identities.
    /// Caller-supplied identities do not grant host receipt authority.
    MaintenanceReceipt {
        #[schemars(length(min = 1, max = 256))]
        operation_id: String,
        #[schemars(length(min = 64, max = 64))]
        idempotency_key: String,
    },
    SnapshotMetadata {
        #[schemars(length(min = 1, max = 1024))]
        snapshot_ref: String,
    },
    CapabilityStatus,
}

impl ProviderControlInspectionSelectorV1 {
    pub const fn view(&self) -> ProviderControlInspectionViewV1 {
        match self {
            Self::StateSummary => ProviderControlInspectionViewV1::StateSummary,
            Self::SourceInfluence { .. } => ProviderControlInspectionViewV1::SourceInfluence,
            Self::Trace { .. } => ProviderControlInspectionViewV1::Trace,
            Self::DeliveryReceipt { .. } => ProviderControlInspectionViewV1::DeliveryReceipt,
            Self::MaintenanceReceipt { .. } => ProviderControlInspectionViewV1::MaintenanceReceipt,
            Self::SnapshotMetadata { .. } => ProviderControlInspectionViewV1::SnapshotMetadata,
            Self::CapabilityStatus => ProviderControlInspectionViewV1::CapabilityStatus,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderInspectionRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    pub selection: ProviderControlInspectionSelectorV1,
    #[schemars(range(min = 1, max = 100000))]
    pub maximum_items: u64,
    #[schemars(range(min = 1, max = 33554432))]
    pub maximum_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 1024))]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderMaintenanceRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    pub task: ProviderControlMaintenanceTaskV1,
    #[schemars(range(min = 1, max = 1000000))]
    pub maximum_items: u64,
    #[schemars(range(min = 1, max = 1073741824))]
    pub maximum_bytes: u64,
    #[schemars(range(min = 1, max = 3600000))]
    pub maximum_duration_millis: u64,
    pub dry_run: bool,
    /// Opaque continuation returned by this provider for the same maintenance query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 1024))]
    pub resume_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshotExportRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    /// The host also applies the negotiated snapshot and response byte limits.
    #[schemars(range(min = 1, max = 1073741824))]
    pub maximum_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshotRestoreRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    #[schemars(length(min = 1, max = 1024))]
    pub snapshot_ref: String,
    pub expected_state_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderReplayRequestV1 {
    pub state: ProviderControlStateSelectorV1,
    /// Host-retained canonical receipts, never provider snapshot references.
    #[schemars(length(min = 1, max = 4096))]
    pub observation_batch_refs: Vec<String>,
    pub first_source_sequence: u64,
    pub last_source_sequence: u64,
    pub expected_state_generation: u64,
    pub expected_previous_acknowledged_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderControlRequestV1 {
    Feedback(ProviderFeedbackRequestV1),
    Correction(ProviderCorrectionRequestV1),
    DeleteBySource(ProviderDeleteBySourceRequestV1),
    Health(ProviderHealthRequestV1),
    Inspection(ProviderInspectionRequestV1),
    Maintenance(ProviderMaintenanceRequestV1),
    SnapshotExport(ProviderSnapshotExportRequestV1),
    SnapshotRestore(ProviderSnapshotRestoreRequestV1),
    Replay(ProviderReplayRequestV1),
}

impl ProviderControlRequestV1 {
    pub const fn operation(&self) -> RetainedSurfaceOperation {
        match self {
            Self::Feedback(_) => RetainedSurfaceOperation::ProviderFeedback,
            Self::Correction(_) => RetainedSurfaceOperation::ProviderCorrection,
            Self::DeleteBySource(_) => RetainedSurfaceOperation::ProviderDeleteBySource,
            Self::Health(_) => RetainedSurfaceOperation::ProviderHealth,
            Self::Inspection(_) => RetainedSurfaceOperation::ProviderInspection,
            Self::Maintenance(_) => RetainedSurfaceOperation::ProviderMaintenance,
            Self::SnapshotExport(_) => RetainedSurfaceOperation::ProviderSnapshotExport,
            Self::SnapshotRestore(_) => RetainedSurfaceOperation::ProviderSnapshotRestore,
            Self::Replay(_) => RetainedSurfaceOperation::ProviderReplay,
        }
    }

    pub fn state_selector(&self) -> Option<&ProviderControlStateSelectorV1> {
        match self {
            Self::Health(request) => Some(&request.state),
            Self::Inspection(request) => Some(&request.state),
            Self::Maintenance(request) => Some(&request.state),
            Self::SnapshotExport(request) => Some(&request.state),
            Self::SnapshotRestore(request) => Some(&request.state),
            Self::Replay(request) => Some(&request.state),
            Self::Feedback(_) | Self::Correction(_) | Self::DeleteBySource(_) => None,
        }
    }

    /// Bounds and time validation only. Canonical receipt settlement, exact
    /// source ownership, namespace authorization, and disposition are host reads.
    pub fn validate_at(&self, observed_at: UtcMicros) -> Result<(), ApplicationContractError> {
        if let Some(state) = self.state_selector() {
            validate_state_selector(state)?;
        }
        match self {
            Self::Feedback(request) => {
                validate_source_selector(&request.source)?;
                require(valid_weight(&request.weight), "provider feedback weight")?;
                validate_references(
                    &request.evidence_refs,
                    0,
                    MAX_PROVIDER_CONTROL_EVIDENCE_REFS,
                )?;
                require(
                    request.occurred_at <= observed_at,
                    "provider feedback occurrence",
                )
            }
            Self::Correction(request) => {
                validate_source_selector(&request.source)?;
                validate_reference(&request.expected_source_revision)?;
                require(
                    valid_text(&request.reason, MAX_PROVIDER_CONTROL_REASON_BYTES),
                    "provider correction reason",
                )?;
                validate_references(
                    &request.evidence_refs,
                    0,
                    MAX_PROVIDER_CONTROL_EVIDENCE_REFS,
                )?;
                match &request.correction {
                    ProviderControlCorrectionV1::Supersede { replacement_source }
                    | ProviderControlCorrectionV1::ReplaceContent { replacement_source } => {
                        validate_source_selector(replacement_source)
                    }
                    ProviderControlCorrectionV1::ChangeValidity {
                        valid_from,
                        valid_until,
                    } => require(
                        valid_until.is_none_or(|until| until > *valid_from),
                        "provider correction validity",
                    ),
                    ProviderControlCorrectionV1::MarkIncorrect { .. } => Ok(()),
                    ProviderControlCorrectionV1::RestrictScope { destination } => {
                        validate_state_selector(destination)
                    }
                }
            }
            Self::DeleteBySource(request) => validate_source_selector(&request.source),
            Self::Health(request) => {
                require(
                    !request.requested_checks.is_empty() && request.requested_checks.len() <= 7,
                    "provider health checks",
                )?;
                for (index, check) in request.requested_checks.iter().enumerate() {
                    require(
                        !request.requested_checks[..index].contains(check),
                        "duplicate provider health check",
                    )?;
                }
                Ok(())
            }
            Self::Inspection(request) => {
                require(
                    (1..=MAX_PROVIDER_CONTROL_INSPECTION_ITEMS as u64)
                        .contains(&request.maximum_items),
                    "provider inspection items",
                )?;
                require(
                    (1..=MAX_PROVIDER_CONTROL_RESPONSE_BYTES as u64)
                        .contains(&request.maximum_bytes),
                    "provider inspection bytes",
                )?;
                if let Some(cursor) = &request.cursor {
                    validate_reference(cursor)?;
                }
                match &request.selection {
                    ProviderControlInspectionSelectorV1::SourceInfluence { source }
                    | ProviderControlInspectionSelectorV1::Trace { source } => {
                        validate_source_selector(source)
                    }
                    ProviderControlInspectionSelectorV1::DeliveryReceipt { source } => {
                        validate_source_selector(source)
                    }
                    ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                        operation_id,
                        idempotency_key,
                    } => require(
                        valid_uuid_v7(operation_id) && valid_sha256(idempotency_key),
                        "maintenance receipt query identities",
                    ),
                    ProviderControlInspectionSelectorV1::SnapshotMetadata { snapshot_ref } => {
                        validate_reference(snapshot_ref)
                    }
                    ProviderControlInspectionSelectorV1::StateSummary
                    | ProviderControlInspectionSelectorV1::CapabilityStatus => Ok(()),
                }
            }
            Self::Maintenance(request) => {
                if let Some(cursor) = &request.resume_cursor {
                    validate_reference(cursor)?;
                }
                require(
                    (1..=1_000_000).contains(&request.maximum_items),
                    "provider maintenance items",
                )?;
                require(
                    (1..=1_073_741_824).contains(&request.maximum_bytes),
                    "provider maintenance bytes",
                )?;
                require(
                    (1..=3_600_000).contains(&request.maximum_duration_millis),
                    "provider maintenance duration",
                )
            }
            Self::SnapshotExport(request) => require(
                (1..=MAX_PROVIDER_CONTROL_SNAPSHOT_BYTES).contains(&request.maximum_bytes),
                "provider snapshot bytes",
            ),
            Self::SnapshotRestore(request) => validate_reference(&request.snapshot_ref),
            Self::Replay(request) => {
                validate_references(
                    &request.observation_batch_refs,
                    1,
                    MAX_PROVIDER_CONTROL_REPLAY_REFS,
                )?;
                require(
                    request.first_source_sequence <= request.last_source_sequence,
                    "provider replay sequence bounds",
                )
            }
        }
    }
}

fn require(condition: bool, field: &'static str) -> Result<(), ApplicationContractError> {
    if condition {
        Ok(())
    } else {
        Err(ApplicationContractError::InvalidRange { field })
    }
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_reference(value: &str) -> Result<(), ApplicationContractError> {
    require(
        valid_text(value, MAX_PROVIDER_CONTROL_REFERENCE_BYTES),
        "provider control reference",
    )
}

fn validate_references(
    values: &[String],
    minimum: usize,
    maximum: usize,
) -> Result<(), ApplicationContractError> {
    require(
        (minimum..=maximum).contains(&values.len()),
        "provider control reference count",
    )?;
    let mut unique = BTreeSet::new();
    for value in values {
        validate_reference(value)?;
        require(unique.insert(value), "duplicate provider control reference")?;
    }
    Ok(())
}

fn validate_source_selector(
    source: &ProviderControlSourceSelectorV1,
) -> Result<(), ApplicationContractError> {
    validate_reference(&source.trace_ref)?;
    validate_reference(&source.item_ref)?;
    validate_reference(&source.observation_id)
}

fn validate_state_selector(
    state: &ProviderControlStateSelectorV1,
) -> Result<(), ApplicationContractError> {
    match state {
        ProviderControlStateSelectorV1::CanonicalSession {
            provider_id,
            registration_revision,
            canonical_provider_id,
            session_id,
        } => {
            validate_reference(provider_id)?;
            validate_reference(canonical_provider_id)?;
            validate_reference(session_id)?;
            require(*registration_revision > 0, "provider registration revision")
        }
        ProviderControlStateSelectorV1::RecallScope { trace_ref } => validate_reference(trace_ref),
    }
}

fn valid_weight(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    if matches!(value, "0" | "1") {
        return true;
    }
    let Some((whole, fractional)) = value.split_once('.') else {
        return false;
    };
    !fractional.is_empty()
        && fractional.bytes().all(|byte| byte.is_ascii_digit())
        && (whole == "0" || (whole == "1" && fractional.bytes().all(|byte| byte == b'0')))
}

/// Bounded advisory data for explicitly open provider-local fields only.
/// This does not carry pinned source, target, receipt, or scope identities.
/// Host wire validation and redaction must precede constructing a projection.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProviderControlEvidenceV1(serde_json::Value);

impl ProviderControlEvidenceV1 {
    pub fn new(value: serde_json::Value) -> Result<Self, ApplicationContractError> {
        let evidence = Self(value);
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn validate(&self) -> Result<(), ApplicationContractError> {
        let mut pending = vec![(&self.0, 0_usize)];
        let mut count = 0;
        while let Some((value, depth)) = pending.pop() {
            count += 1;
            require(depth <= 8 && count <= 4096, "provider evidence structure")?;
            match value {
                serde_json::Value::String(text) => {
                    require(text.len() <= 8192, "provider evidence text")?
                }
                serde_json::Value::Array(values) => {
                    pending.extend(values.iter().map(|value| (value, depth + 1)))
                }
                serde_json::Value::Object(values) => {
                    for (key, value) in values {
                        require(valid_text(key, 256), "provider evidence key")?;
                        pending.push((value, depth + 1));
                    }
                }
                _ => {}
            }
        }
        require(
            serde_json::to_vec(&self.0).is_ok_and(|bytes| bytes.len() <= 65_536),
            "provider evidence bytes",
        )
    }
}

impl<'de> Deserialize<'de> for ProviderControlEvidenceV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(serde_json::Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Producing namespace retained by the host. This type is output only; public
/// state selectors cannot submit an exact scope or its digest for admission.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlScopeV1 {
    pub profile_id: String,
    pub project_id: String,
    pub repository_identity: String,
    pub worktree_identity: String,
    pub branch_identity: String,
    pub agent_session_id: String,
    pub resolved_scope_digest: String,
}

/// Exact original identity projected only after host validation of the full
/// canonical source attribution. Unknown legacy revision remains null.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSourceIdentityV1 {
    pub canonical_provider_id: String,
    pub canonical_session_id: String,
    pub source_key: String,
    pub stable_record_id: Option<String>,
    pub observation_id: String,
    pub source_revision: Option<String>,
    /// Original canonical source-payload digest, not projected content bytes.
    pub content_sha256: String,
}

/// Public projection of one fully validated lifecycle target. The host retains
/// and validates original/delivery scope and target-reference kind separately;
/// this projection cannot be round-tripped as an input authority selector.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSourceTargetV1 {
    pub stable_memory_ref: String,
    pub source: ProviderControlSourceIdentityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlTerminalV1 {
    Success,
    SuccessZeroResults,
    Partial,
    InvalidRequest,
    Unauthorized,
    CapabilityUnsupported,
    ScopeUnavailable,
    ScopeMismatch,
    StaleIdentity,
    Conflict,
    CapacityExceeded,
    DeadlineExceeded,
    Cancelled,
    ProviderUnavailable,
    ResetRequired,
    StateIncompatible,
    PartialEffect,
    EffectUnknown,
    ContractViolation,
    InternalFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlEffectStateV1 {
    None,
    Committed,
    Duplicate,
    Partial,
    Unknown,
}

/// Complete provider effect evidence, independent from the outer application's
/// durable receipt. An offline deletion can commit a host fence while this
/// provider effect remains none and provider erasure remains pending.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlEffectV1 {
    pub state: ProviderControlEffectStateV1,
    pub committed_boundary: Option<String>,
    pub state_generation_before: Option<u64>,
    pub state_generation_after: Option<u64>,
    #[schemars(length(max = 4096))]
    pub committed_item_refs: Vec<String>,
    #[schemars(length(max = 4096))]
    pub uncommitted_item_refs: Vec<String>,
    pub provider_receipt_digest: Option<String>,
    pub reconciliation_action: Option<String>,
    pub verification_digest: Option<String>,
    pub duplicate_of_idempotency_key: Option<String>,
    pub duplicate_of_operation_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlDomainDetailV1 {
    /// Bounded lifecycle refinement such as target_unknown or revision_conflict.
    pub code: String,
    pub message: String,
}

/// Operation-specific receipt fields retain the original committing response;
/// a duplicate attempt's unchanged live generation lives in `effect` instead.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlMutationReceiptV1 {
    pub state_generation_before: u64,
    pub state_generation_after: u64,
    pub provider_receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFeedbackResultV1 {
    pub source: ProviderControlSourceSelectorV1,
    pub target: ProviderControlSourceTargetV1,
    pub target_digest: String,
    pub signal: ProviderControlFeedbackSignalV1,
    pub applied_effect: ProviderControlEvidenceV1,
    pub receipt: ProviderControlMutationReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCorrectionResultV1 {
    pub source: ProviderControlSourceSelectorV1,
    pub target: ProviderControlSourceTargetV1,
    pub target_digest: String,
    pub correction_kind: ProviderControlCorrectionKindV1,
    pub affected_provider_effects: u64,
    pub receipt: ProviderControlMutationReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlDeletionIntentV1 {
    pub fence_revision_before: u64,
    pub fence_revision_after: u64,
    /// Proves the host's durable fence acceptance only, never provider erasure.
    pub host_receipt: crate::EffectReceipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlDeletionVerificationV1 {
    VerifiedAbsent,
    VerifiedAnonymized,
    RetainedUnderExplicitLock,
    VerificationFailed,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlDeletionPostconditionV1 {
    pub matched_effects: u64,
    pub removed_effects: u64,
    pub anonymized_effects: u64,
    pub retained_under_lock: u64,
    pub remaining_influence_count: u64,
    pub snapshots_examined: u64,
    pub snapshots_rewritten: u64,
    pub verification_query_digest: String,
    pub verification_state: ProviderControlDeletionVerificationV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlErasureV1 {
    Pending {
        reason_code: String,
    },
    Verified {
        postcondition: ProviderControlDeletionPostconditionV1,
        receipt: ProviderControlMutationReceiptV1,
    },
    RetainedUnderLock {
        postcondition: ProviderControlDeletionPostconditionV1,
        /// Actual provider control receipt for its reported retention outcome.
        /// This is not independent host authorization of a retention lock.
        retention_lock_receipt: String,
        receipt: ProviderControlMutationReceiptV1,
    },
    Failed {
        reason_code: String,
        postcondition: Option<ProviderControlDeletionPostconditionV1>,
        receipt: Option<ProviderControlMutationReceiptV1>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlHostSnapshotCleanupV1 {
    pub state: ProviderControlHostSnapshotCleanupStateV1,
    pub removed_snapshot_refs: Vec<String>,
    pub matched_count: u64,
    pub unverifiable_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlHostSnapshotCleanupStateV1 {
    NotRequested,
    Complete,
    Partial,
    Unverifiable,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeleteBySourceResultV1 {
    pub source: ProviderControlSourceSelectorV1,
    pub target: ProviderControlSourceTargetV1,
    pub mode: ProviderControlDeletionModeV1,
    pub include_snapshots: bool,
    pub intent: ProviderControlDeletionIntentV1,
    /// Actual host artifact cleanup, independent of provider erasure evidence.
    pub host_snapshot_cleanup: ProviderControlHostSnapshotCleanupV1,
    pub erasure: ProviderControlErasureV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlReadinessV1 {
    Ready,
    Degraded,
    NotReady,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlCapabilityStatusV1 {
    pub capability_id: String,
    /// Provider-declared capability state, not an inferred grant or readiness.
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderHealthResultV1 {
    pub provider_instance_id: String,
    pub implementation_identity_digest: String,
    pub state_identity_digest: String,
    pub state_generation: u64,
    pub scope_digest: String,
    pub readiness: ProviderControlReadinessV1,
    pub capability_states: Vec<ProviderControlCapabilityStatusV1>,
    pub effective_limits_digest: String,
    pub backlog: ProviderControlEvidenceV1,
    pub recovery_state: ProviderControlEvidenceV1,
    /// Actual provider-reported row count; omission is not a reported zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_rows: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlSourceDispositionV1 {
    Available,
    Superseded,
    Revoked,
    Deleted,
    Redacted,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSettledFeedbackV1 {
    pub helpful: u64,
    pub harmful: u64,
    pub ignored: u64,
    pub corrected: u64,
    pub superseded: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSourceInfluenceItemV1 {
    pub target: ProviderControlSourceTargetV1,
    pub active: bool,
    pub disposition: ProviderControlSourceDispositionV1,
    pub settled_feedback: ProviderControlSettledFeedbackV1,
    pub last_feedback_receipt: Option<String>,
    #[schemars(length(min = 1, max = 8192))]
    pub provider_local_effect_summary: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlTraceItemV1 {
    pub stable_memory_ref: String,
    pub content: Option<String>,
    /// SHA-256 of exactly the emitted UTF-8 content, including truncation.
    pub content_sha256: Option<String>,
    /// Identity projection of retained original attribution, or null without
    /// synthesis. Full original scope and validity stay with the host resolver.
    pub original_source: Option<ProviderControlSourceIdentityV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlDeliveryReceiptItemV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub provider_receipt_digest: String,
    pub stable_memory_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlSnapshotIdentityV1 {
    pub snapshot_id: String,
    pub provider_id: String,
    pub implementation_identity_digest: String,
    pub state_schema_version: String,
    pub exact_scope_digest: String,
    pub state_generation: u64,
    pub observation_sequence: u64,
    pub parent_snapshot_id: Option<String>,
    pub content_sha256: String,
    pub byte_length: u64,
    /// Exact RFC3339 timestamp after canonical wire validation by the host.
    /// It remains text so the public projection cannot truncate nanoseconds.
    #[schemars(length(min = 1, max = 64), extend("format" = "date-time"))]
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderMaintenanceResultV1 {
    pub task: ProviderControlMaintenanceTaskV1,
    pub dry_run: bool,
    pub scanned_items: u64,
    pub changed_items: u64,
    pub removed_items: u64,
    /// Provider-reported proposals, distinct from changes actually applied.
    /// A provider may propose multiple actions for one scanned item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_changes: Option<u64>,
    /// Actual provider kernel-state comparison, independent of row changes.
    /// Omission means the producer did not establish whether that state changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_changed: Option<bool>,
    pub partial: bool,
    pub resume_cursor: Option<String>,
    pub receipt: ProviderControlMutationReceiptV1,
}

/// Every pinned inspection identity is a closed typed field. Only state-summary
/// content is provider-local open evidence; source and receipt views cannot use
/// that variant, and the host validates each original wire binding first.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "view",
    content = "items",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderControlInspectionItemsV1 {
    StateSummary(Vec<ProviderControlEvidenceV1>),
    SourceInfluence(Vec<ProviderControlSourceInfluenceItemV1>),
    Trace(Vec<ProviderControlTraceItemV1>),
    DeliveryReceipt(Vec<ProviderControlDeliveryReceiptItemV1>),
    MaintenanceReceipt(Vec<ProviderControlMaintenanceReceiptItemV1>),
    SnapshotMetadata(Vec<ProviderControlSnapshotIdentityV1>),
    CapabilityStatus(Vec<ProviderControlCapabilityStatusV1>),
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlMaintenanceReceiptItemV1 {
    pub operation_id: String,
    pub idempotency_key: String,
    pub outcome: ProviderMaintenanceResultV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderControlInspectionCoverageV1 {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlInspectionEvidenceOriginV1 {
    ProviderRuntime,
    HostSnapshotArtifact {
        snapshot_ref: String,
        export_registration_revision: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderInspectionResultV1 {
    pub selection: ProviderControlInspectionSelectorV1,
    pub evidence_origin: ProviderControlInspectionEvidenceOriginV1,
    pub items: ProviderControlInspectionItemsV1,
    pub coverage: ProviderControlInspectionCoverageV1,
    pub next_cursor: Option<String>,
    pub redactions: Vec<String>,
    /// Current generation observed by a provider runtime; unknown for a host artifact.
    pub state_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshotExportResultV1 {
    /// Host-retained immutable snapshot reference; opaque lookup, not authority.
    pub snapshot_ref: String,
    pub identity: ProviderControlSnapshotIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshotRestoreResultV1 {
    pub snapshot_ref: String,
    pub snapshot_id: String,
    pub restored_observation_sequence: u64,
    /// Actual restored row count, independent of the restored sequence watermark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_rows: Option<u64>,
    pub receipt: ProviderControlMutationReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderReplayResultV1 {
    pub first_source_sequence: u64,
    pub last_source_sequence: u64,
    pub acknowledged_sequence: u64,
    /// Actual host-resolved observation inventory size, not receipt-ref count.
    pub resolved_observations: u64,
    pub applied_observations: u64,
    pub duplicate_observations: u64,
    pub sources_already_applied: u64,
    pub rejected_observations: u64,
    pub effect_unknown_observations: u64,
    pub partial: bool,
    pub receipt: ProviderControlMutationReceiptV1,
}

/// Null data is allowed for a typed unsuccessful provider terminal only.
/// Successful operations must carry their actual operation-specific evidence.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "operation",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderControlOperationResultV1 {
    Feedback(Option<ProviderFeedbackResultV1>),
    Correction(Option<ProviderCorrectionResultV1>),
    DeleteBySource(Option<Box<ProviderDeleteBySourceResultV1>>),
    Health(Option<ProviderHealthResultV1>),
    Inspection(Option<ProviderInspectionResultV1>),
    Maintenance(Option<ProviderMaintenanceResultV1>),
    SnapshotExport(Option<ProviderSnapshotExportResultV1>),
    SnapshotRestore(Option<ProviderSnapshotRestoreResultV1>),
    Replay(Option<ProviderReplayResultV1>),
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderControlResultV1 {
    pub provider_id: String,
    pub registration_revision: u64,
    pub scope: ProviderControlScopeV1,
    /// Host-assembled lifecycle UUIDv7; original duplicates are named in effect.
    pub operation_id: String,
    pub idempotency_key: Option<String>,
    pub terminal: ProviderControlTerminalV1,
    /// Exact provider diagnostic reference, never a synthesized explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub diagnostic_id: Option<String>,
    pub domain_detail: Option<ProviderControlDomainDetailV1>,
    pub effect: ProviderControlEffectV1,
    pub result: ProviderControlOperationResultV1,
    #[schemars(length(max = 32))]
    pub warnings: Vec<String>,
}

impl ProviderControlScopeV1 {
    pub fn validate(&self) -> Result<(), ApplicationContractError> {
        for value in [
            &self.profile_id,
            &self.project_id,
            &self.repository_identity,
            &self.worktree_identity,
            &self.branch_identity,
            &self.agent_session_id,
        ] {
            validate_reference(value)?;
            require(value != "*", "provider scope wildcard")?;
        }
        require(
            self.resolved_scope_digest
                .strip_prefix("sha256:")
                .is_some_and(valid_sha256),
            "provider resolved scope digest",
        )
    }

    /// Derives the provider namespace for a canonical session in this exact scope.
    /// This binds lookup and delivery identities; it grants no session authority.
    pub fn agent_session_id_for_canonical_session(&self, canonical_session_id: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"tracedecay.memory-provider.agent-session-binding.v1\0");
        for value in [
            self.profile_id.as_str(),
            self.project_id.as_str(),
            self.repository_identity.as_str(),
            self.worktree_identity.as_str(),
            self.branch_identity.as_str(),
            self.resolved_scope_digest.as_str(),
            canonical_session_id,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        format!("tdmem-agent-session.v1.{}", hex::encode(digest.finalize()))
    }

    /// Canonical representation digest, not a grant or proof of source authority.
    pub fn sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"tracedecay.memory-provider.exact-scope.v1\0");
        for value in [
            &self.profile_id,
            &self.project_id,
            &self.repository_identity,
            &self.worktree_identity,
            &self.branch_identity,
            &self.agent_session_id,
            &self.resolved_scope_digest,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        hex::encode(digest.finalize())
    }
}

impl ProviderControlSourceIdentityV1 {
    fn validate(&self) -> Result<(), ApplicationContractError> {
        for value in [
            &self.canonical_provider_id,
            &self.canonical_session_id,
            &self.source_key,
            &self.observation_id,
        ] {
            validate_reference(value)?;
        }
        for value in [&self.stable_record_id, &self.source_revision]
            .into_iter()
            .flatten()
        {
            validate_reference(value)?;
        }
        require(
            valid_sha256(&self.content_sha256),
            "provider original content digest",
        )
    }
}

impl ProviderControlSourceTargetV1 {
    fn validate(&self) -> Result<(), ApplicationContractError> {
        validate_reference(&self.stable_memory_ref)?;
        self.source.validate()
    }
}

impl ProviderControlEffectV1 {
    /// Validates retained effect evidence, including disjoint partial partitions.
    /// An unknown outcome may be observed by the host without a provider reply
    /// or confirmed host intent, so only that retained shape permits an absent
    /// provider receipt. A present digest must still name actual provider evidence;
    /// host uncertainty never supplies a replacement provider receipt.
    /// The core provider-reply contract keeps its stricter receipt requirement.
    pub fn validate(&self) -> Result<(), ApplicationContractError> {
        require(
            self.committed_item_refs
                .len()
                .checked_add(self.uncommitted_item_refs.len())
                .is_some_and(|count| count <= 4096),
            "provider effect item count",
        )?;
        let mut references = BTreeSet::new();
        for value in self
            .committed_item_refs
            .iter()
            .chain(&self.uncommitted_item_refs)
        {
            require(
                valid_text(value, 256) && references.insert(value),
                "provider effect item partition",
            )?;
        }
        for value in [&self.provider_receipt_digest, &self.verification_digest]
            .into_iter()
            .flatten()
        {
            require(valid_sha256(value), "provider effect digest")?;
        }
        if let Some(value) = &self.committed_boundary {
            require(valid_text(value, 256), "provider committed boundary")?;
        }
        if let Some(value) = &self.reconciliation_action {
            require(valid_text(value, 512), "provider reconciliation action")?;
        }
        if let Some(value) = &self.duplicate_of_idempotency_key {
            require(valid_sha256(value), "provider duplicate key")?;
        }
        if let Some(value) = &self.duplicate_of_operation_id {
            require(
                valid_text(value, 256),
                "provider original operation identity",
            )?;
        }
        if self.state != ProviderControlEffectStateV1::Duplicate {
            require(
                self.duplicate_of_idempotency_key.is_none()
                    && self.duplicate_of_operation_id.is_none(),
                "provider duplicate identity",
            )?;
        }
        let same_generation = self.state_generation_before == self.state_generation_after;
        let known_generations = matches!((self.state_generation_before, self.state_generation_after), (Some(before), Some(after)) if after >= before);
        let no_items = self.committed_item_refs.is_empty() && self.uncommitted_item_refs.is_empty();
        let valid = match self.state {
            ProviderControlEffectStateV1::None => {
                same_generation
                    && self.committed_boundary.is_none()
                    && no_items
                    && self.provider_receipt_digest.is_none()
                    && self.reconciliation_action.is_none()
                    && self.verification_digest.is_none()
            }
            ProviderControlEffectStateV1::Committed => {
                known_generations
                    && self.committed_boundary.is_none()
                    && self.uncommitted_item_refs.is_empty()
                    && self.provider_receipt_digest.is_some()
                    && self.reconciliation_action.is_none()
                    && self.verification_digest.is_some()
            }
            ProviderControlEffectStateV1::Duplicate => {
                known_generations
                    && same_generation
                    && self.committed_boundary.is_none()
                    && no_items
                    && self.provider_receipt_digest.is_some()
                    && self.reconciliation_action.is_none()
                    && self.verification_digest.is_none()
                    && self.duplicate_of_idempotency_key.is_some()
                    && self.duplicate_of_operation_id.is_some()
            }
            ProviderControlEffectStateV1::Partial => {
                known_generations
                    && self.committed_boundary.is_some()
                    && !self.committed_item_refs.is_empty()
                    && !self.uncommitted_item_refs.is_empty()
                    && self.provider_receipt_digest.is_some()
                    && self.reconciliation_action.is_some()
                    && self.verification_digest.is_some()
            }
            ProviderControlEffectStateV1::Unknown => {
                self.state_generation_before.is_none()
                    && self.state_generation_after.is_none()
                    && self.committed_boundary.is_none()
                    && no_items
                    && self.reconciliation_action.is_some()
                    && self.verification_digest.is_none()
            }
        };
        require(valid, "provider committed effect shape")
    }
}

impl ProviderControlMutationReceiptV1 {
    fn validate(&self) -> Result<(), ApplicationContractError> {
        require(
            self.state_generation_after >= self.state_generation_before
                && valid_sha256(&self.provider_receipt_digest),
            "provider mutation receipt",
        )
    }
}

impl ProviderControlDeletionPostconditionV1 {
    fn validate(&self) -> Result<(), ApplicationContractError> {
        require(
            self.removed_effects <= self.matched_effects
                && self.anonymized_effects <= self.matched_effects
                && self.retained_under_lock <= self.matched_effects
                && self.snapshots_rewritten <= self.snapshots_examined,
            "provider deletion counts",
        )?;
        require(
            valid_sha256(&self.verification_query_digest),
            "provider deletion verification digest",
        )
    }
}

impl ProviderControlSnapshotIdentityV1 {
    fn validate_for(
        &self,
        provider_id: &str,
        scope: &ProviderControlScopeV1,
    ) -> Result<(), ApplicationContractError> {
        validate_reference(&self.snapshot_id)?;
        if let Some(parent) = &self.parent_snapshot_id {
            validate_reference(parent)?;
        }
        require(
            self.provider_id == provider_id && self.exact_scope_digest == scope.sha256(),
            "provider snapshot identity binding",
        )?;
        require(
            valid_text(
                &self.state_schema_version,
                MAX_PROVIDER_CONTROL_REFERENCE_BYTES,
            ) && self.byte_length <= MAX_PROVIDER_CONTROL_SNAPSHOT_BYTES
                && valid_sha256(&self.implementation_identity_digest)
                && valid_sha256(&self.content_sha256),
            "provider snapshot identity",
        )?;
        // The host validates the full canonical RFC3339 value before projection.
        require(
            valid_text(&self.created_at, 64),
            "provider snapshot timestamp",
        )
    }
}

impl ProviderControlInspectionItemsV1 {
    pub const fn view(&self) -> ProviderControlInspectionViewV1 {
        match self {
            Self::StateSummary(_) => ProviderControlInspectionViewV1::StateSummary,
            Self::SourceInfluence(_) => ProviderControlInspectionViewV1::SourceInfluence,
            Self::Trace(_) => ProviderControlInspectionViewV1::Trace,
            Self::DeliveryReceipt(_) => ProviderControlInspectionViewV1::DeliveryReceipt,
            Self::MaintenanceReceipt(_) => ProviderControlInspectionViewV1::MaintenanceReceipt,
            Self::SnapshotMetadata(_) => ProviderControlInspectionViewV1::SnapshotMetadata,
            Self::CapabilityStatus(_) => ProviderControlInspectionViewV1::CapabilityStatus,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::StateSummary(items) => items.len(),
            Self::SourceInfluence(items) => items.len(),
            Self::Trace(items) => items.len(),
            Self::DeliveryReceipt(items) => items.len(),
            Self::MaintenanceReceipt(items) => items.len(),
            Self::SnapshotMetadata(items) => items.len(),
            Self::CapabilityStatus(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn validate_for(
        &self,
        provider_id: &str,
        scope: &ProviderControlScopeV1,
    ) -> Result<(), ApplicationContractError> {
        require(
            self.len() <= MAX_PROVIDER_CONTROL_INSPECTION_ITEMS,
            "provider inspection item count",
        )?;
        match self {
            Self::StateSummary(items) => {
                for item in items {
                    item.validate()?;
                }
            }
            Self::SourceInfluence(items) => {
                for item in items {
                    item.target.validate()?;
                    require(
                        !item.active
                            || item.disposition == ProviderControlSourceDispositionV1::Available,
                        "provider source activity",
                    )?;
                    if let Some(receipt) = &item.last_feedback_receipt {
                        validate_reference(receipt)?;
                    }
                    require(
                        valid_text(&item.provider_local_effect_summary, 8192),
                        "provider source effect summary",
                    )?;
                }
            }
            Self::Trace(items) => {
                use sha2::{Digest, Sha256};
                for item in items {
                    validate_reference(&item.stable_memory_ref)?;
                    if let Some(content) = &item.content {
                        require(
                            content.len() <= MAX_PROVIDER_CONTROL_RESPONSE_BYTES
                                && item.content_sha256.as_deref()
                                    == Some(
                                        hex::encode(Sha256::digest(content.as_bytes())).as_str(),
                                    ),
                            "provider trace content digest",
                        )?;
                        if let Some(source) = &item.original_source {
                            source.validate()?;
                        }
                    } else {
                        require(
                            item.content_sha256.is_none() && item.original_source.is_none(),
                            "provider trace privacy withholding",
                        )?;
                    }
                }
            }
            Self::DeliveryReceipt(items) => {
                for item in items {
                    require(
                        valid_text(&item.operation_id, 256)
                            && valid_text(&item.idempotency_key, 256)
                            && valid_sha256(&item.provider_receipt_digest),
                        "provider original delivery receipt",
                    )?;
                    validate_reference(&item.stable_memory_ref)?;
                }
            }
            Self::MaintenanceReceipt(items) => {
                for item in items {
                    require(
                        valid_text(&item.operation_id, 256)
                            && valid_text(&item.idempotency_key, 256),
                        "provider maintenance receipt identity",
                    )?;
                    validate_maintenance_result(&item.outcome)?;
                }
            }
            Self::SnapshotMetadata(items) => {
                for item in items {
                    item.validate_for(provider_id, scope)?;
                }
            }
            Self::CapabilityStatus(items) => validate_capabilities(items)?,
        }
        Ok(())
    }
}

impl ProviderControlOperationResultV1 {
    pub const fn operation(&self) -> RetainedSurfaceOperation {
        match self {
            Self::Feedback(_) => RetainedSurfaceOperation::ProviderFeedback,
            Self::Correction(_) => RetainedSurfaceOperation::ProviderCorrection,
            Self::DeleteBySource(_) => RetainedSurfaceOperation::ProviderDeleteBySource,
            Self::Health(_) => RetainedSurfaceOperation::ProviderHealth,
            Self::Inspection(_) => RetainedSurfaceOperation::ProviderInspection,
            Self::Maintenance(_) => RetainedSurfaceOperation::ProviderMaintenance,
            Self::SnapshotExport(_) => RetainedSurfaceOperation::ProviderSnapshotExport,
            Self::SnapshotRestore(_) => RetainedSurfaceOperation::ProviderSnapshotRestore,
            Self::Replay(_) => RetainedSurfaceOperation::ProviderReplay,
        }
    }

    fn has_data(&self) -> bool {
        match self {
            Self::Feedback(data) => data.is_some(),
            Self::Correction(data) => data.is_some(),
            Self::DeleteBySource(data) => data.is_some(),
            Self::Health(data) => data.is_some(),
            Self::Inspection(data) => data.is_some(),
            Self::Maintenance(data) => data.is_some(),
            Self::SnapshotExport(data) => data.is_some(),
            Self::SnapshotRestore(data) => data.is_some(),
            Self::Replay(data) => data.is_some(),
        }
    }

    fn mutation_receipt(&self) -> Option<&ProviderControlMutationReceiptV1> {
        match self {
            Self::Feedback(Some(data)) => Some(&data.receipt),
            Self::Correction(Some(data)) => Some(&data.receipt),
            Self::Maintenance(Some(data)) => Some(&data.receipt),
            Self::SnapshotRestore(Some(data)) => Some(&data.receipt),
            Self::Replay(Some(data)) => Some(&data.receipt),
            Self::DeleteBySource(Some(data)) => match &data.erasure {
                ProviderControlErasureV1::Verified { receipt, .. }
                | ProviderControlErasureV1::RetainedUnderLock { receipt, .. } => Some(receipt),
                ProviderControlErasureV1::Failed { receipt, .. } => receipt.as_ref(),
                ProviderControlErasureV1::Pending { .. } => None,
            },
            _ => None,
        }
    }
}

impl ProviderControlResultV1 {
    pub const fn operation(&self) -> RetainedSurfaceOperation {
        self.result.operation()
    }

    /// Verifies typed result evidence independently of the host authority checks
    /// that produced it. Missing provider data never becomes completed success.
    pub fn validate(&self) -> Result<(), ApplicationContractError> {
        validate_reference(&self.provider_id)?;
        require(
            self.registration_revision > 0 && valid_uuid_v7(&self.operation_id),
            "provider result identity",
        )?;
        self.scope.validate()?;
        self.effect.validate()?;
        let mutation = super::retained_surface_operation_is_effect(self.operation());
        require(
            if mutation {
                self.idempotency_key.as_deref().is_some_and(valid_sha256)
            } else {
                self.idempotency_key.is_none()
                    && self.effect.state == ProviderControlEffectStateV1::None
            },
            "provider operation effect class",
        )?;
        require(
            terminal_allows_effect(self.terminal, self.effect.state),
            "provider terminal effect",
        )?;
        if self.effect.state == ProviderControlEffectStateV1::Duplicate {
            require(
                self.effect.duplicate_of_idempotency_key == self.idempotency_key,
                "provider duplicate delivery binding",
            )?;
        }
        if let Some(diagnostic_id) = &self.diagnostic_id {
            require(
                valid_text(
                    diagnostic_id,
                    generated_contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES,
                ),
                "provider diagnostic reference",
            )?;
        }
        if let Some(detail) = &self.domain_detail {
            require(
                valid_text(&detail.code, 128) && valid_text(&detail.message, 8192),
                "provider lifecycle detail",
            )?;
        }
        require(
            self.warnings.len() <= 32
                && self
                    .warnings
                    .iter()
                    .all(|warning| valid_text(warning, 8192)),
            "provider warnings",
        )?;
        if matches!(
            self.terminal,
            ProviderControlTerminalV1::Success
                | ProviderControlTerminalV1::SuccessZeroResults
                | ProviderControlTerminalV1::Partial
        ) {
            require(
                self.result.has_data(),
                "provider successful result evidence",
            )?;
        }
        if matches!(
            self.effect.state,
            ProviderControlEffectStateV1::Committed | ProviderControlEffectStateV1::Partial
        ) {
            require(
                matches!((self.effect.state_generation_before, self.effect.state_generation_after), (Some(before), Some(after)) if after > before),
                "provider mutation generation advance",
            )?;
        }
        if let Some(receipt) = self.result.mutation_receipt() {
            receipt.validate()?;
            if self.effect.state == ProviderControlEffectStateV1::None {
                require(
                    receipt.state_generation_before == receipt.state_generation_after,
                    "provider no-effect generation",
                )?;
            }
            if let Some(digest) = &self.effect.provider_receipt_digest {
                require(
                    *digest == receipt.provider_receipt_digest,
                    "provider effect receipt binding",
                )?;
            }
            if matches!(
                self.effect.state,
                ProviderControlEffectStateV1::Committed | ProviderControlEffectStateV1::Partial
            ) {
                require(
                    self.effect.state_generation_before == Some(receipt.state_generation_before)
                        && self.effect.state_generation_after
                            == Some(receipt.state_generation_after),
                    "provider effect generation binding",
                )?;
            }
        }
        match &self.result {
            ProviderControlOperationResultV1::Feedback(Some(data)) => {
                validate_source_result(&data.source, &data.target)?;
                require(
                    valid_sha256(&data.target_digest),
                    "provider feedback target digest",
                )?;
                data.applied_effect.validate()?;
            }
            ProviderControlOperationResultV1::Correction(Some(data)) => {
                validate_source_result(&data.source, &data.target)?;
                require(
                    valid_sha256(&data.target_digest),
                    "provider correction target digest",
                )?;
            }
            ProviderControlOperationResultV1::DeleteBySource(Some(data)) => {
                self.validate_deletion(data)?
            }
            ProviderControlOperationResultV1::Health(Some(data)) => {
                validate_reference(&data.provider_instance_id)?;
                require(
                    valid_sha256(&data.implementation_identity_digest)
                        && valid_sha256(&data.state_identity_digest)
                        && valid_sha256(&data.effective_limits_digest)
                        && data.scope_digest == self.scope.sha256(),
                    "provider health identity",
                )?;
                validate_capabilities(&data.capability_states)?;
                data.backlog.validate()?;
                data.recovery_state.validate()?;
            }
            ProviderControlOperationResultV1::Inspection(Some(data)) => {
                require(
                    data.items.view() == data.selection.view(),
                    "provider inspection view",
                )?;
                match &data.selection {
                    ProviderControlInspectionSelectorV1::DeliveryReceipt { source } => {
                        validate_source_selector(source)?
                    }
                    ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                        operation_id,
                        idempotency_key,
                    } => require(
                        valid_uuid_v7(operation_id) && valid_sha256(idempotency_key),
                        "maintenance receipt query identities",
                    )?,
                    ProviderControlInspectionSelectorV1::SnapshotMetadata { snapshot_ref } => {
                        validate_reference(snapshot_ref)?
                    }
                    _ => {}
                }
                match &data.evidence_origin {
                    ProviderControlInspectionEvidenceOriginV1::ProviderRuntime => require(
                        data.state_generation.is_some(),
                        "provider runtime inspection generation",
                    )?,
                    ProviderControlInspectionEvidenceOriginV1::HostSnapshotArtifact {
                        snapshot_ref,
                        export_registration_revision,
                    } => {
                        validate_reference(snapshot_ref)?;
                        require(
                            matches!(&data.selection, ProviderControlInspectionSelectorV1::SnapshotMetadata { snapshot_ref: selected } if selected == snapshot_ref)
                                && matches!(&data.items, ProviderControlInspectionItemsV1::SnapshotMetadata(items) if items.len() == 1)
                                && *export_registration_revision == self.registration_revision
                                && data.state_generation.is_none()
                                && data.coverage == ProviderControlInspectionCoverageV1::Complete
                                && data.next_cursor.is_none()
                                && data.redactions.is_empty()
                                && self.terminal == ProviderControlTerminalV1::Success
                                && self.effect.state == ProviderControlEffectStateV1::None
                                && self.effect.state_generation_before.is_none()
                                && self.effect.state_generation_after.is_none()
                                && self.diagnostic_id.is_none()
                                && self.domain_detail.is_none()
                                && self.warnings.is_empty(),
                            "host snapshot metadata evidence",
                        )?;
                    }
                }
                data.items.validate_for(&self.provider_id, &self.scope)?;
                if let Some(cursor) = &data.next_cursor {
                    validate_reference(cursor)?;
                    require(
                        data.coverage == ProviderControlInspectionCoverageV1::Partial,
                        "provider inspection cursor coverage",
                    )?;
                }
                require(
                    data.redactions.len() <= 1024,
                    "provider inspection redactions",
                )?;
                for redaction in &data.redactions {
                    validate_reference(redaction)?;
                }
                match (&data.selection, &data.items) {
                    (
                        ProviderControlInspectionSelectorV1::SourceInfluence { source },
                        ProviderControlInspectionItemsV1::SourceInfluence(items),
                    ) => {
                        validate_source_selector(source)?;
                        require(
                            items.iter().all(|item| {
                                item.target.source.observation_id == source.observation_id
                            }),
                            "provider inspection source membership",
                        )?;
                    }
                    (
                        ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                            operation_id,
                            idempotency_key,
                        },
                        ProviderControlInspectionItemsV1::MaintenanceReceipt(items),
                    ) => require(
                        items.iter().all(|item| {
                            item.operation_id == *operation_id
                                && item.idempotency_key == *idempotency_key
                        }),
                        "provider maintenance receipt query binding",
                    )?,
                    (
                        ProviderControlInspectionSelectorV1::Trace { source },
                        ProviderControlInspectionItemsV1::Trace(items),
                    ) => {
                        validate_source_selector(source)?;
                        require(
                            items.iter().all(|item| {
                                item.original_source.as_ref().is_none_or(|original| {
                                    original.observation_id == source.observation_id
                                })
                            }),
                            "provider trace source membership",
                        )?;
                    }
                    _ => {}
                }
            }
            ProviderControlOperationResultV1::Maintenance(Some(data)) => {
                validate_maintenance_result(data)?
            }
            ProviderControlOperationResultV1::SnapshotExport(Some(data)) => {
                validate_reference(&data.snapshot_ref)?;
                data.identity.validate_for(&self.provider_id, &self.scope)?;
            }
            ProviderControlOperationResultV1::SnapshotRestore(Some(data)) => {
                validate_reference(&data.snapshot_ref)?;
                validate_reference(&data.snapshot_id)?;
            }
            ProviderControlOperationResultV1::Replay(Some(data)) => {
                let total = [
                    data.applied_observations,
                    data.duplicate_observations,
                    data.sources_already_applied,
                    data.rejected_observations,
                    data.effect_unknown_observations,
                ]
                .into_iter()
                .try_fold(0_u64, u64::checked_add);
                require(
                    total == Some(data.resolved_observations)
                        && (1..=4096).contains(&data.resolved_observations)
                        && data.first_source_sequence <= data.last_source_sequence
                        && data.acknowledged_sequence <= data.last_source_sequence,
                    "provider replay accounting",
                )?;
                require(
                    data.partial
                        || (data.acknowledged_sequence == data.last_source_sequence
                            && data.rejected_observations == 0
                            && data.effect_unknown_observations == 0),
                    "provider replay completion",
                )?;
            }
            _ => {}
        }
        if mutation
            && self.terminal == ProviderControlTerminalV1::Success
            && self.effect.state == ProviderControlEffectStateV1::None
        {
            let supported_no_effect = match &self.result {
                ProviderControlOperationResultV1::Feedback(Some(data)) => {
                    data.signal == ProviderControlFeedbackSignalV1::Ignored
                }
                ProviderControlOperationResultV1::Maintenance(Some(data)) => {
                    (data.dry_run || (data.changed_items == 0 && data.removed_items == 0))
                        && data.state_changed != Some(true)
                }
                ProviderControlOperationResultV1::DeleteBySource(Some(data)) => matches!(
                    data.erasure,
                    ProviderControlErasureV1::Verified { .. }
                        | ProviderControlErasureV1::RetainedUnderLock { .. }
                ),
                ProviderControlOperationResultV1::Replay(Some(data)) => {
                    data.applied_observations == 0 && data.effect_unknown_observations == 0
                }
                _ => false,
            };
            require(
                supported_no_effect,
                "provider successful mutation effect evidence",
            )?;
        }
        require(
            serde_json::to_vec(self)
                .is_ok_and(|bytes| bytes.len() <= MAX_PROVIDER_CONTROL_RESPONSE_BYTES),
            "provider result byte bound",
        )
    }

    /// Binds the result to the selected public operation and caller parameters.
    /// Trace/source/receipt authority still comes from host resolution, not echoes.
    pub fn validate_for(
        &self,
        request: &ProviderControlRequestV1,
    ) -> Result<(), ApplicationContractError> {
        self.validate()?;
        require(
            self.operation() == request.operation(),
            "provider result operation",
        )?;
        if let Some(ProviderControlStateSelectorV1::CanonicalSession {
            provider_id,
            registration_revision,
            session_id,
            ..
        }) = request.state_selector()
        {
            require(
                *provider_id == self.provider_id
                    && *registration_revision == self.registration_revision
                    && self.scope.agent_session_id
                        == self
                            .scope
                            .agent_session_id_for_canonical_session(session_id),
                "provider result selection",
            )?;
        }
        match (request, &self.result) {
            (
                ProviderControlRequestV1::Feedback(request),
                ProviderControlOperationResultV1::Feedback(Some(data)),
            ) => require(
                data.source == request.source && data.signal == request.signal,
                "provider feedback request binding",
            )?,
            (
                ProviderControlRequestV1::Correction(request),
                ProviderControlOperationResultV1::Correction(Some(data)),
            ) => require(
                data.source == request.source
                    && data.correction_kind == request.correction.kind()
                    && data.target.source.source_revision.as_ref()
                        == Some(&request.expected_source_revision),
                "provider correction request binding",
            )?,
            (
                ProviderControlRequestV1::DeleteBySource(request),
                ProviderControlOperationResultV1::DeleteBySource(Some(data)),
            ) => require(
                data.source == request.source
                    && data.mode == request.mode
                    && data.include_snapshots == request.include_snapshots
                    && data.intent.fence_revision_before == request.expected_fence_revision,
                "provider deletion request binding",
            )?,
            (
                ProviderControlRequestV1::Inspection(request),
                ProviderControlOperationResultV1::Inspection(Some(data)),
            ) => {
                require(
                    data.selection == request.selection
                        && (!matches!(
                            data.evidence_origin,
                            ProviderControlInspectionEvidenceOriginV1::HostSnapshotArtifact { .. }
                        ) || request.cursor.is_none())
                        && data.items.len() as u64 <= request.maximum_items
                        && serde_json::to_vec(&data.items)
                            .is_ok_and(|bytes| bytes.len() as u64 <= request.maximum_bytes),
                    "provider inspection request binding",
                )?;
            }
            (
                ProviderControlRequestV1::Maintenance(request),
                ProviderControlOperationResultV1::Maintenance(Some(data)),
            ) => require(
                data.task == request.task
                    && data.dry_run == request.dry_run
                    && data.scanned_items <= request.maximum_items,
                "provider maintenance request binding",
            )?,
            (
                ProviderControlRequestV1::SnapshotExport(request),
                ProviderControlOperationResultV1::SnapshotExport(Some(data)),
            ) => require(
                data.identity.byte_length <= request.maximum_bytes,
                "provider snapshot export request binding",
            )?,
            (
                ProviderControlRequestV1::SnapshotRestore(request),
                ProviderControlOperationResultV1::SnapshotRestore(Some(data)),
            ) => require(
                data.snapshot_ref == request.snapshot_ref
                    && data.receipt.state_generation_before == request.expected_state_generation,
                "provider restore request binding",
            )?,
            (
                ProviderControlRequestV1::Replay(request),
                ProviderControlOperationResultV1::Replay(Some(data)),
            ) => require(
                data.first_source_sequence == request.first_source_sequence
                    && data.last_source_sequence == request.last_source_sequence
                    && data.receipt.state_generation_before == request.expected_state_generation
                    && data.acknowledged_sequence
                        >= request.expected_previous_acknowledged_sequence,
                "provider replay request binding",
            )?,
            _ => {}
        }
        Ok(())
    }

    fn validate_deletion(
        &self,
        data: &ProviderDeleteBySourceResultV1,
    ) -> Result<(), ApplicationContractError> {
        validate_source_result(&data.source, &data.target)?;
        let cleanup = &data.host_snapshot_cleanup;
        require(
            cleanup.removed_snapshot_refs.len() as u64 <= cleanup.matched_count,
            "host snapshot cleanup count",
        )?;
        let mut removed = BTreeSet::new();
        for reference in &cleanup.removed_snapshot_refs {
            validate_reference(reference)?;
            require(removed.insert(reference), "host snapshot cleanup duplicate")?;
        }
        require(
            match cleanup.state {
                ProviderControlHostSnapshotCleanupStateV1::NotRequested => {
                    cleanup.matched_count == 0 && cleanup.unverifiable_count == 0
                }
                ProviderControlHostSnapshotCleanupStateV1::Complete => {
                    cleanup.unverifiable_count == 0
                }
                ProviderControlHostSnapshotCleanupStateV1::Partial => {
                    cleanup.unverifiable_count > 0 && !removed.is_empty()
                }
                ProviderControlHostSnapshotCleanupStateV1::Unverifiable => {
                    cleanup.unverifiable_count > 0 && removed.is_empty()
                }
            },
            "host snapshot cleanup state",
        )?;
        require(
            (cleanup.state == ProviderControlHostSnapshotCleanupStateV1::NotRequested)
                == !data.include_snapshots,
            "host snapshot cleanup request",
        )?;
        require(
            data.intent.fence_revision_before.checked_add(1)
                == Some(data.intent.fence_revision_after),
            "provider deletion fence transition",
        )?;
        data.intent.host_receipt.validate()?;
        require(
            data.intent.host_receipt.operation.as_str()
                == "use-case.application.retained.provider-delete-by-source"
                && data.intent.host_receipt.effect_class == EffectClass::Administrative,
            "provider deletion intent operation",
        )?;
        require(
            data.intent.host_receipt.outcome == crate::EffectTermination::Completed,
            "provider deletion intent acceptance",
        )?;
        let postcondition = match &data.erasure {
            ProviderControlErasureV1::Verified { postcondition, .. }
            | ProviderControlErasureV1::RetainedUnderLock { postcondition, .. } => {
                require(
                    matches!(
                        self.terminal,
                        ProviderControlTerminalV1::Success
                            | ProviderControlTerminalV1::SuccessZeroResults
                    ) && matches!(
                        self.effect.state,
                        ProviderControlEffectStateV1::None
                            | ProviderControlEffectStateV1::Committed
                            | ProviderControlEffectStateV1::Duplicate
                    ),
                    "provider verified erasure terminal and effect",
                )?;
                Some(postcondition)
            }
            ProviderControlErasureV1::Failed { postcondition, .. } => postcondition.as_ref(),
            ProviderControlErasureV1::Pending { .. } => None,
        };
        if self.effect.state == ProviderControlEffectStateV1::None
            && let Some(postcondition) = postcondition
        {
            require(
                postcondition.removed_effects == 0
                    && postcondition.anonymized_effects == 0
                    && postcondition.snapshots_rewritten == 0,
                "provider no-effect deletion counts",
            )?;
        }
        match &data.erasure {
            ProviderControlErasureV1::Pending { reason_code } => {
                require(
                    valid_text(reason_code, 128),
                    "provider erasure pending reason",
                )?;
                require(
                    !matches!(
                        self.terminal,
                        ProviderControlTerminalV1::Success
                            | ProviderControlTerminalV1::SuccessZeroResults
                    ) && matches!(
                        self.effect.state,
                        ProviderControlEffectStateV1::None | ProviderControlEffectStateV1::Unknown
                    ),
                    "provider pending erasure terminal",
                )?;
            }
            ProviderControlErasureV1::Verified { postcondition, .. } => {
                postcondition.validate()?;
                require(
                    matches!(
                        postcondition.verification_state,
                        ProviderControlDeletionVerificationV1::VerifiedAbsent
                            | ProviderControlDeletionVerificationV1::VerifiedAnonymized
                    ) && postcondition.remaining_influence_count == 0
                        && postcondition.retained_under_lock == 0,
                    "provider verified erasure",
                )?;
                require(
                    postcondition.verification_state
                        != ProviderControlDeletionVerificationV1::VerifiedAnonymized
                        || data.mode == ProviderControlDeletionModeV1::Anonymize,
                    "provider anonymized deletion mode",
                )?;
            }
            ProviderControlErasureV1::RetainedUnderLock {
                postcondition,
                retention_lock_receipt,
                ..
            } => {
                postcondition.validate()?;
                validate_reference(retention_lock_receipt)?;
                require(
                    postcondition.verification_state
                        == ProviderControlDeletionVerificationV1::RetainedUnderExplicitLock
                        && postcondition.retained_under_lock > 0
                        && postcondition.remaining_influence_count
                            <= postcondition.retained_under_lock,
                    "provider explicit retention lock",
                )?;
            }
            ProviderControlErasureV1::Failed {
                reason_code,
                postcondition,
                ..
            } => {
                require(
                    valid_text(reason_code, 128),
                    "provider erasure failure reason",
                )?;
                if let Some(postcondition) = postcondition {
                    postcondition.validate()?;
                    require(
                        matches!(
                            postcondition.verification_state,
                            ProviderControlDeletionVerificationV1::VerificationFailed
                                | ProviderControlDeletionVerificationV1::Partial
                        ),
                        "provider failed erasure verification",
                    )?;
                }
                require(
                    !matches!(
                        self.terminal,
                        ProviderControlTerminalV1::Success
                            | ProviderControlTerminalV1::SuccessZeroResults
                    ),
                    "provider failed erasure terminal",
                )?;
            }
        }
        Ok(())
    }
}

fn validate_source_result(
    selection: &ProviderControlSourceSelectorV1,
    target: &ProviderControlSourceTargetV1,
) -> Result<(), ApplicationContractError> {
    validate_source_selector(selection)?;
    target.validate()?;
    require(
        selection.observation_id == target.source.observation_id,
        "provider retained source membership",
    )
}

fn validate_capabilities(
    items: &[ProviderControlCapabilityStatusV1],
) -> Result<(), ApplicationContractError> {
    require(
        items.len() <= MAX_PROVIDER_CONTROL_INSPECTION_ITEMS,
        "provider capability status count",
    )?;
    let mut seen = BTreeSet::new();
    for item in items {
        validate_reference(&item.capability_id)?;
        require(
            valid_text(&item.state, 128) && seen.insert(&item.capability_id),
            "provider capability status",
        )?;
    }
    Ok(())
}

fn validate_maintenance_result(
    data: &ProviderMaintenanceResultV1,
) -> Result<(), ApplicationContractError> {
    data.receipt.validate()?;
    require(
        data.scanned_items <= 1_000_000
            && data.changed_items <= data.scanned_items
            && data.removed_items <= data.scanned_items,
        "provider maintenance counts",
    )?;
    if let Some(cursor) = &data.resume_cursor {
        validate_reference(cursor)?;
        require(data.partial, "provider maintenance resume coverage")?;
    }
    require(
        !data.dry_run
            || (data.receipt.state_generation_before == data.receipt.state_generation_after
                && data.state_changed != Some(true)),
        "provider dry-run generation",
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

fn terminal_allows_effect(
    terminal: ProviderControlTerminalV1,
    effect: ProviderControlEffectStateV1,
) -> bool {
    use ProviderControlEffectStateV1 as Effect;
    use ProviderControlTerminalV1 as Terminal;
    match terminal {
        Terminal::Success => matches!(effect, Effect::None | Effect::Committed | Effect::Duplicate),
        Terminal::Partial => matches!(effect, Effect::None | Effect::Committed | Effect::Duplicate),
        Terminal::DeadlineExceeded
        | Terminal::Cancelled
        | Terminal::ContractViolation
        | Terminal::InternalFailure => {
            matches!(effect, Effect::None | Effect::Partial | Effect::Unknown)
        }
        Terminal::ProviderUnavailable => matches!(effect, Effect::None | Effect::Unknown),
        Terminal::PartialEffect => effect == Effect::Partial,
        Terminal::EffectUnknown => effect == Effect::Unknown,
        _ => effect == Effect::None,
    }
}

const PROVIDER_CONTROL_SCOPE: &[ScopeDimension] = &[ScopeDimension::Resource];

pub(super) const SPECS: [RetainedSurfaceSpec; 9] = [
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderFeedback,
        summary: "Record provider feedback",
        description: "Record an authenticated feedback assertion for one retained provider source.",
        example: "Mark this recalled provider source as helpful",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderCorrection,
        summary: "Correct provider source",
        description: "Correct one retained provider source through host-authorized canonical evidence.",
        example: "Correct this recalled provider source",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderDeleteBySource,
        summary: "Delete provider source",
        description: "Accept one durable provider-source fence and separately verify provider erasure.",
        example: "Remove this recalled source from the producing provider",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderHealth,
        summary: "Inspect provider health",
        description: "Read the authorized provider namespace health without repairing state.",
        example: "Check this provider namespace health",
        effect: EffectClass::Read,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderInspection,
        summary: "Inspect provider evidence",
        description: "Read bounded redacted provider evidence under a host-authorized namespace.",
        example: "Inspect the receipt or influence of this provider source",
        effect: EffectClass::Read,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: true,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderMaintenance,
        summary: "Maintain provider state",
        description: "Run finite provider-local maintenance with explicit progress and receipts.",
        example: "Validate this provider namespace within bounded limits",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderSnapshotExport,
        summary: "Export provider snapshot",
        description: "Export a bounded consistent provider snapshot into host-retained snapshot storage.",
        example: "Export this provider namespace snapshot",
        effect: EffectClass::Read,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderSnapshotRestore,
        summary: "Restore provider snapshot",
        description: "Restore one compatible host-retained snapshot after current disposition revalidation.",
        example: "Restore this provider snapshot at the expected generation",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
    RetainedSurfaceSpec {
        operation: RetainedSurfaceOperation::ProviderReplay,
        summary: "Replay canonical provider history",
        description: "Replay host-retained canonical observations into the authorized provider namespace.",
        example: "Replay these canonical observation receipts into this provider",
        effect: EffectClass::Administrative,
        scope: PROVIDER_CONTROL_SCOPE,
        paginated: false,
        surfaces: CURRENT_SURFACES,
    },
];

#[allow(dead_code)]
#[path = "../../../../product/contracts/memory-provider-v1/generated/rust/memory_provider_v1.rs"]
mod generated_contract;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_surfaces::{
        RetainedSurfaceResultV1, SdkRequestIdControlV1, SdkResultSemanticsV1,
        retained_surface_catalog_contribution,
    };
    use serde_json::{Value, json};

    fn source() -> Value {
        json!({"trace_ref":"trace.retained", "item_ref":"item.rank.1", "observation_id":"observation.1"})
    }
    fn state() -> Value {
        json!({"kind":"canonical_session", "provider_id":"native", "registration_revision":7, "canonical_provider_id":"claude", "session_id":"session-1"})
    }
    #[test]
    fn final_public_selectors_use_existing_source_and_session_addresses() {
        let valid = [
            json!({"view":"delivery_receipt","source":source()}),
            json!({"view":"maintenance_receipt","operation_id":"01993262-4d00-7000-8000-000000000001","idempotency_key":"b".repeat(64)}),
        ];
        for selection in valid {
            let request: ProviderControlRequestV1 = serde_json::from_value(json!({"operation":"inspection","request":{"state":state(),"selection":selection,"maximum_items":10,"maximum_bytes":65536}})).expect("final producer request");
            request
                .validate_at(UtcMicros(10))
                .expect("bounded final query");
        }
        for selection in [
            json!({"view":"delivery_receipt","receipt_ref":"invented"}),
            json!({"view":"maintenance_receipt","receipt_ref":"invented"}),
        ] {
            assert!(
                serde_json::from_value::<ProviderControlInspectionSelectorV1>(selection).is_err()
            );
        }
        assert!(serde_json::from_value::<ProviderControlStateSelectorV1>(json!({"kind":"current_invocation","provider_id":"native","registration_revision":7})).is_err());
        assert!(
            serde_json::from_value::<ProviderControlStateSelectorV1>(
                json!({"kind":"canonical_session","provider_id":"native","registration_revision":7})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ProviderControlCorrectionV1>(
                json!({"kind":"replace_content","replacement_receipt_ref":"invented"})
            )
            .is_err()
        );
        let identity: ProviderControlSnapshotIdentityV1 =
            serde_json::from_value(snapshot()).expect("opaque schema identity");
        assert_eq!(identity.state_schema_version, "native-staged-v2");
        let mut numeric = snapshot();
        numeric["state_schema_version"] = json!(1);
        assert!(serde_json::from_value::<ProviderControlSnapshotIdentityV1>(numeric).is_err());
    }

    #[test]
    fn provider_read_evidence_preserves_failure_payload_and_refuses_effect_family() {
        let mut value: ProviderControlResultV1 = serde_json::from_value(result_value(
            &requests()[3],
            Value::Null,
            "provider_unavailable",
        ))
        .expect("actual unavailable reply");
        value.terminal = ProviderControlTerminalV1::ProviderUnavailable;
        value.diagnostic_id = Some("actual.provider.unavailable".to_owned());
        value.result = ProviderControlOperationResultV1::Health(None);
        let retained = RetainedSurfaceResultV1::ProviderControl(value.clone());
        let facts = retained
            .evidence_facts()
            .expect("provider failure evidence");
        assert_eq!(facts.returned, 0);
        assert_eq!(facts.completeness, crate::CoverageCompleteness::Unknown);
        assert_eq!(facts.freshness, crate::FreshnessState::Unknown);
        assert!(
            matches!(retained, RetainedSurfaceResultV1::ProviderControl(actual) if actual == value)
        );
        let effect = RetainedSurfaceResultV1::ProviderControl(
            serde_json::from_value(result_value(&requests()[0], successful_data(0), "success"))
                .expect("actual mutation reply"),
        );
        assert_eq!(
            effect.evidence_facts(),
            Err(super::super::RetainedSurfaceEvidenceTerminalV1::Effect)
        );
    }

    fn requests() -> Vec<ProviderControlRequestV1> {
        [
            json!({"operation":"feedback","request":{"source":source(),"signal":"helpful","weight":"0.5","evidence_refs":["evidence.1"],"occurred_at":10}}),
            json!({"operation":"correction","request":{"source":source(),"expected_source_revision":"revision.1","correction":{"kind":"replace_content","replacement_source":source()},"reason":"Retained correction evidence","evidence_refs":[]}}),
            json!({"operation":"delete_by_source","request":{"source":source(),"mode":"remove_influence","expected_fence_revision":0,"include_snapshots":true}}),
            json!({"operation":"health","request":{"state":state(),"requested_checks":["state","privacy"]}}),
            json!({"operation":"inspection","request":{"state":state(),"selection":{"view":"source_influence","source":source()},"maximum_items":10,"maximum_bytes":65536}}),
            json!({"operation":"maintenance","request":{"state":state(),"task":"validate_state","maximum_items":20,"maximum_bytes":65536,"maximum_duration_millis":1000,"dry_run":false}}),
            json!({"operation":"snapshot_export","request":{"state":state(),"maximum_bytes":65536}}),
            json!({"operation":"snapshot_restore","request":{"state":state(),"snapshot_ref":"snapshot.host.1","expected_state_generation":3}}),
            json!({"operation":"replay","request":{"state":state(),"observation_batch_refs":["observation.batch.1"],"first_source_sequence":1,"last_source_sequence":1,"expected_state_generation":3,"expected_previous_acknowledged_sequence":0}}),
        ].into_iter().map(|value| serde_json::from_value(value).expect("typed request")).collect()
    }
    fn scope() -> ProviderControlScopeV1 {
        let mut scope = ProviderControlScopeV1 {
            profile_id: "profile-1".to_owned(),
            project_id: "project-1".to_owned(),
            repository_identity: "repo-1".to_owned(),
            worktree_identity: "worktree-1".to_owned(),
            branch_identity: "refs/heads/main".to_owned(),
            agent_session_id: "session-1".to_owned(),
            resolved_scope_digest: format!("sha256:{}", "1".repeat(64)),
        };
        scope.agent_session_id = scope.agent_session_id_for_canonical_session("session-1");
        scope
    }
    fn source_identity() -> Value {
        json!({"canonical_provider_id":"native","canonical_session_id":"session-1","source_key":"source.1","stable_record_id":null,"observation_id":"observation.1","source_revision":"revision.1","content_sha256":"a".repeat(64)})
    }
    fn target() -> Value {
        json!({"stable_memory_ref":"provider.memory.1","source":source_identity()})
    }
    fn receipt() -> Value {
        json!({"state_generation_before":3,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64)})
    }
    fn snapshot() -> Value {
        json!({"snapshot_id":"provider.snapshot.1","provider_id":"native","implementation_identity_digest":"a".repeat(64),"state_schema_version":"native-staged-v2","exact_scope_digest":scope().sha256(),"state_generation":3,"observation_sequence":1,"parent_snapshot_id":null,"content_sha256":"c".repeat(64),"byte_length":128,"created_at":"2026-09-10T00:00:00.123456789Z"})
    }
    fn none_effect() -> Value {
        json!({"state":"none","committed_boundary":null,"state_generation_before":null,"state_generation_after":null,"committed_item_refs":[],"uncommitted_item_refs":[],"provider_receipt_digest":null,"reconciliation_action":null,"verification_digest":null,"duplicate_of_idempotency_key":null,"duplicate_of_operation_id":null})
    }
    fn committed_effect() -> Value {
        let mut effect = none_effect();
        effect["state"] = json!("committed");
        effect["state_generation_before"] = json!(3);
        effect["state_generation_after"] = json!(4);
        effect["provider_receipt_digest"] = json!("b".repeat(64));
        effect["verification_digest"] = json!("c".repeat(64));
        effect
    }
    fn result_value(request: &ProviderControlRequestV1, data: Value, terminal: &str) -> Value {
        let operation = serde_json::to_value(request).expect("request")["operation"].clone();
        let mutation = crate::retained_surface_operation_is_effect(request.operation());
        json!({"provider_id":"native","registration_revision":7,"scope":scope(),"operation_id":"018f22c2-77cd-7000-8000-000000000001","idempotency_key":mutation.then(||"d".repeat(64)),"terminal":terminal,"domain_detail":null,"effect":if mutation && terminal=="success" { committed_effect() } else { none_effect() },"result":{"operation":operation,"data":data},"warnings":[]})
    }
    fn host_receipt() -> crate::EffectReceipt {
        use tracedecay_domain::{ActorId, ManifestDigest, ProjectId, RepositoryId, WorktreeId};
        let digest = || ManifestDigest::new(format!("sha256:{}", "a".repeat(64))).expect("digest");
        crate::EffectReceipt {
            operation: tracedecay_tool_catalog::UseCaseId::new(
                "use-case.application.retained.provider-delete-by-source",
            )
            .expect("operation"),
            request_id: crate::RequestId::new("request.delete").expect("request"),
            actor: ActorId::new("actor.delete").expect("actor"),
            scope: crate::ResolvedScope::new(
                ProjectId::new("project-1").expect("project"),
                RepositoryId::new("repo-1").expect("repo"),
                WorktreeId::new("worktree-1").expect("worktree"),
                None,
            )
            .expect("scope"),
            effect_class: EffectClass::Administrative,
            idempotency_key: crate::IdempotencyKey::new("host.delete.key").expect("key"),
            input_digest: digest(),
            expected_state: digest(),
            policy_digest: digest(),
            configuration_digest: digest(),
            catalog_digest: digest(),
            privacy_digest: digest(),
            outcome: crate::EffectTermination::Completed,
            committed_state: Some(digest()),
            external_proof: None,
        }
    }
    fn successful_data(index: usize) -> Value {
        match index {
            0 => {
                json!({"source":source(),"target":target(),"target_digest":"a".repeat(64),"signal":"helpful","applied_effect":{"feedback_recorded":true},"receipt":receipt()})
            }
            1 => {
                json!({"source":source(),"target":target(),"target_digest":"a".repeat(64),"correction_kind":"replace_content","affected_provider_effects":1,"receipt":receipt()})
            }
            2 => {
                json!({"source":source(),"target":target(),"mode":"remove_influence","include_snapshots":true,"host_snapshot_cleanup":{"state":"complete","removed_snapshot_refs":[],"matched_count":0,"unverifiable_count":0},"intent":{"fence_revision_before":0,"fence_revision_after":1,"host_receipt":host_receipt()},"erasure":{"state":"verified","postcondition":{"matched_effects":1,"removed_effects":1,"anonymized_effects":0,"retained_under_lock":0,"remaining_influence_count":0,"snapshots_examined":0,"snapshots_rewritten":0,"verification_query_digest":"a".repeat(64),"verification_state":"verified_absent"},"receipt":receipt()}})
            }
            3 => {
                json!({"provider_instance_id":"instance.1","implementation_identity_digest":"a".repeat(64),"state_identity_digest":"b".repeat(64),"state_generation":3,"scope_digest":scope().sha256(),"readiness":"ready","capability_states":[{"capability_id":"provider.health.v1","state":"available"}],"effective_limits_digest":"c".repeat(64),"backlog":0,"recovery_state":"ready"})
            }
            4 => {
                json!({"selection":{"view":"source_influence","source":source()},"items":{"view":"source_influence","items":[{"target":target(),"active":true,"disposition":"available","settled_feedback":{"helpful":1,"harmful":0,"ignored":0,"corrected":0,"superseded":0},"last_feedback_receipt":"receipt.feedback","provider_local_effect_summary":"Recorded one provider-local feedback signal"}]},"coverage":"complete","next_cursor":null,"redactions":[],"evidence_origin":{"kind":"provider_runtime"},"state_generation":3})
            }
            5 => {
                json!({"task":"validate_state","dry_run":false,"scanned_items":1,"changed_items":1,"removed_items":0,"partial":false,"resume_cursor":null,"receipt":receipt()})
            }
            6 => json!({"snapshot_ref":"snapshot.host.1","identity":snapshot()}),
            7 => {
                json!({"snapshot_ref":"snapshot.host.1","snapshot_id":"provider.snapshot.1","restored_observation_sequence":1,"receipt":receipt()})
            }
            8 => {
                json!({"first_source_sequence":1,"last_source_sequence":1,"acknowledged_sequence":1,"resolved_observations":1,"applied_observations":1,"duplicate_observations":0,"sources_already_applied":0,"rejected_observations":0,"effect_unknown_observations":0,"partial":false,"receipt":receipt()})
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn host_metadata_reports_export_evidence_without_current_runtime_claims() {
        let mut request = requests().remove(4);
        let ProviderControlRequestV1::Inspection(public) = &mut request else {
            panic!("inspection")
        };
        public.selection = ProviderControlInspectionSelectorV1::SnapshotMetadata {
            snapshot_ref: "snapshot.host.1".to_owned(),
        };
        let data = json!({
            "selection": {"view":"snapshot_metadata","snapshot_ref":"snapshot.host.1"},
            "evidence_origin":{"kind":"host_snapshot_artifact","snapshot_ref":"snapshot.host.1","export_registration_revision":7},
            "items":{"view":"snapshot_metadata","items":[snapshot()]},
            "coverage":"complete","next_cursor":null,"redactions":[],"state_generation":null
        });
        let actual = result_value(&request, data, "success");
        let result: ProviderControlResultV1 =
            serde_json::from_value(actual.clone()).expect("host artifact");
        result
            .validate_for(&request)
            .expect("historical export owner and unknown current generation");
        for (pointer, replacement) in [
            ("/result/data/state_generation", json!(0)),
            (
                "/result/data/evidence_origin/export_registration_revision",
                json!(8),
            ),
            (
                "/result/data/evidence_origin/snapshot_ref",
                json!("snapshot.other"),
            ),
            ("/result/data/items/items", json!([])),
            ("/result/data/items/items", json!([snapshot(), snapshot()])),
            ("/effect/state_generation_before", json!(3)),
            ("/effect/state_generation_after", json!(3)),
            ("/warnings", json!(["provider ready"])),
        ] {
            let mut changed = actual.clone();
            *changed.pointer_mut(pointer).expect("fixture field") = replacement;
            assert!(
                serde_json::from_value::<ProviderControlResultV1>(changed)
                    .expect("typed malformed evidence")
                    .validate_for(&request)
                    .is_err(),
                "{pointer}"
            );
        }
        let ProviderControlRequestV1::Inspection(public) = &mut request else {
            unreachable!()
        };
        public.cursor = Some("stale.page".to_owned());
        assert!(result.validate_for(&request).is_err());
        let runtime_request = requests().remove(4);
        let mut runtime = result_value(&runtime_request, successful_data(4), "success");
        runtime["result"]["data"]["state_generation"] = Value::Null;
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(runtime)
                .expect("runtime")
                .validate()
                .is_err()
        );
        let mut missing_origin = actual;
        missing_origin["result"]["data"]
            .as_object_mut()
            .expect("data")
            .remove("evidence_origin");
        assert!(serde_json::from_value::<ProviderControlResultV1>(missing_origin).is_err());
    }

    #[test]
    fn maintenance_state_comparison_is_optional_and_independent_of_item_counts() {
        let request = requests().remove(5);
        let mut raw = result_value(&request, successful_data(5), "success");
        raw["result"]["data"]["changed_items"] = json!(0);
        for comparison in [None, Some(false), Some(true)] {
            let mut value = raw.clone();
            if let Some(comparison) = comparison {
                value["result"]["data"]["state_changed"] = json!(comparison);
            }
            let result: ProviderControlResultV1 =
                serde_json::from_value(value).expect("comparison");
            result
                .validate_for(&request)
                .expect("independent kernel change");
            let ProviderControlOperationResultV1::Maintenance(Some(data)) = result.result else {
                panic!("maintenance")
            };
            assert_eq!(data.state_changed, comparison);
        }
        raw["result"]["data"]["state_changed"] = json!(true);
        raw["effect"] = none_effect();
        raw["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(raw)
                .expect("contradictory no-effect")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn partial_host_snapshot_cleanup_survives_provider_offline_without_proving_erasure() {
        let request = requests().remove(2);
        let mut data = successful_data(2);
        data["erasure"] = json!({"state":"pending","reason_code":"provider_offline"});
        data["host_snapshot_cleanup"] = json!({"state":"partial","removed_snapshot_refs":["snapshot.removed.1"],"matched_count":2,"unverifiable_count":1});
        let raw = result_value(&request, data, "provider_unavailable");
        let result: ProviderControlResultV1 =
            serde_json::from_value(raw.clone()).expect("offline cleanup");
        result
            .validate_for(&request)
            .expect("actual removal independent from provider availability");
        assert_eq!(
            serde_json::to_value(&result.result).expect("deletion wire result"),
            raw["result"]
        );
        let ProviderControlOperationResultV1::DeleteBySource(Some(data)) = result.result else {
            panic!("deletion")
        };
        assert_eq!(
            data.host_snapshot_cleanup.removed_snapshot_refs,
            vec!["snapshot.removed.1"]
        );
        assert!(matches!(
            data.erasure,
            ProviderControlErasureV1::Pending { .. }
        ));
        let mut contradictory = raw;
        contradictory["result"]["data"]["host_snapshot_cleanup"]["state"] = json!("complete");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(contradictory)
                .expect("contradiction")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn requested_host_cleanup_cannot_be_reported_as_not_requested_after_the_fence() {
        let request = requests().remove(2);
        let mut data = successful_data(2);
        data["host_snapshot_cleanup"] = json!({"state":"not_requested","removed_snapshot_refs":[],"matched_count":0,"unverifiable_count":0});
        let invalid: ProviderControlResultV1 =
            serde_json::from_value(result_value(&request, data.clone(), "success"))
                .expect("typed cleanup");
        assert!(invalid.validate_for(&request).is_err());
        data["erasure"] = json!({"state":"pending","reason_code":"provider_offline"});
        data["host_snapshot_cleanup"] = json!({"state":"unverifiable","removed_snapshot_refs":[],"matched_count":0,"unverifiable_count":1});
        let actual: ProviderControlResultV1 =
            serde_json::from_value(result_value(&request, data, "provider_unavailable"))
                .expect("unstarted requested cleanup");
        actual
            .validate_for(&request)
            .expect("actual inability to start requested cleanup");
    }

    #[test]
    fn maintenance_resume_cursor_is_optional_bounded_and_preserved() {
        let mut request = requests().remove(5);
        let ProviderControlRequestV1::Maintenance(data) = &mut request else {
            panic!("maintenance fixture")
        };
        assert_eq!(data.resume_cursor, None);
        data.resume_cursor = Some("native.scope:decay:17".to_owned());
        request
            .validate_at(UtcMicros(20))
            .expect("opaque continuation");
        assert_eq!(
            serde_json::to_value(&request).expect("request")["request"]["resume_cursor"],
            json!("native.scope:decay:17")
        );
        for invalid in [String::new(), "x".repeat(1025)] {
            let ProviderControlRequestV1::Maintenance(data) = &mut request else {
                panic!("maintenance fixture")
            };
            data.resume_cursor = Some(invalid);
            assert!(request.validate_at(UtcMicros(20)).is_err());
        }
    }

    #[test]
    fn optional_provider_counts_preserve_native_values_and_ncm_omissions() {
        let requests = requests();
        for (index, field, count) in [
            (3, "staged_rows", 9_u64),
            (5, "proposed_changes", 3),
            (7, "restored_rows", 2),
        ] {
            for actual in [None, Some(0), Some(count)] {
                let mut data = successful_data(index);
                if let Some(count) = actual {
                    data[field] = json!(count);
                }
                let result: ProviderControlResultV1 =
                    serde_json::from_value(result_value(&requests[index], data, "success"))
                        .expect("typed provider count");
                result
                    .validate_for(&requests[index])
                    .expect("provider count does not invent a cross-field bound");
                let data =
                    serde_json::to_value(&result.result).expect("result wire")["data"].clone();
                match actual {
                    Some(count) => assert_eq!(data[field], json!(count)),
                    None => assert!(data.get(field).is_none()),
                }
            }
            for invalid in [json!(-1), json!(1.5), json!("3")] {
                let mut data = successful_data(index);
                data[field] = invalid;
                assert!(
                    serde_json::from_value::<ProviderControlResultV1>(result_value(
                        &requests[index],
                        data,
                        "success"
                    ))
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn provider_control_requests_are_closed_bounded_and_keep_host_authority_out() {
        for request in requests() {
            request.validate_at(UtcMicros(20)).expect("valid request");
            for field in [
                "exact_scope_identity",
                "history_grant",
                "canonical_outcome_receipt",
                "ready_receipt_digest",
                "operation_id",
                "idempotency_key",
                "deadline",
                "cancellation",
                "request_id",
            ] {
                let mut value = serde_json::to_value(&request).expect("request");
                value["request"][field] = json!("forged");
                assert!(
                    serde_json::from_value::<ProviderControlRequestV1>(value).is_err(),
                    "unexpected caller authority field {field}"
                );
            }
        }
        for field in ["trace_ref", "item_ref", "observation_id"] {
            let mut value = source();
            value.as_object_mut().expect("source").remove(field);
            assert!(serde_json::from_value::<ProviderControlSourceSelectorV1>(value).is_err());
        }
        assert!(
            serde_json::from_value::<ProviderControlSourceSelectorV1>(
                json!({"stable_memory_ref":"provider.memory.1"})
            )
            .is_err()
        );
        let mut deletion = serde_json::to_value(&requests()[2]).expect("delete");
        deletion["request"]["sources"] = json!([source()]);
        assert!(serde_json::from_value::<ProviderControlRequestV1>(deletion).is_err());
        for weight in ["NaN", "1.01", "-0.1", "1e-2", "01", " 0.5", "0.", ".5"] {
            let mut value = serde_json::to_value(&requests()[0]).expect("feedback");
            value["request"]["weight"] = json!(weight);
            let request: ProviderControlRequestV1 =
                serde_json::from_value(value).expect("typed weight");
            assert!(request.validate_at(UtcMicros(20)).is_err());
        }
        assert!(requests()[0].validate_at(UtcMicros(9)).is_err());
        for (index, field, value) in [
            (3, "requested_checks", json!(["state", "state"])),
            (4, "maximum_items", json!(100001)),
            (5, "maximum_duration_millis", json!(0)),
            (6, "maximum_bytes", json!(1073741825_u64)),
            (8, "observation_batch_refs", json!(["same", "same"])),
            (8, "last_source_sequence", json!(0)),
        ] {
            let mut request = serde_json::to_value(&requests()[index]).expect("request");
            request["request"][field] = value;
            let request: ProviderControlRequestV1 =
                serde_json::from_value(request).expect("typed bad bound");
            assert!(
                request.validate_at(UtcMicros(20)).is_err(),
                "accepted {field}"
            );
        }
        let mut correction = serde_json::to_value(&requests()[1]).expect("correction");
        correction["request"]["correction"] =
            json!({"kind":"change_validity","valid_from":20,"valid_until":20});
        let correction: ProviderControlRequestV1 =
            serde_json::from_value(correction).expect("typed validity");
        assert!(correction.validate_at(UtcMicros(20)).is_err());
    }

    #[test]
    fn nine_provider_controls_have_distinct_catalog_schemas_and_sdk_controls() {
        let catalog = retained_surface_catalog_contribution().expect("catalog");
        for request in requests() {
            let operation = request.operation();
            let name = operation.as_str();
            assert!(name.starts_with("provider_"));
            assert_eq!(
                RetainedSurfaceOperation::from_operation_name(name),
                Some(operation)
            );
            assert!(RetainedSurfaceOperation::CALLABLE.contains(&operation));
            let capability = tracedecay_tool_catalog::CapabilityId::new(format!(
                "capability.application.retained.{}",
                name.replace('_', "-")
            ))
            .expect("capability");
            let schema = catalog
                .executable_schema(&capability)
                .expect("selected schema");
            assert_eq!(
                schema.request_schema().body()["additionalProperties"],
                json!(false)
            );
            let properties = schema.request_schema().body()["properties"]
                .as_object()
                .expect("body properties");
            assert!(!properties.contains_key("exact_scope_identity"));
            assert!(!properties.contains_key("history_grant"));
            assert_eq!(
                schema.result_schema().rust_type_path(),
                "tracedecay_contracts::retained_surfaces::ProviderControlResultV1"
            );
            let controls = operation.sdk_operation_contract();
            assert_eq!(
                controls.result_semantics,
                SdkResultSemanticsV1::ProviderControlTerminal
            );
            assert_eq!(
                controls.request_id,
                if crate::retained_surface_operation_is_effect(operation) {
                    SdkRequestIdControlV1::Required
                } else {
                    SdkRequestIdControlV1::ServerMinted
                }
            );
        }
        assert_eq!(
            scope().sha256(),
            "ef6ac8fde32e685111577fe6576c907e473861bf9653c76822c6def002795cc8"
        );
        let mut raw_scope = scope();
        raw_scope.agent_session_id = "session-1".to_owned();
        assert_eq!(
            raw_scope.sha256(),
            "2f525c8c3d59bfa3d9729405c4f3f1307fade77494b6ddf251c89abc490f0a52"
        );
    }

    #[test]
    fn canonical_session_namespaces_preserve_framing_and_utf8_identity() {
        let mut exact = scope();
        assert_eq!(
            exact.agent_session_id,
            "tdmem-agent-session.v1.dd9c4ff540d92ea028a959d6ac0a2233a935dc1938ee9b34b8980e5112ddbca6"
        );
        assert_eq!(
            exact.agent_session_id_for_canonical_session("session.Žluťoučký🧠"),
            "tdmem-agent-session.v1.d1f95c6758f9dc2b1f788447bcecfd51dca614b6db606c3f21f3a9540f5b98d3"
        );
        let expected = exact.agent_session_id.clone();
        exact.agent_session_id = "unrelated.delivery.namespace".to_owned();
        assert_eq!(
            exact.agent_session_id_for_canonical_session("session-1"),
            expected
        );
        exact.profile_id.push_str("project-1");
        exact.project_id.clear();
        assert_ne!(
            exact.agent_session_id_for_canonical_session("session-1"),
            expected
        );
    }

    #[test]
    fn canonical_session_results_bind_the_lookup_key_to_the_exact_provider_namespace() {
        let request = &requests()[3];
        let result: ProviderControlResultV1 =
            serde_json::from_value(result_value(request, Value::Null, "provider_unavailable"))
                .expect("unavailable provider result retains its exact admitted namespace");
        result
            .validate_for(request)
            .expect("derived namespace matches canonical lookup");
        for (field, value) in [
            ("provider_id", json!("other-provider")),
            ("registration_revision", json!(8)),
            ("session_id", json!("another-canonical-session")),
        ] {
            let mut foreign = serde_json::to_value(request).expect("request");
            foreign["request"]["state"][field] = value;
            let foreign: ProviderControlRequestV1 =
                serde_json::from_value(foreign).expect("typed foreign lookup");
            assert!(
                result.validate_for(&foreign).is_err(),
                "accepted foreign {field}"
            );
        }
        let mut raw_namespace = result.clone();
        raw_namespace.scope.agent_session_id = "session-1".to_owned();
        assert!(raw_namespace.validate_for(request).is_err());
        let mut other_checkout = result;
        other_checkout.scope.worktree_identity = "other-worktree".to_owned();
        assert!(other_checkout.validate_for(request).is_err());

        let mut healthy: ProviderControlResultV1 =
            serde_json::from_value(result_value(request, successful_data(3), "success"))
                .expect("actual health evidence");
        healthy
            .validate_for(request)
            .expect("health scope digest matches");
        let ProviderControlOperationResultV1::Health(Some(data)) = &mut healthy.result else {
            panic!("health evidence fixture")
        };
        data.scope_digest = "f".repeat(64);
        assert!(healthy.validate_for(request).is_err());
    }

    #[test]
    fn every_result_requires_real_operation_data_and_exact_caller_bindings() {
        let requests = requests();
        for (index, request) in requests.iter().enumerate() {
            let result: ProviderControlResultV1 =
                serde_json::from_value(result_value(request, successful_data(index), "success"))
                    .expect("typed result");
            result.validate_for(request).expect("matched real result");
            assert!(
                result
                    .validate_for(&requests[(index + 1) % requests.len()])
                    .is_err()
            );
            let missing: ProviderControlResultV1 =
                serde_json::from_value(result_value(request, Value::Null, "success"))
                    .expect("missing result");
            assert!(missing.validate().is_err());
            let unavailable: ProviderControlResultV1 =
                serde_json::from_value(result_value(request, Value::Null, "provider_unavailable"))
                    .expect("unavailable");
            unavailable
                .validate_for(request)
                .expect("truthful unavailable");
            let mut changed = result.clone();
            changed.registration_revision = 8;
            if request.state_selector().is_some() {
                assert!(changed.validate_for(request).is_err());
            }
        }
        let mut bad = result_value(&requests[1], successful_data(1), "success");
        bad["result"]["data"]["target"]["source"]["source_revision"] = json!("other");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(bad)
                .expect("revision result")
                .validate_for(&requests[1])
                .is_err()
        );
        let mut bad = result_value(&requests[0], successful_data(0), "success");
        bad["result"]["data"]["source"]["observation_id"] = json!("other");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(bad)
                .expect("source result")
                .validate_for(&requests[0])
                .is_err()
        );
        let mut bad = result_value(&requests[1], successful_data(1), "success");
        bad["effect"] = none_effect();
        bad["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(bad)
                .expect("unevidenced no-op")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn retained_host_unknown_without_provider_receipt_cannot_claim_commit_evidence() {
        let request = &requests()[5];
        let mut value = result_value(request, Value::Null, "effect_unknown");
        value["effect"]["state"] = json!("unknown");
        value["effect"]["reconciliation_action"] = json!("reconcile_same_operation");
        value["warnings"] = json!(["host: no provider reply was witnessed"]);
        let retained: ProviderControlResultV1 =
            serde_json::from_value(value.clone()).expect("retained host uncertainty");
        retained
            .validate_for(request)
            .expect("unknown without a provider reply");
        assert!(retained.effect.provider_receipt_digest.is_none());

        let mut observed = value.clone();
        observed["effect"]["provider_receipt_digest"] = json!("b".repeat(64));
        serde_json::from_value::<ProviderControlResultV1>(observed)
            .expect("retained provider uncertainty")
            .validate_for(request)
            .expect("actual provider receipt remains admissible");

        for (field, bad) in [
            ("provider_receipt_digest", json!("not-a-provider-receipt")),
            ("state_generation_before", json!(3)),
            ("state_generation_after", json!(4)),
            ("committed_boundary", json!("source.1")),
            ("committed_item_refs", json!(["source.1"])),
            ("uncommitted_item_refs", json!(["source.2"])),
            ("verification_digest", json!("c".repeat(64))),
            ("duplicate_of_idempotency_key", json!("d".repeat(64))),
            ("duplicate_of_operation_id", json!("original.operation")),
            ("reconciliation_action", Value::Null),
            ("reconciliation_action", json!("")),
            ("reconciliation_action", json!("r".repeat(513))),
        ] {
            let mut malformed = value.clone();
            malformed["effect"][field] = bad;
            assert!(
                serde_json::from_value::<ProviderControlResultV1>(malformed)
                    .expect("typed host uncertainty")
                    .validate_for(request)
                    .is_err(),
                "host uncertainty must reject {field}"
            );
        }
        for (field, bad) in [
            ("terminal", json!("success")),
            ("idempotency_key", Value::Null),
            ("operation_id", json!("not-an-operation-id")),
            ("registration_revision", json!(8)),
            ("scope", Value::Null),
        ] {
            let mut malformed = value.clone();
            malformed[field] = bad;
            let rejected = serde_json::from_value::<ProviderControlResultV1>(malformed)
                .map_or(true, |result| result.validate_for(request).is_err());
            assert!(
                rejected,
                "host uncertainty must retain the {field} contract"
            );
        }
    }

    #[test]
    fn committed_partial_and_duplicate_effects_still_require_provider_receipts() {
        let committed = committed_effect();
        let mut partial = committed_effect();
        partial["state"] = json!("partial");
        partial["committed_boundary"] = json!("source.1");
        partial["committed_item_refs"] = json!(["source.1"]);
        partial["uncommitted_item_refs"] = json!(["source.2"]);
        partial["reconciliation_action"] = json!("Resume after source.1");
        let mut duplicate = none_effect();
        duplicate["state"] = json!("duplicate");
        duplicate["state_generation_before"] = json!(4);
        duplicate["state_generation_after"] = json!(4);
        duplicate["provider_receipt_digest"] = json!("b".repeat(64));
        duplicate["duplicate_of_idempotency_key"] = json!("d".repeat(64));
        duplicate["duplicate_of_operation_id"] = json!("original.operation");

        for mut effect in [committed, partial, duplicate] {
            serde_json::from_value::<ProviderControlEffectV1>(effect.clone())
                .expect("typed provider effect")
                .validate()
                .expect("provider receipt supports this effect shape");
            effect["provider_receipt_digest"] = Value::Null;
            assert!(
                serde_json::from_value::<ProviderControlEffectV1>(effect)
                    .expect("effect without its receipt")
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn provider_effects_preserve_duplicates_partitions_and_unknown_reconciliation() {
        let request = &requests()[0];
        let mut value = result_value(request, successful_data(0), "success");
        value["effect"] = none_effect();
        value["effect"]["state"] = json!("duplicate");
        value["effect"]["state_generation_before"] = json!(4);
        value["effect"]["state_generation_after"] = json!(4);
        value["effect"]["provider_receipt_digest"] = json!("b".repeat(64));
        value["effect"]["duplicate_of_idempotency_key"] = json!("d".repeat(64));
        value["effect"]["duplicate_of_operation_id"] = json!("original.retained.operation");
        serde_json::from_value::<ProviderControlResultV1>(value.clone())
            .expect("duplicate")
            .validate_for(request)
            .expect("original receipt with unchanged live generation");
        for (field, bad) in [
            ("state_generation_after", json!(5)),
            ("duplicate_of_idempotency_key", json!("e".repeat(64))),
            ("duplicate_of_operation_id", Value::Null),
        ] {
            let mut malformed = value.clone();
            malformed["effect"][field] = bad;
            assert!(
                serde_json::from_value::<ProviderControlResultV1>(malformed)
                    .expect("typed duplicate")
                    .validate()
                    .is_err()
            );
        }
        let mut unknown = result_value(request, Value::Null, "effect_unknown");
        unknown["effect"]["state"] = json!("unknown");
        unknown["effect"]["provider_receipt_digest"] = json!("b".repeat(64));
        unknown["effect"]["reconciliation_action"] = json!("Inspect retained operation receipt");
        serde_json::from_value::<ProviderControlResultV1>(unknown.clone())
            .expect("unknown")
            .validate()
            .expect("truthful unknown effect");
        unknown["effect"]["state_generation_after"] = json!(4);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(unknown)
                .expect("unknown with fabricated generation")
                .validate()
                .is_err()
        );
        let mut partial = committed_effect();
        partial["state"] = json!("partial");
        partial["committed_boundary"] = json!("source.1");
        partial["committed_item_refs"] = json!(["source.1"]);
        partial["uncommitted_item_refs"] = json!(["source.2"]);
        partial["reconciliation_action"] = json!("Resume after source.1");
        serde_json::from_value::<ProviderControlEffectV1>(partial.clone())
            .expect("partial")
            .validate()
            .expect("disjoint partial evidence");
        partial["uncommitted_item_refs"] = json!(["source.1"]);
        assert!(
            serde_json::from_value::<ProviderControlEffectV1>(partial)
                .expect("overlap")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn deletion_intent_is_not_erasure_and_pinned_inspection_shapes_remain_closed() {
        let request = &requests()[2];
        let mut data = successful_data(2);
        data["erasure"] = json!({"state":"pending","reason_code":"provider_offline"});
        let pending: ProviderControlResultV1 =
            serde_json::from_value(result_value(request, data, "provider_unavailable"))
                .expect("offline intent");
        pending
            .validate_for(request)
            .expect("durable intent with erasure pending");
        let mut forged = serde_json::to_value(&pending).expect("pending");
        forged["terminal"] = json!("success");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(forged)
                .expect("false success")
                .validate()
                .is_err()
        );
        let mut verified = result_value(request, successful_data(2), "success");
        verified["result"]["data"]["erasure"]["postcondition"]["remaining_influence_count"] =
            json!(1);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(verified)
                .expect("residual influence")
                .validate()
                .is_err()
        );
        let request = &requests()[4];
        let mut inspection = result_value(request, successful_data(4), "success");
        inspection["result"]["data"]["items"]["items"][0]["provider_local_effect_summary"] =
            json!({"ranking_bias":1});
        assert!(serde_json::from_value::<ProviderControlResultV1>(inspection).is_err());
        let mut trace:ProviderControlInspectionItemsV1=serde_json::from_value(json!({"view":"trace","items":[{"stable_memory_ref":"provider.memory.1","content":null,"content_sha256":null,"original_source":null}]})).expect("private trace");
        trace
            .validate_for("native", &scope())
            .expect("privacy withholding");
        if let ProviderControlInspectionItemsV1::Trace(items) = &mut trace {
            items[0].original_source =
                Some(serde_json::from_value(source_identity()).expect("source"));
        }
        assert!(trace.validate_for("native", &scope()).is_err());
        assert!(
            serde_json::from_value::<ProviderControlEvidenceV1>(json!("x".repeat(8193))).is_err()
        );
        let mut deep = json!(0);
        for _ in 0..10 {
            deep = json!([deep]);
        }
        assert!(ProviderControlEvidenceV1::new(deep).is_err());
    }

    #[test]
    fn verified_deletion_requires_consistent_provider_proof_and_preserves_real_no_ops() {
        let request = &requests()[2];
        let mut no_op = result_value(request, successful_data(2), "success");
        no_op["effect"] = none_effect();
        no_op["result"]["data"]["erasure"]["receipt"]["state_generation_after"] = json!(3);
        no_op["result"]["data"]["erasure"]["postcondition"]["removed_effects"] = json!(0);
        no_op["result"]["data"]["erasure"]["postcondition"]["matched_effects"] = json!(0);
        serde_json::from_value::<ProviderControlResultV1>(no_op.clone())
            .expect("verified zero change")
            .validate_for(request)
            .expect("actual absence verification is a provider no-op");
        let mut retained = no_op.clone();
        retained["result"]["data"]["erasure"]["state"] = json!("retained_under_lock");
        retained["result"]["data"]["erasure"]["retention_lock_receipt"] = json!("lock.explicit.1");
        retained["result"]["data"]["erasure"]["postcondition"]["verification_state"] =
            json!("retained_under_explicit_lock");
        retained["result"]["data"]["erasure"]["postcondition"]["matched_effects"] = json!(1);
        retained["result"]["data"]["erasure"]["postcondition"]["retained_under_lock"] = json!(1);
        retained["result"]["data"]["erasure"]["postcondition"]["remaining_influence_count"] =
            json!(1);
        serde_json::from_value::<ProviderControlResultV1>(retained.clone())
            .expect("retained zero change")
            .validate_for(request)
            .expect("explicit lock verification is a provider no-op");
        for base in [&no_op, &retained] {
            for count in [
                "removed_effects",
                "anonymized_effects",
                "snapshots_rewritten",
            ] {
                let mut contradiction = base.clone();
                contradiction["result"]["data"]["erasure"]["postcondition"]["matched_effects"] =
                    json!(2);
                contradiction["result"]["data"]["erasure"]["postcondition"]["snapshots_examined"] =
                    json!(1);
                contradiction["result"]["data"]["erasure"]["postcondition"][count] = json!(1);
                assert!(
                    serde_json::from_value::<ProviderControlResultV1>(contradiction)
                        .expect("typed contradictory count")
                        .validate()
                        .is_err(),
                    "accepted no-effect {count}"
                );
            }
            for terminal in [
                "provider_unavailable",
                "effect_unknown",
                "internal_failure",
                "contract_violation",
                "cancelled",
                "partial",
            ] {
                let mut contradiction = base.clone();
                contradiction["terminal"] = json!(terminal);
                if terminal == "effect_unknown" {
                    contradiction["effect"]["state"] = json!("unknown");
                    contradiction["effect"]["provider_receipt_digest"] = json!("b".repeat(64));
                    contradiction["effect"]["reconciliation_action"] =
                        json!("Inspect the actual provider receipt");
                }
                assert!(
                    serde_json::from_value::<ProviderControlResultV1>(contradiction)
                        .expect("typed contradictory terminal")
                        .validate()
                        .is_err(),
                    "accepted verified {terminal}"
                );
            }
            let mut missing = base.clone();
            missing["result"]["data"]["erasure"]
                .as_object_mut()
                .expect("erasure object")
                .remove("receipt");
            assert!(serde_json::from_value::<ProviderControlResultV1>(missing).is_err());
        }
        let mut partial = result_value(request, successful_data(2), "partial_effect");
        partial["effect"] = committed_effect();
        partial["effect"]["state"] = json!("partial");
        partial["effect"]["committed_boundary"] = json!("effect.1");
        partial["effect"]["committed_item_refs"] = json!(["effect.1"]);
        partial["effect"]["uncommitted_item_refs"] = json!(["effect.2"]);
        partial["effect"]["reconciliation_action"] = json!("Inspect remaining provider effects");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(partial)
                .expect("valid partial effect shape")
                .validate()
                .is_err()
        );
        let committed = result_value(request, successful_data(2), "success");
        for pointer in [
            "/effect/provider_receipt_digest",
            "/effect/verification_digest",
        ] {
            let mut missing = committed.clone();
            *missing.pointer_mut(pointer).expect("proof pointer") = Value::Null;
            assert!(
                serde_json::from_value::<ProviderControlResultV1>(missing)
                    .expect("typed missing proof")
                    .validate()
                    .is_err()
            );
        }
        for pointer in [
            "/result/data/erasure/receipt/provider_receipt_digest",
            "/result/data/erasure/postcondition/verification_query_digest",
        ] {
            let mut contradiction = committed.clone();
            *contradiction.pointer_mut(pointer).expect("proof pointer") =
                json!(if pointer.contains("verification_query") {
                    "".to_owned()
                } else {
                    "e".repeat(64)
                });
            assert!(
                serde_json::from_value::<ProviderControlResultV1>(contradiction)
                    .expect("typed contradictory proof")
                    .validate()
                    .is_err()
            );
        }
        let mut maintenance_request = requests()[5].clone();
        if let ProviderControlRequestV1::Maintenance(request) = &mut maintenance_request {
            request.dry_run = true;
        }
        let mut dry_run = result_value(&maintenance_request, successful_data(5), "success");
        dry_run["effect"] = none_effect();
        dry_run["result"]["data"]["dry_run"] = json!(true);
        dry_run["result"]["data"]["changed_items"] = json!(0);
        dry_run["result"]["data"]["removed_items"] = json!(0);
        dry_run["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        serde_json::from_value::<ProviderControlResultV1>(dry_run)
            .expect("dry-run maintenance")
            .validate_for(&maintenance_request)
            .expect("actual dry-run no-op");
    }

    #[test]
    fn replay_partition_and_restore_generation_cannot_claim_incomplete_success() {
        let requests = requests();
        let mut replay = result_value(&requests[8], successful_data(8), "success");
        replay["result"]["data"]["duplicate_observations"] = json!(1);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(replay)
                .expect("wrong partition")
                .validate()
                .is_err()
        );
        let mut restore = result_value(&requests[7], successful_data(7), "success");
        restore["effect"]["state_generation_after"] = json!(3);
        restore["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(restore)
                .expect("no generation advance")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn diagnostic_reference_is_optional_lossless_and_uses_the_generated_bound() {
        let request = &requests()[3];
        let absent = result_value(request, Value::Null, "provider_unavailable");
        let result: ProviderControlResultV1 =
            serde_json::from_value(absent).expect("legacy omitted diagnostic remains valid");
        result.validate_for(request).expect("omitted diagnostic");
        assert!(result.diagnostic_id.is_none());
        assert!(
            serde_json::to_value(&result)
                .expect("result")
                .get("diagnostic_id")
                .is_none()
        );
        let maximum = generated_contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES;
        assert_eq!(
            maximum, 128,
            "schema bound follows the generated canonical bound"
        );
        let mut result = result;
        let diagnostic = "d".repeat(maximum);
        result.diagnostic_id = Some(diagnostic.clone());
        result
            .validate_for(request)
            .expect("maximum diagnostic reference");
        assert_eq!(
            serde_json::to_value(&result).expect("result")["diagnostic_id"],
            diagnostic
        );
        assert!(result.domain_detail.is_none());
        for invalid in [String::new(), " d".to_owned(), "d".repeat(maximum + 1)] {
            result.diagnostic_id = Some(invalid);
            assert!(result.validate().is_err());
        }
    }

    #[test]
    fn serde_enums_and_terminal_effect_policy_match_generated_wire_contract() {
        for value in [
            ProviderControlFeedbackSignalV1::Helpful,
            ProviderControlFeedbackSignalV1::Harmful,
            ProviderControlFeedbackSignalV1::Ignored,
            ProviderControlFeedbackSignalV1::Corrected,
            ProviderControlFeedbackSignalV1::Superseded,
        ] {
            let text = serde_json::to_value(value).expect("signal");
            assert!(
                generated_contract::FeedbackSignal::from_wire(text.as_str().expect("wire string"))
                    .is_some()
            );
        }
        for value in [
            ProviderControlMaintenanceTaskV1::Consolidate,
            ProviderControlMaintenanceTaskV1::Decay,
            ProviderControlMaintenanceTaskV1::PruneExpired,
            ProviderControlMaintenanceTaskV1::ValidateState,
            ProviderControlMaintenanceTaskV1::Repair,
            ProviderControlMaintenanceTaskV1::Compact,
        ] {
            let text = serde_json::to_value(value).expect("task");
            assert!(
                generated_contract::MaintenanceTask::from_wire(text.as_str().expect("wire"))
                    .is_some()
            );
        }
        for value in [
            ProviderControlDeletionModeV1::RemoveInfluence,
            ProviderControlDeletionModeV1::HardDelete,
            ProviderControlDeletionModeV1::Anonymize,
        ] {
            let text = serde_json::to_value(value).expect("mode");
            assert!(
                generated_contract::DeletionMode::from_wire(text.as_str().expect("wire")).is_some()
            );
        }
        let states = [
            ProviderControlEffectStateV1::None,
            ProviderControlEffectStateV1::Committed,
            ProviderControlEffectStateV1::Duplicate,
            ProviderControlEffectStateV1::Partial,
            ProviderControlEffectStateV1::Unknown,
        ];
        for policy in generated_contract::TERMINAL_CODE_POLICIES {
            let terminal: ProviderControlTerminalV1 =
                serde_json::from_value(json!(policy.terminal_code.as_wire()))
                    .expect("same closed terminal");
            for state in states {
                use ProviderControlEffectStateV1 as Effect;
                use generated_contract::CommittedEffectExpectation as Expectation;
                let expected = match policy.effect_expectation {
                    Expectation::OperationSpecific | Expectation::NoneOrOperationSpecific => {
                        matches!(state, Effect::None | Effect::Committed | Effect::Duplicate)
                    }
                    Expectation::None => state == Effect::None,
                    Expectation::NonePartialOrUnknown => {
                        matches!(state, Effect::None | Effect::Partial | Effect::Unknown)
                    }
                    Expectation::NoneOrUnknown => matches!(state, Effect::None | Effect::Unknown),
                    Expectation::Partial => state == Effect::Partial,
                    Expectation::Unknown => state == Effect::Unknown,
                };
                assert_eq!(terminal_allows_effect(terminal, state), expected);
            }
        }
    }
}
