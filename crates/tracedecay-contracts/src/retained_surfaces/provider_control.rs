//! Retained provider-local controls, independent from canonical fact CRUD.
//!
//! Public requests carry a retained namespace lookup key and bounded caller
//! parameters. The host resolves the exact provider namespace, then assembles
//! operation identity, readiness, and request controls. Constructing one of
//! these values never grants provider authority.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{CURRENT_SURFACES, RetainedSurfaceOperation, RetainedSurfaceSpec};
use crate::error::ApplicationContractError;
use tracedecay_tool_catalog::{EffectClass, ScopeDimension};

pub const MAX_PROVIDER_CONTROL_REFERENCE_BYTES: usize = 1024;
pub const MAX_PROVIDER_CONTROL_INSPECTION_ITEMS: usize = 100_000;
pub const MAX_PROVIDER_CONTROL_RESPONSE_BYTES: usize = 33_554_432;

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
    MaintenanceReceipt,
    CapabilityStatus,
}

/// Receipt references are untrusted keys looked up within the separately
/// authorized state namespace; no provider stable reference is accepted.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "view", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderControlInspectionSelectorV1 {
    StateSummary,
    /// Provider-reported outcome query using actual returned control identities.
    /// Caller-supplied identities do not grant host receipt authority.
    MaintenanceReceipt {
        #[schemars(length(min = 1, max = 256))]
        operation_id: String,
        #[schemars(length(min = 64, max = 64))]
        idempotency_key: String,
    },
    CapabilityStatus,
}

impl ProviderControlInspectionSelectorV1 {
    pub const fn view(&self) -> ProviderControlInspectionViewV1 {
        match self {
            Self::StateSummary => ProviderControlInspectionViewV1::StateSummary,
            Self::MaintenanceReceipt { .. } => ProviderControlInspectionViewV1::MaintenanceReceipt,
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
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderControlRequestV1 {
    Health(ProviderHealthRequestV1),
    Inspection(ProviderInspectionRequestV1),
    Maintenance(ProviderMaintenanceRequestV1),
}

impl ProviderControlRequestV1 {
    pub const fn operation(&self) -> RetainedSurfaceOperation {
        match self {
            Self::Health(_) => RetainedSurfaceOperation::ProviderHealth,
            Self::Inspection(_) => RetainedSurfaceOperation::ProviderInspection,
            Self::Maintenance(_) => RetainedSurfaceOperation::ProviderMaintenance,
        }
    }

    pub const fn state_selector(&self) -> &ProviderControlStateSelectorV1 {
        match self {
            Self::Health(request) => &request.state,
            Self::Inspection(request) => &request.state,
            Self::Maintenance(request) => &request.state,
        }
    }

    /// Bounds validation only. Namespace authorization is a host read.
    pub fn validate(&self) -> Result<(), ApplicationContractError> {
        validate_state_selector(self.state_selector())?;
        match self {
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
                    ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                        operation_id,
                        idempotency_key,
                    } => require(
                        valid_uuid_v7(operation_id) && valid_sha256(idempotency_key),
                        "maintenance receipt query identities",
                    ),
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
/// durable receipt.
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
/// content is provider-local open evidence; receipt views cannot use that
/// variant, and the host validates each original wire binding first.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(
    tag = "view",
    content = "items",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderControlInspectionItemsV1 {
    StateSummary(Vec<ProviderControlEvidenceV1>),
    MaintenanceReceipt(Vec<ProviderControlMaintenanceReceiptItemV1>),
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
#[serde(deny_unknown_fields)]
pub struct ProviderInspectionResultV1 {
    pub selection: ProviderControlInspectionSelectorV1,
    pub items: ProviderControlInspectionItemsV1,
    pub coverage: ProviderControlInspectionCoverageV1,
    pub next_cursor: Option<String>,
    pub redactions: Vec<String>,
    /// Current generation observed by the provider runtime.
    pub state_generation: u64,
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
    Health(Option<ProviderHealthResultV1>),
    Inspection(Option<ProviderInspectionResultV1>),
    Maintenance(Option<ProviderMaintenanceResultV1>),
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

    /// Canonical representation digest, not a grant or proof of source authority.
    pub fn sha256(&self) -> String {
        use sha2::{Digest, Sha256};
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

impl ProviderControlInspectionItemsV1 {
    pub const fn view(&self) -> ProviderControlInspectionViewV1 {
        match self {
            Self::StateSummary(_) => ProviderControlInspectionViewV1::StateSummary,
            Self::MaintenanceReceipt(_) => ProviderControlInspectionViewV1::MaintenanceReceipt,
            Self::CapabilityStatus(_) => ProviderControlInspectionViewV1::CapabilityStatus,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::StateSummary(items) => items.len(),
            Self::MaintenanceReceipt(items) => items.len(),
            Self::CapabilityStatus(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn validate(&self) -> Result<(), ApplicationContractError> {
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
            Self::CapabilityStatus(items) => validate_capabilities(items)?,
        }
        Ok(())
    }
}

impl ProviderControlOperationResultV1 {
    pub const fn operation(&self) -> RetainedSurfaceOperation {
        match self {
            Self::Health(_) => RetainedSurfaceOperation::ProviderHealth,
            Self::Inspection(_) => RetainedSurfaceOperation::ProviderInspection,
            Self::Maintenance(_) => RetainedSurfaceOperation::ProviderMaintenance,
        }
    }

    fn has_data(&self) -> bool {
        match self {
            Self::Health(data) => data.is_some(),
            Self::Inspection(data) => data.is_some(),
            Self::Maintenance(data) => data.is_some(),
        }
    }

    fn mutation_receipt(&self) -> Option<&ProviderControlMutationReceiptV1> {
        match self {
            Self::Maintenance(Some(data)) => Some(&data.receipt),
            Self::Health(_) | Self::Inspection(_) | Self::Maintenance(None) => None,
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
                if let ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                    operation_id,
                    idempotency_key,
                } = &data.selection
                {
                    require(
                        valid_uuid_v7(operation_id) && valid_sha256(idempotency_key),
                        "maintenance receipt query identities",
                    )?;
                }
                data.items.validate()?;
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
                if let (
                    ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                        operation_id,
                        idempotency_key,
                    },
                    ProviderControlInspectionItemsV1::MaintenanceReceipt(items),
                ) = (&data.selection, &data.items)
                {
                    require(
                        items.iter().all(|item| {
                            item.operation_id == *operation_id
                                && item.idempotency_key == *idempotency_key
                        }),
                        "provider maintenance receipt query binding",
                    )?;
                }
            }
            ProviderControlOperationResultV1::Maintenance(Some(data)) => {
                validate_maintenance_result(data)?
            }
            _ => {}
        }
        if mutation
            && self.terminal == ProviderControlTerminalV1::Success
            && self.effect.state == ProviderControlEffectStateV1::None
        {
            let supported_no_effect = match &self.result {
                ProviderControlOperationResultV1::Maintenance(Some(data)) => {
                    (data.dry_run || (data.changed_items == 0 && data.removed_items == 0))
                        && data.state_changed != Some(true)
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
    /// Namespace and receipt authority still come from host resolution, not echoes.
    pub fn validate_for(
        &self,
        request: &ProviderControlRequestV1,
    ) -> Result<(), ApplicationContractError> {
        self.validate()?;
        require(
            self.operation() == request.operation(),
            "provider result operation",
        )?;
        // The host binds a canonical session to its provider-qualified agent
        // session; only the provider registration is comparable here.
        if let ProviderControlStateSelectorV1::CanonicalSession {
            provider_id,
            registration_revision,
            ..
        } = request.state_selector()
        {
            require(
                *provider_id == self.provider_id
                    && *registration_revision == self.registration_revision,
                "provider result selection",
            )?;
        }
        match (request, &self.result) {
            (
                ProviderControlRequestV1::Inspection(request),
                ProviderControlOperationResultV1::Inspection(Some(data)),
            ) => {
                require(
                    data.selection == request.selection
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
            _ => {}
        }
        Ok(())
    }
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

pub(super) const SPECS: [RetainedSurfaceSpec; 3] = [
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
        example: "Inspect the state summary or a maintenance receipt of this provider namespace",
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

    fn state() -> Value {
        json!({"kind":"canonical_session", "provider_id":"native", "registration_revision":7, "canonical_provider_id":"claude", "session_id":"session-1"})
    }
    #[test]
    fn public_selectors_address_only_a_host_resolved_namespace() {
        let valid = [
            json!({"view":"state_summary"}),
            json!({"view":"capability_status"}),
            json!({"view":"maintenance_receipt","operation_id":"01993262-4d00-7000-8000-000000000001","idempotency_key":"b".repeat(64)}),
        ];
        for selection in valid {
            let request: ProviderControlRequestV1 = serde_json::from_value(json!({"operation":"inspection","request":{"state":state(),"selection":selection,"maximum_items":10,"maximum_bytes":65536}})).expect("state-only inspection");
            request
                .validate()
                .expect("bounded state-only query");
        }
        for selection in [
            json!({"view":"maintenance_receipt","receipt_ref":"invented"}),
            json!({"view":"source_influence","source":{"trace_ref":"t","item_ref":"i","observation_id":"o"}}),
            json!({"view":"snapshot_metadata","snapshot_ref":"snapshot.host.1"}),
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
        for removed in ["feedback", "correction", "delete_by_source", "snapshot_export", "snapshot_restore", "replay"] {
            assert!(
                serde_json::from_value::<ProviderControlRequestV1>(
                    json!({"operation":removed,"request":{"state":state()}})
                )
                .is_err(),
                "{removed} is not a provider control"
            );
        }
    }

    #[test]
    fn provider_read_evidence_preserves_failure_payload_and_refuses_effect_family() {
        let mut value: ProviderControlResultV1 = serde_json::from_value(result_value(
            &requests()[0],
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
            serde_json::from_value(result_value(&requests()[2], successful_data(2), "success"))
                .expect("actual mutation reply"),
        );
        assert_eq!(
            effect.evidence_facts(),
            Err(super::super::RetainedSurfaceEvidenceTerminalV1::Effect)
        );
    }

    fn requests() -> Vec<ProviderControlRequestV1> {
        [
            json!({"operation":"health","request":{"state":state(),"requested_checks":["state","privacy"]}}),
            json!({"operation":"inspection","request":{"state":state(),"selection":{"view":"state_summary"},"maximum_items":10,"maximum_bytes":65536}}),
            json!({"operation":"maintenance","request":{"state":state(),"task":"validate_state","maximum_items":20,"maximum_bytes":65536,"maximum_duration_millis":1000,"dry_run":false}}),
        ].into_iter().map(|value| serde_json::from_value(value).expect("typed request")).collect()
    }
    fn scope() -> ProviderControlScopeV1 {
        ProviderControlScopeV1 {
            profile_id: "profile-1".to_owned(),
            project_id: "project-1".to_owned(),
            repository_identity: "repo-1".to_owned(),
            worktree_identity: "worktree-1".to_owned(),
            branch_identity: "refs/heads/main".to_owned(),
            agent_session_id: "session-1".to_owned(),
            resolved_scope_digest: format!("sha256:{}", "1".repeat(64)),
        }
    }
    fn receipt() -> Value {
        json!({"state_generation_before":3,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64)})
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
    fn successful_data(index: usize) -> Value {
        match index {
            0 => {
                json!({"provider_instance_id":"instance.1","implementation_identity_digest":"a".repeat(64),"state_identity_digest":"b".repeat(64),"state_generation":3,"scope_digest":scope().sha256(),"readiness":"ready","capability_states":[{"capability_id":"provider.health.v1","state":"available"}],"effective_limits_digest":"c".repeat(64),"backlog":0,"recovery_state":"ready"})
            }
            1 => {
                json!({"selection":{"view":"state_summary"},"items":{"view":"state_summary","items":[{"records":4}]},"coverage":"complete","next_cursor":null,"redactions":[],"state_generation":3})
            }
            2 => {
                json!({"task":"validate_state","dry_run":false,"scanned_items":1,"changed_items":1,"removed_items":0,"partial":false,"resume_cursor":null,"receipt":receipt()})
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn maintenance_state_comparison_is_optional_and_independent_of_item_counts() {
        let request = requests().remove(2);
        let mut raw = result_value(&request, successful_data(2), "success");
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
    fn maintenance_resume_cursor_is_optional_bounded_and_preserved() {
        let mut request = requests().remove(2);
        let ProviderControlRequestV1::Maintenance(data) = &mut request else {
            panic!("maintenance fixture")
        };
        assert_eq!(data.resume_cursor, None);
        data.resume_cursor = Some("native.scope:decay:17".to_owned());
        request
            .validate()
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
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn optional_provider_counts_preserve_native_values_and_ncm_omissions() {
        let requests = requests();
        for (index, field, count) in [(0, "staged_rows", 9_u64), (2, "proposed_changes", 3)] {
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
            request.validate().expect("valid request");
            for field in [
                "exact_scope_identity",
                "history_grant",
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
        for (index, field, value) in [
            (0, "requested_checks", json!(["state", "state"])),
            (0, "requested_checks", json!([])),
            (1, "maximum_items", json!(100001)),
            (1, "maximum_bytes", json!(33554433_u64)),
            (2, "maximum_duration_millis", json!(0)),
            (2, "maximum_bytes", json!(1073741825_u64)),
        ] {
            let mut request = serde_json::to_value(&requests()[index]).expect("request");
            request["request"][field] = value;
            let request: ProviderControlRequestV1 =
                serde_json::from_value(request).expect("typed bad bound");
            assert!(
                request.validate().is_err(),
                "accepted {field}"
            );
        }
        let mut blank_session = serde_json::to_value(&requests()[0]).expect("health");
        blank_session["request"]["state"]["session_id"] = json!(" session-1");
        let blank_session: ProviderControlRequestV1 =
            serde_json::from_value(blank_session).expect("typed selector");
        assert!(blank_session.validate().is_err());
    }

    #[test]
    fn provider_controls_have_distinct_catalog_schemas_and_sdk_controls() {
        let catalog = retained_surface_catalog_contribution().expect("catalog");
        for request in requests() {
            let operation = request.operation();
            let name = operation.as_str();
            assert!(name.starts_with("provider_"));
            assert_eq!(
                RetainedSurfaceOperation::from_operation_name(name),
                Some(operation)
            );
            assert!(RetainedSurfaceOperation::SDK_EXECUTABLE.contains(&operation));
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
        let provider_operations = RetainedSurfaceOperation::ALL
            .iter()
            .filter(|operation| operation.as_str().starts_with("provider_"))
            .count();
        assert_eq!(provider_operations, requests().len());
        assert_eq!(
            scope().sha256(),
            "2f525c8c3d59bfa3d9729405c4f3f1307fade77494b6ddf251c89abc490f0a52"
        );
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
            assert!(changed.validate_for(request).is_err());
        }
        let mut bad = result_value(&requests[2], successful_data(2), "success");
        bad["effect"] = none_effect();
        bad["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(bad)
                .expect("unevidenced no-op")
                .validate()
                .is_err()
        );
        let mut bad = result_value(&requests[0], successful_data(0), "success");
        bad["result"]["data"]["scope_digest"] = json!("e".repeat(64));
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(bad)
                .expect("health for another namespace")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn retained_host_unknown_without_provider_receipt_cannot_claim_commit_evidence() {
        let request = &requests()[2];
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
        let request = &requests()[2];
        let mut value = result_value(request, successful_data(2), "success");
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
    fn pinned_inspection_shapes_remain_closed_and_bounded() {
        let request = &requests()[1];
        let result: ProviderControlResultV1 =
            serde_json::from_value(result_value(request, successful_data(1), "success"))
                .expect("state summary");
        result.validate_for(request).expect("provider state summary");
        let mut mismatched = result_value(request, successful_data(1), "success");
        mismatched["result"]["data"]["items"] = json!({"view":"capability_status","items":[]});
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(mismatched)
                .expect("typed mismatched view")
                .validate()
                .is_err()
        );
        let mut unevidenced = result_value(request, successful_data(1), "success");
        unevidenced["result"]["data"]["state_generation"] = Value::Null;
        assert!(serde_json::from_value::<ProviderControlResultV1>(unevidenced).is_err());
        let mut uncursored = result_value(request, successful_data(1), "success");
        uncursored["result"]["data"]["next_cursor"] = json!("page.2");
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(uncursored)
                .expect("cursor with complete coverage")
                .validate()
                .is_err()
        );
        let receipt = json!({"view":"maintenance_receipt","items":[{"operation_id":"operation.1","idempotency_key":"key.1","outcome":successful_data(2)}]});
        serde_json::from_value::<ProviderControlInspectionItemsV1>(receipt.clone())
            .expect("closed maintenance receipt")
            .validate()
            .expect("provider maintenance receipt");
        let mut widened = receipt;
        widened["items"][0]["stable_memory_ref"] = json!("invented");
        assert!(serde_json::from_value::<ProviderControlInspectionItemsV1>(widened).is_err());
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
    fn dry_run_maintenance_is_a_verified_provider_no_op() {
        let mut maintenance_request = requests()[2].clone();
        if let ProviderControlRequestV1::Maintenance(request) = &mut maintenance_request {
            request.dry_run = true;
        }
        let mut dry_run = result_value(&maintenance_request, successful_data(2), "success");
        dry_run["effect"] = none_effect();
        dry_run["result"]["data"]["dry_run"] = json!(true);
        dry_run["result"]["data"]["changed_items"] = json!(0);
        dry_run["result"]["data"]["removed_items"] = json!(0);
        dry_run["result"]["data"]["receipt"]["state_generation_after"] = json!(3);
        serde_json::from_value::<ProviderControlResultV1>(dry_run.clone())
            .expect("dry-run maintenance")
            .validate_for(&maintenance_request)
            .expect("actual dry-run no-op");
        dry_run["result"]["data"]["receipt"]["state_generation_after"] = json!(4);
        assert!(
            serde_json::from_value::<ProviderControlResultV1>(dry_run)
                .expect("dry-run with a generation advance")
                .validate()
                .is_err()
        );
    }

    #[test]
    fn diagnostic_reference_is_optional_lossless_and_uses_the_generated_bound() {
        let request = &requests()[0];
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
