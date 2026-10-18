//! Pure projection of actual dispatch evidence into retained control results.
//!
//! This module grants no authority and performs no I/O. The caller resolves
//! the retained namespace before dispatch. A rejected result keeps the actual
//! reply for reconciliation.
use std::{collections::BTreeSet, fmt};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tracedecay_contracts::{RequestContext, retained_surfaces::*};
use tracedecay_memory_provider_registry::{
    CanonicalPayload, CommittedEffectState, FallbackDirective, OwnedExactScope, ProviderCall,
    ProviderLimits, ProviderOperation, ProviderReply,
};

use super::super::{
    cognitive_recall::control_attribution::RecallControlTraceRefV1,
    observation_journey::{
        control_dispatch::JourneyControlDispatchReplyV1, exact_scope_names_canonical_session,
    },
};

pub(super) type ProjectionResult<T> = Result<T, &'static str>;

pub(super) struct ProviderControlProjectionInput<'host, 'reply> {
    pub(super) context: &'host RequestContext,
    pub(super) request: &'host ProviderControlRequestV1,
    pub(super) dispatched: &'reply JourneyControlDispatchReplyV1,
}

pub(super) enum InspectionEvidenceV1<'a> {
    StateSummary,
    MaintenanceReceipt {
        operation_id: &'a str,
        idempotency_key: &'a str,
    },
    CapabilityStatus,
}

pub(super) enum HostControlEvidence<'a> {
    Health,
    Inspection(InspectionEvidenceV1<'a>),
    Maintenance,
}

pub(super) struct ProviderControlProjectionRejection<'reply> {
    pub(super) field: &'static str,
    pub(super) actual_reply: &'reply ProviderReply,
}

impl fmt::Debug for ProviderControlProjectionRejection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderControlProjectionRejection")
            .field("field", &self.field)
            .field("operation", &self.actual_reply.terminal.operation())
            .finish_non_exhaustive()
    }
}
impl fmt::Display for ProviderControlProjectionRejection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "provider control result rejected: {}", self.field)
    }
}
impl std::error::Error for ProviderControlProjectionRejection<'_> {}

pub(super) fn project_provider_control_reply<'reply>(
    input: ProviderControlProjectionInput<'_, 'reply>,
    evidence: HostControlEvidence<'_>,
) -> Result<ProviderControlResultV1, ProviderControlProjectionRejection<'reply>> {
    project(&input, evidence).map_err(|field| ProviderControlProjectionRejection {
        field,
        actual_reply: &input.dispatched.reply,
    })
}

fn project(
    input: &ProviderControlProjectionInput<'_, '_>,
    evidence: HostControlEvidence<'_>,
) -> ProjectionResult<ProviderControlResultV1> {
    let dispatch = input.dispatched;
    let call = &dispatch.call;
    let reply = &dispatch.reply;
    let readiness = &dispatch.readiness_evidence;
    let limits = readiness.effective_limits();
    call.validate_request_bytes(limits.request_bytes)
        .map_err(|_| "call boundary")?;
    reply
        .validate(limits.response_bytes)
        .map_err(|_| "reply boundary")?;
    input
        .context
        .validate()
        .map_err(|_| "authenticated context")?;
    require(
        call.request_id == input.context.request_id().as_str(),
        "request identity",
    )?;
    require(
        call.operation.as_wire() == operation_wire(input.request),
        "operation identity",
    )?;
    require(
        call.ready_receipt_sha256 == readiness.ready_receipt_sha256(),
        "ready receipt",
    )?;
    require(
        call.payload.contract_id.as_str() == operation_contract_id(call.operation)?,
        "call payload contract",
    )?;
    if let Some(payload) = &reply.payload {
        require(
            payload.contract_id == call.payload.contract_id,
            "reply payload contract",
        )?;
    }
    let terminal = &reply.terminal;
    require(
        terminal.provider_id() == &call.provider_id
            && terminal.operation() == call.operation
            && terminal.operation_id() == call.operation_id
            && terminal.exact_scope_sha256() == call.exact_scope.exact_scope_sha256(),
        "terminal binding",
    )?;
    // The retained contract has no fallback-policy carrier. Never silently drop one.
    require(
        terminal.fallback() == &FallbackDirective::forbidden(),
        "fallback evidence",
    )?;
    let effect = project_effect(call, reply)?;
    let request = payload(&call.payload)?;
    validate_request_fields(call.operation, &request)?;
    validate_common_request(input.context, call, field(&request, "common_request")?)?;
    validate_state_selector(input.request.state_selector(), call)?;
    let response = reply.payload.as_ref().map(payload).transpose()?;
    let mut warnings = reply.warnings.clone();
    if let Some(value) = &response {
        let payload_warnings: Vec<String> = decode(field(value, "warnings")?, "payload warnings")?;
        warnings.extend(payload_warnings);
        require(warnings.len() <= 32, "aggregate warnings")?;
        validate_optional_receipt(value, call, reply)?;
    }
    let result = match (input.request, evidence) {
        (ProviderControlRequestV1::Health(public), HostControlEvidence::Health) => {
            eq_field(
                &request,
                "requested_checks",
                &wire(&public.requested_checks)?,
            )?;
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    eq_field(value, "provider_id", &json!(call.provider_id.as_str()))?;
                    let data = health_data(value)?;
                    require(
                        data.provider_instance_id == readiness.provider_instance_id()
                            && data.implementation_identity_digest
                                == readiness.implementation_identity_sha256()
                            && data.scope_digest == call.exact_scope.exact_scope_sha256()
                            && data.state_generation == reply.state_generation
                            && data.effective_limits_digest == limits_digest(limits),
                        "health readiness binding",
                    )?;
                    validate_capabilities(&data.capability_states, dispatch, true)?;
                    Ok(data)
                })
                .transpose()?;
            ProviderControlOperationResultV1::Health(data)
        }
        (
            ProviderControlRequestV1::Inspection(public),
            HostControlEvidence::Inspection(selection),
        ) => {
            eq_field(&request, "view", &wire(&public.selection.view())?)?;
            eq_field(&request, "maximum_items", &json!(public.maximum_items))?;
            eq_field(&request, "maximum_bytes", &json!(public.maximum_bytes))?;
            eq_field(&request, "cursor", &json!(public.cursor))?;
            require(
                number(&request, "redaction_policy_revision")? > 0,
                "inspection redaction policy",
            )?;
            validate_inspection_selector(
                &public.selection,
                &selection,
                field(&request, "selector")?,
            )?;
            let data = response
                .as_ref()
                .map(|value| project_inspection(public, &selection, value, dispatch))
                .transpose()?;
            ProviderControlOperationResultV1::Inspection(data)
        }
        (ProviderControlRequestV1::Maintenance(public), HostControlEvidence::Maintenance) => {
            eq_field(&request, "resume_cursor", &json!(public.resume_cursor))?;
            for (name, expected) in [
                ("task", wire(&public.task)?),
                ("maximum_items", json!(public.maximum_items)),
                ("maximum_bytes", json!(public.maximum_bytes)),
                (
                    "maximum_duration_millis",
                    json!(public.maximum_duration_millis),
                ),
                ("dry_run", json!(public.dry_run)),
            ] {
                eq_field(&request, name, &expected)?;
            }
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    let data = maintenance(value, call, reply)?;
                    require(
                        data.task == public.task
                            && data.dry_run == public.dry_run
                            && data.scanned_items <= public.maximum_items,
                        "maintenance request binding",
                    )?;
                    Ok(data)
                })
                .transpose()?;
            ProviderControlOperationResultV1::Maintenance(data)
        }
        _ => return Err("host evidence operation"),
    };
    let result = ProviderControlResultV1 {
        provider_id: call.provider_id.as_str().to_owned(),
        registration_revision: call.registration_revision,
        scope: scope(&call.exact_scope),
        operation_id: call.operation_id.clone(),
        idempotency_key: call.idempotency_key.clone(),
        terminal: decode(
            &json!(terminal.terminal_code().as_wire()),
            "terminal vocabulary",
        )?,
        diagnostic_id: terminal.diagnostic_id().map(str::to_owned),
        domain_detail: None,
        effect,
        result,
        warnings,
    };
    result
        .validate_for(input.request)
        .map_err(|_| "retained result invariants")?;
    Ok(result)
}

fn operation_wire(request: &ProviderControlRequestV1) -> &'static str {
    match request {
        ProviderControlRequestV1::Health(_) => "health",
        ProviderControlRequestV1::Inspection(_) => "inspection",
        ProviderControlRequestV1::Maintenance(_) => "maintenance",
    }
}
fn operation_contract_id(operation: ProviderOperation) -> ProjectionResult<&'static str> {
    Ok(match operation {
        ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
        ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
        ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
        _ => return Err("non-control operation"),
    })
}

fn project_effect(
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<ProviderControlEffectV1> {
    let e = reply.terminal.committed_effect();
    if let Some(after) = e.state_generation_after() {
        require(after == reply.state_generation, "effect after generation")?;
    }
    if matches!(
        e.state(),
        CommittedEffectState::Committed | CommittedEffectState::Partial
    ) {
        require(
            e.state_generation_before() == Some(call.expected_state_generation),
            "effect before generation",
        )?;
    }
    if e.state() == CommittedEffectState::Duplicate {
        require(
            e.duplicate_of_idempotency_key() == call.idempotency_key.as_deref()
                && e.state_generation_before() == e.state_generation_after(),
            "duplicate identity and generation",
        )?;
    }
    Ok(ProviderControlEffectV1 {
        state: decode(&json!(e.state().as_wire()), "effect vocabulary")?,
        committed_boundary: e.committed_boundary().map(str::to_owned),
        state_generation_before: e.state_generation_before(),
        state_generation_after: e.state_generation_after(),
        committed_item_refs: e.committed_item_refs().to_vec(),
        uncommitted_item_refs: e.uncommitted_item_refs().to_vec(),
        provider_receipt_digest: e.provider_receipt_sha256().map(str::to_owned),
        reconciliation_action: e.reconciliation_action().map(str::to_owned),
        verification_digest: e.verification_sha256().map(str::to_owned),
        duplicate_of_idempotency_key: e.duplicate_of_idempotency_key().map(str::to_owned),
        duplicate_of_operation_id: e.duplicate_of_operation_id().map(str::to_owned),
    })
}
fn mutation_receipt(
    value: &Value,
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<ProviderControlMutationReceiptV1> {
    let receipt: ProviderControlMutationReceiptV1 = decode_selected(
        value,
        &[
            "state_generation_before",
            "state_generation_after",
            "provider_receipt_digest",
        ],
    )?;
    validate_receipt(&receipt, call, reply)?;
    Ok(receipt)
}
fn validate_receipt(
    receipt: &ProviderControlMutationReceiptV1,
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<()> {
    let effect = reply.terminal.committed_effect();
    require(
        receipt.state_generation_before <= receipt.state_generation_after
            && valid_digest(&receipt.provider_receipt_digest),
        "mutation receipt shape",
    )?;
    let dry_run_read = call.operation == ProviderOperation::Maintenance
        && effect.state() == CommittedEffectState::None
        && payload(&call.payload)?
            .get("dry_run")
            .and_then(Value::as_bool)
            == Some(true);
    if !call.operation.mutates_provider_state() || dry_run_read {
        require(
            effect.state() == CommittedEffectState::None
                && receipt.state_generation_before == receipt.state_generation_after
                && receipt.state_generation_after == reply.state_generation,
            "unchanged read receipt generation",
        )?;
        return Ok(());
    }
    if effect.state() == CommittedEffectState::Duplicate {
        // Historical payload evidence keeps the original operation's generation.
        require(
            receipt.state_generation_after <= reply.state_generation
                && Some(receipt.provider_receipt_digest.as_str())
                    == effect.provider_receipt_sha256(),
            "duplicate original receipt",
        )?;
    } else {
        require(
            receipt.state_generation_before == call.expected_state_generation
                && receipt.state_generation_after == reply.state_generation,
            "mutation receipt generation",
        )?;
        if let Some(digest) = effect.provider_receipt_sha256() {
            require(
                receipt.provider_receipt_digest == digest,
                "mutation receipt digest",
            )?;
        }
    }
    Ok(())
}
fn validate_optional_receipt(
    value: &Value,
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<()> {
    let has_before = value.get("state_generation_before").is_some();
    let has_after = value.get("state_generation_after").is_some();
    require(has_before == has_after, "partial generation pair")?;
    if has_before {
        mutation_receipt(value, call, reply)?;
    }
    Ok(())
}
fn validate_request_fields(operation: ProviderOperation, request: &Value) -> ProjectionResult<()> {
    let fields: &[&str] = match operation {
        ProviderOperation::Health => &["common_request", "requested_checks"],
        ProviderOperation::Inspection => &[
            "common_request",
            "view",
            "selector",
            "maximum_items",
            "maximum_bytes",
            "redaction_policy_revision",
            "cursor",
        ],
        ProviderOperation::Maintenance => &[
            "common_request",
            "task",
            "maximum_items",
            "maximum_bytes",
            "maximum_duration_millis",
            "dry_run",
            "resume_cursor",
        ],
        _ => return Err("non-control request"),
    };
    closed(request, fields)
}

fn validate_common_request(
    context: &RequestContext,
    call: &ProviderCall,
    value: &Value,
) -> ProjectionResult<()> {
    closed(
        value,
        &[
            "provider_id",
            "registration_revision",
            "ready_receipt_digest",
            "exact_scope_identity",
            "operation_id",
            "idempotency_key",
            "expected_state_generation",
            "request_identity",
            "policy_revision",
            "deadline",
            "cancellation",
            "extensions",
        ],
    )?;
    for (name, expected) in [
        ("provider_id", json!(call.provider_id.as_str())),
        ("registration_revision", json!(call.registration_revision)),
        ("ready_receipt_digest", json!(call.ready_receipt_sha256)),
        ("exact_scope_identity", wire(&scope(&call.exact_scope))?),
        ("operation_id", json!(call.operation_id)),
        ("idempotency_key", json!(call.idempotency_key)),
        (
            "expected_state_generation",
            json!(call.expected_state_generation),
        ),
        ("request_identity", json!(context.request_id().as_str())),
        ("cancellation", json!("live")),
        ("extensions", json!([])),
    ] {
        eq_field(value, name, &expected)?;
    }
    require(
        number(value, "policy_revision")? > 0,
        "control policy revision",
    )?;
    let deadline = field(value, "deadline")?;
    closed(deadline, &["deadline_utc_micros", "remaining_millis"])?;
    eq_field(
        deadline,
        "deadline_utc_micros",
        &json!(call.control.deadline_utc_micros()),
    )?;
    require(
        number(deadline, "remaining_millis")? > 0,
        "dispatch remaining budget",
    )
}
fn validate_state_selector(
    selector: &ProviderControlStateSelectorV1,
    call: &ProviderCall,
) -> ProjectionResult<()> {
    match selector {
        ProviderControlStateSelectorV1::CanonicalSession {
            provider_id,
            registration_revision,
            canonical_provider_id,
            session_id,
        } => {
            require(
                !canonical_provider_id.is_empty() && canonical_provider_id.len() <= 1024,
                "canonical session provider",
            )?;
            // The registered canonical-provider/session pair is resolved by the
            // host; the dispatched scope must carry that session's own
            // provider-qualified agent-session binding.
            require(
                provider_id == call.provider_id.as_str()
                    && *registration_revision == call.registration_revision
                    && exact_scope_names_canonical_session(&call.exact_scope, session_id),
                "state selector binding",
            )
        }
        ProviderControlStateSelectorV1::RecallScope { trace_ref } => {
            let parsed =
                RecallControlTraceRefV1::parse(trace_ref).map_err(|_| "retained state selector")?;
            let (_, address) = parsed
                .as_str()
                .split_once(':')
                .ok_or("retained scope address")?;
            let (scope_digest, _) = address.split_once(':').ok_or("retained scope address")?;
            require(
                scope_digest == call.exact_scope.exact_scope_sha256(),
                "retained state scope binding",
            )
        }
    }
}

pub(super) fn scope(value: &OwnedExactScope) -> ProviderControlScopeV1 {
    ProviderControlScopeV1 {
        profile_id: value.profile_id.clone(),
        project_id: value.project_id.clone(),
        repository_identity: value.repository_identity.clone(),
        worktree_identity: value.worktree_identity.clone(),
        branch_identity: value.branch_identity.clone(),
        agent_session_id: value.agent_session_id.clone(),
        resolved_scope_digest: value.resolved_scope_digest.clone(),
    }
}
fn health_data(value: &Value) -> ProjectionResult<ProviderHealthResultV1> {
    closed(
        value,
        &[
            "provider_id",
            "provider_instance_id",
            "implementation_identity_digest",
            "state_identity_digest",
            "state_generation",
            "scope_digest",
            "readiness",
            "capability_states",
            "effective_limits_digest",
            "backlog",
            "recovery_state",
            "staged_rows",
            "warnings",
            "state_generation_before",
            "state_generation_after",
            "provider_receipt_digest",
        ],
    )?;
    let mut data: ProviderHealthResultV1 = decode_selected(
        value,
        &[
            "provider_instance_id",
            "implementation_identity_digest",
            "state_identity_digest",
            "state_generation",
            "scope_digest",
            "readiness",
            "capability_states",
            "effective_limits_digest",
            "backlog",
            "recovery_state",
        ],
    )?;
    data.staged_rows = optional_count(value, "staged_rows")?;
    Ok(data)
}

fn maintenance(
    value: &Value,
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<ProviderMaintenanceResultV1> {
    closed(
        value,
        &[
            "task",
            "dry_run",
            "scanned_items",
            "changed_items",
            "removed_items",
            "proposed_changes",
            "state_changed",
            "partial",
            "resume_cursor",
            "state_generation_before",
            "state_generation_after",
            "provider_receipt_digest",
            "warnings",
        ],
    )?;
    Ok(ProviderMaintenanceResultV1 {
        task: decode(field(value, "task")?, "maintenance task")?,
        dry_run: boolean(value, "dry_run")?,
        scanned_items: number(value, "scanned_items")?,
        changed_items: number(value, "changed_items")?,
        removed_items: number(value, "removed_items")?,
        proposed_changes: optional_count(value, "proposed_changes")?,
        state_changed: optional_boolean(value, "state_changed")?,
        partial: boolean(value, "partial")?,
        resume_cursor: decode(field(value, "resume_cursor")?, "maintenance cursor")?,
        receipt: mutation_receipt(value, call, reply)?,
    })
}
fn validate_capabilities(
    states: &[ProviderControlCapabilityStatusV1],
    dispatch: &JourneyControlDispatchReplyV1,
    complete: bool,
) -> ProjectionResult<()> {
    let actual: BTreeSet<_> = states
        .iter()
        .map(|state| state.capability_id.as_str())
        .collect();
    let registered: BTreeSet<_> = dispatch
        .registered_capabilities
        .iter()
        .map(|capability| capability.as_str())
        .collect();
    require(
        actual.len() == states.len()
            && actual.is_subset(&registered)
            && (!complete || actual == registered),
        "registered capability identity",
    )
}
fn validate_inspection_selector(
    public: &ProviderControlInspectionSelectorV1,
    evidence: &InspectionEvidenceV1<'_>,
    selected: &Value,
) -> ProjectionResult<()> {
    let expected = match (public, evidence) {
        (ProviderControlInspectionSelectorV1::StateSummary, InspectionEvidenceV1::StateSummary)
        | (
            ProviderControlInspectionSelectorV1::CapabilityStatus,
            InspectionEvidenceV1::CapabilityStatus,
        ) => json!({}),
        (
            ProviderControlInspectionSelectorV1::MaintenanceReceipt {
                operation_id,
                idempotency_key,
            },
            InspectionEvidenceV1::MaintenanceReceipt {
                operation_id: selected_operation,
                idempotency_key: selected_key,
            },
        ) => {
            require(
                operation_id == selected_operation && idempotency_key == selected_key,
                "maintenance receipt selector",
            )?;
            json!({"operation_id":operation_id,"idempotency_key":idempotency_key})
        }
        _ => return Err("inspection host evidence"),
    };
    require(selected == &expected, "inspection selected query")
}

fn project_inspection(
    public: &ProviderInspectionRequestV1,
    evidence: &InspectionEvidenceV1<'_>,
    value: &Value,
    dispatch: &JourneyControlDispatchReplyV1,
) -> ProjectionResult<ProviderInspectionResultV1> {
    closed(
        value,
        &[
            "view",
            "items",
            "coverage",
            "next_cursor",
            "redactions",
            "state_generation",
            "warnings",
            "state_generation_before",
            "state_generation_after",
            "provider_receipt_digest",
        ],
    )?;
    eq_field(value, "view", &wire(&public.selection.view())?)?;
    require(
        number(value, "state_generation")? == dispatch.reply.state_generation,
        "inspection state generation",
    )?;
    let raw = field(value, "items")?
        .as_array()
        .ok_or("inspection items")?;
    require(
        raw.len() as u64
            <= public.maximum_items.min(
                dispatch
                    .readiness_evidence
                    .effective_limits()
                    .inspection_items,
            )
            && serde_json::to_vec(raw)
                .map_err(|_| "inspection encoding")?
                .len() as u64
                <= public.maximum_bytes,
        "inspection bounds",
    )?;
    if matches!(evidence, InspectionEvidenceV1::MaintenanceReceipt { .. }) {
        require(raw.len() <= 1, "inspection singleton query")?;
    }
    let items = match evidence {
        InspectionEvidenceV1::StateSummary => ProviderControlInspectionItemsV1::StateSummary(
            raw.iter()
                .map(|item| {
                    ProviderControlEvidenceV1::new(item.clone())
                        .map_err(|_| "state summary evidence")
                })
                .collect::<ProjectionResult<_>>()?,
        ),
        InspectionEvidenceV1::CapabilityStatus => {
            let states: Vec<ProviderControlCapabilityStatusV1> =
                decode(&Value::Array(raw.clone()), "capability status items")?;
            validate_capabilities(&states, dispatch, field(value, "coverage")? == "complete")?;
            ProviderControlInspectionItemsV1::CapabilityStatus(states)
        }
        InspectionEvidenceV1::MaintenanceReceipt {
            operation_id,
            idempotency_key,
        } => {
            for item in raw {
                optional_count(field(item, "outcome")?, "proposed_changes")?;
                optional_boolean(field(item, "outcome")?, "state_changed")?;
            }
            let data: Vec<ProviderControlMaintenanceReceiptItemV1> =
                decode(&Value::Array(raw.clone()), "maintenance receipt items")?;
            require(
                data.iter().all(|item| {
                    item.operation_id == *operation_id && item.idempotency_key == *idempotency_key
                }),
                "maintenance receipt query binding",
            )?;
            ProviderControlInspectionItemsV1::MaintenanceReceipt(data)
        }
    };
    Ok(ProviderInspectionResultV1 {
        selection: public.selection.clone(),
        items,
        coverage: decode(field(value, "coverage")?, "inspection coverage")?,
        next_cursor: decode(field(value, "next_cursor")?, "inspection cursor")?,
        redactions: decode(field(value, "redactions")?, "inspection redactions")?,
        state_generation: dispatch.reply.state_generation,
    })
}
fn limits_digest(limits: ProviderLimits) -> String {
    let mut hash = Sha256::new();
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
        hash.update(value.to_be_bytes());
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn payload(value: &CanonicalPayload) -> ProjectionResult<Value> {
    value.validate().map_err(|_| "canonical payload digest")?;
    serde_json::from_slice(&value.bytes).map_err(|_| "canonical payload JSON")
}
fn field<'a>(value: &'a Value, name: &'static str) -> ProjectionResult<&'a Value> {
    value.get(name).ok_or(name)
}
/// Provider omission is the only representation of an unreported count.
/// A present null, string, signed-negative or fractional value is malformed.
fn optional_count(value: &Value, name: &'static str) -> ProjectionResult<Option<u64>> {
    value
        .get(name)
        .map(|value| value.as_u64().ok_or(name))
        .transpose()
}

/// Optional boolean evidence has the same omission-only rule as counts.
fn optional_boolean(value: &Value, name: &'static str) -> ProjectionResult<Option<bool>> {
    value
        .get(name)
        .map(|value| value.as_bool().ok_or(name))
        .transpose()
}

fn number(value: &Value, name: &'static str) -> ProjectionResult<u64> {
    field(value, name)?.as_u64().ok_or(name)
}
fn boolean(value: &Value, name: &'static str) -> ProjectionResult<bool> {
    field(value, name)?.as_bool().ok_or(name)
}
fn require(condition: bool, name: &'static str) -> ProjectionResult<()> {
    if condition { Ok(()) } else { Err(name) }
}
fn eq_field(value: &Value, name: &'static str, expected: &Value) -> ProjectionResult<()> {
    require(field(value, name)? == expected, name)
}
fn decode<T: DeserializeOwned>(value: &Value, name: &'static str) -> ProjectionResult<T> {
    serde_json::from_value(value.clone()).map_err(|_| name)
}
fn wire<T: Serialize>(value: &T) -> ProjectionResult<Value> {
    serde_json::to_value(value).map_err(|_| "public wire encoding")
}
fn closed(value: &Value, allowed: &[&str]) -> ProjectionResult<()> {
    let object = value.as_object().ok_or("wire object")?;
    require(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "unknown wire field",
    )
}
fn decode_selected<T: DeserializeOwned>(
    value: &Value,
    names: &[&'static str],
) -> ProjectionResult<T> {
    let mut object = Map::new();
    for name in names {
        object.insert((*name).to_owned(), field(value, name)?.clone());
    }
    decode(&Value::Object(object), "typed operation fields")
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[cfg(test)]
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    use tracedecay_memory_provider_registry::{
        CancellationToken, CommittedEffectEvidence, OperationControl, OwnedProviderId,
        OwnedVersionedId, ProviderCallParts, TerminalCode, TerminalRecord,
    };

    fn call(generation: u64) -> ProviderCall {
        call_for(
            ProviderOperation::Maintenance,
            generation,
            json!({"dry_run": false}),
        )
    }

    fn call_for(operation: ProviderOperation, generation: u64, body: Value) -> ProviderCall {
        let bytes = serde_json::to_vec(&body).expect("canonical test body");
        ProviderCall::new(ProviderCallParts {
            operation,
            provider_id: OwnedProviderId::new("native").expect("provider"),
            registration_revision: 7,
            ready_receipt_sha256: "a".repeat(64),
            exact_scope: OwnedExactScope::new(
                "profile-1",
                "project-1",
                "repo-1",
                "worktree-1",
                "refs/heads/main",
                "session-1",
                format!("sha256:{}", "1".repeat(64)),
            )
            .expect("scope"),
            request_id: "request.projection".to_owned(),
            operation_id: "01993262-4d00-7000-8000-000000000001".to_owned(),
            expected_state_generation: generation,
            idempotency_key: operation.mutates_provider_state().then(|| "d".repeat(64)),
            control: OperationControl::new(i64::MAX, 1000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new(operation_contract_id(operation).expect("control contract"))
                    .expect("contract"),
                bytes.clone(),
                digest(&bytes),
            )
            .expect("payload"),
            required_capabilities: vec![
                OwnedVersionedId::new(operation.capability_id()).expect("capability"),
            ],
            extensions: Vec::new(),
        })
        .expect("actual typed call")
    }

    fn reply(
        call: &ProviderCall,
        code: TerminalCode,
        effect: CommittedEffectEvidence,
        generation: u64,
    ) -> ProviderReply {
        ProviderReply {
            terminal: TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                code,
                effect,
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                Some("actual.provider.diagnostic".to_owned()),
            )
            .expect("typed terminal"),
            payload: None,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: generation,
        }
    }

    #[test]
    fn native_health_staged_rows_and_ncm_omission_are_distinct() {
        let mut value = json!({"provider_id":"native","provider_instance_id":"instance.actual","implementation_identity_digest":"a".repeat(64),"state_identity_digest":"b".repeat(64),"state_generation":5,"scope_digest":"c".repeat(64),"readiness":"ready","capability_states":[{"capability_id":"provider.health.v1","state":"available"}],"effective_limits_digest":"d".repeat(64),"backlog":0,"recovery_state":"complete","staged_rows":17,"warnings":[],"state_generation_before":5,"state_generation_after":5,"provider_receipt_digest":"e".repeat(64)});
        assert_eq!(
            health_data(&value)
                .expect("actual Native health")
                .staged_rows,
            Some(17)
        );
        value["staged_rows"] = json!(0);
        assert_eq!(
            health_data(&value).expect("reported zero").staged_rows,
            Some(0)
        );
        value.as_object_mut().expect("object").remove("staged_rows");
        assert_eq!(
            health_data(&value).expect("NCM omitted count").staged_rows,
            None
        );
        for invalid in [Value::Null, json!(-1), json!(1.5), json!("17")] {
            value["staged_rows"] = invalid;
            assert!(health_data(&value).is_err());
        }
    }

    #[test]
    fn native_dry_run_preserves_proposed_changes_without_claiming_applied_changes() {
        let call = call_for(ProviderOperation::Maintenance, 3, json!({"dry_run":true}));
        let actual = reply(
            &call,
            TerminalCode::Success,
            CommittedEffectEvidence::none(Some(5)),
            5,
        );
        let mut value = json!({"task":"decay","dry_run":true,"scanned_items":7,"changed_items":0,"removed_items":0,"proposed_changes":4,"partial":false,"resume_cursor":null,"state_generation_before":5,"state_generation_after":5,"provider_receipt_digest":"b".repeat(64),"warnings":[]});
        let data = maintenance(&value, &call, &actual).expect("actual Native dry run");
        assert_eq!(data.proposed_changes, Some(4));
        assert_eq!(data.changed_items, 0);
        assert_eq!(data.receipt.state_generation_before, 5);
        value
            .as_object_mut()
            .expect("object")
            .remove("proposed_changes");
        assert_eq!(
            maintenance(&value, &call, &actual)
                .expect("NCM omitted proposals")
                .proposed_changes,
            None
        );
        for invalid in [Value::Null, json!(-1), json!(1.5), json!("4")] {
            value["proposed_changes"] = invalid;
            assert!(maintenance(&value, &call, &actual).is_err());
        }
    }

    #[test]
    fn read_receipts_bind_actual_unchanged_generation_without_weakening_mutation_cas() {
        let raw = json!({"state_generation_before":5,"state_generation_after":5,"provider_receipt_digest":"b".repeat(64)});
        for operation in [ProviderOperation::Health, ProviderOperation::Inspection] {
            let call = call_for(operation, 3, json!({}));
            let actual = reply(
                &call,
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(5)),
                5,
            );
            validate_optional_receipt(&raw, &call, &actual).expect("actual read generation");
            let mut stale = raw.clone();
            stale["state_generation_before"] = json!(3);
            assert!(validate_optional_receipt(&stale, &call, &actual).is_err());
            stale["state_generation_before"] = json!(4);
            stale["state_generation_after"] = json!(4);
            assert!(validate_optional_receipt(&stale, &call, &actual).is_err());
        }
        let mutation = call_for(ProviderOperation::Maintenance, 3, json!({"dry_run":false}));
        let actual = reply(
            &mutation,
            TerminalCode::SuccessZeroResults,
            CommittedEffectEvidence::none(Some(5)),
            5,
        );
        assert!(validate_optional_receipt(&raw, &mutation, &actual).is_err());
        let malformed = call_for(ProviderOperation::Maintenance, 3, json!({"dry_run":"true"}));
        let actual = reply(
            &malformed,
            TerminalCode::SuccessZeroResults,
            CommittedEffectEvidence::none(Some(5)),
            5,
        );
        assert!(validate_optional_receipt(&raw, &malformed, &actual).is_err());
    }

    #[test]
    fn duplicate_keeps_original_receipt_generations_and_original_operation() {
        let call = call(10);
        let original_operation = "01993262-4d00-7000-8000-000000000000";
        let duplicate = reply(
            &call,
            TerminalCode::Success,
            CommittedEffectEvidence::duplicate(
                10,
                call.idempotency_key.clone().expect("key"),
                original_operation,
                "b".repeat(64),
            )
            .expect("duplicate"),
            10,
        );
        let raw = json!({"state_generation_before":3,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64)});
        let receipt = mutation_receipt(&raw, &call, &duplicate).expect("original receipt");
        assert_eq!(
            (
                receipt.state_generation_before,
                receipt.state_generation_after
            ),
            (3, 4)
        );
        let effect = project_effect(&call, &duplicate).expect("duplicate projection");
        assert_eq!(effect.state, ProviderControlEffectStateV1::Duplicate);
        assert_eq!(effect.state_generation_before, Some(10));
        assert_eq!(effect.state_generation_after, Some(10));
        assert_eq!(
            effect.duplicate_of_operation_id.as_deref(),
            Some(original_operation)
        );
        let mut forged = raw;
        forged["provider_receipt_digest"] = json!("c".repeat(64));
        assert!(mutation_receipt(&forged, &call, &duplicate).is_err());
        let wrong = reply(
            &call,
            TerminalCode::Success,
            CommittedEffectEvidence::duplicate(
                10,
                "e".repeat(64),
                original_operation,
                "b".repeat(64),
            )
            .expect("other duplicate"),
            10,
        );
        assert!(project_effect(&call, &wrong).is_err());
    }

    #[test]
    fn partial_and_unknown_keep_actual_reconciliation_evidence() {
        let call = call(3);
        let partial = reply(
            &call,
            TerminalCode::PartialEffect,
            CommittedEffectEvidence::partial(
                "provider.boundary",
                3,
                4,
                vec!["memory.committed".to_owned()],
                vec!["memory.uncommitted".to_owned()],
                "b".repeat(64),
                "reconcile.actual",
                "c".repeat(64),
            )
            .expect("partial"),
            4,
        );
        let actual = project_effect(&call, &partial).expect("partial projection");
        assert_eq!(actual.state, ProviderControlEffectStateV1::Partial);
        assert_eq!(
            actual.committed_boundary.as_deref(),
            Some("provider.boundary")
        );
        assert_eq!(actual.committed_item_refs, vec!["memory.committed"]);
        assert_eq!(actual.uncommitted_item_refs, vec!["memory.uncommitted"]);
        assert_eq!(
            actual.verification_digest.as_deref(),
            Some("c".repeat(64).as_str())
        );
        let unknown = reply(
            &call,
            TerminalCode::EffectUnknown,
            CommittedEffectEvidence::unknown("b".repeat(64), "reconcile.actual").expect("unknown"),
            4,
        );
        let actual = project_effect(&call, &unknown).expect("unknown projection");
        assert_eq!(actual.state, ProviderControlEffectStateV1::Unknown);
        assert_eq!(actual.state_generation_before, None);
        assert_eq!(actual.state_generation_after, None);
        assert_eq!(
            actual.reconciliation_action.as_deref(),
            Some("reconcile.actual")
        );
        assert_eq!(
            unknown.terminal.diagnostic_id(),
            Some("actual.provider.diagnostic")
        );
    }

    #[test]
    fn committed_reply_generation_must_match_actual_effect_and_call() {
        let call = call(3);
        let effect = || {
            CommittedEffectEvidence::committed(
                3,
                4,
                vec!["memory.1".to_owned()],
                "b".repeat(64),
                "c".repeat(64),
            )
            .expect("effect")
        };
        let wrong_after = reply(&call, TerminalCode::Success, effect(), 5);
        assert!(project_effect(&call, &wrong_after).is_err());
        let valid = reply(&call, TerminalCode::Success, effect(), 4);
        let mut stale = call.clone();
        stale.expected_state_generation = 2;
        assert!(project_effect(&stale, &valid).is_err());
        assert!(mutation_receipt(&json!({"state_generation_before":2,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64)}),&call,&valid).is_err());
    }

    #[test]
    fn zero_effect_receipt_stays_unchanged_without_invented_commit() {
        let call = call(3);
        let actual = reply(
            &call,
            TerminalCode::SuccessZeroResults,
            CommittedEffectEvidence::none(Some(3)),
            3,
        );
        let receipt = mutation_receipt(&json!({"state_generation_before":3,"state_generation_after":3,"provider_receipt_digest":"b".repeat(64)}),&call,&actual).expect("actual no-change receipt");
        let projected = project_effect(&call, &actual).expect("effect-free");
        assert_eq!(projected.state, ProviderControlEffectStateV1::None);
        assert!(projected.provider_receipt_digest.is_none());
        assert_eq!(
            receipt.state_generation_before,
            receipt.state_generation_after
        );
    }

    #[test]
    fn rejection_retains_actual_reply_but_debug_does_not_leak_payload() {
        let call = call(3);
        let mut actual = reply(
            &call,
            TerminalCode::EffectUnknown,
            CommittedEffectEvidence::unknown("b".repeat(64), "reconcile.actual").expect("unknown"),
            4,
        );
        let bytes = br#"{"secret":"sensitive-provider-content"}"#.to_vec();
        actual.payload = Some(
            CanonicalPayload::new(
                call.payload.contract_id.clone(),
                bytes.clone(),
                digest(&bytes),
            )
            .expect("payload"),
        );
        assert!(actual.validate(65536).is_err());
        let rejection = ProviderControlProjectionRejection {
            field: "reply boundary",
            actual_reply: &actual,
        };
        assert!(std::ptr::eq(rejection.actual_reply, &actual));
        assert!(!format!("{rejection:?}").contains("sensitive-provider-content"));
        assert_eq!(
            rejection.actual_reply.terminal.diagnostic_id(),
            Some("actual.provider.diagnostic")
        );
    }

    #[test]
    fn typed_receipt_rejects_missing_and_wrongly_typed_evidence() {
        assert!(
            decode_selected::<ProviderControlMutationReceiptV1>(
                &json!({"state_generation_before":1,"state_generation_after":2}),
                &[
                    "state_generation_before",
                    "state_generation_after",
                    "provider_receipt_digest"
                ]
            )
            .is_err()
        );
        assert!(decode::<ProviderControlMutationReceiptV1>(&json!({"state_generation_before":1,"state_generation_after":"2","provider_receipt_digest":"a".repeat(64)}), "receipt").is_err());
        assert!(closed(&json!({"task":"repair","invented_success":true}), &["task"]).is_err());
    }

    #[test]
    fn maintenance_state_changed_preserves_false_and_rejects_malformed_presence() {
        assert_eq!(optional_boolean(&json!({}), "state_changed"), Ok(None));
        for actual in [false, true] {
            assert_eq!(
                optional_boolean(&json!({"state_changed":actual}), "state_changed"),
                Ok(Some(actual))
            );
        }
        for invalid in [Value::Null, json!("false"), json!(0), json!([])] {
            assert!(optional_boolean(&json!({"state_changed":invalid}), "state_changed").is_err());
        }
    }

    #[test]
    fn canonical_session_selector_binds_the_dispatched_agent_session() {
        let call = call_for(ProviderOperation::Health, 3, json!({}));
        let selector = |session_id: &str| ProviderControlStateSelectorV1::CanonicalSession {
            provider_id: "native".to_owned(),
            registration_revision: 7,
            canonical_provider_id: "claude".to_owned(),
            session_id: session_id.to_owned(),
        };
        // The fixture scope carries a raw label, not the host binding of any
        // canonical session, so even the matching label is refused.
        assert!(validate_state_selector(&selector("session-1"), &call).is_err());
        let mut bound = call.clone();
        bound.exact_scope.agent_session_id =
            super::super::super::observation_journey::agent_session_id_for_exact_scope(
                &call.exact_scope,
                "session.canonical",
            );
        validate_state_selector(&selector("session.canonical"), &bound)
            .expect("the dispatched scope binds the selected canonical session");
        assert!(validate_state_selector(&selector("session.other"), &bound).is_err());
    }
}
