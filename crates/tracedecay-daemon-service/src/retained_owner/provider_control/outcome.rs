//! Application outcomes derived from witnessed provider execution.
//!
//! Hashing evidence names what was observed; it does not persist a new receipt
//! or confirm an unobserved provider effect.

use serde::Serialize;
use tracedecay_contracts::retained_surfaces::*;
use tracedecay_contracts::{
    ApplicationOutcome, CancellationObservation, CancellationStage, CoverageDomainState, EffectId,
    EffectReceipt, EffectResult, EffectTermination, EvidenceAuthority, EvidenceCoverage,
    EvidenceIdentity, EvidencePacket, FreshnessState, IdempotencyKey, Omission, OperationReceipt,
    OperationTermination, PageState, ReconciliationState, RetainedSurfaceExecutionContextV1,
    RetainedSurfaceExecutionErrorV1, TemporalState, authority_receipt, effective_memory_deadline,
    measured_budget, now_micros,
};
use tracedecay_domain::{ComponentVersion, ManifestDigest, UtcMicros, canonical_sha256};
use tracedecay_memory_provider_registry::{
    ProviderCall, ProviderReply, TerminalCode, TerminalRecord,
};
use tracedecay_tool_catalog::{EffectClass, SortContractId};

use super::super::cognitive_recall::control_attribution::{
    RecallControlAttributionErrorV1, RetainedRecallControlScopeV1,
};
use super::super::observation_journey::control_dispatch::{
    JourneyControlDispatchErrorV1, JourneyControlNotDispatchedV1,
};
use super::authority::ControlAuthorityErrorV1;
use super::{
    CompletedProviderControlV1, ControlFailureStageV1, ControlFailureV1,
    ControlOperationIdentityV1, ControlResult, projection,
};

type OutcomeResult<T> = Result<T, RetainedSurfaceExecutionErrorV1>;

pub(super) fn assemble_outcome(
    context: &RetainedSurfaceExecutionContextV1<'_>,
    request: &ProviderControlRequestV1,
    result: ControlResult<CompletedProviderControlV1>,
    configuration_digest: &ManifestDigest,
) -> OutcomeResult<ApplicationOutcome<RetainedSurfaceResultV1>> {
    let mut completed = match result {
        Ok(completed) => completed,
        Err(failure) => completed_failure(request, failure)?,
    };
    // A successful no-effect reply is only representable as NoChange when its
    // actual operation receipt proves unchanged generation and operation state.
    // Retain the original identity on a malformed post-contact response.
    if retained_surface_operation_is_effect(request.operation())
        && completed.result.effect.state == ProviderControlEffectStateV1::None
        && matches!(
            completed.result.terminal,
            ProviderControlTerminalV1::Success | ProviderControlTerminalV1::SuccessZeroResults
        )
        && !verified_no_change(&completed.result)
    {
        // Retain the receipt the provider actually supplied before removing
        // malformed operation data; a host observation is not a provider receipt.
        let provider_receipt_digest = mutation_receipt(&completed.result.result)
            .map(|receipt| receipt.provider_receipt_digest.clone());
        completed.result.terminal = ProviderControlTerminalV1::ContractViolation;
        completed.result.effect = unknown_effect();
        completed.result.effect.provider_receipt_digest = provider_receipt_digest;
        completed.result.result = absent_operation_result(request);
        completed.result.warnings.truncate(31);
        completed.result.warnings.push("host: successful provider no-effect reply lacked operation-specific no-change evidence; reconcile the same operation".to_owned());
    }
    completed
        .result
        .validate_for(request)
        .map_err(invalid_outcome)?;
    if retained_surface_operation_is_effect(request.operation()) {
        effect_outcome(context, request, completed, configuration_digest)
    } else {
        read_outcome(context, request, completed.result)
    }
}

/// Used only with independently resolved state and an existing operation ID.
/// No fake ProviderReply or readiness receipt is constructed for offline work.
pub(super) fn result_after_failure(
    request: &ProviderControlRequestV1,
    state: &RetainedRecallControlScopeV1,
    identity: &ControlOperationIdentityV1,
    failure: &ControlFailureStageV1,
) -> ProviderControlResultV1 {
    let mutation = retained_surface_operation_is_effect(request.operation());
    let (terminal, possible_effect) = failure_terminal(failure, mutation);
    let received_terminal = match failure {
        ControlFailureStageV1::Projection { dispatched, .. }
            if dispatched.call.provider_id == state.provider_id
                && dispatched.call.registration_revision == state.registration_revision
                && dispatched.call.exact_scope == state.delivery_scope
                && dispatched.call.operation_id == identity.operation_id
                && dispatched.call.idempotency_key == identity.idempotency_key =>
        {
            validated_reply_terminal(&dispatched.call, &dispatched.reply)
        }
        _ => None,
    };
    let mut effect = if possible_effect {
        unknown_effect()
    } else {
        no_effect()
    };
    if possible_effect && let Some(received) = received_terminal {
        let evidence = received.committed_effect();
        effect.provider_receipt_digest = evidence.provider_receipt_sha256().map(str::to_owned);
        if let Some(action) = evidence.reconciliation_action() {
            effect.reconciliation_action = Some(action.to_owned());
        }
    }
    ProviderControlResultV1 {
        provider_id: state.provider_id.as_str().to_owned(),
        registration_revision: state.registration_revision,
        scope: projection::scope(&state.delivery_scope),
        operation_id: identity.operation_id.clone(),
        idempotency_key: mutation.then(|| identity.idempotency_key.clone()).flatten(),
        terminal,
        diagnostic_id: received_terminal
            .and_then(TerminalRecord::diagnostic_id)
            .map(str::to_owned),
        domain_detail: None,
        effect,
        result: absent_operation_result(request),
        warnings: vec![failure_notice(failure).to_owned()],
    }
}

/// Core terminal construction validates the provider effect shape separately
/// from operation data. Retain that evidence only for the call it answers.
fn validated_reply_terminal<'reply>(
    call: &ProviderCall,
    reply: &'reply ProviderReply,
) -> Option<&'reply TerminalRecord> {
    let terminal = &reply.terminal;
    (terminal.provider_id() == &call.provider_id
        && terminal.operation() == call.operation
        && terminal.operation_id() == call.operation_id
        && terminal.exact_scope_sha256() == call.exact_scope.exact_scope_sha256()
        && terminal.validate_duplicate_binding_for_call(call).is_ok())
    .then_some(terminal)
}

fn completed_failure(
    request: &ProviderControlRequestV1,
    failure: ControlFailureV1,
) -> OutcomeResult<CompletedProviderControlV1> {
    let ControlFailureV1 { stage } = failure;
    let result = match &stage {
        ControlFailureStageV1::Offline {
            state, identity, ..
        }
        | ControlFailureStageV1::Dispatch {
            state, identity, ..
        }
        | ControlFailureStageV1::DispatchWorker { state, identity } => {
            result_after_failure(request, state, identity, &stage)
        }
        ControlFailureStageV1::Projection { dispatched, .. } => {
            let state = RetainedRecallControlScopeV1 {
                provider_id: dispatched.call.provider_id.clone(),
                registration_revision: dispatched.call.registration_revision,
                delivery_scope: dispatched.call.exact_scope.clone(),
            };
            let identity = ControlOperationIdentityV1 {
                operation_id: dispatched.call.operation_id.clone(),
                idempotency_key: dispatched.call.idempotency_key.clone(),
            };
            result_after_failure(request, &state, &identity, &stage)
        }
        _ => return Err(pre_dispatch_error(stage)),
    };
    Ok(CompletedProviderControlV1 { result })
}

fn pre_dispatch_error(stage: ControlFailureStageV1) -> RetainedSurfaceExecutionErrorV1 {
    match stage {
        ControlFailureStageV1::Request(error) => error,
        ControlFailureStageV1::Attribution(error) => match error {
            RecallControlAttributionErrorV1::Invalid(_) => {
                RetainedSurfaceExecutionErrorV1::InvalidRequest
            }
            RecallControlAttributionErrorV1::NotFound
            | RecallControlAttributionErrorV1::MissingAuthority => {
                RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized
            }
            RecallControlAttributionErrorV1::Control(code) => pre_dispatch_control(code),
            error => RetainedSurfaceExecutionErrorV1::unavailable(error.to_string()),
        },
        ControlFailureStageV1::Authority(error) => match error {
            ControlAuthorityErrorV1::Ineligible(_) | ControlAuthorityErrorV1::ClaimMismatch(_) => {
                RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized
            }
            ControlAuthorityErrorV1::Control(code) => pre_dispatch_control(code),
            error => RetainedSurfaceExecutionErrorV1::unavailable(error.to_string()),
        },
        ControlFailureStageV1::Control(code) => pre_dispatch_control(code),
        ControlFailureStageV1::InvalidBinding(_) => {
            RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized
        }
        ControlFailureStageV1::MissingAuthority(detail)
        | ControlFailureStageV1::BlockingRead(detail) => {
            RetainedSurfaceExecutionErrorV1::unavailable(detail)
        }
        _ => invalid_field("post-contact provider result was not retained"),
    }
}

fn pre_dispatch_control(code: TerminalCode) -> RetainedSurfaceExecutionErrorV1 {
    match code {
        TerminalCode::Cancelled => {
            RetainedSurfaceExecutionErrorV1::Cancelled(CancellationStage::BeforeEffect)
        }
        TerminalCode::DeadlineExceeded => {
            RetainedSurfaceExecutionErrorV1::TimedOut(CancellationStage::BeforeEffect)
        }
        _ => {
            RetainedSurfaceExecutionErrorV1::unavailable("provider control stopped before dispatch")
        }
    }
}

fn failure_terminal(
    stage: &ControlFailureStageV1,
    mutation: bool,
) -> (ProviderControlTerminalV1, bool) {
    use ProviderControlTerminalV1 as Terminal;
    match stage {
        ControlFailureStageV1::Offline { .. } => (Terminal::ProviderUnavailable, false),
        ControlFailureStageV1::Projection { .. } => (Terminal::ContractViolation, mutation),
        ControlFailureStageV1::DispatchWorker { .. } => (
            if mutation {
                Terminal::EffectUnknown
            } else {
                Terminal::InternalFailure
            },
            mutation,
        ),
        ControlFailureStageV1::Control(code) => (terminal(*code), false),
        ControlFailureStageV1::Dispatch { error, .. } => match error {
            JourneyControlDispatchErrorV1::NotDispatched(reason) => (
                match reason {
                    JourneyControlNotDispatchedV1::Control(code) => terminal(*code),
                    JourneyControlNotDispatchedV1::ProviderMismatch
                    | JourneyControlNotDispatchedV1::RegistrationRevisionMismatch => {
                        Terminal::ScopeMismatch
                    }
                    JourneyControlNotDispatchedV1::UnsupportedOperation(_) => {
                        Terminal::CapabilityUnsupported
                    }
                    JourneyControlNotDispatchedV1::CompositionDisabled
                    | JourneyControlNotDispatchedV1::ProviderUnavailable
                    | JourneyControlNotDispatchedV1::Stopping => Terminal::ProviderUnavailable,
                    _ => Terminal::InvalidRequest,
                },
                false,
            ),
            JourneyControlDispatchErrorV1::Contract(_)
            | JourneyControlDispatchErrorV1::PayloadEncoding(_)
            | JourneyControlDispatchErrorV1::ReadinessRequest(_) => {
                (Terminal::InvalidRequest, false)
            }
            JourneyControlDispatchErrorV1::Readiness(_) => (Terminal::ProviderUnavailable, false),
            JourneyControlDispatchErrorV1::Fabric(_)
            | JourneyControlDispatchErrorV1::Isolation(_) => (
                if mutation {
                    Terminal::EffectUnknown
                } else {
                    Terminal::ProviderUnavailable
                },
                mutation,
            ),
        },
        ControlFailureStageV1::Request(error) => (
            match error {
                RetainedSurfaceExecutionErrorV1::InvalidRequest
                | RetainedSurfaceExecutionErrorV1::StructuralRefusal(_) => Terminal::InvalidRequest,
                RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized => Terminal::Unauthorized,
                RetainedSurfaceExecutionErrorV1::Conflict => Terminal::Conflict,
                RetainedSurfaceExecutionErrorV1::Stale => Terminal::StaleIdentity,
                RetainedSurfaceExecutionErrorV1::Unsupported => Terminal::CapabilityUnsupported,
                RetainedSurfaceExecutionErrorV1::Saturated => Terminal::CapacityExceeded,
                RetainedSurfaceExecutionErrorV1::ProfileResetRequired
                | RetainedSurfaceExecutionErrorV1::ProjectResetRequired => Terminal::ResetRequired,
                RetainedSurfaceExecutionErrorV1::Cancelled(_) => Terminal::Cancelled,
                RetainedSurfaceExecutionErrorV1::TimedOut(_) => Terminal::DeadlineExceeded,
                RetainedSurfaceExecutionErrorV1::Unavailable { .. } => {
                    Terminal::ProviderUnavailable
                }
                RetainedSurfaceExecutionErrorV1::PartialEffect { .. } => Terminal::PartialEffect,
                RetainedSurfaceExecutionErrorV1::ApplicationProblem(_) => Terminal::InvalidRequest,
            },
            matches!(error, RetainedSurfaceExecutionErrorV1::PartialEffect { .. }),
        ),
        ControlFailureStageV1::Authority(error) => (
            match error {
                ControlAuthorityErrorV1::Ineligible(_)
                | ControlAuthorityErrorV1::ClaimMismatch(_) => Terminal::Unauthorized,
                ControlAuthorityErrorV1::Control(code) => terminal(*code),
                ControlAuthorityErrorV1::Unavailable(_) => Terminal::ProviderUnavailable,
            },
            false,
        ),
        ControlFailureStageV1::Attribution(error) => (
            match error {
                RecallControlAttributionErrorV1::Invalid(_) => Terminal::InvalidRequest,
                RecallControlAttributionErrorV1::NotFound
                | RecallControlAttributionErrorV1::MissingAuthority => Terminal::Unauthorized,
                RecallControlAttributionErrorV1::Control(code) => terminal(*code),
                _ => Terminal::ProviderUnavailable,
            },
            false,
        ),
        ControlFailureStageV1::InvalidBinding(_) => (Terminal::ScopeMismatch, false),
        ControlFailureStageV1::MissingAuthority(_) | ControlFailureStageV1::BlockingRead(_) => {
            (Terminal::ProviderUnavailable, false)
        }
    }
}

fn failure_notice(stage: &ControlFailureStageV1) -> &'static str {
    match stage {
        ControlFailureStageV1::Offline { .. } => {
            "host: the producing provider registration is unavailable for this control"
        }
        ControlFailureStageV1::Projection { .. } => {
            "host: the provider reply failed control-result validation; possible effects remain unconfirmed"
        }
        ControlFailureStageV1::DispatchWorker { .. } => {
            "host: the control worker ended without a witnessed result"
        }
        _ => "host: the original bounded provider control did not produce an admissible result",
    }
}

fn terminal(code: TerminalCode) -> ProviderControlTerminalV1 {
    serde_json::from_value(serde_json::Value::String(code.as_wire().to_owned()))
        .unwrap_or(ProviderControlTerminalV1::ContractViolation)
}

fn absent_operation_result(request: &ProviderControlRequestV1) -> ProviderControlOperationResultV1 {
    match request {
        ProviderControlRequestV1::Health(_) => ProviderControlOperationResultV1::Health(None),
        ProviderControlRequestV1::Inspection(_) => {
            ProviderControlOperationResultV1::Inspection(None)
        }
        ProviderControlRequestV1::Maintenance(_) => {
            ProviderControlOperationResultV1::Maintenance(None)
        }
    }
}

fn no_effect() -> ProviderControlEffectV1 {
    ProviderControlEffectV1 {
        state: ProviderControlEffectStateV1::None,
        committed_boundary: None,
        state_generation_before: None,
        state_generation_after: None,
        committed_item_refs: Vec::new(),
        uncommitted_item_refs: Vec::new(),
        provider_receipt_digest: None,
        reconciliation_action: None,
        verification_digest: None,
        duplicate_of_idempotency_key: None,
        duplicate_of_operation_id: None,
    }
}

/// Host-observed uncertainty can have no provider reply and hence no provider
/// receipt. Received provider evidence is attached only after its own checks.
fn unknown_effect() -> ProviderControlEffectV1 {
    ProviderControlEffectV1 {
        state: ProviderControlEffectStateV1::Unknown,
        reconciliation_action: Some("reconcile_same_operation".to_owned()),
        ..no_effect()
    }
}

fn effect_outcome(
    context: &RetainedSurfaceExecutionContextV1<'_>,
    request: &ProviderControlRequestV1,
    completed: CompletedProviderControlV1,
    configuration_digest: &ManifestDigest,
) -> OutcomeResult<ApplicationOutcome<RetainedSurfaceResultV1>> {
    let result = completed.result;
    let cancellation_stage = if result.effect.state == ProviderControlEffectStateV1::None {
        CancellationStage::BeforeEffect
    } else {
        CancellationStage::EffectInFlight
    };
    let effect_receipt = {
        let termination = effect_termination(&result)?;
        let before = mutation_receipt(&result.result)
            .map(|receipt| receipt.state_generation_before)
            .or(result.effect.state_generation_before);
        let expected_state = digest(&(
            "tracedecay.provider-control.provider.expected.v1",
            &result.provider_id,
            result.registration_revision,
            &result.scope,
            before,
            request,
        ))?;
        let proof = matches!(
            result.effect.state,
            ProviderControlEffectStateV1::Committed
                | ProviderControlEffectStateV1::Duplicate
                | ProviderControlEffectStateV1::Partial
        )
        .then(|| {
            digest(&(
                "tracedecay.provider-control.provider.committed.v1",
                &result.provider_id,
                result.registration_revision,
                &result.scope,
                &result.operation_id,
                &result.idempotency_key,
                &result.effect,
                mutation_receipt(&result.result),
            ))
        })
        .transpose()?;
        let state = RetainedRecallControlScopeV1 {
            provider_id: tracedecay_memory_provider_registry::OwnedProviderId::new(
                &result.provider_id,
            )
            .map_err(invalid_outcome)?,
            registration_revision: result.registration_revision,
            delivery_scope: owned_scope(&result.scope)?,
        };
        receipt(
            context,
            request,
            &state,
            &ControlOperationIdentityV1 {
                operation_id: result.operation_id.clone(),
                idempotency_key: result.idempotency_key.clone(),
            },
            configuration_digest,
            expected_state,
            termination,
            proof,
        )?
    };
    if effect_receipt.operation != *context.operation.use_case_id()
        || effect_receipt.request_id != *context.request_context.request_id()
        || effect_receipt.actor != *context.request_context.actor()
        || effect_receipt.scope != *context.request_context.scope()
        || effect_receipt.idempotency_key.as_str()
            != result.idempotency_key.as_deref().unwrap_or("")
    {
        return Err(invalid_field("provider control outer receipt identity"));
    }
    let finished_at = now_micros();
    let reconciliation = match effect_receipt.outcome {
        EffectTermination::EffectUnknown | EffectTermination::Partial => {
            ReconciliationState::Pending
        }
        _ => ReconciliationState::Reconciled,
    };
    let payload = RetainedSurfaceResultV1::ProviderControl(result);
    let execution = execution_receipt(
        context,
        finished_at,
        effect_receipt.outcome.into(),
        cancellation_stage,
        &payload,
    )?;
    EffectResult::new(
        EffectId::new(format!(
            "effect.provider-control.{}",
            operation_id(&payload)?
        ))
        .map_err(invalid_outcome)?,
        EffectClass::Administrative,
        effect_receipt.idempotency_key.clone(),
        authority_receipt(context, finished_at)?,
        effect_receipt.expected_state.clone(),
        execution,
        reconciliation,
        effect_receipt,
        Some(payload),
    )
    .map(ApplicationOutcome::Effect)
    .map_err(invalid_outcome)
}

fn effect_termination(result: &ProviderControlResultV1) -> OutcomeResult<EffectTermination> {
    use ProviderControlEffectStateV1 as State;
    use ProviderControlTerminalV1 as Terminal;
    match result.effect.state {
        State::Unknown => Ok(EffectTermination::EffectUnknown),
        State::Partial => Ok(EffectTermination::Partial),
        State::Committed | State::Duplicate => Ok(if result.terminal == Terminal::Partial {
            EffectTermination::Partial
        } else {
            EffectTermination::Completed
        }),
        State::None => match result.terminal {
            Terminal::Success | Terminal::SuccessZeroResults if verified_no_change(result) => {
                Ok(EffectTermination::NoChange)
            }
            Terminal::Success | Terminal::SuccessZeroResults => Err(invalid_field(
                "successful provider control lacks no-change evidence",
            )),
            Terminal::Cancelled => Ok(EffectTermination::Cancelled),
            Terminal::DeadlineExceeded => Ok(EffectTermination::TimedOut),
            _ => Ok(EffectTermination::Failed),
        },
    }
}

fn verified_no_change(result: &ProviderControlResultV1) -> bool {
    let Some(receipt) = mutation_receipt(&result.result) else {
        return false;
    };
    if receipt.state_generation_before != receipt.state_generation_after
        || !result.effect.committed_item_refs.is_empty()
        || result.effect.committed_boundary.is_some()
    {
        return false;
    }
    match &result.result {
        ProviderControlOperationResultV1::Maintenance(Some(value)) => {
            (value.dry_run || (value.changed_items == 0 && value.removed_items == 0))
                && value.state_changed != Some(true)
                && !value.partial
        }
        _ => false,
    }
}

fn mutation_receipt(
    result: &ProviderControlOperationResultV1,
) -> Option<&ProviderControlMutationReceiptV1> {
    match result {
        ProviderControlOperationResultV1::Maintenance(Some(value)) => Some(&value.receipt),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    context: &RetainedSurfaceExecutionContextV1<'_>,
    request: &ProviderControlRequestV1,
    state: &RetainedRecallControlScopeV1,
    identity: &ControlOperationIdentityV1,
    configuration_digest: &ManifestDigest,
    expected_state: ManifestDigest,
    outcome: EffectTermination,
    committed_state: Option<ManifestDigest>,
) -> OutcomeResult<EffectReceipt> {
    let receipt = EffectReceipt {
        operation: context.operation.use_case_id().clone(),
        request_id: context.request_context.request_id().clone(),
        actor: context.request_context.actor().clone(),
        scope: context.request_context.scope().clone(),
        effect_class: EffectClass::Administrative,
        idempotency_key: IdempotencyKey::new(
            identity
                .idempotency_key
                .as_deref()
                .ok_or_else(|| invalid_field("provider effect idempotency identity"))?,
        )
        .map_err(invalid_outcome)?,
        input_digest: digest(&(
            "tracedecay.provider-control.input.v1",
            context.request_context.actor(),
            context.request_context.scope(),
            request,
            state.provider_id.as_str(),
            state.registration_revision,
            projection::scope(&state.delivery_scope),
            &identity.operation_id,
            &identity.idempotency_key,
        ))?,
        expected_state,
        policy_digest: context.request_context.grant().digest.clone(),
        configuration_digest: configuration_digest.clone(),
        catalog_digest: digest(&(
            "tracedecay.provider-control.catalog.v1",
            context.operation.capability_id(),
            context.operation.use_case_id(),
            context.operation.result_contract(),
        ))?,
        privacy_digest: digest(&(
            "tracedecay.provider-control.privacy.v1",
            context.request_context.scope(),
            context.request_context.grant().disclosure,
        ))?,
        outcome,
        committed_state,
        external_proof: None,
    };
    receipt.validate().map_err(invalid_outcome)?;
    Ok(receipt)
}

fn read_outcome(
    context: &RetainedSurfaceExecutionContextV1<'_>,
    request: &ProviderControlRequestV1,
    result: ProviderControlResultV1,
) -> OutcomeResult<ApplicationOutcome<RetainedSurfaceResultV1>> {
    let complete_initial_inspection = matches!(
        (request, &result.result),
        (
            ProviderControlRequestV1::Inspection(request),
            ProviderControlOperationResultV1::Inspection(Some(data)),
        ) if request.cursor.is_none()
            && data.coverage == ProviderControlInspectionCoverageV1::Complete
            && data.next_cursor.is_none()
            && data.redactions.is_empty()
            && matches!(
                result.terminal,
                ProviderControlTerminalV1::Success | ProviderControlTerminalV1::SuccessZeroResults
            )
    );
    let finished_at = now_micros();
    let operation = result.operation();
    let execution_terminal = read_termination(result.terminal);
    let payload = RetainedSurfaceResultV1::ProviderControl(result);
    let facts = payload
        .evidence_facts()
        .map_err(|_| invalid_field("provider read coverage"))?;
    let domain = facts.domain;
    let coverage = EvidenceCoverage {
        requested_domains: vec![domain],
        visited: facts.visited,
        eligible: facts.eligible,
        returned: facts.returned,
        completeness: facts.completeness,
        domains: vec![CoverageDomainState {
            domain,
            completeness: facts.completeness,
        }],
    };
    coverage.validate().map_err(invalid_outcome)?;
    let mut page = PageState::first_page(
        SortContractId::new(format!("sort.provider-control.{}.v1", operation.as_str()))
            .map_err(invalid_outcome)?,
        1,
        if complete_initial_inspection {
            Some(facts.returned)
        } else {
            facts.total
        },
        facts.returned,
    )
    .map_err(invalid_outcome)?;
    page.cursor = facts.next_cursor;
    let evidence_digest = digest(&payload)?;
    let mut temporal = TemporalState::current(finished_at);
    temporal.requested_at = context.observed_at;
    if execution_terminal != OperationTermination::Completed {
        temporal.freshness = FreshnessState::Unknown;
    }
    let execution = execution_receipt(
        context,
        finished_at,
        execution_terminal,
        CancellationStage::DuringRead,
        &payload,
    )?;
    Ok(ApplicationOutcome::Evidence(EvidencePacket {
        temporal,
        authority: authority_receipt(context, finished_at)?,
        evidence_authorities: vec![EvidenceAuthority {
            evidence_id: EvidenceIdentity::new(format!(
                "evidence.provider-control.{}",
                evidence_digest.as_str().trim_start_matches("sha256:")
            ))
            .map_err(invalid_outcome)?,
            source_kind: "host_observed_provider_control_outcome".to_owned(),
            producer: "tracedecay.host.provider-control".to_owned(),
            scope: context.request_context.scope().clone(),
            revision: ComponentVersion::new("provider-control.v1").map_err(invalid_outcome)?,
            horizon: None,
        }],
        coverage,
        omissions: facts
            .omissions
            .into_iter()
            .map(|item| Omission {
                domain,
                count: item.count,
                reason: item.reason,
            })
            .collect(),
        scores: Vec::new(),
        contributions: Vec::new(),
        page,
        execution,
        payload: Some(payload),
    }))
}

fn read_termination(terminal: ProviderControlTerminalV1) -> OperationTermination {
    use ProviderControlTerminalV1 as Terminal;
    match terminal {
        Terminal::Success | Terminal::SuccessZeroResults => OperationTermination::Completed,
        Terminal::Partial | Terminal::PartialEffect => OperationTermination::Partial,
        Terminal::Cancelled => OperationTermination::Cancelled,
        Terminal::DeadlineExceeded => OperationTermination::TimedOut,
        Terminal::ProviderUnavailable | Terminal::ScopeUnavailable => {
            OperationTermination::Unavailable
        }
        Terminal::EffectUnknown => OperationTermination::EffectUnknown,
        _ => OperationTermination::Failed,
    }
}

fn execution_receipt(
    context: &RetainedSurfaceExecutionContextV1<'_>,
    finished_at: UtcMicros,
    termination: OperationTermination,
    cancellation_stage: CancellationStage,
    payload: &RetainedSurfaceResultV1,
) -> OutcomeResult<OperationReceipt> {
    let receipt = OperationReceipt {
        started_at: context.observed_at,
        ended_at: finished_at,
        effective_deadline: effective_memory_deadline(context),
        cancellation: matches!(
            termination,
            OperationTermination::Cancelled | OperationTermination::TimedOut
        )
        .then_some(CancellationObservation {
            stage: cancellation_stage,
            observed_at: finished_at,
        }),
        budget: measured_budget(context.observed_at, finished_at, payload)?,
        termination,
    };
    receipt.validate().map_err(invalid_outcome)?;
    Ok(receipt)
}

fn owned_scope(
    scope: &ProviderControlScopeV1,
) -> OutcomeResult<tracedecay_memory_provider_registry::OwnedExactScope> {
    tracedecay_memory_provider_registry::OwnedExactScope::new(
        &scope.profile_id,
        &scope.project_id,
        &scope.repository_identity,
        &scope.worktree_identity,
        &scope.branch_identity,
        &scope.agent_session_id,
        &scope.resolved_scope_digest,
    )
    .map_err(invalid_outcome)
}

fn operation_id(payload: &RetainedSurfaceResultV1) -> OutcomeResult<&str> {
    let RetainedSurfaceResultV1::ProviderControl(result) = payload else {
        return Err(invalid_field("provider effect payload"));
    };
    Ok(&result.operation_id)
}

fn digest<T: Serialize>(value: &T) -> OutcomeResult<ManifestDigest> {
    canonical_sha256(value).map_err(invalid_outcome)
}

fn invalid_outcome(error: impl std::fmt::Display) -> RetainedSurfaceExecutionErrorV1 {
    RetainedSurfaceExecutionErrorV1::unavailable(format!(
        "provider control evidence could not be assembled: {error}"
    ))
}

fn invalid_field(field: &'static str) -> RetainedSurfaceExecutionErrorV1 {
    RetainedSurfaceExecutionErrorV1::unavailable(format!(
        "provider control evidence binding failed: {field}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tracedecay_contracts::{
        CancellationContext, CancellationSignal, CapabilityGrantId, CapabilityGrantSnapshot,
        Deadline, DisclosureClass, RequestContext, RequestId, ResolvedScope,
    };
    use tracedecay_domain::{ActorId, ProjectId, RefId, RepositoryId, WorktreeId};
    use tracedecay_memory_provider_registry::{
        CancellationToken, CanonicalPayload, CommittedEffectEvidence, FallbackDirective,
        OperationControl, OwnedExactScope, OwnedProviderId, OwnedVersionedId, ProviderCallParts,
        ProviderOperation,
    };

    fn state() -> RetainedRecallControlScopeV1 {
        RetainedRecallControlScopeV1 {
            provider_id: OwnedProviderId::new("tracedecay.native").unwrap(),
            registration_revision: 7,
            delivery_scope: OwnedExactScope::new(
                "profile.control",
                "project.control",
                "repository.control",
                "worktree.control",
                "refs/heads/main",
                "session.control",
                format!("sha256:{}", "f".repeat(64)),
            )
            .unwrap(),
        }
    }

    fn request() -> ProviderControlRequestV1 {
        ProviderControlRequestV1::Maintenance(ProviderMaintenanceRequestV1 {
            state: ProviderControlStateSelectorV1::CanonicalSession {
                provider_id: state().provider_id.as_str().to_owned(),
                registration_revision: 7,
                canonical_provider_id: "claude".to_owned(),
                session_id: "session.control".to_owned(),
            },
            task: ProviderControlMaintenanceTaskV1::Compact,
            maximum_items: 10,
            maximum_bytes: 65536,
            maximum_duration_millis: 1000,
            dry_run: false,
            resume_cursor: None,
        })
    }

    fn identity() -> ControlOperationIdentityV1 {
        ControlOperationIdentityV1 {
            operation_id: "01952a1e-5000-7000-8000-000000000001".to_owned(),
            idempotency_key: Some("b".repeat(64)),
        }
    }

    fn context(request: &ProviderControlRequestV1) -> (RequestContext, CancellationSignal) {
        let now = now_micros();
        let expiry = UtcMicros(now.0 + 30_000_000);
        let scope = ResolvedScope::new(
            ProjectId::new("project.control").unwrap(),
            RepositoryId::new("repository.control").unwrap(),
            WorktreeId::new("worktree.control").unwrap(),
            Some(RefId::new("refs/heads/main").unwrap()),
        )
        .unwrap();
        let operation =
            tracedecay_contracts::retained_surface_application_operation(request.operation())
                .unwrap();
        let grant = CapabilityGrantSnapshot::new(
            CapabilityGrantId::new("grant.control").unwrap(),
            1,
            ManifestDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ActorId::new("actor.issuer").unwrap(),
            UtcMicros(now.0 - 1),
            expiry,
            scope.clone(),
            BTreeSet::from([operation.capability_id().clone()]),
            BTreeSet::from([operation.use_case_id().clone()]),
            DisclosureClass::Evidence,
        )
        .unwrap();
        (
            RequestContext::new(
                ActorId::new("actor.control").unwrap(),
                scope,
                grant,
                RequestId::new("request.control").unwrap(),
                Deadline::new(expiry).unwrap(),
                CancellationContext::active("cancel.control").unwrap(),
            )
            .unwrap(),
            CancellationSignal::active("cancel.control").unwrap(),
        )
    }

    fn unchanged_result() -> ProviderControlResultV1 {
        let mut result = result_after_failure(
            &request(),
            &state(),
            &identity(),
            &ControlFailureStageV1::Control(TerminalCode::Cancelled),
        );
        result.terminal = ProviderControlTerminalV1::Success;
        result.warnings.clear();
        result.result =
            ProviderControlOperationResultV1::Maintenance(Some(ProviderMaintenanceResultV1 {
                task: ProviderControlMaintenanceTaskV1::Compact,
                dry_run: false,
                scanned_items: 1,
                changed_items: 0,
                removed_items: 0,
                proposed_changes: None,
                state_changed: Some(false),
                partial: false,
                resume_cursor: None,
                receipt: ProviderControlMutationReceiptV1 {
                    state_generation_before: 5,
                    state_generation_after: 5,
                    provider_receipt_digest: "c".repeat(64),
                },
            }));
        result
    }

    fn assembled(
        result: ProviderControlResultV1,
    ) -> tracedecay_contracts::EffectResult<RetainedSurfaceResultV1> {
        let request = request();
        let (request_context, cancellation_signal) = context(&request);
        let operation =
            tracedecay_contracts::retained_surface_application_operation(request.operation())
                .unwrap();
        let context = RetainedSurfaceExecutionContextV1 {
            request_context: &request_context,
            cancellation_signal: &cancellation_signal,
            operation: &operation,
            observed_at: now_micros(),
        };
        let output = assemble_outcome(
            &context,
            &request,
            Ok(CompletedProviderControlV1 { result }),
            &ManifestDigest::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
        )
        .unwrap();
        let ApplicationOutcome::Effect(output) = output else {
            panic!("provider mutation needs an effect outcome");
        };
        output
    }

    #[test]
    fn received_terminal_evidence_belongs_to_the_original_call() {
        let state = state();
        let identity = identity();
        let operation = ProviderOperation::Maintenance;
        let bytes = b"{}".to_vec();
        let call = ProviderCall::new(ProviderCallParts {
            operation,
            provider_id: state.provider_id,
            registration_revision: state.registration_revision,
            ready_receipt_sha256: "a".repeat(64),
            exact_scope: state.delivery_scope,
            request_id: "request.control".to_owned(),
            operation_id: identity.operation_id,
            expected_state_generation: 5,
            idempotency_key: identity.idempotency_key,
            control: OperationControl::new(i64::MAX, 1000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new("tracedecay.memory.provider.maintenance.v1").unwrap(),
                bytes.clone(),
                tracedecay_domain::canonical_text::sha256_hex(&bytes),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new(operation.capability_id()).unwrap()],
            extensions: Vec::new(),
        })
        .unwrap();
        let reply = |operation_id: &str| ProviderReply {
            terminal: TerminalRecord::new(
                operation,
                call.provider_id.clone(),
                TerminalCode::EffectUnknown,
                CommittedEffectEvidence::unknown("c".repeat(64), "reconcile.actual").unwrap(),
                FallbackDirective::forbidden(),
                operation_id,
                call.exact_scope.exact_scope_sha256(),
                Some("actual.provider.diagnostic".to_owned()),
            )
            .unwrap(),
            payload: None,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: 5,
        };
        let received = reply(&call.operation_id);
        let terminal = validated_reply_terminal(&call, &received).unwrap();
        assert_eq!(
            terminal.committed_effect().provider_receipt_sha256(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(
            terminal.committed_effect().reconciliation_action(),
            Some("reconcile.actual")
        );
        assert_eq!(terminal.diagnostic_id(), Some("actual.provider.diagnostic"));
        let another_operation = reply("01952a1e-5000-7000-8000-000000000002");
        assert!(validated_reply_terminal(&call, &another_operation).is_none());
    }

    #[test]
    fn accepted_identity_survives_known_refusals_without_inventing_possible_effects() {
        let cases = [
            (
                ControlFailureStageV1::Request(RetainedSurfaceExecutionErrorV1::Conflict),
                ProviderControlTerminalV1::Conflict,
            ),
            (
                ControlFailureStageV1::Authority(ControlAuthorityErrorV1::Ineligible(
                    "registered canonical session missing",
                )),
                ProviderControlTerminalV1::Unauthorized,
            ),
            (
                ControlFailureStageV1::InvalidBinding("producing scope"),
                ProviderControlTerminalV1::ScopeMismatch,
            ),
            (
                ControlFailureStageV1::Control(TerminalCode::Cancelled),
                ProviderControlTerminalV1::Cancelled,
            ),
            (
                ControlFailureStageV1::Control(TerminalCode::DeadlineExceeded),
                ProviderControlTerminalV1::DeadlineExceeded,
            ),
        ];
        for (failure, expected) in cases {
            let result = result_after_failure(&request(), &state(), &identity(), &failure);
            assert_eq!(result.operation_id, identity().operation_id);
            assert_eq!(result.idempotency_key, identity().idempotency_key);
            assert_eq!(result.terminal, expected);
            assert_eq!(result.effect.state, ProviderControlEffectStateV1::None);
            assert!(result.effect.provider_receipt_digest.is_none());
            let output = assembled(result);
            assert!(output.receipt.committed_state.is_none());
            assert!(output.receipt.external_proof.is_none());
            assert_eq!(output.reconciliation, ReconciliationState::Reconciled);
        }
    }

    #[test]
    fn effect_receipts_distinguish_proven_no_change_from_unknown_and_committed_work() {
        let unchanged = assembled(unchanged_result());
        assert_eq!(unchanged.receipt.outcome, EffectTermination::NoChange);
        assert_eq!(
            unchanged.execution.termination,
            OperationTermination::Completed
        );
        assert!(unchanged.receipt.committed_state.is_none());
        assert!(unchanged.receipt.external_proof.is_none());
        assert_eq!(unchanged.reconciliation, ReconciliationState::Reconciled);

        let unresolved = result_after_failure(
            &request(),
            &state(),
            &identity(),
            &ControlFailureStageV1::DispatchWorker {
                state: state(),
                identity: identity(),
            },
        );
        let unknown = assembled(unresolved);
        assert_eq!(unknown.receipt.outcome, EffectTermination::EffectUnknown);
        assert_eq!(unknown.reconciliation, ReconciliationState::Pending);
        assert!(unknown.receipt.committed_state.is_none());
        assert_eq!(
            unknown.idempotency_key.as_str(),
            identity().idempotency_key.as_deref().unwrap()
        );
        let Some(RetainedSurfaceResultV1::ProviderControl(retained)) = &unknown.payload else {
            panic!("host uncertainty retains the control identity and warning");
        };
        assert_eq!(retained.provider_id, state().provider_id.as_str());
        assert_eq!(
            retained.registration_revision,
            state().registration_revision
        );
        assert_eq!(retained.scope, projection::scope(&state().delivery_scope));
        assert_eq!(retained.operation_id, identity().operation_id);
        assert_eq!(retained.idempotency_key, identity().idempotency_key);
        assert_eq!(retained.effect.state, ProviderControlEffectStateV1::Unknown);
        assert!(retained.effect.provider_receipt_digest.is_none());
        assert!(retained.diagnostic_id.is_none());
        assert_eq!(
            retained.effect.reconciliation_action.as_deref(),
            Some("reconcile_same_operation")
        );
        assert!(
            retained
                .warnings
                .iter()
                .any(|warning| { warning.contains("ended without a witnessed result") })
        );

        let mut committed = unchanged_result();
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = &mut committed.result
        else {
            unreachable!()
        };
        data.changed_items = 1;
        data.state_changed = Some(true);
        data.receipt.state_generation_after = 6;
        committed.effect.state = ProviderControlEffectStateV1::Committed;
        committed.effect.state_generation_before = Some(5);
        committed.effect.state_generation_after = Some(6);
        committed.effect.committed_boundary = None;
        committed.effect.provider_receipt_digest = Some("c".repeat(64));
        committed.effect.verification_digest = Some("e".repeat(64));
        let committed = assembled(committed);
        assert_eq!(committed.receipt.outcome, EffectTermination::Completed);
        assert!(committed.receipt.committed_state.is_some());
        assert_ne!(
            committed.receipt.committed_state,
            unknown.receipt.committed_state
        );
    }

    #[test]
    fn malformed_success_after_contact_retains_operation_for_reconciliation() {
        let mut result = unchanged_result();
        result.diagnostic_id = Some("actual.provider.diagnostic".to_owned());
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = &mut result.result else {
            unreachable!()
        };
        data.partial = true;
        let output = assembled(result);
        assert_eq!(output.receipt.outcome, EffectTermination::EffectUnknown);
        assert_eq!(output.reconciliation, ReconciliationState::Pending);
        let Some(RetainedSurfaceResultV1::ProviderControl(result)) = output.payload else {
            panic!("typed provider outcome");
        };
        assert_eq!(
            result.terminal,
            ProviderControlTerminalV1::ContractViolation
        );
        assert_eq!(result.operation_id, identity().operation_id);
        assert_eq!(result.idempotency_key, identity().idempotency_key);
        assert_eq!(
            result.diagnostic_id.as_deref(),
            Some("actual.provider.diagnostic")
        );
        assert_eq!(result.effect.state, ProviderControlEffectStateV1::Unknown);
        assert_eq!(result.effect.provider_receipt_digest, Some("c".repeat(64)));
        assert_eq!(
            result.effect.reconciliation_action.as_deref(),
            Some("reconcile_same_operation")
        );
        assert!(result.effect.verification_digest.is_none());
        assert!(matches!(
            result.result,
            ProviderControlOperationResultV1::Maintenance(None)
        ));
    }

    #[test]
    fn maintenance_kernel_change_cannot_be_reported_as_no_change() {
        let mut result = unchanged_result();
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = &mut result.result else {
            unreachable!()
        };
        data.state_changed = Some(true);
        assert!(!verified_no_change(&result));
        let output = assembled(result);
        assert_eq!(output.receipt.outcome, EffectTermination::EffectUnknown);
        assert_eq!(output.reconciliation, ReconciliationState::Pending);
        assert!(output.receipt.committed_state.is_none());
    }

    #[test]
    fn partial_maintenance_page_is_surface_with_cursor_until_continuation_finishes() {
        let mut result = unchanged_result();
        result.terminal = ProviderControlTerminalV1::Partial;
        result.effect = ProviderControlEffectV1 {
            state: ProviderControlEffectStateV1::Partial,
            committed_boundary: Some("item.16".to_owned()),
            state_generation_before: Some(5),
            state_generation_after: Some(6),
            committed_item_refs: vec!["item.16".to_owned()],
            uncommitted_item_refs: vec!["item.17".to_owned()],
            provider_receipt_digest: Some("c".repeat(64)),
            reconciliation_action: Some("resume_from_item.16".to_owned()),
            verification_digest: Some("e".repeat(64)),
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        };
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = &mut result.result else {
            unreachable!()
        };
        data.scanned_items = 16;
        data.changed_items = 1;
        data.state_changed = Some(true);
        data.partial = true;
        data.resume_cursor = Some("ncm-maintenance:6:compact:17".to_owned());
        data.receipt.state_generation_after = 6;

        let output = assembled(result);
        assert_eq!(output.receipt.outcome, EffectTermination::Partial);
        assert_eq!(output.reconciliation, ReconciliationState::Pending);
        let Some(RetainedSurfaceResultV1::ProviderControl(result)) = output.payload else {
            panic!("partial maintenance payload")
        };
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = result.result else {
            panic!("partial maintenance result")
        };
        assert_eq!(
            data.resume_cursor.as_deref(),
            Some("ncm-maintenance:6:compact:17")
        );
        assert!(data.partial);

        // The next caller-issued request carries that cursor with a fresh
        // identity. Once the provider exhausts the page, the host retains the
        // final typed result and settles the effect normally.
        let mut final_result = unchanged_result();
        final_result.effect = ProviderControlEffectV1 {
            state: ProviderControlEffectStateV1::Committed,
            committed_boundary: None,
            state_generation_before: Some(5),
            state_generation_after: Some(6),
            committed_item_refs: vec!["item.17".to_owned()],
            uncommitted_item_refs: Vec::new(),
            provider_receipt_digest: Some("c".repeat(64)),
            reconciliation_action: None,
            verification_digest: Some("e".repeat(64)),
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        };
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = &mut final_result.result
        else {
            unreachable!()
        };
        data.scanned_items = 1;
        data.changed_items = 1;
        data.state_changed = Some(true);
        data.partial = false;
        data.resume_cursor = None;
        data.receipt.state_generation_after = 6;

        let output = assembled(final_result);
        assert_eq!(output.receipt.outcome, EffectTermination::Completed);
        assert_eq!(output.reconciliation, ReconciliationState::Reconciled);
        let Some(RetainedSurfaceResultV1::ProviderControl(result)) = output.payload else {
            panic!("final maintenance payload")
        };
        let ProviderControlOperationResultV1::Maintenance(Some(data)) = result.result else {
            panic!("final maintenance result")
        };
        assert!(!data.partial);
        assert!(data.resume_cursor.is_none());
    }

    #[test]
    fn multi_item_inspection_outcome_preserves_actual_page_and_cursor() {
        let maintenance = request();
        let mut request = ProviderControlRequestV1::Inspection(ProviderInspectionRequestV1 {
            state: maintenance.state_selector().clone(),
            selection: ProviderControlInspectionSelectorV1::CapabilityStatus,
            maximum_items: 2,
            maximum_bytes: 65_536,
            cursor: None,
        });
        let (request_context, cancellation_signal) = context(&request);
        let operation =
            tracedecay_contracts::retained_surface_application_operation(request.operation())
                .unwrap();
        let context = RetainedSurfaceExecutionContextV1 {
            request_context: &request_context,
            cancellation_signal: &cancellation_signal,
            operation: &operation,
            observed_at: now_micros(),
        };
        let configuration = ManifestDigest::new(format!("sha256:{}", "d".repeat(64))).unwrap();
        let mut result = result_after_failure(
            &request,
            &state(),
            &identity(),
            &ControlFailureStageV1::Control(TerminalCode::Cancelled),
        );
        for partial in [false, true] {
            result.terminal = if partial {
                ProviderControlTerminalV1::Partial
            } else {
                ProviderControlTerminalV1::Success
            };
            result.warnings.clear();
            let cursor = partial.then(|| "cursor.capabilities.2".to_owned());
            result.result =
                ProviderControlOperationResultV1::Inspection(Some(ProviderInspectionResultV1 {
                    selection: ProviderControlInspectionSelectorV1::CapabilityStatus,
                    items: ProviderControlInspectionItemsV1::CapabilityStatus(vec![
                        ProviderControlCapabilityStatusV1 {
                            capability_id: "memory.recall".to_owned(),
                            state: "supported".to_owned(),
                        },
                        ProviderControlCapabilityStatusV1 {
                            capability_id: "memory.inspection".to_owned(),
                            state: "supported".to_owned(),
                        },
                    ]),
                    coverage: if partial {
                        ProviderControlInspectionCoverageV1::Partial
                    } else {
                        ProviderControlInspectionCoverageV1::Complete
                    },
                    next_cursor: cursor.clone(),
                    redactions: Vec::new(),
                    state_generation: 5,
                }));
            let output = assemble_outcome(
                &context,
                &request,
                Ok(CompletedProviderControlV1 {
                    result: result.clone(),
                }),
                &configuration,
            )
            .unwrap();
            let ApplicationOutcome::Evidence(output) = output else {
                panic!("inspection evidence")
            };
            assert_eq!(output.coverage.returned, 2);
            assert_eq!(output.page.returned, 2);
            assert_eq!(output.page.sort_revision, 1);
            assert_eq!(output.page.total, (!partial).then_some(2));
            assert_eq!(
                output
                    .page
                    .cursor
                    .as_ref()
                    .and_then(|cursor| cursor.as_opaque())
                    .map(|cursor| cursor.as_str()),
                cursor.as_deref()
            );
            assert_eq!(
                output.payload,
                Some(RetainedSurfaceResultV1::ProviderControl(result.clone()))
            );
        }
        let ProviderControlRequestV1::Inspection(inspection) = &mut request else {
            unreachable!()
        };
        inspection.cursor = Some("cursor.capabilities.2".to_owned());
        result.terminal = ProviderControlTerminalV1::Success;
        let ProviderControlOperationResultV1::Inspection(Some(data)) = &mut result.result else {
            unreachable!()
        };
        data.coverage = ProviderControlInspectionCoverageV1::Complete;
        data.next_cursor = None;
        let resumed = assemble_outcome(
            &context,
            &request,
            Ok(CompletedProviderControlV1 {
                result: result.clone(),
            }),
            &configuration,
        )
        .unwrap();
        let ApplicationOutcome::Evidence(resumed) = resumed else {
            panic!("resumed inspection evidence")
        };
        assert_eq!(resumed.coverage.returned, 2);
        assert_eq!(resumed.page.returned, 2);
        assert_eq!(resumed.page.sort_revision, 1);
        assert_eq!(resumed.page.total, None);
        assert!(resumed.page.cursor.is_none());
        assert_eq!(
            resumed.payload,
            Some(RetainedSurfaceResultV1::ProviderControl(result.clone()))
        );

        let ProviderControlRequestV1::Inspection(inspection) = &mut request else {
            unreachable!()
        };
        inspection.maximum_items = 1;
        assert!(
            assemble_outcome(
                &context,
                &request,
                Ok(CompletedProviderControlV1 { result }),
                &configuration
            )
            .is_err(),
            "the actual inspection request limit still applies"
        );
    }
}
