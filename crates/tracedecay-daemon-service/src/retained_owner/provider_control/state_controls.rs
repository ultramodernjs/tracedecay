//! State controls resolved through actual canonical or retained host authority.

use serde_json::{Value, json};
use tracedecay_contracts::retained_surfaces::{
    ProviderControlInspectionSelectorV1, ProviderHealthRequestV1, ProviderInspectionRequestV1,
    ProviderMaintenanceRequestV1,
};

use super::{
    CompletedProviderControlV1, ControlInvocationV1, ControlResult,
    PROVIDER_CONTROL_POLICY_REVISION_V1, ProjectProviderControlPortV1,
    projection::{HostControlEvidence, InspectionEvidenceV1},
};

pub(super) async fn health(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderHealthRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let dispatched = port
        .dispatch(
            invocation,
            &state,
            json!({"requested_checks": request.requested_checks}),
            &invocation.identity,
            None,
        )
        .await?;
    port.project(invocation, dispatched, HostControlEvidence::Health)
}

pub(super) async fn maintenance(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderMaintenanceRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let dispatched = port
        .dispatch(
            invocation,
            &state,
            maintenance_operation_body(request),
            &invocation.identity,
            None,
        )
        .await?;
    port.project(invocation, dispatched, HostControlEvidence::Maintenance)
}

/// Builds the provider-local maintenance body without changing its caller
/// identity. The cursor is part of the operation semantics, so it must remain
/// in the body while the mutation key stays bound to the caller request ID.
/// Providers can therefore replay the exact page, reject a changed cursor
/// under the same key, and accept a continuation issued with a fresh identity.
pub(super) fn maintenance_operation_body(request: &ProviderMaintenanceRequestV1) -> Value {
    json!({
        "task": request.task,
        "maximum_items": request.maximum_items,
        "maximum_bytes": request.maximum_bytes,
        "maximum_duration_millis": request.maximum_duration_millis,
        "dry_run": request.dry_run,
        "resume_cursor": request.resume_cursor,
    })
}

fn inspection_body(request: &ProviderInspectionRequestV1, selector: Value) -> Value {
    json!({
        "view": request.selection.view(),
        "selector": selector,
        "maximum_items": request.maximum_items,
        "maximum_bytes": request.maximum_bytes,
        "redaction_policy_revision": PROVIDER_CONTROL_POLICY_REVISION_V1,
        "cursor": request.cursor,
    })
}

pub(super) async fn inspection(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderInspectionRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let (selector, evidence) = match &request.selection {
        ProviderControlInspectionSelectorV1::StateSummary => {
            (json!({}), InspectionEvidenceV1::StateSummary)
        }
        ProviderControlInspectionSelectorV1::CapabilityStatus => {
            (json!({}), InspectionEvidenceV1::CapabilityStatus)
        }
        // These are provider outcome-query keys inside the authorized
        // namespace. They confer no host receipt or mutation authority.
        ProviderControlInspectionSelectorV1::MaintenanceReceipt {
            operation_id,
            idempotency_key,
        } => (
            json!({"operation_id": operation_id, "idempotency_key": idempotency_key}),
            InspectionEvidenceV1::MaintenanceReceipt {
                operation_id,
                idempotency_key,
            },
        ),
    };
    let dispatched = port
        .dispatch(
            invocation,
            &state,
            inspection_body(request, selector),
            &invocation.identity,
            None,
        )
        .await?;
    port.project(
        invocation,
        dispatched,
        HostControlEvidence::Inspection(evidence),
    )
}
