//! State controls resolved through actual canonical or retained host authority.

use serde_json::{Value, json};
use tracedecay_contracts::retained_surfaces::{
    ProviderControlInspectionSelectorV1, ProviderControlSourceSelectorV1, ProviderHealthRequestV1,
    ProviderInspectionRequestV1, ProviderMaintenanceRequestV1,
};
use tracedecay_memory_provider_registry::{LifecycleTarget, LifecycleTargetReference};

use super::{
    AuthorizedControlSourceV1, CompletedProviderControlV1, ControlFailureStageV1, ControlFailureV1,
    ControlInvocationV1, ControlResult, PROVIDER_CONTROL_POLICY_REVISION_V1,
    ProjectProviderControlPortV1, ResolvedControlStateV1,
    projection::{HostControlEvidence, InspectionEvidenceV1, lifecycle_target_wire},
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

fn inspection_body(
    request: &ProviderInspectionRequestV1,
    selector: Value,
    target: Option<Value>,
) -> Value {
    let mut body = json!({
        "view": request.selection.view(),
        "selector": selector,
        "maximum_items": request.maximum_items,
        "maximum_bytes": request.maximum_bytes,
        "redaction_policy_revision": PROVIDER_CONTROL_POLICY_REVISION_V1,
        "cursor": request.cursor,
    });
    if let Some(target) = target {
        body["target"] = target;
    }
    body
}

fn source_reference(target: &LifecycleTarget) -> ControlResult<&str> {
    match &target.reference {
        LifecycleTargetReference::StableMemoryRef(value)
        | LifecycleTargetReference::RetainedSourceLocator(value) => Ok(value),
        LifecycleTargetReference::RecallTraceRef(_)
        | LifecycleTargetReference::ContextPackItemRef(_) => Err(ControlFailureV1::new(
            ControlFailureStageV1::InvalidBinding("retained source reference"),
        )),
    }
}

async fn source_for_inspection(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    state: &ResolvedControlStateV1,
    selector: &ProviderControlSourceSelectorV1,
) -> ControlResult<AuthorizedControlSourceV1> {
    // Inspection may explain a tombstone, but still requires fresh original
    // source authorization and exactly the separately selected provider state.
    let source = port
        .resolve_source(selector, true, &invocation.control)
        .await?;
    port.require_same_state(state, &source)?;
    Ok(source)
}

pub(super) async fn inspection(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderInspectionRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    match &request.selection {
        ProviderControlInspectionSelectorV1::StateSummary
        | ProviderControlInspectionSelectorV1::CapabilityStatus => {
            let state = port.resolve_state(&request.state, invocation).await?;
            let dispatched = port
                .dispatch(
                    invocation,
                    &state,
                    inspection_body(request, json!({}), None),
                    &invocation.identity,
                    None,
                )
                .await?;
            let evidence = if matches!(
                request.selection,
                ProviderControlInspectionSelectorV1::StateSummary
            ) {
                InspectionEvidenceV1::StateSummary
            } else {
                InspectionEvidenceV1::CapabilityStatus
            };
            port.project(
                invocation,
                dispatched,
                HostControlEvidence::Inspection(evidence),
            )
        }
        ProviderControlInspectionSelectorV1::SourceInfluence { source: selector }
        | ProviderControlInspectionSelectorV1::Trace { source: selector }
        | ProviderControlInspectionSelectorV1::DeliveryReceipt { source: selector } => {
            let state = port.resolve_state(&request.state, invocation).await?;
            let source = source_for_inspection(port, invocation, &state, selector).await?;
            let delivery_key = if matches!(
                request.selection,
                ProviderControlInspectionSelectorV1::DeliveryReceipt { .. }
            ) {
                let settled = port
                    .authority()?
                    .resolve_settled_observation(&source.authorized, &invocation.control)
                    .await?;
                if settled.source.retained.scope != state.retained {
                    return Err(ControlFailureV1::new(
                        ControlFailureStageV1::InvalidBinding("settled delivery scope"),
                    ));
                }
                Some(settled.receipt.idempotency_key.as_str().to_owned())
            } else {
                None
            };
            let selected = match &request.selection {
                ProviderControlInspectionSelectorV1::SourceInfluence { .. } => {
                    let stable = source_reference(&source.target)?;
                    json!({"stable_memory_ref": stable, "source_key": source.target.source.source_key})
                }
                ProviderControlInspectionSelectorV1::Trace { .. } => {
                    let stable = source_reference(&source.target)?;
                    json!({"stable_memory_ref": stable})
                }
                ProviderControlInspectionSelectorV1::DeliveryReceipt { .. } => {
                    let stable = source_reference(&source.target)?;
                    json!({"idempotency_key": delivery_key.as_deref(), "stable_memory_ref": stable})
                }
                _ => {
                    return Err(ControlFailureV1::new(
                        ControlFailureStageV1::InvalidBinding("source inspection selection"),
                    ));
                }
            };
            let source_evidence = source.projection_evidence(selector)?;
            let target = matches!(
                &source.target.reference,
                LifecycleTargetReference::RetainedSourceLocator(_)
            )
            .then(|| lifecycle_target_wire(source_evidence))
            .transpose()
            .map_err(|error| ControlFailureV1::new(ControlFailureStageV1::InvalidBinding(error)))?;
            let source_grant = target.as_ref().map(|_| source.authorized.grant.clone());
            let dispatched = port
                .dispatch_with_source_grant(
                    invocation,
                    &state,
                    inspection_body(request, selected, target),
                    &invocation.identity,
                    None,
                    source_grant,
                )
                .await?;
            // Re-read current disposition after provider contact. If authority
            // changed, retain the actual reply for truthful outer completion.
            let current = match source_for_inspection(port, invocation, &state, selector).await {
                Ok(current) if current.target == source.target => current,
                _ => {
                    return Err(ControlFailureV1::new(ControlFailureStageV1::Projection {
                        field: "current inspection source authority",
                        dispatched,
                    }));
                }
            };
            let resolved = current.projection_evidence(selector)?;
            let evidence = match &request.selection {
                ProviderControlInspectionSelectorV1::SourceInfluence { .. } => {
                    InspectionEvidenceV1::SourceInfluence(resolved)
                }
                ProviderControlInspectionSelectorV1::Trace { .. } => {
                    InspectionEvidenceV1::Trace(resolved)
                }
                ProviderControlInspectionSelectorV1::DeliveryReceipt { .. } => {
                    let Some(idempotency_key) = delivery_key.as_deref() else {
                        return Err(ControlFailureV1::new(ControlFailureStageV1::Projection {
                            field: "settled delivery identity",
                            dispatched,
                        }));
                    };
                    InspectionEvidenceV1::DeliveryReceipt {
                        source: resolved,
                        idempotency_key,
                    }
                }
                _ => {
                    return Err(ControlFailureV1::new(ControlFailureStageV1::Projection {
                        field: "source inspection selection",
                        dispatched,
                    }));
                }
            };
            port.project(
                invocation,
                dispatched,
                HostControlEvidence::Inspection(evidence),
            )
        }
        ProviderControlInspectionSelectorV1::MaintenanceReceipt {
            operation_id,
            idempotency_key,
        } => {
            let state = port.resolve_state(&request.state, invocation).await?;
            // These are provider outcome-query keys inside the authorized
            // namespace. They confer no host receipt or mutation authority.
            let dispatched = port
                .dispatch(
                    invocation,
                    &state,
                    inspection_body(
                        request,
                        json!({"operation_id": operation_id, "idempotency_key": idempotency_key}),
                        None,
                    ),
                    &invocation.identity,
                    None,
                )
                .await?;
            port.project(
                invocation,
                dispatched,
                HostControlEvidence::Inspection(InspectionEvidenceV1::MaintenanceReceipt {
                    operation_id,
                    idempotency_key,
                }),
            )
        }
        ProviderControlInspectionSelectorV1::SnapshotMetadata { snapshot_ref } => {
            // Historical artifact metadata has its own host origin. No live
            // provider mount, readiness handshake, or provider reply is involved.
            let state = port
                .resolve_retained_state(&request.state, invocation)
                .await?;
            let ledger = port.ledger()?;
            let retained = state.clone();
            let reference = snapshot_ref.clone();
            let control = invocation.control.clone();
            let artifact = invocation
                .run_controlled(async move {
                    invocation
                        .runtime
                        .spawn_blocking(move || {
                            super::portability::read_snapshot_artifact(
                                &ledger, &retained, &reference, &control,
                            )
                        })
                        .await
                        .map_err(|_| {
                            ControlFailureV1::new(ControlFailureStageV1::BlockingRead(
                                "snapshot artifact",
                            ))
                        })?
                        .map_err(super::portability::control_failure)
                })
                .await?;
            if state.provider_id != artifact.export_scope().provider_id
                || state.registration_revision != artifact.export_scope().registration_revision
            {
                return Err(ControlFailureV1::new(
                    ControlFailureStageV1::InvalidBinding("selected snapshot export owner"),
                ));
            }
            let inventory = invocation
                .run_controlled(async {
                    port.authority()?
                        .authorize_retained_source_inventory(
                            &state,
                            artifact.original_sources(),
                            &invocation.control,
                        )
                        .await
                        .map_err(ControlFailureV1::from)
                })
                .await?;
            invocation.check()?;
            let result = super::projection::project_host_snapshot_metadata(
                invocation.context.request_context,
                request,
                &state,
                &invocation.identity,
                &artifact,
                &inventory,
            )
            .map_err(|field| ControlFailureV1::new(ControlFailureStageV1::InvalidBinding(field)))?;
            Ok(CompletedProviderControlV1 {
                result,
                host_receipt: None,
            })
        }
    }
}
