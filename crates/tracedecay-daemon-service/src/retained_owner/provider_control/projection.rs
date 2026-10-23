//! Pure projection of actual dispatch evidence into retained control results.
//!
//! This module grants no authority and performs no I/O. The caller resolves
//! retained selectors, fresh source disposition, and accepted commands before
//! dispatch. A rejected result keeps the actual reply for reconciliation.
use std::{collections::BTreeSet, fmt};

use chrono::DateTime;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tracedecay_contracts::{RequestContext, retained_surfaces::*};
use tracedecay_domain::{canonical_text::sha256_hex, encode_lowercase_hex, research::UtcMicros};
use tracedecay_memory_provider_registry::{
    CanonicalPayload, CommittedEffectState, CurrentSourceDisposition, FallbackDirective,
    LifecycleTarget, LifecycleTargetReference, OriginalSourceIdentity, OwnedExactScope,
    OwnedProviderId, OwnedVersionedId, ProviderCall, ProviderLimits, ProviderOperation,
    ProviderReply, SourceAttribution, SourceDisposition, TerminalCode,
};

use tracedecay_rusqlite_runtime::recall_admission::control_attribution::{
    RecallControlTraceRefV1, RetainedRecallControlScopeV1,
};

use super::super::{
    observation_journey::control_dispatch::JourneyControlDispatchReplyV1,
    provider_history::source_attribution_json,
};
use super::{
    ControlOperationIdentityV1,
    authority::AuthorizedCanonicalControlInventoryV1,
    feedback_receipt::{AcceptedDeletionCommandV1, AcceptedFeedbackAssertionV1},
    portability::{
        HostSnapshotCleanupResultV1, HostSnapshotCleanupStateV1, RetainedSnapshotArtifactV1,
    },
};

pub(super) type ProjectionResult<T> = Result<T, &'static str>;

pub(super) struct ProviderControlProjectionInput<'host, 'reply> {
    pub(super) context: &'host RequestContext,
    pub(super) request: &'host ProviderControlRequestV1,
    pub(super) dispatched: &'reply JourneyControlDispatchReplyV1,
}

/// All references come from host resolution, never the returned provider JSON.
#[derive(Clone, Copy)]
pub(super) struct ResolvedControlSourceV1<'a> {
    pub(super) selector: &'a ProviderControlSourceSelectorV1,
    pub(super) target: &'a LifecycleTarget,
    pub(super) original_attribution: &'a SourceAttribution,
    /// Actual current canonical disposition combined with the provider fence.
    pub(super) current_disposition: &'a CurrentSourceDisposition,
}

#[derive(Clone, Copy)]
pub(super) struct RetainedSnapshotV1<'a> {
    pub(super) snapshot_ref: &'a str,
    /// The actual canonical snapshot carrier: {identity, bytes, sources}.
    pub(super) carrier: &'a CanonicalPayload,
}

#[derive(Clone, Copy)]
pub(super) struct ResolvedObservationV1<'a> {
    pub(super) receipt_ref: &'a str,
    /// The entire admitted canonical observation envelope.
    pub(super) observation: &'a CanonicalPayload,
}

/// Public immutable host batch addresses stay separate from canonical receipt IDs.
#[derive(Clone, Copy)]
pub(super) struct ReplayEvidenceV1<'a> {
    pub(super) observation_batch_refs: &'a [String],
    pub(super) observations: &'a [ResolvedObservationV1<'a>],
}

pub(super) enum CorrectionEvidenceV1<'a> {
    Metadata,
    Replacement {
        source: ResolvedControlSourceV1<'a>,
        observation: &'a CanonicalPayload,
    },
    RestrictScope {
        selector: &'a ProviderControlStateSelectorV1,
        exact_scope: &'a OwnedExactScope,
    },
}

pub(super) enum InspectionEvidenceV1<'a> {
    StateSummary,
    SourceInfluence(ResolvedControlSourceV1<'a>),
    Trace(ResolvedControlSourceV1<'a>),
    DeliveryReceipt {
        source: ResolvedControlSourceV1<'a>,
        idempotency_key: &'a str,
    },
    MaintenanceReceipt {
        operation_id: &'a str,
        idempotency_key: &'a str,
    },
    CapabilityStatus,
}

pub(super) enum HostControlEvidence<'a> {
    Feedback {
        source: ResolvedControlSourceV1<'a>,
        assertion: &'a AcceptedFeedbackAssertionV1,
    },
    Correction {
        source: ResolvedControlSourceV1<'a>,
        change: CorrectionEvidenceV1<'a>,
    },
    DeleteBySource {
        source: ResolvedControlSourceV1<'a>,
        command: &'a AcceptedDeletionCommandV1,
        intent: &'a ProviderControlDeletionIntentV1,
        cleanup: &'a HostSnapshotCleanupResultV1,
    },
    Health,
    Inspection(InspectionEvidenceV1<'a>),
    Maintenance,
    SnapshotExport(Option<RetainedSnapshotV1<'a>>),
    SnapshotRestore(RetainedSnapshotV1<'a>),
    Replay(ReplayEvidenceV1<'a>),
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

/// The same actual cleanup mapping is used for post-fence provider failures.
/// A partial host removal never establishes the provider erasure postcondition.
pub(super) fn host_snapshot_cleanup(
    cleanup: &HostSnapshotCleanupResultV1,
) -> ProviderControlHostSnapshotCleanupV1 {
    ProviderControlHostSnapshotCleanupV1 {
        state: match cleanup.state {
            HostSnapshotCleanupStateV1::NotRequested => {
                ProviderControlHostSnapshotCleanupStateV1::NotRequested
            }
            HostSnapshotCleanupStateV1::Complete => {
                ProviderControlHostSnapshotCleanupStateV1::Complete
            }
            HostSnapshotCleanupStateV1::Partial => {
                ProviderControlHostSnapshotCleanupStateV1::Partial
            }
            HostSnapshotCleanupStateV1::Unverifiable => {
                ProviderControlHostSnapshotCleanupStateV1::Unverifiable
            }
        },
        removed_snapshot_refs: cleanup.removed_snapshot_refs.clone(),
        matched_count: cleanup.matched_count,
        unverifiable_count: cleanup.unverifiable_count,
    }
}

/// Reads immutable metadata from an already-verified host artifact. The authority
/// owner freshly resolved the selected namespace and complete canonical inventory;
/// this helper never mounts, probes, or manufactures a provider runtime reply.
pub(super) fn project_host_snapshot_metadata(
    context: &RequestContext,
    request: &ProviderInspectionRequestV1,
    state: &RetainedRecallControlScopeV1,
    operation_identity: &ControlOperationIdentityV1,
    artifact: &RetainedSnapshotArtifactV1,
    inventory: &AuthorizedCanonicalControlInventoryV1,
) -> ProjectionResult<ProviderControlResultV1> {
    context.validate().map_err(|_| "authenticated context")?;
    require(
        artifact.export_scope() == state && &inventory.scope == state,
        "snapshot export owner binding",
    )?;
    validate_resolved_state_selector(
        &request.state,
        &state.provider_id,
        state.registration_revision,
        &state.delivery_scope,
    )?;
    require(
        matches!(&request.selection, ProviderControlInspectionSelectorV1::SnapshotMetadata { snapshot_ref } if snapshot_ref == artifact.snapshot_ref())
            && request.cursor.is_none()
            && request.maximum_items >= 1
            && operation_identity.idempotency_key.is_none(),
        "host snapshot metadata request",
    )?;
    inventory
        .checkpoint
        .validate_for(&state.delivery_scope)
        .map_err(|_| "snapshot current disposition checkpoint")?;
    let carrier = payload(artifact.carrier())?;
    closed(&carrier, &["identity", "bytes", "sources"])?;
    let identity = snapshot_identity(field(&carrier, "identity")?)?;
    let bytes: Vec<u8> = decode(field(&carrier, "bytes")?, "snapshot bytes")?;
    require(
        &identity == artifact.identity()
            && identity.provider_id == state.provider_id.as_str()
            && identity.exact_scope_digest == state.delivery_scope.exact_scope_sha256()
            && identity.byte_length == bytes.len() as u64
            && identity.byte_length <= MAX_PROVIDER_CONTROL_SNAPSHOT_BYTES
            && identity.content_sha256 == digest(&bytes),
        "host snapshot carrier binding",
    )?;
    require(
        inventory.sources().len() == artifact.original_sources().len(),
        "snapshot canonical inventory count",
    )?;
    let mut sources = Vec::with_capacity(artifact.original_sources().len());
    for (current, original) in inventory.sources().iter().zip(artifact.original_sources()) {
        let original = original
            .to_owned_attribution()
            .map_err(|_| "snapshot original attribution")?;
        current
            .current_disposition
            .validate()
            .map_err(|_| "snapshot source disposition")?;
        require(
            current.attribution == original
                && !matches!(
                    current.current_disposition.state,
                    SourceDisposition::Deleted
                        | SourceDisposition::Redacted
                        | SourceDisposition::Expired
                        | SourceDisposition::Unknown
                ),
            "snapshot fresh source visibility",
        )?;
        sources.push(source_attribution_json(&original)
            .map_err(|_| "snapshot source identity encoding")?["source"].clone());
    }
    eq_field(&carrier, "sources", &Value::Array(sources))?;
    let result = ProviderControlResultV1 {
        provider_id: state.provider_id.as_str().to_owned(),
        registration_revision: artifact.export_scope().registration_revision,
        scope: scope(&state.delivery_scope),
        operation_id: operation_identity.operation_id.clone(),
        idempotency_key: None,
        terminal: ProviderControlTerminalV1::Success,
        diagnostic_id: None,
        domain_detail: None,
        effect: ProviderControlEffectV1 {
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
        },
        result: ProviderControlOperationResultV1::Inspection(Some(ProviderInspectionResultV1 {
            selection: request.selection.clone(),
            evidence_origin: ProviderControlInspectionEvidenceOriginV1::HostSnapshotArtifact {
                snapshot_ref: artifact.snapshot_ref().to_owned(),
                export_registration_revision: artifact.export_scope().registration_revision,
            },
            items: ProviderControlInspectionItemsV1::SnapshotMetadata(vec![identity]),
            coverage: ProviderControlInspectionCoverageV1::Complete,
            next_cursor: None,
            redactions: Vec::new(),
            state_generation: None,
        })),
        warnings: Vec::new(),
    };
    result
        .validate_for(&ProviderControlRequestV1::Inspection(request.clone()))
        .map_err(|_| "host snapshot metadata result invariants")?;
    Ok(result)
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
    if let Some(selector) = input.request.state_selector() {
        validate_state_selector(selector, call)?;
    }
    let response = reply.payload.as_ref().map(payload).transpose()?;
    let mut warnings = reply.warnings.clone();
    if let Some(value) = &response {
        let payload_warnings: Vec<String> = decode(field(value, "warnings")?, "payload warnings")?;
        warnings.extend(payload_warnings);
        require(warnings.len() <= 32, "aggregate warnings")?;
        validate_optional_receipt(value, call, reply)?;
    }
    let result = match (input.request, evidence) {
        (
            ProviderControlRequestV1::Feedback(public),
            HostControlEvidence::Feedback { source, assertion },
        ) => {
            let target = bind_source(source, &public.source, call)?;
            require(
                assertion
                    .matches(
                        input.context,
                        public,
                        source.target,
                        source.original_attribution,
                    )
                    .map_err(|_| "feedback assertion binding")?,
                "feedback assertion binding",
            )?;
            require(
                call.operation_id == assertion.operation_id()
                    && call.idempotency_key.as_deref() == Some(assertion.idempotency_key()),
                "feedback accepted identity",
            )?;
            eq_field(&request, "target", &target)?;
            eq_field(&request, "signal", &wire(&public.signal)?)?;
            eq_field(&request, "weight", &json!(public.weight))?;
            eq_field(
                &request,
                "canonical_outcome_receipt",
                &json!(assertion.canonical_outcome_receipt()),
            )?;
            eq_field(&request, "evidence_refs", &json!(public.evidence_refs))?;
            eq_timestamp(&request, "occurred_at", public.occurred_at)?;
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    closed(
                        value,
                        &[
                            "target_digest",
                            "signal",
                            "applied_effect",
                            "state_generation_before",
                            "state_generation_after",
                            "provider_receipt_digest",
                            "warnings",
                        ],
                    )?;
                    eq_field(value, "target_digest", &json!(json_digest(&target)?))?;
                    eq_field(value, "signal", &wire(&public.signal)?)?;
                    Ok(ProviderFeedbackResultV1 {
                        source: public.source.clone(),
                        target: public_target(source)?,
                        target_digest: string(value, "target_digest")?,
                        signal: public.signal,
                        applied_effect: ProviderControlEvidenceV1::new(
                            field(value, "applied_effect")?.clone(),
                        )
                        .map_err(|_| "feedback applied effect")?,
                        receipt: mutation_receipt(value, call, reply)?,
                    })
                })
                .transpose()?;
            ProviderControlOperationResultV1::Feedback(data)
        }
        (
            ProviderControlRequestV1::Correction(public),
            HostControlEvidence::Correction { source, change },
        ) => {
            let target = bind_source(source, &public.source, call)?;
            source
                .target
                .validate_expected_revision(&public.expected_source_revision)
                .map_err(|_| "correction revision")?;
            eq_field(&request, "target", &target)?;
            eq_field(
                &request,
                "correction_kind",
                &wire(&public.correction.kind())?,
            )?;
            eq_field(
                &request,
                "expected_target_revision",
                &json!(public.expected_source_revision),
            )?;
            eq_field(&request, "reason", &json!(public.reason))?;
            eq_field(&request, "evidence_refs", &json!(public.evidence_refs))?;
            validate_correction(&public.correction, change, field(&request, "replacement")?)?;
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    closed(
                        value,
                        &[
                            "target_digest",
                            "correction_kind",
                            "affected_provider_effects",
                            "state_generation_before",
                            "state_generation_after",
                            "provider_receipt_digest",
                            "warnings",
                        ],
                    )?;
                    eq_field(value, "target_digest", &json!(json_digest(&target)?))?;
                    eq_field(value, "correction_kind", &wire(&public.correction.kind())?)?;
                    let count = affected_count(
                        field(value, "affected_provider_effects")?,
                        stable_ref(source.target)?,
                    )?;
                    Ok(ProviderCorrectionResultV1 {
                        source: public.source.clone(),
                        target: public_target(source)?,
                        target_digest: string(value, "target_digest")?,
                        correction_kind: public.correction.kind(),
                        affected_provider_effects: count,
                        receipt: mutation_receipt(value, call, reply)?,
                    })
                })
                .transpose()?;
            ProviderControlOperationResultV1::Correction(data)
        }
        (
            ProviderControlRequestV1::DeleteBySource(public),
            HostControlEvidence::DeleteBySource {
                source,
                command,
                intent,
                cleanup,
            },
        ) => {
            bind_source(source, &public.source, call)?;
            require(
                command
                    .matches(
                        input.context,
                        public,
                        source.target,
                        source.original_attribution,
                    )
                    .map_err(|_| "deletion command binding")?,
                "deletion command binding",
            )?;
            require(
                call.operation_id == command.operation_id()
                    && call.idempotency_key.as_deref() == Some(command.idempotency_key()),
                "deletion accepted identity",
            )?;
            eq_field(
                &request,
                "forget_source_keys",
                &json!([source.target.source.source_key]),
            )?;
            eq_field(&request, "mode", &wire(&public.mode)?)?;
            eq_field(
                &request,
                "include_snapshots",
                &json!(public.include_snapshots),
            )?;
            require(
                number(&request, "retention_lock_policy_revision")? > 0,
                "retention lock policy",
            )?;
            let query = string(&request, "verification_query")?;
            require(
                !query.is_empty() && query.len() <= 8192,
                "deletion verification query",
            )?;
            require(
                intent.fence_revision_before == public.expected_fence_revision
                    && intent.fence_revision_after
                        == intent
                            .fence_revision_before
                            .checked_add(1)
                            .ok_or("deletion fence overflow")?,
                "accepted deletion intent",
            )?;
            let erasure = match response.as_ref() {
                None => ProviderControlErasureV1::Pending {
                    reason_code: terminal.terminal_code().as_wire().to_owned(),
                },
                Some(value) => deletion_erasure(value, call, reply, &query)?,
            };
            ProviderControlOperationResultV1::DeleteBySource(Some(Box::new(
                ProviderDeleteBySourceResultV1 {
                    source: public.source.clone(),
                    target: public_target(source)?,
                    mode: public.mode,
                    include_snapshots: public.include_snapshots,
                    intent: intent.clone(),
                    host_snapshot_cleanup: host_snapshot_cleanup(cleanup),
                    erasure,
                },
            )))
        }
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
                call,
            )?;
            validate_inspection_target(&selection, &request)?;
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
        (
            ProviderControlRequestV1::SnapshotExport(public),
            HostControlEvidence::SnapshotExport(retained),
        ) => {
            require(
                response.is_some() == retained.is_some(),
                "snapshot artifact success binding",
            )?;
            let data = match (response.as_ref(), retained) {
                (Some(value), Some(retained)) => {
                    let identity = snapshot(retained, dispatch)?;
                    require(
                        identity.byte_length <= public.maximum_bytes,
                        "snapshot requested bytes",
                    )?;
                    closed(
                        value,
                        &[
                            "snapshot",
                            "warnings",
                            "state_generation_before",
                            "state_generation_after",
                            "provider_receipt_digest",
                        ],
                    )?;
                    eq_field(value, "snapshot", &payload(retained.carrier)?)?;
                    require(
                        identity.state_generation == reply.state_generation,
                        "snapshot export generation",
                    )?;
                    Some(ProviderSnapshotExportResultV1 {
                        snapshot_ref: retained.snapshot_ref.to_owned(),
                        identity,
                    })
                }
                (None, None) => None,
                _ => return Err("snapshot artifact success binding"),
            };
            ProviderControlOperationResultV1::SnapshotExport(data)
        }
        (
            ProviderControlRequestV1::SnapshotRestore(public),
            HostControlEvidence::SnapshotRestore(retained),
        ) => {
            require(
                public.snapshot_ref == retained.snapshot_ref
                    && public.expected_state_generation == call.expected_state_generation,
                "snapshot restore request",
            )?;
            let identity = snapshot(retained, dispatch)?;
            eq_field(&request, "snapshot", &payload(retained.carrier)?)?;
            // Current restore authority is attached by the mounted host; JSON is no grant.
            field(&request, "disposition_checkpoint")?;
            field(&request, "source_dispositions")?;
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    snapshot_restore_data(value, retained.snapshot_ref, &identity, call, reply)
                })
                .transpose()?;
            ProviderControlOperationResultV1::SnapshotRestore(data)
        }
        (ProviderControlRequestV1::Replay(public), HostControlEvidence::Replay(evidence)) => {
            validate_replay_request(public, evidence, &request, call)?;
            let observations = evidence.observations;
            let data = response
                .as_ref()
                .map(|value| -> ProjectionResult<_> {
                    closed(
                        value,
                        &[
                            "first_source_sequence",
                            "last_source_sequence",
                            "acknowledged_sequence",
                            "applied_observations",
                            "duplicate_observations",
                            "sources_already_applied",
                            "rejected_observations",
                            "effect_unknown_observations",
                            "partial",
                            "state_generation_before",
                            "state_generation_after",
                            "provider_receipt_digest",
                            "warnings",
                            "items",
                        ],
                    )?;
                    eq_field(
                        value,
                        "first_source_sequence",
                        &json!(public.first_source_sequence),
                    )?;
                    eq_field(
                        value,
                        "last_source_sequence",
                        &json!(public.last_source_sequence),
                    )?;
                    let data = ProviderReplayResultV1 {
                        first_source_sequence: public.first_source_sequence,
                        last_source_sequence: public.last_source_sequence,
                        acknowledged_sequence: number(value, "acknowledged_sequence")?,
                        resolved_observations: observations.len() as u64,
                        applied_observations: number(value, "applied_observations")?,
                        duplicate_observations: number(value, "duplicate_observations")?,
                        sources_already_applied: number(value, "sources_already_applied")?,
                        rejected_observations: number(value, "rejected_observations")?,
                        effect_unknown_observations: number(value, "effect_unknown_observations")?,
                        partial: boolean(value, "partial")?,
                        receipt: mutation_receipt(value, call, reply)?,
                    };
                    require(
                        data.acknowledged_sequence
                            >= public.expected_previous_acknowledged_sequence
                            && data.acknowledged_sequence <= public.last_source_sequence,
                        "replay acknowledgement",
                    )?;
                    Ok(data)
                })
                .transpose()?;
            ProviderControlOperationResultV1::Replay(data)
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
        ProviderControlRequestV1::Feedback(_) => "feedback",
        ProviderControlRequestV1::Correction(_) => "correction",
        ProviderControlRequestV1::DeleteBySource(_) => "delete_by_source",
        ProviderControlRequestV1::Health(_) => "health",
        ProviderControlRequestV1::Inspection(_) => "inspection",
        ProviderControlRequestV1::Maintenance(_) => "maintenance",
        ProviderControlRequestV1::SnapshotExport(_) => "snapshot_export",
        ProviderControlRequestV1::SnapshotRestore(_) => "snapshot_restore",
        ProviderControlRequestV1::Replay(_) => "replay",
    }
}
fn operation_contract_id(operation: ProviderOperation) -> ProjectionResult<&'static str> {
    Ok(match operation {
        ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
        ProviderOperation::Feedback => "tracedecay.memory.provider.feedback.v1",
        ProviderOperation::Correction => "tracedecay.memory.provider.correction.v1",
        ProviderOperation::DeleteBySource => "tracedecay.memory.provider.deletion-by-source.v1",
        ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
        ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
        ProviderOperation::SnapshotExport => "tracedecay.memory.provider.snapshot-export.v1",
        ProviderOperation::SnapshotRestore => "tracedecay.memory.provider.snapshot-restore.v1",
        ProviderOperation::Replay => "tracedecay.memory.provider.replay.v1",
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
        ProviderOperation::Feedback => &[
            "common_request",
            "target",
            "signal",
            "weight",
            "canonical_outcome_receipt",
            "evidence_refs",
            "occurred_at",
        ],
        ProviderOperation::Correction => &[
            "common_request",
            "target",
            "correction_kind",
            "replacement",
            "expected_target_revision",
            "reason",
            "evidence_refs",
        ],
        ProviderOperation::DeleteBySource => &[
            "common_request",
            "forget_source_keys",
            "mode",
            "include_snapshots",
            "retention_lock_policy_revision",
            "verification_query",
        ],
        ProviderOperation::Health => &["common_request", "requested_checks"],
        ProviderOperation::Inspection => &[
            "common_request",
            "view",
            "selector",
            "target",
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
        ProviderOperation::SnapshotExport => &["common_request"],
        ProviderOperation::SnapshotRestore => &[
            "common_request",
            "snapshot",
            "disposition_checkpoint",
            "source_dispositions",
        ],
        ProviderOperation::Replay => &[
            "common_request",
            "observation_batch_refs",
            "first_source_sequence",
            "last_source_sequence",
            "expected_state_generation",
            "expected_previous_acknowledged_sequence",
            "history_grant",
            "resolved_observations",
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
    validate_resolved_state_selector(
        selector,
        &call.provider_id,
        call.registration_revision,
        &call.exact_scope,
    )
}
fn validate_resolved_state_selector(
    selector: &ProviderControlStateSelectorV1,
    actual_provider_id: &OwnedProviderId,
    actual_registration_revision: u64,
    actual_scope: &OwnedExactScope,
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
            // The registered canonical-provider/session pair is resolved by the host;
            // coding scope has no canonical transcript-provider field to invent.
            require(
                provider_id == actual_provider_id.as_str()
                    && *registration_revision == actual_registration_revision
                    && actual_scope.agent_session_id
                        == scope(actual_scope).agent_session_id_for_canonical_session(session_id),
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
                scope_digest == actual_scope.exact_scope_sha256(),
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
fn stable_ref(target: &LifecycleTarget) -> ProjectionResult<&str> {
    match &target.reference {
        LifecycleTargetReference::StableMemoryRef(value)
        | LifecycleTargetReference::RetainedSourceLocator(value) => Ok(value),
        _ => Err("stable source target"),
    }
}
fn bind_source(
    source: ResolvedControlSourceV1<'_>,
    selector: &ProviderControlSourceSelectorV1,
    call: &ProviderCall,
) -> ProjectionResult<Value> {
    require(
        source.selector == selector
            && source.target.source.observation_id == selector.observation_id,
        "retained source selector",
    )?;
    source
        .target
        .validate_for(&call.provider_id, &call.exact_scope)
        .map_err(|_| "source target binding")?;
    require(
        source.target.registration_revision == call.registration_revision,
        "source registration binding",
    )?;
    lifecycle_target_wire(source)
}

/// Canonical serialization of already-resolved host evidence, never a grant.
pub(super) fn lifecycle_target_wire(
    source: ResolvedControlSourceV1<'_>,
) -> ProjectionResult<Value> {
    source
        .target
        .validate()
        .map_err(|_| "source target structure")?;
    source
        .original_attribution
        .validate()
        .map_err(|_| "original attribution")?;
    source
        .original_attribution
        .origin_scope
        .recorded_scope()
        .map_err(|_| "recorded original source")?;
    source
        .current_disposition
        .validate()
        .map_err(|_| "current source disposition")?;
    require(
        source.target.source.observation_id == source.selector.observation_id
            && source.target.source == source.original_attribution.source
            && source.target.original_scope == source.original_attribution.origin_scope,
        "original source binding",
    )?;
    let attribution =
        source_attribution_json(source.original_attribution).map_err(|_| "original source wire")?;
    let reference = match &source.target.reference {
        LifecycleTargetReference::StableMemoryRef(value) => {
            json!({"kind":"stable_memory_ref","reference":value})
        }
        LifecycleTargetReference::RetainedSourceLocator(value) => {
            json!({"kind":"retained_source_locator","reference":value})
        }
        LifecycleTargetReference::RecallTraceRef(_)
        | LifecycleTargetReference::ContextPackItemRef(_) => {
            return Err("stable source target");
        }
    };
    Ok(
        json!({"provider_id":source.target.provider_id.as_str(),"registration_revision":source.target.registration_revision,
        "original_scope":attribution["origin_scope"],"delivery_scope":scope(&source.target.delivery_scope),"source":attribution["source"],
        "reference":reference}),
    )
}

pub(super) fn public_target(
    source: ResolvedControlSourceV1<'_>,
) -> ProjectionResult<ProviderControlSourceTargetV1> {
    lifecycle_target_wire(source)?;
    let attribution =
        source_attribution_json(source.original_attribution).map_err(|_| "original source wire")?;
    Ok(ProviderControlSourceTargetV1 {
        stable_memory_ref: stable_ref(source.target)?.to_owned(),
        source: decode(field(&attribution, "source")?, "source identity")?,
    })
}
fn privacy_withheld(source: ResolvedControlSourceV1<'_>) -> bool {
    matches!(
        source.current_disposition.state,
        SourceDisposition::Deleted
            | SourceDisposition::Redacted
            | SourceDisposition::Expired
            | SourceDisposition::Unknown
    )
}
fn validate_correction(
    public: &ProviderControlCorrectionV1,
    evidence: CorrectionEvidenceV1<'_>,
    replacement: &Value,
) -> ProjectionResult<()> {
    match (public, evidence) {
        (
            ProviderControlCorrectionV1::Supersede { replacement_source }
            | ProviderControlCorrectionV1::ReplaceContent { replacement_source },
            CorrectionEvidenceV1::Replacement {
                source,
                observation,
            },
        ) => {
            require(
                replacement_source == source.selector && !privacy_withheld(source),
                "replacement source binding",
            )?;
            lifecycle_target_wire(source)?;
            let envelope = payload(observation)?;
            require(
                replacement == &envelope,
                "replacement canonical observation",
            )?;
            let original = envelope
                .pointer("/source_identity/original_source")
                .ok_or("replacement original source")?;
            require(
                original
                    == &source_attribution_json(source.original_attribution)
                        .map_err(|_| "replacement attribution")?
                    && number(&envelope, "source_sequence")?
                        == source.original_attribution.source_sequence,
                "replacement original source binding",
            )
        }
        (
            ProviderControlCorrectionV1::ChangeValidity {
                valid_from,
                valid_until,
            },
            CorrectionEvidenceV1::Metadata,
        ) => {
            closed(replacement, &["valid_from", "valid_until"])?;
            eq_timestamp(replacement, "valid_from", *valid_from)?;
            match valid_until {
                Some(value) => eq_timestamp(replacement, "valid_until", *value),
                None => eq_field(replacement, "valid_until", &Value::Null),
            }
        }
        (
            ProviderControlCorrectionV1::MarkIncorrect { revoked_at },
            CorrectionEvidenceV1::Metadata,
        ) => {
            closed(replacement, &["revoked_at"])?;
            eq_timestamp(replacement, "revoked_at", *revoked_at)
        }
        (
            ProviderControlCorrectionV1::RestrictScope { destination },
            CorrectionEvidenceV1::RestrictScope {
                selector,
                exact_scope,
            },
        ) => {
            require(destination == selector, "restriction selector")?;
            exact_scope.validate().map_err(|_| "restriction scope")?;
            closed(replacement, &["exact_scope_identity"])?;
            eq_field(
                replacement,
                "exact_scope_identity",
                &wire(&scope(exact_scope))?,
            )
        }
        _ => Err("correction host evidence"),
    }
}
fn affected_count(value: &Value, target: &str) -> ProjectionResult<u64> {
    if let Some(count) = value.as_u64() {
        return Ok(count);
    }
    let refs: Vec<String> = decode(value, "correction affected references")?;
    require(
        refs.len() <= 4096
            && refs.iter().all(|s| !s.is_empty() && s.len() <= 1024)
            && refs.iter().collect::<BTreeSet<_>>().len() == refs.len()
            && (refs.is_empty() || refs.iter().any(|s| s == target)),
        "correction affected references",
    )?;
    Ok(refs.len() as u64)
}
fn deletion_erasure(
    value: &Value,
    call: &ProviderCall,
    reply: &ProviderReply,
    query: &str,
) -> ProjectionResult<ProviderControlErasureV1> {
    closed(
        value,
        &[
            "postcondition",
            "provider_receipt_digest",
            "warnings",
            "state_generation_before",
            "state_generation_after",
        ],
    )?;
    let raw = field(value, "postcondition")?;
    closed(
        raw,
        &[
            "matched_effects",
            "removed_effects",
            "anonymized_effects",
            "retained_under_lock",
            "remaining_influence_count",
            "snapshots_examined",
            "snapshots_rewritten",
            "verification_query_digest",
            "verification_state",
            "state_generation_before",
            "state_generation_after",
        ],
    )?;
    let postcondition: ProviderControlDeletionPostconditionV1 = decode_selected(
        raw,
        &[
            "matched_effects",
            "removed_effects",
            "anonymized_effects",
            "retained_under_lock",
            "remaining_influence_count",
            "snapshots_examined",
            "snapshots_rewritten",
            "verification_query_digest",
            "verification_state",
        ],
    )?;
    require(
        postcondition.verification_query_digest == digest(query.as_bytes()),
        "deletion verification query digest",
    )?;
    let receipt = ProviderControlMutationReceiptV1 {
        state_generation_before: number(raw, "state_generation_before")?,
        state_generation_after: number(raw, "state_generation_after")?,
        provider_receipt_digest: string(value, "provider_receipt_digest")?,
    };
    validate_receipt(&receipt, call, reply)?;
    let successful = matches!(
        reply.terminal.terminal_code(),
        TerminalCode::Success | TerminalCode::SuccessZeroResults
    );
    match postcondition.verification_state {
        ProviderControlDeletionVerificationV1::VerifiedAbsent
        | ProviderControlDeletionVerificationV1::VerifiedAnonymized
            if successful =>
        {
            Ok(ProviderControlErasureV1::Verified {
                postcondition,
                receipt,
            })
        }
        ProviderControlDeletionVerificationV1::RetainedUnderExplicitLock if successful => {
            Ok(ProviderControlErasureV1::RetainedUnderLock {
                postcondition,
                // Actual provider report receipt, not independent host lock authority.
                retention_lock_receipt: receipt.provider_receipt_digest.clone(),
                receipt,
            })
        }
        _ => Ok(ProviderControlErasureV1::Failed {
            reason_code: reply.terminal.terminal_code().as_wire().to_owned(),
            postcondition: Some(postcondition),
            receipt: Some(receipt),
        }),
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

fn snapshot_restore_data(
    value: &Value,
    snapshot_ref: &str,
    identity: &ProviderControlSnapshotIdentityV1,
    call: &ProviderCall,
    reply: &ProviderReply,
) -> ProjectionResult<ProviderSnapshotRestoreResultV1> {
    closed(
        value,
        &[
            "snapshot_id",
            "state_generation_before",
            "state_generation_after",
            "restored_observation_sequence",
            "restored_rows",
            "provider_receipt_digest",
            "warnings",
        ],
    )?;
    eq_field(value, "snapshot_id", &json!(identity.snapshot_id))?;
    eq_field(
        value,
        "restored_observation_sequence",
        &json!(identity.observation_sequence),
    )?;
    Ok(ProviderSnapshotRestoreResultV1 {
        snapshot_ref: snapshot_ref.to_owned(),
        snapshot_id: identity.snapshot_id.clone(),
        restored_observation_sequence: identity.observation_sequence,
        restored_rows: optional_count(value, "restored_rows")?,
        receipt: mutation_receipt(value, call, reply)?,
    })
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
        .map(OwnedVersionedId::as_str)
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
    call: &ProviderCall,
) -> ProjectionResult<()> {
    let expected = match (public, evidence) {
        (ProviderControlInspectionSelectorV1::StateSummary, InspectionEvidenceV1::StateSummary)
        | (
            ProviderControlInspectionSelectorV1::CapabilityStatus,
            InspectionEvidenceV1::CapabilityStatus,
        ) => json!({}),
        (
            ProviderControlInspectionSelectorV1::SourceInfluence { source },
            InspectionEvidenceV1::SourceInfluence(resolved),
        ) => {
            bind_source(*resolved, source, call)?;
            json!({"stable_memory_ref":stable_ref(resolved.target)?,"source_key":resolved.target.source.source_key})
        }
        (
            ProviderControlInspectionSelectorV1::Trace { source },
            InspectionEvidenceV1::Trace(resolved),
        ) => {
            bind_source(*resolved, source, call)?;
            json!({"stable_memory_ref":stable_ref(resolved.target)?})
        }
        (
            ProviderControlInspectionSelectorV1::DeliveryReceipt { source },
            InspectionEvidenceV1::DeliveryReceipt {
                source: resolved,
                idempotency_key,
            },
        ) => {
            bind_source(*resolved, source, call)?;
            require(
                !idempotency_key.is_empty() && idempotency_key.len() <= 256,
                "delivery receipt key",
            )?;
            json!({"idempotency_key":idempotency_key,"stable_memory_ref":stable_ref(resolved.target)?})
        }
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

fn validate_inspection_target(
    evidence: &InspectionEvidenceV1<'_>,
    request: &Value,
) -> ProjectionResult<()> {
    let expected = match evidence {
        InspectionEvidenceV1::SourceInfluence(source)
        | InspectionEvidenceV1::Trace(source)
        | InspectionEvidenceV1::DeliveryReceipt { source, .. } => match &source.target.reference {
            LifecycleTargetReference::RetainedSourceLocator(_) => {
                Some(lifecycle_target_wire(*source)?)
            }
            LifecycleTargetReference::StableMemoryRef(_) => None,
            LifecycleTargetReference::RecallTraceRef(_)
            | LifecycleTargetReference::ContextPackItemRef(_) => {
                return Err("inspection source target");
            }
        },
        InspectionEvidenceV1::StateSummary
        | InspectionEvidenceV1::MaintenanceReceipt { .. }
        | InspectionEvidenceV1::CapabilityStatus => None,
    };
    match expected {
        Some(expected) => eq_field(request, "target", &expected),
        None => require(request.get("target").is_none(), "inspection target"),
    }
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
    if !matches!(
        evidence,
        InspectionEvidenceV1::StateSummary
            | InspectionEvidenceV1::CapabilityStatus
            | InspectionEvidenceV1::SourceInfluence(_)
    ) {
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
        InspectionEvidenceV1::SourceInfluence(source) => {
            let target = bind_source(*source, source.selector, &dispatch.call)?;
            let mut output = Vec::with_capacity(raw.len());
            for item in raw {
                closed(
                    item,
                    &[
                        "target",
                        "source",
                        "active",
                        "disposition",
                        "settled_feedback",
                        "last_feedback_receipt",
                        "provider_local_effect_summary",
                    ],
                )?;
                eq_field(item, "target", &target)?;
                eq_field(item, "source", field(&target, "source")?)?;
                let active = boolean(item, "active")?;
                let disposition = decode(field(item, "disposition")?, "source disposition")?;
                if privacy_withheld(*source) {
                    require(
                        !active
                            && !matches!(
                                disposition,
                                ProviderControlSourceDispositionV1::Available
                            ),
                        "fresh source privacy fence",
                    )?;
                }
                output.push(ProviderControlSourceInfluenceItemV1 {
                    target: public_target(*source)?,
                    active,
                    disposition,
                    settled_feedback: decode(
                        field(item, "settled_feedback")?,
                        "settled feedback counts",
                    )?,
                    last_feedback_receipt: decode(
                        field(item, "last_feedback_receipt")?,
                        "last feedback receipt",
                    )?,
                    provider_local_effect_summary: string(item, "provider_local_effect_summary")?,
                });
            }
            ProviderControlInspectionItemsV1::SourceInfluence(output)
        }
        InspectionEvidenceV1::Trace(source) => {
            let mut output = Vec::with_capacity(raw.len());
            for item in raw {
                closed(
                    item,
                    &[
                        "stable_memory_ref",
                        "content",
                        "content_sha256",
                        "original_source",
                    ],
                )?;
                eq_field(
                    item,
                    "stable_memory_ref",
                    &json!(stable_ref(source.target)?),
                )?;
                let content: Option<String> = decode(field(item, "content")?, "trace content")?;
                let content_sha256: Option<String> =
                    decode(field(item, "content_sha256")?, "trace content digest")?;
                let original = field(item, "original_source")?;
                let original_source = match &content {
                    Some(content) => {
                        require(!privacy_withheld(*source), "trace content privacy")?;
                        validate_trace_content(
                            content,
                            content_sha256.as_deref(),
                            public
                                .maximum_bytes
                                .min(
                                    dispatch
                                        .readiness_evidence
                                        .effective_limits()
                                        .response_bytes,
                                )
                                .min(MAX_PROVIDER_CONTROL_RESPONSE_BYTES as u64),
                        )?;
                        require(
                            original
                                == &source_attribution_json(source.original_attribution)
                                    .map_err(|_| "trace source attribution")?,
                            "trace original attribution",
                        )?;
                        Some(public_target(*source)?.source)
                    }
                    None => {
                        require(
                            content_sha256.is_none() && original.is_null(),
                            "trace withheld fields",
                        )?;
                        None
                    }
                };
                output.push(ProviderControlTraceItemV1 {
                    stable_memory_ref: stable_ref(source.target)?.to_owned(),
                    content,
                    content_sha256,
                    original_source,
                });
            }
            ProviderControlInspectionItemsV1::Trace(output)
        }
        InspectionEvidenceV1::DeliveryReceipt {
            idempotency_key,
            source,
        } => {
            let data: Vec<ProviderControlDeliveryReceiptItemV1> =
                decode(&Value::Array(raw.clone()), "delivery receipt items")?;
            for item in &data {
                require(
                    item.idempotency_key == *idempotency_key
                        && !privacy_withheld(*source)
                        && stable_ref(source.target)? == item.stable_memory_ref,
                    "delivery receipt source binding",
                )?;
            }
            ProviderControlInspectionItemsV1::DeliveryReceipt(data)
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
        evidence_origin: ProviderControlInspectionEvidenceOriginV1::ProviderRuntime,
        items,
        coverage: decode(field(value, "coverage")?, "inspection coverage")?,
        next_cursor: decode(field(value, "next_cursor")?, "inspection cursor")?,
        redactions: decode(field(value, "redactions")?, "inspection redactions")?,
        state_generation: Some(dispatch.reply.state_generation),
    })
}
fn validate_trace_content(
    content: &str,
    content_sha256: Option<&str>,
    maximum_bytes: u64,
) -> ProjectionResult<()> {
    require(
        content.len() as u64 <= maximum_bytes
            && content_sha256 == Some(digest(content.as_bytes()).as_str()),
        "trace content budget and hash",
    )
}

fn snapshot_identity(value: &Value) -> ProjectionResult<ProviderControlSnapshotIdentityV1> {
    closed(
        value,
        &[
            "snapshot_id",
            "provider_id",
            "implementation_identity_digest",
            "state_schema_version",
            "exact_scope_digest",
            "state_generation",
            "observation_sequence",
            "parent_snapshot_id",
            "content_sha256",
            "byte_length",
            "created_at",
        ],
    )?;
    // Serde Option alone accepts an omitted field. Canonical carriers require
    // an explicit null or the actual parent identifier.
    field(value, "parent_snapshot_id")?;
    let identity: ProviderControlSnapshotIdentityV1 = decode(value, "snapshot identity")?;
    DateTime::parse_from_rfc3339(&identity.created_at)
        .map_err(|_| "snapshot creation timestamp")?;
    Ok(identity)
}

fn snapshot(
    retained: RetainedSnapshotV1<'_>,
    dispatch: &JourneyControlDispatchReplyV1,
) -> ProjectionResult<ProviderControlSnapshotIdentityV1> {
    require(
        !retained.snapshot_ref.is_empty() && retained.snapshot_ref.len() <= 1024,
        "retained snapshot reference",
    )?;
    let carrier = payload(retained.carrier)?;
    closed(&carrier, &["identity", "bytes", "sources"])?;
    let identity = snapshot_identity(field(&carrier, "identity")?)?;
    let bytes: Vec<u8> = decode(field(&carrier, "bytes")?, "snapshot bytes")?;
    let readiness = &dispatch.readiness_evidence;
    require(
        identity.provider_id == dispatch.call.provider_id.as_str()
            && identity.implementation_identity_digest
                == readiness.implementation_identity_sha256()
            && identity.state_schema_version == readiness.state_schema_version()
            && identity.exact_scope_digest == dispatch.call.exact_scope.exact_scope_sha256()
            && identity.byte_length == bytes.len() as u64
            && identity.byte_length <= readiness.effective_limits().snapshot_bytes
            && identity.content_sha256 == digest(&bytes),
        "snapshot carrier binding",
    )?;
    parse_timestamp(&identity.created_at)?;
    let sources: Vec<ProviderControlSourceIdentityV1> =
        decode(field(&carrier, "sources")?, "snapshot sources")?;
    require(sources.len() <= 4096, "snapshot source count")?;
    let mut seen = BTreeSet::new();
    for source in sources {
        validate_source_identity(&source)?;
        require(
            seen.insert(
                serde_json::to_vec(&json!([
                    source.canonical_provider_id,
                    source.canonical_session_id,
                    source.source_key,
                    source.observation_id,
                    source.source_revision
                ]))
                .map_err(|_| "snapshot source encoding")?,
            ),
            "duplicate snapshot source",
        )?;
    }
    Ok(identity)
}
fn validate_source_identity(value: &ProviderControlSourceIdentityV1) -> ProjectionResult<()> {
    OriginalSourceIdentity {
        canonical_provider_id: OwnedProviderId::new(&value.canonical_provider_id)
            .map_err(|_| "source provider identity")?,
        canonical_session_id: value.canonical_session_id.clone(),
        source_key: value.source_key.clone(),
        stable_record_id: value.stable_record_id.clone(),
        observation_id: value.observation_id.clone(),
        source_revision: value.source_revision.clone(),
        content_sha256: value.content_sha256.clone(),
    }
    .validate()
    .map_err(|_| "canonical source identity")
}
fn validate_replay_request(
    public: &ProviderReplayRequestV1,
    evidence: ReplayEvidenceV1<'_>,
    request: &Value,
    call: &ProviderCall,
) -> ProjectionResult<()> {
    let observations = evidence.observations;
    eq_field(
        request,
        "expected_state_generation",
        &json!(public.expected_state_generation),
    )?;
    require(
        public.observation_batch_refs == evidence.observation_batch_refs,
        "replay public artifact binding",
    )?;
    require(
        public.expected_state_generation == call.expected_state_generation,
        "replay expected generation",
    )?;
    for (name, expected) in [
        ("first_source_sequence", json!(public.first_source_sequence)),
        ("last_source_sequence", json!(public.last_source_sequence)),
        (
            "expected_previous_acknowledged_sequence",
            json!(public.expected_previous_acknowledged_sequence),
        ),
    ] {
        eq_field(request, name, &expected)?;
    }
    let length = public
        .last_source_sequence
        .checked_sub(public.first_source_sequence)
        .and_then(|v| v.checked_add(1))
        .ok_or("replay sequence interval")?;
    require(
        !observations.is_empty()
            && observations.len() <= 4096
            && observations.len() as u64 == length,
        "replay resolved interval",
    )?;
    let mut used_refs = BTreeSet::new();
    let mut canonical_refs = Vec::new();
    let mut resolved = Vec::with_capacity(observations.len());
    for (index, observation) in observations.iter().enumerate() {
        if used_refs.insert(observation.receipt_ref) {
            canonical_refs.push(observation.receipt_ref);
        }
        let envelope = payload(observation.observation)?;
        require(
            number(&envelope, "source_sequence")? == public.first_source_sequence + index as u64,
            "replay resolved sequence",
        )?;
        resolved.push(json!({"receipt_ref":observation.receipt_ref,"observation":envelope}));
    }
    eq_field(request, "observation_batch_refs", &json!(canonical_refs))?;
    eq_field(request, "resolved_observations", &Value::Array(resolved))?;
    field(request, "history_grant")?;
    Ok(())
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
    encode_lowercase_hex(&hash.finalize())
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
fn string(value: &Value, name: &'static str) -> ProjectionResult<String> {
    field(value, name)?.as_str().map(str::to_owned).ok_or(name)
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
fn digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn json_digest(value: &Value) -> ProjectionResult<String> {
    Ok(digest(
        &serde_json::to_vec(value).map_err(|_| "canonical JSON digest")?,
    ))
}
fn parse_timestamp(value: &str) -> ProjectionResult<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|time| time.timestamp_nanos_opt())
        .ok_or("UTC timestamp")
}
fn eq_timestamp(value: &Value, name: &'static str, expected: UtcMicros) -> ProjectionResult<()> {
    let nanos = expected.0.checked_mul(1000).ok_or("timestamp overflow")?;
    require(
        parse_timestamp(field(value, name)?.as_str().ok_or(name)?)? == nanos,
        name,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    use tracedecay_memory_provider_registry::{
        CancellationToken, CommittedEffectEvidence, OperationControl, OriginScopeEvidence,
        OwnedVersionedId, ProviderCallParts, RecordedValidity, TerminalRecord,
    };

    fn call(generation: u64) -> ProviderCall {
        call_for(ProviderOperation::Feedback, generation, json!({}))
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
    fn canonical_session_reads_bind_raw_session_to_exact_provider_namespace() {
        let canonical_session_id = "21b21d61-2edc-480d-8753-feeb2d87f58b";
        for operation in [ProviderOperation::Health, ProviderOperation::Inspection] {
            let mut call = call_for(operation, 3, json!({}));
            call.exact_scope.agent_session_id = scope(&call.exact_scope)
                .agent_session_id_for_canonical_session(canonical_session_id);
            let selector = ProviderControlStateSelectorV1::CanonicalSession {
                provider_id: call.provider_id.as_str().to_owned(),
                registration_revision: call.registration_revision,
                canonical_provider_id: "codex".to_owned(),
                session_id: canonical_session_id.to_owned(),
            };
            validate_state_selector(&selector, &call)
                .expect("raw canonical session resolves to its exact provider namespace");

            for (provider_id, registration_revision, session_id) in [
                (
                    "foreign-provider",
                    call.registration_revision,
                    canonical_session_id,
                ),
                (
                    call.provider_id.as_str(),
                    call.registration_revision + 1,
                    canonical_session_id,
                ),
                (
                    call.provider_id.as_str(),
                    call.registration_revision,
                    "256cb721-8f84-49b4-9cc5-609cf29edbb4",
                ),
            ] {
                let foreign = ProviderControlStateSelectorV1::CanonicalSession {
                    provider_id: provider_id.to_owned(),
                    registration_revision,
                    canonical_provider_id: "codex".to_owned(),
                    session_id: session_id.to_owned(),
                };
                assert_eq!(
                    validate_state_selector(&foreign, &call),
                    Err("state selector binding"),
                    "accepted a foreign canonical session selector for {operation:?}"
                );
            }

            let mut foreign_scope = call.exact_scope.clone();
            foreign_scope.agent_session_id = canonical_session_id.to_owned();
            assert_eq!(
                validate_resolved_state_selector(
                    &selector,
                    &call.provider_id,
                    call.registration_revision,
                    &foreign_scope,
                ),
                Err("state selector binding"),
                "accepted the raw session ID as a provider namespace"
            );
            foreign_scope = call.exact_scope.clone();
            foreign_scope.worktree_identity = "foreign-worktree".to_owned();
            assert_eq!(
                validate_resolved_state_selector(
                    &selector,
                    &call.provider_id,
                    call.registration_revision,
                    &foreign_scope,
                ),
                Err("state selector binding"),
                "accepted a namespace bound to another checkout"
            );
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
    fn native_restore_count_is_independent_from_sequence_and_ncm_can_omit_it() {
        let call = call_for(ProviderOperation::SnapshotRestore, 3, json!({}));
        let actual = reply(
            &call,
            TerminalCode::Success,
            CommittedEffectEvidence::committed(3, 4, Vec::new(), "b".repeat(64), "c".repeat(64))
                .expect("committed"),
            4,
        );
        let identity: ProviderControlSnapshotIdentityV1 = decode(&json!({"snapshot_id":"snapshot.actual","provider_id":"native","implementation_identity_digest":"a".repeat(64),"state_schema_version":"native-staged-v2","exact_scope_digest":call.exact_scope.exact_scope_sha256(),"state_generation":3,"observation_sequence":17,"parent_snapshot_id":null,"content_sha256":"b".repeat(64),"byte_length":42,"created_at":"2026-09-10T00:00:00Z"}),"identity").expect("actual identity");
        let mut value = json!({"snapshot_id":"snapshot.actual","restored_observation_sequence":17,"restored_rows":2,"state_generation_before":3,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64),"warnings":[]});
        let data = snapshot_restore_data(&value, "host.snapshot", &identity, &call, &actual)
            .expect("actual Native restore");
        assert_eq!(data.restored_rows, Some(2));
        assert_eq!(data.restored_observation_sequence, 17);
        value
            .as_object_mut()
            .expect("object")
            .remove("restored_rows");
        assert_eq!(
            snapshot_restore_data(&value, "host.snapshot", &identity, &call, &actual)
                .expect("NCM omitted row count")
                .restored_rows,
            None
        );
        for invalid in [Value::Null, json!(-1), json!(1.5), json!("2")] {
            value["restored_rows"] = invalid;
            assert!(
                snapshot_restore_data(&value, "host.snapshot", &identity, &call, &actual).is_err()
            );
        }
    }

    #[test]
    fn read_receipts_bind_actual_unchanged_generation_without_weakening_mutation_cas() {
        let raw = json!({"state_generation_before":5,"state_generation_after":5,"provider_receipt_digest":"b".repeat(64)});
        for operation in [
            ProviderOperation::Health,
            ProviderOperation::Inspection,
            ProviderOperation::SnapshotExport,
        ] {
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
    fn trace_content_above_8192_uses_actual_byte_budget_and_exact_hash() {
        let content = "x".repeat(10_000);
        let hash = digest(content.as_bytes());
        validate_trace_content(&content, Some(&hash), 16_384).expect("within actual request limit");
        assert!(validate_trace_content(&content, Some(&hash), 8192).is_err());
        assert!(validate_trace_content(&content, Some(&"a".repeat(64)), 16_384).is_err());
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
        assert!(std::ptr::eq(rejection.actual_reply, &raw const actual));
        assert!(!format!("{rejection:?}").contains("sensitive-provider-content"));
        assert_eq!(
            rejection.actual_reply.terminal.diagnostic_id(),
            Some("actual.provider.diagnostic")
        );
    }

    #[test]
    fn full_target_digest_binds_source_revision_and_scope() {
        let mut target = json!({"provider_id":"provider.native","registration_revision":1,"original_scope":{"state":"recorded","authority_ref":"marker:1"},"delivery_scope":{"agent_session_id":"session:1"},"source":{"source_key":"source:1","source_revision":"opaque:1"},"reference":{"kind":"stable_memory_ref","reference":"memory:1"}});
        let original = json_digest(&target).expect("digest");
        assert_ne!(original, digest(b"memory:1"));
        target["source"]["source_revision"] = json!("opaque:2");
        assert_ne!(original, json_digest(&target).expect("digest"));
        target["source"]["source_revision"] = json!("opaque:1");
        target["delivery_scope"]["agent_session_id"] = json!("session:2");
        assert_ne!(original, json_digest(&target).expect("digest"));
    }

    #[test]
    fn retained_lock_report_keeps_only_the_actual_provider_receipt() {
        let call = call(3);
        let actual = reply(
            &call,
            TerminalCode::SuccessZeroResults,
            CommittedEffectEvidence::none(Some(3)),
            3,
        );
        let value = json!({"postcondition":{"matched_effects":1,"removed_effects":0,"anonymized_effects":0,"retained_under_lock":1,"remaining_influence_count":1,"snapshots_examined":0,"snapshots_rewritten":0,"verification_query_digest":digest(b"abc"),"verification_state":"retained_under_explicit_lock","state_generation_before":3,"state_generation_after":3},"provider_receipt_digest":"b".repeat(64),"warnings":[]});
        let report = deletion_erasure(&value, &call, &actual, "abc").expect("actual lock report");
        assert!(
            matches!(report,ProviderControlErasureV1::RetainedUnderLock{retention_lock_receipt,receipt,..} if retention_lock_receipt == "b".repeat(64) && retention_lock_receipt == receipt.provider_receipt_digest)
        );
        let mut quoted = value;
        quoted["postcondition"]["verification_query_digest"] =
            json!(json_digest(&json!("abc")).expect("quoted digest"));
        assert!(deletion_erasure(&quoted, &call, &actual, "abc").is_err());
    }

    #[test]
    fn query_digest_hashes_exact_utf8_not_json_string_encoding() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(
            digest(b"abc"),
            json_digest(&json!("abc")).expect("JSON digest")
        );
    }

    #[test]
    fn utc_projection_checks_overflow_and_preserves_instant() {
        assert!(
            eq_timestamp(
                &json!({"at":"2026-01-01T01:00:00+01:00"}),
                "at",
                UtcMicros(1_767_225_600_000_000)
            )
            .is_ok()
        );
        assert!(
            eq_timestamp(
                &json!({"at":"2026-01-01T00:00:00Z"}),
                "at",
                UtcMicros(i64::MAX)
            )
            .is_err()
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
    fn source_influence_query_binds_shared_lineage_to_the_exact_retained_revision() {
        use tracedecay_memory_provider_registry::recall_admission::source_attribution::RecallSourceAttributionV1;
        let call = call_for(ProviderOperation::Inspection, 3, json!({}));
        for revision in [1, 2] {
            let selector = ProviderControlSourceSelectorV1 {
                trace_ref: "trace.retained".to_owned(),
                item_ref: "item.retained".to_owned(),
                observation_id: format!("observation.{revision}"),
            };
            let original: RecallSourceAttributionV1 = serde_json::from_value(json!({
                "source":{"canonical_provider_id":"codex","canonical_session_id":"session-1","source_key":"shared.lineage","stable_record_id":null,"observation_id":selector.observation_id,"source_revision":format!("revision.{revision}"),"content_sha256":"c".repeat(64)},
                "origin_scope":{"state":"recorded","exact_scope_identity":scope(&call.exact_scope),"authority_ref":"host-original:test"},
                "source_sequence":revision,"occurred_at":null,"ingested_at":"2026-09-10T00:00:00Z",
                "validity":{"valid_from":null,"valid_until":null,"superseded_at":null,"superseded_by":null,"revoked_at":null}
            })).expect("retained source");
            let original = original.to_owned_attribution().expect("attribution");
            let target = LifecycleTarget {
                provider_id: call.provider_id.clone(),
                registration_revision: call.registration_revision,
                original_scope: original.origin_scope.clone(),
                delivery_scope: call.exact_scope.clone(),
                source: original.source.clone(),
                reference: LifecycleTargetReference::StableMemoryRef(format!("memory.{revision}")),
            };
            let disposition = CurrentSourceDisposition {
                state: SourceDisposition::Available,
                authority_ref: "canonical.disposition".to_owned(),
                authority_revision: Some(1),
                checked_at_utc_nanos: 1,
            };
            let resolved = ResolvedControlSourceV1 {
                selector: &selector,
                target: &target,
                original_attribution: &original,
                current_disposition: &disposition,
            };
            let public = ProviderControlInspectionSelectorV1::SourceInfluence {
                source: selector.clone(),
            };
            let evidence = InspectionEvidenceV1::SourceInfluence(resolved);
            validate_inspection_selector(&public, &evidence,
                &json!({"source_key":"shared.lineage","stable_memory_ref":format!("memory.{revision}")}), &call)
                .expect("both retained revisions resolve independently");
            for wrong in [
                json!({"source_key":"shared.lineage"}),
                json!({"source_key":"shared.lineage","stable_memory_ref":format!("memory.{}",3-revision)}),
                json!({"source_key":"other.lineage","stable_memory_ref":format!("memory.{revision}")}),
            ] {
                assert!(validate_inspection_selector(&public, &evidence, &wrong, &call).is_err());
            }
        }
    }

    #[test]
    fn lifecycle_target_wire_preserves_retained_locator_and_stable_reference_kinds() {
        let call = call_for(ProviderOperation::Inspection, 3, json!({}));
        let selector = ProviderControlSourceSelectorV1 {
            trace_ref: "recall-trace-v1:cc".to_owned(),
            item_ref: "recall-item-v1:0".to_owned(),
            observation_id: "observation.locator".to_owned(),
        };
        let original = SourceAttribution {
            source: OriginalSourceIdentity {
                canonical_provider_id: OwnedProviderId::new("codex").expect("provider"),
                canonical_session_id: "session.original".to_owned(),
                source_key: "source.locator".to_owned(),
                stable_record_id: Some("record.locator".to_owned()),
                observation_id: selector.observation_id.clone(),
                source_revision: Some("revision.locator".to_owned()),
                content_sha256: "a".repeat(64),
            },
            origin_scope: OriginScopeEvidence::Recorded {
                scope: call.exact_scope.clone(),
                authority_ref: "host-origin.locator".to_owned(),
            },
            source_sequence: 1,
            occurred_at_utc_nanos: Some(1),
            ingested_at_utc_nanos: 2,
            validity: RecordedValidity::default(),
        };
        let disposition = CurrentSourceDisposition {
            state: SourceDisposition::Available,
            authority_ref: "canonical.disposition".to_owned(),
            authority_revision: Some(1),
            checked_at_utc_nanos: 3,
        };
        let mut target = LifecycleTarget {
            provider_id: call.provider_id.clone(),
            registration_revision: call.registration_revision,
            original_scope: original.origin_scope.clone(),
            delivery_scope: call.exact_scope.clone(),
            source: original.source.clone(),
            reference: LifecycleTargetReference::RetainedSourceLocator(
                "recall-memory-ref-v1:opaque-locator".to_owned(),
            ),
        };
        let resolved = ResolvedControlSourceV1 {
            selector: &selector,
            target: &target,
            original_attribution: &original,
            current_disposition: &disposition,
        };
        let retained = lifecycle_target_wire(resolved).expect("retained target wire");
        assert_eq!(
            retained["reference"],
            json!({
                "kind": "retained_source_locator",
                "reference": "recall-memory-ref-v1:opaque-locator"
            })
        );
        let retained_request = json!({
            "common_request": {},
            "view": "source_influence",
            "selector": {
                "source_key": "source.locator",
                "stable_memory_ref": "recall-memory-ref-v1:opaque-locator"
            },
            "target": retained,
            "maximum_items": 1,
            "maximum_bytes": 131_072,
            "redaction_policy_revision": 1,
            "cursor": null
        });
        validate_request_fields(ProviderOperation::Inspection, &retained_request)
            .expect("retained inspection target is an allowed request field");
        validate_inspection_target(
            &InspectionEvidenceV1::SourceInfluence(resolved),
            &retained_request,
        )
        .expect("retained inspection target binds to host evidence");
        let mut forged_request = retained_request.clone();
        forged_request["target"]["source"]["source_key"] = json!("source.forged");
        assert!(
            validate_inspection_target(
                &InspectionEvidenceV1::SourceInfluence(resolved),
                &forged_request,
            )
            .is_err()
        );

        target.reference =
            LifecycleTargetReference::StableMemoryRef("ncm-memory:".to_owned() + &"b".repeat(64));
        let stable = lifecycle_target_wire(ResolvedControlSourceV1 {
            selector: &selector,
            target: &target,
            original_attribution: &original,
            current_disposition: &disposition,
        })
        .expect("stable target wire");
        assert_eq!(stable["reference"]["kind"], "stable_memory_ref");
        assert_eq!(
            stable["reference"]["reference"],
            "ncm-memory:".to_owned() + &"b".repeat(64)
        );
        let mut stable_request = retained_request;
        stable_request
            .as_object_mut()
            .expect("inspection request")
            .remove("target");
        stable_request["selector"]["stable_memory_ref"] =
            json!("ncm-memory:".to_owned() + &"b".repeat(64));
        validate_request_fields(ProviderOperation::Inspection, &stable_request)
            .expect("stable inspection request remains valid");
        validate_inspection_target(
            &InspectionEvidenceV1::SourceInfluence(ResolvedControlSourceV1 {
                selector: &selector,
                target: &target,
                original_attribution: &original,
                current_disposition: &disposition,
            }),
            &stable_request,
        )
        .expect("stable inspection keeps selector-only target compatibility");
    }

    #[test]
    fn snapshot_identity_requires_explicit_parent_and_actual_timestamp() {
        let call = call_for(ProviderOperation::SnapshotExport, 3, json!({}));
        let actual = json!({"snapshot_id":"snapshot.actual","provider_id":"native","implementation_identity_digest":"a".repeat(64),"state_schema_version":"native-staged-v2","exact_scope_digest":call.exact_scope.exact_scope_sha256(),"state_generation":3,"observation_sequence":1,"parent_snapshot_id":null,"content_sha256":digest(b""),"byte_length":0,"created_at":"2026-09-10T00:00:00.123456789Z"});
        assert_eq!(
            snapshot_identity(&actual)
                .expect("actual identity")
                .state_generation,
            3
        );
        let mut omitted = actual.clone();
        omitted
            .as_object_mut()
            .expect("identity")
            .remove("parent_snapshot_id");
        assert!(snapshot_identity(&omitted).is_err());
        for (field, replacement) in [
            ("parent_snapshot_id", json!(false)),
            ("created_at", json!("yesterday")),
            ("unregistered_claim", json!(true)),
        ] {
            let mut changed = actual.clone();
            changed[field] = replacement;
            assert!(snapshot_identity(&changed).is_err());
        }
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
    fn host_cleanup_mapping_keeps_actual_partial_removals() {
        let actual = HostSnapshotCleanupResultV1 {
            state: HostSnapshotCleanupStateV1::Partial,
            removed_snapshot_refs: vec!["snapshot.removed.1".to_owned()],
            matched_count: 2,
            unverifiable_count: 1,
        };
        let projected = host_snapshot_cleanup(&actual);
        assert_eq!(
            projected.state,
            ProviderControlHostSnapshotCleanupStateV1::Partial
        );
        assert_eq!(
            projected.removed_snapshot_refs,
            actual.removed_snapshot_refs
        );
        assert_eq!(projected.matched_count, 2);
        assert_eq!(projected.unverifiable_count, 1);
        assert_eq!(
            host_snapshot_cleanup(&HostSnapshotCleanupResultV1::not_requested()).state,
            ProviderControlHostSnapshotCleanupStateV1::NotRequested
        );
    }

    #[test]
    fn affected_reference_array_must_include_original_and_not_repeat() {
        assert_eq!(
            affected_count(&json!(["memory:old", "memory:new"]), "memory:old"),
            Ok(2)
        );
        assert!(affected_count(&json!(["memory:other"]), "memory:old").is_err());
        assert!(affected_count(&json!(["memory:old", "memory:old"]), "memory:old").is_err());
    }
}
