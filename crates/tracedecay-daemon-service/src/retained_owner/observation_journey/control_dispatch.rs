//! Synchronous lifecycle control through the mounted journey's existing owners.
//!
//! The caller authorizes the original attribution and supplies its original
//! request control. This seam owns only bounded dispatch; it never interprets a
//! terminal as proof that a provider-local effect completed.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use tracedecay_memory_provider_registry::ProviderReply;

use super::{
    ApiError, Arc, BoundedCallRefusalV1, CanonicalPayload, ObservationJourneyError,
    OperationControl, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
    ProjectObservationJourneyV1, ProviderCall, ProviderCallParts, ProviderOperation,
    ReadinessEvidenceV1, SupervisedReadinessError, TerminalCode, readiness_handshake_request,
};

/// One already-authorized control pinned to its original provider and scope.
#[derive(Clone, Debug)]
pub(crate) struct JourneyControlDispatchRequestV1 {
    pub(crate) provider_id: OwnedProviderId,
    pub(crate) registration_revision: u64,
    /// The full original delivery scope, never reconstructed from selection.
    pub(crate) exact_scope: OwnedExactScope,
    pub(crate) operation: ProviderOperation,
    pub(crate) request_id: String,
    pub(crate) operation_id: String,
    pub(crate) idempotency_key: Option<String>,
    /// Already-authorized operation fields, with no caller-supplied host header.
    pub(crate) operation_body: Value,
    /// The host policy revision that authorized this control.
    pub(crate) policy_revision: u64,
    /// Cloning this preserves its running monotonic budget and live token.
    pub(crate) control: OperationControl,
    /// A caller's explicit guard must remain intact. Absence uses the
    /// generation from this dispatch's readiness evidence.
    pub(crate) expected_state_generation: Option<u64>,
}

/// Actual dispatch evidence for the host's operation-specific validation.
#[derive(Debug)]
pub(crate) struct JourneyControlDispatchReplyV1 {
    pub(crate) call: ProviderCall,
    pub(crate) reply: ProviderReply,
    /// Validated before dispatch. Its actual ready generation is independent
    /// of the call's explicit expected guard and the reply's resulting generation.
    pub(crate) readiness_evidence: ReadinessEvidenceV1,
    /// Capabilities from this original registration's accepted descriptor.
    pub(crate) registered_capabilities: BTreeSet<OwnedVersionedId>,
}

/// Why the requested control did not reach registry invocation.
///
/// A readiness handshake may already have run and recovered pending provider
/// privacy work. This classification concerns the requested control only; it
/// does not assert that all provider state stayed unchanged.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum JourneyControlNotDispatchedV1 {
    #[error("control does not target this journey's original provider")]
    ProviderMismatch,
    #[error("control does not target this journey's registration revision")]
    RegistrationRevisionMismatch,
    #[error("the original provider's observation journey is stopping")]
    Stopping,
    #[error("operation is not a mounted provider control: {0:?}")]
    UnsupportedOperation(ProviderOperation),
    #[error("original request control refused dispatch: {0:?}")]
    Control(TerminalCode),
    #[error("the original provider composition is disabled")]
    CompositionDisabled,
    #[error("the original provider is unavailable in this registry")]
    ProviderUnavailable,
    #[error("control operation body must be an object")]
    OperationBodyNotObject,
    #[error("control operation body supplied a host authority header: {0}")]
    SuppliedAuthorityHeader(&'static str),
    #[error("control policy revision must be positive")]
    InvalidPolicyRevision,
}

/// Dispatch stages stay typed without claiming an absent reply means no effect.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JourneyControlDispatchErrorV1 {
    #[error("requested provider control was not dispatched: {0}")]
    NotDispatched(#[from] JourneyControlNotDispatchedV1),
    #[error("provider control contract was refused: {0}")]
    Contract(#[source] ApiError),
    #[error("provider control payload could not be canonically encoded: {0}")]
    PayloadEncoding(#[source] super::HygieneError),
    #[error("provider control readiness request could not be constructed: {0}")]
    ReadinessRequest(#[source] ObservationJourneyError),
    #[error("provider control readiness was refused: {0}")]
    Readiness(#[source] SupervisedReadinessError),
    /// Fabric may reject either admission or the provider's returned terminal.
    /// An error alone does not prove that a mutation had no committed effect.
    #[error("provider control was refused by the fabric: {0}")]
    Fabric(#[source] super::FabricError),
    /// Cancellation, abandonment and an unavailable/panicking worker may occur
    /// after contact. Preserve that uncertainty for reconciliation; never retry
    /// a mutation here or project these variants as verified non-commitment.
    #[error("provider control produced no answer inside its original bound: {0}")]
    Isolation(#[source] BoundedCallRefusalV1),
}

impl JourneyControlDispatchRequestV1 {
    fn validate_control(&self, stopping: bool) -> Result<u64, JourneyControlDispatchErrorV1> {
        if stopping {
            return Err(JourneyControlNotDispatchedV1::Stopping.into());
        }
        self.control
            .snapshot()
            .map(|snapshot| snapshot.remaining_millis)
            .map_err(|terminal| JourneyControlNotDispatchedV1::Control(terminal).into())
    }

    fn validate_before_readiness(
        &self,
        provider_id: &str,
        registration_revision: u64,
        stopping: bool,
    ) -> Result<(), JourneyControlDispatchErrorV1> {
        if self.provider_id.as_str() != provider_id {
            return Err(JourneyControlNotDispatchedV1::ProviderMismatch.into());
        }
        if self.registration_revision != registration_revision {
            return Err(JourneyControlNotDispatchedV1::RegistrationRevisionMismatch.into());
        }
        self.validate_control(stopping)?;
        self.payload_contract_id()?;
        self.exact_scope
            .validate()
            .map_err(JourneyControlDispatchErrorV1::Contract)?;
        if self.policy_revision == 0 {
            return Err(JourneyControlNotDispatchedV1::InvalidPolicyRevision.into());
        }
        let body = self
            .operation_body
            .as_object()
            .ok_or(JourneyControlNotDispatchedV1::OperationBodyNotObject)?;
        for field in [
            "common_request",
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
        ] {
            if body.contains_key(field) {
                return Err(JourneyControlNotDispatchedV1::SuppliedAuthorityHeader(field).into());
            }
        }
        Ok(())
    }

    /// The host mounts exactly the three retained provider controls; every
    /// other provider operation has no host route and is refused here.
    fn payload_contract_id(&self) -> Result<&'static str, JourneyControlDispatchErrorV1> {
        match self.operation {
            ProviderOperation::Health => Ok("tracedecay.memory.provider.health.v1"),
            ProviderOperation::Inspection => Ok("tracedecay.memory.provider.inspection.v1"),
            ProviderOperation::Maintenance => Ok("tracedecay.memory.provider.maintenance.v1"),
            ProviderOperation::Handshake
            | ProviderOperation::Observe
            | ProviderOperation::Recall
            | ProviderOperation::Feedback
            | ProviderOperation::Correction
            | ProviderOperation::DeleteBySource
            | ProviderOperation::SnapshotExport
            | ProviderOperation::SnapshotRestore
            | ProviderOperation::Replay => {
                Err(JourneyControlNotDispatchedV1::UnsupportedOperation(self.operation).into())
            }
        }
    }

    /// Refuse an oversized serialized body before acquiring readiness or
    /// borrowing a provider worker. Final envelope bytes are still checked by
    /// the fabric against the actual negotiated request limit.
    fn validate_body_bytes(&self, maximum: u64) -> Result<(), JourneyControlDispatchErrorV1> {
        let bytes = super::canonical_payload_bytes(&self.operation_body)
            .map_err(JourneyControlDispatchErrorV1::PayloadEncoding)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
            return Err(JourneyControlDispatchErrorV1::Contract(
                ApiError::BoundaryBytesExceeded {
                    field: "control.operation_body",
                    maximum,
                },
            ));
        }
        Ok(())
    }

    /// Add the host header only after fresh readiness. Every operation-body
    /// field retains its original value; no supplied authority field is repaired.
    fn canonical_payload(
        &self,
        ready_receipt_sha256: &str,
        expected_state_generation: u64,
        deadline_utc_micros: i64,
        remaining_millis: u64,
    ) -> Result<CanonicalPayload, JourneyControlDispatchErrorV1> {
        let mut payload = self.operation_body.clone();
        let body = payload
            .as_object_mut()
            .ok_or(JourneyControlNotDispatchedV1::OperationBodyNotObject)?;
        // Preflight rejected this field before readiness; preserve that rule
        // even if this helper is called independently in a future refactor.
        if body.contains_key("common_request") {
            return Err(
                JourneyControlNotDispatchedV1::SuppliedAuthorityHeader("common_request").into(),
            );
        }
        let scope = &self.exact_scope;
        body.insert(
            "common_request".to_owned(),
            json!({
                "provider_id": self.provider_id.as_str(),
                "registration_revision": self.registration_revision,
                "ready_receipt_digest": ready_receipt_sha256,
                "exact_scope_identity": {
                    "profile_id": scope.profile_id,
                    "project_id": scope.project_id,
                    "repository_identity": scope.repository_identity,
                    "worktree_identity": scope.worktree_identity,
                    "branch_identity": scope.branch_identity,
                    "agent_session_id": scope.agent_session_id,
                    "resolved_scope_digest": scope.resolved_scope_digest,
                },
                "operation_id": self.operation_id,
                "idempotency_key": self.idempotency_key,
                "expected_state_generation": expected_state_generation,
                "request_identity": self.request_id,
                "policy_revision": self.policy_revision,
                "deadline": {
                    "deadline_utc_micros": deadline_utc_micros,
                    "remaining_millis": remaining_millis,
                },
                "cancellation": "live",
                "extensions": [],
            }),
        );
        let bytes = super::canonical_payload_bytes(&payload)
            .map_err(JourneyControlDispatchErrorV1::PayloadEncoding)?;
        let digest = tracedecay_domain::canonical_text::sha256_hex(&bytes);
        CanonicalPayload::new(
            OwnedVersionedId::new(self.payload_contract_id()?)
                .map_err(JourneyControlDispatchErrorV1::Contract)?,
            bytes,
            digest,
        )
        .map_err(JourneyControlDispatchErrorV1::Contract)
    }
}

impl ProjectObservationJourneyV1 {
    /// Checks this fixed mount identity without readiness or provider contact.
    /// The executor must require exactly one matching mount before dispatch.
    pub(crate) fn matches_control_owner(
        &self,
        provider_id: &OwnedProviderId,
        registration_revision: u64,
    ) -> bool {
        self.provider_id == provider_id.as_str()
            && self.registration_revision == registration_revision
    }

    /// Dispatches once from an existing caller blocking pool, using this
    /// journey's isolation ceiling and its registration-wide readiness guard.
    ///
    /// The caller must first authorize the original attribution and record any
    /// required durable deletion intent. No selected-provider lookup or fallback
    /// occurs here. Remaining envelope fields are checked by `ProviderCall::new`
    /// before registry invocation, after bounded readiness has been established.
    /// The bounded wait forwards shutdown into the caller's original live
    /// token, including while readiness or control is in flight. Its original
    /// deadline and running budget remain unchanged.
    pub(crate) fn dispatch_control(
        &self,
        request: JourneyControlDispatchRequestV1,
    ) -> Result<JourneyControlDispatchReplyV1, JourneyControlDispatchErrorV1> {
        request.validate_before_readiness(
            &self.provider_id,
            self.registration_revision,
            self.stopping.is_cancelled(),
        )?;
        request.validate_body_bytes(self.delivery.limits.request_bytes)?;
        let delivery = Arc::clone(&self.delivery);
        let stopping = self.stopping.clone();
        let cancellation = request.control.cancellation();
        // Snapshot immediately before isolation: remaining_millis() returns the
        // original budget, whereas snapshot subtracts time already consumed.
        let remaining_millis = request.validate_control(stopping.is_cancelled())?;
        self.provider_isolation
            .call_within_with_shutdown(
                remaining_millis,
                &cancellation,
                Some(&self.stopping),
                true,
                move || {
                    request.validate_before_readiness(
                        delivery.provider_id.as_str(),
                        delivery.registration_revision,
                        stopping.is_cancelled(),
                    )?;
                    let registry = delivery
                        .composition
                        .registry()
                        .ok_or(JourneyControlNotDispatchedV1::CompositionDisabled)?;
                    let registration = registry
                        .registration(&request.provider_id)
                        .ok_or(JourneyControlNotDispatchedV1::ProviderUnavailable)?;
                    if registration.registration_revision != request.registration_revision {
                        return Err(
                            JourneyControlNotDispatchedV1::RegistrationRevisionMismatch.into()
                        );
                    }
                    let capability = OwnedVersionedId::new(request.operation.capability_id())
                        .map_err(JourneyControlDispatchErrorV1::Contract)?;
                    let readiness_request = readiness_handshake_request(
                        &request.provider_id,
                        &request.exact_scope,
                        request.registration_revision,
                        delivery.limits,
                        capability.clone(),
                        request.control.clone(),
                    )
                    .map_err(|error| match error {
                        ObservationJourneyError::Contract(source) => {
                            JourneyControlDispatchErrorV1::Contract(source)
                        }
                        error => JourneyControlDispatchErrorV1::ReadinessRequest(error),
                    })?;
                    // Acquire and retain the !Send guard inside the existing worker.
                    // Copying its receipt out first would let another scope replace
                    // the fabric's readiness between this handshake and invocation.
                    let dispatch = delivery
                        .readiness
                        .ready_dispatch_with_evidence(
                            &readiness_request,
                            tracedecay_contracts::now_micros().0,
                        )
                        .map_err(JourneyControlDispatchErrorV1::Readiness)?;
                    let readiness_evidence = dispatch.evidence().clone();
                    // Read immutable registered capabilities while the same guard
                    // still binds the original provider/revision. Do this before
                    // invocation so an unavailable status cannot erase a result.
                    let registered_status = registry
                        .statuses()
                        .map_err(JourneyControlDispatchErrorV1::Fabric)?
                        .into_iter()
                        .find(|status| status.provider_id == request.provider_id)
                        .ok_or(JourneyControlNotDispatchedV1::ProviderUnavailable)?;
                    if registered_status.registration_revision != request.registration_revision {
                        return Err(
                            JourneyControlNotDispatchedV1::RegistrationRevisionMismatch.into()
                        );
                    }
                    let registered_capabilities = registered_status.descriptor.capabilities;
                    if stopping.is_cancelled() {
                        return Err(JourneyControlNotDispatchedV1::Stopping.into());
                    }
                    let snapshot = request
                        .control
                        .snapshot()
                        .map_err(JourneyControlNotDispatchedV1::Control)?;
                    let expected_state_generation = request
                        .expected_state_generation
                        .unwrap_or_else(|| readiness_evidence.state_generation());
                    let ready_receipt_sha256 = dispatch.target().ready_receipt_sha256().to_owned();
                    let payload = request.canonical_payload(
                        &ready_receipt_sha256,
                        expected_state_generation,
                        snapshot.deadline_utc_micros,
                        snapshot.remaining_millis,
                    )?;
                    let call = ProviderCall::new(ProviderCallParts {
                        operation: request.operation,
                        provider_id: request.provider_id,
                        registration_revision: request.registration_revision,
                        ready_receipt_sha256,
                        exact_scope: request.exact_scope,
                        request_id: request.request_id,
                        operation_id: request.operation_id,
                        expected_state_generation,
                        idempotency_key: request.idempotency_key,
                        control: request.control,
                        payload,
                        required_capabilities: vec![capability],
                        extensions: Vec::new(),
                    })
                    .map_err(JourneyControlDispatchErrorV1::Contract)?;
                    let reply = registry
                        .invoke_control(&call)
                        .map_err(JourneyControlDispatchErrorV1::Fabric)?;
                    drop(dispatch);
                    Ok(JourneyControlDispatchReplyV1 {
                        call,
                        reply,
                        readiness_evidence,
                        registered_capabilities,
                    })
                },
            )
            .map_err(JourneyControlDispatchErrorV1::Isolation)?
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::retained_owner::observation_journey::CancellationToken;

    fn request(operation: ProviderOperation) -> JourneyControlDispatchRequestV1 {
        JourneyControlDispatchRequestV1 {
            provider_id: OwnedProviderId::new("control.original").expect("provider id"),
            registration_revision: 7,
            exact_scope: OwnedExactScope::new(
                "original-profile",
                "original-project",
                "original-repository",
                "original-worktree",
                "original-branch",
                "original-session",
                format!("sha256:{}", "1".repeat(64)),
            )
            .expect("original delivery scope"),
            operation,
            request_id: "control-request".to_owned(),
            operation_id: "control-operation".to_owned(),
            idempotency_key: Some("original-control-key".to_owned()),
            operation_body: json!({}),
            policy_revision: 1,
            control: OperationControl::new(
                tracedecay_contracts::now_micros()
                    .0
                    .saturating_add(60_000_000),
                60_000,
                CancellationToken::new(),
            ),
            expected_state_generation: Some(3),
        }
    }

    #[test]
    fn preflight_admits_only_the_three_mounted_provider_controls() {
        for operation in [
            ProviderOperation::Health,
            ProviderOperation::Inspection,
            ProviderOperation::Maintenance,
        ] {
            request(operation)
                .validate_before_readiness("control.original", 7, false)
                .expect("mounted provider control");
        }
        for operation in [
            ProviderOperation::Handshake,
            ProviderOperation::Observe,
            ProviderOperation::Recall,
            ProviderOperation::Feedback,
            ProviderOperation::Correction,
            ProviderOperation::DeleteBySource,
            ProviderOperation::SnapshotExport,
            ProviderOperation::SnapshotRestore,
            ProviderOperation::Replay,
        ] {
            assert!(matches!(
                request(operation).validate_before_readiness("control.original", 7, false),
                Err(JourneyControlDispatchErrorV1::NotDispatched(
                    JourneyControlNotDispatchedV1::UnsupportedOperation(actual)
                )) if actual == operation
            ));
        }
    }

    #[test]
    fn preflight_refuses_another_provider_revision_stopping_or_incomplete_scope() {
        let mut request = request(ProviderOperation::Maintenance);
        assert!(matches!(
            request.validate_before_readiness("control.selected-new", 7, false),
            Err(JourneyControlDispatchErrorV1::NotDispatched(
                JourneyControlNotDispatchedV1::ProviderMismatch
            ))
        ));
        assert!(matches!(
            request.validate_before_readiness("control.original", 8, false),
            Err(JourneyControlDispatchErrorV1::NotDispatched(
                JourneyControlNotDispatchedV1::RegistrationRevisionMismatch
            ))
        ));
        assert!(matches!(
            request.validate_before_readiness("control.original", 7, true),
            Err(JourneyControlDispatchErrorV1::NotDispatched(
                JourneyControlNotDispatchedV1::Stopping
            ))
        ));
        request.exact_scope.agent_session_id.clear();
        assert!(matches!(
            request.validate_before_readiness("control.original", 7, false),
            Err(JourneyControlDispatchErrorV1::Contract(_))
        ));
    }

    #[test]
    fn preflight_keeps_the_original_live_cancellation_and_expired_deadline() {
        let mut request = request(ProviderOperation::Maintenance);
        let original_control = request.control.clone();
        original_control.cancellation().cancel();
        assert!(matches!(
            request.validate_before_readiness("control.original", 7, false),
            Err(JourneyControlDispatchErrorV1::NotDispatched(
                JourneyControlNotDispatchedV1::Control(TerminalCode::Cancelled)
            ))
        ));
        request.control = OperationControl::new(
            tracedecay_contracts::now_micros().0.saturating_sub(1),
            60_000,
            CancellationToken::new(),
        );
        assert!(matches!(
            request.validate_before_readiness("control.original", 7, false),
            Err(JourneyControlDispatchErrorV1::NotDispatched(
                JourneyControlNotDispatchedV1::Control(TerminalCode::DeadlineExceeded)
            ))
        ));
    }
}
