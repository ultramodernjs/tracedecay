//! Behavioral contract tests for the provider-neutral runtime API.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracedecay_memory_provider_api::contract::{
    CommittedEffectExpectation, CommittedEffectState, FallbackEligibility, PROVIDER_LIMITS,
    TERMINAL_CODE_POLICIES, TerminalCode,
};
use tracedecay_memory_provider_api::{
    ApiError, CancellationToken, CanonicalPayload, CommittedEffectEvidence,
    CommittedEffectEvidenceParts, FallbackDirective, HandshakeRequest, HandshakeRequestParts,
    HandshakeResponse, MAX_COMMITTED_EFFECT_ITEM_REF_BYTES, MAX_COMMITTED_EFFECT_ITEM_REFS,
    MemoryProvider, NativeContextDeliveryMarker, OBSERVATION_HYGIENE_RECEIPT_ID_PREFIX,
    OperationControl, OwnedExactScope, OwnedOpaqueExtension, OwnedProviderId, OwnedVersionedId,
    PayloadSanitizationReceipt, PayloadSanitizationReceiptParts, PinnedFallbackPolicy,
    ProviderCall, ProviderCallParts, ProviderDescriptor, ProviderLimits, ProviderOperation,
    ProviderReply, SanitizationDisposition, TerminalRecord, UNKNOWN_EFFECT_RECONCILIATION_ACTION,
    WithheldReason, empty_opaque_extensions_digest, opaque_extensions_digest,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALT_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RESOLVED_SCOPE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const EMPTY_OBJECT_DIGEST: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

fn capability(value: &str) -> Result<OwnedVersionedId, ApiError> {
    OwnedVersionedId::new(value)
}

fn provider_id() -> Result<OwnedProviderId, ApiError> {
    OwnedProviderId::new("test.provider")
}

fn scope() -> Result<OwnedExactScope, ApiError> {
    OwnedExactScope::new(
        "profile-1",
        "project-1",
        "repo-1",
        "worktree-1",
        "refs/heads/main",
        "session-1",
        RESOLVED_SCOPE_DIGEST,
    )
}

fn limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 1024,
        response_bytes: 2048,
        observation_batch_items: 8,
        recall_candidates: 16,
        concurrent_operations: 2,
        operation_millis: 500,
        snapshot_bytes: 4096,
        inspection_items: 64,
    }
}

fn descriptor() -> Result<ProviderDescriptor, ApiError> {
    ProviderDescriptor::new(
        provider_id()?,
        DIGEST,
        "state.v1",
        0,
        [
            capability("provider.health.v1")?,
            capability("observation.accept.v1")?,
            capability("recall.query.v1")?,
        ],
        limits(),
    )
}

fn payload() -> Result<CanonicalPayload, ApiError> {
    CanonicalPayload::new(
        capability("tracedecay.memory.test-request.v1")?,
        br#"{}"#.to_vec(),
        EMPTY_OBJECT_DIGEST,
    )
}

fn extension() -> Result<OwnedOpaqueExtension, ApiError> {
    OwnedOpaqueExtension::new(
        capability("vendor.test-extension.v1")?,
        1,
        false,
        EMPTY_OBJECT_DIGEST,
        br#"{}"#.to_vec(),
    )
}

fn effect_for_state(state: CommittedEffectState) -> Result<CommittedEffectEvidence, ApiError> {
    match state {
        CommittedEffectState::None => Ok(CommittedEffectEvidence::none(Some(7))),
        CommittedEffectState::Committed => CommittedEffectEvidence::committed(
            7,
            8,
            vec!["item-committed".to_owned()],
            DIGEST,
            DIGEST,
        ),
        CommittedEffectState::Partial => CommittedEffectEvidence::partial(
            "after:item-committed",
            7,
            8,
            vec!["item-committed".to_owned()],
            vec!["item-uncommitted".to_owned()],
            DIGEST,
            "resume:item-uncommitted",
            DIGEST,
        ),
        CommittedEffectState::Duplicate => {
            CommittedEffectEvidence::duplicate(7, DIGEST, "observe-operation-1", DIGEST)
        }
        CommittedEffectState::Unknown => {
            CommittedEffectEvidence::unknown(DIGEST, "reconcile:operation")
        }
    }
}

fn effect_is_allowed(
    terminal_code: TerminalCode,
    expectation: CommittedEffectExpectation,
    state: CommittedEffectState,
) -> bool {
    // A duplicate acknowledgement is a complete success. `operation_specific`
    // also covers the degraded `partial` terminal, so the expectation alone is
    // not enough: the code must be `success` too.
    if state == CommittedEffectState::Duplicate {
        return terminal_code == TerminalCode::Success
            && matches!(
                expectation,
                CommittedEffectExpectation::OperationSpecific
                    | CommittedEffectExpectation::NoneOrOperationSpecific
            );
    }
    match expectation {
        CommittedEffectExpectation::OperationSpecific
        | CommittedEffectExpectation::NoneOrOperationSpecific => {
            matches!(
                state,
                CommittedEffectState::None | CommittedEffectState::Committed
            )
        }
        CommittedEffectExpectation::None => state == CommittedEffectState::None,
        CommittedEffectExpectation::NonePartialOrUnknown => {
            state != CommittedEffectState::Committed
        }
        CommittedEffectExpectation::NoneOrUnknown => {
            matches!(
                state,
                CommittedEffectState::None | CommittedEffectState::Unknown
            )
        }
        CommittedEffectExpectation::Partial => state == CommittedEffectState::Partial,
        CommittedEffectExpectation::Unknown => state == CommittedEffectState::Unknown,
    }
}

fn validated_terminal(result: Result<TerminalRecord, ApiError>) -> TerminalRecord {
    match result {
        Ok(terminal) => terminal,
        Err(_) => std::process::abort(),
    }
}

fn diagnostic_for(code: TerminalCode) -> Option<String> {
    if matches!(
        code,
        TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
    ) {
        None
    } else {
        Some("diagnostic.provider.v1".to_owned())
    }
}

#[derive(Clone)]
struct TestProvider {
    descriptor: ProviderDescriptor,
}

impl MemoryProvider for TestProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        HandshakeResponse {
            terminal: validated_terminal(TerminalRecord::new(
                ProviderOperation::Handshake,
                self.descriptor.provider_id.clone(),
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
                FallbackDirective::forbidden(),
                request.request_id.clone(),
                DIGEST,
                None,
            )),
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some("test.provider.instance-1".to_owned()),
            state_namespace: Some("scope-1".to_owned()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
            ready_receipt_sha256: Some(DIGEST.to_owned()),
            warnings: Vec::new(),
        }
    }

    fn invoke(&self, call: &ProviderCall) -> ProviderReply {
        ProviderReply {
            terminal: validated_terminal(TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                TerminalCode::SuccessZeroResults,
                CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                DIGEST,
                None,
            )),
            payload: Some(call.payload.clone()),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: self.descriptor.state_generation,
        }
    }
}

#[test]
fn provider_and_capability_identifiers_use_generated_validation() {
    assert!(OwnedProviderId::new("tracedecay.native").is_ok());
    assert!(OwnedProviderId::new("TraceDecay").is_err());
    assert!(OwnedVersionedId::new("recall.query.v1").is_ok());
    assert!(OwnedVersionedId::new("recall.query").is_err());
}

#[test]
fn exact_scope_is_complete_and_borrowable() -> Result<(), ApiError> {
    let scope = scope()?;
    assert_eq!(scope.validate(), Ok(()));
    let borrowed = scope.borrowed();
    assert_eq!(borrowed.project_id, "project-1");
    assert_eq!(borrowed.worktree_identity, "worktree-1");
    assert_eq!(borrowed.resolved_scope_digest, RESOLVED_SCOPE_DIGEST);
    let digest = scope.exact_scope_sha256();
    assert_eq!(
        digest,
        "2f525c8c3d59bfa3d9729405c4f3f1307fade77494b6ddf251c89abc490f0a52"
    );
    assert_eq!(digest, scope.clone().exact_scope_sha256());
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let mut variants = Vec::new();
    let mut changed = scope.clone();
    changed.profile_id.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.project_id.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.repository_identity.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.worktree_identity.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.branch_identity.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.agent_session_id.push_str("-changed");
    variants.push(changed);
    let mut changed = scope.clone();
    changed.resolved_scope_digest =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned();
    variants.push(changed);
    assert!(
        variants
            .iter()
            .all(|variant| variant.exact_scope_sha256() != digest)
    );

    let left = OwnedExactScope::new(
        "ab",
        "c",
        "repo",
        "worktree",
        "branch",
        "session",
        RESOLVED_SCOPE_DIGEST,
    )?;
    let right = OwnedExactScope::new(
        "a",
        "bc",
        "repo",
        "worktree",
        "branch",
        "session",
        RESOLVED_SCOPE_DIGEST,
    )?;
    assert_ne!(left.exact_scope_sha256(), right.exact_scope_sha256());
    Ok(())
}

#[test]
fn exact_scope_rejects_malformed_resolved_scope_digests() {
    for invalid in [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sha256:1111",
        "sha256:",
    ] {
        let error = OwnedExactScope::new(
            "profile-1",
            "project-1",
            "repo-1",
            "worktree-1",
            "refs/heads/main",
            "session-1",
            invalid,
        )
        .expect_err("malformed resolved scope digest must fail closed");
        assert_eq!(error, ApiError::InvalidSha256("resolved_scope_digest"));
    }
}

#[test]
fn request_control_distinguishes_cancellation_and_deadline() -> Result<(), TerminalCode> {
    let cancellation = CancellationToken::new();
    let control = OperationControl::new(i64::MAX, 10, cancellation.clone());
    assert!(control.snapshot().is_ok());
    cancellation.cancel();
    assert_eq!(control.snapshot(), Err(TerminalCode::Cancelled));

    let expired = OperationControl::new(i64::MAX, 0, CancellationToken::new());
    assert_eq!(expired.snapshot(), Err(TerminalCode::DeadlineExceeded));

    let wall_clock_expired = OperationControl::new(1, 10, CancellationToken::new());
    assert_eq!(
        wall_clock_expired.snapshot(),
        Err(TerminalCode::DeadlineExceeded)
    );

    let decaying = OperationControl::new(i64::MAX, 10_000, CancellationToken::new());
    std::thread::sleep(Duration::from_millis(2));
    let snapshot = decaying.snapshot()?;
    assert!(snapshot.remaining_millis > 0);
    assert!(snapshot.remaining_millis < 10_000);

    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX);
    let short_wall_deadline = now_micros.saturating_add(20_000);
    let wall_capped = OperationControl::new(short_wall_deadline, 10_000, CancellationToken::new());
    let snapshot = wall_capped.snapshot()?;
    assert!(snapshot.remaining_millis > 0);
    assert!(snapshot.remaining_millis <= 20);
    assert!(wall_capped.remaining_millis() <= 20);
    std::thread::sleep(Duration::from_millis(25));
    assert_eq!(wall_capped.snapshot(), Err(TerminalCode::DeadlineExceeded));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let both_terminal = OperationControl::new(1, 0, cancelled);
    assert_eq!(both_terminal.snapshot(), Err(TerminalCode::Cancelled));
    Ok(())
}

#[test]
fn descriptor_requires_all_mandatory_capabilities() -> Result<(), ApiError> {
    let result = ProviderDescriptor::new(
        provider_id()?,
        DIGEST,
        "state.v1",
        0,
        [capability("provider.health.v1")?],
        limits(),
    );
    assert!(matches!(
        result,
        Err(ApiError::MandatoryCapabilityMissing("recall.query.v1"))
    ));
    // Health and recall are complete: observation is an optional capability
    // that only observation delivery requires.
    let recall_only = ProviderDescriptor::new(
        provider_id()?,
        DIGEST,
        "state.v1",
        0,
        [
            capability("provider.health.v1")?,
            capability("recall.query.v1")?,
        ],
        limits(),
    )?;
    assert!(!recall_only.supports("observation.accept.v1"));
    Ok(())
}

#[test]
fn descriptor_revalidates_public_boundary_fields() -> Result<(), ApiError> {
    let mut invalid = descriptor()?;
    invalid.implementation_identity_sha256.clear();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::InvalidSha256("implementation_identity_sha256"))
    );

    let mut invalid = descriptor()?;
    invalid.state_schema_version.clear();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::EmptyField("state_schema_version"))
    );

    let mut invalid = descriptor()?;
    invalid.protocol_minor = 1;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::IncompatibleProtocol { major: 1, minor: 1 })
    );

    let mut invalid = descriptor()?;
    invalid.capabilities.remove(&capability("recall.query.v1")?);
    assert_eq!(
        invalid.validate(),
        Err(ApiError::MandatoryCapabilityMissing("recall.query.v1"))
    );

    let mut invalid = descriptor()?;
    invalid.limits.request_bytes = 0;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ZeroLimit("request_bytes"))
    );
    Ok(())
}

#[test]
fn canonical_payload_rebinds_bytes_to_declared_digest_after_mutation() -> Result<(), ApiError> {
    let valid = payload()?;
    assert_eq!(valid.validate(), Ok(()));

    let mut invalid = valid.clone();
    invalid.bytes.push(b' ');
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ContentDigestMismatch("payload_sha256"))
    );

    let mut invalid = valid;
    invalid.sha256 = ALT_DIGEST.to_owned();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ContentDigestMismatch("payload_sha256"))
    );
    Ok(())
}

#[test]
fn opaque_extension_revalidates_metadata_and_content_after_mutation() -> Result<(), ApiError> {
    let valid = extension()?;
    assert_eq!(valid.validate(), Ok(()));

    let mut invalid = valid.clone();
    invalid.extension_version = 0;
    assert_eq!(invalid.validate(), Err(ApiError::InvalidExtensionVersion));

    let mut invalid = valid;
    invalid.canonical_payload.push(b' ');
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ContentDigestMismatch("extension_payload_sha256"))
    );
    Ok(())
}

/// Smallest request budget that admits `call`.
///
/// `validate_request_bytes` refuses when the accounted aggregate is strictly
/// greater than the budget, so the smallest admitting budget *is* the accounted
/// aggregate. Binary searching for it keeps the accounting private while still
/// making it observable, which is what lets the boundary test below be
/// falsifiable without pinning a magic byte count.
fn accounted_request_bytes(call: &ProviderCall) -> u64 {
    let mut low = 0_u64;
    let mut high = 1_u64 << 24;
    assert_eq!(
        call.validate_request_bytes(high),
        Ok(()),
        "call must fit the search ceiling"
    );
    while low < high {
        let middle = low + (high - low) / 2;
        if call.validate_request_bytes(middle).is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

fn call_with_scope(exact_scope: OwnedExactScope) -> Result<ProviderCall, ApiError> {
    ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope,
        request_id: "request-boundary".to_owned(),
        operation_id: "operation-boundary".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: vec![extension()?],
    })
}

/// Every one of the seven exact-scope strings must be length-framed into the
/// request accounting — including `resolved_scope_digest`, the tagged digest
/// that replaced the old fixed-width `scope_revision` counter.
///
/// A `resolved_scope_digest` that is not framed makes a call carrying a longer
/// resolved scope look identical in size to one carrying a shorter one, so a
/// provider's `request_bytes` limit stops bounding the largest thing the call
/// actually carries. The seventh assertion below is the one the stale
/// six-string accounting failed.
#[test]
fn request_accounting_frames_every_exact_scope_string() -> Result<(), ApiError> {
    const PADDING: usize = 17;

    let baseline = call_with_scope(scope()?)?;
    let baseline_bytes = accounted_request_bytes(&baseline);

    let extended = |mutate: fn(&mut OwnedExactScope)| -> Result<u64, ApiError> {
        let mut exact_scope = scope()?;
        mutate(&mut exact_scope);
        exact_scope.validate()?;
        Ok(accounted_request_bytes(&call_with_scope(exact_scope)?))
    };

    for (field, mutate) in [
        (
            "profile_id",
            (|scope: &mut OwnedExactScope| {
                scope.profile_id.push_str(&"p".repeat(PADDING));
            }) as fn(&mut OwnedExactScope),
        ),
        ("project_id", |scope: &mut OwnedExactScope| {
            scope.project_id.push_str(&"j".repeat(PADDING));
        }),
        ("repository_identity", |scope: &mut OwnedExactScope| {
            scope.repository_identity.push_str(&"r".repeat(PADDING));
        }),
        ("worktree_identity", |scope: &mut OwnedExactScope| {
            scope.worktree_identity.push_str(&"w".repeat(PADDING));
        }),
        ("branch_identity", |scope: &mut OwnedExactScope| {
            scope.branch_identity.push_str(&"b".repeat(PADDING));
        }),
        ("agent_session_id", |scope: &mut OwnedExactScope| {
            scope.agent_session_id.push_str(&"s".repeat(PADDING));
        }),
    ] {
        assert_eq!(
            extended(mutate)?,
            baseline_bytes + PADDING as u64,
            "exact-scope field {field} must be length-framed into the request accounting"
        );
    }

    // The seventh string is fixed-length, so its presence is proven by removing
    // it from the accounted value rather than by lengthening it: a call whose
    // resolved scope digest is absent from the accounting would be admitted at
    // a budget that cannot hold it.
    let without_seventh = baseline_bytes
        .checked_sub(8 + RESOLVED_SCOPE_DIGEST.len() as u64)
        .expect("resolved_scope_digest must be inside the accounted aggregate");
    assert_eq!(
        baseline.validate_request_bytes(without_seventh),
        Err(ApiError::BoundaryBytesExceeded {
            field: "request",
            maximum: without_seventh,
        }),
        "resolved_scope_digest must be counted; a budget short by exactly its \
         framed size must refuse the call"
    );
    Ok(())
}

#[test]
fn provider_call_revalidates_public_and_nested_fields_after_mutation() -> Result<(), ApiError> {
    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-boundary".to_owned(),
        operation_id: "operation-boundary".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: vec![extension()?],
    })?;
    assert_eq!(call.validate(), Ok(()));
    assert_eq!(call.validate_request_bytes(1_024), Ok(()));
    assert_eq!(
        call.validate_request_bytes(1),
        Err(ApiError::BoundaryBytesExceeded {
            field: "request",
            maximum: 1,
        })
    );

    let mut invalid = call.clone();
    invalid.exact_scope.project_id.clear();
    assert_eq!(invalid.validate(), Err(ApiError::EmptyField("project_id")));

    let mut invalid = call.clone();
    invalid.registration_revision = 0;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::InvalidRegistrationRevision)
    );

    let mut invalid = call.clone();
    invalid.request_id = " request-boundary ".to_owned();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::NonCanonicalTerminalText("request_id"))
    );

    let mut invalid = call.clone();
    invalid.request_id =
        "x".repeat(tracedecay_memory_provider_api::contract::TERMINAL_OPERATION_ID_MAX_BYTES + 1);
    assert_eq!(
        invalid.validate(),
        Err(ApiError::TerminalTextTooLong {
            field: "request_id",
            maximum: tracedecay_memory_provider_api::contract::TERMINAL_OPERATION_ID_MAX_BYTES,
        })
    );

    let mut invalid = call.clone();
    invalid.ready_receipt_sha256.clear();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::InvalidSha256("ready_receipt_sha256"))
    );

    let mut invalid = call.clone();
    invalid.operation_id = " operation-boundary ".to_owned();
    assert_eq!(
        invalid.validate(),
        Err(ApiError::NonCanonicalTerminalText("operation_id"))
    );

    let mut invalid = call.clone();
    invalid.idempotency_key = Some(String::new());
    assert_eq!(
        invalid.validate(),
        Err(ApiError::NonCanonicalTerminalText("idempotency_key"))
    );

    let mut invalid = call.clone();
    invalid.operation = ProviderOperation::Observe;
    assert_eq!(invalid.validate(), Err(ApiError::MissingIdempotencyKey));

    let mut invalid = call.clone();
    invalid.operation = ProviderOperation::Health;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::MissingOperationCapability("provider.health.v1"))
    );

    let mut invalid = call.clone();
    invalid.payload.bytes.push(b' ');
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ContentDigestMismatch("payload_sha256"))
    );

    let mut invalid = call.clone();
    invalid.extensions[0].canonical_payload.push(b' ');
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ContentDigestMismatch("extension_payload_sha256"))
    );

    let mut invalid = call;
    invalid.extensions = vec![extension()?; 17];
    assert_eq!(
        invalid.validate(),
        Err(ApiError::TooManyBoundaryItems {
            field: "extensions",
            maximum: 16,
        })
    );
    Ok(())
}

#[test]
fn handshake_request_revalidates_public_fields_after_mutation() -> Result<(), ApiError> {
    let request = HandshakeRequest::new(HandshakeRequestParts {
        provider_id: provider_id()?,
        registration_revision: 1,
        exact_scope: scope()?,
        request_id: "handshake-boundary".to_owned(),
        required_capabilities: vec![capability("provider.health.v1")?],
        host_limits: limits(),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        challenge_nonce: [7; 32],
    })?;
    assert_eq!(request.validate(), Ok(()));

    let mut invalid = request.clone();
    invalid.request_id.clear();
    assert_eq!(invalid.validate(), Err(ApiError::EmptyField("request_id")));

    let mut invalid = request.clone();
    invalid.registration_revision = 0;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::InvalidRegistrationRevision)
    );

    let mut invalid = request;
    invalid.host_limits.response_bytes = 0;
    assert_eq!(
        invalid.validate(),
        Err(ApiError::ZeroLimit("response_bytes"))
    );
    Ok(())
}

#[test]
fn provider_reply_revalidates_nested_content_and_response_bounds() -> Result<(), ApiError> {
    let terminal = TerminalRecord::new(
        ProviderOperation::Recall,
        provider_id()?,
        TerminalCode::SuccessZeroResults,
        CommittedEffectEvidence::none(Some(7)),
        FallbackDirective::forbidden(),
        "operation-reply-boundary",
        DIGEST,
        None,
    )?;
    let reply = ProviderReply {
        terminal,
        payload: Some(payload()?),
        warnings: Vec::new(),
        extensions: vec![extension()?],
        state_generation: 7,
    };
    assert_eq!(reply.validate(1_024), Ok(()));

    let mut invalid = reply.clone();
    if let Some(payload) = &mut invalid.payload {
        payload.bytes.push(b' ');
    }
    assert_eq!(
        invalid.validate(1_024),
        Err(ApiError::ContentDigestMismatch("payload_sha256"))
    );

    let mut invalid = reply.clone();
    invalid.warnings = vec!["warning".to_owned(); 33];
    assert_eq!(
        invalid.validate(1_024),
        Err(ApiError::TooManyBoundaryItems {
            field: "warnings",
            maximum: 32,
        })
    );

    let mut invalid = reply.clone();
    invalid.extensions = vec![extension()?; 17];
    assert_eq!(
        invalid.validate(8_192),
        Err(ApiError::TooManyBoundaryItems {
            field: "extensions",
            maximum: 16,
        })
    );

    assert_eq!(
        reply.validate(1),
        Err(ApiError::BoundaryBytesExceeded {
            field: "response",
            maximum: 1,
        })
    );

    let failure_terminal = TerminalRecord::new(
        ProviderOperation::Recall,
        provider_id()?,
        TerminalCode::InvalidRequest,
        CommittedEffectEvidence::none(Some(7)),
        FallbackDirective::forbidden(),
        "operation-reply-failure",
        DIGEST,
        Some("diagnostic.invalid-request.v1".to_owned()),
    )?;
    let invalid = ProviderReply {
        terminal: failure_terminal,
        ..reply
    };
    assert_eq!(
        invalid.validate(1_024),
        Err(ApiError::PayloadForbiddenForTerminal {
            terminal_code: TerminalCode::InvalidRequest,
        })
    );
    Ok(())
}

#[test]
fn provider_limits_enforce_every_canonical_bound() {
    let maximum = ProviderLimits {
        request_bytes: 16_777_216,
        response_bytes: 33_554_432,
        observation_batch_items: 4_096,
        recall_candidates: 10_000,
        concurrent_operations: 1_024,
        operation_millis: 3_600_000,
        snapshot_bytes: 1_073_741_824,
        inspection_items: 100_000,
    };
    assert_eq!(maximum.validate(), Ok(maximum));

    for catalog in PROVIDER_LIMITS {
        let mut candidate = maximum;
        let value = catalog.maximum.saturating_add(1);
        match catalog.limit_id {
            "request_bytes" => candidate.request_bytes = value,
            "response_bytes" => candidate.response_bytes = value,
            "observation_batch_items" => candidate.observation_batch_items = value,
            "recall_candidates" => candidate.recall_candidates = value,
            "concurrent_operations" => candidate.concurrent_operations = value,
            "operation_millis" => candidate.operation_millis = value,
            "snapshot_bytes" => candidate.snapshot_bytes = value,
            "inspection_items" => candidate.inspection_items = value,
            _ => continue,
        }
        assert_eq!(
            candidate.validate(),
            Err(ApiError::LimitExceedsMaximum {
                limit: catalog.limit_id,
                maximum: catalog.maximum,
            })
        );
    }
}

#[test]
fn provider_limits_reject_zero_for_every_catalog_row() {
    for catalog in PROVIDER_LIMITS {
        let mut candidate = limits();
        match catalog.limit_id {
            "request_bytes" => candidate.request_bytes = 0,
            "response_bytes" => candidate.response_bytes = 0,
            "observation_batch_items" => candidate.observation_batch_items = 0,
            "recall_candidates" => candidate.recall_candidates = 0,
            "concurrent_operations" => candidate.concurrent_operations = 0,
            "operation_millis" => candidate.operation_millis = 0,
            "snapshot_bytes" => candidate.snapshot_bytes = 0,
            "inspection_items" => candidate.inspection_items = 0,
            _ => continue,
        }
        assert_eq!(
            candidate.validate(),
            Err(ApiError::ZeroLimit(catalog.limit_id))
        );
    }
}

#[test]
fn handshake_and_call_revalidate_every_exact_scope_identity() -> Result<(), ApiError> {
    for field in [
        "profile_id",
        "project_id",
        "repository_identity",
        "worktree_identity",
        "branch_identity",
        "agent_session_id",
    ] {
        let mut invalid_scope = scope()?;
        match field {
            "profile_id" => invalid_scope.profile_id.clear(),
            "project_id" => invalid_scope.project_id.clear(),
            "repository_identity" => invalid_scope.repository_identity.clear(),
            "worktree_identity" => invalid_scope.worktree_identity.clear(),
            "branch_identity" => invalid_scope.branch_identity.clear(),
            "agent_session_id" => invalid_scope.agent_session_id.clear(),
            _ => continue,
        }
        assert_eq!(invalid_scope.validate(), Err(ApiError::EmptyField(field)));
        let handshake = HandshakeRequest::new(HandshakeRequestParts {
            provider_id: provider_id()?,
            registration_revision: 1,
            exact_scope: invalid_scope.clone(),
            request_id: "handshake-request".to_owned(),
            required_capabilities: vec![capability("provider.health.v1")?],
            host_limits: limits(),
            control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
            challenge_nonce: [7; 32],
        });
        assert!(matches!(handshake, Err(ApiError::EmptyField(actual)) if actual == field));

        let call = ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Recall,
            provider_id: provider_id()?,
            registration_revision: 1,
            ready_receipt_sha256: DIGEST.to_owned(),
            exact_scope: invalid_scope,
            request_id: "request-invalid-scope".to_owned(),
            operation_id: "operation-invalid-scope".to_owned(),
            expected_state_generation: 0,
            idempotency_key: None,
            control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
            payload: payload()?,
            required_capabilities: vec![capability("recall.query.v1")?],
            extensions: Vec::new(),
        });
        assert!(matches!(call, Err(ApiError::EmptyField(actual)) if actual == field));
    }
    Ok(())
}

#[test]
fn duplicate_capabilities_are_rejected() -> Result<(), ApiError> {
    let duplicate = capability("provider.health.v1")?;
    let result = ProviderDescriptor::new(
        provider_id()?,
        DIGEST,
        "state.v1",
        0,
        [
            duplicate.clone(),
            duplicate,
            capability("observation.accept.v1")?,
            capability("recall.query.v1")?,
        ],
        limits(),
    );
    assert!(matches!(result, Err(ApiError::DuplicateCapability(_))));
    Ok(())
}

#[test]
fn mutating_calls_require_idempotency_and_operation_capability() -> Result<(), ApiError> {
    let parts = ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("observation.accept.v1")?],
        extensions: Vec::new(),
    };
    assert!(matches!(
        ProviderCall::new(parts),
        Err(ApiError::MissingIdempotencyKey)
    ));

    let missing_capability = ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-2".to_owned(),
        operation_id: "operation-2".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("provider.health.v1")?],
        extensions: Vec::new(),
    };
    assert!(matches!(
        ProviderCall::new(missing_capability),
        Err(ApiError::MissingOperationCapability("recall.query.v1"))
    ));
    Ok(())
}

#[test]
fn trait_object_executes_typed_handshake_and_call() -> Result<(), ApiError> {
    let provider: Box<dyn MemoryProvider> = Box::new(TestProvider {
        descriptor: descriptor()?,
    });
    let handshake = HandshakeRequest::new(HandshakeRequestParts {
        provider_id: provider_id()?,
        registration_revision: 1,
        exact_scope: scope()?,
        request_id: "handshake-request".to_owned(),
        required_capabilities: vec![
            capability("provider.health.v1")?,
            capability("observation.accept.v1")?,
            capability("recall.query.v1")?,
        ],
        host_limits: limits(),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        challenge_nonce: [7; 32],
    })?;
    let response = provider.handshake(&handshake);
    assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
    let ready_descriptor = match response.descriptor.as_ref() {
        Some(value) => value,
        None => return Err(ApiError::EmptyField("ready_descriptor")),
    };
    assert_eq!(ready_descriptor.provider_id.as_str(), "test.provider");

    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-3".to_owned(),
        operation_id: "operation-3".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: Vec::new(),
    })?;
    let reply = provider.invoke(&call);
    assert_eq!(
        reply.terminal.terminal_code(),
        TerminalCode::SuccessZeroResults
    );
    assert_eq!(
        reply.terminal.fallback().eligibility(),
        FallbackEligibility::Forbidden
    );
    Ok(())
}

#[test]
fn committed_effect_factories_retain_borrowed_structured_evidence() -> Result<(), ApiError> {
    let none = CommittedEffectEvidence::none(None);
    assert_eq!(none.state(), CommittedEffectState::None);
    assert_eq!(none.state_generation_before(), None);
    assert_eq!(none.provider_receipt_sha256(), None);

    let committed = effect_for_state(CommittedEffectState::Committed)?;
    assert_eq!(committed.state_generation_before(), Some(7));
    assert_eq!(committed.state_generation_after(), Some(8));
    assert_eq!(committed.committed_item_refs(), &["item-committed"]);
    assert!(committed.uncommitted_item_refs().is_empty());
    assert_eq!(committed.provider_receipt_sha256(), Some(DIGEST));
    assert_eq!(committed.verification_sha256(), Some(DIGEST));

    let partial = effect_for_state(CommittedEffectState::Partial)?;
    assert_eq!(partial.committed_boundary(), Some("after:item-committed"));
    assert_eq!(
        partial.reconciliation_action(),
        Some("resume:item-uncommitted")
    );
    assert_eq!(
        partial.borrowed().uncommitted_item_refs,
        &["item-uncommitted"]
    );

    let unknown = effect_for_state(CommittedEffectState::Unknown)?;
    assert_eq!(unknown.state_generation_before(), None);
    assert_eq!(unknown.state_generation_after(), None);
    assert_eq!(unknown.committed_boundary(), None);
    assert_eq!(unknown.reconciliation_action(), Some("reconcile:operation"));
    assert_eq!(unknown.verification_sha256(), None);
    Ok(())
}

/// Builds a duplicate-acknowledgement terminal for `call` naming
/// `deduplicated_key` as the key the provider matched.
fn duplicate_terminal_naming(
    call: &ProviderCall,
    deduplicated_key: &str,
) -> Result<TerminalRecord, ApiError> {
    let effect = CommittedEffectEvidence::duplicate(
        call.expected_state_generation,
        deduplicated_key,
        "operation-request-original",
        DIGEST,
    )?;
    TerminalRecord::new(
        call.operation,
        call.provider_id.clone(),
        TerminalCode::Success,
        effect,
        FallbackDirective::forbidden(),
        call.operation_id.clone(),
        call.exact_scope.exact_scope_sha256(),
        None,
    )
}

#[test]
fn duplicate_acknowledgement_is_bound_to_the_calls_own_idempotency_key() -> Result<(), ApiError> {
    let call = ProviderCall::new(observe_parts("request-duplicate")?)?;
    let request_key = call
        .idempotency_key
        .clone()
        .ok_or(ApiError::EmptyField("idempotency_key"))?;

    let terminal = duplicate_terminal_naming(&call, &request_key)?;
    let effect = terminal.committed_effect();
    assert_eq!(terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(effect.state(), CommittedEffectState::Duplicate);
    assert_eq!(effect.duplicate_of_idempotency_key(), Some(&*request_key));
    assert_eq!(
        effect.duplicate_of_operation_id(),
        Some("operation-request-original")
    );
    // Nothing new committed, so the generation must not move.
    assert_eq!(effect.state_generation_before(), Some(0));
    assert_eq!(effect.state_generation_after(), Some(0));
    assert_eq!(effect.provider_receipt_sha256(), Some(DIGEST));
    assert!(effect.committed_item_refs().is_empty());
    assert_eq!(effect.verification_sha256(), None);
    assert_eq!(terminal.validate_duplicate_binding_for_call(&call), Ok(()));

    // A duplicate that names some other mutation proves nothing about this
    // delivery, so the dispatch boundary refuses it.
    let misbound = duplicate_terminal_naming(&call, "idempotency-key-of-another-mutation")?;
    assert_eq!(
        misbound.validate_duplicate_binding_for_call(&call),
        Err(ApiError::DuplicateEffectKeyMismatch)
    );
    Ok(())
}

#[test]
fn duplicate_acknowledgement_is_refused_without_a_request_key_or_on_a_read() -> Result<(), ApiError>
{
    let call = ProviderCall::new(observe_parts("request-keyless")?)?;
    let request_key = call
        .idempotency_key
        .clone()
        .ok_or(ApiError::EmptyField("idempotency_key"))?;
    let terminal = duplicate_terminal_naming(&call, &request_key)?;

    let mut keyless = call;
    // Public boundary fields are revalidated after mutation. A duplicate must
    // still be impossible to settle once the validated call loses its key.
    keyless.idempotency_key = None;
    assert_eq!(
        terminal.validate_duplicate_binding_for_call(&keyless),
        Err(ApiError::DuplicateEffectWithoutRequestKey)
    );

    // A read operation cannot carry a committed effect at all, so a duplicate
    // terminal for one cannot be constructed in the first place.
    let recall = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-recall-duplicate".to_owned(),
        operation_id: "operation-recall-duplicate".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: Vec::new(),
    })?;
    assert_eq!(
        duplicate_terminal_naming(&recall, "any-key"),
        Err(ApiError::ReadOnlyOperationEffect {
            operation: ProviderOperation::Recall,
            effect_state: CommittedEffectState::Duplicate,
        })
    );
    Ok(())
}

#[test]
fn duplicate_evidence_rejects_moved_generations_and_unbound_or_misplaced_identity() {
    // A duplicate that advances the generation is applying, not deduplicating.
    let moved = CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
        state: CommittedEffectState::Duplicate,
        committed_boundary: None,
        state_generation_before: Some(1),
        state_generation_after: Some(2),
        committed_item_refs: Vec::new(),
        uncommitted_item_refs: Vec::new(),
        provider_receipt_sha256: Some(DIGEST.to_owned()),
        reconciliation_action: None,
        verification_sha256: None,
        duplicate_of_idempotency_key: Some(DIGEST.to_owned()),
        duplicate_of_operation_id: Some("operation-original".to_owned()),
    });
    assert_eq!(moved, Err(ApiError::InvalidEffectGenerations));

    let unnamed = CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
        state: CommittedEffectState::Duplicate,
        committed_boundary: None,
        state_generation_before: Some(1),
        state_generation_after: Some(1),
        committed_item_refs: Vec::new(),
        uncommitted_item_refs: Vec::new(),
        provider_receipt_sha256: Some(DIGEST.to_owned()),
        reconciliation_action: None,
        verification_sha256: None,
        duplicate_of_idempotency_key: None,
        duplicate_of_operation_id: None,
    });
    assert!(matches!(unnamed, Err(ApiError::InvalidCommittedEffect(_))));

    // Duplicate identity on any other state would let a provider decorate an
    // ordinary commit with a deduplication claim.
    let misplaced = CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
        state: CommittedEffectState::Committed,
        committed_boundary: None,
        state_generation_before: Some(1),
        state_generation_after: Some(2),
        committed_item_refs: vec!["done".to_owned()],
        uncommitted_item_refs: Vec::new(),
        provider_receipt_sha256: Some(DIGEST.to_owned()),
        reconciliation_action: None,
        verification_sha256: Some(DIGEST.to_owned()),
        duplicate_of_idempotency_key: Some(DIGEST.to_owned()),
        duplicate_of_operation_id: Some("operation-original".to_owned()),
    });
    assert!(matches!(
        misplaced,
        Err(ApiError::InvalidCommittedEffect(_))
    ));
}

#[test]
fn committed_effect_rejects_generation_and_state_field_contradictions() {
    let none_with_one_generation =
        CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::None,
            committed_boundary: None,
            state_generation_before: Some(1),
            state_generation_after: None,
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: None,
            reconciliation_action: None,
            verification_sha256: None,
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        });
    assert_eq!(
        none_with_one_generation,
        Err(ApiError::InvalidEffectGenerations)
    );

    let none_with_receipt = CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
        state: CommittedEffectState::None,
        committed_boundary: None,
        state_generation_before: Some(1),
        state_generation_after: Some(1),
        committed_item_refs: Vec::new(),
        uncommitted_item_refs: Vec::new(),
        provider_receipt_sha256: Some(DIGEST.to_owned()),
        reconciliation_action: None,
        verification_sha256: None,
        duplicate_of_idempotency_key: None,
        duplicate_of_operation_id: None,
    });
    assert!(matches!(
        none_with_receipt,
        Err(ApiError::InvalidCommittedEffect(_))
    ));

    assert_eq!(
        CommittedEffectEvidence::committed(2, 1, Vec::new(), DIGEST, DIGEST),
        Err(ApiError::InvalidEffectGenerations)
    );

    let committed_with_uncommitted =
        CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Committed,
            committed_boundary: None,
            state_generation_before: Some(1),
            state_generation_after: Some(2),
            committed_item_refs: vec!["done".to_owned()],
            uncommitted_item_refs: vec!["pending".to_owned()],
            provider_receipt_sha256: Some(DIGEST.to_owned()),
            reconciliation_action: None,
            verification_sha256: Some(DIGEST.to_owned()),
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        });
    assert!(matches!(
        committed_with_uncommitted,
        Err(ApiError::InvalidCommittedEffect(_))
    ));

    let unknown_with_generation =
        CommittedEffectEvidence::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Unknown,
            committed_boundary: None,
            state_generation_before: Some(1),
            state_generation_after: None,
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: Some(DIGEST.to_owned()),
            reconciliation_action: Some("reconcile".to_owned()),
            verification_sha256: None,
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        });
    assert!(matches!(
        unknown_with_generation,
        Err(ApiError::InvalidCommittedEffect(_))
    ));
}

#[test]
fn partial_effect_requires_bounded_unique_disjoint_nonempty_partitions() {
    let overlap = CommittedEffectEvidence::partial(
        "boundary",
        1,
        2,
        vec!["same".to_owned()],
        vec!["same".to_owned()],
        DIGEST,
        "reconcile",
        DIGEST,
    );
    assert_eq!(
        overlap,
        Err(ApiError::OverlappingEffectItemRef("same".to_owned()))
    );

    let duplicate = CommittedEffectEvidence::committed(
        1,
        2,
        vec!["same".to_owned(), "same".to_owned()],
        DIGEST,
        DIGEST,
    );
    assert_eq!(
        duplicate,
        Err(ApiError::DuplicateEffectItemRef("same".to_owned()))
    );

    let empty_item = CommittedEffectEvidence::committed(1, 2, vec![String::new()], DIGEST, DIGEST);
    assert_eq!(
        empty_item,
        Err(ApiError::NonCanonicalTerminalText("effect_item_ref"))
    );

    let too_long = CommittedEffectEvidence::committed(
        1,
        2,
        vec!["x".repeat(MAX_COMMITTED_EFFECT_ITEM_REF_BYTES + 1)],
        DIGEST,
        DIGEST,
    );
    assert_eq!(
        too_long,
        Err(ApiError::TerminalTextTooLong {
            field: "effect_item_ref",
            maximum: MAX_COMMITTED_EFFECT_ITEM_REF_BYTES,
        })
    );

    let too_many = CommittedEffectEvidence::committed(
        1,
        2,
        (0..=MAX_COMMITTED_EFFECT_ITEM_REFS)
            .map(|index| format!("item-{index}"))
            .collect(),
        DIGEST,
        DIGEST,
    );
    assert_eq!(
        too_many,
        Err(ApiError::TooManyEffectItemRefs {
            maximum: MAX_COMMITTED_EFFECT_ITEM_REFS,
        })
    );

    let empty_partition = CommittedEffectEvidence::partial(
        "boundary",
        1,
        2,
        Vec::new(),
        vec!["pending".to_owned()],
        DIGEST,
        "resume",
        DIGEST,
    );
    assert!(matches!(
        empty_partition,
        Err(ApiError::InvalidCommittedEffect(_))
    ));
}

#[test]
fn fallback_requires_complete_distinct_pinned_host_policy() -> Result<(), ApiError> {
    let current = provider_id()?;
    assert_eq!(
        PinnedFallbackPolicy::new("memory.fallback.policy", 0, OwnedProviderId::new("other")?),
        Err(ApiError::InvalidFallbackPolicyRevision)
    );
    let same_target = PinnedFallbackPolicy::new("memory.fallback.policy", 1, current.clone())?;
    assert_eq!(
        FallbackDirective::explicit_policy_only(&current, same_target, "provider unavailable"),
        Err(ApiError::FallbackTargetMatchesCurrentProvider)
    );

    let pin = PinnedFallbackPolicy::new(
        "memory.fallback.policy",
        7,
        OwnedProviderId::new("alternate.provider")?,
    )?;
    assert_eq!(
        FallbackDirective::explicit_policy_only(&current, pin.clone(), ""),
        Err(ApiError::NonCanonicalTerminalText("fallback_reason"))
    );
    let directive = FallbackDirective::explicit_policy_only(
        &current,
        pin,
        "explicit host policy selected an alternate",
    )?;
    assert_eq!(
        directive.eligibility(),
        FallbackEligibility::ExplicitPolicyOnly
    );
    let borrowed = directive.borrowed();
    assert_eq!(
        borrowed.reason,
        Some("explicit host policy selected an alternate")
    );
    assert_eq!(
        borrowed.policy.map(|policy| policy.policy_revision),
        Some(7)
    );
    assert_eq!(
        borrowed.policy.map(|policy| policy.target_provider_id),
        Some("alternate.provider")
    );

    let forbidden = FallbackDirective::forbidden();
    assert_eq!(forbidden.policy(), None);
    assert_eq!(forbidden.reason(), None);
    Ok(())
}

#[test]
fn every_terminal_code_enforces_generated_effect_and_fallback_matrix() -> Result<(), ApiError> {
    let current = provider_id()?;
    for policy in TERMINAL_CODE_POLICIES {
        for state in [
            CommittedEffectState::None,
            CommittedEffectState::Committed,
            CommittedEffectState::Duplicate,
            CommittedEffectState::Partial,
            CommittedEffectState::Unknown,
        ] {
            let result = TerminalRecord::new(
                ProviderOperation::Observe,
                current.clone(),
                policy.terminal_code,
                effect_for_state(state)?,
                FallbackDirective::forbidden(),
                "operation-matrix",
                DIGEST,
                diagnostic_for(policy.terminal_code),
            );
            assert_eq!(
                result.is_ok(),
                effect_is_allowed(policy.terminal_code, policy.effect_expectation, state),
                "effect matrix drift for {} and {}",
                policy.terminal_code.as_wire(),
                state.as_wire()
            );
        }

        let pin = PinnedFallbackPolicy::new(
            "memory.fallback.policy",
            1,
            OwnedProviderId::new("alternate.provider")?,
        )?;
        let explicit =
            FallbackDirective::explicit_policy_only(&current, pin, "explicit test host policy")?;
        let explicit_result = TerminalRecord::new(
            ProviderOperation::Observe,
            current.clone(),
            policy.terminal_code,
            effect_for_state(CommittedEffectState::None)?,
            explicit,
            "operation-fallback-matrix",
            DIGEST,
            diagnostic_for(policy.terminal_code),
        );
        let expected = policy.maximum_fallback_eligibility
            == FallbackEligibility::ExplicitPolicyOnly
            && effect_is_allowed(
                policy.terminal_code,
                policy.effect_expectation,
                CommittedEffectState::None,
            );
        assert_eq!(
            explicit_result.is_ok(),
            expected,
            "fallback matrix drift for {}",
            policy.terminal_code.as_wire()
        );
    }
    Ok(())
}

#[test]
fn terminal_record_requires_failure_diagnostic_and_owns_receipt_once() -> Result<(), ApiError> {
    let no_diagnostic = TerminalRecord::new(
        ProviderOperation::Recall,
        provider_id()?,
        TerminalCode::InvalidRequest,
        CommittedEffectEvidence::none(None),
        FallbackDirective::forbidden(),
        "operation-invalid",
        DIGEST,
        None,
    );
    assert_eq!(no_diagnostic, Err(ApiError::MissingFailureDiagnostic));

    let record = TerminalRecord::new(
        ProviderOperation::Observe,
        provider_id()?,
        TerminalCode::Success,
        effect_for_state(CommittedEffectState::Committed)?,
        FallbackDirective::forbidden(),
        "operation-success",
        DIGEST,
        None,
    )?;
    assert_eq!(
        record.committed_effect().state(),
        CommittedEffectState::Committed
    );
    assert_eq!(
        record.fallback().eligibility(),
        FallbackEligibility::Forbidden
    );
    assert_eq!(record.provider_receipt_sha256(), Some(DIGEST));
    assert_eq!(
        record.borrowed().committed_effect.provider_receipt_digest,
        Some(DIGEST)
    );
    assert_eq!(record.operation(), ProviderOperation::Observe);
    assert_eq!(record.provider_id().as_str(), "test.provider");
    assert_eq!(record.borrowed().operation_kind, "observe");
    assert_eq!(record.borrowed().provider_id, "test.provider");
    Ok(())
}

#[test]
fn read_only_operations_reject_every_non_none_effect() -> Result<(), ApiError> {
    for operation in [
        ProviderOperation::Handshake,
        ProviderOperation::Health,
        ProviderOperation::Recall,
        ProviderOperation::Inspection,
        ProviderOperation::SnapshotExport,
    ] {
        let result = TerminalRecord::new(
            operation,
            provider_id()?,
            TerminalCode::Success,
            effect_for_state(CommittedEffectState::Committed)?,
            FallbackDirective::forbidden(),
            "operation-read-only",
            DIGEST,
            None,
        );
        assert_eq!(
            result,
            Err(ApiError::ReadOnlyOperationEffect {
                operation,
                effect_state: CommittedEffectState::Committed,
            })
        );
    }
    Ok(())
}

#[test]
fn explicit_fallback_is_bound_to_the_exact_terminal_provider() -> Result<(), ApiError> {
    let source = OwnedProviderId::new("source.provider")?;
    let target = OwnedProviderId::new("target.provider")?;
    let policy = PinnedFallbackPolicy::new("memory.fallback.policy", 1, target.clone())?;
    let fallback = FallbackDirective::explicit_policy_only(&source, policy, "host policy")?;
    assert_eq!(fallback.source_provider_id(), Some(&source));

    let laundered = TerminalRecord::new(
        ProviderOperation::Observe,
        target,
        TerminalCode::CapabilityUnsupported,
        CommittedEffectEvidence::none(Some(1)),
        fallback,
        "operation-fallback",
        DIGEST,
        Some("diagnostic.fallback.v1".to_owned()),
    );
    assert_eq!(laundered, Err(ApiError::FallbackSourceProviderMismatch));
    Ok(())
}

#[test]
fn terminal_text_is_bounded_and_rejects_whitespace_or_controls() -> Result<(), ApiError> {
    assert_eq!(
        PinnedFallbackPolicy::new("   ", 1, OwnedProviderId::new("target.provider")?),
        Err(ApiError::NonCanonicalTerminalText("fallback_policy_id"))
    );
    assert_eq!(
        PinnedFallbackPolicy::new(
            "x".repeat(
                tracedecay_memory_provider_api::contract::TERMINAL_FALLBACK_POLICY_ID_MAX_BYTES + 1
            ),
            1,
            OwnedProviderId::new("target.provider")?,
        ),
        Err(ApiError::TerminalTextTooLong {
            field: "fallback_policy_id",
            maximum:
                tracedecay_memory_provider_api::contract::TERMINAL_FALLBACK_POLICY_ID_MAX_BYTES,
        })
    );

    let invalid_boundary = CommittedEffectEvidence::partial(
        " boundary ",
        1,
        2,
        vec!["done".to_owned()],
        vec!["pending".to_owned()],
        DIGEST,
        "resume",
        DIGEST,
    );
    assert_eq!(
        invalid_boundary,
        Err(ApiError::NonCanonicalTerminalText("committed_boundary"))
    );

    let invalid_diagnostic = TerminalRecord::new(
        ProviderOperation::Recall,
        provider_id()?,
        TerminalCode::InvalidRequest,
        CommittedEffectEvidence::none(None),
        FallbackDirective::forbidden(),
        "operation-invalid",
        DIGEST,
        Some("\n".to_owned()),
    );
    assert_eq!(
        invalid_diagnostic,
        Err(ApiError::NonCanonicalTerminalText("diagnostic_id"))
    );
    Ok(())
}

#[test]
fn pre_dispatch_failure_factory_is_infallible_and_normalizes_mutated_call() -> Result<(), ApiError>
{
    let mut call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-factory".to_owned(),
        operation_id: "operation-factory".to_owned(),
        expected_state_generation: 7,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: Vec::new(),
    })?;
    let expected_scope = call.exact_scope.exact_scope_sha256();
    let normal = TerminalRecord::failure_before_dispatch_for_call(
        TerminalCode::ProviderUnavailable,
        &call,
        "diagnostic.provider-unavailable.v1",
    );
    assert_eq!(normal.terminal_code(), TerminalCode::ProviderUnavailable);
    assert_eq!(normal.operation(), ProviderOperation::Recall);
    assert_eq!(normal.provider_id().as_str(), "test.provider");
    assert_eq!(normal.operation_id(), "operation-factory");
    assert_eq!(normal.exact_scope_sha256(), expected_scope);
    assert_eq!(normal.committed_effect().state_generation_before(), Some(7));

    call.operation_id = " mutated\nsecret ".to_owned();
    call.exact_scope.project_id.clear();
    let malformed =
        TerminalRecord::failure_before_dispatch_for_call(TerminalCode::PartialEffect, &call, "   ");
    assert_eq!(malformed.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(
        malformed.operation_id(),
        "tracedecay.internal-failure.operation.v1"
    );
    assert_eq!(
        malformed.diagnostic_id(),
        Some("tracedecay.memory.provider.internal-failure.v1")
    );
    assert_ne!(malformed.exact_scope_sha256(), expected_scope);
    assert!(
        malformed
            .exact_scope_sha256()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        malformed.committed_effect().state(),
        CommittedEffectState::None
    );
    Ok(())
}

#[test]
fn post_dispatch_internal_failure_preserves_validated_unknown_effect() -> Result<(), ApiError> {
    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-post-dispatch".to_owned(),
        operation_id: "operation-post-dispatch".to_owned(),
        expected_state_generation: 7,
        idempotency_key: Some("idempotency-post-dispatch".to_owned()),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("observation.accept.v1")?],
        extensions: Vec::new(),
    })?;
    let terminal = TerminalRecord::internal_failure_for_call(
        &call,
        CommittedEffectEvidence::unknown(DIGEST, "reconcile-provider-effect")?,
        "diagnostic.internal.v1",
    );
    assert_eq!(terminal.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(
        terminal.committed_effect().state(),
        CommittedEffectState::Unknown
    );
    assert_eq!(terminal.provider_receipt_sha256(), Some(DIGEST));
    assert_eq!(
        terminal.committed_effect().reconciliation_action(),
        Some("reconcile-provider-effect")
    );

    let rebound = terminal
        .clone()
        .try_with_identity("operation-public", ALT_DIGEST)?;
    assert_eq!(rebound.operation_id(), "operation-public");
    assert_eq!(rebound.exact_scope_sha256(), ALT_DIGEST);
    assert_eq!(rebound.operation(), terminal.operation());
    assert_eq!(rebound.provider_id(), terminal.provider_id());
    assert_eq!(rebound.terminal_code(), terminal.terminal_code());
    assert_eq!(rebound.committed_effect(), terminal.committed_effect());
    assert_eq!(
        terminal.clone().try_with_identity(" ", ALT_DIGEST),
        Err(ApiError::NonCanonicalTerminalText("operation_id"))
    );
    assert_eq!(
        terminal.try_with_identity("operation-public", "not-a-digest"),
        Err(ApiError::InvalidSha256("exact_scope_sha256"))
    );
    Ok(())
}

#[test]
fn typed_reconciliation_digest_builds_equivalent_unknown_effect() -> Result<(), ApiError> {
    let typed = CommittedEffectEvidence::unknown_from_reconciliation_digest([0xab; 32]);
    let encoded = "ab".repeat(32);
    let general =
        CommittedEffectEvidence::unknown(encoded.clone(), UNKNOWN_EFFECT_RECONCILIATION_ACTION)?;
    assert_eq!(typed, general);
    assert_eq!(typed.provider_receipt_sha256(), Some(encoded.as_str()));
    assert_eq!(
        typed.reconciliation_action(),
        Some("reconcile.provider-effect.v1")
    );
    Ok(())
}

#[test]
fn effect_unknown_factory_preserves_mutating_uncertainty_and_rejects_false_read_effects()
-> Result<(), ApiError> {
    let mut call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-effect-unknown".to_owned(),
        operation_id: "operation-effect-unknown".to_owned(),
        expected_state_generation: 17,
        idempotency_key: Some("idempotency-effect-unknown".to_owned()),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("observation.accept.v1")?],
        extensions: Vec::new(),
    })?;
    let terminal =
        TerminalRecord::effect_unknown_for_call(&call, [0xcd; 32], "diagnostic.effect-unknown.v1");
    assert_eq!(terminal.operation(), ProviderOperation::Observe);
    assert_eq!(terminal.provider_id(), &call.provider_id);
    assert_eq!(terminal.terminal_code(), TerminalCode::EffectUnknown);
    assert_eq!(terminal.operation_id(), call.operation_id);
    assert_eq!(
        terminal.exact_scope_sha256(),
        call.exact_scope.exact_scope_sha256()
    );
    assert_eq!(
        terminal.committed_effect(),
        &CommittedEffectEvidence::unknown_from_reconciliation_digest([0xcd; 32])
    );
    assert_eq!(
        terminal.fallback().eligibility(),
        FallbackEligibility::Forbidden
    );

    call.operation = ProviderOperation::Recall;
    call.idempotency_key = None;
    call.required_capabilities = BTreeSet::from([capability("recall.query.v1")?]);
    let read_only =
        TerminalRecord::effect_unknown_for_call(&call, [0xef; 32], "diagnostic.read-only.v1");
    assert_eq!(read_only.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(
        read_only.committed_effect(),
        &CommittedEffectEvidence::none(Some(17))
    );

    call.operation = ProviderOperation::Observe;
    call.idempotency_key = Some("idempotency-effect-unknown".to_owned());
    call.required_capabilities = BTreeSet::from([capability("observation.accept.v1")?]);
    call.exact_scope.project_id.clear();
    let malformed = TerminalRecord::effect_unknown_for_call(&call, [0xaa; 32], "   ");
    assert_eq!(malformed.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(
        malformed.committed_effect(),
        &CommittedEffectEvidence::none(Some(17))
    );
    assert_eq!(
        malformed.diagnostic_id(),
        Some("tracedecay.memory.provider.internal-failure.v1")
    );
    Ok(())
}

#[test]
fn post_dispatch_factory_handles_malformed_and_read_only_calls_without_losing_truth()
-> Result<(), ApiError> {
    let mut call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-post-dispatch-malformed".to_owned(),
        operation_id: "operation-post-dispatch-malformed".to_owned(),
        expected_state_generation: 11,
        idempotency_key: Some("idempotency-post-dispatch-malformed".to_owned()),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("observation.accept.v1")?],
        extensions: Vec::new(),
    })?;
    call.operation_id = " malformed\nidentity ".to_owned();
    call.exact_scope.project_id.clear();
    let unknown = CommittedEffectEvidence::unknown(DIGEST, "reconcile-provider-effect")?;
    let malformed = TerminalRecord::internal_failure_for_call(&call, unknown.clone(), "   ");
    assert_eq!(malformed.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(malformed.committed_effect(), &unknown);
    assert_eq!(
        malformed.operation_id(),
        "tracedecay.internal-failure.operation.v1"
    );
    assert_eq!(
        malformed.diagnostic_id(),
        Some("tracedecay.memory.provider.internal-failure.v1")
    );

    call.operation = ProviderOperation::Recall;
    let read_only = TerminalRecord::internal_failure_for_call(&call, unknown, "diagnostic.read.v1");
    assert_eq!(read_only.operation(), ProviderOperation::Recall);
    assert_eq!(read_only.terminal_code(), TerminalCode::InternalFailure);
    assert_eq!(
        read_only.committed_effect(),
        &CommittedEffectEvidence::none(Some(11))
    );

    call.operation = ProviderOperation::Observe;
    let committed = CommittedEffectEvidence::committed(
        11,
        12,
        vec!["committed-item".to_owned()],
        DIGEST,
        ALT_DIGEST,
    )?;
    let degraded =
        TerminalRecord::internal_failure_for_call(&call, committed.clone(), "diagnostic.commit.v1");
    assert_eq!(degraded.terminal_code(), TerminalCode::Partial);
    assert_eq!(degraded.committed_effect(), &committed);
    Ok(())
}

#[test]
fn capability_set_is_deterministic() -> Result<(), ApiError> {
    let descriptor = descriptor()?;
    let actual = descriptor
        .capabilities
        .iter()
        .map(OwnedVersionedId::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::from([
            "observation.accept.v1",
            "provider.health.v1",
            "recall.query.v1",
        ])
    );
    Ok(())
}

// -- observation sanitization receipts ------------------------------------------

const SANITIZER_REVISION: &str = "tracedecay.memory.observation.hygiene.v1+test";
const FINDINGS_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn accepted_receipt() -> Result<PayloadSanitizationReceipt, ApiError> {
    PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts::accepted_unmodified(
        SANITIZER_REVISION,
        EMPTY_OBJECT_DIGEST,
    ))
}

fn redacted_receipt() -> Result<PayloadSanitizationReceipt, ApiError> {
    PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts {
        sanitizer_revision: SANITIZER_REVISION.to_owned(),
        source_payload_sha256: DIGEST.to_owned(),
        sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
        extensions_digest: empty_opaque_extensions_digest(),
        disposition: SanitizationDisposition::Redacted,
        finding_count: 2,
        findings_digest: FINDINGS_DIGEST.to_owned(),
    })
}

fn observe_parts(request_id: &str) -> Result<ProviderCallParts, ApiError> {
    Ok(ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: request_id.to_owned(),
        operation_id: format!("operation-{request_id}"),
        expected_state_generation: 0,
        idempotency_key: Some(format!("idempotency-{request_id}")),
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("observation.accept.v1")?],
        extensions: Vec::new(),
    })
}

#[test]
fn accepted_receipt_binds_identical_digests_and_redacted_receipt_binds_delivered_bytes()
-> Result<(), ApiError> {
    let accepted = accepted_receipt()?;
    assert_eq!(accepted.disposition(), SanitizationDisposition::Accepted);
    assert_eq!(accepted.source_payload_sha256(), EMPTY_OBJECT_DIGEST);
    assert_eq!(accepted.sanitized_payload_sha256(), EMPTY_OBJECT_DIGEST);
    assert_eq!(accepted.finding_count(), 0);
    assert!(
        accepted
            .receipt_id()
            .starts_with(OBSERVATION_HYGIENE_RECEIPT_ID_PREFIX)
    );
    accepted.validate()?;

    let redacted = redacted_receipt()?;
    assert_eq!(redacted.disposition(), SanitizationDisposition::Redacted);
    assert_ne!(
        redacted.sanitized_payload_sha256(),
        redacted.source_payload_sha256()
    );
    redacted.validate()?;
    assert_ne!(accepted.receipt_id(), redacted.receipt_id());
    Ok(())
}

#[test]
fn accepted_disposition_forbids_modified_bytes_and_redacted_forbids_unmodified() {
    let modified = PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts {
        sanitizer_revision: SANITIZER_REVISION.to_owned(),
        source_payload_sha256: DIGEST.to_owned(),
        sanitized_payload_sha256: ALT_DIGEST.to_owned(),
        extensions_digest: empty_opaque_extensions_digest(),
        disposition: SanitizationDisposition::Accepted,
        finding_count: 0,
        findings_digest: FINDINGS_DIGEST.to_owned(),
    });
    assert_eq!(modified, Err(ApiError::SanitizationAcceptedPayloadModified));

    let unmodified = PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts {
        sanitizer_revision: SANITIZER_REVISION.to_owned(),
        source_payload_sha256: DIGEST.to_owned(),
        sanitized_payload_sha256: DIGEST.to_owned(),
        extensions_digest: empty_opaque_extensions_digest(),
        disposition: SanitizationDisposition::Redacted,
        finding_count: 1,
        findings_digest: FINDINGS_DIGEST.to_owned(),
    });
    assert_eq!(
        unmodified,
        Err(ApiError::SanitizationRedactedPayloadUnmodified)
    );
}

#[test]
fn receipt_rejects_malformed_digests_and_revisions() {
    let bad_revision = PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts::accepted_unmodified("", EMPTY_OBJECT_DIGEST),
    );
    assert_eq!(bad_revision, Err(ApiError::InvalidSanitizerRevision));

    let quoted_revision = PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts::accepted_unmodified("rev\"1", EMPTY_OBJECT_DIGEST),
    );
    assert_eq!(quoted_revision, Err(ApiError::InvalidSanitizerRevision));

    let bad_digest = PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts::accepted_unmodified(SANITIZER_REVISION, "not-a-digest"),
    );
    assert_eq!(
        bad_digest,
        Err(ApiError::InvalidSha256("source_payload_sha256"))
    );
}

#[test]
fn receipt_identifier_is_derived_from_every_field() -> Result<(), ApiError> {
    let base = redacted_receipt()?;
    let mut perturbed = Vec::new();

    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: format!("{SANITIZER_REVISION}.other"),
            source_payload_sha256: DIGEST.to_owned(),
            sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
            extensions_digest: empty_opaque_extensions_digest(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 2,
            findings_digest: FINDINGS_DIGEST.to_owned(),
        },
    )?);
    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: SANITIZER_REVISION.to_owned(),
            source_payload_sha256: ALT_DIGEST.to_owned(),
            sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
            extensions_digest: empty_opaque_extensions_digest(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 2,
            findings_digest: FINDINGS_DIGEST.to_owned(),
        },
    )?);
    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: SANITIZER_REVISION.to_owned(),
            source_payload_sha256: DIGEST.to_owned(),
            sanitized_payload_sha256: ALT_DIGEST.to_owned(),
            extensions_digest: empty_opaque_extensions_digest(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 2,
            findings_digest: FINDINGS_DIGEST.to_owned(),
        },
    )?);
    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: SANITIZER_REVISION.to_owned(),
            source_payload_sha256: DIGEST.to_owned(),
            sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
            extensions_digest: ALT_DIGEST.to_owned(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 2,
            findings_digest: FINDINGS_DIGEST.to_owned(),
        },
    )?);
    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: SANITIZER_REVISION.to_owned(),
            source_payload_sha256: DIGEST.to_owned(),
            sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
            extensions_digest: empty_opaque_extensions_digest(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 3,
            findings_digest: FINDINGS_DIGEST.to_owned(),
        },
    )?);
    perturbed.push(PayloadSanitizationReceipt::new(
        PayloadSanitizationReceiptParts {
            sanitizer_revision: SANITIZER_REVISION.to_owned(),
            source_payload_sha256: DIGEST.to_owned(),
            sanitized_payload_sha256: EMPTY_OBJECT_DIGEST.to_owned(),
            extensions_digest: empty_opaque_extensions_digest(),
            disposition: SanitizationDisposition::Redacted,
            finding_count: 2,
            findings_digest: ALT_DIGEST.to_owned(),
        },
    )?);
    // The accepted variant perturbs the disposition, which forces the digests
    // to agree, so it is built separately.
    perturbed.push(accepted_receipt()?);

    for candidate in &perturbed {
        assert_ne!(candidate.receipt_id(), base.receipt_id());
        candidate.validate()?;
    }
    Ok(())
}

#[test]
fn receipt_json_round_trips_and_rejects_tampering() -> Result<(), ApiError> {
    let receipt = redacted_receipt()?;
    let encoded = receipt.to_json();
    assert_eq!(PayloadSanitizationReceipt::from_json(&encoded)?, receipt);
    // Whitespace is insignificant; a journal may reformat what it stores.
    let spaced = encoded.replace(',', " , ");
    assert_eq!(PayloadSanitizationReceipt::from_json(&spaced)?, receipt);

    let repointed = encoded.replace(EMPTY_OBJECT_DIGEST, ALT_DIGEST);
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&repointed),
        Err(ApiError::SanitizationReceiptTampered)
    );

    let unknown_field = encoded.replace("{\"receipt_id\"", "{\"surprise\":\"x\",\"receipt_id\"");
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&unknown_field),
        Err(ApiError::MalformedSanitizationReceiptJson("unknown_field"))
    );

    let duplicate = encoded.replace("{\"receipt_id\"", "{\"receipt_id\":\"x\",\"receipt_id\"");
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&duplicate),
        Err(ApiError::MalformedSanitizationReceiptJson(
            "duplicate_field"
        ))
    );

    let missing = encoded.replace(&format!(",\"findings_digest\":\"{FINDINGS_DIGEST}\""), "");
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&missing),
        Err(ApiError::MalformedSanitizationReceiptJson("missing_field"))
    );

    let trailing = format!("{encoded} ");
    assert_eq!(PayloadSanitizationReceipt::from_json(&trailing)?, receipt);
    let junk = format!("{encoded}}}");
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&junk),
        Err(ApiError::MalformedSanitizationReceiptJson(
            "trailing_content"
        ))
    );

    let escaped = encoded.replace(SANITIZER_REVISION, "rev\\u0041");
    assert_eq!(
        PayloadSanitizationReceipt::from_json(&escaped),
        Err(ApiError::MalformedSanitizationReceiptJson("string"))
    );

    assert_eq!(
        PayloadSanitizationReceipt::from_json("{}"),
        Err(ApiError::MalformedSanitizationReceiptJson("missing_field"))
    );
    assert_eq!(
        PayloadSanitizationReceipt::from_json("[]"),
        Err(ApiError::MalformedSanitizationReceiptJson("object"))
    );
    Ok(())
}

#[test]
fn observe_calls_fail_closed_without_a_bound_receipt() -> Result<(), ApiError> {
    let unsanitized = ProviderCall::new(observe_parts("request-unsanitized")?)?;
    assert!(unsanitized.sanitization().is_none());
    assert_eq!(
        unsanitized.validate(),
        Err(ApiError::UnsanitizedObservation)
    );
    assert_eq!(
        unsanitized.validate_request_bytes(u64::MAX),
        Err(ApiError::UnsanitizedObservation)
    );

    let mismatched = ProviderCall::new(observe_parts("request-mismatched")?)?.with_sanitization(
        PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts::accepted_unmodified(
            SANITIZER_REVISION,
            DIGEST,
        ))?,
    );
    assert_eq!(
        mismatched.validate(),
        Err(ApiError::SanitizationReceiptUnbound)
    );

    let admitted = ProviderCall::new(observe_parts("request-admitted")?)?
        .with_sanitization(accepted_receipt()?);
    admitted.validate()?;

    let mut extension_parts = observe_parts("request-extension")?;
    extension_parts.extensions.push(extension()?);
    let extension_digest = opaque_extensions_digest(&extension_parts.extensions)?;
    let extension_call = ProviderCall::new(extension_parts)?;
    assert_eq!(
        extension_call
            .clone()
            .with_sanitization(accepted_receipt()?)
            .validate(),
        Err(ApiError::SanitizationReceiptUnbound),
        "a receipt for an empty extension set must not clear extension bytes",
    );
    extension_call
        .with_sanitization(PayloadSanitizationReceipt::new(
            PayloadSanitizationReceiptParts::accepted_unmodified_with_extensions(
                SANITIZER_REVISION,
                EMPTY_OBJECT_DIGEST,
                extension_digest,
            ),
        )?)
        .validate()?;
    assert_eq!(
        admitted
            .sanitization()
            .map(PayloadSanitizationReceipt::receipt_id),
        Some(accepted_receipt()?.receipt_id())
    );
    Ok(())
}

#[test]
fn non_observe_operations_validate_without_a_receipt() -> Result<(), ApiError> {
    let recall = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider_id()?,
        registration_revision: 1,
        ready_receipt_sha256: DIGEST.to_owned(),
        exact_scope: scope()?,
        request_id: "request-recall-unsanitized".to_owned(),
        operation_id: "operation-recall-unsanitized".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10, CancellationToken::new()),
        payload: payload()?,
        required_capabilities: vec![capability("recall.query.v1")?],
        extensions: Vec::new(),
    })?;
    recall.validate()?;
    assert!(recall.sanitization().is_none());
    Ok(())
}

#[test]
fn withheld_reasons_and_dispositions_have_stable_wire_spellings() {
    assert_eq!(SanitizationDisposition::Accepted.as_str(), "accepted");
    assert_eq!(SanitizationDisposition::Redacted.as_str(), "redacted");
    assert_eq!(
        SanitizationDisposition::from_wire("redacted"),
        Some(SanitizationDisposition::Redacted)
    );
    assert_eq!(SanitizationDisposition::from_wire("rejected"), None);

    assert_eq!(WithheldReason::SecretRejected.as_str(), "secret_rejected");
    assert_eq!(WithheldReason::Quarantined.as_str(), "quarantined");
    assert_eq!(
        WithheldReason::UnclassifiablePayload.as_str(),
        "unclassifiable_payload"
    );
    assert_eq!(
        WithheldReason::from_wire("quarantined"),
        Some(WithheldReason::Quarantined)
    );
    assert_eq!(
        WithheldReason::from_wire("unclassifiable_payload"),
        Some(WithheldReason::UnclassifiablePayload)
    );
    assert_eq!(WithheldReason::from_wire("accepted"), None);
    assert_eq!(WithheldReason::from_wire("payload_too_large"), None);
}

#[test]
fn native_context_delivery_marker_is_bound_to_host_registration_and_request() -> Result<(), ApiError>
{
    let provider = provider_id()?;
    let exact_scope = scope()?;
    let marker = NativeContextDeliveryMarker::from_host_registration(
        provider.clone(),
        9,
        &exact_scope,
        DIGEST,
        ALT_DIGEST,
    )?;

    assert_eq!(
        marker.route_id(),
        "tracedecay.memory.native.context-delivery.v1"
    );
    assert_eq!(marker.operation_id(), "memory_matches");
    assert_eq!(marker.selected_provider_id(), &provider);
    assert_eq!(marker.registration_revision(), 9);
    assert_eq!(
        marker.exact_scope_sha256(),
        exact_scope.exact_scope_sha256()
    );
    assert_eq!(marker.canonical_request_sha256(), DIGEST);
    assert_eq!(marker.canonical_contribution_sha256(), ALT_DIGEST);
    marker.verify_for(&provider, 9, &exact_scope, DIGEST, ALT_DIGEST)?;

    let other_provider = OwnedProviderId::new("other.provider")?;
    assert_eq!(
        marker.verify_for(&other_provider, 9, &exact_scope, DIGEST, ALT_DIGEST),
        Err(ApiError::NativeContextDeliveryBindingMismatch(
            "selected_provider_id"
        ))
    );
    assert_eq!(
        marker.verify_for(&provider, 10, &exact_scope, DIGEST, ALT_DIGEST),
        Err(ApiError::NativeContextDeliveryBindingMismatch(
            "registration_revision"
        ))
    );

    let mut other_scope = exact_scope.clone();
    other_scope.branch_identity = "refs/heads/release".to_owned();
    assert_eq!(
        marker.verify_for(&provider, 9, &other_scope, DIGEST, ALT_DIGEST),
        Err(ApiError::NativeContextDeliveryBindingMismatch(
            "exact_scope_sha256"
        ))
    );
    assert_eq!(
        marker.verify_for(&provider, 9, &exact_scope, ALT_DIGEST, ALT_DIGEST),
        Err(ApiError::NativeContextDeliveryBindingMismatch(
            "canonical_request_sha256"
        ))
    );
    assert_eq!(
        marker.verify_for(&provider, 9, &exact_scope, DIGEST, DIGEST),
        Err(ApiError::NativeContextDeliveryBindingMismatch(
            "canonical_contribution_sha256"
        ))
    );
    Ok(())
}

#[test]
fn native_context_delivery_marker_requires_canonical_digests_and_revision() -> Result<(), ApiError>
{
    let exact_scope = scope()?;
    assert_eq!(
        NativeContextDeliveryMarker::from_host_registration(
            provider_id()?,
            0,
            &exact_scope,
            DIGEST,
            ALT_DIGEST,
        ),
        Err(ApiError::InvalidRegistrationRevision)
    );
    assert_eq!(
        NativeContextDeliveryMarker::from_host_registration(
            provider_id()?,
            1,
            &exact_scope,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ALT_DIGEST,
        ),
        Err(ApiError::InvalidSha256(
            "native_context.canonical_request_sha256"
        ))
    );
    Ok(())
}
