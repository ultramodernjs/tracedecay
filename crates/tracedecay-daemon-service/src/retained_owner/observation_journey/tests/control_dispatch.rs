//! Shutdown reaches an actual control through the existing mounted fixture.

use super::*;
use crate::retained_owner::observation_journey::control_dispatch::{
    JourneyControlDispatchErrorV1, JourneyControlDispatchRequestV1,
};
use tracedecay_memory_conformance::ReleaseLatchV1;

fn successful_health_reply(call: &ProviderCall) -> ProviderReply {
    ProviderReply {
        terminal: TerminalRecord::new(
            ProviderOperation::Health,
            call.provider_id.clone(),
            TerminalCode::Success,
            CommittedEffectEvidence::none(Some(call.expected_state_generation)),
            FallbackDirective::forbidden(),
            call.operation_id.clone(),
            call.exact_scope.exact_scope_sha256(),
            None,
        )
        .expect("health terminal"),
        payload: None,
        warnings: Vec::new(),
        extensions: Vec::new(),
        state_generation: call.expected_state_generation,
    }
}

fn health_request(
    fixture: &RecoveryJourneyFixture,
    control: OperationControl,
) -> JourneyControlDispatchRequestV1 {
    JourneyControlDispatchRequestV1 {
        provider_id: OwnedProviderId::new(FIXTURE_OBSERVER_ID).expect("original provider"),
        registration_revision: 1,
        exact_scope: exact_scope_for_session(
            &fixture.profile_id,
            &fixture.resolved_scope,
            "session.control-shutdown",
        )
        .expect("original delivery scope"),
        operation: ProviderOperation::Health,
        request_id: "control-shutdown-request".to_owned(),
        operation_id: "control-shutdown-operation".to_owned(),
        idempotency_key: None,
        operation_body: serde_json::json!({"requested_checks": ["state"]}),
        policy_revision: 7,
        control,
        expected_state_generation: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_cancels_an_in_flight_control_and_retains_its_worker_until_return() {
    let temp = TempDir::new().expect("temporary journey root");
    let port = Arc::new(JourneyObserverPort::new());
    let fixture = mount_journey_over_port(
        &temp,
        "project.control-shutdown",
        "profile.control-shutdown",
        Arc::clone(&port),
    )
    .await;
    let held = ReleaseLatchV1::new();
    let blocked = held.clone();
    let (entered, entry) = tokio::sync::oneshot::channel();
    let entered = Mutex::new(Some(entered));
    port.on_health(move |call| {
        entered
            .lock()
            .unwrap()
            .take()
            .expect("only one control may be invoked")
            .send(call.clone())
            .expect("control entry receiver");
        blocked.wait();
        successful_health_reply(call)
    });
    let original_control = OperationControl::new(
        tracedecay_contracts::now_micros()
            .0
            .saturating_add(30_000_000),
        30_000,
        CancellationToken::new(),
    );
    let request = health_request(&fixture, original_control.clone());
    let journey = Arc::clone(&fixture.journey);
    let mut dispatch = tokio::task::spawn_blocking(move || journey.dispatch_control(request));
    let entered = tokio::time::timeout(Duration::from_secs(2), entry).await;
    if !matches!(&entered, Ok(Ok(_))) {
        held.release();
    }
    let actual = entered
        .expect("control never reached health")
        .expect("control entry");

    let journey = Arc::clone(&fixture.journey);
    let shutdown = tokio::spawn(async move {
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await
    });
    // The original operation has thirty seconds. Shutdown must hand its caller
    // back while the provider is still held, rather than waiting for that budget.
    let answer = tokio::time::timeout(Duration::from_millis(500), &mut dispatch).await;
    let census_while_held = fixture.journey.provider_call_census();
    let original_cancelled = original_control.cancellation().is_cancelled();
    let provider_cancelled = actual.control.cancellation().is_cancelled();
    let provider_was_held = !held.is_released();
    // Release before any assertions so a failed regression never strands a test
    // worker. The snapshots above are all from the still-held provider call.
    held.release();
    if answer.is_err() {
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut dispatch).await;
    }
    let failures = shutdown.await.expect("journey shutdown task");
    let isolation = Arc::clone(&fixture.journey.provider_isolation);
    let reclaimed = tokio::task::spawn_blocking(move || {
        isolation.wait_for_census(Duration::from_secs(2), |census| {
            census == BoundedCallCensusV1::default()
        })
    })
    .await
    .expect("worker reclamation waiter");

    assert!(
        matches!(
            answer,
            Ok(Ok(Err(JourneyControlDispatchErrorV1::Isolation(
                BoundedCallRefusalV1::Cancelled
            ))))
        ),
        "shutdown did not cancel the still-running control: {answer:?}"
    );
    assert!(provider_was_held);
    assert!(original_cancelled && provider_cancelled);
    assert_eq!(
        actual.control.deadline_utc_micros(),
        original_control.deadline_utc_micros()
    );
    assert_eq!(
        actual.control.remaining_millis(),
        original_control.remaining_millis()
    );
    assert_eq!(
        census_while_held,
        BoundedCallCensusV1 {
            live: 0,
            abandoned: 1
        }
    );
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(reclaimed, Ok(BoundedCallCensusV1::default()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_headers_and_oversized_bodies_are_refused_before_provider_contact() {
    let temp = TempDir::new().expect("temporary journey root");
    let port = Arc::new(JourneyObserverPort::new());
    let fixture = mount_journey_over_port(
        &temp,
        "project.control-preflight",
        "profile.control-preflight",
        Arc::clone(&port),
    )
    .await;
    let contacts = Arc::new(AtomicUsize::new(0));
    let handshakes = Arc::clone(&contacts);
    port.on_handshake(move || {
        handshakes.fetch_add(1, Ordering::AcqRel);
    });
    let controls = Arc::clone(&contacts);
    port.on_health(move |call| {
        controls.fetch_add(1, Ordering::AcqRel);
        successful_health_reply(call)
    });
    let original_control = OperationControl::new(
        tracedecay_contracts::now_micros()
            .0
            .saturating_add(30_000_000),
        30_000,
        CancellationToken::new(),
    );
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
        let mut request = health_request(&fixture, original_control.clone());
        request.operation_body[field] = serde_json::json!({"untrusted": true});
        let journey = Arc::clone(&fixture.journey);
        let result = tokio::task::spawn_blocking(move || journey.dispatch_control(request))
            .await
            .expect("preflight caller");
        assert!(
            matches!(
                result,
                Err(JourneyControlDispatchErrorV1::NotDispatched(
                    super::super::control_dispatch::JourneyControlNotDispatchedV1::SuppliedAuthorityHeader(actual)
                )) if actual == field
            ),
            "supplied {field} was not rejected before readiness"
        );
    }
    let mut request = health_request(&fixture, original_control);
    let maximum = fixture.journey.delivery.limits.request_bytes;
    request.operation_body = serde_json::json!({
        "requested_checks": ["x".repeat(usize::try_from(maximum).expect("request bound") + 1)]
    });
    let journey = Arc::clone(&fixture.journey);
    let result = tokio::task::spawn_blocking(move || journey.dispatch_control(request))
        .await
        .expect("oversized preflight caller");
    assert!(matches!(
        result,
        Err(JourneyControlDispatchErrorV1::Contract(ApiError::BoundaryBytesExceeded {
            field: "control.operation_body", maximum: actual
        })) if actual == maximum
    ));
    assert_eq!(contacts.load(Ordering::Acquire), 0);
    let failures = fixture
        .journey
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    assert!(failures.is_empty(), "{failures:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_health_header_uses_actual_guard_call_and_original_control() {
    let temp = TempDir::new().expect("temporary journey root");
    let port = Arc::new(JourneyObserverPort::with_state_generation(5));
    let fixture = mount_journey_over_port(
        &temp,
        "project.control-header",
        "profile.control-header",
        Arc::clone(&port),
    )
    .await;
    let original_control = OperationControl::new(
        tracedecay_contracts::now_micros()
            .0
            .saturating_add(30_000_000),
        30_000,
        CancellationToken::new(),
    );
    let mut request = health_request(&fixture, original_control.clone());
    request.operation_body = serde_json::json!({"requested_checks": ["scope", "state"]});
    let original_body = request.operation_body.clone();
    port.on_health(successful_health_reply);
    let journey = Arc::clone(&fixture.journey);
    let dispatched = tokio::task::spawn_blocking(move || journey.dispatch_control(request))
        .await
        .expect("health caller")
        .expect("actual health dispatch");
    let payload: Value =
        serde_json::from_slice(&dispatched.call.payload.bytes).expect("canonical health payload");
    let header = &payload["common_request"];
    let scope = &dispatched.call.exact_scope;
    assert_eq!(
        dispatched.call.payload.contract_id.as_str(),
        "tracedecay.memory.provider.health.v1"
    );
    assert_eq!(
        payload["requested_checks"],
        original_body["requested_checks"]
    );
    assert_eq!(payload.as_object().expect("body object").len(), 2);
    assert_eq!(dispatched.readiness_evidence.state_generation(), 5);
    assert_eq!(dispatched.call.expected_state_generation, 5);
    assert_eq!(dispatched.reply.state_generation, 5);
    assert_eq!(
        dispatched.call.ready_receipt_sha256,
        dispatched.readiness_evidence.ready_receipt_sha256()
    );
    let remaining = header["deadline"]["remaining_millis"]
        .as_u64()
        .expect("live remaining");
    assert!(remaining > 0 && remaining <= original_control.remaining_millis());
    assert_eq!(
        header,
        &serde_json::json!({
            "provider_id": dispatched.call.provider_id.as_str(),
            "registration_revision": dispatched.call.registration_revision,
            "ready_receipt_digest": dispatched.readiness_evidence.ready_receipt_sha256(),
            "exact_scope_identity": {
                "profile_id": scope.profile_id,
                "project_id": scope.project_id,
                "repository_identity": scope.repository_identity,
                "worktree_identity": scope.worktree_identity,
                "branch_identity": scope.branch_identity,
                "agent_session_id": scope.agent_session_id,
                "resolved_scope_digest": scope.resolved_scope_digest,
            },
            "operation_id": dispatched.call.operation_id,
            "idempotency_key": dispatched.call.idempotency_key,
            "expected_state_generation": dispatched.call.expected_state_generation,
            "request_identity": dispatched.call.request_id,
            "policy_revision": 7,
            "deadline": {
                "deadline_utc_micros": original_control.deadline_utc_micros(),
                "remaining_millis": remaining,
            },
            "cancellation": "live",
            "extensions": [],
        })
    );
    assert_eq!(
        dispatched.call.payload.bytes,
        canonical_payload_bytes(&payload).expect("canonical bytes")
    );
    assert!(dispatched.call.extensions.is_empty());
    assert!(!original_control.cancellation().is_cancelled());
    let failures = fixture
        .journey
        .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn witnessed_committed_control_answer_survives_caller_cancellation_and_journey_stop() {
    let original_reply = ProviderReply {
        terminal: TerminalRecord::new(
            ProviderOperation::Maintenance,
            OwnedProviderId::new(FIXTURE_OBSERVER_ID).expect("original provider"),
            TerminalCode::Success,
            CommittedEffectEvidence::committed(
                5,
                6,
                vec!["maintenance:committed-control".to_owned()],
                PROVIDER_RECEIPT,
                EFFECT_DIGEST,
            )
            .expect("actual committed evidence"),
            FallbackDirective::forbidden(),
            "committed-control-operation",
            "4".repeat(64),
            None,
        )
        .expect("committed maintenance terminal"),
        payload: None,
        warnings: vec!["committed-control-warning".to_owned()],
        extensions: Vec::new(),
        state_generation: 6,
    };
    for stop_journey in [false, true] {
        let cancellation = CancellationToken::new();
        let stopping = HostCancellationToken::new();
        // This is the exact branch entered after recv_timeout produced an
        // answer. Fire cancellation before it classifies that known reply;
        // no scheduler timing can turn this into the no-answer timeout path.
        let witnessed_reply = original_reply.clone();
        if stop_journey {
            stopping.cancel();
            assert!(!cancellation.is_cancelled());
        } else {
            cancellation.cancel();
        }
        let retained = ThreadBoundedProviderCallV1::settled_answer(
            &cancellation,
            Some(&stopping),
            true,
            witnessed_reply,
        )
        .expect("a witnessed control reply must retain its committed evidence");
        assert_eq!(retained, original_reply);
        assert!(cancellation.is_cancelled());
    }

    // The ordinary observation policy still refuses an answer when its
    // caller has already cancelled, even though that answer is available.
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        ThreadBoundedProviderCallV1::settled_answer(&cancellation, None, false, original_reply),
        Err(BoundedCallRefusalV1::Cancelled)
    ));
}
