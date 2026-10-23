//! Behavioral proof that provider lifecycle supervision is mountable over a
//! real composed provider set, and that the host keeps working while a
//! supervised provider is unavailable.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracedecay_memory_provider_api::contract::TerminalCode;
use tracedecay_memory_provider_api::{
    CancellationToken, CommittedEffectEvidence, FallbackDirective, HandshakeRequest,
    HandshakeRequestParts, HandshakeResponse, OperationControl, OwnedExactScope, OwnedProviderId,
    OwnedVersionedId, ProviderCall, ProviderDescriptor, ProviderLimits, ProviderOperation,
    ProviderReply, TerminalRecord,
};
use tracedecay_memory_provider_native::{
    NATIVE_PROVIDER_ID, NativeMemoryApplicationPort, NativeProvider,
};
mod isolation_fixture;

use isolation_fixture::ThreadBoundedProviderCallV1;
use tracedecay_memory_provider_registry::{
    DegradationKindV1, EnabledProviderMode, FabricConfig, NativeProviderActivation,
    ProjectMemoryProviderComposition, ProviderExecutionShapeV1, ProviderLifecycleOwnerErrorV1,
    ProviderLifecycleOwnerV1, ProviderLifecycleOwnershipV1, ProviderRegistrationV1,
    QuarantinePolicyV1, RecallScopeBindingsV1, RestartBudgetV1, SelectedProviderActivationV1,
    ShutdownBudgetV1, SupervisedProviderReadinessV1, SupervisedReadinessConfigV1,
    SupervisedReadinessError,
};

const ONE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const IMPLEMENTATION_SHA: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const RESOLVED_SCOPE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn limits() -> ProviderLimits {
    ProviderLimits {
        request_bytes: 65_536,
        response_bytes: 65_536,
        observation_batch_items: 16,
        recall_candidates: 16,
        concurrent_operations: 4,
        operation_millis: 1_000,
        snapshot_bytes: 65_536,
        inspection_items: 64,
    }
}

fn descriptor() -> ProviderDescriptor {
    ProviderDescriptor::new(
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        IMPLEMENTATION_SHA,
        "native.state.v1",
        3,
        [
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
        ]
        .into_iter()
        .map(|value| OwnedVersionedId::new(value).expect("capability")),
        limits(),
    )
    .expect("descriptor")
}

fn descriptor_with_capability(capability: &str) -> ProviderDescriptor {
    ProviderDescriptor::new(
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        IMPLEMENTATION_SHA,
        "native.state.v1",
        3,
        [
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
            capability,
        ]
        .into_iter()
        .map(|value| OwnedVersionedId::new(value).expect("capability")),
        limits(),
    )
    .expect("descriptor")
}

fn exact_scope(worktree: &str) -> OwnedExactScope {
    OwnedExactScope::new(
        "profile-mounted",
        "project-mounted",
        "repository-mounted",
        worktree,
        "refs/heads/mounted",
        "session-mounted",
        RESOLVED_SCOPE_DIGEST,
    )
    .expect("exact scope")
}

fn handshake_request(scope: OwnedExactScope) -> HandshakeRequest {
    HandshakeRequest::new(HandshakeRequestParts {
        provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        registration_revision: 1,
        exact_scope: scope,
        request_id: "mounted-readiness".to_owned(),
        required_capabilities: vec![
            OwnedVersionedId::new("provider.health.v1").expect("health capability"),
        ],
        host_limits: limits(),
        control: OperationControl::new(i64::MAX, 1_000, CancellationToken::new()),
        challenge_nonce: [5; 32],
    })
    .expect("handshake request")
}

/// A Native application port that answers a real handshake, and can be told
/// to answer a *malformed* success so the mounted path's own validation is
/// exercised rather than only the supervisor unit's.
struct MountedNativePort {
    descriptor: ProviderDescriptor,
    handshake_terminal: TerminalCode,
    omit_state_namespace: AtomicBool,
    handshake_calls: AtomicUsize,
}

impl MountedNativePort {
    fn new() -> Self {
        Self {
            descriptor: descriptor(),
            handshake_terminal: TerminalCode::Success,
            omit_state_namespace: AtomicBool::new(false),
            handshake_calls: AtomicUsize::new(0),
        }
    }

    /// A provider that declares one additional capability in its real
    /// handshake descriptor.
    fn with_capability(capability: &str) -> Self {
        Self {
            descriptor: descriptor_with_capability(capability),
            handshake_terminal: TerminalCode::Success,
            omit_state_namespace: AtomicBool::new(false),
            handshake_calls: AtomicUsize::new(0),
        }
    }
}

impl NativeMemoryApplicationPort for MountedNativePort {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        self.handshake_calls.fetch_add(1, Ordering::Relaxed);
        let terminal = TerminalRecord::new(
            ProviderOperation::Handshake,
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
            self.handshake_terminal,
            CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
            FallbackDirective::forbidden(),
            request.request_id.clone(),
            request.exact_scope.exact_scope_sha256(),
            (self.handshake_terminal != TerminalCode::Success)
                .then(|| "fixture.handshake_refused".to_owned()),
        )
        .expect("handshake terminal");
        if self.handshake_terminal != TerminalCode::Success {
            return HandshakeResponse {
                terminal,
                descriptor: None,
                provider_instance_id: None,
                state_namespace: None,
                accepted_scope: None,
                effective_limits: None,
                ready_receipt_sha256: None,
                warnings: Vec::new(),
            };
        }
        HandshakeResponse {
            terminal,
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some("native.mounted-instance".to_owned()),
            state_namespace: if self.omit_state_namespace.load(Ordering::Relaxed) {
                None
            } else {
                Some("native.mounted-namespace".to_owned())
            },
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
            ready_receipt_sha256: Some(ONE_SHA.to_owned()),
            warnings: Vec::new(),
        }
    }

    fn health(&self, _call: &ProviderCall) -> ProviderReply {
        unexpected()
    }

    fn recall(&self, _call: &ProviderCall) -> ProviderReply {
        unexpected()
    }
}

fn unexpected<T>() -> T {
    panic!("supervised readiness tests must not execute provider operations")
}

fn enabled_composition(port: Arc<MountedNativePort>) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose(NativeProviderActivation::Enabled {
            fabric_config: FabricConfig {
                max_registered_providers: 1,
                max_in_flight: 1,
            },
            port,
            registration_revision: 1,
            mode: EnabledProviderMode::Active,
        })
        .expect("enabled composition"),
    )
}

#[derive(Default)]
struct SharedRuntimeOwner {
    running: AtomicBool,
    refuse_termination: AtomicBool,
    stops: AtomicUsize,
    kills: AtomicUsize,
}

impl ProviderLifecycleOwnerV1 for SharedRuntimeOwner {
    fn start(&self, _: i64) -> Result<(), ProviderLifecycleOwnerErrorV1> {
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn request_stop(&self, _: i64) -> Result<bool, ProviderLifecycleOwnerErrorV1> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        if self.refuse_termination.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.running.store(false, Ordering::SeqCst);
        Ok(true)
    }

    fn kill(&self, _: i64) -> Result<(), ProviderLifecycleOwnerErrorV1> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        if self.refuse_termination.load(Ordering::SeqCst) {
            return Err(ProviderLifecycleOwnerErrorV1::TerminationUnconfirmed);
        }
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}

fn owned_observer_composition(
    port: Arc<MountedNativePort>,
    owner: Arc<SharedRuntimeOwner>,
) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose_registered(
            SelectedProviderActivationV1::ObserversOnly {
                fabric_config: FabricConfig {
                    max_registered_providers: 1,
                    max_in_flight: 1,
                },
            },
            vec![ProviderRegistrationV1 {
                provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
                provider: Arc::new(NativeProvider::new(port).expect("native adapter")),
                registration_revision: 1,
                mode: EnabledProviderMode::Observer,
                execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                recall_scope_bindings: RecallScopeBindingsV1::new([]),
                lifecycle: ProviderLifecycleOwnershipV1::Owned(owner),
            }],
        )
        .expect("owned observer composition"),
    )
}

fn disabled_composition() -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose(NativeProviderActivation::Disabled)
            .expect("disabled composition"),
    )
}

fn readiness_config(max_supervised_scopes: usize) -> SupervisedReadinessConfigV1 {
    SupervisedReadinessConfigV1 {
        restart_budget: RestartBudgetV1 {
            max_attempts_per_window: 3,
            window_micros: 60_000_000,
            backoff_base_micros: 1_000,
            backoff_max_micros: 8_000,
        },
        shutdown_budget: ShutdownBudgetV1 {
            grace_micros: 5_000,
            kill_micros: 2_000,
        },
        start_budget_micros: 1_000_000,
        handshake_budget_micros: 1_000_000,
        max_supervised_scopes,
    }
}

fn mount(
    composition: Arc<ProjectMemoryProviderComposition>,
    max_supervised_scopes: usize,
) -> SupervisedProviderReadinessV1 {
    SupervisedProviderReadinessV1::new(
        composition,
        Arc::new(ThreadBoundedProviderCallV1::default()),
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        1,
        limits(),
        readiness_config(max_supervised_scopes),
    )
    .expect("mounted supervised readiness")
}

/// A supervised readiness pass over a real composed provider set reaches a
/// readiness target built from the provider's own validated handshake.
/// Catches a mount that never actually drives the supervisor.
#[test]
fn supervised_readiness_over_a_real_composition_reaches_a_readiness_target() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = handshake_request(exact_scope("worktree-a"));

    let target = readiness
        .ready_target(&request, 1_000)
        .expect("readiness target");
    assert_eq!(target.provider_id().as_str(), NATIVE_PROVIDER_ID);
    assert_eq!(target.provider_instance_id(), "native.mounted-instance");
    assert_eq!(target.registration_revision(), 1);
    assert_eq!(target.ready_receipt_sha256(), ONE_SHA);
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
    assert_eq!(readiness.supervised_scopes(), 1);
}

/// One handshake yields both the delivery address and the provider state
/// identity restart recovery compares against. Catches a mount that would take
/// the address from one incarnation and the state evidence from another, or
/// that would spend a second handshake to obtain the second half.
#[test]
fn one_readiness_pass_carries_both_the_target_and_the_state_evidence() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = handshake_request(exact_scope("worktree-a"));

    let (target, evidence) = readiness
        .ready_target_with_evidence(&request, 1_000)
        .expect("readiness target and evidence");
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        target.provider_instance_id(),
        evidence.provider_instance_id()
    );
    assert_eq!(
        target.ready_receipt_sha256(),
        evidence.ready_receipt_sha256()
    );
    assert_eq!(evidence.state_schema_version(), "native.state.v1");
    assert_eq!(evidence.state_generation(), 3);
    assert_eq!(
        evidence.implementation_identity_sha256(),
        IMPLEMENTATION_SHA
    );
    assert!(
        !evidence.retains_replay_position(),
        "a provider with no observation-recovery-position declaration uses host \
         receipt and idempotency recovery"
    );
}

/// Canonical replay capability remains negotiable without claiming a
/// provider-local position for the host journal's recovery target. Direct
/// observations and policy-specific history streams have their own receipts.
#[test]
fn native_application_replay_claim_does_not_escape_capability_projection() {
    let port = Arc::new(MountedNativePort::with_capability("replay.apply.v1"));
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = handshake_request(exact_scope("worktree-canonical-replay"));

    let (_, evidence) = readiness
        .ready_target_with_evidence(&request, 1_000)
        .expect("canonical replay remains negotiable");
    assert!(!evidence.retains_replay_position());
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
}

/// The dedicated declaration comes from the incarnation's validated
/// descriptor. It remains a claim the recovery gate must compare or refuse
/// as unreadable; canonical replay support cannot silently replace it.
#[test]
fn native_application_recovery_position_claim_does_not_escape_capability_projection() {
    let port = Arc::new(MountedNativePort::with_capability(
        "observation.recovery_position.v1",
    ));
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = handshake_request(exact_scope("worktree-recovery-position"));

    let (_, evidence) = readiness
        .ready_target_with_evidence(&request, 1_000)
        .expect("readiness target and evidence");
    assert!(!evidence.retains_replay_position());
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
}

/// A disabled composition produces typed unavailability on every pass, and
/// the host keeps running: repeated passes stay typed, allocate no extra
/// owner, and never panic. This is the acceptance criterion "host remains
/// usable when the provider is unavailable" at the mounted seam.
#[test]
fn a_disabled_composition_is_typed_unavailability_and_the_host_continues() {
    let readiness = mount(disabled_composition(), 4);
    let request = handshake_request(exact_scope("worktree-a"));

    for pass in 0..4_i64 {
        // Instants far enough apart to clear the enforced backoff, so the
        // refusal under test is the composition's, not the pacing's.
        let error = readiness
            .ready_target(&request, pass.saturating_mul(10_000_000))
            .expect_err("disabled composition cannot be ready");
        match error {
            SupervisedReadinessError::Unavailable {
                kind,
                terminal_code,
                ..
            } => {
                assert!(
                    matches!(
                        kind,
                        DegradationKindV1::StartFailed | DegradationKindV1::RestartBudgetExhausted
                    ),
                    "unexpected degradation kind {kind}"
                );
                assert_eq!(
                    terminal_code, None,
                    "no provider handshake terminal was returned"
                );
            }
            other => panic!("expected typed unavailability, got {other}"),
        }
    }
    assert_eq!(readiness.supervised_scopes(), 1);

    // The host still has a working, bounded mount afterwards: a different
    // exact scope is still admitted into supervision.
    let other = handshake_request(exact_scope("worktree-b"));
    assert!(readiness.owner_for(&other, 90_000_000).is_ok());
    assert_eq!(readiness.supervised_scopes(), 2);
}

/// Two distinct worktrees get two distinct owners; the finite ceiling holds
/// by retiring the coldest idle scope, never
/// by growing an unbounded map of supervisors and never by refusing every new
/// scope for the rest of the process's life.
#[test]
fn distinct_worktrees_get_distinct_owners_under_a_finite_ceiling() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(port), 2);

    let first = readiness
        .owner_for(&handshake_request(exact_scope("worktree-a")), 1_000)
        .expect("first owner");
    let second = readiness
        .owner_for(&handshake_request(exact_scope("worktree-b")), 2_000)
        .expect("second owner");
    assert_ne!(first.exact_scope_sha256(), second.exact_scope_sha256());

    // The same scope reuses its own owner rather than creating a second one,
    // and using it makes it the warmer of the two.
    let again = readiness
        .owner_for(&handshake_request(exact_scope("worktree-a")), 3_000)
        .expect("existing owner");
    assert!(Arc::ptr_eq(&first, &again));
    assert_eq!(readiness.supervised_scopes(), 2);
    drop(again);
    let retired = Arc::downgrade(&second);
    let second_digest = second.exact_scope_sha256().to_owned();
    drop(second);

    // A third scope retires the coldest (`worktree-b`) and stays at the
    // ceiling.
    let third = readiness
        .owner_for(&handshake_request(exact_scope("worktree-c")), 4_000)
        .expect("third owner");
    assert_eq!(readiness.supervised_scopes(), 2);
    assert_ne!(third.exact_scope_sha256(), second_digest);
    assert!(
        retired.upgrade().is_none(),
        "a retired scope owner cannot revive through a retained weak reference"
    );

    // `worktree-a` was the warm one, so it survived untouched.
    let survivor = readiness
        .owner_for(&handshake_request(exact_scope("worktree-a")), 5_000)
        .expect("surviving owner");
    assert!(Arc::ptr_eq(&first, &survivor));
    drop(survivor);
    drop(third);

    // The retired scope comes back as a *fresh* owner, never the retired one.
    let revived = readiness
        .owner_for(&handshake_request(exact_scope("worktree-b")), 6_000)
        .expect("revived owner");
    assert_eq!(revived.exact_scope_sha256(), second_digest);
    assert_eq!(readiness.supervised_scopes(), 2);
}

#[test]
fn scope_cache_retirement_preserves_shared_runtime_across_completed_scopes() {
    let port = Arc::new(MountedNativePort::new());
    let runtime = Arc::new(SharedRuntimeOwner::default());
    let readiness = mount(
        owned_observer_composition(Arc::clone(&port), Arc::clone(&runtime)),
        64,
    );

    for index in 0..98 {
        let request = handshake_request(exact_scope(&format!("worktree-{index}")));
        let dispatch = readiness
            .ready_dispatch_with_evidence(&request, 1_000 + index)
            .expect("completed scopes can retire without stopping their shared runtime");
        assert_eq!(
            dispatch.evidence().provider_instance_id(),
            "native.mounted-instance"
        );
    }

    assert_eq!(readiness.supervised_scopes(), 64);
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 98);
    assert!(runtime.running.load(Ordering::SeqCst));
    assert_eq!(runtime.stops.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.kills.load(Ordering::SeqCst), 0);

    let request = handshake_request(exact_scope("worktree-97"));
    let owner = readiness.owner_for(&request, 2_000).expect("ready owner");
    assert!(!owner.shutdown(3_000).expect("explicit bounded shutdown"));
    assert!(!runtime.running.load(Ordering::SeqCst));
    assert_eq!(runtime.stops.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.kills.load(Ordering::SeqCst), 0);
}

#[test]
fn scope_cache_retirement_cannot_evict_an_active_dispatch() {
    let readiness = mount(enabled_composition(Arc::new(MountedNativePort::new())), 1);
    let first = handshake_request(exact_scope("worktree-active"));
    let next = handshake_request(exact_scope("worktree-next"));
    let dispatch = readiness
        .ready_dispatch_with_evidence(&first, 1_000)
        .expect("active dispatch");
    let owner = readiness.owner_for(&first, 2_000).expect("active owner");
    let active = Arc::downgrade(&owner);
    drop(owner);

    assert!(matches!(
        readiness.owner_for(&next, 3_000),
        Err(SupervisedReadinessError::ScopeCapacityExceeded {
            supervised: 1,
            maximum: 1,
            ..
        })
    ));
    assert!(active.upgrade().is_some());

    drop(dispatch);
    readiness
        .ready_target(&next, 4_000)
        .expect("released dispatch permits idle retirement");
    assert!(active.upgrade().is_none());
    assert_eq!(readiness.supervised_scopes(), 1);
}

#[test]
fn scope_cache_retirement_preserves_quarantine_when_death_is_unconfirmed() {
    let port = Arc::new(MountedNativePort::new());
    port.omit_state_namespace.store(true, Ordering::Relaxed);
    let runtime = Arc::new(SharedRuntimeOwner::default());
    runtime.refuse_termination.store(true, Ordering::SeqCst);
    let readiness = mount(
        owned_observer_composition(Arc::clone(&port), Arc::clone(&runtime)),
        1,
    )
    .with_quarantine_policy(QuarantinePolicyV1 {
        max_provider_violations: 1,
    })
    .expect("bounded quarantine policy");
    let hostile = handshake_request(exact_scope("worktree-hostile"));
    readiness
        .ready_target(&hostile, 1_000)
        .expect_err("malformed readiness earns quarantine");
    let quarantine = readiness.quarantined_scopes();
    assert_eq!(quarantine.len(), 1);
    let contacts = port.handshake_calls.load(Ordering::Relaxed);

    assert!(matches!(
        readiness.owner_for(&handshake_request(exact_scope("worktree-new")), 2_000),
        Err(SupervisedReadinessError::ScopeCapacityExceeded {
            supervised: 1,
            maximum: 1,
            ..
        })
    ));
    assert_eq!(readiness.supervised_scopes(), 1);
    assert_eq!(readiness.retired_quarantined_scopes(), 0);
    assert_eq!(readiness.quarantined_scopes(), quarantine);
    assert_eq!(runtime.stops.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.kills.load(Ordering::SeqCst), 1);
    assert!(runtime.running.load(Ordering::SeqCst));
    assert!(matches!(
        readiness.ready_target(&hostile, 3_000),
        Err(SupervisedReadinessError::Unavailable {
            kind: DegradationKindV1::Quarantined,
            ..
        })
    ));
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), contacts);
}

/// A healthy provider answering many readiness requests spends **no** restart
/// budget: the steady-state path re-proves readiness with one handshake and
/// never restarts. Catches a mount that treats every request as a restart and
/// wedges a working provider into `RestartBudgetExhausted`.
#[test]
fn a_healthy_provider_never_spends_its_crash_loop_budget() {
    let port = Arc::new(MountedNativePort::new());
    let mut config = readiness_config(4);
    // One single spawn attempt per window: any restart at all would fail the
    // second request.
    config.restart_budget.max_attempts_per_window = 1;
    let readiness = SupervisedProviderReadinessV1::new(
        enabled_composition(Arc::clone(&port)),
        Arc::new(ThreadBoundedProviderCallV1::default()),
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        1,
        limits(),
        config,
    )
    .expect("mounted supervised readiness");
    let request = handshake_request(exact_scope("worktree-a"));

    for pass in 0..8_i64 {
        readiness
            .ready_target(&request, 1_000 + pass)
            .expect("readiness target on a healthy provider");
    }
    // Readiness is proven per request, so the provider really was contacted
    // every time — the budget simply was not spent doing it.
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 8);
}

/// An owner bound to one worktree refuses a request for another, and the
/// refusal is the supervisor's typed scope mismatch. Catches an owner map
/// that hands the wrong supervisor to a scope.
#[test]
fn an_owner_refuses_a_request_for_another_worktree() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let owner = readiness
        .owner_for(&handshake_request(exact_scope("worktree-a")), 1_000)
        .expect("owner");

    let foreign = handshake_request(exact_scope("worktree-b"));
    match owner.ready_target(&foreign, 1_000) {
        Err(SupervisedReadinessError::Unavailable { kind, .. }) => {
            assert_eq!(kind, DegradationKindV1::ScopeMismatch);
        }
        other => panic!("expected a scope mismatch, got {other:?}"),
    }
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 0);
}

/// A provider that reports a build identity other than the pinned one is
/// refused fail-closed by the mounted path. This defect is invisible to the
/// fabric — only the supervisor knows what the host pinned — so it catches a
/// mount that never runs the supervisor's own readiness validation.
#[test]
fn an_unpinned_build_identity_is_refused_at_the_mounted_seam() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = SupervisedProviderReadinessV1::new(
        enabled_composition(Arc::clone(&port)),
        Arc::new(ThreadBoundedProviderCallV1::default()),
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        1,
        limits(),
        readiness_config(4),
    )
    .expect("mounted supervised readiness")
    .with_pinned_identity(
        Some("4444444444444444444444444444444444444444444444444444444444444444".to_owned()),
        None,
    );
    let request = handshake_request(exact_scope("worktree-a"));

    match readiness.ready_target(&request, 1_000) {
        Err(SupervisedReadinessError::Unavailable { kind, detail, .. }) => {
            assert_eq!(kind, DegradationKindV1::HandshakeContractViolation);
            assert!(detail.contains("pinned"), "unexpected detail: {detail}");
        }
        other => panic!("expected a contract violation, got {other:?}"),
    }
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
}

/// A provider that answers `Success` while omitting its state namespace never
/// yields a readiness target. The refusal is typed and the host continues;
/// once the provider answers correctly the very next admitted pass succeeds,
/// so the mount holds no sticky failure.
#[test]
fn a_malformed_success_never_yields_a_readiness_target() {
    let port = Arc::new(MountedNativePort::new());
    port.omit_state_namespace.store(true, Ordering::Relaxed);
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = handshake_request(exact_scope("worktree-a"));

    match readiness.ready_target(&request, 1_000) {
        Err(SupervisedReadinessError::Unavailable {
            kind,
            terminal_code,
            ..
        }) => {
            assert_eq!(kind, DegradationKindV1::HandshakeRefused);
            assert_eq!(terminal_code, Some(TerminalCode::ContractViolation));
        }
        other => panic!("expected typed unavailability, got {other:?}"),
    }
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);

    port.omit_state_namespace.store(false, Ordering::Relaxed);
    assert!(readiness.ready_target(&request, 10_000_000).is_ok());
}

/// A crash reported through the mounted owner produces the typed `Crashed`
/// degradation and invalidates readiness. Catches a crash report that only
/// flips a coarse availability flag.
#[test]
fn a_crash_reported_through_the_mount_is_typed() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(port), 4);
    let request = handshake_request(exact_scope("worktree-a"));
    let owner = readiness.owner_for(&request, 500).expect("owner");
    assert!(owner.ready_target(&request, 1_000).is_ok());

    assert_eq!(
        owner.report_crash().expect("crash"),
        DegradationKindV1::Crashed
    );
    assert_eq!(
        owner.current_degradation(),
        Some(DegradationKindV1::Crashed)
    );
}

/// A provider whose handshake never returns is a genuinely non-returning
/// call, not an error: this port blocks until the test releases it.
struct HangingNativePort {
    descriptor: ProviderDescriptor,
    gate: std::sync::Mutex<bool>,
    released: std::sync::Condvar,
    hanging: AtomicBool,
    handshake_calls: AtomicUsize,
    entered: AtomicUsize,
}

impl HangingNativePort {
    fn new() -> Self {
        Self {
            descriptor: descriptor(),
            gate: std::sync::Mutex::new(false),
            released: std::sync::Condvar::new(),
            hanging: AtomicBool::new(true),
            handshake_calls: AtomicUsize::new(0),
            entered: AtomicUsize::new(0),
        }
    }

    /// Releases every blocked handshake so the abandoned worker can exit.
    fn release(&self) {
        let mut released = self
            .gate
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *released = true;
        self.released.notify_all();
    }

    fn block_until_released(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self
            .gate
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // The wall-clock cap is a test-suite safety net, never the bound under
        // test: the assertion is that the *host* returned long before it.
        let deadline = std::time::Duration::from_secs(30);
        let started = std::time::Instant::now();
        while !*released && started.elapsed() < deadline {
            let (guard, _) = self
                .released
                .wait_timeout(released, std::time::Duration::from_millis(50))
                .unwrap_or_else(|poison| poison.into_inner());
            released = guard;
        }
    }
}

impl NativeMemoryApplicationPort for HangingNativePort {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        self.handshake_calls.fetch_add(1, Ordering::SeqCst);
        if self.hanging.load(Ordering::SeqCst) {
            self.block_until_released();
        }
        HandshakeResponse {
            terminal: TerminalRecord::new(
                ProviderOperation::Handshake,
                OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
                FallbackDirective::forbidden(),
                request.request_id.clone(),
                request.exact_scope.exact_scope_sha256(),
                None,
            )
            .expect("handshake terminal"),
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some("native.hanging-instance".to_owned()),
            state_namespace: Some("native.mounted-namespace".to_owned()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
            ready_receipt_sha256: Some(ONE_SHA.to_owned()),
            warnings: Vec::new(),
        }
    }

    fn health(&self, _call: &ProviderCall) -> ProviderReply {
        unexpected()
    }

    fn recall(&self, _call: &ProviderCall) -> ProviderReply {
        unexpected()
    }
}

fn hanging_composition(port: Arc<HangingNativePort>) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose(NativeProviderActivation::Enabled {
            fabric_config: FabricConfig {
                max_registered_providers: 1,
                max_in_flight: 4,
            },
            port,
            registration_revision: 1,
            mode: EnabledProviderMode::Active,
        })
        .expect("enabled composition"),
    )
}

/// A provider whose handshake **never returns** does not wedge the host: the
/// supervised pass returns a typed refusal inside its own budget, the host
/// stays usable while the provider is still stuck, and the same mount reaches
/// readiness once the provider answers again.
///
/// This is the acceptance criterion "host remains bounded and usable" against
/// a genuinely non-returning call rather than a fast error. It fails against
/// any lifecycle path that synchronously invokes the provider and merely
/// carries a deadline value alongside it.
#[test]
fn a_provider_that_never_returns_is_abandoned_and_the_host_stays_usable() {
    let port = Arc::new(HangingNativePort::new());
    let mut config = readiness_config(4);
    // 100ms is the whole budget a handshake gets. The provider is stuck for
    // 30 seconds.
    config.handshake_budget_micros = 100_000;
    let readiness = SupervisedProviderReadinessV1::new(
        hanging_composition(Arc::clone(&port)),
        Arc::new(ThreadBoundedProviderCallV1::default()),
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        1,
        limits(),
        config,
    )
    .expect("mounted supervised readiness");
    let request = handshake_request(exact_scope("worktree-hanging"));

    let started = std::time::Instant::now();
    let error = readiness
        .ready_target(&request, 1_000)
        .expect_err("a provider that never answers cannot be ready");
    let elapsed = started.elapsed();
    match error {
        SupervisedReadinessError::Unavailable { kind, detail, .. } => {
            assert_eq!(kind, DegradationKindV1::HandshakeTransportFailed);
            assert!(detail.contains("abandoned"), "unexpected detail: {detail}");
        }
        other => panic!("expected typed unavailability, got {other}"),
    }
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the host waited {elapsed:?} on a provider it gave 100ms"
    );
    assert_eq!(
        port.entered.load(Ordering::SeqCst),
        1,
        "the provider really was entered and really did not return"
    );

    // The host is still usable while the provider is still stuck: another
    // exact scope is admitted and refused typed, again inside its budget.
    let other = handshake_request(exact_scope("worktree-other"));
    let second_started = std::time::Instant::now();
    assert!(
        readiness.ready_target(&other, 200_000_000).is_err(),
        "a stuck provider cannot make another scope ready"
    );
    assert!(
        second_started.elapsed() < std::time::Duration::from_secs(5),
        "a second scope must not inherit the first scope's hang"
    );

    // The provider answers again, and the same mount reaches readiness: the
    // abandonment left no sticky failure.
    port.hanging.store(false, Ordering::SeqCst);
    port.release();
    let recovered = handshake_request(exact_scope("worktree-recovered"));
    readiness
        .ready_target(&recovered, 400_000_000)
        .expect("a provider that answers again reaches readiness");
}

/// A caller whose own deadline has already elapsed is refused before any
/// adapter is contacted at all.
#[test]
fn an_elapsed_caller_deadline_is_refused_without_contacting_the_provider() {
    let port = Arc::new(MountedNativePort::new());
    let readiness = mount(enabled_composition(Arc::clone(&port)), 4);
    let request = HandshakeRequest::new(HandshakeRequestParts {
        provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native provider"),
        registration_revision: 1,
        exact_scope: exact_scope("worktree-a"),
        request_id: "elapsed-readiness".to_owned(),
        required_capabilities: vec![
            OwnedVersionedId::new("provider.health.v1").expect("health capability"),
        ],
        host_limits: limits(),
        control: OperationControl::new(5_000, 1_000, CancellationToken::new()),
        challenge_nonce: [5; 32],
    })
    .expect("handshake request");

    match readiness.ready_target(&request, 6_000) {
        Err(SupervisedReadinessError::RequestTerminal { terminal_code, .. }) => {
            assert_eq!(terminal_code, TerminalCode::DeadlineExceeded)
        }
        other => panic!("expected an elapsed-deadline refusal, got {other:?}"),
    }
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn an_expired_queued_dispatch_preserves_the_shared_runtime() {
    let port = Arc::new(MountedNativePort::new());
    let runtime = Arc::new(SharedRuntimeOwner::default());
    let readiness = Arc::new(mount(
        owned_observer_composition(Arc::clone(&port), Arc::clone(&runtime)),
        2,
    ));
    let request = handshake_request(exact_scope("worktree-ready"));
    let dispatch = readiness
        .ready_dispatch_with_evidence(&request, 1_000)
        .expect("queued dispatch fixture must complete its setup and synchronization");
    let mut queued = handshake_request(exact_scope("worktree-queued"));
    queued.control = OperationControl::new(i64::MAX, 50, CancellationToken::new());
    let queued_control = queued.control.clone();
    let queued_readiness = Arc::clone(&readiness);
    let (entered, entered_rx) = std::sync::mpsc::sync_channel(1);
    let caller = std::thread::spawn(move || {
        entered
            .send(())
            .expect("queued dispatch fixture must complete its setup and synchronization");
        queued_readiness.ready_target(&queued, 1_000)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("queued dispatch fixture must complete its setup and synchronization");
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while queued_control.snapshot().is_ok() && std::time::Instant::now() < until {
        std::thread::yield_now();
    }
    assert!(matches!(
        queued_control.snapshot(),
        Err(TerminalCode::DeadlineExceeded)
    ));
    drop(dispatch);
    assert!(matches!(
        caller
            .join()
            .expect("queued dispatch fixture must complete its setup and synchronization"),
        Err(SupervisedReadinessError::RequestTerminal {
            terminal_code: TerminalCode::DeadlineExceeded,
            ..
        })
    ));
    assert_eq!(readiness.supervised_scopes(), 1);
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
    assert!(runtime.running.load(Ordering::SeqCst));
    assert_eq!(runtime.stops.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.kills.load(Ordering::SeqCst), 0);
    assert!(readiness.quarantined_scopes().is_empty());
    readiness
        .ready_target(&handshake_request(exact_scope("worktree-ready")), 2_000)
        .expect("queued dispatch fixture must complete its setup and synchronization");
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn a_cancelled_queued_dispatch_preserves_the_shared_runtime() {
    let port = Arc::new(MountedNativePort::new());
    let runtime = Arc::new(SharedRuntimeOwner::default());
    let readiness = Arc::new(mount(
        owned_observer_composition(Arc::clone(&port), Arc::clone(&runtime)),
        2,
    ));
    let request = handshake_request(exact_scope("worktree-ready"));
    let dispatch = readiness
        .ready_dispatch_with_evidence(&request, 1_000)
        .expect("queued dispatch fixture must complete its setup and synchronization");
    let queued = handshake_request(exact_scope("worktree-queued"));
    let cancellation = queued.control.cancellation();
    let queued_readiness = Arc::clone(&readiness);
    let (entered, entered_rx) = std::sync::mpsc::sync_channel(1);
    let caller = std::thread::spawn(move || {
        entered
            .send(())
            .expect("queued dispatch fixture must complete its setup and synchronization");
        queued_readiness.ready_target(&queued, 1_000)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("queued dispatch fixture must complete its setup and synchronization");
    cancellation.cancel();
    drop(dispatch);
    assert!(matches!(
        caller
            .join()
            .expect("queued dispatch fixture must complete its setup and synchronization"),
        Err(SupervisedReadinessError::RequestTerminal {
            terminal_code: TerminalCode::Cancelled,
            ..
        })
    ));
    assert_eq!(readiness.supervised_scopes(), 1);
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 1);
    assert!(runtime.running.load(Ordering::SeqCst));
    assert_eq!(runtime.stops.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.kills.load(Ordering::SeqCst), 0);
    assert!(readiness.quarantined_scopes().is_empty());
    readiness
        .ready_target(&handshake_request(exact_scope("worktree-ready")), 2_000)
        .expect("queued dispatch fixture must complete its setup and synchronization");
    assert_eq!(port.handshake_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn refused_handshake_preserves_its_typed_provider_terminal() {
    for terminal_code in [
        TerminalCode::StaleIdentity,
        TerminalCode::InvalidRequest,
        TerminalCode::ScopeMismatch,
        TerminalCode::ProviderUnavailable,
    ] {
        let mut port = MountedNativePort::new();
        port.handshake_terminal = terminal_code;
        let readiness = mount(enabled_composition(Arc::new(port)), 4);
        let error = readiness
            .ready_target(&handshake_request(exact_scope("worktree-terminal")), 1_000)
            .expect_err("handshake terminal must refuse readiness");
        match error {
            SupervisedReadinessError::Unavailable {
                kind,
                terminal_code: retained,
                ..
            } => {
                assert_eq!(kind, DegradationKindV1::HandshakeRefused);
                assert_eq!(retained, Some(terminal_code));
            }
            other => panic!("expected typed handshake refusal, got {other}"),
        }
    }
}
