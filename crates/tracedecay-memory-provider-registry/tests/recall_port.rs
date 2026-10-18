//! Behavioral tests for the production cognitive-recall port: exact-scope
//! admission through the real fabric and Native adapter, typed degradations
//! for cancellation, deadlines, and provider unavailability, typed errors
//! for scope rejection, unattributable outcomes, and disabled composition,
//! and explicit routing: the pinned provider identity on every result,
//! pre-contact refusal of observer or mismatched registrations, and fallback
//! that is never dispatched without a matching host rule.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod recall_fixture;

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use recall_fixture::*;
use tracedecay_contracts::memory::{
    CognitiveRecallDegradation, CognitiveRecallPort, CognitiveRecallRequest,
};
use tracedecay_contracts::{
    CancellationContext, CancellationSignal, Deadline, RequestId, ResolvedScope, now_micros,
};
use tracedecay_domain::{ProjectId, RefId, RepositoryId, UtcMicros, WorktreeId};
use tracedecay_memory_provider_api::contract::TerminalCode;
use tracedecay_memory_provider_api::{
    CommittedEffectEvidence, FallbackDirective, HandshakeRequest, HandshakeResponse,
    MemoryProvider, OwnedExactScope, OwnedProviderId, OwnedVersionedId, PinnedFallbackPolicy,
    ProviderCall, ProviderDescriptor, ProviderOperation, ProviderReply, TerminalRecord,
};
use tracedecay_memory_provider_native::NativeMemoryApplicationPort;
use tracedecay_memory_provider_registry::{
    ActiveRoutingPolicy, BudgetExclusionReason, CognitiveRecallPortError,
    CognitiveRecallPortInputsV1, DegradationCause, DegradationDeclinedReason, DegradationRule,
    DuplicateReason, EnabledProviderMode, ExactScopeBinding, ExactScopeBindingError, FabricConfig,
    FallbackDecision, FallbackDeclinedReason, FallbackRule, NATIVE_PROVIDER_ID,
    NativeProviderActivation, ObserverProviderRegistration, PinnedDegradationPolicy,
    ProjectCognitiveRecallPortV1, ProjectMemoryProviderComposition, ProviderMode,
    ProviderReadiness, RecallAdmissionAuditError, RecallAdmissionError, RecallAdmissionObserver,
    RecallAdmissionReport, RecallBudgetsV1, RecallDenialReason, RecallScopeBindingsV1,
    RecallSelectionPolicyV1, RegistryError, RoutingError, ScopeBinding, ScopeField,
    UnknownValidityPolicy,
};

/// Host-side scope binding standing in for the composition root: profile and
/// session identities are host-owned constants, checkout identity comes from
/// the resolved scope verbatim.
struct TestScopeBinding;

impl ExactScopeBinding for TestScopeBinding {
    fn bind_exact_scope(
        &self,
        scope: &ResolvedScope,
    ) -> Result<OwnedExactScope, ExactScopeBindingError> {
        let reference = scope.reference.as_ref().ok_or_else(|| {
            ExactScopeBindingError::ReferenceUnavailable {
                project_id: scope.project_id.as_str().to_owned(),
            }
        })?;
        Ok(OwnedExactScope::new(
            "profile-recall",
            scope.project_id.as_str(),
            scope.repository_id.as_str(),
            scope.worktree_id.as_str(),
            reference.as_str(),
            "session-recall",
            scope.scope_digest.as_str(),
        )?)
    }
}

#[derive(Default)]
struct LedgerObserver(Mutex<Vec<RecallAdmissionReport>>);

impl RecallAdmissionObserver for LedgerObserver {
    fn observe_admission(
        &self,
        report: &RecallAdmissionReport,
    ) -> Result<(), RecallAdmissionAuditError> {
        self.0.lock().expect("ledger lock").push(report.clone());
        Ok(())
    }
}

/// Audit sink that refuses every report, standing in for an unwritable ledger.
struct RefusingObserver;

impl RecallAdmissionObserver for RefusingObserver {
    fn observe_admission(
        &self,
        report: &RecallAdmissionReport,
    ) -> Result<(), RecallAdmissionAuditError> {
        Err(RecallAdmissionAuditError {
            request_id: report.request_id.clone(),
            source: "ledger unwritable".into(),
        })
    }
}

fn resolved_scope(reference: Option<&str>) -> ResolvedScope {
    ResolvedScope::new(
        ProjectId::new("project.recall-port").expect("project id"),
        RepositoryId::new("repository.recall-port").expect("repository id"),
        WorktreeId::new("worktree.recall-port").expect("worktree id"),
        reference.map(|reference| RefId::new(reference).expect("reference id")),
    )
    .expect("resolved scope")
}

/// The caller's live cancellation identity for a recall: the same token id
/// the request carries, so the port accepts it as the request's own signal.
fn live_signal() -> CancellationSignal {
    CancellationSignal::active("token.recall-port").expect("live cancellation signal")
}

fn request(
    scope: ResolvedScope,
    deadline_offset_micros: i64,
    cancelled: bool,
) -> CognitiveRecallRequest {
    let now = now_micros();
    let cancellation = if cancelled {
        CancellationContext::cancelled("token.recall-port", now).expect("cancelled context")
    } else {
        CancellationContext::active("token.recall-port").expect("active context")
    };
    CognitiveRecallRequest::new(
        scope,
        RequestId::new("request.recall-port").expect("request id"),
        Deadline::new(UtcMicros(now.0.saturating_add(deadline_offset_micros))).expect("deadline"),
        cancellation,
        "recall admission",
        8,
    )
    .expect("recall request")
}

fn compose_mode(
    port: Arc<dyn NativeMemoryApplicationPort>,
    mode: EnabledProviderMode,
) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose(NativeProviderActivation::Enabled {
            fabric_config: FabricConfig {
                max_registered_providers: 1,
                max_in_flight: 2,
            },
            port,
            registration_revision: 31,
            mode,
        })
        .expect("enabled composition"),
    )
}

fn mount(
    composition: Arc<ProjectMemoryProviderComposition>,
    observer: Arc<LedgerObserver>,
) -> Result<ProjectCognitiveRecallPortV1, CognitiveRecallPortError> {
    mount_with(composition, observer, budgets())
}

fn mount_with(
    composition: Arc<ProjectMemoryProviderComposition>,
    observer: Arc<dyn RecallAdmissionObserver>,
    budgets: RecallBudgetsV1,
) -> Result<ProjectCognitiveRecallPortV1, CognitiveRecallPortError> {
    mount_routed(
        composition,
        observer,
        budgets,
        routing(NATIVE_PROVIDER_ID, 31, FallbackRule::Forbidden),
    )
}

fn mount_routed(
    composition: Arc<ProjectMemoryProviderComposition>,
    observer: Arc<dyn RecallAdmissionObserver>,
    budgets: RecallBudgetsV1,
    routing: ActiveRoutingPolicy,
) -> Result<ProjectCognitiveRecallPortV1, CognitiveRecallPortError> {
    ProjectCognitiveRecallPortV1::mount(CognitiveRecallPortInputsV1 {
        invocation_boundary: test_invocation_boundary(),
        composition,
        scope_binding: Arc::new(TestScopeBinding),
        admission_observer: observer,
        routing,
        host_limits: limits(),
        policy_revision: 1,
        budgets,
    })
}

fn routing(provider: &str, revision: u64, fallback: FallbackRule) -> ActiveRoutingPolicy {
    let degradation = PinnedDegradationPolicy::new(
        "policy.recall.degradation",
        1,
        DegradationCause::ALL.iter().copied(),
    )
    .expect("degradation policy");
    ActiveRoutingPolicy::new_with_degradation(
        OwnedProviderId::new(provider).expect("provider id"),
        revision,
        fallback,
        DegradationRule::ExplicitPinned(degradation),
    )
    .expect("routing policy")
}

/// The registered provider's readiness as the fabric reports it; `NotReady`
/// proves no handshake was ever accepted for it.
fn native_readiness(composition: &ProjectMemoryProviderComposition) -> ProviderReadiness {
    let statuses = composition
        .registry()
        .expect("enabled composition")
        .statuses()
        .expect("statuses");
    assert_eq!(statuses.len(), 1);
    statuses[0].readiness
}

/// The host-owned candidate budget is the one admission enforces: when it is
/// smaller than the application request, a provider that returns more than
/// the host budget is refused even though it stayed under the request.
#[tokio::test]
async fn host_candidate_budget_is_enforced_when_smaller_than_the_request() {
    let provider = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(LedgerObserver::default());
    // The fixture returns six candidates; the request asks for eight.
    let host_budgets = RecallBudgetsV1 {
        maximum_candidates: 5,
        ..budgets()
    };
    let port = mount_with(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
        host_budgets,
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let request = request(scope, 60_000_000, false);
    assert_eq!(request.maximum_candidates(), 8);

    let error = port
        .recall_admitted(request, &live_signal())
        .await
        .expect_err("provider exceeded the host candidate budget");
    assert!(
        matches!(
            error,
            CognitiveRecallPortError::Admission(RecallAdmissionError::CandidateBudgetExceeded {
                returned: 6,
                maximum: 5,
            })
        ),
        "{error:?}"
    );
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 1);
    assert!(observer.0.lock().unwrap().is_empty());
}

/// An audit sink that cannot retain the report fails the recall: admitted
/// content is never delivered without its denial ledger.
#[tokio::test]
async fn unwritable_audit_sink_withholds_the_admitted_result() {
    let provider = Arc::new(RecallFixturePort::new());
    let port = mount_with(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        Arc::new(RefusingObserver),
        budgets(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let error = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect_err("audit sink refused the report");
    match error {
        CognitiveRecallPortError::AdmissionAudit(audit) => {
            assert_eq!(audit.request_id, "request.recall-port");
        }
        other => panic!("expected an admission audit error, got {other:?}"),
    }
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 1);
}

/// A provider that returns the same memory twice must not have it delivered
/// twice: the mounted port prunes redundant evidence before anything reaches
/// the application result, and the selection receipt names what was pruned
/// and why.
#[tokio::test]
async fn mounted_recall_prunes_duplicate_candidates_from_the_application_result() {
    let mut fixture = RecallFixturePort::new();
    fixture.candidate_contents = Some(duplicate_candidate_stream());
    let provider = Arc::new(fixture);
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("bridged recall");

    let delivered: Vec<&str> = outcome
        .result
        .candidates()
        .iter()
        .map(|candidate| candidate.candidate_id())
        .collect();
    assert_eq!(delivered, vec!["aa-duplicate-1", "mm-distinct", "zz-other"]);

    let selection = outcome.selection.expect("selection receipt");
    assert_eq!(selection.deduplicated.len(), 1);
    assert_eq!(selection.deduplicated[0].candidate_id, "ab-duplicate-2");
    assert_eq!(
        selection.deduplicated[0].duplicate_of_candidate_id,
        "aa-duplicate-1"
    );
    assert_eq!(
        selection.deduplicated[0].reason,
        DuplicateReason::ContentDigest
    );
    assert!(selection.budget_excluded.is_empty());
    // The report still accounts for all four admitted candidates: selection
    // prunes what is delivered, never what was admitted.
    let report = outcome.report.expect("admission report");
    assert_eq!(report.admitted_count, 4);
    assert!(report.denied.is_empty(), "{:?}", report.denied);
}

/// Under a constrained advisory-context budget a duplicate must not displace
/// a distinct candidate: with a budget of two and the duplicate pair first in
/// host order, an unpruned stream would deliver the same memory twice and
/// drop the distinct evidence entirely. Every candidate that did not fit is
/// still named in the receipt.
#[tokio::test]
async fn duplicates_do_not_displace_a_distinct_candidate_under_a_constrained_budget() {
    let mut fixture = RecallFixturePort::new();
    fixture.candidate_contents = Some(duplicate_candidate_stream());
    let provider = Arc::new(fixture);
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port")
    .with_selection_policy(RecallSelectionPolicyV1::new(2).expect("selection policy"));
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("bridged recall");

    let delivered: Vec<&str> = outcome
        .result
        .candidates()
        .iter()
        .map(|candidate| candidate.candidate_id())
        .collect();
    assert_eq!(delivered, vec!["aa-duplicate-1", "mm-distinct"]);

    let selection = outcome.selection.expect("selection receipt");
    assert_eq!(selection.deduplicated.len(), 1);
    assert_eq!(selection.deduplicated[0].candidate_id, "ab-duplicate-2");
    assert_eq!(selection.budget_excluded.len(), 1);
    assert_eq!(selection.budget_excluded[0].candidate_id, "zz-other");
    assert_eq!(
        selection.budget_excluded[0].reason,
        BudgetExclusionReason::SelectionBudgetExhausted {
            maximum_selected: 2
        }
    );
    // Every admitted candidate is accounted for exactly once.
    let mut accounted: Vec<&str> = selection.accounted_candidate_ids().collect();
    accounted.sort_unstable();
    assert_eq!(
        accounted,
        vec![
            "aa-duplicate-1",
            "ab-duplicate-2",
            "mm-distinct",
            "zz-other"
        ]
    );
}

#[tokio::test]
async fn mounted_recall_preserves_opposed_claims_while_pruning_exact_duplicates() {
    let positive = "after validation and review of production configuration the deployment is safe";
    let negative =
        "after validation and review of production configuration the deployment is unsafe";
    let mut fixture = RecallFixturePort::new();
    fixture.candidate_contents = Some(
        [
            ("a-positive", positive),
            ("b-duplicate", positive),
            ("c-negative", negative),
        ]
        .into_iter()
        .map(|(id, content)| (id.to_owned(), content.to_owned()))
        .collect(),
    );
    let port = mount(
        compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port")
    .with_selection_policy(RecallSelectionPolicyV1::new(2).expect("selection policy"));
    let outcome = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect("bridged recall");
    assert_eq!(
        outcome
            .result
            .candidates()
            .iter()
            .map(|candidate| candidate.candidate_id())
            .collect::<Vec<_>>(),
        ["a-positive", "c-negative"]
    );
    let selection = outcome.selection.expect("selection receipt");
    assert_eq!(selection.deduplicated.len(), 1);
    assert_eq!(selection.deduplicated[0].candidate_id, "b-duplicate");
    assert_eq!(
        selection.deduplicated[0].reason,
        DuplicateReason::ContentDigest
    );
    assert!(selection.budget_excluded.is_empty());
    let mut accounted = selection.accounted_candidate_ids().collect::<Vec<_>>();
    accounted.sort_unstable();
    assert_eq!(accounted, ["a-positive", "b-duplicate", "c-negative"]);
}

/// A provider candidate stream whose first two entries are the same memory
/// under different candidate ids, followed by two distinct memories. Host
/// order is candidate-id order because every fixture candidate scores the
/// same, so the duplicate pair is what an unpruned stream would spend the
/// first two budget slots on.
fn duplicate_candidate_stream() -> Vec<(String, String)> {
    let repeated = "the release checklist requires a database migration before shipping";
    [
        ("aa-duplicate-1", repeated),
        ("ab-duplicate-2", repeated),
        (
            "mm-distinct",
            "telemetry sampling runs at one percent in staging",
        ),
        ("zz-other", "release notes are generated from the changelog"),
    ]
    .into_iter()
    .map(|(id, content)| (id.to_owned(), content.to_owned()))
    .collect()
}

#[tokio::test]
async fn port_admits_only_exact_scope_current_candidates_and_reports_denials() {
    let provider = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let outcome = port
        .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
        .await
        .expect("bridged recall");

    assert!(outcome.result.is_complete(), "{:?}", outcome.result);
    assert_eq!(outcome.result.scope(), &scope);
    let admitted: Vec<_> = outcome
        .result
        .candidates()
        .iter()
        .map(|candidate| candidate.candidate_id())
        .collect();
    assert_eq!(admitted, vec!["in-scope-1", "in-scope-2"]);
    for candidate in outcome.result.candidates() {
        assert!(!candidate.content().contains(SECRET_CONTENT));
        assert_eq!(
            candidate.stable_reference(),
            Some(format!("memory:{}", candidate.candidate_id()).as_str())
        );
        assert_eq!(candidate.explanation(), Some("fixture match"));
    }
    assert!(outcome.unhydrated_reference_candidate_ids.is_empty());

    let report = outcome.report.expect("admission report");
    let denied: Vec<_> = report
        .denied
        .iter()
        .map(|denied| (denied.candidate_id.as_str(), denied.reason.clone()))
        .collect();
    assert_eq!(
        denied,
        vec![
            (
                "cross-worktree",
                RecallDenialReason::ScopeMismatch {
                    field: ScopeField::WorktreeIdentity
                }
            ),
            ("revoked", RecallDenialReason::Revoked),
            (
                "cross-repository",
                RecallDenialReason::ScopeMismatch {
                    field: ScopeField::RepositoryIdentity
                }
            ),
            ("stale-exact-scope", RecallDenialReason::StaleIdentity),
        ]
    );
    assert_eq!(
        report.authorized_scope_bindings,
        RecallScopeBindingsV1::new([
            ScopeBinding::ExactCodingScope,
            ScopeBinding::CheckoutObservations,
            ScopeBinding::ProjectFacts,
            ScopeBinding::ProfileFacts
        ])
    );
    assert_eq!(report.request_id, "request.recall-port");
    let expected_scope = TestScopeBinding
        .bind_exact_scope(&scope)
        .expect("bound scope");
    assert_eq!(
        report.exact_scope_sha256,
        expected_scope.exact_scope_sha256()
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains(SECRET_CONTENT)
    );
    assert_eq!(observer.0.lock().unwrap().len(), 1);
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 1);

    // The application port path returns exactly the admitted result and
    // reports through the same observer.
    let via_port = port
        .bound(live_signal())
        .recall(request(scope, 60_000_000, false))
        .await
        .expect("port recall");
    assert_eq!(via_port.candidates().len(), 2);
    assert!(via_port.is_complete());
    assert_eq!(observer.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn cancelled_and_elapsed_requests_degrade_without_provider_contact() {
    let provider = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let cancelled = port
        .recall_admitted(request(scope.clone(), 60_000_000, true), &live_signal())
        .await
        .expect("cancelled recall");
    assert_eq!(
        cancelled.result.degradation(),
        Some(CognitiveRecallDegradation::Cancelled)
    );
    assert!(cancelled.result.candidates().is_empty());
    assert!(cancelled.report.is_none());

    let elapsed = port
        .recall_admitted(request(scope, -1, false), &live_signal())
        .await
        .expect("elapsed recall");
    assert_eq!(
        elapsed.result.degradation(),
        Some(CognitiveRecallDegradation::TimedOut)
    );
    assert!(elapsed.result.candidates().is_empty());
    assert!(elapsed.report.is_none());

    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);
    assert!(observer.0.lock().unwrap().is_empty());
}

/// A provider that parks inside `recall` until the control it was dispatched
/// with is cancelled. It never returns a normal outcome on its own, so a
/// recall over it can only terminate if the host's live cancellation identity
/// actually reached the provider's own token.
struct BlockingRecallPort {
    descriptor: ProviderDescriptor,
    /// Signalled once, from inside `recall`, the moment the provider is in the
    /// call. A permit is stored even when nobody is waiting yet, so the test
    /// can never miss the entry it is about to act on.
    entered_recall: Arc<tokio::sync::Notify>,
    /// Signalled once the provider has decided whether it saw the caller's
    /// cancellation, so the test waits on that decision rather than polling
    /// for it.
    cancellation_decided: Arc<tokio::sync::Notify>,
    observed_cancellation: Arc<std::sync::atomic::AtomicBool>,
    handshake_calls: std::sync::atomic::AtomicUsize,
    recall_calls: std::sync::atomic::AtomicUsize,
}

impl BlockingRecallPort {
    fn new() -> Self {
        Self {
            descriptor: descriptor(),
            entered_recall: Arc::new(tokio::sync::Notify::new()),
            cancellation_decided: Arc::new(tokio::sync::Notify::new()),
            observed_cancellation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            handshake_calls: std::sync::atomic::AtomicUsize::new(0),
            recall_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl NativeMemoryApplicationPort for BlockingRecallPort {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        self.handshake_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        HandshakeResponse {
            terminal: TerminalRecord::new(
                ProviderOperation::Handshake,
                OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
                FallbackDirective::forbidden(),
                request.request_id.clone(),
                request.exact_scope.exact_scope_sha256(),
                None,
            )
            .expect("handshake terminal"),
            descriptor: Some(self.descriptor.clone()),
            provider_instance_id: Some("native.blocking-recall".to_owned()),
            state_namespace: Some("native.recall-scope".to_owned()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
            ready_receipt_sha256: Some(ONE_SHA.to_owned()),
            warnings: Vec::new(),
        }
    }

    fn recall(&self, call: &ProviderCall) -> ProviderReply {
        self.recall_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.entered_recall.notify_one();
        let cancellation = call.control.cancellation();
        // Bounded so a regression fails the assertions instead of hanging the
        // suite: a token that is never cancelled falls through to a success
        // terminal with no payload, which the port refuses loudly.
        let give_up_at = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !cancellation.is_cancelled() && std::time::Instant::now() < give_up_at {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let cancelled = cancellation.is_cancelled();
        self.observed_cancellation
            .store(cancelled, std::sync::atomic::Ordering::Release);
        self.cancellation_decided.notify_one();
        ProviderReply {
            terminal: TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                if cancelled {
                    TerminalCode::Cancelled
                } else {
                    TerminalCode::Success
                },
                CommittedEffectEvidence::none(Some(call.expected_state_generation)),
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                cancelled.then(|| "native.blocking-recall.cancelled".to_owned()),
            )
            .expect("recall terminal"),
            payload: None,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }

    fn health(&self, _call: &ProviderCall) -> ProviderReply {
        unexpected()
    }
}

/// Cancellation requested *after* the handshake and after dispatch reaches the
/// provider that is already working: the recall terminates as a typed
/// `cancelled` degradation with no admitted content and no admission report.
///
/// This fails if the port mints its own `CancellationToken` per control
/// instead of cloning the caller's live identity, because the provider would
/// then hold a token nothing cancels and would run to its bounded give-up.
#[tokio::test]
async fn cancellation_after_dispatch_reaches_the_working_provider() {
    let provider = Arc::new(BlockingRecallPort::new());
    let entered = Arc::clone(&provider.entered_recall);
    let decided = Arc::clone(&provider.cancellation_decided);
    let observed = Arc::clone(&provider.observed_cancellation);
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let signal = live_signal();

    let canceller = {
        let signal = signal.clone();
        tokio::spawn(async move {
            // Cancel only once the provider is demonstrably inside the call,
            // i.e. after the readiness handshake and after dispatch. The
            // provider signals that entry itself; waiting on the signal is
            // what makes "cancellation reached work already in flight" a fact
            // rather than a guess about scheduling.
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
                .await
                .expect("the provider must be entered before its caller withdraws");
            signal.cancel(now_micros());
        })
    };

    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &signal)
        .await
        .expect("cancelled recall terminates");
    canceller.await.expect("canceller task");

    // The caller is released the moment it withdraws, so the provider is still
    // running when `recall_admitted` returns: reading its record immediately
    // would race the very decoupling this port is supposed to have. The
    // provider publishes its own verdict when it reaches it, and the wait is
    // bounded well under its 10s give-up, so a port that minted its own token
    // -- leaving the provider holding a token nothing cancels -- still fails
    // this assertion rather than passing on a delay.
    tokio::time::timeout(std::time::Duration::from_secs(5), decided.notified())
        .await
        .expect("the provider must reach a verdict about the caller's cancellation");
    assert!(
        observed.load(Ordering::Acquire),
        "the working provider must observe the caller's own cancellation token"
    );
    assert_eq!(
        outcome.result.degradation(),
        Some(CognitiveRecallDegradation::Cancelled)
    );
    assert!(outcome.result.candidates().is_empty());
    assert!(outcome.report.is_none());
    assert!(outcome.normalization.is_none());
    assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 1);
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 1);
    assert!(observer.0.lock().unwrap().is_empty());
}

/// A live signal that is not the request's cancellation identity is refused:
/// an adapter may not swap in a token the caller's runtime cannot cancel.
#[tokio::test]
async fn a_foreign_cancellation_identity_is_refused_before_provider_contact() {
    let provider = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let foreign = CancellationSignal::active("token.some-other-request").expect("foreign signal");

    let error = port
        .recall_admitted(request(scope, 60_000_000, false), &foreign)
        .await
        .expect_err("foreign cancellation identity");
    assert!(
        matches!(
            &error,
            CognitiveRecallPortError::CancellationIdentityMismatch { expected, received }
                if expected == "token.recall-port" && received == "token.some-other-request"
        ),
        "{error:?}"
    );
    assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 0);
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);
    assert!(observer.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn observer_only_and_disabled_compositions_are_typed() {
    let provider = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Observer),
        observer.clone(),
    )
    .expect("mounted port");
    let error = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("observer composition cannot serve recall");
    match error {
        CognitiveRecallPortError::ProviderNotActive { provider_id, mode } => {
            assert_eq!(provider_id, NATIVE_PROVIDER_ID);
            assert_eq!(mode, ProviderMode::Observer);
        }
        other => panic!("observer must be refused by routing before contact: {other:?}"),
    }
    // Refused before any contact: no handshake, no recall.
    assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 0);
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);

    let disabled = Arc::new(
        ProjectMemoryProviderComposition::compose(NativeProviderActivation::Disabled)
            .expect("disabled composition"),
    );
    assert!(matches!(
        mount(disabled, observer).err(),
        Some(CognitiveRecallPortError::CompositionDisabled)
    ));
}

#[tokio::test]
async fn default_degradation_rule_returns_every_content_free_outcome_with_provider_identity() {
    let cases = [
        (
            TerminalCode::ProviderUnavailable,
            CognitiveRecallDegradation::Unavailable,
        ),
        (
            TerminalCode::Cancelled,
            CognitiveRecallDegradation::Cancelled,
        ),
        (
            TerminalCode::DeadlineExceeded,
            CognitiveRecallDegradation::TimedOut,
        ),
        (
            TerminalCode::CapabilityUnsupported,
            CognitiveRecallDegradation::Unsupported,
        ),
        (
            TerminalCode::CapacityExceeded,
            CognitiveRecallDegradation::BudgetExhausted,
        ),
    ];

    for (terminal_code, expected) in cases {
        let mut fixture = RecallFixturePort::new();
        fixture.terminal_code = terminal_code;
        let provider = Arc::new(fixture);
        let outcome = mount_routed(
            compose_mode(provider.clone(), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
            budgets(),
            ActiveRoutingPolicy::new(
                OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
                31,
                FallbackRule::Forbidden,
            )
            .expect("default routing policy"),
        )
        .expect("mounted port")
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .unwrap_or_else(|error| panic!("{terminal_code:?} must degrade by default: {error:?}"));

        assert_eq!(outcome.result.degradation(), Some(expected));
        assert_eq!(outcome.result.provider().provider_id(), NATIVE_PROVIDER_ID);
        assert_eq!(outcome.result.provider().registration_revision(), 31);
        assert_eq!(
            outcome.result.provider().provider_instance_id(),
            Some("native.recall-fixture")
        );
        assert!(outcome.result.candidates().is_empty());
        assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn content_free_readiness_outcomes_degrade_with_pinned_provider_identity() {
    let cases = [
        (
            TerminalCode::ProviderUnavailable,
            CognitiveRecallDegradation::Unavailable,
        ),
        (
            TerminalCode::Cancelled,
            CognitiveRecallDegradation::Cancelled,
        ),
        (
            TerminalCode::DeadlineExceeded,
            CognitiveRecallDegradation::TimedOut,
        ),
        (
            TerminalCode::CapabilityUnsupported,
            CognitiveRecallDegradation::Unsupported,
        ),
        (
            TerminalCode::CapacityExceeded,
            CognitiveRecallDegradation::BudgetExhausted,
        ),
    ];

    for (terminal_code, expected) in cases {
        let mut fixture = RecallFixturePort::new();
        fixture.handshake_terminal_code = terminal_code;
        let provider = Arc::new(fixture);
        let outcome = mount_routed(
            compose_mode(provider.clone(), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
            budgets(),
            ActiveRoutingPolicy::new(
                OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
                31,
                FallbackRule::Forbidden,
            )
            .expect("default routing policy"),
        )
        .expect("mounted port")
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .unwrap_or_else(|error| {
            panic!("readiness {terminal_code:?} must degrade by default: {error:?}")
        });

        assert_eq!(outcome.result.degradation(), Some(expected));
        assert_eq!(outcome.result.provider().provider_id(), NATIVE_PROVIDER_ID);
        assert_eq!(outcome.result.provider().registration_revision(), 31);
        assert_eq!(outcome.result.provider().provider_instance_id(), None);
        assert!(outcome.result.candidates().is_empty());
        assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn content_bearing_degradations_require_and_obey_an_explicit_policy() {
    fn default_policy() -> ActiveRoutingPolicy {
        ActiveRoutingPolicy::new(
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
            31,
            FallbackRule::Forbidden,
        )
        .expect("default routing policy")
    }

    fn explicit_policy(cause: DegradationCause) -> ActiveRoutingPolicy {
        ActiveRoutingPolicy::new_with_degradation(
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
            31,
            FallbackRule::Forbidden,
            DegradationRule::ExplicitPinned(
                PinnedDegradationPolicy::new("policy.recall.content-bearing", 3, [cause])
                    .expect("degradation policy"),
            ),
        )
        .expect("explicit routing policy")
    }

    let partial_port = |routing| {
        let mut fixture = RecallFixturePort::new();
        fixture.terminal_code = TerminalCode::Partial;
        mount_routed(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
            budgets(),
            routing,
        )
        .expect("mounted partial port")
    };
    let error = partial_port(default_policy())
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("partial content requires an explicit policy");
    assert!(matches!(
        error,
        CognitiveRecallPortError::DegradationNotAllowed {
            degradation: CognitiveRecallDegradation::Partial,
            reason: DegradationDeclinedReason::ContentBearingRequiresExplicitPolicy {
                cause: DegradationCause::Partial,
            },
            ..
        }
    ));
    let partial = partial_port(explicit_policy(DegradationCause::Partial))
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect("explicit partial policy admits the result");
    assert_eq!(
        partial.result.degradation(),
        Some(CognitiveRecallDegradation::Partial)
    );
    assert!(!partial.result.candidates().is_empty());
    assert_eq!(partial.result.provider().provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(partial.result.provider().registration_revision(), 31);

    let stale_port = |routing| {
        let mut fixture = RecallFixturePort::new();
        fixture
            .validity_overrides
            .insert("in-scope-1".to_owned(), validity_with("unknown", &[]));
        mount_routed(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
            budgets(),
            routing,
        )
        .expect("mounted stale port")
        .with_unknown_validity_policy(UnknownValidityPolicy::Degrade)
    };
    let error = stale_port(default_policy())
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("stale content requires an explicit policy");
    assert!(matches!(
        error,
        CognitiveRecallPortError::DegradationNotAllowed {
            degradation: CognitiveRecallDegradation::Stale,
            reason: DegradationDeclinedReason::ContentBearingRequiresExplicitPolicy {
                cause: DegradationCause::Stale,
            },
            ..
        }
    ));
    let stale = stale_port(explicit_policy(DegradationCause::Stale))
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect("explicit stale policy admits the result");
    assert_eq!(
        stale.result.degradation(),
        Some(CognitiveRecallDegradation::Stale)
    );
    assert!(!stale.result.candidates().is_empty());
    assert_eq!(stale.result.provider().provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(stale.result.provider().registration_revision(), 31);
}

#[tokio::test]
async fn allow_with_warning_still_requires_the_explicit_stale_policy_gate() {
    let mut fixture = RecallFixturePort::new();
    fixture
        .validity_overrides
        .insert("in-scope-1".to_owned(), validity_with("unknown", &[]));
    let error = mount_routed(
        compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
        budgets(),
        ActiveRoutingPolicy::new(
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
            31,
            FallbackRule::Forbidden,
        )
        .expect("default routing policy"),
    )
    .expect("mounted port")
    .with_unknown_validity_policy(UnknownValidityPolicy::AllowWithWarning)
    .recall_admitted(
        request(
            resolved_scope(Some("refs/heads/recall-port")),
            60_000_000,
            false,
        ),
        &live_signal(),
    )
    .await
    .expect_err("unknown-validity content must pass the stale policy gate");

    assert!(matches!(
        error,
        CognitiveRecallPortError::DegradationNotAllowed {
            degradation: CognitiveRecallDegradation::Stale,
            reason: DegradationDeclinedReason::ContentBearingRequiresExplicitPolicy {
                cause: DegradationCause::Stale,
            },
            ..
        }
    ));
}

#[tokio::test]
async fn pinned_degradation_policy_allows_only_its_named_causes() {
    fn policy(causes: impl IntoIterator<Item = DegradationCause>) -> ActiveRoutingPolicy {
        ActiveRoutingPolicy::new_with_degradation(
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
            31,
            FallbackRule::Forbidden,
            DegradationRule::ExplicitPinned(
                PinnedDegradationPolicy::new("policy.recall.subset", 9, causes)
                    .expect("degradation policy"),
            ),
        )
        .expect("routing policy")
    }

    let mut allowed_provider = RecallFixturePort::new();
    allowed_provider.terminal_code = TerminalCode::ProviderUnavailable;
    let allowed = mount_routed(
        compose_mode(Arc::new(allowed_provider), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
        budgets(),
        policy([DegradationCause::Unavailable]),
    )
    .expect("mounted allowed port")
    .recall_admitted(
        request(
            resolved_scope(Some("refs/heads/recall-port")),
            60_000_000,
            false,
        ),
        &live_signal(),
    )
    .await
    .expect("explicitly allowed unavailability degrades");
    assert_eq!(
        allowed.result.degradation(),
        Some(CognitiveRecallDegradation::Unavailable)
    );
    assert_eq!(allowed.result.provider().provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(allowed.result.provider().registration_revision(), 31);
    assert_eq!(
        allowed.result.provider().provider_instance_id(),
        Some("native.recall-fixture")
    );

    let mut denied_provider = RecallFixturePort::new();
    denied_provider.terminal_code = TerminalCode::ProviderUnavailable;
    let denied = mount_routed(
        compose_mode(Arc::new(denied_provider), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
        budgets(),
        policy([DegradationCause::TimedOut]),
    )
    .expect("mounted denied port")
    .recall_admitted(
        request(
            resolved_scope(Some("refs/heads/recall-port")),
            60_000_000,
            false,
        ),
        &live_signal(),
    )
    .await
    .expect_err("an unnamed degradation cause is refused");
    assert!(matches!(
        denied,
        CognitiveRecallPortError::DegradationNotAllowed {
            degradation: CognitiveRecallDegradation::Unavailable,
            reason: DegradationDeclinedReason::CauseNotAllowed {
                cause: DegradationCause::Unavailable,
                policy,
            },
            ..
        } if policy.policy_id() == "policy.recall.subset" && policy.policy_revision() == 9
    ));
}

#[tokio::test]
async fn unresolved_reference_is_a_typed_scope_error_before_any_provider_contact() {
    let provider = Arc::new(RecallFixturePort::new());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let error = port
        .recall_admitted(
            request(resolved_scope(None), 60_000_000, false),
            &live_signal(),
        )
        .await
        .expect_err("a scope without a reference has no exact branch identity");
    assert!(
        matches!(
            error,
            CognitiveRecallPortError::Scope(ExactScopeBindingError::ReferenceUnavailable { .. })
        ),
        "{error:?}"
    );
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn provider_terminals_map_to_typed_degradations_or_errors_never_empty_success() {
    let mut unavailable = RecallFixturePort::new();
    unavailable.terminal_code = TerminalCode::ProviderUnavailable;
    let port = mount(
        compose_mode(Arc::new(unavailable), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let outcome = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect("unavailable provider degrades the lane");
    assert_eq!(
        outcome.result.degradation(),
        Some(CognitiveRecallDegradation::Unavailable)
    );
    assert!(outcome.result.candidates().is_empty());
    assert!(outcome.report.is_none());

    let mut rejecting = RecallFixturePort::new();
    rejecting.terminal_code = TerminalCode::ScopeMismatch;
    let port = mount(
        compose_mode(Arc::new(rejecting), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let error = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("scope rejection is not a degradation");
    assert!(
        matches!(
            error,
            CognitiveRecallPortError::ScopeRejected {
                terminal_code: TerminalCode::ScopeMismatch,
                ..
            }
        ),
        "{error:?}"
    );

    let mut mismatched = RecallFixturePort::new();
    mismatched.outcome_request_identity = Some("someone-elses-request".to_owned());
    let port = mount(
        compose_mode(Arc::new(mismatched), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let error = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("unattributable outcome is refused");
    assert!(
        matches!(
            error,
            CognitiveRecallPortError::Admission(RecallAdmissionError::OutcomeBinding {
                field: "request_identity"
            })
        ),
        "{error:?}"
    );
}

/// Every result names the configured provider: complete results and
/// terminal degradations carry the handshake's runtime instance, and lanes
/// degraded before any contact still carry the pinned provider and revision.
#[tokio::test]
async fn every_result_carries_the_configured_provider_identity() {
    let provider = Arc::new(RecallFixturePort::new());
    let port = mount(
        compose_mode(provider.clone(), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let complete = port
        .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
        .await
        .expect("complete recall");
    let identity = complete.result.provider();
    assert_eq!(identity.provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(identity.registration_revision(), 31);
    assert_eq!(
        identity.provider_instance_id(),
        Some("native.recall-fixture")
    );
    assert_eq!(complete.fallback, FallbackDecision::NotApplicable);

    let cancelled = port
        .recall_admitted(request(scope.clone(), 60_000_000, true), &live_signal())
        .await
        .expect("cancelled recall");
    let identity = cancelled.result.provider();
    assert_eq!(identity.provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(identity.registration_revision(), 31);
    assert_eq!(identity.provider_instance_id(), None);
    assert_eq!(cancelled.fallback, FallbackDecision::NotApplicable);

    let mut unavailable = RecallFixturePort::new();
    unavailable.terminal_code = TerminalCode::ProviderUnavailable;
    let port = mount(
        compose_mode(Arc::new(unavailable), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let degraded = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("unavailable recall");
    let identity = degraded.result.provider();
    assert_eq!(identity.provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(
        identity.provider_instance_id(),
        Some("native.recall-fixture")
    );
    assert_eq!(
        degraded.result.degradation(),
        Some(CognitiveRecallDegradation::Unavailable)
    );
}

/// A complete zero-result search and a provider that is unavailable are
/// different typed outcomes with different evidence, and neither raises
/// fallback.
#[tokio::test]
async fn zero_results_and_unavailable_are_distinct_typed_outcomes() {
    let mut zero = RecallFixturePort::new();
    zero.terminal_code = TerminalCode::SuccessZeroResults;
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(Arc::new(zero), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let zero = port
        .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
        .await
        .expect("zero-result recall");
    assert!(zero.result.is_complete(), "{:?}", zero.result);
    assert!(zero.result.candidates().is_empty());
    let report = zero
        .report
        .expect("zero results still produce an admission report");
    assert_eq!(report.received_count, 0);
    assert_eq!(report.admitted_count, 0);
    assert_eq!(zero.fallback, FallbackDecision::NotApplicable);
    assert_eq!(observer.0.lock().unwrap().len(), 1);

    let mut down = RecallFixturePort::new();
    down.terminal_code = TerminalCode::ProviderUnavailable;
    let observer = Arc::new(LedgerObserver::default());
    let port = mount(
        compose_mode(Arc::new(down), EnabledProviderMode::Active),
        observer.clone(),
    )
    .expect("mounted port");
    let unavailable = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("unavailable recall");
    assert!(!unavailable.result.is_complete());
    assert_eq!(
        unavailable.result.degradation(),
        Some(CognitiveRecallDegradation::Unavailable)
    );
    assert!(unavailable.result.candidates().is_empty());
    assert!(unavailable.report.is_none());
    // The provider's own directive forbade fallback; the host rule was never
    // consulted and nothing else was contacted.
    assert_eq!(
        unavailable.fallback,
        FallbackDecision::Declined(FallbackDeclinedReason::DirectiveForbidden)
    );
    assert!(observer.0.lock().unwrap().is_empty());
}

/// A routing policy that names a provider other than the registered one, or
/// the registered provider under a stale revision, is refused before any
/// handshake or recall reaches the provider. Native facts are not consulted
/// in place of the missing provider.
#[tokio::test]
async fn misconfigured_routing_is_refused_before_any_provider_contact() {
    let provider = Arc::new(RecallFixturePort::new());
    let composition = compose_mode(provider.clone(), EnabledProviderMode::Active);
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    let foreign = mount_routed(
        Arc::clone(&composition),
        Arc::new(LedgerObserver::default()),
        budgets(),
        routing("provider.ncm-local", 31, FallbackRule::Forbidden),
    )
    .expect("mounted port");
    let error = foreign
        .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
        .await
        .expect_err("an unregistered configured provider has no route");
    match error {
        CognitiveRecallPortError::Routing(RoutingError::ProviderNotRegistered { provider_id }) => {
            assert_eq!(provider_id.as_str(), "provider.ncm-local");
        }
        other => panic!("expected a routing refusal, got {other:?}"),
    }

    let stale = mount_routed(
        Arc::clone(&composition),
        Arc::new(LedgerObserver::default()),
        budgets(),
        routing(NATIVE_PROVIDER_ID, 30, FallbackRule::Forbidden),
    )
    .expect("mounted port");
    let error = stale
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect_err("a stale pinned revision has no route");
    match error {
        CognitiveRecallPortError::Routing(RoutingError::RegistrationRevisionMismatch {
            configured,
            registered,
            ..
        }) => {
            assert_eq!((configured, registered), (30, 31));
        }
        other => panic!("expected a revision refusal, got {other:?}"),
    }

    assert_eq!(provider.handshake_calls.load(Ordering::Relaxed), 0);
    assert_eq!(provider.recall_calls.load(Ordering::Relaxed), 0);
    assert_eq!(native_readiness(&composition), ProviderReadiness::NotReady);
}

/// A host-pinned fallback rule is never a substitute for the provider's own
/// directive: the Native provider's failure terminal forbids fallback, so the
/// pinned target is neither handshaken nor called, and the reply stays
/// attributed to the configured provider.
#[tokio::test]
async fn pinned_fallback_rule_alone_never_dispatches_a_second_provider() {
    let mut down = RecallFixturePort::new();
    down.terminal_code = TerminalCode::ProviderUnavailable;
    let down = Arc::new(down);
    let pinned = PinnedFallbackPolicy::new(
        "policy.memory-failover",
        7,
        OwnedProviderId::new("provider.ncm-local").expect("target id"),
    )
    .expect("pinned policy");
    let port = mount_routed(
        compose_mode(down.clone(), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
        budgets(),
        routing(NATIVE_PROVIDER_ID, 31, FallbackRule::ExplicitPinned(pinned)),
    )
    .expect("mounted port");
    let outcome = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect("unavailable recall");
    assert_eq!(
        outcome.result.degradation(),
        Some(CognitiveRecallDegradation::Unavailable)
    );
    assert_eq!(outcome.result.provider().provider_id(), NATIVE_PROVIDER_ID);
    assert_eq!(
        outcome.fallback,
        FallbackDecision::Declined(FallbackDeclinedReason::DirectiveForbidden)
    );
    assert_eq!(down.handshake_calls.load(Ordering::Relaxed), 1);
    assert_eq!(down.recall_calls.load(Ordering::Relaxed), 1);
}

/// A fallback rule that names the active provider itself is rejected when the
/// policy is built, so no route can loop back to its own source.
#[test]
fn routing_policy_refuses_self_targeting_fallback() {
    let pinned = PinnedFallbackPolicy::new(
        "policy.memory-failover",
        7,
        OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("target id"),
    )
    .expect("pinned policy");
    assert!(
        ActiveRoutingPolicy::new(
            OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("provider id"),
            31,
            FallbackRule::ExplicitPinned(pinned),
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// tdmem-0903: composed provider set (active + observers) and the
// product-output differential over the real recall port.
// ---------------------------------------------------------------------------

/// Composes the bounded provider set the composition root can now mount: the
/// Native provider in `mode`, plus one injected evaluation observer.
fn compose_with_observer(
    port: Arc<dyn NativeMemoryApplicationPort>,
    mode: EnabledProviderMode,
    observer: Arc<EvaluationObserverProvider>,
) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose_with_observers(
            NativeProviderActivation::Enabled {
                fabric_config: FabricConfig {
                    max_registered_providers: 2,
                    max_in_flight: 2,
                },
                port,
                registration_revision: 31,
                mode,
            },
            vec![ObserverProviderRegistration {
                provider: observer,
                registration_revision: 7,
            }],
        )
        .expect("composed provider set"),
    )
}

/// SHA-256 over the canonical serialization of the **final product-visible
/// recall output** — the `CognitiveRecallResult` the application consumes,
/// including its scope, request id, attributed provider identity, every
/// admitted candidate's id, content, provenance and explanation, and the
/// typed degradation.
///
/// This is the product-output digest tdmem-0903's first acceptance criterion
/// is about. It is deliberately *not* a hash of `ProviderReply`, which is the
/// upstream provider envelope one layer below and would not detect an
/// observer-dependent transformation applied during admission, normalization,
/// selection, or bridging.
fn product_output_sha256(result: &tracedecay_contracts::memory::CognitiveRecallResult) -> String {
    let canonical = serde_json::to_vec(result).expect("canonical product output");
    sha256_hex(&canonical)
}

/// Runs one recall through the real port and returns the product-visible
/// result together with its SHA-256.
async fn product_output(
    composition: Arc<ProjectMemoryProviderComposition>,
    scope: ResolvedScope,
) -> (tracedecay_contracts::memory::CognitiveRecallResult, String) {
    let port = mount(composition, Arc::new(LedgerObserver::default())).expect("mounted port");
    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("bridged recall");
    let digest = product_output_sha256(&outcome.result);
    (outcome.result, digest)
}

/// Hands the observer a real observation through the registry's observation
/// route and returns the fabric's typed answer.
fn deliver_to_observer(
    composition: &ProjectMemoryProviderComposition,
    scope: &ResolvedScope,
) -> Result<
    tracedecay_memory_provider_registry::ObserverReceipt,
    tracedecay_memory_provider_registry::FabricError,
> {
    let registry = composition.registry().expect("enabled composition");
    let exact_scope = TestScopeBinding
        .bind_exact_scope(scope)
        .expect("bound observer scope");
    let handshake = registry
        .handshake(&observer_handshake_request(exact_scope.clone(), 7))
        .expect("observer handshake");
    let ready_receipt = handshake
        .ready_receipt_sha256
        .clone()
        .expect("observer ready receipt");
    registry.deliver_observation(&observer_observation_call(exact_scope, 7, ready_receipt))
}

/// tdmem-0903, acceptance 1 and 2, at the product-output layer: the final
/// recall result a request consumes is byte-identical with the observer
/// absent, present and working, and present and failing.
///
/// The earlier proof for this criterion hashed `ProviderReply` — the upstream
/// provider envelope — inside the fabric crate, which cannot see admission,
/// normalization, selection, or the application bridge, and so could not
/// detect an observer-dependent transformation anywhere downstream of the
/// router. This test hashes the actual `CognitiveRecallResult` produced by
/// the real `ProjectCognitiveRecallPortV1` over the real Native adapter, with
/// SHA-256 over its canonical serialization.
///
/// Both observer runs assert the observer genuinely ran: the working observer
/// records a handshake and an invocation and returns a receipt, and the
/// failing observer records the same contacts while its delivery is refused
/// with a typed `FabricError`. A digest that matched because the observer had
/// quietly done nothing would fail those assertions.
#[tokio::test]
async fn product_output_is_identical_with_the_observer_absent_working_and_failing() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));

    // Baseline: no observer registered anywhere in the composition.
    let baseline_native = Arc::new(RecallFixturePort::new());
    let (baseline_result, baseline_digest) = product_output(
        compose_mode(baseline_native.clone(), EnabledProviderMode::Active),
        scope.clone(),
    )
    .await;
    assert!(!baseline_result.candidates().is_empty());
    assert_eq!(baseline_native.recall_calls.load(Ordering::Relaxed), 1);

    // Observer registered alongside the active provider, and actually fed a
    // real observation before the recall runs.
    let accompanied_native = Arc::new(RecallFixturePort::new());
    let working_observer = Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts));
    let accompanied = compose_with_observer(
        accompanied_native.clone(),
        EnabledProviderMode::Active,
        working_observer.clone(),
    );
    let receipt = deliver_to_observer(&accompanied, &scope).expect("observer receipt");
    assert_eq!(
        receipt.provider_id.as_str(),
        EVALUATION_OBSERVER_PROVIDER_ID
    );
    assert_eq!(working_observer.handshake_count(), 1);
    assert_eq!(working_observer.invocation_count(), 1);
    let (accompanied_result, accompanied_digest) =
        product_output(Arc::clone(&accompanied), scope.clone()).await;

    // Observer registered alongside the active provider, and failing.
    let failing_native = Arc::new(RecallFixturePort::new());
    let failing_observer = Arc::new(EvaluationObserverProvider::new(
        ObserverBehaviour::FailsDelivery,
    ));
    let accompanied_failing = compose_with_observer(
        failing_native.clone(),
        EnabledProviderMode::Active,
        failing_observer.clone(),
    );
    let delivery = deliver_to_observer(&accompanied_failing, &scope);
    assert!(
        matches!(
            delivery,
            Err(
                tracedecay_memory_provider_registry::FabricError::ResponseOperationKindMismatch {
                    expected: ProviderOperation::Observe,
                    returned: ProviderOperation::Recall,
                }
            )
        ),
        "{delivery:?}"
    );
    assert_eq!(failing_observer.handshake_count(), 1);
    assert_eq!(failing_observer.invocation_count(), 1);
    let (failing_result, failing_digest) =
        product_output(Arc::clone(&accompanied_failing), scope).await;

    assert_eq!(baseline_digest, accompanied_digest);
    assert_eq!(baseline_digest, failing_digest);
    assert_eq!(baseline_result, accompanied_result);
    assert_eq!(baseline_result, failing_result);
    assert_eq!(accompanied_native.recall_calls.load(Ordering::Relaxed), 1);
    assert_eq!(failing_native.recall_calls.load(Ordering::Relaxed), 1);
}

/// tdmem-0903, acceptance 3 and 4, at the composition layer: an observer in a
/// composed provider set is refused by the registry's own authority, not only
/// by the fabric's mode gate.
///
/// Two independent refusals are asserted:
///
/// * the routing policy can never name the observer — `route_active` refuses
///   it before any provider contact, so an observer cannot answer a product
///   recall even under an operator misconfiguration;
/// * the registry records **no** recall scope binding for an observer, so
///   recall admission has no authorization to admit anything it returned even
///   if a route somehow reached it.
///
/// The Native provider's own binding is asserted present in the same
/// composition, so "no bindings" is a real distinction and not an artifact of
/// bindings being unrecorded for everyone.
#[tokio::test]
async fn a_composed_observer_can_never_be_routed_or_authorized_for_recall() {
    let native = Arc::new(RecallFixturePort::new());
    let observer = Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts));
    let composition = compose_with_observer(
        native.clone(),
        EnabledProviderMode::Active,
        observer.clone(),
    );
    let registry = composition.registry().expect("enabled composition");

    let statuses = registry.statuses().expect("statuses");
    let modes: Vec<_> = statuses
        .iter()
        .map(|status| (status.provider_id.as_str().to_owned(), status.mode))
        .collect();
    assert_eq!(
        modes,
        vec![
            (
                EVALUATION_OBSERVER_PROVIDER_ID.to_owned(),
                ProviderMode::Observer
            ),
            (NATIVE_PROVIDER_ID.to_owned(), ProviderMode::Active),
        ]
    );

    // Recall authorization: recorded for the selected active provider, absent
    // for the observer.
    assert!(
        registry
            .recall_scope_bindings(&OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("native id"))
            .is_some()
    );
    assert!(
        registry
            .recall_scope_bindings(
                &OwnedProviderId::new(EVALUATION_OBSERVER_PROVIDER_ID).expect("observer id")
            )
            .is_none()
    );

    // Routing: the observer can never answer a product recall.
    let port = mount_routed(
        Arc::clone(&composition),
        Arc::new(LedgerObserver::default()),
        budgets(),
        routing(EVALUATION_OBSERVER_PROVIDER_ID, 7, FallbackRule::Forbidden),
    )
    .expect("mounted port");
    let error = port
        .recall_admitted(
            request(
                resolved_scope(Some("refs/heads/recall-port")),
                60_000_000,
                false,
            ),
            &live_signal(),
        )
        .await
        .expect_err("observer must never be routable");
    assert!(
        matches!(
            error,
            CognitiveRecallPortError::ProviderNotActive {
                ref provider_id,
                mode: ProviderMode::Observer,
            } if provider_id == EVALUATION_OBSERVER_PROVIDER_ID
        ),
        "{error:?}"
    );
    assert_eq!(observer.handshake_count(), 0);
    assert_eq!(observer.invocation_count(), 0);
    assert_eq!(native.recall_calls.load(Ordering::Relaxed), 0);
}

/// tdmem-0903: the composed provider set is validated as a whole before
/// anything is registered.
#[test]
fn a_composed_provider_set_is_bounded_and_identity_disjoint() {
    let native = Arc::new(RecallFixturePort::new());

    // Capacity: the set must fit the finite registry the fabric was given.
    let over_capacity = ProjectMemoryProviderComposition::compose_with_observers(
        NativeProviderActivation::Enabled {
            fabric_config: FabricConfig {
                max_registered_providers: 1,
                max_in_flight: 2,
            },
            port: native.clone(),
            registration_revision: 31,
            mode: EnabledProviderMode::Active,
        },
        vec![ObserverProviderRegistration {
            provider: Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts)),
            registration_revision: 7,
        }],
    );
    assert!(
        matches!(
            over_capacity,
            Err(RegistryError::ProviderSetExceedsRegistryCapacity {
                providers: 2,
                maximum: 1
            })
        ),
        "{:?}",
        over_capacity.map(|_| ())
    );

    // Identity: two observers may not declare the same provider identity.
    let duplicate = ProjectMemoryProviderComposition::compose_with_observers(
        NativeProviderActivation::Enabled {
            fabric_config: FabricConfig {
                max_registered_providers: 4,
                max_in_flight: 2,
            },
            port: native.clone(),
            registration_revision: 31,
            mode: EnabledProviderMode::Active,
        },
        vec![
            ObserverProviderRegistration {
                provider: Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts)),
                registration_revision: 7,
            },
            ObserverProviderRegistration {
                provider: Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts)),
                registration_revision: 8,
            },
        ],
    );
    assert!(
        matches!(
            duplicate,
            Err(RegistryError::DuplicateObserverProvider(ref provider))
                if provider == EVALUATION_OBSERVER_PROVIDER_ID
        ),
        "{:?}",
        duplicate.map(|_| ())
    );

    // Observers exist only inside an enabled composition.
    let orphaned = ProjectMemoryProviderComposition::compose_with_observers(
        NativeProviderActivation::Disabled,
        vec![ObserverProviderRegistration {
            provider: Arc::new(EvaluationObserverProvider::new(ObserverBehaviour::Accepts)),
            registration_revision: 7,
        }],
    );
    assert!(
        matches!(
            orphaned,
            Err(RegistryError::ObserverWithoutEnabledComposition { observers: 1 })
        ),
        "{:?}",
        orphaned.map(|_| ())
    );
}

fn canonical_observation_source(exact: &OwnedExactScope) -> serde_json::Value {
    serde_json::json!({
        "source": {
            "canonical_provider_id": "claude", "canonical_session_id": "session-original",
            "source_key": "source-key", "stable_record_id": null,
            "observation_id": "observation-original", "source_revision": "revision-original",
            "content_sha256": "a".repeat(64),
        },
        "origin_scope": {"state": "recorded", "exact_scope_identity": scope_value(exact), "authority_ref": "host-original"},
        "source_sequence": 7, "occurred_at": null, "ingested_at": "2025-01-01T00:00:00.000000Z",
        "validity": {"valid_from": null, "valid_until": null, "superseded_at": null, "superseded_by": null, "revoked_at": null},
    })
}

fn observation_candidate_fields(
    source: &serde_json::Value,
    delivery_scope: &OwnedExactScope,
) -> serde_json::Value {
    let record = source["source"]["stable_record_id"]
        .as_str()
        .unwrap_or(source["source"]["observation_id"].as_str().unwrap());
    serde_json::json!({
        "memory_class": "session_observation",
        "exact_scope_identity": exact_scope_candidate_value(delivery_scope),
        "provenance": {
            "state": "available",
            "origin_refs": [format!("record:{record}")],
            "source_refs": [format!("record:{record}")],
            "observation_refs": [source["source"]["observation_id"]],
            "transform_chain": [], "provider_trace_refs": [], "redaction_reason": null,
            "original_sources": [source],
        },
    })
}

#[tokio::test]
async fn selected_inline_outcome_preserves_actual_admitted_original_sources() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding
        .bind_exact_scope(&scope)
        .expect("bound scope");
    let source = canonical_observation_source(&exact);
    let mut fixture = RecallFixturePort::new();
    fixture.candidate_contents = Some(duplicate_candidate_stream());
    for id in [
        "aa-duplicate-1",
        "ab-duplicate-2",
        "mm-distinct",
        "zz-other",
    ] {
        fixture
            .candidate_overrides
            .insert(id.to_owned(), observation_candidate_fields(&source, &exact));
    }
    let port = mount(
        compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
        Arc::new(LedgerObserver::default()),
    )
    .expect("mounted port");
    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .expect("recall");
    let ids: Vec<_> = outcome
        .result
        .candidates()
        .iter()
        .map(|candidate| candidate.candidate_id().to_owned())
        .collect();
    assert_eq!(
        outcome.original_sources.keys().cloned().collect::<Vec<_>>(),
        ids
    );
    assert!(!outcome.original_sources.contains_key("ab-duplicate-2"));
    assert_eq!(
        outcome.original_sources.len(),
        3,
        "admission={:?}",
        outcome.report
    );
    for sources in outcome.original_sources.values() {
        assert_eq!(
            serde_json::to_value(sources).expect("typed sources"),
            serde_json::json!([source.clone()])
        );
    }
}

#[tokio::test]
async fn buggy_provider_exclusions_are_denied_before_normalization_and_selection() {
    use tracedecay_contracts::memory::CognitiveRecallExclusions;
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    let source = canonical_observation_source(&exact);
    let full_content = format!(
        "{} excluded full content tail",
        "long source content ".repeat(100)
    );
    for field in [
        "stable_memory_refs",
        "candidate_ids",
        "source_refs",
        "trace_refs",
        "observation_ids",
        "content_sha256",
    ] {
        let mut exclusions = CognitiveRecallExclusions::default();
        match field {
            "stable_memory_refs" => exclusions
                .stable_memory_refs
                .push("memory:aa-denied".to_owned()),
            "candidate_ids" => exclusions.candidate_ids.push("aa-denied".to_owned()),
            // These two classes also inspect original typed attribution, even
            // when the provider omits the corresponding top-level list.
            "source_refs" => exclusions.source_refs.push("source-key".to_owned()),
            "trace_refs" => exclusions.trace_refs.push("trace:excluded".to_owned()),
            "observation_ids" => exclusions
                .observation_ids
                .push("observation-original".to_owned()),
            "content_sha256" => exclusions
                .content_sha256
                .push(sha256_hex(full_content.as_bytes())),
            _ => unreachable!(),
        }
        let mut fixture = RecallFixturePort::new();
        fixture.candidate_contents = Some(vec![
            ("aa-denied".to_owned(), full_content.clone()),
            (
                "zz-survivor".to_owned(),
                "distinct surviving content".to_owned(),
            ),
        ]);
        let mut fields = observation_candidate_fields(&source, &exact);
        fields["provenance"]["provider_trace_refs"] = serde_json::json!(["trace:excluded"]);
        fixture
            .candidate_overrides
            .insert("aa-denied".to_owned(), fields);
        let port = mount(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
        )
        .unwrap()
        .with_selection_policy(RecallSelectionPolicyV1::new(1).unwrap());
        let request = request(scope.clone(), 60_000_000, false)
            .with_exclusions(exclusions)
            .unwrap();
        let outcome = port.recall_admitted(request, &live_signal()).await.unwrap();
        assert_eq!(outcome.result.candidates().len(), 1, "{field}");
        assert_eq!(
            outcome.result.candidates()[0].candidate_id(),
            "zz-survivor",
            "{field}"
        );
        assert_eq!(
            outcome.normalization.as_ref().unwrap().candidates.len(),
            1,
            "{field}"
        );
        let report = outcome.report.unwrap();
        assert_eq!(
            (
                report.received_count,
                report.admitted_count,
                report.denied.len()
            ),
            (2, 1, 1),
            "{field}"
        );
        assert!(
            matches!(&report.denied[0].reason, RecallDenialReason::RequestExcluded { field: actual } if actual == field),
            "{field}: denied={:?}",
            report.denied
        );
        assert_eq!(report.denial_counts(), vec![("request_excluded", 1)]);
        assert!(
            outcome.selection.unwrap().budget_excluded.is_empty(),
            "{field}"
        );
        assert!(outcome.original_sources.is_empty(), "{field}");
    }
}

#[tokio::test]
async fn typed_sources_preserve_unavailable_redacted_and_legacy_fact_provenance() {
    use tracedecay_contracts::memory::CognitiveRecallProvenance;
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    let source = canonical_observation_source(&exact);
    for state in ["unavailable", "redacted", "legacy_fact"] {
        let mut fields = observation_candidate_fields(&source, &exact);
        let expected = match state {
            "unavailable" => {
                fields["provenance"]["state"] = serde_json::json!("unavailable");
                CognitiveRecallProvenance::unavailable()
            }
            "redacted" => {
                fields["provenance"]["state"] = serde_json::json!("redacted");
                fields["provenance"]["redaction_reason"] = serde_json::json!("source redacted");
                CognitiveRecallProvenance::redacted("source redacted").unwrap()
            }
            "legacy_fact" => {
                fields["memory_class"] = serde_json::json!("project");
                fields["exact_scope_identity"] = project_facts_candidate_value(&exact);
                fields["provenance"]["origin_refs"] = serde_json::json!(["record:foreign-fact"]);
                CognitiveRecallProvenance::available("record:foreign-fact").unwrap()
            }
            _ => unreachable!(),
        };
        let mut fixture = RecallFixturePort::new();
        fixture.candidate_contents =
            Some(vec![("claim".to_owned(), "fixture source text".to_owned())]);
        fixture
            .candidate_overrides
            .insert("claim".to_owned(), fields);
        let port = mount(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
        )
        .unwrap();
        let outcome = port
            .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
            .await
            .unwrap();
        assert_eq!(
            outcome.result.candidates().len(),
            1,
            "{state}: admission={:?}",
            outcome.report
        );
        assert_eq!(
            outcome.result.candidates()[0].provenance(),
            &expected,
            "{state}"
        );
        assert!(
            outcome.original_sources.is_empty(),
            "{state} must use its declared provenance authority"
        );
    }
}

#[tokio::test]
async fn contradictory_observation_claims_cannot_borrow_legitimate_typed_sources() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    let mut source = canonical_observation_source(&exact);
    source["source"]["stable_record_id"] = serde_json::json!("stable-original");
    for defect in [
        "foreign_record",
        "observation_instead_of_stable_record",
        "foreign_source",
        "missing_observation",
        "extra_observation",
    ] {
        let mut fields = observation_candidate_fields(&source, &exact);
        match defect {
            "foreign_record" => {
                fields["provenance"]["origin_refs"] = serde_json::json!(["record:foreign-fact"])
            }
            "observation_instead_of_stable_record" => {
                fields["provenance"]["origin_refs"] =
                    serde_json::json!(["record:observation-original"])
            }
            "foreign_source" => {
                fields["source_refs"] = serde_json::json!(["source:foreign.rs#L1-L2"])
            }
            "missing_observation" => {
                fields["provenance"]["observation_refs"] = serde_json::json!([])
            }
            "extra_observation" => {
                fields["provenance"]["observation_refs"] =
                    serde_json::json!(["observation-original", "observation-unrelated"])
            }
            _ => unreachable!(),
        }
        let mut fixture = RecallFixturePort::new();
        fixture.candidate_contents =
            Some(vec![("claim".to_owned(), "fixture source text".to_owned())]);
        fixture
            .candidate_overrides
            .insert("claim".to_owned(), fields);
        let port = mount(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
        )
        .unwrap();
        let outcome = port
            .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
            .await
            .unwrap();
        assert!(outcome.result.candidates().is_empty(), "{defect}");
        assert!(outcome.original_sources.is_empty(), "{defect}");
        let report = outcome.report.unwrap();
        assert_eq!(report.denied.len(), 1, "{defect}");
        assert!(
            matches!(
                report.denied[0].reason,
                RecallDenialReason::InvalidSourceAttribution { .. }
            ),
            "{defect}: denied={:?}",
            report.denied
        );
    }
}

#[tokio::test]
async fn native_and_ncm_declared_observation_formats_bind_to_their_actual_sources() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    for format in ["native", "ncm_observation", "ncm_stable"] {
        let mut source = canonical_observation_source(&exact);
        if format == "ncm_stable" {
            source["source"]["stable_record_id"] = serde_json::json!("stable-original");
        }
        let mut fields = observation_candidate_fields(&source, &exact);
        if format == "native" {
            fields["provenance"]["origin_refs"] = serde_json::json!([
                "native-stage:original",
                "operation:delivery",
                "request:delivery"
            ]);
            fields["provenance"]["source_refs"] = serde_json::json!(["source-key"]);
        }
        let mut fixture = RecallFixturePort::new();
        fixture.candidate_contents =
            Some(vec![("claim".to_owned(), "fixture source text".to_owned())]);
        fixture
            .candidate_overrides
            .insert("claim".to_owned(), fields);
        let port = mount(
            compose_mode(Arc::new(fixture), EnabledProviderMode::Active),
            Arc::new(LedgerObserver::default()),
        )
        .unwrap();
        let outcome = port
            .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
            .await
            .unwrap();
        assert_eq!(
            outcome.result.candidates().len(),
            1,
            "{format}: admission={:?}",
            outcome.report
        );
        assert_eq!(
            serde_json::to_value(&outcome.original_sources["claim"]).unwrap(),
            serde_json::json!([source]),
            "{format}"
        );
    }
}

/// Record dispatch envelopes and encoded capabilities without changing fixture behavior.
struct ProfileRecordingFixture {
    inner: RecallFixturePort,
    required_capabilities: Mutex<Vec<(ProviderOperation, BTreeSet<OwnedVersionedId>)>>,
    payload_capabilities: Mutex<Vec<BTreeSet<OwnedVersionedId>>>,
}

const PROFILE_RECORDING_PROVIDER_ID: &str = "test.profile-recording-provider";

impl NativeMemoryApplicationPort for ProfileRecordingFixture {
    fn descriptor(&self) -> ProviderDescriptor {
        self.inner.descriptor()
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        self.required_capabilities.lock().unwrap().push((
            ProviderOperation::Handshake,
            request.required_capabilities.clone(),
        ));
        self.inner.handshake(request)
    }

    fn recall(&self, call: &ProviderCall) -> ProviderReply {
        self.required_capabilities.lock().unwrap().push((
            ProviderOperation::Recall,
            call.required_capabilities.clone(),
        ));
        let payload: serde_json::Value = serde_json::from_slice(&call.payload.bytes).unwrap();
        let encoded = payload["required_capabilities"].as_array().unwrap();
        let capabilities = encoded
            .iter()
            .map(|value| OwnedVersionedId::new(value.as_str().unwrap()).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            capabilities.len(),
            encoded.len(),
            "capabilities must be unique"
        );
        self.payload_capabilities.lock().unwrap().push(capabilities);
        self.inner.recall(call)
    }

    fn health(&self, call: &ProviderCall) -> ProviderReply {
        self.inner.health(call)
    }
}

impl MemoryProvider for ProfileRecordingFixture {
    fn descriptor(&self) -> ProviderDescriptor {
        NativeMemoryApplicationPort::descriptor(self)
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        NativeMemoryApplicationPort::handshake(self, request)
    }

    fn invoke(&self, call: &ProviderCall) -> ProviderReply {
        match call.operation {
            ProviderOperation::Recall => NativeMemoryApplicationPort::recall(self, call),
            _ => unexpected(),
        }
    }
}

/// Both paths use the same implementation and capability declaration. The
/// generic provider takes the common-profile registration path, while the
/// Native-shaped port retains the strict Native adapter and legacy profile.
fn compose_profile_fixture(
    mut fixture: RecallFixturePort,
    common_profile: bool,
) -> (
    Arc<ProjectMemoryProviderComposition>,
    Arc<ProfileRecordingFixture>,
) {
    use tracedecay_memory_provider_registry::{
        COMMON_ADVISORY_PROFILE_ID, COMMON_ADVISORY_REQUIRED_CAPABILITIES,
        ProviderExecutionShapeV1, ProviderLifecycleOwnershipV1, ProviderRegistrationV1,
        SelectedProviderActivationV1,
    };
    for capability in std::iter::once(COMMON_ADVISORY_PROFILE_ID)
        .chain(COMMON_ADVISORY_REQUIRED_CAPABILITIES.iter().copied())
    {
        fixture
            .descriptor
            .capabilities
            .insert(OwnedVersionedId::new(capability).unwrap());
    }
    if common_profile {
        fixture.descriptor.provider_id =
            OwnedProviderId::new(PROFILE_RECORDING_PROVIDER_ID).unwrap();
        fixture.descriptor.validate().unwrap();
    }
    let fixture = Arc::new(ProfileRecordingFixture {
        inner: fixture,
        required_capabilities: Mutex::new(Vec::new()),
        payload_capabilities: Mutex::new(Vec::new()),
    });
    let composition = if common_profile {
        Arc::new(
            ProjectMemoryProviderComposition::compose_registered(
                SelectedProviderActivationV1::Injected {
                    fabric_config: FabricConfig {
                        max_registered_providers: 1,
                        max_in_flight: 2,
                    },
                    registration: ProviderRegistrationV1 {
                        provider: fixture.clone(),
                        provider_id: OwnedProviderId::new(PROFILE_RECORDING_PROVIDER_ID).unwrap(),
                        registration_revision: 31,
                        mode: EnabledProviderMode::Active,
                        execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                        recall_scope_bindings: authorized_native(),
                        lifecycle: ProviderLifecycleOwnershipV1::CompositionBound,
                    },
                },
                vec![],
            )
            .unwrap(),
        )
    } else {
        compose_mode(fixture.clone(), EnabledProviderMode::Active)
    };
    assert_eq!(
        composition
            .registry()
            .unwrap()
            .selected_registration()
            .unwrap()
            .requires_common_advisory_profile,
        common_profile
    );
    (composition, fixture)
}

#[tokio::test]
async fn common_profile_admits_any_session_of_the_checkout_and_denies_everything_else() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    // Recorded by another agent session of the same checkout: NCM answers
    // one session from what another observed, so this source is admitted.
    let mut earlier_session = exact.clone();
    earlier_session.agent_session_id = "agent-session-earlier".to_owned();
    let source = canonical_observation_source(&earlier_session);
    for defect in [
        "project_fact",
        "profile_fact",
        "exact_scope_fact",
        "missing_sources",
        "foreign_branch_origin",
        "ingestion_only_origin",
    ] {
        let mut denied = observation_candidate_fields(&source, &exact);
        match defect {
            "project_fact" => {
                denied["memory_class"] = serde_json::json!("project");
                denied["exact_scope_identity"] = project_facts_candidate_value(&exact);
            }
            "profile_fact" => {
                denied["memory_class"] = serde_json::json!("profile");
                denied["exact_scope_identity"] = serde_json::json!({
                    "scope_binding": "profile_facts", "profile_id": exact.profile_id,
                    "project_id": "", "repository_identity": "", "worktree_identity": "",
                    "branch_identity": "", "agent_session_id": "", "resolved_scope_digest": "",
                });
            }
            "exact_scope_fact" => denied["memory_class"] = serde_json::json!("project"),
            "missing_sources" => {
                denied["provenance"]
                    .as_object_mut()
                    .unwrap()
                    .remove("original_sources");
            }
            "foreign_branch_origin" => {
                denied["provenance"]["original_sources"][0]["origin_scope"]
                    ["exact_scope_identity"]["branch_identity"] =
                    serde_json::json!("refs/heads/another-checkout");
            }
            "ingestion_only_origin" => {
                denied["provenance"]["original_sources"][0]["origin_scope"] =
                    serde_json::json!({"state": "ingestion_only"});
            }
            _ => unreachable!(),
        }
        let mut fixture = RecallFixturePort::new();
        fixture.candidate_contents = Some(vec![
            (
                "aa-denied".to_owned(),
                "higher-ranked denied candidate".to_owned(),
            ),
            (
                "zz-granted".to_owned(),
                "distinct granted observation".to_owned(),
            ),
        ]);
        fixture
            .candidate_overrides
            .insert("aa-denied".to_owned(), denied);
        fixture.candidate_overrides.insert(
            "zz-granted".to_owned(),
            observation_candidate_fields(&source, &exact),
        );
        let port = mount_routed(
            compose_profile_fixture(fixture, true).0,
            Arc::new(LedgerObserver::default()),
            budgets(),
            routing(PROFILE_RECORDING_PROVIDER_ID, 31, FallbackRule::Forbidden),
        )
        .unwrap()
        .with_selection_policy(RecallSelectionPolicyV1::new(1).unwrap());
        let outcome = port
            .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
            .await
            .unwrap();
        assert_eq!(
            outcome.result.candidates().len(),
            1,
            "{defect}: {:?}",
            outcome.report
        );
        assert_eq!(
            outcome.result.candidates()[0].candidate_id(),
            "zz-granted",
            "{defect}"
        );
        assert_eq!(
            outcome.normalization.as_ref().unwrap().candidates.len(),
            1,
            "{defect}"
        );
        assert!(
            outcome
                .selection
                .as_ref()
                .unwrap()
                .budget_excluded
                .is_empty(),
            "{defect}"
        );
        let report = outcome.report.unwrap();
        assert_eq!(
            (
                report.received_count,
                report.admitted_count,
                report.denied.len()
            ),
            (2, 1, 1),
            "{defect}"
        );
        assert!(
            !report
                .authorized_scope_bindings
                .authorizes(ScopeBinding::ProjectFacts)
        );
        assert!(
            !report
                .authorized_scope_bindings
                .authorizes(ScopeBinding::ProfileFacts)
        );
        assert_eq!(report.denied[0].candidate_id, "aa-denied", "{defect}");
        if matches!(defect, "project_fact" | "profile_fact") {
            assert!(
                matches!(
                    report.denied[0].reason,
                    RecallDenialReason::ScopeBindingUnauthorized { .. }
                ),
                "{defect}: {:?}",
                report.denied
            );
        } else {
            assert!(
                matches!(
                    report.denied[0].reason,
                    RecallDenialReason::InvalidSourceAttribution { .. }
                ),
                "{defect}: {:?}",
                report.denied
            );
        }
        assert_eq!(
            serde_json::to_value(&outcome.original_sources["zz-granted"]).unwrap(),
            serde_json::json!([source.clone()])
        );
    }
}

#[tokio::test]
async fn registration_profile_controls_capability_projection_and_source_admission() {
    let scope = resolved_scope(Some("refs/heads/recall-port"));
    let exact = TestScopeBinding.bind_exact_scope(&scope).unwrap();
    let source = canonical_observation_source(&exact);
    // The common registration admits an observation recorded in the
    // dispatched checkout without any host-dispatched history.
    let mut common = RecallFixturePort::new();
    common.candidate_contents = Some(vec![(
        "observation".to_owned(),
        "checkout observation".to_owned(),
    )]);
    common.candidate_overrides.insert(
        "observation".to_owned(),
        observation_candidate_fields(&source, &exact),
    );
    let (common_composition, common_recording) = compose_profile_fixture(common, true);
    let port = mount_routed(
        common_composition,
        Arc::new(LedgerObserver::default()),
        budgets(),
        routing(PROFILE_RECORDING_PROVIDER_ID, 31, FallbackRule::Forbidden),
    )
    .unwrap();
    let outcome = port
        .recall_admitted(request(scope.clone(), 60_000_000, false), &live_signal())
        .await
        .unwrap();
    assert_eq!(outcome.result.candidates().len(), 1, "{:?}", outcome.report);
    assert!(outcome.report.as_ref().unwrap().denied.is_empty());
    assert_eq!(
        serde_json::to_value(&outcome.original_sources["observation"]).unwrap(),
        serde_json::json!([source.clone()])
    );
    // The legacy registration keeps fact extension bindings even with the
    // same declared capabilities.
    let mut legacy = RecallFixturePort::new();
    legacy.candidate_contents = Some(vec![(
        "legacy-fact".to_owned(),
        "retained canonical fact extension".to_owned(),
    )]);
    let (legacy_composition, legacy_recording) = compose_profile_fixture(legacy, false);
    let common_descriptor = MemoryProvider::descriptor(common_recording.as_ref());
    let legacy_descriptor = MemoryProvider::descriptor(legacy_recording.as_ref());
    assert_eq!(
        common_descriptor.provider_id.as_str(),
        PROFILE_RECORDING_PROVIDER_ID
    );
    assert_eq!(legacy_descriptor.provider_id.as_str(), NATIVE_PROVIDER_ID);
    assert_eq!(
        common_descriptor.capabilities,
        legacy_descriptor.capabilities
    );
    assert_eq!(
        common_descriptor.implementation_identity_sha256,
        legacy_descriptor.implementation_identity_sha256
    );
    assert_eq!(
        common_descriptor.state_schema_version,
        legacy_descriptor.state_schema_version
    );
    assert_eq!(
        common_descriptor.state_generation,
        legacy_descriptor.state_generation
    );
    assert_eq!(common_descriptor.limits, legacy_descriptor.limits);
    let port = mount(legacy_composition, Arc::new(LedgerObserver::default())).unwrap();
    let outcome = port
        .recall_admitted(request(scope, 60_000_000, false), &live_signal())
        .await
        .unwrap();
    assert_eq!(outcome.result.candidates().len(), 1, "{:?}", outcome.report);
    assert_eq!(outcome.result.candidates()[0].candidate_id(), "legacy-fact");
    let report = outcome.report.unwrap();
    assert!(
        report
            .authorized_scope_bindings
            .authorizes(ScopeBinding::ProjectFacts)
    );
    assert!(
        report
            .authorized_scope_bindings
            .authorizes(ScopeBinding::ProfileFacts)
    );
    assert!(outcome.original_sources.is_empty());
    let recall_capability =
        OwnedVersionedId::new(tracedecay_memory_provider_registry::RECALL_QUERY_CAPABILITY_ID)
            .unwrap();
    let common_capabilities = BTreeSet::from([
        recall_capability.clone(),
        OwnedVersionedId::new(tracedecay_memory_provider_registry::COMMON_ADVISORY_PROFILE_ID)
            .unwrap(),
    ]);
    assert_eq!(
        *common_recording.required_capabilities.lock().unwrap(),
        vec![
            (ProviderOperation::Handshake, common_capabilities.clone()),
            (ProviderOperation::Recall, common_capabilities.clone()),
        ],
        "the pinned common profile must reach both dispatch envelopes"
    );
    assert_eq!(
        *common_recording.payload_capabilities.lock().unwrap(),
        vec![common_capabilities],
        "the canonical payload must bind the same common capabilities as call and handshake"
    );
    let legacy_capabilities = BTreeSet::from([recall_capability]);
    assert_eq!(
        *legacy_recording.required_capabilities.lock().unwrap(),
        vec![
            (ProviderOperation::Handshake, legacy_capabilities.clone()),
            (ProviderOperation::Recall, legacy_capabilities.clone()),
        ],
        "an otherwise equivalent legacy registration remains recall-only"
    );
    assert_eq!(
        *legacy_recording.payload_capabilities.lock().unwrap(),
        vec![legacy_capabilities],
        "the legacy canonical payload must remain identical to call and handshake capabilities"
    );
}
