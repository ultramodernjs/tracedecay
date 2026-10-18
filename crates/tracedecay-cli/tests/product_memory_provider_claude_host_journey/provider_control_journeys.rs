//! Real provider-control journeys over the Claude/Codex host fixture.
//!
//! The provider namespace is selected by a canonical session the journey's
//! hooks actually committed. Read requests use the shipped
//! `tracedecay tool` surface; the maintenance mutation stays on the
//! authenticated daemon RPC so the test holds its request identity. Every
//! refusal is asserted from the typed application outcome.

use super::*;
use std::path::PathBuf;

use tracedecay_contracts::result::ApplicationProblem;
use tracedecay_contracts::retained_surfaces::{
    ProviderControlEffectStateV1, ProviderControlHealthCheckV1, ProviderControlInspectionItemsV1,
    ProviderControlInspectionSelectorV1, ProviderControlMaintenanceTaskV1,
    ProviderControlOperationResultV1, ProviderControlRequestV1, ProviderControlResultV1,
    ProviderControlStateSelectorV1, ProviderControlTerminalV1, ProviderHealthRequestV1,
    ProviderInspectionRequestV1, ProviderMaintenanceRequestV1, RetainedSurfaceRequestV1,
    RetainedSurfaceResultV1, retained_surface_operation_is_effect,
};
use tracedecay_contracts::{
    ApplicationOutcome, CancellationSignal, Deadline, RequestId, now_micros,
};
use tracedecay_daemon_protocol::{
    DaemonClientIdentity, DaemonConnection, DaemonHandshake, DaemonInvocationClient,
    DaemonInvocationError, DaemonInvocationExecutor, DaemonInvocationOutcome,
    DaemonInvocationRequest, DaemonInvocationResponse, InvocationCancellationPolicy,
    MovedStoreAdoption,
};
use tracedecay_domain::UtcMicros;

const CONTROL_DEADLINE: Duration = Duration::from_secs(60);

/// Runs after the host journey. Provider controls address only providers with
/// a mounted observation journey; Native owns none and is refused typed. The
/// provider namespace is the canonical session's, under the registration the
/// routing policy pinned (every production registration is revision 1).
pub(super) fn assert_provider_control_journeys(journey: &mut ClaudeHostJourney, session_id: &str) {
    let state = ProviderControlStateSelectorV1::CanonicalSession {
        provider_id: journey.active_provider.id().to_owned(),
        registration_revision: 1,
        canonical_provider_id: if journey.codex { "codex" } else { "claude" }.to_owned(),
        session_id: session_id.to_owned(),
    };
    if !journey.active_provider.is_ncm() {
        assert_unmounted_provider_controls_are_refused(journey, &state);
        return;
    }

    assert_health(journey, &state, "health.before-controls");
    assert_state_summary(journey, &state);
    let generation_before_maintenance = assert_health(journey, &state, "health.before-maintenance");
    assert_maintenance(journey, &state, generation_before_maintenance);

    // Maintenance is a durable provider operation. A fresh daemon and a real
    // SessionStart must leave the provider answering the recall lane.
    let after_maintenance = restart_and_recall(journey, session_id);
    assert_answered_lane(&after_maintenance, journey.active_provider.id());

    assert_wrong_selectors_are_refused(journey, &state);
    assert_ncm_unavailable_fallback_and_recovery(journey, session_id);
}

fn invoke(
    journey: &ClaudeHostJourney,
    request_id: &str,
    request: ProviderControlRequestV1,
) -> Result<DaemonInvocationResponse, DaemonInvocationError> {
    let authority: DaemonAuthorityRecord = serde_json::from_slice(
        &fs::read(super::daemon_authority_path(&journey.profile))
            .expect("current daemon authority"),
    )
    .expect("canonical daemon authority JSON");
    let observed_at = now_micros();
    let deadline =
        Deadline::new(UtcMicros(observed_at.0.saturating_add(
            CONTROL_DEADLINE.as_micros().try_into().unwrap_or(i64::MAX),
        )))
        .expect("provider control deadline");
    let request_id = RequestId::new(request_id.to_owned()).expect("provider control request id");
    let cancellation = CancellationSignal::active(format!("{}.cancel", request_id.as_str()))
        .expect("provider control cancellation");
    let policy = if retained_surface_operation_is_effect(request.operation()) {
        InvocationCancellationPolicy::AuthoritativeEffect
    } else {
        InvocationCancellationPolicy::ReadOnly
    };
    let invocation = DaemonInvocationRequest::retained_application(
        request_id.as_str(),
        RetainedSurfaceRequestV1::ProviderControl(request),
        observed_at,
        deadline.clone(),
        cancellation.context(),
    );
    let connection =
        DaemonConnection::new(authority.endpoint.clone(), authority.auth_token.clone())
            .with_daemon_version(authority.version.clone());
    let handshake = DaemonHandshake {
        project_path: Some(journey.project.clone()),
        scope_prefix: None,
        timings: false,
        allow_init: false,
        allow_initialize_root_routing: false,
        client_identity: DaemonClientIdentity::new(
            authority.profile_root.clone(),
            journey.profile.join("global.db"),
        ),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        client_instance_id: format!("host-provider-control-rpc-{}", std::process::id()),
        tool_list_changed_capable: false,
        catalog_version: String::new(),
        moved_store_adoption: MovedStoreAdoption::Never,
    };
    let client = DaemonInvocationClient::new(connection, handshake);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create provider control RPC runtime")
        .block_on(DaemonInvocationExecutor::invoke_controlled(
            &client,
            invocation,
            deadline,
            cancellation,
            policy,
        ))
}

fn typed_result(response: &DaemonInvocationResponse) -> ProviderControlResultV1 {
    let payload = match &response.outcome {
        DaemonInvocationOutcome::RetainedApplication { outcome, .. } => match outcome {
            ApplicationOutcome::Evidence(packet) => packet.payload.as_ref(),
            ApplicationOutcome::Effect(effect) => effect.payload.as_ref(),
            ApplicationOutcome::Preview(_) | ApplicationOutcome::Result(_) => None,
        },
        DaemonInvocationOutcome::RetainedApplicationProblem { problem, .. } => {
            panic!(
                "provider control unexpectedly returned an outer application problem: {problem:?}"
            )
        }
        other => panic!("provider control returned the wrong daemon outcome: {other:?}"),
    };
    match payload {
        Some(RetainedSurfaceResultV1::ProviderControl(result)) => result.clone(),
        other => panic!("provider control omitted its typed result payload: {other:?}"),
    }
}

/// Decode the typed provider-control result printed by the real CLI surface.
/// The dynamic tool command emits the application envelope verbatim; the
/// provider result is the evidence packet's payload. Keeping this helper next
/// to the RPC decoder makes it explicit which checks exercise the public CLI
/// route and which checks require a caller-controlled request identity.
fn typed_tool_result(
    journey: &ClaudeHostJourney,
    tool_name: &str,
    arguments: Value,
) -> ProviderControlResultV1 {
    let envelope = journey.tool_result(tool_name, &arguments);
    assert_eq!(
        envelope["outcome"], "evidence",
        "{tool_name} must return an evidence envelope: {envelope}"
    );
    let payload = envelope
        .pointer("/outcome/value/payload")
        .cloned()
        .filter(|payload| !payload.is_null())
        .unwrap_or_else(|| panic!("{tool_name} omitted its typed payload: {envelope}"));
    serde_json::from_value(payload).unwrap_or_else(|error| {
        panic!("{tool_name} returned an undecodable provider result: {error}")
    })
}

fn assert_outer_problem(response: &DaemonInvocationResponse) {
    match &response.outcome {
        DaemonInvocationOutcome::RetainedApplicationProblem { problem, .. } => assert!(
            matches!(problem, ApplicationProblem::NotFoundOrNotAuthorized { .. }),
            "a selector outside this project's session store must be hidden as a missing grant: {problem:?}"
        ),
        other => panic!("expected a typed missing-grant refusal, got {other:?}"),
    }
}

fn assert_success(result: &ProviderControlResultV1, operation: &str) {
    assert!(
        matches!(result.terminal, ProviderControlTerminalV1::Success),
        "{operation} must settle successfully: {result:?}"
    );
    assert_ne!(
        result.effect.state,
        ProviderControlEffectStateV1::Unknown,
        "{operation} cannot claim unknown effect after successful settlement"
    );
}

fn assert_health(
    journey: &ClaudeHostJourney,
    state: &ProviderControlStateSelectorV1,
    label: &str,
) -> u64 {
    let result = typed_tool_result(
        journey,
        "tracedecay_provider_health",
        serde_json::to_value(ProviderHealthRequestV1 {
            state: state.clone(),
            requested_checks: vec![
                ProviderControlHealthCheckV1::Protocol,
                ProviderControlHealthCheckV1::State,
                ProviderControlHealthCheckV1::Scope,
                ProviderControlHealthCheckV1::Capacity,
                ProviderControlHealthCheckV1::Persistence,
                ProviderControlHealthCheckV1::Recovery,
                ProviderControlHealthCheckV1::Privacy,
            ],
        })
        .expect("provider Health request JSON"),
    );
    assert_success(&result, label);
    let ProviderControlOperationResultV1::Health(Some(health)) = &result.result else {
        panic!("{label} must include typed health evidence: {result:?}");
    };
    assert_eq!(
        health.readiness,
        tracedecay_contracts::retained_surfaces::ProviderControlReadinessV1::Ready,
        "{label} must report a ready provider: {health:?}"
    );
    health.state_generation
}

fn assert_state_summary(journey: &ClaudeHostJourney, state: &ProviderControlStateSelectorV1) {
    let result = typed_tool_result(
        journey,
        "tracedecay_provider_inspection",
        serde_json::to_value(ProviderInspectionRequestV1 {
            state: state.clone(),
            selection: ProviderControlInspectionSelectorV1::StateSummary,
            maximum_items: 16,
            maximum_bytes: 65_536,
            cursor: None,
        })
        .expect("provider inspection request JSON"),
    );
    assert_success(&result, "inspection.state-summary");
    let ProviderControlOperationResultV1::Inspection(Some(inspection)) = &result.result else {
        panic!("state summary must include typed inspection evidence: {result:?}");
    };
    assert!(
        matches!(
            inspection.items,
            ProviderControlInspectionItemsV1::StateSummary(_)
        ),
        "state summary must answer its own view: {inspection:?}"
    );
    assert_eq!(result.effect.state, ProviderControlEffectStateV1::None);
}

fn assert_maintenance(
    journey: &ClaudeHostJourney,
    state: &ProviderControlStateSelectorV1,
    generation_before: u64,
) {
    // Native's staged provider recalculates feedback bias; NCM's real worker
    // consolidates the admitted STM records. Both are mutations with a
    // provider-reported kernel change, but their task names are intentionally
    // provider-specific capabilities.
    let task = if journey.active_provider.is_ncm() {
        ProviderControlMaintenanceTaskV1::Consolidate
    } else {
        ProviderControlMaintenanceTaskV1::Decay
    };
    let response = invoke(
        journey,
        "host-provider-control.maintenance",
        ProviderControlRequestV1::Maintenance(ProviderMaintenanceRequestV1 {
            state: state.clone(),
            task,
            maximum_items: 100,
            maximum_bytes: 65_536,
            maximum_duration_millis: 5_000,
            dry_run: false,
            resume_cursor: None,
        }),
    )
    .expect("provider maintenance RPC transport");
    let result = typed_result(&response);
    assert_success(&result, "maintenance");
    let ProviderControlOperationResultV1::Maintenance(Some(maintenance)) = &result.result else {
        panic!("maintenance must include typed maintenance evidence: {result:?}");
    };
    assert_eq!(maintenance.task, task);
    assert!(!maintenance.dry_run);
    assert!(
        !maintenance.partial,
        "maintenance must finish its bounded scan"
    );
    assert!(
        maintenance.scanned_items > 0,
        "maintenance must inspect the admitted provider state: {maintenance:?}"
    );
    if journey.active_provider.is_ncm() {
        assert_eq!(
            maintenance.state_changed,
            Some(true),
            "NCM maintenance must report its kernel recalculation: {maintenance:?}"
        );
    } else {
        assert!(
            maintenance.state_changed.is_none_or(|changed| changed),
            "Native maintenance cannot report a false state change: {maintenance:?}"
        );
    }
    assert!(
        maintenance.changed_items > 0
            || maintenance.removed_items > 0
            || maintenance.proposed_changes.is_some_and(|count| count > 0),
        "maintenance must report an actual recalculation proposal or changed item: {maintenance:?}"
    );
    assert!(
        maintenance.receipt.state_generation_after > maintenance.receipt.state_generation_before,
        "maintenance must advance durable provider state: {:?}",
        maintenance.receipt
    );
    assert_eq!(
        maintenance.receipt.state_generation_before, generation_before,
        "maintenance must start from the generation observed by the preceding Health RPC"
    );
    assert_eq!(
        result.effect.state,
        ProviderControlEffectStateV1::Committed,
        "maintenance must retain a committed provider effect: {result:?}"
    );
    assert_eq!(
        result.effect.state_generation_before,
        Some(maintenance.receipt.state_generation_before)
    );
    assert_eq!(
        result.effect.state_generation_after,
        Some(maintenance.receipt.state_generation_after)
    );
    assert_eq!(
        result.effect.provider_receipt_digest.as_deref(),
        Some(maintenance.receipt.provider_receipt_digest.as_str())
    );
    assert_eq!(
        assert_health(journey, state, "health.after-maintenance"),
        maintenance.receipt.state_generation_after,
        "maintenance receipt must match the provider's post-maintenance health generation"
    );
}

fn assert_wrong_selectors_are_refused(
    journey: &ClaudeHostJourney,
    state: &ProviderControlStateSelectorV1,
) {
    let ProviderControlStateSelectorV1::CanonicalSession {
        provider_id,
        registration_revision,
        ..
    } = state
    else {
        panic!("host journey uses canonical-session state");
    };
    // A well-formed session under the other host identity has no row in this
    // journey's canonical session table. The host must collapse that into its
    // typed not-found/not-authorized result before any provider contact.
    let (other_provider, other_session) = if journey.codex {
        ("claude", CLAUDE_SESSION)
    } else {
        ("codex", CODEX_SESSION)
    };
    let response = invoke(
        journey,
        "host-provider-control.health.cross-scope",
        ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
            state: ProviderControlStateSelectorV1::CanonicalSession {
                provider_id: provider_id.clone(),
                registration_revision: *registration_revision,
                canonical_provider_id: other_provider.to_owned(),
                session_id: other_session.to_owned(),
            },
            requested_checks: vec![ProviderControlHealthCheckV1::Protocol],
        }),
    )
    .expect("cross-scope selector RPC transport");
    assert_outer_problem(&response);

    // The canonical row is real, but the provider registration revision is
    // stale. The host keeps the failure typed and effect-free instead of
    // dispatching against the current provider owner.
    let mut stale_state = state.clone();
    let ProviderControlStateSelectorV1::CanonicalSession {
        registration_revision,
        ..
    } = &mut stale_state
    else {
        panic!("host journey uses canonical-session state");
    };
    let stale_revision = (*registration_revision)
        .checked_add(1)
        .expect("stale registration revision");
    *registration_revision = stale_revision;
    let response = invoke(
        journey,
        "host-provider-control.health.stale-registration",
        ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
            state: stale_state,
            requested_checks: vec![ProviderControlHealthCheckV1::Protocol],
        }),
    )
    .expect("stale registration RPC transport");
    let stale = typed_result(&response);
    assert_eq!(
        stale.terminal,
        ProviderControlTerminalV1::ProviderUnavailable,
        "stale registration must refuse before provider dispatch: {stale:?}"
    );
    assert_eq!(
        stale.effect.state,
        ProviderControlEffectStateV1::None,
        "stale registration must have no provider effect: {stale:?}"
    );
    assert!(matches!(
        stale.result,
        ProviderControlOperationResultV1::Health(None)
    ));
}

fn restart_and_recall(journey: &mut ClaudeHostJourney, session_id: &str) -> Value {
    journey.stop_daemon();
    journey.start_daemon();
    let transcript = journey.transcript_path_for_session(session_id);
    journey.initialize_session_transcript(session_id);
    let started = journey.run_session_start_event(session_id, &transcript);
    assert!(
        started.status.success(),
        "restart SessionStart must succeed: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    journey.await_startup_history();
    journey.tool(
        "tracedecay_context",
        &json!({
            "task": format!("what does the {JOURNEY_TERM} transport probe record?"),
            "format": "json",
        }),
    )
}

fn assert_answered_lane(answer: &Value, provider_id: &str) -> Value {
    let lane = super::advisory_lane(answer).expect("context must carry advisory lane");
    assert_eq!(lane["state"], "answered", "healthy lane: {lane}");
    assert_eq!(lane["provider_id"], provider_id, "healthy lane: {lane}");
    lane
}

fn assert_unmounted_provider_controls_are_refused(
    journey: &ClaudeHostJourney,
    state: &ProviderControlStateSelectorV1,
) {
    let response = invoke(
        journey,
        "host-provider-control.health.unmounted",
        ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
            state: state.clone(),
            requested_checks: vec![ProviderControlHealthCheckV1::Protocol],
        }),
    )
    .expect("unmounted provider RPC transport");
    let refused = typed_result(&response);
    assert_eq!(
        refused.terminal,
        ProviderControlTerminalV1::ProviderUnavailable,
        "a provider without an observation journey has no control mount: {refused:?}"
    );
    assert_eq!(refused.effect.state, ProviderControlEffectStateV1::None);
    assert!(matches!(
        refused.result,
        ProviderControlOperationResultV1::Health(None)
    ));
}

fn assert_ncm_unavailable_fallback_and_recovery(
    journey: &mut ClaudeHostJourney,
    session_id: &str,
) -> Value {
    let worker = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real NCM worker binary is required"),
    )
    .canonicalize()
    .expect("canonical NCM worker binary");
    let daemon_pid = journey.daemon.as_ref().expect("running NCM daemon").id();
    let listing = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .expect("ps must enumerate the real NCM worker");
    let worker_pid = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line
                .splitn(3, char::is_whitespace)
                .filter(|field| !field.is_empty());
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            let command = fields.next()?.trim();
            (ppid == daemon_pid && command.starts_with(worker.to_string_lossy().as_ref()))
                .then_some(pid)
        })
        .find(|pid| *pid != std::process::id())
        .expect("the daemon must own the real NCM worker child");
    let status = Command::new("kill")
        .args(["-TERM", &worker_pid.to_string()])
        .status()
        .expect("kill must signal only the discovered NCM worker");
    assert!(status.success(), "NCM worker termination must be delivered");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let probe = Command::new("kill")
            .args(["-0", &worker_pid.to_string()])
            .status()
            .expect("kill -0 must probe worker state");
        if !probe.success() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let unavailable = journey.tool(
        "tracedecay_context",
        &json!({
            "task": format!("what does the {JOURNEY_TERM} transport probe record?"),
            "format": "json",
        }),
    );
    let lane =
        super::advisory_lane(&unavailable).expect("NCM worker loss must retain advisory lane");
    assert_eq!(
        lane["state"], "unavailable",
        "typed NCM unavailable lane: {lane}"
    );
    assert_eq!(lane["provider_id"], journey.active_provider.id());
    assert_eq!(lane["registration_revision"], 1);

    let recovered = restart_and_recall(journey, session_id);
    let lane = assert_answered_lane(&recovered, journey.active_provider.id());
    assert_eq!(lane["state"], "answered");
    recovered
}
