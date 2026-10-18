#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Native is upstream TraceDecay memory inside the provider host. These tests
//! prove it is observationally identical to the upstream tools it wraps:
//! fact recall equals `tracedecay_fact_store_{search,probe,related,reason}`
//! (same ids, order, and `score_millionths`), and session recall issues the
//! exact `tracedecay_message_search` kernel query and carries its page
//! verbatim.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tracedecay_contracts::retained_surfaces::{
    FactReadOptionsV1, FactSearchHitV1, FactStoreAddRequestV1, FactStoreProbeRequestV1,
    FactStoreReasonRequestV1, FactStoreRelatedRequestV1, FactStoreSearchRequestV1,
    MemoryScopeV1, MessageSearchRequestV1, RetainedSurfaceResultV1,
};
use tracedecay_contracts::{
    ApplicationOperation, ApplicationOutcome, CancellationContext, CancellationSignal,
    CapabilityGrantId, CapabilityGrantSnapshot, Deadline, DisclosureClass, RequestContext,
    RequestId, ResolvedScope, RetainedMemoryRequestV1, RetainedSessionExecutionPortV1,
    RetainedSessionRequestV1, RetainedSurfaceExecutionContextV1, RetainedSurfaceOperation,
    retained_surface_application_operation,
};
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_domain::{
    ActorId, FactOwnerV1, ManifestDigest, ProjectId, RefId, RepositoryId, UserProfileId,
    UtcMicros, WorktreeId,
};
use tracedecay_memory_provider_registry::{
    CancellationToken, CanonicalPayload, HandshakeRequest, MemoryProviderV1, NATIVE_PROVIDER_ID,
    NativeProvider, OperationControl, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
    ProviderCall, ProviderCallParts, ProviderOperation, TerminalCode,
};
use tracedecay_session_runtime::retained::{
    DirectRetainedSessionPortV1, ProjectRetainedSessionAuthoritiesV1,
};
use tracedecay_session_runtime::session_retrieval::SessionApplicationRetrievalFutureV1;
use tracedecay_sessions::runtime::{SessionMessageRecord, SessionRecord};
use tracedecay_store_runtime::retained_memory::DirectRetainedMemoryPortV1;

use super::*;
use tracedecay_project::project::{TraceDecay, TraceDecayOpenOptions};

const SCOPE_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const CONFIGURATION_DIGEST: &str =
    "sha256:6161616161616161616161616161616161616161616161616161616161616161";
const RECALL_PROFILE: &str = "profile.native-bridge-recall";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn real_project_fixture() -> (tempfile::TempDir, PathBuf, Arc<TraceDecay>, ProjectId) {
    let temporary = tempfile::tempdir().expect("native recall fixture root");
    let project_root = temporary.path().join("project");
    let profile_root = temporary.path().join("profile");
    std::fs::create_dir_all(&project_root).expect("project root");
    std::fs::create_dir_all(&profile_root).expect("profile root");
    // The profile identity authority admits only a private root.
    #[cfg(unix)]
    std::fs::set_permissions(
        &profile_root,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private profile root");
    // Stands in for the composition root, which registers the runtime ports
    // before any project opens; registration is process-global and idempotent.
    tracedecay_project::runtime_ports::register_runtime_ports(
        tracedecay_project::runtime_ports::fixture_daemon_client_ports(),
    )
    .expect("runtime port registration");
    let graph = Arc::new(
        TraceDecay::init_with_options(
            &project_root,
            TraceDecayOpenOptions {
                global_db_path: Some(profile_root.join("global.db")),
                profile_root: Some(profile_root),
            },
        )
        .await
        .expect("initialize TraceDecay recall fixture"),
    );
    let FactOwnerV1::Project { project_id } =
        graph.project_memory_owner().expect("project memory owner")
    else {
        panic!("recall fixture must have a project memory owner");
    };
    // Retained target admission compares the served root with the root it
    // is asked for, so every read in these tests uses the graph's own root.
    let served_root = graph.project_root().to_path_buf();
    (temporary, served_root, graph, project_id)
}

fn recall_resolved_scope(project_id: &str) -> ResolvedScope {
    ResolvedScope::new(
        ProjectId::new(project_id).expect("valid recall project identity"),
        RepositoryId::new("repo.native-bridge-recall").expect("valid recall repository"),
        WorktreeId::new("worktree.native-bridge-recall").expect("valid recall worktree"),
        Some(RefId::new("branch.native-bridge-recall").expect("valid recall branch")),
    )
    .expect("valid recall resolved scope")
}

fn recall_scope_value(project_id: &str) -> Value {
    let scope = recall_resolved_scope(project_id);
    json!({
        "profile_id": RECALL_PROFILE,
        "project_id": project_id,
        "repository_identity": "repo.native-bridge-recall",
        "worktree_identity": "worktree.native-bridge-recall",
        "branch_identity": "branch.native-bridge-recall",
        "agent_session_id": "agent.native-bridge-recall",
        "resolved_scope_digest": scope.scope_digest.as_str(),
    })
}

fn recall_request_value(project_id: &str, objective: &str, query: &str) -> Value {
    json!({
        "provider_id": NATIVE_PROVIDER_ID,
        "registration_revision": 1,
        "ready_receipt_digest": "a".repeat(64),
        "exact_scope_identity": recall_scope_value(project_id),
        "request_identity": "request.native-bridge-recall",
        "objective": objective,
        "query": query,
        "temporal_query": {
            "mode": "current",
            "evaluation_time": "2020-01-01T00:00:00Z",
            "as_of": Value::Null,
            "interval_start": Value::Null,
            "interval_end": Value::Null,
            "include_superseded": false,
            "include_revoked": false,
            "unknown_validity_policy": "exclude",
        },
        "budgets": {
            "maximum_candidates": 8,
            "maximum_candidate_content_bytes": 4_096,
            "maximum_total_content_bytes": 8_192,
            "maximum_source_refs_per_candidate": 8,
            "maximum_trace_refs_per_candidate": 8,
            "maximum_warnings": 8,
            "maximum_extensions_per_candidate": 8,
        },
        "exclusions": {
            "stable_memory_refs": [],
            "candidate_ids": [],
            "source_refs": [],
            "trace_refs": [],
            "observation_ids": [],
            "content_sha256": [],
        },
        "required_capabilities": ["recall.query.v1"],
        "policy_revision": 1,
        "extensions": [],
        "deadline": {
            "deadline_utc_micros": i64::MAX,
            "remaining_millis": 5_000,
        },
        "cancellation": "live",
    })
}

fn valid_recall_call(project_id: &str, request: &Value) -> ProviderCall {
    let bytes = serde_json::to_vec(request).expect("recall request bytes");
    ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("valid provider id"),
        registration_revision: 1,
        ready_receipt_sha256: "a".repeat(64),
        exact_scope: OwnedExactScope::new(
            RECALL_PROFILE,
            project_id,
            "repo.native-bridge-recall",
            "worktree.native-bridge-recall",
            "branch.native-bridge-recall",
            "agent.native-bridge-recall",
            recall_resolved_scope(project_id).scope_digest.as_str(),
        )
        .expect("valid recall exact scope"),
        request_id: "request.native-bridge-recall".to_owned(),
        operation_id: "operation.native-bridge-recall".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
        payload: CanonicalPayload::new(
            OwnedVersionedId::new(RECALL_REQUEST_CONTRACT_ID).expect("valid recall contract"),
            bytes.clone(),
            sha256_hex(&bytes),
        )
        .expect("valid recall payload"),
        required_capabilities: vec![
            OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
        ],
        extensions: Vec::new(),
    })
    .expect("valid recall provider call")
}

fn valid_health_call(project_id: &str) -> ProviderCall {
    let mut call = valid_recall_call(
        project_id,
        &recall_request_value(project_id, "search", "native bridge"),
    );
    let body = json!({
        "requested_checks": ["protocol", "state", "persistence"],
    });
    let bytes = serde_json::to_vec(&body).expect("health request bytes");
    call.operation = ProviderOperation::Health;
    call.required_capabilities =
        BTreeSet::from([OwnedVersionedId::new("provider.health.v1").expect("health capability")]);
    call.payload = CanonicalPayload::new(
        OwnedVersionedId::new(HEALTH_CONTRACT_ID).expect("health contract"),
        bytes.clone(),
        sha256_hex(&bytes),
    )
    .expect("valid health payload");
    call
}

fn ready_request() -> HandshakeRequest {
    HandshakeRequest {
        provider_id: OwnedProviderId::new(NATIVE_PROVIDER_ID).expect("valid provider id"),
        registration_revision: 7,
        exact_scope: OwnedExactScope::new(
            "profile.native-bridge-ready",
            "project.native-bridge-ready",
            "repo.native-bridge-ready",
            "worktree.native-bridge-ready",
            "branch.native-bridge-ready",
            "agent.native-bridge-ready",
            SCOPE_DIGEST,
        )
        .expect("valid exact scope"),
        request_id: "request.native-bridge-ready".to_owned(),
        required_capabilities: BTreeSet::new(),
        host_limits: native_descriptor().expect("descriptor").limits,
        control: OperationControl::new(i64::MAX, 1_000, CancellationToken::new()),
        challenge_nonce: [7; 32],
    }
}

fn session_mount(project_id: &str) -> Arc<NativeSessionRetrievalMountV1> {
    Arc::new(NativeSessionRetrievalMountV1::for_project(
        UserProfileId::new(RECALL_PROFILE).expect("profile id"),
        recall_resolved_scope(project_id),
    ))
}

fn native_port(
    graph: &Arc<TraceDecay>,
    project_root: PathBuf,
    project_id: &str,
) -> Arc<ProjectNativeMemoryApplicationPort> {
    Arc::new(
        ProjectNativeMemoryApplicationPort::new(
            Arc::new(tokio::sync::RwLock::new(Arc::clone(graph))),
            project_root,
            session_mount(project_id),
        )
        .expect("construct project Native application port"),
    )
}

/// Runs one Native recall off the async runtime, exactly as the host
/// invocation boundary runs a synchronous provider call.
async fn native_recall(port: &Arc<ProjectNativeMemoryApplicationPort>, call: ProviderCall) -> Value {
    let port = Arc::clone(port);
    let reply = tokio::task::spawn_blocking(move || port.recall(&call))
        .await
        .expect("native recall worker");
    assert!(
        matches!(
            reply.terminal.terminal_code(),
            TerminalCode::Success | TerminalCode::SuccessZeroResults
        ),
        "{:?}",
        reply.terminal
    );
    let payload = reply.payload.expect("recall payload");
    assert_eq!(payload.contract_id.as_str(), RECALL_RESULT_CONTRACT_ID);
    serde_json::from_slice(&payload.bytes).expect("recall payload JSON")
}

/// The upstream hits Native carried, in Native order.
fn native_fact_hits(outcome: &Value) -> Vec<FactSearchHitV1> {
    outcome["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["memory_class"], json!(FACT_MEMORY_CLASS));
            serde_json::from_value(candidate["provenance"]["fact_search_hit"].clone())
                .expect("carried upstream fact search hit")
        })
        .collect()
}

fn ranking(hits: &[FactSearchHitV1]) -> Vec<(String, u32)> {
    hits.iter()
        .map(|hit| {
            (
                hit.fact.fact_id.as_str().to_owned(),
                hit.scores.score_millionths,
            )
        })
        .collect()
}

fn retained_context(
    project_id: &ProjectId,
    operation: RetainedSurfaceOperation,
    request_id: &str,
) -> (RequestContext, CancellationSignal, ApplicationOperation) {
    let scope = recall_resolved_scope(project_id.as_str());
    let operation =
        retained_surface_application_operation(operation).expect("retained application operation");
    let cancellation_id = format!("cancel.{request_id}");
    let grant = CapabilityGrantSnapshot::new(
        CapabilityGrantId::new(format!("grant.{request_id}")).expect("grant id"),
        1,
        ManifestDigest::new(CONFIGURATION_DIGEST).expect("grant digest"),
        ActorId::new("actor.native-parity").expect("actor id"),
        UtcMicros(1),
        UtcMicros(i64::MAX - 1),
        scope.clone(),
        BTreeSet::from([operation.capability_id().clone()]),
        BTreeSet::from([operation.use_case_id().clone()]),
        DisclosureClass::Evidence,
    )
    .expect("capability grant");
    let context = RequestContext::new(
        ActorId::new("actor.native-parity").expect("actor id"),
        scope,
        grant,
        RequestId::new(request_id).expect("request id"),
        Deadline::new(UtcMicros(i64::MAX - 1)).expect("deadline"),
        CancellationContext::active(cancellation_id.clone()).expect("cancellation context"),
    )
    .expect("request context");
    let signal = CancellationSignal::active(cancellation_id).expect("cancellation signal");
    (context, signal, operation)
}

/// Executes one upstream retained memory tool call, the exact path every
/// `tracedecay_fact_store_*` MCP, CLI and HTTP call takes.
async fn upstream_memory(
    graph: &Arc<TraceDecay>,
    project_root: &std::path::Path,
    project_id: &ProjectId,
    operation: RetainedSurfaceOperation,
    request: RetainedMemoryRequestV1<'_>,
) -> ApplicationOutcome<RetainedSurfaceResultV1> {
    let lock = tokio::sync::RwLock::new(Arc::clone(graph));
    let authority = super::super::live_retained_memory_authority(&lock, project_id, project_root)
        .await
        .expect("retained memory authority");
    let port = DirectRetainedMemoryPortV1::project(
        authority,
        ManifestDigest::new(CONFIGURATION_DIGEST).expect("configuration digest"),
    );
    let (context, signal, application_operation) =
        retained_context(project_id, operation, "request.native-parity.upstream");
    port.execute_request(
        RetainedSurfaceExecutionContextV1 {
            request_context: &context,
            cancellation_signal: &signal,
            operation: &application_operation,
            observed_at: now_micros(),
        },
        request,
    )
    .await
    .expect("upstream retained memory call")
}

fn upstream_hits(outcome: &ApplicationOutcome<RetainedSurfaceResultV1>) -> Vec<FactSearchHitV1> {
    match outcome.payload().expect("upstream payload") {
        RetainedSurfaceResultV1::FactStoreSearch(result) => result.hits.clone(),
        RetainedSurfaceResultV1::FactStoreProbe(result) => result.hits.clone(),
        RetainedSurfaceResultV1::FactStoreRelated(result) => result.hits.clone(),
        RetainedSurfaceResultV1::FactStoreReason(result) => result.hits.clone(),
        other => panic!("unexpected upstream result {other:?}"),
    }
}

fn read_options(scope: MemoryScopeV1) -> FactReadOptionsV1 {
    FactReadOptionsV1 {
        memory_scope: Some(scope),
        category: None,
        min_trust: None,
        limit: Some(8),
        project_selector: None,
    }
}

async fn add_fact(
    graph: &Arc<TraceDecay>,
    project_root: &std::path::Path,
    project_id: &ProjectId,
    scope: MemoryScopeV1,
    content: &str,
    entities: &[&str],
) {
    let request = FactStoreAddRequestV1 {
        content: content.to_owned(),
        memory_scope: Some(scope),
        category: None,
        tags: vec!["native".to_owned()],
        entities: entities.iter().map(|entity| (*entity).to_owned()).collect(),
        trust: Some(0.9),
        source_label: Some("native-parity".to_owned()),
        metadata: None,
        project_selector: None,
    };
    upstream_memory(
        graph,
        project_root,
        project_id,
        RetainedSurfaceOperation::FactStoreAdd,
        RetainedMemoryRequestV1::FactStoreAdd(&request),
    )
    .await;
}

async fn seed_project_facts(
    graph: &Arc<TraceDecay>,
    project_root: &std::path::Path,
    project_id: &ProjectId,
) {
    for (content, entities) in [
        (
            "native bridge recall keeps upstream fact ranking",
            &["TraceDecay", "Bridge"][..],
        ),
        (
            "native bridge never rescales fact scores",
            &["TraceDecay"][..],
        ),
        ("bridge recall reads project facts first", &["Bridge"][..]),
        ("unrelated deployment note", &["Deploy"][..]),
    ] {
        add_fact(
            graph,
            project_root,
            project_id,
            MemoryScopeV1::Project,
            content,
            entities,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Declaration
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_declares_only_health_and_recall() {
    let (_temporary, project_root, graph, project_id) = real_project_fixture().await;
    let port = native_port(&graph, project_root, project_id.as_str());
    let provider = NativeProvider::new(port as Arc<dyn NativeMemoryApplicationPort>)
        .expect("construct Native provider");
    let descriptor = provider.descriptor();
    let capabilities = descriptor
        .capabilities
        .iter()
        .map(|capability| capability.as_str())
        .collect::<Vec<_>>();
    assert_eq!(capabilities, vec!["provider.health.v1", "recall.query.v1"]);
    assert_eq!(descriptor.state_generation, 0);
    assert_eq!(descriptor.state_schema_version, STATE_SCHEMA_VERSION);
    assert_eq!(
        tracedecay_memory_provider_registry::NATIVE_RECALL_SCOPE_BINDINGS,
        &["project_facts", "profile_facts"]
    );
}

#[test]
fn ready_receipt_is_deterministic_and_nonce_bound() {
    let request = ready_request();
    let limits = native_descriptor().expect("descriptor").limits;
    let first = ready_receipt(&request, limits);
    assert_eq!(first, ready_receipt(&request, limits));

    let mut changed = request;
    changed.challenge_nonce[0] ^= 0xff;
    assert_ne!(first, ready_receipt(&changed, limits));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_health_payload_reports_operation_health_data() {
    let (_temporary, project_root, graph, project_id) = real_project_fixture().await;
    let port = native_port(&graph, project_root, project_id.as_str());
    let call = valid_health_call(project_id.as_str());

    let reply = port.health(&call);

    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
    let payload = reply.payload.expect("health result payload");
    assert_eq!(payload.contract_id.as_str(), HEALTH_CONTRACT_ID);
    let body: Value = serde_json::from_slice(&payload.bytes).expect("health result JSON");
    assert_eq!(body["provider_id"], json!(NATIVE_PROVIDER_ID));
    assert_eq!(body["provider_instance_id"], json!(PROVIDER_INSTANCE_ID));
    assert_eq!(body["readiness"], json!("ready"));
    assert_eq!(
        body["capability_states"]
            .as_array()
            .expect("capability states")
            .iter()
            .map(|state| state["capability_id"].clone())
            .collect::<Vec<_>>(),
        vec![json!("provider.health.v1"), json!("recall.query.v1")]
    );
    assert_eq!(
        body["effective_limits_digest"],
        json!(native_limits_digest(
            native_descriptor().expect("descriptor").limits
        ))
    );
}

#[test]
fn native_recall_failures_preserve_typed_terminal_states() {
    let cases = [
        (
            NativeReadFailure::RecallUnsupported,
            TerminalCode::CapabilityUnsupported,
            RECALL_UNSUPPORTED_DIAGNOSTIC,
        ),
        (
            NativeReadFailure::RecallHistoryGrantUnsupported,
            TerminalCode::CapabilityUnsupported,
            RECALL_HISTORY_GRANT_DIAGNOSTIC,
        ),
        (
            NativeReadFailure::RecallNotAuthorized,
            TerminalCode::Unauthorized,
            RECALL_NOT_AUTHORIZED_DIAGNOSTIC,
        ),
        (
            NativeReadFailure::RecallResetRequired,
            TerminalCode::ResetRequired,
            RECALL_RESET_DIAGNOSTIC,
        ),
        (
            NativeReadFailure::RecallCursorStale,
            TerminalCode::StaleIdentity,
            RECALL_CURSOR_STALE_DIAGNOSTIC,
        ),
        (
            NativeReadFailure::RecallCapacityExceeded,
            TerminalCode::CapacityExceeded,
            RECALL_CAPACITY_DIAGNOSTIC,
        ),
    ];
    for (failure, terminal_code, diagnostic_id) in cases {
        assert_eq!(failure.terminal(), (terminal_code, diagnostic_id));
    }
}

// ---------------------------------------------------------------------------
// Lane selection
// ---------------------------------------------------------------------------

fn parsed(request: &Value) -> NativeRecallRequestV1 {
    let project_id = request["exact_scope_identity"]["project_id"]
        .as_str()
        .expect("project id")
        .to_owned();
    parse_native_recall_request(&valid_recall_call(&project_id, request))
        .expect("valid recall request")
}

#[test]
fn objectives_map_onto_upstream_fact_kinds_and_explicit_session_history() {
    let project = "project.native-lanes";
    for (objective, query, expected) in [
        ("search", "bridge", NativeRecallLane::Facts(NativeFactRead::Search)),
        ("probe", "TraceDecay", NativeRecallLane::Facts(NativeFactRead::Probe)),
        (
            "related",
            "TraceDecay",
            NativeRecallLane::Facts(NativeFactRead::Related),
        ),
        (
            "reason",
            "TraceDecay, Bridge",
            NativeRecallLane::Facts(NativeFactRead::Reason {
                entities: vec!["Bridge".to_owned(), "TraceDecay".to_owned()],
            }),
        ),
        (
            SESSION_HISTORY_OBJECTIVE,
            "what did we decide",
            NativeRecallLane::SessionHistory,
        ),
    ] {
        let request = parsed(&recall_request_value(project, objective, query));
        assert_eq!(NativeRecallLane::select(&request), Ok(expected), "{objective}");
    }
    let unknown = parsed(&recall_request_value(project, "summarize", "bridge"));
    assert_eq!(
        NativeRecallLane::select(&unknown),
        Err(NativeReadFailure::RecallUnsupported)
    );
    let duplicate_entities = parsed(&recall_request_value(project, "reason", "Bridge, Bridge"));
    assert_eq!(
        NativeRecallLane::select(&duplicate_entities),
        Err(NativeReadFailure::RecallInvalidRequest)
    );
}

#[test]
fn only_current_state_recall_is_served_and_nothing_falls_back() {
    let project = "project.native-temporal";
    for objective in ["search", SESSION_HISTORY_OBJECTIVE] {
        let mut as_of = recall_request_value(project, objective, "bridge");
        as_of["temporal_query"]["mode"] = json!("as_of");
        as_of["temporal_query"]["as_of"] = json!("2019-01-01T00:00:00Z");
        let mut interval = recall_request_value(project, objective, "bridge");
        interval["temporal_query"]["mode"] = json!("interval");
        interval["temporal_query"]["interval_start"] = json!("2019-01-01T00:00:00Z");
        interval["temporal_query"]["interval_end"] = json!("2019-06-01T00:00:00Z");
        let mut history = recall_request_value(project, objective, "bridge");
        history["temporal_query"]["mode"] = json!("history");
        let mut superseded = recall_request_value(project, objective, "bridge");
        superseded["temporal_query"]["include_superseded"] = json!(true);
        for request in [as_of, interval, history, superseded] {
            assert_eq!(
                NativeRecallLane::select(&parsed(&request)),
                Err(NativeReadFailure::RecallUnsupported),
                "{request}"
            );
        }
    }
    // Facts expose no provider cursor; message search passes its own back.
    let mut fact_cursor = recall_request_value(project, "search", "bridge");
    fact_cursor["temporal_query"]["cursor"] = json!("cursor.opaque");
    assert_eq!(
        NativeRecallLane::select(&parsed(&fact_cursor)),
        Err(NativeReadFailure::RecallUnsupported)
    );
    let mut session_cursor = recall_request_value(project, SESSION_HISTORY_OBJECTIVE, "bridge");
    session_cursor["temporal_query"]["cursor"] = json!("cursor.opaque");
    assert_eq!(
        NativeRecallLane::select(&parsed(&session_cursor)),
        Ok(NativeRecallLane::SessionHistory)
    );
}

#[test]
fn a_canonical_history_grant_is_refused_because_native_observes_nothing() {
    let project = "project.native-history";
    let mut request = recall_request_value(project, "search", "bridge");
    request["history_grant"] = json!({"authorization_ref": "host-history.fixture"});
    assert!(matches!(
        parse_native_recall_request(&valid_recall_call(project, &request)),
        Err(NativeReadFailure::RecallHistoryGrantUnsupported)
    ));
}

// ---------------------------------------------------------------------------
// Fact lane parity with the upstream fact tools
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_fact_recall_equals_upstream_fact_store_reads() {
    let (_temporary, project_root, graph, project_id) = real_project_fixture().await;
    seed_project_facts(&graph, &project_root, &project_id).await;
    let port = native_port(&graph, project_root.clone(), project_id.as_str());

    // Probe, related and reason are pure reads upstream.
    let probe = FactStoreProbeRequestV1 {
        entity: "TraceDecay".to_owned(),
        options: read_options(MemoryScopeV1::Project),
        after: None,
    };
    let related = FactStoreRelatedRequestV1 {
        entity: "TraceDecay".to_owned(),
        options: read_options(MemoryScopeV1::Project),
        after: None,
    };
    let reason = FactStoreReasonRequestV1 {
        entities: vec!["Bridge".to_owned(), "TraceDecay".to_owned()],
        options: read_options(MemoryScopeV1::Project),
        after: None,
    };
    for (objective, query, operation, request) in [
        (
            "probe",
            "TraceDecay",
            RetainedSurfaceOperation::FactStoreProbe,
            RetainedMemoryRequestV1::FactStoreProbe(&probe),
        ),
        (
            "related",
            "TraceDecay",
            RetainedSurfaceOperation::FactStoreRelated,
            RetainedMemoryRequestV1::FactStoreRelated(&related),
        ),
        (
            "reason",
            "TraceDecay, Bridge",
            RetainedSurfaceOperation::FactStoreReason,
            RetainedMemoryRequestV1::FactStoreReason(&reason),
        ),
    ] {
        let native = native_recall(
            &port,
            valid_recall_call(
                project_id.as_str(),
                &recall_request_value(project_id.as_str(), objective, query),
            ),
        )
        .await;
        let upstream =
            upstream_memory(&graph, &project_root, &project_id, operation, request).await;
        assert_eq!(
            ranking(&native_fact_hits(&native)),
            ranking(&upstream_hits(&upstream)),
            "{objective}"
        );
    }

    // Native recall records no retrieval telemetry, so it runs before the
    // explicit upstream search, which does.
    let native = native_recall(
        &port,
        valid_recall_call(
            project_id.as_str(),
            &recall_request_value(project_id.as_str(), "search", "native bridge"),
        ),
    )
    .await;
    let search = FactStoreSearchRequestV1 {
        query: "native bridge".to_owned(),
        options: read_options(MemoryScopeV1::Project),
        after: None,
    };
    let upstream = upstream_memory(
        &graph,
        &project_root,
        &project_id,
        RetainedSurfaceOperation::FactStoreSearch,
        RetainedMemoryRequestV1::FactStoreSearch(&search),
    )
    .await;
    let native_ranking = ranking(&native_fact_hits(&native));
    assert!(!native_ranking.is_empty(), "{native}");
    assert_eq!(native_ranking, ranking(&upstream_hits(&upstream)));
    for candidate in native["candidates"].as_array().expect("candidates") {
        let hit: FactSearchHitV1 =
            serde_json::from_value(candidate["provenance"]["fact_search_hit"].clone())
                .expect("carried hit");
        assert_eq!(
            candidate["native_score"]["components"]["score_millionths"],
            json!(hit.scores.score_millionths),
            "the upstream score is carried, never rescaled"
        );
        assert_eq!(candidate["exact_scope_identity"]["scope_binding"], json!("project_facts"));
        assert_eq!(candidate["stable_memory_ref"], json!(hit.fact.fact_id.as_str()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_fact_recall_reads_project_then_profile_and_dedups_by_fact_then_content() {
    let (_temporary, project_root, graph, project_id) = real_project_fixture().await;
    add_fact(
        &graph,
        &project_root,
        &project_id,
        MemoryScopeV1::Project,
        "shared bridge preference",
        &["Bridge"],
    )
    .await;
    // The same content in the profile owner is the same memory to recall.
    add_fact(
        &graph,
        &project_root,
        &project_id,
        MemoryScopeV1::User,
        "shared bridge preference",
        &["Bridge"],
    )
    .await;
    add_fact(
        &graph,
        &project_root,
        &project_id,
        MemoryScopeV1::User,
        "profile bridge preference only",
        &["Bridge"],
    )
    .await;
    let port = native_port(&graph, project_root.clone(), project_id.as_str());
    let native = native_recall(
        &port,
        valid_recall_call(
            project_id.as_str(),
            &recall_request_value(project_id.as_str(), "search", "bridge preference"),
        ),
    )
    .await;
    let bindings = native["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| {
            (
                candidate["exact_scope_identity"]["scope_binding"]
                    .as_str()
                    .expect("binding")
                    .to_owned(),
                candidate["content"].as_str().expect("content").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        bindings,
        vec![
            (
                "project_facts".to_owned(),
                "shared bridge preference".to_owned()
            ),
            (
                "profile_facts".to_owned(),
                "profile bridge preference only".to_owned()
            ),
        ]
    );
}

// ---------------------------------------------------------------------------
// Session lane parity with upstream message search
// ---------------------------------------------------------------------------

/// A retrieval service that records every kernel query it receives and
/// answers with one fixed kernel outcome.
struct RecordingRetrievalV1 {
    queries: Mutex<Vec<SessionTemporalQuery>>,
    outcome: SessionRetrievalServiceOutcome,
}

impl SessionApplicationRetrievalPortV1 for RecordingRetrievalV1 {
    fn retrieve_admitted<'a>(
        &'a self,
        _context: &'a RequestContext,
        query: SessionTemporalQuery,
    ) -> SessionApplicationRetrievalFutureV1<'a> {
        self.queries.lock().expect("recorded queries").push(query);
        let outcome = self.outcome.clone();
        Box::pin(async move { outcome })
    }
}

fn session_result(session_id: &str, message_id: &str, ordinal: i64, score: f64) -> SessionMessageSearchResult {
    SessionMessageSearchResult {
        session: SessionRecord {
            provider: "claude".to_owned(),
            session_id: session_id.to_owned(),
            project_key: "project-key".to_owned(),
            project_path: "/project".to_owned(),
            title: None,
            started_at: Some(1_700_000_000_000_000),
            ended_at: None,
            transcript_path: None,
            metadata_json: None,
            parent_session_id: None,
            is_subagent: false,
            agent_id: None,
            parent_tool_use_id: None,
        },
        message: SessionMessageRecord {
            provider: "claude".to_owned(),
            message_id: message_id.to_owned(),
            session_id: session_id.to_owned(),
            role: "assistant".to_owned(),
            timestamp: Some(1_700_000_000_000_000 + ordinal),
            ordinal,
            text: format!("message {message_id}"),
            kind: None,
            model: None,
            tool_names: None,
            source_path: None,
            source_offset: None,
            metadata_json: None,
        },
        score,
    }
}

/// A partial kernel page whose order is deliberately not score order: the
/// kernel's order is final and must survive the Native mapping unchanged.
fn partial_page() -> SessionRetrievalServiceOutcome {
    SessionRetrievalServiceOutcome::Partial {
        page: SessionRetrievalPageView {
            results: vec![
                session_result("session.one", "message.b", 2, 0.25),
                session_result("session.two", "message.a", 1, 0.75),
            ],
            temporal: SessionTemporalMetadataView {
                cursor: Some("cursor.next-page".to_owned()),
                ..SessionTemporalMetadataView::default()
            },
        },
        freshness: SessionDataFreshness::Stored { generation_lag: 3 },
        omitted: 2,
    }
}

#[test]
fn session_history_maps_the_kernel_page_verbatim() {
    let project = "project.native-session-page";
    let request = parsed(&recall_request_value(
        project,
        SESSION_HISTORY_OBJECTIVE,
        "what did we decide",
    ));
    let call = valid_recall_call(
        project,
        &recall_request_value(project, SESSION_HISTORY_OBJECTIVE, "what did we decide"),
    );
    let reply = session_history_reply(&call, &request, partial_page()).expect("mapped page");
    assert_eq!(reply.terminal.terminal_code(), TerminalCode::Partial);
    let outcome: Value =
        serde_json::from_slice(&reply.payload.expect("payload").bytes).expect("outcome JSON");
    let candidates = outcome["candidates"].as_array().expect("candidates");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| (
                candidate["provenance"]["message_search_hit"]["message"]["message_id"].clone(),
                candidate["native_score"]["raw_value"].clone(),
                candidate["memory_class"].clone(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (json!("message.b"), json!("0.250000"), json!(SESSION_MESSAGE_MEMORY_CLASS)),
            (json!("message.a"), json!("0.750000"), json!(SESSION_MESSAGE_MEMORY_CLASS)),
        ]
    );
    assert_eq!(outcome["coverage"]["next_cursor"], json!("cursor.next-page"));
    assert_eq!(outcome["coverage"]["truncated_items"], json!(2));
    assert_eq!(outcome["coverage"]["message_search_outcome"], json!("partial"));
    assert_eq!(
        outcome["coverage"]["freshness"],
        json!({"state": "stored", "generation_lag": 3})
    );
    assert_eq!(
        candidates[0]["provenance"]["origin_refs"],
        json!(["session:session.one#2-2"])
    );
}

#[test]
fn session_history_refusals_keep_their_upstream_typed_meaning() {
    let project = "project.native-session-refusals";
    let request = parsed(&recall_request_value(
        project,
        SESSION_HISTORY_OBJECTIVE,
        "what did we decide",
    ));
    let call = valid_recall_call(
        project,
        &recall_request_value(project, SESSION_HISTORY_OBJECTIVE, "what did we decide"),
    );
    for (outcome, failure) in [
        (
            SessionRetrievalServiceOutcome::Denied,
            NativeReadFailure::RecallNotAuthorized,
        ),
        (
            SessionRetrievalServiceOutcome::CursorStale,
            NativeReadFailure::RecallCursorStale,
        ),
        (
            SessionRetrievalServiceOutcome::TimedOut,
            NativeReadFailure::DeadlineExceeded,
        ),
        (
            SessionRetrievalServiceOutcome::Cancelled,
            NativeReadFailure::Cancelled,
        ),
        (
            SessionRetrievalServiceOutcome::Locked,
            NativeReadFailure::ProviderUnavailable,
        ),
    ] {
        assert_eq!(
            session_history_reply(&call, &request, outcome).err(),
            Some(failure)
        );
    }
    let stale = session_history_reply(
        &call,
        &request,
        SessionRetrievalServiceOutcome::Stale {
            temporal: SessionTemporalMetadataView::default(),
            freshness: SessionDataFreshness::Partial { generation_lag: 1 },
        },
    )
    .expect("stale outcome is a partial answer");
    assert_eq!(stale.terminal.terminal_code(), TerminalCode::Partial);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_session_recall_equals_upstream_message_search() {
    use tracedecay_session_memory::context::{SessionRootId, SessionStoreId};
    use tracedecay_session_runtime::StoreOwnerKey;
    use tracedecay_session_runtime::session_temporal_refresh_scheduler::SessionTemporalRefreshSchedulerRegistry;
    use tracedecay_sessions::admission::HostAdmissionScope;

    let temporary = tempfile::tempdir().expect("session parity root");
    let project_id = ProjectId::new("project.native-session-parity").expect("project id");
    let project_root = temporary.path().join("project");
    let runtime = tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1::project(
        &temporary.path().join("profile"),
        &project_root,
        project_id.clone(),
    )
    .await
    .expect("registered project runtime");
    let database = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .expect("registered project database");
    let graph_db_path = database.db_path().to_path_buf();
    let store_root = graph_db_path
        .parent()
        .expect("registered database has a store root")
        .to_path_buf();
    let registry = SessionTemporalRefreshSchedulerRegistry::default();
    let wake = registry
        .ensure_project(
            StoreOwnerKey {
                profile_root: store_root.clone(),
                global_db_path: graph_db_path.clone(),
                project_id: Some(project_id.as_str().to_owned()),
                store_root,
                graph_db_path,
            },
            database.clone(),
        )
        .await;
    let retrieval = Arc::new(RecordingRetrievalV1 {
        queries: Mutex::new(Vec::new()),
        outcome: partial_page(),
    });
    let upstream_port = DirectRetainedSessionPortV1::project(ProjectRetainedSessionAuthoritiesV1 {
        project_root: project_root.clone(),
        project_id: project_id.clone(),
        profile_id: UserProfileId::new(RECALL_PROFILE).expect("profile id"),
        session_store_id: SessionStoreId::new("store.native-session-parity").expect("store id"),
        session_root_id: SessionRootId::new("root.native-session-parity").expect("root id"),
        configuration_digest: ManifestDigest::new(CONFIGURATION_DIGEST).expect("digest"),
        refresh: Arc::new(crate::session_refresh::DaemonSessionRefreshService::new(
            database.clone(),
            Arc::new(wake),
            Some(project_id.as_str().to_owned()),
        )),
        retrieval: Arc::clone(&retrieval) as Arc<dyn SessionApplicationRetrievalPortV1>,
        session_database: database.clone(),
        workflow_index: Arc::new(crate::DaemonWorkflowIndexReadService::new(database.clone())),
    });
    let (context, signal, operation) = retained_context(
        &project_id,
        RetainedSurfaceOperation::MessageSearch,
        "request.native-session-parity.upstream",
    );
    let message_search = MessageSearchRequestV1 {
        query: Some("what did we decide".to_owned()),
        limit: Some(8),
        ..MessageSearchRequestV1::default()
    };
    let upstream = upstream_port
        .execute_session(
            RetainedSurfaceExecutionContextV1 {
                request_context: &context,
                cancellation_signal: &signal,
                operation: &operation,
                observed_at: now_micros(),
            },
            RetainedSessionRequestV1::MessageSearch(&message_search),
        )
        .await
        .expect("upstream message search");
    let RetainedSurfaceResultV1::MessageSearch(upstream) =
        upstream.payload().expect("upstream payload").clone()
    else {
        panic!("unexpected upstream message search result");
    };

    let mount = session_mount(project_id.as_str());
    mount
        .bind(Arc::clone(&retrieval) as Arc<dyn SessionApplicationRetrievalPortV1>)
        .expect("bind canonical session retrieval");
    let request_value =
        recall_request_value(project_id.as_str(), SESSION_HISTORY_OBJECTIVE, "what did we decide");
    let call = valid_recall_call(project_id.as_str(), &request_value);
    let request = parse_native_recall_request(&call).expect("native request");
    let reply = recall_session_history(&mount, &call, &request)
        .await
        .expect("native session recall");
    let native: Value =
        serde_json::from_slice(&reply.payload.expect("payload").bytes).expect("native JSON");

    let queries = retrieval.queries.lock().expect("recorded queries");
    assert_eq!(queries.len(), 2);
    assert_eq!(
        queries[0], queries[1],
        "Native must issue the exact upstream message-search kernel query"
    );
    let upstream_hits = upstream
        .results
        .expect("upstream hits")
        .into_iter()
        .map(|hit| (hit.message.message_id, hit.score))
        .collect::<Vec<_>>();
    let native_hits = native["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| {
            let hit = &candidate["provenance"]["message_search_hit"];
            (
                hit["message"]["message_id"]
                    .as_str()
                    .expect("message id")
                    .to_owned(),
                hit["score"].as_f64().expect("score"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(native_hits, upstream_hits);
    assert_eq!(
        native["coverage"]["next_cursor"],
        json!(upstream.temporal.expect("upstream temporal").next_cursor)
    );
}
