#![cfg(unix)]

use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use tempfile::TempDir;
use tracedecay_contracts::retained_surfaces::{MemoryStatusRequestV1, RetainedSurfaceRequestV1};
use tracedecay_contracts::{
    ApplicationProblemKind, CancellationContext, Deadline, ProblemTerminality, RetryDirective,
    WorkGraphReadRequestV1, WorkProductSelectionScopeV1,
};
#[cfg(feature = "memory-provider-host")]
use tracedecay_domain::canonical_json_bytes;
use tracedecay_domain::{ActorId, ProjectId, RepositoryId, UtcMicros, WorktreeId};
use tracedecay_tool_catalog::ApplicationSurfaceOperation;

use super::{
    enter_test_daemon_database_scope, initialize_test_project, test_client_identity_for,
    test_daemon_engine_for_profile, test_handshake_defaults,
};
use crate::daemon::{
    DaemonEngine, DaemonHandshake, DaemonInvocationOutcome, DaemonInvocationRequest,
    execute_daemon_invocation,
};
use tracedecay_application::primitives::{PrimitiveProjectRuntime, StorageStatusPrimitiveRequest};
use tracedecay_contracts::retrieval::catalog::primitive_read_operation;
use tracedecay_contracts::retrieval::{PrimitiveInvocation, PrimitiveRequest};
#[cfg(feature = "memory-provider-host")]
use tracedecay_contracts::{
    ApplicationOutcome, ConfigurationBatchRequestV1, ConfigurationDirectMutationRequestV1,
    ConfigurationGetRequestV1, ConfigurationMutationReceipt, ConfigurationSetRequestV1,
    ResolvedSetting,
};
use tracedecay_contracts::{
    CapabilityGrantId, CapabilityGrantSnapshot, DisclosureClass, RequestContext, RequestId,
    ResolvedScope,
};
use tracedecay_contracts::{ConfigurationListRequestV1, ConfigurationWireRequestV1};
use tracedecay_daemon_protocol::WorkApplicationInvocationV1;
#[cfg(feature = "memory-provider-host")]
use tracedecay_daemon_service::retained_owner::CognitiveRecallMountError;
use tracedecay_daemon_service::{
    DaemonInvocationProblem, ProjectRuntimePublicationStateV1, RegisteredRetainedRuntime,
};
#[cfg(feature = "memory-provider-host")]
use tracedecay_domain::configuration::{
    ConfigurationIdempotencyKey, ConfigurationLayerIdV1, ConfigurationValueV1,
    MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY, MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
    MemoryProviderNcmObserverV1, MemoryProviderRecallRoutingV1, SettingKey,
};

async fn committed_fixture(
    label: &str,
) -> (
    TempDir,
    tracedecay_runtime_core::db::DaemonDatabaseScope,
    DaemonEngine,
    DaemonHandshake,
) {
    let (temp, database_scope, engine, handshake) = unopened_committed_fixture(label).await;
    engine
        .project_server(&handshake)
        .await
        .expect("committed invocation project open");
    (temp, database_scope, engine, handshake)
}

/// [`committed_fixture`] before its project open, for journeys that must
/// observe the open in flight.
async fn unopened_committed_fixture(
    label: &str,
) -> (
    TempDir,
    tracedecay_runtime_core::db::DaemonDatabaseScope,
    DaemonEngine,
    DaemonHandshake,
) {
    let temp = TempDir::new().expect("committed invocation fixture");
    let project = temp.path().join("project");
    let profile_root = temp.path().join("profile");
    std::fs::create_dir_all(project.join("src")).expect("committed invocation project");
    std::fs::write(project.join("src/main.rs"), "fn main() {}\n")
        .expect("committed invocation source");
    let client_identity = test_client_identity_for(profile_root.clone());
    initialize_test_project(&project, &client_identity).await;
    super::git(&project, &["init", "--quiet"]);
    super::git(&project, &["config", "user.name", "TraceDecay Test"]);
    super::git(
        &project,
        &["config", "user.email", "tracedecay@example.invalid"],
    );
    super::git(&project, &["add", "."]);
    super::git(&project, &["commit", "--quiet", "-m", "base"]);
    let project_alias = temp.path().join("project-alias");
    std::os::unix::fs::symlink(&project, &project_alias).expect("committed project alias");
    let handshake = DaemonHandshake {
        project_path: Some(project_alias),
        client_identity,
        ..test_handshake_defaults()
    };
    let database_scope = enter_test_daemon_database_scope(&profile_root, label);
    let engine = test_daemon_engine_for_profile(&profile_root);
    (temp, database_scope, engine, handshake)
}

// Each surface check constructs its future inside its own function and returns
// it boxed: the daemon invocation state machines are large in debug builds, and
// materializing all four inline in one async fn produced a ~663 KB resident
// poll frame that, stacked on the production dispatch frames, overflowed the
// default 2 MiB test-thread stack. Boxing inside the constructor pops the
// construction temporaries before the deep poll chain runs.
fn assert_configuration_routes_mounted<'a>(
    engine: &'a DaemonEngine,
    handshake: &'a DaemonHandshake,
    observed_at: UtcMicros,
    deadline: Deadline,
    cancellation: CancellationContext,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let configuration = execute_daemon_invocation(
            engine,
            handshake,
            DaemonInvocationRequest::configuration(
                "request.project-open.configuration",
                ApplicationSurfaceOperation::ConfigurationList,
                ConfigurationWireRequestV1::List(ConfigurationListRequestV1::default()),
                observed_at,
                deadline,
                cancellation,
            ),
        )
        .await;
        assert!(
            matches!(
                configuration.outcome,
                DaemonInvocationOutcome::Configuration { .. }
            ),
            "project-open must route configuration through the mounted daemon owner: {configuration:?}"
        );
    })
}

fn assert_primitive_routes_mounted<'a>(
    engine: &'a DaemonEngine,
    handshake: &'a DaemonHandshake,
    observed_at: UtcMicros,
    deadline: Deadline,
    cancellation: CancellationContext,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let primitive = execute_daemon_invocation(
            engine,
            handshake,
            DaemonInvocationRequest::primitive(
                "request.project-open.primitive",
                ApplicationSurfaceOperation::StorageStatus,
                PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                    include_details: false,
                }),
                observed_at,
                deadline,
                cancellation,
            )
            .expect("valid primitive request"),
        )
        .await;
        assert!(
            matches!(primitive.outcome, DaemonInvocationOutcome::Primitive { .. }),
            "project-open must route primitives through the mounted daemon owner: {primitive:?}"
        );
    })
}

fn assert_work_routes_mounted<'a>(
    engine: &'a DaemonEngine,
    handshake: &'a DaemonHandshake,
    observed_at: UtcMicros,
    deadline: Deadline,
    cancellation: CancellationContext,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let work = execute_daemon_invocation(
            engine,
            handshake,
            DaemonInvocationRequest::work_application(
                "request.project-open.work",
                WorkApplicationInvocationV1::Views(WorkGraphReadRequestV1::current(
                    WorkProductSelectionScopeV1::ProfileOwnedNoGit,
                    observed_at,
                )),
                observed_at,
                deadline,
                cancellation,
            ),
        )
        .await;
        // A freshly opened project has published no Work graph version, and a
        // verified version identity requires a real event sequence, so there
        // is no representable empty current graph to answer with: the mounted
        // owner answers the authorized absence as a concealed
        // not-found-or-not-authorized. That still proves routing, an
        // unmounted owner never reaches the Work application and answers
        // `Problem::Unavailable` instead, exactly as the unregistered-project
        // test below asserts.
        let routed_to_mounted_owner = match &work.outcome {
            DaemonInvocationOutcome::WorkApplication { .. } => true,
            DaemonInvocationOutcome::ApplicationProblem { problem } => {
                problem.kind() == ApplicationProblemKind::NotFoundOrNotAuthorized
            }
            _ => false,
        };
        assert!(
            routed_to_mounted_owner,
            "project-open must route Work through the mounted daemon owner: {work:?}"
        );
    })
}

fn assert_feedback_conceals_unknown_handle<'a>(
    engine: &'a DaemonEngine,
    handshake: &'a DaemonHandshake,
    observed_at: UtcMicros,
    deadline: Deadline,
    cancellation: CancellationContext,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let feedback = execute_daemon_invocation(
            engine,
            handshake,
            DaemonInvocationRequest::feedback(
                "request.project-open.feedback",
                ApplicationSurfaceOperation::FeedbackList,
                "feedback-handle.unknown".to_owned(),
                observed_at,
                deadline,
                cancellation,
            ),
        )
        .await;
        assert!(
            matches!(
                feedback.outcome,
                DaemonInvocationOutcome::ApplicationProblem { ref problem }
                    if problem.kind() == ApplicationProblemKind::NotFoundOrNotAuthorized
            ),
            "mounted feedback must conceal an unknown handle instead of reporting owner unavailable: {feedback:?}"
        );
    })
}

async fn assert_mounted_invocations(engine: &DaemonEngine, handshake: &DaemonHandshake) {
    let observed_at = tracedecay_contracts::clock::now_micros();
    let deadline = Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
        .expect("daemon invocation deadline");
    let cancellation = CancellationContext::active("cancel.project-open-invocations")
        .expect("daemon invocation cancellation");
    assert_configuration_routes_mounted(
        engine,
        handshake,
        observed_at,
        deadline.clone(),
        cancellation.clone(),
    )
    .await;
    assert_primitive_routes_mounted(
        engine,
        handshake,
        observed_at,
        deadline.clone(),
        cancellation.clone(),
    )
    .await;
    assert_work_routes_mounted(
        engine,
        handshake,
        observed_at,
        deadline.clone(),
        cancellation.clone(),
    )
    .await;
    assert_feedback_conceals_unknown_handle(engine, handshake, observed_at, deadline, cancellation)
        .await;
}

#[tokio::test]
async fn primitive_identity_is_refused_before_daemon_and_application_owners() {
    let (_temp, _database_scope, engine, handshake) =
        committed_fixture("primitive-invocation-identity").await;
    let now = tracedecay_contracts::clock::now_micros();
    let deadline = Deadline::new(UtcMicros(now.0 + 30_000_000)).expect("deadline");
    let cancellation =
        CancellationContext::active("cancel.primitive-identity").expect("cancellation");
    assert_primitive_routes_mounted(
        &engine,
        &handshake,
        now,
        deadline.clone(),
        cancellation.clone(),
    )
    .await;
    let frame = DaemonInvocationRequest::primitive(
        "request.primitive-identity",
        ApplicationSurfaceOperation::StorageStatus,
        PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
            include_details: true,
        }),
        now,
        deadline.clone(),
        cancellation.clone(),
    )
    .expect("matching frame");
    let mut wire = serde_json::to_value(frame).expect("serialize frame");
    wire["surface_operation"] = serde_json::json!("source_lines");
    let malformed = serde_json::from_value(wire).expect("deserialize malformed pair");
    let response = execute_daemon_invocation(&engine, &handshake, malformed).await;
    assert!(
        matches!(
            response.outcome,
            DaemonInvocationOutcome::Problem {
                problem: DaemonInvocationProblem::InvalidRequest
            }
        ),
        "{response:?}"
    );

    let root = Path::new(handshake.project_path.as_deref().expect("project root"));
    let dispatch = engine
        .invocation
        .service
        .project_runtimes
        .read(root, PrimitiveProjectRuntime::dispatch)
        .await
        .expect("mounted primitive dispatcher");
    let operation = primitive_read_operation("source_lines")
        .expect("catalog")
        .expect("source-lines operation");
    let foreign_scope = ResolvedScope::new(
        ProjectId::new("project.foreign-primitive").expect("project"),
        RepositoryId::new("repository.foreign-primitive").expect("repository"),
        WorktreeId::new("worktree.foreign-primitive").expect("worktree"),
        None,
    )
    .expect("scope");
    let actor = ActorId::new("actor.primitive-identity").expect("actor");
    let grant = CapabilityGrantSnapshot::new(
        CapabilityGrantId::new("grant.primitive-identity").expect("grant"),
        1,
        foreign_scope.scope_digest.clone(),
        actor.clone(),
        now,
        deadline.expires_at,
        foreign_scope.clone(),
        BTreeSet::from([operation.capability_id().clone()]),
        BTreeSet::from([operation.use_case_id().clone()]),
        DisclosureClass::Evidence,
    )
    .expect("fixture grant");
    let context = RequestContext::new(
        actor,
        foreign_scope,
        grant,
        RequestId::new("request.application-primitive-identity").expect("request"),
        deadline.clone(),
        cancellation.clone(),
    )
    .expect("context");
    let mismatch = dispatch
        .dispatch(
            PrimitiveInvocation {
                operation,
                request: PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                    include_details: true,
                }),
            },
            context.clone(),
            now,
        )
        .await
        .expect("application result")
        .expect_err("operation/body mismatch");
    assert_eq!(
        mismatch.problem.kind(),
        ApplicationProblemKind::InvalidRequest
    );
    let matching = dispatch
        .dispatch(
            PrimitiveInvocation {
                operation: primitive_read_operation("storage_status")
                    .expect("catalog")
                    .expect("storage operation"),
                request: PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                    include_details: true,
                }),
            },
            context,
            now,
        )
        .await
        .expect("application result")
        .expect_err("foreign scope");
    assert_eq!(
        matching.problem.kind(),
        ApplicationProblemKind::NotFoundOrNotAuthorized
    );

    drop(dispatch);

    for (label, deadline, cancellation, expected) in [
        (
            "cancelled",
            deadline,
            CancellationContext::cancelled("cancel.primitive-identity.cancelled", now)
                .expect("cancelled"),
            ApplicationProblemKind::Cancelled,
        ),
        (
            "expired",
            Deadline::new(UtcMicros(now.0 - 1)).expect("expired deadline"),
            cancellation,
            ApplicationProblemKind::TimedOut,
        ),
    ] {
        let request = DaemonInvocationRequest::primitive(
            format!("request.primitive-identity.{label}"),
            ApplicationSurfaceOperation::StorageStatus,
            PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                include_details: false,
            }),
            now,
            deadline,
            cancellation,
        )
        .expect("matching controls");
        let response = execute_daemon_invocation(&engine, &handshake, request).await;
        assert!(
            matches!(response.outcome, DaemonInvocationOutcome::ApplicationProblem {ref problem} if problem.kind() == expected),
            "{response:?}"
        );
    }
    let shutdown = engine.shutdown_all().await;
    assert!(shutdown.project_servers.is_clean(), "{shutdown:?}");
}

#[tokio::test]
async fn committed_project_alias_invokes_mounted_primitive_and_shuts_down_cleanly() {
    let (_temp, _database_scope, engine, handshake) =
        committed_fixture("committed-project-invocation-owners").await;
    assert_mounted_invocations(&engine, &handshake).await;
    let project_alias = handshake.project_path.as_deref().expect("project alias");
    assert_eq!(
        engine
            .invocation
            .service
            .project_runtimes
            .publication_state(project_alias),
        Some(ProjectRuntimePublicationStateV1::Ready),
        "a callable owner reached through the alias must be fully published"
    );
    let shutdown = engine.shutdown_all().await;
    assert!(
        shutdown.project_servers.is_clean(),
        "the alias-mounted callable owner must shut down cleanly: {shutdown:?}"
    );
}

/// Right after a restart the profile store's readers can all be busy. The
/// project source-access read then times out, and a mounted project must
/// answer that as a retryable unavailable state naming the configuration
/// authority, never as a denial of a project the caller is standing in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn primitive_read_with_a_saturated_configuration_store_is_unavailable_not_denied() {
    let (_temp, _database_scope, engine, handshake) =
        committed_fixture("primitive-read-saturated-configuration").await;
    let server = engine
        .project_server(&handshake)
        .await
        .expect("mounted project server");
    let configuration_store = server
        .cg()
        .await
        .configuration_runtime()
        .registered_database();
    // Lease readers until the pool, burst workers included, refuses one.
    let mut held_readers = Vec::new();
    while let Ok(reader) = configuration_store.read_snapshot().await {
        held_readers.push(reader);
    }
    assert!(
        !held_readers.is_empty(),
        "the store admitted readers before saturating"
    );

    let observed_at = tracedecay_contracts::clock::now_micros();
    let response = execute_daemon_invocation(
        &engine,
        &handshake,
        DaemonInvocationRequest::primitive(
            "request.saturated-configuration.primitive",
            ApplicationSurfaceOperation::StorageStatus,
            PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                include_details: false,
            }),
            observed_at,
            Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
                .expect("daemon invocation deadline"),
            CancellationContext::active("cancel.saturated-configuration")
                .expect("daemon invocation cancellation"),
        )
        .expect("valid primitive request"),
    )
    .await;
    let DaemonInvocationOutcome::ApplicationProblem { problem } = &response.outcome else {
        panic!("a saturated configuration store must answer a typed problem: {response:?}");
    };
    assert_eq!(
        problem.kind(),
        ApplicationProblemKind::Unavailable,
        "{problem:?}"
    );
    assert_eq!(problem.retry(), RetryDirective::AfterDelay, "{problem:?}");
    assert_eq!(
        problem
            .diagnostic()
            .map(|diagnostic| diagnostic.code.as_str()),
        Some("configuration_authority_unavailable"),
        "{problem:?}"
    );

    drop(held_readers);
    let served = execute_daemon_invocation(
        &engine,
        &handshake,
        DaemonInvocationRequest::primitive(
            "request.saturated-configuration.released",
            ApplicationSurfaceOperation::StorageStatus,
            PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
                include_details: false,
            }),
            tracedecay_contracts::clock::now_micros(),
            Deadline::new(UtcMicros(observed_at.0.saturating_add(60_000_000)))
                .expect("daemon invocation deadline"),
            CancellationContext::active("cancel.saturated-configuration.released")
                .expect("daemon invocation cancellation"),
        )
        .expect("valid primitive request"),
    )
    .await;
    assert!(
        matches!(served.outcome, DaemonInvocationOutcome::Primitive { .. }),
        "the same read is served once readers free up: {served:?}"
    );
    drop((configuration_store, server));
    engine.shutdown_all().await;
}

#[tokio::test]
async fn unregistered_project_invocation_reports_truthful_unavailable() {
    let temp = TempDir::new().expect("unregistered project fixture");
    let profile_root = temp.path().join("profile");
    let client_identity = test_client_identity_for(profile_root.clone());
    let handshake = DaemonHandshake {
        project_path: Some(temp.path().join("missing-project")),
        client_identity,
        ..test_handshake_defaults()
    };
    let _database_scope =
        enter_test_daemon_database_scope(&profile_root, "unregistered-project-invocation");
    let engine = test_daemon_engine_for_profile(&profile_root);
    let observed_at = tracedecay_contracts::clock::now_micros();
    let deadline = Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
        .expect("daemon invocation deadline");
    let cancellation = CancellationContext::active("cancel.unregistered-project-invocation")
        .expect("daemon invocation cancellation");
    let response = execute_daemon_invocation(
        &engine,
        &handshake,
        DaemonInvocationRequest::configuration(
            "request.unregistered-project.configuration",
            ApplicationSurfaceOperation::ConfigurationList,
            ConfigurationWireRequestV1::List(ConfigurationListRequestV1::default()),
            observed_at,
            deadline,
            cancellation,
        ),
    )
    .await;
    assert!(
        matches!(
            response.outcome,
            DaemonInvocationOutcome::Problem {
                problem: DaemonInvocationProblem::Unavailable
            }
        ),
        "an unregistered project must remain truthfully unavailable: {response:?}"
    );
    engine.shutdown_all().await;
}

fn memory_status_request(request_id: &str) -> DaemonInvocationRequest {
    let observed_at = tracedecay_contracts::clock::now_micros();
    DaemonInvocationRequest::retained_application(
        request_id,
        RetainedSurfaceRequestV1::MemoryStatus(MemoryStatusRequestV1 {
            memory_scope: None,
            project_selector: None,
        }),
        observed_at,
        Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
            .expect("daemon invocation deadline"),
        CancellationContext::active(format!("cancel.{request_id}"))
            .expect("daemon invocation cancellation"),
    )
}

/// The core route is admitted before the full server's owner phase registers
/// the retained runtime. Hold its registration open and prove that a retained
/// request landing in the window sees a retryable mounting owner, rather than
/// a scope with no retained runtime. The same request is served after mounting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_invocation_while_owners_mount_is_retryable_not_unmounted() {
    let (_temp, _database_scope, engine, handshake) =
        unopened_committed_fixture("retained-invocation-while-owners-mount").await;
    let canonical_project = handshake
        .project_path
        .as_deref()
        .expect("project alias")
        .canonicalize()
        .expect("canonical project root");
    let registration = engine
        .invocation
        .service
        .pause_retained_runtime_registration(canonical_project.clone())
        .await;
    let opening_engine = engine.clone();
    let opening_handshake = handshake.clone();
    let opening =
        tokio::spawn(async move { opening_engine.project_server(&opening_handshake).await });
    tokio::time::timeout(
        std::time::Duration::from_mins(1),
        registration.before_registration,
    )
    .await
    .expect("project open must reach the owner registration gate")
    .expect("owner registration gate sender");
    assert_eq!(
        engine
            .invocation
            .service
            .project_runtimes
            .publication_state(&canonical_project),
        Some(ProjectRuntimePublicationStateV1::Warming),
        "the admitted route must still be publishing its owners"
    );
    assert!(
        !engine
            .invocation
            .service
            .project_runtimes
            .holds::<RegisteredRetainedRuntime>(&canonical_project)
            .await,
        "the gate must hold the open ahead of the retained registration"
    );

    let mounting = execute_daemon_invocation(
        &engine,
        &handshake,
        memory_status_request("request.retained.while-mounting"),
    )
    .await;
    let DaemonInvocationOutcome::ApplicationProblem { problem } = &mounting.outcome else {
        panic!(
            "a retained request during owner mounting must answer a typed problem: {mounting:?}"
        );
    };
    assert_eq!(problem.kind(), ApplicationProblemKind::Unavailable);
    assert_eq!(problem.terminality(), ProblemTerminality::PreAdmission);
    assert_eq!(problem.retry(), RetryDirective::AfterDelay);
    let diagnostic = problem
        .diagnostic()
        .expect("a mounting retained owner carries a diagnostic");
    assert_eq!(
        diagnostic.code,
        tracedecay_contracts::RUNTIME_MOUNTING_REASON_CODE
    );
    assert!(
        !diagnostic
            .message
            .contains("no retained runtime is registered"),
        "a mounting route must not claim its scope has no retained runtime: {}",
        diagnostic.message
    );

    registration
        .allow_registration
        .send(())
        .expect("release owner registration");
    tokio::time::timeout(
        std::time::Duration::from_mins(1),
        registration.after_registration,
    )
    .await
    .expect("owner registration must publish")
    .expect("owner registration publication sender");
    registration
        .allow_return
        .send(())
        .expect("release project-open owner setup");
    opening
        .await
        .expect("project-open task")
        .expect("project opens once its owners are registered");

    let served = execute_daemon_invocation(
        &engine,
        &handshake,
        memory_status_request("request.retained.after-mounting"),
    )
    .await;
    assert!(
        matches!(
            served.outcome,
            DaemonInvocationOutcome::RetainedApplication { .. }
        ),
        "the same retained request must be answered once the owner phase completes: {served:?}"
    );
    let shutdown = engine.shutdown_all().await;
    assert!(
        shutdown.project_servers.is_clean(),
        "the retained owner must shut down cleanly: {shutdown:?}"
    );
}

/// Primitive reads belong to the admitted core route and must not wait for
/// later retained, native-integration, or Work owners. Hold retained
/// publication after primitive registration and prove a status read is served
/// while the overall project publication is warming.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn primitive_invocation_serves_while_later_owners_mount() {
    let (_temp, _database_scope, engine, handshake) =
        unopened_committed_fixture("primitive-invocation-while-later-owners-mount").await;
    let canonical_project = handshake
        .project_path
        .as_deref()
        .expect("project alias")
        .canonicalize()
        .expect("canonical project root");
    let registration = engine
        .invocation
        .service
        .pause_retained_runtime_registration(canonical_project.clone())
        .await;
    let opening_engine = engine.clone();
    let opening_handshake = handshake.clone();
    let opening =
        tokio::spawn(async move { opening_engine.project_server(&opening_handshake).await });
    tokio::time::timeout(
        std::time::Duration::from_mins(1),
        registration.before_registration,
    )
    .await
    .expect("project open must reach the later owner registration gate")
    .expect("owner registration gate sender");
    assert_eq!(
        engine
            .invocation
            .service
            .project_runtimes
            .publication_state(&canonical_project),
        Some(ProjectRuntimePublicationStateV1::Warming),
        "later owners must still be publishing"
    );

    let observed_at = tracedecay_contracts::clock::now_micros();
    assert_primitive_routes_mounted(
        &engine,
        &handshake,
        observed_at,
        Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
            .expect("daemon invocation deadline"),
        CancellationContext::active("cancel.primitive-while-later-owners-mount")
            .expect("daemon invocation cancellation"),
    )
    .await;

    registration
        .allow_registration
        .send(())
        .expect("release retained registration");
    tokio::time::timeout(
        std::time::Duration::from_mins(1),
        registration.after_registration,
    )
    .await
    .expect("retained owner must publish")
    .expect("retained registration publication sender");
    registration
        .allow_return
        .send(())
        .expect("release project-open owner setup");
    opening
        .await
        .expect("project-open task")
        .expect("project opens once its owners are registered");
    engine.shutdown_all().await;
}

#[cfg(feature = "memory-provider-host")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_ncm_failure_preserves_core_configuration_repair() {
    let (temp, _database_scope, engine, handshake) =
        committed_fixture("required-ncm-configuration-repair").await;
    let server = engine
        .project_server(&handshake)
        .await
        .expect("baseline server");
    let graph = server.cg().await;
    let current = graph
        .configuration_runtime()
        .client()
        .current()
        .await
        .expect("baseline configuration revision");
    let target = graph.configuration_runtime().configuration_target().clone();
    let scope = tracedecay_code_index_runtime::resolved_scope_for_project(
        graph.project_root(),
        &target.project_id,
    )
    .expect("canonical configuration scope");
    let project_root = graph.project_root().to_path_buf();
    let initial_revision = current.revision_id().clone();
    drop(current);
    drop(graph);

    let state_root = temp.path().join("ncm-state");
    std::fs::create_dir_all(&state_root).expect("owned NCM state root");
    let worker_binary = temp.path().join("absent-ncm-worker");
    assert!(
        !worker_binary.exists(),
        "the fixture has no worker to launch"
    );
    let observer = MemoryProviderNcmObserverV1::Enabled {
        worker_binary: worker_binary.clone(),
        state_root,
        namespace_binding: Default::default(),
    };
    let strict_routing = MemoryProviderRecallRoutingV1 {
        active_provider: Some("ncm".to_owned()),
        fallback: None,
        degradation: None,
    };
    let observer_key = SettingKey::new(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY)
        .expect("NCM participation setting key");
    let routing_key = SettingKey::new(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY)
        .expect("NCM routing setting key");
    let strict_value = ConfigurationValueV1::Text(
        String::from_utf8(canonical_json_bytes(&strict_routing).expect("strict routing document"))
            .expect("canonical strict routing UTF-8"),
    );
    let request = |id: &str, operation, body| {
        let observed_at = tracedecay_contracts::clock::now_micros();
        DaemonInvocationRequest::configuration(
            id,
            operation,
            body,
            observed_at,
            Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
                .expect("configuration deadline"),
            CancellationContext::active(format!("cancel.{id}"))
                .expect("configuration cancellation"),
        )
        .with_resolved_scope(Some(scope.clone()))
        .expect("exact configuration request scope")
    };
    let configured = execute_daemon_invocation(
        &engine,
        &handshake,
        request(
            "request.required-ncm.configure",
            ApplicationSurfaceOperation::ConfigurationBatch,
            ConfigurationWireRequestV1::Batch(ConfigurationBatchRequestV1 {
                mutations: vec![
                    ConfigurationDirectMutationRequestV1::Set {
                        layer: ConfigurationLayerIdV1::Project {
                            project_id: target.project_id.clone(),
                        },
                        key: observer_key,
                        value: Box::new(ConfigurationValueV1::Text(
                            String::from_utf8(
                                canonical_json_bytes(&observer)
                                    .expect("NCM participation document"),
                            )
                            .expect("canonical NCM participation UTF-8"),
                        )),
                    },
                    ConfigurationDirectMutationRequestV1::Set {
                        layer: ConfigurationLayerIdV1::Project {
                            project_id: target.project_id.clone(),
                        },
                        key: routing_key.clone(),
                        value: Box::new(strict_value.clone()),
                    },
                ],
                expected_revision: initial_revision.clone(),
                idempotency_key: ConfigurationIdempotencyKey::new(
                    "idempotency.required-ncm.configure",
                )
                .expect("configuration batch identity"),
            }),
        ),
    )
    .await;
    let configured_receipt: ConfigurationMutationReceipt = match configured.outcome {
        DaemonInvocationOutcome::Configuration {
            outcome: ApplicationOutcome::Effect(effect),
            ..
        } => serde_json::from_value(effect.payload.expect("configuration batch receipt"))
            .expect("typed configuration batch receipt"),
        other => panic!("strict NCM must be configured through a real CAS: {other:?}"),
    };
    assert_eq!(configured_receipt.base_revision_id, initial_revision);
    drop(server);
    let shutdown = engine.shutdown_all().await;
    assert!(
        shutdown.project_servers.is_clean(),
        "baseline shutdown: {shutdown:?}"
    );
    drop(engine);

    let engine = test_daemon_engine_for_profile(&target.profile_root);
    let core = engine
        .project_server(&handshake)
        .await
        .expect("failed required NCM activation must preserve the core");
    assert_eq!(
        engine
            .invocation
            .service
            .project_runtimes
            .publication_state(&project_root),
        Some(ProjectRuntimePublicationStateV1::Failed),
        "the missing actual worker must refuse full publication"
    );
    assert!(
        !engine
            .invocation
            .service
            .project_runtimes
            .holds::<RegisteredRetainedRuntime>(&project_root)
            .await,
        "failed full publication must not install a retained owner"
    );
    assert!(
        matches!(
            core.cognitive_recall_port_for_session("session.required-ncm.repair"),
            Err(CognitiveRecallMountError::FullCompositionPending)
        ),
        "strict NCM failure must not return a usable Native recall port"
    );
    let observed_at = tracedecay_contracts::clock::now_micros();
    let storage = DaemonInvocationRequest::primitive(
        "request.required-ncm.storage",
        ApplicationSurfaceOperation::StorageStatus,
        PrimitiveRequest::StorageStatus(StorageStatusPrimitiveRequest {
            include_details: false,
        }),
        observed_at,
        Deadline::new(UtcMicros(observed_at.0.saturating_add(30_000_000)))
            .expect("storage status deadline"),
        CancellationContext::active("cancel.required-ncm.storage")
            .expect("storage status cancellation"),
    )
    .expect("valid storage status primitive request");
    for request in [
        storage,
        memory_status_request("request.required-ncm.memory"),
    ] {
        let response = execute_daemon_invocation(&engine, &handshake, request).await;
        assert!(
            matches!(
                response.outcome,
                DaemonInvocationOutcome::ApplicationProblem { ref problem }
                    if problem.kind() == ApplicationProblemKind::ExecutionFailed
                        && problem.retry() == RetryDirective::Never
                        && problem
                            .diagnostic()
                            .map(|diagnostic| diagnostic.code.as_str())
                            == Some("application.runtime.owner_failed")
            ),
            "a failed full owner must retain its permanent typed refusal: {response:?}"
        );
    }

    let get = |id: &str| {
        request(
            id,
            ApplicationSurfaceOperation::ConfigurationGet,
            ConfigurationWireRequestV1::Get(ConfigurationGetRequestV1 {
                key: routing_key.clone(),
            }),
        )
    };
    let before = execute_daemon_invocation(
        &engine,
        &handshake,
        get("request.required-ncm.before-repair"),
    )
    .await;
    let before: ResolvedSetting = match before.outcome {
        DaemonInvocationOutcome::Configuration {
            outcome: ApplicationOutcome::Evidence(packet),
            ..
        } => serde_json::from_value(packet.payload.expect("configuration evidence"))
            .expect("resolved strict routing"),
        other => panic!("configuration must remain readable after NCM failure: {other:?}"),
    };
    assert_eq!(before.effective_value, strict_value);
    assert_eq!(before.revision_id, configured_receipt.result_revision_id);
    let repaired_value = ConfigurationValueV1::Text(
        String::from_utf8(
            canonical_json_bytes(&MemoryProviderRecallRoutingV1::default())
                .expect("observer-only routing document"),
        )
        .expect("canonical observer-only routing UTF-8"),
    );
    let set = |id: &str, value| {
        request(
            id,
            ApplicationSurfaceOperation::ConfigurationSet,
            ConfigurationWireRequestV1::Set(ConfigurationSetRequestV1 {
                layer: ConfigurationLayerIdV1::Project {
                    project_id: target.project_id.clone(),
                },
                key: routing_key.clone(),
                value,
                expected_revision: before.revision_id.clone(),
                idempotency_key: ConfigurationIdempotencyKey::new(id)
                    .expect("configuration repair identity"),
            }),
        )
    };
    let repaired = execute_daemon_invocation(
        &engine,
        &handshake,
        set("request.required-ncm.repair", repaired_value.clone()),
    )
    .await;
    let receipt: ConfigurationMutationReceipt = match repaired.outcome {
        DaemonInvocationOutcome::Configuration {
            outcome: ApplicationOutcome::Effect(effect),
            ..
        } => serde_json::from_value(effect.payload.expect("configuration repair receipt"))
            .expect("typed configuration repair receipt"),
        other => panic!("configuration repair CAS must remain callable: {other:?}"),
    };
    assert_eq!(receipt.base_revision_id, before.revision_id);
    assert_ne!(receipt.result_revision_id, before.revision_id);
    let stale = execute_daemon_invocation(
        &engine,
        &handshake,
        set("request.required-ncm.stale-repair", strict_value),
    )
    .await;
    assert!(
        matches!(
            stale.outcome,
            DaemonInvocationOutcome::ApplicationProblem { ref problem }
                if problem.kind() == ApplicationProblemKind::Conflict
        ),
        "a stale repair revision must still conflict: {stale:?}"
    );
    let after = execute_daemon_invocation(
        &engine,
        &handshake,
        get("request.required-ncm.after-repair"),
    )
    .await;
    let after: ResolvedSetting = match after.outcome {
        DaemonInvocationOutcome::Configuration {
            outcome: ApplicationOutcome::Evidence(packet),
            ..
        } => serde_json::from_value(packet.payload.expect("repaired configuration evidence"))
            .expect("resolved repaired routing"),
        other => panic!("configuration repair must be readable: {other:?}"),
    };
    assert_eq!(after.effective_value, repaired_value);
    assert_eq!(after.revision_id, receipt.result_revision_id);
    assert!(
        !worker_binary.exists(),
        "configuration repair must not create a worker"
    );
    drop(core);
    let shutdown = engine.shutdown_all().await;
    assert!(
        shutdown.project_servers.is_clean(),
        "failed-owner shutdown: {shutdown:?}"
    );
}
