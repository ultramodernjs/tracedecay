//! Real offline worker on the canonical commit, late-enable, and restart path.

use super::*;
use tracedecay_memory_provider_ncm::{
    NCM_PROVIDER_ID, NcmCognitiveSurface, NcmProviderAdapter, RustNcmConfig, RustNcmSurface,
    RustNcmWorkerOwner, StateRoot, WorkerOptions,
};
use tracedecay_memory_provider_registry::{
    EnabledProviderMode, FabricConfig, ObservationInstanceProofV1,
    ObservationProviderMountV1, ObservationStateNamespacePolicyV1, ObserverProviderRegistration,
    PayloadSanitizationReceiptParts, ProjectMemoryProviderComposition, ProviderExecutionShapeV1,
    ProviderLifecycleOwnershipV1, ProviderRegistrationV1, RecallBudgetsV1, RecallScopeBindingsV1,
    ScopeBinding, SelectedProviderActivationV1, admit_recall_reply, build_recall_request_payload,
    decode_recall_outcome,
};

use std::sync::atomic::{AtomicU64, Ordering};

const REAL_NCM_SANITIZER_REVISION: &str =
    "tracedecay.memory.observation.hygiene.v1+real-ncm-observer";
static REAL_NCM_NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Keep the worker owner with the fixture so a test can prove the final strong
/// owner closes only after the mounted journeys and their provider adapters
/// have been dropped. The service test must construct the provider through the
/// provider crate's topology-neutral surface instead of reaching back into the
/// retired binary composition root.
struct NcmObserverFixture {
    observer: ObserverProviderRegistration,
    mount: ObservationProviderMountV1,
    worker_owner: Arc<RustNcmWorkerOwner>,
}

struct NcmInstanceProof(Arc<RustNcmSurface>);

impl std::fmt::Debug for NcmInstanceProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NcmInstanceProof")
    }
}

impl ObservationInstanceProofV1 for NcmInstanceProof {
    fn prove(
        &self,
        deadline: std::time::Instant,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Option<String>, TerminalCode> {
        self.0.prove_provider_instance(deadline, cancelled)
    }
}

/// Builds one observer registration from the provider's neutral Rust surface.
/// Construction remains lazy with respect to worker/model startup: the worker
/// owner starts its child only when the observation journey performs readiness.
fn construct_ncm_observer(
    worker_binary: PathBuf,
    state_root: PathBuf,
    registration_revision: u64,
) -> Result<NcmObserverFixture, String> {
    let admitted_state_root = StateRoot::new(state_root).map_err(|error| error.to_string())?;
    let mount_state_root = admitted_state_root.path().to_path_buf();
    let worker_owner = Arc::new(
        RustNcmWorkerOwner::new(RustNcmConfig {
            worker_binary,
            state_root: admitted_state_root,
            worker_options: WorkerOptions::default(),
        })
        .map_err(|error| error.to_string())?,
    );
    let surface = Arc::new(
        RustNcmSurface::from_production_worker(Arc::clone(&worker_owner))
            .map_err(|error| error.to_string())?,
    );
    let descriptor = surface.descriptor();
    let provider_instance_id = surface
        .provider_instance_id()
        .map_err(|error| error.to_string())?;
    let instance_proof = Some(
        Arc::new(NcmInstanceProof(Arc::clone(&surface))) as Arc<dyn ObservationInstanceProofV1>
    );
    let provider = Arc::new(
        NcmProviderAdapter::new(Arc::clone(&surface) as Arc<dyn NcmCognitiveSurface>)
            .map_err(|error| error.to_string())?,
    );
    Ok(NcmObserverFixture {
        observer: ObserverProviderRegistration {
            provider,
            registration_revision,
        },
        mount: ObservationProviderMountV1 {
            provider_id: descriptor.provider_id,
            registration_revision,
            provider_instance_id,
            instance_proof,
            host_limits: descriptor.limits,
            state_root: mount_state_root.join("namespaces"),
            journal_file_name: "memory-observation-ncm-journal-v1.sqlite3",
            state_namespace_policy: ObservationStateNamespacePolicyV1::AdapterAttestedExactScope,
        },
        worker_owner,
    })
}

/// Requires the actual production worker and a canonically installed model.
/// The fixture shares immutable model artifacts only; every mutable namespace,
/// canonical database, journal, and receipt lives inside its own temporary root.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
async fn real_ncm_observer_replays_independently_after_native_restart() {
    let worker =
        PathBuf::from(std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real worker fixture"));
    let installed = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT").expect("installed model fixture"),
    );
    assert!(worker.is_absolute() && installed.is_absolute());
    let temp = TempDir::new().unwrap();
    let ncm_root = temp.path().join("ncm");
    std::fs::create_dir_all(&ncm_root).unwrap();
    std::os::unix::fs::symlink(installed.join("models"), ncm_root.join("models")).unwrap();
    let project_id = ProjectId::new("project.real-ncm-observer").unwrap();
    let profile_id = UserProfileId::new("profile.real-ncm-observer").unwrap();
    let resolved_scope = scope(project_id.clone());
    let runtime = HostAdmissionTestRuntimeV1::project(
        &temp.path().join("profile"),
        &temp.path().join("project"),
        project_id.clone(),
    )
    .await
    .unwrap();
    let store = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .unwrap()
        .observation_store();
    let journal_root = temp.path().join("journey");
    std::fs::create_dir_all(&journal_root).unwrap();
    let port = Arc::new(JourneyObserverPort::new());
    let inputs = |composition, provider| ObservationJourneyMountInputsV1 {
        composition,
        profile_id: profile_id.clone(),
        scope: resolved_scope.clone(),
        authoritative_project_id: project_id.clone(),
        store_data_root: journal_root.clone(),
        provider,
        policy: ObservationJourneyPolicyV1::project_default(),
    };
    let native_metadata =
        fixture_observer_mount(&journal_root, 1).unwrap();
    let native = mount_project_observation_journey(inputs(
        composition(port.clone()),
        native_metadata.clone(),
    ))
    .unwrap();
    let session_id = SessionId::new("session.real-ncm-observer").unwrap();
    persist_position(
        &store,
        &project_id,
        &session_id,
        "Database transactions commit atomically after validation.",
        0,
    )
    .await;
    let cancellation = HostCancellationToken::new();
    assert_eq!(
        run_startup_replay(&native, &store, &cancellation)
            .await
            .unwrap()
            .admitted,
        1
    );
    assert_eq!(
        wait_for_settlement(native.journal_path()).await.0,
        "acknowledged"
    );
    assert!(
        native
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
    drop(native);

    // NCM is enabled only after Native has already acknowledged the source.
    // Each open reconstructs the real worker over the same durable root.
    // Open 1 has a same-session commit waiting at startup; open 2 starts
    // caught up and receives its next same-session commit on the live edge.
    for open in 0..3 {
        if open == 1 {
            persist_position(
                &store,
                &project_id,
                &session_id,
                "A pending transaction resumes after the worker restarts.",
                1,
            )
            .await;
        }
        let worker = worker.clone();
        let ncm_root = ncm_root.clone();
        let fixture =
            tokio::task::spawn_blocking(move || construct_ncm_observer(worker, ncm_root, 1))
                .await
                .unwrap()
                .unwrap();
        let NcmObserverFixture {
            observer,
            mount: ncm_metadata,
            worker_owner,
        } = fixture;
        let composition = Arc::new(
            ProjectMemoryProviderComposition::compose_selected(
                SelectedProviderActivationV1::ObserversOnly {
                    fabric_config: FabricConfig {
                        max_registered_providers: 2,
                        max_in_flight: 1,
                    },
                },
                vec![
                    ObserverProviderRegistration {
                        provider: port.clone(),
                        registration_revision: 1,
                    },
                    observer,
                ],
            )
            .unwrap(),
        );
        let native = mount_and_replay(
            inputs(composition.clone(), native_metadata.clone()),
            store.clone(),
            &cancellation,
        )
        .await
        .expect("Native mounts through the production startup/live seam");
        let ncm = mount_and_replay(
            inputs(composition.clone(), ncm_metadata.clone()),
            store.clone(),
            &cancellation,
        )
        .await
        .expect("NCM mounts even when persisted namespace readiness needs a refresh");
        assert_ne!(native.journal_path(), ncm.journal_path());
        if open == 2 {
            wait_for_all_ncm_settlements(&ncm, 2).await;
            persist_position(
                &store,
                &project_id,
                &session_id,
                "A live transaction arrives after an empty restart replay.",
                2,
            )
            .await;
        }
        let expected_count = open + 1;
        wait_for_all_ncm_settlements(&native, expected_count).await;
        wait_for_all_ncm_settlements(&ncm, expected_count).await;
        for journey in [&native, &ncm] {
            let connection = rusqlite::Connection::open(journey.journal_path()).unwrap();
            let (count, applied): (i64, String) = connection
                .query_row(
                    "SELECT COUNT(*), MIN(committed_effect) FROM tdmem_observation_receipt_v1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                (count, applied.as_str()),
                (i64::try_from(expected_count).unwrap(), "applied")
            );
        }
        assert_eq!(port.observe_calls.load(Ordering::Relaxed), expected_count);
        assert_observer_has_no_active_output(
            &composition,
            &ncm_metadata,
            &profile_id,
            &resolved_scope,
            session_id.as_str(),
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for journey in [&native, &ncm] {
            assert!(journey.shutdown(deadline).await.is_empty());
        }
        drop(native);
        drop(ncm);
        drop(composition);
        // The last strong daemon owner must close before a fresh worker opens.
        tokio::task::spawn_blocking(move || drop(worker_owner))
            .await
            .unwrap();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealNcmRecallIdentity {
    stable_memory_ref: String,
    content_sha256: String,
    source_key: String,
    scope_sha256: String,
}

fn real_ncm_scope_wire(exact_scope: &OwnedExactScope) -> Value {
    json!({
        "profile_id": exact_scope.profile_id,
        "project_id": exact_scope.project_id,
        "repository_identity": exact_scope.repository_identity,
        "worktree_identity": exact_scope.worktree_identity,
        "branch_identity": exact_scope.branch_identity,
        "agent_session_id": exact_scope.agent_session_id,
        "resolved_scope_digest": exact_scope.resolved_scope_digest,
    })
}

fn real_ncm_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn real_ncm_payload_contract(operation: ProviderOperation) -> &'static str {
    match operation {
        ProviderOperation::Handshake => "tracedecay.memory.provider.handshake.v1",
        ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
        ProviderOperation::Observe => "tracedecay.memory.provider.observation.v1",
        ProviderOperation::Recall => "tracedecay.memory.provider.recall.v1",
        ProviderOperation::Feedback => "tracedecay.memory.provider.feedback.v1",
        ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
        ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
        ProviderOperation::Correction => "tracedecay.memory.provider.correction.v1",
        ProviderOperation::DeleteBySource => "tracedecay.memory.provider.deletion-by-source.v1",
        ProviderOperation::SnapshotExport => "tracedecay.memory.provider.snapshot-export.v1",
        ProviderOperation::SnapshotRestore => "tracedecay.memory.provider.snapshot-restore.v1",
        ProviderOperation::Replay => "tracedecay.memory.provider.replay.v1",
    }
}

fn real_ncm_payload(operation: ProviderOperation, value: Value) -> CanonicalPayload {
    let bytes = serde_json::to_vec(&value).expect("serialize real NCM payload");
    CanonicalPayload::new(
        OwnedVersionedId::new(real_ncm_payload_contract(operation)).expect("payload contract"),
        bytes.clone(),
        real_ncm_sha256(&bytes),
    )
    .expect("canonical real NCM payload")
}

fn real_ncm_observation(
    exact_scope: &OwnedExactScope,
    source_key: &str,
    source_session: &str,
    source_revision: &str,
    observation_id: &str,
    stable_record_id: &str,
    source_sequence: u64,
    text: &str,
) -> Value {
    assert_eq!(
        source_key,
        exact_scope.session_forget_source_key(source_session),
        "real NCM source aliases must be derived from the exact source session"
    );
    let mut canonical = json!({
        "version": 1,
        "provider": "codex",
        "native_record_kind": "session_message",
        "stable_record_id": stable_record_id,
        "relations": {
            "session_id": source_session,
            "project_id": exact_scope.project_id,
        },
        "facts": [{
            "kind": "message",
            "role": "assistant",
            "content": text,
        }],
    });
    canonical.sort_all_objects();
    let canonical_digest =
        real_ncm_sha256(&serde_json::to_vec(&canonical).expect("canonical bytes"));
    let original_source = json!({
        "source": {
            "canonical_provider_id": "codex",
            "canonical_session_id": source_session,
            "source_key": source_key,
            "stable_record_id": stable_record_id,
            "observation_id": observation_id,
            "source_revision": source_revision,
            "content_sha256": canonical_digest,
        },
        "origin_scope": {
            "state": "recorded",
            "authority_ref": "host.observation.real-ncm.v1",
            "exact_scope_identity": real_ncm_scope_wire(exact_scope),
        },
        "source_sequence": source_sequence,
        "occurred_at": "2025-01-02T12:00:00.123456789Z",
        "ingested_at": "2025-01-03T12:00:00Z",
        "validity": {
            "valid_from": "2025-01-02T12:00:00.123456789Z",
            "valid_until": null,
            "superseded_at": null,
            "superseded_by": null,
            "revoked_at": null,
        },
    });
    json!({
        "observation_kind": "session.message_committed.v1",
        "payload_contract": "tracedecay.memory.observation.session-message.v1",
        "source_identity": {"original_source": original_source},
        "canonical_payload": canonical,
    })
}

fn real_ncm_handshake(
    registry: &ProjectMemoryProviderRegistry,
    exact_scope: &OwnedExactScope,
    request_identity: &str,
) -> HandshakeResponse {
    let provider_id = OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id");
    let descriptor = registry
        .statuses()
        .expect("NCM status")
        .into_iter()
        .find(|status| status.provider_id == provider_id)
        .expect("selected NCM status")
        .descriptor;
    for attempt in 0..3 {
        let request = HandshakeRequest::new(HandshakeRequestParts {
            provider_id: provider_id.clone(),
            registration_revision: 1,
            exact_scope: exact_scope.clone(),
            request_id: format!("{request_identity}-handshake-{attempt}"),
            required_capabilities: descriptor.capabilities.iter().cloned().collect(),
            host_limits: descriptor.limits,
            control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
            challenge_nonce: [0x5a; 32],
        })
        .expect("real NCM handshake request");
        let response = registry
            .handshake(&request)
            .expect("NCM handshake dispatch");
        if response.terminal.terminal_code() != TerminalCode::StaleIdentity {
            return response;
        }
    }
    panic!("real NCM identity never converged after bounded handshake retries");
}

fn real_ncm_observe(
    registry: &ProjectMemoryProviderRegistry,
    exact_scope: &OwnedExactScope,
    idempotency_key: &str,
    observation: Value,
) -> ProviderReply {
    let ready = real_ncm_handshake(registry, exact_scope, idempotency_key);
    let receipt = ready.ready_receipt_sha256.expect("NCM ready receipt");
    let generation = ready
        .descriptor
        .expect("NCM ready descriptor")
        .state_generation;
    let request_id = format!(
        "real-ncm-observe-request-{}",
        REAL_NCM_NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let operation_id = format!(
        "real-ncm-observe-operation-{}",
        REAL_NCM_NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let payload = real_ncm_payload(ProviderOperation::Observe, observation);
    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Observe,
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
        registration_revision: 1,
        ready_receipt_sha256: receipt,
        exact_scope: exact_scope.clone(),
        request_id,
        operation_id,
        expected_state_generation: generation,
        idempotency_key: Some(idempotency_key.to_owned()),
        control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
        payload: payload.clone(),
        required_capabilities: vec![
            OwnedVersionedId::new("observation.accept.v1").expect("observe capability"),
        ],
        extensions: Vec::new(),
    })
    .expect("real NCM observation call");
    let sanitization =
        PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts::accepted_unmodified(
            REAL_NCM_SANITIZER_REVISION,
            payload.sha256.clone(),
        ))
        .expect("real NCM observation sanitization receipt");
    registry
        .invoke_active(&call.with_sanitization(sanitization))
        .expect("active NCM observation dispatch")
}

fn real_ncm_common_request(
    exact_scope: &OwnedExactScope,
    request_id: &str,
    operation_id: &str,
    generation: u64,
    idempotency_key: &str,
) -> Value {
    json!({
        "provider_id": NCM_PROVIDER_ID,
        "registration_revision": 1,
        "ready_receipt_digest": Value::Null,
        "exact_scope_identity": real_ncm_scope_wire(exact_scope),
        "operation_id": operation_id,
        "idempotency_key": idempotency_key,
        "expected_state_generation": generation,
        "request_identity": request_id,
        "policy_revision": 1,
        "deadline": {
            "deadline_utc_micros": i64::MAX,
            "remaining_millis": 10_000,
        },
        "cancellation": "live",
        "extensions": [],
    })
}

fn real_ncm_control(
    registry: &ProjectMemoryProviderRegistry,
    exact_scope: &OwnedExactScope,
    operation: ProviderOperation,
    idempotency_key: &str,
    mut value: Value,
) -> (u64, ProviderReply) {
    let ready = real_ncm_handshake(registry, exact_scope, idempotency_key);
    let receipt = ready.ready_receipt_sha256.expect("NCM ready receipt");
    let generation = ready
        .descriptor
        .expect("NCM ready descriptor")
        .state_generation;
    let request_id = format!(
        "real-ncm-control-request-{}",
        REAL_NCM_NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let operation_id = format!(
        "real-ncm-control-operation-{}",
        REAL_NCM_NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    value["common_request"] = real_ncm_common_request(
        exact_scope,
        &request_id,
        &operation_id,
        generation,
        idempotency_key,
    );
    value["common_request"]["ready_receipt_digest"] = json!(receipt);
    let call = ProviderCall::new(ProviderCallParts {
        operation,
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
        registration_revision: 1,
        ready_receipt_sha256: receipt,
        exact_scope: exact_scope.clone(),
        request_id,
        operation_id,
        expected_state_generation: generation,
        idempotency_key: Some(idempotency_key.to_owned()),
        control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
        payload: real_ncm_payload(operation, value),
        required_capabilities: vec![
            OwnedVersionedId::new(operation.capability_id()).expect("control capability"),
        ],
        extensions: Vec::new(),
    })
    .expect("real NCM control call");
    (
        generation,
        registry
            .invoke_control(&call)
            .expect("active NCM control dispatch"),
    )
}

fn real_ncm_recall(
    registry: &ProjectMemoryProviderRegistry,
    exact_scope: &OwnedExactScope,
    query: &str,
    request_identity: &str,
) -> (
    ProviderCall,
    ProviderReply,
    tracedecay_memory_provider_registry::AdmittedTemporalQuery,
) {
    let ready = real_ncm_handshake(registry, exact_scope, request_identity);
    let receipt = ready.ready_receipt_sha256.expect("NCM ready receipt");
    let descriptor = ready.descriptor.expect("NCM ready descriptor");
    let generation = descriptor.state_generation;
    let temporal =
        tracedecay_memory_provider_registry::AdmittedTemporalQuery::current("2025-02-01T00:00:00Z")
            .expect("real NCM temporal query");
    let payload =
        build_recall_request_payload(&tracedecay_memory_provider_registry::RecallRequestParts {
            provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
            registration_revision: 1,
            ready_receipt_sha256: receipt.clone(),
            exact_scope: exact_scope.clone(),
            request_id: request_identity.to_owned(),
            objective: "Retrieve the held-out production memory evidence".to_owned(),
            query: query.to_owned(),
            temporal: temporal.clone(),
            budgets: RecallBudgetsV1 {
                maximum_candidates: 4,
                maximum_candidate_content_bytes: 8192,
                maximum_total_content_bytes: 32768,
                maximum_source_refs_per_candidate: 4,
                maximum_trace_refs_per_candidate: 4,
                maximum_warnings: 4,
                maximum_extensions_per_candidate: 4,
            },
            policy_revision: 1,
            deadline_utc_micros: i64::MAX,
            remaining_millis: 10_000,
        })
        .expect("real NCM recall payload");
    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
        registration_revision: 1,
        ready_receipt_sha256: receipt,
        exact_scope: exact_scope.clone(),
        request_id: request_identity.to_owned(),
        operation_id: format!("real-ncm-recall-operation-{request_identity}"),
        expected_state_generation: generation,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
        payload,
        required_capabilities: vec![
            OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
        ],
        extensions: Vec::new(),
    })
    .expect("real NCM recall call");
    let reply = registry
        .invoke_active(&call)
        .expect("active NCM recall dispatch");
    (call, reply, temporal)
}

fn real_ncm_admitted_recall(
    call: &ProviderCall,
    reply: &ProviderReply,
    temporal: &tracedecay_memory_provider_registry::AdmittedTemporalQuery,
) -> tracedecay_memory_provider_registry::RecallOutcomeV1 {
    let outcome = decode_recall_outcome(reply.payload.as_ref().expect("NCM recall payload"))
        .expect("decode NCM recall outcome");
    let admitted = admit_recall_reply(
        call,
        temporal,
        4,
        &RecallScopeBindingsV1::new([ScopeBinding::CheckoutObservations]),
        reply,
    )
    .expect("admit NCM recall outcome");
    assert_eq!(admitted.report.admitted_count, outcome.candidates.len());
    assert!(admitted.report.denied.is_empty());
    outcome
}

fn real_ncm_identity(
    candidate: &tracedecay_memory_provider_registry::RecallCandidateV1,
) -> RealNcmRecallIdentity {
    RealNcmRecallIdentity {
        stable_memory_ref: candidate
            .stable_memory_ref
            .clone()
            .expect("stable NCM memory reference"),
        content_sha256: candidate.content_sha256.clone(),
        source_key: candidate.provenance["original_sources"][0]["source"]["source_key"]
            .as_str()
            .expect("original source key")
            .to_owned(),
        scope_sha256: candidate
            .exact_scope_identity
            .claimed_scope_sha256()
            .expect("candidate scope digest"),
    }
}

fn real_ncm_assert_top(
    outcome: &tracedecay_memory_provider_registry::RecallOutcomeV1,
    exact_scope: &OwnedExactScope,
    source_key: &str,
    text: &str,
) -> RealNcmRecallIdentity {
    let candidate = outcome.candidates.first().expect("NCM recall candidate");
    let expected_content = format!("assistant: {text}");
    assert_eq!(
        candidate.content.as_deref(),
        Some(expected_content.as_str())
    );
    assert_eq!(
        candidate.content_sha256,
        real_ncm_sha256(expected_content.as_bytes())
    );
    assert_eq!(
        candidate.exact_scope_identity.scope_binding,
        ScopeBinding::CheckoutObservations
    );
    assert_eq!(
        candidate.exact_scope_identity.project_id,
        exact_scope.project_id
    );
    assert_eq!(
        candidate.exact_scope_identity.repository_identity,
        exact_scope.repository_identity
    );
    assert_eq!(
        candidate.exact_scope_identity.worktree_identity,
        exact_scope.worktree_identity
    );
    assert_eq!(
        candidate.exact_scope_identity.branch_identity,
        exact_scope.branch_identity
    );
    // Checkout observations bind the checkout; the session and resolution
    // are per-delivery evidence the binding forbids a candidate to claim.
    assert!(candidate.exact_scope_identity.agent_session_id.is_empty());
    assert!(
        candidate
            .exact_scope_identity
            .resolved_scope_digest
            .is_empty()
    );
    assert_eq!(
        candidate.provenance["original_sources"][0]["source"]["source_key"],
        json!(source_key)
    );
    let identity = real_ncm_identity(candidate);
    assert_eq!(identity.scope_sha256, exact_scope.exact_scope_sha256());
    identity
}

fn real_ncm_assert_immutable_descriptor(
    actual: &tracedecay_memory_provider_registry::ProviderDescriptor,
    expected: &tracedecay_memory_provider_registry::ProviderDescriptor,
) {
    assert_eq!(&actual.provider_id, &expected.provider_id);
    assert_eq!(
        &actual.implementation_identity_sha256,
        &expected.implementation_identity_sha256
    );
    assert_eq!(&actual.state_schema_version, &expected.state_schema_version);
    assert_eq!(actual.protocol_major, expected.protocol_major);
    assert_eq!(actual.protocol_minor, expected.protocol_minor);
    assert_eq!(&actual.capabilities, &expected.capabilities);
    assert_eq!(actual.limits, expected.limits);
}

fn compose_real_ncm_with_native_observer(
    fixture: &NcmObserverFixture,
    port: Arc<JourneyObserverPort>,
) -> Arc<ProjectMemoryProviderComposition> {
    let ncm_registration = ProviderRegistrationV1 {
        provider_id: fixture.mount.provider_id.clone(),
        provider: fixture.observer.provider.clone(),
        registration_revision: fixture.mount.registration_revision,
        mode: EnabledProviderMode::Active,
        execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
        recall_scope_bindings: RecallScopeBindingsV1::from_wire(["checkout_observations"])
            .expect("NCM recall scope binding"),
        lifecycle: ProviderLifecycleOwnershipV1::CompositionBound,
    };
    Arc::new(
        ProjectMemoryProviderComposition::compose_selected(
            SelectedProviderActivationV1::Injected {
                fabric_config: FabricConfig {
                    max_registered_providers: 2,
                    max_in_flight: 1,
                },
                registration: ncm_registration,
            },
            vec![ObserverProviderRegistration {
                provider: port,
                registration_revision: 1,
            }],
        )
        .expect("active NCM plus Native observer composition"),
    )
}

/// The production replacement acceptance crosses the real observation mount,
/// active-provider selection, durable paged control, restart, scope binding,
/// and privacy deletion fence in one fresh mutable worker root. Immutable model
/// artifacts are shared through a symlink and are never used as state.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
async fn real_ncm_replacement_acceptance_preserves_identity_recall_and_deletion_fence() {
    let worker = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real production worker fixture"),
    );
    let installed = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT").expect("real production model root"),
    );
    assert!(
        worker.is_absolute(),
        "TRACEDECAY_NCM_WORKER must be absolute"
    );
    assert!(
        installed.is_absolute(),
        "TRACEDECAY_NCM_REAL_MODEL_ROOT must be absolute"
    );
    assert!(
        worker.is_file(),
        "TRACEDECAY_NCM_WORKER must name an existing executable"
    );
    let worker = std::fs::canonicalize(worker).expect("canonical production worker");
    let model_dir = std::fs::canonicalize(installed.join("models"))
        .expect("canonical installed immutable model directory");
    assert!(model_dir.is_dir(), "installed model directory must exist");

    let temp = TempDir::new().expect("fresh mutable NCM acceptance root");
    let mutable_root = temp.path().join("ncm-state");
    std::fs::create_dir_all(&mutable_root).expect("create mutable NCM state root");
    std::os::unix::fs::symlink(&model_dir, mutable_root.join("models"))
        .expect("share immutable model directory through a symlink");
    assert_ne!(
        std::fs::canonicalize(&mutable_root).expect("canonical mutable root"),
        model_dir,
        "mutable state root must remain separate from immutable model artifacts"
    );

    let project_id = ProjectId::new("project.real-ncm-replacement").expect("project id");
    let profile_id = UserProfileId::new("profile.real-ncm-replacement").expect("profile id");
    let resolved_scope = scope(project_id.clone());
    let exact_scope =
        exact_scope_for_session(&profile_id, &resolved_scope, "real-ncm-target-session")
            .expect("target exact coding scope");
    let foreign_resolved_scope =
        scope(ProjectId::new("project.real-ncm-replacement-foreign").expect("foreign project id"));
    let foreign_scope = exact_scope_for_session(
        &profile_id,
        &foreign_resolved_scope,
        "real-ncm-foreign-session",
    )
    .expect("foreign exact coding scope");
    let foreign_source = foreign_scope.session_forget_source_key("real-ncm-foreign-source-session");

    let runtime = HostAdmissionTestRuntimeV1::project(
        &temp.path().join("profile"),
        &temp.path().join("project"),
        project_id.clone(),
    )
    .await
    .expect("host admission runtime");
    let store = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .expect("registered project database")
        .observation_store();
    let journal_root = temp.path().join("journey");
    std::fs::create_dir_all(&journal_root).expect("journey journal root");
    let port = Arc::new(JourneyObserverPort::new());
    let native_metadata =
        fixture_observer_mount(&journal_root, 1).expect("Native mount");
    let session_id = SessionId::new("session.real-ncm-control-source").expect("session id");
    let cancellation = HostCancellationToken::new();
    let inputs = |composition, provider| ObservationJourneyMountInputsV1 {
        composition,
        profile_id: profile_id.clone(),
        scope: resolved_scope.clone(),
        authoritative_project_id: project_id.clone(),
        store_data_root: journal_root.clone(),
        provider,
        policy: ObservationJourneyPolicyV1::project_default(),
    };

    // Seed a real record in a different exact namespace before the main
    // composition starts. A separate surface keeps the registry's monotonic
    // generation fence from confusing two namespaces while still exercising
    // cross-scope exclusion against durable foreign data.
    let foreign_fixture = tokio::task::spawn_blocking({
        let worker = worker.clone();
        let mutable_root = mutable_root.clone();
        move || construct_ncm_observer(worker, mutable_root, 1)
    })
    .await
    .expect("construct foreign-scope NCM fixture")
    .expect("construct foreign-scope NCM surface");
    let foreign_owner = foreign_fixture.worker_owner.clone();
    let foreign_composition =
        compose_real_ncm_with_native_observer(&foreign_fixture, Arc::new(JourneyObserverPort::new()));
    drop(foreign_fixture);
    let foreign_registry = foreign_composition
        .registry()
        .expect("foreign-scope registry");
    let foreign_observed = real_ncm_observe(
        foreign_registry,
        &foreign_scope,
        "real-ncm-foreign-delivery",
        real_ncm_observation(
            &foreign_scope,
            &foreign_source,
            "real-ncm-foreign-source-session",
            "real-ncm-foreign-r1",
            "real-ncm-foreign-observation",
            "real-ncm-foreign-record",
            1,
            "The signed artifact manifest is required before compiler cache entries are published.",
        ),
    );
    assert_eq!(
        foreign_observed.terminal.terminal_code(),
        TerminalCode::Success
    );
    let foreign_stop = foreign_owner
        .request_stop(std::time::Instant::now() + Duration::from_secs(5))
        .expect("stop foreign-scope worker");
    assert!(foreign_stop);
    drop(foreign_composition);
    drop(foreign_owner);

    let fixture = tokio::task::spawn_blocking({
        let worker = worker.clone();
        let mutable_root = mutable_root.clone();
        move || construct_ncm_observer(worker, mutable_root, 1)
    })
    .await
    .expect("construct production NCM fixture")
    .expect("construct production NCM surface");
    let ncm_metadata = fixture.mount.clone();
    let ncm_provider = fixture.observer.provider.clone();
    let worker_owner = fixture.worker_owner.clone();
    let declared_descriptor = ncm_provider.descriptor();
    assert!(
        worker_owner.worker_pid().is_none(),
        "production declaration is lazy"
    );
    assert!(
        declared_descriptor
            .state_schema_version
            .starts_with("ncm-biomem-rs.v1+")
    );
    assert_ne!(
        declared_descriptor.implementation_identity_sha256,
        "0".repeat(64),
        "production descriptor must carry the model-bound implementation identity"
    );
    let composition = compose_real_ncm_with_native_observer(&fixture, port.clone());
    drop(fixture);
    let registry = composition
        .registry()
        .expect("enabled provider composition");
    let ncm_id = OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id");
    let native_id = OwnedProviderId::new(FIXTURE_OBSERVER_ID).expect("fixture observer id");
    assert_eq!(
        registry
            .selected_registration()
            .expect("selected registration")
            .provider_id,
        ncm_id
    );
    assert_eq!(
        registry
            .selected_registration()
            .expect("selected registration")
            .mode,
        EnabledProviderMode::Active
    );
    assert_eq!(
        registry
            .registration(&native_id)
            .expect("Native observer registration")
            .mode,
        EnabledProviderMode::Observer
    );

    let handshake = real_ncm_handshake(registry, &exact_scope, "real-ncm-production-identity");
    assert_eq!(handshake.terminal.terminal_code(), TerminalCode::Success);
    assert_eq!(handshake.descriptor.as_ref(), Some(&declared_descriptor));
    assert_eq!(
        handshake.provider_instance_id.as_deref(),
        Some(declared_descriptor.state_schema_version.as_str()),
        "the handshake instance identity must be the production algorithm identity"
    );
    assert_eq!(handshake.accepted_scope.as_ref(), Some(&exact_scope));
    assert_eq!(handshake.effective_limits, Some(declared_descriptor.limits));
    assert!(handshake.ready_receipt_sha256.is_some());
    let first_worker_pid = worker_owner
        .worker_pid()
        .expect("worker starts at handshake");

    let native_journal = {
        let native = mount_and_replay(
            inputs(composition.clone(), native_metadata.clone()),
            store.clone(),
            &cancellation,
        )
        .await
        .expect("Native observer journey mount");
        let ncm = mount_and_replay(
            inputs(composition.clone(), ncm_metadata.clone()),
            store.clone(),
            &cancellation,
        )
        .await
        .expect("active NCM journey mount");
        assert_ne!(native.journal_path(), ncm.journal_path());
        persist_position(
            &store,
            &project_id,
            &session_id,
            "The control source remains available after the NCM replacement.",
            0,
        )
        .await;
        wait_for_all_ncm_settlements(&native, 1).await;
        wait_for_all_ncm_settlements(&ncm, 1).await;
        assert_eq!(port.observe_calls.load(Ordering::Relaxed), 1);
        let native_journal = native.journal_path().to_path_buf();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        assert!(native.shutdown(deadline).await.is_empty());
        assert!(ncm.shutdown(deadline).await.is_empty());
        drop(native);
        drop(ncm);
        native_journal
    };

    let target_session = "real-ncm-target-source-session";
    let distractor_session = "real-ncm-distractor-source-session";
    let target_source = exact_scope.session_forget_source_key(target_session);
    let distractor_source = exact_scope.session_forget_source_key(distractor_session);
    let target_text =
        "The signed artifact manifest is required before compiler cache entries are published.";
    let distractor_text =
        "The cleanup worker deletes temporary object files after failed compiler runs.";
    let target_observation = real_ncm_observation(
        &exact_scope,
        &target_source,
        target_session,
        "real-ncm-target-r1",
        "real-ncm-target-observation",
        "real-ncm-target-record",
        1,
        target_text,
    );
    let distractor_observation = real_ncm_observation(
        &exact_scope,
        &distractor_source,
        distractor_session,
        "real-ncm-distractor-r1",
        "real-ncm-distractor-observation",
        "real-ncm-distractor-record",
        2,
        distractor_text,
    );
    let target_observed = real_ncm_observe(
        registry,
        &exact_scope,
        "real-ncm-target-delivery",
        target_observation,
    );
    assert_eq!(
        target_observed.terminal.terminal_code(),
        TerminalCode::Success
    );
    // Publication is immediately queryable through the routed production
    // surface. A transient empty success here would hide an index/replay
    // race from callers that ask right after accepting an observation.
    let (published_call, published_reply, published_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        "Which signed manifest must be present before cached compiler artifacts are released?",
        "real-ncm-immediate-after-publication",
    );
    assert_eq!(
        published_reply.terminal.terminal_code(),
        TerminalCode::Success,
        "immediate post-publication recall must be a populated success"
    );
    assert_ne!(
        published_reply.terminal.terminal_code(),
        TerminalCode::SuccessZeroResults
    );
    let published_outcome =
        real_ncm_admitted_recall(&published_call, &published_reply, &published_temporal);
    real_ncm_assert_top(
        &published_outcome,
        &exact_scope,
        &target_source,
        target_text,
    );
    let distractor_observed = real_ncm_observe(
        registry,
        &exact_scope,
        "real-ncm-distractor-delivery",
        distractor_observation,
    );
    assert_eq!(
        distractor_observed.terminal.terminal_code(),
        TerminalCode::Success
    );
    let mut maintenance_cursor = None;
    let mut maintenance_pages = 0_u64;
    let maintenance_final_generation;
    loop {
        let mut request = json!({
            "task": "consolidate",
            "maximum_items": 1,
            "maximum_bytes": 65536,
            "maximum_duration_millis": 1000,
            "dry_run": false,
        });
        if let Some(cursor) = maintenance_cursor.clone() {
            request["resume_cursor"] = json!(cursor);
        }
        let idempotency_key = format!("real-ncm-maintenance-page-{maintenance_pages}");
        let (generation, reply) = real_ncm_control(
            registry,
            &exact_scope,
            ProviderOperation::Maintenance,
            &idempotency_key,
            request,
        );
        let output = serde_json::from_slice::<Value>(
            &reply.payload.as_ref().expect("maintenance payload").bytes,
        )
        .expect("maintenance output JSON");
        assert_eq!(output["task"], "consolidate");
        assert_eq!(output["state_generation_before"].as_u64(), Some(generation));
        if output["partial"] == true {
            assert_eq!(output["state_generation_after"].as_u64(), Some(generation));
            maintenance_cursor = output["resume_cursor"].as_str().map(str::to_owned);
            assert!(
                maintenance_cursor.is_some(),
                "partial maintenance must page"
            );
            maintenance_pages += 1;
        } else {
            assert!(
                maintenance_pages >= 1,
                "maintenance must cross a page boundary"
            );
            maintenance_final_generation = output["state_generation_after"]
                .as_u64()
                .expect("final maintenance generation");
            assert_eq!(maintenance_final_generation, generation + 1);
            assert!(output["resume_cursor"].is_null());
            break;
        }
    }
    assert!(maintenance_final_generation > 0);

    let held_out_query =
        "Which signed manifest must be present before cached compiler artifacts are released?";
    let (pre_call, pre_reply, pre_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        held_out_query,
        "real-ncm-held-out-paraphrase",
    );
    assert_eq!(pre_reply.terminal.terminal_code(), TerminalCode::Success);
    let pre_outcome = real_ncm_admitted_recall(&pre_call, &pre_reply, &pre_temporal);
    let pre_identity = real_ncm_assert_top(&pre_outcome, &exact_scope, &target_source, target_text);
    assert!(
        pre_outcome.candidates.iter().all(|candidate| {
            candidate.provenance["original_sources"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|source| source["source"]["source_key"] != json!(&foreign_source))
        }),
        "exact-scope recall must exclude the foreign namespace"
    );

    let first_stop = worker_owner
        .request_stop(std::time::Instant::now() + Duration::from_secs(5))
        .expect("stop first production worker");
    assert!(first_stop);
    assert!(worker_owner.worker_pid().is_none());
    drop(composition);
    drop(ncm_provider);
    drop(ncm_metadata);
    drop(native_metadata);
    drop(worker_owner);

    let fixture = tokio::task::spawn_blocking({
        let worker = worker.clone();
        let mutable_root = mutable_root.clone();
        move || construct_ncm_observer(worker, mutable_root, 1)
    })
    .await
    .expect("construct replacement NCM fixture")
    .expect("construct replacement NCM surface");
    let ncm_metadata = fixture.mount.clone();
    let ncm_provider = fixture.observer.provider.clone();
    let worker_owner = fixture.worker_owner.clone();
    let composition = compose_real_ncm_with_native_observer(&fixture, port.clone());
    drop(fixture);
    let registry = composition.registry().expect("replacement registry");
    // Route the first recall directly through the fresh surface. The
    // persisted generation may make its internal readiness refresh stale once;
    // callers must never see that one-shot handshake terminal or an empty
    // success in its place.
    let (post_call, post_reply, post_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        held_out_query,
        "real-ncm-held-out-paraphrase",
    );
    assert_eq!(post_reply.terminal.terminal_code(), TerminalCode::Success);
    let post_outcome = real_ncm_admitted_recall(&post_call, &post_reply, &post_temporal);
    let post_identity =
        real_ncm_assert_top(&post_outcome, &exact_scope, &target_source, target_text);
    assert_eq!(
        post_identity, pre_identity,
        "recall identity must survive restart"
    );
    let second_worker_pid = worker_owner.worker_pid().expect("replacement worker pid");
    assert_ne!(
        first_worker_pid, second_worker_pid,
        "replacement must use a new worker process instance"
    );
    let post_handshake = real_ncm_handshake(registry, &exact_scope, "real-ncm-post-restart");
    assert_eq!(
        post_handshake.terminal.terminal_code(),
        TerminalCode::Success
    );
    let post_descriptor = post_handshake
        .descriptor
        .as_ref()
        .expect("replacement descriptor");
    real_ncm_assert_immutable_descriptor(post_descriptor, &declared_descriptor);
    assert_eq!(
        post_descriptor.state_generation, maintenance_final_generation,
        "replacement handshake must recover the persisted maintenance generation"
    );

    let (delete_generation, delete_reply) = real_ncm_control(
        registry,
        &exact_scope,
        ProviderOperation::DeleteBySource,
        "real-ncm-delete-target",
        json!({
            "forget_source_keys": [&target_source],
            "mode": "hard_delete",
            "include_snapshots": true,
            "retention_lock_policy_revision": 1,
            "verification_query": held_out_query,
        }),
    );
    assert_eq!(delete_reply.terminal.terminal_code(), TerminalCode::Success);
    let delete_output = serde_json::from_slice::<Value>(
        &delete_reply
            .payload
            .as_ref()
            .expect("deletion payload")
            .bytes,
    )
    .expect("deletion output JSON");
    assert_eq!(
        delete_output["postcondition"]["verification_state"],
        "verified_absent"
    );
    assert!(
        delete_output["postcondition"]["removed_effects"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(delete_reply.state_generation > delete_generation);

    let (deleted_call, deleted_reply, deleted_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        held_out_query,
        "real-ncm-after-delete",
    );
    let deleted_outcome =
        real_ncm_admitted_recall(&deleted_call, &deleted_reply, &deleted_temporal);
    assert!(deleted_outcome.candidates.iter().all(|candidate| {
        candidate.stable_memory_ref.as_deref() != Some(pre_identity.stable_memory_ref.as_str())
            && candidate.provenance["original_sources"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|source| source["source"]["source_key"] != json!(&target_source))
    }));
    let distractor_query = "Which temporary compiler files are removed after a failed build?";
    let (distractor_call, distractor_reply, distractor_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        distractor_query,
        "real-ncm-distractor-survival",
    );
    let distractor_outcome =
        real_ncm_admitted_recall(&distractor_call, &distractor_reply, &distractor_temporal);
    let distractor_identity = real_ncm_assert_top(
        &distractor_outcome,
        &exact_scope,
        &distractor_source,
        distractor_text,
    );
    assert_ne!(distractor_identity.source_key, pre_identity.source_key);

    let native_connection = rusqlite::Connection::open(&native_journal).expect("Native journal");
    let (native_count, native_state): (i64, String) = native_connection
        .query_row(
            "SELECT COUNT(*), MIN(committed_effect) FROM tdmem_observation_receipt_v1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Native control source row");
    assert_eq!((native_count, native_state.as_str()), (1, "applied"));

    let second_stop = worker_owner
        .request_stop(std::time::Instant::now() + Duration::from_secs(5))
        .expect("stop second production worker");
    assert!(second_stop);
    assert!(worker_owner.worker_pid().is_none());
    drop(composition);
    drop(ncm_provider);
    drop(ncm_metadata);
    drop(worker_owner);

    let fixture = tokio::task::spawn_blocking({
        let worker = worker.clone();
        let mutable_root = mutable_root.clone();
        move || construct_ncm_observer(worker, mutable_root, 1)
    })
    .await
    .expect("construct post-deletion NCM fixture")
    .expect("construct post-deletion NCM surface");
    let ncm_provider = fixture.observer.provider.clone();
    let worker_owner = fixture.worker_owner.clone();
    let composition = compose_real_ncm_with_native_observer(&fixture, port);
    drop(fixture);
    let registry = composition.registry().expect("post-deletion registry");
    let final_handshake = real_ncm_handshake(registry, &exact_scope, "real-ncm-post-delete");
    assert_eq!(
        final_handshake.terminal.terminal_code(),
        TerminalCode::Success
    );
    let final_descriptor = final_handshake
        .descriptor
        .as_ref()
        .expect("post-deletion descriptor");
    real_ncm_assert_immutable_descriptor(final_descriptor, &declared_descriptor);
    assert_eq!(
        final_descriptor.state_generation, delete_reply.state_generation,
        "post-deletion handshake must recover the deletion generation"
    );
    let third_worker_pid = worker_owner.worker_pid().expect("post-deletion worker pid");
    assert_ne!(second_worker_pid, third_worker_pid);
    let (final_call, final_reply, final_temporal) = real_ncm_recall(
        registry,
        &exact_scope,
        held_out_query,
        "real-ncm-after-delete-restart",
    );
    let final_outcome = real_ncm_admitted_recall(&final_call, &final_reply, &final_temporal);
    assert!(final_outcome.candidates.iter().all(|candidate| {
        candidate.stable_memory_ref.as_deref() != Some(pre_identity.stable_memory_ref.as_str())
            && candidate.provenance["original_sources"]
                .as_array()
                .into_iter()
                .flatten()
                .all(|source| source["source"]["source_key"] != json!(&target_source))
    }));
    let third_stop = worker_owner
        .request_stop(std::time::Instant::now() + Duration::from_secs(5))
        .expect("stop post-deletion production worker");
    assert!(third_stop);
    assert!(worker_owner.worker_pid().is_none());
    drop(composition);
    drop(ncm_provider);
    drop(worker_owner);
}

/// Append at the canonical source frontier without bypassing the store's cursor CAS.
#[cfg(unix)]
async fn persist_position(
    store: &impl ObservationStore,
    project_id: &ProjectId,
    session_id: &SessionId,
    text: &str,
    position: u64,
) {
    let anchored = anchored_write(canonical_observation_at(
        project_id, session_id, text, position,
    ));
    let observation = anchored.observation();
    let expected_cursor = store
        .get_source_cursor(observation.source(), observation.scope())
        .await
        .expect("read the canonical source cursor");
    assert_eq!(
        expected_cursor
            .as_ref()
            .map(ObservationSourceCursorV1::position),
        (position > 0).then_some(position),
        "each append starts at the preceding commit's source frontier",
    );
    let write = ObservationWrite::new(
        observation.clone(),
        expected_cursor,
        anchored.next_cursor().clone(),
    )
    .expect("observation covers the expected-to-next cursor transition");
    let write = AnchoredObservationWrite::new(
        write,
        anchored.retrieval_anchor().clone(),
        anchored.projection_generation().clone(),
    )
    .expect("retain the canonical retrieval anchor");
    store
        .persist_observation(write)
        .await
        .expect("append canonical observation");
}

/// Require every expected row and its own receipt, including commits appended
/// after restart. Looking at the first acknowledged row would miss a stuck tail.
#[cfg(unix)]
async fn wait_for_all_ncm_settlements(journey: &ProjectObservationJourneyV1, expected: usize) {
    // Live replay's existing error backoff is five seconds, so a recovered
    // handshake needs a budget longer than one such pass.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let page = journey
            .journal
            .inspect(&JournalInspectionFilterV1 {
                limit: 8,
                ..JournalInspectionFilterV1::default()
            })
            .unwrap();
        let all_settled = page.rows.len() == expected
            && page.next_cursor.is_none()
            && page.rows.iter().all(|row| {
                row.state.as_wire() == "acknowledged"
                    && journey
                        .journal
                        .receipts_for(&row.observation_id)
                        .unwrap()
                        .len()
                        == 1
            });
        if all_settled && journey.stalled_on().is_none() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected {expected} acknowledged rows with receipts and no standing stall: {}",
            ncm_delivery_diagnostics(&journey.journal)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(unix)]
fn assert_observer_has_no_active_output(
    composition: &ProjectMemoryProviderComposition,
    provider: &ObservationProviderMountV1,
    profile_id: &UserProfileId,
    scope: &ResolvedScope,
    session: &str,
) {
    let bytes = b"{}".to_vec();
    let call = ProviderCall::new(ProviderCallParts {
        operation: ProviderOperation::Recall,
        provider_id: provider.provider_id.clone(),
        registration_revision: provider.registration_revision,
        ready_receipt_sha256: "0".repeat(64),
        exact_scope: exact_scope_for_session(profile_id, scope, session).unwrap(),
        request_id: "observer-recall-denied".to_owned(),
        operation_id: "observer-recall-denied".to_owned(),
        expected_state_generation: 0,
        idempotency_key: None,
        control: OperationControl::new(i64::MAX, 1000, CancellationToken::new()),
        payload: CanonicalPayload::new(
            OwnedVersionedId::new("tracedecay.memory.provider.recall.v1").unwrap(),
            bytes.clone(),
            hex::encode(Sha256::digest(&bytes)),
        )
        .unwrap(),
        required_capabilities: vec![OwnedVersionedId::new("recall.query.v1").unwrap()],
        extensions: Vec::new(),
    })
    .unwrap();
    assert!(
        matches!(composition.registry().unwrap().invoke_active(&call),
        Err(FabricError::ProviderObserverOnly(id)) if id == provider.provider_id.as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_ncm_observer_preserves_native_canonical_acknowledgement() {
    let temp = TempDir::new().unwrap();
    let project_id = ProjectId::new("project.unavailable-ncm-observer").unwrap();
    let runtime = HostAdmissionTestRuntimeV1::project(
        &temp.path().join("profile"),
        &temp.path().join("project"),
        project_id.clone(),
    )
    .await
    .unwrap();
    let store = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .unwrap()
        .observation_store();
    let root = temp.path().join("journey");
    std::fs::create_dir_all(&root).unwrap();
    let worker = temp.path().join("absent-worker");
    let state_root = temp.path().join("ncm");
    let fixture =
        tokio::task::spawn_blocking(move || construct_ncm_observer(worker, state_root, 1))
            .await
            .unwrap()
            .unwrap();
    let NcmObserverFixture {
        observer,
        mount: metadata,
        worker_owner,
    } = fixture;
    assert!(metadata.provider_instance_id.is_none());
    let port = Arc::new(JourneyObserverPort::new());
    let composition = Arc::new(
        ProjectMemoryProviderComposition::compose_selected(
            SelectedProviderActivationV1::ObserversOnly {
                fabric_config: FabricConfig {
                    max_registered_providers: 2,
                    max_in_flight: 1,
                },
            },
            vec![
                ObserverProviderRegistration {
                    provider: port.clone(),
                    registration_revision: 1,
                },
                observer,
            ],
        )
        .unwrap(),
    );
    let inputs = |provider| ObservationJourneyMountInputsV1 {
        composition: composition.clone(),
        profile_id: UserProfileId::new("profile.unavailable-ncm-observer").unwrap(),
        scope: scope(project_id.clone()),
        authoritative_project_id: project_id.clone(),
        store_data_root: root.clone(),
        provider,
        policy: ObservationJourneyPolicyV1::project_default(),
    };
    let native = mount_project_observation_journey(inputs(
        fixture_observer_mount(&root, 1).unwrap(),
    ))
    .unwrap();
    let ncm = mount_project_observation_journey(inputs(metadata)).unwrap();
    let session = SessionId::new("session.unavailable-ncm-observer").unwrap();
    store
        .persist_observation(anchored_write(canonical_observation(
            &project_id,
            &session,
            "Native still acknowledges this commit.",
        )))
        .await
        .unwrap();
    let cancellation = HostCancellationToken::new();
    let refused = run_startup_replay(&ncm, &store, &cancellation)
        .await
        .expect_err("unavailable worker must refuse readiness before admission");
    let ObservationJourneyError::Ingress(ObservationRuntimeError::Admission { cause, .. }) =
        refused
    else {
        panic!("unavailable observer must fail at the typed admission boundary");
    };
    let Some(AdmissionAdapterError::Readiness {
        source:
            ObservationJourneyError::SupervisedReadiness(SupervisedReadinessError::Unavailable {
                kind,
                terminal_code,
                detail,
                ..
            }),
        ..
    }) = cause.cause().downcast_ref::<AdmissionAdapterError>()
    else {
        panic!("admission must retain the supervised readiness refusal");
    };
    assert_eq!(
        *kind,
        tracedecay_memory_provider_registry::DegradationKindV1::HandshakeRefused
    );
    assert_eq!(*terminal_code, Some(TerminalCode::ProviderUnavailable));
    assert_eq!(
        detail,
        &format!(
            "provider handshake terminated with {}",
            TerminalCode::ProviderUnavailable.as_wire()
        )
    );
    assert_eq!(
        run_startup_replay(&native, &store, &cancellation)
            .await
            .unwrap()
            .admitted,
        1
    );
    assert_eq!(
        wait_for_settlement(native.journal_path()).await.0,
        "acknowledged"
    );
    assert_eq!(port.observe_calls.load(Ordering::Relaxed), 1);
    let connection = rusqlite::Connection::open(ncm.journal_path()).unwrap();
    let receipts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tdmem_observation_receipt_v1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        receipts, 0,
        "unavailable observer cannot claim successful delivery"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    for journey in [&native, &ncm] {
        assert!(journey.shutdown(deadline).await.is_empty());
    }
    drop(ncm);
    drop(native);
    drop(composition);
    drop(worker_owner);
}

/// Bounded, content-free delivery evidence for a failed real-worker assertion.
/// Receipts expose outcomes/effects; refused terminals also retain their code.
#[cfg(unix)]
fn ncm_delivery_diagnostics(journal: &SqliteObservationJournal) -> serde_json::Value {
    let page = journal
        .inspect(&JournalInspectionFilterV1 {
            limit: 8,
            ..JournalInspectionFilterV1::default()
        })
        .expect("inspect NCM delivery metadata");
    let rows = page.rows.iter().map(|row| {
        let receipts = journal.receipts_for(&row.observation_id).expect("inspect NCM receipts");
        let refusals = journal.attempt_refusals_for(&row.observation_id).expect("inspect NCM terminal refusals");
        json!({
            "state": row.state.as_wire(),
            "attempt": row.attempt_number,
            "source_sequence": row.source_sequence.0,
            "receipts": receipts.iter().map(|receipt| json!({
                "attempt": receipt.attempt_number,
                "outcome": receipt.outcome.as_wire(),
                "committed_effect": receipt.committed_effect.as_wire(),
                "provider_receipt_present": receipt.provider_receipt_digest.is_some(),
            })).collect::<Vec<_>>(),
            "refused_terminal_codes": refusals.iter().map(|refusal|
                TerminalCode::from_wire(&refusal.terminal_code).map(TerminalCode::as_wire).unwrap_or("unrecognized")
            ).collect::<Vec<_>>(),
        })
    }).collect::<Vec<_>>();
    json!({ "total_rows": page.total_rows, "page_truncated": page.next_cursor.is_some(), "rows": rows })
}
