//! Real NCM delivery, provider-local durability, and shared checkout recall.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tempfile::TempDir;
use tracedecay_contracts::ResolvedScope;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationFactV1, CanonicalUnknownStateV1,
    DurableObservationV1, ObservationSourceCursorV1, ProjectId, SessionId, UserProfileId,
};
use tracedecay_host_admission::{HostAdmissionAuthorities, HostAdmissionFacade};
use tracedecay_memory_hygiene::{
    ObservationAdmission, ObservationSanitizer, canonical_payload_bytes,
};
use tracedecay_memory_ncm_runtime::embedding::{
    MANIFEST_FILENAME, MODEL_ACQUISITION_RECEIPT_PATH, ModelAcquisitionManifest, install,
};
use tracedecay_memory_ncm_runtime::ports::Deadline;
use tracedecay_memory_observation::{
    DeliveryStateV1, JournalInspectionFilterV1, LeaseRequestV1, ObservationJournalReaderV1,
    ObservationRuntimeError, SqliteObservationJournal,
};
use tracedecay_memory_provider_ncm::{
    NCM_PROVIDER_ID, NcmCognitiveSurface, NcmNamespace, NcmNamespaceBinding, NcmProviderAdapter,
    RustNcmConfig, RustNcmSurface, RustNcmWorkerOwner, StateRoot, WorkerOptions,
};
use tracedecay_memory_provider_registry::{
    CancellationToken, DegradationKindV1, EnabledProviderMode, FabricConfig, HandshakeRequest,
    HandshakeRequestParts, HandshakeResponse, ObservationInstanceProofV1,
    ObservationProviderMountV1, ObservationStateNamespacePolicyV1, ObserverProviderRegistration,
    OperationControl, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
    PayloadSanitizationReceipt, ProjectMemoryProviderComposition, ProjectMemoryProviderRegistry,
    ProviderCall, ProviderCallParts, ProviderExecutionShapeV1, ProviderLifecycleOwnershipV1,
    ProviderOperation, ProviderRegistrationV1, ProviderReply, RecallBudgetsV1, RecallOutcomeV1,
    RecallScopeBindingsV1, ScopeBinding, SelectedProviderActivationV1, SupervisedReadinessError,
    TerminalCode, UnknownValidityPolicy, WithheldReason, admit_recall_reply,
    build_recall_request_payload, decode_recall_outcome,
};
use tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1;
use tracedecay_runtime_core::cancellation::CancellationToken as HostCancellationToken;
use tracedecay_sessions::admission::HostAdmissionScope;
use tracedecay_sessions::runtime::hosts::codex::try_admit_codex_jsonl_observations_for_project_with_admission;
use tracedecay_store::{
    AnchoredObservationWrite, ObservationReplayRequest, ObservationStore, ObservationWrite,
    StoredObservation,
};

use crate::retained_owner::NcmLifecycleOwner;

use super::super::{
    AdmissionAdapterError, CanonicalMessageEligibilityV1, ObservationJourneyError,
    ObservationJourneyMountInputsV1, ObservationJourneyPolicyV1, ProjectObservationJourneyV1,
    REQUIRED_ACTIVATION_BUDGET, SESSION_MESSAGE_OBSERVATION_KIND, SESSION_MESSAGE_PAYLOAD_CONTRACT,
    activate_required_with_instance_ready, canonical_message_eligibility, exact_scope_for_session,
    mount_and_replay, mount_observer_dormant, provider_observation_envelope, run_startup_replay,
};
use super::{
    anchored_write, canonical_observation_at, canonical_observation_with_payload_at, scope,
};

const NCM_NAMESPACE_BINDING: NcmNamespaceBinding = NcmNamespaceBinding::CheckoutObservationsV1;

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
    let admitted_state_root = StateRoot::new(state_root)?;
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
            .map_err(|error| error.to_string())?
            .with_namespace_binding(NCM_NAMESPACE_BINDING),
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

fn compose_real_ncm(fixture: &NcmObserverFixture) -> Arc<ProjectMemoryProviderComposition> {
    Arc::new(
        ProjectMemoryProviderComposition::compose_registered(
            SelectedProviderActivationV1::Injected {
                fabric_config: FabricConfig {
                    max_registered_providers: 1,
                    max_in_flight: 1,
                },
                registration: ProviderRegistrationV1 {
                    provider_id: fixture.mount.provider_id.clone(),
                    provider: Arc::clone(&fixture.observer.provider),
                    registration_revision: fixture.mount.registration_revision,
                    mode: EnabledProviderMode::Active,
                    execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                    recall_scope_bindings: RecallScopeBindingsV1::from_wire(
                        NCM_NAMESPACE_BINDING
                            .recall_scope_bindings()
                            .iter()
                            .copied(),
                    )
                    .expect("NCM recall bindings"),
                    lifecycle: ProviderLifecycleOwnershipV1::Owned(Arc::new(
                        NcmLifecycleOwner::new(Arc::clone(&fixture.worker_owner)),
                    )),
                },
            },
            Vec::new(),
        )
        .expect("NCM-only active provider composition"),
    )
}

/// Every mutable store is isolated. The pinned model is adopted into the owned
/// temporary root, with the acquisition authority creating its own receipt.
/// Recall here verifies provider-local retained content and identity. The host's
/// owning-store hydration is exercised by the separate production journey.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TRACEDECAY_NCM_PRODUCTION_WORKER and external TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
async fn real_ncm_checkout_recall_survives_remount_without_duplicate_delivery() {
    let worker = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_PRODUCTION_WORKER")
            .expect("real production worker fixture"),
    );
    let installed = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT").expect("installed model fixture"),
    );
    assert!(worker.is_absolute() && installed.is_absolute());
    let worker = std::fs::canonicalize(worker).expect("canonical production worker");
    assert!(worker.is_file());
    let installed = std::fs::canonicalize(installed).expect("external installed model root");
    let models = std::fs::canonicalize(installed.join("models"))
        .expect("canonical installed immutable model directory");
    assert!(models.is_dir());
    let temporary_root = PathBuf::from(
        std::env::var_os("TEST_TMPDIR").expect("Bazel-owned external test temporary root"),
    );
    let temporary = TempDir::new_in(temporary_root).expect("isolated external NCM journey root");
    let state_root = temporary.path().join("ncm");
    std::fs::create_dir_all(&state_root).expect("mutable NCM root");
    let acquisition = ModelAcquisitionManifest::reference().expect("pinned model acquisition");
    let repository = PathBuf::from(&acquisition.cache_repository);
    let snapshot = repository.join("snapshots").join(&acquisition.revision);
    let mut model_files = vec![
        PathBuf::from(MANIFEST_FILENAME),
        repository.join("refs/main"),
    ];
    model_files.extend(
        acquisition
            .files
            .iter()
            .map(|file| snapshot.join(&file.path)),
    );
    for relative in model_files {
        let source = models.join(&relative);
        assert!(
            std::fs::symlink_metadata(&source)
                .expect("installed pinned model file")
                .is_file(),
            "installed model artifacts must be regular files"
        );
        let destination = state_root.join(&acquisition.model_root).join(relative);
        std::fs::create_dir_all(destination.parent().expect("model artifact parent"))
            .expect("physical model artifact directory");
        std::fs::copy(source, destination).expect("adopt pinned model file into temporary root");
    }
    let model_root = StateRoot::new(state_root.clone()).expect("admitted fixture model root");
    let model_identity = install(
        &model_root,
        Deadline {
            remaining_ms: 30_000,
        },
    )
    .expect("canonical existing-model adoption");
    assert_eq!(model_identity.model, acquisition.model);
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(model_root.path().join(MODEL_ACQUISITION_RECEIPT_PATH))
            .expect("new fixture acquisition receipt"),
    )
    .expect("canonical fixture acquisition receipt JSON");
    assert_eq!(receipt["operation"], "install");
    assert_eq!(receipt["outcome"], "already_present");
    let project_id = ProjectId::new("project.real-ncm-current-delivery").unwrap();
    let profile_id = UserProfileId::new("profile.real-ncm-current-delivery").unwrap();
    let resolved_scope = scope(project_id.clone());
    let runtime = HostAdmissionTestRuntimeV1::project(
        &temporary.path().join("profile"),
        &temporary.path().join("project"),
        project_id.clone(),
    )
    .await
    .expect("registered project admission");
    let store = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .expect("registered project database")
        .observation_store();
    let journal_root = temporary.path().join("journey");
    std::fs::create_dir_all(&journal_root).expect("journal root");
    let alpha = SessionId::new("session.real-ncm-current-alpha").unwrap();
    let beta = SessionId::new("session.real-ncm-current-beta").unwrap();
    let alpha_text = "Database transactions commit atomically after validation.";
    let beta_text = "The cleanup worker removes temporary object files after failed builds.";
    let mut observations = vec![
        persist_position(&store, &project_id, &alpha, alpha_text, 0).await,
        persist_position(&store, &project_id, &beta, beta_text, 0).await,
    ];
    let project_root = std::fs::canonicalize(temporary.path().join("project")).unwrap();
    let registered = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .unwrap();
    let shard = &registered.binding().shard_id;
    let admission = HostAdmissionFacade::new(
        HostAdmissionAuthorities::for_project(
            shard.brain_id.clone(),
            shard.profile_id.clone(),
            project_id.clone(),
            registered.as_ref(),
        )
        .with_background_cpu(runtime.background_cpu()),
    );
    let codex_session = "11111111-1111-4111-8111-111111111111";
    let codex_text = "A known assistant message follows uncertain turn context.";
    let transcript = temporary
        .path()
        .join(format!("rollout-2026-09-04T12-00-00-{codex_session}.jsonl"));
    let codex_records = [
        json!({"timestamp":"2026-09-04T12:00:00Z", "type":"session_meta",
            "payload":{"id":codex_session,"cwd":project_root}}),
        json!({"timestamp":"2026-09-04T12:00:01Z", "type":"turn_context",
            "payload":{"turn_id":"turn-1","cwd":project_root,"model":"gpt-5.5"}}),
        json!({"timestamp":"2026-09-04T12:00:02Z", "type":"event_msg",
            "payload":{"type":"agent_message","message":codex_text}}),
    ];
    let mut transcript_text = String::new();
    for record in &codex_records {
        writeln!(&mut transcript_text, "{record}").unwrap();
    }
    std::fs::write(&transcript, transcript_text).unwrap();
    let progress = try_admit_codex_jsonl_observations_for_project_with_admission(
        &transcript,
        &project_root,
        project_id.clone(),
        &admission,
        None,
    )
    .await
    .unwrap();
    assert_eq!(progress.frames_persisted, codex_records.len() as u64);
    // Keep unknown eligibility independent of the real transcript's absolute
    // filesystem context, which the hygiene policy scans before eligibility.
    let eligibility_session = SessionId::new("session.unknown").unwrap();
    let mut eligibility_payload =
        canonical_observation_at(&project_id, &eligibility_session, "", 0)
            .payload()
            .clone();
    eligibility_payload["native_record_kind"] = json!("turn_context");
    eligibility_payload["facts"] = json!([CanonicalObservationFactV1::Unknown {
        native_kind: "turn_context".to_owned(),
        state: CanonicalUnknownStateV1::Unsupported,
    }]);
    let eligibility_unknown = canonical_observation_with_payload_at(
        &project_id,
        &eligibility_session,
        eligibility_payload,
        0,
    );
    store
        .persist_observation(anchored_write(eligibility_unknown.clone()))
        .await
        .unwrap();
    let canonical = store
        .replay_observations(
            ObservationReplayRequest::new(0, observations.len() + codex_records.len() + 1).unwrap(),
        )
        .await
        .unwrap();
    let unknown = canonical.iter().find(|record| {
        serde_json::from_value::<CanonicalObservationEnvelopeV1>(record.observation().payload().clone())
            .unwrap().facts().iter().any(|fact| matches!(fact,
                CanonicalObservationFactV1::Unknown { native_kind, state: CanonicalUnknownStateV1::Unsupported }
                    if native_kind == "turn_context"))
    }).expect("real Codex normalization preserves unsupported turn context");
    let unknown = unknown.observation().clone();
    let following = canonical
        .iter()
        .find(|record| {
            record.observation().source().provider().as_str() == "codex"
                && record
                    .observation()
                    .payload()
                    .to_string()
                    .contains(codex_text)
        })
        .expect("following Codex message was durably admitted")
        .observation()
        .clone();
    observations.push(following.clone());
    let non_message_records = canonical.len() - observations.len();
    let unknown_envelope = provider_observation_envelope(
        SESSION_MESSAGE_OBSERVATION_KIND,
        SESSION_MESSAGE_PAYLOAD_CONTRACT,
        unknown.payload(),
        unknown.observation_id(),
    );
    let unknown_digest = tracedecay_domain::canonical_text::sha256_hex(
        &canonical_payload_bytes(&unknown_envelope).unwrap(),
    );
    let sanitizer = ObservationSanitizer::new().unwrap();
    let ObservationAdmission::Withheld {
        reason: WithheldReason::SecretRejected,
        finding_count: unknown_findings,
        ..
    } = sanitizer.admit_observation(&unknown_envelope, &[]).unwrap()
    else {
        panic!(
            "real transcript context must exercise hygiene rejection before unknown eligibility"
        );
    };
    assert!(unknown_findings > 0);
    let eligibility_envelope = provider_observation_envelope(
        SESSION_MESSAGE_OBSERVATION_KIND,
        SESSION_MESSAGE_PAYLOAD_CONTRACT,
        eligibility_unknown.payload(),
        eligibility_unknown.observation_id(),
    );
    let ObservationAdmission::Admitted { receipt, .. } = sanitizer
        .admit_observation(&eligibility_envelope, &[])
        .unwrap()
    else {
        panic!("the clean unknown fixture must pass hygiene before eligibility is checked");
    };
    assert_eq!(receipt.finding_count(), 0);
    let eligibility_digest = tracedecay_domain::canonical_text::sha256_hex(
        &canonical_payload_bytes(&eligibility_envelope).unwrap(),
    );
    let alpha_scope =
        exact_scope_for_session(&profile_id, &resolved_scope, alpha.as_str()).unwrap();
    let beta_scope = exact_scope_for_session(&profile_id, &resolved_scope, beta.as_str()).unwrap();
    let codex_scope = exact_scope_for_session(&profile_id, &resolved_scope, codex_session).unwrap();
    assert_ne!(
        alpha_scope.exact_scope_sha256(),
        beta_scope.exact_scope_sha256()
    );
    let cancellation = HostCancellationToken::new();
    let mut retained_identity: Option<CurrentCapsuleIdentity> = None;
    let mut retained_codex_identity: Option<CurrentCapsuleIdentity> = None;
    let mut previous_journal_path: Option<PathBuf> = None;
    let mut previous_settled_evidence: Option<Vec<SettledDeliveryEvidence>> = None;
    let mut previous_watermark = None;

    for open in 0..3 {
        if open == 1 {
            observations.push(
                persist_position(
                    &store,
                    &project_id,
                    &alpha,
                    "A pending transaction resumes after the worker restarts.",
                    1,
                )
                .await,
            );
        }
        let fixture = tokio::task::spawn_blocking({
            let worker = worker.clone();
            let state_root = state_root.clone();
            move || construct_ncm_observer(worker, state_root, 1)
        })
        .await
        .expect("NCM construction task")
        .expect("actual production NCM surface");
        let owner = Arc::clone(&fixture.worker_owner);
        assert!(
            owner.worker_pid().is_none(),
            "worker construction remains lazy"
        );
        let composition = compose_real_ncm(&fixture);
        let provider = fixture.mount.clone();
        drop(fixture);
        let mount_started_at = Instant::now();
        let journey = mount_and_replay(
            ObservationJourneyMountInputsV1 {
                composition: Arc::clone(&composition),
                profile_id: profile_id.clone(),
                scope: resolved_scope.clone(),
                authoritative_project_id: project_id.clone(),
                store_data_root: journal_root.clone(),
                provider,
                policy: ObservationJourneyPolicyV1::project_default(),
            },
            store.clone(),
            &cancellation,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "NCM canonical startup and live replay mount failed on open {open} after {:?}: {error:?}",
                mount_started_at.elapsed(),
            )
        });
        if let Some(previous) = &previous_journal_path {
            assert_eq!(journey.journal_path(), previous.as_path());
        }
        previous_journal_path = Some(journey.journal_path().to_path_buf());
        wait_for_all_ncm_settlements(&journey, observations.len()).await;
        if open == 2 {
            assert_eq!(
                settled_delivery_evidence(&journey),
                previous_settled_evidence.as_ref().unwrap().clone(),
                "reopening without a new canonical commit cannot append or retry a delivery"
            );
            assert_eq!(
                journey.replay_watermark().await.unwrap(),
                previous_watermark.unwrap(),
                "reopening preserves the journey-wide replay position"
            );
        }
        if open == 2 {
            journey
                .await_instance_ready(&cancellation, REQUIRED_ACTIVATION_BUDGET)
                .await
                .expect("the remounted journey proves the worker before it restarts");
            let before_restart = journey
                .journal
                .inspect(&JournalInspectionFilterV1 {
                    limit: 8,
                    ..Default::default()
                })
                .unwrap()
                .rows
                .into_iter()
                .map(|row| {
                    let receipts = journey.journal.receipts_for(&row.observation_id).unwrap();
                    (row.observation_id, receipts)
                })
                .collect::<BTreeMap<_, _>>();
            let predecessor_instance = journey.provider_instance_id.get().unwrap();
            let predecessor_incarnation = owner.worker_incarnation().unwrap();
            tokio::task::spawn_blocking({
                let owner = Arc::clone(&owner);
                move || {
                    assert!(
                        owner
                            .request_stop(Instant::now() + Duration::from_secs(5))
                            .unwrap()
                    );
                    owner
                        .start(Instant::now() + Duration::from_secs(5))
                        .unwrap();
                }
            })
            .await
            .expect("restart the mounted journey's actual worker");
            assert_eq!(
                owner.worker_incarnation(),
                Some(predecessor_incarnation + 1)
            );
            observations.push(
                persist_position(
                    &store,
                    &project_id,
                    &alpha,
                    "A live transaction arrives after an empty restart replay.",
                    2,
                )
                .await,
            );
            wait_for_all_ncm_settlements(&journey, observations.len()).await;
            let replacement = real_ncm_handshake(
                composition.registry().unwrap(),
                &alpha_scope,
                "mounted-worker-replacement",
            );
            assert_eq!(replacement.terminal.terminal_code(), TerminalCode::Success);
            let replacement_instance = replacement.provider_instance_id.unwrap();
            assert_ne!(replacement_instance, predecessor_instance);
            assert_eq!(
                journey.provider_instance_id.get().as_deref(),
                Some(replacement_instance.as_str())
            );
            let after_restart = journey
                .journal
                .inspect(&JournalInspectionFilterV1 {
                    limit: 8,
                    ..Default::default()
                })
                .unwrap();
            let new_rows = after_restart
                .rows
                .iter()
                .filter(|row| !before_restart.contains_key(&row.observation_id))
                .collect::<Vec<_>>();
            assert_eq!(new_rows.len(), 1);
            assert_eq!(
                new_rows[0].exact_scope_sha256,
                alpha_scope.exact_scope_sha256()
            );
            let receipts = journey
                .journal
                .receipts_for(&new_rows[0].observation_id)
                .unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].outcome.as_wire(), "applied");
            assert_eq!(
                receipts[0].provider_instance_id.as_deref(),
                Some(replacement_instance.as_str()),
                "the ACK must name the worker proved for this delivery"
            );
            for (observation_id, receipts) in before_restart {
                assert_eq!(
                    journey.journal.receipts_for(&observation_id).unwrap(),
                    receipts,
                    "worker replacement cannot rewrite previous attempt evidence"
                );
            }
        }
        assert!(
            owner.worker_pid().is_some(),
            "readiness starts the real worker"
        );
        let canonical = store
            .replay_observations(
                ObservationReplayRequest::new(0, observations.len() + non_message_records).unwrap(),
            )
            .await
            .unwrap();
        assert_current_delivery_receipts(
            &journey,
            &observations,
            &canonical,
            &profile_id,
            &resolved_scope,
        );
        {
            let connection = rusqlite::Connection::open(journey.journal_path()).unwrap();
            let (reason, digest, findings): (String, String, i64) = connection
                .query_row(
                    "SELECT reason, source_payload_sha256, finding_count \
                 FROM tdmem_observation_withheld_v2 WHERE source_event_id = ?1",
                    [unknown.observation_id().as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(reason, "secret_rejected");
            assert_eq!(digest, unknown_digest);
            assert_eq!(findings, i64::from(unknown_findings));
            let (reason, digest, findings): (String, String, i64) = connection
                .query_row(
                    "SELECT reason, source_payload_sha256, finding_count \
                 FROM tdmem_observation_withheld_v2 WHERE source_event_id = ?1",
                    [eligibility_unknown.observation_id().as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(reason, "unknown_eligibility");
            assert_eq!(digest, eligibility_digest);
            assert_eq!(findings, 0);
            let (withheld, delivered): (i64, i64) = connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM tdmem_observation_withheld_v2), \
                 (SELECT COUNT(*) FROM tdmem_observation_journal_v1 WHERE source_event_id IN (?1, ?2))",
                    [unknown.observation_id().as_str(), eligibility_unknown.observation_id().as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(withheld, 2);
            assert_eq!(
                delivered, 0,
                "Unknown must create no provider payload on any mount"
            );
        }
        assert_eq!(
            store
                .get_observation(eligibility_unknown.observation_id())
                .await
                .unwrap()
                .unwrap()
                .observation(),
            &eligibility_unknown,
            "eligibility withholding preserves clean canonical evidence on every mount"
        );
        assert_eq!(
            store
                .get_observation(unknown.observation_id())
                .await
                .unwrap()
                .unwrap()
                .observation(),
            &unknown,
            "withholding must preserve canonical evidence on every mount"
        );
        assert_eq!(
            run_startup_replay(&journey, &store, &cancellation)
                .await
                .unwrap()
                .admitted,
            0,
            "settled source watermarks must prevent duplicate admission",
        );
        assert_current_delivery_receipts(
            &journey,
            &observations,
            &canonical,
            &profile_id,
            &resolved_scope,
        );
        let registry = composition.registry().expect("NCM registry");
        let (call, reply, temporal) = real_ncm_recall(
            registry,
            &alpha_scope,
            alpha_text,
            &format!("current-alpha-{open}"),
        );
        let outcome = real_ncm_admitted_recall(&call, &reply, &temporal);
        let identity = assert_current_capsule(
            &outcome,
            &profile_id,
            &resolved_scope,
            &alpha_scope,
            &observations,
            &observations[0],
            alpha_text,
        );
        if let Some(previous) = &retained_identity {
            assert_eq!(
                &identity, previous,
                "the same persisted capsule survives remount"
            );
        }
        retained_identity = Some(identity.clone());
        let (call, reply, temporal) = real_ncm_recall(
            registry,
            &beta_scope,
            beta_text,
            &format!("current-beta-{open}"),
        );
        let outcome = real_ncm_admitted_recall(&call, &reply, &temporal);
        let foreign = assert_current_capsule(
            &outcome,
            &profile_id,
            &resolved_scope,
            &beta_scope,
            &observations,
            &observations[1],
            beta_text,
        );
        assert_ne!(identity.stable_memory_ref, foreign.stable_memory_ref);
        assert_eq!(identity.checkout_namespace, foreign.checkout_namespace);
        let (call, reply, temporal) = real_ncm_recall(
            registry,
            &codex_scope,
            codex_text,
            &format!("current-codex-{open}"),
        );
        let outcome = real_ncm_admitted_recall(&call, &reply, &temporal);
        let current_codex = assert_current_capsule(
            &outcome,
            &profile_id,
            &resolved_scope,
            &codex_scope,
            &observations,
            &following,
            codex_text,
        );
        assert_eq!(
            current_codex.checkout_namespace,
            identity.checkout_namespace
        );
        assert_eq!(current_codex.checkout_namespace, foreign.checkout_namespace);
        if let Some(previous) = &retained_codex_identity {
            assert_eq!(
                &current_codex, previous,
                "the following real Codex message survives worker remount"
            );
        }
        retained_codex_identity = Some(current_codex);
        let before_recall = settled_delivery_evidence(&journey);
        let watermark = journey.replay_watermark().await.unwrap();
        let mut later_caller = exact_scope_for_session(
            &profile_id,
            &resolved_scope,
            &format!("session.real-ncm-later-caller-{open}"),
        )
        .unwrap();
        later_caller.resolved_scope_digest = format!(
            "sha256:{}",
            tracedecay_domain::canonical_text::sha256_hex(
                format!("later-checkout-resolution-{open}").as_bytes()
            )
        );
        assert_ne!(later_caller.agent_session_id, alpha_scope.agent_session_id);
        assert_ne!(
            later_caller.resolved_scope_digest,
            alpha_scope.resolved_scope_digest
        );
        let (call, reply, temporal) = real_ncm_recall(
            registry,
            &later_caller,
            alpha_text,
            &format!("later-caller-after-open-{open}"),
        );
        let outcome = real_ncm_admitted_recall(&call, &reply, &temporal);
        assert_eq!(
            assert_current_capsule(
                &outcome,
                &profile_id,
                &resolved_scope,
                &later_caller,
                &observations,
                &observations[0],
                alpha_text,
            ),
            identity,
            "later callers recall the same retained record without observation redelivery"
        );
        assert_eq!(
            run_startup_replay(&journey, &store, &cancellation)
                .await
                .unwrap()
                .admitted,
            0
        );
        assert_eq!(settled_delivery_evidence(&journey), before_recall);
        assert_eq!(journey.replay_watermark().await.unwrap(), watermark);
        previous_settled_evidence = Some(before_recall);
        previous_watermark = Some(watermark);
        assert!(
            journey
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
                .await
                .is_empty()
        );
        drop(journey);
        drop(composition);
        stop_real_worker(owner).await;
    }

    let exhausted_session = SessionId::new("session.real-ncm-historical-exhausted").unwrap();
    let pending_session = SessionId::new("session.real-ncm-historical-pending").unwrap();
    let historical = [
        persist_position(
            &store,
            &project_id,
            &exhausted_session,
            "An interrupted historical delivery consumes its bounded attempts.",
            0,
        )
        .await,
        persist_position(
            &store,
            &project_id,
            &pending_session,
            "Another historical delivery remains queued in its original registration.",
            0,
        )
        .await,
    ];
    let exhausted_scope =
        exact_scope_for_session(&profile_id, &resolved_scope, exhausted_session.as_str()).unwrap();
    let pending_scope =
        exact_scope_for_session(&profile_id, &resolved_scope, pending_session.as_str()).unwrap();
    let mut fixture = tokio::task::spawn_blocking({
        let worker = worker.clone();
        let state_root = state_root.clone();
        move || construct_ncm_observer(worker, state_root, 1)
    })
    .await
    .unwrap()
    .unwrap();
    let owner = Arc::clone(&fixture.worker_owner);
    let inputs = |fixture: &NcmObserverFixture, composition| ObservationJourneyMountInputsV1 {
        composition,
        profile_id: profile_id.clone(),
        scope: resolved_scope.clone(),
        authoritative_project_id: project_id.clone(),
        store_data_root: journal_root.clone(),
        provider: fixture.mount.clone(),
        policy: ObservationJourneyPolicyV1::project_default(),
    };
    let composition = compose_real_ncm(&fixture);
    let seed = mount_observer_dormant(inputs(&fixture, Arc::clone(&composition)), &cancellation)
        .await
        .unwrap();
    assert_eq!(
        run_startup_replay(&seed, &store, &cancellation)
            .await
            .unwrap()
            .admitted,
        2
    );
    let historical_filter = |scope: &OwnedExactScope| JournalInspectionFilterV1 {
        provider_id: Some(NCM_PROVIDER_ID.to_owned()),
        exact_scope_sha256: Some(scope.exact_scope_sha256()),
        limit: 2,
        ..Default::default()
    };
    let page = seed
        .journal
        .inspect(&historical_filter(&exhausted_scope))
        .unwrap();
    assert_eq!(page.total_rows, 1);
    let exhausted_row = page.rows.into_iter().next().unwrap();
    assert_eq!(exhausted_row.state, DeliveryStateV1::Pending);
    let mut request = LeaseRequestV1 {
        provider_id: NCM_PROVIDER_ID.to_owned(),
        registration_revision: exhausted_row.registration_revision,
        provider_instance_id: exhausted_row.provider_instance_id.clone(),
        exact_scope_sha256: Some(exhausted_scope.exact_scope_sha256()),
        lease_owner: "real-ncm-historical-dispatcher".to_owned(),
        now_unix_micros: exhausted_row.next_attempt_at_unix_micros,
        lease_duration_micros: 1,
        max_items: 1,
        max_bytes: seed.journal.policy().max_queue_bytes,
    };
    for attempt in 1..=seed.journal.policy().max_attempts {
        let claims = seed.journal.lease_pending(&request).unwrap();
        assert_eq!(claims.len(), 1);
        let claim = &claims[0];
        assert_eq!(claim.observation_id, exhausted_row.observation_id);
        assert_eq!(claim.attempt_number, attempt);
        request.now_unix_micros = claim.lease_expires_at_unix_micros + 1;
        assert!(request.now_unix_micros < claim.deadline_unix_micros);
        assert_eq!(
            seed.journal
                .reap_expired_leases(request.now_unix_micros, 1)
                .unwrap(),
            1
        );
    }
    assert_eq!(seed.journal.lease_pending(&request).unwrap(), Vec::new());
    assert_eq!(
        seed.journal
            .attempt_orphans_for(&exhausted_row.observation_id)
            .unwrap()
            .len(),
        usize::try_from(seed.journal.policy().max_attempts).unwrap()
    );
    assert!(
        seed.shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
    drop(seed);
    drop(composition);

    // A new registration cannot lease the previous registration's history.
    // Its strict instance proof still uses the same real production worker.
    fixture.observer.registration_revision = 2;
    fixture.mount.registration_revision = 2;
    let composition = compose_real_ncm(&fixture);
    let dormant = mount_observer_dormant(inputs(&fixture, Arc::clone(&composition)), &cancellation)
        .await
        .unwrap();
    drop(fixture);
    let cancelled = HostCancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        activate_required_with_instance_ready(Arc::clone(&dormant), store.clone(), &cancelled)
            .await,
        Err(ObservationJourneyError::Cancelled { admitted: 0 })
    ));
    assert!(!dormant.provider_instance_id.is_ready());
    let journey = activate_required_with_instance_ready(dormant, store.clone(), &cancellation)
        .await
        .expect(
            "real instance readiness must publish despite unrelated historical delivery states",
        );
    assert!(journey.provider_instance_id.is_ready());
    assert!(owner.worker_pid().is_some());
    for (scope, state) in [
        (&exhausted_scope, DeliveryStateV1::Exhausted),
        (&pending_scope, DeliveryStateV1::Pending),
    ] {
        let page = journey.journal.inspect(&historical_filter(scope)).unwrap();
        let old = page
            .rows
            .iter()
            .find(|row| row.registration_revision == 1)
            .expect("historical delivery remains durable");
        assert_eq!(old.state, state);
    }
    assert!(matches!(
        journey
            .await_delivery_settled(&cancellation, Duration::ZERO)
            .await,
        Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 })
    ));
    for observation in &historical {
        assert_eq!(
            store
                .get_observation(observation.observation_id())
                .await
                .unwrap()
                .unwrap()
                .observation(),
            observation
        );
    }
    assert!(
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
    drop(journey);
    drop(composition);
    stop_real_worker(owner).await;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentCapsuleIdentity {
    stable_memory_ref: String,
    content_sha256: String,
    canonical_observation_id: String,
    checkout_namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SettledDeliveryEvidence {
    observation_id: String,
    source_event_id: String,
    source_sequence: i64,
    delivery_scope: String,
    state: String,
    attempts: i64,
    receipts: i64,
}

fn settled_delivery_evidence(
    journey: &ProjectObservationJourneyV1,
) -> Vec<SettledDeliveryEvidence> {
    let connection = rusqlite::Connection::open(journey.journal_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT j.observation_id, j.source_event_id, j.source_sequence, j.exact_scope_sha256, \
             d.state, d.attempt_number, \
             (SELECT COUNT(*) FROM tdmem_observation_receipt_v1 r WHERE r.observation_id = j.observation_id) \
             FROM tdmem_observation_journal_v1 j JOIN tdmem_observation_delivery_v1 d \
             ON d.idempotency_key = j.idempotency_key ORDER BY j.source_sequence",
        )
        .unwrap();
    statement
        .query_map([], |row| {
            Ok(SettledDeliveryEvidence {
                observation_id: row.get(0)?,
                source_event_id: row.get(1)?,
                source_sequence: row.get(2)?,
                delivery_scope: row.get(3)?,
                state: row.get(4)?,
                attempts: row.get(5)?,
                receipts: row.get(6)?,
            })
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn assert_current_capsule(
    outcome: &RecallOutcomeV1,
    profile_id: &UserProfileId,
    resolved_scope: &ResolvedScope,
    exact_scope: &OwnedExactScope,
    observations: &[DurableObservationV1],
    expected: &DurableObservationV1,
    text: &str,
) -> CurrentCapsuleIdentity {
    assert_eq!(exact_scope.profile_id, profile_id.as_str());
    assert_eq!(exact_scope.project_id, resolved_scope.project_id.as_str());
    assert_eq!(
        exact_scope.repository_identity,
        resolved_scope.repository_id.as_str()
    );
    assert_eq!(
        exact_scope.worktree_identity,
        resolved_scope.worktree_id.as_str()
    );
    assert_eq!(
        Some(exact_scope.branch_identity.as_str()),
        resolved_scope
            .reference
            .as_ref()
            .map(|reference| reference.as_str())
    );
    let owned = observations
        .iter()
        .map(|observation| observation.observation_id().as_str())
        .collect::<Vec<_>>();
    assert!(
        !outcome.candidates.is_empty(),
        "provider-local recall must return retained content"
    );
    for candidate in &outcome.candidates {
        let scope = &candidate.exact_scope_identity;
        assert_eq!(scope.scope_binding, ScopeBinding::CheckoutObservations);
        assert_eq!(scope.profile_id, exact_scope.profile_id);
        assert_eq!(scope.project_id, exact_scope.project_id);
        assert_eq!(scope.repository_identity, exact_scope.repository_identity);
        assert_eq!(scope.worktree_identity, exact_scope.worktree_identity);
        assert_eq!(scope.branch_identity, exact_scope.branch_identity);
        assert_eq!(scope.agent_session_id, "");
        assert_eq!(scope.resolved_scope_digest, "");
        assert_eq!(candidate.provenance["original_sources"], json!([]));
        assert_eq!(candidate.validity.temporal_state, "unknown");
        let observation_refs = candidate.provenance["observation_refs"].as_array().unwrap();
        assert_eq!(observation_refs.len(), 1);
        let observation_id = observation_refs[0].as_str().unwrap();
        assert!(
            owned.contains(&observation_id),
            "a record outside the checkout's canonical deliveries entered recall: {observation_id}"
        );
        assert_eq!(
            candidate.source_refs,
            vec![format!("record:{observation_id}")]
        );
    }
    let expected_id = expected.observation_id().as_str();
    let candidate = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.provenance["observation_refs"] == json!([expected_id]))
        .expect("the known canonical record is retained");
    let content = format!("assistant: {text}");
    assert_eq!(candidate.content.as_deref(), Some(content.as_str()));
    assert_eq!(
        candidate.content_sha256,
        tracedecay_domain::canonical_text::sha256_hex(content.as_bytes())
    );
    let stable_memory_ref = candidate
        .stable_memory_ref
        .clone()
        .expect("authenticated persisted NCM capsule identity");
    assert_ne!(stable_memory_ref, "");
    assert_eq!(candidate.trace_refs, vec![stable_memory_ref.clone()]);
    CurrentCapsuleIdentity {
        stable_memory_ref,
        content_sha256: candidate.content_sha256.clone(),
        canonical_observation_id: expected_id.to_owned(),
        checkout_namespace: NcmNamespace::from_scope(exact_scope, NCM_NAMESPACE_BINDING)
            .as_str()
            .to_owned(),
    }
}

fn assert_current_delivery_receipts(
    journey: &ProjectObservationJourneyV1,
    observations: &[DurableObservationV1],
    canonical: &[StoredObservation],
    profile_id: &UserProfileId,
    resolved_scope: &ResolvedScope,
) {
    let mut expected = observations
        .iter()
        .map(|observation| {
            (
                observation.observation_id().as_str().to_owned(),
                observation,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let connection = rusqlite::Connection::open(journey.journal_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT journal.observation_id, journal.source_event_id, journal.source_sequence, \
         journal.exact_scope_sha256, journal.payload_bytes, journal.payload_sha256, \
         journal.source_payload_sha256, journal.sanitization_receipt_json, delivery.state \
         FROM tdmem_observation_journal_v1 AS journal \
         JOIN tdmem_observation_delivery_v1 AS delivery \
         ON delivery.observation_id = journal.observation_id ORDER BY journal.source_sequence",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), observations.len());
    for (
        delivery_id,
        source_id,
        sequence,
        scope_digest,
        bytes,
        payload_digest,
        source_digest,
        receipt_json,
        state,
    ) in rows
    {
        let sequence =
            u64::try_from(sequence).expect("journal source sequence must not be negative");
        let observation = expected
            .remove(&source_id)
            .expect("journal source is an actual canonical commit");
        let committed = canonical
            .iter()
            .find(|record| record.observation().observation_id().as_str() == source_id)
            .expect("the delivery source is a committed canonical observation");
        assert_eq!(sequence, committed.sequence());
        assert_eq!(state, "acknowledged");
        let exact_scope = exact_scope_for_session(
            profile_id,
            resolved_scope,
            observation.source().session_id().as_str(),
        )
        .unwrap();
        assert_eq!(scope_digest, exact_scope.exact_scope_sha256());
        let CanonicalMessageEligibilityV1::Message {
            payload,
            shape_error: None,
        } = canonical_message_eligibility(observation).unwrap()
        else {
            panic!("expected delivery must be a validated canonical message");
        };
        let envelope = provider_observation_envelope(
            SESSION_MESSAGE_OBSERVATION_KIND,
            SESSION_MESSAGE_PAYLOAD_CONTRACT,
            &payload,
            observation.observation_id(),
        );
        let source_bytes = canonical_payload_bytes(&envelope).unwrap();
        assert_eq!(
            bytes, source_bytes,
            "safe canonical content remains byte exact"
        );
        assert_eq!(
            payload_digest,
            tracedecay_domain::canonical_text::sha256_hex(&bytes)
        );
        assert_eq!(
            source_digest,
            tracedecay_domain::canonical_text::sha256_hex(&source_bytes)
        );
        let receipt = PayloadSanitizationReceipt::from_json(&receipt_json).unwrap();
        assert_eq!(receipt.sanitized_payload_sha256(), payload_digest);
        assert_eq!(receipt.source_payload_sha256(), source_digest);
        let (count, outcome, effect, provider_digest): (i64, String, String, String) = connection.query_row(
            "SELECT COUNT(*), MIN(outcome), MIN(committed_effect), MIN(provider_receipt_digest) \
             FROM tdmem_observation_receipt_v1 WHERE observation_id = ?1",
            [delivery_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(
            (count, outcome.as_str(), effect.as_str()),
            (1, "applied", "applied")
        );
        assert_eq!(provider_digest.len(), 64);
        assert!(
            provider_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
    assert!(expected.is_empty());
    let (cursors, frontier): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), MAX(last_admitted_sequence) FROM tdmem_observation_replay_cursor_v1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let frontier = u64::try_from(frontier).expect("canonical replay frontier must not be negative");
    let sessions = canonical
        .iter()
        .map(|record| record.observation().source().session_id().as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        cursors,
        i64::try_from(sessions.len()).unwrap(),
        "each source session owns its replay cursor"
    );
    assert_eq!(
        frontier,
        canonical
            .iter()
            .map(StoredObservation::sequence)
            .max()
            .unwrap()
    );
}

async fn stop_real_worker(owner: Arc<RustNcmWorkerOwner>) {
    tokio::task::spawn_blocking(move || {
        assert!(
            owner
                .request_stop(Instant::now() + Duration::from_secs(5))
                .unwrap()
        );
        assert!(owner.worker_pid().is_none());
    })
    .await
    .expect("stop and release the actual worker owner");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_ncm_worker_refuses_admission_and_preserves_canonical_commit() {
    let temporary = TempDir::new().unwrap();
    let project_id = ProjectId::new("project.unavailable-ncm-current").unwrap();
    let runtime = HostAdmissionTestRuntimeV1::project(
        &temporary.path().join("profile"),
        &temporary.path().join("project"),
        project_id.clone(),
    )
    .await
    .unwrap();
    let store = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .unwrap()
        .observation_store();
    let fixture = tokio::task::spawn_blocking({
        let worker = temporary.path().join("absent-worker");
        let state_root = temporary.path().join("ncm");
        move || construct_ncm_observer(worker, state_root, 1)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(fixture.mount.provider_instance_id.is_none());
    let composition = compose_real_ncm(&fixture);
    let owner = Arc::clone(&fixture.worker_owner);
    let root = temporary.path().join("journey");
    std::fs::create_dir_all(&root).unwrap();
    let journey = mount_observer_dormant(
        ObservationJourneyMountInputsV1 {
            composition: Arc::clone(&composition),
            profile_id: UserProfileId::new("profile.unavailable-ncm-current").unwrap(),
            scope: scope(project_id.clone()),
            authoritative_project_id: project_id.clone(),
            store_data_root: root,
            provider: fixture.mount.clone(),
            policy: ObservationJourneyPolicyV1::project_default(),
        },
        &HostCancellationToken::new(),
    )
    .await
    .unwrap();
    drop(fixture);
    let session = SessionId::new("session.unavailable-ncm-current").unwrap();
    let observation = persist_position(
        &store,
        &project_id,
        &session,
        "The canonical commit remains durable without an NCM worker.",
        0,
    )
    .await;
    let refused = run_startup_replay(&journey, &store, &HostCancellationToken::new())
        .await
        .expect_err("unavailable worker must refuse readiness before admission");
    let ObservationJourneyError::Ingress(ObservationRuntimeError::Admission { cause, .. }) =
        refused
    else {
        panic!("unavailable worker must fail at the typed admission boundary");
    };
    let Some(AdmissionAdapterError::Readiness { source, .. }) =
        cause.cause().downcast_ref::<AdmissionAdapterError>()
    else {
        panic!("admission must retain the supervised readiness refusal");
    };
    let ObservationJourneyError::SupervisedReadiness(SupervisedReadinessError::Unavailable {
        kind,
        terminal_code,
        ..
    }) = source.as_ref()
    else {
        panic!("admission must retain the supervised readiness refusal");
    };
    assert_eq!(*kind, DegradationKindV1::StartFailed);
    assert_eq!(*terminal_code, None);
    assert!(matches!(
        activate_required_with_instance_ready(
            Arc::clone(&journey),
            store.clone(),
            &HostCancellationToken::new(),
        )
        .await,
        Err(ObservationJourneyError::ProviderInstanceUnavailable)
    ));
    let page = journey
        .journal
        .inspect(&JournalInspectionFilterV1::default())
        .unwrap();
    assert_eq!(
        page.total_rows, 0,
        "unavailable worker cannot claim a queued observation"
    );
    let connection = rusqlite::Connection::open(journey.journal_path()).unwrap();
    let (receipts, cursors): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tdmem_observation_receipt_v1), \
                (SELECT COUNT(*) FROM tdmem_observation_replay_cursor_v1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((receipts, cursors), (0, 0));
    let stored = store
        .get_observation(observation.observation_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.observation(), &observation);
    assert!(owner.worker_pid().is_none());
    assert!(
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
    drop(journey);
    drop(composition);
    drop(owner);
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
    let temporal = tracedecay_memory_provider_registry::AdmittedTemporalQuery::current(
        &chrono::Utc::now().to_rfc3339(),
    )
    .expect("real NCM current temporal query")
    .with_unknown_validity_policy(UnknownValidityPolicy::AllowWithWarning);
    let payload =
        build_recall_request_payload(&tracedecay_memory_provider_registry::RecallRequestParts {
            provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
            registration_revision: 1,
            ready_receipt_sha256: receipt.clone(),
            exact_scope: exact_scope.clone(),
            request_id: request_identity.to_owned(),
            objective: "Recall the provider-local current canonical record".to_owned(),
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
        &RecallScopeBindingsV1::new([
            ScopeBinding::ExactCodingScope,
            ScopeBinding::CheckoutObservations,
        ]),
        reply,
    )
    .expect("admit NCM recall outcome");
    assert_eq!(admitted.report.admitted_count, outcome.candidates.len());
    assert_eq!(admitted.report.denied, Vec::new());
    outcome
}

/// Append at the canonical source frontier without bypassing the store's cursor CAS.
#[cfg(unix)]
async fn persist_position(
    store: &impl ObservationStore,
    project_id: &ProjectId,
    session_id: &SessionId,
    text: &str,
    position: u64,
) -> DurableObservationV1 {
    let anchored = anchored_write(canonical_observation_at(
        project_id, session_id, text, position,
    ));
    let observation = anchored.observation().clone();
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
    observation
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
                TerminalCode::from_wire(&refusal.terminal_code).map_or("unrecognized", TerminalCode::as_wire)
            ).collect::<Vec<_>>(),
        })
    }).collect::<Vec<_>>();
    json!({ "total_rows": page.total_rows, "page_truncated": page.next_cursor.is_some(), "rows": rows })
}
