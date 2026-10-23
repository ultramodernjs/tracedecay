//! Canonical session authority does not imply original live-event provenance.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use tempfile::TempDir;
use tracedecay_contracts::{
    ApplicationOutcome, CancellationContext, CancellationSignal, CancellationStage,
    CapabilityGrantId, CapabilityGrantSnapshot, Deadline, DisclosureClass, RequestContext,
    RequestId, ResolvedScope, RetainedProviderControlExecutionPortV1,
    RetainedSurfaceExecutionContextV1,
};
use tracedecay_domain::{
    ActorId, CanonicalObservationEnvelopeV1, ManifestDigest, ObservationScopeV1, ProjectId,
    WorktreeId,
};
use tracedecay_global_db::RegisteredGlobalDbLeaseV1;
use tracedecay_host_admission::{HostAdmissionAuthorities, HostAdmissionFacade};
use tracedecay_memory_observation::SqliteObservationJournal;
use tracedecay_memory_provider_registry::recall_admission::source_attribution::RecallSourceAttributionV1;
use tracedecay_memory_provider_registry::{
    CancellationToken, OperationControl, OriginScopeEvidence, OriginalSourceIdentity,
    OwnedProviderId, RecallExplainHostDecisionV1, RecallExplainItemV1,
    RecallExplainProviderExplanationV1, RecallExplainTraceV1, RecordedValidity,
};
use tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1;
use tracedecay_runtime_core::db::Database;
use tracedecay_sessions::admission::HostAdmissionScope;
use tracedecay_sessions::observation::ObservationCancellation;
use tracedecay_sessions::repository_provenance::RepositoryProvenanceAdmissionContext;
use tracedecay_sessions::runtime::hosts::claude::ClaudeSource;
use tracedecay_sessions::runtime::hosts::claude_observation::ingest_source_with_observations_with_admission;
use tracedecay_store::{ObservationReplayRequest, ObservationStore, StoredObservation};

use crate::retained_owner::observation_journey::ObservationJourneyPolicyV1;
use crate::retained_owner::provider_control::ProviderControlMountInputsV1;
use crate::retained_owner::provider_control::authority::{
    ProviderControlAuthorityInputsV1, ProviderControlAuthorityV1,
};
use crate::retained_owner::provider_history::{
    HistoryIdentityBridgeV1, HookOriginReaderV1, MountedOriginalObservationAuthorityV1,
    ORIGINAL_PROVENANCE_UNAVAILABLE, OriginalObservationAuthorityV1, ProviderHistoryErrorV1,
    ProviderHistoryReaderV1, source_attribution_json,
};
use tracedecay_rusqlite_runtime::recall_admission::{
    RecallAdmissionLedgerV1,
    control_attribution::{
        PreparedRecallControlMetadataV1, RecallLocatorKeyV1, RetainedRecallControlBindingV1,
        retained_candidate_identity_alias_for_context, retained_trace_id_with_key,
    },
};

const SESSION: &str = "source-control-session";
const CONTENT: &str = "Canonical transcript content is not an original live-event proof.";

struct CanonicalSourceFixture {
    temporary: TempDir,
    runtime: HostAdmissionTestRuntimeV1,
    port: ProjectProviderControlPortV1,
    original: Arc<MountedOriginalObservationAuthorityV1>,
    ledger: Arc<RecallAdmissionLedgerV1>,
    journal: Arc<SqliteObservationJournal>,
    attribution: SourceAttribution,
    provider: OwnedProviderId,
    canonical_session_db: RegisteredGlobalDbLeaseV1,
    canonical_dispositions: Arc<Database>,
}

fn operation_control() -> OperationControl {
    OperationControl::new(
        tracedecay_contracts::now_micros().0 + 30_000_000,
        30_000,
        CancellationToken::new(),
    )
}

fn repository(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["commit", "--allow-empty", "-q", "-m", "initial"],
    ] {
        let output =
            std::process::Command::new(tracedecay_runtime_core::git::try_git_program().unwrap())
                .args([
                    "-c",
                    "user.name=Source Control Fixture",
                    "-c",
                    "user.email=source-control@example.invalid",
                ])
                .args(&args)
                .current_dir(root)
                .output()
                .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn admit_transcript(
    runtime: &HostAdmissionTestRuntimeV1,
    project_root: &Path,
    project: &ProjectId,
    home: &Path,
    session: &str,
) -> StoredObservation {
    let registered = runtime
        .registered_database_arc(HostAdmissionScope::Project)
        .unwrap();
    let shard = &registered.binding().shard_id;
    let marker = tracedecay_runtime_core::storage::read_repository_identity_marker(project_root)
        .unwrap()
        .unwrap();
    let provenance = RepositoryProvenanceAdmissionContext::from_authoritative_project_marker(
        project_root,
        project,
        &marker,
    )
    .unwrap();
    let facade = HostAdmissionFacade::new(
        HostAdmissionAuthorities::for_project(
            shard.brain_id.clone(),
            shard.profile_id.clone(),
            project.clone(),
            registered.as_ref(),
        )
        .with_repository_provenance(provenance)
        .with_background_cpu(runtime.background_cpu()),
    );
    let transcript = home
        .join(".claude/projects/control-fixture")
        .join(format!("{session}.jsonl"));
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    let now = tracedecay_contracts::now_micros();
    let line = json!({
        "type": "user", "sessionId": session, "uuid": format!("message.{session}"),
        "timestamp": rfc3339_utc_micros(now.0).unwrap(), "cwd": project_root,
        "message": {"role": "user", "content": CONTENT},
    });
    std::fs::write(&transcript, format!("{line}\n")).unwrap();
    let receipt = ingest_source_with_observations_with_admission(
        &ClaudeSource::with_home(home),
        project_root,
        ObservationScopeV1::Project {
            project_id: project.clone(),
        },
        &facade,
        Some(1_048_576),
        ObservationCancellation::default(),
    )
    .await
    .unwrap();
    assert_eq!(receipt.observations_committed, 1);
    assert_eq!(receipt.projections_completed, 1);
    let row = registered
        .get_session("claude", session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.provider, "claude");
    assert_eq!(row.session_id, session);
    let mut observations = registered
        .observation_store()
        .replay_observations(ObservationReplayRequest::new(0, 2).unwrap())
        .await
        .unwrap();
    assert_eq!(observations.len(), 1);
    observations.pop().unwrap()
}

fn canonical_attribution(stored: &StoredObservation) -> SourceAttribution {
    let observation = stored.observation();
    let envelope: CanonicalObservationEnvelopeV1 =
        serde_json::from_value(observation.payload().clone()).unwrap();
    envelope.validate().unwrap();
    let bytes = tracedecay_memory_hygiene::canonical_payload_bytes(observation.payload()).unwrap();
    let attribution = SourceAttribution {
        source: OriginalSourceIdentity {
            canonical_provider_id: OwnedProviderId::new(observation.source().provider().as_str())
                .unwrap(),
            canonical_session_id: observation.source().session_id().as_str().to_owned(),
            source_key: observation.source().source_key().as_str().to_owned(),
            stable_record_id: observation
                .identity()
                .native_record_id()
                .map(|value| value.as_str().to_owned()),
            observation_id: observation.observation_id().as_str().to_owned(),
            source_revision: envelope.evidence().revision().map(str::to_owned),
            content_sha256: tracedecay_domain::canonical_text::sha256_hex(&bytes),
        },
        origin_scope: OriginScopeEvidence::IngestionOnly,
        source_sequence: stored.sequence(),
        occurred_at_utc_nanos: stored
            .retrieval_anchor()
            .occurred_at()
            .map(|time| time.start.0.checked_mul(1_000).unwrap()),
        ingested_at_utc_nanos: stored
            .retrieval_anchor()
            .ingested_at()
            .0
            .checked_mul(1_000)
            .unwrap(),
        validity: RecordedValidity::default(),
    };
    attribution.validate().unwrap();
    attribution
}

impl CanonicalSourceFixture {
    async fn new() -> Self {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("repository");
        repository(&root);
        let root = std::fs::canonicalize(root).unwrap();
        let project = ProjectId::new("project.source-control").unwrap();
        let runtime = HostAdmissionTestRuntimeV1::project(
            temporary.path().join("profile"),
            &root,
            project.clone(),
        )
        .await
        .unwrap();
        tracedecay_runtime_core::storage::write_repository_identity_marker(&root, project.as_str())
            .unwrap();
        let stored = admit_transcript(
            &runtime,
            &root,
            &project,
            &temporary.path().join("host"),
            SESSION,
        )
        .await;
        let attribution = canonical_attribution(&stored);
        let registered = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .unwrap();
        let shard = &registered.binding().shard_id;
        let profile = shard.profile_id.clone();
        let scope =
            tracedecay_code_index_runtime::resolved_scope_for_project(&root, &project).unwrap();
        let data_root = temporary.path().join("provider-data");
        std::fs::create_dir_all(&data_root).unwrap();
        let provider = OwnedProviderId::new("tracedecay.native").unwrap();
        let journal = Arc::new(
            SqliteObservationJournal::open(
                data_root.join("memory-observation-journal-v1.sqlite3"),
                ObservationJourneyPolicyV1::project_default().retention,
            )
            .unwrap(),
        );
        let original = Arc::new(MountedOriginalObservationAuthorityV1 {
            reader: Arc::new(HookOriginReaderV1::new(
                data_root.clone(),
                shard.brain_id.clone(),
                profile.clone(),
            )),
            bridge: Arc::new(
                HistoryIdentityBridgeV1::admit(&root, &profile, &scope, shard).unwrap(),
            ),
        });
        let key = RecallLocatorKeyV1::for_test();
        let ledger = Arc::new(RecallAdmissionLedgerV1::open_for_control_test(&data_root).unwrap());
        let dispositions = runtime
            .session_registry_for_test()
            .project_memory(project.clone(), [root.clone()])
            .await
            .unwrap();
        let authority = Arc::new(
            ProviderControlAuthorityV1::from_mounted_data(
                ProviderControlAuthorityInputsV1 {
                    canonical_project_path: root.clone(),
                    profile_id: profile.clone(),
                    mounted_scope: scope.clone(),
                    session_db: registered.clone(),
                    dispositions: dispositions.clone(),
                    hook_origin_reader: original.reader.clone(),
                    store_data_root: data_root,
                    live_ledger: Some(ledger.clone()),
                    locator_key: key,
                    live_journals: vec![(provider.clone(), journal.clone())],
                    runtime: tokio::runtime::Handle::current(),
                },
                &operation_control(),
            )
            .unwrap(),
        );
        Self {
            temporary,
            runtime,
            original,
            ledger,
            journal,
            attribution,
            provider,
            canonical_session_db: registered,
            canonical_dispositions: dispositions,
            port: ProjectProviderControlPortV1 {
                inputs: ProviderControlMountInputsV1 {
                    authority: Some(authority),
                    journeys: Vec::new(),
                    profile_id: profile,
                    mounted_scope: scope,
                    authoritative_project_id: project,
                    configuration_digest: ManifestDigest::new(format!("sha256:{}", "d".repeat(64)))
                        .unwrap(),
                },
            },
        }
    }

    fn retain_untrusted_source_claim(
        &self,
    ) -> (ProviderControlSourceSelectorV1, SourceAttribution) {
        let delivery = self.original.bridge.destination(SESSION).unwrap();
        // This is an untrusted structural claim retained for denial coverage,
        // never original-event evidence or a canonical history grant.
        let mut claimed = self.attribution.clone();
        claimed.origin_scope = OriginScopeEvidence::Recorded {
            scope: delivery.clone(),
            authority_ref: "untrusted.fixture.original-origin-claim".to_owned(),
        };
        claimed.validate().unwrap();
        let key = RecallLocatorKeyV1::for_test();
        let candidate = retained_candidate_identity_alias_for_context(
            &key,
            &delivery.exact_scope_sha256(),
            "request.source-locator",
            self.provider.as_str(),
            1,
            "candidate.canonical-source",
        )
        .unwrap();
        let trace = RecallExplainTraceV1 {
            trace_id: retained_trace_id_with_key(
                &key,
                &delivery.exact_scope_sha256(),
                "request.source-locator",
                self.provider.as_str(),
                1,
            )
            .unwrap(),
            request_id: "request.source-locator".to_owned(),
            provider_id: self.provider.as_str().to_owned(),
            registration_revision: 1,
            requested_count: 1,
            degraded: false,
            token_summary: None,
            items: vec![RecallExplainItemV1 {
                candidate_id: candidate.clone(),
                provider_rank: 0,
                stage: RecallExplainHostDecisionV1::Selected.stage(),
                host_decision: RecallExplainHostDecisionV1::Selected,
                host_reason_code: RecallExplainHostDecisionV1::Selected.code().to_owned(),
                host_reason_detail: None,
                provider_explanation: RecallExplainProviderExplanationV1::NotProvided,
                section: None,
                tokens: None,
            }],
        };
        let wire: RecallSourceAttributionV1 =
            serde_json::from_value(source_attribution_json(&claimed).unwrap()).unwrap();
        let metadata = PreparedRecallControlMetadataV1::prepare(
            &trace,
            &delivery,
            &BTreeMap::from([(
                candidate,
                RetainedRecallControlBindingV1 {
                    stable_memory_ref: format!("observation:{}", claimed.source.observation_id),
                    original_sources: vec![wire],
                },
            )]),
        )
        .unwrap();
        self.ledger
            .retain_explain_trace_with_control(
                &delivery.exact_scope_sha256(),
                &trace,
                Some(&metadata),
            )
            .unwrap();
        let selector = ProviderControlSourceSelectorV1 {
            trace_ref: metadata.trace_ref().as_str().to_owned(),
            item_ref: metadata.item_ref(0).unwrap().as_str().to_owned(),
            observation_id: claimed.source.observation_id.clone(),
        };
        (selector, claimed)
    }

    fn authority(&self) -> &Arc<ProviderControlAuthorityV1> {
        self.port.inputs.authority.as_ref().unwrap()
    }

    fn canonical_selector(&self, provider: &str, session: &str) -> ProviderControlStateSelectorV1 {
        ProviderControlStateSelectorV1::CanonicalSession {
            provider_id: self.provider.as_str().to_owned(),
            registration_revision: 1,
            canonical_provider_id: provider.to_owned(),
            session_id: session.to_owned(),
        }
    }

    fn context(
        &self,
        request: &ProviderControlRequestV1,
        request_id: &str,
    ) -> (RequestContext, CancellationSignal) {
        let now = tracedecay_contracts::now_micros();
        let expiry = UtcMicros(now.0 + 30_000_000);
        let operation =
            tracedecay_contracts::retained_surface_application_operation(request.operation())
                .unwrap();
        let scope = self.port.inputs.mounted_scope.clone();
        let grant = CapabilityGrantSnapshot::new(
            CapabilityGrantId::new("grant.source-control").unwrap(),
            1,
            ManifestDigest::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
            ActorId::new("actor.issuer").unwrap(),
            UtcMicros(now.0 - 1),
            expiry,
            scope.clone(),
            BTreeSet::from([operation.capability_id().clone()]),
            BTreeSet::from([operation.use_case_id().clone()]),
            DisclosureClass::Evidence,
        )
        .unwrap();
        (
            RequestContext::new(
                ActorId::new("actor.source-control").unwrap(),
                scope,
                grant,
                RequestId::new(request_id).unwrap(),
                Deadline::new(expiry).unwrap(),
                CancellationContext::active("cancel.source-control").unwrap(),
            )
            .unwrap(),
            CancellationSignal::active("cancel.source-control").unwrap(),
        )
    }

    async fn execute(
        &self,
        request: &ProviderControlRequestV1,
        context: &RequestContext,
        signal: &CancellationSignal,
    ) -> Result<ApplicationOutcome<RetainedSurfaceResultV1>, RetainedSurfaceExecutionErrorV1> {
        let operation =
            tracedecay_contracts::retained_surface_application_operation(request.operation())
                .unwrap();
        self.port
            .execute_provider_control(
                RetainedSurfaceExecutionContextV1 {
                    request_context: context,
                    cancellation_signal: signal,
                    operation: &operation,
                    observed_at: tracedecay_contracts::now_micros(),
                },
                request,
            )
            .await
    }
}

fn assert_original_provenance_unavailable<T>(result: Result<T, ProviderHistoryErrorV1>) {
    assert!(matches!(
        result,
        Err(ProviderHistoryErrorV1::Unavailable(
            ORIGINAL_PROVENANCE_UNAVAILABLE
        ))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_ingestion_and_retained_locators_do_not_supply_original_provenance() {
    let fixture = CanonicalSourceFixture::new().await;
    let (selector, _) = fixture.retain_untrusted_source_claim();
    assert_eq!(
        fixture.attribution.origin_scope,
        OriginScopeEvidence::IngestionOnly
    );
    let control = operation_control();
    let destination = fixture.original.bridge.destination(SESSION).unwrap();
    assert_original_provenance_unavailable(fixture.original.validate_live_mount());
    assert_original_provenance_unavailable(
        fixture.original.authorizes_session(SESSION, &destination),
    );
    assert_original_provenance_unavailable(
        fixture
            .authority()
            .current_destination_scope("claude", &control),
    );
    let observations = fixture.canonical_session_db.observation_store();
    let reader = ProviderHistoryReaderV1 {
        bridge: fixture.original.bridge.as_ref(),
        observations: &observations,
        dispositions: fixture.canonical_dispositions.as_ref(),
        original_authority: fixture.original.as_ref(),
        journal: fixture.journal.as_ref(),
        provider_id: &fixture.provider,
        policy_revision: 1,
    };
    assert_original_provenance_unavailable(reader.select_recent_page(&destination, 1, &control));
    let failure = fixture
        .port
        .resolve_source(&selector, true, &control)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        *failure.stage,
        ControlFailureStageV1::Authority(ProviderHistoryErrorV1::Unavailable(
            ORIGINAL_PROVENANCE_UNAVAILABLE
        ))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_controls_refuse_without_publishing_commands_or_deletion_fences() {
    let fixture = CanonicalSourceFixture::new().await;
    let (selector, claimed) = fixture.retain_untrusted_source_claim();
    let requests = [
        ProviderControlRequestV1::Feedback(ProviderFeedbackRequestV1 {
            source: selector.clone(),
            signal: ProviderControlFeedbackSignalV1::Helpful,
            weight: "1".to_owned(),
            evidence_refs: Vec::new(),
            occurred_at: tracedecay_contracts::now_micros(),
        }),
        ProviderControlRequestV1::Correction(ProviderCorrectionRequestV1 {
            source: selector.clone(),
            expected_source_revision: "revision.unavailable".to_owned(),
            correction: ProviderControlCorrectionV1::MarkIncorrect {
                revoked_at: tracedecay_contracts::now_micros(),
            },
            reason: "An admitted transcript is not original-event authority.".to_owned(),
            evidence_refs: Vec::new(),
        }),
        ProviderControlRequestV1::DeleteBySource(ProviderDeleteBySourceRequestV1 {
            source: selector.clone(),
            expected_fence_revision: 0,
            mode: ProviderControlDeletionModeV1::RemoveInfluence,
            include_snapshots: true,
        }),
        ProviderControlRequestV1::Inspection(ProviderInspectionRequestV1 {
            state: fixture.canonical_selector("claude", SESSION),
            selection: ProviderControlInspectionSelectorV1::SourceInfluence {
                source: selector.clone(),
            },
            maximum_items: 1,
            maximum_bytes: 16_384,
            cursor: None,
        }),
    ];
    for (index, request) in requests.iter().enumerate() {
        let (context, signal) = fixture.context(request, &format!("request.source-denial.{index}"));
        let error = fixture
            .execute(request, &context, &signal)
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            RetainedSurfaceExecutionErrorV1::Unavailable { detail }
                if detail.contains(ORIGINAL_PROVENANCE_UNAVAILABLE)
        ));
        assert!(
            super::super::feedback_receipt::retained_feedback_assertion(
                fixture.ledger.path(),
                &context,
                &operation_control()
            )
            .is_err()
        );
        assert!(
            super::super::feedback_receipt::retained_deletion_command(
                fixture.ledger.path(),
                &context,
                &operation_control()
            )
            .is_err()
        );
    }
    assert!(
        fixture
            .journal
            .read_provider_source_fence(
                fixture.provider.as_str(),
                &original_source_fence_digest(&claimed).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    let stored = fixture
        .canonical_session_db
        .observation_store()
        .replay_observations(ObservationReplayRequest::new(0, 2).unwrap())
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(canonical_attribution(&stored[0]), fixture.attribution);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_source_inventory_requires_original_provenance_for_export_and_restore() {
    let fixture = CanonicalSourceFixture::new().await;
    let control = operation_control();
    let scope = fixture
        .authority()
        .authorize_canonical_session(&fixture.provider, 1, "claude", SESSION, &control)
        .await
        .unwrap();
    assert_original_provenance_unavailable(
        fixture
            .authority()
            .authorize_source_inventory(
                &scope,
                std::slice::from_ref(&fixture.attribution.source),
                &control,
            )
            .await,
    );
    let retained: RecallSourceAttributionV1 =
        serde_json::from_value(source_attribution_json(&fixture.attribution).unwrap()).unwrap();
    assert_original_provenance_unavailable(
        fixture
            .authority()
            .authorize_retained_source_inventory(&scope, &[retained], &control)
            .await,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_canonical_session_authorizes_state_without_original_event_proof() {
    let fixture = CanonicalSourceFixture::new().await;
    let control = operation_control();
    let retained = fixture
        .authority()
        .authorize_canonical_session(&fixture.provider, 1, "claude", SESSION, &control)
        .await
        .unwrap();
    assert_eq!(retained.provider_id, fixture.provider);
    assert_eq!(retained.registration_revision, 1);
    assert_eq!(
        retained.delivery_scope,
        fixture.original.bridge.destination(SESSION).unwrap()
    );
    fixture
        .original
        .authorize_registered_canonical_session(SESSION, &retained.delivery_scope, &control)
        .unwrap();
    assert!(matches!(
        fixture.original.authorize_registered_canonical_session(
            "another-session",
            &retained.delivery_scope,
            &control,
        ),
        Err(ProviderHistoryErrorV1::Ineligible(
            "canonical session namespace"
        ))
    ));
    let request = ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
        state: fixture.canonical_selector("claude", SESSION),
        requested_checks: vec![ProviderControlHealthCheckV1::State],
    });
    let (context, signal) = fixture.context(&request, "request.registered-state");
    let ApplicationOutcome::Evidence(evidence) =
        fixture.execute(&request, &context, &signal).await.unwrap()
    else {
        panic!("registered state produces an evidence outcome")
    };
    let Some(RetainedSurfaceResultV1::ProviderControl(result)) = evidence.payload else {
        panic!("registered state produces a provider control result")
    };
    result.validate_for(&request).unwrap();
    assert_ne!(result.scope.agent_session_id, SESSION);
    assert_eq!(
        result.scope.agent_session_id,
        retained.delivery_scope.agent_session_id
    );
    assert_eq!(
        result.scope.agent_session_id,
        result.scope.agent_session_id_for_canonical_session(SESSION)
    );
    assert_eq!(
        result.terminal,
        ProviderControlTerminalV1::ProviderUnavailable
    );
    assert!(matches!(
        result.result,
        ProviderControlOperationResultV1::Health(None)
    ));
    assert_original_provenance_unavailable(fixture.original.validate_live_mount());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_session_lookup_denies_missing_foreign_provider_and_foreign_project_rows() {
    let fixture = CanonicalSourceFixture::new().await;
    for (provider, session) in [("claude", "missing-session"), ("codex", SESSION)] {
        assert!(matches!(
            fixture
                .authority()
                .authorize_canonical_session(
                    &fixture.provider,
                    1,
                    provider,
                    session,
                    &operation_control(),
                )
                .await,
            Err(ProviderHistoryErrorV1::Ineligible(
                "registered canonical session missing"
            ))
        ));
    }
    let foreign_root = fixture.temporary.path().join("foreign-repository");
    repository(&foreign_root);
    let foreign_root = std::fs::canonicalize(foreign_root).unwrap();
    let foreign_project = ProjectId::new("project.foreign-source-control").unwrap();
    let foreign_runtime = fixture
        .runtime
        .sibling_project(&foreign_root, foreign_project.clone())
        .await
        .unwrap();
    tracedecay_runtime_core::storage::write_repository_identity_marker(
        &foreign_root,
        foreign_project.as_str(),
    )
    .unwrap();
    let foreign = admit_transcript(
        &foreign_runtime,
        &foreign_root,
        &foreign_project,
        &fixture.temporary.path().join("foreign-host"),
        "foreign-project-session",
    )
    .await;
    assert_eq!(
        foreign.observation().source().session_id().as_str(),
        "foreign-project-session"
    );
    assert!(matches!(
        fixture
            .authority()
            .authorize_canonical_session(
                &fixture.provider,
                1,
                "claude",
                "foreign-project-session",
                &operation_control(),
            )
            .await,
        Err(ProviderHistoryErrorV1::Ineligible(
            "registered canonical session missing"
        ))
    ));
    let request = ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
        state: fixture.canonical_selector("claude", "foreign-project-session"),
        requested_checks: vec![ProviderControlHealthCheckV1::State],
    });
    let (context, signal) = fixture.context(&request, "request.foreign-canonical-session");
    assert!(matches!(
        fixture.execute(&request, &context, &signal).await,
        Err(RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_session_authority_denies_stale_project_binding_in_admitted_shard() {
    let fixture = CanonicalSourceFixture::new().await;
    let registered = &fixture.canonical_session_db;
    let mut session = registered
        .get_session("claude", SESSION)
        .await
        .unwrap()
        .unwrap();
    let current_project = session.project_key.clone();
    assert_eq!(
        current_project,
        fixture.port.inputs.mounted_scope.project_id.as_str()
    );

    // Re-enrollment can leave an earlier session owner until projection rebinds
    // the row. Keep the admitted row's actual key and transcript fields intact.
    let earlier_project = ProjectId::new("project.earlier-source-control").unwrap();
    session.project_key = earlier_project.as_str().to_owned();
    assert!(registered.upsert_session(&session).await);
    let retained = registered
        .get_session("claude", SESSION)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.provider, session.provider);
    assert_eq!(retained.session_id, session.session_id);
    assert_eq!(retained.project_key, earlier_project.as_str());
    assert_eq!(retained.project_path, session.project_path);
    assert_eq!(retained.transcript_path, session.transcript_path);
    assert!(matches!(
        fixture
            .authority()
            .authorize_canonical_session(
                &fixture.provider,
                1,
                "claude",
                SESSION,
                &operation_control(),
            )
            .await,
        Err(ProviderHistoryErrorV1::Ineligible(
            "canonical session project"
        ))
    ));
    let request = ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
        state: fixture.canonical_selector("claude", SESSION),
        requested_checks: vec![ProviderControlHealthCheckV1::State],
    });
    let (context, signal) = fixture.context(&request, "request.stale-canonical-project");
    assert!(matches!(
        fixture.execute(&request, &context, &signal).await,
        Err(RetainedSurfaceExecutionErrorV1::NotFoundOrNotAuthorized)
    ));

    session.project_key = current_project;
    assert!(registered.upsert_session(&session).await);
    let authorized = fixture
        .authority()
        .authorize_canonical_session(
            &fixture.provider,
            1,
            "claude",
            SESSION,
            &operation_control(),
        )
        .await
        .unwrap();
    assert_eq!(
        authorized.delivery_scope,
        fixture.original.bridge.destination(SESSION).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_session_authority_rejects_foreign_namespace_and_cancellation() {
    let fixture = CanonicalSourceFixture::new().await;
    let destination = fixture.original.bridge.destination(SESSION).unwrap();
    let scope = &fixture.port.inputs.mounted_scope;
    let foreign = ResolvedScope::new(
        scope.project_id.clone(),
        scope.repository_id.clone(),
        WorktreeId::new("worktree.foreign-source-control").unwrap(),
        scope.reference.clone(),
    )
    .unwrap();
    let foreign = crate::retained_owner::observation_journey::exact_scope_for_session(
        &fixture.port.inputs.profile_id,
        &foreign,
        SESSION,
    )
    .unwrap();
    assert_ne!(foreign, destination);
    assert!(matches!(
        fixture.original.authorize_registered_canonical_session(
            SESSION,
            &foreign,
            &operation_control(),
        ),
        Err(ProviderHistoryErrorV1::Ineligible("destination checkout"))
    ));
    let request = ProviderControlRequestV1::Health(ProviderHealthRequestV1 {
        state: fixture.canonical_selector("claude", SESSION),
        requested_checks: vec![ProviderControlHealthCheckV1::State],
    });
    let (context, signal) = fixture.context(&request, "request.cancelled-canonical-session");
    signal.cancel(tracedecay_contracts::now_micros());
    assert!(matches!(
        fixture.execute(&request, &context, &signal).await,
        Err(RetainedSurfaceExecutionErrorV1::Cancelled(
            CancellationStage::BeforeEffect
        ))
    ));
}
