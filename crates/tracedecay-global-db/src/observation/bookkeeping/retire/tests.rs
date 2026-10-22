use super::*;
use crate::tests::harness::RegisteredGlobalDbHarness;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1, CanonicalObservationFactV1,
    CanonicalObservationRelationsV1, CanonicalUnknownStateV1, ComponentVersion,
    DurableObservationV1, ObservationId, ObservationIdentityMaterialV1,
    ObservationOrderingDomainV1, ObservationSourceCursorV1, ObservationSourceGenerationV1,
    ObservationSourceRangeV1, PayloadReferenceV1, ProjectionGenerationId, ProviderId,
    RetentionClass, SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1,
    SanitizerDispositionV1, SensitivityV1, SessionId, UtcMicros,
};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_store::{
    AnchoredObservationWrite, ObservationStore, ObservationWrite,
    build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
};

async fn seed(db: &RegisteredGlobalDb, index: u64) -> DurableObservationV1 {
    seed_facts(
        db,
        index,
        vec![CanonicalObservationFactV1::Unknown {
            native_kind: "future_event".into(),
            state: CanonicalUnknownStateV1::Unsupported,
        }],
    )
    .await
}

async fn seed_facts(
    db: &RegisteredGlobalDb,
    index: u64,
    facts: Vec<CanonicalObservationFactV1>,
) -> DurableObservationV1 {
    let provider = ProviderId::new("codex").unwrap();
    let session = SessionId::new(format!("session.retirement.{index}")).unwrap();
    let native = ObservationId::new(format!("record.retirement.{index}")).unwrap();
    let range = ObservationSourceRangeV1::new(0, 100).unwrap();
    let envelope = CanonicalObservationEnvelopeV1::new(
        provider.clone(),
        "event_msg",
        native.clone(),
        CanonicalObservationRelationsV1::new(session.clone()),
        facts,
        CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
    )
    .unwrap();
    let payload = serde_json::to_value(envelope).unwrap();
    seed_payload(db, index, payload).await
}

async fn seed_payload(
    db: &RegisteredGlobalDb,
    index: u64,
    payload: serde_json::Value,
) -> DurableObservationV1 {
    let provider = ProviderId::new("codex").unwrap();
    let session = SessionId::new(format!("session.retirement.{index}")).unwrap();
    let native = ObservationId::new(format!("record.retirement.{index}")).unwrap();
    let range = ObservationSourceRangeV1::new(0, 100).unwrap();
    let observation = DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            ObservationSourceIdentityV1::for_provider(provider, session).unwrap(),
            ObservationScopeV1::Profile,
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            native,
        )
        .unwrap(),
        SanitizationReceiptV1::new(
            SanitizationReceiptRefV1::new(
                SanitizationReceiptId::new(format!("receipt.retirement.{index}")).unwrap(),
                ComponentVersion::new("sanitizer.retirement.v1").unwrap(),
            )
            .unwrap(),
            SanitizerDispositionV1::Accepted,
            SensitivityV1::NonSensitive,
            Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
        )
        .unwrap(),
        RetentionClass::new("transcript.fixture").unwrap(),
        payload,
    )
    .unwrap();
    let cursor = ObservationSourceCursorV1::for_ordering(
        observation.source().clone(),
        observation.scope().clone(),
        observation.identity().generation(),
        observation.identity().ordering_domain(),
        100,
    )
    .unwrap();
    let generation = ProjectionGenerationId::new("projection.retirement.v1").unwrap();
    let authorization =
        build_observation_resolution_authorization_v1(&observation, "retirement").unwrap();
    let anchor = build_observation_retrieval_anchor(
        &observation,
        generation.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    db.observation_store()
        .persist_observation(
            AnchoredObservationWrite::new(
                ObservationWrite::new(observation.clone(), None, cursor).unwrap(),
                anchor,
                generation,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    observation
}

async fn count(db: &RegisteredGlobalDb, table: &str) -> i64 {
    let snapshot = db.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(&format!("SELECT count(*) FROM {table}"), ())
        .await
        .unwrap();
    rows.next().await.unwrap().unwrap().get(0).unwrap()
}

#[asupersync::test]
async fn retirement_plan_apply_is_confirmed_and_idempotent() {
    let harness = RegisteredGlobalDbHarness::open_without_relation_graph("retirement-kernel").await;
    let db = &harness.registered;
    let observation = seed(db, 1).await;
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(!plan.digest().is_empty());
    assert_eq!(count(db, "observations").await, 1, "planning is read-only");
    assert!(
        db.apply_observation_retirement(&plan, "wrong")
            .await
            .is_err()
    );
    assert!(plan.eligible());
    for expected in [
        ObservationRetirementOutcome::Applied { observations: 1 },
        ObservationRetirementOutcome::AlreadyApplied,
    ] {
        assert_eq!(
            db.apply_observation_retirement(&plan, plan.digest())
                .await
                .unwrap(),
            expected
        );
    }
    for table in [
        "observations",
        "projection_queue",
        "observation_repository_provenance",
        "observation_retrieval_anchors",
    ] {
        assert_eq!(count(db, table).await, 0, "retirement removes {table}");
    }
    // The source frontier is never rewound or fabricated by retirement.
    assert_eq!(count(db, "source_cursors").await, 1);
    let writer = db.writer_connection().unwrap();
    let mut rows = writer
        .query(
            "SELECT seq FROM sqlite_sequence WHERE name='observations'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        1
    );
    drop(rows);
    let second = seed(db, 2).await;
    let mut rows = writer
        .query(
            "SELECT sequence FROM observations WHERE observation_id=?1",
            params![second.observation_id().as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        2
    );
    drop(rows);
    assert!(
        writer
            .execute(
                "DELETE FROM observations WHERE observation_id=?1",
                params![second.observation_id().as_str()]
            )
            .await
            .is_err(),
        "immutable guards restored"
    );
}

#[asupersync::test]
async fn retirement_settled_tail_preserves_authority_frontier() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-settled").await;
    let db = &harness.registered;
    let observation = seed(db, 9).await;
    db.observation_store()
        .project_observation(observation.observation_id())
        .await
        .unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
    let snapshot = db.read_snapshot().await.unwrap();
    crate::schema_contract::invariants::validate_authority_rows_exhaustive(&snapshot)
        .await
        .unwrap();
}

fn marker(observation: &DurableObservationV1) -> ProjectPruneMarker {
    ProjectPruneMarker {
        source: observation.source().clone(),
        scope: observation.scope().clone(),
        approved_plan_digest: "approved-project-prune".into(),
    }
}

#[asupersync::test]
async fn retirement_rollback_preserves_receipt_authority_and_guards() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-rollback").await;
    let db = &harness.registered;
    let observation = seed(db, 20).await;
    let writer = db.writer_connection().unwrap();
    writer
        .execute(
            "INSERT INTO observation_source_presence VALUES ('source.fixture',?1,'1',0)",
            params![observation.observation_id().as_str()],
        )
        .await
        .unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(plan.eligible());
    let key = format!("{RECEIPT_PREFIX}{}", plan.digest());
    assert_eq!(
        plan.tables()
            .iter()
            .find(|size| size.table == "observation_source_presence")
            .unwrap()
            .rows,
        1
    );
    writer.execute_batch("CREATE TRIGGER injected_mid_cascade BEFORE DELETE ON observation_repository_provenance BEGIN SELECT RAISE(ABORT,'injected cascade failure'); END;").await.unwrap();
    assert!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .is_err()
    );
    assert_eq!(
        count(db, "observation_retired_sequences").await,
        0,
        "coverage rolls back with evidence"
    );
    for table in [
        "observations",
        "projection_queue",
        "observation_repository_provenance",
        "observation_retrieval_anchors",
        "observation_source_presence",
    ] {
        assert_eq!(count(db, table).await, 1, "rollback restores {table}");
    }
    let mut rows = writer
        .query(
            "SELECT count(*) FROM session_backfill_meta WHERE key=?1",
            params![key.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0,
        "receipt rolls back with evidence"
    );
    drop(rows);
    let snapshot = db.read_snapshot().await.unwrap();
    assert!(
        crate::schema_contract::invariants::authority_invariant_triggers_intact(&snapshot)
            .await
            .unwrap()
    );
    drop(snapshot);
    writer
        .execute_batch("DROP TRIGGER injected_mid_cascade;")
        .await
        .unwrap();
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
    let mut rows = writer
        .query(
            "SELECT value FROM session_backfill_meta WHERE key=?1",
            params![key],
        )
        .await
        .unwrap();
    assert!(
        rows.next().await.unwrap().is_some(),
        "committed retirement installs its receipt"
    );
    drop(rows);
    for table in [
        "observations",
        "projection_queue",
        "observation_repository_provenance",
        "observation_retrieval_anchors",
        "observation_source_presence",
    ] {
        assert_eq!(count(db, table).await, 0, "retirement removes {table}");
    }
    assert_eq!(count(db, "retrieval_anchor_dispositions").await, 1);
}

#[asupersync::test]
async fn retirement_changed_dependency_digest_is_refused_without_partial_delete() {
    let harness = RegisteredGlobalDbHarness::open_without_relation_graph("retirement-digest").await;
    let db = &harness.registered;
    let observation = seed(db, 21).await;
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    db.writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO observation_source_presence VALUES ('new-source',?1,'1',0)",
            params![observation.observation_id().as_str()],
        )
        .await
        .unwrap();
    assert!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .is_err()
    );
    assert_eq!(count(db, "observations").await, 1);
    assert_eq!(count(db, "projection_queue").await, 1);
}

struct DeferredTarget;
impl HandoffProofValidator for DeferredTarget {
    async fn validate(&self, _: &TargetCopyProof) -> ProjectionStoreResult<HandoffProofStatus> {
        Ok(HandoffProofStatus::Deferred)
    }
}

#[asupersync::test]
async fn retirement_handoff_requires_live_target_fence_and_matching_copies() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-handoff").await;
    let db = &harness.registered;
    let observation = seed(db, 22).await;
    let proof = TargetCopyProof {
        target_store_identity: "missing-target".into(),
        target_incarnation: "previous-incarnation".into(),
        retention_fence: "held-by-target-validator".into(),
        copies: vec![TargetObservationCopy {
            source_observation_id: observation.observation_id().clone(),
            target_observation_id: observation.observation_id().clone(),
            payload_digest: observation.payload_reference().digest().as_str().to_owned(),
        }],
    };
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::CrossStoreOwnerHandoff(proof),
        )
        .await
        .unwrap();
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    assert_eq!(
        db.apply_observation_retirement_with_handoff(&plan, plan.digest(), &DeferredTarget)
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    assert_eq!(count(db, "observations").await, 1);
    assert_eq!(count(db, "projection_queue").await, 1);
    assert_eq!(count(db, "source_cursor_advances").await, 0);
}

#[asupersync::test]
async fn retirement_refuses_useful_codex_and_default_lifecycle_loss() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-classifier").await;
    let db = &harness.registered;
    let observation = seed_facts(
        db,
        23,
        vec![CanonicalObservationFactV1::Message {
            role: tracedecay_domain::CanonicalMessageRoleV1::User,
            content: serde_json::json!("retained conversation"),
            model: None,
            timestamp: Some(1),
        }],
    )
    .await;
    for authorization in [
        ObservationRetirementAuthorization::UnsupportedCodexRecord,
        ObservationRetirementAuthorization::LifecycleRetention,
    ] {
        let plan = db
            .plan_observation_retirement(&[observation.observation_id().clone()], authorization)
            .await
            .unwrap();
        assert!(!plan.eligible());
        assert_eq!(
            db.apply_observation_retirement(&plan, plan.digest())
                .await
                .unwrap(),
            ObservationRetirementOutcome::Deferred
        );
    }
    assert_eq!(count(db, "observations").await, 1);
}

#[asupersync::test]
async fn retirement_cost_stays_index_bounded_and_refuses_missing_reverse_index() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-bounded").await;
    let db = &harness.registered;
    let observation = seed(db, 24).await;
    let writer = db.writer_connection().unwrap();
    writer.execute_batch("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<20000) INSERT INTO observation_source_presence SELECT 'large-unrelated-source',printf('unrelated-%08d',i),'1',i FROM n;").await.unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert_eq!(
        plan.tables()
            .iter()
            .find(|size| size.table == "observation_source_presence")
            .unwrap()
            .rows,
        0
    );
    assert!(plan.eligible());
    writer
        .execute_batch("DROP INDEX idx_retirement_observation_source_presence; ANALYZE observation_source_presence;")
        .await
        .unwrap();
    install_indexes(&writer).await.unwrap();
    let snapshot = db.read_snapshot().await.unwrap();
    crate::schema_contract::validate_authority_schema_contract(&snapshot)
        .await
        .unwrap();
    drop(snapshot);
    assert!(
        db.plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord
        )
        .await
        .is_err(),
        "index loss must not silently enable a full-table scan"
    );
    assert!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .is_err()
    );
    assert_eq!(count(db, "observations").await, 1);
}

#[asupersync::test]
async fn retirement_readmission_never_rewinds_a_retired_stream_tail() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-readmission").await;
    let db = &harness.registered;
    let observation = seed(db, 30).await;
    db.observation_store()
        .project_observation(observation.observation_id())
        .await
        .unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    db.apply_observation_retirement(&plan, plan.digest())
        .await
        .unwrap();
    crate::schema_contract::invariants::ensure_authority_invariants(
        db.runtime_database(),
        true,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        1,
        "a completed stream identity is not reset by payload retirement"
    );
}

#[asupersync::test]
async fn retirement_preserves_direct_anchor_consumers_without_reverse_lineage() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-anchor-pin").await;
    let db = &harness.registered;
    let observation = seed(db, 31).await;
    let other = seed(db, 32).await;
    let writer = db.writer_connection().unwrap();
    let a = tracedecay_domain::derive_exact_observation_anchor_id(
        observation.scope(),
        observation.observation_id(),
    )
    .unwrap();
    let b = tracedecay_domain::derive_exact_observation_anchor_id(
        other.scope(),
        other.observation_id(),
    )
    .unwrap();
    let transaction = db.begin_write_transaction().await.unwrap();
    transaction.execute("INSERT INTO session_temporal_generations(session_id,generation,state,frozen_watermarks_json,created_at) VALUES ('session.direct-anchor-pin',1,'building','{}',1)", ()).await.unwrap();
    transaction.execute("INSERT INTO session_assertions(session_id,generation,assertion_id,assertion_kind,subject_anchor_id,object_anchor_id,knowledge_at,valid_time_json,evidence_json) VALUES ('session.direct-anchor-pin',1,'assertion.pin','supports',?1,?2,1,'{\"kind\":\"unknown\"}','{}')", params![a.as_str(),b.as_str()]).await.unwrap();
    transaction.commit().await.unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(
        !plan.eligible(),
        "a live direct FK consumer is protected without trusting reverse-map completeness"
    );
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    let mut rows = writer
        .query(
            "SELECT count(*) FROM retrieval_anchor_dispositions WHERE anchor_id=?1",
            params![a.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0
    );
}

#[asupersync::test]
async fn retirement_preserves_direct_derived_evidence_without_reverse_lineage() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-derived-pin").await;
    let db = &harness.registered;
    let observation = seed(db, 33).await;
    let anchor = tracedecay_domain::derive_exact_observation_anchor_id(
        observation.scope(),
        observation.observation_id(),
    )
    .unwrap();
    let transaction = db.begin_write_transaction().await.unwrap();
    transaction.execute("INSERT INTO session_temporal_generations(session_id,generation,state,frozen_watermarks_json,created_at) VALUES ('session.derived-pin',1,'building','{}',1)", ()).await.unwrap();
    transaction.execute("INSERT INTO session_derived_evidence(session_id,generation,evidence_kind,first_occurrence_id,evidence_id,retrieval_anchor_id,last_occurrence_id,algorithm_version,configuration_digest,member_count,member_digest,evidence_json) VALUES ('session.derived-pin',1,'span','first.pin','evidence.pin',?1,'last.pin','algorithm.pin','configuration.pin',1,'members.pin','{}')", params![anchor.as_str()]).await.unwrap();
    transaction.commit().await.unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(
        plan.candidates()[0]
            .blockers
            .contains(&RetirementBlocker::RetainedAnchorDerivative)
    );
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    assert_eq!(count(db, "observations").await, 1);
}

#[asupersync::test]
async fn retirement_lifecycle_preserves_materialized_message_workflow_and_usage() {
    use tracedecay_domain::{
        CanonicalMessageRoleV1, CanonicalWorkflowSemanticKindV1, ProviderUsageCounterSemanticsV1,
        ProviderUsageCountersV1, ProviderUsageModelV1, ProviderUsageScopeV1,
    };
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-projected-cascade")
            .await;
    let db = &harness.registered;
    let observation = seed_facts(
        db,
        40,
        vec![
            CanonicalObservationFactV1::Message {
                role: CanonicalMessageRoleV1::User,
                content: serde_json::json!("retained canonical body ".repeat(600)),
                model: None,
                timestamp: Some(1),
            },
            CanonicalObservationFactV1::WorkflowLifecycle {
                semantic_kind: CanonicalWorkflowSemanticKindV1::Goal,
                provider_reference: Some("goal.retire".into()),
                item_id: None,
                parent_reference: None,
                list_reference: None,
                state: None,
                status: Some("active".into()),
                item_order: None,
                revision: None,
                event_sequence: Some(1),
                content: Some(serde_json::json!("finish the storage cleanup")),
            },
            CanonicalObservationFactV1::ProviderUsage {
                model: ProviderUsageModelV1::Known {
                    model: "fixture-model".into(),
                },
                native_scope: ProviderUsageScopeV1::Request,
                counter_semantics: ProviderUsageCounterSemanticsV1::Delta,
                counters: ProviderUsageCountersV1::Known {
                    input_tokens: Some(10),
                    output_tokens: Some(3),
                    cache_read_tokens: None,
                    cache_write_tokens: None,
                    reasoning_tokens: None,
                    total_tokens: Some(13),
                },
                request_id: Some(ObservationId::new("request.retire").unwrap()),
                native_kind: "token_count".into(),
                native_field: "usage".into(),
            },
        ],
    )
    .await;
    db.observation_store()
        .project_observation(observation.observation_id())
        .await
        .unwrap();
    let transaction = db.begin_write_transaction().await.unwrap();
    let mut rows = transaction
        .query(
            "SELECT sequence FROM observations WHERE observation_id=?1",
            params![observation.observation_id().as_str()],
        )
        .await
        .unwrap();
    let sequence: u64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    drop(rows);
    crate::observation_projection::apply_provider_usage_effects(
        &transaction,
        sequence,
        &observation,
    )
    .await
    .unwrap();
    transaction.execute("INSERT INTO observation_projection_aliases SELECT projector_version,observation_id,output_provider,output_message_id FROM observation_projection_provenance WHERE observation_id=?1 LIMIT 1", params![observation.observation_id().as_str()]).await.unwrap();
    transaction
        .execute(
            "INSERT INTO observation_source_presence VALUES ('source.projected',?1,'1',0)",
            params![observation.observation_id().as_str()],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO observation_admission_refusals VALUES (?1,'sha256:refused',?2,1)",
            params![
                observation.observation_id().as_str(),
                observation.payload_reference().digest().as_str()
            ],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::LifecycleRetention,
        )
        .await
        .unwrap();
    for table in [
        "observation_projection_provenance",
        "observation_projection_aliases",
        "observation_workflow_facts",
        "observation_provider_usage",
        "observation_source_presence",
        "observation_admission_refusals",
        "session_canonical_body_references",
        "observations",
        "observation_retrieval_anchors",
        "observation_repository_provenance",
    ] {
        let size = plan
            .tables()
            .iter()
            .find(|size| size.table == table)
            .unwrap();
        assert!(
            size.rows > 0 && size.bytes > 0,
            "fixture must actually populate and size {table}"
        );
    }
    assert!(count(db, "lcm_raw_messages").await > 0);
    assert!(count(db, "session_canonical_bodies").await > 0);
    assert!(
        !plan.eligible(),
        "materialized temporal evidence remains protected: {:?}",
        plan.candidates()
    );
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    assert_eq!(count(db, "observations").await, 1);
    assert!(count(db, "lcm_raw_messages").await > 0);
    assert!(
        count(db, "session_canonical_bodies").await > 0,
        "shared content and projected outputs are not partially released"
    );
}

mod external;

#[asupersync::test]
async fn retirement_queued_sequence_gap_is_explained_for_projection() {
    use tracedecay_store::ObservationProjectionStore;
    let harness = RegisteredGlobalDbHarness::open_without_relation_graph("retirement-drain").await;
    let db = &harness.registered;
    let first = seed(db, 101).await;
    let plan = db
        .plan_observation_retirement(
            &[first.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    let outcome = db
        .apply_observation_retirement(&plan, plan.digest())
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
    let next = seed(db, 102).await;
    db.observation_store()
        .project_observation(next.observation_id())
        .await
        .expect("retirement must not leave an unexplained gap in the normal projection drain");
    assert!(plan.eligible());
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        2
    );
}

#[asupersync::test]
async fn retirement_interior_sequence_gap_is_explained_for_rebuild() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-rebuild").await;
    let db = &harness.registered;
    let first = seed(db, 111).await;
    let interior = seed(db, 112).await;
    let last = seed(db, 113).await;
    for observation in [&first, &interior, &last] {
        db.observation_store()
            .project_observation(observation.observation_id())
            .await
            .unwrap();
    }
    let plan = db
        .plan_observation_retirement(
            &[interior.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    let outcome = db
        .apply_observation_retirement(&plan, plan.digest())
        .await
        .unwrap();
    let rebuilt = db.observation_store().rebuild_projection(3).await.expect(
        "retirement must not leave an unexplained gap in rebuild staging or alias validation",
    );
    assert!(rebuilt.is_complete());
    assert_eq!(rebuilt.checkpoint().last_sequence(), 3);
    assert_eq!(
        outcome,
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
    assert!(plan.eligible());
}

#[asupersync::test]
async fn retirement_refuses_missing_source_occurrence_index_on_populated_store() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-occurrence-index").await;
    let db = &harness.registered;
    let materialized = seed_facts(
        db,
        121,
        vec![CanonicalObservationFactV1::Message {
            role: tracedecay_domain::CanonicalMessageRoleV1::User,
            content: serde_json::json!("a retained unrelated occurrence"),
            model: None,
            timestamp: Some(1),
        }],
    )
    .await;
    db.observation_store()
        .project_observation(materialized.observation_id())
        .await
        .unwrap();
    let writer = db.writer_connection().unwrap();
    writer.execute("INSERT INTO session_temporal_generations(session_id,generation,state,frozen_watermarks_json,created_at) VALUES (?1,1,'building','{}',1)", params!["session.retirement.121"]).await.unwrap();
    writer.execute("INSERT INTO session_occurrences(session_id,generation,occurrence_id,source_observation_id,source_sequence,source_provider,projection_output_ordinal,retrieval_anchor_id,copied_from_anchor_ids_json,role,knowledge_at,valid_time_json,evidence_json,sanitized_content_digest,sanitized_content_bytes,index_text) SELECT 'session.retirement.121',1,'occurrence.index-loss',o.observation_id,o.sequence,'codex',0,a.anchor_id,'[]','user',1,'{\"kind\":\"unknown\"}','{}','0000000000000000000000000000000000000000000000000000000000000000',0,'' FROM observations o JOIN observation_retrieval_anchors a USING(observation_id) WHERE o.observation_id=?1", params![materialized.observation_id().as_str()]).await.unwrap();
    assert_eq!(
        count(db, "session_occurrences").await,
        1,
        "fixture must populate the actual occurrence table"
    );
    let candidate = seed(db, 122).await;
    let ids = [candidate.observation_id().clone()];
    let plan = db
        .plan_observation_retirement(
            &ids,
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    let writer = db.writer_connection().unwrap();
    writer
        .execute_batch("DROP INDEX idx_retirement_occurrences;")
        .await
        .unwrap();
    install_indexes(&writer).await.unwrap();
    let snapshot = db.read_snapshot().await.unwrap();
    crate::schema_contract::validate_authority_schema_contract(&snapshot)
        .await
        .unwrap();
    drop(snapshot);
    assert!(
        db.plan_observation_retirement(
            &ids,
            ObservationRetirementAuthorization::UnsupportedCodexRecord
        )
        .await
        .is_err(),
        "a missing source_observation_id index must refuse instead of scanning populated occurrences"
    );
    assert!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .is_err(),
        "apply must recheck the source occurrence index before mutation"
    );
    assert_eq!(count(db, "observations").await, 2);
}

mod hydration_budget;

mod privacy_rescan;

#[asupersync::test]
async fn retirement_public_api_rejects_fabricated_project_prune_for_live_and_user_sources() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-prune-authority").await;
    let db = &harness.registered;
    for (index, root) in [(51, "/live/project"), (52, "user")] {
        let observation = seed_facts(
            db,
            index,
            vec![CanonicalObservationFactV1::Session {
                project_path: Some(root.into()),
                location_path: Some(root.into()),
                transcript_path: None,
                title: None,
                started_at: None,
                ended_at: None,
                source: None,
                native_source: None,
                profile: None,
                location_provenance: None,
            }],
        )
        .await;
        let result = db
            .plan_observation_retirement(
                &[observation.observation_id().clone()],
                ObservationRetirementAuthorization::OperatorProjectPrune(marker(&observation)),
            )
            .await;
        assert!(
            result.is_err(),
            "ordinary writer authority and an arbitrary digest cannot authorize pruning {root}"
        );
        // Even an old/internal kernel plan is not an apply capability.
        let snapshot = db.read_snapshot().await.unwrap();
        let fabricated = plan_on(
            &snapshot,
            hash(db.verified_locator()).unwrap(),
            vec![observation.observation_id().clone()],
            ObservationRetirementAuthorization::OperatorProjectPrune(marker(&observation)),
        )
        .await
        .unwrap();
        drop(snapshot);
        assert!(
            db.apply_observation_retirement(&fabricated, fabricated.digest())
                .await
                .is_err()
        );
        assert!(
            db.apply_observation_retirement_with_handoff(
                &fabricated,
                fabricated.digest(),
                &NoHandoff
            )
            .await
            .is_err()
        );
    }
    assert_eq!(count(db, "observations").await, 2);
}

#[asupersync::test]
async fn retirement_readmission_refuses_an_unexplained_tail() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-unexplained-tail").await;
    let db = &harness.registered;
    let observation = seed(db, 301).await;
    db.observation_store()
        .project_observation(observation.observation_id())
        .await
        .unwrap();
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
    // Simulate lost retirement authority, not another supported retirement.
    db.writer_connection()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER observation_retired_sequences_immutable_delete;
         DELETE FROM observation_retired_sequences;",
        )
        .await
        .unwrap();
    assert!(
        crate::schema_contract::invariants::ensure_authority_invariants(
            db.runtime_database(),
            true,
            false,
        )
        .await
        .is_err(),
        "allocated identities alone must never explain missing committed evidence"
    );
}

async fn retire_supported_fixture(db: &RegisteredGlobalDb, observation: &DurableObservationV1) {
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(plan.eligible(), "{:?}", plan.candidates());
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Applied { observations: 1 }
    );
}

#[asupersync::test]
async fn retirement_ranges_preserve_window_rebuild_and_empty_stream_frontiers() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-range-consumers").await;
    let db = &harness.registered;
    let mut observations = Vec::new();
    for index in 401..=405 {
        observations.push(seed(db, index).await);
    }
    // Bridge two independently committed ranges, then retire a queued tail.
    for index in [0, 2, 1, 4] {
        retire_supported_fixture(db, &observations[index]).await;
    }
    let batch = db
        .observation_store()
        .project_queued_observations(128)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.items.len(), 1);
    assert!(!batch.has_more);
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        4
    );
    let rebuilt = db.observation_store().rebuild_projection(5).await.unwrap();
    assert!(rebuilt.is_complete());
    assert_eq!(rebuilt.checkpoint().last_sequence(), 5);
    retire_supported_fixture(db, &observations[3]).await;
    let rebuilt = db.observation_store().rebuild_projection(5).await.unwrap();
    assert!(
        rebuilt.is_complete(),
        "an entirely retired stream is still a committed stream"
    );
    assert_eq!(rebuilt.checkpoint().last_sequence(), 5);
    crate::schema_contract::invariants::ensure_authority_invariants(
        db.runtime_database(),
        true,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        5
    );
    let successor = seed(db, 406).await;
    db.observation_store()
        .project_observation(successor.observation_id())
        .await
        .unwrap();
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        6
    );
}

#[asupersync::test]
async fn retirement_rejection_crosses_only_covered_sequences() {
    use tracedecay_store::ObservationProjectionStore;
    for explained in [true, false] {
        let harness =
            RegisteredGlobalDbHarness::open_without_relation_graph("retirement-rejection").await;
        let db = &harness.registered;
        let first = seed(db, 501).await;
        retire_supported_fixture(db, &first).await;
        let invalid = seed_payload(
            db,
            502,
            serde_json::json!({"not_a_canonical_envelope": true}),
        )
        .await;
        if !explained {
            db.writer_connection().unwrap().execute_batch("DROP TRIGGER observation_retired_sequences_immutable_delete; DELETE FROM observation_retired_sequences;").await.unwrap();
        }
        let error = db
            .observation_store()
            .project_observation(invalid.observation_id())
            .await
            .unwrap_err();
        if explained {
            assert!(
                matches!(error, ProjectionStoreError::Contract(_)),
                "{error:?}"
            );
            assert_eq!(
                db.observation_store()
                    .projection_checkpoint()
                    .await
                    .unwrap()
                    .last_sequence(),
                2
            );
            assert!(
                db.observation_store()
                    .next_queued_observation()
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(
                matches!(
                    error,
                    ProjectionStoreError::Gap {
                        expected: 1,
                        actual: 2
                    }
                ),
                "{error:?}"
            );
            assert_eq!(
                db.observation_store()
                    .projection_checkpoint()
                    .await
                    .unwrap()
                    .last_sequence(),
                0
            );
        }
    }
}

#[asupersync::test]
async fn retirement_projection_and_rebuild_refuse_unexplained_interior_gaps() {
    use tracedecay_store::ObservationProjectionStore;
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-unexplained-consumers")
            .await;
    let db = &harness.registered;
    let first = seed(db, 601).await;
    retire_supported_fixture(db, &first).await;
    let next = seed(db, 602).await;
    db.writer_connection().unwrap().execute_batch("DROP TRIGGER observation_retired_sequences_immutable_delete; DELETE FROM observation_retired_sequences;").await.unwrap();
    assert!(matches!(
        db.observation_store()
            .project_observation(next.observation_id())
            .await
            .unwrap_err(),
        ProjectionStoreError::Gap {
            expected: 1,
            actual: 2
        }
    ));
    assert!(matches!(
        db.observation_store()
            .project_queued_observations(128)
            .await
            .unwrap_err(),
        ProjectionStoreError::Gap {
            expected: 1,
            actual: 2
        }
    ));
    assert_eq!(
        db.observation_store()
            .projection_checkpoint()
            .await
            .unwrap()
            .last_sequence(),
        0
    );
    assert!(db.observation_store().rebuild_projection(2).await.is_err());
}

#[asupersync::test]
async fn offline_retirement_index_preparation_is_bounded_and_resumable() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-index-prepare").await;
    let db = &harness.registered;
    let observation = seed(db, 200).await;
    let writer = db.writer_connection().unwrap();
    writer
        .execute(
            "INSERT INTO observation_source_presence VALUES ('source.prepare',?1,'1',0)",
            [observation.observation_id().as_str()],
        )
        .await
        .unwrap();
    writer.execute_batch("DROP INDEX idx_retirement_occurrences; DROP INDEX idx_retirement_observation_source_presence;").await.unwrap();
    // Populate a reverse-lookup table before preparing; startup must leave it alone.
    install_indexes(&writer).await.unwrap();
    writer
        .execute_batch("DROP INDEX idx_retirement_occurrences;")
        .await
        .unwrap();
    let profile = db.db_path().parent().unwrap();
    let lease = tracedecay_runtime_core::lifecycle_lease::acquire_exclusive_for_profile(
        profile,
        "prepare retirement indexes test",
    )
    .unwrap();
    let plan = db.plan_retirement_index_preparation(&lease).await.unwrap();
    assert!(!plan.done);
    assert_eq!(
        plan.index_name.as_deref(),
        Some("idx_retirement_observation_source_presence")
    );
    assert_eq!(plan.rows, 1);
    assert!(
        db.apply_retirement_index_preparation(&lease, &plan, "wrong")
            .await
            .is_err()
    );
    db.apply_retirement_index_preparation(&lease, &plan, plan.digest())
        .await
        .unwrap();
    let next = db.plan_retirement_index_preparation(&lease).await.unwrap();
    assert_eq!(
        next.index_name.as_deref(),
        Some("idx_retirement_occurrences")
    );
    db.apply_retirement_index_preparation(&lease, &next, next.digest())
        .await
        .unwrap();
    assert!(
        db.plan_retirement_index_preparation(&lease)
            .await
            .unwrap()
            .done
    );
    assert!(
        db.plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord
        )
        .await
        .unwrap()
        .eligible()
    );
    let done = db.plan_retirement_index_preparation(&lease).await.unwrap();
    let harness = harness.restart().await;
    let reopened = harness
        .registered
        .plan_retirement_index_preparation(&lease)
        .await
        .unwrap();
    assert_eq!(
        done.digest(),
        reopened.digest(),
        "operator digests must survive process/runtime remounts of the same physical store"
    );
}

#[asupersync::test]
async fn offline_retirement_index_preparation_refuses_oversized_key_work() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-index-budget").await;
    let db = &harness.registered;
    let writer = db.writer_connection().unwrap();
    writer.execute_batch("DROP INDEX idx_retirement_observation_source_presence; WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1024) INSERT INTO observation_source_presence SELECT 'source.oversize',printf('%04d',i)||hex(zeroblob(32768)),'1',0 FROM n;").await.unwrap();
    let lease = tracedecay_runtime_core::lifecycle_lease::acquire_exclusive_for_profile(
        db.db_path().parent().unwrap(),
        "index work budget test",
    )
    .unwrap();
    let plan = db.plan_retirement_index_preparation(&lease).await.unwrap();
    assert_eq!(plan.rows, 1024);
    assert_eq!(plan.key_bytes, 67_137_536);
    assert!(!plan.within_budget);
    assert!(
        db.apply_retirement_index_preparation(&lease, &plan, plan.digest())
            .await
            .is_err()
    );
    let unchanged = db.plan_retirement_index_preparation(&lease).await.unwrap();
    assert_eq!(
        unchanged.index_name.as_deref(),
        Some("idx_retirement_observation_source_presence")
    );
    assert_eq!(
        plan.digest(),
        unchanged.digest(),
        "over-budget apply must leave the store unchanged"
    );
}
