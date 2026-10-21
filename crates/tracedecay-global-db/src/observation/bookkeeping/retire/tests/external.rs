use super::*;
use std::collections::BTreeSet;
use tracedecay_domain::{
    LocatorDigest, ManifestDigest, PrivacyDomainId, SourceAcquisitionCapabilitiesV1,
    SourceAcquisitionContractV1, SourceAggregateFrontierV1, SourceBindingOwnerV1, SourceBindingV1,
    SourceCaptureModeV1, SourceContentStateV1, SourceCoverageV1, SourceDefinitionV1,
    SourceDeletionSemanticsV1, SourceInstanceId, SourceNativeObjectIdV1, SourceObjectObservationV1,
    SourceObjectRevisionV1, SourcePartitionFrontierV1, SourcePartitionIdV1,
    SourceRefetchStrategyV1,
};
use tracedecay_rusqlite_runtime::repository::ExternalSourceExecutor;
use tracedecay_store::{
    ExternalSourceReadOperationV1, ExternalSourceReadResultV1, SourceCommitV1,
    SourceObjectMutationV1, SourceObjectTransitionV1, SourceObservationEvidenceV1,
    build_source_projection,
};

fn digest(label: &str) -> ManifestDigest {
    canonical_sha256(&label).unwrap()
}

// Exercise the production external-source reducer and persistence executor,
// including its slim journals and projection receipts, rather than fabricating
// journal rows with SQL. The connection opens only this harness's temp store.
fn ingest_external(db: &RegisteredGlobalDb, observation: &DurableObservationV1) {
    let definition = SourceDefinitionV1::new(
        SourceInstanceId::new("source.retirement.external").unwrap(),
        1,
        SourceAcquisitionContractV1::new(
            ProviderId::new("codex").unwrap(),
            SourceAcquisitionCapabilitiesV1::new(
                BTreeSet::from([SourceCaptureModeV1::Poll]),
                BTreeSet::from([SourceRefetchStrategyV1::WholeRoot]),
                BTreeSet::from([SourceDeletionSemanticsV1::ExplicitOnly]),
            )
            .unwrap(),
        )
        .unwrap(),
        SourceCaptureModeV1::Poll,
        SourceRefetchStrategyV1::WholeRoot,
        SourceDeletionSemanticsV1::ExplicitOnly,
        1,
    )
    .unwrap();
    let mut authorization =
        build_observation_resolution_authorization_v1(observation, "retirement").unwrap();
    authorization.privacy_domain_id = PrivacyDomainId::new("privacy.retirement.external").unwrap();
    let binding = SourceBindingV1::new(
        &definition,
        SourceBindingOwnerV1::Profile(db.binding().shard_id.profile_id.clone()),
        authorization.privacy_domain_id.clone(),
        LocatorDigest::new(digest("root").as_str()).unwrap(),
        1,
    )
    .unwrap();
    let identity = binding.immutable_identity().unwrap();
    let partition = SourcePartitionIdV1::new(digest("partition"));
    let object = SourceObjectObservationV1::new(
        SourceNativeObjectIdV1::new(digest("object")),
        SourceObjectRevisionV1::new(digest("revision")),
        ManifestDigest::new(observation.payload_reference().digest().as_str()).unwrap(),
        SourceContentStateV1::Live,
    )
    .unwrap();
    let frontier = SourcePartitionFrontierV1::new(
        identity.clone(),
        partition.clone(),
        None,
        None,
        Some(tracedecay_domain::SourceCursorV1::new(digest(
            "continuation",
        ))),
        SourceCoverageV1::Partial,
        1,
        None,
        digest("envelope"),
    )
    .unwrap();
    let evidence = SourceObservationEvidenceV1::new(
        identity.clone(),
        partition.clone(),
        &object,
        observation.receipt().receipt().clone(),
        tracedecay_domain::derive_exact_observation_anchor_id(
            observation.scope(),
            observation.observation_id(),
        )
        .unwrap(),
        authorization,
        digest("source-authorization"),
    )
    .unwrap();
    let mutation =
        SourceObjectMutationV1::new(object, None, SourceObjectTransitionV1::Initial, evidence)
            .unwrap();
    let commit = SourceCommitV1::new(
        definition,
        binding,
        partition,
        digest("idempotency"),
        digest("request"),
        None,
        SourceAggregateFrontierV1::with_updated_partition(identity.clone(), None, frontier)
            .unwrap(),
        vec![mutation],
        None,
    )
    .unwrap();
    let mut connection = rusqlite::Connection::open(db.db_path()).unwrap();
    let mut transaction = connection.transaction().unwrap();
    let savepoint = transaction.savepoint().unwrap();
    ExternalSourceExecutor
        .execute_write(&savepoint, &commit)
        .unwrap();
    savepoint.commit().unwrap();
    transaction.commit().unwrap();
    let transaction = connection.transaction().unwrap();
    let pending = match ExternalSourceExecutor
        .execute_read(
            &transaction,
            &ExternalSourceReadOperationV1::NextPendingProjection {
                binding: Some(identity),
            },
        )
        .unwrap()
    {
        ExternalSourceReadResultV1::PendingProjection(Some(pending)) => pending,
        other => panic!("expected a real pending projection, got {other:?}"),
    };
    drop(transaction);
    let projection = build_source_projection(
        &pending,
        ComponentVersion::new("projector.retirement.external").unwrap(),
    )
    .unwrap();
    let mut transaction = connection.transaction().unwrap();
    let savepoint = transaction.savepoint().unwrap();
    ExternalSourceExecutor
        .execute_projection_write(&savepoint, &projection)
        .unwrap();
    savepoint.commit().unwrap();
    transaction.commit().unwrap();
}

#[asupersync::test]
async fn retirement_external_journals_pin_only_their_own_dependency_closure() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-external").await;
    let db = &harness.registered;
    let external = seed(db, 70).await;
    let unrelated = seed(db, 71).await;
    ingest_external(db, &external);
    assert_eq!(count(db, "external_source_retained_receipts_v1").await, 1);
    assert_eq!(count(db, "external_source_projected_objects_v2").await, 1);
    let unrelated_plan = db
        .plan_observation_retirement(
            &[unrelated.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(
        !unrelated_plan.candidates()[0]
            .blockers
            .contains(&RetirementBlocker::ExternalJournal),
        "an unrelated production journal must not pin the candidate"
    );
    assert_eq!(
        db.apply_observation_retirement(&unrelated_plan, unrelated_plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    let plan = db
        .plan_observation_retirement(
            &[external.observation_id().clone()],
            ObservationRetirementAuthorization::UnsupportedCodexRecord,
        )
        .await
        .unwrap();
    assert!(
        !plan.eligible(),
        "the actual journal consumer remains pinned"
    );
    assert!(
        plan.candidates()[0]
            .blockers
            .contains(&RetirementBlocker::ExternalJournal)
    );
    for table in [
        "external_source_mutations_v1",
        "external_source_commit_receipts_v2",
        "external_source_objects_v2",
        "external_source_projected_objects_v2",
        "retrieval_anchors",
        "sanitization_receipts",
        "retrieval_anchor_aliases",
    ] {
        let size = plan
            .tables()
            .iter()
            .find(|size| size.table == table)
            .unwrap_or_else(|| panic!("plan omitted {table}"));
        assert!(
            size.rows > 0 && size.bytes > 0,
            "real ingestion must populate and report {table}"
        );
    }
    assert_eq!(
        db.apply_observation_retirement(&plan, plan.digest())
            .await
            .unwrap(),
        ObservationRetirementOutcome::Deferred
    );
    assert_eq!(count(db, "observations").await, 2);
    assert_eq!(count(db, "external_source_mutations_v1").await, 1);
}
