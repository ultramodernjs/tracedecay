use super::*;
use std::collections::BTreeSet;
use tracedecay_domain::{
    LocatorDigest, ManifestDigest, PrivacyDomainId, SourceAcquisitionCapabilitiesV1,
    SourceAcquisitionContractV1, SourceAggregateFrontierV1, SourceBindingOwnerV1, SourceBindingV1,
    SourceCaptureModeV1, SourceContentStateV1, SourceCoverageV1, SourceDefinitionV1,
    SourceDeletionSemanticsV1, SourceInstanceId, SourceNativeObjectIdV1, SourceObjectObservationV1,
    SourceObjectRevisionV1, SourcePartitionFrontierV1, SourcePartitionIdV1,
    SourceRefetchStrategyV1, canonical_sha256,
};
use tracedecay_rusqlite_runtime::repository::ExternalSourceExecutor;
use tracedecay_store::{
    ExternalSourceReadOperationV1, ExternalSourceReadResultV1, SourceCommitV1,
    SourceObjectMutationV1, SourceObjectTransitionV1, SourceObservationEvidenceV1,
    build_source_projection,
};

fn source_digest(label: &str) -> ManifestDigest {
    canonical_sha256(&label).unwrap()
}

// Real source commit and projection journals in this test's temporary store.
fn ingest_external(db: &RegisteredGlobalDb, observation: &DurableObservationV1) {
    let definition = SourceDefinitionV1::new(
        SourceInstanceId::new("source.codex-cleanup.external").unwrap(),
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
        build_observation_resolution_authorization_v1(observation, "cleanup-fixture").unwrap();
    authorization.privacy_domain_id =
        PrivacyDomainId::new("privacy.codex-cleanup.external").unwrap();
    let binding = SourceBindingV1::new(
        &definition,
        SourceBindingOwnerV1::Profile(db.binding().shard_id.profile_id.clone()),
        authorization.privacy_domain_id.clone(),
        LocatorDigest::new(source_digest("root").as_str()).unwrap(),
        1,
    )
    .unwrap();
    let identity = binding.immutable_identity().unwrap();
    let partition = SourcePartitionIdV1::new(source_digest("partition"));
    let object = SourceObjectObservationV1::new(
        SourceNativeObjectIdV1::new(source_digest("object")),
        SourceObjectRevisionV1::new(source_digest("revision")),
        ManifestDigest::new(observation.payload_reference().digest().as_str()).unwrap(),
        SourceContentStateV1::Live,
    )
    .unwrap();
    let frontier = SourcePartitionFrontierV1::new(
        identity.clone(),
        partition.clone(),
        None,
        None,
        Some(tracedecay_domain::SourceCursorV1::new(source_digest(
            "continuation",
        ))),
        SourceCoverageV1::Partial,
        1,
        None,
        source_digest("envelope"),
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
        source_digest("source-authorization"),
    )
    .unwrap();
    let mutation =
        SourceObjectMutationV1::new(object, None, SourceObjectTransitionV1::Initial, evidence)
            .unwrap();
    let commit = SourceCommitV1::new(
        definition,
        binding,
        partition,
        source_digest("idempotency"),
        source_digest("request"),
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
        ComponentVersion::new("projector.codex-cleanup.external").unwrap(),
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
async fn unsupported_cleanup_real_journals_pin_only_the_consumed_record() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    ingest_external(database, &seeded[0]);
    let before = file_bytes(database);
    let cursors = source_cursors(database).await;
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 3);
    assert!(
        plan.candidates[0]
            .retained_reasons
            .iter()
            .any(|reason| reason == "dependency:ExternalJournal")
    );
    assert!(
        plan.candidates[1].retained_reasons.is_empty(),
        "unrelated journals must not disable cleanup"
    );
    assert!(plan.candidates[2].retained_reasons.is_empty());
    assert_eq!(
        before,
        file_bytes(database),
        "closure planning must remain read-only"
    );
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        2
    );
    assert_eq!(source_cursors(database).await, cursors);
    let snapshot = database.read_snapshot().await.unwrap();
    for table in [
        "external_source_mutations_v1",
        "external_source_retained_receipts_v1",
        "external_source_projected_objects_v2",
    ] {
        let mut rows = snapshot
            .query(&format!("SELECT count(*) FROM {table}"), ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            1,
            "preserve {table}"
        );
    }
    let mut rows = snapshot
        .query(
            "SELECT payload_digest FROM observations WHERE observation_id=?1",
            params![seeded[0].observation_id().as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        seeded[0].payload_reference().digest().as_str()
    );
    drop(rows);
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}
