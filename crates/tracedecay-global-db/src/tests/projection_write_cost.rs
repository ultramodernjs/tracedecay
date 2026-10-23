//! Projection work follows the requested output, not all retained owners.

use tempfile::TempDir;
use tracedecay_domain::{
    CanonicalMessageRoleV1, CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1,
    CanonicalObservationFactV1, CanonicalObservationRelationsV1, ComponentVersion,
    DurableObservationV1, ObservationId, ObservationIdentityMaterialV1,
    ObservationOrderingDomainV1, ObservationScopeV1, ObservationSourceCursorV1,
    ObservationSourceGenerationV1, ObservationSourceIdentityV1, ObservationSourceRangeV1,
    PayloadReferenceV1, ProjectionGenerationId, ProviderId, RetentionClass, SanitizationReceiptId,
    SanitizationReceiptRefV1, SanitizationReceiptV1, SanitizerDispositionV1, SensitivityV1,
    SessionId, UtcMicros,
};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_store::{AnchoredObservationWrite, ObservationStore, ObservationWrite};

use super::harness::{
    HostAdmissionScope, HostAdmissionTestRuntimeV1, seed_projected_messages, writer_telemetry,
};

async fn queue_target(runtime: &HostAdmissionTestRuntimeV1) -> DurableObservationV1 {
    let provider = ProviderId::new("codex").unwrap();
    let session = SessionId::new("session.projection-cost-target").unwrap();
    let source =
        ObservationSourceIdentityV1::for_provider(provider.clone(), session.clone()).unwrap();
    let record = ObservationId::new("record.projection-cost-target").unwrap();
    let range = ObservationSourceRangeV1::new(0, 100).unwrap();
    let envelope = CanonicalObservationEnvelopeV1::new(
        provider,
        "message",
        record.clone(),
        CanonicalObservationRelationsV1::new(session)
            .with_message_id(ObservationId::new("message.projection-cost-target").unwrap()),
        vec![CanonicalObservationFactV1::Message {
            role: CanonicalMessageRoleV1::Assistant,
            content: serde_json::json!({ "text": "projection cost target" }),
            model: None,
            timestamp: Some(1_750_000_000),
        }],
        CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
    )
    .unwrap();
    let payload = serde_json::to_value(envelope).unwrap();
    let receipt = SanitizationReceiptV1::new(
        SanitizationReceiptRefV1::new(
            SanitizationReceiptId::new("receipt.projection-cost-target").unwrap(),
            ComponentVersion::new("sanitizer.projection-cost.v1").unwrap(),
        )
        .unwrap(),
        SanitizerDispositionV1::Accepted,
        SensitivityV1::NonSensitive,
        Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
    )
    .unwrap();
    let observation = DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            source.clone(),
            ObservationScopeV1::Profile,
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            record,
        )
        .unwrap(),
        receipt,
        RetentionClass::new("retention.projection-cost").unwrap(),
        payload,
    )
    .unwrap();
    let cursor = ObservationSourceCursorV1::for_ordering(
        source,
        ObservationScopeV1::Profile,
        ObservationSourceGenerationV1::new(1).unwrap(),
        ObservationOrderingDomainV1::FileBytes,
        100,
    )
    .unwrap();
    let write = ObservationWrite::new(observation.clone(), None, cursor).unwrap();
    let generation = ProjectionGenerationId::new("projection.cost.v1").unwrap();
    let authorization = tracedecay_store::build_observation_resolution_authorization_v1(
        &observation,
        "projection-cost",
    )
    .unwrap();
    let anchor = tracedecay_store::build_observation_retrieval_anchor(
        &observation,
        generation.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap()
        .persist_observation(AnchoredObservationWrite::new(write, anchor, generation).unwrap())
        .await
        .unwrap();
    observation
}

async fn scalar(database: &crate::RegisteredGlobalDb, sql: &str) -> i64 {
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot.query(sql, ()).await.unwrap();
    rows.next().await.unwrap().unwrap().get(0).unwrap()
}

async fn unrelated_provenance(
    database: &crate::RegisteredGlobalDb,
    target: &str,
) -> Vec<(String, String, String, i64)> {
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT observation_id, output_provider, output_message_id, message_created
         FROM observation_projection_provenance WHERE observation_id <> ?1
         ORDER BY observation_id, output_provider, output_message_id",
            params![target],
        )
        .await
        .unwrap();
    let mut provenance = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        provenance.push((
            row.get(0).unwrap(),
            row.get(1).unwrap(),
            row.get(2).unwrap(),
            row.get(3).unwrap(),
        ));
    }
    provenance
}

async fn cold_projection_cost(owners: usize, abort_first: bool) -> u64 {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed_projected_messages(&runtime, 0..owners).await;
    let target = queue_target(&runtime).await;
    drop(runtime);

    // Reopen after queuing the target: a warm connection would hide the old
    // whole-store TEMP-cache initialization. Its session is unrelated to the
    // retained messages, so session-local reconciliation is constant too.
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let retained = unrelated_provenance(database, target.observation_id().as_str()).await;
    assert_eq!(retained.len(), owners);
    if abort_first {
        // A durable trigger is allowed by the exact-SQL writer policy; TEMP
        // triggers are not. The trigger exists only in this disposable fixture.
        database
            .writer_connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER abort_projection_cost
             BEFORE INSERT ON main.observation_projection_provenance
             BEGIN SELECT RAISE(ABORT, 'injected projection interruption'); END;",
            )
            .await
            .unwrap();
        let error = crate::project_queued_observations(database.runtime_database(), 1)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected projection interruption"),
            "{error}"
        );
        assert_eq!(
            scalar(database, "SELECT COUNT(*) FROM projection_queue").await,
            1
        );
        assert_eq!(
            scalar(database, "SELECT COUNT(*) FROM lcm_raw_messages").await,
            owners as i64
        );
        assert_eq!(
            scalar(
                database,
                "SELECT COUNT(*) FROM observation_projection_provenance"
            )
            .await,
            owners as i64
        );
        assert_eq!(
            scalar(
                database,
                "SELECT last_sequence FROM observation_projection_checkpoints"
            )
            .await,
            owners as i64
        );
        assert_eq!(
            unrelated_provenance(database, target.observation_id().as_str()).await,
            retained
        );
        database
            .writer_connection()
            .unwrap()
            .execute_batch("DROP TRIGGER abort_projection_cost;")
            .await
            .unwrap();
    }
    let before = writer_telemetry(database).sqlite_vm.vm_steps;
    let drained = crate::project_queued_observations(database.runtime_database(), 1)
        .await
        .unwrap();
    assert_eq!(drained.items.len(), 1);
    assert!(!drained.has_more);
    let steps = writer_telemetry(database).sqlite_vm.vm_steps - before;
    assert_eq!(
        scalar(database, "SELECT COUNT(*) FROM lcm_raw_messages").await,
        (owners + 1) as i64
    );
    assert_eq!(
        scalar(
            database,
            "SELECT COUNT(*) FROM observation_projection_provenance"
        )
        .await,
        (owners + 1) as i64
    );
    assert_eq!(
        scalar(database, "SELECT COUNT(*) FROM projection_queue").await,
        0
    );
    assert_eq!(
        scalar(
            database,
            "SELECT last_sequence FROM observation_projection_checkpoints"
        )
        .await,
        (owners + 1) as i64
    );
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT COUNT(*) FROM observation_projection_provenance WHERE observation_id = ?1",
            params![target.observation_id().as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        1
    );
    assert_eq!(
        unrelated_provenance(database, target.observation_id().as_str()).await,
        retained
    );
    steps
}

#[asupersync::test]
async fn cold_projection_cost_does_not_scale_with_unrelated_ownership() {
    let base = cold_projection_cost(32, false).await;
    let grown = cold_projection_cost(512, false).await;
    eprintln!("cold projection VM steps: base={base} grown={grown}");
    assert!(
        grown * 10 <= base * 15,
        "one output on a 16x larger authority must stay within 1.5x VM work: base={base} grown={grown}"
    );
}

#[asupersync::test]
async fn interrupted_projection_retry_preserves_authority_without_global_rebuild() {
    let base = cold_projection_cost(32, true).await;
    let grown = cold_projection_cost(512, true).await;
    eprintln!("retry projection VM steps: base={base} grown={grown}");
    assert!(
        grown * 10 <= base * 15,
        "retry must not rebuild global ownership: base={base} grown={grown}"
    );
}

#[asupersync::test]
async fn projection_drain_does_not_materialize_global_temp_ownership() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed_projected_messages(&runtime, 0..64).await;
    queue_target(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let drained = crate::project_queued_observations(database.runtime_database(), 16)
        .await
        .unwrap();
    assert_eq!(drained.items.len(), 1);
    assert!(!drained.has_more);
    assert_eq!(
        scalar(database, "SELECT COUNT(*) FROM lcm_raw_messages").await,
        65
    );

    // Inspect the pinned writer, not a reader's unrelated TEMP schema.
    let transaction = database.begin_write_transaction().await.unwrap();
    let mut rows = transaction
        .query(
            "SELECT name FROM sqlite_temp_schema WHERE type = 'table'",
            (),
        )
        .await
        .unwrap();
    let mut tables = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        tables.push(row.get::<String>(0).unwrap());
    }
    assert!(
        tables.is_empty(),
        "projection materialized TEMP tables: {tables:?}"
    );
    drop(rows);
    transaction.rollback().await.unwrap();
}
