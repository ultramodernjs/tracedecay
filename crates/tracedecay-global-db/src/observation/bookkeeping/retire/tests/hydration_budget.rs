use super::*;

async fn large_message(
    db: &RegisteredGlobalDb,
    index: u64,
    bytes: usize,
    copies: usize,
) -> DurableObservationV1 {
    // Model a compact historical/native row below today's runtime command
    // admission boundary (which caps new commands at 4 MiB). Retirement must
    // still bound decoding of old or imported stores, not trust that admission.
    let payload = serde_json::json!({"legacy_messages": vec!["x".repeat(bytes); copies]});
    let range = ObservationSourceRangeV1::new(0, 100).unwrap();
    let observation = DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            ObservationSourceIdentityV1::for_provider(
                ProviderId::new("codex").unwrap(),
                SessionId::new(format!("session.large.{index}")).unwrap(),
            )
            .unwrap(),
            ObservationScopeV1::Profile,
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            ObservationId::new(format!("record.large.{index}")).unwrap(),
        )
        .unwrap(),
        SanitizationReceiptV1::new(
            SanitizationReceiptRefV1::new(
                SanitizationReceiptId::new(format!("receipt.large.{index}")).unwrap(),
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
    let (json, bodies) =
        tracedecay_store::slim_stored_json(&serde_json::to_string(&observation).unwrap()).unwrap();
    let transaction = db.begin_write_transaction().await.unwrap();
    for body in bodies {
        transaction
            .execute(
                tracedecay_store::UPSERT_CANONICAL_BODY_SQL,
                params![
                    body.content_hash.as_str(),
                    body.encoding,
                    body.blob,
                    body.uncompressed_bytes
                ],
            )
            .await
            .unwrap();
        transaction
            .execute(
                tracedecay_store::canonical_body::INSERT_OBSERVATION_BODY_REFERENCE_SQL,
                params![
                    observation.observation_id().as_str(),
                    body.content_hash.as_str()
                ],
            )
            .await
            .unwrap();
    }
    let receipt = observation.receipt();
    transaction.execute("INSERT INTO sanitization_receipts(receipt_id,sanitizer_version,payload_digest,receipt_json) VALUES (?1,?2,?3,?4)", params![receipt.receipt().receipt_id().as_str(), receipt.receipt().sanitizer_version().as_str(), observation.payload_reference().digest().as_str(), serde_json::to_string(receipt).unwrap()]).await.unwrap();
    transaction.execute("INSERT INTO observations(observation_id,payload_digest,receipt_id,observation_json,committed_cursor_json) VALUES (?1,?2,?3,?4,?5)", params![observation.observation_id().as_str(), observation.payload_reference().digest().as_str(), receipt.receipt().receipt_id().as_str(), json, serde_json::to_string(&cursor).unwrap()]).await.unwrap();
    transaction.commit().await.unwrap();
    observation
}

#[asupersync::test]
async fn retirement_refuses_oversized_canonical_body_before_hydration() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-body-budget").await;
    let db = &harness.registered;
    let observation = large_message(db, 131, MAX_BYTES as usize + 1, 1).await;
    let ids = [observation.observation_id().clone()];
    let authorization =
        ObservationRetirementAuthorization::OperatorProjectPrune(marker(&observation));
    assert_eq!(count(db, "session_canonical_bodies").await, 1);
    let snapshot = db.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT length(body), uncompressed_bytes FROM session_canonical_bodies",
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert!(
        row.get::<u64>(0).unwrap() < MAX_BYTES / 100,
        "fixture must actually compress well"
    );
    assert!(row.get::<u64>(1).unwrap() > MAX_BYTES);
    drop(rows);
    drop(snapshot);
    assert!(
        matches!(
            db.plan_observation_retirement(&ids, authorization.clone())
                .await,
            Err(ProjectionStoreError::ProvenanceCollision)
        ),
        "oversized canonical bodies must be refused by preflight, not hydrated outside the byte budget"
    );
    // A corrupt compressed stream would produce a hydration Storage error if
    // planning loaded it. The size-only refusal must take precedence instead.
    db.writer_connection()
        .unwrap()
        .execute("UPDATE session_canonical_bodies SET body=X'00'", ())
        .await
        .unwrap();
    assert!(
        matches!(
            db.plan_observation_retirement(&ids, authorization).await,
            Err(ProjectionStoreError::ProvenanceCollision)
        ),
        "budget refusal must happen before compressed-body integrity decoding"
    );
}

#[asupersync::test]
async fn retirement_charges_repeated_body_expansions_cumulatively() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-body-copies").await;
    let db = &harness.registered;
    let observation = large_message(db, 132, MAX_BYTES as usize / 2 + 1, 2).await;
    assert_eq!(
        count(db, "session_canonical_bodies").await,
        1,
        "both references share one stored body"
    );
    assert!(
        matches!(
            db.plan_observation_retirement(
                &[observation.observation_id().clone()],
                ObservationRetirementAuthorization::OperatorProjectPrune(marker(&observation)),
            )
            .await,
            Err(ProjectionStoreError::ProvenanceCollision)
        ),
        "each hydrated reference must consume the shared batch budget, even for the same hash"
    );
}

#[asupersync::test]
async fn retirement_charges_shared_bodies_across_the_whole_batch() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-body-batch").await;
    let db = &harness.registered;
    let mut ids = Vec::new();
    for index in 141..144 {
        let observation = seed_payload(
            db,
            index,
            serde_json::json!({
                "legacy_message": "bounded historical output ".repeat(120_000)
            }),
        )
        .await;
        ids.push(observation.observation_id().clone());
    }
    assert_eq!(count(db, "session_canonical_bodies").await, 1);
    assert!(
        db.plan_observation_retirement(
            &ids[..2],
            ObservationRetirementAuthorization::LifecycleRetention
        )
        .await
        .is_ok(),
        "two individually admitted bodies fit under the batch budget"
    );
    assert!(
        matches!(
            db.plan_observation_retirement(
                &ids,
                ObservationRetirementAuthorization::LifecycleRetention
            )
            .await,
            Err(ProjectionStoreError::ProvenanceCollision)
        ),
        "three expansions exceed the batch budget even though all candidates are already pinned and share one body"
    );
}

#[asupersync::test]
async fn retirement_apply_rechecks_canonical_hydration_budget() {
    let harness =
        RegisteredGlobalDbHarness::open_without_relation_graph("retirement-body-apply").await;
    let db = &harness.registered;
    let observation = seed_payload(
        db,
        145,
        serde_json::json!({"legacy_message": "bounded output ".repeat(10_000)}),
    )
    .await;
    let plan = db
        .plan_observation_retirement(
            &[observation.observation_id().clone()],
            ObservationRetirementAuthorization::OperatorProjectPrune(marker(&observation)),
        )
        .await
        .unwrap();
    db.writer_connection()
        .unwrap()
        .execute(
            "UPDATE session_canonical_bodies SET uncompressed_bytes=?1",
            params![(MAX_BYTES + 1) as i64],
        )
        .await
        .unwrap();
    assert!(
        matches!(
            db.apply_observation_retirement(&plan, plan.digest()).await,
            Err(ProjectionStoreError::ProvenanceCollision)
        ),
        "writer-transaction replanning must refuse before loading a body whose size changed"
    );
    assert_eq!(count(db, "observations").await, 1);
}
