mod apply;
mod external;

use serde_json::json;
use tempfile::TempDir;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1, CanonicalObservationFactV1,
    CanonicalObservationRelationsV1, ComponentVersion, DurableObservationV1, ObservationId,
    ObservationIdentityMaterialV1, ObservationOrderingDomainV1, ObservationScopeV1,
    ObservationSourceCursorV1, ObservationSourceGenerationV1, ObservationSourceIdentityV1,
    ObservationSourceRangeV1, PayloadReferenceV1, ProjectionGenerationId, ProviderId,
    RetentionClass, SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1,
    SanitizerDispositionV1, SensitivityV1, SessionId, UtcMicros,
};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_store::{
    AnchoredObservationWrite, ObservationPersistOutcome, ObservationProjectionStore,
    ObservationStore, ObservationWrite, SESSION_MESSAGE_PROJECTOR_VERSION,
    build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
};

use super::*;
use crate::tests::harness::{HostAdmissionScope, HostAdmissionTestRuntimeV1};

fn observation(index: u64, facts: Vec<serde_json::Value>) -> DurableObservationV1 {
    let record_id = ObservationId::new(format!("record.unsupported-{index}")).unwrap();
    let provider = ProviderId::new("codex").unwrap();
    let session = SessionId::new("session.unsupported-cleanup").unwrap();
    let range = ObservationSourceRangeV1::new(index * 100, index * 100 + 100).unwrap();
    let envelope = CanonicalObservationEnvelopeV1::new(
        provider.clone(),
        "event_msg",
        record_id.clone(),
        CanonicalObservationRelationsV1::new(session.clone()),
        facts
            .into_iter()
            .map(|fact| serde_json::from_value::<CanonicalObservationFactV1>(fact).unwrap())
            .collect(),
        CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
    )
    .unwrap();
    let payload = serde_json::to_value(envelope).unwrap();
    let receipt = SanitizationReceiptV1::new(
        SanitizationReceiptRefV1::new(
            SanitizationReceiptId::new(format!("receipt.unsupported-{index}")).unwrap(),
            ComponentVersion::new("sanitizer.cleanup.v1").unwrap(),
        )
        .unwrap(),
        SanitizerDispositionV1::Accepted,
        SensitivityV1::NonSensitive,
        Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
    )
    .unwrap();
    DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            ObservationSourceIdentityV1::for_provider(provider, session).unwrap(),
            ObservationScopeV1::Profile,
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            record_id,
        )
        .unwrap(),
        receipt,
        RetentionClass::new("retention.cleanup-fixture").unwrap(),
        payload,
    )
    .unwrap()
}

async fn persist(runtime: &HostAdmissionTestRuntimeV1, observation: &DurableObservationV1) {
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let previous = store
        .get_source_cursor(observation.source(), observation.scope())
        .await
        .unwrap();
    let next = ObservationSourceCursorV1::for_ordering(
        observation.source().clone(),
        observation.scope().clone(),
        observation.identity().generation(),
        observation.identity().ordering_domain(),
        observation.identity().position().end(),
    )
    .unwrap();
    let write = ObservationWrite::new(observation.clone(), previous, next).unwrap();
    let generation = ProjectionGenerationId::new("projection.cleanup.v1").unwrap();
    let authorization =
        build_observation_resolution_authorization_v1(write.observation(), "cleanup-fixture")
            .unwrap();
    let anchor = build_observation_retrieval_anchor(
        write.observation(),
        generation.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    assert!(matches!(
        store
            .persist_observation(AnchoredObservationWrite::new(write, anchor, generation).unwrap())
            .await
            .unwrap(),
        ObservationPersistOutcome::Committed(_)
    ));
    store
        .project_observation(observation.observation_id())
        .await
        .unwrap();
}

async fn seed(runtime: &HostAdmissionTestRuntimeV1) -> Vec<DurableObservationV1> {
    let unknown = json!({"kind":"unknown", "native_kind":"future_event", "state":"unsupported"});
    let message = json!({"kind":"message", "role":"user", "content":"Keep supported output"});
    let large_context = json!({"kind":"session", "project_path":"/repo/".to_owned() + &"large/".repeat(3000),
        "source":"codex_rollout", "native_source":"codex", "location_provenance":"rollout_context"});
    let records = [
        vec![unknown.clone()],
        vec![large_context, unknown.clone()],
        vec![unknown.clone(), message.clone()],
        vec![
            unknown.clone(),
            json!({"kind":"unknown", "native_kind":"diagnostic", "state":"malformed"}),
        ],
        vec![unknown],
        vec![message],
    ];
    let mut observations = Vec::new();
    for (index, facts) in (0_u64..).zip(records) {
        let observation = observation(index, facts);
        persist(runtime, &observation).await;
        observations.push(observation);
    }
    observations
}

fn file_bytes(database: &RegisteredGlobalDb) -> Vec<Option<Vec<u8>>> {
    let path = database.db_path();
    [
        path.to_path_buf(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
    ]
    .iter()
    .map(|path| std::fs::read(path).ok())
    .collect()
}

async fn source_cursors(database: &RegisteredGlobalDb) -> Vec<String> {
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT cursor_json FROM source_cursors ORDER BY source_json, scope_json",
            (),
        )
        .await
        .unwrap();
    let mut cursors = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        cursors.push(row.get::<String>(0).unwrap());
    }
    cursors
}

#[asupersync::test]
async fn unsupported_cleanup_dry_run_is_read_only_and_hydrates_bodies() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    database.writer_connection().unwrap().execute(
        "INSERT INTO observation_projection_aliases (projector_version, observation_id, output_provider, output_message_id)
         VALUES (?1, ?2, 'codex', 'retained-alias')",
        params![SESSION_MESSAGE_PROJECTOR_VERSION, seeded[4].observation_id().as_str()],
    ).await.unwrap();
    let before = file_bytes(database);
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(plan.examined, 6);
    assert_eq!(
        plan.candidates.len(),
        3,
        "hydrate canonical bodies, preserve mixed facts and diagnostics"
    );
    assert_eq!(
        plan.candidates[0].observation_id,
        seeded[0].observation_id().as_str()
    );
    assert_eq!(
        plan.candidates[1].observation_id,
        seeded[1].observation_id().as_str()
    );
    assert!(plan.candidates[0].retained_reasons.is_empty());
    assert!(
        plan.candidates[2]
            .retained_reasons
            .iter()
            .any(|reason| reason == "projection_output")
    );
    assert_eq!(
        plan,
        database
            .plan_unsupported_codex_cleanup(None, 128)
            .await
            .unwrap()
    );
    assert_eq!(
        before,
        file_bytes(database),
        "dry-run must not write DB or WAL"
    );
    assert!(plan.next_cursor.is_none());
    let mut page = database
        .plan_unsupported_codex_cleanup(None, 2)
        .await
        .unwrap();
    assert_eq!(page.examined, 2);
    assert_eq!(page.candidates.len(), 2);
    let mut examined = page.examined;
    while let Some(cursor) = page.next_cursor {
        page = database
            .plan_unsupported_codex_cleanup(Some(&cursor), 2)
            .await
            .unwrap();
        assert!(page.examined <= 2);
        examined += page.examined;
    }
    assert_eq!(examined, 6);
    assert_eq!(before, file_bytes(database));
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn unsupported_cleanup_preserves_remote_and_historical_consumers() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    database
        .writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO remote_observation_events
            (event_id, frame_digest, enrollment_id, enrollment_revision, node_id,
             policy_revision, capture_sequence, observation_id, writer_fence_json,
             captured_at, idempotency_key, command_digest)
         VALUES ('event.cleanup', 'frame.cleanup', 'enrollment.cleanup', 1, 'node.cleanup',
             1, 1, ?1, '{}', 1, 'idempotency.cleanup', 'command.cleanup')",
            params![seeded[0].observation_id().as_str()],
        )
        .await
        .unwrap();
    let before = file_bytes(database);
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 3);
    assert_eq!(plan.candidates[0].retained_reasons, ["remote_consumer"]);
    assert!(plan.candidates[1].retained_reasons.is_empty());
    assert_eq!(before, file_bytes(database));

    database
        .writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO observation_projection_aliases
            (projector_version, observation_id, output_provider, output_message_id)
         VALUES ('historical.cleanup.v0', ?1, 'codex', 'historical-output')",
            params![seeded[1].observation_id().as_str()],
        )
        .await
        .unwrap();
    database
        .writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO observation_projection_rebuilds
            (projector_version, generation, frontier_sequence, state)
         VALUES ('rebuild.cleanup.v1', 'generation.cleanup', 6, 'building')",
            (),
        )
        .await
        .unwrap();
    database
        .writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO external_source_retained_receipts_v1
            (binding_id, receipt_digest, predecessor_frontier_digest,
             successor_frontier_digest, receipt_json)
         VALUES ('binding.cleanup', 'receipt.cleanup', 'frontier.before', 'frontier.after', '{}')",
            (),
        )
        .await
        .unwrap();
    let before = file_bytes(database);
    let pinned = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_ne!(pinned.plan_digest, plan.plan_digest);
    for candidate in &pinned.candidates {
        assert!(
            candidate
                .retained_reasons
                .iter()
                .any(|reason| reason == "projection_rebuild"),
            "{} lost projection_rebuild: {:?}",
            candidate.observation_id,
            candidate.retained_reasons
        );
    }
    assert!(
        pinned.candidates[0]
            .retained_reasons
            .iter()
            .any(|reason| reason == "remote_consumer")
    );
    assert_eq!(before, file_bytes(database));
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn unsupported_cleanup_pages_freeze_high_water_and_validate_bounds() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let before = file_bytes(database);
    for size in [0, 129, usize::MAX] {
        assert!(matches!(
            database.plan_unsupported_codex_cleanup(None, size).await,
            Err(UnsupportedCodexCleanupError::InvalidPageSize)
        ));
    }
    let first = database
        .plan_unsupported_codex_cleanup(None, 2)
        .await
        .unwrap();
    for (after, high_water) in [(-1, 6), (7, 6)] {
        let invalid = UnsupportedCodexCleanupCursor {
            after_sequence: after,
            high_water_sequence: high_water,
            ..first.cursor.clone()
        };
        assert!(matches!(
            database
                .plan_unsupported_codex_cleanup(Some(&invalid), 2)
                .await,
            Err(UnsupportedCodexCleanupError::StalePlan)
        ));
    }
    let foreign = UnsupportedCodexCleanupCursor {
        store_digest: "another-store".to_owned(),
        ..first.cursor.clone()
    };
    assert!(matches!(
        database
            .plan_unsupported_codex_cleanup(Some(&foreign), 2)
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    assert_eq!(before, file_bytes(database));

    let appended = observation(
        6,
        vec![json!({"kind":"unknown", "native_kind":"future_event", "state":"unsupported"})],
    );
    persist(&runtime, &appended).await;
    let before = file_bytes(database);
    let mut page = first;
    let mut examined = page.examined;
    let mut ids = page
        .candidates
        .iter()
        .map(|candidate| candidate.observation_id.clone())
        .collect::<Vec<_>>();
    while let Some(cursor) = page.next_cursor {
        page = database
            .plan_unsupported_codex_cleanup(Some(&cursor), 2)
            .await
            .unwrap();
        assert!(page.examined <= 2);
        examined += page.examined;
        ids.extend(
            page.candidates
                .iter()
                .map(|candidate| candidate.observation_id.clone()),
        );
    }
    assert_eq!(examined, 6, "a resumed scan must not chase appended rows");
    assert_eq!(ids.len(), 3);
    assert!(
        !ids.iter()
            .any(|id| id == appended.observation_id().as_str())
    );
    let fresh = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(fresh.examined, 7);
    assert_eq!(fresh.candidates.len(), 4);
    assert_eq!(
        fresh.candidates.last().unwrap().retained_reasons,
        ["source_frontier"],
        "the observation supporting the current source frontier stays pinned"
    );
    assert_eq!(before, file_bytes(database));
}

#[asupersync::test]
async fn unsupported_cleanup_apply_rejects_unconfirmed_tampered_and_cross_store_plans() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert!(
        plan.candidates
            .iter()
            .any(|candidate| candidate.retained_reasons.is_empty())
    );
    let before = file_bytes(database);
    assert!(matches!(
        database
            .apply_unsupported_codex_cleanup(&plan, "not-reviewed")
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    let mut tampered = plan.clone();
    tampered.candidates[0].payload_digest = "not-the-payload-digest".to_owned();
    assert!(matches!(
        database
            .apply_unsupported_codex_cleanup(&tampered, &plan.plan_digest)
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    let other_directory = TempDir::new().unwrap();
    let other_runtime = HostAdmissionTestRuntimeV1::profile(other_directory.path())
        .await
        .unwrap();
    seed(&other_runtime).await;
    let other_database = other_runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let other_before = file_bytes(other_database);
    assert!(matches!(
        other_database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    assert_eq!(before, file_bytes(database));
    assert_eq!(other_before, file_bytes(other_database));
    assert_eq!(
        plan,
        database
            .plan_unsupported_codex_cleanup(None, 128)
            .await
            .unwrap()
    );
}

#[asupersync::test]
async fn unsupported_cleanup_apply_rejects_new_retention_pins() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert!(plan.candidates[0].retained_reasons.is_empty());
    database.writer_connection().unwrap().execute(
        "INSERT INTO observation_projection_aliases (projector_version, observation_id, output_provider, output_message_id)
         VALUES (?1, ?2, 'codex', 'new-retained-alias')",
        params![SESSION_MESSAGE_PROJECTOR_VERSION, seeded[0].observation_id().as_str()],
    ).await.unwrap();
    let before = file_bytes(database);
    assert!(matches!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    let current = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert!(
        current.candidates[0]
            .retained_reasons
            .iter()
            .any(|reason| reason == "projection_output")
    );
    assert_eq!(before, file_bytes(database));
}

#[asupersync::test]
async fn unsupported_cleanup_apply_retires_only_eligible_records_and_is_retry_safe() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    database.writer_connection().unwrap().execute(
        "INSERT INTO observation_projection_aliases (projector_version, observation_id, output_provider, output_message_id)
         VALUES (?1, ?2, 'codex', 'retained-alias')",
        params![SESSION_MESSAGE_PROJECTOR_VERSION, seeded[4].observation_id().as_str()],
    ).await.unwrap();
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 3);
    assert_eq!(
        plan.candidates
            .iter()
            .filter(|candidate| candidate.retained_reasons.is_empty())
            .count(),
        2
    );
    let cursors = source_cursors(database).await;
    assert_eq!(cursors.len(), 1);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        2
    );
    let current = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(
        current.examined, 4,
        "mixed facts, diagnostics, pinned and supported records survive"
    );
    assert_eq!(current.candidates.len(), 1);
    assert_eq!(
        current.candidates[0].observation_id,
        seeded[4].observation_id().as_str()
    );
    assert_eq!(source_cursors(database).await, cursors);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        0,
        "retrying a committed page must not retire records twice"
    );
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT observation_id, payload_digest FROM observations ORDER BY sequence",
            (),
        )
        .await
        .unwrap();
    for expected in &seeded[2..] {
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(
            row.get::<String>(0).unwrap(),
            expected.observation_id().as_str()
        );
        assert_eq!(
            row.get::<String>(1).unwrap(),
            expected.payload_reference().digest().as_str()
        );
    }
    assert!(rows.next().await.unwrap().is_none());
    drop(rows);
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn unsupported_cleanup_refuses_classification_hydration_before_loading_a_body() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    // A historical/imported body can exceed today's command admission bound.
    // Corrupt bytes prove size-only refusal takes precedence over decompression.
    database
        .writer_connection()
        .unwrap()
        .execute(
            "UPDATE session_canonical_bodies SET uncompressed_bytes=8388609, body=X'00'",
            (),
        )
        .await
        .unwrap();
    let before = file_bytes(database);
    let error = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("classification budget/integrity preflight"),
        "classification must authorize hydration before loading canonical blobs: {error}"
    );
    assert_eq!(
        before,
        file_bytes(database),
        "refused planning must remain passive"
    );
}

#[asupersync::test]
async fn unsupported_cleanup_bounds_inline_json_before_classifying_supported_records() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let first = database
        .plan_unsupported_codex_cleanup(None, 1)
        .await
        .unwrap();
    let cursor = UnsupportedCodexCleanupCursor {
        after_sequence: 6,
        high_water_sequence: 7,
        ..first.cursor
    };
    // Model a valid historical/imported row below today's command size cap.
    // It is supported, so the retirement kernel will never see its JSON.
    let observation = observation(
        6,
        vec![json!({"kind":"message", "role":"user", "content":"preserve"})],
    );
    let committed = ObservationSourceCursorV1::for_ordering(
        observation.source().clone(),
        observation.scope().clone(),
        observation.identity().generation(),
        observation.identity().ordering_domain(),
        700,
    )
    .unwrap();
    let receipt = observation.receipt();
    let tx = database.begin_write_transaction().await.unwrap();
    tx.execute("INSERT INTO sanitization_receipts(receipt_id,sanitizer_version,payload_digest,receipt_json) VALUES (?1,?2,?3,?4)",
        params![receipt.receipt().receipt_id().as_str(), receipt.receipt().sanitizer_version().as_str(), observation.payload_reference().digest().as_str(), serde_json::to_string(receipt).unwrap()]).await.unwrap();
    tx.execute("INSERT INTO observations(observation_id,payload_digest,receipt_id,observation_json,committed_cursor_json) VALUES (?1,?2,?3,?4||printf('%*s',8388609,''),?5)",
        params![observation.observation_id().as_str(), observation.payload_reference().digest().as_str(), receipt.receipt().receipt_id().as_str(), serde_json::to_string(&observation).unwrap(), serde_json::to_string(&committed).unwrap()]).await.unwrap();
    tx.commit().await.unwrap();
    let before = file_bytes(database);
    let error = database
        .plan_unsupported_codex_cleanup(Some(&cursor), 1)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("classification budget/integrity preflight refused observation sequence 7"),
        "inline bytes must be bounded before decoding even a supported record: {error}"
    );
    assert_eq!(before, file_bytes(database));
}
