use super::*;

#[asupersync::test]
async fn unsupported_cleanup_historical_output_pins_only_its_record() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    database.writer_connection().unwrap().execute(
        "INSERT INTO observation_projection_aliases (projector_version, observation_id, output_provider, output_message_id) VALUES ('historical.cleanup.v0', ?1, 'codex', 'retained-historical')",
        params![seeded[0].observation_id().as_str()],
    ).await.unwrap();
    let before = file_bytes(database);
    let cursors = source_cursors(database).await;
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert!(!plan.candidates[0].retained_reasons.is_empty());
    assert!(
        plan.candidates[1].retained_reasons.is_empty(),
        "an unrelated historical projector must not disable cleanup"
    );
    assert!(plan.candidates[2].retained_reasons.is_empty());
    assert_eq!(file_bytes(database), before);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        2
    );
    assert_eq!(source_cursors(database).await, cursors);
    let snapshot = database.read_snapshot().await.unwrap();
    assert_eq!(scalar(&snapshot, "SELECT count(*) FROM observation_projection_aliases WHERE projector_version='historical.cleanup.v0'").await.unwrap(), 1);
    assert_eq!(
        scalar(&snapshot, "SELECT count(*) FROM observations")
            .await
            .unwrap(),
        4
    );
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn unsupported_cleanup_rolls_back_partial_cascade_and_retries_after_reopen() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let cursors = source_cursors(database).await;
    let plan = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    let retirement = plan.retirement().unwrap();
    assert!(retirement.eligible());
    for table in [
        "observations",
        "observation_repository_provenance",
        "observation_retrieval_anchors",
    ] {
        let size = retirement
            .tables()
            .iter()
            .find(|size| size.table == table)
            .unwrap();
        assert_eq!(size.rows, 3, "real fixture must populate {table}");
        assert!(!size.retained);
        assert!(size.bytes > 0);
    }
    assert!(
        retirement
            .tables()
            .iter()
            .any(|size| size.retained && size.rows > 0)
    );
    let writer = database.writer_connection().unwrap();
    writer.execute_batch("CREATE TRIGGER cleanup_injected_failure BEFORE DELETE ON observation_repository_provenance BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END;").await.unwrap();
    let error = database
        .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("injected cleanup failure"),
        "exercise a partial cascade, not an early refusal: {error}"
    );
    assert_eq!(source_cursors(database).await, cursors);
    assert_eq!(
        database
            .plan_unsupported_codex_cleanup(None, 128)
            .await
            .unwrap(),
        plan,
        "rollback must restore the complete reviewed closure and guards"
    );
    let snapshot = database.read_snapshot().await.unwrap();
    assert_eq!(scalar(&snapshot, "SELECT count(*) FROM session_backfill_meta WHERE key LIKE 'observation-retirement.v1.applied.%'").await.unwrap(), 0, "failed cascade must not acknowledge completion");
    drop(snapshot);
    writer
        .execute_batch("DROP TRIGGER cleanup_injected_failure;")
        .await
        .unwrap();
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        3
    );
    drop(runtime);
    // The original opaque plan survives loss of the DB client. Completion is
    // checked from durable authority, before attempting to revalidate gone rows.
    let reopened = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let database = reopened
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await
            .unwrap(),
        0
    );
    assert_eq!(source_cursors(database).await, cursors);
    let snapshot = database.read_snapshot().await.unwrap();
    assert_eq!(
        scalar(&snapshot, "SELECT count(*) FROM observations")
            .await
            .unwrap(),
        3
    );
    assert_eq!(scalar(&snapshot, "SELECT count(*) FROM session_backfill_meta WHERE key LIKE 'observation-retirement.v1.applied.%'").await.unwrap(), 1);
    let mut rows = snapshot
        .query("PRAGMA foreign_key_check", ())
        .await
        .unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn unsupported_cleanup_applies_bounded_pages_without_chasing_appends() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    seed(&runtime).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let mut page = database
        .plan_unsupported_codex_cleanup(None, 2)
        .await
        .unwrap();
    let high_water = page.cursor.high_water_sequence;
    assert_eq!(page.examined, 2);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&page, &page.plan_digest)
            .await
            .unwrap(),
        2
    );
    let appended = observation(
        6,
        vec![json!({"kind":"unknown", "native_kind":"future_event", "state":"unsupported"})],
    );
    persist(&runtime, &appended).await;
    let cursors = source_cursors(database).await;
    let mut retired = 2;
    let mut examined = 2;
    let mut pages = 1;
    while let Some(cursor) = page.next_cursor {
        page = database
            .plan_unsupported_codex_cleanup(Some(&cursor), 2)
            .await
            .unwrap();
        assert_eq!(page.cursor.high_water_sequence, high_water);
        assert!(page.examined <= 2);
        retired += database
            .apply_unsupported_codex_cleanup(&page, &page.plan_digest)
            .await
            .unwrap();
        examined += page.examined;
        pages += 1;
    }
    assert_eq!((pages, examined, retired), (3, 6, 3));
    assert_eq!(source_cursors(database).await, cursors);
    let fresh = database
        .plan_unsupported_codex_cleanup(None, 128)
        .await
        .unwrap();
    assert_eq!(fresh.examined, 4);
    assert_eq!(fresh.candidates.len(), 1);
    assert_eq!(
        fresh.candidates[0].observation_id,
        appended.observation_id().as_str()
    );
    assert_eq!(fresh.candidates[0].retained_reasons, ["source_frontier"]);
    let before = file_bytes(database);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&fresh, &fresh.plan_digest)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        file_bytes(database),
        before,
        "retained-only pages need no writer"
    );
    let empty = database
        .plan_unsupported_codex_cleanup(
            Some(&UnsupportedCodexCleanupCursor {
                store_digest: fresh.cursor.store_digest.clone(),
                after_sequence: fresh.cursor.high_water_sequence,
                high_water_sequence: fresh.cursor.high_water_sequence,
            }),
            2,
        )
        .await
        .unwrap();
    assert_eq!(empty.examined, 0);
    assert_eq!(
        database
            .apply_unsupported_codex_cleanup(&empty, &empty.plan_digest)
            .await
            .unwrap(),
        0
    );
    assert_eq!(file_bytes(database), before, "empty pages need no writer");
}

#[asupersync::test]
async fn unsupported_cleanup_missing_reverse_index_refuses_without_schema_repair() {
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
    database.writer_connection().unwrap().execute_batch("DROP INDEX idx_retirement_observation_source_presence; ANALYZE observation_source_presence;").await.unwrap();
    let before = file_bytes(database);
    let cursors = source_cursors(database).await;
    assert!(matches!(
        database
            .apply_unsupported_codex_cleanup(&plan, &plan.plan_digest)
            .await,
        Err(UnsupportedCodexCleanupError::StalePlan)
    ));
    assert!(matches!(
        database.plan_unsupported_codex_cleanup(None, 128).await,
        Err(UnsupportedCodexCleanupError::Retirement(
            ProjectionStoreError::ProvenanceCollision
        ))
    ));
    assert_eq!(
        file_bytes(database),
        before,
        "planning/apply must not rebuild missing indexes"
    );
    assert_eq!(source_cursors(database).await, cursors);
    let snapshot = database.read_snapshot().await.unwrap();
    assert_eq!(
        scalar(&snapshot, "SELECT count(*) FROM observations")
            .await
            .unwrap(),
        6
    );
    assert_eq!(scalar(&snapshot, "SELECT count(*) FROM sqlite_master WHERE name='idx_retirement_observation_source_presence'").await.unwrap(), 0);
}
