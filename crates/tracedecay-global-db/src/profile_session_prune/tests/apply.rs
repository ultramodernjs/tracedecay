use super::*;
use crate::{RegisteredGlobalDb, RegisteredGlobalDbLeaseV1, RegisteredGlobalDbOwnerV1};
use tracedecay_runtime_core::db::{
    Database, DatabaseAuthority, TestDatabaseRuntimeMode, TestDatabaseRuntimeScope,
    enter_maintenance_database_scope,
};
use tracedecay_runtime_core::lifecycle_lease::{LifecycleLease, acquire_exclusive_for_profile};

async fn fixture() -> (
    tempfile::TempDir,
    RegisteredGlobalDbOwnerV1,
    RegisteredGlobalDbLeaseV1,
    LifecycleLease,
) {
    crate::register_registered_schema_installer();
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile");
    tracedecay_runtime_core::storage::PrivateStoreIo::create_dir_all(&profile).unwrap();
    let path = tracedecay_sessions::runtime::user_sessions_db_path(&profile);
    let authority = DatabaseAuthority::acquire_test(&path, "prune apply fixture").unwrap();
    let (owner, _runtime, _retirement) =
        Database::publish_registered_test_runtime_with_retirement_control(
            &path,
            &authority,
            TestDatabaseRuntimeMode::Initialize,
            TestDatabaseRuntimeScope::ProfileSessions,
        )
        .await
        .unwrap()
        .into_parts();
    let owner = RegisteredGlobalDbOwnerV1::admit_and_attach(owner)
        .await
        .unwrap();
    let database = owner.issue_lease().unwrap();
    crate::tests::harness::bind_test_session_relation_graph(&database).unwrap();
    let lease = acquire_exclusive_for_profile(&profile, "prune apply fixture").unwrap();
    {
        let _scope =
            enter_maintenance_database_scope(&lease, &profile, "prepare prune fixture").unwrap();
        database
            .prepare_profile_session_prune_lookup(&lease)
            .await
            .unwrap();
    }

    (directory, owner, database, lease)
}

async fn persist_offered(
    database: &RegisteredGlobalDb,
    observation: DurableObservationV1,
) -> tracedecay_store::ObservationPersistOutcome {
    let outcome = persist_in_database(database, observation.clone()).await;
    database
        .record_observation_source_presence(
            observation.source(),
            observation.scope(),
            &[crate::ObservationSourcePresenceV1 {
                observation_id: observation.observation_id().clone(),
                generation: observation.identity().generation(),
                start_offset: observation.identity().position().start(),
            }],
        )
        .await
        .unwrap();
    outcome
}

async fn present(database: &RegisteredGlobalDb, observation: &DurableObservationV1) -> bool {
    database
        .observation_store()
        .get_observation(observation.observation_id())
        .await
        .unwrap()
        .is_some()
}

#[asupersync::test]
async fn confirmed_apply_retires_missing_sources_but_never_the_user_pseudo_project() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "prune apply test",
    )
    .unwrap();
    let gone = observation("gone", "/missing", "/missing", false);
    let pinned = observation("pinned", "/missing", "/missing", true);
    let rowless = observation("rowless", "/missing", "/missing", false);
    let user = observation("user", "user", "user", true);
    let empty = observation("empty", "", "", true);
    let redacted = observation(
        "redacted",
        "/missing/[REDACTED]",
        "/missing/[REDACTED]",
        true,
    );
    let live = observation("live", "/live", "/live", true);
    for record in [&gone, &rowless, &user, &empty, &redacted, &live, &pinned] {
        persist_offered(&database, record.clone()).await;
    }
    let probe = |path: &Path| {
        if path == Path::new(&fixture_path("/live")) {
            PathProbe::Live
        } else {
            PathProbe::Missing
        }
    };
    let plan = database
        .plan_profile_session_prune(&[], &probe, 2)
        .await
        .unwrap();
    assert_eq!(plan.selected_sources.len(), 3);
    assert!(
        database
            .apply_profile_session_prune_offline(&plan, "wrong", &lease, &[], &probe, 128, 0)
            .await
            .is_err()
    );
    assert!(present(&database, &gone).await);
    let outcome = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 128, 0)
        .await
        .unwrap();
    assert_eq!(outcome.retired_observations, 2, "{outcome:#?}");
    assert_eq!(outcome.completed_sources, 2);
    assert_eq!(outcome.deferred_sources.len(), 1);
    assert_eq!(outcome.deferred_sources[0].source, *pinned.source());
    assert!(matches!(&outcome.deferred_sources[0].reason,
        ProfileSessionPruneDeferReason::Retirement(blockers)
            if blockers.contains(&crate::observation::bookkeeping::retire::RetirementBlocker::TemporalOccurrences)));
    assert!(present(&database, &pinned).await);
    assert!(!present(&database, &gone).await);
    assert!(!present(&database, &rowless).await);
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(
        classify_exclusion(&read, &gone).await.unwrap(),
        Some(PruneExclusion::OperatorPrunedSource)
    );
    for record in [&user, &empty, &redacted, &live, &pinned] {
        assert!(
            present(&database, record).await,
            "preserve {}",
            record.source().session_id()
        );
        assert_eq!(classify_exclusion(&read, record).await.unwrap(), None);
    }
    drop(read);
    let retry = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 128, 0)
        .await
        .unwrap();
    assert_eq!(retry.retired_observations, 0);
    assert_eq!(retry.completed_sources, 2);
}

#[asupersync::test]
async fn bounded_apply_counts_deferred_attempts_and_resumes_after_a_pinned_source() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "bounded prune",
    )
    .unwrap();
    let pinned = observation("a-pinned", "/missing", "/missing", true);
    let eligible = observation("b-eligible", "/missing", "/missing", false);
    persist_offered(&database, pinned.clone()).await;
    persist_offered(&database, eligible.clone()).await;
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    let first = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(
        first.retired_observations, 0,
        "a deferred kernel attempt consumes the page budget"
    );
    assert!(first.has_more);
    assert_eq!(first.next_source_offset, Some(1));
    assert_eq!(first.deferred_sources.len(), 1);
    let second = database
        .apply_profile_session_prune_offline(
            &plan,
            plan.digest(),
            &lease,
            &[],
            &probe,
            1,
            first.next_source_offset.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.retired_observations, 1);
    assert!(!second.has_more);
    assert!(!present(&database, &eligible).await);
    assert!(present(&database, &pinned).await);
}

#[asupersync::test]
async fn interrupted_source_resumes_from_atomic_marker_without_rewinding_its_cursor() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope =
        enter_maintenance_database_scope(&lease, &directory.path().join("profile"), "resume prune")
            .unwrap();
    for ordinal in 0..129 {
        persist_offered(
            &database,
            observation_record("large", "/missing", "/missing", false, ordinal, "fixture"),
        )
        .await;
    }
    let old = observation("large", "/missing", "/missing", false);
    let tail = observation_record("large", "/missing", "/missing", false, 128, "fixture");
    let cursor = database
        .observation_store()
        .get_source_cursor(old.source(), old.scope())
        .await
        .unwrap();
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 7)
        .await
        .unwrap();
    let serialized = serde_json::to_string(&plan).unwrap();
    let first = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(first.retired_observations, 128, "{first:#?}");
    assert_eq!(first.next_source_offset, Some(0));
    assert!(first.has_more);
    let resumed: ProfileSessionPrunePlan = serde_json::from_str(&serialized).unwrap();
    let second = database
        .apply_profile_session_prune_offline(&resumed, resumed.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(second.retired_observations, 1);
    assert_eq!(second.completed_sources, 1);
    assert!(!second.has_more);
    assert!(!present(&database, &old).await);
    assert!(!present(&database, &tail).await);
    assert_eq!(
        database
            .observation_store()
            .get_source_cursor(old.source(), old.scope())
            .await
            .unwrap(),
        cursor
    );
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(
        classify_exclusion(&read, &tail).await.unwrap(),
        Some(PruneExclusion::OperatorPrunedSource)
    );
}

#[asupersync::test]
async fn failed_cascade_rolls_back_exclusion_and_remains_retryable() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "rollback prune",
    )
    .unwrap();
    let old = observation("rollback", "/missing", "/missing", false);
    persist_offered(&database, old.clone()).await;
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    let writer = database.writer_connection().unwrap();
    writer.execute_batch("CREATE TRIGGER injected_prune_failure BEFORE DELETE ON observation_repository_provenance BEGIN SELECT RAISE(ABORT,'prune rollback fixture'); END;").await.unwrap();
    assert!(
        database
            .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
            .await
            .is_err()
    );
    assert!(present(&database, &old).await);
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(
        classify_exclusion(&read, &old).await.unwrap(),
        None,
        "exclusion must not commit ahead of the cascade"
    );
    drop(read);
    writer
        .execute_batch("DROP TRIGGER injected_prune_failure;")
        .await
        .unwrap();
    let retry = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(retry.retired_observations, 1);
    assert!(!present(&database, &old).await);
}

#[asupersync::test]
async fn apply_rechecks_real_filesystem_and_exact_store_and_profile_authority() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope =
        enter_maintenance_database_scope(&lease, &directory.path().join("profile"), "fenced prune")
            .unwrap();
    let available = directory.path().canonicalize().unwrap();
    let gone = available.join("project");
    let root = gone.to_str().unwrap();
    let old = observation("fenced", root, root, false);
    persist_offered(&database, old.clone()).await;
    let roots = [available];
    let probe = |path: &Path| probe_project_path(path, &roots);
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    assert_eq!(plan.selected_sources.len(), 1);
    let (other_directory, _other_owner, other, other_lease) = fixture().await;
    let _other_scope = enter_maintenance_database_scope(
        &other_lease,
        &other_directory.path().join("profile"),
        "other profile",
    )
    .unwrap();
    assert!(
        database
            .apply_profile_session_prune_offline(
                &plan,
                plan.digest(),
                &other_lease,
                &[],
                &probe,
                1,
                0
            )
            .await
            .is_err()
    );
    assert!(
        other
            .apply_profile_session_prune_offline(
                &plan,
                plan.digest(),
                &other_lease,
                &[],
                &probe,
                1,
                0
            )
            .await
            .is_err()
    );
    assert!(
        database
            .apply_profile_session_prune_offline(
                &plan,
                plan.digest(),
                &lease,
                &[vec![gone.clone()]],
                &probe,
                1,
                0
            )
            .await
            .is_err()
    );
    std::fs::create_dir(&gone).unwrap();
    let outcome = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(outcome.retired_observations, 0);
    assert_eq!(outcome.deferred_sources.len(), 1);
    assert!(present(&database, &old).await);
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(classify_exclusion(&read, &old).await.unwrap(), None);
}

#[asupersync::test]
async fn retry_preserves_source_exclusion_without_extending_old_approval() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope =
        enter_maintenance_database_scope(&lease, &directory.path().join("profile"), "stale prune")
            .unwrap();
    let old = observation("reappeared", "/missing", "/missing", false);
    persist_offered(&database, old.clone()).await;
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    // The original approval installed a source exclusion. Later intake is
    // terminal cursor-only coverage, never new evidence for that old approval.
    let newcomer = observation_record(
        "reappeared",
        "/missing",
        "/missing",
        false,
        1,
        "new evidence",
    );
    let admitted = persist_offered(&database, newcomer.clone()).await;
    assert!(matches!(
        admitted,
        tracedecay_store::ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(admitted.receipt().is_none());
    assert_eq!(admitted.committed_cursor().position(), 200);
    assert!(!present(&database, &newcomer).await);
    let retry = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(retry.retired_observations, 0);
    assert_eq!(retry.completed_sources, 1);
}

#[asupersync::test]
async fn one_source_apply_does_not_reclassify_unrelated_observations() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "source-only prune",
    )
    .unwrap();
    let selected = observation("selected", "/missing", "/missing", false);
    persist_offered(&database, selected.clone()).await;
    let probe = |path: &Path| {
        if path == Path::new(&fixture_path("/live")) {
            PathProbe::Live
        } else {
            PathProbe::Missing
        }
    };
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    for index in 0..16 {
        persist_offered(
            &database,
            observation(&format!("unrelated-{index}"), "/live", "/live", false),
        )
        .await;
    }
    CLASSIFIED_OBSERVATIONS.with(|count| count.set(0));
    let outcome = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await
        .unwrap();
    assert_eq!(outcome.retired_observations, 1);
    assert_eq!(
        CLASSIFIED_OBSERVATIONS.with(|count| count.get()),
        1,
        "a one-source apply page must classify only that source's canonical evidence"
    );
    CLASSIFIED_OBSERVATIONS.with(|count| count.set(0));
    let done = database
        .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 1)
        .await
        .unwrap();
    assert!(!done.has_more);
    assert_eq!(
        CLASSIFIED_OBSERVATIONS.with(|count| count.get()),
        0,
        "an end offset must not census anything"
    );
}

#[asupersync::test]
async fn apply_refuses_a_misshaped_source_index_without_canonical_body_reads() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "prune index guard",
    )
    .unwrap();
    let selected = observation("selected", "/missing", "/missing", false);
    persist_offered(&database, selected.clone()).await;
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    let writer = database.writer_connection().unwrap();
    writer.execute_batch("DROP INDEX idx_profile_prune_source; CREATE INDEX idx_profile_prune_source ON observations(sequence);").await.unwrap();
    CLASSIFIED_OBSERVATIONS.with(|count| count.set(0));
    assert!(
        database
            .apply_profile_session_prune_offline(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
            .await
            .is_err(),
        "a named index is not proof of an indexed source lookup"
    );
    assert_eq!(CLASSIFIED_OBSERVATIONS.with(|count| count.get()), 0);
    assert!(present(&database, &selected).await);
}

#[asupersync::test]
async fn production_apply_is_disabled_until_intake_consumes_exclusions() {
    let (directory, _owner, database, lease) = fixture().await;
    let _scope = enter_maintenance_database_scope(
        &lease,
        &directory.path().join("profile"),
        "production prune guard",
    )
    .unwrap();
    let selected = observation("selected", "/missing", "/missing", false);
    persist_offered(&database, selected.clone()).await;
    let probe = |_: &Path| PathProbe::Missing;
    let plan = database
        .plan_profile_session_prune(&[], &probe, 1)
        .await
        .unwrap();
    let result = database
        .apply_profile_session_prune(&plan, plan.digest(), &lease, &[], &probe, 1, 0)
        .await;
    assert!(
        result.is_err(),
        "production apply must not create exclusions that intake does not consume"
    );
    assert!(result.unwrap_err().to_string().contains("admission"));
    assert!(present(&database, &selected).await);
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(classify_exclusion(&read, &selected).await.unwrap(), None);
}
