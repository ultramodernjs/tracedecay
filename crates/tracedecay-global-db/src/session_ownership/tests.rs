#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use tracedecay_domain::{
    CanonicalMessageRoleV1, CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1,
    CanonicalObservationFactV1, CanonicalObservationRelationsV1, ComponentVersion,
    DurableObservationV1, ObservationId, ObservationIdentityMaterialV1,
    ObservationOrderingDomainV1, ObservationScopeV1, ObservationSourceCursorV1,
    ObservationSourceGenerationV1, ObservationSourceIdentityV1, ObservationSourceRangeV1,
    PayloadReferenceV1, ProjectId, ProjectionGenerationId, ProviderId, RetentionClass,
    SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1, SanitizerDispositionV1,
    SensitivityV1, SessionId, UtcMicros,
};
use tracedecay_store::{
    AnchorDispositionReasonClassV1, AnchorDispositionStateV1, AnchoredObservationWrite,
    ObservationProjectionStore, ObservationStore, ObservationWrite,
    RetrievalAnchorDispositionRecordV1, RetrievalAnchorDispositionStore,
    build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
};

use crate::observation::retention::{ObservationRetentionConfig, RetentionMode};

use super::*;
use crate::tests::harness::RegisteredGlobalDbTestRuntime;

async fn record(
    db: &RegisteredGlobalDb,
    scope: ObservationScopeV1,
    root: Option<&Path>,
    index: u64,
    content: &str,
    project: bool,
) -> CanonicalObservationIdV1 {
    let provider = ProviderId::new("claude").unwrap();
    let source = ObservationSourceIdentityV1::for_provider(
        provider.clone(),
        SessionId::new("ownership-mixed-session").unwrap(),
    )
    .unwrap();
    let range = ObservationSourceRangeV1::new(index * 100, index * 100 + 100).unwrap();
    let native = ObservationId::new(format!("native-{index}")).unwrap();
    let facts = vec![
        CanonicalObservationFactV1::Session {
            project_path: root.map(|p| p.to_string_lossy().into_owned()),
            location_path: root.map(|p| p.to_string_lossy().into_owned()),
            transcript_path: Some("/fixture/claude/session.jsonl".to_owned()),
            title: None,
            started_at: None,
            ended_at: None,
            source: Some("claude".to_owned()),
            native_source: None,
            profile: None,
            location_provenance: None,
        },
        CanonicalObservationFactV1::Message {
            role: CanonicalMessageRoleV1::User,
            content: serde_json::json!(content),
            model: None,
            timestamp: Some(1_750_000_000),
        },
    ];
    let envelope = CanonicalObservationEnvelopeV1::new(
        provider,
        "user",
        native.clone(),
        CanonicalObservationRelationsV1::new(source.session_id().clone())
            .with_message_id(native.clone()),
        facts,
        CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
    )
    .unwrap();
    let payload = serde_json::to_value(envelope).unwrap();
    let receipt = SanitizationReceiptV1::new(
        SanitizationReceiptRefV1::new(
            SanitizationReceiptId::new(format!(
                "receipt-{}-{index}",
                if project { "project" } else { "profile" }
            ))
            .unwrap(),
            ComponentVersion::new("sanitizer.ownership.v1").unwrap(),
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
            scope.clone(),
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            native,
        )
        .unwrap(),
        receipt,
        RetentionClass::new("ownership-fixture").unwrap(),
        payload,
    )
    .unwrap();
    let id = observation.observation_id().clone();
    let store = db.observation_store();
    let previous = store.get_source_cursor(&source, &scope).await.unwrap();
    let next = ObservationSourceCursorV1::for_ordering(
        source,
        scope,
        ObservationSourceGenerationV1::new(1).unwrap(),
        ObservationOrderingDomainV1::FileBytes,
        range.end(),
    )
    .unwrap();
    let generation = ProjectionGenerationId::new("ownership-fixture-v1").unwrap();
    let authorization =
        build_observation_resolution_authorization_v1(&observation, "ownership-fixture").unwrap();
    let anchor = build_observation_retrieval_anchor(
        &observation,
        generation.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    let write = ObservationWrite::new(observation, previous, next).unwrap();
    store
        .persist_observation(AnchoredObservationWrite::new(write, anchor, generation).unwrap())
        .await
        .unwrap();
    store.project_observation(&id).await.unwrap();
    id
}

#[asupersync::test]
async fn ownership_plan_matches_native_records_not_sessions_or_text() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("profile"),
        &project,
        ProjectId::new("ownership-project").unwrap(),
        tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
            tracedecay_domain::BrainId::new("brain.ownership").unwrap(),
            tracedecay_domain::UserProfileId::new("profile.ownership").unwrap(),
        ),
    )
    .await
    .unwrap();
    let profile = runtime.profile_database();
    let target = runtime.project_database().unwrap();
    let scope = ObservationScopeV1::Project {
        project_id: ProjectId::new("ownership-project").unwrap(),
    };
    let expected = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        0,
        "shared text",
        false,
    )
    .await;
    let target_expected = record(
        target,
        scope.clone(),
        Some(&project),
        0,
        "shared text",
        true,
    )
    .await;
    record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        1,
        "shared text",
        false,
    )
    .await;
    let target_store = target.observation_store();
    let source = target_store
        .get_observation(&target_expected)
        .await
        .unwrap()
        .unwrap()
        .observation()
        .source()
        .clone();
    let previous = target_store
        .get_source_cursor(&source, &scope)
        .await
        .unwrap();
    target_store
        .advance_source_cursor(
            tracedecay_store::ObservationCursorAdvance::new(
                source,
                scope.clone(),
                ObservationSourceGenerationV1::new(1).unwrap(),
                previous,
                ObservationSourceRangeV1::new(100, 200).unwrap(),
                tracedecay_store::ObservationCoverageReason::OutOfScope,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        2,
        "shared text",
        false,
    )
    .await;
    record(
        target,
        scope.clone(),
        Some(&project),
        2,
        "conflicting native contents",
        true,
    )
    .await;
    record(
        profile,
        ObservationScopeV1::Profile,
        None,
        3,
        "shared text",
        false,
    )
    .await;
    record(target, scope.clone(), None, 3, "shared text", true).await;
    let other = temp.path().join("unregistered");
    std::fs::create_dir_all(&other).unwrap();
    record(
        profile,
        ObservationScopeV1::Profile,
        Some(&other),
        4,
        "shared text",
        false,
    )
    .await;
    record(target, scope, Some(&other), 4, "shared text", true).await;
    let roots = vec![project];
    let targets = [SessionOwnershipTargetV1 {
        database: target,
        roots: &roots,
    }];
    let before = crate::tests::harness::writer_telemetry(profile);
    let plan = profile
        .plan_session_ownership_page(&targets, 0, 3)
        .await
        .unwrap();
    assert_eq!(plan.scanned, 3);
    assert_eq!(
        plan.verified.len(),
        1,
        "only a proven native record may be handed off"
    );
    assert_eq!(plan.verified[0].profile_observation_id, expected);
    assert_eq!(plan.verified[0].project_observation_id, target_expected);
    assert_ne!(
        expected, target_expected,
        "scope-qualified identities must stay distinct"
    );
    assert_eq!(plan.retained, 2);
    let tail = profile
        .plan_session_ownership_page(&targets, plan.next_after_sequence, 3)
        .await
        .unwrap();
    assert_eq!(tail.scanned, 2);
    assert_eq!(tail.retained, 2);
    assert!(tail.verified.is_empty());
    let repeated = profile
        .plan_session_ownership_page(&targets, 0, 3)
        .await
        .unwrap();
    assert_eq!(plan, repeated, "read-only plans must be stable");
    assert_eq!(
        before,
        crate::tests::harness::writer_telemetry(profile),
        "planning must never submit a write"
    );
}

#[asupersync::test]
async fn ownership_proof_binds_the_source_profile_store() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let project_id = ProjectId::new("ownership-project").unwrap();
    let identity = tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
        tracedecay_domain::BrainId::new("brain.ownership").unwrap(),
        tracedecay_domain::UserProfileId::new("profile.ownership").unwrap(),
    );
    let original = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("original-profile"),
        &project,
        project_id.clone(),
        identity.clone(),
    )
    .await
    .unwrap();
    let profile = original.profile_database();
    let target = original.project_database().unwrap();
    let id = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        0,
        "identical evidence in distinct source stores",
        false,
    )
    .await;
    record(
        target,
        ObservationScopeV1::Project {
            project_id: project_id.clone(),
        },
        Some(&project),
        0,
        "identical evidence in distinct source stores",
        true,
    )
    .await;
    let replacement = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("replacement-profile"),
        &project,
        project_id,
        identity,
    )
    .await
    .unwrap();
    let replacement_profile = replacement.profile_database();
    let replacement_id = record(
        replacement_profile,
        ObservationScopeV1::Profile,
        Some(&project),
        0,
        "identical evidence in distinct source stores",
        false,
    )
    .await;
    assert_eq!(
        id, replacement_id,
        "observation identity is scope-qualified, not store-qualified"
    );
    assert_ne!(
        profile.verified_locator(),
        replacement_profile.verified_locator()
    );
    let roots = [project];
    let targets = [SessionOwnershipTargetV1 {
        database: target,
        roots: &roots,
    }];
    let original_plan = profile
        .plan_session_ownership_page(&targets, 0, 1)
        .await
        .unwrap();
    let replacement_plan = replacement_profile
        .plan_session_ownership_page(&targets, 0, 1)
        .await
        .unwrap();
    assert_eq!(original_plan.verified.len(), 1);
    assert_eq!(replacement_plan.verified.len(), 1);
    assert_ne!(
        original_plan.verified[0].proof_digest, replacement_plan.verified[0].proof_digest,
        "a record proof must not transfer to a different source profile store"
    );
}

async fn release_evidence(
    database: &RegisteredGlobalDb,
    observation_id: &CanonicalObservationIdV1,
    config: &ObservationRetentionConfig,
) {
    let stored = database
        .observation_store()
        .get_observation(observation_id)
        .await
        .unwrap()
        .unwrap();
    let anchor = stored.retrieval_anchor();
    let now = tracedecay_contracts::clock::now_micros();
    let disposition = RetrievalAnchorDispositionRecordV1::new(
        format!("ownership-retention:{}", anchor.anchor_id().as_str()),
        anchor.anchor_id().clone(),
        tracedecay_domain::FactOwnerV1::from(anchor.owner().clone()),
        AnchorDispositionStateV1::Deleted,
        None,
        AnchorDispositionReasonClassV1::Retention,
        UtcMicros(now.0 - 40 * 24 * 60 * 60 * 1_000_000),
    )
    .unwrap();
    database
        .runtime_database()
        .append_disposition(disposition)
        .await
        .unwrap();
    let report = database
        .run_observation_retention(None, config, RetentionMode::Apply, now)
        .await
        .unwrap();
    assert!(report.errors.is_empty(), "{report:?}");
    assert!(
        report.bytes_reclaimed() > 0,
        "fixture must release evidence"
    );
}

#[asupersync::test]
async fn ownership_plan_skips_released_profile_rows_and_continues() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("profile"),
        &project,
        ProjectId::new("ownership-project").unwrap(),
        tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
            tracedecay_domain::BrainId::new("brain.ownership").unwrap(),
            tracedecay_domain::UserProfileId::new("profile.ownership").unwrap(),
        ),
    )
    .await
    .unwrap();
    let profile = runtime.profile_database();
    let target = runtime.project_database().unwrap();
    let scope = ObservationScopeV1::Project {
        project_id: ProjectId::new("ownership-project").unwrap(),
    };
    // Profile observations have no captured repository provenance. Exercise
    // independent observation and anchor release windows with real retention.
    for (index, windows) in [(Some(30), None), (None, Some(30))].into_iter().enumerate() {
        let id = record(
            profile,
            ObservationScopeV1::Profile,
            Some(&project),
            index as u64,
            "released profile evidence",
            false,
        )
        .await;
        record(
            target,
            scope.clone(),
            Some(&project),
            index as u64,
            "released profile evidence",
            true,
        )
        .await;
        release_evidence(
            profile,
            &id,
            &ObservationRetentionConfig {
                observation_release_after_days: windows.0,
                anchor_release_after_days: windows.1,
                provenance_release_after_days: None,
                ..ObservationRetentionConfig::default()
            },
        )
        .await;
        // Check before the next retention family runs: a later anchor pass
        // would otherwise mask a missing observation-tombstone check.
        let released_page = profile
            .plan_session_ownership_page(&[], 0, index + 1)
            .await
            .unwrap();
        assert_eq!(released_page.scanned, index + 1);
        assert_eq!(released_page.released, index + 1);
        assert!(released_page.verified.is_empty());
    }
    let expected = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        2,
        "live duplicate after released rows",
        false,
    )
    .await;
    record(
        target,
        scope,
        Some(&project),
        2,
        "live duplicate after released rows",
        true,
    )
    .await;
    let roots = [project];
    let targets = [SessionOwnershipTargetV1 {
        database: target,
        roots: &roots,
    }];
    let before = crate::tests::harness::writer_telemetry(profile);
    let mut after_sequence = 0;
    for _ in 0..2 {
        let page = profile
            .plan_session_ownership_page(&targets, after_sequence, 1)
            .await
            .unwrap();
        assert_eq!(page.scanned, 1);
        assert_eq!(page.released, 1);
        assert_eq!(page.retained, 0);
        assert!(page.verified.is_empty());
        assert!(page.next_after_sequence > after_sequence);
        after_sequence = page.next_after_sequence;
    }
    let page = profile
        .plan_session_ownership_page(&targets, after_sequence, 1)
        .await
        .unwrap();
    assert_eq!(page.scanned, 1);
    assert_eq!(page.released, 0);
    assert_eq!(page.retained, 0);
    assert_eq!(page.verified.len(), 1);
    assert_eq!(page.verified[0].profile_observation_id, expected);
    assert_eq!(before, crate::tests::harness::writer_telemetry(profile));
    let end = profile
        .plan_session_ownership_page(&targets, page.next_after_sequence, 1)
        .await
        .unwrap();
    assert_eq!(end.scanned, 0);
    assert_eq!(end.next_after_sequence, page.next_after_sequence);
}

#[asupersync::test]
async fn ownership_plan_retains_profile_when_project_evidence_is_released() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("profile"),
        &project,
        ProjectId::new("ownership-project").unwrap(),
        tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
            tracedecay_domain::BrainId::new("brain.ownership").unwrap(),
            tracedecay_domain::UserProfileId::new("profile.ownership").unwrap(),
        ),
    )
    .await
    .unwrap();
    let profile = runtime.profile_database();
    let target = runtime.project_database().unwrap();
    let scope = ObservationScopeV1::Project {
        project_id: ProjectId::new("ownership-project").unwrap(),
    };
    let retained_id = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        0,
        "retain the only live evidence",
        false,
    )
    .await;
    let released_id = record(
        target,
        scope.clone(),
        Some(&project),
        0,
        "retain the only live evidence",
        true,
    )
    .await;
    release_evidence(target, &released_id, &ObservationRetentionConfig::default()).await;
    let expected = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        1,
        "later live duplicate",
        false,
    )
    .await;
    record(
        target,
        scope,
        Some(&project),
        1,
        "later live duplicate",
        true,
    )
    .await;
    let roots = [project];
    let targets = [SessionOwnershipTargetV1 {
        database: target,
        roots: &roots,
    }];
    let before_profile = crate::tests::harness::writer_telemetry(profile);
    let before_target = crate::tests::harness::writer_telemetry(target);
    let page = profile
        .plan_session_ownership_page(&targets, 0, 2)
        .await
        .unwrap();
    assert_eq!(page.scanned, 2);
    assert_eq!(page.released, 0);
    assert_eq!(page.retained, 1);
    assert_eq!(page.verified.len(), 1);
    assert_eq!(page.verified[0].profile_observation_id, expected);
    assert!(
        profile
            .observation_store()
            .get_observation(&retained_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        before_profile,
        crate::tests::harness::writer_telemetry(profile)
    );
    assert_eq!(
        before_target,
        crate::tests::harness::writer_telemetry(target)
    );
    let end = profile
        .plan_session_ownership_page(&targets, page.next_after_sequence, 2)
        .await
        .unwrap();
    assert_eq!(end.scanned, 0);
}

#[asupersync::test]
async fn ownership_plan_propagates_corrupt_target_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let runtime = RegisteredGlobalDbTestRuntime::project_for_profile_identity(
        temp.path().join("profile"),
        &project,
        ProjectId::new("ownership-project").unwrap(),
        tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1::new(
            tracedecay_domain::BrainId::new("brain.ownership").unwrap(),
            tracedecay_domain::UserProfileId::new("profile.ownership").unwrap(),
        ),
    )
    .await
    .unwrap();
    let profile = runtime.profile_database();
    let target = runtime.project_database().unwrap();
    let profile_id = record(
        profile,
        ObservationScopeV1::Profile,
        Some(&project),
        0,
        "never lose the profile copy on a target error",
        false,
    )
    .await;
    let target_id = record(
        target,
        ObservationScopeV1::Project {
            project_id: ProjectId::new("ownership-project").unwrap(),
        },
        Some(&project),
        0,
        "never lose the profile copy on a target error",
        true,
    )
    .await;
    let roots = [project];
    let targets = [SessionOwnershipTargetV1 {
        database: target,
        roots: &roots,
    }];
    for corrupt in ["{}", "not JSON", r#"{"__retention_released":"unknown"}"#] {
        // Deliberately damage only the disposable fixture; restore the exact
        // immutable guard before making the corruption visible to the reader.
        let transaction = target.begin_write_transaction().await.unwrap();
        transaction
            .execute_batch("DROP TRIGGER observations_immutable_update")
            .await
            .unwrap();
        transaction
            .execute(
                "UPDATE observations SET observation_json = ?1 WHERE observation_id = ?2",
                params![corrupt, target_id.as_str()],
            )
            .await
            .unwrap();
        transaction
            .execute_batch(
                "CREATE TRIGGER observations_immutable_update BEFORE UPDATE ON observations
                 BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END",
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let before = crate::tests::harness::writer_telemetry(profile);
        assert!(
            profile
                .plan_session_ownership_page(&targets, 0, 1)
                .await
                .is_err(),
            "corruption must not become an unavailable-proof skip: {corrupt}"
        );
        assert!(
            profile
                .observation_store()
                .get_observation(&profile_id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(before, crate::tests::harness::writer_telemetry(profile));
    }
}
