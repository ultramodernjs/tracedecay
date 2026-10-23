#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::tests::harness::{HostAdmissionScope, HostAdmissionTestRuntimeV1};
use tracedecay_domain::*;
use tracedecay_runtime_core::db::engine::params;
use tracedecay_store::{
    AnchoredObservationWrite, ObservationProjectionStore, ObservationStore, ObservationWrite,
    build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
};

mod apply;

std::thread_local! {
    pub(super) static CLASSIFIED_OBSERVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static APPROVAL_DIGEST_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn record_approval_digest() {
    APPROVAL_DIGEST_CALLS.with(|calls| calls.set(calls.get() + 1));
}

/// Keep synthetic absolute locators absolute on the host under test. A rooted
/// `/missing` spelling has no drive on Windows and cannot authorize pruning.
fn fixture_path(path: &str) -> String {
    if cfg!(windows) && path.starts_with('/') {
        format!("C:{path}")
    } else {
        path.to_owned()
    }
}

fn observation(session: &str, root: &str, location: &str, message: bool) -> DurableObservationV1 {
    observation_record(session, root, location, message, 0, "fixture")
}

fn observation_record(
    session: &str,
    root: &str,
    location: &str,
    message: bool,
    ordinal: u64,
    content: &str,
) -> DurableObservationV1 {
    let provider = ProviderId::new("codex").unwrap();
    let session = SessionId::new(session).unwrap();
    let source =
        ObservationSourceIdentityV1::for_provider(provider.clone(), session.clone()).unwrap();
    let range = ObservationSourceRangeV1::new(ordinal * 100, (ordinal + 1) * 100).unwrap();
    let record = ObservationId::new(format!("record.{session}.{ordinal}")).unwrap();
    let mut facts = vec![CanonicalObservationFactV1::Session {
        project_path: Some(fixture_path(root)),
        location_path: Some(fixture_path(location)),
        transcript_path: None,
        title: None,
        started_at: None,
        ended_at: None,
        source: None,
        native_source: None,
        profile: None,
        location_provenance: None,
    }];
    if message {
        facts.push(CanonicalObservationFactV1::Message {
            role: CanonicalMessageRoleV1::Assistant,
            content: serde_json::json!({"text": content}),
            model: None,
            timestamp: Some(1),
        });
    }
    let envelope = CanonicalObservationEnvelopeV1::new(
        provider,
        "response_item",
        record.clone(),
        CanonicalObservationRelationsV1::new(session.clone()).with_message_id(record.clone()),
        facts,
        CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
    )
    .unwrap();
    let payload = serde_json::to_value(envelope).unwrap();
    let receipt = SanitizationReceiptV1::new(
        SanitizationReceiptRefV1::new(
            SanitizationReceiptId::new(format!("receipt.{session}.{ordinal}")).unwrap(),
            ComponentVersion::new("sanitizer.fixture.v1").unwrap(),
        )
        .unwrap(),
        SanitizerDispositionV1::Accepted,
        SensitivityV1::NonSensitive,
        Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
    )
    .unwrap();
    DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            source,
            ObservationScopeV1::Profile,
            ObservationSourceGenerationV1::new(1).unwrap(),
            range,
            ObservationOrderingDomainV1::FileBytes,
            record,
        )
        .unwrap(),
        receipt,
        RetentionClass::new("retention.fixture").unwrap(),
        payload,
    )
    .unwrap()
}

async fn persist(runtime: &HostAdmissionTestRuntimeV1, observation: DurableObservationV1) {
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    persist_in_database(database, observation).await;
}

async fn persist_in_database(
    database: &crate::RegisteredGlobalDb,
    observation: DurableObservationV1,
) -> tracedecay_store::ObservationPersistOutcome {
    let store = database.observation_store();
    let cursor = ObservationSourceCursorV1::for_ordering(
        observation.source().clone(),
        observation.scope().clone(),
        observation.identity().generation(),
        ObservationOrderingDomainV1::FileBytes,
        observation.identity().position().end(),
    )
    .unwrap();
    let expected = store
        .get_source_cursor(observation.source(), observation.scope())
        .await
        .unwrap();
    let write = ObservationWrite::new(observation.clone(), expected, cursor).unwrap();
    let generation = ProjectionGenerationId::new("projection.fixture.v1").unwrap();
    let authorization =
        build_observation_resolution_authorization_v1(&observation, "fixture").unwrap();
    let anchor = build_observation_retrieval_anchor(
        &observation,
        generation.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    let outcome = store
        .persist_observation(AnchoredObservationWrite::new(write, anchor, generation).unwrap())
        .await
        .unwrap();
    if outcome.receipt().is_some() {
        store
            .project_observation(observation.observation_id())
            .await
            .unwrap();
    }
    outcome
}

#[test]
fn filesystem_probe_requires_available_nofollow_ancestry() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let available = root.join("available");
    std::fs::create_dir(&available).unwrap();
    let roots = vec![available.clone()];
    assert_eq!(probe_project_path(&available, &roots), PathProbe::Live);
    assert_eq!(
        probe_project_path(&available.join("missing/deep"), &roots),
        PathProbe::Missing
    );
    assert_eq!(
        probe_project_path(&root.join("unmounted/project"), &roots),
        PathProbe::Unavailable
    );
    assert_eq!(
        probe_project_path(&available.join("../unmounted"), &roots),
        PathProbe::Unavailable
    );
    assert_eq!(
        probe_project_path(Path::new("relative"), &roots),
        PathProbe::Unavailable
    );
    std::fs::write(available.join("file"), b"not a directory").unwrap();
    assert_eq!(
        probe_project_path(&available.join("file/child"), &roots),
        PathProbe::Unavailable
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("absent-target"), available.join("dangling")).unwrap();
        assert_eq!(
            probe_project_path(&available.join("dangling/child"), &roots),
            PathProbe::Unavailable
        );
        std::os::unix::fs::symlink(&available, root.join("alias")).unwrap();
        assert_eq!(
            probe_project_path(&root.join("alias/missing"), &[root.join("alias")]),
            PathProbe::Unavailable
        );
        std::fs::remove_file(available.join("dangling")).unwrap();

        let inaccessible = available.join("inaccessible");
        std::fs::create_dir(&inaccessible).unwrap();
        let permissions = std::fs::metadata(&inaccessible).unwrap().permissions();
        std::fs::set_permissions(&inaccessible, std::fs::Permissions::from_mode(0o000)).unwrap();
        let access = std::fs::symlink_metadata(inaccessible.join("project"));
        let classification = probe_project_path(&inaccessible.join("project"), &roots);
        // Restore access before assertions so fixture cleanup also works on a
        // failed assertion. Privileged test runners can bypass mode bits.
        std::fs::set_permissions(&inaccessible, permissions).unwrap();
        if access.is_err_and(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied) {
            assert_eq!(classification, PathProbe::Unavailable);
        }
        std::fs::remove_dir(&inaccessible).unwrap();
    }
    std::fs::remove_file(available.join("file")).unwrap();
    std::fs::remove_dir(&available).unwrap();
    assert_eq!(
        probe_project_path(&available.join("project"), &roots),
        PathProbe::Unavailable
    );
}

#[asupersync::test]
async fn missing_project_plan_includes_profile_sessions_and_rowless_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    persist(
        &runtime,
        observation("projected", "/missing", "/missing", true),
    )
    .await;
    persist(
        &runtime,
        observation("rowless", "/missing", "/missing", false),
    )
    .await;
    persist(&runtime, observation("live", "/live", "/live", true)).await;
    persist(&runtime, observation("mixed", "/missing", "/live", true)).await;
    persist(
        &runtime,
        observation("unavailable", "/unavailable", "/unavailable", true),
    )
    .await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let plan = plan_profile_session_prune(
        &read,
        &[],
        &|path| {
            if path == Path::new(&fixture_path("/missing")) {
                PathProbe::Missing
            } else if path == Path::new(&fixture_path("/live")) {
                PathProbe::Live
            } else {
                PathProbe::Unavailable
            }
        },
        2,
    )
    .await
    .unwrap();
    assert_eq!(plan.selected_sources.len(), 2, "{plan:#?}");
    assert_eq!(plan.observation_count, 2);
    assert_eq!(plan.rowless_source_count, 1);
}

#[asupersync::test]
async fn pseudo_empty_and_redacted_paths_are_never_vanished_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    for (session, root, location) in [
        ("gone", "/missing", "/missing"),
        ("user", "user", "user"),
        ("empty", "", ""),
        ("redacted", "[TraceDecay redacted: sensitive field]", ""),
        ("placeholder", "/redacted/project", "/redacted/project"),
        (
            "credential",
            "/missing/[TraceDecay redacted: exact credential]/project",
            "/missing/[TraceDecay redacted: exact credential]/project",
        ),
        (
            "redacted-location",
            "/missing",
            "/missing/prefix[TraceDecay redacted: high-entropy token]suffix",
        ),
        ("bracketed", "/missing/[REDACTED]", "/missing/[REDACTED]"),
        ("angled", "/missing/<redacted>", "/missing/<redacted>"),
    ] {
        persist(&runtime, observation(session, root, location, true)).await;
    }
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let plan = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 2)
        .await
        .unwrap();
    let selected: BTreeSet<_> = plan
        .selected_sources
        .iter()
        .map(|source| source.source.session_id().as_str())
        .collect();
    assert_eq!(
        selected,
        BTreeSet::from(["gone"]),
        "a missing placeholder is not a vanished project: {plan:#?}"
    );
    assert_eq!(plan.preserved_sources.len(), 8);
    assert!(
        plan.preserved_sources
            .iter()
            .all(|source| source.reason == PreserveReason::UnknownOwnership)
    );
}

#[asupersync::test]
async fn incomplete_record_ownership_preserves_the_entire_source() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    for session in ["missing-root", "missing-session-fact"] {
        persist(&runtime, observation(session, "/missing", "/missing", true)).await;
        let record = observation_record(session, "/missing", "/missing", true, 1, "unattributed");
        let mut payload = record.payload().clone();
        if session == "missing-root" {
            payload["facts"][0]
                .as_object_mut()
                .unwrap()
                .remove("project_path");
        } else {
            payload["facts"].as_array_mut().unwrap().remove(0);
        }
        let receipt = SanitizationReceiptV1::new(
            record.receipt().receipt().clone(),
            SanitizerDispositionV1::Accepted,
            SensitivityV1::NonSensitive,
            Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
        )
        .unwrap();
        persist(
            &runtime,
            DurableObservationV1::new(
                record.identity().clone(),
                receipt,
                record.retention_class().clone(),
                payload,
            )
            .unwrap(),
        )
        .await;
    }
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let plan = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 1)
        .await
        .unwrap();
    assert!(
        plan.selected_sources.is_empty(),
        "each record must establish ownership: {plan:#?}"
    );
    assert_eq!(plan.preserved_sources.len(), 2);
    assert!(
        plan.preserved_sources
            .iter()
            .all(|source| source.reason == PreserveReason::UnknownOwnership)
    );
}

#[asupersync::test]
async fn explicit_forget_selects_only_the_named_project_and_aliases() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    for (name, root, location) in [
        ("canonical", "/live", "/live/src"),
        ("alias", "/old-alias", "/live/src"),
        ("other-missing", "/missing", "/missing"),
        ("nested-project", "/live/nested", "/live/nested"),
        ("mixed", "/live", "/elsewhere"),
    ] {
        persist(&runtime, observation(name, root, location, true)).await;
    }
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let roots = vec![
        PathBuf::from(fixture_path("/live")),
        PathBuf::from(fixture_path("/old-alias")),
    ];
    let registry = vec![roots.clone()];
    let probe = |path: &Path| {
        if path.starts_with(fixture_path("/missing"))
            || path.starts_with(fixture_path("/old-alias"))
        {
            PathProbe::Missing
        } else {
            PathProbe::Live
        }
    };
    let stale = plan_profile_session_prune(&read, &registry, &probe, 1)
        .await
        .unwrap();
    assert_eq!(stale.selected_sources.len(), 1);
    assert_eq!(
        stale.selected_sources[0].source.session_id().as_str(),
        "other-missing"
    );
    let forget = plan_profile_session_forget(&read, &registry, &roots, &probe, 1)
        .await
        .unwrap();
    let selected: BTreeSet<_> = forget
        .selected_sources
        .iter()
        .map(|source| source.source.session_id().as_str())
        .collect();
    assert_eq!(
        selected,
        BTreeSet::from(["canonical", "alias"]),
        "explicit forget must not become a missing-path sweep"
    );
    assert_ne!(stale.digest(), forget.digest());
    assert!(forget.approve(forget.digest()).is_ok());
    assert!(
        plan_profile_session_forget(&read, &registry, &[], &probe, 1)
            .await
            .is_err()
    );
    assert!(
        plan_profile_session_forget(&read, &registry, &[PathBuf::from("relative")], &probe, 1)
            .await
            .is_err()
    );
    let incomplete = plan_profile_session_forget(
        &read,
        &registry,
        &[PathBuf::from(fixture_path("/old-alias"))],
        &probe,
        1,
    )
    .await
    .unwrap();
    assert!(
        incomplete.selected_sources.is_empty(),
        "unnamed live aliases must remain protected"
    );
}

#[asupersync::test]
async fn missing_canonical_body_prevents_source_wide_prune_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    persist(
        &runtime,
        observation("shared", "/missing", "/missing", true),
    )
    .await;
    let live = observation_record(
        "shared",
        "/missing",
        "/live",
        true,
        1,
        &"live body".repeat(tracedecay_store::INLINE_BODY_BYTES),
    );
    persist(&runtime, live.clone()).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let tx = database.begin_write_transaction().await.unwrap();
    let mut rows = tx
        .query(
            "SELECT observation_json FROM observations WHERE observation_id = ?1",
            params![live.observation_id().as_str()],
        )
        .await
        .unwrap();
    let json = rows
        .next()
        .await
        .unwrap()
        .unwrap()
        .get::<String>(0)
        .unwrap();
    drop(rows);
    let hashes = tracedecay_store::collect_body_refs(&json).unwrap();
    assert!(
        !hashes.is_empty(),
        "fixture must use external canonical bodies"
    );
    for hash in hashes {
        assert_eq!(
            tx.execute(
                "DELETE FROM session_canonical_bodies WHERE content_hash = ?1",
                params![hash],
            )
            .await
            .unwrap(),
            1
        );
    }
    tx.commit().await.unwrap();
    let read = database.read_snapshot().await.unwrap();
    assert!(
        crate::observation::decode_observation_json(&read, &json, "prune corruption fixture")
            .await
            .is_err(),
        "fixture must have undecodable evidence in the otherwise selectable source"
    );
    let result = plan_profile_session_prune(
        &read,
        &[],
        &|path| {
            if path == Path::new(&fixture_path("/live")) {
                PathProbe::Live
            } else {
                PathProbe::Missing
            }
        },
        1,
    )
    .await;
    assert!(
        result.is_err(),
        "undecodable evidence must prevent an actionable source-wide prune plan: {result:?}"
    );
}

#[asupersync::test]
async fn prune_dry_run_is_passive_and_digest_is_independent_of_page_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    for name in ["a", "b", "c"] {
        persist(&runtime, observation(name, "/missing", "/missing", true)).await;
    }
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let before =
        tracedecay_runtime_core::sqlite_read_snapshot::family_fingerprint(database.db_path())
            .unwrap();
    let small = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 1)
        .await
        .unwrap();
    let large = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 200)
        .await
        .unwrap();
    let after =
        tracedecay_runtime_core::sqlite_read_snapshot::family_fingerprint(database.db_path())
            .unwrap();
    assert_eq!(before, after, "preview must not change the database family");
    assert_eq!(small.observation_count, 3);
    assert_eq!(small.largest_page, 1);
    assert_eq!(large.largest_page, 3);
    assert_eq!(
        small.digest(),
        large.digest(),
        "page budget is not approval identity"
    );
}

#[asupersync::test]
async fn prune_approval_rejects_modified_selection() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    persist(
        &runtime,
        observation("selected", "/missing", "/missing", true),
    )
    .await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let mut plan = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 2)
        .await
        .unwrap();
    plan.selected_sources[0].source = observation("unapproved", "/live", "/live", true)
        .source()
        .clone();
    assert!(
        plan.approve(plan.digest()).is_err(),
        "approval must bind the complete selection, not just a caller-supplied digest string"
    );
}

#[test]
fn prune_approval_rejects_legacy_unattributed_evidence() {
    let mut plan = ProfileSessionPrunePlan {
        unattributed_observations: 1,
        ..Default::default()
    };
    plan.digest = approval_digest(&plan).unwrap();
    assert!(
        plan.approve(plan.digest()).is_err(),
        "even an approved legacy digest cannot authorize unclassified evidence"
    );
}

#[asupersync::test]
async fn approved_source_markers_validate_the_census_once() {
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    for ordinal in 0..128 {
        persist(
            &runtime,
            observation(
                &format!("selected.{ordinal}"),
                "/missing",
                "/missing",
                false,
            ),
        )
        .await;
    }
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let plan = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 128)
        .await
        .unwrap();
    assert_eq!(plan.selected_sources.len(), 128);
    assert!(
        plan.approve(&"0".repeat(64)).is_err(),
        "approval requires the exact digest"
    );
    APPROVAL_DIGEST_CALLS.with(|calls| calls.set(0));
    let approved = plan.approve(plan.digest()).unwrap();
    let mut keys = BTreeSet::new();
    for source in approved.selected_sources() {
        let (key, _) = approved.source_exclusion_metadata(source).unwrap();
        assert!(
            keys.insert(key),
            "each approved identity needs its own marker"
        );
    }
    assert_eq!(keys.len(), 128);
    let mut modified = approved.selected_sources()[0].clone();
    modified.observation_count += 1;
    assert!(approved.source_exclusion_metadata(&modified).is_err());
    let mut unselected = approved.selected_sources()[0].clone();
    unselected.source = observation("unselected", "/live", "/live", true)
        .source()
        .clone();
    assert!(approved.source_exclusion_metadata(&unselected).is_err());
    assert_eq!(
        APPROVAL_DIGEST_CALLS.with(|calls| calls.get()),
        1,
        "constructing N source markers must not rehash the entire census N times"
    );
}

#[asupersync::test]
async fn pruned_source_exclusion_survives_generation_changes_without_suppressing_other_sources() {
    use tracedecay_runtime_core::db::engine::params;
    let tmp = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(tmp.path().join("profile"))
        .await
        .unwrap();
    let old = observation("pruned", "/missing", "/missing", true);
    persist(&runtime, old.clone()).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let read = database.read_snapshot().await.unwrap();
    let plan = plan_profile_session_prune(&read, &[], &|_| PathProbe::Missing, 2)
        .await
        .unwrap();
    drop(read);
    let approved = plan.approve(plan.digest()).unwrap();
    let (key, value) = approved
        .source_exclusion_metadata(&approved.selected_sources()[0])
        .unwrap();
    let tx = database.begin_write_transaction().await.unwrap();
    tx.execute(
        "INSERT INTO session_backfill_meta(key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let successor = DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            old.source().clone(),
            old.scope().clone(),
            ObservationSourceGenerationV1::new(99).unwrap(),
            old.identity().position(),
            old.identity().ordering_domain(),
            ObservationId::new("record.new-generation").unwrap(),
        )
        .unwrap(),
        old.receipt().clone(),
        old.retention_class().clone(),
        old.payload().clone(),
    )
    .unwrap();
    let read = database.read_snapshot().await.unwrap();
    assert_eq!(
        classify_exclusion(&read, &successor).await.unwrap(),
        Some(PruneExclusion::OperatorPrunedSource)
    );
    assert_eq!(
        classify_exclusion(&read, &observation("other", "/missing", "/missing", true))
            .await
            .unwrap(),
        None
    );
}
