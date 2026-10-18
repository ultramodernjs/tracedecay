//! A settled canonical source stays settled across caller and mount changes.

use super::{
    HostCancellationToken, JourneyObservationProvider, MemoryProviderV1,
    ObservationJourneyMountInputsV1, ObservationJourneyPolicyV1, ObservationStore,
    RecoveryJourneyFixture, RefId, ResolvedScope, SessionId, TempDir, anchored_write,
    canonical_observation, composition, exact_scope_for_session, journal_snapshot,
    mount_and_replay, mount_journey_over_port, run_startup_replay, test_observation_mount,
    wait_for_settlement,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracedecay_memory_observation::ObservationJournalReaderV1;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_source_is_not_reenqueued_after_reopen_with_a_later_session_and_resolution() {
    let temp = TempDir::new().unwrap();
    let port = Arc::new(JourneyObservationProvider::new());
    let RecoveryJourneyFixture {
        _runtime,
        store,
        journey,
        project_id,
        profile_id,
        resolved_scope,
    } = mount_journey_over_port(
        &temp,
        "project.journal-checkout-recall",
        "profile.journal-checkout-recall",
        Arc::clone(&port),
    )
    .await;
    let source_session = SessionId::new("session.journal-original-source").unwrap();
    let original = canonical_observation(&project_id, &source_session, "Canonical source text");
    store
        .persist_observation(anchored_write(original.clone()))
        .await
        .unwrap();
    run_startup_replay(&journey, &store, &HostCancellationToken::new())
        .await
        .unwrap();
    let journal_path = journey.journal_path().to_path_buf();
    assert_eq!(
        wait_for_settlement(&journal_path).await,
        ("acknowledged".to_owned(), 1)
    );
    let watermark = journey.replay_watermark().await.unwrap();
    assert!(watermark > 0);
    let inspection = journey
        .journal
        .inspect(&tracedecay_memory_observation::JournalInspectionFilterV1::default())
        .unwrap();
    assert_eq!(inspection.rows.len(), 1);
    let delivery = &inspection.rows[0];
    let receipts = journey
        .journal
        .receipts_for(&delivery.observation_id)
        .unwrap();
    assert_eq!(receipts.len(), 1);
    let snapshot = journal_snapshot(&journal_path);
    let original_exact =
        exact_scope_for_session(&profile_id, &resolved_scope, source_session.as_str()).unwrap();
    assert_eq!(
        delivery.exact_scope_sha256,
        original_exact.exact_scope_sha256()
    );
    assert!(
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
    drop(journey);

    // A valid ResolvedScope digest changes with its branch. The durable replay
    // position still covers the original observation, regardless of the next
    // caller or the delivery scope a new admission would derive today.
    let later_scope = ResolvedScope::new(
        project_id.clone(),
        resolved_scope.repository_id.clone(),
        resolved_scope.worktree_id.clone(),
        Some(RefId::new("refs/heads/later-journal-resolution").unwrap()),
    )
    .unwrap();
    later_scope.validate().unwrap();
    let caller =
        exact_scope_for_session(&profile_id, &later_scope, "session.journal-later-caller").unwrap();
    assert_ne!(caller.agent_session_id, original_exact.agent_session_id);
    assert_ne!(
        caller.resolved_scope_digest,
        original_exact.resolved_scope_digest
    );
    let journal_root = journal_path.parent().unwrap().to_path_buf();
    let reopened = mount_and_replay(
        ObservationJourneyMountInputsV1 {
            composition: composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>),
            profile_id,
            scope: later_scope,
            authoritative_project_id: project_id,
            provider: test_observation_mount(&journal_root, 1).unwrap(),
            store_data_root: journal_root,
            policy: ObservationJourneyPolicyV1::project_default(),
        },
        store.clone(),
        &HostCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.journal_path(), journal_path);
    assert_eq!(reopened.replay_watermark().await.unwrap(), watermark);
    assert_eq!(
        run_startup_replay(&reopened, &store, &HostCancellationToken::new())
            .await
            .unwrap()
            .admitted,
        0
    );
    assert_eq!(journal_snapshot(&journal_path), snapshot);
    assert_eq!(
        reopened
            .journal
            .receipts_for(&delivery.observation_id)
            .unwrap(),
        receipts
    );
    assert_eq!(port.observe_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        store
            .get_observation(original.observation_id())
            .await
            .unwrap()
            .unwrap()
            .observation(),
        &original
    );
    assert!(
        reopened
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .is_empty()
    );
}
