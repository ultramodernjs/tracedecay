use crate::tests::harness::{HostAdmissionScope, HostAdmissionTestRuntimeV1};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Mutex, mpsc};
use tempfile::TempDir;
use tracedecay_domain::{
    ComponentVersion, DurableObservationV1, ObservationId, ObservationIdentityMaterialV1,
    ObservationOrderingDomainV1, ObservationScopeV1, ObservationSourceCursorV1,
    ObservationSourceGenerationV1, ObservationSourceIdentityV1, ObservationSourceRangeV1,
    PayloadReferenceV1, ProjectionGenerationId, ProviderId, RetentionClass, SanitizationReceiptId,
    SanitizationReceiptRefV1, SanitizationReceiptV1, SanitizerDispositionV1, SensitivityV1,
    SessionId, UtcMicros,
};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_store::{
    AnchoredObservationWrite, ObservationPersistOutcome, ObservationStore, ObservationStoreError,
    ObservationStoreResult, ObservationWrite, build_observation_resolution_authorization_v1,
    build_observation_retrieval_anchor,
};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

fn excluded_write(generation: u64) -> AnchoredObservationWrite {
    write_for_session(generation, "source.excluded")
}

fn write_for_session(generation: u64, session: &str) -> AnchoredObservationWrite {
    write_with_payload(generation, session, json!({"body": "excluded evidence"}))
}

fn write_with_payload(
    generation: u64,
    session: &str,
    payload: serde_json::Value,
) -> AnchoredObservationWrite {
    let source = ObservationSourceIdentityV1::for_provider(
        ProviderId::new("codex").unwrap(),
        SessionId::new(session).unwrap(),
    )
    .unwrap();
    let generation = ObservationSourceGenerationV1::new(generation).unwrap();
    let observation = DurableObservationV1::new(
        ObservationIdentityMaterialV1::for_native_record(
            source.clone(),
            ObservationScopeV1::Profile,
            generation,
            ObservationSourceRangeV1::new(0, 100).unwrap(),
            ObservationOrderingDomainV1::FileBytes,
            ObservationId::new("record.excluded").unwrap(),
        )
        .unwrap(),
        SanitizationReceiptV1::new(
            SanitizationReceiptRefV1::new(
                SanitizationReceiptId::new("receipt.excluded").unwrap(),
                ComponentVersion::new("sanitizer.exclusion.v1").unwrap(),
            )
            .unwrap(),
            SanitizerDispositionV1::Accepted,
            SensitivityV1::NonSensitive,
            Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
        )
        .unwrap(),
        RetentionClass::new("retention.exclusion-fixture").unwrap(),
        payload,
    )
    .unwrap();
    let next = ObservationSourceCursorV1::for_ordering(
        source,
        ObservationScopeV1::Profile,
        generation,
        ObservationOrderingDomainV1::FileBytes,
        100,
    )
    .unwrap();
    let write = ObservationWrite::new(observation, None, next).unwrap();
    let projection = ProjectionGenerationId::new("projection.exclusion.v1").unwrap();
    let authorization =
        build_observation_resolution_authorization_v1(write.observation(), "exclusion-fixture")
            .unwrap();
    let anchor = build_observation_retrieval_anchor(
        write.observation(),
        projection.clone(),
        UtcMicros(1),
        authorization,
    )
    .unwrap();
    AnchoredObservationWrite::new(write, anchor, projection).unwrap()
}

async fn mark_excluded(runtime: &HostAdmissionTestRuntimeV1, write: &AnchoredObservationWrite) {
    let observation = write.observation();
    let tuple = serde_json::to_string(&(observation.source(), observation.scope())).unwrap();
    let key = format!(
        "profile-project-prune.v1.source.{}",
        hex::encode(Sha256::digest(tuple.as_bytes()))
    );
    let value = json!({
        "version": 1,
        "source": observation.source(),
        "scope": observation.scope(),
        "plan_digest": "a".repeat(64),
    });
    runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap()
        .writer_connection()
        .unwrap()
        .execute(
            "INSERT INTO session_backfill_meta (key, value) VALUES (?1, ?2)",
            params![key, value.to_string()],
        )
        .await
        .unwrap();
}

struct BarrierSubscriber {
    next: Option<Box<BarrierSubscriber>>,
    message: &'static str,
    reached: Mutex<Option<asupersync::channel::oneshot::Sender<()>>>,
    cx: asupersync::Cx,
    release: Mutex<mpsc::Receiver<()>>,
}
impl Subscriber for BarrierSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "tracedecay::observation_admission_work"
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if let Some(next) = &self.next {
            next.event(event);
        }
        struct IsSubmit {
            message: &'static str,
            matched: bool,
        }
        impl tracing::field::Visit for IsSubmit {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" && format!("{value:?}") == self.message {
                    self.matched = true;
                }
            }
        }
        let mut submit = IsSubmit {
            message: self.message,
            matched: false,
        };
        event.record(&mut submit);
        if submit.matched
            && let Some(reached) = self.reached.lock().unwrap().take()
        {
            let _ = reached.send(&self.cx, ());
            self.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(30))
                .unwrap();
        }
    }
}
// Release and join even if marker setup or an assertion unwinds.
struct Worker {
    release: Vec<mpsc::SyncSender<()>>,
    join: Option<std::thread::JoinHandle<ObservationStoreResult<ObservationPersistOutcome>>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        for release in self.release.drain(..) {
            let _ = release.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[asupersync::test]
async fn excluded_source_admission_is_successful_cursor_only_coverage() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let write = excluded_write(1);
    mark_excluded(&runtime, &write).await;
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let outcome = store.persist_observation(write.clone()).await.unwrap();
    assert!(matches!(
        outcome,
        ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(outcome.receipt().is_none());
    assert_eq!(outcome.committed_cursor(), write.next_cursor());
    assert!(
        store
            .get_observation(write.observation().observation_id())
            .await
            .unwrap()
            .is_none(),
        "an excluded source must not persist observation evidence"
    );
    assert_eq!(
        store
            .get_source_cursor(write.observation().source(), write.observation().scope())
            .await
            .unwrap()
            .as_ref(),
        Some(write.next_cursor())
    );
}

#[asupersync::test]
async fn excluded_source_retries_and_new_generations_preserve_cursor_checkpoints() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let first = excluded_write(1);
    mark_excluded(&runtime, &first).await;
    for _ in 0..2 {
        let batch = store
            .persist_observations(vec![first.clone()])
            .await
            .unwrap();
        assert!(batch[0].outcome().receipt().is_none());
        assert!(batch[0].stored().is_none());
        assert_eq!(batch[0].outcome().committed_cursor(), first.next_cursor());
    }
    let second = excluded_write(2);
    let next = second.next_cursor().clone().with_resume_checkpoint(42, 99);
    let second = AnchoredObservationWrite::new(
        ObservationWrite::new(
            second.observation().clone(),
            Some(first.next_cursor().clone()),
            next.clone(),
        )
        .unwrap(),
        second.retrieval_anchor().clone(),
        second.projection_generation().clone(),
    )
    .unwrap();
    let outcome = store.persist_observation(second.clone()).await.unwrap();
    assert!(outcome.receipt().is_none());
    assert_eq!(outcome.committed_cursor(), &next);
    assert_eq!(outcome.committed_cursor().file_identity(), Some(42));
    assert_eq!(outcome.committed_cursor().resume_fingerprint(), Some(99));
    assert!(
        store
            .get_observation(second.observation().observation_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store
            .persist_observation(excluded_write(3))
            .await
            .unwrap_err(),
        ObservationStoreError::CursorConflict { .. }
    ));
    assert_eq!(
        store
            .get_source_cursor(second.observation().source(), second.observation().scope())
            .await
            .unwrap(),
        Some(next)
    );
}

#[asupersync::test]
async fn excluded_source_presence_and_rewrite_admission_do_not_recreate_bookkeeping() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let write = excluded_write(1);
    mark_excluded(&runtime, &write).await;
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    database
        .record_observation_source_presence(
            write.observation().source(),
            write.observation().scope(),
            &[crate::ObservationSourcePresenceV1 {
                observation_id: write.observation().observation_id().clone(),
                generation: write.observation().identity().generation(),
                start_offset: 0,
            }],
        )
        .await
        .unwrap();
    database
        .begin_observation_source_rewrite(
            write.observation().source(),
            write.observation().scope(),
            ObservationSourceGenerationV1::new(1).unwrap(),
            ObservationSourceGenerationV1::new(2).unwrap(),
            0,
        )
        .await
        .unwrap();
    let snapshot = database.read_snapshot().await.unwrap();
    for table in ["observation_source_presence", "observation_source_rewrites"] {
        let mut rows = snapshot
            .query(&format!("SELECT count(*) FROM {table}"), ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0,
            "{table}"
        );
    }
}

#[asupersync::test]
async fn excluded_source_installed_after_preflight_is_cursor_only_on_commit_and_replay() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let write = excluded_write(1);
    let client = store.clone();
    let candidate = write.clone();
    let cx = asupersync::Cx::current().unwrap();
    let (reached, mut waiting) = asupersync::channel::oneshot::channel();
    let (release, released) = mpsc::sync_channel(1);
    let subscriber = BarrierSubscriber {
        next: None,
        message: "dispatch observation runtime submit",
        reached: Mutex::new(Some(reached)),
        release: Mutex::new(released),
        cx: cx.clone(),
    };
    let join = std::thread::spawn(move || {
        let execution = asupersync::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .unwrap();
        let _capture = tracedecay_runtime_core::logging::set_tracing_capture(subscriber);
        execution.block_on(client.persist_observation(candidate))
    });
    let mut worker = Worker {
        release: vec![release],
        join: Some(join),
    };
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        std::time::Duration::from_secs(30),
        waiting.recv(&cx),
    )
    .await
    .unwrap()
    .unwrap();
    mark_excluded(&runtime, &write).await;
    worker.release.pop().unwrap().send(()).unwrap();
    let outcome = worker.join.take().unwrap().join().unwrap().unwrap();
    assert!(matches!(
        outcome,
        ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(outcome.receipt().is_none());
    assert_eq!(outcome.committed_cursor(), write.next_cursor());
    let replay = store.persist_observation(write.clone()).await.unwrap();
    assert!(matches!(
        replay,
        ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(
        store
            .get_observation(write.observation().observation_id())
            .await
            .unwrap()
            .is_none()
    );
    let snapshot = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap()
        .read_snapshot()
        .await
        .unwrap();
    for table in [
        "observations",
        "sanitization_receipts",
        "session_canonical_bodies",
        "retrieval_anchors",
        "observation_retrieval_anchors",
        "observation_repository_provenance",
        "projection_queue",
        "observation_admission_refusals",
    ] {
        let mut rows = snapshot
            .query(&format!("SELECT count(*) FROM {table}"), ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0,
            "{table}"
        );
    }
}

#[asupersync::test]
async fn excluded_source_mixed_batches_preserve_unrelated_evidence_and_order() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let excluded = excluded_write(1);
    let retained = write_for_session(1, "source.unrelated");
    mark_excluded(&runtime, &excluded).await;
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let outcomes = store
        .persist_observations(vec![excluded.clone(), retained.clone()])
        .await
        .unwrap();
    assert!(matches!(
        outcomes[0].outcome(),
        ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(outcomes[0].stored().is_none());
    assert!(matches!(
        outcomes[1].outcome(),
        ObservationPersistOutcome::Committed(_)
    ));
    let durable = store
        .get_observation(retained.observation().observation_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.observation(), retained.observation());
    let replay = store
        .persist_observations(vec![excluded.clone(), retained.clone()])
        .await
        .unwrap();
    assert!(replay[0].outcome().receipt().is_none());
    assert!(matches!(
        replay[1].outcome(),
        ObservationPersistOutcome::ExactDuplicate(_)
    ));
    assert_eq!(
        store
            .get_observation(retained.observation().observation_id())
            .await
            .unwrap()
            .unwrap(),
        durable
    );
    assert!(
        store
            .get_observation(excluded.observation().observation_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[asupersync::test]
async fn excluded_source_invalid_markers_fail_closed_without_evidence_or_content_in_errors() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let write = excluded_write(1);
    mark_excluded(&runtime, &write).await;
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let valid = json!({"version": 1, "source": write.observation().source(), "scope": write.observation().scope(), "plan_digest": "a".repeat(64)});
    let mut wrong_version = valid.clone();
    wrong_version["version"] = json!(2);
    let mut wrong_source = valid.clone();
    wrong_source["source"] =
        serde_json::to_value(write_for_session(1, "source.other").observation().source()).unwrap();
    let mut wrong_digest = valid;
    wrong_digest["plan_digest"] = json!("z".repeat(64));
    let secret = "private-marker-content-never-echo";
    for value in [
        secret.to_owned(),
        wrong_version.to_string(),
        wrong_source.to_string(),
        wrong_digest.to_string(),
    ] {
        database.writer_connection().unwrap().execute("UPDATE session_backfill_meta SET value = ?1 WHERE key LIKE 'profile-project-prune.v1.source.%'", [value]).await.unwrap();
        let error = store.persist_observation(write.clone()).await.unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(
            store
                .get_source_cursor(write.observation().source(), write.observation().scope())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_observation(write.observation().observation_id())
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(crate::profile_session_prune::require_profile_session_prune_admission().is_err());
}

#[asupersync::test]
async fn excluded_source_acknowledges_accepted_generation_after_frontier_moves() {
    acknowledge_generation_race(false, 0).await;
}

#[asupersync::test]
async fn excluded_source_submitted_and_deferred_acknowledge_generation_race() {
    acknowledge_generation_race(true, 0).await;
}

#[asupersync::test]
async fn excluded_source_deferred_acknowledgement_keeps_prior_partition_coverage() {
    acknowledge_generation_race(
        true,
        tracedecay_store::BACKGROUND_BATCH_MAX_OPERATIONS as usize,
    )
    .await;
}

async fn acknowledge_generation_race(marker_during_submit: bool, additional_writes: usize) {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let first = excluded_write(1);
    if !marker_during_submit {
        mark_excluded(&runtime, &first).await;
    }
    let cx = asupersync::Cx::current().unwrap();
    let (reached, mut waiting) = asupersync::channel::oneshot::channel();
    let (release, released) = mpsc::sync_channel(1);
    let (preflight, mut waiting_preflight) = asupersync::channel::oneshot::channel();
    let (release_preflight, released_preflight) = mpsc::sync_channel(1);
    let subscriber = BarrierSubscriber {
        next: marker_during_submit.then(|| {
            Box::new(BarrierSubscriber {
                next: None,
                message: "dispatch observation runtime submit",
                reached: Mutex::new(Some(preflight)),
                release: Mutex::new(released_preflight),
                cx: cx.clone(),
            })
        }),
        message: "receive observation runtime outcome",
        reached: Mutex::new(Some(reached)),
        release: Mutex::new(released),
        cx: cx.clone(),
    };
    let client = store.clone();
    let candidate = first.clone();
    let join = std::thread::spawn(move || {
        let execution = asupersync::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .unwrap();
        let _capture = tracedecay_runtime_core::logging::set_tracing_capture(subscriber);
        execution.block_on(async move {
            if marker_during_submit {
                let mut writes = vec![candidate.clone()];
                writes.extend(
                    (0..additional_writes)
                        .map(|index| write_for_session(1, &format!("source.partition.{index}"))),
                );
                writes.push(candidate);
                let outcomes = client.persist_observations(writes).await?;
                assert_eq!(outcomes.len(), additional_writes + 2);
                for outcome in [&outcomes[0], outcomes.last().unwrap()] {
                    assert!(matches!(
                        outcome.outcome(),
                        ObservationPersistOutcome::SourceExcluded(_)
                    ));
                    assert!(outcome.outcome().receipt().is_none());
                }
                assert!(
                    outcomes[1..outcomes.len() - 1]
                        .iter()
                        .all(|outcome| outcome.outcome().receipt().is_some())
                );
                Ok(outcomes[0].outcome().clone())
            } else {
                client.persist_observation(candidate).await
            }
        })
    });
    let mut worker = Worker {
        release: vec![release],
        join: Some(join),
    };
    if marker_during_submit {
        worker.release.push(release_preflight);
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            std::time::Duration::from_secs(30),
            waiting_preflight.recv(&cx),
        )
        .await
        .unwrap()
        .unwrap();
        mark_excluded(&runtime, &first).await;
        worker.release.pop().unwrap().send(()).unwrap();
    }
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        std::time::Duration::from_secs(30),
        waiting.recv(&cx),
    )
    .await
    .unwrap()
    .unwrap();
    // The first command is committed, but its acknowledgement has not read back.
    assert_eq!(
        store
            .get_source_cursor(first.observation().source(), first.observation().scope())
            .await
            .unwrap()
            .as_ref(),
        Some(first.next_cursor())
    );
    let second = excluded_write(2);
    let second = AnchoredObservationWrite::new(
        ObservationWrite::new(
            second.observation().clone(),
            Some(first.next_cursor().clone()),
            second.next_cursor().clone(),
        )
        .unwrap(),
        second.retrieval_anchor().clone(),
        second.projection_generation().clone(),
    )
    .unwrap();
    let advanced = store.persist_observation(second.clone()).await.unwrap();
    assert_eq!(advanced.committed_cursor(), second.next_cursor());
    worker.release.pop().unwrap().send(()).unwrap();
    let accepted = worker.join.take().unwrap().join().unwrap()
        .expect("a committed exclusion must acknowledge its accepted generation even after another generation advances");
    assert!(matches!(
        accepted,
        ObservationPersistOutcome::SourceExcluded(_)
    ));
    assert!(accepted.receipt().is_none());
    assert_eq!(accepted.committed_cursor(), first.next_cursor());
    assert_eq!(
        store
            .get_source_cursor(first.observation().source(), first.observation().scope())
            .await
            .unwrap()
            .as_ref(),
        Some(second.next_cursor())
    );
    assert!(
        store
            .get_observation(first.observation().observation_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn source_exclusion_marker_preserves_existing_wire_bytes() {
    let write = excluded_write(1);
    let observation = write.observation();
    let digest = "a".repeat(64);
    let legacy_value = json!({
        "version": 1, "source": observation.source(), "scope": observation.scope(),
        "plan_digest": digest,
    })
    .to_string();
    let tuple = serde_json::to_string(&(observation.source(), observation.scope())).unwrap();
    let legacy_key = format!(
        "profile-project-prune.v1.source.{}",
        hex::encode(Sha256::digest(tuple.as_bytes()))
    );
    let metadata = crate::observation::bookkeeping::retire::ProjectPruneMarker {
        source: observation.source().clone(),
        scope: observation.scope().clone(),
        approved_plan_digest: digest,
    }
    .metadata()
    .unwrap();
    assert_eq!(metadata, (legacy_key, legacy_value));
    tracedecay_store::validate_observation_source_exclusion(
        &metadata.1,
        observation.source(),
        observation.scope(),
    )
    .unwrap();
}

#[asupersync::test]
async fn excluded_source_replay_bypasses_a_corrupt_retained_canonical_body() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let store = runtime
        .observation_store(HostAdmissionScope::Profile)
        .unwrap();
    let write = write_with_payload(
        1,
        "source.excluded",
        json!({"body": "large retained body ".repeat(512)}),
    );
    let committed = store.persist_observation(write.clone()).await.unwrap();
    assert!(committed.receipt().is_some());
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    assert_eq!(
        database
            .writer_connection()
            .unwrap()
            .execute("UPDATE session_canonical_bodies SET body=X'00'", ())
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .get_observation(write.observation().observation_id())
            .await
            .is_err(),
        "the retained fixture must actually fail canonical-body hydration"
    );
    mark_excluded(&runtime, &write).await;
    for _ in 0..2 {
        let accepted = store
            .persist_observation(write.clone())
            .await
            .expect("excluded replay must not hydrate retained observation bodies");
        assert!(matches!(
            accepted,
            ObservationPersistOutcome::SourceExcluded(_)
        ));
        assert!(accepted.receipt().is_none());
        assert_eq!(accepted.committed_cursor(), write.next_cursor());
    }
    // Success did not repair, replace, or accidentally hydrate the corrupt body.
    assert!(
        store
            .get_observation(write.observation().observation_id())
            .await
            .is_err()
    );
}
