use std::future::Future;
use std::task::{Context, Poll, Waker};

use serde_json::json;
use tracedecay_contracts::CancellationSignal;
use tracedecay_domain::{ObservationScopeV1, ProjectId, SessionId, UtcMicros};
use tracedecay_global_db::RegisteredGlobalDbLeaseV1;
use tracedecay_global_db::tests::harness::RegisteredGlobalDbHarness;
use tracedecay_lcm::{LcmCompressionRequest, LcmError, LcmSummarizerMode, LcmSummaryRequest};
use tracedecay_runtime_core::db::engine::params;
use tracedecay_session_temporal_store::{SessionRefreshRestartStateV1, SessionTemporalAccess};
use tracedecay_store::{SessionRefreshReceiptRequestV1, SessionRefreshTerminalStateV1};

use super::super::DaemonLcmEffectService;
use super::{
    ProjectSummarizerFixture, canonical_envelope, canonical_record_for_scope, compression_request,
    daemon_summary_request, execution_control, explicit_refresh_request, ingest_canonical, message,
    session,
};
use crate::session_temporal_refresh_scheduler::projector::{
    CanonicalSessionTemporalProjector, SessionTemporalRefreshEffect,
    SessionTemporalRefreshProjector,
};

async fn seed_observed_session(
    db: &RegisteredGlobalDbLeaseV1,
    project_id: &ProjectId,
    session_id: &str,
) {
    let records = (1..=4)
        .map(|ordinal| {
            canonical_record_for_scope(
                canonical_envelope(
                    "cursor",
                    session_id,
                    &format!("{session_id}-{ordinal}"),
                    None,
                    (ordinal, ordinal - 1),
                    vec![json!({
                        "kind": "message",
                        "role": "assistant",
                        "content": format!("canonical observed summary source {ordinal}")
                    })],
                ),
                ObservationScopeV1::Project {
                    project_id: project_id.clone(),
                },
            )
        })
        .collect::<Vec<_>>();
    ingest_canonical(db, session_id, &[], &records.iter().collect::<Vec<_>>()).await;
}

async fn selected_refresh_is_settled_before_summary(ready: bool) {
    let fixture = ProjectSummarizerFixture::open().await;
    let db = fixture.db();
    let selected = SessionId::new("selected-refresh-summary").unwrap();
    let unrelated = SessionId::new("unrelated-refresh-summary").unwrap();
    seed_observed_session(&db, &fixture.project_id, selected.as_str()).await;
    seed_observed_session(&db, &fixture.project_id, unrelated.as_str()).await;
    let access = SessionTemporalAccess::new(db.as_ref());
    let selected_begin = access
        .begin_or_join_session_refresh_result(explicit_refresh_request(&selected, 4, 0))
        .await
        .unwrap();
    access
        .begin_or_join_session_refresh_result(explicit_refresh_request(&unrelated, 4, 0))
        .await
        .unwrap();
    let unrelated_before = access
        .session_refresh_recovery_result(&unrelated)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        unrelated_before.restart_state(),
        SessionRefreshRestartStateV1::BeginProjection
    );
    if ready {
        let recovery = access
            .session_refresh_recovery_result(&selected)
            .await
            .unwrap()
            .unwrap();
        let effect = CanonicalSessionTemporalProjector
            .project(&db, recovery)
            .await
            .unwrap();
        let SessionTemporalRefreshEffect::Projection { progress, batch } = effect else {
            panic!("the observed fixture must produce one canonical projection page");
        };
        access
            .persist_session_refresh_projection_batch_controlled_result(
                progress,
                batch,
                execution_control(),
            )
            .await
            .unwrap();
        assert_eq!(
            access
                .session_refresh_recovery_result(&selected)
                .await
                .unwrap()
                .unwrap()
                .restart_state(),
            SessionRefreshRestartStateV1::ReadyToComplete
        );
    }

    let service = DaemonLcmEffectService::new(db.clone(), None, None);
    let compressed = service
        .compress(compression_request(selected.as_str()))
        .await
        .unwrap();
    assert_eq!(compressed.summary_nodes_created, 1);
    assert!(
        access
            .session_refresh_recovery_result(&selected)
            .await
            .unwrap()
            .is_none()
    );
    let receipt = access
        .session_refresh_receipt_result(SessionRefreshReceiptRequestV1::new(
            selected_begin.operation_id().clone(),
            selected.clone(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), SessionRefreshTerminalStateV1::Complete);
    assert_eq!(
        access
            .session_refresh_recovery_result(&unrelated)
            .await
            .unwrap(),
        Some(unrelated_before),
        "compaction must preserve another session's exact candidate and refresh ownership"
    );
    assert_eq!(
        db.lcm_status("cursor", Some(unrelated.as_str()))
            .await
            .unwrap()
            .summary_node_count,
        0
    );
}

#[tokio::test]
async fn summary_completes_its_building_refresh_without_advancing_unrelated_refresh() {
    selected_refresh_is_settled_before_summary(false).await;
}

#[tokio::test]
async fn summary_completes_its_ready_refresh_without_advancing_unrelated_refresh() {
    selected_refresh_is_settled_before_summary(true).await;
}

async fn seed_raw_session(db: &RegisteredGlobalDbLeaseV1, session_id: &str) {
    assert!(db.upsert_session(&session("cursor", session_id)).await);
    for ordinal in 1..=4 {
        let mut record = message(session_id, ordinal);
        record.message_id = format!("{session_id}-{ordinal}");
        db.lcm_ingest_raw_message(db.db_path().parent().unwrap(), &record)
            .await
            .unwrap();
    }
}

async fn plan_summary(
    service: &DaemonLcmEffectService,
    session_id: &str,
) -> (LcmCompressionRequest, LcmSummaryRequest, i64) {
    let mut request = daemon_summary_request("cursor", session_id);
    // One plan covers three raw messages and leaves exactly one fresh tail.
    request.overrides.leaf_chunk_tokens = None;
    let (planned, revision) = service.commit_compression(&request, None).await.unwrap();
    assert_eq!(planned.status, "needs_summary");
    assert_eq!(planned.summary_nodes_created, 0);
    let summary = planned.summary_request.unwrap();
    assert_eq!(summary.source_messages.len(), 3);
    request.summarizer = LcmSummarizerMode::Provided {
        summary_text: "summary generated from the original exact three-message plan".to_owned(),
        route: Some("test_exact_planned_source".to_owned()),
        extraction_result: None,
    };
    (request, summary, revision.unwrap())
}

async fn assert_no_summary(db: &RegisteredGlobalDbLeaseV1, session_id: &str) {
    assert_eq!(
        db.lcm_status("cursor", Some(session_id))
            .await
            .unwrap()
            .summary_node_count,
        0
    );
}

async fn revised_plan_cannot_publish(change_role: bool) {
    let harness = RegisteredGlobalDbHarness::open("summary-foreground-revision-guard").await;
    let db = harness.registered.clone();
    let session_id = "foreground-source-revised";
    seed_raw_session(&db, session_id).await;
    let service = DaemonLcmEffectService::new(db.clone(), None, None);
    let (request, summary, revision) = plan_summary(&service, session_id).await;
    let mut revised = message(session_id, 2);
    revised.message_id = format!("{session_id}-2");
    if change_role {
        revised.role = "user".to_owned();
    } else {
        revised.text = "same message identity with different canonical source content".to_owned();
    }
    db.lcm_ingest_raw_message(db.db_path().parent().unwrap(), &revised)
        .await
        .unwrap();
    let snapshot = db.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT store_id FROM lcm_raw_messages WHERE provider = ?1 AND message_id = ?2",
            params![revised.provider.as_str(), revised.message_id.as_str()],
        )
        .await
        .unwrap();
    let revised_store_id = rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap();
    drop(rows);
    drop(snapshot);
    assert_eq!(summary.source_messages[1].store_id, revised_store_id);
    let error = service
        .commit_compression(&request, Some((&summary, revision)))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        LcmError::StaleRawRevision { expected, actual: Some(actual) }
            if expected == revision && actual > revision
    ));
    assert_no_summary(&db, session_id).await;
}

#[tokio::test]
async fn foreground_summary_rejects_same_identity_content_revision() {
    revised_plan_cannot_publish(false).await;
}

#[tokio::test]
async fn foreground_summary_rejects_same_identity_role_revision() {
    revised_plan_cannot_publish(true).await;
}

#[tokio::test]
async fn foreground_summary_rejects_retired_interior_source_with_same_endpoints() {
    let harness = RegisteredGlobalDbHarness::open("summary-interior-source-retirement").await;
    let db = harness.registered.clone();
    let session_id = "foreground-interior-source-retired";
    seed_raw_session(&db, session_id).await;
    let service = DaemonLcmEffectService::new(db.clone(), None, None);
    let (request, summary, revision) = plan_summary(&service, session_id).await;
    // Transcript rewrite EOF retirement can remove an interior source row.
    // Exercise that writer boundary with unchanged intake revision so endpoint
    // equality alone cannot protect text generated from the old source.
    let writer = db.begin_write_transaction().await.unwrap();
    assert_eq!(
        writer
            .execute(
                "DELETE FROM lcm_raw_messages WHERE store_id = ?1",
                params![summary.source_messages[1].store_id],
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        tracedecay_lcm::summary_convergence::session_raw_revision(&writer, "cursor", session_id)
            .await
            .unwrap(),
        Some(revision)
    );
    writer.commit().await.unwrap();
    let error = service
        .commit_compression(&request, Some((&summary, revision)))
        .await
        .unwrap_err();
    assert_eq!(error, LcmError::StaleSummarySourceContent);
    assert_no_summary(&db, session_id).await;
}

#[tokio::test]
async fn foreground_summary_rejects_append_that_changes_the_planned_range() {
    let harness = RegisteredGlobalDbHarness::open("summary-source-range-after-append").await;
    let db = harness.registered.clone();
    let session_id = "foreground-source-appended";
    seed_raw_session(&db, session_id).await;
    let service = DaemonLcmEffectService::new(db.clone(), None, None);
    let (request, summary, revision) = plan_summary(&service, session_id).await;
    let mut appended = message(session_id, 5);
    appended.message_id = format!("{session_id}-5");
    db.lcm_ingest_raw_message(db.db_path().parent().unwrap(), &appended)
        .await
        .unwrap();
    let first = service
        .commit_compression(&request, Some((&summary, revision)))
        .await
        .unwrap_err();
    assert!(matches!(first, LcmError::StaleRawRevision { .. }));

    let snapshot = db.read_snapshot().await.unwrap();
    let current_revision =
        tracedecay_lcm::summary_convergence::session_raw_revision(&snapshot, "cursor", session_id)
            .await
            .unwrap()
            .unwrap();
    drop(snapshot);
    // Even with a current revision, source text from the old plan cannot be
    // rebound to the newly selected range by a caller.
    let second = service
        .commit_compression(&request, Some((&summary, current_revision)))
        .await
        .unwrap_err();
    assert!(matches!(
        second,
        LcmError::StaleSummarySourceRange {
            expected_from,
            expected_to,
            actual_from: Some(actual_from),
            actual_to: Some(actual_to),
        } if expected_from == summary.source_range.from_store_id
            && expected_to == summary.source_range.to_store_id
            && actual_from == expected_from && actual_to > expected_to
    ));
    assert_no_summary(&db, session_id).await;
}

#[tokio::test]
async fn cancelled_queued_summary_leaves_the_publication_gate_usable() {
    let harness = RegisteredGlobalDbHarness::open("summary-publication-gate-cancellation").await;
    let db = harness.registered.clone();
    let session_id = "queued-summary-cancelled";
    seed_raw_session(&db, session_id).await;
    let held = db.session_publication_guard().await;
    let cancellation = CancellationSignal::active("cancellation.queued-summary").unwrap();
    let cancelled_service = DaemonLcmEffectService::new(db.clone(), None, Some(&cancellation));
    let mut queued = Box::pin(cancelled_service.compress(compression_request(session_id)));
    assert!(matches!(
        queued
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    assert!(cancellation.cancel(UtcMicros(1)));
    assert_eq!(queued.await.unwrap_err(), LcmError::Cancelled);
    assert_no_summary(&db, session_id).await;
    drop(held);

    let service = DaemonLcmEffectService::new(db.clone(), None, None);
    let published = service
        .compress(compression_request(session_id))
        .await
        .unwrap();
    assert_eq!(published.summary_nodes_created, 1);
    assert_eq!(
        db.lcm_status("cursor", Some(session_id))
            .await
            .unwrap()
            .summary_node_count,
        1
    );
}
