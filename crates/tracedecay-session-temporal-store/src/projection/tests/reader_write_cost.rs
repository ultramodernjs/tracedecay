use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tracedecay_graph_db::GraphCancellation;
use tracedecay_runtime_core::db::DatabaseEngineReadSnapshot;
use tracedecay_runtime_core::db::engine::{IntoParams, Rows};

struct PlanCheckedSnapshot {
    snapshot: DatabaseEngineReadSnapshot,
    occurrence_plans: Mutex<Vec<Vec<String>>>,
    cancel_on_second_page: Option<Arc<CancelReconstruction>>,
}

#[derive(Default)]
struct CancelReconstruction(AtomicBool);

impl GraphCancellation for CancelReconstruction {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl crate::handle::SessionTemporalQuery for PlanCheckedSnapshot {
    async fn query<P>(
        &self,
        sql: &str,
        params: P,
    ) -> tracedecay_runtime_core::db::engine::Result<Rows>
    where
        P: IntoParams + Send,
    {
        let params = params.into_params()?;
        if sql.contains("FROM session_occurrences AS occurrence") {
            let mut rows = self
                .snapshot
                .query(&format!("EXPLAIN QUERY PLAN {sql}"), params.clone())
                .await?;
            let mut plan = Vec::new();
            while let Some(row) = rows.next().await? {
                plan.push(row.get::<String>(3)?);
            }
            self.occurrence_plans.lock().unwrap().push(plan);
        }
        let result = self.snapshot.query(sql, params).await;
        if sql.contains("FROM session_occurrences AS occurrence")
            && self.occurrence_plans.lock().unwrap().len() == 2
            && let Some(cancellation) = &self.cancel_on_second_page
        {
            cancellation.0.store(true, Ordering::Relaxed);
        }
        result
    }
}

#[asupersync::test]
async fn relation_reconstruction_does_not_sort_session_occurrences() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let session = fixture_session("session.reader-cost");
    // Cross a page boundary with equal timestamps. The occurrence id, not
    // just the instant, must advance the continuation without losing rows.
    for ordinal in 0..520 {
        let mut relations = CanonicalObservationRelationsV1::new(session.clone())
            .with_message_id(ObservationId::new(format!("message.reader-cost-{ordinal}")).unwrap());
        if ordinal >= 512 {
            relations = relations
                .with_agent_id(ObservationId::new(format!("agent.reader-cost-{ordinal}")).unwrap())
                .with_parent_agent_id(ObservationId::new("agent.reader-cost-root").unwrap());
        }
        let (observation, write) = fixture_observation_from_facts(
            &session,
            ordinal,
            ProviderId::new(format!("reader-cost-{ordinal}")).unwrap(),
            ObservationId::new(format!("record.reader-cost-{ordinal}")).unwrap(),
            relations,
            vec![CanonicalObservationFactV1::Message {
                role: CanonicalMessageRoleV1::Assistant,
                content: json!({"text": "reader cost"}),
                model: None,
                timestamp: Some(1_750_000_000),
            }],
            None,
        );
        Box::pin(persist_fixture(&runtime, observation, write)).await;
    }
    temporal_store(&runtime)
        .materialize_pending_session_refresh_for_test(&session)
        .await
        .unwrap();
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let snapshot = database.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT active.generation, COUNT(occurrence.occurrence_id)
         FROM session_temporal_generations AS active
         JOIN session_occurrences AS occurrence ON occurrence.session_id = active.session_id
           AND occurrence.generation <= active.generation
         WHERE active.session_id = ?1 AND active.state = 'active'
         GROUP BY active.generation",
            params![session.as_str()],
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    let generation = tracedecay_domain::SessionProjectionGenerationV1::new(
        u64::try_from(row.get::<i64>(0).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        row.get::<i64>(1).unwrap(),
        520,
        "all fixture rows must be visible at the tested generation"
    );
    eprintln!("reconstructing active generation: {generation:?}");
    drop(rows);
    let checked = PlanCheckedSnapshot {
        snapshot,
        occurrence_plans: Mutex::new(Vec::new()),
        cancel_on_second_page: None,
    };
    let scope =
        SessionRelationScope::profile_sessions(UserProfileId::new("profile.reader-cost").unwrap());
    let projection = crate::relation_projection::reconstruct_session_relation_projection(
        &checked,
        &scope,
        &session,
        generation,
        520,
        100_000,
        Arc::new(NeverCancelled),
    )
    .await
    .unwrap();
    assert_eq!(projection.session_id, session);
    assert!(projection.logical_copies.is_empty());
    assert_eq!(projection.agent_hierarchy.len(), 8);
    for (offset, relation) in projection.agent_hierarchy.iter().enumerate() {
        assert_eq!(relation.parent_agent_id.as_str(), "agent.reader-cost-root");
        assert_eq!(
            relation.child_agent_id.as_str(),
            format!("agent.reader-cost-{}", 512 + offset)
        );
    }
    assert!(projection.thread_hierarchy.is_empty());
    {
        let plans = checked.occurrence_plans.lock().unwrap();
        assert!(
            plans.len() >= 2,
            "reconstruction must read bounded pages: {plans:?}"
        );
        for plan in plans.iter() {
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("USE TEMP B-TREE")),
                "relation reconstruction must read index-ordered pages, not sort a session: {plan:?}"
            );
        }
        eprintln!("relation reconstruction plans: {plans:?}");
    }
    // Exactly 520 rows fit; 519 must fail rather than silently omit an
    // equal-instant occurrence on the second page.
    let error = crate::relation_projection::reconstruct_session_relation_projection(
        &checked,
        &scope,
        &session,
        generation,
        519,
        100_000,
        Arc::new(NeverCancelled),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");

    let cancellation = Arc::new(CancelReconstruction::default());
    let interrupted = PlanCheckedSnapshot {
        snapshot: database.read_snapshot().await.unwrap(),
        occurrence_plans: Mutex::new(Vec::new()),
        cancel_on_second_page: Some(Arc::clone(&cancellation)),
    };
    let error = crate::relation_projection::reconstruct_session_relation_projection(
        &interrupted,
        &scope,
        &session,
        generation,
        520,
        100_000,
        cancellation,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SessionStoreError::Cancelled), "{error}");
    assert_eq!(interrupted.occurrence_plans.lock().unwrap().len(), 2);
    // Cancellation must not publish partial output or consume the cursor.
    let retried = crate::relation_projection::reconstruct_session_relation_projection(
        &checked,
        &scope,
        &session,
        generation,
        520,
        100_000,
        Arc::new(NeverCancelled),
    )
    .await
    .unwrap();
    assert_eq!(retried, projection);
}
