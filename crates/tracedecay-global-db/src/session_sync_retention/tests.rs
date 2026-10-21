use super::*;
use crate::tests::harness::HostAdmissionTestRuntimeV1;
use tracedecay_contracts::session_sync::{
    SessionSyncCommandV1, SessionSyncCompletionReceiptV1, SessionSyncCoverageV1,
    SessionSyncJournalStatusV1, SessionSyncJournalV1, SessionSyncOutcomeV1, SessionSyncRequestV1,
    SessionSyncSourceCoverageV1, SessionSyncSourceFrontierV1, SessionTranscriptImportV1,
};
use tracedecay_contracts::{
    CancellationSignal, Deadline, IdempotencyKey, OperationTermination, RequestId,
};
use tracedecay_domain::{ProjectId, UserProfileId, UtcMicros};
use tracedecay_runtime_core::db::engine::params;

const NOW: UtcMicros = UtcMicros(1_790_000_000_000_000);

fn fixture_journal(id: &str, project: &str, completed_at: UtcMicros) -> SessionSyncJournalV1 {
    let scope = SessionSyncScopeV1::new(
        ProjectId::new(project).unwrap(),
        UserProfileId::new("profile.fixture").unwrap(),
    );
    let request = SessionSyncRequestV1::new(
        RequestId::new(id).unwrap(),
        IdempotencyKey::new(id).unwrap(),
        scope,
        Deadline::new(UtcMicros(NOW.0 + 60_000_000)).unwrap(),
        CancellationSignal::active(id).unwrap(),
        SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
    );
    let mut journal = SessionSyncJournalV1::queued(&request, UtcMicros(completed_at.0 - 1));
    journal.status = SessionSyncJournalStatusV1::Complete;
    journal.updated_at = completed_at;
    journal.stats.sessions_imported = 7;
    journal.coverage = ["project", "profile"]
        .into_iter()
        .map(|store_scope| SessionSyncSourceCoverageV1 {
            store_scope: store_scope.to_owned(),
            coverage: SessionSyncCoverageV1::Complete,
        })
        .collect();
    journal.completion = Some(SessionSyncCompletionReceiptV1 {
        admission: journal.admission.clone(),
        coalesced_primary: None,
        completed_at,
        termination: OperationTermination::Completed,
        stats: journal.stats.clone(),
        coverage: journal.coverage.clone(),
        source_frontiers: Vec::new(),
        failure_codes: Vec::new(),
    });
    journal
}

fn key(journal: &SessionSyncJournalV1) -> String {
    let profile = journal.scope.profile_id().as_str();
    let project = journal.scope.project_id().as_str();
    format!(
        "session-sync.v1.p{}:{profile}.r{}:{project}.{}",
        profile.len(),
        project.len(),
        journal.admission.idempotency_key.as_str()
    )
}

async fn seed(registry: &RegisteredGlobalDb, journal: &SessionSyncJournalV1) -> String {
    let key = key(journal);
    assert!(
        registry
            .insert_session_sync_journal(&key, &serde_json::to_string(journal).unwrap())
            .await
            .unwrap()
    );
    registry
        .writer_connection()
        .unwrap()
        .execute(
            "UPDATE session_backfill_meta SET updated_at = 123 WHERE key = ?1",
            params![key.as_str()],
        )
        .await
        .unwrap();
    key
}

#[asupersync::test]
async fn legacy_terminal_compaction_preserves_outcome_and_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    assert_eq!(registry.db_path().file_name().unwrap(), "global.db");
    let mut journal = fixture_journal(
        "session-sync.startup.00000000000000000000000000000001.project.fixture",
        "project.fixture",
        UtcMicros(10),
    );
    journal.scope = SessionSyncScopeV1::new(
        journal.scope.project_id().clone(),
        registry.binding().shard_id.profile_id.clone(),
    );
    let frontiers: Vec<_> = (0..1024)
        .map(|n| SessionSyncSourceFrontierV1 {
            store_scope: "profile".to_owned(),
            source_json: format!(r#"{{"provider":"codex","session_id":"session-{n}"}}"#),
            scope_json: r#"{"kind":"profile"}"#.to_owned(),
            committed_cursor_json: format!(
                r#"{{"offset":{n},"generation":"{}"}}"#,
                "x".repeat(2048)
            ),
        })
        .collect();
    journal.source_frontiers = frontiers.clone();
    journal.completion.as_mut().unwrap().source_frontiers = frontiers;
    let expected_outcome = SessionSyncOutcomeV1::Complete {
        source: journal.source.source(),
        receipt: journal.completion.clone().unwrap(),
    };
    assert_eq!(journal.outcome(), expected_outcome);
    let before = serde_json::to_string(&journal).unwrap();
    assert!(before.len() > 4 * 1024 * 1024);
    let key = seed(registry, &journal).await;
    registry
        .insert_session_sync_journal("profile-project-prune.v1.fixture", &before)
        .await
        .unwrap();

    let plan = plan_session_sync_journal_gc(registry, None, None)
        .await
        .unwrap();
    assert_eq!(
        registry
            .read_session_sync_journal(&key)
            .await
            .unwrap()
            .unwrap(),
        before,
        "preview must not write"
    );
    assert_eq!(
        plan.candidates.len(),
        1,
        "legacy duplicate frontier payload must be planned for compaction"
    );
    assert!(plan.candidates[0].logical_bytes_released > 2 * 1024 * 1024);
    assert!(
        apply_session_sync_journal_gc(registry, &plan, "unapproved")
            .await
            .is_err()
    );
    let receipt = apply_session_sync_journal_gc(registry, &plan, &plan.digest)
        .await
        .unwrap();
    assert_eq!(receipt.compacted, 1);
    let encoded = registry
        .read_session_sync_journal(&key)
        .await
        .unwrap()
        .unwrap();
    let compacted: SessionSyncJournalV1 = serde_json::from_str(&encoded).unwrap();
    assert!(compacted.source_frontiers.is_empty());
    assert_eq!(compacted.completion, journal.completion);
    assert_eq!(compacted.outcome(), expected_outcome);
    assert_eq!(compacted.updated_at, journal.updated_at);
    assert_eq!(
        registry
            .read_session_sync_journal("profile-project-prune.v1.fixture")
            .await
            .unwrap()
            .unwrap(),
        before
    );
    let snapshot = registry.read_snapshot().await.unwrap();
    let mut rows = snapshot
        .query(
            "SELECT updated_at FROM session_backfill_meta WHERE key = ?1",
            params![key.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        123
    );
    drop(rows);
    drop(snapshot);
    let again = plan_session_sync_journal_gc(registry, None, None)
        .await
        .unwrap();
    assert!(
        again.candidates.is_empty(),
        "already compacted rows must not be rewritten"
    );
    assert_eq!(
        apply_session_sync_journal_gc(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .stale,
        1
    );
}

#[asupersync::test]
async fn journal_compaction_preserves_manual_nonterminal_and_unrelated_keys() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let mut original = Vec::new();
    for (id, status) in [
        ("manual-import", SessionSyncJournalStatusV1::Complete),
        (
            "session-sync.startup.manual.project.fixture",
            SessionSyncJournalStatusV1::Complete,
        ),
        (
            "session-sync.startup.00000000000000000000000000000001.project.fixture",
            SessionSyncJournalStatusV1::Running,
        ),
        (
            "session-sync.startup.00000000000000000000000000000002.project.fixture",
            SessionSyncJournalStatusV1::Queued,
        ),
    ] {
        let mut journal = fixture_journal(id, "project.fixture", UtcMicros(10));
        journal.scope = SessionSyncScopeV1::new(
            journal.scope.project_id().clone(),
            registry.binding().shard_id.profile_id.clone(),
        );
        journal.status = status;
        journal.source_frontiers = vec![SessionSyncSourceFrontierV1 {
            store_scope: "profile".to_owned(),
            source_json: "{}".to_owned(),
            scope_json: "{}".to_owned(),
            committed_cursor_json: "{}".to_owned(),
        }];
        journal.completion.as_mut().unwrap().source_frontiers = journal.source_frontiers.clone();
        let key = seed(registry, &journal).await;
        original.push((key, serde_json::to_string(&journal).unwrap()));
    }
    let unrelated = "profile-project-prune.v1.fixture";
    assert!(
        registry
            .insert_session_sync_journal(unrelated, "{unrelated}")
            .await
            .unwrap()
    );
    let plan = plan_session_sync_journal_gc(registry, None, None)
        .await
        .unwrap();
    assert!(
        plan.candidates.is_empty(),
        "manual and nonterminal journal bytes must not change"
    );
    assert_eq!(
        apply_session_sync_journal_gc(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .compacted,
        0
    );
    for (key, before) in original {
        assert_eq!(
            registry.read_session_sync_journal(&key).await.unwrap(),
            Some(before)
        );
    }
    assert_eq!(
        registry
            .read_session_sync_journal(unrelated)
            .await
            .unwrap()
            .as_deref(),
        Some("{unrelated}")
    );
}

#[asupersync::test]
async fn journal_compaction_binds_preview_and_cursor_to_registry_and_scope() {
    let root = tempfile::tempdir().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(root.path())
        .await
        .unwrap();
    let registry = runtime.profile_registry();
    let mut journal = fixture_journal(
        "session-sync.startup.00000000000000000000000000000001.project.fixture",
        "project.fixture",
        UtcMicros(10),
    );
    journal.scope = SessionSyncScopeV1::new(
        journal.scope.project_id().clone(),
        registry.binding().shard_id.profile_id.clone(),
    );
    journal.source_frontiers = vec![SessionSyncSourceFrontierV1 {
        store_scope: "profile".to_owned(),
        source_json: "{}".to_owned(),
        scope_json: "{}".to_owned(),
        committed_cursor_json: "{}".to_owned(),
    }];
    journal.completion.as_mut().unwrap().source_frontiers = journal.source_frontiers.clone();
    let first_key = seed(registry, &journal).await;
    let mut second = journal.clone();
    let id = "session-sync.startup.00000000000000000000000000000002.project.fixture";
    second.admission.operation_id = RequestId::new(id).unwrap();
    second.admission.idempotency_key = IdempotencyKey::new(id).unwrap();
    second.completion.as_mut().unwrap().admission = second.admission.clone();
    seed(registry, &second).await;
    let plan = plan_session_sync_journal_gc(registry, None, None)
        .await
        .unwrap();
    assert_eq!(plan.candidates.len(), 1);
    let cursor = plan.next.as_ref().unwrap();

    let other_root = tempfile::tempdir().unwrap();
    let other = HostAdmissionTestRuntimeV1::profile(other_root.path())
        .await
        .unwrap();
    let other_registry = other.profile_registry();
    // A copied registry can have identical key/value/timestamps. The preview
    // authorizes only the selected database, not any store with matching bytes.
    seed(other_registry, &journal).await;
    let before = other_registry
        .read_session_sync_journal(&first_key)
        .await
        .unwrap();
    assert!(
        apply_session_sync_journal_gc(other_registry, &plan, &plan.digest)
            .await
            .is_err(),
        "a preview must not authorize writes to another registry"
    );
    assert_eq!(
        other_registry
            .read_session_sync_journal(&first_key)
            .await
            .unwrap(),
        before
    );
    assert!(
        plan_session_sync_journal_gc(other_registry, None, Some(cursor))
            .await
            .is_err()
    );
    assert!(
        plan_session_sync_journal_gc(registry, Some(&journal.scope), Some(cursor))
            .await
            .is_err(),
        "a full-registry cursor cannot silently become a scoped cursor"
    );
    let foreign_scope = SessionSyncScopeV1::new(
        journal.scope.project_id().clone(),
        other_registry.binding().shard_id.profile_id.clone(),
    );
    assert!(
        plan_session_sync_journal_gc(registry, Some(&foreign_scope), None)
            .await
            .is_err()
    );
    assert_eq!(
        apply_session_sync_journal_gc(registry, &plan, &plan.digest)
            .await
            .unwrap()
            .compacted,
        1
    );
}
