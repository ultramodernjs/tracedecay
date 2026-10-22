use clap::Parser;
use tracedecay_contracts::retrieval::AdminCliSurfaceRequestV1;
use tracedecay_contracts::session_sync::{
    SessionSyncCommandV1, SessionSyncCompletionReceiptV1, SessionSyncJournalStatusV1,
    SessionSyncJournalV1, SessionSyncRequestV1, SessionSyncScopeV1, SessionSyncSourceFrontierV1,
    SessionTranscriptImportV1,
};
use tracedecay_contracts::{
    CancellationSignal, Deadline, IdempotencyKey, OperationTermination, RequestId,
};
use tracedecay_domain::{ProjectId, UtcMicros};
use tracedecay_runtime_core::native_runtime;

#[test]
fn journal_gc_preview_never_writes_and_stale_digest_is_refused() {
    let _ = native_runtime::install(native_runtime::default_builder());
    native_runtime::block_on(async {
        crate::cli::Cli::try_parse_from(["tracedecay", "storage", "journal-gc", "--json"]).unwrap();
        let root = tempfile::tempdir().unwrap();
        let (lease, _owner) =
            tracedecay_global_db::tests::harness::open_registered_test_database_fixture(
                &root.path().join("global.db"),
                tracedecay_runtime_core::db::TestDatabaseRuntimeScope::Profile,
            )
            .await
            .unwrap();
        let db = &lease;
        let now = tracedecay_contracts::now_micros();
        let scope = SessionSyncScopeV1::new(
            ProjectId::new("project.b9").unwrap(),
            db.binding().shard_id.profile_id.clone(),
        );
        let mut keys = Vec::new();
        let mut journals = Vec::new();
        for n in 1..=10 {
            let id = format!("session-sync.startup.{n:032x}.project.b9");
            let request = SessionSyncRequestV1::new(
                RequestId::new(&id).unwrap(),
                IdempotencyKey::new(&id).unwrap(),
                scope.clone(),
                Deadline::new(UtcMicros(now.0 + 60_000_000)).unwrap(),
                CancellationSignal::active(&id).unwrap(),
                SessionSyncCommandV1::ImportTranscripts(SessionTranscriptImportV1::all_hosts()),
            );
            let mut journal = SessionSyncJournalV1::queued(&request, now);
            journal.status = SessionSyncJournalStatusV1::Complete;
            journal.source_frontiers = vec![SessionSyncSourceFrontierV1 {
                store_scope: "profile".to_owned(),
                source_json: "{}".to_owned(),
                scope_json: "{}".to_owned(),
                committed_cursor_json: "{\"offset\":42}".to_owned(),
            }];
            journal.completion = Some(SessionSyncCompletionReceiptV1 {
                admission: journal.admission.clone(),
                coalesced_primary: None,
                completed_at: now,
                termination: OperationTermination::Completed,
                stats: Default::default(),
                coverage: Vec::new(),
                source_frontiers: journal.source_frontiers.clone(),
                failure_codes: Vec::new(),
            });
            let p = scope.profile_id().as_str();
            let r = scope.project_id().as_str();
            let key = format!("session-sync.v1.p{}:{p}.r{}:{r}.{id}", p.len(), r.len());
            db.insert_session_sync_journal(&key, &serde_json::to_string(&journal).unwrap())
                .await
                .unwrap();
            keys.push(key);
            journals.push(journal);
        }
        let key = &keys[0];
        let mut journal = journals[0].clone();
        let original = serde_json::to_string(&journal).unwrap();
        let observer = rusqlite::Connection::open_with_flags(
            db.db_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let version = || {
            observer
                .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        let before = version();
        let invoke = |body| {
            let request = serde_json::from_value::<AdminCliSurfaceRequestV1>(body).unwrap();
            tracedecay_mcp::handlers::admin_cli::compute_projectless_admin_cli(
                request,
                db,
                None,
                root.path(),
                None,
                None,
                &[],
            )
        };
        let preview = invoke(serde_json::json!({
            "action": "storage_journal_gc", "cursor": null, "apply": null,
        }))
        .await
        .unwrap();
        let preview = serde_json::to_value(preview).unwrap();
        assert_eq!(version(), before, "preview must issue no database writes");
        assert_eq!(
            db.read_session_sync_journal(key).await.unwrap().as_deref(),
            Some(original.as_str()),
        );
        assert_eq!(preview["candidates"].as_array().unwrap().len(), 1);
        assert!(preview["logical_bytes_released"].as_u64().unwrap() > 0);
        let digest = preview["digest"].as_str().unwrap();
        // Change the candidate after preview, including its byte size.
        journal.stats.sessions_imported = 12345;
        let changed = serde_json::to_string(&journal).unwrap();
        assert!(
            db.compare_and_swap_session_sync_journal(key, &original, &changed)
                .await
                .unwrap()
        );
        assert!(
            invoke(serde_json::json!({
                "action": "storage_journal_gc", "cursor": null, "apply": digest,
            }))
            .await
            .is_err()
        );
        assert_eq!(
            db.read_session_sync_journal(key).await.unwrap().as_deref(),
            Some(changed.as_str()),
        );
        let fresh = serde_json::to_value(
            invoke(serde_json::json!({
                "action": "storage_journal_gc", "cursor": null, "apply": null,
            }))
            .await
            .unwrap(),
        )
        .unwrap();
        let applied = serde_json::to_value(
            invoke(serde_json::json!({
                "action": "storage_journal_gc", "cursor": null, "apply": fresh["digest"],
            }))
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(applied["compacted"], 1);
        let mut cursor = applied["next_cursor"].clone();
        let mut total = 1;
        let mut pages = 0;
        while !cursor.is_null() {
            let preview = serde_json::to_value(
                invoke(serde_json::json!({
                    "action": "storage_journal_gc", "cursor": cursor, "apply": null,
                }))
                .await
                .unwrap(),
            )
            .unwrap();
            assert!(preview["scanned"].as_u64().unwrap() <= 8);
            assert!(preview["candidates"].as_array().unwrap().len() <= 1);
            let applied = serde_json::to_value(
                invoke(serde_json::json!({
                    "action": "storage_journal_gc", "cursor": cursor, "apply": preview["digest"],
                }))
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(applied["cursor"], cursor);
            total += applied["compacted"].as_u64().unwrap();
            cursor = applied["next_cursor"].clone();
            pages += 1;
            assert!(pages < 20, "cursor loop must converge");
        }
        assert_eq!(total, 10);
        for (key, journal) in keys.iter().zip(&journals) {
            let compacted: SessionSyncJournalV1 =
                serde_json::from_str(&db.read_session_sync_journal(key).await.unwrap().unwrap())
                    .unwrap();
            assert!(compacted.source_frontiers.is_empty());
            assert_eq!(compacted.completion, journal.completion);
        }
        let before = version();
        let exhausted = serde_json::to_value(
            invoke(serde_json::json!({
                "action": "storage_journal_gc", "cursor": null, "apply": null,
            }))
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(exhausted["candidates"].as_array().unwrap().is_empty());
        assert_eq!(version(), before, "no-op preview must not write");
    })
    .unwrap();
}
