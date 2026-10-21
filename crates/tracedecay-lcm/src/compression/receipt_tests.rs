#![cfg(test)]

use tracedecay_runtime_core::db::engine::TestConnection;

use super::*;

async fn fixture() -> (tempfile::TempDir, TestConnection) {
    let temp = tempfile::tempdir().unwrap();
    let conn = TestConnection::open(&temp.path().join("compression.db"));
    conn.execute_batch("CREATE TABLE sessions (provider TEXT NOT NULL, session_id TEXT NOT NULL, project_key TEXT NOT NULL, project_path TEXT NOT NULL, PRIMARY KEY(provider, session_id)); INSERT INTO sessions VALUES ('codex', 'session.receipts', '', '');").await.unwrap();
    crate::schema::ensure_lcm_schema(&conn).await.unwrap();
    (temp, conn)
}

#[asupersync::test]
async fn active_compression_preserves_reference_backed_receipts_after_replay_annotation() {
    let (temp, conn) = fixture().await;
    let request: LcmCompressionRequest = serde_json::from_value(json!({
        "provider": "codex", "session_id": "session.receipts",
        "messages": [{"id": "active.receipt", "role": "user", "content": "safe active fixture"}],
        "summarizer": {"mode": "noop"}
    }))
    .unwrap();
    let mut rollback = payload::PayloadFileRollback::begin_cancellation_safe(temp.path());
    let result = begin_compression_pass(
        &*conn,
        &ObservationScopeV1::Profile,
        temp.path(),
        &request,
        &mut rollback,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(result, CompressionAdmission::Finished(_)));
    let mut rows = conn
        .query(
            "SELECT metadata_json FROM lcm_raw_messages WHERE message_id = 'active.receipt'",
            (),
        )
        .await
        .unwrap();
    let stored: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    let metadata: Value = serde_json::from_str(&stored).unwrap();
    for field in ["sanitization_receipt", "metadata_sanitization_receipt"] {
        assert!(
            metadata["ingest_protection"][field]["lcm_receipt_v1"].is_string(),
            "replay annotation must not re-embed {field}"
        );
    }
    assert!(
        metadata
            .get(replay_transactions::ACTIVE_REPLAY_MESSAGE_KEY)
            .is_some()
    );
    drop(rows);
    assert!(
        raw::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "active.receipt")
            .await
            .unwrap()
            .is_some()
    );
}

#[asupersync::test]
async fn retained_compression_reads_nonempty_reference_backed_page_and_byte_count() {
    let (_temp, conn) = fixture().await;
    let message: SessionMessageRecord = SessionMessageRecord {
        provider: "codex".into(),
        message_id: "retained.receipt".into(),
        session_id: "session.receipts".into(),
        role: "user".into(),
        timestamp: None,
        ordinal: 1,
        text: "safe retained fixture".into(),
        kind: Some("message".into()),
        model: None,
        tool_names: None,
        source_path: None,
        source_offset: None,
        metadata_json: None,
    };
    raw::upsert_projection_raw_message(&*conn, &message, None)
        .await
        .unwrap();
    let page = load_raw_messages_for_session_page(
        &*conn,
        "codex",
        "session.receipts",
        0,
        RetainedCompressionGuard {
            row_limit: 10,
            byte_limit: 1024 * 1024,
            expected_summary_source_range: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.rows_scanned, 1);
    assert!(page.bytes_scanned > 0);
    assert_eq!(page.messages[0].content, "safe retained fixture");
    assert!(!page.has_more);
}
