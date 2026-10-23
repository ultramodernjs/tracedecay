use tracedecay_runtime_core::db::engine::{TestConnection, params};
use tracedecay_store::SessionMessageRecord;

fn message(id: &str, text: &str) -> SessionMessageRecord {
    SessionMessageRecord {
        provider: "codex".into(),
        message_id: id.into(),
        session_id: "session.receipts".into(),
        role: "user".into(),
        timestamp: Some(1),
        ordinal: 1,
        text: text.into(),
        kind: Some("message".into()),
        model: None,
        tool_names: None,
        source_path: None,
        source_offset: None,
        metadata_json: Some(r#"{"fixture":"safe"}"#.into()),
    }
}

#[asupersync::test]
async fn receipt_refs_round_trip_body_and_metadata_authorities() {
    let temp = tempfile::tempdir().unwrap();
    let conn = TestConnection::open(&temp.path().join("sessions.db"));
    conn.execute_batch(
        "CREATE TABLE sessions (
        provider TEXT NOT NULL, session_id TEXT NOT NULL, project_key TEXT NOT NULL,
        project_path TEXT NOT NULL, PRIMARY KEY(provider, session_id)
    ); INSERT INTO sessions VALUES ('codex', 'session.receipts', '', '');",
    )
    .await
    .unwrap();
    crate::schema::ensure_lcm_schema(&conn).await.unwrap();
    let message = message("message.first", "safe receipt fixture");
    let expected = super::projection_stored_message(&message).unwrap();
    super::upsert_projection_raw_message(&*conn, &message, None)
        .await
        .unwrap();
    let second = message_with_id(&message, "message.second");
    super::upsert_projection_raw_message(&*conn, &second, None)
        .await
        .unwrap();
    let mut rows = conn
        .query(
            "SELECT metadata_json FROM lcm_raw_messages ORDER BY store_id",
            (),
        )
        .await
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(
        &rows
            .next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
    )
    .unwrap();
    assert!(
        metadata["ingest_protection"]["sanitization_receipt"]
            .get("lcm_receipt_v1")
            .is_some(),
        "raw metadata must reference, not embed, a receipt"
    );
    assert!(
        metadata["ingest_protection"]["sanitization_receipt"]
            .get("payload")
            .is_none()
    );
    drop(rows);
    let loaded =
        super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "message.first")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(loaded.metadata_json.as_deref().unwrap())
            .unwrap(),
        serde_json::from_str::<serde_json::Value>(expected.metadata_json.as_deref().unwrap())
            .unwrap()
    );
    let columns = super::stored_message_record_select_columns("r");
    let mut rows = conn
        .query(
            &format!("SELECT {columns} FROM lcm_raw_messages r ORDER BY store_id"),
            (),
        )
        .await
        .unwrap();
    let stored: String = rows.next().await.unwrap().unwrap().get(12).unwrap();
    assert_eq!(
        stored,
        expected.metadata_json.as_deref().unwrap(),
        "projection digests bind exact metadata bytes, including object key order"
    );

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stored).unwrap(),
        serde_json::from_str::<serde_json::Value>(expected.metadata_json.as_deref().unwrap())
            .unwrap()
    );
    drop(rows);
    let mut rows = conn
        .query("SELECT COUNT(*) FROM lcm_sanitization_receipts_v1", ())
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        2,
        "identical messages share both authorities"
    );
    drop(rows);
    assert!(
        conn.execute(
            "DELETE FROM lcm_sanitization_receipts_v1 WHERE receipt_key = ?1",
            params![
                metadata["ingest_protection"]["sanitization_receipt"]["lcm_receipt_v1"]
                    .as_str()
                    .unwrap()
            ]
        )
        .await
        .is_err(),
        "ordinary deletion cannot remove a live receipt"
    );
    conn.execute_batch("DROP TRIGGER lcm_sanitization_receipts_referenced_delete_v1")
        .await
        .unwrap();
    conn.execute(
        "DELETE FROM lcm_sanitization_receipts_v1 WHERE receipt_key = ?1",
        params![
            metadata["ingest_protection"]["sanitization_receipt"]["lcm_receipt_v1"]
                .as_str()
                .unwrap()
        ],
    )
    .await
    .unwrap();
    assert!(
        super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "message.first")
            .await
            .is_err(),
        "a missing dictionary receipt fails closed"
    );
}

fn message_with_id(message: &SessionMessageRecord, id: &str) -> SessionMessageRecord {
    let mut message = message.clone();
    message.message_id = id.into();
    message
}

#[asupersync::test]
async fn receipt_compaction_dry_run_resume_and_shared_gc() {
    let temp = tempfile::tempdir().unwrap();
    let conn = TestConnection::open(&temp.path().join("legacy.db"));
    conn.execute_batch("CREATE TABLE sessions (provider TEXT NOT NULL, session_id TEXT NOT NULL, project_key TEXT NOT NULL, project_path TEXT NOT NULL, PRIMARY KEY(provider, session_id)); INSERT INTO sessions VALUES ('codex', 'session.receipts', '', '');").await.unwrap();
    crate::schema::ensure_lcm_schema(&conn).await.unwrap();
    let original = message("legacy.first", "safe legacy receipt fixture");
    let expected = super::projection_stored_message(&original).unwrap();
    for id in ["legacy.first", "legacy.second", "legacy.third"] {
        super::upsert_projection_raw_message(&*conn, &message_with_id(&original, id), None)
            .await
            .unwrap();
    }
    conn.execute(
        "UPDATE lcm_raw_messages SET metadata_json = ?1",
        params![expected.metadata_json.as_deref()],
    )
    .await
    .unwrap();
    let mut rows = conn.query("PRAGMA schema_version", ()).await.unwrap();
    let schema: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    drop(rows);
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, 0, 2, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.scanned_rows(), 2);
    assert_eq!(plan.changed_rows(), 2);
    assert!(plan.has_more());
    let mut rows = conn.query("PRAGMA schema_version", ()).await.unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        schema
    );
    drop(rows);
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    assert!(
        super::receipt_store::apply_receipt_compaction(&transaction, &plan, "wrong-plan")
            .await
            .is_err()
    );
    assert_eq!(
        super::receipt_store::apply_receipt_compaction(&transaction, &plan, plan.digest())
            .await
            .unwrap(),
        2
    );
    transaction.commit().await.unwrap();
    let after = plan.next_cursor().unwrap();
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, after, 2, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.changed_rows(), 1);
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    super::receipt_store::apply_receipt_compaction(&transaction, &plan, plan.digest())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let loaded =
        super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "legacy.first")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(loaded.metadata_json.as_deref().unwrap())
            .unwrap(),
        serde_json::from_str::<serde_json::Value>(expected.metadata_json.as_deref().unwrap())
            .unwrap()
    );
    let repeated = super::receipt_store::plan_receipt_compaction(&*conn, 0, 10, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(repeated.changed_rows(), 0);
    let plan = super::receipt_store::plan_receipt_gc(&*conn, 10)
        .await
        .unwrap();
    assert_eq!(plan.rows(), 0, "shared receipt authorities stay pinned");
    conn.execute(
        "DELETE FROM lcm_raw_messages WHERE message_id <> 'legacy.third'",
        (),
    )
    .await
    .unwrap();
    assert_eq!(
        super::receipt_store::plan_receipt_gc(&*conn, 10)
            .await
            .unwrap()
            .rows(),
        0
    );
    conn.execute("DELETE FROM lcm_raw_messages", ())
        .await
        .unwrap();
    let plan = super::receipt_store::plan_receipt_gc(&*conn, 1)
        .await
        .unwrap();
    assert_eq!(plan.rows(), 1, "orphan GC must be page bounded");
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    assert_eq!(
        super::receipt_store::apply_receipt_gc(&transaction, &plan, plan.digest())
            .await
            .unwrap(),
        1
    );
    transaction.commit().await.unwrap();
    assert_eq!(
        super::receipt_store::plan_receipt_gc(&*conn, 10)
            .await
            .unwrap()
            .rows(),
        1
    );
}

async fn receipt_fixture() -> (tempfile::TempDir, TestConnection) {
    let temp = tempfile::tempdir().unwrap();
    let conn = TestConnection::open(&temp.path().join("receipts.db"));
    conn.execute_batch("CREATE TABLE sessions (provider TEXT NOT NULL, session_id TEXT NOT NULL, project_key TEXT NOT NULL, project_path TEXT NOT NULL, PRIMARY KEY(provider, session_id)); INSERT INTO sessions VALUES ('codex', 'session.receipts', '', '');").await.unwrap();
    crate::schema::ensure_lcm_schema(&conn).await.unwrap();
    super::upsert_projection_raw_message(
        &*conn,
        &message("message.first", "safe receipt fixture"),
        None,
    )
    .await
    .unwrap();
    (temp, conn)
}

#[asupersync::test]
async fn raw_selectors_preserve_retained_and_native_summary_column_positions() {
    let (_temp, conn) = receipt_fixture().await;
    let mut rows = conn
        .query(
            &format!(
                "SELECT {}, 1234 FROM lcm_raw_messages",
                super::RAW_MESSAGE_SELECT_COLUMNS
            ),
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(
        row.get::<i64>(16).unwrap(),
        1234,
        "retained compression appends its byte count at column 16"
    );
    assert_eq!(
        super::verified_raw_message_from_row(&row).unwrap().content,
        "safe receipt fixture"
    );
    drop(rows);
    let mut rows = conn.query(&format!(
        "SELECT message.*, 7, 9, '{{}}' FROM (SELECT {}, kind, placeholder_text FROM lcm_raw_messages) message",
        super::RAW_MESSAGE_SELECT_COLUMNS
    ), ()).await.unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(
        row.get::<Option<String>>(16).unwrap().as_deref(),
        Some("message")
    );
    assert_eq!(row.get::<i64>(18).unwrap(), 7);
    assert_eq!(row.get::<i64>(19).unwrap(), 9);
    assert_eq!(row.get::<String>(20).unwrap(), "{}");
    assert!(super::verified_raw_message_from_row(&row).is_ok());
    drop(rows);
    let mut rows = conn
        .query(
            &format!(
                "SELECT {}, 4321 FROM lcm_raw_messages",
                super::RAW_MESSAGE_METADATA_SELECT_COLUMNS
            ),
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(row.get::<i64>(16).unwrap(), 4321);
    assert!(super::raw_message_metadata_from_row(&row).is_ok());
}

#[asupersync::test]
async fn stored_record_body_decoder_rejects_missing_and_mismatched_receipts() {
    for missing in [false, true] {
        let (_temp, conn) = receipt_fixture().await;
        conn.execute_batch("DROP TRIGGER lcm_sanitization_receipts_referenced_delete_v1; DROP TRIGGER lcm_sanitization_receipts_immutable_update_v1;").await.unwrap();
        if missing {
            conn.execute("DELETE FROM lcm_sanitization_receipts_v1", ())
                .await
                .unwrap();
        } else {
            conn.execute("UPDATE lcm_sanitization_receipts_v1 SET material_json = json_set(material_json, '$[0]', 'receipt.tampered')", ()).await.unwrap();
        }
        let columns = super::stored_message_record_select_columns("r");
        let mut rows = conn
            .query(
                &format!("SELECT {columns}, 'appended-payload' FROM lcm_raw_messages r"),
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<String>(19).unwrap(), "appended-payload");
        assert!(
            super::message_body_from_record_row(&row, 0).is_err(),
            "every stored-record reader must fail closed before serving a body"
        );
    }
}

#[asupersync::test]
async fn receipt_compaction_preserves_published_lineage_and_convergence() {
    let (_temp, conn) = receipt_fixture().await;
    let legacy =
        super::projection_stored_message(&message("message.first", "safe receipt fixture"))
            .unwrap();
    conn.execute(
        "UPDATE lcm_raw_messages SET metadata_json = ?1",
        params![legacy.metadata_json],
    )
    .await
    .unwrap();
    crate::test_support::seed_active_generation(&conn, "session.receipts").await;
    conn.execute_batch("INSERT INTO session_summary_nodes(summary_id, provider, conversation_id, session_id, depth, summary_text, summary_hash, summary_token_count, source_token_count, created_at) VALUES ('summary.receipts', 'codex', 'session.receipts', 'session.receipts', 0, 'safe summary', 'hash', 1, 1, 1);
    INSERT INTO session_summary_sources(summary_id, source_kind, source_id, ordinal) SELECT 'summary.receipts', 'raw_message', CAST(store_id AS TEXT), 0 FROM lcm_raw_messages;
    INSERT INTO session_summary_availability(session_id, generation, summary_id, availability) VALUES ('session.receipts', 1, 'summary.receipts', 'available');
    DELETE FROM lcm_summary_convergence_invalidation_work;
    DELETE FROM lcm_summary_convergence_dirty_raw;
    UPDATE lcm_summary_convergence_queue SET state = 'current', attempted_raw_store_id = newest_raw_store_id, protection_frontier_store_id = newest_raw_store_id, stale_from_store_id = NULL;").await.unwrap();
    let before = convergence_state(&conn).await;
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, 0, 10, 1024 * 1024)
        .await
        .unwrap();
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    assert_eq!(
        super::receipt_store::apply_receipt_compaction(&transaction, &plan, plan.digest())
            .await
            .unwrap(),
        1
    );
    transaction.commit().await.unwrap();
    assert_eq!(
        convergence_state(&conn).await,
        before,
        "encoding maintenance cannot invalidate semantic inputs"
    );
    let mut rows = conn.query("SELECT availability FROM session_summary_availability WHERE summary_id = 'summary.receipts'", ()).await.unwrap();
    assert_eq!(
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        "available"
    );
    drop(rows);
    // The convergence guard must be restored, not permanently disabled.
    conn.execute("UPDATE lcm_raw_messages SET ordinal = ordinal + 1", ())
        .await
        .unwrap();
    assert_ne!(convergence_state(&conn).await, before);
}

async fn convergence_state(conn: &TestConnection) -> (String, i64, i64) {
    let mut rows = conn.query("SELECT json_array(provider, session_id, newest_raw_store_id, protection_frontier_store_id, attempted_raw_store_id, state, failure_code, failure_count, next_attempt_at_ms, raw_revision_generation, stale_from_store_id), (SELECT count(*) FROM lcm_summary_convergence_dirty_raw), (SELECT count(*) FROM lcm_summary_convergence_invalidation_work) FROM lcm_summary_convergence_queue", ()).await.unwrap();
    let row = rows.next().await.unwrap().unwrap();
    (
        row.get(0).unwrap(),
        row.get(1).unwrap(),
        row.get(2).unwrap(),
    )
}

#[asupersync::test]
async fn receipt_compaction_bounds_materialized_payload_bytes() {
    let (_temp, conn) = receipt_fixture().await;
    let legacy =
        super::projection_stored_message(&message("message.first", "safe receipt fixture"))
            .unwrap();
    let mut metadata: serde_json::Value =
        serde_json::from_str(legacy.metadata_json.as_deref().unwrap()).unwrap();
    metadata["fixture_padding"] = serde_json::Value::String("x".repeat(700 * 1024));
    let metadata = metadata.to_string();
    for index in 0..100 {
        conn.execute("INSERT INTO lcm_raw_messages(provider, message_id, session_id, role, ordinal, content, content_hash, storage_kind, metadata_json) VALUES ('codex', ?1, 'session.receipts', 'user', ?2, 'safe receipt fixture', 'fixture-hash', 'inline', ?3)", params![format!("large.{index}"), index, metadata.as_str()]).await.unwrap();
    }
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, 0, 1000, 4 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        plan.scanned_rows(),
        6,
        "one compact row plus five large rows fit before the payload query is materialized"
    );
    assert!(plan.has_more());
}

#[asupersync::test]
async fn metadata_only_remediation_uses_stored_bytes_for_cas_and_compact_replacement() {
    let (_temp, conn) = receipt_fixture().await;
    let secret = ["sk-at-rest-rescan-secret-", "1234567890abcdef"].concat();
    conn.execute(
        "UPDATE lcm_raw_messages SET metadata_json = json_set(metadata_json, '$.api_key', ?1)",
        params![secret.as_str()],
    )
    .await
    .unwrap();
    let columns = super::stored_message_record_select_columns("r");
    let mut rows = conn
        .query(
            &format!("SELECT r.store_id, {columns} FROM lcm_raw_messages r"),
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    let store_id: i64 = row.get(0).unwrap();
    let stored = super::stored_metadata_bytes_from_record_row(&row, 1)
        .unwrap()
        .unwrap();
    let hydrated: String = row.get(13).unwrap();
    assert_ne!(
        stored, hydrated,
        "the privacy reader must retain both authorities"
    );
    assert_eq!(
        super::message_body_from_record_row(&row, 1).unwrap(),
        "safe receipt fixture"
    );
    drop(rows);
    let sanitized = super::resanitize_stored_provider_metadata_json(&hydrated).unwrap();
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    assert!(
        super::compare_and_swap_raw_metadata(
            &transaction,
            store_id,
            "codex",
            "message.first",
            Some(&hydrated),
            Some(&sanitized)
        )
        .await
        .is_err(),
        "hydrated bytes cannot be used as the CAS authority"
    );
    super::compare_and_swap_raw_metadata(
        &transaction,
        store_id,
        "codex",
        "message.first",
        Some(&stored),
        Some(&sanitized),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let mut rows = conn
        .query("SELECT metadata_json FROM lcm_raw_messages", ())
        .await
        .unwrap();
    let persisted: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    let persisted: serde_json::Value = serde_json::from_str(&persisted).unwrap();
    assert!(persisted["ingest_protection"]["sanitization_receipt"]["lcm_receipt_v1"].is_string());
    assert!(
        persisted["ingest_protection"]["metadata_sanitization_receipt"]["lcm_receipt_v1"]
            .is_string()
    );
    drop(rows);
    let loaded =
        super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "message.first")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(loaded.content, "safe receipt fixture");
    assert!(!loaded.metadata_json.unwrap().contains(&secret));
}

#[asupersync::test]
async fn released_v15_receipt_upgrade_installs_owners_and_survives_reopen() {
    use tracedecay_runtime_core::db::engine::TransactionBehavior;
    use tracedecay_runtime_core::db::schema_version;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("released-v15.db");
    let original = message("legacy.first", "safe upgrade fixture");
    let expected = super::projection_stored_message(&original).unwrap();
    let conn = TestConnection::open(&path);
    conn.execute_batch(include_str!("fixtures/pre_receipt_lcm_v15.sql"))
        .await
        .unwrap();
    conn.execute(
        "INSERT INTO sessions VALUES ('codex', 'session.receipts', '', '')",
        (),
    )
    .await
    .unwrap();
    conn.execute("INSERT INTO lcm_raw_messages(provider, message_id, session_id, role, ordinal, timestamp, content, content_hash, storage_kind, metadata_json) VALUES ('codex', 'legacy.first', 'session.receipts', 'user', 1, 1, ?1, ?2, 'inline', ?3)", params![expected.text.as_str(), crate::retrieval_content::projected_content_hash(&expected.text), expected.metadata_json.as_deref()]).await.unwrap();
    let mut rows = conn
        .query(
            "SELECT count(*) FROM sqlite_schema WHERE name LIKE 'lcm%receipt%'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0,
        "fixture must really lack the new dictionary and triggers"
    );
    drop(rows);
    assert_eq!(
        schema_version::read_version(&*conn, "lcm-sanitization-receipts-v1")
            .await
            .unwrap(),
        None
    );
    drop(conn);

    let conn = TestConnection::open(&path);
    assert!(matches!(
        crate::schema::require_admissible_lcm_schema(&*conn)
            .await
            .unwrap(),
        crate::schema::LcmSchemaAdmission::Current
    ));
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .unwrap();
    crate::schema::ensure_lcm_schema_in_transaction(&transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let loaded =
        super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", "legacy.first")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(loaded.content, expected.text);
    assert_eq!(
        schema_version::read_version(&*conn, "lcm-sanitization-receipts-v1")
            .await
            .unwrap(),
        Some(1)
    );
    super::upsert_projection_raw_message(
        &*conn,
        &message_with_id(&original, "compact.second"),
        None,
    )
    .await
    .unwrap();
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, 0, 10, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.changed_rows(), 1);
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .unwrap();
    super::receipt_store::apply_receipt_compaction(&transaction, &plan, plan.digest())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(conn);

    let conn = TestConnection::open(&path);
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await
        .unwrap();
    crate::schema::ensure_lcm_schema_in_transaction(&transaction)
        .await
        .unwrap();
    crate::schema::ensure_lcm_schema_in_transaction(&transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let mut rows = conn
        .query(
            "SELECT count(*), min(owner_count), max(owner_count) FROM lcm_sanitization_receipts_v1",
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(
        (
            row.get::<i64>(0).unwrap(),
            row.get::<i64>(1).unwrap(),
            row.get::<i64>(2).unwrap()
        ),
        (2, 2, 2),
        "reinstallation must not double-count owners"
    );
    drop(rows);
    for id in ["legacy.first", "compact.second"] {
        let loaded = super::load_raw_message_by_identity(&*conn, "codex", "session.receipts", id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(loaded.metadata_json.as_deref().unwrap())
                .unwrap(),
            serde_json::from_str::<serde_json::Value>(expected.metadata_json.as_deref().unwrap())
                .unwrap()
        );
    }
    assert_eq!(
        super::receipt_store::plan_receipt_compaction(&*conn, 0, 10, 1024 * 1024)
            .await
            .unwrap()
            .changed_rows(),
        0
    );
    let mut rows = conn.query("PRAGMA foreign_key_check", ()).await.unwrap();
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn receipt_compaction_failure_rolls_back_material_and_restores_update_guards() {
    let (_temp, conn) = receipt_fixture().await;
    let legacy =
        super::projection_stored_message(&message("message.first", "safe receipt fixture"))
            .unwrap();
    conn.execute(
        "UPDATE lcm_raw_messages SET metadata_json = ?1",
        params![legacy.metadata_json.as_deref()],
    )
    .await
    .unwrap();
    conn.execute(
        "DELETE FROM lcm_sanitization_receipts_v1 WHERE owner_count = 0",
        (),
    )
    .await
    .unwrap();
    conn.execute_batch("CREATE TRIGGER fixture_fail_receipt_page BEFORE UPDATE OF metadata_json ON lcm_raw_messages BEGIN SELECT RAISE(ABORT, 'injected receipt page failure'); END;").await.unwrap();
    let before = convergence_state(&conn).await;
    let plan = super::receipt_store::plan_receipt_compaction(&*conn, 0, 10, 1024 * 1024)
        .await
        .unwrap();
    let transaction = conn
        .transaction_with_behavior(
            tracedecay_runtime_core::db::engine::TransactionBehavior::Immediate,
        )
        .await
        .unwrap();
    assert!(
        super::receipt_store::apply_receipt_compaction(&transaction, &plan, plan.digest())
            .await
            .is_err()
    );
    // Deliberately commit despite the error to exercise the inner rollback,
    // rather than allowing outer transaction Drop to hide partial changes.
    transaction.commit().await.unwrap();
    assert_eq!(convergence_state(&conn).await, before);
    let mut rows = conn.query("SELECT metadata_json, (SELECT count(*) FROM lcm_sanitization_receipts_v1), (SELECT count(*) FROM sqlite_schema WHERE type = 'trigger' AND name IN ('lcm_summary_convergence_raw_unprotected_update', 'lcm_raw_messages_fts_update', 'lcm_raw_messages_gc_candidate_update')) FROM lcm_raw_messages", ()).await.unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(row.get::<String>(0).unwrap(), legacy.metadata_json.unwrap());
    assert_eq!(row.get::<i64>(1).unwrap(), 0);
    assert_eq!(row.get::<i64>(2).unwrap(), 3);
    drop(rows);
    conn.execute_batch("DROP TRIGGER fixture_fail_receipt_page")
        .await
        .unwrap();
    conn.execute("UPDATE lcm_raw_messages SET ordinal = ordinal + 1", ())
        .await
        .unwrap();
    assert_ne!(convergence_state(&conn).await, before);
}
