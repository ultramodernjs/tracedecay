use super::*;

use tracedecay_runtime_core::db::TestRuntimeProfileIdentityV1;
use tracedecay_runtime_core::db::engine::{QueryExecutor, Row};

use crate::RegisteredGlobalDbOwnerV1;
use crate::tests::harness::{
    HostAdmissionScope, HostAdmissionTestRuntimeV1, seed_projected_messages,
};

#[asupersync::test]
async fn fresh_temporal_schema_stores_and_searches_a_summary_node() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");

    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);
    assert!(
        table_exists(&db_path, "lcm_raw_messages").await,
        "fresh initialization must compose the final temporal and LCM schemas"
    );

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    conn.execute_batch(
        "INSERT INTO retrieval_anchors (
            anchor_id, anchor_json, owner_json, projection_generation
         ) VALUES ('fresh-anchor', '{}', '{}', 'test');
         INSERT INTO session_summary_nodes (
            summary_id, session_id, provider, conversation_id, depth, summary_anchor_id,
            summary_text, summary_hash, summary_token_count, source_token_count,
            source_horizon_json, created_at
         ) VALUES (
            'fresh-summary', 'fresh-session', 'test', 'fresh-session', 0, 'fresh-anchor',
            'fresh summary text quokka migration notes', 'hash', 1, 1, '{}', 100
         );",
    )
    .await
    .unwrap();
    let mut rows = conn
        .query(
            "SELECT n.summary_id, n.session_id, n.summary_text, n.created_at
             FROM session_summary_nodes_fts
             JOIN session_summary_nodes AS n ON n.rowid = session_summary_nodes_fts.rowid
             WHERE session_summary_nodes_fts MATCH 'quokka'",
            (),
        )
        .await
        .unwrap();
    let row = rows.next().await.unwrap().expect("FTS finds the summary");
    assert_eq!(
        (
            row.get::<String>(0).unwrap(),
            row.get::<String>(1).unwrap(),
            row.get::<String>(2).unwrap(),
            row.get::<i64>(3).unwrap(),
        ),
        (
            "fresh-summary".to_string(),
            "fresh-session".to_string(),
            "fresh summary text quokka migration notes".to_string(),
            100,
        )
    );
    assert!(rows.next().await.unwrap().is_none());
}

#[asupersync::test]
async fn temporal_payload_manifest_schema_is_payload_global() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    let mut rows = conn
        .query(
            "SELECT name FROM pragma_table_info('session_external_payload_manifests')
             ORDER BY cid",
            (),
        )
        .await
        .unwrap();
    let mut columns = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        columns.push(row.get::<String>(0).unwrap());
    }
    assert_eq!(
        columns,
        [
            "payload_ref",
            "session_id",
            "payload_digest",
            "manifest_json",
            "receipt_id",
            "created_at",
        ]
    );

    let mut rows = conn
        .query(
            "SELECT \"from\", \"table\", \"to\"
             FROM pragma_foreign_key_list('session_external_payload_manifests')
             ORDER BY \"from\"",
            (),
        )
        .await
        .unwrap();
    let mut foreign_keys = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        foreign_keys.push((
            row.get::<String>(0).unwrap(),
            row.get::<String>(1).unwrap(),
            row.get::<String>(2).unwrap(),
        ));
    }
    assert_eq!(
        foreign_keys,
        [(
            "receipt_id".to_string(),
            "sanitization_receipts".to_string(),
            "receipt_id".to_string(),
        )]
    );

    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         INSERT INTO sessions(provider, session_id, project_key, project_path)
         VALUES ('cursor', 'manifest-owner', '/tmp/project', '/tmp/project');
         INSERT INTO sanitization_receipts (
             receipt_id, sanitizer_version, payload_digest, receipt_json
         ) VALUES ('manifest-receipt', 'test', 'digest', '{}');
         INSERT INTO lcm_external_payloads (
             payload_ref, provider, session_id, message_id, kind, content_hash,
             byte_count, char_count, created_at
         ) VALUES
             ('payload-owned', 'cursor', 'manifest-owner', 'message-owned',
              'tool', 'digest', 1, 1, 100),
             ('payload-cross-session', 'cursor', 'manifest-owner', 'message-cross',
              'tool', 'digest', 1, 1, 100);
         INSERT INTO session_external_payload_manifests (
             payload_ref, session_id, payload_digest, manifest_json, receipt_id, created_at
         ) VALUES (
             'payload-owned', 'manifest-owner', 'digest', '{}', 'manifest-receipt', 100
         );",
    )
    .await
    .unwrap();
    assert!(
        conn.execute(
            "INSERT INTO session_external_payload_manifests (
                 payload_ref, session_id, payload_digest, manifest_json, receipt_id, created_at
             ) VALUES (
                 'payload-cross-session', 'different-owner', 'digest', '{}',
                 'manifest-receipt', 100
             )",
            (),
        )
        .await
        .is_err(),
        "a payload manifest owner must match raw payload authority"
    );
    for sql in [
        "UPDATE session_external_payload_manifests SET payload_digest = 'rewrite'
         WHERE payload_ref = 'payload-owned'",
        "DELETE FROM session_external_payload_manifests WHERE payload_ref = 'payload-owned'",
    ] {
        assert!(
            conn.execute(sql, ()).await.is_err(),
            "payload-global authority must remain immutable: {sql}"
        );
    }
}

mod admission;

#[asupersync::test]
async fn temporal_schema_query_indexes_cover_exact_lookup_shapes() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    for (sql, index) in [
        (
            "SELECT occurrence_id
             FROM session_occurrences
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND retrieval_anchor_id = 'anchor-one'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, occurrence_id",
            "idx_session_occurrences_anchor_order",
        ),
        (
            "SELECT occurrence_id
             FROM session_occurrences
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND message_id = 'message-one'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, occurrence_id",
            "idx_session_occurrences_message",
        ),
        (
            "SELECT occurrence.occurrence_id
             FROM session_occurrences AS occurrence
                  INDEXED BY idx_session_occurrences_message
             WHERE occurrence.session_id = 'session-one'
               AND occurrence.message_id = 'message-one'
               AND +occurrence.generation <= 1
             ORDER BY occurrence.source_sequence,
                      occurrence.projection_output_ordinal,
                      occurrence.occurrence_id
             LIMIT 1",
            "idx_session_occurrences_message",
        ),
        (
            "SELECT occurrence_id
             FROM session_occurrences
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND thread_id = 'thread-one'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, occurrence_id",
            "idx_session_occurrences_thread",
        ),
        (
            "SELECT occurrence_id
             FROM session_occurrences
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND turn_id = 'turn-one'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, occurrence_id",
            "idx_session_occurrences_turn",
        ),
        (
            "SELECT occurrence_id
             FROM session_occurrences
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND agent_id = 'agent-one'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, occurrence_id",
            "idx_session_occurrences_agent",
        ),
        (
            "SELECT entity_id
             FROM session_current_entities
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND current_occurrence_id = 'occurrence-one'",
            "idx_session_current_entities_occurrence",
        ),
        (
            "SELECT assertion_id
             FROM session_assertions
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND object_anchor_id = 'anchor-object'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, assertion_id",
            "idx_session_assertions_object_order",
        ),
        (
            "SELECT assertion_id
             FROM session_assertions
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND assertion_kind = 'corrects'
               AND knowledge_at >= 0
             ORDER BY knowledge_at, assertion_id",
            "idx_session_assertions_kind_order",
        ),
        (
            "SELECT assertion_id
             FROM session_assertions
             WHERE session_id = 'session-one'
               AND +generation <= 1
               AND knowledge_at >= 0
             ORDER BY knowledge_at, assertion_id",
            "idx_session_assertions_generation_order",
        ),
        (
            "SELECT payload_ref
             FROM session_external_payload_manifests
             WHERE session_id = 'session-one'",
            "idx_session_external_payload_manifests_session",
        ),
    ] {
        let details = explain_query_plan(&conn, sql).await;
        assert!(
            details.iter().any(|detail| detail.contains(index)),
            "EXPLAIN did not use {index} for `{sql}`: {details:?}"
        );
    }
}

#[asupersync::test]
async fn temporal_schema_root_retrieval_indexes_cover_catalog_and_large_query_shapes() {
    const OCCURRENCE_ROOT_INDEX: &str = "idx_session_occurrences_root_generation_order";
    const SUMMARY_ROOT_INDEX: &str = "idx_session_summary_nodes_root_created_order";

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    for (table, index, expected_columns, root_prefix) in [
        (
            "session_occurrences",
            OCCURRENCE_ROOT_INDEX,
            &[
                ("knowledge_at", 1),
                ("session_id", 0),
                ("occurrence_id", 0),
                ("generation", 0),
            ][..],
            "idx_session_occurrences_root_",
        ),
        (
            "session_summary_nodes",
            SUMMARY_ROOT_INDEX,
            &[("created_at", 0), ("session_id", 0), ("summary_id", 0)][..],
            "idx_session_summary_nodes_root_",
        ),
    ] {
        let expected = expected_columns
            .iter()
            .map(|(column, descending)| ((*column).to_owned(), *descending))
            .collect::<Vec<_>>();
        assert_eq!(
            index_key_columns(&conn, index).await,
            expected,
            "{index} must retain its exact key-order contract"
        );

        let index_names = table_index_names(&conn, table).await;
        let mut matching_keysets = Vec::new();
        for candidate in &index_names {
            if index_key_columns(&conn, candidate).await == expected {
                matching_keysets.push(candidate.clone());
            }
        }
        assert_eq!(
            matching_keysets,
            [index.to_owned()],
            "{table} must not retain a redundant index with the root keyset"
        );

        let root_indexes = index_names
            .into_iter()
            .filter(|candidate| candidate.starts_with(root_prefix))
            .collect::<Vec<_>>();
        assert_eq!(
            root_indexes,
            [index.to_owned()],
            "{table} must not retain a conflicting root index variant"
        );
    }

    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         INSERT INTO sanitization_receipts (
            receipt_id, sanitizer_version, payload_digest, receipt_json
         ) VALUES ('root-receipt', 'test', 'root-digest', '{}');
         INSERT INTO observations (
            observation_id, payload_digest, receipt_id, observation_json, committed_cursor_json
         ) VALUES (
            'root-observation',
            'root-digest',
            'root-receipt',
            '{\"identity\":{\"source\":{\"provider\":\"claude\"}}}',
            '{}'
         );
         INSERT INTO retrieval_anchors (
            anchor_id, anchor_json, owner_json, projection_generation
         ) VALUES ('root-anchor', '{}', '{}', 'test');
         WITH RECURSIVE sequence(value) AS (
            VALUES(0)
            UNION ALL
            SELECT value + 1 FROM sequence WHERE value < 7
         )
         INSERT INTO session_temporal_generations (
            session_id, generation, state, frozen_watermarks_json, created_at
         )
         SELECT printf('root-session-%02d', value), 1, 'building', '{}', 0
         FROM sequence;
         UPDATE session_temporal_generations
         SET state = 'ready', ready_at = 1;
         UPDATE session_temporal_generations
         SET state = 'active', activated_at = 2;",
    )
    .await
    .unwrap();

    // Planner-scale seeding is bulk-write work: it legitimately outlives the
    // ordinary per-statement deadline. Chunking alone still raced that
    // deadline, so under CPU contention the guard interrupted the fixture
    // itself (SQLITE_INTERRUPT) before a single asserted query ever ran.
    // Seed through the authorized long-lease path the production bulk writers
    // use, which drops the ordinary statement deadline and renews the lease on
    // each committed chunk. Row count and value distribution are unchanged.
    const FIXTURE_ROWS: usize = 100_000;
    const FIXTURE_CHUNK: usize = 20_000;
    let seed = conn.authorized_long_lease_transaction().await.unwrap();
    for start in (0..FIXTURE_ROWS).step_by(FIXTURE_CHUNK) {
        let end = start + FIXTURE_CHUNK - 1;
        seed.execute_authority_revalidated_batch(&format!(
            "WITH RECURSIVE sequence(value) AS (
                VALUES({start})
                UNION ALL
                SELECT value + 1 FROM sequence WHERE value < {end}
             )
             INSERT INTO session_occurrences (
                session_id, generation, occurrence_id, source_observation_id,
                source_sequence, source_provider, projection_output_ordinal,
                retrieval_anchor_id, copied_from_anchor_ids_json, role, knowledge_at,
                valid_time_json, evidence_json, sanitized_content_digest,
                sanitized_content_bytes, index_text
             )
             SELECT
                printf('root-session-%02d', value % 8),
                1,
                printf('root-occurrence-%06d', value),
                'root-observation',
                1,
                'test',
                value,
                'root-anchor',
                '[]',
                'assistant',
                value / 8,
                json_object('kind', 'unknown'),
                '{{}}',
                '0000000000000000000000000000000000000000000000000000000000000000',
                15,
                'root occurrence'
             FROM sequence;"
        ))
        .await
        .unwrap();
    }
    for start in (0..FIXTURE_ROWS).step_by(FIXTURE_CHUNK) {
        let end = start + FIXTURE_CHUNK - 1;
        seed.execute_authority_revalidated_batch(&format!(
            "WITH RECURSIVE sequence(value) AS (
                VALUES({start})
                UNION ALL
                SELECT value + 1 FROM sequence WHERE value < {end}
             )
             INSERT INTO session_summary_nodes (
                summary_id, session_id, provider, conversation_id, depth, summary_anchor_id,
                summary_text, summary_hash, summary_token_count, source_token_count,
                source_horizon_json, created_at
             )
             SELECT
                printf('root-summary-%06d', value),
                printf('root-session-%02d', value % 8),
                'test',
                printf('root-session-%02d', value % 8),
                0,
                'root-anchor',
                'root summary',
                'hash',
                1,
                1,
                '{{}}',
                value / 8
             FROM sequence;"
        ))
        .await
        .unwrap();
    }
    seed.execute_authority_revalidated_batch("ANALYZE;")
        .await
        .unwrap();
    seed.commit().await.unwrap();

    for table in ["session_occurrences", "session_summary_nodes"] {
        let mut rows = conn
            .query(&format!("SELECT COUNT(*) FROM {table}"), ())
            .await
            .unwrap();
        let count: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
        assert_eq!(count, 100_000, "{table} fixture must stay planner-scale");
    }

    for (shape, sql, index) in [
        (
            "root occurrence candidate",
            "SELECT o.occurrence_id
             FROM session_temporal_generations AS frozen
             JOIN session_occurrences AS o
               INDEXED BY idx_session_occurrences_root_generation_order
               ON o.session_id = frozen.session_id
              AND o.generation = frozen.generation
             WHERE frozen.state = 'active'
               AND (NULL IS NULL OR o.source_provider = NULL)
               AND o.knowledge_at >= 0
               AND o.knowledge_at < 12500
               AND (
                   o.knowledge_at < 9223372036854775807
                   OR (
                       o.knowledge_at = 9223372036854775807
                       AND (
                           o.session_id > ''
                           OR (o.session_id = '' AND o.occurrence_id > '')
                       )
                   )
               )
             ORDER BY o.knowledge_at DESC, o.session_id, o.occurrence_id
             LIMIT 38",
            OCCURRENCE_ROOT_INDEX,
        ),
        (
            "root occurrence pagination",
            "SELECT o.occurrence_id
             FROM session_temporal_generations AS frozen
             JOIN session_occurrences AS o
               INDEXED BY idx_session_occurrences_root_generation_order
               ON o.session_id = frozen.session_id
              AND o.generation = frozen.generation
             WHERE frozen.state = 'active'
               AND (NULL IS NULL OR o.source_provider = NULL)
               AND o.knowledge_at >= 0
               AND o.knowledge_at < 12500
               AND (
                   o.knowledge_at < 7111
                   OR (
                       o.knowledge_at = 7111
                       AND (
                           o.session_id > 'root-session-03'
                           OR (
                               o.session_id = 'root-session-03'
                               AND o.occurrence_id > 'root-occurrence-057000'
                           )
                       )
                   )
               )
             ORDER BY o.knowledge_at DESC, o.session_id, o.occurrence_id
             LIMIT 38",
            OCCURRENCE_ROOT_INDEX,
        ),
        (
            "root occurrence provider filter",
            "SELECT o.occurrence_id
             FROM session_temporal_generations AS frozen
             JOIN session_occurrences AS o
               INDEXED BY idx_session_occurrences_root_generation_order
               ON o.session_id = frozen.session_id
              AND o.generation = frozen.generation
             WHERE frozen.state = 'active'
               AND ('claude' IS NULL OR o.source_provider = 'claude')
               AND o.knowledge_at >= 0
               AND o.knowledge_at < 12500
               AND (
                   o.knowledge_at < 7111
                   OR (
                       o.knowledge_at = 7111
                       AND (
                           o.session_id > 'root-session-03'
                           OR (
                               o.session_id = 'root-session-03'
                               AND o.occurrence_id > 'root-occurrence-057000'
                           )
                       )
                   )
               )
             ORDER BY o.knowledge_at DESC, o.session_id, o.occurrence_id
             LIMIT 38",
            OCCURRENCE_ROOT_INDEX,
        ),
        (
            "root summary candidate",
            "SELECT summary_id
             FROM session_summary_nodes
             WHERE created_at >= 0
               AND created_at < 12500
               AND (
                   created_at < 7111
                   OR (
                       created_at = 7111
                       AND (
                           session_id > 'root-session-03'
                           OR (
                               session_id = 'root-session-03'
                               AND summary_id > 'root-summary-057000'
                           )
                       )
                   )
               )
             ORDER BY created_at DESC, session_id, summary_id
             LIMIT 38",
            SUMMARY_ROOT_INDEX,
        ),
    ] {
        let details = explain_query_plan(&conn, sql).await;
        assert!(
            details.iter().any(|detail| detail.contains(index)),
            "EXPLAIN did not use {index} for {shape}: {details:?}"
        );
    }
}

async fn retained_root_index_rows(conn: &impl QueryExecutor) -> Vec<(&'static str, Vec<Row>)> {
    let mut retained = Vec::new();
    for (table, order) in [
        ("observations", "observation_id"),
        ("retrieval_anchors", "anchor_id"),
        ("session_temporal_generations", "session_id, generation"),
        (
            "session_occurrences",
            "session_id, generation, occurrence_id",
        ),
        ("source_cursors", "source_json, scope_json"),
        ("session_temporal_resets", "session_id"),
        ("session_query_cursor_keys", "key_version"),
        ("session_relation_effect_journal", "session_id, generation"),
        (
            tracedecay_runtime_core::db::schema_version::TABLE,
            "component",
        ),
    ] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY {order}"), ())
            .await
            .unwrap();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            values.push(row);
        }
        retained.push((table, values));
    }
    retained
}

#[asupersync::test]
async fn temporal_schema_root_occurrence_index_rebuild_preserves_registered_state() {
    let directory = TempDir::new().unwrap();
    let runtime = HostAdmissionTestRuntimeV1::profile(directory.path())
        .await
        .unwrap();
    let seeded = seed_projected_messages(&runtime, 0..3).await;
    runtime
        .session_temporal_store_for_test(HostAdmissionScope::Profile)
        .unwrap()
        .materialize_pending_session_refresh_for_test(
            &tracedecay_domain::SessionId::new("session.audit-batch").unwrap(),
        )
        .await
        .unwrap();
    let database = runtime
        .registered_database(HostAdmissionScope::Profile)
        .unwrap();
    let path = database.db_path().to_path_buf();
    let binding = database.binding().clone();
    let locator = database.verified_locator().clone();
    let conn = database.writer_connection().unwrap();
    tracedecay_session_temporal_store::request_session_temporal_reset(
        &conn,
        seeded[0].0.observation_id().as_str(),
    )
    .await
    .unwrap();
    let retained = retained_root_index_rows(&conn).await;
    for table in [
        "observations",
        "retrieval_anchors",
        "session_temporal_generations",
        "session_occurrences",
        "source_cursors",
        "session_temporal_resets",
        tracedecay_runtime_core::db::schema_version::TABLE,
    ] {
        assert!(
            retained
                .iter()
                .any(|(name, rows)| *name == table && !rows.is_empty()),
            "the registered fixture must retain real {table} rows"
        );
    }
    drop(runtime);

    let old = TestConnection::open(&path);
    old.execute_batch(
        "DROP INDEX idx_session_occurrences_root_generation_order;
         CREATE INDEX idx_session_occurrences_root_generation_order
             ON session_occurrences(knowledge_at, session_id, occurrence_id, generation);",
    )
    .await
    .unwrap();
    let old_columns =
        index_key_columns(&old, "idx_session_occurrences_root_generation_order").await;
    assert!(old_columns.iter().all(|(_, descending)| *descending == 0));
    drop(old);

    let authority =
        DatabaseAuthority::acquire_test(&path, "inspect root occurrence index").unwrap();
    let fixture =
        Database::publish_registered_test_runtime_with_retirement_control_for_profile_identity(
            &path,
            &authority,
            TestDatabaseRuntimeMode::Existing,
            TestRuntimeProfileIdentityV1::new(
                binding.shard_id.brain_id.clone(),
                binding.shard_id.profile_id.clone(),
            ),
            TestDatabaseRuntimeScope::ProfileSessions,
        )
        .await
        .unwrap();
    let (owner, inspection_runtime, inspection_retirement) = fixture.into_parts();
    assert!(
        RegisteredGlobalDbOwnerV1::attach_reset_refusal(&owner)
            .await
            .unwrap()
            .is_none()
    );
    let inspected = TestConnection::open(&path);
    assert_eq!(
        index_key_columns(&inspected, "idx_session_occurrences_root_generation_order").await,
        old_columns,
        "rollback-only attach inspection must retain the ascending index"
    );
    assert_eq!(retained_root_index_rows(&inspected).await, retained);
    drop(inspected);
    drop(owner);
    drop(inspection_runtime);
    drop(inspection_retirement);
    drop(authority);

    let mut prior_epoch = binding.authority_epoch;
    for _ in 0..2 {
        let reopened = HostAdmissionTestRuntimeV1::profile(directory.path())
            .await
            .unwrap();
        let database = reopened
            .registered_database(HostAdmissionScope::Profile)
            .unwrap();
        assert_eq!(database.binding().shard_id, binding.shard_id);
        assert_eq!(database.binding().incarnation, binding.incarnation);
        assert_eq!(database.verified_locator(), &locator);
        assert!(database.binding().authority_epoch > prior_epoch);
        prior_epoch = database.binding().authority_epoch;
        assert_eq!(
            retained_root_index_rows(&database.read_connection()).await,
            retained
        );
        let conn = TestConnection::open(&path);
        assert_eq!(
            index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await,
            old_columns
                .iter()
                .map(|(name, _)| (name.clone(), i64::from(name == "knowledge_at")))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            table_index_names(&conn, "session_occurrences")
                .await
                .into_iter()
                .filter(|name| name.starts_with("idx_session_occurrences_root_"))
                .collect::<Vec<_>>(),
            ["idx_session_occurrences_root_generation_order".to_owned()]
        );
        drop(conn);
        drop(reopened);
    }
}

#[asupersync::test]
async fn temporal_schema_root_occurrence_index_rebuild_refuses_other_schema_drift() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("sessions.db");
    drop(open_global_db(&path).await.unwrap());
    let conn = TestConnection::open(&path);
    conn.execute_batch(
        "DROP INDEX idx_session_occurrences_root_generation_order;
         CREATE INDEX idx_session_occurrences_root_generation_order
             ON session_occurrences(knowledge_at, session_id, occurrence_id, generation);
         DROP INDEX idx_session_occurrences_session_time;",
    )
    .await
    .unwrap();
    let columns = index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await;
    drop(conn);
    let catalog = temporal_schema_object_catalog(&path).await;
    let error = match open_global_db(&path).await {
        Ok(_) => panic!("an ascending root index must not admit unrelated schema damage"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("session temporal")
    );
    assert_eq!(temporal_schema_object_catalog(&path).await, catalog);
    let conn = TestConnection::open(&path);
    assert_eq!(
        index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await,
        columns
    );
}

#[asupersync::test]
async fn temporal_schema_root_occurrence_index_rebuild_rolls_back_on_authority_drift() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("sessions.db");
    drop(open_global_db(&path).await.unwrap());
    let conn = TestConnection::open(&path);
    conn.execute_batch(
        "DROP INDEX idx_session_occurrences_root_generation_order;
         CREATE INDEX idx_session_occurrences_root_generation_order
             ON session_occurrences(knowledge_at, session_id, occurrence_id, generation);
         CREATE INDEX idx_retrieval_anchors_unexpected ON retrieval_anchors(owner_json);",
    )
    .await
    .unwrap();
    let columns = index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await;
    let anchor_indexes = table_index_names(&conn, "retrieval_anchors").await;
    drop(conn);
    let catalog = temporal_schema_object_catalog(&path).await;
    let error = match open_global_db(&path).await {
        Ok(_) => panic!("the root index rebuild must roll back on unrelated authority drift"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("authority schema")
    );
    assert_eq!(temporal_schema_object_catalog(&path).await, catalog);
    let conn = TestConnection::open(&path);
    assert_eq!(
        index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await,
        columns
    );
    assert_eq!(
        table_index_names(&conn, "retrieval_anchors").await,
        anchor_indexes
    );
}

#[asupersync::test]
async fn temporal_schema_root_occurrence_index_rebuild_rejects_unreleased_key_orders() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("sessions.db");
    drop(open_global_db(&path).await.unwrap());
    let conn = TestConnection::open(&path);
    conn.execute_batch(
        "DROP INDEX idx_session_occurrences_root_generation_order;
         CREATE INDEX idx_session_occurrences_root_generation_order
             ON session_occurrences(knowledge_at, session_id, occurrence_id DESC, generation);",
    )
    .await
    .unwrap();
    let columns = index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await;
    drop(conn);
    let catalog = temporal_schema_object_catalog(&path).await;
    let error = match open_global_db(&path).await {
        Ok(_) => panic!("an unreleased root index order must require reset"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("session temporal")
    );
    assert_eq!(temporal_schema_object_catalog(&path).await, catalog);
    let conn = TestConnection::open(&path);
    assert_eq!(
        index_key_columns(&conn, "idx_session_occurrences_root_generation_order").await,
        columns
    );
}

#[asupersync::test]
async fn temporal_schema_rejects_unexpected_indexes_without_dropping_them() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_session_refresh_progress_operation
             ON session_refresh_progress(session_id, operation_id, progress_ordinal);
         CREATE INDEX IF NOT EXISTS idx_session_temporal_projection_receipts_digest
             ON session_temporal_projection_receipts(session_id, generation, batch_digest);",
    )
    .await
    .unwrap();
    drop(conn);
    drop(raw_db);

    let error = match open_global_db(&db_path).await {
        Ok(_) => panic!("unexpected temporal indexes must require reset"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("session temporal")
    );

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    for index in [
        "idx_session_refresh_progress_operation",
        "idx_session_temporal_projection_receipts_digest",
    ] {
        let mut rows = conn
            .query(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1",
                params![index],
            )
            .await
            .unwrap();
        assert!(
            rows.next().await.unwrap().is_some(),
            "rejected temporal schema must not drop {index}"
        );
    }
}

#[asupersync::test]
async fn temporal_schema_refuses_markerless_malformed_fts_without_mutation() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    conn.execute_batch(
        "CREATE TABLE session_occurrences_fts (
            index_text TEXT NOT NULL,
            snippet_text TEXT NOT NULL
        );
         INSERT INTO session_occurrences_fts (index_text, snippet_text)
         VALUES ('retained malformed FTS', 'retained malformed FTS');",
    )
    .await
    .unwrap();
    drop(conn);
    drop(raw_db);
    let before_catalog = temporal_schema_object_catalog(&db_path).await;

    let error = match open_global_db(&db_path).await {
        Ok(_) => panic!("a markerless malformed FTS store must require reset"),
        Err(error) => error,
    };
    let (authority, reason) = error
        .reset_required_context()
        .expect("a markerless malformed FTS store must return typed reset-required");
    assert_eq!(authority, "session temporal");
    assert!(
        reason.contains("nonempty store"),
        "unexpected reason: {reason}"
    );
    assert!(
        !table_exists(&db_path, "tracedecay_schema_version").await,
        "typed refusal must not install the temporal marker"
    );
    assert!(
        !table_exists(&db_path, "session_summary_nodes").await,
        "typed refusal must not install temporal authority tables"
    );
    assert!(
        table_exists(&db_path, "session_occurrences_fts").await,
        "typed refusal must preserve the malformed FTS table"
    );
    assert_eq!(
        row_count(&db_path, "session_occurrences_fts").await,
        1,
        "typed refusal must preserve malformed FTS rows"
    );
    assert_eq!(
        temporal_schema_object_catalog(&db_path).await,
        before_catalog,
        "typed refusal must not rewrite malformed FTS storage"
    );
}

#[asupersync::test]
async fn temporal_schema_rejects_missing_fts_without_rebuilding_it() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    conn.execute_batch(
        "DROP TRIGGER session_summary_nodes_fts_insert_v1;
         DROP TRIGGER session_summary_nodes_fts_delete_v1;
         DROP TRIGGER session_summary_nodes_fts_update_v1;
         DROP TABLE session_summary_nodes_fts;
         INSERT INTO retrieval_anchors (
            anchor_id, anchor_json, owner_json, projection_generation
         ) VALUES ('fts-anchor', '{}', '{}', 'test');
         INSERT INTO session_summary_nodes (
            summary_id, session_id, provider, conversation_id, depth, summary_anchor_id,
            summary_text, summary_hash, summary_token_count, source_token_count,
            source_horizon_json, created_at
         ) VALUES (
            'fts-summary', 'fts-session', 'test', 'fts-session', 0, 'fts-anchor',
            'existing summary', 'hash', 1, 1, '{}', 100
         );",
    )
    .await
    .unwrap();
    drop(conn);
    drop(raw_db);

    let error = match open_global_db(&db_path).await {
        Ok(_) => panic!("missing temporal FTS objects must require reset"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("session temporal")
    );

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    let mut rows = conn
        .query(
            "SELECT 1 FROM sqlite_master
             WHERE type = 'table' AND name = 'session_summary_nodes_fts'",
            (),
        )
        .await
        .unwrap();
    assert!(
        rows.next().await.unwrap().is_none(),
        "rejected current schema must not recreate missing FTS storage"
    );
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM session_summary_nodes
             WHERE summary_id = 'fts-summary'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        1
    );
}

#[asupersync::test]
async fn temporal_schema_rejects_missing_graph_publication_authority_without_rebuilding_it() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join(".tracedecay").join("sessions.db");
    let db = open_global_db(&db_path)
        .await
        .expect("temporal schema initialization should not error");
    drop(db);

    let raw_db = TestConnection::open(&db_path);
    let conn = (*raw_db).clone();
    conn.execute("DROP TABLE graph_verified_heads_v1", ())
        .await
        .unwrap();
    drop(conn);
    drop(raw_db);

    let error = match open_global_db(&db_path).await {
        Ok(_) => panic!("missing graph publication authority must require reset"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .reset_required_context()
            .map(|(authority, _)| authority),
        Some("session temporal")
    );
    assert!(
        !table_exists(&db_path, "graph_verified_heads_v1").await,
        "rejected current schema must not recreate missing graph publication storage"
    );
}
