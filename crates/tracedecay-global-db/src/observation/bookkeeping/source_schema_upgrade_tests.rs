use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1, SessionId};
use tracedecay_runtime_core::db::{
    engine::{TestConnection, TransactionBehavior, params},
    schema_version,
};

use super::source_keys::SourceKey;

#[asupersync::test]
async fn released_source_schema_installs_descriptors_and_preserves_pending_rewrite_on_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("released-source.db");
    let source =
        ObservationSourceIdentityV1::new(SessionId::new("session.released-source").unwrap())
            .unwrap();
    let scope = ObservationScopeV1::Profile;
    let key = SourceKey::new(&source, &scope).unwrap();
    let conn = TestConnection::open(&path);
    tracedecay_runtime_core::db::retrieval_anchor_schema::install_retrieval_anchor_schema(
        &*conn,
        "seed released observation fixture",
    )
    .await
    .unwrap();
    conn.execute_batch(include_str!("fixtures/pre_source_descriptor_v1.sql"))
        .await
        .unwrap();
    conn.execute(
        "INSERT INTO observation_source_presence VALUES (?1, 'sha256:legacy', '1', 5)",
        params![key.legacy.as_str()],
    )
    .await
    .unwrap();
    conn.execute(
        "INSERT INTO observation_source_rewrites VALUES (?1, '2', 5)",
        params![key.legacy.as_str()],
    )
    .await
    .unwrap();
    let mut rows = conn
        .query(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'observation_source_descriptors'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0
    );
    drop(rows);
    assert_eq!(
        schema_version::read_version(&*conn, "observation-source-descriptors-v1")
            .await
            .unwrap(),
        None
    );
    drop(conn);

    for _ in 0..2 {
        let conn = TestConnection::open(&path);
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .unwrap();
        assert!(
            super::super::schema::ensure_observation_schema(&transaction)
                .await
                .unwrap()
                .is_none()
        );
        // New writes use the production collision-checked descriptor authority;
        // startup must not scan or rewrite old keys or pending generations.
        key.ensure_descriptor(&transaction).await.unwrap();
        transaction.execute("INSERT INTO observation_source_presence VALUES (?1, 'sha256:new', '2', 10) ON CONFLICT DO NOTHING", params![key.compact.as_str()]).await.unwrap();
        transaction.commit().await.unwrap();
        assert_eq!(
            schema_version::read_version(&*conn, "observation-source-descriptors-v1")
                .await
                .unwrap(),
            Some(1)
        );
        let mut rows = conn.query("SELECT generation, retained_through FROM observation_source_rewrites WHERE source_key = ?1", params![key.legacy.as_str()]).await.unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(
            (row.get::<String>(0).unwrap(), row.get::<i64>(1).unwrap()),
            ("2".into(), 5)
        );
        drop(rows);
        let mut rows = conn
            .query(
                "SELECT count(*), max(length(source_key)) FROM observation_source_descriptors",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(
            (row.get::<i64>(0).unwrap(), row.get::<i64>(1).unwrap()),
            (1, 71)
        );
        drop(rows);
        let mut rows = conn
            .query("SELECT count(*) FROM observation_source_presence", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            2
        );
        drop(rows);
        let mut rows = conn.query("PRAGMA foreign_key_check", ()).await.unwrap();
        assert!(rows.next().await.unwrap().is_none());
    }
}
