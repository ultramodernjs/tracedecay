use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1, SessionId};
use tracedecay_runtime_core::db::engine::params;

use crate::tests::harness::RegisteredGlobalDbHarness;

#[asupersync::test]
async fn source_key_migration_is_read_only_stale_safe_and_bounded() {
    let harness = RegisteredGlobalDbHarness::open("source-key-migration").await;
    let database = &harness.registered;
    let source =
        ObservationSourceIdentityV1::new(SessionId::new("session.legacy-keys").unwrap()).unwrap();
    let scope = ObservationScopeV1::Profile;
    let legacy = serde_json::to_string(&(&source, &scope)).unwrap();
    let writer = database.writer_connection().unwrap();
    for index in 0..3 {
        writer
            .execute(
                "INSERT INTO observation_source_presence VALUES (?1, ?2, '1', ?3)",
                params![legacy.as_str(), format!("sha256:{index:064x}"), index],
            )
            .await
            .unwrap();
    }
    writer
        .execute(
            "INSERT INTO observation_source_rewrites VALUES (?1, '2', 0)",
            params![legacy.as_str()],
        )
        .await
        .unwrap();
    let mut rows = writer.query("PRAGMA schema_version", ()).await.unwrap();
    let schema: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    drop(rows);
    let plan = database
        .plan_source_key_compaction(&source, &scope, 2, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.rows(), 2);
    assert!(plan.has_more());
    let mut rows = writer
        .query("SELECT COUNT(*) FROM observation_source_descriptors", ())
        .await
        .unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        0,
        "dry-run must not install descriptors"
    );
    drop(rows);
    let mut rows = writer.query("PRAGMA schema_version", ()).await.unwrap();
    assert_eq!(
        rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
        schema
    );
    drop(rows);
    assert!(
        database
            .apply_source_key_compaction(&plan, "wrong-digest")
            .await
            .is_err()
    );
    assert_eq!(
        database
            .apply_source_key_compaction(&plan, plan.digest())
            .await
            .unwrap(),
        2
    );
    assert!(
        database
            .apply_source_key_compaction(&plan, plan.digest())
            .await
            .is_err(),
        "a stale page must not be applied twice"
    );
    let plan = database
        .plan_source_key_compaction(&source, &scope, 2, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.rows(), 1);
    assert!(!plan.has_more());
    assert_eq!(
        database
            .apply_source_key_compaction(&plan, plan.digest())
            .await
            .unwrap(),
        1
    );
    let plan = database
        .plan_source_key_compaction(&source, &scope, 2, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(plan.rows(), 0);
    assert_eq!(
        database
            .apply_source_key_compaction(&plan, plan.digest())
            .await
            .unwrap(),
        0
    );
    let mut rows = writer
        .query("SELECT source_key FROM observation_source_rewrites", ())
        .await
        .unwrap();
    assert_eq!(
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap()
            .len(),
        71,
        "pending rewrites must move with their presence"
    );
    drop(rows);
    writer
        .execute(
            "UPDATE observation_source_descriptors SET descriptor_json = '[]'",
            (),
        )
        .await
        .unwrap();
    let plan = database
        .plan_source_key_compaction(&source, &scope, 2, 1024 * 1024)
        .await
        .unwrap();
    assert!(
        database
            .apply_source_key_compaction(&plan, plan.digest())
            .await
            .is_err(),
        "descriptor digest collisions must be refused"
    );
}
