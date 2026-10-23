use tracedecay_domain::{
    CanonicalObservationIdV1, ObservationScopeV1, ObservationSourceGenerationV1,
    ObservationSourceIdentityV1, SessionId,
};
use tracedecay_runtime_core::db::engine::params;

use crate::{ObservationSourcePresenceV1, tests::harness::RegisteredGlobalDbHarness};

#[asupersync::test]
async fn source_presence_keys_are_compact_and_rewrite_equivalent() {
    let harness = RegisteredGlobalDbHarness::open("compact-source-presence").await;
    let database = &harness.registered;
    let source = ObservationSourceIdentityV1::new(
        SessionId::new(format!("session.{}", "long-source-".repeat(15))).unwrap(),
    )
    .unwrap();
    let scope = ObservationScopeV1::Profile;
    let old = ObservationSourceGenerationV1::new(1).unwrap();
    let new = ObservationSourceGenerationV1::new(2).unwrap();
    let writer = database.writer_connection().unwrap();
    let legacy = serde_json::to_string(&(&source, &scope)).unwrap();
    writer
        .execute(
            "INSERT INTO observation_source_presence VALUES (?1, 'sha256:legacy-refused', '1', 0)",
            params![legacy.as_str()],
        )
        .await
        .unwrap();
    writer
        .execute(
            "INSERT INTO observation_source_rewrites VALUES (?1, '2', 0)",
            params![legacy.as_str()],
        )
        .await
        .unwrap();
    let records = (0..10)
        .map(|index| ObservationSourcePresenceV1 {
            observation_id: CanonicalObservationIdV1::new(format!("sha256:{index:064x}")).unwrap(),
            generation: old,
            start_offset: index,
        })
        .collect::<Vec<_>>();
    database
        .record_observation_source_presence(&source, &scope, &records)
        .await
        .unwrap();
    let mut rows = writer.query(
        "SELECT MAX(length(source_key)), COUNT(DISTINCT source_key) FROM observation_source_presence WHERE source_key <> ?1",
        params![legacy.as_str()],
    ).await.unwrap();
    let row = rows.next().await.unwrap().unwrap();
    assert_eq!(
        row.get::<i64>(0).unwrap(),
        71,
        "source keys must be fixed-size digests"
    );
    assert_eq!(row.get::<i64>(1).unwrap(), 1);
    drop(rows);
    let mut rows = writer
        .query(
            "SELECT descriptor_json FROM observation_source_descriptors",
            (),
        )
        .await
        .unwrap();
    assert_eq!(
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        legacy
    );
    assert!(rows.next().await.unwrap().is_none());
    drop(rows);
    database
        .begin_observation_source_rewrite(&source, &scope, old, new, 0)
        .await
        .unwrap();
    database
        .record_observation_source_presence(
            &source,
            &scope,
            &[ObservationSourcePresenceV1 {
                observation_id: records[0].observation_id.clone(),
                generation: new,
                start_offset: 0,
            }],
        )
        .await
        .unwrap();
    assert_eq!(
        database
            .complete_observation_source_rewrite(&source, &scope, new)
            .await
            .unwrap(),
        0
    );
    let mut rows = writer
        .query("SELECT observation_id FROM observation_source_presence", ())
        .await
        .unwrap();
    assert_eq!(
        rows.next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap(),
        records[0].observation_id.as_str()
    );
    assert!(
        rows.next().await.unwrap().is_none(),
        "legacy and compact unoffered records must both retire"
    );
}
