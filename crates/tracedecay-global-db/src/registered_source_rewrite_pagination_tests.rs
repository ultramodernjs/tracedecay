use tracedecay_runtime_core::db::engine::{QueryExecutor, TestConnection, params};

use super::{UNOFFERED_RECORD_PAGE_SIZE, unoffered_source_record_page};
use crate::observation::bookkeeping::source_keys::SourceKey;
use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1, SessionId};

#[asupersync::test]
async fn rewrite_pages_merge_bounded_legacy_and_compact_index_streams() {
    let temp = tempfile::tempdir().unwrap();
    let conn = TestConnection::open(&temp.path().join("presence.db"));
    conn.execute_batch(
        "CREATE TABLE observation_source_presence (
        source_key TEXT NOT NULL, observation_id TEXT NOT NULL,
        generation TEXT NOT NULL, start_offset INTEGER NOT NULL,
        PRIMARY KEY(source_key, observation_id)
    ) WITHOUT ROWID;",
    )
    .await
    .unwrap();
    let source =
        ObservationSourceIdentityV1::new(SessionId::new("session.pagination").unwrap()).unwrap();
    let key = SourceKey::new(&source, &ObservationScopeV1::Profile).unwrap();
    // Two encodings overlap at even IDs; duplicates at page boundaries must
    // neither starve later IDs nor cause a whole-source DISTINCT sorter.
    conn.execute(
        "WITH RECURSIVE ids(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM ids WHERE n < 19999)
         INSERT INTO observation_source_presence
         SELECT ?1, printf('sha256:%064x', n), '1', 0 FROM ids",
        params![key.legacy.as_str()],
    )
    .await
    .unwrap();
    conn.execute(
        "INSERT INTO observation_source_presence
         SELECT ?1, observation_id, generation, start_offset
         FROM observation_source_presence WHERE source_key = ?2 AND substr(observation_id, -1, 1) IN ('0', '2', '4', '6', '8', 'a', 'c', 'e')",
        params![key.compact.as_str(), key.legacy.as_str()],
    ).await.unwrap();
    let mut after = String::new();
    let mut all = Vec::new();
    loop {
        let page = unoffered_source_record_page(&*conn, &key, "2", &after)
            .await
            .unwrap();
        assert!(page.len() <= UNOFFERED_RECORD_PAGE_SIZE as usize);
        let Some(last) = page.last() else {
            break;
        };
        after = last.clone();
        all.extend(page);
    }
    assert_eq!(
        all,
        (0..20_000)
            .map(|index| format!("sha256:{index:064x}"))
            .collect::<Vec<_>>()
    );
    let mut rows = conn
        .query(
            &format!(
                "EXPLAIN QUERY PLAN {}",
                super::UNOFFERED_SOURCE_RECORD_PAGE_SQL
            ),
            params![key.legacy.as_str(), "2", "", UNOFFERED_RECORD_PAGE_SIZE],
        )
        .await
        .unwrap();
    let mut count = 0;
    while let Some(row) = rows.next().await.unwrap() {
        let detail: String = row.get(3).unwrap();
        assert!(
            !detail.contains("TEMP B-TREE"),
            "bounded per-key page must stream its primary key: {detail}"
        );
        count += 1;
    }
    assert_ne!(count, 0);
}
