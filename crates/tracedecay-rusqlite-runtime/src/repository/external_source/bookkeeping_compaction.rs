use super::*;

#[test]
fn legacy_mutation_compaction_is_lossless_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let mut connection = rusqlite::Connection::open(temp.path().join("legacy.db")).unwrap();
    connection.execute_batch(EXTERNAL_SOURCE_SCHEMA_V1).unwrap();
    let (commit, binding) = fixture();
    let mut transaction = connection.transaction().unwrap();
    let savepoint = transaction.savepoint().unwrap();
    ExternalSourceExecutor
        .execute_write(&savepoint, &commit)
        .unwrap();
    savepoint.commit().unwrap();
    transaction.commit().unwrap();
    let mutation = &commit.mutations()[0];
    let legacy = serde_json::to_string(mutation).unwrap();
    connection
        .execute(
            "UPDATE external_source_mutations_v1 SET mutation_json = ?1",
            [&legacy],
        )
        .unwrap();
    let changes = connection.total_changes();
    let plan = ExternalSourceExecutor
        .plan_mutation_compaction(&connection, None, 1, 1024 * 1024)
        .unwrap();
    assert_eq!(
        connection.total_changes(),
        changes,
        "dry run must not change history or schema"
    );
    assert_eq!(plan.scanned_rows(), 1);
    assert_eq!(plan.changed_rows(), 1);
    assert!(plan.logical_bytes_saved() > 0);
    let mut transaction = connection.transaction().unwrap();
    let savepoint = transaction.savepoint().unwrap();
    assert!(
        ExternalSourceExecutor
            .apply_mutation_compaction(&savepoint, &plan, "wrong-plan")
            .is_err()
    );
    ExternalSourceExecutor
        .apply_mutation_compaction(&savepoint, &plan, plan.digest())
        .unwrap();
    savepoint.commit().unwrap();
    transaction.commit().unwrap();
    let stored: String = connection
        .query_row(
            "SELECT mutation_json FROM external_source_mutations_v1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(stored.len() < legacy.len());
    let hydrated = super::super::slim::hydrate_mutation(
        &stored,
        &binding,
        super::super::slim::MutationRowKeys {
            native_object: mutation.observation().native_object().digest().as_str(),
            revision: mutation.observation().revision().digest().as_str(),
            mutation_digest: mutation.mutation_digest().as_str(),
        },
    )
    .unwrap();
    assert_eq!(&hydrated, mutation);
    let repeated = ExternalSourceExecutor
        .plan_mutation_compaction(&connection, None, 1, 1024 * 1024)
        .unwrap();
    assert_eq!(
        repeated.changed_rows(),
        0,
        "an already compact history must not rewrite"
    );
    assert!(
        ExternalSourceExecutor
            .plan_mutation_compaction(&connection, None, 1, 1)
            .is_err(),
        "an oversized row must not silently exceed its byte budget"
    );
    connection
        .execute(
            "UPDATE external_source_mutations_v1 SET mutation_json = ?1",
            [&legacy],
        )
        .unwrap();
    let plan = ExternalSourceExecutor
        .plan_mutation_compaction(&connection, None, 1, 1024 * 1024)
        .unwrap();
    connection.execute("UPDATE external_source_mutations_v1 SET mutation_json = json_set(mutation_json, '$.evidence.binding.owner', json('{\"kind\":\"profile\",\"profile_id\":\"other\"}'))", []).unwrap();
    let mut transaction = connection.transaction().unwrap();
    let savepoint = transaction.savepoint().unwrap();
    assert!(
        ExternalSourceExecutor
            .apply_mutation_compaction(&savepoint, &plan, plan.digest())
            .is_err(),
        "stale or conflicting histories must not be overwritten"
    );
}
