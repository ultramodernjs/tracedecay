use super::*;

fn request_batch(
    connection: &Connection,
    sql: &str,
    pinned_transaction: bool,
) -> Result<SqlResult, ExactSqlError> {
    execute_request(
        connection,
        SqlRequest::ExecuteBatch(sql.to_owned()),
        pinned_transaction,
        None,
        None,
        true,
        None,
    )
}

#[test]
fn interrupted_batch_records_attempted_work_and_private_template_events() {
    const CHILD: &str = "TRACEDECAY_BATCH_COST_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Other runtime tests install a process-wide subscriber. Keep this
        // capture and tracing's callsite cache independent of those tests.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exact_sql::statement_cost_tests::batch_cost_tests::interrupted_batch_records_attempted_work_and_private_template_events",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "batch-cost capture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let connection = fixture();
    connection
        .execute_batch("CREATE TABLE batch_output(value INTEGER, payload TEXT)")
        .unwrap();
    let events = CostEvents(Arc::default(), std::thread::current().id());
    tracing::subscriber::set_global_default(events.clone()).unwrap();
    let clock = clock::fake::FakeClock::ticking(EXACT_SQL_EXECUTION_LIMIT / 4);
    clock.install();

    let error = request_batch(
        &connection,
        concat!(
            "INSERT INTO batch_output VALUES(-1, 'private-prefix');",
            "INSERT INTO batch_output SELECT value, 'private-payload' FROM items ORDER BY value DESC;",
            "CREATE TABLE batch_must_not_run(value INTEGER);"
        ),
        false,
    )
    .unwrap_err();
    assert!(matches!(error, ExactSqlError::Sqlite { code: Some(9), .. }));
    let cost = crate::telemetry::take_observed_vm();
    assert!(
        cost.vm_steps >= 1000,
        "interrupted batch lost its VM cost: {cost:?}"
    );
    assert!(
        cost.fullscan_steps > 0,
        "interrupted batch lost its scan cost: {cost:?}"
    );
    // An interrupted sorter need not increment Sort, even after building
    // substantial input. VM and scan counters still attribute that attempt.
    let captured = events.0.lock().unwrap();
    assert_eq!(captured.len(), 2, "{captured:?}");
    assert_eq!(
        captured[0]["sql_template_id"],
        "cf15fde86d547ffb7d24d560ba3d0edd582409151440248c9f4a4d8ef539d776"
    );
    assert_eq!(captured[0]["failed"], "false");
    assert_eq!(
        captured[1]["sql_template_id"],
        "64ef7b8ec7c0306f225406f59e1925cf51b8e9e1c9c750bed5cc771aeb8c1624"
    );
    assert_eq!(captured[1]["failed"], "true");
    assert_eq!(captured[1]["sqlite_code"], "Some(9)");
    assert!(captured[1]["vm_steps"].parse::<u64>().unwrap() >= 1000);
    assert!(captured[1]["fullscan_steps"].parse::<u64>().unwrap() > 0);
    let total = |field: &str| {
        captured
            .iter()
            .map(|event| event[field].parse::<u64>().unwrap())
            .sum::<u64>()
    };
    assert_eq!(cost.vm_steps, total("vm_steps"));
    assert_eq!(cost.fullscan_steps, total("fullscan_steps"));
    assert_eq!(cost.sort_steps, total("sort_steps"));
    let debug = format!("{captured:?}");
    for sensitive in ["private-", "INSERT", "SELECT", "batch_output", "items"] {
        assert!(!debug.contains(sensitive), "{debug}");
    }
    // Keep execute_batch's stop-on-first-error and non-atomic behavior:
    // the first statement committed, the interrupted insert rolled back,
    // and nothing after it was prepared or executed.
    assert!(connection.is_autocommit());
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM batch_output", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);
    let tail_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'batch_must_not_run'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tail_tables, 0);
}

#[test]
fn batch_telemetry_preserves_sqlite_parsing_changes_and_pinned_transaction() {
    let expected = fixture();
    let actual = fixture();
    let sql = "CREATE TABLE receipts(value INTEGER);
        CREATE TABLE receipt_log(payload TEXT);
        CREATE TRIGGER track_receipt AFTER INSERT ON receipts BEGIN
            INSERT INTO receipt_log VALUES('a;--not SQL');
            INSERT INTO receipt_log VALUES('b; /*still literal*/');
        END;
        INSERT INTO receipts VALUES(1), (2) RETURNING value;
        PRAGMA table_info(receipts);
        SELECT ?1;
        SELECT value FROM receipts ORDER BY value DESC;
        INSERT INTO receipts VALUES(3);
        -- trailing comment with a semicolon; and UTF-8: café";
    expected.execute_batch("BEGIN IMMEDIATE").unwrap();
    actual.execute_batch("BEGIN IMMEDIATE").unwrap();
    let before = expected.total_changes();
    expected.execute_batch(sql).unwrap();
    let expected_changes = expected.total_changes() - before;
    let SqlResult::BatchExecuted(result) = request_batch(&actual, sql, true).unwrap() else {
        panic!("batch did not return a batch result");
    };
    assert_eq!(expected_changes, 9);
    assert_eq!(result.changed_rows, expected_changes);
    let cost = crate::telemetry::take_observed_vm();
    assert!(cost.vm_steps > 0, "successful batch lost its VM cost");
    assert!(cost.sort_steps > 0, "successful batch lost its sorter cost");
    assert!(
        !actual.is_autocommit(),
        "batch committed its pinned transaction"
    );
    for connection in [&expected, &actual] {
        let receipts: i64 = connection
            .query_row("SELECT count(*) FROM receipts", [], |row| row.get(0))
            .unwrap();
        let logs: i64 = connection
            .query_row("SELECT count(*) FROM receipt_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!((receipts, logs), (3, 6));
        connection.execute_batch("ROLLBACK").unwrap();
        let tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name IN ('receipts', 'receipt_log')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "batch escaped its caller's rollback");
    }
}
