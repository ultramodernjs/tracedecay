use super::*;

#[test]
fn interrupted_sorter_reports_spilled_bytes_before_sort_completion() {
    const CHILD: &str = "TRACEDECAY_SPILL_COST_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exact_sql::statement_cost_tests::spill_cost_tests::interrupted_sorter_reports_spilled_bytes_before_sort_completion",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "spill-cost capture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "PRAGMA temp_store=FILE;
             PRAGMA cache_size=-64;
             CREATE TABLE spill_items(value INTEGER, payload TEXT);
             WITH RECURSIVE numbers(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM numbers WHERE value < 4096
             ) INSERT INTO spill_items SELECT value, printf('%04096d', value) FROM numbers;",
        )
        .unwrap();
    let events = CostEvents(Arc::default(), std::thread::current().id());
    tracing::subscriber::set_global_default(events.clone()).unwrap();
    let mut polls = 0;
    connection
        .progress_handler(
            1000,
            Some(move || {
                polls += 1;
                polls >= 10
            }),
        )
        .unwrap();
    let sql = "SELECT payload, value FROM spill_items ORDER BY value DESC";
    let result = execute_query_unchecked(
        &connection,
        ExactSqlStatement::new(sql.to_owned(), vec![]).unwrap(),
    );
    assert!(matches!(
        result,
        Err(ExactSqlError::Sqlite { code: Some(9), .. })
    ));
    connection
        .progress_handler(0, None::<fn() -> bool>)
        .unwrap();
    {
        let captured = events.0.lock().unwrap();
        assert_eq!(captured.len(), 1, "{captured:?}");
        let event = &captured[0];
        assert_eq!(
            event["sort_steps"], "0",
            "interrupted before producing sorted rows"
        );
        let spill = event.get("temp_spill_bytes").expect(
            "interrupted sorter construction must report spill bytes even when Sort Operations is zero",
        );
        assert!(spill.parse::<u64>().unwrap() >= 1_000_000, "{event:?}");
        assert!(event["vm_steps"].parse::<u64>().unwrap() >= 10000);
        assert_eq!(event["failed"], "true");
        eprintln!("interrupted sorter cost: {event:?}");
    }
    // Connection counters are cumulative. A later statement must not inherit
    // the interrupted sorter's bytes, including on a cached-statement retry.
    for _ in 0..2 {
        let result = execute_query_unchecked(
            &connection,
            ExactSqlStatement::new(
                "SELECT ?1".to_owned(),
                vec![ExactSqlValue::Text("private-spill-value".to_owned())],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result.rows.len(), 1);
    }
    let captured = events.0.lock().unwrap();
    assert_eq!(captured.len(), 3, "{captured:?}");
    for event in &captured[1..] {
        assert_eq!(event["temp_spill_bytes"], "0", "{event:?}");
    }
    let debug = format!("{captured:?}");
    for sensitive in ["private-spill-value", "SELECT", "spill_items", "payload"] {
        assert!(!debug.contains(sensitive), "{debug}");
    }
}
