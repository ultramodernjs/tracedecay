use super::*;

mod batch_cost_tests;
mod spill_cost_tests;

fn fixture() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE items(value INTEGER);
             WITH RECURSIVE numbers(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM numbers WHERE value < 12000
             ) INSERT INTO items SELECT value FROM numbers;",
        )
        .unwrap();
    let _ = crate::telemetry::take_observed_vm();
    connection
}

#[test]
fn failed_materialization_records_sort_and_scan_cost() {
    let connection = fixture();
    let result = execute_query(
        &connection,
        ExactSqlStatement::new(
            "SELECT value FROM items ORDER BY value DESC".to_owned(),
            vec![],
        )
        .unwrap(),
        ExactSqlStatementBudget::Request,
    );
    assert!(matches!(result, Err(ExactSqlError::QueryLimitExceeded)));
    let cost = crate::telemetry::take_observed_vm();
    assert!(
        cost.sort_steps > 0,
        "failed read lost its sorter cost: {cost:?}"
    );
    assert!(
        cost.fullscan_steps >= 11999,
        "failed read lost its scan cost: {cost:?}"
    );
    assert!(cost.vm_steps > 0, "failed read lost its VM cost: {cost:?}");
}

#[test]
fn interrupted_query_records_work_before_cancellation() {
    let connection = fixture();
    connection.progress_handler(1000, Some(|| true)).unwrap();
    let result = execute_query_unchecked(
        &connection,
        ExactSqlStatement::new(
            "SELECT value FROM items ORDER BY value DESC".to_owned(),
            vec![],
        )
        .unwrap(),
    );
    assert!(matches!(
        result,
        Err(ExactSqlError::Sqlite { code: Some(9), .. })
    ));
    let cost = crate::telemetry::take_observed_vm();
    assert!(
        cost.vm_steps >= 1000,
        "interrupted read lost its VM cost: {cost:?}"
    );
    assert!(
        cost.fullscan_steps > 0,
        "interrupted read lost its scan cost: {cost:?}"
    );
}

#[test]
fn failed_write_records_work_and_cached_retry_does_not_double_count() {
    let connection = fixture();
    connection
        .execute_batch("CREATE TABLE unique_items(value INTEGER UNIQUE);")
        .unwrap();
    let result = execute_statement(
        &connection,
        ExactSqlStatement::new(
            "INSERT INTO unique_items SELECT value % 4000 FROM items".to_owned(),
            vec![],
        )
        .unwrap(),
    );
    assert!(result.is_err());
    let cost = crate::telemetry::take_observed_vm();
    assert!(
        cost.vm_steps > 4000,
        "failed write lost its VM cost: {cost:?}"
    );
    let result = execute_statement(
        &connection,
        ExactSqlStatement::new(
            "INSERT INTO unique_items SELECT value % 4000 FROM items".to_owned(),
            vec![],
        )
        .unwrap(),
    );
    assert!(result.is_err());
    assert_eq!(crate::telemetry::take_observed_vm(), cost);
}

#[derive(Clone)]
struct CostEvents(
    Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    std::thread::ThreadId,
);

impl tracing::Subscriber for CostEvents {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        self.1 == std::thread::current().id()
            && metadata.target() == "tracedecay_rusqlite_runtime::exact_sql::statement_cost"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != "tracedecay_rusqlite_runtime::exact_sql::statement_cost" {
            return;
        }
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

#[test]
fn failed_statement_events_identify_templates_without_values_or_sql_text() {
    const CHILD: &str = "TRACEDECAY_STATEMENT_COST_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The reader-worker regressions install a process-wide subscriber.
        // Keep both captures independent, including tracing's callsite cache.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exact_sql::statement_cost_tests::failed_statement_events_identify_templates_without_values_or_sql_text",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "statement-cost capture failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let connection = fixture();
    let events = CostEvents(Arc::default(), std::thread::current().id());
    tracing::subscriber::set_global_default(events.clone()).unwrap();
    {
        for secret in ["private-value-one", "private-value-two"] {
            let result = execute_query(
                &connection,
                ExactSqlStatement::new(
                    "SELECT value, ?1 FROM items ORDER BY value DESC".to_owned(),
                    vec![ExactSqlValue::Text(secret.to_owned())],
                )
                .unwrap(),
                ExactSqlStatementBudget::Request,
            );
            assert!(matches!(result, Err(ExactSqlError::QueryLimitExceeded)));
        }
        let result = execute_query(
            &connection,
            ExactSqlStatement::new(
                "SELECT ?1 FROM missing_items".to_owned(),
                vec![ExactSqlValue::Text("private-value-three".to_owned())],
            )
            .unwrap(),
            ExactSqlStatementBudget::Request,
        );
        assert!(result.is_err());
        connection.progress_handler(1000, Some(|| true)).unwrap();
        let result = execute_query_unchecked(
            &connection,
            ExactSqlStatement::new(
                "SELECT value FROM items ORDER BY value DESC".to_owned(),
                vec![],
            )
            .unwrap(),
        );
        assert!(matches!(
            result,
            Err(ExactSqlError::Sqlite { code: Some(9), .. })
        ));
    }
    let captured = events.0.lock().unwrap();
    assert_eq!(captured.len(), 4, "{captured:?}");
    for event in &captured[..2] {
        assert_eq!(
            event["sql_template_id"],
            "41e4357939d1b5425013869cfff5d1bbb2b2ea65677e83a5fa5d349b452d95fc"
        );
        assert_eq!(event["failed"], "true");
        assert_eq!(event["sort_steps"], "1");
        assert!(event["vm_steps"].parse::<u64>().unwrap() > 0);
    }
    assert_eq!(
        captured[2]["sql_template_id"],
        "3047ebb2483e05f356c0699c17c39cb771b2290a104164ee8f6be2b4c389c034"
    );
    assert_eq!(captured[2]["vm_steps"], "0");
    assert_eq!(captured[3]["failed"], "true");
    assert_eq!(captured[3]["sqlite_code"], "Some(9)");
    assert!(captured[3]["vm_steps"].parse::<u64>().unwrap() >= 1000);
    assert_eq!(
        captured[3]["sql_template_id"],
        "27290ed4401824317f812456fe0a399d62ac8007f9b8e8fc2ee9d59a173ceae0"
    );
    let debug = format!("{captured:?}");
    assert!(!debug.contains("private-value"));
    assert!(!debug.contains("SELECT"));
    assert!(!debug.contains("missing_items"));
}
