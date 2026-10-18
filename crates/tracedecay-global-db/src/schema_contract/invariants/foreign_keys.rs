use std::collections::BTreeMap;

use tracedecay_domain::errors::Result;
use tracedecay_runtime_core::db::engine::QueryExecutor;

use super::AUDIT_PAGE_ROWS;
use super::rows::{audit_read_error, authority_violation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForeignKeyPage {
    Complete,
    Progress {
        last_rowid: i64,
    },
    Violation {
        rowid: i64,
        parent: String,
        foreign_key_id: i64,
    },
}

struct TableShape {
    without_rowid: bool,
    columns: Vec<Column>,
}

struct Column {
    name: String,
    primary_key_position: i64,
}

struct ForeignKey {
    parent: String,
    columns: Vec<(String, Option<String>)>,
}

/// Checks every declared foreign key against one rowid page of child rows.
///
/// The caller retains the same read snapshot through metadata and page reads,
/// then releases it before committing the returned cursor. A nonempty final
/// page returns progress; the following empty page confirms completion.
pub(super) async fn check_foreign_key_page(
    conn: &impl QueryExecutor,
    table: &str,
    after_rowid: Option<i64>,
) -> Result<ForeignKeyPage> {
    let child = table_shape(conn, table).await?;
    let mut foreign_keys = foreign_key_metadata(conn, table, &child).await?;
    if foreign_keys.is_empty() {
        return Ok(ForeignKeyPage::Complete);
    }
    if child.without_rowid {
        return Err(authority_violation(format!(
            "foreign key audit requires rowid pagination for table {table}"
        )));
    }
    let rowid = ["_rowid_", "rowid", "oid"]
        .into_iter()
        .find(|alias| {
            !child
                .columns
                .iter()
                .any(|column| column.name.eq_ignore_ascii_case(alias))
        })
        .ok_or_else(|| {
            authority_violation(format!(
                "foreign key audit has no unshadowed rowid alias for table {table}"
            ))
        })?;

    for key in foreign_keys.values_mut() {
        let parent = table_shape(conn, &key.parent).await?;
        let implicit = key.columns.iter().all(|(_, parent)| parent.is_none());
        if implicit {
            let mut primary_key: Vec<_> = parent
                .columns
                .iter()
                .filter(|column| column.primary_key_position > 0)
                .collect();
            primary_key.sort_by_key(|column| column.primary_key_position);
            if primary_key.len() != key.columns.len() {
                return Err(authority_violation(format!(
                    "foreign key audit found an incompatible primary key for parent {}",
                    key.parent
                )));
            }
            for ((_, target), column) in key.columns.iter_mut().zip(primary_key) {
                *target = Some(column.name.clone());
            }
        } else if key.columns.iter().any(|(_, parent)| parent.is_none()) {
            return Err(authority_violation(format!(
                "foreign key audit found partially omitted columns for parent {}",
                key.parent
            )));
        }
        for (_, target) in &key.columns {
            if !parent.columns.iter().any(|column| {
                target
                    .as_ref()
                    .is_some_and(|target| column.name.eq_ignore_ascii_case(target))
            }) {
                return Err(authority_violation(format!(
                    "foreign key audit found an unknown column in parent {}",
                    key.parent
                )));
            }
        }
    }

    // SQLite resolves the parent's eligible unique index and its declared
    // collations while compiling this pragma. EXPLAIN returns its program
    // without executing it, so malformed keys fail even for an empty child
    // without invoking the pragma's unbounded table scan.
    let explain = format!(
        "EXPLAIN PRAGMA main.foreign_key_check({})",
        quote_identifier(table)
    );
    let mut program = conn.query(&explain, ()).await.map_err(audit_read_error)?;
    if program.next().await.map_err(audit_read_error)?.is_none() {
        return Err(authority_violation(
            "foreign key metadata validation returned no SQLite program",
        ));
    }
    drop(program);

    let (sql, initial_rowid) = page_query(table, rowid, &foreign_keys, after_rowid)?;
    let mut rows = conn
        .query(&sql, (initial_rowid,))
        .await
        .map_err(audit_read_error)?;
    let row = rows
        .next()
        .await
        .map_err(audit_read_error)?
        .ok_or_else(|| authority_violation("foreign key page query returned no row"))?;
    let last_rowid: Option<i64> = row.get(0).map_err(audit_read_error)?;
    let violation_rowid: Option<i64> = row.get(1).map_err(audit_read_error)?;
    let violation_id: Option<i64> = row.get(2).map_err(audit_read_error)?;
    match (last_rowid, violation_rowid, violation_id) {
        (Some(_), Some(rowid), Some(foreign_key_id)) => {
            let key = foreign_keys.get(&foreign_key_id).ok_or_else(|| {
                authority_violation("foreign key page returned an unknown foreign key")
            })?;
            Ok(ForeignKeyPage::Violation {
                rowid,
                parent: key.parent.clone(),
                foreign_key_id,
            })
        }
        (Some(last_rowid), None, None) => Ok(ForeignKeyPage::Progress { last_rowid }),
        (None, None, None) => Ok(ForeignKeyPage::Complete),
        _ => Err(authority_violation(
            "foreign key page returned inconsistent violation columns",
        )),
    }
}

async fn table_shape(conn: &impl QueryExecutor, table: &str) -> Result<TableShape> {
    let mut tables = conn
        .query(
            "SELECT type, wr FROM pragma_table_list
             WHERE schema = 'main' AND name = ?1 COLLATE NOCASE",
            (table,),
        )
        .await
        .map_err(audit_read_error)?;
    let table_row = tables
        .next()
        .await
        .map_err(audit_read_error)?
        .ok_or_else(|| {
            authority_violation(format!("foreign key audit table {table} is missing"))
        })?;
    let kind: String = table_row.get(0).map_err(audit_read_error)?;
    let without_rowid: i64 = table_row.get(1).map_err(audit_read_error)?;
    if kind != "table" || !matches!(without_rowid, 0 | 1) {
        return Err(authority_violation(format!(
            "foreign key audit does not support table shape {table}"
        )));
    }
    drop(tables);
    let mut rows = conn
        .query(
            "SELECT cid, name, pk FROM pragma_table_xinfo(?1, 'main') ORDER BY cid",
            (table,),
        )
        .await
        .map_err(audit_read_error)?;
    let mut columns = Vec::<Column>::new();
    while let Some(row) = rows.next().await.map_err(audit_read_error)? {
        let cid: i64 = row.get(0).map_err(audit_read_error)?;
        let name: String = row.get(1).map_err(audit_read_error)?;
        let primary_key_position: i64 = row.get(2).map_err(audit_read_error)?;
        if usize::try_from(cid).ok() != Some(columns.len())
            || primary_key_position < 0
            || columns
                .iter()
                .any(|column| column.name.eq_ignore_ascii_case(&name))
        {
            return Err(authority_violation(format!(
                "foreign key audit found invalid column metadata in table {table}"
            )));
        }
        columns.push(Column {
            name,
            primary_key_position,
        });
    }
    if columns.is_empty() {
        return Err(authority_violation(format!(
            "foreign key audit found no columns in table {table}"
        )));
    }
    let mut positions: Vec<_> = columns
        .iter()
        .filter_map(|column| {
            (column.primary_key_position > 0).then_some(column.primary_key_position)
        })
        .collect();
    positions.sort_unstable();
    for (index, position) in positions.iter().enumerate() {
        if usize::try_from(*position).ok() != Some(index + 1) {
            return Err(authority_violation(format!(
                "foreign key audit found invalid primary key metadata in table {table}"
            )));
        }
    }
    Ok(TableShape {
        without_rowid: without_rowid == 1,
        columns,
    })
}

async fn foreign_key_metadata(
    conn: &impl QueryExecutor,
    table: &str,
    child: &TableShape,
) -> Result<BTreeMap<i64, ForeignKey>> {
    let mut rows = conn
        .query(
            "SELECT id, seq, \"table\", \"from\", \"to\"
             FROM pragma_foreign_key_list(?1, 'main') ORDER BY id, seq",
            (table,),
        )
        .await
        .map_err(audit_read_error)?;
    let mut keys = BTreeMap::<i64, ForeignKey>::new();
    while let Some(row) = rows.next().await.map_err(audit_read_error)? {
        let id: i64 = row.get(0).map_err(audit_read_error)?;
        let sequence: i64 = row.get(1).map_err(audit_read_error)?;
        let parent: String = row.get(2).map_err(audit_read_error)?;
        let source: String = row.get(3).map_err(audit_read_error)?;
        let target: Option<String> = row.get(4).map_err(audit_read_error)?;
        let key = keys.entry(id).or_insert_with(|| ForeignKey {
            parent: parent.clone(),
            columns: Vec::new(),
        });
        if id < 0
            || usize::try_from(sequence).ok() != Some(key.columns.len())
            || parent != key.parent
            || !child
                .columns
                .iter()
                .any(|column| column.name.eq_ignore_ascii_case(&source))
        {
            return Err(authority_violation(format!(
                "foreign key audit found invalid foreign key metadata in table {table}"
            )));
        }
        key.columns.push((source, target));
    }
    Ok(keys)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn page_query(
    table: &str,
    rowid: &str,
    foreign_keys: &BTreeMap<i64, ForeignKey>,
    after_rowid: Option<i64>,
) -> Result<(String, i64)> {
    let mut projection = vec![format!("child.{} AS cursor", quote_identifier(rowid))];
    let mut checks = Vec::new();
    let mut key_index = 0;
    for (id, key) in foreign_keys {
        let mut non_null = Vec::new();
        let mut equal = Vec::new();
        for (source, target) in &key.columns {
            let target = target.as_ref().ok_or_else(|| {
                authority_violation("foreign key audit parent column was not resolved")
            })?;
            let alias = format!("key_{key_index}");
            projection.push(format!("child.{} AS {alias}", quote_identifier(source)));
            non_null.push(format!("page.{alias} IS NOT NULL"));
            // Parent affinity and collation define SQLite FK equality. Unary
            // plus removes child-column affinity without converting its value.
            equal.push(format!(
                "parent.{} = +page.{alias}",
                quote_identifier(target)
            ));
            key_index += 1;
        }
        checks.push(format!(
            "SELECT page.cursor, {id} AS foreign_key_id FROM child_page AS page
             WHERE {} AND NOT EXISTS (
                 SELECT 1 FROM main.{} AS parent WHERE {}
             )",
            non_null.join(" AND "),
            quote_identifier(&key.parent),
            equal.join(" AND ")
        ));
    }
    let (comparison, initial_rowid) = match after_rowid {
        Some(rowid) => (">", rowid),
        None => (">=", i64::MIN),
    };
    Ok((
        format!(
            "WITH child_page AS MATERIALIZED (
                 SELECT {} FROM main.{} AS child
                 WHERE child.{} {comparison} ?1
                 ORDER BY child.{} LIMIT {AUDIT_PAGE_ROWS}
             ), violation AS MATERIALIZED ({} ORDER BY cursor, foreign_key_id LIMIT 1)
             SELECT frontier.last_rowid, violation.cursor, violation.foreign_key_id
             FROM (SELECT MAX(cursor) AS last_rowid FROM child_page) AS frontier
             LEFT JOIN violation ON 1",
            projection.join(", "),
            quote_identifier(table),
            quote_identifier(rowid),
            quote_identifier(rowid),
            checks.join(" UNION ALL ")
        ),
        initial_rowid,
    ))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use tracedecay_domain::errors::ProjectOpenFailureKind;

    use crate::tests::harness::RegisteredGlobalDbTestFixture;

    use super::super::test_fixture::open_registered;
    use super::{AUDIT_PAGE_ROWS, ForeignKeyPage, check_foreign_key_page};

    async fn fixture(schema: &str) -> (TempDir, RegisteredGlobalDbTestFixture) {
        let (directory, database) = open_registered().await;
        let seed = rusqlite::Connection::open(directory.path().join("sessions.db")).unwrap();
        seed.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        seed.execute_batch(schema).unwrap();
        drop(seed);
        (directory, database)
    }

    async fn oracle(conn: &RegisteredGlobalDbTestFixture, table: &str) -> Vec<(i64, i64)> {
        use tracedecay_runtime_core::db::engine::QueryExecutor;

        let mut rows = conn
            .query(
                "SELECT rowid, fkid FROM pragma_foreign_key_check(?1, 'main')
                 ORDER BY rowid, fkid",
                (table,),
            )
            .await
            .unwrap();
        let mut violations = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            violations.push((row.get(0).unwrap(), row.get(1).unwrap()));
        }
        violations
    }

    #[asupersync::test]
    async fn composite_nullable_keys_resolve_omitted_primary_key_order() {
        let (_directory, conn) = fixture(
            "CREATE TABLE fk_parent (
                 name TEXT COLLATE NOCASE, number INTEGER,
                 PRIMARY KEY(number, name)
             ) WITHOUT ROWID;
             CREATE TABLE fk_child (
                 number TEXT, name BLOB,
                 FOREIGN KEY(number, name) REFERENCES fk_parent
             );
             INSERT INTO fk_parent VALUES ('Mixed', 7);
             INSERT INTO fk_child VALUES ('007', 'mixed'), (NULL, 'absent'), ('99', NULL),
                                         (NULL, NULL);",
        )
        .await;
        assert!(oracle(&conn, "fk_child").await.is_empty());
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", None)
                .await
                .unwrap(),
            ForeignKeyPage::Progress { last_rowid: 4 }
        );
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", Some(4))
                .await
                .unwrap(),
            ForeignKeyPage::Complete
        );
    }

    #[asupersync::test]
    async fn parent_affinity_and_collation_match_sqlite_for_every_declared_key() {
        let (_directory, conn) = fixture(
            "CREATE TABLE fk_text_parent (value TEXT PRIMARY KEY);
             CREATE TABLE fk_number_parent (value INTEGER PRIMARY KEY);
             CREATE TABLE fk_nocase_parent (value TEXT COLLATE NOCASE PRIMARY KEY);
             CREATE TABLE fk_child (
                 text_value INTEGER REFERENCES fk_text_parent(value),
                 number_value TEXT REFERENCES fk_number_parent(value),
                 name BLOB REFERENCES fk_nocase_parent(value)
             );
             INSERT INTO fk_text_parent VALUES ('1'), ('01');
             INSERT INTO fk_number_parent VALUES (1);
             INSERT INTO fk_nocase_parent VALUES ('MiXeD');
             INSERT INTO fk_child VALUES (1, '001', 'mixed');
             INSERT INTO fk_child VALUES (2, '001', 'mixed');",
        )
        .await;
        let expected = oracle(&conn, "fk_child").await;
        assert_eq!(expected.len(), 1);
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", None)
                .await
                .unwrap(),
            ForeignKeyPage::Violation {
                rowid: expected[0].0,
                parent: "fk_text_parent".to_owned(),
                foreign_key_id: expected[0].1,
            }
        );
    }

    #[asupersync::test]
    async fn child_numeric_affinity_and_collation_do_not_override_parent() {
        let (_directory, conn) = fixture(
            "CREATE TABLE fk_parent (value TEXT PRIMARY KEY);
             CREATE TABLE fk_child (value INTEGER COLLATE NOCASE REFERENCES fk_parent);
             INSERT INTO fk_parent VALUES ('01'), ('MiXeD');
             INSERT INTO fk_child VALUES (1), ('mixed');",
        )
        .await;
        let expected = oracle(&conn, "fk_child").await;
        assert_eq!(expected.len(), 2);
        for (rowid, foreign_key_id) in expected {
            assert_eq!(
                check_foreign_key_page(&conn, "fk_child", Some(rowid - 1))
                    .await
                    .unwrap(),
                ForeignKeyPage::Violation {
                    rowid,
                    parent: "fk_parent".to_owned(),
                    foreign_key_id,
                }
            );
        }
    }

    #[asupersync::test]
    async fn violation_after_page_boundary_is_found_on_resumption() {
        let (_directory, conn) = fixture(&format!(
            "CREATE TABLE fk_parent (value INTEGER PRIMARY KEY);
             CREATE TABLE fk_child (value INTEGER REFERENCES fk_parent);
             INSERT INTO fk_parent VALUES (1);
             WITH RECURSIVE n(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < {AUDIT_PAGE_ROWS}
             ) INSERT INTO fk_child SELECT 1 FROM n;
             INSERT INTO fk_child VALUES (2);"
        ))
        .await;
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", None)
                .await
                .unwrap(),
            ForeignKeyPage::Progress {
                last_rowid: AUDIT_PAGE_ROWS
            }
        );
        let expected = oracle(&conn, "fk_child").await;
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[0].0, AUDIT_PAGE_ROWS + 1);
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", Some(AUDIT_PAGE_ROWS))
                .await
                .unwrap(),
            ForeignKeyPage::Violation {
                rowid: expected[0].0,
                parent: "fk_parent".to_owned(),
                foreign_key_id: expected[0].1,
            }
        );
    }

    #[asupersync::test]
    async fn keyset_pages_cover_negative_minimum_gaps_and_multiple_pages() {
        let (_directory, conn) = fixture(&format!(
            "CREATE TABLE fk_parent (value INTEGER PRIMARY KEY);
             CREATE TABLE fk_child (value INTEGER REFERENCES fk_parent);
             INSERT INTO fk_parent VALUES (1);
             INSERT INTO fk_child(rowid, value) VALUES ({}, 1), (-2, 1), (0, 1);
             WITH RECURSIVE n(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM n WHERE value < {}
             ) INSERT INTO fk_child(rowid, value) SELECT value * 2, 1 FROM n;",
            i64::MIN,
            AUDIT_PAGE_ROWS * 2
        ))
        .await;
        let snapshot = conn
            .database()
            .read_connection()
            .background()
            .read_snapshot()
            .await
            .unwrap();
        let first = check_foreign_key_page(&snapshot, "fk_child", None)
            .await
            .unwrap();
        assert_eq!(
            first,
            ForeignKeyPage::Progress {
                last_rowid: (AUDIT_PAGE_ROWS - 3) * 2
            }
        );
        drop(snapshot);
        let second = check_foreign_key_page(&conn, "fk_child", Some((AUDIT_PAGE_ROWS - 3) * 2))
            .await
            .unwrap();
        assert_eq!(
            second,
            ForeignKeyPage::Progress {
                last_rowid: (AUDIT_PAGE_ROWS * 2 - 3) * 2
            }
        );
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", Some((AUDIT_PAGE_ROWS * 2 - 3) * 2))
                .await
                .unwrap(),
            ForeignKeyPage::Progress {
                last_rowid: AUDIT_PAGE_ROWS * 4
            }
        );
        assert_eq!(
            check_foreign_key_page(&conn, "fk_child", Some(AUDIT_PAGE_ROWS * 4))
                .await
                .unwrap(),
            ForeignKeyPage::Complete
        );
    }

    #[asupersync::test]
    async fn empty_and_foreign_key_free_tables_complete() {
        let (_directory, conn) = fixture(
            "CREATE TABLE fk_parent (value INTEGER PRIMARY KEY);
             CREATE TABLE fk_empty (value INTEGER REFERENCES fk_parent);
             CREATE TABLE fk_free (value TEXT PRIMARY KEY) WITHOUT ROWID;
             INSERT INTO fk_free VALUES ('present');",
        )
        .await;
        for table in ["fk_empty", "fk_free"] {
            assert_eq!(
                check_foreign_key_page(&conn, table, None).await.unwrap(),
                ForeignKeyPage::Complete
            );
        }
    }

    #[asupersync::test]
    async fn quoted_identifiers_and_one_shadowed_rowid_use_real_rowids() {
        let (_directory, conn) = fixture(
            "CREATE TABLE \"fk\"\"parent\" (\"key\"\"value\" TEXT PRIMARY KEY);
             CREATE TABLE \"fk\"\"child\" (
                 rowid TEXT, \"from\" TEXT REFERENCES \"fk\"\"parent\"(\"key\"\"value\")
             );
             INSERT INTO \"fk\"\"parent\" VALUES ('present');
             INSERT INTO \"fk\"\"child\" VALUES ('shadow', 'present');",
        )
        .await;
        assert_eq!(
            check_foreign_key_page(&conn, "fk\"child", None)
                .await
                .unwrap(),
            ForeignKeyPage::Progress { last_rowid: 1 }
        );
    }

    #[asupersync::test]
    async fn unsupported_rowid_shapes_fail_closed() {
        let (_directory, conn) = fixture(
            "CREATE TABLE fk_parent (value INTEGER PRIMARY KEY);
             CREATE TABLE fk_shadowed (
                 rowid TEXT, _rowid_ TEXT, oid TEXT, value INTEGER REFERENCES fk_parent
             );
             CREATE TABLE fk_without_rowid (
                 value INTEGER PRIMARY KEY REFERENCES fk_parent
             ) WITHOUT ROWID;",
        )
        .await;
        for table in ["fk_shadowed", "fk_without_rowid", "unknown_table"] {
            let error = check_foreign_key_page(&conn, table, None)
                .await
                .expect_err("unsupported table must fail closed");
            assert_eq!(
                error.project_open_failure_kind(),
                Some(ProjectOpenFailureKind::AuthorityVerdict {
                    migration_pending: false
                })
            );
        }
    }

    #[asupersync::test]
    async fn malformed_parent_keys_fail_even_when_child_is_empty() {
        for schema in [
            "CREATE TABLE fk_parent(value TEXT);
             CREATE TABLE fk_child(value TEXT REFERENCES fk_parent(value));",
            "CREATE TABLE fk_parent(value TEXT COLLATE NOCASE);
             CREATE UNIQUE INDEX fk_wrong_collation ON fk_parent(value COLLATE BINARY);
             CREATE TABLE fk_child(value TEXT REFERENCES fk_parent(value));",
            "CREATE TABLE fk_parent(value TEXT PRIMARY KEY);
             CREATE TABLE fk_child(value TEXT REFERENCES fk_parent(missing));",
            "CREATE TABLE fk_child(value TEXT REFERENCES missing_parent(value));",
            "CREATE TABLE fk_parent(a TEXT, b TEXT, PRIMARY KEY(a,b));
             CREATE TABLE fk_child(value TEXT REFERENCES fk_parent);",
            "CREATE TABLE fk_parent(value TEXT);
             CREATE UNIQUE INDEX fk_partial ON fk_parent(value) WHERE value IS NOT NULL;
             CREATE TABLE fk_child(value TEXT REFERENCES fk_parent(value));",
        ] {
            let (_directory, conn) = fixture(schema).await;
            let error = check_foreign_key_page(&conn, "fk_child", None)
                .await
                .expect_err("malformed foreign key must fail closed");
            assert_eq!(
                error.project_open_failure_kind(),
                Some(ProjectOpenFailureKind::AuthorityVerdict {
                    migration_pending: false
                })
            );
        }
    }
}
