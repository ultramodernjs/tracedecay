use super::{compact_offline_v1, inspect_compaction_candidate_v1};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

fn fixture(root: &Path) -> PathBuf {
    let path = root.join("sessions.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA auto_vacuum=NONE;
         PRAGMA foreign_keys=ON;
         PRAGMA user_version=42;
         PRAGMA application_id=123;
         CREATE TABLE sessions(id INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE);
         CREATE TABLE observations(id INTEGER PRIMARY KEY, session_id INTEGER REFERENCES sessions(id), body TEXT);
         CREATE TABLE writer_ledger(id INTEGER PRIMARY KEY, receipt TEXT NOT NULL);
         CREATE TABLE audit(id INTEGER PRIMARY KEY, observation_id INTEGER);
         CREATE TRIGGER observation_audit AFTER INSERT ON observations BEGIN
             INSERT INTO audit(observation_id) VALUES (new.id);
         END;
         CREATE VIRTUAL TABLE search USING fts5(body, content=observations, content_rowid=id);
         INSERT INTO sessions VALUES(71, 'session.stable');
         INSERT INTO writer_ledger VALUES(81, 'receipt.stable');",
    ).unwrap();
    for id in 1..=400 {
        conn.execute(
            "INSERT INTO observations VALUES(?1, 71, ?2)",
            rusqlite::params![id, format!("needle {}", "retained payload ".repeat(600))],
        )
        .unwrap();
    }
    conn.execute_batch(
        "DELETE FROM observations WHERE id % 2 = 0; INSERT INTO search(search) VALUES('rebuild');",
    )
    .unwrap();
    path
}

#[test]
fn legacy_none_store_compacts_to_incremental_without_changing_session_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    let before = std::fs::read(&database).unwrap();
    let entries = std::fs::read_dir(&root).unwrap().count();
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    assert_eq!(plan.auto_vacuum, 0);
    assert!(plan.expected_compacted_bytes < plan.bytes_before);
    assert_eq!(
        std::fs::read(&database).unwrap(),
        before,
        "preview is read only"
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), entries);
    let receipt = compact_offline_v1(&root, &database, &plan.digest, 100_000).unwrap();
    assert!(receipt.bytes_after < receipt.bytes_before);
    assert_eq!(
        receipt.bytes_after,
        std::fs::metadata(&database).unwrap().len()
    );
    let conn = Connection::open(&database).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA auto_vacuum", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        42
    );
    assert_eq!(
        conn.query_row("SELECT identity FROM sessions WHERE id=71", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "session.stable"
    );
    assert_eq!(
        conn.query_row("SELECT receipt FROM writer_ledger WHERE id=81", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "receipt.stable"
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM observations", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        200
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM search WHERE search MATCH 'needle'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        200
    );
    conn.execute(
        "INSERT INTO observations VALUES(999,71,'trigger still works')",
        [],
    )
    .unwrap();
    assert_eq!(
        conn.query_row("SELECT observation_id FROM audit WHERE id=401", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        999
    );
    assert!(
        !conn
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap()
    );
    assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".td-offline-compact-")
    }));
}

#[test]
fn offline_compaction_occupied_page_slack_repacked_even_when_freelist_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = root.join("sessions.db");
    {
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; CREATE TABLE retained(id INTEGER PRIMARY KEY, body TEXT);").unwrap();
        for id in 1..=200 {
            conn.execute(
                "INSERT INTO retained VALUES(?1,?2)",
                rusqlite::params![id, "x".repeat(3500)],
            )
            .unwrap();
        }
        conn.execute("UPDATE retained SET body=substr(body,1,1000)", [])
            .unwrap();
    }
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    assert_eq!(
        plan.free_page_bytes, 0,
        "this is occupied-page slack, not a freelist test"
    );
    let result = compact_offline_v1(&root, &database, &plan.digest, 100_000).unwrap();
    assert!(result.bytes_after < result.bytes_before / 2);
    eprintln!(
        "occupied-page compaction: {} -> {} bytes",
        result.bytes_before, result.bytes_after
    );
    let conn = Connection::open(&database).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM retained WHERE length(body)=1000",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        200
    );
}

#[test]
fn offline_compaction_busy_profile_never_replaces_database() {
    use crate::lifecycle_lease::acquire_shared_for_profile;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    let _daemon = acquire_shared_for_profile(&root, "fixture-daemon").unwrap();
    let before = std::fs::read(&database).unwrap();
    let error = compact_offline_v1(&root, &database, &plan.digest, 100_000).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(std::fs::read(&database).unwrap(), before);
}

#[test]
fn offline_compaction_rejects_stale_preview_budget_sidecars_and_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    assert!(
        inspect_compaction_candidate_v1(&root, &database, 1)
            .unwrap_err()
            .to_string()
            .contains("page budget")
    );
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    let conn = Connection::open(&database).unwrap();
    conn.execute("UPDATE sessions SET identity='session.changed'", [])
        .unwrap();
    drop(conn);
    assert!(
        compact_offline_v1(&root, &database, &plan.digest, 100_000)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
    let alias = root.join("alias.db");
    std::os::unix::fs::symlink(&database, &alias).unwrap();
    assert!(inspect_compaction_candidate_v1(&root, &alias, 100_000).is_err());
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; INSERT INTO sessions VALUES(72,'committed.wal');")
        .unwrap();
    assert!(
        inspect_compaction_candidate_v1(&root, &database, 100_000)
            .unwrap_err()
            .to_string()
            .contains("sidecar")
    );
    assert!(
        compact_offline_v1(&root, &database, &plan.digest, 100_000)
            .unwrap_err()
            .to_string()
            .contains("sidecar")
    );
    assert_eq!(
        conn.query_row("SELECT identity FROM sessions WHERE id=72", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "committed.wal"
    );
}

#[test]
fn offline_compaction_quick_check_blocks_invalid_source_before_staging() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    {
        use std::io::{Seek, SeekFrom, Write};
        let conn = Connection::open(&database).unwrap();
        let page = conn
            .query_row(
                "SELECT rootpage FROM sqlite_schema WHERE name='sessions'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap();
        let page_size = conn
            .query_row("PRAGMA page_size", [], |row| row.get::<_, u32>(0))
            .unwrap();
        drop(conn);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&database)
            .unwrap();
        file.seek(SeekFrom::Start(u64::from(page - 1) * u64::from(page_size)))
            .unwrap();
        file.write_all(&[255]).unwrap(); // invalid B-tree page type, not an application-level policy
    }
    let before = std::fs::read(&database).unwrap();
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    assert!(
        compact_offline_v1(&root, &database, &plan.digest, 100_000)
            .unwrap_err()
            .to_string()
            .contains("quick_check")
    );
    assert_eq!(std::fs::read(&database).unwrap(), before);
    assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".td-offline-compact-")
    }));
}

#[test]
fn offline_compaction_preserves_or_refuses_implicit_rowids() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    {
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("CREATE TABLE implicit(body TEXT); INSERT INTO implicit(rowid,body) VALUES(1,'one'),(99,'ninety nine');").unwrap();
    }
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    let before = std::fs::read(&database).unwrap();
    match compact_offline_v1(&root, &database, &plan.digest, 100_000) {
        Ok(_) => {
            let conn = Connection::open(&database).unwrap();
            let rows = conn
                .prepare("SELECT rowid,body FROM implicit ORDER BY rowid")
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                [(1, "one".to_owned()), (99, "ninety nine".to_owned())]
            );
        }
        Err(error) => {
            assert!(error.to_string().contains("changed schema, rows, ROWIDs"));
            assert_eq!(std::fs::read(&database).unwrap(), before);
        }
    }
}

#[test]
fn offline_compaction_publication_failures_keep_verified_database_and_remove_staging() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            super::PUBLISH_FAULT.with(|fault| fault.set(None));
        }
    }
    for phase in ["before_replace", "after_replace", "after_parent_sync"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let database = fixture(&root);
        let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
        let reset = Reset;
        super::PUBLISH_FAULT.with(|fault| fault.set(Some(phase)));
        assert!(
            compact_offline_v1(&root, &database, &plan.digest, 100_000)
                .unwrap_err()
                .to_string()
                .contains("injected publication failure")
        );
        drop(reset);
        let conn = Connection::open(&database).unwrap();
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM search WHERE search MATCH 'needle'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            200
        );
        assert_eq!(
            conn.query_row("SELECT identity FROM sessions WHERE id=71", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "session.stable"
        );
        assert!(
            !std::fs::read_dir(&root).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".td-offline-compact-")
            }),
            "publication failure must not retain a secondary database copy"
        );
    }
}

#[test]
#[ignore = "subprocess helper for interruption recovery"]
fn offline_compaction_interruption_child() {
    let root = PathBuf::from(std::env::var_os("TRACEDECAY_TEST_COMPACTION_ROOT").unwrap());
    let database = root.join("sessions.db");
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    compact_offline_v1(&root, &database, &plan.digest, 100_000).unwrap();
}

#[test]
fn offline_compaction_recovers_its_staging_after_process_interruption() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct Reap(Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    let original = std::fs::read(&database).unwrap();
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    let ready = root.join("child-ready");
    let mut child = Reap(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "offline_compaction::tests::offline_compaction_interruption_child",
            ])
            .env("TRACEDECAY_TEST_COMPACTION_ROOT", &root)
            .env("TRACEDECAY_TEST_COMPACTION_PAUSE", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "compaction child exited before its publication boundary"
        );
        assert!(
            Instant::now() < deadline,
            "compaction child did not reach publication"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(
        std::fs::read(&database).unwrap(),
        original,
        "interruption must leave the active database intact"
    );
    compact_offline_v1(&root, &database, &plan.digest, 100_000).unwrap();
    assert!(
        !std::fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("offline-compact")
        }),
        "retry must reclaim the interrupted operation's staging before allocating another copy"
    );
}

#[test]
fn offline_compaction_preserves_or_refuses_shadowed_implicit_rowids() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let database = fixture(&root);
    {
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("CREATE TABLE implicit(_rowid_ TEXT, body TEXT); INSERT INTO implicit(rowid,_rowid_,body) VALUES(1,'alias.one','one'),(99,'alias.two','ninety nine');").unwrap();
    }
    let plan = inspect_compaction_candidate_v1(&root, &database, 100_000).unwrap();
    let before = std::fs::read(&database).unwrap();
    match compact_offline_v1(&root, &database, &plan.digest, 100_000) {
        Ok(_) => {
            let conn = Connection::open(&database).unwrap();
            let rows = conn
                .prepare("SELECT rowid,body FROM implicit ORDER BY rowid")
                .unwrap()
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                [(1, "one".to_owned()), (99, "ninety nine".to_owned())]
            );
        }
        Err(error) => {
            assert!(error.to_string().contains("changed schema, rows, ROWIDs"));
            assert_eq!(std::fs::read(&database).unwrap(), before);
        }
    }
}
