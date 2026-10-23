#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::{create, discard, initialize, new_stage, publish};
use crate::embedding::doubles::HashEncoder;
use crate::engine::{NcmEngine, Outcome};
use crate::ports::StateRoot;
use crate::store::{
    NamespaceStore, StoreError, StoreIdentity, StoreMeta, configure_connection, create_schema,
};
use rusqlite::Connection;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use tracedecay_memory_ncm_core::types::{AlgorithmIdentity, NcmConfig};

const CHILD_ROOT: &str = "NCM_BOOTSTRAP_CHILD_ROOT";
const CHILD_PHASE: &str = "NCM_BOOTSTRAP_CHILD_PHASE";
const READY: &str = "BOOTSTRAP_READY ";

fn namespace() -> String {
    "ab".repeat(32)
}

fn identity(seed: u64) -> StoreIdentity {
    let projection_bytes = vec![1, 2, 3];
    StoreIdentity {
        algorithm: AlgorithmIdentity {
            profile: "ncm-biomem-rs.v1".to_owned(),
            config_sha256: "config-digest".to_owned(),
        },
        projection_sha256: crate::store::sha256_hex(&projection_bytes),
        encoder_model: "test-encoder".to_owned(),
        encoder_artifact_sha256: "encoder-digest".to_owned(),
        projection_bytes,
        seed,
        config_json: "{}".to_owned(),
    }
}

fn root(temp: &TempDir) -> StateRoot {
    StateRoot::new(temp.path()).unwrap()
}

fn catalog_count(root: &StateRoot) -> u64 {
    let engine = NcmEngine::new(
        root.clone(),
        Arc::new(HashEncoder::new()),
        NcmConfig::default(),
    );
    let reply = engine.health();
    assert_eq!(reply.outcome, Outcome::Success);
    reply.payload["catalog_namespaces"].as_u64().unwrap()
}

#[test]
fn completed_stage_is_not_live_until_publication() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let ns = namespace();
    let stage = new_stage(&root).unwrap();
    initialize(&stage, &ns, identity(7)).unwrap();
    assert!(!NamespaceStore::exists(&root, &ns));
    assert_eq!(catalog_count(&root), 0);
    assert!(!stage.path().join("ncm.sqlite-wal").exists());
    let old_stage = stage.path().to_owned();
    publish(&root, &ns, stage).unwrap();
    assert!(!old_stage.exists());
    let store = NamespaceStore::open(&root, &ns, &identity(7)).unwrap();
    assert_eq!(store.meta().unwrap(), StoreMeta::default());
    assert_eq!(catalog_count(&root), 1);
}

#[test]
fn failed_initialization_removes_only_its_stage() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let stage = new_stage(&root).unwrap();
    let orphan = new_stage(&root).unwrap();
    let failed_path = stage.path().to_owned();
    let conn = Connection::open(stage.path().join("ncm.sqlite")).unwrap();
    conn.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB)")
        .unwrap();
    conn.close().unwrap();
    let error = initialize(&stage, &namespace(), identity(7)).unwrap_err();
    assert!(matches!(discard(stage, error), StoreError::Sqlite(_)));
    assert!(!failed_path.exists());
    assert!(orphan.path().exists(), "foreign staging remains untouched");
    assert!(!NamespaceStore::exists(&root, &namespace()));
    let store = create(&root, &namespace(), identity(7)).unwrap();
    assert_eq!(store.meta().unwrap(), StoreMeta::default());
}

#[test]
fn simultaneous_publishers_have_exactly_one_winner() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let ns = namespace();
    // Prepare both candidates before spawning a barrier waiter: an initialization
    // assertion failure must not leave a scoped thread waiting forever.
    let stages = [7, 19].map(|seed| {
        let stage = new_stage(&root).unwrap();
        initialize(&stage, &ns, identity(seed)).unwrap();
        (seed, stage)
    });
    let barrier = Arc::new(Barrier::new(2));
    let results = thread::scope(|scope| {
        let mut handles = Vec::new();
        for (seed, stage) in stages {
            let root = root.clone();
            let ns = ns.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(scope.spawn(move || {
                barrier.wait();
                (seed, publish(&root, &ns, stage))
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, Err(StoreError::AlreadyExists)))
            .count(),
        1
    );
    let seed = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
    let store = NamespaceStore::open(&root, &ns, &identity(seed)).unwrap();
    assert_eq!(store.identity().seed, seed);
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        1,
        "losing stage is removed"
    );
}

#[test]
fn delayed_creator_cannot_overwrite_a_committed_winner() {
    let temp = TempDir::new().unwrap();
    let root = root(&temp);
    let ns = namespace();
    let loser = new_stage(&root).unwrap();
    initialize(&loser, &ns, identity(19)).unwrap();
    let loser_path = loser.path().to_owned();
    let mut winner = create(&root, &ns, identity(7)).unwrap();
    let mut mutation = winner.begin_mutation().unwrap();
    mutation
        .append_event("observe", Some("winner"), "payload", "{}", 1)
        .unwrap();
    assert_eq!(mutation.commit().unwrap(), 1);
    assert!(matches!(
        publish(&root, &ns, loser),
        Err(StoreError::AlreadyExists)
    ));
    assert!(!loser_path.exists());
    assert_eq!(winner.meta().unwrap().commit_seq, 1);
    assert_eq!(
        winner.events_after(0).unwrap()[0]
            .idempotency_key
            .as_deref(),
        Some("winner")
    );
    drop(winner);
    assert!(matches!(
        create(&root, &ns, identity(19)),
        Err(StoreError::AlreadyExists)
    ));
    assert!(matches!(
        NamespaceStore::open(&root, &ns, &identity(19)),
        Err(StoreError::Incompatible { .. })
    ));
    let reopened = NamespaceStore::open(&root, &ns, &identity(7)).unwrap();
    assert_eq!(reopened.meta().unwrap().commit_seq, 1);
    assert_eq!(reopened.events_after(0).unwrap().len(), 1);
}

#[test]
fn malformed_destinations_are_never_replaced_or_repaired() {
    for kind in ["empty", "garbage", "partial-schema"] {
        let temp = TempDir::new().unwrap();
        let root = root(&temp);
        let ns = namespace();
        let stage = new_stage(&root).unwrap();
        initialize(&stage, &ns, identity(7)).unwrap();
        // Occupy the destination after initialization, defeating a mere exists check.
        let destination = root.namespace_dir(&ns).unwrap();
        fs::create_dir(&destination).unwrap();
        let db = destination.join("ncm.sqlite");
        match kind {
            "garbage" => fs::write(&db, b"not sqlite").unwrap(),
            "partial-schema" => {
                let conn = Connection::open(&db).unwrap();
                create_schema(&conn).unwrap();
                conn.close().unwrap();
            }
            _ => {}
        }
        let before = fs::read(&db).ok();
        assert!(matches!(
            publish(&root, &ns, stage),
            Err(StoreError::AlreadyExists)
        ));
        assert!(matches!(
            create(&root, &ns, identity(7)),
            Err(StoreError::AlreadyExists)
        ));
        assert_eq!(
            fs::read(&db).ok(),
            before,
            "{kind} was modified by creation"
        );
        let error = NamespaceStore::open(&root, &ns, &identity(7)).unwrap_err();
        if kind == "empty" {
            assert!(matches!(error, StoreError::Missing));
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        } else {
            assert!(matches!(error, StoreError::Corrupt(_)), "{kind}: {error}");
        }
    }
}

// This helper runs only in the unit-test executable, never the production worker.
// It escrows a precise SQL/publication boundary and parks until killed.
#[test]
fn interrupted_bootstrap_child() {
    let Some(path) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = StateRoot::new(PathBuf::from(path)).unwrap();
    let stage = new_stage(&root).unwrap();
    let phase = std::env::var(CHILD_PHASE).unwrap();
    let held_connection = if phase == "schema" {
        let conn = Connection::open(stage.path().join("ncm.sqlite")).unwrap();
        configure_connection(&conn).unwrap();
        create_schema(&conn).unwrap();
        // Exact original defect boundary: committed DDL, no initial metadata.
        Some(conn)
    } else {
        assert_eq!(phase, "initialized");
        initialize(&stage, &namespace(), identity(7)).unwrap();
        None
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{READY}{}",
        serde_json::to_string(stage.path()).unwrap()
    )
    .unwrap();
    stdout.flush().unwrap();
    drop(stdout);
    // libtest may close stdin before the parent kills us. Stay at the SQL
    // boundary instead of unwinding (and closing the connection) on pipe EOF.
    let _held_connection = held_connection;
    loop {
        thread::park();
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn interrupted_first_bootstrap_leaves_retry_usable() {
    for phase in ["schema", "initialized"] {
        let temp = TempDir::new().unwrap();
        let root = root(&temp);
        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::bootstrap::tests::interrupted_bootstrap_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, root.path())
                .env(CHILD_PHASE, phase)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if let Some((_, path)) = line.split_once(READY) {
                    ready_tx
                        .send(serde_json::from_str::<PathBuf>(path).unwrap())
                        .unwrap();
                    return;
                }
            }
        });
        let stage = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("explicit bootstrap boundary");
        reader.join().unwrap();
        assert!(!NamespaceStore::exists(&root, &namespace()));
        assert_eq!(catalog_count(&root), 0);
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(9),
                "child must remain live until SIGKILL"
            );
        }
        assert!(
            stage.join("ncm.sqlite").is_file(),
            "kill must leave a real orphan"
        );
        assert_eq!(catalog_count(&root), 0, "orphan is not a live namespace");
        let mut store = create(&root, &namespace(), identity(7)).unwrap();
        assert_eq!(store.meta().unwrap(), StoreMeta::default());
        let mut mutation = store.begin_mutation().unwrap();
        mutation
            .append_event("observe", Some("retry"), "payload", "{}", 1)
            .unwrap();
        assert_eq!(mutation.commit().unwrap(), 1);
        drop(store);
        let reopened = NamespaceStore::open(&root, &namespace(), &identity(7)).unwrap();
        assert_eq!(reopened.meta().unwrap().commit_seq, 1);
        assert_eq!(
            reopened.events_after(0).unwrap()[0]
                .idempotency_key
                .as_deref(),
            Some("retry")
        );
        assert!(stage.exists(), "retry must not sweep orphan staging");
        assert_eq!(catalog_count(&root), 1);
    }
}
