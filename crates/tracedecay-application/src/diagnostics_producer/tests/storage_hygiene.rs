#[cfg(windows)]
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime};

#[cfg(windows)]
use crate::diagnostics_producer::{
    TypeScriptDiagnosticsAvailabilityV1, TypeScriptProducerStateV1, TypeScriptProjectCheckV1,
    run_typescript_producer_v1, typescript_diagnostics_availability,
};
#[cfg(windows)]
use crate::diagnostics_publication::CodeIndexPublicationIdentityV1;
#[cfg(windows)]
use crate::diagnostics_store::DiagnosticsStore;
#[cfg(windows)]
use tracedecay_domain::UtcMicros;
#[cfg(windows)]
use tracedecay_domain::test_fixtures::id;
#[cfg(windows)]
use tracedecay_lsp::typescript_projects;
use tracedecay_runtime_core::native_runtime;
#[cfg(unix)]
use tracedecay_runtime_core::storage::typescript_cache::{
    BuildInfoCachePolicyV1, acquire_build_info_lease_v1, sweep_build_info_cache_v1,
};
#[cfg(unix)]
use tracedecay_runtime_core::test_executable::write_executable_script;

pub(super) fn install_native_runtime() {
    match native_runtime::install(
        native_runtime::default_builder()
            .worker_threads(2)
            .blocking_threads(1, 32),
    ) {
        Ok(_) | Err(native_runtime::InstallError::AlreadyStarted) => {}
        Err(error) => panic!("install native test runtime: {error}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn storage_hygiene_cancelled_producer_defers_eviction_until_compilers_are_reaped() {
    struct Compilers(Vec<std::path::PathBuf>);
    impl Compilers {
        fn pids(&self) -> Vec<u32> {
            self.0
                .iter()
                .filter_map(|path| std::fs::read_to_string(path).ok()?.trim().parse().ok())
                .collect()
        }

        fn any_alive(&self) -> bool {
            self.pids().into_iter().any(|pid| {
                Command::new("/bin/kill")
                    .args(["-0", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("probe fixture compiler")
                    .success()
            })
        }
    }
    impl Drop for Compilers {
        fn drop(&mut self) {
            // A failed assertion must not leave any fixture compiler behind.
            // Its native supervisor remains responsible for reaping it.
            for pid in self.pids() {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    install_native_runtime();
    let fixture = super::ProducerFixture::new();
    write_executable_script(
        &fixture.root.join("node_modules/.bin/tsc"),
        "#!/bin/sh\nprintf '{}' > \"$8\"\necho $$ > \"$2.pid\"\nexec /bin/sleep 30\n",
    )
    .expect("cancellable compiler");
    let mut compilers = Compilers(
        ["app", "lib", "broken"]
            .map(|package| {
                fixture
                    .root
                    .join(format!("packages/{package}/tsconfig.json.pid"))
            })
            .to_vec(),
    );
    let mut state = super::TypeScriptProducerStateV1::default();
    let owner = Arc::new(());
    let inherited_owner = Arc::clone(&owner);
    let mut pending = Box::pin(native_runtime::BLOCKING_WORK_OWNER.scope(
        inherited_owner,
        fixture.run("generation.cancelled", &mut state),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    while compilers.pids().len() != 3 {
        assert!(Instant::now() < deadline, "fixture compilers must start");
        tokio::select! {
            run = &mut pending => panic!("compiler unexpectedly finished: {run:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
    let policy = BuildInfoCachePolicyV1 {
        byte_budget: 1,
        ..BuildInfoCachePolicyV1::default()
    };
    let busy = sweep_build_info_cache_v1(&fixture.build_info_dir, policy, SystemTime::now(), true)
        .unwrap();
    assert_eq!(busy.bytes_before, 6);
    assert_eq!(busy.leased_bytes, 6);
    assert_eq!(busy.reclaimed_bytes, 0);
    // Cancellation abandons the async wait, not the native supervisors.
    drop(pending);
    let mut reclaimed = 0;
    loop {
        let report =
            sweep_build_info_cache_v1(&fixture.build_info_dir, policy, SystemTime::now(), true)
                .unwrap();
        reclaimed += report.reclaimed_bytes;
        // Probe after sweeping: a compiler still alive at this point was also
        // alive during eviction, avoiding a false failure if reaping raced us.
        let alive = compilers.any_alive();
        if alive {
            assert_eq!(report.reclaimed_bytes, 0, "compiler not yet reaped");
            assert_eq!(report.leased_bytes, 6);
        } else if report.leased_bytes == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cancelled compilers must be reaped"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(reclaimed, 6);
    assert_eq!(Arc::strong_count(&owner), 1, "enclosing owner released too");
    compilers.0.clear();
}

#[cfg(unix)]
#[tokio::test]
async fn storage_hygiene_compiler_supervisor_retains_owner_when_wait_is_cancelled() {
    install_native_runtime();
    let root = tempfile::tempdir().unwrap();
    let build_info = root.path().join(format!("{:064x}.tsbuildinfo", 1));
    let ready = root.path().join("ready");
    let compiler = root.path().join("tsc");
    let tsconfig = root.path().join("tsconfig.json");
    std::fs::write(&tsconfig, "{}").unwrap();
    write_executable_script(
        &compiler,
        "#!/bin/sh\nprintf ready > ready\nexec /bin/sleep 30\n",
    )
    .unwrap();
    let lease = Arc::new(acquire_build_info_lease_v1(&build_info).unwrap());
    let retained = Arc::downgrade(&lease);
    let mut pending = Box::pin(native_runtime::BLOCKING_WORK_OWNER.scope(
        lease as Arc<dyn Send + Sync>,
        tracedecay_lsp::run_typescript_compiler(
            &compiler,
            root.path(),
            &tsconfig,
            Some(&build_info),
        ),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "compiler must start");
        tokio::select! {
            run = &mut pending => panic!("compiler unexpectedly finished: {run:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
    // Deterministic ownership assertion, independent of how quickly kill/wait
    // runs after cancellation: the sleeping compiler has not ended yet.
    let owners_while_running = retained.strong_count();
    drop(pending);
    while retained.strong_count() != 0 {
        assert!(
            Instant::now() < deadline,
            "cancelled supervisor must release its owner"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        owners_while_running, 2,
        "async scope and blocking supervisor must each own the lease"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn storage_hygiene_producer_rechecks_existing_caches_and_sweeps_retired_entries() {
    install_native_runtime();
    let fixture = super::ProducerFixture::new();
    std::fs::create_dir_all(&fixture.build_info_dir).unwrap();
    let retired = fixture
        .build_info_dir
        .join(format!("{:064x}.tsbuildinfo", 1));
    std::fs::write(&retired, "retired compiler cache").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&retired)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    for generation in ["generation.cache.1", "generation.cache.2"] {
        let mut state = super::TypeScriptProducerStateV1::default();
        assert_eq!(
            fixture.run(generation, &mut state).await,
            super::published(generation, 3, 0)
        );
        assert_eq!(fixture.checked(), ["app", "broken", "lib"]);
        assert!(!retired.exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn storage_hygiene_producer_without_compilers_still_sweeps_retired_entries() {
    install_native_runtime();
    let fixture = super::ProducerFixture::new();
    std::fs::create_dir_all(&fixture.build_info_dir).unwrap();
    let retired = fixture
        .build_info_dir
        .join(format!("{:064x}.tsbuildinfo", 1));
    std::fs::write(&retired, "retired compiler cache").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&retired)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    let store = crate::diagnostics_store::DiagnosticsStore::new_runtime(&fixture.conn);
    let run = super::run_typescript_producer_v1(
        &fixture.root,
        &[],
        &fixture.identity("generation.no.compilers"),
        &store,
        &fixture.build_info_dir,
        &mut super::TypeScriptProducerStateV1::default(),
        tracedecay_domain::UtcMicros(1_700_000_000_000_000),
    )
    .await;
    assert!(matches!(
        run,
        super::CompilerProducerRunV1::CompilerFailed { .. }
    ));
    assert!(!retired.exists());
}

#[cfg(windows)]
#[tokio::test]
async fn storage_hygiene_windows_producer_rechecks_existing_cache() {
    install_native_runtime();
    let temp = tempfile::tempdir().expect("fixture");
    let root = temp.path().join("project");
    let bin = root.join("node_modules/.bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(root.join("tsconfig.json"), "{}").unwrap();
    std::fs::write(root.join("index.ts"), "export const value = 1;\n").unwrap();
    std::fs::write(
        bin.join("tsc.cmd"),
        "@echo off\r\n>> \"%~dp0calls.log\" echo checked\r\n> \"%~8\" echo {\"fileNames\":[]}\r\nexit /b 0\r\n",
    )
    .unwrap();
    let conn = tracedecay_runtime_core::db::engine::TestConnection::open(
        &temp.path().join("diagnostics.db"),
    );
    let store = DiagnosticsStore::new_runtime(&conn);
    let projects = typescript_projects(&root);
    assert_eq!(projects.len(), 1);
    let build_info_dir = temp.path().join("store/typescript-build-info");
    for generation in ["generation.windows.1", "generation.windows.2"] {
        let identity = CodeIndexPublicationIdentityV1::new(
            id(generation),
            id("repository.fixture"),
            Some(id("worktree.fixture")),
            Some(id("ref.main")),
            None,
            [(
                "index.ts".to_owned(),
                id("file.index"),
                tracedecay_code_index::intake::content_digest(b"export const value = 1;\n"),
            )],
        );
        // A new state requires a real check on both runs, not result reuse.
        run_typescript_producer_v1(
            &root,
            &projects,
            &identity,
            &store,
            &build_info_dir,
            &mut TypeScriptProducerStateV1::default(),
            UtcMicros(1_700_000_000_000_000),
        )
        .await;
        assert!(matches!(
            typescript_diagnostics_availability(&root, Some(Path::new("index.ts"))),
            TypeScriptDiagnosticsAvailabilityV1::Configured {
                check: Some(TypeScriptProjectCheckV1::Checked),
                ..
            }
        ));
    }
    assert_eq!(
        std::fs::read_to_string(bin.join("calls.log"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}
