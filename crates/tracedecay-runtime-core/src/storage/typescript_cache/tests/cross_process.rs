use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use super::{
    BuildInfoCachePolicyV1, acquire_build_info_lease_v1, cache, sweep_build_info_cache_v1,
};

const CHILD_DIRECTORY: &str = "TRACEDECAY_CACHE_LEASE_TEST_CHILD_DIRECTORY";

#[test]
#[ignore = "child helper; invoked only by the cross-process lease regression"]
fn storage_hygiene_cache_lease_child() {
    let directory = std::env::var_os(CHILD_DIRECTORY).expect("parent supplies isolated directory");
    let path = std::path::Path::new(&directory).join(format!("{:064x}.tsbuildinfo", 1));
    let _lease = acquire_build_info_lease_v1(&path).unwrap();
    println!("__lease_ready__");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0_u8]).unwrap();
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn storage_hygiene_other_process_lease_defers_nonzero_budget_eviction() {
    let root = tempfile::tempdir().unwrap();
    let first = cache(root.path(), 1, 80);
    let second = cache(root.path(), 2, 80);
    let helper = concat!(module_path!(), "::storage_hygiene_cache_lease_child");
    // libtest names omit the crate prefix that module_path! includes.
    let helper = helper.split_once("::").unwrap().1;
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", helper, "--ignored", "--nocapture"])
            .env(CHILD_DIRECTORY, root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (ready, received) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.unwrap().contains("__lease_ready__") {
                let _ = ready.send(());
            }
        }
    });
    received
        .recv_timeout(Duration::from_secs(10))
        .expect("child must hold a real shared lease");
    let policy = BuildInfoCachePolicyV1 {
        byte_budget: 100,
        ..BuildInfoCachePolicyV1::default()
    };
    for apply in [false, true] {
        let report =
            sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), apply).unwrap();
        assert!(report.inventory_complete);
        assert_eq!(report.bytes_before, 160);
        assert_eq!(report.leased_bytes, 160);
        assert_eq!(report.reclaimed_bytes, 0);
        assert_eq!(report.candidates.len(), 0);
        assert!(first.exists() && second.exists());
    }
    child.0.stdin.take().unwrap().write_all(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "child must release its lease");
        std::thread::sleep(Duration::from_millis(1));
    }
    reader.join().unwrap();
    let report = sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), true).unwrap();
    assert!(report.inventory_complete);
    assert_eq!(report.leased_bytes, 0);
    assert_eq!(report.reclaimed_bytes, 80);
    assert_eq!(report.bytes_after, 80);
    assert_eq!(report.candidates.len(), 1);
    assert_ne!(first.exists(), second.exists());
}
