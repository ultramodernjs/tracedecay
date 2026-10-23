//! Bounded retention for compiler-owned TypeScript incremental state.

use std::io;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_WRITE_ATTRIBUTES,
};

#[derive(Debug, Clone, Copy)]
pub struct BuildInfoCachePolicyV1 {
    pub unused_ttl: Duration,
    pub byte_budget: u64,
    /// Fail closed if a directory is larger than one bounded inventory.
    pub max_scan_entries: usize,
}

impl Default for BuildInfoCachePolicyV1 {
    fn default() -> Self {
        Self {
            unused_ttl: Duration::from_hours(30 * 24),
            byte_budget: 128 * 1024 * 1024,
            max_scan_entries: 4096,
        }
    }
}

#[derive(Debug, Default)]
pub struct BuildInfoCacheSweepV1 {
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub reclaimed_bytes: u64,
    pub leased_bytes: u64,
    pub candidates: Vec<PathBuf>,
    pub inventory_complete: bool,
}

const LEASE_FILENAME: &str = ".typescript-build-info.lock";

/// Shared by all compilers using this directory. Eviction takes the exclusive
/// side of the same fixed lease, so it never unlinks compiler state in use and
/// never leaves one lock inode behind for every retired worktree.
pub fn acquire_build_info_lease_v1(path: &Path) -> io::Result<tracedecay_private_fs::FileLease> {
    if !recognized(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unrecognized build-info filename",
        ));
    }
    let directory = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "build-info has no directory")
    })?;
    let directory = cache_directory(directory)?;
    let path = directory.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("build-info has no filename"))?,
    );
    let file = open_lease(&directory, true)?
        .ok_or_else(|| io::Error::other("cache lease was not created"))?;
    file.lock_shared()?;
    let lease = tracedecay_private_fs::FileLease::held(file, "typescript.cache.compiler");
    match open_for_recency(&path) {
        Ok(file) => file.set_modified(SystemTime::now())?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(lease)
}

#[cfg(not(windows))]
fn open_for_recency(path: &Path) -> io::Result<std::fs::File> {
    tracedecay_private_fs::framed_log::open_regular_read_no_follow(path)
}

#[cfg(windows)]
fn open_for_recency(path: &Path) -> io::Result<std::fs::File> {
    // SetFileTime needs FILE_WRITE_ATTRIBUTES, not a read-only handle. Open
    // without creation/truncation or reparse traversal, and validate that exact
    // handle before updating its timestamps (never reopen by pathname).
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build-info is not a regular file",
        ));
    }
    Ok(file)
}

fn cache_directory(directory: &Path) -> io::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TypeScript cache must be a real directory",
        ));
    }
    // Profile roots may intentionally use a filesystem alias (as does /var
    // on macOS). Pin that root before checking any cache-owned child paths.
    directory.canonicalize()
}

fn open_lease(directory: &Path, create: bool) -> io::Result<Option<std::fs::File>> {
    let path = directory.join(LEASE_FILENAME);
    match tracedecay_private_fs::open_private_file(&path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match tracedecay_private_fs::create_private_file(&path) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    tracedecay_private_fs::open_private_file(&path).map(Some)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn recognized(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".tsbuildinfo"))
        .is_some_and(|stem| {
            stem.len() == 64
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Preview is read-only, including when no cache/lease exists. Apply uses a
/// bounded complete inventory; an oversized directory is reported incomplete
/// and left untouched instead of claiming a budget from a partial sample.
pub fn sweep_build_info_cache_v1(
    directory: &Path,
    policy: BuildInfoCachePolicyV1,
    now: SystemTime,
    apply: bool,
) -> io::Result<BuildInfoCacheSweepV1> {
    let directory = match cache_directory(directory) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BuildInfoCacheSweepV1 {
                inventory_complete: true,
                ..BuildInfoCacheSweepV1::default()
            });
        }
        Err(error) => return Err(error),
    };
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BuildInfoCacheSweepV1 {
                inventory_complete: true,
                ..BuildInfoCacheSweepV1::default()
            });
        }
        Err(error) => return Err(error),
    };
    let mut result = BuildInfoCacheSweepV1::default();
    let lock = open_lease(&directory, apply)?;
    let mut busy = false;
    let _lease = match lock {
        Some(file) => match file.try_lock().map_err(io::Error::from) {
            Ok(()) => Some(tracedecay_private_fs::FileLease::held(
                file,
                "typescript.cache.sweep",
            )),
            Err(error) if crate::db::is_lock_contended(&error) => {
                busy = true;
                None
            }
            Err(error) => return Err(error),
        },
        None => None,
    };
    let mut inventory = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= policy.max_scan_entries {
            result.bytes_after = result.bytes_before;
            return Ok(result);
        }
        let entry = entry?;
        let path = entry.path();
        if !recognized(&path) || !entry.file_type()?.is_file() {
            continue;
        }
        let file = tracedecay_private_fs::framed_log::open_regular_read_no_follow(&path)?;
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                continue;
            }
        }
        result.bytes_before = result.bytes_before.saturating_add(metadata.len());
        inventory.push((metadata.modified()?, path, metadata.len()));
    }
    result.inventory_complete = true;
    result.bytes_after = result.bytes_before;
    if busy {
        result.leased_bytes = result.bytes_before;
        return Ok(result);
    }
    inventory.sort();
    let mut projected_bytes = result.bytes_before;
    for (modified, path, bytes) in inventory {
        let expired = now
            .duration_since(modified)
            .is_ok_and(|age| age >= policy.unused_ttl);
        if !expired && projected_bytes <= policy.byte_budget {
            continue;
        }
        result.candidates.push(path.clone());
        projected_bytes = projected_bytes.saturating_sub(bytes);
        if apply {
            super::reject_symlink_components(&path, "TypeScript cache file")?;
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() != bytes || metadata.modified()? != modified {
                return Err(io::Error::other("TypeScript cache changed during eviction"));
            }
            std::fs::remove_file(&path)?;
            result.reclaimed_bytes = result.reclaimed_bytes.saturating_add(bytes);
            result.bytes_after = result.bytes_after.saturating_sub(bytes);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    mod cross_process;

    use super::*;

    fn cache(directory: &Path, index: u64, size: usize) -> PathBuf {
        let path = directory.join(format!("{index:064x}.tsbuildinfo"));
        std::fs::write(&path, vec![b'x'; size]).unwrap();
        path
    }

    #[test]
    fn storage_hygiene_existing_cache_can_be_leased_repeatedly_without_truncation() {
        let root = tempfile::tempdir().unwrap();
        let path = cache(root.path(), 1, 80);
        for _ in 0..2 {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH)
                .unwrap();
            let lease = acquire_build_info_lease_v1(&path).unwrap();
            assert!(std::fs::metadata(&path).unwrap().modified().unwrap() > SystemTime::UNIX_EPOCH);
            assert_eq!(std::fs::read(&path).unwrap(), vec![b'x'; 80]);
            drop(lease);
        }
    }

    #[test]
    fn storage_hygiene_cache_compiler_lease_defers_eviction_until_release() {
        let root = tempfile::tempdir().unwrap();
        let path = cache(root.path(), 1, 80);
        let lease = acquire_build_info_lease_v1(&path).unwrap();
        let policy = BuildInfoCachePolicyV1 {
            byte_budget: 40,
            ..BuildInfoCachePolicyV1::default()
        };
        let busy = sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), true).unwrap();
        assert_eq!(busy.leased_bytes, 80);
        assert_eq!(busy.reclaimed_bytes, 0);
        assert!(path.exists());
        drop(lease);
        let reclaimed =
            sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), true).unwrap();
        assert_eq!(reclaimed.reclaimed_bytes, 80);
        assert!(!path.exists());
    }

    #[test]
    fn storage_hygiene_fresh_cache_budget_orders_eviction_and_stops_at_budget() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        for (budget, remaining, reclaimed) in [(100, 100, 50), (90, 60, 90)] {
            let root = tempfile::tempdir().unwrap();
            // Filename order deliberately disagrees with age order. Every
            // entry is fresh: a TTL-only sweeper cannot satisfy this test.
            let newest = cache(root.path(), 1, 60);
            let middle = cache(root.path(), 2, 40);
            let oldest = cache(root.path(), 3, 50);
            for (path, age) in [(&newest, 1), (&middle, 2), (&oldest, 3)] {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_modified(now - Duration::from_hours(age))
                    .unwrap();
            }
            let policy = BuildInfoCachePolicyV1 {
                byte_budget: budget,
                ..BuildInfoCachePolicyV1::default()
            };
            let expected = if budget == 100 {
                vec![oldest.canonicalize().unwrap()]
            } else {
                vec![
                    oldest.canonicalize().unwrap(),
                    middle.canonicalize().unwrap(),
                ]
            };
            let preview = sweep_build_info_cache_v1(root.path(), policy, now, false).unwrap();
            assert!(preview.inventory_complete);
            assert_eq!(preview.bytes_before, 150);
            assert_eq!(preview.bytes_after, 150);
            assert_eq!(preview.reclaimed_bytes, 0);
            assert_eq!(preview.candidates, expected);
            assert!(newest.exists() && middle.exists() && oldest.exists());

            let applied = sweep_build_info_cache_v1(root.path(), policy, now, true).unwrap();
            assert!(applied.inventory_complete);
            assert_eq!(applied.candidates, expected);
            assert_eq!(applied.bytes_before, 150);
            assert_eq!(applied.bytes_after, remaining);
            assert_eq!(applied.reclaimed_bytes, reclaimed);
            assert!(newest.exists());
            assert_eq!(middle.exists(), budget == 100);
            assert!(!oldest.exists());
            let settled = sweep_build_info_cache_v1(root.path(), policy, now, true).unwrap();
            assert_eq!(settled.candidates.len(), 0);
            assert_eq!(settled.reclaimed_bytes, 0);
            assert_eq!(settled.bytes_after, remaining);
        }
    }

    #[test]
    fn storage_hygiene_preview_does_not_create_a_lease() {
        let root = tempfile::tempdir().unwrap();
        cache(root.path(), 1, 80);
        sweep_build_info_cache_v1(
            root.path(),
            BuildInfoCachePolicyV1::default(),
            SystemTime::now(),
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn storage_hygiene_ttl_reclaims_expired_cache_without_budget_pressure() {
        let root = tempfile::tempdir().unwrap();
        let old = cache(root.path(), 1, 80);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH)
            .unwrap();
        let result = sweep_build_info_cache_v1(
            root.path(),
            BuildInfoCachePolicyV1::default(),
            SystemTime::now(),
            true,
        )
        .unwrap();
        assert_eq!(result.reclaimed_bytes, 80);
        assert!(!old.exists());
    }

    #[test]
    fn storage_hygiene_incomplete_inventory_never_claims_a_byte_bound() {
        let root = tempfile::tempdir().unwrap();
        let first = cache(root.path(), 1, 80);
        let second = cache(root.path(), 2, 80);
        let policy = BuildInfoCachePolicyV1 {
            byte_budget: 1,
            max_scan_entries: 1,
            ..BuildInfoCachePolicyV1::default()
        };
        let result =
            sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), true).unwrap();
        assert!(!result.inventory_complete);
        assert!(first.exists() && second.exists());
    }

    #[cfg(unix)]
    #[test]
    fn storage_hygiene_cache_sweep_never_follows_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let external = root.path().join("unique");
        std::fs::write(&external, "not disposable").unwrap();
        let cache_dir = root.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        std::os::unix::fs::symlink(&external, cache_dir.join(format!("{:064x}.tsbuildinfo", 1)))
            .unwrap();
        let policy = BuildInfoCachePolicyV1 {
            byte_budget: 0,
            ..BuildInfoCachePolicyV1::default()
        };
        let result =
            sweep_build_info_cache_v1(&cache_dir, policy, SystemTime::now(), true).unwrap();
        assert_eq!(result.reclaimed_bytes, 0);
        assert_eq!(
            std::fs::read_to_string(&external).unwrap(),
            "not disposable"
        );
    }

    #[test]
    fn storage_hygiene_cache_budget_preview_and_apply_preserve_unknown_files() {
        let root = tempfile::tempdir().unwrap();
        let old = cache(root.path(), 1, 80);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_hours(1))
            .unwrap();
        let new = cache(root.path(), 2, 80);
        let unknown = root.path().join("owner-notes.txt");
        std::fs::write(&unknown, "not disposable").unwrap();
        let policy = BuildInfoCachePolicyV1 {
            byte_budget: 100,
            ..BuildInfoCachePolicyV1::default()
        };
        let preview =
            sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), false).unwrap();
        assert_eq!(preview.candidates, vec![old.canonicalize().unwrap()]);
        assert_eq!(preview.reclaimed_bytes, 0);
        assert!(old.exists());
        let applied =
            sweep_build_info_cache_v1(root.path(), policy, SystemTime::now(), true).unwrap();
        assert_eq!(applied.reclaimed_bytes, 80);
        assert_eq!(applied.bytes_after, 80);
        assert!(!old.exists());
        assert!(new.exists());
        assert!(unknown.exists());
    }
}
