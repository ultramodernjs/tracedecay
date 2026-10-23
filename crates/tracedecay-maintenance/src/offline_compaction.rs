//! Explicit, offline SQLite repacking. Never called by live maintenance.
//!
//! Preview reads an immutable, sidecar-free database and never creates files.
//! Apply requires its exact digest and nonblocking exclusive profile admission;
//! it never stops a daemon. The caller chooses a whole-database page budget.
//! A same-volume, validated copy replaces the source in one atomic rename.
//! Temporary staging is removed on returned success or failure; no old database
//! copy is retained. Publication errors leave the original or validated new
//! database at the active path, never delete that path, and report uncertainty.

use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, types::ValueRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracedecay_runtime_core::lifecycle_lease::{
    ExclusiveLeaseAttempt, try_acquire_exclusive_for_profile,
};
use tracedecay_runtime_core::storage::reject_symlink_components;

const STAGING_PREFIX: &str = ".td-offline-compact-";

#[derive(Debug, Serialize)]
pub struct OfflineCompactionPlanV1 {
    pub database: PathBuf,
    pub digest: String,
    pub bytes_before: u64,
    /// Free-page-only estimate, not a promised output size. In-page slack can
    /// make the actual copy smaller; pointer maps can make it slightly larger.
    pub expected_compacted_bytes: u64,
    pub free_page_bytes: u64,
    pub required_scratch_bytes: u64,
    pub auto_vacuum: u64,
    pub page_count: u64,
}

#[derive(Debug, Serialize)]
pub struct OfflineCompactionReceiptV1 {
    pub database: PathBuf,
    pub preview_digest: String,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub reclaimed_bytes: u64,
}

pub fn inspect_compaction_candidate_v1(
    profile_root: &Path,
    database: &Path,
    max_pages: u64,
) -> io::Result<OfflineCompactionPlanV1> {
    let database = resolve_database(profile_root, database)?;
    refuse_sidecars(&database)?;
    let connection = open_immutable(&database)?;
    let page_count = pragma(&connection, "page_count")?;
    if max_pages == 0 || page_count > max_pages {
        return Err(io::Error::other(
            "offline compaction exceeds the explicit page budget",
        ));
    }
    let page_size = pragma(&connection, "page_size")?;
    let free_page_bytes = pragma(&connection, "freelist_count")?.saturating_mul(page_size);
    let bytes_before = fs::metadata(&database)?.len();
    if bytes_before > max_pages.saturating_mul(page_size) {
        return Err(io::Error::other(
            "offline database file exceeds the explicit page budget",
        ));
    }
    let digest = source_digest(&database)?;
    Ok(OfflineCompactionPlanV1 {
        database,
        digest,
        bytes_before,
        expected_compacted_bytes: page_count
            .saturating_mul(page_size)
            .saturating_sub(free_page_bytes),
        free_page_bytes,
        // A compacted copy, private-stage VACUUM temporary, and headroom for
        // pointer-map pages. Staging stays on the database's volume.
        required_scratch_bytes: page_count
            .saturating_mul(page_size)
            .saturating_sub(free_page_bytes)
            .saturating_mul(3)
            .saturating_add(16 * 1024 * 1024),
        auto_vacuum: pragma(&connection, "auto_vacuum")?,
        page_count,
    })
}

pub fn compact_offline_v1(
    profile_root: &Path,
    database: &Path,
    digest: &str,
    max_pages: u64,
) -> io::Result<OfflineCompactionReceiptV1> {
    let profile = profile_root.canonicalize()?;
    let database = resolve_database(profile_root, database)?;
    let _lease = match try_acquire_exclusive_for_profile(&profile, "offline-compaction")
        .map_err(io::Error::other)?
    {
        ExclusiveLeaseAttempt::Acquired(lease) => lease,
        ExclusiveLeaseAttempt::Busy { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "profile is busy; stop the daemon separately before offline compaction",
            ));
        }
    };
    let plan = inspect_compaction_candidate_v1(&profile, &database, max_pages)?;
    if plan.digest != digest {
        return Err(io::Error::other(
            "offline compaction preview digest is stale",
        ));
    }
    let parent = database
        .parent()
        .ok_or_else(|| io::Error::other("database has no parent"))?;
    // The exclusive profile lease proves no other compaction is running, so any
    // remaining staging belongs to an interrupted operation.
    reclaim_interrupted_staging(parent)?;
    if tracedecay_private_fs::available_space(parent)? < plan.required_scratch_bytes {
        return Err(io::Error::other(
            "insufficient space for offline compaction",
        ));
    }
    let source = open_immutable(&database)?;
    validate_health(&source)?;
    let logical_before = logical_digest(&source)?;
    let original_metadata = fs::metadata(&database)?;
    let original_content = file_digest(&database)?;
    let operation = tempfile::Builder::new()
        .prefix(STAGING_PREFIX)
        .tempdir_in(parent)?;
    let stage = operation.path().join("compacted.db");
    // Precreate owner-private, empty output: SQLite accepts a zero-byte file.
    tracedecay_private_fs::create_private_file(&stage)?;
    source
        .execute(
            "VACUUM INTO ?1",
            [stage
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 staging path"))?],
        )
        .map_err(io::Error::other)?;
    drop(source);
    {
        let staged = Connection::open_with_flags(
            &stage,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(io::Error::other)?;
        // Legacy NONE needs pointer maps. A second explicit INTO keeps every
        // whole-database temporary on this same volume (never SQLite's ambient
        // temporary directory), and is skipped for already-incremental stores.
        if pragma(&staged, "auto_vacuum")? == 2 {
            drop(staged);
        } else {
            let incremental = operation.path().join("incremental.db");
            tracedecay_private_fs::create_private_file(&incremental)?;
            staged
                .execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
                .map_err(io::Error::other)?;
            staged
                .execute(
                    "VACUUM INTO ?1",
                    [incremental
                        .to_str()
                        .ok_or_else(|| io::Error::other("non-UTF8 staging path"))?],
                )
                .map_err(io::Error::other)?;
            drop(staged);
            fs::rename(incremental, &stage)?;
        }
        refuse_sidecars(&stage)?;
        let verified = open_immutable(&stage)?;
        validate_health(&verified)?;
        if pragma(&verified, "auto_vacuum")? != 2 || logical_digest(&verified)? != logical_before {
            return Err(io::Error::other(
                "compacted database changed schema, rows, ROWIDs or application identity",
            ));
        }
    }
    let bytes_after = fs::metadata(&stage)?.len();
    if bytes_after >= plan.bytes_before {
        return Err(io::Error::other(
            "validated compaction would not save bytes",
        ));
    }
    let permissions = fs::metadata(&database)?.permissions();
    fs::set_permissions(&stage, permissions)?;
    File::open(&stage)?.sync_all()?;
    refuse_sidecars(&database)?;
    if source_digest(&database)? != digest {
        return Err(io::Error::other("database changed while compacting"));
    }
    // Rename publishes only a fully validated, synced inode. Never link or
    // retain the old database: on either side of publication the active path
    // remains the sole active authority, including when directory sync fails.
    let publication = (|| {
        sync_directory(operation.path())?;
        inject_publish_fault("before_replace")?;
        let current_metadata = fs::symlink_metadata(&database)?;
        if current_metadata.file_type().is_symlink()
            || current_metadata.dev() != original_metadata.dev()
            || current_metadata.ino() != original_metadata.ino()
            || current_metadata.nlink() != 1
            || file_digest(&database)? != original_content
        {
            return Err(io::Error::other(
                "database identity changed before publication",
            ));
        }
        reject_symlink_components(&database, "offline database publication")?;
        refuse_sidecars(&database)?;
        fs::rename(&stage, &database)?;
        inject_publish_fault("after_replace")?;
        sync_directory(parent)?;
        inject_publish_fault("after_parent_sync")?;
        Ok(OfflineCompactionReceiptV1 {
            database: database.clone(),
            preview_digest: digest.to_owned(),
            bytes_before: plan.bytes_before,
            bytes_after,
            reclaimed_bytes: plan.bytes_before - bytes_after,
        })
    })();
    let staging = operation.path().to_path_buf();
    let cleanup = operation.close();
    // Attempt this barrier even if staging removal failed: a published inode
    // must not depend on successful cleanup to make its active name durable.
    let directory_sync = sync_directory(parent);
    let cleanup = match (cleanup, directory_sync) {
        (Err(cleanup), Err(sync)) => Err(io::Error::new(
            cleanup.kind(),
            format!("{cleanup}; database directory sync failed: {sync}"),
        )),
        (cleanup, sync) => cleanup.and(sync),
    };
    match (publication, cleanup) {
        (Ok(receipt), Ok(())) => Ok(receipt),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(io::Error::new(
            error.kind(),
            format!(
                "database published; staging cleanup failed at '{}': {error}",
                staging.display()
            ),
        )),
        (Err(error), Err(cleanup)) => Err(io::Error::new(
            error.kind(),
            format!(
                "{error}; staging cleanup failed at '{}': {cleanup}",
                staging.display()
            ),
        )),
    }
}

fn resolve_database(profile_root: &Path, database: &Path) -> io::Result<PathBuf> {
    let root = profile_root.canonicalize()?;
    // Allow the selected profile root to be an intentional alias, but no
    // symlink children or paths escaping that authority.
    let relative = database
        .strip_prefix(profile_root)
        .or_else(|_| database.strip_prefix(&root))
        .map_err(|_| io::Error::other("database is outside the selected profile"))?;
    if relative
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(io::Error::other(
            "database path must contain only normal components",
        ));
    }
    let path = root.join(relative);
    reject_symlink_components(&path, "offline database")?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::other(
            "offline database must be a single-link regular file",
        ));
    }
    Ok(path)
}

fn reclaim_interrupted_staging(parent: &Path) -> io::Result<()> {
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_bytes()
            .starts_with(STAGING_PREFIX.as_bytes())
        {
            continue;
        }
        // Never follow a planted link out of the profile.
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

fn refuse_sidecars(database: &Path) -> io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut path = database.as_os_str().to_owned();
        path.push(suffix);
        match fs::symlink_metadata(Path::new(&path)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "offline compaction requires a cleanly closed database without WAL/journal sidecars",
                ));
            }
        }
    }
    Ok(())
}

fn open_immutable(path: &Path) -> io::Result<Connection> {
    use std::fmt::Write;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        write!(&mut uri, "%{byte:02X}").map_err(io::Error::other)?;
    }
    uri.push_str("?mode=ro&immutable=1");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(io::Error::other)
}

fn pragma(connection: &Connection, name: &str) -> io::Result<u64> {
    let value = connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
        .map_err(io::Error::other)?;
    u64::try_from(value).map_err(io::Error::other)
}

fn validate_health(connection: &Connection) -> io::Result<()> {
    connection
        .execute_batch("PRAGMA ignore_check_constraints=OFF; PRAGMA cell_size_check=ON;")
        .map_err(io::Error::other)?;
    let quick_check_error =
        |error| io::Error::other(format!("offline compaction quick_check failed: {error}"));
    let mut statement = connection
        .prepare("PRAGMA quick_check")
        .map_err(quick_check_error)?;
    let checks = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(quick_check_error)?;
    let mut count = 0;
    for check in checks {
        count += 1;
        if check.map_err(quick_check_error)? != "ok" {
            return Err(io::Error::other("offline compaction quick_check failed"));
        }
    }
    if count != 1
        || connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(io::Error::other)?
            .exists([])
            .map_err(io::Error::other)?
    {
        return Err(io::Error::other(
            "offline compaction integrity validation failed",
        ));
    }
    Ok(())
}

fn file_digest(path: &Path) -> io::Result<String> {
    let mut file = tracedecay_private_fs::framed_log::open_regular_read_no_follow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}

fn source_digest(path: &Path) -> io::Result<String> {
    let before = fs::symlink_metadata(path)?;
    let bytes = file_digest(path)?;
    let after = fs::symlink_metadata(path)?;
    let stamp = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if stamp(&before) != stamp(&after) || before.nlink() != 1 {
        return Err(io::Error::other("offline database changed during preview"));
    }
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().as_bytes());
    hasher.update(format!("{:?}", stamp(&before)));
    hasher.update(bytes);
    Ok(hex_digest(&hasher.finalize()))
}

fn logical_digest(connection: &Connection) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for name in ["user_version", "application_id", "encoding"] {
        let value: String = connection
            .query_row(
                &format!("SELECT CAST({name} AS TEXT) FROM pragma_{name}"),
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        hasher.update(value.as_bytes());
    }
    hash_query(
        connection,
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
        &mut hasher,
    )?;
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .map_err(io::Error::other)?;
    let tables = tables
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(io::Error::other)?;
    for (index, table) in tables.enumerate() {
        if index >= 4096 {
            return Err(io::Error::other(
                "offline schema inventory exceeds 4096 tables",
            ));
        }
        let table = table.map_err(io::Error::other)?;
        hasher.update(table.as_bytes());
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        // Pin implicit ROWIDs too: a rewrite that renumbers load-bearing
        // associations fails validation rather than publishing silent damage.
        let without_rowid: bool = connection
            .query_row(
                "SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?1",
                [&table],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let mut columns = connection
            .prepare(&format!("PRAGMA table_xinfo({quoted})"))
            .map_err(io::Error::other)?;
        let names = columns
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(io::Error::other)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(io::Error::other)?;
        if without_rowid {
            // A WITHOUT ROWID table is its primary-key B-tree. Force that
            // scan rather than a covering secondary index, without a sorter
            // that could spill an entire store to the ambient temp volume.
            hash_query(
                connection,
                &format!("SELECT * FROM {quoted} NOT INDEXED"),
                &mut hasher,
            )?;
        } else {
            let alias = ["_rowid_", "rowid", "oid"]
                .into_iter()
                .find(|alias| !names.iter().any(|name| name.eq_ignore_ascii_case(alias)))
                .ok_or_else(|| {
                    io::Error::other(
                        "all implicit ROWID aliases are shadowed; refusing an unverifiable rewrite",
                    )
                })?;
            hash_query(
                connection,
                &format!("SELECT {alias},* FROM {quoted} ORDER BY {alias}"),
                &mut hasher,
            )?;
        }
    }
    Ok(hasher.finalize().to_vec())
}

fn hash_query(connection: &Connection, sql: &str, hasher: &mut Sha256) -> io::Result<()> {
    let mut statement = connection.prepare(sql).map_err(io::Error::other)?;
    let columns = statement.column_count();
    let mut rows = statement.query([]).map_err(io::Error::other)?;
    while let Some(row) = rows.next().map_err(io::Error::other)? {
        hasher.update(b"row");
        for index in 0..columns {
            match row.get_ref(index).map_err(io::Error::other)? {
                ValueRef::Null => hasher.update(b"null"),
                ValueRef::Integer(value) => {
                    hasher.update(b"int");
                    hasher.update(value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hasher.update(b"real");
                    hasher.update(value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) | ValueRef::Blob(value) => {
                    hasher.update(if matches!(row.get_ref(index), Ok(ValueRef::Text(_))) {
                        b"text"
                    } else {
                        b"blob"
                    });
                    hasher.update((value.len() as u64).to_le_bytes());
                    hasher.update(value);
                }
            }
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(test))]
fn inject_publish_fault(_phase: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
fn inject_publish_fault(phase: &str) -> io::Result<()> {
    if phase == "before_replace"
        && let Some(ready) = std::env::var_os("TRACEDECAY_TEST_COMPACTION_PAUSE")
    {
        fs::write(ready, b"staged and validated")?;
        loop {
            std::thread::park();
        }
    }
    if PUBLISH_FAULT.with(|fault| fault.get() == Some(phase)) {
        return Err(io::Error::other(format!(
            "injected publication failure: {phase}"
        )));
    }
    Ok(())
}

#[cfg(test)]
thread_local! { static PUBLISH_FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
mod tests;
