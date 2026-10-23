//! Resumable administrative segment marking. The ordinary retention planner
//! keeps its strict semantic census; this continuation conservatively marks
//! *every* tagged SHA-256 in each authenticated manifest, including escaped
//! JSON strings. That superset can retain extra bytes, never omit a segment
//! reference. No deletion is permitted until every root has been fully hashed.
//!
//! Progress is disposable process memory, not deletion authority on disk. All
//! cooperating manifest writers invalidate it before mutation under the shared
//! segment lock. Root identity and replay-pool changes invalidate it too. A
//! restart, eviction or invalidation simply starts another bounded mark.

use std::fs::{Metadata, ReadDir};
use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex, OnceLock};

use super::generation_transactions::metadata_identity_matches;
use super::*;

pub(super) const EPOCH_FILE: &str = ".code-generation-segment-census-epoch-v1";
const MAX_STEPS: usize = 32;
const MAX_READ_BYTES: usize = 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const MAX_CENSUSES: usize = 4;
const MAX_MARKS: usize = 1_000_000;

type CensusKey = (PathBuf, PathBuf);
type CachedCensus = (Instant, Arc<Mutex<Census>>);
static CENSUSES: OnceLock<Mutex<BTreeMap<CensusKey, CachedCensus>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static IO_OBSERVATION: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
pub(super) fn take_io_observation() -> (usize, usize) {
    IO_OBSERVATION.with(|observation| observation.replace((0, 0)))
}

pub(super) fn invalidate(project_root: &Path) -> Result<(), CodeGenerationRetentionErrorV1> {
    // Stores that have never started an administrative census need no marker
    // and pay no write or sync cost on their ordinary publication path.
    match std::fs::symlink_metadata(project_root.join(EPOCH_FILE)) {
        Ok(_) => replace_epoch(project_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage(error)),
    }
}

fn ensure_epoch(project_root: &Path) -> Result<(), CodeGenerationRetentionErrorV1> {
    match std::fs::symlink_metadata(project_root.join(EPOCH_FILE)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => replace_epoch(project_root),
        Err(error) => Err(storage(error)),
    }
}

fn replace_epoch(project_root: &Path) -> Result<(), CodeGenerationRetentionErrorV1> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(storage)?
        .as_nanos();
    let token = format!(
        "{}:{now}:{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    // This need not survive a crash: no in-memory census survives one either.
    // Atomic replacement also makes concurrent shared-lock writers safe.
    atomic_write(
        &project_root.join(EPOCH_FILE),
        "segment-census-invalidation",
        token.as_bytes(),
        DirectorySyncPolicy::Strict,
    )
    .map_err(storage)
}

#[derive(Clone)]
struct Roots {
    epoch: Vec<u8>,
    project: Metadata,
    store: Metadata,
    pool: Option<Metadata>,
}

impl Roots {
    fn read(store: &Path, pool: &Path) -> Result<Self, CodeGenerationRetentionErrorV1> {
        let project = generation_segment_project_root(store);
        let mut epoch = Vec::new();
        match File::open(project.join(EPOCH_FILE)) {
            Ok(file) => {
                file.take(256).read_to_end(&mut epoch).map_err(storage)?;
                if epoch.len() == 256 {
                    return Err(unsafe_state("segment census epoch exceeds its bound"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage(error)),
        }
        let pool = match std::fs::symlink_metadata(pool) {
            Ok(metadata) if metadata.is_dir() => Some(metadata),
            Ok(_) => return Err(unsafe_state("replay pool is not a directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(storage(error)),
        };
        Ok(Self {
            epoch,
            project: std::fs::symlink_metadata(project).map_err(storage)?,
            store: std::fs::symlink_metadata(store).map_err(storage)?,
            pool,
        })
    }

    fn matches(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && metadata_identity_matches(&self.project, &other.project)
            && metadata_identity_matches(&self.store, &other.store)
            && match (&self.pool, &other.pool) {
                (Some(left), Some(right)) => metadata_identity_matches(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

#[derive(Clone, Copy)]
enum DirectoryKind {
    Scopes,
    ScopeStages,
    ManifestStages,
    Manifests { pool: bool },
}

struct Directory {
    entries: ReadDir,
    kind: DirectoryKind,
}

struct Manifest {
    path: PathBuf,
    offset: u64,
    admitted: Metadata,
    expected_digest: String,
    hasher: Sha256,
    scanner: DigestScanner,
}

struct Census {
    roots: Roots,
    directories: Vec<Directory>,
    manifest: Option<Manifest>,
    live: BTreeSet<String>,
    retired: Vec<PathBuf>,
    segments: Option<ReadDir>,
    marking: bool,
}

fn unsafe_state(message: impl Into<String>) -> CodeGenerationRetentionErrorV1 {
    CodeGenerationRetentionErrorV1::UnsafeState(message.into())
}

impl Census {
    fn new(
        store: &Path,
        pool: &Path,
        roots: Roots,
    ) -> Result<Self, CodeGenerationRetentionErrorV1> {
        let mut census = Self {
            roots,
            directories: Vec::new(),
            manifest: None,
            live: BTreeSet::new(),
            retired: Vec::new(),
            segments: None,
            marking: true,
        };
        census.push(pool, DirectoryKind::Manifests { pool: true })?;
        if shares_project_generation_segments(store) {
            let project = generation_segment_project_root(store);
            census.push(
                &project.join(SCOPE_RETENTION_QUARANTINE_DIRECTORY),
                DirectoryKind::ScopeStages,
            )?;
            census.push(project, DirectoryKind::Scopes)?;
        } else {
            census.push_scope(store)?;
        }
        Ok(census)
    }

    fn push(
        &mut self,
        root: &Path,
        kind: DirectoryKind,
    ) -> Result<(), CodeGenerationRetentionErrorV1> {
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(unsafe_state(format!(
                    "segment census root '{}' is not a directory",
                    root.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(storage(error)),
        }
        self.directories.push(Directory {
            entries: std::fs::read_dir(root).map_err(storage)?,
            kind,
        });
        Ok(())
    }

    fn push_scope(&mut self, root: &Path) -> Result<(), CodeGenerationRetentionErrorV1> {
        self.push(
            &root.join(QUARANTINE_DIRECTORY),
            DirectoryKind::ManifestStages,
        )?;
        self.push(
            &root.join(GENERATIONS_DIRECTORY),
            DirectoryKind::Manifests { pool: false },
        )
    }

    fn observe_entry(
        &mut self,
        entry: std::fs::DirEntry,
        kind: DirectoryKind,
    ) -> Result<(), CodeGenerationRetentionErrorV1> {
        #[cfg(test)]
        IO_OBSERVATION.with(|observation| {
            let (entries, bytes) = observation.get();
            observation.set((entries + 1, bytes));
        });
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| unsafe_state("segment census entry has no UTF-8 name"))?;
        if !matches!(kind, DirectoryKind::Manifests { .. })
            && !entry.file_type().map_err(storage)?.is_dir()
        {
            return Ok(());
        }
        match kind {
            DirectoryKind::Scopes if is_code_index_scope_hash(name) => self.push_scope(&path),
            DirectoryKind::ScopeStages => self.push(&path, DirectoryKind::Scopes),
            DirectoryKind::ManifestStages => {
                self.push(&path, DirectoryKind::Manifests { pool: false })
            }
            DirectoryKind::Scopes => Ok(()),
            DirectoryKind::Manifests { pool } => {
                if pool && name == STORE_LOCK_FILE {
                    return Ok(());
                }
                if !pool && is_retired_read_bundle_file(name) {
                    if self.retired.len() == MAX_MARKS {
                        return Err(unsafe_state(
                            "segment census exceeds its retired-file bound",
                        ));
                    }
                    self.retired.push(path);
                    return Ok(());
                }
                let digest = if pool {
                    Some(replay_generation_file_digest(name).ok_or_else(|| {
                        unsafe_state(format!(
                            "unrecognized replay pool entry '{}'",
                            path.display()
                        ))
                    })?)
                } else {
                    generation_file_digest(name)
                };
                let Some(digest) = digest else {
                    return Ok(());
                };
                let admitted = std::fs::symlink_metadata(&path).map_err(deferred_if_absent)?;
                if !admitted.is_file() {
                    return Err(unsafe_state("generation manifest is not a regular file"));
                }
                self.manifest = Some(Manifest {
                    path,
                    offset: 0,
                    admitted,
                    expected_digest: digest.to_owned(),
                    hasher: Sha256::new(),
                    scanner: DigestScanner::default(),
                });
                Ok(())
            }
        }
    }

    fn advance(
        &mut self,
        store: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, CodeGenerationRetentionErrorV1> {
        let mut bytes_left = MAX_READ_BYTES;
        let mut buffer = [0_u8; READ_CHUNK];
        let mut deleted = false;
        let segments_root = code_generation_segments_root(store);
        for _ in 0..MAX_STEPS {
            if is_cancelled() {
                if deleted {
                    sync_directory(&segments_root)?;
                }
                return Err(CodeGenerationRetentionErrorV1::Cancelled);
            }
            if let Some(manifest) = &mut self.manifest {
                if bytes_left == 0 {
                    return Ok(true);
                }
                // Never pin a multi-GiB retired inode between calls. Reopen
                // the exact immutable file and resume from its checked offset.
                let mut file = File::open(&manifest.path).map_err(deferred_if_absent)?;
                if !path_still_names_open_file(&manifest.path, &file, &manifest.admitted)? {
                    return Err(unsafe_state(
                        "generation manifest changed during bounded marking",
                    ));
                }
                file.seek(SeekFrom::Start(manifest.offset))
                    .map_err(storage)?;
                let length = file
                    .read(&mut buffer[..READ_CHUNK.min(bytes_left)])
                    .map_err(storage)?;
                manifest.offset = manifest
                    .offset
                    .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
                #[cfg(test)]
                IO_OBSERVATION.with(|observation| {
                    let (entries, bytes) = observation.get();
                    observation.set((entries, bytes + length));
                });
                if length > 0 {
                    bytes_left -= length;
                    manifest.hasher.update(&buffer[..length]);
                    // Partial marks are conservative, never authorization:
                    // the sweep phase remains fenced until *all* hashes pass.
                    // Merge as bytes arrive, not in an unbounded EOF step.
                    for byte in &buffer[..length] {
                        manifest.scanner.feed(*byte, &mut self.live)?;
                    }
                    if self.live.len() > MAX_MARKS {
                        return Err(unsafe_state(
                            "segment census exceeds its in-memory mark bound",
                        ));
                    }
                    continue;
                }
                if !manifest.scanner.complete()
                    || encode_lowercase_hex(&manifest.hasher.clone().finalize())
                        != manifest.expected_digest
                    || !path_still_names_open_file(&manifest.path, &file, &manifest.admitted)?
                {
                    return Err(unsafe_state(format!(
                        "generation manifest '{}' does not match its complete content address",
                        manifest.path.display()
                    )));
                }
                self.manifest = None;
                continue;
            }
            if self.marking {
                if let Some(directory) = self.directories.last_mut() {
                    let kind = directory.kind;
                    match directory.entries.next() {
                        Some(entry) => self.observe_entry(entry.map_err(storage)?, kind)?,
                        None => {
                            self.directories.pop();
                        }
                    }
                    continue;
                }
                self.marking = false;
                self.segments = match std::fs::read_dir(&segments_root) {
                    Ok(entries) => Some(entries),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(storage(error)),
                };
            }
            if let Some(path) = self.retired.pop() {
                remove_regular_file(&path)?;
                if let Some(parent) = path.parent() {
                    sync_directory(parent)?;
                }
                continue;
            }
            let Some(entries) = &mut self.segments else {
                return Ok(false);
            };
            let Some(entry) = entries.next() else {
                if deleted {
                    sync_directory(&segments_root)?;
                }
                return Ok(false);
            };
            #[cfg(test)]
            IO_OBSERVATION.with(|observation| {
                let (entries, bytes) = observation.get();
                observation.set((entries + 1, bytes));
            });
            let path = entry.map_err(storage)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let digest = name
                .strip_prefix("segment-")
                .and_then(|name| name.strip_suffix(".json"))
                .filter(|digest| is_lowercase_hex(digest, 64))
                .map(|digest| format!("sha256:{digest}"))
                .or_else(|| is_retired_read_bundle_file(name).then(|| name.to_owned()));
            if digest.is_some_and(|digest| !self.live.contains(&digest)) {
                remove_regular_file(&path)?;
                deleted = true;
            }
        }
        if deleted {
            sync_directory(&segments_root)?;
        }
        Ok(true)
    }
}

fn remove_regular_file(path: &Path) -> Result<(), CodeGenerationRetentionErrorV1> {
    if !path
        .symlink_metadata()
        .map_err(deferred_if_absent)?
        .is_file()
    {
        return Err(unsafe_state(format!(
            "segment census candidate '{}' is not a regular file",
            path.display()
        )));
    }
    std::fs::remove_file(path).map_err(storage)
}

/// A streaming conservative projection, not a JSON authorization parser. Every
/// possible `ManifestDigest` is a tagged lower-case SHA-256 string. Decode JSON
/// escapes before scanning, across arbitrary read boundaries, and overmark any
/// unrelated digest too. The full raw-byte hash remains the authority fence.
#[derive(Default)]
struct DigestScanner {
    matched: usize,
    digest: Vec<u8>,
    escape: bool,
    unicode: Option<(u16, u8)>,
}

impl DigestScanner {
    fn feed(
        &mut self,
        byte: u8,
        marks: &mut BTreeSet<String>,
    ) -> Result<(), CodeGenerationRetentionErrorV1> {
        if let Some((value, digits)) = self.unicode {
            let digit = char::from(byte)
                .to_digit(16)
                .ok_or_else(|| unsafe_state("invalid manifest Unicode escape"))?;
            let value = (value << 4) | u16::try_from(digit).map_err(storage)?;
            if digits == 3 {
                self.unicode = None;
                self.scan(u8::try_from(value).unwrap_or(0), marks);
            } else {
                self.unicode = Some((value, digits + 1));
            }
        } else if self.escape {
            self.escape = false;
            if byte == b'u' {
                self.unicode = Some((0, 0));
            } else {
                // Non-Unicode JSON escapes cannot contribute a hex digit or
                // the tag. A decoded backslash must not escape the next byte.
                self.scan(0, marks);
            }
        } else if byte == b'\\' {
            self.escape = true;
        } else {
            self.scan(byte, marks);
        }
        Ok(())
    }

    fn scan(&mut self, byte: u8, marks: &mut BTreeSet<String>) {
        const PREFIX: &[u8] = b"sha256:";
        if self.matched == PREFIX.len() {
            if byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) {
                self.digest.push(byte);
                if self.digest.len() == 64 {
                    marks.insert(format!("sha256:{}", String::from_utf8_lossy(&self.digest)));
                    self.digest.clear();
                    self.matched = 0;
                }
                return;
            }
            self.digest.clear();
            self.matched = 0;
        }
        if byte == PREFIX[self.matched] {
            self.matched += 1;
        } else {
            self.matched = usize::from(byte == PREFIX[0]);
        }
    }

    fn complete(&self) -> bool {
        !self.escape && self.unicode.is_none()
    }
}

pub(super) fn sweep(
    store: &Path,
    pool: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodeGenerationRetentionErrorV1> {
    let key = (
        std::fs::canonicalize(store).map_err(storage)?,
        pool.to_path_buf(),
    );
    ensure_epoch(generation_segment_project_root(&key.0))?;
    let roots = Roots::read(&key.0, pool)?;
    let cache = CENSUSES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let census = {
        // This map lock never covers a directory traversal, hash or unlink:
        // unrelated projects must not turn a bounded census into busy errors.
        let mut censuses = cache
            .lock()
            .map_err(|_| unsafe_state("segment census cache is poisoned"))?;
        if !censuses.contains_key(&key) {
            if censuses.len() == MAX_CENSUSES {
                let oldest = censuses
                    .iter()
                    .min_by_key(|(_, (last_used, _))| last_used)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    censuses.remove(&oldest);
                }
            }
            censuses.insert(
                key.clone(),
                (
                    Instant::now(),
                    Arc::new(Mutex::new(Census::new(&key.0, pool, roots.clone())?)),
                ),
            );
        }
        let (last_used, census) = censuses
            .get_mut(&key)
            .ok_or_else(|| unsafe_state("segment census was not retained"))?;
        *last_used = Instant::now();
        Arc::clone(census)
    };
    let result = {
        let mut state = census
            .try_lock()
            .map_err(|_| CodeGenerationRetentionErrorV1::GenerationStoreBusy)?;
        if !state.roots.matches(&roots) {
            *state = Census::new(&key.0, pool, roots)?;
        }
        state.advance(&key.0, is_cancelled)
    };
    if !matches!(
        result,
        Ok(true) | Err(CodeGenerationRetentionErrorV1::Cancelled)
    ) {
        let mut censuses = cache
            .lock()
            .map_err(|_| unsafe_state("segment census cache is poisoned"))?;
        if censuses
            .get(&key)
            .is_some_and(|(_, cached)| Arc::ptr_eq(cached, &census))
        {
            censuses.remove(&key);
        }
    }
    result
}
