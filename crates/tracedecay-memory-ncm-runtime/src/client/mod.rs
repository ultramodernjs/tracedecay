//! Bounded single-owner client for the supervised NCM worker process.

use crate::wire::{self, Operation, Reply, Request};
use crate::worker_artifact::{VerifiedWorkerArtifact, stage_verified_worker_binary};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Maximum queued calls per client.
pub const MAX_QUEUED_REQUESTS: usize = 32;
/// Maximum aggregate encoded bytes in the client mailbox.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of indeterminate mutating requests retained for reconciliation.
pub const MAX_RETAINED_UNKNOWN_ENTRIES: usize = 64;
/// Maximum aggregate in-memory request representation retained for reconciliation.
pub const MAX_RETAINED_UNKNOWN_BYTES: usize = 8 * 1024 * 1024;
/// Hard worker termination escalation budget after a deadline.
pub const KILL_ESCALATION: Duration = Duration::from_millis(250);
const MAX_SNAPSHOT_TRANSPORT_BYTES: usize = 256 * 1024 * 1024;
static NEXT_SNAPSHOT_FILE: AtomicU64 = AtomicU64::new(1);
const GLOBAL_READINESS_NAMESPACE: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Process launch and restart controls.
#[derive(Clone, Debug)]
pub struct WorkerOptions {
    /// Whether the provider is admitted to launch a worker.
    pub enabled: bool,
    /// Launch the named hash-encoder test double.
    #[cfg(feature = "test-transport")]
    pub test_double: bool,
    /// Permit startup without a locally loaded production encoder.
    pub no_encoder_required: bool,
    /// Consecutive spawn failures allowed before reporting restart exhaustion.
    pub max_restart_attempts: u32,
    /// Budget used by [`WorkerClient::reconcile_unknown`].
    pub reconciliation_deadline: Duration,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            #[cfg(feature = "test-transport")]
            test_double: false,
            no_encoder_required: false,
            max_restart_attempts: 3,
            reconciliation_deadline: Duration::from_secs(5),
        }
    }
}

/// Client-side process, framing, deadline, or admission failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The provider is disabled and must not launch a process.
    Disabled,
    /// The bounded request-count or byte mailbox is full.
    Busy,
    /// The request expired before it could start or complete without a possible effect.
    Cancelled,
    /// A mutating call lost transport after it may have committed.
    EffectUnknown {
        /// Request identifier whose effect must be reconciled.
        op_id: u64,
    },
    /// Request JSON exceeded the 256 KiB wire bound.
    RequestTooLarge,
    /// Worker process creation failed.
    Spawn(String),
    /// The configured worker is not an admitted local artifact.
    Unavailable(String),
    /// Consecutive process creation failures exhausted the configured budget.
    RestartExhausted,
    /// Pipe I/O failed.
    Transport(String),
    /// Worker stdout was not a valid bounded reply stream.
    MalformedReply(String),
    /// The worker exited before acknowledging a request.
    WorkerExited,
    /// No indeterminate request is retained under this namespace/idempotency key pair.
    UnknownIdempotencyKey,
    /// Retaining an indeterminate request would exceed the bounded ledger.
    UnknownRetentionLimit {
        /// Request identifier whose uncertainty could not be retained.
        op_id: u64,
    },
    /// A new indeterminate request reused a retained key for a different effect.
    UnknownRetentionConflict {
        /// Request identifier whose uncertainty could not be retained.
        op_id: u64,
    },
    /// The client owner thread stopped unexpectedly.
    OwnerStopped,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("worker provider is disabled"),
            Self::Busy => formatter.write_str("worker mailbox is full"),
            Self::Cancelled => formatter.write_str("worker request cancelled"),
            Self::EffectUnknown { op_id } => {
                write!(formatter, "effect unknown for request {op_id}")
            }
            Self::RequestTooLarge => formatter.write_str("worker request exceeds 256 KiB"),
            Self::Spawn(detail) => write!(formatter, "spawn worker: {detail}"),
            Self::Unavailable(detail) => write!(formatter, "worker unavailable: {detail}"),
            Self::RestartExhausted => formatter.write_str("worker restart budget exhausted"),
            Self::Transport(detail) => write!(formatter, "worker transport: {detail}"),
            Self::MalformedReply(detail) => write!(formatter, "malformed worker reply: {detail}"),
            Self::WorkerExited => formatter.write_str("worker exited before reply"),
            Self::UnknownIdempotencyKey => formatter.write_str("unknown idempotency key"),
            Self::UnknownRetentionLimit { op_id } => {
                write!(
                    formatter,
                    "unknown request {op_id} exceeds the retention limit"
                )
            }
            Self::UnknownRetentionConflict { op_id } => write!(
                formatter,
                "unknown request {op_id} conflicts with the retained idempotency key"
            ),
            Self::OwnerStopped => formatter.write_str("worker owner stopped"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One supervised worker process and its bounded owner mailbox.
pub struct WorkerClient {
    calls: SyncSender<OwnerMessage>,
    queued_bytes: Arc<AtomicUsize>,
    unknown: Arc<Mutex<UnknownRequests>>,
    shutdown: Arc<AtomicBool>,
    owner: Mutex<Option<JoinHandle<()>>>,
    pid: Arc<AtomicU32>,
    owner_incarnation: Arc<AtomicU64>,
    fenced: Arc<AtomicBool>,
    ledger_generation: AtomicU64,
    reconcile_gate: Mutex<()>,
    reconciliation_deadline: Duration,
    root: PathBuf,
    lifecycle: Arc<LifecycleState>,
}

#[derive(Clone, Debug)]
struct RetainedRequest {
    request: Request,
    identity_digest: String,
    bytes: usize,
    snapshot_backup: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct OwnedSnapshotFiles {
    send_file: PathBuf,
    backup_file: Option<PathBuf>,
}

impl OwnedSnapshotFiles {
    fn both(send_file: PathBuf, backup_file: PathBuf) -> Self {
        Self {
            send_file,
            backup_file: Some(backup_file),
        }
    }

    fn send_only(send_file: PathBuf) -> Self {
        Self {
            send_file,
            backup_file: None,
        }
    }
}

#[derive(Clone, Debug)]
struct RetentionReservation {
    key: (String, String),
    identity_digest: String,
    bytes: usize,
}

struct RetentionReservationGuard {
    unknown: Arc<Mutex<UnknownRequests>>,
    reservation: Option<RetentionReservation>,
}

impl RetentionReservationGuard {
    fn none(unknown: Arc<Mutex<UnknownRequests>>) -> Self {
        Self {
            unknown,
            reservation: None,
        }
    }

    fn new(unknown: Arc<Mutex<UnknownRequests>>, reservation: RetentionReservation) -> Self {
        Self {
            unknown,
            reservation: Some(reservation),
        }
    }
}

impl Drop for RetentionReservationGuard {
    fn drop(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        if let Ok(mut unknown) = self.unknown.lock() {
            unknown.release_reservation(&reservation);
        }
    }
}

struct SnapshotFilesGuard {
    files: Option<OwnedSnapshotFiles>,
}

impl SnapshotFilesGuard {
    fn new(files: OwnedSnapshotFiles) -> Self {
        Self { files: Some(files) }
    }

    fn as_ref(&self) -> Option<&OwnedSnapshotFiles> {
        self.files.as_ref()
    }

    fn disarm(&mut self) {
        self.files = None;
    }
}

impl Drop for SnapshotFilesGuard {
    fn drop(&mut self) {
        if let Some(files) = self.files.take() {
            remove_transport_file(Some(&files.send_file));
            cleanup_snapshot_backup(files.backup_file.as_deref());
        }
    }
}

#[derive(Default)]
struct UnknownRequests {
    entries: BTreeMap<(String, String), RetainedRequest>,
    bytes: usize,
    reservations: BTreeMap<(String, String), RetentionReservation>,
    reserved_bytes: usize,
}

impl UnknownRequests {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, key: &(String, String)) -> Option<&RetainedRequest> {
        self.entries.get(key)
    }

    fn contains_key(&self, key: &(String, String)) -> bool {
        self.entries.contains_key(key)
    }

    fn retain(
        &mut self,
        key: (String, String),
        candidate: RetainedRequest,
    ) -> Result<(), RetentionError> {
        if self.reservations.contains_key(&key) {
            return Err(RetentionError::Busy);
        }
        if let Some(existing) = self.entries.get(&key) {
            if existing.identity_digest != candidate.identity_digest {
                return Err(RetentionError::Conflict);
            }
            let next_bytes = self
                .bytes
                .checked_sub(existing.bytes)
                .and_then(|bytes| bytes.checked_add(candidate.bytes))
                .ok_or(RetentionError::Limit)?;
            if candidate.bytes > MAX_RETAINED_UNKNOWN_BYTES
                || next_bytes
                    .checked_add(self.reserved_bytes)
                    .is_none_or(|bytes| bytes > MAX_RETAINED_UNKNOWN_BYTES)
            {
                return Err(RetentionError::Limit);
            }
            self.bytes = next_bytes;
            self.entries.insert(key, candidate);
            return Ok(());
        }
        let next_entries = self
            .entries
            .len()
            .checked_add(self.reservations.len())
            .ok_or(RetentionError::Limit)?;
        let next_bytes = self
            .bytes
            .checked_add(self.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(candidate.bytes))
            .ok_or(RetentionError::Limit)?;
        if candidate.bytes > MAX_RETAINED_UNKNOWN_BYTES
            || next_entries >= MAX_RETAINED_UNKNOWN_ENTRIES
            || next_bytes > MAX_RETAINED_UNKNOWN_BYTES
        {
            return Err(RetentionError::Limit);
        }
        self.bytes = self
            .bytes
            .checked_add(candidate.bytes)
            .ok_or(RetentionError::Limit)?;
        self.entries.insert(key, candidate);
        Ok(())
    }

    fn reserve(
        &mut self,
        key: (String, String),
        identity_digest: String,
        bytes: usize,
    ) -> Result<Option<RetentionReservation>, RetentionError> {
        if let Some(existing) = self.entries.get(&key) {
            if existing.identity_digest != identity_digest {
                return Err(RetentionError::Conflict);
            }
            return Ok(None);
        }
        if let Some(existing) = self.reservations.get(&key) {
            if existing.identity_digest != identity_digest {
                return Err(RetentionError::Conflict);
            }
            return Err(RetentionError::Busy);
        }
        let next_entries = self
            .entries
            .len()
            .checked_add(self.reservations.len())
            .and_then(|entries| entries.checked_add(1))
            .ok_or(RetentionError::Limit)?;
        let next_bytes = self
            .bytes
            .checked_add(self.reserved_bytes)
            .and_then(|total| total.checked_add(bytes))
            .ok_or(RetentionError::Limit)?;
        if bytes > MAX_RETAINED_UNKNOWN_BYTES
            || next_entries > MAX_RETAINED_UNKNOWN_ENTRIES
            || next_bytes > MAX_RETAINED_UNKNOWN_BYTES
        {
            return Err(RetentionError::Limit);
        }
        let reservation = RetentionReservation {
            key: key.clone(),
            identity_digest,
            bytes,
        };
        self.reserved_bytes = self
            .reserved_bytes
            .checked_add(bytes)
            .ok_or(RetentionError::Limit)?;
        self.reservations.insert(key, reservation.clone());
        Ok(Some(reservation))
    }

    fn release_reservation(&mut self, reservation: &RetentionReservation) -> bool {
        let matches = self
            .reservations
            .get(&reservation.key)
            .is_some_and(|current| {
                current.identity_digest == reservation.identity_digest
                    && current.bytes == reservation.bytes
            });
        if !matches {
            return false;
        }
        self.reservations.remove(&reservation.key);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(reservation.bytes);
        true
    }

    fn remove_if_matches(
        &mut self,
        key: &(String, String),
        identity_digest: &str,
    ) -> Option<RetainedRequest> {
        let matches = self
            .entries
            .get(key)
            .is_some_and(|retained| retained.identity_digest == identity_digest);
        if !matches {
            return None;
        }
        let removed = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub(removed.bytes);
        Some(removed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetentionError {
    Limit,
    Conflict,
    Busy,
}

#[derive(Default)]
struct LifecycleState {
    gate: Mutex<()>,
    stopped: AtomicBool,
    requested: AtomicU64,
    completed: AtomicU64,
    force: AtomicBool,
}

impl WorkerClient {
    /// Creates a client owner. The worker itself starts lazily on the first call.
    pub fn spawn(
        binary_path: impl AsRef<Path>,
        root: impl AsRef<Path>,
        options: WorkerOptions,
    ) -> Result<Self, ClientError> {
        if !options.enabled {
            return Err(ClientError::Disabled);
        }
        let binary = binary_path.as_ref();
        if !binary.is_absolute() {
            return Err(ClientError::Spawn(
                "worker binary path must be absolute".to_owned(),
            ));
        }
        let state_root = root.as_ref();
        if !state_root.is_absolute() {
            return Err(ClientError::Spawn("state root must be absolute".to_owned()));
        }
        #[cfg(feature = "test-transport")]
        let test_double = options.test_double;
        #[cfg(not(feature = "test-transport"))]
        let test_double = false;
        let (calls, receiver) = mpsc::sync_channel::<OwnerMessage>(MAX_QUEUED_REQUESTS);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let pid = Arc::new(AtomicU32::new(0));
        let owner_incarnation = Arc::new(AtomicU64::new(0));
        let fenced = Arc::new(AtomicBool::new(false));
        let ledger_generation = AtomicU64::new(0);
        let reconcile_gate = Mutex::new(());
        let owner_shutdown = Arc::clone(&shutdown);
        let owner_pid = Arc::clone(&pid);
        let owner_owner_incarnation = Arc::clone(&owner_incarnation);
        let owner_queued_bytes = Arc::clone(&queued_bytes);
        let lifecycle = Arc::new(LifecycleState::default());
        let owner_lifecycle = Arc::clone(&lifecycle);
        let launch = Launch {
            binary: binary.to_path_buf(),
            root: state_root.to_path_buf(),
            test_double,
            no_encoder_required: options.no_encoder_required,
            max_restart_attempts: options.max_restart_attempts,
        };
        let owner = thread::Builder::new()
            .name("ncm-worker-owner".to_owned())
            .spawn(move || {
                owner_loop(
                    receiver,
                    owner_shutdown,
                    owner_pid,
                    owner_owner_incarnation,
                    owner_queued_bytes,
                    launch,
                    owner_lifecycle,
                )
            })
            .map_err(|error| ClientError::Spawn(error.to_string()))?;
        Ok(Self {
            calls,
            queued_bytes,
            unknown: Arc::new(Mutex::new(UnknownRequests::default())),
            shutdown,
            owner: Mutex::new(Some(owner)),
            pid,
            owner_incarnation,
            fenced,
            ledger_generation,
            reconcile_gate,
            reconciliation_deadline: options.reconciliation_deadline,
            root: state_root.to_path_buf(),
            lifecycle,
        })
    }

    /// Sends one bounded call and waits through the hard-kill escalation budget.
    pub fn call(&self, request: Request, deadline: Duration) -> Result<Reply, ClientError> {
        self.call_cancellable(request, deadline, Arc::new(|| false))
    }

    /// Sends one bounded request with a caller-owned cancellation probe.
    /// Cancellation retires only this request, using the existing kill/reap
    /// path if it reached the child. The shared owner remains available.
    pub fn call_cancellable(
        &self,
        request: Request,
        deadline: Duration,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Reply, ClientError> {
        self.call_cancellable_with_identity(request, deadline, cancelled, None, None)
    }

    fn call_cancellable_with_identity(
        &self,
        mut request: Request,
        deadline: Duration,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
        retained_identity_digest: Option<&str>,
        retained_snapshot_backup: Option<&Path>,
    ) -> Result<Reply, ClientError> {
        if cancelled() || deadline.is_zero() {
            return Err(ClientError::Cancelled);
        }
        if self.lifecycle.stopped.load(Ordering::Acquire) {
            return Err(ClientError::Disabled);
        }
        let lifecycle = Arc::clone(&self.lifecycle);
        let epoch = lifecycle.requested.load(Ordering::Acquire);
        let cancelled: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            cancelled()
                || lifecycle.stopped.load(Ordering::Acquire)
                || lifecycle.requested.load(Ordering::Acquire) != epoch
        });
        let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        request.deadline_ms = deadline_ms;
        let logical_request = request.clone();
        let mut snapshot_files = if let Some(backup) = retained_snapshot_backup {
            SnapshotFilesGuard::new(self.refresh_snapshot_transport(&mut request, backup)?)
        } else if retained_identity_digest.is_none() && snapshot_transport_file(&request).is_some()
        {
            SnapshotFilesGuard::new(self.copy_snapshot_restore_file(&mut request)?)
        } else if retained_identity_digest.is_none()
            && request.op == Operation::SnapshotRestore
            && inline_snapshot_bytes(&request)?.is_some()
        {
            SnapshotFilesGuard::new(self.externalize_snapshot_restore(&mut request)?)
        } else {
            SnapshotFilesGuard { files: None }
        };
        let frame_bytes = match wire::encode_request(&request) {
            Ok(frame) => frame.len(),
            Err(wire::FrameError::Oversized { .. }) if request.op == Operation::SnapshotRestore => {
                snapshot_files =
                    SnapshotFilesGuard::new(self.externalize_snapshot_restore(&mut request)?);
                match wire::encode_request(&request) {
                    Ok(frame) => frame.len(),
                    Err(wire::FrameError::Oversized { .. }) => {
                        return Err(ClientError::RequestTooLarge);
                    }
                    Err(error) => return Err(ClientError::Transport(error.to_string())),
                }
            }
            Err(wire::FrameError::Oversized { .. }) => return Err(ClientError::RequestTooLarge),
            Err(error) => return Err(ClientError::Transport(error.to_string())),
        };
        let retention_reservation = self.admit_unknown(
            &logical_request,
            &request,
            retained_identity_digest,
            snapshot_files.as_ref(),
        )?;
        self.reserve_bytes(frame_bytes)?;
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        let expires = Instant::now()
            .checked_add(deadline)
            .unwrap_or_else(Instant::now);
        let command = OwnerCommand {
            request: request.clone(),
            expires,
            queued_bytes: frame_bytes,
            response: response_tx,
            cancelled: Arc::clone(&cancelled),
        };
        match self.calls.try_send(OwnerMessage::Call(command)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(frame_bytes, Ordering::AcqRel);
                return Err(ClientError::Busy);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(frame_bytes, Ordering::AcqRel);
                return Err(ClientError::OwnerStopped);
            }
        }
        let wait = deadline
            .saturating_add(KILL_ESCALATION)
            .saturating_add(Duration::from_millis(100));
        let mut wait_until = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        let mut cancellation_seen = false;
        let mut result = loop {
            if !cancellation_seen && cancelled() {
                cancellation_seen = true;
                wait_until =
                    wait_until.min(Instant::now() + KILL_ESCALATION + Duration::from_millis(100));
            }
            let Some(remaining) = wait_until.checked_duration_since(Instant::now()) else {
                break Err(if cancellation_seen {
                    indeterminate_or(&request, ClientError::Cancelled)
                } else {
                    ClientError::Cancelled
                });
            };
            match response_rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(result) => {
                    // A worker-side cancellation reply is an authoritative
                    // pre-commit no-effect result.  Preserve it even when
                    // the caller cancellation races with reply delivery;
                    // only a successful/unknown mutating reply remains
                    // ambiguous after that race.
                    let reply_can_be_indeterminate = matches!(
                        &result,
                        Ok(Reply {
                            outcome: crate::engine::Outcome::Success
                                | crate::engine::Outcome::EffectUnknown,
                            ..
                        })
                    );
                    break if (cancellation_seen || cancelled()) && reply_can_be_indeterminate {
                        Err(indeterminate_or(&request, ClientError::Cancelled))
                    } else {
                        result
                    };
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break Err(ClientError::OwnerStopped),
            }
        };
        if let Ok(reply) = result {
            result = self.hydrate_snapshot_export(&request, reply);
        }
        result = normalize_result(&logical_request, &result);
        let retention = self.update_unknown_with_retained(
            &logical_request,
            &request,
            &result,
            retained_identity_digest,
            snapshot_files.as_ref(),
            retention_reservation.reservation.as_ref(),
        );
        let retained = retention?;
        if retained
            && matches!(
                &result,
                Err(ClientError::EffectUnknown { .. })
                    | Ok(Reply {
                        outcome: crate::engine::Outcome::EffectUnknown,
                        ..
                    })
            )
        {
            // An indeterminate replay adopts the prepared files. A Busy replay
            // keeps the prior ledger entry, so its refreshed send is still guarded.
            snapshot_files.disarm();
        }
        result
    }

    /// Replays the retained mutating request for an indeterminate namespace/key pair.
    pub fn reconcile_unknown(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Reply, ClientError> {
        let _reconcile_gate = self
            .reconcile_gate
            .lock()
            .map_err(|_| ClientError::OwnerStopped)?;
        let (retained, fenced, fence_generation) = {
            let unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
            let retained = unknown
                .get(&(namespace.to_owned(), idempotency_key.to_owned()))
                .cloned()
                .ok_or(ClientError::UnknownIdempotencyKey)?;
            (
                retained,
                self.fenced.load(Ordering::Acquire),
                self.ledger_generation.load(Ordering::Acquire),
            )
        };
        if fenced {
            let deadline = Instant::now()
                .checked_add(self.reconciliation_deadline)
                .unwrap_or_else(Instant::now);
            self.kill(deadline)?;
            self.start(deadline)?;
            let unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
            let current = unknown
                .get(&(namespace.to_owned(), idempotency_key.to_owned()))
                .cloned()
                .ok_or(ClientError::UnknownIdempotencyKey)?;
            if current.identity_digest != retained.identity_digest {
                return Err(ClientError::UnknownRetentionConflict {
                    op_id: current.request.id,
                });
            }
            if self.ledger_generation.load(Ordering::Acquire) == fence_generation {
                self.fenced.store(false, Ordering::Release);
            }
            drop(unknown);
            // A concurrent request may have replaced another ledger entry
            // while the owner was being restarted. Reconcile the current
            // generation of this exact key, never a stale request snapshot.
            return self.call_cancellable_with_identity(
                current.request,
                self.reconciliation_deadline,
                Arc::new(|| false),
                Some(&current.identity_digest),
                current.snapshot_backup.as_deref(),
            );
        }
        // The ledger lock above establishes the initial identity. Re-read it
        // immediately before replay so a normal call that completed between
        // the initial read and this point cannot clear or replay a different
        // request under the same namespace/key.
        let current = {
            let unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
            unknown
                .get(&(namespace.to_owned(), idempotency_key.to_owned()))
                .cloned()
                .ok_or(ClientError::UnknownIdempotencyKey)?
        };
        if current.identity_digest != retained.identity_digest {
            return Err(ClientError::UnknownRetentionConflict {
                op_id: current.request.id,
            });
        }
        self.call_cancellable_with_identity(
            current.request,
            self.reconciliation_deadline,
            Arc::new(|| false),
            Some(&current.identity_digest),
            current.snapshot_backup.as_deref(),
        )
    }

    /// Current worker process identifier, or `None` while stopped/lazy.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        match self.pid.load(Ordering::Acquire) {
            0 => None,
            pid => Some(pid),
        }
    }

    /// Monotonic owner incarnation for the currently or most recently spawned
    /// worker process. It advances on every internal respawn, including when
    /// the operating system reuses a process identifier.
    #[must_use]
    pub fn owner_incarnation(&self) -> Option<u64> {
        match self.owner_incarnation.load(Ordering::Acquire) {
            0 => None,
            incarnation => Some(incarnation),
        }
    }

    /// Starts or resumes this owner's actual worker. Only a live process may
    /// reuse its previously successful global handshake.
    pub fn start(&self, deadline: Instant) -> Result<(), ClientError> {
        let _gate = self.lifecycle_gate(deadline)?;
        if self.lifecycle.completed.load(Ordering::Acquire)
            < self.lifecycle.requested.load(Ordering::Acquire)
        {
            return Err(ClientError::Busy);
        }
        self.lifecycle.stopped.store(false, Ordering::Release);
        remaining(deadline).ok_or(ClientError::Cancelled)?;
        let (response, receiver) = mpsc::sync_channel(1);
        match self.calls.try_send(OwnerMessage::Start(OwnerStart {
            expires: deadline,
            response,
        })) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(ClientError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(ClientError::OwnerStopped),
        }
        let wait_until = deadline
            .checked_add(KILL_ESCALATION + Duration::from_millis(100))
            .unwrap_or(deadline);
        match wait_channel(&receiver, wait_until, &self.shutdown, &|| false) {
            Ok(result) => result,
            Err(WaitError::Deadline | WaitError::Shutdown) => Err(ClientError::Cancelled),
            Err(WaitError::Disconnected) => Err(ClientError::OwnerStopped),
        }
    }

    /// Requests graceful termination and waits for the owner to confirm child
    /// reap and pipe-thread completion. False leaves termination unconfirmed.
    pub fn request_stop(&self, deadline: Instant) -> Result<bool, ClientError> {
        self.stop_owned_worker(deadline, false)
    }

    /// Forces termination through this existing owner. Success proves the child
    /// was reaped; callers must not treat a deadline error as confirmed erasure.
    pub fn kill(&self, deadline: Instant) -> Result<(), ClientError> {
        if self.stop_owned_worker(deadline, true)? {
            Ok(())
        } else {
            Err(ClientError::Cancelled)
        }
    }

    fn lifecycle_gate(
        &self,
        deadline: Instant,
    ) -> Result<std::sync::MutexGuard<'_, ()>, ClientError> {
        loop {
            if Instant::now() >= deadline {
                return Err(ClientError::Cancelled);
            }
            match self.lifecycle.gate.try_lock() {
                Ok(gate) => return Ok(gate),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(ClientError::OwnerStopped),
                Err(std::sync::TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(2)),
            }
        }
    }

    fn stop_owned_worker(&self, deadline: Instant, force: bool) -> Result<bool, ClientError> {
        let _gate = self.lifecycle_gate(deadline)?;
        self.lifecycle.stopped.store(true, Ordering::Release);
        self.lifecycle.force.store(force, Ordering::Release);
        let requested = self
            .lifecycle
            .requested
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        loop {
            if self.lifecycle.completed.load(Ordering::Acquire) >= requested {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if self.shutdown.load(Ordering::Acquire) {
                return Err(ClientError::OwnerStopped);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn externalize_snapshot_restore(
        &self,
        request: &mut Request,
    ) -> Result<OwnedSnapshotFiles, ClientError> {
        let common = request
            .payload
            .pointer("/common_portability/action")
            .is_some_and(|value| value == "snapshot_restore");
        let snapshot = if common {
            request.payload.pointer("/common_portability/bytes")
        } else {
            request.payload.get("snapshot")
        }
        .cloned()
        .ok_or(ClientError::RequestTooLarge)?;
        let bytes: Vec<u8> = serde_json::from_value(snapshot)
            .map_err(|error| ClientError::Transport(format!("snapshot payload: {error}")))?;
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_TRANSPORT_BYTES {
            return Err(ClientError::RequestTooLarge);
        }
        let (send_file, backup_file) = self.write_retained_snapshot_files(request, &bytes)?;
        let content_sha256 = sha256_hex(&bytes);
        if let Err(error) =
            set_snapshot_transport(request, &send_file, bytes.len(), &content_sha256)
        {
            remove_transport_file(Some(&send_file));
            remove_transport_file(Some(&backup_file));
            return Err(error);
        }
        Ok(OwnedSnapshotFiles::both(send_file, backup_file))
    }

    fn copy_snapshot_restore_file(
        &self,
        request: &mut Request,
    ) -> Result<OwnedSnapshotFiles, ClientError> {
        let Some((source, byte_length, content_sha256)) = snapshot_file_metadata(request)? else {
            return Err(ClientError::RequestTooLarge);
        };
        let bytes = read_caller_snapshot_file(&source, byte_length, &content_sha256)?;
        let (send_file, backup_file) = self.write_retained_snapshot_files(request, &bytes)?;
        if let Err(error) =
            set_snapshot_transport(request, &send_file, bytes.len(), &content_sha256)
        {
            remove_transport_file(Some(&send_file));
            remove_transport_file(Some(&backup_file));
            return Err(error);
        }
        Ok(OwnedSnapshotFiles::both(send_file, backup_file))
    }

    fn hydrate_snapshot_export(
        &self,
        request: &Request,
        mut reply: Reply,
    ) -> Result<Reply, ClientError> {
        if request.op != Operation::SnapshotExport
            || !matches!(reply.outcome, crate::engine::Outcome::Success)
        {
            return Ok(reply);
        }
        let payload = reply.payload.as_ref().ok_or_else(|| {
            ClientError::MalformedReply("snapshot export omitted file metadata".to_owned())
        })?;
        let snapshot_file = payload
            .get("snapshot_file")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                ClientError::MalformedReply("snapshot export omitted snapshot_file".to_owned())
            })?;
        let byte_length = payload
            .get("byte_length")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                ClientError::MalformedReply("snapshot export omitted byte_length".to_owned())
            })?;
        let content_sha256 = payload
            .get("content_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ClientError::MalformedReply("snapshot export omitted content_sha256".to_owned())
            })?;
        let payload_generation = payload
            .get("state_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                ClientError::MalformedReply("snapshot export omitted state_generation".to_owned())
            })?;
        if payload_generation != reply.state_generation {
            return Err(ClientError::MalformedReply(
                "snapshot export generation mismatch".to_owned(),
            ));
        }
        let bytes = read_verified_snapshot_file(
            &self.root,
            &request.namespace,
            &snapshot_file,
            byte_length,
            content_sha256,
        )?;
        let common = request
            .payload
            .pointer("/common_portability/action")
            .is_some_and(|value| value == "snapshot_export");
        if common && payload["common_portability"] != "snapshot_export" {
            return Err(ClientError::MalformedReply(
                "common snapshot marker differs".to_owned(),
            ));
        }
        reply.payload = Some(json!({
            "format": "ncm-snapshot.v1",
            "bytes": bytes,
            "byte_length": byte_length,
            "content_sha256": content_sha256,
            "state_generation": reply.state_generation
        }));
        if common {
            reply.payload = Some(
                json!({"common_portability": "snapshot_export", "bytes": reply.payload.as_ref().and_then(|payload| payload.get("bytes")), "warnings": []}),
            );
        }
        Ok(reply)
    }

    fn reserve_bytes(&self, bytes: usize) -> Result<(), ClientError> {
        self.queued_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= MAX_QUEUED_BYTES)
            })
            .map(|_| ())
            .map_err(|_| ClientError::Busy)
    }

    fn admit_unknown(
        &self,
        identity_request: &Request,
        retained_request: &Request,
        retained_identity_digest: Option<&str>,
        prepared_snapshot: Option<&OwnedSnapshotFiles>,
    ) -> Result<RetentionReservationGuard, ClientError> {
        let Some(idempotency_key) = idempotency_key(identity_request) else {
            return Ok(RetentionReservationGuard::none(Arc::clone(&self.unknown)));
        };
        let identity_digest = match retained_identity_digest {
            Some(digest) => digest.to_owned(),
            None => request_identity_digest(identity_request)?,
        };
        let bytes = retained_request_size(
            retained_request,
            &identity_digest,
            prepared_snapshot.and_then(|files| files.backup_file.as_deref()),
        )?;
        let key = (
            identity_request.namespace.clone(),
            idempotency_key.to_owned(),
        );
        let mut unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
        match unknown.reserve(key, identity_digest, bytes) {
            Ok(Some(reservation)) => Ok(RetentionReservationGuard::new(
                Arc::clone(&self.unknown),
                reservation,
            )),
            Ok(None) => Ok(RetentionReservationGuard::none(Arc::clone(&self.unknown))),
            Err(RetentionError::Limit) => Err(ClientError::UnknownRetentionLimit {
                op_id: identity_request.id,
            }),
            Err(RetentionError::Conflict) => Err(ClientError::UnknownRetentionConflict {
                op_id: identity_request.id,
            }),
            Err(RetentionError::Busy) => Err(ClientError::Busy),
        }
    }

    fn update_unknown_with_retained(
        &self,
        identity_request: &Request,
        retained_request: &Request,
        result: &Result<Reply, ClientError>,
        retained_identity_digest: Option<&str>,
        prepared_snapshot: Option<&OwnedSnapshotFiles>,
        reservation: Option<&RetentionReservation>,
    ) -> Result<bool, ClientError> {
        let normalized_result = normalize_result(identity_request, result);
        let result = &normalized_result;
        let Some(idempotency_key) = idempotency_key(identity_request) else {
            // There is no safe public replay route without a mutating
            // idempotency key. In particular, a keyless read/handshake
            // cancellation or ordinary terminal reply must never create a
            // global fence that no caller can clear.
            if let Some(reservation) = reservation {
                self.release_unknown_reservation(reservation)?;
            }
            return Ok(false);
        };
        let key = (
            identity_request.namespace.clone(),
            idempotency_key.to_owned(),
        );
        let identity_digest = match retained_identity_digest {
            Some(digest) => digest.to_owned(),
            None => match request_identity_digest(identity_request) {
                Ok(digest) => digest,
                Err(error) => {
                    if let Some(reservation) = reservation {
                        self.release_unknown_reservation(reservation)?;
                    }
                    return Err(error);
                }
            },
        };

        let should_retain = identity_request.op.is_mutating()
            && matches!(
                result,
                Err(ClientError::EffectUnknown { .. })
                    | Ok(Reply {
                        outcome: crate::engine::Outcome::EffectUnknown,
                        ..
                    })
            );
        if should_retain {
            let mut unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
            let existing = unknown.get(&key).cloned();
            if existing
                .as_ref()
                .is_some_and(|retained| retained.identity_digest != identity_digest)
            {
                // The original retained request is the only request that may
                // be replayed under this key. Keep it intact when a conflicting
                // request reaches an uncertain outcome.
                if let Some(reservation) = reservation {
                    unknown.release_reservation(reservation);
                }
                return Err(ClientError::UnknownRetentionConflict {
                    op_id: identity_request.id,
                });
            }
            let (candidate, newly_owned) = match self.compact_retained_request(
                identity_request,
                retained_request,
                &identity_digest,
                existing.as_ref(),
                prepared_snapshot,
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    if let Some(reservation) = reservation {
                        unknown.release_reservation(reservation);
                    }
                    return Err(error);
                }
            };
            if let Some(reservation) = reservation {
                // The candidate is about to replace this reservation while
                // the ledger lock is held, so release its provisional budget
                // before applying the normal retain accounting.
                unknown.release_reservation(reservation);
            }
            match unknown.retain(key, candidate.clone()) {
                Ok(()) => {
                    // A retained entry always has a real
                    // namespace/idempotency route: reconciliation
                    // replaces/fences the owner, proves readiness, and
                    // replays this exact request. Set the global fence only
                    // after the bounded ledger accepted that route.
                    self.fenced.store(true, Ordering::Release);
                    self.ledger_generation.fetch_add(1, Ordering::AcqRel);
                    if let Some(previous) = existing {
                        let previous_send = snapshot_transport_file(&previous.request);
                        let candidate_send = snapshot_transport_file(&candidate.request);
                        if previous_send != candidate_send {
                            remove_transport_file(previous_send.as_deref());
                        }
                        if previous.snapshot_backup != candidate.snapshot_backup {
                            cleanup_snapshot_backup(previous.snapshot_backup.as_deref());
                        }
                    }
                    return Ok(true);
                }
                Err(RetentionError::Limit) => {
                    cleanup_snapshot_files(&newly_owned);
                    return Err(ClientError::UnknownRetentionLimit {
                        op_id: identity_request.id,
                    });
                }
                Err(RetentionError::Conflict) => {
                    cleanup_snapshot_files(&newly_owned);
                    return Err(ClientError::UnknownRetentionConflict {
                        op_id: identity_request.id,
                    });
                }
                Err(RetentionError::Busy) => {
                    cleanup_snapshot_files(&newly_owned);
                    return Err(ClientError::Busy);
                }
            }
        }

        if let Some(reservation) = reservation {
            self.release_unknown_reservation(reservation)?;
        }

        let resolves_effect = match result {
            Ok(Reply {
                outcome: crate::engine::Outcome::Success,
                ..
            }) => true,
            Ok(Reply {
                outcome, payload, ..
            }) if payload
                .as_ref()
                .is_some_and(|payload| durable_no_effect_proof(outcome, payload)) =>
            {
                true
            }
            _ => false,
        };
        if !resolves_effect {
            // Busy, idempotency conflict, and a terminal result from a
            // replay attempt are deliberately unresolved for an already
            // retained request. A later reconciliation must still be able to
            // replay the original request; a fresh known terminal result did
            // not create an entry above.
            let remains = self
                .unknown
                .lock()
                .map_err(|_| ClientError::OwnerStopped)?
                .contains_key(&key);
            if remains {
                // The replay did not prove an effect or a durable no-effect
                // result. Keep the owner fenced so the next reconciliation
                // starts with a fresh process and namespace handshake.
                self.fenced.store(true, Ordering::Release);
            }
            return Ok(remains);
        }

        let mut unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
        let removed = unknown.remove_if_matches(&key, &identity_digest);
        let ledger_empty = unknown.len() == 0;
        if removed.is_some() {
            self.ledger_generation.fetch_add(1, Ordering::AcqRel);
            if ledger_empty {
                self.fenced.store(false, Ordering::Release);
            }
        }
        drop(unknown);
        if let Some(removed) = removed {
            cleanup_retained_snapshot(&removed);
        }
        Ok(false)
    }

    fn release_unknown_reservation(
        &self,
        reservation: &RetentionReservation,
    ) -> Result<(), ClientError> {
        let mut unknown = self.unknown.lock().map_err(|_| ClientError::OwnerStopped)?;
        unknown.release_reservation(reservation);
        Ok(())
    }

    fn compact_retained_request(
        &self,
        identity_request: &Request,
        retained_request: &Request,
        identity_digest: &str,
        existing: Option<&RetainedRequest>,
        prepared_snapshot: Option<&OwnedSnapshotFiles>,
    ) -> Result<(RetainedRequest, Vec<OwnedSnapshotFiles>), ClientError> {
        let mut request = retained_request.clone();
        let mut newly_owned = Vec::new();
        let mut snapshot_backup = prepared_snapshot
            .and_then(|files| files.backup_file.clone())
            .or_else(|| existing.and_then(|retained| retained.snapshot_backup.clone()));
        if request.op == Operation::SnapshotRestore {
            if prepared_snapshot.is_none()
                && let Some(bytes) = inline_snapshot_bytes(identity_request)?
            {
                let (send_file, backup_file) =
                    self.write_retained_snapshot_files(&request, &bytes)?;
                if let Err(error) = set_snapshot_transport(
                    &mut request,
                    &send_file,
                    bytes.len(),
                    &sha256_hex(&bytes),
                ) {
                    remove_transport_file(Some(&send_file));
                    remove_transport_file(Some(&backup_file));
                    return Err(error);
                }
                snapshot_backup = Some(backup_file.clone());
                newly_owned.push(OwnedSnapshotFiles::both(send_file, backup_file));
            } else if prepared_snapshot.is_none()
                && let Some(backup) = snapshot_backup.as_deref()
            {
                let files = self.refresh_snapshot_transport(&mut request, backup)?;
                newly_owned.push(files);
            } else if prepared_snapshot.is_none()
                && let Some(source) = snapshot_transport_file(&request)
            {
                // `update_unknown` is also used by the focused client tests
                // and by adapters that already received a wire reply.  When
                // that path has not prepared a transport guard, validate and
                // copy a caller-owned file before retaining it.  A retry of a
                // previously retained request, by contrast, carries an
                // internal send path and is handled by the backup branch.
                let bytes = if is_snapshot_transport_path(&self.root, &request.namespace, &source) {
                    if let Some((metadata_source, byte_length, content_sha256)) =
                        snapshot_file_metadata(identity_request)?
                    {
                        if metadata_source != source {
                            return Err(ClientError::Transport(
                                "snapshot transport metadata path differs from request".to_owned(),
                            ));
                        }
                        read_caller_snapshot_file(&source, byte_length, &content_sha256)?
                    } else {
                        fs::read(&source).map_err(|error| {
                            ClientError::Transport(format!("read snapshot transport file: {error}"))
                        })?
                    }
                } else {
                    let (caller_source, byte_length, content_sha256) =
                        snapshot_file_metadata(identity_request)?.ok_or_else(|| {
                            ClientError::Transport(
                                "snapshot transport metadata is missing".to_owned(),
                            )
                        })?;
                    if caller_source != source {
                        return Err(ClientError::Transport(
                            "snapshot transport metadata path differs from request".to_owned(),
                        ));
                    }
                    read_caller_snapshot_file(&caller_source, byte_length, &content_sha256)?
                };
                if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_TRANSPORT_BYTES {
                    return Err(ClientError::RequestTooLarge);
                }
                let (send_file, backup_file) =
                    self.write_retained_snapshot_files(&request, &bytes)?;
                if let Err(error) = set_snapshot_transport(
                    &mut request,
                    &send_file,
                    bytes.len(),
                    &sha256_hex(&bytes),
                ) {
                    remove_transport_file(Some(&send_file));
                    remove_transport_file(Some(&backup_file));
                    return Err(error);
                }
                snapshot_backup = Some(backup_file.clone());
                newly_owned.push(OwnedSnapshotFiles::both(send_file, backup_file));
            }
        }
        let bytes =
            match retained_request_size(&request, identity_digest, snapshot_backup.as_deref()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    cleanup_snapshot_files(&newly_owned);
                    return Err(error);
                }
            };
        Ok((
            RetainedRequest {
                request,
                identity_digest: identity_digest.to_owned(),
                bytes,
                snapshot_backup,
            },
            newly_owned,
        ))
    }

    fn write_retained_snapshot_files(
        &self,
        request: &Request,
        bytes: &[u8],
    ) -> Result<(PathBuf, PathBuf), ClientError> {
        let directory =
            snapshot_directory(&self.root, &request.namespace).map_err(ClientError::Transport)?;
        fs::create_dir_all(&directory).map_err(|error| {
            ClientError::Transport(format!("create snapshot retention directory: {error}"))
        })?;
        let serial = NEXT_SNAPSHOT_FILE.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("retained-{}-{}-{serial}", std::process::id(), request.id);
        let send_file = directory.join(format!("{prefix}.json"));
        let backup_file = directory.join(format!("{prefix}.backup.json"));
        write_snapshot_file(&directory, &send_file, bytes, &format!("{prefix}.tmp"))?;
        if let Err(error) = write_snapshot_file(
            &directory,
            &backup_file,
            bytes,
            &format!("{prefix}.backup.tmp"),
        ) {
            remove_transport_file(Some(&send_file));
            return Err(error);
        }
        Ok((send_file, backup_file))
    }

    fn refresh_snapshot_transport(
        &self,
        request: &mut Request,
        backup: &Path,
    ) -> Result<OwnedSnapshotFiles, ClientError> {
        if !is_snapshot_transport_path(&self.root, &request.namespace, backup) {
            return Err(ClientError::Transport(
                "retained snapshot backup escapes namespace directory".to_owned(),
            ));
        }
        let bytes = fs::read(backup).map_err(|error| {
            ClientError::Transport(format!("read retained snapshot backup: {error}"))
        })?;
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_TRANSPORT_BYTES {
            return Err(ClientError::RequestTooLarge);
        }
        if let Some((_, byte_length, content_sha256)) = snapshot_file_metadata(request)? {
            let expected_length =
                usize::try_from(byte_length).map_err(|_| ClientError::RequestTooLarge)?;
            if bytes.len() != expected_length || sha256_hex(&bytes) != content_sha256 {
                return Err(ClientError::Transport(
                    "retained snapshot backup failed content verification".to_owned(),
                ));
            }
        }
        let directory =
            snapshot_directory(&self.root, &request.namespace).map_err(ClientError::Transport)?;
        fs::create_dir_all(&directory).map_err(|error| {
            ClientError::Transport(format!("create snapshot retention directory: {error}"))
        })?;
        let serial = NEXT_SNAPSHOT_FILE.fetch_add(1, Ordering::Relaxed);
        let destination = directory.join(format!(
            "reconcile-{}-{}-{serial}.json",
            std::process::id(),
            request.id
        ));
        let temporary = format!(".reconcile-{}-{serial}.tmp", std::process::id());
        write_snapshot_file(&directory, &destination, &bytes, &temporary)?;
        let previous_send = snapshot_transport_file(request);
        let digest = sha256_hex(&bytes);
        if let Err(error) = set_snapshot_transport(request, &destination, bytes.len(), &digest) {
            remove_transport_file(Some(&destination));
            return Err(error);
        }
        if previous_send.as_deref() != Some(backup) {
            remove_transport_file(previous_send.as_deref());
        }
        Ok(OwnedSnapshotFiles::send_only(destination))
    }
}

fn inline_snapshot_bytes(request: &Request) -> Result<Option<Vec<u8>>, ClientError> {
    let common = request
        .payload
        .pointer("/common_portability/action")
        .is_some_and(|value| value == "snapshot_restore");
    let snapshot = if common {
        request.payload.pointer("/common_portability/bytes")
    } else {
        request.payload.get("snapshot")
    };
    snapshot
        .cloned()
        .map(|snapshot| {
            serde_json::from_value(snapshot)
                .map_err(|error| ClientError::Transport(format!("snapshot payload: {error}")))
        })
        .transpose()
}

fn snapshot_file_metadata(
    request: &Request,
) -> Result<Option<(PathBuf, u64, String)>, ClientError> {
    if request.op != Operation::SnapshotRestore {
        return Ok(None);
    }
    let common = request
        .payload
        .pointer("/common_portability/action")
        .is_some_and(|value| value == "snapshot_restore");
    let object = if common {
        request.payload.get("common_portability")
    } else {
        Some(&request.payload)
    }
    .and_then(Value::as_object)
    .ok_or_else(|| {
        ClientError::Transport("snapshot restore payload must be an object".to_owned())
    })?;
    let Some(snapshot_file) = object.get("snapshot_file") else {
        return Ok(None);
    };
    let path = snapshot_file
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| ClientError::Transport("snapshot file path must be a string".to_owned()))?;
    let byte_length = object
        .get("byte_length")
        .and_then(Value::as_u64)
        .ok_or_else(|| ClientError::Transport("snapshot file length is missing".to_owned()))?;
    let content_sha256 = object
        .get("content_sha256")
        .and_then(Value::as_str)
        .filter(|digest| is_sha256_hex(digest))
        .ok_or_else(|| ClientError::Transport("snapshot file digest is invalid".to_owned()))?
        .to_owned();
    Ok(Some((path, byte_length, content_sha256)))
}

fn read_caller_snapshot_file(
    path: &Path,
    byte_length: u64,
    content_sha256: &str,
) -> Result<Vec<u8>, ClientError> {
    if !path.is_absolute() {
        return Err(ClientError::Transport(
            "snapshot file path must be absolute".to_owned(),
        ));
    }
    let expected_length = usize::try_from(byte_length).map_err(|_| ClientError::RequestTooLarge)?;
    if expected_length == 0 || expected_length > MAX_SNAPSHOT_TRANSPORT_BYTES {
        return Err(ClientError::RequestTooLarge);
    }
    let bytes = fs::read(path)
        .map_err(|error| ClientError::Transport(format!("read caller snapshot file: {error}")))?;
    if bytes.len() != expected_length {
        return Err(ClientError::Transport(
            "caller snapshot file length differs from metadata".to_owned(),
        ));
    }
    if sha256_hex(&bytes) != content_sha256 {
        return Err(ClientError::Transport(
            "caller snapshot file digest differs from metadata".to_owned(),
        ));
    }
    Ok(bytes)
}

fn snapshot_transport_file(request: &Request) -> Option<PathBuf> {
    if request.op != Operation::SnapshotRestore {
        return None;
    }
    let common = request
        .payload
        .pointer("/common_portability/action")
        .is_some_and(|value| value == "snapshot_restore");
    let pointer = if common {
        "/common_portability/snapshot_file"
    } else {
        "/snapshot_file"
    };
    request
        .payload
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(PathBuf::from)
}

fn is_snapshot_transport_path(root: &Path, namespace: &str, path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Some(directory) = snapshot_directory(root, namespace).ok() else {
        return false;
    };
    let Ok(canonical_directory) = fs::canonicalize(directory) else {
        return false;
    };
    let Ok(canonical_path) = fs::canonicalize(path) else {
        return false;
    };
    canonical_path.parent() == Some(canonical_directory.as_path())
}

fn set_snapshot_transport(
    request: &mut Request,
    destination: &Path,
    byte_length: usize,
    content_sha256: &str,
) -> Result<(), ClientError> {
    let common = request
        .payload
        .pointer("/common_portability/action")
        .is_some_and(|value| value == "snapshot_restore");
    let object = (if common {
        request
            .payload
            .get_mut("common_portability")
            .and_then(Value::as_object_mut)
    } else {
        request.payload.as_object_mut()
    })
    .ok_or_else(|| {
        ClientError::Transport("snapshot restore payload must be an object".to_owned())
    })?;
    object.remove(if common { "bytes" } else { "snapshot" });
    object.insert(
        "snapshot_file".to_owned(),
        Value::String(destination.to_string_lossy().into_owned()),
    );
    object.insert(
        "byte_length".to_owned(),
        Value::from(u64::try_from(byte_length).map_err(|_| ClientError::RequestTooLarge)?),
    );
    object.insert(
        "content_sha256".to_owned(),
        Value::String(content_sha256.to_owned()),
    );
    Ok(())
}

fn write_snapshot_file(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
    temporary_name: &str,
) -> Result<(), ClientError> {
    atomic_write(&directory.join(temporary_name), destination, bytes)
        .map_err(ClientError::Transport)
}

fn cleanup_snapshot_backup(path: Option<&Path>) {
    remove_transport_file(path);
}

fn cleanup_snapshot_files(files: &[OwnedSnapshotFiles]) {
    for files in files {
        remove_transport_file(Some(&files.send_file));
        cleanup_snapshot_backup(files.backup_file.as_deref());
    }
}

fn cleanup_retained_snapshot(retained: &RetainedRequest) {
    remove_transport_file(snapshot_transport_file(&retained.request).as_deref());
    cleanup_snapshot_backup(retained.snapshot_backup.as_deref());
}

fn retained_request_size(
    request: &Request,
    identity_digest: &str,
    snapshot_backup: Option<&Path>,
) -> Result<usize, ClientError> {
    let request_bytes = serde_json::to_vec(request)
        .map_err(|error| ClientError::Transport(format!("serialize retained request: {error}")))?
        .len();
    request_bytes
        .checked_add(identity_digest.len())
        .and_then(|bytes| {
            snapshot_transport_file(request)
                .and_then(|path| path.to_str().map(str::len))
                .unwrap_or(0)
                .checked_add(bytes)
        })
        .and_then(|bytes| {
            snapshot_backup
                .and_then(|path| path.to_str().map(str::len))
                .unwrap_or(0)
                .checked_add(bytes)
        })
        .ok_or(ClientError::UnknownRetentionLimit { op_id: request.id })
}

#[derive(serde::Serialize)]
struct RequestIdentity<'a> {
    protocol_version: u16,
    op: Operation,
    namespace: &'a str,
    payload: &'a Value,
}

struct DigestSink(Sha256);

impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn request_identity_digest(request: &Request) -> Result<String, ClientError> {
    let mut payload = request.payload.clone();
    normalize_snapshot_transport_identity(request.op, &mut payload);
    let identity = RequestIdentity {
        protocol_version: request.protocol_version,
        op: request.op,
        namespace: &request.namespace,
        payload: &payload,
    };
    let mut sink = DigestSink(Sha256::new());
    serde_json::to_writer(&mut sink, &identity)
        .map_err(|error| ClientError::Transport(format!("digest retained request: {error}")))?;
    Ok(hex_digest(&sink.0.finalize()))
}

fn normalize_snapshot_transport_identity(operation: Operation, payload: &mut Value) {
    if operation != Operation::SnapshotRestore {
        return;
    }
    if let Some(object) = payload.as_object_mut() {
        if let Some(common) = object
            .get_mut("common_portability")
            .and_then(Value::as_object_mut)
            && common.get("action").and_then(Value::as_str) == Some("snapshot_restore")
        {
            common.remove("snapshot_file");
            return;
        }
        object.remove("snapshot_file");
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn normalize_result(
    request: &Request,
    result: &Result<Reply, ClientError>,
) -> Result<Reply, ClientError> {
    match result {
        Ok(reply) => Ok(normalize_reply(request, reply.clone())),
        Err(error) => Err(error.clone()),
    }
}

fn normalize_reply(request: &Request, mut reply: Reply) -> Reply {
    if request.op.is_mutating()
        && reply.outcome == crate::engine::Outcome::Corrupt
        && post_commit_corrupt_evidence(request, &reply)
    {
        reply.outcome = crate::engine::Outcome::EffectUnknown;
        match reply.payload.as_mut() {
            Some(payload) => {
                if let Some(object) = payload.as_object_mut() {
                    object.insert("post_commit_corrupt".to_owned(), Value::Bool(true));
                    object.insert("reconciliation_required".to_owned(), Value::Bool(true));
                    object.insert("commit_seq".to_owned(), Value::from(reply.state_generation));
                } else {
                    reply.payload = Some(json!({
                        "post_commit_corrupt": true,
                        "reconciliation_required": true,
                        "commit_seq": reply.state_generation,
                    }));
                }
            }
            None => {
                reply.payload = Some(json!({
                    "post_commit_corrupt": true,
                    "reconciliation_required": true,
                    "commit_seq": reply.state_generation,
                }));
            }
        }
    }
    reply
}

fn post_commit_corrupt_evidence(request: &Request, reply: &Reply) -> bool {
    if let Some(payload) = reply.payload.as_ref().and_then(Value::as_object) {
        if [
            "post_commit",
            "post_commit_corrupt",
            "committed",
            "effect_unknown",
            "reconciliation_required",
        ]
        .iter()
        .any(|field| payload.get(*field).and_then(Value::as_bool) == Some(true))
        {
            return true;
        }
        if payload
            .get("commit_seq")
            .and_then(Value::as_u64)
            .is_some_and(|sequence| sequence == reply.state_generation && sequence > 0)
        {
            return true;
        }
    }
    let Some(expected) = expected_generation(request) else {
        return false;
    };
    reply.state_generation > expected
}

fn expected_generation(request: &Request) -> Option<u64> {
    request
        .payload
        .get("expected_generation")
        .or_else(|| {
            request
                .payload
                .pointer("/common_control/expected_generation")
        })
        .or_else(|| {
            request
                .payload
                .pointer("/common_portability/expected_generation")
        })
        .and_then(Value::as_u64)
}

fn durable_no_effect_proof(_outcome: &crate::engine::Outcome, payload: &Value) -> bool {
    payload
        .get("durable_no_effect")
        .and_then(Value::as_bool)
        .or_else(|| payload.get("no_effect").and_then(Value::as_bool))
        == Some(true)
}

fn snapshot_directory(root: &Path, namespace: &str) -> Result<PathBuf, String> {
    if namespace.len() != 64
        || !namespace
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("snapshot namespace must be lowercase sha256 hex".to_owned());
    }
    Ok(root.join("namespaces").join(namespace).join("snapshots"))
}

fn atomic_write(temporary_file: &Path, destination: &Path, bytes: &[u8]) -> Result<(), String> {
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary_file)
            .map_err(|error| format!("create snapshot transport file: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("write snapshot transport file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync snapshot transport file: {error}"))?;
        fs::rename(temporary_file, destination)
            .map_err(|error| format!("publish snapshot transport file: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary_file);
    }
    result
}

fn read_verified_snapshot_file(
    root: &Path,
    namespace: &str,
    snapshot_file: &Path,
    byte_length: u64,
    content_sha256: &str,
) -> Result<Vec<u8>, ClientError> {
    if !snapshot_file.is_absolute() || !is_sha256_hex(content_sha256) {
        return Err(ClientError::MalformedReply(
            "invalid snapshot export file metadata".to_owned(),
        ));
    }
    let expected_length = usize::try_from(byte_length)
        .map_err(|_| ClientError::MalformedReply("snapshot export length overflow".to_owned()))?;
    if expected_length == 0 || expected_length > MAX_SNAPSHOT_TRANSPORT_BYTES {
        return Err(ClientError::MalformedReply(
            "snapshot export length is outside the snapshot budget".to_owned(),
        ));
    }
    let directory = snapshot_directory(root, namespace).map_err(ClientError::MalformedReply)?;
    let canonical_directory = fs::canonicalize(&directory).map_err(|error| {
        ClientError::MalformedReply(format!("open snapshot export directory: {error}"))
    })?;
    let canonical_file = fs::canonicalize(snapshot_file).map_err(|error| {
        ClientError::MalformedReply(format!("open snapshot export file: {error}"))
    })?;
    if !canonical_file.starts_with(&canonical_directory)
        || canonical_file.parent() != Some(canonical_directory.as_path())
    {
        return Err(ClientError::MalformedReply(
            "snapshot export file escapes namespace directory".to_owned(),
        ));
    }
    let _guard = SnapshotFileGuard {
        path: canonical_file.clone(),
    };
    let file = File::open(&canonical_file).map_err(|error| {
        ClientError::MalformedReply(format!("open snapshot export file: {error}"))
    })?;
    let actual_length = file
        .metadata()
        .map_err(|error| {
            ClientError::MalformedReply(format!("inspect snapshot export file: {error}"))
        })?
        .len();
    if actual_length != byte_length {
        return Err(ClientError::MalformedReply(
            "snapshot export byte length mismatch".to_owned(),
        ));
    }
    let read_limit = byte_length.checked_add(1).ok_or_else(|| {
        ClientError::MalformedReply("snapshot export read limit overflow".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(expected_length);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ClientError::MalformedReply(format!("read snapshot export file: {error}"))
        })?;
    if bytes.len() != expected_length || sha256_hex(&bytes) != content_sha256 {
        return Err(ClientError::MalformedReply(
            "snapshot export content verification failed".to_owned(),
        ));
    }
    Ok(bytes)
}

fn remove_transport_file(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct SnapshotFileGuard {
    path: PathBuf,
}

impl Drop for SnapshotFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Ok(owner) = self.owner.get_mut()
            && let Some(owner) = owner.take()
        {
            let _ = owner.join();
        }
        if let Ok(mut unknown) = self.unknown.lock() {
            let retained = std::mem::take(&mut unknown.entries);
            unknown.bytes = 0;
            unknown.reservations.clear();
            unknown.reserved_bytes = 0;
            for retained in retained.into_values() {
                cleanup_retained_snapshot(&retained);
            }
        }
    }
}

fn idempotency_key(request: &Request) -> Option<&str> {
    if request.op.is_mutating() {
        request
            .payload
            .pointer("/common_control/idempotency_key")
            .or_else(|| {
                request
                    .payload
                    .pointer("/common_portability/idempotency_key")
            })
            .or_else(|| request.payload.get("idempotency_key"))
            .and_then(Value::as_str)
    } else {
        None
    }
}

enum OwnerMessage {
    Call(OwnerCommand),
    Start(OwnerStart),
}

struct OwnerStart {
    expires: Instant,
    response: SyncSender<Result<(), ClientError>>,
}

struct OwnerCommand {
    request: Request,
    expires: Instant,
    queued_bytes: usize,
    response: SyncSender<Result<Reply, ClientError>>,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

#[derive(Clone)]
struct Launch {
    binary: PathBuf,
    root: PathBuf,
    test_double: bool,
    no_encoder_required: bool,
    max_restart_attempts: u32,
}

fn owner_loop(
    calls: Receiver<OwnerMessage>,
    shutdown: Arc<AtomicBool>,
    pid: Arc<AtomicU32>,
    owner_incarnation: Arc<AtomicU64>,
    queued_bytes: Arc<AtomicUsize>,
    launch: Launch,
    lifecycle: Arc<LifecycleState>,
) {
    let mut process: Option<WorkerProcess> = None;
    let mut restart_failures = 0_u32;
    while !shutdown.load(Ordering::Acquire) {
        let requested = lifecycle.requested.load(Ordering::Acquire);
        if requested > lifecycle.completed.load(Ordering::Acquire) {
            if let Some(worker) = process.take() {
                worker.terminate(!lifecycle.force.load(Ordering::Acquire));
            }
            restart_failures = 0;
            lifecycle.completed.store(requested, Ordering::Release);
        }
        let command = match calls.recv_timeout(Duration::from_millis(10)) {
            Ok(OwnerMessage::Call(command)) => command,
            Ok(OwnerMessage::Start(command)) => {
                let result = start_owner_process(
                    &mut process,
                    &mut restart_failures,
                    &launch,
                    &pid,
                    &owner_incarnation,
                    command.expires,
                    &shutdown,
                );
                let _ = command.response.send(result);
                continue;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        queued_bytes.fetch_sub(command.queued_bytes, Ordering::AcqRel);
        if (command.cancelled)() || Instant::now() >= command.expires {
            let _ = command.response.send(Err(ClientError::Cancelled));
            continue;
        }
        if process.is_none() {
            match spawn_owner_process(&launch, &pid, &owner_incarnation, &mut restart_failures) {
                Ok(worker) => process = Some(worker),
                Err(error) => {
                    let _ = command.response.send(Err(error));
                    continue;
                }
            }
        }
        let mut restart_failure_recorded = false;
        let mut result = match process.as_mut() {
            Some(worker) => execute_owner_command(worker, &command, &shutdown),
            None => Err(ClientError::OwnerStopped),
        };
        // A killed worker can be discovered by the first namespace operation
        // rather than by a separate health probe. Read-only operations are
        // safe to retry after the dead process is reaped; the replacement's
        // empty readiness set forces a real namespace handshake before recall.
        if should_retry_after_worker_loss(&command.request, &result) {
            if let Some(worker) = process.take() {
                worker.terminate(false);
            }
            if !shutdown.load(Ordering::Acquire)
                && !(command.cancelled)()
                && remaining(command.expires).is_some()
            {
                match WorkerProcess::spawn(&launch, Arc::clone(&pid)) {
                    Ok(worker) => {
                        owner_incarnation.fetch_add(1, Ordering::AcqRel);
                        process = Some(worker);
                        result = match process.as_mut() {
                            Some(worker) => execute_owner_command(worker, &command, &shutdown),
                            None => Err(ClientError::OwnerStopped),
                        };
                    }
                    Err(error) => {
                        if !matches!(&error, ClientError::Unavailable(_)) {
                            restart_failures = restart_failures.saturating_add(1);
                            restart_failure_recorded = true;
                        }
                        result = Err(if restart_failures > launch.max_restart_attempts {
                            ClientError::RestartExhausted
                        } else {
                            error
                        });
                    }
                }
            }
        }
        let abnormal = process
            .as_ref()
            .is_some_and(|worker| worker.must_retire_after(&result));
        if abnormal && let Some(worker) = process.take() {
            worker.terminate(false);
        }
        if abnormal && !(command.cancelled)() && !restart_failure_recorded {
            restart_failures = restart_failures.saturating_add(1);
        } else if result.is_ok() {
            restart_failures = 0;
        }
        let _ = command.response.send(result);
    }
    if let Some(worker) = process {
        worker.terminate(true);
    }
    pid.store(0, Ordering::Release);
}

fn spawn_owner_process(
    launch: &Launch,
    pid: &Arc<AtomicU32>,
    owner_incarnation: &AtomicU64,
    restart_failures: &mut u32,
) -> Result<WorkerProcess, ClientError> {
    if *restart_failures > launch.max_restart_attempts {
        return Err(ClientError::RestartExhausted);
    }
    match WorkerProcess::spawn(launch, Arc::clone(pid)) {
        Ok(worker) => {
            owner_incarnation.fetch_add(1, Ordering::AcqRel);
            Ok(worker)
        }
        Err(error) => {
            if matches!(&error, ClientError::Unavailable(_)) {
                return Err(error);
            }
            *restart_failures = restart_failures.saturating_add(1);
            Err(if *restart_failures > launch.max_restart_attempts {
                ClientError::RestartExhausted
            } else {
                error
            })
        }
    }
}

fn start_owner_process(
    process: &mut Option<WorkerProcess>,
    restart_failures: &mut u32,
    launch: &Launch,
    pid: &Arc<AtomicU32>,
    owner_incarnation: &AtomicU64,
    expires: Instant,
    shutdown: &AtomicBool,
) -> Result<(), ClientError> {
    if shutdown.load(Ordering::Acquire) || remaining(expires).is_none() {
        return Err(ClientError::Cancelled);
    }
    // The readiness set belongs to this exact child and verified launch
    // artifact. A remembered PID or incarnation alone cannot prove liveness.
    if let Some(worker) = process.as_mut() {
        match worker.child.try_wait() {
            Ok(None) => {}
            Ok(Some(_)) => {
                if let Some(worker) = process.take() {
                    worker.terminate(false);
                }
            }
            Err(error) => {
                if let Some(worker) = process.take() {
                    worker.terminate(false);
                }
                *restart_failures = restart_failures.saturating_add(1);
                return Err(ClientError::Transport(error.to_string()));
            }
        }
    }
    if shutdown.load(Ordering::Acquire) || remaining(expires).is_none() {
        return Err(ClientError::Cancelled);
    }
    if process.is_none() {
        *process = Some(spawn_owner_process(
            launch,
            pid,
            owner_incarnation,
            restart_failures,
        )?);
    }
    if let Some(worker) = process.as_mut()
        && worker.ready_namespaces.contains(GLOBAL_READINESS_NAMESPACE)
    {
        // An expired borrower has not touched the wire and must not retire
        // the healthy shared child whose readiness it was asking to reuse.
        return worker.ensure_ready(GLOBAL_READINESS_NAMESPACE, expires, shutdown, &|| false);
    }
    let result = match process.as_mut() {
        Some(worker) => {
            worker.ensure_ready(GLOBAL_READINESS_NAMESPACE, expires, shutdown, &|| false)
        }
        None => Err(ClientError::OwnerStopped),
    };
    if process
        .as_ref()
        .is_some_and(|worker| worker.must_retire_after(&result))
    {
        if let Some(worker) = process.take() {
            worker.terminate(false);
        }
        *restart_failures = restart_failures.saturating_add(1);
    } else if result.is_ok() {
        *restart_failures = 0;
    }
    result
}

fn execute_owner_command(
    worker: &mut WorkerProcess,
    command: &OwnerCommand,
    shutdown: &AtomicBool,
) -> Result<Reply, ClientError> {
    let result = if requires_readiness(&command.request) {
        worker.ensure_ready(
            &command.request.namespace,
            command.expires,
            shutdown,
            command.cancelled.as_ref(),
        )
    } else {
        Ok(())
    }
    .and_then(|()| {
        worker.execute(
            &command.request,
            command.expires,
            shutdown,
            command.cancelled.as_ref(),
        )
    });
    if let Ok(reply) = &result
        && command.request.op == Operation::Handshake
        && reply.outcome == crate::engine::Outcome::Success
    {
        worker.mark_ready(&command.request.namespace);
    }
    if let Some(reply) = result.as_ref().ok()
        && matches!(
            &reply.outcome,
            crate::engine::Outcome::Unavailable(_) | crate::engine::Outcome::Corrupt
        )
    {
        worker.invalidate_ready(&command.request.namespace);
    }
    result
}

fn should_retry_after_worker_loss(request: &Request, result: &Result<Reply, ClientError>) -> bool {
    if matches!(request.op, Operation::Health) || request.op.is_mutating() {
        return false;
    }
    matches!(
        result,
        Err(ClientError::MalformedReply(_))
            | Err(ClientError::Transport(_))
            | Err(ClientError::WorkerExited)
    )
}

enum WriterCommand {
    Frame(Vec<u8>, SyncSender<Result<(), String>>),
    Shutdown,
}

struct WorkerProcess {
    child: Child,
    _artifact: Option<VerifiedWorkerArtifact>,
    writer: SyncSender<WriterCommand>,
    replies: Receiver<Result<Reply, String>>,
    writer_thread: JoinHandle<()>,
    reader_thread: JoinHandle<()>,
    pid: Arc<AtomicU32>,
    ready_namespaces: BTreeSet<String>,
    exchange_pending: bool,
}

impl WorkerProcess {
    fn spawn(launch: &Launch, pid: Arc<AtomicU32>) -> Result<Self, ClientError> {
        let artifact = if launch.test_double {
            None
        } else {
            Some(
                stage_verified_worker_binary(&launch.binary)
                    .map_err(|error| ClientError::Unavailable(error.to_string()))?,
            )
        };
        let binary = artifact
            .as_ref()
            .map(VerifiedWorkerArtifact::path)
            .unwrap_or(launch.binary.as_path());
        let mut command = ProcessCommand::new(binary);
        command
            .arg("--state-root")
            .arg(&launch.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if launch.test_double {
            command.arg("--test-double");
        }
        if launch.no_encoder_required {
            command.arg("--no-encoder-required");
        }
        let mut child = command
            .spawn()
            .map_err(|error| ClientError::Spawn(error.to_string()))?;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ClientError::Spawn("worker stdin was not piped".to_owned()));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                drop(stdin);
                let _ = child.kill();
                let _ = child.wait();
                return Err(ClientError::Spawn("worker stdout was not piped".to_owned()));
            }
        };

        let (writer, writer_rx) = mpsc::sync_channel::<WriterCommand>(1);
        let writer_thread = match thread::Builder::new()
            .name("ncm-worker-writer".to_owned())
            .spawn(move || writer_loop(stdin, writer_rx))
        {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ClientError::Spawn(error.to_string()));
            }
        };
        let (reply_tx, replies) = mpsc::sync_channel(1);
        let reader_thread = match thread::Builder::new()
            .name("ncm-worker-reader".to_owned())
            .spawn(move || reader_loop(stdout, reply_tx))
        {
            Ok(handle) => handle,
            Err(error) => {
                drop(writer);
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer_thread.join();
                return Err(ClientError::Spawn(error.to_string()));
            }
        };
        pid.store(child.id(), Ordering::Release);
        Ok(Self {
            child,
            _artifact: artifact,
            writer,
            replies,
            writer_thread,
            reader_thread,
            pid,
            ready_namespaces: BTreeSet::new(),
            exchange_pending: false,
        })
    }

    fn must_retire_after<T>(&self, result: &Result<T, ClientError>) -> bool {
        match result {
            // Cancellation before dispatch or after a fully consumed handshake
            // leaves the shared transport synchronized. An outstanding frame
            // still requires reap so its late reply cannot answer another call.
            Err(ClientError::Cancelled) => self.exchange_pending,
            Err(
                ClientError::EffectUnknown { .. }
                | ClientError::Transport(_)
                | ClientError::MalformedReply(_)
                | ClientError::WorkerExited,
            ) => true,
            _ => false,
        }
    }

    fn ensure_ready(
        &mut self,
        namespace: &str,
        expires: Instant,
        shutdown: &AtomicBool,
        cancelled: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<(), ClientError> {
        if shutdown.load(Ordering::Acquire) || cancelled() || remaining(expires).is_none() {
            return Err(ClientError::Cancelled);
        }
        if self.ready_namespaces.contains(namespace) {
            return Ok(());
        }
        let remaining = remaining(expires).ok_or(ClientError::Cancelled)?;
        let request = Request::new(
            0,
            u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .max(1),
            Operation::Handshake,
            namespace,
            json!({
                "protocol_version": wire::PROTOCOL_VERSION,
                "protocol_identity": wire::PROTOCOL_IDENTITY,
                "algorithm_profile": "ncm-biomem-rs.v1"
            }),
        );
        let reply = self.execute(&request, expires, shutdown, cancelled)?;
        match reply.outcome {
            crate::engine::Outcome::Success => {
                self.ready_namespaces.insert(namespace.to_owned());
                Ok(())
            }
            crate::engine::Outcome::Cancelled => Err(ClientError::Cancelled),
            crate::engine::Outcome::Unavailable(detail) => Err(ClientError::Unavailable(detail)),
            outcome => Err(ClientError::Unavailable(format!(
                "worker readiness refused: {outcome:?}"
            ))),
        }
    }

    fn mark_ready(&mut self, namespace: &str) {
        self.ready_namespaces.insert(namespace.to_owned());
    }

    fn invalidate_ready(&mut self, namespace: &str) {
        self.ready_namespaces.remove(namespace);
    }

    fn execute(
        &mut self,
        request: &Request,
        expires: Instant,
        shutdown: &AtomicBool,
        cancelled: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<Reply, ClientError> {
        if cancelled() {
            return Err(ClientError::Cancelled);
        }
        let remaining = remaining(expires).ok_or_else(|| timeout_error(request))?;
        let mut outbound = request.clone();
        outbound.deadline_ms = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let frame = wire::encode_request(&outbound).map_err(|error| match error {
            wire::FrameError::Oversized { .. } => ClientError::RequestTooLarge,
            other => ClientError::Transport(other.to_string()),
        })?;
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.writer
            .send(WriterCommand::Frame(frame, ack_tx))
            .map_err(|_| ClientError::WorkerExited)?;
        self.exchange_pending = true;
        match wait_channel(&ack_rx, expires, shutdown, cancelled) {
            Ok(Ok(())) => {}
            Ok(Err(detail)) => return Err(ClientError::Transport(detail)),
            Err(WaitError::Deadline) => return Err(timeout_error(request)),
            // The writer may have sent the frame before cancellation was
            // observed. A mutating operation is indeterminate until reconciled.
            Err(WaitError::Shutdown) => {
                return Err(indeterminate_or(request, ClientError::Cancelled));
            }
            Err(WaitError::Disconnected) => return Err(ClientError::WorkerExited),
        }
        let reply = match wait_channel(&self.replies, expires, shutdown, cancelled) {
            Ok(Ok(reply)) => reply,
            Ok(Err(detail)) => {
                return Err(indeterminate_or(
                    request,
                    ClientError::MalformedReply(detail),
                ));
            }
            Err(WaitError::Deadline) => return Err(timeout_error(request)),
            Err(WaitError::Shutdown) => {
                return Err(indeterminate_or(request, ClientError::Cancelled));
            }
            Err(WaitError::Disconnected) => {
                return Err(indeterminate_or(request, ClientError::WorkerExited));
            }
        };
        if reply.id != request.id {
            return Err(indeterminate_or(
                request,
                ClientError::MalformedReply(format!(
                    "reply id {} does not match request {}",
                    reply.id, request.id
                )),
            ));
        }
        self.exchange_pending = false;
        Ok(reply)
    }

    fn terminate(mut self, graceful: bool) {
        if graceful {
            let _ = self.writer.try_send(WriterCommand::Shutdown);
            if wait_for_exit(&mut self.child, KILL_ESCALATION) {
                self.finish_threads();
                return;
            }
        }
        let _ = self.child.kill();
        let _ = wait_for_exit(&mut self.child, KILL_ESCALATION);
        let _ = self.child.wait();
        self.finish_threads();
    }

    fn finish_threads(self) {
        self.pid.store(0, Ordering::Release);
        drop(self.writer);
        let _ = self.writer_thread.join();
        let _ = self.reader_thread.join();
    }
}

fn requires_readiness(request: &Request) -> bool {
    if !is_sha256_hex(&request.namespace) {
        return false;
    }
    match request.op {
        Operation::Handshake => false,
        Operation::Health => {
            !request.namespace.is_empty() || request.payload.get("common_control").is_some()
        }
        _ => true,
    }
}

fn writer_loop(mut stdin: std::process::ChildStdin, commands: Receiver<WriterCommand>) {
    while let Ok(command) = commands.recv() {
        match command {
            WriterCommand::Frame(frame, acknowledgement) => {
                let result = stdin
                    .write_all(&frame)
                    .and_then(|()| stdin.flush())
                    .map_err(|error| error.to_string());
                let failed = result.is_err();
                let _ = acknowledgement.send(result);
                if failed {
                    break;
                }
            }
            WriterCommand::Shutdown => break,
        }
    }
}

fn reader_loop(mut stdout: std::process::ChildStdout, replies: SyncSender<Result<Reply, String>>) {
    loop {
        match wire::read_reply(&mut stdout) {
            Ok(Some(reply)) => {
                if replies.send(Ok(reply)).is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = replies.send(Err("worker stdout reached EOF".to_owned()));
                break;
            }
            Err(error) => {
                let _ = replies.send(Err(error.to_string()));
                break;
            }
        }
    }
}

fn remaining(expires: Instant) -> Option<Duration> {
    expires.checked_duration_since(Instant::now())
}

fn timeout_error(request: &Request) -> ClientError {
    if request.op.is_mutating() {
        ClientError::EffectUnknown { op_id: request.id }
    } else {
        ClientError::Cancelled
    }
}

fn indeterminate_or(request: &Request, otherwise: ClientError) -> ClientError {
    if request.op.is_mutating() {
        ClientError::EffectUnknown { op_id: request.id }
    } else {
        otherwise
    }
}

enum WaitError {
    Deadline,
    Shutdown,
    Disconnected,
}

fn wait_channel<T>(
    receiver: &Receiver<T>,
    expires: Instant,
    shutdown: &AtomicBool,
    cancelled: &(dyn Fn() -> bool + Send + Sync),
) -> Result<T, WaitError> {
    loop {
        if shutdown.load(Ordering::Acquire) || cancelled() {
            return Err(WaitError::Shutdown);
        }
        let remaining = remaining(expires).ok_or(WaitError::Deadline)?;
        let slice = remaining.min(Duration::from_millis(10));
        match receiver.recv_timeout(slice) {
            Ok(value) => return Ok(value),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(WaitError::Disconnected),
        }
    }
}

fn wait_for_exit(child: &mut Child, budget: Duration) -> bool {
    let deadline = Instant::now()
        .checked_add(budget)
        .unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_client() -> WorkerClient {
        let (calls, _receiver) = mpsc::sync_channel(1);
        WorkerClient {
            calls,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            unknown: Arc::new(Mutex::new(UnknownRequests::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
            owner: Mutex::new(None),
            pid: Arc::new(AtomicU32::new(0)),
            owner_incarnation: Arc::new(AtomicU64::new(0)),
            fenced: Arc::new(AtomicBool::new(false)),
            ledger_generation: AtomicU64::new(0),
            reconcile_gate: Mutex::new(()),
            reconciliation_deadline: Duration::from_secs(1),
            root: PathBuf::from("/"),
            lifecycle: Arc::new(LifecycleState::default()),
        }
    }

    fn test_client_with_owner(
        outcomes: Vec<crate::engine::Outcome>,
    ) -> (WorkerClient, Arc<Mutex<Vec<Operation>>>) {
        let (calls, receiver): (SyncSender<OwnerMessage>, Receiver<OwnerMessage>) =
            mpsc::sync_channel(MAX_QUEUED_REQUESTS);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let pid = Arc::new(AtomicU32::new(0));
        let owner_incarnation = Arc::new(AtomicU64::new(0));
        let lifecycle = Arc::new(LifecycleState::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_events = Arc::clone(&events);
        let owner_shutdown = Arc::clone(&shutdown);
        let owner_pid = Arc::clone(&pid);
        let owner_incarnations = Arc::clone(&owner_incarnation);
        let owner_queued_bytes = Arc::clone(&queued_bytes);
        let owner_lifecycle = Arc::clone(&lifecycle);
        let owner = thread::spawn(move || {
            let mut process_alive = false;
            let outcomes = Mutex::new(outcomes);
            while !owner_shutdown.load(Ordering::Acquire) {
                let requested = owner_lifecycle.requested.load(Ordering::Acquire);
                if requested > owner_lifecycle.completed.load(Ordering::Acquire) {
                    process_alive = false;
                    owner_pid.store(0, Ordering::Release);
                    owner_lifecycle
                        .completed
                        .store(requested, Ordering::Release);
                }
                let command = match receiver.recv_timeout(Duration::from_millis(2)) {
                    Ok(OwnerMessage::Call(command)) => command,
                    Ok(OwnerMessage::Start(command)) => {
                        owner_events
                            .lock()
                            .expect("owner events lock")
                            .push(Operation::Handshake);
                        if !process_alive {
                            owner_incarnations.fetch_add(1, Ordering::AcqRel);
                        }
                        process_alive = true;
                        owner_pid.store(123, Ordering::Release);
                        let _ = command.response.send(Ok(()));
                        continue;
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                owner_queued_bytes.fetch_sub(command.queued_bytes, Ordering::AcqRel);
                if (command.cancelled)() {
                    let _ = command.response.send(Err(ClientError::Cancelled));
                    continue;
                }
                owner_events
                    .lock()
                    .expect("owner events lock")
                    .push(command.request.op);
                let outcome = if command.request.op == Operation::Handshake {
                    if !process_alive {
                        owner_incarnations.fetch_add(1, Ordering::AcqRel);
                    }
                    process_alive = true;
                    owner_pid.store(123, Ordering::Release);
                    crate::engine::Outcome::Success
                } else {
                    outcomes
                        .lock()
                        .expect("owner outcomes lock")
                        .pop()
                        .unwrap_or(crate::engine::Outcome::Success)
                };
                let _ = command.response.send(Ok(Reply {
                    id: command.request.id,
                    outcome,
                    state_generation: 1,
                    payload: None,
                    error: None,
                }));
            }
        });
        (
            WorkerClient {
                calls,
                queued_bytes,
                unknown: Arc::new(Mutex::new(UnknownRequests::default())),
                shutdown,
                owner: Mutex::new(Some(owner)),
                pid,
                owner_incarnation,
                fenced: Arc::new(AtomicBool::new(false)),
                ledger_generation: AtomicU64::new(0),
                reconcile_gate: Mutex::new(()),
                reconciliation_deadline: Duration::from_secs(1),
                root: PathBuf::from("/"),
                lifecycle,
            },
            events,
        )
    }

    fn mutating_request(namespace: &str, idempotency_key: &str) -> Request {
        Request::new(
            1,
            1_000,
            Operation::Observe,
            namespace,
            json!({"idempotency_key": idempotency_key}),
        )
    }

    fn wire_reply(outcome: crate::engine::Outcome) -> Reply {
        Reply {
            id: 1,
            outcome,
            state_generation: 1,
            payload: None,
            error: None,
        }
    }

    fn update_unknown(
        client: &WorkerClient,
        request: &Request,
        result: &Result<Reply, ClientError>,
    ) -> Result<bool, ClientError> {
        client.update_unknown_with_retained(request, request, result, None, None, None)
    }

    #[test]
    fn spawn_requires_an_absolute_worker_path() {
        let root = tempfile::tempdir().expect("state root");
        assert!(matches!(
            WorkerClient::spawn("tracedecay-ncm-worker", root.path(), WorkerOptions::default()),
            Err(ClientError::Spawn(detail)) if detail == "worker binary path must be absolute"
        ));
    }

    #[test]
    fn idempotency_key_reads_common_control_before_legacy_fields() {
        let request = Request::new(
            1,
            1_000,
            Operation::Maintenance,
            "namespace",
            serde_json::json!({
                "idempotency_key": "legacy-key",
                "common_control": {"idempotency_key": "common-key"}
            }),
        );
        assert_eq!(idempotency_key(&request), Some("common-key"));
    }

    #[test]
    fn wire_effect_unknown_is_retained_until_reconciliation_resolves_it() {
        let client = test_client();
        let request = mutating_request("namespace-a", "committed-unknown");
        let retained_key = (request.namespace.clone(), "committed-unknown".to_owned());

        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );
        assert!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );

        // Cancellation of a replay attempt does not resolve the original
        // unknown effect; it also does not create a second retained entry.
        let _ = update_unknown(&client, &request, &Err(ClientError::Cancelled));
        assert!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );

        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::Success)),
        );
        assert!(
            !client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );
        assert!(!client.fenced.load(Ordering::Acquire));
    }

    #[test]
    fn fresh_unavailable_and_cancelled_replies_do_not_create_a_fence() {
        let client = test_client();
        let unavailable = mutating_request("namespace-a", "wire-unavailable");
        assert!(
            !update_unknown(
                &client,
                &unavailable,
                &Ok(wire_reply(crate::engine::Outcome::Unavailable(
                    "worker unavailable".to_owned(),
                )))
            )
            .expect("fresh wire unavailable is a known non-effect")
        );

        let corrupt = mutating_request("namespace-a", "wire-corrupt");
        assert!(
            !update_unknown(
                &client,
                &corrupt,
                &Ok(wire_reply(crate::engine::Outcome::Corrupt))
            )
            .expect("pre-effect corrupt remains ordinary")
        );

        let cancelled = mutating_request("namespace-a", "wire-cancelled");
        assert!(
            !update_unknown(
                &client,
                &cancelled,
                &Ok(wire_reply(crate::engine::Outcome::Cancelled))
            )
            .expect("worker cancellation is known no effect")
        );

        let unknown = client.unknown.lock().expect("unknown requests lock");
        assert!(unknown.entries.is_empty());
        assert!(unknown.reservations.is_empty());
        drop(unknown);
        assert!(!client.fenced.load(Ordering::Acquire));
    }

    #[test]
    fn same_idempotency_key_is_retained_and_cleared_per_namespace() {
        let client = test_client();
        let first = mutating_request("namespace-a", "shared-key");
        let second = mutating_request("namespace-b", "shared-key");
        let unknown = Ok(wire_reply(crate::engine::Outcome::EffectUnknown));
        let _ = update_unknown(&client, &first, &unknown);
        let _ = update_unknown(&client, &second, &unknown);

        let unknown_requests = client.unknown.lock().expect("unknown requests lock");
        assert_eq!(unknown_requests.len(), 2);
        assert_eq!(
            unknown_requests
                .get(&(first.namespace.clone(), "shared-key".to_owned()))
                .map(|retained| &retained.request),
            Some(&first)
        );
        assert_eq!(
            unknown_requests
                .get(&(second.namespace.clone(), "shared-key".to_owned()))
                .map(|retained| &retained.request),
            Some(&second)
        );
        drop(unknown_requests);

        let _ = update_unknown(
            &client,
            &first,
            &Ok(wire_reply(crate::engine::Outcome::Success)),
        );
        let unknown_requests = client.unknown.lock().expect("unknown requests lock");
        assert!(!unknown_requests.contains_key(&(first.namespace, "shared-key".to_owned())));
        assert!(unknown_requests.contains_key(&(second.namespace, "shared-key".to_owned())));
    }

    #[test]
    fn conflicting_same_key_reply_cannot_clear_the_original_request() {
        let client = test_client();
        let original = mutating_request("namespace-a", "same-key");
        let mut conflicting = mutating_request("namespace-a", "same-key");
        conflicting.payload["value"] = json!("different effect");

        let _ = update_unknown(
            &client,
            &original,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );
        let _ = update_unknown(
            &client,
            &conflicting,
            &Ok(wire_reply(crate::engine::Outcome::Success)),
        );
        assert_eq!(
            update_unknown(
                &client,
                &conflicting,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            ),
            Err(ClientError::UnknownRetentionConflict {
                op_id: conflicting.id
            })
        );

        let unknown = client.unknown.lock().expect("unknown requests lock");
        let retained = unknown
            .get(&(original.namespace.clone(), "same-key".to_owned()))
            .expect("original request remains retained");
        assert_eq!(retained.request, original);
        assert_ne!(
            retained.identity_digest.as_str(),
            request_identity_digest(&conflicting).expect("conflicting digest")
        );
    }

    #[test]
    fn request_digest_ignores_transport_id_and_deadline_but_covers_effect_payload() {
        let first = mutating_request("namespace-a", "same-key");
        let mut retry = first.clone();
        retry.id = 99;
        retry.deadline_ms = 7;
        assert_eq!(
            request_identity_digest(&first).expect("first digest"),
            request_identity_digest(&retry).expect("retry digest")
        );

        retry.payload["value"] = json!("different effect");
        assert_ne!(
            request_identity_digest(&first).expect("first digest"),
            request_identity_digest(&retry).expect("conflicting digest")
        );

        let file_request = Request::new(
            1,
            1_000,
            Operation::SnapshotRestore,
            "namespace-a",
            json!({
                "idempotency_key": "snapshot-key",
                "snapshot_file": "/caller/first.snapshot",
                "byte_length": 4,
                "content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }),
        );
        let mut retry_file = file_request.clone();
        retry_file.payload["snapshot_file"] = json!("/caller/retry.snapshot");
        assert_eq!(
            request_identity_digest(&file_request).expect("file digest"),
            request_identity_digest(&retry_file).expect("retry file digest")
        );
    }

    #[test]
    fn busy_and_idempotency_conflict_replies_keep_the_retained_request() {
        let client = test_client();
        let request = mutating_request("namespace-a", "busy-key");
        let retained_key = (request.namespace.clone(), "busy-key".to_owned());
        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );

        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::Busy)),
        );
        assert!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );

        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::Rejected(
                crate::engine::RejectReason::IdempotencyConflict,
            ))),
        );
        assert!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );
    }

    #[test]
    fn only_authoritative_success_or_durable_no_effect_resolves_unknown() {
        let client = test_client();
        let request = mutating_request("namespace-a", "resolution-key");
        let retained_key = (request.namespace.clone(), "resolution-key".to_owned());
        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );

        for outcome in [
            crate::engine::Outcome::Incompatible,
            crate::engine::Outcome::Unsupported,
            crate::engine::Outcome::BudgetExceeded,
            crate::engine::Outcome::Corrupt,
            crate::engine::Outcome::Rejected(crate::engine::RejectReason::InvalidRequest(
                "current request is invalid".to_owned(),
            )),
            crate::engine::Outcome::Rejected(crate::engine::RejectReason::SourceRevoked),
            crate::engine::Outcome::Rejected(crate::engine::RejectReason::IdempotencyConflict),
            crate::engine::Outcome::Rejected(crate::engine::RejectReason::UnknownRecord(
                tracedecay_memory_ncm_core::RecordId(7),
            )),
        ] {
            let _ = update_unknown(&client, &request, &Ok(wire_reply(outcome)));
            assert!(
                client
                    .unknown
                    .lock()
                    .expect("unknown requests lock")
                    .contains_key(&retained_key)
            );
        }

        let mut no_effect = wire_reply(crate::engine::Outcome::Empty);
        no_effect.payload = Some(json!({"durable_no_effect": true}));
        let _ = update_unknown(&client, &request, &Ok(no_effect));
        assert!(
            !client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );
    }

    #[test]
    fn post_commit_corrupt_is_normalized_but_pre_effect_corrupt_stays_ordinary() {
        let client = test_client();
        let request = mutating_request("namespace-a", "corrupt-key");

        let pre_effect = wire_reply(crate::engine::Outcome::Corrupt);
        let normalized = normalize_result(&request, &Ok(pre_effect.clone()))
            .expect("pre-effect reply normalizes");
        assert_eq!(normalized.outcome, crate::engine::Outcome::Corrupt);
        assert!(
            !update_unknown(&client, &request, &Ok(pre_effect))
                .expect("pre-effect corrupt is ordinary")
        );

        let mut post_commit = wire_reply(crate::engine::Outcome::Corrupt);
        post_commit.payload = Some(json!({"committed": true}));
        let normalized = normalize_result(&request, &Ok(post_commit.clone()))
            .expect("post-commit reply normalizes");
        assert_eq!(normalized.outcome, crate::engine::Outcome::EffectUnknown);
        assert_eq!(
            normalized.payload.as_ref().unwrap()["reconciliation_required"],
            true
        );
        assert!(
            update_unknown(&client, &request, &Ok(post_commit))
                .expect("post-commit corrupt is retained")
        );
    }

    #[test]
    fn wire_uncertain_replies_keep_an_existing_replay_route() {
        let client = test_client();
        let request = mutating_request("namespace-a", "fenced-key");
        let retained_key = (request.namespace.clone(), "fenced-key".to_owned());
        assert!(
            update_unknown(
                &client,
                &request,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            )
            .expect("initial uncertainty is retained")
        );
        for outcome in [
            crate::engine::Outcome::Unavailable("fenced worker".to_owned()),
            crate::engine::Outcome::Corrupt,
            crate::engine::Outcome::Cancelled,
        ] {
            assert!(
                update_unknown(&client, &request, &Ok(wire_reply(outcome)))
                    .expect("uncertain replay outcome remains retained")
            );
            assert!(
                client
                    .unknown
                    .lock()
                    .expect("unknown requests lock")
                    .contains_key(&retained_key)
            );
        }
    }

    #[test]
    fn keyless_read_and_handshake_terminals_never_fence_or_replay() {
        let (client, events) = test_client_with_owner(vec![]);
        for operation in [Operation::Handshake, Operation::Recall, Operation::Health] {
            for outcome in [
                crate::engine::Outcome::Cancelled,
                crate::engine::Outcome::Unavailable("worker unavailable".to_owned()),
                crate::engine::Outcome::Corrupt,
            ] {
                let request = Request::new(7, 1_000, operation, "namespace-a", json!({}));
                assert!(
                    !update_unknown(&client, &request, &Ok(wire_reply(outcome)))
                        .expect("keyless terminal outcome is not retained")
                );
            }
        }
        assert!(!client.fenced.load(Ordering::Acquire));
        assert_eq!(
            client.reconcile_unknown("namespace-a", "missing-key"),
            Err(ClientError::UnknownIdempotencyKey)
        );
        assert!(events.lock().expect("owner events lock").is_empty());
    }

    #[test]
    fn wire_uncertain_reconciliation_replaces_worker_before_resolving() {
        let (client, events) = test_client_with_owner(vec![]);
        let request = mutating_request("namespace-a", "replace-key");
        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );

        let reply = client
            .reconcile_unknown("namespace-a", "replace-key")
            .expect("replacement owner resolves retained request");
        assert_eq!(reply.outcome, crate::engine::Outcome::Success);
        assert_eq!(
            events.lock().expect("owner events lock").as_slice(),
            &[Operation::Handshake, Operation::Observe]
        );
        assert_eq!(client.owner_incarnation(), Some(1));
        assert!(!client.fenced.load(Ordering::Acquire));
        assert!(
            !client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&("namespace-a".to_owned(), "replace-key".to_owned()))
        );
    }

    #[test]
    fn busy_reconciliation_keeps_unknown_until_a_later_resolution() {
        // Outcomes are consumed from the end so the first observe receives
        // Busy and the second receives Success.
        let (client, _events) = test_client_with_owner(vec![
            crate::engine::Outcome::Success,
            crate::engine::Outcome::Busy,
        ]);
        let request = mutating_request("namespace-a", "busy-reconcile");
        let retained_key = (request.namespace.clone(), "busy-reconcile".to_owned());
        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );

        let busy = client
            .reconcile_unknown("namespace-a", "busy-reconcile")
            .expect("busy reply is typed on reconciliation");
        assert_eq!(busy.outcome, crate::engine::Outcome::Busy);
        assert!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );

        let resolved = client
            .reconcile_unknown("namespace-a", "busy-reconcile")
            .expect("later reconciliation resolves busy request");
        assert_eq!(resolved.outcome, crate::engine::Outcome::Success);
        assert!(
            !client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );
    }

    #[test]
    fn busy_snapshot_reconciliation_cleans_refreshed_send_but_keeps_backup() {
        let root = tempfile::tempdir().expect("snapshot root");
        let namespace = "c".repeat(64);
        let (mut client, _events) = test_client_with_owner(vec![
            crate::engine::Outcome::Success,
            crate::engine::Outcome::Busy,
        ]);
        client.root = root.path().to_path_buf();
        let bytes = b"snapshot for busy reconciliation".to_vec();
        let request = Request::new(
            12,
            1_000,
            Operation::SnapshotRestore,
            &namespace,
            json!({
                "idempotency_key": "snapshot-busy",
                "snapshot": bytes,
                "blocked_sources": [],
            }),
        );
        assert!(
            update_unknown(
                &client,
                &request,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            )
            .expect("snapshot request is retained")
        );
        let directory = root
            .path()
            .join("namespaces")
            .join(&namespace)
            .join("snapshots");
        assert_eq!(
            fs::read_dir(&directory)
                .expect("snapshot directory")
                .count(),
            2
        );
        let retained_key = (namespace.clone(), "snapshot-busy".to_owned());
        let backup = client
            .unknown
            .lock()
            .expect("unknown requests lock")
            .get(&retained_key)
            .and_then(|retained| retained.snapshot_backup.clone())
            .expect("retained snapshot backup");

        let busy = client
            .reconcile_unknown(&namespace, "snapshot-busy")
            .expect("busy reply is returned");
        assert_eq!(busy.outcome, crate::engine::Outcome::Busy);
        assert_eq!(
            client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .get(&retained_key)
                .and_then(|retained| retained.snapshot_backup.clone()),
            Some(backup.clone()),
            "the Busy replay retains the original snapshot backup"
        );
        assert_eq!(
            fs::read(&backup).expect("snapshot backup after busy"),
            b"snapshot for busy reconciliation".to_vec()
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("snapshot directory after busy")
                .count(),
            1,
            "the refreshed send file is cleaned while the existing backup remains"
        );

        let resolved = client
            .reconcile_unknown(&namespace, "snapshot-busy")
            .expect("later replay resolves the retained snapshot");
        assert_eq!(resolved.outcome, crate::engine::Outcome::Success);
        assert!(
            !client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .contains_key(&retained_key)
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("snapshot directory after success")
                .count(),
            0
        );
    }

    #[test]
    fn concurrent_reconciliation_of_one_key_has_one_authoritative_replay() {
        let (client, events) = test_client_with_owner(vec![crate::engine::Outcome::Success]);
        let client = Arc::new(client);
        let request = mutating_request("namespace-a", "serialized-reconcile");
        assert!(
            update_unknown(
                &client,
                &request,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            )
            .expect("request is retained")
        );

        let mut handles = Vec::new();
        for _ in 0..2 {
            let client = Arc::clone(&client);
            handles.push(thread::spawn(move || {
                client.reconcile_unknown("namespace-a", "serialized-reconcile")
            }));
        }
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("reconciliation thread joins"))
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_ok_and(|reply| reply.outcome == crate::engine::Outcome::Success))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, &&Err(ClientError::UnknownIdempotencyKey)))
                .count(),
            1
        );
        assert_eq!(
            events.lock().expect("owner events lock").as_slice(),
            &[Operation::Handshake, Operation::Observe]
        );
    }

    #[test]
    fn retained_unknown_ledger_refuses_entries_and_bytes_over_its_bounds() {
        let client = test_client();
        for index in 0..MAX_RETAINED_UNKNOWN_ENTRIES {
            let key = format!("bounded-{index}");
            let request = mutating_request("namespace-a", &key);
            let result = update_unknown(
                &client,
                &request,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            );
            assert!(result.is_ok(), "entry {index} should fit: {result:?}");
        }
        let overflow = mutating_request("namespace-a", "bounded-overflow");
        assert_eq!(
            update_unknown(
                &client,
                &overflow,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            ),
            Err(ClientError::UnknownRetentionLimit { op_id: overflow.id })
        );
        let unknown = client.unknown.lock().expect("unknown requests lock");
        assert_eq!(unknown.len(), MAX_RETAINED_UNKNOWN_ENTRIES);
        assert!(unknown.bytes <= MAX_RETAINED_UNKNOWN_BYTES);
        drop(unknown);

        let bytes_client = test_client();
        let mut oversized = mutating_request("namespace-a", "bounded-bytes");
        oversized.payload["padding"] = Value::String("x".repeat(MAX_RETAINED_UNKNOWN_BYTES + 1));
        assert!(matches!(
            bytes_client.admit_unknown(&oversized, &oversized, None, None),
            Err(ClientError::UnknownRetentionLimit { op_id }) if op_id == oversized.id
        ));
        assert_eq!(
            update_unknown(
                &bytes_client,
                &oversized,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            ),
            Err(ClientError::UnknownRetentionLimit {
                op_id: oversized.id
            })
        );
        assert_eq!(
            bytes_client
                .unknown
                .lock()
                .expect("unknown requests lock")
                .len(),
            0
        );
        let unknown = bytes_client.unknown.lock().expect("unknown requests lock");
        assert!(unknown.reservations.is_empty());
        assert_eq!(unknown.reserved_bytes, 0);
        drop(unknown);
        assert!(!bytes_client.fenced.load(Ordering::Acquire));
    }

    #[test]
    fn retention_entry_overflow_is_rejected_before_worker_dispatch() {
        let (client, events) = test_client_with_owner(Vec::new());
        for index in 0..MAX_RETAINED_UNKNOWN_ENTRIES {
            let key = format!("admission-{index}");
            let request = mutating_request("namespace-a", &key);
            assert!(
                update_unknown(
                    &client,
                    &request,
                    &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
                )
                .expect("ledger entry fits")
            );
        }

        let overflow = mutating_request("namespace-a", "admission-overflow");
        assert_eq!(
            client.call(overflow.clone(), Duration::from_secs(1)),
            Err(ClientError::UnknownRetentionLimit { op_id: overflow.id })
        );
        assert!(
            events.lock().expect("owner events lock").is_empty(),
            "a request rejected by retention admission must not reach the worker"
        );
        let unknown = client.unknown.lock().expect("unknown requests lock");
        assert_eq!(unknown.len(), MAX_RETAINED_UNKNOWN_ENTRIES);
        assert!(unknown.reservations.is_empty());
        assert_eq!(unknown.reserved_bytes, 0);
    }

    #[test]
    fn retention_reservation_is_released_when_mailbox_send_fails() {
        let client = test_client();
        let request = mutating_request("namespace-a", "disconnected-admission");
        assert_eq!(
            client.call(request, Duration::from_secs(1)),
            Err(ClientError::OwnerStopped)
        );
        let unknown = client.unknown.lock().expect("unknown requests lock");
        assert!(unknown.reservations.is_empty());
        assert_eq!(unknown.reserved_bytes, 0);
    }

    #[test]
    fn snapshot_retention_keeps_payload_on_disk_and_bounds_memory() {
        let root = tempfile::tempdir().expect("snapshot root");
        let mut client = test_client();
        client.root = root.path().to_path_buf();
        let namespace = "a".repeat(64);
        let bytes = vec![7_u8; 32 * 1024];
        let request = Request::new(
            9,
            1_000,
            Operation::SnapshotRestore,
            &namespace,
            json!({
                "idempotency_key": "snapshot-bounded",
                "snapshot": bytes,
            }),
        );
        let _ = update_unknown(
            &client,
            &request,
            &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
        );
        let unknown = client.unknown.lock().expect("unknown requests lock");
        let retained = unknown
            .get(&(namespace.clone(), "snapshot-bounded".to_owned()))
            .expect("snapshot request remains retained");
        assert!(retained.bytes < 4 * 1024);
        assert!(retained.snapshot_backup.is_some());
        assert!(snapshot_transport_file(&retained.request).is_some());
        assert!(unknown.bytes <= MAX_RETAINED_UNKNOWN_BYTES);
    }

    #[test]
    fn caller_snapshot_file_is_copied_before_unknown_retention() {
        let root = tempfile::tempdir().expect("snapshot root");
        let caller = tempfile::tempdir().expect("caller root");
        let mut client = test_client();
        client.root = root.path().to_path_buf();
        let namespace = "b".repeat(64);
        let bytes = b"caller-owned snapshot bytes".to_vec();
        let source = caller.path().join("restore.snapshot");
        fs::write(&source, &bytes).expect("caller snapshot writes");
        let request = Request::new(
            10,
            1_000,
            Operation::SnapshotRestore,
            &namespace,
            json!({
                "idempotency_key": "caller-file",
                "snapshot_file": source,
                "byte_length": bytes.len(),
                "content_sha256": sha256_hex(&bytes),
                "blocked_sources": [],
            }),
        );
        assert!(
            update_unknown(
                &client,
                &request,
                &Ok(wire_reply(crate::engine::Outcome::EffectUnknown)),
            )
            .expect("caller snapshot is retained")
        );
        assert!(source.exists(), "caller-owned source remains available");
        let unknown = client.unknown.lock().expect("unknown requests lock");
        let retained = unknown
            .get(&(namespace.clone(), "caller-file".to_owned()))
            .expect("caller snapshot request remains retained");
        let retained_send = snapshot_transport_file(&retained.request)
            .expect("retained request uses a client-owned send file");
        assert_ne!(retained_send, source);
        let backup = retained
            .snapshot_backup
            .as_ref()
            .expect("retained request has a durable backup");
        assert!(retained_send.exists());
        assert!(backup.exists());
        assert_eq!(
            fs::read_dir(
                root.path()
                    .join("namespaces")
                    .join(&namespace)
                    .join("snapshots")
            )
            .expect("retained snapshot directory")
            .count(),
            2
        );
    }
}
