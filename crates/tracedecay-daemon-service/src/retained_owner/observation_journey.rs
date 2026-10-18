//! The mounted production observation journey.
//!
//! This module is the one place where three authorities meet, and it owns the
//! seam between them rather than letting any of them learn about the others:
//!
//! * the **canonical observation store** (`tracedecay_store::ObservationStore`,
//!   reached through the project's registered session database) settles host
//!   session messages;
//! * the **durable journal** (`tracedecay_memory_observation`) owns delivery
//!   status, attempts, acknowledgements, and replay position;
//! * the **provider registry** (`tracedecay_memory_provider_registry`) owns the
//!   readiness handshake and the only dispatch route.
//!
//! # Why the mount order is what it is
//!
//! The exact coding scope is copied verbatim from the authoritative
//! [`ResolvedScope`] that project-open code-index authorities already
//! published. Nothing here re-derives repository, worktree, or branch identity
//! from a path, a CWD, or the journal's own storage location — the host-event
//! observation policy names exactly those as forbidden inference inputs. That
//! is why the journey mounts *after* `project_code_index_authorities` and
//! *after* the project session database is open: before both, there is no
//! truthful scope and no settled source to replay.
//!
//! # What the journal path is, and is not
//!
//! The journal file lives beside the project's other store-owned databases,
//! under the canonical store layout's data root. That location is diagnostic
//! and storage placement only. It is never an identity input: two checkouts
//! that resolve to the same exact scope would share an identity regardless of
//! where their journals sit, and a journal that is moved keeps every identity
//! it holds.
//!
//! # Crash safety
//!
//! Startup replay is authoritative. The journal's per-stream replay cursor says
//! where to resume, so a crash between the canonical commit and the journal
//! append is recovered by re-presenting the canonical record — safe because the
//! idempotency key is content-derived. A bounded live replay worker scans the
//! same durable watermark while the project server is mounted; it only makes
//! convergence faster and is never the thing that makes it correct.
//!
//! # Native never observes
//!
//! `TraceDecay` Native is upstream memory: facts through the owner-bound memory
//! application and sessions through the message-search kernel, both already
//! fed by the one upstream capture path. Native declares no observation
//! capability, so production never mounts a Native journey; journeys exist
//! only for providers that keep provider-local state, such as NCM.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracedecay_contracts::ResolvedScope;
use tracedecay_contracts::retained_surfaces::ProviderControlScopeV1;
use tracedecay_domain::{
    CanonicalMessageRoleV1, CanonicalObservationEnvelopeV1, CanonicalObservationFactV1,
    CanonicalObservationIdV1, DurableObservationV1, ObservationContractError, ObservationScopeV1,
    ProjectId, UserProfileId,
};
use tracedecay_memory_hygiene::{
    AdvisoryMetadataAdmissionV1, AdvisoryMetadataFieldV1, AdvisoryTextAdmissionV1,
    AdvisoryTextHardener, AdvisoryTextWithheldReasonV1, AdvisoryTrustTierV1, HygieneError,
    ObservationAdmission, ObservationSanitizer, TrustedClaudeObservationSourceIdV1,
    UNTRUSTED_BOUNDARY_LABEL, canonical_payload_bytes,
};
use tracedecay_memory_observation::{
    AdapterFailureV1, AdmissionDecisionV1, AdmittedObservationV1, AttemptRefusalCategoryV1,
    BackpressureGateV1, BackpressureHaltV1, BackpressurePolicyV1, BackpressureReasonV1,
    BackpressureStateV1, CanonicalSettlementReceiptV1, DeliveryAttemptV1, DeliveryControlV1,
    DeliveryRuntimeV1, DeliveryStateV1, DeliveryWakeV1, DispatchPolicyV1, DispatchRequestV1,
    DrainStopV1, ForgetSourceKeyV1, IdempotencyInputV1, IngressBatchReportV1, IngressControlV1,
    IngressHaltV1, IngressRuntimeV1, IngressStopReasonV1, LeaseRequestV1, LeasedObservationV1,
    OBSERVATION_CONTRACT_ID, ObservationAdmissionAdapterV1, ObservationDispatchPortV1,
    ObservationIdV1, ObservationIdempotencyKeyV1, ObservationJournalError,
    ObservationJournalReaderV1, ObservationLaneKeyV1, ObservationLoadClassV1, ObservationPrivacyV1,
    ObservationRuntimeError, PrivacyClassificationV1, ProvenanceOriginV1, ProviderCheckpointV1,
    ProviderDeliveryAdapterV1, ProviderReplayPositionV1, ProviderTargetV1, QueueBacklogV1,
    RecoveryBudgetV1, RecoveryControlV1, RecoveryPlanV1, RecoveryRuntimeV1, RecoveryTargetKeyV1,
    RetentionClassV1, RetentionPolicyV1, RetentionSweepScheduleV1, RetentionSweeperV1,
    RetentionTickV1, RetryBackoffV1, SanitizationBindingV1, ShutdownRequestV1, SourceAuthorityV1,
    SourceRecordV1, SourceSequenceV1, SourceStreamIdV1, SourceStreamKeyV1,
    SqliteObservationJournal, TerminalIdentityMismatchV1, WakeOutcomeV1, WithheldAdmissionV1,
    extensions_digest,
};
use tracedecay_memory_provider_registry::{
    ApiError, BoundedCallRefusalV1, BoundedProviderCallV1, CancellationToken, CanonicalPayload,
    CompositionLifecycleError, FabricError, HandshakeRequest, HandshakeRequestParts,
    HandshakeResponse, ObservationInstanceProofV1, ObservationProviderMountV1,
    ObservationStateNamespacePolicyV1, ObserverDeliveryResult, OperationControl, OwnedExactScope,
    OwnedProviderId, OwnedVersionedId, PayloadSanitizationReceipt,
    ProjectMemoryProviderComposition, ProjectMemoryProviderRegistry, ProviderCall,
    ProviderCallParts, ProviderHandshakeWorkV1, ProviderLimits, ProviderOperation,
    ReadinessEvidenceV1, RestartBudgetV1, ShutdownBudgetV1, SupervisedProviderReadinessV1,
    SupervisedReadinessConfigV1, SupervisedReadinessError, TerminalCode,
};
use tracedecay_runtime_core::cancellation::CancellationToken as HostCancellationToken;
use tracedecay_store::{
    ObservationReplayRequest, ObservationStore, ObservationStoreError, StoredObservation,
};

pub(crate) mod control_dispatch;

/// File name of the project-owned observation journal inside the canonical
/// store layout. Placement only; never an identity input.
#[cfg(test)]
const JOURNAL_FILE_NAME: &str = "memory-observation-journal-v1.sqlite3";

/// Directory name of the host-owned root every supervised provider's state is
/// contained under, inside the canonical store layout. The host creates it and
/// grants each admitted namespace a capability rooted beneath it; a provider
/// never names a path outside it.
#[cfg(test)]
const PROVIDER_STATE_DIR_NAME: &str = "provider-state";

/// The observation kind and inner payload contract this journey admits for the
/// host event class `host.session_message_committed.v1`, from the provider
/// observation contract's kind/contract table.
const SESSION_MESSAGE_OBSERVATION_KIND: &str = "session.message_committed.v1";
const SESSION_MESSAGE_PAYLOAD_CONTRACT: &str = "tracedecay.memory.observation.session-message.v1";

/// `canonical_commit_point.point_id` for that event class.
const SESSION_COMMIT_POINT_ID: &str = "session_observation_store.commit";

/// The single source stream this journey replays: one canonical observation
/// sequence per project observation store.
const SESSION_SOURCE_STREAM: &str = "session_observation_store";

/// Bounded page size for canonical replay. The store caps replay at `1_000`.
const REPLAY_PAGE_ITEMS: usize = 128;

/// Bounded startup replay budget. Convergence continues on the live replay
/// worker, so a large backlog never holds project open.
const REPLAY_STARTUP_PAGES: usize = 64;

/// Bounded live replay budget per pass. A larger backlog remains canonical and
/// is picked up by the next pass without monopolizing the async runtime.
const REPLAY_LIVE_PAGES: usize = 8;
/// Wall-clock budget for the inline startup replay pass in project open.
const STARTUP_REPLAY_BUDGET: Duration = Duration::from_secs(10);
/// Wall-clock budget for the required instance proof and for explicitly
/// configured delivery settlement. Historical convergence has its own owner.
const REQUIRED_ACTIVATION_BUDGET: Duration = Duration::from_secs(10);
/// Pause after a failed or halted live replay pass before the next attempt.
const LIVE_REPLAY_ERROR_BACKOFF: Duration = Duration::from_secs(5);
/// Wall-clock deadline one live replay pass runs under. A pass that reaches it
/// stops between records and the next pass resumes from the durable watermark
/// after the park: a yield, not a fault.
const LIVE_REPLAY_PASS_BUDGET: Duration = Duration::from_secs(5);

/// Maximum time between canonical-store replay passes while the project server
/// is mounted. Startup replay remains the crash authority; this bounded poll
/// closes the live post-commit edge for every producer that writes the shared
/// registered store, including producers that do not run through the MCP server.
const LIVE_REPLAY_PARK: Duration = Duration::from_millis(250);

/// Deadline one readiness handshake is given. A handshake is proven per exact
/// scope and cached by the registry, so this bounds a rare call, not a batch.
const READINESS_DEADLINE_MICROS: i64 = 5_000_000;

/// Pause between transient failures while proving the provider instance.
///
/// The proof runs on the journey's one delivery worker. Keeping the retry
/// delay explicit means an immediately failing proof cannot turn that worker
/// into a tight loop, while a provider that becomes available later can still
/// recover without remounting the journey.
const INSTANCE_PROOF_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum number of proof calls one mounted journey may make. A transient
/// provider failure is recoverable, but it cannot make the delivery worker
/// hammer an unavailable provider for the whole lifetime of the daemon.
const INSTANCE_PROOF_MAX_ATTEMPTS: u32 = 3;

/// Maximum wall-clock lifetime of one proof-retry sequence. This remains a
/// second finite bound if a future backoff or wake policy changes.
const INSTANCE_PROOF_MAX_LIFETIME: Duration = Duration::from_secs(30);

/// Delivery deadline stamped on the journal envelope. Longer than one attempt's
/// deadline because it bounds the whole at-least-once lifetime of the row.
const ADMISSION_DEADLINE_MICROS: i64 = 86_400_000_000;

/// Retention class every canonical session observation is admitted under.
///
/// One constant serves both the pre-admission classification the backpressure
/// gate refuses on and the envelope the adapter then builds, so the cheap gate
/// and the envelope can never disagree about what this stream is.
const ADMITTED_RETENTION_CLASS: RetentionClassV1 = RetentionClassV1::Session;

/// How long the caller waits past its own deadline for an in-flight blocking
/// admission to observe its cancellation and return.
///
/// This is not how a record is bounded — the record's own deadline and
/// cancellation are checked inside the blocking work, before hygiene and
/// before the append. This is the last resort that keeps the *caller* bounded
/// when the blocking pool itself is saturated by other work, so a replay pass
/// returns a typed deadline terminal instead of parking indefinitely. The
/// record stays canonical either way and the watermark does not move.
const FOREGROUND_ABORT_GRACE: Duration = Duration::from_secs(2);

/// Spawn attempts one supervised exact scope may make inside
/// [`SUPERVISOR_RESTART_WINDOW_MICROS`]. Re-proving the readiness of a healthy
/// incarnation spends none of these, so this bounds crash loops only.
const SUPERVISOR_RESTART_ATTEMPTS_PER_WINDOW: u32 = 5;
/// Rolling window those spawn attempts are counted in.
const SUPERVISOR_RESTART_WINDOW_MICROS: i64 = 60_000_000;
/// First enforced delay between spawn attempts.
const SUPERVISOR_BACKOFF_BASE_MICROS: i64 = 50_000;
/// Ceiling the enforced doubling saturates at.
const SUPERVISOR_BACKOFF_MAX_MICROS: i64 = 5_000_000;
/// Graceful-stop budget before a supervised instance is forcibly terminated.
const SUPERVISOR_GRACE_MICROS: i64 = 2_000_000;
/// Forced-termination budget after grace elapses.
const SUPERVISOR_KILL_MICROS: i64 = 1_000_000;
/// Finite ceiling on concurrently supervised exact scopes for one project.
/// Beyond it the coldest scope is retired after its instance's death is
/// confirmed, so the owner set never grows without bound and never wedges.
const SUPERVISED_SCOPE_CEILING: usize = 64;

/// Consecutive automatic recovery assessments one incompatible provider state
/// may consume before the journey stops proposing automatic recovery and the
/// refusal names the repair an operator has to perform. The counter is durable
/// and is cleared by an actual convergence, so a provider that comes back
/// healthy is not held against its history.
const RECOVERY_MAX_AUTOMATIC_ATTEMPTS: u32 = 3;

/// Withheld audit rows one delivery-worker turn revalidates.
///
/// Opening the journal validates a bounded page so project open stays flat in
/// the size of that table; the rest is finished here, a page per turn, until
/// the walk reports complete. Bounded on both sides: a page is small enough
/// that it never competes with a delivery round, and the walk ends rather than
/// re-reading a table nothing has changed.
const WITHHELD_AUDIT_PAGE_ROWS: u32 = 512;

/// Every bound the mounted journey runs under, supplied by the composition
/// root through [`ObservationJourneyMountInputsV1`] and validated at mount.
///
/// Nothing in here is a library default: the retention policy bounds the
/// journal, the dispatch policy bounds one delivery round and must fit inside
/// the retention policy, and the cadences bound the worker's own loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObservationJourneyPolicyV1 {
    /// Queue size, attempt ceiling, backoff, ages, and sweep batch of the
    /// project-owned journal.
    pub(crate) retention: RetentionPolicyV1,
    /// Lease length, batch size, per-attempt budget, and reap budget of the
    /// delivery worker.
    pub(crate) dispatch: DispatchPolicyV1,
    /// Thresholds the ingress gate sheds and refuses on, and the foreground
    /// admission budget a coding agent is entitled to.
    pub(crate) backpressure: BackpressurePolicyV1,
    /// How long the delivery worker parks between wakes. A missed wake still
    /// converges within this bound; it never replaces the wake.
    pub(crate) delivery_park: Duration,
    /// Cadence of the bounded retention sweep the delivery worker drives over
    /// the project journal. Each pass is bounded by the policy's
    /// `sweep_batch_rows`; a backlog is due again on the next worker turn.
    pub(crate) retention_sweep_interval_micros: i64,
    /// How long a failed or non-actionable sweep pass waits before retrying.
    pub(crate) retention_sweep_error_backoff_micros: i64,
}

impl ObservationJourneyPolicyV1 {
    /// The product's bounds for a project journey. Explicit, not defaulted:
    /// every value is a product decision the composition root passes through,
    /// and the composition root may pass a different validated policy instead.
    pub(crate) const fn project_default() -> Self {
        Self {
            retention: RetentionPolicyV1 {
                ephemeral_max_age_micros: 3_600_000_000,
                session_max_age_micros: 86_400_000_000,
                project_max_age_micros: 2_592_000_000_000,
                profile_max_age_micros: 2_592_000_000_000,
                receipt_retention_micros: 604_800_000_000,
                max_queue_items: 10_000,
                max_queue_bytes: 64 * 1_048_576,
                max_attempts: 8,
                backoff_base_micros: 1_000_000,
                backoff_max_micros: 300_000_000,
                sweep_batch_rows: 512,
            },
            dispatch: DispatchPolicyV1 {
                lease_duration_micros: 30_000_000,
                batch_max_items: 16,
                batch_max_bytes: 1_048_576,
                attempt_budget_micros: 5_000_000,
                reap_budget: 256,
                // A restart backlog is durable and nothing signals about it
                // twice, so one turn drains up to sixteen batches — bounded by
                // a wall budget well inside the daemon's shutdown deadline so
                // reaping, retention, and stopping are never starved.
                max_rounds_per_drain: 16,
                drain_budget_micros: 10_000_000,
            },
            backpressure: BackpressurePolicyV1 {
                // Session-lifetime observation traffic — everything this
                // journey admits today — stops at three quarters of the
                // journal's own ceiling, leaving the last quarter for
                // project- and profile-lifetime work that must not be
                // refused early. Nothing is discarded either way: a shed
                // holds the canonical watermark and the record is
                // re-presented by the next replay pass.
                shed_optional_at_ppm: 750_000,
                refuse_at_ppm: 950_000,
                // A lane whose oldest queued row has waited five minutes is
                // not draining, and adding to it helps nobody.
                max_backlog_age_micros: 300_000_000,
                // One canonical record's sanitize-derive-append path. Beyond
                // it the journal itself is what is slow.
                foreground_budget_micros: 250_000,
                // Three consecutive overruns, not one: a single slow fsync is
                // a disk hiccup, and refusing observation traffic over it
                // would make the product jumpy for nothing. A run of three is
                // an admission path that is genuinely not keeping up, and
                // there the remedy — optional traffic stops competing for the
                // journal so the delivery worker can drain — is real.
                foreground_breach_streak: 3,
            },
            delivery_park: Duration::from_millis(250),
            retention_sweep_interval_micros: 60_000_000,
            retention_sweep_error_backoff_micros: 300_000_000,
        }
    }

    /// Refuses a policy that cannot bound the worker. The retention policy is
    /// validated again by the journal at open; the dispatch policy must fit
    /// inside it; the park must be finite and non-zero so a missed wake still
    /// converges.
    fn validate(&self) -> Result<(), ObservationJourneyError> {
        self.retention
            .validate()
            .map_err(ObservationJourneyError::Journal)?;
        self.dispatch
            .validate_against(&self.retention)
            .map_err(ObservationJourneyError::Journal)?;
        self.backpressure
            .validate()
            .map_err(ObservationJourneyError::Journal)?;
        if self.delivery_park.is_zero() {
            return Err(ObservationJourneyError::Journal(
                ObservationJournalError::InvalidDispatchPolicy {
                    field: "delivery_park",
                },
            ));
        }
        Ok(())
    }
}

/// Every way the mounted journey can refuse, typed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ObservationJourneyError {
    #[error("host history authorization failed: {0}")]
    History(#[from] super::provider_history::ProviderHistoryErrorV1),
    /// Composition is disabled, so there is no registry to mount against.
    #[error("provider composition is disabled, so no observation journey can mount")]
    CompositionDisabled,
    /// The authoritative resolved scope carries no branch or detached
    /// reference, so no exact coding scope exists. The journey does not mount
    /// rather than inventing a branch identity from a path.
    #[error(
        "authoritative resolved scope for project {project_id} carries no reference, so no exact \
         coding scope exists for provider observation"
    )]
    ScopeReferenceUnavailable {
        /// Project whose scope could not be completed.
        project_id: String,
    },
    /// The mount inputs disagree with the authoritative scope. Nothing is
    /// re-derived to make them agree.
    #[error(
        "observation journey inputs disagree with the authoritative scope on {field}: expected \
         {expected}, received {received}"
    )]
    ScopeDisagreement {
        /// Which identity disagreed.
        field: &'static str,
        /// The authoritative value.
        expected: String,
        /// The value the caller supplied.
        received: String,
    },
    /// A provider-contract value was rejected.
    #[error("provider contract rejected an observation journey value: {0}")]
    Contract(#[source] ApiError),
    /// The supervised provider lifecycle refused readiness for this exact
    /// scope. The host keeps running against this typed degradation; nothing
    /// downstream is admitted without a validated readiness target.
    #[error("supervised provider lifecycle refused readiness: {0}")]
    SupervisedReadiness(#[source] SupervisedReadinessError),
    /// A journal-contract value was rejected.
    #[error("observation journal rejected a mount value: {0}")]
    Journal(#[source] ObservationJournalError),
    /// The journal file could not be opened.
    #[error("observation journal at {path} could not be opened: {source}")]
    JournalOpen {
        /// Storage placement of the journal, for diagnostics only.
        path: PathBuf,
        /// Underlying journal failure.
        #[source]
        source: ObservationJournalError,
    },
    /// The canonical hygiene policy could not be loaded.
    #[error("observation hygiene policy is unavailable: {0}")]
    Hygiene(#[source] HygieneError),
    /// System entropy was unavailable, so no unforgeable challenge nonce could
    /// be minted. A constant nonce would make the handshake replayable, so the
    /// mount fails instead of substituting one.
    #[error("system entropy is unavailable, so no readiness challenge could be minted")]
    EntropyUnavailable,
    /// The delivery worker thread could not start.
    #[error("observation delivery worker could not start: {0}")]
    Worker(#[source] std::io::Error),
    /// Canonical replay failed.
    #[error("canonical observation replay failed: {0}")]
    Replay(#[source] ObservationStoreError),
    /// The authoritative startup replay failed in a way no later pass can
    /// clear, so the mount is refused instead of reporting a healthy journey
    /// over a committed observation that will never be delivered.
    ///
    /// The journal watermark still holds in front of the refused record and
    /// nothing was lost; what is refused is the *claim* that the journey is
    /// converging, because it is not.
    #[error(
        "project observation startup replay failed permanently, so the journey did not mount: \
         {source}"
    )]
    StartupReplayPermanent {
        /// The refusal that cannot be retried away.
        #[source]
        source: Box<ObservationJourneyError>,
    },
    /// Ingress refused a batch.
    #[error("observation ingress refused a canonical batch: {0}")]
    Ingress(#[source] ObservationRuntimeError),
    /// The blocking-pool task that recovers and ingests one record did not
    /// complete. The record's own transaction either committed or did not; the
    /// next pass re-presents it from the watermark either way.
    #[error("observation ingest task did not complete: {0}")]
    IngestTask(#[source] tokio::task::JoinError),
    /// The blocking-pool task that mounts the journey did not complete.
    ///
    /// The mount opens a SQLite file and applies its schema, which is a
    /// synchronous filesystem operation that must not run on a runtime worker.
    /// Nothing partial escapes: a mount that did not return produced no
    /// journey, and the durable journal is exactly what the previous life left.
    #[error("observation journey mount task did not complete: {0}")]
    MountTask(#[source] tokio::task::JoinError),
    /// The caller's cancellation token was cancelled between records. Every
    /// record is its own journal transaction, so the durable watermark holds
    /// exactly the records admitted before the cancellation was observed.
    #[error(
        "canonical observation replay was cancelled after admitting {admitted} records; the \
         durable watermark is preserved"
    )]
    Cancelled {
        /// Records this pass admitted before it observed the cancellation.
        admitted: u64,
    },
    /// The caller's deadline elapsed between records. Same durability as
    /// [`Self::Cancelled`]: nothing past the watermark is lost.
    #[error(
        "canonical observation replay stopped at its deadline after admitting {admitted} \
         records; the durable watermark is preserved"
    )]
    DeadlineExceeded {
        /// Records this pass admitted before it reached the deadline.
        admitted: u64,
    },
    /// A required provider delivery reached a terminal state without a
    /// committed or duplicate acknowledgement. Publishing the recall route
    /// after this state would turn a failed replay into an empty answer.
    #[error("required provider delivery settled as {state:?} rather than an acknowledged effect")]
    RequiredDeliveryFailed {
        /// Terminal state recorded by the durable journal.
        state: DeliveryStateV1,
    },
    #[error("required provider instance proof is unavailable")]
    ProviderInstanceUnavailable,
    #[error("required provider instance proof did not complete before its deadline")]
    ProviderInstanceDeadlineExceeded,
}

/// One way the mounted journey failed to stop cleanly.
///
/// Returned to the daemon's shutdown status rather than only logged, so an
/// unclean stop surfaces as `Failed` instead of hiding behind `Clean`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ObservationShutdownFailureV1 {
    /// The initial backlog refresh exceeded the shared shutdown deadline.
    #[error("observation backlog refresh did not finish within the daemon shutdown deadline")]
    BacklogRefreshDeadline,
    /// The live replay task ended with something other than a cancellation.
    #[error("the canonical observation replay task did not exit cleanly: {0}")]
    LiveReplayJoin(#[source] tokio::task::JoinError),
    /// The live replay task did not stop inside the daemon deadline.
    #[error(
        "the canonical observation replay task did not stop within the daemon shutdown deadline"
    )]
    LiveReplayDeadline,
    /// The delivery worker thread panicked.
    #[error("the observation delivery worker did not exit cleanly")]
    WorkerPanicked,
    /// The blocking join of the delivery worker failed.
    #[error("the observation delivery worker join task failed: {0}")]
    WorkerJoin(#[source] tokio::task::JoinError),
    /// The delivery worker did not stop inside the daemon deadline.
    #[error("the observation delivery worker did not stop within the daemon shutdown deadline")]
    WorkerDeadline,
    /// Leases were still held after the bounded reap.
    #[error(
        "{leases_outstanding} observation delivery leases remain outstanding after shutdown \
         ({leases_reaped} reaped)"
    )]
    LeasesOutstanding {
        /// Leases the bounded reap released.
        leases_reaped: u32,
        /// Leases still held when the reap budget ran out.
        leases_outstanding: u64,
    },
    /// The journal's own shutdown pass failed.
    #[error("observation delivery shutdown pass failed: {0}")]
    ShutdownPass(#[source] ObservationRuntimeError),
    /// The blocking join of the journal's shutdown pass failed.
    #[error("observation delivery shutdown pass task failed: {0}")]
    ShutdownPassJoin(#[source] tokio::task::JoinError),
    /// The journal's shutdown pass did not finish inside the daemon deadline.
    ///
    /// The pass is a bounded reap and one indexed read against the same SQLite
    /// file the delivery worker writes, so it can legitimately wait behind a
    /// writer. Waiting past the daemon's own stop deadline is not legitimate,
    /// and neither is waiting for it on a runtime worker: the pass runs on the
    /// blocking pool and this is what the daemon is told when it outlives the
    /// deadline. Nothing is stranded — every outstanding lease carries its own
    /// expiry and any later process reaps it.
    #[error(
        "observation delivery shutdown pass did not finish within the daemon shutdown deadline"
    )]
    ShutdownPassDeadline,
}

// ---------------------------------------------------------------------------
// Untrusted-memory gate for provider recall
//
// Hygiene has two directions. Outbound, it keeps a credential from leaving the
// host inside an observation. Inbound, a recall candidate is text a provider
// wrote that ends up inside the context an agent reads as instructions, so it
// is untrusted advisory data and must be contained, de-marked-up, secret-
// scanned, and trust-labelled before context assembly.
//
// This module is the one root file that owns the hygiene pipeline, so the gate
// is composed here and handed to the advisory recall lane as a root-local
// value. The recall lane therefore never names the hygiene crate itself, and
// the pipeline keeps exactly one owner inside the composition root.
// ---------------------------------------------------------------------------

/// The provider-controlled label one metadata hardening decided about.
///
/// Re-exported under a root-local name so the advisory recall lane can name a
/// metadata field without naming the hygiene pipeline: this file is the one
/// root owner of that crate.
pub(super) use tracedecay_memory_hygiene::AdvisoryMetadataFieldV1 as UntrustedRecallMetadataFieldV1;
/// Why the untrusted-memory gate refused one provider string, re-exported
/// under a root-local name for the same reason.
pub(super) use tracedecay_memory_hygiene::AdvisoryTextWithheldReasonV1 as UntrustedRecallWithheldReasonV1;

/// The fault the untrusted-memory gate raises when the admitted secret
/// pipeline itself cannot decide, re-exported under a root-local name so the
/// recall lane can propagate it as a typed value rather than as prose.
pub(super) type UntrustedRecallGateFaultV1 = HygieneError;

/// Trust the host places in one recall candidate's text.
///
/// It is derived from the host's *own* provenance verdict, never from the
/// provider's claim: only a host authority's confirmation is
/// [`Self::HostConfirmed`], and a claim the host could not confirm is worth no
/// more than no claim at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UntrustedRecallTrustV1 {
    /// No provenance was established, or the claim did not resolve.
    Unattributed,
    /// The provider named a source or gave a redaction reason; unconfirmed.
    ProviderAttested,
    /// A host authority confirmed the claimed source.
    HostConfirmed,
}

impl UntrustedRecallTrustV1 {
    /// The provider-neutral tier the hygiene gate reads.
    const fn tier(self) -> AdvisoryTrustTierV1 {
        match self {
            Self::Unattributed => AdvisoryTrustTierV1::Unattributed,
            Self::ProviderAttested => AdvisoryTrustTierV1::ProviderAttested,
            Self::HostConfirmed => AdvisoryTrustTierV1::HostConfirmed,
        }
    }
}

/// The untrusted-memory gate every provider recall candidate passes before it
/// can reach context assembly.
#[derive(Clone, Debug)]
pub(super) struct UntrustedRecallGateV1 {
    hardener: AdvisoryTextHardener,
}

impl UntrustedRecallGateV1 {
    /// The instruction boundary an admitted advisory item carries. The host
    /// writes it; a provider copy of it inside candidate text is neutralized.
    pub(super) const BOUNDARY_LABEL: &'static str = UNTRUSTED_BOUNDARY_LABEL;

    /// Composes the gate from the canonical hygiene policy.
    ///
    /// # Errors
    ///
    /// Returns the hygiene fault itself, not a rendered string, when the
    /// canonical class-to-action table cannot be assembled. The caller reports
    /// its lane unavailable: provider text is never delivered unclassified,
    /// and the caller can still say *which* fault stopped it.
    pub(super) fn open() -> Result<Self, HygieneError> {
        AdvisoryTextHardener::new().map(|hardener| Self { hardener })
    }

    /// Hardens one candidate's content and optional explanation.
    ///
    /// A refused item is not dropped: the typed outcome keeps the withheld
    /// reason, the trust tier, and the source digest, so a refusal stays a
    /// structural fact rather than a sentence a caller would have to parse.
    /// The in-band notice the agent reads is derived from that same typed
    /// reason by [`UntrustedRecallItemV1::rendered_content`].
    ///
    /// # Errors
    ///
    /// Returns [`HygieneError`] when the admitted secret pipeline itself
    /// faults. A detector fault says nothing about whether the text was safe,
    /// so it is never flattened into a withholding: the caller must fail its
    /// lane.
    pub(super) fn harden(
        &self,
        content: &str,
        explanation: Option<&str>,
        trust: UntrustedRecallTrustV1,
    ) -> Result<UntrustedRecallItemV1, HygieneError> {
        Ok(
            match self.hardener.harden(content, explanation, trust.tier())? {
                AdvisoryTextAdmissionV1::Admitted(hardened) => UntrustedRecallItemV1::Admitted {
                    content: hardened.content().to_owned(),
                    explanation: hardened.explanation().map(str::to_owned),
                    source_content_sha256: hardened.source_content_sha256().to_owned(),
                    hardened_content_sha256: hardened.hardened_content_sha256().to_owned(),
                },
                AdvisoryTextAdmissionV1::Withheld {
                    reason,
                    source_content_sha256,
                    ..
                } => UntrustedRecallItemV1::Withheld {
                    reason,
                    source_content_sha256,
                },
            },
        )
    }

    /// Hardens one provider-controlled metadata label — a candidate identity,
    /// a claimed provenance source, or a provider-authored reason.
    ///
    /// These are agent-visible for exactly the same reason content is: they
    /// are interpolated into the same rendered line. They therefore pass the
    /// same gate rather than being copied through as opaque keys.
    ///
    /// # Errors
    ///
    /// Returns [`HygieneError`] when the admitted secret pipeline faults.
    pub(super) fn harden_metadata(
        &self,
        field: AdvisoryMetadataFieldV1,
        value: &str,
    ) -> Result<UntrustedRecallMetadataV1, HygieneError> {
        Ok(match self.hardener.harden_metadata(field, value)? {
            AdvisoryMetadataAdmissionV1::Admitted {
                value,
                source_sha256,
                ..
            } => UntrustedRecallMetadataV1::Admitted {
                value,
                source_sha256,
            },
            AdvisoryMetadataAdmissionV1::Withheld {
                reason,
                source_sha256,
                ..
            } => UntrustedRecallMetadataV1::Withheld {
                reason,
                source_sha256,
            },
        })
    }

    /// The in-band notice that stands in for one withheld item's text.
    pub(super) fn withheld_text(code: &str) -> String {
        format!("{} withheld: {code}", Self::BOUNDARY_LABEL)
    }
}

/// What the untrusted-memory gate decided about one candidate's text.
///
/// Both arms carry the source digest, so a refusal is auditable without
/// keeping a copy of the refused bytes, and a caller never has to read prose
/// to learn which happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UntrustedRecallItemV1 {
    /// The text may be compiled into a context pack.
    Admitted {
        /// Agent-visible content, host boundary label included.
        content: String,
        /// Retained explanation, if the gate admitted one.
        explanation: Option<String>,
        /// Digest of the provider's original content.
        source_content_sha256: String,
        /// Digest of the delivered content.
        hardened_content_sha256: String,
    },
    /// The text must not be delivered.
    Withheld {
        /// Which rule fired.
        reason: AdvisoryTextWithheldReasonV1,
        /// Digest of the provider's original content.
        source_content_sha256: String,
    },
}

impl UntrustedRecallItemV1 {
    /// The content the agent reads for this item.
    ///
    /// A withheld item is never silently dropped: it keeps its place in the
    /// list and its text is replaced by a typed in-band notice, so a refusal
    /// looks like a refusal rather than like a provider with less to say.
    pub(super) fn rendered_content(&self) -> String {
        match self {
            Self::Admitted { content, .. } => content.clone(),
            Self::Withheld { reason, .. } => UntrustedRecallGateV1::withheld_text(reason.code()),
        }
    }

    /// The retained explanation, if any.
    pub(super) fn rendered_explanation(&self) -> Option<String> {
        match self {
            Self::Admitted { explanation, .. } => explanation.clone(),
            Self::Withheld { .. } => None,
        }
    }

    /// Digest of the provider's original content, admitted or not.
    pub(super) fn source_content_sha256(&self) -> &str {
        match self {
            Self::Admitted {
                source_content_sha256,
                ..
            }
            | Self::Withheld {
                source_content_sha256,
                ..
            } => source_content_sha256,
        }
    }

    /// Digest of the delivered content, when there is delivered content.
    pub(super) fn hardened_content_sha256(&self) -> Option<&str> {
        match self {
            Self::Admitted {
                hardened_content_sha256,
                ..
            } => Some(hardened_content_sha256),
            Self::Withheld { .. } => None,
        }
    }

    /// The typed withholding reason, when the gate refused the text.
    pub(super) const fn withheld_reason(&self) -> Option<AdvisoryTextWithheldReasonV1> {
        match self {
            Self::Admitted { .. } => None,
            Self::Withheld { reason, .. } => Some(*reason),
        }
    }
}

/// What the untrusted-memory gate decided about one provider-controlled
/// metadata label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UntrustedRecallMetadataV1 {
    /// The label may be rendered, in this contained form.
    Admitted {
        /// The contained label, as the gate would render it.
        value: String,
        /// Digest of the provider's original label.
        source_sha256: String,
    },
    /// The label must not be rendered. The caller substitutes a host-minted
    /// stand-in rather than a repaired copy of the provider's bytes.
    Withheld {
        /// Which rule fired.
        reason: AdvisoryTextWithheldReasonV1,
        /// Digest of the provider's original label.
        source_sha256: String,
    },
}

impl UntrustedRecallMetadataV1 {
    /// The contained label, when the gate admitted one.
    pub(super) fn admitted(&self) -> Option<&str> {
        match self {
            Self::Admitted { value, .. } => Some(value),
            Self::Withheld { .. } => None,
        }
    }

    /// The typed refusal, when the gate refused the label.
    pub(super) const fn withheld_reason(&self) -> Option<AdvisoryTextWithheldReasonV1> {
        match self {
            Self::Admitted { .. } => None,
            Self::Withheld { reason, .. } => Some(*reason),
        }
    }
}

/// Binds the actual canonical session through the shared control-scope
/// namespace authority, preserving the resolved checkout inputs verbatim.
pub(super) fn provider_agent_session_id(
    profile_id: &UserProfileId,
    scope: &ResolvedScope,
    canonical_session_id: &str,
) -> String {
    ProviderControlScopeV1 {
        profile_id: profile_id.as_str().to_owned(),
        project_id: scope.project_id.as_str().to_owned(),
        repository_identity: scope.repository_id.as_str().to_owned(),
        worktree_identity: scope.worktree_id.as_str().to_owned(),
        branch_identity: scope
            .reference
            .as_ref()
            .map_or("", |reference| reference.as_str())
            .to_owned(),
        agent_session_id: canonical_session_id.to_owned(),
        resolved_scope_digest: scope.scope_digest.as_str().to_owned(),
    }
    .agent_session_id_for_canonical_session(canonical_session_id)
}

/// Builds the exact coding scope for one canonical session, copying the
/// authoritative resolved scope verbatim.
///
/// `scope_digest` is already an algorithm-tagged `sha256:` digest, which is
/// exactly the shape `OwnedExactScope` requires of `resolved_scope_digest`; it
/// is passed through untouched rather than re-tagged or re-hashed.
pub(super) fn exact_scope_for_session(
    profile_id: &UserProfileId,
    scope: &ResolvedScope,
    canonical_session_id: &str,
) -> Result<OwnedExactScope, ObservationJourneyError> {
    let reference = scope.reference.as_ref().ok_or_else(|| {
        ObservationJourneyError::ScopeReferenceUnavailable {
            project_id: scope.project_id.as_str().to_owned(),
        }
    })?;
    OwnedExactScope::new(
        profile_id.as_str(),
        scope.project_id.as_str(),
        scope.repository_id.as_str(),
        scope.worktree_id.as_str(),
        reference.as_str(),
        provider_agent_session_id(profile_id, scope, canonical_session_id),
        scope.scope_digest.as_str(),
    )
    .map_err(ObservationJourneyError::Contract)
}

/// Everything the admission adapter needs that does not change per record.
struct AdmissionContextV1 {
    profile_id: UserProfileId,
    scope: ResolvedScope,
    readiness: Arc<SupervisedProviderReadinessV1>,
    /// The provider lane this journey's records queue in. Named from the
    /// registration alone, so ingress can measure the lane's pressure before
    /// it pays for the readiness handshake that would name an instance.
    provider_lane: ObservationLaneKeyV1,
    registration_revision: u64,
    limits: ProviderLimits,
    observe_capability: OwnedVersionedId,
    sanitizer: ObservationSanitizer,
    observation_kind: OwnedVersionedId,
    provider_payload_contract: OwnedVersionedId,
}

enum CanonicalMessageEligibilityV1 {
    Message {
        payload: Value,
        shape_error: Option<ObservationContractError>,
    },
    NonMessage,
    Unknown {
        shape_error: Option<ObservationContractError>,
    },
}

/// Validate the canonical contract before deciding eligibility. Only a known
/// message's provider copy is narrowed; unknown facts withhold the whole copy.
/// Source evidence and its identity remain untouched. Shape-limit failures
/// follow hygiene's terminal path, but still refuse a copy hygiene admits.
fn canonical_message_eligibility(
    observation: &DurableObservationV1,
) -> Result<CanonicalMessageEligibilityV1, String> {
    let envelope: CanonicalObservationEnvelopeV1 =
        serde_json::from_value(observation.payload().clone()).map_err(|error| error.to_string())?;
    let shape_error = match envelope.validate() {
        Ok(()) => None,
        Err(
            error @ (ObservationContractError::CanonicalEnvelopeTooLarge
            | ObservationContractError::CanonicalEnvelopeTooDeep
            | ObservationContractError::CanonicalEnvelopeTooManyValues),
        ) => Some(error),
        Err(error) => return Err(error.to_string()),
    };
    if envelope.provider() != observation.source().provider()
        || envelope.relations().session_id() != observation.source().session_id()
        || envelope.evidence().ordering_domain() != observation.identity().ordering_domain()
        || envelope.evidence().range() != observation.identity().position()
        || observation
            .identity()
            .native_record_id()
            .is_some_and(|id| id != envelope.stable_record_id())
    {
        return Err("canonical envelope source identity mismatch".to_owned());
    }
    if envelope
        .facts()
        .iter()
        .any(|fact| matches!(fact, CanonicalObservationFactV1::Unknown { .. }))
    {
        return Ok(CanonicalMessageEligibilityV1::Unknown { shape_error });
    }
    let facts: Vec<_> = envelope
        .facts()
        .iter()
        .filter(|fact| {
            matches!(
                fact,
                CanonicalObservationFactV1::Message {
                    role: CanonicalMessageRoleV1::User | CanonicalMessageRoleV1::Assistant,
                    ..
                }
            )
        })
        .collect();
    if facts.is_empty() {
        if let Some(error) = shape_error {
            return Err(error.to_string());
        }
        return Ok(CanonicalMessageEligibilityV1::NonMessage);
    }
    let mut payload = observation.payload().clone();
    payload["facts"] = serde_json::to_value(facts).map_err(|error| error.to_string())?;
    Ok(CanonicalMessageEligibilityV1::Message {
        payload,
        shape_error,
    })
}

/// Turns one canonical `StoredObservation` into an admission decision.
///
/// The order is fixed by the observation contract and enforced here, not
/// documented and hoped for: hygiene runs *before* any journal digest or
/// idempotency key is derived, and the key is derived over the sanitized bytes
/// that will actually be delivered. Nothing in this adapter writes to, mutates,
/// or deletes canonical evidence — a secret-bearing record produces a withheld
/// audit row in the journal and leaves the canonical observation exactly as the
/// host settled it.
struct CanonicalObservationAdmissionAdapterV1 {
    context: AdmissionContextV1,
}

/// Typed admission refusals. None of them is a silent drop: each one stops
/// ingress at the offending record with that record's own identity attached.
#[derive(Debug, thiserror::Error)]
enum AdmissionAdapterError {
    #[error("host history authorization failed: {0}")]
    History(#[source] super::provider_history::ProviderHistoryErrorV1),
    #[error(
        "canonical observation {source_event_id} is scoped outside the mounted project, so it \
         cannot be admitted under this journey's exact scope"
    )]
    ScopeMismatch {
        /// Settled event identity that could not be admitted.
        source_event_id: String,
    },
    #[error("canonical observation {source_event_id} has no usable exact coding scope: {source}")]
    ExactScope {
        /// Settled event identity that could not be admitted.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: Box<ObservationJourneyError>,
    },
    #[error("canonical observation {source_event_id} has an invalid envelope: {detail}")]
    InvalidCanonicalEnvelope {
        source_event_id: String,
        detail: String,
    },
    #[error("hygiene could not decide canonical observation {source_event_id}: {source}")]
    Hygiene {
        /// Settled event identity that could not be decided.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: HygieneError,
    },
    #[error("provider envelope for {source_event_id} could not be canonically encoded: {source}")]
    CanonicalEncoding {
        /// Settled event identity that could not be encoded.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: HygieneError,
    },
    #[error("hygiene rewrote the provider envelope shape for {source_event_id}")]
    EnvelopeShapeRewritten {
        /// Settled event identity whose envelope no longer parses.
        source_event_id: String,
    },
    #[error("journal contract refused the decision for {source_event_id}: {source}")]
    Journal {
        /// Settled event identity the journal refused.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: ObservationJournalError,
    },
    #[error("provider contract refused the admitted payload for {source_event_id}: {source}")]
    Payload {
        /// Settled event identity whose payload was refused.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: ApiError,
    },
    #[error("provider readiness could not be proven for {source_event_id}: {source}")]
    Readiness {
        /// Settled event identity whose exact scope was not accepted.
        source_event_id: String,
        /// Underlying refusal.
        #[source]
        source: Box<ObservationJourneyError>,
    },
}

impl ObservationAdmissionAdapterV1 for CanonicalObservationAdmissionAdapterV1 {
    type Record = StoredObservation;
    type Error = AdmissionAdapterError;
    type Control = ReplayIngestControlV1;

    fn lane(&self, _record: &SourceRecordV1<Self::Record>) -> ObservationLaneKeyV1 {
        self.context.provider_lane.clone()
    }

    fn classify(&self, _record: &SourceRecordV1<Self::Record>) -> ObservationLoadClassV1 {
        // The same constant the envelope below carries. Answering here costs
        // nothing, and it is what lets the gate refuse a lane that is already
        // shedding this stream *before* hygiene, digest derivation, and a
        // readiness proof are paid for on a record that cannot be admitted.
        ObservationLoadClassV1::of(ADMITTED_RETENTION_CLASS)
    }

    fn decide(
        &self,
        record: &SourceRecordV1<Self::Record>,
        control: &Self::Control,
    ) -> Result<AdmissionDecisionV1, Self::Error> {
        self.decide_with_history(record, control, None)
    }
}

impl CanonicalObservationAdmissionAdapterV1 {
    fn decide_with_history(
        &self,
        record: &SourceRecordV1<StoredObservation>,
        control: &ReplayIngestControlV1,
        history: Option<&tracedecay_memory_provider_registry::HistoryGrant>,
    ) -> Result<AdmissionDecisionV1, AdmissionAdapterError> {
        let context = &self.context;
        let stored = &record.record;
        let observation = stored.observation();
        let source_event_id = record.source_event_id.clone();

        // The canonical record must already belong to the mounted project. One
        // that does not is refused, never re-scoped: re-scoping would deliver
        // another project's content under this project's exact scope.
        let scoped_here = matches!(
            observation.scope(),
            ObservationScopeV1::Project { project_id } if project_id == &context.scope.project_id
        );
        if !scoped_here {
            return Err(AdmissionAdapterError::ScopeMismatch { source_event_id });
        }
        let exact_scope = match history {
            Some(history) => history.destination_scope.clone(),
            None => exact_scope_for_session(
                &context.profile_id,
                &context.scope,
                observation.source().session_id().as_str(),
            )
            .map_err(|source| AdmissionAdapterError::ExactScope {
                source_event_id: source_event_id.clone(),
                source: Box::new(source),
            })?,
        };

        let eligibility = canonical_message_eligibility(observation).map_err(|detail| {
            AdmissionAdapterError::InvalidCanonicalEnvelope {
                source_event_id: source_event_id.clone(),
                detail,
            }
        })?;
        let (message_payload, shape_error, unknown_eligibility) = match eligibility {
            CanonicalMessageEligibilityV1::Message {
                payload,
                shape_error,
            } => (payload, shape_error, false),
            CanonicalMessageEligibilityV1::Unknown { shape_error } => {
                (observation.payload().clone(), shape_error, true)
            }
            CanonicalMessageEligibilityV1::NonMessage => {
                return Ok(AdmissionDecisionV1::NonMessage(Box::new(
                    canonical_settlement_receipt(record, stored),
                )));
            }
        };

        // The provider sees the observation envelope, not the bare canonical
        // payload, so hygiene has to run over the envelope: the sanitization
        // receipt binds the exact bytes that will be delivered, and a receipt
        // minted over the inner payload alone would not describe them. The
        // sanitizer walks the whole structure, so a secret nested anywhere in
        // the canonical payload is still found.
        let mut envelope = provider_observation_envelope(
            context.observation_kind.as_str(),
            SESSION_MESSAGE_PAYLOAD_CONTRACT,
            &message_payload,
            observation.observation_id(),
        );
        let trusted_history_source = if let Some(history) = history {
            let attribution = super::provider_history::validate_history_record(history, stored)
                .map_err(AdmissionAdapterError::History)?;
            envelope["source_identity"]["original_source"] =
                super::provider_history::source_attribution_json(attribution)
                    .map_err(AdmissionAdapterError::History)?;
            envelope["history_grant"] = super::provider_history::history_grant_json(history)
                .map_err(AdmissionAdapterError::History)?;
            TrustedClaudeObservationSourceIdV1::from_validated_source(
                attribution.source.canonical_provider_id.as_str(),
                &attribution.source.source_key,
            )
        } else {
            None
        };
        // A settled record whose *shape* hygiene will not walk — nested or
        // sized beyond the ceilings the store itself never lets a record reach
        // — has been classified as nothing, so it is withheld under a typed
        // reason rather than refused: a refusal here would stall the replay
        // cursor on evidence the host already settled and repeat on every
        // open. Every other hygiene error stays a refusal, because a detector
        // fault must keep failing closed and a caller bug must stay visible.
        let admission_result = match trusted_history_source.as_ref() {
            Some(trusted_source) => context
                .sanitizer
                .admit_observation_with_trusted_history_source(&envelope, &[], trusted_source),
            None => context.sanitizer.admit_observation(&envelope, &[]),
        };
        let admission = admission_result
            .or_else(|error| {
                let terminal = context
                    .sanitizer
                    .withhold_unclassifiable(&envelope, &[], error)?;
                tracing::warn!(
                    event = "memory_observation_unclassifiable_record_withheld",
                    source_event_id = %source_event_id,
                    "settled canonical record lies beyond the hygiene ceilings; withheld \
                     without classification, canonical evidence untouched"
                );
                Ok(terminal)
            })
            .map_err(|source| AdmissionAdapterError::Hygiene {
                source_event_id: source_event_id.clone(),
                source,
            })?;

        if matches!(admission, ObservationAdmission::Admitted { .. })
            && let Some(error) = shape_error
        {
            return Err(AdmissionAdapterError::InvalidCanonicalEnvelope {
                source_event_id,
                detail: error.to_string(),
            });
        }
        let admission = match admission {
            ObservationAdmission::Admitted { .. } if unknown_eligibility => {
                let withheld = context
                    .sanitizer
                    .withhold_unknown_eligibility(&envelope, &[])
                    .map_err(|source| AdmissionAdapterError::Hygiene {
                        source_event_id: source_event_id.clone(),
                        source,
                    })?;
                tracing::debug!(
                    event = "memory_observation_unknown_eligibility_withheld",
                    source_event_id = %source_event_id,
                    "settled canonical facts do not establish message eligibility; the whole \
                     provider copy is withheld, canonical evidence untouched"
                );
                withheld
            }
            admission => admission,
        };

        let settlement = canonical_settlement_receipt(record, stored);
        let forget_source_key = match history {
            Some(history) => {
                let attribution = super::provider_history::validate_history_record(history, stored)
                    .map_err(AdmissionAdapterError::History)?;
                let digest = super::provider_history::original_source_fence_digest(attribution)
                    .map_err(AdmissionAdapterError::History)?;
                ForgetSourceKeyV1::new(format!("original-source:{digest}"))
            }
            None => forget_source_key_for(&exact_scope, observation),
        }
        .map_err(|source| AdmissionAdapterError::Journal {
            source_event_id: source_event_id.clone(),
            source,
        })?;

        match admission {
            ObservationAdmission::Withheld {
                reason,
                receipt_id,
                source_payload_sha256,
                extensions_digest,
                sanitizer_revision,
                finding_count,
                findings_digest,
            } => {
                #[cfg(feature = "test-helpers")]
                if history.is_some() {
                    super::cognitive_recall::emit_host_history_recall_test_diagnostic(|| {
                        serde_json::json!({
                            "phase": "history_withheld",
                            "source_sequence": record.source_sequence.0,
                            "reason": reason.as_str(),
                        })
                    });
                }
                // Digests and a typed reason only. The canonical evidence the
                // host settled is not touched; the withheld row advances the
                // replay cursor so a refused event is not re-emitted forever,
                // and `source_event_id` still points at the untouched record.
                let withheld = WithheldAdmissionV1 {
                    source_authority: record.stream.source_authority.as_wire().to_owned(),
                    exact_scope_sha256: exact_scope.exact_scope_sha256(),
                    source_stream: record.stream.source_stream.as_str().to_owned(),
                    source_sequence: record.source_sequence.0,
                    source_event_id: source_event_id.clone(),
                    source_event_revision: record.source_event_revision.to_string(),
                    receipt_id,
                    reason: reason.as_str().to_owned(),
                    source_payload_sha256,
                    extensions_digest,
                    sanitizer_revision,
                    finding_count,
                    findings_digest,
                    forget_source_key,
                };
                withheld
                    .validate()
                    .map_err(|source| AdmissionAdapterError::Journal {
                        source_event_id,
                        source,
                    })?;
                Ok(AdmissionDecisionV1::Withhold(Box::new(withheld)))
            }
            ObservationAdmission::Admitted { sanitized, receipt } => {
                // Hygiene may redact spans inside the payload; it must not have
                // turned the envelope into something the provider cannot parse.
                // Checking is one map lookup, and the alternative is a dispatch
                // that fails at the provider with a contract violation nobody
                // can attribute back to redaction.
                if !envelope_shape_survived(&sanitized, context.observation_kind.as_str()) {
                    return Err(AdmissionAdapterError::EnvelopeShapeRewritten { source_event_id });
                }
                let source_identity_rewritten =
                    sanitized.get("source_identity") != envelope.get("source_identity");
                if history.is_some()
                    && (sanitized.get("history_grant") != envelope.get("history_grant")
                        || source_identity_rewritten)
                {
                    return Err(AdmissionAdapterError::History(
                        super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                            "sanitized history metadata",
                        ),
                    ));
                }
                if source_identity_rewritten {
                    return Err(AdmissionAdapterError::EnvelopeShapeRewritten { source_event_id });
                }
                let bytes = canonical_payload_bytes(&sanitized).map_err(|source| {
                    AdmissionAdapterError::CanonicalEncoding {
                        source_event_id: source_event_id.clone(),
                        source,
                    }
                })?;
                let payload_sha256 = receipt.sanitized_payload_sha256().to_owned();
                let payload = CanonicalPayload::new(
                    context.provider_payload_contract.clone(),
                    bytes,
                    payload_sha256.clone(),
                )
                .map_err(|source| AdmissionAdapterError::Payload {
                    source_event_id: source_event_id.clone(),
                    source,
                })?;
                let extensions = Vec::new();
                let extensions_digest = extensions_digest(&extensions).map_err(|source| {
                    AdmissionAdapterError::Journal {
                        source_event_id: source_event_id.clone(),
                        source,
                    }
                })?;
                let sanitization = SanitizationBindingV1 {
                    receipt_id: receipt.receipt_id().to_owned(),
                    sanitizer_revision: receipt.sanitizer_revision().to_owned(),
                    source_payload_sha256: receipt.source_payload_sha256().to_owned(),
                    receipt_json: receipt.to_json(),
                };

                let target = readiness_target_for_scope(
                    &context.readiness,
                    &context.provider_lane.provider_id,
                    &exact_scope,
                    context.registration_revision,
                    context.limits,
                    context.observe_capability.clone(),
                    // The caller's own bound, narrowed to the admission-time
                    // handshake budget. Minting a fresh token here is what
                    // made a five-second readiness call outlive a project that
                    // had already closed.
                    control.operation_control(READINESS_DEADLINE_MICROS),
                )
                .map_err(|source| AdmissionAdapterError::Readiness {
                    source_event_id: source_event_id.clone(),
                    source: Box::new(source),
                })?;
                let admitted_at_unix_micros = tracedecay_contracts::now_micros().0;
                let occurred_at_unix_micros = settlement.settled_at_unix_micros;
                let privacy = ObservationPrivacyV1 {
                    classification: PrivacyClassificationV1::Sensitive,
                    retention_class: ADMITTED_RETENTION_CLASS,
                    redaction_revision: 1,
                    content_policy_revision: 1,
                    forget_source_key,
                    expires_at_unix_micros: admitted_at_unix_micros
                        .saturating_add(ADMISSION_DEADLINE_MICROS),
                };
                let idempotency_key = ObservationIdempotencyKeyV1::derive(&IdempotencyInputV1 {
                    contract_id: OBSERVATION_CONTRACT_ID,
                    provider_id: target.provider_id.as_str(),
                    registration_revision: target.registration_revision,
                    exact_scope_sha256: &exact_scope.exact_scope_sha256(),
                    source_authority: settlement.source_authority,
                    source_event_id: &settlement.source_event_id,
                    source_event_revision: settlement.source_event_revision,
                    observation_kind: context.observation_kind.as_str(),
                    payload_contract: payload.contract_id.as_str(),
                    payload_sha256: &payload_sha256,
                    extensions_digest: &extensions_digest,
                });
                let observation_id =
                    mint_observation_id(admitted_at_unix_micros).map_err(|source| {
                        AdmissionAdapterError::Journal {
                            source_event_id: source_event_id.clone(),
                            source,
                        }
                    })?;
                let mut admitted = AdmittedObservationV1 {
                    observation_id,
                    idempotency_key,
                    target,
                    exact_scope,
                    source: settlement,
                    observation_kind: context.observation_kind.clone(),
                    payload,
                    extensions,
                    extensions_digest,
                    provenance_origin: ProvenanceOriginV1::Agent,
                    provenance_sha256: canonical_provenance_digest(stored),
                    privacy,
                    sanitization,
                    occurred_at_unix_micros,
                    admitted_at_unix_micros,
                    deadline_unix_micros: admitted_at_unix_micros
                        .saturating_add(ADMISSION_DEADLINE_MICROS),
                    request_id: format!("observe.{}", record.source_sequence.0),
                    envelope_sha256: String::new(),
                };
                admitted.envelope_sha256 = admitted.expected_envelope_sha256();
                admitted
                    .validate()
                    .map_err(|source| AdmissionAdapterError::Journal {
                        source_event_id,
                        source,
                    })?;
                Ok(AdmissionDecisionV1::Admit(Box::new(admitted)))
            }
        }
    }
}

struct GrantedHistoryAdmissionAdapterV1 {
    canonical: Arc<CanonicalObservationAdmissionAdapterV1>,
    grant: Option<tracedecay_memory_provider_registry::HistoryGrant>,
}

impl ObservationAdmissionAdapterV1 for GrantedHistoryAdmissionAdapterV1 {
    type Record = StoredObservation;
    type Error = AdmissionAdapterError;
    type Control = ReplayIngestControlV1;

    fn lane(&self, record: &SourceRecordV1<Self::Record>) -> ObservationLaneKeyV1 {
        self.canonical.lane(record)
    }

    fn classify(&self, record: &SourceRecordV1<Self::Record>) -> ObservationLoadClassV1 {
        self.canonical.classify(record)
    }

    fn decide(
        &self,
        record: &SourceRecordV1<Self::Record>,
        control: &Self::Control,
    ) -> Result<AdmissionDecisionV1, Self::Error> {
        let Some(grant) = self.grant.as_ref().filter(|grant| {
            grant
                .sources
                .iter()
                .any(|source| source.attribution.source.observation_id == record.source_event_id)
        }) else {
            // An authoritative bounded scan found this canonical event outside
            // this destination's delivery contract. Checkpoint it in this
            // destination stream; no source bytes are copied or relabeled.
            return Ok(AdmissionDecisionV1::NonMessage(Box::new(
                canonical_settlement_receipt(record, &record.record),
            )));
        };
        let mut grant = grant.clone();
        grant
            .sources
            .retain(|source| source.attribution.source.observation_id == record.source_event_id);
        self.canonical
            .decide_with_history(record, control, Some(&grant))
    }
}

/// Exact operation identity used by every original Observe delivery attempt.
pub(crate) fn delivery_operation_id(
    observation_id: &tracedecay_memory_observation::ObservationIdV1,
    attempt_number: u32,
) -> String {
    format!("{}.{}", observation_id.as_str(), attempt_number)
}

pub(crate) fn history_source_stream(
    destination: &OwnedExactScope,
    policy_revision: u64,
) -> Result<SourceStreamIdV1, ObservationJournalError> {
    SourceStreamIdV1::new(format!(
        "host-history.{policy_revision}.{}",
        destination.exact_scope_sha256()
    ))
}

/// Cancels a queued/running bounded snapshot even if its async caller is dropped.
struct HistoryDeliveryCancellationV1(CancellationToken);

impl Drop for HistoryDeliveryCancellationV1 {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) fn validate_history_delivery_evidence(
    grant: &tracedecay_memory_provider_registry::HistoryGrant,
    evidence: Vec<tracedecay_memory_observation::SourceDeliveryEvidenceV1>,
    cancellation: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<bool, ObservationJourneyError> {
    use super::provider_history::ProviderHistoryErrorV1;
    use tracedecay_memory_observation::{
        DeliveryStateV1, ObservationCommittedEffectV1, ObservationOutcomeV1,
        SourceDeliveryEvidenceV1,
    };
    if evidence.len() != grant.sources.len() {
        return Err(
            ProviderHistoryErrorV1::ClaimMismatch("history delivery evidence count").into(),
        );
    }
    let mut settled = true;
    for (source, evidence) in grant.sources.iter().zip(evidence) {
        if cancellation.is_cancelled() {
            return Err(ObservationJourneyError::Cancelled { admitted: 0 });
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 });
        }
        let (admitted, state, receipt) = match evidence {
            SourceDeliveryEvidenceV1::Missing => {
                #[cfg(feature = "test-helpers")]
                super::cognitive_recall::emit_host_history_recall_test_diagnostic(|| {
                    serde_json::json!({
                        "phase": "history_delivery_missing",
                        "source_sequence": source.attribution.source_sequence,
                    })
                });
                return Err(
                    ProviderHistoryErrorV1::Ineligible("history source not admitted").into(),
                );
            }
            SourceDeliveryEvidenceV1::Purged { .. } => {
                return Err(ProviderHistoryErrorV1::Ineligible("history source purged").into());
            }
            SourceDeliveryEvidenceV1::Retained {
                admitted,
                state,
                receipt,
            } => (admitted, state, receipt),
        };
        let payload: Value = serde_json::from_slice(&admitted.payload.bytes)
            .map_err(|_| ProviderHistoryErrorV1::ClaimMismatch("history delivery envelope"))?;
        let retained = payload
            .get("history_grant")
            .ok_or(ProviderHistoryErrorV1::ClaimMismatch(
                "history delivery grant",
            ))
            .and_then(super::provider_history::history_grant_from_json)?;
        let original = super::provider_history::source_attribution_json(&source.attribution)?;
        if retained.policy_revision != grant.policy_revision
            || retained.destination_scope != grant.destination_scope
            || retained.relation != grant.relation
            || retained.sources.len() != 1
            || retained.sources[0].attribution != source.attribution
            || payload.pointer("/source_identity/original_source") != Some(&original)
            || admitted.source.source_event_id != source.attribution.source.observation_id
            || admitted.source.source_sequence.0 != source.attribution.source_sequence
            || admitted.source.settled_at_unix_micros.checked_mul(1_000)
                != Some(source.attribution.ingested_at_utc_nanos)
            || admitted.observation_kind.as_str() != SESSION_MESSAGE_OBSERVATION_KIND
            || !envelope_shape_survived(&payload, SESSION_MESSAGE_OBSERVATION_KIND)
        {
            return Err(
                ProviderHistoryErrorV1::ClaimMismatch("history delivery original source").into(),
            );
        }
        match state {
            DeliveryStateV1::Pending | DeliveryStateV1::Leased | DeliveryStateV1::EffectUnknown => {
                settled = false;
            }
            DeliveryStateV1::Acknowledged | DeliveryStateV1::DuplicateAcknowledged => {
                let receipt = receipt.ok_or(ProviderHistoryErrorV1::ClaimMismatch(
                    "history acknowledgement receipt",
                ))?;
                if !matches!(
                    (receipt.outcome, receipt.committed_effect),
                    (
                        ObservationOutcomeV1::Applied,
                        ObservationCommittedEffectV1::Applied
                    ) | (
                        ObservationOutcomeV1::DuplicateAcknowledged,
                        ObservationCommittedEffectV1::Duplicate
                    )
                ) {
                    return Err(ProviderHistoryErrorV1::Ineligible(
                        "history delivery has no complete effect",
                    )
                    .into());
                }
            }
            _ => {
                return Err(ProviderHistoryErrorV1::Ineligible(
                    "history delivery terminal refusal",
                )
                .into());
            }
        }
    }
    Ok(settled)
}

/// The provider envelope retains the settled canonical record's identity
/// alongside its payload; provider-local delivery IDs never replace it.
fn provider_observation_envelope(
    observation_kind: &str,
    payload_contract: &str,
    canonical_payload: &Value,
    canonical_observation_id: &CanonicalObservationIdV1,
) -> Value {
    let mut envelope = Map::new();
    envelope.insert("canonical_payload".to_owned(), canonical_payload.clone());
    envelope.insert(
        "source_identity".to_owned(),
        serde_json::json!({ "canonical_observation_id": canonical_observation_id.as_str() }),
    );
    envelope.insert(
        "observation_kind".to_owned(),
        Value::String(observation_kind.to_owned()),
    );
    envelope.insert(
        "payload_contract".to_owned(),
        Value::String(payload_contract.to_owned()),
    );
    Value::Object(envelope)
}

/// Whether the sanitized envelope still carries the three fields the provider
/// adapter requires, with the kind and contract unrewritten.
fn envelope_shape_survived(sanitized: &Value, observation_kind: &str) -> bool {
    let Some(object) = sanitized.as_object() else {
        return false;
    };
    object.get("observation_kind").and_then(Value::as_str) == Some(observation_kind)
        && object.get("payload_contract").and_then(Value::as_str)
            == Some(SESSION_MESSAGE_PAYLOAD_CONTRACT)
        && object
            .get("canonical_payload")
            .is_some_and(|payload| !payload.is_null())
}

/// Mints a `UUIDv7` observation identity from real entropy.
///
/// The stamp is the admission instant; the ten trailing bytes come from the
/// operating system. Feeding a counter here would collide on the journal's
/// unique index, so the entropy is not decorative — and an entropy failure is
/// reported rather than papered over with a constant.
pub(super) fn mint_observation_id(
    admitted_at_unix_micros: i64,
) -> Result<ObservationIdV1, ObservationJournalError> {
    let unix_millis = u64::try_from(admitted_at_unix_micros.max(0) / 1_000).unwrap_or(0);
    let mut entropy = [0u8; 10];
    if getrandom::fill(&mut entropy).is_err() {
        return Err(ObservationJournalError::InvalidObservationId {
            detail: "system entropy is unavailable for observation identity".to_owned(),
        });
    }
    ObservationIdV1::from_v7_parts(unix_millis, entropy)
}

/// The forget-source key a privacy deletion targets: the exact scope plus the
/// canonical session the content came from. Deleting one agent session's
/// provider copies must not reach another session in the same project.
fn forget_source_key_for(
    exact_scope: &OwnedExactScope,
    observation: &DurableObservationV1,
) -> Result<ForgetSourceKeyV1, ObservationJournalError> {
    ForgetSourceKeyV1::new(
        exact_scope.session_forget_source_key(observation.source().session_id().as_str()),
    )
}

/// Copies the canonical commit receipt into the journal's settlement proof.
///
/// Every field is carried over from what the host authority already settled.
/// Nothing here mints a settlement the store did not report — that is exactly
/// the observation contract's `reject_not_canonically_settled`.
fn canonical_settlement_receipt(
    record: &SourceRecordV1<StoredObservation>,
    stored: &StoredObservation,
) -> CanonicalSettlementReceiptV1 {
    CanonicalSettlementReceiptV1 {
        source_authority: record.stream.source_authority,
        commit_point_id: SESSION_COMMIT_POINT_ID.to_owned(),
        source_event_id: record.source_event_id.clone(),
        source_event_revision: record.source_event_revision,
        source_event_sha256: canonical_source_event_digest(stored),
        source_stream: record.stream.source_stream.clone(),
        source_sequence: record.source_sequence,
        settled_at_unix_micros: stored.retrieval_anchor().ingested_at().0,
        settlement_proof_sha256: canonical_settlement_proof_digest(stored),
    }
}

/// Digest of the settled source event: the canonical observation identity, the
/// payload the store durably holds, and the position it settled at.
fn canonical_source_event_digest(stored: &StoredObservation) -> String {
    let observation = stored.observation();
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.memory-provider.canonical-source-event.v1\0");
    absorb(
        &mut digest,
        observation.observation_id().as_str().as_bytes(),
    );
    absorb(
        &mut digest,
        observation.payload_reference().digest().as_str().as_bytes(),
    );
    absorb(&mut digest, &stored.sequence().to_be_bytes());
    hex::encode(digest.finalize())
}

/// Digest over exactly the `receipt_fields` the host-event observation policy
/// names for the `session_observation_store.commit` point.
fn canonical_settlement_proof_digest(stored: &StoredObservation) -> String {
    let observation = stored.observation();
    let identity = observation.identity();
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.memory-provider.canonical-settlement-proof.v1\0");
    // durable_observation_id
    absorb(
        &mut digest,
        observation.observation_id().as_str().as_bytes(),
    );
    // source_cursor
    absorb(
        &mut digest,
        &stored.committed_cursor().position().to_be_bytes(),
    );
    // source_generation
    absorb(
        &mut digest,
        &identity.generation().generation_id().to_be_bytes(),
    );
    // source_range
    absorb(&mut digest, &identity.position().start().to_be_bytes());
    absorb(&mut digest, &identity.position().end().to_be_bytes());
    // settlement_digest: the retained sanitization receipt the store settled
    // under. `resolved_scope_digest` is bound separately, through the exact
    // scope the envelope digest already absorbs.
    absorb(
        &mut digest,
        stored
            .sanitization_receipt()
            .receipt()
            .receipt_id()
            .as_str()
            .as_bytes(),
    );
    hex::encode(digest.finalize())
}

/// Digest over the provenance the admitting authority holds. The provider gets
/// the digest, never the retained provenance record itself.
fn canonical_provenance_digest(stored: &StoredObservation) -> String {
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.memory-provider.canonical-provenance.v1\0");
    absorb(
        &mut digest,
        stored.retrieval_anchor_id().as_str().as_bytes(),
    );
    absorb(
        &mut digest,
        stored.projection_generation().as_str().as_bytes(),
    );
    absorb(
        &mut digest,
        stored.observation().source().provider().as_str().as_bytes(),
    );
    hex::encode(digest.finalize())
}

/// Length-frames one field so no two field boundaries can collide.
fn absorb(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

/// Delivers one leased observation through the registry, and only through the
/// registry.
///
/// The call is built from the leased row's own bytes, extensions, stored
/// sanitization binding, exact scope, idempotency key, and deadline, plus the
/// readiness evidence currently held. Nothing is re-read from the canonical
/// store at delivery time: the provider must see exactly the bytes the journal
/// committed, or its `payload_sha256` comparison would not match the receipt
/// the journal stores.
#[derive(Clone)]
struct RegistryObservationDeliveryAdapterV1 {
    provider_id: OwnedProviderId,
    composition: Arc<ProjectMemoryProviderComposition>,
    readiness: Arc<SupervisedProviderReadinessV1>,
    provider_instance: Arc<ProviderInstanceStateV1>,
    /// The bounded-execution boundary every provider call runs on. Delivery
    /// runs on the journey's single dedicated worker thread, so a provider
    /// that hangs or crashes inside `observe` would otherwise take the whole
    /// lane with it.
    isolation: Arc<ThreadBoundedProviderCallV1>,
    registration_revision: u64,
    limits: ProviderLimits,
    observe_capability: OwnedVersionedId,
    /// Restart recovery. Every attempt passes through it, so a provider whose
    /// state moved under the journal is refused before it is written to.
    recovery: ObservationRecoveryGateV1,
    history_authority: Arc<OnceLock<Arc<dyn super::provider_history::HistoryGrantRevalidationV1>>>,
}

/// Typed delivery-adapter failures and provider-terminal refusals.
///
/// A failure before an answer produces no receipt. A provider terminal refused
/// after contact is also published here, but the journal records it separately
/// as refusal evidence with an unknown-effect receipt before redelivery.
#[derive(Debug, thiserror::Error)]
enum DeliveryAdapterError {
    #[error("host history authorization failed: {0}")]
    History(#[source] super::provider_history::ProviderHistoryErrorV1),
    #[error("provider composition is disabled, so no observation can be delivered")]
    Disabled,
    #[error("provider readiness could not be proven for the leased exact scope: {0}")]
    Readiness(#[source] ObservationJourneyError),
    #[error("leased provider instance {leased} differs from current proved instance {current}")]
    ProviderInstanceChanged { leased: String, current: String },
    #[error("restart recovery refused this provider incarnation: {0}")]
    Recovery(#[source] RecoveryRefusalV1),
    #[error("stored sanitization receipt could not be reattached: {0}")]
    Sanitization(#[source] ApiError),
    #[error("observation call could not be built: {0}")]
    Call(#[source] ApiError),
    #[error("registry refused the observation: {0}")]
    Fabric(#[source] FabricError),
    #[error("the provider call could not be completed inside its own bound: {0}")]
    Isolation(#[source] BoundedCallRefusalV1),
}

impl RegistryObservationDeliveryAdapterV1 {
    fn registry(&self) -> Result<&ProjectMemoryProviderRegistry, DeliveryAdapterError> {
        self.composition
            .registry()
            .ok_or(DeliveryAdapterError::Disabled)
    }
}

/// How many recent delivery refusals the lane keeps.
///
/// A bounded window, not a log: the lane answers "what is going wrong right
/// now" and nothing accumulates for the life of the process.
const DELIVERY_REFUSAL_HISTORY: usize = 16;

/// The exact classification of one delivery refusal.
///
/// The worker already held this and threw it away into a formatted string. An
/// operator asking the only question that matters — "is the provider
/// unreachable, or is it answering things we refuse?" — cannot get an answer
/// out of free text, because the two faults have different repairs: the first
/// is the provider's liveness, the second is a contract violation that will
/// repeat on every retry until somebody fixes the provider. This is that
/// answer, typed, published by the lane and carried on its log line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DeliveryRefusalClassV1 {
    /// Current host source/session/privacy authority refused historical reuse.
    HistoryRefused,
    /// The provider composition is disabled, so nothing could be delivered.
    CompositionDisabled,
    /// Readiness could not be proven for the leased exact scope.
    ReadinessRefused,
    /// Restart recovery refused the incarnation that answered readiness.
    RecoveryRefused,
    /// The stored sanitization receipt could not be reattached to the bytes.
    SanitizationUnusable(ApiError),
    /// The observation call could not be built inside the host's own limits.
    CallNotConstructible(ApiError),
    /// The provider answered and the registry refused what it answered. This
    /// is the provider-misbehaviour class, and the inner value names which
    /// misbehaviour.
    ProviderReplyRefused(FabricError),
    /// The provider call did not complete inside the host's own bound.
    BoundedCallRefused(BoundedCallRefusalV1),
    /// The provider answered a terminal that does not describe the delivery it
    /// was handed, so no receipt could be minted from it.
    TerminalIdentityMismatch {
        /// Logical terminal field that disagreed with the lease.
        field: &'static str,
    },
    /// The provider's terminal was about this delivery but could not be
    /// admitted as a receipt.
    ReceiptNotAdmissible,
    /// A failure reached the runtime's adapter channel from somewhere this
    /// mount does not produce. Never silently folded into another class: an
    /// unclassified refusal is itself a finding.
    Unclassified,
}

impl DeliveryRefusalClassV1 {
    /// Stable wire label for the log line and any operator surface built on it.
    pub(crate) const fn as_wire(&self) -> &'static str {
        match self {
            Self::HistoryRefused => "history_refused",
            Self::CompositionDisabled => "composition_disabled",
            Self::ReadinessRefused => "readiness_refused",
            Self::RecoveryRefused => "recovery_refused",
            Self::SanitizationUnusable(_) => "sanitization_unusable",
            Self::CallNotConstructible(_) => "call_not_constructible",
            Self::ProviderReplyRefused(_) => "provider_reply_refused",
            Self::BoundedCallRefused(_) => "bounded_call_refused",
            Self::TerminalIdentityMismatch { .. } => "terminal_identity_mismatch",
            Self::ReceiptNotAdmissible => "receipt_not_admissible",
            Self::Unclassified => "unclassified",
        }
    }

    /// Classifies one adapter failure as the mount itself produced it.
    ///
    /// The runtime keeps the adapter's own error whole rather than mapping it,
    /// which is what makes this recoverable at all: the concrete type is still
    /// in there. Two of the classes come from the runtime instead of from this
    /// adapter — a terminal that does not describe the lease, and a terminal
    /// that cannot become a receipt — and both are provider misbehaviour just
    /// as much as a fabric refusal is, so both are named here.
    fn classify(cause: &(dyn std::error::Error + Send + Sync + 'static)) -> Self {
        if let Some(adapter) = cause.downcast_ref::<DeliveryAdapterError>() {
            return match adapter {
                DeliveryAdapterError::History(_) => Self::HistoryRefused,
                DeliveryAdapterError::Disabled => Self::CompositionDisabled,
                DeliveryAdapterError::Readiness(_)
                | DeliveryAdapterError::ProviderInstanceChanged { .. } => Self::ReadinessRefused,
                DeliveryAdapterError::Recovery(_) => Self::RecoveryRefused,
                DeliveryAdapterError::Sanitization(error) => {
                    Self::SanitizationUnusable(error.clone())
                }
                DeliveryAdapterError::Call(error) => Self::CallNotConstructible(error.clone()),
                DeliveryAdapterError::Fabric(error) => Self::ProviderReplyRefused(error.clone()),
                DeliveryAdapterError::Isolation(refusal) => {
                    Self::BoundedCallRefused(refusal.clone())
                }
            };
        }
        if let Some(mismatch) = cause.downcast_ref::<TerminalIdentityMismatchV1>() {
            return Self::TerminalIdentityMismatch {
                field: mismatch.field,
            };
        }
        if cause.downcast_ref::<ObservationJournalError>().is_some() {
            return Self::ReceiptNotAdmissible;
        }
        Self::Unclassified
    }
}

/// One delivery refusal, as the lane publishes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliveryRefusalV1 {
    /// Observation the refused attempt addressed.
    pub(crate) observation_id: String,
    /// Attempt number the refused claim consumed.
    pub(crate) attempt_number: u32,
    /// When the lane recorded the refusal.
    pub(crate) at_unix_micros: i64,
    /// The typed classification.
    pub(crate) class: DeliveryRefusalClassV1,
    /// The failure's own text, so the class never has to carry every detail.
    pub(crate) detail: String,
}

/// The lane's bounded window onto its own delivery refusals.
///
/// Deliberately finite and deliberately in memory: it is a diagnostic about
/// the running lane, not durable evidence. The durable statement about a
/// refused *answer* is the journal's own attempt-refusal audit; this window
/// covers every delivery refused by the lane, including the ones where no
/// answer arrived at all and the journal therefore has nothing to record.
#[derive(Debug, Default)]
struct DeliveryRefusalWindowV1 {
    recent: Mutex<std::collections::VecDeque<DeliveryRefusalV1>>,
    total: std::sync::atomic::AtomicU64,
    changed: CensusTransitionV1,
}

impl DeliveryRefusalWindowV1 {
    fn record(&self, refusal: DeliveryRefusalV1) {
        self.total.fetch_add(1, Ordering::AcqRel);
        let mut recent = match self.recent.lock() {
            Ok(recent) => recent,
            Err(poisoned) => poisoned.into_inner(),
        };
        while recent.len() >= DELIVERY_REFUSAL_HISTORY {
            recent.pop_front();
        }
        recent.push_back(refusal);
        drop(recent);
        self.changed.publish();
    }

    fn recent(&self) -> Vec<DeliveryRefusalV1> {
        match self.recent.lock() {
            Ok(recent) => recent.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    fn total(&self) -> u64 {
        self.total.load(Ordering::Acquire)
    }

    #[cfg(test)]
    async fn wait_for(
        &self,
        within: Duration,
        mut admits: impl FnMut(&DeliveryRefusalV1) -> bool,
    ) -> Result<DeliveryRefusalV1, Vec<DeliveryRefusalV1>> {
        self.changed
            .wait_until_async(within, || self.recent().into_iter().find(&mut admits))
            .await
            .map_err(|()| self.recent())
    }
}

/// Why restart recovery refused to deliver into the incarnation that answered
/// the handshake.
///
/// Every variant produces no provider call, no receipt, and no state change:
/// the row stays exactly as deliverable as it was, and the failure reaches the
/// dispatch report with its cause intact.
#[derive(Debug, thiserror::Error)]
enum RecoveryRefusalV1 {
    #[error("recovery could not be assessed against the journal: {0}")]
    Assessment(#[source] ObservationRuntimeError),
    #[error("restart recovery stopped because the delivery attempt was cancelled: {0}")]
    Cancelled(#[source] ObservationRuntimeError),
    #[error("restart recovery stopped because the attempt's budget expired: {0}")]
    DeadlineExceeded(#[source] ObservationRuntimeError),
    #[error("provider state is incompatible ({defect}); {repair} before delivery resumes")]
    StateIncompatible {
        /// Canonical wire value of the typed defect.
        defect: &'static str,
        /// Canonical wire value of the repair the defect requires.
        repair: &'static str,
    },
}

impl RecoveryRefusalV1 {
    /// Classifies one runtime failure without flattening a bound that expired
    /// into a journal failure: only the first is a reason to hand the row
    /// straight back.
    fn from_runtime(error: ObservationRuntimeError) -> Self {
        match error {
            cancelled @ ObservationRuntimeError::RecoveryCancelled { .. } => {
                Self::Cancelled(cancelled)
            }
            expired @ ObservationRuntimeError::RecoveryDeadlineExceeded { .. } => {
                Self::DeadlineExceeded(expired)
            }
            other => Self::Assessment(other),
        }
    }
}

/// The restart-recovery gate every delivery attempt passes through.
///
/// The provider's own state schema and generation come from the *same*
/// validated handshake that produced the delivery address, so the journal never
/// pairs an address from one incarnation with state evidence from another. A
/// provider whose state schema moved, or whose generation went backwards
/// because it was restored or wiped, is refused here — before any observation
/// reaches it — instead of being silently reinitialized by replaying history it
/// no longer holds.
///
/// The admitted answer is the expected state generation the provider call must
/// declare. Nothing else may supply it: a hardcoded expectation would make the
/// fabric's own `ready.state_generation == call.expected_state_generation`
/// check vacuous.
#[derive(Clone)]
struct ObservationRecoveryGateV1 {
    journal: Arc<SqliteObservationJournal>,
    provider_id: String,
    registration_revision: u64,
    source_authority: SourceAuthorityV1,
    source_stream: SourceStreamIdV1,
    budget: RecoveryBudgetV1,
}

impl ObservationRecoveryGateV1 {
    /// The replay position the validated readiness evidence proves for this
    /// incarnation.
    ///
    /// Absence is a *decision* here, not a default. The handshake contract's
    /// only sanctioned channel for a provider-local acknowledged position is
    /// the replay capability, so an incarnation that does not declare it keeps
    /// no position, and exact-effect verification rests on the host's
    /// content-derived idempotency key and its own durable receipts. An
    /// incarnation that *does* declare it and whose position the host cannot
    /// read is refused rather than treated as the first case, because that is
    /// precisely the shape in which lost provider effects would go unnoticed.
    fn replay_position(evidence: &ReadinessEvidenceV1) -> ProviderReplayPositionV1 {
        if evidence.retains_replay_position() {
            ProviderReplayPositionV1::Unreadable
        } else {
            ProviderReplayPositionV1::NotRetained
        }
    }

    /// Assesses the incarnation that just proved readiness for one exact scope
    /// and returns the generation a delivery call may declare.
    ///
    /// The attempt's own bound travels into the assessment: the journal read,
    /// the frontier read, and the single durable write all run under the
    /// delivery deadline and the delivery cancellation token, so a shutdown or
    /// an expired budget stops recovery itself rather than only the provider
    /// call after it.
    fn admit_delivery(
        &self,
        exact_scope_sha256: &str,
        evidence: &ReadinessEvidenceV1,
        control: &DeliveryControlV1,
        now_unix_micros: i64,
    ) -> Result<u64, RecoveryRefusalV1> {
        let checkpoint = ProviderCheckpointV1 {
            target: RecoveryTargetKeyV1 {
                provider_id: self.provider_id.clone(),
                registration_revision: self.registration_revision,
                stream: SourceStreamKeyV1 {
                    source_authority: self.source_authority,
                    exact_scope_sha256: exact_scope_sha256.to_owned(),
                    source_stream: self.source_stream.clone(),
                },
            },
            implementation_identity_sha256: evidence.implementation_identity_sha256().to_owned(),
            state_schema_version: evidence.state_schema_version().to_owned(),
            state_generation: evidence.state_generation(),
            replay_position: Self::replay_position(evidence),
        };
        let recovery_control =
            RecoveryControlV1::new(control.deadline_unix_micros(), control.cancellation());
        let runtime = RecoveryRuntimeV1::new(self.journal.as_ref(), self.budget)
            .map_err(RecoveryRefusalV1::Assessment)?;
        let plan = runtime
            .assess(&checkpoint, &recovery_control, now_unix_micros)
            .map_err(RecoveryRefusalV1::from_runtime)?;
        let operator_repair_required =
            matches!(plan, RecoveryPlanV1::OperatorRepairRequired { .. });
        match &plan {
            // Replay is not a separate code path: the outbox already holds the
            // unacknowledged rows, and this dispatcher is the loop that drains
            // them. What the plan adds is the verified generation and the
            // proof that draining them is safe.
            RecoveryPlanV1::Converged {
                expected_state_generation,
                ..
            }
            | RecoveryPlanV1::ReplayUnacknowledged {
                expected_state_generation,
                ..
            } => Ok(*expected_state_generation),
            RecoveryPlanV1::StateIncompatible { defect, repair, .. }
            | RecoveryPlanV1::OperatorRepairRequired { defect, repair, .. } => {
                tracing::warn!(
                    event = "memory_observation_recovery_refused",
                    exact_scope_sha256,
                    defect = defect.as_wire(),
                    repair = repair.as_wire(),
                    operator_repair_required,
                    "restart recovery refused delivery into this provider state"
                );
                Err(RecoveryRefusalV1::StateIncompatible {
                    defect: defect.as_wire(),
                    repair: repair.as_wire(),
                })
            }
        }
    }
}

fn rejected_terminal_binding(
    error: &FabricError,
) -> (
    AttemptRefusalCategoryV1,
    &'static str,
    Option<String>,
    Option<String>,
) {
    match error {
        FabricError::ResponseOperationMismatch { expected, returned } => (
            AttemptRefusalCategoryV1::TerminalIdentityMismatch,
            "operation_id",
            Some(expected.clone()),
            Some(returned.clone()),
        ),
        FabricError::ResponseOperationKindMismatch { expected, returned } => (
            AttemptRefusalCategoryV1::TerminalIdentityMismatch,
            "operation_kind",
            Some(expected.as_wire().to_owned()),
            Some(returned.as_wire().to_owned()),
        ),
        FabricError::ResponseProviderMismatch { expected, returned } => (
            AttemptRefusalCategoryV1::TerminalIdentityMismatch,
            "provider_id",
            Some(expected.clone()),
            Some(returned.clone()),
        ),
        FabricError::ResponseScopeMismatch { expected, returned } => (
            AttemptRefusalCategoryV1::TerminalIdentityMismatch,
            "exact_scope_sha256",
            Some(expected.clone()),
            Some(returned.clone()),
        ),
        _ => (
            AttemptRefusalCategoryV1::ReceiptNotAdmissible,
            "terminal_record",
            None,
            None,
        ),
    }
}

impl ProviderDeliveryAdapterV1 for RegistryObservationDeliveryAdapterV1 {
    type Error = DeliveryAdapterError;

    fn deliver(
        &self,
        leased: &LeasedObservationV1,
        control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        // Readiness owns registry and supervisor mutexes in addition to the
        // provider handshake it performs. Put the whole proof-to-dispatch
        // critical section behind the attempt's hard boundary so neither a
        // non-cooperative handshake nor a contended readiness owner can hold
        // the journey's single delivery thread past shutdown. The borrowed
        // worker rechecks the same cancellation token before every provider
        // effect; if it answers after cancellation, `call_within` discards the
        // answer and this method records only host-owned cancellation evidence.
        let started_at_unix_micros = tracedecay_contracts::now_micros().0;
        let budget_millis = u64::try_from(control.remaining_micros(started_at_unix_micros) / 1_000)
            .unwrap_or(u64::MAX);
        let cancellation = control.cancellation();
        if budget_millis == 0 {
            return Err(DeliveryAdapterError::Isolation(
                BoundedCallRefusalV1::Abandoned { waited_millis: 0 },
            ));
        }
        let adapter = self.clone();
        let leased = leased.clone();
        let isolated_control = control.clone();
        match self
            .isolation
            .call_within(budget_millis, &cancellation, move || {
                adapter.deliver_after_readiness(&leased, &isolated_control)
            }) {
            Ok(answer) => answer,
            Err(BoundedCallRefusalV1::Cancelled) if cancellation.is_cancelled() => {
                Ok(DeliveryAttemptV1::CancelledByShutdown {
                    started_at_unix_micros,
                    finished_at_unix_micros: tracedecay_contracts::now_micros().0,
                })
            }
            Err(refusal) => Err(DeliveryAdapterError::Isolation(refusal)),
        }
    }
}

impl RegistryObservationDeliveryAdapterV1 {
    fn deliver_after_readiness(
        &self,
        leased: &LeasedObservationV1,
        control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, DeliveryAdapterError> {
        // The attempt's bound is the runtime's, never minted here: its
        // deadline is already the tightest of the dispatch budget, the lease
        // expiry, and the row's own delivery deadline, and its token is the
        // wake edge's, cancelled at shutdown. Readiness and the observation
        // call both run under it, so a shutdown reaches a provider that is
        // inside either.
        let started_at_unix_micros = tracedecay_contracts::now_micros().0;
        let operation_control = |now: i64| {
            OperationControl::new(
                control.deadline_unix_micros(),
                u64::try_from(control.remaining_micros(now) / 1_000).unwrap_or(u64::MAX),
                control.cancellation(),
            )
        };
        let payload: Value = serde_json::from_slice(&leased.payload.bytes).map_err(|_| {
            DeliveryAdapterError::History(
                super::provider_history::ProviderHistoryErrorV1::ClaimMismatch("journal envelope"),
            )
        })?;
        let history = payload
            .get("history_grant")
            .map(super::provider_history::history_grant_from_json)
            .transpose()
            .map_err(DeliveryAdapterError::History)?;
        let mut recovery = self.recovery.clone();
        if let Some(history) = &history {
            if history.destination_scope != leased.exact_scope || history.sources.len() != 1 {
                return Err(DeliveryAdapterError::History(
                    super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                        "journal history destination/source",
                    ),
                ));
            }
            let original =
                super::provider_history::source_attribution_json(&history.sources[0].attribution)
                    .map_err(DeliveryAdapterError::History)?;
            if payload.pointer("/source_identity/original_source") != Some(&original) {
                return Err(DeliveryAdapterError::History(
                    super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                        "journal original attribution",
                    ),
                ));
            }
            let authority = self.history_authority.get().ok_or_else(|| {
                DeliveryAdapterError::History(
                    super::provider_history::ProviderHistoryErrorV1::Unavailable(
                        "history authority mount",
                    ),
                )
            })?;
            authority
                .revalidate(
                    &self.provider_id,
                    history,
                    &operation_control(started_at_unix_micros),
                )
                .map_err(DeliveryAdapterError::History)?;
            recovery.source_stream =
                history_source_stream(&history.destination_scope, history.policy_revision)
                    .map_err(|_| {
                        DeliveryAdapterError::History(
                            super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                                "history stream",
                            ),
                        )
                    })?;
        }
        let readiness_request = readiness_handshake_request(
            &self.provider_id,
            &leased.exact_scope,
            self.registration_revision,
            self.limits,
            self.observe_capability.clone(),
            operation_control(started_at_unix_micros),
        )
        .map_err(DeliveryAdapterError::Readiness)?;
        // Keep registration-wide dispatch ownership from this handshake through
        // the observation call. Admission also obtains readiness through this
        // owner, so it cannot rotate the fabric's current receipt in the gap.
        let readiness_dispatch = match self
            .readiness
            .ready_dispatch_with_evidence(&readiness_request, tracedecay_contracts::now_micros().0)
        {
            Ok(dispatch) => dispatch,
            // Classify this result at the instant readiness answers. A
            // shutdown already visible here owns the attempt and must leave
            // cancellation evidence; otherwise preserve readiness's exact
            // typed refusal.
            Err(_cause) if control.is_cancelled() => {
                return Ok(DeliveryAttemptV1::CancelledByShutdown {
                    started_at_unix_micros,
                    finished_at_unix_micros: tracedecay_contracts::now_micros().0,
                });
            }
            Err(cause) => {
                return Err(DeliveryAdapterError::Readiness(
                    ObservationJourneyError::SupervisedReadiness(cause),
                ));
            }
        };
        if control.is_cancelled() {
            return Ok(DeliveryAttemptV1::CancelledByShutdown {
                started_at_unix_micros,
                finished_at_unix_micros: tracedecay_contracts::now_micros().0,
            });
        }
        let current_instance = readiness_dispatch.target().provider_instance_id();
        self.provider_instance
            .refresh_from_readiness(current_instance, &control.cancellation());
        if leased.target.provider_instance_id != current_instance {
            // The lease owns cancellation, refusal, and acknowledgement identity.
            // A replacement may receive these bytes only after the journal's
            // existing retry claims them under this newly proved instance.
            return Err(DeliveryAdapterError::ProviderInstanceChanged {
                leased: leased.target.provider_instance_id.clone(),
                current: current_instance.to_owned(),
            });
        }
        // The recovery gate runs on the evidence of the very handshake above,
        // before one byte reaches the provider. A refusal is typed and leaves
        // the row exactly as deliverable as it was; shutdown cancellation is
        // additionally recorded as host-owned attempt evidence.
        let expected_state_generation = match recovery.admit_delivery(
            &leased.exact_scope_sha256,
            readiness_dispatch.evidence(),
            control,
            tracedecay_contracts::now_micros().0,
        ) {
            Ok(generation) => generation,
            // A recovery pass stopped by the shutdown that owns this attempt is
            // not a provider refusal: no byte reached the provider, so the row
            // is handed straight back to the next life of the dispatcher
            // instead of serving a backoff for a shutdown it did not cause.
            Err(RecoveryRefusalV1::Cancelled(_)) if control.is_cancelled() => {
                return Ok(DeliveryAttemptV1::CancelledByShutdown {
                    started_at_unix_micros,
                    finished_at_unix_micros: tracedecay_contracts::now_micros().0,
                });
            }
            Err(refusal) => return Err(DeliveryAdapterError::Recovery(refusal)),
        };
        // Fail fast and typed when the composition is disabled: no worker is
        // borrowed for a provider that is not there.
        self.registry()?;
        let control = operation_control(tracedecay_contracts::now_micros().0);
        // The persisted receipt is reattached verbatim so the boundary check
        // runs against the exact hygiene evidence that admitted these bytes.
        let sanitization = PayloadSanitizationReceipt::from_json(&leased.sanitization.receipt_json)
            .map_err(DeliveryAdapterError::Sanitization)?;
        let call = ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Observe,
            provider_id: readiness_dispatch.target().provider_id().clone(),
            registration_revision: readiness_dispatch.target().registration_revision(),
            ready_receipt_sha256: readiness_dispatch
                .target()
                .ready_receipt_sha256()
                .to_owned(),
            exact_scope: leased.exact_scope.clone(),
            request_id: leased.observation_id.as_str().to_owned(),
            operation_id: delivery_operation_id(&leased.observation_id, leased.attempt_number),
            expected_state_generation,
            idempotency_key: Some(leased.idempotency_key.as_str().to_owned()),
            control,
            payload: CanonicalPayload::new(
                leased.payload.contract_id.clone(),
                leased.payload.bytes.clone(),
                leased.payload.sha256.clone(),
            )
            .map_err(DeliveryAdapterError::Call)?,
            required_capabilities: vec![self.observe_capability.clone()],
            extensions: leased.extensions.clone(),
        })
        .map_err(DeliveryAdapterError::Call)?
        .with_sanitization(sanitization);
        call.validate_request_bytes(self.limits.request_bytes)
            .map_err(DeliveryAdapterError::Call)?;

        if let Some(history) = &history {
            self.history_authority
                .get()
                .ok_or_else(|| {
                    DeliveryAdapterError::History(
                        super::provider_history::ProviderHistoryErrorV1::Unavailable(
                            "history authority mount",
                        ),
                    )
                })?
                .revalidate(&self.provider_id, history, &call.control)
                .map_err(DeliveryAdapterError::History)?;
        }

        // This helper itself runs on the attempt's borrowed worker. Keep the
        // readiness guard alive through the direct registry call so no other
        // scope can rotate the ready receipt in between; the outer boundary
        // contains a provider that hangs or panics and discards any answer that
        // arrives after cancellation.
        let answered = self
            .registry()?
            .deliver_observation_result(&call)
            .map_err(DeliveryAdapterError::Fabric)?;
        drop(readiness_dispatch);
        let finished_at_unix_micros = tracedecay_contracts::now_micros().0;
        match answered {
            ObserverDeliveryResult::Accepted(receipt) => Ok(DeliveryAttemptV1::Answered {
                terminal: Box::new(receipt.terminal),
                started_at_unix_micros,
                finished_at_unix_micros,
            }),
            ObserverDeliveryResult::RejectedTerminal { terminal, error } => {
                let (category, refused_field, expected, provided) =
                    rejected_terminal_binding(&error);
                Ok(DeliveryAttemptV1::RejectedTerminal {
                    terminal: Box::new(terminal),
                    category,
                    refused_field,
                    expected,
                    provided,
                    cause: AdapterFailureV1::new(DeliveryAdapterError::Fabric(error)),
                    started_at_unix_micros,
                    finished_at_unix_micros,
                })
            }
        }
    }
}

/// One record's bound, in the shape both the ingress runtime and the admission
/// adapter take.
///
/// The deadline is the replay pass's own remaining wall budget, so a record can
/// never outlive the pass that started it. The cancellation is not a fresh
/// identity: it is the caller's own project-open token and the journey's own
/// stop token, read synchronously at every checkpoint, plus a relay that
/// carries the same signal into a sub-operation that is already in flight.
/// Minting a token here instead is what let an admission keep working — for up
/// to a five-second readiness budget — for a project that had already closed.
#[derive(Debug)]
pub(crate) struct ReplayIngestControlV1 {
    deadline_unix_micros: i64,
    /// The caller's own token — the project-open cancellation at startup, the
    /// journey's stop token on the live task. Read synchronously at every
    /// checkpoint, so a checkpoint can never race an asynchronous relay.
    caller: HostCancellationToken,
    /// The journey's stop token, so shutdown reaches inside a record too.
    stopping: HostCancellationToken,
    /// The very same signal in the shape a provider operation takes. It is
    /// flipped from the two tokens above — never minted as a new identity —
    /// both before a sub-operation starts and, by the relay the caller spawns,
    /// while one is already in flight.
    cancellation: CancellationToken,
}

impl ReplayIngestControlV1 {
    /// The bound a sub-operation inside this record runs under: never wider
    /// than the caller's remaining budget, and carrying the caller's own
    /// cancellation rather than a new one.
    fn operation_control(&self, budget_micros: i64) -> OperationControl {
        if self.caller.is_cancelled() || self.stopping.is_cancelled() {
            self.cancellation.cancel();
        }
        let now = tracedecay_contracts::now_micros().0;
        let deadline = now
            .saturating_add(budget_micros)
            .min(self.deadline_unix_micros);
        let remaining = deadline.saturating_sub(now).max(0);
        OperationControl::new(
            deadline,
            u64::try_from(remaining / 1_000).unwrap_or(0),
            self.cancellation.clone(),
        )
    }
}

impl IngressControlV1 for ReplayIngestControlV1 {
    fn now_unix_micros(&self) -> i64 {
        tracedecay_contracts::now_micros().0
    }

    fn deadline_unix_micros(&self) -> i64 {
        self.deadline_unix_micros
    }

    fn is_cancelled(&self) -> bool {
        self.caller.is_cancelled()
            || self.stopping.is_cancelled()
            || self.cancellation.is_cancelled()
    }
}

/// The wall-clock instant a monotonic pass deadline corresponds to.
///
/// The pass budget is a `tokio::time::Instant` and every bound inside a record
/// is UTC micros, so the remaining budget is what carries across — never a
/// fresh budget, which would silently widen the caller's deadline.
fn wall_deadline_micros(deadline: tokio::time::Instant) -> i64 {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let remaining = i64::try_from(remaining.as_micros()).unwrap_or(i64::MAX);
    tracedecay_contracts::now_micros()
        .0
        .saturating_add(remaining)
}

/// Finite ceiling on provider calls this host will hold parked in a provider
/// at once before it refuses to start another one. A parked call costs one
/// borrowed thread; bounding them is what keeps "the host stays usable" from
/// becoming "the host grows a thread per hung call".
const MAX_ABANDONED_PROVIDER_CALLS: usize = 8;

/// How often the bounded wait re-checks the caller's cancellation.
const ISOLATION_POLL_MILLIS: u64 = 5;

/// The host's bounded-execution boundary for provider calls.
///
/// A provider that never returns cannot be contained by an unwind boundary:
/// containing it needs a thread the host can walk away from. This is that
/// thread. The provider call runs on a borrowed worker, the calling thread
/// waits only for the operation's own live budget, and a provider that does
/// not answer inside it is **abandoned** — the host returns a typed refusal
/// and keeps running while the borrowed worker stays parked in the provider.
/// Borrowed workers are counted and finite: past the ceiling the boundary
/// refuses to start another call at all, and a worker that finally returns
/// releases its own slot, so a provider that hangs once and recovers does not
/// consume the ceiling forever.
///
/// The same boundary contains a provider that **crashes**: the panic unwinds
/// the borrowed worker, is caught there, and reaches the caller as a typed
/// refusal instead of tearing down the host thread that made the call. That
/// matters most for observation delivery, whose caller is the journey's single
/// dedicated delivery thread: without this, one panicking provider call ended
/// that thread and the lane delivered nothing again for the life of the
/// process.
///
/// This lives at the composition root because the provider registry names no
/// OS capability: the registry declares the boundary, the root supplies it.
#[derive(Debug)]
struct ThreadBoundedProviderCallV1 {
    /// Borrowed workers currently inside a provider call, whether or not
    /// anybody is still waiting for them. A live gauge, not a lifetime tally:
    /// the worker releases its own slot when the provider finally returns,
    /// however long that takes.
    owned_workers: Arc<AtomicUsize>,
    /// The subset of [`Self::owned_workers`] whose caller stopped waiting — at
    /// its deadline or on cancellation — and which are therefore running for
    /// nobody. This is the number an operator needs: it is what a runaway
    /// provider costs the host right now.
    abandoned_workers: Arc<AtomicUsize>,
    /// Published after every census mutation. Tests and diagnostics can wait on
    /// the real transition instead of sampling the atomics on a timer.
    census_changed: Arc<CensusTransitionV1>,
    max_abandoned: usize,
}

/// A condition variable tied to borrowed-worker accounting transitions.
#[derive(Debug, Default)]
struct CensusTransitionV1 {
    generation: Mutex<u64>,
    changed: Condvar,
    async_changed: tokio::sync::Notify,
}

impl CensusTransitionV1 {
    fn publish(&self) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *generation = generation.saturating_add(1);
        self.changed.notify_all();
        self.async_changed.notify_waiters();
    }

    #[cfg(test)]
    fn wait_until<T>(
        &self,
        within: Duration,
        mut observe: impl FnMut() -> Option<T>,
    ) -> Result<T, ()> {
        let deadline = Instant::now() + within;
        let mut observed_generation = *self
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(observed) = observe() {
                return Ok(observed);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(());
            };
            let generation = self
                .generation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *generation != observed_generation {
                observed_generation = *generation;
                continue;
            }
            let (generation, timed) = self
                .changed
                .wait_timeout(generation, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            observed_generation = *generation;
            drop(generation);
            if timed.timed_out() {
                return observe().ok_or(());
            }
        }
    }

    async fn wait_until_async<T>(
        &self,
        within: Duration,
        mut observe: impl FnMut() -> Option<T>,
    ) -> Result<T, ()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let mut changed = Box::pin(self.async_changed.notified());
            changed.as_mut().enable();
            if let Some(observed) = observe() {
                return Ok(observed);
            }
            if tokio::time::timeout_at(deadline, &mut changed)
                .await
                .is_err()
            {
                return observe().ok_or(());
            }
        }
    }
}

/// What the host's borrowed provider workers are doing right now.
///
/// Published rather than inferred: a caller's own answer says nothing about
/// whether the worker behind it has left the provider, so the boundary counts
/// both populations and reports them together.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BoundedCallCensusV1 {
    /// Borrowed workers whose caller is still waiting for them.
    pub(crate) live: usize,
    /// Borrowed workers whose caller stopped waiting and which have not left
    /// the provider.
    pub(crate) abandoned: usize,
}

impl BoundedCallCensusV1 {
    /// Every borrowed worker the host currently owns.
    pub(crate) const fn owned(self) -> usize {
        self.live.saturating_add(self.abandoned)
    }
}

/// One borrowed worker is running.
const BORROWED_WORKER_RUNNING: u8 = 0;
/// It left the provider.
const BORROWED_WORKER_RETURNED: u8 = 1;
/// Its caller stopped waiting while it was still inside the provider.
const BORROWED_WORKER_ABANDONED: u8 = 2;

/// The accounting one borrowed worker shares with the caller that borrowed it.
///
/// Both ends move it exactly once, and the transition is a compare-and-swap,
/// so a worker that returns in the same instant its caller gives up is counted
/// as returned by one side and by neither twice.
#[derive(Debug)]
struct BorrowedWorkerAccountingV1 {
    owned: Arc<AtomicUsize>,
    abandoned: Arc<AtomicUsize>,
    census_changed: Arc<CensusTransitionV1>,
    state: AtomicU8,
}

impl BorrowedWorkerAccountingV1 {
    /// The caller stopped waiting. The worker keeps its slot — it is still
    /// inside the provider — but it is now running for nobody.
    ///
    /// The abandoned count is **reserved before** the state moves and rolled
    /// back when the move loses, because the worker reads the state to decide
    /// what to give back. Incrementing after a winning compare-and-swap left a
    /// window in which the worker saw `ABANDONED`, found no abandoned count to
    /// release yet, released only its owned slot — and then this side added an
    /// abandoned worker that no worker was behind. The census hides that
    /// phantom only while nothing is owned, so the next live call published it
    /// as a stranded worker that did not exist.
    fn abandon(&self) {
        self.abandoned.fetch_add(1, Ordering::AcqRel);
        if self
            .state
            .compare_exchange(
                BORROWED_WORKER_RUNNING,
                BORROWED_WORKER_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // The worker had already left, so it released nothing on this
            // reservation's behalf: it is given back here instead.
            release_borrowed_worker_count(&self.abandoned, "abandoned");
        }
        self.census_changed.publish();
    }

    /// The worker left the provider, whatever its caller did in the meantime.
    ///
    /// Idempotent, because two different things can be the one that ends a
    /// call: the worker's own guard, and the boundary itself when no worker
    /// could be started and the unstarted closure was dropped instead. Both
    /// say the same thing, and the slot is given back exactly once.
    fn returned(&self) {
        let previous = self.state.swap(BORROWED_WORKER_RETURNED, Ordering::AcqRel);
        if previous == BORROWED_WORKER_RETURNED {
            return;
        }
        if previous == BORROWED_WORKER_ABANDONED {
            // Reserved by `abandon` before it published this state, so there
            // is always one to release here.
            release_borrowed_worker_count(&self.abandoned, "abandoned");
        }
        release_borrowed_worker_count(&self.owned, "owned");
        self.census_changed.publish();
    }
}

/// Gives one borrowed-worker count back without ever wrapping.
///
/// A decrement that cannot happen is an accounting defect, not something to
/// absorb: wrapping would publish `usize::MAX` stranded workers and jam the
/// boundary's ceiling shut for the life of the process, and swallowing it
/// silently is how the reservation race above stayed invisible. Debug builds
/// fail on it; release builds keep the counter sane and say so.
fn release_borrowed_worker_count(counter: &AtomicUsize, population: &'static str) {
    if counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_sub(1)
        })
        .is_err()
    {
        debug_assert!(
            false,
            "borrowed-worker accounting released a {population} worker that was never counted"
        );
        tracing::error!(
            event = "memory_observation_borrowed_worker_accounting_underflow",
            population,
            "borrowed-worker accounting released a worker that was never counted"
        );
    }
}

/// Releases one borrowed-worker slot when the worker leaves the provider.
struct BorrowedWorkerSlotV1(Arc<BorrowedWorkerAccountingV1>);

impl Drop for BorrowedWorkerSlotV1 {
    fn drop(&mut self) {
        self.0.returned();
    }
}

impl ThreadBoundedProviderCallV1 {
    fn new(max_abandoned: usize) -> Self {
        Self {
            owned_workers: Arc::new(AtomicUsize::new(0)),
            abandoned_workers: Arc::new(AtomicUsize::new(0)),
            census_changed: Arc::new(CensusTransitionV1::default()),
            max_abandoned,
        }
    }

    /// The boundary's own worker census.
    ///
    /// Read in this order on purpose: `owned` first, then the abandoned subset
    /// clamped to it, so a worker that returns between the two loads reports a
    /// smaller census rather than an impossible one.
    fn census(&self) -> BoundedCallCensusV1 {
        let owned = self.owned_workers.load(Ordering::Acquire);
        let abandoned = self.abandoned_workers.load(Ordering::Acquire).min(owned);
        BoundedCallCensusV1 {
            live: owned.saturating_sub(abandoned),
            abandoned,
        }
    }

    /// Waits for a real accounting transition until `admits` accepts the
    /// resulting census. The condition is checked before waiting and again at
    /// the terminal deadline, so neither an early transition nor the final one
    /// can be missed.
    #[cfg(test)]
    fn wait_for_census(
        &self,
        within: Duration,
        admits: impl Fn(BoundedCallCensusV1) -> bool,
    ) -> Result<BoundedCallCensusV1, BoundedCallCensusV1> {
        self.census_changed
            .wait_until(within, || {
                let census = self.census();
                admits(census).then_some(census)
            })
            .map_err(|()| self.census())
    }

    /// Runs `work` on a borrowed worker, waiting at most `budget_millis` for
    /// it and giving up as soon as `cancellation` fires.
    ///
    /// The three outcomes are all typed: the provider's own answer, a refusal
    /// naming why the host stopped waiting, and — for a provider that
    /// panicked — a refusal that names the crash rather than propagating it
    /// into the calling thread.
    fn call_within<T>(
        &self,
        budget_millis: u64,
        cancellation: &CancellationToken,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, BoundedCallRefusalV1>
    where
        T: Send + 'static,
    {
        self.call_within_with_shutdown(budget_millis, cancellation, None, false, work)
    }

    /// Runs the same bounded engine while synchronously forwarding journey
    /// shutdown to the original provider token at its existing checkpoints.
    /// No additional worker, relay task, token or timeout budget is created.
    fn call_within_with_shutdown<T>(
        &self,
        budget_millis: u64,
        cancellation: &CancellationToken,
        stopping: Option<&HostCancellationToken>,
        preserve_settled_result: bool,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, BoundedCallRefusalV1>
    where
        T: Send + 'static,
    {
        let is_cancelled = || {
            if stopping.is_some_and(HostCancellationToken::is_cancelled) {
                cancellation.cancel();
            }
            cancellation.is_cancelled()
        };
        // Consent that is already withdrawn is checked before a slot is
        // claimed and before a worker is borrowed, so a caller that has
        // nothing to wait for never reaches the provider at all. Checking only
        // after the first polling slice meant a cancelled call still occupied
        // the finite ceiling, still handed the provider work the host no
        // longer wanted, and — if the provider was quick — still had its
        // answer accepted.
        if is_cancelled() {
            return Err(BoundedCallRefusalV1::Cancelled);
        }
        let maximum = self.max_abandoned;
        let claimed = self
            .owned_workers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |owned| {
                (owned < maximum).then_some(owned.saturating_add(1))
            });
        let Ok(previously_owned) = claimed else {
            return Err(BoundedCallRefusalV1::Exhausted {
                abandoned: self.census().abandoned,
                maximum,
            });
        };
        debug_assert!(previously_owned < maximum);
        self.census_changed.publish();
        let accounting = Arc::new(BorrowedWorkerAccountingV1 {
            owned: Arc::clone(&self.owned_workers),
            abandoned: Arc::clone(&self.abandoned_workers),
            census_changed: Arc::clone(&self.census_changed),
            state: AtomicU8::new(BORROWED_WORKER_RUNNING),
        });
        let slot = BorrowedWorkerSlotV1(Arc::clone(&accounting));
        let (answers, inbox) = mpsc::sync_channel(1);
        let diagnostics = tracing::dispatcher::get_default(Clone::clone);
        if let Err(source) = thread::Builder::new()
            .name("tdmem-provider-call".to_owned())
            .spawn(move || {
                tracing::dispatcher::with_default(&diagnostics, || {
                    // Diagnose here, even if cancellation already dropped the
                    // receiver. Never retain or log the untrusted panic payload.
                    let answer = catch_unwind(AssertUnwindSafe(work)).map_err(|_| {
                        tracing::warn!(
                            event = "memory_provider_panic_contained",
                            "provider panic was contained by the borrowed worker"
                        );
                    });
                    // Release before answering so a caller with an answer never
                    // reads a census still counting the worker that produced it.
                    drop(slot);
                    // A send failure means the caller already abandoned this call.
                    let _ = answers.send(answer);
                });
            })
        {
            // No worker started. The slot is given back here rather than left
            // to the dropped closure, so a unit of the boundary's own finite
            // ceiling can never be spent on a call that never happened.
            accounting.returned();
            return Err(BoundedCallRefusalV1::Unavailable(source.to_string()));
        }

        let mut remaining = Duration::from_millis(budget_millis);
        let slice = Duration::from_millis(ISOLATION_POLL_MILLIS);
        loop {
            let wait = remaining.min(slice);
            match inbox.recv_timeout(wait) {
                Ok(Ok(answer)) => {
                    return Self::settled_answer(
                        cancellation,
                        stopping,
                        preserve_settled_result,
                        answer,
                    );
                }
                Ok(Err(())) => {
                    // Shutdown owns classification once it has fired, even if
                    // the contained worker reports its panic on the same edge.
                    // The worker already diagnosed the crash independently of
                    // this attempt's terminal outcome.
                    if is_cancelled() {
                        return Err(BoundedCallRefusalV1::Cancelled);
                    }
                    return Err(BoundedCallRefusalV1::Unavailable(
                        "provider panicked mid-call; the borrowed worker was contained".to_owned(),
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(BoundedCallRefusalV1::Unavailable(
                        "bounded provider call ended without answering".to_owned(),
                    ));
                }
                Err(RecvTimeoutError::Timeout) => {
                    remaining = remaining.saturating_sub(wait);
                    if is_cancelled() {
                        // The caller walks away while the worker is still
                        // inside the provider: the boundary says so instead of
                        // quietly forgetting a thread it still owns.
                        accounting.abandon();
                        return Err(BoundedCallRefusalV1::Cancelled);
                    }
                    if remaining.is_zero() {
                        accounting.abandon();
                        return Err(BoundedCallRefusalV1::Abandoned {
                            waited_millis: budget_millis,
                        });
                    }
                }
            }
        }
    }

    /// A received control answer may contain committed effects. Forward stop
    /// into the original token, but never discard that witnessed evidence.
    /// Observation calls retain their existing cancellation-wins policy.
    fn settled_answer<T>(
        cancellation: &CancellationToken,
        stopping: Option<&HostCancellationToken>,
        preserve_settled_result: bool,
        answer: T,
    ) -> Result<T, BoundedCallRefusalV1> {
        if stopping.is_some_and(HostCancellationToken::is_cancelled) {
            cancellation.cancel();
        }
        if !preserve_settled_result && cancellation.is_cancelled() {
            return Err(BoundedCallRefusalV1::Cancelled);
        }
        Ok(answer)
    }
}

impl BoundedProviderCallV1 for ThreadBoundedProviderCallV1 {
    fn handshake_within(
        &self,
        budget_millis: u64,
        cancellation: &CancellationToken,
        work: ProviderHandshakeWorkV1,
    ) -> Result<Result<HandshakeResponse, CompositionLifecycleError>, BoundedCallRefusalV1> {
        self.call_within(budget_millis, cancellation, work)
    }
}

/// Mounts the project's provider lifecycle supervisor over the composed
/// provider set.
///
/// The journey obtains **every** readiness target from
/// it, so restart bounding, exact-scope ownership, predecessor-death
/// confirmation, adapter-panic containment, and fail-closed readiness
/// validation are on the only path a provider observation can take.
fn mount_supervised_provider_readiness(
    composition: Arc<ProjectMemoryProviderComposition>,
    isolation: Arc<ThreadBoundedProviderCallV1>,
    provider: &ObservationProviderMountV1,
) -> Result<SupervisedProviderReadinessV1, ObservationJourneyError> {
    let supervised = SupervisedProviderReadinessV1::new(
        composition,
        isolation,
        provider.provider_id.clone(),
        provider.registration_revision,
        provider.host_limits,
        SupervisedReadinessConfigV1 {
            restart_budget: RestartBudgetV1 {
                max_attempts_per_window: SUPERVISOR_RESTART_ATTEMPTS_PER_WINDOW,
                window_micros: SUPERVISOR_RESTART_WINDOW_MICROS,
                backoff_base_micros: SUPERVISOR_BACKOFF_BASE_MICROS,
                backoff_max_micros: SUPERVISOR_BACKOFF_MAX_MICROS,
            },
            shutdown_budget: ShutdownBudgetV1 {
                grace_micros: SUPERVISOR_GRACE_MICROS,
                kill_micros: SUPERVISOR_KILL_MICROS,
            },
            start_budget_micros: READINESS_DEADLINE_MICROS,
            handshake_budget_micros: READINESS_DEADLINE_MICROS,
            max_supervised_scopes: SUPERVISED_SCOPE_CEILING,
        },
    )
    .map_err(ObservationJourneyError::SupervisedReadiness)?;
    let supervised = match &provider.state_namespace_policy {
        ObservationStateNamespacePolicyV1::Prefix(prefix) => supervised
            .with_admitted_state_namespace_prefix(prefix)
            .map_err(ObservationJourneyError::SupervisedReadiness)?,
        ObservationStateNamespacePolicyV1::AdapterAttestedExactScope => supervised,
    };
    supervised
        .with_state_root(provider.state_root.clone())
        .map_err(ObservationJourneyError::SupervisedReadiness)
}

/// Obtains a readiness target for one exact scope **through the mounted
/// provider lifecycle supervisor**, never straight from the registry.
///
/// The supervisor is what makes this path bounded: it owns exactly this exact
/// scope, refuses a request for any other, enforces a finite restart budget
/// and capped backoff instead of re-handshaking on every record, confirms a
/// predecessor incarnation is dead before it starts a replacement, contains an
/// adapter panic, and validates every readiness invariant before a target
/// exists. A refusal is typed degradation: the record is not admitted or
/// delivered, and the host keeps running.
fn readiness_target_for_scope(
    supervised: &SupervisedProviderReadinessV1,
    provider_id: &OwnedProviderId,
    exact_scope: &OwnedExactScope,
    registration_revision: u64,
    host_limits: ProviderLimits,
    observe_capability: OwnedVersionedId,
    control: OperationControl,
) -> Result<ProviderTargetV1, ObservationJourneyError> {
    readiness_target_and_evidence_for_scope(
        supervised,
        provider_id,
        exact_scope,
        registration_revision,
        host_limits,
        observe_capability,
        control,
    )
    .map(|(target, _)| target)
}

/// The same supervised pass, also returning the readiness evidence it proved.
///
/// One handshake, two answers. Delivery needs both — the address to send to and
/// the provider state identity restart recovery compares against its durable
/// expectation — and taking them from separate handshakes would let the journal
/// deliver to one incarnation while it verified another.
fn readiness_target_and_evidence_for_scope(
    supervised: &SupervisedProviderReadinessV1,
    provider_id: &OwnedProviderId,
    exact_scope: &OwnedExactScope,
    registration_revision: u64,
    host_limits: ProviderLimits,
    observe_capability: OwnedVersionedId,
    control: OperationControl,
) -> Result<(ProviderTargetV1, ReadinessEvidenceV1), ObservationJourneyError> {
    let request = readiness_handshake_request(
        provider_id,
        exact_scope,
        registration_revision,
        host_limits,
        observe_capability,
        control,
    )?;
    let (readiness, evidence) = supervised
        .ready_target_with_evidence(&request, tracedecay_contracts::now_micros().0)
        .map_err(ObservationJourneyError::SupervisedReadiness)?;
    let target = ProviderTargetV1 {
        provider_id: readiness.provider_id().clone(),
        provider_instance_id: readiness.provider_instance_id().to_owned(),
        registration_revision: readiness.registration_revision(),
        ready_receipt_digest: readiness.ready_receipt_sha256().to_owned(),
    };
    target
        .validate()
        .map_err(ObservationJourneyError::Journal)?;
    Ok((target, evidence))
}

/// Builds the readiness handshake request for one exact scope.
fn readiness_handshake_request(
    provider_id: &OwnedProviderId,
    exact_scope: &OwnedExactScope,
    registration_revision: u64,
    host_limits: ProviderLimits,
    observe_capability: OwnedVersionedId,
    control: OperationControl,
) -> Result<HandshakeRequest, ObservationJourneyError> {
    let mut challenge_nonce = [0u8; 32];
    if getrandom::fill(&mut challenge_nonce).is_err() {
        return Err(ObservationJourneyError::EntropyUnavailable);
    }
    HandshakeRequest::new(HandshakeRequestParts {
        provider_id: provider_id.clone(),
        registration_revision,
        exact_scope: exact_scope.clone(),
        request_id: format!("observation-readiness.{}", exact_scope.exact_scope_sha256()),
        required_capabilities: vec![observe_capability],
        host_limits,
        control,
        challenge_nonce,
    })
    .map_err(ObservationJourneyError::Contract)
}

/// Caller-owned bounds one replay pass runs under.
///
/// Both are propagated, never minted here: the composition root passes the
/// project-open cancellation and the startup budget, the live replay task
/// passes the journey's own stop token and its per-pass budget. Replay checks
/// both before every page and before every record; a record already handed to
/// the journal completes its own transaction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplayBoundsV1<'a> {
    /// Cancels the pass between records with a typed terminal.
    pub(crate) cancellation: &'a HostCancellationToken,
    /// Absolute deadline the pass stops at between records.
    pub(crate) deadline: tokio::time::Instant,
}

/// What one record's bounded admission did.
///
/// The deadline case is separate from every other outcome because it is the
/// one where the runtime has *no* report: the blocking admission did not come
/// back inside the caller's budget. Nothing is lost — the record is canonical
/// and the journal owns its own watermark — but the pass has to say so with a
/// typed terminal rather than invent an empty report.
#[derive(Debug)]
pub(crate) enum RecordOutcomeV1 {
    /// Admission returned, with whatever it decided.
    Reported(Box<IngressBatchReportV1>),
    /// Admission did not return inside the caller's budget.
    DeadlineExceeded,
}

/// What one bounded replay pass did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayPassV1 {
    /// Canonical records this pass newly appended to the journal.
    pub(crate) admitted: u64,
    /// The typed journal refusal that stopped the pass, when one did. The
    /// per-stream watermark stays at the refused position: the journal is
    /// delivery-status authority only and cannot decide which of two settled
    /// events at one source position is the truthful one, so it never steps
    /// over the refusal.
    pub(crate) halted: Option<IngressHaltV1>,
    /// The typed backpressure refusal that stopped the pass, when one did.
    /// Like a halt, the watermark stays where it was and the canonical store
    /// still holds the record — this is a lane that stopped taking work, never
    /// a record that was thrown away.
    pub(crate) shed: Option<BackpressureHaltV1>,
}

/// What the live replay edge is standing on, when it is standing on anything.
///
/// A pass that cannot get past its position leaves one of exactly two shapes
/// behind. Both hold the durable watermark where it was, and both are reported
/// once per distinct condition rather than at the backoff rate, so a standing
/// condition is an operator-visible fact instead of an identical warning every
/// five seconds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LiveReplayStallV1 {
    /// The journal refused the record at a named source position. The refusal
    /// is typed and the position is known.
    Halted(IngressHaltV1),
    /// The pass itself failed. There is no source position to name — the
    /// failure happened around the record, not in the journal's answer to it —
    /// so the stall carries the refusal's own classification and text.
    Faulted(LiveReplayFaultV1),
}

/// A live replay pass that failed, classified by whether a later pass can
/// clear it.
///
/// The summary is the refusal's own `Display`, and equality over it is what
/// makes "the same condition, again" distinguishable from a new one:
/// [`ObservationJourneyError`] is neither `Clone` nor `Eq`, and reducing it to
/// its variant name alone would collapse two different permanent refusals into
/// one reported condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveReplayFaultV1 {
    /// Whether a later pass over the same watermark can clear this.
    pub(crate) recoverability: ReplayRecoverabilityV1,
    /// The refusal as it was reported.
    pub(crate) summary: String,
}

/// The retained owner for one project's observation journey.
///
/// It holds the registry handle, the durable journal, the delivery wake edge,
/// and the worker thread. Dropping it without [`Self::shutdown`] still strands
/// nothing: every lease carries its own expiry and any process can reap it.
pub(crate) struct ProjectObservationJourneyV1 {
    journal: Arc<SqliteObservationJournal>,
    wake: Arc<DeliveryWakeV1>,
    /// The one gate every admission on this journey is measured against, and
    /// the owner of this lane's backlog metrics.
    backpressure: Arc<BackpressureGateV1>,
    /// The provider lane this journey's queue pressure is accounted under.
    /// Naming it without a readiness handshake is what lets the journey
    /// republish real backlog on a pass that admitted nothing.
    provider_lane: ObservationLaneKeyV1,
    source_stream: SourceStreamIdV1,
    adapter: Arc<CanonicalObservationAdmissionAdapterV1>,
    delivery: Arc<RegistryObservationDeliveryAdapterV1>,
    /// The bounded-execution boundary readiness and delivery share. Held here
    /// so the lane can publish what a misbehaving provider is currently
    /// costing the host in borrowed workers.
    provider_isolation: Arc<ThreadBoundedProviderCallV1>,
    /// The lane's bounded window onto deliveries that produced no receipt,
    /// with the exact classification the host produced for each one.
    delivery_refusals: Arc<DeliveryRefusalWindowV1>,
    /// Published after each delivery drain mutates or observes the journal, so
    /// acceptance tests can read the resulting durable row without polling.
    delivery_changed: Arc<CensusTransitionV1>,
    provider_id: String,
    provider_instance_id: Arc<ProviderInstanceStateV1>,
    instance_proof: Option<Arc<dyn ObservationInstanceProofV1>>,
    registration_revision: u64,
    lease_owner: String,
    retention_sweep_schedule: RetentionSweepScheduleV1,
    dispatch_policy: DispatchPolicyV1,
    delivery_park: Duration,
    stopping: HostCancellationToken,
    worker: Mutex<Option<JoinHandle<()>>>,
    live_replay_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// What the most recent replay pass stopped on, so a standing condition —
    /// a typed journal refusal or a permanent pass failure — is reported once
    /// rather than at the backoff rate.
    live_stall: Mutex<Option<LiveReplayStallV1>>,
    journal_path: PathBuf,
}

/// Readiness state for a lazily proved provider instance.
///
/// A `OnceLock<Option<String>>` cannot represent a transient refusal: its
/// first `None` is permanent for the lifetime of the journey. This state keeps
/// the proof's retry decision behind one mutex, while the delivery worker
/// remains the only caller that can transition `Pending` to `InFlight`.
#[derive(Debug)]
struct ProviderInstanceStateV1 {
    state: Mutex<ProviderInstanceAvailabilityV1>,
    changed: Condvar,
    readiness_changed: CensusTransitionV1,
}

#[derive(Debug)]
enum ProviderInstanceAvailabilityV1 {
    /// A provider instance has been proved and can receive leased rows.
    Ready(String),
    /// The previous proof was transiently unavailable; retry no earlier than
    /// this instant. `attempts` includes all proof calls in this sequence.
    /// The lifetime starts at the first actual claim, so a dormant mount does
    /// not spend its retry budget before activation.
    Pending {
        retry_at: Instant,
        attempts: u32,
        first_attempt_at: Option<Instant>,
    },
    /// The one delivery worker currently owns the proof call.
    InFlight {
        attempts: u32,
        first_attempt_at: Instant,
    },
    /// No instance is available and no proof can retry (for example, after
    /// journey shutdown or when the mount supplied neither identity nor proof).
    Unavailable,
}

/// Only failures whose retry is safe and useful belong in this allowlist.
/// Cancellation belongs to the lifecycle, and all state, capability, scope,
/// request, authorization, effect, and contract failures are terminal for a
/// mounted journey.
fn instance_proof_terminal_is_retryable(terminal: TerminalCode) -> bool {
    matches!(
        terminal,
        TerminalCode::CapacityExceeded
            | TerminalCode::DeadlineExceeded
            | TerminalCode::ProviderUnavailable
    )
}

impl ProviderInstanceStateV1 {
    /// Creates the state carried by one mounted journey. A supplied proof is
    /// authoritative even if a stale identity was also present in the mount;
    /// a supplied proof always starts in the retryable pending state.
    fn from_mount(instance: Option<String>, proof_present: bool) -> Self {
        let now = Instant::now();
        let state = if proof_present {
            ProviderInstanceAvailabilityV1::Pending {
                retry_at: now,
                attempts: 0,
                first_attempt_at: None,
            }
        } else if let Some(instance) = instance {
            ProviderInstanceAvailabilityV1::Ready(instance)
        } else {
            ProviderInstanceAvailabilityV1::Unavailable
        };
        Self {
            state: Mutex::new(state),
            changed: Condvar::new(),
            readiness_changed: CensusTransitionV1::default(),
        }
    }

    fn notify_changed(&self) {
        self.changed.notify_all();
        self.readiness_changed.publish();
    }

    fn readiness_outcome(&self) -> Option<Result<(), ObservationJourneyError>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*state {
            ProviderInstanceAvailabilityV1::Ready(_) => Some(Ok(())),
            ProviderInstanceAvailabilityV1::Unavailable => {
                Some(Err(ObservationJourneyError::ProviderInstanceUnavailable))
            }
            ProviderInstanceAvailabilityV1::Pending { .. }
            | ProviderInstanceAvailabilityV1::InFlight { .. } => None,
        }
    }

    /// The proved instance, if one is currently available. The clone keeps
    /// the mutex held only for the state snapshot, never across delivery.
    fn get(&self) -> Option<String> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*state {
            ProviderInstanceAvailabilityV1::Ready(instance) => Some(instance.clone()),
            ProviderInstanceAvailabilityV1::Pending { .. }
            | ProviderInstanceAvailabilityV1::InFlight { .. }
            | ProviderInstanceAvailabilityV1::Unavailable => None,
        }
    }

    /// Refreshes an available lease identity from the guarded dispatch proof.
    /// A late proof cannot revive a journey whose lifecycle already stopped.
    fn refresh_from_readiness(&self, instance: &str, cancellation: &CancellationToken) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cancellation.is_cancelled() {
            return;
        }
        if let ProviderInstanceAvailabilityV1::Ready(previous) = &mut *state
            && previous.as_str() != instance
        {
            instance.clone_into(previous);
            self.notify_changed();
        }
    }

    /// Whether dispatch may use the current state.
    fn is_ready(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!(&*state, ProviderInstanceAvailabilityV1::Ready(_))
    }

    /// Whether a transient proof failure is waiting for its next deadline.
    fn is_pending(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!(&*state, ProviderInstanceAvailabilityV1::Pending { .. })
    }

    /// Claims a due proof attempt for the delivery worker.
    fn take_proof_attempt(&self, now: Instant) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*state {
            ProviderInstanceAvailabilityV1::Pending {
                retry_at,
                attempts,
                first_attempt_at,
            } if *retry_at <= now => {
                let lifetime_expired = first_attempt_at.is_some_and(|first_attempt_at| {
                    now.saturating_duration_since(first_attempt_at) >= INSTANCE_PROOF_MAX_LIFETIME
                });
                if *attempts >= INSTANCE_PROOF_MAX_ATTEMPTS || lifetime_expired {
                    *state = ProviderInstanceAvailabilityV1::Unavailable;
                    self.notify_changed();
                    false
                } else {
                    *state = ProviderInstanceAvailabilityV1::InFlight {
                        attempts: attempts.saturating_add(1),
                        first_attempt_at: first_attempt_at.unwrap_or(now),
                    };
                    true
                }
            }
            ProviderInstanceAvailabilityV1::Ready(_)
            | ProviderInstanceAvailabilityV1::Pending { .. }
            | ProviderInstanceAvailabilityV1::InFlight { .. }
            | ProviderInstanceAvailabilityV1::Unavailable => false,
        }
    }

    /// Records a proof result and returns whether another bounded attempt was
    /// scheduled. The cancellation check is repeated while the state mutex is
    /// held immediately before installing the result, so shutdown cannot leave
    /// a late `Ready` state behind a cancelled worker.
    fn finish_proof(
        &self,
        result: Result<Option<String>, TerminalCode>,
        stopping: &HostCancellationToken,
        now: Instant,
    ) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (attempts, first_attempt_at) = match &*state {
            ProviderInstanceAvailabilityV1::InFlight {
                attempts,
                first_attempt_at,
            } => (*attempts, *first_attempt_at),
            // A lifecycle transition (shutdown or a prior terminal result)
            // won the state lock first. Never overwrite it with a late proof.
            ProviderInstanceAvailabilityV1::Ready(_)
            | ProviderInstanceAvailabilityV1::Pending { .. }
            | ProviderInstanceAvailabilityV1::Unavailable => return false,
        };

        if stopping.is_cancelled() {
            *state = ProviderInstanceAvailabilityV1::Unavailable;
            self.notify_changed();
            return false;
        }

        let retryable = match result {
            Ok(Some(instance)) => {
                // Check immediately before the transition too. The state
                // mutex serializes this with `cancel`, so a caller that has
                // already published shutdown cannot be made ready again.
                if stopping.is_cancelled() {
                    *state = ProviderInstanceAvailabilityV1::Unavailable;
                } else {
                    *state = ProviderInstanceAvailabilityV1::Ready(instance);
                    // Cancellation can become visible between the check and
                    // the assignment. Recheck before releasing the mutex so
                    // the lifecycle transition cannot expose a late ready
                    // identity to the replay worker.
                    if stopping.is_cancelled() {
                        *state = ProviderInstanceAvailabilityV1::Unavailable;
                    }
                }
                self.notify_changed();
                return false;
            }
            Ok(None) => true,
            Err(terminal) if instance_proof_terminal_is_retryable(terminal) => true,
            Err(_) => false,
        };

        if stopping.is_cancelled() {
            *state = ProviderInstanceAvailabilityV1::Unavailable;
            self.notify_changed();
            return false;
        }

        if !retryable {
            *state = ProviderInstanceAvailabilityV1::Unavailable;
            self.notify_changed();
            return false;
        }

        if attempts >= INSTANCE_PROOF_MAX_ATTEMPTS
            || now.saturating_duration_since(first_attempt_at) >= INSTANCE_PROOF_MAX_LIFETIME
        {
            *state = ProviderInstanceAvailabilityV1::Unavailable;
            self.notify_changed();
            return false;
        }

        *state = ProviderInstanceAvailabilityV1::Pending {
            retry_at: now.checked_add(INSTANCE_PROOF_RETRY_BACKOFF).unwrap_or(now),
            attempts,
            first_attempt_at: Some(first_attempt_at),
        };
        self.notify_changed();
        true
    }

    /// Cancels proof ownership and wakes a worker waiting for a retry.
    fn cancel(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *state = ProviderInstanceAvailabilityV1::Unavailable;
        self.notify_changed();
    }

    /// Waits for the proof's own retry deadline or lifecycle cancellation.
    /// Delivery wakeups are intentionally not involved: a noisy journal must
    /// not postpone a due proof or turn the retry into a busy loop.
    fn wait_until_retry_or_stop(&self, stopping: &HostCancellationToken) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if stopping.is_cancelled() {
                return false;
            }
            let retry_at = match &*state {
                ProviderInstanceAvailabilityV1::Pending { retry_at, .. } => *retry_at,
                ProviderInstanceAvailabilityV1::Ready(_)
                | ProviderInstanceAvailabilityV1::InFlight { .. }
                | ProviderInstanceAvailabilityV1::Unavailable => return false,
            };
            let remaining = retry_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            let (guard, _) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = guard;
        }
    }

    /// Makes the retry state visible to same-file lifecycle assertions without
    /// exposing the internal mutex or allowing a second proof owner.
    #[cfg(test)]
    fn is_unavailable(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!(&*state, ProviderInstanceAvailabilityV1::Unavailable)
    }
}

impl ProjectObservationJourneyV1 {
    /// Installs the root's existing-authority adapter once. Replacing an
    /// authority while queued records are being delivered is not permitted.
    pub(crate) fn bind_history_authority(
        &self,
        authority: Arc<dyn super::provider_history::HistoryGrantRevalidationV1>,
    ) -> Result<(), ObservationJourneyError> {
        self.delivery.history_authority.set(authority).map_err(|_| {
            super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                "history authority already bound",
            )
            .into()
        })
    }

    /// Checks a selected history binding against this journey's existing
    /// mounted identity without retaining another copy of that identity.
    pub(crate) fn validate_history_mount(
        &self,
        provider_id: &OwnedProviderId,
        registration_revision: u64,
        profile_id: &UserProfileId,
        scope: &ResolvedScope,
    ) -> Result<(), ObservationJourneyError> {
        let context = &self.adapter.context;
        if self.provider_id != provider_id.as_str()
            || self.registration_revision != registration_revision
            || &self.provider_lane.provider_id != provider_id
            || self.provider_lane.registration_revision != registration_revision
            || &context.provider_lane.provider_id != provider_id
            || context.provider_lane.registration_revision != registration_revision
            || &context.profile_id != profile_id
            || &context.scope != scope
        {
            return Err(
                super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                    "history journey mount",
                )
                .into(),
            );
        }
        Ok(())
    }

    /// Provider-specific host deletion intents share this existing journal.
    /// The caller records intent here before attempting provider control.
    pub(crate) fn history_journal(&self) -> Arc<SqliteObservationJournal> {
        Arc::clone(&self.journal)
    }

    /// Waits for actual durable full-effect receipts for every granted source.
    /// Current provider readiness/recovery remains a separate pre-recall check.
    pub(crate) async fn await_history_delivery(
        &self,
        grant: &tracedecay_memory_provider_registry::HistoryGrant,
        bounds: ReplayBoundsV1<'_>,
    ) -> Result<(), ObservationJourneyError> {
        use super::provider_history::ProviderHistoryErrorV1;
        check_replay_bounds(bounds, 0)?;
        if grant.sources.len() > 256 {
            return Err(
                ProviderHistoryErrorV1::ClaimMismatch("history delivery source bound").into(),
            );
        }
        let authority = self.delivery.history_authority.get().cloned().ok_or(
            ProviderHistoryErrorV1::Unavailable("history authority mount"),
        )?;
        let cancellation = HistoryDeliveryCancellationV1(CancellationToken::new());
        let deadline_micros = wall_deadline_micros(bounds.deadline);
        let control = OperationControl::new(
            deadline_micros,
            u64::try_from(
                deadline_micros
                    .saturating_sub(tracedecay_contracts::now_micros().0)
                    .max(0)
                    / 1_000,
            )
            .unwrap_or(u64::MAX),
            cancellation.0.clone(),
        );
        let work = async {
            authority
                .revalidate_async(
                    &self.adapter.context.provider_lane.provider_id,
                    grant,
                    &control,
                )
                .await?;
            if grant.sources.is_empty() {
                return Ok(());
            }
            let stream = SourceStreamKeyV1 {
                source_authority: SourceAuthorityV1::HostSession,
                exact_scope_sha256: grant.destination_scope.exact_scope_sha256(),
                source_stream: history_source_stream(
                    &grant.destination_scope,
                    grant.policy_revision,
                )
                .map_err(ObservationJourneyError::Journal)?,
            };
            let sources = grant
                .sources
                .iter()
                .map(
                    |source| tracedecay_memory_observation::ExpectedSourceDeliveryV1 {
                        source_sequence: SourceSequenceV1(source.attribution.source_sequence),
                        source_event_id: source.attribution.source.observation_id.clone(),
                    },
                )
                .collect::<Vec<_>>();
            loop {
                // Enable before observing: a commit during the snapshot must
                // wake this waiter even if the worker publishes before await.
                let mut changed = Box::pin(self.delivery_changed.async_changed.notified());
                changed.as_mut().enable();
                self.wake_delivery();
                let journal = Arc::clone(&self.journal);
                let lane = self.adapter.context.provider_lane.clone();
                let snapshot_grant = grant.clone();
                let stream = stream.clone();
                let sources = sources.clone();
                let token = cancellation.0.clone();
                let deadline = bounds.deadline;
                let settled = tokio::task::spawn_blocking(move || {
                    let evidence = journal
                        .read_source_deliveries(
                            &lane,
                            &snapshot_grant.destination_scope,
                            &stream,
                            &sources,
                            tracedecay_memory_observation::RecoveryTimeBudgetV1 {
                                remaining_micros: i64::try_from(
                                    deadline
                                        .saturating_duration_since(tokio::time::Instant::now())
                                        .as_micros(),
                                )
                                .unwrap_or(i64::MAX),
                            },
                            &token,
                        )
                        .map_err(ObservationJourneyError::Journal)?;
                    validate_history_delivery_evidence(&snapshot_grant, evidence, &token, deadline)
                })
                .await
                .map_err(ObservationJourneyError::IngestTask)??;
                if settled {
                    authority
                        .revalidate_async(
                            &self.adapter.context.provider_lane.provider_id,
                            grant,
                            &control,
                        )
                        .await?;
                    return Ok(());
                }
                changed.await;
            }
        };
        tokio::select! {
            biased;
            () = bounds.cancellation.cancelled() => Err(ObservationJourneyError::Cancelled { admitted: 0 }),
            () = self.stopping.cancelled() => Err(ObservationJourneyError::Cancelled { admitted: 0 }),
            result = tokio::time::timeout_at(bounds.deadline, work) => {
                match result {
                    Err(_) => Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 }),
                    Ok(Err(ObservationJourneyError::Journal(ObservationJournalError::BudgetExhausted { .. }))) => Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 }),
                    Ok(Err(ObservationJourneyError::Journal(ObservationJournalError::OperationCancelled { .. }))) => Err(ObservationJourneyError::Cancelled { admitted: 0 }),
                    Ok(result) => result,
                }
            }
        }
    }

    /// Delivers one bounded canonical history page through the same hygiene,
    /// journal, idempotency, backpressure and supervised provider path as live
    /// observations. Every effect retains the original source session/key.
    pub(crate) async fn replay_authorized_history_page(
        &self,
        page: super::provider_history::ProviderHistoryPageV1,
        destination: OwnedExactScope,
        policy_revision: u64,
        bounds: ReplayBoundsV1<'_>,
    ) -> Result<ReplayPassV1, ObservationJourneyError> {
        check_replay_bounds(bounds, 0)?;
        if policy_revision == 0
            || page.records.len() > 256
            || page.grant.as_ref().is_some_and(|grant| {
                grant.destination_scope != destination || grant.policy_revision != policy_revision
            })
        {
            return Err(
                super::provider_history::ProviderHistoryErrorV1::ClaimMismatch(
                    "history page destination/bounds",
                )
                .into(),
            );
        }
        let authority = self.delivery.history_authority.get().cloned().ok_or(
            super::provider_history::ProviderHistoryErrorV1::Unavailable("history authority mount"),
        )?;
        if let Some(grant) = &page.grant {
            let deadline = wall_deadline_micros(bounds.deadline);
            let now = tracedecay_contracts::now_micros().0;
            let control = OperationControl::new(
                deadline,
                u64::try_from(deadline.saturating_sub(now).max(0) / 1000).unwrap_or(u64::MAX),
                CancellationToken::new(),
            );
            tokio::select! {
                () = bounds.cancellation.cancelled() => return Err(ObservationJourneyError::Cancelled { admitted: 0 }),
                () = self.stopping.cancelled() => return Err(ObservationJourneyError::Cancelled { admitted: 0 }),
                result = tokio::time::timeout_at(bounds.deadline, authority.revalidate_async(
                    &self.adapter.context.provider_lane.provider_id, grant, &control,
                )) => {
                    result.map_err(|_| ObservationJourneyError::DeadlineExceeded { admitted: 0 })??;
                }
            }
        }
        let adapter = Arc::new(GrantedHistoryAdmissionAdapterV1 {
            canonical: Arc::clone(&self.adapter),
            grant: page.grant,
        });
        let stream = SourceStreamKeyV1 {
            source_authority: SourceAuthorityV1::HostSession,
            exact_scope_sha256: destination.exact_scope_sha256(),
            source_stream: history_source_stream(&destination, policy_revision)
                .map_err(ObservationJourneyError::Journal)?,
        };
        let mut admitted = 0;
        for stored in page.records {
            check_replay_bounds(bounds, admitted)?;
            if self.stopping.is_cancelled() {
                break;
            }
            let record = SourceRecordV1 {
                stream: stream.clone(),
                source_sequence: SourceSequenceV1(stored.sequence()),
                source_event_id: stored.observation().observation_id().as_str().to_owned(),
                source_event_revision: 1,
                record: stored,
            };
            #[cfg(feature = "test-helpers")]
            let (source_sequence, granted) = (
                record.source_sequence.0,
                adapter.grant.as_ref().is_some_and(|grant| {
                    grant.sources.iter().any(|source| {
                        source.attribution.source.observation_id == record.source_event_id
                    })
                }),
            );
            let report = match self
                .ingest_record_with_adapter(record, Arc::clone(&adapter), bounds)
                .await?
            {
                RecordOutcomeV1::Reported(report) => *report,
                RecordOutcomeV1::DeadlineExceeded => {
                    return Err(ObservationJourneyError::DeadlineExceeded { admitted });
                }
            };
            #[cfg(feature = "test-helpers")]
            super::cognitive_recall::emit_host_history_recall_test_diagnostic(|| {
                serde_json::json!({
                    "phase": "history_ingress",
                    "source_sequence": source_sequence,
                    "granted": granted,
                    "appended": report.appended,
                    "duplicates": report.duplicates,
                    "withheld": report.withheld,
                    "non_messages": report.non_messages,
                    "already_processed": report.already_processed,
                })
            });
            admitted += u64::from(report.appended);
            if let Some(stop) = report.stopped_on {
                return Err(match stop.reason {
                    IngressStopReasonV1::Cancelled => {
                        ObservationJourneyError::Cancelled { admitted }
                    }
                    IngressStopReasonV1::DeadlineExceeded => {
                        ObservationJourneyError::DeadlineExceeded { admitted }
                    }
                });
            }
            if report.halted_on.is_some() || report.shed_on.is_some() {
                return Ok(ReplayPassV1 {
                    admitted,
                    halted: report.halted_on,
                    shed: report.shed_on,
                });
            }
        }
        Ok(ReplayPassV1 {
            admitted,
            halted: None,
            shed: None,
        })
    }

    /// Storage placement of the journal. Diagnostics only — never identity.
    pub(crate) fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// How many borrowed workers this lane currently has inside the provider,
    /// split by whether anybody is still waiting for them.
    ///
    /// This is the lane's operational answer to "what is the provider costing
    /// us right now": a delivery failure names it, and so does a shutdown that
    /// stops while calls are still parked in a provider that never returned.
    pub(crate) fn provider_call_census(&self) -> BoundedCallCensusV1 {
        self.provider_isolation.census()
    }

    /// The most recent deliveries this lane refused, newest last, with the
    /// exact typed classification of each.
    ///
    /// The counterpart to [`Self::provider_call_census`]: that says what a
    /// provider is costing the host right now, this says *why* the host is
    /// refusing what the provider does. Bounded by
    /// [`DELIVERY_REFUSAL_HISTORY`].
    #[cfg(test)]
    pub(crate) fn recent_delivery_refusals(&self) -> Vec<DeliveryRefusalV1> {
        self.delivery_refusals.recent()
    }

    /// Every delivery this lane has refused since it was mounted, including
    /// the ones already aged out of [`Self::recent_delivery_refusals`].
    #[cfg(test)]
    pub(crate) fn delivery_refusals_total(&self) -> u64 {
        self.delivery_refusals.total()
    }

    /// Runs bounded canonical replay, admitting or withholding every settled
    /// observation after the journal watermark.
    ///
    /// This is the authoritative path. It is what runs at mount, and a live
    /// wakeup only calls it earlier. `bounds` are checked before every page and
    /// before every record. A journal refusal is returned typed *in* the pass
    /// rather than as an error: the pass did what it could, the watermark
    /// holds at the refused position, and the caller decides how to treat it.
    pub(crate) async fn replay_canonical_observations<S>(
        &self,
        store: &S,
        max_pages: usize,
        bounds: ReplayBoundsV1<'_>,
    ) -> Result<ReplayPassV1, ObservationJourneyError>
    where
        S: ObservationStore + ?Sized,
    {
        let mut admitted = 0_u64;
        for _ in 0..max_pages {
            // Journey shutdown is not a caller terminal: every record is
            // journaled in its own transaction, so stopping between pages
            // loses nothing and the next pass resumes from the watermark.
            if self.stopping.is_cancelled() {
                break;
            }
            check_replay_bounds(bounds, admitted)?;
            let after_sequence = self.replay_watermark().await?;
            let request = ObservationReplayRequest::new(after_sequence, REPLAY_PAGE_ITEMS)
                .map_err(ObservationJourneyError::Replay)?;
            let page =
                match tokio::time::timeout_at(bounds.deadline, store.replay_observations(request))
                    .await
                {
                    Ok(page) => page.map_err(ObservationJourneyError::Replay)?,
                    Err(_elapsed) => {
                        return Err(ObservationJourneyError::DeadlineExceeded { admitted });
                    }
                };
            if page.is_empty() {
                break;
            }

            for stored in page {
                if self.stopping.is_cancelled() {
                    return Ok(ReplayPassV1 {
                        admitted,
                        halted: None,
                        shed: None,
                    });
                }
                check_replay_bounds(bounds, admitted)?;
                let record = self.source_record(stored)?;
                let report = match self.ingest_record(record, bounds).await? {
                    RecordOutcomeV1::Reported(report) => *report,
                    RecordOutcomeV1::DeadlineExceeded => {
                        // The record did not return inside the caller's own
                        // budget. Nothing was committed for it that the
                        // watermark does not already describe, so the pass
                        // reports its typed terminal and the next one resumes
                        // from the journal.
                        return Err(ObservationJourneyError::DeadlineExceeded { admitted });
                    }
                };
                admitted = admitted.saturating_add(u64::from(report.appended));
                if let Some(stop) = report.stopped_on {
                    // The caller's own bound reached inside the record. The
                    // watermark holds at the named position and the canonical
                    // store still owns it. Journey shutdown is not a caller
                    // terminal — every record is journaled in its own
                    // transaction, so stopping loses nothing.
                    if self.stopping.is_cancelled() {
                        return Ok(ReplayPassV1 {
                            admitted,
                            halted: None,
                            shed: None,
                        });
                    }
                    return Err(match stop.reason {
                        IngressStopReasonV1::Cancelled => {
                            ObservationJourneyError::Cancelled { admitted }
                        }
                        IngressStopReasonV1::DeadlineExceeded => {
                            ObservationJourneyError::DeadlineExceeded { admitted }
                        }
                    });
                }
                if let Some(shed) = report.shed_on {
                    // The lane refused the record, so the pass stops here.
                    // Continuing would re-pay sanitization, digest derivation,
                    // and a readiness proof per record for a lane that is
                    // already refusing, which is exactly the foreground cost
                    // the gate exists to avoid. The watermark holds and the
                    // canonical store still owns the record.
                    self.report_backpressure(&shed);
                    return Ok(ReplayPassV1 {
                        admitted,
                        halted: None,
                        shed: Some(shed),
                    });
                }
                if let Some(halt) = report.halted_on {
                    return Ok(ReplayPassV1 {
                        admitted,
                        halted: Some(halt),
                        shed: None,
                    });
                }
            }
        }
        Ok(ReplayPassV1 {
            admitted,
            halted: None,
            shed: None,
        })
    }

    /// Reads the journey-wide replay watermark on the blocking pool: the
    /// journal connection sits behind a mutex the delivery worker also holds
    /// across fsync'd writes, so even a read may wait on disk.
    async fn replay_watermark(&self) -> Result<u64, ObservationJourneyError> {
        let journal = Arc::clone(&self.journal);
        let source_stream = self.source_stream.clone();
        let sequence = tokio::task::spawn_blocking(move || {
            journal.maximum_replay_sequence(SourceAuthorityV1::HostSession, &source_stream)
        })
        .await
        .map_err(ObservationJourneyError::IngestTask)?
        .map_err(ObservationJourneyError::Journal)?;
        Ok(sequence.map_or(0, |sequence| sequence.0))
    }

    /// Binds one settled canonical record to its exact per-session stream.
    fn source_record(
        &self,
        stored: StoredObservation,
    ) -> Result<SourceRecordV1<StoredObservation>, ObservationJourneyError> {
        let exact_scope = exact_scope_for_session(
            &self.adapter.context.profile_id,
            &self.adapter.context.scope,
            stored.observation().source().session_id().as_str(),
        )?;
        let stream = SourceStreamKeyV1 {
            source_authority: SourceAuthorityV1::HostSession,
            exact_scope_sha256: exact_scope.exact_scope_sha256(),
            source_stream: self.source_stream.clone(),
        };
        stream
            .validate()
            .map_err(ObservationJourneyError::Journal)?;
        Ok(SourceRecordV1 {
            stream,
            source_sequence: SourceSequenceV1(stored.sequence()),
            source_event_id: stored.observation().observation_id().as_str().to_owned(),
            source_event_revision: 1,
            record: stored,
        })
    }

    /// Recovers the record's stream position and ingests it on the blocking
    /// pool. Recovery and ingest are synchronous SQLite work under a
    /// `synchronous = FULL` journal behind a mutex, and admission walks the
    /// whole envelope through hygiene; none of it may park a runtime worker
    /// that serves the project, whether the caller is project open or the
    /// live replay task.
    async fn ingest_record(
        &self,
        record: SourceRecordV1<StoredObservation>,
        bounds: ReplayBoundsV1<'_>,
    ) -> Result<RecordOutcomeV1, ObservationJourneyError> {
        self.ingest_record_with_adapter(record, Arc::clone(&self.adapter), bounds)
            .await
    }

    async fn ingest_record_with_adapter<A>(
        &self,
        record: SourceRecordV1<StoredObservation>,
        adapter: Arc<A>,
        bounds: ReplayBoundsV1<'_>,
    ) -> Result<RecordOutcomeV1, ObservationJourneyError>
    where
        A: ObservationAdmissionAdapterV1<
                Record = StoredObservation,
                Error = AdmissionAdapterError,
                Control = ReplayIngestControlV1,
            > + Send
            + Sync
            + 'static,
    {
        let journal = Arc::clone(&self.journal);
        let wake = Arc::clone(&self.wake);
        let backpressure = Arc::clone(&self.backpressure);
        // The caller's bound, carried into the record rather than checked
        // around it. The deadline is what is left of the pass; the tokens are
        // the caller's own, read synchronously at every checkpoint.
        let control = Arc::new(ReplayIngestControlV1 {
            deadline_unix_micros: wall_deadline_micros(bounds.deadline),
            caller: bounds.cancellation.clone(),
            stopping: self.stopping.clone(),
            cancellation: CancellationToken::new(),
        });
        // Ingress reads the caller's tokens directly at every checkpoint, so
        // the stop before the append is synchronous and cannot race. This
        // relay covers the other half: a sub-operation that is *already
        // running* under an `OperationControl` — a readiness handshake with a
        // five-second budget — sees the same give-up while it is in flight
        // rather than only at the next record.
        let relay = {
            let caller = bounds.cancellation.clone();
            let stopping = self.stopping.clone();
            let record_cancellation = control.cancellation.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = caller.cancelled() => {}
                    () = stopping.cancelled() => {}
                }
                record_cancellation.cancel();
            })
        };
        // The admission path is what a coding agent's committed message waits
        // behind, so it is measured rather than assumed: the gate takes the
        // sample and sheds optional traffic while the journal itself is what
        // is slow. `Instant` is monotonic, so a clock step cannot fabricate a
        // budget breach.
        let started = std::time::Instant::now();
        let ingest_control = Arc::clone(&control);
        let task = tokio::task::spawn_blocking(move || {
            let ingress = IngressRuntimeV1::new(
                journal.as_ref(),
                adapter.as_ref(),
                wake.as_ref(),
                backpressure.as_ref(),
                ingest_control.as_ref(),
            );
            let resume = ingress.recover(&record.stream)?;
            ingress.ingest(&resume, std::slice::from_ref(&record))
        });
        // The caller is bounded even when the record is not: the blocking pool
        // is shared, and a pass that has spent its budget has to return rather
        // than wait for a turn on it.
        let joined = tokio::time::timeout_at(bounds.deadline + FOREGROUND_ABORT_GRACE, task).await;
        relay.abort();
        // Sampled on every path, including the ones that failed. A latency
        // sample taken only after a successful report leaves the lane blind to
        // exactly the admissions that hurt most — the slow ones that then
        // failed — and the breach run is what sheds optional traffic before
        // the next record pays the same cost.
        let elapsed = i64::try_from(started.elapsed().as_micros()).unwrap_or(i64::MAX);
        let foreground = self.backpressure.observe_foreground(elapsed);
        if !foreground.within_budget() {
            tracing::warn!(
                event = "memory_observation_foreground_budget_exceeded",
                elapsed_micros = elapsed,
                budget_micros = self.backpressure.policy().foreground_budget_micros,
                consecutive_breaches = self.backpressure.foreground_breaches(),
                journal = %self.journal_path.display(),
                "one canonical observation admission overran its foreground budget; a run of \
                 them sheds optional observation traffic before the next record is admitted, \
                 until an admission comes back inside it"
            );
        }
        match joined {
            Ok(joined) => match joined.map_err(ObservationJourneyError::IngestTask)? {
                Ok(report) => Ok(RecordOutcomeV1::Reported(Box::new(report))),
                Err(error) => {
                    // This terminal belongs to host admission control, before
                    // the record could commit. Provider refusals retain their
                    // own failure classification; neither path advances the
                    // durable watermark past the unadmitted record.
                    let terminal = match &error {
                        ObservationRuntimeError::Admission { cause, .. } => {
                            match cause.cause().downcast_ref::<AdmissionAdapterError>() {
                                Some(AdmissionAdapterError::Readiness { source, .. }) => {
                                    match source.as_ref() {
                                        ObservationJourneyError::SupervisedReadiness(
                                            SupervisedReadinessError::RequestTerminal {
                                                terminal_code,
                                                ..
                                            },
                                        ) => Some(*terminal_code),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    match terminal {
                        Some(TerminalCode::DeadlineExceeded) => {
                            Ok(RecordOutcomeV1::DeadlineExceeded)
                        }
                        Some(TerminalCode::Cancelled) => {
                            Err(ObservationJourneyError::Cancelled { admitted: 0 })
                        }
                        _ => Err(ObservationJourneyError::Ingress(error)),
                    }
                }
            },
            Err(_elapsed) => {
                // Tell the abandoned work to stop at its next checkpoint. It
                // holds nothing the next pass cannot recover: every decision
                // it could still commit carries its own watermark.
                control.cancellation.cancel();
                Ok(RecordOutcomeV1::DeadlineExceeded)
            }
        }
    }

    /// Reports one backpressure refusal with the measurements it was taken on.
    ///
    /// This is the lane's operational signal: queue size, queue bytes, the age
    /// of the oldest row still waiting, and which of them refused the record.
    fn report_backpressure(&self, shed: &BackpressureHaltV1) {
        let backlog = &shed.refusal.backlog;
        tracing::warn!(
            event = "memory_observation_backpressure_shed",
            source_sequence = shed.source_sequence.0,
            source_event_id = %shed.source_event_id,
            load_class = shed.refusal.load_class.as_wire(),
            reason = shed.refusal.reason.as_wire(),
            state = shed.refusal.state.as_wire(),
            queue_items = backlog.queue_items,
            queue_bytes = backlog.queue_bytes,
            max_queue_items = backlog.max_queue_items,
            max_queue_bytes = backlog.max_queue_bytes,
            utilization_ppm = backlog.utilization_ppm,
            projected_utilization_ppm = shed.refusal.projected_utilization_ppm,
            additional_bytes = shed.refusal.additional_bytes,
            oldest_backlog_age_micros = backlog.oldest_backlog_age_micros,
            foreground_latency_micros = backlog.foreground_latency_micros,
            journal = %self.journal_path.display(),
            "the observation lane refused a canonical record; the watermark holds and the record \
             is re-presented once the lane drains"
        );
    }

    /// The most recent backlog measurement this lane took, for telemetry and
    /// operational inspection. `None` until the first gated admission.
    pub(crate) fn backlog_metrics(&self) -> Option<QueueBacklogV1> {
        self.backpressure.metrics()
    }

    /// Re-reads the lane and republishes its backlog on the current instant.
    ///
    /// This is the only thing that keeps the published metric current. Ingress
    /// measures around the records it admits; delivery drains rows without
    /// ever passing through ingress; and a pass that admitted nothing measures
    /// nothing at all. So the lane is read again — from the journal, not from
    /// anything remembered — after every pass and at shutdown, which is what
    /// makes an idle lane's reported size, age, and state describe the journal
    /// as it is rather than as it was at the last admission.
    async fn refresh_backlog(&self) -> Result<QueueBacklogV1, ObservationJourneyError> {
        let journal = Arc::clone(&self.journal);
        let backpressure = Arc::clone(&self.backpressure);
        let lane = self.provider_lane.clone();
        let now_unix_micros = tracedecay_contracts::now_micros().0;
        tokio::task::spawn_blocking(move || {
            journal
                .lane_pressure(&lane)
                .map(|pressure| backpressure.observe(&pressure, now_unix_micros))
        })
        .await
        .map_err(ObservationJourneyError::IngestTask)?
        .map_err(ObservationJourneyError::Journal)
    }

    /// Refreshes the lane and publishes it whenever it is not nominal.
    ///
    /// Called on every replay pass, so a lane that is filling up is visible
    /// *before* it starts refusing work — a metric that only appeared on a
    /// refusal would tell an operator about the problem exactly one step too
    /// late. A nominal lane emits nothing, so this is not a log-rate loop.
    async fn report_backlog(&self) {
        let backlog = match self.refresh_backlog().await {
            Ok(backlog) => backlog,
            Err(error) => {
                tracing::debug!(
                    event = "memory_observation_backlog_refresh_failed",
                    error = %error,
                    "the observation lane's backlog could not be re-read"
                );
                return;
            }
        };
        if backlog.state == BackpressureStateV1::Nominal {
            return;
        }
        tracing::info!(
            event = "memory_observation_backlog_pressure",
            state = backlog.state.as_wire(),
            trigger = backlog.trigger.map(BackpressureReasonV1::as_wire),
            queue_items = backlog.queue_items,
            queue_bytes = backlog.queue_bytes,
            max_queue_items = backlog.max_queue_items,
            max_queue_bytes = backlog.max_queue_bytes,
            utilization_ppm = backlog.utilization_ppm,
            oldest_backlog_age_micros = backlog.oldest_backlog_age_micros,
            foreground_latency_micros = backlog.foreground_latency_micros,
            foreground_breaches = backlog.foreground_breaches,
            journal = %self.journal_path.display(),
            "the observation lane is under backpressure"
        );
    }

    /// Records the typed refusal a replay pass stopped on.
    ///
    /// Logged at error level only when it is a new halt, so a permanent
    /// refusal is reported once and then retried at the backoff rate without
    /// repeating itself at log rate.
    fn record_halt(&self, halt: IngressHaltV1) {
        let source_sequence = halt.source_sequence.0;
        let source_event_id = halt.source_event_id.clone();
        let outcome = format!("{:?}", halt.outcome);
        if !self.remember_stall(LiveReplayStallV1::Halted(halt)) {
            tracing::trace!(
                event = "memory_observation_replay_still_halted",
                source_sequence,
                "canonical replay is still halted at the same refused position"
            );
            return;
        }
        tracing::error!(
            event = "memory_observation_replay_halted",
            source_sequence,
            source_event_id = %source_event_id,
            outcome = %outcome,
            journal = %self.journal_path.display(),
            "canonical replay halted on a typed journal refusal; the watermark holds at the \
             refused position and replay backs off"
        );
    }

    /// Records a replay pass that failed rather than one the journal refused at
    /// a named position, classified by whether a later pass can clear it.
    ///
    /// This is the branch a bare `warn!` used to own. A refusal that describes
    /// the *evidence* — a canonical record the contract cannot read, a journal
    /// or ingress refusal, a panicked ingest task — is answered identically by
    /// every later pass, so the stream stands still at the same watermark.
    /// Without a recorded stall that condition was invisible to
    /// [`Self::stalled_on`] and to shutdown, and its only trace was the same
    /// warning every backoff interval. It is now reported once, typed, with
    /// the classification that says whether waiting can help.
    fn record_fault(
        &self,
        recoverability: ReplayRecoverabilityV1,
        error: &ObservationJourneyError,
    ) {
        let fault = LiveReplayFaultV1 {
            recoverability,
            summary: error.to_string(),
        };
        if !self.remember_stall(LiveReplayStallV1::Faulted(fault)) {
            tracing::trace!(
                event = "memory_observation_live_replay_still_failing",
                recoverability = recoverability.as_wire(),
                error = %error,
                "bounded canonical observation replay failed the same way again"
            );
            return;
        }
        match recoverability {
            ReplayRecoverabilityV1::Permanent => tracing::error!(
                event = "memory_observation_live_replay_failed",
                recoverability = "permanent",
                error = %error,
                journal = %self.journal_path.display(),
                "bounded canonical observation replay failed permanently; no later pass can \
                 clear it, so the watermark stands still here and the commit behind it stays \
                 undelivered until the underlying evidence or code is repaired"
            ),
            ReplayRecoverabilityV1::Retryable => tracing::warn!(
                event = "memory_observation_live_replay_failed",
                recoverability = "retryable",
                error = %error,
                journal = %self.journal_path.display(),
                "bounded canonical observation replay failed on a retryable condition; the \
                 durable watermark holds and the next pass resumes from it"
            ),
        }
    }

    /// Stores one stall, answering whether it is new.
    ///
    /// The whole point of the slot is that a standing condition is reported
    /// once: an unchanged stall is answered `false`, so the caller logs at
    /// trace instead of repeating itself at the backoff rate.
    fn remember_stall(&self, stall: LiveReplayStallV1) -> bool {
        let mut slot = match self.live_stall.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot.as_ref() == Some(&stall) {
            return false;
        }
        *slot = Some(stall);
        true
    }

    /// Clears a recorded stall once a pass got past whatever it stood on.
    fn clear_stall(&self) {
        let mut slot = match self.live_stall.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot.take().is_some() {
            tracing::info!(
                event = "memory_observation_replay_halt_cleared",
                journal = %self.journal_path.display(),
                "canonical replay advanced past a previously refused position"
            );
        }
    }

    /// What the most recent replay pass stopped on, if anything.
    pub(crate) fn stalled_on(&self) -> Option<LiveReplayStallV1> {
        match self.live_stall.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The typed journal refusal the most recent replay pass stopped on, when
    /// that is what it stopped on.
    #[cfg(test)]
    pub(crate) fn halted_on(&self) -> Option<IngressHaltV1> {
        match self.stalled_on() {
            Some(LiveReplayStallV1::Halted(halt)) => Some(halt),
            Some(LiveReplayStallV1::Faulted(_)) | None => None,
        }
    }

    /// Signals the delivery worker that new work landed.
    pub(crate) fn wake_delivery(&self) {
        self.wake.signal();
    }

    /// Publication needs a proved instance, not settlement of unrelated
    /// historical sessions. The delivery worker remains the sole proof owner;
    /// this waiter observes its existing state and never calls the provider.
    pub(crate) async fn await_instance_ready(
        &self,
        cancellation: &HostCancellationToken,
        within: Duration,
    ) -> Result<(), ObservationJourneyError> {
        if cancellation.is_cancelled() || self.stopping.is_cancelled() {
            return Err(ObservationJourneyError::Cancelled { admitted: 0 });
        }
        let wait = self
            .provider_instance_id
            .readiness_changed
            .wait_until_async(within, || self.provider_instance_id.readiness_outcome());
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                Err(ObservationJourneyError::Cancelled { admitted: 0 })
            }
            () = self.stopping.cancelled() => {
                Err(ObservationJourneyError::Cancelled { admitted: 0 })
            }
            outcome = wait => outcome
                .map_err(|()| ObservationJourneyError::ProviderInstanceDeadlineExceeded)
                .and_then(|outcome| outcome),
        };
        if cancellation.is_cancelled() || self.stopping.is_cancelled() {
            return Err(ObservationJourneyError::Cancelled { admitted: 0 });
        }
        outcome
    }

    /// Waits until this journey has proved its provider instance and every
    /// journaled delivery for this provider has settled successfully. Explicit
    /// mounts that require settlement retain this stronger publication fence.
    pub(crate) async fn await_delivery_settled(
        &self,
        cancellation: &HostCancellationToken,
        within: Duration,
    ) -> Result<(), ObservationJourneyError> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if cancellation.is_cancelled() || self.stopping.is_cancelled() {
                return Err(ObservationJourneyError::Cancelled { admitted: 0 });
            }

            let journal = Arc::clone(&self.journal);
            let provider_id = self.provider_id.clone();
            let unsettled = tokio::task::spawn_blocking(move || {
                journal
                    .inspect(&tracedecay_memory_observation::JournalInspectionFilterV1 {
                        provider_id: Some(provider_id),
                        states: vec![
                            DeliveryStateV1::Pending,
                            DeliveryStateV1::Leased,
                            DeliveryStateV1::EffectUnknown,
                        ],
                        limit: 1,
                        ..Default::default()
                    })
                    .map(|page| page.total_rows)
            })
            .await
            .map_err(ObservationJourneyError::IngestTask)?
            .map_err(ObservationJourneyError::Journal)?;
            if self.provider_instance_id.is_ready() && unsettled == 0 {
                let journal = Arc::clone(&self.journal);
                let provider_id = self.provider_id.clone();
                let failed = tokio::task::spawn_blocking(move || {
                    journal
                        .inspect(&tracedecay_memory_observation::JournalInspectionFilterV1 {
                            provider_id: Some(provider_id),
                            states: vec![
                                DeliveryStateV1::Rejected,
                                DeliveryStateV1::Cancelled,
                                DeliveryStateV1::Expired,
                                DeliveryStateV1::Exhausted,
                            ],
                            limit: 1,
                            ..Default::default()
                        })
                        .map(|page| page.rows.into_iter().next().map(|row| row.state))
                })
                .await
                .map_err(ObservationJourneyError::IngestTask)?
                .map_err(ObservationJourneyError::Journal)?;
                if let Some(state) = failed {
                    return Err(ObservationJourneyError::RequiredDeliveryFailed { state });
                }
                if cancellation.is_cancelled() || self.stopping.is_cancelled() {
                    return Err(ObservationJourneyError::Cancelled { admitted: 0 });
                }
                return Ok(());
            }

            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 });
            };

            // Register interest before the next snapshot and wake the worker
            // explicitly. This covers both the no-row readiness case and a
            // row that startup replay appended just before this check.
            let mut changed = Box::pin(self.delivery_changed.async_changed.notified());
            changed.as_mut().enable();
            self.wake_delivery();
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    return Err(ObservationJourneyError::Cancelled { admitted: 0 });
                }
                () = self.stopping.cancelled() => {
                    return Err(ObservationJourneyError::Cancelled { admitted: 0 });
                }
                () = &mut changed => {}
                () = tokio::time::sleep(remaining.min(Duration::from_millis(25))) => {}
            }
        }
    }

    /// Starts the bounded live replay edge over the canonical registered store.
    ///
    /// The store is the same durable authority used by every session producer.
    /// Polling its journal watermark instead of decorating individual producers
    /// means commits made by daemon sync, historical refresh, hooks, or MCP
    /// replay all converge through one path. At most one task may be installed.
    pub(crate) fn start_live_replay<S>(
        self: &Arc<Self>,
        store: S,
    ) -> Result<(), ObservationJourneyError>
    where
        S: ObservationStore + 'static,
    {
        let mut slot = self.live_replay_task.lock().map_err(|_| {
            ObservationJourneyError::Worker(std::io::Error::other("live replay task lock poisoned"))
        })?;
        if self.stopping.is_cancelled() {
            return Err(ObservationJourneyError::Cancelled { admitted: 0 });
        }
        if slot.is_some() {
            return Err(ObservationJourneyError::Worker(std::io::Error::other(
                "live replay task already started",
            )));
        }
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(LIVE_REPLAY_PARK).await;
                let Some(journey) = weak.upgrade() else {
                    break;
                };
                if journey.stopping.is_cancelled() {
                    break;
                }
                if !journey.provider_instance_id.is_ready() {
                    // A pending proof has not proved an instance.
                    // A transiently unavailable bootstrap is retried by the
                    // delivery worker; until it succeeds, do not advance its
                    // canonical cursor.
                    journey.report_backlog().await;
                    continue;
                }
                let bounds = ReplayBoundsV1 {
                    cancellation: &journey.stopping,
                    deadline: tokio::time::Instant::now() + LIVE_REPLAY_PASS_BUDGET,
                };
                match journey
                    .replay_canonical_observations(&store, REPLAY_LIVE_PAGES, bounds)
                    .await
                {
                    Ok(pass) => {
                        if pass.admitted > 0 {
                            journey.wake_delivery();
                        }
                        journey.report_backlog().await;
                        if pass.shed.is_some() {
                            // The lane refused work. A drain is the only thing
                            // that can clear it, and ingress already woke the
                            // worker, so back off rather than re-presenting the
                            // same record at park rate against the same full
                            // lane. Nothing is lost: the watermark holds and
                            // the refusal was already reported typed.
                            tokio::time::sleep(LIVE_REPLAY_ERROR_BACKOFF).await;
                            continue;
                        }
                        match pass.halted {
                            Some(halt) => {
                                // The watermark stays at the refused position,
                                // so retrying at the park interval would only
                                // repeat the same refusal at log rate. Record
                                // it typed, once per distinct halt, and back
                                // off; a queue that drains clears on a later
                                // pass, a permanent conflict stays visible.
                                journey.record_halt(halt);
                                tokio::time::sleep(LIVE_REPLAY_ERROR_BACKOFF).await;
                            }
                            None => journey.clear_stall(),
                        }
                    }
                    Err(ObservationJourneyError::Cancelled { .. }) => break,
                    Err(ObservationJourneyError::DeadlineExceeded { admitted }) => {
                        if admitted > 0 {
                            journey.wake_delivery();
                        }
                        tracing::debug!(
                            event = "memory_observation_live_replay_pass_budget",
                            admitted,
                            "live replay pass stopped at its budget; the next pass resumes from \
                             the watermark"
                        );
                    }
                    Err(error) => {
                        // Not every refusal is transient. A storage-layer
                        // failure clears on its own, but a canonical record the
                        // contract cannot read, a journal or ingress refusal,
                        // or a panicked ingest task is answered identically by
                        // every later pass: the watermark stands still and the
                        // commit behind it is never delivered. Both are
                        // recorded typed, once per distinct condition, so the
                        // standing one reaches `stalled_on` and shutdown
                        // instead of being the same warning every backoff.
                        journey.record_fault(replay_recoverability(&error), &error);
                        tokio::time::sleep(LIVE_REPLAY_ERROR_BACKOFF).await;
                    }
                }
            }
        });
        *slot = Some(task);
        Ok(())
    }

    /// Stops the worker and reports truthfully whether anything is still held.
    ///
    /// The deadline is the daemon's own shared shutdown deadline. A worker that
    /// does not stop inside it, and a lease still outstanding after the bounded
    /// reap, are both returned as typed failures for the daemon's shutdown
    /// status rather than reported as a clean stop. Every stage still runs:
    /// one failure never skips the teardown after it.
    pub(crate) async fn shutdown(
        &self,
        deadline: tokio::time::Instant,
    ) -> Vec<ObservationShutdownFailureV1> {
        let mut failures = Vec::new();
        self.stopping.cancel();
        self.provider_instance_id.cancel();
        self.wake.request_shutdown();
        match self.stalled_on() {
            // Not a shutdown failure: a standing replay condition the next
            // life meets again at the same durable watermark.
            Some(LiveReplayStallV1::Halted(halt)) => tracing::warn!(
                event = "memory_observation_shutdown_with_halted_replay",
                source_sequence = halt.source_sequence.0,
                source_event_id = %halt.source_event_id,
                outcome = ?halt.outcome,
                journal = %self.journal_path.display(),
                "canonical replay is still halted at a refused position at shutdown"
            ),
            Some(LiveReplayStallV1::Faulted(fault)) => tracing::warn!(
                event = "memory_observation_shutdown_with_failing_replay",
                recoverability = fault.recoverability.as_wire(),
                error = %fault.summary,
                journal = %self.journal_path.display(),
                "canonical replay was still failing at shutdown; the durable watermark holds \
                 where it was"
            ),
            None => {}
        }
        // Read the lane one last time rather than replaying whatever the last
        // admission happened to see: delivery may have drained rows since, and
        // a final admission may have crossed a threshold the remembered
        // measurement was taken one row before. If the shared deadline prevents
        // a fresh reading, explicitly label the cached handover instead.
        let (backlog, backlog_cached) = match tokio::time::timeout_at(
            deadline,
            self.refresh_backlog(),
        )
        .await
        {
            Ok(Ok(backlog)) => (Some(backlog), false),
            Ok(Err(error)) => {
                tracing::warn!(
                    event = "memory_observation_backlog_refresh_failed_at_shutdown",
                    error = %error,
                    journal = %self.journal_path.display(),
                    "the observation lane could not be re-read at shutdown; using cached backlog"
                );
                (self.backlog_metrics(), true)
            }
            Err(_) => {
                // Dropping the wait does not abort SQLite work already running
                // on the blocking pool. Continue teardown under the same deadline.
                failures.push(ObservationShutdownFailureV1::BacklogRefreshDeadline);
                tracing::warn!(
                    event = "memory_observation_backlog_refresh_deadline_at_shutdown",
                    journal = %self.journal_path.display(),
                    "the observation backlog refresh exceeded the shutdown deadline; using cached backlog"
                );
                (self.backlog_metrics(), true)
            }
        };
        if let Some(backlog) = backlog {
            // What the lane was still holding when it stopped. The rows are
            // durable and the next life resumes on them, so this is the
            // operational handover, not a loss report.
            tracing::info!(
                event = "memory_observation_backlog_at_shutdown",
                backlog_cached,
                state = backlog.state.as_wire(),
                queue_items = backlog.queue_items,
                queue_bytes = backlog.queue_bytes,
                max_queue_items = backlog.max_queue_items,
                max_queue_bytes = backlog.max_queue_bytes,
                utilization_ppm = backlog.utilization_ppm,
                oldest_backlog_age_micros = backlog.oldest_backlog_age_micros,
                foreground_latency_micros = backlog.foreground_latency_micros,
                journal = %self.journal_path.display(),
                "observation lane backlog at shutdown"
            );
        }
        let live_replay_task = match self.live_replay_task.lock() {
            Ok(mut task) => task.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(task) = live_replay_task {
            task.abort();
            match tokio::time::timeout_at(deadline, task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if error.is_cancelled() => {}
                Ok(Err(error)) => {
                    failures.push(ObservationShutdownFailureV1::LiveReplayJoin(error));
                }
                Err(_) => failures.push(ObservationShutdownFailureV1::LiveReplayDeadline),
            }
        }
        let worker = match self.worker.lock() {
            Ok(mut worker) => worker.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(worker) = worker {
            let join = tokio::task::spawn_blocking(move || worker.join());
            match tokio::time::timeout_at(deadline, join).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(_))) => failures.push(ObservationShutdownFailureV1::WorkerPanicked),
                Ok(Err(error)) => failures.push(ObservationShutdownFailureV1::WorkerJoin(error)),
                Err(_) => failures.push(ObservationShutdownFailureV1::WorkerDeadline),
            }
        }
        // Borrowed workers are not joined at shutdown by design — a provider
        // that never returns must not be able to hold the daemon's stop — so
        // the lane says what it is walking away from instead of stopping
        // silently over it.
        let census = self.provider_call_census();
        if census.owned() > 0 {
            tracing::warn!(
                event = "memory_observation_provider_calls_at_shutdown",
                borrowed_workers_live = census.live,
                borrowed_workers_abandoned = census.abandoned,
                journal = %self.journal_path.display(),
                "observation lane stopped while provider calls were still inside the provider;                  those workers are released when the provider returns"
            );
        }
        // What the lane refused while it ran, in the shape that says whether
        // the provider needs fixing: the count, and the class of the last one.
        // Without the class this is a number nobody can act on.
        let refused = self.delivery_refusals.total();
        if refused > 0 {
            let recent = self.delivery_refusals.recent();
            let last = recent.last();
            tracing::info!(
                event = "memory_observation_delivery_refusals_at_shutdown",
                deliveries_refused = refused,
                last_refusal_class = last.map(|refusal| refusal.class.as_wire()),
                last_refusal_observation = last.map(|refusal| refusal.observation_id.as_str()),
                last_refusal_detail = last.map(|refusal| refusal.detail.as_str()),
                journal = %self.journal_path.display(),
                "observation lane refused deliveries while it ran"
            );
        }
        // The shutdown pass reaps lapsed leases and reads the lane back, both
        // synchronous SQLite against the file the worker thread was writing
        // until a moment ago. Run inline it parked a runtime worker for as
        // long as the busy timeout allowed — during the daemon's stop, when
        // every other project's teardown wants that worker — and it carried no
        // deadline at all. On the blocking pool, under the daemon's own
        // deadline, both are answered: the wait is off the runtime, and
        // outliving the deadline is a typed failure rather than a hang.
        let journal = Arc::clone(&self.journal);
        let delivery = Arc::clone(&self.delivery);
        let wake = Arc::clone(&self.wake);
        let request = ShutdownRequestV1 {
            provider_id: self.provider_id.clone(),
            now_unix_micros: tracedecay_contracts::now_micros().0,
            reap_budget: self.dispatch_policy.reap_budget,
        };
        let pass = tokio::task::spawn_blocking(move || {
            DeliveryRuntimeV1::new(journal.as_ref(), delivery.as_ref(), wake.as_ref())
                .shutdown(&request)
        });
        match tokio::time::timeout_at(deadline, pass).await {
            Ok(Ok(Ok(report))) if report.quiesced => {}
            Ok(Ok(Ok(report))) => failures.push(ObservationShutdownFailureV1::LeasesOutstanding {
                leases_reaped: report.leases_reaped,
                leases_outstanding: report.leases_outstanding,
            }),
            Ok(Ok(Err(error))) => {
                failures.push(ObservationShutdownFailureV1::ShutdownPass(error));
            }
            Ok(Err(error)) => failures.push(ObservationShutdownFailureV1::ShutdownPassJoin(error)),
            Err(_) => failures.push(ObservationShutdownFailureV1::ShutdownPassDeadline),
        }
        failures
    }

    /// Starts an already-owned delivery worker once, ordered against shutdown.
    fn start_delivery_worker(&self) -> Result<(), ObservationJourneyError> {
        let mut slot = self.worker.lock().map_err(|_| {
            ObservationJourneyError::Worker(std::io::Error::other("delivery worker lock poisoned"))
        })?;
        if self.stopping.is_cancelled() {
            return Err(ObservationJourneyError::Cancelled { admitted: 0 });
        }
        if slot.is_some() {
            return Err(ObservationJourneyError::Worker(std::io::Error::other(
                "delivery worker already started",
            )));
        }
        *slot = Some(
            self.spawn_worker()
                .map_err(ObservationJourneyError::Worker)?,
        );
        Ok(())
    }

    /// Starts the owned delivery and bounded live replay workers without
    /// waiting for historical convergence.
    pub(crate) fn start_observer_with_live_replay<S>(
        self: &Arc<Self>,
        observation_store: S,
    ) -> Result<(), ObservationJourneyError>
    where
        S: ObservationStore + 'static,
    {
        self.start_delivery_worker()?;
        if let Err(error) = self.start_live_replay(observation_store) {
            self.stopping.cancel();
            self.provider_instance_id.cancel();
            self.wake.request_shutdown();
            return Err(error);
        }
        Ok(())
    }

    fn spawn_worker(&self) -> Result<JoinHandle<()>, std::io::Error> {
        let journal = Arc::clone(&self.journal);
        let delivery = Arc::clone(&self.delivery);
        let isolation = Arc::clone(&self.provider_isolation);
        let refusals = Arc::clone(&self.delivery_refusals);
        let delivery_changed = Arc::clone(&self.delivery_changed);
        let wake = Arc::clone(&self.wake);
        let stopping = self.stopping.clone();
        let provider_id = self.provider_id.clone();
        let provider_instance_id = Arc::clone(&self.provider_instance_id);
        let instance_proof = self.instance_proof.clone();
        let registration_revision = self.registration_revision;
        let lease_owner = self.lease_owner.clone();
        let retention_sweep_schedule = self.retention_sweep_schedule;
        let dispatch_policy = self.dispatch_policy;
        let delivery_park = self.delivery_park;
        // A dedicated OS thread rather than a tokio task: both the journal and
        // `deliver_observation` are synchronous and hold a mutex across the
        // whole call, so parking them on a runtime worker would block it.
        thread::Builder::new()
            .name("td-memory-observation".to_owned())
            .spawn(move || {
                let runtime =
                    DeliveryRuntimeV1::new(journal.as_ref(), delivery.as_ref(), wake.as_ref());
                // Due at once: a journal a restart found full of aged rows is
                // swept on the first turn, not after the first interval.
                let mut sweeper = RetentionSweeperV1::new(
                    journal.as_ref(),
                    retention_sweep_schedule,
                    tracedecay_contracts::now_micros().0,
                );
                // Open validated one page; whatever is left is walked here.
                let mut withheld_audit_complete = false;
                while !stopping.is_cancelled() {
                    // The proof is owned by this worker, just like delivery.
                    // A retry waits on the proof deadline itself. It must not
                    // be hidden behind a noisy delivery wake or an arbitrary
                    // delivery park interval.
                    if let Some(proof) = instance_proof.as_ref() {
                        if !provider_instance_id.take_proof_attempt(Instant::now()) {
                            if provider_instance_id.is_pending() {
                                if !provider_instance_id.wait_until_retry_or_stop(&stopping)
                                    && stopping.is_cancelled()
                                {
                                    break;
                                }
                                continue;
                            }
                        } else {
                            let cancelled = stopping.clone();
                            let result = proof.prove(
                                Instant::now()
                                    + Duration::from_micros(READINESS_DEADLINE_MICROS as u64),
                                Arc::new(move || cancelled.is_cancelled()),
                            );
                            let terminal = result.as_ref().err().copied();
                            let retryable = match &result {
                                Ok(None) => true,
                                Ok(Some(_)) => false,
                                Err(terminal) => {
                                    instance_proof_terminal_is_retryable(*terminal)
                                }
                            };
                            let retry_scheduled = provider_instance_id.finish_proof(
                                result,
                                &stopping,
                                Instant::now(),
                            );
                            if !stopping.is_cancelled() {
                                if let Some(terminal) = terminal {
                                    if retryable && retry_scheduled {
                                        tracing::warn!(
                                            ?terminal,
                                            provider = %provider_id,
                                            "observer instance proof unavailable; retrying"
                                        );
                                    } else if retryable {
                                        tracing::warn!(
                                            ?terminal,
                                            provider = %provider_id,
                                            "observer instance proof retry budget exhausted"
                                        );
                                    } else {
                                        tracing::warn!(
                                            ?terminal,
                                            provider = %provider_id,
                                            "observer instance proof is permanently unavailable; retry disabled"
                                        );
                                    }
                                } else if retryable && retry_scheduled {
                                    tracing::warn!(
                                        provider = %provider_id,
                                        "observer instance proof returned no instance; retrying"
                                    );
                                } else if retryable {
                                    tracing::warn!(
                                        provider = %provider_id,
                                        "observer instance proof returned no instance; retry budget exhausted"
                                    );
                                }
                            }
                            if stopping.is_cancelled() {
                                break;
                            }
                            if retry_scheduled {
                                continue;
                            }
                        }
                    }
                    if runtime.wait_for_work(delivery_park) == WakeOutcomeV1::ShutdownRequested {
                        break;
                    }
                    // Only a proved instance or the admitted static instance
                    // can authorize per-attempt lease identity.
                    if let Some(leased_instance_id) = provider_instance_id.get() {
                        let now = tracedecay_contracts::now_micros().0;
                        let request = DispatchRequestV1 {
                            lease: LeaseRequestV1 {
                                provider_id: provider_id.clone(),
                                registration_revision,
                                provider_instance_id: leased_instance_id,
                                exact_scope_sha256: None,
                                lease_owner: lease_owner.clone(),
                                now_unix_micros: now,
                                lease_duration_micros: dispatch_policy.lease_duration_micros,
                                max_items: dispatch_policy.batch_max_items,
                                max_bytes: dispatch_policy.batch_max_bytes,
                            },
                            // An adapter failure produced no provider answer, so
                            // the row comes back on the journal's own capped
                            // exponential for the attempt the claim consumed — the
                            // same curve a recorded `provider_unavailable` rides,
                            // rather than a flat interval that would hammer an
                            // unreachable provider until its ceiling is gone. The
                            // journal's attempt ceiling still bounds it; nothing
                            // here retries a typed terminal.
                            retry_backoff: RetryBackoffV1::of(journal.policy()),
                            attempt_budget_micros: dispatch_policy.attempt_budget_micros,
                        };
                        // A drain, not a single batch: the wake edge is one
                        // collapsed signal, so a backlog that is already journalled
                        // would otherwise move `batch_max_items` per park interval
                        // with nothing to signal about it again. The bounds are
                        // derived from the dispatch policy revalidated against the
                        // journal's own retention policy, which is the only way to
                        // obtain them — this loop cannot widen them.
                        match dispatch_policy
                            .drain_bounds(journal.policy(), now)
                            .map_err(ObservationRuntimeError::from)
                            .and_then(|bounds| {
                                runtime.drain(
                                    &request,
                                    &bounds,
                                    || tracedecay_contracts::now_micros().0,
                                    || {
                                        provider_instance_id.get().as_deref()
                                            == Some(request.lease.provider_instance_id.as_str())
                                    },
                                )
                            }) {
                            Ok(report) => {
                                if report.totals.cancelled_before_dispatch > 0
                                    || report.totals.cancelled_in_flight > 0
                                {
                                    tracing::info!(
                                        event = "memory_observation_dispatch_cancelled",
                                        rounds = report.rounds,
                                        leased = report.totals.leased,
                                        cancelled_in_flight = report.totals.cancelled_in_flight,
                                        cancelled_before_dispatch =
                                            report.totals.cancelled_before_dispatch,
                                        "shutdown stopped an observation dispatch round; released rows stay pending"
                                    );
                                }
                                for failure in &report.totals.failures {
                                    // The worker census travels with the failure:
                                    // a delivery that produced no receipt because
                                    // the provider never answered is only half
                                    // reported without saying how many borrowed
                                    // workers that provider is still holding.
                                    let census = isolation.census();
                                    // And so does the *classification*: whether
                                    // the provider could not be reached, crashed,
                                    // was abandoned at the host's bound, or
                                    // answered something the host refused are four
                                    // different faults with four different
                                    // repairs, and the log line is where an
                                    // operator meets them.
                                    let class =
                                        DeliveryRefusalClassV1::classify(failure.cause.cause());
                                    tracing::warn!(
                                        event = "memory_observation_delivery_failed",
                                        observation_id = %failure.observation_id.as_str(),
                                        attempt = failure.attempt_number,
                                        lease_released = failure.lease_released,
                                        refusal_class = class.as_wire(),
                                        error = %failure.cause,
                                        borrowed_workers_live = census.live,
                                        borrowed_workers_abandoned = census.abandoned,
                                        "one observation delivery produced no receipt"
                                    );
                                    refusals.record(DeliveryRefusalV1 {
                                        observation_id: failure
                                            .observation_id
                                            .as_str()
                                            .to_owned(),
                                        attempt_number: failure.attempt_number,
                                        at_unix_micros: tracedecay_contracts::now_micros().0,
                                        class,
                                        detail: failure.cause.to_string(),
                                    });
                                }
                                // Work the bounds cut short is real, durable, and
                                // eligible now. Re-arming the wake makes the next
                                // turn start at once instead of parking on a
                                // backlog nothing will signal about again; a
                                // shutdown stop is not re-armed, because the next
                                // wait must return `ShutdownRequested`.
                                if report.more_work_pending()
                                    && report.stop != DrainStopV1::ShutdownRequested
                                {
                                    tracing::debug!(
                                        event = "memory_observation_dispatch_yielded",
                                        rounds = report.rounds,
                                        leased = report.totals.leased,
                                        stop = ?report.stop,
                                        "observation dispatch reached its drain bound with work still queued"
                                    );
                                    wake.signal();
                                }
                            }
                            Err(error) => {
                                // A journal-level failure is neither swallowed nor
                                // retried in a tight loop: the worker parks and the
                                // next wake tries again.
                                tracing::warn!(
                                    event = "memory_observation_dispatch_failed",
                                    error = %error,
                                    "one observation dispatch round failed"
                                );
                            }
                        }
                        // `drain` owns the attempt/state/refusal transitions the
                        // mounted acceptance suite observes. Publish only after the
                        // whole report, including its refusal classifications, is
                        // visible so a waiter reads one coherent result.
                        delivery_changed.publish();
                    }
                    if let Err(error) = runtime.reap(
                        tracedecay_contracts::now_micros().0,
                        dispatch_policy.reap_budget,
                    ) {
                        tracing::warn!(
                            event = "memory_observation_reap_failed",
                            error = %error,
                            "lapsed observation leases could not be reaped"
                        );
                    }
                    // Retention is driven by the same loop that delivers, so
                    // an expired row is terminalized with a receipt and then
                    // purged by a mounted path — never left to a sweep nobody
                    // calls. The sweeper owns the cadence; a failure here is
                    // logged and waits out its backoff rather than looping.
                    match sweeper.tick(tracedecay_contracts::now_micros().0) {
                        Ok(RetentionTickV1::NotDue { .. }) => {}
                        Ok(RetentionTickV1::Swept {
                            receipt,
                            next_due_unix_micros,
                        }) => {
                            if receipt.remaining_candidates > 0
                                || receipt.payloads_purged > 0
                                || receipt.deliveries_expired > 0
                                || receipt.deliveries_forgotten > 0
                                || receipt.journal_rows_deleted > 0
                                || receipt.withheld_rows_deleted > 0
                            {
                                tracing::info!(
                                    event = "memory_observation_retention_swept",
                                    payloads_purged = receipt.payloads_purged,
                                    deliveries_expired = receipt.deliveries_expired,
                                    deliveries_forgotten = receipt.deliveries_forgotten,
                                    journal_rows_deleted = receipt.journal_rows_deleted,
                                    receipts_deleted = receipt.receipts_deleted,
                                    withheld_rows_deleted = receipt.withheld_rows_deleted,
                                    wal_truncated = receipt.wal_truncated,
                                    remaining_candidates = receipt.remaining_candidates,
                                    next_due_unix_micros,
                                    "observation journal retention sweep ran"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                event = "memory_observation_retention_sweep_failed",
                                error = %error,
                                next_due_unix_micros = sweeper.next_due_unix_micros(),
                                "observation journal retention sweep failed"
                            );
                        }
                    }
                    // The other half of the bounded open. Opening the journal
                    // revalidates one page of the withheld audit so project
                    // open costs the same whatever that table has grown to;
                    // this loop finishes the walk, one bounded page per turn,
                    // and then stops asking. A page that meets a corrupt
                    // receipt does not advance its cursor, so the defect is
                    // reported on every turn until it is dealt with rather
                    // than being stepped over once.
                    if !withheld_audit_complete {
                        match journal.validate_withheld_backlog(WITHHELD_AUDIT_PAGE_ROWS) {
                            Ok(progress) => {
                                withheld_audit_complete = progress.complete;
                                if progress.complete {
                                    tracing::debug!(
                                        event = "memory_observation_withheld_audit_complete",
                                        rows_validated = progress.rows_validated,
                                        "the withheld receipt audit finished its resumable walk"
                                    );
                                }
                            }
                            Err(error) => {
                                tracing::error!(
                                    event = "memory_observation_withheld_audit_failed",
                                    error = %error,
                                    "a withheld receipt no longer matches the evidence stored \
                                     beside it; the audit holds at that row"
                                );
                            }
                        }
                    }
                }
            })
    }
}

impl Drop for ProjectObservationJourneyV1 {
    fn drop(&mut self) {
        self.stopping.cancel();
        self.provider_instance_id.cancel();
        self.wake.request_shutdown();
        let live_replay_task = match self.live_replay_task.get_mut() {
            Ok(task) => task.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(task) = live_replay_task {
            task.abort();
        }
        let worker = match self.worker.get_mut() {
            Ok(worker) => worker.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(worker) = worker
            && worker.join().is_err()
        {
            tracing::warn!(
                event = "memory_observation_worker_panicked",
                "the observation delivery worker panicked during owner drop"
            );
        }
    }
}

/// Inputs the composition root supplies to mount one project's journey.
pub(crate) struct ObservationJourneyMountInputsV1 {
    /// Enabled provider composition. A disabled composition is refused.
    pub(crate) composition: Arc<ProjectMemoryProviderComposition>,
    /// Authoritative profile identity.
    pub(crate) profile_id: UserProfileId,
    /// Authoritative resolved scope, used verbatim.
    pub(crate) scope: ResolvedScope,
    /// The authoritative project identity the composition root resolved
    /// independently of the scope. Checked against the scope rather than
    /// trusted, so one mount can never straddle two projects.
    pub(crate) authoritative_project_id: ProjectId,
    /// Canonical store-owned data root. Storage placement only.
    pub(crate) store_data_root: PathBuf,
    /// Registered provider identity, state authority, and handshake limits.
    pub(crate) provider: ObservationProviderMountV1,
    /// Every bound the journey runs under. Validated at mount; a policy that
    /// cannot bound the worker refuses the mount.
    pub(crate) policy: ObservationJourneyPolicyV1,
}

/// Mounts one project's observation journey.
///
/// Order is enforced by the argument list: the caller cannot reach this
/// function without an authoritative resolved scope and an enabled composition.
/// Readiness is proved separately for each canonical record's own source-session
/// scope before admission and again immediately before delivery.
#[cfg(test)]
pub(crate) fn mount_project_observation_journey(
    inputs: ObservationJourneyMountInputsV1,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError> {
    let journey = construct_project_observation_journey(inputs)?;
    journey.start_delivery_worker()?;
    Ok(journey)
}

/// Constructs retained state without starting provider proof or replay workers.
fn construct_project_observation_journey(
    inputs: ObservationJourneyMountInputsV1,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError> {
    inputs
        .composition
        .registry()
        .ok_or(ObservationJourneyError::CompositionDisabled)?;
    if inputs.scope.project_id != inputs.authoritative_project_id {
        return Err(ObservationJourneyError::ScopeDisagreement {
            field: "project_id",
            expected: inputs.authoritative_project_id.as_str().to_owned(),
            received: inputs.scope.project_id.as_str().to_owned(),
        });
    }
    inputs.policy.validate()?;
    let observe_capability = OwnedVersionedId::new("observation.accept.v1")
        .map_err(ObservationJourneyError::Contract)?;
    let source_stream =
        SourceStreamIdV1::new(SESSION_SOURCE_STREAM).map_err(ObservationJourneyError::Journal)?;
    let lease_owner = format!(
        "tracedecay.daemon.observation.{}",
        inputs.scope.scope_digest.as_str()
    );

    let retention_sweep_schedule = RetentionSweepScheduleV1::bounded(
        inputs.policy.retention_sweep_interval_micros,
        inputs.policy.retention_sweep_error_backoff_micros,
    )
    .map_err(ObservationJourneyError::Journal)?;

    let journal_path = inputs
        .store_data_root
        .join(inputs.provider.journal_file_name);
    // Shared before the adapters are built: the delivery adapter's recovery
    // gate reads the same durable journal the worker delivers from, so the
    // acknowledged watermark it compares against is the one this dispatcher
    // actually advances.
    let journal = Arc::new(
        SqliteObservationJournal::open(&journal_path, inputs.policy.retention).map_err(
            |source| ObservationJourneyError::JournalOpen {
                path: journal_path.clone(),
                source,
            },
        )?,
    );
    let sanitizer = ObservationSanitizer::new().map_err(ObservationJourneyError::Hygiene)?;

    // One supervised lifecycle owner for this project's journey, shared by
    // admission and delivery so both observe the same incarnation, the same
    // restart budget, and the same typed degradation.
    // One bounded-execution boundary for this journey, shared by readiness and
    // delivery: they park the same kind of borrowed thread in the same
    // provider, so they answer to one ceiling.
    let provider_isolation = Arc::new(ThreadBoundedProviderCallV1::new(
        MAX_ABANDONED_PROVIDER_CALLS,
    ));
    let supervised_readiness = Arc::new(mount_supervised_provider_readiness(
        Arc::clone(&inputs.composition),
        Arc::clone(&provider_isolation),
        &inputs.provider,
    )?);

    // The lane this journey queues in, named from the registration alone so
    // pressure can be measured without a readiness handshake.
    let provider_lane = ObservationLaneKeyV1 {
        provider_id: inputs.provider.provider_id.clone(),
        registration_revision: inputs.provider.registration_revision,
    };
    provider_lane
        .validate()
        .map_err(ObservationJourneyError::Journal)?;

    let adapter = Arc::new(CanonicalObservationAdmissionAdapterV1 {
        context: AdmissionContextV1 {
            profile_id: inputs.profile_id,
            scope: inputs.scope,
            readiness: Arc::clone(&supervised_readiness),
            provider_lane: provider_lane.clone(),
            registration_revision: inputs.provider.registration_revision,
            limits: inputs.provider.host_limits,
            observe_capability: observe_capability.clone(),
            sanitizer,
            observation_kind: OwnedVersionedId::new(SESSION_MESSAGE_OBSERVATION_KIND)
                .map_err(ObservationJourneyError::Contract)?,
            provider_payload_contract: OwnedVersionedId::new(OBSERVATION_CONTRACT_ID)
                .map_err(ObservationJourneyError::Contract)?,
        },
    });
    let provider_instance_id = Arc::new(ProviderInstanceStateV1::from_mount(
        inputs.provider.provider_instance_id.clone(),
        inputs.provider.instance_proof.is_some(),
    ));
    let delivery = Arc::new(RegistryObservationDeliveryAdapterV1 {
        history_authority: Arc::new(OnceLock::new()),
        provider_id: inputs.provider.provider_id.clone(),
        composition: Arc::clone(&inputs.composition),
        readiness: supervised_readiness,
        provider_instance: Arc::clone(&provider_instance_id),
        isolation: Arc::clone(&provider_isolation),
        registration_revision: inputs.provider.registration_revision,
        limits: inputs.provider.host_limits,
        observe_capability,
        recovery: ObservationRecoveryGateV1 {
            journal: Arc::clone(&journal),
            provider_id: inputs.provider.provider_id.as_str().to_owned(),
            registration_revision: inputs.provider.registration_revision,
            source_authority: SourceAuthorityV1::HostSession,
            source_stream: source_stream.clone(),
            budget: RecoveryBudgetV1 {
                max_automatic_attempts: RECOVERY_MAX_AUTOMATIC_ATTEMPTS,
            },
        },
    });

    // Validated at mount, exactly like the retention and dispatch policies:
    // an ingress whose bounds were never checked would be an ingress with no
    // bounds at all until the first saturation.
    let backpressure = Arc::new(
        BackpressureGateV1::new(inputs.policy.backpressure)
            .map_err(ObservationJourneyError::Journal)?,
    );
    let journey = Arc::new(ProjectObservationJourneyV1 {
        journal,
        wake: Arc::new(DeliveryWakeV1::new()),
        backpressure,
        provider_lane,
        source_stream,
        adapter,
        provider_isolation,
        delivery_refusals: Arc::new(DeliveryRefusalWindowV1::default()),
        delivery_changed: Arc::new(CensusTransitionV1::default()),
        provider_id: inputs.provider.provider_id.as_str().to_owned(),
        provider_instance_id,
        instance_proof: inputs.provider.instance_proof,
        registration_revision: inputs.provider.registration_revision,
        lease_owner,
        retention_sweep_schedule,
        dispatch_policy: inputs.policy.dispatch,
        delivery_park: inputs.policy.delivery_park,
        delivery,
        stopping: HostCancellationToken::new(),
        worker: Mutex::new(None),
        live_replay_task: Mutex::new(None),
        live_stall: Mutex::new(None),
        journal_path,
    });
    Ok(journey)
}

/// Refuses to start another record once the caller's bounds are spent.
fn check_replay_bounds(
    bounds: ReplayBoundsV1<'_>,
    admitted: u64,
) -> Result<(), ObservationJourneyError> {
    if bounds.cancellation.is_cancelled() {
        return Err(ObservationJourneyError::Cancelled { admitted });
    }
    if tokio::time::Instant::now() >= bounds.deadline {
        return Err(ObservationJourneyError::DeadlineExceeded { admitted });
    }
    Ok(())
}

/// The bounded startup replay the composition root runs once the journey is
/// mounted and the canonical observation store is reachable.
///
/// This is the authoritative convergence pass; the bounded live replay task
/// only makes later convergence faster. It runs inline in project open under
/// the project-open `cancellation` and its own wall-clock budget: the page
/// bound caps the work, the budget keeps a slow store from holding the open
/// hostage (past it the pass stops between records and the live replay task
/// continues from the watermark), and cancellation is the caller's terminal,
/// returned typed so the open reports it as the drain it is.
pub(crate) async fn run_startup_replay<S>(
    journey: &ProjectObservationJourneyV1,
    store: &S,
    cancellation: &HostCancellationToken,
) -> Result<ReplayPassV1, ObservationJourneyError>
where
    S: ObservationStore + ?Sized,
{
    let bounds = ReplayBoundsV1 {
        cancellation,
        deadline: tokio::time::Instant::now() + STARTUP_REPLAY_BUDGET,
    };
    let pass = match journey
        .replay_canonical_observations(store, REPLAY_STARTUP_PAGES, bounds)
        .await
    {
        Ok(pass) => pass,
        Err(ObservationJourneyError::DeadlineExceeded { admitted }) => {
            tracing::warn!(
                event = "memory_observation_startup_replay_budget_exhausted",
                budget_millis = STARTUP_REPLAY_BUDGET.as_millis() as u64,
                admitted,
                journal = %journey.journal_path().display(),
                "startup canonical replay stopped at its time budget; live replay continues"
            );
            ReplayPassV1 {
                admitted,
                halted: None,
                shed: None,
            }
        }
        Err(error) => return Err(error),
    };
    if pass.admitted > 0 {
        journey.wake_delivery();
    }
    if let Some(halt) = pass.halted.clone() {
        journey.record_halt(halt);
    }
    Ok(pass)
}

/// Whether a startup replay refusal is one a later pass can clear.
///
/// The rule is fail-closed: a refusal counts as retryable only when the store
/// itself named a transport-level failure, the blocking ingest task was
/// cancelled rather than lost, or canonical admission retained a refused
/// handshake with `StaleIdentity`. That handshake can refresh a persisted
/// namespace's descriptor before a later pass admits the same record.
/// Canonical contract defects, identity or cursor disagreements, other journal
/// or ingress refusals, panicked ingest tasks, and scope or hygiene failures
/// remain permanent: replaying the same evidence cannot repair those defects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayRecoverabilityV1 {
    /// A later pass over the same watermark can succeed.
    Retryable,
    /// No retry can clear this. The commit stays undelivered until the
    /// underlying evidence or code is repaired.
    Permanent,
}

impl ReplayRecoverabilityV1 {
    /// Canonical wire value, for logs and for typed reporting.
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Permanent => "permanent",
        }
    }
}

/// Classifies one replay refusal — on the startup pass and on the live edge
/// alike. "Can a later pass clear this?" has one answer, and both callers have
/// to act on it: startup refuses the mount, live records a standing stall.
pub(crate) fn replay_recoverability(error: &ObservationJourneyError) -> ReplayRecoverabilityV1 {
    match error {
        // The canonical store reported a storage-layer failure: a busy
        // database, a transient I/O error, a lock it could not take. The rows
        // are intact and the next pass reads them.
        ObservationJourneyError::Replay(ObservationStoreError::Storage { .. }) => {
            ReplayRecoverabilityV1::Retryable
        }
        // A persisted provider namespace can refresh its descriptor during
        // the first handshake. The unchanged canonical record is admissible
        // on a later supervised pass; retain every other admission refusal.
        ObservationJourneyError::Ingress(ObservationRuntimeError::Admission { cause, .. })
            if matches!(
                cause.cause().downcast_ref::<AdmissionAdapterError>(),
                Some(AdmissionAdapterError::Readiness { source, .. }) if matches!(
                    source.as_ref(),
                    ObservationJourneyError::SupervisedReadiness(
                        SupervisedReadinessError::Unavailable {
                            terminal_code: Some(TerminalCode::StaleIdentity),
                            ..
                        }
                    )
                )
            ) =>
        {
            ReplayRecoverabilityV1::Retryable
        }
        // The blocking-pool task was cancelled, not lost: its transaction
        // either committed or did not, and the watermark re-presents the
        // record either way. A panicked task is a different thing entirely and
        // falls through to permanent.
        ObservationJourneyError::IngestTask(join) if join.is_cancelled() => {
            ReplayRecoverabilityV1::Retryable
        }
        _ => ReplayRecoverabilityV1::Permanent,
    }
}

/// Runs the retained mount, startup replay, and delivery activation for journey
/// fixtures under the same cancellation used by project open. Production uses
/// these operations directly around its publication boundary.
///
/// Cancellation during startup replay is returned typed as
/// [`ObservationJourneyError::Cancelled`]; the journey is dropped with the
/// refused open and nothing past the durable watermark is lost.
///
/// Every other startup replay refusal is **classified** rather than swallowed,
/// because "live replay will retry it" is only true of a failure a retry can
/// clear. A retryable refusal — a canonical store that was busy, a blocking
/// ingest task the runtime cancelled, or canonical admission whose handshake
/// returned `StaleIdentity` while refreshing a namespace descriptor — leaves
/// the watermark where it was and the bounded live replay task converges on
/// it. The mount succeeds and logs the refusal with its retry path. A permanent one —
/// an unreadable or contract-violating canonical record, another journal or
/// admission evidence refusal, a panicked ingest task — cannot be cleared by
/// replaying the same bytes again, and a mount that reported success would leave a
/// committed observation undelivered for as long as the project stayed open
/// while every readiness surface said the journey was healthy. That is
/// returned typed as [`ObservationJourneyError::StartupReplayPermanent`], so
/// project open fails with the reason instead of starting degraded in silence.
///
/// Mount and live-replay-start failures are returned typed.
#[cfg(test)]
pub(crate) async fn mount_and_replay<S>(
    inputs: ObservationJourneyMountInputsV1,
    observation_store: S,
    cancellation: &HostCancellationToken,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError>
where
    S: ObservationStore + 'static,
{
    let journey = mount_observer_dormant(inputs, cancellation).await?;
    activate_required_with_startup_replay(journey, observation_store, cancellation).await
}

/// Starts the existing required journey after its source authority is bound,
/// preserving startup replay classification and the project-open cancellation.
pub(crate) async fn activate_required_with_startup_replay<S>(
    journey: Arc<ProjectObservationJourneyV1>,
    observation_store: S,
    cancellation: &HostCancellationToken,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError>
where
    S: ObservationStore + 'static,
{
    if cancellation.is_cancelled() {
        return Err(ObservationJourneyError::Cancelled { admitted: 0 });
    }
    journey.start_delivery_worker()?;
    let admitted = match run_startup_replay(journey.as_ref(), &observation_store, cancellation)
        .await
    {
        Ok(pass) => pass.admitted,
        Err(error @ ObservationJourneyError::Cancelled { .. }) => return Err(error),
        Err(error) => {
            let recoverability = replay_recoverability(&error);
            match recoverability {
                ReplayRecoverabilityV1::Retryable => {
                    tracing::error!(
                        event = "memory_observation_startup_replay_failed",
                        error = %error,
                        recoverability = "retryable",
                        journal = %journey.journal_path().display(),
                        "project observation startup replay failed on a retryable condition; the \
                         project server stays up and live replay retries from the durable \
                         watermark"
                    );
                    0
                }
                ReplayRecoverabilityV1::Permanent => {
                    tracing::error!(
                        event = "memory_observation_startup_replay_failed",
                        error = %error,
                        recoverability = "permanent",
                        journal = %journey.journal_path().display(),
                        "project observation startup replay failed permanently; no retry can \
                         clear it, so project open is refused rather than reporting a healthy \
                         journey over an undelivered commit"
                    );
                    return Err(ObservationJourneyError::StartupReplayPermanent {
                        source: Box::new(error),
                    });
                }
            }
        }
    };
    journey.start_live_replay(observation_store)?;
    tracing::info!(
        event = "memory_observation_startup_replay",
        admitted,
        journal = %journey.journal_path().display(),
        "project observation journey mounted"
    );
    Ok(journey)
}

/// Required deferred publication waits for the existing instance proof while
/// its owned replay and delivery workers continue historical convergence.
pub(crate) async fn activate_required_with_instance_ready<S>(
    journey: Arc<ProjectObservationJourneyV1>,
    observation_store: S,
    cancellation: &HostCancellationToken,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError>
where
    S: ObservationStore + 'static,
{
    if cancellation.is_cancelled() {
        return Err(ObservationJourneyError::Cancelled { admitted: 0 });
    }
    journey.start_observer_with_live_replay(observation_store)?;
    journey
        .await_instance_ready(cancellation, REQUIRED_ACTIVATION_BUDGET)
        .await?;
    Ok(journey)
}

/// Activates an explicitly settled journey and waits until its provider
/// instance and all durable deliveries have settled. Startup replay can append a row before the worker has
/// delivered it, and exposing recall in that interval permits a valid empty
/// answer to race the pending effect.
pub(crate) async fn activate_required_with_startup_replay_and_delivery_settled<S>(
    journey: Arc<ProjectObservationJourneyV1>,
    observation_store: S,
    cancellation: &HostCancellationToken,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError>
where
    S: ObservationStore + 'static,
{
    let journey =
        activate_required_with_startup_replay(journey, observation_store, cancellation).await?;
    journey
        .await_delivery_settled(cancellation, REQUIRED_ACTIVATION_BUDGET)
        .await?;
    Ok(journey)
}

/// Retains an optional observer without starting its provider bootstrap or replay.
/// The published full server activates the existing owned workers after cutover.
pub(crate) async fn mount_observer_dormant(
    inputs: ObservationJourneyMountInputsV1,
    cancellation: &HostCancellationToken,
) -> Result<Arc<ProjectObservationJourneyV1>, ObservationJourneyError> {
    if cancellation.is_cancelled() {
        return Err(ObservationJourneyError::Cancelled { admitted: 0 });
    }
    let journey =
        tokio::task::spawn_blocking(move || construct_project_observation_journey(inputs))
            .await
            .map_err(ObservationJourneyError::MountTask)??;
    if cancellation.is_cancelled() {
        return Err(ObservationJourneyError::Cancelled { admitted: 0 });
    }
    Ok(journey)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;
    use std::fmt::Write as _;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use serde_json::json;
    use tempfile::TempDir;
    use tracedecay_contracts::ResolvedScope;
    use tracedecay_domain::{
        CanonicalMessageRoleV1, CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1,
        CanonicalObservationFactV1, CanonicalObservationIdV1, CanonicalObservationRelationsV1,
        CanonicalUnknownStateV1, ComponentVersion, ObservationId, ObservationIdentityMaterialV1,
        ObservationOrderingDomainV1, ObservationSourceCursorV1, ObservationSourceGenerationV1,
        ObservationSourceIdentityV1, ObservationSourceRangeV1, PayloadReferenceV1,
        ProjectionGenerationId, ProviderId, RefId, RepositoryId, RetentionClass,
        SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1,
        SanitizerDispositionV1, SensitivityV1, SessionId, UtcMicros, WorktreeId,
    };
    use tracedecay_host_admission::{HostAdmissionAuthorities, HostAdmissionFacade};
    use tracedecay_memory_observation::{
        AppendOutcomeV1, DeliveryStateV1, JournalInspectionFilterV1, ObservationJournalReaderV1,
        RecoveryTimeBudgetV1,
    };
    use tracedecay_memory_provider_registry::{
        CommittedEffectEvidence, FabricConfig, FallbackDirective, HandshakeResponse,
        MemoryProviderV1, ObserverProviderRegistration, ProviderDescriptor, ProviderReply,
        SelectedProviderActivationV1, TerminalRecord,
    };
    use tracedecay_sessions::admission::HostAdmissionScope;
    use tracedecay_sessions::runtime::hosts::codex::try_admit_codex_jsonl_observations_for_project_with_admission;
    use tracedecay_store::{
        AnchoredObservationWrite, CursorAdvanceOutcome, ObservationBatchPersistOutcome,
        ObservationCursorAdvance, ObservationPersistOutcome, ObservationStore,
        ObservationStoreResult, ObservationWrite, build_observation_resolution_authorization_v1,
        build_observation_retrieval_anchor,
    };

    use super::*;
    use tracedecay_global_db::GlobalDbObservationStore;
    use tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1;

    const JOURNEY_PROVIDER_ID: &str = "tracedecay.journey-fixture";
    const JOURNEY_PROVIDER_INSTANCE_ID: &str = "tracedecay.journey-fixture.instance.v1";

    const READY_RECEIPT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PROVIDER_RECEIPT: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const EFFECT_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    mod control_dispatch;
    mod journal_replay;

    /// Seeded crash and restart fuzzing of this mount. It lives
    /// beside the journey's own suite because it reuses these fixtures to
    /// build the very same mount, and kills it in a child process at every
    /// boundary between the host's canonical commit and the provider's durable
    /// acknowledgement.
    #[cfg(unix)]
    mod crash_restart_fuzz;
    mod provider_history;
    #[cfg(unix)]
    mod real_ncm_observer;

    // The host's bounded-execution boundary, judged on its own accounting
    // rather than through a journey.
    mod bounded_provider_call {
        //! What the boundary publishes about the workers it owns.
        //!
        //! The mounted suite proves the journey survives a provider that does not
        //! return; this proves the numbers the journey (and an operator reading the
        //! delivery-failure log line) is given about it are true: a worker whose
        //! caller walked away is reported as abandoned for exactly as long as it is
        //! still running, the finite ceiling refuses the next call while it is, and
        //! every slot comes back when the work finally ends.
        #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

        use std::time::{Duration, Instant};

        use tracedecay_memory_conformance::ReleaseLatchV1;

        use super::*;

        /// Waits on the accounting transition that reaches `expected`.
        fn settle(boundary: &ThreadBoundedProviderCallV1, expected: BoundedCallCensusV1) {
            let observed =
                boundary.wait_for_census(Duration::from_secs(5), |census| census == expected);
            assert_eq!(
                observed,
                Ok(expected),
                "the boundary never reached {expected:?}; it still reports {:?}",
                boundary.census()
            );
        }

        /// A call whose worker is still running when its caller gives up is counted
        /// as abandoned, keeps its slot, and gives it back only when it returns.
        #[test]
        fn an_abandoned_worker_is_published_until_it_returns_and_then_reclaimed() {
            let boundary = ThreadBoundedProviderCallV1::new(1);
            let latch = ReleaseLatchV1::new();
            assert_eq!(boundary.census(), BoundedCallCensusV1::default());

            let held = latch.clone();
            let refusal = boundary
                .call_within(50, &CancellationToken::new(), move || {
                    held.wait();
                    7_u8
                })
                .expect_err("a worker that outlives its budget must not be waited out");
            assert!(
                matches!(
                    refusal,
                    BoundedCallRefusalV1::Abandoned { waited_millis: 50 }
                ),
                "{refusal:?}"
            );
            assert_eq!(
                boundary.census(),
                BoundedCallCensusV1 {
                    live: 0,
                    abandoned: 1,
                },
                "a worker still inside the work must be published, not forgotten"
            );

            // The ceiling is real while the worker is stranded, and the refusal
            // states the true number rather than assuming the whole budget is
            // abandoned.
            let refusal = boundary
                .call_within(50, &CancellationToken::new(), || 1_u8)
                .expect_err("the boundary's whole budget is committed");
            assert!(
                matches!(
                    refusal,
                    BoundedCallRefusalV1::Exhausted {
                        abandoned: 1,
                        maximum: 1,
                    }
                ),
                "{refusal:?}"
            );

            latch.release();
            settle(&boundary, BoundedCallCensusV1::default());
            assert_eq!(
                boundary
                    .call_within(5_000, &CancellationToken::new(), || 9_u8)
                    .expect("the reclaimed slot must be usable again"),
                9,
                "the boundary never took its slot back"
            );
            assert_eq!(boundary.census(), BoundedCallCensusV1::default());
        }

        /// Longest the boundary may take to hand a withdrawn caller back,
        /// measured from the instant its consent was withdrawn.
        ///
        /// The provider in this test is blocked on a latch nothing releases
        /// until the assertion has already been made, so anything above this
        /// means the caller was waiting the *provider* out rather than its own
        /// cancellation.
        const CANCELLATION_RELEASE_CEILING: Duration = Duration::from_millis(100);

        /// A caller cancelled **while its worker is inside the provider** is
        /// handed back promptly and leaves the same honest trace as one that
        /// ran out of budget: the worker it walked away from is abandoned, not
        /// lost.
        ///
        /// The cancellation deliberately fires only once the work has been
        /// entered — the work itself opens the entry latch the withdrawing
        /// thread is parked on, so "cancellation reached a call already inside
        /// the provider" is a fact rather than a guess about scheduling.
        /// Cancelling first proves something else entirely — that no worker is
        /// borrowed at all — and is asserted separately below.
        ///
        /// Real defect this catches: a boundary that notices cancellation only
        /// when the work finally answers. The provider here holds its worker
        /// far past the ceiling, so a caller that is released inside it can
        /// only have been released by its own cancellation.
        #[test]
        fn a_caller_cancelled_mid_call_leaves_its_worker_counted() {
            let boundary = ThreadBoundedProviderCallV1::new(2);
            let latch = ReleaseLatchV1::new();
            let entry = ReleaseLatchV1::new();
            let cancellation = CancellationToken::new();

            let announced = entry.clone();
            let cancelling = cancellation.clone();
            let withdraw = std::thread::spawn(move || {
                announced.wait();
                let withdrawn_at = Instant::now();
                cancelling.cancel();
                withdrawn_at
            });

            let held = latch.clone();
            let opened = entry.clone();
            let refusal = boundary
                .call_within(30_000, &cancellation, move || {
                    opened.release();
                    held.wait();
                    3_u8
                })
                .expect_err("a cancelled caller must stop waiting");
            let released_at = Instant::now();
            let withdrawn_at = withdraw.join().expect("the cancelling thread");
            assert!(
                matches!(refusal, BoundedCallRefusalV1::Cancelled),
                "{refusal:?}"
            );
            let waited = released_at.saturating_duration_since(withdrawn_at);
            assert!(
                waited <= CANCELLATION_RELEASE_CEILING,
                "the caller was handed back {waited:?} after it withdrew, past the \
                 {CANCELLATION_RELEASE_CEILING:?} ceiling: it was waiting out the provider \
                 rather than its own cancellation"
            );
            assert!(
                !latch.is_released(),
                "the provider was let go before the assertion, so this proves nothing about \
                 a caller released while its worker is still inside the provider"
            );
            assert_eq!(
                boundary.census(),
                BoundedCallCensusV1 {
                    live: 0,
                    abandoned: 1,
                }
            );

            latch.release();
            settle(&boundary, BoundedCallCensusV1::default());
        }

        /// A caller whose consent was already withdrawn contacts nobody.
        ///
        /// Cancellation is read *before* a slot is claimed and before a worker
        /// is borrowed, so a call the host no longer wants costs the provider
        /// nothing, costs the finite ceiling nothing, and cannot be answered
        /// into acceptance by a provider quick enough to beat the first
        /// polling slice.
        #[test]
        fn an_already_cancelled_caller_never_reaches_the_provider() {
            let boundary = ThreadBoundedProviderCallV1::new(1);
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            let contacted = Arc::new(AtomicBool::new(false));

            let reached = Arc::clone(&contacted);
            let refusal = boundary
                .call_within(5_000, &cancellation, move || {
                    reached.store(true, Ordering::Release);
                    3_u8
                })
                .expect_err("an already-cancelled caller must not be answered");
            assert!(
                matches!(refusal, BoundedCallRefusalV1::Cancelled),
                "{refusal:?}"
            );
            assert!(
                !contacted.load(Ordering::Acquire),
                "the boundary handed work to a provider after its caller had already \
                 withdrawn consent"
            );
            assert_eq!(
                boundary.census(),
                BoundedCallCensusV1::default(),
                "a call that never happened must not spend a borrowed worker"
            );
            assert_eq!(
                boundary
                    .call_within(5_000, &CancellationToken::new(), || 4_u8)
                    .expect("the ceiling of one must be untouched"),
                4
            );
        }

        /// Cancellation returns to the caller before a blocked provider is released to panic.
        ///
        /// The provider cannot panic until the test releases `release`, and that
        /// release happens only after the caller thread has joined with a typed
        /// `Cancelled` refusal. This is the cancellation-first ordering the
        /// immediate race below cannot establish. The worker is still published
        /// as abandoned at the join point, then its contained panic must release
        /// the last slot and emit the application-owned diagnostic after release.
        #[test]
        fn cancellation_returns_before_a_released_provider_panic_is_contained() {
            #[derive(Clone)]
            struct DiagnosticWriter(Arc<Mutex<Vec<u8>>>);

            impl std::io::Write for DiagnosticWriter {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(bytes);
                    Ok(bytes.len())
                }

                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }

            let boundary = Arc::new(ThreadBoundedProviderCallV1::new(1));
            let cancellation = CancellationToken::new();
            let (entered, entered_rx) = std::sync::mpsc::sync_channel(1);
            let (release, release_rx) = std::sync::mpsc::sync_channel(1);
            let diagnostics = Arc::new(Mutex::new(Vec::new()));
            let writer_diagnostics = Arc::clone(&diagnostics);
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(move || DiagnosticWriter(Arc::clone(&writer_diagnostics)))
                .finish();
            let dispatcher = tracing::Dispatch::new(subscriber);

            let worker_boundary = Arc::clone(&boundary);
            let worker_cancellation = cancellation.clone();
            let caller = std::thread::spawn(move || {
                tracing::dispatcher::with_default(&dispatcher, || {
                    worker_boundary.call_within(5_000, &worker_cancellation, move || -> u8 {
                        entered.send(()).expect("provider entry receiver");
                        release_rx.recv().expect("provider release sender");
                        panic!("provider panic after caller cancellation")
                    })
                })
            });

            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("provider did not enter before the cancellation");
            cancellation.cancel();
            let refusal = caller
                .join()
                .expect("the caller thread")
                .expect_err("cancellation must return before the provider is released");
            assert!(
                matches!(refusal, BoundedCallRefusalV1::Cancelled),
                "{refusal:?}"
            );
            assert_eq!(
                boundary.census(),
                BoundedCallCensusV1 {
                    live: 0,
                    abandoned: 1,
                },
                "the blocked provider must still be counted after the caller returns"
            );
            assert!(
                diagnostics.lock().unwrap().is_empty(),
                "the provider was diagnosed before the test released it to panic"
            );

            release.send(()).expect("provider release receiver");
            settle(&boundary, BoundedCallCensusV1::default());
            let captured = String::from_utf8(diagnostics.lock().unwrap().clone())
                .expect("captured diagnostic is UTF-8");
            assert!(
                captured.contains("memory_provider_panic_contained"),
                "the contained panic produced no application-owned diagnostic: {captured:?}"
            );
            assert!(
                !captured.contains("provider panic after caller cancellation"),
                "the untrusted panic payload escaped into the application-owned diagnostic: \
                 {captured:?}"
            );
        }

        /// Shutdown cancellation owns the attempt when it races a contained panic.
        #[test]
        fn cancellation_that_fires_before_a_panic_is_observed_wins_classification() {
            let boundary = ThreadBoundedProviderCallV1::new(1);
            for round in 0..64 {
                let cancellation = CancellationToken::new();
                let cancelled = cancellation.clone();
                let refusal = boundary
                    .call_within(5_000, &cancellation, move || -> u8 {
                        cancelled.cancel();
                        panic!("provider panic after cancellation")
                    })
                    .expect_err("shutdown cancellation must own the raced attempt");
                assert!(
                    matches!(refusal, BoundedCallRefusalV1::Cancelled),
                    "round {round}: {refusal:?}"
                );
                settle(&boundary, BoundedCallCensusV1::default());
            }
        }

        /// An answer produced after cancellation is refused rather than
        /// accepted, however narrowly it beats the next polling slice.
        ///
        /// The work here withdraws its own caller's consent and then answers
        /// success immediately, which is exactly what a provider that ignores
        /// cancellation does. The boundary receives a perfectly good answer
        /// and must still refuse it: once cancellation is observed the host
        /// has no consent left to act on the result.
        #[test]
        fn an_answer_produced_after_cancellation_is_refused_rather_than_accepted() {
            let boundary = ThreadBoundedProviderCallV1::new(1);
            let answered = Arc::new(AtomicUsize::new(0));
            let rounds = 64;

            for round in 0..rounds {
                let cancellation = CancellationToken::new();
                let ignored = cancellation.clone();
                let produced = Arc::clone(&answered);
                let refusal = boundary
                    .call_within(5_000, &cancellation, move || {
                        ignored.cancel();
                        produced.fetch_add(1, Ordering::AcqRel);
                        7_u8
                    })
                    .expect_err("an answer produced after cancellation must not be accepted");
                assert!(
                    matches!(refusal, BoundedCallRefusalV1::Cancelled),
                    "round {round}: {refusal:?}"
                );
                settle(&boundary, BoundedCallCensusV1::default());
            }

            assert_eq!(
                answered.load(Ordering::Acquire),
                rounds,
                "the work never actually produced the answer that had to be refused, so \
                 this proves nothing about refusing one"
            );
        }

        /// A worker that returns in the very instant its caller abandons it
        /// leaves no phantom behind.
        ///
        /// The two sides move the same accounting, and the abandoned count has
        /// to be reserved before the state that tells the worker to release it
        /// is published. Incrementing afterwards left a window in which the
        /// worker read `ABANDONED`, found nothing to release, and gave back
        /// only its owned slot — leaving one abandoned worker recorded that no
        /// thread was behind. The census hid that while nothing was owned, so
        /// the defect only surfaced on the *next* live call, as a stranded
        /// worker that did not exist and a ceiling one unit smaller for good.
        /// That is what the live call at the end is for.
        #[test]
        fn a_return_racing_with_abandonment_returns_every_count_to_the_baseline() {
            let boundary = Arc::new(ThreadBoundedProviderCallV1::new(2));
            let rounds = 1_000;

            for round in 0..rounds {
                // Accounted exactly as `call_within` accounts a borrowed
                // worker, so this races the production accounting rather than
                // a test-local imitation of it.
                boundary.owned_workers.fetch_add(1, Ordering::AcqRel);
                let accounting = Arc::new(BorrowedWorkerAccountingV1 {
                    owned: Arc::clone(&boundary.owned_workers),
                    abandoned: Arc::clone(&boundary.abandoned_workers),
                    census_changed: Arc::clone(&boundary.census_changed),
                    state: AtomicU8::new(BORROWED_WORKER_RUNNING),
                });
                let start = Arc::new(std::sync::Barrier::new(2));
                let worker = {
                    let accounting = Arc::clone(&accounting);
                    let start = Arc::clone(&start);
                    std::thread::spawn(move || {
                        start.wait();
                        accounting.returned();
                    })
                };
                start.wait();
                accounting.abandon();
                worker.join().expect("the racing worker");

                assert_eq!(
                    boundary.owned_workers.load(Ordering::Acquire),
                    0,
                    "round {round}: a borrowed-worker slot was never given back"
                );
                assert_eq!(
                    boundary.abandoned_workers.load(Ordering::Acquire),
                    0,
                    "round {round}: the accounting kept an abandoned worker that had \
                     already returned"
                );
                assert_eq!(
                    boundary.census(),
                    BoundedCallCensusV1::default(),
                    "round {round}"
                );
            }

            // The census only clamps a stale abandoned count while nothing is
            // owned. A live call is what makes a phantom visible, so the
            // baseline has to survive one.
            let latch = ReleaseLatchV1::new();
            let live = {
                let boundary = Arc::clone(&boundary);
                let held = latch.clone();
                std::thread::spawn(move || {
                    boundary.call_within(5_000, &CancellationToken::new(), move || {
                        held.wait();
                        5_u8
                    })
                })
            };
            settle(
                &boundary,
                BoundedCallCensusV1 {
                    live: 1,
                    abandoned: 0,
                },
            );
            latch.release();
            assert_eq!(
                live.join()
                    .expect("the live call thread")
                    .expect("a live call must be answered after the races settled"),
                5
            );
            settle(&boundary, BoundedCallCensusV1::default());
        }

        /// A worker that unwinds releases its slot and reaches the caller as a
        /// typed refusal, so a panicking provider cannot spend the ceiling either.
        #[test]
        fn a_panicking_worker_releases_its_slot_and_is_contained() {
            let boundary = ThreadBoundedProviderCallV1::new(1);
            let refusal = boundary
                .call_within(5_000, &CancellationToken::new(), || -> u8 {
                    panic!("provider crashed mid-call")
                })
                .expect_err("a panic must reach the caller as a refusal");
            assert!(
                matches!(refusal, BoundedCallRefusalV1::Unavailable(_)),
                "{refusal:?}"
            );
            settle(&boundary, BoundedCallCensusV1::default());
            assert_eq!(
                boundary
                    .call_within(5_000, &CancellationToken::new(), || 4_u8)
                    .expect("a crashed call must not spend the ceiling"),
                4
            );
        }
    }

    // The adversarial provider harness against this mount. It
    // lives beside the journey's own suite because it judges the same journal
    // rows, driven by a provider double that misbehaves on demand.
    mod adversarial_mounted_journey {
        //! The adversarial provider harness against the **mounted observation
        //! journey**.
        //!
        //! The sibling suite in `tracedecay-memory-provider-registry` drives a
        //! misbehaving provider through the registry's own dispatch and recall ports.
        //! What it cannot reach is the durable half of the story: the journal row.
        //! This module closes that gap. Every test here mounts the *production*
        //! journey through its retained constructor and delivery worker, using
        //! a provider double that misbehaves on demand, admits a real
        //! canonical observation through the real replay path, and then asserts three
        //! things together:
        //!
        //! * the **journal row settles correctly** — the delivery state and the
        //!   receipt table are the host's durable answer, and a misbehaving provider
        //!   may never buy an `acknowledged` row or a receipt;
        //! * **no worker is left parked in the provider** — judged from *both*
        //!   sides. The double counts the calls that entered it and have not left,
        //!   and the host publishes its own borrowed-worker census
        //!   ([`ProjectObservationJourneyV1::provider_call_census`]), which is the
        //!   count that actually matters: every episode captures the census before
        //!   the misbehaviour and asserts the lane returns to exactly that baseline
        //!   once the provider lets go. The journey's own typed shutdown report
        //!   still names a worker that panicked, a worker that missed the shutdown
        //!   deadline, or leases it could not reap;
        //! * the **journey stays responsive** — the lane keeps working after the
        //!   misbehaviour: it attempts the row again, a compliant retry settles where
        //!   the script allows one, and shutdown quiesces inside its budget. That is
        //!   the difference between "contained" and "the lane is dead until the
        //!   daemon restarts".
        #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

        use std::collections::BTreeSet;
        use std::sync::Arc;
        use std::time::Duration;

        use tracedecay_memory_conformance::{
            AdversarialPayloadSourceV1, AdversarialProviderInputsV1, AdversarialProviderV1,
            AdversarialScriptV1, HandshakeMisbehaviourV1, MisbehaviourV1, NoPayloadSourceV1,
            ReleaseLatchV1,
        };
        use tracedecay_memory_observation::{ObservationCommittedEffectV1, ObservationOutcomeV1};
        use tracedecay_memory_provider_registry::MemoryProviderV1;

        use super::*;

        /// State namespace the double reports at handshake. It has to sit under the
        /// observer's own admitted prefix or readiness is refused before a
        /// single delivery — which would prove nothing about delivery.
        const ADVERSARIAL_STATE_NAMESPACE: &str = "tracedecay.journey-fixture.adversarial";

        /// How long a settlement wait may run before the test reports the journal
        /// snapshot instead of a bare timeout.
        const SETTLEMENT_BUDGET: Duration = Duration::from_secs(20);

        /// The hold used when the point is the provider *ignoring* cancellation: long
        /// enough that the host's per-attempt bound and its whole shutdown budget both
        /// expire while the call is still inside the provider, short enough that the
        /// test can then wait for the late answer it must not accept.
        const IGNORED_CANCELLATION_BLOCK_MILLIS: u64 = 1_500;

        /// The descriptor the double registers under: its observer identity, the host's
        /// own limits, and the implementation identity the durable recovery record
        /// compares against.
        /// The state generation a freshly mounted adversarial double reports.
        ///
        /// Deliberately not zero. A provider whose state generation *moved
        /// backwards* can only be exhibited against a generation there is
        /// room below: at generation zero the misbehaviour degenerates into a
        /// compliant one, the mounted case is silently untested, and the
        /// refusal the test observes comes from some unrelated check further
        /// down the admission path.
        const ADVERSARIAL_STATE_GENERATION: u64 = 9;

        fn adversarial_descriptor() -> ProviderDescriptor {
            ProviderDescriptor::new(
                OwnedProviderId::new(JOURNEY_PROVIDER_ID).expect("journey provider"),
                "0".repeat(64),
                "adversarial-journey-v1",
                ADVERSARIAL_STATE_GENERATION,
                BTreeSet::from([
                    OwnedVersionedId::new("provider.health.v1").expect("health capability"),
                    OwnedVersionedId::new("observation.accept.v1").expect("observe capability"),
                    OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
                ]),
                crate::retained_owner::native_provider::native_provider_limits(),
            )
            .expect("adversarial descriptor")
        }

        /// A double whose readiness is impeccable and whose delivery follows `script`.
        ///
        /// Readiness is deliberately compliant here: the registry suite already proves
        /// a lying handshake never reaches a call, and this module is about what the
        /// *journal* does once a call really is dispatched.
        fn journey_double(
            script: AdversarialScriptV1<MisbehaviourV1>,
        ) -> Arc<AdversarialProviderV1> {
            journey_double_with_payloads(script, Arc::new(NoPayloadSourceV1))
        }

        /// The same double with a caller-chosen reply payload source.
        ///
        /// Observation delivery normally answers with no payload at all, which
        /// makes one behaviour unreachable: a *failing* terminal that smuggles
        /// a result payload past the host degenerates, with no payload, into an
        /// ordinary failure terminal. Injecting a payload source is what puts
        /// that behaviour back on the mounted path.
        fn journey_double_with_payloads(
            script: AdversarialScriptV1<MisbehaviourV1>,
            payloads: Arc<dyn AdversarialPayloadSourceV1>,
        ) -> Arc<AdversarialProviderV1> {
            Arc::new(AdversarialProviderV1::new(AdversarialProviderInputsV1 {
                descriptor: adversarial_descriptor(),
                provider_instance_id: JOURNEY_PROVIDER_INSTANCE_ID.to_owned(),
                state_namespace: ADVERSARIAL_STATE_NAMESPACE.to_owned(),
                ready_receipt_sha256: READY_RECEIPT.to_owned(),
                handshake_script: AdversarialScriptV1::always(HandshakeMisbehaviourV1::Compliant),
                invoke_script: script,
                payloads,
            }))
        }

        /// A reply payload bound to the contract of the call it answers.
        ///
        /// Small, canonical, and well-formed: the payload itself is never the
        /// misbehaviour, the terminal it is attached to is.
        struct ObservationReplyPayloadV1;

        impl AdversarialPayloadSourceV1 for ObservationReplyPayloadV1 {
            fn payload_for(&self, call: &ProviderCall) -> Result<Option<CanonicalPayload>, String> {
                let bytes = br#"{"observation":"accepted"}"#.to_vec();
                let digest = hex::encode(Sha256::digest(&bytes));
                CanonicalPayload::new(call.payload.contract_id.clone(), bytes, digest)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }

        // ---------------------------------------------------------------------------
        // Mounting
        // ---------------------------------------------------------------------------

        /// The mounted journey plus everything a test needs to feed and inspect it.
        struct AdversarialJourneyFixture {
            _runtime: HostAdmissionTestRuntimeV1,
            store: GlobalDbObservationStore,
            journey: Arc<ProjectObservationJourneyV1>,
            project_id: ProjectId,
        }

        impl AdversarialJourneyFixture {
            /// Commits one canonical observation and admits it through the production
            /// replay path, so the journal row under test is the one the daemon writes.
            async fn admit(&self, session: &str, text: &str) {
                let session_id = SessionId::new(session).expect("session id");
                self.store
                    .persist_observation(anchored_write(canonical_observation(
                        &self.project_id,
                        &session_id,
                        text,
                    )))
                    .await
                    .expect("canonical observation commit");
                self.journey
                    .replay_canonical_observations(&self.store, REPLAY_LIVE_PAGES, open_bounds())
                    .await
                    .expect("canonical replay");
            }

            fn journal_path(&self) -> &Path {
                self.journey.journal_path()
            }
        }

        /// A policy whose retry curve and per-attempt budget are short enough to run
        /// inside a test, and identical to the shipped one everywhere else.
        ///
        /// Both values are the *host's* bounds, which is exactly what a hanging
        /// provider is supposed to run into: shrinking them shortens the test without
        /// changing which side of the boundary makes the decision.
        fn bounded_policy(attempt_budget_micros: i64) -> ObservationJourneyPolicyV1 {
            let mut policy = ObservationJourneyPolicyV1::project_default();
            policy.retention.backoff_base_micros = 50_000;
            policy.dispatch.attempt_budget_micros = attempt_budget_micros;
            policy
        }

        /// Mounts the production journey over the double.
        async fn mount_adversarial_journey(
            temp: &TempDir,
            project: &str,
            profile: &str,
            provider: &Arc<AdversarialProviderV1>,
            policy: ObservationJourneyPolicyV1,
        ) -> AdversarialJourneyFixture {
            let project_id = ProjectId::new(project).expect("project id");
            let runtime = HostAdmissionTestRuntimeV1::project(
                &temp.path().join("profile"),
                &temp.path().join("project"),
                project_id.clone(),
            )
            .await
            .expect("registered project database");
            let store = runtime
                .registered_database_arc(HostAdmissionScope::Project)
                .expect("project database")
                .observation_store();
            let profile_id = UserProfileId::new(profile).expect("profile id");
            let journal_root = temp.path().join("journey");
            std::fs::create_dir_all(&journal_root).expect("journal root");
            let journey = mount_project_observation_journey(ObservationJourneyMountInputsV1 {
                composition: composition(Arc::clone(provider) as Arc<dyn MemoryProviderV1>),
                profile_id,
                scope: scope(project_id.clone()),
                authoritative_project_id: project_id.clone(),
                provider: test_observation_mount(&(journal_root), 1)
                    .expect("observer mount metadata"),
                store_data_root: journal_root,
                policy,
            })
            .expect("mounted journey");
            AdversarialJourneyFixture {
                _runtime: runtime,
                store,
                journey,
                project_id,
            }
        }

        // ---------------------------------------------------------------------------
        // Journal readers
        // ---------------------------------------------------------------------------

        /// The delivery row as the journal holds it right now: state, attempts, and
        /// the last outcome the host recorded against it.
        fn delivery_row(journal_path: &Path) -> Option<(String, i64, Option<String>)> {
            let connection = rusqlite::Connection::open(journal_path).expect("journal");
            connection
                .query_row(
                    "SELECT state, attempt_number, last_outcome FROM tdmem_observation_delivery_v1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .ok()
        }

        /// Receipts settled so far. A provider that misbehaved must never leave one.
        fn receipt_count(journal_path: &Path) -> i64 {
            let connection = rusqlite::Connection::open(journal_path).expect("journal");
            connection
                .query_row(
                    "SELECT COUNT(*) FROM tdmem_observation_receipt_v1",
                    [],
                    |row| row.get(0),
                )
                .expect("receipt count")
        }

        /// Durable receipt outcomes, in attempt order.
        fn receipt_outcomes(journal_path: &Path) -> Vec<(String, String)> {
            let connection = rusqlite::Connection::open(journal_path).expect("journal");
            let mut statement = connection
                .prepare(
                    "SELECT outcome, committed_effect FROM tdmem_observation_receipt_v1 \
                     ORDER BY attempt_number",
                )
                .expect("receipt outcome query");
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("receipt outcome rows")
                .map(|row| row.expect("receipt outcome row"))
                .collect()
        }

        /// The exact scope the delivery row is bound to. A provider's terminal may
        /// never move it: the host owns which checkout a row belongs to.
        fn delivery_scope(journal_path: &Path) -> Option<String> {
            let connection = rusqlite::Connection::open(journal_path).expect("journal");
            connection
                .query_row(
                    "SELECT exact_scope_sha256 FROM tdmem_observation_delivery_v1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .ok()
        }

        /// Answered attempts whose terminal the host refused as delivery evidence,
        /// as the durable audit records them.
        fn attempt_refusals(journal_path: &Path) -> Vec<(i64, String, String)> {
            let connection = rusqlite::Connection::open(journal_path).expect("journal");
            let mut statement = connection
                .prepare(
                    "SELECT attempt_number, category, refused_field \
                     FROM tdmem_observation_attempt_refusal_v1 ORDER BY attempt_number",
                )
                .expect("refusal query");
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("refusal rows");
            rows.map(|row| row.expect("refusal row")).collect()
        }

        /// Waits for a delivery drain to publish a row satisfying `admits`.
        /// Interest is registered before each read, so a transition between the
        /// read and the await cannot be lost.
        async fn wait_for_delivery_row(
            fixture: &AdversarialJourneyFixture,
            mut admits: impl FnMut(&(String, i64, Option<String>)) -> bool,
            expectation: &str,
        ) -> (String, i64, Option<String>) {
            match fixture
                .journey
                .delivery_changed
                .wait_until_async(SETTLEMENT_BUDGET, || {
                    delivery_row(fixture.journal_path()).filter(&mut admits)
                })
                .await
            {
                Ok(row) => row,
                Err(()) => panic!(
                    "{expectation}; {}",
                    journal_snapshot(fixture.journal_path())
                ),
            }
        }

        /// Waits until the journal records at least `attempts` attempts against the
        /// single delivery row, and returns it.
        ///
        /// The attempt number is what a *started* attempt costs, so this is the
        /// question "did the host get to try again?" — which a host still parked in
        /// its first call can never answer.
        async fn wait_for_attempts(
            fixture: &AdversarialJourneyFixture,
            attempts: i64,
        ) -> (String, i64, Option<String>) {
            wait_for_delivery_row(
                fixture,
                |row| row.1 >= attempts,
                &format!("the journal never recorded {attempts} attempt(s)"),
            )
            .await
        }

        /// Waits until the single delivery row reaches `state`.
        async fn wait_for_state(
            fixture: &AdversarialJourneyFixture,
            state: &str,
        ) -> (String, i64, Option<String>) {
            wait_for_delivery_row(
                fixture,
                |row| row.0 == state,
                &format!("the delivery row never reached `{state}`"),
            )
            .await
        }

        /// Waits on the adversarial provider's own in-flight transition.
        async fn wait_for_provider_in_flight(
            provider: &Arc<AdversarialProviderV1>,
            calls: u64,
            fixture: &AdversarialJourneyFixture,
        ) {
            let provider = Arc::clone(provider);
            let reached = tokio::task::spawn_blocking(move || {
                provider.wait_until_in_flight(calls, SETTLEMENT_BUDGET)
            })
            .await
            .expect("provider in-flight waiter");
            assert!(
                reached,
                "the mounted journey never reached {calls} provider call(s); {}",
                journal_snapshot(fixture.journal_path())
            );
        }

        /// Waits on the adversarial provider's own transition back to idle.
        async fn wait_for_provider_idle(
            provider: &Arc<AdversarialProviderV1>,
            fixture: &AdversarialJourneyFixture,
        ) {
            let provider = Arc::clone(provider);
            let idle =
                tokio::task::spawn_blocking(move || provider.wait_until_idle(SETTLEMENT_BUDGET))
                    .await
                    .expect("provider idle waiter");
            assert!(
                idle,
                "the provider never returned to idle; {}",
                journal_snapshot(fixture.journal_path())
            );
        }

        /// Shuts the journey down inside `budget` and returns the typed failures.
        async fn shutdown_within(
            journey: &ProjectObservationJourneyV1,
            budget: Duration,
        ) -> Vec<ObservationShutdownFailureV1> {
            journey.shutdown(tokio::time::Instant::now() + budget).await
        }

        /// Waits until the lane's own borrowed-worker census is back to
        /// `baseline`, and reports what it still holds if it never is.
        ///
        /// This is the host-owned half of "no worker was leaked". The double's
        /// in-flight counter says whether *provider* work is still running; this
        /// says whether the **host** still owns a thread for it, which is the count
        /// that matters and the only one that can grow without bound. An
        /// episode that ends above its baseline left a worker behind.
        async fn wait_for_census(
            fixture: &AdversarialJourneyFixture,
            baseline: BoundedCallCensusV1,
        ) {
            let settled = fixture
                .journey
                .provider_isolation
                .census_changed
                .wait_until_async(SETTLEMENT_BUDGET, || {
                    let census = fixture.journey.provider_call_census();
                    (census == baseline).then_some(census)
                })
                .await;
            assert_eq!(
                settled,
                Ok(baseline),
                "the host never returned its borrowed workers to the baseline census \
                 {baseline:?}; it still reports {:?}; {}",
                fixture.journey.provider_call_census(),
                journal_snapshot(fixture.journal_path())
            );
        }

        /// The census the lane starts from, asserted empty so a later comparison
        /// against it is a comparison against zero borrowed workers rather than
        /// against whatever the mount happened to leave behind.
        fn worker_baseline(fixture: &AdversarialJourneyFixture) -> BoundedCallCensusV1 {
            let baseline = fixture.journey.provider_call_census();
            assert_eq!(
                baseline,
                BoundedCallCensusV1::default(),
                "a freshly mounted journey must own no borrowed provider workers"
            );
            baseline
        }

        /// Waits until the mounted lane publishes a delivery refusal whose
        /// typed class satisfies `admits`, and returns it.
        ///
        /// This is the assertion the rest of this suite cannot make on its
        /// own. A retry count says the host refused *something*; it does not
        /// say the host refused it for the reason the behaviour is about, so a
        /// test that only counts attempts still passes when a misbehaviour is
        /// rejected by accident — a readiness failure, a byte ceiling, an
        /// unreachable provider. The lane's own published classification
        /// ([`ProjectObservationJourneyV1::recent_delivery_refusals`]) closes
        /// that gap with the exact `DeliveryAdapterError`/`FabricError` the
        /// mounted delivery produced.
        async fn wait_for_refusal(
            fixture: &AdversarialJourneyFixture,
            mut admits: impl FnMut(&DeliveryRefusalClassV1) -> bool,
            expectation: &str,
        ) -> DeliveryRefusalV1 {
            match fixture
                .journey
                .delivery_refusals
                .wait_for(SETTLEMENT_BUDGET, |refusal| admits(&refusal.class))
                .await
            {
                Ok(refusal) => refusal,
                Err(published) => panic!(
                    "the lane never classified a delivery refusal as {expectation}; it \
                     published {published:?}; {}",
                    journal_snapshot(fixture.journal_path())
                ),
            }
        }

        /// Every refusal the lane published carries a class the host actually
        /// produced.
        ///
        /// An `Unclassified` refusal means a failure reached the runtime's
        /// adapter channel from a path this mount does not know it has, which
        /// is a finding in itself rather than something to fold into a
        /// neighbouring class.
        fn every_refusal_is_classified(fixture: &AdversarialJourneyFixture) {
            let unclassified: Vec<_> = fixture
                .journey
                .recent_delivery_refusals()
                .into_iter()
                .filter(|refusal| refusal.class == DeliveryRefusalClassV1::Unclassified)
                .collect();
            assert!(
                unclassified.is_empty(),
                "the lane refused deliveries it could not classify: {unclassified:?}"
            );
            assert!(
                fixture.journey.delivery_refusals_total() > 0,
                "the lane published no delivery refusal at all, so the misbehaviour was \
                 never refused on the mounted delivery path"
            );
        }

        // ---------------------------------------------------------------------------
        // Crash mid-dispatch
        // ---------------------------------------------------------------------------

        /// A provider that panics after receiving the delivery and before replying
        /// must not take the journey's delivery worker with it.
        ///
        /// What the journal has to say afterwards is exact: the row is **not**
        /// acknowledged, no receipt exists, and the attempt was consumed. What the
        /// process has to say is just as exact: the delivery worker is still the one
        /// the mount started — proved by the next attempt being made at all — and
        /// shutdown reports no panicked worker.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_provider_that_crashes_mid_delivery_does_not_kill_the_delivery_worker() {
            let provider = journey_double(AdversarialScriptV1::always(
                MisbehaviourV1::PanicsMidDispatch,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-crash",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-crash", "crash mid dispatch")
                .await;
            fixture.journey.wake_delivery();

            let (state, attempts, outcome) = wait_for_attempts(&fixture, 2).await;
            assert_ne!(
                state, "acknowledged",
                "a provider that never replied must not settle an acknowledgement"
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                0,
                "a crashed delivery must leave no receipt: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert!(
                attempts >= 2,
                "the delivery worker stopped after the crash instead of retrying: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                provider.in_flight(),
                0,
                "a crashed call must not be left counted as in flight"
            );
            // A call that never returned told the journal nothing about the
            // provider's effect, so the row carries no outcome at all. A host
            // that recorded one here would be inventing knowledge about a
            // mutation it cannot see.
            assert_eq!(
                outcome, None,
                "a crashed call must not leave a provider outcome behind"
            );

            // The exact typed terminal the mounted delivery produced for the
            // crash: the boundary contained the unwind on the borrowed worker
            // and handed the lane a refusal naming it, rather than any of the
            // other reasons a delivery can fail.
            let refusal = wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::BoundedCallRefused(
                            BoundedCallRefusalV1::Unavailable(_)
                        )
                    )
                },
                "a bounded provider call that could not be completed because the provider \
                 unwound",
            )
            .await;
            assert!(
                refusal.detail.contains("panicked"),
                "the crash refusal does not name the crash: {refusal:?}"
            );
            every_refusal_is_classified(&fixture);

            // The journey's own statement about its worker. A panic that escaped
            // into the delivery thread shows up here as `WorkerPanicked`, and a
            // dead worker cannot quiesce its leases either.
            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(
                failures.is_empty(),
                "the provider's panic reached the journey's own worker: {failures:?}"
            );

            // The borrowed worker each crash unwound through was released by
            // the boundary that lent it: the lane owns exactly the workers it
            // started with.
            wait_for_census(&fixture, baseline).await;
        }

        // ---------------------------------------------------------------------------
        // Hang past the deadline
        // ---------------------------------------------------------------------------

        /// A provider that holds the delivery call far past the host's own per-attempt
        /// budget must not hold the journey's single delivery worker with it.
        ///
        /// The host's bound is half a second; the provider holds for five. The journal
        /// must record the attempt as unsettled inside the host's bound, the worker
        /// must be free to take the next row, and shutdown must not have to wait for
        /// the provider.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_provider_that_hangs_past_the_attempt_budget_does_not_park_the_delivery_worker() {
            // The hold ends when the test says so, not after a wall-clock span: a
            // loaded runner must not let the provider answer before the host's
            // retry is observed.
            let release = tracedecay_memory_conformance::ReleaseLatchV1::new();
            let provider = journey_double(AdversarialScriptV1::always(
                MisbehaviourV1::NeverRepliesUntilReleased(release.clone()),
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-hang",
                "profile.adversarial",
                &provider,
                bounded_policy(200_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-hang", "hang past the deadline")
                .await;
            fixture.journey.wake_delivery();

            // Wait until the provider really is holding the host's call. Every
            // assertion below is about a *live* hang, not about a provider that
            // happened to answer early.
            wait_for_provider_in_flight(&provider, 1, &fixture).await;
            assert_eq!(
                provider.invocation_count(),
                1,
                "the in-flight transition must describe the first provider contact"
            );

            // The discriminator is not wall-clock: it is that the host got on
            // with its work while its first call was still inside the provider.
            // A second attempt appears on the row, and the provider has still
            // been contacted exactly once — the fabric refuses the retry while
            // the abandoned call holds the provider's single in-flight slot. A
            // host that followed its provider down could not show a second
            // attempt without a second contact, because its only delivery
            // thread would still be inside the first one.
            let (_, attempts, _) = wait_for_attempts(&fixture, 2).await;
            assert!(attempts >= 2);
            assert_eq!(
                provider.invocation_count(),
                1,
                "the retry must be refused before a second provider contact"
            );
            assert!(
                provider.in_flight() >= 1,
                "the first call returned before the journal recorded the retry"
            );

            // The host's own count of the thread it walked away from, not the
            // provider's: the call it stopped waiting for is still owned and
            // is reported as abandoned rather than forgotten.
            let hung_census = fixture.journey.provider_call_census();
            assert!(
                hung_census.abandoned >= 1,
                "the host stopped waiting for a call that is still inside the provider but \
                 reported no abandoned worker: {hung_census:?}"
            );
            let parked_at_peak = fixture.journey.provider_call_census().owned();

            // The exact typed terminal for a hang: the host stopped waiting at
            // its own bound and said so, rather than reporting an unreachable
            // provider or a refused answer.
            let refusal = wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::BoundedCallRefused(
                            BoundedCallRefusalV1::Abandoned { .. }
                        )
                    )
                },
                "a bounded provider call abandoned at the host's own budget",
            )
            .await;
            assert!(
                matches!(
                    refusal.class,
                    DeliveryRefusalClassV1::BoundedCallRefused(
                        BoundedCallRefusalV1::Abandoned { waited_millis }
                    ) if waited_millis > 0
                ),
                "the host reported abandoning a call it never waited for: {refusal:?}"
            );
            every_refusal_is_classified(&fixture);

            // Shutdown is the host's own statement about its worker: with the
            // delivery thread free it quiesces inside its budget while the
            // provider still holds the call. A worker parked in the provider
            // reports `WorkerDeadline` here instead.
            let failures = shutdown_within(&fixture.journey, Duration::from_secs(2)).await;
            assert!(
                failures.is_empty(),
                "shutdown could not reclaim the delivery worker: {failures:?}"
            );
            assert!(
                provider.in_flight() >= 1,
                "the provider had already returned, so nothing here was abandoned"
            );

            let (state, _, outcome) = delivery_row(fixture.journal_path()).expect("delivery row");
            assert_ne!(
                state, "acknowledged",
                "a provider that never answered inside the bound must not settle: \
                 outcome={outcome:?}"
            );
            assert_eq!(receipt_count(fixture.journal_path()), 0);

            // The thread count that matters is the one the host itself grows:
            // every call inside the double is one host thread parked in the
            // provider. It never passed the boundary's ceiling while the hang
            // was live, and once the provider finally lets go it returns to
            // zero — nothing stayed parked, and nothing accumulated.
            assert!(
                parked_at_peak <= MAX_ABANDONED_PROVIDER_CALLS,
                "the host parked {parked_at_peak} threads in the provider, past its own \
                 ceiling of {MAX_ABANDONED_PROVIDER_CALLS}"
            );
            release.release();
            wait_for_provider_idle(&provider, &fixture).await;
            wait_for_census(&fixture, baseline).await;
        }

        // ---------------------------------------------------------------------------
        // Protocol violations, judged by the journal
        // ---------------------------------------------------------------------------

        /// A duplicate acknowledgement naming a mutation the host never delivered
        /// settles nothing, and the row is still there for the compliant retry.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_duplicate_naming_another_mutation_settles_no_receipt_and_the_row_is_redelivered()
        {
            let provider = journey_double(AdversarialScriptV1::then(
                vec![MisbehaviourV1::DuplicateAcknowledgingAnotherMutation],
                MisbehaviourV1::Compliant,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-duplicate",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-duplicate", "duplicate ack")
                .await;
            fixture.journey.wake_delivery();

            let (state, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert_eq!(state, "acknowledged");
            assert!(
                attempts >= 2,
                "the forged duplicate must have cost an attempt rather than settling: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                2,
                "the rejected terminal and compliant retry must both leave evidence"
            );
            assert_eq!(attempt_refusals(fixture.journal_path()).len(), 1);
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("applied".to_owned(), "applied".to_owned()),
                ]
            );
            assert_eq!(provider.in_flight(), 0);

            // Refused for being a duplicate that names somebody else's
            // mutation — not for its size, its scope, or its operation.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(FabricError::Api(
                            ApiError::DuplicateEffectKeyMismatch
                        ))
                    )
                },
                "a duplicate acknowledgement bound to another mutation's key",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        /// A reply padded past the negotiated response ceiling is refused with
        /// unknown-effect evidence, and the row is redelivered to the compliant retry.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_oversized_delivery_reply_is_refused_and_the_row_is_redelivered() {
            let padding_bytes = usize::try_from(adversarial_descriptor().limits.response_bytes)
                .expect("response limit fits this host")
                .checked_add(1)
                .expect("oversized fixture fits this host");
            let provider = journey_double(AdversarialScriptV1::then(
                vec![MisbehaviourV1::OversizedReply { padding_bytes }],
                MisbehaviourV1::Compliant,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-oversized",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-oversized", "oversized reply")
                .await;
            fixture.journey.wake_delivery();

            let (_, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert!(
                attempts >= 2,
                "the oversized reply must have been refused rather than settled: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(receipt_count(fixture.journal_path()), 2);
            assert_eq!(attempt_refusals(fixture.journal_path()).len(), 1);
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("applied".to_owned(), "applied".to_owned()),
                ]
            );

            // Refused at the negotiated response ceiling itself, named field
            // and all — the reply never became a receipt for another reason.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(FabricError::Api(
                            ApiError::BoundaryBytesExceeded {
                                field: "response",
                                ..
                            }
                        ))
                    )
                },
                "a reply past the negotiated response byte ceiling",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        /// Success carrying effect evidence whose digest does not describe the bytes
        /// is not an acknowledgement.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_corrupted_effect_digest_is_not_acknowledged() {
            let provider = journey_double(AdversarialScriptV1::then(
                vec![MisbehaviourV1::CorruptedPayloadDigest],
                MisbehaviourV1::Compliant,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-digest",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-digest", "corrupted digest")
                .await;
            fixture.journey.wake_delivery();

            let (_, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert!(
                attempts >= 2,
                "corrupted effect evidence must not settle: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(receipt_count(fixture.journal_path()), 2);
            assert_eq!(attempt_refusals(fixture.journal_path()).len(), 1);
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("applied".to_owned(), "applied".to_owned()),
                ]
            );

            // Refused because the declared digest does not describe the bytes
            // it is attached to: evidence the host cannot verify is not
            // evidence.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(FabricError::Api(
                            ApiError::ContentDigestMismatch("payload_sha256")
                        ))
                    )
                },
                "a reply whose declared payload digest does not describe its bytes",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        /// A provider whose reported state generation moves backwards is refused,
        /// and both attempts remain durable unknown effects when the retry cap
        /// stops delivery without recording an effect the host cannot verify.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_state_generation_that_moved_backwards_is_refused_by_the_mounted_journey() {
            let provider = journey_double(AdversarialScriptV1::always(
                MisbehaviourV1::StateGenerationBackwards,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            // Refused answers remain pending with unknown effects. Once both
            // provider attempts are consumed, the journal adds its own exhaustion
            // receipt without dispatching another provider call.
            let mut policy = bounded_policy(1_000_000);
            policy.retention.max_attempts = 2;
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-generation",
                "profile.adversarial",
                &provider,
                policy,
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-generation", "generation backwards")
                .await;
            fixture.journey.wake_delivery();

            let (state, attempts, outcome) = wait_for_delivery_row(
                &fixture,
                |row| row.0 == "exhausted" && fixture.journey.delivery_refusals_total() == 2,
                "both generation refusals were not settled and published at the retry cap",
            )
            .await;
            assert_eq!(attempts, 3);
            assert_ne!(state, "acknowledged", "outcome={outcome:?}");
            assert_eq!(provider.ledger().count_for(ProviderOperation::Observe), 2);
            assert_eq!(attempt_refusals(fixture.journal_path()).len(), 2);
            let inspection = fixture
                .journey
                .journal
                .inspect(&JournalInspectionFilterV1::default())
                .unwrap();
            assert_eq!(inspection.rows.len(), 1);
            let receipts = fixture
                .journey
                .journal
                .receipts_for(&inspection.rows[0].observation_id)
                .unwrap();
            assert_eq!(receipts.len(), 3);
            for (receipt, attempt) in receipts[..2].iter().zip([1, 2]) {
                assert_eq!(receipt.attempt_number, attempt);
                assert_eq!(receipt.outcome, ObservationOutcomeV1::EffectUnknown);
                assert_eq!(
                    receipt.committed_effect,
                    ObservationCommittedEffectV1::Unknown
                );
                assert_eq!(
                    receipt.provider_instance_id.as_deref(),
                    Some(JOURNEY_PROVIDER_INSTANCE_ID)
                );
                assert_eq!(receipt.provider_effect_summary.no_effect_reason, None);
            }
            let exhaustion = &receipts[2];
            assert_eq!(exhaustion.attempt_number, 3);
            assert_eq!(
                exhaustion.outcome,
                ObservationOutcomeV1::ProviderUnavailable
            );
            assert_eq!(
                exhaustion.committed_effect,
                ObservationCommittedEffectV1::None
            );
            assert_eq!(exhaustion.provider_instance_id, None);
            assert_eq!(
                exhaustion
                    .provider_effect_summary
                    .no_effect_reason
                    .as_deref(),
                Some("max_delivery_attempts_consumed")
            );
            for receipt in &receipts {
                assert_eq!(receipt.provider_id.as_str(), JOURNEY_PROVIDER_ID);
                assert_eq!(receipt.registration_revision, 1);
                assert_eq!(receipt.state_generation_before, None);
                assert_eq!(receipt.state_generation_after, None);
                assert_eq!(receipt.provider_receipt_digest, None);
                assert_eq!(receipt.provider_effect_summary.effect_count, 0);
                assert_eq!(
                    receipt.provider_effect_summary.stable_memory_refs,
                    Vec::<String>::new()
                );
                assert_eq!(
                    receipt.provider_effect_summary.provider_trace_refs,
                    Vec::<String>::new()
                );
            }
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("provider_unavailable".to_owned(), "none".to_owned()),
                ]
            );
            assert_eq!(provider.in_flight(), 0);

            // Refused because the effect evidence contradicts the generation
            // the call was admitted against — a restore or a wipe under the
            // journal, not merely "an error".
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(
                            FabricError::ResponseStateGenerationMismatch { .. }
                        )
                    )
                },
                "effect evidence whose starting generation contradicts the admitted call",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        // ---------------------------------------------------------------------------
        // A failing terminal that smuggles a payload
        // ---------------------------------------------------------------------------

        /// A failing terminal that nevertheless carries a result payload is refused
        /// **whole**: the host does not strip the payload and keep the terminal, and
        /// the row is redelivered to the compliant retry.
        ///
        /// This behaviour needs a provider that has a payload to smuggle, so the
        /// double is given a real reply payload source here rather than the
        /// no-payload one the rest of this suite uses. Without it the misbehaviour
        /// is unreachable and the case is silently untested.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_payload_on_a_failing_observation_terminal_is_refused_and_redelivered() {
            let provider = journey_double_with_payloads(
                AdversarialScriptV1::then(
                    vec![MisbehaviourV1::PayloadOnFailureTerminal(
                        TerminalCode::CapacityExceeded,
                    )],
                    MisbehaviourV1::Compliant,
                ),
                Arc::new(ObservationReplyPayloadV1),
            );
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-payload-on-failure",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit(
                    "session.adversarial-payload",
                    "payload on a failing terminal",
                )
                .await;
            fixture.journey.wake_delivery();

            let (_, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert!(
                attempts >= 2,
                "a failing terminal carrying a payload must have cost an attempt rather \
                 than settling one: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                2,
                "the rejected terminal and compliant retry must both leave evidence: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                attempt_refusals(fixture.journal_path()).len(),
                1,
                "the rejected terminal must leave a durable refusal audit row"
            );
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![
                    ("effect_unknown".to_owned(), "unknown".to_owned()),
                    ("applied".to_owned(), "applied".to_owned()),
                ]
            );

            // Refused for exactly the thing the behaviour is about: a payload
            // the terminal it rides on may not carry.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(FabricError::Api(
                            ApiError::PayloadForbiddenForTerminal {
                                terminal_code: TerminalCode::CapacityExceeded,
                            }
                        ))
                    )
                },
                "a result payload carried by a capacity_exceeded terminal",
            )
            .await;
            every_refusal_is_classified(&fixture);
            assert_eq!(
                provider.invocation_count(),
                2,
                "the smuggling reply must have been a real dispatch, not a pre-contact refusal"
            );
            assert_eq!(provider.in_flight(), 0);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        // ---------------------------------------------------------------------------
        // A provider that never returns at all
        // ---------------------------------------------------------------------------

        /// The provider that does not come back: every delivery call it receives
        /// stays inside it until this test releases it, on no timer and through no
        /// cancellation.
        ///
        /// This is the case a timed "hang" cannot prove. A double that eventually
        /// returns lets a host pass by outlasting it; this one cannot be outlasted,
        /// so the only way the lane can keep working is by walking away from its own
        /// call. What the host owes then is stated in full here:
        ///
        /// * the call is **abandoned, not forgotten** — the boundary's published
        ///   census counts the borrowed worker as abandoned while it is still inside
        ///   the provider;
        /// * the cost is **finite** — the census never passes the host's own ceiling,
        ///   however many attempts the row makes;
        /// * the lane **keeps working** — the journal records further attempts and
        ///   shutdown quiesces in a budget the provider never agreed to;
        /// * nothing settles — no acknowledgement and no receipt;
        /// * and every borrowed worker is **reclaimed** the moment the provider
        ///   finally lets go, which the test triggers itself, as cleanup, after the
        ///   containment assertions are done.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_provider_that_never_returns_is_abandoned_bounded_and_fully_reclaimed() {
            let latch = ReleaseLatchV1::new();
            let provider = journey_double(AdversarialScriptV1::always(
                MisbehaviourV1::NeverRepliesUntilReleased(latch.clone()),
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-never-returns",
                "profile.adversarial",
                &provider,
                bounded_policy(200_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-never-returns", "never returns")
                .await;
            fixture.journey.wake_delivery();

            // The provider really is holding a call, and only this test can end it.
            wait_for_provider_in_flight(&provider, 1, &fixture).await;

            // The host answered itself at its own bound with the call still inside
            // the provider, and says so: the worker it walked away from is counted
            // as abandoned rather than dropped from the books.
            let abandoned = fixture
                .journey
                .provider_isolation
                .census_changed
                .wait_until_async(SETTLEMENT_BUDGET, || {
                    let census = fixture.journey.provider_call_census();
                    (census.abandoned >= 1).then_some(census)
                })
                .await
                .unwrap_or_else(|()| {
                    panic!(
                        "the host never published the borrowed worker it stopped waiting for; {}",
                        journal_snapshot(fixture.journal_path())
                    )
                });
            assert!(abandoned.abandoned >= 1);
            assert!(
                latch.parked() >= 1,
                "the call was not still parked on the provider's release latch"
            );

            // The lane got on with its work while the first call was still parked,
            // and the cost of doing so stayed inside the host's own ceiling.
            let (_, attempts, _) = wait_for_attempts(&fixture, 2).await;
            assert!(
                attempts >= 2,
                "the delivery worker never started a second attempt"
            );
            let parked_at_peak = fixture.journey.provider_call_census().owned();
            assert!(
                parked_at_peak <= MAX_ABANDONED_PROVIDER_CALLS,
                "the host parked {parked_at_peak} borrowed workers in a provider that never \
                 returns, past its own ceiling of {MAX_ABANDONED_PROVIDER_CALLS}"
            );

            let (state, _, outcome) = delivery_row(fixture.journal_path()).expect("delivery row");
            assert_ne!(
                state, "acknowledged",
                "a provider that never answered must not settle: outcome={outcome:?}"
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                0,
                "a call that never returned must leave no receipt: {}",
                journal_snapshot(fixture.journal_path())
            );

            // The exact typed terminal: abandoned at the host's own bound. A
            // provider that cannot be outlasted can only be answered this way.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::BoundedCallRefused(
                            BoundedCallRefusalV1::Abandoned { .. }
                        )
                    )
                },
                "a bounded provider call abandoned at the host's own budget",
            )
            .await;
            every_refusal_is_classified(&fixture);

            // Shutdown does not wait for a provider that never returns: the delivery
            // thread is the journey's own and was never inside the provider.
            let failures = shutdown_within(&fixture.journey, Duration::from_secs(2)).await;
            assert!(
                failures.is_empty(),
                "shutdown could not reclaim the delivery worker while a provider call was \
                 still parked: {failures:?}"
            );

            // Everything above was asserted against a call that had genuinely not
            // returned, and the host owns only workers nobody is waiting for.
            assert!(
                !latch.is_released(),
                "the double answered on its own, so nothing here was abandoned"
            );
            let parked = fixture.journey.provider_call_census();
            assert!(
                parked.abandoned >= 1 && parked.live == 0,
                "after shutdown every borrowed worker still inside the provider must be \
                 reported as abandoned: {parked:?}"
            );
            assert!(
                provider.in_flight() >= 1 && latch.parked() >= 1,
                "the provider is no longer holding the call the host abandoned"
            );

            // Cleanup only: let the double go, and prove the host gives every
            // borrowed worker back rather than leaking them for the process's life.
            latch.release();
            wait_for_census(&fixture, baseline).await;
            wait_for_provider_idle(&provider, &fixture).await;
            assert_eq!(
                latch.parked(),
                0,
                "the released provider never let go of its calls"
            );
        }

        // ---------------------------------------------------------------------------
        // Cancellation ignored
        // ---------------------------------------------------------------------------

        /// A provider that keeps working after the host's cancellation fires, and
        /// then answers a perfectly formed success, must not settle the row with it.
        ///
        /// The cancellation here is the real one: shutdown cancels the very token the
        /// delivery call was handed. The double never reads it, works on, and answers
        /// success — and the ledger proves it answered while the token was already
        /// cancelled, so this is a test of a provider ignoring cancellation rather
        /// than of a host that pre-empted it. The late success reaches nobody: the
        /// row is unsettled, one cancellation receipt exists, and the borrowed
        /// worker comes back.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_late_success_from_a_provider_that_ignored_cancellation_settles_nothing() {
            let provider = journey_double(AdversarialScriptV1::always(
                MisbehaviourV1::BlocksPastDeadline {
                    block_millis: IGNORED_CANCELLATION_BLOCK_MILLIS,
                },
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-cancellation",
                "profile.adversarial",
                &provider,
                bounded_policy(200_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-cancellation", "ignores cancellation")
                .await;
            fixture.journey.wake_delivery();

            wait_for_provider_in_flight(&provider, 1, &fixture).await;

            // Withdraw the host's consent while the provider is working. Shutdown
            // cancels the wake edge's token, which is the token the call carries.
            let failures = shutdown_within(&fixture.journey, Duration::from_secs(2)).await;
            assert!(
                failures.is_empty(),
                "shutdown waited for a provider that ignores cancellation: {failures:?}"
            );

            // Let the provider finish on its own schedule and answer success anyway.
            wait_for_provider_idle(&provider, &fixture).await;
            assert!(
                provider.ledger().answered_after_cancellation(),
                "the double never answered while the token was cancelled, so this proves \
                 nothing about ignoring cancellation: {:?}",
                provider.ledger().contacts()
            );

            let (state, _, outcome) = delivery_row(fixture.journal_path()).expect("delivery row");
            assert_ne!(
                state, "acknowledged",
                "a success produced after the host cancelled must not settle the row: \
                 outcome={outcome:?}"
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                1,
                "a cancelled attempt must leave one host-owned receipt: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                receipt_outcomes(fixture.journal_path()),
                vec![("cancelled".to_owned(), "unknown".to_owned())],
                "shutdown must be the only durable terminal outcome"
            );
            assert_eq!(
                attempt_refusals(fixture.journal_path()),
                Vec::new(),
                "an answer produced after cancellation must not even be weighed as \
                 delivery evidence"
            );
            // Nothing the provider answered after cancellation was weighed:
            // the lane never classified a refusal of its *reply*, because the
            // reply was never considered. Cancellation is not a provider
            // refusal, so the row is simply handed back.
            let weighed: Vec<_> = fixture
                .journey
                .recent_delivery_refusals()
                .into_iter()
                .filter(|refusal| {
                    matches!(
                        refusal.class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(_)
                            | DeliveryRefusalClassV1::TerminalIdentityMismatch { .. }
                            | DeliveryRefusalClassV1::ReceiptNotAdmissible
                    )
                })
                .collect();
            assert!(
                weighed.is_empty(),
                "the host weighed an answer it had already withdrawn consent for: {weighed:?}"
            );
            wait_for_census(&fixture, baseline).await;
        }

        // ---------------------------------------------------------------------------
        // Replies that do not answer the call they were sent for
        // ---------------------------------------------------------------------------

        /// Two replies that are each well-formed on their own and each wrong about the
        /// call they answer — a terminal attributed to another operation kind, and a
        /// terminal naming an operation id the host never dispatched — settle nothing.
        /// Only the compliant third attempt leaves a receipt.
        ///
        /// Judged by the journal on purpose: a host that accepted either would have
        /// acknowledged the row on the first attempt, and the attempt count is what
        /// makes "refused" distinguishable from "never dispatched". The refusal audit
        /// records each rejected terminal beside its unknown-effect receipt, so a reply
        /// that does not answer the dispatched call is retained as bounded evidence
        /// without being treated as a provider effect.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn replies_that_do_not_answer_the_dispatched_call_settle_nothing() {
            let provider = journey_double(AdversarialScriptV1::then(
                vec![
                    MisbehaviourV1::TerminalForAnotherOperation(ProviderOperation::Recall),
                    MisbehaviourV1::ReplyForForeignOperation,
                ],
                MisbehaviourV1::Compliant,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-malformed",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-malformed", "malformed replies")
                .await;
            fixture.journey.wake_delivery();

            let (_, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert!(
                attempts >= 3,
                "a reply that does not answer the dispatched call must cost an attempt \
                 rather than settling it: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                3,
                "each rejected terminal and the compliant attempt leave bounded evidence: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                attempt_refusals(fixture.journal_path()).len(),
                2,
                "each registry-rejected terminal must leave durable refusal evidence"
            );
            assert_eq!(
                provider.invocation_count(),
                3,
                "each refused reply must have been a real dispatch, not a pre-contact refusal"
            );

            // Both wrongnesses are named exactly, and separately: a terminal
            // attributed to another operation kind, and a terminal naming an
            // operation the host never dispatched.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(
                            FabricError::ResponseOperationKindMismatch {
                                expected: ProviderOperation::Observe,
                                returned: ProviderOperation::Recall,
                            }
                        )
                    )
                },
                "a terminal attributed to the recall operation",
            )
            .await;
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(
                            FabricError::ResponseOperationMismatch { .. }
                        )
                    )
                },
                "a terminal naming an operation the host never dispatched",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }

        /// A success bound to a checkout the host never asked about is forged
        /// provenance, and buys nothing: the row is not acknowledged by it, no
        /// receipt is written under the foreign scope, and the compliant retry
        /// settles the row under the host's own scope.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_terminal_bound_to_a_foreign_scope_settles_nothing_and_the_row_is_redelivered() {
            let provider = journey_double(AdversarialScriptV1::then(
                vec![MisbehaviourV1::TerminalForForeignScope],
                MisbehaviourV1::Compliant,
            ));
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_adversarial_journey(
                &temp,
                "project.adversarial-foreign-scope",
                "profile.adversarial",
                &provider,
                bounded_policy(1_000_000),
            )
            .await;
            let baseline = worker_baseline(&fixture);

            fixture
                .admit("session.adversarial-foreign-scope", "forged scope")
                .await;
            let host_scope = delivery_scope(fixture.journal_path()).expect("delivery scope");
            fixture.journey.wake_delivery();

            let (_, attempts, _) = wait_for_state(&fixture, "acknowledged").await;
            assert!(
                attempts >= 2,
                "a terminal bound to another checkout must have been refused rather than \
                 settled: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                receipt_count(fixture.journal_path()),
                2,
                "the rejected terminal and compliant retry must both leave evidence: {}",
                journal_snapshot(fixture.journal_path())
            );
            assert_eq!(
                delivery_scope(fixture.journal_path()).as_deref(),
                Some(host_scope.as_str()),
                "a provider's terminal moved the row onto the checkout the provider named"
            );
            assert_eq!(
                attempt_refusals(fixture.journal_path()).len(),
                1,
                "the foreign-scope terminal must leave durable refusal evidence"
            );
            assert_eq!(
                provider.invocation_count(),
                2,
                "the forged terminal must have been a real dispatch, not a pre-contact refusal"
            );

            // Refused as forged provenance specifically: the scope digest the
            // terminal claimed is not the one the host asked about.
            wait_for_refusal(
                &fixture,
                |class| {
                    matches!(
                        class,
                        DeliveryRefusalClassV1::ProviderReplyRefused(
                            FabricError::ResponseScopeMismatch { .. }
                        )
                    )
                },
                "a terminal bound to a checkout the host never asked about",
            )
            .await;
            every_refusal_is_classified(&fixture);

            let failures = shutdown_within(&fixture.journey, Duration::from_secs(5)).await;
            assert!(failures.is_empty(), "{failures:?}");
            wait_for_census(&fixture, baseline).await;
        }
    }

    #[derive(Clone)]
    struct DeliveredObservation {
        bytes: Vec<u8>,
        exact_scope: OwnedExactScope,
    }

    type HealthHook = dyn Fn(&ProviderCall) -> ProviderReply + Send + Sync;

    struct JourneyObservationProvider {
        descriptor: ProviderDescriptor,
        observe_calls: AtomicUsize,
        delivered: Mutex<Vec<DeliveredObservation>>,
        handshake_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        observe_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        health_hook: Mutex<Option<Box<HealthHook>>>,
    }

    impl JourneyObservationProvider {
        fn new() -> Self {
            Self::with_state_generation(0)
        }

        /// An incarnation reporting `state_generation`.
        ///
        /// A non-zero generation is what makes "the verified generation
        /// reached the provider call" checkable: the fabric refuses a call
        /// whose `expected_state_generation` is not this incarnation's own, so
        /// a hardcoded expectation cannot reach a settlement.
        fn with_state_generation(state_generation: u64) -> Self {
            let capabilities = BTreeSet::from([
                OwnedVersionedId::new("provider.health.v1").expect("health capability"),
                OwnedVersionedId::new("observation.accept.v1").expect("observe capability"),
                OwnedVersionedId::new("recall.query.v1").expect("recall capability"),
            ]);
            let descriptor = ProviderDescriptor::new(
                OwnedProviderId::new(JOURNEY_PROVIDER_ID).expect("journey provider"),
                "0".repeat(64),
                "journey-test-v1",
                state_generation,
                capabilities,
                super::super::native_provider::native_provider_limits(),
            )
            .expect("provider descriptor");
            Self {
                descriptor,
                observe_calls: AtomicUsize::new(0),
                delivered: Mutex::new(Vec::new()),
                handshake_hook: Mutex::new(None),
                observe_hook: Mutex::new(None),
                health_hook: Mutex::new(None),
            }
        }

        /// Runs `hook` on every readiness handshake. Admission proves
        /// readiness for each record's own session scope, so this is the one
        /// point inside record admission a test can act from.
        fn on_handshake(&self, hook: impl Fn() + Send + Sync + 'static) {
            *self.handshake_hook.lock().unwrap() = Some(Box::new(hook));
        }

        /// Holds a provider observation call at the target namespace boundary.
        /// The publication-barrier regression uses this to distinguish a
        /// journal append from the provider's durable effect.
        fn on_observe(&self, hook: impl Fn() + Send + Sync + 'static) {
            *self.observe_hook.lock().unwrap() = Some(Box::new(hook));
        }

        /// Holds or answers a control through the same mounted provider port.
        fn on_health(&self, hook: impl Fn(&ProviderCall) -> ProviderReply + Send + Sync + 'static) {
            *self.health_hook.lock().unwrap() = Some(Box::new(hook));
        }

        fn observe(&self, call: &ProviderCall) -> ProviderReply {
            self.observe_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(hook) = self.observe_hook.lock().unwrap().as_ref() {
                hook();
            }
            self.delivered.lock().unwrap().push(DeliveredObservation {
                bytes: call.payload.bytes.clone(),
                exact_scope: call.exact_scope.clone(),
            });
            // The descriptor is fixed for this incarnation. Reporting an advance
            // would become a regression at the next readiness handshake.
            ProviderReply {
                terminal: TerminalRecord::new(
                    ProviderOperation::Observe,
                    call.provider_id.clone(),
                    TerminalCode::Success,
                    CommittedEffectEvidence::committed(
                        call.expected_state_generation,
                        call.expected_state_generation,
                        vec!["observation:journey-test".to_owned()],
                        PROVIDER_RECEIPT,
                        EFFECT_DIGEST,
                    )
                    .expect("committed effect"),
                    FallbackDirective::forbidden(),
                    call.operation_id.clone(),
                    call.exact_scope.exact_scope_sha256(),
                    None,
                )
                .expect("observation terminal"),
                payload: Some(call.payload.clone()),
                warnings: Vec::new(),
                extensions: call.extensions.clone(),
                state_generation: call.expected_state_generation,
            }
        }

        fn unexpected<T>() -> T {
            panic!("journey test reached an unrelated provider operation")
        }
    }

    impl MemoryProviderV1 for JourneyObservationProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor.clone()
        }

        fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
            if let Some(hook) = self.handshake_hook.lock().unwrap().as_ref() {
                hook();
            }
            HandshakeResponse {
                terminal: TerminalRecord::new(
                    ProviderOperation::Handshake,
                    request.provider_id.clone(),
                    TerminalCode::Success,
                    CommittedEffectEvidence::none(Some(self.descriptor.state_generation)),
                    FallbackDirective::forbidden(),
                    request.request_id.clone(),
                    request.exact_scope.exact_scope_sha256(),
                    None,
                )
                .expect("handshake terminal"),
                descriptor: Some(self.descriptor.clone()),
                provider_instance_id: Some(JOURNEY_PROVIDER_INSTANCE_ID.to_owned()),
                // Inside the namespace the mount admits for the observer
                // provider; a namespace outside it is a readiness refusal.
                state_namespace: Some("tracedecay.journey-fixture.journey-test".to_owned()),
                accepted_scope: Some(request.exact_scope.clone()),
                effective_limits: Some(request.host_limits.minimum(self.descriptor.limits)),
                ready_receipt_sha256: Some(READY_RECEIPT.to_owned()),
                warnings: Vec::new(),
            }
        }

        fn invoke(&self, call: &ProviderCall) -> ProviderReply {
            match call.operation {
                ProviderOperation::Observe => self.observe(call),
                ProviderOperation::Health => match self.health_hook.lock().unwrap().as_ref() {
                    Some(hook) => hook(call),
                    None => Self::unexpected(),
                },
                _ => Self::unexpected(),
            }
        }
    }

    fn scope(project_id: ProjectId) -> ResolvedScope {
        ResolvedScope::new(
            project_id,
            RepositoryId::new("repository.observation-journey").expect("repository"),
            WorktreeId::new("worktree.observation-journey").expect("worktree"),
            Some(RefId::new("refs/heads/observation-journey").expect("reference")),
        )
        .expect("resolved scope")
    }

    fn canonical_observation(
        project_id: &ProjectId,
        session_id: &SessionId,
        text: &str,
    ) -> DurableObservationV1 {
        canonical_observation_at(project_id, session_id, text, 0)
    }

    /// The native record identity of the `position`-th settled record of one
    /// session. Position zero keeps the plain name so existing rows and
    /// snapshots read the same.
    fn record_id_at(session_id: &SessionId, position: u64) -> ObservationId {
        let name = if position == 0 {
            format!("record.{}", session_id.as_str())
        } else {
            format!("record.{}.{position}", session_id.as_str())
        };
        ObservationId::new(name).expect("record id")
    }

    /// The receipt name for the `position`-th settled record of one session,
    /// with the same position-zero shape as [`record_id_at`].
    fn receipt_name_at(session_id: &SessionId, position: u64) -> String {
        if position == 0 {
            format!("receipt.{}", session_id.as_str())
        } else {
            format!("receipt.{}.{position}", session_id.as_str())
        }
    }

    /// Like [`canonical_observation`], but as the `position`-th record of the
    /// session: a *different* settled event under the same exact session
    /// scope, which is what a source position conflict needs.
    fn canonical_observation_at(
        project_id: &ProjectId,
        session_id: &SessionId,
        text: &str,
        position: u64,
    ) -> DurableObservationV1 {
        let provider = ProviderId::new("claude").expect("provider");
        let range = ObservationSourceRangeV1::new(position, position + 1).expect("range");
        let record_id = record_id_at(session_id, position);
        let envelope = CanonicalObservationEnvelopeV1::new(
            provider,
            "message",
            record_id,
            CanonicalObservationRelationsV1::new(session_id.clone()),
            vec![CanonicalObservationFactV1::Message {
                role: CanonicalMessageRoleV1::Assistant,
                content: json!({"text": text}),
                model: Some("model.fixture".to_owned()),
                timestamp: Some(1_750_000_000),
            }],
            CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::SnapshotOrder, range),
        )
        .expect("canonical envelope");
        let payload = serde_json::to_value(envelope).expect("canonical payload");
        canonical_observation_with_payload_at(project_id, session_id, payload, position)
    }

    /// Settles `payload` as the durable record for `session_id` the way the
    /// store API does: identity, receipt, and payload reference are bound to
    /// exactly these bytes, whatever their shape. The canonical envelope
    /// validator is not consulted here, which is how a row persisted under a
    /// different contract revision looks to the journey.
    fn canonical_observation_with_payload(
        project_id: &ProjectId,
        session_id: &SessionId,
        payload: Value,
    ) -> DurableObservationV1 {
        canonical_observation_with_payload_at(project_id, session_id, payload, 0)
    }

    fn canonical_observation_with_payload_at(
        project_id: &ProjectId,
        session_id: &SessionId,
        payload: Value,
        position: u64,
    ) -> DurableObservationV1 {
        let provider = ProviderId::new("claude").expect("provider");
        let source = ObservationSourceIdentityV1::for_provider(provider, session_id.clone())
            .expect("source");
        let generation = ObservationSourceGenerationV1::new(1).expect("generation");
        let range = ObservationSourceRangeV1::new(position, position + 1).expect("range");
        let record_id = record_id_at(session_id, position);
        let identity = ObservationIdentityMaterialV1::for_native_record(
            source,
            ObservationScopeV1::Project {
                project_id: project_id.clone(),
            },
            generation,
            range,
            ObservationOrderingDomainV1::SnapshotOrder,
            record_id,
        )
        .expect("observation identity");
        let receipt = SanitizationReceiptV1::new(
            SanitizationReceiptRefV1::new(
                SanitizationReceiptId::new(receipt_name_at(session_id, position))
                    .expect("receipt id"),
                ComponentVersion::new("sanitizer.observation-journey-test.v1")
                    .expect("sanitizer version"),
            )
            .expect("receipt reference"),
            SanitizerDispositionV1::Accepted,
            SensitivityV1::NonSensitive,
            Some(PayloadReferenceV1::for_payload(&payload).expect("payload reference")),
        )
        .expect("sanitization receipt");
        DurableObservationV1::new(
            identity,
            receipt,
            RetentionClass::new("retention.observation-journey-test").expect("retention"),
            payload,
        )
        .expect("durable observation")
    }

    fn anchored_write(observation: DurableObservationV1) -> AnchoredObservationWrite {
        let identity = observation.identity();
        let next_cursor = ObservationSourceCursorV1::for_ordering(
            observation.source().clone(),
            observation.scope().clone(),
            identity.generation(),
            identity.ordering_domain(),
            identity.position().end(),
        )
        .expect("next cursor");
        let write = ObservationWrite::new(observation, None, next_cursor).expect("write");
        let projection_generation =
            ProjectionGenerationId::new("projection.observation-journey-test.v1")
                .expect("projection generation");
        let authorization = build_observation_resolution_authorization_v1(
            write.observation(),
            "observation-journey-test",
        )
        .expect("resolution authorization");
        let anchor = build_observation_retrieval_anchor(
            write.observation(),
            projection_generation.clone(),
            UtcMicros(1_750_000_000_000_000),
            authorization,
        )
        .expect("retrieval anchor");
        AnchoredObservationWrite::new(write, anchor, projection_generation).expect("anchored write")
    }

    /// Builds the committed shape of `observation` at `sequence` the way the
    /// canonical store commits it, without going through the store's write
    /// boundary.
    fn settled_record(sequence: u64, observation: DurableObservationV1) -> StoredObservation {
        let identity = observation.identity();
        let committed_cursor = ObservationSourceCursorV1::for_ordering(
            observation.source().clone(),
            observation.scope().clone(),
            identity.generation(),
            identity.ordering_domain(),
            identity.position().end(),
        )
        .expect("committed cursor");
        let projection_generation =
            ProjectionGenerationId::new("projection.observation-journey-test.v1")
                .expect("projection generation");
        let authorization =
            build_observation_resolution_authorization_v1(&observation, "observation-journey-test")
                .expect("resolution authorization");
        let anchor = build_observation_retrieval_anchor(
            &observation,
            projection_generation.clone(),
            UtcMicros(1_750_000_000_000_000),
            authorization,
        )
        .expect("retrieval anchor");
        StoredObservation::new(
            sequence,
            observation,
            committed_cursor,
            anchor,
            projection_generation,
            tracedecay_store::ObservationProjectionStatus::NotQueued,
        )
        .expect("settled record")
    }

    fn read_only_observation_store_error(operation: &'static str) -> ObservationStoreError {
        ObservationStoreError::Storage {
            operation,
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "settled replay fixture is read-only",
            )),
        }
    }

    /// Replay port over records already settled elsewhere. It stands in for
    /// the canonical store only where the store's own write boundary cannot
    /// produce the row under test; the journey reads it through the same
    /// trait it reads the store through.
    struct SettledRecordsPort {
        records: Vec<StoredObservation>,
    }

    impl SettledRecordsPort {
        fn single(record: StoredObservation) -> Self {
            Self {
                records: vec![record],
            }
        }
    }

    impl ObservationStore for SettledRecordsPort {
        fn persist_observation(
            &self,
            _write: AnchoredObservationWrite,
        ) -> impl std::future::Future<Output = ObservationStoreResult<ObservationPersistOutcome>> + Send
        {
            async move { Err(read_only_observation_store_error("persist_observation")) }
        }

        fn persist_observations(
            &self,
            _writes: Vec<AnchoredObservationWrite>,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Vec<ObservationBatchPersistOutcome>>,
        > + Send {
            async move { Err(read_only_observation_store_error("persist_observations")) }
        }

        fn get_source_cursor(
            &self,
            _source: &ObservationSourceIdentityV1,
            _scope: &ObservationScopeV1,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Option<ObservationSourceCursorV1>>,
        > + Send {
            async move { Err(read_only_observation_store_error("get_source_cursor")) }
        }

        fn committed_source_cursors(
            &self,
            _source: &ObservationSourceIdentityV1,
            _scope: &ObservationScopeV1,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Vec<ObservationSourceCursorV1>>,
        > + Send {
            async move {
                Err(read_only_observation_store_error(
                    "committed_source_cursors",
                ))
            }
        }

        fn advance_source_cursor(
            &self,
            _advance: ObservationCursorAdvance,
        ) -> impl std::future::Future<Output = ObservationStoreResult<CursorAdvanceOutcome>> + Send
        {
            async move { Err(read_only_observation_store_error("advance_source_cursor")) }
        }

        fn get_observation(
            &self,
            observation_id: &CanonicalObservationIdV1,
        ) -> impl std::future::Future<
            Output = Result<Option<StoredObservation>, ObservationStoreError>,
        > + Send {
            async move {
                Ok(self
                    .records
                    .iter()
                    .find(|record| record.observation().observation_id() == observation_id)
                    .cloned())
            }
        }

        fn replay_observations(
            &self,
            request: ObservationReplayRequest,
        ) -> impl std::future::Future<
            Output = Result<Vec<StoredObservation>, ObservationStoreError>,
        > + Send {
            async move {
                Ok(self
                    .records
                    .iter()
                    .filter(|record| record.sequence() > request.after_sequence())
                    .take(request.limit())
                    .cloned()
                    .collect())
            }
        }
    }

    static NEVER_CANCELLED: LazyLock<HostCancellationToken> =
        LazyLock::new(HostCancellationToken::new);

    /// Bounds no test pass reaches: replay here is bounded by its page count.
    fn open_bounds() -> ReplayBoundsV1<'static> {
        ReplayBoundsV1 {
            cancellation: LazyLock::force(&NEVER_CANCELLED),
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        }
    }

    /// Replay port that re-presents the same settled records on every pass
    /// and counts the passes, so a test can see whether the live replay task
    /// backs off or spins.
    struct CountingReplayPort {
        inner: SettledRecordsPort,
        passes: Arc<AtomicUsize>,
    }

    impl ObservationStore for CountingReplayPort {
        async fn persist_observation(
            &self,
            write: AnchoredObservationWrite,
        ) -> ObservationStoreResult<ObservationPersistOutcome> {
            self.inner.persist_observation(write).await
        }

        async fn persist_observations(
            &self,
            writes: Vec<AnchoredObservationWrite>,
        ) -> ObservationStoreResult<Vec<ObservationBatchPersistOutcome>> {
            self.inner.persist_observations(writes).await
        }

        async fn get_source_cursor(
            &self,
            source: &ObservationSourceIdentityV1,
            scope: &ObservationScopeV1,
        ) -> ObservationStoreResult<Option<ObservationSourceCursorV1>> {
            self.inner.get_source_cursor(source, scope).await
        }

        async fn committed_source_cursors(
            &self,
            source: &ObservationSourceIdentityV1,
            scope: &ObservationScopeV1,
        ) -> ObservationStoreResult<Vec<ObservationSourceCursorV1>> {
            self.inner.committed_source_cursors(source, scope).await
        }

        async fn advance_source_cursor(
            &self,
            advance: ObservationCursorAdvance,
        ) -> ObservationStoreResult<CursorAdvanceOutcome> {
            self.inner.advance_source_cursor(advance).await
        }

        async fn get_observation(
            &self,
            observation_id: &CanonicalObservationIdV1,
        ) -> Result<Option<StoredObservation>, ObservationStoreError> {
            self.inner.get_observation(observation_id).await
        }

        async fn replay_observations(
            &self,
            request: ObservationReplayRequest,
        ) -> Result<Vec<StoredObservation>, ObservationStoreError> {
            self.passes.fetch_add(1, Ordering::Relaxed);
            self.inner.replay_observations(request).await
        }
    }

    fn composition(port: Arc<dyn MemoryProviderV1>) -> Arc<ProjectMemoryProviderComposition> {
        Arc::new(
            ProjectMemoryProviderComposition::compose_selected(
                SelectedProviderActivationV1::ObserversOnly {
                    fabric_config: FabricConfig {
                        max_registered_providers: 1,
                        max_in_flight: 1,
                    },
                },
                vec![ObserverProviderRegistration {
                    provider: port,
                    registration_revision: 1,
                }],
            )
            .expect("provider composition"),
        )
    }

    fn test_observation_mount(
        data_root: &Path,
        registration_revision: u64,
    ) -> Result<ObservationProviderMountV1, ApiError> {
        Ok(ObservationProviderMountV1 {
            provider_id: OwnedProviderId::new(JOURNEY_PROVIDER_ID)?,
            registration_revision,
            provider_instance_id: Some(JOURNEY_PROVIDER_INSTANCE_ID.to_owned()),
            instance_proof: None,
            host_limits: super::super::native_provider::native_provider_limits(),
            state_root: data_root.join(PROVIDER_STATE_DIR_NAME),
            journal_file_name: JOURNAL_FILE_NAME,
            state_namespace_policy: ObservationStateNamespacePolicyV1::Prefix(
                JOURNEY_PROVIDER_ID.to_owned(),
            ),
        })
    }

    /// Diagnostic snapshot of the journal so a failed wait explains itself
    /// instead of reporting only a deadline.
    fn journal_snapshot(path: &Path) -> String {
        let connection = rusqlite::Connection::open(path).expect("journal connection");
        let count = |table: &str| -> i64 {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or(-1)
        };
        let mut deliveries = String::new();
        if let Ok(mut statement) = connection.prepare(
            "SELECT observation_id, state, attempt_number, last_outcome FROM tdmem_observation_delivery_v1",
        ) {
            let rows = statement
                .query_map([], |row| {
                    Ok(format!(
                        "{}:{}:{}:{}",
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2).unwrap_or(-1),
                        row.get::<_, Option<String>>(3)?.unwrap_or_default()
                    ))
                })
                .map(|rows| rows.flatten().collect::<Vec<_>>())
                .unwrap_or_default();
            deliveries = rows.join(" | ");
        }
        format!(
            "journal={} delivery={} withheld={} receipts={} cursors={} deliveries=[{}]",
            count("tdmem_observation_journal_v1"),
            count("tdmem_observation_delivery_v1"),
            count("tdmem_observation_withheld_v2"),
            count("tdmem_observation_receipt_v1"),
            count("tdmem_observation_replay_cursor_v1"),
            deliveries
        )
    }

    /// Waits until the single delivery row leaves `pending`/`leased` and
    /// returns its settled state and attempt count.
    async fn wait_for_settlement(journal_path: &Path) -> (String, i64) {
        wait_for_settlement_within(journal_path, Duration::from_secs(5)).await
    }

    /// The same wait with the caller's own budget, for a journey whose next
    /// replay pass is deliberately behind a backoff interval.
    async fn wait_for_settlement_within(journal_path: &Path, budget: Duration) -> (String, i64) {
        let settled = tokio::time::timeout(budget, async {
            loop {
                let connection = rusqlite::Connection::open(journal_path).expect("journal");
                let row = connection
                    .query_row(
                        "SELECT state, attempt_number FROM tdmem_observation_delivery_v1",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .ok();
                match row {
                    Some((state, attempts)) if state != "pending" && state != "leased" => {
                        return (state, attempts);
                    }
                    _ => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await;
        match settled {
            Ok(settled) => settled,
            Err(error) => panic!(
                "observation delivery never settled: {error}; {}",
                journal_snapshot(journal_path)
            ),
        }
    }

    /// Mounts the retained journey constructor and delivery worker over one
    /// caller-supplied observer incarnation.
    ///
    /// Restart-recovery tests need to move the provider state identity the
    /// journal compares against, which means owning the port the mount runs
    /// over.
    struct RecoveryJourneyFixture {
        _runtime: HostAdmissionTestRuntimeV1,
        store: GlobalDbObservationStore,
        journey: Arc<ProjectObservationJourneyV1>,
        project_id: ProjectId,
        profile_id: UserProfileId,
        resolved_scope: ResolvedScope,
    }

    async fn mount_journey_over_port(
        temp: &TempDir,
        project: &str,
        profile: &str,
        port: Arc<JourneyObservationProvider>,
    ) -> RecoveryJourneyFixture {
        let project_id = ProjectId::new(project).expect("project id");
        let runtime = HostAdmissionTestRuntimeV1::project(
            &temp.path().join("profile"),
            &temp.path().join("project"),
            project_id.clone(),
        )
        .await
        .expect("registered project database");
        let store = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .expect("project database")
            .observation_store();
        let profile_id = UserProfileId::new(profile).expect("profile id");
        let resolved_scope = scope(project_id.clone());
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).expect("journal root");
        let journey = mount_project_observation_journey(ObservationJourneyMountInputsV1 {
            composition: composition(port),
            profile_id: profile_id.clone(),
            scope: resolved_scope.clone(),
            authoritative_project_id: project_id.clone(),
            provider: test_observation_mount(&(journal_root), 1).expect("observer mount metadata"),
            store_data_root: journal_root,
            policy: ObservationJourneyPolicyV1::project_default(),
        })
        .expect("mounted journey");
        RecoveryJourneyFixture {
            _runtime: runtime,
            store,
            journey,
            project_id,
            profile_id,
            resolved_scope,
        }
    }

    /// One row of the mounted journey's durable recovery record.
    fn recovery_row(journal_path: &Path) -> Option<(String, i64, i64, Option<String>)> {
        let connection = rusqlite::Connection::open(journal_path).expect("journal");
        connection
            .query_row(
                "SELECT implementation_identity_sha256, state_generation, \
                 automatic_repair_attempts, last_defect \
                 FROM tdmem_observation_recovery_v1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .ok()
    }

    fn journal_counts(journal_path: &Path) -> (i64, String) {
        let connection = rusqlite::Connection::open(journal_path).expect("journal");
        let receipts: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tdmem_observation_receipt_v1",
                [],
                |row| row.get(0),
            )
            .expect("receipt count");
        let state: String = connection
            .query_row(
                "SELECT state FROM tdmem_observation_delivery_v1",
                [],
                |row| row.get(0),
            )
            .expect("delivery state");
        (receipts, state)
    }

    /// Mounted restart recovery. The generation a delivery call declares is the one
    /// restart recovery verified against this incarnation's own readiness
    /// evidence, and the gate's decision is written through the journey's real
    /// journal.
    ///
    /// The fabric refuses any call whose `expected_state_generation` is not the
    /// ready incarnation's, so a hardcoded expectation never reaches a
    /// settlement at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mounted_delivery_declares_the_state_generation_recovery_verified() {
        let temp = TempDir::new().expect("temporary journey root");
        let port = Arc::new(JourneyObservationProvider::with_state_generation(5));
        let fixture = mount_journey_over_port(
            &temp,
            "project.observation-recovery-generation",
            "profile.observation-recovery",
            Arc::clone(&port),
        )
        .await;
        let store = &fixture.store;
        let journey = &fixture.journey;
        let project_id = &fixture.project_id;

        let session_id = SessionId::new("session.observation-recovery").expect("session id");
        store
            .persist_observation(anchored_write(canonical_observation(
                project_id,
                &session_id,
                "recovery journey text",
            )))
            .await
            .expect("canonical observation commit");
        let admitted = journey
            .replay_canonical_observations(store, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("canonical replay")
            .admitted;
        assert!(admitted <= 1, "unexpected admitted count {admitted}");

        journey.wake_delivery();
        let (state, attempts) = wait_for_settlement(journey.journal_path()).await;
        assert_eq!(
            (state.as_str(), attempts),
            ("acknowledged", 1),
            "delivery never reached the provider under the verified generation: {}",
            journal_snapshot(journey.journal_path())
        );

        let (identity, generation, repair_attempts, defect) =
            recovery_row(journey.journal_path()).expect("recovery record written by the gate");
        assert_eq!(identity, "0".repeat(64));
        assert_eq!(
            generation, 5,
            "the gate accepted a generation that is not this incarnation's"
        );
        assert_eq!(repair_attempts, 0);
        assert_eq!(defect, None);

        let failures = journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Shutdown that becomes visible while supervised readiness is still
    /// waiting owns the attempt. It leaves one cancellation receipt, never
    /// reaches `observe`, and keeps the row deliverable for the next process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_delivery_readiness_records_cancellation_receipt() {
        use tracedecay_memory_conformance::ReleaseLatchV1;

        let temp = TempDir::new().expect("temporary journey root");
        let port = Arc::new(JourneyObservationProvider::new());
        let fixture = mount_journey_over_port(
            &temp,
            "project.observation-readiness-cancellation",
            "profile.observation-readiness-cancellation",
            Arc::clone(&port),
        )
        .await;
        let session_id =
            SessionId::new("session.observation-readiness-cancellation").expect("session id");
        fixture
            .store
            .persist_observation(anchored_write(canonical_observation(
                &fixture.project_id,
                &session_id,
                "cancel readiness",
            )))
            .await
            .expect("canonical observation commit");
        // Admission and delivery share the same port hook. Install the gate
        // before replay so the worker cannot win the gap between the admission
        // handshake and a later hook installation: the first call is admission
        // and passes; the second is delivery readiness and is held.
        let held = ReleaseLatchV1::new();
        let entered = ReleaseLatchV1::new();
        let handshake_calls = Arc::new(AtomicUsize::new(0));
        let blocked = held.clone();
        let announced = entered.clone();
        let calls = Arc::clone(&handshake_calls);
        port.on_handshake(move || {
            if calls.fetch_add(1, Ordering::AcqRel) > 0 {
                announced.release();
                blocked.wait();
            }
        });
        fixture
            .journey
            .replay_canonical_observations(&fixture.store, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("canonical replay");
        fixture.journey.wake_delivery();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || entered.wait()),
        )
        .await
        .expect("delivery never entered readiness")
        .expect("readiness entry waiter");

        // Let the non-cooperative handshake answer only after shutdown has
        // become visible. The bounded readiness boundary must discard that
        // late answer and return cancellation to the delivery runtime.
        let release_after_shutdown = held.clone();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            release_after_shutdown.release();
        });
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        release.join().expect("readiness release thread");
        assert!(failures.is_empty(), "{failures:?}");
        let (receipts, state) = journal_counts(fixture.journey.journal_path());
        assert_eq!(
            receipts,
            1,
            "{}",
            journal_snapshot(fixture.journey.journal_path())
        );
        assert_eq!(
            state,
            "pending",
            "{}",
            journal_snapshot(fixture.journey.journal_path())
        );
        let receipt_outcome: (String, String) =
            rusqlite::Connection::open(fixture.journey.journal_path())
                .expect("journal")
                .query_row(
                    "SELECT outcome, committed_effect FROM tdmem_observation_receipt_v1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("cancellation receipt");
        assert_eq!(
            receipt_outcome,
            ("cancelled".to_owned(), "unknown".to_owned())
        );
        assert_eq!(
            port.observe_calls.load(Ordering::Relaxed),
            0,
            "shutdown during readiness reached the provider observation call"
        );
    }

    /// Mounted restart recovery. A durable recovery record naming a different
    /// implementation identity refuses delivery *before* the provider is
    /// called: no receipt, no settlement, the row still deliverable, and the
    /// refusal recorded once however many times the dispatcher retries it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_moved_provider_identity_refuses_mounted_delivery_before_the_provider_call() {
        let temp = TempDir::new().expect("temporary journey root");
        let port = Arc::new(JourneyObservationProvider::with_state_generation(5));
        let fixture = mount_journey_over_port(
            &temp,
            "project.observation-recovery-identity",
            "profile.observation-recovery",
            Arc::clone(&port),
        )
        .await;
        let store = &fixture.store;
        let journey = &fixture.journey;
        let project_id = &fixture.project_id;
        let profile_id = &fixture.profile_id;
        let resolved_scope = &fixture.resolved_scope;

        // A previous life of this host converged with a *different*
        // implementation under the same pinned registration. Nothing about the
        // schema or the generation moved, so only the identity comparison can
        // catch it.
        let session_id = SessionId::new("session.observation-recovery").expect("session id");
        let exact_scope = exact_scope_for_session(profile_id, resolved_scope, session_id.as_str())
            .expect("exact scope");
        {
            let connection = rusqlite::Connection::open(journey.journal_path()).expect("journal");
            connection
                .execute(
                    "INSERT INTO tdmem_observation_recovery_v1 (\
                         provider_id, registration_revision, source_authority, \
                         exact_scope_sha256, source_stream, implementation_identity_sha256, \
                         state_schema_version, state_generation, replay_position_retained, \
                         automatic_repair_attempts, updated_at_micros) \
                     VALUES (?1, 1, 'host_session', ?2, ?3, ?4, 'journey-test-v1', 5, 0, 0, 1)",
                    rusqlite::params![
                        JOURNEY_PROVIDER_ID,
                        exact_scope.exact_scope_sha256(),
                        SESSION_SOURCE_STREAM,
                        "1".repeat(64),
                    ],
                )
                .expect("seeded recovery record");
        }

        store
            .persist_observation(anchored_write(canonical_observation(
                project_id,
                &session_id,
                "recovery journey text",
            )))
            .await
            .expect("canonical observation commit");
        let admitted = journey
            .replay_canonical_observations(store, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("canonical replay")
            .admitted;
        assert!(admitted <= 1, "unexpected admitted count {admitted}");

        journey.wake_delivery();
        let refused = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some((_, _, attempts, Some(defect))) = recovery_row(journey.journal_path()) {
                    return (attempts, defect);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        let (attempts, defect) = match refused {
            Ok(refused) => refused,
            Err(error) => panic!(
                "the mounted recovery gate never refused: {error}; {}",
                journal_snapshot(journey.journal_path())
            ),
        };
        assert_eq!(defect, "implementation_identity_changed");
        assert_eq!(
            attempts, 1,
            "one incarnation is one assessment however often the dispatcher retries it"
        );

        // The provider was never asked: no receipt exists, and the row is
        // still deliverable rather than settled.
        let (receipts, state) = journal_counts(journey.journal_path());
        assert_eq!(receipts, 0, "a refused recovery must produce no receipt");
        assert!(
            state == "pending" || state == "leased",
            "a refused recovery must leave the row deliverable, found {state}"
        );
        assert_eq!(port.observe_calls.load(Ordering::Relaxed), 0);

        let failures = journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Reads every on-disk byte of the journal, including a WAL segment that
    /// has not been checkpointed, so a secret cannot hide in the write-ahead
    /// log while the main file looks clean.
    fn journal_files_contain(journal_path: &Path, needle: &[u8]) -> bool {
        assert!(!needle.is_empty(), "an empty needle proves nothing");
        // The main file must exist, or the scan is vacuous; the WAL and the
        // shared-memory index are optional side files.
        let main = std::fs::read(journal_path).expect("journal main file readable");
        let side = ["-wal", "-shm"].into_iter().filter_map(|suffix| {
            let mut path = journal_path.as_os_str().to_owned();
            path.push(suffix);
            std::fs::read(PathBuf::from(path)).ok()
        });
        std::iter::once(main)
            .chain(side)
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    }

    struct HygieneJourneyFixture {
        _runtime: HostAdmissionTestRuntimeV1,
        store: GlobalDbObservationStore,
        port: Arc<JourneyObservationProvider>,
        journey: Arc<ProjectObservationJourneyV1>,
        project_id: ProjectId,
        /// The journal root this fixture's journey was mounted over, so a test
        /// can mount a *later open* of the same project over the same durable
        /// state.
        journal_root: PathBuf,
    }

    impl HygieneJourneyFixture {
        /// Mounts a second, independent journey over this fixture's durable
        /// journal — a genuinely later open of the same project.
        ///
        /// Project open is what constructs a journey: `mount_and_replay`
        /// mounts one, replays into it, and drops it when the open fails. A
        /// test that re-runs startup replay against the *same* journey is
        /// therefore not testing a later open at all; it is testing a second
        /// pass inside the same one, which shares that mount's live provider
        /// supervisor and its enforced restart pacing. The only durable thing
        /// a later open inherits is the journal, and that is exactly what this
        /// hands it.
        fn reopen(&self) -> Arc<ProjectObservationJourneyV1> {
            mount_project_observation_journey(ObservationJourneyMountInputsV1 {
                composition: composition(Arc::clone(&self.port) as Arc<dyn MemoryProviderV1>),
                profile_id: UserProfileId::new("profile.observation-hygiene").expect("profile id"),
                scope: scope(self.project_id.clone()),
                authoritative_project_id: self.project_id.clone(),
                provider: test_observation_mount(&(self.journal_root.clone()), 1)
                    .expect("observer mount metadata"),
                store_data_root: self.journal_root.clone(),
                policy: ObservationJourneyPolicyV1::project_default(),
            })
            .expect("a later open mounts over the same durable journal")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_message_checkpoint_survives_reopen_and_mixed_batch_delivers_only_messages() {
        let temp = TempDir::new().unwrap();
        let fixture = mount_hygiene_fixture(&temp, "project.non-message").await;
        let session = SessionId::new("session.non-message").unwrap();
        let mut metadata = canonical_observation(&fixture.project_id, &session, "unused")
            .payload()
            .clone();
        metadata["native_record_kind"] = json!("session_meta");
        metadata["facts"] = json!([{"kind":"boundary", "boundary_kind":"session_start"}]);
        let observation =
            canonical_observation_with_payload(&fixture.project_id, &session, metadata.clone());
        let records = SettledRecordsPort::single(settled_record(1, observation));
        let pass = run_startup_replay(
            fixture.journey.as_ref(),
            &records,
            &HostCancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(pass.admitted, 0);
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);
        let connection = rusqlite::Connection::open(fixture.journey.journal_path()).unwrap();
        let disposition: String = connection
            .query_row(
                "SELECT last_disposition FROM tdmem_observation_replay_cursor_v1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(disposition, "non_message");
        assert_eq!(records.records[0].observation().payload(), &metadata);
        assert!(
            journal_snapshot(fixture.journey.journal_path())
                .starts_with("journal=0 delivery=0 withheld=0 receipts=0 cursors=1 ")
        );
        fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        let reopened = fixture.reopen();
        assert_eq!(
            run_startup_replay(reopened.as_ref(), &records, &HostCancellationToken::new())
                .await
                .unwrap()
                .admitted,
            0
        );
        let mut mixed = records.records.clone();
        for position in 1..=2 {
            let mut payload = canonical_observation_at(
                &fixture.project_id,
                &session,
                "eligible message",
                position,
            )
            .payload()
            .clone();
            payload["facts"]
                .as_array_mut()
                .unwrap()
                .push(json!({"kind":"boundary", "boundary_kind":"session_start"}));
            mixed.push(settled_record(
                position + 1,
                canonical_observation_with_payload_at(
                    &fixture.project_id,
                    &session,
                    payload,
                    position,
                ),
            ));
        }
        let records = SettledRecordsPort { records: mixed };
        assert_eq!(
            run_startup_replay(reopened.as_ref(), &records, &HostCancellationToken::new())
                .await
                .unwrap()
                .admitted,
            2
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if fixture.port.delivered.lock().unwrap().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 2);
        let expected_scope = exact_scope_for_session(
            &UserProfileId::new("profile.observation-hygiene").unwrap(),
            &scope(fixture.project_id.clone()),
            session.as_str(),
        )
        .unwrap();
        for delivered in fixture.port.delivered.lock().unwrap().iter() {
            assert_eq!(delivered.exact_scope, expected_scope);
            let payload: Value = serde_json::from_slice(&delivered.bytes).unwrap();
            // Only message facts enter the provider copy, including mixed-fact records.
            let text = serde_json::to_string(&payload).unwrap();
            assert!(!text.contains("session_start"));
        }
        assert_eq!(
            records.records[1].observation().payload()["facts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        reopened
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn corrupt_canonical_metadata_refuses_without_checkpoint() {
        let temp = TempDir::new().unwrap();
        let fixture = mount_hygiene_fixture(&temp, "project.corrupt-metadata").await;
        let session = SessionId::new("session.corrupt-metadata").unwrap();
        let mut payload = canonical_observation(&fixture.project_id, &session, "unused")
            .payload()
            .clone();
        payload["version"] = json!(999);
        let records = SettledRecordsPort::single(settled_record(
            1,
            canonical_observation_with_payload(&fixture.project_id, &session, payload),
        ));
        assert!(
            run_startup_replay(
                fixture.journey.as_ref(),
                &records,
                &HostCancellationToken::new()
            )
            .await
            .is_err()
        );
        assert!(
            journal_snapshot(fixture.journey.journal_path())
                .starts_with("journal=0 delivery=0 withheld=0 receipts=0 cursors=0 ")
        );
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);
        fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
    }

    /// A required provider's publication barrier waits for the target
    /// namespace effect, rather than treating the journal append as if the
    /// provider had already observed it. This is the race that can otherwise
    /// turn an immediate post-publication recall into a valid empty answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publication_barrier_waits_for_provider_delivery_after_startup_replay() {
        use tracedecay_memory_conformance::ReleaseLatchV1;

        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.publication-barrier").await;
        let entered = ReleaseLatchV1::new();
        let release = ReleaseLatchV1::new();
        let entered_by_provider = entered.clone();
        let release_provider = release.clone();
        fixture.port.on_observe(move || {
            entered_by_provider.release();
            release_provider.wait();
        });
        let settled = canonical_observation(
            &fixture.project_id,
            &SessionId::new("session.publication-barrier").expect("session id"),
            "the target namespace must receive this before recall is published",
        );
        let records = SettledRecordsPort::single(settled_record(1, settled));
        let cancellation = HostCancellationToken::new();
        let pass = run_startup_replay(fixture.journey.as_ref(), &records, &cancellation)
            .await
            .expect("startup replay admission");
        assert_eq!(pass.admitted, 1);
        entered.wait();

        let refused_while_provider_held = fixture
            .journey
            .await_delivery_settled(&cancellation, Duration::from_millis(100))
            .await
            .expect_err("publication must stay fenced while the target call is held");
        assert!(
            matches!(
                refused_while_provider_held,
                ObservationJourneyError::DeadlineExceeded { admitted: 0 }
            ),
            "unexpected publication-barrier result: {refused_while_provider_held}"
        );

        let barrier_cancellation = HostCancellationToken::new();
        let cancel = barrier_cancellation.clone();
        let cancellation_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });
        let unwound = fixture
            .journey
            .await_delivery_settled(&barrier_cancellation, Duration::from_secs(1))
            .await
            .expect_err("cancellation must unwind the publication barrier");
        cancellation_task
            .await
            .expect("publication-barrier cancellation task");
        assert!(
            matches!(unwound, ObservationJourneyError::Cancelled { admitted: 0 }),
            "unexpected cancellation result: {unwound}"
        );

        release.release();
        fixture
            .journey
            .await_delivery_settled(&cancellation, Duration::from_secs(5))
            .await
            .expect("publication barrier after target delivery");
        assert_eq!(
            fixture.port.delivered.lock().unwrap().len(),
            1,
            "the publication barrier must wait for the provider effect"
        );
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// A required observation recipient keeps a restarted project behind the
    /// publication fence while a durable observation is still pending. The
    /// provider-side delivery list stands in for the immediate recall that
    /// follows publication: it must contain the restarted observation before
    /// activation can return.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn required_activation_waits_for_pending_restart_delivery_before_immediate_recall() {
        use tracedecay_memory_conformance::ReleaseLatchV1;

        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.restart-publication-barrier").await;
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
        let mount_inputs = || ObservationJourneyMountInputsV1 {
            composition: composition(Arc::clone(&fixture.port) as Arc<dyn MemoryProviderV1>),
            profile_id: fixture.journey.adapter.context.profile_id.clone(),
            scope: fixture.journey.adapter.context.scope.clone(),
            authoritative_project_id: fixture.project_id.clone(),
            provider: test_observation_mount(&fixture.journal_root, 1)
                .expect("observer mount metadata"),
            store_data_root: fixture.journal_root.clone(),
            policy: ObservationJourneyPolicyV1::project_default(),
        };
        let cancellation = HostCancellationToken::new();
        let seeded = mount_observer_dormant(mount_inputs(), &cancellation)
            .await
            .expect("dormant seed journey");
        let session = SessionId::new("session.restart-publication-barrier").expect("session id");
        let record = settled_record(
            1,
            canonical_observation(
                &fixture.project_id,
                &session,
                "this observation must be visible to the first recall after restart",
            ),
        );

        // First life admits the canonical row with no worker, leaving the
        // durable delivery pending exactly where a crash or stop can leave it.
        let pass = run_startup_replay(
            seeded.as_ref(),
            &SettledRecordsPort::single(record.clone()),
            &cancellation,
        )
        .await
        .expect("seed startup replay");
        assert_eq!(pass.admitted, 1);
        let pending_path = seeded.journal_path().to_owned();
        assert!(!journal_snapshot(&pending_path).contains("acknowledged"));
        assert_eq!(fixture.port.observe_calls.load(Ordering::Acquire), 0);
        let failures = seeded
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
        drop(seeded);

        let entered = ReleaseLatchV1::new();
        let release = ReleaseLatchV1::new();
        let entered_by_provider = entered.clone();
        let release_provider = release.clone();
        fixture.port.on_observe(move || {
            entered_by_provider.release();
            release_provider.wait();
        });

        let reopened = mount_observer_dormant(mount_inputs(), &cancellation)
            .await
            .expect("dormant restarted journey");
        let activation_cancellation = cancellation.clone();
        let mut activation = tokio::spawn(async move {
            activate_required_with_startup_replay_and_delivery_settled(
                Arc::clone(&reopened),
                SettledRecordsPort::single(record),
                &activation_cancellation,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.port.observe_calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the restarted delivery must reach the provider");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut activation)
                .await
                .is_err(),
            "required activation returned while the restarted delivery was held"
        );
        release.release();
        let activated = activation
            .await
            .expect("required activation task")
            .expect("required activation and settlement");
        assert_eq!(
            fixture.port.delivered.lock().unwrap().len(),
            1,
            "an immediate recall after publication must see the restarted observation"
        );
        assert_eq!(
            wait_for_settlement(&pending_path).await,
            ("acknowledged".to_owned(), 1)
        );

        let failures = activated
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Mounts the retained journey constructor against a real registered project
    /// store and a real journal, without the
    /// bounded live replay task so admission counts are deterministic: direct
    /// canonical replay is the authoritative path either way.
    async fn mount_hygiene_fixture(temp: &TempDir, project: &str) -> HygieneJourneyFixture {
        let project_id = ProjectId::new(project).expect("project id");
        let runtime = HostAdmissionTestRuntimeV1::project(
            &temp.path().join("profile"),
            &temp.path().join("project"),
            project_id.clone(),
        )
        .await
        .expect("registered project database");
        let store = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .expect("project database")
            .observation_store();
        let port = Arc::new(JourneyObservationProvider::new());
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).expect("journal root");
        let journey = mount_project_observation_journey(ObservationJourneyMountInputsV1 {
            composition: composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>),
            profile_id: UserProfileId::new("profile.observation-hygiene").expect("profile id"),
            scope: scope(project_id.clone()),
            authoritative_project_id: project_id.clone(),
            provider: test_observation_mount(&(journal_root.clone()), 1)
                .expect("observer mount metadata"),
            store_data_root: journal_root.clone(),
            policy: ObservationJourneyPolicyV1::project_default(),
        })
        .expect("mounted journey");
        assert_eq!(
            run_startup_replay(journey.as_ref(), &store, &HostCancellationToken::new())
                .await
                .unwrap()
                .admitted,
            0
        );
        HygieneJourneyFixture {
            _runtime: runtime,
            store,
            port,
            journey,
            project_id,
            journal_root,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_canonical_facts_withhold_the_whole_message_and_preserve_source_evidence() {
        let temp = TempDir::new().unwrap();
        let fixture = mount_hygiene_fixture(&temp, "project.unknown-eligibility").await;
        let session = SessionId::new("session.unknown-eligibility").unwrap();
        let message =
            "Authored content must stay out of a provider copy with uncertain eligibility.";
        let states = [
            CanonicalUnknownStateV1::Absent,
            CanonicalUnknownStateV1::Null,
            CanonicalUnknownStateV1::Unsupported,
            CanonicalUnknownStateV1::Redacted,
            CanonicalUnknownStateV1::Unrecoverable,
            CanonicalUnknownStateV1::Malformed,
        ];
        let mut originals = Vec::new();
        for (position, state) in states.into_iter().enumerate() {
            let mut payload =
                canonical_observation_at(&fixture.project_id, &session, message, position as u64)
                    .payload()
                    .clone();
            payload["facts"].as_array_mut().unwrap().push(
                serde_json::to_value(CanonicalObservationFactV1::Unknown {
                    native_kind: "unresolved_fact".to_owned(),
                    state,
                })
                .unwrap(),
            );
            serde_json::from_value::<CanonicalObservationEnvelopeV1>(payload.clone())
                .unwrap()
                .validate()
                .unwrap();
            let observation = canonical_observation_with_payload_at(
                &fixture.project_id,
                &session,
                payload.clone(),
                position as u64,
            );
            let id = observation.observation_id().clone();
            let envelope = provider_observation_envelope(
                SESSION_MESSAGE_OBSERVATION_KIND,
                SESSION_MESSAGE_PAYLOAD_CONTRACT,
                &payload,
                &id,
            );
            let source_digest = tracedecay_domain::canonical_text::sha256_hex(
                &canonical_payload_bytes(&envelope).unwrap(),
            );
            let exact = exact_scope_for_session(
                &fixture.journey.adapter.context.profile_id,
                &fixture.journey.adapter.context.scope,
                session.as_str(),
            )
            .unwrap();
            let forget_key = forget_source_key_for(&exact, &observation)
                .unwrap()
                .as_str()
                .to_owned();
            let anchored = anchored_write(observation);
            let expected_cursor = fixture
                .store
                .get_source_cursor(
                    anchored.observation().source(),
                    anchored.observation().scope(),
                )
                .await
                .unwrap();
            assert_eq!(
                expected_cursor
                    .as_ref()
                    .map(ObservationSourceCursorV1::position),
                (position > 0).then_some(position as u64)
            );
            let write = ObservationWrite::new(
                anchored.observation().clone(),
                expected_cursor,
                anchored.next_cursor().clone(),
            )
            .unwrap();
            fixture
                .store
                .persist_observation(
                    AnchoredObservationWrite::new(
                        write,
                        anchored.retrieval_anchor().clone(),
                        anchored.projection_generation().clone(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            originals.push((id, payload, source_digest, forget_key));
        }
        let pass = run_startup_replay(
            fixture.journey.as_ref(),
            &fixture.store,
            &HostCancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(pass.admitted, 0);
        assert_eq!(fixture.port.observe_calls.load(Ordering::Acquire), 0);
        assert!(fixture.port.delivered.lock().unwrap().is_empty());
        let connection = rusqlite::Connection::open(fixture.journey.journal_path()).unwrap();
        for (id, payload, digest, forget_key) in &originals {
            let (reason, actual_digest, findings, actual_forget_key): (
                String,
                String,
                i64,
                String,
            ) = connection
                .query_row(
                    "SELECT reason, source_payload_sha256, finding_count, forget_source_key \
                     FROM tdmem_observation_withheld_v2 WHERE source_event_id = ?1",
                    [id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(reason, "unknown_eligibility");
            assert_eq!(&actual_digest, digest);
            assert_eq!(findings, 0);
            assert_eq!(&actual_forget_key, forget_key);
            assert_eq!(
                fixture
                    .store
                    .get_observation(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .observation()
                    .payload(),
                payload
            );
        }
        let withheld: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tdmem_observation_withheld_v2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(withheld, i64::try_from(originals.len()).unwrap());
        drop(connection);
        assert!(!journal_files_contain(
            fixture.journey.journal_path(),
            message.as_bytes()
        ));
        assert_eq!(
            fixture.journey.replay_watermark().await.unwrap(),
            originals.len() as u64
        );
        assert_eq!(
            run_startup_replay(
                fixture.journey.as_ref(),
                &fixture.store,
                &HostCancellationToken::new(),
            )
            .await
            .unwrap()
            .admitted,
            0
        );
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with(&format!(
                "journal=0 delivery=0 withheld={} receipts=0 cursors=1 ",
                originals.len()
            )),
            "{snapshot}"
        );
        assert!(
            fixture
                .journey
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn codex_turn_context_withholding_allows_following_message_and_durable_restart() {
        let temp = TempDir::new().unwrap();
        let fixture = mount_hygiene_fixture(&temp, "project.codex-unknown-replay").await;
        let project_root = std::fs::canonicalize(temp.path().join("project")).unwrap();
        let registered = fixture
            ._runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .unwrap();
        let shard = &registered.binding().shard_id;
        let admission = HostAdmissionFacade::new(
            HostAdmissionAuthorities::for_project(
                shard.brain_id.clone(),
                shard.profile_id.clone(),
                fixture.project_id.clone(),
                registered.as_ref(),
            )
            .with_background_cpu(fixture._runtime.background_cpu()),
        );
        let session = "11111111-1111-4111-8111-111111111111";
        let message = "A known assistant message follows uncertain turn context.";
        let transcript = temp
            .path()
            .join(format!("rollout-2026-09-04T12-00-00-{session}.jsonl"));
        let records = [
            json!({"timestamp":"2026-09-04T12:00:00Z", "type":"session_meta",
                "payload":{"id":session,"cwd":project_root}}),
            json!({"timestamp":"2026-09-04T12:00:01Z", "type":"turn_context",
                "payload":{"turn_id":"turn-1","cwd":project_root,"model":"gpt-5.5"}}),
            json!({"timestamp":"2026-09-04T12:00:02Z", "type":"event_msg",
                "payload":{"type":"agent_message","message":message}}),
        ];
        std::fs::write(
            &transcript,
            records.iter().fold(String::new(), |mut output, record| {
                writeln!(output, "{record}").expect("write JSON record");
                output
            }),
        )
        .unwrap();
        let progress = try_admit_codex_jsonl_observations_for_project_with_admission(
            &transcript,
            &project_root,
            fixture.project_id.clone(),
            &admission,
            None,
        )
        .await
        .unwrap();
        assert_eq!(progress.frames_persisted, records.len() as u64);
        let stored = fixture
            .store
            .replay_observations(ObservationReplayRequest::new(0, records.len()).unwrap())
            .await
            .unwrap();
        let unknown = stored.iter().find(|record| {
            serde_json::from_value::<CanonicalObservationEnvelopeV1>(record.observation().payload().clone())
                .unwrap().facts().iter().any(|fact| matches!(fact,
                    CanonicalObservationFactV1::Unknown { native_kind, state: CanonicalUnknownStateV1::Unsupported }
                    if native_kind == "turn_context"))
        }).expect("the real Codex normalizer emits Unsupported turn_context evidence");
        let unknown_id = unknown.observation().observation_id().clone();
        let unknown_payload = unknown.observation().payload().clone();
        let following = stored
            .iter()
            .find(|record| record.observation().payload().to_string().contains(message))
            .expect("the following message was durably admitted");
        let following_id = following.observation().observation_id().clone();
        assert!(unknown.sequence() < following.sequence());
        assert_eq!(
            run_startup_replay(
                fixture.journey.as_ref(),
                &fixture.store,
                &HostCancellationToken::new(),
            )
            .await
            .unwrap()
            .admitted,
            1
        );
        assert_eq!(
            wait_for_settlement(fixture.journey.journal_path()).await,
            ("acknowledged".to_owned(), 1)
        );
        {
            let delivered = fixture.port.delivered.lock().unwrap();
            assert_eq!(delivered.len(), 1);
            let envelope: Value = serde_json::from_slice(&delivered[0].bytes).unwrap();
            assert_eq!(
                envelope["source_identity"]["canonical_observation_id"],
                following_id.as_str()
            );
            assert!(envelope.to_string().contains(message));
            assert!(!envelope.to_string().contains("turn_context"));
            assert!(!envelope.to_string().contains(unknown_id.as_str()));
        }
        assert_eq!(
            fixture
                .store
                .get_observation(&unknown_id)
                .await
                .unwrap()
                .unwrap()
                .observation()
                .payload(),
            &unknown_payload
        );
        let before = journal_snapshot(fixture.journey.journal_path());
        assert!(
            before.starts_with("journal=1 delivery=1 withheld=1 receipts=1 cursors=1 "),
            "{before}"
        );
        {
            let envelope = provider_observation_envelope(
                SESSION_MESSAGE_OBSERVATION_KIND,
                SESSION_MESSAGE_PAYLOAD_CONTRACT,
                &unknown_payload,
                &unknown_id,
            );
            let digest = tracedecay_domain::canonical_text::sha256_hex(
                &canonical_payload_bytes(&envelope).unwrap(),
            );
            let connection = rusqlite::Connection::open(fixture.journey.journal_path()).unwrap();
            let (reason, actual_digest, findings): (String, String, i64) = connection
                .query_row(
                    "SELECT reason, source_payload_sha256, finding_count \
                 FROM tdmem_observation_withheld_v2 WHERE source_event_id = ?1",
                    [unknown_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(reason, "unknown_eligibility");
            assert_eq!(actual_digest, digest);
            assert_eq!(findings, 0);
        }
        assert!(
            fixture
                .journey
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await
                .is_empty()
        );
        let reopened = fixture.reopen();
        assert_eq!(
            run_startup_replay(
                reopened.as_ref(),
                &fixture.store,
                &HostCancellationToken::new(),
            )
            .await
            .unwrap()
            .admitted,
            0
        );
        assert_eq!(journal_snapshot(reopened.journal_path()), before);
        assert_eq!(fixture.port.observe_calls.load(Ordering::Acquire), 1);
        assert!(
            reopened
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_facts_do_not_mask_invalid_envelopes_identity_or_structure() {
        let temp = TempDir::new().unwrap();
        let fixture = mount_hygiene_fixture(&temp, "project.unknown-refusals").await;
        let session = SessionId::new("session.unknown-refusals").unwrap();
        let mut mixed =
            canonical_observation(&fixture.project_id, &session, "ordinary authored content")
                .payload()
                .clone();
        mixed["facts"].as_array_mut().unwrap().push(
            serde_json::to_value(CanonicalObservationFactV1::Unknown {
                native_kind: "unresolved_fact".to_owned(),
                state: CanonicalUnknownStateV1::Unsupported,
            })
            .unwrap(),
        );
        let mut malformed = mixed.clone();
        malformed["facts"][1]["native_kind"] = json!("");
        let mut foreign_provider = mixed.clone();
        foreign_provider["provider"] = json!("codex");
        let mut foreign_session = mixed.clone();
        foreign_session["relations"]["session_id"] = json!("session.foreign");
        let mut excessive_values = mixed;
        excessive_values["facts"][0]["content"] = json!(vec![
                Value::Null;
                tracedecay_domain::MAX_OBSERVATION_STRUCTURE_VALUES
            ]);
        assert_eq!(
            serde_json::from_value::<CanonicalObservationEnvelopeV1>(excessive_values.clone())
                .unwrap()
                .validate()
                .unwrap_err(),
            ObservationContractError::CanonicalEnvelopeTooManyValues
        );
        for payload in [
            malformed,
            foreign_provider,
            foreign_session,
            excessive_values,
        ] {
            let observation =
                canonical_observation_with_payload(&fixture.project_id, &session, payload);
            let error = run_startup_replay(
                fixture.journey.as_ref(),
                &SettledRecordsPort::single(settled_record(1, observation)),
                &HostCancellationToken::new(),
            )
            .await
            .expect_err(
                "Unknown must not convert malformed or foreign evidence to a settled refusal",
            );
            assert_eq!(
                replay_recoverability(&error),
                ReplayRecoverabilityV1::Permanent
            );
            assert!(
                matches!(&error, ObservationJourneyError::Ingress(ObservationRuntimeError::Admission { cause, .. })
                if matches!(cause.cause().downcast_ref::<AdmissionAdapterError>(),
                    Some(AdmissionAdapterError::InvalidCanonicalEnvelope { .. }))),
                "{error}"
            );
            assert_eq!(fixture.journey.replay_watermark().await.unwrap(), 0);
            let snapshot = journal_snapshot(fixture.journey.journal_path());
            assert!(
                snapshot.starts_with("journal=0 delivery=0 withheld=0 receipts=0 cursors=0 "),
                "{snapshot}"
            );
        }
        assert_eq!(fixture.port.observe_calls.load(Ordering::Acquire), 0);
        assert!(
            fixture
                .journey
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await
                .is_empty()
        );
    }

    mod admission_readiness_terminals {
        use super::*;

        struct RefuseOnceAdmission {
            canonical: Arc<CanonicalObservationAdmissionAdapterV1>,
            refusal: Mutex<Option<SupervisedReadinessError>>,
        }

        impl ObservationAdmissionAdapterV1 for RefuseOnceAdmission {
            type Record = StoredObservation;
            type Error = AdmissionAdapterError;
            type Control = ReplayIngestControlV1;

            fn lane(&self, record: &SourceRecordV1<Self::Record>) -> ObservationLaneKeyV1 {
                self.canonical.lane(record)
            }

            fn classify(&self, record: &SourceRecordV1<Self::Record>) -> ObservationLoadClassV1 {
                self.canonical.classify(record)
            }

            fn decide(
                &self,
                record: &SourceRecordV1<Self::Record>,
                control: &Self::Control,
            ) -> Result<AdmissionDecisionV1, Self::Error> {
                if let Some(source) = self.refusal.lock().unwrap().take() {
                    return Err(AdmissionAdapterError::Readiness {
                        source_event_id: record.source_event_id.clone(),
                        source: Box::new(ObservationJourneyError::SupervisedReadiness(source)),
                    });
                }
                self.canonical.decide(record, control)
            }
        }

        #[derive(Clone, Copy)]
        enum ReadinessRefusal {
            Request(TerminalCode),
            Provider(TerminalCode),
        }

        async fn refusal_preserves_watermark_and_canonical_retry(refusal: ReadinessRefusal) {
            let temp = TempDir::new().expect("temporary journey root");
            let fixture = mount_hygiene_fixture(&temp, "project.readiness-terminal").await;
            let session = SessionId::new("session.readiness-terminal").unwrap();
            let mut payload = canonical_observation(&fixture.project_id, &session, "unused")
                .payload()
                .clone();
            payload["native_record_kind"] = json!("session_meta");
            payload["facts"] = json!([{"kind": "boundary", "boundary_kind": "session_start"}]);
            let observation =
                canonical_observation_with_payload(&fixture.project_id, &session, payload.clone());
            let observation_id = observation.observation_id().clone();
            fixture
                .store
                .persist_observation(anchored_write(observation))
                .await
                .expect("canonical record is durably committed");
            let stored = fixture
                .store
                .get_observation(&observation_id)
                .await
                .unwrap()
                .expect("canonical record remains available for retry");
            let sequence = stored.sequence();
            let record = fixture.journey.source_record(stored).unwrap();
            let source = match refusal {
                ReadinessRefusal::Request(terminal_code) => {
                    SupervisedReadinessError::RequestTerminal {
                        exact_scope_sha256: record.stream.exact_scope_sha256.clone(),
                        terminal_code,
                    }
                }
                ReadinessRefusal::Provider(terminal_code) => {
                    SupervisedReadinessError::Unavailable {
                        exact_scope_sha256: record.stream.exact_scope_sha256.clone(),
                        kind:
                            tracedecay_memory_provider_registry::DegradationKindV1::HandshakeRefused,
                        terminal_code: Some(terminal_code),
                        detail: "provider refusal is not a host request terminal".to_owned(),
                        retry_in_micros: 1_000,
                    }
                }
            };
            let adapter = Arc::new(RefuseOnceAdmission {
                canonical: Arc::clone(&fixture.journey.adapter),
                refusal: Mutex::new(Some(source)),
            });
            let watermark_before = fixture.journey.replay_watermark().await.unwrap();
            assert_eq!(watermark_before, 0);
            let outcome = fixture
                .journey
                .ingest_record_with_adapter(record.clone(), Arc::clone(&adapter), open_bounds())
                .await;
            match refusal {
                ReadinessRefusal::Request(TerminalCode::DeadlineExceeded) => {
                    assert!(matches!(outcome, Ok(RecordOutcomeV1::DeadlineExceeded)));
                }
                ReadinessRefusal::Request(TerminalCode::Cancelled) => {
                    assert!(matches!(
                        outcome,
                        Err(ObservationJourneyError::Cancelled { admitted: 0 })
                    ));
                }
                ReadinessRefusal::Provider(terminal_code) => {
                    assert!(matches!(
                        outcome,
                        Err(ObservationJourneyError::Ingress(
                            ObservationRuntimeError::Admission { ref cause, .. }
                        )) if matches!(
                            cause.cause().downcast_ref::<AdmissionAdapterError>(),
                            Some(AdmissionAdapterError::Readiness { source, .. }) if matches!(
                                source.as_ref(),
                                ObservationJourneyError::SupervisedReadiness(
                                    SupervisedReadinessError::Unavailable {
                                        terminal_code: Some(actual), ..
                                    }
                                ) if *actual == terminal_code
                            )
                        )
                    ));
                }
                ReadinessRefusal::Request(other) => {
                    panic!("unexpected request terminal: {other:?}")
                }
            }
            assert_eq!(
                fixture.journey.replay_watermark().await.unwrap(),
                watermark_before,
                "a refused admission must not commit its journal position"
            );
            assert_eq!(
                fixture
                    .store
                    .get_observation(&observation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .observation()
                    .payload(),
                &payload
            );
            let retry = fixture
                .journey
                .ingest_record_with_adapter(record, adapter, open_bounds())
                .await
                .expect("the canonical adapter can retry the same committed record");
            let RecordOutcomeV1::Reported(report) = retry else {
                panic!("canonical retry must return its real journal report");
            };
            assert_eq!(report.non_messages, 1);
            assert_eq!(report.appended, 0);
            assert_eq!(report.high_watermark, Some(SourceSequenceV1(sequence)));
            assert_eq!(fixture.journey.replay_watermark().await.unwrap(), sequence);
            assert_eq!(fixture.port.observe_calls.load(Ordering::Acquire), 0);
            let failures = fixture
                .journey
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
                .await;
            assert!(failures.is_empty(), "{failures:?}");
        }

        #[tokio::test]
        async fn host_readiness_deadline_preserves_watermark_and_allows_canonical_retry() {
            refusal_preserves_watermark_and_canonical_retry(ReadinessRefusal::Request(
                TerminalCode::DeadlineExceeded,
            ))
            .await;
        }

        #[tokio::test]
        async fn host_readiness_cancellation_preserves_watermark_and_allows_canonical_retry() {
            refusal_preserves_watermark_and_canonical_retry(ReadinessRefusal::Request(
                TerminalCode::Cancelled,
            ))
            .await;
        }

        #[tokio::test]
        async fn provider_readiness_refusal_remains_an_admission_failure() {
            for terminal_code in [TerminalCode::DeadlineExceeded, TerminalCode::Cancelled] {
                refusal_preserves_watermark_and_canonical_retry(ReadinessRefusal::Provider(
                    terminal_code,
                ))
                .await;
            }
        }
    }

    /// Acceptance: startup replay honours the project-open cancellation
    /// *inside* a record with a typed terminal, and the durable watermark
    /// holds exactly the records that were committed before it. A later open
    /// resumes from that watermark under its own token and admits everything
    /// the cancelled open did not commit.
    ///
    /// The cancellation fires during the first record's readiness handshake —
    /// the expensive step inside admission — so this is the case a
    /// between-records check cannot catch: the record was fully admitted and
    /// is then *not* committed, because the caller stopped wanting it before
    /// the append. Committing it anyway would charge a closing project for
    /// work it gave up on and move a watermark on its behalf.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn startup_replay_cancelled_inside_a_record_returns_typed_terminal_and_holds_watermark() {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.observation-cancel").await;
        let first = canonical_observation(
            &fixture.project_id,
            &SessionId::new("session.observation-cancel-first").expect("session id"),
            "first settled record",
        );
        let second = canonical_observation(
            &fixture.project_id,
            &SessionId::new("session.observation-cancel-second").expect("session id"),
            "second settled record",
        );
        let records = SettledRecordsPort {
            records: vec![settled_record(1, first), settled_record(2, second)],
        };

        // Admission proves readiness for each record's own session scope, so
        // the provider handshake is the one point inside record admission the
        // test can act from: the first record's admission drains the open.
        let cancellation = HostCancellationToken::new();
        let cancel = cancellation.clone();
        fixture.port.on_handshake(move || cancel.cancel());

        let error = run_startup_replay(fixture.journey.as_ref(), &records, &cancellation)
            .await
            .expect_err("a cancelled open must not report a completed replay");
        assert!(
            matches!(error, ObservationJourneyError::Cancelled { admitted: 0 }),
            "unexpected terminal: {error}"
        );
        let watermark = fixture
            .journey
            .journal
            .maximum_replay_sequence(
                SourceAuthorityV1::HostSession,
                &fixture.journey.source_stream,
            )
            .expect("watermark");
        assert_eq!(
            watermark, None,
            "the record the caller cancelled during must not be committed"
        );
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with("journal=0 delivery=0 "),
            "nothing may be journaled after the caller gave up: {snapshot}"
        );

        // The cancelled open ends here, exactly as `mount_and_replay` ends it:
        // the typed terminal is returned and the journey that open constructed
        // is shut down and dropped.
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");

        // Nothing was lost either: both records are still the canonical
        // store's, and the *next open* — a new journey over the same durable
        // journal, under its own token — admits both exactly once. The
        // provider double keeps the cancelling hook armed, so the later open
        // also proves the dead token cannot reach across mounts.
        let reopened = fixture.reopen();
        let pass = run_startup_replay(reopened.as_ref(), &records, &HostCancellationToken::new())
            .await
            .expect("resumed replay");
        assert_eq!(
            pass,
            ReplayPassV1 {
                admitted: 2,
                halted: None,
                shed: None,
            }
        );
        let snapshot = journal_snapshot(reopened.journal_path());
        assert!(snapshot.starts_with("journal=2 delivery=2 "), "{snapshot}");
        let failures = reopened
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Acceptance: the mounted lane's published backlog is re-read from the
    /// journal rather than replayed from whatever the last admission measured.
    ///
    /// Ingress only measures around records it admits, and delivery moves rows
    /// to terminal without ever passing through ingress. So a lane that is
    /// quiet — the normal case — would otherwise keep reporting the pressure
    /// of the last append forever, which is the one reading guaranteed to be
    /// out of date.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_mounted_lane_republishes_backlog_read_from_the_journal() {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.observation-backlog").await;
        let settled = canonical_observation(
            &fixture.project_id,
            &SessionId::new("session.observation-backlog").expect("session id"),
            "a settled record for the lane",
        );
        let records = SettledRecordsPort::single(settled_record(1, settled));
        let pass = run_startup_replay(
            fixture.journey.as_ref(),
            &records,
            &HostCancellationToken::new(),
        )
        .await
        .expect("startup replay");
        assert_eq!(pass.admitted, 1);

        // Ingress republished the lane after the append it committed, so a
        // measurement exists at all.
        let after_append = fixture
            .journey
            .backlog_metrics()
            .expect("an admitted record must publish the lane it landed in");

        // Wait until the delivery worker has made the journal stable before
        // comparing two independent reads. Otherwise it can drain between the
        // publication and the assertion, which tests scheduling rather than
        // republication.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let state = fixture
                .journey
                .journal
                .inspect(&JournalInspectionFilterV1::default())
                .expect("journal inspection")
                .rows
                .first()
                .map(|row| row.state);
            if state.is_some_and(DeliveryStateV1::is_terminal) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "delivery did not settle"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Re-reading is what keeps it current. The stable published reading
        // has to agree with the journal.
        fixture.journey.report_backlog().await;
        let published = fixture
            .journey
            .backlog_metrics()
            .expect("a refreshed lane must still publish");
        let pressure = fixture
            .journey
            .journal
            .lane_pressure(&fixture.journey.provider_lane)
            .expect("lane pressure");
        assert_eq!(published.queue_items, pressure.queue_items);
        assert_eq!(published.queue_bytes, pressure.queue_bytes);
        assert_eq!(published.max_queue_items, pressure.max_queue_items);
        assert_eq!(published.max_queue_bytes, pressure.max_queue_bytes);
        assert!(
            published.observed_at_unix_micros >= after_append.observed_at_unix_micros,
            "a refresh must publish a later instant than the append that preceded it"
        );

        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Acceptance: a mounted admission that ignores its own budget still
    /// returns inside the *caller's* bound, with a typed terminal, an
    /// unmoved watermark, and a foreground latency sample — and the record it
    /// abandoned is still the canonical store's to re-present.
    ///
    /// This is the production path, not a hand-driven gate. The readiness
    /// handshake is the expensive step inside admission; here it does not come
    /// back, which is exactly what a wedged or overloaded provider looks like.
    /// Without a bound on the caller, one such record parks the replay pass for
    /// as long as the provider feels like taking — orders of magnitude past the
    /// declared 250 ms foreground budget — and the pass deadline, checked only
    /// between records, never gets a turn.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_mounted_admission_that_ignores_its_budget_returns_at_the_caller_bound() {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.observation-slow").await;
        let settled = canonical_observation(
            &fixture.project_id,
            &SessionId::new("session.observation-slow").expect("session id"),
            "a settled record behind a wedged provider",
        );
        let records = SettledRecordsPort::single(settled_record(1, settled));

        // A provider that returns only when this test lets it. Nothing but the
        // caller's own bound can end the wait, which is the point.
        let release = Arc::new(AtomicBool::new(false));
        let waiter = Arc::clone(&release);
        fixture.port.on_handshake(move || {
            let give_up = std::time::Instant::now() + Duration::from_secs(10);
            while !waiter.load(Ordering::Relaxed) && std::time::Instant::now() < give_up {
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        // The caller's bound sits past the lane's foreground budget on
        // purpose: the admission below runs until that bound, so the sample it
        // leaves behind is a genuine budget breach rather than an in-budget
        // deadline hit.
        let budget = fixture
            .journey
            .backpressure
            .policy()
            .foreground_budget_micros;
        let cancellation = HostCancellationToken::new();
        let bounds = ReplayBoundsV1 {
            cancellation: &cancellation,
            deadline: tokio::time::Instant::now()
                + Duration::from_micros(u64::try_from(budget).expect("budget is positive"))
                + Duration::from_millis(100),
        };
        let started = std::time::Instant::now();
        let error = fixture
            .journey
            .replay_canonical_observations(&records, 1, bounds)
            .await
            .expect_err("a pass that ran out of budget must not report a completed replay");
        let elapsed = started.elapsed();

        assert!(
            matches!(
                error,
                ObservationJourneyError::DeadlineExceeded { admitted: 0 }
            ),
            "unexpected terminal: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the pass must return on its own bound rather than on the provider's, took {elapsed:?}"
        );

        // Nothing was committed for the record the pass gave up on, so the
        // watermark is exactly where it was and the canonical store still owns
        // it.
        let watermark = fixture
            .journey
            .journal
            .maximum_replay_sequence(
                SourceAuthorityV1::HostSession,
                &fixture.journey.source_stream,
            )
            .expect("watermark");
        assert_eq!(watermark, None);
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(snapshot.starts_with("journal=0 delivery=0 "), "{snapshot}");

        // The admission was measured even though it never produced a report.
        // A sample taken only on success would leave the lane blind to exactly
        // the admissions that hurt, and the breach run is what sheds optional
        // traffic before the next record pays the same cost.
        let sample = fixture
            .journey
            .backpressure
            .foreground_sample()
            .expect("a foreground sample must be taken on every path");
        assert!(
            sample > budget,
            "a {sample}us admission must be recorded as over the {budget}us budget"
        );
        assert_eq!(fixture.journey.backpressure.foreground_breaches(), 1);

        // Let the provider go and prove the abandoned record is still
        // admittable: nothing was dropped, only refused.
        release.store(true, Ordering::Relaxed);
        let pass = run_startup_replay(
            fixture.journey.as_ref(),
            &records,
            &HostCancellationToken::new(),
        )
        .await
        .expect("resumed replay");
        assert_eq!(pass.admitted, 1);
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Acceptance: a permanent journal refusal is a typed halt, not an error
    /// and not a hole. The watermark holds at the refused position, the halt
    /// is reported typed from the pass and from the journey, and the live
    /// replay task backs off instead of repeating the refusal at park rate.
    ///
    /// The refusal is seeded the way a partial restore leaves a journal: the
    /// journaled row survives, its replay cursor does not, and the canonical
    /// stream then presents a different settled event at the same position.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_replay_backs_off_on_a_permanent_source_sequence_conflict_and_holds_watermark() {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.observation-conflict").await;
        let session_id = SessionId::new("session.observation-conflict").expect("session id");
        let original =
            canonical_observation(&fixture.project_id, &session_id, "original settled event");
        let original_event_id = original.observation_id().as_str().to_owned();
        let pass = run_startup_replay(
            fixture.journey.as_ref(),
            &SettledRecordsPort::single(settled_record(1, original)),
            &HostCancellationToken::new(),
        )
        .await
        .expect("original replay");
        assert_eq!(
            pass,
            ReplayPassV1 {
                admitted: 1,
                halted: None,
                shed: None,
            }
        );
        let (state, _) = wait_for_settlement(fixture.journey.journal_path()).await;
        assert_eq!(state, "acknowledged");

        {
            let connection =
                rusqlite::Connection::open(fixture.journey.journal_path()).expect("journal");
            connection
                .busy_timeout(Duration::from_secs(5))
                .expect("busy timeout");
            connection
                .execute("DELETE FROM tdmem_observation_replay_cursor_v1", [])
                .expect("drop replay cursor");
        }
        let conflicting = canonical_observation_at(
            &fixture.project_id,
            &session_id,
            "a different settled event at the same position",
            1,
        );
        assert_ne!(conflicting.observation_id().as_str(), original_event_id);
        let passes = Arc::new(AtomicUsize::new(0));
        let rewritten = CountingReplayPort {
            inner: SettledRecordsPort::single(settled_record(1, conflicting)),
            passes: Arc::clone(&passes),
        };

        // The authoritative pass returns the refusal typed inside the pass:
        // nothing admitted, nothing stepped over, the row that was there stays.
        let pass = fixture
            .journey
            .replay_canonical_observations(&rewritten, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("a typed journal refusal is a halt, not a replay error");
        assert_eq!(pass.admitted, 0);
        let halt = pass.halted.expect("halted pass");
        assert_eq!(halt.source_sequence, SourceSequenceV1(1));
        assert!(
            matches!(
                &halt.outcome,
                AppendOutcomeV1::SourceSequenceConflict {
                    stored_source_event_id,
                    ..
                } if stored_source_event_id == &original_event_id
            ),
            "unexpected refusal: {:?}",
            halt.outcome
        );
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(snapshot.starts_with("journal=1 delivery=1 "), "{snapshot}");

        // The live replay task meets the same refusal, reports it typed on the
        // journey, and then waits out the backoff instead of polling the
        // refused position at the park interval.
        fixture
            .journey
            .start_live_replay(rewritten)
            .expect("live replay task");
        let halted = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(halt) = fixture.journey.halted_on() {
                    return halt;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("live replay must surface the halt");
        assert_eq!(halted, halt);
        let passes_at_halt = passes.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(
            passes.load(Ordering::Relaxed),
            passes_at_halt,
            "live replay retried a halted position inside its backoff"
        );
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(snapshot.starts_with("journal=1 delivery=1 "), "{snapshot}");
        let failures = fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Acceptance: a reject-floor secret inside a settled canonical session
    /// message is withheld by the mounted production journey before any
    /// journal payload, delivery row, or provider call exists — and the
    /// canonical evidence the host settled is still there, unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn secret_bearing_canonical_commit_is_withheld_before_dispatch_and_evidence_survives() {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture = mount_hygiene_fixture(&temp, "project.observation-hygiene-withheld").await;
        let session_id =
            SessionId::new("session.observation-hygiene-withheld").expect("session id");
        // Assembled from fragments so this file is not itself a secret corpus.
        let secret = concat!("ghp_", "KsY7QwT2mZ4bV9nR6cX1jH8pL3dG5fA0eUwQ");
        let observation = canonical_observation(
            &fixture.project_id,
            &session_id,
            &format!("rotate the token {secret} before the next deploy"),
        );
        let canonical_id = observation.observation_id().clone();
        let canonical_payload = observation.payload().clone();
        let source_envelope_bytes = canonical_payload_bytes(&provider_observation_envelope(
            SESSION_MESSAGE_OBSERVATION_KIND,
            SESSION_MESSAGE_PAYLOAD_CONTRACT,
            &canonical_payload,
            &canonical_id,
        ))
        .expect("provider envelope bytes");
        fixture
            .store
            .persist_observation(anchored_write(observation))
            .await
            .expect("canonical observation commit");

        let admitted = fixture
            .journey
            .replay_canonical_observations(&fixture.store, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("direct canonical replay")
            .admitted;
        assert_eq!(admitted, 0, "a withheld event must not count as admitted");
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with("journal=0 delivery=0 withheld=1 receipts=0 cursors=1 "),
            "expected one withheld row and no delivery work: {snapshot}"
        );
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);

        // The withheld row is a typed reason plus digests that point back at
        // the untouched canonical record, and the replay cursor moved past it.
        {
            let connection = rusqlite::Connection::open(fixture.journey.journal_path()).unwrap();
            let (reason, source_event_id, source_payload_sha256, receipt_id, finding_count): (
                String,
                String,
                String,
                String,
                i64,
            ) = connection
                .query_row(
                    "SELECT reason, source_event_id, source_payload_sha256, receipt_id, \
                     finding_count FROM tdmem_observation_withheld_v2",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(reason, "secret_rejected");
            assert_eq!(source_event_id, canonical_id.as_str());
            assert_eq!(
                source_payload_sha256,
                tracedecay_domain::canonical_text::sha256_hex(&source_envelope_bytes)
            );
            assert!(
                receipt_id.starts_with("obs-hygiene-withheld.v1."),
                "{receipt_id}"
            );
            assert!(finding_count >= 1);
            let (disposition, last_event_id): (String, String) = connection
                .query_row(
                    "SELECT last_disposition, last_source_event_id \
                     FROM tdmem_observation_replay_cursor_v1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(disposition, "withheld");
            assert_eq!(last_event_id, canonical_id.as_str());
        }
        assert!(
            !journal_files_contain(fixture.journey.journal_path(), secret.as_bytes()),
            "the secret reached the journal file or its WAL"
        );

        // Transient or secret, hygiene never deletes or rewrites canonical
        // evidence: the host's record is still readable and byte-identical.
        let stored = fixture
            .store
            .get_observation(&canonical_id)
            .await
            .expect("canonical store read")
            .expect("canonical record still present");
        assert_eq!(stored.observation().payload(), &canonical_payload);

        // Replaying again is idempotent: the cursor already covers the event,
        // so no second withheld row appears and still nothing is dispatched.
        let admitted_again = fixture
            .journey
            .replay_canonical_observations(&fixture.store, REPLAY_LIVE_PAGES, open_bounds())
            .await
            .expect("second canonical replay")
            .admitted;
        assert_eq!(admitted_again, 0);
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with("journal=0 delivery=0 withheld=1 receipts=0 cursors=1 "),
            "replay was not idempotent: {snapshot}"
        );
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);

        fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
    }

    /// The host sanitizes the complete provider envelope before admission:
    /// the receipt binds the redacted bytes while canonical evidence remains
    /// untouched. Provider delivery is verified by the real NCM worker suite.
    #[test]
    fn credential_assignment_is_redacted_and_receipt_binds_the_provider_envelope() {
        let project_id = ProjectId::new("project.observation-hygiene-redacted").unwrap();
        let session_id = SessionId::new("session.observation-hygiene-redacted").unwrap();
        let secret = concat!("api_", "key=", "0000000000000000");
        let observation = canonical_observation(
            &project_id,
            &session_id,
            &format!("the config still sets {secret} for the sandbox"),
        );
        let canonical_payload = observation.payload().clone();
        let envelope = provider_observation_envelope(
            SESSION_MESSAGE_OBSERVATION_KIND,
            SESSION_MESSAGE_PAYLOAD_CONTRACT,
            &canonical_payload,
            observation.observation_id(),
        );
        let source_bytes = canonical_payload_bytes(&envelope).unwrap();
        let sanitizer = ObservationSanitizer::new().unwrap();
        let ObservationAdmission::Admitted { sanitized, receipt } =
            sanitizer.admit_observation(&envelope, &[]).unwrap()
        else {
            panic!("a credential assignment must be redacted, not silently withheld");
        };
        assert!(envelope_shape_survived(
            &sanitized,
            SESSION_MESSAGE_OBSERVATION_KIND
        ));
        assert_eq!(sanitized["source_identity"], envelope["source_identity"]);
        assert_eq!(
            sanitized["source_identity"]["canonical_observation_id"].as_str(),
            Some(observation.observation_id().as_str()),
        );
        let redacted_bytes = canonical_payload_bytes(&sanitized).unwrap();
        assert_ne!(
            redacted_bytes, source_bytes,
            "redaction left the bytes untouched"
        );
        let redacted_text = std::str::from_utf8(&redacted_bytes).unwrap();
        assert!(!redacted_text.contains(secret));
        assert!(redacted_text.contains("[TraceDecay redacted: credential assignment]"));
        assert!(redacted_text.contains("for the sandbox"));
        assert_eq!(
            receipt.disposition(),
            tracedecay_memory_hygiene::SanitizationDisposition::Redacted,
        );
        assert_eq!(
            receipt.sanitized_payload_sha256(),
            tracedecay_domain::canonical_text::sha256_hex(&redacted_bytes),
        );
        assert_eq!(
            receipt.source_payload_sha256(),
            tracedecay_domain::canonical_text::sha256_hex(&source_bytes),
        );
        let decoded = PayloadSanitizationReceipt::from_json(&receipt.to_json()).unwrap();
        assert_eq!(decoded.receipt_id(), receipt.receipt_id());
        assert_eq!(decoded.sanitizer_revision(), receipt.sanitizer_revision());
        assert_eq!(
            decoded.source_payload_sha256(),
            receipt.source_payload_sha256()
        );
        let payload = CanonicalPayload::new(
            OwnedVersionedId::new(SESSION_MESSAGE_PAYLOAD_CONTRACT).unwrap(),
            redacted_bytes.clone(),
            receipt.sanitized_payload_sha256().to_owned(),
        )
        .unwrap();
        assert_eq!(payload.bytes, redacted_bytes);
        assert_eq!(observation.payload(), &canonical_payload);
        assert!(
            canonical_payload_bytes(observation.payload())
                .unwrap()
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }

    /// Acceptance: a settled canonical record whose *shape* lies beyond the
    /// hygiene ceilings is not an admission fault. The mounted journey records
    /// a typed `unclassifiable_payload` withheld row carrying digests only,
    /// advances the replay cursor, creates no delivery work, leaves the
    /// canonical record untouched, and replays idempotently — so the startup
    /// pass returns `Ok` and the project server opens.
    ///
    /// The hygiene ceilings are derived from the canonical store contract, so
    /// no record that passes the canonical envelope validator can reach this
    /// path any more; the fixture persists the record through the durable
    /// store API, which is exactly how a row settled under another contract
    /// revision would look here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unclassifiable_canonical_record_is_withheld_with_a_typed_reason_and_replay_stays_idempotent()
     {
        let temp = TempDir::new().expect("temporary journey root");
        let fixture =
            mount_hygiene_fixture(&temp, "project.observation-hygiene-unclassifiable").await;
        let session_id =
            SessionId::new("session.observation-hygiene-unclassifiable").expect("session id");
        let ceiling = fixture
            .journey
            .adapter
            .context
            .sanitizer
            .policy()
            .max_canonical_bytes();

        // Grow the message text until the provider envelope's canonical bytes
        // sit one past the hygiene ceiling. The prose has no separator or long
        // token, so size is the only thing hygiene could object to.
        let placeholder = "placeholder";
        let placeholder_observation =
            canonical_observation(&fixture.project_id, &session_id, placeholder);
        let envelope_for = |observation: &DurableObservationV1| {
            canonical_payload_bytes(&provider_observation_envelope(
                SESSION_MESSAGE_OBSERVATION_KIND,
                SESSION_MESSAGE_PAYLOAD_CONTRACT,
                observation.payload(),
                observation.observation_id(),
            ))
            .expect("provider envelope bytes")
        };
        let overhead = envelope_for(&placeholder_observation).len() - placeholder.len();
        let text_len = ceiling + 1 - overhead;
        let mut text = "fact ".repeat(text_len / 5);
        text.push_str(&"f".repeat(text_len % 5));
        let mut payload = placeholder_observation.payload().clone();
        payload["facts"][0]["content"]["text"] = Value::String(text);
        let observation =
            canonical_observation_with_payload(&fixture.project_id, &session_id, payload.clone());
        let source_envelope_bytes = envelope_for(&observation);
        assert_eq!(source_envelope_bytes.len(), ceiling + 1);
        let canonical_id = observation.observation_id().clone();
        // The current canonical store refuses a record this large at its own
        // write boundary, so the row is presented through the replay port the
        // journey reads, exactly as a row settled under another contract
        // revision would arrive: sequence 1, cursor and anchor built the way
        // the store builds them.
        let records = SettledRecordsPort::single(settled_record(1, observation));

        // The authoritative startup pass is Ok: the record is a typed terminal,
        // not a refusal that stalls the cursor and fails every open.
        let admitted = run_startup_replay(
            fixture.journey.as_ref(),
            &records,
            &HostCancellationToken::new(),
        )
        .await
        .expect("an unclassifiable record must not be an admission fault")
        .admitted;
        assert_eq!(admitted, 0, "a withheld event must not count as admitted");
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with("journal=0 delivery=0 withheld=1 receipts=0 cursors=1 "),
            "expected one withheld row and no delivery work: {snapshot}"
        );
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);

        {
            let connection = rusqlite::Connection::open(fixture.journey.journal_path()).unwrap();
            let (reason, source_event_id, source_payload_sha256, receipt_id, finding_count): (
                String,
                String,
                String,
                String,
                i64,
            ) = connection
                .query_row(
                    "SELECT reason, source_event_id, source_payload_sha256, receipt_id, \
                     finding_count FROM tdmem_observation_withheld_v2",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(reason, "unclassifiable_payload");
            assert_eq!(source_event_id, canonical_id.as_str());
            assert_eq!(
                source_payload_sha256,
                tracedecay_domain::canonical_text::sha256_hex(&source_envelope_bytes)
            );
            assert!(
                receipt_id.starts_with("obs-hygiene-withheld.v1."),
                "{receipt_id}"
            );
            assert_eq!(finding_count, 0, "nothing was classified");
            let (disposition, last_event_id): (String, String) = connection
                .query_row(
                    "SELECT last_disposition, last_source_event_id \
                     FROM tdmem_observation_replay_cursor_v1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(disposition, "withheld");
            assert_eq!(last_event_id, canonical_id.as_str());
        }

        // Withholding never touches canonical evidence: the oversized record is
        // still readable through the port and byte-identical.
        let stored = records
            .get_observation(&canonical_id)
            .await
            .expect("settled record read")
            .expect("settled record still present");
        assert_eq!(stored.observation().payload(), &payload);

        // A second startup pass is idempotent: the cursor already covers the
        // event, so no second withheld row appears and still nothing is sent.
        let admitted_again = run_startup_replay(
            fixture.journey.as_ref(),
            &records,
            &HostCancellationToken::new(),
        )
        .await
        .expect("second startup replay")
        .admitted;
        assert_eq!(admitted_again, 0);
        let snapshot = journal_snapshot(fixture.journey.journal_path());
        assert!(
            snapshot.starts_with("journal=0 delivery=0 withheld=1 receipts=0 cursors=1 "),
            "replay was not idempotent: {snapshot}"
        );
        assert_eq!(fixture.port.observe_calls.load(Ordering::Relaxed), 0);

        fixture
            .journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
    }

    /// Waits until the single journal row's content has been purged by the
    /// mounted worker's retention sweep, and returns its delivery state.
    async fn wait_for_content_purge(journal_path: &Path) -> String {
        let purged = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let connection = rusqlite::Connection::open(journal_path).expect("journal");
                let row = connection
                    .query_row(
                        "SELECT d.state, \
                         j.payload_bytes IS NULL AND j.content_forgotten_at_micros IS NOT NULL \
                         FROM tdmem_observation_journal_v1 j \
                         JOIN tdmem_observation_delivery_v1 d \
                         ON d.idempotency_key = j.idempotency_key",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
                    )
                    .ok();
                match row {
                    Some((state, true)) => return state,
                    _ => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await;
        match purged {
            Ok(state) => state,
            Err(error) => panic!(
                "the mounted retention sweep never purged the expired row: {error}; {}",
                journal_snapshot(journal_path)
            ),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remount_sweeps_rows_that_expired_while_the_journey_was_down() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
        let temp = TempDir::new().expect("temporary journey root");
        let project_id = ProjectId::new("project.observation-retention").expect("project id");
        let profile_root = temp.path().join("profile");
        let project_root = temp.path().join("project");
        let runtime =
            HostAdmissionTestRuntimeV1::project(&profile_root, &project_root, project_id.clone())
                .await
                .expect("registered project database");
        let database = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .expect("project database");
        let store = database.observation_store();
        let port = Arc::new(JourneyObservationProvider::new());
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).expect("journal root");
        let inputs = || ObservationJourneyMountInputsV1 {
            composition: composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>),
            profile_id: UserProfileId::new("profile.observation-retention").expect("profile id"),
            scope: scope(project_id.clone()),
            authoritative_project_id: project_id.clone(),
            provider: test_observation_mount(&(journal_root.clone()), 1)
                .expect("observer mount metadata"),
            store_data_root: journal_root.clone(),
            policy: ObservationJourneyPolicyV1::project_default(),
        };

        // First life: one canonical commit settles through the real path, via
        // the same helper the composition root calls.
        let journey = mount_and_replay(inputs(), store.clone(), &HostCancellationToken::new())
            .await
            .expect("mounted journey");
        let journal_path = journey.journal_path().to_path_buf();
        let session_id = SessionId::new("session.observation-retention").expect("session id");
        store
            .persist_observation(anchored_write(canonical_observation(
                &project_id,
                &session_id,
                "retained journey text",
            )))
            .await
            .expect("canonical observation commit");
        let (state, attempts) = wait_for_settlement(&journal_path).await;
        assert_eq!(
            (state.as_str(), attempts),
            ("acknowledged", 1),
            "{}",
            journal_snapshot(&journal_path)
        );
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        drop(journey);

        // A settled row keeps its bytes until its effective expiry, and the
        // first life's sweeps found nothing expired. Age it past its admitted
        // privacy expiry while the journey is down, the way a clock does
        // between two daemon lives.
        {
            let connection = rusqlite::Connection::open(&journal_path).unwrap();
            let present: bool = connection
                .query_row(
                    "SELECT payload_bytes IS NOT NULL FROM tdmem_observation_journal_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(present, "content was purged before expiry");
            let aged = tracedecay_contracts::now_micros().0 - 3_600_000_000;
            connection
                .execute(
                    "UPDATE tdmem_observation_journal_v1 SET expires_at_micros = ?1",
                    [aged],
                )
                .unwrap();
        }

        // Second life: the mounted worker's first retention turn purges the
        // expired content through the production path — the row is already
        // terminal, so nothing is re-terminalized — while startup replay
        // resumes at the durable watermark instead of re-admitting the record.
        let journey = mount_and_replay(inputs(), store.clone(), &HostCancellationToken::new())
            .await
            .expect("remounted journey");
        assert_eq!(journey.journal_path(), journal_path.as_path());
        let state = wait_for_content_purge(&journal_path).await;
        assert_eq!(
            state, "acknowledged",
            "a settled row is purged, not re-terminalized"
        );
        let snapshot = journal_snapshot(&journal_path);
        assert!(
            snapshot.starts_with("journal=1 ") && snapshot.contains("receipts=1 "),
            "replay must not re-admit and audit must survive purge: {snapshot}"
        );
        // Exactly the one delivery of the first life. The second life neither
        // re-admits the record nor re-delivers the settled row.
        assert_eq!(port.observe_calls.load(Ordering::Relaxed), 1);
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    // ---------------------------------------------------------------- //
    // Startup replay classification: a permanent refusal never mounts. //
    // ---------------------------------------------------------------- //

    /// A canonical store whose replay refuses with caller-chosen failures
    /// before it answers.
    ///
    /// The refusal comes back through the same trait method the real store
    /// answers on, so the classification runs over a real replay refusal
    /// rather than over a constructed error value.
    struct RefusingReplayPort {
        /// Refusals still to hand out; popped from the end.
        refusals: Mutex<Vec<ObservationStoreError>>,
        /// What replay returns once the refusals are spent.
        then: Vec<StoredObservation>,
    }

    impl ObservationStore for RefusingReplayPort {
        fn persist_observation(
            &self,
            _write: AnchoredObservationWrite,
        ) -> impl std::future::Future<Output = ObservationStoreResult<ObservationPersistOutcome>> + Send
        {
            async move { Err(read_only_observation_store_error("persist_observation")) }
        }

        fn persist_observations(
            &self,
            _writes: Vec<AnchoredObservationWrite>,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Vec<ObservationBatchPersistOutcome>>,
        > + Send {
            async move { Err(read_only_observation_store_error("persist_observations")) }
        }

        fn get_source_cursor(
            &self,
            _source: &ObservationSourceIdentityV1,
            _scope: &ObservationScopeV1,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Option<ObservationSourceCursorV1>>,
        > + Send {
            async move { Err(read_only_observation_store_error("get_source_cursor")) }
        }

        fn committed_source_cursors(
            &self,
            _source: &ObservationSourceIdentityV1,
            _scope: &ObservationScopeV1,
        ) -> impl std::future::Future<
            Output = ObservationStoreResult<Vec<ObservationSourceCursorV1>>,
        > + Send {
            async move {
                Err(read_only_observation_store_error(
                    "committed_source_cursors",
                ))
            }
        }

        fn advance_source_cursor(
            &self,
            _advance: ObservationCursorAdvance,
        ) -> impl std::future::Future<Output = ObservationStoreResult<CursorAdvanceOutcome>> + Send
        {
            async move { Err(read_only_observation_store_error("advance_source_cursor")) }
        }

        fn get_observation(
            &self,
            _observation_id: &CanonicalObservationIdV1,
        ) -> impl std::future::Future<Output = ObservationStoreResult<Option<StoredObservation>>> + Send
        {
            async move { Ok(None) }
        }

        fn replay_observations(
            &self,
            request: ObservationReplayRequest,
        ) -> impl std::future::Future<Output = ObservationStoreResult<Vec<StoredObservation>>> + Send
        {
            async move {
                let next = match self.refusals.lock() {
                    Ok(mut slot) => slot.pop(),
                    Err(poisoned) => poisoned.into_inner().pop(),
                };
                if let Some(error) = next {
                    return Err(error);
                }
                Ok(self
                    .then
                    .iter()
                    .filter(|record| record.sequence() > request.after_sequence())
                    .take(request.limit())
                    .cloned()
                    .collect())
            }
        }
    }

    fn busy_store_failure() -> ObservationStoreError {
        ObservationStoreError::Storage {
            operation: "replay_observations",
            source: Box::new(std::io::Error::other("canonical store was busy")),
        }
    }

    /// Mount inputs for a journey whose only collaborator under test is the
    /// canonical replay port.
    fn classification_mount_inputs(
        temp: &TempDir,
        project: &str,
    ) -> ObservationJourneyMountInputsV1 {
        let project_id = ProjectId::new(project).expect("project id");
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).expect("journal root");
        ObservationJourneyMountInputsV1 {
            composition: composition(Arc::new(JourneyObservationProvider::new())),
            profile_id: UserProfileId::new("profile.observation-startup-classification")
                .expect("profile id"),
            scope: scope(project_id.clone()),
            authoritative_project_id: project_id,
            provider: test_observation_mount(&(journal_root), 1).expect("observer mount metadata"),
            store_data_root: journal_root,
            policy: ObservationJourneyPolicyV1::project_default(),
        }
    }

    #[derive(Debug)]
    struct HeldInstanceProof {
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
        instance: String,
    }

    impl ObservationInstanceProofV1 for HeldInstanceProof {
        fn prove(
            &self,
            deadline: Instant,
            cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
        ) -> Result<Option<String>, TerminalCode> {
            self.entered.store(true, Ordering::Release);
            loop {
                if cancelled() {
                    return Err(TerminalCode::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(TerminalCode::DeadlineExceeded);
                }
                if self.release.load(Ordering::Acquire) {
                    return Ok(Some(self.instance.clone()));
                }
                thread::park_timeout(Duration::from_millis(1));
            }
        }
    }

    #[derive(Debug)]
    struct FailOnceInstanceProof {
        attempts: Arc<AtomicUsize>,
        instance: String,
    }

    impl ObservationInstanceProofV1 for FailOnceInstanceProof {
        fn prove(
            &self,
            deadline: Instant,
            cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
        ) -> Result<Option<String>, TerminalCode> {
            if cancelled() {
                return Err(TerminalCode::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(TerminalCode::DeadlineExceeded);
            }
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err(TerminalCode::ProviderUnavailable);
            }
            Ok(Some(self.instance.clone()))
        }
    }

    #[tokio::test]
    async fn instance_readiness_wait_observes_success_and_identity_refusal() {
        for proof in [
            Ok(Some("proved-instance".to_owned())),
            Err(TerminalCode::StateIncompatible),
        ] {
            let state = ProviderInstanceStateV1::from_mount(None, true);
            let stopping = HostCancellationToken::new();
            assert!(state.take_proof_attempt(Instant::now()));
            let waiter = state
                .readiness_changed
                .wait_until_async(Duration::from_secs(1), || state.readiness_outcome());
            tokio::pin!(waiter);
            tokio::select! {
                biased;
                outcome = &mut waiter => panic!("in-flight proof must not publish readiness: {outcome:?}"),
                () = tokio::task::yield_now() => {}
            }
            let should_be_ready = proof.is_ok();
            assert!(!state.finish_proof(proof, &stopping, Instant::now()));
            let outcome = waiter
                .await
                .expect("proof transition must notify its waiter");
            if should_be_ready {
                outcome.expect("successful proof installs readiness");
            } else {
                assert!(matches!(
                    outcome,
                    Err(ObservationJourneyError::ProviderInstanceUnavailable)
                ));
                assert!(state.get().is_none());
            }
        }
    }

    #[tokio::test]
    async fn instance_publication_wait_refuses_missing_proof_and_cancellation() {
        let temp = TempDir::new().expect("temporary journey root");
        let mut inputs = classification_mount_inputs(&temp, "project.instance-publication-refusal");
        inputs.provider.provider_instance_id = None;
        inputs.provider.instance_proof = None;
        let journey = mount_observer_dormant(inputs, &HostCancellationToken::new())
            .await
            .expect("dormant journey with unavailable instance");
        let missing = journey
            .await_instance_ready(&HostCancellationToken::new(), Duration::from_secs(1))
            .await;
        assert!(matches!(
            missing,
            Err(ObservationJourneyError::ProviderInstanceUnavailable)
        ));
        let cancellation = HostCancellationToken::new();
        cancellation.cancel();
        let cancelled = journey
            .await_instance_ready(&cancellation, Duration::from_secs(1))
            .await;
        assert!(matches!(
            cancelled,
            Err(ObservationJourneyError::Cancelled { admitted: 0 })
        ));
        let failures = journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn dispatch_instance_refresh_cannot_revive_cancelled_or_unproved_readiness() {
        let state = ProviderInstanceStateV1::from_mount(Some("instance.predecessor".into()), false);
        let cancellation = CancellationToken::new();
        state.refresh_from_readiness("instance.replacement", &cancellation);
        assert_eq!(state.get().as_deref(), Some("instance.replacement"));

        cancellation.cancel();
        state.refresh_from_readiness("instance.late", &cancellation);
        assert_eq!(state.get().as_deref(), Some("instance.replacement"));
        state.cancel();
        state.refresh_from_readiness("instance.late", &CancellationToken::new());
        assert!(state.is_unavailable());

        let pending = ProviderInstanceStateV1::from_mount(None, true);
        pending.refresh_from_readiness("instance.unclaimed", &CancellationToken::new());
        assert!(pending.is_pending());
        assert!(pending.get().is_none());
    }

    #[test]
    fn optional_instance_proof_dormant_activation_starts_lifetime_on_claim() {
        let state = ProviderInstanceStateV1::from_mount(None, true);
        let stopping = HostCancellationToken::new();
        // Advance the injected claim instant beyond the full retry lifetime.
        // A dormant mount must still get its first proof attempt when it is
        // activated later; the lifetime starts at this claim, not construction.
        let delayed_activation = Instant::now()
            .checked_add(INSTANCE_PROOF_MAX_LIFETIME + Duration::from_secs(1))
            .unwrap();

        assert!(state.take_proof_attempt(delayed_activation));
        assert!(!state.finish_proof(
            Ok(Some("activated-instance".to_owned())),
            &stopping,
            delayed_activation,
        ));
        assert_eq!(
            state.get().as_deref(),
            Some("activated-instance"),
            "a delayed dormant activation must not expire before its first proof"
        );
    }

    #[test]
    fn optional_instance_proof_permanent_failure_is_not_retried() {
        for terminal in [
            TerminalCode::StateIncompatible,
            TerminalCode::ResetRequired,
            TerminalCode::CapabilityUnsupported,
            TerminalCode::InvalidRequest,
        ] {
            let state = ProviderInstanceStateV1::from_mount(None, true);
            let stopping = HostCancellationToken::new();
            let now = Instant::now();
            assert!(state.take_proof_attempt(now));
            assert!(!state.finish_proof(Err(terminal), &stopping, now));
            assert!(state.is_unavailable());
            assert!(!state.take_proof_attempt(now.checked_add(Duration::from_secs(2)).unwrap()));
        }
    }

    #[test]
    fn optional_instance_proof_transient_failure_stops_at_attempt_bound() {
        let state = ProviderInstanceStateV1::from_mount(None, true);
        let stopping = HostCancellationToken::new();
        let mut now = Instant::now();

        for attempt in 1..=INSTANCE_PROOF_MAX_ATTEMPTS {
            assert!(state.take_proof_attempt(now), "proof attempt {attempt}");
            let retry_scheduled =
                state.finish_proof(Err(TerminalCode::ProviderUnavailable), &stopping, now);
            if attempt < INSTANCE_PROOF_MAX_ATTEMPTS {
                assert!(retry_scheduled, "attempt {attempt} should retry");
                now = now.checked_add(INSTANCE_PROOF_RETRY_BACKOFF).unwrap();
            } else {
                assert!(!retry_scheduled, "attempt budget must terminate retries");
            }
        }

        assert!(state.is_unavailable());
        assert!(!state.take_proof_attempt(now.checked_add(INSTANCE_PROOF_RETRY_BACKOFF).unwrap()));
    }

    #[test]
    fn optional_instance_proof_cancellation_cannot_install_ready() {
        let state = ProviderInstanceStateV1::from_mount(None, true);
        let stopping = HostCancellationToken::new();
        let now = Instant::now();
        assert!(state.take_proof_attempt(now));
        stopping.cancel();

        assert!(!state.finish_proof(Ok(Some("late-instance".to_owned())), &stopping, now,));
        assert!(state.is_unavailable());
        assert!(state.get().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn optional_instance_proof_retries_after_transient_failure_without_remount() {
        let temp = TempDir::new().unwrap();
        let project = "project.observation-startup-classification";
        let project_id = ProjectId::new(project).unwrap();
        let session = SessionId::new("session.optional-bootstrap-retry").unwrap();
        let record = settled_record(
            1,
            canonical_observation(&project_id, &session, "pending observer message"),
        );
        let store = || RefusingReplayPort {
            refusals: Mutex::new(vec![]),
            then: vec![record.clone()],
        };

        // Seed one pending row, then close that first journey. The observer
        // below must settle this same row after its proof fails once.
        let mut seed_inputs = classification_mount_inputs(&temp, project);
        let expected_instance = seed_inputs.provider.provider_instance_id.take().unwrap();
        // Keep the seed dormant so no delivery worker can race this assertion
        // and settle the row before the proof-retry journey owns it.
        let seed = mount_observer_dormant(seed_inputs, &HostCancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            run_startup_replay(seed.as_ref(), &store(), &HostCancellationToken::new())
                .await
                .unwrap()
                .admitted,
            1
        );
        let pending_path = seed.journal_path().to_owned();
        assert!(!journal_snapshot(&pending_path).contains("acknowledged"));
        seed.shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        drop(seed);

        let attempts = Arc::new(AtomicUsize::new(0));
        let mut inputs = classification_mount_inputs(&temp, project);
        inputs.provider.provider_instance_id = None;
        inputs.provider.instance_proof = Some(Arc::new(FailOnceInstanceProof {
            attempts: Arc::clone(&attempts),
            instance: expected_instance.clone(),
        }));
        let observer = mount_observer_dormant(inputs, &HostCancellationToken::new())
            .await
            .unwrap();
        observer.start_observer_with_live_replay(store()).unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if observer.provider_instance_id.get().as_deref()
                    == Some(expected_instance.as_str())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the same journey must retry and record the instance");
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        assert_eq!(
            wait_for_settlement_within(&pending_path, Duration::from_secs(5)).await,
            ("acknowledged".to_owned(), 1)
        );
        assert_eq!(observer.journal_path(), pending_path.as_path());

        observer
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn optional_instance_bootstrap_does_not_block_ready_journey_and_drains_restart_pending_rows()
     {
        let temp = TempDir::new().unwrap();
        let project = "project.observation-startup-classification";
        let project_id = ProjectId::new(project).unwrap();
        let session = SessionId::new("session.optional-bootstrap-pending").unwrap();
        let record = settled_record(
            1,
            canonical_observation(&project_id, &session, "pending observer message"),
        );
        let store = || RefusingReplayPort {
            refusals: Mutex::new(vec![]),
            then: vec![record.clone()],
        };
        // Persist admission and its watermark without a proved delivery instance.
        let mut seed_inputs = classification_mount_inputs(&temp, project);
        let expected_instance = seed_inputs.provider.provider_instance_id.take().unwrap();
        // Keep the seed dormant so this test controls exactly when delivery
        // begins and the pending row cannot be settled by a racing worker.
        let seed = mount_observer_dormant(seed_inputs, &HostCancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            run_startup_replay(seed.as_ref(), &store(), &HostCancellationToken::new())
                .await
                .unwrap()
                .admitted,
            1
        );
        let pending_path = seed.journal_path().to_owned();
        assert!(!journal_snapshot(&pending_path).contains("acknowledged"));
        seed.shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        drop(seed);

        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let mut inputs = classification_mount_inputs(&temp, project);
        inputs.provider.provider_instance_id = None;
        inputs.provider.instance_proof = Some(Arc::new(HeldInstanceProof {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            instance: expected_instance,
        }));
        let observer = tokio::time::timeout(
            Duration::from_secs(1),
            mount_observer_dormant(inputs, &HostCancellationToken::new()),
        )
        .await
        .expect("mount must not await optional bootstrap")
        .unwrap();
        assert!(!entered.load(Ordering::Acquire));
        assert!(observer.worker.lock().unwrap().is_none());
        assert!(observer.live_replay_task.lock().unwrap().is_none());
        observer.start_observer_with_live_replay(store()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(observer.provider_instance_id.get().is_none());

        let ready_root = TempDir::new().unwrap();
        let ready = mount_and_replay(
            classification_mount_inputs(&ready_root, project),
            store(),
            &HostCancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            wait_for_settlement(ready.journal_path()).await,
            ("acknowledged".to_owned(), 1)
        );
        assert!(
            observer.provider_instance_id.get().is_none(),
            "an independent ready journey settled while observer proof was held"
        );
        release.store(true, Ordering::Release);
        assert_eq!(
            wait_for_settlement(&pending_path).await,
            ("acknowledged".to_owned(), 1)
        );
        ready
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        observer
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn optional_instance_bootstrap_observes_journey_shutdown() {
        let temp = TempDir::new().unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let mut inputs =
            classification_mount_inputs(&temp, "project.observation-startup-classification");
        let instance = inputs.provider.provider_instance_id.take().unwrap();
        inputs.provider.instance_proof = Some(Arc::new(HeldInstanceProof {
            entered: Arc::clone(&entered),
            release: Arc::new(AtomicBool::new(false)),
            instance,
        }));
        let observer = mount_observer_dormant(inputs, &HostCancellationToken::new())
            .await
            .unwrap();
        assert!(!entered.load(Ordering::Acquire));
        observer
            .start_observer_with_live_replay(RefusingReplayPort {
                refusals: Mutex::new(vec![]),
                then: vec![],
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let started = Instant::now();
        let failures = observer
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert!(
            failures.is_empty(),
            "shutdown must join the cancelled proof: {failures:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(observer.provider_instance_id.is_unavailable());
    }

    #[tokio::test]
    async fn dormant_observer_shutdown_prevents_late_worker_activation() {
        let temp = TempDir::new().unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let mut inputs =
            classification_mount_inputs(&temp, "project.observation-startup-classification");
        let instance = inputs.provider.provider_instance_id.take().unwrap();
        inputs.provider.instance_proof = Some(Arc::new(HeldInstanceProof {
            entered: Arc::clone(&entered),
            release: Arc::new(AtomicBool::new(false)),
            instance,
        }));
        let observer = mount_observer_dormant(inputs, &HostCancellationToken::new())
            .await
            .unwrap();
        assert!(observer.worker.lock().unwrap().is_none());
        assert!(observer.live_replay_task.lock().unwrap().is_none());
        assert!(
            observer
                .shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_empty()
        );
        assert!(matches!(
            observer.start_observer_with_live_replay(RefusingReplayPort {
                refusals: Mutex::new(vec![]),
                then: vec![],
            }),
            Err(ObservationJourneyError::Cancelled { admitted: 0 })
        ));
        assert!(matches!(
            observer.start_live_replay(RefusingReplayPort {
                refusals: Mutex::new(vec![]),
                then: vec![],
            }),
            Err(ObservationJourneyError::Cancelled { admitted: 0 })
        ));
        assert!(observer.worker.lock().unwrap().is_none());
        assert!(observer.live_replay_task.lock().unwrap().is_none());
        drop(observer);
        assert!(
            !entered.load(Ordering::Acquire),
            "discarded candidate must never prove a provider instance"
        );
    }

    /// Acceptance: the classification is fail-closed. Only a storage-layer
    /// refusal, a cancelled ingest task, and an admitted stale handshake are
    /// retryable; evidence defects remain permanent because replaying the same bytes
    /// produces the same answer forever.
    #[test]
    fn replay_recoverability_is_fail_closed() {
        assert_eq!(
            replay_recoverability(&ObservationJourneyError::Replay(busy_store_failure())),
            ReplayRecoverabilityV1::Retryable
        );
        assert_eq!(
            replay_recoverability(&ObservationJourneyError::Replay(
                ObservationStoreError::CursorObservationMismatch
            )),
            ReplayRecoverabilityV1::Permanent
        );
        assert_eq!(
            replay_recoverability(&ObservationJourneyError::Ingress(
                ObservationRuntimeError::InvalidDispatchRequest {
                    field: "attempt_budget_micros"
                }
            )),
            ReplayRecoverabilityV1::Permanent
        );
        assert_eq!(
            replay_recoverability(&ObservationJourneyError::Journal(
                ObservationJournalError::EnvelopeDigestMismatch
            )),
            ReplayRecoverabilityV1::Permanent
        );
        assert_eq!(
            replay_recoverability(&ObservationJourneyError::EntropyUnavailable),
            ReplayRecoverabilityV1::Permanent
        );
    }

    #[test]
    fn only_nested_stale_handshake_admission_is_retryable() {
        for terminal_code in [
            Some(TerminalCode::StaleIdentity),
            Some(TerminalCode::InvalidRequest),
            Some(TerminalCode::ScopeMismatch),
            Some(TerminalCode::ProviderUnavailable),
            None,
        ] {
            let readiness = SupervisedReadinessError::Unavailable {
                exact_scope_sha256: "0".repeat(64),
                kind: tracedecay_memory_provider_registry::DegradationKindV1::HandshakeRefused,
                terminal_code,
                detail: "text is not used to classify readiness".to_owned(),
                retry_in_micros: 1_000,
            };
            assert_eq!(
                replay_recoverability(&ObservationJourneyError::SupervisedReadiness(
                    readiness.clone()
                )),
                ReplayRecoverabilityV1::Permanent,
                "only the canonical admission boundary gains replay recovery"
            );
            let error = ObservationJourneyError::Ingress(ObservationRuntimeError::Admission {
                source_event_id: "record.stale-handshake".to_owned(),
                source_sequence: 1,
                cause: AdapterFailureV1::new(AdmissionAdapterError::Readiness {
                    source_event_id: "record.stale-handshake".to_owned(),
                    source: Box::new(ObservationJourneyError::SupervisedReadiness(readiness)),
                }),
            });
            let expected = if terminal_code == Some(TerminalCode::StaleIdentity) {
                ReplayRecoverabilityV1::Retryable
            } else {
                ReplayRecoverabilityV1::Permanent
            };
            assert_eq!(replay_recoverability(&error), expected, "{terminal_code:?}");
        }
    }

    /// Acceptance: a permanent startup replay refusal refuses the mount.
    ///
    /// This is the defect the catch-all used to hide. A canonical record the
    /// contract cannot read is not something a retry clears, so a mount that
    /// substituted `admitted = 0` and returned `Ok` left a committed
    /// observation undelivered for as long as the project stayed open while
    /// project open reported success.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permanent_startup_replay_failure_refuses_the_mount() {
        let temp = TempDir::new().expect("temporary journey root");
        let store = RefusingReplayPort {
            refusals: Mutex::new(vec![ObservationStoreError::CursorObservationMismatch]),
            then: Vec::new(),
        };
        let outcome = mount_and_replay(
            classification_mount_inputs(&temp, "project.observation-permanent"),
            store,
            &HostCancellationToken::new(),
        )
        .await;
        let Err(error) = outcome else {
            panic!("a permanent startup replay refusal must not mount a healthy journey");
        };
        assert!(
            matches!(
                error,
                ObservationJourneyError::StartupReplayPermanent { .. }
            ),
            "unexpected terminal: {error}"
        );
    }

    /// The same is true of an ingress refusal and of a journal refusal that
    /// reaches the pass as an error: neither is an attempt that can be retried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permanent_replay_limit_refusal_refuses_the_mount() {
        let temp = TempDir::new().expect("temporary journey root");
        let store = RefusingReplayPort {
            refusals: Mutex::new(vec![ObservationStoreError::InvalidReplayLimit {
                limit: 0,
                max: 512,
            }]),
            then: Vec::new(),
        };
        let outcome = mount_and_replay(
            classification_mount_inputs(&temp, "project.observation-permanent-limit"),
            store,
            &HostCancellationToken::new(),
        )
        .await;
        let Err(error) = outcome else {
            panic!("a permanent startup replay refusal must not mount a healthy journey");
        };
        assert!(
            matches!(
                error,
                ObservationJourneyError::StartupReplayPermanent { .. }
            ),
            "unexpected terminal: {error}"
        );
    }

    /// Acceptance: a retryable refusal keeps the project open *and* the retry
    /// it promises actually happens.
    ///
    /// The mount is only allowed to survive a storage-layer refusal because
    /// live replay converges on the record afterwards, so the test holds the
    /// mount to that claim rather than to the `Ok` alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retryable_startup_replay_failure_mounts_and_live_replay_converges() {
        let temp = TempDir::new().expect("temporary journey root");
        let project_id =
            ProjectId::new("project.observation-startup-classification").expect("project id");
        let session_id =
            SessionId::new("session.observation-startup-retryable").expect("session id");
        let record = settled_record(
            1,
            canonical_observation(&project_id, &session_id, "settled behind a busy store"),
        );
        let store = RefusingReplayPort {
            refusals: Mutex::new(vec![busy_store_failure()]),
            then: vec![record],
        };
        let journey = mount_and_replay(
            classification_mount_inputs(&temp, "project.observation-startup-classification"),
            store,
            &HostCancellationToken::new(),
        )
        .await
        .expect("a retryable startup replay refusal keeps the project open");
        let (state, attempts) = wait_for_settlement(journey.journal_path()).await;
        assert_eq!(
            (state.as_str(), attempts),
            ("acknowledged", 1),
            "live replay never converged on the record the busy store withheld: {}",
            journal_snapshot(journey.journal_path())
        );
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    /// A live replay pass that fails is recorded as a
    /// typed stall with its recoverability, and the stall is cleared by the
    /// pass that gets through.
    ///
    /// This is the defect the live loop's catch-all used to hide. A refusal
    /// that no retry can clear stopped the stream at its watermark while the
    /// only trace was an identical `warn` every backoff interval:
    /// `halted_on` reported nothing, shutdown reported nothing, and a
    /// committed observation stayed undelivered behind a journey every surface
    /// called healthy. The refusal is now classified and recorded, and because
    /// the recorded stall is cleared rather than remembered, this test also
    /// holds the loop to actually converging on the record afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permanent_live_replay_failure_is_recorded_typed_and_cleared_when_the_record_lands() {
        let temp = TempDir::new().expect("temporary journey root");
        let project_id =
            ProjectId::new("project.observation-startup-classification").expect("project id");
        let session_id = SessionId::new("session.observation-live-fault").expect("session id");
        let record = settled_record(
            1,
            canonical_observation(
                &project_id,
                &session_id,
                "settled behind a permanent refusal",
            ),
        );
        // Not a storage-layer failure: an unreadable cursor describes the
        // evidence, so every later pass answers it the same way.
        let store = RefusingReplayPort {
            refusals: Mutex::new(vec![ObservationStoreError::CursorObservationMismatch]),
            then: vec![record],
        };
        let journey = mount_project_observation_journey(classification_mount_inputs(
            &temp,
            "project.observation-startup-classification",
        ))
        .expect("mount the journey without running startup replay");
        journey
            .start_live_replay(store)
            .expect("live replay task starts");

        let stall = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(stall) = journey.stalled_on() {
                    return stall;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a failing live replay pass must surface a typed stall");
        let LiveReplayStallV1::Faulted(fault) = stall else {
            panic!("a pass that failed is not a positional journal halt: {stall:?}");
        };
        assert_eq!(
            fault.recoverability,
            ReplayRecoverabilityV1::Permanent,
            "an unreadable canonical cursor is not something a retry clears"
        );
        assert!(
            fault
                .summary
                .contains("canonical observation replay failed"),
            "the stall must carry the refusal it stood on: {}",
            fault.summary
        );
        assert!(
            journey.halted_on().is_none(),
            "a failed pass names no refused source position"
        );

        // The refusal is spent, so the next pass gets through: the record the
        // failure stood in front of is delivered, and the stall is cleared
        // rather than left standing over a healthy stream. The budget spans the
        // backoff a recorded fault deliberately waits out.
        let (state, attempts) =
            wait_for_settlement_within(journey.journal_path(), Duration::from_secs(30)).await;
        assert_eq!(
            (state.as_str(), attempts),
            ("acknowledged", 1),
            "live replay never converged after the refusal was spent: {}",
            journal_snapshot(journey.journal_path())
        );
        assert_eq!(
            journey.stalled_on(),
            None,
            "a pass that got through must clear the stall it recorded"
        );
        let failures = journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// A standing condition is reported once.
    ///
    /// The slot is what keeps a permanent refusal from being re-reported at
    /// the backoff rate, so the property under test is exactly "is this new?":
    /// the same condition answers `false` and a different one answers `true`.
    /// Both classifications reach the slot, so a retryable failure is visible
    /// too — labelled as the thing a later pass can clear.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_standing_replay_fault_is_reported_once_and_a_different_one_replaces_it() {
        let temp = TempDir::new().expect("temporary journey root");
        let journey = mount_project_observation_journey(classification_mount_inputs(
            &temp,
            "project.observation-standing-fault",
        ))
        .expect("mount the journey");

        let permanent =
            ObservationJourneyError::Replay(ObservationStoreError::CursorObservationMismatch);
        journey.record_fault(replay_recoverability(&permanent), &permanent);
        let recorded = journey.stalled_on().expect("the fault is recorded");
        assert_eq!(
            recorded,
            LiveReplayStallV1::Faulted(LiveReplayFaultV1 {
                recoverability: ReplayRecoverabilityV1::Permanent,
                summary: permanent.to_string(),
            })
        );
        assert!(
            !journey.remember_stall(recorded.clone()),
            "the same standing condition must not be reported twice"
        );

        let retryable = ObservationJourneyError::Replay(busy_store_failure());
        journey.record_fault(replay_recoverability(&retryable), &retryable);
        let recorded = journey.stalled_on().expect("the second fault is recorded");
        assert_eq!(
            recorded,
            LiveReplayStallV1::Faulted(LiveReplayFaultV1 {
                recoverability: ReplayRecoverabilityV1::Retryable,
                summary: retryable.to_string(),
            }),
            "a different condition replaces the one that was standing"
        );

        journey.clear_stall();
        assert_eq!(journey.stalled_on(), None);
        assert!(
            journey.remember_stall(recorded),
            "a cleared condition is new again when it comes back"
        );
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    // ------------------------------------------------------------------ //
    // Blocking journal I/O never runs on a runtime worker.               //
    // ------------------------------------------------------------------ //

    /// Holds this journal's write lock from a plain thread for a bounded
    /// while, exactly as a second process would.
    ///
    /// The point is not the lock: it is that opening the journal, and reaping
    /// its leases, are synchronous SQLite calls that can genuinely wait. A
    /// mount or a shutdown that pays that wait on a tokio worker parks the
    /// runtime, and on a single-worker runtime it parks all of it.
    fn hold_journal_write_lock(path: &Path, hold: Duration) -> std::thread::JoinHandle<()> {
        let path = path.to_path_buf();
        let (ready, holding) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut connection = rusqlite::Connection::open(&path).unwrap();
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            ready.send(()).unwrap();
            std::thread::sleep(hold);
            transaction.rollback().unwrap();
        });
        holding.recv().unwrap();
        handle
    }

    /// A journey mount opens a SQLite file and applies its schema. On one
    /// runtime worker, doing that inline stops every other task on that
    /// worker for as long as the disk — or another writer — takes.
    ///
    /// The heartbeat is counted *inside* the mounting task, between the
    /// instant before the mount call and the instant after, so the window is
    /// exactly the mount and nothing else. An inline mount has no await point
    /// in that window at all, so a task sharing its worker cannot advance the
    /// counter even once; a mount on the blocking pool leaves the worker free
    /// for the whole wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn mounting_a_journey_does_not_park_the_runtime_worker() {
        let temp = TempDir::new().unwrap();
        let project_id = ProjectId::new("project.mount-off-worker").unwrap();
        let profile_root = temp.path().join("profile");
        let project_root = temp.path().join("project");
        let runtime =
            HostAdmissionTestRuntimeV1::project(&profile_root, &project_root, project_id.clone())
                .await
                .expect("registered project database");
        let database = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .expect("project database");
        let store = database.observation_store();
        let port = Arc::new(JourneyObservationProvider::new());
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).unwrap();
        let inputs = || ObservationJourneyMountInputsV1 {
            composition: composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>),
            profile_id: UserProfileId::new("profile.mount-off-worker").unwrap(),
            scope: scope(project_id.clone()),
            authoritative_project_id: project_id.clone(),
            provider: test_observation_mount(&(journal_root.clone()), 1)
                .expect("observer mount metadata"),
            store_data_root: journal_root.clone(),
            policy: ObservationJourneyPolicyV1::project_default(),
        };

        // First life creates the journal file, so the second mount is the one
        // a restart actually performs: an existing store, opened again.
        let first = mount_and_replay(inputs(), store.clone(), &HostCancellationToken::new())
            .await
            .expect("first mount");
        let journal_path = first.journal_path().to_path_buf();
        first
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        drop(first);

        let beats = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = tokio::spawn({
            let beats = Arc::clone(&beats);
            let stop = Arc::clone(&stop);
            async move {
                while !stop.load(Ordering::Relaxed) {
                    beats.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });

        // Another writer holds the journal for long enough that the schema
        // transaction inside the open really does wait.
        let holder = hold_journal_write_lock(&journal_path, Duration::from_millis(400));

        let mount = tokio::spawn({
            let beats = Arc::clone(&beats);
            let inputs = inputs();
            let store = store.clone();
            async move {
                let before = beats.load(Ordering::Relaxed);
                let journey = mount_and_replay(inputs, store, &HostCancellationToken::new()).await;
                let after = beats.load(Ordering::Relaxed);
                (journey, before, after)
            }
        });
        let (journey, before, after) = mount.await.expect("the mounting task");
        let journey = journey.expect("second mount");
        stop.store(true, Ordering::Relaxed);
        heartbeat.await.expect("the heartbeat task");
        holder.join().unwrap();

        assert!(
            after - before >= 1_000,
            "the runtime worker advanced only {} times while the journey mounted against a \
             contended journal: the open is still running on the worker",
            after - before,
        );
        assert_eq!(journey.journal_path(), journal_path.as_path());
        journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
    }

    /// The shutdown pass reaps lapsed leases and reads the lane back, both
    /// synchronous SQLite against the file the delivery worker was writing.
    ///
    /// Run inline it had no deadline at all: behind another writer it waited
    /// out the connection's whole five-second busy timeout, on a runtime
    /// worker, during the daemon's stop. On the blocking pool under the
    /// daemon's own deadline it does neither — it reports the deadline as a
    /// typed shutdown failure and hands the worker back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_contended_shutdown_pass_reports_the_deadline_instead_of_waiting_it_out() {
        let temp = TempDir::new().unwrap();
        let project_id = ProjectId::new("project.shutdown-off-worker").unwrap();
        let profile_root = temp.path().join("profile");
        let project_root = temp.path().join("project");
        let runtime =
            HostAdmissionTestRuntimeV1::project(&profile_root, &project_root, project_id.clone())
                .await
                .expect("registered project database");
        let database = runtime
            .registered_database_arc(HostAdmissionScope::Project)
            .expect("project database");
        let store = database.observation_store();
        let port = Arc::new(JourneyObservationProvider::new());
        let journal_root = temp.path().join("journey");
        std::fs::create_dir_all(&journal_root).unwrap();
        let journey = mount_observer_dormant(
            ObservationJourneyMountInputsV1 {
                composition: composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>),
                profile_id: UserProfileId::new("profile.shutdown-off-worker").unwrap(),
                scope: scope(project_id.clone()),
                authoritative_project_id: project_id.clone(),
                provider: test_observation_mount(&(journal_root.clone()), 1)
                    .expect("observer mount metadata"),
                store_data_root: journal_root.clone(),
                policy: ObservationJourneyPolicyV1::project_default(),
            },
            &HostCancellationToken::new(),
        )
        .await
        .expect("mounted journey");
        let journal_path = journey.journal_path().to_path_buf();

        // Release only after shutdown returns (or the scheduling guard fires),
        // never after a sleep. Dropping the guard also releases and joins the
        // writer on assertion failure or cancellation of this test future.
        struct HeldWriter {
            release: Option<std::sync::mpsc::Sender<()>>,
            thread: Option<std::thread::JoinHandle<()>>,
            reaper: Option<std::thread::JoinHandle<Result<u32, ObservationJournalError>>>,
        }
        impl Drop for HeldWriter {
            fn drop(&mut self) {
                drop(self.release.take());
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
                if let Some(reaper) = self.reaper.take() {
                    let _ = reaper.join();
                }
            }
        }
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (ready, holding) = tokio::sync::oneshot::channel();
        let mut holder = HeldWriter {
            release: Some(release),
            reaper: None,
            thread: Some(std::thread::spawn(move || {
                let mut connection = rusqlite::Connection::open(&journal_path).unwrap();
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                ready.send(()).unwrap();
                let _ = released.recv();
                transaction.rollback().unwrap();
            })),
        };
        holding.await.expect("writer holds the transaction");

        let source_sha256 = hex::encode(Sha256::digest(journey.source_stream.as_str().as_bytes()));
        let fence_probe = || {
            let journal = Arc::clone(&journey.journal);
            let provider_id = journey.provider_id.clone();
            let source_sha256 = source_sha256.clone();
            tokio::task::spawn_blocking(move || {
                journal.read_provider_source_fence_bounded(
                    &provider_id,
                    &source_sha256,
                    RecoveryTimeBudgetV1 {
                        remaining_micros: 50_000,
                    },
                    &CancellationToken::new(),
                )
            })
        };
        // An external WAL writer alone does not block these committed reads.
        // Establish that before creating contention on the journal connection.
        let backlog = tokio::time::timeout(Duration::from_millis(500), async {
            assert!(
                fence_probe()
                    .await
                    .expect("baseline fence reader")
                    .expect("the WAL fence read does not reserve the writer")
                    .is_none()
            );
            journey
                .refresh_backlog()
                .await
                .expect("the WAL backlog read does not reserve the writer")
        })
        .await
        .expect("baseline reads must finish while the external writer is held");
        assert_eq!(backlog.queue_items, 0);
        assert_eq!(backlog.queue_bytes, 0);

        journey
            .start_observer_with_live_replay(store.clone())
            .expect("activate the delivery and replay workers after the WAL read baseline");
        holder.reaper = Some(std::thread::spawn({
            let journal = Arc::clone(&journey.journal);
            move || journal.reap_expired_leases(tracedecay_contracts::now_micros().0, 1)
        }));
        // Observe same-connection contention through the bounded reader that
        // succeeded against the external writer, rather than assuming that a
        // newly spawned reap has already acquired the mutex.
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                match fence_probe().await.expect("journal contention reader") {
                    Err(ObservationJournalError::BudgetExhausted {
                        operation: "read_provider_source_fence",
                    }) => break,
                    Ok(None) => tokio::task::yield_now().await,
                    outcome => panic!("unexpected journal contention measurement: {outcome:?}"),
                }
            }
        })
        .await
        .expect("journal connection contention must be observable before shutdown");
        assert!(
            !holder.reaper.as_ref().unwrap().is_finished(),
            "the real reap finished before shutdown began"
        );
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            journey.shutdown(tokio::time::Instant::now() + Duration::from_millis(50)),
        )
        .await;
        let writer_still_held = !holder.thread.as_ref().unwrap().is_finished();
        // Cleanup before asserting even when the scheduling guard expired.
        drop(holder.release.take());
        holder.thread.take().unwrap().join().unwrap();
        assert_eq!(
            holder
                .reaper
                .take()
                .unwrap()
                .join()
                .expect("contended reap thread")
                .expect("the reap completes after the external writer is released"),
            0
        );
        let failures = result.expect("shutdown must return while the writer remains held");
        assert!(
            writer_still_held,
            "writer released before shutdown returned"
        );
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                ObservationShutdownFailureV1::BacklogRefreshDeadline
            )),
            "the initial backlog refresh must report its deadline: {failures:?}"
        );
        // An expired initial refresh must not skip the later bounded reap.
        assert!(
            failures.iter().any(|failure| matches!(
                failure,
                ObservationShutdownFailureV1::ShutdownPassDeadline
            )),
            "a shutdown pass that could not finish inside the deadline must say so: {failures:?}"
        );

        // Nothing was stranded by giving up: the reap the deadline cut short
        // is repeatable, and a later pass with room to run reports cleanly.
        let clean = journey
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        assert!(
            clean.is_empty(),
            "an uncontended shutdown pass must complete: {clean:?}"
        );
    }
}
