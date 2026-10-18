//! The Claude Code and Codex host memory journeys, driven as real subprocesses
//! against a live daemon.
//!
//! Everything here is the shipped `tracedecay` binary: the daemon is
//! `tracedecay daemon run`, the operator gates are committed through
//! `tracedecay tool tracedecay_configuration_set`, and the hooks are the processes
//! Claude Code and Codex spawn (their native session-start and Stop commands,
//! with native payloads on stdin). The later agent question is
//! `tracedecay tool tracedecay_context`. Nothing in this file constructs a
//! hook envelope, seals a binding, or runs an administrative import; the only
//! fixture action that can ingest between the negative control and the first
//! settled rows is the shipped hook process.
//!
//! That ordering is the point. The daemon runs a transcript import when a
//! project mounts, so a journey that writes the transcript *before* the daemon
//! comes up cannot tell a working hook from a broken one — startup would have
//! ingested the same rows. Here the daemon is already up and has already
//! mounted the project (the baseline `tracedecay_context` call below forces
//! that). After startup import and projection complete, the fixture opens an
//! empty Claude transcript or metadata-only Codex rollout and runs SessionStart
//! to establish the live baseline. It then appends the first turn and, when NCM
//! participates, proves its journal stays empty across a bounded settling
//! window before Stop. Background history reconciliation remains enabled.
//!
//! Native is upstream memory: with Native selected there is no provider lane
//! and no observation journal. The ignored real-NCM variants select NCM with
//! Native disabled, retain Native as active with NCM observing, or roll back
//! from NCM to Native. They share only the installed model artifacts; mutable
//! NCM state belongs to the isolated HOME.
//!
//! # What this proves about the product
//!
//! * an operator can reach the provider host through the shipped CLI: the
//!   `memory-provider-host` feature is a real CLI feature, so the binary under
//!   test contains the mount (`required-features` on this target);
//! * Claude Code and Codex lifecycle hook invocations commit their session's
//!   messages as canonical project observations, which NCM's observation
//!   journey settles exactly once, each carrying the host's attribution;
//! * NCM answers later `tracedecay_context` calls of this and other sessions
//!   from its own state, with host-confirmed canonical evidence, and nothing is
//!   delivered to it at recall time or redelivered after a restart.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "product_memory_provider_claude_host_journey/provider_control_journeys.rs"]
mod provider_control_journeys;

use serde_json::{Value, json};
use tempfile::TempDir;
use tracedecay_daemon_identity::authority::DaemonAuthorityRecord;
use tracedecay_daemon_protocol::BrokerStream;
use tracedecay_domain::configuration::{
    MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY, MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
    MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY, MemoryProviderNcmObserverV1,
    MemoryProviderRecallDegradationCauseV1, MemoryProviderRecallDegradationV1,
    MemoryProviderRecallRoutingV1,
};
use tracedecay_domain::{
    CanonicalMessageRoleV1, CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1,
    CanonicalObservationFactV1, CanonicalObservationIdV1, CanonicalObservationRelationsV1,
    ObservationId, ObservationIdentityMaterialV1, ObservationOrderingDomainV1, ObservationScopeV1,
    ObservationSourceGenerationV1, ObservationSourceIdentityV1, ObservationSourceRangeV1,
    ProjectId, ProviderId, RetentionClass, SessionId,
};
use tracedecay_memory_observation::{
    AdmittedObservationV1, DeliveryStateV1, JournalInspectionFilterV1, JournalInspectionRowV1,
    ObservationCommittedEffectV1, ObservationDeliveryReceiptV1, ObservationJournalReaderV1,
    ObservationOutcomeV1, RetentionPolicyV1, SqliteObservationJournal,
};
use tracedecay_sessions::admission::HostAdmissionScope;
use tracedecay_sessions::observation::{
    CaptureObservationOutcome, CaptureObservationRequest, ObservationApplication,
    ObservationCancellation,
};

/// The provider-control journey needs one source with a real canonical
/// revision. The shipped Claude/Codex normalizers currently emit revision-less
/// file evidence, so the test-owned producer below feeds the same public
/// parser, sanitizer, and registered observation store a canonical envelope
/// carrying this revision.
const REVISION_FIXTURE_SOURCE_KEY: &str = "host-provider-control-revision-source";
const REVISION_FIXTURE_RECORD_ID: &str = "host-provider-control-revision-record";
const REVISION_FIXTURE_REVISION: &str = "host-provider-control-source-revision-v1";

/// The Claude Code session id the whole journey is bound to.
const CLAUDE_SESSION: &str = "claude-cli-journey-session";
const CODEX_SESSION: &str = "codex-cli-journey-session";

/// A term that appears in the transcript and in the later question, so a recall
/// that answers at all has something to answer with.
const JOURNEY_TERM: &str = "quicksilver";

/// The last words of the long assistant message the mid-session turn writes.
///
/// It exists so recall can be asked for something only an *untruncated*
/// candidate can carry: a lane that returned the head of the message and
/// dropped its tail would still contain [`JOURNEY_TERM`] and would not contain
/// this.
const TAIL_SENTINEL: &str = "obsidian-ledger-tail";

/// The provider identity an operator writes into
/// `memory.provider_recall_routing.v1` to select Native, the configured,
/// operator-facing spelling of upstream memory.
const CONFIGURED_PROVIDER_ID: &str = "tracedecay.native";

/// File name a Native observation journal would carry. Native is upstream
/// memory and observes nothing, so the journey proves this file never exists.
const NATIVE_JOURNAL_FILE_NAME: &str = "memory-observation-journal-v1.sqlite3";

/// Matches the adapter's declared `tracedecay_memory_provider_ncm::NCM_PROVIDER_ID`.
/// This CLI target deliberately has no direct dependency on the adapter.
const NCM_OBSERVER_PROVIDER_ID: &str = "ncm";
const NCM_JOURNAL_FILE_NAME: &str = "memory-observation-ncm-journal-v1.sqlite3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveProvider {
    Native,
    RustNcm,
}

impl ActiveProvider {
    fn id(self) -> &'static str {
        match self {
            Self::Native => CONFIGURED_PROVIDER_ID,
            Self::RustNcm => NCM_OBSERVER_PROVIDER_ID,
        }
    }

    fn is_ncm(self) -> bool {
        self == Self::RustNcm
    }
}

/// Observation kind the journey admits for host session messages.
const SESSION_MESSAGE_OBSERVATION_KIND: &str = "session.message_committed.v1";

/// How long the journey waits for the journal to settle after the hook. The
/// mounted live replay parks for 250ms between passes, so this is a
/// convergence bound with generous headroom, never a sleep: every wait below
/// returns as soon as its condition holds.
const SETTLEMENT_BUDGET: Duration = Duration::from_secs(60);

/// How often a bounded wait re-reads the journal. Each read opens a second
/// handle on the live store, so the interval keeps the reader from competing
/// with the daemon's own writer; it bounds only how promptly a satisfied
/// condition is noticed, and no assertion rests on it.
const JOURNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The mounted observation journey's live replay park, in milliseconds
/// (`ObservationJourneyPolicyV1::project_default().delivery_park`). The
/// negative-control window below is a multiple of it, so it is tied to the
/// product's own cadence rather than to a guessed wall-clock number.
const LIVE_REPLAY_PARK_MILLIS: u64 = 250;

/// How many live-replay passes the journal must survive unchanged while a
/// transcript sits on disk and no hook has run.
const QUIESCENCE_REPLAY_PASSES: u64 = 4;

/// How long the journal must *stay* unchanged in that negative control. Long
/// enough that a route ingesting the transcript on its own is caught here
/// rather than mistaken for the hook's effect, short enough that the journey
/// does not pay seconds for it.
const QUIESCENCE_WINDOW: Duration =
    Duration::from_millis(QUIESCENCE_REPLAY_PASSES * LIVE_REPLAY_PARK_MILLIS);

/// How many deliveries one turn from either host contributes: the observation journey
/// admits one `session.message_committed.v1` per committed session message, and
/// each turn written below is one user record and one assistant record.
const ROWS_PER_TURN: usize = 2;

/// One page of inspection is far more than this journey can produce, so a full
/// page means the reader, not the journey, is what changed.
const JOURNAL_INSPECTION_PAGE_LIMIT: u32 = 100;

const USER_DATA_DIR_ENV: &str = "TRACEDECAY_DATA_DIR";
const GLOBAL_DB_ENV: &str = "TRACEDECAY_GLOBAL_DB";
const NCM_RECALL_DIAGNOSTIC_EVENT: &str = "[tracedecay] event=ncm_recall_diagnostic ";

// ---------------------------------------------------------------------------
// Isolated daemon fixture
// ---------------------------------------------------------------------------

struct ClaudeHostJourney {
    codex: bool,
    active_provider: ActiveProvider,
    ncm_observer: bool,
    daemon: Option<Child>,
    home: TempDir,
    profile: PathBuf,
    project: PathBuf,
    bin_dir: PathBuf,
    /// The read handle on the NCM observation journal for the current daemon
    /// incarnation.
    ///
    /// Opening the store initializes its schema inside a write transaction, so
    /// re-opening it on every poll would contend with the daemon's own writer
    /// for the duration of the journey. The observation is a read; it takes one
    /// handle and keeps it until the daemon stops. The slot is cleared at every
    /// lifecycle boundary so a later read cannot retain a stale SQLite
    /// connection across a restart.
    journal: RefCell<Option<Arc<SqliteObservationJournal>>>,
}

impl ClaudeHostJourney {
    /// A registered project with the selected advisory provider configured.
    /// Provider settings are `DaemonRestart`, so restart publishes the chosen
    /// composition before the journey begins.
    fn start(codex: bool, active_provider: ActiveProvider, ncm_observer: bool) -> Self {
        let home = TempDir::new().expect("isolated home");
        let mut journey = Self::allocate(home, codex, active_provider, ncm_observer);
        journey.start_daemon();
        journey.initialize_registered_project();
        let project_id = journey.project_id();
        // Routing is admitted only when its target is constructible, so the
        // NCM observer is enabled before any route can select it.
        journey.commit_native_gate(&project_id);
        if active_provider.is_ncm() || ncm_observer {
            journey.commit_real_ncm(&project_id);
        }
        journey.commit_routing(&project_id);
        // All provider gates are DaemonRestart settings: restart is what makes the
        // provider host mount.
        journey.stop_daemon();
        journey.start_daemon();
        journey
    }

    /// Allocate paths before choosing any provider or starting a daemon.
    fn allocate(
        home: TempDir,
        codex: bool,
        active_provider: ActiveProvider,
        ncm_observer: bool,
    ) -> Self {
        let root = home.path().to_path_buf();
        let profile = root.join(".tracedecay");
        let project = root.join("project");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&profile).expect("profile root");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        install_binary_shim(&bin_dir);
        initialize_project(&project);

        Self {
            codex,
            active_provider,
            ncm_observer,
            daemon: None,
            home,
            profile,
            project,
            bin_dir,
            journal: RefCell::new(None),
        }
    }

    fn cli(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tracedecay"));
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.bin_dir.clone()).chain(std::env::split_paths(&inherited_path)),
        )
        .expect("PATH with the isolated shim first");
        command
            .args(args)
            .current_dir(&self.project)
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env(USER_DATA_DIR_ENV, &self.profile)
            .env(GLOBAL_DB_ENV, self.profile.join("global.db"))
            .env("TRACEDECAY_TEST_ALLOW_INCOMPLETE_HOLDER_SCAN", "1")
            .env("PATH", path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn start_daemon(&mut self) {
        assert!(self.daemon.is_none(), "a daemon is already running");
        let log = fs::File::create(self.home.path().join("daemon.stderr.log"))
            .expect("isolated daemon log");
        let mut command = self.cli(&["daemon", "run"]);
        command
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        if self.active_provider.is_ncm() || self.ncm_observer {
            command.env("TRACEDECAY_TEST_NCM_RECALL_DIAGNOSTICS", "1");
        }
        let mut daemon = command.spawn().expect("daemon should start");
        wait_for_authority(&mut daemon, &daemon_authority_path(&self.profile));
        self.daemon = Some(daemon);
    }

    /// Reads only the daemon's bounded, opt-in NCM stage markers. The marker
    /// contains keyed request identity plus scalar counters; it never contains
    /// raw request ids, query text, candidate/source ids, content, or source
    /// sequence values.
    fn ncm_recall_diagnostic_events(&self) -> Vec<NcmRecallDiagnosticRecord> {
        let Ok(mut log) = fs::File::open(self.home.path().join("daemon.stderr.log")) else {
            return Vec::new();
        };
        let Ok(metadata) = log.metadata() else {
            return Vec::new();
        };
        let offset = metadata.len().saturating_sub(256 * 1024);
        if std::io::Seek::seek(&mut log, std::io::SeekFrom::Start(offset)).is_err() {
            return Vec::new();
        }
        let mut tail = Vec::new();
        if log.take(256 * 1024).read_to_end(&mut tail).is_err() {
            return Vec::new();
        }
        String::from_utf8_lossy(&tail)
            .lines()
            .filter_map(parse_ncm_recall_diagnostic)
            .collect()
    }

    /// Proves the live adapter emitted a correlated worker stage before the
    /// adapter reconstruction stage for every observed recall request. Equal
    /// state generations and non-increasing candidate counts make the marker
    /// useful for diagnosing a lost result without exposing its contents.
    fn assert_ncm_recall_diagnostics(&self, expected_candidates: usize) {
        if !self.active_provider.is_ncm() {
            return;
        }
        let expected_candidates =
            u64::try_from(expected_candidates).expect("candidate count fits u64");
        let events = self.ncm_recall_diagnostic_events();
        assert!(
            !events.is_empty(),
            "the opt-in NCM diagnostic sink must emit at least one stage marker"
        );
        let current_request_digest = events
            .last()
            .expect("NCM diagnostics include the current recall")
            .request_digest
            .clone();
        let mut by_request = BTreeMap::<String, Vec<NcmRecallDiagnosticRecord>>::new();
        for event in events {
            by_request
                .entry(event.request_digest.clone())
                .or_default()
                .push(event);
        }
        let mut joined_current_recall = false;
        for (request_digest, stages) in by_request {
            let worker = stages
                .first()
                .expect("a request must have a first NCM stage");
            assert_eq!(
                worker.stage, "worker",
                "NCM worker stage must precede adapter stages for request {request_digest}: {stages:?}"
            );
            let reconstructed = stages
                .iter()
                .find(|event| matches!(event.stage.as_str(), "reconstructed" | "partial_reply"))
                .unwrap_or_else(|| {
                    panic!(
                        "NCM request {request_digest} has no reconstructed or partial stage: {stages:?}"
                    )
                });
            assert_eq!(
                worker.state_generation, reconstructed.state_generation,
                "NCM stage pair must observe one provider generation for request {request_digest}"
            );
            assert!(
                reconstructed.candidate_count <= worker.candidate_count,
                "adapter reconstruction cannot create candidates for request {request_digest}: {stages:?}"
            );
            assert!(
                stages.iter().skip(1).all(|event| event.stage != "worker"),
                "worker must be the only first stage for request {request_digest}: {stages:?}"
            );
            if request_digest != current_request_digest {
                continue;
            }
            joined_current_recall = true;
            assert_eq!(
                worker.scanned_items, reconstructed.scanned_items,
                "NCM reconstruction must propagate the worker scanned item count for request {request_digest}: {stages:?}"
            );
            assert!(
                worker.scanned_items >= expected_candidates,
                "NCM's own state must hold every recalled message for request {request_digest}: {stages:?}"
            );
            assert_eq!(
                reconstructed.candidate_count, expected_candidates,
                "NCM reconstruction must answer every observed message for request {request_digest}: {stages:?}"
            );
        }
        assert!(
            joined_current_recall,
            "the latest NCM diagnostic request must join to the verified recall"
        );
    }

    fn stop_daemon(&mut self) {
        self.reset_journal_readers();
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }

    /// Drop all journal connections before a daemon restart. Opening a fresh
    /// reader after startup is part of the assertion: it proves the test sees
    /// the durable store published by the new daemon process rather than a
    /// connection that was opened before the lifecycle boundary.
    fn reset_journal_readers(&mut self) {
        self.journal.get_mut().take();
    }

    /// Append one canonical source through the public parser, privacy
    /// sanitizer, and registered observation store while the shipped daemon
    /// is stopped. The normal host normalizers intentionally leave
    /// `evidence.revision` empty; this producer gives the live provider
    /// control journey a real source revision so the current-revision
    /// correction path is exercised before the stale-revision refusal.
    ///
    /// The canonical envelope itself is the native fixture record. Snapshot
    /// ordering keeps the fixture independent of a physical transcript byte
    /// offset while still binding its source range through the parser and
    /// observation identity.
    fn produce_revision_fixture(
        &self,
        session_id: &str,
        project_id: &str,
    ) -> CanonicalObservationIdV1 {
        assert!(
            self.daemon.is_none(),
            "the canonical producer fixture requires the shipped daemon to be stopped"
        );
        let provider = ProviderId::new(if self.codex { "codex" } else { "claude" })
            .expect("canonical fixture provider");
        let session = SessionId::new(session_id.to_owned()).expect("canonical fixture session");
        let source_key =
            SessionId::new(REVISION_FIXTURE_SOURCE_KEY).expect("canonical fixture source key");
        let project_id =
            ProjectId::new(project_id.to_owned()).expect("canonical fixture project id");
        let scope = ObservationScopeV1::Project {
            project_id: project_id.clone(),
        };
        let generation =
            ObservationSourceGenerationV1::new(1).expect("canonical fixture generation");
        let range = ObservationSourceRangeV1::new(0, 1).expect("canonical fixture source range");
        let stable_record_id =
            ObservationId::new(REVISION_FIXTURE_RECORD_ID).expect("canonical fixture record id");
        let envelope = CanonicalObservationEnvelopeV1::new(
            provider.clone(),
            "message",
            stable_record_id.clone(),
            CanonicalObservationRelationsV1::new(session.clone()),
            vec![CanonicalObservationFactV1::Message {
                role: CanonicalMessageRoleV1::Assistant,
                content: json!({
                    "text": format!(
                        "{JOURNEY_TERM} source revision fixture preserves the control path"
                    ),
                }),
                model: Some("host-provider-control-fixture".to_owned()),
                timestamp: Some(1_750_000_000),
            }],
            CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::SnapshotOrder, range)
                .with_revision(REVISION_FIXTURE_REVISION)
                .expect("canonical fixture source revision"),
        )
        .expect("canonical fixture envelope");
        let native_record = serde_json::to_vec(&envelope).expect("canonical fixture bytes");
        let parsed = tracedecay_privacy::parse_normalized_observation_record_v1(
            &native_record,
            range,
            ObservationOrderingDomainV1::SnapshotOrder,
            |native| {
                serde_json::from_value(native)
                    .map_err(|_| tracedecay_privacy::ObservationRecordParseErrorV1::Malformed)
            },
        )
        .expect("parse canonical revision fixture");
        let identity = ObservationIdentityMaterialV1::for_native_record(
            ObservationSourceIdentityV1::for_provider_source(provider, session, source_key)
                .expect("canonical fixture source identity"),
            scope.clone(),
            generation,
            range,
            ObservationOrderingDomainV1::SnapshotOrder,
            stable_record_id,
        )
        .expect("canonical fixture identity");
        let observation_id =
            CanonicalObservationIdV1::derive(&identity).expect("canonical fixture observation id");
        let request = CaptureObservationRequest::new(
            parsed,
            identity,
            None,
            RetentionClass::new("retention.host-provider-control-journey")
                .expect("canonical fixture retention"),
            ObservationCancellation::default(),
        )
        .expect("canonical fixture capture request");

        let expected_observation_id = observation_id.clone();
        let profile = self.profile.clone();
        let project = self.project.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("canonical fixture runtime");
        runtime.block_on(async move {
            let host_runtime =
                tracedecay_project::test_support::host_admission::HostAdmissionTestRuntimeV1::project(
                    &profile, &project, project_id,
                )
                .await
                .expect("open registered canonical fixture authority");
            let store = host_runtime
                .observation_store(HostAdmissionScope::Project)
                .expect("bind registered canonical fixture store");
            let application = ObservationApplication::new(
                store,
                tracedecay_privacy::RecordSanitizerV1::observation_v1()
                    .expect("canonical fixture observation sanitizer"),
            );
            let outcome = application
                .capture_observation(request)
                .await
                .expect("persist canonical revision fixture");
            match &outcome {
                CaptureObservationOutcome::Persisted { outcome, .. }
                | CaptureObservationOutcome::AcceptedForReplay { outcome, .. } => assert_eq!(
                    outcome.receipt().observation().observation_id(),
                    &expected_observation_id,
                    "canonical producer receipt must retain its derived observation identity"
                ),
                CaptureObservationOutcome::Rejected { .. }
                | CaptureObservationOutcome::Quarantined { .. } => panic!(
                    "canonical revision fixture must cross the durable admission boundary: {outcome:?}"
                ),
            }
            drop(application);
            drop(host_runtime);
        });
        observation_id
    }

    /// Initializes through the daemon-owned scheduler, grading its real
    /// startup window instead of sleeping past it. Authority publication makes
    /// the transport usable before the scheduler is necessarily mounted; only
    /// that exact retryable state may precede success.
    fn initialize_registered_project(&self) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let output = self
                .cli(&["init"])
                .current_dir(&self.project)
                .output()
                .expect("tracedecay init runs");
            if output.status.success() {
                return;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("code_index_scheduler_unavailable"),
                "tracedecay init failed outside the typed scheduler warming window with {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                stderr
            );
            assert!(
                Instant::now() < deadline,
                "daemon-owned code-index scheduler never became available: {stderr}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The registered project identity, read back from the daemon rather than
    /// derived here.
    fn project_id(&self) -> String {
        let stdout = run_ok(
            self.cli(&["projects", "context"])
                .arg(&self.project)
                .arg("--json"),
            "tracedecay projects context",
        );
        let context: Value = serde_json::from_slice(&stdout).expect("project context JSON");
        context["project"]["project_id"]
            .as_str()
            .expect("registered project id")
            .to_owned()
    }

    /// Reads the daemon's existing internal scheduler status transport. The CLI
    /// public tool catalog intentionally omits this administration binding.
    fn startup_sync_status(
        &self,
        runtime: &tokio::runtime::Runtime,
        key: &str,
        deadline: Instant,
    ) -> Value {
        self.startup_sync_status_for_daemon(
            runtime,
            key,
            deadline,
            self.daemon.as_ref().expect("owned journey daemon").id(),
        )
    }

    /// Read the existing startup status when a caller already owns the Child.
    fn startup_sync_status_for_daemon(
        &self,
        runtime: &tokio::runtime::Runtime,
        key: &str,
        deadline: Instant,
        daemon_pid: u32,
    ) -> Value {
        use tokio::io::AsyncWriteExt;
        use tracedecay_daemon_protocol::{
            DaemonClientIdentity, DaemonConnection, DaemonHandshake, MovedStoreAdoption,
            next_daemon_response_line, write_daemon_preamble,
        };
        let authority: DaemonAuthorityRecord = serde_json::from_slice(
            &fs::read(daemon_authority_path(&self.profile)).expect("current daemon authority"),
        )
        .expect("canonical daemon authority");
        assert_eq!(
            authority.pid, daemon_pid,
            "status authority must name the fixture daemon"
        );
        assert_eq!(
            fs::canonicalize(&authority.profile_root).expect("canonical authority profile"),
            fs::canonicalize(&self.profile).expect("canonical isolated profile"),
            "status authority must name the isolated profile"
        );
        let connection =
            DaemonConnection::new(authority.endpoint.clone(), authority.auth_token.clone())
                .with_daemon_version(authority.version.clone());
        let handshake = DaemonHandshake {
            project_path: Some(self.project.clone()),
            scope_prefix: None,
            timings: false,
            allow_init: false,
            allow_initialize_root_routing: false,
            client_identity: DaemonClientIdentity::new(
                authority.profile_root,
                self.profile.join("global.db"),
            ),
            client_version: authority.version,
            client_instance_id: format!("startup-status-fixture-{}", std::process::id()),
            tool_list_changed_capable: false,
            catalog_version: String::new(),
            moved_store_adoption: MovedStoreAdoption::Never,
        };
        let request_id = json!("startup-history-status");
        let remaining = deadline.saturating_duration_since(Instant::now());
        let now = tracedecay_contracts::clock::now_micros();
        let expires_at = tracedecay_domain::UtcMicros(
            now.0
                .saturating_add(i64::try_from(remaining.as_micros()).unwrap_or(i64::MAX)),
        );
        // A one-shot daemon request carries its SEP-2575 per-request MCP
        // context instead of an `initialize` session, exactly as the CLI does.
        let mut request: tracedecay_mcp::JsonRpcRequest = serde_json::from_value(json!({
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "tracedecay_admin_cli", "arguments": {
                "action": "sessions_sync_status", "idempotency_key": key,
            }, "_meta": tracedecay_mcp::tool_call_deadline_meta(expires_at)},
        }))
        .expect("status JSON-RPC request");
        assert!(
            tracedecay_mcp::server::attach_stateless_request_context(&mut request),
            "the status request must carry its per-request MCP context"
        );
        let phase = std::cell::Cell::new("connect");
        runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let stream = BrokerStream::connect(&connection.endpoint)
                    .await
                    .expect("connect status transport");
                let (reader, mut writer) = tokio::io::split(stream);
                phase.set("preamble");
                write_daemon_preamble(&mut writer, &connection, &handshake)
                    .await
                    .expect("status preamble");
                phase.set("request_write");
                let mut bytes = serde_json::to_vec(&request).expect("encode status request");
                bytes.push(b'\n');
                writer
                    .write_all(&bytes)
                    .await
                    .expect("write status request");
                writer.flush().await.expect("flush status request");
                phase.set("response_read");
                let mut reader = tokio::io::BufReader::new(reader);
                // Server notifications (for example a version notice) may
                // precede the correlated response on the same transport.
                let response = loop {
                    let line = next_daemon_response_line(
                        &mut reader,
                        &connection,
                        "startup history status",
                        Duration::from_millis(250),
                    )
                    .await
                    .expect("bounded status response")
                    .expect("status response must exist");
                    let message: Value =
                        serde_json::from_str(&line).expect("status JSON-RPC message");
                    if message.get("id").is_none() && message.get("method").is_some() {
                        continue;
                    }
                    break message;
                };
                assert_eq!(response["jsonrpc"], "2.0", "status JSON-RPC version");
                assert_eq!(response["id"], request_id, "status response correlation");
                assert!(
                    response.get("error").is_none_or(Value::is_null),
                    "status RPC must succeed: {response}"
                );
                let result = response
                    .get("result")
                    .filter(|result| result.is_object())
                    .expect("status tool result");
                assert_ne!(result["isError"], true, "status tool must succeed");
                let payload = tracedecay::daemon::tool_json_payload(result, "tracedecay_admin_cli")
                    .expect("status tool JSON payload");
                phase.set("close");
                writer.shutdown().await.expect("close status transport");
                payload
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "startup status exceeded settlement deadline: phase={}",
                    phase.get()
                )
            })
        })
    }

    /// Drain the actual startup import and retained projection before the
    /// fixture writes evidence. These read-only status calls schedule no import.
    fn await_startup_history(&self) {
        let authority: DaemonAuthorityRecord = serde_json::from_slice(
            &fs::read(daemon_authority_path(&self.profile)).expect("current daemon authority"),
        )
        .expect("canonical daemon authority");
        let key = format!(
            "session-sync.startup.{}.{}",
            authority.process_run_id,
            self.project_id()
        );
        let deadline = Instant::now() + SETTLEMENT_BUDGET;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("startup status runtime");
        loop {
            let outcome = self.startup_sync_status(&runtime, &key, deadline);
            let status = outcome["status"].as_str().expect("startup sync status");
            match status {
                "accepted" | "joined" => {}
                "unavailable"
                    if matches!(
                        outcome["reason_code"].as_str(),
                        Some(
                            "session_sync_authority_unavailable"
                                | "session_sync_operation_not_found"
                        )
                    ) => {}
                "complete" => {
                    assert_eq!(
                        outcome["termination"], "completed",
                        "startup import must complete successfully"
                    );
                    let coverage = outcome["coverage"]
                        .as_array()
                        .expect("startup source coverage");
                    assert!(
                        !coverage.is_empty(),
                        "startup import must report source coverage"
                    );
                    // Match the shipped CLI await's remaining-work accounting.
                    let remaining = coverage
                        .iter()
                        .try_fold(0_u64, |remaining, entry| {
                            let coverage = entry.get("coverage")?;
                            let deferred = match coverage.get("outcome")?.as_str()? {
                                "complete" => 0,
                                "partial" => coverage.get("deferred_units")?.as_u64()?,
                                "backpressured" => coverage.get("rejected_units")?.as_u64()?,
                                _ => return None,
                            };
                            Some(remaining.saturating_add(deferred))
                        })
                        .expect("truthful startup source coverage");
                    assert_eq!(remaining, 0, "startup import must leave no remaining work");
                    break;
                }
                other => panic!("startup import refused with status {other}"),
            }
            assert!(
                Instant::now() < deadline,
                "startup import did not finish; last status {status}, reason {:?}",
                outcome["reason_code"].as_str()
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
        loop {
            let doctor = self.tool("tracedecay_lcm_doctor", &json!({ "format": "json" }));
            let projection = doctor
                .pointer("/outcome/value/payload/projection")
                .expect("project doctor must report its retained projection");
            let state = projection["state"].as_str().expect("projection state");
            match state {
                "current" => return,
                "stale" => {}
                other => panic!("startup projection cannot converge from state {other}"),
            }
            assert!(
                Instant::now() < deadline,
                "startup projection did not converge; last state {state}"
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
    }

    /// One MCP tool call through the shipped `tracedecay tool` surface, which
    /// dispatches over the daemon transport exactly like any other client.
    ///
    /// `--json` makes the CLI print the daemon's own result object verbatim.
    /// The process exits nonzero whenever the daemon marked the call failed,
    /// so [`run_ok`] is the refusal check and nothing here has to re-derive it.
    fn tool_result(&self, name: &str, arguments: &Value) -> Value {
        self.tool_result_with_bytes(name, arguments).0
    }

    fn tool_result_with_bytes(&self, name: &str, arguments: &Value) -> (Value, Vec<u8>) {
        let project = self.project.to_string_lossy().to_string();
        let payload = arguments.to_string();
        let stage = match arguments
            .pointer("/_meta/session_id")
            .and_then(Value::as_str)
        {
            Some(session) if session == self.session_id() => "origin-session",
            Some(_) => "next-session",
            None => "unbound-session",
        };
        let stdout = run_ok(
            &mut self.cli(&[
                "tool",
                "--project",
                &project,
                name,
                "--args",
                &payload,
                "--json",
            ]),
            &format!("tracedecay tool {name} ({stage})"),
        );
        let text = std::str::from_utf8(&stdout).expect("tool output is UTF-8");
        let result = serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("tool {name} answered non-JSON `{text}`: {error}"));
        (result, stdout)
    }

    /// The tool's own JSON payload: compatibility MCP results carry it inside
    /// `content[*].text`, and typed application-surface results are already the
    /// object itself.
    fn tool(&self, name: &str, arguments: &Value) -> Value {
        self.tool_with_bytes(name, arguments).0
    }

    fn tool_with_bytes(&self, name: &str, arguments: &Value) -> (Value, Vec<u8>) {
        let (result, stdout) = self.tool_result_with_bytes(name, arguments);
        assert_ne!(
            result["isError"], true,
            "tool {name} reported an application failure: {result}"
        );
        let Some(text) = join_content_text(&result) else {
            return (result, stdout);
        };
        let decoded = serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!("tool {name} produced non-JSON content text `{text}`: {error}")
        });
        (decoded, stdout)
    }

    /// The configuration revision every component agrees on, which the
    /// revision-CAS write below must present.
    fn configuration_revision(&self) -> String {
        let observed = self.tool_result("tracedecay_configuration_observed_state", &json!({}));
        let mut revisions = Vec::new();
        collect_string_field(&observed, "desired_revision_id", &mut revisions);
        assert!(
            !revisions.is_empty(),
            "configuration observed state must report a desired revision: {observed}"
        );
        revisions.sort();
        revisions.dedup();
        assert_eq!(
            revisions.len(),
            1,
            "configuration components must agree on one desired revision: {observed}"
        );
        revisions.remove(0)
    }

    /// Commits one project-layer setting through the shipped operator surface.
    fn configuration_set(&self, project_id: &str, key: &str, value: Value, idempotency: &str) {
        let expected_revision = self.configuration_revision();
        // A refusal exits nonzero, so reaching the next line already means the
        // operator write settled.
        let _ = self.tool_result(
            "tracedecay_configuration_set",
            &json!({
                "layer": { "kind": "project", "project_id": project_id },
                "key": key,
                "value": value,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency,
            }),
        );
        assert_ne!(
            self.configuration_revision(),
            expected_revision,
            "committing {key} must advance the canonical configuration revision"
        );
    }

    fn commit_native_gate(&self, project_id: &str) {
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            json!({ "kind": "boolean", "value": self.active_provider == ActiveProvider::Native }),
            "configuration.idempotency.claude-cli-journey-host",
        );
    }

    fn commit_routing(&self, project_id: &str) {
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
            journey_routing_setting(self.active_provider),
            "configuration.idempotency.claude-cli-journey-routing",
        );
    }

    /// Only the opt-in real-worker tests call this. The existing TempDir owns
    /// every mutable NCM namespace; only installed model artifacts are shared.
    #[cfg(unix)]
    fn commit_real_ncm(&self, project_id: &str) {
        let worker = PathBuf::from(
            std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real NCM worker binary is required"),
        );
        let installed = PathBuf::from(
            std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT")
                .expect("installed pinned NCM model root is required"),
        );
        assert!(
            worker.is_absolute() && worker.is_file(),
            "worker must be an absolute binary path"
        );
        assert!(installed.is_absolute(), "model root must be absolute");
        let models = installed
            .join("models")
            .canonicalize()
            .expect("installed models directory");
        assert!(models.is_dir(), "installed root must contain models");
        let state_root = self.home.path().join("ncm-observer");
        fs::create_dir(&state_root).expect("isolated NCM state root");
        stage_isolated_ncm_models(&models, &state_root)
            .expect("stage installed model artifacts into the isolated state root");
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            canonical_text_setting(&MemoryProviderNcmObserverV1::Enabled {
                worker_binary: worker.canonicalize().expect("canonical worker binary"),
                state_root: state_root
                    .canonicalize()
                    .expect("canonical isolated state root"),
            }),
            "configuration.idempotency.cli-journey-ncm-observer",
        );
    }

    #[cfg(not(unix))]
    fn commit_real_ncm(&self, _project_id: &str) {
        panic!("the opt-in real NCM model fixture requires Unix");
    }

    /// Runs one shipped Claude lifecycle hook process, handing it the bytes
    /// Claude Code itself writes on stdin.
    fn run_hook(&self, subcommand: &str, payload: &Value) -> Output {
        let payload = payload.to_string();
        let mut command = self.cli(&[subcommand]);
        command.stdin(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("Claude {subcommand} hook spawns: {error}"));
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload.as_bytes())
            .expect("hook payload delivery");
        child.wait_with_output().expect("hook completes")
    }

    /// Captures the first completed turn after the live SessionStart baseline.
    fn run_first_stop_hook(&self) -> Output {
        if self.codex {
            self.run_codex_stop_hook(1)
        } else {
            self.run_stop_hook()
        }
    }

    /// The shipped SessionStart route binding, independent of turn capture.
    fn run_session_start_event(&self, session_id: &str, transcript: &Path) -> Output {
        self.run_hook(
            if self.codex {
                "hook-codex-session-start"
            } else {
                "hook-claude-session-start"
            },
            &json!({
                "session_id": session_id,
                "transcript_path": transcript.to_string_lossy(),
                "cwd": self.project.to_string_lossy(),
                "hook_event_name": "SessionStart",
                "source": "startup",
            }),
        )
    }

    /// The shipped `Stop` hook, with Claude Code's own payload.
    ///
    /// `Stop` — not `PostToolUse` — is the mid-session hook that carries the
    /// turn's own evidence: `hook_stop` runs the project transcript ingest
    /// (`crates/tracedecay-agent-hosts/src/hooks/claude.rs`,
    /// `claude_stop_response_for_event`), while the `PostToolUse` handler only
    /// dispatches guidance and commits nothing.
    fn run_stop_hook(&self) -> Output {
        if self.codex {
            return self.run_codex_stop_hook(2);
        }
        self.run_hook(
            "hook-stop",
            &json!({
                "session_id": CLAUDE_SESSION,
                "transcript_path": self.transcript_path().to_string_lossy(),
                "cwd": self.project.to_string_lossy(),
                "hook_event_name": "Stop",
                "stop_hook_active": false,
            }),
        )
    }

    fn session_id(&self) -> &'static str {
        if self.codex {
            CODEX_SESSION
        } else {
            CLAUDE_SESSION
        }
    }

    /// Native Stop grammar from fixtures/host_events/codex/stop.json.
    fn run_codex_stop_hook(&self, turn: u32) -> Output {
        self.run_hook(
            "hook-codex-stop",
            &json!({
                "session_id": CODEX_SESSION,
                "turn_id": format!("codex-journey-turn-{turn}"),
                "transcript_path": self.transcript_path().to_string_lossy(),
                "cwd": self.project.to_string_lossy(),
                "hook_event_name": "Stop",
                "model": "gpt-5",
                "permission_mode": "default",
                "stop_hook_active": false,
                "last_assistant_message": null,
            }),
        )
    }

    fn transcript_path(&self) -> PathBuf {
        self.transcript_path_for_session(self.session_id())
    }

    fn transcript_path_for_session(&self, session_id: &str) -> PathBuf {
        if self.codex {
            return self
                .home
                .path()
                .join(".codex/sessions/2026/02/01")
                .join(format!("rollout-2026-02-01T00-00-00-{session_id}.jsonl"));
        }
        self.home
            .path()
            .join(".claude/projects/-claude-cli-journey")
            .join(format!("{session_id}.jsonl"))
    }

    /// Opens a real host transcript before its live SessionStart baseline.
    fn initialize_session_transcript(&self, session_id: &str) {
        let path = self.transcript_path_for_session(session_id);
        fs::create_dir_all(path.parent().expect("transcript directory"))
            .expect("transcript directory");
        let initial = if self.codex {
            format!(
                "{}\n",
                json!({
                    "timestamp": "2026-02-01T00:00:00.000Z",
                    "type": "session_meta",
                    "payload": { "id": session_id, "cwd": self.project },
                })
            )
        } else {
            String::new()
        };
        fs::write(path, initial).expect("initialize host transcript");
    }

    /// Appends the unchanged first turn after the live SessionStart baseline.
    fn write_claude_transcript(&self) {
        let path = self.transcript_path();
        let turn = self.claude_turn(
            1,
            "2026-02-01T00:00:00.000Z",
            "2026-02-01T00:00:01.000Z",
            &format!("how does the {JOURNEY_TERM} transport probe decide its retry budget?"),
            &format!(
                "the {JOURNEY_TERM} transport probe reads its retry budget from the pinned \
                 deadline"
            ),
        );
        let mut existing = fs::read_to_string(&path).expect("read host transcript baseline");
        existing.push_str(&turn);
        fs::write(&path, existing).expect("write host transcript");
    }

    /// Appends the second turn: the exchange the session has *while it is
    /// running*, after the SessionStart hook has already settled the first.
    ///
    /// The assistant reply is deliberately long and ends in [`TAIL_SENTINEL`],
    /// so a later recall can be asked to prove it carries the whole message and
    /// not just its opening.
    fn append_mid_session_claude_turn(&self) {
        let path = self.transcript_path();
        let turn = self.claude_turn(
            3,
            "2026-02-01T00:05:00.000Z",
            "2026-02-01T00:05:01.000Z",
            &format!("what did the {JOURNEY_TERM} retry budget change actually record?"),
            &format!(
                "the {JOURNEY_TERM} transport probe records its retry budget change in three \
                 places: the pinned deadline it reads at construction, the attempt ledger it \
                 advances on every refused delivery, and the operator-visible note the session \
                 leaves behind, which ends with {TAIL_SENTINEL}"
            ),
        );
        let mut existing = fs::read_to_string(&path).expect("read Claude transcript");
        existing.push_str(&turn);
        fs::write(&path, existing).expect("append Claude transcript turn");
    }

    /// One user/assistant exchange in Claude Code's own transcript shape,
    /// terminated by a newline so appending another turn stays well-formed
    /// JSONL.
    fn claude_turn(
        &self,
        first_uuid: u32,
        user_timestamp: &str,
        assistant_timestamp: &str,
        user_text: &str,
        assistant_text: &str,
    ) -> String {
        let cwd = self.project.to_string_lossy().to_string();
        if self.codex {
            // Native event_msg records, as in transcript_ingest_suite/codex.rs.
            // Metadata is written once; later turns append to the same rollout.
            let rows = [
                json!({
                    "timestamp": user_timestamp,
                    "type": "event_msg",
                    "payload": { "type": "user_message", "message": user_text },
                }),
                json!({
                    "timestamp": assistant_timestamp,
                    "type": "event_msg",
                    "payload": { "type": "agent_message", "message": assistant_text },
                }),
            ];
            return rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
        }
        let user_uuid = format!("cli-journey-uuid-{first_uuid}");
        let assistant_uuid = format!("cli-journey-uuid-{}", first_uuid + 1);
        let rows = [
            json!({
                "type": "user",
                "cwd": cwd,
                "sessionId": CLAUDE_SESSION,
                "uuid": user_uuid,
                "timestamp": user_timestamp,
                "message": {
                    "role": "user",
                    "content": user_text,
                },
            }),
            json!({
                "type": "assistant",
                "cwd": cwd,
                "sessionId": CLAUDE_SESSION,
                "uuid": assistant_uuid,
                "parentUuid": user_uuid,
                "timestamp": assistant_timestamp,
                "message": {
                    "id": format!("msg_cli_journey_{}", first_uuid + 1),
                    "role": "assistant",
                    "model": "claude-opus-4-8",
                    "content": [{
                        "type": "text",
                        "text": assistant_text,
                    }],
                },
            }),
        ];
        let mut turn = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        turn.push('\n');
        turn
    }

    /// Whether this composition mounts NCM, as the active provider or as an
    /// observer. Only NCM observes; Native answers from upstream memory.
    fn ncm_participates(&self) -> bool {
        self.active_provider.is_ncm() || self.ncm_observer
    }

    /// The NCM observation journal, located under this profile's own store
    /// layout rather than guessed at.
    fn journal_path(&self) -> Option<PathBuf> {
        find_file(&self.profile, NCM_JOURNAL_FILE_NAME)
    }

    /// The read handle on the NCM journal, opened once per daemon incarnation
    /// and reused for the rest of that incarnation.
    ///
    /// `None` only while the mounted journey has not created its store yet,
    /// which is genuinely "no deliveries"; a store that exists but refuses to
    /// open fails the test loudly rather than reading as an empty journal.
    fn journal(&self) -> Option<Arc<SqliteObservationJournal>> {
        if let Some(journal) = self.journal.borrow().as_ref().cloned() {
            return Some(journal);
        }
        let path = self.journal_path()?;
        let journal = Arc::new(
            SqliteObservationJournal::open(&path, inspection_retention_policy())
                .expect("the durable observation journal must open through its own store API"),
        );
        *self.journal.borrow_mut() = Some(Arc::clone(&journal));
        Some(journal)
    }

    /// Native observes nothing: no composition ever creates a Native journal.
    fn assert_no_native_journal(&self) {
        assert!(
            find_file(&self.profile, NATIVE_JOURNAL_FILE_NAME).is_none(),
            "Native is upstream memory and must never mount an observation journal"
        );
    }

    /// With NCM absent the provider host stores nothing at all.
    fn assert_no_provider_journal(&self) {
        self.assert_no_native_journal();
        assert!(
            self.journal_path().is_none(),
            "no NCM participation means no NCM journal"
        );
    }

    /// Every delivery the NCM journal holds, read through the journal crate's
    /// own inspection surface.
    ///
    /// No SQL and no column name appears here: the journal's schema belongs to
    /// `tracedecay-memory-observation`, and a reader that re-derived it could
    /// silently return nothing after a schema change and be mistaken for an
    /// empty journal. Every row must come from the live canonical session
    /// stream: the host replays no provider history.
    fn journal_rows(&self) -> Vec<JournalInspectionRowV1> {
        let Some(journal) = self.journal() else {
            return Vec::new();
        };
        let page = journal
            .inspect(&JournalInspectionFilterV1 {
                limit: JOURNAL_INSPECTION_PAGE_LIMIT,
                ..JournalInspectionFilterV1::default()
            })
            .expect("the durable observation journal must answer an inspection");
        assert!(
            page.next_cursor.is_none(),
            "this journey cannot produce more than {JOURNAL_INSPECTION_PAGE_LIMIT} deliveries; \
             {} rows were reported",
            page.total_rows
        );
        for row in &page.rows {
            assert_eq!(
                row.source_stream, "session_observation_store",
                "the host delivers only live canonical session messages: {:?}",
                journal_digest(&page.rows)
            );
        }
        page.rows
    }

    /// Waits, bounded, until the journal holds at least `minimum_rows`
    /// deliveries and every one of them is terminal, and returns them the
    /// moment it does. A deadline is a failure that reports what it last saw,
    /// never a half-settled journal handed back to be asserted against.
    fn await_settled_journal(&self, minimum_rows: usize) -> Vec<JournalInspectionRowV1> {
        let deadline = Instant::now() + SETTLEMENT_BUDGET;
        loop {
            let rows = self.journal_rows();
            if rows.len() >= minimum_rows && rows.iter().all(|row| row.state.is_terminal()) {
                return rows;
            }
            assert!(
                Instant::now() < deadline,
                "the hook's observations never settled {minimum_rows} NCM deliveries within \
                 {SETTLEMENT_BUDGET:?}; last saw {:?}; daemon stderr: {}",
                journal_digest(&rows),
                self.daemon_log_tail()
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
    }

    /// A bounded, privacy-sanitized tail of the isolated daemon log.
    fn daemon_log_tail(&self) -> String {
        let Ok(mut log) = fs::File::open(self.home.path().join("daemon.stderr.log")) else {
            return "[no daemon log]".to_owned();
        };
        let offset = log
            .metadata()
            .map(|metadata| metadata.len().saturating_sub(16 * 1024))
            .unwrap_or(0);
        if std::io::Seek::seek(&mut log, std::io::SeekFrom::Start(offset)).is_err() {
            return "[unreadable daemon log]".to_owned();
        }
        let mut tail = Vec::new();
        if log.take(16 * 1024).read_to_end(&mut tail).is_err() {
            return "[unreadable daemon log]".to_owned();
        }
        tracedecay_privacy::sanitize_provider_metadata_text(&String::from_utf8_lossy(&tail))
            .unwrap_or_else(|| "[daemon diagnostics withheld by privacy policy]".to_owned())
    }

    /// Every settled NCM delivery was applied exactly once with the provider's
    /// own acknowledgement, and carries the host's attribution of the exact
    /// canonical record it came from, recorded under that record's own
    /// session scope.
    fn assert_ncm_deliveries(&self, rows: &[JournalInspectionRowV1]) {
        let journal = self.journal().expect("mounted NCM journal");
        for row in rows {
            assert_eq!(row.provider_id, NCM_OBSERVER_PROVIDER_ID);
            let receipts = journal
                .receipts_for(&row.observation_id)
                .expect("provider receipts");
            assert_eq!(
                receipts.len(),
                1,
                "one provider receipt per committed message"
            );
            let receipt = &receipts[0];
            assert_eq!(receipt.provider_id.as_str(), NCM_OBSERVER_PROVIDER_ID);
            assert_eq!(receipt.observation_id, row.observation_id);
            assert_eq!(receipt.idempotency_key, row.idempotency_key);
            assert_eq!(receipt.payload_sha256, row.payload_sha256);
            assert_eq!(receipt.extensions_digest, row.extensions_digest);
            assert_eq!(receipt.registration_revision, row.registration_revision);
            assert_eq!(
                receipt.provider_instance_id.as_ref(),
                Some(&row.provider_instance_id)
            );
            assert_eq!(receipt.attempt_number, 1);
            assert_session_message_receipt(receipt);
            let admitted = journal
                .read_admitted_observation_by_idempotency(&row.idempotency_key)
                .expect("read admitted delivery")
                .expect("delivered content retained");
            let payload: Value =
                serde_json::from_slice(&admitted.payload.bytes).expect("delivered payload");
            let original = &payload["source_identity"]["original_source"];
            assert_eq!(
                original["source"]["observation_id"].as_str(),
                Some(admitted.source.source_event_id.as_str()),
                "the delivery attributes its own canonical record: {payload}"
            );
            assert_eq!(original["origin_scope"]["state"], "recorded");
            assert_eq!(
                original["origin_scope"]["exact_scope_identity"],
                admitted_scope(&admitted),
                "attribution is recorded under the record's own session scope"
            );
            assert!(
                payload.get("history_grant").is_none(),
                "the host never dispatches provider history"
            );
        }
    }

    /// The negative control. For one window derived from the journey's own
    /// live-replay park, the journal must hold exactly the deliveries it held
    /// before — which is what makes the next hook invocation the only possible
    /// cause of the rows that follow, and a restart provably redelivers nothing.
    fn assert_journal_unchanged_without_a_hook(&self, expected: &[JournalInspectionRowV1]) {
        let expected_identities = journal_row_identities(expected);
        let deadline = Instant::now() + QUIESCENCE_WINDOW;
        while Instant::now() < deadline {
            let rows = self.journal_rows();
            assert_eq!(
                journal_row_identities(&rows),
                expected_identities,
                "nothing may reach the NCM journal without a hook. Observed {:?}",
                journal_digest(&rows)
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
    }

    /// Upstream session history is the canonical authority whichever provider
    /// is selected: `tracedecay_message_search` recalls what the Claude hooks
    /// committed. The Codex Stop hook commits canonical observations but its
    /// rollout reaches message search only through upstream's explicit session
    /// refresh, which this provider journey does not drive.
    fn assert_message_search_recalls_journey(&self) {
        if self.codex {
            return;
        }
        let deadline = Instant::now() + SETTLEMENT_BUDGET;
        loop {
            let envelope = self.tool(
                "tracedecay_message_search",
                &json!({ "query": format!("{JOURNEY_TERM} retry budget"), "format": "json" }),
            );
            let payload = envelope
                .pointer("/outcome/value/payload")
                .cloned()
                .unwrap_or(envelope);
            let found = payload["results"].as_array().is_some_and(|results| {
                results.iter().any(|result| {
                    result["message"]["text"]
                        .as_str()
                        .is_some_and(|text| text.contains(JOURNEY_TERM))
                })
            });
            if found {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "upstream message search never recalled the committed hook messages: {payload}"
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
    }

    /// A third completed turn after rollback, proving the retained observer
    /// keeps observing the live session.
    fn append_third_turn(&self) {
        let path = self.transcript_path();
        let turn = self.claude_turn(
            5,
            "2026-02-01T00:10:00.000Z",
            "2026-02-01T00:10:01.000Z",
            &format!("did the {JOURNEY_TERM} retry budget survive the rollback?"),
            &format!("the {JOURNEY_TERM} retry budget survived the rollback unchanged"),
        );
        let mut existing = fs::read_to_string(&path).expect("read host transcript");
        existing.push_str(&turn);
        fs::write(&path, existing).expect("append third host transcript turn");
    }

    fn run_third_stop_hook(&self) -> Output {
        if self.codex {
            return self.run_codex_stop_hook(3);
        }
        self.run_stop_hook()
    }
}

/// A valid retention policy for a *read-only* second handle on the journal.
///
/// This handle never appends, leases, sweeps, or forgets, so none of these
/// bounds ever applies to anything; they exist because `open` validates a
/// policy before it will hand back a store. The bounds the running journey
/// actually enforces are the daemon's own
/// (`ObservationJourneyPolicyV1::project_default`), which this test has no
/// business restating.
/// Structured provider settings are stored as the repository's exact
/// canonical JSON text, so fixtures encode the domain document itself.
fn canonical_text_setting<T: serde::Serialize>(document: &T) -> Value {
    let text = String::from_utf8(
        tracedecay_domain::canonical_json_bytes(document).expect("canonical setting document"),
    )
    .expect("canonical setting text is UTF-8");
    json!({ "kind": "text", "value": text })
}

/// The journey's routing policy: the selected provider, with the typed
/// history degradations the multi-session recall legitimately reports.
fn journey_routing_setting(active_provider: ActiveProvider) -> Value {
    canonical_text_setting(&MemoryProviderRecallRoutingV1 {
        active_provider: Some(active_provider.id().to_owned()),
        fallback: None,
        degradation: Some(MemoryProviderRecallDegradationV1 {
            policy_id: "policy.host-cli-journey.history.v1".to_owned(),
            policy_revision: 1,
            allowed_causes: vec![
                MemoryProviderRecallDegradationCauseV1::Partial,
                MemoryProviderRecallDegradationCauseV1::Stale,
            ],
        }),
    })
}

fn inspection_retention_policy() -> RetentionPolicyV1 {
    RetentionPolicyV1 {
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
    }
}

/// The row identity a replayed hook must reproduce exactly: who the
/// observation is, what content it carries, and how many attempts it cost.
///
/// Comparing this set — not a length — is what makes the idempotency claim
/// real: a journal that dropped one row and admitted a different one has the
/// same length and a different set.
fn journal_row_identities(rows: &[JournalInspectionRowV1]) -> Vec<(String, String, String, u32)> {
    let mut identities = rows
        .iter()
        .map(|row| {
            (
                row.idempotency_key.as_str().to_owned(),
                row.observation_id.as_str().to_owned(),
                row.payload_sha256.clone(),
                row.attempt_number,
            )
        })
        .collect::<Vec<_>>();
    identities.sort();
    identities
}

/// A compact, sorted description of the journal, so a failed wait names what it
/// actually observed instead of reporting only a deadline.
fn journal_digest(rows: &[JournalInspectionRowV1]) -> Vec<String> {
    let mut digest = rows
        .iter()
        .map(|row| {
            format!(
                "{}|{}|{}|attempt={}|seq={}|content_present={}",
                row.observation_kind,
                row.exact_scope_sha256,
                row.state.as_wire(),
                row.attempt_number,
                row.source_sequence.0,
                row.content_present,
            )
        })
        .collect::<Vec<_>>();
    digest.sort();
    digest
}

/// NCM keeps its own state and must apply every committed message once, with
/// its own acknowledgement digest.
fn assert_session_message_receipt(receipt: &ObservationDeliveryReceiptV1) {
    assert_eq!(receipt.outcome, ObservationOutcomeV1::Applied);
    assert_eq!(
        receipt.committed_effect,
        ObservationCommittedEffectV1::Applied
    );
    assert!(
        receipt
            .provider_receipt_digest
            .as_ref()
            .is_some_and(|digest| digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "an applied delivery must carry its provider acknowledgement digest"
    );
}

fn assert_settled_session_messages(rows: &[JournalInspectionRowV1], expected: usize) {
    assert_eq!(
        rows.len(),
        expected,
        "the committed Claude turns must produce exactly {expected} deliveries: {:?}",
        journal_digest(rows)
    );
    let mut scopes = rows
        .iter()
        .map(|row| row.exact_scope_sha256.as_str())
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    assert_eq!(
        scopes.len(),
        1,
        "every row this host session produced belongs to one exact coding scope: {:?}",
        journal_digest(rows)
    );
    for row in rows {
        assert_eq!(
            row.observation_kind,
            SESSION_MESSAGE_OBSERVATION_KIND,
            "the hook admits exactly the session-message observation kind: {:?}",
            journal_digest(rows)
        );
        assert_eq!(
            row.state,
            DeliveryStateV1::Acknowledged,
            "NCM acknowledges every committed session message: {:?}",
            journal_digest(rows)
        );
        assert_eq!(
            row.attempt_number,
            1,
            "an accepted observation is delivered once, never retried: {:?}",
            journal_digest(rows)
        );
        assert!(
            row.content_present,
            "a settled delivery still holds its content until retention takes it: {:?}",
            journal_digest(rows)
        );
    }
    // Distinct messages, not one message journalled repeatedly.
    let mut sequences = rows
        .iter()
        .map(|row| row.source_sequence.0)
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    sequences.dedup();
    assert_eq!(
        sequences.len(),
        expected,
        "each committed message occupies its own source position: {:?}",
        journal_digest(rows)
    );
}

impl Drop for ClaudeHostJourney {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn install_binary_shim(bin_dir: &Path) {
    let shim = bin_dir.join(if cfg!(windows) {
        "tracedecay.exe"
    } else {
        "tracedecay"
    });
    if fs::hard_link(env!("CARGO_BIN_EXE_tracedecay"), &shim).is_err() {
        fs::copy(env!("CARGO_BIN_EXE_tracedecay"), &shim).expect("stage the shipped binary");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&shim).expect("shim metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&shim, permissions).expect("shim is executable");
    }
}

/// A real git project: the composition refuses to resolve an exact scope
/// without a repository, a worktree, and a checked-out reference.
fn initialize_project(project: &Path) {
    fs::create_dir_all(project.join("src")).expect("project source directory");
    git(project, &["init", "--quiet", "-b", "main"]);
    git(project, &["config", "user.email", "journey@example.com"]);
    git(project, &["config", "user.name", "Journey"]);
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname=\"claude-host-journey-fixture\"\nversion=\"0.0.0\"\nedition=\"2024\"\n",
    )
    .expect("fixture manifest");
    fs::write(
        project.join("src/lib.rs"),
        "/// Quicksilver transport probe.\npub fn quicksilver_probe() -> u8 { 7 }\n",
    )
    .expect("fixture source");
    git(project, &["add", "."]);
    git(project, &["commit", "--quiet", "-m", "initial"]);
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(arguments)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {arguments:?} failed");
}

fn daemon_authority_path(profile_root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        profile_root
            .join("daemon-authority")
            .join("daemon-authority.json")
    }
    #[cfg(not(windows))]
    {
        profile_root.join("daemon-authority.json")
    }
}

fn wait_for_authority(daemon: &mut Child, path: &Path) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("daemon listener probe runtime");
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        if let Some(status) = daemon.try_wait().expect("daemon status") {
            let mut stderr = String::new();
            if let Some(mut piped) = daemon.stderr.take() {
                let _ = piped.read_to_string(&mut stderr);
            }
            panic!("daemon exited before publishing authority: {status}; stderr: {stderr}");
        }
        if let Ok(bytes) = fs::read(path)
            && let Ok(record) = serde_json::from_slice::<DaemonAuthorityRecord>(&bytes)
            && record.pid == daemon.id()
            && record.auth_token.len() == 64
        {
            // Authority JSON survives shutdown and is published before bind.
            // Require this child and its listener; the shipped hook and tool
            // calls that follow prove authenticated route publication.
            if runtime.block_on(async {
                matches!(
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        BrokerStream::connect(&record.endpoint),
                    )
                    .await,
                    Ok(Ok(_))
                )
            }) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timed out waiting for the daemon to publish its authority at {}",
        path.display()
    );
}

fn run_ok(command: &mut Command, label: &str) -> Vec<u8> {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{label} could not run: {error}"));
    assert!(
        output.status.success(),
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// First file with this name anywhere under `root`, so the journal is found
/// through the profile's own store layout instead of a guessed path.
fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|found| found == name) {
                return Some(path);
            }
        }
    }
    None
}

/// Joins semantic `content[*].text` blocks of a compatibility MCP result, or
/// `None` when the value is not one. Transport accounting may be appended to
/// the same text block and is not part of the tool's JSON payload.
fn join_content_text(result: &Value) -> Option<String> {
    let blocks = result.get("content")?.as_array()?;
    let texts = blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .map(|text| {
            text.lines()
                .take_while(|line| !line.trim_start().starts_with("tracedecay_metrics:"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|text| !text.trim().is_empty())
        .collect::<Vec<_>>();
    // A structured result is one JSON block; independent host notices (such
    // as an available-upgrade warning) travel in their own content blocks.
    let mut structured = texts
        .iter()
        .filter(|text| serde_json::from_str::<Value>(text).is_ok_and(|value| value.is_object()));
    if let (Some(only), None) = (structured.next(), structured.next()) {
        return Some(only.clone());
    }
    let text = texts.join("\n\n");
    (!text.is_empty()).then_some(text)
}

/// Every string value stored under `field`, anywhere in the document. Typed
/// application-surface envelopes nest their payload differently per operation,
/// and this journey only needs the daemon's own reported value, not the shape
/// it happened to be wrapped in.
fn collect_string_field(value: &Value, field: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                if key == field
                    && let Some(text) = member.as_str()
                {
                    out.push(text.to_owned());
                } else {
                    collect_string_field(member, field, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_string_field(item, field, out);
            }
        }
        _ => {}
    }
}

/// The advisory provider-memory lane of one `tracedecay_context` answer, or
/// `None` when the answer carries no lane at all.
fn advisory_lane(answer: &Value) -> Option<Value> {
    answer
        .get("advisory_provider_memory")
        .filter(|value| !value.is_null())
        .cloned()
}

#[derive(Debug)]
struct NcmRecallDiagnosticRecord {
    request_digest: String,
    stage: String,
    state_generation: u64,
    scanned_items: u64,
    candidate_count: u64,
}

/// Parses the fixed scalar subset emitted by the test-only NCM sink. Values
/// are deliberately logfmt-safe, so a malformed or duplicate field cannot be
/// mistaken for a valid stage marker.
fn parse_ncm_recall_diagnostic(line: &str) -> Option<NcmRecallDiagnosticRecord> {
    if line.len() > 4096 {
        return None;
    }
    let encoded = line.strip_prefix(NCM_RECALL_DIAGNOSTIC_EVENT)?;
    let mut fields = BTreeMap::new();
    for token in encoded.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        if fields.insert(key, value).is_some() {
            return None;
        }
    }
    const ALLOWED_FIELDS: &[&str] = &[
        "stage",
        "request_digest",
        "state_generation",
        "scanned_items",
        "candidate_count",
        "excluded_count",
        "truncated_count",
        "unknown_count",
        "empty_content_count",
        "score_tie_count",
        "score_margin_below_epsilon_count",
        "remaining_candidate_slots",
        "remaining_content_bytes",
    ];
    if fields.keys().any(|key| !ALLOWED_FIELDS.contains(key)) {
        return None;
    }
    let request_digest = fields.get("request_digest").copied()?;
    if request_digest.len() != 64
        || !request_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let stage = fields.get("stage").copied()?;
    if !matches!(
        stage,
        "worker"
            | "reconstructed"
            | "partial_reply"
            | "post_dispatch_cancellation"
            | "post_dispatch_deadline"
            | "reconstruction_failure"
    ) {
        return None;
    }
    for field in ALLOWED_FIELDS.iter().skip(2) {
        fields.get(field)?.parse::<u64>().ok()?;
    }
    Some(NcmRecallDiagnosticRecord {
        request_digest: request_digest.to_owned(),
        stage: stage.to_owned(),
        state_generation: fields.get("state_generation")?.parse().ok()?,
        scanned_items: fields.get("scanned_items")?.parse().ok()?,
        candidate_count: fields.get("candidate_count")?.parse().ok()?,
    })
}

/// The pinned recall policy allows useful Partial/Stale evidence. Keep the
/// actual returned label; an accepted degraded answer is not a complete answer.
fn assert_recall_degradation(lane: &Value) {
    let degradation = lane
        .get("degradation")
        .expect("an answered lane must retain its actual degradation metadata");
    assert!(
        degradation.is_null() || matches!(degradation.as_str(), Some("partial" | "stale")),
        "the journey only permits its pinned Partial/Stale degradations: {lane}"
    );
}

fn journey_task() -> String {
    format!("how does the {JOURNEY_TERM} transport probe decide its retry budget?")
}

/// The agent session that resumes the project after a daemon restart.
fn next_session_id(journey: &ClaudeHostJourney) -> &'static str {
    if journey.codex {
        "5ab47634-f1b2-4ccd-a1c3-2b0c2a9a3e10"
    } else {
        "b93546e4-5ca5-4e9a-a94c-d4867f679ee2"
    }
}

// ---------------------------------------------------------------------------
// The journeys
// ---------------------------------------------------------------------------

/// Native selected: the provider host adds nothing to upstream memory. The
/// shipped SessionStart and Stop hooks commit canonical history that upstream
/// message search recalls, `tracedecay_context` carries no provider lane, no
/// observation journal exists, and canonical facts keep their own authority.
#[test]
fn native_selected_claude_host_journey_is_upstream_memory_with_no_provider_lane() {
    assert_native_selected_journey(false);
}

#[test]
fn native_selected_codex_host_journey_is_upstream_memory_with_no_provider_lane() {
    assert_native_selected_journey(true);
}

/// Opt-in production mount coverage: actual worker plus pinned offline model,
/// configured through the shipped CLI. NCM observes every committed message
/// exactly once while Native keeps answering as upstream memory, and a daemon
/// restart redelivers nothing NCM already acknowledged.
#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_observer_receives_shipped_claude_hooks_while_native_answers_context() {
    assert_ncm_observer_journey(false);
}

#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_observer_receives_shipped_codex_hooks_while_native_answers_context() {
    assert_ncm_observer_journey(true);
}

/// NCM active: it answers the originating session from what that session's
/// hooks delivered, and after a restart answers a different session of the
/// same project from the same state. Nothing is replayed to it at recall.
#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_active_recalls_claude_history_across_sessions_from_its_own_state() {
    assert_ncm_active_journey(false);
}

#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_active_recalls_codex_history_across_sessions_from_its_own_state() {
    assert_ncm_active_journey(true);
}

/// Operator rollback from an active real NCM worker to Native. After one
/// restart Native answers as upstream memory, the installed NCM stays mounted
/// as an observer, nothing it acknowledged is redelivered, and it keeps
/// observing new turns.
#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_active_recall_rolls_back_to_native_without_redelivering_history() {
    assert_ncm_to_native_rollback_journey(false);
}

#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
fn real_ncm_active_codex_recall_rolls_back_to_native_without_redelivering_history() {
    assert_ncm_to_native_rollback_journey(true);
}

/// Two completed turns of the journey's own session through the shipped
/// lifecycle hooks: SessionStart establishes the live baseline, each Stop
/// commits one turn, and every Stop is replayed once. When NCM participates,
/// its journal proves each step: nothing lands without a hook, each turn
/// settles exactly its own messages once, and a replayed hook reproduces the
/// same rows by identity.
fn drive_two_hook_turns(journey: &ClaudeHostJourney) -> Vec<JournalInspectionRowV1> {
    let observed = journey.ncm_participates();
    journey.initialize_session_transcript(journey.session_id());
    let started = journey.run_session_start_event(journey.session_id(), &journey.transcript_path());
    assert!(
        started.status.success(),
        "SessionStart must establish the live source baseline: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    journey.write_claude_transcript();
    if observed {
        journey.assert_journal_unchanged_without_a_hook(&[]);
    }
    let first = journey.run_first_stop_hook();
    assert!(
        first.status.success(),
        "the shipped first Stop hook must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let mut rows = Vec::new();
    if observed {
        rows = journey.await_settled_journal(ROWS_PER_TURN);
        assert_settled_session_messages(&rows, ROWS_PER_TURN);
    }
    let replay = journey.run_first_stop_hook();
    assert!(replay.status.success(), "a replayed hook must still succeed");
    if observed {
        let replayed = journey.await_settled_journal(ROWS_PER_TURN);
        assert_eq!(
            journal_row_identities(&replayed),
            journal_row_identities(&rows),
            "replaying one hook invocation must reproduce exactly the same deliveries: {:?}",
            journal_digest(&replayed)
        );
        rows = replayed;
    }
    journey.append_mid_session_claude_turn();
    if observed {
        journey.assert_journal_unchanged_without_a_hook(&rows);
    }
    let stop = journey.run_stop_hook();
    assert!(
        stop.status.success(),
        "the shipped Stop hook must succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
    if observed {
        rows = journey.await_settled_journal(2 * ROWS_PER_TURN);
        assert_settled_session_messages(&rows, 2 * ROWS_PER_TURN);
    }
    let stop_replay = journey.run_stop_hook();
    assert!(
        stop_replay.status.success(),
        "a replayed Stop hook must still succeed"
    );
    if observed {
        let replayed = journey.await_settled_journal(2 * ROWS_PER_TURN);
        assert_eq!(
            journal_row_identities(&replayed),
            journal_row_identities(&rows),
            "replaying the Stop hook must reproduce exactly the same deliveries: {:?}",
            journal_digest(&replayed)
        );
        journey.assert_ncm_deliveries(&replayed);
        rows = replayed;
    }
    rows
}

fn assert_native_selected_journey(codex: bool) {
    let mut journey = ClaudeHostJourney::start(codex, ActiveProvider::Native, false);
    let baseline = journey.tool(
        "tracedecay_context",
        &json!({ "task": journey_task(), "format": "json" }),
    );
    assert!(
        advisory_lane(&baseline).is_none(),
        "Native is upstream memory; tracedecay_context carries no provider lane: {baseline}"
    );
    journey.await_startup_history();
    drive_two_hook_turns(&journey);
    let answer = journey.tool(
        "tracedecay_context",
        &json!({
            "task": journey_task(),
            "format": "json",
        }),
    );
    assert!(
        advisory_lane(&answer).is_none(),
        "Native-selected recall stays upstream memory after live hooks: {answer}"
    );
    journey.assert_no_provider_journal();
    journey.assert_message_search_recalls_journey();
    let session = journey.session_id();
    assert_canonical_fact_feedback_journey(&mut journey, session);
    #[cfg(unix)]
    provider_control_journeys::assert_provider_control_journeys(&mut journey, session);
    journey.assert_no_provider_journal();
}

#[cfg(unix)]
fn assert_ncm_observer_journey(codex: bool) {
    let mut journey = ClaudeHostJourney::start(codex, ActiveProvider::Native, true);
    let baseline = journey.tool(
        "tracedecay_context",
        &json!({ "task": journey_task(), "format": "json" }),
    );
    assert!(
        advisory_lane(&baseline).is_none(),
        "an observer never answers; Native stays upstream memory: {baseline}"
    );
    assert!(
        journey.journal().is_some(),
        "the configured NCM observer mounts its own journal"
    );
    assert!(
        journey.journal_rows().is_empty(),
        "the observer starts with no messages"
    );
    journey.assert_no_native_journal();
    journey.await_startup_history();
    let rows = drive_two_hook_turns(&journey);
    let answer = journey.tool(
        "tracedecay_context",
        &json!({
            "task": journey_task(),
            "format": "json",
        }),
    );
    assert!(
        advisory_lane(&answer).is_none(),
        "Native keeps answering while NCM observes: {answer}"
    );
    journey.assert_message_search_recalls_journey();

    // A fresh daemon replays its canonical backlog to the observer; every
    // message NCM already acknowledged is behind its watermark.
    journey.stop_daemon();
    journey.start_daemon();
    let reopened = journey.tool(
        "tracedecay_context",
        &json!({ "task": journey_task(), "format": "json" }),
    );
    assert!(advisory_lane(&reopened).is_none(), "{reopened}");
    journey.await_startup_history();
    journey.assert_journal_unchanged_without_a_hook(&rows);
    journey.assert_ncm_deliveries(&journey.journal_rows());
    journey.assert_no_native_journal();
}

#[cfg(unix)]
fn assert_ncm_active_journey(codex: bool) {
    let mut journey = ClaudeHostJourney::start(codex, ActiveProvider::RustNcm, false);
    let baseline = journey.tool(
        "tracedecay_context",
        &json!({ "task": journey_task(), "format": "json" }),
    );
    let baseline_lane = advisory_lane(&baseline)
        .unwrap_or_else(|| panic!("active NCM must mount the advisory lane: {baseline}"));
    assert_eq!(baseline_lane["provider_id"], NCM_OBSERVER_PROVIDER_ID);
    assert!(
        journey.journal_rows().is_empty(),
        "the journey starts from an empty journal, so the hook's effect is unambiguous"
    );
    journey.assert_no_native_journal();
    journey.await_startup_history();

    // 1. The originating session recalls exactly what its hooks delivered.
    let rows = drive_two_hook_turns(&journey);
    let mut original_sources = capture_original_hook_sources(&journey, &rows);
    let original =
        assert_recalled_session_messages(&journey, journey.session_id(), &original_sources);

    // 2. While the daemon is down a producer-owned canonical source lands in
    //    the same session. The single restart delivers exactly that record;
    //    nothing NCM acknowledged is delivered again.
    let project_id = journey.project_id();
    journey.stop_daemon();
    let revision_fixture_id = journey.produce_revision_fixture(journey.session_id(), &project_id);
    journey.start_daemon();

    // 3. A different agent session starts through the shipped lifecycle with an
    //    empty transcript and recalls the same durable messages from NCM's own
    //    state: route binding adds no canonical messages and no delivery.
    let next_session = next_session_id(&journey);
    let next_transcript = journey.transcript_path_for_session(next_session);
    journey.initialize_session_transcript(next_session);
    let started = journey.run_session_start_event(next_session, &next_transcript);
    assert!(
        started.status.success(),
        "next SessionStart must publish its route: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let expected_sources = 2 * ROWS_PER_TURN + 1;
    let after_start = journey.await_settled_journal(expected_sources);
    assert_settled_session_messages(&after_start, expected_sources);
    let after_start_identities = journal_row_identities(&after_start);
    assert!(
        journal_row_identities(&rows)
            .iter()
            .all(|identity| after_start_identities.contains(identity)),
        "the restart must preserve every acknowledged delivery unchanged"
    );
    journey.assert_ncm_deliveries(&after_start);
    let (revision_source_event_id, revision_source) =
        capture_revision_fixture_source(&journey, &after_start, &revision_fixture_id);
    assert!(
        original_sources
            .insert(revision_source_event_id, revision_source)
            .is_none(),
        "the revision producer must add one distinct canonical source"
    );
    let recalled = assert_recalled_session_messages(&journey, next_session, &original_sources);
    assert_eq!(
        recalled.0.len(),
        original.0.len() + 1,
        "the other session recalls the four hook messages plus the revisioned producer source"
    );
    assert!(
        original
            .0
            .iter()
            .all(|identity| recalled.0.contains(identity)),
        "another session must recall every original message with its canonical source evidence"
    );
    assert_ne!(
        original.2, recalled.2,
        "each session's recall must have a fresh recall trace"
    );
    #[cfg(unix)]
    provider_control_journeys::assert_provider_control_journeys(&mut journey, next_session);
}

#[cfg(unix)]
fn assert_ncm_to_native_rollback_journey(codex: bool) {
    let mut journey = ClaudeHostJourney::start(codex, ActiveProvider::RustNcm, false);
    let baseline = journey.tool(
        "tracedecay_context",
        &json!({ "task": journey_task(), "format": "json" }),
    );
    let baseline_lane = advisory_lane(&baseline)
        .unwrap_or_else(|| panic!("active NCM must mount the advisory lane: {baseline}"));
    assert_eq!(baseline_lane["provider_id"], NCM_OBSERVER_PROVIDER_ID);
    journey.assert_no_native_journal();
    journey.await_startup_history();

    let rows = drive_two_hook_turns(&journey);
    let sources = capture_original_hook_sources(&journey, &rows);
    assert_recalled_session_messages(&journey, journey.session_id(), &sources);
    let acknowledged = journey.journal_rows();

    // Roll the project back to Native through the same public settings. The
    // NCM configuration is deliberately left in place, so NCM remains mounted
    // as an observer.
    let project_id = journey.project_id();
    journey.configuration_set(
        &project_id,
        MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
        json!({ "kind": "boolean", "value": true }),
        "configuration.idempotency.rollback-native-enable",
    );
    journey.configuration_set(
        &project_id,
        MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
        journey_routing_setting(ActiveProvider::Native),
        "configuration.idempotency.rollback-native-route",
    );
    journey.stop_daemon();
    journey.active_provider = ActiveProvider::Native;
    journey.ncm_observer = true;
    journey.start_daemon();

    let rolled_back = journey.tool(
        "tracedecay_context",
        &json!({
            "task": journey_task(),
            "format": "json",
        }),
    );
    assert!(
        advisory_lane(&rolled_back).is_none(),
        "rolled-back Native answers as upstream memory with no provider lane: {rolled_back}"
    );
    journey.await_startup_history();
    journey.assert_journal_unchanged_without_a_hook(&acknowledged);
    journey.assert_ncm_deliveries(&acknowledged);
    journey.assert_no_native_journal();
    journey.assert_message_search_recalls_journey();

    // The retained observer keeps observing the live session.
    journey.append_third_turn();
    let third = journey.run_third_stop_hook();
    assert!(
        third.status.success(),
        "the Stop hook after rollback must succeed: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    let observed = journey.await_settled_journal(acknowledged.len() + ROWS_PER_TURN);
    assert_eq!(observed.len(), acknowledged.len() + ROWS_PER_TURN);
    let observed_identities = journal_row_identities(&observed);
    assert!(
        journal_row_identities(&acknowledged)
            .iter()
            .all(|identity| observed_identities.contains(identity)),
        "rollback must preserve every NCM delivery unchanged"
    );
    journey.assert_ncm_deliveries(&observed);
}

/// Canonical fact feedback has its own public host authority. This separate
/// journey does not attribute an outcome to any staged session observation.
fn assert_canonical_fact_feedback_journey(journey: &mut ClaudeHostJourney, session_id: &str) {
    let canonical_payload = |journey: &ClaudeHostJourney, name: &str, arguments: Value| {
        let response = journey.tool(name, &arguments);
        response
            .pointer("/outcome/value/payload")
            .cloned()
            .unwrap_or_else(|| {
                panic!("{name} omitted its canonical application payload: {response}")
            })
    };
    let term = if journey.codex {
        "amber garden codex feedback"
    } else {
        "amber garden claude feedback"
    };
    let content = format!("The {term} retry budget is three seconds.");
    let created = canonical_payload(
        journey,
        "tracedecay_fact_store_add",
        json!({ "content": content, "category": "decision", "trust": 0.5, "format": "json" }),
    );
    assert_eq!(created["outcome"], "committed");
    assert_eq!(created["result"]["disposition"], "added");
    assert_eq!(created["result"]["fact"]["kind"], "available");
    let fact_id = created["result"]["fact"]["fact"]["fact_id"]
        .as_str()
        .expect("created canonical fact identity")
        .to_owned();
    assert_eq!(created["result"]["commit"]["fact_id"], fact_id);

    // Native is upstream memory: the context answer carries the canonical fact
    // lane and never a provider lane beside it.
    let assert_context_has_no_provider_lane = |journey: &ClaudeHostJourney| {
        let answer = journey.tool(
            "tracedecay_context",
            &json!({
                "task": term,
                "format": "json",
            }),
        );
        assert!(
            advisory_lane(&answer).is_none(),
            "Native-selected context carries no provider lane: {answer}"
        );
    };
    assert_context_has_no_provider_lane(journey);
    let before = canonical_payload(
        journey,
        "tracedecay_fact_store_get",
        json!({ "fact_id": fact_id, "format": "json" }),
    );
    assert_eq!(before["fact"]["kind"], "available");
    assert_eq!(before["fact"]["fact"]["fact_id"], fact_id);
    assert_eq!(before["fact"]["fact"]["content"], content);
    let previous_event = before["fact"]["fact"]["last_event_id"]
        .as_str()
        .expect("current canonical event");
    let old_trust = before["fact"]["fact"]["trust_score_millionths"]
        .as_u64()
        .expect("current canonical trust");
    let source_label = format!("native-canonical-feedback-{session_id}");
    let reason = "The canonical fact read supplied the retry budget.";
    let feedback = canonical_payload(
        journey,
        "tracedecay_fact_feedback",
        json!({
            "fact_id": fact_id,
            "expected_last_event_id": previous_event,
            "action": "helpful",
            "source_label": source_label,
            "reason": reason,
            "format": "json",
        }),
    );
    assert_eq!(feedback["feedback"]["fact_id"], fact_id);
    assert_eq!(feedback["feedback"]["action"], "helpful");
    assert_eq!(feedback["feedback"]["old_trust_millionths"], old_trust);
    let new_trust = feedback["feedback"]["new_trust_millionths"]
        .as_u64()
        .expect("feedback trust");
    assert!(
        new_trust > old_trust,
        "helpful feedback must increase trust: {feedback}"
    );
    assert_eq!(feedback["feedback"]["helpful_count"], 1);
    assert_eq!(feedback["feedback"]["unhelpful_count"], 0);
    let feedback_event = feedback["feedback"]["event_id"]
        .as_str()
        .expect("canonical feedback event");
    assert_ne!(feedback_event, previous_event);
    assert_eq!(feedback["fact"]["kind"], "available");
    assert_eq!(feedback["fact"]["fact"]["fact_id"], fact_id);
    assert_eq!(feedback["fact"]["fact"]["last_event_id"], feedback_event);
    assert_eq!(
        feedback["fact"]["fact"]["trust_score_millionths"],
        new_trust
    );
    assert_eq!(feedback["commit"]["disposition"], "committed");
    assert_eq!(
        feedback["commit"]["owner"],
        created["result"]["commit"]["owner"]
    );
    assert_eq!(feedback["commit"]["fact_id"], fact_id);
    assert_eq!(feedback["commit"]["last_event_id"], feedback_event);
    assert!(
        feedback["commit"]["committed_event_ids"]
            .as_array()
            .expect("committed feedback events")
            .contains(&json!(feedback_event))
    );

    // Restart only to prove the feedback event and its attribution are durable.
    journey.stop_daemon();
    journey.start_daemon();
    // The route is process-local; the shipped hook republishes the same session.
    let transcript = journey.transcript_path_for_session(session_id);
    let started = journey.run_session_start_event(session_id, &transcript);
    assert!(
        started.status.success(),
        "SessionStart must republish the canonical feedback session after restart: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let persisted = canonical_payload(
        journey,
        "tracedecay_fact_store_get",
        json!({ "fact_id": fact_id, "format": "json" }),
    );
    assert_eq!(persisted["fact"]["kind"], "available");
    assert_eq!(persisted["fact"]["fact"]["fact_id"], fact_id);
    assert_eq!(persisted["fact"]["fact"]["content"], content);
    assert_eq!(persisted["fact"]["fact"]["last_event_id"], feedback_event);
    assert_eq!(
        persisted["fact"]["fact"]["trust_score_millionths"],
        new_trust
    );
    let history = persisted["trust_history"]
        .as_array()
        .expect("persisted trust history");
    assert_eq!(
        history.len(),
        1,
        "one attributed feedback event must survive restart"
    );
    assert_eq!(history[0]["event_id"], feedback_event);
    assert_eq!(history[0]["action"], "helpful");
    assert_eq!(history[0]["source_label"], source_label);
    assert_eq!(history[0]["reason"], reason);
    assert_eq!(history[0]["old_trust_millionths"], old_trust);
    assert_eq!(history[0]["new_trust_millionths"], new_trust);
    assert_context_has_no_provider_lane(journey);
}

/// Exact scope read from an admitted host envelope; session encoding belongs
/// to the host and is never reconstructed from a canonical session string.
fn admitted_scope(admitted: &AdmittedObservationV1) -> Value {
    let scope = &admitted.exact_scope;
    json!({
        "profile_id": scope.profile_id, "project_id": scope.project_id,
        "repository_identity": scope.repository_identity, "worktree_identity": scope.worktree_identity,
        "branch_identity": scope.branch_identity, "agent_session_id": scope.agent_session_id,
        "resolved_scope_digest": scope.resolved_scope_digest,
    })
}

fn capture_original_hook_sources(
    journey: &ClaudeHostJourney,
    rows: &[JournalInspectionRowV1],
) -> BTreeMap<String, Value> {
    let journal = journey
        .journal()
        .expect("mounted NCM journal");
    let mut originals = BTreeMap::new();
    for row in rows {
        assert_eq!(row.source_stream, "session_observation_store");
        let admitted = journal
            .read_admitted_observation_by_idempotency(&row.idempotency_key)
            .expect("read original admitted hook evidence")
            .expect("original content retained");
        let payload: Value =
            serde_json::from_slice(&admitted.payload.bytes).expect("canonical admitted payload");
        let canonical: tracedecay_domain::observation::CanonicalObservationEnvelopeV1 =
            serde_json::from_value(payload["canonical_payload"].clone())
                .expect("canonical source envelope");
        canonical
            .validate()
            .expect("valid canonical source envelope");
        assert_eq!(
            canonical.provider().as_str(),
            if journey.codex { "codex" } else { "claude" }
        );
        assert_eq!(
            canonical.relations().session_id().as_str(),
            journey.session_id()
        );
        assert!(
            payload.get("history_grant").is_none(),
            "the host never dispatches provider history"
        );
        let captured = json!({
            "canonical_provider_id": canonical.provider().as_str(),
            "canonical_session_id": canonical.relations().session_id().as_str(),
            "stable_record_id": canonical.stable_record_id().as_str(),
            "source_revision": canonical.evidence().revision(),
            "source_sequence": admitted.source.source_sequence.0,
            "original_scope": admitted_scope(&admitted),
        });
        assert!(
            originals
                .insert(admitted.source.source_event_id.clone(), captured)
                .is_none(),
            "hook source identities are unique"
        );
    }
    assert_eq!(originals.len(), 2 * ROWS_PER_TURN);
    originals
}

/// Capture the producer fixture's admitted source from the same provider
/// journal surface as the hook rows. This keeps the later control selector
/// bound to the source the restarted daemon actually replayed, while making
/// the non-null canonical revision an explicit assertion of the producer
/// contract.
fn capture_revision_fixture_source(
    journey: &ClaudeHostJourney,
    rows: &[JournalInspectionRowV1],
    fixture_observation_id: &CanonicalObservationIdV1,
) -> (String, Value) {
    let journal = journey
        .journal()
        .expect("mounted NCM journal");
    let matching = rows
        .iter()
        .filter_map(|row| {
            let admitted = journal
                .read_admitted_observation_by_idempotency(&row.idempotency_key)
                .expect("read revision fixture admission");
            let Some(admitted) = admitted else {
                return None;
            };
            (admitted.source.source_event_id == fixture_observation_id.as_str())
                .then_some((row, admitted))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "the restarted provider must admit the revision fixture exactly once"
    );
    let (_, admitted) = matching.into_iter().next().expect("revision fixture row");
    admitted
        .validate()
        .expect("revision fixture admission validates");
    let payload: Value =
        serde_json::from_slice(&admitted.payload.bytes).expect("revision fixture payload");
    assert!(
        payload.get("history_grant").is_none(),
        "the producer fixture reaches the provider as a live canonical source"
    );
    let canonical: CanonicalObservationEnvelopeV1 =
        serde_json::from_value(payload["canonical_payload"].clone())
            .expect("revision fixture canonical envelope");
    canonical
        .validate()
        .expect("revision fixture canonical envelope validates");
    assert_eq!(
        canonical.provider().as_str(),
        if journey.codex { "codex" } else { "claude" }
    );
    assert_eq!(
        canonical.relations().session_id().as_str(),
        journey.session_id()
    );
    assert_eq!(
        canonical.stable_record_id().as_str(),
        REVISION_FIXTURE_RECORD_ID
    );
    assert_eq!(
        canonical.evidence().revision(),
        Some(REVISION_FIXTURE_REVISION),
        "the producer fixture must retain its canonical source revision"
    );
    assert_eq!(
        admitted.source.source_event_id,
        fixture_observation_id.as_str(),
        "the journal source event must retain the producer fixture observation id"
    );
    let captured = json!({
        "canonical_provider_id": canonical.provider().as_str(),
        "canonical_session_id": canonical.relations().session_id().as_str(),
        "stable_record_id": canonical.stable_record_id().as_str(),
        "source_revision": canonical.evidence().revision(),
        "source_sequence": admitted.source.source_sequence.0,
        "original_scope": admitted_scope(&admitted),
    });
    (admitted.source.source_event_id.clone(), captured)
}

fn assert_original_source(source: &Value, captured: &Value) {
    for field in [
        "canonical_provider_id",
        "canonical_session_id",
        "source_revision",
    ] {
        assert_eq!(
            source["source"][field], captured[field],
            "original {field} must match pre-recall A evidence"
        );
    }
    if !source["source"]["stable_record_id"].is_null() {
        assert_eq!(
            source["source"]["stable_record_id"],
            captured["stable_record_id"]
        );
    }
    assert_eq!(source["source_sequence"], captured["source_sequence"]);
    assert_eq!(source["origin_scope"]["state"], "recorded");
    assert_eq!(
        source["origin_scope"]["exact_scope_identity"], captured["original_scope"],
        "a recalled source keeps the scope of the session that recorded it"
    );
    assert!(
        source["origin_scope"]["authority_ref"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

/// One `tracedecay_context` recall made while `recalled_session_id` is the live
/// agent session, answered by the active NCM provider from its own state. The
/// lane binds each shipped CLI call to its own MCP connection, so every recall
/// here is served across sessions from the project's checkout memory. Returns canonical content and
/// provenance identities, the raw result bytes, and the lane's recall trace.
///
/// Every candidate must carry host-confirmed canonical observation evidence
/// for the captured hook sources, the mid-session message must arrive whole,
/// and the recall must deliver nothing to the provider: the host replays no
/// history at recall time.
fn assert_recalled_session_messages(
    journey: &ClaudeHostJourney,
    recalled_session_id: &str,
    original_sources: &BTreeMap<String, Value>,
) -> (Vec<(String, String)>, Vec<u8>, String) {
    let before_recall = journal_row_identities(&journey.journal_rows());
    let (answer, result_bytes) = journey.tool_with_bytes(
        "tracedecay_context",
        &json!({
            "task": format!(
                "what did the {JOURNEY_TERM} retry budget change record, down to the \
                 {TAIL_SENTINEL} note?"
            ),
            "format": "json",
        }),
    );
    let lane = advisory_lane(&answer)
        .unwrap_or_else(|| panic!("the active provider must contribute an advisory lane: {answer}"));
    assert_eq!(
        lane["state"], "answered",
        "the advisory lane must answer rather than report a refusal (origin_session={}): {lane}",
        recalled_session_id == journey.session_id(),
    );
    assert_recall_degradation(&lane);
    assert_eq!(
        lane["provider_id"],
        journey.active_provider.id(),
        "the lane must name the provider the routing policy pinned: {lane}"
    );
    assert_eq!(lane["registration_revision"], 1, "{lane}");
    let trace_ref = lane["recall_trace"]["trace_ref"]
        .as_str()
        .expect("the lane must identify its recall trace");
    assert!(!trace_ref.is_empty(), "recall trace must be nonempty");
    let request_id = lane["recall_trace"]["request_id"]
        .as_str()
        .expect("the lane must identify its recall request");
    assert!(!request_id.is_empty(), "recall request must be nonempty");
    let candidates = lane["candidates"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        candidates.len(),
        original_sources.len(),
        "the healthy journey must recall every observed canonical source exactly once (origin_session={}): {lane}",
        recalled_session_id == journey.session_id(),
    );
    journey.assert_ncm_recall_diagnostics(original_sources.len());
    let mut recalled_originals = BTreeSet::new();
    let mut recall_item_refs = BTreeSet::new();
    for candidate in &candidates {
        let evidence = &candidate["provenance_evidence"];
        assert_eq!(
            evidence["recall"]["trace_ref"].as_str(),
            Some(trace_ref),
            "candidate audit evidence must refer to this lane's recall trace"
        );
        let item_ref = evidence["recall"]["item_ref"]
            .as_str()
            .expect("candidate audit evidence must identify its recall item");
        assert!(
            !item_ref.is_empty(),
            "recall item reference must be nonempty"
        );
        assert!(
            recall_item_refs.insert(item_ref),
            "recall item references must be unique within this reply"
        );
        assert_eq!(
            evidence["kind"], "canonical_observations",
            "final candidates require host-confirmed original evidence"
        );
        let sources = evidence["sources"]
            .as_array()
            .expect("typed original sources");
        assert!(
            !sources.is_empty(),
            "admitted content must have original source evidence"
        );
        for source in sources {
            let id = source["source"]["observation_id"]
                .as_str()
                .expect("canonical observation id");
            assert_original_source(
                source,
                original_sources
                    .get(id)
                    .expect("candidate source is one the hooks or producer committed"),
            );
            recalled_originals.insert(id.to_owned());
        }
    }
    assert_eq!(
        recalled_originals,
        original_sources.keys().cloned().collect(),
        "recall must cover the actual original sources"
    );
    let mut provenance = candidates
        .iter()
        .map(|candidate| candidate["provenance"].to_string())
        .collect::<Vec<_>>();
    let total = provenance.len();
    provenance.sort();
    provenance.dedup();
    assert_eq!(
        provenance.len(),
        total,
        "recall candidates must be de-duplicated: {lane}"
    );
    assert!(
        candidates.iter().all(|candidate| {
            candidate["content"]
                .as_str()
                .is_some_and(|content| content.contains(JOURNEY_TERM))
        }),
        "every advisory candidate must be evidence this session actually produced, never \
         fabricated context: {lane}"
    );
    // Whole evidence, not a prefix of it: the mid-session assistant message
    // opens with the journey term and ends with the sentinel, so a candidate
    // carrying both is one the lane did not truncate on its way back.
    assert!(
        candidates.iter().any(|candidate| {
            candidate["content"].as_str().is_some_and(|content| {
                content.contains(JOURNEY_TERM) && content.contains(TAIL_SENTINEL)
            })
        }),
        "the advisory lane must recall the mid-session message whole, tail included: {lane}"
    );
    assert_eq!(
        journal_row_identities(&journey.journal_rows()),
        before_recall,
        "recall delivers nothing: NCM answers from its own state"
    );

    let mut identities = candidates
        .iter()
        .map(|candidate| {
            let mut evidence = candidate["provenance_evidence"].clone();
            evidence
                .as_object_mut()
                .expect("verified canonical provenance evidence")
                .remove("recall");
            (
                candidate["content"]
                    .as_str()
                    .expect("verified message content")
                    .to_owned(),
                json!({
                    "label": candidate["provenance"],
                    "evidence": evidence,
                })
                .to_string(),
            )
        })
        .collect::<Vec<_>>();
    identities.sort();
    (identities, result_bytes, trace_ref.to_owned())
}

/// Stage the installed pinned NCM model into one isolated state root.
///
/// The worker admits only a regular model tree carrying an acquisition
/// receipt bound to its own state root, so the installed tree is hard-linked
/// (or copied across devices) and the product installer then records the
/// offline `already_present` receipt for this root. No model is downloaded.
#[cfg(unix)]
fn stage_isolated_ncm_models(models: &Path, state_root: &Path) -> Result<(), String> {
    fn link_tree(source: &Path, target: &Path) -> std::io::Result<()> {
        let metadata = fs::symlink_metadata(source)?;
        if metadata.is_dir() {
            fs::create_dir_all(target)?;
            for entry in fs::read_dir(source)? {
                let entry = entry?;
                link_tree(&entry.path(), &target.join(entry.file_name()))?;
            }
            Ok(())
        } else if metadata.is_file() {
            fs::hard_link(source, target).or_else(|_| fs::copy(source, target).map(|_| ()))
        } else {
            Err(std::io::Error::other(format!(
                "installed NCM model tree holds an unsupported entry: {}",
                source.display()
            )))
        }
    }
    link_tree(models, &state_root.join("models"))
        .map_err(|error| format!("stage installed NCM models: {error}"))?;
    let root = tracedecay_memory_ncm_runtime::ports::StateRoot::new(state_root)?;
    // Tree verification is deeper than a default test thread's stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tracedecay_memory_ncm_runtime::embedding::install(
                &root,
                tracedecay_memory_ncm_runtime::ports::Deadline {
                    remaining_ms: 120_000,
                },
            )
            .map(|_| ())
            .map_err(|error| format!("record the isolated NCM model receipt: {error}"))
        })
        .map_err(|error| format!("spawn NCM model staging: {error}"))?
        .join()
        .map_err(|_| "NCM model staging panicked".to_owned())?
}
