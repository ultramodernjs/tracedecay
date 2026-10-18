//! Live Hermes provider journey through the shipped CLI and generated plugin.
//!
//! The test installs Hermes into an isolated HOME, starts a real TraceDecay
//! daemon, registers a real git project, enables one configured provider
//! through the operator configuration surface, and then runs the installed
//! Python provider. The provider's project-scoped `ingest_transcript` call,
//! its asynchronous `turnCompleted`/`turnIngested` callbacks, and the
//! installed context-engine callback are therefore exercised as Hermes invokes
//! them. The project observation journal and a later context recall are the
//! assertions that the full route settled.
//!
//! The repository does not ship a stock Hermes runtime, so the Python fixture
//! uses the generated plugin's public `register(ctx)` contract with a faithful
//! minimal `PluginContext` stand-in. The fixture names that boundary in its
//! sentinel; it does not pretend to be a stock loader.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use tracedecay_memory_observation::{
    AdmittedObservationV1, DeliveryStateV1, JournalInspectionFilterV1, JournalInspectionRowV1,
    ObservationCommittedEffectV1, ObservationJournalReaderV1, ObservationOutcomeV1,
    RetentionPolicyV1, SqliteObservationJournal,
};

const SESSION_ID: &str = "hermes-cli-project-journey";
const PROJECT_TERM: &str = "quartz";
const RECALL_QUERY: &str = "Which crystal themed workspace note did Hermes capture?";
const FOREIGN_RECALL_QUERY: &str = "Which crystal themed workspace note did Hermes capture?";
const JOURNAL_FILE_NAME: &str = "memory-observation-journal-v1.sqlite3";
const NCM_JOURNAL_FILE_NAME: &str = "memory-observation-ncm-journal-v1.sqlite3";
const OBSERVATION_KIND: &str = "session.message_committed.v1";
const NATIVE_PROVIDER_ID: &str = "tracedecay.native";
const NCM_PROVIDER_ID: &str = "ncm";
const HERMES_CANONICAL_PROVIDER_ID: &str = "hermes";
const JOURNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SETTLEMENT_BUDGET: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveProvider {
    Native,
    RustNcm,
}

impl ActiveProvider {
    fn id(self) -> &'static str {
        match self {
            Self::Native => NATIVE_PROVIDER_ID,
            Self::RustNcm => NCM_PROVIDER_ID,
        }
    }

    fn journal_file_name(self) -> &'static str {
        match self {
            Self::Native => JOURNAL_FILE_NAME,
            Self::RustNcm => NCM_JOURNAL_FILE_NAME,
        }
    }

    fn is_ncm(self) -> bool {
        self == Self::RustNcm
    }
}

struct HermesJourney {
    home: TempDir,
    profile: PathBuf,
    project: PathBuf,
    foreign_project: PathBuf,
    bin_dir: PathBuf,
    active_provider: ActiveProvider,
    daemon: Option<Child>,
    journal: OnceLock<SqliteObservationJournal>,
}

impl HermesJourney {
    fn new(active_provider: ActiveProvider) -> Self {
        let home = TempDir::new().expect("isolated Hermes HOME");
        let root = home.path().to_path_buf();
        let profile = root.join(".tracedecay");
        let project = root.join("project");
        let foreign_project = root.join("foreign-project");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&profile).expect("profile root");
        fs::create_dir_all(root.join(".hermes")).expect("Hermes home");
        fs::create_dir_all(&bin_dir).expect("binary shim directory");
        install_binary_shim(&bin_dir);
        initialize_project(
            &project,
            "hermes-cli-journey-fixture",
            "pub fn quartz_project_observation() -> u8 { 7 }\n",
        );
        initialize_project(
            &foreign_project,
            "hermes-cli-foreign-journey-fixture",
            "pub fn unrelated_foreign_observation() -> u8 { 3 }\n",
        );
        Self {
            home,
            profile,
            project,
            foreign_project,
            bin_dir,
            active_provider,
            daemon: None,
            journal: OnceLock::new(),
        }
    }

    fn cli(&self, args: &[&str]) -> Command {
        self.cli_at(&self.project, args)
    }

    fn cli_at(&self, project: &Path, args: &[&str]) -> Command {
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.bin_dir.clone()).chain(std::env::split_paths(&inherited_path)),
        )
        .expect("isolated PATH");
        let mut command = Command::new(env!("CARGO_BIN_EXE_tracedecay"));
        command
            .args(args)
            .current_dir(project)
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env("TRACEDECAY_DATA_DIR", &self.profile)
            .env("TRACEDECAY_GLOBAL_DB", self.profile.join("global.db"))
            .env("TRACEDECAY_TEST_ALLOW_INCOMPLETE_HOLDER_SCAN", "1")
            .env("PATH", path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn start_daemon(&mut self) {
        assert!(self.daemon.is_none(), "daemon already running");
        let log = fs::File::create(self.home.path().join("daemon.stderr.log")).expect("daemon log");
        let mut command = self.cli(&["daemon", "run"]);
        command
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let mut daemon = command.spawn().expect("daemon starts");
        wait_for_authority(&mut daemon, &daemon_authority_path(&self.profile));
        self.daemon = Some(daemon);
    }

    fn stop_daemon(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }

    fn init_project(&self) {
        self.init_project_at(&self.project);
    }

    fn init_project_at(&self, project: &Path) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let output = self
                .cli_at(project, &["init"])
                .output()
                .expect("tracedecay init runs");
            if output.status.success() {
                return;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("code_index_scheduler_unavailable"),
                "init failed outside scheduler warming window\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                stderr
            );
            assert!(Instant::now() < deadline, "init never became available");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn project_id(&self) -> String {
        self.project_id_at(&self.project)
    }

    fn project_id_at(&self, project: &Path) -> String {
        let bytes = run_ok(
            &mut self
                .cli_at(project, &["projects", "context"])
                .arg(project)
                .arg("--json"),
            "projects context",
        );
        let context: Value = serde_json::from_slice(&bytes).expect("project context JSON");
        context["project"]["project_id"]
            .as_str()
            .expect("project id")
            .to_owned()
    }

    fn configuration_revision(&self) -> String {
        let value = self.tool_result("tracedecay_configuration_observed_state", &json!({}));
        let mut revisions = Vec::new();
        collect_string_field(&value, "desired_revision_id", &mut revisions);
        revisions.sort();
        revisions.dedup();
        assert_eq!(
            revisions.len(),
            1,
            "one canonical configuration revision: {value}"
        );
        revisions.remove(0)
    }

    fn configuration_set(&self, project_id: &str, key: &str, value: Value, idempotency_key: &str) {
        let expected_revision = self.configuration_revision();
        self.tool_result(
            "tracedecay_configuration_set",
            &json!({
                "layer": { "kind": "project", "project_id": project_id },
                "key": key,
                "value": value,
                "expected_revision": expected_revision,
                "idempotency_key": idempotency_key,
            }),
        );
        assert_ne!(
            self.configuration_revision(),
            expected_revision,
            "configuration write must advance revision"
        );
    }

    fn configure_provider(&self, project_id: &str) {
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            json!({
                "kind": "boolean",
                "value": self.active_provider == ActiveProvider::Native,
            }),
            "configuration.idempotency.hermes-cli-project-journey.native-gate",
        );
        // Routing is admitted only when its target is constructible.
        if self.active_provider.is_ncm() {
            self.configure_real_ncm(project_id);
        }
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
            canonical_text_setting(&MemoryProviderRecallRoutingV1 {
                active_provider: Some(self.active_provider.id().to_owned()),
                fallback: None,
                degradation: Some(MemoryProviderRecallDegradationV1 {
                    policy_id: "policy.hermes-cli-project-journey.v1".to_owned(),
                    policy_revision: 1,
                    allowed_causes: vec![
                        MemoryProviderRecallDegradationCauseV1::Partial,
                        MemoryProviderRecallDegradationCauseV1::Stale,
                    ],
                }),
            }),
            "configuration.idempotency.hermes-cli-project-journey.routing",
        );
    }

    #[cfg(unix)]
    fn configure_real_ncm(&self, project_id: &str) {
        let worker = PathBuf::from(
            std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real NCM worker binary is required"),
        );
        let installed = PathBuf::from(
            std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT")
                .expect("installed pinned NCM model root is required"),
        );
        assert!(
            worker.is_absolute() && worker.is_file(),
            "NCM worker must be an absolute binary path"
        );
        let models = installed
            .join("models")
            .canonicalize()
            .expect("installed NCM models directory");
        assert!(models.is_dir(), "NCM model root must contain models");
        let state_root = self.home.path().join("ncm-observer");
        fs::create_dir_all(&state_root).expect("isolated NCM state root");
        stage_isolated_ncm_models(&models, &state_root)
            .expect("stage installed NCM model artifacts into the isolated state root");
        self.configuration_set(
            project_id,
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            canonical_text_setting(&MemoryProviderNcmObserverV1::Enabled {
                worker_binary: worker.canonicalize().expect("canonical NCM worker"),
                state_root: state_root.canonicalize().expect("canonical NCM state root"),
            }),
            "configuration.idempotency.hermes-cli-project-journey.ncm",
        );
    }

    #[cfg(not(unix))]
    fn configure_real_ncm(&self, _project_id: &str) {
        panic!("the opt-in real NCM Hermes journey requires Unix");
    }

    fn tool_result(&self, name: &str, args: &Value) -> Value {
        self.tool_result_at(&self.project, name, args)
    }

    fn tool_result_at(&self, project_root: &Path, name: &str, args: &Value) -> Value {
        let project = project_root.to_string_lossy().to_string();
        let payload = args.to_string();
        let bytes = run_ok(
            &mut self.cli_at(
                project_root,
                &[
                    "tool",
                    "--project",
                    &project,
                    name,
                    "--args",
                    &payload,
                    "--json",
                ],
            ),
            name,
        );
        let result: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{name} returned invalid JSON: {error}"));
        assert_ne!(result["isError"], true, "{name} failed: {result}");
        result
    }

    fn context(&self, task: &str) -> Value {
        self.context_at(&self.project, task)
    }

    fn context_at(&self, project_root: &Path, task: &str) -> Value {
        let result = self.tool_result_at(
            project_root,
            "tracedecay_context",
            &json!({ "task": task, "format": "json" }),
        );
        content_json(&result).unwrap_or(result)
    }

    fn install_hermes_plugin(&self) {
        run_ok(
            &mut self.cli(&["install", "--agent", "hermes", "--no-dashboard"]),
            "install Hermes plugin",
        );
        let plugin = self.home.path().join(".hermes/plugins/tracedecay");
        for file in ["plugin.yaml", "__init__.py", "tools.py", "schemas.py"] {
            assert!(
                plugin.join(file).is_file(),
                "installed Hermes plugin missing {file}"
            );
        }
    }

    fn run_provider_fixture(&self, mode: &str, timestamp_ns: u128) -> Value {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/product_memory_provider_hermes_host_journey/hermes_sync_turn.py");
        let plugin = self.home.path().join(".hermes/plugins/tracedecay");
        let output = python_command()
            .arg(script)
            .arg(plugin)
            .arg(&self.project)
            .arg(env!("CARGO_BIN_EXE_tracedecay"))
            .arg(mode)
            .current_dir(&self.project)
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env("TRACEDECAY_DATA_DIR", &self.profile)
            .env("TRACEDECAY_GLOBAL_DB", self.profile.join("global.db"))
            .env("TRACEDECAY_TEST_ALLOW_INCOMPLETE_HOLDER_SCAN", "1")
            .env(
                "TRACEDECAY_HERMES_REPLAY_TIMESTAMP_NS",
                timestamp_ns.to_string(),
            )
            .output()
            .expect("Hermes Python fixture runs");
        assert!(
            output.status.success(),
            "Hermes provider fixture failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value =
            serde_json::from_slice(&output.stdout).expect("Hermes fixture sentinel JSON");
        assert_eq!(result["sync"], "complete");
        let expected_project = fs::canonicalize(&self.project).expect("canonical project root");
        assert_eq!(result["project_root"].as_str(), expected_project.to_str());
        assert_eq!(result["installed_provider_id"], "tracedecay");
        assert_eq!(
            result["host_boundary"], "register_ctx_fixture",
            "the fixture must state that it exercised register(ctx) without stock Hermes"
        );
        assert_eq!(result["context_engine_callback"], "complete");
        result
    }

    fn journal(&self) -> Option<&SqliteObservationJournal> {
        if let Some(journal) = self.journal.get() {
            return Some(journal);
        }
        let path = find_file(&self.profile, self.active_provider.journal_file_name())?;
        let journal = SqliteObservationJournal::open_existing(&path, inspection_policy())
            .unwrap_or_else(|error| {
                panic!(
                    "{} observation journal opens: {error}",
                    self.active_provider.id()
                )
            });
        let _ = self.journal.set(journal);
        self.journal.get()
    }

    /// Close the reader inherited from the first daemon and open a fresh
    /// journal handle after restart. Reusing a pre-restart SQLite connection
    /// would leave this journey unable to prove durable reopen semantics.
    fn reopen_journal(&mut self) {
        self.journal.take();
        let path = find_file(&self.profile, self.active_provider.journal_file_name())
            .unwrap_or_else(|| {
                panic!(
                    "{} observation journal must exist before reopen",
                    self.active_provider.id()
                )
            });
        let journal = SqliteObservationJournal::open_existing(&path, inspection_policy())
            .unwrap_or_else(|error| {
                panic!(
                    "{} observation journal reopens: {error}",
                    self.active_provider.id()
                )
            });
        assert!(
            self.journal.set(journal).is_ok(),
            "reopened journal slot is empty"
        );
    }

    fn journal_rows(&self) -> Vec<JournalInspectionRowV1> {
        let Some(journal) = self.journal() else {
            return Vec::new();
        };
        journal
            .inspect(&JournalInspectionFilterV1 {
                limit: 100,
                provider_id: Some(self.active_provider.id().to_owned()),
                ..JournalInspectionFilterV1::default()
            })
            .unwrap_or_else(|error| {
                panic!("{} journal inspection: {error}", self.active_provider.id())
            })
            .rows
    }

    fn await_settled_rows(&self) -> Vec<JournalInspectionRowV1> {
        let deadline = Instant::now() + SETTLEMENT_BUDGET;
        loop {
            let rows = self.journal_rows();
            if rows.len() >= 2 && rows.iter().all(|row| row.state.is_terminal()) {
                return rows;
            }
            assert!(
                Instant::now() < deadline,
                "Hermes project observation journal did not settle: {}",
                journal_digest(&rows)
            );
            std::thread::sleep(JOURNAL_POLL_INTERVAL);
        }
    }
}

impl Drop for HermesJourney {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

/// Native selected: Native is upstream memory and observes nothing. The
/// installed Hermes provider's callbacks still reach this project's canonical
/// route, while `tracedecay_context` carries no provider lane and no
/// observation journal exists anywhere in the profile.
#[test]
fn installed_hermes_provider_with_native_selected_is_upstream_memory() {
    let mut journey = HermesJourney::new(ActiveProvider::Native);
    journey.install_hermes_plugin();
    journey.start_daemon();
    journey.init_project();
    let project_id = journey.project_id();
    journey.configure_provider(&project_id);
    journey.stop_daemon();
    journey.start_daemon();
    journey.init_project_at(&journey.foreign_project);

    let baseline = journey.context("hermes quartz project provider baseline");
    assert_no_provider_lane(&baseline);
    let original = journey.run_provider_fixture("original", replay_timestamp_ns());
    assert_original_fixture(&original);
    assert_no_provider_lane(&journey.context(RECALL_QUERY));
    assert_no_provider_lane(&journey.context_at(&journey.foreign_project, FOREIGN_RECALL_QUERY));
    assert!(
        find_file(&journey.profile, JOURNAL_FILE_NAME).is_none()
            && find_file(&journey.profile, NCM_JOURNAL_FILE_NAME).is_none(),
        "Native observes nothing: no provider journal may exist"
    );
    assert_project_hook_route(&journey);
}

fn assert_no_provider_lane(answer: &Value) {
    assert!(
        answer
            .get("advisory_provider_memory")
            .is_none_or(Value::is_null),
        "Native-selected context carries no provider lane: {answer}"
    );
}

/// The real worker/model path is deliberately opt-in: CI and ordinary test
/// runs stay offline, while a pinned installation proves the Hermes
/// admission, receipt, restart and recall contract against the NCM provider.
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with a pinned offline model"]
fn real_ncm_hermes_provider_reopens_and_recalls_with_native_disabled() {
    assert_hermes_provider_journey(ActiveProvider::RustNcm);
}

/// A real NCM process loss must surface as the provider's typed refusal and
/// retain the exact configured provider identity. The journey is ignored for
/// the same reason as the healthy NCM variant and kills only the worker child
/// owned by this isolated daemon.
#[cfg(unix)]
#[test]
#[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with a pinned offline model"]
fn unavailable_ncm_hermes_provider_refuses_then_recovers() {
    let mut journey = HermesJourney::new(ActiveProvider::RustNcm);
    journey.install_hermes_plugin();
    journey.start_daemon();
    journey.init_project();
    let project_id = journey.project_id();
    journey.configure_provider(&project_id);
    journey.stop_daemon();
    journey.start_daemon();
    journey.init_project_at(&journey.foreign_project);

    journey.assert_baseline();
    let timestamp_ns = replay_timestamp_ns();
    let original = journey.run_provider_fixture("original", timestamp_ns);
    assert_original_fixture(&original);
    let rows = journey.await_settled_rows();
    assert_settled_rows(&rows, journey.active_provider);
    let original_admissions = capture_admissions(journey.journal().expect("NCM journal"), &rows);
    assert_provider_receipts(
        journey.journal().expect("NCM journal"),
        &rows,
        journey.active_provider,
    );

    let replay = journey.run_provider_fixture("replay", timestamp_ns);
    assert_fixture_replay(&replay);
    let replayed_rows = journey.await_settled_rows();
    assert_eq!(
        journal_identities(&replayed_rows),
        journal_identities(&rows)
    );
    assert_eq!(
        capture_admissions(journey.journal().expect("NCM journal"), &replayed_rows),
        original_admissions,
        "exact provider replay must preserve the original admitted envelope"
    );

    journey.stop_daemon();
    journey.start_daemon();
    journey.reopen_journal();
    let reopened = journey.await_settled_rows();
    assert_eq!(journal_identities(&reopened), journal_identities(&rows));
    assert_eq!(
        capture_admissions(journey.journal().expect("reopened NCM journal"), &reopened),
        original_admissions,
        "daemon restart must preserve every admitted envelope"
    );

    terminate_owned_ncm_worker(&journey);
    let unavailable = journey.context(RECALL_QUERY);
    let lane = unavailable
        .get("advisory_provider_memory")
        .expect("NCM worker loss retains an advisory lane");
    assert_eq!(lane["state"], "unavailable", "typed NCM refusal: {lane}");
    assert_eq!(lane["provider_id"], NCM_PROVIDER_ID);
    assert_eq!(lane["registration_revision"], 1);

    journey.stop_daemon();
    journey.start_daemon();
    journey.reopen_journal();
    let recovered = journey.context(RECALL_QUERY);
    assert_answered_recall(&recovered, journey.active_provider);
}

fn assert_hermes_provider_journey(active_provider: ActiveProvider) {
    let mut journey = HermesJourney::new(active_provider);
    journey.install_hermes_plugin();
    journey.start_daemon();
    journey.init_project();
    let project_id = journey.project_id();
    journey.configure_provider(&project_id);
    journey.stop_daemon();
    journey.start_daemon();
    // Register a second git project after provider configuration. Its context
    // is the foreign-scope control: it must not inherit this project's rows.
    journey.init_project_at(&journey.foreign_project);

    journey.assert_baseline();
    let timestamp_ns = replay_timestamp_ns();
    let original = journey.run_provider_fixture("original", timestamp_ns);
    assert_original_fixture(&original);
    let rows = journey.await_settled_rows();
    assert_settled_rows(&rows, active_provider);
    let original_admissions =
        capture_admissions(journey.journal().expect("provider journal"), &rows);
    assert_provider_receipts(
        journey.journal().expect("provider journal"),
        &rows,
        active_provider,
    );

    // Replay the same deterministic admission in a new host process and with
    // a fresh provider instance. Compare the full row identity and immutable
    // admitted envelope before and after the replay, not just a row count.
    let replay = journey.run_provider_fixture("replay", timestamp_ns);
    assert_fixture_replay(&replay);
    let replayed_rows = journey.await_settled_rows();
    assert_eq!(
        journal_identities(&replayed_rows),
        journal_identities(&rows)
    );
    assert_eq!(
        capture_admissions(journey.journal().expect("provider journal"), &replayed_rows),
        original_admissions,
        "exact provider replay must preserve the original admitted envelope"
    );

    // Reopen the journal only after a real daemon restart. This catches a
    // stale reader or in-memory provider mount that would make recall appear
    // durable while the process that admitted it is still alive.
    journey.stop_daemon();
    journey.start_daemon();
    journey.reopen_journal();
    let reopened = journey.await_settled_rows();
    assert_eq!(journal_identities(&reopened), journal_identities(&rows));
    assert_eq!(
        capture_admissions(
            journey.journal().expect("reopened provider journal"),
            &reopened
        ),
        original_admissions,
        "reopened journal must decode the same immutable admissions"
    );
    assert_provider_receipts(
        journey.journal().expect("reopened provider journal"),
        &reopened,
        active_provider,
    );

    let foreign = journey.context_at(&journey.foreign_project, FOREIGN_RECALL_QUERY);
    assert_foreign_scope_control(&foreign, active_provider);

    let answer = journey.context(RECALL_QUERY);
    assert_answered_recall(&answer, active_provider);

    assert_project_hook_route(&journey);
}

/// The provider callbacks carry the resolved project: Hermes turns are
/// admitted through the canonical observation authority and projected into
/// upstream session history, where `tracedecay_message_search` recalls them.
/// A route proof independent of any memory provider.
fn assert_project_hook_route(journey: &HermesJourney) {
    let deadline = Instant::now() + SETTLEMENT_BUDGET;
    loop {
        let result = journey.tool_result(
            "tracedecay_message_search",
            &json!({ "query": PROJECT_TERM, "format": "json" }),
        );
        let envelope = content_json(&result).unwrap_or(result);
        let payload = envelope
            .pointer("/outcome/value/payload")
            .cloned()
            .unwrap_or(envelope);
        if payload["results"].as_array().is_some_and(|results| {
            results.iter().any(|entry| {
                entry["message"]["text"]
                    .as_str()
                    .is_some_and(|text| text.contains(PROJECT_TERM))
            })
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Hermes project callbacks never reached this project's session history: {payload}"
        );
        std::thread::sleep(JOURNAL_POLL_INTERVAL);
    }
}

impl HermesJourney {
    fn assert_baseline(&self) {
        // The first context call mounts the configured provider before Hermes
        // writes evidence, so the empty journal is an unambiguous baseline.
        let baseline = self.context("hermes quartz project provider baseline");
        let lane = baseline
            .get("advisory_provider_memory")
            .expect("baseline advisory provider lane");
        assert_eq!(lane["provider_id"], self.active_provider.id());
        assert!(self.journal().is_some(), "provider journal must be mounted");
        assert!(self.journal_rows().is_empty(), "baseline journal is empty");
    }
}

fn replay_timestamp_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_nanos()
}

fn assert_original_fixture(fixture: &Value) {
    assert_eq!(fixture["replay"]["mode"], "original");
    assert_eq!(fixture["replay"]["fresh_provider"], false);
    assert_eq!(fixture["context_engine_callback"], "complete");
    let ids = fixture["replay"]["message_ids"]
        .as_array()
        .expect("fixture reports original message ids");
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(Value::is_string));
}

fn assert_fixture_replay(fixture: &Value) {
    assert_eq!(fixture["replay"]["mode"], "exact");
    assert_eq!(fixture["replay"]["fresh_provider"], true);
    assert_eq!(fixture["context_engine_callback"], "complete");
    let ids = fixture["replay"]["message_ids"]
        .as_array()
        .expect("fixture reports exact original message ids");
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(Value::is_string));
}

fn assert_settled_rows(rows: &[JournalInspectionRowV1], provider: ActiveProvider) {
    assert_eq!(rows.len(), 2, "one Hermes user and one assistant message");
    let mut source_sequences = rows
        .iter()
        .map(|row| row.source_sequence.0)
        .collect::<Vec<_>>();
    source_sequences.sort_unstable();
    source_sequences.dedup();
    assert_eq!(
        source_sequences.len(),
        2,
        "messages use distinct source positions"
    );
    for row in rows {
        assert_eq!(row.provider_id, provider.id());
        assert_eq!(row.observation_kind, OBSERVATION_KIND);
        assert_eq!(row.state, DeliveryStateV1::Acknowledged);
        assert_eq!(row.attempt_number, 1);
        assert!(row.content_present);
    }
}

fn capture_admissions(
    journal: &SqliteObservationJournal,
    rows: &[JournalInspectionRowV1],
) -> Vec<AdmittedObservationV1> {
    let mut admissions = rows
        .iter()
        .map(|row| {
            assert_eq!(
                row.source_stream, "session_observation_store",
                "Hermes journey admits live canonical source rows only"
            );
            let admitted = journal
                .read_admitted_observation_by_idempotency(&row.idempotency_key)
                .expect("read retained Hermes admission")
                .expect("Hermes admission content is retained");
            admitted
                .validate()
                .expect("valid retained Hermes admission");
            assert_eq!(admitted.observation_id, row.observation_id);
            assert_eq!(admitted.idempotency_key, row.idempotency_key);
            assert_eq!(admitted.payload.sha256, row.payload_sha256);
            assert_eq!(admitted.extensions_digest, row.extensions_digest);
            let payload: Value = serde_json::from_slice(&admitted.payload.bytes)
                .expect("canonical retained Hermes payload");
            let canonical: tracedecay_domain::observation::CanonicalObservationEnvelopeV1 =
                serde_json::from_value(
                    payload
                        .get("canonical_payload")
                        .cloned()
                        .expect("retained payload canonical source envelope"),
                )
                .expect("retained Hermes canonical source envelope");
            canonical
                .validate()
                .expect("valid retained Hermes canonical source envelope");
            assert_eq!(
                canonical.provider().as_str(),
                HERMES_CANONICAL_PROVIDER_ID,
                "admission source must preserve Hermes' canonical provider identity"
            );
            assert_eq!(
                canonical.relations().session_id().as_str(),
                SESSION_ID,
                "admission source must preserve Hermes' session identity"
            );
            assert!(
                payload.get("history_grant").is_none(),
                "the host never dispatches provider history"
            );
            assert_eq!(
                payload["source_identity"]["original_source"]["source"]["observation_id"]
                    .as_str(),
                Some(admitted.source.source_event_id.as_str()),
                "each delivery carries the host attribution of its own canonical record"
            );
            admitted
        })
        .collect::<Vec<_>>();
    admissions.sort_by(|left, right| {
        left.idempotency_key
            .as_str()
            .cmp(right.idempotency_key.as_str())
    });
    admissions
}

fn assert_provider_receipts(
    journal: &SqliteObservationJournal,
    rows: &[JournalInspectionRowV1],
    provider: ActiveProvider,
) {
    for row in rows {
        let receipts = journal
            .receipts_for(&row.observation_id)
            .expect("provider receipt lookup");
        assert_eq!(receipts.len(), 1, "one receipt for each exact admission");
        let receipt = &receipts[0];
        receipt.validate().expect("valid provider receipt");
        assert_eq!(receipt.provider_id.as_str(), provider.id());
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
        assert_eq!(receipt.outcome, ObservationOutcomeV1::Applied);
        assert_eq!(
            receipt.committed_effect,
            ObservationCommittedEffectV1::Applied
        );
        assert!(
            receipt
                .provider_receipt_digest
                .as_ref()
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                }),
            "applied {provider:?} receipt must carry a 64-character digest"
        );
    }
}

fn assert_foreign_scope_control(foreign: &Value, provider: ActiveProvider) {
    if let Some(lane) = foreign.get("advisory_provider_memory") {
        assert_ne!(
            lane["state"], "answered",
            "foreign project must not answer from the Hermes project store: {lane}"
        );
        if lane["provider_id"].is_string() {
            assert_eq!(lane["provider_id"], provider.id());
        }
        if let Some(candidates) = lane["candidates"].as_array() {
            assert!(
                candidates.iter().all(|candidate| candidate["content"]
                    .as_str()
                    .is_none_or(|content| !content.contains(PROJECT_TERM))),
                "foreign project returned primary-project evidence: {lane}"
            );
        }
    }
}

fn assert_answered_recall(answer: &Value, provider: ActiveProvider) {
    let lane = answer
        .get("advisory_provider_memory")
        .expect("recall advisory provider lane");
    assert_eq!(lane["provider_id"], provider.id());
    assert_eq!(lane["state"], "answered");
    let candidates = lane["candidates"].as_array().expect("recall candidates");
    assert!(
        candidates.len() >= 2,
        "recall returns both Hermes messages: {lane}"
    );
    assert!(
        candidates.iter().all(|candidate| candidate["content"]
            .as_str()
            .is_some_and(|content| content.contains(PROJECT_TERM))),
        "recall returns the project-scoped Hermes evidence: {lane}"
    );
}

#[cfg(unix)]
fn terminate_owned_ncm_worker(journey: &HermesJourney) {
    let worker = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_WORKER").expect("real NCM worker binary is required"),
    )
    .canonicalize()
    .expect("canonical NCM worker binary");
    let daemon_pid = journey.daemon.as_ref().expect("running NCM daemon").id();
    let listing = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .expect("ps enumerates NCM workers");
    let worker_pid = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line
                .splitn(3, char::is_whitespace)
                .filter(|field| !field.is_empty());
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            let command = fields.next()?.trim();
            (ppid == daemon_pid && command.starts_with(worker.to_string_lossy().as_ref()))
                .then_some(pid)
        })
        .find(|pid| *pid != std::process::id())
        .expect("daemon must own the real NCM worker child");
    let status = Command::new("kill")
        .args(["-TERM", &worker_pid.to_string()])
        .status()
        .expect("kill signals only the discovered NCM worker");
    assert!(status.success(), "NCM worker termination must be delivered");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let probe = Command::new("kill")
            .args(["-0", &worker_pid.to_string()])
            .status()
            .expect("kill -0 probes worker state");
        if !probe.success() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("NCM worker {worker_pid} did not exit after SIGTERM");
}

#[cfg(not(unix))]
fn terminate_owned_ncm_worker(_journey: &HermesJourney) {
    panic!("the unavailable-NCM Hermes journey requires Unix");
}

fn inspection_policy() -> RetentionPolicyV1 {
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

fn journal_identities(rows: &[JournalInspectionRowV1]) -> Vec<(String, String, String, u32)> {
    let mut result = rows
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
    result.sort();
    result
}

fn journal_digest(rows: &[JournalInspectionRowV1]) -> String {
    rows.iter()
        .map(|row| {
            format!(
                "{}:{}:{}:{}",
                row.observation_kind,
                row.source_sequence.0,
                row.state.as_wire(),
                row.attempt_number
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn install_binary_shim(bin_dir: &Path) {
    let shim = bin_dir.join(if cfg!(windows) {
        "tracedecay.exe"
    } else {
        "tracedecay"
    });
    if fs::hard_link(env!("CARGO_BIN_EXE_tracedecay"), &shim).is_err() {
        fs::copy(env!("CARGO_BIN_EXE_tracedecay"), &shim).expect("stage binary");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&shim).expect("shim metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(shim, permissions).expect("shim executable");
    }
}

fn initialize_project(project: &Path, package_name: &str, source: &str) {
    fs::create_dir_all(project.join("src")).expect("project source");
    git(project, &["init", "--quiet", "-b", "main"]);
    git(project, &["config", "user.email", "journey@example.com"]);
    git(project, &["config", "user.name", "Hermes Journey"]);
    fs::write(
        project.join("Cargo.toml"),
        format!("[package]\nname=\"{package_name}\"\nversion=\"0.0.0\"\nedition=\"2024\"\n"),
    )
    .expect("fixture manifest");
    fs::write(project.join("src/lib.rs"), source).expect("fixture source");
    git(project, &["add", "."]);
    git(project, &["commit", "--quiet", "-m", "initial"]);
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed");
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
        .expect("listener probe runtime");
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        if let Some(status) = daemon.try_wait().expect("daemon status") {
            panic!("daemon exited before authority publication: {status}");
        }
        if let Ok(bytes) = fs::read(path)
            && let Ok(record) = serde_json::from_slice::<DaemonAuthorityRecord>(&bytes)
            && record.pid == daemon.id()
            && record.auth_token.len() == 64
            && runtime.block_on(async {
                matches!(
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        BrokerStream::connect(&record.endpoint),
                    )
                    .await,
                    Ok(Ok(_))
                )
            })
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for daemon authority {}", path.display());
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

fn python_command() -> Command {
    static PYTHON: OnceLock<PathBuf> = OnceLock::new();
    let executable = PYTHON.get_or_init(|| {
        if cfg!(windows) {
            for variable in ["Python_ROOT_DIR", "pythonLocation"] {
                if let Some(root) = std::env::var_os(variable) {
                    let candidate = PathBuf::from(root).join("python.exe");
                    if candidate.is_file() {
                        return candidate;
                    }
                }
            }
        }
        PathBuf::from("python3")
    });
    Command::new(executable)
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(path).ok()?;
        for entry in entries.flatten() {
            let candidate = entry.path();
            if candidate.is_dir() {
                stack.push(candidate);
            } else if candidate.file_name().is_some_and(|file| file == name) {
                return Some(candidate);
            }
        }
    }
    None
}

fn content_json(result: &Value) -> Option<Value> {
    let blocks = result.get("content")?.as_array()?;
    let text = blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .map(|text| {
            text.lines()
                .take_while(|line| !line.trim_start().starts_with("tracedecay_metrics:"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|text| !text.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&text).ok()
}

fn collect_string_field(value: &Value, field: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, member) in map {
                if key == field {
                    if let Some(text) = member.as_str() {
                        output.push(text.to_owned());
                    }
                } else {
                    collect_string_field(member, field, output);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_string_field(item, field, output);
            }
        }
        _ => {}
    }
}

/// Structured provider settings are stored as the repository's exact
/// canonical JSON text, so fixtures encode the domain document itself.
fn canonical_text_setting<T: serde::Serialize>(document: &T) -> Value {
    let text = String::from_utf8(
        tracedecay_domain::canonical_json_bytes(document).expect("canonical setting document"),
    )
    .expect("canonical setting text is UTF-8");
    json!({ "kind": "text", "value": text })
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
