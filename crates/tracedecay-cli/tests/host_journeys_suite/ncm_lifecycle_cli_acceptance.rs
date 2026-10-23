//! NCM lifecycle journeys through the shipped CLI.
//!
//! The fixture gives every subprocess its own HOME, profile root, global
//! database, and registered project. The daemon is therefore the real scope
//! authority while no command can read or mutate the developer's profile.
//!
//! The always-on cases cover confirmation, exact project targeting, pending
//! journal refusal, digest-guarded recovery, and configuration revision drift.
//! The worker artifact journey exercises the arm64 macOS release and is
//! ignored unless that real release worker is supplied through
//! `TRACEDECAY_NCM_WORKER`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tracedecay_contracts::{ApplicationEnvelope, ApplicationOutcome, ResolvedSetting};
use tracedecay_daemon_identity::authority::current_record;
use tracedecay_daemon_protocol::DaemonClientStream;
use tracedecay_runtime_core::config::ProfileRoot;
use tracedecay_runtime_core::test_executable::link_or_copy_executable;

use crate::isolated_profile::{
    apply_hermetic_child_env, apply_isolated_profile_env, hermetic_path, run_ok,
};

const NCM_SETTING: &str = "memory.provider_ncm_observer.v1";
const WORKER_NAME: &str = "tracedecay-ncm-worker";
const WORKER_MANIFEST_NAME: &str = "worker-manifest.json";
const MODEL_ACQUISITION_MANIFEST_NAME: &str = "model-acquisition-manifest.json";
const TRUSTED_MODEL_ACQUISITION_MANIFEST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../product/ncm/release/model-acquisition-manifest.json"
));

struct NcmJourney {
    home: TempDir,
    profile: ProfileRoot,
    project: PathBuf,
    foreign_project: PathBuf,
    bin_dir: PathBuf,
    daemon: Option<Child>,
}

impl NcmJourney {
    fn new() -> Self {
        // macOS's per-user temporary directory can exceed the Unix socket path limit.
        let home = if cfg!(target_os = "macos") {
            TempDir::new_in(fs::canonicalize("/tmp").expect("canonical temporary root"))
                .expect("isolated NCM HOME")
        } else {
            TempDir::new().expect("isolated NCM HOME")
        };
        // Plain host form, as the product reports roots (no Windows `\\?\` prefix).
        let root = tracedecay_runtime_core::path_safety::canonical_existing_identity(home.path())
            .expect("canonical NCM HOME");
        let profile = ProfileRoot::new(root.join("tracedecay-profile"))
            .with_home(&root)
            .with_xdg_config_home(root.join(".config"));
        let project = root.join("project");
        let foreign_project = root.join("foreign-project");
        let bin_dir = root.join("bin");
        tracedecay_private_fs::create_private_directory(profile.data_dir())
            .expect("isolated private profile root");
        fs::create_dir_all(&bin_dir).expect("isolated binary directory");
        install_binary_shim(&bin_dir);
        initialize_project(home.path(), &project, "ncm-cli-journey-fixture");
        initialize_project(home.path(), &foreign_project, "ncm-cli-foreign-fixture");
        Self {
            home,
            profile,
            project,
            foreign_project,
            bin_dir,
            daemon: None,
        }
    }

    fn cli(&self, args: &[String]) -> Command {
        self.cli_at(&self.project, args)
    }

    fn cli_at(&self, project: &Path, args: &[String]) -> Command {
        let mut command = Command::new(crate::tracedecay_exe());
        apply_isolated_profile_env(&mut command, self.home.path(), self.profile.data_dir());
        command
            .args(args)
            .current_dir(project)
            .env("PATH", hermetic_path(&[&self.bin_dir]))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn start_daemon(&mut self) {
        assert!(self.daemon.is_none(), "NCM fixture daemon already running");
        let log = fs::File::create(self.home.path().join("daemon.stderr.log")).expect("daemon log");
        let mut command = self.cli(&strings(&["daemon", "run"]));
        command.stdout(Stdio::null()).stderr(Stdio::from(log));
        self.daemon = Some(command.spawn().expect("NCM fixture daemon starts"));
        wait_for_authority(
            self.daemon.as_mut().expect("NCM fixture owns its daemon"),
            self.profile.data_dir(),
        );
    }

    fn stop_daemon(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }

    fn init_project(&self) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let output = self
                .cli(&strings(&["init"]))
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

    fn project_context(&self) -> Value {
        let selector = self.project.to_string_lossy().into_owned();
        let mut args = strings(&["projects", "context"]);
        args.push(selector);
        args.push("--json".to_owned());
        let stdout = run_ok(&mut self.cli(&args), "projects context");
        serde_json::from_slice(&stdout).expect("projects context JSON")
    }

    fn project_id(&self) -> String {
        self.project_context()["project"]["project_id"]
            .as_str()
            .expect("registered project id")
            .to_owned()
    }

    fn profile_id(&self) -> String {
        self.project_context()["profile_id"]
            .as_str()
            .expect("registered profile id")
            .to_owned()
    }

    fn ncm_output(&self, yes: bool, action: &str, options: &[String]) -> Output {
        let mut args = Vec::with_capacity(options.len() + 3);
        if yes {
            args.push("--yes".to_owned());
        }
        args.push("ncm".to_owned());
        args.push(action.to_owned());
        args.extend(options.iter().cloned());
        self.cli(&args).output().expect("NCM command runs")
    }

    fn ncm_json(&self, yes: bool, action: &str, options: &[String]) -> Value {
        let output = self.ncm_output(yes, action, options);
        assert!(
            output.status.success(),
            "ncm {action} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "ncm {action} did not return JSON: {error}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    fn status(&self) -> Value {
        self.ncm_json(false, "status", &scoped_options(&self.project, true))
    }

    fn tool_result(&self, name: &str, arguments: &Value) -> Value {
        let project = self.project.to_string_lossy().into_owned();
        let mut args = strings(&["tool", "--project"]);
        args.push(project);
        args.extend(strings(&[name, "--args"]));
        args.push(arguments.to_string());
        args.push("--json".to_owned());
        let stdout = run_ok(&mut self.cli(&args), &format!("tracedecay tool {name}"));
        let result: Value = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
            panic!(
                "tool {name} returned non-JSON: {error}\nstdout:\n{}\nstderr omitted",
                String::from_utf8_lossy(&stdout)
            )
        });
        assert_ne!(
            result["isError"], true,
            "tool {name} returned an error: {result}"
        );
        result
    }

    fn tool_value(&self, name: &str, arguments: &Value) -> Value {
        let result = self.tool_result(name, arguments);
        let Some(text) = join_content_text(&result) else {
            return result;
        };
        serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!("tool {name} returned non-JSON content `{text}`: {error}")
        })
    }

    fn configuration_revision(&self) -> String {
        let envelope: ApplicationEnvelope<ResolvedSetting> =
            serde_json::from_value(self.tool_value(
                "tracedecay_configuration_get",
                &json!({ "key": NCM_SETTING }),
            ))
            .expect("typed canonical NCM configuration setting");
        let ApplicationOutcome::Evidence(evidence) = envelope.outcome else {
            panic!("configuration read must return evidence");
        };
        evidence
            .payload
            .expect("configuration setting payload")
            .revision_id
            .as_str()
            .to_owned()
    }

    fn set_observer(&self, project_id: &str, document: String) {
        let expected_revision = self.configuration_revision();
        let idempotency = format!("ncm-cli-observer-{}", sha256_hex(document.as_bytes()));
        let result = self.tool_result(
            "tracedecay_configuration_set",
            &json!({
                "layer": { "kind": "project", "project_id": project_id },
                "key": NCM_SETTING,
                "value": { "kind": "text", "value": document },
                "expected_revision": expected_revision,
                "idempotency_key": idempotency,
            }),
        );
        let after = self.configuration_revision();
        assert_ne!(
            after, expected_revision,
            "configuration write did not advance revision"
        );
        assert_ne!(result["isError"], true);
    }

    fn set_observer_disabled(&self, project_id: &str) {
        self.set_observer(project_id, disabled_document());
    }

    fn set_observer_enabled(&self, project_id: &str, worker: &Path, state_root: &Path) {
        self.set_observer(project_id, enabled_document(worker, state_root));
    }

    fn write_interrupted_install_journal(&self) -> InterruptedInstall {
        let project_id = self.project_id();
        let profile_id = self.profile_id();
        let operation_id = "11111111111111111111111111111111";
        let worker_path = self
            .profile
            .data_dir()
            .join("ncm")
            .join("worker")
            .join(operation_id)
            .join(WORKER_NAME);
        let manifest_path = worker_path
            .parent()
            .expect("interrupted worker parent")
            .join(WORKER_MANIFEST_NAME);
        let model_manifest_path = worker_path
            .parent()
            .expect("interrupted worker parent")
            .join(MODEL_ACQUISITION_MANIFEST_NAME);
        let state_root = self.home.path().join("ncm-state");
        let worker_bytes = b"interrupted worker bytes";
        let manifest_bytes = br#"{"schema_version":1,"interrupted":true}"#;
        let model_manifest_bytes = TRUSTED_MODEL_ACQUISITION_MANIFEST;
        fs::create_dir_all(worker_path.parent().expect("worker parent"))
            .expect("interrupted worker parent directory");
        fs::write(&worker_path, worker_bytes).expect("interrupted worker bytes");
        fs::write(&manifest_path, manifest_bytes).expect("interrupted manifest bytes");
        fs::write(&model_manifest_path, model_manifest_bytes)
            .expect("interrupted model acquisition manifest bytes");
        fs::create_dir_all(state_root.join("models")).expect("interrupted model root");
        fs::write(
            state_root.join("models/ncm-encoder-manifest.json"),
            b"model state must survive recovery",
        )
        .expect("interrupted model manifest");

        let journal = json!({
            "schema_version": 1,
            "operation_id": operation_id,
            "operation": "install",
            "phase": "staged",
            "profile_id": profile_id,
            "project_id": project_id,
            "worker_path": worker_path,
            "manifest_path": manifest_path,
            "model_manifest_path": model_manifest_path,
            "state_root": state_root,
            "before_configuration_revision": self.configuration_revision(),
            "before_document": disabled_document(),
            "after_document": enabled_document(&worker_path, &state_root),
            "before_worker_digest": null,
            "before_manifest_digest": null,
            "before_model_manifest_digest": null,
            "after_worker_digest": sha256_hex(worker_bytes),
            "after_manifest_digest": sha256_hex(manifest_bytes),
            "after_model_manifest_digest": sha256_hex(model_manifest_bytes),
            "before_worker_backup": null,
            "before_manifest_backup": null,
            "before_model_manifest_backup": null,
        });
        let journal_path = self.profile.data_dir().join("ncm/control-journal-v1.json");
        fs::create_dir_all(journal_path.parent().expect("journal parent"))
            .expect("NCM control root");
        fs::write(
            &journal_path,
            serde_json::to_vec_pretty(&journal).expect("interrupted journal JSON"),
        )
        .expect("interrupted journal");
        InterruptedInstall {
            journal_path,
            worker_path,
            manifest_path,
            model_manifest_path,
            state_root,
            worker_bytes: worker_bytes.to_vec(),
        }
    }
}

impl Drop for NcmJourney {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

struct InterruptedInstall {
    journal_path: PathBuf,
    worker_path: PathBuf,
    manifest_path: PathBuf,
    model_manifest_path: PathBuf,
    state_root: PathBuf,
    worker_bytes: Vec<u8>,
}

#[test]
fn ncm_lifecycle_is_opt_in_and_scope_is_exact() {
    let mut journey = NcmJourney::new();
    journey.start_daemon();
    journey.init_project();

    let initial = journey.status();
    assert_eq!(
        initial["profile_root"].as_str(),
        Some(
            journey
                .profile
                .data_dir()
                .to_str()
                .expect("profile path is UTF-8")
        ),
        "NCM status must stay inside the fixture profile"
    );
    assert_eq!(
        initial["project_root"].as_str(),
        Some(journey.project.to_str().expect("project path is UTF-8"))
    );
    assert_eq!(initial["enabled"], false);
    assert_eq!(initial["pending_recovery"], false);
    assert_eq!(initial["worker_present"], false);
    assert_eq!(initial["manifest_present"], false);

    let mut foreign_install = scoped_options(&journey.foreign_project, true);
    foreign_install.extend(strings(&[
        "--worker",
        "relative-worker",
        "--state-root",
        "relative-state",
    ]));
    let confirmation = journey.ncm_output(false, "install", &foreign_install);
    assert!(!confirmation.status.success());
    assert!(
        String::from_utf8_lossy(&confirmation.stderr)
            .contains("ncm install changes project configuration; pass --yes to confirm"),
        "missing confirmation must be refused before scope or path resolution\nstderr:\n{}",
        String::from_utf8_lossy(&confirmation.stderr)
    );

    let model_revision = journey.configuration_revision();
    let mut model_options = scoped_options(&journey.foreign_project, true);
    model_options.extend(strings(&["--state-root", "relative-state"]));
    let model_confirmation = journey.ncm_output(false, "install-model", &model_options);
    assert!(!model_confirmation.status.success());
    assert!(
        String::from_utf8_lossy(&model_confirmation.stderr)
            .contains("ncm install-model downloads model artifacts; pass --yes to confirm"),
        "model acquisition must require confirmation before scope or path admission\nstderr:\n{}",
        String::from_utf8_lossy(&model_confirmation.stderr)
    );
    let model_missing_root = journey.ncm_output(
        true,
        "install-model",
        &scoped_options(&journey.project, true),
    );
    assert!(!model_missing_root.status.success());
    assert!(
        String::from_utf8_lossy(&model_missing_root.stderr)
            .contains("NCM install-model requires --state-root"),
        "model acquisition must require an explicit root\nstderr:\n{}",
        String::from_utf8_lossy(&model_missing_root.stderr)
    );
    let mut relative_model_root = scoped_options(&journey.project, true);
    relative_model_root.extend(strings(&["--state-root", "relative-state"]));
    let relative_model_root = journey.ncm_output(true, "install-model", &relative_model_root);
    assert!(!relative_model_root.status.success());
    assert!(
        String::from_utf8_lossy(&relative_model_root.stderr)
            .contains("NCM state root must be absolute"),
        "model acquisition must reject relative roots\nstderr:\n{}",
        String::from_utf8_lossy(&relative_model_root.stderr)
    );
    let model_root = journey.home.path().join("ncm-model-state");
    let mut foreign_model_root = scoped_options(&journey.foreign_project, true);
    foreign_model_root.push("--state-root".to_owned());
    foreign_model_root.push(model_root.to_string_lossy().into_owned());
    let foreign_model = journey.ncm_output(true, "install-model", &foreign_model_root);
    assert!(!foreign_model.status.success());
    assert!(
        String::from_utf8_lossy(&foreign_model.stderr)
            .contains("no registered TraceDecay project at exact root"),
        "model acquisition must use exact project authority\nstderr:\n{}",
        String::from_utf8_lossy(&foreign_model.stderr)
    );
    assert!(
        !model_root.exists(),
        "foreign scope cannot create model state"
    );
    assert_eq!(
        journey.configuration_revision(),
        model_revision,
        "refused acquisition must not change Native participation or recall routing"
    );

    #[cfg(unix)]
    {
        fs::create_dir(&model_root).expect("model state root");
        let foreign_models = journey.home.path().join("foreign-models");
        fs::create_dir(&foreign_models).expect("foreign models directory");
        let sentinel = foreign_models.join("sentinel");
        fs::write(&sentinel, b"foreign model state").expect("foreign model sentinel");
        std::os::unix::fs::symlink(&foreign_models, model_root.join("models"))
            .expect("foreign models symlink");
        let mut unsafe_model_options = scoped_options(&journey.project, true);
        unsafe_model_options.push("--state-root".to_owned());
        unsafe_model_options.push(model_root.to_string_lossy().into_owned());
        let unsafe_models = journey.ncm_output(true, "install-model", &unsafe_model_options);
        assert!(!unsafe_models.status.success());
        assert!(
            String::from_utf8_lossy(&unsafe_models.stderr)
                .contains("NCM model directory path is unsafe"),
            "model acquisition must reject a symlink before any download\nstderr:\n{}",
            String::from_utf8_lossy(&unsafe_models.stderr)
        );
        assert_eq!(
            fs::read(&sentinel).expect("foreign sentinel"),
            b"foreign model state"
        );
        assert!(!model_root.join("receipts").exists());
    }

    let project_id = journey.project_id();
    let configured_root = journey.home.path().join("configured-ncm-state");
    journey.set_observer_enabled(
        &project_id,
        &journey.home.path().join("configured-ncm-worker"),
        &configured_root,
    );
    let configured_revision = journey.configuration_revision();
    let different_root = journey.home.path().join("different-ncm-state");
    let mut different_model_options = scoped_options(&journey.project, true);
    different_model_options.push("--state-root".to_owned());
    different_model_options.push(different_root.to_string_lossy().into_owned());
    let different_model = journey.ncm_output(true, "install-model", &different_model_options);
    assert!(!different_model.status.success());
    assert!(
        String::from_utf8_lossy(&different_model.stderr)
            .contains("state root does not match this project's configured state root"),
        "model acquisition must retain the configured root identity\nstderr:\n{}",
        String::from_utf8_lossy(&different_model.stderr)
    );
    assert!(!different_root.exists());
    assert_eq!(journey.configuration_revision(), configured_revision);
    let mut live_model_options = scoped_options(&journey.project, true);
    live_model_options.push("--state-root".to_owned());
    live_model_options.push(configured_root.to_string_lossy().into_owned());
    let live_model = journey.ncm_output(true, "install-model", &live_model_options);
    assert!(!live_model.status.success());
    assert!(
        String::from_utf8_lossy(&live_model.stderr)
            .contains("NCM model acquisition is blocked while the daemon owns an enabled observer"),
        "model acquisition must refuse to replace state owned by a live enabled worker\nstderr:\n{}",
        String::from_utf8_lossy(&live_model.stderr)
    );
    assert!(
        !configured_root.exists(),
        "live ownership refusal must precede state creation"
    );
    assert_eq!(journey.configuration_revision(), configured_revision);
    journey.set_observer_disabled(&project_id);

    let wrong_target = journey.ncm_output(
        true,
        "status",
        &scoped_options(&journey.foreign_project, true),
    );
    assert!(!wrong_target.status.success());
    let wrong_target_stderr = String::from_utf8_lossy(&wrong_target.stderr);
    assert!(
        wrong_target_stderr.contains("no registered TraceDecay project at exact root")
            && wrong_target_stderr.contains("no fallback project is substituted"),
        "wrong target must fail closed\nstderr:\n{wrong_target_stderr}"
    );

    let update = journey.ncm_output(true, "update", &scoped_options(&journey.project, true));
    assert!(!update.status.success());
    let update_stderr = String::from_utf8_lossy(&update.stderr);
    if initial["platform_supported"]
        .as_bool()
        .expect("worker platform capability")
    {
        assert!(
            update_stderr.contains("NCM is disabled; use `ncm install`"),
            "update cannot implicitly opt in\nstderr:\n{update_stderr}"
        );
    } else {
        assert!(
            update_stderr.contains("NCM worker unsupported on"),
            "unsupported targets must fail closed before NCM mutation\nstderr:\n{update_stderr}"
        );
    }

    let recover = journey.ncm_output(true, "recover", &scoped_options(&journey.project, true));
    assert!(!recover.status.success());
    assert!(
        String::from_utf8_lossy(&recover.stderr).contains("no pending NCM control journal"),
        "recover without interruption must fail clearly\nstderr:\n{}",
        String::from_utf8_lossy(&recover.stderr)
    );

    let uninstall = journey.ncm_json(true, "uninstall", &scoped_options(&journey.project, true));
    assert_eq!(uninstall["operation"], "uninstall");
    assert_eq!(uninstall["outcome"], "no_effect");
    assert_eq!(uninstall["model_state"], "preserved");
    assert_eq!(journey.status()["enabled"], false);
}

#[cfg(unix)]
#[test]
fn ncm_recovery_rolls_back_interruption_and_rejects_symlink_and_revision_drift() {
    let mut journey = NcmJourney::new();
    journey.start_daemon();
    journey.init_project();
    let project_id = journey.project_id();
    let interrupted = journey.write_interrupted_install_journal();

    assert_eq!(journey.status()["pending_recovery"], true);
    let blocked = journey.ncm_output(true, "uninstall", &scoped_options(&journey.project, true));
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("pending control journal"),
        "mutations must stop at an interruption boundary\nstderr:\n{}",
        String::from_utf8_lossy(&blocked.stderr)
    );

    let original_journal = fs::read(&interrupted.journal_path).expect("interrupted journal bytes");
    let mut foreign_journal: Value =
        serde_json::from_slice(&original_journal).expect("interrupted journal JSON");
    foreign_journal["profile_id"] = json!("profile.foreign");
    fs::write(
        &interrupted.journal_path,
        serde_json::to_vec_pretty(&foreign_journal).expect("foreign journal JSON"),
    )
    .expect("foreign journal bytes");
    let mut foreign_model_options = scoped_options(&journey.project, true);
    foreign_model_options.push("--state-root".to_owned());
    foreign_model_options.push(interrupted.state_root.to_string_lossy().into_owned());
    let foreign_model = journey.ncm_output(true, "install-model", &foreign_model_options);
    assert!(!foreign_model.status.success());
    assert!(
        String::from_utf8_lossy(&foreign_model.stderr)
            .contains("belongs to another profile or project"),
        "model acquisition must refuse another profile's control journal\nstderr:\n{}",
        String::from_utf8_lossy(&foreign_model.stderr)
    );
    let cross_scope = journey.ncm_output(true, "recover", &scoped_options(&journey.project, true));
    assert!(!cross_scope.status.success());
    assert!(
        String::from_utf8_lossy(&cross_scope.stderr)
            .contains("belongs to another profile or project"),
        "cross-scope recovery must be refused\nstderr:\n{}",
        String::from_utf8_lossy(&cross_scope.stderr)
    );
    assert!(interrupted.journal_path.is_file());
    assert!(interrupted.worker_path.is_file());
    fs::write(&interrupted.journal_path, original_journal).expect("restore interrupted journal");

    let symlink_target = journey.home.path().join("symlink-target");
    fs::write(&symlink_target, &interrupted.worker_bytes).expect("symlink target");
    fs::remove_file(&interrupted.worker_path).expect("replace staged worker with symlink");
    std::os::unix::fs::symlink(&symlink_target, &interrupted.worker_path)
        .expect("staged worker symlink");
    let symlink_refusal =
        journey.ncm_output(true, "recover", &scoped_options(&journey.project, true));
    assert!(!symlink_refusal.status.success());
    let symlink_stderr = String::from_utf8_lossy(&symlink_refusal.stderr);
    assert!(
        symlink_stderr.contains("not a regular file") || symlink_stderr.contains("path is unsafe"),
        "recovery must reject a symlinked staged worker\nstderr:\n{symlink_stderr}"
    );
    assert!(interrupted.journal_path.is_file());
    fs::remove_file(&interrupted.worker_path).expect("remove staged worker symlink");
    fs::write(&interrupted.worker_path, &interrupted.worker_bytes)
        .expect("restore staged worker bytes");

    let foreign_worker = journey.home.path().join("foreign-worker");
    let foreign_state = journey.home.path().join("foreign-state");
    journey.set_observer_enabled(&project_id, &foreign_worker, &foreign_state);
    let revision_refusal =
        journey.ncm_output(true, "recover", &scoped_options(&journey.project, true));
    assert!(!revision_refusal.status.success());
    assert!(
        String::from_utf8_lossy(&revision_refusal.stderr)
            .contains("configuration changed outside the pending journal"),
        "recovery must refuse foreign configuration revision\nstderr:\n{}",
        String::from_utf8_lossy(&revision_refusal.stderr)
    );
    assert!(interrupted.journal_path.is_file());
    assert!(interrupted.worker_path.is_file());
    assert!(interrupted.manifest_path.is_file());

    journey.set_observer_disabled(&project_id);
    let recovered = journey.ncm_json(true, "recover", &scoped_options(&journey.project, true));
    assert_eq!(recovered["operation"], "recover");
    assert_eq!(recovered["outcome"], "recovered");
    assert!(!interrupted.journal_path.exists());
    assert!(!interrupted.worker_path.exists());
    assert!(!interrupted.manifest_path.exists());
    assert!(!interrupted.model_manifest_path.exists());
    assert!(
        interrupted
            .state_root
            .join("models/ncm-encoder-manifest.json")
            .is_file(),
        "recovery preserves model state"
    );
    let final_status = journey.status();
    assert_eq!(final_status["enabled"], false);
    assert_eq!(final_status["pending_recovery"], false);
}

#[cfg(unix)]
#[test]
fn ncm_update_and_uninstall_recovery_is_phase_aware_and_preserves_companion_manifest() {
    let mut journey = NcmJourney::new();
    journey.start_daemon();
    journey.init_project();
    let project_id = journey.project_id();
    let profile_id = journey.profile_id();
    let control_root = journey.profile.data_dir().join("ncm");
    let worker_root = control_root.join("worker");
    let state_root = journey.home.path().join("ncm-state");
    let old_operation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let new_operation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let old_parent = worker_root.join(old_operation);
    let new_parent = worker_root.join(new_operation);
    let old_worker = old_parent.join(WORKER_NAME);
    let old_manifest = old_parent.join(WORKER_MANIFEST_NAME);
    let old_model_manifest = old_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
    let new_worker = new_parent.join(WORKER_NAME);
    let new_manifest = new_parent.join(WORKER_MANIFEST_NAME);
    let new_model_manifest = new_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
    fs::create_dir_all(&old_parent).expect("old worker parent");
    fs::create_dir_all(&new_parent).expect("new worker parent");
    fs::create_dir_all(&state_root).expect("NCM state root");
    let old_worker_bytes = b"old worker bytes";
    let old_manifest_bytes = b"old worker manifest";
    let new_worker_bytes = b"new worker bytes";
    let new_manifest_bytes = b"new worker manifest";
    fs::write(&old_worker, old_worker_bytes).expect("old worker");
    fs::write(&old_manifest, old_manifest_bytes).expect("old worker manifest");
    fs::write(&old_model_manifest, TRUSTED_MODEL_ACQUISITION_MANIFEST)
        .expect("old model acquisition manifest");
    fs::write(&new_worker, new_worker_bytes).expect("new worker");
    fs::write(&new_manifest, new_manifest_bytes).expect("new worker manifest");
    fs::write(&new_model_manifest, TRUSTED_MODEL_ACQUISITION_MANIFEST)
        .expect("new model acquisition manifest");

    journey.set_observer_enabled(&project_id, &old_worker, &state_root);
    let update_journal = control_root.join("control-journal-v1.json");
    let update_before_document = enabled_document(&old_worker, &state_root);
    let update_after_document = enabled_document(&new_worker, &state_root);
    let update = json!({
        "schema_version": 1,
        "operation_id": new_operation,
        "operation": "update",
        "phase": "staged",
        "profile_id": &profile_id,
        "project_id": &project_id,
        "worker_path": &new_worker,
        "manifest_path": &new_manifest,
        "model_manifest_path": &new_model_manifest,
        "state_root": &state_root,
        "before_configuration_revision": journey.configuration_revision(),
        "before_document": update_before_document,
        "after_document": update_after_document,
        "before_worker_digest": sha256_hex(old_worker_bytes),
        "before_manifest_digest": sha256_hex(old_manifest_bytes),
        "before_model_manifest_digest": sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST),
        "after_worker_digest": sha256_hex(new_worker_bytes),
        "after_manifest_digest": sha256_hex(new_manifest_bytes),
        "after_model_manifest_digest": sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST),
        "before_worker_backup": null,
        "before_manifest_backup": null,
        "before_model_manifest_backup": null,
    });
    fs::write(
        &update_journal,
        serde_json::to_vec_pretty(&update).expect("update journal JSON"),
    )
    .expect("update journal");
    let update_recovered =
        journey.ncm_json(true, "recover", &scoped_options(&journey.project, true));
    assert_eq!(update_recovered["operation"], "recover");
    assert_eq!(update_recovered["outcome"], "recovered");
    assert!(!new_parent.exists(), "staged update bundle is rolled back");
    assert!(old_worker.is_file());
    assert!(old_manifest.is_file());
    assert!(old_model_manifest.is_file());
    assert_eq!(
        fs::read(&old_model_manifest).expect("old model acquisition manifest"),
        TRUSTED_MODEL_ACQUISITION_MANIFEST
    );

    let uninstall_operation = "cccccccccccccccccccccccccccccccc";
    let backup_parent = control_root.join("backups").join(uninstall_operation);
    fs::create_dir_all(&backup_parent).expect("uninstall backup parent");
    fs::write(backup_parent.join(WORKER_NAME), old_worker_bytes).expect("worker backup");
    fs::write(backup_parent.join(WORKER_MANIFEST_NAME), old_manifest_bytes)
        .expect("worker manifest backup");
    fs::write(
        backup_parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
        TRUSTED_MODEL_ACQUISITION_MANIFEST,
    )
    .expect("model acquisition manifest backup");
    let uninstall_before_document = enabled_document(&old_worker, &state_root);
    let uninstall = json!({
        "schema_version": 1,
        "operation_id": uninstall_operation,
        "operation": "uninstall",
        "phase": "staged",
        "profile_id": journey.profile_id(),
        "project_id": journey.project_id(),
        "worker_path": &old_worker,
        "manifest_path": &old_manifest,
        "model_manifest_path": &old_model_manifest,
        "state_root": &state_root,
        "before_configuration_revision": journey.configuration_revision(),
        "before_document": uninstall_before_document,
        "after_document": disabled_document(),
        "before_worker_digest": sha256_hex(old_worker_bytes),
        "before_manifest_digest": sha256_hex(old_manifest_bytes),
        "before_model_manifest_digest": sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST),
        "after_worker_digest": null,
        "after_manifest_digest": null,
        "after_model_manifest_digest": null,
        "before_worker_backup": backup_parent.join(WORKER_NAME),
        "before_manifest_backup": backup_parent.join(WORKER_MANIFEST_NAME),
        "before_model_manifest_backup": backup_parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
    });
    fs::write(
        &update_journal,
        serde_json::to_vec_pretty(&uninstall).expect("uninstall journal JSON"),
    )
    .expect("uninstall journal");
    journey.set_observer_disabled(&journey.project_id());
    fs::write(&old_model_manifest, b"tampered installed model manifest")
        .expect("tampered installed model manifest");
    let uninstall_recovered =
        journey.ncm_json(true, "recover", &scoped_options(&journey.project, true));
    assert_eq!(uninstall_recovered["operation"], "uninstall");
    assert_eq!(uninstall_recovered["outcome"], "committed");
    assert!(!update_journal.exists());
    assert!(!backup_parent.exists(), "verified backups are cleaned");
    assert!(
        old_worker.is_file(),
        "disable recovery keeps the worker available"
    );
    assert!(old_manifest.is_file());
    assert_eq!(
        fs::read(&old_model_manifest).expect("tampered model acquisition manifest"),
        b"tampered installed model manifest"
    );
    assert_eq!(journey.status()["enabled"], false);
    assert_eq!(journey.status()["pending_recovery"], false);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
#[ignore = "requires the pinned production worker at TRACEDECAY_NCM_WORKER"]
fn ncm_worker_lifecycle_verifies_target_and_preserves_model_state() {
    let worker = PathBuf::from(
        std::env::var_os("TRACEDECAY_NCM_WORKER")
            .expect("TRACEDECAY_NCM_WORKER points to the pinned release worker"),
    );
    assert!(worker.is_absolute() && worker.is_file());

    let mut journey = NcmJourney::new();
    journey.start_daemon();
    journey.init_project();
    let model_root = journey.home.path().join("ncm-state");
    fs::create_dir_all(model_root.join("models")).expect("model root");
    let model_manifest = model_root.join("models/ncm-encoder-manifest.json");
    fs::write(&model_manifest, br#"{"schema_version":1,"fixture":true}"#).expect("model manifest");

    let source_root = journey.home.path().join("worker-source");
    fs::create_dir_all(&source_root).expect("worker source root");
    let source_worker = source_root.join(WORKER_NAME);
    fs::copy(&worker, &source_worker).expect("copy pinned worker into fixture");
    let reference_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../product/ncm/reference/worker-manifest.json")
        .canonicalize()
        .expect("reference worker manifest");
    let source_manifest = source_root.join("worker-manifest.json");
    fs::copy(&reference_manifest, &source_manifest).expect("copy worker manifest");
    let reference_model_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../product/ncm/release/model-acquisition-manifest.json")
        .canonicalize()
        .expect("reference model acquisition manifest");
    let source_model_manifest = source_root.join(MODEL_ACQUISITION_MANIFEST_NAME);
    fs::copy(&reference_model_manifest, &source_model_manifest)
        .expect("copy model acquisition manifest");

    fs::remove_file(&source_model_manifest).expect("remove model acquisition manifest");
    let missing_model_manifest = journey.ncm_output(
        true,
        "install",
        &install_options(&journey.project, &source_worker, &model_root),
    );
    assert!(!missing_model_manifest.status.success());
    assert!(
        String::from_utf8_lossy(&missing_model_manifest.stderr)
            .contains("model acquisition manifest is missing")
    );
    assert!(
        fs::read_dir(journey.profile.data_dir().join("ncm/worker"))
            .expect("control worker root after rejected install")
            .next()
            .is_none()
    );
    fs::copy(&reference_model_manifest, &source_model_manifest)
        .expect("restore model acquisition manifest");

    let trusted_model_manifest = fs::read(&source_model_manifest).expect("trusted model manifest");
    fs::write(
        &source_model_manifest,
        b"tampered model acquisition manifest",
    )
    .expect("tamper model acquisition manifest");
    let tampered_model_manifest = journey.ncm_output(
        true,
        "install",
        &install_options(&journey.project, &source_worker, &model_root),
    );
    assert!(!tampered_model_manifest.status.success());
    assert!(
        String::from_utf8_lossy(&tampered_model_manifest.stderr)
            .contains("failed trusted release verification")
    );
    assert!(
        fs::read_dir(journey.profile.data_dir().join("ncm/worker"))
            .expect("control worker root after tampered install")
            .next()
            .is_none()
    );
    fs::write(&source_model_manifest, trusted_model_manifest)
        .expect("restore trusted model manifest bytes");

    let wrong_target_root = journey.home.path().join("wrong-target");
    fs::create_dir_all(&wrong_target_root).expect("wrong target root");
    fs::copy(&source_worker, wrong_target_root.join(WORKER_NAME)).expect("wrong target worker");
    let mut wrong_manifest: Value =
        serde_json::from_slice(&fs::read(&reference_manifest).expect("reference bytes"))
            .expect("reference manifest JSON");
    wrong_manifest["targets"][0]["triple"] = json!("x86_64-apple-darwin");
    fs::write(
        wrong_target_root.join("worker-manifest.json"),
        serde_json::to_vec_pretty(&wrong_manifest).expect("wrong target manifest"),
    )
    .expect("wrong target manifest bytes");
    fs::copy(
        &source_model_manifest,
        wrong_target_root.join(MODEL_ACQUISITION_MANIFEST_NAME),
    )
    .expect("wrong target model acquisition manifest");
    let mut wrong_target = scoped_options(&journey.project, true);
    wrong_target.extend(strings(&[
        "--worker",
        wrong_target_root
            .join(WORKER_NAME)
            .to_str()
            .expect("wrong worker path"),
        "--state-root",
        model_root.to_str().expect("model root path"),
    ]));
    let wrong_target_output = journey.ncm_output(true, "install", &wrong_target);
    assert!(!wrong_target_output.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_target_output.stderr)
            .contains("failed offline verification"),
        "wrong target must fail offline verification\nstderr:\n{}",
        String::from_utf8_lossy(&wrong_target_output.stderr)
    );

    let symlink_worker_root = journey.home.path().join("symlink-worker");
    fs::create_dir_all(&symlink_worker_root).expect("symlink worker root");
    std::os::unix::fs::symlink(&source_worker, symlink_worker_root.join(WORKER_NAME))
        .expect("symlink worker");
    fs::copy(
        &source_manifest,
        symlink_worker_root.join(WORKER_MANIFEST_NAME),
    )
    .expect("symlink worker manifest");
    fs::copy(
        &source_model_manifest,
        symlink_worker_root.join(MODEL_ACQUISITION_MANIFEST_NAME),
    )
    .expect("symlink worker model acquisition manifest");
    let mut symlink_worker = scoped_options(&journey.project, true);
    symlink_worker.extend(strings(&[
        "--worker",
        symlink_worker_root
            .join(WORKER_NAME)
            .to_str()
            .expect("symlink worker path"),
        "--state-root",
        model_root.to_str().expect("model root path"),
    ]));
    let symlink_output = journey.ncm_output(true, "install", &symlink_worker);
    assert!(!symlink_output.status.success());
    assert!(
        String::from_utf8_lossy(&symlink_output.stderr).contains("failed offline verification"),
        "symlink worker must fail offline verification\nstderr:\n{}",
        String::from_utf8_lossy(&symlink_output.stderr)
    );

    let mut install = scoped_options(&journey.project, true);
    install.extend(strings(&[
        "--worker",
        source_worker.to_str().expect("source worker path"),
        "--state-root",
        model_root.to_str().expect("model root path"),
    ]));
    let installed = journey.ncm_json(true, "install", &install);
    assert_eq!(installed["operation"], "install");
    assert_eq!(installed["outcome"], "committed");
    assert_eq!(installed["model_state"], "preserved");
    assert_eq!(installed["native_state"], "preserved");
    assert_eq!(installed["recall_routing"], "preserved");
    assert_eq!(
        installed["model_manifest_sha256"],
        Value::String(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST))
    );
    let installed_worker = PathBuf::from(
        installed["worker_path"]
            .as_str()
            .expect("installed worker path"),
    );
    assert!(installed_worker.starts_with(journey.profile.data_dir().join("ncm/worker")));
    assert!(installed_worker.is_file());
    let installed_model_manifest = installed_worker
        .parent()
        .expect("installed worker parent")
        .join(MODEL_ACQUISITION_MANIFEST_NAME);
    assert_eq!(
        fs::read(&installed_model_manifest).expect("installed model acquisition manifest"),
        fs::read(&reference_model_manifest).expect("reference model acquisition manifest bytes")
    );
    assert_eq!(journey.status()["enabled"], true);
    assert_eq!(journey.status()["model_manifest_present"], true);
    assert_eq!(journey.status()["model_acquisition_manifest_present"], true);

    let updated = journey.ncm_json(true, "update", &scoped_options(&journey.project, true));
    assert_eq!(updated["operation"], "update");
    assert_eq!(updated["outcome"], "committed");
    assert_eq!(
        updated["state_root"].as_str(),
        Some(model_root.to_str().expect("model root is UTF-8"))
    );
    assert_eq!(
        updated["model_manifest_sha256"],
        Value::String(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST))
    );
    let updated_worker = PathBuf::from(
        updated["worker_path"]
            .as_str()
            .expect("updated worker path"),
    );
    assert_ne!(updated_worker, installed_worker);
    assert!(updated_worker.is_file());
    let updated_model_manifest = updated_worker
        .parent()
        .expect("updated worker parent")
        .join(MODEL_ACQUISITION_MANIFEST_NAME);
    assert_eq!(
        fs::read(&updated_model_manifest).expect("updated model acquisition manifest"),
        fs::read(&reference_model_manifest).expect("reference model acquisition manifest bytes")
    );

    let updated_model_manifest_bytes =
        fs::read(&updated_model_manifest).expect("updated model manifest bytes");
    fs::write(
        &updated_model_manifest,
        b"tampered installed model manifest",
    )
    .expect("tamper installed model manifest");
    let tampered_status = journey.status();
    assert_eq!(tampered_status["model_acquisition_manifest_present"], true);
    assert_eq!(tampered_status["encoder_ready"], false);
    // A damaged installation still has a guarded disable path. The daemon is
    // intentionally kept live here: the CLI must disable configuration while
    // leaving bytes in place until the live owner releases them.
    let tampered_uninstall =
        journey.ncm_output(true, "uninstall", &scoped_options(&journey.project, true));
    assert!(tampered_uninstall.status.success());
    assert!(updated_worker.is_file());
    assert!(updated_model_manifest.is_file());
    assert_eq!(journey.status()["enabled"], false);
    fs::write(&updated_model_manifest, updated_model_manifest_bytes)
        .expect("restore installed model manifest");

    let reinstalled = journey.ncm_json(true, "install", &install);
    assert_eq!(reinstalled["outcome"], "committed");
    let reinstalled_worker = PathBuf::from(
        reinstalled["worker_path"]
            .as_str()
            .expect("reinstalled worker path"),
    );
    let uninstalled = journey.ncm_json(true, "uninstall", &scoped_options(&journey.project, true));
    assert_eq!(uninstalled["operation"], "uninstall");
    assert_eq!(uninstalled["outcome"], "committed");
    assert_eq!(uninstalled["model_state"], "preserved");
    assert!(reinstalled_worker.exists());
    assert!(
        reinstalled_worker
            .parent()
            .expect("reinstalled worker parent")
            .join(MODEL_ACQUISITION_MANIFEST_NAME)
            .exists()
    );
    assert!(model_manifest.is_file());
    assert_eq!(
        fs::read(&model_manifest).expect("model state"),
        br#"{"schema_version":1,"fixture":true}"#
    );
    let final_status = journey.status();
    assert_eq!(final_status["enabled"], false);
    assert_eq!(final_status["pending_recovery"], false);
    let no_effect = journey.ncm_json(true, "uninstall", &scoped_options(&journey.project, true));
    assert_eq!(no_effect["outcome"], "no_effect");
}

fn scoped_options(project: &Path, json: bool) -> Vec<String> {
    let mut options = strings(&["--path"]);
    options.push(project.to_string_lossy().into_owned());
    if json {
        options.push("--json".to_owned());
    }
    options
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn install_options(project: &Path, worker: &Path, state_root: &Path) -> Vec<String> {
    let mut options = scoped_options(project, true);
    options.extend(strings(&[
        "--worker",
        worker.to_str().expect("worker path is UTF-8"),
        "--state-root",
        state_root.to_str().expect("state root is UTF-8"),
    ]));
    options
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn disabled_document() -> String {
    r#"{"mode":"disabled"}"#.to_owned()
}

fn enabled_document(worker: &Path, state_root: &Path) -> String {
    json!({
        "mode": "enabled",
        "worker_binary": worker.to_string_lossy(),
        "state_root": state_root.to_string_lossy(),
    })
    .to_string()
}

fn install_binary_shim(bin_dir: &Path) {
    let shim = bin_dir.join(if cfg!(windows) {
        "tracedecay.exe"
    } else {
        "tracedecay"
    });
    link_or_copy_executable(crate::tracedecay_exe(), &shim).expect("stage shipped binary");
}

fn initialize_project(home: &Path, project: &Path, package_name: &str) {
    fs::create_dir_all(project.join("src")).expect("fixture source directory");
    git(home, project, &["init", "--quiet", "-b", "main"]);
    git(
        home,
        project,
        &["config", "user.email", "ncm-journey@example.com"],
    );
    git(home, project, &["config", "user.name", "NCM Journey"]);
    fs::write(
        project.join("Cargo.toml"),
        format!("[package]\nname=\"{package_name}\"\nversion=\"0.0.0\"\nedition=\"2024\"\n"),
    )
    .expect("fixture manifest");
    fs::write(
        project.join("src/lib.rs"),
        "pub fn ncm_lifecycle_fixture() -> u8 { 7 }\n",
    )
    .expect("fixture source");
    git(home, project, &["add", "."]);
    git(home, project, &["commit", "--quiet", "-m", "initial"]);
}

fn git(home: &Path, root: &Path, arguments: &[&str]) {
    let mut command = Command::new("git");
    apply_hermetic_child_env(&mut command, home);
    let status = command
        .current_dir(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {arguments:?} failed");
}

fn wait_for_authority(daemon: &mut Child, profile_root: &Path) {
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
            panic!("daemon exited before authority publication: {status}; stderr: {stderr}");
        }
        if let Some(record) = current_record(profile_root).expect("read isolated daemon authority")
            && record.pid == daemon.id()
            && record.profile_root == profile_root
            && record.auth_token.len() == 64
            && runtime.block_on(async {
                matches!(
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        DaemonClientStream::connect(&record.endpoint),
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
    panic!(
        "timed out waiting for daemon authority for profile {}",
        profile_root.display()
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn join_content_text(result: &Value) -> Option<String> {
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
        .join("\n\n");
    (!text.is_empty()).then_some(text)
}
