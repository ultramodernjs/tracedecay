//! Explicit lifecycle control for the opt-in NCM worker.
//!
//! The command owns only the operator-facing transaction around the existing
//! project configuration API and the runtime's offline worker verifier. NCM
//! stays disabled until `install` or `update` is explicitly confirmed. Native
//! participation and recall routing are deliberately read-only here.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracedecay_daemon_protocol::DaemonEndpoint;
use tracedecay_domain::configuration::{
    ConfigurationRevisionId, ConfigurationValueV1, MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
    MemoryProviderNcmObserverV1,
};
use tracedecay_memory_ncm_runtime::platform::current_worker_platform_capability;
use tracedecay_memory_ncm_runtime::worker_artifact::{
    WORKER_NAME, WorkerIntegrityError, stage_verified_worker_binary,
};
use tracedecay_private_fs::framed_log::{DirectorySyncPolicy, atomic_write, remove_conditionally};

const CONTROL_SCHEMA_VERSION: u16 = 1;
const CONTROL_DIRECTORY_NAME: &str = "ncm";
const WORKER_DIRECTORY_NAME: &str = "worker";
const BACKUP_DIRECTORY_NAME: &str = "backups";
const JOURNAL_FILE_NAME: &str = "control-journal-v1.json";
const RECEIPT_FILE_PREFIX: &str = "control-receipt.";
const RECEIPT_FILE_SUFFIX: &str = ".v1.json";
const WORKER_MANIFEST_NAME: &str = "worker-manifest.json";
const MODEL_ACQUISITION_MANIFEST_NAME: &str = "model-acquisition-manifest.json";
const MAX_WORKER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const TRUSTED_MODEL_ACQUISITION_MANIFEST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../product/ncm/release/model-acquisition-manifest.json"
));

/// NCM's explicit operator lifecycle operations.
#[derive(Clone, Debug, Subcommand)]
pub enum NcmAction {
    /// Report NCM configuration, worker, model, and pending-recovery state.
    Status {
        #[command(flatten)]
        scope: NcmScopeArgs,
        /// Emit one JSON object instead of a human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Verify and install a worker, then explicitly enable the NCM observer.
    Install {
        #[command(flatten)]
        scope: NcmScopeArgs,
        /// Absolute worker executable with its verified worker and model manifests.
        #[arg(long, alias = "worker-binary", alias = "worker-path")]
        worker: Option<PathBuf>,
        /// Absolute NCM state root. Existing model and provider state is kept.
        #[arg(long = "state-root")]
        state_root: Option<PathBuf>,
        /// Emit the committed control receipt as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify and stage a replacement worker while retaining NCM state.
    Update {
        #[command(flatten)]
        scope: NcmScopeArgs,
        /// Absolute replacement worker executable with its worker and model manifests.
        /// When omitted, the configured worker is reverified.
        #[arg(long, alias = "worker-binary", alias = "worker-path")]
        worker: Option<PathBuf>,
        /// Absolute NCM state root. When omitted, the configured root is kept.
        #[arg(long = "state-root")]
        state_root: Option<PathBuf>,
        /// Emit the committed control receipt as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Recover one interrupted NCM control transaction under digest guards.
    Recover {
        #[command(flatten)]
        scope: NcmScopeArgs,
        /// Emit the recovery receipt as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disable NCM and remove only the control-owned worker; model state stays.
    Uninstall {
        #[command(flatten)]
        scope: NcmScopeArgs,
        /// Emit the committed control receipt as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Project selector shared by all NCM commands.
#[derive(Args, Clone, Debug)]
pub struct NcmScopeArgs {
    /// Project path (default: current directory, with discovery).
    #[arg(short, long)]
    pub(crate) path: Option<String>,
    /// Registered project id to address instead of discovering from cwd.
    #[arg(long, conflicts_with = "path")]
    pub(crate) project_id: Option<String>,
    /// Registered project root path or alias to address instead of discovering from cwd.
    #[arg(long, conflicts_with_all = ["path", "project_id"])]
    pub(crate) project_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NcmControlOperation {
    Install,
    Update,
    Recover,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NcmJournalPhase {
    Prepared,
    Staged,
    Configured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NcmControlJournalV1 {
    schema_version: u16,
    operation_id: String,
    operation: NcmControlOperation,
    phase: NcmJournalPhase,
    profile_id: String,
    project_id: String,
    worker_path: PathBuf,
    manifest_path: PathBuf,
    model_manifest_path: PathBuf,
    state_root: Option<PathBuf>,
    before_configuration_revision: String,
    before_document: String,
    after_document: String,
    before_worker_digest: Option<String>,
    before_manifest_digest: Option<String>,
    before_model_manifest_digest: Option<String>,
    after_worker_digest: Option<String>,
    after_manifest_digest: Option<String>,
    after_model_manifest_digest: Option<String>,
    before_worker_backup: Option<PathBuf>,
    before_manifest_backup: Option<PathBuf>,
    before_model_manifest_backup: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct NcmControlReceiptV1 {
    schema_version: u16,
    operation_id: String,
    operation: NcmControlOperation,
    outcome: &'static str,
    profile_id: String,
    project_id: String,
    worker_path: Option<PathBuf>,
    state_root: Option<PathBuf>,
    worker_sha256: Option<String>,
    manifest_sha256: Option<String>,
    model_manifest_sha256: Option<String>,
    /// Explicitly records that lifecycle commands did not remove model state.
    model_state: &'static str,
    /// Explicitly records that the Native setting was not part of this mutation.
    native_state: &'static str,
    /// Explicitly records that recall routing was not part of this mutation.
    recall_routing: &'static str,
    configuration_receipt: Option<String>,
    created_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct NcmReceiptIndex {
    project_id: String,
    created_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct NcmReceiptArtifactIndex {
    operation: NcmControlOperation,
    outcome: String,
    project_id: String,
    created_at_unix: u64,
    #[serde(default)]
    worker_path: Option<PathBuf>,
    #[serde(default)]
    worker_sha256: Option<String>,
    #[serde(default)]
    manifest_sha256: Option<String>,
    #[serde(default)]
    model_manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NcmStatusReport {
    profile_root: PathBuf,
    project_root: PathBuf,
    profile_id: String,
    project_id: String,
    platform_supported: bool,
    platform_target: String,
    enabled: bool,
    worker_path: Option<PathBuf>,
    worker_manifest_path: Option<PathBuf>,
    model_acquisition_manifest_path: Option<PathBuf>,
    state_root: Option<PathBuf>,
    worker_present: bool,
    worker_sha256: Option<String>,
    manifest_present: bool,
    manifest_sha256: Option<String>,
    model_acquisition_manifest_present: bool,
    model_acquisition_manifest_sha256: Option<String>,
    model_manifest_present: bool,
    encoder_ready: bool,
    pending_recovery: bool,
    latest_receipt: Option<PathBuf>,
}

struct ControlPaths {
    root: PathBuf,
    worker_root: PathBuf,
    backup_root: PathBuf,
    journal: PathBuf,
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    bytes: Vec<u8>,
    digest: String,
}

type Result<T> = tracedecay_domain::errors::Result<T>;

/// Dispatches an NCM action after the root CLI has validated the global
/// confirmation flag. Mutating actions require that explicit confirmation.
pub(crate) async fn handle_ncm_action(action: NcmAction, assume_yes: bool) -> Result<()> {
    match action {
        NcmAction::Status { scope, json } => handle_status(scope, json).await,
        NcmAction::Install {
            scope,
            worker,
            state_root,
            json,
        } => {
            require_confirmation(assume_yes, "ncm install")?;
            handle_install_or_update(
                NcmControlOperation::Install,
                scope,
                worker,
                state_root,
                json,
            )
            .await
        }
        NcmAction::Update {
            scope,
            worker,
            state_root,
            json,
        } => {
            require_confirmation(assume_yes, "ncm update")?;
            handle_install_or_update(NcmControlOperation::Update, scope, worker, state_root, json)
                .await
        }
        NcmAction::Recover { scope, json } => {
            require_confirmation(assume_yes, "ncm recover")?;
            handle_recover(scope, json).await
        }
        NcmAction::Uninstall { scope, json } => {
            require_confirmation(assume_yes, "ncm uninstall")?;
            handle_uninstall(scope, json).await
        }
    }
}

fn require_confirmation(assume_yes: bool, operation: &str) -> Result<()> {
    if assume_yes {
        Ok(())
    } else {
        Err(config_error(format!(
            "{operation} changes project configuration; pass --yes to confirm"
        )))
    }
}

async fn resolve_scope(scope: NcmScopeArgs) -> Result<crate::commands::ResolvedCliScope> {
    let requested =
        crate::resolve_cli_project_root(scope.path, scope.project_id, scope.project_path).await?;
    crate::commands::resolve_project_scope(requested).await
}

fn control_paths(create: bool) -> Result<(PathBuf, ControlPaths)> {
    let profile_root = tracedecay_runtime_core::storage::default_profile_root()?;
    let paths = control_paths_for_profile(&profile_root, create)?;
    Ok((profile_root, paths))
}

fn control_paths_for_profile(profile_root: &Path, create: bool) -> Result<ControlPaths> {
    require_absolute_path(profile_root, "profile root")?;
    let root = profile_root.join(CONTROL_DIRECTORY_NAME);
    let worker_root = root.join(WORKER_DIRECTORY_NAME);
    let backup_root = root.join(BACKUP_DIRECTORY_NAME);
    reject_symlink_components(&root, "NCM control directory")?;
    if create {
        for directory in [&root, &worker_root, &backup_root] {
            reject_symlink_components(directory, "NCM control directory")?;
            fs::create_dir_all(directory)
                .map_err(|error| io_error("create NCM control directory", directory, error))?;
            tracedecay_private_fs::make_private_directory(directory)
                .map_err(|error| io_error("secure NCM control directory", directory, error))?;
            tracedecay_private_fs::framed_log::sync_parent_directory(
                directory,
                DirectorySyncPolicy::Strict,
            )
            .map_err(|error| io_error("sync NCM control directory parent", directory, error))?;
        }
    }
    let journal = root.join(JOURNAL_FILE_NAME);
    Ok(ControlPaths {
        root,
        worker_root,
        backup_root,
        journal,
    })
}

async fn handle_status(scope: NcmScopeArgs, json: bool) -> Result<()> {
    let resolved = resolve_scope(scope).await?;
    let (profile_root, paths) = control_paths(false)?;
    let (observer_document, observer) = read_observer(&resolved.project_path).await?;
    let _ = observer_document;
    let (worker_path, state_root) = match observer {
        MemoryProviderNcmObserverV1::Disabled {} => (None, None),
        MemoryProviderNcmObserverV1::Enabled {
            worker_binary,
            state_root,
        } => (Some(worker_binary), Some(state_root)),
    };
    let manifest_path = worker_path
        .as_deref()
        .and_then(Path::parent)
        .map(|parent| parent.join(WORKER_MANIFEST_NAME));
    let model_acquisition_manifest_path = worker_path
        .as_deref()
        .and_then(Path::parent)
        .map(|parent| parent.join(MODEL_ACQUISITION_MANIFEST_NAME));
    let worker = worker_path
        .as_deref()
        .map(|path| read_regular_snapshot(path, MAX_WORKER_BYTES, "worker"))
        .transpose()?
        .flatten();
    let manifest = manifest_path
        .as_deref()
        .map(|path| read_regular_snapshot(path, MAX_MANIFEST_BYTES, "worker manifest"))
        .transpose()?
        .flatten();
    let model_acquisition_manifest = model_acquisition_manifest_path
        .as_deref()
        .map(|path| read_regular_snapshot(path, MAX_MANIFEST_BYTES, "model acquisition manifest"))
        .transpose()?
        .flatten();
    let state_root_is_safe = state_root
        .as_deref()
        .is_some_and(|root| reject_symlink_components(root, "state root").is_ok());
    let model_lifecycle_pending = state_root_is_safe
        && state_root
            .as_deref()
            .map(model_lifecycle_journal_present)
            .transpose()?
            .unwrap_or(false);
    let model_manifest_present = state_root_is_safe
        && state_root.as_deref().is_some_and(|root| {
            read_regular_snapshot(
                &root.join("models").join("ncm-encoder-manifest.json"),
                MAX_MANIFEST_BYTES,
                "model state manifest",
            )
            .ok()
            .flatten()
            .is_some()
        });
    let sidecar_is_trusted = model_acquisition_manifest
        .as_ref()
        .is_some_and(|file| file.bytes.as_slice() == TRUSTED_MODEL_ACQUISITION_MANIFEST);
    let encoder_ready = worker.is_some()
        && manifest.is_some()
        && sidecar_is_trusted
        && state_root_is_safe
        && state_root.as_deref().is_some_and(|root| {
            tracedecay_memory_ncm_runtime::ports::StateRoot::new(root.to_path_buf()).is_ok_and(
                |state_root| tracedecay_memory_ncm_runtime::embedding::offline_probe(&state_root),
            )
        });
    let capability = current_worker_platform_capability();
    let report = NcmStatusReport {
        profile_root,
        project_root: resolved.project_path,
        profile_id: resolved.profile_id.as_str().to_owned(),
        project_id: resolved.project_id.as_str().to_owned(),
        platform_supported: capability.is_supported(),
        platform_target: capability.target().to_owned(),
        enabled: worker_path.is_some(),
        worker_path,
        worker_manifest_path: manifest_path,
        model_acquisition_manifest_path,
        state_root,
        worker_present: worker.is_some(),
        worker_sha256: worker.as_ref().map(|file| file.digest.clone()),
        manifest_present: manifest.is_some(),
        manifest_sha256: manifest.as_ref().map(|file| file.digest.clone()),
        model_acquisition_manifest_present: model_acquisition_manifest.is_some(),
        model_acquisition_manifest_sha256: model_acquisition_manifest
            .as_ref()
            .map(|file| file.digest.clone()),
        model_manifest_present,
        encoder_ready,
        pending_recovery: journal_present(&paths)? || model_lifecycle_pending,
        latest_receipt: latest_receipt(&paths.root, resolved.project_id.as_str())?,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| config_error(error.to_string()))?
        );
    } else {
        let mode = if report.enabled {
            "enabled"
        } else {
            "disabled"
        };
        println!("NCM: {mode}");
        println!("Platform: {}", report.platform_target);
        if let Some(path) = &report.worker_path {
            println!("Worker: {}", path.display());
            println!("Worker present: {}", report.worker_present);
        }
        if let Some(path) = &report.model_acquisition_manifest_path {
            println!("Model acquisition manifest: {}", path.display());
            println!(
                "Model acquisition manifest present: {}",
                report.model_acquisition_manifest_present
            );
        }
        if let Some(root) = &report.state_root {
            println!("State root: {}", root.display());
            println!("Model manifest present: {}", report.model_manifest_present);
            println!("Encoder ready: {}", report.encoder_ready);
        }
        if report.pending_recovery {
            println!("Recovery: pending ({})", paths.journal.display());
        }
        if let Some(receipt) = &report.latest_receipt {
            println!("Latest receipt: {}", receipt.display());
        }
    }
    Ok(())
}

async fn handle_install_or_update(
    operation: NcmControlOperation,
    scope: NcmScopeArgs,
    worker: Option<PathBuf>,
    state_root: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    ensure_supported_platform()?;
    let resolved = resolve_scope(scope).await?;
    let (_profile_root, paths) = control_paths(true)?;
    refuse_pending_journal(
        &paths,
        Some((resolved.profile_id.as_str(), resolved.project_id.as_str())),
    )?;
    let (_before_document, before_observer) = read_observer(&resolved.project_path).await?;
    let before_configuration_revision =
        crate::commands::current_configuration_revision(&resolved.project_path).await?;
    let before_document = observer_document(&before_observer)?;
    let before_enabled = matches!(before_observer, MemoryProviderNcmObserverV1::Enabled { .. });
    if matches!(operation, NcmControlOperation::Update) && !before_enabled {
        return Err(config_error(
            "NCM is disabled; use `ncm install` to enable it explicitly",
        ));
    }
    let configured_worker = match &before_observer {
        MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } => Some(worker_binary.clone()),
        MemoryProviderNcmObserverV1::Disabled {} => None,
    };
    let source_worker = worker.or(configured_worker).ok_or_else(|| {
        config_error(
            "NCM install requires --worker; the worker must have worker-manifest.json and model-acquisition-manifest.json beside it",
        )
    })?;
    require_absolute_path(&source_worker, "worker path")?;
    let source_model_manifest = source_worker
        .parent()
        .map(|parent| parent.join(MODEL_ACQUISITION_MANIFEST_NAME))
        .ok_or_else(|| config_error("worker path has no parent for model acquisition manifest"))?;
    let source_model_manifest = read_verified_model_acquisition_manifest(&source_model_manifest)?;
    let (before_worker_digest, before_manifest_digest, before_model_manifest_digest) =
        if matches!(operation, NcmControlOperation::Update) {
            match &before_observer {
                MemoryProviderNcmObserverV1::Enabled { worker_binary, .. }
                    if is_control_worker_path(&paths, worker_binary) =>
                {
                    best_effort_previous_bundle_digests(
                        &paths,
                        resolved.project_id.as_str(),
                        worker_binary,
                    )
                }
                _ => (None, None, None),
            }
        } else {
            (None, None, None)
        };
    let state_root = state_root
        .or_else(|| match &before_observer {
            MemoryProviderNcmObserverV1::Enabled { state_root, .. } => Some(state_root.clone()),
            MemoryProviderNcmObserverV1::Disabled {} => None,
        })
        .ok_or_else(|| config_error("NCM install requires --state-root"))?;
    require_absolute_path(&state_root, "state root")?;
    reject_symlink_components(&state_root, "state root")?;
    if matches!(operation, NcmControlOperation::Update)
        && let MemoryProviderNcmObserverV1::Enabled {
            state_root: previous_state_root,
            ..
        } = &before_observer
        && previous_state_root != &state_root
    {
        return Err(config_error(
            "NCM state-root changes require an explicit model migration",
        ));
    }
    if model_lifecycle_journal_present(&state_root)? && daemon_profile_has_live_owner(&paths)? {
        return Err(config_error(
            "NCM model lifecycle recovery is blocked while the daemon owns the profile",
        ));
    }
    recover_pending_model_lifecycle(&state_root)?;
    let artifact = stage_verified_worker_binary(&source_worker)
        .map_err(|error| verifier_error(&source_worker, error))?;
    let manifest_bytes = artifact.manifest_bytes();
    if manifest_bytes.is_empty() {
        return Err(config_error(
            "verified worker did not retain its manifest bytes",
        ));
    }
    let manifest_digest = sha256_hex(manifest_bytes);
    let operation_identity = format!(
        "worker_sha256={}|worker_manifest_sha256={}|model_manifest_sha256={}|state_root={}",
        artifact.sha256(),
        manifest_digest,
        &source_model_manifest.digest,
        state_root.display(),
    );
    let operation_id = operation_id_for_identity(
        resolved.profile_id.as_str(),
        resolved.project_id.as_str(),
        operation,
        &operation_identity,
    );
    let worker_path = paths.worker_root.join(&operation_id).join(WORKER_NAME);
    let manifest_path = worker_path
        .parent()
        .map(|parent| parent.join(WORKER_MANIFEST_NAME))
        .ok_or_else(|| config_error("staged worker path has no parent"))?;
    let model_manifest_path = worker_path
        .parent()
        .map(|parent| parent.join(MODEL_ACQUISITION_MANIFEST_NAME))
        .ok_or_else(|| config_error("staged worker path has no parent"))?;
    let after_observer = MemoryProviderNcmObserverV1::Enabled {
        worker_binary: worker_path.clone(),
        state_root: state_root.clone(),
    };
    after_observer
        .validate()
        .map_err(|error| config_error(error.to_string()))?;
    let after_document = observer_document(&after_observer)?;

    if matches!(operation, NcmControlOperation::Install) && before_enabled {
        let committed_same_bundle = matches!(
            &before_observer,
            MemoryProviderNcmObserverV1::Enabled {
                worker_binary: configured_worker,
                state_root: configured_state_root,
            } if configured_worker == &worker_path
                && configured_state_root == &state_root
                && control_bundle_has_only_expected_entries(configured_worker).unwrap_or(false)
                && bundle_digests_match(
                    configured_worker,
                    artifact.sha256(),
                    &manifest_digest,
                    source_model_manifest.digest.as_str(),
                )
        );
        if committed_same_bundle {
            if receipt_path_for(&paths, &operation_id).is_some() {
                emit_existing_receipt(&paths, NcmControlOperation::Install, &operation_id, json)?;
            } else {
                emit_reconstructed_receipt(
                    &paths,
                    NcmControlOperation::Install,
                    &operation_id,
                    resolved.profile_id.as_str(),
                    resolved.project_id.as_str(),
                    worker_path.clone(),
                    state_root.clone(),
                    Some(artifact.sha256().to_owned()),
                    Some(manifest_digest.clone()),
                    Some(source_model_manifest.digest.clone()),
                    json,
                    "NCM install already committed",
                )?;
            }
            return Ok(());
        }
        return Err(config_error(
            "NCM is already enabled; use `ncm update` to replace its worker",
        ));
    }

    // A retry after a committed update must reuse the same staged identity and
    // leave the already committed worker untouched. The regular digests above
    // are the same snapshots used by guarded cleanup, so this check cannot
    // turn a changed installation into an idempotent success.
    let committed_same_update = if matches!(operation, NcmControlOperation::Update) {
        match &before_observer {
            MemoryProviderNcmObserverV1::Enabled {
                worker_binary: configured_worker,
                state_root: configured_state_root,
            } if configured_worker == &worker_path
                && configured_state_root == &state_root
                && before_worker_digest.as_deref() == Some(artifact.sha256())
                && before_manifest_digest.as_deref() == Some(manifest_digest.as_str())
                && before_model_manifest_digest.as_deref()
                    == Some(source_model_manifest.digest.as_str())
                && control_bundle_has_only_expected_entries(configured_worker).unwrap_or(false)
                && bundle_digests_match(
                    configured_worker,
                    artifact.sha256(),
                    &manifest_digest,
                    source_model_manifest.digest.as_str(),
                ) =>
            {
                true
            }
            _ => false,
        }
    } else {
        false
    };
    if committed_same_update {
        if receipt_path_for(&paths, &operation_id).is_some() {
            emit_existing_receipt(&paths, NcmControlOperation::Update, &operation_id, json)?;
        } else {
            emit_reconstructed_receipt(
                &paths,
                NcmControlOperation::Update,
                &operation_id,
                resolved.profile_id.as_str(),
                resolved.project_id.as_str(),
                worker_path.clone(),
                state_root.clone(),
                Some(artifact.sha256().to_owned()),
                Some(manifest_digest.clone()),
                Some(source_model_manifest.digest.clone()),
                json,
                "NCM update already committed",
            )?;
        }
        return Ok(());
    }
    let reuse_existing_target = if daemon_profile_has_live_owner(&paths)? {
        let target_parent = worker_path
            .parent()
            .ok_or_else(|| config_error("staged worker path has no parent"))?;
        match fs::symlink_metadata(target_parent) {
            Ok(metadata) if metadata.is_dir() => {
                reject_symlink_components(target_parent, "staged NCM worker directory")?;
                if !control_bundle_has_only_expected_entries(&worker_path)?
                    || !bundle_digests_match(
                        &worker_path,
                        artifact.sha256(),
                        &manifest_digest,
                        source_model_manifest.digest.as_str(),
                    )
                {
                    return Err(config_error(
                        "NCM cannot replace a live daemon's worker bundle; stop the daemon first",
                    ));
                }
                true
            }
            Ok(_) => {
                return Err(config_error(
                    "NCM staged worker target is not a directory owned by the control root",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(io_error(
                    "inspect staged NCM worker directory",
                    target_parent,
                    error,
                ));
            }
        }
    } else {
        false
    };
    let journal = NcmControlJournalV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id: operation_id.clone(),
        operation,
        phase: NcmJournalPhase::Prepared,
        profile_id: resolved.profile_id.as_str().to_owned(),
        project_id: resolved.project_id.as_str().to_owned(),
        worker_path: worker_path.clone(),
        manifest_path: manifest_path.clone(),
        model_manifest_path: model_manifest_path.clone(),
        state_root: Some(state_root.clone()),
        before_configuration_revision: before_configuration_revision.to_string(),
        before_document,
        after_document,
        before_worker_digest,
        before_manifest_digest,
        before_model_manifest_digest,
        after_worker_digest: Some(artifact.sha256().to_owned()),
        after_manifest_digest: Some(manifest_digest),
        after_model_manifest_digest: Some(source_model_manifest.digest.clone()),
        before_worker_backup: None,
        before_manifest_backup: None,
        before_model_manifest_backup: None,
    };
    write_journal(&paths, &journal)?;
    if !reuse_existing_target {
        if let Err(error) = publish_worker(
            &worker_path,
            manifest_bytes,
            &source_model_manifest.bytes,
            artifact.path(),
        ) {
            return Err(error);
        }
    }
    let mut journal = journal;
    journal.phase = NcmJournalPhase::Staged;
    write_journal(&paths, &journal)?;
    let configuration_receipt = match set_observer_if_unchanged(
        &resolved,
        &journal.before_document,
        Some(&journal.before_configuration_revision),
        &after_observer,
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Err(recovery_error) = recover_journal(&resolved, &paths, false, false).await {
                return Err(config_error(format!(
                    "NCM configuration failed: {error}; automatic recovery failed: {recovery_error}"
                )));
            }
            return Err(error);
        }
    };
    journal.phase = NcmJournalPhase::Configured;
    write_journal(&paths, &journal)?;
    if matches!(operation, NcmControlOperation::Update) {
        cleanup_previous_control_worker(&before_observer, &journal, &paths)?;
    }
    cleanup_orphaned_control_workers(
        &paths,
        resolved.project_id.as_str(),
        &[&journal.worker_path],
    )?;
    let receipt = NcmControlReceiptV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id,
        operation,
        outcome: "committed",
        profile_id: resolved.profile_id.as_str().to_owned(),
        project_id: resolved.project_id.as_str().to_owned(),
        worker_path: Some(worker_path),
        state_root: Some(state_root),
        worker_sha256: journal.after_worker_digest.clone(),
        manifest_sha256: journal.after_manifest_digest.clone(),
        model_manifest_sha256: journal.after_model_manifest_digest.clone(),
        model_state: "preserved",
        native_state: "preserved",
        recall_routing: "preserved",
        configuration_receipt: configuration_receipt
            .as_ref()
            .map(|effect| effect.request_id.as_str().to_owned()),
        created_at_unix: now_unix(),
    };
    let receipt_path = write_receipt(&paths, &receipt)?;
    remove_journal(&paths)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt)
                .map_err(|error| config_error(error.to_string()))?
        );
    } else {
        println!(
            "NCM {} committed; receipt {}",
            operation_name(operation),
            receipt_path.display()
        );
        tracedecay_cli_configuration_receipt(configuration_receipt.as_ref());
    }
    Ok(())
}

async fn handle_uninstall(scope: NcmScopeArgs, json: bool) -> Result<()> {
    let resolved = resolve_scope(scope).await?;
    let (_profile_root, paths) = control_paths(true)?;
    refuse_pending_journal(
        &paths,
        Some((resolved.profile_id.as_str(), resolved.project_id.as_str())),
    )?;
    let (_before_document, before_observer) = read_observer(&resolved.project_path).await?;
    let before_configuration_revision =
        crate::commands::current_configuration_revision(&resolved.project_path).await?;
    let before_document = observer_document(&before_observer)?;
    let MemoryProviderNcmObserverV1::Enabled {
        worker_binary,
        state_root,
    } = before_observer
    else {
        cleanup_orphaned_control_workers(&paths, resolved.project_id.as_str(), &[])?;
        let operation_id = new_operation_id(
            resolved.profile_id.as_str(),
            resolved.project_id.as_str(),
            NcmControlOperation::Uninstall,
        );
        let receipt = NcmControlReceiptV1 {
            schema_version: CONTROL_SCHEMA_VERSION,
            operation_id,
            operation: NcmControlOperation::Uninstall,
            outcome: "no_effect",
            profile_id: resolved.profile_id.as_str().to_owned(),
            project_id: resolved.project_id.as_str().to_owned(),
            worker_path: None,
            state_root: None,
            worker_sha256: None,
            manifest_sha256: None,
            model_manifest_sha256: None,
            model_state: "preserved",
            native_state: "preserved",
            recall_routing: "preserved",
            configuration_receipt: None,
            created_at_unix: now_unix(),
        };
        let receipt_path = write_receipt(&paths, &receipt)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt)
                    .map_err(|error| config_error(error.to_string()))?
            );
        } else {
            println!("NCM already disabled; receipt {}", receipt_path.display());
        }
        return Ok(());
    };
    require_absolute_path(&worker_binary, "configured worker path")?;
    require_absolute_path(&state_root, "configured state root")?;
    let control_owned = is_control_worker_path(&paths, &worker_binary);
    if control_owned
        && reject_symlink_components(&state_root, "configured state root").is_ok()
        && !daemon_profile_has_live_owner(&paths)?
    {
        // Disable is still available when a model transaction is damaged: the
        // CLI does not own model bytes and must leave that journal for an
        // explicit model repair path.
        let _ = recover_pending_model_lifecycle(&state_root);
    }
    let manifest_path = worker_binary
        .parent()
        .map(|parent| parent.join(WORKER_MANIFEST_NAME))
        .ok_or_else(|| config_error("configured worker path has no parent"))?;
    let model_manifest_path = worker_binary
        .parent()
        .map(|parent| parent.join(MODEL_ACQUISITION_MANIFEST_NAME))
        .ok_or_else(|| config_error("configured worker path has no parent"))?;
    // Uninstall is the guarded disable path. A missing, malformed, or
    // tampered artifact must never prevent the configuration from being
    // disabled; only regular bytes observed before the journal are eligible
    // for later guarded deletion. The trusted model sidecar is deliberately
    // excluded from deletion unless it is the exact release descriptor.
    let committed_bundle =
        committed_bundle_digests(&paths, resolved.project_id.as_str(), &worker_binary);
    let before_worker =
        best_effort_snapshot(&worker_binary, MAX_WORKER_BYTES, "worker").filter(|file| {
            committed_bundle
                .as_ref()
                .is_none_or(|bundle| bundle.0.as_deref() == Some(file.digest.as_str()))
        });
    let before_manifest =
        best_effort_snapshot(&manifest_path, MAX_MANIFEST_BYTES, "worker manifest").filter(
            |file| {
                committed_bundle
                    .as_ref()
                    .is_none_or(|bundle| bundle.1.as_deref() == Some(file.digest.as_str()))
            },
        );
    let before_model_manifest = best_effort_snapshot(
        &model_manifest_path,
        MAX_MANIFEST_BYTES,
        "model acquisition manifest",
    )
    .filter(|file| file.bytes.as_slice() == TRUSTED_MODEL_ACQUISITION_MANIFEST)
    .filter(|file| {
        committed_bundle
            .as_ref()
            .is_none_or(|bundle| bundle.2.as_deref() == Some(file.digest.as_str()))
    });
    let operation_identity = format!(
        "worker={}|worker_sha256={}|manifest_sha256={}|model_manifest_sha256={}",
        worker_binary.display(),
        before_worker
            .as_ref()
            .map_or("", |file| file.digest.as_str()),
        before_manifest
            .as_ref()
            .map_or("", |file| file.digest.as_str()),
        before_model_manifest
            .as_ref()
            .map_or("", |file| file.digest.as_str()),
    );
    let operation_id = operation_id_for_identity(
        resolved.profile_id.as_str(),
        resolved.project_id.as_str(),
        NcmControlOperation::Uninstall,
        &operation_identity,
    );
    let backup_dir = paths.backup_root.join(&operation_id);
    fs::create_dir_all(&backup_dir)
        .map_err(|error| io_error("create NCM uninstall backup", &backup_dir, error))?;
    tracedecay_private_fs::make_private_directory(&backup_dir)
        .map_err(|error| io_error("secure NCM uninstall backup", &backup_dir, error))?;
    tracedecay_private_fs::framed_log::sync_parent_directory(
        &backup_dir,
        DirectorySyncPolicy::Strict,
    )
    .map_err(|error| io_error("sync NCM uninstall backup parent", &backup_dir, error))?;
    let worker_backup = control_owned
        .then(|| before_worker.as_ref().map(|_| backup_dir.join(WORKER_NAME)))
        .flatten();
    let manifest_backup = control_owned
        .then(|| {
            before_manifest
                .as_ref()
                .map(|_| backup_dir.join(WORKER_MANIFEST_NAME))
        })
        .flatten();
    let model_manifest_backup = control_owned
        .then(|| {
            before_model_manifest
                .as_ref()
                .map(|_| backup_dir.join(MODEL_ACQUISITION_MANIFEST_NAME))
        })
        .flatten();
    if let (Some(path), Some(file)) = (&worker_backup, &before_worker) {
        write_atomic(path, "ncm-worker-backup", &file.bytes)?;
    }
    if let (Some(path), Some(file)) = (&manifest_backup, &before_manifest) {
        write_atomic(path, "ncm-manifest-backup", &file.bytes)?;
    }
    if let (Some(path), Some(file)) = (&model_manifest_backup, &before_model_manifest) {
        write_atomic(path, "ncm-model-manifest-backup", &file.bytes)?;
    }
    let after_observer = MemoryProviderNcmObserverV1::Disabled {};
    let after_document = observer_document(&after_observer)?;
    let mut journal = NcmControlJournalV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id: operation_id.clone(),
        operation: NcmControlOperation::Uninstall,
        phase: NcmJournalPhase::Prepared,
        profile_id: resolved.profile_id.as_str().to_owned(),
        project_id: resolved.project_id.as_str().to_owned(),
        worker_path: worker_binary.clone(),
        manifest_path: manifest_path.clone(),
        model_manifest_path: model_manifest_path.clone(),
        state_root: Some(state_root.clone()),
        before_configuration_revision: before_configuration_revision.to_string(),
        before_document,
        after_document,
        before_worker_digest: before_worker.as_ref().map(|file| file.digest.clone()),
        before_manifest_digest: before_manifest.as_ref().map(|file| file.digest.clone()),
        before_model_manifest_digest: before_model_manifest
            .as_ref()
            .map(|file| file.digest.clone()),
        after_worker_digest: None,
        after_manifest_digest: None,
        after_model_manifest_digest: None,
        before_worker_backup: worker_backup,
        before_manifest_backup: manifest_backup,
        before_model_manifest_backup: model_manifest_backup,
    };
    write_journal(&paths, &journal)?;
    let configuration_receipt = match set_observer_if_unchanged(
        &resolved,
        &journal.before_document,
        Some(&journal.before_configuration_revision),
        &after_observer,
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Err(recovery_error) = recover_journal(&resolved, &paths, false, false).await {
                return Err(config_error(format!(
                    "NCM configuration failed: {error}; automatic recovery failed: {recovery_error}"
                )));
            }
            return Err(error);
        }
    };
    journal.phase = NcmJournalPhase::Configured;
    write_journal(&paths, &journal)?;
    if control_owned && !daemon_profile_has_live_owner(&paths)? {
        // Verify the complete bundle before deleting any member. A missing or
        // tampered companion therefore leaves the whole directory available
        // for repair instead of causing a partial uninstall.
        let _ = remove_control_worker_bundle(
            &paths,
            &worker_binary,
            &manifest_path,
            &model_manifest_path,
            journal.before_worker_digest.as_deref(),
            journal.before_manifest_digest.as_deref(),
            journal.before_model_manifest_digest.as_deref(),
        )?;
    }
    cleanup_orphaned_control_workers(&paths, resolved.project_id.as_str(), &[&worker_binary])?;
    cleanup_uninstall_backups(&paths, &journal)?;
    let receipt = NcmControlReceiptV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id,
        operation: NcmControlOperation::Uninstall,
        outcome: "committed",
        profile_id: resolved.profile_id.as_str().to_owned(),
        project_id: resolved.project_id.as_str().to_owned(),
        worker_path: Some(worker_binary),
        state_root: Some(state_root),
        worker_sha256: journal.before_worker_digest.clone(),
        manifest_sha256: journal.before_manifest_digest.clone(),
        model_manifest_sha256: journal.before_model_manifest_digest.clone(),
        model_state: "preserved",
        native_state: "preserved",
        recall_routing: "preserved",
        configuration_receipt: configuration_receipt
            .as_ref()
            .map(|effect| effect.request_id.as_str().to_owned()),
        created_at_unix: now_unix(),
    };
    let receipt_path = write_receipt(&paths, &receipt)?;
    remove_journal(&paths)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt)
                .map_err(|error| config_error(error.to_string()))?
        );
    } else {
        println!(
            "NCM uninstalled; model state preserved; receipt {}",
            receipt_path.display()
        );
        tracedecay_cli_configuration_receipt(configuration_receipt.as_ref());
    }
    Ok(())
}

async fn handle_recover(scope: NcmScopeArgs, json: bool) -> Result<()> {
    let resolved = resolve_scope(scope).await?;
    let (_profile_root, paths) = control_paths(true)?;
    let receipt = if read_journal(&paths)?.is_some() {
        recover_journal(&resolved, &paths, true, json).await?
    } else {
        let (_current_document, observer) = read_observer(&resolved.project_path).await?;
        let MemoryProviderNcmObserverV1::Enabled {
            worker_binary,
            state_root,
        } = observer
        else {
            return Err(config_error(format!(
                "no pending NCM control journal or model lifecycle journal at {}",
                paths.journal.display()
            )));
        };
        require_absolute_path(&state_root, "state root")?;
        reject_symlink_components(&state_root, "state root")?;
        if !model_lifecycle_journal_present(&state_root)? {
            return Err(config_error(format!(
                "no pending NCM control journal or model lifecycle journal at {}",
                paths.journal.display()
            )));
        }
        if daemon_profile_has_live_owner(&paths)? {
            return Err(config_error(
                "NCM model lifecycle recovery is blocked while the daemon owns the profile",
            ));
        }
        recover_pending_model_lifecycle(&state_root)?;
        let receipt = NcmControlReceiptV1 {
            schema_version: CONTROL_SCHEMA_VERSION,
            operation_id: new_operation_id(
                resolved.profile_id.as_str(),
                resolved.project_id.as_str(),
                NcmControlOperation::Recover,
            ),
            operation: NcmControlOperation::Recover,
            outcome: "recovered",
            profile_id: resolved.profile_id.as_str().to_owned(),
            project_id: resolved.project_id.as_str().to_owned(),
            worker_path: Some(worker_binary),
            state_root: Some(state_root),
            worker_sha256: None,
            manifest_sha256: None,
            model_manifest_sha256: None,
            model_state: "preserved",
            native_state: "preserved",
            recall_routing: "preserved",
            configuration_receipt: None,
            created_at_unix: now_unix(),
        };
        let receipt_path = write_receipt(&paths, &receipt)?;
        if json {
            let output = String::from_utf8(
                required_regular_snapshot(&receipt_path, 1024 * 1024, "control receipt")?.bytes,
            )
            .map_err(|error| config_error(format!("invalid UTF-8 NCM control receipt: {error}")))?;
            println!("{output}");
        }
        receipt_path
    };
    if !json {
        println!("NCM recovery committed; receipt {}", receipt.display());
    }
    Ok(())
}

async fn recover_journal(
    resolved: &crate::commands::ResolvedCliScope,
    paths: &ControlPaths,
    emit: bool,
    json: bool,
) -> Result<PathBuf> {
    let journal = read_journal(paths)?
        .ok_or_else(|| config_error("NCM control journal disappeared during recovery"))?;
    validate_journal(&journal, paths)?;
    if journal.profile_id != resolved.profile_id.as_str()
        || journal.project_id != resolved.project_id.as_str()
    {
        return Err(config_error(
            "NCM control journal belongs to another profile or project",
        ));
    }
    let (_current_document, current_observer) = read_observer(&resolved.project_path).await?;
    let current_document = observer_document(&current_observer)?;
    let before_observer = decode_observer_document(&journal.before_document)?;
    let before_document = observer_document(&before_observer)?;
    let after_observer = decode_observer_document(&journal.after_document)?;
    let after_document = observer_document(&after_observer)?;
    validate_journal_document_binding(&journal, &before_observer, &after_observer)?;
    let current_digest = sha256_hex(current_document.as_bytes());
    let before_digest = sha256_hex(before_document.as_bytes());
    let after_digest = sha256_hex(after_document.as_bytes());
    if current_digest != before_digest && current_digest != after_digest {
        return Err(config_error(
            "NCM recovery refused: configuration changed outside the pending journal",
        ));
    }
    let current_is_before = current_digest == before_digest;
    let current_is_after = current_digest == after_digest;
    let uninstall_state_root_is_safe = !matches!(journal.operation, NcmControlOperation::Uninstall)
        || journal.state_root.as_deref().is_some_and(|state_root| {
            reject_symlink_components(state_root, "NCM control state root").is_ok()
        });
    // Establish that this journal still owns the current configuration before
    // touching the runtime model journal. A stale or cross-scope recovery must
    // be a read-only refusal, including when model recovery is also pending.
    if let Some(state_root) = &journal.state_root
        && (!matches!(journal.operation, NcmControlOperation::Uninstall)
            || (is_control_worker_path(paths, &journal.worker_path)
                && uninstall_state_root_is_safe))
    {
        reject_symlink_components(state_root, "NCM control state root")?;
        if matches!(journal.operation, NcmControlOperation::Uninstall) {
            // A failed model recovery must not force the operator to keep an
            // NCM worker enabled. Leave model state and its journal untouched
            // while the guarded disable transaction finishes.
            if !daemon_profile_has_live_owner(paths)? {
                let _ = recover_pending_model_lifecycle(state_root);
            }
        } else {
            if model_lifecycle_journal_present(state_root)? && daemon_profile_has_live_owner(paths)?
            {
                return Err(config_error(
                    "NCM model lifecycle recovery is blocked while the daemon owns the profile",
                ));
            }
            recover_pending_model_lifecycle(state_root)?;
        }
    }
    let configured_phase = matches!(journal.phase, NcmJournalPhase::Configured);
    let mut finalized = false;
    match journal.operation {
        NcmControlOperation::Install | NcmControlOperation::Update => {
            if configured_phase && current_is_before {
                return Err(config_error(
                    "NCM recovery refused: configured journal does not contain its committed configuration",
                ));
            }
            if current_is_after && configured_phase {
                require_guarded(
                    &journal.worker_path,
                    journal.after_worker_digest.as_deref(),
                    "staged worker",
                )?;
                require_guarded(
                    &journal.manifest_path,
                    journal.after_manifest_digest.as_deref(),
                    "staged worker manifest",
                )?;
                require_guarded(
                    &journal.model_manifest_path,
                    journal.after_model_manifest_digest.as_deref(),
                    "staged model acquisition manifest",
                )?;
                if matches!(journal.operation, NcmControlOperation::Update) {
                    cleanup_previous_control_worker(&before_observer, &journal, paths)?;
                }
                finalized = true;
            } else if current_is_before || current_is_after {
                verify_guarded(
                    &journal.worker_path,
                    journal.after_worker_digest.as_deref(),
                    "staged worker",
                )?;
                verify_guarded(
                    &journal.manifest_path,
                    journal.after_manifest_digest.as_deref(),
                    "staged worker manifest",
                )?;
                verify_guarded(
                    &journal.model_manifest_path,
                    journal.after_model_manifest_digest.as_deref(),
                    "staged model acquisition manifest",
                )?;
                let can_restore_before = !current_is_after
                    || (!daemon_profile_has_live_owner(paths)?
                        && before_observer_bundle_is_available(&before_observer, &journal, paths));
                if current_is_after && !can_restore_before {
                    // The old update target is no longer a safe rollback
                    // destination. Keep the verified replacement bound to the
                    // current configuration rather than resurrecting a path
                    // that may point at deleted or tampered bytes.
                    require_guarded(
                        &journal.worker_path,
                        journal.after_worker_digest.as_deref(),
                        "staged worker",
                    )?;
                    require_guarded(
                        &journal.manifest_path,
                        journal.after_manifest_digest.as_deref(),
                        "staged worker manifest",
                    )?;
                    require_guarded(
                        &journal.model_manifest_path,
                        journal.after_model_manifest_digest.as_deref(),
                        "staged model acquisition manifest",
                    )?;
                    if matches!(journal.operation, NcmControlOperation::Update) {
                        cleanup_previous_control_worker(&before_observer, &journal, paths)?;
                    }
                    finalized = true;
                } else {
                    remove_guarded(
                        &journal.worker_path,
                        journal.after_worker_digest.as_deref(),
                        "staged worker",
                    )?;
                    remove_guarded(
                        &journal.manifest_path,
                        journal.after_manifest_digest.as_deref(),
                        "staged worker manifest",
                    )?;
                    remove_guarded(
                        &journal.model_manifest_path,
                        journal.after_model_manifest_digest.as_deref(),
                        "staged model acquisition manifest",
                    )?;
                    if let Some(parent) = journal.worker_path.parent() {
                        remove_empty_directory(parent, "staged NCM worker")?;
                    }
                    if current_is_after {
                        let _ = set_observer_if_unchanged(
                            resolved,
                            &current_document,
                            None,
                            &before_observer,
                        )
                        .await?;
                    }
                }
            }
        }
        NcmControlOperation::Uninstall => {
            if configured_phase && current_is_before {
                return Err(config_error(
                    "NCM recovery refused: configured journal does not contain its committed configuration",
                ));
            }
            if current_is_after && configured_phase {
                if !uninstall_state_root_is_safe
                    || !is_control_worker_path(paths, &journal.worker_path)
                    || daemon_profile_has_live_owner(paths)?
                {
                    finalized = true;
                    // External workers and live daemon generations are
                    // disable-only cases. Their bytes remain under their
                    // owner's control while the committed disabled config is
                    // finalized.
                } else {
                    let _ = remove_control_worker_bundle(
                        paths,
                        &journal.worker_path,
                        &journal.manifest_path,
                        &journal.model_manifest_path,
                        journal.before_worker_digest.as_deref(),
                        journal.before_manifest_digest.as_deref(),
                        journal.before_model_manifest_digest.as_deref(),
                    )?;
                    finalized = true;
                }
            } else if current_is_after {
                if !uninstall_state_root_is_safe
                    || !is_control_worker_path(paths, &journal.worker_path)
                {
                    // External workers are always disable-only. The CLI does
                    // not own their bytes and must never resurrect a config
                    // that points back to an owner-managed path.
                    finalized = true;
                } else {
                    // A crash after the disable CAS may leave the old bundle
                    // partially written, or an operator may have tampered
                    // with one of its sidecars before recovery. Treat those
                    // cases as a successful guarded disable. Restoring the
                    // enabled document is allowed only after every current
                    // artifact and every backup has been proved unchanged;
                    // this keeps recovery from resurrecting a dangling or
                    // damaged worker target.
                    let current_bundle_is_safe = control_artifacts_are_safe(
                        paths,
                        &journal.worker_path,
                        &journal.manifest_path,
                        &journal.model_manifest_path,
                    ) && guarded_artifact_matches(
                        &journal.worker_path,
                        journal.before_worker_digest.as_deref(),
                        "worker",
                    ) && guarded_artifact_matches(
                        &journal.manifest_path,
                        journal.before_manifest_digest.as_deref(),
                        "worker manifest",
                    ) && guarded_artifact_matches(
                        &journal.model_manifest_path,
                        journal.before_model_manifest_digest.as_deref(),
                        "model acquisition manifest",
                    );
                    let backups_are_safe =
                        journal.before_worker_backup.as_deref().is_some_and(|path| {
                            guarded_artifact_matches(
                                path,
                                journal.before_worker_digest.as_deref(),
                                "worker backup",
                            )
                        }) && journal
                            .before_manifest_backup
                            .as_deref()
                            .is_some_and(|path| {
                                guarded_artifact_matches(
                                    path,
                                    journal.before_manifest_digest.as_deref(),
                                    "worker manifest backup",
                                )
                            })
                            && journal.before_model_manifest_backup.as_deref().is_some_and(
                                |path| {
                                    guarded_artifact_matches(
                                        path,
                                        journal.before_model_manifest_digest.as_deref(),
                                        "model acquisition manifest backup",
                                    )
                                },
                            );
                    let can_restore_before = !daemon_profile_has_live_owner(paths)?
                        && before_observer_bundle_is_available(&before_observer, &journal, paths)
                        && current_bundle_is_safe
                        && backups_are_safe;
                    if can_restore_before {
                        require_guarded(
                            &journal.worker_path,
                            journal.before_worker_digest.as_deref(),
                            "worker",
                        )?;
                        require_guarded(
                            &journal.manifest_path,
                            journal.before_manifest_digest.as_deref(),
                            "worker manifest",
                        )?;
                        require_guarded(
                            &journal.model_manifest_path,
                            journal.before_model_manifest_digest.as_deref(),
                            "model acquisition manifest",
                        )?;
                        require_guarded(
                            journal.before_worker_backup.as_deref().ok_or_else(|| {
                                config_error("NCM worker backup disappeared during recovery")
                            })?,
                            journal.before_worker_digest.as_deref(),
                            "worker backup",
                        )?;
                        require_guarded(
                            journal.before_manifest_backup.as_deref().ok_or_else(|| {
                                config_error(
                                    "NCM worker manifest backup disappeared during recovery",
                                )
                            })?,
                            journal.before_manifest_digest.as_deref(),
                            "worker manifest backup",
                        )?;
                        require_guarded(
                            journal
                                .before_model_manifest_backup
                                .as_deref()
                                .ok_or_else(|| config_error("NCM model acquisition manifest backup disappeared during recovery"))?,
                            journal.before_model_manifest_digest.as_deref(),
                            "model acquisition manifest backup",
                        )?;
                        if let Some(backup) = &journal.before_worker_backup
                            && let Some(file) =
                                read_regular_snapshot(backup, MAX_WORKER_BYTES, "worker backup")?
                        {
                            write_atomic(&journal.worker_path, "ncm-worker-recovery", &file.bytes)?;
                            set_worker_mode(&journal.worker_path)?;
                        }
                        if let Some(backup) = &journal.before_manifest_backup
                            && let Some(file) = read_regular_snapshot(
                                backup,
                                MAX_MANIFEST_BYTES,
                                "manifest backup",
                            )?
                        {
                            write_atomic(
                                &journal.manifest_path,
                                "ncm-manifest-recovery",
                                &file.bytes,
                            )?;
                        }
                        if let Some(backup) = &journal.before_model_manifest_backup
                            && let Some(file) = read_regular_snapshot(
                                backup,
                                MAX_MANIFEST_BYTES,
                                "model acquisition manifest backup",
                            )?
                        {
                            write_atomic(
                                &journal.model_manifest_path,
                                "ncm-model-manifest-recovery",
                                &file.bytes,
                            )?;
                        }
                        let _ = set_observer_if_unchanged(
                            resolved,
                            &current_document,
                            None,
                            &before_observer,
                        )
                        .await?;
                    } else {
                        // Disable-only recovery: the old worker cannot be
                        // proved to be a complete, unowned bundle, so leave
                        // the disabled configuration in place and finalize
                        // without restoring a possibly dangling target.
                        finalized = true;
                    }
                }
            }
        }
        NcmControlOperation::Recover => {
            return Err(config_error("nested NCM recovery journal is invalid"));
        }
    }
    if matches!(journal.operation, NcmControlOperation::Uninstall) {
        cleanup_uninstall_backups(paths, &journal)?;
        let protected_workers = if current_is_before {
            match &before_observer {
                MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } => {
                    vec![worker_binary.as_path()]
                }
                MemoryProviderNcmObserverV1::Disabled {} => Vec::new(),
            }
        } else {
            Vec::new()
        };
        cleanup_orphaned_control_workers(paths, journal.project_id.as_str(), &protected_workers)?;
    } else {
        let before_worker = match &before_observer {
            MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } => {
                Some(worker_binary.as_path())
            }
            MemoryProviderNcmObserverV1::Disabled {} => None,
        };
        let mut protected_workers = vec![journal.worker_path.as_path()];
        if let Some(before_worker) = before_worker {
            protected_workers.push(before_worker);
        }
        cleanup_orphaned_control_workers(paths, journal.project_id.as_str(), &protected_workers)?;
    }
    let (operation, outcome, worker_sha256, manifest_sha256, model_manifest_sha256) = if finalized {
        match journal.operation {
            NcmControlOperation::Install | NcmControlOperation::Update => (
                journal.operation,
                "committed",
                journal.after_worker_digest.clone(),
                journal.after_manifest_digest.clone(),
                journal.after_model_manifest_digest.clone(),
            ),
            NcmControlOperation::Uninstall => (
                journal.operation,
                "committed",
                journal.before_worker_digest.clone(),
                journal.before_manifest_digest.clone(),
                journal.before_model_manifest_digest.clone(),
            ),
            NcmControlOperation::Recover => {
                return Err(config_error("nested NCM recovery journal is invalid"));
            }
        }
    } else {
        (
            NcmControlOperation::Recover,
            "recovered",
            journal.before_worker_digest.clone(),
            journal.before_manifest_digest.clone(),
            journal.before_model_manifest_digest.clone(),
        )
    };
    let receipt = NcmControlReceiptV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id: journal.operation_id.clone(),
        operation,
        outcome,
        profile_id: journal.profile_id,
        project_id: journal.project_id,
        worker_path: Some(journal.worker_path),
        state_root: journal.state_root,
        worker_sha256,
        manifest_sha256,
        model_manifest_sha256,
        model_state: "preserved",
        native_state: "preserved",
        recall_routing: "preserved",
        configuration_receipt: None,
        created_at_unix: now_unix(),
    };
    let path = write_receipt(paths, &receipt)?;
    remove_journal(paths)?;
    if emit && json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt)
                .map_err(|error| config_error(error.to_string()))?
        );
    }
    Ok(path)
}

fn validate_journal_document_binding(
    journal: &NcmControlJournalV1,
    before_observer: &MemoryProviderNcmObserverV1,
    after_observer: &MemoryProviderNcmObserverV1,
) -> Result<()> {
    let journal_state_root = journal.state_root.as_ref();
    match journal.operation {
        NcmControlOperation::Install => {
            if !matches!(before_observer, MemoryProviderNcmObserverV1::Disabled {})
                || !observer_binds_worker_and_state(
                    after_observer,
                    &journal.worker_path,
                    journal_state_root,
                )
            {
                return Err(config_error(
                    "NCM recovery refused: install journal does not bind its configuration documents",
                ));
            }
        }
        NcmControlOperation::Update => {
            let before_worker_is_distinct = match before_observer {
                MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } => {
                    worker_binary != &journal.worker_path
                }
                MemoryProviderNcmObserverV1::Disabled {} => false,
            };
            if !observer_binds_worker_and_state(
                after_observer,
                &journal.worker_path,
                journal_state_root,
            ) || !same_state_root(before_observer, after_observer)
                || !before_worker_is_distinct
            {
                return Err(config_error(
                    "NCM recovery refused: update journal changes its worker or state-root binding",
                ));
            }
        }
        NcmControlOperation::Uninstall => {
            if !observer_binds_worker_and_state(
                before_observer,
                &journal.worker_path,
                journal_state_root,
            ) || !matches!(after_observer, MemoryProviderNcmObserverV1::Disabled {})
            {
                return Err(config_error(
                    "NCM recovery refused: uninstall journal does not bind its configuration documents",
                ));
            }
        }
        NcmControlOperation::Recover => {
            return Err(config_error("nested NCM recovery journal is invalid"));
        }
    }
    Ok(())
}

fn observer_binds_worker_and_state(
    observer: &MemoryProviderNcmObserverV1,
    worker_path: &Path,
    state_root: Option<&PathBuf>,
) -> bool {
    let MemoryProviderNcmObserverV1::Enabled {
        worker_binary,
        state_root: observer_state_root,
    } = observer
    else {
        return false;
    };
    worker_binary == worker_path && Some(observer_state_root) == state_root
}

fn same_state_root(
    before_observer: &MemoryProviderNcmObserverV1,
    after_observer: &MemoryProviderNcmObserverV1,
) -> bool {
    match (before_observer, after_observer) {
        (
            MemoryProviderNcmObserverV1::Enabled {
                state_root: before, ..
            },
            MemoryProviderNcmObserverV1::Enabled {
                state_root: after, ..
            },
        ) => before == after,
        _ => false,
    }
}

async fn read_observer(project_path: &Path) -> Result<(String, MemoryProviderNcmObserverV1)> {
    let value = crate::commands::current_project_setting(
        project_path,
        MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
    )
    .await?;
    let ConfigurationValueV1::Text(document) = value else {
        return Err(config_error(format!(
            "configuration setting {MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY} is not text"
        )));
    };
    let observer = decode_observer_document(&document)?;
    Ok((document, observer))
}

fn decode_observer_document(document: &str) -> Result<MemoryProviderNcmObserverV1> {
    let observer: MemoryProviderNcmObserverV1 = serde_json::from_str(document)
        .map_err(|error| config_error(format!("invalid NCM observer document: {error}")))?;
    observer
        .validate()
        .map_err(|error| config_error(format!("invalid NCM observer document: {error}")))?;
    Ok(observer)
}

fn observer_document(observer: &MemoryProviderNcmObserverV1) -> Result<String> {
    let bytes = tracedecay_domain::canonical_json_bytes(observer)
        .map_err(|error| config_error(format!("encode NCM observer document: {error}")))?;
    String::from_utf8(bytes)
        .map_err(|error| config_error(format!("NCM observer document is not UTF-8: {error}")))
}

async fn set_observer_if_unchanged(
    resolved: &crate::commands::ResolvedCliScope,
    expected_document: &str,
    expected_revision: Option<&str>,
    observer: &MemoryProviderNcmObserverV1,
) -> Result<Option<tracedecay_contracts::EffectReceipt>> {
    let observed_revision =
        crate::commands::current_configuration_revision(&resolved.project_path).await?;
    let (_current_document, current) = read_observer(&resolved.project_path).await?;
    let current_document = observer_document(&current)?;
    if current_document != expected_document {
        return Err(config_error(
            "NCM configuration changed during the pending control transaction",
        ));
    }
    let confirmed_revision =
        crate::commands::current_configuration_revision(&resolved.project_path).await?;
    if observed_revision != confirmed_revision {
        return Err(config_error(
            "NCM configuration changed during the pending control transaction",
        ));
    }
    let expected_revision = match expected_revision {
        Some(expected_revision) => ConfigurationRevisionId::new(expected_revision.to_owned())
            .map_err(|error| config_error(error.to_string()))?,
        None => confirmed_revision.clone(),
    };
    if expected_revision != confirmed_revision {
        return Err(config_error(
            "NCM configuration changed during the pending control transaction",
        ));
    }
    if current == *observer {
        return Ok(None);
    }
    let value = observer_document(observer)?;
    let mutation = crate::commands::project_configuration_set(
        &resolved.project_id,
        MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
        ConfigurationValueV1::Text(value),
    )?;
    crate::commands::mutate_project_configuration(
        &resolved.project_path,
        &resolved.project_id,
        expected_revision,
        vec![mutation],
    )
    .await
}

fn remove_empty_directory(path: &Path, role: &str) -> Result<()> {
    reject_symlink_components(path, role)?;
    match fs::remove_dir(path) {
        Ok(()) => tracedecay_private_fs::framed_log::sync_parent_directory(
            path,
            DirectorySyncPolicy::Strict,
        )
        .map_err(|error| io_error("sync removed NCM directory", path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(&format!("remove {role} directory"), path, error)),
    }
}

fn remove_control_worker_bundle(
    paths: &ControlPaths,
    worker_path: &Path,
    manifest_path: &Path,
    model_manifest_path: &Path,
    worker_digest: Option<&str>,
    manifest_digest: Option<&str>,
    model_manifest_digest: Option<&str>,
) -> Result<bool> {
    if worker_digest.is_none() || manifest_digest.is_none() || model_manifest_digest.is_none() {
        return Ok(false);
    }
    if daemon_profile_has_live_owner(paths)? {
        // A daemon may have acquired its endpoint after the caller's initial
        // handoff probe. Keep the complete bundle until that live owner is
        // gone rather than racing its executable or model access.
        return Ok(false);
    }
    if !control_artifacts_are_safe(paths, worker_path, manifest_path, model_manifest_path) {
        return Ok(false);
    }
    if !control_bundle_has_only_expected_entries(worker_path)? {
        return Ok(false);
    }
    // A damaged bundle is still a valid disable/replace target, but none of
    // its members is safe to delete. Preflight every byte so ordinary tamper
    // becomes a clean no-op instead of surfacing an error after configuration
    // has already been disabled.
    if !guarded_artifact_matches(worker_path, worker_digest, "worker")
        || !guarded_artifact_matches(manifest_path, manifest_digest, "worker manifest")
        || !guarded_artifact_matches(
            model_manifest_path,
            model_manifest_digest,
            "model acquisition manifest",
        )
    {
        return Ok(false);
    }
    require_guarded(worker_path, worker_digest, "worker")?;
    require_guarded(manifest_path, manifest_digest, "worker manifest")?;
    require_guarded(
        model_manifest_path,
        model_manifest_digest,
        "model acquisition manifest",
    )?;
    remove_guarded(worker_path, worker_digest, "worker")?;
    remove_guarded(manifest_path, manifest_digest, "worker manifest")?;
    remove_guarded(
        model_manifest_path,
        model_manifest_digest,
        "model acquisition manifest",
    )?;
    if let Some(parent) = worker_path.parent() {
        remove_empty_directory(parent, "NCM worker")?;
    }
    Ok(true)
}

fn guarded_artifact_matches(path: &Path, expected_digest: Option<&str>, role: &str) -> bool {
    let Some(expected_digest) = expected_digest else {
        return false;
    };
    let max_bytes = if role.contains("manifest") {
        MAX_MANIFEST_BYTES
    } else {
        MAX_WORKER_BYTES
    };
    let Ok(Some(snapshot)) = read_regular_snapshot(path, max_bytes, role) else {
        return false;
    };
    snapshot.digest == expected_digest
        && (!role.contains("model acquisition manifest")
            || snapshot.bytes.as_slice() == TRUSTED_MODEL_ACQUISITION_MANIFEST)
}

fn control_bundle_has_only_expected_entries(worker_path: &Path) -> Result<bool> {
    let Some(parent) = worker_path.parent() else {
        return Ok(false);
    };
    reject_symlink_components(parent, "NCM worker bundle")?;
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error("list NCM worker bundle", parent, error)),
    };
    let expected = [
        std::ffi::OsStr::new(WORKER_NAME),
        std::ffi::OsStr::new(WORKER_MANIFEST_NAME),
        std::ffi::OsStr::new(MODEL_ACQUISITION_MANIFEST_NAME),
    ];
    let mut seen = [false; 3];
    for entry in entries {
        let entry = entry.map_err(|error| io_error("inspect NCM worker bundle", parent, error))?;
        let name = entry.file_name();
        let Some(index) = expected
            .iter()
            .position(|expected| *expected == name.as_os_str())
        else {
            return Ok(false);
        };
        if seen[index] {
            return Ok(false);
        }
        seen[index] = true;
    }
    Ok(seen.into_iter().all(|present| present))
}

/// Reclaims complete control-owned worker bundles left behind after an update
/// while the previous daemon generation still held them open. The daemon
/// endpoint is checked before scanning, and every candidate must still be a
/// complete, release-verified worker bundle before any member is removed.
fn cleanup_orphaned_control_workers(
    paths: &ControlPaths,
    project_id: &str,
    keep_workers: &[&Path],
) -> Result<()> {
    if daemon_profile_has_live_owner(paths)? {
        return Ok(());
    }
    let entries = match fs::read_dir(&paths.root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io_error("list NCM control receipts", &paths.root, error));
        }
    };
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let now = now_unix();
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("inspect NCM control receipt", &paths.root, error))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(RECEIPT_FILE_PREFIX) || !name.ends_with(RECEIPT_FILE_SUFFIX) {
            continue;
        }
        let Some(file) = (match read_regular_snapshot(&path, 1024 * 1024, "control receipt") {
            Ok(file) => file,
            Err(_) => continue,
        }) else {
            continue;
        };
        let Ok(receipt) = serde_json::from_slice::<NcmReceiptArtifactIndex>(&file.bytes) else {
            // Receipt cleanup is advisory. A malformed or tampered receipt
            // must not prevent a guarded disable or replacement transaction.
            continue;
        };
        if receipt.project_id != project_id {
            continue;
        }
        if receipt.created_at_unix > now {
            continue;
        }
        let Some(worker_path) = receipt.worker_path else {
            continue;
        };
        if keep_workers
            .iter()
            .any(|worker| worker.parent() == worker_path.parent())
        {
            continue;
        }
        if !is_control_worker_path(paths, &worker_path) || !seen.insert(worker_path.clone()) {
            continue;
        }
        let (Some(worker_digest), Some(manifest_digest), Some(model_manifest_digest)) = (
            receipt.worker_sha256,
            receipt.manifest_sha256,
            receipt.model_manifest_sha256,
        ) else {
            continue;
        };
        candidates.push((
            worker_path,
            worker_digest,
            manifest_digest,
            model_manifest_digest,
        ));
    }
    for (worker, worker_digest, manifest_digest, model_manifest_digest) in candidates {
        let Some(parent) = worker.parent() else {
            continue;
        };
        let manifest = parent.join(WORKER_MANIFEST_NAME);
        let model_manifest = parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        let (Some(worker_file), Some(manifest_file), Some(model_manifest_file)) = (
            best_effort_snapshot(&worker, MAX_WORKER_BYTES, "orphaned worker"),
            best_effort_snapshot(&manifest, MAX_MANIFEST_BYTES, "orphaned worker manifest"),
            best_effort_snapshot(
                &model_manifest,
                MAX_MANIFEST_BYTES,
                "orphaned model acquisition manifest",
            ),
        ) else {
            continue;
        };
        if worker_file.digest != worker_digest
            || manifest_file.digest != manifest_digest
            || model_manifest_file.digest != model_manifest_digest
            || model_manifest_file.bytes.as_slice() != TRUSTED_MODEL_ACQUISITION_MANIFEST
        {
            continue;
        }
        // Re-run the release worker verifier so a bundle without a journal
        // still has an authenticated identity before cleanup. A damaged
        // bundle remains available for explicit repair.
        let Ok(artifact) = stage_verified_worker_binary(&worker) else {
            continue;
        };
        if artifact.sha256() != worker_digest.as_str() {
            continue;
        }
        let _ = remove_control_worker_bundle(
            paths,
            &worker,
            &manifest,
            &model_manifest,
            Some(&worker_digest),
            Some(&manifest_digest),
            Some(&model_manifest_digest),
        );
    }
    Ok(())
}

fn cleanup_uninstall_backups(paths: &ControlPaths, journal: &NcmControlJournalV1) -> Result<()> {
    let backups = [
        (
            &journal.before_worker_backup,
            journal.before_worker_digest.as_deref(),
            "worker backup",
        ),
        (
            &journal.before_manifest_backup,
            journal.before_manifest_digest.as_deref(),
            "worker manifest backup",
        ),
        (
            &journal.before_model_manifest_backup,
            journal.before_model_manifest_digest.as_deref(),
            "model acquisition manifest backup",
        ),
    ];
    for (path, digest, role) in backups {
        if let Some(path) = path
            && guarded_artifact_matches(path, digest, role)
        {
            remove_guarded(path, digest, role)?;
        }
    }
    let backup_dir = paths.backup_root.join(&journal.operation_id);
    reject_symlink_components(&backup_dir, "NCM uninstall backup")?;
    let has_entries = match fs::read_dir(&backup_dir) {
        Ok(mut entries) => entries
            .next()
            .transpose()
            .map_err(|error| io_error("inspect NCM uninstall backup", &backup_dir, error))?
            .is_some(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(io_error("inspect NCM uninstall backup", &backup_dir, error)),
    };
    if has_entries {
        return Ok(());
    }
    remove_empty_directory(&backup_dir, "NCM uninstall backup")
}

fn cleanup_previous_control_worker(
    before_observer: &MemoryProviderNcmObserverV1,
    journal: &NcmControlJournalV1,
    paths: &ControlPaths,
) -> Result<()> {
    let MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } = before_observer else {
        return Ok(());
    };
    if !is_control_worker_path(paths, worker_binary) {
        return Ok(());
    }
    if daemon_profile_has_live_owner(paths)? {
        // The daemon's worker owner may still hold an open executable or model
        // state. Leave the old bundle in place until that owner generation is
        // gone; the configuration already points at the replacement.
        return Ok(());
    }
    if journal.before_worker_digest.is_none()
        || journal.before_manifest_digest.is_none()
        || journal.before_model_manifest_digest.is_none()
    {
        // A damaged installation is replaceable, but its bytes are not safe
        // to delete without a complete pre-journal snapshot.
        return Ok(());
    }
    let previous_parent = worker_binary
        .parent()
        .ok_or_else(|| config_error("previous NCM worker path has no parent"))?;
    let new_parent = journal
        .worker_path
        .parent()
        .ok_or_else(|| config_error("staged NCM worker path has no parent"))?;
    if previous_parent == new_parent {
        // A retry after a committed update reuses the deterministic target.
        // The configured worker is already the staged identity, so there is
        // no previous generation to clean and deleting this directory would
        // remove the live target itself.
        if worker_binary == &journal.worker_path {
            return Ok(());
        }
        return Err(config_error(
            "NCM recovery refused: previous and staged workers share a directory",
        ));
    }
    if previous_parent.parent() != Some(paths.worker_root.as_path())
        || worker_binary.file_name() != Some(std::ffi::OsStr::new(WORKER_NAME))
    {
        return Err(config_error(
            "NCM recovery refused: previous worker path is outside the control worker root",
        ));
    }
    let manifest_path = previous_parent.join(WORKER_MANIFEST_NAME);
    let model_manifest_path = previous_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
    if !control_bundle_has_only_expected_entries(worker_binary)? {
        return Ok(());
    }
    if daemon_profile_has_live_owner(paths)? {
        return Ok(());
    }

    // Read all three artifacts before removing any of them so a tampered sidecar
    // leaves the entire previous worker directory available for inspection. A
    // damaged previous install remains replaceable; its guarded cleanup is a
    // no-op and the committed replacement stays authoritative.
    if !guarded_artifact_matches(
        worker_binary,
        journal.before_worker_digest.as_deref(),
        "previous worker",
    ) || !guarded_artifact_matches(
        &manifest_path,
        journal.before_manifest_digest.as_deref(),
        "previous worker manifest",
    ) || !guarded_artifact_matches(
        &model_manifest_path,
        journal.before_model_manifest_digest.as_deref(),
        "previous model acquisition manifest",
    ) {
        return Ok(());
    }
    require_guarded(
        worker_binary,
        journal.before_worker_digest.as_deref(),
        "previous worker",
    )?;
    require_guarded(
        &manifest_path,
        journal.before_manifest_digest.as_deref(),
        "previous worker manifest",
    )?;
    require_guarded(
        &model_manifest_path,
        journal.before_model_manifest_digest.as_deref(),
        "previous model acquisition manifest",
    )?;
    remove_guarded(
        worker_binary,
        journal.before_worker_digest.as_deref(),
        "previous worker",
    )?;
    remove_guarded(
        &manifest_path,
        journal.before_manifest_digest.as_deref(),
        "previous worker manifest",
    )?;
    remove_guarded(
        &model_manifest_path,
        journal.before_model_manifest_digest.as_deref(),
        "previous model acquisition manifest",
    )?;
    remove_empty_directory(previous_parent, "previous NCM worker")
}

fn publish_worker(
    worker_path: &Path,
    manifest_bytes: &[u8],
    model_manifest_bytes: &[u8],
    staged_worker: &Path,
) -> Result<()> {
    if model_manifest_bytes != TRUSTED_MODEL_ACQUISITION_MANIFEST {
        return Err(config_error(
            "NCM model acquisition manifest failed trusted release verification before publication",
        ));
    }
    let parent = worker_path
        .parent()
        .ok_or_else(|| config_error("staged worker path has no parent"))?;
    reject_symlink_components(parent, "staged worker directory")?;
    fs::create_dir_all(parent)
        .map_err(|error| io_error("create staged worker directory", parent, error))?;
    tracedecay_private_fs::make_private_directory(parent)
        .map_err(|error| io_error("secure staged worker directory", parent, error))?;
    tracedecay_private_fs::framed_log::sync_parent_directory(parent, DirectorySyncPolicy::Strict)
        .map_err(|error| io_error("sync staged worker directory parent", parent, error))?;
    let worker_bytes =
        read_regular_snapshot(staged_worker, MAX_WORKER_BYTES, "verified worker")?
            .ok_or_else(|| config_error("verified worker disappeared before publication"))?;
    write_atomic(worker_path, "ncm-worker", &worker_bytes.bytes)?;
    set_worker_mode(worker_path)?;
    let manifest_path = worker_path
        .parent()
        .map(|parent| parent.join(WORKER_MANIFEST_NAME))
        .ok_or_else(|| config_error("staged worker path has no parent"))?;
    write_atomic(&manifest_path, "ncm-worker-manifest", manifest_bytes)?;
    let model_manifest_path = worker_path
        .parent()
        .map(|parent| parent.join(MODEL_ACQUISITION_MANIFEST_NAME))
        .ok_or_else(|| config_error("staged worker path has no parent"))?;
    write_atomic(
        &model_manifest_path,
        "ncm-model-acquisition-manifest",
        model_manifest_bytes,
    )
}

fn verify_guarded(path: &Path, expected_digest: Option<&str>, role: &str) -> Result<()> {
    let Some(expected_digest) = expected_digest else {
        return Ok(());
    };
    let Some(current) = read_regular_snapshot(
        path,
        if role.contains("manifest") {
            MAX_MANIFEST_BYTES
        } else {
            MAX_WORKER_BYTES
        },
        role,
    )?
    else {
        return Ok(());
    };
    if current.digest != expected_digest {
        return Err(config_error(format!(
            "NCM recovery refused: {role} bytes changed outside the pending journal (expected {expected_digest}, got {})",
            current.digest
        )));
    }
    ensure_trusted_model_manifest(path, &current.bytes, role)?;
    Ok(())
}

fn require_guarded(path: &Path, expected_digest: Option<&str>, role: &str) -> Result<()> {
    let Some(expected_digest) = expected_digest else {
        return Err(config_error(format!(
            "NCM recovery refused: {role} has no committed digest"
        )));
    };
    let Some(current) = read_regular_snapshot(
        path,
        if role.contains("manifest") {
            MAX_MANIFEST_BYTES
        } else {
            MAX_WORKER_BYTES
        },
        role,
    )?
    else {
        return Err(config_error(format!(
            "NCM recovery refused: committed {role} is missing"
        )));
    };
    if current.digest != expected_digest {
        return Err(config_error(format!(
            "NCM recovery refused: committed {role} bytes changed outside the pending journal (expected {expected_digest}, got {})",
            current.digest
        )));
    }
    ensure_trusted_model_manifest(path, &current.bytes, role)?;
    Ok(())
}

fn remove_guarded(path: &Path, expected_digest: Option<&str>, role: &str) -> Result<()> {
    let Some(expected_digest) = expected_digest else {
        return Ok(());
    };
    let Some(current) = read_regular_snapshot(
        path,
        if role.contains("manifest") {
            MAX_MANIFEST_BYTES
        } else {
            MAX_WORKER_BYTES
        },
        role,
    )?
    else {
        return Ok(());
    };
    if current.digest != expected_digest {
        return Err(config_error(format!(
            "NCM recovery refused: {role} digest changed (expected {expected_digest}, got {})",
            current.digest
        )));
    }
    ensure_trusted_model_manifest(path, &current.bytes, role)?;
    let digest = expected_digest.to_owned();
    remove_conditionally(
        path,
        || {},
        |rollback| {
            let bytes = fs::read(rollback)?;
            Ok(sha256_hex(&bytes) == digest)
        },
        DirectorySyncPolicy::Strict,
    )
    .map_err(|error| io_error("remove NCM control artifact", path, error))
}

fn read_regular_snapshot(path: &Path, max_bytes: u64, role: &str) -> Result<Option<FileSnapshot>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("inspect NCM artifact", path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(config_error(format!(
            "NCM {role} path is not a regular file: {}",
            path.display()
        )));
    }
    reject_symlink_components(path, role)?;
    if metadata.len() > max_bytes {
        return Err(config_error(format!(
            "NCM {role} exceeds the bounded size of {max_bytes} bytes: {}",
            path.display()
        )));
    }
    let file = tracedecay_private_fs::framed_log::open_regular_read_no_follow(path)
        .map_err(|error| io_error("read NCM artifact", path, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read NCM artifact", path, error))?;
    if bytes.len() as u64 > max_bytes {
        return Err(config_error(format!(
            "NCM {role} exceeds the bounded size of {max_bytes} bytes: {}",
            path.display()
        )));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(config_error(format!(
            "NCM {role} changed while reading: {}",
            path.display()
        )));
    }
    let digest = sha256_hex(&bytes);
    Ok(Some(FileSnapshot { bytes, digest }))
}

fn required_regular_snapshot(path: &Path, max_bytes: u64, role: &str) -> Result<FileSnapshot> {
    read_regular_snapshot(path, max_bytes, role)?.ok_or_else(|| {
        config_error(format!(
            "NCM {role} is missing from the control-owned worker directory: {}",
            path.display()
        ))
    })
}

fn best_effort_snapshot(path: &Path, max_bytes: u64, role: &str) -> Option<FileSnapshot> {
    read_regular_snapshot(path, max_bytes, role).ok().flatten()
}

fn best_effort_previous_bundle_digests(
    paths: &ControlPaths,
    project_id: &str,
    worker_binary: &Path,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(parent) = worker_binary.parent() else {
        return (None, None, None);
    };
    let committed = committed_bundle_digests(paths, project_id, worker_binary);
    let worker = best_effort_snapshot(worker_binary, MAX_WORKER_BYTES, "configured worker");
    let manifest = best_effort_snapshot(
        &parent.join(WORKER_MANIFEST_NAME),
        MAX_MANIFEST_BYTES,
        "configured worker manifest",
    );
    let model_manifest = best_effort_snapshot(
        &parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
        MAX_MANIFEST_BYTES,
        "configured model acquisition manifest",
    )
    .filter(|file| file.bytes.as_slice() == TRUSTED_MODEL_ACQUISITION_MANIFEST);
    (
        worker
            .filter(|file| {
                committed
                    .as_ref()
                    .is_none_or(|bundle| bundle.0.as_deref() == Some(file.digest.as_str()))
            })
            .map(|file| file.digest),
        manifest
            .filter(|file| {
                committed
                    .as_ref()
                    .is_none_or(|bundle| bundle.1.as_deref() == Some(file.digest.as_str()))
            })
            .map(|file| file.digest),
        model_manifest
            .filter(|file| {
                committed
                    .as_ref()
                    .is_none_or(|bundle| bundle.2.as_deref() == Some(file.digest.as_str()))
            })
            .map(|file| file.digest),
    )
}

fn bundle_digests_match(
    worker_path: &Path,
    worker_digest: &str,
    manifest_digest: &str,
    model_manifest_digest: &str,
) -> bool {
    let Some(parent) = worker_path.parent() else {
        return false;
    };
    read_regular_snapshot(worker_path, MAX_WORKER_BYTES, "configured worker")
        .ok()
        .flatten()
        .is_some_and(|file| file.digest == worker_digest)
        && read_regular_snapshot(
            &parent.join(WORKER_MANIFEST_NAME),
            MAX_MANIFEST_BYTES,
            "configured worker manifest",
        )
        .ok()
        .flatten()
        .is_some_and(|file| file.digest == manifest_digest)
        && read_regular_snapshot(
            &parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
            MAX_MANIFEST_BYTES,
            "configured model acquisition manifest",
        )
        .ok()
        .flatten()
        .is_some_and(|file| file.digest == model_manifest_digest)
}

fn control_artifacts_are_safe(
    paths: &ControlPaths,
    worker_path: &Path,
    manifest_path: &Path,
    model_manifest_path: &Path,
) -> bool {
    is_control_worker_path(paths, worker_path)
        && manifest_path.parent() == worker_path.parent()
        && model_manifest_path.parent() == worker_path.parent()
        && manifest_path.file_name() == Some(std::ffi::OsStr::new(WORKER_MANIFEST_NAME))
        && model_manifest_path.file_name()
            == Some(std::ffi::OsStr::new(MODEL_ACQUISITION_MANIFEST_NAME))
        && reject_symlink_components(worker_path, "worker").is_ok()
        && reject_symlink_components(manifest_path, "worker manifest").is_ok()
        && reject_symlink_components(model_manifest_path, "model acquisition manifest").is_ok()
}

fn daemon_profile_has_live_owner(paths: &ControlPaths) -> Result<bool> {
    let profile_root = paths
        .root
        .parent()
        .ok_or_else(|| config_error("NCM control root has no profile parent"))?;
    let Some(record) = tracedecay_daemon_identity::authority::current_record(profile_root)
        .map_err(|error| config_error(format!("inspect NCM daemon ownership: {error}")))?
    else {
        return Ok(false);
    };
    Ok(daemon_endpoint_is_reachable(&record.endpoint) || daemon_authority_lock_held(profile_root))
}

/// The authority record is published before a daemon binds its transport. In
/// that startup interval the endpoint probe is necessarily negative, while
/// the profile lock already prevents another daemon generation from owning the
/// profile. Probe that same lock without waiting so cleanup cannot race the
/// daemon's worker handoff.
fn daemon_authority_lock_held(profile_root: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let lock_path =
            profile_root.join(tracedecay_runtime_core::storage::DAEMON_AUTHORITY_LOCK_FILE);
        let Ok(lock) = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
        else {
            return false;
        };
        let result = unsafe {
            // SAFETY: `lock` keeps this descriptor open for the duration of
            // both nonblocking flock calls.
            libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
        };
        if result == 0 {
            let _ = unsafe {
                // SAFETY: the descriptor remains valid until `lock` drops.
                libc::flock(lock.as_raw_fd(), libc::LOCK_UN)
            };
            false
        } else {
            // An existing authority lock that cannot be probed is safer to
            // treat as held than to delete a worker owned by an unknown
            // generation. This also covers platform-specific contention
            // errno values without turning an error into permission to delete.
            true
        }
    }
    #[cfg(not(unix))]
    {
        let _ = profile_root;
        false
    }
}

fn daemon_endpoint_is_reachable(endpoint: &DaemonEndpoint) -> bool {
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
    match endpoint {
        #[cfg(unix)]
        DaemonEndpoint::Unix(path) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => true,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::AddrNotAvailable
                ) =>
            {
                false
            }
            Err(_) => true,
        },
        DaemonEndpoint::Loopback(address) => {
            match std::net::TcpStream::connect_timeout(address, PROBE_TIMEOUT) {
                Ok(_) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::AddrNotAvailable
                    ) =>
                {
                    false
                }
                Err(_) => true,
            }
        }
    }
}

fn recover_pending_model_lifecycle(state_root: &Path) -> Result<()> {
    if !model_lifecycle_journal_present(state_root)? {
        return Ok(());
    }
    let state_root =
        tracedecay_memory_ncm_runtime::ports::StateRoot::new(state_root).map_err(config_error)?;
    tracedecay_memory_ncm_runtime::embedding::model_lifecycle::recover(&state_root)
        .map_err(|error| config_error(format!("recover NCM model lifecycle: {error}")))
}

fn model_lifecycle_journal_present(state_root: &Path) -> Result<bool> {
    reject_symlink_components(state_root, "model lifecycle state root")?;
    let model_journal = state_root
        .join(tracedecay_memory_ncm_runtime::embedding::model_lifecycle::JOURNAL_FILENAME);
    match fs::symlink_metadata(&model_journal) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(config_error(format!(
                "NCM model lifecycle journal is not a regular file: {}",
                model_journal.display()
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(
            "inspect NCM model lifecycle journal",
            &model_journal,
            error,
        )),
    }
}

fn before_observer_bundle_is_available(
    before_observer: &MemoryProviderNcmObserverV1,
    journal: &NcmControlJournalV1,
    paths: &ControlPaths,
) -> bool {
    let MemoryProviderNcmObserverV1::Enabled { worker_binary, .. } = before_observer else {
        return true;
    };
    if journal.before_worker_digest.is_none()
        || journal.before_manifest_digest.is_none()
        || journal.before_model_manifest_digest.is_none()
    {
        return false;
    }
    let Some(parent) = worker_binary.parent() else {
        return false;
    };
    let manifest_path = parent.join(WORKER_MANIFEST_NAME);
    let model_manifest_path = parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
    if is_control_worker_path(paths, worker_binary)
        && !control_artifacts_are_safe(paths, worker_binary, &manifest_path, &model_manifest_path)
    {
        return false;
    }
    require_guarded(
        worker_binary,
        journal.before_worker_digest.as_deref(),
        "previous worker",
    )
    .is_ok()
        && require_guarded(
            &manifest_path,
            journal.before_manifest_digest.as_deref(),
            "previous worker manifest",
        )
        .is_ok()
        && require_guarded(
            &model_manifest_path,
            journal.before_model_manifest_digest.as_deref(),
            "previous model acquisition manifest",
        )
        .is_ok()
}

fn read_verified_model_acquisition_manifest(path: &Path) -> Result<FileSnapshot> {
    let snapshot = read_regular_snapshot(path, MAX_MANIFEST_BYTES, "model acquisition manifest")?
        .ok_or_else(|| {
        config_error(format!(
            "NCM model acquisition manifest is missing beside the worker: {}",
            path.display()
        ))
    })?;
    if snapshot.bytes.as_slice() != TRUSTED_MODEL_ACQUISITION_MANIFEST {
        return Err(config_error(format!(
            "NCM model acquisition manifest failed trusted release verification: {}",
            path.display()
        )));
    }
    Ok(snapshot)
}

fn ensure_trusted_model_manifest(path: &Path, bytes: &[u8], role: &str) -> Result<()> {
    if role.contains("model acquisition manifest") && bytes != TRUSTED_MODEL_ACQUISITION_MANIFEST {
        return Err(config_error(format!(
            "NCM {role} failed trusted release verification: {}",
            path.display()
        )));
    }
    Ok(())
}

fn write_journal(paths: &ControlPaths, journal: &NcmControlJournalV1) -> Result<()> {
    validate_journal(journal, paths)?;
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| config_error(format!("encode NCM control journal: {error}")))?;

    // Claim the profile-wide journal with create_new before publishing its
    // first complete record. A competing project therefore cannot race the
    // initial existence check and replace this transaction's claim.
    if matches!(
        fs::symlink_metadata(&paths.journal),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        match tracedecay_private_fs::create_private_file(&paths.journal) {
            Ok(mut file) => {
                file.write_all(&bytes).map_err(|error| {
                    io_error("write NCM control journal", &paths.journal, error)
                })?;
                file.sync_all()
                    .map_err(|error| io_error("sync NCM control journal", &paths.journal, error))?;
                tracedecay_private_fs::framed_log::sync_parent_directory(
                    &paths.journal,
                    DirectorySyncPolicy::Strict,
                )
                .map_err(|error| io_error("sync NCM control directory", &paths.root, error))?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(io_error("claim NCM control journal", &paths.journal, error));
            }
        }
    }
    if let Some(existing) = read_journal(paths)? {
        if existing.operation_id != journal.operation_id {
            return Err(config_error(
                "NCM profile already has a control transaction claimed by another operation",
            ));
        }
        let mut existing_identity = existing.clone();
        existing_identity.phase = NcmJournalPhase::Prepared;
        let mut next_identity = journal.clone();
        next_identity.phase = NcmJournalPhase::Prepared;
        if existing_identity != next_identity
            || journal_phase_rank(journal.phase) < journal_phase_rank(existing.phase)
        {
            return Err(config_error(
                "NCM control journal phase or transaction identity regressed",
            ));
        }
    }
    write_atomic(&paths.journal, "ncm-control-journal", &bytes)
}

fn journal_phase_rank(phase: NcmJournalPhase) -> u8 {
    match phase {
        NcmJournalPhase::Prepared => 0,
        NcmJournalPhase::Staged => 1,
        NcmJournalPhase::Configured => 2,
    }
}

fn read_journal(paths: &ControlPaths) -> Result<Option<NcmControlJournalV1>> {
    let Some(file) = read_regular_snapshot(&paths.journal, 1024 * 1024, "control journal")? else {
        return Ok(None);
    };
    let journal = serde_json::from_slice(&file.bytes)
        .map_err(|error| config_error(format!("invalid NCM control journal: {error}")))?;
    validate_journal(&journal, paths)?;
    Ok(Some(journal))
}

fn validate_journal(journal: &NcmControlJournalV1, paths: &ControlPaths) -> Result<()> {
    if journal.schema_version != CONTROL_SCHEMA_VERSION || journal.operation_id.is_empty() {
        return Err(config_error("unsupported NCM control journal schema"));
    }
    if journal.operation_id.len() != 32
        || !journal
            .operation_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(config_error(
            "NCM control journal contains an unsafe operation id",
        ));
    }
    let worker_parent = journal
        .worker_path
        .parent()
        .ok_or_else(|| config_error("NCM control journal worker path has no parent"))?;
    let operation_parent = paths.worker_root.join(&journal.operation_id);
    let operation_binds_worker = worker_parent == operation_parent;
    let worker_is_control_owned = is_control_worker_path(paths, &journal.worker_path);
    if worker_is_control_owned
        && !matches!(journal.operation, NcmControlOperation::Uninstall)
        && !operation_binds_worker
    {
        return Err(config_error(
            "NCM control journal operation id does not bind its worker directory",
        ));
    }
    for (role, path) in [
        ("worker", &journal.worker_path),
        ("worker manifest", &journal.manifest_path),
        ("model acquisition manifest", &journal.model_manifest_path),
    ] {
        require_absolute_path(path, role)?;
        // Uninstall is also the guarded disable path for a worker installed
        // outside this profile, or for a damaged control bundle. Those paths
        // are recorded for configuration recovery but are never mutated by
        // this command, so a final symlink must not make disable impossible.
        if !matches!(journal.operation, NcmControlOperation::Uninstall) {
            reject_symlink_components(path, role)?;
        }
    }
    if journal.manifest_path.parent() != Some(worker_parent)
        || journal.model_manifest_path.parent() != Some(worker_parent)
        || journal.worker_path.file_name() != Some(std::ffi::OsStr::new(WORKER_NAME))
        || journal.manifest_path.file_name() != Some(std::ffi::OsStr::new(WORKER_MANIFEST_NAME))
        || journal.model_manifest_path.file_name()
            != Some(std::ffi::OsStr::new(MODEL_ACQUISITION_MANIFEST_NAME))
    {
        return Err(config_error(
            "NCM control journal must bind the worker to its sibling manifests",
        ));
    }
    if let Some(state_root) = &journal.state_root {
        require_absolute_path(state_root, "state root")?;
    }
    let all_artifacts_control_owned = worker_is_control_owned;
    if !all_artifacts_control_owned && !matches!(journal.operation, NcmControlOperation::Uninstall)
    {
        return Err(config_error(
            "NCM control journal names a path outside its control worker root",
        ));
    }
    let backup_dir = paths.backup_root.join(&journal.operation_id);
    for (role, backup, expected_name) in [
        ("worker backup", &journal.before_worker_backup, WORKER_NAME),
        (
            "worker manifest backup",
            &journal.before_manifest_backup,
            WORKER_MANIFEST_NAME,
        ),
        (
            "model acquisition manifest backup",
            &journal.before_model_manifest_backup,
            MODEL_ACQUISITION_MANIFEST_NAME,
        ),
    ]
    .into_iter()
    .filter_map(|(role, path, expected_name)| path.as_ref().map(|path| (role, path, expected_name)))
    {
        require_absolute_path(backup, role)?;
        reject_symlink_components(backup, role)?;
        if !is_control_owned_path(&paths.backup_root, backup)
            || backup.parent() != Some(backup_dir.as_path())
            || backup.file_name() != Some(std::ffi::OsStr::new(expected_name))
        {
            return Err(config_error(
                "NCM control journal names a backup outside its operation backup directory",
            ));
        }
    }
    if journal.before_configuration_revision.is_empty() {
        return Err(config_error(
            "NCM control journal contains an empty configuration revision",
        ));
    }
    ConfigurationRevisionId::new(journal.before_configuration_revision.clone())
        .map_err(|error| config_error(error.to_string()))?;
    if journal.profile_id.is_empty() || journal.project_id.is_empty() {
        return Err(config_error(
            "NCM control journal contains an empty profile or project identity",
        ));
    }
    for digest in [
        journal.before_worker_digest.as_deref(),
        journal.before_manifest_digest.as_deref(),
        journal.before_model_manifest_digest.as_deref(),
        journal.after_worker_digest.as_deref(),
        journal.after_manifest_digest.as_deref(),
        journal.after_model_manifest_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(config_error(
                "NCM control journal contains an invalid digest",
            ));
        }
    }
    match journal.operation {
        NcmControlOperation::Install | NcmControlOperation::Update => {
            if journal.state_root.is_none()
                || journal.after_worker_digest.is_none()
                || journal.after_manifest_digest.is_none()
                || journal.after_model_manifest_digest.is_none()
                || journal.before_worker_backup.is_some()
                || journal.before_manifest_backup.is_some()
                || journal.before_model_manifest_backup.is_some()
            {
                return Err(config_error(
                    "NCM install/update journal is missing its complete staged bundle identity",
                ));
            }
        }
        NcmControlOperation::Uninstall => {
            if journal.state_root.is_none()
                || journal.after_worker_digest.is_some()
                || journal.after_manifest_digest.is_some()
                || journal.after_model_manifest_digest.is_some()
                || (!all_artifacts_control_owned
                    && (journal.before_worker_backup.is_some()
                        || journal.before_manifest_backup.is_some()
                        || journal.before_model_manifest_backup.is_some()))
                || (all_artifacts_control_owned
                    && (journal.before_worker_backup.is_some()
                        != journal.before_worker_digest.is_some()
                        || journal.before_manifest_backup.is_some()
                            != journal.before_manifest_digest.is_some()
                        || journal.before_model_manifest_backup.is_some()
                            != journal.before_model_manifest_digest.is_some()))
            {
                return Err(config_error(
                    "NCM uninstall journal has an inconsistent artifact snapshot",
                ));
            }
        }
        NcmControlOperation::Recover => {
            return Err(config_error("nested NCM recovery journal is invalid"));
        }
    }
    Ok(())
}

fn write_receipt(paths: &ControlPaths, receipt: &NcmControlReceiptV1) -> Result<PathBuf> {
    let name = format!(
        "{RECEIPT_FILE_PREFIX}{}{RECEIPT_FILE_SUFFIX}",
        receipt.operation_id
    );
    let path = paths.root.join(name);
    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|error| config_error(format!("encode NCM control receipt: {error}")))?;
    write_atomic(&path, "ncm-control-receipt", &bytes)?;
    Ok(path)
}

fn latest_receipt(root: &Path, project_id: &str) -> Result<Option<PathBuf>> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("list NCM control receipts", root, error)),
    };
    let now = now_unix();
    let mut latest = None::<(u64, String, PathBuf)>;
    for entry in entries {
        let path = entry
            .map_err(|error| io_error("inspect NCM control receipt", root, error))?
            .path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(RECEIPT_FILE_PREFIX) || !name.ends_with(RECEIPT_FILE_SUFFIX) {
            continue;
        }
        let Some(file) = (match read_regular_snapshot(&path, 1024 * 1024, "control receipt") {
            Ok(file) => file,
            Err(_) => continue,
        }) else {
            continue;
        };
        let Ok(index) = serde_json::from_slice::<NcmReceiptIndex>(&file.bytes) else {
            continue;
        };
        if index.project_id != project_id || index.created_at_unix > now {
            continue;
        }
        let candidate = (index.created_at_unix, name.to_owned(), path);
        if latest
            .as_ref()
            .is_none_or(|current| (candidate.0, &candidate.1) > (current.0, &current.1))
        {
            latest = Some(candidate);
        }
    }
    Ok(latest.map(|(_, _, path)| path))
}

/// Returns the most recent receipt snapshot for this exact configured worker.
/// A receipt is the authority for deletion guards; a fresh digest of a
/// changed file must never turn an untrusted replacement into a deletable
/// control bundle.
fn committed_bundle_digests(
    paths: &ControlPaths,
    project_id: &str,
    worker_path: &Path,
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    let entries = fs::read_dir(&paths.root).ok()?;
    let now = now_unix();
    let mut latest = None::<(
        u64,
        String,
        (Option<String>, Option<String>, Option<String>),
    )>;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(RECEIPT_FILE_PREFIX) || !name.ends_with(RECEIPT_FILE_SUFFIX) {
            continue;
        }
        let Some(file) = (match read_regular_snapshot(&path, 1024 * 1024, "control receipt") {
            Ok(file) => file,
            Err(_) => continue,
        }) else {
            continue;
        };
        let Ok(receipt) = serde_json::from_slice::<NcmReceiptArtifactIndex>(&file.bytes) else {
            continue;
        };
        if receipt.project_id != project_id
            || receipt.created_at_unix > now
            || receipt.worker_path.as_deref() != Some(worker_path)
        {
            continue;
        }
        let candidate = (
            receipt.created_at_unix,
            name.to_owned(),
            (
                receipt.worker_sha256,
                receipt.manifest_sha256,
                receipt.model_manifest_sha256,
            ),
        );
        if latest
            .as_ref()
            .is_none_or(|current| (candidate.0, &candidate.1) > (current.0, &current.1))
        {
            latest = Some(candidate);
        }
    }
    latest.map(|(_, _, digests)| digests)
}

fn receipt_path_for(paths: &ControlPaths, operation_id: &str) -> Option<PathBuf> {
    let path = paths.root.join(format!(
        "{RECEIPT_FILE_PREFIX}{operation_id}{RECEIPT_FILE_SUFFIX}"
    ));
    let file = read_regular_snapshot(&path, 1024 * 1024, "control receipt")
        .ok()
        .flatten()?;
    let value = serde_json::from_slice::<serde_json::Value>(&file.bytes).ok()?;
    (value.get("operation_id").and_then(|value| value.as_str()) == Some(operation_id))
        .then_some(path)
}

fn emit_existing_receipt(
    paths: &ControlPaths,
    operation: NcmControlOperation,
    operation_id: &str,
    json: bool,
) -> Result<()> {
    let path = receipt_path_for(paths, operation_id)
        .ok_or_else(|| config_error("NCM idempotent receipt disappeared during retry"))?;
    if json {
        let file = required_regular_snapshot(&path, 1024 * 1024, "control receipt")?;
        let output = String::from_utf8(file.bytes)
            .map_err(|error| config_error(format!("invalid UTF-8 NCM control receipt: {error}")))?;
        println!("{output}");
    } else {
        println!(
            "NCM {} already committed; receipt {}",
            operation_name(operation),
            path.display()
        );
    }
    Ok(())
}

fn emit_reconstructed_receipt(
    paths: &ControlPaths,
    operation: NcmControlOperation,
    operation_id: &str,
    profile_id: &str,
    project_id: &str,
    worker_path: PathBuf,
    state_root: PathBuf,
    worker_sha256: Option<String>,
    manifest_sha256: Option<String>,
    model_manifest_sha256: Option<String>,
    json: bool,
    message: &str,
) -> Result<()> {
    let receipt = NcmControlReceiptV1 {
        schema_version: CONTROL_SCHEMA_VERSION,
        operation_id: operation_id.to_owned(),
        operation,
        outcome: "committed",
        profile_id: profile_id.to_owned(),
        project_id: project_id.to_owned(),
        worker_path: Some(worker_path),
        state_root: Some(state_root),
        worker_sha256,
        manifest_sha256,
        model_manifest_sha256,
        model_state: "preserved",
        native_state: "preserved",
        recall_routing: "preserved",
        configuration_receipt: None,
        created_at_unix: now_unix(),
    };
    let receipt_path = write_receipt(paths, &receipt)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&receipt)
                .map_err(|error| config_error(error.to_string()))?
        );
    } else {
        println!("{message}; receipt {}", receipt_path.display());
    }
    Ok(())
}

fn remove_journal(paths: &ControlPaths) -> Result<()> {
    reject_symlink_components(&paths.journal, "control journal")?;
    match fs::symlink_metadata(&paths.journal) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&paths.journal)
                .map_err(|error| io_error("remove NCM control journal", &paths.journal, error))?;
            tracedecay_private_fs::framed_log::sync_parent_directory(
                &paths.journal,
                DirectorySyncPolicy::Strict,
            )
            .map_err(|error| io_error("sync NCM control directory", &paths.root, error))?;
            Ok(())
        }
        Ok(_) => Err(config_error("NCM control journal is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(
            "inspect NCM control journal",
            &paths.journal,
            error,
        )),
    }
}

fn journal_present(paths: &ControlPaths) -> Result<bool> {
    match fs::symlink_metadata(&paths.journal) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(
            "inspect NCM control journal",
            &paths.journal,
            error,
        )),
    }
}

fn refuse_pending_journal(
    paths: &ControlPaths,
    expected_scope: Option<(&str, &str)>,
) -> Result<()> {
    match fs::symlink_metadata(&paths.journal) {
        Ok(metadata) if metadata.file_type().is_file() => {
            if let Some(journal) = read_journal(paths)?
                && let Some((profile_id, project_id)) = expected_scope
                && (journal.profile_id != profile_id || journal.project_id != project_id)
            {
                return Err(config_error(
                    "NCM pending control journal belongs to another profile or project",
                ));
            }
            Err(config_error(format!(
                "NCM has a pending control journal at {}; run `tracedecay ncm recover --yes` first",
                paths.journal.display()
            )))
        }
        Ok(_) => Err(config_error("NCM control journal is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(
            "inspect NCM control journal",
            &paths.journal,
            error,
        )),
    }
}

fn write_atomic(path: &Path, kind: &str, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        config_error(format!(
            "NCM artifact path has no parent: {}",
            path.display()
        ))
    })?;
    reject_symlink_components(parent, kind)?;
    reject_symlink_components(path, kind)?;
    fs::create_dir_all(parent)
        .map_err(|error| io_error("create NCM artifact parent", parent, error))?;
    tracedecay_private_fs::framed_log::sync_parent_directory(parent, DirectorySyncPolicy::Strict)
        .map_err(|error| io_error("sync NCM artifact parent", parent, error))?;
    reject_symlink_components(path, kind)?;
    atomic_write(path, kind, bytes, DirectorySyncPolicy::Strict)
        .map_err(|error| io_error("write NCM control artifact", path, error))?;
    Ok(())
}

fn set_worker_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = tracedecay_private_fs::open_private_file(path)
            .map_err(|error| io_error("open staged NCM worker", path, error))?;
        file.sync_all()
            .map_err(|error| io_error("sync staged NCM worker", path, error))?;
        file.set_permissions(fs::Permissions::from_mode(0o500))
            .map_err(|error| io_error("seal staged NCM worker", path, error))?;
        file.sync_all()
            .map_err(|error| io_error("sync sealed NCM worker", path, error))?;
        tracedecay_private_fs::framed_log::sync_parent_directory(path, DirectorySyncPolicy::Strict)
            .map_err(|error| io_error("sync staged NCM worker metadata", path, error))?;
    }
    Ok(())
}

fn is_control_owned_path(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|relative| {
        !relative.as_os_str().is_empty()
            && !relative.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir
                        | Component::ParentDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            })
    })
}

fn is_control_worker_path(paths: &ControlPaths, worker_path: &Path) -> bool {
    let Some(parent) = worker_path.parent() else {
        return false;
    };
    parent.parent() == Some(paths.worker_root.as_path())
        && parent
            .file_name()
            .is_some_and(|name| name != std::ffi::OsStr::new(""))
        && worker_path.file_name() == Some(std::ffi::OsStr::new(WORKER_NAME))
        && reject_symlink_components(worker_path, "worker").is_ok()
}

fn require_absolute_path(path: &Path, role: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.to_str().is_none_or(|text| text.contains('\0'))
    {
        return Err(config_error(format!(
            "NCM {role} must be absolute and must not contain parent traversal"
        )));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path, role: &str) -> Result<()> {
    tracedecay_runtime_core::storage::reject_symlink_components(path, role).map_err(|error| {
        config_error(format!(
            "NCM {role} path is unsafe: {} ({})",
            path.display(),
            error
        ))
    })
}

fn ensure_supported_platform() -> Result<()> {
    let capability = current_worker_platform_capability();
    if capability.is_supported() {
        Ok(())
    } else {
        Err(config_error(format!(
            "NCM lifecycle is supported only on arm64 macOS; {}",
            capability
        )))
    }
}

fn operation_id_for_identity(
    profile_id: &str,
    project_id: &str,
    operation: NcmControlOperation,
    identity: &str,
) -> String {
    let digest = Sha256::digest(
        format!(
            "ncm-control.v1|{profile_id}|{project_id}|{}|{identity}",
            operation_name(operation)
        )
        .as_bytes(),
    );
    digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn new_operation_id(profile_id: &str, project_id: &str, operation: NcmControlOperation) -> String {
    operation_id_for_identity(profile_id, project_id, operation, "")
}

fn operation_name(operation: NcmControlOperation) -> &'static str {
    match operation {
        NcmControlOperation::Install => "install",
        NcmControlOperation::Update => "update",
        NcmControlOperation::Recover => "recover",
        NcmControlOperation::Uninstall => "uninstall",
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verifier_error(
    path: &Path,
    error: WorkerIntegrityError,
) -> tracedecay_domain::errors::TraceDecayError {
    config_error(format!(
        "NCM worker '{}' failed offline verification: {error}",
        path.display()
    ))
}

fn io_error(
    operation: &str,
    path: &Path,
    error: std::io::Error,
) -> tracedecay_domain::errors::TraceDecayError {
    config_error(format!("{operation} '{}': {error}", path.display()))
}

fn config_error(message: impl Into<String>) -> tracedecay_domain::errors::TraceDecayError {
    tracedecay_domain::errors::TraceDecayError::Config {
        message: message.into(),
    }
}

fn tracedecay_cli_configuration_receipt(receipt: Option<&tracedecay_contracts::EffectReceipt>) {
    crate::commands::report_configuration_receipt(receipt);
}

#[cfg(test)]
mod tests {
    use super::{
        ControlPaths, MODEL_ACQUISITION_MANIFEST_NAME, NcmControlJournalV1, NcmControlOperation,
        NcmJournalPhase, NcmScopeArgs, RECEIPT_FILE_PREFIX, RECEIPT_FILE_SUFFIX,
        TRUSTED_MODEL_ACQUISITION_MANIFEST, WORKER_MANIFEST_NAME, WORKER_NAME,
        before_observer_bundle_is_available, cleanup_previous_control_worker,
        daemon_endpoint_is_reachable, daemon_profile_has_live_owner, latest_receipt,
        new_operation_id, now_unix, operation_id_for_identity, publish_worker,
        read_verified_model_acquisition_manifest, refuse_pending_journal,
        remove_control_worker_bundle, remove_guarded, require_absolute_path, sha256_hex,
        validate_journal,
    };
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use tracedecay_domain::configuration::MemoryProviderNcmObserverV1;

    use tempfile::tempdir;

    #[test]
    fn operation_ids_are_bounded_hex() {
        let id = new_operation_id("profile.test", "project.test", NcmControlOperation::Install);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            id,
            new_operation_id("profile.test", "project.test", NcmControlOperation::Install)
        );
        assert_ne!(
            id,
            operation_id_for_identity(
                "profile.test",
                "project.test",
                NcmControlOperation::Install,
                "worker-sha256=changed",
            )
        );
    }

    #[test]
    fn worker_and_state_paths_require_absolute_non_traversing_values() {
        assert!(require_absolute_path(Path::new("relative/worker"), "worker").is_err());
        assert!(require_absolute_path(Path::new("/tmp/../worker"), "worker").is_err());
        assert!(require_absolute_path(Path::new("/tmp/worker"), "worker").is_ok());
    }

    #[test]
    fn model_acquisition_manifest_requires_the_trusted_release_bytes() {
        let root = tempdir().expect("manifest fixture root");
        let path = root.path().join(MODEL_ACQUISITION_MANIFEST_NAME);
        fs::write(&path, TRUSTED_MODEL_ACQUISITION_MANIFEST).expect("trusted manifest bytes");
        let snapshot = read_verified_model_acquisition_manifest(&path)
            .expect("trusted model manifest is admitted");
        assert_eq!(snapshot.bytes, TRUSTED_MODEL_ACQUISITION_MANIFEST);
        assert_eq!(
            snapshot.digest,
            sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)
        );

        fs::write(&path, b"tampered").expect("tampered manifest bytes");
        assert!(read_verified_model_acquisition_manifest(&path).is_err());
    }

    #[test]
    fn publish_worker_stages_the_worker_and_both_bound_manifests() {
        let root = tempdir().expect("worker fixture root");
        let source_root = root.path().join("source");
        fs::create_dir_all(&source_root).expect("source root");
        let source_worker = source_root.join("verified-worker");
        fs::write(&source_worker, b"verified worker bytes").expect("source worker");
        let worker_path = root
            .path()
            .join("control/worker/operation/tracedecay-ncm-worker");
        publish_worker(
            &worker_path,
            b"worker manifest bytes",
            TRUSTED_MODEL_ACQUISITION_MANIFEST,
            &source_worker,
        )
        .expect("publish worker sidecar");
        assert_eq!(
            fs::read(&worker_path).expect("published worker"),
            b"verified worker bytes"
        );
        assert_eq!(
            fs::read(
                worker_path
                    .parent()
                    .expect("published worker parent")
                    .join("worker-manifest.json")
            )
            .expect("published worker manifest"),
            b"worker manifest bytes"
        );
        assert_eq!(
            fs::read(
                worker_path
                    .parent()
                    .expect("published worker parent")
                    .join(MODEL_ACQUISITION_MANIFEST_NAME),
            )
            .expect("published model acquisition manifest"),
            TRUSTED_MODEL_ACQUISITION_MANIFEST
        );

        let rejected_path = root
            .path()
            .join("control/worker/rejected/tracedecay-ncm-worker");
        let rejected = publish_worker(
            &rejected_path,
            b"worker manifest bytes",
            b"tampered model acquisition manifest",
            &source_worker,
        );
        assert!(rejected.is_err());
        assert!(!rejected_path.exists());
    }

    #[test]
    fn guarded_removal_refuses_tampered_model_manifest_without_deleting_it() {
        let root = tempdir().expect("manifest fixture root");
        let path = root.path().join(MODEL_ACQUISITION_MANIFEST_NAME);
        let expected = TRUSTED_MODEL_ACQUISITION_MANIFEST;
        fs::write(&path, b"tampered installed manifest").expect("tampered manifest");
        let result = remove_guarded(
            &path,
            Some(&sha256_hex(expected)),
            "model acquisition manifest",
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(&path).expect("tampered manifest remains for review"),
            b"tampered installed manifest"
        );
    }

    #[test]
    fn uninstall_bundle_deletion_is_all_or_nothing_for_tampered_sidecars() {
        let root = tempdir().expect("control fixture root");
        let control_root = root.path().join("ncm");
        let worker_root = control_root.join("worker");
        let backup_root = control_root.join("backups");
        let operation_root = worker_root.join("operation");
        let worker = operation_root.join(WORKER_NAME);
        let manifest = operation_root.join(WORKER_MANIFEST_NAME);
        let model_manifest = operation_root.join(MODEL_ACQUISITION_MANIFEST_NAME);
        fs::create_dir_all(&operation_root).expect("worker operation directory");
        fs::create_dir_all(&backup_root).expect("backup root");
        let worker_bytes = b"worker bytes";
        let manifest_bytes = b"worker manifest bytes";
        fs::write(&worker, worker_bytes).expect("worker");
        fs::write(&manifest, manifest_bytes).expect("worker manifest");
        fs::write(&model_manifest, TRUSTED_MODEL_ACQUISITION_MANIFEST)
            .expect("model acquisition manifest");
        let paths = ControlPaths {
            root: control_root,
            worker_root,
            backup_root,
            journal: root.path().join("ncm/control-journal-v1.json"),
        };
        let worker_digest = sha256_hex(worker_bytes);
        let manifest_digest = sha256_hex(manifest_bytes);
        let model_manifest_digest = sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST);
        assert!(
            remove_control_worker_bundle(
                &paths,
                &worker,
                &manifest,
                &model_manifest,
                Some(&worker_digest),
                Some(&manifest_digest),
                Some(&model_manifest_digest),
            )
            .expect("complete bundle is removable")
        );
        assert!(!operation_root.exists());

        fs::create_dir_all(&operation_root).expect("recreate worker operation directory");
        fs::write(&worker, worker_bytes).expect("worker");
        fs::write(&manifest, manifest_bytes).expect("worker manifest");
        fs::write(&model_manifest, b"tampered model acquisition manifest")
            .expect("tampered model acquisition manifest");
        let result = remove_control_worker_bundle(
            &paths,
            &worker,
            &manifest,
            &model_manifest,
            Some(&worker_digest),
            Some(&manifest_digest),
            Some(&model_manifest_digest),
        );
        assert!(!result.expect("tampered bundle is retained without deletion"));
        assert!(worker.is_file());
        assert!(manifest.is_file());
        assert!(model_manifest.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn stale_daemon_authority_does_not_block_control_cleanup() {
        let root = tempdir().expect("authority fixture root");
        let profile = root.path().join("profile");
        fs::create_dir_all(&profile).expect("profile root");
        let socket = profile.join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("daemon socket");
        let authority = tracedecay_daemon_identity::authority::DaemonAuthority::acquire(
            &profile,
            &tracedecay_daemon_protocol::DaemonEndpoint::Unix(socket.clone()),
            "ncm-test",
        )
        .expect("daemon authority");
        let paths = ControlPaths {
            root: profile.join("ncm"),
            worker_root: profile.join("ncm/worker"),
            backup_root: profile.join("ncm/backups"),
            journal: profile.join("ncm/control-journal-v1.json"),
        };
        let endpoint = authority.record().endpoint.clone();
        assert!(daemon_endpoint_is_reachable(&endpoint));
        assert!(daemon_profile_has_live_owner(&paths).expect("live daemon probe"));
        drop(listener);
        assert!(
            daemon_profile_has_live_owner(&paths).expect("unbound authority lock probe"),
            "the authority lock remains ownership while transport is unbound"
        );
        drop(authority);
        assert!(!daemon_endpoint_is_reachable(&endpoint));
        assert!(!daemon_profile_has_live_owner(&paths).expect("stale daemon probe"));
    }

    #[test]
    fn update_cleanup_removes_complete_previous_bundle_and_retains_tampered_bytes() {
        let root = tempdir().expect("control fixture root");
        let control_root = root.path().join("ncm");
        let worker_root = control_root.join("worker");
        let backup_root = control_root.join("backups");
        fs::create_dir_all(&backup_root).expect("control directories");
        let paths = ControlPaths {
            root: control_root.clone(),
            worker_root: worker_root.clone(),
            backup_root,
            journal: control_root.join("control-journal-v1.json"),
        };

        let old_parent = worker_root.join("old-operation");
        let old_worker = old_parent.join("tracedecay-ncm-worker");
        let old_manifest = old_parent.join("worker-manifest.json");
        let old_model_manifest = old_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        fs::create_dir_all(&old_parent).expect("old worker directory");
        let old_worker_bytes = b"old worker";
        let old_manifest_bytes = b"old worker manifest";
        fs::write(&old_worker, old_worker_bytes).expect("old worker");
        fs::write(&old_manifest, old_manifest_bytes).expect("old worker manifest");
        fs::write(&old_model_manifest, TRUSTED_MODEL_ACQUISITION_MANIFEST)
            .expect("old model manifest");

        let new_worker = worker_root.join("new-operation/tracedecay-ncm-worker");
        let observer = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: old_worker.clone(),
            state_root: root.path().join("state"),
        };
        let journal = NcmControlJournalV1 {
            schema_version: 1,
            operation_id: "22222222222222222222222222222222".to_owned(),
            operation: NcmControlOperation::Update,
            phase: NcmJournalPhase::Configured,
            profile_id: "profile.test".to_owned(),
            project_id: "project.test".to_owned(),
            worker_path: new_worker,
            manifest_path: worker_root.join("new-operation/worker-manifest.json"),
            model_manifest_path: worker_root
                .join("new-operation")
                .join(MODEL_ACQUISITION_MANIFEST_NAME),
            state_root: Some(root.path().join("state")),
            before_configuration_revision: "configuration.revision.test".to_owned(),
            before_document: String::new(),
            after_document: String::new(),
            before_worker_digest: Some(sha256_hex(old_worker_bytes)),
            before_manifest_digest: Some(sha256_hex(old_manifest_bytes)),
            before_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            after_worker_digest: Some(sha256_hex(b"new worker")),
            after_manifest_digest: Some(sha256_hex(b"new worker manifest")),
            after_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            before_worker_backup: None,
            before_manifest_backup: None,
            before_model_manifest_backup: None,
        };
        cleanup_previous_control_worker(&observer, &journal, &paths)
            .expect("previous worker bundle is removed");
        assert!(!old_parent.exists());

        let tampered_parent = worker_root.join("tampered-operation");
        let tampered_worker = tampered_parent.join("tracedecay-ncm-worker");
        let tampered_manifest = tampered_parent.join("worker-manifest.json");
        let tampered_model_manifest = tampered_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        fs::create_dir_all(&tampered_parent).expect("tampered worker directory");
        fs::write(&tampered_worker, old_worker_bytes).expect("tampered worker");
        fs::write(&tampered_manifest, old_manifest_bytes).expect("tampered worker manifest");
        fs::write(&tampered_model_manifest, b"tampered model manifest")
            .expect("tampered model manifest");
        let tampered_observer = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: tampered_worker.clone(),
            state_root: root.path().join("state"),
        };
        let tampered_journal = NcmControlJournalV1 {
            operation_id: "22222222222222222222222222222222".to_owned(),
            before_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            ..journal
        };
        let result = cleanup_previous_control_worker(&tampered_observer, &tampered_journal, &paths);
        result.expect("tampered previous bundle is retained for replacement");
        assert!(tampered_model_manifest.is_file());
        assert!(tampered_worker.is_file());
        assert!(tampered_manifest.is_file());
    }

    #[test]
    fn rollback_availability_requires_every_previous_bundle_artifact() {
        let root = tempdir().expect("control fixture root");
        let control_root = root.path().join("ncm");
        let worker_root = control_root.join("worker");
        let backup_root = control_root.join("backups");
        let old_parent = worker_root.join("old-operation");
        let old_worker = old_parent.join("tracedecay-ncm-worker");
        let old_manifest = old_parent.join(WORKER_MANIFEST_NAME);
        let old_model_manifest = old_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        fs::create_dir_all(&old_parent).expect("old worker directory");
        fs::create_dir_all(&backup_root).expect("backup root");
        fs::write(&old_worker, b"old worker").expect("old worker");
        fs::write(&old_manifest, b"old worker manifest").expect("old manifest");
        fs::write(&old_model_manifest, TRUSTED_MODEL_ACQUISITION_MANIFEST)
            .expect("old model manifest");
        let new_parent = worker_root.join("new-operation");
        let journal = NcmControlJournalV1 {
            schema_version: 1,
            operation_id: "22222222222222222222222222222222".to_owned(),
            operation: NcmControlOperation::Update,
            phase: NcmJournalPhase::Staged,
            profile_id: "profile.test".to_owned(),
            project_id: "project.test".to_owned(),
            worker_path: new_parent.join(WORKER_NAME),
            manifest_path: new_parent.join(WORKER_MANIFEST_NAME),
            model_manifest_path: new_parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
            state_root: Some(root.path().join("state")),
            before_configuration_revision: "configuration.revision.test".to_owned(),
            before_document: String::new(),
            after_document: String::new(),
            before_worker_digest: Some(sha256_hex(b"old worker")),
            before_manifest_digest: Some(sha256_hex(b"old worker manifest")),
            before_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            after_worker_digest: Some(sha256_hex(b"new worker")),
            after_manifest_digest: Some(sha256_hex(b"new manifest")),
            after_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            before_worker_backup: None,
            before_manifest_backup: None,
            before_model_manifest_backup: None,
        };
        let paths = ControlPaths {
            root: control_root,
            worker_root,
            backup_root,
            journal: root.path().join("ncm/control-journal-v1.json"),
        };
        let observer = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: old_worker.clone(),
            state_root: root.path().join("state"),
        };
        assert!(before_observer_bundle_is_available(
            &observer, &journal, &paths
        ));
        fs::remove_file(&old_worker).expect("remove previous worker");
        assert!(!before_observer_bundle_is_available(
            &observer, &journal, &paths
        ));
    }

    #[test]
    fn journal_validation_binds_operation_and_backup_paths() {
        let root = tempdir().expect("control fixture root");
        let control_root = root.path().join("ncm");
        let worker_root = control_root.join("worker");
        let backup_root = control_root.join("backups");
        let operation_id = "33333333333333333333333333333333";
        let worker_parent = worker_root.join(operation_id);
        let paths = ControlPaths {
            root: control_root.clone(),
            worker_root: worker_root.clone(),
            backup_root: backup_root.clone(),
            journal: control_root.join("control-journal-v1.json"),
        };
        let journal = NcmControlJournalV1 {
            schema_version: 1,
            operation_id: operation_id.to_owned(),
            operation: NcmControlOperation::Uninstall,
            phase: NcmJournalPhase::Prepared,
            profile_id: "profile.test".to_owned(),
            project_id: "project.test".to_owned(),
            worker_path: worker_parent.join("tracedecay-ncm-worker"),
            manifest_path: worker_parent.join("worker-manifest.json"),
            model_manifest_path: worker_parent.join(MODEL_ACQUISITION_MANIFEST_NAME),
            state_root: Some(root.path().join("state")),
            before_configuration_revision: "configuration.revision.test".to_owned(),
            before_document: String::new(),
            after_document: String::new(),
            before_worker_digest: None,
            before_manifest_digest: None,
            before_model_manifest_digest: Some(sha256_hex(TRUSTED_MODEL_ACQUISITION_MANIFEST)),
            after_worker_digest: None,
            after_manifest_digest: None,
            after_model_manifest_digest: None,
            before_worker_backup: None,
            before_manifest_backup: None,
            before_model_manifest_backup: Some(
                backup_root
                    .join(operation_id)
                    .join(MODEL_ACQUISITION_MANIFEST_NAME),
            ),
        };
        validate_journal(&journal, &paths).expect("bound journal is accepted");

        let mut independent_uninstall = journal.clone();
        independent_uninstall.operation_id = "44444444444444444444444444444444".to_owned();
        independent_uninstall.before_model_manifest_backup = Some(
            backup_root
                .join(&independent_uninstall.operation_id)
                .join(MODEL_ACQUISITION_MANIFEST_NAME),
        );
        validate_journal(&independent_uninstall, &paths)
            .expect("uninstall operation id need not equal install worker directory");

        let mut mismatched_worker = journal.clone();
        let mismatched_parent = worker_root.join("another-operation");
        mismatched_worker.worker_path = mismatched_parent.join(WORKER_NAME);
        mismatched_worker.manifest_path = mismatched_parent.join(WORKER_MANIFEST_NAME);
        mismatched_worker.model_manifest_path =
            mismatched_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        assert!(validate_journal(&mismatched_worker, &paths).is_err());

        let mut escaped = journal.clone();
        escaped.operation_id = "../escaped".to_owned();
        assert!(validate_journal(&escaped, &paths).is_err());
        let mut escaped_backup = journal.clone();
        escaped_backup.before_model_manifest_backup = Some(root.path().join("outside.json"));
        assert!(validate_journal(&escaped_backup, &paths).is_err());

        let external_parent = root.path().join("external-worker");
        let mut external = journal.clone();
        external.operation = NcmControlOperation::Uninstall;
        external.worker_path = external_parent.join("tracedecay-ncm-worker");
        external.manifest_path = external_parent.join(WORKER_MANIFEST_NAME);
        external.model_manifest_path = external_parent.join(MODEL_ACQUISITION_MANIFEST_NAME);
        external.before_model_manifest_backup = None;
        validate_journal(&external, &paths).expect("external uninstall is disable-only");
        external.operation = NcmControlOperation::Update;
        assert!(validate_journal(&external, &paths).is_err());

        let mut incomplete_install = journal;
        incomplete_install.operation = NcmControlOperation::Install;
        incomplete_install.state_root = Some(root.path().join("state"));
        incomplete_install.before_model_manifest_digest = None;
        incomplete_install.before_model_manifest_backup = None;
        incomplete_install.after_worker_digest = Some(sha256_hex(b"worker"));
        incomplete_install.after_manifest_digest = Some(sha256_hex(b"manifest"));
        incomplete_install.after_model_manifest_digest = None;
        assert!(validate_journal(&incomplete_install, &paths).is_err());
    }

    #[test]
    fn latest_receipt_is_scoped_by_project_and_timestamp() {
        let root = tempdir().expect("receipt fixture root");
        let now = now_unix();
        for (name, project_id, created_at_unix) in [
            ("a", "other-project", now.saturating_add(1)),
            ("b", "target-project", now.saturating_sub(2)),
            ("c", "target-project", now.saturating_sub(1)),
        ] {
            let path = root
                .path()
                .join(format!("{RECEIPT_FILE_PREFIX}{name}{RECEIPT_FILE_SUFFIX}"));
            let mut file =
                tracedecay_private_fs::create_private_file(&path).expect("private receipt fixture");
            let bytes = serde_json::to_vec(&serde_json::json!({
                "project_id": project_id,
                "created_at_unix": created_at_unix,
            }))
            .expect("receipt index JSON");
            file.write_all(&bytes).expect("receipt bytes");
            file.sync_all().expect("receipt sync");
        }
        let latest = latest_receipt(root.path(), "target-project")
            .expect("receipt scan")
            .expect("scoped receipt");
        assert!(latest.ends_with("control-receipt.c.v1.json"));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_journal_entries_block_mutations() {
        let root = tempdir().expect("control fixture root");
        let journal = root.path().join("control-journal-v1.json");
        std::os::unix::fs::symlink(root.path().join("missing"), &journal)
            .expect("dangling journal symlink");
        let paths = ControlPaths {
            root: root.path().to_owned(),
            worker_root: root.path().join("worker"),
            backup_root: root.path().join("backups"),
            journal,
        };
        assert!(refuse_pending_journal(&paths, None).is_err());
    }

    #[allow(dead_code)]
    fn scope_is_constructible_for_clap() {
        let _ = NcmScopeArgs {
            path: None,
            project_id: None,
            project_path: None,
        };
    }
}
