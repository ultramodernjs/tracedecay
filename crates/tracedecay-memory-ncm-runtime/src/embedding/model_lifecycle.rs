//! Crash-safe lifecycle for the NCM encoder model directory.
//!
//! The encoder's model cache is a single admitted filesystem object.  A
//! download is performed below a private, same-filesystem staging directory;
//! the complete candidate is verified before the live `models` directory is
//! changed.  Publication is a pair of directory-entry renames guarded by a
//! durable journal.  That gives readers either the old complete tree or the
//! new complete tree, while recovery can repair the short interval between
//! the two renames after a process or machine failure.

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
#[cfg(feature = "real-encoder")]
use hf_hub::{Repo, RepoType, api::sync::ApiBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
#[cfg(all(test, unix))]
use std::fs;
use std::io::{Read, Write};
#[cfg(feature = "real-encoder")]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    CACHE_REPOSITORY_DIR, MANIFEST_FILENAME, MODEL_ACQUISITION_RECEIPT_PATH, MODEL_NAME,
    MODEL_REPOSITORY, MODEL_REVISION, ModelAcquisitionManifest, PinnedEncoder, REQUIRED_FILES,
    ensure_manifest_is_pinned, is_safe_relative_path, is_sha256_digest, validate_manifest_shape,
};
#[cfg(feature = "real-encoder")]
use super::{digest_bytes, read_file_nofollow};
use crate::ports::{Deadline, EncoderError, EncoderIdentity, StateRoot};

const JOURNAL_SCHEMA_VERSION: u16 = 1;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
/// Durable journal kept beside the live model directory.
pub const JOURNAL_FILENAME: &str = "ncm-model-lifecycle-v1.json";
/// Prefix used for private same-filesystem staging roots.
pub const STAGING_PREFIX: &str = ".ncm-model-staging-";
/// Prefix used for rollback directories retained by an interrupted operation.
pub const BACKUP_PREFIX: &str = ".ncm-model-backup-";
const ROLLBACK_PREFIX: &str = ".ncm-model-rollback-";
const RECEIPT_FILENAME: &str = "ncm-model-acquisition-v1.json";
#[cfg(feature = "real-encoder")]
const CANDIDATE_DIRECTORY: &str = "candidate";
#[cfg(feature = "real-encoder")]
const DOWNLOAD_DIRECTORY: &str = "download";

/// Installs the pinned model if it is absent and returns its verified identity.
pub fn install(root: &StateRoot, deadline: Deadline) -> Result<EncoderIdentity, EncoderError> {
    install_or_update(root, deadline, Operation::Install)
}

/// Replaces the live model tree with a freshly acquired pinned model.
pub fn update(root: &StateRoot, deadline: Deadline) -> Result<EncoderIdentity, EncoderError> {
    install_or_update(root, deadline, Operation::Update)
}

/// Repairs one interrupted model lifecycle transaction.
///
/// A missing journal is a successful no-op.  A present journal is accepted
/// only when every path and digest still belongs to the transaction that
/// created it; an unexpected external edit remains in place for inspection.
pub fn recover(root: &StateRoot) -> Result<(), EncoderError> {
    let root_directory = open_root_directory(root)?;
    let acquisition = ModelAcquisitionManifest::reference()?;
    let Some(journal) = read_journal_at(&root_directory, root.path())? else {
        cleanup_orphan_staging(&root_directory, root.path(), "")?;
        return Ok(());
    };
    validate_journal(&journal)?;
    recover_journal(root, &root_directory, &journal, &acquisition)
}

/// Removes the complete model tree transactionally.
///
/// The provider namespace and every other state-root entry remain untouched.
/// If the operation is interrupted after the live directory is moved, the
/// journal lets [`recover`] restore the exact pre-uninstall tree.
pub fn uninstall(root: &StateRoot) -> Result<(), EncoderError> {
    let root_directory = open_root_directory(root)?;
    let acquisition = ModelAcquisitionManifest::reference()?;
    refuse_pending_journal_at(&root_directory, root.path())?;
    let Some(before_digest) =
        digest_optional_entry(&root_directory, OsStr::new("models"), &root.models_dir())?
    else {
        return Ok(());
    };

    let operation_id = operation_id(Operation::Uninstall);
    let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
    if path_entry_exists(
        &root_directory,
        OsStr::new(&backup_name),
        &root.path().join(&backup_name),
    )? {
        return Err(EncoderError::ArtifactMismatch(
            "uninstall backup entry already exists".to_owned(),
        ));
    }
    let journal = LifecycleJournal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        operation_id,
        operation: Operation::Uninstall,
        phase: Phase::Prepared,
        revision: acquisition.revision.clone(),
        staging_name: None,
        backup_name: Some(backup_name.clone()),
        before_digest: Some(before_digest),
        after_digest: None,
    };
    reserve_journal_at(&root_directory, root.path(), &journal)?;

    if let Err(error) = tracedecay_private_fs::capability_dir::rename_noreplace(
        &root_directory,
        OsStr::new("models"),
        &root_directory,
        OsStr::new(&backup_name),
    ) {
        let _ = remove_journal_at(&root_directory, root.path());
        return Err(io_error(
            "move model tree to uninstall backup",
            &root.models_dir(),
            error,
        ));
    }
    sync_directory(&root_directory, root.path())?;

    let mut journal = journal;
    journal.phase = Phase::BackedUp;
    write_journal_at(&root_directory, root.path(), &journal)?;

    journal.phase = Phase::Published;
    write_journal_at(&root_directory, root.path(), &journal)?;
    let backup_path = root.path().join(&backup_name);
    remove_verified_directory_entry(
        &root_directory,
        OsStr::new(&backup_name),
        &backup_path,
        journal.before_digest.as_deref().ok_or_else(|| {
            EncoderError::ArtifactMismatch(
                "uninstall backup has no original tree digest".to_owned(),
            )
        })?,
    )?;
    sync_directory(&root_directory, root.path())?;
    remove_journal_at(&root_directory, root.path())
}

fn install_or_update(
    root: &StateRoot,
    deadline: Deadline,
    operation: Operation,
) -> Result<EncoderIdentity, EncoderError> {
    if deadline.remaining_ms == 0 {
        return Err(EncoderError::Cancelled);
    }
    let root_directory = open_root_directory(root)?;
    refuse_pending_journal_at(&root_directory, root.path())?;
    super::ensure_authoritative_environment()?;
    let acquisition = ModelAcquisitionManifest::reference()?;
    let expected = acquisition.pinned_encoder()?;
    ensure_manifest_is_pinned(&expected)?;

    #[cfg(feature = "real-encoder")]
    {
        let before_digest =
            digest_optional_entry(&root_directory, OsStr::new("models"), &root.models_dir())?;
        let operation_id = operation_id(operation);
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        if path_entry_exists(
            &root_directory,
            OsStr::new(&staging_name),
            &root.path().join(&staging_name),
        )? || path_entry_exists(
            &root_directory,
            OsStr::new(&backup_name),
            &root.path().join(&backup_name),
        )? {
            return Err(EncoderError::ArtifactMismatch(
                "model lifecycle operation names are already in use".to_owned(),
            ));
        }
        let mut journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation,
            phase: Phase::Prepared,
            revision: acquisition.revision.clone(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name.clone()),
            before_digest: before_digest.clone(),
            after_digest: None,
        };
        // Reserve the journal before making the staging directory. A crash
        // between these two operations leaves an authoritative reservation
        // that recovery can remove instead of leaking an orphan directory.
        reserve_journal_at(&root_directory, root.path(), &journal)?;
        cleanup_orphan_staging(&root_directory, root.path(), &staging_name)?;

        if matches!(operation, Operation::Install)
            && has_exact_verified_model(&root_directory, root, &expected)?
        {
            let tree_digest = before_digest.as_deref().ok_or_else(|| {
                EncoderError::ArtifactMismatch(
                    "verified installed model has no live tree digest".to_owned(),
                )
            })?;
            let receipt_result = write_and_verify_acquisition_receipt(
                root,
                &root_directory,
                &acquisition,
                operation,
                "already_present",
                &journal.operation_id,
                tree_digest,
            );
            if receipt_result.is_ok() {
                remove_journal_at(&root_directory, root.path())?;
            }
            receipt_result?;
            return super::encoder_identity(&expected);
        }

        let (staging_path, staging_directory) =
            match create_private_staging(&root_directory, root.path(), &staging_name) {
                Ok(staging) => staging,
                Err(error) => {
                    let _ = remove_journal_at(&root_directory, root.path());
                    let _ = cleanup_orphan_staging(&root_directory, root.path(), "");
                    return Err(error);
                }
            };
        let cleanup_journal = journal.clone();
        let result = (|| {
            let download_path =
                create_private_directory(&staging_directory, &staging_path, DOWNLOAD_DIRECTORY)?;
            acquire_manifest_files(&acquisition, &download_path)?;
            if deadline.remaining_ms == 0 {
                return Err(EncoderError::Cancelled);
            }

            let manifest = super::materialize_verified_snapshot(&download_path, &expected)?;
            super::ensure_pinned_metadata(&manifest, &expected)?;
            super::validate_materialized_encoder(&download_path, &manifest)?;

            let candidate_models =
                create_private_directory(&staging_directory, &staging_path, CANDIDATE_DIRECTORY)?;
            let candidate_directory = open_directory_nofollow(
                &staging_directory,
                OsStr::new(CANDIDATE_DIRECTORY),
                &candidate_models,
            )?;
            super::publish_materialized_snapshot(
                &download_path,
                &candidate_models,
                &candidate_directory,
                &manifest,
            )?;
            // Windows refuses to rename a directory while a handle to it is
            // open, so close the candidate before publication moves it.
            drop(candidate_directory);
            super::write_manifest(&candidate_models, &manifest)?;
            validate_candidate(&candidate_models, &manifest)?;
            sync_tree_path(&candidate_models)?;

            let candidate_digest = digest_directory_path(&candidate_models)?;
            journal.phase = Phase::Staged;
            journal.after_digest = Some(candidate_digest);
            write_journal_at(&root_directory, root.path(), &journal)?;
            publish_candidate(
                root,
                &root_directory,
                journal,
                &staging_path,
                staging_directory,
                &acquisition,
                &manifest,
            )?;
            super::encoder_identity(&manifest)
        })();

        if result.is_err() {
            // Keep cleanup bound to the reserved transaction.  Recovery can
            // safely remove a partial staging tree, while an unexpected or
            // tampered candidate remains available for inspection.
            let _ = cleanup_staging_entry(
                root,
                &root_directory,
                &cleanup_journal,
                Some(OsStr::new(&staging_name)),
                Some(&expected),
            );
        }
        result
    }

    #[cfg(not(feature = "real-encoder"))]
    {
        let _ = (root, root_directory, expected, operation);
        Err(EncoderError::ArtifactsMissing(
            "real-encoder feature is disabled".to_owned(),
        ))
    }
}

/// Acquires exactly the files named by the release descriptor.
///
/// `fastembed`'s convenience constructor resolves a moving `main` ref.  The
/// lifecycle instead gives `hf-hub` an explicit immutable revision and checks
/// both the URL it is about to request and the snapshot path returned by the
/// server before any bytes are admitted to materialization.
#[cfg(feature = "real-encoder")]
fn acquire_manifest_files(
    acquisition: &ModelAcquisitionManifest,
    download_path: &Path,
) -> Result<(), EncoderError> {
    acquisition.validate()?;
    let endpoint = manifest_endpoint(acquisition)?;
    let api = ApiBuilder::new()
        .with_cache_dir(download_path.to_path_buf())
        .with_endpoint(endpoint)
        .with_progress(false)
        .with_retries(3)
        .build()
        .map_err(|error| {
            EncoderError::Inference(format!("initialize pinned model client: {error}"))
        })?;
    let repository = api.repo(Repo::with_revision(
        acquisition.repository.clone(),
        RepoType::Model,
        acquisition.revision.clone(),
    ));

    for file in &acquisition.files {
        if repository.url(&file.path) != file.url {
            return Err(EncoderError::ArtifactMismatch(format!(
                "acquisition client URL differs from the release pin for {}",
                file.path
            )));
        }
        let downloaded = repository.get(&file.path).map_err(|error| {
            EncoderError::Inference(format!(
                "acquire pinned model artifact {}@{}: {error}",
                acquisition.repository, acquisition.revision
            ))
        })?;
        let expected_path = download_path
            .join(CACHE_REPOSITORY_DIR)
            .join("snapshots")
            .join(&acquisition.revision)
            .join(&file.path);
        if downloaded != expected_path {
            return Err(EncoderError::ArtifactMismatch(format!(
                "acquisition returned a non-pinned snapshot path for {}",
                file.path
            )));
        }
    }

    let download_directory = open_directory_path(download_path)?;
    ensure_cache_main_ref(&download_directory, download_path, &acquisition.revision)?;
    let snapshot = super::cache_snapshot(download_path, Some(acquisition.revision.as_str()))?;
    for file in &acquisition.files {
        let bytes = super::read_snapshot_file_following(&snapshot, &file.path, file.bytes)?;
        if bytes.len() as u64 != file.bytes || digest_bytes(&bytes) != file.sha256 {
            return Err(EncoderError::ArtifactMismatch(format!(
                "downloaded artifact does not match the release pin for {}",
                file.path
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "real-encoder")]
fn manifest_endpoint(acquisition: &ModelAcquisitionManifest) -> Result<String, EncoderError> {
    let suffix = format!(
        "{}/resolve/{}/",
        acquisition.repository, acquisition.revision
    );
    let endpoint = acquisition
        .base_url
        .strip_suffix(&suffix)
        .and_then(|prefix| prefix.strip_suffix('/'))
        .filter(|prefix| prefix.starts_with("https://") && !prefix.contains('?'))
        .ok_or_else(|| {
            EncoderError::ArtifactMismatch(
                "release acquisition base URL is not revision-bound".to_owned(),
            )
        })?;
    Ok(endpoint.to_owned())
}

#[cfg(feature = "real-encoder")]
fn ensure_cache_main_ref(
    download_directory: &Dir,
    download_path: &Path,
    revision: &str,
) -> Result<(), EncoderError> {
    let repository_path = download_path.join(CACHE_REPOSITORY_DIR);
    let repository = open_directory_nofollow(
        download_directory,
        OsStr::new(CACHE_REPOSITORY_DIR),
        &repository_path,
    )?;
    let refs_path = repository_path.join("refs");
    let refs = open_directory_nofollow(&repository, OsStr::new("refs"), &refs_path)?;
    let main_path = refs_path.join("main");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    match refs.open_with(OsStr::new("main"), &options) {
        Ok(mut file) => {
            file.write_all(revision.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error("write pinned model cache ref", &main_path, error))?;
            drop(file);
            sync_directory(&refs, &refs_path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = read_file_nofollow(&refs, OsStr::new("main"), &main_path, 256)?;
            let actual = std::str::from_utf8(&bytes).map_err(|error| {
                EncoderError::ArtifactMismatch(format!(
                    "decode pinned model cache ref {}: {error}",
                    main_path.display()
                ))
            })?;
            if actual.trim() != revision {
                return Err(EncoderError::ArtifactMismatch(
                    "model cache ref points at an unexpected revision".to_owned(),
                ));
            }
        }
        Err(error) => return Err(io_error("create pinned model cache ref", &main_path, error)),
    }
    Ok(())
}

#[cfg(feature = "real-encoder")]
fn publish_candidate(
    root: &StateRoot,
    root_directory: &Dir,
    mut journal: LifecycleJournal,
    staging_path: &Path,
    staging_directory: Dir,
    acquisition: &ModelAcquisitionManifest,
    manifest: &PinnedEncoder,
) -> Result<(), EncoderError> {
    let staging_name = staging_path.file_name().ok_or_else(|| {
        EncoderError::ArtifactMismatch("staged model root has no directory name".to_owned())
    })?;
    let backup_name = journal.backup_name.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("publication journal has no backup name".to_owned())
    })?;
    let models_path = root.models_dir();
    let backup_path = root.path().join(backup_name);

    if path_entry_exists(root_directory, OsStr::new(backup_name), &backup_path)? {
        return Err(EncoderError::ArtifactMismatch(
            "model backup entry already exists".to_owned(),
        ));
    }
    let current_before = digest_optional_entry(root_directory, OsStr::new("models"), &models_path)?;
    if current_before != journal.before_digest {
        let _ = remove_journal_at(root_directory, root.path());
        return Err(EncoderError::ArtifactMismatch(
            "live model tree changed before publication".to_owned(),
        ));
    }

    if let Err(error) = tracedecay_private_fs::capability_dir::rename_noreplace(
        root_directory,
        OsStr::new("models"),
        root_directory,
        OsStr::new(backup_name),
    ) && error.kind() != std::io::ErrorKind::NotFound
    {
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            io_error("move previous model tree to backup", &models_path, error),
        );
    }
    sync_directory(root_directory, root.path())?;
    journal.phase = Phase::BackedUp;
    write_journal_at(root_directory, root.path(), &journal)?;

    // The candidate is below the staging root.  Rename it through the open
    // staging capability so a swapped path cannot redirect publication.
    let candidate_path = staging_path.join(CANDIDATE_DIRECTORY);
    let staged_digest = digest_optional_entry(
        &staging_directory,
        OsStr::new(CANDIDATE_DIRECTORY),
        &candidate_path,
    )?
    .ok_or_else(|| EncoderError::ArtifactsMissing(candidate_path.display().to_string()))?;
    if journal.after_digest.as_deref() != Some(staged_digest.as_str()) {
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            EncoderError::ArtifactMismatch(
                "staged model candidate changed before publication".to_owned(),
            ),
        );
    }
    validate_candidate_structure(&candidate_path, manifest)?;
    let verified_staged_digest = digest_optional_entry(
        &staging_directory,
        OsStr::new(CANDIDATE_DIRECTORY),
        &candidate_path,
    )?
    .ok_or_else(|| EncoderError::ArtifactsMissing(candidate_path.display().to_string()))?;
    if journal.after_digest.as_deref() != Some(verified_staged_digest.as_str()) {
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            EncoderError::ArtifactMismatch(
                "staged model candidate changed during publication verification".to_owned(),
            ),
        );
    }
    if let Err(error) = tracedecay_private_fs::capability_dir::rename_noreplace(
        &staging_directory,
        OsStr::new(CANDIDATE_DIRECTORY),
        root_directory,
        OsStr::new("models"),
    ) {
        let detail = io_error("publish verified model tree", &models_path, error);
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            detail,
        );
    }
    sync_directory(root_directory, root.path())?;
    journal.phase = Phase::Published;
    write_journal_at(root_directory, root.path(), &journal)?;

    let published = root.models_dir();
    let published_digest = digest_optional_entry(root_directory, OsStr::new("models"), &published)?;
    if validate_candidate(&published, manifest).is_err()
        || journal.after_digest.as_deref() != published_digest.as_deref()
    {
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            EncoderError::ArtifactMismatch("published model tree failed verification".to_owned()),
        );
    }

    let tree_digest = published_digest.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("published journal has no candidate digest".to_owned())
    })?;
    write_and_verify_acquisition_receipt(
        root,
        root_directory,
        acquisition,
        journal.operation,
        "committed",
        &journal.operation_id,
        tree_digest,
    )?;

    // Receipt publication is the final commit boundary. Re-read the live
    // candidate after writing it so a mutation in the receipt window cannot
    // leave a durable receipt that names a different tree.
    let final_digest = digest_optional_entry(root_directory, OsStr::new("models"), &published)?;
    if final_digest.as_deref() != Some(tree_digest) {
        return rollback_after_publish_failure(
            root,
            root_directory,
            &journal,
            staging_name,
            &models_path,
            manifest,
            EncoderError::ArtifactMismatch(
                "published model tree changed while committing its acquisition receipt".to_owned(),
            ),
        );
    }

    if path_entry_exists(root_directory, OsStr::new(backup_name), &backup_path)? {
        remove_verified_directory_entry(
            root_directory,
            OsStr::new(backup_name),
            &backup_path,
            journal.before_digest.as_deref().ok_or_else(|| {
                EncoderError::ArtifactMismatch(
                    "publication backup has no original tree digest".to_owned(),
                )
            })?,
        )?;
    }
    // Windows refuses to remove a directory while a handle to it is open.
    drop(staging_directory);
    cleanup_staging_entry(
        root,
        root_directory,
        &journal,
        Some(staging_name),
        Some(manifest),
    )?;
    sync_directory(root_directory, root.path())?;
    remove_journal_at(root_directory, root.path())
}

#[cfg(feature = "real-encoder")]
fn rollback_after_publish_failure(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    staging_name: &OsStr,
    models_path: &Path,
    expected: &PinnedEncoder,
    fallback: EncoderError,
) -> Result<(), EncoderError> {
    let rollback_result = rollback_to_before(
        root,
        root_directory,
        journal,
        Some(staging_name),
        models_path,
        Some(expected),
    );
    match rollback_result {
        Ok(()) => {
            let _ = remove_journal_at(root_directory, root.path());
            Err(fallback)
        }
        Err(error) => Err(EncoderError::Inference(format!(
            "model publication failed ({fallback}); rollback failed: {error}"
        ))),
    }
}

fn rollback_to_before(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    staging_name: Option<&OsStr>,
    models_path: &Path,
    expected: Option<&PinnedEncoder>,
) -> Result<(), EncoderError> {
    let backup_name = journal.backup_name.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("journal has no rollback backup".to_owned())
    })?;
    let backup_path = root.path().join(backup_name);
    let live_digest = digest_optional_entry(root_directory, OsStr::new("models"), models_path)?;
    let backup_digest =
        digest_optional_entry(root_directory, OsStr::new(backup_name), &backup_path)?;

    match journal.operation {
        Operation::Uninstall => {
            if let Some(backup_digest) = backup_digest.as_deref()
                && Some(backup_digest) != journal.before_digest.as_deref()
            {
                return Err(EncoderError::ArtifactMismatch(
                    "uninstall rollback backup changed outside the transaction".to_owned(),
                ));
            }
            if backup_digest.is_some() && live_digest.is_some() {
                return Err(EncoderError::ArtifactMismatch(
                    "uninstall recovery found both live and backup model trees".to_owned(),
                ));
            }
            match (live_digest.as_deref(), backup_digest.as_deref()) {
                (Some(live), None) if Some(live) == journal.before_digest.as_deref() => {}
                (None, Some(_)) => {
                    restore_backup(root, root_directory, journal, models_path)?;
                }
                (None, None) => {
                    return Err(EncoderError::ArtifactsMissing(
                        "uninstall rollback backup is missing".to_owned(),
                    ));
                }
                (Some(_), _) => {
                    return Err(EncoderError::ArtifactMismatch(
                        "live model tree changed during uninstall recovery".to_owned(),
                    ));
                }
            }
        }
        Operation::Install | Operation::Update => {
            let candidate_is_live = match journal.phase {
                Phase::Prepared | Phase::Staged => {
                    if backup_digest.is_some() {
                        if let Some(live) = live_digest.as_deref() {
                            let after = journal.after_digest.as_deref().ok_or_else(|| {
                                EncoderError::ArtifactMismatch(
                                    "publication backup has a live tree without a candidate digest"
                                        .to_owned(),
                                )
                            })?;
                            if live != after {
                                return Err(EncoderError::ArtifactMismatch(
                                    "rollback found an unexpected live tree beside its backup"
                                        .to_owned(),
                                ));
                            }
                            let expected = expected.ok_or_else(|| {
                                EncoderError::ArtifactMismatch(
                                    "recovery has no pinned candidate manifest".to_owned(),
                                )
                            })?;
                            validate_candidate_structure(models_path, expected)?;
                            true
                        } else {
                            false
                        }
                    } else {
                        if live_digest.as_deref() == journal.before_digest.as_deref() {
                            false
                        } else if journal.before_digest.is_none()
                            && live_digest.as_deref() == journal.after_digest.as_deref()
                        {
                            let expected = expected.ok_or_else(|| {
                                EncoderError::ArtifactMismatch(
                                    "recovery has no pinned candidate manifest".to_owned(),
                                )
                            })?;
                            validate_candidate_structure(models_path, expected)?;
                            let verified = digest_optional_entry(
                                root_directory,
                                OsStr::new("models"),
                                models_path,
                            )?
                            .ok_or_else(|| {
                                EncoderError::ArtifactsMissing(models_path.display().to_string())
                            })?;
                            if Some(verified.as_str()) != journal.after_digest.as_deref() {
                                return Err(EncoderError::ArtifactMismatch(
                                    "live model candidate changed during recovery".to_owned(),
                                ));
                            }
                            true
                        } else {
                            verify_before_digest(
                                live_digest.as_deref(),
                                journal.before_digest.as_deref(),
                            )?;
                            false
                        }
                    }
                }
                Phase::BackedUp | Phase::Published => {
                    if let Some(live) = live_digest.as_deref() {
                        let after = journal.after_digest.as_deref().ok_or_else(|| {
                            EncoderError::ArtifactMismatch(
                                "publication phase has no candidate digest".to_owned(),
                            )
                        })?;
                        if live != after {
                            return Err(EncoderError::ArtifactMismatch(
                                "live model tree changed outside the model transaction".to_owned(),
                            ));
                        }
                        let expected = expected.ok_or_else(|| {
                            EncoderError::ArtifactMismatch(
                                "recovery has no pinned candidate manifest".to_owned(),
                            )
                        })?;
                        validate_candidate_structure(models_path, expected)?;
                        true
                    } else {
                        false
                    }
                }
            };

            if backup_digest.is_some()
                && !candidate_is_live
                && live_digest.as_deref() == journal.before_digest.as_deref()
            {
                remove_verified_directory_entry(
                    root_directory,
                    OsStr::new(backup_name),
                    &backup_path,
                    journal.before_digest.as_deref().ok_or_else(|| {
                        EncoderError::ArtifactMismatch(
                            "publication backup has no original tree digest".to_owned(),
                        )
                    })?,
                )?;
            } else if backup_digest.is_some() {
                if journal.before_digest.is_none() {
                    return Err(EncoderError::ArtifactMismatch(
                        "publication backup has no original tree digest".to_owned(),
                    ));
                }
                if live_digest.is_some() && !candidate_is_live {
                    return Err(EncoderError::ArtifactMismatch(
                        "rollback found an unexpected live tree beside its backup".to_owned(),
                    ));
                }
                if candidate_is_live {
                    move_live_candidate_aside_and_restore_backup(
                        root,
                        root_directory,
                        journal,
                        models_path,
                        expected,
                    )?;
                } else {
                    restore_backup(root, root_directory, journal, models_path)?;
                }
            } else if candidate_is_live {
                if journal.before_digest.is_some() {
                    return Err(EncoderError::ArtifactsMissing(
                        "publication backup is missing; live candidate retained".to_owned(),
                    ));
                }
                // An install with no previous tree can safely remove its
                // candidate, but only after the digest and structural checks
                // above have proved that this is the transaction's tree.
                remove_verified_directory_entry(
                    root_directory,
                    OsStr::new("models"),
                    models_path,
                    journal.after_digest.as_deref().ok_or_else(|| {
                        EncoderError::ArtifactMismatch(
                            "live candidate has no expected digest".to_owned(),
                        )
                    })?,
                )?;
            } else if matches!(journal.phase, Phase::BackedUp | Phase::Published)
                && !(journal.before_digest.is_none() && live_digest.is_none())
            {
                return Err(EncoderError::ArtifactsMissing(
                    "model publication has neither its live candidate nor rollback backup"
                        .to_owned(),
                ));
            }
        }
    }
    cleanup_staging_entry(root, root_directory, journal, staging_name, expected)?;
    sync_directory(root_directory, root.path())
}

fn verify_before_digest(actual: Option<&str>, expected: Option<&str>) -> Result<(), EncoderError> {
    if actual != expected {
        return Err(EncoderError::ArtifactMismatch(
            "live model tree changed before publication recovery".to_owned(),
        ));
    }
    Ok(())
}

fn restore_backup(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    models_path: &Path,
) -> Result<(), EncoderError> {
    let backup_name = journal.backup_name.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("journal has no rollback backup".to_owned())
    })?;
    verify_backup_digest(root_directory, root, journal, backup_name)?;
    tracedecay_private_fs::capability_dir::rename_noreplace(
        root_directory,
        OsStr::new(backup_name),
        root_directory,
        OsStr::new("models"),
    )
    .map_err(|error| io_error("restore model rollback backup", models_path, error))?;
    let restored = digest_optional_entry(root_directory, OsStr::new("models"), models_path)?;
    if restored.as_deref() != journal.before_digest.as_deref() {
        return Err(EncoderError::ArtifactMismatch(
            "restored model rollback backup changed during recovery".to_owned(),
        ));
    }
    Ok(())
}

fn move_live_candidate_aside_and_restore_backup(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    models_path: &Path,
    expected: Option<&PinnedEncoder>,
) -> Result<(), EncoderError> {
    if journal.backup_name.is_none() {
        return Err(EncoderError::ArtifactMismatch(
            "journal has no rollback backup".to_owned(),
        ));
    }
    let rollback_name = format!("{ROLLBACK_PREFIX}{}", journal.operation_id);
    let rollback_path = root.path().join(&rollback_name);
    if path_entry_exists(root_directory, OsStr::new(&rollback_name), &rollback_path)? {
        return Err(EncoderError::ArtifactMismatch(
            "model rollback entry already exists".to_owned(),
        ));
    }
    let after = journal.after_digest.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("live candidate has no expected digest".to_owned())
    })?;
    let candidate_manifest = expected.ok_or_else(|| {
        EncoderError::ArtifactMismatch("recovery has no pinned candidate manifest".to_owned())
    })?;
    let live_before = digest_optional_entry(root_directory, OsStr::new("models"), models_path)?;
    if live_before.as_deref() != Some(after) {
        return Err(EncoderError::ArtifactMismatch(
            "live model candidate changed during recovery".to_owned(),
        ));
    }
    validate_candidate_structure(models_path, candidate_manifest)?;
    tracedecay_private_fs::capability_dir::rename_noreplace(
        root_directory,
        OsStr::new("models"),
        root_directory,
        OsStr::new(&rollback_name),
    )
    .map_err(|error| io_error("move failed model tree aside", models_path, error))?;

    let moved_digest =
        digest_optional_entry(root_directory, OsStr::new(&rollback_name), &rollback_path)?;
    if moved_digest.as_deref() != Some(after) {
        return Err(EncoderError::ArtifactMismatch(
            "moved model candidate changed during recovery".to_owned(),
        ));
    }
    validate_candidate_structure(&rollback_path, candidate_manifest)?;
    restore_backup(root, root_directory, journal, models_path)?;
    let final_digest = digest_optional_entry(root_directory, OsStr::new("models"), models_path)?;
    if final_digest.as_deref() != journal.before_digest.as_deref() {
        return Err(EncoderError::ArtifactMismatch(
            "restored model tree changed during recovery".to_owned(),
        ));
    }
    let moved_after_restore =
        digest_optional_entry(root_directory, OsStr::new(&rollback_name), &rollback_path)?;
    if moved_after_restore.as_deref() != Some(after) {
        return Err(EncoderError::ArtifactMismatch(
            "rollback candidate changed before cleanup".to_owned(),
        ));
    }
    remove_verified_directory_entry(
        root_directory,
        OsStr::new(&rollback_name),
        &rollback_path,
        after,
    )
}

fn cleanup_staging_entry(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    staging_name: Option<&OsStr>,
    expected: Option<&PinnedEncoder>,
) -> Result<(), EncoderError> {
    let Some(staging_name) = staging_name else {
        return Ok(());
    };
    let staging_path = root.path().join(staging_name);
    let staging = match open_directory_nofollow(root_directory, staging_name, &staging_path) {
        Ok(directory) => directory,
        Err(EncoderError::ArtifactsMissing(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let candidate_path = staging_path.join("candidate");
    let candidate =
        match open_directory_nofollow(&staging, OsStr::new("candidate"), &candidate_path) {
            Ok(directory) => Some(directory),
            Err(EncoderError::ArtifactsMissing(_)) => None,
            Err(error) => return Err(error),
        };
    if let Some(candidate) = candidate {
        if let Some(after) = journal.after_digest.as_deref() {
            let actual = digest_directory_handle(&candidate, &candidate_path)?;
            if actual != after {
                return Err(EncoderError::ArtifactMismatch(
                    "staging candidate changed outside the model transaction".to_owned(),
                ));
            }
            let expected = expected.ok_or_else(|| {
                EncoderError::ArtifactMismatch(
                    "staging candidate has no pinned manifest".to_owned(),
                )
            })?;
            validate_candidate_structure(&candidate_path, expected)?;
            let verified = digest_directory_handle(&candidate, &candidate_path)?;
            if verified != after {
                return Err(EncoderError::ArtifactMismatch(
                    "staging candidate changed during structural verification".to_owned(),
                ));
            }
        } else {
            // A prepared journal has not admitted a candidate digest yet. A
            // crash during candidate construction can therefore discard this
            // transaction-owned partial tree without guessing at its content.
            remove_open_directory(&staging, candidate, &candidate_path)?;
        }
    }
    remove_open_directory(root_directory, staging, &staging_path)
}

fn recover_journal(
    root: &StateRoot,
    root_directory: &Dir,
    journal: &LifecycleJournal,
    acquisition: &ModelAcquisitionManifest,
) -> Result<(), EncoderError> {
    let models_path = root.models_dir();
    let expected = match journal.operation {
        Operation::Install | Operation::Update => Some(acquisition.pinned_encoder()?),
        Operation::Uninstall => None,
    };
    match journal.phase {
        Phase::Prepared | Phase::Staged | Phase::BackedUp => {
            rollback_to_before(
                root,
                root_directory,
                journal,
                journal.staging_name.as_deref().map(OsStr::new),
                &models_path,
                expected.as_ref(),
            )?;
        }
        Phase::Published => match journal.operation {
            Operation::Uninstall => {
                if path_entry_exists(root_directory, OsStr::new("models"), &models_path)? {
                    return Err(EncoderError::ArtifactMismatch(
                        "uninstall journal found a live model tree".to_owned(),
                    ));
                }
                if let Some(name) = journal.backup_name.as_deref()
                    && path_entry_exists(root_directory, OsStr::new(name), &root.path().join(name))?
                {
                    remove_verified_directory_entry(
                        root_directory,
                        OsStr::new(name),
                        &root.path().join(name),
                        journal.before_digest.as_deref().ok_or_else(|| {
                            EncoderError::ArtifactMismatch(
                                "uninstall backup has no original tree digest".to_owned(),
                            )
                        })?,
                    )?;
                }
            }
            Operation::Install | Operation::Update => {
                let Some(expected_digest) = journal.after_digest.as_deref() else {
                    return Err(EncoderError::ArtifactMismatch(
                        "publish journal has no candidate digest".to_owned(),
                    ));
                };
                let Some(actual) =
                    digest_optional_entry(root_directory, OsStr::new("models"), &models_path)?
                else {
                    return Err(EncoderError::ArtifactMismatch(
                        "published model tree is missing during recovery".to_owned(),
                    ));
                };
                if actual != expected_digest {
                    return Err(EncoderError::ArtifactMismatch(
                        "published model tree changed outside the model transaction".to_owned(),
                    ));
                }
                let expected = expected.as_ref().ok_or_else(|| {
                    EncoderError::ArtifactMismatch(
                        "published journal has no pinned candidate manifest".to_owned(),
                    )
                })?;
                validate_candidate_structure(&models_path, expected)?;
                let verified_digest =
                    digest_optional_entry(root_directory, OsStr::new("models"), &models_path)?
                        .ok_or_else(|| {
                            EncoderError::ArtifactsMissing(models_path.display().to_string())
                        })?;
                if verified_digest != expected_digest {
                    return Err(EncoderError::ArtifactMismatch(
                        "published model tree changed during structural verification".to_owned(),
                    ));
                }
                match read_acquisition_receipt(root, root_directory, acquisition)? {
                    Some(receipt) => validate_acquisition_receipt(
                        &receipt,
                        root,
                        acquisition,
                        journal.operation,
                        "committed",
                        &journal.operation_id,
                        expected_digest,
                    )?,
                    None => write_and_verify_acquisition_receipt(
                        root,
                        root_directory,
                        acquisition,
                        journal.operation,
                        "committed",
                        &journal.operation_id,
                        expected_digest,
                    )?,
                }
                if let Some(name) = journal.backup_name.as_deref()
                    && path_entry_exists(root_directory, OsStr::new(name), &root.path().join(name))?
                {
                    remove_verified_directory_entry(
                        root_directory,
                        OsStr::new(name),
                        &root.path().join(name),
                        journal.before_digest.as_deref().ok_or_else(|| {
                            EncoderError::ArtifactMismatch(
                                "publication backup has no original tree digest".to_owned(),
                            )
                        })?,
                    )?;
                }
            }
        },
    }
    cleanup_staging_entry(
        root,
        root_directory,
        journal,
        journal.staging_name.as_deref().map(OsStr::new),
        expected.as_ref(),
    )?;
    sync_directory(root_directory, root.path())?;
    remove_journal_at(root_directory, root.path())
}

/// Verifies the complete published release tree and its durable acquisition
/// receipt without constructing an inference session.
pub(crate) fn verify_installed(root: &StateRoot) -> Result<(), EncoderError> {
    let expected = ModelAcquisitionManifest::reference()?.pinned_encoder()?;
    validate_candidate_structure(&root.models_dir(), &expected)?;
    verify_installed_receipt(root)
}

/// Verifies the published tree layout and binds its one content digest to the
/// durable acquisition receipt. Callers that load the model verify the pinned
/// artifact bytes themselves; a tree changed after that load no longer
/// matches the receipt digest, so no second full-tree pass is needed.
pub(crate) fn verify_installed_receipt(root: &StateRoot) -> Result<(), EncoderError> {
    let root_directory = open_root_directory(root)?;
    let acquisition = ModelAcquisitionManifest::reference()?;
    let expected = acquisition.pinned_encoder()?;
    validate_manifest_shape(&expected)?;
    let models_path = root.models_dir();
    exact_layout(&models_path)?;
    let tree_digest =
        digest_optional_entry(&root_directory, OsStr::new("models"), &models_path)?
            .ok_or_else(|| EncoderError::ArtifactsMissing(models_path.display().to_string()))?;
    let receipt =
        read_acquisition_receipt(root, &root_directory, &acquisition)?.ok_or_else(|| {
            EncoderError::ArtifactsMissing(
                root.path()
                    .join(MODEL_ACQUISITION_RECEIPT_PATH)
                    .display()
                    .to_string(),
            )
        })?;
    let valid_outcome = matches!(
        (receipt.operation, receipt.outcome.as_str()),
        (Operation::Install, "committed" | "already_present") | (Operation::Update, "committed")
    );
    if !valid_outcome {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt has an invalid published outcome".to_owned(),
        ));
    }
    validate_acquisition_receipt(
        &receipt,
        root,
        &acquisition,
        receipt.operation,
        &receipt.outcome,
        &receipt.operation_id,
        &tree_digest,
    )
}

#[cfg(feature = "real-encoder")]
fn has_exact_verified_model(
    root_directory: &Dir,
    root: &StateRoot,
    expected: &PinnedEncoder,
) -> Result<bool, EncoderError> {
    let Some(models) =
        open_optional_directory(root_directory, OsStr::new("models"), &root.models_dir())?
    else {
        return Ok(false);
    };
    let _ = models;
    validate_candidate(&root.models_dir(), expected)
        .map(|()| true)
        .or_else(|error| {
            if matches!(error, EncoderError::ArtifactsMissing(_)) {
                Ok(false)
            } else {
                Err(error)
            }
        })
}

#[cfg(feature = "real-encoder")]
fn validate_candidate(path: &Path, expected: &PinnedEncoder) -> Result<(), EncoderError> {
    validate_candidate_structure(path, expected)?;
    super::validate_materialized_encoder(path, expected)
}

fn validate_candidate_structure(path: &Path, expected: &PinnedEncoder) -> Result<(), EncoderError> {
    validate_manifest_shape(expected)?;
    super::verify_cached_state(path, expected)?;
    exact_layout(path)?;
    Ok(())
}

fn exact_layout(models_path: &Path) -> Result<(), EncoderError> {
    let models = open_directory_path(models_path)?;
    expect_entries(
        &models,
        models_path,
        &[CACHE_REPOSITORY_DIR],
        &[MANIFEST_FILENAME],
    )?;
    let repository_path = models_path.join(CACHE_REPOSITORY_DIR);
    let repository =
        open_directory_nofollow(&models, OsStr::new(CACHE_REPOSITORY_DIR), &repository_path)?;
    expect_entries(&repository, &repository_path, &["refs", "snapshots"], &[])?;
    let refs_path = repository_path.join("refs");
    let refs = open_directory_nofollow(&repository, OsStr::new("refs"), &refs_path)?;
    expect_entries(&refs, &refs_path, &[], &["main"])?;
    let snapshots_path = repository_path.join("snapshots");
    let snapshots = open_directory_nofollow(&repository, OsStr::new("snapshots"), &snapshots_path)?;
    expect_entries(&snapshots, &snapshots_path, &[MODEL_REVISION], &[])?;
    let snapshot_path = snapshots_path.join(MODEL_REVISION);
    let snapshot = open_directory_nofollow(&snapshots, OsStr::new(MODEL_REVISION), &snapshot_path)?;
    expect_entries(&snapshot, &snapshot_path, &["onnx"], &REQUIRED_FILES[1..])?;
    let onnx_path = snapshot_path.join("onnx");
    let onnx = open_directory_nofollow(&snapshot, OsStr::new("onnx"), &onnx_path)?;
    expect_entries(&onnx, &onnx_path, &[], &["model.onnx"])
}

fn expect_entries(
    directory: &Dir,
    path: &Path,
    expected_directories: &[&str],
    expected_files: &[&str],
) -> Result<(), EncoderError> {
    let mut seen = Vec::new();
    for entry in directory
        .read_dir(".")
        .map_err(|error| io_error("list model directory", path, error))?
    {
        let entry = entry.map_err(|error| io_error("read model directory", path, error))?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("inspect model directory entry", path, error))?;
        if file_type.is_symlink() {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle path is a symlink: {}",
                path.join(&name).display()
            )));
        }
        let name_text = name.to_string_lossy();
        if file_type.is_dir() {
            if !expected_directories
                .iter()
                .any(|expected| *expected == name_text)
            {
                return Err(EncoderError::ArtifactMismatch(format!(
                    "unexpected model directory entry {}",
                    path.join(&name).display()
                )));
            }
        } else if file_type.is_file() {
            if !expected_files.iter().any(|expected| *expected == name_text) {
                return Err(EncoderError::ArtifactMismatch(format!(
                    "unexpected model file {}",
                    path.join(&name).display()
                )));
            }
        } else {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model directory entry is not a regular object: {}",
                path.join(&name).display()
            )));
        }
        seen.push((name_text.into_owned(), file_type.is_dir()));
    }
    for expected in expected_directories {
        if !seen
            .iter()
            .any(|(name, directory)| name == expected && *directory)
        {
            return Err(EncoderError::ArtifactsMissing(
                path.join(expected).display().to_string(),
            ));
        }
    }
    for expected in expected_files {
        if !seen
            .iter()
            .any(|(name, directory)| name == expected && !*directory)
        {
            return Err(EncoderError::ArtifactsMissing(
                path.join(expected).display().to_string(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Install,
    Update,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Staged,
    BackedUp,
    Published,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleJournal {
    schema_version: u16,
    operation_id: String,
    operation: Operation,
    phase: Phase,
    revision: String,
    staging_name: Option<String>,
    backup_name: Option<String>,
    before_digest: Option<String>,
    after_digest: Option<String>,
}

fn operation_id(operation: Operation) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let digest = Sha256::digest(
        format!(
            "ncm-model-lifecycle.v1|{operation:?}|{now}|{counter}|{}",
            std::process::id(),
        )
        .as_bytes(),
    );
    let nonce = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{now:x}-{nonce}-{}",
        match operation {
            Operation::Install => "install",
            Operation::Update => "update",
            Operation::Uninstall => "uninstall",
        }
    )
}

#[cfg(feature = "real-encoder")]
fn create_private_staging(
    root_directory: &Dir,
    root: &Path,
    name: &str,
) -> Result<(PathBuf, Dir), EncoderError> {
    let path = root.join(name);
    match root_directory.create_dir(OsStr::new(name)) {
        Ok(()) => {
            let directory =
                secure_private_directory_entry(root_directory, OsStr::new(name), &path)?;
            Ok((path, directory))
        }
        Err(error) => Err(io_error("create model staging directory", &path, error)),
    }
}

#[cfg(feature = "real-encoder")]
fn create_private_directory(
    parent: &Dir,
    parent_path: &Path,
    name: &str,
) -> Result<PathBuf, EncoderError> {
    let path = parent_path.join(name);
    parent
        .create_dir(OsStr::new(name))
        .map_err(|error| io_error("create model staging child", &path, error))?;
    drop(secure_private_directory_entry(
        parent,
        OsStr::new(name),
        &path,
    )?);
    Ok(path)
}

fn secure_private_directory_entry(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
) -> Result<Dir, EncoderError> {
    let mut options = OpenOptions::new();
    // `maybe_dir`: Windows grants a directory handle only with backup
    // semantics and refuses the open as access denied otherwise.
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = parent
        .open_with(name, &options)
        .map_err(|error| io_error("open model staging directory for privacy", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect model staging directory for privacy", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(EncoderError::ArtifactMismatch(format!(
            "model staging entry is not a directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        file.set_permissions(cap_std::fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("secure model staging directory", path, error))?;
        Ok(Dir::from_std_file(file.into_std()))
    }
    #[cfg(windows)]
    {
        drop(file);
        tracedecay_private_fs::make_private_directory(path)
            .map_err(|error| io_error("secure model staging directory", path, error))?;
        open_directory_nofollow(parent, name, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        drop(file);
        tracedecay_private_fs::make_private_directory(path)
            .map_err(|error| io_error("secure model staging directory", path, error))?;
        open_directory_nofollow(parent, name, path)
    }
}

fn read_journal_at(
    root_directory: &Dir,
    root: &Path,
) -> Result<Option<LifecycleJournal>, EncoderError> {
    let path = root.join(JOURNAL_FILENAME);
    let file = match open_file_nofollow(root_directory, OsStr::new(JOURNAL_FILENAME), &path) {
        Ok(file) => file,
        Err(EncoderError::ArtifactsMissing(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let length = file
        .metadata()
        .map_err(|error| io_error("inspect model lifecycle journal", &path, error))?
        .len();
    if length == 0 || length > MAX_JOURNAL_BYTES {
        return Err(EncoderError::ArtifactMismatch(
            "model lifecycle journal exceeds its bounded size".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read model lifecycle journal", &path, error))?;
    if bytes.len() as u64 != length {
        return Err(EncoderError::ArtifactMismatch(
            "model lifecycle journal changed during read".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        EncoderError::ArtifactMismatch(format!("parse model lifecycle journal: {error}"))
    })
}

fn write_journal_at(
    root_directory: &Dir,
    root: &Path,
    journal: &LifecycleJournal,
) -> Result<(), EncoderError> {
    validate_journal(journal)?;
    let bytes = journal_bytes(journal)?;
    let path = root.join(JOURNAL_FILENAME);
    super::atomically_replace_file(root_directory, OsStr::new(JOURNAL_FILENAME), &path, &bytes)?;
    tracedecay_private_fs::make_private_file(&path)
        .map(drop)
        .map_err(|error| io_error("secure model lifecycle journal", &path, error))?;
    sync_directory(root_directory, root)
}

fn reserve_journal_at(
    root_directory: &Dir,
    root: &Path,
    journal: &LifecycleJournal,
) -> Result<(), EncoderError> {
    validate_journal(journal)?;
    let bytes = journal_bytes(journal)?;
    let path = root.join(JOURNAL_FILENAME);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut file = match root_directory.open_with(OsStr::new(JOURNAL_FILENAME), &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle has a pending journal at {}; recover it first",
                path.display()
            )));
        }
        Err(error) => return Err(io_error("reserve model lifecycle journal", &path, error)),
    };
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    result.map_err(|error| io_error("write reserved model lifecycle journal", &path, error))?;
    tracedecay_private_fs::make_private_file(&path)
        .map(drop)
        .map_err(|error| io_error("secure reserved model lifecycle journal", &path, error))?;
    sync_directory(root_directory, root)
}

fn refuse_pending_journal_at(root_directory: &Dir, root: &Path) -> Result<(), EncoderError> {
    let path = root.join(JOURNAL_FILENAME);
    match open_file_nofollow(root_directory, OsStr::new(JOURNAL_FILENAME), &path) {
        Ok(_) => Err(EncoderError::ArtifactMismatch(format!(
            "model lifecycle has a pending journal at {}; recover it first",
            path.display()
        ))),
        Err(EncoderError::ArtifactsMissing(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_journal_at(root_directory: &Dir, root: &Path) -> Result<(), EncoderError> {
    let path = root.join(JOURNAL_FILENAME);
    match open_file_nofollow(root_directory, OsStr::new(JOURNAL_FILENAME), &path) {
        Ok(_) => {}
        Err(EncoderError::ArtifactsMissing(_)) => return Ok(()),
        Err(error) => return Err(error),
    }
    root_directory
        .remove_file(OsStr::new(JOURNAL_FILENAME))
        .map_err(|error| io_error("remove model lifecycle journal", &path, error))?;
    sync_directory(root_directory, root)
}

#[cfg(all(test, unix))]
fn write_journal(path: &Path, journal: &LifecycleJournal) -> Result<(), EncoderError> {
    validate_journal(journal)?;
    let bytes = journal_bytes(journal)?;
    tracedecay_private_fs::framed_log::atomic_write(
        path,
        "ncm-model-lifecycle-journal",
        &bytes,
        directory_sync_policy(),
    )
    .map_err(|error| io_error("write model lifecycle journal", path, error))
}

#[cfg(all(test, unix))]
fn reserve_journal(path: &Path, journal: &LifecycleJournal) -> Result<(), EncoderError> {
    validate_journal(journal)?;
    let bytes = journal_bytes(journal)?;
    let mut file = match tracedecay_private_fs::create_private_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle has a pending journal at {}; recover it first",
                path.display()
            )));
        }
        Err(error) => return Err(io_error("reserve model lifecycle journal", path, error)),
    };
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    result.map_err(|error| io_error("write reserved model lifecycle journal", path, error))?;
    tracedecay_private_fs::framed_log::sync_parent_directory(path, directory_sync_policy()).map_err(
        |error| {
            io_error(
                "sync reserved model lifecycle journal directory",
                path,
                error,
            )
        },
    )
}

fn journal_bytes(journal: &LifecycleJournal) -> Result<Vec<u8>, EncoderError> {
    let mut bytes = serde_json::to_vec_pretty(journal).map_err(|error| {
        EncoderError::Inference(format!("encode model lifecycle journal: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionReceiptFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelAcquisitionReceipt {
    schema_version: u16,
    operation_id: String,
    operation: Operation,
    outcome: String,
    model: String,
    repository: String,
    revision: String,
    manifest_sha256: String,
    revision_provenance_sha256: String,
    acquisition_manifest_sha256: String,
    root: String,
    tree_sha256: String,
    files: Vec<AcquisitionReceiptFile>,
    created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_path: Option<String>,
}

fn read_acquisition_receipt(
    root: &StateRoot,
    root_directory: &Dir,
    acquisition: &ModelAcquisitionManifest,
) -> Result<Option<ModelAcquisitionReceipt>, EncoderError> {
    acquisition.validate()?;
    let receipt_path = root.path().join(MODEL_ACQUISITION_RECEIPT_PATH);
    let receipts_path = root.path().join("receipts");
    let receipts =
        match open_directory_nofollow(root_directory, OsStr::new("receipts"), &receipts_path) {
            Ok(directory) => directory,
            Err(EncoderError::ArtifactsMissing(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
    let file = match open_file_nofollow(&receipts, OsStr::new(RECEIPT_FILENAME), &receipt_path) {
        Ok(file) => file,
        Err(EncoderError::ArtifactsMissing(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let length = file
        .metadata()
        .map_err(|error| io_error("inspect model acquisition receipt", &receipt_path, error))?
        .len();
    const MAX_RECEIPT_BYTES: u64 = 4 * 1024 * 1024;
    if length == 0 || length > MAX_RECEIPT_BYTES {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt exceeds its bounded size".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read model acquisition receipt", &receipt_path, error))?;
    if bytes.len() as u64 != length {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt changed during read".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        EncoderError::ArtifactMismatch(format!(
            "parse model acquisition receipt {}: {error}",
            receipt_path.display()
        ))
    })
}

fn validate_acquisition_receipt(
    receipt: &ModelAcquisitionReceipt,
    root: &StateRoot,
    acquisition: &ModelAcquisitionManifest,
    operation: Operation,
    outcome: &str,
    operation_id: &str,
    tree_digest: &str,
) -> Result<(), EncoderError> {
    if receipt.schema_version != 1
        || receipt.operation != operation
        || receipt.operation_id != operation_id
        || !is_valid_operation_id(&receipt.operation_id, operation)
        || receipt.outcome != outcome
        || receipt.model != MODEL_NAME
        || receipt.repository != MODEL_REPOSITORY
        || receipt.revision != MODEL_REVISION
        || receipt.manifest_sha256 != acquisition.embedding_manifest_sha256
        || receipt.revision_provenance_sha256 != acquisition.revision_provenance_sha256
        || receipt.acquisition_manifest_sha256 != acquisition.canonical_sha256()?
        || receipt.root != root.path().display().to_string()
        || receipt.tree_sha256 != tree_digest
        || receipt.files.len() != acquisition.files.len()
        || receipt.created_at_unix == 0
    {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt is not bound to the release contract".to_owned(),
        ));
    }
    if let Some(path) = receipt.receipt_path.as_deref()
        && path
            != root
                .path()
                .join(MODEL_ACQUISITION_RECEIPT_PATH)
                .display()
                .to_string()
    {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt path is not bound to the state root".to_owned(),
        ));
    }
    if !is_sha256_digest(&receipt.manifest_sha256)
        || !is_sha256_digest(&receipt.revision_provenance_sha256)
        || !is_sha256_digest(&receipt.acquisition_manifest_sha256)
        || !is_sha256_digest(&receipt.tree_sha256)
    {
        return Err(EncoderError::ArtifactMismatch(
            "model acquisition receipt contains an invalid digest".to_owned(),
        ));
    }
    let mut paths = std::collections::BTreeSet::new();
    for file in &receipt.files {
        if !paths.insert(file.path.as_str())
            || !is_safe_relative_path(&file.path)
            || !is_sha256_digest(&file.sha256)
        {
            return Err(EncoderError::ArtifactMismatch(
                "model acquisition receipt contains an unsafe file identity".to_owned(),
            ));
        }
        let expected = acquisition
            .files
            .iter()
            .find(|expected| expected.path == file.path)
            .ok_or_else(|| {
                EncoderError::ArtifactMismatch(format!(
                    "model acquisition receipt contains unexpected file {}",
                    file.path
                ))
            })?;
        if file.bytes != expected.bytes || file.sha256 != expected.sha256 {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model acquisition receipt digest differs for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn write_and_verify_acquisition_receipt(
    root: &StateRoot,
    root_directory: &Dir,
    acquisition: &ModelAcquisitionManifest,
    operation: Operation,
    outcome: &str,
    operation_id: &str,
    tree_digest: &str,
) -> Result<(), EncoderError> {
    acquisition.validate()?;
    let current_digest =
        digest_optional_entry(root_directory, OsStr::new("models"), &root.models_dir())?
            .ok_or_else(|| {
                EncoderError::ArtifactsMissing(root.models_dir().display().to_string())
            })?;
    if current_digest != tree_digest {
        return Err(EncoderError::ArtifactMismatch(
            "live model tree changed before committing its acquisition receipt".to_owned(),
        ));
    }
    let receipts_name = OsStr::new("receipts");
    let receipts_path = root.path().join(receipts_name);
    let receipts = match root_directory.create_dir(receipts_name) {
        Ok(()) => secure_private_directory_entry(root_directory, receipts_name, &receipts_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_directory_nofollow(root_directory, receipts_name, &receipts_path)?
        }
        Err(error) => {
            return Err(io_error(
                "create model acquisition receipt directory",
                &receipts_path,
                error,
            ));
        }
    };
    let receipt = ModelAcquisitionReceipt {
        schema_version: 1,
        operation_id: operation_id.to_owned(),
        operation,
        outcome: outcome.to_owned(),
        model: acquisition.model.clone(),
        repository: acquisition.repository.clone(),
        revision: acquisition.revision.clone(),
        manifest_sha256: acquisition.embedding_manifest_sha256.clone(),
        revision_provenance_sha256: acquisition.revision_provenance_sha256.clone(),
        acquisition_manifest_sha256: acquisition.canonical_sha256()?,
        root: root.path().display().to_string(),
        tree_sha256: tree_digest.to_owned(),
        files: acquisition
            .files
            .iter()
            .map(|file| AcquisitionReceiptFile {
                path: file.path.clone(),
                bytes: file.bytes,
                sha256: file.sha256.clone(),
            })
            .collect(),
        created_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        receipt_path: Some(
            root.path()
                .join(MODEL_ACQUISITION_RECEIPT_PATH)
                .display()
                .to_string(),
        ),
    };
    validate_acquisition_receipt(
        &receipt,
        root,
        acquisition,
        operation,
        outcome,
        operation_id,
        tree_digest,
    )?;
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| {
        EncoderError::Inference(format!("encode model acquisition receipt: {error}"))
    })?;
    bytes.push(b'\n');
    let receipt_path = root.path().join(MODEL_ACQUISITION_RECEIPT_PATH);
    super::atomically_replace_file(
        &receipts,
        OsStr::new(RECEIPT_FILENAME),
        &receipt_path,
        &bytes,
    )?;
    tracedecay_private_fs::make_private_file(&receipt_path)
        .map(drop)
        .map_err(|error| io_error("secure model acquisition receipt", &receipt_path, error))?;
    sync_directory(&receipts, &receipts_path)?;
    sync_directory(root_directory, root.path())?;
    let published = read_acquisition_receipt(root, root_directory, acquisition)?
        .ok_or_else(|| EncoderError::ArtifactsMissing(receipt_path.display().to_string()))?;
    validate_acquisition_receipt(
        &published,
        root,
        acquisition,
        operation,
        outcome,
        operation_id,
        tree_digest,
    )?;
    let final_digest =
        digest_optional_entry(root_directory, OsStr::new("models"), &root.models_dir())?
            .ok_or_else(|| {
                EncoderError::ArtifactsMissing(root.models_dir().display().to_string())
            })?;
    if final_digest != tree_digest {
        return Err(EncoderError::ArtifactMismatch(
            "live model tree changed after committing its acquisition receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_journal(journal: &LifecycleJournal) -> Result<(), EncoderError> {
    if journal.schema_version != JOURNAL_SCHEMA_VERSION
        || !is_valid_operation_id(&journal.operation_id, journal.operation)
        || journal.revision != MODEL_REVISION
    {
        return Err(EncoderError::ArtifactMismatch(
            "unsupported model lifecycle journal schema".to_owned(),
        ));
    }
    if journal
        .staging_name
        .as_deref()
        .is_some_and(|name| !is_safe_entry_name(name) || !name.starts_with(STAGING_PREFIX))
        || journal
            .backup_name
            .as_deref()
            .is_some_and(|name| !is_safe_entry_name(name) || !name.starts_with(BACKUP_PREFIX))
    {
        return Err(EncoderError::ArtifactMismatch(
            "model lifecycle journal contains an unsafe private path".to_owned(),
        ));
    }
    for digest in journal
        .before_digest
        .iter()
        .chain(journal.after_digest.iter())
    {
        if !is_sha256_digest(digest) {
            return Err(EncoderError::ArtifactMismatch(
                "model lifecycle journal contains an invalid digest".to_owned(),
            ));
        }
    }
    if matches!(journal.operation, Operation::Uninstall)
        && (journal.staging_name.is_some() || matches!(journal.phase, Phase::Staged))
    {
        return Err(EncoderError::ArtifactMismatch(
            "uninstall journal unexpectedly names staging or staged phase".to_owned(),
        ));
    }
    if !matches!(journal.operation, Operation::Uninstall) {
        let expected_staging = format!("{STAGING_PREFIX}{}", journal.operation_id);
        if journal.staging_name.as_deref() != Some(expected_staging.as_str()) {
            return Err(EncoderError::ArtifactMismatch(
                "model publication journal staging does not match its operation".to_owned(),
            ));
        }
    }
    let expected_backup = format!("{BACKUP_PREFIX}{}", journal.operation_id);
    if journal.backup_name.as_deref() != Some(expected_backup.as_str()) {
        return Err(EncoderError::ArtifactMismatch(
            "model lifecycle journal backup does not match its operation".to_owned(),
        ));
    }
    match journal.operation {
        Operation::Uninstall
            if journal.before_digest.is_none() || journal.after_digest.is_some() =>
        {
            return Err(EncoderError::ArtifactMismatch(
                "uninstall journal has invalid transaction digests".to_owned(),
            ));
        }
        Operation::Install | Operation::Update if journal.phase == Phase::Prepared => {
            if journal.after_digest.is_some() {
                return Err(EncoderError::ArtifactMismatch(
                    "prepared model publication journal already has a candidate digest".to_owned(),
                ));
            }
        }
        Operation::Install | Operation::Update if journal.after_digest.is_none() => {
            return Err(EncoderError::ArtifactMismatch(
                "model publication journal has no candidate digest".to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn is_valid_operation_id(value: &str, operation: Operation) -> bool {
    let suffix = match operation {
        Operation::Install => "-install",
        Operation::Update => "-update",
        Operation::Uninstall => "-uninstall",
    };
    let Some(prefix) = value.strip_suffix(suffix) else {
        return false;
    };
    let mut pieces = prefix.split('-');
    let Some(timestamp) = pieces.next() else {
        return false;
    };
    let Some(nonce) = pieces.next() else {
        return false;
    };
    pieces.next().is_none()
        && !timestamp.is_empty()
        && timestamp
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && nonce.len() == 16
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(all(test, unix))]
fn remove_journal(path: &Path) -> Result<(), EncoderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path)
                .map_err(|error| io_error("remove model lifecycle journal", path, error))?;
            tracedecay_private_fs::framed_log::sync_parent_directory(path, directory_sync_policy())
                .map_err(|error| io_error("sync model lifecycle journal directory", path, error))
        }
        Ok(_) => Err(EncoderError::ArtifactMismatch(
            "model lifecycle journal is not a regular file".to_owned(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect model lifecycle journal", path, error)),
    }
}

fn open_root_directory(root: &StateRoot) -> Result<Dir, EncoderError> {
    validate_root_path(root.path())?;
    let parent = root
        .path()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = root.path().file_name().ok_or_else(|| {
        EncoderError::ArtifactMismatch("state root has no directory name".to_owned())
    })?;
    let parent_directory = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|error| {
        EncoderError::ArtifactMismatch(format!(
            "open state root parent {}: {error}",
            parent.display()
        ))
    })?;
    open_directory_nofollow(&parent_directory, name, root.path())
}

pub(super) fn open_directory_path(path: &Path) -> Result<Dir, EncoderError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        EncoderError::ArtifactMismatch(format!("directory has no name: {}", path.display()))
    })?;
    let parent_directory = Dir::open_ambient_dir(parent, ambient_authority()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EncoderError::ArtifactsMissing(path.display().to_string())
        } else {
            io_error("open model directory parent", parent, error)
        }
    })?;
    open_directory_nofollow(&parent_directory, name, path)
}

fn open_directory_nofollow(parent: &Dir, name: &OsStr, path: &Path) -> Result<Dir, EncoderError> {
    let mut options = OpenOptions::new();
    // `maybe_dir` lets Windows open a directory handle (backup semantics);
    // without it the open is refused with access denied.
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    let file = parent.open_with(name, &options).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EncoderError::ArtifactsMissing(path.display().to_string())
        } else {
            io_error(
                "open model directory without following symlinks",
                path,
                error,
            )
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect model directory", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(EncoderError::ArtifactMismatch(format!(
            "model lifecycle path is not a directory: {}",
            path.display()
        )));
    }
    Ok(Dir::from_std_file(file.into_std()))
}

#[cfg(feature = "real-encoder")]
fn open_optional_directory(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
) -> Result<Option<Dir>, EncoderError> {
    match open_directory_nofollow(parent, name, path) {
        Ok(directory) => Ok(Some(directory)),
        Err(EncoderError::ArtifactsMissing(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn path_entry_exists(parent: &Dir, name: &OsStr, path: &Path) -> Result<bool, EncoderError> {
    let mut options = OpenOptions::new();
    // The entry may be a directory; Windows opens one only with `maybe_dir`.
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .maybe_dir(true);
    match parent.open_with(name, &options) {
        Ok(file) => {
            let metadata = file
                .metadata()
                .map_err(|error| io_error("inspect model lifecycle entry", path, error))?;
            if !metadata.file_type().is_dir() {
                return Err(EncoderError::ArtifactMismatch(format!(
                    "model lifecycle entry is not a directory: {}",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect model lifecycle entry", path, error)),
    }
}

fn digest_optional_entry(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
) -> Result<Option<String>, EncoderError> {
    let directory = match open_directory_nofollow(parent, name, path) {
        Ok(directory) => directory,
        Err(EncoderError::ArtifactsMissing(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    digest_directory_handle(&directory, path).map(Some)
}

fn verify_backup_digest(
    root_directory: &Dir,
    root: &StateRoot,
    journal: &LifecycleJournal,
    backup_name: &str,
) -> Result<(), EncoderError> {
    let expected = journal.before_digest.as_deref().ok_or_else(|| {
        EncoderError::ArtifactMismatch("rollback backup has no expected original digest".to_owned())
    })?;
    let backup_path = root.path().join(backup_name);
    let actual = digest_optional_entry(root_directory, OsStr::new(backup_name), &backup_path)?
        .ok_or_else(|| EncoderError::ArtifactsMissing(backup_path.display().to_string()))?;
    if actual != expected {
        return Err(EncoderError::ArtifactMismatch(
            "rollback backup changed outside the model transaction".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "real-encoder", test))]
fn digest_directory_path(path: &Path) -> Result<String, EncoderError> {
    let directory = open_directory_path(path)?;
    digest_directory_handle(&directory, path)
}

fn digest_directory_handle(directory: &Dir, path: &Path) -> Result<String, EncoderError> {
    let mut hasher = Sha256::new();
    // One heap read buffer serves the whole recursive walk.
    let mut buffer = vec![0_u8; 1024 * 1024];
    digest_directory(directory, path, Path::new(""), &mut hasher, &mut buffer)?;
    Ok(hex_digest(hasher.finalize()))
}

fn digest_directory(
    directory: &Dir,
    path: &Path,
    relative: &Path,
    hasher: &mut Sha256,
    buffer: &mut [u8],
) -> Result<(), EncoderError> {
    let mut entries = Vec::new();
    for entry in directory
        .read_dir(".")
        .map_err(|error| io_error("list model lifecycle tree", path, error))?
    {
        let entry = entry.map_err(|error| io_error("read model lifecycle tree", path, error))?;
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("inspect model lifecycle tree", path, error))?;
        let child_relative = relative.join(&name);
        hasher.update(child_relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        if file_type.is_symlink() {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle tree contains a symlink: {}",
                path.join(&name).display()
            )));
        }
        if file_type.is_dir() {
            let child_path = path.join(&name);
            let child = open_directory_nofollow(directory, &name, &child_path)?;
            hasher.update([b'd', 0]);
            digest_directory(&child, &child_path, &child_relative, hasher, buffer)?;
        } else if file_type.is_file() {
            let child_path = path.join(&name);
            let file = open_file_nofollow(directory, &name, &child_path)?;
            hasher.update([b'f', 0]);
            let mut reader = file;
            loop {
                let read = reader
                    .read(buffer)
                    .map_err(|error| io_error("read model lifecycle tree", &child_path, error))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle tree contains a non-regular entry: {}",
                path.join(&name).display()
            )));
        }
    }
    Ok(())
}

fn open_file_nofollow(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
) -> Result<cap_std::fs::File, EncoderError> {
    open_file_nofollow_with(parent, name, path, false)
}

/// [`open_file_nofollow`] for a handle that will be flushed: Windows'
/// `FlushFileBuffers` refuses a read-only handle with access denied.
#[cfg(feature = "real-encoder")]
fn open_file_nofollow_for_sync(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
) -> Result<cap_std::fs::File, EncoderError> {
    open_file_nofollow_with(parent, name, path, cfg!(windows))
}

fn open_file_nofollow_with(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    write: bool,
) -> Result<cap_std::fs::File, EncoderError> {
    let mut options = OpenOptions::new();
    options.read(true).write(write).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EncoderError::ArtifactsMissing(path.display().to_string())
        } else {
            io_error("open model lifecycle file", path, error)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect model lifecycle file", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(EncoderError::ArtifactMismatch(format!(
            "model lifecycle entry is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn remove_verified_directory_entry(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    expected_digest: &str,
) -> Result<(), EncoderError> {
    let directory = open_directory_nofollow(parent, name, path)?;
    let actual_digest = digest_directory_handle(&directory, path)?;
    if actual_digest != expected_digest {
        return Err(EncoderError::ArtifactMismatch(format!(
            "model lifecycle entry changed before removal: {}",
            path.display()
        )));
    }
    remove_open_directory(parent, directory, path)
}

fn remove_open_directory(parent: &Dir, directory: Dir, path: &Path) -> Result<(), EncoderError> {
    let mut interrupt = || Ok(());
    tracedecay_private_fs::capability_dir::remove_open_dir_all_nofollow(directory, &mut interrupt)
        .map_err(|error| io_error("remove model lifecycle directory", path, error))?;
    tracedecay_private_fs::capability_dir::sync_directory(parent)
        .map_err(|error| io_error("sync model lifecycle directory removal", path, error))
}

fn cleanup_orphan_staging(
    root_directory: &Dir,
    root: &Path,
    reserved_name: &str,
) -> Result<(), EncoderError> {
    let mut orphans = Vec::new();
    for entry in root_directory
        .read_dir(".")
        .map_err(|error| io_error("list model staging entries", root, error))?
    {
        let entry = entry.map_err(|error| io_error("read model staging entry", root, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(operation_id) = name.strip_prefix(STAGING_PREFIX) else {
            continue;
        };
        if name == reserved_name
            || (!is_valid_operation_id(operation_id, Operation::Install)
                && !is_valid_operation_id(operation_id, Operation::Update))
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("inspect model staging entry", &root.join(name), error))?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(EncoderError::ArtifactMismatch(format!(
                "orphan model staging entry is not a directory: {}",
                root.join(name).display()
            )));
        }
        let path = root.join(name);
        let directory = open_directory_nofollow(root_directory, OsStr::new(name), &path)?;
        orphans.push((name.to_owned(), directory));
    }
    let had_orphans = !orphans.is_empty();
    for (name, directory) in orphans {
        let path = root.join(name);
        remove_open_directory(root_directory, directory, &path)?;
    }
    if had_orphans {
        sync_directory(root_directory, root)?;
    }
    Ok(())
}

#[cfg(feature = "real-encoder")]
fn sync_tree_path(path: &Path) -> Result<(), EncoderError> {
    let directory = open_directory_path(path)?;
    sync_tree(&directory, path)
}

#[cfg(feature = "real-encoder")]
fn sync_tree(directory: &Dir, path: &Path) -> Result<(), EncoderError> {
    let mut entries = Vec::new();
    for entry in directory
        .read_dir(".")
        .map_err(|error| io_error("list model lifecycle tree for sync", path, error))?
    {
        let entry =
            entry.map_err(|error| io_error("read model lifecycle tree for sync", path, error))?;
        entries.push(entry);
    }
    for entry in entries {
        let name = entry.file_name();
        let child_path = path.join(&name);
        let file_type = entry.file_type().map_err(|error| {
            io_error("inspect model lifecycle tree for sync", &child_path, error)
        })?;
        if file_type.is_symlink() {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle tree contains a symlink: {}",
                child_path.display()
            )));
        }
        if file_type.is_dir() {
            let child = open_directory_nofollow(directory, &name, &child_path)?;
            sync_tree(&child, &child_path)?;
        } else if file_type.is_file() {
            open_file_nofollow_for_sync(directory, &name, &child_path)?
                .sync_all()
                .map_err(|error| io_error("sync model lifecycle file", &child_path, error))?;
        } else {
            return Err(EncoderError::ArtifactMismatch(format!(
                "model lifecycle tree contains a non-regular entry: {}",
                child_path.display()
            )));
        }
    }
    tracedecay_private_fs::capability_dir::sync_directory(directory)
        .map_err(|error| io_error("sync model lifecycle directory", path, error))
}

fn sync_directory(directory: &Dir, path: &Path) -> Result<(), EncoderError> {
    tracedecay_private_fs::capability_dir::sync_directory(directory)
        .map_err(|error| io_error("sync model lifecycle directory", path, error))
}

#[cfg(all(test, unix))]
fn directory_sync_policy() -> tracedecay_private_fs::framed_log::DirectorySyncPolicy {
    tracedecay_private_fs::framed_log::DirectorySyncPolicy::Strict
}

fn validate_root_path(path: &Path) -> Result<(), EncoderError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(EncoderError::ArtifactMismatch(
            "state root must be absolute and free of parent traversal".to_owned(),
        ));
    }
    Ok(())
}

fn is_safe_entry_name(name: &str) -> bool {
    let path = Path::new(name);
    !name.is_empty()
        && !name.contains('\\')
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> EncoderError {
    EncoderError::Inference(format!("{action} {}: {error}", path.display()))
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn root() -> (tempfile::TempDir, StateRoot) {
        let temp = tempfile::tempdir().expect("create model lifecycle root");
        let root = StateRoot::new(temp.path()).expect("absolute state root");
        (temp, root)
    }

    #[test]
    fn uninstall_rejects_a_symlink_without_touching_its_target() {
        let (_temp, root) = root();
        let models = root.models_dir();
        let outside = tempfile::tempdir().expect("create outside directory");
        fs::create_dir_all(&models).expect("create model tree");
        fs::write(models.join("owned"), b"owned").expect("write model file");
        symlink(outside.path(), models.join("redirect")).expect("create redirect symlink");

        let error = uninstall(&root).expect_err("symlinked model tree must be rejected");
        assert!(matches!(error, EncoderError::ArtifactMismatch(_)));
        assert!(outside.path().exists());
        assert!(models.exists());
    }

    #[test]
    fn uninstall_removes_only_the_model_tree_and_is_idempotent() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(models.join("nested")).expect("create model tree");
        fs::write(models.join("nested/model.bin"), b"model").expect("write model file");
        fs::write(root.path().join("sibling"), b"keep").expect("write sibling state");

        uninstall(&root).expect("uninstall model tree");
        assert!(!models.exists());
        assert_eq!(
            fs::read(root.path().join("sibling")).expect("read sibling"),
            b"keep"
        );
        assert!(!root.path().join(JOURNAL_FILENAME).exists());
        assert!(
            fs::read_dir(root.path())
                .expect("list state root")
                .all(|entry| {
                    let name = entry.expect("read state root entry").file_name();
                    !name.to_string_lossy().starts_with(BACKUP_PREFIX)
                })
        );

        uninstall(&root).expect("repeated uninstall is a no-op");
        assert_eq!(
            fs::read(root.path().join("sibling")).expect("read sibling"),
            b"keep"
        );
    }

    #[test]
    fn recover_backed_up_publication_restores_the_original_tree() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(&models).expect("create model tree");
        fs::write(models.join("model.bin"), b"original").expect("write original model");
        let before_digest = digest_directory_path(&models).expect("digest original model");

        let operation_id = "b".repeat(32) + "-" + &"c".repeat(16) + "-update";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        fs::create_dir(root.path().join(&staging_name)).expect("create staging directory");
        let root_directory = open_root_directory(&root).expect("open root");
        tracedecay_private_fs::capability_dir::rename_noreplace(
            &root_directory,
            OsStr::new("models"),
            &root_directory,
            OsStr::new(&backup_name),
        )
        .expect("move model tree to recovery backup");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Update,
            phase: Phase::BackedUp,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name.clone()),
            before_digest: Some(before_digest),
            after_digest: Some("c".repeat(64)),
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write recovery journal");

        recover(&root).expect("recover backed-up publication");
        assert_eq!(
            fs::read(models.join("model.bin")).expect("read restored model"),
            b"original"
        );
        assert!(!root.path().join(&backup_name).exists());
        assert!(!root.path().join(&staging_name).exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn recover_staged_journal_after_backup_rename_restores_the_original_tree() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(&models).expect("create model tree");
        fs::write(models.join("model.bin"), b"original").expect("write original model");
        let before_digest = digest_directory_path(&models).expect("digest original model");

        let operation_id = "9".repeat(32) + "-" + &"a".repeat(16) + "-update";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        fs::create_dir(root.path().join(&staging_name)).expect("create staging directory");
        let root_directory = open_root_directory(&root).expect("open root");
        tracedecay_private_fs::capability_dir::rename_noreplace(
            &root_directory,
            OsStr::new("models"),
            &root_directory,
            OsStr::new(&backup_name),
        )
        .expect("move model tree to recovery backup");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Update,
            phase: Phase::Staged,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name.clone()),
            before_digest: Some(before_digest),
            after_digest: Some("b".repeat(64)),
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write recovery journal");

        recover(&root).expect("recover stale staged publication");
        assert_eq!(
            fs::read(models.join("model.bin")).expect("read restored model"),
            b"original"
        );
        assert!(!root.path().join(&backup_name).exists());
        assert!(!root.path().join(&staging_name).exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn recover_leaves_an_externally_changed_published_tree_for_inspection() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(&models).expect("create candidate model tree");
        fs::write(models.join("model.bin"), b"published").expect("write candidate model");
        let after_digest = digest_directory_path(&models).expect("digest candidate model");
        fs::write(models.join("model.bin"), b"changed").expect("mutate candidate model");

        let operation_id = "d".repeat(32) + "-" + &"e".repeat(16) + "-update";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        fs::create_dir(root.path().join(&backup_name)).expect("create backup directory");
        fs::write(
            root.path().join(&backup_name).join("model.bin"),
            b"original",
        )
        .expect("write backup model");
        let before_digest =
            digest_directory_path(&root.path().join(&backup_name)).expect("digest backup model");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Update,
            phase: Phase::Published,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name),
            backup_name: Some(backup_name.clone()),
            before_digest: Some(before_digest),
            after_digest: Some(after_digest),
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write recovery journal");

        let error = recover(&root).expect_err("external publication edit must be rejected");
        assert!(matches!(error, EncoderError::ArtifactMismatch(_)));
        assert_eq!(
            fs::read(models.join("model.bin")).expect("read changed model"),
            b"changed"
        );
        assert!(root.path().join(&backup_name).exists());
        assert!(journal_path.exists());
    }

    #[test]
    fn backed_up_recovery_rejects_an_unverified_live_candidate_without_deleting_it() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(&models).expect("create live candidate tree");
        fs::write(models.join("unexpected.bin"), b"candidate").expect("write live candidate");
        let after_digest = digest_directory_path(&models).expect("digest live candidate");

        let operation_id = "e".repeat(32) + "-" + &"f".repeat(16) + "-update";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        fs::create_dir(root.path().join(&staging_name)).expect("create staging directory");
        fs::create_dir(root.path().join(&backup_name)).expect("create backup directory");
        fs::write(
            root.path().join(&backup_name).join("model.bin"),
            b"original",
        )
        .expect("write rollback backup");
        let before_digest =
            digest_directory_path(&root.path().join(&backup_name)).expect("digest rollback backup");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Update,
            phase: Phase::BackedUp,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name.clone()),
            before_digest: Some(before_digest),
            after_digest: Some(after_digest),
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write recovery journal");

        let error = recover(&root).expect_err("unverified live candidate must be retained");
        assert!(matches!(
            error,
            EncoderError::ArtifactMismatch(_) | EncoderError::ArtifactsMissing(_)
        ));
        assert_eq!(
            fs::read(models.join("unexpected.bin")).expect("read retained candidate"),
            b"candidate"
        );
        assert!(root.path().join(&backup_name).exists());
        assert!(journal_path.exists());
    }

    #[test]
    fn journal_reservation_serializes_concurrent_installers() {
        let (_temp, root) = root();
        let journal_path = root.path().join(JOURNAL_FILENAME);
        let operation_id = "1".repeat(32) + "-" + &"2".repeat(16) + "-update";
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            operation: Operation::Update,
            phase: Phase::Prepared,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(format!("{STAGING_PREFIX}{operation_id}")),
            backup_name: Some(format!("{BACKUP_PREFIX}{operation_id}")),
            before_digest: None,
            after_digest: None,
        };
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let journal_path = journal_path.clone();
                let journal = journal.clone();
                thread::spawn(move || {
                    barrier.wait();
                    reserve_journal(&journal_path, &journal)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join reservation worker"))
            .collect::<Vec<_>>();

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one installer owns the journal reservation"
        );
        assert!(
            results
                .iter()
                .any(|result| { matches!(result, Err(EncoderError::ArtifactMismatch(_))) })
        );
        remove_journal(&journal_path).expect("remove reserved journal");
    }

    #[test]
    fn orphan_staging_cleanup_removes_only_valid_stale_entries() {
        let (_temp, root) = root();
        let orphan_id = "3".repeat(32) + "-" + &"4".repeat(16) + "-update";
        let orphan_name = format!("{STAGING_PREFIX}{orphan_id}");
        let reserved_id = "5".repeat(32) + "-" + &"6".repeat(16) + "-install";
        let reserved_name = format!("{STAGING_PREFIX}{reserved_id}");
        fs::create_dir(root.path().join(&orphan_name)).expect("create orphan staging");
        fs::create_dir(root.path().join(&reserved_name)).expect("create reserved staging");
        let root_directory = open_root_directory(&root).expect("open lifecycle root");

        cleanup_orphan_staging(&root_directory, root.path(), &reserved_name)
            .expect("clean stale staging");

        assert!(!root.path().join(&orphan_name).exists());
        assert!(root.path().join(&reserved_name).exists());
    }

    #[test]
    fn prepared_recovery_removes_a_partial_candidate_without_a_digest() {
        let (_temp, root) = root();
        let models = root.models_dir();
        fs::create_dir_all(&models).expect("create original model tree");
        fs::write(models.join("model.bin"), b"original").expect("write original model");
        let before_digest = digest_directory_path(&models).expect("digest original model");

        let operation_id = "7".repeat(32) + "-" + &"8".repeat(16) + "-update";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        let candidate = root.path().join(&staging_name).join("candidate");
        fs::create_dir_all(&candidate).expect("create partial candidate");
        fs::write(candidate.join("partial.bin"), b"incomplete").expect("write partial candidate");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Update,
            phase: Phase::Prepared,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name),
            before_digest: Some(before_digest),
            after_digest: None,
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write prepared journal");

        recover(&root).expect("recover partial prepared candidate");

        assert_eq!(
            fs::read(models.join("model.bin")).expect("read original model"),
            b"original"
        );
        assert!(!root.path().join(&staging_name).exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn backed_up_recovery_with_no_original_tree_cleans_before_candidate_publish() {
        let (_temp, root) = root();
        let operation_id = "9".repeat(32) + "-" + &"a".repeat(16) + "-install";
        let staging_name = format!("{STAGING_PREFIX}{operation_id}");
        let backup_name = format!("{BACKUP_PREFIX}{operation_id}");
        fs::create_dir(root.path().join(&staging_name)).expect("create staging directory");
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id,
            operation: Operation::Install,
            phase: Phase::BackedUp,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(staging_name.clone()),
            backup_name: Some(backup_name),
            before_digest: None,
            after_digest: Some("b".repeat(64)),
        };
        let journal_path = root.path().join(JOURNAL_FILENAME);
        write_journal(&journal_path, &journal).expect("write backed-up journal");

        recover(&root).expect("recover before fresh install candidate publish");

        assert!(!root.models_dir().exists());
        assert!(!root.path().join(&staging_name).exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn journal_paths_are_private_single_directory_entries() {
        let operation_id = "a".repeat(32) + "-" + &"b".repeat(16) + "-update";
        let journal = LifecycleJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            operation: Operation::Update,
            phase: Phase::Prepared,
            revision: MODEL_REVISION.to_owned(),
            staging_name: Some(format!("{STAGING_PREFIX}{operation_id}")),
            backup_name: Some(format!("{BACKUP_PREFIX}{operation_id}")),
            before_digest: None,
            after_digest: None,
        };
        validate_journal(&journal).expect("private journal names validate");
        let mut unsafe_journal = journal;
        unsafe_journal.staging_name = Some("../outside".to_owned());
        assert!(validate_journal(&unsafe_journal).is_err());
    }

    #[test]
    fn tree_digest_refuses_symlinked_entries() {
        let (_temp, root) = root();
        let models = root.models_dir();
        let outside = tempfile::tempdir().expect("create outside directory");
        fs::create_dir_all(&models).expect("create model tree");
        symlink(outside.path(), models.join("redirect")).expect("create redirect symlink");
        let error = digest_directory_path(&models).expect_err("digest must refuse symlink");
        assert!(matches!(error, EncoderError::ArtifactMismatch(_)));
    }
}
