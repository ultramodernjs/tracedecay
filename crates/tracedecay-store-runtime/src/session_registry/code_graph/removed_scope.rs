//! Vanished-scope authority and bounded graph-source draining before quarantine.
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use super::{
    GRAPH_OPERATION_DEADLINE, GraphPublicationProbeV1, MaintenanceGraphCancellationV1,
    graph_lifecycle_cancellation,
};
use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use tracedecay_code_index_retention::code_index_generations as retention;
use tracedecay_code_index_runtime::code_index_scheduler::CodeIndexSchedulerRegistryV1;
use tracedecay_domain::{CodeGenerationId, ProjectId, RefId, RepositoryId, WorktreeId};
use tracedecay_graph_db::{GraphDbError, GraphGenerationReplaySource};
use tracedecay_runtime_core::cancellation::CancellationToken;
use tracedecay_store::{
    CodeShardScopeV1, GraphProjectionIdentityV1, GraphPublicationOperationContextV1,
    GraphPublicationProjectionPageRequestV1, GraphPublicationReplayLookupV1,
    GraphPublicationReplayPageRequestV1, GraphPublicationRetiredCleanupPageRequestV1,
    GraphPublicationStoreV1, RuntimeCancellationIdV1, RuntimeCancellationIdentityV1,
    RuntimeDeadlineIdV1, RuntimeDeadlineV1, RuntimeRequestControlV1, StoreShardIdV1,
};

use super::super::DaemonSessionRuntimeRegistryV1;

#[derive(Clone)]
pub(super) struct RemovedScopeAuthority {
    scope_root: PathBuf,
    root: PathBuf,
    repository_root: PathBuf,
    schedulers: CodeIndexSchedulerRegistryV1,
    proof: retention::ScopeRootLivenessProofV1,
}

fn retention_error(error: retention::CodeGenerationRetentionErrorV1) -> GraphDbError {
    match error {
        retention::CodeGenerationRetentionErrorV1::Cancelled => GraphDbError::Cancelled,
        error => storage_error(error),
    }
}

fn root_missing(root: &Path) -> Result<bool, GraphDbError> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(storage_error(error)),
    }
}

fn storage_error(error: impl std::fmt::Display) -> GraphDbError {
    GraphDbError::unavailable(error.to_string())
}

/// Read both scheduler maps in their retirement lock order. Contention is a
/// refusal, never evidence of no owner; re-run immediately before head CAS.
fn scheduler_roots(
    schedulers: &CodeIndexSchedulerRegistryV1,
) -> Result<BTreeSet<PathBuf>, GraphDbError> {
    let retiring = schedulers
        .retiring
        .try_lock()
        .map_err(|_| GraphDbError::conflict("removed_scope.scheduler_busy"))?;
    let mounted = schedulers
        .mounted
        .try_lock()
        .map_err(|_| GraphDbError::conflict("removed_scope.scheduler_busy"))?;
    Ok(mounted.keys().chain(retiring.keys()).cloned().collect())
}

impl RemovedScopeAuthority {
    fn prove(
        scope_root: &Path,
        repository_root: &Path,
        schedulers: &CodeIndexSchedulerRegistryV1,
    ) -> Result<Option<Self>, GraphDbError> {
        let file = std::fs::File::open(scope_root.join(retention::SCOPE_ROOT_RECORD_FILE))
            .map_err(storage_error)?;
        let mut recorded = String::new();
        file.take(4097)
            .read_to_string(&mut recorded)
            .map_err(storage_error)?;
        if recorded.is_empty() || recorded.len() > 4096 {
            return Err(GraphDbError::invalid("invalid bounded scope root record"));
        }
        let root = PathBuf::from(recorded);
        let parent = scope_root
            .parent()
            .ok_or_else(|| GraphDbError::invalid("scope parent missing"))?;
        if retention::scoped_code_index_store_root(parent, &root) != scope_root {
            return Err(GraphDbError::invalid("scope root record hash mismatch"));
        }
        Self::from_root(scope_root, root, repository_root, schedulers)
    }

    fn from_root(
        scope_root: &Path,
        root: PathBuf,
        repository_root: &Path,
        schedulers: &CodeIndexSchedulerRegistryV1,
    ) -> Result<Option<Self>, GraphDbError> {
        if !root.is_absolute() {
            return Ok(None);
        }
        let mounted_roots = scheduler_roots(schedulers)?;
        let proof = retention::scope_root_liveness_proof(repository_root, &mounted_roots)
            .map_err(storage_error)?;
        let authority = Self {
            scope_root: scope_root.to_path_buf(),
            root,
            repository_root: repository_root.to_path_buf(),
            schedulers: schedulers.clone(),
            proof,
        };
        if !root_missing(&authority.root)?
            || authority
                .proof
                .live_scope_hashes
                .contains(&retention::code_index_scope_hash(&authority.root))
        {
            return Ok(None);
        }
        authority.check()?;
        Ok(Some(authority))
    }

    pub(super) fn check(&self) -> Result<(), GraphDbError> {
        let missing = root_missing(&self.root)?;
        let hash = retention::code_index_scope_hash(&self.root);
        let mounted_roots = scheduler_roots(&self.schedulers)?;
        let current = retention::scope_root_liveness_proof(&self.repository_root, &mounted_roots)
            .map_err(storage_error)?;
        if !missing || current != self.proof || current.live_scope_hashes.contains(&hash) {
            return Err(GraphDbError::conflict("removed_scope.liveness_changed"));
        }
        Ok(())
    }

    pub(super) fn projection(
        &self,
        project_shard: &StoreShardIdV1,
        generation: &CodeGenerationId,
        generation_file: &str,
        replay_root: &Path,
        check: &dyn Fn() -> Result<(), GraphDbError>,
    ) -> Result<Option<GraphProjectionIdentityV1>, GraphDbError> {
        let digest = super::seals::sealed_digest_from_generation_file(generation_file)?;
        let scoped = self
            .scope_root
            .join("code-generations-v1")
            .join(generation_file);
        let path = if !root_missing(&scoped)? {
            scoped
        } else {
            replay_root.join(generation_file)
        };
        // A completed source unlink may precede durable queue acknowledgement
        // across a crash. Without bytes, ordinary reconciliation is still safe:
        // it preserves every shared head and only finishes retired cleanup.
        if root_missing(&path)? {
            return Ok(None);
        }
        let prefix = super::seals::authenticated_seal_prefix(&path, &digest, check)?;
        let scope = read_scope_prefix(&prefix)?;
        if scope.generation != *generation
            || scope.project != project_id(project_shard)?
            || scope.worktree.as_ref().map(WorktreeId::as_str)
                != Some(
                    format!(
                        "worktree.daemon.{}",
                        retention::code_index_scope_hash(&self.root)
                    )
                    .as_str(),
                )
        {
            return Err(GraphDbError::conflict("removed_scope.source_binding"));
        }
        let worktree_id = scope
            .worktree
            .ok_or_else(|| GraphDbError::invalid("seal has no worktree"))?;
        let code_scope = match scope.reference {
            Some(ref_id) => CodeShardScopeV1::Branch {
                worktree_id,
                ref_id,
            },
            None => CodeShardScopeV1::Worktree { worktree_id },
        };
        let shard = StoreShardIdV1::code(
            project_shard.brain_id.clone(),
            project_shard.profile_id.clone(),
            scope.project,
            scope.repository,
            code_scope,
        );
        let projection = tracedecay_code_index::graph_projection::code_graph_projection_identity(
            tracedecay_graph_db::code_graph_shard_namespace(&shard)?,
        )
        .map_err(storage_error)?;
        Ok(Some(GraphProjectionIdentityV1 {
            shard_id: project_shard.clone(),
            namespace: tracedecay_store::GraphNamespaceV1::new(projection.namespace.as_str())
                .map_err(storage_error)?,
            projection: tracedecay_store::GraphProjectionIdV1::new(projection.projection.as_str())
                .map_err(storage_error)?,
        }))
    }
}

fn project_id(shard: &StoreShardIdV1) -> Result<ProjectId, GraphDbError> {
    match &shard.scope {
        tracedecay_store::StoreShardScopeV1::Project { project_id } => Ok(project_id.clone()),
        _ => Err(GraphDbError::invalid(
            "removed scope requires a project shard",
        )),
    }
}

struct SealScope {
    project: ProjectId,
    generation: CodeGenerationId,
    repository: RepositoryId,
    worktree: Option<WorktreeId>,
    reference: Option<RefId>,
}

/// The canonical seal puts scope fields before snapshot files. Deliberately
/// terminate the visitor after those fields: neither a large file census nor
/// graph/segment rows belong in a retention authorization's resident memory.
fn read_scope_prefix(prefix: &[u8]) -> Result<SealScope, GraphDbError> {
    #[derive(Deserialize)]
    struct Manifest {
        project_id: ProjectId,
        generation_id: CodeGenerationId,
    }
    struct Envelope<'a>(&'a mut Option<SealScope>);
    struct Snapshot<'a> {
        result: &'a mut Option<SealScope>,
        manifest: Manifest,
    }
    impl<'de> Visitor<'de> for Snapshot<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("snapshot scope prefix")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            let (mut repository, mut worktree, mut reference) = (None, None, None);
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "repository" => repository = Some(map.next_value::<RepositoryId>()?),
                    "worktree" => worktree = Some(map.next_value::<Option<WorktreeId>>()?),
                    "reference" => reference = Some(map.next_value::<Option<RefId>>()?),
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                if repository.is_some() && worktree.is_some() && reference.is_some() {
                    *self.result = Some(SealScope {
                        project: self.manifest.project_id,
                        generation: self.manifest.generation_id,
                        repository: repository
                            .ok_or_else(|| serde::de::Error::custom("repository absent"))?,
                        worktree: worktree.flatten(),
                        reference: reference.flatten(),
                    });
                    return Err(serde::de::Error::custom("scope prefix complete"));
                }
            }
            Err(serde::de::Error::custom("incomplete snapshot scope"))
        }
    }
    impl<'de> DeserializeSeed<'de> for Snapshot<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_map(self)
        }
    }
    impl<'de> DeserializeSeed<'de> for Envelope<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Envelope<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("sealed generation")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            let mut manifest = None;
            while let Some(key) = map.next_key::<String>()? {
                match key.as_str() {
                    "generation" => return map.next_value_seed(Envelope(self.0)),
                    "manifest" => manifest = Some(map.next_value::<Manifest>()?),
                    "snapshot" => {
                        return map.next_value_seed(Snapshot {
                            result: self.0,
                            manifest: manifest
                                .ok_or_else(|| serde::de::Error::custom("manifest absent"))?,
                        });
                    }
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Err(serde::de::Error::custom("snapshot absent"))
        }
    }
    let mut result = None;
    let mut decoder = serde_json::Deserializer::from_slice(prefix);
    let _ = serde::Deserializer::deserialize_map(&mut decoder, Envelope(&mut result));
    result.ok_or_else(|| GraphDbError::invalid("sealed generation has no bounded scope prefix"))
}

impl DaemonSessionRuntimeRegistryV1 {
    /// A bounded generation batch and release page, plus the active generation.
    /// Returning false preserves the whole scope and its durable retry evidence.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_removed_code_scope_graph_replays(
        &self,
        project_id: ProjectId,
        project_database: &tracedecay_runtime_core::db::Database,
        scope_root: &Path,
        repository_root: &Path,
        schedulers: &CodeIndexSchedulerRegistryV1,
        cancellation: &CancellationToken,
        release_after: Option<String>,
    ) -> Result<(bool, Option<String>), GraphDbError> {
        let scope = scope_root.to_path_buf();
        let repository = repository_root.to_path_buf();
        let schedulers = schedulers.clone();
        let authority = tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
            RemovedScopeAuthority::prove(&scope, &repository, &schedulers)
        })
        .await
        .map_err(storage_error)??;
        let Some(authority) = authority else {
            return Ok((false, None));
        };
        let pool = project_database
            .database_path()
            .with_extension("graph-replay");
        let scope = scope_root.to_path_buf();
        let cancel = cancellation.clone();
        let report = tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
            let plan = retention::prepare_next_code_generation_retention_cancellable(
                &scope,
                &BTreeSet::new(),
                &|| cancel.is_cancelled(),
                Some(&pool),
            )
            .map_err(retention_error)?;
            let mode = if plan.has_collectable_work() {
                retention::CodeGenerationRetentionModeV1::Apply
            } else {
                retention::CodeGenerationRetentionModeV1::DryRun
            };
            retention::execute_code_generation_retention_cancellable(
                &scope,
                plan,
                mode,
                tracedecay_contracts::clock::now_micros(),
                Some(&pool),
                &|| cancel.is_cancelled(),
            )
            .map_err(retention_error)
        })
        .await
        .map_err(storage_error)??;
        let page = retention::code_generation_graph_replay_release_page(
            scope_root,
            release_after.as_deref(),
        )
        .map_err(retention_error)?;
        let mut drained = release_after.is_none()
            && page.continuation.is_none()
            && report.plan.superseded_generations.len() == report.deleted_generations.len();
        let continuation = page.continuation;
        for release in page.releases {
            if self
                .reconcile_code_generation_graph_replays(
                    project_id.clone(),
                    project_database,
                    &release.generation.generation_id,
                    &release.generation.generation_file,
                    cancellation,
                    Some(authority.clone()),
                )
                .await?
            {
                retention::complete_code_generation_graph_replay_release(scope_root, &release)
                    .map_err(retention_error)?;
            } else {
                drained = false;
            }
        }
        // The ordinary generation journal protects the active pointer. The
        // whole-scope journal will remove it only after its graph reader drains.
        let pointer_path = scope_root.join("active-code-generation-v1.json");
        match std::fs::File::open(pointer_path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(retention::MAX_DURABLE_PUBLICATION_POINTER_BYTES_V1 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(storage_error)?;
                if bytes.len() as u64 > retention::MAX_DURABLE_PUBLICATION_POINTER_BYTES_V1 {
                    return Err(GraphDbError::invalid(
                        "publication pointer exceeds its bound",
                    ));
                }
                let pointer: retention::DurablePublicationPointerV1 =
                    serde_json::from_slice(&bytes).map_err(storage_error)?;
                let generation =
                    CodeGenerationId::new(pointer.generation_id).map_err(storage_error)?;
                drained &= self
                    .reconcile_code_generation_graph_replays(
                        project_id,
                        project_database,
                        &generation,
                        &pointer.generation_file,
                        cancellation,
                        Some(authority),
                    )
                    .await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage_error(error)),
        }
        Ok((drained, continuation))
    }
}

impl DaemonSessionRuntimeRegistryV1 {
    /// Inspect one projection against one bounded page of historical checkout
    /// roots. A held reader does not hold the cursor: later projections still
    /// make progress, and the next census retries this one. No graph is opened
    /// merely to discover a head. Tombstones remain discoverable after crashes.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_removed_code_graph_head_page(
        &self,
        project: ProjectId,
        database: &tracedecay_runtime_core::db::Database,
        roots: &[PathBuf],
        repository: &Path,
        schedulers: &CodeIndexSchedulerRegistryV1,
        after: Option<GraphProjectionIdentityV1>,
        cancellation: &CancellationToken,
    ) -> Result<(Option<GraphProjectionIdentityV1>, bool), GraphDbError> {
        if roots.len() > 32 {
            return Err(GraphDbError::invalid("root page exceeds bound"));
        }
        let shard = StoreShardIdV1::project(
            self.identity.brain_id().clone(),
            self.identity.profile_id().clone(),
            project.clone(),
        );
        let mut storage = database
            .graph_publication_storage()
            .map_err(storage_error)?;
        let cancel = cancellation.clone();
        let lifecycle = Arc::clone(&self.graph_lifecycle_cancelled);
        let discovered = tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
            let cancellation_id = RuntimeCancellationIdentityV1 {
                cancellation_id: RuntimeCancellationIdV1::new("removed-scope-discovery")
                    .map_err(storage_error)?,
                generation: 1,
            };
            let deadline = RuntimeDeadlineV1 {
                deadline_id: RuntimeDeadlineIdV1::new("removed-scope-discovery-deadline")
                    .map_err(storage_error)?,
            };
            let probe = GraphPublicationProbeV1 {
                request_cancellation: Arc::new(MaintenanceGraphCancellationV1(cancel)),
                lifecycle_cancellation: graph_lifecycle_cancellation(&lifecycle, None),
                deadline_at: Instant::now() + GRAPH_OPERATION_DEADLINE,
                cancellation: cancellation_id.clone(),
                deadline: deadline.clone(),
                commit_started: AtomicBool::new(false),
                deadline_warned: AtomicBool::new(false),
            };
            let control = RuntimeRequestControlV1 {
                requested_at: tracedecay_contracts::clock::now_micros(),
                deadline,
                cancellation: cancellation_id,
            };
            let context =
                GraphPublicationOperationContextV1::new(&control, &probe).map_err(storage_error)?;
            let request = GraphPublicationProjectionPageRequestV1::new(shard, after, 1)
                .map_err(storage_error)?;
            let page = storage
                .projection_page(&request, &context)
                .map_err(storage_error)?;
            let Some(projection) = page.projections.into_iter().next() else {
                return Ok((page.continuation, None));
            };
            if !tracedecay_graph_db::is_code_graph_shard_namespace(
                &tracedecay_graph_db::GraphNamespace::new(projection.namespace.as_str())
                    .map_err(storage_error)?,
            ) {
                return Ok((page.continuation, None));
            }
            let payload = if let Some(head) = storage
                .verified_head(&projection, &context)
                .map_err(storage_error)?
            {
                match storage.replay(&head.key, &context).map_err(storage_error)? {
                    GraphPublicationReplayLookupV1::Active(replay) => {
                        Some((replay.publication.canonical_replay_source, false))
                    }
                    _ => None,
                }
            } else {
                let request = GraphPublicationReplayPageRequestV1::new(projection.clone(), None, 1)
                    .map_err(storage_error)?;
                if let Some(replay) = storage
                    .replay_page(&request, &context)
                    .map_err(storage_error)?
                    .records
                    .into_iter()
                    .next()
                {
                    Some((replay.publication.canonical_replay_source, false))
                } else {
                    let request = GraphPublicationRetiredCleanupPageRequestV1::new(
                        projection.clone(),
                        None,
                        1,
                    )
                    .map_err(storage_error)?;
                    storage
                        .retired_cleanup_page(&request, &context)
                        .map_err(storage_error)?
                        .records
                        .into_iter()
                        .next()
                        .and_then(|retired| {
                            retired.canonical_replay_source.map(|source| (source, true))
                        })
                }
            };
            let source = payload
                .map(|(payload, retired)| {
                    serde_json::from_slice::<GraphGenerationReplaySource>(&payload)
                        .map(|source| (projection, source, retired))
                        .map_err(storage_error)
                })
                .transpose()?;
            Ok::<_, GraphDbError>((page.continuation, source))
        })
        .await
        .map_err(storage_error)??;
        let (continuation, source) = discovered;
        let Some((projection, GraphGenerationReplaySource::SealedCodeGeneration(source), retired)) =
            source
        else {
            return Ok((continuation, false));
        };
        let digest = tracedecay_domain::sha256_hex_suffix(source.sealed_state_digest.as_str())
            .ok_or_else(|| GraphDbError::invalid("invalid seal digest"))?;
        let generation_file = format!("generation-{digest}.json");
        if retired {
            let drained = self
                .reconcile_deleted_code_generation_graph_replays(
                    project,
                    database,
                    &source.generation,
                    &generation_file,
                    cancellation,
                )
                .await?;
            return Ok((continuation, !drained));
        }
        let roots = roots.to_vec();
        let repository = repository.to_path_buf();
        let schedulers = schedulers.clone();
        let pool = database.database_path().with_extension("graph-replay");
        let data_root = database
            .database_path()
            .parent()
            .ok_or_else(|| GraphDbError::invalid("project store parent missing"))?
            .to_path_buf();
        let check_cancel = cancellation.clone();
        let file = generation_file.clone();
        let generation = source.generation.clone();
        let authority = tracedecay_runtime_core::native_runtime::spawn_blocking(move || {
            let check = || {
                if check_cancel.is_cancelled() {
                    Err(GraphDbError::Cancelled)
                } else {
                    Ok(())
                }
            };
            let path = pool.join(&file);
            if root_missing(&path)? {
                return Ok(None);
            }
            check()?;
            let mut prefix = Vec::new();
            std::fs::File::open(&path)
                .map_err(storage_error)?
                .take(16 * 1024 * 1024)
                .read_to_end(&mut prefix)
                .map_err(storage_error)?;
            let seal = read_scope_prefix(&prefix)?;
            if seal.project != project_id(&projection.shard_id)?
                || seal.generation != generation
                || seal.repository != source.repository
            {
                return Err(GraphDbError::conflict("removed_scope.discovery_binding"));
            }
            for root in roots {
                let expected = format!(
                    "worktree.daemon.{}",
                    retention::code_index_scope_hash(&root)
                );
                if seal.worktree.as_ref().map(WorktreeId::as_str) != Some(expected.as_str()) {
                    continue;
                }
                let scope_root = retention::scoped_code_index_store_root(
                    &retention::code_index_scope_store_root(&data_root),
                    &root,
                );
                if let Some(authority) =
                    RemovedScopeAuthority::from_root(&scope_root, root, &repository, &schedulers)?
                {
                    // This prefix is only a discovery hint. The common reconcile
                    // authenticates the entire source and derives its exact
                    // repository/worktree/ref projection before retiring anything.
                    return Ok(Some(authority));
                }
            }
            Ok::<_, GraphDbError>(None)
        })
        .await
        .map_err(storage_error)??;
        if let Some(authority) = authority {
            let drained = self
                .reconcile_code_generation_graph_replays(
                    project,
                    database,
                    &source.generation,
                    &generation_file,
                    cancellation,
                    Some(authority),
                )
                .await?;
            return Ok((continuation, !drained));
        }
        Ok((continuation, false))
    }
}
