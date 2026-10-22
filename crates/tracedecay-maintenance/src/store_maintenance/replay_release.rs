//! Bounded, read-only release previews and digest-confirmed administrative apply.
//! A queue receipt proves collection, not graph liveness. Only the production
//! retirement executor may decide whether a source is still needed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracedecay_code_index_retention::code_index_generations::{
    CodeGenerationGraphReplayReleaseV1, code_generation_graph_replay_release_page,
    code_index_store_root, complete_code_generation_graph_replay_release,
    sweep_released_code_generation_segments_cancellable,
};
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_domain::{ProjectId, canonical_sha256};
use tracedecay_runtime_core::cancellation::CancellationToken;
use tracedecay_runtime_core::native_runtime;
use tracedecay_runtime_core::storage::StoreLayout;

use crate::lease::ProjectStoreMaintenanceLeaseV1;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphReplayReleaseAuthorityV1 {
    /// Preview is read-only; heads, dependencies and readers are revalidated
    /// by the production executor for each source at apply time.
    Unvalidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct GraphReplayReleasePlanV1 {
    pub project_id: String,
    pub store_root: PathBuf,
    pub checkout_root: PathBuf,
    pub after: Option<String>,
    pub releases: Vec<CodeGenerationGraphReplayReleaseV1>,
    pub continuation: Option<String>,
    pub authority: GraphReplayReleaseAuthorityV1,
    /// Unknown until graph authority is revalidated. Queue entries are never
    /// counted as reclaimable bytes or described as live heads.
    pub reclaimable_bytes: Option<u64>,
    /// A later bounded mark/sweep revalidates all retained manifest roots.
    /// No estimate sums segment sizes across manifests or hardlinks.
    pub segment_candidate_bytes: Option<u64>,
    pub sweep_segments_after_release: bool,
    pub plan_digest: String,
}

pub(super) fn release_error(message: impl Into<String>) -> TraceDecayError {
    TraceDecayError::Config {
        message: message.into(),
    }
}

/// Filesystem-only preview, also used by storage reporting when no admitted
/// project authority is available. Reading never acquires a writable lock,
/// acknowledges a queue entry, or creates a store.
pub fn plan_graph_replay_releases(
    project_id: &str,
    store_root: &Path,
    checkout_root: &Path,
    after: Option<&str>,
) -> Result<GraphReplayReleasePlanV1> {
    tracedecay_runtime_core::storage::validate_project_id(project_id).map_err(release_error)?;
    let page = code_generation_graph_replay_release_page(store_root, after)
        .map_err(|error| release_error(format!("graph replay release preview: {error}")))?;
    let digest = canonical_sha256(&(
        "tracedecay.graph-replay-release-plan.v1",
        project_id,
        store_root,
        checkout_root,
        after,
        &page.releases,
        &page.continuation,
        true,
    ))
    .map_err(|error| release_error(error.to_string()))?;
    Ok(GraphReplayReleasePlanV1 {
        project_id: project_id.to_owned(),
        store_root: store_root.to_path_buf(),
        checkout_root: checkout_root.to_path_buf(),
        after: after.map(str::to_owned),
        releases: page.releases,
        continuation: page.continuation,
        authority: GraphReplayReleaseAuthorityV1::Unvalidated,
        reclaimable_bytes: None,
        segment_candidate_bytes: None,
        sweep_segments_after_release: true,
        plan_digest: digest.to_string(),
    })
}

/// Read-only preview for a registry-resolved layout. Root provenance is checked
/// without admitting writable graph SQL or creating an absent store.
pub fn plan_project_graph_replay_releases(
    layout: &StoreLayout,
    checkout_root: &Path,
    after: Option<&str>,
) -> Result<GraphReplayReleasePlanV1> {
    let project_id = layout
        .identity
        .project_id
        .as_deref()
        .ok_or_else(|| release_error("graph replay project identity unavailable"))?;
    let store_root = code_index_store_root(&layout.data_root, checkout_root);
    let scopes = tracedecay_code_index_retention::code_index_generations::code_index_scopes(
        &layout.data_root,
    )
    .map_err(|error| release_error(error.to_string()))?;
    if !scopes.iter().any(|scope| {
        scope.store_root == store_root
            && (scope.recorded_root.as_deref() == Some(checkout_root)
                || checkout_root == layout.project_root)
    }) {
        return Err(release_error(
            "graph replay checkout root is not recorded for this scope",
        ));
    }
    plan_graph_replay_releases(project_id, &store_root, checkout_root, after)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GraphReplayReleaseRunV1 {
    DryRun {
        plan: GraphReplayReleasePlanV1,
    },
    Applied {
        plan_digest: String,
        released: usize,
        retained: usize,
        continuation: Option<String>,
        segment_sweep_more_work: bool,
    },
}

/// One scope/page per call. `None` is dry-run; apply requires the digest of
/// that exact preview. Both the durable queue and admitted project identity
/// are revalidated before apply; graph retirement revalidates the serving,
/// pending, dependency and reader guards again at its mutation boundary.
/// CLI registration belongs to the integration layer.
pub async fn release_graph_replays(
    lease: &ProjectStoreMaintenanceLeaseV1,
    checkout_root: &Path,
    after: Option<&str>,
    apply_plan_digest: Option<&str>,
    cancellation: &CancellationToken,
) -> Result<GraphReplayReleaseRunV1> {
    if cancellation.is_cancelled() {
        return Err(release_error("graph replay release cancelled"));
    }
    let layout = lease.store_layout();
    let project_id = layout
        .identity
        .project_id
        .as_deref()
        .ok_or_else(|| release_error("graph replay project identity unavailable"))?;
    let id = ProjectId::new(project_id).map_err(|error| release_error(error.to_string()))?;
    let binding = lease.graph_db().registered_binding();
    if binding.shard_id.profile_id != lease.profile_database().binding().shard_id.profile_id
        || !matches!(&binding.shard_id.scope,
            tracedecay_store::StoreShardScopeV1::Project { project_id } if project_id == &id)
        || !tracedecay_runtime_core::path_safety::same_canonical_path(
            lease.graph_db().database_path(),
            &layout.graph_db_path,
        )
    {
        return Err(release_error(
            "graph replay maintenance lease identity mismatch",
        ));
    }
    let store_root = code_index_store_root(&layout.data_root, checkout_root);
    let layout = layout.clone();
    let checkout = checkout_root.to_path_buf();
    let after = after.map(str::to_owned);
    let plan = native_runtime::spawn_blocking(move || {
        plan_project_graph_replay_releases(&layout, &checkout, after.as_deref())
    })
    .await
    .map_err(|error| release_error(format!("join release preview: {error}")))??;
    let Some(expected_digest) = apply_plan_digest else {
        return Ok(GraphReplayReleaseRunV1::DryRun { plan });
    };
    if expected_digest != plan.plan_digest {
        return Err(release_error(
            "graph replay release plan changed; run dry-run again",
        ));
    }
    if !lease.graph_db().is_writable() {
        return Err(release_error(
            "graph replay apply requires admitted write authority",
        ));
    }
    let mut released = 0;
    let mut retained = 0;
    for release in &plan.releases {
        if cancellation.is_cancelled() {
            return Err(release_error(
                "graph replay release cancelled; rerun dry-run",
            ));
        }
        let source_released = lease
            .store_runtime()
            .reconcile_deleted_code_generation_graph_replays(
                id.clone(),
                lease.graph_db(),
                &release.generation.generation_id,
                &release.generation.generation_file,
                cancellation,
            )
            .await
            .map_err(|error| release_error(format!("graph replay release: {error}")))?;
        if source_released {
            complete_code_generation_graph_replay_release(&store_root, release).map_err(
                |error| release_error(format!("checkpoint graph replay release: {error}")),
            )?;
            released += 1;
        } else {
            retained += 1;
        }
    }
    let pool = lease
        .graph_db()
        .database_path()
        .with_extension("graph-replay");
    let cancellation = cancellation.clone();
    let segment_sweep_more_work = native_runtime::spawn_blocking(move || {
        sweep_released_code_generation_segments_cancellable(&store_root, &pool, &|| {
            cancellation.is_cancelled()
        })
    })
    .await
    .map_err(|error| release_error(format!("join segment sweep: {error}")))?
    .map_err(|error| release_error(format!("graph replay segment sweep: {error}")))?;
    Ok(GraphReplayReleaseRunV1::Applied {
        plan_digest: plan.plan_digest,
        released,
        retained,
        continuation: plan.continuation,
        segment_sweep_more_work,
    })
}

#[cfg(test)]
mod tests;
