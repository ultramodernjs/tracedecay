//! Passive selection and operator-authorized retirement of profile-session sources.
//!
//! Session rows are projections, not observation ownership. In particular, a
//! missing session row is never deletion authority: ownership comes from the
//! canonical Session facts across the entire provider/source/scope identity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationFactV1, DurableObservationV1,
    ObservationScopeV1, ObservationSourceIdentityV1,
};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_store::SESSION_MESSAGE_PROJECTOR_VERSION;

const OPERATION: &str = "profile session prune";
const MAX_PAGE: usize = 256;
const MAX_PATHS_PER_SOURCE: usize = 64;
const MAX_SOURCES: usize = 100_000;

/// Fail closed until the admission/replay owners implement both preflight and
/// final-writer exclusion checks with successful terminal cursor-only coverage.
/// Do not replace this with a flag or caller assertion: enable it only together
/// with production same-generation, new-generation and writer-race regressions.
pub fn require_profile_session_prune_admission() -> Result<()> {
    Err(error(
        "profile-session prune admission/replay integration is not installed; public prune-sessions apply is disabled",
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathProbe {
    Live,
    Missing,
    Unavailable,
}

/// Passive filesystem classification below caller-confirmed available roots.
/// The roots must be known available filesystem boundaries, not containers of
/// possibly unmounted filesystems such as `/Volumes`. Uncovered paths, absent
/// boundaries, symlinks and inaccessible ancestry are never deletion authority.
/// Revalidate again at apply time; this read is not a filesystem lease.
pub fn probe_project_path(path: &Path, available_roots: &[PathBuf]) -> PathProbe {
    if path.to_str().and_then(safe_path).is_none() {
        return PathProbe::Unavailable;
    }
    let Some(boundary) = available_roots
        .iter()
        .filter(|root| root.to_str().and_then(safe_path).is_some() && path.starts_with(root))
        .max_by_key(|root| root.components().count())
    else {
        return PathProbe::Unavailable;
    };
    let mut current = PathBuf::new();
    let mut boundary_checked = false;
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound && boundary_checked => {
                return PathProbe::Missing;
            }
            // A symlink, non-directory, inaccessible ancestor or absent
            // availability boundary cannot prove project disappearance.
            _ => return PathProbe::Unavailable,
        }
        boundary_checked |= current == *boundary;
    }
    PathProbe::Live
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneSource {
    pub source: ObservationSourceIdentityV1,
    pub scope: ObservationScopeV1,
    pub project_roots: BTreeSet<PathBuf>,
    pub locations: BTreeSet<PathBuf>,
    pub observation_count: u64,
    /// Stored observation JSON only, not physical filesystem savings.
    pub observation_json_bytes: u64,
    pub has_session_row: bool,
    pending: bool,
    ambiguous: bool,
    last_sequence: i64,
    evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreserveReason {
    UnknownOwnership,
    MixedLocations,
    LiveOrUnavailable,
    PendingProjection,
    NonProfileScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservedSource {
    pub source: ObservationSourceIdentityV1,
    pub scope: ObservationScopeV1,
    pub reason: PreserveReason,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileSessionPrunePlan {
    pub selected_sources: Vec<PruneSource>,
    pub preserved_sources: Vec<PreservedSource>,
    pub observation_count: u64,
    pub rowless_source_count: u64,
    pub observation_json_bytes: u64,
    pub unattributed_observations: u64,
    pub high_water: i64,
    /// Maximum observations materialized by any one page.
    pub largest_page: usize,
    forgotten_roots: Option<BTreeSet<PathBuf>>,
    evidence_digest: String,
    registry_digest: String,
    store_locator: Option<tracedecay_store::VerifiedStoreLocatorV1>,
    digest: String,
}

impl ProfileSessionPrunePlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Validates serialized approval once, then borrows the selection immutably
    /// so individual markers need only an indexed source lookup. This does not
    /// replace transaction-local ownership and filesystem revalidation.
    pub fn approve(&self, confirmed_digest: &str) -> Result<ApprovedProfileSessionPrunePlan<'_>> {
        if self.digest().is_empty()
            || confirmed_digest != self.digest()
            || self.unattributed_observations != 0
            || approval_digest(self)? != confirmed_digest
        {
            return Err(error(
                "prune approval does not match a fully attributed plan",
            ));
        }
        let mut sources = BTreeMap::new();
        for source in &self.selected_sources {
            if sources
                .insert(source_key(&source.source, &source.scope)?, source)
                .is_some()
            {
                return Err(error("prune approval contains a repeated source identity"));
            }
        }
        Ok(ApprovedProfileSessionPrunePlan {
            plan: self,
            sources,
        })
    }
}

/// An immutable, validated approval. It cannot outlive or mutate its plan and
/// cannot be constructed by deserializing an unchecked approval token.
pub struct ApprovedProfileSessionPrunePlan<'a> {
    plan: &'a ProfileSessionPrunePlan,
    sources: BTreeMap<String, &'a PruneSource>,
}

impl ApprovedProfileSessionPrunePlan<'_> {
    pub fn selected_sources(&self) -> &[PruneSource] {
        &self.plan.selected_sources
    }

    /// Builds a compact store-local marker with O(log N) identity lookup and
    /// no full-plan hashing. Persist it only in the same transaction that
    /// retires this source's owned evidence through the shared owner.
    pub fn source_exclusion_metadata(&self, source: &PruneSource) -> Result<(String, String)> {
        let key = source_key(&source.source, &source.scope)?;
        if self.sources.get(&key).copied() != Some(source) {
            return Err(error("prune approval does not name this source"));
        }
        crate::observation::bookkeeping::retire::ProjectPruneMarker {
            source: source.source.clone(),
            scope: source.scope.clone(),
            approved_plan_digest: self.plan.digest().to_owned(),
        }
        .metadata()
        .map_err(error)
    }
}

fn error(error: impl std::fmt::Display) -> TraceDecayError {
    TraceDecayError::Database {
        operation: OPERATION.to_owned(),
        message: error.to_string(),
    }
}

pub(crate) fn source_key(
    source: &ObservationSourceIdentityV1,
    scope: &ObservationScopeV1,
) -> Result<String> {
    serde_json::to_string(&(source, scope)).map_err(error)
}

fn safe_path(path: &str) -> Option<PathBuf> {
    // Sanitizers can replace only part of an otherwise absolute locator. Such
    // a spelling, like the `user` pseudo-root, cannot prove vanished ownership.
    let lower = path.to_ascii_lowercase();
    let path = Path::new(path);
    (path.is_absolute()
        && path.parent().is_some()
        && !["[tracedecay redacted:", "[redacted]", "<redacted>"]
            .iter()
            .any(|marker| lower.contains(marker))
        && !path.components().any(|part| match part {
            std::path::Component::ParentDir | std::path::Component::CurDir => true,
            std::path::Component::Normal(name) => name
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("redacted")),
            _ => false,
        }))
    .then(|| path.to_path_buf())
}

fn add_ownership(source: &mut PruneSource, observation: &DurableObservationV1) {
    #[cfg(test)]
    tests::CLASSIFIED_OBSERVATIONS.with(|count| count.set(count.get() + 1));
    let Ok(envelope) =
        serde_json::from_value::<CanonicalObservationEnvelopeV1>(observation.payload().clone())
    else {
        source.ambiguous = true;
        return;
    };
    if envelope.validate().is_err()
        || envelope.provider() != observation.source().provider()
        || envelope.relations().session_id() != observation.source().session_id()
    {
        source.ambiguous = true;
        return;
    }
    let mut has_project_root = false;
    for fact in envelope.facts() {
        if let CanonicalObservationFactV1::Session {
            project_path,
            location_path,
            ..
        } = fact
        {
            has_project_root |= project_path.is_some();
            source.ambiguous |= project_path.is_none();
            for (value, paths) in [
                (project_path, &mut source.project_roots),
                (location_path, &mut source.locations),
            ] {
                if let Some(value) = value {
                    if let Some(path) = safe_path(value) {
                        if paths.len() < MAX_PATHS_PER_SOURCE {
                            paths.insert(path);
                        } else if !paths.contains(&path) {
                            source.ambiguous = true;
                        }
                    } else {
                        source.ambiguous = true;
                    }
                }
            }
        }
    }
    // Another record's root cannot supply this record's missing ownership.
    source.ambiguous |= !has_project_root;
}

fn preserve_reason(
    source: &PruneSource,
    registry_roots: &[Vec<PathBuf>],
    forgotten_roots: Option<&BTreeSet<PathBuf>>,
    probe: &impl Fn(&Path) -> PathProbe,
) -> Option<PreserveReason> {
    if source.scope != ObservationScopeV1::Profile {
        return Some(PreserveReason::NonProfileScope);
    }
    if source.pending {
        return Some(PreserveReason::PendingProjection);
    }
    if source.ambiguous || source.project_roots.is_empty() {
        return Some(PreserveReason::UnknownOwnership);
    }
    if let Some(roots) = forgotten_roots {
        if source
            .project_roots
            .iter()
            .any(|root| !roots.contains(root))
            || source
                .locations
                .iter()
                .any(|location| !roots.iter().any(|root| location.starts_with(root)))
        {
            return Some(PreserveReason::MixedLocations);
        }
        for group in registry_roots {
            if group
                .iter()
                .any(|alias| source.project_roots.contains(alias))
            {
                if group
                    .iter()
                    .any(|alias| !roots.contains(alias) && probe(alias) != PathProbe::Missing)
                {
                    return Some(PreserveReason::LiveOrUnavailable);
                }
            } else if group.iter().any(|alias| {
                source
                    .locations
                    .iter()
                    .any(|location| location.starts_with(alias))
            }) {
                // A separately registered nested project is not authorized by
                // forgetting its lexical parent.
                return Some(PreserveReason::MixedLocations);
            }
        }
        return None;
    }
    if source.project_roots.len() != 1 {
        return Some(PreserveReason::MixedLocations);
    }
    let root = source.project_roots.iter().next()?;
    if source
        .locations
        .iter()
        .any(|location| !location.starts_with(root))
    {
        return Some(PreserveReason::MixedLocations);
    }
    if source
        .project_roots
        .iter()
        .chain(&source.locations)
        .any(|path| probe(path) != PathProbe::Missing)
    {
        return Some(PreserveReason::LiveOrUnavailable);
    }
    // A moved root or live alias protects the entire identity, not just the
    // spelling carried by this source's initial working directory.
    if registry_roots.iter().any(|group| {
        group.iter().any(|alias| root.starts_with(alias))
            && group.iter().any(|alias| probe(alias) != PathProbe::Missing)
    }) {
        return Some(PreserveReason::LiveOrUnavailable);
    }
    None
}

async fn high_water(read: &impl QueryExecutor) -> Result<i64> {
    let mut rows = read
        .query("SELECT COALESCE(MAX(sequence), 0) FROM observations", ())
        .await
        .map_err(error)?;
    rows.next()
        .await
        .map_err(error)?
        .ok_or_else(|| error("missing high water"))?
        .get(0)
        .map_err(error)
}

/// Plans against an already-open, consistent read snapshot. This function can
/// neither create a store nor acquire a writer, converge schema, or migrate.
/// Registry root groups contain canonical/display paths and all aliases for
/// each identity. The probe must distinguish absent from inaccessible roots.
/// Any undecodable observation refuses the entire plan: its source may share
/// identity with an otherwise selectable cohort.
pub async fn plan_profile_session_prune(
    read: &impl QueryExecutor,
    registry_roots: &[Vec<PathBuf>],
    probe: &impl Fn(&Path) -> PathProbe,
    page_size: usize,
) -> Result<ProfileSessionPrunePlan> {
    plan_sources(read, registry_roots, None, probe, page_size).await
}

async fn plan_sources(
    read: &impl QueryExecutor,
    registry_roots: &[Vec<PathBuf>],
    forgotten_roots: Option<BTreeSet<PathBuf>>,
    probe: &impl Fn(&Path) -> PathProbe,
    page_size: usize,
) -> Result<ProfileSessionPrunePlan> {
    let page_size = page_size.clamp(1, MAX_PAGE);
    let mut plan = ProfileSessionPrunePlan {
        high_water: high_water(read).await?,
        forgotten_roots,
        ..Default::default()
    };
    let mut sources = BTreeMap::<String, PruneSource>::new();
    let mut source_fingerprints = BTreeMap::<String, Sha256>::new();
    let mut after = 0;
    let mut fingerprint = Sha256::new();
    loop {
        let mut rows = read.query(
            "SELECT o.sequence, o.observation_id, o.payload_digest, o.observation_json,
                (EXISTS (SELECT 1 FROM observation_projection_provenance p
                         WHERE p.projector_version = ?4 AND p.observation_id = o.observation_id)
                 OR EXISTS (SELECT 1 FROM observation_projection_dispositions d
                         WHERE d.projector_version = ?4 AND d.observation_id = o.observation_id))
                 AND NOT EXISTS (SELECT 1 FROM projection_queue q WHERE q.observation_id = o.observation_id),
                o.committed_cursor_json
             FROM observations o WHERE o.sequence > ?1 AND o.sequence <= ?2
             ORDER BY o.sequence LIMIT ?3",
            params![after, plan.high_water, page_size as i64, SESSION_MESSAGE_PROJECTOR_VERSION]
        ).await.map_err(error)?;
        let mut page = Vec::with_capacity(page_size);
        while let Some(row) = rows.next().await.map_err(error)? {
            page.push((
                row.get::<i64>(0).map_err(error)?,
                row.get::<String>(1).map_err(error)?,
                row.get::<String>(2).map_err(error)?,
                row.get::<String>(3).map_err(error)?,
                row.get::<i64>(4).map_err(error)? != 0,
                row.get::<String>(5).map_err(error)?,
            ));
        }
        drop(rows);
        if page.is_empty() {
            break;
        }
        plan.largest_page = plan.largest_page.max(page.len());
        for (sequence, id, digest, json, settled, cursor) in page {
            after = sequence;
            for bytes in [
                sequence.to_le_bytes().as_slice(),
                id.as_bytes(),
                digest.as_bytes(),
            ] {
                fingerprint.update((bytes.len() as u64).to_le_bytes());
                fingerprint.update(bytes);
            }
            // A missing/corrupt canonical body can hide live ownership or
            // pending work in an otherwise selectable source. Without a
            // separately validated identity, no source-wide approval is safe.
            let observation = crate::observation::decode_observation_json(read, &json, OPERATION)
                .await
                .map_err(|cause| {
                    error(format!(
                        "cannot classify observation {id} at sequence {sequence}; prune planning refused: {cause}"
                    ))
                })?;
            revalidate::validate_cursor(&cursor, &observation)?;
            let key = source_key(observation.source(), observation.scope())?;
            if !sources.contains_key(&key) && sources.len() >= MAX_SOURCES {
                return Err(error(
                    "source census limit reached; narrow the store before pruning",
                ));
            }
            let source_fingerprint = source_fingerprints.entry(key.clone()).or_default();
            source_fingerprint
                .update(serde_json::to_vec(&(sequence, &id, &digest, settled)).map_err(error)?);
            let source = sources.entry(key).or_insert_with(|| PruneSource {
                source: observation.source().clone(),
                scope: observation.scope().clone(),
                project_roots: BTreeSet::new(),
                locations: BTreeSet::new(),
                observation_count: 0,
                observation_json_bytes: 0,
                has_session_row: false,
                pending: false,
                ambiguous: false,
                last_sequence: 0,
                evidence_digest: String::new(),
            });
            source.last_sequence = sequence;
            source.observation_count += 1;
            source.observation_json_bytes += json.len() as u64;
            source.pending |= !settled;
            add_ownership(source, &observation);
        }
    }
    for (key, mut source) in sources {
        source.evidence_digest = hex::encode(
            source_fingerprints
                .remove(&key)
                .ok_or_else(|| error("missing source evidence digest"))?
                .finalize(),
        );
        if let Some(reason) = preserve_reason(
            &source,
            registry_roots,
            plan.forgotten_roots.as_ref(),
            probe,
        ) {
            plan.preserved_sources.push(PreservedSource {
                source: source.source,
                scope: source.scope,
                reason,
            });
            continue;
        }
        let mut rows = read
            .query(
                "SELECT 1 FROM sessions WHERE provider = ?1 AND session_id = ?2",
                params![
                    source.source.provider().as_str(),
                    source.source.session_id().as_str()
                ],
            )
            .await
            .map_err(error)?;
        source.has_session_row = rows.next().await.map_err(error)?.is_some();
        if !source.has_session_row {
            plan.rowless_source_count += 1;
        }
        plan.observation_count += source.observation_count;
        plan.observation_json_bytes += source.observation_json_bytes;
        plan.selected_sources.push(source);
    }
    if high_water(read).await? != plan.high_water {
        return Err(error(
            "observation high water changed during planning; retry with a consistent snapshot",
        ));
    }
    let registry_json = serde_json::to_vec(registry_roots).map_err(error)?;
    plan.registry_digest = hex::encode(Sha256::digest(&registry_json));
    fingerprint.update(&registry_json);
    plan.evidence_digest = hex::encode(fingerprint.finalize());
    plan.digest = approval_digest(&plan)?;
    Ok(plan)
}

/// Plans explicit forgetting while retaining the same source-wide safety fences.
/// `forgotten_roots` must name the resolved project's canonical/display roots
/// and aliases; a caller must not infer this authority from a missing directory.
pub async fn plan_profile_session_forget(
    read: &impl QueryExecutor,
    registry_roots: &[Vec<PathBuf>],
    forgotten_roots: &[PathBuf],
    probe: &impl Fn(&Path) -> PathProbe,
    page_size: usize,
) -> Result<ProfileSessionPrunePlan> {
    if forgotten_roots.is_empty()
        || forgotten_roots
            .iter()
            .any(|root| root.to_str().and_then(safe_path).is_none())
    {
        return Err(error(
            "explicit forget requires nonempty absolute project roots",
        ));
    }
    plan_sources(
        read,
        registry_roots,
        Some(forgotten_roots.iter().cloned().collect()),
        probe,
        page_size,
    )
    .await
}

fn approval_digest(plan: &ProfileSessionPrunePlan) -> Result<String> {
    #[cfg(test)]
    tests::record_approval_digest();
    // Recompute from the approved values rather than trusting a deserialized
    // digest alongside caller-mutable selections. Page size is an execution
    // budget, not part of operator approval identity.
    let mut material = plan.clone();
    material.digest.clear();
    material.largest_page = 0;
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&material).map_err(error)?,
    )))
}

mod apply;
mod revalidate;
pub(crate) use apply::ProjectPruneAuthorization;
pub use apply::{
    ProfileSessionPruneDeferReason, ProfileSessionPruneDeferred, ProfileSessionPruneOutcome,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

/// Classification is source-scoped and deliberately independent of source
/// generation. The caller owns terminal cursor-only coverage, not this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneExclusion {
    OperatorPrunedSource,
}

/// Read before evidence/bookkeeping admission, and recheck in the final writer
/// transaction. An exclusion must advance terminal cursor-only coverage; it is
/// not an exact duplicate, a failed write, or a per-observation refusal row.
/// The database being queried supplies the profile/store identity fence.
pub async fn classify_exclusion(
    read: &impl QueryExecutor,
    observation: &DurableObservationV1,
) -> Result<Option<PruneExclusion>> {
    let key = tracedecay_store::observation_source_exclusion_key(
        observation.source(),
        observation.scope(),
    )
    .map_err(error)?;
    let mut rows = read
        .query(
            "SELECT value FROM session_backfill_meta WHERE key = ?1",
            params![key],
        )
        .await
        .map_err(error)?;
    let Some(row) = rows.next().await.map_err(error)? else {
        return Ok(None);
    };
    let value = row.get::<String>(0).map_err(error)?;
    tracedecay_store::validate_observation_source_exclusion(
        &value,
        observation.source(),
        observation.scope(),
    )
    .map_err(error)?;
    Ok(Some(PruneExclusion::OperatorPrunedSource))
}
