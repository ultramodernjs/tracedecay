//! Bounded, read-only proof of profile records already owned by a project.
//!
//! Plans do not authorize deletion: apply must revalidate the proof while
//! retaining the target and use the complete bookkeeping retirement owner.

use std::path::{Path, PathBuf};

use serde::Serialize;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationFactV1, CanonicalObservationIdV1,
    ObservationIdentityMaterialV1, ObservationScopeV1, canonical_text::sha256_hex,
};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_sessions::runtime::shared::{ProjectMembership, ProjectRootMatcher};
use tracedecay_store::{
    ObservationCommitReceipt, SESSION_MESSAGE_PROJECTOR_VERSION, StoreRuntimeBindingV1,
    StoreShardScopeV1, VerifiedStoreLocatorV1,
};

use crate::observation::ownership_read;
use crate::{RegisteredGlobalDb, global_db_operation_error, global_db_operation_message};

const OPERATION: &str = "plan session ownership";
pub const MAX_OWNERSHIP_PAGE_RECORDS: usize = 64;
const MAX_OWNERSHIP_TARGETS: usize = 64;
const MAX_OWNERSHIP_ROOTS: usize = 256;

type Result<T> = tracedecay_domain::errors::Result<T>;

/// One currently registered project session shard and its registered roots.
/// Callers must supply the complete registry snapshot, including aliases.
pub struct SessionOwnershipTargetV1<'a> {
    pub database: &'a RegisteredGlobalDb,
    pub roots: &'a [PathBuf],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionOwnershipTargetBindingV1 {
    pub binding: StoreRuntimeBindingV1,
    pub locator: VerifiedStoreLocatorV1,
    pub roots: Vec<PathBuf>,
}

/// Binds one equivalent record pair to both stores' runtime identities and
/// verified locators. The enclosing plan supplies the source-store binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionOwnershipProofV1 {
    pub profile_observation_id: CanonicalObservationIdV1,
    pub project_observation_id: CanonicalObservationIdV1,
    pub project_binding: StoreRuntimeBindingV1,
    pub proof_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionOwnershipPlanV1 {
    pub profile_binding: StoreRuntimeBindingV1,
    pub profile_locator: VerifiedStoreLocatorV1,
    pub targets: Vec<SessionOwnershipTargetBindingV1>,
    pub after_sequence: u64,
    pub next_after_sequence: u64,
    pub scanned: usize,
    /// Sequence rows whose observation, anchor or provenance evidence was released.
    pub released: usize,
    pub retained: usize,
    pub verified: Vec<SessionOwnershipProofV1>,
    pub plan_digest: String,
}

fn digest(domain: &str, value: &impl Serialize) -> Result<String> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(
        serde_json::to_vec(value).map_err(|error| global_db_operation_error(OPERATION, error))?,
    );
    Ok(sha256_hex(&bytes))
}

fn native_location(envelope: &CanonicalObservationEnvelopeV1) -> Option<&Path> {
    let mut location = None;
    for fact in envelope.facts() {
        if let CanonicalObservationFactV1::Session { location_path, .. } = fact {
            let path = Path::new(location_path.as_deref()?);
            if !path.is_absolute() || location.is_some_and(|previous| previous != path) {
                return None;
            }
            location = Some(path);
        }
    }
    location
}

async fn projection_is_complete(
    snapshot: &impl QueryExecutor,
    stored: &ObservationCommitReceipt,
) -> Result<bool> {
    let mut rows = snapshot
        .query(
            "SELECT EXISTS (
             SELECT 1 FROM observation_projection_provenance
             WHERE observation_id = ?1 AND projector_version = ?2
         ) AND NOT EXISTS (
             SELECT 1 FROM projection_queue WHERE observation_id = ?1
         ) AND NOT EXISTS (
             SELECT 1 FROM observation_projection_dispositions WHERE observation_id = ?1
         ) AND NOT EXISTS (
             SELECT 1 FROM observation_admission_refusals WHERE observation_id = ?1
         ) AND NOT EXISTS (
             SELECT 1 FROM retrieval_anchor_dispositions
             WHERE anchor_id = ?3 AND state IN ('superseded', 'deleted')
         )",
            params![
                stored.observation().observation_id().as_str(),
                SESSION_MESSAGE_PROJECTOR_VERSION,
                stored.retrieval_anchor_id().as_str()
            ],
        )
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?;
    let row = rows
        .next()
        .await
        .map_err(|error| global_db_operation_error(OPERATION, error))?
        .ok_or_else(|| global_db_operation_message(OPERATION, "missing projection proof result"))?;
    row.get::<i64>(0)
        .map(|value| value == 1)
        .map_err(|error| global_db_operation_error(OPERATION, error))
}

fn target_identity(
    source: &ObservationIdentityMaterialV1,
    scope: ObservationScopeV1,
) -> Result<ObservationIdentityMaterialV1> {
    let identity = match source.native_record_id() {
        Some(native) => ObservationIdentityMaterialV1::for_native_record(
            source.source().clone(),
            scope,
            source.generation(),
            source.position(),
            source.ordering_domain(),
            native.clone(),
        ),
        None => ObservationIdentityMaterialV1::new(
            source.source().clone(),
            scope,
            source.generation(),
            source.position(),
        ),
    };
    identity.map_err(|error| global_db_operation_error(OPERATION, error))
}

impl RegisteredGlobalDb {
    /// Reads at most `limit` observations in sequence order (maximum 64).
    /// Resume at `next_after_sequence`; a short page ends the current sweep.
    /// No schema installation, checkpoints, or maintenance writes occur here.
    ///
    /// Proof is intentionally conservative: native location, complete current
    /// message projections, identical native payloads and source generation /
    /// ranges are required. Uncertain, conflicting, retired and locationless
    /// evidence remains in the profile. This is not an apply authorization.
    pub async fn plan_session_ownership_page(
        &self,
        targets: &[SessionOwnershipTargetV1<'_>],
        after_sequence: u64,
        limit: usize,
    ) -> Result<SessionOwnershipPlanV1> {
        if self.binding().shard_id.scope != StoreShardScopeV1::ProfileSessions
            || limit == 0
            || limit > MAX_OWNERSHIP_PAGE_RECORDS
            || targets.len() > MAX_OWNERSHIP_TARGETS
            || targets
                .iter()
                .map(|target| target.roots.len())
                .sum::<usize>()
                > MAX_OWNERSHIP_ROOTS
        {
            return Err(global_db_operation_message(
                OPERATION,
                "invalid ownership scope or page bounds",
            ));
        }
        let mut bindings = Vec::with_capacity(targets.len());
        let mut matchers = Vec::with_capacity(targets.len());
        for target in targets {
            let binding = target.database.binding();
            if !matches!(
                binding.shard_id.scope,
                StoreShardScopeV1::ProjectSessions { .. }
            ) || binding.shard_id.brain_id != self.binding().shard_id.brain_id
                || binding.shard_id.profile_id != self.binding().shard_id.profile_id
                || bindings
                    .iter()
                    .any(|other: &SessionOwnershipTargetBindingV1| {
                        other.binding.shard_id == binding.shard_id
                    })
                || target.roots.is_empty()
            {
                return Err(global_db_operation_message(
                    OPERATION,
                    "invalid or repeated project ownership target",
                ));
            }
            let mut roots = target.roots.to_vec();
            roots.sort();
            roots.dedup();
            matchers.push(
                roots
                    .iter()
                    .map(|root| ProjectRootMatcher::new(root))
                    .collect::<Vec<_>>(),
            );
            bindings.push(SessionOwnershipTargetBindingV1 {
                binding: binding.clone(),
                locator: target.database.verified_locator().clone(),
                roots,
            });
        }
        let profile_snapshot = self.read_snapshot().await?;
        let records = ownership_read::read_page(&profile_snapshot, after_sequence, limit)
            .await
            .map_err(|error| global_db_operation_error(OPERATION, error))?;
        let mut plan = SessionOwnershipPlanV1 {
            profile_binding: self.binding().clone(),
            profile_locator: self.verified_locator().clone(),
            targets: bindings,
            after_sequence,
            next_after_sequence: records
                .last()
                .map_or(after_sequence, |(sequence, _)| *sequence),
            scanned: records.len(),
            released: records
                .iter()
                .filter(|(_, stored)| stored.is_none())
                .count(),
            retained: records
                .iter()
                .filter(|(_, stored)| stored.is_some())
                .count(),
            verified: Vec::new(),
            plan_digest: String::new(),
        };
        for (_, stored) in records {
            let Some(stored) = stored else {
                continue;
            };
            let observation = stored.observation();
            if observation.scope() != &ObservationScopeV1::Profile {
                continue;
            }
            let Ok(envelope) = serde_json::from_value::<CanonicalObservationEnvelopeV1>(
                observation.payload().clone(),
            ) else {
                continue;
            };
            let Some(location) = native_location(&envelope) else {
                continue;
            };
            let mut owner = None;
            let mut uncertain = false;
            for (index, roots) in matchers.iter().enumerate() {
                let mut matched = false;
                let mut unknown = false;
                for root in roots {
                    match root.contains_status(location) {
                        ProjectMembership::Match => matched = true,
                        ProjectMembership::Unknown => unknown = true,
                        ProjectMembership::NoMatch => {}
                    }
                }
                if matched {
                    if owner.replace(index).is_some() {
                        uncertain = true;
                    }
                } else {
                    uncertain |= unknown;
                }
            }
            let Some(index) = owner.filter(|_| !uncertain) else {
                continue;
            };
            let StoreShardScopeV1::ProjectSessions { project_id } =
                &targets[index].database.binding().shard_id.scope
            else {
                continue;
            };
            let scope = ObservationScopeV1::Project {
                project_id: project_id.clone(),
            };
            let identity = target_identity(observation.identity(), scope)?;
            let target_id = CanonicalObservationIdV1::derive(&identity)
                .map_err(|error| global_db_operation_error(OPERATION, error))?;
            let target_snapshot = targets[index].database.read_snapshot().await?;
            let Some(target) = ownership_read::read_retained(&target_snapshot, &target_id)
                .await
                .map_err(|error| global_db_operation_error(OPERATION, error))?
            else {
                continue;
            };
            let target_observation = target.observation();
            if target_observation.identity() != &identity
                || target_observation.payload() != observation.payload()
                || target_observation.retention_class() != observation.retention_class()
                || target_observation.receipt().sensitivity() != observation.receipt().sensitivity()
                || target_observation.receipt().disposition() != observation.receipt().disposition()
                || target_observation.receipt().receipt().sanitizer_version()
                    != observation.receipt().receipt().sanitizer_version()
                || !projection_is_complete(&profile_snapshot, &stored).await?
                || !projection_is_complete(&target_snapshot, &target).await?
            {
                continue;
            }
            let proof_digest = digest(
                "tracedecay.session-ownership.proof.v1",
                &(
                    &plan.profile_binding,
                    &plan.profile_locator,
                    observation,
                    stored.committed_cursor(),
                    target_observation,
                    target.committed_cursor(),
                    &plan.targets[index],
                ),
            )?;
            plan.verified.push(SessionOwnershipProofV1 {
                profile_observation_id: observation.observation_id().clone(),
                project_observation_id: target_id,
                project_binding: targets[index].database.binding().clone(),
                proof_digest,
            });
            plan.retained -= 1;
        }
        plan.plan_digest = digest("tracedecay.session-ownership.plan.v1", &plan)?;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests;
