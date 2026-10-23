use super::revalidate::{SourceValidation, source_evidence};
use super::{PathProbe, PreserveReason, ProfileSessionPrunePlan, error, preserve_reason};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tracedecay_domain::errors::Result;
use tracedecay_domain::{CanonicalObservationIdV1, ObservationSourceIdentityV1};
use tracedecay_runtime_core::db::engine::{QueryExecutor, params};
use tracedecay_runtime_core::lifecycle_lease::LifecycleLease;
use tracedecay_store::StoreShardScopeV1;

use crate::RegisteredGlobalDb;
use crate::observation::bookkeeping::retire::{
    ObservationRetirementOutcome, ProjectPruneMarker, RetirementBlocker,
};
use crate::observation::bookkeeping::source_keys::SourceKey;

const MAX_BATCHES: usize = 128;
const IDS_PER_BATCH: usize = 128;

/// Sealed capability: constructed only after approval and source-wide validation.
/// Borrowing the exact lease keeps it exclusive through the kernel transaction.
pub(crate) struct ProjectPruneAuthorization<'a> {
    marker: ProjectPruneMarker,
    store: tracedecay_store::VerifiedStoreLocatorV1,
    lifecycle: &'a LifecycleLease,
}

impl ProjectPruneAuthorization<'_> {
    pub(crate) fn marker(&self) -> &ProjectPruneMarker {
        &self.marker
    }

    pub(crate) fn authorizes(&self, db: &RegisteredGlobalDb, marker: &ProjectPruneMarker) -> bool {
        self.store == *db.verified_locator()
            && db.binding().shard_id.scope == StoreShardScopeV1::ProfileSessions
            && self.lifecycle.is_exclusive()
            && db
                .db_path()
                .parent()
                .is_some_and(|profile| self.lifecycle.guards_profile(profile))
            && self.marker.source == marker.source
            && self.marker.scope == marker.scope
            && self.marker.approved_plan_digest == marker.approved_plan_digest
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum ProfileSessionPruneDeferReason {
    Protected(PreserveReason),
    MissingSourcePresence,
    /// Source-local validation exceeded 4096 observations or 8 MiB stored JSON.
    ValidationBudget,
    Retirement(Vec<RetirementBlocker>),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileSessionPruneDeferred {
    pub source: ObservationSourceIdentityV1,
    pub reason: ProfileSessionPruneDeferReason,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProfileSessionPruneOutcome {
    pub retired_observations: usize,
    /// Completed sources in this page, including those already retired under
    /// this exact approval. Deferred sources are never counted as completed.
    pub completed_sources: usize,
    pub deferred_sources: Vec<ProfileSessionPruneDeferred>,
    /// A source page or batch budget was exhausted; resume the original plan
    /// at `next_source_offset`. This does not imply deferred sources succeeded.
    pub has_more: bool,
    /// Index in the original approved source ordering. Deferred sources may be
    /// revisited from offset zero after their dependencies become eligible.
    pub next_source_offset: Option<usize>,
    /// Logical deleted columns only, excluding the kernel's retained rows.
    pub retired_logical_bytes: u64,
}

async fn marker_value(read: &impl QueryExecutor, key: &str) -> Result<Option<String>> {
    let mut rows = read
        .query(
            "SELECT value FROM session_backfill_meta WHERE key=?1",
            params![key],
        )
        .await
        .map_err(error)?;
    rows.next()
        .await
        .map_err(error)?
        .map(|row| row.get(0).map_err(error))
        .transpose()
}

/// Both legacy and compact source keys are admitted until explicit convergence.
/// Each lookup is a bounded primary-key range, never a JSON table scan.
async fn candidate_ids(
    read: &impl QueryExecutor,
    source: &super::PruneSource,
) -> Result<Vec<CanonicalObservationIdV1>> {
    let key = SourceKey::new(&source.source, &source.scope).map_err(error)?;
    let mut ids = BTreeSet::new();
    for spelling in [&key.compact, &key.legacy] {
        let mut rows = read.query(
            "SELECT observation_id FROM observation_source_presence WHERE source_key=?1 ORDER BY observation_id LIMIT ?2",
            params![spelling.as_str(), IDS_PER_BATCH as i64],
        ).await.map_err(error)?;
        while let Some(row) = rows.next().await.map_err(error)? {
            ids.insert(row.get::<String>(0).map_err(error)?);
        }
    }
    ids.into_iter()
        .take(IDS_PER_BATCH)
        .map(|id| CanonicalObservationIdV1::new(id).map_err(error))
        .collect()
}

impl RegisteredGlobalDb {
    /// Explicit offline preparation, not startup work. Building this index on a
    /// populated store may be expensive; obtain an authorized maintenance window
    /// first. Planning remains passive, and apply refuses an absent index.
    pub async fn prepare_profile_session_prune_lookup(
        &self,
        lifecycle: &LifecycleLease,
    ) -> Result<()> {
        let profile = self
            .db_path()
            .parent()
            .ok_or_else(|| error("profile-session store has no profile root"))?;
        if !lifecycle.is_exclusive()
            || !lifecycle.guards_profile(profile)
            || self.binding().shard_id.scope != StoreShardScopeV1::ProfileSessions
        {
            return Err(error(
                "prune lookup preparation requires the exact profile-session exclusive lease",
            ));
        }
        self.require_active_write_scope("prepare profile session prune lookup")?;
        let transaction = self.begin_write_transaction().await?;
        transaction
            .execute_batch(super::revalidate::LOOKUP_INDEX_SQL)
            .await
            .map_err(error)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Passive census bound to this registered store's exact incarnation.
    pub async fn plan_profile_session_prune(
        &self,
        registry_roots: &[Vec<PathBuf>],
        probe: &impl Fn(&Path) -> PathProbe,
        page_size: usize,
    ) -> Result<ProfileSessionPrunePlan> {
        let read = self.read_snapshot().await?;
        let mut plan =
            super::plan_profile_session_prune(&read, registry_roots, probe, page_size).await?;
        plan.store_locator = Some(self.verified_locator().clone());
        plan.digest = super::approval_digest(&plan)?;
        Ok(plan)
    }

    /// Explicit-forget census with the same exact-store apply fence.
    pub async fn plan_profile_session_forget(
        &self,
        registry_roots: &[Vec<PathBuf>],
        forgotten_roots: &[PathBuf],
        probe: &impl Fn(&Path) -> PathProbe,
        page_size: usize,
    ) -> Result<ProfileSessionPrunePlan> {
        let read = self.read_snapshot().await?;
        let mut plan = super::plan_profile_session_forget(
            &read,
            registry_roots,
            forgotten_roots,
            probe,
            page_size,
        )
        .await?;
        plan.store_locator = Some(self.verified_locator().clone());
        plan.digest = super::approval_digest(&plan)?;
        Ok(plan)
    }

    /// Applies only an explicitly confirmed census, under the exact profile's
    /// exclusive maintenance scope. The offline owner must not run concurrent
    /// intake: the kernel owns each writer transaction, so a caller transaction
    /// cannot fence source-wide validation across it. No daemon/startup caller
    /// may use this API. Planning itself remains passive and needs no writer.
    ///
    /// Only the approved source page is revalidated through the explicitly
    /// prepared source index, with per-source row/byte caps; no whole-store
    /// census runs here. Up to 128 bounded kernel transactions follow.
    /// The kernel atomically commits its exclusion and retirement receipt; B5
    /// never writes a marker or implements a deletion cascade. After interruption,
    /// retry the original plan, not a new approval: matching markers establish
    /// that the immutable, pre-high-water remainder belongs to the old approval.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_profile_session_prune(
        &self,
        plan: &ProfileSessionPrunePlan,
        confirmed_digest: &str,
        lifecycle: &LifecycleLease,
        registry_roots: &[Vec<PathBuf>],
        probe: &impl Fn(&Path) -> PathProbe,
        max_batches: usize,
        source_offset: usize,
    ) -> Result<ProfileSessionPruneOutcome> {
        super::require_profile_session_prune_admission()?;
        self.apply_profile_session_prune_offline(
            plan,
            confirmed_digest,
            lifecycle,
            registry_roots,
            probe,
            max_batches,
            source_offset,
        )
        .await
    }

    // Module-private engine for the future integrated public path. Unit fixtures
    // exercise it without pretending admission has been delivered. No external
    // caller or feature flag can bypass the production gate above.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn apply_profile_session_prune_offline(
        &self,
        plan: &ProfileSessionPrunePlan,
        confirmed_digest: &str,
        lifecycle: &LifecycleLease,
        registry_roots: &[Vec<PathBuf>],
        probe: &impl Fn(&Path) -> PathProbe,
        max_batches: usize,
        source_offset: usize,
    ) -> Result<ProfileSessionPruneOutcome> {
        let approved = plan.approve(confirmed_digest)?;
        if plan.store_locator.as_ref() != Some(self.verified_locator()) {
            return Err(error(
                "prune approval belongs to a different or unbound store",
            ));
        }
        let profile = self
            .db_path()
            .parent()
            .ok_or_else(|| error("profile-session store has no profile root"))?;
        if !lifecycle.is_exclusive() || !lifecycle.guards_profile(profile) {
            return Err(error(
                "prune apply requires the exact profile's exclusive lifecycle lease",
            ));
        }
        self.require_active_write_scope("profile session prune")?;
        if self.binding().shard_id.scope != StoreShardScopeV1::ProfileSessions {
            return Err(error("prune apply requires the profile-session store"));
        }
        if !(1..=MAX_BATCHES).contains(&max_batches) {
            return Err(error("prune apply requires 1..=128 batches"));
        }
        let read = self.read_snapshot().await?;
        let registry_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(registry_roots).map_err(error)?,
        ));
        if registry_digest != plan.registry_digest {
            return Err(error(
                "registered project roots changed; obtain a new approval",
            ));
        }
        let mut work = Vec::new();
        if source_offset > approved.selected_sources().len() {
            return Err(error("prune source offset is outside the approved plan"));
        }
        let page_end = source_offset
            .saturating_add(max_batches)
            .min(approved.selected_sources().len());
        let mut outcome = ProfileSessionPruneOutcome {
            has_more: page_end < approved.selected_sources().len(),
            next_source_offset: (page_end < approved.selected_sources().len()).then_some(page_end),
            ..Default::default()
        };
        // Validate the entire bounded source page before making any new writes.
        for (index, source) in approved
            .selected_sources()
            .iter()
            .enumerate()
            .take(page_end)
            .skip(source_offset)
        {
            let (marker_key, expected_marker) = approved.source_exclusion_metadata(source)?;
            let marker = marker_value(&read, &marker_key).await?;
            if marker
                .as_ref()
                .is_some_and(|value| value != &expected_marker)
            {
                return Err(error("source has a conflicting prune approval"));
            }
            let live = match source_evidence(&read, source).await? {
                SourceValidation::Complete(live) => live,
                SourceValidation::BudgetExceeded => {
                    outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                        source: source.source.clone(),
                        reason: ProfileSessionPruneDeferReason::ValidationBudget,
                    });
                    continue;
                }
            };
            let Some(live) = live else {
                if marker.is_none() {
                    return Err(error(
                        "approved source disappeared without a retirement marker",
                    ));
                }
                outcome.completed_sources += 1;
                continue;
            };
            if let Some(reason) =
                preserve_reason(&live, registry_roots, plan.forgotten_roots.as_ref(), probe)
            {
                outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                    source: source.source.clone(),
                    reason: ProfileSessionPruneDeferReason::Protected(reason),
                });
                continue;
            }
            if marker.is_none() {
                if &live != source {
                    return Err(error(
                        "approved source evidence changed; obtain a new approval",
                    ));
                }
            } else if live.last_sequence > plan.high_water
                || live.observation_count > source.observation_count
                || !live.project_roots.is_subset(&source.project_roots)
                || !live.locations.is_subset(&source.locations)
            {
                // Observation updates are guarded and AUTOINCREMENT never rewinds.
                // Thus a matching committed marker can resume only its old tail,
                // not evidence appended or re-admitted after the census.
                return Err(error(
                    "pruned source acquired evidence outside its approved census",
                ));
            }
            work.push((index, source, live.observation_count));
        }
        drop(read);
        let mut batches = 0;
        for (index, source, mut count) in work {
            while count > 0 {
                if batches == max_batches {
                    outcome.has_more = true;
                    outcome.next_source_offset = Some(index);
                    return Ok(outcome);
                }
                batches += 1;
                self.require_active_write_scope("profile session prune batch")?;
                if let Some(reason) =
                    preserve_reason(source, registry_roots, plan.forgotten_roots.as_ref(), probe)
                {
                    outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                        source: source.source.clone(),
                        reason: ProfileSessionPruneDeferReason::Protected(reason),
                    });
                    break;
                }
                let read = self.read_snapshot().await?;
                let ids = candidate_ids(&read, source).await?;
                drop(read);
                if ids.is_empty() || ids.len() as u64 > count {
                    outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                        source: source.source.clone(),
                        reason: ProfileSessionPruneDeferReason::MissingSourcePresence,
                    });
                    break;
                }
                let authorization = ProjectPruneAuthorization {
                    marker: ProjectPruneMarker {
                        source: source.source.clone(),
                        scope: source.scope.clone(),
                        approved_plan_digest: plan.digest().to_owned(),
                    },
                    store: self.verified_locator().clone(),
                    lifecycle,
                };
                let retirement = self
                    .plan_project_prune_retirement(&ids, &authorization)
                    .await
                    .map_err(error)?;
                let blockers = retirement
                    .candidates()
                    .iter()
                    .flat_map(|candidate| candidate.blockers.clone())
                    .collect();
                let logical_bytes: u64 = retirement
                    .tables()
                    .iter()
                    .filter(|table| !table.retained)
                    .map(|table| table.bytes)
                    .sum();
                // The filesystem is not leased by SQLite; probe at the final
                // transaction boundary as well as during source-wide selection.
                if let Some(reason) =
                    preserve_reason(source, registry_roots, plan.forgotten_roots.as_ref(), probe)
                {
                    outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                        source: source.source.clone(),
                        reason: ProfileSessionPruneDeferReason::Protected(reason),
                    });
                    break;
                }
                match self
                    .apply_project_prune_retirement(
                        &retirement,
                        retirement.digest(),
                        &authorization,
                    )
                    .await
                    .map_err(error)?
                {
                    ObservationRetirementOutcome::Applied { observations } => {
                        count -= observations as u64;
                        outcome.retired_observations += observations;
                        outcome.retired_logical_bytes += logical_bytes;
                    }
                    ObservationRetirementOutcome::Deferred => {
                        outcome.deferred_sources.push(ProfileSessionPruneDeferred {
                            source: source.source.clone(),
                            reason: ProfileSessionPruneDeferReason::Retirement(blockers),
                        });
                        break;
                    }
                    ObservationRetirementOutcome::AlreadyApplied => {
                        return Err(error("source changed during exclusive prune maintenance"));
                    }
                }
            }
            if count == 0 {
                outcome.completed_sources += 1;
            }
        }
        Ok(outcome)
    }
}
