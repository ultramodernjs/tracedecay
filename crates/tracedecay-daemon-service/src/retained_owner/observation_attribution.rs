//! Host-authored original-source attribution for canonical session
//! observations.
//!
//! The observation journey attaches this attribution to every message it
//! delivers to an observing provider, so the provider can cite the exact
//! canonical record a later recall candidate came from. When a provider cites
//! it back, the recall lane re-reads the canonical record and derives the
//! attribution again with this same function: only byte-equal attribution of a
//! record that is still available in this project is host-confirmed evidence.
//! A provider-held copy is therefore a claim, never an authority.

use sha2::{Digest, Sha256};
use tracedecay_contracts::ResolvedScope;
use tracedecay_domain::{CanonicalObservationEnvelopeV1, ObservationScopeV1, UserProfileId};
use tracedecay_memory_provider_registry::recall_admission::RecallOutcomeScopeV1;
use tracedecay_memory_provider_registry::recall_admission::source_attribution::{
    RecallOriginScopeEvidenceV1, RecallOriginalSourceIdentityV1, RecallRecordedValidityV1,
    RecallSourceAttributionV1,
};
use tracedecay_memory_provider_registry::{OwnedExactScope, SourceAttribution};
use tracedecay_store::StoredObservation;

use super::observation_journey::exact_scope_for_session;

/// Prefix of the origin authority reference: the host's own admission of one
/// canonical observation into this checkout's provider delivery scope.
const ORIGIN_AUTHORITY_PREFIX: &str = "host-observation-admission:";

/// Why a canonical record has no attributable original source here.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ObservationAttributionErrorV1 {
    /// The record belongs to another project and is never re-scoped.
    #[error("canonical observation belongs to another project")]
    ForeignProject,
    /// The canonical envelope is unreadable or disagrees with its record.
    #[error("canonical observation envelope is invalid: {0}")]
    Envelope(String),
    /// The mounted checkout cannot bind the record's session.
    #[error("canonical observation delivery scope is unavailable: {0}")]
    Scope(String),
    /// A retained clock lies outside the nanosecond attribution range.
    #[error("canonical observation timestamp is outside the attribution range")]
    Timestamp,
    /// The derived attribution violates the shared source contract.
    #[error("canonical observation attribution is invalid: {0}")]
    Invalid(String),
}

/// Derives the one attribution this host ever issues for `stored` under the
/// mounted checkout. Deterministic: the same canonical record and mount always
/// produce the same value, which is what makes a provider's retained copy
/// checkable.
pub(crate) fn canonical_observation_attribution(
    profile_id: &UserProfileId,
    scope: &ResolvedScope,
    stored: &StoredObservation,
) -> Result<RecallSourceAttributionV1, ObservationAttributionErrorV1> {
    let observation = stored.observation();
    if observation.scope()
        != &(ObservationScopeV1::Project {
            project_id: scope.project_id.clone(),
        })
    {
        return Err(ObservationAttributionErrorV1::ForeignProject);
    }
    let envelope: CanonicalObservationEnvelopeV1 =
        serde_json::from_value(observation.payload().clone())
            .map_err(|error| ObservationAttributionErrorV1::Envelope(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| ObservationAttributionErrorV1::Envelope(error.to_string()))?;
    if envelope.provider() != observation.source().provider()
        || envelope.relations().session_id() != observation.source().session_id()
        || envelope.evidence().ordering_domain() != observation.identity().ordering_domain()
        || envelope.evidence().range() != observation.identity().position()
        || observation
            .identity()
            .native_record_id()
            .is_some_and(|id| id != envelope.stable_record_id())
    {
        return Err(ObservationAttributionErrorV1::Envelope(
            "canonical envelope source identity mismatch".to_owned(),
        ));
    }
    let canonical_bytes = tracedecay_memory_hygiene::canonical_payload_bytes(observation.payload())
        .map_err(|error| ObservationAttributionErrorV1::Envelope(error.to_string()))?;
    let session_id = observation.source().session_id().as_str();
    let origin = exact_scope_for_session(profile_id, scope, session_id)
        .map_err(|error| ObservationAttributionErrorV1::Scope(error.to_string()))?;
    let observation_id = observation.observation_id().as_str();
    let anchor = stored.retrieval_anchor();
    let attribution = RecallSourceAttributionV1 {
        source: RecallOriginalSourceIdentityV1 {
            canonical_provider_id: observation.source().provider().as_str().to_owned(),
            canonical_session_id: session_id.to_owned(),
            source_key: observation.source().source_key().as_str().to_owned(),
            stable_record_id: observation
                .identity()
                .native_record_id()
                .map(|id| id.as_str().to_owned()),
            observation_id: observation_id.to_owned(),
            source_revision: envelope.evidence().revision().map(str::to_owned),
            content_sha256: hex::encode(Sha256::digest(canonical_bytes)),
        },
        origin_scope: RecallOriginScopeEvidenceV1::Recorded {
            exact_scope_identity: outcome_scope(&origin),
            authority_ref: format!("{ORIGIN_AUTHORITY_PREFIX}{observation_id}"),
        },
        source_sequence: stored.sequence(),
        occurred_at: anchor
            .occurred_at()
            .map(|interval| utc_timestamp(interval.start.0))
            .transpose()?,
        ingested_at: utc_timestamp(anchor.ingested_at().0)?,
        validity: RecallRecordedValidityV1 {
            valid_from: None,
            valid_until: None,
            superseded_at: None,
            superseded_by: None,
            revoked_at: None,
        },
    };
    attribution
        .to_owned_attribution()
        .map_err(|reason| ObservationAttributionErrorV1::Invalid(format!("{reason:?}")))?;
    Ok(attribution)
}

/// The owned form of a derived attribution, for equality with a provider's
/// structurally admitted claim. Timestamps compare as instants, not strings.
pub(crate) fn owned_attribution(
    attribution: &RecallSourceAttributionV1,
) -> Result<SourceAttribution, ObservationAttributionErrorV1> {
    attribution
        .to_owned_attribution()
        .map_err(|reason| ObservationAttributionErrorV1::Invalid(format!("{reason:?}")))
}

fn outcome_scope(scope: &OwnedExactScope) -> RecallOutcomeScopeV1 {
    RecallOutcomeScopeV1 {
        profile_id: scope.profile_id.clone(),
        project_id: scope.project_id.clone(),
        repository_identity: scope.repository_identity.clone(),
        worktree_identity: scope.worktree_identity.clone(),
        branch_identity: scope.branch_identity.clone(),
        agent_session_id: scope.agent_session_id.clone(),
        resolved_scope_digest: scope.resolved_scope_digest.clone(),
    }
}

/// UTC RFC 3339 with nanosecond precision, the shared attribution clock form.
fn utc_timestamp(micros: i64) -> Result<String, ObservationAttributionErrorV1> {
    let nanos = micros
        .checked_mul(1_000)
        .ok_or(ObservationAttributionErrorV1::Timestamp)?;
    Ok(chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(nanos)
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}
