//! Host admission authority for provider recall replies.
//!
//! A provider answers a recall call with a canonical
//! `tracedecay.memory.recall.query.outcome.v1` outcome. Nothing in that outcome is
//! trusted on its own: every candidate re-asserts the exact coding scope and a
//! validity record, and this module is the single place where those provider
//! claims are compared against the scope and temporal query the host itself
//! admitted when it built the [`ProviderCall`].
//!
//! Admission is **rank-final**: it runs after the provider's own ordering and
//! before any normalization, deduplication, or context packing. Later stages
//! consume only [`RecallAdmission::admitted`]; a denied candidate survives only
//! as a [`DeniedRecallCandidate`] ledger row that carries identity, reason, and
//! the provider's claimed scope digest — never content — so it is structurally
//! unable to re-enter a prompt while remaining fully audit-visible.
//!
//! Provider assertions cannot widen scope or validity. Every candidate names
//! the [`ScopeBinding`] it attests (`exact_coding_scope`, `checkout_observations`,
//! `project_facts`, or `profile_facts`, following the authority-matrix boundaries); the host
//! admits a binding only when the registry recorded it as authorized for the
//! provider at registration ([`RecallScopeBindingsV1`], carried with the
//! admitted call and never read from a reply), and then applies that
//! binding's required / optional / forbidden identity-field rules against the
//! admitted scope byte-for-byte. A `temporal_state` the provider claims must
//! agree with the state the host computes from the validity timestamps, and
//! unknown validity is governed by the host's admitted
//! [`UnknownValidityPolicy`], never by the provider.

use std::collections::BTreeSet;

#[path = "recall_source_attribution.rs"]
/// Strict canonical source attribution wire projections; decoding grants no authority.
pub mod source_attribution;

use source_attribution::{RecallSourceAttributionV1, original_sources_from_provenance};

use chrono::{DateTime, SecondsFormat};
use serde::de::{Deserializer, Error as _};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use tracedecay_domain::CanonicalObservationIdV1;
use tracedecay_memory_provider_api::contract::{TemporalMode, TerminalCode};

use crate::recall_normalization::{
    NativeScoreDefect, NativeScoreV1, ValidatedNativeScoreV1, validate_native_score,
};
use crate::recall_provenance_hydration::HostEvidenceRefV1;
use tracedecay_memory_provider_api::{
    ApiError, CanonicalPayload, OwnedExactScope, OwnedProviderId, OwnedVersionedId, ProviderCall,
    ProviderReply,
};
use tracedecay_memory_provider_native::RECALL_RESULT_CONTRACT_ID;

/// Canonical payload contract identity of recall requests.
pub const RECALL_REQUEST_CONTRACT_ID: &str = "tracedecay.memory.provider.recall.v1";

/// Capability every recall call requires.
pub const RECALL_QUERY_CAPABILITY_ID: &str = "recall.query.v1";

/// Maximum bytes of a decode diagnostic retained in a typed error.
const MAX_DECODE_DETAIL_BYTES: usize = 512;

/// Host policy for candidates whose validity the provider could not establish.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownValidityPolicy {
    /// Deny the candidate and record it in the ledger.
    Exclude,
    /// Admit the candidate but mark the whole recall lane degraded.
    Degrade,
    /// Admit the candidate with an explicit per-candidate warning.
    AllowWithWarning,
}

impl UnknownValidityPolicy {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Exclude => "exclude",
            Self::Degrade => "degrade",
            Self::AllowWithWarning => "allow_with_warning",
        }
    }
}

/// Closed set of temporal states a validity record may be in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalState {
    /// Valid at the evaluation instant.
    Current,
    /// `valid_from` lies after the evaluation instant.
    Future,
    /// `valid_until` lies at or before the evaluation instant.
    Expired,
    /// A later record supersedes this one.
    Superseded,
    /// The record was revoked.
    Revoked,
    /// The provider could not establish validity.
    Unknown,
}

impl TemporalState {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Future => "future",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "current" => Some(Self::Current),
            "future" => Some(Self::Future),
            "expired" => Some(Self::Expired),
            "superseded" => Some(Self::Superseded),
            "revoked" => Some(Self::Revoked),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// One exact-scope identity field, named for denial ledgers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeField {
    /// `profile_id`.
    ProfileId,
    /// `project_id`.
    ProjectId,
    /// `repository_identity`.
    RepositoryIdentity,
    /// `worktree_identity`.
    WorktreeIdentity,
    /// `branch_identity`.
    BranchIdentity,
    /// `agent_session_id`.
    AgentSessionId,
    /// `resolved_scope_digest`.
    ResolvedScopeDigest,
}

/// Identity namespace one candidate attests, mirroring the namespace variants
/// of the accepted coding-memory authority matrix. Wire values are those of
/// `tracedecay.memory.provider.recall.v1` `candidate_scope_binding.bindings`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeBinding {
    /// All seven identity fields bind byte-for-byte to the admitted scope.
    ExactCodingScope,
    /// A staged observation of this checkout: profile, project, repository,
    /// worktree and branch bind; session and resolved-scope digest are forbidden.
    CheckoutObservations,
    /// A project-owned fact: profile and project bind; repository, worktree,
    /// and branch are optional; session and resolved-scope digest are
    /// forbidden.
    ProjectFacts,
    /// A profile-owned fact: only the profile binds; every other field is
    /// forbidden.
    ProfileFacts,
}

impl ScopeBinding {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::ExactCodingScope => "exact_coding_scope",
            Self::CheckoutObservations => "checkout_observations",
            Self::ProjectFacts => "project_facts",
            Self::ProfileFacts => "profile_facts",
        }
    }

    /// Decodes one canonical wire value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "exact_coding_scope" => Some(Self::ExactCodingScope),
            "checkout_observations" => Some(Self::CheckoutObservations),
            "project_facts" => Some(Self::ProjectFacts),
            "profile_facts" => Some(Self::ProfileFacts),
            _ => None,
        }
    }

    /// The rule this binding applies to one identity field, per the
    /// contract's `candidate_scope_binding.binding_rules`.
    const fn field_rule(self, field: ScopeField) -> ScopeFieldRule {
        match self {
            Self::ExactCodingScope => ScopeFieldRule::RequiredEqual,
            Self::CheckoutObservations => match field {
                ScopeField::AgentSessionId | ScopeField::ResolvedScopeDigest => {
                    ScopeFieldRule::Forbidden
                }
                _ => ScopeFieldRule::RequiredEqual,
            },
            Self::ProjectFacts => match field {
                ScopeField::ProfileId | ScopeField::ProjectId => ScopeFieldRule::RequiredEqual,
                ScopeField::RepositoryIdentity
                | ScopeField::WorktreeIdentity
                | ScopeField::BranchIdentity => ScopeFieldRule::OptionalEmptyOrEqual,
                ScopeField::AgentSessionId | ScopeField::ResolvedScopeDigest => {
                    ScopeFieldRule::Forbidden
                }
            },
            Self::ProfileFacts => match field {
                ScopeField::ProfileId => ScopeFieldRule::RequiredEqual,
                _ => ScopeFieldRule::Forbidden,
            },
        }
    }
}

/// How one binding treats one identity field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopeFieldRule {
    /// Must be non-empty and byte-equal to the admitted scope.
    RequiredEqual,
    /// Either empty or byte-equal to the admitted scope.
    OptionalEmptyOrEqual,
    /// Must be empty.
    Forbidden,
}

/// Scope bindings the registry authorized one provider to attest, recorded
/// at registration and handed to admission with the admitted call.
///
/// This is host-owned data: a provider reply can neither declare nor widen
/// it. An empty set authorizes nothing, so every candidate is denied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecallScopeBindingsV1(BTreeSet<ScopeBinding>);

impl RecallScopeBindingsV1 {
    /// Builds the authorized set from typed bindings.
    pub fn new(bindings: impl IntoIterator<Item = ScopeBinding>) -> Self {
        Self(bindings.into_iter().collect())
    }

    /// Builds the authorized set from contract wire values, refusing any
    /// value outside the closed contract vocabulary.
    pub fn from_wire<'a>(
        values: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, RecallAdmissionError> {
        let mut bindings = BTreeSet::new();
        for value in values {
            let binding = ScopeBinding::from_wire(value).ok_or_else(|| {
                RecallAdmissionError::ScopeBindingUnknown {
                    value: bounded_detail(value),
                }
            })?;
            bindings.insert(binding);
        }
        Ok(Self(bindings))
    }

    /// Returns whether `binding` is authorized.
    #[must_use]
    pub fn authorizes(&self, binding: ScopeBinding) -> bool {
        self.0.contains(&binding)
    }

    /// Iterates the authorized bindings in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = ScopeBinding> + '_ {
        self.0.iter().copied()
    }

    /// Returns whether nothing is authorized.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Typed reason one candidate was refused admission.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecallDenialReason {
    /// The candidate attests a scope binding the registry did not authorize
    /// for its provider.
    ScopeBindingUnauthorized {
        /// The binding the provider claimed.
        binding: ScopeBinding,
    },
    /// The candidate's declared memory class may not be admitted under the
    /// scope binding it claimed, whatever the provider is otherwise
    /// authorized for.
    MemoryClassBindingUnauthorized {
        /// Host-recognised memory class the candidate declared. Never
        /// provider bytes: the field is set from the host's own constant for
        /// the class the policy matched.
        memory_class: String,
        /// The binding the provider claimed for that class.
        binding: ScopeBinding,
    },
    /// An identity field differs from the admitted scope.
    ScopeMismatch {
        /// First differing field in contract order.
        field: ScopeField,
    },
    /// Every identity field matches but the resolved scope digest does not:
    /// the candidate belongs to an earlier resolution of this checkout.
    StaleIdentity,
    /// The candidate carries an identity the host cannot resolve at all.
    UnknownIdentity {
        /// Empty or malformed field.
        field: ScopeField,
    },
    /// The candidate carries an identity its scope binding forbids.
    ForbiddenIdentity {
        /// First non-empty forbidden field in contract order.
        field: ScopeField,
    },
    /// `valid_from` lies after the evaluation window.
    NotYetValid,
    /// `valid_until` lies at or before the evaluation window.
    Expired,
    /// The record is revoked and the query did not include revoked records.
    Revoked,
    /// The record is superseded and the query did not include superseded
    /// records.
    Superseded,
    /// Validity is unknown and the admitted policy excludes such records.
    UnknownValidity,
    /// The validity record is internally inconsistent or contradicts the
    /// provider's own claimed temporal state.
    InvalidValidityRecord {
        /// Bounded, content-free description of the inconsistency.
        detail: String,
    },
    /// Original-source attribution is malformed, unbounded or inconsistent.
    InvalidSourceAttribution {
        /// Bounded content-free structural defect, never raw source content.
        detail: String,
    },
    /// A returned candidate matches an exclusion in the dispatched request.
    RequestExcluded {
        /// Host-owned canonical exclusion field name, without provider content.
        field: String,
    },
    /// Inline content does not hash to the declared `content_sha256`.
    ContentDigestMismatch,
    /// The candidate carries neither or both of `content` / `content_ref`.
    ContentSelectionInvalid,
    /// The provider-native score is absent, malformed, non-finite, or
    /// contradicts the range the provider itself declared, so no honest
    /// relevance can be established for the candidate.
    NativeScoreMalformed {
        /// The first defect found in contract field order.
        defect: NativeScoreDefect,
    },
    /// The provider confidence datum is not a finite JSON number in the
    /// inclusive unit interval.
    ConfidenceMalformed {
        /// The defect found in the provider confidence datum.
        defect: RecallConfidenceDefect,
    },
}

impl RecallDenialReason {
    /// Stable snake_case label for metrics and log fields.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ScopeBindingUnauthorized { .. } => "scope_binding_unauthorized",
            Self::MemoryClassBindingUnauthorized { .. } => "memory_class_binding_unauthorized",
            Self::ScopeMismatch { .. } => "scope_mismatch",
            Self::StaleIdentity => "stale_identity",
            Self::UnknownIdentity { .. } => "unknown_identity",
            Self::ForbiddenIdentity { .. } => "forbidden_identity",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::UnknownValidity => "unknown_validity",
            Self::InvalidValidityRecord { .. } => "invalid_validity_record",
            Self::InvalidSourceAttribution { .. } => "invalid_source_attribution",
            Self::RequestExcluded { .. } => "request_excluded",
            Self::ContentDigestMismatch => "content_digest_mismatch",
            Self::ContentSelectionInvalid => "content_selection_invalid",
            Self::NativeScoreMalformed { .. } => "native_score_malformed",
            Self::ConfidenceMalformed { .. } => "confidence_malformed",
        }
    }

    /// Returns the reason safe to embed in a retained explain trace.
    ///
    /// Parser diagnostics are provider-controlled strings even though the
    /// surrounding denial variant is host-owned. Replace those diagnostics
    /// before serializing the typed decision so a caller cannot bypass the
    /// trace's bounded detail projection by inspecting its nested reason.
    pub(crate) fn retained_for_trace(&self) -> Self {
        match self {
            Self::InvalidValidityRecord { .. } => Self::InvalidValidityRecord {
                detail: "provider_validity_detail_withheld".to_owned(),
            },
            Self::InvalidSourceAttribution { .. } => Self::InvalidSourceAttribution {
                detail: "provider_source_detail_withheld".to_owned(),
            },
            Self::NativeScoreMalformed {
                defect: NativeScoreDefect::Undecodable { .. },
            } => Self::NativeScoreMalformed {
                defect: NativeScoreDefect::Undecodable {
                    detail: "provider_score_detail_withheld".to_owned(),
                },
            },
            _ => self.clone(),
        }
    }
}

/// Why a supplied provider confidence datum cannot be admitted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallConfidenceDefect {
    /// The non-null datum is not a JSON number.
    NotNumber,
    /// The number cannot be represented as a finite host value.
    NotFinite,
    /// The number lies outside the inclusive `0.0..=1.0` interval.
    OutOfRange,
}

impl RecallConfidenceDefect {
    /// Stable snake_case label for metrics and log fields.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotNumber => "not_number",
            Self::NotFinite => "not_finite",
            Self::OutOfRange => "out_of_range",
        }
    }
}

/// Failure that prevents admission from producing any decision at all.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecallAdmissionError {
    /// The reply terminal is not a success, zero-result, or partial terminal.
    #[error("recall terminal {} carries no admissible outcome", .terminal_code.as_wire())]
    TerminalNotSuccessful {
        /// The reply terminal code.
        terminal_code: TerminalCode,
    },
    /// A successful terminal arrived without the mandatory outcome payload.
    #[error("recall reply terminal succeeded without an outcome payload")]
    MissingPayload,
    /// The payload names a contract other than the recall outcome contract.
    #[error("recall payload contract {contract_id} is not {RECALL_RESULT_CONTRACT_ID}")]
    PayloadContractMismatch {
        /// The declared contract identity.
        contract_id: String,
    },
    /// The payload bytes are not a canonical recall outcome.
    #[error("recall outcome payload could not be decoded: {detail}")]
    PayloadDecode {
        /// Bounded decoder diagnostic.
        detail: String,
    },
    /// The outcome envelope names a different call than the one dispatched.
    #[error("recall outcome {field} does not match the dispatched call")]
    OutcomeBinding {
        /// The mismatching envelope field.
        field: &'static str,
    },
    /// The provider returned more candidates than the admitted budget.
    #[error("recall outcome returned {returned} candidates over the admitted budget {maximum}")]
    CandidateBudgetExceeded {
        /// Candidates returned.
        returned: usize,
        /// Admitted maximum.
        maximum: usize,
    },
    /// Two candidates share one request-scoped identity.
    #[error("recall outcome repeats candidate id {0}")]
    DuplicateCandidateId(String),
    /// The admitted temporal query is malformed.
    #[error("recall temporal query {field} is invalid: {detail}")]
    InvalidTemporalQuery {
        /// The offending field.
        field: &'static str,
        /// Bounded diagnostic.
        detail: &'static str,
    },
    /// The dispatched request did not carry valid canonical exclusions.
    #[error("recall request exclusions invalid: {detail}")]
    InvalidRequestExclusions {
        /// Bounded structural diagnostic.
        detail: String,
    },
    /// A recall request part failed API validation.
    #[error("recall request part invalid: {0}")]
    Api(#[from] ApiError),
    /// A registry-declared scope binding is outside the contract vocabulary.
    #[error("recall scope binding {value} is not a contract value")]
    ScopeBindingUnknown {
        /// The offending wire value, bounded.
        value: String,
    },
    /// The request could not be encoded.
    #[error("recall request could not be encoded: {detail}")]
    RequestEncode {
        /// Bounded encoder diagnostic.
        detail: String,
    },
}

/// Parses one `utc_rfc3339_nanos` timestamp into UTC nanoseconds since epoch.
///
/// This is the only instant parser the admission authority uses; hosts that
/// project their own instants onto the wire compare against it rather than
/// against a second parser.
#[must_use]
pub fn parse_rfc3339_nanos(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()?
        .timestamp_nanos_opt()
}

/// Formats UTC microseconds since epoch as an RFC 3339 UTC timestamp with
/// microsecond precision, the representation recall requests carry.
#[must_use]
pub fn rfc3339_utc_micros(micros: i64) -> Option<String> {
    DateTime::from_timestamp_micros(micros)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true))
}

/// Temporal query the host admitted for one recall.
///
/// Every instant is retained both as the canonical wire string (so the
/// request payload carries exactly what was admitted) and as parsed UTC
/// nanoseconds (so admission arithmetic never re-parses provider input).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedTemporalQuery {
    mode: TemporalMode,
    evaluation_time: String,
    evaluation_nanos: i64,
    as_of: Option<(String, i64)>,
    interval: Option<((String, i64), (String, i64))>,
    include_superseded: bool,
    include_revoked: bool,
    unknown_validity_policy: UnknownValidityPolicy,
}

impl AdmittedTemporalQuery {
    /// Builds a `current` query evaluated at `evaluation_time`.
    pub fn current(evaluation_time: &str) -> Result<Self, RecallAdmissionError> {
        let evaluation_nanos = parse_instant(evaluation_time, "evaluation_time")?;
        Ok(Self {
            mode: TemporalMode::Current,
            evaluation_time: evaluation_time.to_owned(),
            evaluation_nanos,
            as_of: None,
            interval: None,
            include_superseded: false,
            include_revoked: false,
            unknown_validity_policy: UnknownValidityPolicy::Exclude,
        })
    }

    /// Builds an `as_of` query evaluated at `as_of`.
    pub fn as_of(evaluation_time: &str, as_of: &str) -> Result<Self, RecallAdmissionError> {
        let mut query = Self::current(evaluation_time)?;
        let as_of_nanos = parse_instant(as_of, "as_of")?;
        if as_of_nanos > query.evaluation_nanos {
            return Err(RecallAdmissionError::InvalidTemporalQuery {
                field: "as_of",
                detail: "as_of lies after evaluation_time",
            });
        }
        query.mode = TemporalMode::AsOf;
        query.as_of = Some((as_of.to_owned(), as_of_nanos));
        Ok(query)
    }

    /// Builds an `interval` query over `[interval_start, interval_end)`.
    pub fn interval(
        evaluation_time: &str,
        interval_start: &str,
        interval_end: &str,
    ) -> Result<Self, RecallAdmissionError> {
        let mut query = Self::current(evaluation_time)?;
        let start = parse_instant(interval_start, "interval_start")?;
        let end = parse_instant(interval_end, "interval_end")?;
        if start >= end {
            return Err(RecallAdmissionError::InvalidTemporalQuery {
                field: "interval_end",
                detail: "interval_end must lie after interval_start",
            });
        }
        query.mode = TemporalMode::Interval;
        query.interval = Some((
            (interval_start.to_owned(), start),
            (interval_end.to_owned(), end),
        ));
        Ok(query)
    }

    /// Builds a `history` query that retains historical records with their
    /// validity metadata.
    pub fn history(evaluation_time: &str) -> Result<Self, RecallAdmissionError> {
        let mut query = Self::current(evaluation_time)?;
        query.mode = TemporalMode::History;
        Ok(query)
    }

    /// Admits superseded records instead of denying them.
    #[must_use]
    pub const fn with_include_superseded(mut self, include: bool) -> Self {
        self.include_superseded = include;
        self
    }

    /// Admits revoked records instead of denying them.
    #[must_use]
    pub const fn with_include_revoked(mut self, include: bool) -> Self {
        self.include_revoked = include;
        self
    }

    /// Sets the policy for records with unknown validity.
    #[must_use]
    pub const fn with_unknown_validity_policy(mut self, policy: UnknownValidityPolicy) -> Self {
        self.unknown_validity_policy = policy;
        self
    }

    /// Returns the temporal mode.
    #[must_use]
    pub const fn mode(&self) -> TemporalMode {
        self.mode
    }

    /// Returns the admitted evaluation instant as the canonical wire string.
    #[must_use]
    pub fn evaluation_time(&self) -> &str {
        &self.evaluation_time
    }

    /// Returns the admitted evaluation instant in UTC nanoseconds.
    #[must_use]
    pub const fn evaluation_nanos(&self) -> i64 {
        self.evaluation_nanos
    }

    /// Returns the unknown-validity policy.
    #[must_use]
    pub const fn unknown_validity_policy(&self) -> UnknownValidityPolicy {
        self.unknown_validity_policy
    }

    /// Returns whether the query admits revoked records.
    #[must_use]
    pub const fn include_revoked(&self) -> bool {
        self.include_revoked
    }

    /// Returns whether the query admits superseded records.
    #[must_use]
    pub const fn include_superseded(&self) -> bool {
        self.include_superseded
    }

    /// Returns the canonical `temporal_query` wire object.
    #[must_use]
    pub fn to_wire_value(&self) -> Value {
        let (interval_start, interval_end) = self
            .interval
            .as_ref()
            .map_or((Value::Null, Value::Null), |((start, _), (end, _))| {
                (Value::String(start.clone()), Value::String(end.clone()))
            });
        serde_json::json!({
            "mode": self.mode.as_wire(),
            "evaluation_time": self.evaluation_time,
            "as_of": self.as_of.as_ref().map_or(Value::Null, |(value, _)| Value::String(value.clone())),
            "interval_start": interval_start,
            "interval_end": interval_end,
            "include_superseded": self.include_superseded,
            "include_revoked": self.include_revoked,
            "unknown_validity_policy": self.unknown_validity_policy.as_wire(),
        })
    }

    /// The single instant a point query evaluates validity at.
    fn point_instant(&self) -> Option<i64> {
        match self.mode {
            TemporalMode::Current => Some(self.evaluation_nanos),
            TemporalMode::AsOf => self.as_of.as_ref().map(|(_, nanos)| *nanos),
            TemporalMode::Interval | TemporalMode::History => None,
        }
    }
}

fn parse_instant(value: &str, field: &'static str) -> Result<i64, RecallAdmissionError> {
    parse_rfc3339_nanos(value).ok_or(RecallAdmissionError::InvalidTemporalQuery {
        field,
        detail: "not a utc_rfc3339_nanos timestamp",
    })
}

/// Positive, finite recall budgets the host admits for one request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallBudgetsV1 {
    /// Maximum candidates the provider may return.
    pub maximum_candidates: u64,
    /// Maximum inline content bytes per candidate.
    pub maximum_candidate_content_bytes: u64,
    /// Maximum inline content bytes across all candidates.
    pub maximum_total_content_bytes: u64,
    /// Maximum source references per candidate.
    pub maximum_source_refs_per_candidate: u64,
    /// Maximum trace references per candidate.
    pub maximum_trace_refs_per_candidate: u64,
    /// Maximum warnings in the outcome.
    pub maximum_warnings: u64,
    /// Maximum opaque extensions per candidate.
    pub maximum_extensions_per_candidate: u64,
}

impl RecallBudgetsV1 {
    /// Rejects zero budgets, which the contract forbids.
    pub fn validate(&self) -> Result<(), RecallAdmissionError> {
        for (field, value) in [
            ("maximum_candidates", self.maximum_candidates),
            (
                "maximum_candidate_content_bytes",
                self.maximum_candidate_content_bytes,
            ),
            (
                "maximum_total_content_bytes",
                self.maximum_total_content_bytes,
            ),
            (
                "maximum_source_refs_per_candidate",
                self.maximum_source_refs_per_candidate,
            ),
            (
                "maximum_trace_refs_per_candidate",
                self.maximum_trace_refs_per_candidate,
            ),
            ("maximum_warnings", self.maximum_warnings),
            (
                "maximum_extensions_per_candidate",
                self.maximum_extensions_per_candidate,
            ),
        ] {
            if value == 0 {
                return Err(RecallAdmissionError::InvalidTemporalQuery {
                    field,
                    detail: "recall budgets must be positive",
                });
            }
        }
        Ok(())
    }
}

/// Everything the host binds into one canonical recall request payload.
#[derive(Clone, Debug)]
pub struct RecallRequestParts {
    /// Target provider identity.
    pub provider_id: OwnedProviderId,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Fabric-validated ready-receipt digest.
    pub ready_receipt_sha256: String,
    /// Exact coding scope the host admitted.
    pub exact_scope: OwnedExactScope,
    /// Stable request identity.
    pub request_id: String,
    /// Bounded objective text.
    pub objective: String,
    /// Bounded query text.
    pub query: String,
    /// Admitted temporal query.
    pub temporal: AdmittedTemporalQuery,
    /// Admitted budgets.
    pub budgets: RecallBudgetsV1,
    /// Pinned policy revision.
    pub policy_revision: u64,
    /// Absolute UTC deadline in microseconds.
    pub deadline_utc_micros: i64,
    /// Remaining budget in milliseconds at dispatch.
    pub remaining_millis: u64,
}

/// Builds the canonical recall request payload bound to the admitted parts.
pub fn build_recall_request_payload(
    parts: &RecallRequestParts,
) -> Result<CanonicalPayload, RecallAdmissionError> {
    build_recall_request_payload_with_context(parts, None, None)
}

/// Attaches only host-admitted exclusions and canonical history grant JSON.
/// Source authorization remains with the mounted host authority at dispatch.
/// The complete value is encoded and hashed once, after these fields are bound.
pub fn build_recall_request_payload_with_context(
    parts: &RecallRequestParts,
    exclusions: Option<&tracedecay_contracts::memory::CognitiveRecallExclusions>,
    history_grant: Option<&Value>,
) -> Result<CanonicalPayload, RecallAdmissionError> {
    build_recall_request_payload_with_capabilities(
        parts,
        exclusions,
        history_grant,
        &[OwnedVersionedId::new(RECALL_QUERY_CAPABILITY_ID)?],
    )
}

/// Bind the exact unique capabilities already selected by the host recall plan.
/// Public legacy builders retain their recall-only capability requirement.
pub(crate) fn build_recall_request_payload_with_capabilities(
    parts: &RecallRequestParts,
    exclusions: Option<&tracedecay_contracts::memory::CognitiveRecallExclusions>,
    history_grant: Option<&Value>,
    required_capabilities: &[OwnedVersionedId],
) -> Result<CanonicalPayload, RecallAdmissionError> {
    parts.exact_scope.validate()?;
    parts.budgets.validate()?;
    if let Some(exclusions) = exclusions {
        exclusions
            .validate()
            .map_err(|_| RecallAdmissionError::InvalidTemporalQuery {
                field: "exclusions",
                detail: "exclusions violate the admitted application bounds",
            })?;
    }
    if let Some(grant) = history_grant
        && (!grant.is_object()
            || grant.get("policy_revision").and_then(Value::as_u64) != Some(parts.policy_revision)
            || grant.get("destination_scope") != Some(&scope_wire_value(&parts.exact_scope)))
    {
        return Err(RecallAdmissionError::InvalidTemporalQuery {
            field: "history_grant",
            detail: "history grant must bind the request policy and exact destination",
        });
    }
    if parts.policy_revision == 0 {
        return Err(RecallAdmissionError::InvalidTemporalQuery {
            field: "policy_revision",
            detail: "policy revision must be positive",
        });
    }
    let mut value = serde_json::json!({
        "provider_id": parts.provider_id.as_str(),
        "registration_revision": parts.registration_revision,
        "ready_receipt_digest": parts.ready_receipt_sha256,
        "exact_scope_identity": scope_wire_value(&parts.exact_scope),
        "request_identity": parts.request_id,
        "objective": parts.objective,
        "query": parts.query,
        "temporal_query": parts.temporal.to_wire_value(),
        "budgets": parts.budgets,
        "exclusions": {
            "stable_memory_refs": [],
            "candidate_ids": [],
            "source_refs": [],
            "trace_refs": [],
            "observation_ids": [],
            "content_sha256": [],
        },
        "required_capabilities": required_capabilities.iter().map(OwnedVersionedId::as_str).collect::<Vec<_>>(),
        "policy_revision": parts.policy_revision,
        "extensions": [],
        "deadline": {
            "deadline_utc_micros": parts.deadline_utc_micros,
            "remaining_millis": parts.remaining_millis,
        },
        "cancellation": "live",
    });
    if let Some(exclusions) = exclusions {
        value["exclusions"] = serde_json::to_value(exclusions).map_err(|error| {
            RecallAdmissionError::RequestEncode {
                detail: bounded_detail(&error.to_string()),
            }
        })?;
    }
    if let Some(grant) = history_grant {
        value["history_grant"] = grant.clone();
    }
    let bytes =
        serde_json::to_vec(&value).map_err(|error| RecallAdmissionError::RequestEncode {
            detail: bounded_detail(&error.to_string()),
        })?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(CanonicalPayload::new(
        OwnedVersionedId::new(RECALL_REQUEST_CONTRACT_ID)?,
        bytes,
        sha256,
    )?)
}

fn scope_wire_value(scope: &OwnedExactScope) -> Value {
    serde_json::json!({
        "profile_id": scope.profile_id,
        "project_id": scope.project_id,
        "repository_identity": scope.repository_identity,
        "worktree_identity": scope.worktree_identity,
        "branch_identity": scope.branch_identity,
        "agent_session_id": scope.agent_session_id,
        "resolved_scope_digest": scope.resolved_scope_digest,
    })
}

/// Requires a nullable field to be present on the wire; `null` decodes to
/// `None`, a missing key is a contract violation.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Exact-scope identity as a provider asserts it on one candidate, together
/// with the explicit binding that says which fields the provider attests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallScopeIdentityV1 {
    /// Which identity namespace the provider attests for this candidate.
    pub scope_binding: ScopeBinding,
    /// Claimed profile identity.
    pub profile_id: String,
    /// Claimed project identity.
    pub project_id: String,
    /// Claimed repository identity.
    pub repository_identity: String,
    /// Claimed worktree identity.
    pub worktree_identity: String,
    /// Claimed branch identity.
    pub branch_identity: String,
    /// Claimed agent session identity.
    pub agent_session_id: String,
    /// Claimed resolved scope digest.
    pub resolved_scope_digest: String,
}

impl RecallScopeIdentityV1 {
    /// Digest of the claimed scope, when the claim is well-formed enough to
    /// digest. A malformed claim yields `None` rather than a fabricated digest.
    #[must_use]
    pub fn claimed_scope_sha256(&self) -> Option<String> {
        OwnedExactScope::new(
            self.profile_id.as_str(),
            self.project_id.as_str(),
            self.repository_identity.as_str(),
            self.worktree_identity.as_str(),
            self.branch_identity.as_str(),
            self.agent_session_id.as_str(),
            self.resolved_scope_digest.as_str(),
        )
        .ok()
        .map(|scope| scope.exact_scope_sha256())
    }

    fn fields(&self) -> [(ScopeField, &str); 7] {
        [
            (ScopeField::ProfileId, self.profile_id.as_str()),
            (ScopeField::ProjectId, self.project_id.as_str()),
            (
                ScopeField::RepositoryIdentity,
                self.repository_identity.as_str(),
            ),
            (
                ScopeField::WorktreeIdentity,
                self.worktree_identity.as_str(),
            ),
            (ScopeField::BranchIdentity, self.branch_identity.as_str()),
            (ScopeField::AgentSessionId, self.agent_session_id.as_str()),
            (
                ScopeField::ResolvedScopeDigest,
                self.resolved_scope_digest.as_str(),
            ),
        ]
    }
}

/// Scope the provider searched, re-asserted on the outcome envelope. This is
/// a binding to the request the provider answered, never an attestation
/// about any candidate, so it carries no `scope_binding`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallOutcomeScopeV1 {
    /// Searched profile identity.
    pub profile_id: String,
    /// Searched project identity.
    pub project_id: String,
    /// Searched repository identity.
    pub repository_identity: String,
    /// Searched worktree identity.
    pub worktree_identity: String,
    /// Searched branch identity.
    pub branch_identity: String,
    /// Searched agent session identity.
    pub agent_session_id: String,
    /// Searched resolved scope digest.
    pub resolved_scope_digest: String,
}

impl RecallOutcomeScopeV1 {
    fn fields(&self) -> [(ScopeField, &str); 7] {
        [
            (ScopeField::ProfileId, self.profile_id.as_str()),
            (ScopeField::ProjectId, self.project_id.as_str()),
            (
                ScopeField::RepositoryIdentity,
                self.repository_identity.as_str(),
            ),
            (
                ScopeField::WorktreeIdentity,
                self.worktree_identity.as_str(),
            ),
            (ScopeField::BranchIdentity, self.branch_identity.as_str()),
            (ScopeField::AgentSessionId, self.agent_session_id.as_str()),
            (
                ScopeField::ResolvedScopeDigest,
                self.resolved_scope_digest.as_str(),
            ),
        ]
    }
}

fn admitted_scope_fields(scope: &OwnedExactScope) -> [(ScopeField, &str); 7] {
    [
        (ScopeField::ProfileId, scope.profile_id.as_str()),
        (ScopeField::ProjectId, scope.project_id.as_str()),
        (
            ScopeField::RepositoryIdentity,
            scope.repository_identity.as_str(),
        ),
        (
            ScopeField::WorktreeIdentity,
            scope.worktree_identity.as_str(),
        ),
        (ScopeField::BranchIdentity, scope.branch_identity.as_str()),
        (ScopeField::AgentSessionId, scope.agent_session_id.as_str()),
        (
            ScopeField::ResolvedScopeDigest,
            scope.resolved_scope_digest.as_str(),
        ),
    ]
}

/// Validity record as a provider asserts it on one candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallValidityV1 {
    /// When the provider observed the record.
    #[serde(deserialize_with = "required_nullable")]
    pub observed_at: Option<String>,
    /// Start of validity, inclusive.
    #[serde(deserialize_with = "required_nullable")]
    pub valid_from: Option<String>,
    /// End of validity, exclusive; `null` is open-ended.
    #[serde(deserialize_with = "required_nullable")]
    pub valid_until: Option<String>,
    /// When a later record superseded this one.
    #[serde(deserialize_with = "required_nullable")]
    pub superseded_at: Option<String>,
    /// Stable reference of the superseding record.
    #[serde(deserialize_with = "required_nullable")]
    pub superseded_by: Option<String>,
    /// When the record was revoked.
    #[serde(deserialize_with = "required_nullable")]
    pub revoked_at: Option<String>,
    /// Provider-local source revision.
    #[serde(deserialize_with = "required_nullable")]
    pub source_revision: Option<String>,
    /// Temporal state the provider claims.
    pub temporal_state: String,
}

/// One raw provider confidence datum, retained until admission classifies it.
#[derive(Clone, Debug)]
pub struct RecallConfidenceWire(Box<RawValue>);

impl PartialEq for RecallConfidenceWire {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}

impl Eq for RecallConfidenceWire {}

impl Serialize for RecallConfidenceWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecallConfidenceWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Box::<RawValue>::deserialize(deserializer).map(Self)
    }
}

/// One candidate exactly as the provider returned it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallCandidateV1 {
    /// Request-scoped candidate identity.
    pub candidate_id: String,
    /// Optional stable provider memory reference.
    #[serde(deserialize_with = "required_nullable")]
    pub stable_memory_ref: Option<String>,
    /// Inline content, exclusive with `content_ref`.
    #[serde(deserialize_with = "required_nullable")]
    pub content: Option<String>,
    /// Content reference, exclusive with `content`.
    #[serde(deserialize_with = "required_nullable")]
    pub content_ref: Option<Value>,
    /// Canonical content digest.
    pub content_sha256: String,
    /// Provider-native score, retained opaque for host normalization.
    pub native_score: Value,
    /// Optional provider-supplied confidence. The key is required on the wire;
    /// `null` means the provider made no confidence claim.
    #[serde(deserialize_with = "required_nullable")]
    pub confidence: Option<RecallConfidenceWire>,
    /// Claimed exact scope.
    pub exact_scope_identity: RecallScopeIdentityV1,
    /// Claimed validity.
    pub validity: RecallValidityV1,
    /// Provenance record.
    pub provenance: Value,
    /// Explanation record.
    pub explanation: Value,
    /// Source references.
    pub source_refs: Vec<String>,
    /// Trace references.
    pub trace_refs: Vec<String>,
    /// Sensitivity label.
    pub sensitivity: String,
    /// Memory class.
    pub memory_class: Value,
    /// Provider warnings.
    pub warnings: Vec<String>,
    /// Opaque extensions.
    pub extensions: Vec<Value>,
}

/// Recall outcome envelope exactly as the provider returned it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallOutcomeV1 {
    /// Provider identity.
    pub provider_id: String,
    /// Provider runtime instance.
    pub provider_instance_id: String,
    /// Registration revision.
    pub registration_revision: u64,
    /// Ready-receipt digest.
    pub ready_receipt_digest: String,
    /// Request identity.
    pub request_identity: String,
    /// Scope the provider searched.
    pub exact_scope_identity: RecallOutcomeScopeV1,
    /// Provider state generation.
    pub provider_state_generation: u64,
    /// Candidates in provider order.
    pub candidates: Vec<RecallCandidateV1>,
    /// Coverage record.
    pub coverage: Value,
    /// Ordering record.
    pub ordering: Value,
    /// Terminal record.
    pub terminal: Value,
    /// Outcome warnings.
    pub warnings: Vec<String>,
}

/// Content carried by one admitted candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallCandidateContent<'candidate> {
    /// Inline content whose digest was verified.
    Inline(&'candidate str),
    /// A content reference that still needs scope-revalidated hydration.
    Reference(&'candidate Value),
}

/// One candidate that passed admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdmittedRecallCandidate {
    candidate: RecallCandidateV1,
    host_temporal_state: TemporalState,
    warnings: Vec<String>,
    native_score: ValidatedNativeScoreV1,
    confidence: Option<Number>,
    // The original wire fields remain in candidate.provenance. This typed
    // projection supplies validated access without another serialized authority.
    #[serde(skip)]
    original_sources: Vec<RecallSourceAttributionV1>,
}

impl AdmittedRecallCandidate {
    /// Structurally validated original source claims. Source existence, history
    /// relations and current disposition still require host revalidation.
    #[must_use]
    pub fn original_sources(&self) -> &[RecallSourceAttributionV1] {
        &self.original_sources
    }

    /// Observation claims whose declared provenance passed the canonical
    /// binding checks. Host authority must still confirm every source.
    #[must_use]
    pub fn observation_history_sources(&self) -> Option<&[RecallSourceAttributionV1]> {
        observation_history_claim(&self.candidate, &self.original_sources)
            .then_some(self.original_sources.as_slice())
    }
    /// Returns the candidate as the provider returned it.
    #[must_use]
    pub const fn candidate(&self) -> &RecallCandidateV1 {
        &self.candidate
    }

    /// Returns the temporal state the host computed for the candidate.
    #[must_use]
    pub const fn host_temporal_state(&self) -> TemporalState {
        self.host_temporal_state
    }

    /// Returns the scope binding the candidate was admitted under.
    #[must_use]
    pub const fn scope_binding(&self) -> ScopeBinding {
        self.candidate.exact_scope_identity.scope_binding
    }

    /// Returns host warnings attached at admission.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Returns the provider-native score exactly as declared. Admission
    /// established it is well formed; nothing here rewrites it.
    #[must_use]
    pub const fn native_score(&self) -> &NativeScoreV1 {
        self.native_score.score()
    }

    /// Returns the framed digest of the declared native score, which host
    /// normalization records as the input its value was derived from.
    #[must_use]
    pub fn native_score_sha256(&self) -> &str {
        self.native_score.native_score_sha256()
    }

    /// Returns the provider-supplied confidence, when present. Admission
    /// established that the number is finite and within `0.0..=1.0`.
    #[must_use]
    pub fn confidence(&self) -> Option<&Number> {
        self.confidence.as_ref()
    }

    /// Returns the verified content selection.
    #[must_use]
    pub fn content(&self) -> RecallCandidateContent<'_> {
        match (&self.candidate.content, &self.candidate.content_ref) {
            (Some(content), _) => RecallCandidateContent::Inline(content),
            (None, Some(reference)) => RecallCandidateContent::Reference(reference),
            // Unreachable after admission; admission denies every candidate
            // that carries neither field. Reporting an empty reference keeps
            // the accessor total without inventing content.
            (None, None) => RecallCandidateContent::Reference(&Value::Null),
        }
    }

    /// Consumes the admitted wrapper.
    #[must_use]
    pub fn into_candidate(self) -> RecallCandidateV1 {
        self.candidate
    }
}

/// Audit row for one denied candidate. Carries no content by construction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeniedRecallCandidate {
    /// Request-scoped candidate identity.
    pub candidate_id: String,
    /// Optional stable provider memory reference.
    pub stable_memory_ref: Option<String>,
    /// Typed denial reason.
    pub reason: RecallDenialReason,
    /// Scope binding the provider claimed.
    pub provider_claimed_scope_binding: ScopeBinding,
    /// Digest of the scope the provider claimed, when digestible.
    pub provider_claimed_scope_sha256: Option<String>,
    /// Temporal state the provider claimed.
    pub provider_claimed_temporal_state: String,
}

/// Serialisable admission report for explain traces and audit logs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecallAdmissionReport {
    /// Request identity the admission ran under.
    pub request_id: String,
    /// Provider identity and registration revision that produced this report,
    /// when the report came from an admitted provider call. Pure admission
    /// helpers that have no call envelope leave this absent; retained-state
    /// projections use a fixed opaque sentinel in that case.
    #[serde(default)]
    pub provider_id: Option<String>,
    /// Registration revision that produced this report, when known.
    #[serde(default)]
    pub registration_revision: Option<u64>,
    /// Digest of the admitted exact scope.
    pub exact_scope_sha256: String,
    /// Admitted temporal mode.
    pub temporal_mode: String,
    /// Admitted evaluation instant.
    pub evaluation_time: String,
    /// Admitted unknown-validity policy.
    pub unknown_validity_policy: UnknownValidityPolicy,
    /// Scope bindings the registry authorized the provider to attest.
    pub authorized_scope_bindings: RecallScopeBindingsV1,
    /// Candidates the provider returned.
    pub received_count: usize,
    /// Request-scoped identity of every candidate the provider returned, in
    /// the provider's own order.
    ///
    /// The denial ledger and the admitted slice are each in provider order,
    /// but neither alone recovers the interleaving of the two. This is the
    /// one place a later stage — an explain trace, an audit query — can learn
    /// the provider rank of *every* received candidate, so a per-candidate
    /// reconciliation can be a complete, ordered partition rather than a
    /// concatenation of per-stage groups. It carries identities only: the
    /// report stays content-free.
    pub received_candidate_ids: Vec<String>,
    /// Candidates admitted, in provider order.
    pub admitted_count: usize,
    /// Denied candidates, in provider order.
    pub denied: Vec<DeniedRecallCandidate>,
    /// Whether the lane is degraded because unknown-validity candidates were
    /// admitted under [`UnknownValidityPolicy::Degrade`].
    pub degraded: bool,
    /// Lane-level host warnings.
    pub warnings: Vec<String>,
}

impl RecallAdmissionReport {
    /// Counts denials per reason label in label order.
    #[must_use]
    pub fn denial_counts(&self) -> Vec<(&'static str, usize)> {
        let mut counts: Vec<(&'static str, usize)> = Vec::new();
        for denied in &self.denied {
            let label = denied.reason.label();
            match counts.iter_mut().find(|(existing, _)| *existing == label) {
                Some((_, count)) => *count += 1,
                None => counts.push((label, 1)),
            }
        }
        counts.sort_by(|left, right| left.0.cmp(right.0));
        counts
    }
}

/// Rank-final admission result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallAdmission {
    /// Admitted candidates in provider order.
    pub admitted: Vec<AdmittedRecallCandidate>,
    /// Audit report including every denial.
    pub report: RecallAdmissionReport,
}

/// Admits the candidates of one validated recall reply against the exact
/// scope and temporal query the host dispatched in `call`.
///
/// The reply must already have passed fabric validation. The outcome envelope
/// is bound to the call (provider, revision, receipt, request identity, and
/// scope); a mismatch is an error, not a denial, because the whole outcome is
/// then unattributable. `authorized` is the registry's record of the scope
/// bindings this provider may attest; it comes from registration, never from
/// the reply.
pub fn admit_recall_reply(
    call: &ProviderCall,
    temporal: &AdmittedTemporalQuery,
    maximum_candidates: usize,
    authorized: &RecallScopeBindingsV1,
    reply: &ProviderReply,
) -> Result<RecallAdmission, RecallAdmissionError> {
    admit_recall_reply_with_profile(call, temporal, maximum_candidates, authorized, reply, false)
}

/// The production port supplies this requirement from the exact registration
/// metadata it pinned, never from a provider or payload claim.
pub(crate) fn admit_recall_reply_with_profile(
    call: &ProviderCall,
    temporal: &AdmittedTemporalQuery,
    maximum_candidates: usize,
    authorized: &RecallScopeBindingsV1,
    reply: &ProviderReply,
    requires_common_profile: bool,
) -> Result<RecallAdmission, RecallAdmissionError> {
    let common_bindings;
    let authorized = if requires_common_profile {
        common_bindings = RecallScopeBindingsV1::new(authorized.iter().filter(|binding| {
            !matches!(
                binding,
                ScopeBinding::ProjectFacts | ScopeBinding::ProfileFacts
            )
        }));
        &common_bindings
    } else {
        authorized
    };
    let terminal_code = reply.terminal.terminal_code();
    if !matches!(
        terminal_code,
        TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
    ) {
        return Err(RecallAdmissionError::TerminalNotSuccessful { terminal_code });
    }
    let payload = reply
        .payload
        .as_ref()
        .ok_or(RecallAdmissionError::MissingPayload)?;
    let outcome = decode_recall_outcome(payload)?;
    bind_outcome_to_call(&outcome, call)?;
    if outcome.candidates.len() > maximum_candidates {
        return Err(RecallAdmissionError::CandidateBudgetExceeded {
            returned: outcome.candidates.len(),
            maximum: maximum_candidates,
        });
    }
    // Read the exclusions from the exact hashed request that was dispatched,
    // so a buggy provider cannot make a returned candidate eligible again.
    #[derive(Deserialize)]
    struct DispatchedRecallExclusions {
        exclusions: tracedecay_contracts::memory::CognitiveRecallExclusions,
        policy_revision: u64,
        history_grant: Option<Value>,
    }
    let context: DispatchedRecallExclusions =
        serde_json::from_slice(&call.payload.bytes).map_err(|error| {
            RecallAdmissionError::InvalidRequestExclusions {
                detail: bounded_detail(&error.to_string()),
            }
        })?;
    context.exclusions.validate().map_err(|error| {
        RecallAdmissionError::InvalidRequestExclusions {
            detail: bounded_detail(&error.to_string()),
        }
    })?;
    let common_profile = requires_common_profile
        .then(|| {
            CommonRecallProfileV1::from_dispatched_history(
                call,
                context.policy_revision,
                context.history_grant.as_ref(),
            )
        })
        .transpose()?;
    let mut admission = admit_recall_candidates_with_context(
        &call.exact_scope,
        &call.request_id,
        temporal,
        authorized,
        outcome.candidates,
        Some(&context.exclusions),
        common_profile.as_ref(),
    )?;
    // The pure admission helper intentionally has no provider-call envelope.
    // Attach the exact routed identity here, before observers persist the
    // report, so every retained projection can share one context-bound alias.
    admission.report.provider_id = Some(call.provider_id.as_str().to_owned());
    admission.report.registration_revision = Some(call.registration_revision);
    Ok(admission)
}

/// Decodes one canonical recall outcome payload without admitting anything.
pub fn decode_recall_outcome(
    payload: &CanonicalPayload,
) -> Result<RecallOutcomeV1, RecallAdmissionError> {
    if payload.contract_id.as_str() != RECALL_RESULT_CONTRACT_ID {
        return Err(RecallAdmissionError::PayloadContractMismatch {
            contract_id: payload.contract_id.as_str().to_owned(),
        });
    }
    payload.validate()?;
    serde_json::from_slice::<RecallOutcomeV1>(&payload.bytes).map_err(|error| {
        RecallAdmissionError::PayloadDecode {
            detail: bounded_detail(&error.to_string()),
        }
    })
}

fn bind_outcome_to_call(
    outcome: &RecallOutcomeV1,
    call: &ProviderCall,
) -> Result<(), RecallAdmissionError> {
    if outcome.provider_id != call.provider_id.as_str() {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "provider_id",
        });
    }
    if outcome.registration_revision != call.registration_revision {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "registration_revision",
        });
    }
    if outcome.ready_receipt_digest != call.ready_receipt_sha256 {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "ready_receipt_digest",
        });
    }
    if outcome.request_identity != call.request_id {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "request_identity",
        });
    }
    if outcome.provider_instance_id.trim().is_empty() {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "provider_instance_id",
        });
    }
    let claimed = outcome.exact_scope_identity.fields();
    let admitted = admitted_scope_fields(&call.exact_scope);
    if claimed
        .iter()
        .zip(admitted.iter())
        .any(|((_, left), (_, right))| left != right)
    {
        return Err(RecallAdmissionError::OutcomeBinding {
            field: "exact_scope_identity",
        });
    }
    Ok(())
}

/// Pure, clock-free, deterministic admission of already-decoded candidates.
///
/// Provider order is preserved in both the admitted list and the denial
/// ledger. The same inputs always yield the same output.
pub fn admit_recall_candidates(
    admitted_scope: &OwnedExactScope,
    request_id: &str,
    temporal: &AdmittedTemporalQuery,
    authorized: &RecallScopeBindingsV1,
    candidates: Vec<RecallCandidateV1>,
) -> Result<RecallAdmission, RecallAdmissionError> {
    admit_recall_candidates_with_context(
        admitted_scope,
        request_id,
        temporal,
        authorized,
        candidates,
        None,
        None,
    )
}

fn admit_recall_candidates_with_context(
    admitted_scope: &OwnedExactScope,
    request_id: &str,
    temporal: &AdmittedTemporalQuery,
    authorized: &RecallScopeBindingsV1,
    candidates: Vec<RecallCandidateV1>,
    exclusions: Option<&tracedecay_contracts::memory::CognitiveRecallExclusions>,
    common_profile: Option<&CommonRecallProfileV1>,
) -> Result<RecallAdmission, RecallAdmissionError> {
    admitted_scope.validate()?;
    let mut seen = BTreeSet::new();
    for candidate in &candidates {
        if !seen.insert(candidate.candidate_id.as_str()) {
            return Err(RecallAdmissionError::DuplicateCandidateId(
                candidate.candidate_id.clone(),
            ));
        }
    }
    let received_count = candidates.len();
    let received_candidate_ids: Vec<String> = candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect();
    let mut admitted = Vec::new();
    let mut denied = Vec::new();
    let mut degraded = false;
    for candidate in candidates {
        match admit_one(
            admitted_scope,
            temporal,
            authorized,
            &candidate,
            exclusions,
            common_profile,
        ) {
            Ok(parts) => {
                degraded |= parts.decision.degrades_lane;
                admitted.push(AdmittedRecallCandidate {
                    host_temporal_state: parts.decision.host_temporal_state,
                    warnings: parts.decision.warnings,
                    native_score: parts.native_score,
                    confidence: parts.confidence,
                    original_sources: parts.original_sources,
                    candidate,
                });
            }
            Err(reason) => denied.push(DeniedRecallCandidate {
                provider_claimed_scope_binding: candidate.exact_scope_identity.scope_binding,
                provider_claimed_scope_sha256: candidate
                    .exact_scope_identity
                    .claimed_scope_sha256(),
                provider_claimed_temporal_state: candidate.validity.temporal_state.clone(),
                candidate_id: candidate.candidate_id,
                stable_memory_ref: candidate.stable_memory_ref,
                reason,
            }),
        }
    }
    let mut warnings = Vec::new();
    if degraded {
        warnings
            .push("incomplete source revision or validity coverage; lane is degraded".to_owned());
    }
    Ok(RecallAdmission {
        report: RecallAdmissionReport {
            request_id: request_id.to_owned(),
            provider_id: None,
            registration_revision: None,
            exact_scope_sha256: admitted_scope.exact_scope_sha256(),
            temporal_mode: temporal.mode.as_wire().to_owned(),
            evaluation_time: temporal.evaluation_time.clone(),
            unknown_validity_policy: temporal.unknown_validity_policy,
            authorized_scope_bindings: authorized.clone(),
            received_count,
            received_candidate_ids,
            admitted_count: admitted.len(),
            denied,
            degraded,
            warnings,
        },
        admitted,
    })
}

struct AdmitDecision {
    host_temporal_state: TemporalState,
    warnings: Vec<String>,
    degrades_lane: bool,
}

/// Historical sources the host selected and freshly revalidated before dispatch.
/// Current-session locators carry no original-source authority; the root must
/// confirm their canonical record and hydrate through its owning message store.
struct CommonRecallProfileV1 {
    granted_sources: Vec<tracedecay_memory_provider_api::SourceAttribution>,
}

impl CommonRecallProfileV1 {
    fn from_dispatched_history(
        call: &ProviderCall,
        policy_revision: u64,
        grant: Option<&Value>,
    ) -> Result<Self, RecallAdmissionError> {
        let invalid = || RecallAdmissionError::InvalidTemporalQuery {
            field: "history_grant",
            detail: "common recall history must bind the dispatched scope and original sources",
        };
        let Some(grant) = grant else {
            // Without history, original-source claims remain outside the
            // allowlist. Current record locators still require host hydration.
            return Ok(Self {
                granted_sources: Vec::new(),
            });
        };
        if grant.get("destination_scope") != Some(&scope_wire_value(&call.exact_scope))
            || grant.get("policy_revision").and_then(Value::as_u64) != Some(policy_revision)
        {
            return Err(invalid());
        }
        let sources = grant
            .get("sources")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        if sources.is_empty()
            || sources.len() > tracedecay_memory_provider_api::MAX_ADVISORY_ADMISSION_SOURCES
        {
            return Err(invalid());
        }
        let granted_sources = sources
            .iter()
            .map(|source| {
                let attribution: RecallSourceAttributionV1 =
                    serde_json::from_value(source.get("attribution").ok_or_else(invalid)?.clone())
                        .map_err(|_| invalid())?;
                attribution.to_owned_attribution().map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { granted_sources })
    }

    fn check_candidate(
        &self,
        candidate: &RecallCandidateV1,
        sources: &[RecallSourceAttributionV1],
    ) -> Result<(), RecallDenialReason> {
        let invalid = |detail: &str| RecallDenialReason::InvalidSourceAttribution {
            detail: detail.to_owned(),
        };
        if candidate.memory_class.as_str() != Some(SESSION_OBSERVATION_MEMORY_CLASS) {
            return Err(invalid(
                "common advisory recall requires a session observation",
            ));
        }
        if sources.is_empty() {
            return Self::check_current_record_locator(candidate);
        }
        if candidate.exact_scope_identity.scope_binding != ScopeBinding::ExactCodingScope {
            return Err(invalid("original observation requires exact coding scope"));
        }
        for source in sources {
            let attribution = source.to_owned_attribution()?;
            if !self.granted_sources.contains(&attribution) {
                return Err(invalid(
                    "original observation is outside dispatched canonical history",
                ));
            }
        }
        Ok(())
    }

    fn check_current_record_locator(
        candidate: &RecallCandidateV1,
    ) -> Result<(), RecallDenialReason> {
        let invalid = || RecallDenialReason::InvalidSourceAttribution {
            detail: "current observation requires one canonical record claim".to_owned(),
        };
        if !matches!(
            candidate.exact_scope_identity.scope_binding,
            ScopeBinding::ExactCodingScope | ScopeBinding::CheckoutObservations
        ) || candidate.provenance.get("state").and_then(Value::as_str) != Some("available")
            || candidate.provenance.get("original_sources") != Some(&serde_json::json!([]))
        {
            return Err(invalid());
        }
        let observations = candidate
            .provenance
            .get("observation_refs")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let [observation] = observations.as_slice() else {
            return Err(invalid());
        };
        let observation_id =
            CanonicalObservationIdV1::new(observation.as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        let source = HostEvidenceRefV1::CanonicalRecord {
            record_id: observation_id.as_str().to_owned(),
        }
        .label();
        let expected_refs = serde_json::json!([source]);
        if candidate.provenance.get("origin_refs") != Some(&expected_refs)
            || candidate.provenance.get("source_refs") != Some(&expected_refs)
            || candidate.source_refs.as_slice() != [source]
        {
            return Err(invalid());
        }
        // A current locator proves neither an occurrence time nor an original
        // source revision. Known lifecycle bounds remain subject to validity
        // admission; unknown validity never bypasses the dispatched policy.
        if candidate.validity.observed_at.is_some()
            || candidate.validity.valid_from.is_some()
            || candidate.validity.source_revision.is_some()
            || candidate.validity.temporal_state != TemporalState::Unknown.as_wire()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

struct AdmittedCandidateParts {
    decision: AdmitDecision,
    native_score: ValidatedNativeScoreV1,
    confidence: Option<Number>,
    original_sources: Vec<RecallSourceAttributionV1>,
}

fn validate_recall_confidence(
    value: Option<&RecallConfidenceWire>,
) -> Result<Option<Number>, RecallConfidenceDefect> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = value.0.get();
    if !matches!(raw.as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
        return Err(RecallConfidenceDefect::NotNumber);
    }
    let number =
        serde_json::from_str::<Number>(raw).map_err(|_| RecallConfidenceDefect::NotFinite)?;
    let parsed = number.as_f64().ok_or(RecallConfidenceDefect::NotFinite)?;
    if !parsed.is_finite() {
        return Err(RecallConfidenceDefect::NotFinite);
    }
    if !(0.0..=1.0).contains(&parsed) {
        return Err(RecallConfidenceDefect::OutOfRange);
    }
    Ok(Some(number))
}

fn admit_one(
    admitted_scope: &OwnedExactScope,
    temporal: &AdmittedTemporalQuery,
    authorized: &RecallScopeBindingsV1,
    candidate: &RecallCandidateV1,
    exclusions: Option<&tracedecay_contracts::memory::CognitiveRecallExclusions>,
    common_profile: Option<&CommonRecallProfileV1>,
) -> Result<AdmittedCandidateParts, RecallDenialReason> {
    check_class_binding(
        &candidate.memory_class,
        candidate.exact_scope_identity.scope_binding,
    )?;
    check_scope(admitted_scope, authorized, &candidate.exact_scope_identity)?;
    check_content(candidate)?;
    let original_sources = original_sources_from_provenance(&candidate.provenance)?;
    check_recall_exclusions(candidate, &original_sources, exclusions)?;
    check_original_source_claims(candidate, &original_sources)?;
    if let Some(common_profile) = common_profile {
        common_profile.check_candidate(candidate, &original_sources)?;
    }
    let decision = check_validity(temporal, &candidate.validity)?;
    // Relevance inputs are admitted, never repaired: a score the host cannot
    // project honestly denies the candidate here rather than reaching
    // normalization as a neutral value.
    let native_score = validate_native_score(&candidate.native_score)
        .map_err(|defect| RecallDenialReason::NativeScoreMalformed { defect })?;
    let confidence = validate_recall_confidence(candidate.confidence.as_ref())
        .map_err(|defect| RecallDenialReason::ConfidenceMalformed { defect })?;
    Ok(AdmittedCandidateParts {
        decision,
        native_score,
        confidence,
        original_sources,
    })
}

fn provenance_refs<'a>(
    candidate: &'a RecallCandidateV1,
    field: &str,
) -> impl Iterator<Item = &'a str> {
    candidate
        .provenance
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn observation_history_claim(
    candidate: &RecallCandidateV1,
    sources: &[RecallSourceAttributionV1],
) -> bool {
    !sources.is_empty()
        && candidate.memory_class.as_str() == Some(SESSION_OBSERVATION_MEMORY_CLASS)
        && candidate.provenance.get("state").and_then(Value::as_str) == Some("available")
}

fn original_record_ref(source: &RecallSourceAttributionV1) -> String {
    format!(
        "record:{}",
        source
            .source
            .stable_record_id
            .as_deref()
            .unwrap_or(&source.source.observation_id)
    )
}

/// Typed attribution cannot replace a contradictory declared claim.
/// Observation-sourced candidates name source keys or canonical records;
/// facts retain their separate host record authority.
fn check_original_source_claims(
    candidate: &RecallCandidateV1,
    sources: &[RecallSourceAttributionV1],
) -> Result<(), RecallDenialReason> {
    if !observation_history_claim(candidate, sources) {
        return Ok(());
    }
    let invalid = |detail: &str| RecallDenialReason::InvalidSourceAttribution {
        detail: detail.to_owned(),
    };
    let declared = candidate
        .provenance
        .get("observation_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("observation_refs must cover original source identities"))?;
    if declared.iter().any(|value| value.as_str().is_none()) {
        return Err(invalid("observation_refs contains a non-reference"));
    }
    let declared: BTreeSet<_> = declared.iter().filter_map(Value::as_str).collect();
    let original: BTreeSet<_> = sources
        .iter()
        .map(|source| source.source.observation_id.as_str())
        .collect();
    if declared != original {
        return Err(invalid(
            "observation_refs contradict original source identities",
        ));
    }
    let record_refs: BTreeSet<_> = sources.iter().map(original_record_ref).collect();
    let source_keys: BTreeSet<_> = sources
        .iter()
        .map(|source| source.source.source_key.as_str())
        .collect();
    for field in ["source_refs", "origin_refs"] {
        let Some(values) = candidate.provenance.get(field).and_then(Value::as_array) else {
            return Err(invalid("source provenance references must be arrays"));
        };
        if values.iter().any(|value| value.as_str().is_none()) {
            return Err(invalid("source provenance contains a non-reference"));
        }
    }
    for reference in provenance_refs(candidate, "source_refs")
        .chain(candidate.source_refs.iter().map(String::as_str))
    {
        if !source_keys.contains(reference) && !record_refs.contains(reference) {
            return Err(invalid("source_refs contradict original source identities"));
        }
    }
    for reference in provenance_refs(candidate, "origin_refs") {
        if reference.starts_with("record:") && !record_refs.contains(reference)
            || (reference.starts_with("source:") || reference.starts_with("session:"))
                && !source_keys.contains(reference)
        {
            return Err(invalid("origin_refs contradict original source identities"));
        }
    }
    Ok(())
}

/// Exclusions run over the complete admitted content and reference sets,
/// before normalization, deduplication, or host output truncation.
fn check_recall_exclusions(
    candidate: &RecallCandidateV1,
    sources: &[RecallSourceAttributionV1],
    exclusions: Option<&tracedecay_contracts::memory::CognitiveRecallExclusions>,
) -> Result<(), RecallDenialReason> {
    let Some(exclusions) = exclusions else {
        return Ok(());
    };
    let contains =
        |values: &[String], reference: &str| values.iter().any(|value| value == reference);
    let field = if candidate
        .stable_memory_ref
        .as_deref()
        .is_some_and(|reference| contains(&exclusions.stable_memory_refs, reference))
    {
        Some("stable_memory_refs")
    } else if contains(&exclusions.candidate_ids, &candidate.candidate_id) {
        Some("candidate_ids")
    } else if candidate
        .source_refs
        .iter()
        .map(String::as_str)
        .chain(provenance_refs(candidate, "source_refs"))
        .chain(provenance_refs(candidate, "origin_refs"))
        .any(|reference| contains(&exclusions.source_refs, reference))
        || sources.iter().any(|source| {
            contains(&exclusions.source_refs, &source.source.source_key)
                || contains(&exclusions.source_refs, &original_record_ref(source))
        })
    {
        Some("source_refs")
    } else if candidate
        .trace_refs
        .iter()
        .map(String::as_str)
        .chain(provenance_refs(candidate, "provider_trace_refs"))
        .chain(
            candidate
                .explanation
                .get("activation_trace_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        )
        .any(|reference| contains(&exclusions.trace_refs, reference))
    {
        Some("trace_refs")
    } else if provenance_refs(candidate, "observation_refs")
        .any(|reference| contains(&exclusions.observation_ids, reference))
        || sources
            .iter()
            .any(|source| contains(&exclusions.observation_ids, &source.source.observation_id))
    {
        Some("observation_ids")
    } else if contains(&exclusions.content_sha256, &candidate.content_sha256)
        || sources
            .iter()
            .any(|source| contains(&exclusions.content_sha256, &source.source.content_sha256))
    {
        Some("content_sha256")
    } else {
        None
    };
    match field {
        Some(field) => Err(RecallDenialReason::RequestExcluded {
            field: field.to_owned(),
        }),
        None => Ok(()),
    }
}

/// Memory class of one provider-local staged session observation.
///
/// The host owns this token, not the provider: it is compared against the
/// class the candidate declared, and it is what the denial reason records, so
/// no provider byte reaches the ledger through this path.
const SESSION_OBSERVATION_MEMORY_CLASS: &str = "session_observation";

/// Host-owned policy relating a candidate's declared memory class to the
/// scope binding it may be admitted under.
///
/// Provider authorization is provider-wide, while session observations must
/// retain all five checkout identities. They may use the fully exact binding
/// or the checkout binding; project/profile fact bindings
/// would make checkout fields optional or forbidden and are never admissible
/// for this class. Session and resolved-scope identity remain origin metadata
/// when the candidate uses the checkout binding.
///
/// This rule constrains session observations without changing canonical facts'
/// existing owner-bound admission.
fn check_class_binding(
    memory_class: &Value,
    binding: ScopeBinding,
) -> Result<(), RecallDenialReason> {
    if memory_class.as_str() == Some(SESSION_OBSERVATION_MEMORY_CLASS)
        && !matches!(
            binding,
            ScopeBinding::ExactCodingScope | ScopeBinding::CheckoutObservations
        )
    {
        return Err(RecallDenialReason::MemoryClassBindingUnauthorized {
            memory_class: SESSION_OBSERVATION_MEMORY_CLASS.to_owned(),
            binding,
        });
    }
    Ok(())
}

/// Applies the claimed scope binding's field rules byte-for-byte in contract
/// order.
///
/// The binding must first be one the registry authorized for the provider.
/// Then, for every field: a malformed value (surrounding whitespace or control
/// characters) is an identity the host cannot resolve; a required field that
/// is empty is likewise unknown; a required or optional field that differs
/// from the admitted scope is a scope mismatch, except a differing
/// `resolved_scope_digest` under `exact_coding_scope`, which is a stale
/// resolution of this checkout; and a non-empty forbidden field is an
/// identity the binding does not allow the provider to claim.
fn check_scope(
    admitted_scope: &OwnedExactScope,
    authorized: &RecallScopeBindingsV1,
    claimed: &RecallScopeIdentityV1,
) -> Result<(), RecallDenialReason> {
    let binding = claimed.scope_binding;
    if !authorized.authorizes(binding) {
        return Err(RecallDenialReason::ScopeBindingUnauthorized { binding });
    }
    let claimed_fields = claimed.fields();
    for (field, value) in &claimed_fields {
        let malformed = value.trim() != *value || value.chars().any(char::is_control);
        let missing_required =
            value.is_empty() && binding.field_rule(*field) == ScopeFieldRule::RequiredEqual;
        if malformed || missing_required {
            return Err(RecallDenialReason::UnknownIdentity { field: *field });
        }
    }
    let admitted_fields = admitted_scope_fields(admitted_scope);
    for ((field, claimed_value), (_, admitted_value)) in
        claimed_fields.iter().zip(admitted_fields.iter())
    {
        match binding.field_rule(*field) {
            ScopeFieldRule::RequiredEqual => {
                if claimed_value == admitted_value {
                    continue;
                }
                return Err(match field {
                    ScopeField::ResolvedScopeDigest => RecallDenialReason::StaleIdentity,
                    other => RecallDenialReason::ScopeMismatch { field: *other },
                });
            }
            ScopeFieldRule::OptionalEmptyOrEqual => {
                if claimed_value.is_empty() || claimed_value == admitted_value {
                    continue;
                }
                return Err(RecallDenialReason::ScopeMismatch { field: *field });
            }
            ScopeFieldRule::Forbidden => {
                if !claimed_value.is_empty() {
                    return Err(RecallDenialReason::ForbiddenIdentity { field: *field });
                }
            }
        }
    }
    Ok(())
}

fn check_content(candidate: &RecallCandidateV1) -> Result<(), RecallDenialReason> {
    match (&candidate.content, &candidate.content_ref) {
        (Some(content), None) => {
            let actual = hex::encode(Sha256::digest(content.as_bytes()));
            if actual != candidate.content_sha256 {
                return Err(RecallDenialReason::ContentDigestMismatch);
            }
            Ok(())
        }
        (None, Some(reference)) if !reference.is_null() => Ok(()),
        _ => Err(RecallDenialReason::ContentSelectionInvalid),
    }
}

fn invalid(detail: &'static str) -> RecallDenialReason {
    RecallDenialReason::InvalidValidityRecord {
        detail: detail.to_owned(),
    }
}

fn parse_optional_instant(
    value: Option<&String>,
    field: &'static str,
) -> Result<Option<i64>, RecallDenialReason> {
    match value {
        None => Ok(None),
        Some(text) => parse_rfc3339_nanos(text).map(Some).ok_or_else(|| {
            RecallDenialReason::InvalidValidityRecord {
                detail: format!("{field} is not a utc_rfc3339_nanos timestamp"),
            }
        }),
    }
}

/// Computes the host's own temporal state, compares it with the provider's
/// claim, and applies the admitted temporal query.
fn check_validity(
    temporal: &AdmittedTemporalQuery,
    validity: &RecallValidityV1,
) -> Result<AdmitDecision, RecallDenialReason> {
    let claimed_state = TemporalState::from_wire(&validity.temporal_state)
        .ok_or_else(|| invalid("temporal_state is not a contract value"))?;
    if let Some(revision) = validity.source_revision.as_deref()
        && (revision.is_empty()
            || revision.trim() != revision
            || revision.len() > 1024
            || revision.chars().any(char::is_control))
    {
        return Err(invalid(
            "source_revision must be a nonempty opaque revision token",
        ));
    }
    let revision_unknown = validity.source_revision.is_none();
    parse_optional_instant(validity.observed_at.as_ref(), "observed_at")?;
    let valid_from = parse_optional_instant(validity.valid_from.as_ref(), "valid_from")?;
    let valid_until = parse_optional_instant(validity.valid_until.as_ref(), "valid_until")?;
    let superseded_at = parse_optional_instant(validity.superseded_at.as_ref(), "superseded_at")?;
    let revoked_at = parse_optional_instant(validity.revoked_at.as_ref(), "revoked_at")?;
    if let (Some(from), Some(until)) = (valid_from, valid_until)
        && from >= until
    {
        return Err(invalid("valid_from must lie before valid_until"));
    }
    if validity.superseded_by.is_some() != superseded_at.is_some() {
        return Err(invalid(
            "superseded_by and superseded_at must be retained together",
        ));
    }
    if let Some(replacement) = validity.superseded_by.as_deref()
        && (replacement.is_empty()
            || replacement.trim() != replacement
            || replacement.len() > 1024
            || replacement.chars().any(char::is_control))
    {
        return Err(invalid("superseded_by must be a bounded stable reference"));
    }
    for event in [superseded_at, revoked_at].into_iter().flatten() {
        if valid_from.is_some_and(|from| event < from) {
            return Err(invalid("lifecycle event precedes valid_from"));
        }
    }

    let mut effective_until = valid_until;
    for boundary in [
        superseded_at.filter(|_| !temporal.include_superseded),
        revoked_at.filter(|_| !temporal.include_revoked),
    ]
    .into_iter()
    .flatten()
    {
        effective_until = Some(effective_until.map_or(boundary, |end| end.min(boundary)));
    }
    let cutoff_reason = |at| {
        if !temporal.include_revoked && revoked_at.is_some_and(|event| event <= at) {
            RecallDenialReason::Revoked
        } else if !temporal.include_superseded && superseded_at.is_some_and(|event| event <= at) {
            RecallDenialReason::Superseded
        } else {
            RecallDenialReason::Expired
        }
    };
    let revision_warnings = || {
        if revision_unknown {
            vec!["source revision unknown; retained validity evaluated independently".to_owned()]
        } else {
            Vec::new()
        }
    };

    if claimed_state == TemporalState::Unknown {
        // A provider may disclaim the start while retaining an end or event.
        // Those known upper bounds still exclude later requests; no admission
        // clock or occurrence timestamp is substituted for the unknown start.
        let earliest_requested = temporal
            .point_instant()
            .or_else(|| temporal.interval.as_ref().map(|((_, start), _)| *start))
            .unwrap_or(temporal.evaluation_nanos);
        if effective_until.is_some_and(|end| end <= earliest_requested) {
            return Err(cutoff_reason(earliest_requested));
        }
        return match temporal.unknown_validity_policy {
            UnknownValidityPolicy::Exclude => Err(RecallDenialReason::UnknownValidity),
            UnknownValidityPolicy::Degrade | UnknownValidityPolicy::AllowWithWarning => {
                let mut warnings = revision_warnings();
                warnings.push(format!(
                    "validity unknown; admitted under {} policy",
                    temporal.unknown_validity_policy.as_wire()
                ));
                Ok(AdmitDecision {
                    host_temporal_state: TemporalState::Unknown,
                    warnings,
                    degrades_lane: true,
                })
            }
        };
    }

    let Some(from) = valid_from else {
        return Err(invalid("valid_from is required for a known temporal_state"));
    };
    // Point claims describe the requested instant, not the present disposition.
    // Comparing nanoseconds directly preserves the wire parser's precision.
    let state_at = |instant| {
        if from > instant {
            TemporalState::Future
        } else if revoked_at.is_some_and(|at| at <= instant) {
            TemporalState::Revoked
        } else if superseded_at.is_some_and(|at| at <= instant) {
            TemporalState::Superseded
        } else {
            window_state(from, valid_until, instant)
        }
    };
    let host_state = match temporal.point_instant() {
        Some(instant) => state_at(instant),
        None => match temporal.interval.as_ref() {
            Some(((_, start), (_, end))) => {
                if from >= *end {
                    TemporalState::Future
                } else if effective_until.is_some_and(|until| until <= *start || until <= from) {
                    state_at(*start)
                } else {
                    TemporalState::Current
                }
            }
            None => state_at(temporal.evaluation_nanos),
        },
    };
    // Interval claims may describe their eligible portion or the evaluation
    // instant. Current/as-of/history have one unambiguous comparison instant.
    let claim_consistent = claimed_state == host_state
        || (temporal.mode == TemporalMode::Interval
            && claimed_state == state_at(temporal.evaluation_nanos));
    if !claim_consistent {
        return Err(invalid(
            "provider temporal_state contradicts validity timestamps",
        ));
    }

    match temporal.mode {
        TemporalMode::Current | TemporalMode::AsOf => {
            let Some(instant) = temporal.point_instant() else {
                return Err(invalid("point temporal mode has no admitted instant"));
            };
            if from > instant {
                return Err(RecallDenialReason::NotYetValid);
            }
            if effective_until.is_some_and(|until| until <= instant) {
                return Err(cutoff_reason(instant));
            }
        }
        TemporalMode::Interval => {
            let Some(((_, start), (_, end))) = temporal.interval.as_ref() else {
                return Err(invalid("interval mode has no admitted bounds"));
            };
            if from >= *end {
                return Err(RecallDenialReason::NotYetValid);
            }
            if effective_until.is_some_and(|until| until <= *start || until <= from) {
                return Err(cutoff_reason((*start).max(from)));
            }
        }
        TemporalMode::History => {
            if from > temporal.evaluation_nanos {
                return Err(RecallDenialReason::NotYetValid);
            }
            if !temporal.include_revoked
                && revoked_at.is_some_and(|at| at <= temporal.evaluation_nanos)
            {
                return Err(RecallDenialReason::Revoked);
            }
            if !temporal.include_superseded
                && superseded_at.is_some_and(|at| at <= temporal.evaluation_nanos)
            {
                return Err(RecallDenialReason::Superseded);
            }
        }
    }
    Ok(AdmitDecision {
        host_temporal_state: host_state,
        warnings: revision_warnings(),
        degrades_lane: revision_unknown,
    })
}

fn window_state(from: i64, until: Option<i64>, instant: i64) -> TemporalState {
    if from > instant {
        TemporalState::Future
    } else if until.is_some_and(|until| until <= instant) {
        TemporalState::Expired
    } else {
        TemporalState::Current
    }
}

fn bounded_detail(detail: &str) -> String {
    let mut end = detail.len().min(MAX_DECODE_DETAIL_BYTES);
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_owned()
}

impl<'de> Deserialize<'de> for AdmittedTemporalQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            mode: String,
            evaluation_time: String,
            #[serde(deserialize_with = "required_nullable")]
            as_of: Option<String>,
            #[serde(deserialize_with = "required_nullable")]
            interval_start: Option<String>,
            #[serde(deserialize_with = "required_nullable")]
            interval_end: Option<String>,
            include_superseded: bool,
            include_revoked: bool,
            unknown_validity_policy: UnknownValidityPolicy,
        }
        let wire = Wire::deserialize(deserializer)?;
        let mode = TemporalMode::from_wire(&wire.mode)
            .ok_or_else(|| D::Error::custom("temporal mode is not a contract value"))?;
        let query = match (mode, wire.as_of, wire.interval_start, wire.interval_end) {
            (TemporalMode::Current, None, None, None) => Self::current(&wire.evaluation_time),
            (TemporalMode::AsOf, Some(as_of), None, None) => {
                Self::as_of(&wire.evaluation_time, &as_of)
            }
            (TemporalMode::Interval, None, Some(start), Some(end)) => {
                Self::interval(&wire.evaluation_time, &start, &end)
            }
            (TemporalMode::History, None, None, None) => Self::history(&wire.evaluation_time),
            _ => Err(RecallAdmissionError::InvalidTemporalQuery {
                field: "mode",
                detail: "temporal bounds do not match the mode",
            }),
        }
        .map_err(D::Error::custom)?;
        Ok(query
            .with_include_superseded(wire.include_superseded)
            .with_include_revoked(wire.include_revoked)
            .with_unknown_validity_policy(wire.unknown_validity_policy))
    }
}

impl Serialize for AdmittedTemporalQuery {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_wire_value().serialize(serializer)
    }
}

#[cfg(test)]
mod request_context_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use tracedecay_contracts::memory::CognitiveRecallExclusions;
    use tracedecay_memory_provider_api::{
        CancellationToken, CommittedEffectEvidence, FallbackDirective, OperationControl,
        ProviderCallParts, ProviderOperation, TerminalRecord,
    };

    fn parts() -> RecallRequestParts {
        RecallRequestParts {
            provider_id: OwnedProviderId::new("provider.context").unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "1".repeat(64),
            exact_scope: OwnedExactScope::new(
                "profile",
                "project",
                "repository",
                "worktree",
                "refs/heads/main",
                "session",
                format!("sha256:{}", "2".repeat(64)),
            )
            .unwrap(),
            request_id: "request.context".to_owned(),
            objective: "search".to_owned(),
            query: "query".to_owned(),
            temporal: AdmittedTemporalQuery::current("2025-01-01T00:00:00.000000Z").unwrap(),
            budgets: RecallBudgetsV1 {
                maximum_candidates: 8,
                maximum_candidate_content_bytes: 4096,
                maximum_total_content_bytes: 8192,
                maximum_source_refs_per_candidate: 8,
                maximum_trace_refs_per_candidate: 8,
                maximum_warnings: 8,
                maximum_extensions_per_candidate: 8,
            },
            policy_revision: 3,
            deadline_utc_micros: 42,
            remaining_millis: 7,
        }
    }

    fn current_candidate() -> RecallCandidateV1 {
        let observation_id = format!("sha256:{}", "a".repeat(64));
        let source = HostEvidenceRefV1::CanonicalRecord {
            record_id: observation_id.clone(),
        }
        .label();
        let content = "provider text still requiring owning-store hydration";
        let mut scope = scope_wire_value(&parts().exact_scope);
        scope["scope_binding"] = serde_json::json!("exact_coding_scope");
        serde_json::from_value(serde_json::json!({
            "candidate_id": "current-observation",
            "stable_memory_ref": "ncm-memory:current",
            "content": content,
            "content_ref": null,
            "content_sha256": hex::encode(Sha256::digest(content.as_bytes())),
            "native_score": {
                "score_domain_id": "test.score", "score_domain_version": 1,
                "raw_value": "0.5", "direction": "higher_is_better",
                "declared_minimum": "0", "declared_maximum": "1",
                "calibration_state": "uncalibrated", "semantics": "similarity",
                "components": {}
            },
            "confidence": null,
            "exact_scope_identity": scope,
            "validity": {
                "observed_at": null, "valid_from": null, "valid_until": null,
                "superseded_at": null, "superseded_by": null, "revoked_at": null,
                "source_revision": null, "temporal_state": "unknown"
            },
            "provenance": {
                "state": "available", "origin_refs": [source],
                "observation_refs": [observation_id], "source_refs": [source],
                "original_sources": [], "transform_chain": [],
                "provider_trace_refs": [], "redaction_reason": null
            },
            "explanation": {}, "source_refs": [source], "trace_refs": [],
            "sensitivity": "unknown", "memory_class": SESSION_OBSERVATION_MEMORY_CLASS,
            "warnings": [], "extensions": []
        }))
        .unwrap()
    }

    fn common_admission(
        candidate: RecallCandidateV1,
        policy: UnknownValidityPolicy,
        exclusions: Option<&CognitiveRecallExclusions>,
    ) -> RecallAdmission {
        let mut parts = parts();
        parts.temporal = parts.temporal.with_unknown_validity_policy(policy);
        let required_capabilities = vec![
            OwnedVersionedId::new(RECALL_QUERY_CAPABILITY_ID).unwrap(),
            OwnedVersionedId::new(crate::COMMON_ADVISORY_PROFILE_ID).unwrap(),
        ];
        let payload = build_recall_request_payload_with_capabilities(
            &parts,
            exclusions,
            None,
            &required_capabilities,
        )
        .unwrap();
        let call = ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Recall,
            provider_id: parts.provider_id.clone(),
            registration_revision: parts.registration_revision,
            ready_receipt_sha256: parts.ready_receipt_sha256.clone(),
            exact_scope: parts.exact_scope.clone(),
            request_id: parts.request_id.clone(),
            operation_id: "operation.current".to_owned(),
            expected_state_generation: 0,
            idempotency_key: None,
            control: OperationControl::new(42, 7, CancellationToken::new()),
            payload,
            required_capabilities,
            extensions: Vec::new(),
        })
        .unwrap();
        let outcome = serde_json::json!({
            "provider_id": call.provider_id.as_str(),
            "provider_instance_id": "provider.instance",
            "registration_revision": call.registration_revision,
            "ready_receipt_digest": call.ready_receipt_sha256,
            "request_identity": call.request_id,
            "exact_scope_identity": scope_wire_value(&call.exact_scope),
            "provider_state_generation": 0, "candidates": [candidate],
            "coverage": {}, "ordering": {}, "terminal": {}, "warnings": []
        });
        let bytes = serde_json::to_vec(&outcome).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        let reply = ProviderReply {
            terminal: TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                TerminalCode::Partial,
                CommittedEffectEvidence::none(Some(0)),
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                None,
            )
            .unwrap(),
            payload: Some(
                CanonicalPayload::new(
                    OwnedVersionedId::new(RECALL_RESULT_CONTRACT_ID).unwrap(),
                    bytes,
                    digest,
                )
                .unwrap(),
            ),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: 0,
        };
        admit_recall_reply_with_profile(
            &call,
            &parts.temporal,
            usize::try_from(parts.budgets.maximum_candidates).unwrap(),
            &RecallScopeBindingsV1::new([
                ScopeBinding::ExactCodingScope,
                ScopeBinding::CheckoutObservations,
            ]),
            &reply,
            true,
        )
        .unwrap()
    }

    #[test]
    fn common_profile_admits_current_record_only_as_a_claim_requiring_hydration() {
        let admission = common_admission(current_candidate(), UnknownValidityPolicy::Degrade, None);
        assert_eq!(admission.admitted.len(), 1);
        assert!(admission.report.denied.is_empty());
        assert!(admission.report.degraded);
        let admitted = &admission.admitted[0];
        assert_eq!(admitted.host_temporal_state(), TemporalState::Unknown);
        assert!(admitted.original_sources().is_empty());
        assert!(admitted.observation_history_sources().is_none());
        let candidate = admitted.candidate();
        assert_eq!(candidate.provenance["state"], "available");
        let reference = candidate.provenance["origin_refs"][0].as_str().unwrap();
        assert_eq!(
            HostEvidenceRefV1::parse(reference).unwrap(),
            HostEvidenceRefV1::CanonicalRecord {
                record_id: format!("sha256:{}", "a".repeat(64))
            }
        );
        assert_eq!(candidate.source_refs, vec![reference]);
        assert_eq!(
            candidate.provenance["source_refs"],
            candidate.provenance["origin_refs"]
        );
        assert!(
            !crate::recall_context_pack::ProviderItemProvenanceV1::from_candidate(candidate)
                .is_hydrated()
        );
    }

    #[test]
    fn common_profile_checkout_locator_requires_five_identities_and_no_session_claim() {
        let mut candidate = current_candidate();
        candidate.exact_scope_identity.scope_binding = ScopeBinding::CheckoutObservations;
        candidate.exact_scope_identity.agent_session_id.clear();
        candidate.exact_scope_identity.resolved_scope_digest.clear();
        let admitted = common_admission(candidate.clone(), UnknownValidityPolicy::Degrade, None);
        assert_eq!(admitted.admitted.len(), 1);
        assert!(admitted.admitted[0].original_sources().is_empty());
        for (field, expected) in [
            ("worktree", ScopeField::WorktreeIdentity),
            ("branch", ScopeField::BranchIdentity),
        ] {
            let mut foreign = candidate.clone();
            match field {
                "worktree" => foreign.exact_scope_identity.worktree_identity = "foreign".to_owned(),
                _ => foreign.exact_scope_identity.branch_identity = "foreign".to_owned(),
            }
            let denied = common_admission(foreign, UnknownValidityPolicy::Degrade, None);
            assert!(denied.admitted.is_empty());
            assert_eq!(
                denied.report.denied[0].reason,
                RecallDenialReason::ScopeMismatch { field: expected }
            );
        }
        for field in [ScopeField::AgentSessionId, ScopeField::ResolvedScopeDigest] {
            let mut malformed = candidate.clone();
            match field {
                ScopeField::AgentSessionId => {
                    malformed.exact_scope_identity.agent_session_id = "claimed-session".to_owned()
                }
                _ => {
                    malformed.exact_scope_identity.resolved_scope_digest =
                        "claimed-digest".to_owned()
                }
            }
            let denied = common_admission(malformed, UnknownValidityPolicy::Degrade, None);
            assert!(denied.admitted.is_empty());
            assert_eq!(
                denied.report.denied[0].reason,
                RecallDenialReason::ForbiddenIdentity { field }
            );
        }
    }

    #[test]
    fn common_profile_denies_alternate_fabricated_and_ungranted_history_claims() {
        let valid = current_candidate();
        let mut alternate = valid.clone();
        alternate.provenance["origin_refs"] = serde_json::json!(["source:README.md#L1-L1"]);
        let mut fact = valid.clone();
        fact.provenance["observation_refs"] = serde_json::json!(["fact-record"]);
        fact.provenance["origin_refs"] = serde_json::json!(["record:fact-record"]);
        fact.provenance["source_refs"] = fact.provenance["origin_refs"].clone();
        fact.source_refs = vec!["record:fact-record".to_owned()];
        let mut mismatch = valid.clone();
        mismatch.provenance["observation_refs"] =
            serde_json::json!([format!("sha256:{}", "b".repeat(64))]);
        let mut hydrated = valid.clone();
        hydrated.provenance["state"] = serde_json::json!("hydrated");
        let mut original_time = valid.clone();
        original_time.validity.observed_at = Some("2024-01-01T00:00:00Z".to_owned());
        let mut historical = valid.clone();
        historical.provenance["original_sources"] = serde_json::json!([{
            "source": {
                "canonical_provider_id": "codex", "canonical_session_id": "old-session",
                "source_key": "old-source", "stable_record_id": null,
                "observation_id": format!("sha256:{}", "a".repeat(64)), "source_revision": null,
                "content_sha256": "c".repeat(64)
            },
            "origin_scope": {"state": "unavailable"}, "source_sequence": 1,
            "occurred_at": null, "ingested_at": "2024-01-01T00:00:00Z",
            "validity": {"valid_from": null, "valid_until": null,
                "superseded_at": null, "superseded_by": null, "revoked_at": null}
        }]);
        for candidate in [alternate, fact, mismatch, hydrated, original_time] {
            let admission = common_admission(candidate, UnknownValidityPolicy::Degrade, None);
            assert!(admission.admitted.is_empty());
            assert_eq!(admission.report.denied.len(), 1);
            assert!(matches!(
                admission.report.denied[0].reason,
                RecallDenialReason::InvalidSourceAttribution { .. }
            ));
        }
        let mut checkout_history = historical.clone();
        checkout_history.exact_scope_identity.scope_binding = ScopeBinding::CheckoutObservations;
        checkout_history
            .exact_scope_identity
            .agent_session_id
            .clear();
        checkout_history
            .exact_scope_identity
            .resolved_scope_digest
            .clear();
        let checkout_history =
            common_admission(checkout_history, UnknownValidityPolicy::Degrade, None);
        assert!(checkout_history.admitted.is_empty());
        assert_eq!(
            checkout_history.report.denied[0].reason,
            RecallDenialReason::InvalidSourceAttribution {
                detail: "original observation requires exact coding scope".to_owned()
            }
        );
        let historical = common_admission(historical, UnknownValidityPolicy::Degrade, None);
        assert!(historical.admitted.is_empty());
        assert_eq!(
            historical.report.denied[0].reason,
            RecallDenialReason::InvalidSourceAttribution {
                detail: "original observation is outside dispatched canonical history".to_owned()
            }
        );
    }

    #[test]
    fn common_profile_current_records_retain_exclusions_and_unknown_validity_policy() {
        let exclusions = CognitiveRecallExclusions {
            observation_ids: vec![format!("sha256:{}", "a".repeat(64))],
            ..CognitiveRecallExclusions::default()
        };
        let excluded = common_admission(
            current_candidate(),
            UnknownValidityPolicy::Degrade,
            Some(&exclusions),
        );
        assert!(excluded.admitted.is_empty());
        assert_eq!(
            excluded.report.denied[0].reason,
            RecallDenialReason::RequestExcluded {
                field: "observation_ids".to_owned()
            }
        );
        let unknown = common_admission(current_candidate(), UnknownValidityPolicy::Exclude, None);
        assert!(unknown.admitted.is_empty());
        assert_eq!(
            unknown.report.denied[0].reason,
            RecallDenialReason::UnknownValidity
        );
        let mut revoked = current_candidate();
        revoked.validity.revoked_at = Some("2024-01-01T00:00:00Z".to_owned());
        let revoked = common_admission(revoked, UnknownValidityPolicy::Degrade, None);
        assert!(revoked.admitted.is_empty());
        assert_eq!(revoked.report.denied[0].reason, RecallDenialReason::Revoked);
    }

    #[test]
    fn exclusions_and_history_are_in_the_single_canonical_payload_hash() {
        let parts = parts();
        let exclusions = CognitiveRecallExclusions {
            stable_memory_refs: vec!["stable".to_owned()],
            candidate_ids: vec!["candidate".to_owned()],
            source_refs: vec!["source".to_owned()],
            trace_refs: vec!["trace".to_owned()],
            observation_ids: vec!["observation".to_owned()],
            content_sha256: vec!["3".repeat(64)],
        };
        // This fixture tests the envelope binding only; it is not a source grant.
        let mut grant = serde_json::json!({"policy_revision": 3, "destination_scope": scope_wire_value(&parts.exact_scope), "authorization_ref": "host.first"});
        let first =
            build_recall_request_payload_with_context(&parts, Some(&exclusions), Some(&grant))
                .unwrap();
        let wire: Value = serde_json::from_slice(&first.bytes).unwrap();
        assert_eq!(
            wire["exclusions"],
            serde_json::to_value(&exclusions).unwrap()
        );
        assert_eq!(wire["history_grant"], grant);
        assert_eq!(first.sha256, hex::encode(Sha256::digest(&first.bytes)));
        assert_eq!(
            wire["required_capabilities"],
            serde_json::json!([RECALL_QUERY_CAPABILITY_ID])
        );
        let mut capabilities = vec![OwnedVersionedId::new(RECALL_QUERY_CAPABILITY_ID).unwrap()];
        let legacy = build_recall_request_payload_with_capabilities(
            &parts,
            Some(&exclusions),
            Some(&grant),
            &capabilities,
        )
        .unwrap();
        assert_eq!(legacy.bytes, first.bytes);
        assert_eq!(legacy.sha256, first.sha256);
        capabilities.push(OwnedVersionedId::new(crate::COMMON_ADVISORY_PROFILE_ID).unwrap());
        let common = build_recall_request_payload_with_capabilities(
            &parts,
            Some(&exclusions),
            Some(&grant),
            &capabilities,
        )
        .unwrap();
        let mut common_wire: Value = serde_json::from_slice(&common.bytes).unwrap();
        assert_eq!(
            common_wire["required_capabilities"],
            serde_json::json!([
                RECALL_QUERY_CAPABILITY_ID,
                crate::COMMON_ADVISORY_PROFILE_ID
            ])
        );
        assert_eq!(common.sha256, hex::encode(Sha256::digest(&common.bytes)));
        assert_ne!(first.sha256, common.sha256);
        common_wire["required_capabilities"] = wire["required_capabilities"].clone();
        assert_eq!(common_wire, wire, "only the selected capabilities changed");
        grant["authorization_ref"] = Value::String("host.second".to_owned());
        let changed =
            build_recall_request_payload_with_context(&parts, Some(&exclusions), Some(&grant))
                .unwrap();
        assert_ne!(first.sha256, changed.sha256);
        assert_ne!(
            first.sha256,
            build_recall_request_payload(&parts).unwrap().sha256
        );
    }

    #[test]
    fn grant_envelope_refuses_nonobject_policy_and_every_foreign_destination_field() {
        let parts = parts();
        let valid = serde_json::json!({"policy_revision": 3, "destination_scope": scope_wire_value(&parts.exact_scope)});
        for invalid in [
            Value::Null,
            serde_json::json!([]),
            serde_json::json!({"policy_revision": 4, "destination_scope": scope_wire_value(&parts.exact_scope)}),
        ] {
            assert!(
                build_recall_request_payload_with_context(&parts, None, Some(&invalid)).is_err()
            );
        }
        for field in [
            "profile_id",
            "project_id",
            "repository_identity",
            "worktree_identity",
            "branch_identity",
            "agent_session_id",
            "resolved_scope_digest",
        ] {
            let mut foreign = valid.clone();
            foreign["destination_scope"][field] = Value::String("foreign".to_owned());
            assert!(
                build_recall_request_payload_with_context(&parts, None, Some(&foreign)).is_err(),
                "{field}"
            );
        }
    }
}
