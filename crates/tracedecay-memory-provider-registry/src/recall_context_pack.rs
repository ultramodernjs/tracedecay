//! Host-owned bridge from selected provider recall candidates into the
//! canonical token-budgeted context pack.
//!
//! Selection ([`crate::recall_selection`]) decided *which* admitted
//! candidates are still distinct evidence. This module is the last stage
//! before anything reaches an agent: it compiles required host evidence and
//! the advisory provider contribution into one pack under an explicit token
//! budget, measured with the canonical tokenizer, and emits a deterministic
//! pack receipt.
//!
//! Four properties are load-bearing, and each is enforced here rather than
//! documented and hoped for:
//!
//! * **The budget is measured, never estimated.** Every item's cost is the
//!   exact `o200k_base` BPE token count of its content
//!   ([`CANONICAL_CONTEXT_TOKENIZER_ID`]). A tokenizer that declares any
//!   other identity or revision is refused with
//!   [`ContextPackError::TokenizerNotCanonical`]; a byte-, character-, or
//!   word-count stand-in cannot be substituted silently, because a pack
//!   compiled under a different counter would carry a budget claim the host
//!   never verified.
//! * **Required host evidence cannot be evicted by provider volume.**
//!   Sections are compiled in priority order and every required section
//!   ([`ContextSectionKind::is_required`]) is placed *before* one advisory
//!   provider token is spent. Provider items compete only for what remains,
//!   and only up to the policy's advisory quota, which is itself bounded
//!   strictly below the total budget. No quantity of provider candidates can
//!   displace, truncate, or reorder code truth, safety evidence, session
//!   evidence, or Native facts. Required evidence that genuinely does not fit
//!   the configured total is a typed
//!   [`ContextPackError::RequiredEvidenceDoesNotFit`], never a silent drop.
//! * **Provenance survives compilation.** Every pack item keeps its section
//!   and a typed [`ContextItemProvenanceV1`]: host items name the host
//!   authority that produced them, provider items name the provider, the
//!   registration revision the reply was admitted under, the request-scoped
//!   candidate id, and the candidate's own provenance state — including the
//!   explicit "unknown" state, which is never collapsed into an empty label.
//! * **The pack is reconcilable and deterministic.** Every provider item of
//!   the contribution appears exactly once, either in the advisory section or
//!   in [`ContextPackV1::excluded_provider_items`] with a typed reason, so a
//!   pack can always be reconciled against its input. The
//!   [`ContextPackV1::pack_hash`] binds the policy identity, the tokenizer
//!   identity, the budgets, and every admitted item's section, identity,
//!   provenance, measured token cost, and content digest: identical inputs
//!   under an identical policy always produce an identical hash, and any
//!   change to what was admitted or to what it cost changes it.
//!
//! **An advisory item is admitted whole or not at all.** Provider content is
//! never truncated mid-item to fill a remaining token gap: half a recalled
//! memory is a different claim from the whole one, and a truncated advisory
//! sentence is exactly the kind of silently corrupted evidence this stage
//! exists to prevent. An item that does not fit is excluded and recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::recall_admission::{AdmittedRecallCandidate, RecallCandidateContent, RecallCandidateV1};
use crate::recall_selection::{RecallSelectionError, RecallSelectionV1};

/// Identity of the host context-pack policy implemented here.
pub const HOST_CONTEXT_PACK_POLICY_ID: &str = "tracedecay.host.context.pack.v1";

/// Revision of [`HOST_CONTEXT_PACK_POLICY_ID`]. Any change to section
/// priority, quota arithmetic, the exclusion vocabulary, or the pack-hash
/// encoding must increment this.
pub const HOST_CONTEXT_PACK_POLICY_REVISION: u64 = 6;

/// Host authority label for accepted TraceDecay Native project-memory facts
/// carried in a context answer. Native stays the authority for accepted
/// explicit facts, so a host mount attributes that evidence here rather than
/// to the tool that rendered it. Declared in the registry so mounts never
/// spell a provider identity themselves.
pub const NATIVE_FACTS_HOST_AUTHORITY: &str = "tracedecay.native.project_memory";

/// Identity of the canonical context tokenizer.
///
/// It is the same estimator identity the coding-memory conformance baseline
/// records its admitted-context token costs under, so a pack budget and a
/// baseline token cost are the same measurement rather than two numbers that
/// happen to share a name.
pub const CANONICAL_CONTEXT_TOKENIZER_ID: &str = "tiktoken.o200k_base";

/// Revision of [`CANONICAL_CONTEXT_TOKENIZER_ID`]: the pinned `tiktoken-rs`
/// release whose vendored `o200k_base` ranks and pre-tokenizer pattern
/// produce every count.
pub const CANONICAL_CONTEXT_TOKENIZER_REVISION: &str = "tiktoken-rs-0.12";

/// A tokenizer the context compiler may measure a budget with.
///
/// The trait exists so the counter is injectable for measurement-behaviour
/// tests, not so an arbitrary counter can be mounted: [`compile_context_pack`]
/// refuses any implementation whose declared identity and revision are not
/// the canonical pair.
pub trait ContextTokenizer {
    /// Stable tokenizer identity.
    fn tokenizer_id(&self) -> &str;
    /// Tokenizer revision.
    fn tokenizer_revision(&self) -> &str;
    /// Exact token count of `text` under this tokenizer.
    fn count_tokens(&self, text: &str) -> u64;
}

/// The canonical context tokenizer: exact `o200k_base` BPE token counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct O200kBaseContextTokenizer;

impl ContextTokenizer for O200kBaseContextTokenizer {
    fn tokenizer_id(&self) -> &str {
        CANONICAL_CONTEXT_TOKENIZER_ID
    }

    fn tokenizer_revision(&self) -> &str {
        CANONICAL_CONTEXT_TOKENIZER_REVISION
    }

    fn count_tokens(&self, text: &str) -> u64 {
        let ranks = tiktoken_rs::o200k_base_singleton().encode_ordinary(text);
        u64::try_from(ranks.len()).unwrap_or(u64::MAX)
    }
}

/// One section of a compiled context pack.
///
/// Declaration order *is* compilation priority: a section declared earlier is
/// compiled first and therefore claims budget first. Every variant but
/// [`Self::ProviderMemory`] is required host evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSectionKind {
    /// Code truth the host resolved from the indexed checkout.
    CodeTruth,
    /// Safety, risk, or policy evidence the host is obliged to carry.
    SafetyEvidence,
    /// Session evidence the host resolved from its own transcript stores.
    SessionEvidence,
    /// Accepted TraceDecay Native facts. Native remains the authority for
    /// accepted explicit facts, so its section is required host evidence and
    /// never competes with the advisory provider lane.
    NativeFacts,
    /// The advisory provider-memory contribution. The only evictable section.
    ProviderMemory,
}

impl ContextSectionKind {
    /// Whether this section is required host evidence, which provider volume
    /// can never displace.
    #[must_use]
    pub const fn is_required(self) -> bool {
        !matches!(self, Self::ProviderMemory)
    }

    /// Stable wire label, used by the pack-hash encoding and by renderers.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CodeTruth => "code_truth",
            Self::SafetyEvidence => "safety_evidence",
            Self::SessionEvidence => "session_evidence",
            Self::NativeFacts => "native_facts",
            Self::ProviderMemory => "provider_memory",
        }
    }

    /// Every section kind in compilation-priority order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::CodeTruth,
            Self::SafetyEvidence,
            Self::SessionEvidence,
            Self::NativeFacts,
            Self::ProviderMemory,
        ]
    }
}

/// How a compiled pack is serialized for the agent.
///
/// The budget is measured against the form that is actually delivered:
/// markdown framing and JSON framing cost different numbers of tokens, and a
/// pack budgeted for one and rendered as the other would carry a claim the
/// host never verified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPackRenderFormV1 {
    /// The pack is appended to a markdown answer.
    Markdown,
    /// The pack is rendered as members of one JSON object.
    Json,
}

impl ContextPackRenderFormV1 {
    /// Stable wire label, used by the pack-hash encoding and by renderers.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Json => "json",
        }
    }
}

/// Why a [`ContextPackPolicyV1`] could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContextPackPolicyError {
    /// A pack that can carry no tokens is not a usable budget.
    #[error("context pack total token budget must be greater than zero")]
    ZeroTotalBudget,
    /// The advisory quota must leave room for required host evidence. A quota
    /// equal to or above the total budget would let the advisory lane consume
    /// the entire pack, which is exactly the crowding-out this policy exists
    /// to prevent.
    #[error(
        "advisory token quota {advisory} must stay strictly below the total token budget {total}"
    )]
    AdvisoryQuotaNotBoundedByTotal {
        /// The configured advisory quota.
        advisory: u64,
        /// The configured total budget.
        total: u64,
    },
}

impl ContextPackPolicyError {
    /// Stable machine-readable code of this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ZeroTotalBudget => "context_pack_policy_zero_total_budget",
            Self::AdvisoryQuotaNotBoundedByTotal { .. } => {
                "context_pack_policy_advisory_quota_not_bounded_by_total"
            }
        }
    }
}

/// Pinned host context-pack configuration.
///
/// Determinism is a property of this value: the same items under the same
/// policy always compile to the same pack, in the same order, with the same
/// hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextPackPolicyV1 {
    policy_id: &'static str,
    policy_revision: u64,
    total_token_budget: u64,
    advisory_token_quota: u64,
    render_form: ContextPackRenderFormV1,
}

impl ContextPackPolicyV1 {
    /// The pinned policy under an explicit total budget and advisory quota.
    ///
    /// # Errors
    ///
    /// Returns [`ContextPackPolicyError::ZeroTotalBudget`] for a budget that
    /// can carry nothing, and
    /// [`ContextPackPolicyError::AdvisoryQuotaNotBoundedByTotal`] when the
    /// advisory quota is not strictly below the total budget. Nothing here
    /// clamps or repairs an invalid configuration.
    pub fn new(
        total_token_budget: u64,
        advisory_token_quota: u64,
        render_form: ContextPackRenderFormV1,
    ) -> Result<Self, ContextPackPolicyError> {
        if total_token_budget == 0 {
            return Err(ContextPackPolicyError::ZeroTotalBudget);
        }
        if advisory_token_quota >= total_token_budget {
            return Err(ContextPackPolicyError::AdvisoryQuotaNotBoundedByTotal {
                advisory: advisory_token_quota,
                total: total_token_budget,
            });
        }
        Ok(Self {
            policy_id: HOST_CONTEXT_PACK_POLICY_ID,
            policy_revision: HOST_CONTEXT_PACK_POLICY_REVISION,
            total_token_budget,
            advisory_token_quota,
            render_form,
        })
    }

    /// Policy identity carried on every pack it compiles.
    #[must_use]
    pub const fn policy_id(&self) -> &'static str {
        self.policy_id
    }

    /// Pinned policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Total token budget of the whole pack.
    #[must_use]
    pub const fn total_token_budget(&self) -> u64 {
        self.total_token_budget
    }

    /// Maximum tokens the advisory provider section may consume, its own
    /// framing included.
    #[must_use]
    pub const fn advisory_token_quota(&self) -> u64 {
        self.advisory_token_quota
    }

    /// Serialization form the budget is measured against.
    #[must_use]
    pub const fn render_form(&self) -> ContextPackRenderFormV1 {
        self.render_form
    }
}

/// One required host-evidence item offered to the compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostContextItemV1 {
    /// Required section this item belongs to.
    pub section: ContextSectionKind,
    /// Stable, pack-scoped item identity.
    pub item_id: String,
    /// The host authority that produced the item, retained as provenance.
    pub authority: String,
    /// The item's content.
    pub content: String,
}

/// Provenance state of one provider candidate, preserved through
/// compilation.
///
/// Absent provenance is a distinct, explicit state. It is never rendered as
/// an empty label, because an unlabelled advisory item is indistinguishable
/// from cited host evidence at the point of use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderItemProvenanceV1 {
    /// The provider named a source for the item. This is the provider's own
    /// claim, not yet confirmed by a host authority; only
    /// [`Self::Hydrated`] is cited grounding.
    Available {
        /// The named source reference.
        source: String,
    },
    /// A host authority confirmed the claimed source names one of the
    /// host's own exact evidence shapes. This, and only this, is cited
    /// grounding: a source/session range or a canonical record the host
    /// itself resolved, never the provider's raw claim.
    Hydrated {
        /// The host-resolved evidence.
        evidence: crate::recall_provenance_hydration::HostEvidenceRefV1,
    },
    /// The provider claimed a source but a host authority could not confirm
    /// it. Distinct from [`Self::Unknown`]: a claim was made and it did not
    /// stand up, so it is labelled as unresolved rather than absent.
    Unresolvable {
        /// The raw claimed reference that did not resolve.
        source: String,
        /// Bounded, host-authored reason it did not resolve.
        reason: String,
    },
    /// The provider redacted provenance and gave a reason.
    Redacted {
        /// The provider's redaction reason.
        reason: String,
    },
    /// No provenance was established: the provider named no source at all.
    Unknown,
}

impl ProviderItemProvenanceV1 {
    /// Stable single-line encoding used by the pack-hash and by renderers.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Available { source } => format!("available:{source}"),
            Self::Hydrated { evidence } => match self.canonical_observation_evidence() {
                Some(original) => format!(
                    "hydrated:{}:evidence={}",
                    evidence.label(),
                    serde_json::json!(original)
                ),
                None => format!("hydrated:{}", evidence.label()),
            },
            Self::Unresolvable { source, reason } => format!("unresolvable:{source}:{reason}"),
            Self::Redacted { reason } => format!("redacted:{reason}"),
            Self::Unknown => "unknown".to_owned(),
        }
    }

    /// The agent-facing form of this provenance state.
    ///
    /// Absent provenance says so in words. An advisory item is never rendered
    /// with an empty provenance label, because an unlabelled advisory line is
    /// indistinguishable from cited host evidence at the point of use.
    #[must_use]
    pub fn human_label(&self) -> String {
        match self {
            Self::Available { source } => format!("source {source}"),
            Self::Hydrated { evidence } => format!("cited source {}", evidence.label()),
            Self::Unresolvable { source, reason } => {
                format!("provenance unresolved (claimed {source}: {reason})")
            }
            Self::Redacted { reason } => format!("redacted: {reason}"),
            Self::Unknown => "provenance unknown".to_owned(),
        }
    }

    /// This is the existing confirmed evidence object, never a second source
    /// projection or a provider's unresolved attribution.
    fn canonical_observation_evidence(
        &self,
    ) -> Option<&crate::recall_provenance_hydration::HostEvidenceRefV1> {
        match self {
            Self::Hydrated { evidence: evidence @ crate::recall_provenance_hydration::HostEvidenceRefV1::CanonicalObservations { .. } } => Some(evidence),
            _ => None,
        }
    }

    /// Adds only host-prepared locators beside the existing confirmed sources.
    /// A locator identifies a retained row; it is never source authority.
    fn canonical_observation_evidence_value(
        &self,
        recall: Option<&ContextRecallControlRefV1>,
    ) -> Option<serde_json::Value> {
        let mut evidence = serde_json::json!(self.canonical_observation_evidence()?);
        if let Some(recall) = recall {
            evidence["recall"] = serde_json::json!(recall);
        }
        Some(evidence)
    }

    /// Markdown retains the familiar human label and the same typed evidence
    /// object the JSON candidate carries. Both enter token admission whole.
    fn markdown_label(&self, recall: Option<&ContextRecallControlRefV1>) -> String {
        let mut label = self.human_label();
        if let Some(evidence) = self.canonical_observation_evidence_value(recall) {
            let _ = write!(
                label,
                "; provenance_evidence={}",
                serde_json::json!(evidence)
            );
        }
        label
    }

    /// Whether this state names host-confirmed evidence rather than a bare
    /// provider claim, a redaction, or nothing at all.
    #[must_use]
    pub const fn is_hydrated(&self) -> bool {
        matches!(self, Self::Hydrated { .. })
    }

    /// The provenance a candidate declared, read exactly as the recall port
    /// reads it for the application contract: an `available` state must name
    /// a source or it is not established provenance at all.
    #[must_use]
    pub fn from_candidate(candidate: &RecallCandidateV1) -> Self {
        let state = candidate
            .provenance
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unavailable");
        match state {
            "available" => {
                let first_ref = |key: &str| {
                    candidate
                        .provenance
                        .get(key)
                        .and_then(serde_json::Value::as_array)
                        .and_then(|refs| refs.first())
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                };
                candidate
                    .stable_memory_ref
                    .clone()
                    .or_else(|| first_ref("origin_refs"))
                    .or_else(|| first_ref("source_refs"))
                    .or_else(|| candidate.source_refs.first().cloned())
                    .filter(|source| !source.trim().is_empty())
                    .map_or(Self::Unknown, |source| Self::Available { source })
            }
            "redacted" => {
                let reason = candidate
                    .provenance
                    .get("redaction_reason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|reason| !reason.is_empty())
                    .unwrap_or("provider_redacted")
                    .to_owned();
                Self::Redacted { reason }
            }
            _ => Self::Unknown,
        }
    }
}

/// One advisory provider item offered to the compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderContextItemV1 {
    /// Request-scoped candidate identity the provider assigned.
    pub candidate_id: String,
    /// Bounded advisory content the host admitted.
    pub content: String,
    /// Provenance state, preserved verbatim through compilation.
    pub provenance: ProviderItemProvenanceV1,
    /// Optional provider explanation summary.
    pub explanation: Option<String>,
}

/// The advisory contribution of one provider to one pack.
///
/// It is attributed: the pack records which provider produced the items and
/// under which registration revision the reply was admitted, so an advisory
/// item can never be mistaken for host evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderContributionV1 {
    /// Provider the routing policy pinned, as the result attributed it.
    pub provider_id: String,
    /// Registration revision the reply was admitted under.
    pub registration_revision: u64,
    /// Lane degradation the provider terminal or host admission reported,
    /// retained so a partial or stale answer is attributed as one.
    pub degradation: Option<String>,
    /// Advisory items in host selection order.
    pub items: Vec<ProviderContextItemV1>,
    /// Selected candidates whose content is a reference rather than inline
    /// text. They carry no compilable content, and are recorded in the pack's
    /// exclusion ledger rather than dropped.
    pub reference_only_candidate_ids: Vec<String>,
}

impl ProviderContributionV1 {
    /// The advisory contribution of one host selection.
    ///
    /// The selection's `selected` list is walked in host order, and each
    /// entry is resolved against the admitted slice it indexes. Integrity is
    /// re-verified here rather than assumed: a `provider_rank` outside the
    /// slice, an admitted entry with a different candidate identity, or a
    /// disagreeing content digest is a typed [`RecallSelectionError`], never
    /// a silently mismatched item that would attach one candidate's words to
    /// another candidate's identity and provenance.
    ///
    /// # Errors
    ///
    /// Returns [`RecallSelectionError`] when the selection does not describe
    /// the admitted slice supplied.
    pub fn from_selection(
        provider_id: impl Into<String>,
        registration_revision: u64,
        selection: &RecallSelectionV1,
        admitted: &[AdmittedRecallCandidate],
    ) -> Result<Self, RecallSelectionError> {
        let mut items = Vec::with_capacity(selection.selected.len());
        let mut reference_only_candidate_ids = Vec::new();
        for selected in &selection.selected {
            let Some(entry) = admitted.get(selected.provider_rank) else {
                return Err(RecallSelectionError::ProviderRankOutOfRange {
                    candidate_id: selected.candidate_id.clone(),
                    provider_rank: selected.provider_rank,
                    admitted_len: admitted.len(),
                });
            };
            let candidate = entry.candidate();
            if candidate.candidate_id != selected.candidate_id {
                return Err(RecallSelectionError::CandidateIdentityMismatch {
                    provider_rank: selected.provider_rank,
                    expected: selected.candidate_id.clone(),
                    admitted: candidate.candidate_id.clone(),
                });
            }
            if candidate.content_sha256 != selected.content_sha256 {
                return Err(RecallSelectionError::ContentDigestMismatch {
                    candidate_id: selected.candidate_id.clone(),
                    expected: selected.content_sha256.clone(),
                    admitted: candidate.content_sha256.clone(),
                });
            }
            match entry.content() {
                RecallCandidateContent::Inline(content) => items.push(ProviderContextItemV1 {
                    candidate_id: candidate.candidate_id.clone(),
                    content: content.to_owned(),
                    provenance: ProviderItemProvenanceV1::from_candidate(candidate),
                    explanation: selected.explanation_summary.clone(),
                }),
                RecallCandidateContent::Reference(_) => {
                    reference_only_candidate_ids.push(candidate.candidate_id.clone());
                }
            }
        }
        Ok(Self {
            provider_id: provider_id.into(),
            registration_revision,
            degradation: None,
            items,
            reference_only_candidate_ids,
        })
    }
}

/// Bounded host-prepared locators beside a confirmed observation's provenance.
/// These are render data, not authorization. The host must atomically retain
/// their final trace and source bindings before publishing a controlled pack.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRecallControlRefV1 {
    /// Retained delivery-scope and trace locator.
    pub trace_ref: String,
    /// Original provider rank within that retained trace.
    pub item_ref: String,
}

/// Provenance of one compiled pack item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum ContextItemProvenanceV1 {
    /// Required host evidence, attributed to the host authority that
    /// produced it.
    Host {
        /// Host authority identity.
        authority: String,
    },
    /// Advisory provider memory, attributed to the provider, the
    /// registration revision, the candidate, and the candidate's own
    /// provenance state.
    Provider {
        /// Provider identity.
        provider_id: String,
        /// Registration revision the reply was admitted under.
        registration_revision: u64,
        /// Request-scoped candidate identity.
        candidate_id: String,
        /// The candidate's declared provenance state.
        candidate_provenance: ProviderItemProvenanceV1,
        /// Host-prepared locators, published only after atomic retention.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recall_control: Option<ContextRecallControlRefV1>,
        /// Optional provider explanation summary.
        explanation: Option<String>,
    },
}

impl ContextItemProvenanceV1 {
    /// Stable single-line encoding used by the pack-hash and by renderers.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Host { authority } => format!("host:{authority}"),
            Self::Provider {
                provider_id,
                registration_revision,
                candidate_id,
                candidate_provenance,
                recall_control,
                explanation,
            } => {
                let mut label = String::new();
                let _ = write!(
                    label,
                    "provider:{provider_id}:{registration_revision}:{candidate_id}:{}",
                    candidate_provenance.label()
                );
                if let Some(recall) = recall_control {
                    let _ = write!(label, ":recall={}", serde_json::json!(recall));
                }
                if let Some(explanation) = explanation {
                    let _ = write!(label, ":explained({explanation})");
                }
                label
            }
        }
    }
}

/// One compiled pack item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextPackItemV1 {
    /// Section the item was compiled into.
    pub section: ContextSectionKind,
    /// Pack-scoped item identity.
    pub item_id: String,
    /// Exact token cost of [`Self::content`] under the canonical tokenizer.
    pub tokens: u64,
    /// Preserved provenance.
    pub provenance: ContextItemProvenanceV1,
    /// The item's content, admitted whole and never truncated.
    pub content: String,
}

/// One compiled pack section.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextPackSectionV1 {
    /// Which section this is.
    pub section: ContextSectionKind,
    /// Whether the section is required host evidence.
    pub required: bool,
    /// Token quota that bounded the section, when one applies. Required
    /// sections carry no quota: they are not evictable.
    pub token_quota: Option<u64>,
    /// Total measured tokens of the section's items.
    pub tokens: u64,
    /// Items in compilation order.
    pub items: Vec<ContextPackItemV1>,
}

/// Which provider-controlled label failed the renderer's containment
/// precondition.
///
/// Content is not the only provider-controlled string the agent reads. A
/// candidate identity, a claimed provenance source, a provider-authored
/// reason, and an explanation are all interpolated into the same rendered
/// line, so each of them can end that line and start a forged one. Naming the
/// field makes a refusal actionable instead of anonymous.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMetadataFieldV1 {
    /// The provider's candidate identity.
    CandidateId,
    /// The advisory claim itself.
    Content,
    /// A claimed or provider-authored provenance string.
    Provenance,
    /// The provider's explanation summary.
    Explanation,
}

impl ProviderMetadataFieldV1 {
    /// Stable snake_case label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CandidateId => "candidate_id",
            Self::Content => "content",
            Self::Provenance => "provenance",
            Self::Explanation => "explanation",
        }
    }
}

/// Why one advisory provider item was not compiled into the pack.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ProviderExclusionReason {
    /// One of the item's provider-controlled strings was not contained: it
    /// carried a line break, a control or hidden character, or a forged copy
    /// of the host's own untrusted-memory boundary label. Such a string
    /// cannot be rendered beside host evidence without being able to forge
    /// structure, so the whole item is excluded rather than repaired.
    MetadataNotContained {
        /// Which label failed containment.
        field: ProviderMetadataFieldV1,
    },
    /// The advisory section's own quota could not hold the item.
    AdvisoryQuotaExhausted {
        /// The quota that bounded the section.
        advisory_token_quota: u64,
        /// Tokens the section had already spent, framing included.
        section_tokens_used: u64,
        /// Measured token cost of the excluded item, framing included.
        item_tokens: u64,
    },
    /// Required host evidence had already claimed the remaining total
    /// budget. This is the crowding-out direction that is allowed: provider
    /// volume yields to host evidence, never the other way round.
    TotalBudgetExhausted {
        /// The pack's total token budget.
        total_token_budget: u64,
        /// Tokens still unspent when the item was evaluated.
        remaining_tokens: u64,
        /// Measured token cost of the excluded item, framing included.
        item_tokens: u64,
    },
    /// The selected candidate carried a content reference rather than inline
    /// text, so there was nothing to compile.
    ContentNotInline,
    /// The advisory lane's own framing — its heading and provider
    /// attribution — already costs more than the advisory quota, so the whole
    /// lane is withheld rather than rendered unbudgeted.
    AdvisoryFramingDoesNotFit {
        /// The quota that bounded the section.
        advisory_token_quota: u64,
        /// Measured token cost of the lane framing alone.
        framing_tokens: u64,
    },
    /// The item was admitted by the per-item accounting but the exact
    /// rendered pack still measured above a budget, so the item was evicted
    /// from the tail until the rendered text fit.
    RenderedPackOverBudget {
        /// The budget the rendered text exceeded.
        token_budget: u64,
        /// Measured token cost of the rendered text before this eviction.
        rendered_tokens: u64,
    },
}

/// One advisory provider item that did not reach the pack.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExcludedProviderItemV1 {
    /// Request-scoped candidate identity.
    pub candidate_id: String,
    /// Why it was excluded.
    pub reason: ProviderExclusionReason,
}

/// Why one pack could not be compiled at all.
///
/// Every variant is a refusal, not a degradation: a pack that silently
/// dropped required evidence or measured its budget with an unverified
/// counter would carry a guarantee the host never established. Every variant
/// also carries a stable [`ContextPackError::code`] so a caller — and a
/// receipt — can distinguish the refusals structurally instead of by string
/// matching a rendered message.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContextPackError {
    /// The supplied tokenizer is not the canonical one.
    #[error(
        "context pack requires the canonical tokenizer {expected_id}/{expected_revision}, not \
         {received_id}/{received_revision}"
    )]
    TokenizerNotCanonical {
        /// Canonical tokenizer identity.
        expected_id: &'static str,
        /// Canonical tokenizer revision.
        expected_revision: &'static str,
        /// Identity the supplied tokenizer declared.
        received_id: String,
        /// Revision the supplied tokenizer declared.
        received_revision: String,
    },
    /// A host item claimed the advisory section. Host evidence and provider
    /// memory are different trust classes and never share a section.
    #[error("host item {item_id} claims the advisory provider section")]
    HostItemInAdvisorySection {
        /// The offending item identity.
        item_id: String,
    },
    /// An item identity was empty or untrimmed, so it could not identify
    /// anything in the pack receipt.
    #[error("context pack item identity is empty or untrimmed")]
    ItemIdentityInvalid,
    /// Two items claimed the same identity, so the pack could not be
    /// reconciled item by item. A provider candidate admitted inline *and*
    /// listed as reference-only is this error, not a silently doubled ledger
    /// row.
    #[error("context pack item identity {item_id} is used more than once")]
    DuplicateItemIdentity {
        /// The repeated identity.
        item_id: String,
    },
    /// The pack renders as one JSON object, so every host item must be a
    /// well-formed `"key": value` member of it. An item that is not cannot be
    /// rendered without corrupting the host's own answer.
    #[error("host item {item_id} is not a well-formed JSON object member")]
    HostItemNotJsonMember {
        /// The offending item identity.
        item_id: String,
    },
    /// Required host evidence did not fit the configured total budget. It is
    /// never evicted to make the pack fit; the configuration is wrong and
    /// says so.
    #[error(
        "required {section} evidence {item_id} costs {item_tokens} tokens but only \
         {remaining_tokens} of the {total_token_budget}-token budget remain"
    )]
    RequiredEvidenceDoesNotFit {
        /// Section of the item that did not fit.
        section: &'static str,
        /// Identity of the item that did not fit.
        item_id: String,
        /// Measured token cost of the item.
        item_tokens: u64,
        /// Tokens still unspent when the item was evaluated.
        remaining_tokens: u64,
        /// The configured total budget.
        total_token_budget: u64,
    },
    /// Required host evidence and the pack's own framing fit the per-item
    /// accounting but the exact rendered pack still measures above the total
    /// budget, and there is no advisory item left to evict. Nothing required
    /// is ever truncated to hide this.
    #[error(
        "the rendered pack costs {rendered_tokens} tokens, above the {total_token_budget}-token \
         budget, with no advisory item left to evict"
    )]
    RenderedRequiredEvidenceOverBudget {
        /// Measured token cost of the rendered pack.
        rendered_tokens: u64,
        /// The configured total budget.
        total_token_budget: u64,
    },
    /// The lane's own attribution — the pinned provider identity or the
    /// degradation label — was not contained. Attribution is host-registered
    /// rather than provider-supplied, so this is a host defect and the whole
    /// pack is refused; the caller delivers its own answer unchanged instead
    /// of rendering an attribution line that could forge structure.
    #[error("advisory lane attribution field {field} is not a contained single-line label")]
    ProviderAttributionInvalid {
        /// Which attribution field failed containment.
        field: &'static str,
    },
}

impl ContextPackError {
    /// Stable machine-readable code of this refusal.
    ///
    /// Receipts and callers branch on this, never on the rendered message: a
    /// tokenizer refusal, an identity refusal, and required evidence that
    /// does not fit are different terminal outcomes and stay distinguishable
    /// after the error has been carried across a boundary.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TokenizerNotCanonical { .. } => "context_pack_tokenizer_not_canonical",
            Self::HostItemInAdvisorySection { .. } => "context_pack_host_item_in_advisory_section",
            Self::ItemIdentityInvalid => "context_pack_item_identity_invalid",
            Self::DuplicateItemIdentity { .. } => "context_pack_duplicate_item_identity",
            Self::HostItemNotJsonMember { .. } => "context_pack_host_item_not_json_member",
            Self::RequiredEvidenceDoesNotFit { .. } => {
                "context_pack_required_evidence_does_not_fit"
            }
            Self::RenderedRequiredEvidenceOverBudget { .. } => {
                "context_pack_rendered_required_evidence_over_budget"
            }
            Self::ProviderAttributionInvalid { .. } => "context_pack_provider_attribution_invalid",
        }
    }
}

/// The bounded pack receipt, rendered into the agent-visible text itself.
///
/// It is bounded by construction: every field is a fixed identity or a
/// number, and the exclusion ledger is summarised by typed counts rather than
/// by an unbounded list of candidate identities. That is what makes the
/// receipt's own token cost reservable before a single item is admitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextPackReceiptV1 {
    /// Always `compiled`: a pack that could not be compiled has no receipt.
    pub state: String,
    /// Deterministic pack hash.
    pub pack_hash: String,
    /// Policy identity that compiled the pack.
    pub pack_policy_id: String,
    /// Revision of that policy.
    pub pack_policy_revision: u64,
    /// Tokenizer every count was measured with.
    pub tokenizer_id: String,
    /// Revision of that tokenizer.
    pub tokenizer_revision: String,
    /// Serialization form the budget was measured against.
    pub render_form: ContextPackRenderFormV1,
    /// Total token budget.
    pub total_token_budget: u64,
    /// Advisory quota inside that budget.
    pub advisory_token_quota: u64,
    /// Tokens reserved for the pack's own deterministic framing.
    pub framing_tokens: u64,
    /// Accounted tokens of framing plus every admitted item.
    pub total_tokens: u64,
    /// Accounted tokens of the advisory lane, its framing included.
    pub advisory_tokens: u64,
    /// Advisory items excluded because the advisory quota was exhausted.
    pub excluded_advisory_quota_exhausted: u64,
    /// Advisory items excluded because the total budget was exhausted.
    pub excluded_total_budget_exhausted: u64,
    /// Selected candidates excluded because their content was a reference.
    pub excluded_content_not_inline: u64,
    /// Advisory items excluded because the lane framing alone exceeded the
    /// advisory quota.
    pub excluded_advisory_framing_does_not_fit: u64,
    /// Advisory items evicted because the exact rendered pack measured above
    /// a budget.
    pub excluded_rendered_pack_over_budget: u64,
    /// Advisory items excluded because one of their provider-controlled
    /// strings was not a contained single-line label.
    pub excluded_metadata_not_contained: u64,
}

/// Actual retained recall correlation, independent of whether any candidate survived.
/// The host publishes this value only after the final trace is retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRecallTraceV1 {
    /// Actual advisory recall request identity minted by the host.
    pub request_id: String,
    /// Exact scope and trace address in the host's retained ledger.
    pub trace_ref: String,
}

struct PreparedContextRecallTraceV1<'a> {
    metadata: &'a ContextRecallTraceV1,
    json: String,
}

/// One compiled, token-budgeted context pack.
///
/// [`Self::rendered`] is the exact agent-visible text this pack compiles to,
/// and [`Self::rendered_tokens`] is that text's measured cost under the
/// canonical tokenizer. Compilation does not return a pack whose rendered
/// text exceeds [`Self::total_token_budget`], or whose advisory lane exceeds
/// [`Self::advisory_token_quota`]: the budget is a property of what the agent
/// actually receives, framing, identities, provenance, explanations and
/// receipt included, not of the raw item bodies alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextPackV1 {
    /// Policy identity that compiled this pack.
    pub pack_policy_id: String,
    /// Revision of that policy.
    pub pack_policy_revision: u64,
    /// Identity of the tokenizer every token count was measured with.
    pub tokenizer_id: String,
    /// Revision of that tokenizer.
    pub tokenizer_revision: String,
    /// Serialization form the pack was compiled and measured for.
    pub render_form: ContextPackRenderFormV1,
    /// Total token budget the pack was compiled under.
    pub total_token_budget: u64,
    /// Advisory quota that bounded the provider section.
    pub advisory_token_quota: u64,
    /// Retained trace correlation admitted with the complete advisory framing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_trace: Option<ContextRecallTraceV1>,
    /// Compiled sections in priority order. A section with no admitted item
    /// is omitted.
    pub sections: Vec<ContextPackSectionV1>,
    /// Provider items that did not reach the pack, in evaluation order.
    pub excluded_provider_items: Vec<ExcludedProviderItemV1>,
    /// Tokens reserved for the pack's own deterministic framing.
    pub framing_tokens: u64,
    /// Accounted tokens: framing plus every admitted item.
    pub total_tokens: u64,
    /// The exact agent-visible text this pack renders to.
    pub rendered: String,
    /// Measured token cost of [`Self::rendered`].
    pub rendered_tokens: u64,
    /// Bounded receipt, also rendered inside [`Self::rendered`].
    pub receipt: ContextPackReceiptV1,
    /// Deterministic receipt over the policy, the tokenizer, the budgets, and
    /// every admitted item's section, identity, provenance, token cost, and
    /// content digest.
    pub pack_hash: String,
}

impl ContextPackV1 {
    /// The admitted items of one section, in compilation order.
    pub fn section(&self, section: ContextSectionKind) -> Option<&ContextPackSectionV1> {
        self.sections
            .iter()
            .find(|compiled| compiled.section == section)
    }

    /// Every admitted item across every section, in compilation order.
    pub fn items(&self) -> impl Iterator<Item = &ContextPackItemV1> {
        self.sections
            .iter()
            .flat_map(|section| section.items.iter())
    }

    /// Accounted tokens the advisory provider lane consumed, its own framing
    /// included.
    #[must_use]
    pub fn advisory_tokens(&self) -> u64 {
        self.receipt.advisory_tokens
    }
}

/// The advisory lane one pack compiles, in the exact shape the agent sees.
///
/// Every shape is explicit, because "no lane at all", "a lane that could not
/// answer", and "a lane that answered" are three different things to an agent
/// reading the pack, and only the last one may spend advisory budget on
/// provider content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdvisoryLaneV1 {
    /// No advisory lane exists for this pack. Nothing advisory is rendered
    /// and no advisory framing is charged.
    Absent,
    /// The lane exists but produced no answer. The notice is rendered and its
    /// framing is charged to the advisory quota exactly like content would
    /// be.
    Notice {
        /// Provider the routing policy selected for this unavailable lane.
        provider_id: String,
        /// Registration revision the unavailable call was routed under.
        registration_revision: u64,
        /// Bounded, host-authored reason the lane could not answer.
        notice: String,
    },
    /// The lane answered with an attributed provider contribution.
    Contribution(ProviderContributionV1),
}

impl AdvisoryLaneV1 {
    /// The contribution this lane carries, if it answered.
    #[must_use]
    pub const fn contribution(&self) -> Option<&ProviderContributionV1> {
        match self {
            Self::Contribution(contribution) => Some(contribution),
            Self::Absent | Self::Notice { .. } => None,
        }
    }
}

/// Placeholder pack hash used when reserving framing, the exact width of a
/// real hex-encoded SHA-256 digest.
const HASH_WIDTH_PROBE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Compiles required host evidence and one advisory lane into a
/// token-budgeted context pack, and renders the exact agent-visible text.
///
/// Host items are compiled first, in section priority order and, within a
/// section, in the order supplied; they are *rendered* in the order supplied,
/// so a markdown host answer split into attributed evidence items reassembles
/// byte-for-byte. Provider items are compiled last and only into
/// [`ContextSectionKind::ProviderMemory`], bounded by both the policy's
/// advisory quota and whatever the required sections left of the total
/// budget.
///
/// The budget covers the *rendered* pack: the pack's own framing is measured
/// and reserved before the first item is admitted, each item is charged the
/// cost of the fragment it actually contributes to the rendered text, and the
/// finished text is measured once more and advisory items are evicted from
/// the tail until it fits. A returned pack therefore always satisfies
/// `rendered_tokens <= total_token_budget`.
///
/// # Errors
///
/// Returns [`ContextPackError::TokenizerNotCanonical`] for any tokenizer but
/// the canonical one, [`ContextPackError::HostItemInAdvisorySection`] when a
/// host item claims the advisory section,
/// [`ContextPackError::ItemIdentityInvalid`] or
/// [`ContextPackError::DuplicateItemIdentity`] for an unusable item identity
/// — including a candidate that is both admitted inline and listed as
/// reference-only — [`ContextPackError::HostItemNotJsonMember`] when a JSON
/// pack is offered a host item that is not an object member, and
/// [`ContextPackError::RequiredEvidenceDoesNotFit`] or
/// [`ContextPackError::RenderedRequiredEvidenceOverBudget`] when the
/// configured total budget cannot hold the required evidence offered.
pub fn compile_context_pack(
    policy: ContextPackPolicyV1,
    tokenizer: &dyn ContextTokenizer,
    host_items: &[HostContextItemV1],
    lane: &AdvisoryLaneV1,
) -> Result<ContextPackV1, ContextPackError> {
    compile_context_pack_with_control_refs(policy, tokenizer, host_items, lane, &BTreeMap::new())
}

/// Compiles private host-prepared locators through the ordinary budget and hash
/// path. Callers must retain the final trace and metadata before publishing this
/// pack. The ordinary compiler deliberately never accepts or fabricates locators.
pub fn compile_context_pack_with_control_refs(
    policy: ContextPackPolicyV1,
    tokenizer: &dyn ContextTokenizer,
    host_items: &[HostContextItemV1],
    lane: &AdvisoryLaneV1,
    control_refs: &BTreeMap<String, ContextRecallControlRefV1>,
) -> Result<ContextPackV1, ContextPackError> {
    compile_context_pack_with_control_metadata(
        policy,
        tokenizer,
        host_items,
        lane,
        control_refs,
        None,
    )
}

/// Compiles retained lane metadata through the same framing, quota, and hash
/// path as the provider contribution. The host must compare the final emitted
/// metadata with its private durable-retention carrier before publication.
pub fn compile_context_pack_with_control_metadata(
    policy: ContextPackPolicyV1,
    tokenizer: &dyn ContextTokenizer,
    host_items: &[HostContextItemV1],
    lane: &AdvisoryLaneV1,
    control_refs: &BTreeMap<String, ContextRecallControlRefV1>,
    recall_trace: Option<&ContextRecallTraceV1>,
) -> Result<ContextPackV1, ContextPackError> {
    validate_control_refs(lane, control_refs)?;
    let recall_trace = prepare_context_recall_trace(lane, recall_trace)?;
    if tokenizer.tokenizer_id() != CANONICAL_CONTEXT_TOKENIZER_ID
        || tokenizer.tokenizer_revision() != CANONICAL_CONTEXT_TOKENIZER_REVISION
    {
        return Err(ContextPackError::TokenizerNotCanonical {
            expected_id: CANONICAL_CONTEXT_TOKENIZER_ID,
            expected_revision: CANONICAL_CONTEXT_TOKENIZER_REVISION,
            received_id: tokenizer.tokenizer_id().to_owned(),
            received_revision: tokenizer.tokenizer_revision().to_owned(),
        });
    }

    // Provider-controlled strings are contained before anything is measured
    // or rendered. Every later stage — identity validation, token accounting,
    // the pack hash, and the rendered text — sees only labels that cannot end
    // their own line, so no volume of hostile metadata can forge a heading, a
    // list row, or a second section.
    let mut excluded_provider_items: Vec<ExcludedProviderItemV1> = Vec::new();
    let contained_lane = contain_advisory_lane(lane, &mut excluded_provider_items)?;
    let lane = &contained_lane;

    let form = policy.render_form;
    let mut seen_identities = BTreeSet::new();
    for item in host_items {
        if !item.section.is_required() {
            return Err(ContextPackError::HostItemInAdvisorySection {
                item_id: item.item_id.clone(),
            });
        }
        validate_identity(&item.item_id, &mut seen_identities)?;
        if form == ContextPackRenderFormV1::Json && !is_json_object_member(&item.content) {
            return Err(ContextPackError::HostItemNotJsonMember {
                item_id: item.item_id.clone(),
            });
        }
    }
    if let Some(contribution) = lane.contribution() {
        for item in &contribution.items {
            validate_identity(&item.candidate_id, &mut seen_identities)?;
        }
        // Reference-only identities are ledger rows, and a ledger row that
        // repeats an identity — or repeats an inline item — cannot be
        // reconciled against the contribution it claims to describe. They go
        // through the same identity set as everything else.
        for candidate_id in &contribution.reference_only_candidate_ids {
            validate_identity(candidate_id, &mut seen_identities)?;
        }
    }

    // The pack's own framing is deterministic and is measured before any item
    // competes for the budget: a header, an identity line, and a bounded
    // receipt are agent-visible tokens exactly like content is.
    let host_framing_tokens = tokenizer.count_tokens(&host_framing_probe(form, lane));
    let lane_framing_text = lane_framing_text(form, lane, recall_trace.as_ref());
    let lane_framing_tokens = tokenizer.count_tokens(&lane_framing_text);
    let lane_fits_quota = lane_framing_tokens <= policy.advisory_token_quota;
    let framing_tokens = host_framing_tokens.saturating_add(if lane_fits_quota {
        lane_framing_tokens
    } else {
        0
    });

    let mut spent = framing_tokens;
    if spent > policy.total_token_budget {
        return Err(ContextPackError::RenderedRequiredEvidenceOverBudget {
            rendered_tokens: spent,
            total_token_budget: policy.total_token_budget,
        });
    }

    // Required host evidence first, in priority order. Nothing an advisory
    // provider returns has been measured yet, so nothing it returns can
    // affect what is admitted here.
    let mut required_sections: Vec<ContextPackSectionV1> = Vec::new();
    for kind in ContextSectionKind::all().iter().copied() {
        if !kind.is_required() {
            continue;
        }
        let mut items = Vec::new();
        let mut section_tokens = 0_u64;
        for item in host_items.iter().filter(|item| item.section == kind) {
            let tokens = tokenizer.count_tokens(&host_fragment(form, &item.content));
            let remaining = policy.total_token_budget.saturating_sub(spent);
            if tokens > remaining {
                return Err(ContextPackError::RequiredEvidenceDoesNotFit {
                    section: kind.label(),
                    item_id: item.item_id.clone(),
                    item_tokens: tokens,
                    remaining_tokens: remaining,
                    total_token_budget: policy.total_token_budget,
                });
            }
            spent = spent.saturating_add(tokens);
            section_tokens = section_tokens.saturating_add(tokens);
            items.push(ContextPackItemV1 {
                section: kind,
                item_id: item.item_id.clone(),
                tokens,
                provenance: ContextItemProvenanceV1::Host {
                    authority: item.authority.clone(),
                },
                content: item.content.clone(),
            });
        }
        if !items.is_empty() {
            required_sections.push(ContextPackSectionV1 {
                section: kind,
                required: true,
                token_quota: None,
                tokens: section_tokens,
                items,
            });
        }
    }

    // The advisory lane competes only for what required evidence left, and
    // never for more than its own quota — its framing already counted.
    let mut advisory_items: Vec<ContextPackItemV1> = Vec::new();
    let mut advisory_tokens = if lane_fits_quota {
        lane_framing_tokens
    } else {
        0
    };
    if let Some(contribution) = lane.contribution() {
        for item in &contribution.items {
            if !lane_fits_quota {
                excluded_provider_items.push(ExcludedProviderItemV1 {
                    candidate_id: item.candidate_id.clone(),
                    reason: ProviderExclusionReason::AdvisoryFramingDoesNotFit {
                        advisory_token_quota: policy.advisory_token_quota,
                        framing_tokens: lane_framing_tokens,
                    },
                });
                continue;
            }
            let provenance = ContextItemProvenanceV1::Provider {
                provider_id: contribution.provider_id.clone(),
                registration_revision: contribution.registration_revision,
                candidate_id: item.candidate_id.clone(),
                candidate_provenance: item.provenance.clone(),
                recall_control: control_refs.get(&item.candidate_id).cloned(),
                explanation: item.explanation.clone(),
            };
            let tokens = tokenizer.count_tokens(&advisory_fragment(
                form,
                &item.candidate_id,
                &item.content,
                &item.provenance,
                item.explanation.as_deref(),
                control_refs.get(&item.candidate_id),
            ));
            let quota_left = policy.advisory_token_quota.saturating_sub(advisory_tokens);
            if tokens > quota_left {
                excluded_provider_items.push(ExcludedProviderItemV1 {
                    candidate_id: item.candidate_id.clone(),
                    reason: ProviderExclusionReason::AdvisoryQuotaExhausted {
                        advisory_token_quota: policy.advisory_token_quota,
                        section_tokens_used: advisory_tokens,
                        item_tokens: tokens,
                    },
                });
                continue;
            }
            let remaining = policy.total_token_budget.saturating_sub(spent);
            if tokens > remaining {
                excluded_provider_items.push(ExcludedProviderItemV1 {
                    candidate_id: item.candidate_id.clone(),
                    reason: ProviderExclusionReason::TotalBudgetExhausted {
                        total_token_budget: policy.total_token_budget,
                        remaining_tokens: remaining,
                        item_tokens: tokens,
                    },
                });
                continue;
            }
            spent = spent.saturating_add(tokens);
            advisory_tokens = advisory_tokens.saturating_add(tokens);
            advisory_items.push(ContextPackItemV1 {
                section: ContextSectionKind::ProviderMemory,
                item_id: item.candidate_id.clone(),
                tokens,
                provenance,
                content: item.content.clone(),
            });
        }
        for candidate_id in &contribution.reference_only_candidate_ids {
            excluded_provider_items.push(ExcludedProviderItemV1 {
                candidate_id: candidate_id.clone(),
                reason: ProviderExclusionReason::ContentNotInline,
            });
        }
    }

    // Per-item accounting is a sum of measured fragments; the rendered text is
    // one string, and BPE is not additive across fragment boundaries. So the
    // finished text is measured once more and advisory items are evicted from
    // the tail until it fits both budgets. Required evidence is never evicted.
    loop {
        let compiled = finish_pack(
            &policy,
            tokenizer,
            host_items,
            lane,
            recall_trace.as_ref(),
            lane_fits_quota,
            &required_sections,
            &advisory_items,
            &excluded_provider_items,
            framing_tokens,
            advisory_tokens,
            spent,
        );
        let over_total = compiled.rendered_tokens > policy.total_token_budget;
        let over_quota = compiled.advisory_rendered_tokens > policy.advisory_token_quota;
        if !over_total && !over_quota {
            return Ok(compiled.pack);
        }
        let Some(evicted) = advisory_items.pop() else {
            if over_total {
                return Err(ContextPackError::RenderedRequiredEvidenceOverBudget {
                    rendered_tokens: compiled.rendered_tokens,
                    total_token_budget: policy.total_token_budget,
                });
            }
            // The lane framing alone measures above the quota once rendered:
            // withhold the whole lane rather than render it unbudgeted.
            return Ok(finish_pack(
                &policy,
                tokenizer,
                host_items,
                lane,
                recall_trace.as_ref(),
                false,
                &required_sections,
                &[],
                &excluded_provider_items,
                host_framing_tokens,
                0,
                spent.saturating_sub(lane_framing_tokens),
            )
            .pack);
        };
        let (token_budget, rendered_tokens) = if over_total {
            (policy.total_token_budget, compiled.rendered_tokens)
        } else {
            (
                policy.advisory_token_quota,
                compiled.advisory_rendered_tokens,
            )
        };
        spent = spent.saturating_sub(evicted.tokens);
        advisory_tokens = advisory_tokens.saturating_sub(evicted.tokens);
        excluded_provider_items.push(ExcludedProviderItemV1 {
            candidate_id: evicted.item_id.clone(),
            reason: ProviderExclusionReason::RenderedPackOverBudget {
                token_budget,
                rendered_tokens,
            },
        });
    }
}

/// One finished candidate pack plus the two measurements the budget loop
/// checks it against.
struct FinishedPack {
    pack: ContextPackV1,
    rendered_tokens: u64,
    advisory_rendered_tokens: u64,
}

/// Assembles, hashes, renders, and measures one candidate pack.
#[allow(clippy::too_many_arguments)]
fn finish_pack(
    policy: &ContextPackPolicyV1,
    tokenizer: &dyn ContextTokenizer,
    host_items: &[HostContextItemV1],
    lane: &AdvisoryLaneV1,
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
    lane_rendered: bool,
    required_sections: &[ContextPackSectionV1],
    advisory_items: &[ContextPackItemV1],
    excluded_provider_items: &[ExcludedProviderItemV1],
    framing_tokens: u64,
    advisory_tokens: u64,
    total_tokens: u64,
) -> FinishedPack {
    let mut sections = required_sections.to_vec();
    if !advisory_items.is_empty() {
        sections.push(ContextPackSectionV1 {
            section: ContextSectionKind::ProviderMemory,
            required: false,
            token_quota: Some(policy.advisory_token_quota),
            tokens: advisory_tokens,
            items: advisory_items.to_vec(),
        });
    }
    let recall_trace = if lane_rendered { recall_trace } else { None };
    let pack_hash = pack_hash(policy, tokenizer, &sections, recall_trace);
    let receipt = ContextPackReceiptV1 {
        state: "compiled".to_owned(),
        pack_hash: pack_hash.clone(),
        pack_policy_id: policy.policy_id.to_owned(),
        pack_policy_revision: policy.policy_revision,
        tokenizer_id: tokenizer.tokenizer_id().to_owned(),
        tokenizer_revision: tokenizer.tokenizer_revision().to_owned(),
        render_form: policy.render_form,
        total_token_budget: policy.total_token_budget,
        advisory_token_quota: policy.advisory_token_quota,
        framing_tokens,
        total_tokens,
        advisory_tokens,
        excluded_advisory_quota_exhausted: count_exclusions(excluded_provider_items, |reason| {
            matches!(
                reason,
                ProviderExclusionReason::AdvisoryQuotaExhausted { .. }
            )
        }),
        excluded_total_budget_exhausted: count_exclusions(excluded_provider_items, |reason| {
            matches!(reason, ProviderExclusionReason::TotalBudgetExhausted { .. })
        }),
        excluded_content_not_inline: count_exclusions(excluded_provider_items, |reason| {
            matches!(reason, ProviderExclusionReason::ContentNotInline)
        }),
        excluded_advisory_framing_does_not_fit: count_exclusions(
            excluded_provider_items,
            |reason| {
                matches!(
                    reason,
                    ProviderExclusionReason::AdvisoryFramingDoesNotFit { .. }
                )
            },
        ),
        excluded_metadata_not_contained: count_exclusions(excluded_provider_items, |reason| {
            matches!(reason, ProviderExclusionReason::MetadataNotContained { .. })
        }),
        excluded_rendered_pack_over_budget: count_exclusions(excluded_provider_items, |reason| {
            matches!(
                reason,
                ProviderExclusionReason::RenderedPackOverBudget { .. }
            )
        }),
    };
    let rendered = render_pack(
        policy.render_form,
        host_items,
        lane,
        recall_trace,
        lane_rendered,
        advisory_items,
        &receipt,
    );
    let rendered_tokens = tokenizer.count_tokens(&rendered.text);
    let advisory_rendered_tokens = tokenizer.count_tokens(&rendered.advisory_block);
    FinishedPack {
        pack: ContextPackV1 {
            pack_policy_id: policy.policy_id.to_owned(),
            pack_policy_revision: policy.policy_revision,
            tokenizer_id: tokenizer.tokenizer_id().to_owned(),
            tokenizer_revision: tokenizer.tokenizer_revision().to_owned(),
            render_form: policy.render_form,
            total_token_budget: policy.total_token_budget,
            advisory_token_quota: policy.advisory_token_quota,
            recall_trace: recall_trace.map(|value| value.metadata.clone()),
            sections,
            excluded_provider_items: excluded_provider_items.to_vec(),
            framing_tokens,
            total_tokens,
            rendered: rendered.text,
            rendered_tokens,
            receipt,
            pack_hash,
        },
        rendered_tokens,
        advisory_rendered_tokens,
    }
}

/// Counts exclusion-ledger rows matching one typed reason.
fn count_exclusions(
    excluded: &[ExcludedProviderItemV1],
    matching: impl Fn(&ProviderExclusionReason) -> bool,
) -> u64 {
    u64::try_from(excluded.iter().filter(|row| matching(&row.reason)).count()).unwrap_or(u64::MAX)
}

/// Whether one character would let a provider-controlled string escape the
/// line it is rendered on, or make the rendered line read differently from
/// the bytes.
///
/// `char::is_control` already covers the C0/C1 ranges, `\n` and `\r`
/// included; the extra arms are the Unicode line separators and the
/// zero-width, joiner, and direction-override characters, which are not
/// classified as control characters but are exactly as dangerous here.
const fn is_uncontained_character(character: char) -> bool {
    character.is_control()
        || matches!(character,
            '\u{2028}'
            | '\u{2029}'
            | '\u{ad}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}')
}

/// Whether one provider-controlled string may be interpolated into the
/// rendered pack.
///
/// This is the renderer's precondition, enforced at the renderer's own
/// boundary rather than assumed from whatever hardened the text upstream. A
/// compiler that trusts its caller to have contained provider bytes is one
/// refactor away from rendering raw ones.
fn is_contained_provider_label(text: &str) -> bool {
    !text.chars().any(is_uncontained_character)
}

/// Bounds opaque host-prepared locators and their confirmed source carriers.
/// The existing durable reader remains the semantic locator parser and authority.
fn validate_control_refs(
    lane: &AdvisoryLaneV1,
    refs: &BTreeMap<String, ContextRecallControlRefV1>,
) -> Result<(), ContextPackError> {
    let invalid = || ContextPackError::ProviderAttributionInvalid {
        field: "recall_control_refs",
    };
    if refs.len() > 8 {
        return Err(invalid());
    }
    for (candidate_id, reference) in refs {
        if reference.trace_ref.is_empty()
            || reference.trace_ref.len() > 145
            || reference.item_ref.is_empty()
            || reference.item_ref.len() > 35
            || !is_contained_provider_label(&reference.trace_ref)
            || !is_contained_provider_label(&reference.item_ref)
        {
            return Err(invalid());
        }
        let item = lane
            .contribution()
            .and_then(|contribution| {
                contribution
                    .items
                    .iter()
                    .find(|item| &item.candidate_id == candidate_id)
            })
            .ok_or_else(invalid)?;
        let Some(crate::recall_provenance_hydration::HostEvidenceRefV1::CanonicalObservations {
            sources,
        }) = item.provenance.canonical_observation_evidence()
        else {
            return Err(invalid());
        };
        if sources.is_empty() || sources.len() > 64 {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Validate the correlation's bounded render shape; durable identity belongs to
/// the host's retention check after compilation.
fn prepare_context_recall_trace<'a>(
    lane: &AdvisoryLaneV1,
    metadata: Option<&'a ContextRecallTraceV1>,
) -> Result<Option<PreparedContextRecallTraceV1<'a>>, ContextPackError> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let invalid = || ContextPackError::ProviderAttributionInvalid {
        field: "recall_trace",
    };
    if lane.contribution().is_none()
        || metadata.request_id.is_empty()
        || metadata.request_id.len() > 1_024
        || metadata.request_id.trim() != metadata.request_id
        || !is_contained_provider_label(&metadata.request_id)
    {
        return Err(invalid());
    }
    let Some((scope, trace)) = metadata
        .trace_ref
        .strip_prefix("recall-trace-v1:")
        .and_then(|body| body.split_once(':'))
    else {
        return Err(invalid());
    };
    for digest in [scope, trace] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
    }
    let json = serde_json::to_string(metadata).map_err(|_| invalid())?;
    Ok(Some(PreparedContextRecallTraceV1 { metadata, json }))
}

/// The first provider-controlled string of one item that fails containment.
///
/// Fields are checked in the order they are rendered, so the reported field
/// is the first one an attacker would have used.
fn uncontained_provider_field(item: &ProviderContextItemV1) -> Option<ProviderMetadataFieldV1> {
    if !is_contained_provider_label(&item.candidate_id) {
        return Some(ProviderMetadataFieldV1::CandidateId);
    }
    if !is_contained_provider_label(&item.content) {
        return Some(ProviderMetadataFieldV1::Content);
    }
    // Both encodings are checked: `markdown_label` is what markdown renders and
    // `label` is what the pack hash absorbs, and they interpolate the same
    // provider strings through different framing.
    if !is_contained_provider_label(&item.provenance.markdown_label(None))
        || !is_contained_provider_label(&item.provenance.label())
    {
        return Some(ProviderMetadataFieldV1::Provenance);
    }
    if item
        .explanation
        .as_deref()
        .is_some_and(|explanation| !is_contained_provider_label(explanation))
    {
        return Some(ProviderMetadataFieldV1::Explanation);
    }
    None
}

/// The host-minted stand-in identity an uncontained item is recorded under.
///
/// The exclusion ledger is agent- and operator-visible, so recording the
/// provider's own uncontained identity there would reintroduce exactly the
/// bytes the exclusion exists to keep out. The digest still binds the row to
/// the refused identity.
///
/// It is public because reconciliation is only possible if a later stage can
/// re-derive the stand-in: an explain trace that matched exclusion rows by
/// candidate identity alone would silently lose every containment refusal.
#[must_use]
pub fn uncontained_item_identity(candidate_id: &str) -> String {
    let digest = hex::encode(Sha256::digest(candidate_id.as_bytes()));
    let short = digest.get(..16).unwrap_or(digest.as_str());
    format!("advisory.uncontained.{short}")
}

/// Filters one lane down to the items whose every provider-controlled string
/// is contained, recording each refusal as a typed exclusion.
///
/// Attribution is different from item metadata: `provider_id` and the
/// degradation label are host-registered, so an uncontained one is a host
/// defect and refuses the whole pack rather than excluding an item.
///
/// # Errors
///
/// Returns [`ContextPackError::ProviderAttributionInvalid`] when the lane's
/// own attribution is not a contained single-line label.
fn contain_advisory_lane(
    lane: &AdvisoryLaneV1,
    excluded: &mut Vec<ExcludedProviderItemV1>,
) -> Result<AdvisoryLaneV1, ContextPackError> {
    let contribution = match lane {
        AdvisoryLaneV1::Absent => return Ok(AdvisoryLaneV1::Absent),
        AdvisoryLaneV1::Notice {
            provider_id,
            registration_revision,
            notice,
        } => {
            if !is_contained_provider_label(provider_id) {
                return Err(ContextPackError::ProviderAttributionInvalid {
                    field: "provider_id",
                });
            }
            return Ok(AdvisoryLaneV1::Notice {
                provider_id: provider_id.clone(),
                registration_revision: *registration_revision,
                notice: notice.clone(),
            });
        }
        AdvisoryLaneV1::Contribution(contribution) => contribution,
    };
    if !is_contained_provider_label(&contribution.provider_id) {
        return Err(ContextPackError::ProviderAttributionInvalid {
            field: "provider_id",
        });
    }
    if contribution
        .degradation
        .as_deref()
        .is_some_and(|degradation| !is_contained_provider_label(degradation))
    {
        return Err(ContextPackError::ProviderAttributionInvalid {
            field: "degradation",
        });
    }
    let mut items = Vec::with_capacity(contribution.items.len());
    for item in &contribution.items {
        match uncontained_provider_field(item) {
            None => items.push(item.clone()),
            Some(field) => excluded.push(ExcludedProviderItemV1 {
                candidate_id: uncontained_item_identity(&item.candidate_id),
                reason: ProviderExclusionReason::MetadataNotContained { field },
            }),
        }
    }
    let mut reference_only_candidate_ids =
        Vec::with_capacity(contribution.reference_only_candidate_ids.len());
    for candidate_id in &contribution.reference_only_candidate_ids {
        if is_contained_provider_label(candidate_id) {
            reference_only_candidate_ids.push(candidate_id.clone());
        } else {
            excluded.push(ExcludedProviderItemV1 {
                candidate_id: uncontained_item_identity(candidate_id),
                reason: ProviderExclusionReason::MetadataNotContained {
                    field: ProviderMetadataFieldV1::CandidateId,
                },
            });
        }
    }
    Ok(AdvisoryLaneV1::Contribution(ProviderContributionV1 {
        provider_id: contribution.provider_id.clone(),
        registration_revision: contribution.registration_revision,
        degradation: contribution.degradation.clone(),
        items,
        reference_only_candidate_ids,
    }))
}

/// Rejects an item identity that cannot name a row in the pack receipt.
fn validate_identity(item_id: &str, seen: &mut BTreeSet<String>) -> Result<(), ContextPackError> {
    if item_id.is_empty() || item_id.trim() != item_id || !is_contained_provider_label(item_id) {
        return Err(ContextPackError::ItemIdentityInvalid);
    }
    if !seen.insert(item_id.to_owned()) {
        return Err(ContextPackError::DuplicateItemIdentity {
            item_id: item_id.to_owned(),
        });
    }
    Ok(())
}

/// Whether `content` is a well-formed `"key": value` member of a JSON object.
fn is_json_object_member(content: &str) -> bool {
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&format!("{{{content}}}"))
        .is_ok_and(|members| members.len() == 1)
}

// ---------------------------------------------------------------------------
// Rendering: the exact agent-visible text the budget is measured against
// ---------------------------------------------------------------------------

/// Markdown heading that opens the advisory lane.
const ADVISORY_MARKDOWN_HEADING: &str = "\n### Provider memory (advisory)\n";

/// Line rendered when the advisory lane answered but admitted nothing.
const ADVISORY_MARKDOWN_EMPTY_LINE: &str = "No admitted advisory candidates.\n";

/// JSON key the advisory lane is rendered under.
pub const ADVISORY_CONTEXT_PACK_JSON_KEY: &str = "advisory_provider_memory";

/// The rendered pack and, separately, the advisory block the quota bounds.
struct RenderedPack {
    text: String,
    advisory_block: String,
}

/// The fragment one host item contributes to the rendered pack.
fn host_fragment(form: ContextPackRenderFormV1, content: &str) -> String {
    match form {
        ContextPackRenderFormV1::Markdown => content.to_owned(),
        ContextPackRenderFormV1::Json => format!("{content},"),
    }
}

/// The fragment one advisory item contributes to the rendered pack.
fn advisory_fragment(
    form: ContextPackRenderFormV1,
    candidate_id: &str,
    content: &str,
    provenance: &ProviderItemProvenanceV1,
    explanation: Option<&str>,
    recall: Option<&ContextRecallControlRefV1>,
) -> String {
    match form {
        ContextPackRenderFormV1::Markdown => {
            let mut fragment = format!(
                "- {candidate_id} — {content} [{}]\n",
                provenance.markdown_label(recall)
            );
            if let Some(explanation) = explanation {
                let _ = writeln!(fragment, "  - {explanation}");
            }
            fragment
        }
        ContextPackRenderFormV1::Json => {
            let value = json_candidate(candidate_id, content, provenance, explanation, recall);
            format!("{},", serde_json::to_string(&value).unwrap_or_default())
        }
    }
}

/// One advisory candidate as the JSON form renders it.
fn json_candidate(
    candidate_id: &str,
    content: &str,
    provenance: &ProviderItemProvenanceV1,
    explanation: Option<&str>,
    recall: Option<&ContextRecallControlRefV1>,
) -> serde_json::Value {
    let mut candidate = serde_json::json!({
        "candidate_id": candidate_id,
        "content": content,
        "provenance": provenance.human_label(),
        "explanation": explanation,
    });
    if let Some(evidence) = provenance.canonical_observation_evidence_value(recall) {
        candidate["provenance_evidence"] = evidence;
    }
    candidate
}

/// The advisory lane's own framing: everything the lane renders that is not a
/// candidate and not the receipt. It is charged to the advisory quota.
fn lane_framing_text(
    form: ContextPackRenderFormV1,
    lane: &AdvisoryLaneV1,
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
) -> String {
    match (form, lane) {
        (_, AdvisoryLaneV1::Absent) => String::new(),
        (ContextPackRenderFormV1::Markdown, lane) => {
            let mut framing = lane_head_markdown(lane, recall_trace);
            if lane.contribution().is_some() {
                framing.push_str(ADVISORY_MARKDOWN_EMPTY_LINE);
            }
            framing
        }
        (ContextPackRenderFormV1::Json, lane) => {
            let scaffold = json_lane_head(lane, recall_trace);
            format!(",\"{ADVISORY_CONTEXT_PACK_JSON_KEY}\":{{{scaffold}\"candidates\":[]}}",)
        }
    }
}

/// The JSON lane's leading members, up to but excluding `candidates`.
fn json_lane_head(
    lane: &AdvisoryLaneV1,
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
) -> String {
    let mut head = match lane {
        AdvisoryLaneV1::Absent => String::new(),
        AdvisoryLaneV1::Notice {
            provider_id,
            registration_revision,
            notice,
        } => {
            let provider = serde_json::to_string(provider_id).unwrap_or_else(|_| "\"\"".to_owned());
            let reason = serde_json::to_string(notice).unwrap_or_else(|_| "\"\"".to_owned());
            format!(
                "\"state\":\"unavailable\",\"provider_id\":{provider},\"registration_revision\":{registration_revision},\"reason\":{reason},"
            )
        }
        AdvisoryLaneV1::Contribution(contribution) => {
            let provider = serde_json::to_string(&contribution.provider_id)
                .unwrap_or_else(|_| "\"\"".to_owned());
            let degradation = serde_json::to_string(&contribution.degradation)
                .unwrap_or_else(|_| "null".to_owned());
            format!(
                "\"state\":\"answered\",\"provider_id\":{provider},\"registration_revision\":{},\
                 \"degradation\":{degradation},",
                contribution.registration_revision
            )
        }
    };
    if let Some(trace) = recall_trace {
        let _ = write!(head, "\"recall_trace\":{},", trace.json);
    }
    head
}

/// Everything the pack renders that is neither host content nor advisory
/// lane: the receipt, and in the JSON form the object braces. Reserved with
/// worst-case-width numbers so the reservation does not depend on the
/// accounting it is reserved for.
fn host_framing_probe(form: ContextPackRenderFormV1, lane: &AdvisoryLaneV1) -> String {
    if matches!(lane, AdvisoryLaneV1::Absent) {
        return match form {
            ContextPackRenderFormV1::Markdown => String::new(),
            ContextPackRenderFormV1::Json => "{}".to_owned(),
        };
    }
    let probe = ContextPackReceiptV1 {
        state: "compiled".to_owned(),
        pack_hash: HASH_WIDTH_PROBE.to_owned(),
        pack_policy_id: HOST_CONTEXT_PACK_POLICY_ID.to_owned(),
        pack_policy_revision: u64::MAX,
        tokenizer_id: CANONICAL_CONTEXT_TOKENIZER_ID.to_owned(),
        tokenizer_revision: CANONICAL_CONTEXT_TOKENIZER_REVISION.to_owned(),
        render_form: form,
        total_token_budget: u64::MAX,
        advisory_token_quota: u64::MAX,
        framing_tokens: u64::MAX,
        total_tokens: u64::MAX,
        advisory_tokens: u64::MAX,
        excluded_advisory_quota_exhausted: u64::MAX,
        excluded_total_budget_exhausted: u64::MAX,
        excluded_content_not_inline: u64::MAX,
        excluded_advisory_framing_does_not_fit: u64::MAX,
        excluded_rendered_pack_over_budget: u64::MAX,
        excluded_metadata_not_contained: u64::MAX,
    };
    match form {
        ContextPackRenderFormV1::Markdown => receipt_markdown_line(&probe),
        ContextPackRenderFormV1::Json => {
            format!(
                "{{,\"context_pack\":{}}}",
                serde_json::to_string(&probe).unwrap_or_default()
            )
        }
    }
}

/// The receipt as one bounded markdown line.
fn receipt_markdown_line(receipt: &ContextPackReceiptV1) -> String {
    format!(
        "Context pack {} — tokenizer {}/{}, form {}, {} of {} tokens (framing {}), advisory {} of \
         {}, excluded {} quota / {} budget / {} not-inline / {} lane-framing / {} rendered / {} \
         uncontained.\n",
        receipt.pack_hash,
        receipt.tokenizer_id,
        receipt.tokenizer_revision,
        receipt.render_form.label(),
        receipt.total_tokens,
        receipt.total_token_budget,
        receipt.framing_tokens,
        receipt.advisory_tokens,
        receipt.advisory_token_quota,
        receipt.excluded_advisory_quota_exhausted,
        receipt.excluded_total_budget_exhausted,
        receipt.excluded_content_not_inline,
        receipt.excluded_advisory_framing_does_not_fit,
        receipt.excluded_rendered_pack_over_budget,
        receipt.excluded_metadata_not_contained,
    )
}

/// Renders one pack to the exact text the agent receives.
fn render_pack(
    form: ContextPackRenderFormV1,
    host_items: &[HostContextItemV1],
    lane: &AdvisoryLaneV1,
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
    lane_rendered: bool,
    advisory_items: &[ContextPackItemV1],
    receipt: &ContextPackReceiptV1,
) -> RenderedPack {
    match form {
        ContextPackRenderFormV1::Markdown => {
            // Host evidence is rendered in the order it was supplied, so a
            // host answer split into attributed items reassembles exactly.
            let mut text = String::new();
            for item in host_items {
                text.push_str(&item.content);
            }
            let mut advisory_block = String::new();
            if lane_rendered && !matches!(lane, AdvisoryLaneV1::Absent) {
                advisory_block.push_str(&lane_head_markdown(lane, recall_trace));
                if lane.contribution().is_some() {
                    if advisory_items.is_empty() {
                        advisory_block.push_str(ADVISORY_MARKDOWN_EMPTY_LINE);
                    } else {
                        for item in advisory_items {
                            advisory_block.push_str(&markdown_item(item));
                        }
                    }
                }
                text.push_str(&advisory_block);
                text.push_str(&receipt_markdown_line(receipt));
            }
            RenderedPack {
                text,
                advisory_block,
            }
        }
        ContextPackRenderFormV1::Json => {
            let mut members: Vec<String> =
                host_items.iter().map(|item| item.content.clone()).collect();
            let mut advisory_block = String::new();
            if lane_rendered && !matches!(lane, AdvisoryLaneV1::Absent) {
                let candidates = advisory_items
                    .iter()
                    .map(json_item_string)
                    .collect::<Vec<_>>()
                    .join(",");
                advisory_block = format!(
                    ",\"{ADVISORY_CONTEXT_PACK_JSON_KEY}\":{{{}\"candidates\":[{candidates}]}}",
                    json_lane_head(lane, recall_trace)
                );
                members.push(format!(
                    "\"{ADVISORY_CONTEXT_PACK_JSON_KEY}\":{{{}\"candidates\":[{candidates}],\
                     \"context_pack\":{}}}",
                    json_lane_head(lane, recall_trace),
                    serde_json::to_string(receipt).unwrap_or_default()
                ));
            }
            RenderedPack {
                text: format!("{{{}}}", members.join(",")),
                advisory_block,
            }
        }
    }
}

/// The advisory lane's markdown head: heading plus identity or notice.
fn lane_head_markdown(
    lane: &AdvisoryLaneV1,
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
) -> String {
    let mut head = match lane {
        AdvisoryLaneV1::Absent => String::new(),
        AdvisoryLaneV1::Notice {
            provider_id,
            registration_revision,
            notice,
        } => format!(
            "{ADVISORY_MARKDOWN_HEADING}Provider {provider_id} (registration revision \
             {registration_revision}), unavailable: {notice}\n"
        ),
        AdvisoryLaneV1::Contribution(contribution) => {
            let mut head = format!(
                "{ADVISORY_MARKDOWN_HEADING}Provider {} (registration revision {})",
                contribution.provider_id, contribution.registration_revision
            );
            if let Some(degradation) = &contribution.degradation {
                let _ = write!(head, ", degraded: {degradation}");
            }
            head.push('\n');
            head
        }
    };
    if let Some(trace) = recall_trace {
        let _ = writeln!(head, "recall_trace={}", trace.json);
    }
    head
}

/// One admitted advisory item as the markdown form renders it.
fn markdown_item(item: &ContextPackItemV1) -> String {
    let (provenance, explanation) = match &item.provenance {
        ContextItemProvenanceV1::Provider {
            candidate_provenance,
            recall_control,
            explanation,
            ..
        } => (
            candidate_provenance.markdown_label(recall_control.as_ref()),
            explanation.clone(),
        ),
        ContextItemProvenanceV1::Host { authority } => (format!("host {authority}"), None),
    };
    let mut rendered = format!("- {} — {} [{provenance}]\n", item.item_id, item.content);
    if let Some(explanation) = explanation {
        let _ = writeln!(rendered, "  - {explanation}");
    }
    rendered
}

/// One admitted advisory item as the JSON form renders it.
fn json_item_string(item: &ContextPackItemV1) -> String {
    let (provenance, explanation, recall) = match &item.provenance {
        ContextItemProvenanceV1::Provider {
            candidate_provenance,
            recall_control,
            explanation,
            ..
        } => (
            candidate_provenance.clone(),
            explanation.clone(),
            recall_control.clone(),
        ),
        ContextItemProvenanceV1::Host { authority } => (
            ProviderItemProvenanceV1::Redacted {
                reason: format!("host {authority}"),
            },
            None,
            None,
        ),
    };
    let value = json_candidate(
        &item.item_id,
        &item.content,
        &provenance,
        explanation.as_deref(),
        recall.as_ref(),
    );
    serde_json::to_string(&value).unwrap_or_default()
}

/// Deterministic pack receipt.
///
/// Every field is absorbed length-prefixed, so no separator can be forged out
/// of content and two different packs can never encode to the same byte
/// stream. Content is bound by its own digest rather than inline, which keeps
/// the receipt bounded while still changing whenever any admitted byte
/// changes.
fn pack_hash(
    policy: &ContextPackPolicyV1,
    tokenizer: &dyn ContextTokenizer,
    sections: &[ContextPackSectionV1],
    recall_trace: Option<&PreparedContextRecallTraceV1<'_>>,
) -> String {
    let mut hasher = Sha256::new();
    absorb(&mut hasher, policy.policy_id.as_bytes());
    absorb(&mut hasher, &policy.policy_revision.to_be_bytes());
    absorb(&mut hasher, tokenizer.tokenizer_id().as_bytes());
    absorb(&mut hasher, tokenizer.tokenizer_revision().as_bytes());
    absorb(&mut hasher, policy.render_form.label().as_bytes());
    absorb(&mut hasher, &policy.total_token_budget.to_be_bytes());
    absorb(&mut hasher, &policy.advisory_token_quota.to_be_bytes());
    if let Some(trace) = recall_trace {
        absorb(&mut hasher, b"recall_trace");
        absorb(&mut hasher, trace.json.as_bytes());
    }
    for section in sections {
        absorb(&mut hasher, section.section.label().as_bytes());
        absorb(&mut hasher, &section.tokens.to_be_bytes());
        for item in &section.items {
            absorb(&mut hasher, item.item_id.as_bytes());
            absorb(&mut hasher, &item.tokens.to_be_bytes());
            absorb(&mut hasher, item.provenance.label().as_bytes());
            absorb(&mut hasher, &Sha256::digest(item.content.as_bytes()));
        }
    }
    hex::encode(hasher.finalize())
}

/// Absorbs one length-prefixed field.
fn absorb(hasher: &mut Sha256, field: &[u8]) {
    let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(field);
}
