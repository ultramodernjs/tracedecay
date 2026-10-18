//! Behavioral tests for the token-budgeted context pack: required host
//! evidence survives any volume of provider candidates, the budget is
//! measured with the canonical `o200k_base` tokenizer and not with a
//! byte-count stand-in, every provider item is accounted for, provenance
//! survives compilation, and the pack receipt is deterministic.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod recall_fixture;

use std::collections::BTreeSet;
use std::error::Error;

use recall_fixture::*;
use tracedecay_memory_provider_registry::{
    AdmittedRecallCandidate, AdvisoryLaneV1, CANONICAL_CONTEXT_TOKENIZER_ID,
    CANONICAL_CONTEXT_TOKENIZER_REVISION, ContextItemProvenanceV1, ContextPackError,
    ContextPackPolicyError, ContextPackPolicyV1, ContextPackRenderFormV1, ContextPackV1,
    ContextSectionKind, ContextTokenizer, HostContextItemV1, O200kBaseContextTokenizer,
    ProviderContextItemV1, ProviderContributionV1, ProviderExclusionReason,
    ProviderItemProvenanceV1, RecallCandidateV1, RecallSelectionError, RecallSelectionPolicyV1,
    RecallSelectionV1, admit_recall_candidates, compile_context_pack,
    normalize_admitted_candidates, select_recall_candidates,
};

/// The markdown render form, used by every test that is not specifically
/// about the JSON form.
const MARKDOWN: ContextPackRenderFormV1 = ContextPackRenderFormV1::Markdown;

/// A pack with no advisory lane at all.
const NO_LANE: AdvisoryLaneV1 = AdvisoryLaneV1::Absent;

/// The canonical tokenizer, used by every test that is not specifically
/// about refusing a different one.
const CANONICAL: O200kBaseContextTokenizer = O200kBaseContextTokenizer;

/// A counter that is not the canonical tokenizer: it reports a plausible
/// identity and returns a byte-quarter estimate. Mounting it must be refused,
/// not silently accepted.
struct ByteQuarterCounter;

impl ContextTokenizer for ByteQuarterCounter {
    fn tokenizer_id(&self) -> &str {
        "tracedecay.chars_div4"
    }

    fn tokenizer_revision(&self) -> &str {
        "v1"
    }

    fn count_tokens(&self, text: &str) -> u64 {
        (text.len() as u64).div_ceil(4)
    }
}

/// A counter that claims the canonical identity but a different revision. A
/// revision drift changes counts, so it must be refused exactly like a
/// different tokenizer.
struct WrongRevisionCounter;

impl ContextTokenizer for WrongRevisionCounter {
    fn tokenizer_id(&self) -> &str {
        CANONICAL_CONTEXT_TOKENIZER_ID
    }

    fn tokenizer_revision(&self) -> &str {
        "tiktoken-rs-0.99"
    }

    fn count_tokens(&self, text: &str) -> u64 {
        text.len() as u64
    }
}

fn host_item(
    section: ContextSectionKind,
    item_id: &str,
    authority: &str,
    content: &str,
) -> HostContextItemV1 {
    HostContextItemV1 {
        section,
        item_id: item_id.to_owned(),
        authority: authority.to_owned(),
        content: content.to_owned(),
    }
}

fn provider_item(candidate_id: &str, content: &str) -> ProviderContextItemV1 {
    ProviderContextItemV1 {
        candidate_id: candidate_id.to_owned(),
        content: content.to_owned(),
        provenance: ProviderItemProvenanceV1::Available {
            source: format!("memory:{candidate_id}"),
        },
        explanation: None,
    }
}

fn contribution(items: Vec<ProviderContextItemV1>) -> ProviderContributionV1 {
    ProviderContributionV1 {
        provider_id: "provider.native".to_owned(),
        registration_revision: 7,
        degradation: None,
        items,
        reference_only_candidate_ids: Vec::new(),
    }
}

/// One advisory lane carrying `contribution`.
fn lane(contribution: ProviderContributionV1) -> AdvisoryLaneV1 {
    AdvisoryLaneV1::Contribution(contribution)
}

/// The token cost the lane's own framing adds under `policy`, measured by
/// compiling the same lane with no advisory items at all.
fn lane_framing_tokens(
    policy: ContextPackPolicyV1,
    contribution: &ProviderContributionV1,
) -> Result<u64, Box<dyn Error>> {
    let empty = ProviderContributionV1 {
        items: Vec::new(),
        reference_only_candidate_ids: Vec::new(),
        ..contribution.clone()
    };
    Ok(compile_context_pack(policy, &CANONICAL, &[], &lane(empty))?.advisory_tokens())
}

/// The four required host-evidence items every crowding-out test carries.
fn required_evidence() -> Vec<HostContextItemV1> {
    vec![
        host_item(
            ContextSectionKind::CodeTruth,
            "code.fn_resolve_scope",
            "tracedecay.code_index",
            "fn resolve_scope(root: &Path) -> Result<ResolvedScope> { /* canonical code truth */ }",
        ),
        host_item(
            ContextSectionKind::SafetyEvidence,
            "safety.unwrap_sites",
            "tracedecay.audit_safety",
            "resolve_scope has two panic sites reachable from the daemon composition root",
        ),
        host_item(
            ContextSectionKind::SessionEvidence,
            "session.prior_decision",
            "tracedecay.sessions",
            "the prior session decided scope resolution stays in the daemon, not the CLI",
        ),
        host_item(
            ContextSectionKind::NativeFacts,
            "native.fact_17",
            "tracedecay.native",
            "accepted fact: exact scope identity is authoritative for recall admission",
        ),
    ]
}

/// A provider contribution large enough to exhaust any advisory quota.
fn provider_flood(items: usize) -> ProviderContributionV1 {
    contribution(
        (0..items)
            .map(|index| {
                provider_item(
                    &format!("candidate-{index:03}"),
                    &format!(
                        "advisory recollection {index} about scope resolution that repeats the \
                         same point at length so it consumes real advisory budget rather than a \
                         token or two"
                    ),
                )
            })
            .collect(),
    )
}

/// Required host evidence is compiled before one advisory token is spent, so
/// no volume of provider candidates can displace, truncate, or reorder it.
///
/// Real defect this catches: an advisory lane compiled first, or compiled
/// into the same undifferentiated budget, so a chatty provider silently
/// pushes code truth or safety evidence out of the pack.
#[test]
fn provider_volume_cannot_evict_required_host_evidence() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(2_000, 64, MARKDOWN)?;
    let evidence = required_evidence();

    let host_only = compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE)?;
    let flooded = compile_context_pack(policy, &CANONICAL, &evidence, &lane(provider_flood(400)))?;

    for section in [
        ContextSectionKind::CodeTruth,
        ContextSectionKind::SafetyEvidence,
        ContextSectionKind::SessionEvidence,
        ContextSectionKind::NativeFacts,
    ] {
        let alone = host_only.section(section).expect("required section alone");
        let under_flood = flooded.section(section).expect("required section flooded");
        assert_eq!(
            alone,
            under_flood,
            "{} evidence changed when 400 advisory candidates arrived",
            section.label()
        );
        assert!(alone.required, "{} must be required", section.label());
        assert!(
            alone.token_quota.is_none(),
            "required sections carry no evictable quota"
        );
    }

    assert!(
        flooded.advisory_tokens() <= policy.advisory_token_quota(),
        "advisory section spent {} tokens against a {} quota",
        flooded.advisory_tokens(),
        policy.advisory_token_quota()
    );
    assert!(
        flooded.total_tokens <= policy.total_token_budget(),
        "pack spent {} tokens against a {} budget",
        flooded.total_tokens,
        policy.total_token_budget()
    );

    // The flood is accounted for rather than silently discarded.
    let admitted_advisory = flooded
        .section(ContextSectionKind::ProviderMemory)
        .map_or(0, |section| section.items.len());
    assert_eq!(
        admitted_advisory + flooded.excluded_provider_items.len(),
        400,
        "every advisory candidate must be admitted or recorded as excluded"
    );
    assert!(
        (1..400).contains(&admitted_advisory),
        "the quota must admit some advisory items and exclude the rest, admitted {admitted_advisory}"
    );
    assert!(
        flooded
            .excluded_provider_items
            .iter()
            .all(|excluded| matches!(
                excluded.reason,
                ProviderExclusionReason::AdvisoryQuotaExhausted { .. }
            )),
        "excluded advisory items must name the quota that bounded them"
    );
    Ok(())
}

/// Ordering of host items in the input never changes section priority: code
/// truth is compiled first even when it is offered last.
///
/// Real defect this catches: sections emitted in caller order, so an
/// integration that appends its safety evidence first would silently demote
/// code truth's claim on the budget.
#[test]
fn sections_compile_in_priority_order_not_caller_order() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(2_000, 64, MARKDOWN)?;
    let mut reversed = required_evidence();
    reversed.reverse();
    let pack = compile_context_pack(policy, &CANONICAL, &reversed, &NO_LANE)?;
    let order: Vec<ContextSectionKind> = pack
        .sections
        .iter()
        .map(|section| section.section)
        .collect();
    assert_eq!(
        order,
        vec![
            ContextSectionKind::CodeTruth,
            ContextSectionKind::SafetyEvidence,
            ContextSectionKind::SessionEvidence,
            ContextSectionKind::NativeFacts,
        ]
    );
    Ok(())
}

/// The advisory section is bounded by whatever required evidence left of the
/// total budget, even when the advisory quota alone would have allowed more.
///
/// Real defect this catches: a quota applied in isolation, so required
/// evidence plus a full advisory quota overruns the pack's total budget.
#[test]
fn required_evidence_claims_the_total_budget_before_the_advisory_quota()
-> Result<(), Box<dyn Error>> {
    let evidence = required_evidence();
    let required_tokens: u64 = evidence
        .iter()
        .map(|item| CANONICAL.count_tokens(&item.content))
        .sum();
    // The pack's own framing — its advisory heading, provider attribution and
    // bounded receipt — is agent-visible text and is reserved before any item
    // competes, so the headroom is measured past framing as well as past the
    // required evidence.
    let measuring = ContextPackPolicyV1::new(100_000, 10_000, MARKDOWN)?;
    let framing =
        compile_context_pack(measuring, &CANONICAL, &evidence, &lane(provider_flood(20)))?
            .framing_tokens;
    // Two tokens of headroom past the required evidence and the framing, and
    // an advisory quota far larger than that headroom (but still, as the
    // policy demands, strictly below the total budget).
    let policy = ContextPackPolicyV1::new(
        required_tokens + framing + 2,
        required_tokens + framing,
        MARKDOWN,
    )?;
    let pack = compile_context_pack(policy, &CANONICAL, &evidence, &lane(provider_flood(20)))?;

    assert_eq!(
        pack.total_tokens,
        required_tokens + framing,
        "no advisory item fits in two tokens of headroom"
    );
    assert!(
        pack.section(ContextSectionKind::ProviderMemory).is_none(),
        "an advisory section with no admitted item must be omitted, not empty"
    );
    assert_eq!(pack.excluded_provider_items.len(), 20);
    assert!(
        pack.excluded_provider_items.iter().all(|excluded| matches!(
            excluded.reason,
            ProviderExclusionReason::TotalBudgetExhausted { .. }
        )),
        "the exclusion reason must name the total budget, not the unspent quota: {:?}",
        pack.excluded_provider_items
    );
    Ok(())
}

/// Budget decisions follow the exact `o200k_base` token count, not a byte or
/// character estimate.
///
/// Real defect this catches: the canonical tokenizer swapped for a
/// `bytes / 4` heuristic. The content below costs materially more real tokens
/// than the heuristic predicts, so the two counters disagree about whether it
/// fits, and the admission decision flips.
#[test]
fn the_budget_is_measured_with_the_canonical_tokenizer_not_a_byte_estimate()
-> Result<(), Box<dyn Error>> {
    // Dense non-Latin text: many bytes per character, and more BPE tokens
    // than a byte-quarter estimate predicts.
    let dense = "日本語のテキストは同じバイト数でもトークン数が大きく異なる".repeat(4);
    let measured = CANONICAL.count_tokens(&dense);
    let estimated = ByteQuarterCounter.count_tokens(&dense);
    assert!(
        measured > estimated,
        "fixture is not discriminating: measured {measured} tokens vs estimated {estimated}"
    );

    // A quota that the real count overruns but the byte estimate would fit.
    let quota = estimated;
    assert!(quota < measured);
    let policy = ContextPackPolicyV1::new(quota * 8, quota, MARKDOWN)?;
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &[],
        &lane(contribution(vec![provider_item("dense", &dense)])),
    )?;

    assert!(
        pack.section(ContextSectionKind::ProviderMemory).is_none(),
        "an item whose real token cost exceeds the quota must not be admitted"
    );
    match pack.excluded_provider_items.as_slice() {
        [excluded] => {
            assert_eq!(excluded.candidate_id, "dense");
            match excluded.reason {
                ProviderExclusionReason::AdvisoryQuotaExhausted { item_tokens, .. } => {
                    assert!(
                        item_tokens >= measured,
                        "the recorded cost must be at least the canonical token count of the \
                         content, not a byte estimate: {item_tokens} vs {measured}"
                    );
                    assert!(
                        item_tokens > estimated,
                        "a byte-quarter estimate would have admitted this item"
                    );
                }
                other => panic!("unexpected exclusion reason: {other:?}"),
            }
        }
        other => panic!("expected exactly one excluded item, got {other:?}"),
    }

    // The same item under a quota that fits its rendered cost is admitted, and
    // one token less excludes it: the boundary is the exact canonical count of
    // what is rendered, never a byte estimate.
    let admitting = ContextPackPolicyV1::new(measured * 16, measured * 4, MARKDOWN)?;
    let admitted = compile_context_pack(
        admitting,
        &CANONICAL,
        &[],
        &lane(contribution(vec![provider_item("dense", &dense)])),
    )?;
    let advisory_cost = admitted.advisory_tokens();
    assert!(
        advisory_cost >= measured,
        "the advisory lane costs at least the content it carries"
    );
    assert!(admitted.excluded_provider_items.is_empty());

    let boundary =
        ContextPackPolicyV1::new(measured * 16, advisory_cost.saturating_sub(1), MARKDOWN)?;
    let refused = compile_context_pack(
        boundary,
        &CANONICAL,
        &[],
        &lane(contribution(vec![provider_item("dense", &dense)])),
    )?;
    assert!(
        refused
            .section(ContextSectionKind::ProviderMemory)
            .is_none(),
        "one token below the rendered advisory cost must exclude the item"
    );
    Ok(())
}

/// A tokenizer that is not the canonical one cannot compile a pack at all.
///
/// Real defect this catches: a host mounting a cheap estimator, producing a
/// pack that claims a verified token budget the estimator never measured.
#[test]
fn a_non_canonical_tokenizer_is_refused() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 100, MARKDOWN)?;
    match compile_context_pack(policy, &ByteQuarterCounter, &required_evidence(), &NO_LANE) {
        Err(ContextPackError::TokenizerNotCanonical {
            expected_id,
            received_id,
            ..
        }) => {
            assert_eq!(expected_id, CANONICAL_CONTEXT_TOKENIZER_ID);
            assert_eq!(received_id, "tracedecay.chars_div4");
        }
        other => panic!("a byte-quarter counter must be refused, got {other:?}"),
    }
    match compile_context_pack(
        policy,
        &WrongRevisionCounter,
        &required_evidence(),
        &NO_LANE,
    ) {
        Err(ContextPackError::TokenizerNotCanonical {
            expected_revision,
            received_revision,
            ..
        }) => {
            assert_eq!(expected_revision, CANONICAL_CONTEXT_TOKENIZER_REVISION);
            assert_eq!(received_revision, "tiktoken-rs-0.99");
        }
        other => panic!("a revision-drifted tokenizer must be refused, got {other:?}"),
    }
    Ok(())
}

/// Required evidence that does not fit the configured total is a typed
/// refusal, never a silent eviction.
///
/// Real defect this catches: a compiler that drops or truncates required
/// evidence to make the arithmetic work, so the pack looks budget-compliant
/// while missing the code truth the caller was obliged to carry.
#[test]
fn required_evidence_that_does_not_fit_is_a_typed_refusal() -> Result<(), Box<dyn Error>> {
    let evidence = required_evidence();
    let first_tokens = CANONICAL.count_tokens(&evidence[0].content);
    let policy = ContextPackPolicyV1::new(first_tokens.saturating_sub(1).max(1), 1, MARKDOWN)?;
    match compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE) {
        Err(ContextPackError::RequiredEvidenceDoesNotFit {
            section,
            item_id,
            item_tokens,
            ..
        }) => {
            assert_eq!(section, "code_truth");
            assert_eq!(item_id, "code.fn_resolve_scope");
            assert_eq!(item_tokens, first_tokens);
        }
        other => panic!("undersized required evidence must refuse, got {other:?}"),
    }
    Ok(())
}

/// Host evidence and provider memory never share a section.
///
/// Real defect this catches: a caller labelling its own evidence as provider
/// memory (or the reverse), which would let required evidence be evicted by
/// the advisory quota or let advisory text inherit host trust.
#[test]
fn a_host_item_cannot_claim_the_advisory_section() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 100, MARKDOWN)?;
    let items = vec![host_item(
        ContextSectionKind::ProviderMemory,
        "host.smuggled",
        "tracedecay.code_index",
        "code truth wearing an advisory label",
    )];
    match compile_context_pack(policy, &CANONICAL, &items, &NO_LANE) {
        Err(ContextPackError::HostItemInAdvisorySection { item_id }) => {
            assert_eq!(item_id, "host.smuggled");
        }
        other => panic!("a host item in the advisory section must be refused, got {other:?}"),
    }
    Ok(())
}

/// Section and item provenance survives compilation, including the explicit
/// unknown state.
///
/// Real defect this catches: provenance collapsed into an empty string or
/// dropped for advisory items, making unattributed provider text
/// indistinguishable from cited host evidence at the point of use.
#[test]
fn every_item_keeps_its_section_and_provenance() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 500, MARKDOWN)?;
    let mut items = vec![provider_item(
        "cited",
        "an advisory point with a named source",
    )];
    items.push(ProviderContextItemV1 {
        candidate_id: "uncited".to_owned(),
        content: "an advisory point with no established provenance".to_owned(),
        provenance: ProviderItemProvenanceV1::Unknown,
        explanation: Some("activation summary".to_owned()),
    });
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &required_evidence(),
        &lane(contribution(items)),
    )?;

    for item in pack.items() {
        assert!(
            !item.provenance.label().is_empty(),
            "item {} lost its provenance label",
            item.item_id
        );
        match (&item.provenance, item.section.is_required()) {
            (ContextItemProvenanceV1::Host { authority }, true) => {
                assert!(!authority.is_empty(), "host authority must be named");
            }
            (
                ContextItemProvenanceV1::Provider {
                    provider_id,
                    registration_revision,
                    candidate_id,
                    ..
                },
                false,
            ) => {
                assert_eq!(provider_id, "provider.native");
                assert_eq!(*registration_revision, 7);
                assert_eq!(candidate_id, &item.item_id);
            }
            (provenance, required) => panic!(
                "item {} in section {} (required {required}) carries mismatched provenance \
                 {provenance:?}",
                item.item_id,
                item.section.label()
            ),
        }
    }

    let advisory = pack
        .section(ContextSectionKind::ProviderMemory)
        .expect("advisory section");
    let uncited = advisory
        .items
        .iter()
        .find(|item| item.item_id == "uncited")
        .expect("uncited advisory item");
    match &uncited.provenance {
        ContextItemProvenanceV1::Provider {
            candidate_provenance,
            explanation,
            ..
        } => {
            assert_eq!(candidate_provenance, &ProviderItemProvenanceV1::Unknown);
            assert_eq!(candidate_provenance.label(), "unknown");
            assert_eq!(explanation.as_deref(), Some("activation summary"));
        }
        other => panic!("advisory item must carry provider provenance: {other:?}"),
    }
    Ok(())
}

/// Identical inputs under an identical policy always produce an identical
/// pack hash, and any change to the policy, the content, or the admitted set
/// changes it.
///
/// Real defect this catches: a receipt derived from wall-clock time, a hash
/// map iteration order, or only from item identities — any of which would
/// make a pack hash useless for reproducing what an agent was actually given.
#[test]
fn the_pack_hash_is_deterministic_and_input_sensitive() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 200, MARKDOWN)?;
    let evidence = required_evidence();
    let advisory = contribution(vec![provider_item("cited", "an advisory point")]);

    let first = compile_context_pack(policy, &CANONICAL, &evidence, &lane(advisory.clone()))?;
    let second = compile_context_pack(policy, &CANONICAL, &evidence, &lane(advisory.clone()))?;
    assert_eq!(
        first.pack_hash, second.pack_hash,
        "identical inputs must produce an identical pack hash"
    );
    assert_eq!(
        first, second,
        "identical inputs must produce identical packs"
    );

    let mut distinct: BTreeSet<String> = BTreeSet::new();
    distinct.insert(first.pack_hash.clone());

    // A different budget is a different pack.
    let wider = ContextPackPolicyV1::new(1_001, 200, MARKDOWN)?;
    distinct.insert(
        compile_context_pack(wider, &CANONICAL, &evidence, &lane(advisory.clone()))?.pack_hash,
    );

    // A different advisory quota is a different pack.
    let narrower = ContextPackPolicyV1::new(1_000, 199, MARKDOWN)?;
    distinct.insert(
        compile_context_pack(narrower, &CANONICAL, &evidence, &lane(advisory.clone()))?.pack_hash,
    );

    // Changed content under unchanged identities is a different pack.
    let mut edited = evidence.clone();
    edited[0].content.push_str(" // edited");
    distinct.insert(
        compile_context_pack(policy, &CANONICAL, &edited, &lane(advisory.clone()))?.pack_hash,
    );

    // A dropped advisory item is a different pack.
    distinct.insert(compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE)?.pack_hash);

    // Changed provenance under unchanged content is a different pack.
    let reprovenanced = ProviderContributionV1 {
        items: vec![ProviderContextItemV1 {
            candidate_id: "cited".to_owned(),
            content: "an advisory point".to_owned(),
            provenance: ProviderItemProvenanceV1::Unknown,
            explanation: None,
        }],
        ..advisory.clone()
    };
    distinct.insert(
        compile_context_pack(policy, &CANONICAL, &evidence, &lane(reprovenanced))?.pack_hash,
    );

    assert_eq!(
        distinct.len(),
        6,
        "each distinct input must produce a distinct pack hash: {distinct:?}"
    );
    Ok(())
}

/// A pack refuses inputs it could not reconcile item by item.
#[test]
fn unusable_item_identities_are_refused() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 200, MARKDOWN)?;
    let blank = vec![host_item(
        ContextSectionKind::CodeTruth,
        "  ",
        "tracedecay.code_index",
        "code truth",
    )];
    assert!(matches!(
        compile_context_pack(policy, &CANONICAL, &blank, &NO_LANE),
        Err(ContextPackError::ItemIdentityInvalid)
    ));

    let duplicated = vec![
        host_item(
            ContextSectionKind::CodeTruth,
            "code.same",
            "tracedecay.code_index",
            "code truth",
        ),
        host_item(
            ContextSectionKind::NativeFacts,
            "code.same",
            "tracedecay.native",
            "a fact",
        ),
    ];
    match compile_context_pack(policy, &CANONICAL, &duplicated, &NO_LANE) {
        Err(ContextPackError::DuplicateItemIdentity { item_id }) => {
            assert_eq!(item_id, "code.same");
        }
        other => panic!("a repeated item identity must be refused, got {other:?}"),
    }
    Ok(())
}

/// An advisory quota at or above the total budget is refused: it would let
/// the advisory lane claim the entire pack.
#[test]
fn an_advisory_quota_that_could_claim_the_whole_pack_is_refused() {
    assert!(matches!(
        ContextPackPolicyV1::new(0, 0, MARKDOWN),
        Err(ContextPackPolicyError::ZeroTotalBudget)
    ));
    match ContextPackPolicyV1::new(100, 100, MARKDOWN) {
        Err(ContextPackPolicyError::AdvisoryQuotaNotBoundedByTotal { advisory, total }) => {
            assert_eq!((advisory, total), (100, 100));
        }
        other => panic!("an unbounded advisory quota must be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The real pipeline: admission -> normalization -> selection -> pack
// ---------------------------------------------------------------------------

/// Admits, normalizes, and selects over `candidates`.
fn selection_of(
    candidates: Vec<RecallCandidateV1>,
    maximum_selected: usize,
) -> Result<(RecallSelectionV1, Vec<AdmittedRecallCandidate>), Box<dyn Error>> {
    let admission = admit_recall_candidates(
        &admitted_scope(),
        "request",
        &current_query(),
        &authorized_exact(),
        candidates,
    )?;
    let normalization = normalize_admitted_candidates(Default::default(), &admission.admitted)?;
    let selection = select_recall_candidates(
        RecallSelectionPolicyV1::new(maximum_selected)?,
        &normalization,
        &admission.admitted,
    )?;
    Ok((selection, admission.admitted))
}

fn distinct_candidate(id: &str, content: &str) -> RecallCandidateV1 {
    let mut value = candidate_value(
        id,
        content,
        scope_value(&admitted_scope()),
        current_validity(),
    );
    value["stable_memory_ref"] = serde_json::json!(format!("memory:{id}"));
    decode(value)
}

/// Every candidate a real selection retained reaches the pack exactly once —
/// either admitted into the advisory section or recorded as excluded — with
/// the provenance admission established for it.
///
/// Real defect this catches: a bridge that silently drops selected candidates
/// past a budget, leaving a pack that cannot be reconciled against the
/// selection receipt it came from.
#[test]
fn every_selected_candidate_is_accounted_for_in_the_pack() -> Result<(), Box<dyn Error>> {
    let candidates = vec![
        distinct_candidate(
            "alpha",
            "scope resolution lives in the daemon composition root",
        ),
        distinct_candidate(
            "bravo",
            "the recall admission ledger keeps denial rows without content",
        ),
        distinct_candidate(
            "charlie",
            "provider replies are advisory and never canonical facts",
        ),
    ];
    let (selection, admitted) = selection_of(candidates, 3)?;
    assert_eq!(selection.selected.len(), 3);

    let contribution =
        ProviderContributionV1::from_selection("provider.native", 3, &selection, &admitted)?;
    assert_eq!(contribution.items.len(), 3);
    assert!(contribution.reference_only_candidate_ids.is_empty());

    // A quota that fits the lane framing plus exactly one rendered item forces
    // the rest into the exclusion ledger.
    let measuring = ContextPackPolicyV1::new(100_000, 10_000, MARKDOWN)?;
    let generous = compile_context_pack(
        measuring,
        &CANONICAL,
        &required_evidence(),
        &lane(contribution.clone()),
    )?;
    let admitted_section = generous
        .section(ContextSectionKind::ProviderMemory)
        .expect("a generous quota admits every selected candidate");
    assert_eq!(admitted_section.items.len(), 3);
    let framing = lane_framing_tokens(measuring, &contribution)?;
    let policy = ContextPackPolicyV1::new(
        100_000,
        framing + admitted_section.items[0].tokens,
        MARKDOWN,
    )?;
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &required_evidence(),
        &lane(contribution.clone()),
    )?;
    assert_eq!(
        pack.section(ContextSectionKind::ProviderMemory)
            .map_or(0, |section| section.items.len()),
        1,
        "the quota must admit exactly one rendered advisory item"
    );

    let mut accounted: Vec<&str> = pack
        .section(ContextSectionKind::ProviderMemory)
        .map(|section| {
            section
                .items
                .iter()
                .map(|item| item.item_id.as_str())
                .collect()
        })
        .unwrap_or_default();
    accounted.extend(
        pack.excluded_provider_items
            .iter()
            .map(|excluded| excluded.candidate_id.as_str()),
    );
    accounted.sort_unstable();
    assert_eq!(accounted, vec!["alpha", "bravo", "charlie"]);

    // Provenance came from admission, not from the bridge.
    let advisory = pack
        .section(ContextSectionKind::ProviderMemory)
        .expect("one advisory item fits");
    match &advisory.items[0].provenance {
        ContextItemProvenanceV1::Provider {
            candidate_provenance,
            ..
        } => assert_eq!(
            candidate_provenance,
            &ProviderItemProvenanceV1::Available {
                source: format!("memory:{}", advisory.items[0].item_id),
            }
        ),
        other => panic!("advisory item must carry provider provenance: {other:?}"),
    }
    Ok(())
}

/// A selection that does not describe the admitted slice it claims to index
/// is a typed refusal, never a bridge that attaches one candidate's words to
/// another candidate's identity.
///
/// Real defect this catches: a bridge that trusts `provider_rank` blindly, so
/// a reordered or foreign admitted slice would silently mislabel advisory
/// content and its provenance.
#[test]
fn a_selection_that_does_not_describe_the_admitted_slice_is_refused() -> Result<(), Box<dyn Error>>
{
    let candidates = vec![
        distinct_candidate("alpha", "the daemon resolves scope at project open"),
        distinct_candidate("bravo", "denial rows never carry candidate content"),
    ];
    let (selection, admitted) = selection_of(candidates, 2)?;

    match ProviderContributionV1::from_selection("provider.native", 1, &selection, &[]) {
        Err(RecallSelectionError::ProviderRankOutOfRange { admitted_len, .. }) => {
            assert_eq!(admitted_len, 0);
        }
        other => panic!("an empty admitted slice must be refused, got {other:?}"),
    }

    let mut reordered = admitted.clone();
    reordered.reverse();
    match ProviderContributionV1::from_selection("provider.native", 1, &selection, &reordered) {
        Err(RecallSelectionError::CandidateIdentityMismatch {
            expected, admitted, ..
        }) => {
            assert_ne!(expected, admitted);
        }
        other => panic!("a reordered admitted slice must be refused, got {other:?}"),
    }
    Ok(())
}

/// The pack a real pipeline produces is serializable and round-trips, so the
/// receipt can be persisted and compared later.
#[test]
fn a_compiled_pack_round_trips_through_its_wire_form() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 200, MARKDOWN)?;
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &required_evidence(),
        &lane(contribution(vec![provider_item(
            "cited",
            "an advisory point",
        )])),
    )?;
    let encoded = serde_json::to_string(&pack)?;
    let decoded: ContextPackV1 = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, pack);
    assert_eq!(decoded.tokenizer_id, CANONICAL_CONTEXT_TOKENIZER_ID);
    assert_eq!(
        decoded.tokenizer_revision,
        CANONICAL_CONTEXT_TOKENIZER_REVISION
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The budget covers what the agent actually receives
// ---------------------------------------------------------------------------

/// One host answer of roughly `tokens` canonical tokens.
fn host_answer(tokens: u64) -> String {
    let unit = "the daemon composition root resolves the exact coding scope at project open. ";
    let per_unit = CANONICAL.count_tokens(unit).max(1);
    unit.repeat(usize::try_from(tokens.div_ceil(per_unit)).unwrap_or(1))
}

/// An advisory contribution whose *metadata* dwarfs its content: one-token
/// bodies carrying long provenance sources and long explanations.
fn metadata_heavy_contribution(items: usize) -> ProviderContributionV1 {
    ProviderContributionV1 {
        provider_id: "provider.native".to_owned(),
        registration_revision: 7,
        degradation: Some("partial".to_owned()),
        items: (0..items)
            .map(|index| ProviderContextItemV1 {
                candidate_id: format!("candidate-{index:03}"),
                // One token of content.
                content: "yes".to_owned(),
                provenance: ProviderItemProvenanceV1::Available {
                    source: format!(
                        "memory://{index}/a-very-long-stable-memory-reference-that-names-the-\
                         originating-session-the-worktree-and-the-commit-it-was-observed-under"
                    ),
                },
                explanation: Some(format!(
                    "selected because candidate {index} restates at considerable length why the \
                     retained owner mounts recall inside the daemon composition root"
                )),
            })
            .collect(),
        reference_only_candidate_ids: Vec::new(),
    }
}

/// The pack's own rendered text — framing, identities, provenance,
/// explanations and receipt included — never exceeds the budgets the pack
/// claims, at the boundary where the raw content alone would have fit.
///
/// Real defect this catches: budgeting only each item's raw `content` and
/// then rendering headers, candidate identities, provenance labels,
/// explanations and the receipt on top, so a one-token advisory body carrying
/// large uncounted metadata overruns the advisory quota and the total budget
/// the receipt claims to have honoured.
#[test]
fn the_rendered_pack_stays_inside_both_budgets_at_the_boundary() -> Result<(), Box<dyn Error>> {
    for form in [
        ContextPackRenderFormV1::Markdown,
        ContextPackRenderFormV1::Json,
    ] {
        let evidence = match form {
            ContextPackRenderFormV1::Markdown => vec![host_item(
                ContextSectionKind::CodeTruth,
                "host.answer",
                "tracedecay.tool.tracedecay_context",
                &host_answer(400),
            )],
            ContextPackRenderFormV1::Json => vec![host_item(
                ContextSectionKind::CodeTruth,
                "host.answer",
                "tracedecay.tool.tracedecay_context",
                &format!("\"answer\":{}", serde_json::json!(host_answer(400))),
            )],
        };
        let total = 1_000;
        let quota = 200;
        let policy = ContextPackPolicyV1::new(total, quota, form)?;
        let pack = compile_context_pack(
            policy,
            &CANONICAL,
            &evidence,
            &lane(metadata_heavy_contribution(64)),
        )?;

        // The canonical count of the exact text the agent receives.
        let rendered_tokens = CANONICAL.count_tokens(&pack.rendered);
        assert_eq!(
            rendered_tokens, pack.rendered_tokens,
            "the pack must report the measured cost of its own rendered text"
        );
        assert!(
            rendered_tokens <= total,
            "{} pack rendered {rendered_tokens} tokens against a {total}-token budget",
            form.label()
        );

        // Advisory metadata is inside the advisory quota, not outside it.
        let admitted = pack
            .section(ContextSectionKind::ProviderMemory)
            .map_or(0, |section| section.items.len());
        assert!(
            admitted > 0 && admitted < 64,
            "{}: the quota must admit some items and exclude the rest, admitted {admitted}",
            form.label()
        );
        assert_eq!(
            admitted + pack.excluded_provider_items.len(),
            64,
            "every advisory candidate must be admitted or recorded as excluded"
        );
        assert!(
            pack.advisory_tokens() <= quota,
            "{}: advisory lane accounted {} tokens against a {quota}-token quota",
            form.label(),
            pack.advisory_tokens()
        );

        // Every admitted item's rendered identity, provenance and explanation
        // is present in the text the budget was measured against.
        for item in pack
            .section(ContextSectionKind::ProviderMemory)
            .into_iter()
            .flat_map(|section| section.items.iter())
        {
            assert!(
                pack.rendered.contains(&item.item_id),
                "{}: admitted item {} is missing from the rendered pack",
                form.label(),
                item.item_id
            );
        }
        // An excluded item never reaches the agent.
        if let Some(excluded) = pack.excluded_provider_items.last() {
            assert!(
                !pack.rendered.contains(&excluded.candidate_id),
                "{}: excluded item {} was rendered anyway",
                form.label(),
                excluded.candidate_id
            );
        }
        assert!(
            pack.rendered.contains(&pack.pack_hash),
            "{}: the receipt must be part of the budgeted text",
            form.label()
        );
    }
    Ok(())
}

/// A JSON pack renders as one valid object that still carries the host's own
/// answer verbatim, plus the advisory lane under its own key.
///
/// Real defect this catches: JSON framing and escaping charged to nobody, or
/// a rebuilt object that loses or corrupts the host's answer.
#[test]
fn a_json_pack_renders_as_one_valid_object() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(4_000, 800, ContextPackRenderFormV1::Json)?;
    let evidence = vec![
        host_item(
            ContextSectionKind::CodeTruth,
            "host.answer",
            "tracedecay.tool.tracedecay_context",
            "\"answer\":{\"symbols\":[\"resolve_scope\"]}",
        ),
        host_item(
            ContextSectionKind::NativeFacts,
            "host.memory",
            "tracedecay.native.project_memory",
            "\"memory\":[{\"fact_id\":\"f1\",\"content\":\"scope is authoritative\"}]",
        ),
    ];
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &evidence,
        &lane(contribution(vec![provider_item(
            "cited",
            "an advisory point",
        )])),
    )?;

    let parsed: serde_json::Value = serde_json::from_str(&pack.rendered)?;
    assert_eq!(parsed["answer"]["symbols"][0], "resolve_scope");
    assert_eq!(parsed["memory"][0]["fact_id"], "f1");
    assert_eq!(parsed["advisory_provider_memory"]["state"], "answered");
    assert_eq!(
        parsed["advisory_provider_memory"]["candidates"][0]["provenance"],
        "source memory:cited"
    );
    assert_eq!(
        parsed["advisory_provider_memory"]["context_pack"]["pack_hash"],
        pack.pack_hash.as_str()
    );
    assert!(pack.rendered_tokens <= pack.total_token_budget);
    Ok(())
}

/// A host item that is not a well-formed JSON object member cannot be
/// rendered into a JSON pack, and is refused rather than corrupting the
/// host's own answer.
#[test]
fn a_json_pack_refuses_a_host_item_that_is_not_an_object_member() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 200, ContextPackRenderFormV1::Json)?;
    let evidence = vec![host_item(
        ContextSectionKind::CodeTruth,
        "host.answer",
        "tracedecay.tool.tracedecay_context",
        "## Code Context\nnot json at all\n",
    )];
    match compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE) {
        Err(error @ ContextPackError::HostItemNotJsonMember { .. }) => {
            assert_eq!(error.code(), "context_pack_host_item_not_json_member");
        }
        other => panic!("a non-member host item must be refused, got {other:?}"),
    }
    Ok(())
}

/// A markdown pack reassembles the host's own answer byte-for-byte from the
/// separately attributed evidence items it was compiled from.
///
/// Real defect this catches: attributing host evidence per section but then
/// re-rendering it in section-priority order, silently rewriting the host
/// answer the agent was supposed to receive unchanged.
#[test]
fn a_markdown_pack_reassembles_the_host_answer_in_input_order() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(4_000, 400, MARKDOWN)?;
    // Deliberately supplied in the host's own rendering order, which is *not*
    // section-priority order.
    let evidence = vec![
        host_item(
            ContextSectionKind::NativeFacts,
            "host.memory_matches",
            "tracedecay.native.project_memory",
            "### Memory Matches\n- accepted fact\n",
        ),
        host_item(
            ContextSectionKind::CodeTruth,
            "host.code",
            "tracedecay.code_index",
            "### Code\nfn resolve_scope() {}\n",
        ),
        host_item(
            ContextSectionKind::SafetyEvidence,
            "host.index_coverage",
            "tracedecay.index.coverage",
            "### Index Coverage Hint\nthe index is 12m stale\n",
        ),
    ];
    let original: String = evidence.iter().map(|item| item.content.clone()).collect();
    let pack = compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE)?;
    assert_eq!(
        pack.rendered, original,
        "an absent advisory lane must render the host answer unchanged"
    );

    let with_lane = compile_context_pack(
        policy,
        &CANONICAL,
        &evidence,
        &lane(contribution(vec![provider_item(
            "cited",
            "an advisory point",
        )])),
    )?;
    assert!(
        with_lane.rendered.starts_with(&original),
        "the host answer must be delivered first and unchanged: {}",
        with_lane.rendered
    );
    // Every populated host section keeps its own authority in the pack.
    for (section, authority) in [
        (ContextSectionKind::CodeTruth, "tracedecay.code_index"),
        (
            ContextSectionKind::SafetyEvidence,
            "tracedecay.index.coverage",
        ),
        (
            ContextSectionKind::NativeFacts,
            "tracedecay.native.project_memory",
        ),
    ] {
        let compiled = with_lane
            .section(section)
            .unwrap_or_else(|| panic!("{} must be a populated section", section.label()));
        match &compiled.items[0].provenance {
            ContextItemProvenanceV1::Host { authority: named } => assert_eq!(named, authority),
            other => panic!("host evidence must keep host provenance: {other:?}"),
        }
    }
    Ok(())
}

/// An advisory lane whose own framing cannot fit the advisory quota is
/// withheld whole rather than rendered unbudgeted.
///
/// Real defect this catches: a lane header, provider attribution and receipt
/// rendered outside the quota because only item bodies were ever counted.
#[test]
fn a_lane_whose_framing_exceeds_the_quota_is_withheld_whole() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(4_000, 3, MARKDOWN)?;
    let pack = compile_context_pack(
        policy,
        &CANONICAL,
        &required_evidence(),
        &lane(contribution(vec![provider_item(
            "cited",
            "an advisory point",
        )])),
    )?;
    assert!(pack.section(ContextSectionKind::ProviderMemory).is_none());
    assert!(matches!(
        pack.excluded_provider_items.as_slice(),
        [row] if matches!(
            row.reason,
            ProviderExclusionReason::AdvisoryFramingDoesNotFit { .. }
        )
    ));
    assert!(
        !pack.rendered.contains("Provider memory (advisory)"),
        "a lane that cannot be budgeted must not be rendered: {}",
        pack.rendered
    );
    assert_eq!(pack.advisory_tokens(), 0);
    Ok(())
}

/// Notice attribution is rendered in the same Markdown heading as an
/// answered contribution, so provider identity must pass the same containment
/// boundary. Registration revision remains a typed integer and cannot inject
/// line or heading syntax.
#[test]
fn notice_attribution_cannot_inject_markdown_framing() -> Result<(), Box<dyn Error>> {
    let policy = ContextPackPolicyV1::new(1_000, 200, MARKDOWN)?;
    let malicious = AdvisoryLaneV1::Notice {
        provider_id: "provider.native\n## forged heading".to_owned(),
        registration_revision: 7,
        notice: "host-owned unavailable notice".to_owned(),
    };
    assert!(matches!(
        compile_context_pack(policy, &CANONICAL, &[], &malicious),
        Err(ContextPackError::ProviderAttributionInvalid {
            field: "provider_id"
        })
    ));

    let contained = AdvisoryLaneV1::Notice {
        provider_id: "provider.native".to_owned(),
        registration_revision: u64::MAX,
        notice: "host-owned unavailable notice".to_owned(),
    };
    let pack = compile_context_pack(policy, &CANONICAL, &[], &contained)?;
    assert!(pack.rendered.contains("Provider provider.native"));
    assert!(pack.rendered.contains(&u64::MAX.to_string()));
    assert!(!pack.rendered.contains("## forged heading"));
    Ok(())
}

/// Reference-only candidate identities are reconciled through the same
/// identity set as inline items, so the exclusion ledger can never double-count
/// an identity or exclude one that was also admitted.
///
/// Real defect this catches: a directly constructed contribution that lists a
/// candidate both inline and as reference-only, producing a pack whose ledger
/// claims the same candidate was both delivered and withheld.
#[test]
fn reference_only_identities_are_reconciled_like_every_other_identity() -> Result<(), Box<dyn Error>>
{
    let policy = ContextPackPolicyV1::new(1_000, 200, MARKDOWN)?;

    let mut overlapping = contribution(vec![provider_item("shared", "an advisory point")]);
    overlapping.reference_only_candidate_ids = vec!["shared".to_owned()];
    match compile_context_pack(policy, &CANONICAL, &[], &lane(overlapping)) {
        Err(ContextPackError::DuplicateItemIdentity { item_id }) => {
            assert_eq!(item_id, "shared");
        }
        other => panic!("an inline item also listed as reference-only must be refused: {other:?}"),
    }

    let mut repeated = contribution(Vec::new());
    repeated.reference_only_candidate_ids = vec!["ref".to_owned(), "ref".to_owned()];
    match compile_context_pack(policy, &CANONICAL, &[], &lane(repeated)) {
        Err(ContextPackError::DuplicateItemIdentity { item_id }) => assert_eq!(item_id, "ref"),
        other => panic!("a repeated reference identity must be refused: {other:?}"),
    }

    let mut untrimmed = contribution(Vec::new());
    untrimmed.reference_only_candidate_ids = vec![" ref ".to_owned()];
    assert!(matches!(
        compile_context_pack(policy, &CANONICAL, &[], &lane(untrimmed)),
        Err(ContextPackError::ItemIdentityInvalid)
    ));

    let mut blank = contribution(Vec::new());
    blank.reference_only_candidate_ids = vec![String::new()];
    assert!(matches!(
        compile_context_pack(policy, &CANONICAL, &[], &lane(blank)),
        Err(ContextPackError::ItemIdentityInvalid)
    ));

    // A well-formed reference-only identity still reaches the ledger exactly
    // once, with its typed reason.
    let mut valid = contribution(vec![provider_item("inline", "an advisory point")]);
    valid.reference_only_candidate_ids = vec!["reference".to_owned()];
    let pack = compile_context_pack(policy, &CANONICAL, &[], &lane(valid))?;
    assert_eq!(pack.excluded_provider_items.len(), 1);
    assert_eq!(pack.excluded_provider_items[0].candidate_id, "reference");
    assert!(matches!(
        pack.excluded_provider_items[0].reason,
        ProviderExclusionReason::ContentNotInline
    ));
    Ok(())
}

/// Every compile refusal carries a stable machine-readable code, so a caller
/// that carries the failure across a boundary can still tell the refusals
/// apart.
///
/// Real defect this catches: a terminal outcome flattened to a human string,
/// which makes "required evidence does not fit" indistinguishable from a
/// tokenizer or identity refusal at the receipt.
#[test]
fn every_compile_refusal_carries_a_stable_code() -> Result<(), Box<dyn Error>> {
    let evidence = required_evidence();
    let first_tokens = CANONICAL.count_tokens(&evidence[0].content);
    let policy = ContextPackPolicyV1::new(first_tokens.saturating_sub(1).max(1), 1, MARKDOWN)?;
    let does_not_fit = compile_context_pack(policy, &CANONICAL, &evidence, &NO_LANE)
        .expect_err("undersized required evidence must refuse");
    assert_eq!(
        does_not_fit.code(),
        "context_pack_required_evidence_does_not_fit"
    );

    let wide = ContextPackPolicyV1::new(1_000, 100, MARKDOWN)?;
    let not_canonical = compile_context_pack(wide, &ByteQuarterCounter, &evidence, &NO_LANE)
        .expect_err("a byte-quarter counter must refuse");
    assert_eq!(not_canonical.code(), "context_pack_tokenizer_not_canonical");

    assert_eq!(
        ContextPackPolicyV1::new(100, 100, MARKDOWN)
            .expect_err("an unbounded advisory quota must refuse")
            .code(),
        "context_pack_policy_advisory_quota_not_bounded_by_total"
    );
    assert_eq!(
        ContextPackPolicyV1::new(0, 0, MARKDOWN)
            .expect_err("a zero budget must refuse")
            .code(),
        "context_pack_policy_zero_total_budget"
    );
    Ok(())
}

fn canonical_observation_provenance(branch: &str, revision: &str) -> ProviderItemProvenanceV1 {
    use tracedecay_memory_provider_registry::recall_admission::source_attribution::RecallSourceAttributionV1;
    let mut scope = scope_value(&admitted_scope());
    scope["branch_identity"] = serde_json::json!(branch);
    let source: RecallSourceAttributionV1 = serde_json::from_value(serde_json::json!({
        "source": {"canonical_provider_id": "claude", "canonical_session_id": "session-original", "source_key": "source-original", "stable_record_id": null,
            "observation_id": "observation-original", "source_revision": revision, "content_sha256": ONE_SHA},
        "origin_scope": {"state": "recorded", "exact_scope_identity": scope, "authority_ref": "host-original"},
        "source_sequence": 7, "occurred_at": null, "ingested_at": "2025-01-01T00:00:00.000000Z",
        "validity": {"valid_from": null, "valid_until": null, "superseded_at": null, "superseded_by": null, "revoked_at": null},
    })).unwrap();
    source.to_owned_attribution().unwrap();
    ProviderItemProvenanceV1::Hydrated {
        evidence: tracedecay_memory_provider_registry::HostEvidenceRefV1::CanonicalObservations {
            sources: vec![source],
        },
    }
}

#[test]
fn final_provenance_evidence_preserves_original_sources_and_binds_revision_and_scope() {
    for form in [
        ContextPackRenderFormV1::Json,
        ContextPackRenderFormV1::Markdown,
    ] {
        let compile = |provenance: ProviderItemProvenanceV1| {
            let mut item = provider_item("candidate-original", "retained source content");
            item.provenance = provenance;
            compile_context_pack(
                ContextPackPolicyV1::new(12_000, 6_000, form).unwrap(),
                &CANONICAL,
                &[],
                &lane(contribution(vec![item])),
            )
            .unwrap()
        };
        let provenance = canonical_observation_provenance("refs/heads/a", "revision-1");
        let expected = match &provenance {
            ProviderItemProvenanceV1::Hydrated { evidence } => {
                serde_json::to_value(evidence).unwrap()
            }
            _ => unreachable!(),
        };
        let original = compile(provenance.clone());
        let revision = compile(canonical_observation_provenance(
            "refs/heads/a",
            "revision-2",
        ));
        let scope = compile(canonical_observation_provenance(
            "refs/heads/b",
            "revision-1",
        ));
        for changed in [&revision, &scope] {
            let original_item = &original
                .section(ContextSectionKind::ProviderMemory)
                .unwrap()
                .items[0];
            let changed_item = &changed
                .section(ContextSectionKind::ProviderMemory)
                .unwrap()
                .items[0];
            assert_eq!(original_item.item_id, changed_item.item_id);
            assert_eq!(original_item.content, changed_item.content);
            assert_eq!(
                original_item.tokens, changed_item.tokens,
                "same-size metadata must not rely on token counts to change the hash"
            );
            assert_ne!(original.pack_hash, changed.pack_hash);
            assert_ne!(
                sha256_hex(original.rendered.as_bytes()),
                sha256_hex(changed.rendered.as_bytes())
            );
        }
        assert!(original.rendered.contains("session-original"));
        assert!(original.rendered.contains("revision-1"));
        assert!(original.rendered.contains("source-original"));
        match form {
            ContextPackRenderFormV1::Json => {
                let rendered: serde_json::Value = serde_json::from_str(&original.rendered).unwrap();
                let candidate = &rendered
                    [tracedecay_memory_provider_registry::ADVISORY_CONTEXT_PACK_JSON_KEY]["candidates"]
                    [0];
                assert_eq!(candidate["provenance"], provenance.human_label());
                assert_eq!(candidate["provenance_evidence"], expected);
            }
            ContextPackRenderFormV1::Markdown => {
                assert!(original.rendered.contains(&provenance.human_label()));
                assert!(
                    original
                        .rendered
                        .contains(&format!("provenance_evidence={expected}"))
                );
            }
        }
    }
}

#[test]
fn confirmed_source_evidence_is_charged_before_candidate_budget_admission() {
    for form in [
        ContextPackRenderFormV1::Json,
        ContextPackRenderFormV1::Markdown,
    ] {
        let mut item = provider_item("candidate-original", "retained source content");
        item.provenance = canonical_observation_provenance("refs/heads/a", "revision-1");
        let rich = contribution(vec![item.clone()]);
        let roomy = ContextPackPolicyV1::new(12_000, 6_000, form).unwrap();
        let full = compile_context_pack(roomy, &CANONICAL, &[], &lane(rich.clone())).unwrap();
        let quota = full.advisory_tokens() - 1;
        let tight = ContextPackPolicyV1::new(12_000, quota, form).unwrap();
        let withheld = compile_context_pack(tight, &CANONICAL, &[], &lane(rich)).unwrap();
        assert!(
            withheld
                .section(ContextSectionKind::ProviderMemory)
                .is_none()
        );
        assert_eq!(withheld.excluded_provider_items.len(), 1);
        assert!(!withheld.rendered.contains("session-original"));
        assert!(!withheld.rendered.contains("retained source content"));
        item.provenance = ProviderItemProvenanceV1::Hydrated {
            evidence: tracedecay_memory_provider_registry::HostEvidenceRefV1::CanonicalRecord {
                record_id: "observation-original".to_owned(),
            },
        };
        let smaller =
            compile_context_pack(tight, &CANONICAL, &[], &lane(contribution(vec![item]))).unwrap();
        assert_eq!(
            smaller
                .section(ContextSectionKind::ProviderMemory)
                .unwrap()
                .items
                .len(),
            1
        );
        assert!(full.advisory_tokens() > smaller.advisory_tokens());
    }
}

#[test]
fn unconfirmed_and_redacted_states_never_render_confirmed_original_sources() {
    for provenance in [
        ProviderItemProvenanceV1::Unknown,
        ProviderItemProvenanceV1::Redacted {
            reason: "provider redacted".to_owned(),
        },
        ProviderItemProvenanceV1::Available {
            source: "record:observation-original".to_owned(),
        },
        ProviderItemProvenanceV1::Unresolvable {
            source: "record:observation-original".to_owned(),
            reason: "unavailable".to_owned(),
        },
    ] {
        let mut item = provider_item("candidate-original", "advisory content");
        item.provenance = provenance;
        let pack = compile_context_pack(
            ContextPackPolicyV1::new(12_000, 6_000, ContextPackRenderFormV1::Json).unwrap(),
            &CANONICAL,
            &[],
            &lane(contribution(vec![item])),
        )
        .unwrap();
        let rendered: serde_json::Value = serde_json::from_str(&pack.rendered).unwrap();
        let candidate = &rendered
            [tracedecay_memory_provider_registry::ADVISORY_CONTEXT_PACK_JSON_KEY]["candidates"][0];
        assert!(candidate.get("provenance_evidence").is_none());
        assert!(!pack.rendered.contains("canonical_observations"));
    }
}

#[test]
fn retained_control_references_share_source_provenance_budget_and_hash_accounting() {
    use std::collections::BTreeMap;
    use tracedecay_memory_provider_registry::recall_context_pack::{
        ContextRecallControlRefV1, compile_context_pack_with_control_refs,
    };
    for form in [
        ContextPackRenderFormV1::Json,
        ContextPackRenderFormV1::Markdown,
    ] {
        let mut item = provider_item("candidate-original", "retained source content");
        item.provenance = canonical_observation_provenance("refs/heads/a", "revision-1");
        let lane = lane(contribution(vec![item]));
        let reference = ContextRecallControlRefV1 {
            trace_ref: format!("recall-trace-v1:{}:{}", "a".repeat(64), "b".repeat(64)),
            item_ref: "recall-item-v1:2".to_owned(),
        };
        let refs = BTreeMap::from([("candidate-original".to_owned(), reference.clone())]);
        let roomy = ContextPackPolicyV1::new(12_000, 6_000, form).unwrap();
        let compiled =
            compile_context_pack_with_control_refs(roomy, &CANONICAL, &[], &lane, &refs).unwrap();
        let mut changed_refs = refs.clone();
        changed_refs.get_mut("candidate-original").unwrap().item_ref =
            "recall-item-v1:3".to_owned();
        let changed =
            compile_context_pack_with_control_refs(roomy, &CANONICAL, &[], &lane, &changed_refs)
                .unwrap();
        assert_eq!(compiled.advisory_tokens(), changed.advisory_tokens());
        assert_ne!(compiled.pack_hash, changed.pack_hash);
        assert_ne!(compiled.rendered, changed.rendered);
        assert!(compiled.rendered.contains(&reference.trace_ref));
        assert!(compiled.rendered.contains(&reference.item_ref));
        assert!(compiled.rendered.contains("session-original"));
        assert!(compiled.rendered.contains("observation-original"));
        let ordinary = compile_context_pack(roomy, &CANONICAL, &[], &lane).unwrap();
        assert!(!ordinary.rendered.contains("recall-trace-v1:"));
        assert!(!ordinary.rendered.contains("recall-item-v1:"));
        assert!(compiled.advisory_tokens() > ordinary.advisory_tokens());
        let tight = ContextPackPolicyV1::new(12_000, compiled.advisory_tokens() - 1, form).unwrap();
        let withheld =
            compile_context_pack_with_control_refs(tight, &CANONICAL, &[], &lane, &refs).unwrap();
        assert!(
            withheld
                .section(ContextSectionKind::ProviderMemory)
                .is_none()
        );
        assert!(!withheld.rendered.contains("recall-trace-v1:"));
        assert!(!withheld.rendered.contains("retained source content"));
        assert_eq!(
            compile_context_pack(tight, &CANONICAL, &[], &lane)
                .unwrap()
                .section(ContextSectionKind::ProviderMemory)
                .unwrap()
                .items
                .len(),
            1
        );
        if form == ContextPackRenderFormV1::Json {
            let value: serde_json::Value = serde_json::from_str(&compiled.rendered).unwrap();
            let evidence = &value
                [tracedecay_memory_provider_registry::ADVISORY_CONTEXT_PACK_JSON_KEY]["candidates"]
                [0]["provenance_evidence"];
            assert_eq!(evidence["kind"], "canonical_observations");
            assert_eq!(
                evidence["sources"][0]["source"]["observation_id"],
                "observation-original"
            );
            assert_eq!(evidence["recall"], serde_json::to_value(reference).unwrap());
        }
    }
}

#[test]
fn control_render_input_is_bounded_and_requires_confirmed_original_sources() {
    use std::collections::BTreeMap;
    use tracedecay_memory_provider_registry::recall_context_pack::{
        ContextRecallControlRefV1, compile_context_pack_with_control_refs,
    };
    let reference = ContextRecallControlRefV1 {
        trace_ref: format!("recall-trace-v1:{}:{}", "a".repeat(64), "b".repeat(64)),
        item_ref: "recall-item-v1:2".to_owned(),
    };
    let mut item = provider_item("candidate-original", "advisory content");
    let refs = BTreeMap::from([("candidate-original".to_owned(), reference.clone())]);
    let policy = ContextPackPolicyV1::new(12_000, 6_000, MARKDOWN).unwrap();
    for provenance in [
        ProviderItemProvenanceV1::Unknown,
        ProviderItemProvenanceV1::Redacted {
            reason: "redacted".to_owned(),
        },
        ProviderItemProvenanceV1::Available {
            source: "record:claimed".to_owned(),
        },
        ProviderItemProvenanceV1::Hydrated {
            evidence: tracedecay_memory_provider_registry::HostEvidenceRefV1::CanonicalRecord {
                record_id: "fact-id".to_owned(),
            },
        },
    ] {
        item.provenance = provenance;
        assert!(
            compile_context_pack_with_control_refs(
                policy,
                &CANONICAL,
                &[],
                &lane(contribution(vec![item.clone()])),
                &refs
            )
            .is_err()
        );
    }
    item.provenance = canonical_observation_provenance("refs/heads/a", "revision-1");
    let too_many = (0..9)
        .map(|index| (format!("candidate.{index}"), reference.clone()))
        .collect();
    assert!(
        compile_context_pack_with_control_refs(
            policy,
            &CANONICAL,
            &[],
            &lane(contribution(vec![item.clone()])),
            &too_many
        )
        .is_err()
    );
    let mut hostile = refs.clone();
    let _ = hostile
        .get_mut("candidate-original")
        .unwrap()
        .trace_ref
        .pop();
    hostile
        .get_mut("candidate-original")
        .unwrap()
        .trace_ref
        .push('\n');
    assert!(
        compile_context_pack_with_control_refs(
            policy,
            &CANONICAL,
            &[],
            &lane(contribution(vec![item.clone()])),
            &hostile
        )
        .is_err()
    );
    if let ProviderItemProvenanceV1::Hydrated {
        evidence:
            tracedecay_memory_provider_registry::HostEvidenceRefV1::CanonicalObservations { sources },
    } = &mut item.provenance
    {
        *sources = vec![sources[0].clone(); 65];
    }
    assert!(
        compile_context_pack_with_control_refs(
            policy,
            &CANONICAL,
            &[],
            &lane(contribution(vec![item])),
            &refs
        )
        .is_err()
    );
}

#[test]
fn recall_correlation_roundtrips_and_obeys_the_whole_lane_budget() {
    use std::collections::BTreeMap;
    use tracedecay_memory_provider_registry::recall_context_pack::{
        ContextRecallTraceV1, compile_context_pack_with_control_metadata,
    };
    let lane = lane(contribution(Vec::new()));
    let trace = ContextRecallTraceV1 {
        request_id: "recall.context.actual.empty".to_owned(),
        trace_ref: format!("recall-trace-v1:{}:{}", "a".repeat(64), "b".repeat(64)),
    };
    for form in [ContextPackRenderFormV1::Json, MARKDOWN] {
        let policy = ContextPackPolicyV1::new(12_000, 6_000, form).unwrap();
        let compile = |policy, trace: &ContextRecallTraceV1| {
            compile_context_pack_with_control_metadata(
                policy,
                &CANONICAL,
                &[],
                &lane,
                &BTreeMap::new(),
                Some(trace),
            )
            .unwrap()
        };
        let pack = compile(policy, &trace);
        assert!(pack.items().next().is_none());
        assert_eq!(pack.recall_trace.as_ref(), Some(&trace));
        let wire: serde_json::Value = if form == ContextPackRenderFormV1::Json {
            let json: serde_json::Value = serde_json::from_str(&pack.rendered).unwrap();
            json[tracedecay_memory_provider_registry::ADVISORY_CONTEXT_PACK_JSON_KEY]["recall_trace"].clone()
        } else {
            serde_json::from_str(
                pack.rendered
                    .lines()
                    .find_map(|line| line.strip_prefix("recall_trace="))
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(wire, serde_json::to_value(&trace).unwrap());
        assert!(pack.rendered_tokens <= policy.total_token_budget());
        assert!(pack.advisory_tokens() <= policy.advisory_token_quota());
        let mut changed = trace.clone();
        changed.request_id.push_str(".other");
        assert_ne!(pack.pack_hash, compile(policy, &changed).pack_hash);
        let ordinary = compile_context_pack(policy, &CANONICAL, &[], &lane).unwrap();
        assert!(ordinary.recall_trace.is_none());
        assert!(!ordinary.rendered.contains("recall_trace"));
        assert!(pack.advisory_tokens() > ordinary.advisory_tokens());
        let tight = ContextPackPolicyV1::new(12_000, ordinary.advisory_tokens(), form).unwrap();
        let withheld = compile(tight, &trace);
        assert!(withheld.recall_trace.is_none());
        assert!(!withheld.rendered.contains("recall-trace-v1:"));
        assert_eq!(withheld.advisory_tokens(), 0);
        assert_eq!(withheld.pack_hash, compile(tight, &changed).pack_hash);
    }
}
