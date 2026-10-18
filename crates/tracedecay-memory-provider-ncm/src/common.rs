//! Canonical host evidence projection. The worker retains opaque capsules;
//! only this adapter reconstructs host-facing source and scope claims.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use chrono::DateTime;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracedecay_memory_provider_api::contract::{TemporalMode, TerminalCode, UnknownValidityPolicy};
use tracedecay_memory_provider_api::{
    CanonicalPayload, CurrentAdvisoryAdmission, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
    ProviderCall, ProviderReply,
};
use tracedecay_memory_provider_api::{
    OriginScopeEvidence, OriginalSourceIdentity, OwnedRecallExclusions, OwnedTemporalQuery,
    RecordedValidity, SourceAttribution,
};

use crate::{
    NcmNamespace, NcmRecallDiagnosticEvent, NcmRecallDiagnosticSink, NcmRecallDiagnosticStage,
    digest_field, hex_digest, opaque_surface_id,
};

mod lifecycle;
mod portability;
mod replay_boundary;
mod source_binding;
pub(crate) use lifecycle::{project as project_lifecycle, reconstruct as reconstruct_lifecycle};
pub(crate) use portability::{
    project as project_portability, reconstruct as reconstruct_portability,
};
pub(crate) use replay_boundary::valid_replay_payload;
pub(crate) use source_binding::project_source_id;
use source_binding::{source_binding, validate_source_binding};

const BUDGETS: &[&str] = &[
    "maximum_candidates",
    "maximum_candidate_content_bytes",
    "maximum_total_content_bytes",
    "maximum_source_refs_per_candidate",
    "maximum_trace_refs_per_candidate",
    "maximum_warnings",
    "maximum_extensions_per_candidate",
];
const EXCLUSIONS: &[&str] = &[
    "stable_memory_refs",
    "candidate_ids",
    "source_refs",
    "trace_refs",
    "observation_ids",
    "content_sha256",
];

/// The NCM worker's bounded recall window. Keep the worker's `top_k` and
/// selection budget coupled so a small caller budget is never widened at the
/// adapter boundary.
const MAX_RECALL_CANDIDATES: u64 = 16;

/// Canonical host-facing outcome produced after reconstructing a worker recall.
const RECALL_RESULT_CONTRACT_ID: &str = "tracedecay.memory.recall.query.outcome.v1";

/// Maximum serialized size of any retained named capsule.
///
/// Projection and reconstruction share this bound. Projection must reject a
/// capsule before dispatch so a successful mutation cannot become an unknown
/// effect only when its response is reconstructed.
pub(crate) const MAX_NAMED_CAPSULE_BYTES: usize = 131_072;

fn fields(value: &Value, names: &[&str]) -> Option<()> {
    let object = value.as_object()?;
    (object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)))
        .then_some(())
}

fn string(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
}

fn nullable_string(value: &Value) -> Option<Option<String>> {
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(string(value)?.to_owned()))
    }
}

fn instant(value: &Value) -> Option<i64> {
    let text = value.as_str()?;
    if !text.ends_with('Z') && !text.ends_with("+00:00") {
        return None;
    }
    let time = DateTime::parse_from_rfc3339(text).ok()?;
    time.timestamp_nanos_opt()
}

fn nullable_instant(value: &Value) -> Option<Option<i64>> {
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(instant(value)?))
    }
}

fn scope(value: &Value) -> Option<OwnedExactScope> {
    fields(
        value,
        &[
            "profile_id",
            "project_id",
            "repository_identity",
            "worktree_identity",
            "branch_identity",
            "agent_session_id",
            "resolved_scope_digest",
        ],
    )?;
    let scope = OwnedExactScope {
        profile_id: string(&value["profile_id"])?.to_owned(),
        project_id: string(&value["project_id"])?.to_owned(),
        repository_identity: string(&value["repository_identity"])?.to_owned(),
        worktree_identity: string(&value["worktree_identity"])?.to_owned(),
        branch_identity: string(&value["branch_identity"])?.to_owned(),
        agent_session_id: string(&value["agent_session_id"])?.to_owned(),
        resolved_scope_digest: string(&value["resolved_scope_digest"])?.to_owned(),
    };
    scope.validate().ok()?;
    Some(scope)
}

fn validity(value: &Value) -> Option<RecordedValidity> {
    fields(
        value,
        &[
            "valid_from",
            "valid_until",
            "superseded_at",
            "superseded_by",
            "revoked_at",
        ],
    )?;
    let validity = RecordedValidity {
        valid_from_utc_nanos: nullable_instant(&value["valid_from"])?,
        valid_until_utc_nanos: nullable_instant(&value["valid_until"])?,
        superseded_at_utc_nanos: nullable_instant(&value["superseded_at"])?,
        superseded_by: nullable_string(&value["superseded_by"])?,
        revoked_at_utc_nanos: nullable_instant(&value["revoked_at"])?,
    };
    validity.validate().ok()?;
    Some(validity)
}

fn attribution(value: &Value) -> Option<SourceAttribution> {
    fields(
        value,
        &[
            "source",
            "origin_scope",
            "source_sequence",
            "occurred_at",
            "ingested_at",
            "validity",
        ],
    )?;
    let source = &value["source"];
    fields(
        source,
        &[
            "canonical_provider_id",
            "canonical_session_id",
            "source_key",
            "stable_record_id",
            "observation_id",
            "source_revision",
            "content_sha256",
        ],
    )?;
    let original = OriginalSourceIdentity {
        canonical_provider_id: OwnedProviderId::new(string(&source["canonical_provider_id"])?)
            .ok()?,
        canonical_session_id: string(&source["canonical_session_id"])?.to_owned(),
        source_key: string(&source["source_key"])?.to_owned(),
        stable_record_id: nullable_string(&source["stable_record_id"])?,
        observation_id: string(&source["observation_id"])?.to_owned(),
        source_revision: nullable_string(&source["source_revision"])?,
        content_sha256: string(&source["content_sha256"])?.to_owned(),
    };
    let origin = &value["origin_scope"];
    let origin_scope = match origin["state"].as_str()? {
        "recorded" => {
            fields(origin, &["state", "exact_scope_identity", "authority_ref"])?;
            OriginScopeEvidence::Recorded {
                scope: scope(&origin["exact_scope_identity"])?,
                authority_ref: string(&origin["authority_ref"])?.to_owned(),
            }
        }
        "ingestion_only" => {
            fields(origin, &["state"])?;
            OriginScopeEvidence::IngestionOnly
        }
        "unavailable" => {
            fields(origin, &["state"])?;
            OriginScopeEvidence::Unavailable
        }
        _ => return None,
    };
    let result = SourceAttribution {
        source: original,
        origin_scope,
        source_sequence: value["source_sequence"].as_u64()?,
        occurred_at_utc_nanos: nullable_instant(&value["occurred_at"])?,
        ingested_at_utc_nanos: instant(&value["ingested_at"])?,
        validity: validity(&value["validity"])?,
    };
    result.validate().ok()?;
    Some(result)
}

fn temporal(value: &Value) -> Option<OwnedTemporalQuery> {
    fields(
        value,
        &[
            "mode",
            "evaluation_time",
            "as_of",
            "interval_start",
            "interval_end",
            "include_superseded",
            "include_revoked",
            "unknown_validity_policy",
        ],
    )?;
    let result = OwnedTemporalQuery {
        mode: match value["mode"].as_str()? {
            "current" => TemporalMode::Current,
            "as_of" => TemporalMode::AsOf,
            "interval" => TemporalMode::Interval,
            "history" => TemporalMode::History,
            _ => return None,
        },
        evaluation_time_utc_nanos: instant(&value["evaluation_time"])?,
        as_of_utc_nanos: nullable_instant(&value["as_of"])?,
        interval_start_utc_nanos: nullable_instant(&value["interval_start"])?,
        interval_end_utc_nanos: nullable_instant(&value["interval_end"])?,
        include_superseded: value["include_superseded"].as_bool()?,
        include_revoked: value["include_revoked"].as_bool()?,
        unknown_validity_policy: match value["unknown_validity_policy"].as_str()? {
            "exclude" => UnknownValidityPolicy::Exclude,
            "degrade" => UnknownValidityPolicy::Degrade,
            "allow_with_warning" => UnknownValidityPolicy::AllowWithWarning,
            _ => return None,
        },
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos(),
    )
    .ok()?;
    result.validate_at(now).ok()?;
    Some(result)
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| Some(string(item)?.to_owned()))
        .collect()
}

pub(crate) fn project_recall(
    call: &ProviderCall,
    value: &Value,
    namespace: &NcmNamespace,
) -> Option<Value> {
    let names = [
        "provider_id",
        "registration_revision",
        "ready_receipt_digest",
        "exact_scope_identity",
        "request_identity",
        "objective",
        "query",
        "temporal_query",
        "budgets",
        "exclusions",
        "required_capabilities",
        "policy_revision",
        "extensions",
        "deadline",
        "cancellation",
    ];
    let object = value.as_object()?;
    if object
        .keys()
        .any(|name| !names.contains(&name.as_str()))
        || names.iter().any(|name| !object.contains_key(*name))
    {
        return None;
    }
    if value["provider_id"].as_str()? != call.provider_id.as_str()
        || value["registration_revision"].as_u64()? != call.registration_revision
        || value["ready_receipt_digest"].as_str()? != call.ready_receipt_sha256
        || value["request_identity"].as_str()? != call.request_id
        || scope(&value["exact_scope_identity"])? != call.exact_scope
        || string(&value["objective"])?.len() > 8192
        || string(&value["query"])?.len() > 32768
        || value["policy_revision"].as_u64()? == 0
        || value["cancellation"] != "live"
    {
        return None;
    }
    let capabilities = strings(&value["required_capabilities"])?;
    let expected: BTreeSet<_> = call
        .required_capabilities
        .iter()
        .map(|item| item.as_str())
        .collect();
    if capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
        || capabilities.len() != expected.len()
    {
        return None;
    }
    fields(
        &value["deadline"],
        &["deadline_utc_micros", "remaining_millis"],
    )?;
    if value["deadline"]["deadline_utc_micros"].as_i64()? != call.control.deadline_utc_micros() {
        return None;
    }
    let remaining_millis = value["deadline"]["remaining_millis"].as_u64()?;
    if remaining_millis == 0 || remaining_millis != call.control.remaining_millis() {
        return None;
    }
    // Optional extensions remain inert; the outer adapter round-trips them.
    let extensions = value["extensions"].as_array()?;
    if extensions.len() > 16
        || extensions
            .iter()
            .any(|item| item["criticality"] != "optional")
    {
        return None;
    }
    let query = temporal(&value["temporal_query"])?;
    fields(&value["budgets"], BUDGETS)?;
    let maximum_candidates = value["budgets"]["maximum_candidates"].as_u64()?;
    for field in BUDGETS {
        if value["budgets"][*field].as_u64()? == 0 {
            return None;
        }
    }
    fields(&value["exclusions"], EXCLUSIONS)?;
    let exclusions = OwnedRecallExclusions {
        stable_memory_refs: strings(&value["exclusions"]["stable_memory_refs"])?,
        candidate_ids: strings(&value["exclusions"]["candidate_ids"])?,
        source_refs: strings(&value["exclusions"]["source_refs"])?,
        trace_refs: strings(&value["exclusions"]["trace_refs"])?,
        observation_ids: strings(&value["exclusions"]["observation_ids"])?,
        content_sha256: strings(&value["exclusions"]["content_sha256"])?,
    };
    exclusions.validate().ok()?;
    let mut projected_exclusions = json!({});
    for name in EXCLUSIONS {
        let values = strings(&value["exclusions"][*name])?;
        projected_exclusions[*name] = json!(
            values
                .iter()
                .map(|item| opaque_surface_id(namespace, name.as_bytes(), item))
                .collect::<Vec<_>>()
        );
    }
    // The worker selection schema accepts the candidate cap, temporal query,
    // and exclusions. Byte/reference/warning/extension budgets remain
    // enforced while reconstructing the canonical response below; putting
    // unsupported fields into selection would make the worker reject the
    // request rather than preserve those host-owned limits.
    Some(json!({
        "query_text": value["query"], "top_k": maximum_candidates.min(MAX_RECALL_CANDIDATES),
        "selection": {
            "mode": value["temporal_query"]["mode"], "evaluation": query.evaluation_time_utc_nanos,
            "as_of": query.as_of_utc_nanos, "start": query.interval_start_utc_nanos, "end": query.interval_end_utc_nanos,
            "include_superseded": query.include_superseded, "include_revoked": query.include_revoked,
            "unknown_policy": value["temporal_query"]["unknown_validity_policy"], "exclusions": projected_exclusions,
            "maximum_candidates": maximum_candidates.min(MAX_RECALL_CANDIDATES),
            "request_token": opaque_surface_id(namespace, b"recall-request", &call.request_id),
        }
    }))
}

pub(crate) fn project_attribution(
    call: &ProviderCall,
    value: &Value,
    namespace: &NcmNamespace,
) -> Option<Option<Value>> {
    let Some(original) = value.pointer("/source_identity/original_source") else {
        return Some(None);
    };
    let admitted = attribution(original)?;
    // The host delivers each canonical record under the exact scope of its own
    // session. An attribution recorded anywhere else is refused, never
    // relabelled into this delivery.
    if let OriginScopeEvidence::Recorded { scope, .. } = &admitted.origin_scope
        && scope != &call.exact_scope
    {
        return None;
    }
    let canonical = value.get("canonical_payload")?;
    let source_ref = format!(
        "record:{}",
        admitted
            .source
            .stable_record_id
            .as_deref()
            .unwrap_or(&admitted.source.observation_id)
    );
    let kind = value["observation_kind"].as_str()?;
    let (key_text, value_text) = evidence_text(kind, canonical)?;
    let retained = json!({"original_source": original, "canonical_payload": canonical, "source_refs": [source_ref], "delivery_scope": scope_value(&call.exact_scope),
        "projection": {"key_text": key_text, "value_text": value_text, "observation_kind": kind}});
    let bytes = serde_json::to_vec(&retained).ok()?;
    if bytes.len() > MAX_NAMED_CAPSULE_BYTES {
        return None;
    }
    let digest = hex_digest(&Sha256::digest(&bytes));
    let v = &admitted.validity;
    let delivery_bytes = serde_json::to_vec(
        &json!({"operation_id": call.operation_id, "idempotency_key": call.idempotency_key}),
    )
    .ok()?;
    if delivery_bytes.len() > MAX_NAMED_CAPSULE_BYTES {
        return None;
    }
    let delivery_digest = hex_digest(&Sha256::digest(&delivery_bytes));
    Some(Some(json!({
        "source_binding": source_binding(namespace, &admitted)?.provenance(),
        "common_capsule": {"version": 1, "bytes": bytes, "sha256": digest},
        "delivery_capsule": {"version": 1, "bytes": delivery_bytes, "sha256": delivery_digest},
        "selection": {
            "valid_from": v.valid_from_utc_nanos, "valid_until": v.valid_until_utc_nanos,
            "superseded_at": v.superseded_at_utc_nanos,
            "superseded_by": v.superseded_by.as_ref().map(|item| opaque_surface_id(namespace, b"stable_memory_refs", item)),
            "revoked_at": v.revoked_at_utc_nanos,
            "source_refs": [opaque_surface_id(namespace, b"source_refs", &source_ref)],
            "observation_ids": [opaque_surface_id(namespace, b"observation_ids", &admitted.source.observation_id)],
            "unknown_revision": admitted.source.source_revision.is_none(),
            "source_identity_sha256": opaque_surface_id(namespace, b"source-target", &serde_json::to_string(&json!({"source": original["source"], "origin_scope": original["origin_scope"]})).ok()?),
            "revision_digest": admitted.source.source_revision.as_ref().map(|revision| opaque_surface_id(namespace, b"source-revision", revision)),
            "observation_identity": opaque_surface_id(namespace, b"observation-identity", &serde_json::to_string(&json!([admitted.source.canonical_provider_id.as_str(), admitted.source.canonical_session_id, admitted.source.observation_id])).ok()?)
        }
    })))
}


pub(crate) fn evidence_text(kind: &str, canonical: &Value) -> Option<(String, String)> {
    let payload = canonical.get("payload").unwrap_or(canonical);
    if kind == "session.message_committed.v1" {
        if let Some(facts) = canonical["facts"].as_array() {
            let mut roles = Vec::new();
            let mut texts = Vec::new();
            for fact in facts {
                if fact["kind"] != "message" {
                    continue;
                }
                roles.push(string(&fact["role"])?.to_owned());
                texts.push(crate::message_fact_text(&fact["content"])?);
            }
            if texts.is_empty() {
                return None;
            }
            let content = texts.join("\n");
            return Some((content.clone(), format!("{}: {content}", roles.join("\n"))));
        }
        let content = crate::message_fact_text(&payload["content"])?;
        let role = string(&payload["role"])?;
        return Some((content.clone(), format!("{role}: {content}")));
    }
    let (key_names, value_names): (&[&str], &[&str]) = match kind {
        "tool.execution_settled.v1" => (
            &["command", "tool_name", "tool", "summary"],
            &["outcome_summary", "result", "output", "outcome", "summary"],
        ),
        "source.edit_settled.v1" => (
            &[
                "change_summary",
                "path_summary",
                "claim",
                "assertion",
                "summary",
            ],
            &[
                "result_summary",
                "diff_summary",
                "status",
                "content",
                "reason",
                "summary",
            ],
        ),
        "test.execution_settled.v1" => (
            &["test_name", "command", "assertion", "approach", "summary"],
            &[
                "outcome_summary",
                "result",
                "outcome",
                "status",
                "reason",
                "summary",
            ],
        ),
        "diagnostic.observed.v1" => (
            &["code", "diagnostic", "summary"],
            &["message", "detail", "summary"],
        ),
        "git.evidence_observed.v1" => (
            &["commit", "ref", "summary"],
            &["message", "evidence", "summary"],
        ),
        "native.fact_promoted.v1" => (
            &["subject", "key", "summary"],
            &["fact", "value", "content", "summary"],
        ),
        "feedback.outcome_settled.v1" | "automation.outcome_settled.v1" => (
            &["action", "job", "approach", "claim", "summary"],
            &[
                "outcome_summary",
                "result",
                "outcome",
                "signal",
                "status",
                "reason",
                "summary",
            ],
        ),
        _ => return None,
    };
    let key = evidence_field(payload, key_names)?;
    let value = evidence_field(payload, value_names)?;
    if key.len().saturating_add(value.len()) > 32_768 {
        return None;
    }
    Some((key, value))
}

fn evidence_field(payload: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        payload
            .get(*name)
            .and_then(|field| string(field))
            .filter(|text| text.len() <= 8_192)
            .map(str::to_owned)
    })
}

/// Whether two exact scopes name the same checkout. Every agent session of a
/// checkout shares NCM's memory; the session binding and resolved-scope
/// digest are per-delivery evidence, not a partition.
fn same_checkout(left: &OwnedExactScope, right: &OwnedExactScope) -> bool {
    left.profile_id == right.profile_id
        && left.project_id == right.project_id
        && left.repository_identity == right.repository_identity
        && left.worktree_identity == right.worktree_identity
        && left.branch_identity == right.branch_identity
}

/// A recall candidate's `checkout_observations` identity: the five checkout
/// fields of the admitted call, with the session and resolved-scope digest the
/// binding forbids left empty.
fn checkout_scope_value(scope: &OwnedExactScope) -> Value {
    json!({"scope_binding": "checkout_observations", "profile_id": scope.profile_id,
        "project_id": scope.project_id, "repository_identity": scope.repository_identity,
        "worktree_identity": scope.worktree_identity, "branch_identity": scope.branch_identity,
        "agent_session_id": "", "resolved_scope_digest": ""})
}

fn scope_value(scope: &OwnedExactScope) -> Value {
    json!({"profile_id": scope.profile_id, "project_id": scope.project_id,
        "repository_identity": scope.repository_identity, "worktree_identity": scope.worktree_identity,
        "branch_identity": scope.branch_identity, "agent_session_id": scope.agent_session_id,
        "resolved_scope_digest": scope.resolved_scope_digest})
}

fn decode_capsule(provenance: &Value) -> Option<Value> {
    decode_named_capsule(provenance, "common_capsule")
}

/// Diagnostic-only capsule decoder that checks the serialized byte count
/// before allocating a temporary byte vector. The normal reconstruction path
/// keeps its existing decoder and validation behavior.
fn decode_capsule_bounded(provenance: &Value, maximum_bytes: usize) -> Option<Value> {
    let capsule = provenance.get("common_capsule")?;
    if capsule["version"] != 1 {
        return None;
    }
    let encoded = capsule["bytes"].as_array()?;
    if encoded.len() > maximum_bytes.min(MAX_NAMED_CAPSULE_BYTES) {
        return None;
    }
    let bytes = encoded
        .iter()
        .map(|item| u8::try_from(item.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    if capsule["sha256"].as_str()? != hex_digest(&Sha256::digest(&bytes)) {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn decode_named_capsule(provenance: &Value, name: &str) -> Option<Value> {
    let capsule = provenance.get(name)?;
    if capsule["version"] != 1 {
        return None;
    }
    let encoded = capsule["bytes"].as_array()?;
    if encoded.len() > MAX_NAMED_CAPSULE_BYTES {
        return None;
    }
    let bytes = encoded
        .iter()
        .map(|item| u8::try_from(item.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    if capsule["sha256"].as_str()? != hex_digest(&Sha256::digest(&bytes)) {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn stable_reference(namespace: &NcmNamespace, record: u64, capsule_digest: &str) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"tracedecay.ncm.memory-reference.v1".as_slice(),
        namespace.as_str().as_bytes(),
        &record.to_be_bytes(),
        capsule_digest.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!("ncm-memory:{}", hex_digest(&digest.finalize()))
}

pub(crate) fn reconstruct_observation(
    call: &ProviderCall,
    reply: &mut ProviderReply,
) -> Option<()> {
    let mut payload: Value = serde_json::from_slice(&reply.payload.as_ref()?.bytes).ok()?;
    let metadata = payload.get("common_observation")?;
    let retained = decode_capsule(&metadata["provenance"])?;
    let delivery = decode_named_capsule(&metadata["provenance"], "delivery_capsule")?;
    let source = attribution(&retained["original_source"])?;
    let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
    if scope(&retained["delivery_scope"])? != call.exact_scope {
        return None;
    }
    validate_source_binding(
        &namespace,
        &source,
        &metadata["provenance"],
        metadata["source"].as_str()?,
    )?;
    let original_key = string(&delivery["idempotency_key"])?;
    if Some(original_key) != call.idempotency_key.as_deref() {
        return None;
    }
    let original_operation = string(&delivery["operation_id"])?;
    let stable = stable_reference(
        &namespace,
        metadata["record_id"].as_u64()?,
        metadata["provenance"]["common_capsule"]["sha256"].as_str()?,
    );
    if reply.terminal.committed_effect().state() == crate::CommittedEffectState::Duplicate {
        let effect = tracedecay_memory_provider_api::CommittedEffectEvidence::duplicate(
            reply.state_generation,
            original_key,
            original_operation,
            reply
                .terminal
                .committed_effect()
                .provider_receipt_sha256()?,
        )
        .ok()?;
        reply.terminal = tracedecay_memory_provider_api::TerminalRecord::new(
            call.operation,
            call.provider_id.clone(),
            reply.terminal.terminal_code(),
            effect,
            reply.terminal.fallback().clone(),
            call.operation_id.clone(),
            call.exact_scope.exact_scope_sha256(),
            reply.terminal.diagnostic_id().map(str::to_owned),
        )
        .ok()?;
    }
    payload.as_object_mut()?.remove("common_observation");
    payload["stable_memory_ref"] = json!(stable);
    payload["provider_receipt_digest"] = json!(
        reply
            .terminal
            .committed_effect()
            .provider_receipt_sha256()?
    );
    let bytes = serde_json::to_vec(&payload).ok()?;
    reply.payload = Some(
        CanonicalPayload::new(
            call.payload.contract_id.clone(),
            bytes.clone(),
            hex_digest(&Sha256::digest(&bytes)),
        )
        .ok()?,
    );
    Some(())
}

#[cfg(test)]
pub(crate) fn reconstruct_recall(
    call: &ProviderCall,
    instance: &str,
    reply: &mut ProviderReply,
) -> Option<()> {
    reconstruct_recall_with_diagnostics(call, instance, reply, None, None)
}

pub(crate) fn reconstruct_recall_with_diagnostics(
    call: &ProviderCall,
    instance: &str,
    reply: &mut ProviderReply,
    diagnostic_sink: Option<&dyn NcmRecallDiagnosticSink>,
    diagnostic_key: Option<&[u8; 32]>,
) -> Option<()> {
    let result = reconstruct_recall_inner(
        call,
        instance,
        reply,
        diagnostic_sink,
        diagnostic_key,
    );
    if result.is_none()
        && let Some(sink) = diagnostic_sink
    {
        emit_recall_diagnostic(
            Some(sink),
            diagnostic_for_reconstruction_failure(
                call,
                instance,
                reply.state_generation,
                diagnostic_key,
            ),
        );
    }
    result
}

fn reconstruct_recall_inner(
    call: &ProviderCall,
    instance: &str,
    reply: &mut ProviderReply,
    diagnostic_sink: Option<&dyn NcmRecallDiagnosticSink>,
    diagnostic_key: Option<&[u8; 32]>,
) -> Option<()> {
    let request: Value = serde_json::from_slice(&call.payload.bytes).ok()?;
    let query = temporal(&request["temporal_query"])?;
    let worker: Value = serde_json::from_slice(&reply.payload.as_ref()?.bytes).ok()?;
    let rows = worker["common_recall"]["candidates"].as_array()?;
    let budgets = &request["budgets"];
    let max_candidates = budgets["maximum_candidates"]
        .as_u64()?
        .min(MAX_RECALL_CANDIDATES) as usize;
    let max_content = budgets["maximum_candidate_content_bytes"].as_u64()?;
    let max_total = budgets["maximum_total_content_bytes"].as_u64()?;
    if let Some(sink) = diagnostic_sink {
        emit_recall_diagnostic(
            Some(sink),
            diagnostic_for_worker(
                call,
                instance,
                &request,
                &worker,
                rows,
                max_candidates,
                max_total,
                reply.state_generation,
                diagnostic_key,
            ),
        );
    }
    let mut candidates = Vec::new();
    let mut total = 0_u64;
    let mut truncated = worker["common_recall"]["truncated"].as_bool()?;
    let mut unknown = worker["common_recall"]["unknown_items"].as_u64()?;
    let mut excluded = worker["common_recall"]["excluded_items"].as_u64()?;
    let mut truncated_items = 0_u64;
    for row in rows {
        let retained = decode_capsule(&row["provenance"])?;
        let original = &retained["original_source"];
        let source = attribution(original)?;
        if !same_checkout(&scope(&retained["delivery_scope"])?, &call.exact_scope) {
            return None;
        }
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        validate_source_binding(
            &namespace,
            &source,
            &row["provenance"],
            row["source"].as_str()?,
        )?;
        if row["key_text"] != retained["projection"]["key_text"]
            || row["value_text"] != retained["projection"]["value_text"]
        {
            return None;
        }
        if let OriginScopeEvidence::Recorded { scope, .. } = &source.origin_scope
            && !same_checkout(scope, &call.exact_scope)
        {
            return None;
        }
        let content = row["value_text"].as_str()?;
        let digest = hex_digest(&Sha256::digest(content.as_bytes()));
        let stable = row["stable_memory_ref"].as_str()?;
        let candidate_id = row["candidate_id"].as_str()?;
        if stable
            != stable_reference(
                &namespace,
                row["record_id"].as_u64()?,
                row["provenance"]["common_capsule"]["sha256"].as_str()?,
            )
        {
            return None;
        }
        let request_token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
        let mut candidate_digest = Sha256::new();
        for field in [request_token.as_bytes(), stable.as_bytes()] {
            candidate_digest.update((field.len() as u64).to_be_bytes());
            candidate_digest.update(field);
        }
        if candidate_id != format!("ncm-candidate:{}", hex_digest(&candidate_digest.finalize())) {
            return None;
        }
        let source_refs = strings(&retained["source_refs"])?;
        let is_excluded = [
            ("stable_memory_refs", stable),
            ("trace_refs", stable),
            ("candidate_ids", candidate_id),
            ("observation_ids", source.source.observation_id.as_str()),
            ("content_sha256", digest.as_str()),
        ]
        .iter()
        .any(|(name, value)| {
            request["exclusions"][*name]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
        }) || source_refs
            .iter()
            .chain(std::iter::once(&source.source.source_key))
            .any(|source| {
                request["exclusions"]["source_refs"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(source)))
            });
        if is_excluded {
            excluded += 1;
            continue;
        }
        if candidates.len() == max_candidates
            || source_refs.len() as u64 > budgets["maximum_source_refs_per_candidate"].as_u64()?
        {
            truncated = true;
            truncated_items += 1;
            continue;
        }
        let content_limit = max_content.min(max_total.saturating_sub(total));
        let boundary = utf8_budget_boundary(content, content_limit);
        if boundary < content.len() {
            truncated = true;
            truncated_items += 1;
        }
        let emitted_content = &content[..boundary];
        if emitted_content.is_empty() {
            continue;
        }
        // Exclusions above use the complete retained content; this digest
        // describes exactly the UTF-8 excerpt emitted under the caller's budget.
        let emitted_digest = hex_digest(&Sha256::digest(emitted_content.as_bytes()));
        let score = validated_worker_activation(row)?;
        let (wire_validity, validity) = patched_worker_validity(original, row)?;
        let score_upper_bound =
            validated_worker_score_upper_bound(&worker["common_recall"]["score_upper_bound"])?;
        let at = query
            .as_of_utc_nanos
            .unwrap_or(query.evaluation_time_utc_nanos);
        let temporal_state = if validity.valid_from_utc_nanos.is_none() {
            "unknown"
        } else if validity.revoked_at_utc_nanos.is_some_and(|time| time <= at) {
            "revoked"
        } else if validity
            .superseded_at_utc_nanos
            .is_some_and(|time| time <= at)
        {
            "superseded"
        } else if validity.valid_from_utc_nanos.is_some_and(|time| time > at) {
            "future"
        } else if validity
            .valid_until_utc_nanos
            .is_some_and(|time| time <= at)
        {
            "expired"
        } else {
            "current"
        };
        let degraded = temporal_state == "unknown" || source.source.source_revision.is_none();
        if degraded {
            unknown += 1;
        }
        let warnings: Vec<&str> = if degraded {
            vec!["ncm.original_source_evidence_incomplete"]
        } else {
            Vec::new()
        };
        let candidate_scope = checkout_scope_value(&call.exact_scope);
        total += emitted_content.len() as u64;
        // The validated stable reference is also the existing retained trace
        // inspection selector. It does not attest a kernel activation trace.
        candidates.push(json!({
            "candidate_id": candidate_id, "stable_memory_ref": stable,
            "content": emitted_content, "content_ref": null, "content_sha256": emitted_digest,
            "native_score": {"score_domain_id": "ncm.rbf_activation.v1", "score_domain_version": 1,
                "raw_value": (score as f32).to_string(), "direction": "higher_is_better", "declared_minimum": "0",
                "declared_maximum": (score_upper_bound as f32).to_string(), "calibration_state": "uncalibrated",
                "semantics": "Peak intensity-weighted RBF activation across supporting NCM centers", "components": {}},
            "confidence": row.pointer("/confidence/Uncalibrated").cloned().unwrap_or(Value::Null),
            "exact_scope_identity": candidate_scope,
            "validity": {"observed_at": original["occurred_at"], "valid_from": wire_validity["valid_from"],
                "valid_until": wire_validity["valid_until"], "superseded_at": wire_validity["superseded_at"],
                "superseded_by": wire_validity["superseded_by"], "revoked_at": wire_validity["revoked_at"],
                "source_revision": original["source"]["source_revision"], "temporal_state": temporal_state},
            "provenance": {"state": "available", "origin_refs": source_refs, "observation_refs": [source.source.observation_id],
                "source_refs": source_refs, "transform_chain": ["ncm.canonical_evidence_projection.v1"],
                "provider_trace_refs": [stable], "redaction_reason": null, "original_sources": [original]},
            "explanation": {"summary": "Retained source content recalled through NCM center support", "matched_features": [],
                "activation_trace_refs": [], "limitations": ["Uncalibrated provider-native score"]},
            "source_refs": source_refs, "trace_refs": [stable], "sensitivity": "internal",
            "memory_class": "session_observation", "warnings": warnings, "extensions": []
        }));
    }
    candidates.sort_by(|left, right| {
        let score = |value: &Value| {
            value["native_score"]["raw_value"]
                .as_str()
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        score(right).total_cmp(&score(left)).then_with(|| {
            left["candidate_id"]
                .as_str()
                .cmp(&right["candidate_id"].as_str())
        })
    });
    let partial = truncated || unknown > 0;
    let zero = candidates.is_empty();
    let code = if partial {
        TerminalCode::Partial
    } else if zero {
        TerminalCode::SuccessZeroResults
    } else {
        TerminalCode::Success
    };
    let mut reasons = Vec::new();
    if truncated {
        reasons.push("ncm.recall_budget_truncated");
    }
    if unknown > 0 {
        reasons.push("ncm.original_source_evidence_incomplete");
    }
    let warnings = reasons
        .iter()
        .take(budgets["maximum_warnings"].as_u64()? as usize)
        .copied()
        .collect::<Vec<_>>();
    let value = json!({
        "provider_id": call.provider_id.as_str(), "provider_instance_id": instance,
        "registration_revision": call.registration_revision, "ready_receipt_digest": call.ready_receipt_sha256,
        "request_identity": call.request_id, "exact_scope_identity": scope_value(&call.exact_scope),
        "provider_state_generation": reply.state_generation, "candidates": candidates,
        "coverage": {"state": if partial {"partial"} else if zero {"zero_results"} else {"complete"},
            "searched_scope_digest": call.exact_scope.exact_scope_sha256(),
            "searched_temporal_digest": hex_digest(&Sha256::digest(serde_json::to_vec(&request["temporal_query"]).ok()?)),
            "scanned_items": worker["common_recall"]["scanned_items"], "matched_items": rows.len(),
            "returned_items": candidates.len(), "excluded_items": excluded, "truncated_items": truncated_items,
            "next_cursor": null, "reasons": reasons},
        "ordering": {"provider_order": "deterministic_native_score_then_candidate_id_within_one_score_domain", "tie_breaker": "candidate_id_lexicographic_utf8"},
        "terminal": {"code": code.as_wire()}, "warnings": warnings
    });
    if let Some(sink) = diagnostic_sink {
        emit_recall_diagnostic(
            Some(sink),
            diagnostic_for_reconstructed(
                call,
                instance,
                &request,
                &value,
                max_candidates,
                max_total,
                worker["common_recall"]["scanned_items"]
                    .as_u64()
                    .unwrap_or(0),
                reply.state_generation,
                if partial {
                    NcmRecallDiagnosticStage::PartialReply
                } else {
                    NcmRecallDiagnosticStage::Reconstructed
                },
                excluded,
                truncated_items,
                unknown,
                diagnostic_key,
            ),
        );
    }
    let bytes = serde_json::to_vec(&value).ok()?;
    reply.payload = Some(
        CanonicalPayload::new(
            OwnedVersionedId::new(RECALL_RESULT_CONTRACT_ID).ok()?,
            bytes.clone(),
            hex_digest(&Sha256::digest(&bytes)),
        )
        .ok()?,
    );
    reply.terminal = tracedecay_memory_provider_api::TerminalRecord::new(
        call.operation,
        call.provider_id.clone(),
        code,
        tracedecay_memory_provider_api::CommittedEffectEvidence::none(Some(reply.state_generation)),
        tracedecay_memory_provider_api::FallbackDirective::forbidden(),
        &call.operation_id,
        call.exact_scope.exact_scope_sha256(),
        None,
    )
    .ok()?;
    Some(())
}

const RECALL_DIAGNOSTIC_MAX_ITEMS: usize = 16;
const RECALL_DIAGNOSTIC_MAX_CAPSULE_BYTES: usize = 131_072;
const RECALL_DIAGNOSTIC_REQUEST_DOMAIN: &[u8] = b"tracedecay.ncm.recall-diagnostic.request.v1\0";
const RECALL_DIAGNOSTIC_OPERATION_DOMAIN: &[u8] =
    b"tracedecay.ncm.recall-diagnostic.operation.v1\0";
const RECALL_DIAGNOSTIC_QUERY_DOMAIN: &[u8] = b"tracedecay.ncm.recall-diagnostic.query.v1\0";
const RECALL_DIAGNOSTIC_EXACT_SCOPE_DOMAIN: &[u8] =
    b"tracedecay.ncm.recall-diagnostic.exact-scope.v1\0";
const RECALL_DIAGNOSTIC_INSTANCE_DOMAIN: &[u8] = b"tracedecay.ncm.recall-diagnostic.instance.v1\0";

struct RecallDiagnosticAccumulator {
    scanned_items: u64,
    candidate_count: u64,
    admitted_candidate_count: u64,
    candidate_ranks: Vec<u64>,
    candidate_content_bytes: Vec<u64>,
    total_content_bytes: u64,
    empty_content_count: u64,
    previous_score: Option<f64>,
    score_tie_count: u64,
    score_margin_below_epsilon_count: u64,
}

impl RecallDiagnosticAccumulator {
    fn new() -> Self {
        Self {
            scanned_items: 0,
            candidate_count: 0,
            admitted_candidate_count: 0,
            candidate_ranks: Vec::with_capacity(RECALL_DIAGNOSTIC_MAX_ITEMS),
            candidate_content_bytes: Vec::with_capacity(RECALL_DIAGNOSTIC_MAX_ITEMS),
            total_content_bytes: 0,
            empty_content_count: 0,
            previous_score: None,
            score_tie_count: 0,
            score_margin_below_epsilon_count: 0,
        }
    }

    fn push(
        &mut self,
        rank: usize,
        content_bytes: usize,
        budgeted_content_bytes: usize,
        score: Option<f64>,
    ) {
        self.candidate_count = self.candidate_count.saturating_add(1);
        if budgeted_content_bytes > 0 {
            self.admitted_candidate_count = self.admitted_candidate_count.saturating_add(1);
        }
        let content_bytes = u64::try_from(content_bytes).unwrap_or(u64::MAX);
        self.total_content_bytes = self
            .total_content_bytes
            .saturating_add(u64::try_from(budgeted_content_bytes).unwrap_or(u64::MAX));
        if content_bytes == 0 {
            self.empty_content_count = self.empty_content_count.saturating_add(1);
        }
        if self.candidate_ranks.len() < RECALL_DIAGNOSTIC_MAX_ITEMS {
            self.candidate_ranks
                .push(u64::try_from(rank).unwrap_or(u64::MAX));
            self.candidate_content_bytes.push(content_bytes);
        }
        if let Some(score) = score.filter(|score| score.is_finite()) {
            if let Some(previous) = self.previous_score {
                let margin = (previous - score).abs();
                if margin == 0.0 {
                    self.score_tie_count = self.score_tie_count.saturating_add(1);
                }
                if margin <= 0.000_001 {
                    self.score_margin_below_epsilon_count =
                        self.score_margin_below_epsilon_count.saturating_add(1);
                }
            }
            self.previous_score = Some(score);
        }
    }

    fn finish(
        self,
        call: &ProviderCall,
        instance: &str,
        request: &Value,
        stage: NcmRecallDiagnosticStage,
        state_generation: u64,
        diagnostic_key: Option<&[u8; 32]>,
        max_candidates: usize,
        max_total: u64,
        excluded_count: u64,
        truncated_count: u64,
        unknown_count: u64,
    ) -> NcmRecallDiagnosticEvent {
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let remaining_candidate_slots = u64::try_from(max_candidates)
            .unwrap_or(u64::MAX)
            .saturating_sub(self.admitted_candidate_count);
        NcmRecallDiagnosticEvent {
            stage,
            request_id_sha256: diagnostic_digest(
                diagnostic_key,
                &namespace,
                RECALL_DIAGNOSTIC_REQUEST_DOMAIN,
                call.request_id.as_bytes(),
            ),
            operation_id_sha256: diagnostic_digest(
                diagnostic_key,
                &namespace,
                RECALL_DIAGNOSTIC_OPERATION_DOMAIN,
                call.operation_id.as_bytes(),
            ),
            query_sha256: diagnostic_digest(
                diagnostic_key,
                &namespace,
                RECALL_DIAGNOSTIC_QUERY_DOMAIN,
                request["query"].as_str().unwrap_or_default().as_bytes(),
            ),
            exact_scope_sha256: diagnostic_digest(
                diagnostic_key,
                &namespace,
                RECALL_DIAGNOSTIC_EXACT_SCOPE_DOMAIN,
                call.exact_scope.exact_scope_sha256().as_bytes(),
            ),
            namespace_sha256: diagnostic_key.map(|_| namespace.as_str().to_owned()),
            provider_instance_sha256: diagnostic_digest(
                diagnostic_key,
                &namespace,
                RECALL_DIAGNOSTIC_INSTANCE_DOMAIN,
                instance.as_bytes(),
            ),
            state_generation,
            scanned_items: self.scanned_items,
            candidate_count: self.candidate_count,
            candidate_ranks: self.candidate_ranks,
            candidate_content_bytes: self.candidate_content_bytes,
            excluded_count,
            truncated_count,
            unknown_count,
            empty_content_count: self.empty_content_count,
            score_tie_count: self.score_tie_count,
            score_margin_below_epsilon_count: self.score_margin_below_epsilon_count,
            remaining_candidate_slots,
            remaining_content_bytes: max_total.saturating_sub(self.total_content_bytes),
        }
    }
}

fn diagnostic_digest(
    key: Option<&[u8; 32]>,
    namespace: &NcmNamespace,
    domain: &[u8],
    value: &[u8],
) -> Option<String> {
    let key = key?;
    let mut key_block = [0_u8; 64];
    key_block[..key.len()].copy_from_slice(key);

    let mut inner_pad = [0_u8; 64];
    let mut outer_pad = [0_u8; 64];
    for index in 0..key_block.len() {
        inner_pad[index] = key_block[index] ^ 0x36;
        outer_pad[index] = key_block[index] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    digest_field(&mut inner, namespace.as_str().as_bytes());
    digest_field(&mut inner, value);
    let inner_result = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_result);
    Some(hex_digest(&outer.finalize()))
}

fn emit_recall_diagnostic(
    sink: Option<&dyn NcmRecallDiagnosticSink>,
    event: NcmRecallDiagnosticEvent,
) {
    if let Some(sink) = sink {
        let _ = catch_unwind(AssertUnwindSafe(|| sink.record(event)));
    }
}

fn utf8_budget_boundary(content: &str, content_limit: u64) -> usize {
    let mut boundary = usize::try_from(content_limit)
        .unwrap_or(usize::MAX)
        .min(content.len());
    while !content.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

fn validated_worker_activation(row: &Value) -> Option<f64> {
    let score = row["activation"].as_f64()?;
    score.is_finite().then_some(score)
}

fn validated_worker_score_upper_bound(value: &Value) -> Option<f64> {
    let score_upper_bound = value.as_f64()?;
    score_upper_bound.is_finite().then_some(score_upper_bound)
}

fn patched_worker_validity(original: &Value, row: &Value) -> Option<(Value, RecordedValidity)> {
    let mut wire_validity = original["validity"].clone();
    if let Some(patch) = row
        .pointer("/provenance/control/validity_patch")
        .and_then(Value::as_object)
    {
        for (field, value) in patch {
            wire_validity[field] = value.clone();
        }
    }
    let validity = validity(&wire_validity)?;
    Some((wire_validity, validity))
}

fn worker_budgeted_content_bytes(
    call: &ProviderCall,
    request: &Value,
    row: &Value,
    score_upper_bound: Option<f64>,
    max_candidates: usize,
    max_content: u64,
    max_total: u64,
    accepted_candidates: usize,
    accepted_content_bytes: u64,
) -> Option<usize> {
    if accepted_candidates >= max_candidates || accepted_content_bytes >= max_total {
        return Some(0);
    }
    validated_worker_activation(row)?;
    let content = row["value_text"].as_str()?;
    let (retained, source) = authorized_worker_row(call, row)?;
    if row["key_text"] != retained["projection"]["key_text"]
        || row["value_text"] != retained["projection"]["value_text"]
    {
        return Some(0);
    }
    let source_refs = retained["source_refs"].as_array()?;
    let maximum_source_refs = request["budgets"]["maximum_source_refs_per_candidate"].as_u64()?;
    if source_refs.len() as u64 > maximum_source_refs
        || source_refs.iter().any(|item| string(item).is_none())
    {
        return Some(0);
    }
    let stable = row["stable_memory_ref"].as_str()?;
    let candidate_id = row["candidate_id"].as_str()?;
    let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
    if stable
        != stable_reference(
            &namespace,
            row["record_id"].as_u64()?,
            row["provenance"]["common_capsule"]["sha256"].as_str()?,
        )
    {
        return Some(0);
    }
    let request_token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
    let mut candidate_digest = Sha256::new();
    for field in [request_token.as_bytes(), stable.as_bytes()] {
        candidate_digest.update((field.len() as u64).to_be_bytes());
        candidate_digest.update(field);
    }
    let expected_candidate_id =
        format!("ncm-candidate:{}", hex_digest(&candidate_digest.finalize()));
    if candidate_id != expected_candidate_id {
        return Some(0);
    }
    let content_digest = hex_digest(&Sha256::digest(content.as_bytes()));
    let excluded = [
        ("stable_memory_refs", stable),
        ("trace_refs", stable),
        ("candidate_ids", candidate_id),
        ("observation_ids", source.source.observation_id.as_str()),
        ("content_sha256", content_digest.as_str()),
    ]
    .iter()
    .any(|(name, value)| {
        request["exclusions"][*name]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
    }) || source_refs
        .iter()
        .filter_map(Value::as_str)
        .chain(std::iter::once(source.source.source_key.as_str()))
        .any(|source_ref| {
            request["exclusions"]["source_refs"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(source_ref)))
        });
    if excluded {
        return Some(0);
    }
    let content_limit = max_content.min(max_total.saturating_sub(accepted_content_bytes));
    let boundary = utf8_budget_boundary(content, content_limit);
    if boundary == 0 {
        return Some(0);
    }
    score_upper_bound?;
    patched_worker_validity(&retained["original_source"], row)?;
    Some(boundary)
}


fn diagnostic_for_worker(
    call: &ProviderCall,
    instance: &str,
    request: &Value,
    worker: &Value,
    rows: &[Value],
    max_candidates: usize,
    max_total: u64,
    state_generation: u64,
    diagnostic_key: Option<&[u8; 32]>,
) -> NcmRecallDiagnosticEvent {
    let mut summary = RecallDiagnosticAccumulator::new();
    summary.scanned_items = worker["common_recall"]["scanned_items"]
        .as_u64()
        .unwrap_or(0);
    let mut budgeted_total = 0_u64;
    let mut budgeted_candidates = 0_usize;
    let mut budget_available = max_candidates > 0 && max_total > 0;
    let max_content = request["budgets"]["maximum_candidate_content_bytes"]
        .as_u64()
        .unwrap_or(0);
    let score_upper_bound =
        validated_worker_score_upper_bound(&worker["common_recall"]["score_upper_bound"]);
    for (index, row) in rows.iter().enumerate() {
        // Keep the scalar budget accounting exact across excluded or invalid
        // rows that precede the first eligible candidate. Each inspected row
        // is decoded through the bounded capsule path; once either budget is
        // saturated, later rows need no decoding at all.
        let budgeted_content_bytes = if budget_available && score_upper_bound.is_some() {
            worker_budgeted_content_bytes(
                call,
                request,
                row,
                score_upper_bound,
                max_candidates,
                max_content,
                max_total,
                budgeted_candidates,
                budgeted_total,
            )
            .unwrap_or(0)
        } else {
            0
        };
        if budgeted_content_bytes > 0 {
            budgeted_candidates = budgeted_candidates.saturating_add(1);
            budgeted_total = budgeted_total
                .saturating_add(u64::try_from(budgeted_content_bytes).unwrap_or(u64::MAX));
        }
        budget_available = budgeted_candidates < max_candidates && budgeted_total < max_total;
        summary.push(
            index.saturating_add(1),
            row["value_text"].as_str().map_or(0, str::len),
            budgeted_content_bytes,
            validated_worker_activation(row),
        );
    }
    summary.finish(
        call,
        instance,
        request,
        NcmRecallDiagnosticStage::Worker,
        state_generation,
        diagnostic_key,
        max_candidates,
        max_total,
        worker["common_recall"]["excluded_items"]
            .as_u64()
            .unwrap_or(0),
        worker["common_recall"]["truncated_items"]
            .as_u64()
            .or_else(|| {
                worker["common_recall"]["truncated"]
                    .as_bool()
                    .is_some_and(|value| value)
                    .then_some(1)
            })
            .unwrap_or(0),
        worker["common_recall"]["unknown_items"]
            .as_u64()
            .unwrap_or(0),
    )
}

fn diagnostic_for_reconstructed(
    call: &ProviderCall,
    instance: &str,
    request: &Value,
    value: &Value,
    max_candidates: usize,
    max_total: u64,
    scanned_items: u64,
    state_generation: u64,
    stage: NcmRecallDiagnosticStage,
    excluded_count: u64,
    truncated_count: u64,
    unknown_count: u64,
    diagnostic_key: Option<&[u8; 32]>,
) -> NcmRecallDiagnosticEvent {
    let mut summary = RecallDiagnosticAccumulator::new();
    summary.scanned_items = scanned_items;
    if let Some(candidates) = value["candidates"].as_array() {
        for (index, candidate) in candidates.iter().enumerate() {
            summary.push(
                index.saturating_add(1),
                candidate["content"].as_str().map_or(0, str::len),
                candidate["content"].as_str().map_or(0, str::len),
                candidate["native_score"]["raw_value"]
                    .as_str()
                    .and_then(|score| score.parse::<f64>().ok()),
            );
        }
    }
    summary.finish(
        call,
        instance,
        request,
        stage,
        state_generation,
        diagnostic_key,
        max_candidates,
        max_total,
        excluded_count,
        truncated_count,
        unknown_count,
    )
}

fn diagnostic_for_reconstruction_failure(
    call: &ProviderCall,
    instance: &str,
    state_generation: u64,
    diagnostic_key: Option<&[u8; 32]>,
) -> NcmRecallDiagnosticEvent {
    let request = serde_json::from_slice::<Value>(&call.payload.bytes).unwrap_or(Value::Null);
    let max_candidates = request["budgets"]["maximum_candidates"]
        .as_u64()
        .unwrap_or(0)
        .min(RECALL_DIAGNOSTIC_MAX_ITEMS as u64) as usize;
    let max_total = request["budgets"]["maximum_total_content_bytes"]
        .as_u64()
        .unwrap_or(0);
    RecallDiagnosticAccumulator::new().finish(
        call,
        instance,
        &request,
        NcmRecallDiagnosticStage::ReconstructionFailure,
        state_generation,
        diagnostic_key,
        max_candidates,
        max_total,
        0,
        0,
        0,
    )
}

/// Emits a typed recall diagnostic when the caller control terminal is
/// observed after the surface has already returned.
pub(crate) fn emit_recall_post_dispatch_control_diagnostic(
    call: &ProviderCall,
    instance: &str,
    reply: &ProviderReply,
    code: TerminalCode,
    diagnostic_sink: Option<&dyn NcmRecallDiagnosticSink>,
    diagnostic_key: Option<&[u8; 32]>,
) {
    let Some(sink) = diagnostic_sink else {
        return;
    };
    let stage = match code {
        TerminalCode::Cancelled => NcmRecallDiagnosticStage::PostDispatchCancellation,
        TerminalCode::DeadlineExceeded => NcmRecallDiagnosticStage::PostDispatchDeadline,
        _ => return,
    };
    emit_recall_diagnostic(
        Some(sink),
        diagnostic_for_control_terminal(
            call,
            instance,
            reply.state_generation,
            stage,
            diagnostic_key,
        ),
    );
}

fn diagnostic_for_control_terminal(
    call: &ProviderCall,
    instance: &str,
    state_generation: u64,
    stage: NcmRecallDiagnosticStage,
    diagnostic_key: Option<&[u8; 32]>,
) -> NcmRecallDiagnosticEvent {
    let request = serde_json::from_slice::<Value>(&call.payload.bytes).unwrap_or(Value::Null);
    let max_candidates = request["budgets"]["maximum_candidates"]
        .as_u64()
        .unwrap_or(0)
        .min(RECALL_DIAGNOSTIC_MAX_ITEMS as u64) as usize;
    let max_total = request["budgets"]["maximum_total_content_bytes"]
        .as_u64()
        .unwrap_or(0);
    RecallDiagnosticAccumulator::new().finish(
        call,
        instance,
        &request,
        stage,
        state_generation,
        diagnostic_key,
        max_candidates,
        max_total,
        0,
        0,
        0,
    )
}

fn authorized_worker_row(call: &ProviderCall, row: &Value) -> Option<(Value, SourceAttribution)> {
    let retained = decode_capsule_bounded(&row["provenance"], RECALL_DIAGNOSTIC_MAX_CAPSULE_BYTES)?;
    let source = attribution(&retained["original_source"])?;
    if !same_checkout(&scope(&retained["delivery_scope"])?, &call.exact_scope) {
        return None;
    }
    let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
    validate_source_binding(
        &namespace,
        &source,
        &row["provenance"],
        row["source"].as_str()?,
    )?;
    if let OriginScopeEvidence::Recorded { scope, .. } = &source.origin_scope
        && !same_checkout(scope, &call.exact_scope)
    {
        return None;
    }
    Some((retained, source))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod recall_diagnostic_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracedecay_memory_provider_api::{
        CancellationToken, CommittedEffectEvidence, FallbackDirective, OperationControl,
        OwnedProviderId, OwnedVersionedId, ProviderCallParts, ProviderOperation, ProviderReply,
        TerminalRecord,
    };

    struct RecordingSink(Mutex<Vec<NcmRecallDiagnosticEvent>>);

    const DIAGNOSTIC_KEY: [u8; 32] = [0xa5; 32];
    // Independent Python hashlib/hmac computation for DIAGNOSTIC_KEY, the
    // diagnostic-session namespace, and the query domain/value below.
    const EXPECTED_QUERY_HMAC: &str =
        "a3d33c05e33d4b614723953e4fd22d9b9cb9ace09eac999ea3ef9bd4b7191aa5";

    impl NcmRecallDiagnosticSink for RecordingSink {
        fn record(&self, event: NcmRecallDiagnosticEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn exact_scope_with_session(session: &str) -> OwnedExactScope {
        OwnedExactScope::new(
            "profile",
            "project",
            "repository",
            "worktree",
            "master",
            session,
            format!("sha256:{}", "ab".repeat(32)),
        )
        .unwrap()
    }

    fn exact_scope() -> OwnedExactScope {
        exact_scope_with_session("diagnostic-session")
    }

    fn call_for_scope(scope: OwnedExactScope) -> ProviderCall {
        let value = json!({"query":"private query marker", "budgets": {"maximum_candidates": 4, "maximum_total_content_bytes": 8192}});
        let bytes = serde_json::to_vec(&value).unwrap();
        ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Recall,
            provider_id: OwnedProviderId::new(crate::NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "11".repeat(32),
            exact_scope: scope,
            request_id: "private request marker".to_owned(),
            operation_id: "private operation marker".to_owned(),
            expected_state_generation: 7,
            idempotency_key: None,
            control: OperationControl::new(i64::MAX, 60_000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new("tracedecay.memory.provider.recall.v1").unwrap(),
                bytes.clone(),
                hex_digest(&Sha256::digest(&bytes)),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new("recall.query.v1").unwrap()],
            extensions: Vec::new(),
        })
        .unwrap()
    }

    fn call() -> ProviderCall {
        call_for_scope(exact_scope())
    }

    fn original_source(call: &ProviderCall, sequence: u64) -> Value {
        original_source_in(&call.exact_scope, sequence)
    }

    fn original_source_in(origin: &OwnedExactScope, sequence: u64) -> Value {
        json!({
            "source": {
                "canonical_provider_id": "claude",
                "canonical_session_id": "private-session",
                "source_key": format!("private-source-{sequence}"),
                "stable_record_id": format!("private-record-{sequence}"),
                "observation_id": format!("private-observation-{sequence}"),
                "source_revision": format!("private-revision-{sequence}"),
                "content_sha256": "cd".repeat(32)
            },
            "origin_scope": {
                "state": "recorded",
                "exact_scope_identity": scope_value(origin),
                "authority_ref": "private-authority"
            },
            "source_sequence": sequence,
            "occurred_at": "2026-01-01T00:00:00Z",
            "ingested_at": "2026-01-01T00:00:00Z",
            "validity": {
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": null,
                "superseded_at": null,
                "superseded_by": null,
                "revoked_at": null
            }
        })
    }

    fn worker_row(call: &ProviderCall, sequence: u64, content: &str, activation: f64) -> Value {
        worker_row_delivered(call, &call.exact_scope, sequence, content, activation)
    }

    /// A row the worker retained from a delivery under `delivery`, returned
    /// to a recall issued by `call`.
    fn worker_row_delivered(
        call: &ProviderCall,
        delivery: &OwnedExactScope,
        sequence: u64,
        content: &str,
        activation: f64,
    ) -> Value {
        let original = original_source_in(delivery, sequence);
        let source = attribution(&original).unwrap();
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let binding = source_binding(&namespace, &source).unwrap();
        let retained = json!({
            "original_source": original,
            "delivery_scope": scope_value(delivery),
            "projection": {"key_text": content, "value_text": content},
            "source_refs": [format!("private-ref-{sequence}")]
        });
        let retained_bytes = serde_json::to_vec(&retained).unwrap();
        let capsule_digest = hex_digest(&Sha256::digest(&retained_bytes));
        let stable = stable_reference(&namespace, sequence, &capsule_digest);
        let request_token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
        let mut candidate_digest = Sha256::new();
        for field in [request_token.as_bytes(), stable.as_bytes()] {
            candidate_digest.update((field.len() as u64).to_be_bytes());
            candidate_digest.update(field);
        }
        let candidate_id = format!("ncm-candidate:{}", hex_digest(&candidate_digest.finalize()));
        json!({
            "record_id": sequence,
            "source": binding.source_id,
            "stable_memory_ref": stable,
            "candidate_id": candidate_id,
            "key_text": content,
            "value_text": content,
            "activation": activation,
            "provenance": {
                "source_binding": binding.provenance(),
                "common_capsule": {
                    "version": 1,
                    "bytes": retained_bytes,
                    "sha256": capsule_digest
                }
            }
        })
    }

    fn canonical_budgets() -> Value {
        json!({
            "maximum_candidates": 8,
            "maximum_candidate_content_bytes": 8192,
            "maximum_total_content_bytes": 16384,
            "maximum_source_refs_per_candidate": 4,
            "maximum_trace_refs_per_candidate": 4,
            "maximum_warnings": 4,
            "maximum_extensions_per_candidate": 4
        })
    }

    fn canonical_exclusions() -> Value {
        json!({
            "stable_memory_refs": [],
            "candidate_ids": [],
            "source_refs": [],
            "trace_refs": [],
            "observation_ids": [],
            "content_sha256": []
        })
    }

    fn canonical_temporal(mode: &str) -> Value {
        match mode {
            "current" | "history" => json!({
                "mode": mode,
                "evaluation_time": "2026-01-02T00:00:00Z",
                "as_of": null,
                "interval_start": null,
                "interval_end": null,
                "include_superseded": true,
                "include_revoked": true,
                "unknown_validity_policy": "degrade"
            }),
            "as_of" => json!({
                "mode": mode,
                "evaluation_time": "2026-01-02T00:00:00Z",
                "as_of": "2026-01-01T12:00:00Z",
                "interval_start": null,
                "interval_end": null,
                "include_superseded": true,
                "include_revoked": true,
                "unknown_validity_policy": "degrade"
            }),
            "interval" => json!({
                "mode": mode,
                "evaluation_time": "2026-01-02T00:00:00Z",
                "as_of": null,
                "interval_start": "2025-12-31T00:00:00Z",
                "interval_end": "2026-01-03T00:00:00Z",
                "include_superseded": true,
                "include_revoked": true,
                "unknown_validity_policy": "degrade"
            }),
            _ => Value::Null,
        }
    }

    fn canonical_request(
        temporal_query: Value,
        budgets: Value,
        exclusions: Value,
        remaining_millis: u64,
    ) -> Value {
        json!({
            "provider_id": crate::NCM_PROVIDER_ID,
            "registration_revision": 1,
            "ready_receipt_digest": "11".repeat(32),
            "exact_scope_identity": scope_value(&exact_scope()),
            "request_identity": "canonical-request",
            "objective": "canonical recall objective",
            "query": "canonical recall query",
            "temporal_query": temporal_query,
            "budgets": budgets,
            "exclusions": exclusions,
            "required_capabilities": ["recall.query.v1"],
            "policy_revision": 3,
            "extensions": [],
            "deadline": {
                "deadline_utc_micros": i64::MAX,
                "remaining_millis": remaining_millis
            },
            "cancellation": "live"
        })
    }

    fn canonical_call(request: &Value, remaining_millis: u64) -> ProviderCall {
        let bytes = serde_json::to_vec(request).unwrap();
        ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Recall,
            provider_id: OwnedProviderId::new(crate::NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "11".repeat(32),
            exact_scope: exact_scope(),
            request_id: "canonical-request".to_owned(),
            operation_id: "canonical-operation".to_owned(),
            expected_state_generation: 7,
            idempotency_key: None,
            control: OperationControl::new(i64::MAX, remaining_millis, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new("tracedecay.memory.provider.recall.v1").unwrap(),
                bytes.clone(),
                hex_digest(&Sha256::digest(&bytes)),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new("recall.query.v1").unwrap()],
            extensions: Vec::new(),
        })
        .unwrap()
    }

    fn worker_reply(call: &ProviderCall, worker: &Value) -> ProviderReply {
        let bytes = serde_json::to_vec(worker).unwrap();
        let terminal = TerminalRecord::new(
            ProviderOperation::Recall,
            call.provider_id.clone(),
            TerminalCode::Success,
            CommittedEffectEvidence::none(Some(call.expected_state_generation)),
            FallbackDirective::forbidden(),
            &call.operation_id,
            call.exact_scope.exact_scope_sha256(),
            None,
        )
        .unwrap();
        ProviderReply {
            terminal,
            payload: Some(
                CanonicalPayload::new(
                    call.payload.contract_id.clone(),
                    bytes.clone(),
                    hex_digest(&Sha256::digest(&bytes)),
                )
                .unwrap(),
            ),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: call.expected_state_generation,
        }
    }

    #[test]
    fn recall_projection_binds_low_item_byte_and_work_budgets() {
        let mut budgets = canonical_budgets();
        budgets["maximum_candidates"] = json!(1);
        budgets["maximum_candidate_content_bytes"] = json!(1);
        budgets["maximum_total_content_bytes"] = json!(1);
        let request = canonical_request(
            canonical_temporal("current"),
            budgets,
            canonical_exclusions(),
            17,
        );
        let call = canonical_call(&request, 17);
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let projected = project_recall(&call, &request, &namespace).expect("projection");
        assert_eq!(projected["top_k"], json!(1));
        assert_eq!(projected["selection"]["maximum_candidates"], json!(1));

        let mut widened_deadline = request.clone();
        widened_deadline["deadline"]["remaining_millis"] = json!(18);
        assert!(project_recall(&call, &widened_deadline, &namespace).is_none());
        let mut remapped_request = request;
        remapped_request["request_identity"] = json!("other-request");
        assert!(project_recall(&call, &remapped_request, &namespace).is_none());
    }

    #[test]
    fn recall_projection_rejects_every_zero_budget_before_worker_dispatch() {
        for field in BUDGETS {
            let mut budgets = canonical_budgets();
            budgets[*field] = json!(0);
            let request = canonical_request(
                canonical_temporal("current"),
                budgets,
                canonical_exclusions(),
                60_000,
            );
            let call = canonical_call(&request, 60_000);
            let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
            assert!(
                project_recall(&call, &request, &namespace).is_none(),
                "zero budget {field} reached the worker"
            );
        }
    }

    #[test]
    fn recall_projection_forwards_every_temporal_selector() {
        for mode in ["current", "as_of", "interval", "history"] {
            let temporal_query = canonical_temporal(mode);
            let request = canonical_request(
                temporal_query.clone(),
                canonical_budgets(),
                canonical_exclusions(),
                60_000,
            );
            let call = canonical_call(&request, 60_000);
            let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
            let projected = project_recall(&call, &request, &namespace).expect("projection");
            let selection = &projected["selection"];
            let parsed = temporal(&temporal_query).expect("temporal query");
            assert_eq!(selection["mode"], json!(mode));
            assert_eq!(
                selection["evaluation"],
                json!(parsed.evaluation_time_utc_nanos)
            );
            assert_eq!(
                selection["as_of"],
                parsed
                    .as_of_utc_nanos
                    .map_or(Value::Null, |value| json!(value))
            );
            assert_eq!(
                selection["start"],
                parsed
                    .interval_start_utc_nanos
                    .map_or(Value::Null, |value| json!(value))
            );
            assert_eq!(
                selection["end"],
                parsed
                    .interval_end_utc_nanos
                    .map_or(Value::Null, |value| json!(value))
            );
            assert_eq!(selection["include_superseded"], json!(true));
            assert_eq!(selection["include_revoked"], json!(true));
            assert_eq!(selection["unknown_policy"], json!("degrade"));
        }
    }

    #[test]
    fn recall_projection_namespaces_every_exclusion_class() {
        let content_digest = "ab".repeat(32);
        let exclusions = json!({
            "stable_memory_refs": ["stable-ref"],
            "candidate_ids": ["candidate-id"],
            "source_refs": ["source-ref"],
            "trace_refs": ["trace-ref"],
            "observation_ids": ["observation-id"],
            "content_sha256": [content_digest.clone()]
        });
        let request = canonical_request(
            canonical_temporal("current"),
            canonical_budgets(),
            exclusions,
            60_000,
        );
        let call = canonical_call(&request, 60_000);
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let projected = project_recall(&call, &request, &namespace).expect("projection");
        for (name, value) in [
            ("stable_memory_refs", "stable-ref"),
            ("candidate_ids", "candidate-id"),
            ("source_refs", "source-ref"),
            ("trace_refs", "trace-ref"),
            ("observation_ids", "observation-id"),
            ("content_sha256", content_digest.as_str()),
        ] {
            let expected = opaque_surface_id(&namespace, name.as_bytes(), value);
            assert_eq!(
                projected["selection"]["exclusions"][name][0],
                json!(expected),
                "exclusion class {name} was not bound"
            );
        }
    }

    #[test]
    fn recall_reconstruction_preserves_provenance_and_explicitly_has_no_cursor() {
        let mut budgets = canonical_budgets();
        budgets["maximum_candidate_content_bytes"] = json!(1);
        budgets["maximum_total_content_bytes"] = json!(1);
        let request = canonical_request(
            canonical_temporal("current"),
            budgets,
            canonical_exclusions(),
            60_000,
        );
        let call = canonical_call(&request, 60_000);
        let row = worker_row(&call, 42, "aé", 0.8);
        let worker = json!({
            "common_recall": {
                "candidates": [row],
                "truncated": false,
                "unknown_items": 0,
                "excluded_items": 0,
                "scanned_items": 1,
                "score_upper_bound": 1.0
            }
        });
        let mut reply = worker_reply(&call, &worker);
        reconstruct_recall(&call, "ncm.instance.contract", &mut reply)
            .expect("reconstruction");
        assert_eq!(
            reply.payload.as_ref().unwrap().contract_id.as_str(),
            RECALL_RESULT_CONTRACT_ID
        );
        let output: Value = serde_json::from_slice(&reply.payload.as_ref().unwrap().bytes).unwrap();
        assert_eq!(output["request_identity"], json!(call.request_id));
        assert_eq!(
            output["exact_scope_identity"],
            scope_value(&call.exact_scope)
        );
        assert_eq!(output["coverage"]["next_cursor"], Value::Null);
        assert_eq!(output["coverage"]["state"], json!("partial"));
        assert_eq!(output["coverage"]["truncated_items"], json!(1));
        let candidate = &output["candidates"][0];
        assert_eq!(candidate["content"], json!("a"));
        assert_eq!(
            candidate["content_sha256"],
            json!(hex_digest(&Sha256::digest(b"a")))
        );
        assert_eq!(
            candidate["provenance"]["original_sources"][0],
            original_source(&call, 42)
        );
        assert_eq!(
            candidate["provenance"]["source_refs"],
            json!(["private-ref-42"])
        );
        assert_eq!(candidate["trace_refs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn recall_answers_any_session_of_the_checkout_and_refuses_another_checkout() {
        let request = canonical_request(
            canonical_temporal("current"),
            canonical_budgets(),
            canonical_exclusions(),
            60_000,
        );
        let call = canonical_call(&request, 60_000);
        let earlier_session = exact_scope_with_session("earlier-session");
        let worker = |row: Value| {
            json!({
                "common_recall": {
                    "candidates": [row],
                    "truncated": false,
                    "unknown_items": 0,
                    "excluded_items": 0,
                    "scanned_items": 1,
                    "score_upper_bound": 1.0
                }
            })
        };
        let mut reply = worker_reply(
            &call,
            &worker(worker_row_delivered(
                &call,
                &earlier_session,
                7,
                "earlier session evidence",
                0.9,
            )),
        );
        reconstruct_recall(&call, "ncm.instance.contract", &mut reply)
            .expect("another session of this checkout is recallable");
        let output: Value = serde_json::from_slice(&reply.payload.as_ref().unwrap().bytes).unwrap();
        let candidate = &output["candidates"][0];
        assert_eq!(candidate["content"], json!("earlier session evidence"));
        assert_eq!(
            candidate["exact_scope_identity"],
            checkout_scope_value(&call.exact_scope)
        );
        assert_eq!(
            candidate["exact_scope_identity"]["scope_binding"],
            json!("checkout_observations")
        );
        assert_eq!(
            candidate["provenance"]["original_sources"][0],
            original_source_in(&earlier_session, 7),
            "the original session's attribution is preserved, never relabelled"
        );

        let mut other_checkout = earlier_session.clone();
        other_checkout.branch_identity = "refs/heads/another-checkout".to_owned();
        let mut foreign = worker_reply(
            &call,
            &worker(worker_row_delivered(
                &call,
                &other_checkout,
                8,
                "another checkout's evidence",
                0.9,
            )),
        );
        assert!(
            reconstruct_recall(&call, "ncm.instance.contract", &mut foreign).is_none(),
            "a row delivered for another checkout is never re-scoped into this one"
        );
    }

    #[test]
    fn diagnostic_sink_localizes_four_worker_rows_to_two_reconstructed_rows() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 8192,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let rows = (2..=5)
            .map(|sequence| {
                worker_row(
                    &call,
                    sequence,
                    &format!("private content marker {sequence}"),
                    1.0 - (sequence as f64 / 100.0),
                )
            })
            .collect::<Vec<_>>();
        let worker = json!({
            "common_recall": {
                "candidates": rows,
                "excluded_items": 0,
                "truncated_items": 0,
                "unknown_items": 0,
                "score_upper_bound": 1.0
            }
        });
        let raw = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        let reconstructed = json!({
            "candidates": [
                {"content":"private content marker 4", "native_score":{"raw_value":"0.96"}, "provenance":{"original_sources":[original_source(&call, 4)]}},
                {"content":"private content marker 5", "native_score":{"raw_value":"0.95"}, "provenance":{"original_sources":[original_source(&call, 5)]}}
            ]
        });
        let post = diagnostic_for_reconstructed(
            &call,
            "private-provider-instance",
            &request,
            &reconstructed,
            4,
            8192,
            0,
            7,
            NcmRecallDiagnosticStage::Reconstructed,
            0,
            0,
            0,
            Some(&DIAGNOSTIC_KEY),
        );
        let sink = Arc::new(RecordingSink(Mutex::new(Vec::new())));
        emit_recall_diagnostic(Some(sink.as_ref()), raw.clone());
        emit_recall_diagnostic(Some(sink.as_ref()), post.clone());
        let events = sink.0.lock().unwrap();
        assert_eq!(events.as_slice(), [raw.clone(), post.clone()]);
        assert_eq!(raw.stage, NcmRecallDiagnosticStage::Worker);
        assert_eq!(raw.candidate_count, 4);
        assert_eq!(raw.candidate_ranks, [1, 2, 3, 4]);
        assert_eq!(post.stage, NcmRecallDiagnosticStage::Reconstructed);
        assert_eq!(post.candidate_count, 2);
        assert_eq!(post.candidate_ranks, [1, 2]);
        assert_eq!(raw.state_generation, post.state_generation);
        assert_eq!(raw.request_id_sha256, post.request_id_sha256);
        assert_eq!(raw.query_sha256, post.query_sha256);
        assert_eq!(
            raw.remaining_content_bytes,
            8192 - raw.candidate_content_bytes.iter().sum::<u64>()
        );
        assert_eq!(
            post.remaining_content_bytes,
            8192 - post.candidate_content_bytes.iter().sum::<u64>()
        );
    }

    #[test]
    fn diagnostic_event_contains_digests_and_counts_but_no_private_values() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 8192,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let rows = vec![worker_row(&call, 91_000_007, "private content marker", 0.5)];
        let worker = json!({"common_recall":{"candidates":rows,"excluded_items":1,"truncated_items":2,"unknown_items":3,"score_upper_bound":1.0}});
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        let debug = format!("{event:?}");
        for private_value in [
            "private query marker",
            "private content marker",
            "private request marker",
            "private operation marker",
            "private-source-91000007",
            "private-record-91000007",
            "private-observation-91000007",
            "private-provider-instance",
            "91000007",
        ] {
            assert!(
                !debug.contains(private_value),
                "diagnostic leaked {private_value}"
            );
        }
        for digest in [
            &event.request_id_sha256,
            &event.operation_id_sha256,
            &event.query_sha256,
            &event.exact_scope_sha256,
            &event.provider_instance_sha256,
        ] {
            let digest = digest.as_ref().expect("keyed digest");
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(event.excluded_count, 1);
        assert_eq!(event.truncated_count, 2);
        assert_eq!(event.unknown_count, 3);
    }

    #[test]
    fn diagnostic_identity_is_unlinkable_across_checkouts() {
        let call_a = call_for_scope(exact_scope_with_session("diagnostic-session-a"));
        // Sessions of one checkout share NCM's memory and its namespace.
        let same_checkout = call_for_scope(exact_scope_with_session("diagnostic-session-b"));
        assert_eq!(
            NcmNamespace::from_exact_scope(&call_a.exact_scope),
            NcmNamespace::from_exact_scope(&same_checkout.exact_scope)
        );
        let mut other_checkout = exact_scope_with_session("diagnostic-session-b");
        other_checkout.branch_identity = "refs/heads/diagnostic-other-checkout".to_owned();
        let call_b = call_for_scope(other_checkout);
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 8192,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let worker_a = json!({"common_recall":{"candidates":[worker_row(
            &call_a,
            91_000_007,
            "private content marker",
            0.5
        )],"score_upper_bound":1.0}});
        let worker_b = json!({"common_recall":{"candidates":[worker_row(
            &call_b,
            91_000_007,
            "private content marker",
            0.5
        )],"score_upper_bound":1.0}});
        let event_a = diagnostic_for_worker(
            &call_a,
            "private-provider-instance",
            &request,
            &worker_a,
            worker_a["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        let event_b = diagnostic_for_worker(
            &call_b,
            "private-provider-instance",
            &request,
            &worker_b,
            worker_b["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_ne!(event_a.namespace_sha256, event_b.namespace_sha256);
        assert_ne!(event_a.request_id_sha256, event_b.request_id_sha256);
        assert_ne!(event_a.operation_id_sha256, event_b.operation_id_sha256);
        assert_ne!(event_a.query_sha256, event_b.query_sha256);
        assert_ne!(event_a.exact_scope_sha256, event_b.exact_scope_sha256);
        assert_ne!(
            event_a.provider_instance_sha256,
            event_b.provider_instance_sha256
        );
        for event in [event_a, event_b] {
            let debug = format!("{event:?}");
            assert!(!debug.contains("private query marker"));
            assert!(!debug.contains("private content marker"));
            assert!(!debug.contains("91000007"));
        }
    }

    #[test]
    fn diagnostic_key_is_required_for_reversible_identity_fingerprints() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 8192,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let rows = vec![worker_row(&call, 17, "private content marker", 0.5)];
        let worker = json!({"common_recall":{"candidates":rows,"score_upper_bound":1.0}});
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            None,
        );
        assert!(event.request_id_sha256.is_none());
        assert!(event.operation_id_sha256.is_none());
        assert!(event.query_sha256.is_none());
        assert!(event.exact_scope_sha256.is_none());
        assert!(event.namespace_sha256.is_none());
        assert!(event.provider_instance_sha256.is_none());
        let debug = format!("{event:?}");
        assert!(!debug.contains("private query marker"));
        assert!(!debug.contains("private content marker"));
    }

    fn namespace_keyed_public_hmac(namespace: &str, domain: &[u8], value: &[u8]) -> String {
        let mut key_block = [0_u8; 64];
        key_block[..namespace.len()].copy_from_slice(namespace.as_bytes());
        let mut inner_pad = [0_u8; 64];
        let mut outer_pad = [0_u8; 64];
        for index in 0..key_block.len() {
            inner_pad[index] = key_block[index] ^ 0x36;
            outer_pad[index] = key_block[index] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        inner.update(domain);
        digest_field(&mut inner, value);
        let inner_result = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(outer_pad);
        outer.update(inner_result);
        hex_digest(&outer.finalize())
    }

    #[test]
    fn diagnostic_query_fingerprint_is_not_a_dictionary_recoverable_sha256() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 8192,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let rows = vec![worker_row(&call, 18, "private content marker", 0.5)];
        let worker = json!({"common_recall":{"candidates":rows,"score_upper_bound":1.0}});
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            8192,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        assert_eq!(event.namespace_sha256.as_deref(), Some(namespace.as_str()));
        assert_eq!(event.query_sha256.as_deref(), Some(EXPECTED_QUERY_HMAC));

        let wrong_key = [0xa6; 32];
        let wrong_key_digest = diagnostic_digest(
            Some(&wrong_key),
            &namespace,
            RECALL_DIAGNOSTIC_QUERY_DOMAIN,
            b"private query marker",
        )
        .expect("wrong-key digest");
        assert_ne!(wrong_key_digest, EXPECTED_QUERY_HMAC);

        let public_namespace_digest = namespace_keyed_public_hmac(
            namespace.as_str(),
            RECALL_DIAGNOSTIC_QUERY_DOMAIN,
            b"private query marker",
        );
        assert_ne!(public_namespace_digest, EXPECTED_QUERY_HMAC);

        let mut plain = Sha256::new();
        plain.update(RECALL_DIAGNOSTIC_QUERY_DOMAIN);
        digest_field(
            &mut plain,
            event
                .namespace_sha256
                .as_deref()
                .expect("keyed namespace")
                .as_bytes(),
        );
        digest_field(&mut plain, b"private query marker");
        let plain = hex_digest(&plain.finalize());
        assert_ne!(event.query_sha256.as_deref(), Some(plain.as_str()));
    }

    #[test]
    fn worker_diagnostic_uses_the_reconstruction_utf8_budget_boundary() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidate_content_bytes": 2,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let content = "aéclair";
        assert_eq!(utf8_budget_boundary(content, 2), 1);
        let rows = vec![worker_row(&call, 19, content, 0.5)];
        let worker = json!({"common_recall":{"candidates":rows,"score_upper_bound":1.0}});
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            2,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_eq!(event.candidate_content_bytes, [content.len() as u64]);
        assert_eq!(event.remaining_content_bytes, 1);
    }

    #[test]
    fn worker_remaining_budget_ignores_excluded_and_overbudget_row_content_bytes() {
        let call = call();
        let excluded_content = "x".repeat(128);
        let overbudget_content = "y".repeat(128);
        let retained_content = "kept";
        let excluded = worker_row(&call, 91_000_007, &excluded_content, 0.9);
        let mut overbudget = worker_row(&call, 91_000_008, &overbudget_content, 0.8);
        let mut overbudget_retained = decode_capsule(&overbudget["provenance"]).unwrap();
        overbudget_retained["source_refs"] = json!(["private-ref-a", "private-ref-b"]);
        let overbudget_bytes = serde_json::to_vec(&overbudget_retained).unwrap();
        let overbudget_digest = hex_digest(&Sha256::digest(&overbudget_bytes));
        overbudget["provenance"]["common_capsule"]["bytes"] = json!(overbudget_bytes);
        overbudget["provenance"]["common_capsule"]["sha256"] = json!(overbudget_digest);
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let overbudget_stable = stable_reference(&namespace, 91_000_008, &overbudget_digest);
        overbudget["stable_memory_ref"] = json!(overbudget_stable);
        let request_token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
        let mut candidate_digest = Sha256::new();
        for field in [request_token.as_bytes(), overbudget_stable.as_bytes()] {
            candidate_digest.update((field.len() as u64).to_be_bytes());
            candidate_digest.update(field);
        }
        overbudget["candidate_id"] = json!(format!(
            "ncm-candidate:{}",
            hex_digest(&candidate_digest.finalize())
        ));
        let excluded_stable = excluded["stable_memory_ref"].as_str().unwrap().to_owned();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidates": 4,
                "maximum_candidate_content_bytes": 128,
                "maximum_source_refs_per_candidate": 1
            },
            "exclusions": {
                "stable_memory_refs": [excluded_stable],
                "candidate_ids": [],
                "source_refs": [],
                "trace_refs": [],
                "observation_ids": [],
                "content_sha256": []
            }
        });
        let rows = vec![
            excluded,
            overbudget,
            worker_row(&call, 91_000_009, retained_content, 0.7),
        ];
        let worker = json!({
            "common_recall": {
                "candidates": rows,
                "excluded_items": 1,
                "truncated_items": 1,
                "unknown_items": 0,
                "score_upper_bound": 1.0
            }
        });
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            4,
            64,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_eq!(event.candidate_content_bytes, [128, 128, 4]);
        assert_eq!(
            event.remaining_content_bytes,
            64 - retained_content.len() as u64
        );
    }

    #[test]
    fn worker_remaining_budget_streams_past_the_sample_for_invalid_rows() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidates": 1,
                "maximum_candidate_content_bytes": 64,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let mut rows = (0..17)
            .map(|sequence| {
                let mut row = worker_row(&call, sequence, "invalid", 0.9);
                row["provenance"] = json!({});
                row
            })
            .collect::<Vec<_>>();
        rows.push(worker_row(&call, 17, "kept", 0.8));
        let worker = json!({"common_recall":{"candidates":rows,"score_upper_bound":1.0}});
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            1,
            64,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_eq!(event.candidate_count, 18);
        assert_eq!(event.candidate_ranks.len(), 16);
        assert_eq!(event.remaining_candidate_slots, 0);
        assert_eq!(event.remaining_content_bytes, 60);
    }

    #[test]
    fn worker_budget_admission_matches_reconstruction_validation() {
        let call = call();
        let request = json!({
            "query": "private query marker",
            "budgets": {
                "maximum_candidates": 1,
                "maximum_candidate_content_bytes": 64,
                "maximum_source_refs_per_candidate": 1
            }
        });
        let mut missing_activation = worker_row(&call, 20, "missing", 0.9);
        missing_activation["activation"] = Value::Null;
        let mut invalid_patch = worker_row(&call, 21, "patched", 0.8);
        invalid_patch["provenance"]["control"] = json!({
            "validity_patch": {"valid_from": "not-an-rfc3339-instant"}
        });
        let valid = worker_row(&call, 22, "valid", 0.7);
        let worker = json!({
            "common_recall": {
                "candidates": [missing_activation, invalid_patch, valid],
                "score_upper_bound": 1.0
            }
        });
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &worker,
            worker["common_recall"]["candidates"].as_array().unwrap(),
            1,
            64,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_eq!(event.candidate_count, 3);
        assert_eq!(event.remaining_candidate_slots, 0);
        assert_eq!(event.remaining_content_bytes, 59);

        let invalid_upper_bound = json!({
            "common_recall": {
                "candidates": [worker_row(&call, 23, "valid", 0.7)],
                "score_upper_bound": "1.0"
            }
        });
        let event = diagnostic_for_worker(
            &call,
            "private-provider-instance",
            &request,
            &invalid_upper_bound,
            invalid_upper_bound["common_recall"]["candidates"]
                .as_array()
                .unwrap(),
            1,
            64,
            7,
            Some(&DIAGNOSTIC_KEY),
        );
        assert_eq!(event.remaining_candidate_slots, 1);
        assert_eq!(event.remaining_content_bytes, 64);
    }

    #[test]
    fn retained_attribution_rejects_an_oversized_named_capsule_before_dispatch() {
        let call = call();
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let canonical = json!({
            "command": "build",
            "outcome_summary": "passed",
            "ignored_retained_metadata": "x".repeat(MAX_NAMED_CAPSULE_BYTES)
        });
        let observation = json!({
            "observation_kind": "tool.execution_settled.v1",
            "canonical_payload": canonical,
            "source_identity": {"original_source": original_source(&call, 1)}
        });
        assert!(project_attribution(&call, &observation, &namespace).is_none());
    }

    #[test]
    fn evidence_text_covers_every_advertised_observation_kind() {
        let cases = [
            (
                "session.message_committed.v1",
                json!({"role": "assistant", "content": "ready"}),
            ),
            (
                "tool.execution_settled.v1",
                json!({"command": "cargo test", "outcome_summary": "passed"}),
            ),
            (
                "source.edit_settled.v1",
                json!({"change_summary": "updated adapter", "result_summary": "applied"}),
            ),
            (
                "test.execution_settled.v1",
                json!({"test_name": "adapter boundary", "outcome_summary": "passed"}),
            ),
            (
                "diagnostic.observed.v1",
                json!({"code": "E0001", "message": "fixed"}),
            ),
            (
                "git.evidence_observed.v1",
                json!({"commit": "abc123", "message": "landed"}),
            ),
            (
                "native.fact_promoted.v1",
                json!({"subject": "adapter", "fact": "bounded"}),
            ),
            (
                "feedback.outcome_settled.v1",
                json!({"action": "retain", "outcome_summary": "helpful"}),
            ),
            (
                "automation.outcome_settled.v1",
                json!({"job": "nightly", "outcome_summary": "complete"}),
            ),
        ];
        for (kind, payload) in cases {
            let (key, value) = evidence_text(kind, &payload).expect("advertised kind");
            assert!(!key.is_empty(), "empty key for {kind}");
            assert!(!value.is_empty(), "empty value for {kind}");
        }
    }
}
