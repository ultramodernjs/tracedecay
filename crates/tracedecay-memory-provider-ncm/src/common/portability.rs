//! Canonical portability over the private NCM snapshot and observation formats.

use super::*;
use std::collections::BTreeMap;
use tracedecay_memory_provider_api::{
    ProviderDescriptor, ProviderLimits, ProviderOperation, ReplayAccounting,
};

const MAX_ITEMS: usize = 4096;
const SNAPSHOT_FORMAT: &str = "ncm-snapshot.v1";

pub(crate) fn project(
    call: &ProviderCall,
    value: &Value,
    namespace: &NcmNamespace,
    admission: Option<&CurrentAdvisoryAdmission>,
    descriptor: &ProviderDescriptor,
    limits: ProviderLimits,
) -> Option<Option<Value>> {
    if !matches!(
        call.operation,
        ProviderOperation::SnapshotExport
            | ProviderOperation::SnapshotRestore
            | ProviderOperation::Replay
    ) || value.get("common_request").is_none()
    {
        return Some(None);
    }
    super::lifecycle::common_context(call, &value["common_request"])?;
    let mut control = json!({"action":call.operation.as_wire(),"expected_generation":call.expected_state_generation});
    match call.operation {
        ProviderOperation::SnapshotExport => fields(value, &["common_request"])?,
        ProviderOperation::SnapshotRestore => {
            fields(
                value,
                &[
                    "common_request",
                    "snapshot",
                    "disposition_checkpoint",
                    "source_dispositions",
                ],
            )?;
            let snapshot = &value["snapshot"];
            fields(snapshot, &["identity", "bytes", "sources"])?;
            let bytes = byte_array(&snapshot["bytes"], limits.snapshot_bytes)?;
            let inventory = snapshot_inventory(&bytes, namespace, &call.exact_scope)?;
            validate_snapshot_identity(
                call,
                &snapshot["identity"],
                descriptor,
                &bytes,
                &inventory,
            )?;
            let declared = snapshot["sources"].as_array()?;
            if declared.len() != inventory.sources.len()
                || canonical_sources(declared)? != canonical_sources(&inventory.wire_sources)?
            {
                return None;
            }
            let admitted = admission?;
            admitted.verify_for(call).ok()?;
            let current = admitted.restore.as_ref()?;
            current.verify_inventory(&inventory.sources).ok()?;
            for source in &inventory.attributions {
                if let OriginScopeEvidence::Recorded { scope, .. } = &source.origin_scope
                    && scope != &call.exact_scope
                    && !admitted
                        .history_sources
                        .iter()
                        .any(|entry| entry.attribution == *source)
                {
                    return None;
                }
            }
            validate_checkpoint(&value["disposition_checkpoint"], &call.exact_scope)?;
            let dispositions = value["source_dispositions"].as_array()?;
            let mut declared_dispositions = Vec::new();
            for item in dispositions {
                fields(item, &["source", "current_disposition"])?;
                validate_disposition(&item["current_disposition"])?;
                declared_dispositions.push(item["source"].clone());
            }
            if canonical_sources(&declared_dispositions)? != canonical_sources(declared)? {
                return None;
            }
            // The installed authority's fresh result determines which sources
            // are fenced. Wire dispositions only declare checked inventory.
            let mut blocked = BTreeSet::new();
            for (source, disposition) in &current.sources {
                match disposition.state.as_wire() {
                    "available" => {}
                    "superseded" | "revoked" => {
                        let effective = inventory.effective_validities.get(&source_key(source))?;
                        if (disposition.state.as_wire() == "superseded"
                            && effective.superseded_at_utc_nanos.is_none())
                            || (disposition.state.as_wire() == "revoked"
                                && effective.revoked_at_utc_nanos.is_none())
                        {
                            return None;
                        }
                    }
                    "deleted" | "redacted" | "expired" => {
                        let index = inventory.sources.iter().position(|item| item == source)?;
                        let binding = source_binding(namespace, &inventory.attributions[index])?;
                        // A raw-key fence would erase every colliding origin. A
                        // blocked legacy capsule cannot be safely imported.
                        if inventory.stored_source_ids[index] != binding.source_id {
                            return None;
                        }
                        blocked.insert(binding.source_id);
                    }
                    _ => return None,
                }
            }
            control["bytes"] = json!(bytes);
            control["blocked_sources"] = json!(blocked);
            control["snapshot_id"] = snapshot["identity"]["snapshot_id"].clone();
            control["observation_sequence"] = json!(inventory.observation_sequence);
        }
        ProviderOperation::Replay => {
            project_replay(call, value, namespace, admission?, &mut control)?
        }
        _ => return Some(None),
    }
    Some(Some(json!({"common_portability":control})))
}

fn project_replay(
    call: &ProviderCall,
    value: &Value,
    namespace: &NcmNamespace,
    admission: &CurrentAdvisoryAdmission,
    control: &mut Value,
) -> Option<()> {
    fields(
        value,
        &[
            "common_request",
            "observation_batch_refs",
            "first_source_sequence",
            "last_source_sequence",
            "expected_state_generation",
            "expected_previous_acknowledged_sequence",
            "history_grant",
            "resolved_observations",
        ],
    )?;
    admission.verify_for(call).ok()?;
    if value["expected_state_generation"].as_u64()? != call.expected_state_generation {
        return None;
    }
    let refs = strings(&value["observation_batch_refs"])?;
    let refs_set = refs.iter().collect::<BTreeSet<_>>();
    if refs.is_empty() || refs.len() > MAX_ITEMS || refs_set.len() != refs.len() {
        return None;
    }
    let items = value["resolved_observations"].as_array()?;
    let first = value["first_source_sequence"].as_u64()?;
    let last = value["last_source_sequence"].as_u64()?;
    if first == 0
        || items.is_empty()
        || items.len() > MAX_ITEMS
        || last.checked_sub(first)?.checked_add(1)? != items.len() as u64
    {
        return None;
    }
    let grant = &value["history_grant"];
    fields(
        grant,
        &[
            "authorization_ref",
            "policy_revision",
            "destination_scope",
            "relation",
            "sources",
            "disposition_checkpoint",
        ],
    )?;
    string(&grant["authorization_ref"])?;
    if grant["policy_revision"].as_u64()? == 0
        || scope(&grant["destination_scope"])? != call.exact_scope
    {
        return None;
    }
    let exact = match string(&grant["relation"])? {
        "exact_scope" => true,
        "same_checkout" => false,
        _ => return None,
    };
    validate_checkpoint(&grant["disposition_checkpoint"], &call.exact_scope)?;
    let claims = grant["sources"].as_array()?;
    if claims.is_empty() || claims.len() > MAX_ITEMS {
        return None;
    }
    let mut claim_sources = BTreeSet::new();
    for claim in claims {
        fields(claim, &["attribution", "current_disposition"])?;
        let source = attribution(&claim["attribution"])?;
        validate_disposition(&claim["current_disposition"])?;
        if !claim_sources.insert(source_key(&source.source)) {
            return None;
        }
    }
    let mut seen_refs = BTreeSet::new();
    let mut seen_sources = BTreeSet::new();
    let mut projected = Vec::new();
    for (index, item) in items.iter().enumerate() {
        fields(item, &["receipt_ref", "observation"])?;
        let receipt = string(&item["receipt_ref"])?;
        if !refs.iter().any(|candidate| candidate == receipt) || !seen_refs.insert(receipt) {
            return None;
        }
        let observation = &item["observation"];
        let original = observation.pointer("/source_identity/original_source")?;
        let source = attribution(original)?;
        if source.source_sequence != first.checked_add(index as u64)?
            || observation["source_sequence"].as_u64()? != source.source_sequence
            || !seen_sources.insert(source_key(&source.source))
        {
            return None;
        }
        let origin = source.origin_scope.recorded_scope().ok()?;
        if exact && origin != &call.exact_scope {
            return None;
        }
        if !claims.iter().any(|claim| claim["attribution"] == *original) {
            return None;
        }
        let current = admission
            .history_sources
            .iter()
            .find(|entry| entry.attribution == source)?;
        let state = current.current_disposition.state.as_wire();
        let blocked = matches!(state, "deleted" | "redacted" | "expired");
        let eligible = match state {
            "available" => true,
            "superseded" => source.validity.superseded_at_utc_nanos.is_some(),
            "revoked" => source.validity.revoked_at_utc_nanos.is_some(),
            "deleted" | "redacted" | "expired" | "unknown" => false,
            _ => return None,
        };
        let kind = string(&observation["observation_kind"])?;
        let (key_text, value_text) = evidence_text(kind, &observation["canonical_payload"])?;
        let binding = source_binding(namespace, &source)?;
        let source_id = &binding.source_id;
        let delivery_key = opaque_caller_id(
            namespace,
            &call.exact_scope,
            b"replay-delivery-key",
            string(&observation["idempotency_key"])?,
        );
        let provenance = if eligible {
            let mut provenance =
                project_attribution(call, observation, namespace, Some(admission))??;
            let delivery = serde_json::to_vec(&json!({"operation_id":call.operation_id,"idempotency_key":string(&observation["idempotency_key"])?})).ok()?;
            provenance["delivery_capsule"] = json!({"version":1,"sha256":hex_digest(&Sha256::digest(&delivery)),"bytes":delivery});
            provenance
        } else {
            Value::Null
        };
        projected.push(json!({"source_sequence":source.source_sequence,
            "receipt_digest":opaque_surface_id(namespace,b"replay-receipt",receipt),
            "delivery_key":delivery_key,"source":source_id,"legacy_source":binding.legacy_source_id,"admitted":eligible,"blocked":blocked,
            "observation":if eligible { json!({"observation_kind":kind,"payload_contract":observation["payload_contract"],
                "canonical_payload":{"forget_source_key":source_id,"_ncm_key_text":key_text,"_ncm_value_text":value_text},"provenance":provenance}) } else { Value::Null }}));
    }
    if seen_refs.len() != refs.len()
        || seen_sources != claim_sources
        || admission.history_sources.len() != seen_sources.len()
    {
        return None;
    }
    let mut page_delivery = json!({
        "operation_id": call.operation_id,
        "idempotency_key": call.idempotency_key.as_deref()?
    });
    if namespace.1 == NcmNamespaceBinding::CheckoutObservationsV1 {
        page_delivery["caller_binding"] =
            json!({"version": 1, "exact_scope": scope_value(&call.exact_scope)});
    }
    let page_delivery = serde_json::to_vec(&page_delivery).ok()?;
    if page_delivery.len() > 131_072 {
        return None;
    }
    control["page_delivery_capsule"] = json!({"version": 1,
        "sha256": hex_digest(&Sha256::digest(&page_delivery)), "bytes": page_delivery});
    control["items"] = json!(projected);
    for name in [
        "first_source_sequence",
        "last_source_sequence",
        "expected_previous_acknowledged_sequence",
    ] {
        control[name] = json!(value[name].as_u64()?);
    }
    Some(())
}

struct Inventory {
    generation: u64,
    observation_sequence: u64,
    sources: Vec<OriginalSourceIdentity>,
    attributions: Vec<SourceAttribution>,
    stored_source_ids: Vec<String>,
    effective_validities: BTreeMap<String, RecordedValidity>,
    wire_sources: Vec<Value>,
}

/// Reads the runtime's source revocation authority without treating scrubbed
/// tombstones as ordinary source inventory.  A revoked capsule has no retained
/// provenance to authenticate its original source, so the durable revocation
/// row is the only evidence that makes the tombstone meaningful.  Authority
/// rows without a capsule are allowed: a deletion can revoke a source after
/// its last retained record was compacted away.
fn snapshot_revocation_authority(
    snapshot: &Value,
    generation: u64,
) -> Option<BTreeMap<String, (u64, u64)>> {
    let Some(value) = snapshot.get("revocations") else {
        // Snapshots written before revocation authority was exported remain
        // readable as long as they contain no scrubbed tombstones.  The caller
        // rejects a revoked capsule when this field is absent.
        return Some(BTreeMap::new());
    };
    let rows = value.as_array()?;
    if rows.len() > MAX_ITEMS {
        return None;
    }
    let mut authority = BTreeMap::new();
    let mut previous = None;
    for row in rows {
        fields(row, &["source_id", "epoch", "seq"])?;
        let source_id = string(&row["source_id"])?;
        let epoch = row["epoch"].as_u64()?;
        let sequence = row["seq"].as_u64()?;
        if source_id.is_empty()
            || epoch == 0
            || sequence == 0
            || sequence > generation
            || previous.is_some_and(|previous: &str| previous >= source_id)
            || authority
                .insert(source_id.to_owned(), (epoch, sequence))
                .is_some()
        {
            return None;
        }
        previous = Some(source_id);
    }
    Some(authority)
}

/// Returns the record IDs bound to an authenticated deletion completion in a
/// runtime snapshot. A raw source deletion may scrub capsules that retain
/// distinct typed source IDs, so the capsule's source ID alone is not enough
/// to match the revocation row. The completion receipt's full deleted-record
/// set is the durable relation in that case.
fn snapshot_deleted_record_ids(
    snapshot: &Value,
    generation: u64,
    revocations: &BTreeMap<String, (u64, u64)>,
) -> Option<BTreeSet<u64>> {
    let events = snapshot.get("events")?.as_array()?;
    if events.len() > MAX_ITEMS {
        return None;
    }
    let mut deleted = BTreeSet::new();
    for event in events {
        if event["kind"] != "delete_by_source" {
            continue;
        }
        let sequence = event["seq"].as_u64()?;
        if sequence == 0 || sequence > generation {
            return None;
        }
        let receipt: Value = serde_json::from_str(event["receipt"].as_str()?).ok()?;
        let operation = receipt.get("operation")?.as_object()?;
        let sources = operation.get("sources")?.as_array()?;
        let record_ids = operation.get("deleted_record_ids")?.as_array()?;
        if sources.is_empty() || sources.len() > MAX_ITEMS || record_ids.len() > MAX_ITEMS {
            return None;
        }
        for source in sources {
            let source = source.as_str().filter(|source| !source.is_empty())?;
            if !revocations.contains_key(source) {
                return None;
            }
        }
        for record_id in record_ids {
            let record_id = record_id.as_u64().filter(|record_id| *record_id > 0)?;
            if !deleted.insert(record_id) {
                return None;
            }
        }
    }
    Some(deleted)
}

fn snapshot_inventory(
    bytes: &[u8],
    namespace: &NcmNamespace,
    exact: &OwnedExactScope,
) -> Option<Inventory> {
    let snapshot: Value = serde_json::from_slice(bytes).ok()?;
    if snapshot["format"] != SNAPSHOT_FORMAT || snapshot["namespace"] != namespace.as_str() {
        return None;
    }
    let capsules = snapshot["capsules"].as_array()?;
    if capsules.len() > MAX_ITEMS {
        return None;
    }
    let revocations = snapshot_revocation_authority(&snapshot, snapshot["commit_seq"].as_u64()?)?;
    let deleted_record_ids =
        snapshot_deleted_record_ids(&snapshot, snapshot["commit_seq"].as_u64()?, &revocations);
    let mut inventory = Inventory {
        generation: snapshot["commit_seq"].as_u64()?,
        observation_sequence: 0,
        sources: Vec::new(),
        attributions: Vec::new(),
        stored_source_ids: Vec::new(),
        effective_validities: BTreeMap::new(),
        wire_sources: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for capsule in capsules {
        let status = capsule["status"].as_str()?;
        let stored_source_id = capsule["source_id"].as_str()?;
        if stored_source_id.is_empty() {
            return None;
        }
        if status == "revoked" {
            // Runtime deletion deliberately clears every source-bearing field
            // before export.  Keep the row in the authenticated bytes for the
            // runtime restore, but omit it from the host-facing inventory so a
            // scrubbed tombstone can never be replayed as content.
            let record_id = capsule["record_id"].as_u64().filter(|id| *id > 0)?;
            if capsule["key_text"] != ""
                || capsule["value_text"] != ""
                || !capsule["key_embedding"].as_array()?.is_empty()
                || !capsule["value_embedding"].as_array()?.is_empty()
                || !capsule["ltm_key"].as_array()?.is_empty()
                || capsule["provenance"] != "{}"
                || (!revocations.contains_key(stored_source_id)
                    && !deleted_record_ids
                        .as_ref()
                        .is_some_and(|ids| ids.contains(&record_id)))
            {
                return None;
            }
            continue;
        }
        if !matches!(status, "valid" | "superseded") {
            return None;
        }
        let provenance: Value = serde_json::from_str(capsule["provenance"].as_str()?).ok()?;
        let retained = decode_capsule(&provenance)?;
        fields(
            &retained,
            &[
                "original_source",
                "canonical_payload",
                "source_refs",
                "delivery_scope",
                "projection",
            ],
        )?;
        let source = attribution(&retained["original_source"])?;
        if scope(&retained["delivery_scope"])? != *exact || !seen.insert(source_key(&source.source))
        {
            return None;
        }
        validate_source_binding(namespace, &source, &provenance, stored_source_id)?;
        let (key, value) = evidence_text(
            string(&retained["projection"]["observation_kind"])?,
            &retained["canonical_payload"],
        )?;
        if capsule["key_text"] != key
            || capsule["value_text"] != value
            || retained["projection"]["key_text"] != key
            || retained["projection"]["value_text"] != value
        {
            return None;
        }
        let mut effective = retained["original_source"]["validity"].clone();
        if let Some(patch) = provenance.pointer("/control/validity_patch") {
            for (field, value) in patch.as_object()? {
                effective[field] = value.clone();
            }
        }
        inventory
            .effective_validities
            .insert(source_key(&source.source), validity(&effective)?);
        inventory.observation_sequence = inventory.observation_sequence.max(source.source_sequence);
        inventory
            .wire_sources
            .push(retained["original_source"]["source"].clone());
        inventory.sources.push(source.source.clone());
        inventory.attributions.push(source);
        inventory
            .stored_source_ids
            .push(stored_source_id.to_owned());
    }
    // A live capsule must never share the source ID of a durable revocation.
    // Otherwise a later restore could import apparently valid content while
    // the runtime has already fenced that source.
    if inventory
        .stored_source_ids
        .iter()
        .any(|source_id| revocations.contains_key(source_id))
    {
        return None;
    }
    Some(inventory)
}

fn source_key(source: &OriginalSourceIdentity) -> String {
    json!([
        source.canonical_provider_id.as_str(),
        source.canonical_session_id,
        source.source_key,
        source.observation_id,
        source.source_revision
    ])
    .to_string()
}

fn canonical_sources(values: &[Value]) -> Option<BTreeMap<String, Value>> {
    let mut sources = BTreeMap::new();
    for value in values {
        fields(
            value,
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
        let key = json!([
            string(&value["canonical_provider_id"])?,
            string(&value["canonical_session_id"])?,
            string(&value["source_key"])?,
            string(&value["observation_id"])?,
            nullable_string(&value["source_revision"])?
        ])
        .to_string();
        if sources.insert(key, value.clone()).is_some() {
            return None;
        }
    }
    Some(sources)
}

fn validate_snapshot_identity(
    call: &ProviderCall,
    identity: &Value,
    descriptor: &ProviderDescriptor,
    bytes: &[u8],
    inventory: &Inventory,
) -> Option<()> {
    fields(
        identity,
        &[
            "snapshot_id",
            "provider_id",
            "implementation_identity_digest",
            "state_schema_version",
            "exact_scope_digest",
            "state_generation",
            "observation_sequence",
            "parent_snapshot_id",
            "content_sha256",
            "byte_length",
            "created_at",
        ],
    )?;
    let digest = hex_digest(&Sha256::digest(bytes));
    if identity["snapshot_id"] != format!("ncm-snapshot:{digest}")
        || identity["provider_id"] != call.provider_id.as_str()
        || identity["implementation_identity_digest"] != descriptor.implementation_identity_sha256
        || identity["state_schema_version"] != descriptor.state_schema_version
        || identity["exact_scope_digest"] != call.exact_scope.exact_scope_sha256()
        || identity["state_generation"].as_u64()? != inventory.generation
        || identity["observation_sequence"].as_u64()? != inventory.observation_sequence
        || identity["content_sha256"] != digest
        || identity["byte_length"].as_u64()? != bytes.len() as u64
    {
        return None;
    }
    nullable_string(&identity["parent_snapshot_id"])?;
    instant(&identity["created_at"])?;
    Some(())
}

fn validate_checkpoint(value: &Value, exact: &OwnedExactScope) -> Option<()> {
    fields(
        value,
        &[
            "exact_scope",
            "authority_ref",
            "authority_revision",
            "checked_at",
        ],
    )?;
    if scope(&value["exact_scope"])? != *exact {
        return None;
    }
    string(&value["authority_ref"])?;
    if !value["authority_revision"].is_null() {
        value["authority_revision"].as_u64()?;
    }
    instant(&value["checked_at"])?;
    Some(())
}

fn validate_disposition(value: &Value) -> Option<()> {
    fields(
        value,
        &["state", "authority_ref", "authority_revision", "checked_at"],
    )?;
    if !matches!(
        string(&value["state"])?,
        "available" | "superseded" | "revoked" | "deleted" | "redacted" | "expired"
    ) {
        return None;
    }
    string(&value["authority_ref"])?;
    if !value["authority_revision"].is_null() {
        value["authority_revision"].as_u64()?;
    }
    instant(&value["checked_at"])?;
    Some(())
}

fn byte_array(value: &Value, limit: u64) -> Option<Vec<u8>> {
    let array = value.as_array()?;
    if array.is_empty() || array.len() as u64 > limit {
        return None;
    }
    array
        .iter()
        .map(|value| u8::try_from(value.as_u64()?).ok())
        .collect()
}

pub(crate) fn reconstruct(
    call: &ProviderCall,
    namespace: &NcmNamespace,
    reply: &mut ProviderReply,
    descriptor: &ProviderDescriptor,
    limits: ProviderLimits,
) -> Option<()> {
    let worker: Value = serde_json::from_slice(&reply.payload.as_ref()?.bytes).ok()?;
    if worker["common_portability"] != call.operation.as_wire() {
        return None;
    }
    let no_change = call.operation == ProviderOperation::Replay && worker["no_change"] == true;
    let response_evidence = if no_change {
        let payload = reply.payload.as_ref()?;
        payload.validate().ok()?;
        Some(payload.sha256.clone())
    } else {
        None
    };
    let mut output = if call.operation == ProviderOperation::SnapshotExport {
        let bytes = byte_array(&worker["bytes"], limits.snapshot_bytes)?;
        let inventory = snapshot_inventory(&bytes, namespace, &call.exact_scope)?;
        if inventory.generation != reply.state_generation {
            return None;
        }
        let digest = hex_digest(&Sha256::digest(&bytes));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let created_at =
            DateTime::from_timestamp(i64::try_from(now.as_secs()).ok()?, now.subsec_nanos())?
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        json!({"snapshot":{"identity":{"snapshot_id":format!("ncm-snapshot:{digest}"),"provider_id":call.provider_id.as_str(),
            "implementation_identity_digest":descriptor.implementation_identity_sha256,"state_schema_version":descriptor.state_schema_version,
            "exact_scope_digest":call.exact_scope.exact_scope_sha256(),"state_generation":inventory.generation,"observation_sequence":inventory.observation_sequence,
            "parent_snapshot_id":null,"content_sha256":digest,"byte_length":bytes.len(),"created_at":created_at},"bytes":bytes,"sources":inventory.wire_sources},"warnings":[]})
    } else {
        let mut output = worker.as_object()?.clone();
        output.remove("common_portability");
        output.remove("replayed");
        output.remove("_retained_receipt");
        if call.operation == ProviderOperation::Replay {
            output.remove("no_change");
            let delivery =
                super::lifecycle::decode_receipt_capsule(&worker["page_delivery_capsule"])?;
            super::lifecycle::validate_delivery_caller(call, namespace, &delivery)?;
            if namespace.1 == NcmNamespaceBinding::CheckoutObservationsV1
                && delivery.get("caller_binding").is_none()
            {
                return None;
            }
            let original_key = string(&delivery["idempotency_key"])?;
            let original_operation = string(&delivery["operation_id"])?;
            if Some(original_key) != call.idempotency_key.as_deref() {
                return None;
            }
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
            output.remove("page_delivery_capsule");
            let request: Value = serde_json::from_slice(&call.payload.bytes).ok()?;
            let mut accounting = ReplayAccounting {
                attempted: request["resolved_observations"].as_array()?.len() as u64,
                applied: worker["applied_observations"].as_u64()?,
                delivery_duplicates: worker["duplicate_observations"].as_u64()?,
                sources_already_applied: worker["sources_already_applied"].as_u64()?,
                rejected: worker["rejected_observations"].as_u64()?,
                effect_unknown: worker["effect_unknown_observations"].as_u64()?,
            };
            accounting.validate().ok()?;
            if no_change
                && (reply.terminal.committed_effect().state() != crate::CommittedEffectState::None
                    || reply.terminal.terminal_code() != TerminalCode::Success
                    || reply.state_generation != call.expected_state_generation
                    || worker["state_generation_before"].as_u64()? != reply.state_generation
                    || worker["state_generation_after"].as_u64()? != reply.state_generation
                    || worker["acknowledged_sequence"]
                        != request["expected_previous_acknowledged_sequence"]
                    || worker["partial"] != false
                    || worker["replayed"] != false
                    || accounting.applied != 0
                    || accounting.delivery_duplicates != 0
                    || accounting.effect_unknown != 0)
            {
                return None;
            }
            if worker["replayed"] == true {
                accounting.delivery_duplicates = accounting
                    .delivery_duplicates
                    .checked_add(accounting.applied)?
                    .checked_add(accounting.sources_already_applied)?;
                output.insert(
                    "duplicate_observations".to_owned(),
                    json!(accounting.delivery_duplicates),
                );
                output.insert("applied_observations".to_owned(), json!(0));
                output.insert("sources_already_applied".to_owned(), json!(0));
                for item in output.get_mut("items")?.as_array_mut()? {
                    if matches!(
                        item["state"].as_str()?,
                        "applied" | "source_already_applied"
                    ) {
                        item["state"] = json!("delivery_duplicate");
                    }
                }
            }
        }
        Value::Object(output)
    };
    if call.operation != ProviderOperation::SnapshotExport {
        if let Some(receipt) = reply.terminal.committed_effect().provider_receipt_sha256() {
            output["provider_receipt_digest"] = json!(receipt);
        } else if let Some(response_evidence) = response_evidence {
            // Required public response evidence hashes the actual validated worker
            // payload. None effect carries no journal receipt or duplicate claim.
            output["provider_receipt_digest"] = json!(response_evidence);
        } else if reply.terminal.terminal_code() == TerminalCode::Success {
            return None;
        }
    }
    let response_limit = if call.operation == ProviderOperation::SnapshotExport {
        limits.snapshot_bytes
    } else {
        limits.response_bytes
    };
    let bytes = serde_json::to_vec(&output).ok()?;
    if bytes.len() as u64 > response_limit {
        return None;
    }
    reply.payload = Some(
        CanonicalPayload::new(
            call.payload.contract_id.clone(),
            bytes.clone(),
            hex_digest(&Sha256::digest(&bytes)),
        )
        .ok()?,
    );
    if call.operation == ProviderOperation::SnapshotExport
        && crate::encoded_response_bytes(call, reply) > response_limit
    {
        return None;
    }
    Some(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn canonical_payload_digest(value: &Value) -> String {
        let mut canonical = value.clone();
        canonical.sort_all_objects();
        hex_digest(&Sha256::digest(serde_json::to_vec(&canonical).unwrap()))
    }

    fn fixture() -> (OwnedExactScope, NcmNamespace, Value, Value) {
        let exact = OwnedExactScope {
            profile_id: "profile".to_owned(),
            project_id: "project".to_owned(),
            repository_identity: "repository".to_owned(),
            worktree_identity: "worktree".to_owned(),
            branch_identity: "master".to_owned(),
            agent_session_id: "session".to_owned(),
            resolved_scope_digest: format!("sha256:{}", "ab".repeat(32)),
        };
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let payload = json!({"role":"assistant","content":"retained answer"});
        let source = json!({"canonical_provider_id":"claude","canonical_session_id":"source-session","source_key":"source-key","stable_record_id":null,
            "observation_id":"observation-1","source_revision":"revision-1","content_sha256":canonical_payload_digest(&payload)});
        let original = json!({"source":source,"origin_scope":{"state":"recorded","exact_scope_identity":scope_value(&exact),"authority_ref":"source.authority"},
            "source_sequence":1,"occurred_at":"2026-01-01T00:00:00Z","ingested_at":"2026-01-01T00:00:00Z",
            "validity":{"valid_from":"2026-01-01T00:00:00Z","valid_until":null,"superseded_at":null,"superseded_by":null,"revoked_at":null}});
        let retained = json!({"original_source":original,"canonical_payload":payload,"source_refs":["record:observation-1"],"delivery_scope":scope_value(&exact),
            "projection":{"key_text":"retained answer","value_text":"assistant: retained answer","observation_kind":"session.message_committed.v1"}});
        let capsule_bytes = serde_json::to_vec(&retained).unwrap();
        let provenance = json!({"common_capsule":{"version":1,"sha256":hex_digest(&Sha256::digest(&capsule_bytes)),"bytes":capsule_bytes}});
        let snapshot = json!({"format":SNAPSHOT_FORMAT,"namespace":namespace.as_str(),"commit_seq":1,"capsules":[{"record_id":1,"source_id":opaque_surface_id(&namespace,b"forget-source-key","source-key"),
            "key_text":"retained answer","value_text":"assistant: retained answer","status":"valid","provenance":provenance.to_string()}]});
        (exact, namespace, snapshot, retained)
    }

    #[test]
    fn snapshot_export_uses_snapshot_limit_for_body_and_complete_public_reply() {
        use tracedecay_memory_provider_api::{
            CancellationToken, CommittedEffectEvidence, FallbackDirective, OperationControl,
            OwnedOpaqueExtension, OwnedVersionedId, ProviderCallParts, TerminalRecord,
        };

        let (exact, namespace, snapshot, _) = fixture();
        let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
        let inventory = snapshot_inventory(&snapshot_bytes, &namespace, &exact).unwrap();
        let extension_bytes = vec![b'x'; 2048];
        let request_bytes = b"{}".to_vec();
        let call = ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::SnapshotExport,
            provider_id: OwnedProviderId::new(crate::NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "ab".repeat(32),
            exact_scope: exact,
            request_id: "snapshot-boundary-request".to_owned(),
            operation_id: "snapshot-boundary-operation".to_owned(),
            expected_state_generation: 1,
            idempotency_key: None,
            control: OperationControl::new(i64::MAX, 60_000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new("tracedecay.memory.provider.snapshot-export.v1").unwrap(),
                request_bytes.clone(),
                hex_digest(&Sha256::digest(&request_bytes)),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new("snapshot.export.v1").unwrap()],
            extensions: vec![
                OwnedOpaqueExtension::new(
                    OwnedVersionedId::new("vendor.snapshot-boundary.v1").unwrap(),
                    1,
                    false,
                    hex_digest(&Sha256::digest(&extension_bytes)),
                    extension_bytes,
                )
                .unwrap(),
            ],
        })
        .unwrap();
        let limits = ProviderLimits {
            request_bytes: 1_048_576,
            response_bytes: 1_048_576,
            observation_batch_items: 16,
            recall_candidates: 32,
            concurrent_operations: 4,
            operation_millis: 60_000,
            snapshot_bytes: 268_435_456,
            inspection_items: 64,
        };
        let descriptor = ProviderDescriptor::new(
            call.provider_id.clone(),
            "ab".repeat(32),
            "ncm-state-v1",
            1,
            [
                "provider.health.v1",
                "observation.accept.v1",
                "recall.query.v1",
                "snapshot.export.v1",
            ]
            .into_iter()
            .map(|id| OwnedVersionedId::new(id).unwrap()),
            limits,
        )
        .unwrap();
        let worker_bytes = serde_json::to_vec(&json!({
            "common_portability":"snapshot_export", "bytes":snapshot_bytes, "warnings":[]
        }))
        .unwrap();
        let worker_reply = ProviderReply {
            terminal: TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(1)),
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                None,
            )
            .unwrap(),
            payload: Some(
                CanonicalPayload::new(
                    call.payload.contract_id.clone(),
                    worker_bytes.clone(),
                    hex_digest(&Sha256::digest(&worker_bytes)),
                )
                .unwrap(),
            ),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: 1,
        };
        let mut baseline = worker_reply.clone();
        reconstruct(&call, &namespace, &mut baseline, &descriptor, limits).unwrap();
        let body_bytes = baseline.payload.as_ref().unwrap().bytes.len() as u64;
        let framed_bytes = crate::encoded_response_bytes(&call, &baseline);
        assert!(framed_bytes > body_bytes + 2048);
        let snapshot_limits = ProviderLimits {
            response_bytes: body_bytes - 1,
            snapshot_bytes: framed_bytes,
            ..limits
        };
        snapshot_limits.validate().unwrap();
        let mut exported = worker_reply.clone();
        reconstruct(
            &call,
            &namespace,
            &mut exported,
            &descriptor,
            snapshot_limits,
        )
        .unwrap();
        assert_eq!(
            crate::encoded_response_bytes(&call, &exported),
            framed_bytes
        );
        let output: Value = serde_json::from_slice(&exported.payload.unwrap().bytes).unwrap();
        assert_eq!(output["snapshot"]["bytes"], json!(snapshot_bytes));
        assert_eq!(output["snapshot"]["sources"], json!(inventory.wire_sources));
        assert_eq!(
            output["snapshot"]["identity"]["content_sha256"],
            hex_digest(&Sha256::digest(&snapshot_bytes))
        );
        assert_eq!(
            output["snapshot"]["identity"]["byte_length"],
            snapshot_bytes.len()
        );
        for snapshot_limit in [body_bytes - 1, framed_bytes - 1] {
            let mut rejected = worker_reply.clone();
            assert!(
                reconstruct(
                    &call,
                    &namespace,
                    &mut rejected,
                    &descriptor,
                    ProviderLimits {
                        snapshot_bytes: snapshot_limit,
                        ..snapshot_limits
                    },
                )
                .is_none(),
                "accepted snapshot limit {snapshot_limit}"
            );
        }
    }

    #[test]
    fn no_change_replay_preserves_validated_response_evidence_without_a_commit_receipt() {
        use tracedecay_memory_provider_api::{
            CancellationToken, CommittedEffectEvidence, FallbackDirective, OperationControl,
            OwnedVersionedId, ProviderCallParts, TerminalRecord,
        };
        let (exact, namespace, _, _) = fixture();
        let request = serde_json::to_vec(&json!({
            "resolved_observations":[{}], "expected_previous_acknowledged_sequence":1
        }))
        .unwrap();
        let call = ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Replay,
            provider_id: OwnedProviderId::new(crate::NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "ab".repeat(32),
            exact_scope: exact,
            request_id: "no-change-request".to_owned(),
            operation_id: "no-change-operation".to_owned(),
            expected_state_generation: 2,
            idempotency_key: Some("no-change-key".to_owned()),
            control: OperationControl::new(i64::MAX, 60_000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new("tracedecay.memory.provider.replay.v1").unwrap(),
                request.clone(),
                hex_digest(&Sha256::digest(&request)),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new("replay.apply.v1").unwrap()],
            extensions: Vec::new(),
        })
        .unwrap();
        let limits = ProviderLimits {
            request_bytes: 1_048_576,
            response_bytes: 1_048_576,
            observation_batch_items: 16,
            recall_candidates: 32,
            concurrent_operations: 4,
            operation_millis: 60_000,
            snapshot_bytes: 1_048_576,
            inspection_items: 64,
        };
        let descriptor = ProviderDescriptor::new(
            call.provider_id.clone(),
            "ab".repeat(32),
            "ncm-state-v1",
            2,
            [
                "provider.health.v1",
                "observation.accept.v1",
                "recall.query.v1",
                "replay.apply.v1",
            ]
            .into_iter()
            .map(|id| OwnedVersionedId::new(id).unwrap()),
            limits,
        )
        .unwrap();
        let delivery = serde_json::to_vec(
            &json!({"operation_id":call.operation_id,"idempotency_key":call.idempotency_key}),
        )
        .unwrap();
        let worker = serde_json::to_vec(&json!({
            "common_portability":"replay", "first_source_sequence":1,"last_source_sequence":1,
            "acknowledged_sequence":1,"state_generation_before":2,"state_generation_after":2,
            "applied_observations":0,"duplicate_observations":0,"sources_already_applied":1,
            "rejected_observations":0,"effect_unknown_observations":0,"partial":false,"replayed":false,
            "warnings":[],"no_change":true,"items":[{"source_sequence":1,"receipt_digest":"ab".repeat(32),
                "state":"source_already_applied","reason":null,"record_id":1,"state_generation":2}],
            "page_delivery_capsule":{"version":1,"bytes":delivery,"sha256":hex_digest(&Sha256::digest(&delivery))}
        })).unwrap();
        let response_digest = hex_digest(&Sha256::digest(&worker));
        let incoming = ProviderReply {
            terminal: TerminalRecord::new(
                call.operation,
                call.provider_id.clone(),
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(2)),
                FallbackDirective::forbidden(),
                call.operation_id.clone(),
                call.exact_scope.exact_scope_sha256(),
                None,
            )
            .unwrap(),
            payload: Some(
                CanonicalPayload::new(
                    call.payload.contract_id.clone(),
                    worker,
                    response_digest.clone(),
                )
                .unwrap(),
            ),
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: 2,
        };
        let mut reply = incoming.clone();
        reconstruct(&call, &namespace, &mut reply, &descriptor, limits).unwrap();
        reply.validate(limits.response_bytes).unwrap();
        let output: Value = serde_json::from_slice(&reply.payload.as_ref().unwrap().bytes).unwrap();
        fields(
            &output,
            &[
                "first_source_sequence",
                "last_source_sequence",
                "acknowledged_sequence",
                "state_generation_before",
                "state_generation_after",
                "applied_observations",
                "duplicate_observations",
                "sources_already_applied",
                "rejected_observations",
                "effect_unknown_observations",
                "partial",
                "warnings",
                "items",
                "provider_receipt_digest",
            ],
        )
        .unwrap();
        assert_eq!(output["provider_receipt_digest"], response_digest);
        assert_eq!(output["state_generation_before"], 2);
        assert_eq!(output["state_generation_after"], 2);
        assert_eq!(output["sources_already_applied"], 1);
        assert_eq!(
            reply.terminal.committed_effect().state(),
            crate::CommittedEffectState::None
        );
        assert!(
            reply
                .terminal
                .committed_effect()
                .provider_receipt_sha256()
                .is_none()
        );
        assert!(
            reply
                .terminal
                .committed_effect()
                .verification_sha256()
                .is_none()
        );
        assert!(
            reply
                .terminal
                .committed_effect()
                .duplicate_of_operation_id()
                .is_none()
        );
        for malformed in ["missing", "digest", "bytes"] {
            let mut invalid = incoming.clone();
            match malformed {
                "missing" => invalid.payload = None,
                "digest" => invalid.payload.as_mut().unwrap().sha256 = "f".repeat(64),
                _ => invalid.payload.as_mut().unwrap().bytes.push(b' '),
            }
            assert!(
                reconstruct(&call, &namespace, &mut invalid, &descriptor, limits).is_none(),
                "accepted {malformed}"
            );
        }
    }

    #[test]
    fn inventory_requires_unique_actual_sources_and_exact_declared_identities() {
        let (exact, namespace, mut snapshot, _) = fixture();
        let actual =
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .unwrap();
        assert_eq!(actual.sources.len(), 1);
        let canonical = canonical_sources(&actual.wire_sources).unwrap();
        let mut forged = actual.wire_sources[0].clone();
        forged["content_sha256"] = json!("ff".repeat(32));
        assert_ne!(canonical_sources(&[forged]).unwrap(), canonical);
        assert_ne!(canonical_sources(&[]).unwrap(), canonical);
        assert!(
            canonical_sources(&[
                actual.wire_sources[0].clone(),
                actual.wire_sources[0].clone()
            ])
            .is_none()
        );
        let duplicate = snapshot["capsules"][0].clone();
        snapshot["capsules"].as_array_mut().unwrap().push(duplicate);
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }

    #[test]
    fn inventory_accepts_runtime_scrubbed_tombstones_with_revocation_authority() {
        let (exact, namespace, mut snapshot, _) = fixture();
        snapshot["commit_seq"] = json!(2);
        snapshot["revocations"] = json!([{
            "source_id": "revoked-source",
            "epoch": 2,
            "seq": 2
        }]);
        snapshot["capsules"].as_array_mut().unwrap().push(json!({
            "record_id": 2,
            "source_id": "revoked-source",
            "key_text": "",
            "value_text": "",
            "key_embedding": [],
            "value_embedding": [],
            "ltm_key": [],
            "status": "revoked",
            "provenance": "{}"
        }));

        let inventory =
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .unwrap();
        assert_eq!(inventory.sources.len(), 1);
        assert_eq!(inventory.wire_sources.len(), 1);
        assert!(
            !inventory
                .stored_source_ids
                .iter()
                .any(|source| source == "revoked-source")
        );
    }

    #[test]
    fn inventory_rejects_scrubbed_tombstones_without_exact_revocation_authority() {
        let (exact, namespace, mut snapshot, _) = fixture();
        snapshot["capsules"].as_array_mut().unwrap().push(json!({
            "record_id": 2,
            "source_id": "revoked-source",
            "key_text": "",
            "value_text": "",
            "key_embedding": [],
            "value_embedding": [],
            "ltm_key": [],
            "status": "revoked",
            "provenance": "{}"
        }));
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );

        snapshot["revocations"] = json!([{
            "source_id": "different-source",
            "epoch": 2,
            "seq": 2
        }]);
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }

    #[test]
    fn inventory_accepts_raw_authority_for_a_scrubbed_typed_tombstone() {
        let (exact, namespace, mut snapshot, _) = fixture();
        snapshot["commit_seq"] = json!(2);
        snapshot["revocations"] = json!([{
            "source_id": "raw-source",
            "epoch": 2,
            "seq": 2
        }]);
        snapshot["events"] = json!([{
            "seq": 2,
            "kind": "delete_by_source",
            "receipt": serde_json::to_string(&json!({
                "operation": {
                    "sources": ["raw-source"],
                    "deleted_record_ids": [2]
                }
            })).unwrap()
        }]);
        snapshot["capsules"].as_array_mut().unwrap().push(json!({
            "record_id": 2,
            "source_id": "typed-source",
            "key_text": "",
            "value_text": "",
            "key_embedding": [],
            "value_embedding": [],
            "ltm_key": [],
            "status": "revoked",
            "provenance": "{}"
        }));

        let inventory =
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .unwrap();
        assert_eq!(inventory.sources.len(), 1);
        assert!(
            !inventory
                .stored_source_ids
                .iter()
                .any(|source| source == "typed-source")
        );
    }

    #[test]
    fn snapshot_inventory_keeps_effective_corrections_separate_from_original_validity() {
        for patch in [
            json!({"superseded_at":"2026-01-02T00:00:00Z","superseded_by":"ncm-memory:replacement"}),
            json!({"revoked_at":"2026-01-02T00:00:00Z"}),
        ] {
            let (exact, namespace, mut snapshot, retained) = fixture();
            let mut provenance: Value =
                serde_json::from_str(snapshot["capsules"][0]["provenance"].as_str().unwrap())
                    .unwrap();
            provenance["control"] = json!({"validity_patch":patch});
            snapshot["capsules"][0]["provenance"] = json!(provenance.to_string());
            let inventory =
                snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                    .unwrap();
            assert_eq!(
                inventory.attributions[0],
                attribution(&retained["original_source"]).unwrap()
            );
            let effective = &inventory.effective_validities[&source_key(&inventory.sources[0])];
            assert_eq!(
                effective.superseded_at_utc_nanos.is_some(),
                patch.get("superseded_at").is_some()
            );
            assert_eq!(
                effective.revoked_at_utc_nanos.is_some(),
                patch.get("revoked_at").is_some()
            );
            assert!(
                inventory.attributions[0]
                    .validity
                    .superseded_at_utc_nanos
                    .is_none()
            );
            assert!(
                inventory.attributions[0]
                    .validity
                    .revoked_at_utc_nanos
                    .is_none()
            );
        }
        let (exact, namespace, mut snapshot, _) = fixture();
        let mut provenance: Value =
            serde_json::from_str(snapshot["capsules"][0]["provenance"].as_str().unwrap()).unwrap();
        provenance["control"] = json!({"validity_patch":{"revoked_at":"invalid-time"}});
        snapshot["capsules"][0]["provenance"] = json!(provenance.to_string());
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }

    #[test]
    fn changed_capsule_bytes_require_their_matching_integrity_digest() {
        let (exact, namespace, mut snapshot, mut retained) = fixture();
        let unchanged = serde_json::to_vec(&retained).unwrap();
        retained["canonical_payload"]["content"] = json!("forged answer");
        retained["projection"]["key_text"] = json!("forged answer");
        retained["projection"]["value_text"] = json!("assistant: forged answer");
        let changed = serde_json::to_vec(&retained).unwrap();
        let provenance = json!({"common_capsule":{"version":1,"sha256":hex_digest(&Sha256::digest(&unchanged)),"bytes":changed}});
        snapshot["capsules"][0]["provenance"] = json!(provenance.to_string());
        snapshot["capsules"][0]["key_text"] = json!("forged answer");
        snapshot["capsules"][0]["value_text"] = json!("assistant: forged answer");
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }

    #[test]
    fn sanitized_delivery_preserves_the_original_host_source_digest() {
        let (exact, namespace, mut snapshot, mut retained) = fixture();
        let original_digest = canonical_payload_digest(
            &json!({"role":"assistant","content":"retained answer with removed secret"}),
        );
        retained["original_source"]["source"]["content_sha256"] = json!(original_digest);
        let bytes = serde_json::to_vec(&retained).unwrap();
        snapshot["capsules"][0]["provenance"]=json!(json!({"common_capsule":{"version":1,"sha256":hex_digest(&Sha256::digest(&bytes)),"bytes":bytes}}).to_string());
        let inventory =
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .unwrap();
        assert_eq!(inventory.sources[0].content_sha256, original_digest);
    }

    #[test]
    fn snapshot_inventory_preserves_actual_legacy_and_full_ids_for_colliding_origins() {
        let (exact, namespace, mut snapshot, retained) = fixture();
        let first = attribution(&retained["original_source"]).unwrap();
        let first_binding = source_binding(&namespace, &first).unwrap();
        let mut second = retained.clone();
        second["original_source"]["source"]["canonical_session_id"] = json!("another-session");
        let bytes = serde_json::to_vec(&second).unwrap();
        let second_binding = source_binding(
            &namespace,
            &attribution(&second["original_source"]).unwrap(),
        )
        .unwrap();
        assert_ne!(first_binding.source_id, second_binding.source_id);
        assert_eq!(
            first_binding.legacy_source_id,
            second_binding.legacy_source_id
        );
        let provenance = json!({"source_binding":second_binding.provenance(),
            "common_capsule":{"version":1,"sha256":hex_digest(&Sha256::digest(&bytes)),"bytes":bytes}});
        let mut second_capsule = snapshot["capsules"][0].clone();
        second_capsule["record_id"] = json!(2);
        second_capsule["source_id"] = json!(second_binding.source_id);
        second_capsule["provenance"] = json!(provenance.to_string());
        snapshot["capsules"]
            .as_array_mut()
            .unwrap()
            .push(second_capsule);
        let inventory =
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .unwrap();
        assert_eq!(
            inventory.stored_source_ids,
            vec![first_binding.legacy_source_id, second_binding.source_id]
        );
        assert_eq!(inventory.attributions[0], first);
        assert_eq!(
            inventory.attributions[1],
            attribution(&second["original_source"]).unwrap()
        );
        // A full ID or binding from a colliding lineage cannot substitute for the actual row.
        snapshot["capsules"][0]["source_id"] = json!(first_binding.source_id);
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }

    #[test]
    fn snapshot_inventory_rejects_a_forged_binding_even_with_valid_capsule_bytes() {
        let (exact, namespace, mut snapshot, retained) = fixture();
        let binding = source_binding(
            &namespace,
            &attribution(&retained["original_source"]).unwrap(),
        )
        .unwrap();
        let mut provenance: Value =
            serde_json::from_str(snapshot["capsules"][0]["provenance"].as_str().unwrap()).unwrap();
        provenance["source_binding"] = binding.provenance();
        snapshot["capsules"][0]["source_id"] = json!(binding.source_id);
        snapshot["capsules"][0]["provenance"] = json!(provenance.to_string());
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_some()
        );
        provenance["source_binding"]["legacy_source_id"] = json!("forged-alias");
        snapshot["capsules"][0]["provenance"] = json!(provenance.to_string());
        assert!(
            snapshot_inventory(&serde_json::to_vec(&snapshot).unwrap(), &namespace, &exact)
                .is_none()
        );
    }
}
