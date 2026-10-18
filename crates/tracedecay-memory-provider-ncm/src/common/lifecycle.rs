use super::*;
use tracedecay_memory_provider_api::ProviderOperation;

pub(super) fn common_context(call: &ProviderCall, value: &Value) -> Option<()> {
    fields(
        value,
        &[
            "provider_id",
            "registration_revision",
            "ready_receipt_digest",
            "exact_scope_identity",
            "operation_id",
            "idempotency_key",
            "expected_state_generation",
            "request_identity",
            "policy_revision",
            "deadline",
            "cancellation",
            "extensions",
        ],
    )?;
    if value["provider_id"].as_str()? != call.provider_id.as_str()
        || value["registration_revision"].as_u64()? != call.registration_revision
        || value["ready_receipt_digest"].as_str()? != call.ready_receipt_sha256
        || scope(&value["exact_scope_identity"])? != call.exact_scope
        || value["operation_id"].as_str()? != call.operation_id
        || nullable_string(&value["idempotency_key"])? != call.idempotency_key
        || value["expected_state_generation"].as_u64()? != call.expected_state_generation
        || value["request_identity"].as_str()? != call.request_id
        || value["policy_revision"].as_u64()? == 0
        || value["cancellation"] != "live"
    {
        return None;
    }
    if value["extensions"].as_array()?.len() > 16 {
        return None;
    }
    for extension in value["extensions"].as_array()? {
        if extension["criticality"] != "optional" {
            return None;
        }
    }
    fields(
        &value["deadline"],
        &["deadline_utc_micros", "remaining_millis"],
    )?;
    value["deadline"]["deadline_utc_micros"].as_i64()?;
    if value["deadline"]["remaining_millis"].as_u64()? == 0 {
        return None;
    }
    Some(())
}

fn legacy_record_id(reference: &str) -> Option<u64> {
    let id = reference.parse::<u64>().ok()?;
    (id > 0 && id <= i64::MAX as u64 && id.to_string() == reference).then_some(id)
}

fn legacy_trace_item(namespace: &NcmNamespace, selected: &str, row: &Value) -> Option<Value> {
    fields(
        row,
        &[
            "legacy_record_id",
            "legacy_namespace_sha256",
            "stable_memory_ref",
            "content",
            "content_sha256",
            "original_source",
        ],
    )?;
    let id = legacy_record_id(selected)?;
    let content = row["content"].as_str()?;
    if row["legacy_record_id"].as_u64()? != id
        || row["legacy_namespace_sha256"]
            != hex_digest(&Sha256::digest(namespace.as_str().as_bytes()))
        || row["stable_memory_ref"] != selected
        || !row["original_source"].is_null()
        || row["content_sha256"] != hex_digest(&Sha256::digest(content.as_bytes()))
    {
        return None;
    }
    Some(json!({"stable_memory_ref": selected, "content": content,
        "content_sha256": row["content_sha256"], "original_source": null}))
}

fn target(call: &ProviderCall, target: &Value, namespace: &NcmNamespace) -> Option<Value> {
    fields(
        target,
        &[
            "provider_id",
            "registration_revision",
            "original_scope",
            "delivery_scope",
            "source",
            "reference",
        ],
    )?;
    if target["provider_id"].as_str()? != call.provider_id.as_str()
        || target["registration_revision"].as_u64()? != call.registration_revision
        || scope(&target["delivery_scope"])? != call.exact_scope
    {
        return None;
    }
    fields(&target["reference"], &["kind", "reference"])?;
    let original = json!({"source": target["source"], "origin_scope": target["original_scope"],
        "source_sequence": 0, "occurred_at": null, "ingested_at": "1970-01-01T00:00:00Z",
        "validity": {"valid_from": null, "valid_until": null, "superseded_at": null, "superseded_by": null, "revoked_at": null}});
    let source = attribution(&original)?;
    let identity = json!({"source": target["source"], "origin_scope": target["original_scope"]});
    let binding = source_binding(namespace, &source)?;
    let source_identity_sha256 = opaque_surface_id(
        namespace,
        b"source-target",
        &serde_json::to_string(&identity).ok()?,
    );
    match target["reference"]["kind"].as_str()? {
        // Trace/context references are host-resolved to retained stable
        // attribution before provider dispatch; a transient candidate id is
        // never accepted.
        "stable_memory_ref" => {
            let stable = string(&target["reference"]["reference"])?;
            if !stable.starts_with("ncm-memory:") || stable.len() != "ncm-memory:".len() + 64 {
                return None;
            }
            Some(
                json!({"stable_memory_ref": stable, "source": binding.source_id,
                "legacy_source": binding.legacy_source_id, "source_identity_sha256": source_identity_sha256}),
            )
        }
        "retained_source_locator" => {
            // The host locator is intentionally opaque and is only a retained
            // handle. NCM resolves the provider-local row from the canonical
            // source-derived observation identity and source binding below.
            let retained_source_locator = string(&target["reference"]["reference"])?;
            let observation_identity = opaque_surface_id(
                namespace,
                b"observation-identity",
                &serde_json::to_string(&json!([
                    source.source.canonical_provider_id.as_str(),
                    source.source.canonical_session_id,
                    source.source.observation_id,
                ]))
                .ok()?,
            );
            Some(json!({"retained_source_locator": retained_source_locator,
                "observation_identity": observation_identity, "source": binding.source_id,
                "legacy_source": binding.legacy_source_id, "source_identity_sha256": source_identity_sha256}))
        }
        _ => None,
    }
}

pub(crate) fn project(
    call: &ProviderCall,
    value: &Value,
    namespace: &NcmNamespace,
    admission: Option<&CurrentAdvisoryAdmission>,
) -> Option<Option<Value>> {
    let Some(context) = value.get("common_request") else {
        return Some(None);
    };
    common_context(call, context)?;
    let mut control = json!({"action": call.operation.as_wire(), "expected_generation": call.expected_state_generation});
    match call.operation {
        ProviderOperation::Health => {
            fields(value, &["common_request", "requested_checks"])?;
            let checks = strings(&value["requested_checks"])?;
            if checks.is_empty()
                || checks.iter().any(|item| {
                    ![
                        "protocol",
                        "state",
                        "scope",
                        "capacity",
                        "persistence",
                        "recovery",
                        "privacy",
                    ]
                    .contains(&item.as_str())
                })
            {
                return None;
            }
        }
        ProviderOperation::Inspection => {
            let mut names = vec![
                "common_request",
                "view",
                "selector",
                "maximum_items",
                "maximum_bytes",
                "redaction_policy_revision",
                "cursor",
            ];
            if value.get("target").is_some() {
                names.push("target");
            }
            fields(value, &names)?;
            let view = string(&value["view"])?;
            if ![
                "state_summary",
                "source_influence",
                "trace",
                "delivery_receipt",
                "maintenance_receipt",
                "snapshot_metadata",
                "capability_status",
            ]
            .contains(&view)
                || value["redaction_policy_revision"].as_u64()? == 0
            {
                return None;
            }
            let items = value["maximum_items"].as_u64()?;
            let bytes = value["maximum_bytes"].as_u64()?;
            if items == 0 || items > 1_000_000 || bytes == 0 || bytes > 1_073_741_824 {
                return None;
            }
            control["view"] = json!(view);
            control["maximum_items"] = json!(items);
            control["maximum_bytes"] = json!(bytes);
            let selector = value["selector"].as_object()?;
            let retained_target = match value.get("target") {
                Some(raw_target)
                    if matches!(view, "source_influence" | "trace" | "delivery_receipt") =>
                {
                    let projected = target(call, raw_target, namespace)?;
                    // Inspection's retained path must be explicitly addressed by
                    // the opaque locator. A stable target stays on the legacy
                    // selector-only path so its wire behavior is unchanged.
                    projected.get("retained_source_locator")?;
                    if view == "source_influence"
                        && raw_target["source"]["source_key"] != selector.get("source_key")?.clone()
                    {
                        return None;
                    }
                    Some(projected)
                }
                Some(_) => return None,
                None => None,
            };
            let retained_locator = retained_target
                .as_ref()
                .and_then(|target| target.get("retained_source_locator"))
                .and_then(Value::as_str);
            match view {
                "delivery_receipt" | "maintenance_receipt" => {
                    let optional = if view == "delivery_receipt" {
                        "stable_memory_ref"
                    } else {
                        "operation_id"
                    };
                    if let Some(selected) = selector.get(optional) {
                        fields(&value["selector"], &["idempotency_key", optional])?;
                        let selected = string(selected)?;
                        if optional == "stable_memory_ref" {
                            if let Some(locator) = retained_locator {
                                if selected != locator {
                                    return None;
                                }
                            } else if !crate::NcmProviderAdapter::valid_sha256(
                                selected.strip_prefix("ncm-memory:")?,
                            ) {
                                return None;
                            }
                            if retained_locator.is_none() {
                                control["stable_memory_ref"] = json!(selected);
                            }
                        }
                    } else {
                        fields(&value["selector"], &["idempotency_key"])?;
                    }
                    control["delivery_key"] = json!(opaque_surface_id(
                        namespace,
                        b"idempotency-key",
                        string(&value["selector"]["idempotency_key"])?
                    ));
                }
                "trace" => {
                    fields(&value["selector"], &["stable_memory_ref"])?;
                    let stable = string(&value["selector"]["stable_memory_ref"])?;
                    if let Some(locator) = retained_locator {
                        if stable != locator {
                            return None;
                        }
                    } else if let Some(id) = legacy_record_id(stable) {
                        control["legacy_record_id"] = json!(id);
                    } else if !stable
                        .strip_prefix("ncm-memory:")
                        .is_some_and(crate::NcmProviderAdapter::valid_sha256)
                    {
                        return None;
                    }
                    if retained_locator.is_none() {
                        control["stable_memory_ref"] = json!(stable);
                    }
                }
                "source_influence" => {
                    if let Some(stable) = selector.get("stable_memory_ref") {
                        fields(&value["selector"], &["source_key", "stable_memory_ref"])?;
                        let stable = string(stable)?;
                        if let Some(locator) = retained_locator {
                            if stable != locator {
                                return None;
                            }
                        } else {
                            let digest = stable.strip_prefix("ncm-memory:")?;
                            if !crate::NcmProviderAdapter::valid_sha256(digest) {
                                return None;
                            }
                        }
                        if retained_locator.is_none() {
                            control["stable_memory_ref"] = json!(stable);
                        }
                    } else {
                        fields(&value["selector"], &["source_key"])?;
                    }
                }
                _ => {
                    if !selector.is_empty() {
                        return None;
                    }
                }
            }
            control["source"] = if let Some(target) = &retained_target {
                target["source"].clone()
            } else {
                match selector.get("source_key") {
                    Some(source) => json!(opaque_surface_id(
                        namespace,
                        b"forget-source-key",
                        string(source)?
                    )),
                    None => Value::Null,
                }
            };
            if let Some(target) = retained_target {
                control["target"] = target;
            }
            let binding = cursor_binding(call, value)?;
            control["after"] = json!(match nullable_string(&value["cursor"])? {
                None => 0,
                Some(cursor) => {
                    let mut parts = cursor.split(':');
                    if parts.next()? != "ncm-cursor" {
                        return None;
                    }
                    let after = parts.next()?.parse::<u64>().ok()?;
                    if parts.next()? != binding || parts.next().is_some() {
                        return None;
                    }
                    if view == "capability_status"
                        && cursor != format!("ncm-cursor:{after}:{binding}")
                    {
                        return None;
                    }
                    after
                }
            });
        }
        ProviderOperation::Maintenance => {
            let mut names = vec![
                "common_request",
                "task",
                "maximum_items",
                "maximum_bytes",
                "maximum_duration_millis",
                "dry_run",
            ];
            if value.get("resume_cursor").is_some() {
                names.push("resume_cursor");
            }
            fields(value, &names)?;
            let task = string(&value["task"])?;
            if ![
                "consolidate",
                "decay",
                "prune_expired",
                "validate_state",
                "repair",
                "compact",
            ]
            .contains(&task)
            {
                return None;
            }
            for (name, bound) in [
                ("maximum_items", 1_000_000),
                ("maximum_bytes", 1_073_741_824),
                ("maximum_duration_millis", 3_600_000),
            ] {
                let number = value[name].as_u64()?;
                if number == 0 || number > bound {
                    return None;
                }
                control[name] = json!(number);
            }
            control["task"] = json!(task);
            control["dry_run"] = json!(value["dry_run"].as_bool()?);
            control["resume_cursor"] = match value.get("resume_cursor") {
                None | Some(Value::Null) => Value::Null,
                Some(value) => {
                    let cursor = string(value)?;
                    if cursor.len() > 1024 {
                        return None;
                    }
                    let prefix = format!("ncm-maintenance:{}:{task}:", namespace.as_str());
                    let mut parts = cursor.strip_prefix(&prefix)?.split(':');
                    let generation_text = parts.next()?;
                    let generation = generation_text.parse::<u64>().ok()?;
                    let after_text = parts.next()?;
                    let after = after_text.parse::<u64>().ok()?;
                    if parts.next().is_some()
                        || generation.to_string() != generation_text
                        || after > i64::MAX as u64
                        || after.to_string() != after_text
                    {
                        return None;
                    }
                    // The runtime checks current generation after exact durable replay lookup.
                    json!(cursor)
                }
            };
            control["policy_revision"] = context["policy_revision"].clone();
            control["extensions"] = context["extensions"].clone();
            let semantic = json!({
                "action": "maintenance",
                "task": control["task"],
                "dry_run": control["dry_run"],
                "maximum_items": control["maximum_items"],
                "maximum_bytes": control["maximum_bytes"],
                "maximum_duration_millis": control["maximum_duration_millis"],
                "resume_cursor": control["resume_cursor"],
                "policy_revision": control["policy_revision"],
                "extensions": control["extensions"]
            });
            let request_semantic_sha256 =
                hex_digest(&Sha256::digest(serde_json::to_vec(&semantic).ok()?));
            let bytes = serde_json::to_vec(&json!({
                "namespace": namespace.as_str(),
                "operation_id": call.operation_id,
                "idempotency_key": call.idempotency_key.as_deref()?,
                "request_semantic_sha256": request_semantic_sha256
            }))
            .ok()?;
            control["maintenance_capsule"] = json!({
                "version": 1,
                "sha256": hex_digest(&Sha256::digest(&bytes)),
                "bytes": bytes
            });
        }
        ProviderOperation::DeleteBySource => {
            control["action"] = json!("delete_by_source");
            fields(
                value,
                &[
                    "common_request",
                    "forget_source_keys",
                    "mode",
                    "include_snapshots",
                    "retention_lock_policy_revision",
                    "verification_query",
                ],
            )?;
            let sources = strings(&value["forget_source_keys"])?;
            if sources.is_empty()
                || sources.len() > 1024
                || sources.iter().collect::<BTreeSet<_>>().len() != sources.len()
                || !["remove_influence", "hard_delete"].contains(&string(&value["mode"])?)
                || value["include_snapshots"] != true
                || value["retention_lock_policy_revision"].as_u64()? == 0
            {
                return None;
            }
            let query = string(&value["verification_query"])?;
            if query.len() > 32768 {
                return None;
            }
            if call.history_grant().is_some() {
                let current = admission?;
                current.verify_for(call).ok()?;
                let bindings =
                    source_binding::claimed_source_bindings(namespace, &sources, current)?;
                control["sources"] = json!(
                    bindings
                        .iter()
                        .map(|binding| &binding.source_id)
                        .collect::<Vec<_>>()
                );
                control["source_bindings"] = json!(
                    bindings
                        .iter()
                        .map(source_binding::SourceBinding::target)
                        .collect::<Vec<_>>()
                );
            } else {
                control["sources"] = json!(
                    sources
                        .iter()
                        .map(|source| opaque_surface_id(namespace, b"forget-source-key", source))
                        .collect::<Vec<_>>()
                );
            }
            control["verification_query_digest"] =
                json!(hex_digest(&Sha256::digest(query.as_bytes())));
        }
        ProviderOperation::Feedback => {
            fields(
                value,
                &[
                    "common_request",
                    "target",
                    "signal",
                    "weight",
                    "canonical_outcome_receipt",
                    "evidence_refs",
                    "occurred_at",
                ],
            )?;
            control["target"] = target(call, &value["target"], namespace)?;
            let signal = value["signal"].as_str()?;
            if !["helpful", "harmful", "ignored", "corrected", "superseded"].contains(&signal) {
                return None;
            }
            let weight = string(&value["weight"])?;
            if weight.len() > 64
                || weight
                    .chars()
                    .any(|character| !character.is_ascii_digit() && character != '.')
            {
                return None;
            }
            let weight: f64 = weight.parse().ok()?;
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return None;
            }
            let evidence = strings(&value["evidence_refs"])?;
            if evidence.len() > 64 {
                return None;
            }
            control["signal"] = json!(signal);
            control["weight"] = json!(weight);
            control["outcome_receipt"] = json!(opaque_surface_id(
                namespace,
                b"feedback-receipt",
                string(&value["canonical_outcome_receipt"])?
            ));
            control["occurred_at"] = json!(instant(&value["occurred_at"])?);
            control["evidence_digest"] = json!(hex_digest(&Sha256::digest(
                serde_json::to_vec(&evidence).ok()?
            )));
            control["target_digest"] = json!(hex_digest(&Sha256::digest(
                serde_json::to_vec(&value["target"]).ok()?
            )));
        }
        ProviderOperation::Correction => {
            fields(
                value,
                &[
                    "common_request",
                    "target",
                    "correction_kind",
                    "replacement",
                    "expected_target_revision",
                    "reason",
                    "evidence_refs",
                ],
            )?;
            control["target"] = target(call, &value["target"], namespace)?;
            let target_revision = string(&value["target"]["source"]["source_revision"])?;
            // Retained target identity and the caller's revision CAS are independent.
            // The runtime compares the latter with durable state under its lock.
            let expected = string(&value["expected_target_revision"])?;
            let reason = string(&value["reason"])?;
            if reason.len() > 8192 || strings(&value["evidence_refs"])?.len() > 64 {
                return None;
            }
            let kind = value["correction_kind"].as_str()?;
            control["expected_revision"] =
                json!(opaque_surface_id(namespace, b"source-revision", expected));
            control["correction_kind"] = json!(kind);
            control["target_digest"] = json!(hex_digest(&Sha256::digest(
                serde_json::to_vec(&value["target"]).ok()?
            )));
            control["evidence_digest"] = json!(hex_digest(&Sha256::digest(
                serde_json::to_vec(&json!([value["evidence_refs"], reason])).ok()?
            )));
            match kind {
                "supersede" | "replace_content" => {
                    let original =
                        value["replacement"].pointer("/source_identity/original_source")?;
                    let replacement = attribution(original)?;
                    let replacement_binding = source_binding(namespace, &replacement)?;
                    if replacement.source.source_revision.as_deref()? == target_revision {
                        return None;
                    }
                    control["transition_time"] = json!(replacement.validity.valid_from_utc_nanos?);
                    control["transition_wire"] = original["validity"]["valid_from"].clone();
                    let provenance =
                        project_attribution(call, &value["replacement"], namespace)??;
                    let kind = value["replacement"]["observation_kind"].as_str()?;
                    let (key_text, value_text) =
                        evidence_text(kind, &value["replacement"]["canonical_payload"])?;
                    control["replacement"] = json!({"observation_kind": kind, "payload_contract": value["replacement"]["payload_contract"],
                        "canonical_payload": {"forget_source_key": replacement_binding.source_id,
                            "_ncm_key_text": key_text, "_ncm_value_text": value_text}, "provenance": provenance});
                }
                "change_validity" => {
                    fields(&value["replacement"], &["valid_from", "valid_until"])?;
                    let from = nullable_instant(&value["replacement"]["valid_from"])?;
                    let until = nullable_instant(&value["replacement"]["valid_until"])?;
                    if matches!((from, until), (Some(from), Some(until)) if from >= until)
                        || (from.is_none() && until.is_none())
                    {
                        return None;
                    }
                    control["selection_patch"] = json!({"valid_from": from, "valid_until": until});
                    control["validity_patch"] = value["replacement"].clone();
                }
                "mark_incorrect" => {
                    fields(&value["replacement"], &["revoked_at"])?;
                    control["selection_patch"] =
                        json!({"revoked_at": instant(&value["replacement"]["revoked_at"])?});
                    control["validity_patch"] = value["replacement"].clone();
                }
                "restrict_scope" => {
                    fields(&value["replacement"], &["exact_scope_identity"])?;
                    // Exact namespaces cannot be widened or silently moved.
                    // A different scope withdraws this local contribution.
                    if scope(&value["replacement"]["exact_scope_identity"])? == call.exact_scope {
                        return None;
                    }
                    control["selection_patch"] = json!({});
                    control["validity_patch"] = json!({});
                }
                _ => return None,
            }
        }
        _ => return Some(None),
    }
    if call.operation == ProviderOperation::Feedback {
        let mut semantic = control.clone();
        semantic.as_object_mut()?.remove("expected_generation");
        let bytes = serde_json::to_vec(&json!({
            "namespace": namespace.as_str(),
            "operation_id": call.operation_id,
            "idempotency_key": call.idempotency_key.as_deref()?,
            "request_semantic_sha256": hex_digest(&Sha256::digest(serde_json::to_vec(&semantic).ok()?))
        })).ok()?;
        control["feedback_delivery_capsule"] = json!({
            "version": 1, "sha256": hex_digest(&Sha256::digest(&bytes)), "bytes": bytes
        });
    }
    Some(Some(json!({"common_control": control})))
}

pub(super) fn decode_receipt_capsule(capsule: &Value) -> Option<Value> {
    fields(capsule, &["version", "bytes", "sha256"])?;
    if capsule["bytes"].as_array()?.len() > 131_072
        || !crate::NcmProviderAdapter::valid_sha256(capsule["sha256"].as_str()?)
    {
        return None;
    }
    decode_named_capsule(&json!({"receipt": capsule}), "receipt")
}

fn maintenance_receipt_item(call: &ProviderCall, request: &Value, row: &Value) -> Option<Value> {
    fields(row, &["maintenance_receipt", "provider_receipt_digest"])?;
    let retained = &row["maintenance_receipt"];
    fields(
        retained,
        &[
            "admission",
            "request_semantic_sha256",
            "outcome",
            "event_basis",
        ],
    )?;
    let admission = decode_receipt_capsule(&retained["admission"])?;
    fields(
        &admission,
        &[
            "namespace",
            "operation_id",
            "idempotency_key",
            "request_semantic_sha256",
        ],
    )?;
    let operation_id = string(&admission["operation_id"])?;
    let idempotency_key = string(&admission["idempotency_key"])?;
    let semantic = string(&admission["request_semantic_sha256"])?;
    let digest = string(&row["provider_receipt_digest"])?;
    let basis = &retained["event_basis"];
    let outcome = &retained["outcome"];
    let before = outcome["state_generation_before"].as_u64()?;
    let after = outcome["state_generation_after"].as_u64()?;
    let scanned = outcome["scanned_items"].as_u64()?;
    let changed = outcome["changed_items"].as_u64()?;
    let removed = outcome["removed_items"].as_u64()?;
    if admission["namespace"] != NcmNamespace::from_exact_scope(&call.exact_scope).as_str()
        || idempotency_key != request["selector"]["idempotency_key"].as_str()?
        || request["selector"]
            .get("operation_id")
            .is_some_and(|selected| selected.as_str() != Some(operation_id))
        || !crate::NcmProviderAdapter::valid_sha256(semantic)
        || !crate::NcmProviderAdapter::valid_sha256(digest)
        || retained["request_semantic_sha256"] != semantic
        || basis["payload_sha256"] != semantic
        || basis["sequence"].as_u64()? != after
        || before.checked_add(1)? != after
        || after > call.expected_state_generation
        || changed.checked_add(removed)? > scanned
        || outcome["dry_run"] != false
        || outcome["partial"] != false
        || !outcome["resume_cursor"].is_null()
        || !outcome["warnings"].as_array()?.is_empty()
    {
        return None;
    }
    let task = string(&outcome["task"])?;
    if !["consolidate", "decay", "prune_expired", "repair", "compact"].contains(&task) {
        return None;
    }
    Some(
        json!({"operation_id": operation_id, "idempotency_key": idempotency_key,
        "outcome": {"task": task, "dry_run": false, "scanned_items": scanned,
            "changed_items": changed, "removed_items": removed, "state_changed": outcome["state_changed"].as_bool()?,
            "partial": false, "resume_cursor": null,
            "receipt": {"state_generation_before": before, "state_generation_after": after, "provider_receipt_digest": digest}}}),
    )
}

fn cursor_binding(call: &ProviderCall, value: &Value) -> Option<String> {
    let basis = if value["view"] == "capability_status" {
        json!([
            value["view"],
            value["selector"],
            value["redaction_policy_revision"],
            call.ready_receipt_sha256
        ])
    } else {
        json!([
            value["view"],
            value["selector"],
            value["redaction_policy_revision"]
        ])
    };
    Some(opaque_surface_id(
        &NcmNamespace::from_exact_scope(&call.exact_scope),
        b"inspection-cursor",
        &serde_json::to_string(&basis).ok()?,
    ))
}

fn reconstruct_feedback_delivery(
    call: &ProviderCall,
    reply: &mut ProviderReply,
    payload: &Value,
) -> Option<()> {
    let retained = decode_receipt_capsule(&payload["feedback_delivery_capsule"])?;
    fields(
        &retained,
        &[
            "namespace",
            "operation_id",
            "idempotency_key",
            "request_semantic_sha256",
        ],
    )?;
    let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
    let request: Value = serde_json::from_slice(&call.payload.bytes).ok()?;
    let expected = project(call, &request, &namespace, None)??;
    let admission =
        decode_receipt_capsule(&expected["common_control"]["feedback_delivery_capsule"])?;
    let operation = string(&retained["operation_id"])?;
    let key = string(&retained["idempotency_key"])?;
    let duplicate =
        reply.terminal.committed_effect().state() == crate::CommittedEffectState::Duplicate;
    if payload["common_control"] != "feedback"
        || retained["namespace"] != namespace.as_str()
        || retained["request_semantic_sha256"] != admission["request_semantic_sha256"]
        || Some(key) != call.idempotency_key.as_deref()
        || operation.len() > 256
        || (!duplicate && operation != call.operation_id)
        || payload["replayed"].as_bool()? != duplicate
    {
        return None;
    }
    if duplicate {
        let effect = tracedecay_memory_provider_api::CommittedEffectEvidence::duplicate(
            reply.state_generation,
            key,
            operation,
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
    Some(())
}

pub(crate) fn reconstruct(
    call: &ProviderCall,
    reply: &mut ProviderReply,
    readiness: &crate::AcceptedReadiness,
) -> Option<()> {
    let payload: Value = serde_json::from_slice(&reply.payload.as_ref()?.bytes).ok()?;
    let mut output = payload.as_object()?.clone();
    if !output.contains_key("common_control") {
        return None;
    }
    output.remove("common_control");
    output.remove("replayed");
    output.remove("no_change");
    output.remove("_retained_receipt");
    if call.operation == ProviderOperation::Feedback {
        reconstruct_feedback_delivery(call, reply, &payload)?;
        output.remove("feedback_delivery_capsule");
    }
    if call.operation == ProviderOperation::Health {
        let mut limits_digest = Sha256::new();
        crate::digest_limits(&mut limits_digest, readiness.effective_limits);
        output = json!({"provider_id": call.provider_id.as_str(), "provider_instance_id": readiness.provider_instance_id,
            "implementation_identity_digest": readiness.descriptor.implementation_identity_sha256,
            "state_identity_digest": hex_digest(&Sha256::digest(serde_json::to_vec(&json!([payload["state_digest"], readiness.descriptor.state_schema_version, reply.state_generation])).ok()?)),
            "state_generation": reply.state_generation, "scope_digest": call.exact_scope.exact_scope_sha256(), "readiness": "ready",
            "capability_states": readiness.descriptor.capabilities.iter().map(|capability| json!({"capability_id": capability.as_str(), "state": "available"})).collect::<Vec<_>>(),
            "effective_limits_digest": hex_digest(&limits_digest.finalize()), "backlog": 0, "recovery_state": "ready", "warnings": []}).as_object()?.clone();
    } else if call.operation == ProviderOperation::Inspection
        && payload["view"] == "capability_status"
    {
        let request: Value = serde_json::from_slice(&call.payload.bytes).ok()?;
        if request["view"] != "capability_status"
            || payload["common_control"] != "inspection"
            || payload["state_generation"].as_u64()? != reply.state_generation
            || reply.state_generation != call.expected_state_generation
            || !readiness.matches_call(call, &readiness.descriptor)
        {
            return None;
        }
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let projected = project(call, &request, &namespace, None)??;
        let after = projected["common_control"]["after"].as_u64()?;
        let offset = usize::try_from(after).ok()?;
        if offset > readiness.descriptor.capabilities.len() {
            return None;
        }
        let maximum_items = request["maximum_items"]
            .as_u64()?
            .min(readiness.effective_limits.inspection_items);
        let maximum_bytes = request["maximum_bytes"]
            .as_u64()?
            .min(readiness.effective_limits.response_bytes);
        let items = readiness
            .descriptor
            .capabilities
            .iter()
            .skip(offset)
            .take(usize::try_from(maximum_items).ok()?)
            .map(|capability| json!({"capability_id": capability.as_str(), "state": "available"}))
            .collect::<Vec<_>>();
        let binding = cursor_binding(call, &request)?;
        // Try complete public replies, including cursor, warnings, caller identity,
        // and extensions. A payload-only sum cannot enforce the negotiated ceiling.
        let minimum_items = usize::from(offset < readiness.descriptor.capabilities.len());
        for count in (minimum_items..=items.len()).rev() {
            let cursor = after.checked_add(count as u64)?;
            let partial = offset.checked_add(count)? < readiness.descriptor.capabilities.len();
            let output = json!({"view": "capability_status", "items": &items[..count],
                "coverage": if partial { "partial" } else { "complete" },
                "next_cursor": partial.then(|| format!("ncm-cursor:{cursor}:{binding}")),
                "redactions": [], "state_generation": reply.state_generation,
                "warnings": if partial { vec!["ncm.inspection.incomplete_or_withheld"] } else { vec![] }});
            let bytes = serde_json::to_vec(&output).ok()?;
            if bytes.len() as u64 > maximum_bytes {
                continue;
            }
            let mut candidate = reply.clone();
            candidate.payload = Some(
                CanonicalPayload::new(
                    call.payload.contract_id.clone(),
                    bytes.clone(),
                    hex_digest(&Sha256::digest(&bytes)),
                )
                .ok()?,
            );
            candidate.extensions.clone_from(&call.extensions);
            if candidate
                .validate(readiness.effective_limits.response_bytes)
                .is_ok()
                && crate::encoded_response_bytes(call, &candidate)
                    <= readiness.effective_limits.response_bytes
            {
                *reply = candidate;
                return Some(());
            }
        }
        // A continuation must consume an item. Report the actual capacity limit
        // instead of returning a cursor at the same offset indefinitely.
        *reply = crate::NcmProviderAdapter::invoke_failure(
            call,
            TerminalCode::CapacityExceeded,
            "ncm.inspection.capacity",
        );
        reply.extensions.clone_from(&call.extensions);
        return Some(());
    } else if call.operation == ProviderOperation::Inspection {
        let request: Value = serde_json::from_slice(&call.payload.bytes).ok()?;
        let namespace = NcmNamespace::from_exact_scope(&call.exact_scope);
        let retained_locator = match request.get("target") {
            Some(raw_target) => {
                let projected = target(call, raw_target, &namespace)?;
                Some(string(&projected["retained_source_locator"])?.to_owned())
            }
            None => None,
        };
        let mut items = Vec::new();
        let mut partial = payload["partial"].as_bool()?;
        let mut bytes_used = 0_u64;
        let mut delivery_identity = None;
        let mut seen_stable = BTreeSet::new();
        for row in payload["items"].as_array()? {
            if items.len() as u64 >= request["maximum_items"].as_u64()? {
                partial = true;
                break;
            }
            if request["view"] == "maintenance_receipt" {
                if !items.is_empty() {
                    return None;
                }
                let item = maintenance_receipt_item(call, &request, row)?;
                let item_bytes = serde_json::to_vec(&item).ok()?.len() as u64;
                if bytes_used.saturating_add(item_bytes) > request["maximum_bytes"].as_u64()? {
                    partial = true;
                    break;
                }
                bytes_used += item_bytes;
                items.push(item);
                continue;
            }
            if row.get("legacy_record_id").is_some() {
                if request["view"] != "trace" || !partial || !items.is_empty() {
                    return None;
                }
                let item = legacy_trace_item(
                    &namespace,
                    request["selector"]["stable_memory_ref"].as_str()?,
                    row,
                )?;
                let item_bytes = serde_json::to_vec(&item).ok()?.len() as u64;
                if bytes_used.saturating_add(item_bytes) > request["maximum_bytes"].as_u64()? {
                    break;
                }
                bytes_used += item_bytes;
                items.push(item);
                continue;
            }
            let retained = decode_capsule(&row["provenance"])?;
            let original = &retained["original_source"];
            let source = attribution(original)?;
            if scope(&retained["delivery_scope"])? != call.exact_scope {
                return None;
            }
            validate_source_binding(
                &namespace,
                &source,
                &row["provenance"],
                row["source"].as_str()?,
            )?;
            let stable = stable_reference(
                &namespace,
                row["record_id"].as_u64()?,
                row["provenance"]["common_capsule"]["sha256"].as_str()?,
            );
            if row["stable_memory_ref"] != stable {
                return None;
            }
            if request["view"] == "source_influence" {
                if source.source.source_key != request["selector"]["source_key"].as_str()? {
                    return None;
                }
                if let Some(expected) = request["selector"].get("stable_memory_ref") {
                    if let Some(locator) = retained_locator.as_deref() {
                        if expected.as_str()? != locator {
                            return None;
                        }
                    } else if expected.as_str()? != stable {
                        return None;
                    }
                }
            }
            let mut item = if request["view"] == "delivery_receipt" {
                let delivery = decode_receipt_capsule(&row["delivery_capsule"])?;
                fields(&delivery, &["operation_id", "idempotency_key"])?;
                let operation_id = string(&delivery["operation_id"])?;
                let idempotency_key = string(&delivery["idempotency_key"])?;
                let receipt = string(&row["provider_receipt_digest"])?;
                if idempotency_key != request["selector"]["idempotency_key"].as_str()?
                    || request["selector"]
                        .get("stable_memory_ref")
                        .is_some_and(|selected| {
                            selected.as_str()
                                != Some(retained_locator.as_deref().unwrap_or(stable.as_str()))
                        })
                    || !crate::NcmProviderAdapter::valid_sha256(receipt)
                    || !seen_stable.insert(stable.clone())
                {
                    return None;
                }
                let identity = (
                    operation_id.to_owned(),
                    idempotency_key.to_owned(),
                    receipt.to_owned(),
                );
                if delivery_identity
                    .as_ref()
                    .is_some_and(|previous| previous != &identity)
                {
                    return None;
                }
                delivery_identity = Some(identity);
                json!({"operation_id": operation_id, "idempotency_key": idempotency_key, "provider_receipt_digest": receipt, "stable_memory_ref": stable})
            } else if request["view"] == "trace" {
                if let Some(locator) = retained_locator.as_deref() {
                    if request["selector"]["stable_memory_ref"] != locator {
                        return None;
                    }
                } else if request["selector"]["stable_memory_ref"] != stable {
                    return None;
                }
                let content = row["content"].as_str()?;
                if content != retained["projection"]["value_text"].as_str()? {
                    return None;
                }
                if row["provenance"]["control"]["restricted"] == true {
                    json!({"stable_memory_ref": stable, "content": null, "content_sha256": null, "original_source": null})
                } else {
                    json!({"stable_memory_ref": stable, "content": content, "content_sha256": hex_digest(&Sha256::digest(content.as_bytes())), "original_source": original})
                }
            } else {
                let effect_summary = serde_json::to_string(&json!({"provider_id": "ncm",
                    "suppressed": row["provenance"]["control"]["feedback"]["suppressed"].as_bool().unwrap_or(false),
                    "centers_updated": row["provenance"]["control"]["feedback"]["centers_updated"].as_u64().unwrap_or(0)})).ok()?;
                if effect_summary.is_empty() || effect_summary.len() > 8192 {
                    return None;
                }
                let settled_feedback = if request["view"] == "source_influence" {
                    let mut counts = json!({"helpful": 0, "harmful": 0, "ignored": 0, "corrected": 0, "superseded": 0});
                    if let Some(stored) =
                        row["provenance"].pointer("/control/feedback/settled_counts")
                    {
                        for (signal, count) in stored.as_object()? {
                            counts.get(signal)?;
                            counts[signal] = json!(count.as_u64()?);
                        }
                    }
                    counts
                } else {
                    json!(
                        row["provenance"]["control"]["feedback"]["settled_counts"]
                            .as_object()
                            .cloned()
                            .unwrap_or_default()
                    )
                };
                json!({"target": {"provider_id": call.provider_id.as_str(), "registration_revision": call.registration_revision,
                "original_scope": original["origin_scope"], "delivery_scope": scope_value(&call.exact_scope), "source": original["source"],
                "reference": {"kind": "stable_memory_ref", "reference": stable}}, "source": original["source"], "active": row["active"],
                "disposition": row["disposition"], "settled_feedback": settled_feedback,
                "last_feedback_receipt": row["provenance"]["control"]["feedback"]["receipt"],
                "provider_local_effect_summary": effect_summary})
            };
            if let Some(locator) = retained_locator.as_deref() {
                match request["view"].as_str()? {
                    "source_influence" => {
                        item["target"]["reference"] =
                            json!({"kind": "retained_source_locator", "reference": locator});
                    }
                    "trace" | "delivery_receipt" => {
                        item["stable_memory_ref"] = json!(locator);
                    }
                    _ => return None,
                }
            }
            let item_bytes = serde_json::to_vec(&item).ok()?.len() as u64;
            if bytes_used.saturating_add(item_bytes) > request["maximum_bytes"].as_u64()? {
                partial = true;
                break;
            }
            bytes_used += item_bytes;
            items.push(item);
        }
        if request["view"] == "trace" && items.is_empty() && !partial {
            let item = json!({"stable_memory_ref": request["selector"]["stable_memory_ref"], "content": null, "content_sha256": null, "original_source": null});
            if serde_json::to_vec(&item).ok()?.len() as u64 <= request["maximum_bytes"].as_u64()? {
                items.push(item);
            }
            partial = true;
        }
        let cursor = match payload["cursor_after"].as_u64() {
            Some(after) => json!(format!(
                "ncm-cursor:{after}:{}",
                cursor_binding(call, &request)?
            )),
            None => Value::Null,
        };
        output = json!({"view": request["view"], "items": items, "coverage": if partial { "partial" } else { "complete" },
            "next_cursor": cursor, "redactions": [], "state_generation": reply.state_generation, "warnings": if partial { vec!["ncm.inspection.incomplete_or_withheld"] } else { vec![] }}).as_object()?.clone();
    } else {
        output.insert(
            "provider_receipt_digest".to_owned(),
            json!(
                reply
                    .terminal
                    .committed_effect()
                    .provider_receipt_sha256()
                    .unwrap_or(&call.payload.sha256)
            ),
        );
    }
    let bytes = serde_json::to_vec(&output).ok()?;
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
#[allow(clippy::unwrap_used)]
mod legacy_trace_tests {
    use super::*;

    #[test]
    fn legacy_reference_is_canonical_positive_sqlite_record_identity() {
        assert_eq!(legacy_record_id("1"), Some(1));
        assert_eq!(
            legacy_record_id(&i64::MAX.to_string()),
            Some(i64::MAX as u64)
        );
        for malformed in [
            "",
            "0",
            "01",
            "+1",
            "-1",
            "1.0",
            "1e0",
            " 1",
            "1 ",
            "١",
            "9223372036854775808",
        ] {
            assert_eq!(legacy_record_id(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn legacy_trace_requires_exact_namespace_record_and_unknown_attribution() {
        let namespace = NcmNamespace("ab".repeat(32));
        let row = json!({"legacy_record_id":1,"legacy_namespace_sha256":hex_digest(&Sha256::digest(namespace.as_str().as_bytes())),"stable_memory_ref":"1",
            "content":"retained 🦀", "content_sha256":hex_digest(&Sha256::digest("retained 🦀".as_bytes())),"original_source":null});
        assert!(legacy_trace_item(&namespace, "1", &row).is_some());
        // This is the same string containment primitive used before reconstruction.
        assert!(!crate::json_contains_any(&row, &[namespace.as_str()]));
        let mut plaintext_namespace = row.clone();
        plaintext_namespace["namespace"] = json!(namespace.as_str());
        assert!(crate::json_contains_any(
            &plaintext_namespace,
            &[namespace.as_str()]
        ));
        assert!(legacy_trace_item(&namespace, "1", &plaintext_namespace).is_none());
        for (field, value) in [
            (
                "legacy_namespace_sha256",
                json!(hex_digest(&Sha256::digest("cd".repeat(32).as_bytes()))),
            ),
            ("legacy_namespace_sha256", Value::Null),
            ("legacy_record_id", json!(2)),
            ("stable_memory_ref", json!("01")),
            ("content_sha256", json!("00".repeat(32))),
            ("original_source", json!({"source":"invented"})),
        ] {
            let mut malformed = row.clone();
            malformed[field] = value;
            assert!(
                legacy_trace_item(&namespace, "1", &malformed).is_none(),
                "{field}"
            );
        }
    }
}
