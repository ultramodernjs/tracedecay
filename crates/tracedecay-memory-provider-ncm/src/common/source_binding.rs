//! Private source identities bind original scope and canonical source lineage.

use super::*;

pub(super) struct SourceBinding {
    pub(super) source_id: String,
    pub(super) legacy_source_id: String,
}

impl SourceBinding {
    pub(super) fn provenance(&self) -> Value {
        json!({"version": 1, "source_id": self.source_id,
            "legacy_source_id": self.legacy_source_id})
    }

    pub(super) fn target(&self) -> Value {
        json!({"source_id": self.source_id, "legacy_source_id": self.legacy_source_id})
    }
}

pub(super) fn source_binding(
    namespace: &NcmNamespace,
    source: &SourceAttribution,
) -> Option<SourceBinding> {
    let origin = source.origin_scope.recorded_scope().ok()?;
    binding_for_lineage(
        namespace,
        origin,
        source.source.canonical_provider_id.as_str(),
        &source.source.canonical_session_id,
        &source.source.source_key,
    )
}

fn binding_for_lineage(
    namespace: &NcmNamespace,
    scope: &OwnedExactScope,
    provider: &str,
    session: &str,
    source_key: &str,
) -> Option<SourceBinding> {
    let identity = serde_json::to_string(&json!([
        scope.profile_id,
        scope.project_id,
        provider,
        session,
        source_key,
    ]))
    .ok()?;
    Some(SourceBinding {
        source_id: opaque_surface_id(namespace, b"common-source-key-v1", &identity),
        legacy_source_id: opaque_surface_id(namespace, b"forget-source-key", source_key),
    })
}

/// A current record binds its admitted delivery scope and canonical session;
/// it makes no claim about the scope or time of an original historical event.
pub(super) fn current_source_binding(
    namespace: &NcmNamespace,
    exact: &OwnedExactScope,
    value: &Value,
) -> Option<SourceBinding> {
    fields(&value["source_identity"], &["canonical_observation_id"])?;
    string(&value["source_identity"]["canonical_observation_id"])?;
    let canonical = &value["canonical_payload"];
    if canonical["version"].as_u64()? != 1 {
        return None;
    }
    string(&canonical["native_record_kind"])?;
    string(&canonical["stable_record_id"])?;
    let provider = string(&canonical["provider"])?;
    let session = string(&canonical["relations"]["session_id"])?;
    binding_for_lineage(
        namespace,
        exact,
        provider,
        session,
        &exact.session_forget_source_key(session),
    )
}

pub(crate) fn project_current_source_id(
    namespace: &NcmNamespace,
    call: &ProviderCall,
    value: &Value,
) -> Option<String> {
    Some(current_source_binding(namespace, &call.exact_scope, value)?.source_id)
}

pub(super) fn validate_current_source_binding(
    namespace: &NcmNamespace,
    exact: &OwnedExactScope,
    retained: &Value,
    provenance: &Value,
    actual: &str,
) -> Option<()> {
    let expected = current_source_binding(namespace, exact, retained)?;
    let binding = provenance.get("source_binding")?;
    fields(binding, &["version", "source_id", "legacy_source_id"])?;
    (binding == &expected.provenance() && actual == expected.source_id).then_some(())
}

pub(crate) fn project_source_id(namespace: &NcmNamespace, original: &Value) -> Option<String> {
    Some(source_binding(namespace, &attribution(original)?)?.source_id)
}

/// Existing raw identities remain readable only in their original unbound form.
/// A v1 claim must agree with both the retained original and the stored full ID.
pub(super) fn validate_source_binding(
    namespace: &NcmNamespace,
    source: &SourceAttribution,
    provenance: &Value,
    actual: &str,
) -> Option<()> {
    let Some(binding) = provenance.get("source_binding") else {
        return (actual
            == opaque_surface_id(namespace, b"forget-source-key", &source.source.source_key))
        .then_some(());
    };
    fields(binding, &["version", "source_id", "legacy_source_id"])?;
    let expected = source_binding(namespace, source)?;
    (binding == &expected.provenance() && actual == expected.source_id).then_some(())
}

/// Fresh host admission chooses a single original lineage per requested alias.
/// Multiple revisions of that lineage are harmless; multiple origins are not.
pub(super) fn claimed_source_bindings(
    namespace: &NcmNamespace,
    sources: &[String],
    admission: &CurrentAdvisoryAdmission,
) -> Option<Vec<SourceBinding>> {
    let mut bindings = std::collections::BTreeMap::new();
    for key in sources {
        let mut matching = std::collections::BTreeMap::new();
        for entry in &admission.history_sources {
            if entry.attribution.source.source_key == *key {
                let binding = source_binding(namespace, &entry.attribution)?;
                matching.insert(binding.source_id.clone(), binding);
            }
        }
        if matching.len() != 1 {
            return None;
        }
        bindings.extend(matching);
    }
    Some(bindings.into_values().collect())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use tracedecay_memory_provider_api::{
        CancellationToken, CurrentSourceDisposition, GrantedHistorySource, OperationControl,
        OwnedVersionedId, ProviderCallParts, ProviderOperation,
    };

    fn fixture() -> (OwnedExactScope, Value) {
        let exact = OwnedExactScope::new(
            "profile",
            "project",
            "repository",
            "worktree",
            "master",
            "delivery-session",
            format!("sha256:{}", "ab".repeat(32)),
        )
        .unwrap();
        let original = json!({
            "source": {"canonical_provider_id":"claude", "canonical_session_id":"original-session",
                "source_key":"shared-key", "stable_record_id":"record-1", "observation_id":"observation-1",
                "source_revision":"revision-1", "content_sha256":"ab".repeat(32)},
            "origin_scope":{"state":"recorded", "exact_scope_identity":scope_value(&exact), "authority_ref":"authority"},
            "source_sequence":1, "occurred_at":"2026-01-01T00:00:00Z", "ingested_at":"2026-01-01T00:00:00Z",
            "validity":{"valid_from":"2026-01-01T00:00:00Z", "valid_until":null, "superseded_at":null, "superseded_by":null, "revoked_at":null}
        });
        (exact, original)
    }

    fn call(exact: &OwnedExactScope, operation: ProviderOperation, value: Value) -> ProviderCall {
        let bytes = serde_json::to_vec(&value).unwrap();
        ProviderCall::new(ProviderCallParts {
            operation,
            provider_id: OwnedProviderId::new(crate::NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: "ab".repeat(32),
            exact_scope: exact.clone(),
            request_id: "source-binding-request".to_owned(),
            operation_id: "source-binding-operation".to_owned(),
            expected_state_generation: 0,
            idempotency_key: operation
                .mutates_provider_state()
                .then(|| "source-binding-key".to_owned()),
            control: OperationControl::new(i64::MAX, 60_000, CancellationToken::new()),
            payload: CanonicalPayload::new(
                OwnedVersionedId::new(match operation {
                    ProviderOperation::Recall => "tracedecay.memory.provider.recall.v1",
                    ProviderOperation::DeleteBySource => {
                        "tracedecay.memory.provider.delete-by-source.v1"
                    }
                    _ => "tracedecay.memory.provider.observation.v1",
                })
                .unwrap(),
                bytes.clone(),
                hex_digest(&Sha256::digest(&bytes)),
            )
            .unwrap(),
            required_capabilities: vec![OwnedVersionedId::new(operation.capability_id()).unwrap()],
            extensions: Vec::new(),
        })
        .unwrap()
    }

    fn granted(original: &Value) -> GrantedHistorySource {
        GrantedHistorySource {
            attribution: attribution(original).unwrap(),
            current_disposition: CurrentSourceDisposition {
                state: tracedecay_memory_provider_api::contract::SourceDisposition::Deleted,
                authority_ref: "fresh-disposition".to_owned(),
                authority_revision: Some(1),
                checked_at_utc_nanos: 0,
            },
        }
    }

    #[test]
    fn identity_separates_original_lineage_and_namespace_but_survives_new_revisions() {
        let (exact, original) = fixture();
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let expected = source_binding(&namespace, &attribution(&original).unwrap()).unwrap();
        for (path, value) in [
            ("/source/canonical_provider_id", json!("codex")),
            ("/source/canonical_session_id", json!("another-session")),
            ("/source/source_key", json!("another-key")),
            (
                "/origin_scope/exact_scope_identity/profile_id",
                json!("another-profile"),
            ),
            (
                "/origin_scope/exact_scope_identity/project_id",
                json!("another-project"),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = value;
            let binding = source_binding(&namespace, &attribution(&changed).unwrap()).unwrap();
            assert_ne!(binding.source_id, expected.source_id, "{path}");
            if path != "/source/source_key" {
                assert_eq!(binding.legacy_source_id, expected.legacy_source_id);
            }
        }
        let mut revision = original.clone();
        revision["source"]["source_revision"] = json!("revision-2");
        revision["source"]["observation_id"] = json!("observation-2");
        revision["source"]["content_sha256"] = json!("cd".repeat(32));
        revision["source"]["stable_record_id"] = json!("record-2");
        assert_eq!(
            project_source_id(&namespace, &revision).unwrap(),
            expected.source_id
        );
        let mut other_delivery = exact.clone();
        other_delivery.agent_session_id = "another-delivery-session".to_owned();
        assert_ne!(
            project_source_id(&NcmNamespace::from_exact_scope(&other_delivery), &original).unwrap(),
            expected.source_id,
        );
        other_delivery.worktree_identity = "another-worktree".to_owned();
        assert_ne!(
            project_source_id(&NcmNamespace::from_exact_scope(&other_delivery), &original).unwrap(),
            expected.source_id,
        );
    }

    #[test]
    fn current_checkout_recall_preserves_delivery_binding_and_refuses_forgery() {
        let (delivery, _) = fixture();
        let namespace =
            NcmNamespace::from_scope(&delivery, NcmNamespaceBinding::CheckoutObservationsV1);
        let observation = json!({
            "source_identity": {"canonical_observation_id": format!("sha256:{}", "ac".repeat(32))},
            "observation_kind": "session.message_committed.v1",
            "payload_contract": "tracedecay.memory.observation.session-message.v1",
            "canonical_payload": {
                "version": 1, "provider": "codex", "native_record_kind": "message",
                "stable_record_id": "stored-record", "relations": {"session_id": "canonical-session", "project_id": delivery.project_id},
                "facts": [{"kind": "message", "role": "assistant", "content": "Remember this checkout"}]
            }
        });
        let observed = call(&delivery, ProviderOperation::Observe, observation.clone());
        let provenance = project_current_attribution(&observed, &observation, &namespace).unwrap();
        let retained = decode_capsule(&provenance).unwrap();
        let source_id = current_source_binding(&namespace, &delivery, &observation)
            .unwrap()
            .source_id;
        let mut query_scope = delivery.clone();
        query_scope.agent_session_id = "new-session".to_owned();
        query_scope.resolved_scope_digest = format!("sha256:{}", "ef".repeat(32));
        let query = call(&query_scope, ProviderOperation::Recall, json!({}));
        let admitted =
            retained_source(&query, &namespace, &retained, &provenance, &source_id, None).unwrap();
        assert_eq!(
            admitted.source_key(),
            delivery.session_forget_source_key("canonical-session")
        );
        assert_ne!(
            admitted.source_key(),
            query_scope.session_forget_source_key("canonical-session")
        );
        assert!(
            validate_current_source_binding(
                &namespace,
                &query_scope,
                &retained,
                &provenance,
                &source_id
            )
            .is_none()
        );
        for field in [
            "profile_id",
            "project_id",
            "repository_identity",
            "worktree_identity",
            "branch_identity",
        ] {
            let mut foreign = scope_value(&query_scope);
            foreign[field] = json!("foreign");
            let query = call(
                &scope(&foreign).unwrap(),
                ProviderOperation::Recall,
                json!({}),
            );
            assert!(
                retained_source(&query, &namespace, &retained, &provenance, &source_id, None)
                    .is_none(),
                "{field}"
            );
        }
        for malformed in [
            Value::Null,
            json!({"version": 2, "source_id": source_id, "legacy_source_id": "forged"}),
            json!({"version": 1, "source_id": source_id}),
            json!({"version": 1, "source_id": "forged", "legacy_source_id": "forged"}),
        ] {
            let mut forged = provenance.clone();
            forged["source_binding"] = malformed;
            assert!(
                retained_source(&query, &namespace, &retained, &forged, &source_id, None).is_none()
            );
        }
        let mut forged = retained.clone();
        forged["canonical_payload"]["provider"] = json!("claude");
        assert!(
            retained_source(&query, &namespace, &forged, &provenance, &source_id, None).is_none()
        );
        forged = retained.clone();
        forged["canonical_payload"]["relations"]["session_id"] = json!("forged-session");
        assert!(
            retained_source(&query, &namespace, &forged, &provenance, &source_id, None).is_none()
        );
    }

    #[test]
    fn reconstruction_accepts_actual_legacy_and_bound_full_ids_and_rejects_forgery() {
        let (exact, original) = fixture();
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let source = attribution(&original).unwrap();
        let binding = source_binding(&namespace, &source).unwrap();
        let provenance = json!({"source_binding":binding.provenance()});
        assert!(
            validate_source_binding(&namespace, &source, &json!({}), &binding.legacy_source_id)
                .is_some()
        );
        assert!(
            validate_source_binding(&namespace, &source, &provenance, &binding.source_id).is_some()
        );
        assert!(
            validate_source_binding(&namespace, &source, &json!({}), &binding.source_id).is_none()
        );
        assert!(
            validate_source_binding(&namespace, &source, &provenance, &binding.legacy_source_id)
                .is_none()
        );
        for bad in [
            Value::Null,
            json!({"version":2,"source_id":binding.source_id,"legacy_source_id":binding.legacy_source_id}),
            json!({"version":1,"source_id":binding.source_id}),
            json!({"version":1,"source_id":binding.source_id,"legacy_source_id":"forged"}),
            json!({"version":1,"source_id":"forged","legacy_source_id":binding.legacy_source_id}),
            json!({"version":1,"source_id":binding.source_id,"legacy_source_id":binding.legacy_source_id,"extra":true}),
        ] {
            assert!(
                validate_source_binding(
                    &namespace,
                    &source,
                    &json!({"source_binding":bad}),
                    &binding.source_id
                )
                .is_none()
            );
        }
        let mut other = source.clone();
        other.source.canonical_session_id = "colliding-original-session".to_owned();
        assert!(
            validate_source_binding(&namespace, &other, &provenance, &binding.source_id).is_none()
        );
        for origin in [
            OriginScopeEvidence::IngestionOnly,
            OriginScopeEvidence::Unavailable,
        ] {
            other.origin_scope = origin;
            assert!(source_binding(&namespace, &other).is_none());
            assert!(
                validate_source_binding(&namespace, &other, &json!({}), &binding.legacy_source_id)
                    .is_some()
            );
        }
    }

    #[test]
    fn claimed_deletion_deduplicates_revisions_and_refuses_ambiguous_or_missing_origins() {
        let (exact, original) = fixture();
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let call = call(&exact, ProviderOperation::DeleteBySource, json!({}));
        let keys = vec!["shared-key".to_owned()];
        let mut revision = original.clone();
        revision["source"]["observation_id"] = json!("observation-2");
        revision["source"]["source_revision"] = json!("revision-2");
        let current = CurrentAdvisoryAdmission::new(
            &call,
            vec![granted(&original), granted(&revision)],
            None,
        )
        .unwrap();
        let selected = claimed_source_bindings(&namespace, &keys, &current).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].source_id,
            project_source_id(&namespace, &original).unwrap()
        );
        assert!(
            claimed_source_bindings(&namespace, &["missing-key".to_owned()], &current).is_none()
        );
        revision["source"]["canonical_session_id"] = json!("another-original-session");
        let ambiguous = CurrentAdvisoryAdmission::new(
            &call,
            vec![granted(&original), granted(&revision)],
            None,
        )
        .unwrap();
        assert!(claimed_source_bindings(&namespace, &keys, &ambiguous).is_none());
        let empty = CurrentAdvisoryAdmission::new(&call, vec![], None).unwrap();
        assert!(claimed_source_bindings(&namespace, &keys, &empty).is_none());
    }

    #[test]
    fn recall_excludes_raw_source_alias_before_final_candidate_byte_budget() {
        let (exact, original) = fixture();
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let request = json!({
            "temporal_query":{"mode":"current","evaluation_time":"2026-01-02T00:00:00Z",
                "as_of":null,"interval_start":null,"interval_end":null,"include_superseded":false,
                "include_revoked":false,"unknown_validity_policy":"exclude"},
            "exclusions":{"source_refs":["shared-key"]},
            "budgets":{"maximum_candidates":1,"maximum_candidate_content_bytes":16,
                "maximum_total_content_bytes":16,"maximum_source_refs_per_candidate":1,"maximum_warnings":4}
        });
        let call = call(&exact, ProviderOperation::Recall, request);
        for legacy in [false, true] {
            let mut rows = Vec::new();
            for (index, content) in ["excluded content over the byte budget", "kept"]
                .into_iter()
                .enumerate()
            {
                let mut item = original.clone();
                if index == 1 {
                    item["source"]["source_key"] = json!("another-key");
                }
                let observation = json!({"source_identity":{"original_source":item},
                    "observation_kind":"session.message_committed.v1", "canonical_payload":{"role":"assistant","content":content}});
                let mut provenance = project_attribution(&call, &observation, &namespace, None)
                    .unwrap()
                    .unwrap();
                let binding = source_binding(&namespace, &attribution(&item).unwrap()).unwrap();
                let source = if legacy {
                    provenance.as_object_mut().unwrap().remove("source_binding");
                    binding.legacy_source_id
                } else {
                    binding.source_id
                };
                let record = (index + 1) as u64;
                let stable = stable_reference(
                    &namespace,
                    record,
                    provenance["common_capsule"]["sha256"].as_str().unwrap(),
                );
                let token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
                let mut digest = Sha256::new();
                for field in [token.as_bytes(), stable.as_bytes()] {
                    digest.update((field.len() as u64).to_be_bytes());
                    digest.update(field);
                }
                rows.push(json!({"record_id":record,"source":source,"stable_memory_ref":stable,
                    "candidate_id":format!("ncm-candidate:{}",hex_digest(&digest.finalize())),
                    "key_text":content,"value_text":format!("assistant: {content}"),"activation":1.0,"provenance":provenance}));
            }
            let worker = serde_json::to_vec(&json!({"common_recall":{"candidates":rows,
                "truncated":false,"unknown_items":0,"excluded_items":0,"scanned_items":2,"score_upper_bound":1.0}})).unwrap();
            let mut reply = ProviderReply {
                terminal: tracedecay_memory_provider_api::TerminalRecord::internal_failure_before_dispatch_for_call(&call, "source-binding-test"),
                payload: Some(CanonicalPayload::new(call.payload.contract_id.clone(), worker.clone(), hex_digest(&Sha256::digest(&worker))).unwrap()),
                warnings: Vec::new(), extensions: Vec::new(), state_generation: 0,
            };
            reconstruct_recall(&call, "ncm-instance", &mut reply, None).unwrap();
            let result: Value = serde_json::from_slice(&reply.payload.unwrap().bytes).unwrap();
            assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
            assert_eq!(result["candidates"][0]["content"], "assistant: kept");
            assert_eq!(result["coverage"]["excluded_items"], 1);
            assert_eq!(result["coverage"]["truncated_items"], 0);
        }
    }

    fn recall_projection_fixture(
        messages: [(&str, &str); 2],
    ) -> (OwnedExactScope, Value, Vec<Value>, Vec<Value>) {
        let (exact, original) = fixture();
        let namespace = NcmNamespace::from_exact_scope(&exact);
        let request = json!({
            "temporal_query":{"mode":"current","evaluation_time":"2026-01-02T00:00:00Z",
                "as_of":null,"interval_start":null,"interval_end":null,"include_superseded":false,
                "include_revoked":false,"unknown_validity_policy":"exclude"},
            "exclusions":{"stable_memory_refs":[],"candidate_ids":[],"source_refs":[],
                "trace_refs":[],"observation_ids":[],"content_sha256":[]},
            "budgets":{"maximum_candidates":2,"maximum_candidate_content_bytes":128,
                "maximum_total_content_bytes":256,"maximum_source_refs_per_candidate":1,
                "maximum_trace_refs_per_candidate":1,"maximum_warnings":4,
                "maximum_extensions_per_candidate":1}
        });
        let call = call(&exact, ProviderOperation::Recall, request.clone());
        let mut rows = Vec::new();
        let mut originals = Vec::new();
        for (index, (role, content)) in messages.into_iter().enumerate() {
            let record = (index + 1) as u64;
            let mut item = original.clone();
            item["source"]["source_key"] = json!(format!("source-{record}"));
            item["source"]["stable_record_id"] = json!(format!("record-{record}"));
            item["source"]["observation_id"] = json!(format!("observation-{record}"));
            item["source_sequence"] = json!(record);
            let observation = json!({"source_identity":{"original_source":item},
                "observation_kind":"session.message_committed.v1",
                "canonical_payload":{"role":role,"content":content}});
            let provenance = project_attribution(&call, &observation, &namespace, None)
                .unwrap()
                .unwrap();
            let source = source_binding(&namespace, &attribution(&item).unwrap())
                .unwrap()
                .source_id;
            let stable = stable_reference(
                &namespace,
                record,
                provenance["common_capsule"]["sha256"].as_str().unwrap(),
            );
            let token = opaque_surface_id(&namespace, b"recall-request", &call.request_id);
            let mut digest = Sha256::new();
            for field in [token.as_bytes(), stable.as_bytes()] {
                digest.update((field.len() as u64).to_be_bytes());
                digest.update(field);
            }
            rows.push(
                json!({"record_id":record,"source":source,"stable_memory_ref":stable,
                "candidate_id":format!("ncm-candidate:{}",hex_digest(&digest.finalize())),
                "key_text":content,"value_text":format!("{role}: {content}"),
                "activation":if index == 0 {1.0} else {0.5},"provenance":provenance}),
            );
            originals.push(item);
        }
        (exact, request, rows, originals)
    }

    fn reconstruct_fixture(call: &ProviderCall, rows: &[Value]) -> Value {
        let worker = serde_json::to_vec(&json!({"common_recall":{"candidates":rows,
            "truncated":false,"unknown_items":0,"excluded_items":0,
            "scanned_items":rows.len(),"score_upper_bound":1.0}}))
        .unwrap();
        let mut reply = ProviderReply {
            terminal: tracedecay_memory_provider_api::TerminalRecord::internal_failure_before_dispatch_for_call(call, "recall-projection-test"),
            payload: Some(CanonicalPayload::new(call.payload.contract_id.clone(), worker.clone(), hex_digest(&Sha256::digest(&worker))).unwrap()),
            warnings: Vec::new(), extensions: Vec::new(), state_generation: 2,
        };
        reconstruct_recall(call, "ncm-instance", &mut reply, None).unwrap();
        serde_json::from_slice(&reply.payload.unwrap().bytes).unwrap()
    }

    #[test]
    fn recall_exposes_retained_trace_and_defensively_excludes_it_before_budgeting() {
        let (exact, mut request, rows, originals) = recall_projection_fixture([
            ("assistant", "excluded retained evidence"),
            ("assistant", "kept"),
        ]);
        let full = reconstruct_fixture(
            &call(&exact, ProviderOperation::Recall, request.clone()),
            &rows,
        );
        for (candidate, row) in full["candidates"].as_array().unwrap().iter().zip(&rows) {
            let trace = json!([row["stable_memory_ref"]]);
            assert_eq!(candidate["trace_refs"], trace);
            assert_eq!(candidate["provenance"]["provider_trace_refs"], trace);
            assert_eq!(candidate["explanation"]["activation_trace_refs"], json!([]));
        }
        request["exclusions"]["trace_refs"] = full["candidates"][0]["trace_refs"].clone();
        request["budgets"]["maximum_candidates"] = json!(1);
        request["budgets"]["maximum_candidate_content_bytes"] = json!(16);
        request["budgets"]["maximum_total_content_bytes"] = json!(16);
        let filtered =
            reconstruct_fixture(&call(&exact, ProviderOperation::Recall, request), &rows);
        assert_eq!(filtered["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(filtered["candidates"][0]["content"], "assistant: kept");
        assert_eq!(
            filtered["candidates"][0]["provenance"]["original_sources"][0],
            originals[1]
        );
        assert_eq!(filtered["coverage"]["excluded_items"], 1);
        assert_eq!(filtered["coverage"]["truncated_items"], 0);
        assert_eq!(filtered["terminal"]["code"], "success");
    }

    #[test]
    fn recall_clips_utf8_under_candidate_and_remaining_total_budgets() {
        let (exact, request, rows, originals) = recall_projection_fixture([
            ("assistant", "éclair retained evidence"),
            ("assistant", "éclair second source"),
        ]);
        for (candidate_limit, total_limit, expected) in [
            (12, 128, ["assistant: ", "assistant: "]),
            (13, 25, ["assistant: é", "assistant: "]),
        ] {
            let mut bounded = request.clone();
            bounded["budgets"]["maximum_candidate_content_bytes"] = json!(candidate_limit);
            bounded["budgets"]["maximum_total_content_bytes"] = json!(total_limit);
            let result =
                reconstruct_fixture(&call(&exact, ProviderOperation::Recall, bounded), &rows);
            let candidates = result["candidates"].as_array().unwrap();
            assert_eq!(candidates.len(), 2);
            let mut total = 0;
            for ((candidate, expected), original) in candidates.iter().zip(expected).zip(&originals)
            {
                assert_eq!(candidate["content"], expected);
                assert_eq!(
                    candidate["content_sha256"],
                    hex_digest(&Sha256::digest(expected.as_bytes()))
                );
                assert_eq!(
                    serde_json::to_vec(&candidate["provenance"]["original_sources"][0]).unwrap(),
                    serde_json::to_vec(original).unwrap()
                );
                assert!(expected.len() <= candidate_limit);
                total += expected.len();
            }
            assert!(total <= total_limit);
            assert_eq!(result["terminal"]["code"], "partial");
            assert_eq!(result["coverage"]["truncated_items"], 2);
            assert_eq!(result["warnings"], json!(["ncm.recall_budget_truncated"]));
        }

        let mut excluded = request;
        excluded["budgets"]["maximum_candidates"] = json!(1);
        excluded["budgets"]["maximum_candidate_content_bytes"] = json!(12);
        excluded["exclusions"]["content_sha256"] = json!([hex_digest(&Sha256::digest(
            rows[0]["value_text"].as_str().unwrap().as_bytes()
        ))]);
        let result = reconstruct_fixture(&call(&exact, ProviderOperation::Recall, excluded), &rows);
        assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(result["candidates"][0]["content"], "assistant: ");
        assert_eq!(
            result["candidates"][0]["provenance"]["original_sources"][0],
            originals[1]
        );
        assert_eq!(result["coverage"]["excluded_items"], 1);
        assert_eq!(result["coverage"]["truncated_items"], 1);
    }

    #[test]
    fn recall_does_not_emit_or_charge_content_when_no_utf8_character_fits() {
        let (exact, mut request, rows, originals) = recall_projection_fixture([
            ("é", "cannot fit a complete initial character"),
            ("assistant", "fits one ASCII character"),
        ]);
        request["budgets"]["maximum_candidate_content_bytes"] = json!(1);
        request["budgets"]["maximum_total_content_bytes"] = json!(1);
        let result = reconstruct_fixture(&call(&exact, ProviderOperation::Recall, request), &rows);
        assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(result["candidates"][0]["content"], "a");
        assert_eq!(
            result["candidates"][0]["provenance"]["original_sources"][0],
            originals[1]
        );
        assert_eq!(result["coverage"]["truncated_items"], 2);
        assert_eq!(result["terminal"]["code"], "partial");
    }
}
