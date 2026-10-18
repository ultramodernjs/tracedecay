//! Narrow validation for inspectable canonical replay partial outcomes.

use super::*;
use crate::NcmSurfaceCall;
use tracedecay_memory_provider_api::ProviderOperation;

pub(crate) fn valid_replay_payload(surface: &NcmSurfaceCall, reply: &ProviderReply) -> bool {
    if surface.operation != ProviderOperation::Replay {
        return false;
    }
    let Some(payload) = reply.payload.as_ref() else {
        return false;
    };
    let Ok(request) = serde_json::from_slice::<Value>(&surface.payload.bytes) else {
        return false;
    };
    let Ok(response) = serde_json::from_slice::<Value>(&payload.bytes) else {
        return false;
    };
    validate(
        &request["common_portability"],
        &response,
        surface.expected_state_generation,
        reply.state_generation,
        reply.terminal.terminal_code(),
        reply.terminal.committed_effect().state(),
    )
    .is_some()
}

fn validate(
    request: &Value,
    response: &Value,
    before: u64,
    after: u64,
    terminal: TerminalCode,
    effect: crate::CommittedEffectState,
) -> Option<()> {
    let mut response_fields = vec![
        "common_portability",
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
        "replayed",
        "warnings",
        "items",
    ];
    if response.get("page_delivery_capsule").is_some() {
        response_fields.push("page_delivery_capsule");
    }
    let no_change = match response.get("no_change") {
        None => false,
        Some(Value::Bool(true)) => {
            response_fields.push("no_change");
            true
        }
        Some(_) => return None,
    };
    fields(response, &response_fields)?;
    if request["action"] != "replay" || response["common_portability"] != "replay" {
        return None;
    }
    let requested = request["items"].as_array()?;
    let rows = response["items"].as_array()?;
    if requested.is_empty()
        || requested.len() > 4096
        || rows.len() != requested.len()
        || request["first_source_sequence"].as_u64() == Some(0)
        || request["last_source_sequence"].as_u64() < request["first_source_sequence"].as_u64()
        || request["last_source_sequence"].as_u64().and_then(|last| {
            request["first_source_sequence"]
                .as_u64()
                .and_then(|first| last.checked_sub(first)?.checked_add(1))
        }) != Some(requested.len() as u64)
        || !response["warnings"].as_array()?.is_empty()
    {
        return None;
    }
    let replayed = response["replayed"].as_bool()?;
    match (
        request.get("page_delivery_capsule"),
        response.get("page_delivery_capsule"),
    ) {
        (None, None) => {}
        (Some(request_capsule), Some(response_capsule)) => {
            let requested = super::lifecycle::decode_receipt_capsule(request_capsule)?;
            let retained = super::lifecycle::decode_receipt_capsule(response_capsule)?;
            for delivery in [&requested, &retained] {
                if let Some(binding) = delivery.get("caller_binding") {
                    fields(
                        delivery,
                        &["operation_id", "idempotency_key", "caller_binding"],
                    )?;
                    fields(binding, &["version", "exact_scope"])?;
                    if binding["version"] != 1 {
                        return None;
                    }
                    scope(&binding["exact_scope"])?;
                } else {
                    fields(delivery, &["operation_id", "idempotency_key"])?;
                }
            }
            // A retry may carry a new public operation identity, but its
            // retained page receipt must still belong to the same exact caller.
            if requested.get("caller_binding") != retained.get("caller_binding") {
                return None;
            }
            string(&requested["operation_id"])?;
            string(&retained["operation_id"])?;
            let requested_key = string(&requested["idempotency_key"])?;
            let retained_key = string(&retained["idempotency_key"])?;
            if requested_key != retained_key || (!replayed && request_capsule != response_capsule) {
                return None;
            }
        }
        _ => return None,
    }
    let partial = response["partial"].as_bool()?;
    let stored_before = response["state_generation_before"].as_u64()?;
    let stored_after = response["state_generation_after"].as_u64()?;
    if stored_after < stored_before
        || (!replayed && (stored_before != before || stored_after != after))
        || (replayed && (stored_after > after || effect != crate::CommittedEffectState::Duplicate))
    {
        return None;
    }
    for field in ["first_source_sequence", "last_source_sequence"] {
        if request[field] != response[field] {
            return None;
        }
    }
    let acknowledged = response["acknowledged_sequence"].as_u64()?;
    let previous = request["expected_previous_acknowledged_sequence"].as_u64()?;
    let last = request["last_source_sequence"].as_u64()?;
    if acknowledged < previous || acknowledged > previous.max(last) {
        return None;
    }
    let mut counts = [0_u64; 5];
    let mut seen = BTreeSet::new();
    let mut seen_receipts = BTreeSet::new();
    let mut seen_delivery_keys = BTreeSet::new();
    for (input, row) in requested.iter().zip(rows) {
        fields(
            row,
            &[
                "source_sequence",
                "receipt_digest",
                "state",
                "reason",
                "record_id",
                "state_generation",
            ],
        )?;
        let sequence = row["source_sequence"].as_u64()?;
        let receipt = row["receipt_digest"].as_str()?;
        let delivery_key = input["delivery_key"].as_str()?;
        if !seen.insert(sequence)
            || sequence == 0
            || input["source_sequence"] != sequence
            || input["receipt_digest"] != receipt
            || !crate::NcmProviderAdapter::valid_sha256(receipt)
            || !crate::NcmProviderAdapter::valid_sha256(delivery_key)
            || !seen_receipts.insert(receipt.to_owned())
            || !seen_delivery_keys.insert(delivery_key.to_owned())
        {
            return None;
        }
        let index = match row["state"].as_str()? {
            "applied" => 0,
            "delivery_duplicate" => 1,
            "source_already_applied" => 2,
            "rejected" => 3,
            "effect_unknown" => 4,
            _ => return None,
        };
        counts[index] += 1;
        let generation = row["state_generation"].as_u64()?;
        if generation > stored_after || (index == 0 && generation <= stored_before) {
            return None;
        }
        if !row["record_id"].is_null() && row["record_id"].as_u64()? == 0 {
            return None;
        }
        if let Some(reason) = row["reason"].as_str() {
            if reason.is_empty()
                || reason.len() > 64
                || !reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return None;
            }
        } else if !row["reason"].is_null() {
            return None;
        }
        if index == 1 && input["delivery_key"].as_str().is_none_or(str::is_empty) {
            return None;
        }
        if index == 4 && row["reason"].is_null() {
            return None;
        }
    }
    for (field, count) in [
        "applied_observations",
        "duplicate_observations",
        "sources_already_applied",
        "rejected_observations",
        "effect_unknown_observations",
    ]
    .iter()
    .zip(counts)
    {
        if response[*field].as_u64()? != count {
            return None;
        }
    }
    if no_change && effect != crate::CommittedEffectState::None {
        return None;
    }
    match effect {
        crate::CommittedEffectState::None => {
            if !no_change
                || response.get("page_delivery_capsule").is_none()
                || partial
                || replayed
                || counts[0] != 0
                || counts[1] != 0
                || counts[4] != 0
                || acknowledged != previous
                || before != after
                || stored_before != stored_after
                || terminal != TerminalCode::Success
            {
                return None;
            }
        }
        crate::CommittedEffectState::Partial => {
            if !partial
                || counts[4] > 0
                || acknowledged <= previous
                || stored_after <= stored_before
                || (acknowledged < last && counts[3] == 0)
                || terminal != TerminalCode::PartialEffect
            {
                return None;
            }
        }
        crate::CommittedEffectState::Unknown => {
            if !partial
                || !matches!(
                    terminal,
                    TerminalCode::EffectUnknown
                        | TerminalCode::Cancelled
                        | TerminalCode::DeadlineExceeded
                )
                || (counts[4] == 0 && stored_after == stored_before)
            {
                return None;
            }
        }
        crate::CommittedEffectState::Committed | crate::CommittedEffectState::Duplicate => {
            if partial || counts[4] != 0 || terminal != TerminalCode::Success {
                return None;
            }
        }
    }
    Some(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture() -> (Value, Value) {
        let receipt = "a".repeat(64);
        let second_receipt = "b".repeat(64);
        let first_delivery = "1".repeat(64);
        let second_delivery = "2".repeat(64);
        (
            json!({"action":"replay", "first_source_sequence":1, "last_source_sequence":2, "expected_previous_acknowledged_sequence":0,
            "items":[{"source_sequence":1,"receipt_digest":receipt,"delivery_key":first_delivery},{"source_sequence":2,"receipt_digest":second_receipt,"delivery_key":second_delivery}]}),
            json!({"common_portability":"replay", "first_source_sequence":1, "last_source_sequence":2, "acknowledged_sequence":1,
            "state_generation_before":0,"state_generation_after":1,"applied_observations":1,"duplicate_observations":0,"sources_already_applied":0,
            "rejected_observations":0,"effect_unknown_observations":1,"partial":true,"replayed":false,"warnings":[],
            "items":[{"source_sequence":1,"receipt_digest":receipt,"state":"applied","reason":null,"record_id":1,"state_generation":1},
            {"source_sequence":2,"receipt_digest":second_receipt,"state":"effect_unknown","reason":"commit_unknown","record_id":null,"state_generation":1}]}),
        )
    }

    fn receipt_capsule(identity: Value) -> Value {
        let bytes = serde_json::to_vec(&identity).unwrap();
        json!({"version":1,"sha256":hex_digest(&Sha256::digest(&bytes)),"bytes":bytes})
    }

    fn completed_page() -> (Value, Value) {
        let (mut request, mut response) = fixture();
        let capsule = receipt_capsule(json!({
            "operation_id":"first-page-operation", "idempotency_key":"page-key"
        }));
        request["page_delivery_capsule"] = capsule.clone();
        response["page_delivery_capsule"] = capsule;
        response["acknowledged_sequence"] = json!(2);
        response["state_generation_after"] = json!(3);
        response["applied_observations"] = json!(2);
        response["effect_unknown_observations"] = json!(0);
        response["partial"] = json!(false);
        response["items"][1]["state"] = json!("applied");
        response["items"][1]["reason"] = Value::Null;
        response["items"][1]["record_id"] = json!(2);
        response["items"][1]["state_generation"] = json!(2);
        (request, response)
    }

    #[test]
    fn checkout_page_receipts_require_the_same_exact_caller_on_success_and_retry() {
        let (mut request, mut response) = completed_page();
        let binding = json!({"version":1,"exact_scope":{
            "profile_id":"profile", "project_id":"project", "repository_identity":"repository",
            "worktree_identity":"worktree", "branch_identity":"master", "agent_session_id":"session",
            "resolved_scope_digest":format!("sha256:{}", "ab".repeat(32))}});
        let mut delivery = json!({"operation_id":"first-page-operation", "idempotency_key":"page-key", "caller_binding":binding});
        request["page_delivery_capsule"] = receipt_capsule(delivery.clone());
        response["page_delivery_capsule"] = request["page_delivery_capsule"].clone();
        assert!(
            validate(
                &request,
                &response,
                0,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed
            )
            .is_some()
        );
        response["replayed"] = json!(true);
        delivery["operation_id"] = json!("retry-page-operation");
        request["page_delivery_capsule"] = receipt_capsule(delivery.clone());
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Duplicate
            )
            .is_some()
        );
        for field in [
            "profile_id",
            "project_id",
            "repository_identity",
            "worktree_identity",
            "branch_identity",
            "agent_session_id",
            "resolved_scope_digest",
        ] {
            let mut forged = delivery.clone();
            forged["caller_binding"]["exact_scope"][field] = if field == "resolved_scope_digest" {
                json!(format!("sha256:{}", "cd".repeat(32)))
            } else {
                json!("other")
            };
            let mut rejected = response.clone();
            rejected["page_delivery_capsule"] = receipt_capsule(forged);
            assert!(
                validate(
                    &request,
                    &rejected,
                    3,
                    3,
                    TerminalCode::Success,
                    crate::CommittedEffectState::Duplicate
                )
                .is_none(),
                "{field}"
            );
        }
        for malformed in [
            "unknown_field",
            "missing_scope",
            "unsupported_version",
            "missing_binding",
        ] {
            let mut forged = delivery.clone();
            match malformed {
                "unknown_field" => forged["caller_binding"]["extra"] = json!(true),
                "missing_scope" => {
                    forged["caller_binding"]
                        .as_object_mut()
                        .unwrap()
                        .remove("exact_scope");
                }
                "unsupported_version" => forged["caller_binding"]["version"] = json!(2),
                _ => {
                    forged.as_object_mut().unwrap().remove("caller_binding");
                }
            }
            let mut rejected = response.clone();
            rejected["page_delivery_capsule"] = receipt_capsule(forged);
            assert!(
                validate(
                    &request,
                    &rejected,
                    3,
                    3,
                    TerminalCode::Success,
                    crate::CommittedEffectState::Duplicate
                )
                .is_none(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn public_no_change_replay_requires_unchanged_generation_and_acknowledgement() {
        let (mut request, mut response) = completed_page();
        request["expected_previous_acknowledged_sequence"] = json!(2);
        response["state_generation_before"] = json!(3);
        response["applied_observations"] = json!(0);
        response["sources_already_applied"] = json!(2);
        response["no_change"] = json!(true);
        for row in response["items"].as_array_mut().unwrap() {
            row["state"] = json!("source_already_applied");
        }
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::None
            )
            .is_some()
        );
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed
            )
            .is_none()
        );
        for changed in [
            "missing_marker",
            "false_marker",
            "generation",
            "acknowledgement",
            "partial",
            "replayed",
            "applied",
            "duplicate",
            "legacy",
        ] {
            let mut request = request.clone();
            let mut response = response.clone();
            match changed {
                "missing_marker" => {
                    response.as_object_mut().unwrap().remove("no_change");
                }
                "false_marker" => response["no_change"] = json!(false),
                "generation" => response["state_generation_after"] = json!(4),
                "acknowledgement" => request["expected_previous_acknowledged_sequence"] = json!(1),
                "partial" => response["partial"] = json!(true),
                "replayed" => response["replayed"] = json!(true),
                "applied" => {
                    response["sources_already_applied"] = json!(1);
                    response["applied_observations"] = json!(1);
                    response["items"][0]["state"] = json!("applied");
                }
                "duplicate" => {
                    response["sources_already_applied"] = json!(1);
                    response["duplicate_observations"] = json!(1);
                    response["items"][0]["state"] = json!("delivery_duplicate");
                }
                _ => {
                    request
                        .as_object_mut()
                        .unwrap()
                        .remove("page_delivery_capsule");
                    response
                        .as_object_mut()
                        .unwrap()
                        .remove("page_delivery_capsule");
                }
            }
            assert!(
                validate(
                    &request,
                    &response,
                    3,
                    3,
                    TerminalCode::Success,
                    crate::CommittedEffectState::None
                )
                .is_none(),
                "accepted {changed}"
            );
        }
    }

    #[test]
    fn replay_page_receipt_binds_fresh_identity_and_retains_first_duplicate_identity() {
        let (mut request, mut response) = completed_page();
        assert!(
            validate(
                &request,
                &response,
                0,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed,
            )
            .is_some()
        );
        request["page_delivery_capsule"] = receipt_capsule(json!({
            "operation_id":"retry-page-operation", "idempotency_key":"page-key"
        }));
        assert!(
            validate(
                &request,
                &response,
                0,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed,
            )
            .is_none()
        );
        response["replayed"] = json!(true);
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Duplicate,
            )
            .is_some()
        );
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed,
            )
            .is_none()
        );
        request["page_delivery_capsule"] = receipt_capsule(json!({
            "operation_id":"retry-page-operation", "idempotency_key":"other-page-key"
        }));
        assert!(
            validate(
                &request,
                &response,
                3,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Duplicate,
            )
            .is_none()
        );
    }

    #[test]
    fn replay_page_receipt_rejects_missing_malformed_and_extra_identity_fields() {
        let (request, response) = completed_page();
        for side in ["request", "response", "both"] {
            for changed in [
                "missing",
                "null",
                "digest",
                "version",
                "byte",
                "oversized",
                "outer_field",
                "inner_field",
                "empty_operation",
                "empty_key",
            ] {
                if side == "both" && changed == "missing" {
                    continue;
                }
                let mut request = request.clone();
                let mut response = response.clone();
                let value = if side != "response" {
                    &mut request
                } else {
                    &mut response
                };
                match changed {
                    "missing" => {
                        value
                            .as_object_mut()
                            .unwrap()
                            .remove("page_delivery_capsule");
                    }
                    "null" => value["page_delivery_capsule"] = Value::Null,
                    "digest" => value["page_delivery_capsule"]["sha256"] = json!("f".repeat(64)),
                    "version" => value["page_delivery_capsule"]["version"] = json!(2),
                    "byte" => value["page_delivery_capsule"]["bytes"][0] = json!(256),
                    "oversized" => {
                        value["page_delivery_capsule"]["bytes"] = json!(vec![0_u8; 131_073])
                    }
                    "outer_field" => value["page_delivery_capsule"]["extra"] = json!(true),
                    "inner_field" => {
                        value["page_delivery_capsule"] = receipt_capsule(json!({
                            "operation_id":"first-page-operation", "idempotency_key":"page-key", "extra":true
                        }))
                    }
                    "empty_operation" => {
                        value["page_delivery_capsule"] = receipt_capsule(json!({
                            "operation_id":"", "idempotency_key":"page-key"
                        }))
                    }
                    _ => {
                        value["page_delivery_capsule"] = receipt_capsule(json!({
                            "operation_id":"first-page-operation", "idempotency_key":""
                        }))
                    }
                }
                if side == "both" {
                    response["page_delivery_capsule"] = request["page_delivery_capsule"].clone();
                }
                assert!(
                    validate(
                        &request,
                        &response,
                        0,
                        3,
                        TerminalCode::Success,
                        crate::CommittedEffectState::Committed,
                    )
                    .is_none(),
                    "accepted {changed} capsule on {side}"
                );
            }
        }
        let mut legacy_request = request;
        let mut legacy_response = response;
        legacy_request
            .as_object_mut()
            .unwrap()
            .remove("page_delivery_capsule");
        legacy_response
            .as_object_mut()
            .unwrap()
            .remove("page_delivery_capsule");
        assert!(
            validate(
                &legacy_request,
                &legacy_response,
                0,
                3,
                TerminalCode::Success,
                crate::CommittedEffectState::Committed,
            )
            .is_some()
        );
    }

    #[test]
    fn interrupted_replay_preserves_exact_known_and_unknown_partition() {
        let (request, response) = fixture();
        assert!(
            validate(
                &request,
                &response,
                0,
                1,
                TerminalCode::EffectUnknown,
                crate::CommittedEffectState::Unknown
            )
            .is_some()
        );
    }

    #[test]
    fn replay_partial_rejects_malformed_sequence_digest_ref_and_acknowledgement() {
        for malformed in [
            "missing_sequence",
            "zero_sequence",
            "invalid_digest",
            "duplicate_digest",
            "duplicate_ref",
            "ack_too_high",
            "ack_before_previous",
        ] {
            let (mut request, mut response) = fixture();
            match malformed {
                "missing_sequence" => {
                    response["items"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("source_sequence");
                }
                "zero_sequence" => {
                    request["items"][0]["source_sequence"] = json!(0);
                    response["items"][0]["source_sequence"] = json!(0);
                }
                "invalid_digest" => {
                    request["items"][0]["receipt_digest"] = json!("invalid");
                    response["items"][0]["receipt_digest"] = json!("invalid");
                }
                "duplicate_digest" => {
                    let first = request["items"][0]["receipt_digest"].clone();
                    request["items"][1]["receipt_digest"] = first.clone();
                    response["items"][1]["receipt_digest"] = first;
                }
                "duplicate_ref" => {
                    let first = request["items"][0]["delivery_key"].clone();
                    request["items"][1]["delivery_key"] = first;
                }
                "ack_too_high" => response["acknowledged_sequence"] = json!(3),
                "ack_before_previous" => {
                    request["expected_previous_acknowledged_sequence"] = json!(2);
                }
                _ => unreachable!(),
            }
            assert!(
                validate(
                    &request,
                    &response,
                    0,
                    1,
                    TerminalCode::EffectUnknown,
                    crate::CommittedEffectState::Unknown,
                )
                .is_none(),
                "accepted malformed replay metadata: {malformed}"
            );
        }
    }

    #[test]
    fn malformed_or_foreign_error_accounting_is_rejected() {
        let (request, response) = fixture();
        for changed in ["counter", "foreign", "hidden_unknown", "item_source"] {
            let mut response = response.clone();
            match changed {
                "counter" => response["applied_observations"] = json!(2),
                "foreign" => response["common_portability"] = json!("inspection"),
                "hidden_unknown" => {
                    response["effect_unknown_observations"] = json!(0);
                    response["rejected_observations"] = json!(1);
                }
                _ => response["items"][1]["source_sequence"] = json!(9),
            }
            assert!(
                validate(
                    &request,
                    &response,
                    0,
                    1,
                    TerminalCode::EffectUnknown,
                    crate::CommittedEffectState::Unknown
                )
                .is_none()
            );
        }
    }
}
