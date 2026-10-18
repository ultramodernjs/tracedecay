//! Cross-field result validation selected by generated operation metadata.

use serde_json::Value;
use tracedecay_contracts::RequestId;
use tracedecay_contracts::retained_surfaces::{
    AutomationRunResultV1, FactStoreCurateRequestV1, ProviderControlRequestV1,
    ProviderControlResultV1, RetainedSurfaceOperation, SdkResultSemanticsV1,
};

pub(crate) fn response_matches(
    semantics: SdkResultSemanticsV1,
    operation_id: &str,
    request_id: &str,
    expected_request_id: Option<&RequestId>,
    request: &Value,
    result: &Value,
) -> bool {
    if expected_request_id.is_some_and(|expected| expected.as_str() != request_id) {
        return false;
    }
    match semantics {
        SdkResultSemanticsV1::SchemaOnly => true,
        SdkResultSemanticsV1::ProviderControlTerminal => {
            // SDK requests are the concrete operation body, without the retained
            // union tag. Only the generated caller metadata selects that tag.
            let Some(operation) = operation_id
                .strip_prefix("operation.application.")
                .and_then(RetainedSurfaceOperation::from_operation_name)
            else {
                return false;
            };
            let operation = match operation {
                RetainedSurfaceOperation::ProviderHealth => "health",
                RetainedSurfaceOperation::ProviderInspection => "inspection",
                RetainedSurfaceOperation::ProviderMaintenance => "maintenance",
                _ => return false,
            };
            let Ok(request) = serde_json::from_value::<ProviderControlRequestV1>(
                serde_json::json!({"operation": operation, "request": request}),
            ) else {
                return false;
            };
            serde_json::from_value::<ProviderControlResultV1>(result.clone())
                .is_ok_and(|result| result.validate_for(&request).is_ok())
        }
        SdkResultSemanticsV1::FactStoreCurateTerminal => {
            let Ok(request_id) = RequestId::new(request_id.to_owned()) else {
                return false;
            };
            let Ok(request) = serde_json::from_value::<FactStoreCurateRequestV1>(request.clone())
            else {
                return false;
            };
            let Ok(admission) = request.automation_request(&request_id) else {
                return false;
            };
            serde_json::from_value::<AutomationRunResultV1>(result.clone())
                .is_ok_and(|result| result.matches_admission(&admission))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tracedecay_contracts::retained_surfaces::SdkResultSemanticsV1;

    use super::response_matches;

    #[test]
    fn curate_semantics_reject_a_structural_terminal_with_foreign_run_identity() {
        let terminal = json!({
            "run_id": "request.foreign",
            "task": "memory_curator",
            "request_digest": concat!(
                "sha256:",
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            "terminal": {
                "status": "completed",
                "summary": {
                    "reviewed_count": 0,
                    "accepted_count": 0,
                    "rejected_count": 0,
                    "skipped_count": 0
                }
            },
            "committed_receipts": []
        });
        assert!(!response_matches(
            SdkResultSemanticsV1::FactStoreCurateTerminal,
            "operation.application.fact_store_curate",
            "request.sdk.curate",
            None,
            &json!({}),
            &terminal,
        ));
    }

    #[test]
    fn provider_control_semantics_bind_generated_operation_request_and_terminal_effect() {
        use crate::operations::{ProviderHealth, ProviderMaintenance, TypedOperation};
        use tracedecay_contracts::RequestId;
        use tracedecay_contracts::retained_surfaces::ProviderControlResultV1;

        let state = json!({"kind":"canonical_session","provider_id":"native","registration_revision":7,"canonical_provider_id":"claude","session_id":"session-1"});
        let request: <ProviderMaintenance as TypedOperation>::Request =
            serde_json::from_value(json!({"state":state,"task":"validate_state","maximum_items":20,"maximum_bytes":65536,"maximum_duration_millis":1000,"dry_run":false})).expect("concrete SDK request body");
        let request = serde_json::to_value(request).expect("SDK serialized request");
        assert!(request.get("operation").is_none());
        let expected_id = RequestId::new("request.sdk.provider").expect("request ID");
        let none_effect = json!({"state":"none","committed_boundary":null,"state_generation_before":null,"state_generation_after":null,"committed_item_refs":[],"uncommitted_item_refs":[],"provider_receipt_digest":null,"reconciliation_action":null,"verification_digest":null,"duplicate_of_idempotency_key":null,"duplicate_of_operation_id":null});
        let mut effect = none_effect.clone();
        effect["state"] = json!("committed");
        effect["state_generation_before"] = json!(3);
        effect["state_generation_after"] = json!(4);
        effect["provider_receipt_digest"] = json!("b".repeat(64));
        effect["verification_digest"] = json!("c".repeat(64));
        let result = json!({
            "provider_id":"native","registration_revision":7,
            "scope":{"profile_id":"profile-1","project_id":"project-1","repository_identity":"repo-1","worktree_identity":"worktree-1","branch_identity":"refs/heads/main","agent_session_id":"session-1","resolved_scope_digest":format!("sha256:{}","1".repeat(64))},
            "operation_id":"018f22c2-77cd-7000-8000-000000000001","idempotency_key":"d".repeat(64),
            "terminal":"success","diagnostic_id":null,"domain_detail":null,"effect":effect,"warnings":[],
            "result":{"operation":"maintenance","data":{
                "task":"validate_state","dry_run":false,"scanned_items":1,"changed_items":1,"removed_items":0,"partial":false,"resume_cursor":null,
                "receipt":{"state_generation_before":3,"state_generation_after":4,"provider_receipt_digest":"b".repeat(64)}
            }}
        });
        let matches = |result: &serde_json::Value| {
            response_matches(
                ProviderMaintenance::RESULT_SEMANTICS,
                ProviderMaintenance::OPERATION_ID,
                expected_id.as_str(),
                Some(&expected_id),
                &request,
                result,
            )
        };
        assert!(
            matches(&result),
            "actual typed request and committing maintenance"
        );

        let mut foreign_operation = result.clone();
        foreign_operation["result"] = json!({"operation":"health","data":null});
        foreign_operation["terminal"] = json!("provider_unavailable");
        foreign_operation["effect"] = none_effect;
        foreign_operation["idempotency_key"] = serde_json::Value::Null;
        serde_json::from_value::<ProviderControlResultV1>(foreign_operation.clone())
            .expect("typed foreign terminal")
            .validate()
            .expect("independently valid health result");
        assert!(
            !matches(&foreign_operation),
            "a valid result for another operation is refused"
        );
        assert!(
            !response_matches(
                ProviderMaintenance::RESULT_SEMANTICS,
                ProviderHealth::OPERATION_ID,
                expected_id.as_str(),
                Some(&expected_id),
                &request,
                &result,
            ),
            "the response cannot choose its own operation"
        );

        let mut foreign_task = result.clone();
        foreign_task["result"]["data"]["task"] = json!("compact");
        serde_json::from_value::<ProviderControlResultV1>(foreign_task.clone())
            .expect("typed foreign task")
            .validate()
            .expect("internally consistent foreign task result");
        assert!(
            !matches(&foreign_task),
            "the result must answer the requested maintenance task"
        );

        let mut invalid_terminal = result.clone();
        invalid_terminal["terminal"] = json!("provider_unavailable");
        assert!(
            !matches(&invalid_terminal),
            "unavailable cannot claim committed maintenance"
        );
        assert!(
            !response_matches(
                ProviderMaintenance::RESULT_SEMANTICS,
                ProviderMaintenance::OPERATION_ID,
                "request.foreign",
                Some(&expected_id),
                &request,
                &result,
            ),
            "expected request ID remains mandatory"
        );
        assert!(
            !response_matches(
                ProviderMaintenance::RESULT_SEMANTICS,
                "operation.application.fact_store_curate",
                expected_id.as_str(),
                Some(&expected_id),
                &request,
                &result,
            ),
            "non-provider metadata cannot select a provider validator"
        );
    }
}
