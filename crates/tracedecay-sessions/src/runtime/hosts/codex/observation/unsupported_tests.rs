use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::admission::test_support::MemoryHostAdmission;
use crate::runtime::observation::jsonl_observation_admission::install_test_shared_jsonl_preparation_authority;

#[tokio::test]
async fn unsupported_codex_frames_advance_without_capture_in_both_scopes() {
    install_test_shared_jsonl_preparation_authority();
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project_id = ProjectId::new("project.unsupported-codex").unwrap();
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(
        &project,
        project_id.as_str(),
    )
    .unwrap();
    let path = tmp.path().join("rollout.jsonl");
    let lines = [
        json!({"type":"session_meta", "payload":{"id":"unsupported-session", "cwd":project}}),
        json!({"type":"event_msg", "payload":{"type":"future_event", "data":"ignored"}}),
        json!({"type":"response_item", "payload":{"type":"future_item"}}),
        json!({"type":"turn_context", "payload":{"cwd":project, "model":"gpt-5"}}),
        json!({"type":"event_msg", "payload":{"type":"item_completed", "item":{
            "type":"UserMessage", "id":"supported-item", "content":[{"type":"text", "text":"Keep me"}]
        }}}),
    ];
    let text = lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&path, &text).unwrap();
    for profile in [false, true] {
        let admission = MemoryHostAdmission::default();
        let admit = || async {
            if profile {
                try_admit_codex_jsonl_observations_for_profile_with_admission(
                    &path,
                    None,
                    &[],
                    &admission,
                    None,
                )
                .await
            } else {
                try_admit_codex_jsonl_observations_for_project_with_admission(
                    &path,
                    &project,
                    project_id.clone(),
                    &admission,
                    None,
                )
                .await
            }
        };
        let first = admit().await.unwrap();
        assert_eq!(
            first.frames_persisted, 2,
            "only header and supported message may persist (profile={profile})"
        );
        assert_eq!(admission.observations().len(), 2);
        let advances = admission.non_durable_advances();
        assert!(
            !advances.is_empty(),
            "unsupported frames need receiptless coverage"
        );
        assert!(advances.iter().all(|advance| {
            advance.reason() == ObservationCoverageReason::UnsupportedFact
                && advance.sanitization_receipt().is_none()
        }));
        let scope = if profile {
            ObservationScopeV1::Profile
        } else {
            ObservationScopeV1::Project {
                project_id: project_id.clone(),
            }
        };
        let cursor = admission
            .get_source_cursor(
                &codex_observation_source_v2("unsupported-session").unwrap(),
                &scope,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cursor.position(), text.len() as u64);
        assert_eq!(admit().await.unwrap().frames_persisted, 0);
        assert_eq!(admission.observations().len(), 2);
    }
}

#[tokio::test]
async fn unsupported_turn_context_preserves_scope_model_and_resume() {
    use std::io::Write as _;
    install_test_shared_jsonl_preparation_authority();
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    let nested = project.join("nested");
    let other = tmp.path().join("other");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let project_id = ProjectId::new("project.context-resume").unwrap();
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(
        &project,
        project_id.as_str(),
    )
    .unwrap();
    tracedecay_runtime_core::storage::pin_fixture_repository_identity(&other, "project.other")
        .unwrap();
    let path = tmp.path().join("context-rollout.jsonl");
    let append = |lines: &[serde_json::Value]| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    };
    append(&[
        json!({"type":"session_meta", "payload":{"id":"context-session", "cwd":project}}),
        json!({"type":"turn_context", "payload":{"cwd":nested, "model":"model-before"}}),
    ]);
    let admission = MemoryHostAdmission::default();
    let admit = || async {
        try_admit_codex_jsonl_observations_for_project_with_admission(
            &path,
            &project,
            project_id.clone(),
            &admission,
            None,
        )
        .await
        .unwrap()
    };
    assert_eq!(
        admit().await.frames_persisted,
        1,
        "the final context is covered but not captured"
    );
    append(&[
        json!({"type":"response_item", "payload":{"type":"message", "id":"resumed-message", "role":"assistant", "content":[{"type":"output_text", "text":"Resumed in nested cwd"}]}}),
    ]);
    let resumed = admit().await;
    assert!(resumed.resumed);
    assert_eq!(resumed.frames_persisted, 1);
    let observations = admission.observations();
    let payload = observations.last().unwrap().observation().payload();
    let facts = payload["facts"].as_array().unwrap();
    assert!(
        facts
            .iter()
            .any(|fact| fact["kind"] == "message" && fact["model"] == "model-before")
    );
    assert!(facts.iter().any(|fact| fact["kind"] == "session"
        && fact["location_path"] == nested.to_string_lossy().as_ref()));
    append(&[
        json!({"type":"turn_context", "payload":{"cwd":other, "model":"model-outside"}}),
        json!({"type":"response_item", "payload":{"type":"message", "id":"outside-message", "role":"assistant", "content":[{"type":"output_text", "text":"Not this project"}]}}),
        json!({"type":"turn_context", "payload":{"cwd":nested, "model":"model-after"}}),
    ]);
    assert_eq!(admit().await.frames_persisted, 0);
    append(&[
        json!({"type":"response_item", "payload":{"type":"message", "id":"returned-message", "role":"assistant", "content":[{"type":"output_text", "text":"Returned to project"}]}}),
    ]);
    assert_eq!(admit().await.frames_persisted, 1);
    let observations = admission.observations();
    assert_eq!(observations.len(), 3);
    let payload = observations.last().unwrap().observation().payload();
    assert!(
        payload["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| fact["kind"] == "message" && fact["model"] == "model-after")
    );
    assert!(
        observations
            .iter()
            .all(|stored| stored.observation().payload()["native_record_kind"] != "turn_context")
    );
    assert_eq!(admit().await.frames_persisted, 0);
}
