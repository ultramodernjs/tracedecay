#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Mutex;

use serde_json::json;

use super::*;
use crate::admission::test_support::MemoryHostAdmission;
use crate::runtime::hosts::{claude::ClaudeSource, claude_observation};

#[derive(Default)]
struct Registry(Mutex<Option<Vec<PathBuf>>>);

#[tokio::test]
async fn unavailable_or_changed_registry_preserves_profile_cursor_and_allows_reads() {
    let admission = MemoryHostAdmission::default();
    let registry = Registry(Mutex::new(Some(vec![
        PathBuf::from("/project-b"),
        PathBuf::from("/project-a"),
    ])));
    let guarded = ProfileOwnershipAdmission::new(
        &admission,
        &registry,
        &[
            PathBuf::from("/project-a"),
            PathBuf::from("/project-b"),
            PathBuf::from("/project-a"),
        ],
    );
    let initial = ParseOffset {
        byte_offset: 23,
        mtime: 1,
        file_id: 1,
    };
    guarded
        .advance_parse_offset(&ObservationScopeV1::Profile, "ownership-cursor", initial)
        .await
        .unwrap();
    for (roots, reason) in [
        (None, "project_registry_unavailable"),
        (Some(Vec::new()), "project_registry_changed"),
    ] {
        *registry.0.lock().unwrap() = roots;
        let error = guarded
            .advance_parse_offset(
                &ObservationScopeV1::Profile,
                "ownership-cursor",
                ParseOffset {
                    byte_offset: 50,
                    ..initial
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.reason_code, Some(reason));
        assert!(error.retryable);
        assert_eq!(
            guarded
                .get_parse_offset(&ObservationScopeV1::Profile, "ownership-cursor")
                .await
                .unwrap(),
            Some(initial)
        );
    }
}

#[tokio::test]
async fn stale_ownership_defers_non_durable_coverage_rewrites_and_checkpoints() {
    let admission = MemoryHostAdmission::default();
    let registry = Registry(Mutex::new(Some(Vec::new())));
    let guarded = ProfileOwnershipAdmission::new(&admission, &registry, &[]);
    let source = ObservationSourceIdentityV1::for_provider(
        tracedecay_domain::ProviderId::new("claude").unwrap(),
        tracedecay_domain::SessionId::new("ownership-coverage").unwrap(),
    )
    .unwrap();
    let scope = ObservationScopeV1::Profile;
    let previous = ObservationSourceGenerationV1::new(1).unwrap();
    let generation = ObservationSourceGenerationV1::new(2).unwrap();
    let advance = ObservationCursorAdvance::new(
        source.clone(),
        scope.clone(),
        previous,
        None,
        tracedecay_domain::ObservationSourceRangeV1::new(0, 100).unwrap(),
        tracedecay_store::ObservationCoverageReason::OutOfScope,
    )
    .unwrap();
    assert!(
        guarded
            .compare_and_swap_session_backfill_state(&scope, "ownership", None, "pending")
            .await
            .unwrap()
    );
    for (roots, reason) in [
        (None, "project_registry_unavailable"),
        (
            Some(vec![PathBuf::from("/project")]),
            "project_registry_changed",
        ),
    ] {
        *registry.0.lock().unwrap() = roots;
        let errors = [
            guarded.capture_observations(Vec::new()).await.unwrap_err(),
            guarded
                .advance_non_durable_source_cursor(
                    advance.clone(),
                    ObservationCancellation::default(),
                )
                .await
                .unwrap_err(),
            guarded
                .begin_source_rewrite(&source, &scope, previous, generation, 0)
                .await
                .unwrap_err(),
            guarded
                .complete_source_rewrite(&source, &scope, generation)
                .await
                .unwrap_err(),
            guarded
                .compare_and_swap_session_backfill_state(
                    &scope,
                    "ownership",
                    Some("pending"),
                    "done",
                )
                .await
                .unwrap_err(),
            guarded
                .compare_and_delete_session_backfill_state(&scope, "ownership", "pending")
                .await
                .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error.reason_code, Some(reason));
            assert!(error.retryable);
        }
        assert!(
            guarded
                .get_source_cursor(&source, &scope)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            guarded
                .read_session_backfill_state(&scope, "ownership")
                .await
                .unwrap()
                .as_deref(),
            Some("pending")
        );
    }
    assert!(admission.non_durable_advances().is_empty());
    assert_eq!(admission.capture_call_counts(), (0, 0));
    *registry.0.lock().unwrap() = Some(Vec::new());
    guarded
        .advance_non_durable_source_cursor(advance, ObservationCancellation::default())
        .await
        .unwrap();
    assert_eq!(
        guarded
            .get_source_cursor(&source, &scope)
            .await
            .unwrap()
            .unwrap()
            .position(),
        100
    );
    guarded
        .begin_source_rewrite(&source, &scope, previous, generation, 100)
        .await
        .unwrap();
    guarded
        .complete_source_rewrite(&source, &scope, generation)
        .await
        .unwrap();
    assert!(
        guarded
            .compare_and_swap_session_backfill_state(&scope, "ownership", Some("pending"), "done")
            .await
            .unwrap()
    );
    assert!(
        guarded
            .compare_and_delete_session_backfill_state(&scope, "ownership", "done")
            .await
            .unwrap()
    );
}

impl RegisteredRootsReader for Registry {
    fn registered_roots(&self) -> RegisteredRootsRead<'_> {
        Box::pin(async { self.0.lock().unwrap().clone() })
    }
}

#[tokio::test]
async fn newly_registered_project_defers_stale_profile_capture_without_cursor_advance() {
    let _ = tracedecay_runtime_core::native_runtime::install(
        tracedecay_runtime_core::native_runtime::default_builder(),
    );
    crate::runtime::jsonl_observation_admission::install_test_shared_jsonl_preparation_authority();
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let directory = home.path().join(".claude/projects/ownership");
    std::fs::create_dir_all(&directory).unwrap();
    let transcript = directory.join("ownership-transition.jsonl");
    std::fs::write(&transcript, format!("{}\n", json!({
        "type": "user", "sessionId": "ownership-transition", "uuid": "message-ownership-transition",
        "timestamp": "2026-10-20T00:00:00Z", "cwd": project,
        "message": {"role": "user", "content": "project-owned evidence"}
    }))).unwrap();
    crate::runtime::source::spin_until_jsonl_change_settled(&transcript);
    let admission = MemoryHostAdmission::default();
    let registry = Registry(Mutex::new(Some(Vec::new())));
    let guarded = ProfileOwnershipAdmission::new(&admission, &registry, &[]);
    // A source and admission were prepared before the project was registered.
    let source = ClaudeSource::with_home(home.path())
        .for_user_scope(Some("ownership-transition".to_owned()), Vec::new());
    *registry.0.lock().unwrap() = Some(vec![project.clone()]);
    let result = claude_observation::ingest_source_with_observations_with_admission(
        &source,
        &home.path().join("profile"),
        ObservationScopeV1::Profile,
        &guarded,
        None,
        ObservationCancellation::default(),
    )
    .await;
    assert!(
        result.is_err(),
        "stale profile ownership must defer, not capture: {result:?}"
    );
    assert!(admission.observations().is_empty());
    let identity = crate::runtime::hosts::claude::identify_claude_source(
        &home.path().join(".claude/projects"),
        &transcript,
    )
    .unwrap();
    let observation_source = ObservationSourceIdentityV1::for_source(
        tracedecay_domain::SessionId::new(identity.session_id).unwrap(),
        tracedecay_domain::SessionId::new(identity.source_id).unwrap(),
    )
    .unwrap();
    assert!(
        admission
            .get_source_cursor(&observation_source, &ObservationScopeV1::Profile)
            .await
            .unwrap()
            .is_none()
    );

    // A fresh pass excludes those frames, rather than leaving them retrying.
    let fresh =
        ProfileOwnershipAdmission::new(&admission, &registry, std::slice::from_ref(&project));
    let source = ClaudeSource::with_home(home.path())
        .for_user_scope(Some("ownership-transition".to_owned()), vec![project]);
    claude_observation::ingest_source_with_observations_with_admission(
        &source,
        &home.path().join("profile"),
        ObservationScopeV1::Profile,
        &fresh,
        None,
        ObservationCancellation::default(),
    )
    .await
    .unwrap();
    assert!(admission.observations().is_empty());
}
