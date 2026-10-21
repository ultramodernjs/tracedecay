use serde_json::json;
use tempfile::TempDir;
use tracedecay_runtime_core::git_discovery::{
    GitDiscoveryUnknown, GitRepositoryIdentity, GitRepositoryIdentityOutcome,
};

use super::*;
use crate::admission::test_support::MemoryHostAdmission;
use crate::runtime::observation::jsonl_observation_admission::install_test_shared_jsonl_preparation_authority;
use crate::runtime::shared::ProjectRootMatcher;

fn unknown_identity(_: &Path) -> GitRepositoryIdentityOutcome {
    GitRepositoryIdentityOutcome::Unknown(GitDiscoveryUnknown::DeadlineExceeded)
}

fn resolved_identity(path: &Path) -> GitRepositoryIdentityOutcome {
    let root = path
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "repo"))
        .unwrap();
    GitRepositoryIdentityOutcome::Resolved(GitRepositoryIdentity {
        worktree_root: root.to_path_buf(),
        git_dir: root.join(".git"),
        common_dir: root.join(".git"),
    })
}

#[tokio::test]
async fn codex_profile_unknown_membership_defers_without_cursor_advance() {
    install_test_shared_jsonl_preparation_authority();
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("repo");
    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    for context_change in [false, true] {
        let path = tmp.path().join(format!("unknown-{context_change}.jsonl"));
        let lines = [
            json!({"type":"session_meta", "payload":{"id":"scope-session", "cwd":if context_change { &root } else { &nested }}}),
            json!({"type":"turn_context", "payload":{"cwd":nested}}),
            json!({"type":"event_msg", "payload":{"type":"item_completed", "item":{
                "type":"UserMessage", "id":"scope-item", "content":[{"type":"text", "text":"Project only"}]
            }}}),
        ];
        let text = lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, &text).unwrap();
        let parsed_meta = session_meta_with_provenance(&path)
            .unwrap()
            .ready()
            .unwrap();
        let roots = [root.clone()];
        let scope = CodexObservationAdmission::Profile {
            session_id: None,
            registered_roots: &roots,
        };
        let admission = MemoryHostAdmission::default();
        let cancellation = ObservationCancellation::default();
        let context = CodexAdmissionContext {
            path: &path,
            scope: &scope,
            admission: &admission,
            meta: &parsed_meta.meta,
            native_thread_id: parsed_meta.native_thread_id.as_deref(),
            rollout: CodexRolloutFile::of(&path, &parsed_meta.meta.session_id),
            cancellation: &cancellation,
        };
        let source = codex_observation_source_v2("scope-session").unwrap();
        let pending =
            admit_codex_jsonl_page_with_matcher(context, source.clone(), None, None, || {
                TranscriptScopeMatcher::Profile(vec![Arc::new(
                    ProjectRootMatcher::new_with_identity_resolver(&root, unknown_identity),
                )])
            })
            .await;
        assert!(
            matches!(
                pending,
                Err(TranscriptIngestError::HostAdmission {
                    reason: "scope_membership_pending",
                    retryable: true,
                    status: HostAdmissionStatus::Unavailable,
                    ..
                })
            ),
            "unknown scope must defer, not admit or skip: {pending:?}"
        );
        assert!(admission.observations().is_empty());
        let cursor = admission
            .get_source_cursor(&source, &ObservationScopeV1::Profile)
            .await
            .unwrap();
        let undecidable_start = if context_change {
            lines[0].to_string().len() as u64 + 1
        } else {
            0
        };
        assert!(cursor.is_none_or(|cursor| cursor.position() <= undecidable_start));

        admit_codex_jsonl_page_with_matcher(context, source.clone(), None, None, || {
            TranscriptScopeMatcher::Profile(vec![Arc::new(
                ProjectRootMatcher::new_with_identity_resolver(&root, resolved_identity),
            )])
        })
        .await
        .unwrap();
        assert!(admission.observations().is_empty());
        assert_eq!(
            admission
                .get_source_cursor(&source, &ObservationScopeV1::Profile)
                .await
                .unwrap()
                .unwrap()
                .position(),
            text.len() as u64
        );

        let project_scope = CodexObservationAdmission::Project {
            root: &root,
            project_id: ProjectId::new("project.scope").unwrap(),
        };
        let project_admission = MemoryHostAdmission::default();
        let project_context = CodexAdmissionContext {
            scope: &project_scope,
            admission: &project_admission,
            ..context
        };
        admit_codex_jsonl_page_with_matcher(project_context, source, None, None, || {
            TranscriptScopeMatcher::Project(Arc::new(
                ProjectRootMatcher::new_with_identity_resolver(&root, resolved_identity),
            ))
        })
        .await
        .unwrap();
        assert!(project_admission.observations().iter().any(|stored| {
            stored
                .observation()
                .payload()
                .to_string()
                .contains("Project only")
        }));
    }
}
