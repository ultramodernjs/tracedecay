//! Claude Code hook handlers.
//!
//! Claude and Codex share the common hook JSON shape.

use std::path::PathBuf;
use std::time::Instant;

use serde_json::Value;
use tracedecay_contracts::retrieval::HookRuntimeSurfaceRequestV1;

use crate::ports::hook_runtime::HookRuntimeV1;

use super::post_tool_use::is_post_tool_use_failure_event;
use super::steering::session_start_context;
use super::{
    additional_context_json, event_project_root_with_identity, read_hook_event,
    record_hook_invoked_parsed,
};
use tracedecay_domain::HostIntegrationIdV1;

pub(super) fn is_code_research_prompt(prompt: &str) -> bool {
    let lower = prompt.to_ascii_lowercase();
    let exploration_patterns = [
        "explore",
        "codebase structure",
        "codebase architecture",
        "codebase overview",
        "source files contents",
        "read every",
        "full contents",
        "entire codebase",
        "architecture and structure",
        "call graph",
        "call path",
        "call chain",
        "symbol relat",
        "symbol lookup",
        "who calls",
        "callers of",
        "callees of",
    ];
    exploration_patterns.iter().any(|pat| lower.contains(pat))
}

/// Claude Code `SessionStart` hook handler.
#[tracing::instrument(name = "hosts.hooks.claude.session_start", level = "trace", skip_all)]
pub async fn hook_claude_session_start(runtime: &HookRuntimeV1) -> i32 {
    claude_guidance_hook(runtime, "SessionStart").await
}

/// Claude Code `PostCompact` hook handler.
///
/// Claude does not currently expose machine-verifiable provenance for the
/// compacted source frontier. The daemon therefore treats this event as a
/// read-only capability probe and returns typed unavailable without publishing
/// transcript or summary state.
#[tracing::instrument(name = "hosts.hooks.claude.post_compact", level = "trace", skip_all)]
pub async fn hook_claude_post_compact(runtime: &HookRuntimeV1) -> i32 {
    let event = read_hook_event!(
        runtime,
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        "PostCompact"
    );
    let parsed = serde_json::from_str::<Value>(&event).unwrap_or(Value::Null);
    let root = event_project_root_with_identity(runtime, &parsed).await;
    let hook_telemetry = record_hook_invoked_parsed(
        runtime,
        root.as_deref(),
        HostIntegrationIdV1::Claude,
        "PostCompact",
        &event,
        &parsed,
    );
    let args = HookRuntimeSurfaceRequestV1::ClaudeCompact {
        event_json: event.clone(),
        user_scope: root.is_none(),
    };
    if let Err(error) =
        super::daemon_hook_action(runtime, root.as_deref(), args, Some(&hook_telemetry)).await
    {
        tracing::warn!(%error, "Claude PostCompact daemon call failed");
    }
    if !super::write_hook_output(
        &runtime.profile,
        root.as_deref(),
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        &event,
        &serde_json::json!({}).to_string(),
    )
    .await
    {
        return 1;
    }
    0
}

/// Claude Code `PostToolUse` / `PostToolUseFailure` hook handler.
#[tracing::instrument(name = "hosts.hooks.claude.post_tool_use", level = "trace", skip_all)]
pub async fn hook_claude_post_tool_use(runtime: &HookRuntimeV1) -> i32 {
    let event = read_hook_event!(
        runtime,
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        "PostToolUse"
    );
    let (root, response) = claude_post_tool_use_response(runtime, &event).await;
    if let Some(response) = response
        && !super::write_hook_output(
            &runtime.profile,
            root.as_deref(),
            tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
            &event,
            &response,
        )
        .await
    {
        return 1;
    }
    0
}

/// Returns the identity-resolved root alongside the response so the handler
/// does not repeat the registry-probing resolution for output delivery.
async fn claude_post_tool_use_response(
    runtime: &HookRuntimeV1,
    event: &str,
) -> (Option<PathBuf>, Option<String>) {
    let parsed = serde_json::from_str::<Value>(event).unwrap_or(Value::Null);
    let hook_event_name = if is_post_tool_use_failure_event(&parsed) {
        "PostToolUseFailure"
    } else {
        "PostToolUse"
    };
    let root = event_project_root_with_identity(runtime, &parsed).await;
    // Registry discovery is not daemon admission. Charging its cold-start
    // cost to the 25ms admission window can make every retry spool forever.
    let started = Instant::now();
    let hook_telemetry = record_hook_invoked_parsed(
        runtime,
        root.as_deref(),
        HostIntegrationIdV1::Claude,
        hook_event_name,
        event,
        &parsed,
    );
    let response = super::dispatch::dispatch_for_scope(
        runtime,
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        event,
        root.as_deref(),
        Some(&hook_telemetry),
        started,
    )
    .await
    .into_recorded_guidance(&hook_telemetry)
    .flatten()
    .map(|guidance| additional_context_json(hook_event_name, &guidance));
    (root, response)
}

/// `Stop` hook handler: submits the native turn boundary to the daemon.
#[tracing::instrument(name = "hosts.hooks.claude.stop", level = "trace", skip_all)]
pub async fn hook_stop(runtime: &HookRuntimeV1) -> i32 {
    claude_guidance_hook(runtime, "Stop").await
}

/// SessionStart and Stop share one guidance envelope. The project root is
/// resolved once and reused for both dispatch and stdout delivery.
async fn claude_guidance_hook(runtime: &HookRuntimeV1, hook_name: &'static str) -> i32 {
    let event = read_hook_event!(
        runtime,
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        hook_name
    );
    let parsed = serde_json::from_str::<Value>(&event).unwrap_or(Value::Null);
    let root = event_project_root_with_identity(runtime, &parsed).await;
    // Match the telemetry/admission boundary used by PostToolUse. In
    // particular, a slow Windows registry probe must not starve Stop retries.
    let started = Instant::now();
    let hook_telemetry = record_hook_invoked_parsed(
        runtime,
        root.as_deref(),
        HostIntegrationIdV1::Claude,
        hook_name,
        &event,
        &parsed,
    );
    let guidance = super::dispatch::dispatch_for_scope(
        runtime,
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        &event,
        root.as_deref(),
        Some(&hook_telemetry),
        started,
    )
    .await
    .into_recorded_guidance(&hook_telemetry)
    .flatten();
    let guidance = match hook_name {
        "SessionStart" => session_start_context(root.as_deref(), guidance),
        _ => guidance,
    };
    let output = guidance.map_or_else(
        || serde_json::json!({}).to_string(),
        |guidance| additional_context_json(hook_name, &guidance),
    );
    if !super::write_hook_output(
        &runtime.profile,
        root.as_deref(),
        tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
        &event,
        &output,
    )
    .await
    {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::path::Path;
    use std::pin::Pin;
    use std::time::Duration;
    use tracedecay_contracts::ResolvedScope;
    use tracedecay_domain::{ProjectId, RepositoryId, WorktreeId};
    use tracedecay_runtime_core::config::ProfileRoot;

    #[tokio::test]
    async fn slow_project_root_discovery_does_not_spend_daemon_admission_window() {
        fn slow_root<'a>(
            _: &'a ProfileRoot,
            requested: &'a Path,
        ) -> Pin<Box<dyn Future<Output = Option<PathBuf>> + Send + 'a>> {
            Box::pin(async move {
                // Longer than the 25ms admission window on every platform.
                tokio::time::sleep(Duration::from_millis(50)).await;
                Some(requested.to_path_buf())
            })
        }
        fn scope(_: &Path, project: &ProjectId) -> Result<ResolvedScope, String> {
            ResolvedScope::new(
                project.clone(),
                RepositoryId::new("repository.slow-hook-root").unwrap(),
                WorktreeId::new("worktree.slow-hook-root").unwrap(),
                None,
            )
            .map_err(|error| error.to_string())
        }
        fn daemon<'a>(
            profile: &'a ProfileRoot,
            _: Option<&'a Path>,
            tool: &'a str,
            arguments: Value,
            _: bool,
        ) -> Pin<Box<dyn Future<Output = tracedecay_domain::errors::Result<Value>> + Send + 'a>>
        {
            Box::pin(async move {
                assert_eq!(tool, "tracedecay_hook_runtime");
                assert_eq!(arguments["action"], "hook_v2_admit");
                std::fs::write(profile.data_dir().join("admission-called"), b"called").unwrap();
                Ok(serde_json::json!({
                    "action": "hook_v2_admit",
                    "status": "rejected",
                    "disposition": "catchup_required",
                }))
            })
        }

        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();
        let profile = ProfileRoot::under_home(home.path());
        let project_id = "proj_slow_hook_root";
        tracedecay_runtime_core::storage::pin_fixture_repository_identity(&project, project_id)
            .unwrap();
        let layout = tracedecay_runtime_core::storage::profile_sharded_layout(
            &project,
            profile.data_dir(),
            project_id,
        )
        .unwrap();
        let runtime = HookRuntimeV1 {
            project_root_resolver: slow_root,
            scope_resolver: scope,
            daemon_tool: daemon,
            ..crate::ports::hook_runtime::crate_test_runtime(profile.clone())
        };
        super::super::dispatch::publish_daemon_bindings(&runtime, &layout).unwrap();
        // Use the maintained native schema: a partial hand-built payload is
        // rejected before dispatch (transcript_path, prompt_id, permission_mode
        // and duration_ms are required even though their values are ignored).
        let mut event: Value = serde_json::from_str(include_str!(
            "../../../tracedecay-hooks/fixtures/host_events/claude/post_tool_use_write.json"
        ))
        .unwrap();
        event["session_id"] = serde_json::json!("slow-root-session");
        event["tool_use_id"] = serde_json::json!("slow-root-call");
        event["prompt_id"] = serde_json::json!("slow-root-call");
        event["cwd"] = serde_json::json!(project);
        event["tool_input"]["file_path"] = serde_json::json!(project.join("src/lib.rs"));
        event["tool_response"]["filePath"] = serde_json::json!(project.join("src/lib.rs"));
        let event = event.to_string();
        tracedecay_hooks::decode_native_hook_event(
            tracedecay_domain::NativeHostIdentityV1::ClaudeCode,
            event.as_bytes(),
        )
        .expect("fixture must reach native dispatch before testing its admission clock");
        let started = Instant::now();
        claude_post_tool_use_response(&runtime, &event).await;
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(
            profile.data_dir().join("admission-called").is_file(),
            "slow root discovery must still leave time for daemon admission"
        );
    }
}
