//! Cross-lane regressions for source-local scope uncertainty. Keep these
//! explicitly pending until B4 wires retryable, witness-independent deferral.

use std::path::{Path, PathBuf};

use serde_json::json;
use tempfile::TempDir;
use tracedecay_domain::{ObservationScopeV1, ProjectId};
use tracedecay_runtime_core::config::ProfileRoot;
use tracedecay_runtime_core::git_discovery::{
    GitDiscoveryUnknown, GitRepositoryIdentity, GitRepositoryIdentityOutcome,
};

use super::failure::ProviderRunOutcome;
use super::project_provider::ProjectProviderRun;
use super::quarantine::SourceSweep;
use super::user::{CodexUserIngestOutcome, try_ingest_user_codex_sessions_rotated};
use crate::admission::HostAdmission;
use crate::admission::test_support::MemoryHostAdmission;
use crate::observation::ObservationCancellation;
use crate::runtime::SessionProvider;
use crate::runtime::hosts::codex::{
    CodexDiscoveryDelivery, CodexDiscoveryFrontier, CodexDiscoveryHub, CodexSource,
    codex_observation_source_v2,
};
use crate::runtime::jsonl_observation_admission::install_test_shared_jsonl_preparation_authority;
use crate::runtime::shared::GitIdentityResolver;
use crate::runtime::source::{
    HostProviderCoverage, TranscriptDiscoveryBounds, read_host_provider_coverage,
    spin_until_jsonl_change_settled,
};
use crate::runtime::with_transcript_source_profile;

tokio::task_local! {
    // Only the current async sweep sees this override, never another test or
    // a process-global Git/cache configuration.
    pub(crate) static SCOPE_IDENTITY_RESOLVER: GitIdentityResolver;
}

fn resolved_identity(path: &Path) -> GitRepositoryIdentityOutcome {
    let root = path
        .ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == "repo"))
        .unwrap_or(path);
    GitRepositoryIdentityOutcome::Resolved(GitRepositoryIdentity {
        worktree_root: root.to_path_buf(),
        git_dir: root.join(".git"),
        common_dir: root.join(".git"),
    })
}

fn pending_identity(path: &Path) -> GitRepositoryIdentityOutcome {
    if path.file_name().is_some_and(|name| name == "pending") {
        GitRepositoryIdentityOutcome::Unknown(GitDiscoveryUnknown::DeadlineExceeded)
    } else {
        resolved_identity(path)
    }
}

struct ScopePendingFixture {
    home: TempDir,
    root: PathBuf,
    pending: PathBuf,
    peer: PathBuf,
    project_id: ProjectId,
    admission: MemoryHostAdmission,
    cancellation: ObservationCancellation,
}

impl ScopePendingFixture {
    fn new(project: bool) -> Self {
        install_test_shared_jsonl_preparation_authority();
        let home = TempDir::new().unwrap();
        let root = home.path().join("repo");
        let pending_cwd = root.join("pending");
        let peer_cwd = if project {
            root.clone()
        } else {
            home.path().join("unregistered")
        };
        std::fs::create_dir_all(&pending_cwd).unwrap();
        std::fs::create_dir_all(&peer_cwd).unwrap();
        let project_id = ProjectId::new("project.scope-pending-sweep").unwrap();
        tracedecay_runtime_core::storage::pin_fixture_repository_identity(
            &root,
            project_id.as_str(),
        )
        .unwrap();
        let write = |day: &str, session: &str, cwd: &Path| {
            let directory = home.path().join(".codex/sessions/2026/10").join(day);
            std::fs::create_dir_all(&directory).unwrap();
            let path = directory.join(format!("rollout-{session}.jsonl"));
            let text = format!(
                "{}\n{}\n",
                json!({"type":"session_meta", "payload":{"id":session, "cwd":cwd}}),
                json!({"type":"event_msg", "payload":{"type":"user_message", "message":session}}),
            );
            std::fs::write(&path, text).unwrap();
            spin_until_jsonl_change_settled(&path);
            path
        };
        let pending = write("21", "pending-scope", &pending_cwd);
        let peer = write("20", "decidable-peer", &peer_cwd);
        Self {
            home,
            root,
            pending,
            peer,
            project_id,
            admission: MemoryHostAdmission::default(),
            cancellation: ObservationCancellation::default(),
        }
    }

    async fn hub(&self) -> CodexDiscoveryHub {
        let hub = CodexDiscoveryHub::default();
        hub.register("scope-pending", Some(self.home.path()));
        let source = CodexSource::with_home(self.home.path());
        for _ in 0..32 {
            let CodexDiscoveryDelivery::Ready(pass) = hub
                .discover(
                    "scope-pending",
                    &source,
                    TranscriptDiscoveryBounds::default_walk(),
                    CodexDiscoveryFrontier::initial(),
                )
                .await
                .unwrap()
            else {
                panic!("no concurrent scanner in this fixture");
            };
            if !pass.report.paths.is_empty() {
                assert_eq!(
                    pass.report.paths,
                    vec![self.pending.clone(), self.peer.clone()]
                );
                // Keep this exact page unacknowledged for the production sweep.
                return hub;
            }
            hub.acknowledge("scope-pending");
        }
        panic!("discovery did not reach the two-rollout fixture");
    }

    async fn project_run(&self, hub: &CodexDiscoveryHub) -> ProviderRunOutcome {
        let scope = ObservationScopeV1::Project {
            project_id: self.project_id.clone(),
        };
        with_transcript_source_profile(
            ProfileRoot::under_home(self.home.path()),
            ProjectProviderRun {
                project_root: &self.root,
                project_id: &self.project_id,
                facade: &self.admission,
                scope: &scope,
                candidate: SessionProvider::Codex,
                max_new_bytes: 1 << 20,
                cancellation: &self.cancellation,
                codex_discovery: Some((hub, "scope-pending")),
            }
            .run_codex(),
        )
        .await
    }

    async fn profile_run(&self, hub: &CodexDiscoveryHub) -> CodexUserIngestOutcome {
        let mut sweep = SourceSweep::new("codex", Some((hub, "scope-pending")));
        with_transcript_source_profile(
            ProfileRoot::under_home(self.home.path()),
            try_ingest_user_codex_sessions_rotated(
                self.home.path(),
                None,
                vec![self.root.clone()],
                &self.admission,
                Some(1 << 20),
                &self.cancellation,
                CodexDiscoveryFrontier::initial(),
                Some((hub, "scope-pending")),
                &mut sweep,
            ),
        )
        .await
        .expect("scope uncertainty must not abort the profile sweep")
    }

    async fn assert_pending_has_no_coverage(&self, scope: &ObservationScopeV1) {
        let source = codex_observation_source_v2("pending-scope").unwrap();
        assert!(
            self.admission
                .get_source_cursor(&source, scope)
                .await
                .unwrap()
                .is_none(),
            "an undecidable first frame must remain retryable, not OutOfScope"
        );
        assert_eq!(
            self.admission.observations().len(),
            2,
            "the later decidable rollout must be captured in the same sweep"
        );
    }

    async fn pending_covered(&self, scope: &ObservationScopeV1) -> bool {
        let source = codex_observation_source_v2("pending-scope").unwrap();
        self.admission
            .get_source_cursor(&source, scope)
            .await
            .unwrap()
            .is_some_and(|cursor| {
                cursor.position() == std::fs::metadata(&self.pending).unwrap().len()
            })
    }
}

#[tokio::test]
#[ignore = "requires B4 source-local, witness-independent scope deferral wiring"]
async fn codex_project_scope_pending_does_not_starve_later_rollout() {
    let fixture = ScopePendingFixture::new(true);
    let hub = fixture.hub().await;
    let scope = ObservationScopeV1::Project {
        project_id: fixture.project_id.clone(),
    };
    let bytes = std::fs::read(&fixture.pending).unwrap();
    for _ in 0..2 {
        let outcome = SCOPE_IDENTITY_RESOLVER
            .scope(
                pending_identity as GitIdentityResolver,
                fixture.project_run(&hub),
            )
            .await;
        assert!(outcome.failures.iter().any(|failure| {
            failure.reason_code == "scope_membership_pending" && failure.retryable
        }));
        fixture.assert_pending_has_no_coverage(&scope).await;
        assert_eq!(
            read_host_provider_coverage(&fixture.admission, &scope, "codex")
                .await
                .unwrap(),
            Some(HostProviderCoverage::Partial)
        );
    }
    for _ in 0..32 {
        SCOPE_IDENTITY_RESOLVER
            .scope(
                resolved_identity as GitIdentityResolver,
                fixture.project_run(&hub),
            )
            .await;
        if fixture.pending_covered(&scope).await {
            break;
        }
    }
    assert!(fixture.pending_covered(&scope).await);
    assert_eq!(fixture.admission.observations().len(), 4);
    assert_eq!(std::fs::read(&fixture.pending).unwrap(), bytes);
}

#[tokio::test]
#[ignore = "requires B4 source-local, witness-independent scope deferral wiring"]
async fn codex_profile_scope_pending_does_not_starve_later_rollout() {
    let fixture = ScopePendingFixture::new(false);
    let hub = fixture.hub().await;
    let scope = ObservationScopeV1::Profile;
    let bytes = std::fs::read(&fixture.pending).unwrap();
    for _ in 0..2 {
        let result = SCOPE_IDENTITY_RESOLVER
            .scope(
                pending_identity as GitIdentityResolver,
                fixture.profile_run(&hub),
            )
            .await;
        assert!(result.failures.iter().any(|failure| {
            failure.reason_code == "scope_membership_pending" && failure.retryable
        }));
        assert!(result.outcome.deferred_by_byte_cap);
        fixture.assert_pending_has_no_coverage(&scope).await;
    }
    for _ in 0..32 {
        SCOPE_IDENTITY_RESOLVER
            .scope(
                resolved_identity as GitIdentityResolver,
                fixture.profile_run(&hub),
            )
            .await;
        if fixture.pending_covered(&scope).await {
            break;
        }
    }
    assert!(fixture.pending_covered(&scope).await);
    assert_eq!(fixture.admission.observations().len(), 2);
    assert_eq!(std::fs::read(&fixture.pending).unwrap(), bytes);
}
