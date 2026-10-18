use std::path::Path;
use std::process::Command;

use tracedecay_domain::ProjectId;
use tracedecay_session_memory::context::{ApplicationScopeError, RegisteredScopeResolver};

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .expect("git command starts");
    assert!(status.success(), "git command failed: {args:?}");
}

/// The repository root in plain host form: Git for Windows rejects the
/// `\\?\` spelling `std::fs::canonicalize` returns there.
fn registered_root(repository: &tempfile::TempDir) -> std::path::PathBuf {
    tracedecay_runtime_core::path_safety::canonical_existing_identity(repository.path())
        .expect("registered root")
}

fn repository() -> tempfile::TempDir {
    let root = tempfile::TempDir::new().expect("repository");
    for args in [
        &["init", "-q"][..],
        &["config", "user.name", "TraceDecay Test"][..],
        &["config", "user.email", "test@tracedecay.invalid"][..],
        &["commit", "--allow-empty", "-qm", "initial"][..],
    ] {
        git(root.path(), args);
    }
    root
}

#[test]
fn registered_scope_route_preserves_linked_worktree_identity() {
    let repository = repository();
    let registered_root = registered_root(&repository);
    let project_id = ProjectId::new("project.registered-route").expect("project id");
    assert!(
        tracedecay_runtime_core::storage::write_repository_identity_marker(
            &registered_root,
            project_id.as_str(),
        )
        .expect("identity marker")
    );
    let linked_parent = tempfile::TempDir::new().expect("linked parent");
    let linked = linked_parent.path().join("linked");
    git(
        &registered_root,
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            linked.to_str().expect("linked path"),
        ],
    );

    let registered_scope =
        RegisteredScopeResolver::resolve(&registered_root, &registered_root, &project_id)
            .expect("registered scope");
    let linked_scope = RegisteredScopeResolver::resolve(&registered_root, &linked, &project_id)
        .expect("linked scope");

    assert_eq!(linked_scope.project_id, project_id);
    assert_eq!(linked_scope.repository_id, registered_scope.repository_id);
    assert_ne!(linked_scope.worktree_id, registered_scope.worktree_id);
}

#[test]
fn registered_scope_route_rejects_foreign_repository() {
    let registered = repository();
    let foreign = repository();
    let project_id = ProjectId::new("project.registered-route").expect("project id");
    assert!(
        tracedecay_runtime_core::storage::write_repository_identity_marker(
            registered.path(),
            project_id.as_str(),
        )
        .expect("identity marker")
    );

    assert!(
        RegisteredScopeResolver::resolve(registered.path(), foreign.path(), &project_id).is_err()
    );
}

#[test]
fn registered_scope_route_preserves_nested_linked_worktree_and_descendants() {
    let repository = repository();
    let registered_root = registered_root(&repository);
    let project_id = ProjectId::new("project.registered-route").expect("project id");
    assert!(
        tracedecay_runtime_core::storage::write_repository_identity_marker(
            &registered_root,
            project_id.as_str(),
        )
        .expect("identity marker")
    );
    let ordinary = registered_root.join("src");
    std::fs::create_dir(&ordinary).expect("ordinary subdirectory");
    let linked = registered_root.join(".worktrees/feature");
    std::fs::create_dir(linked.parent().expect("linked parent")).expect("linked parent directory");
    git(
        &registered_root,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature",
            linked.to_str().expect("linked path"),
        ],
    );
    let linked_child = linked.join("src");
    std::fs::create_dir(&linked_child).expect("linked subdirectory");

    let registered_scope =
        RegisteredScopeResolver::resolve(&registered_root, &registered_root, &project_id)
            .expect("registered scope");
    let linked_scope = RegisteredScopeResolver::resolve(&registered_root, &linked, &project_id)
        .expect("nested linked scope");
    assert_eq!(linked_scope.project_id, project_id);
    assert_eq!(linked_scope.repository_id, registered_scope.repository_id);
    assert_ne!(linked_scope.worktree_id, registered_scope.worktree_id);
    assert_eq!(
        linked_scope
            .reference
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("refs/heads/feature")
    );
    assert_eq!(
        RegisteredScopeResolver::canonical_scope_root(&registered_root, &linked, &project_id)
            .expect("nested linked root"),
        linked
    );
    assert_eq!(
        RegisteredScopeResolver::canonical_scope_root(&registered_root, &linked_child, &project_id)
            .expect("nested linked child root"),
        linked
    );
    assert_eq!(
        RegisteredScopeResolver::resolve(&registered_root, &linked_child, &project_id)
            .expect("nested linked child scope"),
        linked_scope
    );
    assert_eq!(
        RegisteredScopeResolver::canonical_scope_root(&registered_root, &ordinary, &project_id)
            .expect("ordinary child root"),
        registered_root
    );
    assert_eq!(
        RegisteredScopeResolver::resolve(&registered_root, &ordinary, &project_id)
            .expect("ordinary child scope"),
        registered_scope
    );
}

#[test]
fn registered_scope_route_rejects_foreign_nested_repository() {
    let repository = repository();
    let registered_root = registered_root(&repository);
    let project_id = ProjectId::new("project.registered-route").expect("project id");
    assert!(
        tracedecay_runtime_core::storage::write_repository_identity_marker(
            &registered_root,
            project_id.as_str(),
        )
        .expect("identity marker")
    );
    let foreign = registered_root.join("foreign");
    std::fs::create_dir(&foreign).expect("foreign repository directory");
    git(&foreign, &["init", "--quiet"]);

    assert!(matches!(
        RegisteredScopeResolver::canonical_scope_root(&registered_root, &foreign, &project_id),
        Err(ApplicationScopeError::UnauthorizedSiblingRoot { .. })
    ));
    assert!(matches!(
        RegisteredScopeResolver::resolve(&registered_root, &foreign, &project_id),
        Err(ApplicationScopeError::UnauthorizedSiblingRoot { .. })
    ));
}

#[test]
fn registered_scope_route_admits_a_clone_whose_marker_names_the_project() {
    let repository = repository();
    let registered_root = repository.path().canonicalize().expect("registered root");
    let project_id = ProjectId::new("project.registered-route").expect("project id");
    let clone_parent = tempfile::TempDir::new().expect("clone parent");
    let clone = clone_parent.path().join("clone");
    git(
        clone_parent.path(),
        &[
            "clone",
            "--quiet",
            registered_root.to_str().expect("registered path"),
            clone.to_str().expect("clone path"),
        ],
    );
    for root in [registered_root.as_path(), clone.as_path()] {
        assert!(
            tracedecay_runtime_core::storage::write_repository_identity_marker(
                root,
                project_id.as_str(),
            )
            .expect("identity marker")
        );
    }

    let registered_scope =
        RegisteredScopeResolver::resolve(&registered_root, &registered_root, &project_id)
            .expect("registered scope");
    let clone_scope = RegisteredScopeResolver::resolve(&registered_root, &clone, &project_id)
        .expect("a clone whose own marker names the project resolves");

    assert_eq!(clone_scope.project_id, project_id);
    assert_ne!(clone_scope.worktree_id, registered_scope.worktree_id);
}
