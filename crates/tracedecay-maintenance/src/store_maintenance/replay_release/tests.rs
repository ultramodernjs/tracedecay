#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use super::*;
use crate::store_maintenance::registered_tests::maintenance_lease;
use tracedecay_code_index_retention::code_index_generations::fixture::write_segmented_generation_store_fixture;
use tracedecay_code_index_retention::code_index_generations::{
    CodeGenerationRetentionModeV1, execute_code_generation_retention,
    plan_code_generation_retention,
};

#[test]
fn project_preview_uses_canonical_checkout_identity_for_scope_and_confirmation() {
    use tracedecay_code_index_retention::code_index_generations::record_scope_root;
    use tracedecay_runtime_core::path_safety::canonical_existing_identity;

    let temp = tempfile::tempdir().expect("isolated release fixture");
    let checkout = temp.path().join("checkout");
    std::fs::create_dir(&checkout).expect("checkout");
    // On Windows these are respectively plain C:\ and verbatim \\?\C:\.
    let plain = canonical_existing_identity(&checkout).expect("plain checkout identity");
    let verbatim = checkout.canonicalize().expect("native canonical checkout");
    let layout = tracedecay_runtime_core::storage::profile_sharded_layout(
        &plain,
        &temp.path().join("profile"),
        "project.release-preview-identity",
    )
    .expect("fixture layout");
    let root = code_index_store_root(&layout.data_root, &plain);
    write_segmented_generation_store_fixture(&root, 1);
    record_scope_root(&root, &plain).expect("record canonical root");
    let before = inventory(&layout.data_root);
    let expected =
        plan_project_graph_replay_releases(&layout, &plain, None).expect("plain preview");
    for spelling in [&verbatim, &plain.join("..").join("checkout")] {
        assert_eq!(
            plan_project_graph_replay_releases(&layout, spelling, None).expect("alias preview"),
            expected,
            "equivalent checkout spellings must bind the same queue and digest"
        );
    }
    assert_eq!(inventory(&layout.data_root), before, "preview is read-only");
    assert!(!layout.graph_db_path.exists());

    // A linked checkout needs its own valid record, not just a directory
    // whose name hashes to the caller-supplied path.
    let linked = temp.path().join("linked");
    std::fs::create_dir(&linked).expect("linked checkout");
    let linked = canonical_existing_identity(&linked).expect("linked identity");
    let linked_scope = code_index_store_root(&layout.data_root, &linked);
    write_segmented_generation_store_fixture(&linked_scope, 1);
    assert!(plan_project_graph_replay_releases(&layout, &linked, None).is_err());
    record_scope_root(&linked_scope, &plain).expect("record mismatching root");
    assert!(plan_project_graph_replay_releases(&layout, &linked, None).is_err());
    record_scope_root(&linked_scope, &linked).expect("record matching linked root");
    let linked_plan = plan_project_graph_replay_releases(
        &layout,
        &linked.canonicalize().expect("native linked spelling"),
        None,
    )
    .expect("proven linked preview");
    assert_eq!(linked_plan.store_root, linked_scope);
    assert_eq!(linked_plan.checkout_root, linked);
}

#[asupersync::test]
async fn release_handler_previews_and_confirms_a_real_durable_queue() {
    let temp = tempfile::tempdir().expect("isolated release fixture");
    let profile = temp.path().join("profile");
    let checkout = temp.path().join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let checkout = checkout.canonicalize().expect("canonical checkout");
    let (lease, _scope, _owner) =
        maintenance_lease(&profile, &checkout, "project.release-handler").await;
    let root = code_index_store_root(&lease.store_layout().data_root, &checkout);
    let generations = write_segmented_generation_store_fixture(&root, 3);
    // The linked scope still needs the first pack. The second is exclusive
    // to a released generation, while the primary active head needs the third.
    let linked = temp.path().join("linked");
    std::fs::create_dir_all(&linked).expect("linked checkout");
    let linked_root = code_index_store_root(&lease.store_layout().data_root, &linked);
    write_segmented_generation_store_fixture(&linked_root, 1);
    let segments =
        tracedecay_code_index_retention::code_index_generations::code_generation_segments_root(
            &root,
        );
    let segment_path = |generation: &tracedecay_code_index_retention::code_index_generations::fixture::GenerationStoreFixtureV1| {
        let bytes = std::fs::read(root.join("code-generations-v1").join(&generation.file))
            .expect("fixture manifest");
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).expect("manifest JSON");
        let digest = manifest["generation"]["generation_evidence"]["segment_digest"]
            .as_str().expect("pack digest");
        segments.join(format!("segment-{}.json", digest.strip_prefix("sha256:").expect("digest prefix")))
    };
    let shared_pack = segment_path(&generations[0]);
    let exclusive_pack = segment_path(&generations[1]);
    let active_pack = segment_path(&generations[2]);
    let pool = lease
        .graph_db()
        .database_path()
        .with_extension("graph-replay");
    let plan = plan_code_generation_retention(&root, &BTreeSet::new()).expect("retention plan");
    execute_code_generation_retention(
        &root,
        plan,
        CodeGenerationRetentionModeV1::Apply,
        tracedecay_domain::UtcMicros(2),
        Some(&pool),
    )
    .expect("durable release evidence and production pool links");
    assert!(shared_pack.is_file() && exclusive_pack.is_file() && active_pack.is_file());
    let before_preview = inventory(&lease.store_layout().data_root);
    let cancellation = CancellationToken::new();
    let GraphReplayReleaseRunV1::DryRun { plan } =
        release_graph_replays(&lease, &checkout, None, None, &cancellation)
            .await
            .expect("read-only preview")
    else {
        panic!("dry run must not apply")
    };
    assert_eq!(plan.releases.len(), 2);
    assert_eq!(
        inventory(&lease.store_layout().data_root),
        before_preview,
        "dry-run preserves every file's bytes and modification time"
    );
    assert_eq!(
        plan.reclaimable_bytes, None,
        "a receipt cannot prove source liveness or reclaimable bytes"
    );
    assert_eq!(plan.authority, GraphReplayReleaseAuthorityV1::Unvalidated);
    for generation in &generations[..2] {
        assert!(
            pool.join(&generation.file).is_file(),
            "preview preserves pool link"
        );
    }
    let wrong_digest = format!("sha256:{}", "0".repeat(64));
    assert!(
        release_graph_replays(&lease, &checkout, None, Some(&wrong_digest), &cancellation,)
            .await
            .is_err(),
        "a missing or stale confirmation must not mutate the queue"
    );
    assert_eq!(
        code_generation_graph_replay_release_page(&root, None)
            .expect("queue after refusal")
            .releases
            .len(),
        2
    );
    assert_eq!(
        inventory(&lease.store_layout().data_root),
        before_preview,
        "refused confirmation cannot mutate the fixture"
    );
    let GraphReplayReleaseRunV1::Applied {
        released, retained, ..
    } = release_graph_replays(
        &lease,
        &checkout,
        None,
        Some(&plan.plan_digest),
        &cancellation,
    )
    .await
    .expect("confirmed production release")
    else {
        panic!("confirmed apply")
    };
    assert_eq!((released, retained), (2, 0));
    assert!(
        !exclusive_pack.exists(),
        "source unlink must enable the following segment sweep"
    );
    assert!(
        shared_pack.is_file(),
        "another scope's live pack is protected"
    );
    assert!(
        active_pack.is_file(),
        "the active generation's pack is protected"
    );
    assert_eq!(
        code_generation_graph_replay_release_page(&root, None)
            .expect("acknowledged queue")
            .releases,
        Vec::new()
    );
    for generation in &generations[..2] {
        assert!(
            !pool.join(&generation.file).exists(),
            "production source unlink"
        );
    }
    assert!(
        root.join("code-generations-v1")
            .join(&generations[2].file)
            .is_file(),
        "one-shot release never collects the active generation"
    );
    assert!(
        !lease
            .graph_db()
            .database_path()
            .with_extension("grafeo")
            .exists(),
        "the lazy maintenance path must not open native staging"
    );
    assert!(
        release_graph_replays(
            &lease,
            &checkout,
            None,
            Some(&plan.plan_digest),
            &cancellation
        )
        .await
        .is_err(),
        "a changed queue invalidates the old confirmation"
    );
    let GraphReplayReleaseRunV1::DryRun { plan } =
        release_graph_replays(&lease, &checkout, None, None, &cancellation)
            .await
            .expect("empty preview")
    else {
        panic!("dry run")
    };
    let GraphReplayReleaseRunV1::Applied {
        released, retained, ..
    } = release_graph_replays(
        &lease,
        &checkout,
        None,
        Some(&plan.plan_digest),
        &cancellation,
    )
    .await
    .expect("idempotent rerun")
    else {
        panic!("confirmed apply")
    };
    assert_eq!((released, retained), (0, 0));
}

fn inventory(root: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(root).expect("fixture inventory") {
        let entry = entry.expect("fixture entry");
        if entry.file_type().expect("fixture type").is_dir() {
            result.extend(inventory(&entry.path()));
        } else {
            result.push((
                entry.path(),
                std::fs::read(entry.path()).expect("fixture bytes"),
                entry
                    .metadata()
                    .expect("fixture metadata")
                    .modified()
                    .expect("fixture mtime"),
            ));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}
