use std::cell::Cell;

use super::*;

#[test]
fn released_segment_mark_resumes_across_bounded_calls_and_cancellation() {
    let store = tempfile::tempdir().expect("isolated store");
    let pool = store.path().join("replay-pool");
    tracedecay_private_fs::create_private_directory(&pool).expect("private replay pool");
    let generations = fixture::write_segmented_generation_store_fixture(store.path(), 96);
    let segments = code_generation_segments_root(store.path());
    let mut orphans = Vec::new();
    for index in 0..70 {
        let bytes = format!("orphan pack {index}");
        let digest = encode_lowercase_hex(&Sha256::digest(bytes.as_bytes()));
        let path = segments.join(format!("segment-{digest}.json"));
        std::fs::write(&path, bytes).expect("orphan pack");
        orphans.push(path);
    }
    segment_release::take_io_observation();
    let calls = Cell::new(0);
    let first = sweep_released_code_generation_segments_cancellable(store.path(), &pool, &|| {
        calls.set(calls.get() + 1);
        calls.get() > 100
    });
    assert!(
        matches!(first, Ok(true)),
        "a bounded mark yields before traversing all retained manifests, got {first:?}"
    );
    let (entries, bytes) = segment_release::take_io_observation();
    assert!(
        entries <= 32 && bytes <= 1024 * 1024,
        "first page examined {entries} entries and {bytes} bytes"
    );
    assert!(
        orphans.iter().all(|path| path.exists()),
        "no partial mark may authorize deletion"
    );
    assert!(matches!(
        sweep_released_code_generation_segments_cancellable(store.path(), &pool, &|| true),
        Err(CodeGenerationRetentionErrorV1::Cancelled)
    ));
    let mut completed = false;
    for _ in 0..40 {
        calls.set(0);
        let more =
            sweep_released_code_generation_segments_cancellable(store.path(), &pool, &|| {
                calls.set(calls.get() + 1);
                calls.get() > 100
            })
            .expect("bounded continuation must progress instead of restarting its census");
        let (entries, bytes) = segment_release::take_io_observation();
        assert!(
            entries <= 32 && bytes <= 1024 * 1024,
            "continuation examined {entries} entries and {bytes} bytes"
        );
        if !more {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "the census and three deletion batches must converge"
    );
    assert!(orphans.iter().all(|path| !path.exists()));
    assert_eq!(
        std::fs::read_dir(&segments).unwrap().count(),
        96,
        "every retained pack survives"
    );
    assert_eq!(generations.len(), 96);
}

#[test]
fn released_segment_mark_includes_scope_and_manifest_quarantines_and_staged_unlinks() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("project-data");
    let primary = code_index_store_root(&data, &temp.path().join("primary"));
    let linked = code_index_store_root(&data, &temp.path().join("linked"));
    let generations = fixture::write_segmented_generation_store_fixture(&primary, 3);
    fixture::write_segmented_generation_store_fixture(&linked, 1);
    let pool = data.join("replay-pool");
    tracedecay_private_fs::create_private_directory(&pool).unwrap();
    let manifests = primary.join(GENERATIONS_DIRECTORY);
    // Only the quarantined linked scope still names pack zero.
    std::fs::remove_file(manifests.join(&generations[0].file)).unwrap();
    let stage = generation_segment_project_root(&primary)
        .join(SCOPE_RETENTION_QUARANTINE_DIRECTORY)
        .join("restorable-scope");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::rename(&linked, stage.join(linked.file_name().unwrap())).unwrap();
    // Pack one survives as a staged graph-source unlink, pack two as a
    // generation retention quarantine that recovery may still restore.
    let digest = generation_file_digest(&generations[1].file).unwrap();
    std::fs::rename(
        manifests.join(&generations[1].file),
        pool.join(format!(".generation-{digest}.unlink-fixture")),
    )
    .unwrap();
    let quarantine = primary
        .join(QUARANTINE_DIRECTORY)
        .join("restorable-generation");
    std::fs::create_dir_all(&quarantine).unwrap();
    std::fs::rename(
        manifests.join(&generations[2].file),
        quarantine.join(&generations[2].file),
    )
    .unwrap();
    let (orphan, _) = orphan_pack(&primary, b"unreferenced quarantined-store pack");
    finish_sweep(&primary, &pool);
    assert!(!orphan.exists());
    assert_eq!(
        std::fs::read_dir(code_generation_segments_root(&primary))
            .unwrap()
            .count(),
        3,
        "all three independent restorable roots keep their packs"
    );
}

fn orphan_pack(store: &Path, bytes: &[u8]) -> (PathBuf, String) {
    let digest = encode_lowercase_hex(&Sha256::digest(bytes));
    let path = code_generation_segments_root(store).join(format!("segment-{digest}.json"));
    std::fs::write(&path, bytes).expect("orphan pack");
    (path, format!("sha256:{digest}"))
}

fn publish_manifest_naming_pack(source: &Path, destination: &Path, digest: &str, size: usize) {
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
    let evidence = &mut manifest["generation"]["generation_evidence"];
    evidence["segment_digest"] = serde_json::json!(digest);
    evidence["segment_size_bytes"] = serde_json::json!(size);
    evidence["pages"][0]["page_digest"] = serde_json::json!(digest);
    evidence["pages"][0]["page_size_bytes"] = serde_json::json!(size);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let digest = encode_lowercase_hex(&Sha256::digest(&bytes));
    std::fs::write(destination.join(format!("generation-{digest}.json")), bytes).unwrap();
}

fn finish_sweep(store: &Path, pool: &Path) {
    for _ in 0..100 {
        if !sweep_released_code_generation_segments_cancellable(store, pool, &|| false)
            .expect("bounded sweep")
        {
            return;
        }
    }
    panic!("bounded sweep did not converge");
}

#[test]
fn released_segment_census_invalidates_when_publication_adds_a_root() {
    let store = tempfile::tempdir().unwrap();
    let pool = store.path().join("replay-pool");
    tracedecay_private_fs::create_private_directory(&pool).unwrap();
    let generations = fixture::write_segmented_generation_store_fixture(store.path(), 2);
    let mut orphans = Vec::new();
    for index in 0..70 {
        let bytes = format!("newly publishable pack {index}");
        let (path, digest) = orphan_pack(store.path(), bytes.as_bytes());
        orphans.push((path, digest, bytes.len()));
    }
    // Get past the completed mark and into a multi-batch sweep.
    while orphans.iter().all(|(path, _, _)| path.exists()) {
        assert!(
            sweep_released_code_generation_segments_cancellable(store.path(), &pool, &|| false)
                .unwrap()
        );
    }
    let (newly_live, digest, size) = orphans.iter().find(|(path, _, _)| path.exists()).unwrap();
    {
        let _publication =
            acquire_generation_segments_publication_lock(store.path(), &|| false).unwrap();
        let root = store.path().join(GENERATIONS_DIRECTORY);
        publish_manifest_naming_pack(&root.join(&generations[0].file), &root, digest, *size);
    }
    finish_sweep(store.path(), &pool);
    assert!(
        newly_live.exists(),
        "publication invalidates a previously complete mark before any further unlink"
    );
    assert_eq!(
        std::fs::read_dir(code_generation_segments_root(store.path()))
            .unwrap()
            .count(),
        3
    );
}

#[test]
fn released_segment_census_invalidates_when_replay_pool_changes() {
    let store = tempfile::tempdir().unwrap();
    let pool = store.path().join("replay-pool");
    tracedecay_private_fs::create_private_directory(&pool).unwrap();
    let generations = fixture::write_segmented_generation_store_fixture(store.path(), 2);
    let mut orphans = Vec::new();
    for index in 0..70 {
        let bytes = format!("new replay pool pack {index}");
        let (path, digest) = orphan_pack(store.path(), bytes.as_bytes());
        orphans.push((path, digest, bytes.len()));
    }
    while orphans.iter().all(|(path, _, _)| path.exists()) {
        assert!(
            sweep_released_code_generation_segments_cancellable(store.path(), &pool, &|| false)
                .unwrap()
        );
    }
    let (newly_live, digest, size) = orphans.iter().find(|(path, _, _)| path.exists()).unwrap();
    {
        let _pool = acquire_code_generation_store_lock(&pool).unwrap();
        publish_manifest_naming_pack(
            &store
                .path()
                .join(GENERATIONS_DIRECTORY)
                .join(&generations[0].file),
            &pool,
            digest,
            *size,
        );
    }
    finish_sweep(store.path(), &pool);
    assert!(
        newly_live.exists(),
        "a new replay-pool manifest invalidates the cached roots too"
    );
}

fn padded_manifest(store: &Path, valid_digest: bool) -> (tempfile::TempDir, PathBuf) {
    let pool = tempfile::tempdir().unwrap();
    tracedecay_private_fs::make_private_directory(pool.path()).unwrap();
    let generations = fixture::write_segmented_generation_store_fixture(store, 1);
    let root = store.join(GENERATIONS_DIRECTORY);
    let original = root.join(&generations[0].file);
    let bytes = std::fs::read(&original).unwrap();
    let text = std::str::from_utf8(&bytes)
        .unwrap()
        .replace("sha256:", "\\u0073ha256\\u003a");
    let padded = format!(
        "{{\"padding\":\"{}\",{}",
        "x".repeat(3 * 1024 * 1024),
        &text[1..]
    );
    let digest = if valid_digest {
        encode_lowercase_hex(&Sha256::digest(padded.as_bytes()))
    } else {
        "0".repeat(64)
    };
    std::fs::write(root.join(format!("generation-{digest}.json")), padded).unwrap();
    std::fs::remove_file(original).unwrap();
    // This models an unpublished seal, not a pointer naming a renamed file.
    std::fs::remove_file(store.join(ACTIVE_POINTER_FILE)).unwrap();
    let (orphan, _) = orphan_pack(store, b"exclusive orphan pack");
    (pool, orphan)
}

#[test]
fn released_segment_mark_bounds_bytes_and_marks_escaped_digests() {
    let store = tempfile::tempdir().unwrap();
    let (pool, orphan) = padded_manifest(store.path(), true);
    let manifest_bytes = std::fs::read_dir(store.path().join(GENERATIONS_DIRECTORY))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .metadata()
        .unwrap()
        .len();
    segment_release::take_io_observation();
    let polls = Cell::new(0);
    assert!(
        sweep_released_code_generation_segments_cancellable(store.path(), pool.path(), &|| {
            polls.set(polls.get() + 1);
            polls.get() > 100
        })
        .unwrap()
    );
    assert!(
        orphan.exists(),
        "a manifest larger than a read page cannot authorize deletion in its first call"
    );
    let (_, bytes) = segment_release::take_io_observation();
    assert!(bytes <= 1024 * 1024);
    let mut bytes_examined = bytes as u64;
    let cancelled_polls = Cell::new(0);
    assert!(matches!(
        sweep_released_code_generation_segments_cancellable(store.path(), pool.path(), &|| {
            cancelled_polls.set(cancelled_polls.get() + 1);
            cancelled_polls.get() > 10
        }),
        Err(CodeGenerationRetentionErrorV1::Cancelled)
    ));
    assert!(orphan.exists());
    let (_, bytes) = segment_release::take_io_observation();
    assert!(bytes <= 1024 * 1024);
    bytes_examined += bytes as u64;
    let mut finished = false;
    for _ in 0..3 {
        let more =
            sweep_released_code_generation_segments_cancellable(store.path(), pool.path(), &|| {
                false
            })
            .unwrap();
        let (_, bytes) = segment_release::take_io_observation();
        assert!(bytes <= 1024 * 1024);
        bytes_examined += bytes as u64;
        if !more {
            finished = true;
            break;
        }
    }
    assert_eq!(
        bytes_examined, manifest_bytes,
        "continuation and cancellation must never re-read an authenticated prefix"
    );
    assert!(
        finished,
        "a mid-file cancellation must preserve the hashed byte prefix, not restart the 3-MiB manifest"
    );
    assert!(!orphan.exists());
    assert_eq!(
        std::fs::read_dir(code_generation_segments_root(store.path()))
            .unwrap()
            .count(),
        1,
        "an escaped live segment digest is marked across byte pages"
    );
}

#[test]
fn released_segment_mark_checks_full_digest_before_any_unlink() {
    let store = tempfile::tempdir().unwrap();
    let (pool, orphan) = padded_manifest(store.path(), false);
    let mut refused = false;
    for _ in 0..10 {
        match sweep_released_code_generation_segments_cancellable(
            store.path(),
            pool.path(),
            &|| false,
        ) {
            Ok(true) => assert!(orphan.exists()),
            Err(CodeGenerationRetentionErrorV1::UnsafeState(_)) => {
                refused = true;
                break;
            }
            other => panic!("expected bounded mark or digest refusal, got {other:?}"),
        }
    }
    assert!(
        refused,
        "the final byte page must verify the complete content digest"
    );
    assert!(
        orphan.exists(),
        "no partial or digest-mismatched mark may authorize deletion"
    );
}
