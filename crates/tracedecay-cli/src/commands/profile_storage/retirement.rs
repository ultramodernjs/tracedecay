//! Offline operator-only observation retirement. No daemon RPC, service
//! lifecycle changes, schema installer, graph open or historical convergence.

use std::path::Path;
use std::sync::Arc;

use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_global_db::{RegisteredGlobalDbLeaseV1, RegisteredGlobalDbOwnerV1};
use tracedecay_runtime_core::config::{GLOBAL_DB_FILENAME, ProfileRoot};
use tracedecay_runtime_core::db::{Database, DatabaseAccessMode, DatabaseAuthority};
use tracedecay_runtime_core::lifecycle_lease::{
    ExclusiveLeaseAttempt, LifecycleLease, try_acquire_exclusive_for_profile,
};
use tracedecay_runtime_core::shard_runtime::registry::{
    LifecycleShardRuntimePublisher, ProfileAuthorityPinResult, StoreRuntimeClientLease,
    StoreRuntimeOpenRequest, StoreRuntimeOpenResult, StoreRuntimeRegistry,
};
use tracedecay_runtime_core::storage::USER_SESSIONS_DB_FILENAME;
use tracedecay_store::{StoreIncarnationV1, StoreShardIdV1};
use tracedecay_store_runtime::store_locator_resolver::{
    LocalProfileStoreAuthorityV1, LocalStoreRuntimeResolverV1,
};

fn error(cause: impl std::fmt::Display) -> TraceDecayError {
    TraceDecayError::Config {
        message: cause.to_string(),
    }
}

fn acquire_offline(profile: &Path, operation: &'static str) -> Result<LifecycleLease> {
    match try_acquire_exclusive_for_profile(profile, operation)? {
        ExclusiveLeaseAttempt::Acquired(lease) => Ok(lease),
        ExclusiveLeaseAttempt::Busy { owner_operation } => Err(error(format!(
            "{operation} requires the daemon stopped and the exclusive profile lease{}; stop the daemon explicitly, retry, then restart it when maintenance is complete",
            owner_operation
                .map(|owner| format!(" (held by {owner})"))
                .unwrap_or_default(),
        ))),
    }
}

struct OfflineStore {
    db: RegisteredGlobalDbLeaseV1,
    _owner: RegisteredGlobalDbOwnerV1,
    _profile: StoreRuntimeClientLease,
    _registry: StoreRuntimeRegistry,
}

fn process_incarnation() -> Result<StoreIncarnationV1> {
    let generation = tracedecay_store_runtime::process_runtime_generation(
        tracedecay_runtime_core::runtime_identity::process_run_id(),
    )
    .ok_or_else(|| error("unsupported process runtime identity"))?;
    StoreIncarnationV1::new(generation).map_err(error)
}

async fn open_existing(
    profile_root: &Path,
    lifecycle: &LifecycleLease,
    writable: bool,
    incarnation: StoreIncarnationV1,
) -> Result<OfflineStore> {
    // Do not manufacture a new profile/store because a maintenance path is wrong.
    for name in [GLOBAL_DB_FILENAME, USER_SESSIONS_DB_FILENAME] {
        if !profile_root.join(name).is_file() {
            return Err(error(format!(
                "existing store {} is required; nothing created",
                profile_root.join(name).display()
            )));
        }
    }
    let identity = tracedecay_daemon_identity::profile_identity::load_existing(profile_root)?;
    let profile_shard =
        StoreShardIdV1::profile(identity.brain_id().clone(), identity.profile_id().clone());
    let sessions_shard = StoreShardIdV1::profile_sessions(
        identity.brain_id().clone(),
        identity.profile_id().clone(),
    );
    let resolver = Arc::new(LocalStoreRuntimeResolverV1::new(
        LocalProfileStoreAuthorityV1::new(
            identity.brain_id().clone(),
            identity.profile_id().clone(),
            identity.profile_root().to_path_buf(),
        ),
    ));
    let registry = {
        let runtime = tracedecay_runtime_core::native_runtime::handle()
            .ok_or_else(|| error("retirement maintenance requires the native runtime"))?;
        StoreRuntimeRegistry::new(
            runtime.clone(),
            resolver,
            Arc::new(LifecycleShardRuntimePublisher),
        )
        .map_err(|failure| error(format!("cannot open offline store registry: {failure:?}")))?
    };
    let profile = match registry
        .open(StoreRuntimeOpenRequest::new_read_only(
            profile_shard.clone(),
            incarnation,
            None,
        ))
        .await
    {
        StoreRuntimeOpenResult::Published(runtime) => runtime,
        StoreRuntimeOpenResult::Failed(failure) => {
            return Err(tracedecay_store_runtime::registry_open_error(
                "open existing offline profile",
                failure,
            ));
        }
    };
    let pin = match registry.profile_authority_pin(&profile_shard) {
        ProfileAuthorityPinResult::Pinned(pin) => pin,
        failure => {
            return Err(error(format!(
                "cannot pin existing profile authority: {failure:?}"
            )));
        }
    };
    let request = if writable {
        let authority = DatabaseAuthority::for_owned_runtime(
            &profile_root.join(USER_SESSIONS_DB_FILENAME),
            "offline observation retirement",
        )?;
        StoreRuntimeOpenRequest::new_authorized(sessions_shard, incarnation, Some(pin), authority)
    } else {
        StoreRuntimeOpenRequest::new_read_only(sessions_shard, incarnation, Some(pin))
    };
    let sessions = match registry.open(request).await {
        StoreRuntimeOpenResult::Published(runtime) => runtime,
        StoreRuntimeOpenResult::Failed(failure) => {
            return Err(tracedecay_store_runtime::registry_open_error(
                "open existing offline profile sessions",
                failure,
            ));
        }
    };
    let access = if writable {
        DatabaseAccessMode::ReadWrite
    } else {
        DatabaseAccessMode::ReadOnly
    };
    let database = Database::publish_runtime(sessions, access).await?;
    let owner =
        Box::pin(RegisteredGlobalDbOwnerV1::attach_for_observation_retirement(database, lifecycle))
            .await?;
    let db = owner
        .issue_lease()
        .map_err(|failure| error(format!("cannot issue offline session lease: {failure:?}")))?;
    Ok(OfflineStore {
        db,
        _owner: owner,
        _profile: profile,
        _registry: registry,
    })
}

pub(super) async fn prepare_indexes(
    profile: &ProfileRoot,
    apply: Option<String>,
    json: bool,
) -> Result<()> {
    let profile_root = profile.data_dir().canonicalize()?;
    let lifecycle = acquire_offline(&profile_root, "prepare-retirement-indexes")?;
    let _scope = tracedecay_runtime_core::db::enter_maintenance_database_scope(
        &lifecycle,
        &profile_root,
        "prepare-retirement-indexes",
    )?;
    let store = Box::pin(open_existing(
        &profile_root,
        &lifecycle,
        apply.is_some(),
        process_incarnation()?,
    ))
    .await?;
    let plan = store
        .db
        .plan_retirement_index_preparation(&lifecycle)
        .await
        .map_err(error)?;
    if let Some(digest) = &apply {
        store
            .db
            .apply_retirement_index_preparation(&lifecycle, &plan, digest)
            .await
            .map_err(error)?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "applied": apply.is_some() && !plan.done, "plan": plan })
            )
            .map_err(error)?
        );
    } else if plan.done {
        println!("Retirement indexes are ready; no index built.");
    } else {
        println!(
            "{}: {} rows, {} bounded key bytes; within budget: {}",
            plan.index_name.as_deref().ok_or_else(|| error(
                "unfinished retirement preparation plan is missing its index name"
            ))?,
            plan.rows,
            plan.key_bytes,
            plan.within_budget
        );
        println!("digest: {}", plan.digest());
        println!(
            "{}; rerun without --apply to review the next missing index. Completed indexes are the resume cursor.",
            if apply.is_some() {
                "Built one index"
            } else {
                "Dry run only; confirm with --apply <digest> to build this one index"
            }
        );
    }
    Ok(())
}

pub(super) async fn cleanup_codex(
    profile: &ProfileRoot,
    apply: Option<String>,
    cursor: Option<String>,
    page_size: u16,
    json: bool,
) -> Result<()> {
    let cursor = cursor
        .as_deref()
        .map(
            serde_json::from_str::<
                tracedecay_global_db::observation::unsupported_codex::UnsupportedCodexCleanupCursor,
            >,
        )
        .transpose()
        .map_err(error)?;
    let profile_root = profile.data_dir().canonicalize()?;
    let lifecycle = acquire_offline(&profile_root, "cleanup-codex")?;
    let _scope = tracedecay_runtime_core::db::enter_maintenance_database_scope(
        &lifecycle,
        &profile_root,
        "cleanup-codex",
    )?;
    let store = Box::pin(open_existing(
        &profile_root,
        &lifecycle,
        apply.is_some(),
        process_incarnation()?,
    ))
    .await?;
    let plan = store.db.plan_unsupported_codex_cleanup(cursor.as_ref(), usize::from(page_size)).await.map_err(|cause| error(format!(
        "cleanup-codex refused: {cause}. Missing retirement reverse indexes must be prepared offline with `tracedecay storage prepare-retirement-indexes` until done"
    )))?;
    let retired = match &apply {
        Some(digest) => store
            .db
            .apply_unsupported_codex_cleanup(&plan, digest)
            .await
            .map_err(error)?,
        None => 0,
    };
    let eligible = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.retained_reasons.is_empty())
        .count();
    let tables = plan
        .retirement()
        .map(|retirement| retirement.tables())
        .unwrap_or(&[]);
    let rows: u64 = tables
        .iter()
        .filter(|table| !table.retained)
        .map(|table| table.rows)
        .sum();
    let bytes: u64 = tables
        .iter()
        .filter(|table| !table.retained)
        .map(|table| table.bytes)
        .sum();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dry_run": apply.is_none(), "retired_observations": retired,
                "summary": { "examined": plan.examined, "candidates": plan.candidates.len(),
                    "eligible": eligible, "retained": plan.candidates.len() - eligible,
                    "exclusive_rows": rows, "exclusive_column_bytes": bytes },
                "plan": plan,
            }))
            .map_err(error)?
        );
    } else {
        println!(
            "{}: examined {}, unsupported candidates {}, eligible {}, retained {}; {} exclusive rows / {} logical column bytes",
            if apply.is_some() {
                "Applied reviewed page"
            } else {
                "Dry run only"
            },
            plan.examined,
            plan.candidates.len(),
            eligible,
            plan.candidates.len() - eligible,
            rows,
            bytes
        );
        println!(
            "Retired observations: {retired}; physical disk reclamation is not measured or performed."
        );
        println!("digest: {}", plan.plan_digest);
        println!(
            "page cursor: {}",
            serde_json::to_string(&plan.cursor).map_err(error)?
        );
        for candidate in &plan.candidates {
            if !candidate.retained_reasons.is_empty() {
                println!(
                    "retained {}: {}",
                    candidate.observation_id,
                    candidate.retained_reasons.join(", ")
                );
            }
        }
        if let Some(next) = &plan.next_cursor {
            println!(
                "next cursor (use after applying this page): {}",
                serde_json::to_string(next).map_err(error)?
            );
        } else {
            println!("Reached the reviewed high water; no next cursor.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{acquire_offline, open_existing, process_incarnation};
    use tracedecay_domain::{
        CanonicalObservationEnvelopeV1, CanonicalObservationEvidenceV1,
        CanonicalObservationRelationsV1, ComponentVersion, DurableObservationV1, ObservationId,
        ObservationIdentityMaterialV1, ObservationOrderingDomainV1, ObservationScopeV1,
        ObservationSourceCursorV1, ObservationSourceGenerationV1, ObservationSourceIdentityV1,
        ObservationSourceRangeV1, PayloadReferenceV1, ProjectionGenerationId, ProviderId,
        RetentionClass, SanitizationReceiptId, SanitizationReceiptRefV1, SanitizationReceiptV1,
        SanitizerDispositionV1, SensitivityV1, SessionId, UtcMicros,
    };
    use tracedecay_global_db::{RegisteredGlobalDbLeaseV1, RegisteredGlobalDbOwnerV1};
    use tracedecay_runtime_core::config::GLOBAL_DB_FILENAME;
    use tracedecay_runtime_core::db::{
        Database, DatabaseAuthority, TestDatabaseRuntimeMode, TestDatabaseRuntimeScope,
        TestRuntimeProfileIdentityV1,
    };
    use tracedecay_runtime_core::storage::USER_SESSIONS_DB_FILENAME;
    use tracedecay_store::{
        AnchoredObservationWrite, ObservationStore, ObservationWrite, StoreIncarnationV1,
        build_observation_resolution_authorization_v1, build_observation_retrieval_anchor,
    };

    async fn cleanup_record(
        db: &RegisteredGlobalDbLeaseV1,
        index: u64,
        supported: bool,
    ) -> DurableObservationV1 {
        let provider = ProviderId::new("codex").unwrap();
        let session = SessionId::new("session.offline.cleanup").unwrap();
        let native = ObservationId::new(format!("record.offline.cleanup.{index}")).unwrap();
        let range = ObservationSourceRangeV1::new(index * 100, index * 100 + 100).unwrap();
        let fact = if supported {
            serde_json::json!({"kind":"message", "role":"user", "content":"Keep supported evidence"})
        } else {
            serde_json::json!({"kind":"unknown", "native_kind":"future_event", "state":"unsupported"})
        };
        let envelope = CanonicalObservationEnvelopeV1::new(
            provider.clone(),
            "event_msg",
            native.clone(),
            CanonicalObservationRelationsV1::new(session.clone()),
            vec![serde_json::from_value(fact).unwrap()],
            CanonicalObservationEvidenceV1::new(ObservationOrderingDomainV1::FileBytes, range),
        )
        .unwrap();
        let payload = serde_json::to_value(envelope).unwrap();
        let observation = DurableObservationV1::new(
            ObservationIdentityMaterialV1::for_native_record(
                ObservationSourceIdentityV1::for_provider(provider, session).unwrap(),
                ObservationScopeV1::Profile,
                ObservationSourceGenerationV1::new(1).unwrap(),
                range,
                ObservationOrderingDomainV1::FileBytes,
                native,
            )
            .unwrap(),
            SanitizationReceiptV1::new(
                SanitizationReceiptRefV1::new(
                    SanitizationReceiptId::new(format!("receipt.offline.cleanup.{index}")).unwrap(),
                    ComponentVersion::new("sanitizer.offline.v1").unwrap(),
                )
                .unwrap(),
                SanitizerDispositionV1::Accepted,
                SensitivityV1::NonSensitive,
                Some(PayloadReferenceV1::for_payload(&payload).unwrap()),
            )
            .unwrap(),
            RetentionClass::new("retention.offline.fixture").unwrap(),
            payload,
        )
        .unwrap();
        let previous = db
            .observation_store()
            .get_source_cursor(observation.source(), observation.scope())
            .await
            .unwrap();
        let next = ObservationSourceCursorV1::for_ordering(
            observation.source().clone(),
            observation.scope().clone(),
            observation.identity().generation(),
            observation.identity().ordering_domain(),
            range.end(),
        )
        .unwrap();
        let generation = ProjectionGenerationId::new("projection.offline.v1").unwrap();
        let authorization =
            build_observation_resolution_authorization_v1(&observation, "offline-cleanup").unwrap();
        let anchor = build_observation_retrieval_anchor(
            &observation,
            generation.clone(),
            UtcMicros(1),
            authorization,
        )
        .unwrap();
        let write = ObservationWrite::new(observation.clone(), previous, next).unwrap();
        db.observation_store()
            .persist_observation(AnchoredObservationWrite::new(write, anchor, generation).unwrap())
            .await
            .unwrap();
        observation
    }

    #[asupersync::test]
    async fn offline_retirement_digest_survives_runtime_incarnation_and_dry_run_is_passive() {
        tracedecay::register_runtime_ports().unwrap();
        tracedecay_global_db::register_registered_schema_installer();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        tracedecay_runtime_core::storage::PrivateStoreIo::create_dir_all(&root).unwrap();
        let identity = tracedecay_daemon_identity::profile_identity::load_or_create(&root).unwrap();
        let lifecycle = acquire_offline(&root, "offline retirement fixture").unwrap();
        let _scope = tracedecay_runtime_core::db::enter_maintenance_database_scope(
            &lifecycle,
            &root,
            "offline retirement fixture",
        )
        .unwrap();
        let mut reviewed = None;
        for (name, scope) in [
            (GLOBAL_DB_FILENAME, TestDatabaseRuntimeScope::Profile),
            (
                USER_SESSIONS_DB_FILENAME,
                TestDatabaseRuntimeScope::ProfileSessions,
            ),
        ] {
            let path = root.join(name);
            let authority =
                DatabaseAuthority::acquire_test(&path, "offline retirement fixture").unwrap();
            let fixture = Database::publish_registered_test_runtime_with_retirement_control_for_profile_identity(
                &path, &authority, TestDatabaseRuntimeMode::Initialize,
                TestRuntimeProfileIdentityV1::new(identity.brain_id().clone(), identity.profile_id().clone()), scope,
            ).await.unwrap();
            let (database, runtime, control) = fixture.into_parts();
            let owner = RegisteredGlobalDbOwnerV1::admit_and_attach(database)
                .await
                .unwrap();
            let db = owner.issue_lease().unwrap();
            if name == USER_SESSIONS_DB_FILENAME {
                db.writer_connection()
                    .unwrap()
                    .execute_batch("DROP INDEX idx_retirement_occurrences;")
                    .await
                    .unwrap();
                reviewed = Some(
                    db.plan_retirement_index_preparation(&lifecycle)
                        .await
                        .unwrap(),
                );
            }
            drop(db);
            drop(owner);
            drop(runtime);
            drop(control);
        }
        let reviewed = reviewed.unwrap();
        let before = std::fs::read(root.join(USER_SESSIONS_DB_FILENAME)).unwrap();
        let store = Box::pin(open_existing(
            &root,
            &lifecycle,
            false,
            process_incarnation().unwrap(),
        ))
        .await
        .unwrap();
        assert_ne!(
            store.db.verified_locator().incarnation,
            StoreIncarnationV1::new(1).unwrap()
        );
        let plan = store
            .db
            .plan_retirement_index_preparation(&lifecycle)
            .await
            .unwrap();
        assert_eq!(
            reviewed.digest(),
            plan.digest(),
            "a fresh offline process must accept the reviewed physical-store digest"
        );
        assert_eq!(
            plan.index_name.as_deref(),
            Some("idx_retirement_occurrences")
        );
        drop(store);
        assert_eq!(
            before,
            std::fs::read(root.join(USER_SESSIONS_DB_FILENAME)).unwrap(),
            "dry-run must not install schema or indexes"
        );
        let store = Box::pin(open_existing(
            &root,
            &lifecycle,
            true,
            process_incarnation().unwrap(),
        ))
        .await
        .unwrap();
        store
            .db
            .apply_retirement_index_preparation(&lifecycle, &plan, reviewed.digest())
            .await
            .unwrap();
        assert!(
            store
                .db
                .plan_retirement_index_preparation(&lifecycle)
                .await
                .unwrap()
                .done
        );
        let first = cleanup_record(&store.db, 0, false).await;
        cleanup_record(&store.db, 1, false).await;
        let kept = cleanup_record(&store.db, 2, true).await;
        let reviewed = store
            .db
            .plan_unsupported_codex_cleanup(None, 1)
            .await
            .unwrap();
        assert_eq!(reviewed.examined, 1);
        assert_eq!(reviewed.candidates.len(), 1);
        assert_eq!(
            reviewed.candidates[0].observation_id,
            first.observation_id().as_str()
        );
        assert!(reviewed.candidates[0].retained_reasons.is_empty());
        let cursor =
            serde_json::from_str(&serde_json::to_string(&reviewed.cursor).unwrap()).unwrap();
        drop(store);
        let before_cleanup = std::fs::read(root.join(USER_SESSIONS_DB_FILENAME)).unwrap();
        let read_only = Box::pin(open_existing(
            &root,
            &lifecycle,
            false,
            StoreIncarnationV1::new(2).unwrap(),
        ))
        .await
        .unwrap();
        let remounted = read_only
            .db
            .plan_unsupported_codex_cleanup(Some(&cursor), 1)
            .await
            .unwrap();
        assert_eq!(
            reviewed.plan_digest, remounted.plan_digest,
            "cleanup approval and its bounded cursor must survive a fresh process"
        );
        drop(read_only);
        assert_eq!(
            before_cleanup,
            std::fs::read(root.join(USER_SESSIONS_DB_FILENAME)).unwrap()
        );
        let apply = Box::pin(open_existing(
            &root,
            &lifecycle,
            true,
            StoreIncarnationV1::new(3).unwrap(),
        ))
        .await
        .unwrap();
        assert!(
            apply
                .db
                .apply_unsupported_codex_cleanup(&remounted, "wrong")
                .await
                .is_err()
        );
        assert_eq!(
            apply
                .db
                .apply_unsupported_codex_cleanup(&remounted, &reviewed.plan_digest)
                .await
                .unwrap(),
            1
        );
        let next = apply
            .db
            .plan_unsupported_codex_cleanup(remounted.next_cursor.as_ref(), 1)
            .await
            .unwrap();
        assert_eq!(next.examined, 1);
        assert_eq!(next.cursor.high_water_sequence, 3);
        let remaining = apply
            .db
            .plan_unsupported_codex_cleanup(None, 128)
            .await
            .unwrap();
        assert_eq!(
            remaining.examined, 2,
            "only the reviewed unsupported record is removed"
        );
        assert_eq!(
            remaining.candidates.len(),
            1,
            "supported evidence is not a cleanup candidate"
        );
        assert_eq!(
            apply
                .db
                .observation_store()
                .get_source_cursor(kept.source(), kept.scope())
                .await
                .unwrap()
                .unwrap()
                .position(),
            300
        );
    }

    #[test]
    fn offline_retirement_refuses_daemon_lease_without_stopping_it() {
        let temp = tempfile::tempdir().unwrap();
        let shared = tracedecay_runtime_core::lifecycle_lease::acquire_shared_for_profile(
            temp.path(),
            "daemon",
        )
        .unwrap();
        let refused = acquire_offline(temp.path(), "prepare-retirement-indexes")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("daemon stopped"), "{refused}");
        assert!(shared.guards_profile(temp.path()));
        assert!(acquire_offline(temp.path(), "cleanup-codex").is_err());
        drop(shared);
        assert!(
            acquire_offline(temp.path(), "prepare-retirement-indexes")
                .unwrap()
                .is_exclusive()
        );
    }
}
