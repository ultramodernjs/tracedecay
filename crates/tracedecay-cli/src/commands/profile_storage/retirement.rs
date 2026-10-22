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

async fn open_existing(
    profile_root: &Path,
    lifecycle: &LifecycleLease,
    writable: bool,
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
    let generation = tracedecay_store_runtime::process_runtime_generation(
        tracedecay_runtime_core::runtime_identity::process_run_id(),
    )
    .ok_or_else(|| error("unsupported process runtime identity"))?;
    let incarnation = StoreIncarnationV1::new(generation).map_err(error)?;
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
    let store = Box::pin(open_existing(&profile_root, &lifecycle, apply.is_some())).await?;
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

#[cfg(test)]
mod tests {
    use super::{acquire_offline, open_existing};
    use tracedecay_global_db::RegisteredGlobalDbOwnerV1;
    use tracedecay_runtime_core::config::GLOBAL_DB_FILENAME;
    use tracedecay_runtime_core::db::{
        Database, DatabaseAuthority, TestDatabaseRuntimeMode, TestDatabaseRuntimeScope,
        TestRuntimeProfileIdentityV1,
    };
    use tracedecay_runtime_core::storage::USER_SESSIONS_DB_FILENAME;
    use tracedecay_store::StoreIncarnationV1;

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
        let store = Box::pin(open_existing(&root, &lifecycle, false))
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
        let store = Box::pin(open_existing(&root, &lifecycle, true))
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
