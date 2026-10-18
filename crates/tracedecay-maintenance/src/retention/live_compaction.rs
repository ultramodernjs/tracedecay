//! Bounded compaction for stores retained by a live runtime.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracedecay_contracts::storage::compaction::CompactionTriggerPolicyV1;
use tracedecay_contracts::storage::identity::{FreePageRatioV1, StorageByteSizeV1, StoreKeyV1};
use tracedecay_contracts::storage::telemetry::StoreSizeSampleV1;
use tracedecay_domain::UtcMicros;
use tracedecay_global_db::RegisteredGlobalDb;
use tracedecay_runtime_core::db::Database;

use tracedecay_contracts::storage::compaction::CompactionThresholdConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveStoreCompactionFailureV1 {
    StoreSizeSampleFailed,
    InvalidCompactionPolicy,
    IncrementalVacuumFailed,
    PostCompactionSampleFailed,
}

impl LiveStoreCompactionFailureV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreSizeSampleFailed => "store_size_sample_failed",
            Self::InvalidCompactionPolicy => "invalid_compaction_policy",
            Self::IncrementalVacuumFailed => "incremental_vacuum_failed",
            Self::PostCompactionSampleFailed => "post_compaction_sample_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveStoreCompactionOutcomeV1 {
    NotScheduled,
    /// The observed logical database shrank. WAL checkpointing and filesystem
    /// allocation are independent, so this does not claim reclaimed file bytes.
    Compacted {
        page_count_before: u64,
        page_count_after: u64,
        freelist_before: u64,
        freelist_after: u64,
    },
    /// The writer command succeeded without an observed page-count reduction.
    /// SQLite permits this for legacy stores with `auto_vacuum=NONE`, and live
    /// writes can also consume or add pages between the two samples.
    NoProgress {
        page_count_before: u64,
        page_count_after: u64,
        freelist_before: u64,
        freelist_after: u64,
    },
    Failed(LiveStoreCompactionFailureV1),
}

enum RetainedCompactionStore<'a> {
    Registered(&'a RegisteredGlobalDb),
    Project(&'a Database),
}

impl RetainedCompactionStore<'_> {
    async fn storage_page_counts(&self) -> tracedecay_domain::errors::Result<(u64, u64, u64)> {
        match self {
            Self::Registered(database) => database.storage_page_counts().await,
            Self::Project(database) => database.storage_page_counts().await,
        }
    }

    async fn run_bounded_incremental_compaction(
        &self,
        max_pages: u64,
    ) -> tracedecay_domain::errors::Result<()> {
        match self {
            Self::Registered(database) => {
                database.run_bounded_incremental_compaction(max_pages).await
            }
            Self::Project(database) => database.run_incremental_vacuum(max_pages).await,
        }
    }
}

#[tracing::instrument(
    name = "maintenance.live_compaction.registered",
    level = "trace",
    skip_all
)]
pub async fn compact_registered_store(
    database: &RegisteredGlobalDb,
    config: &CompactionThresholdConfig,
) -> LiveStoreCompactionOutcomeV1 {
    compact_store(RetainedCompactionStore::Registered(database), config).await
}

#[tracing::instrument(
    name = "maintenance.live_compaction.project",
    level = "trace",
    skip_all
)]
pub async fn compact_project_store(
    database: &Database,
    config: &CompactionThresholdConfig,
) -> LiveStoreCompactionOutcomeV1 {
    compact_store(RetainedCompactionStore::Project(database), config).await
}

async fn compact_store(
    store: RetainedCompactionStore<'_>,
    config: &CompactionThresholdConfig,
) -> LiveStoreCompactionOutcomeV1 {
    let Ok((page_size, page_count, freelist)) = store.storage_page_counts().await else {
        return LiveStoreCompactionOutcomeV1::Failed(
            LiveStoreCompactionFailureV1::StoreSizeSampleFailed,
        );
    };
    let Ok(scheduled) = compaction_is_scheduled(page_size, page_count, freelist, config) else {
        return LiveStoreCompactionOutcomeV1::Failed(
            LiveStoreCompactionFailureV1::InvalidCompactionPolicy,
        );
    };
    if !scheduled {
        return LiveStoreCompactionOutcomeV1::NotScheduled;
    }
    if store
        .run_bounded_incremental_compaction(u64::from(config.max_pages_per_tick.max(1)))
        .await
        .is_err()
    {
        return LiveStoreCompactionOutcomeV1::Failed(
            LiveStoreCompactionFailureV1::IncrementalVacuumFailed,
        );
    }
    let Ok((page_size_after, page_count_after, freelist_after)) = store.storage_page_counts().await
    else {
        return LiveStoreCompactionOutcomeV1::Failed(
            LiveStoreCompactionFailureV1::PostCompactionSampleFailed,
        );
    };
    if page_size_after != page_size {
        return LiveStoreCompactionOutcomeV1::Failed(
            LiveStoreCompactionFailureV1::PostCompactionSampleFailed,
        );
    }
    if page_count_after >= page_count {
        return LiveStoreCompactionOutcomeV1::NoProgress {
            page_count_before: page_count,
            page_count_after,
            freelist_before: freelist,
            freelist_after,
        };
    }
    LiveStoreCompactionOutcomeV1::Compacted {
        page_count_before: page_count,
        page_count_after,
        freelist_before: freelist,
        freelist_after,
    }
}

fn compaction_is_scheduled(
    page_size: u64,
    page_count: u64,
    freelist: u64,
    config: &CompactionThresholdConfig,
) -> Result<bool, ()> {
    if page_size == 0 || page_count == 0 {
        return Ok(false);
    }
    let observed_at = duration_to_utc_micros(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?,
    )?;
    let sample = store_size_sample_at(page_size, page_count, freelist, observed_at)?;
    let policy = CompactionTriggerPolicyV1 {
        free_page_ratio_threshold: FreePageRatioV1::new(config.free_page_ratio_threshold)
            .map_err(|_| ())?,
        minimum_reclaimable_bytes: StorageByteSizeV1(config.minimum_reclaimable_bytes),
    };
    policy
        .decide(&sample)
        .map(|decision| decision.is_scheduled())
        .map_err(|_| ())
}

fn duration_to_utc_micros(duration: Duration) -> Result<UtcMicros, ()> {
    i64::try_from(duration.as_micros())
        .map(UtcMicros)
        .map_err(|_| ())
}

fn store_size_sample_at(
    page_size: u64,
    page_count: u64,
    freelist: u64,
    observed_at: UtcMicros,
) -> Result<StoreSizeSampleV1, ()> {
    Ok(StoreSizeSampleV1 {
        store: StoreKeyV1::new("store.db").map_err(|_| ())?,
        page_size_bytes: u32::try_from(page_size).map_err(|_| ())?,
        page_count,
        freelist_pages: freelist,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tracedecay_runtime_core::db::{
        DatabaseAuthority, TestDatabaseRuntimeMode, TestDatabaseRuntimeScope,
    };

    use super::*;

    fn config(threshold: f64, minimum_reclaimable_bytes: u64) -> CompactionThresholdConfig {
        CompactionThresholdConfig {
            free_page_ratio_threshold: threshold,
            minimum_reclaimable_bytes,
            max_pages_per_tick: 16,
        }
    }

    fn create_sqlite_fixture(path: &Path, auto_vacuum: &str) {
        let mut connection = rusqlite::Connection::open(path).unwrap();
        connection
            .pragma_update(None, "auto_vacuum", auto_vacuum)
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE compaction_fixture (id INTEGER PRIMARY KEY, body BLOB NOT NULL)",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        for id in 1..=128 {
            transaction
                .execute(
                    "INSERT INTO compaction_fixture (id, body) VALUES (?1, zeroblob(4096))",
                    [id],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        connection
            .execute("DELETE FROM compaction_fixture WHERE id <= 120", [])
            .unwrap();
    }

    async fn attach_fixture(path: &Path, mode: TestDatabaseRuntimeMode) -> Database {
        let authority =
            DatabaseAuthority::acquire_test(path, "live compaction SQLite fixture").unwrap();
        Database::publish_registered_test_runtime(
            path,
            &authority,
            mode,
            TestDatabaseRuntimeScope::Profile,
        )
        .await
        .unwrap()
        .0
    }

    async fn assert_retained_rows(database: &Database) {
        let mut rows = database
            .read_connection()
            .query(
                "SELECT count(*), sum(length(body)) FROM compaction_fixture",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<i64>(0).unwrap(), 8);
        assert_eq!(row.get::<i64>(1).unwrap(), 8 * 4096);
    }

    #[asupersync::test]
    async fn legacy_none_auto_vacuum_reports_no_progress_and_preserves_file_pages() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.db");
        create_sqlite_fixture(&path, "NONE");
        let database = attach_fixture(&path, TestDatabaseRuntimeMode::Existing).await;
        let before = database.storage_page_counts().await.unwrap();
        let file_bytes_before = std::fs::metadata(&path).unwrap().len();
        assert!(before.2 > 16, "the fixture must contain reclaimable pages");

        let outcome = compact_project_store(&database, &config(0.01, 1)).await;

        assert_eq!(
            outcome,
            LiveStoreCompactionOutcomeV1::NoProgress {
                page_count_before: before.1,
                page_count_after: before.1,
                freelist_before: before.2,
                freelist_after: before.2,
            }
        );
        assert_eq!(database.storage_page_counts().await.unwrap(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), file_bytes_before);
        assert_retained_rows(&database).await;
        assert!(crate::compaction_receipt::record_live_compaction_outcome(
            "fixture", outcome
        ));
    }

    #[asupersync::test]
    async fn incremental_auto_vacuum_reports_bounded_observed_page_reduction() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.db");
        create_sqlite_fixture(&path, "INCREMENTAL");
        let database = attach_fixture(&path, TestDatabaseRuntimeMode::Existing).await;
        let before = database.storage_page_counts().await.unwrap();
        assert!(before.2 > 16, "the fixture must contain reclaimable pages");
        let mut policy = config(0.01, 1);
        policy.max_pages_per_tick = 1;

        let outcome = compact_project_store(&database, &policy).await;

        let after = database.storage_page_counts().await.unwrap();
        assert_eq!(after.0, before.0);
        assert_eq!(before.1 - after.1, 1);
        assert_eq!(before.2 - after.2, 1);
        assert_eq!(
            outcome,
            LiveStoreCompactionOutcomeV1::Compacted {
                page_count_before: before.1,
                page_count_after: after.1,
                freelist_before: before.2,
                freelist_after: after.2,
            }
        );
        assert_retained_rows(&database).await;
        assert!(crate::compaction_receipt::record_live_compaction_outcome(
            "fixture", outcome
        ));
    }

    #[asupersync::test]
    async fn read_only_compaction_reports_writer_failure_without_modifying_pages() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.db");
        create_sqlite_fixture(&path, "INCREMENTAL");
        let database = attach_fixture(&path, TestDatabaseRuntimeMode::ReadOnly).await;
        let before = database.storage_page_counts().await.unwrap();
        assert!(before.2 > 16, "the fixture must contain reclaimable pages");

        let outcome = compact_project_store(&database, &config(0.01, 1)).await;

        assert_eq!(
            outcome,
            LiveStoreCompactionOutcomeV1::Failed(
                LiveStoreCompactionFailureV1::IncrementalVacuumFailed,
            )
        );
        assert_eq!(database.storage_page_counts().await.unwrap(), before);
        assert_retained_rows(&database).await;
        assert!(!crate::compaction_receipt::record_live_compaction_outcome(
            "fixture", outcome
        ));
    }

    #[test]
    fn compaction_policy_distinguishes_ineligible_eligible_and_invalid() {
        assert_eq!(
            compaction_is_scheduled(4_096, 100, 50, &config(0.75, 0)),
            Ok(false)
        );
        assert_eq!(
            compaction_is_scheduled(4_096, 100, 50, &config(0.5, 0)),
            Ok(true)
        );
        assert_eq!(
            compaction_is_scheduled(4_096, 100, 50, &config(0.0, 0)),
            Err(())
        );
    }

    #[test]
    fn compaction_clock_conversion_preserves_sub_millisecond_microseconds_and_refuses_overflow() {
        let observed_at =
            duration_to_utc_micros(std::time::Duration::new(1_700_000_000, 123_456_000))
                .expect("unix duration fits");

        assert_eq!(observed_at, UtcMicros(1_700_000_000_123_456));
        assert_eq!(duration_to_utc_micros(std::time::Duration::MAX), Err(()));
    }
}
