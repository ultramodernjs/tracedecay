//! Explicit offline preparation. SQLite builds a native index atomically, so
//! resume granularity is ONE index, not one source row. Bound that indivisible
//! unit before starting it; never spill its sorter to disk. Completed indexes
//! are the durable cursor, including after interruption or process restart.

use super::{
    ANCHOR_REVERSE_INDEXES, EXTERNAL_ANCHOR_KEY, TABLES, hash, require_index, scalar, storage,
};
use crate::RegisteredGlobalDb;
use serde::Serialize;
use tracedecay_runtime_core::db::engine::QueryExecutor;
use tracedecay_runtime_core::lifecycle_lease::LifecycleLease;
use tracedecay_store::{ProjectionStoreError, ProjectionStoreResult};

pub const MAX_PREPARATION_ROWS: u64 = 1_000_000;
pub const MAX_PREPARATION_KEY_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct RetirementIndex {
    pub table: &'static str,
    pub name: String,
    pub key: &'static str,
}

pub(super) fn definitions() -> Vec<RetirementIndex> {
    let mut indexes = Vec::new();
    for &(table, key, _) in TABLES {
        if matches!(
            table,
            "observations"
                | "projection_queue"
                | "session_canonical_body_references"
                | "observation_repository_capture_references"
                | "observation_repository_provenance"
                | "observation_retrieval_anchors"
                | "observation_admission_refusals"
                | "session_temporal_observation_effects"
        ) {
            continue;
        }
        indexes.push(RetirementIndex {
            table,
            name: format!("idx_retirement_{table}"),
            key,
        });
    }
    for &(table, key) in ANCHOR_REVERSE_INDEXES {
        indexes.push(RetirementIndex {
            table,
            name: format!("idx_retirement_{table}_{key}"),
            key,
        });
    }
    indexes.push(RetirementIndex {
        table: "session_occurrences",
        name: "idx_retirement_occurrences".into(),
        key: "source_observation_id",
    });
    indexes.push(RetirementIndex {
        table: "external_source_mutations_v1",
        name: "idx_retirement_external_source_anchor".into(),
        key: EXTERNAL_ANCHOR_KEY,
    });
    indexes
}

#[derive(Clone, Debug, Serialize)]
pub struct RetirementIndexPreparationPlan {
    pub index_name: Option<String>,
    pub table: Option<String>,
    pub rows: u64,
    /// Key bytes plus 24 bytes per entry for row identity/record overhead.
    /// This is a work bound, not a physical-space or peak-RSS prediction.
    pub key_bytes: u64,
    pub done: bool,
    pub max_rows: u64,
    pub max_key_bytes: u64,
    pub within_budget: bool,
    pub digest: String,
    store: String,
}

impl RetirementIndexPreparationPlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn preparation_error(message: impl Into<String>) -> ProjectionStoreError {
    storage(tracedecay_runtime_core::db::engine::Error::InvalidOperation(message.into()))
}

fn require_lease(db: &RegisteredGlobalDb, lease: &LifecycleLease) -> ProjectionStoreResult<()> {
    if !lease.is_exclusive()
        || !db
            .db_path()
            .parent()
            .is_some_and(|profile| lease.guards_profile(profile))
    {
        return Err(preparation_error(
            "retirement index preparation requires the exact exclusive profile lease; stop the daemon first",
        ));
    }
    Ok(())
}

async fn plan_on(
    conn: &impl QueryExecutor,
    store: String,
) -> ProjectionStoreResult<RetirementIndexPreparationPlan> {
    let mut plan = RetirementIndexPreparationPlan {
        index_name: None,
        table: None,
        rows: 0,
        key_bytes: 0,
        done: true,
        max_rows: MAX_PREPARATION_ROWS,
        max_key_bytes: MAX_PREPARATION_KEY_BYTES,
        within_budget: true,
        digest: String::new(),
        store,
    };
    for index in definitions() {
        if scalar(
            conn,
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1)",
            &index.name,
        )
        .await?
            != 0
        {
            // Admission verifies the exact index shape. Do not trust a name alone.
            require_index(conn, index.table, index.key, "").await?;
            continue;
        }
        // No ORDER BY, GROUP BY, DISTINCT or automatic-index join: this bounded
        // preflight cannot construct a whole-store sorter. Never read payloads.
        let mut rows = conn.query(&format!(
            "SELECT count(*), coalesce(sum(coalesce(length(CAST(retirement_key AS BLOB)),0)+24),0) FROM (SELECT {} AS retirement_key FROM {} LIMIT {})",
            index.key, index.table, MAX_PREPARATION_ROWS + 1), ()).await.map_err(storage)?;
        let row = rows
            .next()
            .await
            .map_err(storage)?
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        plan.rows = row.get(0).map_err(storage)?;
        plan.key_bytes = row.get(1).map_err(storage)?;
        plan.index_name = Some(index.name);
        plan.table = Some(index.table.into());
        plan.done = false;
        plan.within_budget =
            plan.rows <= MAX_PREPARATION_ROWS && plan.key_bytes <= MAX_PREPARATION_KEY_BYTES;
        break;
    }
    plan.digest = hash(&("retirement-index-preparation.v1", &plan))?;
    Ok(plan)
}

impl RegisteredGlobalDb {
    /// Review just the next missing index. No DDL, migrations or marker writes.
    pub async fn plan_retirement_index_preparation(
        &self,
        lease: &LifecycleLease,
    ) -> ProjectionStoreResult<RetirementIndexPreparationPlan> {
        require_lease(self, lease)?;
        let read = self.read_snapshot().await.map_err(storage)?;
        plan_on(&read, hash(&self.retirement_store_identity())?).await
    }

    /// Build at most one native index, transactionally, under a retained offline
    /// lease. Interrupted builds roll back only this index; rerun the dry-run.
    pub async fn apply_retirement_index_preparation(
        &self,
        lease: &LifecycleLease,
        plan: &RetirementIndexPreparationPlan,
        confirmed_digest: &str,
    ) -> ProjectionStoreResult<()> {
        require_lease(self, lease)?;
        if plan.digest != confirmed_digest || plan.store != hash(&self.retirement_store_identity())?
        {
            return Err(preparation_error(
                "index preparation digest/store changed; run dry-run again",
            ));
        }
        if !plan.within_budget {
            return Err(preparation_error(
                "native index exceeds the offline row/key-byte bound; no index built",
            ));
        }
        self.require_active_write_scope("prepare retirement indexes")
            .map_err(storage)?;
        // Connection-local only, through the authorized retained writer. This
        // setting never touches persisted database content or startup defaults.
        self.writer_connection()
            .map_err(storage)?
            .execute_batch("PRAGMA temp_store=MEMORY;")
            .await
            .map_err(storage)?;
        let tx = self.begin_write_transaction().await.map_err(storage)?;
        let current = plan_on(&tx, plan.store.clone()).await?;
        if current.digest != confirmed_digest {
            return Err(preparation_error(
                "index preparation changed; run dry-run again",
            ));
        }
        if let Some(name) = current.index_name {
            let index = definitions()
                .into_iter()
                .find(|index| index.name == name)
                .ok_or(ProjectionStoreError::ProvenanceCollision)?;
            tx.execute_batch(&format!(
                "CREATE INDEX {} ON {}({});",
                index.name, index.table, index.key
            ))
            .await
            .map_err(storage)?;
            require_index(&tx, index.table, index.key, "").await?;
        }
        tx.commit().await.map_err(storage)?;
        Ok(())
    }
}
