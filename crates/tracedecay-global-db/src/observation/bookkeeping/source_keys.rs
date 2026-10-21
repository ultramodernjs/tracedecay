//! Fixed-size source identities, with dual reads until explicit convergence.

use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1, canonical_sha256};
use tracedecay_runtime_core::db::engine::{Executor, params};
use tracedecay_store::{ProjectionStoreError, ProjectionStoreResult};

pub(crate) const SOURCE_DESCRIPTOR_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS observation_source_descriptors (
    source_key TEXT PRIMARY KEY NOT NULL,
    descriptor_json TEXT NOT NULL CHECK(json_valid(descriptor_json))
) WITHOUT ROWID;";

pub(crate) struct SourceKey {
    pub(crate) compact: String,
    pub(crate) legacy: String,
}

impl SourceKey {
    pub(crate) fn new(
        source: &ObservationSourceIdentityV1,
        scope: &ObservationScopeV1,
    ) -> ProjectionStoreResult<Self> {
        let legacy = serde_json::to_string(&(source, scope))
            .map_err(|error| ProjectionStoreError::storage("encode source descriptor", error))?;
        let compact = canonical_sha256(&("tracedecay.observation-source-key.v1", &legacy))
            .map_err(|error| ProjectionStoreError::storage("digest source descriptor", error))?
            .as_str()
            .to_owned();
        Ok(Self { compact, legacy })
    }

    pub(crate) async fn ensure_descriptor(
        &self,
        conn: &impl Executor,
    ) -> ProjectionStoreResult<()> {
        conn.execute("INSERT INTO observation_source_descriptors(source_key, descriptor_json) VALUES (?1, ?2) ON CONFLICT(source_key) DO NOTHING", params![self.compact.as_str(), self.legacy.as_str()])
            .await.map_err(|error| ProjectionStoreError::storage("persist source descriptor", error))?;
        let mut rows = conn
            .query(
                "SELECT descriptor_json FROM observation_source_descriptors WHERE source_key = ?1",
                params![self.compact.as_str()],
            )
            .await
            .map_err(|error| ProjectionStoreError::storage("check source descriptor", error))?;
        let row = rows
            .next()
            .await
            .map_err(|error| ProjectionStoreError::storage("check source descriptor", error))?
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        let stored: String = row
            .get(0)
            .map_err(|error| ProjectionStoreError::storage("check source descriptor", error))?;
        if stored != self.legacy {
            return Err(ProjectionStoreError::ProvenanceCollision);
        }
        Ok(())
    }
}
