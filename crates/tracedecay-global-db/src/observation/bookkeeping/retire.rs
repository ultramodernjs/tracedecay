//! Registered observation retirement; apply owns the writer transaction.
//!
//! Sequence deletion is currently disabled: all existing observations report
//! `ProjectionSequenceCoverageUnavailable` until every projection/rebuild
//! consumer understands durable retirement coverage. Planning remains read-only;
//! confirmed apply defers before any marker, deletion or disposition mutation.
//! Canonical-body compressed bytes and expanded references share the 8-MiB batch
//! budget with selected column bytes and are preflighted before hydration.
//!
//! Public entry points (no caller transaction / nested transaction):
//! ```ignore
//! RegisteredGlobalDb::plan_observation_retirement(&self, ids: &[CanonicalObservationIdV1],
//!     authorization: ObservationRetirementAuthorization) -> ProjectionStoreResult<ObservationRetirementPlan>
//! RegisteredGlobalDb::apply_observation_retirement(&self, plan: &ObservationRetirementPlan,
//!     confirmed_digest: &str) -> ProjectionStoreResult<ObservationRetirementOutcome>
//! RegisteredGlobalDb::apply_observation_retirement_with_handoff(&self,
//!     plan: &ObservationRetirementPlan, confirmed_digest: &str,
//!     validator: &impl HandoffProofValidator) -> ProjectionStoreResult<ObservationRetirementOutcome>
//! ```
//! Handoff validators MUST hold the target retention/writer fence until apply
//! returns, including source COMMIT. Validation is called inside the source
//! writer transaction. An unfenced target snapshot is not a copy proof.
//!
//! Plans count logical column bytes, not SQLite/APFS space. Shared receipts,
//! anchor/disposition identities, captures and canonical bodies are retained;
//! their established owner-aware collectors remain authoritative. Remote chains,
//! external journals, rebuilds and materialized temporal occurrences defer the
//! entire batch rather than release an incompletely understood dependency.

mod hydration;

use std::collections::BTreeSet;
use std::future::Future;

use serde::Serialize;
use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationIdV1, DurableObservationV1,
    ObservationScopeV1, ObservationSourceIdentityV1, canonical_sha256,
};
use tracedecay_runtime_core::db::engine::{Executor, QueryExecutor, Value, params};
use tracedecay_store::{
    ObservationProjection, ProjectionSkipReason, ProjectionStoreError, ProjectionStoreResult,
    codex_observation_policy::unsupported_codex_record, derive_canonical_projection,
};

use crate::RegisteredGlobalDb;

const MAX_IDS: usize = 128;
const MAX_ROWS: usize = 4096;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const OPERATION: &str = "retire observation bookkeeping";
const RECEIPT_PREFIX: &str = "observation-retirement.v1.applied.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ObservationRetirementReason {
    UnsupportedCodexRecord,
    OperatorProjectPrune,
    CrossStoreOwnerHandoff,
    LifecycleRetention,
}

/// Same typed document and key derivation consumed by profile-session exclusion
/// admission. `approved_plan_digest` is B5's independently reviewed selection.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectPruneMarker {
    pub source: ObservationSourceIdentityV1,
    pub scope: ObservationScopeV1,
    pub approved_plan_digest: String,
}

impl ProjectPruneMarker {
    pub fn metadata(&self) -> ProjectionStoreResult<(String, String)> {
        let identity = serde_json::to_string(&(&self.source, &self.scope)).map_err(storage)?;
        let key = format!(
            "profile-project-prune.v1.source.{}",
            tracedecay_domain::canonical_text::sha256_hex(identity.as_bytes())
        );
        let value = serde_json::to_string(&serde_json::json!({
            "version": 1, "source": self.source, "scope": self.scope,
            "plan_digest": self.approved_plan_digest,
        }))
        .map_err(storage)?;
        Ok((key, value))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetCopyProof {
    pub target_store_identity: String,
    pub target_incarnation: String,
    pub retention_fence: String,
    pub copies: Vec<TargetObservationCopy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetObservationCopy {
    pub source_observation_id: CanonicalObservationIdV1,
    pub target_observation_id: CanonicalObservationIdV1,
    pub payload_digest: String,
}

#[derive(Clone, Debug, Serialize)]
pub enum ObservationRetirementAuthorization {
    UnsupportedCodexRecord,
    OperatorProjectPrune(ProjectPruneMarker),
    CrossStoreOwnerHandoff(TargetCopyProof),
    /// Already terminal anchor dispositions only; never implicit age-based loss.
    LifecycleRetention,
}

impl ObservationRetirementAuthorization {
    pub fn reason(&self) -> ObservationRetirementReason {
        match self {
            Self::UnsupportedCodexRecord => ObservationRetirementReason::UnsupportedCodexRecord,
            Self::OperatorProjectPrune(_) => ObservationRetirementReason::OperatorProjectPrune,
            Self::CrossStoreOwnerHandoff(_) => ObservationRetirementReason::CrossStoreOwnerHandoff,
            Self::LifecycleRetention => ObservationRetirementReason::LifecycleRetention,
        }
    }
}

/// Implementations own a target lease/fence for their entire lifetime. Returning
/// `Verified` promises that every named copy is durable and cannot be retired
/// until the source transaction has settled. Never acquire source writer again.
pub trait HandoffProofValidator: Sync {
    fn validate<'a>(
        &'a self,
        proof: &'a TargetCopyProof,
    ) -> impl Future<Output = ProjectionStoreResult<HandoffProofStatus>> + Send + 'a;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffProofStatus {
    Verified,
    Deferred,
}

struct NoHandoff;
impl HandoffProofValidator for NoHandoff {
    async fn validate(
        &self,
        _proof: &TargetCopyProof,
    ) -> ProjectionStoreResult<HandoffProofStatus> {
        Ok(HandoffProofStatus::Deferred)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetirementTableSize {
    pub table: String,
    pub rows: u64,
    /// Logical stored column bytes; excludes B-tree and WAL allocation.
    pub bytes: u64,
    /// Shared or journal rows reported for visibility, never cascade-deleted.
    pub retained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RetirementBlocker {
    MissingObservation,
    UnsupportedClassifierChanged,
    RemoteChain,
    ExternalJournal,
    ProjectionRebuild,
    TemporalOccurrences,
    LiveAnchor,
    MarkerConflict,
    LegalHold,
    SourceFrontier,
    RetainedAnchorDerivative,
    /// Projection, rejection and rebuild consumers still require a contiguous
    /// observation stream. Never delete a sequence until they all understand
    /// transactionally persisted retirement coverage.
    ProjectionSequenceCoverageUnavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetirementCandidate {
    pub observation_id: CanonicalObservationIdV1,
    pub payload_digest: String,
    pub blockers: Vec<RetirementBlocker>,
}

#[derive(Clone, Debug, Serialize)]
struct RetirementAnchor {
    anchor_id: tracedecay_domain::RetrievalAnchorId,
    owner: tracedecay_domain::FactOwnerV1,
    state: Option<tracedecay_store::AnchorDispositionStateV1>,
}

#[derive(Clone, Debug, Serialize)]
struct RetirementCoverage {
    source_json: String,
    scope_json: String,
    coverage_json: String,
    receipt_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationRetirementPlan {
    ids: Vec<CanonicalObservationIdV1>,
    authorization: ObservationRetirementAuthorization,
    store: String,
    candidates: Vec<RetirementCandidate>,
    tables: Vec<RetirementTableSize>,
    evidence: Vec<String>,
    guards: Vec<(String, String)>,
    coverage: Vec<RetirementCoverage>,
    anchors: Vec<RetirementAnchor>,
    digest: String,
}

impl ObservationRetirementPlan {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn tables(&self) -> &[RetirementTableSize] {
        &self.tables
    }
    pub fn candidates(&self) -> &[RetirementCandidate] {
        &self.candidates
    }
    pub fn reason(&self) -> ObservationRetirementReason {
        self.authorization.reason()
    }
    pub fn eligible(&self) -> bool {
        self.candidates.iter().all(|row| row.blockers.is_empty())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationRetirementOutcome {
    Applied { observations: usize },
    AlreadyApplied,
    Deferred,
}

// Child-first closure, including all twelve per-observation authority families,
// staging families, and rebuildable shared-resource owner maps. Shared resources
// themselves deliberately are not deleted by an observation ID.
const TABLES: &[(&str, &str, &str)] = &[
    (
        "observation_projection_rebuild_provenance",
        "observation_id",
        "",
    ),
    (
        "observation_projection_rebuild_dispositions",
        "observation_id",
        "",
    ),
    (
        "observation_projection_rebuild_aliases",
        "observation_id",
        "",
    ),
    (
        "observation_projection_rebuild_workflow_facts",
        "observation_id",
        "",
    ),
    (
        "observation_projection_rebuild_provider_usage",
        "observation_id",
        "",
    ),
    ("session_temporal_observation_effects", "observation_id", ""),
    ("observation_projection_provenance", "observation_id", ""),
    ("observation_projection_aliases", "observation_id", ""),
    ("observation_projection_dispositions", "observation_id", ""),
    ("observation_workflow_facts", "observation_id", ""),
    ("observation_provider_usage", "observation_id", ""),
    ("projection_queue", "observation_id", ""),
    ("observation_admission_refusals", "observation_id", ""),
    ("observation_source_presence", "observation_id", ""),
    (
        "observation_repository_capture_references",
        "observation_id",
        "",
    ),
    (
        "session_canonical_body_references",
        "owner_key",
        " AND owner_kind = 'observation'",
    ),
    ("observation_repository_provenance", "observation_id", ""),
    ("observation_retrieval_anchors", "observation_id", ""),
    ("observations", "observation_id", ""),
];

const ANCHOR_REVERSE_INDEXES: &[(&str, &str)] = &[
    ("session_assertions", "subject_anchor_id"),
    ("session_assertions", "object_anchor_id"),
    ("session_derived_evidence", "retrieval_anchor_id"),
    ("session_occurrences", "retrieval_anchor_id"),
    ("session_summary_nodes", "summary_anchor_id"),
    ("retrieval_anchor_dispositions", "superseded_by"),
    ("observation_projection_provenance", "retrieval_anchor_id"),
    ("observation_workflow_facts", "retrieval_anchor_id"),
];

// Slim and legacy mutation encodings both retain this evidence identity.
const EXTERNAL_ANCHOR_KEY: &str = "json_extract(mutation_json, '$.evidence.retrieval_anchor')";
const EXTERNAL_TABLES: &[&str] = &[
    "external_source_mutations_v1",
    "external_source_commit_receipts_v2",
    "external_source_objects_v2",
    "external_source_projected_objects_v2",
    "external_source_retained_receipts_v1",
    "external_source_pending_projections_v1",
    "external_source_projection_publications_v2",
];

const GUARDS: &[&str] = &[
    "observations_immutable_delete",
    "observation_retrieval_anchors_immutable_delete",
    "observation_repository_provenance_immutable_delete",
    "observation_admission_refusals_immutable_delete",
    "observation_provider_usage_no_delete",
    "session_temporal_observation_effects_immutable_delete_v1",
];

/// Installed only on empty tables during admission, never by a dry-run or
/// apply. Populated stores require explicit index preparation while offline;
/// missing reverse indexes refuse retirement rather than scan the live store.
pub(crate) async fn install_indexes(
    conn: &impl Executor,
) -> tracedecay_runtime_core::db::engine::Result<()> {
    for (table, key, _) in TABLES {
        if matches!(
            *table,
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
        install_empty_table_index(conn, table, &format!("idx_retirement_{table}"), key).await?;
    }
    for (table, column) in ANCHOR_REVERSE_INDEXES {
        install_empty_table_index(
            conn,
            table,
            &format!("idx_retirement_{table}_{column}"),
            column,
        )
        .await?;
    }
    install_empty_table_index(
        conn,
        "session_occurrences",
        "idx_retirement_occurrences",
        "source_observation_id",
    )
    .await?;
    install_empty_table_index(
        conn,
        "external_source_mutations_v1",
        "idx_retirement_external_source_anchor",
        EXTERNAL_ANCHOR_KEY,
    )
    .await
}

async fn install_empty_table_index(
    conn: &impl Executor,
    table: &str,
    name: &str,
    key: &str,
) -> tracedecay_runtime_core::db::engine::Result<()> {
    let mut rows = conn
        .query(&format!("SELECT 1 FROM {table} LIMIT 1"), ())
        .await?;
    let empty = rows.next().await?.is_none();
    drop(rows);
    if empty {
        conn.execute_batch(&format!(
            "CREATE INDEX IF NOT EXISTS {name} ON {table}({key});"
        ))
        .await?;
    }
    Ok(())
}

fn storage(error: impl std::error::Error + Send + Sync + 'static) -> ProjectionStoreError {
    ProjectionStoreError::storage(OPERATION, error)
}
fn refused<T>() -> ProjectionStoreResult<T> {
    Err(ProjectionStoreError::ProvenanceCollision)
}
fn hash(value: &impl Serialize) -> ProjectionStoreResult<String> {
    Ok(canonical_sha256(value)
        .map_err(storage)?
        .as_str()
        .to_owned())
}

async fn scalar(conn: &impl QueryExecutor, sql: &str, id: &str) -> ProjectionStoreResult<i64> {
    let mut rows = conn.query(sql, params![id]).await.map_err(storage)?;
    rows.next()
        .await
        .map_err(storage)?
        .ok_or(ProjectionStoreError::ProvenanceCollision)?
        .get(0)
        .map_err(storage)
}

async fn read_guards(conn: &impl QueryExecutor) -> ProjectionStoreResult<Vec<(String, String)>> {
    let mut guards = Vec::new();
    for name in GUARDS {
        let mut rows = conn
            .query(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                params![*name],
            )
            .await
            .map_err(storage)?;
        let row = rows
            .next()
            .await
            .map_err(storage)?
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        guards.push(((*name).to_owned(), row.get(0).map_err(storage)?));
    }
    Ok(guards)
}

// Probe the query plan before fetching data: missing reverse indexes must refuse,
// not turn a bounded batch into N whole-store scans. A per-ID sort is bounded by
// the row cap below and never sorts a whole source/session.
async fn require_index(
    conn: &impl QueryExecutor,
    table: &str,
    key: &str,
    extra: &str,
) -> ProjectionStoreResult<()> {
    let mut versions = conn
        .query("PRAGMA schema_version", ())
        .await
        .map_err(storage)?;
    let schema: i64 = versions
        .next()
        .await
        .map_err(storage)?
        .ok_or(ProjectionStoreError::ProvenanceCollision)?
        .get(0)
        .map_err(storage)?;
    drop(versions);
    let mut rows = conn
        .query(
            &format!("EXPLAIN QUERY PLAN SELECT * FROM {table} WHERE {key}=?1{extra} LIMIT 1 /* schema {schema} */"),
            params![""],
        )
        .await
        .map_err(storage)?;
    let mut indexed = false;
    while let Some(row) = rows.next().await.map_err(storage)? {
        let detail: String = row.get(3).map_err(storage)?;
        if detail.starts_with("SCAN ") || detail.contains("AUTOMATIC") || detail.contains("ANY(") {
            return refused();
        }
        indexed |= detail.starts_with("SEARCH ");
    }
    if !indexed {
        return refused();
    }
    Ok(())
}

async fn retained_anchor_consumers(
    conn: &impl QueryExecutor,
    anchor_id: &str,
    selected: &[CanonicalObservationIdV1],
) -> ProjectionStoreResult<bool> {
    for (table, column) in ANCHOR_REVERSE_INDEXES {
        require_index(conn, table, column, "").await?;
        if matches!(
            *table,
            "observation_projection_provenance" | "observation_workflow_facts"
        ) {
            let mut rows = conn
                .query(
                    &format!(
                        "SELECT observation_id FROM {table} WHERE {column}=?1 LIMIT {}",
                        MAX_ROWS + 1
                    ),
                    params![anchor_id],
                )
                .await
                .map_err(storage)?;
            let mut count = 0;
            while let Some(row) = rows.next().await.map_err(storage)? {
                count += 1;
                let id: String = row.get(0).map_err(storage)?;
                if count > MAX_ROWS || !selected.iter().any(|candidate| candidate.as_str() == id) {
                    return Ok(true);
                }
            }
        } else if scalar(
            conn,
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {column}=?1)"),
            anchor_id,
        )
        .await?
            != 0
        {
            return Ok(true);
        }
    }
    for (table, column) in [
        ("observation_retrieval_anchors", "anchor_id"),
        ("observation_repository_provenance", "retrieval_anchor_id"),
    ] {
        let mut rows = conn
            .query(
                &format!("SELECT observation_id FROM {table} WHERE {column}=?1 LIMIT 2"),
                params![anchor_id],
            )
            .await
            .map_err(storage)?;
        while let Some(row) = rows.next().await.map_err(storage)? {
            let id: String = row.get(0).map_err(storage)?;
            if !selected.iter().any(|candidate| candidate.as_str() == id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// Reverse lookup, not a store-wide receipt probe: other bindings cannot pin
// this candidate. History remains authoritative even after a receipt is slimmed
// or superseded, so any surviving mutation consumer protects its anchor.
async fn external_anchor_bindings(
    conn: &impl QueryExecutor,
    anchor_id: &str,
    bindings: &mut BTreeSet<String>,
) -> ProjectionStoreResult<bool> {
    require_index(
        conn,
        "external_source_mutations_v1",
        EXTERNAL_ANCHOR_KEY,
        "",
    )
    .await?;
    let mut rows = conn.query(
        &format!("SELECT binding_id FROM external_source_mutations_v1 WHERE {EXTERNAL_ANCHOR_KEY}=?1 LIMIT {}", MAX_ROWS + 1),
        params![anchor_id],
    ).await.map_err(storage)?;
    let mut count = 0;
    while let Some(row) = rows.next().await.map_err(storage)? {
        count += 1;
        if count > MAX_ROWS {
            return refused();
        }
        bindings.insert(row.get(0).map_err(storage)?);
    }
    Ok(count != 0)
}

#[derive(Default)]
struct CaptureBudget {
    rows: usize,
    bytes: u64,
}

async fn capture_table(
    conn: &impl QueryExecutor,
    table: &str,
    key: &str,
    extra: &str,
    ids: &[String],
    evidence: &mut Vec<String>,
    budget: &mut CaptureBudget,
) -> ProjectionStoreResult<RetirementTableSize> {
    require_index(conn, table, key, extra).await?;
    let mut info = conn
        .query(&format!("PRAGMA table_info({table})"), ())
        .await
        .map_err(storage)?;
    let mut columns = Vec::new();
    while let Some(row) = info.next().await.map_err(storage)? {
        columns.push(row.get::<String>(1).map_err(storage)?);
    }
    drop(info);
    if columns.is_empty() {
        return refused();
    }
    let expression = columns.iter().map(|name| format!("CASE typeof(\"{name}\") WHEN 'null' THEN 0 WHEN 'integer' THEN 8 WHEN 'real' THEN 8 ELSE length(CAST(\"{name}\" AS BLOB)) END")).collect::<Vec<_>>().join("+");
    let mut size = RetirementTableSize {
        table: table.into(),
        rows: 0,
        bytes: 0,
        retained: false,
    };
    for id in ids {
        // Size before materialization; even a single oversized row fails closed.
        let mut sizes = conn
            .query(
                &format!(
                    "SELECT {expression} FROM {table} WHERE {key}=?1{extra} LIMIT {}",
                    MAX_ROWS + 1
                ),
                params![id.as_str()],
            )
            .await
            .map_err(storage)?;
        let mut count = 0;
        let mut bytes = 0_u64;
        while let Some(row) = sizes.next().await.map_err(storage)? {
            count += 1;
            bytes = bytes
                .checked_add(row.get::<u64>(0).map_err(storage)?)
                .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        }
        drop(sizes);
        budget.rows += count;
        budget.bytes = budget
            .bytes
            .checked_add(bytes)
            .ok_or(ProjectionStoreError::ProvenanceCollision)?;
        if budget.rows > MAX_ROWS || budget.bytes > MAX_BYTES {
            return refused();
        }
        let mut rows = conn
            .query(
                &format!(
                    "SELECT * FROM {table} WHERE {key}=?1{extra} LIMIT {}",
                    MAX_ROWS + 1
                ),
                params![id.as_str()],
            )
            .await
            .map_err(storage)?;
        let width = rows.column_count();
        let mut encoded = Vec::new();
        while let Some(row) = rows.next().await.map_err(storage)? {
            let mut values = Vec::new();
            for index in 0..width {
                values.push(match row.get::<Value>(index).map_err(storage)? {
                    Value::Null => serde_json::json!(["null"]),
                    Value::Integer(value) => serde_json::json!(["integer", value]),
                    Value::Real(value) => serde_json::json!(["real", value.to_bits()]),
                    Value::Text(value) => serde_json::json!(["text", value]),
                    Value::Blob(value) => serde_json::json!(["blob", value]),
                });
            }
            encoded.push(hash(&values)?);
        }
        encoded.sort();
        evidence.push(hash(&(table, id.as_str(), encoded))?);
        size.rows += count as u64;
        size.bytes += bytes;
    }
    Ok(size)
}

async fn plan_on(
    conn: &impl QueryExecutor,
    store: String,
    ids: Vec<CanonicalObservationIdV1>,
    authorization: ObservationRetirementAuthorization,
) -> ProjectionStoreResult<ObservationRetirementPlan> {
    if ids.is_empty() || ids.len() > MAX_IDS {
        return refused();
    }
    if ids
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return refused();
    }
    let guards = read_guards(conn).await?;
    let mut plan = ObservationRetirementPlan {
        ids,
        authorization,
        store,
        candidates: Vec::new(),
        tables: Vec::new(),
        evidence: Vec::new(),
        guards,
        digest: String::new(),
        coverage: Vec::new(),
        anchors: Vec::new(),
    };
    let mut budget = CaptureBudget::default();
    let ids = plan
        .ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut receipt_ids = BTreeSet::new();
    let mut external_bindings = BTreeSet::new();
    for (table, key, extra) in TABLES {
        plan.tables.push(
            capture_table(
                conn,
                table,
                key,
                extra,
                &ids,
                &mut plan.evidence,
                &mut budget,
            )
            .await?,
        );
    }
    let rebuild = scalar(
        conn,
        "SELECT EXISTS(SELECT 1 FROM observation_projection_rebuilds) WHERE ?1 IS NOT NULL",
        "",
    )
    .await?
        != 0;
    for id in &plan.ids {
        let mut rows = conn
            .query(
                "SELECT observation_json, payload_digest, committed_cursor_json, receipt_id FROM observations WHERE observation_id=?1",
                params![id.as_str()],
            )
            .await
            .map_err(storage)?;
        let Some(row) = rows.next().await.map_err(storage)? else {
            plan.candidates.push(RetirementCandidate {
                observation_id: id.clone(),
                payload_digest: String::new(),
                blockers: vec![RetirementBlocker::MissingObservation],
            });
            continue;
        };
        let json: String = row.get(0).map_err(storage)?;
        let payload_digest: String = row.get(1).map_err(storage)?;
        let committed_cursor: String = row.get(2).map_err(storage)?;
        let receipt_id: String = row.get(3).map_err(storage)?;
        receipt_ids.insert(receipt_id.clone());
        drop(rows);
        let mut blockers = Vec::new();
        let cursor: tracedecay_domain::ObservationSourceCursorV1 =
            serde_json::from_str(&committed_cursor).map_err(storage)?;
        let source_json = serde_json::to_string(cursor.source()).map_err(storage)?;
        let scope_json = serde_json::to_string(cursor.scope()).map_err(storage)?;
        let mut frontiers = conn
            .query(
                "SELECT cursor_json FROM source_cursors WHERE source_json=?1 AND scope_json=?2",
                params![source_json.as_str(), scope_json.as_str()],
            )
            .await
            .map_err(storage)?;
        let frontier = frontiers
            .next()
            .await
            .map_err(storage)?
            .map(|row| row.get::<String>(0).map_err(storage))
            .transpose()?;
        plan.evidence.push(hash(&(id.as_str(), &frontier))?);
        drop(frontiers);
        let mut anchors = conn.query("SELECT a.anchor_id, a.anchor_json, (SELECT record_json FROM retrieval_anchor_dispositions d WHERE d.anchor_id=a.anchor_id AND d.owner_json=a.owner_json ORDER BY sequence DESC LIMIT 1), (SELECT reason_class FROM retrieval_anchor_dispositions d WHERE d.anchor_id=a.anchor_id AND d.owner_json=a.owner_json ORDER BY sequence DESC LIMIT 1), a.owner_json, (SELECT state FROM retrieval_anchor_dispositions d WHERE d.anchor_id=a.anchor_id AND d.owner_json=a.owner_json ORDER BY sequence DESC LIMIT 1) FROM retrieval_anchors a WHERE a.anchor_id IN (SELECT anchor_id FROM observation_retrieval_anchors WHERE observation_id=?1 UNION SELECT retrieval_anchor_id FROM observation_repository_provenance WHERE observation_id=?1 AND retrieval_anchor_id IS NOT NULL) ORDER BY a.anchor_id", params![id.as_str()]).await.map_err(storage)?;
        while let Some(anchor) = anchors.next().await.map_err(storage)? {
            let anchor_id: String = anchor.get(0).map_err(storage)?;
            let anchor_json: String = anchor.get(1).map_err(storage)?;
            let disposition: Option<String> = anchor.get(2).map_err(storage)?;
            let reason: Option<String> = anchor.get(3).map_err(storage)?;
            plan.evidence
                .push(hash(&(&anchor_id, anchor_json, disposition, &reason))?);
            if reason.as_deref() == Some("legal_hold") {
                blockers.push(RetirementBlocker::LegalHold);
            }
            if scalar(conn, "SELECT EXISTS(SELECT 1 FROM retrieval_anchor_reverse_lineage WHERE source_anchor_id=?1)", &anchor_id).await? != 0 {
                blockers.push(RetirementBlocker::RetainedAnchorDerivative);
            }
            if retained_anchor_consumers(conn, &anchor_id, &plan.ids).await? {
                blockers.push(RetirementBlocker::RetainedAnchorDerivative);
            }
            if external_anchor_bindings(conn, &anchor_id, &mut external_bindings).await? {
                blockers.push(RetirementBlocker::ExternalJournal);
            }
            plan.anchors.push(RetirementAnchor {
                anchor_id: tracedecay_domain::RetrievalAnchorId::new(anchor_id).map_err(storage)?,
                owner: serde_json::from_str(&anchor.get::<String>(4).map_err(storage)?)
                    .map_err(storage)?,
                state: anchor
                    .get::<Option<String>>(5)
                    .map_err(storage)?
                    .map(|value| {
                        tracedecay_store::AnchorDispositionStateV1::parse(&value).map_err(storage)
                    })
                    .transpose()?,
            });
        }
        drop(anchors);
        if rebuild {
            blockers.push(RetirementBlocker::ProjectionRebuild);
        }
        if scalar(
            conn,
            "SELECT EXISTS(SELECT 1 FROM remote_observation_events WHERE observation_id=?1)",
            id.as_str(),
        )
        .await?
            != 0
        {
            blockers.push(RetirementBlocker::RemoteChain);
        }
        require_index(conn, "session_occurrences", "source_observation_id", "").await?;
        if scalar(conn, "SELECT EXISTS(SELECT 1 FROM session_occurrences WHERE source_observation_id=?1)", id.as_str()).await? != 0
            || scalar(conn, "SELECT EXISTS(SELECT 1 FROM session_temporal_observation_effects WHERE observation_id=?1 AND output_count>0)", id.as_str()).await? != 0 {
            blockers.push(RetirementBlocker::TemporalOccurrences);
        }
        // The stored JSON can be tiny while its referenced strings expand far
        // beyond the batch limit. Charge compressed reads and every expansion
        // before any authorization decoder can fetch or inflate a body.
        hydration::preflight(conn, &json, &mut plan.evidence, &mut budget).await?;
        match &plan.authorization {
            ObservationRetirementAuthorization::LifecycleRetention => {
                if frontier.as_deref() == Some(committed_cursor.as_str()) {
                    blockers.push(RetirementBlocker::SourceFrontier);
                }
                // Includes repository anchors. Unavailable, redacted and active
                // evidence is protected. Released JSON need not be decoded.
                let live = scalar(conn, "SELECT EXISTS(
                    SELECT 1 FROM retrieval_anchors a WHERE a.anchor_id IN (
                        SELECT anchor_id FROM observation_retrieval_anchors WHERE observation_id=?1
                        UNION SELECT retrieval_anchor_id FROM observation_repository_provenance WHERE observation_id=?1 AND retrieval_anchor_id IS NOT NULL)
                    AND COALESCE((SELECT state FROM retrieval_anchor_dispositions d WHERE d.anchor_id=a.anchor_id AND d.owner_json=a.owner_json ORDER BY sequence DESC LIMIT 1), 'active') NOT IN ('superseded','deleted','expired'))", id.as_str()).await?;
                if live != 0 {
                    blockers.push(RetirementBlocker::LiveAnchor);
                }
            }
            authorization if blockers.is_empty() => {
                let observation: DurableObservationV1 =
                    super::super::decode_observation_json(conn, &json, OPERATION)
                        .await
                        .map_err(storage)?;
                if observation.observation_id() != id
                    || observation.payload_reference().digest().as_str() != payload_digest
                {
                    return refused();
                }
                if frontier.as_deref() == Some(committed_cursor.as_str()) {
                    plan.coverage.push(RetirementCoverage {
                        source_json,
                        scope_json,
                        coverage_json: serde_json::to_string(
                            &tracedecay_store::ObservationCoverageV1::new(
                                observation.identity().generation(),
                                observation.identity().ordering_domain(),
                                observation.identity().position(),
                            ),
                        )
                        .map_err(storage)?,
                        receipt_id,
                    });
                }
                match authorization {
                    ObservationRetirementAuthorization::UnsupportedCodexRecord => {
                        let envelope: CanonicalObservationEnvelopeV1 =
                            serde_json::from_value(observation.payload().clone())
                                .map_err(storage)?;
                        if !unsupported_codex_record(&envelope)
                            || derive_canonical_projection(&observation)?
                                != ObservationProjection::Skipped(
                                    ProjectionSkipReason::NonConversationalRecord,
                                )
                        {
                            blockers.push(RetirementBlocker::UnsupportedClassifierChanged);
                        }
                        // Historical outputs remain protected even if today's reducer skips.
                        for table in [
                            "observation_projection_provenance",
                            "observation_projection_aliases",
                            "observation_workflow_facts",
                            "observation_provider_usage",
                        ] {
                            if scalar(
                                conn,
                                &format!(
                                    "SELECT EXISTS(SELECT 1 FROM {table} WHERE observation_id=?1)"
                                ),
                                id.as_str(),
                            )
                            .await?
                                != 0
                            {
                                blockers.push(RetirementBlocker::UnsupportedClassifierChanged);
                                break;
                            }
                        }
                    }
                    ObservationRetirementAuthorization::OperatorProjectPrune(marker) => {
                        if marker.approved_plan_digest.is_empty()
                            || observation.source() != &marker.source
                            || observation.scope() != &marker.scope
                            || marker.scope != ObservationScopeV1::Profile
                        {
                            return refused();
                        }
                    }
                    ObservationRetirementAuthorization::CrossStoreOwnerHandoff(proof) => {
                        if proof.target_store_identity.is_empty()
                            || proof.target_incarnation.is_empty()
                            || proof.retention_fence.is_empty()
                            || proof.copies.len() != plan.ids.len()
                            || observation.scope() != &ObservationScopeV1::Profile
                            || proof
                                .copies
                                .iter()
                                .filter(|copy| {
                                    &copy.source_observation_id == id
                                        && copy.payload_digest == payload_digest
                                })
                                .count()
                                != 1
                        {
                            return refused();
                        }
                    }
                    ObservationRetirementAuthorization::LifecycleRetention => return refused(),
                }
            }
            // Pinned candidates cannot be applied. Defer semantic authorization
            // rather than hydrate their bodies merely to report another blocker.
            _ => {}
        }
        // Source cursor coverage is not projector sequence coverage. Scalar and
        // window projection, rejection and rebuild frontiers still require every
        // sequence, including queued skips and already-projected interior rows.
        // Keep this gate unconditional until all those consumers can verify
        // durable retired-sequence coverage; apply re-plans under its writer.
        blockers.push(RetirementBlocker::ProjectionSequenceCoverageUnavailable);
        plan.candidates.push(RetirementCandidate {
            observation_id: id.clone(),
            payload_digest,
            blockers,
        });
    }
    let anchor_ids = plan
        .anchors
        .iter()
        .map(|anchor| anchor.anchor_id.as_str().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let receipt_ids = receipt_ids.into_iter().collect::<Vec<_>>();
    let binding_ids = external_bindings.into_iter().collect::<Vec<_>>();
    for (table, key, keys) in [
        ("retrieval_anchors", "anchor_id", &anchor_ids),
        ("retrieval_anchor_aliases", "anchor_id", &anchor_ids),
        ("sanitization_receipts", "receipt_id", &receipt_ids),
    ] {
        let mut size =
            capture_table(conn, table, key, "", keys, &mut plan.evidence, &mut budget).await?;
        size.retained = true;
        plan.tables.push(size);
    }
    for table in EXTERNAL_TABLES {
        let mut size = capture_table(
            conn,
            table,
            "binding_id",
            "",
            &binding_ids,
            &mut plan.evidence,
            &mut budget,
        )
        .await?;
        size.retained = true;
        plan.tables.push(size);
    }
    if let ObservationRetirementAuthorization::OperatorProjectPrune(marker) = &plan.authorization {
        let (key, value) = marker.metadata()?;
        let mut rows = conn
            .query(
                "SELECT value FROM session_backfill_meta WHERE key=?1",
                params![key],
            )
            .await
            .map_err(storage)?;
        if let Some(row) = rows.next().await.map_err(storage)?
            && row.get::<String>(0).map_err(storage)? != value
        {
            for candidate in &mut plan.candidates {
                candidate.blockers.push(RetirementBlocker::MarkerConflict);
            }
        }
    }
    plan.digest = hash(&("tracedecay.observation-retirement.v1", &plan))?;
    Ok(plan)
}

impl RegisteredGlobalDb {
    pub async fn plan_observation_retirement(
        &self,
        ids: &[CanonicalObservationIdV1],
        authorization: ObservationRetirementAuthorization,
    ) -> ProjectionStoreResult<ObservationRetirementPlan> {
        let mut ids = ids.to_vec();
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let snapshot = self.read_snapshot().await.map_err(storage)?;
        plan_on(
            &snapshot,
            hash(self.verified_locator())?,
            ids,
            authorization,
        )
        .await
    }

    pub async fn apply_observation_retirement(
        &self,
        plan: &ObservationRetirementPlan,
        confirmed_digest: &str,
    ) -> ProjectionStoreResult<ObservationRetirementOutcome> {
        self.apply_observation_retirement_with_handoff(plan, confirmed_digest, &NoHandoff)
            .await
    }

    pub async fn apply_observation_retirement_with_handoff(
        &self,
        plan: &ObservationRetirementPlan,
        confirmed_digest: &str,
        validator: &impl HandoffProofValidator,
    ) -> ProjectionStoreResult<ObservationRetirementOutcome> {
        if confirmed_digest != plan.digest || plan.store != hash(self.verified_locator())? {
            return refused();
        }
        let transaction = self.begin_write_transaction().await.map_err(storage)?;
        let receipt_key = format!("{RECEIPT_PREFIX}{}", plan.digest);
        let mut receipts = transaction
            .query(
                "SELECT value FROM session_backfill_meta WHERE key=?1",
                params![receipt_key.as_str()],
            )
            .await
            .map_err(storage)?;
        if let Some(row) = receipts.next().await.map_err(storage)? {
            if row.get::<String>(0).map_err(storage)? != plan.store {
                return refused();
            }
            drop(receipts);
            for id in &plan.ids {
                if scalar(
                    &transaction,
                    "SELECT EXISTS(SELECT 1 FROM observations WHERE observation_id=?1)",
                    id.as_str(),
                )
                .await?
                    != 0
                {
                    return refused();
                }
            }
            transaction.commit().await.map_err(storage)?;
            return Ok(ObservationRetirementOutcome::AlreadyApplied);
        }
        drop(receipts);
        let current = plan_on(
            &transaction,
            plan.store.clone(),
            plan.ids.clone(),
            plan.authorization.clone(),
        )
        .await?;
        if current.digest != plan.digest {
            return refused();
        }
        if !current.eligible() {
            return Ok(ObservationRetirementOutcome::Deferred);
        }
        if let ObservationRetirementAuthorization::CrossStoreOwnerHandoff(proof) =
            &current.authorization
            && validator.validate(proof).await? != HandoffProofStatus::Verified
        {
            return Ok(ObservationRetirementOutcome::Deferred);
        }
        if let ObservationRetirementAuthorization::OperatorProjectPrune(marker) =
            &current.authorization
        {
            let (key, value) = marker.metadata()?;
            transaction.execute("INSERT INTO session_backfill_meta(key,value) VALUES (?1,?2) ON CONFLICT(key) DO NOTHING", params![key, value]).await.map_err(storage)?;
        }
        if !crate::schema_contract::invariants::authority_invariant_triggers_intact(&transaction)
            .await
            .map_err(storage)?
        {
            return refused();
        }
        // The canonical exact-SQL writer authorizes transactional schema
        // maintenance. Only named delete guards are lifted; all update guards,
        // ownership accounting and audit invalidation triggers stay installed.
        for (name, _) in &current.guards {
            transaction
                .execute_batch(&format!("DROP TRIGGER \"{name}\";"))
                .await
                .map_err(storage)?;
        }
        for coverage in &current.coverage {
            // Preserve verified historical commitment as compact cursor coverage;
            // incoming capture is never reported as an exact duplicate here.
            transaction.execute("INSERT INTO source_cursor_advances(source_json,scope_json,coverage_json,reason,receipt_id) VALUES (?1,?2,?3,'duplicate_observation',?4) ON CONFLICT(source_json,scope_json,coverage_json) DO NOTHING", params![coverage.source_json.as_str(), coverage.scope_json.as_str(), coverage.coverage_json.as_str(), coverage.receipt_id.as_str()]).await.map_err(storage)?;
        }
        for id in &current.ids {
            // Retract derived output through its existing shared-owner reducer.
            // Settled records are intentionally NOT skipped by our cascade.
            crate::observation_projection::retire_source_record(&transaction, id.as_str()).await?;
            for (table, key, extra) in TABLES {
                transaction
                    .execute(
                        &format!("DELETE FROM {table} WHERE {key}=?1{extra}"),
                        params![id.as_str()],
                    )
                    .await
                    .map_err(storage)?;
            }
        }
        // Keep sequence-bearing anchor identity/ledger rows, but terminate
        // servability through the canonical state machine in this transaction.
        let now = tracedecay_domain::UtcMicros(
            scalar(
                &transaction,
                "SELECT CAST(unixepoch('subsec') * 1000000 AS INTEGER) WHERE ?1 IS NOT NULL",
                "",
            )
            .await?,
        );
        let mut seen = BTreeSet::new();
        for anchor in &current.anchors {
            if !seen.insert(anchor.anchor_id.as_str())
                || !tracedecay_store::AnchorDispositionStateV1::transition_allowed(
                    anchor.state,
                    tracedecay_store::AnchorDispositionStateV1::Deleted,
                )
            {
                continue;
            }
            let record = tracedecay_store::RetrievalAnchorDispositionRecordV1::new(
                hash(&(
                    "tracedecay.observation-retirement.anchor.v1",
                    &current.digest,
                    anchor.anchor_id.as_str(),
                ))?,
                anchor.anchor_id.clone(),
                anchor.owner.clone(),
                tracedecay_store::AnchorDispositionStateV1::Deleted,
                None,
                match current.reason() {
                    ObservationRetirementReason::OperatorProjectPrune => {
                        tracedecay_store::AnchorDispositionReasonClassV1::UserRequest
                    }
                    ObservationRetirementReason::LifecycleRetention => {
                        tracedecay_store::AnchorDispositionReasonClassV1::Retention
                    }
                    _ => tracedecay_store::AnchorDispositionReasonClassV1::Correction,
                },
                now,
            )
            .map_err(storage)?;
            tracedecay_runtime_core::db::append_retrieval_anchor_disposition_on(
                &transaction,
                &record,
            )
            .await
            .map_err(storage)?;
        }
        for (_, sql) in &current.guards {
            transaction.execute_batch(sql).await.map_err(storage)?;
        }
        if read_guards(&transaction).await? != current.guards {
            return refused();
        }
        transaction
            .execute(
                "INSERT INTO session_backfill_meta(key,value) VALUES (?1,?2)",
                params![receipt_key, current.store],
            )
            .await
            .map_err(storage)?;
        transaction.commit().await.map_err(storage)?;
        Ok(ObservationRetirementOutcome::Applied {
            observations: current.ids.len(),
        })
    }
}

#[cfg(test)]
mod tests;
