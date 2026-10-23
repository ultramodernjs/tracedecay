//! Durable recall admission and explain/control attribution storage.
//!
//! The host selects the canonical ledger path and authorizes each operation.
//! This module owns the SQLite schema, atomic retention, keyed identities, and
//! bounded retained-control reads. Retained evidence never grants current authority.

pub mod control_attribution;
#[cfg(test)]
mod tests;

#[cfg(feature = "test-helpers")]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
#[cfg(feature = "test-helpers")]
use serde_json::json;
use tracedecay_contracts::try_now_micros;
use tracedecay_memory_provider_registry::{
    OwnedProviderId, RecallAdmissionAuditError, RecallAdmissionObserver, RecallAdmissionReport,
    RecallBudgetsV1, RecallDenialReason, RecallExplainTraceV1,
};
#[cfg(any(test, feature = "test-helpers"))]
use tracedecay_memory_provider_registry::{
    RecallExplainHostDecisionV1, RecallExplainItemV1, RecallExplainProviderExplanationV1,
    RecallExplainStageV1, RecallExplainTokenSummaryV1,
};

/// File name of the project-owned recall admission ledger inside the
/// canonical store layout. Placement only; never an identity input.
pub const LEDGER_FILE_NAME: &str = "memory-recall-admission-ledger-v1.sqlite3";

/// Product-owned per-request recall budgets. These are the budgets the
/// coding-memory evaluation scenarios declare for a project recall and stay
/// under the Native provider's negotiated `recall_candidates` limit.
pub const PROJECT_RECALL_BUDGETS: RecallBudgetsV1 = RecallBudgetsV1 {
    maximum_candidates: 8,
    maximum_candidate_content_bytes: 4_096,
    maximum_total_content_bytes: 8_192,
    maximum_source_refs_per_candidate: 8,
    maximum_trace_refs_per_candidate: 8,
    maximum_warnings: 8,
    maximum_extensions_per_candidate: 8,
};

/// Failure to open or initialize the recall ledger at its host-selected path.
#[derive(Debug, thiserror::Error)]
#[error("recall admission ledger at {path} could not be opened: {source}")]
pub struct RecallAdmissionLedgerOpenError {
    /// Storage placement for diagnostics, never an identity input.
    pub path: PathBuf,
    /// Underlying SQLite failure.
    #[source]
    pub source: rusqlite::Error,
}

/// Typed failure of retaining one admission report.
#[derive(Debug, thiserror::Error)]
pub enum RecallAdmissionLedgerError {
    /// Control data differs from the final trace, or the sink cannot retain it.
    #[error(
        "recall control metadata does not match the final trace or is unsupported by this sink"
    )]
    InvalidControlMetadata,
    /// The host clock could not stamp the ledger row.
    #[error("host clock unavailable for the recall admission ledger: {0}")]
    Clock(#[source] tracedecay_contracts::ClockError),
    /// The report could not be serialised for its content digest.
    #[error("recall admission report could not be encoded: {0}")]
    Encode(#[source] serde_json::Error),
    /// A report with the same identity but different content is already
    /// retained. The ledger is append-only per request; a divergent replay is
    /// a defect, not something to overwrite.
    #[error(
        "recall admission report for request {request_id} under scope {exact_scope_sha256} is \
         already retained with different content"
    )]
    ConflictingReport {
        /// Request identity of the retained report.
        request_id: String,
        /// Exact-scope digest of the retained report.
        exact_scope_sha256: String,
    },
    /// A trace with the same identity but different content is already
    /// retained. Traces are append-only per `(scope, trace_id)`; a divergent
    /// replay is a defect, not something to overwrite.
    #[error(
        "recall explain trace {trace_id} under scope {exact_scope_sha256} is already retained \
         with different content"
    )]
    ConflictingTrace {
        /// Deterministic identity of the retained trace.
        trace_id: String,
        /// Exact-scope digest the trace was retained under.
        exact_scope_sha256: String,
    },
    /// A retained row could not be decoded back into its typed value.
    #[error("retained recall explain trace row could not be decoded: {0}")]
    #[cfg(any(test, feature = "test-helpers"))]
    Decode(#[source] serde_json::Error),
    /// A keyed attribution could not be constructed or validated.
    #[error("recall attribution failed: {0}")]
    Attribution(#[source] control_attribution::RecallControlAttributionErrorV1),
    /// The SQLite ledger refused the write.
    #[error("recall admission ledger write failed: {0}")]
    Sqlite(#[source] rusqlite::Error),
}

/// Outcome of retaining one report: the ledger is idempotent per
/// `(exact_scope_sha256, request_id)`, so a crash-recovery replay of an
/// identical report is a no-op rather than a duplicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecallAdmissionLedgerWriteV1 {
    /// The report was retained by this write.
    Recorded,
    /// An identical report was already retained.
    AlreadyRecorded,
}

/// The project-scoped audit surface one recall's explain trace is retained
/// in.
///
/// The lane holds this rather than a mount handle: the trace can only be
/// reconciled after the pack stage has run, which is downstream of the
/// recall, and a lane that carried a whole mount into the render path would
/// be able to do far more than record one audit row.
pub trait RecallExplainTraceSinkV1: Send + Sync + 'static {
    /// Retains one trace idempotently under one exact-scope digest.
    ///
    /// # Errors
    ///
    /// Returns the typed ledger failure. A divergent replay of the same
    /// trace identity is a conflict, never an overwrite.
    fn record_explain_trace(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError>;

    /// Retains control attribution in the same transaction as the trace.
    /// A legacy sink refuses metadata instead of claiming it retained authority.
    fn record_explain_trace_with_control(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
        metadata: Option<&control_attribution::PreparedRecallControlMetadataV1>,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        if metadata.is_some() {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        self.record_explain_trace(exact_scope_sha256, trace)
    }
}

/// One retained explain trace as the project audit ledger holds it.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecallExplainTraceV1 {
    /// Exact-scope digest the recall ran under.
    pub exact_scope_sha256: String,
    /// Host instant the trace was retained at.
    pub recorded_at_utc_micros: i64,
    /// The trace itself.
    pub trace: RecallExplainTraceV1,
}

/// Durable, content-free ledger of recall admission reports.
///
/// One row per admission report plus one row per denied candidate. Neither
/// table has a content column:
/// [`DeniedRecallCandidate`](tracedecay_memory_provider_registry::DeniedRecallCandidate)
/// carries none, and admitted candidates are not retained at all.
pub struct RecallAdmissionLedgerV1 {
    path: PathBuf,
    connection: Mutex<Connection>,
    locator_key: control_attribution::RecallLocatorKeyV1,
}

type RetainedTraceIntegrityRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[cfg(any(test, feature = "test-helpers"))]
type RetainedTraceHeaderRow = (
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    Option<String>,
    i64,
    Option<String>,
);

impl std::fmt::Debug for RecallAdmissionLedgerV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecallAdmissionLedgerV1")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl RecallAdmissionLedgerV1 {
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_for_control_test(
        store_data_root: &Path,
    ) -> Result<Self, RecallAdmissionLedgerOpenError> {
        Self::open(store_data_root.join(LEDGER_FILE_NAME))
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open(path: PathBuf) -> Result<Self, RecallAdmissionLedgerOpenError> {
        Self::open_with_key(path, control_attribution::RecallLocatorKeyV1::for_test())
    }

    pub fn open_with_key(
        path: PathBuf,
        locator_key: control_attribution::RecallLocatorKeyV1,
    ) -> Result<Self, RecallAdmissionLedgerOpenError> {
        Self::open_with_flags(path, rusqlite::OpenFlags::default(), locator_key)
    }

    /// Opens an existing host-owned ledger without creating a missing target.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn open_existing(path: PathBuf) -> Result<Self, RecallAdmissionLedgerOpenError> {
        Self::open_existing_with_key(path, control_attribution::RecallLocatorKeyV1::for_test())
    }

    /// Opens an existing host-owned ledger with the durable composition key.
    pub fn open_existing_with_key(
        path: PathBuf,
        locator_key: control_attribution::RecallLocatorKeyV1,
    ) -> Result<Self, RecallAdmissionLedgerOpenError> {
        Self::open_with_flags(
            path,
            rusqlite::OpenFlags::default() & !rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            locator_key,
        )
    }

    fn open_with_flags(
        path: PathBuf,
        flags: rusqlite::OpenFlags,
        locator_key: control_attribution::RecallLocatorKeyV1,
    ) -> Result<Self, RecallAdmissionLedgerOpenError> {
        let connection = Connection::open_with_flags(&path, flags).map_err(|source| {
            RecallAdmissionLedgerOpenError {
                path: path.clone(),
                source,
            }
        })?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS recall_admission_reports (
                     exact_scope_sha256 TEXT NOT NULL,
                     request_id TEXT NOT NULL,
                     report_sha256 TEXT NOT NULL,
                     temporal_mode TEXT NOT NULL,
                     evaluation_time TEXT NOT NULL,
                     unknown_validity_policy TEXT NOT NULL,
                     received_count INTEGER NOT NULL,
                     admitted_count INTEGER NOT NULL,
                     denied_count INTEGER NOT NULL,
                     degraded INTEGER NOT NULL,
                     warnings_json TEXT NOT NULL,
                     recorded_at_utc_micros INTEGER NOT NULL,
                     PRIMARY KEY (exact_scope_sha256, request_id)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS recall_admission_denials (
                     exact_scope_sha256 TEXT NOT NULL,
                     request_id TEXT NOT NULL,
                     position INTEGER NOT NULL,
                     candidate_id TEXT NOT NULL,
                     stable_memory_ref TEXT,
                     reason_label TEXT NOT NULL,
                     reason_json TEXT NOT NULL,
                     provider_claimed_scope_binding TEXT NOT NULL,
                     provider_claimed_scope_sha256 TEXT,
                     provider_claimed_temporal_state TEXT NOT NULL,
                     PRIMARY KEY (exact_scope_sha256, request_id, position),
                     FOREIGN KEY (exact_scope_sha256, request_id)
                         REFERENCES recall_admission_reports (exact_scope_sha256, request_id)
                         ON DELETE CASCADE
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS recall_explain_traces (
                     exact_scope_sha256 TEXT NOT NULL,
                     trace_id TEXT NOT NULL,
                     request_id TEXT NOT NULL,
                     provider_id TEXT NOT NULL,
                     registration_revision INTEGER NOT NULL,
                     requested_count INTEGER NOT NULL,
                     degraded INTEGER NOT NULL,
                     trace_sha256 TEXT NOT NULL,
                     token_summary_json TEXT,
                     recorded_at_utc_micros INTEGER NOT NULL,
                     delivery_scope_json TEXT,
                     scope_binding_mac TEXT,
                     control_metadata_sha256 TEXT,
                     control_metadata_mac TEXT,
                     trace_mac TEXT,
                     PRIMARY KEY (exact_scope_sha256, trace_id)
                 ) STRICT;
                 CREATE INDEX IF NOT EXISTS recall_explain_traces_by_request
                     ON recall_explain_traces (exact_scope_sha256, request_id);
                 CREATE TABLE IF NOT EXISTS recall_explain_trace_items (
                     exact_scope_sha256 TEXT NOT NULL,
                     trace_id TEXT NOT NULL,
                     provider_rank INTEGER NOT NULL,
                     candidate_id TEXT NOT NULL,
                     stage TEXT NOT NULL,
                     host_reason_code TEXT NOT NULL,
                     host_reason_detail TEXT,
                     host_decision_json TEXT NOT NULL,
                     provider_explanation_json TEXT NOT NULL,
                     section TEXT,
                     tokens INTEGER,
                     stable_memory_ref TEXT,
                     original_sources_json TEXT,
                     control_binding_mac TEXT,
                     item_mac TEXT,
                     PRIMARY KEY (exact_scope_sha256, trace_id, provider_rank),
                     FOREIGN KEY (exact_scope_sha256, trace_id)
                         REFERENCES recall_explain_traces (exact_scope_sha256, trace_id)
                         ON DELETE CASCADE
                 ) STRICT;",
            )
            .map_err(|source| RecallAdmissionLedgerOpenError {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            connection: Mutex::new(connection),
            locator_key,
        })
    }

    /// Storage placement of the ledger.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keyed projection context shared by explain, denial and control
    /// retention. Secret bytes stay inside the key type.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn locator_key(&self) -> &control_attribution::RecallLocatorKeyV1 {
        &self.locator_key
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave a partial write behind:
        // every write is one SQLite transaction.
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Retains one admission report and its denial rows atomically.
    pub fn record(
        &self,
        report: &RecallAdmissionReport,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        // The projection is deliberately bound to the routed provider and
        // registration revision. A pure registry helper may leave these
        // fields unset, but such a report is not safe to retain at the host
        // boundary and must fail closed instead of using an "unknown"
        // projection context.
        if report.provider_id.as_deref().is_none_or(str::is_empty)
            || report
                .registration_revision
                .is_none_or(|revision| revision == 0)
        {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        let recorded_at = try_now_micros().map_err(RecallAdmissionLedgerError::Clock)?;
        let report_bytes =
            serde_json::to_vec(report).map_err(RecallAdmissionLedgerError::Encode)?;
        let report_sha256 = tracedecay_domain::canonical_text::sha256_hex(&report_bytes);
        let warnings_json =
            serde_json::to_string(&report.warnings).map_err(RecallAdmissionLedgerError::Encode)?;
        let unknown_validity_policy = serde_json::to_value(report.unknown_validity_policy)
            .map_err(RecallAdmissionLedgerError::Encode)?;
        let unknown_validity_policy = unknown_validity_policy
            .as_str()
            .map_or_else(|| unknown_validity_policy.to_string(), str::to_owned);
        let retained_aliases = control_attribution::retained_candidate_identity_aliases_for_report(
            report,
            &self.locator_key,
        )
        .map_err(RecallAdmissionLedgerError::Attribution)?;
        let mut denial_rows = Vec::with_capacity(report.denied.len());
        for denied in &report.denied {
            let reason_json = sanitized_denial_reason_json(&denied.reason)
                .map_err(RecallAdmissionLedgerError::Encode)?;
            let Some(retained_candidate_id) = retained_aliases.get(&denied.candidate_id).cloned()
            else {
                // A malformed report that denies an identity absent from its
                // received partition cannot receive a collision-safe alias.
                // Refuse it instead of falling back to an ambiguous projection.
                return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
            };
            // Denials are durable project state. Keep the report's raw id for
            // the in-memory admission result and its replay digest, but make
            // the retained denial row opaque so a provider cannot park source
            // paths or secret-looking bytes in SQLite. The complete map is
            // shared with explain/control retention, including any collision
            // suffixes.
            denial_rows.push((
                denied,
                reason_json,
                retained_candidate_id.clone(),
                denied
                    .stable_memory_ref
                    .as_deref()
                    .map(|stable_memory_ref| {
                        control_attribution::opaque_denial_stable_memory_ref(
                            report,
                            &self.locator_key,
                            &retained_candidate_id,
                            stable_memory_ref,
                        )
                    })
                    .transpose()
                    .map_err(RecallAdmissionLedgerError::Attribution)?,
            ));
        }

        let mut connection = self.connection();
        let transaction = connection
            .transaction()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT report_sha256 FROM recall_admission_reports
                 WHERE exact_scope_sha256 = ?1 AND request_id = ?2",
                params![report.exact_scope_sha256, report.request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        if let Some(existing) = existing {
            return if existing == report_sha256 {
                Ok(RecallAdmissionLedgerWriteV1::AlreadyRecorded)
            } else {
                Err(RecallAdmissionLedgerError::ConflictingReport {
                    request_id: report.request_id.clone(),
                    exact_scope_sha256: report.exact_scope_sha256.clone(),
                })
            };
        }
        transaction
            .execute(
                "INSERT INTO recall_admission_reports (
                     exact_scope_sha256, request_id, report_sha256, temporal_mode,
                     evaluation_time, unknown_validity_policy, received_count, admitted_count,
                     denied_count, degraded, warnings_json, recorded_at_utc_micros
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    report.exact_scope_sha256,
                    report.request_id,
                    report_sha256,
                    report.temporal_mode,
                    report.evaluation_time,
                    unknown_validity_policy,
                    i64::try_from(report.received_count).unwrap_or(i64::MAX),
                    i64::try_from(report.admitted_count).unwrap_or(i64::MAX),
                    i64::try_from(report.denied.len()).unwrap_or(i64::MAX),
                    i64::from(report.degraded),
                    warnings_json,
                    recorded_at.0,
                ],
            )
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        for (position, (denied, reason_json, retained_candidate_id, retained_stable_memory_ref)) in
            denial_rows.iter().enumerate()
        {
            transaction
                .execute(
                    "INSERT INTO recall_admission_denials (
                         exact_scope_sha256, request_id, position, candidate_id,
                         stable_memory_ref, reason_label, reason_json,
                         provider_claimed_scope_binding, provider_claimed_scope_sha256,
                         provider_claimed_temporal_state
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        report.exact_scope_sha256,
                        report.request_id,
                        i64::try_from(position).unwrap_or(i64::MAX),
                        retained_candidate_id,
                        retained_stable_memory_ref,
                        denied.reason.label(),
                        reason_json,
                        denied.provider_claimed_scope_binding.as_wire(),
                        denied.provider_claimed_scope_sha256,
                        retained_temporal_state(&denied.provider_claimed_temporal_state),
                    ],
                )
                .map_err(RecallAdmissionLedgerError::Sqlite)?;
        }
        transaction
            .commit()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        #[cfg(feature = "test-helpers")]
        emit_host_history_recall_test_diagnostic(|| {
            let mut reasons = BTreeMap::<&str, usize>::new();
            for denied in &report.denied {
                *reasons.entry(denied.reason.label()).or_default() += 1;
            }
            json!({"phase":"admission", "received":report.received_count,
                "admitted":report.admitted_count, "denied":report.denied.len(),
                "degraded":report.degraded, "denial_reasons":reasons})
        });
        Ok(RecallAdmissionLedgerWriteV1::Recorded)
    }

    /// Retains one explain trace and every one of its per-candidate rows
    /// atomically.
    ///
    /// Idempotent per `(exact_scope_sha256, trace_id)`: replaying an
    /// identical trace is a no-op, and a divergent one is refused rather than
    /// silently overwriting the account of what the host actually decided.
    ///
    /// # Errors
    ///
    /// Returns [`RecallAdmissionLedgerError`] when the host clock is
    /// unavailable, a row cannot be encoded, the same identity is already
    /// retained with different content, or SQLite refuses the write.
    pub fn retain_explain_trace(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        self.retain_explain_trace_with_control(exact_scope_sha256, trace, None)
    }

    pub fn retain_explain_trace_with_control(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
        metadata: Option<&control_attribution::PreparedRecallControlMetadataV1>,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        // The registry's trace id is an unsalted reconciliation digest. The
        // retained ledger is a privacy boundary, so enforce the durable,
        // scope/request/provider-bound projection here as well as in the
        // production builder. This also prevents a legacy or alternate sink
        // caller from parking a dictionary-recoverable trace id in SQLite.
        if !control_attribution::is_lower_hex_sha256(exact_scope_sha256)
            || OwnedProviderId::new(&trace.provider_id).is_err()
            || trace.registration_revision == 0
            || trace.registration_revision > i64::MAX as u64
            || trace.requested_count != trace.items.len()
            || trace.requested_count as u64 > PROJECT_RECALL_BUDGETS.maximum_candidates
        {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        let expected_trace_id = control_attribution::retained_trace_id_with_key(
            &self.locator_key,
            exact_scope_sha256,
            &trace.request_id,
            &trace.provider_id,
            trace.registration_revision,
        )
        .map_err(RecallAdmissionLedgerError::Attribution)?;
        if trace.trace_id != expected_trace_id {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        // The sink is the last durable boundary. Every provider identity must
        // already be the context-bound opaque projection made by the host;
        // a missing or legacy alias is a typed refusal and can never be
        // serialized into the ledger.
        let mut candidate_ids = std::collections::BTreeSet::new();
        if trace.items.iter().enumerate().any(|(rank, item)| {
            item.provider_rank != rank
                || item.stage != item.host_decision.stage()
                || !candidate_ids.insert(item.candidate_id.as_str())
                || control_attribution::validate_retained_trace_candidate_id(&item.candidate_id)
                    .is_err()
        }) {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        // Keep the denormalized reason columns tied to the typed host
        // decision. A row can otherwise retain a raw provider detail beside a
        // valid-looking decision JSON and reintroduce it through the explain
        // renderer.
        if trace.items.iter().any(|item| {
            item.host_reason_code != item.host_decision.code()
                || item.host_reason_detail != item.host_decision.detail()
        }) {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        if let Some(metadata) = metadata
            && !metadata
                .matches_trace(exact_scope_sha256, trace, &self.locator_key)
                .map_err(RecallAdmissionLedgerError::Attribution)?
        {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        let recorded_at = try_now_micros().map_err(RecallAdmissionLedgerError::Clock)?;
        let trace_bytes = serde_json::to_vec(trace).map_err(RecallAdmissionLedgerError::Encode)?;
        let trace_sha256 = tracedecay_domain::canonical_text::sha256_hex(&trace_bytes);
        let trace_mac = control_attribution::retained_trace_bytes_mac(
            &self.locator_key,
            exact_scope_sha256,
            &trace.trace_id,
            &trace.provider_id,
            trace.registration_revision,
            &trace_bytes,
        )
        .map_err(RecallAdmissionLedgerError::Attribution)?;
        let token_summary_json = match &trace.token_summary {
            None => None,
            Some(summary) => {
                Some(serde_json::to_string(summary).map_err(RecallAdmissionLedgerError::Encode)?)
            }
        };
        let mut item_rows = Vec::with_capacity(trace.items.len());
        for item in &trace.items {
            let host_decision_json = serde_json::to_string(&item.host_decision)
                .map_err(RecallAdmissionLedgerError::Encode)?;
            let provider_explanation_json = serde_json::to_string(&item.provider_explanation)
                .map_err(RecallAdmissionLedgerError::Encode)?;
            let item_bytes =
                serde_json::to_vec(item).map_err(RecallAdmissionLedgerError::Encode)?;
            let item_mac = control_attribution::retained_item_bytes_mac(
                &self.locator_key,
                exact_scope_sha256,
                &trace.trace_id,
                control_attribution::RetainedItemBindingV1 {
                    provider_id: &trace.provider_id,
                    registration_revision: trace.registration_revision,
                    provider_rank: item.provider_rank,
                    candidate_id: &item.candidate_id,
                },
                &item_bytes,
            )
            .map_err(RecallAdmissionLedgerError::Attribution)?;
            item_rows.push((
                item,
                host_decision_json,
                provider_explanation_json,
                item_mac,
            ));
        }

        let mut connection = self.connection();
        let transaction = connection
            .transaction()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        let existing: Option<RetainedTraceIntegrityRow> = transaction
            .query_row(
                "SELECT trace_sha256, trace_mac, control_metadata_sha256,
                        scope_binding_mac, control_metadata_mac
                 FROM recall_explain_traces
                 WHERE exact_scope_sha256 = ?1 AND trace_id = ?2",
                params![exact_scope_sha256, trace.trace_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        if let Some((
            existing,
            existing_trace_mac,
            existing_metadata,
            existing_scope_mac,
            existing_control_mac,
        )) = existing
        {
            return if existing == trace_sha256
                && existing_trace_mac.as_deref() == Some(trace_mac.as_str())
                && existing_metadata.as_deref()
                    == metadata
                        .map(control_attribution::PreparedRecallControlMetadataV1::metadata_sha256)
                && existing_scope_mac.as_deref()
                    == metadata.map(
                        control_attribution::PreparedRecallControlMetadataV1::scope_binding_mac,
                    )
                && existing_control_mac.as_deref()
                    == metadata.map(
                        control_attribution::PreparedRecallControlMetadataV1::control_metadata_mac,
                    )
            {
                Ok(RecallAdmissionLedgerWriteV1::AlreadyRecorded)
            } else {
                Err(RecallAdmissionLedgerError::ConflictingTrace {
                    trace_id: trace.trace_id.clone(),
                    exact_scope_sha256: exact_scope_sha256.to_owned(),
                })
            };
        }
        transaction
            .execute(
                "INSERT INTO recall_explain_traces (
                     exact_scope_sha256, trace_id, request_id, provider_id,
                     registration_revision, requested_count, degraded, trace_sha256,
                     trace_mac, token_summary_json, recorded_at_utc_micros,
                     delivery_scope_json, scope_binding_mac, control_metadata_sha256,
                     control_metadata_mac
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    exact_scope_sha256,
                    &trace.trace_id,
                    trace.request_id,
                    trace.provider_id,
                    i64::try_from(trace.registration_revision).unwrap_or(i64::MAX),
                    i64::try_from(trace.requested_count).unwrap_or(i64::MAX),
                    i64::from(trace.degraded),
                    trace_sha256,
                    trace_mac,
                    token_summary_json,
                    recorded_at.0,
                    metadata.map(
                        control_attribution::PreparedRecallControlMetadataV1::delivery_scope_json
                    ),
                    metadata.map(
                        control_attribution::PreparedRecallControlMetadataV1::scope_binding_mac
                    ),
                    metadata
                        .map(control_attribution::PreparedRecallControlMetadataV1::metadata_sha256),
                    metadata.map(
                        control_attribution::PreparedRecallControlMetadataV1::control_metadata_mac
                    ),
                ],
            )
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        for (item, host_decision_json, provider_explanation_json, item_mac) in &item_rows {
            let binding = metadata.and_then(|value| value.item_sql(item.provider_rank));
            transaction
                .execute(
                    "INSERT INTO recall_explain_trace_items (
                         exact_scope_sha256, trace_id, provider_rank, candidate_id, stage,
                         host_reason_code, host_reason_detail, host_decision_json,
                         provider_explanation_json, section, tokens,
                         stable_memory_ref, original_sources_json, control_binding_mac,
                         item_mac
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        exact_scope_sha256,
                        trace.trace_id,
                        i64::try_from(item.provider_rank).unwrap_or(i64::MAX),
                        item.candidate_id,
                        item.stage.label(),
                        item.host_reason_code,
                        item.host_reason_detail,
                        host_decision_json,
                        provider_explanation_json,
                        item.section,
                        item.tokens
                            .map(|tokens| i64::try_from(tokens).unwrap_or(i64::MAX)),
                        binding.map(|(reference, _, _)| reference),
                        binding.map(|(_, sources, _)| sources),
                        binding.map(|(_, _, mac)| mac),
                        item_mac,
                    ],
                )
                .map_err(RecallAdmissionLedgerError::Sqlite)?;
        }
        transaction
            .commit()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        #[cfg(feature = "test-helpers")]
        emit_host_history_recall_test_diagnostic(|| {
            let mut reasons = BTreeMap::<&str, usize>::new();
            for item in &trace.items {
                let code = match &item.host_decision {
                    RecallExplainHostDecisionV1::HostWithheld { reason_code, .. } => {
                        match reason_code.as_str() {
                            "content_not_inline" => "content_not_inline",
                            "provenance_claimed_unconfirmed" => "provenance_claimed_unconfirmed",
                            "provenance_redacted" => "provenance_redacted",
                            "provenance_unresolvable" => "provenance_unresolvable",
                            "provenance_unknown" => "provenance_unknown",
                            _ => "other_host_withheld",
                        }
                    }
                    decision => decision.code(),
                };
                *reasons.entry(code).or_default() += 1;
            }
            let stages: BTreeMap<_, _> = trace.stage_counts().into_iter().collect();
            json!({"phase":"trace", "received":trace.requested_count,
                "items":trace.items.len(), "degraded":trace.degraded,
                "stage_counts":stages, "reason_counts":reasons})
        });
        Ok(RecallAdmissionLedgerWriteV1::Recorded)
    }

    /// Reads one retained explain trace back by its deterministic identity.
    ///
    /// The ledger file is the project boundary: a row can only be read from
    /// the project whose store holds it, so a trace identity alone is a
    /// project-scoped address.
    ///
    /// # Errors
    ///
    /// Returns [`RecallAdmissionLedgerError`] when SQLite refuses the read or
    /// a retained row cannot be decoded back into its typed value.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn explain_trace(
        &self,
        trace: &control_attribution::RecallControlTraceRefV1,
    ) -> Result<Option<RetainedRecallExplainTraceV1>, RecallAdmissionLedgerError> {
        let connection = self.connection();
        let header: Option<RetainedTraceHeaderRow> = connection
            .query_row(
                "SELECT exact_scope_sha256, request_id, provider_id, registration_revision,
                            requested_count, degraded, trace_sha256, token_summary_json,
                            recorded_at_utc_micros, trace_mac
                     FROM recall_explain_traces
                     WHERE exact_scope_sha256 = ?1 AND trace_id = ?2",
                params![trace.exact_scope_sha256(), trace.trace_id()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        let Some((
            exact_scope_sha256,
            request_id,
            provider_id,
            registration_revision,
            requested_count,
            degraded,
            trace_sha256,
            token_summary_json,
            recorded_at_utc_micros,
            trace_mac,
        )) = header
        else {
            return Ok(None);
        };
        let expected_trace_id = control_attribution::retained_trace_id_with_key(
            &self.locator_key,
            &exact_scope_sha256,
            &request_id,
            &provider_id,
            u64::try_from(registration_revision).unwrap_or(0),
        )
        .map_err(RecallAdmissionLedgerError::Attribution)?;
        if trace.trace_id() != expected_trace_id {
            // Additive upgrades can leave an older unsalted trace row in the
            // same database. Quarantine it before decoding any item bytes.
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        let token_summary: Option<RecallExplainTokenSummaryV1> = match token_summary_json {
            None => None,
            Some(encoded) => {
                Some(serde_json::from_str(&encoded).map_err(RecallAdmissionLedgerError::Decode)?)
            }
        };
        let mut statement = connection
            .prepare(
                "SELECT provider_rank, candidate_id, host_reason_code, host_reason_detail,
                        host_decision_json, provider_explanation_json, section, tokens, item_mac
                 FROM recall_explain_trace_items
                 WHERE exact_scope_sha256 = ?1 AND trace_id = ?2
                 ORDER BY provider_rank ASC",
            )
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        let rows = statement
            .query_map(params![exact_scope_sha256, trace.trace_id()], |row| {
                let provider_rank: i64 = row.get(0)?;
                let host_decision_json: String = row.get(4)?;
                let provider_explanation_json: String = row.get(5)?;
                let tokens: Option<i64> = row.get(7)?;
                Ok((
                    usize::try_from(provider_rank).unwrap_or(0),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    host_decision_json,
                    provider_explanation_json,
                    row.get::<_, Option<String>>(6)?,
                    tokens.map(|tokens| u64::try_from(tokens).unwrap_or(0)),
                    row.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(RecallAdmissionLedgerError::Sqlite)?;
        let mut items = Vec::new();
        for row in rows {
            let (
                provider_rank,
                candidate_id,
                host_reason_code,
                host_reason_detail,
                host_decision_json,
                provider_explanation_json,
                section,
                tokens,
                item_mac,
            ) = row.map_err(RecallAdmissionLedgerError::Sqlite)?;
            let host_decision: RecallExplainHostDecisionV1 =
                serde_json::from_str(&host_decision_json)
                    .map_err(RecallAdmissionLedgerError::Decode)?;
            let provider_explanation: RecallExplainProviderExplanationV1 =
                serde_json::from_str(&provider_explanation_json)
                    .map_err(RecallAdmissionLedgerError::Decode)?;
            // A row may have a valid digest while still carrying a
            // provider-controlled candidate id (or a raw dedup target).
            // Quarantine the whole trace before any caller can render those
            // bytes.
            if control_attribution::validate_retained_trace_candidate_id(&candidate_id).is_err() {
                return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
            }
            if let RecallExplainHostDecisionV1::Deduplicated {
                duplicate_of_candidate_id,
                ..
            } = &host_decision
                && control_attribution::validate_retained_trace_candidate_id(
                    duplicate_of_candidate_id,
                )
                .is_err()
            {
                return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
            }
            if host_reason_code != host_decision.code()
                || host_reason_detail != host_decision.detail()
            {
                return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
            }
            let stage: RecallExplainStageV1 = host_decision.stage();
            let item = RecallExplainItemV1 {
                candidate_id,
                provider_rank,
                stage,
                host_reason_code,
                host_reason_detail,
                host_decision,
                provider_explanation,
                section,
                tokens,
            };
            let item_mac = item_mac.ok_or(RecallAdmissionLedgerError::InvalidControlMetadata)?;
            let item_bytes =
                serde_json::to_vec(&item).map_err(RecallAdmissionLedgerError::Encode)?;
            if !control_attribution::is_lower_hex_sha256(&item_mac)
                || item_mac
                    != control_attribution::retained_item_bytes_mac(
                        &self.locator_key,
                        &exact_scope_sha256,
                        trace.trace_id(),
                        control_attribution::RetainedItemBindingV1 {
                            provider_id: &provider_id,
                            registration_revision: u64::try_from(registration_revision)
                                .unwrap_or(0),
                            provider_rank: item.provider_rank,
                            candidate_id: &item.candidate_id,
                        },
                        &item_bytes,
                    )
                    .map_err(RecallAdmissionLedgerError::Attribution)?
            {
                return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
            }
            items.push(item);
        }
        let degraded = degraded != 0;
        let trace = RecallExplainTraceV1 {
            trace_id: trace.trace_id().to_owned(),
            request_id,
            provider_id,
            registration_revision: u64::try_from(registration_revision).unwrap_or(0),
            requested_count: usize::try_from(requested_count).unwrap_or(0),
            degraded,
            items,
            token_summary,
        };
        // The trace digest covers every externally rendered field. Treat a
        // modified row as unavailable instead of returning attacker/provider
        // bytes from a host-owned SQLite file, especially for candidate ids,
        // dedup details, or explanation text.
        let trace_bytes = serde_json::to_vec(&trace).map_err(RecallAdmissionLedgerError::Encode)?;
        if tracedecay_domain::canonical_text::sha256_hex(&trace_bytes) != trace_sha256 {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        let trace_mac = trace_mac.ok_or(RecallAdmissionLedgerError::InvalidControlMetadata)?;
        if !control_attribution::is_lower_hex_sha256(&trace_mac)
            || trace_mac
                != control_attribution::retained_trace_bytes_mac(
                    &self.locator_key,
                    &exact_scope_sha256,
                    &trace.trace_id,
                    &trace.provider_id,
                    trace.registration_revision,
                    &trace_bytes,
                )
                .map_err(RecallAdmissionLedgerError::Attribution)?
        {
            return Err(RecallAdmissionLedgerError::InvalidControlMetadata);
        }
        Ok(Some(RetainedRecallExplainTraceV1 {
            exact_scope_sha256: exact_scope_sha256.clone(),
            recorded_at_utc_micros,
            trace,
        }))
    }

    /// Every retained trace identity for one request, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`RecallAdmissionLedgerError`] when SQLite refuses the read.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn explain_trace_ids_for_request(
        &self,
        exact_scope_sha256: &str,
        request_id: &str,
    ) -> Result<Vec<String>, RecallAdmissionLedgerError> {
        let candidates = {
            let connection = self.connection();
            let mut statement = connection
                .prepare(
                    "SELECT trace_id, provider_id, registration_revision
                     FROM recall_explain_traces
                     WHERE exact_scope_sha256 = ?1 AND request_id = ?2
                     ORDER BY recorded_at_utc_micros ASC, trace_id ASC",
                )
                .map_err(RecallAdmissionLedgerError::Sqlite)?;
            let rows = statement
                .query_map(params![exact_scope_sha256, request_id], |row| {
                    let trace: String = row.get(0)?;
                    let provider: String = row.get(1)?;
                    let registration_revision: i64 = row.get(2)?;
                    Ok((trace, provider, registration_revision))
                })
                .map_err(RecallAdmissionLedgerError::Sqlite)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(RecallAdmissionLedgerError::Sqlite)?
        };
        let mut identities = Vec::new();
        for (trace_id, provider_id, registration_revision) in candidates {
            let Some(registration_revision) = u64::try_from(registration_revision)
                .ok()
                .filter(|revision| *revision > 0)
            else {
                continue;
            };
            let expected_trace_id = control_attribution::retained_trace_id_with_key(
                &self.locator_key,
                exact_scope_sha256,
                request_id,
                &provider_id,
                registration_revision,
            )
            .map_err(RecallAdmissionLedgerError::Attribution)?;
            // Do not expose a trace reference that is not bound to the
            // durable recall key.
            if trace_id == expected_trace_id {
                let wire = format!("recall-trace-v1:{exact_scope_sha256}:{trace_id}");
                let Ok(reference) = control_attribution::RecallControlTraceRefV1::parse(&wire)
                else {
                    continue;
                };
                match self.explain_trace(&reference) {
                    Ok(Some(_)) => identities.push(wire),
                    Ok(None)
                    | Err(
                        RecallAdmissionLedgerError::InvalidControlMetadata
                        | RecallAdmissionLedgerError::Decode(_),
                    ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(identities)
    }

    /// Number of retained reports.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn report_count(&self) -> usize {
        self.connection()
            .query_row("SELECT COUNT(*) FROM recall_admission_reports", [], |row| {
                row.get::<_, i64>(0)
            })
            .ok()
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0)
    }

    /// Denied candidates retained for one report, in provider order.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn denied_candidates(
        &self,
        exact_scope_sha256: &str,
        request_id: &str,
    ) -> Result<Vec<tracedecay_memory_provider_registry::DeniedRecallCandidate>, rusqlite::Error>
    {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT candidate_id, stable_memory_ref, reason_json,
                    provider_claimed_scope_binding, provider_claimed_scope_sha256,
                    provider_claimed_temporal_state
             FROM recall_admission_denials
             WHERE exact_scope_sha256 = ?1 AND request_id = ?2
             ORDER BY position ASC",
        )?;
        let rows = statement.query_map(params![exact_scope_sha256, request_id], |row| {
            let candidate_id: String = row.get(0)?;
            let stable_memory_ref: Option<String> = row.get(1)?;
            let reason_json: String = row.get(2)?;
            let binding_wire: String = row.get(3)?;
            let provider_claimed_scope_binding =
                tracedecay_memory_provider_registry::ScopeBinding::from_wire(&binding_wire);
            let reason = serde_json::from_str::<RecallDenialReason>(&reason_json).ok();
            // Do not let the read helper turn a raw candidate id, stable ref,
            // or provider detail back into a retained result. Valid rows are
            // canonicalized and compared to the sanitized wire before they
            // cross this read boundary; malformed or unkeyed rows are withheld.
            let provider_claimed_scope_sha256: Option<String> = row.get(4)?;
            let provider_claimed_temporal_state: String = row.get(5)?;
            let retained = match (reason, provider_claimed_scope_binding) {
                (Some(reason), Some(provider_claimed_scope_binding))
                    if control_attribution::validate_retained_candidate_identity(&candidate_id)
                        .is_ok()
                        && stable_memory_ref
                            .as_deref()
                            .is_none_or(control_attribution::is_opaque_retained_memory_ref)
                        && sanitized_denial_reason_json(&reason)
                            .is_ok_and(|sanitized| sanitized == reason_json) =>
                {
                    Some(tracedecay_memory_provider_registry::DeniedRecallCandidate {
                        candidate_id,
                        stable_memory_ref,
                        reason,
                        provider_claimed_scope_binding,
                        provider_claimed_scope_sha256,
                        provider_claimed_temporal_state,
                    })
                }
                _ => None,
            };
            Ok(retained)
        })?;
        rows.filter_map(|row| match row {
            Ok(Some(retained)) => Some(Ok(retained)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
    }
}

impl RecallExplainTraceSinkV1 for RecallAdmissionLedgerV1 {
    fn record_explain_trace(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        self.retain_explain_trace(exact_scope_sha256, trace)
    }

    fn record_explain_trace_with_control(
        &self,
        exact_scope_sha256: &str,
        trace: &RecallExplainTraceV1,
        metadata: Option<&control_attribution::PreparedRecallControlMetadataV1>,
    ) -> Result<RecallAdmissionLedgerWriteV1, RecallAdmissionLedgerError> {
        self.retain_explain_trace_with_control(exact_scope_sha256, trace, metadata)
    }
}

impl RecallAdmissionObserver for RecallAdmissionLedgerV1 {
    fn observe_admission(
        &self,
        report: &RecallAdmissionReport,
    ) -> Result<(), RecallAdmissionAuditError> {
        self.record(report)
            .map(|_| ())
            .map_err(|source| RecallAdmissionAuditError {
                request_id: report.request_id.clone(),
                source: Box::new(source),
            })
    }
}

fn sanitized_denial_reason_json(reason: &RecallDenialReason) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(reason)?;
    sanitize_detail_fields(&mut value);
    serde_json::to_string(&value)
}

fn sanitize_detail_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                if key == "detail" {
                    *field = Value::String("provider_detail_withheld".to_owned());
                } else {
                    sanitize_detail_fields(field);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                sanitize_detail_fields(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn retained_temporal_state(value: &str) -> &'static str {
    match value {
        "current" => "current",
        "future" => "future",
        "expired" => "expired",
        "superseded" => "superseded",
        "revoked" => "revoked",
        "unknown" => "unknown",
        _ => "unknown",
    }
}

/// Content-free diagnostics for the isolated CLI journey, never a product API.
#[cfg(feature = "test-helpers")]
fn emit_host_history_recall_test_diagnostic(build: impl FnOnce() -> Value) {
    if std::env::var_os("TRACEDECAY_TEST_HOST_HISTORY_RECALL_DIAGNOSTICS").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    let encoded = build().to_string();
    if encoded.len() <= 4096 {
        eprintln!("[tracedecay] event=host_history_recall_test_diagnostic {encoded}");
    }
}
