//! Retained recall locators and bounded attribution reads from the existing ledger.
//!
//! These values record what the host confirmed for an earlier recall. They never
//! authorize a later action: the caller must resolve current canonical authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, TryLockError};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracedecay_memory_provider_registry::{
    OperationControl, OwnedExactScope, OwnedProviderId, RecallExplainHostDecisionV1,
    RecallExplainStageV1, RecallExplainTraceV1, RecallOutcomeScopeV1, TerminalCode,
    recall_admission::source_attribution::{
        RecallOriginScopeEvidenceV1, RecallOriginalSourceIdentityV1, RecallRecordedValidityV1,
        RecallSourceAttributionV1,
    },
};
use zeroize::Zeroizing;

use super::{PROJECT_RECALL_BUDGETS, RecallAdmissionLedgerV1};

const TRACE_PREFIX: &str = "recall-trace-v1:";
const ITEM_PREFIX: &str = "recall-item-v1:";
const MAX_SOURCES: usize = 64;
const MAX_ID_BYTES: usize = 1_024;
const MAX_SCOPE_BYTES: usize = 16_384;
const MAX_SOURCES_BYTES: usize = 1_048_576;
const MAX_DECISION_BYTES: usize = 16_384;
const MAX_DETAIL_BYTES: usize = 16_384;
const RETAINED_MEMORY_REF_PREFIX: &str = "recall-memory-ref-v1:";
const RETAINED_SOURCE_LOCATOR_PREFIX: &str = "recall-source-locator-v1:";
const RETAINED_CANDIDATE_ID_PREFIX: &str = "advisory.retained-identity-v1.";

/// Durable host secret used to project provider-controlled identities into
/// retained state. The material is held only in zeroizing storage and is never
/// included in a debug representation or a retained record.
#[derive(Clone)]
pub struct RecallLocatorKeyV1(Arc<Zeroizing<Vec<u8>>>);

impl RecallLocatorKeyV1 {
    pub fn from_material(material: Vec<u8>) -> Result<Self> {
        if material.len() != 32 {
            return Err(invalid("recall locator key length"));
        }
        Ok(Self(Arc::new(Zeroizing::new(material))))
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn for_test() -> Self {
        Self::from_material(vec![0xA5; 32]).expect("fixed recall locator test key")
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Debug for RecallLocatorKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecallLocatorKeyV1(REDACTED)")
    }
}

/// Typed refusal of retained attribution; absence never supplies authority.
#[derive(Debug, thiserror::Error)]
pub enum RecallControlAttributionErrorV1 {
    #[error("invalid retained recall control attribution: {0}")]
    Invalid(&'static str),
    #[error("retained recall control target was not found")]
    NotFound,
    #[error("retained recall has no host-confirmed control attribution")]
    MissingAuthority,
    #[error("retained recall control read stopped: {0:?}")]
    Control(TerminalCode),
    #[error("retained recall control storage read failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("retained recall control metadata could not be encoded or decoded: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, RecallControlAttributionErrorV1>;

#[derive(Clone, Copy)]
pub(super) struct RetainedItemBindingV1<'a> {
    pub(super) provider_id: &'a str,
    pub(super) registration_revision: u64,
    pub(super) provider_rank: usize,
    pub(super) candidate_id: &'a str,
}

/// Versioned address of the ledger's existing `(scope digest, trace id)` key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallControlTraceRefV1 {
    wire: String,
    exact_scope_sha256: String,
    trace_id: String,
}

impl RecallControlTraceRefV1 {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != TRACE_PREFIX.len() + 129 {
            return Err(invalid("trace reference length"));
        }
        let (scope, trace) = value
            .strip_prefix(TRACE_PREFIX)
            .and_then(|body| body.split_once(':'))
            .ok_or_else(|| invalid("trace reference version"))?;
        require_sha256(scope)?;
        require_sha256(trace)?;
        Ok(Self {
            wire: value.to_owned(),
            exact_scope_sha256: scope.to_owned(),
            trace_id: trace.to_owned(),
        })
    }

    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    pub fn exact_scope_sha256(&self) -> &str {
        &self.exact_scope_sha256
    }

    pub fn as_str(&self) -> &str {
        &self.wire
    }

    /// The scope digest is part of the retained trace key and is also the
    /// context input to every opaque source locator derived from that trace.
    /// Callers resolving a retained source must prove that the trace and the
    /// freshly mounted destination are the same scope before using it.
    pub fn is_bound_to_scope(&self, scope: &OwnedExactScope) -> bool {
        self.exact_scope_sha256 == scope.exact_scope_sha256()
    }
}

/// Original provider rank in the final trace, never a normalization-list rank.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallControlItemRefV1 {
    wire: String,
    provider_rank: usize,
}

impl RecallControlItemRefV1 {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > ITEM_PREFIX.len() + 20 {
            return Err(invalid("item reference length"));
        }
        let rank = value
            .strip_prefix(ITEM_PREFIX)
            .ok_or_else(|| invalid("item reference version"))?;
        let provider_rank = rank
            .parse::<usize>()
            .map_err(|_| invalid("item reference rank"))?;
        if rank != provider_rank.to_string() || !valid_rank(provider_rank) {
            return Err(invalid("item reference rank"));
        }
        Ok(Self {
            wire: value.to_owned(),
            provider_rank,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.wire
    }
}

/// Previously confirmed data, structurally checked but never fresh authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedRecallControlBindingV1 {
    pub stable_memory_ref: String,
    pub original_sources: Vec<RecallSourceAttributionV1>,
}

impl RetainedRecallControlBindingV1 {
    fn validated(&self, control: Option<&OperationControl>) -> Result<Self> {
        require_id(&self.stable_memory_ref)?;
        if !is_opaque_retained_memory_ref(&self.stable_memory_ref) {
            return Err(invalid("retained stable reference is not opaque"));
        }
        if self.original_sources.is_empty() || self.original_sources.len() > MAX_SOURCES {
            return Err(invalid("source count"));
        }
        let mut sources = self.original_sources.clone();
        let mut seen = BTreeSet::new();
        for source in &sources {
            if let Some(control) = control {
                control
                    .snapshot()
                    .map_err(RecallControlAttributionErrorV1::Control)?;
            }
            let attribution = source
                .to_owned_attribution()
                .map_err(|_| invalid("original source attribution"))?;
            attribution
                .origin_scope
                .recorded_scope()
                .map_err(|_| invalid("missing recorded original scope"))?;
            require_id(&source.source.observation_id)?;
            if !seen.insert(source.source.observation_id.clone()) {
                return Err(invalid("duplicate source observation identity"));
            }
        }
        sources.sort_by(|left, right| left.source.observation_id.cmp(&right.source.observation_id));
        Ok(Self {
            stable_memory_ref: self.stable_memory_ref.clone(),
            original_sources: sources,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PreparedItemV1 {
    candidate_id: String,
    binding: RetainedRecallControlBindingV1,
    original_sources_json: String,
    /// Keyed integrity for the opaque binding, bound to the durable recall key.
    control_binding_mac: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeBindingEnvelopeV1 {
    version: u32,
    delivery_scope: RecallOutcomeScopeV1,
    scope_binding_sha256: String,
}

/// Deterministic metadata prepared before entering the existing trace transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRecallControlMetadataV1 {
    trace_ref: RecallControlTraceRefV1,
    delivery_scope_json: String,
    scope_binding_mac: String,
    metadata_sha256: String,
    control_metadata_mac: String,
    rows: BTreeMap<usize, PreparedItemV1>,
}

impl PreparedRecallControlMetadataV1 {
    /// `bindings` must come from final successful host hydration, keyed by the
    /// original candidate identity. This function confers no source authority.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn prepare(
        trace: &RecallExplainTraceV1,
        delivery_scope: &OwnedExactScope,
        bindings: &BTreeMap<String, RetainedRecallControlBindingV1>,
    ) -> Result<Self> {
        Self::prepare_with_key(
            trace,
            delivery_scope,
            bindings,
            &RecallLocatorKeyV1::for_test(),
        )
    }

    pub fn prepare_with_key(
        trace: &RecallExplainTraceV1,
        delivery_scope: &OwnedExactScope,
        bindings: &BTreeMap<String, RetainedRecallControlBindingV1>,
        locator_key: &RecallLocatorKeyV1,
    ) -> Result<Self> {
        delivery_scope
            .validate()
            .map_err(|_| invalid("delivery scope"))?;
        OwnedProviderId::new(&trace.provider_id).map_err(|_| invalid("provider identity"))?;
        if trace.registration_revision == 0
            || trace.registration_revision > i64::MAX as u64
            || trace.requested_count != trace.items.len()
            || trace.requested_count as u64 > PROJECT_RECALL_BUDGETS.maximum_candidates
        {
            return Err(invalid("trace identity or candidate bound"));
        }
        if trace.trace_id
            != retained_trace_id_with_key(
                locator_key,
                &delivery_scope.exact_scope_sha256(),
                &trace.request_id,
                &trace.provider_id,
                trace.registration_revision,
            )?
        {
            return Err(invalid("trace identity"));
        }
        let trace_ref = RecallControlTraceRefV1::parse(&format!(
            "{TRACE_PREFIX}{}:{}",
            delivery_scope.exact_scope_sha256(),
            trace.trace_id
        ))?;
        let delivery_scope_json = serde_json::to_string(&ScopeBindingEnvelopeV1 {
            version: 1,
            delivery_scope: scope_wire(delivery_scope),
            scope_binding_sha256: scope_binding_sha256(
                &trace.provider_id,
                trace.registration_revision,
                delivery_scope,
            )?,
        })?;
        require_size(&delivery_scope_json, MAX_SCOPE_BYTES)?;
        let scope_binding_mac = retained_scope_binding_mac(
            locator_key,
            &trace_ref.exact_scope_sha256,
            trace_ref.trace_id(),
            &trace.provider_id,
            trace.registration_revision,
            delivery_scope_json.as_bytes(),
        )?;
        let mut rows = BTreeMap::new();
        let mut candidates = BTreeSet::new();
        for (rank, item) in trace.items.iter().enumerate() {
            validate_retained_trace_candidate_id(&item.candidate_id)?;
            if item.provider_rank != rank
                || !candidates.insert(item.candidate_id.as_str())
                || item.stage != item.host_decision.stage()
            {
                return Err(invalid("final trace rank or decision"));
            }
            if !eligible_stage(item.stage) {
                continue;
            }
            let Some(binding) = bindings.get(&item.candidate_id) else {
                continue;
            };
            let binding = redact_control_binding(
                locator_key,
                &trace.provider_id,
                &trace_ref,
                trace.registration_revision,
                rank,
                &item.candidate_id,
                binding,
            )?
            .validated(None)?;
            let original_sources_json = serde_json::to_string(&binding.original_sources)?;
            require_size(&original_sources_json, MAX_SOURCES_BYTES)?;
            let control_binding_mac = binding_mac(
                locator_key,
                &trace.provider_id,
                trace.registration_revision,
                &trace_ref.exact_scope_sha256,
                rank,
                &item.candidate_id,
                &binding,
            )?;
            rows.insert(
                rank,
                PreparedItemV1 {
                    candidate_id: item.candidate_id.clone(),
                    binding,
                    original_sources_json,
                    control_binding_mac,
                },
            );
        }
        if bindings
            .keys()
            .any(|candidate| !candidates.contains(candidate.as_str()))
        {
            return Err(invalid("binding outside final trace"));
        }
        // A deterministic struct/tuple and BTreeMap keep hashing independent of
        // caller insertion order. Scope retains every identity, not just its hash.
        let bytes = serde_json::to_vec(&(
            "recall-control-metadata-v1",
            &trace.provider_id,
            trace.registration_revision,
            &delivery_scope_json,
            &rows,
        ))?;
        let metadata_sha256 = tracedecay_domain::canonical_text::sha256_hex(&bytes);
        let control_metadata_mac = retained_control_metadata_mac_from_parts(
            locator_key,
            &trace_ref.exact_scope_sha256,
            trace_ref.trace_id(),
            &trace.provider_id,
            trace.registration_revision,
            &delivery_scope_json,
            &metadata_mac_rows(&rows),
        )?;
        Ok(Self {
            trace_ref,
            delivery_scope_json,
            scope_binding_mac,
            metadata_sha256,
            control_metadata_mac,
            rows,
        })
    }

    pub(crate) fn delivery_scope_json(&self) -> &str {
        &self.delivery_scope_json
    }
    pub(crate) fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }

    pub(crate) fn scope_binding_mac(&self) -> &str {
        &self.scope_binding_mac
    }

    pub(crate) fn control_metadata_mac(&self) -> &str {
        &self.control_metadata_mac
    }

    /// Use only after the enclosing atomic trace write reports success.
    pub fn trace_ref(&self) -> &RecallControlTraceRefV1 {
        &self.trace_ref
    }

    pub fn item_ref(&self, provider_rank: usize) -> Option<RecallControlItemRefV1> {
        self.rows.get(&provider_rank)?;
        Some(RecallControlItemRefV1 {
            wire: format!("{ITEM_PREFIX}{provider_rank}"),
            provider_rank,
        })
    }

    pub(crate) fn item_sql(&self, provider_rank: usize) -> Option<(&str, &str, &str)> {
        self.rows.get(&provider_rank).map(|row| {
            (
                row.binding.stable_memory_ref.as_str(),
                row.original_sources_json.as_str(),
                row.control_binding_mac.as_str(),
            )
        })
    }

    pub(crate) fn matches_trace(
        &self,
        scope_sha256: &str,
        trace: &RecallExplainTraceV1,
        locator_key: &RecallLocatorKeyV1,
    ) -> Result<bool> {
        if self.trace_ref.exact_scope_sha256 != scope_sha256
            || self.trace_ref.trace_id != trace.trace_id
        {
            return Ok(false);
        }
        if trace.requested_count != trace.items.len()
            || trace.registration_revision == 0
            || trace.registration_revision > i64::MAX as u64
        {
            return Ok(false);
        }
        let scope = decode_scope_envelope(
            &self.delivery_scope_json,
            &trace.provider_id,
            trace.registration_revision,
        )?;
        if scope.exact_scope_sha256() != self.trace_ref.exact_scope_sha256 {
            return Ok(false);
        }
        if self.scope_binding_mac
            != retained_scope_binding_mac(
                locator_key,
                &self.trace_ref.exact_scope_sha256,
                self.trace_ref.trace_id(),
                &trace.provider_id,
                trace.registration_revision,
                self.delivery_scope_json.as_bytes(),
            )?
        {
            return Ok(false);
        }
        let mut candidates = BTreeSet::new();
        for (rank, item) in trace.items.iter().enumerate() {
            if item.provider_rank != rank
                || item.stage != item.host_decision.stage()
                || !candidates.insert(item.candidate_id.as_str())
            {
                return Ok(false);
            }
            let Some(row) = self.rows.get(&rank) else {
                if eligible_stage(item.stage) {
                    // A selected/injected item may legitimately have no
                    // source binding, but the row must still be absent only
                    // when preparation had no binding for it.
                    continue;
                }
                continue;
            };
            if row.candidate_id != item.candidate_id || !eligible_stage(item.stage) {
                return Ok(false);
            }
            row.binding.validated(None)?;
            if serde_json::to_string(&row.binding.original_sources)? != row.original_sources_json {
                return Ok(false);
            }
            let expected_mac = binding_mac(
                locator_key,
                &trace.provider_id,
                trace.registration_revision,
                &self.trace_ref.exact_scope_sha256,
                rank,
                &row.candidate_id,
                &row.binding,
            )?;
            if expected_mac != row.control_binding_mac {
                return Ok(false);
            }
        }
        if self.rows.keys().any(|rank| {
            trace
                .items
                .get(*rank)
                .is_none_or(|item| !eligible_stage(item.stage))
        }) {
            return Ok(false);
        }
        let bytes = serde_json::to_vec(&(
            "recall-control-metadata-v1",
            &trace.provider_id,
            trace.registration_revision,
            &self.delivery_scope_json,
            &self.rows,
        ))?;
        if tracedecay_domain::canonical_text::sha256_hex(&bytes) != self.metadata_sha256 {
            return Ok(false);
        }
        Ok(self.control_metadata_mac
            == retained_control_metadata_mac_from_parts(
                locator_key,
                &self.trace_ref.exact_scope_sha256,
                self.trace_ref.trace_id(),
                &trace.provider_id,
                trace.registration_revision,
                &self.delivery_scope_json,
                &metadata_mac_rows(&self.rows),
            )?)
    }
}

/// Retained producing identity and delivery scope; the caller must authorize them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecallControlScopeV1 {
    pub provider_id: OwnedProviderId,
    pub registration_revision: u64,
    pub delivery_scope: OwnedExactScope,
}

/// Exact retained member selected by observation identity, including multi-source items.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecallControlSourceV1 {
    /// In-memory context for re-redacting the persisted source locator. The
    /// trace itself is never serialized into the control tables.
    pub trace: RecallControlTraceRefV1,
    pub scope: RetainedRecallControlScopeV1,
    pub candidate_id: String,
    pub provider_rank: usize,
    pub stable_memory_ref: String,
    pub original_source: RecallSourceAttributionV1,
}

impl RecallAdmissionLedgerV1 {
    /// Execute on the caller's existing blocking pool with its original control.
    pub fn read_retained_control_scope(
        &self,
        trace: &RecallControlTraceRefV1,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        self.with_control_connection(control, |connection| {
            validate_retained_trace_identity_on_connection(connection, trace, &self.locator_key)?;
            read_retained_control_scope_on_connection(connection, trace, control, &self.locator_key)
        })
    }

    /// One composite-key JOIN reads a single item; siblings are never fetched.
    pub fn read_retained_control_source(
        &self,
        trace: &RecallControlTraceRefV1,
        item: &RecallControlItemRefV1,
        observation_id: &str,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlSourceV1> {
        control
            .snapshot()
            .map_err(RecallControlAttributionErrorV1::Control)?;
        require_id(observation_id)?;
        let locator_key = self.locator_key.clone();
        self.with_control_connection(control, |connection| {
            validate_retained_trace_identity_on_connection(connection, trace, &locator_key)?;
            let result = connection
                .query_row(
                    "SELECT substr(CAST(t.exact_scope_sha256 AS BLOB),1,65),
                        substr(CAST(t.trace_id AS BLOB),1,65),
                        substr(CAST(t.provider_id AS BLOB),1,1025), t.registration_revision,
                        substr(CAST(t.delivery_scope_json AS BLOB),1,16385),
                        substr(CAST(t.control_metadata_sha256 AS BLOB),1,65),
                        substr(CAST(t.scope_binding_mac AS BLOB),1,65),
                        i.provider_rank, substr(CAST(i.candidate_id AS BLOB),1,1025),
                        substr(CAST(i.stage AS BLOB),1,65),
                        substr(CAST(i.host_reason_code AS BLOB),1,1025),
                        substr(CAST(i.host_reason_detail AS BLOB),1,16385),
                        substr(CAST(i.host_decision_json AS BLOB),1,16385),
                        substr(CAST(i.stable_memory_ref AS BLOB),1,1025),
                        substr(CAST(i.original_sources_json AS BLOB),1,1048577),
                        substr(CAST(i.control_binding_mac AS BLOB),1,65),
                        substr(CAST(i.provider_explanation_json AS BLOB),1,16385),
                        substr(CAST(i.section AS BLOB),1,1025), i.tokens,
                        substr(CAST(i.item_mac AS BLOB),1,65)
                 FROM recall_explain_traces t
                 JOIN recall_explain_trace_items i
                   ON i.exact_scope_sha256=t.exact_scope_sha256 AND i.trace_id=t.trace_id
                 WHERE t.exact_scope_sha256=?1 AND t.trace_id=?2 AND i.provider_rank=?3 LIMIT 1",
                    params![
                        trace.exact_scope_sha256,
                        trace.trace_id,
                        item.provider_rank as i64
                    ],
                    |row| {
                        Ok(decode_source(
                            row,
                            trace,
                            item,
                            observation_id,
                            control,
                            &locator_key,
                        ))
                    },
                )
                .optional()?;
            result.ok_or(RecallControlAttributionErrorV1::NotFound)?
        })
    }

    fn with_control_connection<T>(
        &self,
        control: &OperationControl,
        read: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let connection = loop {
            let remaining = control
                .snapshot()
                .map_err(RecallControlAttributionErrorV1::Control)?;
            match self.connection.try_lock() {
                Ok(connection) => break connection,
                Err(TryLockError::Poisoned(_)) => return Err(invalid("ledger mutex poisoned")),
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(remaining.remaining_millis.min(1)));
                }
            }
        };
        let remaining = control
            .snapshot()
            .map_err(RecallControlAttributionErrorV1::Control)?;
        let previous: i64 =
            connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
        let previous = u64::try_from(previous).map_err(|_| invalid("ledger busy timeout"))?;
        // A short busy allowance also bounds cancellation latency inside SQLite.
        connection.busy_timeout(Duration::from_millis(remaining.remaining_millis.min(10)))?;
        let restore = RestoreBusyTimeout(&connection, Duration::from_millis(previous));
        let result = read(&connection);
        drop(restore);
        control
            .snapshot()
            .map_err(RecallControlAttributionErrorV1::Control)?;
        result
    }
}

/// Shares the existing scope query with the read-only test reader's transaction.
fn read_retained_control_scope_on_connection(
    connection: &Connection,
    trace: &RecallControlTraceRefV1,
    control: &OperationControl,
    locator_key: &RecallLocatorKeyV1,
) -> Result<RetainedRecallControlScopeV1> {
    control
        .snapshot()
        .map_err(RecallControlAttributionErrorV1::Control)?;
    let result = connection
        .query_row(
            "SELECT substr(CAST(exact_scope_sha256 AS BLOB),1,65),
                substr(CAST(trace_id AS BLOB),1,65),
                substr(CAST(provider_id AS BLOB),1,1025), registration_revision,
                substr(CAST(delivery_scope_json AS BLOB),1,16385),
                substr(CAST(control_metadata_sha256 AS BLOB),1,65),
                substr(CAST(scope_binding_mac AS BLOB),1,65)
         FROM recall_explain_traces
         WHERE exact_scope_sha256=?1 AND trace_id=?2 LIMIT 1",
            params![trace.exact_scope_sha256, trace.trace_id],
            |row| Ok(decode_scope(row, trace, locator_key)),
        )
        .optional();
    control
        .snapshot()
        .map_err(RecallControlAttributionErrorV1::Control)?;
    let Some(scope) = result? else {
        return Err(RecallControlAttributionErrorV1::NotFound);
    };
    let scope = scope?;
    validate_retained_control_items_on_connection(connection, trace, control, locator_key, &scope)?;
    Ok(scope)
}

/// Validate every retained item before a scope read crosses the control
/// boundary. Scope callers do not request a source row, but a legacy trace
/// could still carry raw candidate, dedup, or source bytes beside an otherwise
/// valid scope envelope. Quarantine the complete control trace instead of
/// letting a later operation observe a partially trusted record.
fn validate_retained_control_items_on_connection(
    connection: &Connection,
    trace: &RecallControlTraceRefV1,
    control: &OperationControl,
    locator_key: &RecallLocatorKeyV1,
    scope: &RetainedRecallControlScopeV1,
) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT provider_rank,
                substr(CAST(candidate_id AS BLOB),1,1025),
                substr(CAST(stage AS BLOB),1,65),
                substr(CAST(host_reason_code AS BLOB),1,1025),
                substr(CAST(host_reason_detail AS BLOB),1,16385),
                substr(CAST(host_decision_json AS BLOB),1,16385),
                substr(CAST(provider_explanation_json AS BLOB),1,16385),
                substr(CAST(section AS BLOB),1,1025), tokens,
                substr(CAST(stable_memory_ref AS BLOB),1,1025),
                substr(CAST(original_sources_json AS BLOB),1,1048577),
                substr(CAST(control_binding_mac AS BLOB),1,65),
                substr(CAST(item_mac AS BLOB),1,65)
         FROM recall_explain_trace_items
         WHERE exact_scope_sha256=?1 AND trace_id=?2
         ORDER BY provider_rank ASC",
    )?;
    // The query deliberately bounds each value as bytes before it crosses the
    // SQLite boundary. Read those values as bytes here so malformed UTF-8 is
    // rejected by our retained-field validator instead of being surfaced as a
    // rusqlite type error (or silently replaced by SQLite's TEXT conversion).
    let rows = statement.query_map(params![trace.exact_scope_sha256, trace.trace_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Option<Vec<u8>>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Option<Vec<u8>>>(6)?,
            row.get::<_, Option<Vec<u8>>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<Vec<u8>>>(9)?,
            row.get::<_, Option<Vec<u8>>>(10)?,
            row.get::<_, Option<Vec<u8>>>(11)?,
            row.get::<_, Option<Vec<u8>>>(12)?,
        ))
    })?;
    let mut metadata_rows = BTreeMap::new();
    for row in rows {
        control
            .snapshot()
            .map_err(RecallControlAttributionErrorV1::Control)?;
        let (
            provider_rank,
            candidate_id_bytes,
            stage_bytes,
            host_reason_code_bytes,
            host_reason_detail_bytes,
            host_decision_json_bytes,
            provider_explanation_json_bytes,
            section_bytes,
            tokens,
            stable_memory_ref_bytes,
            original_sources_json_bytes,
            control_binding_mac_bytes,
            item_mac_bytes,
        ) = row?;
        let candidate_id = bounded_text_bytes(candidate_id_bytes, MAX_ID_BYTES)?;
        let stage = bounded_text_bytes(stage_bytes, 64)?;
        let host_reason_code = bounded_text_bytes(host_reason_code_bytes, MAX_ID_BYTES)?;
        let host_reason_detail = host_reason_detail_bytes
            .map(|bytes| bounded_text_bytes(bytes, MAX_DETAIL_BYTES))
            .transpose()?;
        let host_decision_json = bounded_text_bytes(host_decision_json_bytes, MAX_DECISION_BYTES)?;
        let provider_explanation_json = bounded_text_bytes(
            provider_explanation_json_bytes
                .ok_or_else(|| invalid("missing retained provider explanation"))?,
            MAX_DECISION_BYTES,
        )?;
        let section = section_bytes
            .map(|bytes| bounded_text_bytes(bytes, MAX_ID_BYTES))
            .transpose()?;
        let stable_memory_ref = stable_memory_ref_bytes
            .map(|bytes| bounded_text_bytes(bytes, MAX_ID_BYTES))
            .transpose()?;
        let original_sources_json = original_sources_json_bytes
            .map(|bytes| bounded_text_bytes(bytes, MAX_SOURCES_BYTES))
            .transpose()?;
        let control_binding_mac = control_binding_mac_bytes
            .map(|bytes| bounded_text_bytes(bytes, 64))
            .transpose()?;
        let item_mac = item_mac_bytes
            .map(|bytes| bounded_text_bytes(bytes, 64))
            .transpose()?
            .ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
        require_sha256(&item_mac)?;
        validate_retained_trace_candidate_id(&candidate_id)?;
        let host_decision: RecallExplainHostDecisionV1 = serde_json::from_str(&host_decision_json)?;
        if host_decision.stage().label() != stage
            || host_reason_code != host_decision.code()
            || host_reason_detail != host_decision.detail()
        {
            return Err(invalid("retained item decision projection"));
        }
        if let RecallExplainHostDecisionV1::Deduplicated {
            duplicate_of_candidate_id,
            ..
        } = &host_decision
        {
            validate_retained_trace_candidate_id(duplicate_of_candidate_id)?;
        }
        let provider_explanation: tracedecay_memory_provider_registry::RecallExplainProviderExplanationV1 =
            serde_json::from_str(&provider_explanation_json)?;
        let provider_rank = usize::try_from(provider_rank)
            .ok()
            .filter(|rank| valid_rank(*rank))
            .ok_or_else(|| invalid("retained provider rank"))?;
        let item = tracedecay_memory_provider_registry::RecallExplainItemV1 {
            candidate_id: candidate_id.clone(),
            provider_rank,
            stage: host_decision.stage(),
            host_reason_code: host_reason_code.clone(),
            host_reason_detail: host_reason_detail.clone(),
            host_decision,
            provider_explanation,
            section,
            tokens: tokens
                .map(|value| u64::try_from(value).map_err(|_| invalid("retained tokens")))
                .transpose()?,
        };
        let item_bytes = serde_json::to_vec(&item)?;
        let expected_item_mac = retained_item_bytes_mac(
            locator_key,
            trace.exact_scope_sha256(),
            trace.trace_id(),
            RetainedItemBindingV1 {
                provider_id: scope.provider_id.as_str(),
                registration_revision: scope.registration_revision,
                provider_rank,
                candidate_id: &candidate_id,
            },
            &item_bytes,
        )?;
        if expected_item_mac != item_mac {
            return Err(invalid("retained item mac"));
        }
        let metadata_row = match (
            stable_memory_ref.as_ref(),
            original_sources_json.as_ref(),
            control_binding_mac.as_ref(),
        ) {
            (None, None, None) => None,
            (Some(stable_memory_ref), Some(original_sources_json), Some(retained_binding_mac)) => {
                if !is_opaque_retained_memory_ref(stable_memory_ref.as_str()) {
                    return Err(invalid("retained stable reference is not opaque"));
                }
                require_sha256(retained_binding_mac.as_str())?;
                let sources = serde_json::from_str::<BoundedSourcesV1>(original_sources_json)?;
                for source in &sources.0 {
                    validate_opaque_retained_source(source)?;
                }
                let binding = RetainedRecallControlBindingV1 {
                    stable_memory_ref: (*stable_memory_ref).clone(),
                    original_sources: sources.0,
                }
                .validated(None)?;
                let expected_mac = binding_mac(
                    locator_key,
                    scope.provider_id.as_str(),
                    scope.registration_revision,
                    trace.exact_scope_sha256(),
                    provider_rank,
                    &candidate_id,
                    &binding,
                )?;
                if expected_mac.as_str() != retained_binding_mac.as_str() {
                    return Err(invalid("retained source binding mac"));
                }
                Some((
                    candidate_id.clone(),
                    stable_memory_ref.clone(),
                    original_sources_json.clone(),
                    retained_binding_mac.clone(),
                ))
            }
            _ => return Err(invalid("retained control binding projection")),
        };
        if let Some(metadata_row) = metadata_row {
            metadata_rows.insert(provider_rank, metadata_row);
        }
    }
    let (delivery_scope_json, control_metadata_mac): (Option<Vec<u8>>, Option<Vec<u8>>) =
        connection
            .query_row(
                "SELECT substr(CAST(delivery_scope_json AS BLOB),1,16385),
                    substr(CAST(control_metadata_mac AS BLOB),1,65)
             FROM recall_explain_traces
             WHERE exact_scope_sha256=?1 AND trace_id=?2 LIMIT 1",
                params![trace.exact_scope_sha256, trace.trace_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(RecallControlAttributionErrorV1::NotFound)?;
    let delivery_scope_json = bounded_text_bytes(
        delivery_scope_json.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?,
        MAX_SCOPE_BYTES,
    )?;
    let control_metadata_mac = bounded_text_bytes(
        control_metadata_mac.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?,
        64,
    )?;
    require_sha256(&control_metadata_mac)?;
    if retained_control_metadata_mac_from_parts(
        locator_key,
        trace.exact_scope_sha256(),
        trace.trace_id(),
        scope.provider_id.as_str(),
        scope.registration_revision,
        &delivery_scope_json,
        &metadata_rows,
    )? != control_metadata_mac
    {
        return Err(invalid("retained control metadata mac"));
    }
    Ok(())
}

struct RestoreBusyTimeout<'a>(&'a Connection, Duration);

impl Drop for RestoreBusyTimeout<'_> {
    fn drop(&mut self) {
        let _ = self.0.busy_timeout(self.1);
    }
}

/// Refuses trace references produced by the pre-keyed registry identity
/// scheme. The request/provider/revision tuple is read from the same header
/// row as the control lookup, so a caller cannot make an old raw trace id look
/// valid by presenting a different context.
fn validate_retained_trace_identity_on_connection(
    connection: &Connection,
    trace: &RecallControlTraceRefV1,
    locator_key: &RecallLocatorKeyV1,
) -> Result<()> {
    let identity: Option<(String, String, i64)> = connection
        .query_row(
            "SELECT request_id, provider_id, registration_revision
             FROM recall_explain_traces
             WHERE exact_scope_sha256=?1 AND trace_id=?2 LIMIT 1",
            params![trace.exact_scope_sha256, trace.trace_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((request_id, provider_id, registration_revision)) = identity else {
        return Err(RecallControlAttributionErrorV1::NotFound);
    };
    let registration_revision = u64::try_from(registration_revision)
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| invalid("retained trace registration revision"))?;
    let expected = retained_trace_id_with_key(
        locator_key,
        trace.exact_scope_sha256(),
        &request_id,
        &provider_id,
        registration_revision,
    )?;
    if expected != trace.trace_id() {
        return Err(invalid("retained trace identity"));
    }
    Ok(())
}

fn decode_scope(
    row: &Row<'_>,
    trace: &RecallControlTraceRefV1,
    locator_key: &RecallLocatorKeyV1,
) -> Result<RetainedRecallControlScopeV1> {
    let scope_sha256 = required_text(row, 0, 64)?;
    let trace_id = required_text(row, 1, 64)?;
    if scope_sha256 != trace.exact_scope_sha256 || trace_id != trace.trace_id {
        return Err(invalid("retained composite identity"));
    }
    let provider = required_text(row, 2, MAX_ID_BYTES)?;
    require_id(&provider)?;
    let provider_id =
        OwnedProviderId::new(provider).map_err(|_| invalid("retained provider identity"))?;
    let revision: i64 = row.get(3)?;
    let registration_revision = u64::try_from(revision)
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| invalid("retained registration revision"))?;
    let scope_json = optional_text(row, 4, MAX_SCOPE_BYTES)?
        .ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    let metadata_sha256 =
        optional_text(row, 5, 64)?.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    require_sha256(&metadata_sha256)?;
    let scope_binding_mac =
        optional_text(row, 6, 64)?.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    require_sha256(&scope_binding_mac)?;
    let expected_scope_binding_mac = retained_scope_binding_mac(
        locator_key,
        &scope_sha256,
        &trace_id,
        provider_id.as_str(),
        registration_revision,
        scope_json.as_bytes(),
    )?;
    if expected_scope_binding_mac != scope_binding_mac {
        return Err(invalid("retained scope binding mac"));
    }
    let delivery_scope =
        decode_scope_envelope(&scope_json, provider_id.as_str(), registration_revision)?;
    if delivery_scope.exact_scope_sha256() != scope_sha256 {
        return Err(invalid("retained full scope digest"));
    }
    Ok(RetainedRecallControlScopeV1 {
        provider_id,
        registration_revision,
        delivery_scope,
    })
}

fn decode_source(
    row: &Row<'_>,
    trace: &RecallControlTraceRefV1,
    item: &RecallControlItemRefV1,
    observation_id: &str,
    control: &OperationControl,
    locator_key: &RecallLocatorKeyV1,
) -> Result<RetainedRecallControlSourceV1> {
    let scope = decode_scope(row, trace, locator_key)?;
    let rank: i64 = row.get(7)?;
    if usize::try_from(rank).ok() != Some(item.provider_rank) || !valid_rank(item.provider_rank) {
        return Err(invalid("retained provider rank"));
    }
    let candidate_id = required_text(row, 8, MAX_ID_BYTES)?;
    validate_retained_trace_candidate_id(&candidate_id)?;
    let stage = required_text(row, 9, 64)?;
    let host_reason_code = required_text(row, 10, MAX_ID_BYTES)?;
    let host_reason_detail = optional_text(row, 11, MAX_DETAIL_BYTES)?;
    let decision: RecallExplainHostDecisionV1 =
        serde_json::from_str(&required_text(row, 12, MAX_DECISION_BYTES)?)?;
    if !eligible_stage(decision.stage()) || decision.stage().label() != stage {
        return Err(invalid("retained item was not selected or injected"));
    }
    if host_reason_code != decision.code() || host_reason_detail != decision.detail() {
        return Err(invalid("retained item decision projection"));
    }
    let stable_memory_ref = optional_text(row, 13, MAX_ID_BYTES)?
        .ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    if !is_opaque_locator(&stable_memory_ref, RETAINED_MEMORY_REF_PREFIX) {
        return Err(invalid("retained stable reference is not opaque"));
    }
    let sources_json = optional_text(row, 14, MAX_SOURCES_BYTES)?
        .ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    let retained_binding_mac =
        optional_text(row, 15, 64)?.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    require_sha256(&retained_binding_mac)?;
    let provider_explanation_json = required_text(row, 16, MAX_DECISION_BYTES)?;
    let provider_explanation: tracedecay_memory_provider_registry::RecallExplainProviderExplanationV1 =
        serde_json::from_str(&provider_explanation_json)?;
    let section = optional_text(row, 17, MAX_ID_BYTES)?;
    let tokens: Option<i64> = row.get(18)?;
    let item_mac =
        optional_text(row, 19, 64)?.ok_or(RecallControlAttributionErrorV1::MissingAuthority)?;
    require_sha256(&item_mac)?;
    let provider_rank = item.provider_rank;
    let item_value = tracedecay_memory_provider_registry::RecallExplainItemV1 {
        candidate_id: candidate_id.clone(),
        provider_rank,
        stage: decision.stage(),
        host_reason_code,
        host_reason_detail,
        host_decision: decision.clone(),
        provider_explanation,
        section,
        tokens: tokens
            .map(|value| u64::try_from(value).map_err(|_| invalid("retained tokens")))
            .transpose()?,
    };
    let item_binding = RetainedItemBindingV1 {
        provider_id: scope.provider_id.as_str(),
        registration_revision: scope.registration_revision,
        provider_rank,
        candidate_id: &candidate_id,
    };
    let expected_item_mac = retained_item_bytes_mac(
        locator_key,
        trace.exact_scope_sha256(),
        trace.trace_id(),
        item_binding,
        &serde_json::to_vec(&item_value)?,
    )?;
    if expected_item_mac != item_mac {
        return Err(invalid("retained item mac"));
    }
    let binding = RetainedRecallControlBindingV1 {
        stable_memory_ref,
        original_sources: serde_json::from_str::<BoundedSourcesV1>(&sources_json)?.0,
    };
    for source in &binding.original_sources {
        validate_opaque_retained_source(source)?;
    }
    let binding = binding.validated(Some(control))?;
    if retained_binding_mac
        != binding_mac(
            locator_key,
            scope.provider_id.as_str(),
            scope.registration_revision,
            &scope.delivery_scope.exact_scope_sha256(),
            item.provider_rank,
            &candidate_id,
            &binding,
        )?
    {
        return Err(invalid("retained source binding mac"));
    }
    control
        .snapshot()
        .map_err(RecallControlAttributionErrorV1::Control)?;
    let retained_observation_id = opaque_control_locator(
        locator_key,
        RETAINED_SOURCE_LOCATOR_PREFIX,
        trace,
        item_binding,
        "observation_id",
        observation_id,
    )?;
    let original_source = binding
        .original_sources
        .into_iter()
        .find(|source| source.source.observation_id == retained_observation_id)
        .ok_or_else(|| invalid("observation identity outside retained item"))?;
    Ok(RetainedRecallControlSourceV1 {
        trace: trace.clone(),
        scope,
        candidate_id,
        provider_rank: item.provider_rank,
        stable_memory_ref: binding.stable_memory_ref,
        original_source,
    })
}

fn optional_text(row: &Row<'_>, column: usize, maximum: usize) -> Result<Option<String>> {
    let bytes: Option<Vec<u8>> = row.get(column)?;
    bytes
        .map(|bytes| {
            if bytes.len() > maximum {
                return Err(invalid("retained field byte bound"));
            }
            String::from_utf8(bytes).map_err(|_| invalid("retained field UTF-8"))
        })
        .transpose()
}

fn required_text(row: &Row<'_>, column: usize, maximum: usize) -> Result<String> {
    optional_text(row, column, maximum)?.ok_or_else(|| invalid("missing retained field"))
}

fn bounded_text_bytes(bytes: Vec<u8>, maximum: usize) -> Result<String> {
    if bytes.len() > maximum {
        return Err(invalid("retained field byte bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("retained field UTF-8"))
}

fn binding_mac(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    registration_revision: u64,
    exact_scope_sha256: &str,
    provider_rank: usize,
    candidate_id: &str,
    binding: &RetainedRecallControlBindingV1,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        "recall-control-binding-mac-v1",
        provider_id,
        registration_revision,
        exact_scope_sha256,
        provider_rank,
        candidate_id,
        binding,
    ))?;
    hmac_hex(
        locator_key,
        b"tracedecay.recall-control-binding-mac.v1",
        &[&bytes],
    )
}

/// Redacts all provider/source locators before control metadata can enter the
/// durable trace tables. The transformation is idempotent so prepared
/// metadata can be revalidated against its own retained rows.
fn redact_control_binding(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    binding: &RetainedRecallControlBindingV1,
) -> Result<RetainedRecallControlBindingV1> {
    let stable_memory_ref = opaque_control_locator(
        locator_key,
        RETAINED_MEMORY_REF_PREFIX,
        trace,
        RetainedItemBindingV1 {
            provider_id,
            registration_revision,
            provider_rank,
            candidate_id,
        },
        "stable_memory_ref",
        &binding.stable_memory_ref,
    )?;
    let original_sources = binding
        .original_sources
        .iter()
        .map(|source| {
            redact_retained_source_attribution_with_key(
                locator_key,
                provider_id,
                trace,
                registration_revision,
                provider_rank,
                candidate_id,
                source,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RetainedRecallControlBindingV1 {
        stable_memory_ref,
        original_sources,
    })
}

pub fn redact_retained_source_attribution_with_key(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    source: &RecallSourceAttributionV1,
) -> Result<RecallSourceAttributionV1> {
    let binding = RetainedItemBindingV1 {
        provider_id,
        registration_revision,
        provider_rank,
        candidate_id,
    };
    let locator = |field: &str, value: &str| {
        opaque_control_locator(
            locator_key,
            RETAINED_SOURCE_LOCATOR_PREFIX,
            trace,
            binding,
            field,
            value,
        )
    };
    let source_identity = &source.source;
    let redacted_source = RecallOriginalSourceIdentityV1 {
        canonical_provider_id: "recall.opaque".to_owned(),
        canonical_session_id: locator(
            "canonical_session_id",
            &source_identity.canonical_session_id,
        )?,
        source_key: locator("source_key", &source_identity.source_key)?,
        stable_record_id: source_identity
            .stable_record_id
            .as_deref()
            .map(|value| locator("stable_record_id", value))
            .transpose()?,
        observation_id: locator("observation_id", &source_identity.observation_id)?,
        source_revision: source_identity
            .source_revision
            .as_deref()
            .map(|value| locator("source_revision", value))
            .transpose()?,
        content_sha256: opaque_control_digest(
            locator_key,
            trace,
            binding,
            "content_sha256",
            &source_identity.content_sha256,
        )?,
    };
    let origin_scope = match &source.origin_scope {
        RecallOriginScopeEvidenceV1::Recorded {
            exact_scope_identity,
            authority_ref,
        } => RecallOriginScopeEvidenceV1::Recorded {
            exact_scope_identity: redact_scope(
                locator_key,
                provider_id,
                trace,
                registration_revision,
                provider_rank,
                candidate_id,
                exact_scope_identity,
            )?,
            authority_ref: locator("authority_ref", authority_ref)?,
        },
        RecallOriginScopeEvidenceV1::IngestionOnly => RecallOriginScopeEvidenceV1::IngestionOnly,
        RecallOriginScopeEvidenceV1::Unavailable => RecallOriginScopeEvidenceV1::Unavailable,
    };
    let validity = RecallRecordedValidityV1 {
        valid_from: source.validity.valid_from.clone(),
        valid_until: source.validity.valid_until.clone(),
        superseded_at: source.validity.superseded_at.clone(),
        superseded_by: source
            .validity
            .superseded_by
            .as_deref()
            .map(|value| locator("superseded_by", value))
            .transpose()?,
        revoked_at: source.validity.revoked_at.clone(),
    };
    Ok(RecallSourceAttributionV1 {
        source: redacted_source,
        origin_scope,
        source_sequence: source.source_sequence,
        occurred_at: source.occurred_at.clone(),
        ingested_at: source.ingested_at.clone(),
        validity,
    })
}

fn redact_scope(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    scope: &RecallOutcomeScopeV1,
) -> Result<RecallOutcomeScopeV1> {
    let binding = RetainedItemBindingV1 {
        provider_id,
        registration_revision,
        provider_rank,
        candidate_id,
    };
    let locator = |field: &str, value: &str| {
        opaque_control_locator(
            locator_key,
            RETAINED_SOURCE_LOCATOR_PREFIX,
            trace,
            binding,
            field,
            value,
        )
    };
    let digest = opaque_control_digest(
        locator_key,
        trace,
        binding,
        "origin_scope_digest",
        &scope.resolved_scope_digest,
    )?;
    Ok(RecallOutcomeScopeV1 {
        profile_id: locator("origin_profile_id", &scope.profile_id)?,
        project_id: locator("origin_project_id", &scope.project_id)?,
        repository_identity: locator("origin_repository_identity", &scope.repository_identity)?,
        worktree_identity: locator("origin_worktree_identity", &scope.worktree_identity)?,
        branch_identity: locator("origin_branch_identity", &scope.branch_identity)?,
        agent_session_id: locator("origin_agent_session_id", &scope.agent_session_id)?,
        resolved_scope_digest: format!("sha256:{digest}"),
    })
}

fn opaque_control_locator(
    locator_key: &RecallLocatorKeyV1,
    prefix: &str,
    trace: &RecallControlTraceRefV1,
    binding: RetainedItemBindingV1<'_>,
    field: &str,
    value: &str,
) -> Result<String> {
    Ok(format!(
        "{prefix}{}",
        opaque_control_digest(locator_key, trace, binding, field, value)?
    ))
}

fn opaque_control_digest(
    locator_key: &RecallLocatorKeyV1,
    trace: &RecallControlTraceRefV1,
    binding: RetainedItemBindingV1<'_>,
    field: &str,
    value: &str,
) -> Result<String> {
    let revision = binding.registration_revision.to_be_bytes();
    let rank = (binding.provider_rank as u64).to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.recall-control-opaque-locator.v2",
        &[
            trace.exact_scope_sha256.as_bytes(),
            trace.trace_id.as_bytes(),
            binding.provider_id.as_bytes(),
            &revision,
            &rank,
            binding.candidate_id.as_bytes(),
            field.as_bytes(),
            value.as_bytes(),
        ],
    )
}

fn hmac_hex(locator_key: &RecallLocatorKeyV1, domain: &[u8], fields: &[&[u8]]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(locator_key.bytes())
        .map_err(|_| invalid("recall locator HMAC key"))?;
    update_length_delimited(&mut mac, domain);
    for field in fields {
        update_length_delimited(&mut mac, field);
    }
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Keyed commitment over bytes retained in the explain ledger. Every
/// commitment carries the complete routing context as separate length
/// delimited fields so copying a valid value between providers, revisions,
/// scopes, traces, or ranks cannot make it authoritative.
pub(crate) fn retained_trace_bytes_mac(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    trace_id: &str,
    provider_id: &str,
    registration_revision: u64,
    trace_bytes: &[u8],
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.retained-recall-trace-bytes.v1",
        &[
            exact_scope_sha256.as_bytes(),
            trace_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
            trace_bytes,
        ],
    )
}

pub(super) fn retained_item_bytes_mac(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    trace_id: &str,
    binding: RetainedItemBindingV1<'_>,
    item_bytes: &[u8],
) -> Result<String> {
    let revision = binding.registration_revision.to_be_bytes();
    let rank = (binding.provider_rank as u64).to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.retained-recall-item-bytes.v1",
        &[
            exact_scope_sha256.as_bytes(),
            trace_id.as_bytes(),
            binding.provider_id.as_bytes(),
            &revision,
            &rank,
            binding.candidate_id.as_bytes(),
            item_bytes,
        ],
    )
}

pub(crate) fn retained_scope_binding_mac(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    trace_id: &str,
    provider_id: &str,
    registration_revision: u64,
    scope_bytes: &[u8],
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.retained-recall-scope-binding.v1",
        &[
            exact_scope_sha256.as_bytes(),
            trace_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
            scope_bytes,
        ],
    )
}

pub(crate) fn retained_control_metadata_mac_from_parts(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    trace_id: &str,
    provider_id: &str,
    registration_revision: u64,
    delivery_scope_json: &str,
    rows: &BTreeMap<usize, (String, String, String, String)>,
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    let bytes = serde_json::to_vec(&(
        "recall-control-metadata-mac-v1",
        provider_id,
        registration_revision,
        exact_scope_sha256,
        trace_id,
        delivery_scope_json,
        rows,
    ))?;
    hmac_hex(
        locator_key,
        b"tracedecay.retained-recall-control-metadata.v1",
        &[
            exact_scope_sha256.as_bytes(),
            trace_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
            &bytes,
        ],
    )
}

fn metadata_mac_rows(
    rows: &BTreeMap<usize, PreparedItemV1>,
) -> BTreeMap<usize, (String, String, String, String)> {
    rows.iter()
        .map(|(rank, row)| {
            (
                *rank,
                (
                    row.candidate_id.clone(),
                    row.binding.stable_memory_ref.clone(),
                    row.original_sources_json.clone(),
                    row.control_binding_mac.clone(),
                ),
            )
        })
        .collect()
}

fn update_length_delimited(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn is_opaque_locator(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Checks the retained-memory namespace used by both control bindings and
/// admission-denial rows. Legacy rows are withheld when they do not carry
/// this host-owned projection prefix.
pub(crate) fn is_opaque_retained_memory_ref(value: &str) -> bool {
    is_opaque_locator(value, RETAINED_MEMORY_REF_PREFIX)
}

pub fn validate_opaque_retained_source(source: &RecallSourceAttributionV1) -> Result<()> {
    if source.source_sequence == 0 {
        return Err(invalid("retained source sequence is not resolvable"));
    }
    let identity = &source.source;
    if identity.canonical_provider_id.as_str() != "recall.opaque"
        || !is_opaque_locator(
            &identity.canonical_session_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        )
        || !is_opaque_locator(&identity.source_key, RETAINED_SOURCE_LOCATOR_PREFIX)
        || !identity
            .stable_record_id
            .as_deref()
            .is_none_or(|value| is_opaque_locator(value, RETAINED_SOURCE_LOCATOR_PREFIX))
        || !is_opaque_locator(&identity.observation_id, RETAINED_SOURCE_LOCATOR_PREFIX)
        || !identity
            .source_revision
            .as_deref()
            .is_none_or(|value| is_opaque_locator(value, RETAINED_SOURCE_LOCATOR_PREFIX))
    {
        return Err(invalid("retained source identity is not opaque"));
    }
    require_sha256(&identity.content_sha256)?;
    if !source
        .validity
        .superseded_by
        .as_deref()
        .is_none_or(|value| is_opaque_locator(value, RETAINED_SOURCE_LOCATOR_PREFIX))
    {
        return Err(invalid("retained source lineage is not opaque"));
    }
    if let RecallOriginScopeEvidenceV1::Recorded {
        exact_scope_identity,
        authority_ref,
    } = &source.origin_scope
        && (!is_opaque_locator(
            &exact_scope_identity.profile_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !is_opaque_locator(
            &exact_scope_identity.project_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !is_opaque_locator(
            &exact_scope_identity.repository_identity,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !is_opaque_locator(
            &exact_scope_identity.worktree_identity,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !is_opaque_locator(
            &exact_scope_identity.branch_identity,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !is_opaque_locator(
            &exact_scope_identity.agent_session_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
        ) || !exact_scope_identity
            .resolved_scope_digest
            .strip_prefix("sha256:")
            .is_some_and(is_opaque_digest)
            || !is_opaque_locator(authority_ref, RETAINED_SOURCE_LOCATOR_PREFIX))
    {
        return Err(invalid("retained source scope is not opaque"));
    }
    Ok(())
}

fn is_opaque_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn scope_binding_sha256(
    provider_id: &str,
    registration_revision: u64,
    scope: &OwnedExactScope,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        "recall-control-scope-binding-v1",
        provider_id,
        registration_revision,
        scope_wire(scope),
    ))?;
    Ok(tracedecay_domain::canonical_text::sha256_hex(&bytes))
}

fn decode_scope_envelope(
    scope_json: &str,
    provider_id: &str,
    registration_revision: u64,
) -> Result<OwnedExactScope> {
    let envelope: ScopeBindingEnvelopeV1 = serde_json::from_str(scope_json)?;
    if envelope.version != 1 {
        return Err(invalid("retained scope envelope version"));
    }
    require_sha256(&envelope.scope_binding_sha256)?;
    let scope = scope_owned(envelope.delivery_scope)?;
    if envelope.scope_binding_sha256
        != scope_binding_sha256(provider_id, registration_revision, &scope)?
    {
        return Err(invalid("retained scope binding digest"));
    }
    Ok(scope)
}

struct BoundedSourcesV1(Vec<RecallSourceAttributionV1>);

impl<'de> Deserialize<'de> for BoundedSourcesV1 {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct SourcesVisitor;
        impl<'de> serde::de::Visitor<'de> for SourcesVisitor {
            type Value = BoundedSourcesV1;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an array of 1 to 64 canonical source attributions")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut sources = Vec::new();
                while let Some(source) = sequence.next_element::<RecallSourceAttributionV1>()? {
                    if sources.len() == MAX_SOURCES {
                        return Err(serde::de::Error::custom("source count exceeds 64"));
                    }
                    sources.push(source);
                }
                if sources.is_empty() {
                    return Err(serde::de::Error::custom("source array is empty"));
                }
                Ok(BoundedSourcesV1(sources))
            }
        }
        deserializer.deserialize_seq(SourcesVisitor)
    }
}

fn scope_wire(scope: &OwnedExactScope) -> RecallOutcomeScopeV1 {
    RecallOutcomeScopeV1 {
        profile_id: scope.profile_id.clone(),
        project_id: scope.project_id.clone(),
        repository_identity: scope.repository_identity.clone(),
        worktree_identity: scope.worktree_identity.clone(),
        branch_identity: scope.branch_identity.clone(),
        agent_session_id: scope.agent_session_id.clone(),
        resolved_scope_digest: scope.resolved_scope_digest.clone(),
    }
}

fn scope_owned(scope: RecallOutcomeScopeV1) -> Result<OwnedExactScope> {
    OwnedExactScope::new(
        scope.profile_id,
        scope.project_id,
        scope.repository_identity,
        scope.worktree_identity,
        scope.branch_identity,
        scope.agent_session_id,
        scope.resolved_scope_digest,
    )
    .map_err(|_| invalid("retained delivery scope"))
}

fn invalid(field: &'static str) -> RecallControlAttributionErrorV1 {
    RecallControlAttributionErrorV1::Invalid(field)
}
fn valid_rank(rank: usize) -> bool {
    (rank as u64) < PROJECT_RECALL_BUDGETS.maximum_candidates
}
fn eligible_stage(stage: RecallExplainStageV1) -> bool {
    matches!(
        stage,
        RecallExplainStageV1::Selected | RecallExplainStageV1::Injected
    )
}
fn require_sha256(value: &str) -> Result<()> {
    if !is_lower_hex_sha256(value) {
        return Err(invalid("canonical SHA-256"));
    }
    Ok(())
}

pub(crate) fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn require_id(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid("bounded identity"));
    }
    require_size(value, MAX_ID_BYTES)
}

pub fn validate_retained_candidate_identity(value: &str) -> Result<()> {
    validate_retained_trace_candidate_id(value)
}

/// Projects the trace identity into the same durable host-owned namespace as
/// its candidate and source locators. The registry's deterministic trace id
/// is useful while reconciling an in-memory result, but the retained trace
/// reference must not expose a dictionary-recoverable request id.
pub fn retained_trace_id_with_key(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    request_id: &str,
    provider_id: &str,
    registration_revision: u64,
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.recall-trace-identity.v2",
        &[
            exact_scope_sha256.as_bytes(),
            request_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
        ],
    )
}

/// Projects every provider candidate into one request/context-bound opaque id.
/// The HMAC key is durable host material, so the result is resistant to
/// offline dictionary recovery of provider-controlled ids.
pub fn retained_candidate_identity_alias_for_context(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    request_id: &str,
    provider_id: &str,
    registration_revision: u64,
    candidate_id: &str,
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    Ok(format!(
        "{RETAINED_CANDIDATE_ID_PREFIX}{}",
        hmac_hex(
            locator_key,
            b"tracedecay.recall-candidate-identity.v2",
            &[
                exact_scope_sha256.as_bytes(),
                request_id.as_bytes(),
                provider_id.as_bytes(),
                &revision,
                candidate_id.as_bytes(),
            ],
        )?
    ))
}

pub fn retained_candidate_identity_alias_for_report(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
    candidate_id: &str,
) -> Result<String> {
    let provider_id = report.provider_id.as_deref().unwrap_or("provider.unknown");
    retained_candidate_identity_alias_for_context(
        locator_key,
        &report.exact_scope_sha256,
        &report.request_id,
        provider_id,
        report.registration_revision.unwrap_or(0),
        candidate_id,
    )
}

/// Returns the complete collision-safe projection in provider order. An alias
/// is disambiguated if it happens to equal another raw id or an earlier alias.
pub fn retained_candidate_identity_aliases_for_report(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
) -> Result<BTreeMap<String, String>> {
    let raw_ids = report
        .received_candidate_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut retained_ids = BTreeSet::new();
    let mut aliases = BTreeMap::new();
    for candidate_id in &report.received_candidate_ids {
        let base = retained_candidate_identity_alias_for_report(report, locator_key, candidate_id)?;
        let mut retained = base.clone();
        let mut suffix = 0usize;
        while raw_ids.contains(retained.as_str()) || retained_ids.contains(retained.as_str()) {
            suffix = suffix.saturating_add(1);
            retained = format!("{base}.{suffix}");
        }
        retained_ids.insert(retained.clone());
        aliases.insert(candidate_id.clone(), retained);
    }
    Ok(aliases)
}

/// Opaque stable reference retained alongside an admission denial. This uses
/// the same candidate alias context as explain/control retention, making rows
/// correlatable without exposing the provider's reference bytes.
pub(crate) fn opaque_denial_stable_memory_ref(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
    retained_candidate_id: &str,
    stable_memory_ref: &str,
) -> Result<String> {
    let provider_id = report.provider_id.as_deref().unwrap_or("provider.unknown");
    let revision = report.registration_revision.unwrap_or(0).to_be_bytes();
    Ok(format!(
        "{RETAINED_MEMORY_REF_PREFIX}{}",
        hmac_hex(
            locator_key,
            b"tracedecay.recall-denial-memory-ref.v2",
            &[
                report.exact_scope_sha256.as_bytes(),
                report.request_id.as_bytes(),
                provider_id.as_bytes(),
                &revision,
                retained_candidate_id.as_bytes(),
                b"stable_memory_ref",
                stable_memory_ref.as_bytes(),
            ],
        )?
    ))
}

/// Retained candidate ids must already be host projections. A missing alias is
/// a typed refusal at the ledger boundary; it can never fall back to raw bytes.
pub fn validate_retained_trace_candidate_id(value: &str) -> Result<()> {
    if !value.starts_with(RETAINED_CANDIDATE_ID_PREFIX) {
        return Err(invalid("retained candidate identity is not opaque"));
    }
    let suffix = &value[RETAINED_CANDIDATE_ID_PREFIX.len()..];
    let (digest, disambiguator) = suffix
        .split_once('.')
        .map_or((suffix, None), |(d, s)| (d, Some(s)));
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || disambiguator.is_some_and(|value| {
            value.is_empty()
                || value.starts_with('0')
                || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(invalid("retained candidate identity is malformed"));
    }
    Ok(())
}

pub fn validate_retained_provider_rank(rank: usize) -> Result<()> {
    if valid_rank(rank) {
        Ok(())
    } else {
        Err(invalid("retained provider rank"))
    }
}

fn require_size(value: &str, maximum: usize) -> Result<()> {
    if value.len() > maximum {
        return Err(invalid("metadata byte bound"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{RecallAdmissionLedgerError, RecallAdmissionLedgerWriteV1};
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;
    use tracedecay_memory_provider_registry::{
        CancellationToken, RecallExplainItemV1, RecallExplainProviderExplanationV1,
    };

    #[test]
    fn opaque_control_locator_matches_known_bytes() {
        let key = RecallLocatorKeyV1::from_material((0_u8..32).collect()).unwrap();
        let trace = RecallControlTraceRefV1::parse(&format!(
            "{TRACE_PREFIX}{}:{}",
            "b".repeat(64),
            "d".repeat(64),
        ))
        .unwrap();
        let binding = RetainedItemBindingV1 {
            provider_id: "provider.native\0route",
            registration_revision: 0x0102_0304_0506_0708,
            provider_rank: 0x0102_0304,
            candidate_id: "candidate.\u{03b1}\0retained",
        };
        // Python hmac/sha256 over the domain and each field, each prefixed
        // with its u64 big-endian byte length, gives this fixed digest.
        let expected = "d37c9e581c946030ed939a1c8761e7738b8e051523aecab0c16148446932e6b2";
        assert_eq!(
            opaque_control_digest(
                &key,
                &trace,
                binding,
                "observation_id",
                "source.\u{03b2}\0record",
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            opaque_control_locator(
                &key,
                RETAINED_SOURCE_LOCATOR_PREFIX,
                &trace,
                binding,
                "observation_id",
                "source.\u{03b2}\0record",
            )
            .unwrap(),
            format!("{RETAINED_SOURCE_LOCATOR_PREFIX}{expected}")
        );
    }

    #[test]
    fn retained_item_bytes_mac_matches_known_bytes() {
        let key = RecallLocatorKeyV1::from_material((0_u8..32).collect()).unwrap();
        let binding = RetainedItemBindingV1 {
            provider_id: "provider.native\0route",
            registration_revision: 0x0102_0304_0506_0708,
            provider_rank: 0x0102_0304,
            candidate_id: "candidate.\u{03b1}\0retained",
        };
        // The independently computed vector includes non-UTF-8 item bytes.
        assert_eq!(
            retained_item_bytes_mac(
                &key,
                &"b".repeat(64),
                &"d".repeat(64),
                binding,
                b"\0{\"candidate\":\"\xce\xb1\"}\xff\n",
            )
            .unwrap(),
            "c8d122eed2c1d3f2991951da4b17a866184e74a830bdbfabb1d703526cffc84d"
        );
    }

    fn control(millis: u64) -> OperationControl {
        OperationControl::new(
            tracedecay_contracts::now_micros()
                .0
                .saturating_add((millis * 1_000) as i64),
            millis,
            CancellationToken::new(),
        )
    }

    fn scope() -> OwnedExactScope {
        OwnedExactScope::new(
            "profile.test",
            "project.test",
            "repository.test",
            "worktree.test",
            "branch.test",
            "session.destination",
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap()
    }

    fn source(observation_id: &str, sequence: u64) -> RecallSourceAttributionV1 {
        let mut origin = scope();
        origin.agent_session_id = "session.original".to_owned();
        serde_json::from_value(serde_json::json!({
            "source": {
                "canonical_provider_id": "codex", "canonical_session_id": "session.original",
                "source_key": format!("source.{observation_id}"), "stable_record_id": null,
                "observation_id": observation_id, "source_revision": null,
                "content_sha256": "c".repeat(64)
            },
            "origin_scope": {"state": "recorded", "exact_scope_identity": scope_wire(&origin),
                "authority_ref": "host-original:test"},
            "source_sequence": sequence, "occurred_at": null,
            "ingested_at": "2025-05-01T00:00:00.000000000Z",
            "validity": {"valid_from":null,"valid_until":null,"superseded_at":null,
                "superseded_by":null,"revoked_at":null}
        }))
        .unwrap()
    }

    fn candidate_alias(candidate_id: &str) -> String {
        retained_candidate_identity_alias_for_context(
            &RecallLocatorKeyV1::for_test(),
            &scope().exact_scope_sha256(),
            "request.test",
            "tracedecay.native",
            7,
            candidate_id,
        )
        .unwrap()
    }

    fn trace() -> RecallExplainTraceV1 {
        let exact_scope_sha256 = scope().exact_scope_sha256();
        RecallExplainTraceV1 {
            trace_id: retained_trace_id_with_key(
                &RecallLocatorKeyV1::for_test(),
                &exact_scope_sha256,
                "request.test",
                "tracedecay.native",
                7,
            )
            .unwrap(),
            request_id: "request.test".to_owned(),
            provider_id: "tracedecay.native".to_owned(),
            registration_revision: 7,
            requested_count: 3,
            degraded: false,
            token_summary: None,
            items: (0..3)
                .map(|rank| {
                    let host_decision = if rank == 1 {
                        RecallExplainHostDecisionV1::HostWithheld {
                            reason_code: "unresolvable".to_owned(),
                            detail: None,
                        }
                    } else {
                        RecallExplainHostDecisionV1::Selected
                    };
                    RecallExplainItemV1 {
                        candidate_id: candidate_alias(&format!("candidate.{rank}")),
                        provider_rank: rank,
                        stage: host_decision.stage(),
                        host_reason_code: host_decision.code().to_owned(),
                        host_reason_detail: host_decision.detail(),
                        host_decision,
                        provider_explanation: RecallExplainProviderExplanationV1::NotProvided,
                        section: None,
                        tokens: None,
                    }
                })
                .collect(),
        }
    }

    fn bindings() -> BTreeMap<String, RetainedRecallControlBindingV1> {
        BTreeMap::from([
            (
                candidate_alias("candidate.0"),
                RetainedRecallControlBindingV1 {
                    stable_memory_ref: "memory.first".to_owned(),
                    original_sources: vec![source("observation.1", 1)],
                },
            ),
            (
                candidate_alias("candidate.2"),
                RetainedRecallControlBindingV1 {
                    stable_memory_ref: "memory.multisource".to_owned(),
                    original_sources: vec![source("observation.3", 3), source("observation.2", 2)],
                },
            ),
        ])
    }

    fn prepared() -> PreparedRecallControlMetadataV1 {
        PreparedRecallControlMetadataV1::prepare(&trace(), &scope(), &bindings()).unwrap()
    }

    fn retained() -> (
        tempfile::TempDir,
        RecallAdmissionLedgerV1,
        PreparedRecallControlMetadataV1,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let ledger =
            RecallAdmissionLedgerV1::open(temporary.path().join("ledger.sqlite3")).unwrap();
        let metadata = prepared();
        assert_eq!(
            ledger
                .retain_explain_trace_with_control(
                    &scope().exact_scope_sha256(),
                    &trace(),
                    Some(&metadata),
                )
                .unwrap(),
            RecallAdmissionLedgerWriteV1::Recorded
        );
        (temporary, ledger, metadata)
    }

    #[test]
    fn control_locators_and_final_rank_metadata_are_strict_and_deterministic() {
        let metadata = prepared();
        assert_eq!(
            RecallControlTraceRefV1::parse(metadata.trace_ref().as_str()).unwrap(),
            *metadata.trace_ref()
        );
        assert_eq!(metadata.item_ref(2).unwrap().as_str(), "recall-item-v1:2");
        assert!(metadata.item_ref(1).is_none());
        for invalid in [
            "recall-item-v1:+1",
            "recall-item-v1:01",
            "recall-item-v1:-1",
            "recall-item-v2:1",
            "recall-item-v1:8",
        ] {
            assert!(RecallControlItemRefV1::parse(invalid).is_err(), "{invalid}");
        }
        for invalid in [
            metadata.trace_ref().as_str().to_uppercase(),
            format!("{}:extra", metadata.trace_ref().as_str()),
            "a".repeat(64),
        ] {
            assert!(RecallControlTraceRefV1::parse(&invalid).is_err());
        }
        let mut same_bindings = bindings();
        same_bindings
            .get_mut(&candidate_alias("candidate.2"))
            .unwrap()
            .original_sources
            .reverse();
        assert_eq!(
            PreparedRecallControlMetadataV1::prepare(&trace(), &scope(), &same_bindings).unwrap(),
            metadata
        );
        same_bindings
            .get_mut(&candidate_alias("candidate.2"))
            .unwrap()
            .stable_memory_ref = "memory.changed".to_owned();
        assert_ne!(
            PreparedRecallControlMetadataV1::prepare(&trace(), &scope(), &same_bindings)
                .unwrap()
                .metadata_sha256(),
            metadata.metadata_sha256()
        );
        let mut malformed = trace();
        malformed.items[2].provider_rank = 1;
        assert!(
            PreparedRecallControlMetadataV1::prepare(&malformed, &scope(), &bindings()).is_err()
        );
        assert!(
            !metadata
                .matches_trace(&"f".repeat(64), &trace(), &RecallLocatorKeyV1::for_test(),)
                .unwrap()
        );
    }

    #[test]
    fn retained_trace_identity_is_keyed_and_context_bound() {
        let key = RecallLocatorKeyV1::for_test();
        let scope = "b".repeat(64);
        let first = retained_trace_id_with_key(
            &key,
            &scope,
            "request.secret-looking-id",
            "provider.native",
            7,
        )
        .unwrap();
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) })
        );
        assert_ne!(
            first,
            retained_trace_id_with_key(
                &RecallLocatorKeyV1::from_material(vec![0x5A; 32]).unwrap(),
                &scope,
                "request.secret-looking-id",
                "provider.native",
                7,
            )
            .unwrap()
        );
        assert_ne!(
            first,
            retained_trace_id_with_key(&key, &scope, "request.other", "provider.native", 7,)
                .unwrap()
        );
        assert_ne!(
            first,
            retained_trace_id_with_key(
                &key,
                &"c".repeat(64),
                "request.secret-looking-id",
                "provider.native",
                7,
            )
            .unwrap()
        );
    }

    #[test]
    fn control_reads_reopen_exact_multisource_member_without_reading_siblings() {
        let (temporary, ledger, metadata) = retained();
        assert_eq!(
            ledger
                .retain_explain_trace_with_control(
                    &scope().exact_scope_sha256(),
                    &trace(),
                    Some(&metadata),
                )
                .unwrap(),
            RecallAdmissionLedgerWriteV1::AlreadyRecorded
        );
        drop(ledger);
        let ledger =
            RecallAdmissionLedgerV1::open(temporary.path().join("ledger.sqlite3")).unwrap();
        let item = metadata.item_ref(2).unwrap();
        let read = ledger
            .read_retained_control_source(
                metadata.trace_ref(),
                &item,
                "observation.3",
                &control(1_000),
            )
            .unwrap();
        assert_eq!(read.scope.provider_id.as_str(), "tracedecay.native");
        assert_eq!(read.scope.registration_revision, 7);
        assert_eq!(read.scope.delivery_scope, scope());
        assert_eq!(read.provider_rank, 2);
        assert_eq!(read.candidate_id, candidate_alias("candidate.2"));
        assert!(
            read.stable_memory_ref
                .starts_with(RETAINED_MEMORY_REF_PREFIX)
        );
        assert_ne!(read.original_source, source("observation.3", 3));
        assert_eq!(
            read.original_source.source.canonical_provider_id.as_str(),
            "recall.opaque"
        );
        assert_eq!(
            ledger
                .read_retained_control_scope(metadata.trace_ref(), &control(1_000))
                .unwrap(),
            read.scope
        );
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &item,
                    "observation.1",
                    &control(1_000)
                )
                .is_err()
        );
        ledger.connection.lock().unwrap().execute(
            "UPDATE recall_explain_trace_items SET original_sources_json='broken' WHERE provider_rank=0", [],
        ).unwrap();
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &item,
                    "observation.3",
                    &control(1_000)
                )
                .is_ok()
        );
        let missing = RecallControlTraceRefV1::parse(&format!(
            "{TRACE_PREFIX}{}:{}",
            scope().exact_scope_sha256(),
            "d".repeat(64)
        ))
        .unwrap();
        assert!(matches!(
            ledger.read_retained_control_scope(&missing, &control(1_000)),
            Err(RecallControlAttributionErrorV1::NotFound)
        ));
    }

    #[test]
    fn trace_lookup_requires_the_scope_bound_reference_when_trace_ids_collide() {
        let temporary = tempfile::tempdir().unwrap();
        let ledger =
            RecallAdmissionLedgerV1::open(temporary.path().join("ledger.sqlite3")).unwrap();
        let first_scope = scope();
        let mut second_scope = scope();
        second_scope.agent_session_id = "session.other".to_owned();
        let first_trace = trace();
        let mut second_trace = trace();
        second_trace.trace_id = retained_trace_id_with_key(
            &RecallLocatorKeyV1::for_test(),
            &second_scope.exact_scope_sha256(),
            &second_trace.request_id,
            &second_trace.provider_id,
            second_trace.registration_revision,
        )
        .unwrap();
        let first_metadata =
            PreparedRecallControlMetadataV1::prepare(&first_trace, &first_scope, &bindings())
                .unwrap();
        let second_metadata =
            PreparedRecallControlMetadataV1::prepare(&second_trace, &second_scope, &bindings())
                .unwrap();
        ledger
            .retain_explain_trace_with_control(
                &first_scope.exact_scope_sha256(),
                &first_trace,
                Some(&first_metadata),
            )
            .unwrap();
        ledger
            .retain_explain_trace_with_control(
                &second_scope.exact_scope_sha256(),
                &second_trace,
                Some(&second_metadata),
            )
            .unwrap();

        let first = ledger
            .explain_trace(first_metadata.trace_ref())
            .unwrap()
            .unwrap();
        let second = ledger
            .explain_trace(second_metadata.trace_ref())
            .unwrap()
            .unwrap();
        assert_eq!(first.exact_scope_sha256, first_scope.exact_scope_sha256());
        assert_eq!(second.exact_scope_sha256, second_scope.exact_scope_sha256());
        assert_ne!(first.trace.trace_id, second.trace.trace_id);
        assert!(
            RecallControlTraceRefV1::parse(&format!("{TRACE_PREFIX}{}", trace().trace_id)).is_err()
        );

        let forged_scope = RecallControlTraceRefV1::parse(&format!(
            "{TRACE_PREFIX}{}:{}",
            "f".repeat(64),
            trace().trace_id
        ))
        .unwrap();
        assert!(matches!(ledger.explain_trace(&forged_scope), Ok(None)));
    }

    #[test]
    fn forged_opaque_locator_bytes_cannot_authorize_a_reopened_source() {
        let (_temporary, ledger, metadata) = retained();
        let item = metadata.item_ref(2).unwrap();
        let control = control(1_000);
        {
            let connection = ledger.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE recall_explain_trace_items
                     SET stable_memory_ref=?1 WHERE provider_rank=2",
                    [format!("{RETAINED_MEMORY_REF_PREFIX}{}", "0".repeat(64))],
                )
                .unwrap();
        }
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &item,
                    "observation.3",
                    &control,
                )
                .is_err()
        );

        let (_temporary, ledger, metadata) = retained();
        let item = metadata.item_ref(2).unwrap();
        let connection = ledger.connection.lock().unwrap();
        let existing: String = connection
            .query_row(
                "SELECT original_sources_json FROM recall_explain_trace_items
                 WHERE provider_rank=2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut forged: serde_json::Value = serde_json::from_str(&existing).unwrap();
        forged[0]["source"]["observation_id"] = serde_json::json!(format!(
            "{RETAINED_SOURCE_LOCATOR_PREFIX}{}",
            "1".repeat(64)
        ));
        connection
            .execute(
                "UPDATE recall_explain_trace_items
                 SET original_sources_json=?1 WHERE provider_rank=2",
                [serde_json::to_string(&forged).unwrap()],
            )
            .unwrap();
        drop(connection);
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &item,
                    "observation.3",
                    &control,
                )
                .is_err()
        );
    }

    #[test]
    fn control_binding_hash_refuses_changed_stable_ref_source_and_producer() {
        for changed in [
            "stable",
            "source",
            "provider",
            "revision",
            "scope",
            "rank",
            "state",
            "missing_hash",
        ] {
            let (_temporary, ledger, metadata) = retained();
            {
                let connection = ledger.connection.lock().unwrap();
                match changed {
                    "stable" => {
                        connection.execute("UPDATE recall_explain_trace_items SET stable_memory_ref='memory.changed' WHERE provider_rank=2", []).unwrap();
                    }
                    "source" => {
                        let mut sources = bindings()
                            .remove(&candidate_alias("candidate.2"))
                            .unwrap()
                            .original_sources;
                        sources[0].source.content_sha256 = "e".repeat(64);
                        connection.execute("UPDATE recall_explain_trace_items SET original_sources_json=?1 WHERE provider_rank=2", [serde_json::to_string(&sources).unwrap()]).unwrap();
                    }
                    "provider" => {
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET provider_id='another.provider'",
                                [],
                            )
                            .unwrap();
                    }
                    "revision" => {
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET registration_revision=8",
                                [],
                            )
                            .unwrap();
                    }
                    "scope" => {
                        let mut changed = scope();
                        changed.agent_session_id = "session.changed".to_owned();
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET delivery_scope_json=?1",
                                [serde_json::to_string(&scope_wire(&changed)).unwrap()],
                            )
                            .unwrap();
                    }
                    "rank" => {
                        connection.execute("UPDATE recall_explain_trace_items SET candidate_id='candidate.changed' WHERE provider_rank=2", []).unwrap();
                    }
                    "state" => {
                        connection.execute("UPDATE recall_explain_trace_items SET stage='denied' WHERE provider_rank=2", []).unwrap();
                    }
                    "missing_hash" => {
                        connection.execute("UPDATE recall_explain_trace_items SET control_binding_mac=NULL WHERE provider_rank=2", []).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
            let result = ledger.read_retained_control_source(
                metadata.trace_ref(),
                &metadata.item_ref(2).unwrap(),
                "observation.3",
                &control(1_000),
            );
            assert!(result.is_err(), "{changed}");
            if changed == "missing_hash" {
                assert!(matches!(
                    result,
                    Err(RecallControlAttributionErrorV1::MissingAuthority)
                ));
            }
        }
    }

    #[test]
    fn control_metadata_conflicts_are_atomic_and_legacy_nulls_do_not_gain_authority() {
        let (_temporary, ledger, metadata) = retained();
        let mut changed = bindings();
        changed
            .get_mut(&candidate_alias("candidate.2"))
            .unwrap()
            .stable_memory_ref = "memory.changed".to_owned();
        let changed =
            PreparedRecallControlMetadataV1::prepare(&trace(), &scope(), &changed).unwrap();
        assert!(matches!(
            ledger.retain_explain_trace_with_control(
                &scope().exact_scope_sha256(),
                &trace(),
                Some(&changed)
            ),
            Err(RecallAdmissionLedgerError::ConflictingTrace { .. })
        ));
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &metadata.item_ref(2).unwrap(),
                    "observation.3",
                    &control(1_000)
                )
                .unwrap()
                .stable_memory_ref
                .starts_with(RETAINED_MEMORY_REF_PREFIX)
        );
        let mut legacy = trace();
        legacy.request_id = "request.legacy".to_owned();
        legacy.trace_id = retained_trace_id_with_key(
            &RecallLocatorKeyV1::for_test(),
            &scope().exact_scope_sha256(),
            &legacy.request_id,
            &legacy.provider_id,
            legacy.registration_revision,
        )
        .unwrap();
        ledger
            .retain_explain_trace(&scope().exact_scope_sha256(), &legacy)
            .unwrap();
        let metadata =
            PreparedRecallControlMetadataV1::prepare(&legacy, &scope(), &bindings()).unwrap();
        assert!(matches!(
            ledger.read_retained_control_scope(metadata.trace_ref(), &control(1_000)),
            Err(RecallControlAttributionErrorV1::MissingAuthority)
        ));
        assert!(matches!(
            ledger.retain_explain_trace_with_control(
                &scope().exact_scope_sha256(),
                &legacy,
                Some(&metadata)
            ),
            Err(RecallAdmissionLedgerError::ConflictingTrace { .. })
        ));
        assert!(matches!(
            ledger.read_retained_control_source(
                metadata.trace_ref(),
                &metadata.item_ref(2).unwrap(),
                "observation.3",
                &control(1_000)
            ),
            Err(RecallControlAttributionErrorV1::MissingAuthority)
        ));
    }

    #[test]
    fn legacy_raw_control_rows_are_withheld_after_reopen() {
        let (temporary, ledger, metadata) = retained();
        let raw_candidate = "provider-secret:/private/legacy-control-candidate";
        let raw_stable_ref = "memory:/private/legacy-control-ref";
        let raw_source = source("observation.3", 3);
        let trace_id = metadata.trace_ref().trace_id().to_owned();
        ledger
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE recall_explain_trace_items
                 SET candidate_id=?1, stable_memory_ref=?2, original_sources_json=?3
                 WHERE exact_scope_sha256=?4 AND trace_id=?5 AND provider_rank=2",
                params![
                    raw_candidate,
                    raw_stable_ref,
                    serde_json::to_string(&vec![raw_source]).unwrap(),
                    metadata.trace_ref().exact_scope_sha256(),
                    trace_id,
                ],
            )
            .unwrap();
        drop(ledger);

        let reopened =
            RecallAdmissionLedgerV1::open(temporary.path().join("ledger.sqlite3")).unwrap();
        assert!(matches!(
            reopened.read_retained_control_scope(metadata.trace_ref(), &control(1_000)),
            Err(RecallControlAttributionErrorV1::Invalid(_))
        ));
        assert!(matches!(
            reopened.read_retained_control_source(
                metadata.trace_ref(),
                &metadata.item_ref(2).unwrap(),
                "observation.3",
                &control(1_000),
            ),
            Err(RecallControlAttributionErrorV1::Invalid(_))
        ));
        assert!(matches!(
            reopened.explain_trace(metadata.trace_ref()),
            Err(RecallAdmissionLedgerError::InvalidControlMetadata)
        ));
    }

    #[test]
    fn control_scope_read_checks_producer_revision_scope_and_envelope_digest() {
        for changed in ["provider", "revision", "scope", "hash", "version"] {
            let (_temporary, ledger, metadata) = retained();
            assert_eq!(
                ledger
                    .read_retained_control_scope(metadata.trace_ref(), &control(1_000))
                    .unwrap()
                    .delivery_scope,
                scope()
            );
            {
                let connection = ledger.connection.lock().unwrap();
                match changed {
                    "provider" => {
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET provider_id='other.provider'",
                                [],
                            )
                            .unwrap();
                    }
                    "revision" => {
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET registration_revision=8",
                                [],
                            )
                            .unwrap();
                    }
                    _ => {
                        let mut envelope: serde_json::Value =
                            serde_json::from_str(metadata.delivery_scope_json()).unwrap();
                        match changed {
                            "scope" => {
                                envelope["delivery_scope"]["agent_session_id"] =
                                    "session.changed".into();
                            }
                            "hash" => {
                                envelope["scope_binding_sha256"] = "f".repeat(64).into();
                            }
                            "version" => {
                                envelope["version"] = 2.into();
                            }
                            _ => unreachable!(),
                        }
                        connection
                            .execute(
                                "UPDATE recall_explain_traces SET delivery_scope_json=?1",
                                [serde_json::to_string(&envelope).unwrap()],
                            )
                            .unwrap();
                    }
                }
            }
            assert!(
                ledger
                    .read_retained_control_scope(metadata.trace_ref(), &control(1_000))
                    .is_err(),
                "{changed}"
            );
        }
    }

    #[test]
    fn control_reads_refuse_source_count_and_field_byte_overflow() {
        let (_temporary, ledger, metadata) = retained();
        let sources: Vec<_> = (1..=65)
            .map(|sequence| source(&format!("observation.{sequence}"), sequence))
            .collect();
        ledger.connection.lock().unwrap().execute("UPDATE recall_explain_trace_items SET original_sources_json=?1 WHERE provider_rank=2", [serde_json::to_string(&sources).unwrap()]).unwrap();
        assert!(
            ledger
                .read_retained_control_source(
                    metadata.trace_ref(),
                    &metadata.item_ref(2).unwrap(),
                    "observation.3",
                    &control(1_000)
                )
                .is_err()
        );
        ledger.connection.lock().unwrap().execute("UPDATE recall_explain_trace_items SET original_sources_json=?1 WHERE provider_rank=2", ["x".repeat(MAX_SOURCES_BYTES + 1)]).unwrap();
        assert!(matches!(
            ledger.read_retained_control_source(
                metadata.trace_ref(),
                &metadata.item_ref(2).unwrap(),
                "observation.3",
                &control(1_000)
            ),
            Err(RecallControlAttributionErrorV1::Invalid(
                "retained field byte bound"
            ))
        ));
    }

    #[test]
    fn control_connection_wait_keeps_original_deadline_and_cancellation() {
        let ledger = RecallAdmissionLedgerV1 {
            path: "unused".into(),
            connection: Mutex::new(Connection::open_in_memory().unwrap()),
            locator_key: RecallLocatorKeyV1::for_test(),
        };
        let held = ledger.connection.lock().unwrap();
        let metadata = prepared();
        let started = Instant::now();
        assert!(matches!(
            ledger.read_retained_control_scope(metadata.trace_ref(), &control(10)),
            Err(RecallControlAttributionErrorV1::Control(
                TerminalCode::DeadlineExceeded
            ))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        let cancellable = control(5_000);
        let token = cancellable.cancellation();
        std::thread::scope(|threads| {
            threads.spawn(|| {
                std::thread::sleep(Duration::from_millis(5));
                token.cancel();
            });
            let started = Instant::now();
            assert!(matches!(
                ledger.read_retained_control_scope(metadata.trace_ref(), &cancellable),
                Err(RecallControlAttributionErrorV1::Control(
                    TerminalCode::Cancelled
                ))
            ));
            assert!(started.elapsed() < Duration::from_secs(1));
        });
        drop(held);
    }
}
