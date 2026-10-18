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
pub(crate) struct RecallLocatorKeyV1(Arc<Zeroizing<Vec<u8>>>);

impl RecallLocatorKeyV1 {
    pub(crate) fn from_material(material: Vec<u8>) -> Result<Self> {
        if material.len() != 32 {
            return Err(invalid("recall locator key length"));
        }
        Ok(Self(Arc::new(Zeroizing::new(material))))
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
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
pub(crate) enum RecallControlAttributionErrorV1 {
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

/// Versioned address of the ledger's existing `(scope digest, trace id)` key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecallControlTraceRefV1 {
    wire: String,
    exact_scope_sha256: String,
    trace_id: String,
}

impl RecallControlTraceRefV1 {
    pub(crate) fn parse(value: &str) -> Result<Self> {
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

    pub(crate) fn trace_id(&self) -> &str {
        &self.trace_id
    }

    pub(crate) fn exact_scope_sha256(&self) -> &str {
        &self.exact_scope_sha256
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.wire
    }
}

/// Original provider rank in the final trace, never a normalization-list rank.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecallControlItemRefV1 {
    wire: String,
    provider_rank: usize,
}

impl RecallControlItemRefV1 {
    pub(crate) fn as_str(&self) -> &str {
        &self.wire
    }
}

/// Previously confirmed data, structurally checked but never fresh authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RetainedRecallControlBindingV1 {
    pub(crate) stable_memory_ref: String,
    pub(crate) original_sources: Vec<RecallSourceAttributionV1>,
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
    #[cfg(test)]
    pub(crate) fn prepare(
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

    pub(crate) fn prepare_with_key(
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
            )
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
        );
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
        );
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
    pub(crate) fn trace_ref(&self) -> &RecallControlTraceRefV1 {
        &self.trace_ref
    }

    pub(crate) fn item_ref(&self, provider_rank: usize) -> Option<RecallControlItemRefV1> {
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
    ) -> bool {
        if self.trace_ref.exact_scope_sha256 != scope_sha256
            || self.trace_ref.trace_id != trace.trace_id
        {
            return false;
        }
        if trace.requested_count != trace.items.len()
            || trace.registration_revision == 0
            || trace.registration_revision > i64::MAX as u64
        {
            return false;
        }
        let Ok(scope) = decode_scope_envelope(
            &self.delivery_scope_json,
            &trace.provider_id,
            trace.registration_revision,
        ) else {
            return false;
        };
        if scope.exact_scope_sha256() != self.trace_ref.exact_scope_sha256 {
            return false;
        }
        if self.scope_binding_mac
            != retained_scope_binding_mac(
                locator_key,
                &self.trace_ref.exact_scope_sha256,
                self.trace_ref.trace_id(),
                &trace.provider_id,
                trace.registration_revision,
                self.delivery_scope_json.as_bytes(),
            )
        {
            return false;
        }
        let mut candidates = BTreeSet::new();
        for (rank, item) in trace.items.iter().enumerate() {
            if item.provider_rank != rank
                || item.stage != item.host_decision.stage()
                || !candidates.insert(item.candidate_id.as_str())
            {
                return false;
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
            if row.candidate_id != item.candidate_id
                || !eligible_stage(item.stage)
                || row.binding.validated(None).is_err()
                || serde_json::to_string(&row.binding.original_sources)
                    .ok()
                    .as_deref()
                    != Some(row.original_sources_json.as_str())
            {
                return false;
            }
            let Ok(expected_mac) = binding_mac(
                locator_key,
                &trace.provider_id,
                trace.registration_revision,
                &self.trace_ref.exact_scope_sha256,
                rank,
                &row.candidate_id,
                &row.binding,
            ) else {
                return false;
            };
            if expected_mac != row.control_binding_mac {
                return false;
            }
        }
        if self.rows.keys().any(|rank| {
            trace
                .items
                .get(*rank)
                .is_none_or(|item| !eligible_stage(item.stage))
        }) {
            return false;
        }
        let Ok(bytes) = serde_json::to_vec(&(
            "recall-control-metadata-v1",
            &trace.provider_id,
            trace.registration_revision,
            &self.delivery_scope_json,
            &self.rows,
        )) else {
            return false;
        };
        if tracedecay_domain::canonical_text::sha256_hex(&bytes) != self.metadata_sha256 {
            return false;
        }
        self.control_metadata_mac
            == retained_control_metadata_mac_from_parts(
                locator_key,
                &self.trace_ref.exact_scope_sha256,
                self.trace_ref.trace_id(),
                &trace.provider_id,
                trace.registration_revision,
                &self.delivery_scope_json,
                &metadata_mac_rows(&self.rows),
            )
    }
}

/// Retained producing identity and delivery scope; the caller must authorize them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedRecallControlScopeV1 {
    pub(crate) provider_id: OwnedProviderId,
    pub(crate) registration_revision: u64,
    pub(crate) delivery_scope: OwnedExactScope,
}

impl RecallAdmissionLedgerV1 {
    /// Execute on the caller's existing blocking pool with its original control.
    pub(crate) fn read_retained_control_scope(
        &self,
        trace: &RecallControlTraceRefV1,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        self.with_control_connection(control, |connection| {
            validate_retained_trace_identity_on_connection(connection, trace, &self.locator_key)?;
            read_retained_control_scope_on_connection(connection, trace, control, &self.locator_key)
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
            scope.provider_id.as_str(),
            scope.registration_revision,
            provider_rank,
            &candidate_id,
            &item_bytes,
        );
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
    ) != control_metadata_mac
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
    );
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
    );
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
    Ok(hmac_hex(
        locator_key,
        b"tracedecay.recall-control-binding-mac.v1",
        &[&bytes],
    ))
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
        provider_id,
        RETAINED_MEMORY_REF_PREFIX,
        trace,
        registration_revision,
        provider_rank,
        candidate_id,
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

pub(crate) fn redact_retained_source_attribution_with_key(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    source: &RecallSourceAttributionV1,
) -> Result<RecallSourceAttributionV1> {
    let locator = |field: &str, value: &str| {
        opaque_control_locator(
            locator_key,
            provider_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
            trace,
            registration_revision,
            provider_rank,
            candidate_id,
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
            provider_id,
            trace,
            registration_revision,
            provider_rank,
            candidate_id,
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
    let locator = |field: &str, value: &str| {
        opaque_control_locator(
            locator_key,
            provider_id,
            RETAINED_SOURCE_LOCATOR_PREFIX,
            trace,
            registration_revision,
            provider_rank,
            candidate_id,
            field,
            value,
        )
    };
    let digest = opaque_control_digest(
        locator_key,
        provider_id,
        trace,
        registration_revision,
        provider_rank,
        candidate_id,
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
    provider_id: &str,
    prefix: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    field: &str,
    value: &str,
) -> Result<String> {
    Ok(format!(
        "{prefix}{}",
        opaque_control_digest(
            locator_key,
            provider_id,
            trace,
            registration_revision,
            provider_rank,
            candidate_id,
            field,
            value,
        )?
    ))
}

fn opaque_control_digest(
    locator_key: &RecallLocatorKeyV1,
    provider_id: &str,
    trace: &RecallControlTraceRefV1,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    field: &str,
    value: &str,
) -> Result<String> {
    let revision = registration_revision.to_be_bytes();
    let rank = (provider_rank as u64).to_be_bytes();
    Ok(hmac_hex(
        locator_key,
        b"tracedecay.recall-control-opaque-locator.v2",
        &[
            trace.exact_scope_sha256.as_bytes(),
            trace.trace_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
            &rank,
            candidate_id.as_bytes(),
            field.as_bytes(),
            value.as_bytes(),
        ],
    ))
}

fn hmac_hex(locator_key: &RecallLocatorKeyV1, domain: &[u8], fields: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(locator_key.bytes())
        .expect("RecallLocatorKeyV1 validates the HMAC key length");
    update_length_delimited(&mut mac, domain);
    for field in fields {
        update_length_delimited(&mut mac, field);
    }
    hex::encode(mac.finalize().into_bytes())
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
) -> String {
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

pub(crate) fn retained_item_bytes_mac(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    trace_id: &str,
    provider_id: &str,
    registration_revision: u64,
    provider_rank: usize,
    candidate_id: &str,
    item_bytes: &[u8],
) -> String {
    let revision = registration_revision.to_be_bytes();
    let rank = (provider_rank as u64).to_be_bytes();
    hmac_hex(
        locator_key,
        b"tracedecay.retained-recall-item-bytes.v1",
        &[
            exact_scope_sha256.as_bytes(),
            trace_id.as_bytes(),
            provider_id.as_bytes(),
            &revision,
            &rank,
            candidate_id.as_bytes(),
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
) -> String {
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
) -> String {
    let revision = registration_revision.to_be_bytes();
    let bytes = serde_json::to_vec(&(
        "recall-control-metadata-mac-v1",
        provider_id,
        registration_revision,
        exact_scope_sha256,
        trace_id,
        delivery_scope_json,
        rows,
    ))
    .expect("retained control metadata uses bounded serializable fields");
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

pub(crate) fn validate_opaque_retained_source(source: &RecallSourceAttributionV1) -> Result<()> {
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
    {
        if !is_opaque_locator(
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
            || !is_opaque_locator(authority_ref, RETAINED_SOURCE_LOCATOR_PREFIX)
        {
            return Err(invalid("retained source scope is not opaque"));
        }
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

/// Projects the trace identity into the same durable host-owned namespace as
/// its candidate and source locators. The registry's deterministic trace id
/// is useful while reconciling an in-memory result, but the retained trace
/// reference must not expose a dictionary-recoverable request id.
pub(crate) fn retained_trace_id_with_key(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    request_id: &str,
    provider_id: &str,
    registration_revision: u64,
) -> String {
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
pub(crate) fn retained_candidate_identity_alias_for_context(
    locator_key: &RecallLocatorKeyV1,
    exact_scope_sha256: &str,
    request_id: &str,
    provider_id: &str,
    registration_revision: u64,
    candidate_id: &str,
) -> String {
    let revision = registration_revision.to_be_bytes();
    format!(
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
        )
    )
}

pub(crate) fn retained_candidate_identity_alias_for_report(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
    candidate_id: &str,
) -> String {
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
pub(crate) fn retained_candidate_identity_aliases_for_report(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
) -> BTreeMap<String, String> {
    let raw_ids = report
        .received_candidate_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut retained_ids = BTreeSet::new();
    let mut aliases = BTreeMap::new();
    for candidate_id in &report.received_candidate_ids {
        let base = retained_candidate_identity_alias_for_report(report, locator_key, candidate_id);
        let mut retained = base.clone();
        let mut suffix = 0usize;
        while raw_ids.contains(retained.as_str()) || retained_ids.contains(retained.as_str()) {
            suffix = suffix.saturating_add(1);
            retained = format!("{base}.{suffix}");
        }
        retained_ids.insert(retained.clone());
        aliases.insert(candidate_id.clone(), retained);
    }
    aliases
}

/// Opaque stable reference retained alongside an admission denial. This uses
/// the same candidate alias context as explain/control retention, making rows
/// correlatable without exposing the provider's reference bytes.
pub(crate) fn opaque_denial_stable_memory_ref(
    report: &tracedecay_memory_provider_registry::RecallAdmissionReport,
    locator_key: &RecallLocatorKeyV1,
    retained_candidate_id: &str,
    stable_memory_ref: &str,
) -> String {
    let provider_id = report.provider_id.as_deref().unwrap_or("provider.unknown");
    let revision = report.registration_revision.unwrap_or(0).to_be_bytes();
    format!(
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
        )
    )
}

/// Retained candidate ids must already be host projections. A missing alias is
/// a typed refusal at the ledger boundary; it can never fall back to raw bytes.
pub(crate) fn validate_retained_trace_candidate_id(value: &str) -> Result<()> {
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

fn require_size(value: &str, maximum: usize) -> Result<()> {
    if value.len() > maximum {
        return Err(invalid("metadata byte bound"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::RecallAdmissionLedgerWriteV1;
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;
    use tracedecay_memory_provider_registry::{
        CancellationToken, RecallExplainItemV1, RecallExplainProviderExplanationV1,
    };

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
            ),
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
    fn retained_trace_identity_is_keyed_and_context_bound() {
        let key = RecallLocatorKeyV1::for_test();
        let scope = "b".repeat(64);
        let first = retained_trace_id_with_key(
            &key,
            &scope,
            "request.secret-looking-id",
            "provider.native",
            7,
        );
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
        );
        assert_ne!(
            first,
            retained_trace_id_with_key(&key, &scope, "request.other", "provider.native", 7,)
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
        );
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
        );
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
