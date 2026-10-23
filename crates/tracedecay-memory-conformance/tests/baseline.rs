//! Behavioral tests for the no-memory, explicit-documentation, and provider
//! baseline lanes over the checked-in coding-memory scenario corpus.
//!
//! The provider lane is exercised here with an in-memory test provider that
//! implements the real `MemoryProvider` boundary so lane mechanics (handshake
//! per scope, control preflight, replay, cancellation boundaries, deletion,
//! state-load corruption) run through real typed calls. It is a test double
//! for lane behavior only; the real Native baseline runs inside the root crate
//! against the production `NativeProvider` and its application port.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracedecay_memory_conformance::{
    BaselineComparison, BaselineError, BaselineLane, BaselineReport, BaselineRunConfig,
    BaselineRunner, CheckVerdict, CorpusError, CountRecord, LaneKind, O200K_BASE_ESTIMATOR_ID,
    O200K_BASE_ESTIMATOR_REVISION, O200kBaseTokenEstimator, ProviderLane, ScenarioCorpus,
    StepOutcome, TokenEstimateError, TokenEstimator, TokenEstimatorIdentity, TokenRecord,
};
use tracedecay_memory_provider_api::contract::{CommittedEffectState, TerminalCode};
use tracedecay_memory_provider_api::{
    CanonicalPayload, CommittedEffectEvidence, FallbackDirective, HandshakeRequest,
    HandshakeResponse, MemoryProvider, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
    ProviderCall, ProviderDescriptor, ProviderLimits, ProviderOperation, ProviderReply,
    TerminalRecord,
};

const CORPUS_PATH: &str = "../../product/evaluation/coding-memory-scenarios.v1.json";
const BUILD_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const EFFECT_RECEIPT: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const REGISTRATION_REVISION: u64 = 7;
static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn corpus_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
    // Bazel's launcher supplies this run's manifest directory; the compiled
    // value may name a different execroot when the binary came from cache.
    let path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest directory")?)
        .join(CORPUS_PATH);
    Ok(std::fs::read(path)?)
}

fn load_corpus() -> Result<ScenarioCorpus, Box<dyn Error>> {
    Ok(ScenarioCorpus::from_json_bytes(&corpus_bytes()?)?)
}

/// Per-test fixture root under the OS temporary directory. The directory is
/// removed when the guard drops (normal return or unwinding), so a run leaves
/// nothing behind; keep the guard alive for as long as the runner it feeds.
struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let ordinal = WORKSPACE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "tracedecay-baseline-{label}-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(Self(root))
    }

    fn config(&self) -> BaselineRunConfig {
        BaselineRunConfig::new(self.0.join("workspaces"))
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Byte-length estimator pinned by the test so token costs become determinate.
struct ByteQuarterEstimator;

impl TokenEstimator for ByteQuarterEstimator {
    fn estimator_id(&self) -> &str {
        "test.byte-quarter"
    }

    fn estimator_revision(&self) -> &str {
        "1"
    }

    fn estimate_tokens(&self, bytes: &[u8]) -> Result<u64, TokenEstimateError> {
        Ok(u64::try_from(bytes.len().div_ceil(4)).unwrap_or(u64::MAX))
    }
}

#[derive(Clone)]
struct StoredObservation {
    operation_id: String,
    scope: OwnedExactScope,
    forget_source_key: Option<String>,
    content: String,
}

#[derive(Default)]
struct ProviderState {
    generation: u64,
    observations: BTreeMap<String, StoredObservation>,
    /// Exact scopes whose loaded state partition failed digest verification.
    corrupted_scopes: BTreeSet<String>,
    handshakes: u64,
}

/// In-memory provider for lane mechanics; implements the real boundary.
struct InMemoryTestProvider {
    provider_id: OwnedProviderId,
    limits: ProviderLimits,
    state: Mutex<ProviderState>,
}

impl InMemoryTestProvider {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            provider_id: OwnedProviderId::new("test.in-memory-baseline")?,
            limits: BaselineRunConfig::new(PathBuf::from("unused")).host_limits,
            state: Mutex::new(ProviderState::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ProviderState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn capabilities() -> Result<Vec<OwnedVersionedId>, Box<dyn Error>> {
        Ok([
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
            "deletion.by_source.v1",
            "snapshot.restore.v1",
        ]
        .into_iter()
        .map(OwnedVersionedId::new)
        .collect::<Result<Vec<_>, _>>()?)
    }

    fn descriptor_at(&self, generation: u64) -> ProviderDescriptor {
        let capabilities = Self::capabilities().unwrap_or_default();
        ProviderDescriptor::new(
            self.provider_id.clone(),
            BUILD_DIGEST,
            "in-memory-baseline.v1",
            generation,
            capabilities,
            self.limits,
        )
        .unwrap_or_else(|_| std::process::abort())
    }

    fn terminal(
        &self,
        operation: ProviderOperation,
        code: TerminalCode,
        effect: CommittedEffectEvidence,
        operation_id: &str,
        scope: &OwnedExactScope,
        diagnostic: Option<String>,
    ) -> TerminalRecord {
        TerminalRecord::new(
            operation,
            self.provider_id.clone(),
            code,
            effect,
            FallbackDirective::forbidden(),
            operation_id,
            scope.exact_scope_sha256(),
            diagnostic,
        )
        .unwrap_or_else(|_| std::process::abort())
    }

    fn reply(
        &self,
        call: &ProviderCall,
        code: TerminalCode,
        effect: CommittedEffectEvidence,
        payload: Option<Value>,
        generation: u64,
        diagnostic: Option<String>,
    ) -> ProviderReply {
        let payload = payload.and_then(|value| {
            let bytes = serde_json::to_vec(&value).ok()?;
            let sha256 = sha256_hex(&bytes);
            CanonicalPayload::new(call.payload.contract_id.clone(), bytes, sha256).ok()
        });
        ProviderReply {
            terminal: self.terminal(
                call.operation,
                code,
                effect,
                &call.operation_id,
                &call.exact_scope,
                diagnostic,
            ),
            payload,
            warnings: Vec::new(),
            extensions: Vec::new(),
            state_generation: generation,
        }
    }

    fn same_code_scope(left: &OwnedExactScope, right: &OwnedExactScope) -> bool {
        left.profile_id == right.profile_id
            && left.project_id == right.project_id
            && left.repository_identity == right.repository_identity
            && left.worktree_identity == right.worktree_identity
            && left.branch_identity == right.branch_identity
    }
}

impl MemoryProvider for InMemoryTestProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        let generation = self.lock().generation;
        self.descriptor_at(generation)
    }

    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
        let mut state = self.lock();
        state.handshakes += 1;
        let generation = state.generation;
        let failure = |code: TerminalCode| HandshakeResponse {
            terminal: self.terminal(
                ProviderOperation::Handshake,
                code,
                CommittedEffectEvidence::none(Some(generation)),
                &request.request_id,
                &request.exact_scope,
                Some(format!("test.{}", code.as_wire())),
            ),
            descriptor: None,
            provider_instance_id: None,
            state_namespace: None,
            accepted_scope: None,
            effective_limits: None,
            ready_receipt_sha256: None,
            warnings: Vec::new(),
        };
        if let Err(code) = request.control.snapshot() {
            return failure(code);
        }
        if request.provider_id != self.provider_id {
            return failure(TerminalCode::StaleIdentity);
        }
        let receipt = sha256_hex(
            format!(
                "{}:{}:{}",
                request.exact_scope.exact_scope_sha256(),
                request.registration_revision,
                state.handshakes
            )
            .as_bytes(),
        );
        HandshakeResponse {
            terminal: self.terminal(
                ProviderOperation::Handshake,
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(generation)),
                &request.request_id,
                &request.exact_scope,
                None,
            ),
            descriptor: Some(self.descriptor_at(generation)),
            provider_instance_id: Some("in-memory-instance".to_owned()),
            state_namespace: Some("in-memory".to_owned()),
            accepted_scope: Some(request.exact_scope.clone()),
            effective_limits: Some(effective_limits(request.host_limits, self.limits)),
            ready_receipt_sha256: Some(receipt),
            warnings: Vec::new(),
        }
    }

    fn invoke(&self, call: &ProviderCall) -> ProviderReply {
        let mut state = self.lock();
        let generation = state.generation;
        if let Err(code) = call.control.snapshot() {
            return self.reply(
                call,
                code,
                CommittedEffectEvidence::none(Some(generation)),
                None,
                generation,
                Some(format!("test.{}", code.as_wire())),
            );
        }
        if state
            .corrupted_scopes
            .contains(&call.exact_scope.exact_scope_sha256())
            && matches!(
                call.operation,
                ProviderOperation::Health | ProviderOperation::Recall | ProviderOperation::Observe
            )
        {
            return self.reply(
                call,
                TerminalCode::StateIncompatible,
                CommittedEffectEvidence::none(Some(generation)),
                None,
                generation,
                Some("test.state_digest_mismatch".to_owned()),
            );
        }
        match call.operation {
            ProviderOperation::Health => self.reply(
                call,
                TerminalCode::Success,
                CommittedEffectEvidence::none(Some(generation)),
                Some(json!({})),
                generation,
                None,
            ),
            ProviderOperation::Observe => {
                let Some(key) = call.idempotency_key.clone() else {
                    return self.reply(
                        call,
                        TerminalCode::InvalidRequest,
                        CommittedEffectEvidence::none(Some(generation)),
                        None,
                        generation,
                        Some("test.missing_idempotency_key".to_owned()),
                    );
                };
                if let Some(existing) = state.observations.get(&key) {
                    let effect = CommittedEffectEvidence::duplicate(
                        generation,
                        key.clone(),
                        existing.operation_id.clone(),
                        EFFECT_RECEIPT,
                    )
                    .unwrap_or_else(|_| std::process::abort());
                    return self.reply(call, TerminalCode::Success, effect, None, generation, None);
                }
                let envelope: Value =
                    serde_json::from_slice(&call.payload.bytes).unwrap_or(Value::Null);
                let forget_source_key = envelope
                    .pointer("/canonical_payload/forget_source_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let content = envelope
                    .get("canonical_payload")
                    .map(Value::to_string)
                    .unwrap_or_default();
                state.observations.insert(
                    key.clone(),
                    StoredObservation {
                        operation_id: call.operation_id.clone(),
                        scope: call.exact_scope.clone(),
                        forget_source_key,
                        content,
                    },
                );
                state.generation += 1;
                let after = state.generation;
                let effect = CommittedEffectEvidence::committed(
                    generation,
                    after,
                    vec![key],
                    EFFECT_RECEIPT,
                    call.payload.sha256.clone(),
                )
                .unwrap_or_else(|_| std::process::abort());
                self.reply(call, TerminalCode::Success, effect, None, after, None)
            }
            ProviderOperation::Recall => {
                let request: Value =
                    serde_json::from_slice(&call.payload.bytes).unwrap_or(Value::Null);
                let requested_project = request
                    .pointer("/exact_scope_identity/project_id")
                    .and_then(Value::as_str);
                if requested_project != Some(call.exact_scope.project_id.as_str()) {
                    return self.reply(
                        call,
                        TerminalCode::ScopeMismatch,
                        CommittedEffectEvidence::none(Some(generation)),
                        None,
                        generation,
                        Some("test.recall_scope_mismatch".to_owned()),
                    );
                }
                let scope = &call.exact_scope;
                let candidates: Vec<Value> = state
                    .observations
                    .iter()
                    .filter(|(_, stored)| Self::same_code_scope(&stored.scope, scope))
                    .map(|(key, stored)| {
                        json!({
                            "candidate_id": format!("candidate:{key}"),
                            "stable_memory_ref": key,
                            "content": stored.content,
                            "content_sha256": sha256_hex(stored.content.as_bytes()),
                            "exact_scope_identity": {
                                "scope_binding": "exact_coding_scope",
                                "profile_id": scope.profile_id,
                                "project_id": scope.project_id,
                                "repository_identity": scope.repository_identity,
                                "worktree_identity": scope.worktree_identity,
                                "branch_identity": scope.branch_identity,
                                "agent_session_id": scope.agent_session_id,
                                "resolved_scope_digest": scope.resolved_scope_digest,
                            },
                        })
                    })
                    .collect();
                let code = if candidates.is_empty() {
                    TerminalCode::SuccessZeroResults
                } else {
                    TerminalCode::Success
                };
                self.reply(
                    call,
                    code,
                    CommittedEffectEvidence::none(Some(generation)),
                    Some(json!({
                        "candidates": candidates,
                        "coverage": "same_code_scope",
                        "ordering": "stable_memory_ref",
                    })),
                    generation,
                    None,
                )
            }
            ProviderOperation::DeleteBySource => {
                let request: Value =
                    serde_json::from_slice(&call.payload.bytes).unwrap_or(Value::Null);
                let key = request
                    .get("forget_source_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let removed: Vec<String> = state
                    .observations
                    .iter()
                    .filter(|(_, stored)| {
                        stored.forget_source_key.is_some() && stored.forget_source_key == key
                    })
                    .map(|(stored_key, _)| stored_key.clone())
                    .collect();
                for stored_key in &removed {
                    state.observations.remove(stored_key);
                }
                state.generation += 1;
                let after = state.generation;
                let effect = CommittedEffectEvidence::committed(
                    generation,
                    after,
                    removed,
                    EFFECT_RECEIPT,
                    call.payload.sha256.clone(),
                )
                .unwrap_or_else(|_| std::process::abort());
                self.reply(call, TerminalCode::Success, effect, None, after, None)
            }
            ProviderOperation::SnapshotRestore => {
                let request: Value =
                    serde_json::from_slice(&call.payload.bytes).unwrap_or(Value::Null);
                if request.get("digest_status").and_then(Value::as_str) == Some("match") {
                    return self.reply(
                        call,
                        TerminalCode::Success,
                        CommittedEffectEvidence::none(Some(generation)),
                        None,
                        generation,
                        None,
                    );
                }
                state
                    .corrupted_scopes
                    .insert(call.exact_scope.exact_scope_sha256());
                self.reply(
                    call,
                    TerminalCode::StateIncompatible,
                    CommittedEffectEvidence::none(Some(generation)),
                    None,
                    generation,
                    Some("test.snapshot_digest_mismatch".to_owned()),
                )
            }
            _ => self.reply(
                call,
                TerminalCode::CapabilityUnsupported,
                CommittedEffectEvidence::none(Some(generation)),
                None,
                generation,
                Some("test.capability_unsupported".to_owned()),
            ),
        }
    }
}

fn effective_limits(host: ProviderLimits, provider: ProviderLimits) -> ProviderLimits {
    ProviderLimits {
        request_bytes: host.request_bytes.min(provider.request_bytes),
        response_bytes: host.response_bytes.min(provider.response_bytes),
        observation_batch_items: host
            .observation_batch_items
            .min(provider.observation_batch_items),
        recall_candidates: host.recall_candidates.min(provider.recall_candidates),
        concurrent_operations: host
            .concurrent_operations
            .min(provider.concurrent_operations),
        operation_millis: host.operation_millis.min(provider.operation_millis),
        snapshot_bytes: host.snapshot_bytes.min(provider.snapshot_bytes),
        inspection_items: host.inspection_items.min(provider.inspection_items),
    }
}

fn run_all_lanes(
    corpus: &ScenarioCorpus,
    label: &str,
) -> Result<(BaselineReport, BaselineReport, BaselineReport), Box<dyn Error>> {
    let provider = InMemoryTestProvider::new()?;
    let scratch = ScratchRoot::create(label)?;
    let runner = BaselineRunner::new(corpus, scratch.config())?;
    let no_memory = runner.run(&BaselineLane::NoMemory)?.report;
    let docs = runner.run(&BaselineLane::ExplicitDocumentation)?.report;
    let lane = BaselineLane::Provider(ProviderLane::new(&provider, REGISTRATION_REVISION)?);
    let provided = runner.run(&lane)?.report;
    Ok((no_memory, docs, provided))
}

#[test]
fn corpus_loads_and_binds_every_recall_request_exactly_once() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    assert_eq!(corpus.scenarios().len(), 9);
    assert_eq!(corpus.recall_requests().len(), 12);
    assert_eq!(corpus.corpus_sha256(), sha256_hex(&corpus_bytes()?));
    assert!(corpus.provider_neutral());
    Ok(())
}

#[test]
fn corpus_loader_rejects_digest_and_reference_faults() -> Result<(), Box<dyn Error>> {
    let text = String::from_utf8(corpus_bytes()?)?;
    let mut value: Value = serde_json::from_str(&text)?;

    // Fixture content digest drift.
    let mut drifted = value.clone();
    drifted["fixtures"][0]["files"][0]["revisions"][0]["content"] = json!("tampered");
    let error = ScenarioCorpus::from_json_bytes(&serde_json::to_vec(&drifted)?).err();
    assert!(
        matches!(error, Some(CorpusError::RevisionDigestMismatch { .. })),
        "{error:?}"
    );

    // Unknown catalogued request.
    let mut unknown = value.clone();
    unknown["scenarios"][0]["steps"][3]["request_id"] = json!("request_missing");
    let error = ScenarioCorpus::from_json_bytes(&serde_json::to_vec(&unknown)?).err();
    assert!(
        matches!(error, Some(CorpusError::UnknownReference { .. })),
        "{error:?}"
    );

    // A batch without its observation_batch_requested template: the runner
    // derives batch items only from that template, never from defaults.
    let mut templateless = value.clone();
    let cancellation = templateless["scenarios"]
        .as_array()
        .and_then(|scenarios| {
            scenarios
                .iter()
                .position(|scenario| scenario["id"] == json!("cancellation"))
        })
        .ok_or("cancellation scenario")?;
    let observations = templateless["scenarios"][cancellation]["observations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    templateless["scenarios"][cancellation]["observations"] = Value::Array(
        observations
            .into_iter()
            .filter(|observation| observation["event_type"] != json!("observation_batch_requested"))
            .collect(),
    );
    let error = ScenarioCorpus::from_json_bytes(&serde_json::to_vec(&templateless)?).err();
    assert!(
        matches!(
            &error,
            Some(CorpusError::MissingBatchTemplate { scenario_id, batch_id })
                if scenario_id == "cancellation" && batch_id == "batch_cancel_001"
        ),
        "{error:?}"
    );

    // Request referenced twice.
    let steps = value["scenarios"][0]["steps"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut duplicated = steps.clone();
    duplicated.insert(
        4,
        json!({"step": 5, "action": "recall", "request_id": "request_stale_001"}),
    );
    duplicated[5]["step"] = json!(6);
    value["scenarios"][0]["steps"] = Value::Array(duplicated);
    let error = ScenarioCorpus::from_json_bytes(&serde_json::to_vec(&value)?).err();
    assert!(
        matches!(error, Some(CorpusError::RecallRequestReferenceCount { .. })),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn all_lanes_share_identical_inputs_and_are_comparable() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let (no_memory, docs, provided) = run_all_lanes(&corpus, "shared")?;
    assert_eq!(
        no_memory.identity.shared_inputs_sha256,
        docs.identity.shared_inputs_sha256
    );
    assert_eq!(
        docs.identity.shared_inputs_sha256,
        provided.identity.shared_inputs_sha256
    );
    assert_eq!(
        no_memory.identity.shared_inputs,
        provided.identity.shared_inputs
    );
    assert_ne!(
        no_memory.identity.run_identity_sha256,
        docs.identity.run_identity_sha256
    );
    assert_eq!(no_memory.identity.lane.kind, LaneKind::NoMemory);
    assert_eq!(docs.identity.lane.kind, LaneKind::ExplicitDocumentation);
    assert_eq!(provided.identity.lane.kind, LaneKind::Provider);
    assert_eq!(
        provided.identity.lane.lane_id,
        "provider:test.in-memory-baseline"
    );
    let provider_identity = provided
        .identity
        .lane
        .provider
        .as_ref()
        .ok_or("provider identity missing")?;
    assert_eq!(
        provider_identity.registration_revision,
        REGISTRATION_REVISION
    );
    assert_eq!(provider_identity.build_identity_sha256, BUILD_DIGEST);
    assert!(no_memory.identity.lane.provider.is_none());

    let comparison = BaselineComparison::compare(&[&no_memory, &docs, &provided])?;
    assert_eq!(comparison.rows.len(), 9);
    assert_eq!(comparison.lane_ids.len(), 3);
    for row in &comparison.rows {
        assert_eq!(row.lanes.len(), 3, "{}", row.scenario_id);
    }

    let duplicate = BaselineComparison::compare(&[&docs, &docs]).err();
    assert!(
        matches!(duplicate, Some(BaselineError::ComparisonInputs { .. })),
        "{duplicate:?}"
    );
    Ok(())
}

#[test]
fn reports_are_byte_identical_across_reruns_and_bound_to_inputs() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let (first_none, first_docs, first_provider) = run_all_lanes(&corpus, "rerun-a")?;
    let (second_none, second_docs, second_provider) = run_all_lanes(&corpus, "rerun-b")?;
    assert_eq!(
        first_none.to_canonical_json()?,
        second_none.to_canonical_json()?
    );
    assert_eq!(
        first_docs.to_canonical_json()?,
        second_docs.to_canonical_json()?
    );
    assert_eq!(
        first_provider.to_canonical_json()?,
        second_provider.to_canonical_json()?
    );

    // Changing the host configuration changes the shared identity.
    let altered_scratch = ScratchRoot::create("altered-host")?;
    let mut altered = altered_scratch.config();
    altered.remaining_millis += 1;
    let altered_runner = BaselineRunner::new(&corpus, altered)?;
    assert_ne!(
        altered_runner.shared_inputs_sha256(),
        first_none.identity.shared_inputs_sha256
    );
    let altered_report = altered_runner.run(&BaselineLane::NoMemory)?.report;
    let mismatch = BaselineComparison::compare(&[&first_none, &altered_report]).err();
    assert!(
        matches!(mismatch, Some(BaselineError::ComparisonInputs { .. })),
        "{mismatch:?}"
    );

    // Changing the recall catalog (a query string) changes the shared identity.
    let text = String::from_utf8(corpus_bytes()?)?;
    let mut value: Value = serde_json::from_str(&text)?;
    value["recall_requests"][0]["query"] = json!("is cache writing atomic today");
    let changed = ScenarioCorpus::from_json_bytes(&serde_json::to_vec(&value)?)?;
    let changed_scratch = ScratchRoot::create("changed-catalog")?;
    let changed_runner = BaselineRunner::new(&changed, changed_scratch.config())?;
    assert_ne!(
        changed_runner.shared_inputs_sha256(),
        first_none.identity.shared_inputs_sha256
    );
    Ok(())
}

#[test]
fn scratch_root_is_removed_after_a_run() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("cleanup")?;
    let root = scratch.0.clone();
    let config = scratch.config();
    let fixture_root = config.fixture_root.clone();
    let runner = BaselineRunner::new(&corpus, config)?;
    let report = runner.run(&BaselineLane::NoMemory)?.report;
    assert_eq!(report.scenarios.len(), corpus.scenarios().len());
    assert!(root.is_dir(), "{}", root.display());
    assert!(
        std::fs::read_dir(&fixture_root)?.next().is_none(),
        "per-scenario workspaces must be closed after the run"
    );
    drop(runner);
    drop(scratch);
    assert!(!root.exists(), "{}", root.display());
    Ok(())
}

#[test]
fn no_memory_lane_issues_no_calls_and_admits_no_context() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("no-memory")?;
    let runner = BaselineRunner::new(&corpus, scratch.config())?;
    let output = runner.run(&BaselineLane::NoMemory)?;
    assert!(output.timings.calls.is_empty());
    // The default configuration pins the production o200k_base estimator, so
    // zero admitted context is a determinate zero-token cost.
    assert_eq!(
        output.report.identity.token_estimator,
        TokenEstimatorIdentity::Pinned {
            estimator_id: O200K_BASE_ESTIMATOR_ID.to_owned(),
            estimator_revision: O200K_BASE_ESTIMATOR_REVISION.to_owned(),
        }
    );
    for scenario in &output.report.scenarios {
        assert_eq!(scenario.cost.provider_calls, 0, "{}", scenario.scenario_id);
        assert_eq!(
            scenario.cost.admitted_context_bytes, 0,
            "{}",
            scenario.scenario_id
        );
        assert_eq!(
            scenario.cost.estimated_tokens,
            TokenRecord::Estimated { tokens: 0 }
        );
        for step in &scenario.steps {
            assert!(step.provider_calls.is_empty());
            if let Some(context) = &step.context {
                assert_eq!(context.terminal_code, "success_zero_results");
                assert!(context.entries.is_empty());
                assert_eq!(
                    context.estimated_tokens,
                    TokenRecord::Estimated { tokens: 0 }
                );
            }
        }
        assert!(
            scenario.adjudication.terminal_gate.passed,
            "{} {:?}",
            scenario.scenario_id, scenario.adjudication.terminal_gate.violations
        );
    }
    let stale = output
        .report
        .scenario("stale_project_change")
        .ok_or("missing")?;
    assert_eq!(stale.cost.recall_steps, 1);
    Ok(())
}

/// Scope and corruption checks with nothing admitted must not score: a lane
/// that admits no context has no isolation evidence.
#[test]
fn no_memory_lane_earns_no_basis_points_from_vacuous_scope_or_corruption_checks()
-> Result<(), Box<dyn Error>> {
    const EVIDENCE_CHECKS: [&str; 6] = [
        "scope_exact",
        "exact_scope_match",
        "scope_preserved",
        "sibling_isolation",
        "project_isolation",
        "no_corrupt_recall",
    ];
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("no-memory-vacuous")?;
    let runner = BaselineRunner::new(&corpus, scratch.config())?;
    let report = runner.run(&BaselineLane::NoMemory)?.report;
    let mut evidence_checks_seen = 0_usize;
    for scenario in &report.scenarios {
        assert_eq!(
            scenario.adjudication.weighted_pass_basis_points, 0,
            "{} earned basis points without evidence: {:?}",
            scenario.scenario_id, scenario.adjudication.checks
        );
        assert!(!scenario.adjudication.safety_gate_passed);
        for check in &scenario.adjudication.checks {
            assert_ne!(
                check.verdict,
                CheckVerdict::Pass,
                "{} {} passed without evidence: {}",
                scenario.scenario_id,
                check.check_id,
                check.evidence
            );
            if EVIDENCE_CHECKS.contains(&check.check_id.as_str()) {
                evidence_checks_seen += 1;
                assert_eq!(check.verdict, CheckVerdict::Indeterminate);
                if check.check_id != "no_corrupt_recall" {
                    assert_eq!(
                        check.evaluator, "vacuous_zero_admission",
                        "{} {}",
                        scenario.scenario_id, check.check_id
                    );
                }
            }
        }
    }
    assert!(evidence_checks_seen >= 4, "{evidence_checks_seen}");

    // The other-project request in the no-memory lane is an empty success,
    // not a scope-aware rejection, so project isolation is not evidenced.
    let scope = report.scenario("project_worktree_scope").ok_or("missing")?;
    let project_isolation = scope
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "project_isolation")
        .ok_or("project_isolation")?;
    assert_eq!(project_isolation.verdict, CheckVerdict::Indeterminate);
    assert_eq!(project_isolation.evaluator, "vacuous_zero_admission");

    // The corruption scenario loads no provider state in this lane, so no
    // recall carries post-load evidence.
    let corruption = report.scenario("provider_corruption").ok_or("missing")?;
    let no_corrupt = corruption
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "no_corrupt_recall")
        .ok_or("no_corrupt_recall")?;
    assert_eq!(no_corrupt.verdict, CheckVerdict::Indeterminate);
    assert_eq!(no_corrupt.evidence, "no recall after state load");
    Ok(())
}

/// The shipped estimator is an exact tokenizer count, bound into the run
/// identity, and refuses non-UTF-8 bytes instead of counting altered text.
#[test]
fn default_estimator_counts_o200k_base_tokens_of_admitted_documentation()
-> Result<(), Box<dyn Error>> {
    let estimator = O200kBaseTokenEstimator;
    assert_eq!(estimator.estimator_id(), O200K_BASE_ESTIMATOR_ID);
    assert_eq!(
        estimator.estimator_revision(),
        O200K_BASE_ESTIMATOR_REVISION
    );
    assert_eq!(estimator.estimate_tokens(b"")?, 0);
    let hello = estimator.estimate_tokens("hello world".as_bytes())?;
    assert!((1..=3).contains(&hello), "{hello}");
    assert_eq!(
        estimator.estimate_tokens(&[0x68, 0x65, 0xff, 0x6c]),
        Err(TokenEstimateError::NotUtf8 { valid_up_to: 2 })
    );

    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("docs-o200k")?;
    let runner = BaselineRunner::new(&corpus, scratch.config())?;
    let report = runner.run(&BaselineLane::ExplicitDocumentation)?.report;
    assert_eq!(
        report.identity.token_estimator,
        TokenEstimatorIdentity::Pinned {
            estimator_id: O200K_BASE_ESTIMATOR_ID.to_owned(),
            estimator_revision: O200K_BASE_ESTIMATOR_REVISION.to_owned(),
        }
    );
    let stale = report.scenario("stale_project_change").ok_or("missing")?;
    let recall = stale
        .steps
        .iter()
        .find_map(|step| step.context.as_ref())
        .ok_or("recall context")?;
    assert!(!recall.entries.is_empty());
    let fixture = corpus
        .fixture(
            &corpus
                .scenario("stale_project_change")
                .ok_or("scenario")?
                .fixture_id,
        )
        .ok_or("fixture")?;
    let mut expected = 0_u64;
    for entry in &recall.entries {
        let file = fixture
            .files
            .iter()
            .find(|file| file.path == entry.source_ref)
            .ok_or("documentation file")?;
        let revision = file
            .revisions
            .iter()
            .find(|revision| Some(&revision.revision_id) == entry.revision_id.as_ref())
            .ok_or("documentation revision")?;
        expected += estimator.estimate_tokens(revision.content.as_bytes())?;
    }
    assert!(expected > 0);
    assert_eq!(
        recall.estimated_tokens,
        TokenRecord::Estimated { tokens: expected }
    );
    assert_eq!(
        stale.cost.estimated_tokens,
        TokenRecord::Estimated { tokens: expected }
    );

    // An unpinned run records typed indeterminate costs and a distinct identity.
    let mut config = scratch.config();
    config.token_estimator = None;
    let unpinned = BaselineRunner::new(&corpus, config)?
        .run(&BaselineLane::ExplicitDocumentation)?
        .report;
    assert_eq!(
        unpinned.identity.token_estimator,
        TokenEstimatorIdentity::Indeterminate
    );
    assert_eq!(
        unpinned.identity.shared_inputs_sha256,
        report.identity.shared_inputs_sha256
    );
    assert_ne!(
        unpinned.identity.run_identity_sha256,
        report.identity.run_identity_sha256
    );
    let unpinned_stale = unpinned.scenario("stale_project_change").ok_or("missing")?;
    assert_eq!(
        unpinned_stale.cost.estimated_tokens,
        TokenRecord::Indeterminate
    );
    Ok(())
}

#[test]
fn explicit_documentation_lane_admits_current_documentation_only() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let scratch = ScratchRoot::create("docs")?;
    let mut config = scratch.config();
    config.token_estimator = Some(Box::new(ByteQuarterEstimator));
    let runner = BaselineRunner::new(&corpus, config)?;
    let report = runner.run(&BaselineLane::ExplicitDocumentation)?.report;
    assert!(matches!(
        report.identity.token_estimator,
        TokenEstimatorIdentity::Pinned { .. }
    ));
    let stale = report.scenario("stale_project_change").ok_or("missing")?;
    let recall = stale
        .steps
        .iter()
        .find_map(|step| step.context.as_ref())
        .ok_or("no recall context")?;
    assert_eq!(recall.terminal_code, "success");
    let sources: Vec<&str> = recall
        .entries
        .iter()
        .map(|entry| entry.source_ref.as_str())
        .collect();
    assert_eq!(
        sources,
        vec!["docs/retry_runbook.txt", "notes/fixture_note.txt"]
    );
    assert!(
        recall
            .entries
            .iter()
            .all(|entry| entry.revision_id.is_some())
    );
    let expected_bytes: u64 = recall.entries.iter().map(|entry| entry.bytes).sum();
    assert_eq!(recall.admitted_context_bytes, expected_bytes);
    assert!(expected_bytes > 0);
    assert_eq!(
        recall.estimated_tokens,
        TokenRecord::Estimated {
            tokens: recall
                .entries
                .iter()
                .map(|entry| entry.bytes.div_ceil(4))
                .sum()
        }
    );
    assert_eq!(recall.provider_call_count, 0);
    assert_eq!(stale.cost.provider_calls, 0);

    // The other-project request is a typed scope mismatch, not silent zero results.
    let scope = report.scenario("project_worktree_scope").ok_or("missing")?;
    let other = scope
        .steps
        .iter()
        .find(|step| step.step == 5)
        .ok_or("step 5")?;
    assert!(
        matches!(other.outcome, StepOutcome::ScopeMismatch { .. }),
        "{:?}",
        other.outcome
    );
    let context = other.context.as_ref().ok_or("context")?;
    assert_eq!(context.terminal_code, "scope_mismatch");
    assert!(context.entries.is_empty());
    assert!(scope.adjudication.terminal_gate.passed);
    Ok(())
}

#[test]
fn provider_lane_records_calls_costs_and_terminal_outcomes() -> Result<(), Box<dyn Error>> {
    let corpus = load_corpus()?;
    let provider = InMemoryTestProvider::new()?;
    let scratch = ScratchRoot::create("provider")?;
    let mut config = scratch.config();
    config.token_estimator = Some(Box::new(ByteQuarterEstimator));
    let runner = BaselineRunner::new(&corpus, config)?;
    let lane = BaselineLane::Provider(ProviderLane::new(&provider, REGISTRATION_REVISION)?);
    let output = runner.run(&lane)?;
    let report = &output.report;
    assert!(!output.timings.calls.is_empty());

    // Staleness: two observations then one recall returning both candidates.
    let stale = report.scenario("stale_project_change").ok_or("missing")?;
    assert_eq!(stale.cost.recall_steps, 1);
    assert!(
        stale.cost.provider_calls >= 4,
        "{}",
        stale.cost.provider_calls
    );
    let recall = stale
        .steps
        .iter()
        .find_map(|step| step.context.as_ref())
        .ok_or("context")?;
    assert_eq!(recall.terminal_code, "success");
    assert_eq!(recall.candidate_count, CountRecord::Exact { value: 2 });
    assert_eq!(recall.entries.len(), 2);
    assert!(recall.entries.iter().all(|entry| entry.scope_match));
    assert!(recall.admitted_context_bytes > 0);
    assert!(recall.provider_response_bytes > 0);
    assert!(matches!(recall.estimated_tokens, TokenRecord::Estimated { tokens } if tokens > 0));
    let first_call = &stale.steps[0].provider_calls;
    assert_eq!(first_call[0].operation, "handshake");
    assert_eq!(first_call[1].operation, "observe");
    assert_eq!(first_call[1].committed_effect_state, "committed");
    assert!(first_call[1].request_payload_bytes > 0);

    // Cross-agent reuse handshakes the new session scope before recalling.
    let cross = report.scenario("cross_agent_reuse").ok_or("missing")?;
    let opened = cross
        .steps
        .iter()
        .find(|step| step.step == 3)
        .ok_or("step 3")?;
    assert!(matches!(
        &opened.outcome,
        StepOutcome::SessionOpened { handshake_terminal_code: Some(code), .. } if code == "success"
    ));
    let reuse = cross
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "reuse_is_available")
        .ok_or("check")?;
    assert_eq!(reuse.verdict, CheckVerdict::Pass);

    // Restart: replay is acknowledged as a duplicate and state survives.
    let restart = report.scenario("restart").ok_or("missing")?;
    let replay = restart
        .steps
        .iter()
        .find(|step| step.step == 3)
        .ok_or("step 3")?;
    let replay_call = replay
        .provider_calls
        .iter()
        .find(|call| call.operation == "observe")
        .ok_or("call")?;
    assert_eq!(
        replay_call.committed_effect_state,
        CommittedEffectState::Duplicate.as_wire()
    );
    assert_eq!(replay_call.operation_id, "operation_restart_001");
    assert!(
        replay
            .provider_calls
            .iter()
            .any(|call| call.operation == "handshake")
    );
    for check_id in ["state_survives", "replay_idempotent", "scope_preserved"] {
        let check = restart
            .adjudication
            .checks
            .iter()
            .find(|check| check.check_id == check_id)
            .ok_or(check_id)?;
        assert_eq!(
            check.verdict,
            CheckVerdict::Pass,
            "{check_id}: {}",
            check.evidence
        );
    }

    // Cancellation: the cancelled item never reaches the provider; resume replays then finishes.
    let cancellation = report.scenario("cancellation").ok_or("missing")?;
    let cancel = cancellation
        .steps
        .iter()
        .find(|step| step.step == 3)
        .ok_or("step 3")?;
    let StepOutcome::BatchCancelled { boundary } = &cancel.outcome else {
        return Err(format!("unexpected cancel outcome {:?}", cancel.outcome).into());
    };
    assert_eq!(boundary.terminal_code, "cancelled");
    assert_eq!(
        boundary.committed_item_ids,
        vec!["item_cancel_001".to_owned()]
    );
    assert_eq!(boundary.uncommitted_item_ids.len(), 2);
    let cancelled_call = cancel
        .provider_calls
        .iter()
        .find(|call| call.operation == "observe")
        .ok_or("call")?;
    assert!(!cancelled_call.provider_contacted);
    assert_eq!(cancelled_call.terminal_code, "cancelled");
    let resume = cancellation
        .steps
        .iter()
        .find(|step| step.step == 4)
        .ok_or("step 4")?;
    let StepOutcome::BatchResumed {
        replayed, resumed, ..
    } = &resume.outcome
    else {
        return Err(format!("unexpected resume outcome {:?}", resume.outcome).into());
    };
    assert_eq!(
        replayed,
        &vec![("item_cancel_001".to_owned(), "duplicate".to_owned())]
    );
    assert_eq!(resumed.len(), 2);
    assert!(resumed.iter().all(|(_, code)| code == "success"));
    assert!(cancellation.adjudication.terminal_gate.passed);

    // Corruption: state load mismatch surfaces typed terminals, no corrupt recall.
    let corruption = report.scenario("provider_corruption").ok_or("missing")?;
    let health = corruption
        .steps
        .iter()
        .find(|step| step.step == 3)
        .ok_or("step 3")?;
    assert!(
        matches!(&health.outcome, StepOutcome::Terminal { terminal_code, .. } if terminal_code == "state_incompatible")
    );
    let corrupt_recall = corruption
        .steps
        .iter()
        .find_map(|step| step.context.as_ref())
        .ok_or("context")?;
    assert_eq!(corrupt_recall.terminal_code, "state_incompatible");
    assert!(corrupt_recall.entries.is_empty());
    assert!(corruption.adjudication.terminal_gate.passed);
    for check_id in ["corruption_visible", "no_corrupt_recall"] {
        let check = corruption
            .adjudication
            .checks
            .iter()
            .find(|check| check.check_id == check_id)
            .ok_or(check_id)?;
        assert_eq!(
            check.verdict,
            CheckVerdict::Pass,
            "{check_id}: {}",
            check.evidence
        );
    }

    // Privacy: deletion by exact source key, verified absent, absent after restart.
    let privacy = report.scenario("privacy_deletion").ok_or("missing")?;
    let contexts: Vec<&_> = privacy
        .steps
        .iter()
        .filter_map(|step| step.context.as_ref())
        .collect();
    assert_eq!(contexts.len(), 3);
    assert!(!contexts[0].entries.is_empty());
    assert_eq!(contexts[1].entries.len(), contexts[0].entries.len() - 1);
    assert_eq!(contexts[2].entries.len(), contexts[0].entries.len() - 1);
    assert!(contexts.iter().all(|context| {
        context
            .entries
            .iter()
            .all(|entry| !entry.contains_forgotten_source)
    }));
    for check_id in [
        "exact_source_target",
        "verified_absence",
        "restart_persistence",
    ] {
        let check = privacy
            .adjudication
            .checks
            .iter()
            .find(|check| check.check_id == check_id)
            .ok_or(check_id)?;
        assert_eq!(
            check.verdict,
            CheckVerdict::Pass,
            "{check_id}: {}",
            check.evidence
        );
    }
    let unrelated = privacy
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "unrelated_state_preserved")
        .ok_or("check")?;
    assert_eq!(unrelated.verdict, CheckVerdict::Indeterminate);
    assert!(!privacy.adjudication.safety_gate_passed);

    // Scope isolation is earned from inspected admitted entries: the sibling
    // request admits only its exact scope, and the other project's request
    // admits only that project's own observation, never the ledger's.
    let scope = report.scenario("project_worktree_scope").ok_or("missing")?;
    let sibling = scope
        .steps
        .iter()
        .find(|step| step.step == 4)
        .and_then(|step| step.context.as_ref())
        .ok_or("sibling recall context")?;
    assert!(!sibling.entries.is_empty());
    assert!(sibling.entries.iter().all(|entry| entry.scope_match));
    let other = scope
        .steps
        .iter()
        .find(|step| step.step == 5)
        .and_then(|step| step.context.as_ref())
        .ok_or("other-project recall context")?;
    assert_eq!(other.terminal_code, "success");
    assert_eq!(other.entries.len(), 1);
    assert!(other.entries.iter().all(|entry| entry.scope_match));
    for (check_id, evaluator) in [
        ("sibling_isolation", "admitted_context_scope"),
        ("project_isolation", "other_project_request"),
    ] {
        let check = scope
            .adjudication
            .checks
            .iter()
            .find(|check| check.check_id == check_id)
            .ok_or(check_id)?;
        assert_eq!(
            check.verdict,
            CheckVerdict::Pass,
            "{check_id}: {}",
            check.evidence
        );
        assert_eq!(check.evaluator, evaluator, "{check_id}");
    }
    assert!(scope.adjudication.weighted_pass_basis_points > 0);
    Ok(())
}

#[test]
fn provider_without_optional_capabilities_gets_host_preflight_not_a_call()
-> Result<(), Box<dyn Error>> {
    struct MinimalProvider(InMemoryTestProvider);
    impl MemoryProvider for MinimalProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            let capabilities = [
                "provider.health.v1",
                "observation.accept.v1",
                "recall.query.v1",
            ]
            .into_iter()
            .map(OwnedVersionedId::new)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();
            ProviderDescriptor::new(
                self.0.provider_id.clone(),
                BUILD_DIGEST,
                "in-memory-baseline.v1",
                self.0.lock().generation,
                capabilities,
                self.0.limits,
            )
            .unwrap_or_else(|_| std::process::abort())
        }
        fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
            let mut response = self.0.handshake(request);
            response.descriptor = response.descriptor.map(|_| self.descriptor());
            response
        }
        fn invoke(&self, call: &ProviderCall) -> ProviderReply {
            self.0.invoke(call)
        }
    }
    let corpus = load_corpus()?;
    let provider = MinimalProvider(InMemoryTestProvider::new()?);
    let scratch = ScratchRoot::create("minimal")?;
    let runner = BaselineRunner::new(&corpus, scratch.config())?;
    let lane = BaselineLane::Provider(ProviderLane::new(&provider, REGISTRATION_REVISION)?);
    let report = runner.run(&lane)?.report;
    let privacy = report.scenario("privacy_deletion").ok_or("missing")?;
    let delete = privacy
        .steps
        .iter()
        .find(|step| step.step == 3)
        .ok_or("step 3")?;
    let call = delete
        .provider_calls
        .iter()
        .find(|call| call.operation == "deletion_by_source")
        .ok_or("call")?;
    assert!(!call.provider_contacted);
    assert_eq!(call.terminal_code, "capability_unsupported");
    assert_eq!(
        call.diagnostic_id.as_deref(),
        Some("host.capability_undeclared")
    );
    assert!(privacy.adjudication.terminal_gate.passed);
    let verified = privacy
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "verified_absence")
        .ok_or("check")?;
    assert_eq!(
        verified.verdict,
        CheckVerdict::Fail,
        "{}",
        verified.evidence
    );

    // A deletion the host refused before dispatch deleted nothing, so it
    // cannot evidence that deletion addressed the exact source. This check
    // previously returned Pass for any terminal but InvalidRequest, handing
    // 2000 basis points to a lane for a deletion that never happened.
    let exact_source = privacy
        .adjudication
        .checks
        .iter()
        .find(|check| check.check_id == "exact_source_target")
        .ok_or("exact_source_target")?;
    assert_eq!(
        exact_source.verdict,
        CheckVerdict::Indeterminate,
        "{}",
        exact_source.evidence
    );
    assert!(
        exact_source.evidence.contains("was not performed"),
        "{}",
        exact_source.evidence
    );
    Ok(())
}

/// A batch whose every item the provider refused has nothing on the committed
/// side of the boundary, so `effect_boundary` cannot score. `commit_item` used
/// to record every item as committed regardless of its terminal, which made a
/// lane that committed nothing look like a lane that committed everything.
#[test]
fn refused_batch_items_are_not_recorded_as_committed() -> Result<(), Box<dyn Error>> {
    // Declares observation acceptance so the descriptor stays valid and the
    // host dispatches, then refuses every observation with a non-committing
    // terminal — the shape a provider takes when it accepts the capability but
    // stores nothing for the kinds this corpus emits.
    struct RefusingObservationProvider(InMemoryTestProvider);
    impl MemoryProvider for RefusingObservationProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            self.0.descriptor()
        }
        fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse {
            self.0.handshake(request)
        }
        fn invoke(&self, call: &ProviderCall) -> ProviderReply {
            if call.operation != ProviderOperation::Observe {
                return self.0.invoke(call);
            }
            let generation = self.0.lock().generation;
            self.0.reply(
                call,
                TerminalCode::CapabilityUnsupported,
                CommittedEffectEvidence::none(Some(generation)),
                None,
                generation,
                Some("test.observation_refused".to_owned()),
            )
        }
    }
    let corpus = load_corpus()?;
    let provider = RefusingObservationProvider(InMemoryTestProvider::new()?);
    let scratch = ScratchRoot::create("refused-batch")?;
    let runner = BaselineRunner::new(&corpus, scratch.config())?;
    let lane = BaselineLane::Provider(ProviderLane::new(&provider, REGISTRATION_REVISION)?);
    let report = runner.run(&lane)?.report;

    let mut boundaries_seen = 0_usize;
    for scenario in &report.scenarios {
        for check in &scenario.adjudication.checks {
            if check.check_id != "effect_boundary" {
                continue;
            }
            boundaries_seen += 1;
            assert_eq!(
                check.verdict,
                CheckVerdict::Indeterminate,
                "{} effect_boundary scored without a committed item: {}",
                scenario.scenario_id,
                check.evidence
            );
            assert!(
                check.evidence.contains("no item committed"),
                "{} {}",
                scenario.scenario_id,
                check.evidence
            );
        }
    }
    assert!(
        boundaries_seen > 0,
        "no scenario exercised the batch effect boundary"
    );

    // The contrast that proves the check still discriminates: the same corpus
    // against a provider that does commit must still score the boundary Pass
    // with items on the committed side. Without this, the fix above could have
    // turned every effect_boundary Indeterminate and no test would have noticed.
    let healthy = InMemoryTestProvider::new()?;
    let healthy_scratch = ScratchRoot::create("committed-batch")?;
    let healthy_runner = BaselineRunner::new(&corpus, healthy_scratch.config())?;
    let healthy_lane = BaselineLane::Provider(ProviderLane::new(&healthy, REGISTRATION_REVISION)?);
    let healthy_report = healthy_runner.run(&healthy_lane)?.report;
    let mut passing_boundaries = 0_usize;
    for scenario in &healthy_report.scenarios {
        for check in &scenario.adjudication.checks {
            if check.check_id == "effect_boundary" && check.verdict == CheckVerdict::Pass {
                passing_boundaries += 1;
                assert!(
                    check.evidence.contains("committed"),
                    "{} {}",
                    scenario.scenario_id,
                    check.evidence
                );
            }
        }
    }
    assert!(
        passing_boundaries > 0,
        "a committing provider scored no passing effect boundary; the check no longer discriminates"
    );
    Ok(())
}
