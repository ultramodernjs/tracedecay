//! Real-worker diagnostic for namespace-seed-dependent Codex history recall.
//!
//! The fixture sends the same four message observations and the same query to
//! six independent 64-hex namespaces by default. Inspection proves whether
//! all four observations reached durable NCM state; recall then proves whether
//! a candidate loss happened after admission. Handshake and inspection
//! digests retain only bounded identities and hashes, never message content.

#![cfg(all(feature = "real-encoder", unix))]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![doc = "Real NCM worker diagnostic for seed-dependent Codex history recall."]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tempfile::TempDir;
use tracedecay_memory_ncm_core::types::SourceId;
use tracedecay_memory_ncm_runtime::client::{WorkerClient, WorkerOptions};
use tracedecay_memory_ncm_runtime::engine::{ObserveRequest, Outcome};
use tracedecay_memory_ncm_runtime::ports::Deadline;
use tracedecay_memory_ncm_runtime::wire::{Operation, Reply, Request};

static WORKER_BINARY: OnceLock<PathBuf> = OnceLock::new();

fn worker_binary() -> PathBuf {
    WORKER_BINARY
        .get_or_init(|| {
            let path = std::env::var_os("CARGO_BIN_EXE_tracedecay-ncm-worker")
                .map(PathBuf::from)
                .expect("Bazel must supply the NCM worker executable");
            assert!(path.is_absolute(), "NCM worker executable must be absolute");
            assert!(path.is_file(), "NCM worker executable must exist");
            path
        })
        .clone()
}
const MODEL_ROOT_ENV: &str = "TRACEDECAY_NCM_REAL_MODEL_ROOT";
// Set FIXED_SEED_ENV to select one exact prefix deterministically. Pair it
// with FIXED_SEED_REPEATS_ENV to run that prefix repeatedly; set
// SEED_COUNT_ENV to sweep a deterministic prefix of the varied seed list.
const FIXED_SEED_ENV: &str = "TRACEDECAY_NCM_REAL_FIXED_SEED";
const SEED_COUNT_ENV: &str = "TRACEDECAY_NCM_REAL_SEED_COUNT";
const FIXED_SEED_REPEATS_ENV: &str = "TRACEDECAY_NCM_REAL_FIXED_SEED_REPEATS";
const SEED_PREFIX_HEX_LEN: usize = 16;
const MAX_VARIED_SEED_COUNT: usize = 32;
const MAX_FIXED_SEED_REPEATS: usize = 128;
const EXTRA_SEED_BASE: u64 = 0x8000_0000_0000_0000;
const MIN_RECALL_ACTIVATION: f64 = 0.03;
const CALL_DEADLINE: Duration = Duration::from_secs(30);
const QUERY_TEXT: &str =
    "what did the quicksilver retry budget change record, down to the obsidian-ledger-tail note?";

/// Distinct first sixteen hex digits become distinct deterministic projection
/// seeds. The remaining forty-eight digits keep every namespace valid.
const NAMESPACE_SEEDS: [&str; 6] = [
    "0000000000000001",
    "0000000000000011",
    "0000000000000101",
    "0000000000001001",
    // Recovered from the intermittent cold-start 2/4 and fresh 4/4 runs.
    "490f00f66e94ca18", // 5264427547836598808
    "7061cce2694b084b", // 8097978877790062667
];

const DEFAULT_SEED_COUNT: usize = NAMESPACE_SEEDS.len();

const CODEX_HISTORY: [(u64, &str, &str); 4] = [
    (
        2,
        "how does the quicksilver transport probe decide its retry budget?",
        "user: how does the quicksilver transport probe decide its retry budget?",
    ),
    (
        3,
        "the quicksilver transport probe reads its retry budget from the pinned deadline",
        "assistant: the quicksilver transport probe reads its retry budget from the pinned deadline",
    ),
    (
        4,
        "what did the quicksilver retry budget change actually record?",
        "user: what did the quicksilver retry budget change actually record?",
    ),
    (
        5,
        "the quicksilver transport probe records its retry budget change in three places: the pinned deadline it reads at construction, the attempt ledger it advances on every refused delivery, and the operator-visible note the session leaves behind, which ends with obsidian-ledger-tail",
        "assistant: the quicksilver transport probe records its retry budget change in three places: the pinned deadline it reads at construction, the attempt ledger it advances on every refused delivery, and the operator-visible note the session leaves behind, which ends with obsidian-ledger-tail",
    ),
];

#[derive(Debug)]
struct CandidateEvidence {
    record_id: u64,
    source: String,
    activation: f64,
    key_sha256: String,
    value_sha256: String,
    payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeedRun {
    seed_prefix: String,
    namespace_variant: usize,
}

#[derive(Debug)]
struct NamespaceResult {
    seed_prefix: String,
    namespace_variant: usize,
    algorithm: Value,
    encoder: Value,
    projection_sha256: String,
    observed_record_ids: Vec<u64>,
    inspected_records: u64,
    inspected_sources: u64,
    state_digest: String,
    stm_terrain_digest: u64,
    ltm_terrain_digest: u64,
    recall_outcome: &'static str,
    candidate_ids: Vec<u64>,
    candidate_evidence: Vec<CandidateEvidence>,
    candidate_count: usize,
    recall_truncated: bool,
}

fn namespace(seed_prefix: &str, namespace_variant: usize) -> String {
    assert_eq!(seed_prefix.len(), SEED_PREFIX_HEX_LEN);
    assert!(namespace_variant < MAX_FIXED_SEED_REPEATS);
    format!("{seed_prefix}{namespace_variant:048x}")
}

fn parse_fixed_seed(value: &str) -> Result<String, String> {
    if value.len() != SEED_PREFIX_HEX_LEN {
        return Err(format!(
            "must contain exactly {SEED_PREFIX_HEX_LEN} ASCII hex digits"
        ));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "must contain only ASCII hex digits in its {SEED_PREFIX_HEX_LEN}-digit prefix"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_seed_count(value: &str) -> Result<usize, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("must be an unsigned decimal seed count".to_owned());
    }
    let count = value
        .parse::<usize>()
        .map_err(|_| "does not fit in the platform seed-count integer".to_owned())?;
    if !(1..=MAX_VARIED_SEED_COUNT).contains(&count) {
        return Err(format!(
            "must be between 1 and {MAX_VARIED_SEED_COUNT} (inclusive)"
        ));
    }
    Ok(count)
}

fn parse_fixed_seed_repeats(value: &str) -> Result<usize, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("must be an unsigned decimal fixed-seed repeat count".to_owned());
    }
    let repeats = value
        .parse::<usize>()
        .map_err(|_| "does not fit in the platform fixed-seed repeat count".to_owned())?;
    if !(1..=MAX_FIXED_SEED_REPEATS).contains(&repeats) {
        return Err(format!(
            "must be between 1 and {MAX_FIXED_SEED_REPEATS} (inclusive)"
        ));
    }
    Ok(repeats)
}

fn varied_seed_runs(count: usize) -> Result<Vec<SeedRun>, String> {
    if !(1..=MAX_VARIED_SEED_COUNT).contains(&count) {
        return Err(format!(
            "varied seed count must be between 1 and {MAX_VARIED_SEED_COUNT} (inclusive)"
        ));
    }

    let built_in = NAMESPACE_SEEDS.iter().take(count).map(|seed| SeedRun {
        seed_prefix: (*seed).to_owned(),
        namespace_variant: 0,
    });
    let extra = (NAMESPACE_SEEDS.len().min(count)..count).map(|index| SeedRun {
        seed_prefix: format!(
            "{:016x}",
            EXTRA_SEED_BASE + (index - NAMESPACE_SEEDS.len()) as u64
        ),
        namespace_variant: 0,
    });
    Ok(built_in.chain(extra).collect())
}

fn select_seed_runs(
    fixed_seed: Option<&str>,
    seed_count: Option<&str>,
    fixed_seed_repeats: Option<&str>,
) -> Result<Vec<SeedRun>, String> {
    if fixed_seed_repeats.is_some() && fixed_seed.is_none() {
        return Err(format!(
            "{FIXED_SEED_REPEATS_ENV} requires {FIXED_SEED_ENV}"
        ));
    }
    if seed_count.is_some() && fixed_seed.is_some() {
        return Err(format!(
            "{FIXED_SEED_ENV} and {SEED_COUNT_ENV} cannot be set together"
        ));
    }
    if seed_count.is_some() && fixed_seed_repeats.is_some() {
        return Err(format!(
            "{SEED_COUNT_ENV} and {FIXED_SEED_REPEATS_ENV} cannot be set together"
        ));
    }

    if let Some(fixed_seed) = fixed_seed {
        let seed_prefix = parse_fixed_seed(fixed_seed)?;
        let repeats = fixed_seed_repeats
            .map(parse_fixed_seed_repeats)
            .transpose()?
            .unwrap_or(1);
        return Ok((0..repeats)
            .map(|namespace_variant| SeedRun {
                seed_prefix: seed_prefix.clone(),
                namespace_variant,
            })
            .collect());
    }

    let count = seed_count
        .map(parse_seed_count)
        .transpose()?
        .unwrap_or(DEFAULT_SEED_COUNT);
    varied_seed_runs(count)
}

fn optional_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn configured_seed_runs() -> Vec<SeedRun> {
    let fixed_seed = optional_env(FIXED_SEED_ENV)
        .unwrap_or_else(|error| panic!("invalid {FIXED_SEED_ENV}: {error}"));
    let seed_count = optional_env(SEED_COUNT_ENV)
        .unwrap_or_else(|error| panic!("invalid {SEED_COUNT_ENV}: {error}"));
    let fixed_seed_repeats = optional_env(FIXED_SEED_REPEATS_ENV)
        .unwrap_or_else(|error| panic!("invalid {FIXED_SEED_REPEATS_ENV}: {error}"));
    select_seed_runs(
        fixed_seed.as_deref(),
        seed_count.as_deref(),
        fixed_seed_repeats.as_deref(),
    )
    .unwrap_or_else(|error| panic!("invalid namespace seed controls: {error}"))
}

fn real_worker_state_root() -> TempDir {
    let configured = PathBuf::from(std::env::var_os(MODEL_ROOT_ENV).unwrap_or_else(|| {
        panic!("{MODEL_ROOT_ENV} is required for the ignored real-worker diagnostic")
    }));
    assert!(
        configured.is_absolute(),
        "{MODEL_ROOT_ENV} must be an absolute installed fixture root"
    );
    let models = configured
        .join("models")
        .canonicalize()
        .unwrap_or_else(|error| panic!("{MODEL_ROOT_ENV}/models is unavailable: {error}"));
    assert!(
        models.is_dir(),
        "installed NCM model directory must be a directory"
    );

    let state_root = TempDir::new().expect("isolated NCM state root");
    std::os::unix::fs::symlink(&models, state_root.path().join("models"))
        .expect("share installed model artifacts through a read-only symlink");
    state_root
}

fn source_id(sequence: u64) -> String {
    format!("codex-history-source-{sequence}")
}

fn provenance(sequence: u64) -> Value {
    json!({
        "provider": "codex",
        "native_record_kind": "event_msg",
        "observation_kind": "session.message_committed.v1",
        "canonical_session_id": "codex-seed-sweep-session",
        "source_sequence": sequence,
    })
}

fn observe_request(sequence: u64, key_text: &str, value_text: &str) -> ObserveRequest {
    ObserveRequest {
        idempotency_key: format!("codex-history-seed-sweep-{sequence}"),
        payload_sha256: String::new(),
        source: SourceId(source_id(sequence)),
        key_text: key_text.to_owned(),
        value_text: value_text.to_owned(),
        affect: None,
        surprise: 0.4,
        intensity: 1.0,
        provenance: provenance(sequence),
        deadline: Deadline {
            remaining_ms: u64::MAX,
        },
    }
}

fn expected_payload_sha256(sequence: u64, key_text: &str, value_text: &str) -> String {
    let mut request = observe_request(sequence, key_text, value_text);
    request.payload_sha256 = request
        .canonical_payload_sha256()
        .expect("Codex history observation payload is serializable");
    request.payload_sha256
}

fn observe_payload(sequence: u64, key_text: &str, value_text: &str) -> Value {
    let mut request = observe_request(sequence, key_text, value_text);
    request.payload_sha256 = request
        .canonical_payload_sha256()
        .expect("Codex history observation payload is serializable");
    json!({
        "idempotency_key": request.idempotency_key,
        "payload_sha256": request.payload_sha256,
        "source": request.source.0,
        "key_text": request.key_text,
        "value_text": request.value_text,
        "affect": request.affect,
        "surprise": request.surprise,
        "intensity": request.intensity,
        "provenance": request.provenance,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn content_sha256(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

fn source_sequence(source: &str) -> Option<u64> {
    source
        .strip_prefix("codex-history-source-")
        .and_then(|sequence| sequence.parse().ok())
}

fn candidate_payload_sha256(source: &str, key_text: &str, value_text: &str) -> String {
    let Some(sequence) = source_sequence(source) else {
        return "invalid-source".to_owned();
    };
    let mut request = observe_request(sequence, key_text, value_text);
    request.source = SourceId(source.to_owned());
    request
        .canonical_payload_sha256()
        .expect("recalled candidate payload is serializable")
}

fn expected_history_for_source(source: &str) -> Option<(u64, &'static str, &'static str, u64)> {
    CODEX_HISTORY
        .iter()
        .enumerate()
        .find_map(|(index, (sequence, key_text, value_text))| {
            (source_id(*sequence) == source).then_some((
                *sequence,
                *key_text,
                *value_text,
                index as u64 + 1,
            ))
        })
}

fn assert_success(reply: &Reply, operation: &str) {
    assert!(
        matches!(reply.outcome, Outcome::Success),
        "{operation} must succeed; outcome={:?}",
        reply.outcome
    );
}

fn recall_evidence(reply: &Reply) -> (Vec<CandidateEvidence>, bool) {
    if reply.outcome == Outcome::Empty {
        return (Vec::new(), false);
    }
    assert_success(reply, "recall");
    let payload = reply.payload.as_ref().expect("successful recall payload");
    let candidates = payload["Candidates"]["candidates"]
        .as_array()
        .expect("successful recall candidate array");
    let evidence = candidates
        .iter()
        .map(|candidate| {
            let record_id = candidate["record_id"]
                .as_u64()
                .expect("recall candidate record id");
            let source = candidate["source"]
                .as_str()
                .expect("recall candidate source")
                .to_owned();
            let key_text = candidate["key_text"]
                .as_str()
                .expect("recall candidate key text");
            let value_text = candidate["value_text"]
                .as_str()
                .expect("recall candidate value text");
            CandidateEvidence {
                record_id,
                source: source.clone(),
                activation: candidate["activation"]
                    .as_f64()
                    .expect("recall candidate activation"),
                key_sha256: content_sha256(key_text),
                value_sha256: content_sha256(value_text),
                payload_sha256: candidate_payload_sha256(&source, key_text, value_text),
            }
        })
        .collect();
    let truncated = payload["Candidates"]["truncated"]
        .as_bool()
        .expect("recall truncation flag");
    (evidence, truncated)
}

fn bounded_digest(value: &Value, field: &str) -> String {
    let digest = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("inspection field {field} must be a string"));
    assert_eq!(digest.len(), 64, "inspection field {field} must be SHA-256");
    assert!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "inspection field {field} must be hexadecimal"
    );
    digest.to_owned()
}

fn bounded_counter(value: &Value, field: &str) -> u64 {
    value[field]
        .as_u64()
        .unwrap_or_else(|| panic!("inspection field {field} must be an unsigned integer"))
}

fn summary(result: &NamespaceResult) -> String {
    format!(
        "seed={} variant={} observed_records={:?} inspected_records={} inspected_sources={} candidates={} candidate_ids={:?} candidate_activations={:?} candidate_evidence={:?} truncated={} projection={} state={} stm={} ltm={} outcome={}",
        result.seed_prefix,
        result.namespace_variant,
        result.observed_record_ids,
        result.inspected_records,
        result.inspected_sources,
        result.candidate_count,
        result.candidate_ids,
        result
            .candidate_evidence
            .iter()
            .map(|candidate| candidate.activation)
            .collect::<Vec<_>>(),
        result.candidate_evidence,
        result.recall_truncated,
        result.projection_sha256,
        result.state_digest,
        result.stm_terrain_digest,
        result.ltm_terrain_digest,
        result.recall_outcome,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built_in_runs(count: usize) -> Vec<SeedRun> {
        NAMESPACE_SEEDS[..count]
            .iter()
            .map(|seed| SeedRun {
                seed_prefix: (*seed).to_owned(),
                namespace_variant: 0,
            })
            .collect()
    }

    #[test]
    fn missing_controls_preserve_the_six_seed_default() {
        assert_eq!(
            select_seed_runs(None, None, None).expect("default seed selection"),
            built_in_runs(DEFAULT_SEED_COUNT)
        );
    }

    #[test]
    fn fixed_seed_selects_one_canonical_prefix_for_repeatable_runs() {
        assert_eq!(
            select_seed_runs(Some("ABCDEF0123456789"), None, None).expect("fixed seed selection"),
            vec![SeedRun {
                seed_prefix: "abcdef0123456789".to_owned(),
                namespace_variant: 0,
            }]
        );
    }

    #[test]
    fn seed_count_selects_bounded_deterministic_prefixes() {
        assert_eq!(
            select_seed_runs(None, Some("3"), None).expect("varied seed selection"),
            built_in_runs(3)
        );
        let runs =
            select_seed_runs(None, Some("30"), None).expect("expanded varied seed selection");
        assert_eq!(runs.len(), 30);
        assert_eq!(runs[6].seed_prefix, "8000000000000000");
        assert_eq!(runs[29].seed_prefix, "8000000000000017");
        assert!(runs.iter().all(|run| {
            run.seed_prefix.len() == SEED_PREFIX_HEX_LEN
                && run.seed_prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
                && run.namespace_variant == 0
        }));
        assert_eq!(
            runs.iter()
                .map(|run| run.seed_prefix.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            runs.len()
        );
        let maximum_runs =
            select_seed_runs(None, Some("32"), None).expect("maximum varied seed selection");
        assert_eq!(maximum_runs.len(), MAX_VARIED_SEED_COUNT);
        assert_eq!(maximum_runs[31].seed_prefix, "8000000000000019");
    }

    #[test]
    fn fixed_seed_repeats_are_bounded_and_namespace_isolated() {
        let runs = select_seed_runs(Some("0123456789abcdef"), None, Some("100"))
            .expect("fixed seed repeat selection");
        assert_eq!(runs.len(), 100);
        assert!(runs.iter().enumerate().all(|(index, run)| {
            run.seed_prefix == "0123456789abcdef" && run.namespace_variant == index
        }));
        assert_eq!(
            runs.iter()
                .map(|run| namespace(&run.seed_prefix, run.namespace_variant))
                .collect::<BTreeSet<_>>()
                .len(),
            runs.len()
        );
    }

    #[test]
    fn malformed_or_ambiguous_controls_fail_closed() {
        for fixed_seed in [
            "",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789abcdeg",
        ] {
            assert!(
                select_seed_runs(Some(fixed_seed), None, None).is_err(),
                "fixed seed should be rejected: {fixed_seed:?}"
            );
        }
        for seed_count in [
            "",
            "0",
            "-1",
            " 3",
            "3 ",
            "three",
            "999999999999999999999999",
            "33",
        ] {
            assert!(
                select_seed_runs(None, Some(seed_count), None).is_err(),
                "seed count should be rejected: {seed_count:?}"
            );
        }
        for fixed_seed_repeats in ["", "0", "129", "-1", "100 ", "many"] {
            assert!(
                select_seed_runs(Some("0123456789abcdef"), None, Some(fixed_seed_repeats),)
                    .is_err(),
                "fixed seed repeat count should be rejected: {fixed_seed_repeats:?}"
            );
        }
        assert!(select_seed_runs(None, None, Some("1")).is_err());
        assert!(select_seed_runs(Some("0123456789abcdef"), Some("1"), None).is_err());
        assert!(select_seed_runs(None, Some("1"), Some("1")).is_err());
        assert!(select_seed_runs(Some("0123456789abcdef"), Some("1"), Some("1"),).is_err());
    }
}

fn spawn_real_worker() -> (TempDir, WorkerClient) {
    let state_root = real_worker_state_root();
    let root_path = state_root.path().to_path_buf();
    let client = WorkerClient::spawn(
        worker_binary(),
        &root_path,
        WorkerOptions {
            reconciliation_deadline: CALL_DEADLINE,
            ..WorkerOptions::default()
        },
    )
    .expect("real NCM worker client starts");

    let health = client
        .call(
            Request::new(1, 0, Operation::Health, "", json!({})),
            CALL_DEADLINE,
        )
        .expect("real NCM worker health reply");
    assert_success(&health, "health");
    assert_eq!(
        health.payload.as_ref().expect("health payload")["encoder_ready"],
        true
    );

    (state_root, client)
}

fn run_namespace(
    client: &WorkerClient,
    namespace_index: usize,
    seed_run: &SeedRun,
) -> NamespaceResult {
    let namespace = namespace(&seed_run.seed_prefix, seed_run.namespace_variant);
    assert_eq!(namespace.len(), 64);
    assert!(namespace.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let handshake = client
        .call(
            Request::new(
                10 + namespace_index as u64,
                0,
                Operation::Handshake,
                &namespace,
                json!({}),
            ),
            CALL_DEADLINE,
        )
        .expect("namespace handshake reply");
    assert_success(&handshake, "handshake");
    let handshake_payload = handshake.payload.as_ref().expect("handshake payload");
    assert_eq!(handshake_payload["ready"], true);
    let projection_sha256 = bounded_digest(handshake_payload, "projection_sha256");
    let algorithm = handshake_payload["algorithm"].clone();
    let encoder = handshake_payload["encoder"].clone();

    let mut observed_record_ids = Vec::with_capacity(CODEX_HISTORY.len());
    for (offset, (sequence, key_text, value_text)) in CODEX_HISTORY.into_iter().enumerate() {
        let observed = client
            .call(
                Request::new(
                    100 + namespace_index as u64 * 10 + offset as u64,
                    0,
                    Operation::Observe,
                    &namespace,
                    observe_payload(sequence, key_text, value_text),
                ),
                CALL_DEADLINE,
            )
            .expect("Codex history observation reply");
        assert_success(&observed, "observe");
        let record_id = observed.payload.as_ref().expect("observe payload")["record_id"]
            .as_u64()
            .expect("observe record id");
        observed_record_ids.push(record_id);
    }

    let inspection = client
        .call(
            Request::new(
                200 + namespace_index as u64,
                0,
                Operation::Inspection,
                &namespace,
                json!({}),
            ),
            CALL_DEADLINE,
        )
        .expect("namespace inspection reply");
    assert_success(&inspection, "inspection");
    let inspection_payload = inspection.payload.as_ref().expect("inspection payload");
    let inspected_records = inspection_payload["records"]
        .as_u64()
        .expect("inspection record count");
    let inspected_sources = inspection_payload["sources"]
        .as_u64()
        .expect("inspection source count");
    let state_digest = bounded_digest(inspection_payload, "state_digest");
    let stm_terrain_digest = bounded_counter(inspection_payload, "stm_terrain_digest");
    let ltm_terrain_digest = bounded_counter(inspection_payload, "ltm_terrain_digest");

    let recall = client
        .call(
            Request::new(
                300 + namespace_index as u64,
                0,
                Operation::Recall,
                &namespace,
                json!({"query_text": QUERY_TEXT, "top_k": 16}),
            ),
            CALL_DEADLINE,
        )
        .expect("namespace recall reply");
    let (candidate_evidence, recall_truncated) = recall_evidence(&recall);
    let candidate_ids = candidate_evidence
        .iter()
        .map(|candidate| candidate.record_id)
        .collect::<Vec<_>>();
    let recall_outcome = match recall.outcome {
        Outcome::Success => "success",
        Outcome::Empty => "empty",
        _ => "other",
    };
    let candidate_count = candidate_ids.len();
    NamespaceResult {
        seed_prefix: seed_run.seed_prefix.clone(),
        namespace_variant: seed_run.namespace_variant,
        algorithm,
        encoder,
        projection_sha256,
        observed_record_ids,
        inspected_records,
        inspected_sources,
        state_digest,
        stm_terrain_digest,
        ltm_terrain_digest,
        recall_outcome,
        candidate_ids,
        candidate_evidence,
        candidate_count,
        recall_truncated,
    }
}

fn run_seed_runs(seed_runs: &[SeedRun]) -> Vec<NamespaceResult> {
    let isolate_each_run =
        seed_runs.len() > 1 && seed_runs.iter().any(|run| run.namespace_variant != 0);
    if isolate_each_run {
        // The worker catalog allows 32 namespaces, so batch fixed repeats
        // across temporary roots while keeping the test in one invocation.
        let mut results = Vec::with_capacity(seed_runs.len());
        for (batch_index, batch) in seed_runs.chunks(MAX_VARIED_SEED_COUNT).enumerate() {
            let (_state_root, client) = spawn_real_worker();
            let batch_start = batch_index * MAX_VARIED_SEED_COUNT;
            results.extend(
                batch.iter().enumerate().map(|(offset, seed_run)| {
                    run_namespace(&client, batch_start + offset, seed_run)
                }),
            );
        }
        return results;
    }

    let (_state_root, client) = spawn_real_worker();
    seed_runs
        .iter()
        .enumerate()
        .map(|(namespace_index, seed_run)| run_namespace(&client, namespace_index, seed_run))
        .collect()
}

/// The same four Codex history observations must survive admission in every
/// selected seed namespace. If recall returns 2/4 while inspection says 4/4,
/// the failure is downstream of durable admission and can be compared against
/// the seed-specific projection/state digests below. Set
/// `TRACEDECAY_NCM_REAL_FIXED_SEED` with
/// `TRACEDECAY_NCM_REAL_FIXED_SEED_REPEATS` to repeat one fixed 16-hex seed
/// in one invocation, or set `TRACEDECAY_NCM_REAL_SEED_COUNT` to select the
/// first one through thirty-two deterministic varied seeds. With neither set,
/// all six built-in seeds run.
#[test]
#[ignore = "requires TRACEDECAY_NCM_REAL_MODEL_ROOT with the pinned offline NCM model"]
#[allow(clippy::print_stderr)]
fn real_worker_codex_history_recall_is_seed_stable() {
    let seed_runs = configured_seed_runs();
    let results = run_seed_runs(&seed_runs);

    let first = &results[0];
    assert!(
        results
            .iter()
            .all(|result| result.algorithm == first.algorithm),
        "algorithm identity must stay constant across seeds: {:?}",
        results.iter().map(summary).collect::<Vec<_>>()
    );
    assert!(
        results.iter().all(|result| result.encoder == first.encoder),
        "encoder identity must stay constant across seeds: {:?}",
        results.iter().map(summary).collect::<Vec<_>>()
    );

    let projection_digests = results
        .iter()
        .map(|result| result.projection_sha256.clone())
        .collect::<BTreeSet<_>>();
    let distinct_seed_prefixes = seed_runs
        .iter()
        .map(|run| run.seed_prefix.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        projection_digests.len(),
        distinct_seed_prefixes.len(),
        "selected namespace seeds must produce distinct projection identities: {:?}",
        results.iter().map(summary).collect::<Vec<_>>()
    );

    let state_digests = results
        .iter()
        .map(|result| result.state_digest.clone())
        .collect::<BTreeSet<_>>();
    if distinct_seed_prefixes.len() > 1 {
        assert!(
            state_digests.len() > 1,
            "seed-specific projections must produce more than one persisted state digest: {:?}",
            results.iter().map(summary).collect::<Vec<_>>()
        );
    }

    let summaries = results.iter().map(summary).collect::<Vec<_>>();
    assert!(
        results
            .iter()
            .all(|result| result.observed_record_ids == [1, 2, 3, 4]),
        "all four Codex observations must receive durable record ids: {summaries:?}"
    );
    assert!(
        results.iter().all(|result| result.inspected_records == 4),
        "inspection distinguishes durable admission from downstream recall loss: {summaries:?}"
    );
    assert!(
        results.iter().all(|result| result.inspected_sources == 4),
        "each Codex history observation must retain its source identity: {summaries:?}"
    );
    assert!(
        results.iter().all(|result| !result.recall_truncated),
        "short fixture must not hit recall text budget: {summaries:?}"
    );
    assert!(
        results.iter().all(|result| result.candidate_count == 4),
        "all four admitted Codex history observations must recall for every seed; a 2/4 result is downstream candidate loss, not admission loss: {summaries:?}"
    );
    assert!(
        results
            .iter()
            .flat_map(|result| &result.candidate_evidence)
            .all(|candidate| { candidate.activation + f64::EPSILON >= MIN_RECALL_ACTIVATION }),
        "every recalled candidate must meet the calibrated activation floor: {summaries:?}"
    );
    let expected_sources = CODEX_HISTORY
        .iter()
        .map(|(sequence, _, _)| source_id(*sequence))
        .collect::<BTreeSet<_>>();
    assert!(
        results.iter().all(|result| {
            let actual_sources = result
                .candidate_evidence
                .iter()
                .map(|candidate| candidate.source.clone())
                .collect::<BTreeSet<_>>();
            actual_sources == expected_sources
                && result.candidate_evidence.iter().all(|candidate| {
                    let Some((sequence, key_text, value_text, record_id)) =
                        expected_history_for_source(&candidate.source)
                    else {
                        return false;
                    };
                    candidate.record_id == record_id
                        && candidate.key_sha256 == content_sha256(key_text)
                        && candidate.value_sha256 == content_sha256(value_text)
                        && candidate.payload_sha256
                            == expected_payload_sha256(sequence, key_text, value_text)
                })
        }),
        "recalled candidates must preserve every exact source identity and bounded payload/content digest: {summaries:?}"
    );
    assert!(
        results.iter().all(|result| {
            let expected_ids = result
                .observed_record_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let actual_ids = result
                .candidate_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            actual_ids == expected_ids
        }),
        "recall candidate IDs must equal the four admitted record IDs: {summaries:?}"
    );

    eprintln!(
        "real NCM namespace-seed recall diagnostic: {}",
        results.iter().map(summary).collect::<Vec<_>>().join("; ")
    );
}
