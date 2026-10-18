//! End-to-end tests for the feature-gated Rust NCM worker surface.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[cfg(not(feature = "rust-backend"))]
#[test]
fn feature_off_compiles_without_starting_a_worker() {
    assert!(option_env!("CARGO_FEATURE_RUST_BACKEND").is_none());
}

#[cfg(feature = "rust-backend")]
mod enabled {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tracedecay_memory_provider_api::contract::{CommittedEffectState, TerminalCode};
    use tracedecay_memory_provider_api::{
        AdvisoryAdmissionAuthority, AdvisoryAdmissionError, CancellationToken, CanonicalPayload,
        CurrentAdvisoryAdmission, GrantedHistorySource, HandshakeRequest, HandshakeRequestParts,
        MemoryProvider, OperationControl, OwnedExactScope, OwnedProviderId, OwnedVersionedId,
        PayloadSanitizationReceipt, PayloadSanitizationReceiptParts, ProviderCall,
        ProviderCallParts, ProviderLimits, ProviderOperation, ProviderReply,
        observation_extensions_digest,
    };
    use tracedecay_memory_provider_ncm::{
        NCM_PROVIDER_ID, NcmCognitiveSurface, NcmNamespaceBinding, NcmProviderAdapter,
        NcmSurfaceCall, NcmSurfaceHandshakeRequest, NcmSurfaceHandshakeResponse, RustNcmConfig,
        RustNcmSurface, RustNcmWorkerOwner, StateRoot, WorkerOptions,
    };

    const RESOLVED_SCOPE_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const TEST_SANITIZER_REVISION: &str =
        "tracedecay.memory.observation.hygiene.v1+ncm-rust-backend-test";
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
    static WORKER_BINARY: OnceLock<PathBuf> = OnceLock::new();

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let scratch = PathBuf::from(
                std::env::var_os("TEST_TMPDIR").expect("Bazel writable test directory"),
            );
            let root = scratch.join("test-profile").join(format!(
                "ncm-rs-018-{label}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create test state root");
            Self(root)
        }

        fn state_root(&self) -> StateRoot {
            StateRoot::new(self.0.clone()).expect("valid absolute state root")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn worker_binary() -> PathBuf {
        WORKER_BINARY
            .get_or_init(|| {
                let path = std::env::var_os("TRACEDECAY_NCM_WORKER")
                    .map(PathBuf::from)
                    .expect("Bazel declared NCM test worker executable");
                assert!(
                    path.is_absolute(),
                    "NCM test worker executable must be absolute"
                );
                assert!(path.is_file(), "NCM test worker executable must exist");
                path
            })
            .clone()
    }

    fn surface(root: &TestRoot) -> Arc<RustNcmSurface> {
        Arc::new(
            RustNcmSurface::new(RustNcmConfig {
                worker_binary: worker_binary(),
                state_root: root.state_root(),
                worker_options: WorkerOptions {
                    test_double: true,
                    reconciliation_deadline: Duration::from_secs(3),
                    ..WorkerOptions::default()
                },
            })
            .expect("construct Rust NCM surface"),
        )
    }

    fn scope(project_id: &str) -> OwnedExactScope {
        OwnedExactScope::new(
            "profile-rust-backend",
            project_id,
            "repository-rust-backend",
            "worktree-rust-backend",
            "refs/heads/feat/ncm-biomem-rust-v1",
            "session-rust-backend",
            RESOLVED_SCOPE_DIGEST,
        )
        .expect("valid scope")
    }

    fn limits() -> ProviderLimits {
        ProviderLimits {
            request_bytes: 256 * 1024,
            response_bytes: 1024 * 1024,
            observation_batch_items: 16,
            recall_candidates: 16,
            concurrent_operations: 1,
            operation_millis: 30_000,
            snapshot_bytes: 256 * 1024 * 1024,
            inspection_items: 1_000,
        }
    }

    fn all_capabilities() -> Vec<OwnedVersionedId> {
        [
            "provider.health.v1",
            "observation.accept.v1",
            "recall.query.v1",
            "feedback.record.v1",
            "maintenance.run.v1",
            "inspection.read.v1",
            "correction.apply.v1",
            "deletion.by_source.v1",
            "snapshot.export.v1",
            "snapshot.restore.v1",
            "recall.temporal.v1",
            "replay.apply.v1",
            "memory.advisory_common.v1",
        ]
        .into_iter()
        .map(|value| OwnedVersionedId::new(value).expect("known capability"))
        .collect()
    }

    fn handshake(
        adapter: &NcmProviderAdapter,
        exact_scope: &OwnedExactScope,
    ) -> tracedecay_memory_provider_api::HandshakeResponse {
        adapter.handshake(
            &HandshakeRequest::new(HandshakeRequestParts {
                provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
                registration_revision: 1,
                exact_scope: exact_scope.clone(),
                request_id: format!("handshake-{}", NEXT_ROOT.fetch_add(1, Ordering::Relaxed)),
                required_capabilities: all_capabilities(),
                host_limits: limits(),
                control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
                challenge_nonce: [7; 32],
            })
            .expect("valid handshake request"),
        )
    }

    #[test]
    fn production_declaration_starts_no_child_and_refuses_test_double_identity() {
        let root = TestRoot::new("lazy-production-identity");
        let owner = Arc::new(
            RustNcmWorkerOwner::new(RustNcmConfig {
                worker_binary: worker_binary(),
                state_root: root.state_root(),
                worker_options: WorkerOptions {
                    test_double: true,
                    ..WorkerOptions::default()
                },
            })
            .unwrap(),
        );
        let surface = Arc::new(RustNcmSurface::from_production_worker(Arc::clone(&owner)).unwrap());
        assert!(owner.worker_pid().is_none());
        assert!(surface.provider_instance_id().unwrap().is_none());
        let declared = surface.descriptor();
        assert!(
            declared
                .state_schema_version
                .starts_with("ncm-biomem-rs.v2+")
        );
        assert_eq!(declared.state_generation, 0);
        assert_eq!(
            surface.prove_provider_instance(
                std::time::Instant::now() + Duration::from_secs(5),
                Arc::new(|| true),
            ),
            Err(TerminalCode::Cancelled)
        );
        assert_eq!(
            surface.prove_provider_instance(std::time::Instant::now(), Arc::new(|| false),),
            Err(TerminalCode::DeadlineExceeded)
        );
        assert!(owner.worker_pid().is_none());
        assert_eq!(
            surface.prove_provider_instance(
                std::time::Instant::now() + Duration::from_secs(5),
                Arc::new(|| false),
            ),
            Err(TerminalCode::StateIncompatible)
        );
        assert_eq!(surface.descriptor(), declared);
        assert!(surface.provider_instance_id().unwrap().is_none());
        let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
        for _ in 0..2 {
            let reply = handshake(&adapter, &scope("lazy-production-identity"));
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::StateIncompatible
            );
            assert_eq!(surface.descriptor(), declared);
            assert!(surface.provider_instance_id().unwrap().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
    fn lazy_production_declaration_is_proved_by_real_worker_handshake() {
        let root = TestRoot::new("lazy-production-real-model");
        let installed = PathBuf::from(std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT").unwrap());
        assert!(installed.is_absolute());
        std::os::unix::fs::symlink(installed.join("models"), root.0.join("models")).unwrap();
        let owner = Arc::new(
            RustNcmWorkerOwner::new(RustNcmConfig {
                worker_binary: worker_binary(),
                state_root: root.state_root(),
                worker_options: WorkerOptions::default(),
            })
            .unwrap(),
        );
        let surface = Arc::new(RustNcmSurface::from_production_worker(Arc::clone(&owner)).unwrap());
        let declared = surface.descriptor();
        assert!(owner.worker_pid().is_none());
        assert!(surface.provider_instance_id().unwrap().is_none());
        let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
        let proved = surface
            .prove_provider_instance(
                std::time::Instant::now() + Duration::from_secs(5),
                Arc::new(|| false),
            )
            .unwrap();
        let proved_instance = proved.expect("real worker proves pinned V2 identity");
        assert_eq!(surface.descriptor(), declared);
        assert!(
            surface.provider_instance_id().unwrap().is_none(),
            "global proof must not install session identity"
        );
        let ready = handshake(&adapter, &scope("lazy-production-real-model"));
        assert_eq!(ready.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(surface.descriptor(), declared);
        assert!(surface.provider_instance_id().unwrap().is_some());
        assert_eq!(
            ready.provider_instance_id.as_deref(),
            Some(proved_instance.as_str()),
            "the real worker handshake must preserve the proved production identity"
        );
        assert!(ready.ready_receipt_sha256.is_some());
    }

    #[test]
    fn missing_worker_retains_real_adapter_and_reports_unavailable_handshake() {
        let root = TestRoot::new("missing-worker-observer");
        let surface = RustNcmSurface::new(RustNcmConfig {
            worker_binary: root.0.join("absent-ncm-worker"),
            state_root: root.state_root(),
            worker_options: WorkerOptions::default(),
        })
        .expect("missing executable retains lazy real surface");
        assert!(surface.provider_instance_id().unwrap().is_none());
        let provider = NcmProviderAdapter::new(Arc::new(surface)).expect("real adapter");
        let response = handshake(&provider, &scope("missing-worker-observer"));
        assert_eq!(
            response.terminal.terminal_code(),
            TerminalCode::ProviderUnavailable
        );
        assert_eq!(
            response.terminal.diagnostic_id(),
            Some("ncm.rust.worker_unavailable")
        );
        assert!(response.provider_instance_id.is_none());
        assert!(response.ready_receipt_sha256.is_none());
    }

    fn operation_contract(operation: ProviderOperation) -> &'static str {
        match operation {
            ProviderOperation::Handshake => "tracedecay.memory.provider.handshake.v1",
            ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
            ProviderOperation::Observe => "tracedecay.memory.provider.observation.v1",
            ProviderOperation::Recall => "tracedecay.memory.provider.recall.v1",
            ProviderOperation::Feedback => "tracedecay.memory.provider.feedback.v1",
            ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
            ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
            ProviderOperation::Correction => "tracedecay.memory.provider.correction.v1",
            ProviderOperation::DeleteBySource => "tracedecay.memory.provider.deletion-by-source.v1",
            ProviderOperation::SnapshotExport => "tracedecay.memory.provider.snapshot-export.v1",
            ProviderOperation::SnapshotRestore => "tracedecay.memory.provider.snapshot-restore.v1",
            ProviderOperation::Replay => "tracedecay.memory.provider.replay.v1",
        }
    }

    fn payload(operation: ProviderOperation, value: Value) -> CanonicalPayload {
        let bytes = serde_json::to_vec(&value).expect("serialize test payload");
        CanonicalPayload::new(
            OwnedVersionedId::new(operation_contract(operation)).expect("payload contract"),
            bytes.clone(),
            hex_sha256(&bytes),
        )
        .expect("canonical payload")
    }

    fn call(
        operation: ProviderOperation,
        exact_scope: &OwnedExactScope,
        ready_receipt: &str,
        generation: u64,
        idempotency_key: Option<&str>,
        value: Value,
        remaining_millis: u64,
    ) -> ProviderCall {
        let call = ProviderCall::new(ProviderCallParts {
            operation,
            provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).expect("NCM provider id"),
            registration_revision: 1,
            ready_receipt_sha256: ready_receipt.to_owned(),
            exact_scope: exact_scope.clone(),
            request_id: format!("request-{}", NEXT_ROOT.fetch_add(1, Ordering::Relaxed)),
            operation_id: format!(
                "operation-{}-{}",
                operation.as_wire(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ),
            expected_state_generation: generation,
            idempotency_key: idempotency_key.map(str::to_owned),
            control: OperationControl::new(i64::MAX, remaining_millis, CancellationToken::new()),
            payload: payload(operation, value),
            required_capabilities: vec![
                OwnedVersionedId::new(operation.capability_id()).expect("operation capability"),
            ],
            extensions: Vec::new(),
        })
        .expect("valid provider call");
        if operation == ProviderOperation::Observe {
            admit_observation(call)
        } else {
            call
        }
    }

    fn admit_observation(call: ProviderCall) -> ProviderCall {
        let extensions_digest =
            observation_extensions_digest(&call.extensions).expect("empty extension digest");
        let receipt = PayloadSanitizationReceipt::new(
            PayloadSanitizationReceiptParts::accepted_unmodified_with_extensions(
                TEST_SANITIZER_REVISION,
                call.payload.sha256.clone(),
                extensions_digest,
            ),
        )
        .expect("sanitization receipt");
        call.with_sanitization(receipt)
    }

    fn observe_value(source: &str, key: &str, value: &str) -> Value {
        json!({
            "observation_kind": "tool.execution_settled.v1",
            "payload_contract": "tracedecay.memory.observation.tool-execution.v1",
            "canonical_payload": {
                "forget_source_key": source,
                "command": key,
                "outcome_summary": value
            }
        })
    }

    fn ready_parts(response: &tracedecay_memory_provider_api::HandshakeResponse) -> (String, u64) {
        assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
        let receipt = response
            .ready_receipt_sha256
            .clone()
            .expect("ready receipt");
        let generation = response
            .descriptor
            .as_ref()
            .expect("ready descriptor")
            .state_generation;
        (receipt, generation)
    }

    fn invoke_after_handshake(
        adapter: &NcmProviderAdapter,
        exact_scope: &OwnedExactScope,
        operation: ProviderOperation,
        idempotency_key: Option<&str>,
        value: Value,
    ) -> ProviderReply {
        let ready = handshake(adapter, exact_scope);
        let (receipt, generation) = ready_parts(&ready);
        adapter.invoke(&call(
            operation,
            exact_scope,
            &receipt,
            generation,
            idempotency_key,
            value,
            10_000,
        ))
    }

    fn response_json(reply: &ProviderReply) -> Value {
        serde_json::from_slice(
            &reply
                .payload
                .as_ref()
                .expect("successful response payload")
                .bytes,
        )
        .expect("response JSON")
    }

    fn find_string(value: &Value, field: &str, expected: &str) -> bool {
        match value {
            Value::Object(object) => {
                object.get(field).and_then(Value::as_str) == Some(expected)
                    || object
                        .values()
                        .any(|child| find_string(child, field, expected))
            }
            Value::Array(items) => items
                .iter()
                .any(|child| find_string(child, field, expected)),
            _ => false,
        }
    }

    fn find_u64(value: &Value, field: &str) -> Option<u64> {
        match value {
            Value::Object(object) => object
                .get(field)
                .and_then(Value::as_u64)
                .or_else(|| object.values().find_map(|child| find_u64(child, field))),
            Value::Array(items) => items.iter().find_map(|child| find_u64(child, field)),
            _ => None,
        }
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(bytes);
        let mut output = String::with_capacity(64);
        for byte in digest {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn canonical_ready(
        adapter: &NcmProviderAdapter,
        exact_scope: &OwnedExactScope,
    ) -> (String, u64) {
        let mut response = handshake(adapter, exact_scope);
        if response.terminal.terminal_code() == TerminalCode::StaleIdentity {
            response = handshake(adapter, exact_scope);
        }
        ready_parts(&response)
    }

    fn canonical_observation(exact_scope: &OwnedExactScope, number: u64, text: &str) -> Value {
        let source_session = "canonical-ncm-source-session";
        let observation_id = format!("canonical-ncm-observation-{number}");
        let mut canonical = json!({"version": 1, "provider": "codex", "native_record_kind": "session_message",
            "stable_record_id": format!("canonical-ncm-record-{number}"),
            "relations": {"session_id": source_session, "project_id": exact_scope.project_id},
            "facts": [{"kind": "message", "role": "assistant", "content": text}]});
        canonical.sort_all_objects();
        let original_digest = hex_sha256(&serde_json::to_vec(&canonical).unwrap());
        let original = json!({
            "source": {"canonical_provider_id": "codex", "canonical_session_id": source_session,
                "source_key": exact_scope.session_forget_source_key(source_session),
                "stable_record_id": format!("canonical-ncm-record-{number}"), "observation_id": observation_id,
                "source_revision": "cache_policy_r2", "content_sha256": original_digest},
            "origin_scope": {"state": "recorded", "authority_ref": "host.observation.receipt.v1",
                "exact_scope_identity": {
                    "profile_id": exact_scope.profile_id, "project_id": exact_scope.project_id,
                    "repository_identity": exact_scope.repository_identity, "worktree_identity": exact_scope.worktree_identity,
                    "branch_identity": exact_scope.branch_identity, "agent_session_id": exact_scope.agent_session_id,
                    "resolved_scope_digest": exact_scope.resolved_scope_digest}},
            "source_sequence": number, "occurred_at": "2025-01-02T12:00:00.123456789Z",
            "ingested_at": "2025-01-03T12:00:00Z", "validity": {
                "valid_from": "2025-01-02T12:00:00.123456789Z", "valid_until": null,
                "superseded_at": null, "superseded_by": null, "revoked_at": null}
        });
        json!({"observation_kind": "session.message_committed.v1",
            "payload_contract": "tracedecay.memory.observation.session-message.v1",
            "source_identity": {"original_source": original},
            "canonical_payload": canonical})
    }

    fn current_observation(
        exact: &OwnedExactScope,
        session: &str,
        number: u64,
        text: &str,
    ) -> Value {
        let stable = format!("current-message-{number}");
        let observation_id = format!(
            "sha256:{}",
            hex_sha256(
                &serde_json::to_vec(&json!([exact.project_id, "codex", session, stable])).unwrap()
            )
        );
        json!({
            "observation_kind": "session.message_committed.v1",
            "payload_contract": "tracedecay.memory.observation.session-message.v1",
            "source_identity": {"canonical_observation_id": observation_id},
            "canonical_payload": {
                "version": 1,
                "provider": "codex",
                "native_record_kind": "message",
                "stable_record_id": stable,
                "relations": {"session_id": session, "project_id": exact.project_id},
                "facts": [{"kind": "message", "role": "assistant", "content": text}]
            }
        })
    }

    fn exact_scope_value(exact: &OwnedExactScope) -> Value {
        json!({
            "profile_id": exact.profile_id,
            "project_id": exact.project_id,
            "repository_identity": exact.repository_identity,
            "worktree_identity": exact.worktree_identity,
            "branch_identity": exact.branch_identity,
            "agent_session_id": exact.agent_session_id,
            "resolved_scope_digest": exact.resolved_scope_digest
        })
    }

    fn canonical_recall_call(
        adapter: &NcmProviderAdapter,
        exact_scope: &OwnedExactScope,
        query: &str,
        temporal: tracedecay_memory_provider_registry::recall_admission::AdmittedTemporalQuery,
        request_identity: &str,
    ) -> ProviderCall {
        use tracedecay_memory_provider_registry::recall_admission::{
            RecallBudgetsV1, RecallRequestParts, build_recall_request_payload,
        };
        let (receipt, generation) = canonical_ready(adapter, exact_scope);
        let request_id = request_identity.to_owned();
        let payload = build_recall_request_payload(&RecallRequestParts {
            provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: receipt.clone(),
            exact_scope: exact_scope.clone(),
            request_id: request_id.clone(),
            objective: "Retrieve source-grounded cache policy".to_owned(),
            query: query.to_owned(),
            temporal,
            budgets: RecallBudgetsV1 {
                maximum_candidates: 4,
                maximum_candidate_content_bytes: 8192,
                maximum_total_content_bytes: 32768,
                maximum_source_refs_per_candidate: 4,
                maximum_trace_refs_per_candidate: 4,
                maximum_warnings: 4,
                maximum_extensions_per_candidate: 4,
            },
            policy_revision: 1,
            deadline_utc_micros: i64::MAX,
            remaining_millis: 10_000,
        })
        .unwrap();
        ProviderCall::new(ProviderCallParts {
            operation: ProviderOperation::Recall,
            provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).unwrap(),
            registration_revision: 1,
            ready_receipt_sha256: receipt,
            exact_scope: exact_scope.clone(),
            request_id,
            operation_id: format!("canonical-op-{}", NEXT_ROOT.fetch_add(1, Ordering::Relaxed)),
            expected_state_generation: generation,
            idempotency_key: None,
            control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
            payload,
            required_capabilities: vec![OwnedVersionedId::new("recall.query.v1").unwrap()],
            extensions: Vec::new(),
        })
        .unwrap()
    }

    fn exercise_canonical_recall(options: WorkerOptions) {
        use tracedecay_memory_provider_registry::recall_admission::{
            AdmittedTemporalQuery, RecallScopeBindingsV1, ScopeBinding, admit_recall_reply,
            decode_recall_outcome,
        };
        let root = TestRoot::new("canonical-recall");
        #[cfg(unix)]
        if !options.test_double {
            let installed = PathBuf::from(
                std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT")
                    .expect("installed pinned model fixture"),
            );
            assert!(installed.is_absolute());
            std::os::unix::fs::symlink(installed.join("models"), root.0.join("models"))
                .expect("share immutable models only");
        }
        let exact_scope = scope("canonical-source-provenance");
        let text = "The build cache key includes the compiler version, target triple, and dependency lockfile digest.";
        let mut expected = Vec::new();
        let mut stable_before = Vec::new();
        let mut ordering_before = Vec::new();
        for restarted in [false, true] {
            let surface = Arc::new(
                RustNcmSurface::new(RustNcmConfig {
                    worker_binary: worker_binary(),
                    state_root: root.state_root(),
                    worker_options: options.clone(),
                })
                .unwrap(),
            );
            let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
            if !restarted {
                for number in 1..=3 {
                    let value = canonical_observation(&exact_scope, number, text);
                    expected.push(value["source_identity"]["original_source"].clone());
                    let (receipt, generation) = canonical_ready(&adapter, &exact_scope);
                    let observed = adapter.invoke(&call(
                        ProviderOperation::Observe,
                        &exact_scope,
                        &receipt,
                        generation,
                        Some(&format!("canonical-observe-{number}")),
                        value,
                        10_000,
                    ));
                    assert_eq!(
                        observed.terminal.terminal_code(),
                        TerminalCode::Success,
                        "{observed:?}"
                    );
                }
            }
            let temporal = AdmittedTemporalQuery::current("2025-02-01T00:00:00Z").unwrap();
            let recall = canonical_recall_call(
                &adapter,
                &exact_scope,
                text,
                temporal.clone(),
                "canonical-current-recall-across-restart",
            );
            let original_request_bytes = recall.payload.bytes.clone();
            let reply = adapter.invoke(&recall);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            assert_eq!(
                recall.payload.bytes, original_request_bytes,
                "canonical builder bytes must remain unchanged"
            );
            let outcome = decode_recall_outcome(reply.payload.as_ref().unwrap()).unwrap();
            assert!(
                !outcome.candidates.is_empty(),
                "real NCM support must be nonempty"
            );
            let admitted = admit_recall_reply(
                &recall,
                &temporal,
                4,
                &RecallScopeBindingsV1::new([ScopeBinding::ExactCodingScope]),
                &reply,
            )
            .unwrap();
            assert_eq!(
                admitted.report.admitted_count,
                outcome.candidates.len(),
                "{:?}",
                admitted.report
            );
            assert!(admitted.report.denied.is_empty());
            for pair in outcome.candidates.windows(2) {
                let score = |index: usize| {
                    pair[index].native_score["raw_value"]
                        .as_str()
                        .unwrap()
                        .parse::<f64>()
                        .unwrap()
                };
                assert!(
                    score(0) > score(1)
                        || (score(0) == score(1) && pair[0].candidate_id < pair[1].candidate_id)
                );
            }
            for candidate in &outcome.candidates {
                assert_eq!(
                    candidate.content.as_deref(),
                    Some(format!("assistant: {text}").as_str())
                );
                assert!(expected.contains(&candidate.provenance["original_sources"][0]));
                assert_eq!(
                    candidate.validity.source_revision.as_deref(),
                    Some("cache_policy_r2")
                );
                assert_eq!(
                    candidate.validity.valid_from.as_deref(),
                    Some("2025-01-02T12:00:00.123456789Z")
                );
            }
            let stable = outcome
                .candidates
                .iter()
                .map(|candidate| candidate.stable_memory_ref.clone())
                .collect::<Vec<_>>();
            let ordering = outcome
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.candidate_id.clone(),
                        candidate.native_score.clone(),
                    )
                })
                .collect::<Vec<_>>();
            if restarted {
                assert_eq!(stable, stable_before);
                assert_eq!(ordering, ordering_before);
            } else {
                stable_before = stable;
                ordering_before = ordering;
            }

            let before = AdmittedTemporalQuery::as_of(
                "2025-02-01T00:00:00Z",
                "2025-01-02T12:00:00.123456788Z",
            )
            .unwrap();
            let recall = canonical_recall_call(
                &adapter,
                &exact_scope,
                text,
                before.clone(),
                "canonical-before-recall-across-restart",
            );
            let reply = adapter.invoke(&recall);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::SuccessZeroResults,
                "{reply:?}"
            );
            let zero = admit_recall_reply(
                &recall,
                &before,
                4,
                &RecallScopeBindingsV1::new([ScopeBinding::ExactCodingScope]),
                &reply,
            )
            .unwrap();
            assert_eq!(zero.report.admitted_count, 0);
            drop(adapter);
            drop(surface);
        }
    }

    #[test]
    fn canonical_recall_hash_fixture_preserves_source_across_restart() {
        exercise_canonical_recall(WorkerOptions {
            test_double: true,
            ..WorkerOptions::default()
        });
    }

    fn canonical_lifecycle_call(
        adapter: &NcmProviderAdapter,
        exact_scope: &OwnedExactScope,
        operation: ProviderOperation,
        key: Option<&str>,
        mut value: Value,
    ) -> ProviderCall {
        let (receipt, generation) = canonical_ready(adapter, exact_scope);
        let mut request = call(
            operation,
            exact_scope,
            &receipt,
            generation,
            key,
            value.clone(),
            10_000,
        );
        let scope = exact_scope_value(exact_scope);
        value["common_request"] = json!({"provider_id":"ncm", "registration_revision":1, "ready_receipt_digest":receipt,
            "exact_scope_identity":scope,"operation_id":request.operation_id,"idempotency_key":key,"expected_state_generation":generation,
            "request_identity":request.request_id,"policy_revision":1,"deadline":{"deadline_utc_micros":i64::MAX,"remaining_millis":10_000},"cancellation":"live","extensions":[]});
        if operation == ProviderOperation::Replay {
            value["expected_state_generation"] = json!(generation);
        }
        request.payload = payload(operation, value);
        request
    }

    struct FixtureHistoryAuthority(Vec<GrantedHistorySource>);

    impl AdvisoryAdmissionAuthority for FixtureHistoryAuthority {
        fn admit(
            &self,
            request: &ProviderCall,
        ) -> Result<CurrentAdvisoryAdmission, AdvisoryAdmissionError> {
            CurrentAdvisoryAdmission::new(
                request,
                if request.operation == ProviderOperation::Replay {
                    self.0.clone()
                } else {
                    Vec::new()
                },
                None,
            )
        }
    }

    #[test]
    fn checkout_original_history_replay_keeps_granted_origin_and_public_receipt_after_restart() {
        use tracedecay_memory_provider_api::contract::SourceDisposition;
        use tracedecay_memory_provider_api::{
            CurrentSourceDisposition, OriginScopeEvidence, OriginalSourceIdentity,
            RecordedValidity, SourceAttribution,
        };
        let root = TestRoot::new("checkout-granted-replay");
        let origin = scope("checkout-granted-replay");
        let mut destination = origin.clone();
        destination.agent_session_id = "new-replay-caller".to_owned();
        destination.resolved_scope_digest = format!("sha256:{}", "33".repeat(32));
        let mut observation = canonical_observation(
            &origin,
            1,
            "The original history retains compiler identity.",
        );
        observation["source_sequence"] = json!(1);
        observation["idempotency_key"] = json!("granted-original-delivery");
        let original = observation["source_identity"]["original_source"].clone();
        let source = &original["source"];
        let instant = |value: &str| {
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap()
        };
        let granted = GrantedHistorySource {
            attribution: SourceAttribution {
                source: OriginalSourceIdentity {
                    canonical_provider_id: OwnedProviderId::new("codex").unwrap(),
                    canonical_session_id: source["canonical_session_id"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    source_key: source["source_key"].as_str().unwrap().to_owned(),
                    stable_record_id: Some(source["stable_record_id"].as_str().unwrap().to_owned()),
                    observation_id: source["observation_id"].as_str().unwrap().to_owned(),
                    source_revision: Some(source["source_revision"].as_str().unwrap().to_owned()),
                    content_sha256: source["content_sha256"].as_str().unwrap().to_owned(),
                },
                origin_scope: OriginScopeEvidence::Recorded {
                    scope: origin.clone(),
                    authority_ref: "host.observation.receipt.v1".to_owned(),
                },
                source_sequence: 1,
                occurred_at_utc_nanos: Some(instant("2025-01-02T12:00:00.123456789Z")),
                ingested_at_utc_nanos: instant("2025-01-03T12:00:00Z"),
                validity: RecordedValidity {
                    valid_from_utc_nanos: Some(instant("2025-01-02T12:00:00.123456789Z")),
                    ..RecordedValidity::default()
                },
            },
            current_disposition: CurrentSourceDisposition {
                state: SourceDisposition::Available,
                authority_ref: "host.current-source.v1".to_owned(),
                authority_revision: Some(1),
                checked_at_utc_nanos: instant("2025-02-01T00:00:00Z"),
            },
        };
        let disposition = json!({"state":"available","authority_ref":"host.current-source.v1","authority_revision":1,"checked_at":"2025-02-01T00:00:00Z"});
        let body = json!({"observation_batch_refs":["history.receipt.1"],
            "first_source_sequence":1,"last_source_sequence":1,"expected_state_generation":0,"expected_previous_acknowledged_sequence":0,
            "history_grant":{"authorization_ref":"host.history.checked.v1","policy_revision":1,
                "destination_scope":exact_scope_value(&destination),"relation":"same_checkout",
                "sources":[{"attribution":original,"current_disposition":disposition}],
                "disposition_checkpoint":{"exact_scope":exact_scope_value(&destination),"authority_ref":"host.current-source.v1","authority_revision":1,"checked_at":"2025-02-01T00:00:00Z"}},
            "resolved_observations":[{"receipt_ref":"history.receipt.1","observation":observation}]});
        let mut original_receipt = None;
        let mut original_operation = None;
        for restarted in [false, true] {
            let adapter = NcmProviderAdapter::new(surface(&root))
                .unwrap()
                .with_namespace_binding(NcmNamespaceBinding::CheckoutObservationsV1)
                .with_admission_authority(Arc::new(FixtureHistoryAuthority(vec![granted.clone()])));
            let request = canonical_lifecycle_call(
                &adapter,
                &destination,
                ProviderOperation::Replay,
                Some("granted-original-page"),
                body.clone(),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            let effect = reply.terminal.committed_effect();
            if restarted {
                assert_eq!(effect.state(), CommittedEffectState::Duplicate, "{reply:?}");
                assert_eq!(
                    effect.provider_receipt_sha256(),
                    original_receipt.as_deref()
                );
                assert_eq!(
                    effect.duplicate_of_operation_id(),
                    original_operation.as_deref()
                );
            } else {
                assert_eq!(effect.state(), CommittedEffectState::Committed, "{reply:?}");
                assert_eq!(response_json(&reply)["applied_observations"], 1);
                original_receipt = effect.provider_receipt_sha256().map(str::to_owned);
                original_operation = Some(request.operation_id.clone());
            }
            assert!(response_json(&reply).get("page_delivery_capsule").is_none());
            let inspected = adapter.invoke(&canonical_lifecycle_call(&adapter, &destination, ProviderOperation::Inspection, None,
                json!({"view":"delivery_receipt","selector":{"idempotency_key":"granted-original-page"},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null})));
            assert_eq!(
                inspected.terminal.terminal_code(),
                TerminalCode::Success,
                "{inspected:?}"
            );
            assert_eq!(
                response_json(&inspected)["items"][0]["provider_receipt_digest"],
                json!(original_receipt)
            );
            assert_eq!(
                response_json(&inspected)["items"][0]["operation_id"],
                json!(original_operation)
            );
            let native = invoke_after_handshake(
                &adapter,
                &destination,
                ProviderOperation::Inspection,
                None,
                json!({}),
            );
            assert_eq!(response_json(&native)["records"], 1);
        }
    }

    #[test]
    fn current_memory_survives_new_session_and_restart_without_redelivery_or_history_grants() {
        use tracedecay_memory_provider_registry::recall_admission::{
            AdmittedTemporalQuery, RecallScopeBindingsV1, ScopeBinding, UnknownValidityPolicy,
            admit_recall_reply, decode_recall_outcome,
        };

        let root = TestRoot::new("canonical-replay-unavailable");
        let exact = scope("canonical-replay-unavailable");
        let text = "The cache reuses the compiler result.";
        let observation = current_observation(&exact, "current-replay-session", 1, text);
        let source_ref = format!(
            "record:{}",
            observation["source_identity"]["canonical_observation_id"]
                .as_str()
                .unwrap()
        );
        let mut stable: Option<String> = None;
        let mut durable_state: Option<Value> = None;
        let mut health_identity: Option<String> = None;
        let mut recalled_source: Option<Value> = None;
        for restarted in [false, true] {
            let worker = surface(&root);
            let adapter = NcmProviderAdapter::new(worker.clone())
                .unwrap()
                .with_namespace_binding(NcmNamespaceBinding::CheckoutObservationsV1);
            if !restarted {
                let (ready, generation) = canonical_ready(&adapter, &exact);
                let observed = adapter.invoke(&call(
                    ProviderOperation::Observe,
                    &exact,
                    &ready,
                    generation,
                    Some("current-replay-source"),
                    observation.clone(),
                    10_000,
                ));
                assert_eq!(
                    observed.terminal.terminal_code(),
                    TerminalCode::Success,
                    "{observed:?}"
                );
                assert_eq!(
                    observed.terminal.committed_effect().state(),
                    CommittedEffectState::Committed
                );
                stable = Some(
                    response_json(&observed)["stable_memory_ref"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                );
            }
            let health = adapter.invoke(&canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Health,
                None,
                json!({"requested_checks":["state","persistence","recovery"]}),
            ));
            assert_eq!(
                health.terminal.terminal_code(),
                TerminalCode::Success,
                "{health:?}"
            );
            let health_value = response_json(&health);
            let identity = health_value["state_identity_digest"]
                .as_str()
                .unwrap()
                .to_owned();
            if let Some(expected) = &health_identity {
                assert_eq!(&identity, expected);
            } else {
                health_identity = Some(identity);
            }
            let native = invoke_after_handshake(
                &adapter,
                &exact,
                ProviderOperation::Inspection,
                None,
                json!({}),
            );
            assert_eq!(
                native.terminal.terminal_code(),
                TerminalCode::Success,
                "{native:?}"
            );
            let before = response_json(&native);
            assert_eq!(before["records"], 1);
            assert!(before["quota_usage"]["event_bytes"].as_u64().unwrap() > 0);
            if let Some(expected) = &durable_state {
                for pointer in [
                    "/commit_seq",
                    "/state_digest",
                    "/records",
                    "/sources",
                    "/quota_usage/event_bytes",
                    "/quota_usage/capsule_bytes",
                    "/quota_usage/checkpoint_bytes",
                ] {
                    assert_eq!(
                        before.pointer(pointer),
                        expected.pointer(pointer),
                        "restart changed {pointer}"
                    );
                }
            } else {
                durable_state = Some(before.clone());
            }
            let generation = native.state_generation;
            assert_eq!(before["commit_seq"], generation);
            assert_eq!(before["sources"], 1);
            assert!(before["state_digest"].as_str().is_some());
            let mut replay_observation = observation.clone();
            replay_observation["idempotency_key"] = json!("canonical-replay-delivery");
            replay_observation["source_sequence"] = json!(1);
            let mut body = json!({
                "observation_batch_refs":["current.observation.receipt.1"],
                "first_source_sequence":1,"last_source_sequence":1,
                "expected_state_generation":generation,"expected_previous_acknowledged_sequence":0,
                "history_grant":null,
                "resolved_observations":[{"receipt_ref":"current.observation.receipt.1","observation":replay_observation}]
            });
            let mut first_operation: Option<String> = None;
            for attempt in 0..3 {
                if attempt == 2 {
                    body["resolved_observations"][0]["observation"]["canonical_payload"]["facts"]
                        [0]["content"] =
                        json!("Changed source content under the same delivery key.");
                }
                let request = canonical_lifecycle_call(
                    &adapter,
                    &exact,
                    ProviderOperation::Replay,
                    Some("canonical-replay-page"),
                    body.clone(),
                );
                if let Some(original) = &first_operation {
                    assert_ne!(&request.operation_id, original);
                } else {
                    first_operation = Some(request.operation_id.clone());
                }
                let reply = adapter.invoke(&request);
                assert_eq!(
                    reply.terminal.terminal_code(),
                    TerminalCode::ProviderUnavailable,
                    "{reply:?}"
                );
                assert_eq!(
                    reply.terminal.diagnostic_id(),
                    Some("ncm.current_advisory_admission_refused")
                );
                let effect = reply.terminal.committed_effect();
                assert_eq!(effect.state(), CommittedEffectState::None);
                assert_eq!(effect.state_generation_before(), Some(generation));
                assert_eq!(effect.state_generation_after(), Some(generation));
                assert!(effect.provider_receipt_sha256().is_none());
                assert!(effect.duplicate_of_operation_id().is_none());
                assert!(reply.payload.is_none());
                assert_eq!(reply.state_generation, generation);
            }
            let after = invoke_after_handshake(
                &adapter,
                &exact,
                ProviderOperation::Inspection,
                None,
                json!({}),
            );
            assert_eq!(
                after.terminal.terminal_code(),
                TerminalCode::Success,
                "{after:?}"
            );
            assert_eq!(after.state_generation, generation);
            assert_eq!(
                response_json(&after),
                before,
                "unavailable replay changed native state or journal"
            );
            let after_health = adapter.invoke(&canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Health,
                None,
                json!({"requested_checks":["state","persistence","recovery"]}),
            ));
            assert_eq!(
                after_health.terminal.terminal_code(),
                TerminalCode::Success,
                "{after_health:?}"
            );
            assert_eq!(after_health.state_generation, generation);
            assert_eq!(
                response_json(&after_health)["state_identity_digest"],
                health_value["state_identity_digest"]
            );

            let temporal = AdmittedTemporalQuery::current("2025-02-01T00:00:00Z")
                .unwrap()
                .with_unknown_validity_policy(UnknownValidityPolicy::Degrade);
            let mut recall_scope = exact.clone();
            if restarted {
                recall_scope.agent_session_id = "next-agent-session".to_owned();
                recall_scope.resolved_scope_digest = format!("sha256:{}", "ef".repeat(32));
            }
            let request = canonical_recall_call(
                &adapter,
                &recall_scope,
                text,
                temporal.clone(),
                "current-recall-after-unavailable-replay",
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Partial,
                "{reply:?}"
            );
            assert_eq!(reply.state_generation, generation);
            let outcome = decode_recall_outcome(reply.payload.as_ref().unwrap()).unwrap();
            assert_eq!(outcome.candidates.len(), 1);
            let candidate = &outcome.candidates[0];
            assert_eq!(candidate.stable_memory_ref, stable);
            assert_eq!(
                candidate.content.as_deref(),
                Some(format!("assistant: {text}").as_str())
            );
            assert_eq!(candidate.source_refs, vec![source_ref.clone()]);
            assert_eq!(candidate.provenance["original_sources"], json!([]));
            assert_eq!(
                candidate.exact_scope_identity.scope_binding,
                ScopeBinding::CheckoutObservations
            );
            assert!(candidate.exact_scope_identity.agent_session_id.is_empty());
            assert!(
                candidate
                    .exact_scope_identity
                    .resolved_scope_digest
                    .is_empty()
            );
            assert!(candidate.validity.observed_at.is_none());
            assert!(candidate.validity.source_revision.is_none());
            assert!(candidate.validity.valid_from.is_none());
            let admitted = admit_recall_reply(
                &request,
                &temporal,
                4,
                &RecallScopeBindingsV1::new([
                    ScopeBinding::ExactCodingScope,
                    ScopeBinding::CheckoutObservations,
                ]),
                &reply,
            )
            .unwrap();
            assert_eq!(admitted.report.admitted_count, 1);
            assert!(admitted.report.degraded);
            if restarted {
                let old_alias = exact.session_forget_source_key("current-replay-session");
                assert_ne!(
                    old_alias,
                    recall_scope.session_forget_source_key("current-replay-session")
                );
                let mut excluded_request = request.clone();
                let mut excluded_payload: Value =
                    serde_json::from_slice(&request.payload.bytes).unwrap();
                excluded_payload["exclusions"]["source_refs"] = json!([old_alias]);
                excluded_request.payload = payload(ProviderOperation::Recall, excluded_payload);
                let excluded = adapter.invoke(&excluded_request);
                let excluded = decode_recall_outcome(excluded.payload.as_ref().unwrap()).unwrap();
                assert!(
                    excluded.candidates.is_empty(),
                    "old delivery alias must remain an exclusion in a later session"
                );
                let exclude_temporal = temporal
                    .clone()
                    .with_unknown_validity_policy(UnknownValidityPolicy::Exclude);
                let excluded_request = canonical_recall_call(
                    &adapter,
                    &recall_scope,
                    text,
                    exclude_temporal,
                    "unknown-validity-excluded-new-session",
                );
                let excluded = adapter.invoke(&excluded_request);
                let excluded = decode_recall_outcome(excluded.payload.as_ref().unwrap()).unwrap();
                assert!(
                    excluded.candidates.is_empty(),
                    "checkout sharing must not invent occurrence validity"
                );
            }
            let current = json!({"stable_memory_ref":candidate.stable_memory_ref,
                "content":candidate.content,"content_sha256":candidate.content_sha256,
                "source_refs":candidate.source_refs,"provenance":candidate.provenance,"validity":candidate.validity});
            if let Some(expected) = &recalled_source {
                assert_eq!(&current, expected);
            } else {
                recalled_source = Some(current);
            }
            drop(adapter);
            drop(worker);
        }
    }

    #[test]
    fn canonical_trace_preserves_legacy_decimal_reference_and_unknown_attribution() {
        let root = TestRoot::new("legacy-canonical-trace");
        let exact = scope("legacy-canonical-trace");
        let text = "Stored legacy 🦀 text with \"quoted\" evidence.".repeat(30);
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker.clone()).unwrap();
        let (ready, generation) = canonical_ready(&adapter, &exact);
        let observed = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact,
            &ready,
            generation,
            Some("legacy-observe"),
            observe_value("legacy-source", "legacy key", &text),
            10_000,
        ));
        assert_eq!(
            observed.terminal.terminal_code(),
            TerminalCode::Success,
            "{observed:?}"
        );
        let reference = response_json(&observed)["record_id"]
            .as_u64()
            .unwrap()
            .to_string();
        assert_eq!(reference, "1");
        drop(adapter);
        drop(worker);
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker).unwrap();
        for maximum_bytes in [512, 65536] {
            let request = canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Inspection,
                None,
                json!({"view":"trace","selector":{"stable_memory_ref":reference},"maximum_items":1,
                    "maximum_bytes":maximum_bytes,"redaction_policy_revision":1,"cursor":null}),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            let output = response_json(&reply);
            let item = &output["items"][0];
            let content = item["content"].as_str().unwrap();
            assert!(!content.is_empty());
            assert!(text.starts_with(content));
            if maximum_bytes == 65536 {
                assert_eq!(content, text);
            }
            assert_eq!(item["stable_memory_ref"], reference);
            assert_eq!(item["content_sha256"], hex_sha256(content.as_bytes()));
            assert_eq!(item["original_source"], Value::Null);
            assert_eq!(output["coverage"], "partial");
            assert_eq!(output["next_cursor"], Value::Null);
            assert!(serde_json::to_vec(item).unwrap().len() <= maximum_bytes as usize);
            assert_eq!(reply.state_generation, request.expected_state_generation);
        }
        for malformed in ["0", "01", "+1", "1.0", " 1", "9223372036854775808"] {
            let reply = adapter.invoke(&canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Inspection,
                None,
                json!({"view":"trace","selector":{"stable_memory_ref":malformed},"maximum_items":1,
                    "maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
            ));
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::InvalidRequest,
                "{malformed}: {reply:?}"
            );
        }
        let influence = adapter.invoke(&canonical_lifecycle_call(
            &adapter, &exact, ProviderOperation::Inspection, None,
            json!({"view":"source_influence","selector":{"source_key":"legacy-source"},
                "maximum_items":1,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
        ));
        assert_eq!(influence.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(response_json(&influence)["items"], json!([]));
        assert_eq!(response_json(&influence)["coverage"], "partial");
        drop(adapter);
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker).unwrap();
        let different = scope("legacy-other-namespace");
        let other = adapter.invoke(&canonical_lifecycle_call(
            &adapter,
            &different,
            ProviderOperation::Inspection,
            None,
            json!({"view":"trace","selector":{"stable_memory_ref":reference},"maximum_items":1,
                "maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
        ));
        assert!(
            !serde_json::to_string(&response_json(&other))
                .unwrap()
                .contains("Stored legacy")
        );
    }

    #[test]
    fn canonical_feedback_retry_retains_original_public_identity_across_restart() {
        let root = TestRoot::new("canonical-feedback-retry");
        let exact = scope("canonical-feedback-retry");
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker.clone()).unwrap();
        let observation = canonical_observation(&exact, 1, "The cache retains compiler identity.");
        let (ready, generation) = canonical_ready(&adapter, &exact);
        let observed = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact,
            &ready,
            generation,
            Some("feedback-source"),
            observation.clone(),
            10_000,
        ));
        assert_eq!(
            observed.terminal.terminal_code(),
            TerminalCode::Success,
            "{observed:?}"
        );
        let source = &observation["source_identity"]["original_source"];
        let body = json!({"target": {"provider_id":"ncm","registration_revision":1,
            "original_scope":source["origin_scope"],
            "delivery_scope":source["origin_scope"]["exact_scope_identity"],"source":source["source"],
            "reference":{"kind":"stable_memory_ref","reference":response_json(&observed)["stable_memory_ref"]}},
            "signal":"helpful","weight":"1","canonical_outcome_receipt":"feedback-outcome",
            "evidence_refs":[],"occurred_at":"2025-01-03T12:00:00Z"});
        let original = canonical_lifecycle_call(
            &adapter,
            &exact,
            ProviderOperation::Feedback,
            Some("feedback-original-key"),
            body.clone(),
        );
        let committed = adapter.invoke(&original);
        assert_eq!(
            committed.terminal.committed_effect().state(),
            CommittedEffectState::Committed,
            "{committed:?}"
        );
        let receipt = committed
            .terminal
            .committed_effect()
            .provider_receipt_sha256()
            .unwrap()
            .to_owned();
        assert!(
            response_json(&committed)
                .get("feedback_delivery_capsule")
                .is_none()
        );
        drop(adapter);
        drop(worker);
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker).unwrap();
        let retry = canonical_lifecycle_call(
            &adapter,
            &exact,
            ProviderOperation::Feedback,
            Some("feedback-original-key"),
            body.clone(),
        );
        assert_ne!(retry.operation_id, original.operation_id);
        let duplicate = adapter.invoke(&retry);
        let effect = duplicate.terminal.committed_effect();
        assert_eq!(
            effect.state(),
            CommittedEffectState::Duplicate,
            "{duplicate:?}"
        );
        assert_eq!(
            effect.duplicate_of_operation_id(),
            Some(original.operation_id.as_str())
        );
        assert_eq!(
            effect.duplicate_of_idempotency_key(),
            Some("feedback-original-key")
        );
        assert_eq!(effect.provider_receipt_sha256(), Some(receipt.as_str()));
        assert_eq!(duplicate.state_generation, retry.expected_state_generation);
        let mut changed = body;
        changed["signal"] = json!("harmful");
        let changed = adapter.invoke(&canonical_lifecycle_call(
            &adapter,
            &exact,
            ProviderOperation::Feedback,
            Some("feedback-original-key"),
            changed,
        ));
        assert_eq!(
            changed.terminal.terminal_code(),
            TerminalCode::Conflict,
            "{changed:?}"
        );
    }

    #[test]
    fn canonical_original_receipt_and_trace_are_inspectable_across_restart() {
        let root = TestRoot::new("canonical-inspection");
        let exact_scope = scope("canonical-inspection");
        let text = "The cache key contains compiler version and dependency lock digest.";
        let mut original_operation = String::new();
        let mut original_receipt = String::new();
        let mut stable = String::new();
        let key = "canonical-inspection-original";
        for restart in [false, true] {
            let surface = Arc::new(
                RustNcmSurface::new(RustNcmConfig {
                    worker_binary: worker_binary(),
                    state_root: root.state_root(),
                    worker_options: WorkerOptions {
                        test_double: true,
                        ..WorkerOptions::default()
                    },
                })
                .unwrap(),
            );
            let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
            if !restart {
                let (receipt, generation) = canonical_ready(&adapter, &exact_scope);
                let request = call(
                    ProviderOperation::Observe,
                    &exact_scope,
                    &receipt,
                    generation,
                    Some(key),
                    canonical_observation(&exact_scope, 1, text),
                    10_000,
                );
                original_operation = request.operation_id.clone();
                let reply = adapter.invoke(&request);
                assert_eq!(
                    reply.terminal.terminal_code(),
                    TerminalCode::Success,
                    "{reply:?}"
                );
                original_receipt = reply
                    .terminal
                    .committed_effect()
                    .provider_receipt_sha256()
                    .unwrap()
                    .to_owned();
                stable = response_json(&reply)["stable_memory_ref"]
                    .as_str()
                    .unwrap()
                    .to_owned();
            }
            let request = canonical_lifecycle_call(
                &adapter,
                &exact_scope,
                ProviderOperation::Inspection,
                None,
                json!({"view":"delivery_receipt","selector":{"idempotency_key":key},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            assert_eq!(reply.state_generation, request.expected_state_generation);
            assert_eq!(
                response_json(&reply)["items"][0],
                json!({"operation_id":original_operation,"idempotency_key":key,"provider_receipt_digest":original_receipt,"stable_memory_ref":stable})
            );
            let request = canonical_lifecycle_call(
                &adapter,
                &exact_scope,
                ProviderOperation::Inspection,
                None,
                json!({"view":"trace","selector":{"stable_memory_ref":stable},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            let trace = &response_json(&reply)["items"][0];
            assert_eq!(trace["content"], format!("assistant: {text}"));
            assert_eq!(
                trace["content_sha256"],
                hex_sha256(format!("assistant: {text}").as_bytes())
            );
            assert_eq!(
                trace["original_source"],
                canonical_observation(&exact_scope, 1, text)["source_identity"]["original_source"]
            );
            let request = canonical_lifecycle_call(
                &adapter,
                &exact_scope,
                ProviderOperation::Inspection,
                None,
                json!({"view":"source_influence","selector":{"source_key":trace["original_source"]["source"]["source_key"]},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null}),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{reply:?}"
            );
            let influence = &response_json(&reply)["items"][0];
            let summary = influence["provider_local_effect_summary"]
                .as_str()
                .expect("source influence summary is a string");
            assert!((1..=8192).contains(&summary.len()));
            assert_eq!(
                serde_json::from_str::<Value>(summary).unwrap(),
                json!({"provider_id":"ncm","suppressed":false,"centers_updated":0})
            );
            assert_eq!(influence["active"], true);
            assert_eq!(influence["disposition"], "available");
            let (receipt, generation) = canonical_ready(&adapter, &exact_scope);
            let request = call(
                ProviderOperation::Observe,
                &exact_scope,
                &receipt,
                generation,
                Some(key),
                canonical_observation(&exact_scope, 1, text),
                10_000,
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.committed_effect().state(),
                CommittedEffectState::Duplicate,
                "{reply:?}"
            );
            assert_eq!(
                reply
                    .terminal
                    .committed_effect()
                    .duplicate_of_operation_id(),
                Some(original_operation.as_str())
            );
            assert_eq!(
                reply.terminal.committed_effect().provider_receipt_sha256(),
                Some(original_receipt.as_str())
            );
            drop(adapter);
            drop(surface);
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
    fn canonical_recall_real_model_is_admitted_without_request_rewriting() {
        exercise_canonical_recall(WorkerOptions::default());
    }

    #[test]
    fn explicit_worker_owner_lifecycle_stops_reaps_and_restarts_same_owner() {
        let root = TestRoot::new("owner-lifecycle");
        let owner = RustNcmWorkerOwner::new(RustNcmConfig {
            worker_binary: worker_binary(),
            state_root: root.state_root(),
            worker_options: WorkerOptions {
                test_double: true,
                ..WorkerOptions::default()
            },
        })
        .unwrap();
        assert_eq!(owner.worker_pid(), None);
        assert_eq!(owner.worker_incarnation(), None);
        owner
            .start(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        let first = owner.worker_pid().unwrap();
        let first_incarnation = owner.worker_incarnation().unwrap();
        assert_eq!(first_incarnation, 1);
        assert!(
            owner
                .request_stop(std::time::Instant::now() + Duration::from_secs(5))
                .unwrap()
        );
        assert_eq!(owner.worker_pid(), None);
        assert_eq!(owner.worker_incarnation(), Some(first_incarnation));
        owner
            .start(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        let second = owner.worker_pid().unwrap();
        assert_eq!(owner.worker_incarnation(), Some(first_incarnation + 1));
        assert_ne!(first, second);
        owner
            .kill(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(owner.worker_pid(), None);
        assert!(owner.start(std::time::Instant::now()).is_err());
        assert_eq!(
            owner.worker_pid(),
            None,
            "expired start must not create a child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repeated_owner_start_reuses_live_worker_readiness() {
        let root = TestRoot::new("owner-live-readiness");
        let owner = RustNcmWorkerOwner::new(RustNcmConfig {
            worker_binary: worker_binary(),
            state_root: root.state_root(),
            worker_options: WorkerOptions {
                test_double: true,
                ..WorkerOptions::default()
            },
        })
        .unwrap();
        owner
            .start(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        let pid = owner.worker_pid().unwrap();
        let incarnation = owner.worker_incarnation().unwrap();
        assert!(
            Command::new("kill")
                .args(["-STOP", &pid.to_string()])
                .status()
                .expect("suspend owned worker")
                .success()
        );
        // A live suspended child cannot answer a new wire handshake. Start
        // must use the successful proof already owned by this exact process.
        let started = owner.start(std::time::Instant::now() + Duration::from_secs(2));
        let resumed = Command::new("kill")
            .args(["-CONT", &pid.to_string()])
            .status()
            .expect("resume owned worker");
        assert!(
            started.is_ok(),
            "live worker readiness was not reused: {started:?}"
        );
        assert!(resumed.success());
        assert_eq!(owner.worker_pid(), Some(pid));
        assert_eq!(owner.worker_incarnation(), Some(incarnation));
        assert!(owner.start(std::time::Instant::now()).is_err());
        assert_eq!(owner.worker_pid(), Some(pid));
        assert_eq!(owner.worker_incarnation(), Some(incarnation));
        owner
            .kill(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owner_start_reaps_exited_worker_before_reusing_readiness() {
        let root = TestRoot::new("owner-exited-readiness");
        let owner = RustNcmWorkerOwner::new(RustNcmConfig {
            worker_binary: worker_binary(),
            state_root: root.state_root(),
            worker_options: WorkerOptions {
                test_double: true,
                ..WorkerOptions::default()
            },
        })
        .unwrap();
        owner
            .start(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
        let pid = owner.worker_pid().unwrap();
        let incarnation = owner.worker_incarnation().unwrap();
        assert!(
            Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status()
                .expect("kill owned worker")
                .success()
        );
        // Signal delivery can precede process exit. Keep asking the actual
        // owner until it observes exit and proves a replacement incarnation.
        let exit_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while owner.worker_incarnation() == Some(incarnation) {
            owner.start(exit_deadline).unwrap();
            if owner.worker_incarnation() == Some(incarnation) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        assert_eq!(owner.worker_incarnation(), Some(incarnation + 1));
        assert!(owner.worker_pid().is_some());
        owner
            .kill(std::time::Instant::now() + Duration::from_secs(5))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn internal_worker_respawn_invalidates_cached_surface_readiness() {
        let root = TestRoot::new("internal-worker-respawn-readiness");
        let surface = surface(&root);
        let adapter = NcmProviderAdapter::new(surface.clone()).expect("construct adapter");
        let exact_scope = scope("internal-worker-respawn-readiness");
        let first = handshake(&adapter, &exact_scope);
        let (receipt, generation) = ready_parts(&first);
        let first_instance = first
            .provider_instance_id
            .clone()
            .expect("initial provider instance");
        let first_pid = surface.worker_pid().expect("initial worker process");
        let first_incarnation = surface
            .worker_incarnation()
            .expect("initial worker owner incarnation");
        assert!(
            Command::new("kill")
                .args(["-9", &first_pid.to_string()])
                .status()
                .expect("kill worker process")
                .success(),
            "worker process must be killed"
        );

        let stale = adapter.invoke(&call(
            ProviderOperation::Recall,
            &exact_scope,
            &receipt,
            generation,
            None,
            json!({"query_text": "after internal restart", "top_k": 1}),
            10_000,
        ));
        assert_eq!(
            stale.terminal.terminal_code(),
            TerminalCode::StaleIdentity,
            "cached readiness must not route through a replacement worker: {stale:?}"
        );

        let replacement = handshake(&adapter, &exact_scope);
        assert_eq!(
            replacement.terminal.terminal_code(),
            TerminalCode::Success,
            "{replacement:?}"
        );
        assert_ne!(
            replacement.provider_instance_id.as_deref(),
            Some(first_instance.as_str()),
            "replacement worker must receive a fresh provider instance identity"
        );
        assert_ne!(
            surface.worker_pid(),
            Some(first_pid),
            "worker owner must have respawned a different process"
        );
        assert_eq!(
            surface.worker_incarnation(),
            Some(first_incarnation + 1),
            "worker owner incarnation must advance across an internal respawn"
        );
        assert_ne!(
            replacement.ready_receipt_sha256, first.ready_receipt_sha256,
            "readiness receipt must bind the worker owner incarnation"
        );
    }

    #[test]
    fn canonical_correction_checks_actual_revision_and_retains_cross_source_history() {
        use tracedecay_memory_provider_registry::recall_admission::{
            AdmittedTemporalQuery, decode_recall_outcome,
        };

        let root = TestRoot::new("canonical-correction-revisions");
        let exact = scope("canonical-correction-revisions");
        let old_text = "The cache uses compiler version one.";
        let new_text = "The cache uses compiler version two.";
        let transition = "2025-01-04T00:00:00Z";
        let before_transition = "2025-01-03T00:00:00Z";
        let evaluation = "2025-02-01T00:00:00Z";
        let adapter = NcmProviderAdapter::new(surface(&root))
            .unwrap()
            .with_admission_authority(Arc::new(FixtureHistoryAuthority(Vec::new())));
        let mut original = canonical_observation(&exact, 1, old_text);
        original["source_identity"]["original_source"]["source"]["source_key"] = json!("source/1");
        let observed = invoke_after_handshake(
            &adapter,
            &exact,
            ProviderOperation::Observe,
            Some("correction-revision-seed"),
            original.clone(),
        );
        assert_eq!(
            observed.terminal.terminal_code(),
            TerminalCode::Success,
            "{observed:?}"
        );
        let old_ref = response_json(&observed)["stable_memory_ref"].clone();
        let mut replacement = canonical_observation(&exact, 2, new_text);
        replacement["source_identity"]["original_source"]["source"]["source_key"] =
            json!("source/2");
        replacement["source_identity"]["original_source"]["source"]["source_revision"] =
            json!("cache_policy_r3");
        replacement["source_identity"]["original_source"]["validity"]["valid_from"] =
            json!(transition);
        let source = &original["source_identity"]["original_source"];
        let correction = json!({"target":{"provider_id":"ncm","registration_revision":1,
            "original_scope":source["origin_scope"],
            "delivery_scope":source["origin_scope"]["exact_scope_identity"],
            "source":source["source"],"reference":{"kind":"stable_memory_ref","reference":old_ref}},
            "correction_kind":"supersede","replacement":replacement,
            "expected_target_revision":"cache_policy_r2","reason":"Settled compiler correction",
            "evidence_refs":["test.compiler.revision-settled"]});
        // The replacement revision may equal a stale CAS value; only equality
        // with the actual retained target revision makes the replacement invalid.
        for expected in ["99", "cache_policy_r3"] {
            let mut stale = correction.clone();
            stale["expected_target_revision"] = json!(expected);
            let request = canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Correction,
                Some(&format!("correction-stale-{expected}")),
                stale,
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Conflict,
                "{reply:?}"
            );
            assert_eq!(
                reply.terminal.committed_effect().state(),
                CommittedEffectState::None
            );
            assert_eq!(reply.state_generation, observed.state_generation);
            assert_eq!(
                canonical_ready(&adapter, &exact).1,
                observed.state_generation
            );
        }
        let mut same_revision = correction.clone();
        same_revision["expected_target_revision"] = json!("99");
        same_revision["replacement"]["source_identity"]["original_source"]["source"]["source_revision"] =
            json!("cache_policy_r2");
        let mut wrong_target = correction.clone();
        wrong_target["target"]["source"]["source_revision"] = json!("invented-target");
        for (key, body) in [
            ("correction-same-revision", same_revision),
            ("correction-wrong-target", wrong_target),
        ] {
            let reply = adapter.invoke(&canonical_lifecycle_call(
                &adapter,
                &exact,
                ProviderOperation::Correction,
                Some(key),
                body,
            ));
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::InvalidRequest,
                "{reply:?}"
            );
            assert_eq!(
                reply.terminal.committed_effect().state(),
                CommittedEffectState::None
            );
            assert_eq!(
                canonical_ready(&adapter, &exact).1,
                observed.state_generation
            );
        }
        let corrected = adapter.invoke(&canonical_lifecycle_call(
            &adapter,
            &exact,
            ProviderOperation::Correction,
            Some("correction-source-two"),
            correction,
        ));
        assert_eq!(
            corrected.terminal.terminal_code(),
            TerminalCode::Success,
            "{corrected:?}"
        );
        assert_eq!(
            corrected.terminal.committed_effect().state(),
            CommittedEffectState::Committed
        );
        assert_eq!(corrected.state_generation, observed.state_generation + 1);
        let new_ref = response_json(&corrected)["replacement_ref"].clone();
        assert_ne!(new_ref, old_ref);
        drop(adapter);

        let adapter = NcmProviderAdapter::new(surface(&root)).unwrap();
        for (name, temporal, query, expected_source, expected_ref) in [
            (
                "current",
                AdmittedTemporalQuery::current(evaluation).unwrap(),
                new_text,
                replacement["source_identity"]["original_source"].clone(),
                new_ref.clone(),
            ),
            (
                "as-of",
                AdmittedTemporalQuery::as_of(evaluation, before_transition).unwrap(),
                old_text,
                source.clone(),
                old_ref.clone(),
            ),
            (
                "interval",
                AdmittedTemporalQuery::interval(evaluation, before_transition, transition).unwrap(),
                old_text,
                source.clone(),
                old_ref,
            ),
        ] {
            let request = canonical_recall_call(
                &adapter,
                &exact,
                query,
                temporal,
                &format!("correction-retained-{name}"),
            );
            let reply = adapter.invoke(&request);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Success,
                "{name}: {reply:?}"
            );
            assert_eq!(reply.state_generation, corrected.state_generation);
            let outcome = decode_recall_outcome(reply.payload.as_ref().unwrap()).unwrap();
            assert_eq!(outcome.candidates.len(), 1, "{name}: {outcome:?}");
            let candidate = &outcome.candidates[0];
            assert_eq!(
                candidate.stable_memory_ref.as_deref(),
                expected_ref.as_str(),
                "{name}"
            );
            assert_eq!(
                candidate.provenance["original_sources"],
                json!([expected_source]),
                "{name}"
            );
            let expected_supersession = if name == "current" {
                (None, None)
            } else {
                (Some(transition), new_ref.as_str())
            };
            assert_eq!(
                (
                    candidate.validity.superseded_at.as_deref(),
                    candidate.validity.superseded_by.as_deref(),
                ),
                expected_supersession,
                "{name}"
            );
            assert_eq!(
                candidate.content.as_deref(),
                Some(format!("assistant: {query}").as_str()),
                "{name}"
            );
        }
    }

    #[test]
    fn canonical_control_retries_keep_original_receipt_and_reject_changed_effects() {
        let root = TestRoot::new("canonical-control-retries");
        let exact = scope("canonical-control-retries");
        let surface = Arc::new(
            RustNcmSurface::new(RustNcmConfig {
                worker_binary: worker_binary(),
                state_root: root.state_root(),
                worker_options: WorkerOptions {
                    test_double: true,
                    ..WorkerOptions::default()
                },
            })
            .unwrap(),
        );
        let adapter = NcmProviderAdapter::new(surface).unwrap();
        let original = canonical_observation(&exact, 1, "The cache uses compiler version one.");
        let (ready, generation) = canonical_ready(&adapter, &exact);
        let observed = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact,
            &ready,
            generation,
            Some("retry-seed"),
            original.clone(),
            10_000,
        ));
        assert_eq!(
            observed.terminal.terminal_code(),
            TerminalCode::Success,
            "{observed:?}"
        );
        let stable = response_json(&observed)["stable_memory_ref"].clone();
        let mut replacement =
            canonical_observation(&exact, 2, "The cache uses compiler version two.");
        replacement["source_identity"]["original_source"]["source"]["source_revision"] =
            json!("cache_policy_r3");
        replacement["source_identity"]["original_source"]["validity"]["valid_from"] =
            json!("2025-01-04T00:00:00Z");
        let source = &original["source_identity"]["original_source"];
        let correction = json!({"target":{"provider_id":"ncm","registration_revision":1,"original_scope":source["origin_scope"],
            "delivery_scope":source["origin_scope"]["exact_scope_identity"],"source":source["source"],"reference":{"kind":"stable_memory_ref","reference":stable}},
            "correction_kind":"replace_content","replacement":replacement,"expected_target_revision":"cache_policy_r2","reason":"Compiler version corrected","evidence_refs":["test.compiler.version"]});
        let maintenance = json!({"task":"consolidate","maximum_items":64,"maximum_bytes":65536,"maximum_duration_millis":1000,"dry_run":false});
        let deletion = json!({"forget_source_keys":[source["source"]["source_key"]],"mode":"hard_delete","include_snapshots":true,"retention_lock_policy_revision":1,"verification_query":"cache compiler"});
        for (operation, key, body) in [
            (
                ProviderOperation::Correction,
                "retry-correction",
                correction,
            ),
            (
                ProviderOperation::Maintenance,
                "retry-maintenance",
                maintenance,
            ),
            (
                ProviderOperation::DeleteBySource,
                "retry-deletion",
                deletion,
            ),
        ] {
            let request =
                canonical_lifecycle_call(&adapter, &exact, operation, Some(key), body.clone());
            let first = adapter.invoke(&request);
            assert_eq!(
                first.terminal.terminal_code(),
                TerminalCode::Success,
                "{operation:?}: {first:?}"
            );
            if operation == ProviderOperation::Maintenance {
                assert_eq!(
                    first.terminal.committed_effect().state(),
                    CommittedEffectState::Committed
                );
                assert!(first.state_generation > request.expected_state_generation);
                assert!(response_json(&first).get("_retained_receipt").is_none());
            }
            if operation == ProviderOperation::DeleteBySource {
                let deletion = response_json(&first);
                assert_eq!(
                    deletion["postcondition"]["verification_state"],
                    "verified_absent"
                );
                assert_eq!(deletion["postcondition"]["matched_effects"], 2);
                assert_eq!(deletion["postcondition"]["removed_effects"], 2);
                assert_eq!(deletion["postcondition"]["remaining_influence_count"], 0);
                assert!(first.state_generation > request.expected_state_generation);
            }
            let receipt = first
                .terminal
                .committed_effect()
                .provider_receipt_sha256()
                .unwrap()
                .to_owned();
            let retry =
                canonical_lifecycle_call(&adapter, &exact, operation, Some(key), body.clone());
            assert_ne!(request.operation_id, retry.operation_id);
            let duplicate = adapter.invoke(&retry);
            assert_eq!(
                duplicate.terminal.terminal_code(),
                TerminalCode::Success,
                "{operation:?}: {duplicate:?}"
            );
            assert_eq!(
                duplicate.terminal.committed_effect().state(),
                CommittedEffectState::Duplicate,
                "{operation:?}: {duplicate:?}"
            );
            if operation == ProviderOperation::Maintenance {
                assert!(response_json(&duplicate).get("_retained_receipt").is_none());
            }
            assert_eq!(
                duplicate
                    .terminal
                    .committed_effect()
                    .provider_receipt_sha256(),
                Some(receipt.as_str())
            );
            assert_eq!(duplicate.state_generation, retry.expected_state_generation);
            let mut changed = body;
            match operation {
                ProviderOperation::Correction => changed["reason"] = json!("Different evidence"),
                ProviderOperation::Maintenance => changed["task"] = json!("decay"),
                _ => changed["forget_source_keys"] = json!(["different-source-key"]),
            }
            let changed = canonical_lifecycle_call(&adapter, &exact, operation, Some(key), changed);
            let rejected = adapter.invoke(&changed);
            assert_eq!(
                rejected.terminal.terminal_code(),
                TerminalCode::Conflict,
                "{operation:?}: {rejected:?}"
            );
            assert_eq!(rejected.state_generation, changed.expected_state_generation);
        }
    }

    fn exercise_shared_worker_project_surfaces(root: &TestRoot, options: WorkerOptions) {
        let owner = Arc::new(
            RustNcmWorkerOwner::new(RustNcmConfig {
                worker_binary: worker_binary(),
                state_root: root.state_root(),
                worker_options: options,
            })
            .expect("shared worker owner"),
        );
        assert!(owner.worker_pid().is_none(), "owner construction is lazy");
        let barrier = std::sync::Barrier::new(2);
        let (surface_a, surface_b) = std::thread::scope(|threads| {
            let mount = || {
                barrier.wait();
                Arc::new(
                    RustNcmSurface::from_worker(Arc::clone(&owner)).expect("project-local surface"),
                )
            };
            let a = threads.spawn(mount);
            let b = threads.spawn(mount);
            (a.join().unwrap(), b.join().unwrap())
        });
        let pid = owner.worker_pid().expect("one live worker process");
        assert_eq!(surface_a.worker_pid(), Some(pid));
        assert_eq!(surface_b.worker_pid(), Some(pid));
        let adapter_a = NcmProviderAdapter::new(surface_a.clone()).unwrap();
        let adapter_b = NcmProviderAdapter::new(surface_b.clone()).unwrap();
        let scope_a = scope("project-shared-worker-a");
        let scope_b = scope("project-shared-worker-b");
        for (id, key) in [
            ("a-first", "alpha first command"),
            ("a-second", "alpha second command"),
        ] {
            let reply = invoke_after_handshake(
                &adapter_a,
                &scope_a,
                ProviderOperation::Observe,
                Some(id),
                observe_value(id, key, "project A only"),
            );
            assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
        }

        // B's handshake must not replace A's accepted readiness or descriptor
        // generation. A and B intentionally start this pair at different generations.
        let (receipt_a, generation_a) = ready_parts(&handshake(&adapter_a, &scope_a));
        let (receipt_b, generation_b) = ready_parts(&handshake(&adapter_b, &scope_b));
        assert!(generation_a > generation_b);
        let a = adapter_a.invoke(&call(
            ProviderOperation::Observe,
            &scope_a,
            &receipt_a,
            generation_a,
            Some("a-third"),
            observe_value("a-third", "cargo test", "project A only"),
            10_000,
        ));
        assert_eq!(a.terminal.terminal_code(), TerminalCode::Success);
        let b = adapter_b.invoke(&call(
            ProviderOperation::Observe,
            &scope_b,
            &receipt_b,
            generation_b,
            Some("b-first"),
            observe_value("b-first", "cargo test", "project B only"),
            10_000,
        ));
        assert_eq!(b.terminal.terminal_code(), TerminalCode::Success);
        assert_ne!(a.state_generation, b.state_generation);

        let (receipt_b, generation_b) = ready_parts(&handshake(&adapter_b, &scope_b));
        let (receipt_a, generation_a) = ready_parts(&handshake(&adapter_a, &scope_a));
        let descriptor_before_proof = surface_a.descriptor();
        let instance_before_proof = surface_a.provider_instance_id().unwrap();
        assert_eq!(
            surface_a
                .prove_provider_instance(
                    std::time::Instant::now() + Duration::from_secs(5),
                    Arc::new(|| false),
                )
                .unwrap(),
            instance_before_proof
        );
        assert_eq!(surface_a.descriptor(), descriptor_before_proof);
        // The existing accepted session receipts below must remain usable.
        let recall_b = adapter_b.invoke(&call(
            ProviderOperation::Recall,
            &scope_b,
            &receipt_b,
            generation_b,
            None,
            json!({"query_text": "cargo test", "top_k": 5}),
            10_000,
        ));
        let recall_a = adapter_a.invoke(&call(
            ProviderOperation::Recall,
            &scope_a,
            &receipt_a,
            generation_a,
            None,
            json!({"query_text": "cargo test", "top_k": 5}),
            10_000,
        ));
        assert_eq!(recall_a.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(recall_b.terminal.terminal_code(), TerminalCode::Success);
        let recalled_a = response_json(&recall_a);
        let recalled_b = response_json(&recall_b);
        assert!(find_string(&recalled_a, "value_text", "project A only"));
        assert!(!find_string(&recalled_a, "value_text", "project B only"));
        assert!(find_string(&recalled_b, "value_text", "project B only"));
        assert!(!find_string(&recalled_b, "value_text", "project A only"));
        assert_ne!(
            handshake(&adapter_a, &scope_a).state_namespace,
            handshake(&adapter_b, &scope_b).state_namespace
        );

        drop(adapter_a);
        drop(surface_a);
        assert_eq!(
            owner.worker_pid(),
            Some(pid),
            "closing A must leave B's worker alive"
        );
        let retained = invoke_after_handshake(
            &adapter_b,
            &scope_b,
            ProviderOperation::Recall,
            None,
            json!({"query_text": "cargo test", "top_k": 5}),
        );
        assert_eq!(retained.terminal.terminal_code(), TerminalCode::Success);
        assert!(find_string(
            &response_json(&retained),
            "value_text",
            "project B only"
        ));
        assert_eq!(
            owner.worker_pid(),
            Some(pid),
            "B must not need a replacement worker"
        );
        drop(adapter_b);
        drop(surface_b);
        let witness = Arc::downgrade(&owner);
        let started = std::time::Instant::now();
        drop(owner);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "last owner uses bounded client teardown"
        );
        assert!(witness.upgrade().is_none());
    }

    #[test]
    fn shared_worker_keeps_project_readiness_generations_and_namespaces_independent() {
        let root = TestRoot::new("shared-project-surfaces");
        exercise_shared_worker_project_surfaces(
            &root,
            WorkerOptions {
                test_double: true,
                ..WorkerOptions::default()
            },
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires TRACEDECAY_NCM_WORKER and TRACEDECAY_NCM_REAL_MODEL_ROOT with pinned offline model"]
    fn real_shared_worker_keeps_project_readiness_generations_and_namespaces_independent() {
        let root = TestRoot::new("shared-project-real-model");
        let installed = PathBuf::from(
            std::env::var_os("TRACEDECAY_NCM_REAL_MODEL_ROOT")
                .expect("installed pinned model fixture"),
        );
        assert!(installed.is_absolute());
        std::os::unix::fs::symlink(installed.join("models"), root.0.join("models"))
            .expect("share immutable models only");
        exercise_shared_worker_project_surfaces(&root, WorkerOptions::default());
    }

    #[test]
    fn descriptor_and_handshake_expose_reserved_identity_and_exact_capabilities() {
        let root = TestRoot::new("handshake");
        let surface = surface(&root);
        let descriptor = surface.descriptor();
        assert_eq!(descriptor.provider_id.as_str(), NCM_PROVIDER_ID);
        assert!(
            descriptor
                .state_schema_version
                .starts_with("ncm-biomem-rs.v1+")
        );
        let capabilities = descriptor
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let expected = all_capabilities()
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(capabilities, expected);
        assert!(!capabilities.contains("replay.execute.v1"));

        let adapter = NcmProviderAdapter::new(surface).expect("construct adapter");
        let response = handshake(&adapter, &scope("project-handshake"));
        assert_eq!(response.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(
            response
                .descriptor
                .as_ref()
                .expect("descriptor")
                .provider_id
                .as_str(),
            NCM_PROVIDER_ID
        );
        assert!(response.ready_receipt_sha256.is_some());
    }

    #[test]
    fn canonical_message_embeds_content_and_deletes_by_same_source_after_restart() {
        let root = TestRoot::new("canonical-message-restart");
        let exact_scope = scope("project-canonical-message");
        let canonical_session = "host-session-canonical-message";
        let text = "Remember the violet telescope calibration procedure";
        {
            let adapter = NcmProviderAdapter::new(surface(&root)).expect("adapter");
            let observed = invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::Observe,
                Some("canonical-message"),
                json!({
                    "observation_kind": "session.message_committed.v1",
                    "payload_contract": "tracedecay.memory.observation.session-message.v1",
                    "canonical_payload": {
                        "version": 1, "provider": "claude", "native_record_kind": "message",
                        "stable_record_id": "private-canonical-message-record",
                        "relations": {"session_id": canonical_session, "project_id": exact_scope.project_id},
                        "facts": [{"kind": "message", "role": "assistant", "content": [{"type": "text", "text": text}]}]
                    }
                }),
            );
            assert_eq!(observed.terminal.terminal_code(), TerminalCode::Success);
            let recalled = invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::Recall,
                None,
                json!({"query_text": text, "top_k": 5}),
            );
            assert_eq!(recalled.terminal.terminal_code(), TerminalCode::Success);
            let recalled = response_json(&recalled);
            assert!(find_string(&recalled, "key_text", text));
            assert!(find_string(
                &recalled,
                "value_text",
                &format!("assistant: {text}")
            ));
        }
        let reopened_surface = surface(&root);
        assert_eq!(reopened_surface.descriptor().state_generation, 0);
        let adapter = NcmProviderAdapter::new(reopened_surface).expect("restarted adapter");
        // Construction preflights an empty namespace. Loading this persisted
        // namespace refreshes the new surface's generation inside the first
        // public handshake, before readiness is admitted.
        let reopened_ready = handshake(&adapter, &exact_scope);
        assert_eq!(
            reopened_ready.terminal.terminal_code(),
            TerminalCode::Success,
            "persisted namespace must be ready after at most one identity refresh"
        );
        let (receipt, generation) = ready_parts(&reopened_ready);
        assert_eq!(generation, 1);
        let recalled = adapter.invoke(&call(
            ProviderOperation::Recall,
            &exact_scope,
            &receipt,
            generation,
            None,
            json!({"query_text": text, "top_k": 5}),
            10_000,
        ));
        assert_eq!(recalled.terminal.terminal_code(), TerminalCode::Success);
        assert!(find_string(&response_json(&recalled), "key_text", text));
        let deleted = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::DeleteBySource,
            Some("canonical-message-delete"),
            json!({"forget_source_key": exact_scope.session_forget_source_key(canonical_session)}),
        );
        assert_eq!(deleted.terminal.terminal_code(), TerminalCode::Success);
        let recalled = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Recall,
            None,
            json!({"query_text": text, "top_k": 5}),
        );
        assert_eq!(
            recalled.terminal.terminal_code(),
            TerminalCode::SuccessZeroResults
        );
    }

    #[test]
    fn checkout_caller_keys_are_exact_scoped_and_retries_survive_restart() {
        let root = TestRoot::new("checkout-caller-keys");
        let first_scope = scope("checkout-caller-keys");
        let mut second_scope = first_scope.clone();
        second_scope.agent_session_id = "second-caller".to_owned();
        second_scope.resolved_scope_digest = format!("sha256:{}", "22".repeat(32));
        let first_value = current_observation(
            &first_scope,
            "canonical-first",
            1,
            "The first session stores compiler identity.",
        );
        let second_value = current_observation(
            &second_scope,
            "canonical-second",
            2,
            "The second session stores dependency identity.",
        );
        let original_operation = "shared-public-operation";
        let original_key = "shared-public-key";
        let first_receipt;
        let mut committed_receipts = Vec::new();
        {
            let adapter = NcmProviderAdapter::new(surface(&root))
                .unwrap()
                .with_namespace_binding(NcmNamespaceBinding::CheckoutObservationsV1);
            for (exact, value) in [(&first_scope, &first_value), (&second_scope, &second_value)] {
                let (ready, generation) = canonical_ready(&adapter, exact);
                let mut request = call(
                    ProviderOperation::Observe,
                    exact,
                    &ready,
                    generation,
                    Some(original_key),
                    value.clone(),
                    10_000,
                );
                request.request_id = "shared-public-request".to_owned();
                request.operation_id = original_operation.to_owned();
                let committed = adapter.invoke(&request);
                assert_eq!(
                    committed.terminal.terminal_code(),
                    TerminalCode::Success,
                    "{committed:?}"
                );
                assert_eq!(
                    committed.terminal.committed_effect().state(),
                    CommittedEffectState::Committed,
                    "{committed:?}"
                );
                assert!(committed.state_generation > generation);
                committed_receipts.push((
                    committed
                        .terminal
                        .committed_effect()
                        .provider_receipt_sha256()
                        .unwrap()
                        .to_owned(),
                    response_json(&committed)["stable_memory_ref"].clone(),
                ));
            }
            for (exact, (receipt, stable)) in [&first_scope, &second_scope]
                .into_iter()
                .zip(&committed_receipts)
            {
                let inspected = adapter.invoke(&canonical_lifecycle_call(&adapter, exact, ProviderOperation::Inspection, None,
                    json!({"view":"delivery_receipt","selector":{"idempotency_key":original_key},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null})));
                assert_eq!(
                    inspected.terminal.terminal_code(),
                    TerminalCode::Success,
                    "{inspected:?}"
                );
                assert_eq!(
                    response_json(&inspected)["items"],
                    json!([{"operation_id":original_operation,"idempotency_key":original_key,"provider_receipt_digest":receipt,"stable_memory_ref":stable}])
                );
            }
            let (ready, generation) = canonical_ready(&adapter, &first_scope);
            let retry = call(
                ProviderOperation::Observe,
                &first_scope,
                &ready,
                generation,
                Some(original_key),
                first_value.clone(),
                10_000,
            );
            let duplicate = adapter.invoke(&retry);
            assert_eq!(
                duplicate.terminal.committed_effect().state(),
                CommittedEffectState::Duplicate,
                "{duplicate:?}"
            );
            assert_eq!(duplicate.state_generation, generation);
            first_receipt = duplicate
                .terminal
                .committed_effect()
                .provider_receipt_sha256()
                .unwrap()
                .to_owned();
            assert_eq!(
                duplicate
                    .terminal
                    .committed_effect()
                    .duplicate_of_operation_id(),
                Some(original_operation)
            );
        }
        let adapter = NcmProviderAdapter::new(surface(&root))
            .unwrap()
            .with_namespace_binding(NcmNamespaceBinding::CheckoutObservationsV1);
        for (exact, (receipt, stable)) in [&first_scope, &second_scope]
            .into_iter()
            .zip(&committed_receipts)
        {
            let inspected = adapter.invoke(&canonical_lifecycle_call(&adapter, exact, ProviderOperation::Inspection, None,
                json!({"view":"delivery_receipt","selector":{"idempotency_key":original_key},"maximum_items":8,"maximum_bytes":65536,"redaction_policy_revision":1,"cursor":null})));
            assert_eq!(
                inspected.terminal.terminal_code(),
                TerminalCode::Success,
                "{inspected:?}"
            );
            assert_eq!(
                response_json(&inspected)["items"],
                json!([{"operation_id":original_operation,"idempotency_key":original_key,"provider_receipt_digest":receipt,"stable_memory_ref":stable}])
            );
        }
        let (ready, generation) = canonical_ready(&adapter, &first_scope);
        let retry = call(
            ProviderOperation::Observe,
            &first_scope,
            &ready,
            generation,
            Some(original_key),
            first_value.clone(),
            10_000,
        );
        let duplicate = adapter.invoke(&retry);
        assert_eq!(
            duplicate.terminal.committed_effect().state(),
            CommittedEffectState::Duplicate,
            "{duplicate:?}"
        );
        assert_eq!(duplicate.state_generation, generation);
        assert_eq!(
            duplicate
                .terminal
                .committed_effect()
                .provider_receipt_sha256(),
            Some(first_receipt.as_str())
        );
        assert_eq!(
            duplicate
                .terminal
                .committed_effect()
                .duplicate_of_operation_id(),
            Some(original_operation)
        );
        assert_eq!(
            duplicate
                .terminal
                .committed_effect()
                .duplicate_of_idempotency_key(),
            Some(original_key)
        );
        let mut changed = first_value;
        changed["canonical_payload"]["facts"][0]["content"] =
            json!("A changed payload cannot reuse the first caller key.");
        let (ready, generation) = canonical_ready(&adapter, &first_scope);
        let conflict = adapter.invoke(&call(
            ProviderOperation::Observe,
            &first_scope,
            &ready,
            generation,
            Some(original_key),
            changed,
            10_000,
        ));
        assert_eq!(
            conflict.terminal.terminal_code(),
            TerminalCode::Conflict,
            "{conflict:?}"
        );
        assert_eq!(conflict.state_generation, generation);
    }

    #[test]
    fn mutation_generation_requires_rehandshake_and_duplicate_replays_receipt() {
        let root = TestRoot::new("generation");
        let adapter = NcmProviderAdapter::new(surface(&root)).expect("construct adapter");
        let exact_scope = scope("project-generation");
        let initial = handshake(&adapter, &exact_scope);
        let (receipt, generation) = ready_parts(&initial);
        let observation = observe_value("source-generation", "cargo test", "all tests passed");
        let first_call = call(
            ProviderOperation::Observe,
            &exact_scope,
            &receipt,
            generation,
            Some("observe-generation"),
            observation.clone(),
            10_000,
        );
        let first = adapter.invoke(&first_call);
        assert_eq!(first.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(
            first.terminal.committed_effect().state(),
            CommittedEffectState::Committed
        );
        assert!(first.state_generation > generation);
        let first_receipt = first
            .terminal
            .committed_effect()
            .provider_receipt_sha256()
            .expect("committed receipt")
            .to_owned();

        let refused = adapter.invoke(&call(
            ProviderOperation::Recall,
            &exact_scope,
            &receipt,
            first.state_generation,
            None,
            json!({"query_text": "cargo test", "top_k": 5}),
            10_000,
        ));
        assert_eq!(
            refused.terminal.terminal_code(),
            TerminalCode::StaleIdentity
        );

        let readmitted = handshake(&adapter, &exact_scope);
        let (receipt, generation) = ready_parts(&readmitted);
        assert_eq!(generation, first.state_generation);
        let duplicate = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact_scope,
            &receipt,
            generation,
            Some("observe-generation"),
            observation,
            10_000,
        ));
        assert_eq!(duplicate.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(
            duplicate.terminal.committed_effect().state(),
            CommittedEffectState::Duplicate
        );
        assert_eq!(duplicate.state_generation, generation);
        assert_eq!(
            duplicate
                .terminal
                .committed_effect()
                .provider_receipt_sha256(),
            Some(first_receipt.as_str())
        );

        let recall = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Recall,
            None,
            json!({"query_text": "cargo test", "top_k": 5}),
        );
        assert_eq!(recall.terminal.terminal_code(), TerminalCode::Success);
        assert!(find_string(
            &response_json(&recall),
            "value_text",
            "all tests passed"
        ));
    }

    #[test]
    fn feedback_correction_maintenance_inspection_and_delete_use_durable_state() {
        let root = TestRoot::new("operations");
        let adapter = NcmProviderAdapter::new(surface(&root)).expect("construct adapter");
        let exact_scope = scope("project-operations");
        let first = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Observe,
            Some("observe-one"),
            current_observation(
                &exact_scope,
                "source-delete",
                1,
                "first command: first outcome",
            ),
        );
        let first_id = find_u64(&response_json(&first), "record_id").expect("first record id");
        let second = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Observe,
            Some("observe-two"),
            current_observation(
                &exact_scope,
                "source-keep",
                2,
                "second command: second outcome",
            ),
        );
        let second_id = find_u64(&response_json(&second), "record_id").expect("second record id");

        let feedback = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Feedback,
            Some("feedback-one"),
            json!({"record_ids": [first_id]}),
        );
        assert_eq!(feedback.terminal.terminal_code(), TerminalCode::Success);

        let correction = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Correction,
            Some("correction-one"),
            json!({
                "superseded_record_id": first_id,
                "superseding_record_id": second_id,
                "evidence_sha256": hex_sha256(b"correction evidence")
            }),
        );
        assert_eq!(correction.terminal.terminal_code(), TerminalCode::Success);

        let maintenance = adapter.invoke(&canonical_lifecycle_call(
            &adapter,
            &exact_scope,
            ProviderOperation::Maintenance,
            Some("maintenance-checkpoint"),
            json!({
                "task": "consolidate",
                "maximum_items": 64,
                "maximum_bytes": 65_536,
                "maximum_duration_millis": 1_000,
                "dry_run": false
            }),
        ));
        assert_eq!(maintenance.terminal.terminal_code(), TerminalCode::Success);

        let inspection = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Inspection,
            None,
            json!({}),
        );
        assert_eq!(inspection.terminal.terminal_code(), TerminalCode::Success);
        assert!(find_u64(&response_json(&inspection), "records").is_some());

        let deleted = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::DeleteBySource,
            Some("delete-source"),
            json!({"source_id": exact_scope.session_forget_source_key("source-delete")}),
        );
        assert_eq!(deleted.terminal.terminal_code(), TerminalCode::Success);
        let post_delete_snapshot = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::SnapshotExport,
            None,
            json!({}),
        );
        assert_eq!(
            post_delete_snapshot.terminal.terminal_code(),
            TerminalCode::Success,
            "post-delete snapshot export diagnostic: {:?}",
            post_delete_snapshot.terminal.diagnostic_id()
        );
        let recall = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Recall,
            None,
            json!({"query_text": "first command", "top_k": 5}),
        );
        if recall.terminal.terminal_code() == TerminalCode::Success {
            assert!(!find_string(
                &response_json(&recall),
                "value_text",
                "assistant: first command: first outcome"
            ));
        } else {
            assert_eq!(
                recall.terminal.terminal_code(),
                TerminalCode::SuccessZeroResults
            );
        }
    }

    #[test]
    fn canonical_portability_malformed_json_is_invalid_before_authority_admission() {
        let root = TestRoot::new("malformed-portability");
        let exact = scope("malformed-portability");
        let adapter = NcmProviderAdapter::new(surface(&root)).unwrap();
        let observed = invoke_after_handshake(
            &adapter,
            &exact,
            ProviderOperation::Observe,
            Some("malformed-portability-current-source"),
            current_observation(
                &exact,
                "malformed-portability-session",
                1,
                "Retain this current observation when malformed portability requests are denied.",
            ),
        );
        assert_eq!(observed.terminal.terminal_code(), TerminalCode::Success);
        let before = invoke_after_handshake(
            &adapter,
            &exact,
            ProviderOperation::Inspection,
            None,
            json!({}),
        );
        assert_eq!(before.terminal.terminal_code(), TerminalCode::Success);
        for operation in [
            ProviderOperation::SnapshotRestore,
            ProviderOperation::Replay,
        ] {
            for bytes in [b"{".as_slice(), b"[]".as_slice(), b"null".as_slice()] {
                let (receipt, generation) = canonical_ready(&adapter, &exact);
                let mut request = call(
                    operation,
                    &exact,
                    &receipt,
                    generation,
                    Some("malformed-portability-key"),
                    json!({}),
                    10_000,
                );
                request.payload = CanonicalPayload::new(
                    request.payload.contract_id.clone(),
                    bytes.to_vec(),
                    hex_sha256(bytes),
                )
                .unwrap();
                let denied = adapter.invoke(&request);
                assert_eq!(
                    denied.terminal.terminal_code(),
                    TerminalCode::InvalidRequest,
                    "{operation:?}: {denied:?}"
                );
                assert_eq!(
                    denied.terminal.committed_effect().state(),
                    CommittedEffectState::None
                );
                assert_eq!(denied.state_generation, before.state_generation);
                assert!(denied.payload.is_none());
            }
        }
        let after = invoke_after_handshake(
            &adapter,
            &exact,
            ProviderOperation::Inspection,
            None,
            json!({}),
        );
        assert_eq!(after.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(after.state_generation, before.state_generation);
        assert_eq!(response_json(&after), response_json(&before));
    }

    #[test]
    fn snapshot_restore_without_current_authority_preserves_later_state() {
        use tracedecay_memory_provider_registry::recall_admission::{
            AdmittedTemporalQuery, UnknownValidityPolicy, decode_recall_outcome,
        };

        let root = TestRoot::new("snapshot");
        let worker = surface(&root);
        let adapter = NcmProviderAdapter::new(worker.clone()).expect("construct adapter");
        let exact_scope = scope("project-snapshot");
        let alpha_text = "alpha command: alpha outcome";
        let beta_text = "beta command: beta outcome";
        let first = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Observe,
            Some("snapshot-observe-one"),
            current_observation(&exact_scope, "snapshot-current-session", 1, alpha_text),
        );
        assert_eq!(first.terminal.terminal_code(), TerminalCode::Success);
        let alpha_ref = response_json(&first)["stable_memory_ref"].clone();
        let exported = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::SnapshotExport,
            None,
            json!({}),
        );
        assert_eq!(
            exported.terminal.terminal_code(),
            TerminalCode::Success,
            "{exported:?}"
        );
        let snapshot = response_json(&exported)["bytes"]
            .as_array()
            .expect("snapshot byte array")
            .clone();
        assert!(!snapshot.is_empty());

        let second = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Observe,
            Some("snapshot-observe-two"),
            current_observation(&exact_scope, "snapshot-current-session", 2, beta_text),
        );
        assert_eq!(second.terminal.terminal_code(), TerminalCode::Success);
        let beta_ref = response_json(&second)["stable_memory_ref"].clone();
        assert_ne!(alpha_ref, beta_ref);
        let inspection = || {
            invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::Inspection,
                None,
                json!({}),
            )
        };
        let before = inspection();
        assert_eq!(before.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(find_u64(&response_json(&before), "records"), Some(2));
        for bytes in [snapshot.clone(), snapshot] {
            let restored = invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::SnapshotRestore,
                Some("snapshot-restore"),
                json!({"snapshot": bytes}),
            );
            assert_eq!(
                restored.terminal.terminal_code(),
                TerminalCode::ProviderUnavailable,
                "{restored:?}"
            );
            assert_eq!(
                restored.terminal.diagnostic_id(),
                Some("ncm.current_advisory_admission_refused")
            );
            assert_eq!(
                restored.terminal.committed_effect().state(),
                CommittedEffectState::None
            );
            assert_eq!(restored.state_generation, second.state_generation);
            assert!(restored.payload.is_none());
        }
        let after = inspection();
        assert_eq!(after.state_generation, before.state_generation);
        assert_eq!(
            response_json(&after),
            response_json(&before),
            "refused restore must not change native state or journal counts"
        );
        drop(adapter);
        drop(worker);

        let adapter = NcmProviderAdapter::new(surface(&root)).unwrap();
        for (query, reference) in [(alpha_text, alpha_ref), (beta_text, beta_ref)] {
            let recall = canonical_recall_call(
                &adapter,
                &exact_scope,
                query,
                AdmittedTemporalQuery::current("2026-01-02T00:00:00Z")
                    .unwrap()
                    .with_unknown_validity_policy(UnknownValidityPolicy::Degrade),
                "snapshot-current-after-refusal",
            );
            let reply = adapter.invoke(&recall);
            assert_eq!(
                reply.terminal.terminal_code(),
                TerminalCode::Partial,
                "{reply:?}"
            );
            assert_eq!(reply.state_generation, second.state_generation);
            let outcome = decode_recall_outcome(reply.payload.as_ref().unwrap()).unwrap();
            let retained = outcome
                .candidates
                .iter()
                .find(|candidate| candidate.stable_memory_ref.as_deref() == reference.as_str())
                .expect("current source remains durable after refused restore");
            assert_eq!(
                retained.content.as_deref(),
                Some(format!("assistant: {query}").as_str())
            );
            assert_eq!(retained.provenance["original_sources"], json!([]));
            assert!(retained.validity.source_revision.is_none());
            assert!(retained.validity.valid_from.is_none());
        }
    }

    #[cfg(unix)]
    mod cancellation {
        use std::fs::{self, File};
        use std::io::{Cursor, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
        use std::sync::{Arc, mpsc};
        use std::thread;
        use std::time::{Duration, Instant};

        use serde_json::json;
        use tracedecay_memory_ncm_runtime::embedding::doubles::HashEncoder;
        use tracedecay_memory_ncm_runtime::engine::NcmEngine;
        use tracedecay_memory_ncm_runtime::wire;
        use tracedecay_memory_ncm_runtime::worker::{ServeOptions, serve_with_options};
        use tracedecay_memory_provider_api::contract::{CommittedEffectState, TerminalCode};
        use tracedecay_memory_provider_api::{
            CancellationToken, HandshakeRequest, HandshakeRequestParts, MemoryProvider,
            OperationControl, OwnedProviderId, ProviderOperation,
        };
        use tracedecay_memory_provider_ncm::{
            NCM_PROVIDER_ID, NcmProviderAdapter, RustNcmConfig, RustNcmSurface, StateRoot,
            WorkerOptions,
        };

        use super::{
            TestRoot, all_capabilities, call, handshake, invoke_after_handshake, limits,
            observe_value, ready_parts, response_json, scope,
        };

        /// Runs the real engine and worker dispatcher in the supervised test
        /// process. Only the input boundary is held; replies use the runtime's
        /// canonical framing and the original request remains unchanged.
        #[test]
        #[ignore = "subprocess fixture for adapter cancellation tests"]
        fn worker_fixture() {
            // This is only a self-exec harness entry. Broad ignored-test runs
            // may call it without a launcher; it is never behavioral evidence.
            let Some(root) = std::env::var_os("TRACEDECAY_NCM_CANCELLATION_FIXTURE_ROOT") else {
                return;
            };
            let root = StateRoot::new(root).unwrap();
            let engine = Arc::new(NcmEngine::new(
                root.clone(),
                Arc::new(HashEncoder::new()),
                Default::default(),
            ));
            let address = fs::read_to_string(root.path().join("control-address")).unwrap();
            let mut control = TcpStream::connect(address).unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            control
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut input = std::io::stdin().lock();
            // The launcher reserves fd 3 for worker replies so libtest's own
            // progress output cannot enter the supervised protocol stream.
            let mut output = File::options().write(true).open("/dev/fd/3").unwrap();
            while let Some(request) = wire::read_request(&mut input).unwrap() {
                let marker = root.path().join("cancel-next-request");
                if marker.exists() {
                    fs::remove_file(marker).unwrap();
                    control
                        .write_all(&std::process::id().to_be_bytes())
                        .unwrap();
                    let mut release = [0];
                    control.read_exact(&mut release).unwrap();
                }
                serve_with_options(
                    Cursor::new(wire::encode_request(&request).unwrap()),
                    &mut output,
                    Arc::clone(&engine),
                    ServeOptions {
                        allow_test_delays: true,
                        encoder_ready: true,
                        allow_legacy_identity: true,
                    },
                )
                .unwrap();
            }
        }

        fn controlled_surface(root: &TestRoot) -> (Arc<RustNcmSurface>, TcpListener, TcpStream) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            fs::write(
                root.0.join("control-address"),
                listener.local_addr().unwrap().to_string(),
            )
            .unwrap();
            symlink(std::env::current_exe().unwrap(), root.0.join("test-runner")).unwrap();
            // Execute a declared, immutable runfile: writing a launcher in
            // concurrently spawning tests can leave its inode write-open in
            // another child and make exec fail with ETXTBSY on Linux.
            let launcher = PathBuf::from(
                std::env::var_os("CARGO_MANIFEST_DIR").expect("Bazel crate runfiles directory"),
            )
            .join("tests/fixtures/cancellation-worker.sh");
            assert!(launcher.is_absolute());
            assert!(launcher.is_file());
            let surface = Arc::new(
                RustNcmSurface::new(RustNcmConfig {
                    worker_binary: launcher,
                    state_root: root.state_root(),
                    worker_options: WorkerOptions {
                        test_double: true,
                        ..WorkerOptions::default()
                    },
                })
                .unwrap(),
            );
            // The child connects before servicing preflight. Proved identity
            // therefore guarantees a pending connection; fallback construction
            // alone does not, so assert identity before entering accept.
            assert!(surface.provider_instance_id().unwrap().is_some());
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            (surface, listener, stream)
        }

        struct ReleaseOnDrop {
            cancellation: CancellationToken,
            stream: TcpStream,
        }

        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.cancellation.cancel();
                let _ = self.stream.write_all(&[1]);
            }
        }

        fn cancel_dispatched<T: Send>(
            root: &TestRoot,
            surface: &RustNcmSurface,
            stream: TcpStream,
            cancellation: CancellationToken,
            invoke: impl FnOnce() -> T + Send,
        ) -> T {
            let pid = surface
                .worker_pid()
                .expect("preflight started fixture worker");
            fs::write(root.0.join("cancel-next-request"), []).unwrap();
            thread::scope(|threads| {
                let (reply_tx, reply_rx) = mpsc::sync_channel(1);
                let task = threads.spawn(move || reply_tx.send(invoke()).unwrap());
                // Drop runs before the scoped join, including on assertion
                // failures, so a live fixture is always released and cancelled.
                let mut guard = ReleaseOnDrop {
                    cancellation,
                    stream,
                };
                let mut entered_pid = [0; 4];
                guard
                    .stream
                    .read_exact(&mut entered_pid)
                    .expect("worker must decode the armed request");
                assert_eq!(u32::from_be_bytes(entered_pid), pid);
                assert_eq!(surface.worker_pid(), Some(pid));

                let started = Instant::now();
                guard.cancellation.cancel();
                let reply = reply_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("cancellation must finish before the long request deadline");
                task.join().unwrap();
                assert!(started.elapsed() < Duration::from_secs(1));
                assert!(
                    surface.worker_pid().is_none(),
                    "cancelled worker must be reaped"
                );
                assert!(
                    !Command::new("kill")
                        .args(["-0", &pid.to_string()])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success(),
                    "retired fixture process must no longer exist"
                );
                reply
            })
        }

        #[test]
        fn inflight_handshake_cancellation_reaps_worker_and_recovers() {
            let root = TestRoot::new("cancel-handshake");
            let (surface, _listener, stream) = controlled_surface(&root);
            let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
            let exact_scope = scope("cancel-handshake");
            let request = HandshakeRequest::new(HandshakeRequestParts {
                provider_id: OwnedProviderId::new(NCM_PROVIDER_ID).unwrap(),
                registration_revision: 1,
                exact_scope: exact_scope.clone(),
                request_id: "cancel-handshake".to_owned(),
                required_capabilities: all_capabilities(),
                host_limits: limits(),
                control: OperationControl::new(i64::MAX, 10_000, CancellationToken::new()),
                challenge_nonce: [7; 32],
            })
            .unwrap();
            let reply = cancel_dispatched(
                &root,
                &surface,
                stream,
                request.control.cancellation(),
                || adapter.handshake(&request),
            );
            assert_eq!(reply.terminal.terminal_code(), TerminalCode::Cancelled);
            assert_eq!(
                reply.terminal.committed_effect().state(),
                CommittedEffectState::None
            );
            assert!(reply.ready_receipt_sha256.is_none());
            assert!(reply.provider_instance_id.is_none());
            ready_parts(&handshake(&adapter, &exact_scope));
            assert!(surface.worker_pid().is_some());
        }

        #[test]
        fn inflight_recall_cancellation_reaps_worker_and_retains_observation() {
            let root = TestRoot::new("cancel-recall");
            let (surface, _listener, stream) = controlled_surface(&root);
            let adapter = NcmProviderAdapter::new(surface.clone()).unwrap();
            let exact_scope = scope("cancel-recall");
            let observed = invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::Observe,
                Some("cancel-recall-observation"),
                observe_value(
                    "cancel-recall-source",
                    "cancellation command",
                    "durable outcome",
                ),
            );
            assert_eq!(observed.terminal.terminal_code(), TerminalCode::Success);
            let (receipt, generation) = ready_parts(&handshake(&adapter, &exact_scope));
            let request = call(
                ProviderOperation::Recall,
                &exact_scope,
                &receipt,
                generation,
                None,
                json!({"query_text": "cancellation command", "top_k": 5}),
                10_000,
            );
            let reply = cancel_dispatched(
                &root,
                &surface,
                stream,
                request.control.cancellation(),
                || adapter.invoke(&request),
            );
            assert_eq!(reply.terminal.terminal_code(), TerminalCode::Cancelled);
            assert_eq!(
                reply.terminal.committed_effect().state(),
                CommittedEffectState::None
            );
            assert!(reply.payload.is_none());
            let recalled = invoke_after_handshake(
                &adapter,
                &exact_scope,
                ProviderOperation::Recall,
                None,
                json!({"query_text": "cancellation command", "top_k": 5}),
            );
            assert_eq!(recalled.terminal.terminal_code(), TerminalCode::Success);
            let value = response_json(&recalled);
            let candidates = value["Candidates"]["candidates"].as_array().unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0]["value_text"], "durable outcome");
            assert!(surface.worker_pid().is_some());
        }
    }

    /// Withholds a successful observation from the caller by cancelling only
    /// after the real worker has returned evidence that its effect committed.
    struct CancelAfterCommitSurface {
        inner: Arc<RustNcmSurface>,
        cancel_next_observe: AtomicBool,
    }

    impl NcmCognitiveSurface for CancelAfterCommitSurface {
        fn descriptor(&self) -> tracedecay_memory_provider_api::ProviderDescriptor {
            self.inner.descriptor()
        }

        fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
            self.inner.handshake(request)
        }

        fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
            let reply = self.inner.invoke(call);
            if call.operation == ProviderOperation::Observe
                && self.cancel_next_observe.swap(false, Ordering::SeqCst)
            {
                assert_eq!(reply.terminal.terminal_code(), TerminalCode::Success);
                assert_eq!(
                    reply.terminal.committed_effect().state(),
                    CommittedEffectState::Committed
                );
                call.control.cancellation().cancel();
            }
            reply
        }
    }

    #[test]
    fn cancellation_after_commit_returns_effect_unknown_then_retry_is_duplicate() {
        let root = TestRoot::new("effect-unknown");
        let controlled = Arc::new(CancelAfterCommitSurface {
            inner: surface(&root),
            cancel_next_observe: AtomicBool::new(true),
        });
        let adapter = NcmProviderAdapter::new(controlled).expect("construct adapter");
        let exact_scope = scope("project-effect-unknown");
        let ready = handshake(&adapter, &exact_scope);
        let (receipt, generation) = ready_parts(&ready);
        let observation = observe_value(
            "source-effect-unknown",
            "cancellation command",
            "cancellation outcome",
        );
        // The real worker commits before the decorator cancels this call.
        // No scheduler-dependent deadline decides whether dispatch happened.
        let unknown = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact_scope,
            &receipt,
            generation,
            Some("observe-effect-unknown"),
            observation.clone(),
            10_000,
        ));
        assert_eq!(
            unknown.terminal.terminal_code(),
            TerminalCode::EffectUnknown
        );
        assert_eq!(
            unknown.terminal.committed_effect().state(),
            CommittedEffectState::Unknown
        );
        assert!(
            unknown
                .terminal
                .committed_effect()
                .reconciliation_action()
                .is_some()
        );

        let mut retry_ready = handshake(&adapter, &exact_scope);
        if retry_ready.terminal.terminal_code() == TerminalCode::StaleIdentity {
            retry_ready = handshake(&adapter, &exact_scope);
        }
        let (retry_receipt, retry_generation) = ready_parts(&retry_ready);
        let retried = adapter.invoke(&call(
            ProviderOperation::Observe,
            &exact_scope,
            &retry_receipt,
            retry_generation,
            Some("observe-effect-unknown"),
            observation.clone(),
            10_000,
        ));
        assert_eq!(retried.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(
            retried.terminal.committed_effect().state(),
            CommittedEffectState::Duplicate
        );
        let replayed = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Observe,
            Some("observe-effect-unknown"),
            observation,
        );
        assert_eq!(replayed.terminal.terminal_code(), TerminalCode::Success);
        assert_eq!(
            replayed.terminal.committed_effect().state(),
            CommittedEffectState::Duplicate
        );
        let recall = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Recall,
            None,
            json!({"query_text": "cancellation command", "top_k": 5}),
        );
        assert_eq!(recall.terminal.terminal_code(), TerminalCode::Success);
        let recalled = response_json(&recall);
        let candidates = recalled["Candidates"]["candidates"]
            .as_array()
            .expect("recall candidate array");
        assert_eq!(candidates.len(), 1, "observation must commit exactly once");
        assert_eq!(candidates[0]["value_text"], "cancellation outcome");
    }

    struct LeakingSurface {
        inner: Arc<RustNcmSurface>,
        raw_project_id: String,
    }

    impl NcmCognitiveSurface for LeakingSurface {
        fn descriptor(&self) -> tracedecay_memory_provider_api::ProviderDescriptor {
            self.inner.descriptor()
        }

        fn handshake(&self, request: &NcmSurfaceHandshakeRequest) -> NcmSurfaceHandshakeResponse {
            self.inner.handshake(request)
        }

        fn invoke(&self, call: &NcmSurfaceCall) -> ProviderReply {
            let mut reply = self.inner.invoke(call);
            if reply.terminal.terminal_code() == TerminalCode::Success {
                reply.payload = Some(payload(
                    call.operation,
                    json!({"raw_project_id": self.raw_project_id}),
                ));
            }
            reply
        }
    }

    #[test]
    fn adapter_rejects_raw_project_identity_in_surface_reply() {
        let root = TestRoot::new("scope-leak");
        let raw_project_id = "project-scope-leak";
        let leaker = Arc::new(LeakingSurface {
            inner: surface(&root),
            raw_project_id: raw_project_id.to_owned(),
        });
        let adapter = NcmProviderAdapter::new(leaker).expect("construct adapter");
        let exact_scope = scope(raw_project_id);
        let reply = invoke_after_handshake(
            &adapter,
            &exact_scope,
            ProviderOperation::Health,
            None,
            json!({}),
        );
        assert_eq!(
            reply.terminal.terminal_code(),
            TerminalCode::ContractViolation
        );
        assert!(reply.payload.is_none());
    }
}
