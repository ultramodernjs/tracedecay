//! Real-ledger retention, privacy, replay, and scope-isolation tests.

use tracedecay_memory_provider_registry::{
    DeniedRecallCandidate, NATIVE_PROVIDER_ID, RecallScopeBindingsV1, ScopeBinding, ScopeField,
    UnknownValidityPolicy,
};

use super::*;

#[test]
fn existing_ledger_open_refuses_a_missing_target_without_creating_it() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join(LEDGER_FILE_NAME);
    let error = RecallAdmissionLedgerV1::open_existing_with_key(
        path.clone(),
        control_attribution::RecallLocatorKeyV1::for_test(),
    )
    .unwrap_err();
    assert_eq!(error.path, path);
    assert!(!path.exists());
}

fn ledger_report(request_id: &str, denied: Vec<DeniedRecallCandidate>) -> RecallAdmissionReport {
    RecallAdmissionReport {
        request_id: request_id.to_owned(),
        provider_id: Some("tracedecay.native".to_owned()),
        registration_revision: Some(7),
        exact_scope_sha256: "b".repeat(64),
        temporal_mode: "current".to_owned(),
        evaluation_time: "2026-09-02T00:00:00.000000Z".to_owned(),
        unknown_validity_policy: UnknownValidityPolicy::Exclude,
        authorized_scope_bindings: RecallScopeBindingsV1::new([
            ScopeBinding::ProjectFacts,
            ScopeBinding::ProfileFacts,
        ]),
        received_count: 1 + denied.len(),
        received_candidate_ids: std::iter::once(format!("{request_id}:admitted"))
            .chain(denied.iter().map(|denied| denied.candidate_id.clone()))
            .collect(),
        admitted_count: 1,
        denied,
        degraded: false,
        warnings: Vec::new(),
    }
}

#[test]
fn ledger_retains_denials_without_content_and_refuses_divergent_replays() {
    let temporary = tempfile::tempdir().expect("ledger root");
    let path = temporary.path().join(LEDGER_FILE_NAME);
    let ledger = RecallAdmissionLedgerV1::open(path.clone()).expect("open ledger");
    let denied = vec![
        DeniedRecallCandidate {
            candidate_id: "source:/private/Authorization-Bearer-SECRET-9a7f".to_owned(),
            stable_memory_ref: Some("memory:cross-worktree".to_owned()),
            reason: RecallDenialReason::ScopeMismatch {
                field: ScopeField::WorktreeIdentity,
            },
            provider_claimed_scope_binding: ScopeBinding::ExactCodingScope,
            provider_claimed_scope_sha256: Some("c".repeat(64)),
            provider_claimed_temporal_state: "current".to_owned(),
        },
        DeniedRecallCandidate {
            candidate_id: "source:/private/revoked-token.json#L7".to_owned(),
            stable_memory_ref: None,
            reason: RecallDenialReason::Revoked,
            provider_claimed_scope_binding: ScopeBinding::ProjectFacts,
            provider_claimed_scope_sha256: None,
            provider_claimed_temporal_state: "revoked".to_owned(),
        },
        DeniedRecallCandidate {
            candidate_id: "source:/private/session-claim.env#L3".to_owned(),
            stable_memory_ref: Some("memory:checkout".to_owned()),
            reason: RecallDenialReason::ForbiddenIdentity {
                field: ScopeField::AgentSessionId,
            },
            provider_claimed_scope_binding: ScopeBinding::CheckoutObservations,
            provider_claimed_scope_sha256: None,
            provider_claimed_temporal_state: "current".to_owned(),
        },
        DeniedRecallCandidate {
            candidate_id: "source:/private/provider-detail.json#L11".to_owned(),
            stable_memory_ref: None,
            reason: RecallDenialReason::InvalidSourceAttribution {
                detail: "source:/private/Authorization-Bearer-SECRET-detail".to_owned(),
            },
            provider_claimed_scope_binding: ScopeBinding::ExactCodingScope,
            provider_claimed_scope_sha256: None,
            provider_claimed_temporal_state: "unknown".to_owned(),
        },
    ];
    let report = ledger_report("request.ledger", denied.clone());
    assert_eq!(
        ledger.record(&report).expect("first write"),
        RecallAdmissionLedgerWriteV1::Recorded
    );
    assert_eq!(
        ledger.record(&report).expect("identical replay"),
        RecallAdmissionLedgerWriteV1::AlreadyRecorded
    );
    let retained_denials = ledger
        .denied_candidates(&report.exact_scope_sha256, "request.ledger")
        .expect("denial rows");
    assert_eq!(retained_denials.len(), denied.len());
    let retained_json = serde_json::to_string(&retained_denials).expect("retained denials");
    for (raw, retained) in denied.iter().zip(&retained_denials) {
        assert_eq!(
            retained.candidate_id,
            control_attribution::retained_candidate_identity_alias_for_report(
                &report,
                ledger.locator_key(),
                &raw.candidate_id,
            )
            .expect("valid recall attribution fixture")
        );
        assert_ne!(retained.candidate_id, raw.candidate_id);
        assert!(
            !retained_json.contains(&raw.candidate_id),
            "raw denied candidate id reached SQLite projection: {raw:?}: {retained_json}"
        );
        if let Some(raw_ref) = raw.stable_memory_ref.as_deref() {
            assert!(
                retained.stable_memory_ref.as_deref().is_some_and(|value| {
                    value.starts_with("recall-memory-ref-v1:") && !value.contains(raw_ref)
                }),
                "raw denial stable ref reached SQLite projection: {raw_ref:?}: {retained_json}"
            );
        }
    }
    assert!(retained_json.contains("provider_detail_withheld"));
    assert!(!retained_json.contains("Authorization-Bearer-SECRET-detail"));
    let divergent = ledger_report("request.ledger", Vec::new());
    assert!(matches!(
        ledger.record(&divergent),
        Err(RecallAdmissionLedgerError::ConflictingReport { .. })
    ));
    assert_eq!(ledger.report_count(), 1);

    // The ledger schema has no content column anywhere.
    let connection = ledger.connection();
    let mut statement = connection
        .prepare("SELECT name FROM pragma_table_info('recall_admission_denials')")
        .expect("table info");
    let columns: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .expect("columns")
        .collect::<Result<_, _>>()
        .expect("column names");
    assert!(!columns.iter().any(|column| column.contains("content")));
    drop(statement);
    drop(connection);
    drop(ledger);

    // The privacy boundary survives a real close/reopen, rather than only
    // the in-process projection above. Read the durable rows again and
    // assert that the provider ids never reappear after SQLite recovery.
    let reopened = RecallAdmissionLedgerV1::open(path).expect("reopen ledger");
    let reopened_denials = reopened
        .denied_candidates(&report.exact_scope_sha256, "request.ledger")
        .expect("reopened denial rows");
    assert_eq!(reopened_denials, retained_denials);
    let reopened_json = serde_json::to_string(&reopened_denials).expect("reopened denials");
    for raw in &denied {
        assert!(!reopened_json.contains(&raw.candidate_id));
    }
}

#[test]
fn legacy_raw_denial_rows_are_withheld_after_reopen() {
    let temporary = tempfile::tempdir().expect("ledger root");
    let path = temporary.path().join(LEDGER_FILE_NAME);
    let ledger = RecallAdmissionLedgerV1::open(path.clone()).expect("open ledger");
    let raw_candidate = "source:/private/legacy-denial-secret";
    let raw_ref = "memory:/private/legacy-denial-ref";
    let report = ledger_report(
        "request.legacy-denial",
        vec![DeniedRecallCandidate {
            candidate_id: raw_candidate.to_owned(),
            stable_memory_ref: Some(raw_ref.to_owned()),
            reason: RecallDenialReason::InvalidSourceAttribution {
                detail: raw_ref.to_owned(),
            },
            provider_claimed_scope_binding: ScopeBinding::ExactCodingScope,
            provider_claimed_scope_sha256: None,
            provider_claimed_temporal_state: "unknown".to_owned(),
        }],
    );
    ledger.record(&report).expect("record denial");

    // Emulate a pre-keyed row left behind by an additive upgrade. The
    // report row remains valid, but its denial projection is no longer a
    // safe retained identity and must be quarantined on every read.
    let raw_reason = serde_json::to_string(&RecallDenialReason::InvalidSourceAttribution {
        detail: raw_ref.to_owned(),
    })
    .expect("raw denial reason JSON");
    ledger
        .connection()
        .execute(
            "UPDATE recall_admission_denials
                 SET candidate_id=?1, stable_memory_ref=?2, reason_json=?3
                 WHERE exact_scope_sha256=?4 AND request_id=?5",
            params![
                raw_candidate,
                raw_ref,
                raw_reason,
                report.exact_scope_sha256,
                report.request_id,
            ],
        )
        .expect("inject legacy denial row");
    assert_eq!(
        ledger
            .denied_candidates(&report.exact_scope_sha256, &report.request_id)
            .expect("legacy denial read"),
        []
    );
    drop(ledger);

    let reopened = RecallAdmissionLedgerV1::open(path).expect("reopen ledger");
    let retained = reopened
        .denied_candidates(&report.exact_scope_sha256, &report.request_id)
        .expect("reopened legacy denial read");
    assert!(retained.is_empty(), "legacy denial leaked: {retained:?}");
}

#[test]
fn retained_candidate_aliases_disambiguate_raw_id_collisions() {
    let mut report = ledger_report("request.alias-collision", Vec::new());
    report.received_count = 1;
    report.received_candidate_ids = vec!["source.secret-value".to_owned()];
    let key = control_attribution::RecallLocatorKeyV1::for_test();
    let base = control_attribution::retained_candidate_identity_alias_for_report(
        &report,
        &key,
        &report.received_candidate_ids[0],
    )
    .expect("valid recall attribution fixture");
    report.received_count = 2;
    report.received_candidate_ids.push(base.clone());
    let aliases =
        control_attribution::retained_candidate_identity_aliases_for_report(&report, &key)
            .expect("valid recall attribution fixture");
    assert_eq!(aliases["source.secret-value"], format!("{base}.1"));
    assert_ne!(aliases["source.secret-value"], aliases[&base]);
    assert!(
        aliases.values().all(|alias| {
            control_attribution::validate_retained_trace_candidate_id(alias).is_ok()
        })
    );
}

#[test]
fn explain_trace_listing_is_bound_to_the_requested_scope() {
    let temporary = tempfile::tempdir().expect("ledger root");
    let ledger = RecallAdmissionLedgerV1::open(temporary.path().join(LEDGER_FILE_NAME))
        .expect("open ledger");
    let request_id = "request.shared-across-scopes";
    let first_scope = "b".repeat(64);
    let second_scope = "c".repeat(64);
    let trace_for_scope = |scope: &str| RecallExplainTraceV1 {
        trace_id: control_attribution::retained_trace_id_with_key(
            ledger.locator_key(),
            scope,
            request_id,
            NATIVE_PROVIDER_ID,
            1,
        )
        .expect("valid recall attribution fixture"),
        request_id: request_id.to_owned(),
        provider_id: NATIVE_PROVIDER_ID.to_owned(),
        registration_revision: 1,
        requested_count: 0,
        degraded: false,
        items: Vec::new(),
        token_summary: None,
    };
    let first_trace = trace_for_scope(&first_scope);
    let second_trace = trace_for_scope(&second_scope);
    ledger
        .retain_explain_trace(&first_scope, &first_trace)
        .expect("first scope trace");
    ledger
        .retain_explain_trace(&second_scope, &second_trace)
        .expect("second scope trace");

    assert_eq!(
        ledger
            .explain_trace_ids_for_request(&first_scope, request_id)
            .expect("first scope trace ids"),
        vec![format!(
            "recall-trace-v1:{first_scope}:{}",
            first_trace.trace_id
        )]
    );
    assert_eq!(
        ledger
            .explain_trace_ids_for_request(&second_scope, request_id)
            .expect("second scope trace ids"),
        vec![format!(
            "recall-trace-v1:{second_scope}:{}",
            second_trace.trace_id
        )]
    );
    assert_eq!(
        ledger
            .explain_trace_ids_for_request(&"d".repeat(64), request_id)
            .expect("unrelated scope trace ids")
            .len(),
        0
    );
}

#[test]
fn legacy_unsalted_trace_rows_are_withheld_from_reads_and_listings() {
    let temporary = tempfile::tempdir().unwrap();
    let ledger = RecallAdmissionLedgerV1::open(temporary.path().join(LEDGER_FILE_NAME))
        .expect("open ledger");
    let exact_scope_sha256 = "e".repeat(64);
    let request_id = "request.legacy-trace";
    let provider_id = NATIVE_PROVIDER_ID;
    let registration_revision = 1_i64;
    let trace_id = "f".repeat(64);
    let legacy_trace = RecallExplainTraceV1 {
        trace_id: trace_id.clone(),
        request_id: request_id.to_owned(),
        provider_id: provider_id.to_owned(),
        registration_revision: registration_revision as u64,
        requested_count: 0,
        degraded: false,
        items: Vec::new(),
        token_summary: None,
    };
    let trace_sha256 = tracedecay_domain::canonical_text::sha256_hex(
        &serde_json::to_vec(&legacy_trace).expect("legacy trace JSON"),
    );
    ledger
        .connection()
        .execute(
            "INSERT INTO recall_explain_traces (
                     exact_scope_sha256, trace_id, request_id, provider_id,
                     registration_revision, requested_count, degraded, trace_sha256,
                     token_summary_json, recorded_at_utc_micros
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, NULL, 1)",
            params![
                exact_scope_sha256,
                trace_id,
                request_id,
                provider_id,
                registration_revision,
                trace_sha256,
            ],
        )
        .expect("insert legacy trace row");
    let trace_ref = control_attribution::RecallControlTraceRefV1::parse(&format!(
        "recall-trace-v1:{exact_scope_sha256}:{trace_id}"
    ))
    .expect("legacy trace reference shape");
    assert!(matches!(
        ledger.explain_trace(&trace_ref),
        Err(RecallAdmissionLedgerError::InvalidControlMetadata)
    ));
    assert_eq!(
        ledger
            .explain_trace_ids_for_request(&exact_scope_sha256, request_id)
            .expect("legacy trace listing")
            .len(),
        0
    );
}
