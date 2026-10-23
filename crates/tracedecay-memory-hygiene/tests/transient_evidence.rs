//! Acceptance criterion 2 — transient detections never auto-delete canonical
//! evidence.
//!
//! The structural guarantee is the signature: `admit` takes `&Value` and
//! returns a new owned value, and the sanitizer holds no store handle. These
//! tests prove the behavioural half — the caller's value is untouched, a
//! transient class can never withhold, and a withheld admission still names the
//! untouched source so a journal can advance its cursor without deleting
//! anything.
#![allow(clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_memory_hygiene::{
    HygieneAction, HygieneClass, ObservationAdmission, ObservationSanitizer,
    SanitizationDisposition, canonical_payload_bytes, transient_matches,
};

const TRANSIENT_FACTS: &str = include_str!("fixtures/transient_facts.json");

struct TransientCase {
    id: String,
    expected_class: HygieneClass,
    expected_disposition: SanitizationDisposition,
    payload: Value,
}

fn cases() -> Vec<TransientCase> {
    let document: Value = serde_json::from_str(TRANSIENT_FACTS).expect("fixture json");
    document["cases"]
        .as_array()
        .expect("fixture cases")
        .iter()
        .map(|row| TransientCase {
            id: row["id"].as_str().expect("case id").to_owned(),
            expected_class: HygieneClass::from_wire(
                row["expected_class"].as_str().expect("expected class"),
            )
            .expect("known class"),
            expected_disposition: match row["expected_disposition"]
                .as_str()
                .expect("expected disposition")
            {
                "accepted" => SanitizationDisposition::Accepted,
                "redacted" => SanitizationDisposition::Redacted,
                other => panic!("unknown disposition {other}"),
            },
            payload: row["payload"].clone(),
        })
        .collect()
}

#[test]
fn admission_never_mutates_the_caller_value() {
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let payloads = [
        json!({ "note": "wrote /tmp/tracedecay-a91f3c/spool.json then exited" }),
        json!({ "note": concat!("AKIA", "4S27TQXBVCZ5MJ6L is the access key") }),
        json!({ "config": { "refresh_token": "abc" } }),
        json!({ "note": "Use pnpm rather than npm for installs in this repo" }),
    ];
    for payload in payloads {
        let before = payload.clone();
        let before_bytes = canonical_payload_bytes(&payload).expect("canonical bytes");
        let _ = sanitizer.admit(&payload).expect("admission");
        assert_eq!(payload, before, "admission mutated its input");
        assert_eq!(
            canonical_payload_bytes(&payload).expect("canonical bytes"),
            before_bytes
        );
    }
}

#[test]
fn transient_findings_never_withhold_and_never_classify_as_secret() {
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    for case in cases() {
        let findings = sanitizer.classify(&case.payload).expect("classification");
        assert!(
            findings
                .iter()
                .any(|finding| finding.class() == case.expected_class),
            "{}: expected {:?}, got {findings:?}",
            case.id,
            case.expected_class
        );
        for finding in &findings {
            assert!(
                !finding.action().withholds(),
                "{}: a transient class must never withhold ({finding:?})",
                case.id
            );
        }
        match sanitizer.admit(&case.payload).expect("admission") {
            ObservationAdmission::Admitted { receipt, .. } => {
                assert_eq!(
                    receipt.disposition(),
                    case.expected_disposition,
                    "{}: unexpected disposition",
                    case.id
                );
            }
            other => panic!(
                "{}: transient output must be admitted, got {other:?}",
                case.id
            ),
        }
    }
}

#[test]
fn annotate_classes_leave_bytes_untouched_while_still_recording_a_finding() {
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    for case in cases() {
        if sanitizer.policy().action(case.expected_class) != HygieneAction::Annotate {
            continue;
        }
        match sanitizer.admit(&case.payload).expect("admission") {
            ObservationAdmission::Admitted { sanitized, receipt } => {
                assert_eq!(
                    sanitized, case.payload,
                    "{}: annotate rewrote bytes",
                    case.id
                );
                assert_eq!(receipt.disposition(), SanitizationDisposition::Accepted);
                assert!(
                    receipt.finding_count() > 0,
                    "{}: annotate recorded no finding",
                    case.id
                );
            }
            other => panic!("{}: expected an admission, got {other:?}", case.id),
        }
    }
}

#[test]
fn redacted_transients_rewrite_only_the_detected_span() {
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let payload = json!({ "note": "server started with pid 48213 and stayed up" });
    match sanitizer.admit(&payload).expect("admission") {
        ObservationAdmission::Admitted { sanitized, .. } => {
            let note = sanitized["note"].as_str().expect("note");
            assert!(note.starts_with("server started with pid "));
            assert!(note.ends_with(" and stayed up"));
            assert!(!note.contains("48213"));
        }
        other => panic!("expected an admission, got {other:?}"),
    }
}

#[test]
fn a_withheld_admission_names_untouched_evidence_and_stores_no_payload() {
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let payload = json!({ "note": concat!("ghp_", "KsY7QwT2mZ4bV9nR6cX1jH8pL3dG5fA0eUwQ") });
    let expected_digest = sha256_hex(&canonical_payload_bytes(&payload).expect("canonical bytes"));
    match sanitizer.admit(&payload).expect("admission") {
        ObservationAdmission::Withheld {
            receipt_id,
            source_payload_sha256,
            ..
        } => {
            assert_eq!(source_payload_sha256, expected_digest);
            assert_ne!(receipt_id, source_payload_sha256);
            // The withheld arm structurally carries no payload, so there is no
            // sanitized copy of a rejected observation anywhere in the result.
        }
        other => panic!("expected a withheld admission, got {other:?}"),
    }
    // The caller still holds the canonical evidence, unchanged.
    assert_eq!(
        sha256_hex(&canonical_payload_bytes(&payload).expect("canonical bytes")),
        expected_digest
    );
}

#[test]
fn the_local_transient_corpus_agrees_with_the_shared_upstream_detector() {
    // The upstream detector answers "is this transient" without exposing a
    // span; this crate owns the spans. Wherever this crate finds a span, the
    // shared corpus must agree the text is transient — that is what keeps the
    // deliberate duplication honest until the two can be unified.
    let transient_texts = [
        "server started with pid 48213 and stayed up",
        "wrote /tmp/tracedecay-a91f3c/spool.json then exited",
        "dashboard listening on 127.0.0.1:43817 for this run",
        "build finished in 12.4s",
        "the daemon lock is held by pid=48213 until shutdown",
        "PID: 90210 reaped the child worker",
        "worktree seeded under /tmp/tracedecay-agent-4f8e21/checkout",
        "the flaky suite ended with exit code 101 on the second run",
        "daemon started in 42 ms",
        "bound 0.0.0.0:43817 for the duration of the test",
    ];
    for text in transient_texts {
        assert!(
            !transient_matches(text).is_empty(),
            "local corpus missed {text}"
        );
    }

    let durable_texts = [
        "Curation hard-deletes losers; there is no archive",
        "scratch output goes under /tmp/cache",
    ];
    for text in durable_texts {
        assert!(
            transient_matches(text).is_empty(),
            "local corpus over-matched {text}"
        );
    }
}

#[test]
fn a_redacted_process_id_leaves_an_annotated_port_beside_it_intact() {
    // The bead names ports and pids side by side, and real run output carries
    // both in one sentence. The pid is instance data and is rewritten; the bind
    // address is annotated only, so the durable half of the sentence survives
    // byte-for-byte and the receipt still records both findings.
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let payload = json!({ "note": "worker pid 555 bound 127.0.0.1:8080 and served the dashboard" });
    let findings = sanitizer.classify(&payload).expect("classification");
    assert!(
        findings
            .iter()
            .any(|finding| finding.class() == HygieneClass::TransientProcessId)
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.class() == HygieneClass::TransientEphemeralPort)
    );
    match sanitizer.admit(&payload).expect("admission") {
        ObservationAdmission::Admitted { sanitized, receipt } => {
            let note = sanitized["note"].as_str().expect("note");
            assert_eq!(receipt.disposition(), SanitizationDisposition::Redacted);
            assert_eq!(receipt.finding_count(), 2);
            assert!(!note.contains("pid 555"), "pid survived: {note}");
            assert!(
                note.contains("bound 127.0.0.1:8080 and served the dashboard"),
                "annotated port was rewritten: {note}"
            );
        }
        other => panic!("expected a redacted admission, got {other:?}"),
    }
}

#[test]
fn instance_shaped_temporary_paths_are_redacted_but_documented_stable_paths_survive() {
    // `$TMPDIR` on macOS resolves under `/private/var/folders`, and a generated
    // run directory anywhere under a temporary root is instance data. A stable,
    // hand-documented location under the same roots is durable knowledge and
    // must be delivered untouched — that is the false-positive edge the
    // instance-shape rule exists for.
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let instance_paths = [
        "/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/tracedecay-run-77f2/out.log",
        "/var/folders/xy/abcd1234/T/spool-0001.sqlite3",
        "/tmp/tracedecay-agent-4f8e21/checkout",
    ];
    for path in instance_paths {
        let payload = json!({ "note": format!("wrote {path} during the run") });
        match sanitizer.admit(&payload).expect("admission") {
            ObservationAdmission::Admitted { sanitized, receipt } => {
                let note = sanitized["note"].as_str().expect("note");
                assert_eq!(
                    receipt.disposition(),
                    SanitizationDisposition::Redacted,
                    "{path} was not redacted"
                );
                assert!(!note.contains(path), "instance path survived: {note}");
                assert!(note.starts_with("wrote "), "durable prefix lost: {note}");
                assert!(
                    note.ends_with(" during the run"),
                    "durable suffix lost: {note}"
                );
            }
            other => panic!("{path}: expected a redacted admission, got {other:?}"),
        }
    }

    let stable_paths = [
        "/tmp/cache",
        "/var/folders/shared",
        "/private/var/folders/T",
    ];
    for path in stable_paths {
        let payload = json!({ "note": format!("scratch output goes under {path}") });
        match sanitizer.admit(&payload).expect("admission") {
            ObservationAdmission::Admitted { sanitized, receipt } => {
                assert_eq!(sanitized, payload, "{path}: stable path was rewritten");
                assert_eq!(receipt.disposition(), SanitizationDisposition::Accepted);
            }
            other => panic!("{path}: expected an accepted admission, got {other:?}"),
        }
    }
}

#[test]
fn raw_log_output_is_annotated_never_withheld_and_never_rewritten() {
    // Raw run logs are the noisiest class the bead names. The policy answers
    // them with `annotate`: the finding reaches the receipt so a provider can
    // decide retention, while the bytes — including a multi-line stdout
    // capture — are delivered exactly as settled.
    let sanitizer = ObservationSanitizer::new().expect("canonical hygiene policy");
    let payload = json!({
        "stdout": [
            "compiling tracedecay v0.0.49",
            "daemon started in 42 ms",
            "listening on http://localhost:3000",
            "build finished in 12.4s",
            "exit code 0"
        ]
    });
    let findings = sanitizer.classify(&payload).expect("classification");
    let run_log_findings = findings
        .iter()
        .filter(|finding| finding.class() == HygieneClass::TransientRunLog)
        .count();
    assert!(
        run_log_findings >= 4,
        "expected one finding per log line: {findings:?}"
    );
    assert!(findings.iter().all(|finding| !finding.action().withholds()));
    match sanitizer.admit(&payload).expect("admission") {
        ObservationAdmission::Admitted { sanitized, receipt } => {
            assert_eq!(sanitized, payload);
            assert_eq!(receipt.disposition(), SanitizationDisposition::Accepted);
            assert_eq!(
                receipt.sanitized_payload_sha256(),
                receipt.source_payload_sha256()
            );
            assert_eq!(
                receipt.finding_count(),
                u32::try_from(findings.len()).expect("count")
            );
        }
        other => panic!("expected an accepted admission, got {other:?}"),
    }
}
