//! Transient-noise detection with byte spans.
//!
//! Redacting a transient span needs its byte range, so this module owns the
//! four transient patterns.
//!
//! This is deliberate, bounded duplication of exactly four expressions, kept
//! here rather than reached for upstream because reaching for it would mean
//! moving roughly two thousand lines of the shared privacy corpus across a
//! crate boundary. FOLLOW-UP: unify the two transient corpora behind one public
//! span-returning surface in `tracedecay-session-memory` once the upstream patch
//! budget allows the extraction; `transient_corpus_matches_runtime_core` in
//! `tests/transient_evidence.rs` keeps the two in agreement until then.
//!
//! Two of the four classes deliberately never rewrite bytes. Ordinary code
//! facts routinely document a bind address ("the dashboard binds
//! `127.0.0.1:8080`") or describe timing ("the incremental pass finished in
//! 12.4s"), so ports and run-log phrasing are annotated and left alone. Only
//! unambiguous instance data — a process identifier, and a temporary path whose
//! final component is instance-shaped — is rewritten.

use std::ops::Range;
use std::sync::OnceLock;

use regex::Regex;

use crate::policy::HygieneClass;

/// Replacement text for a redacted process identifier.
pub const REDACTED_PROCESS_ID: &str = "[TraceDecay redacted: transient process id]";

/// Replacement text for a redacted instance-shaped temporary path.
pub const REDACTED_TEMP_PATH: &str = "[TraceDecay redacted: transient path]";

/// Replacement text for a redacted ephemeral local bind address.
pub const REDACTED_EPHEMERAL_ENDPOINT: &str = "[TraceDecay redacted: transient endpoint]";

/// Replacement text for a redacted run-log line.
pub const REDACTED_RUN_LOG: &str = "[TraceDecay redacted: transient run log]";

/// Minimum length of a temporary-path leaf before it is treated as instance
/// data rather than a documented stable location.
const INSTANCE_LEAF_MIN_LEN: usize = 8;

/// One transient detection inside a single string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientMatch {
    /// Detected class.
    pub class: HygieneClass,
    /// Byte span inside the scanned string.
    pub span: Range<usize>,
}

struct TransientPatterns {
    process_id: Regex,
    temp_path: Regex,
    ephemeral_port: Regex,
    run_log: Regex,
}

fn patterns() -> Option<&'static TransientPatterns> {
    static PATTERNS: OnceLock<Option<TransientPatterns>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            Some(TransientPatterns {
                // The span is the digit run only, so the durable sentence
                // around a pid survives redaction.
                process_id: Regex::new(r"(?i)\bpid\s*[:=#]?\s*(\d{2,})\b").ok()?,
                temp_path: Regex::new(
                    r"(?:/private/var/folders|/var/folders|/tmp)(?:/[A-Za-z0-9._-]+)+",
                )
                .ok()?,
                ephemeral_port: Regex::new(
                    r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}\b",
                )
                .ok()?,
                run_log: Regex::new(
                    r"(?i)\b(?:listening on|started in \d+\s*ms|exit code \d+|finished in \d+(?:\.\d+)?s)\b",
                )
                .ok()?,
            })
        })
        .as_ref()
}

/// Returns whether the transient corpus compiled.
///
/// A corpus that failed to compile has proven nothing, so the pipeline treats
/// it as a hard error rather than an empty match list.
#[must_use]
pub fn corpus_is_available() -> bool {
    patterns().is_some()
}

/// Finds every transient span inside one string, in ascending start order with
/// overlaps resolved in favour of the earlier, longer match.
#[must_use]
pub fn transient_matches(text: &str) -> Vec<TransientMatch> {
    let Some(patterns) = patterns() else {
        return Vec::new();
    };
    let mut matches: Vec<TransientMatch> = Vec::new();

    for captures in patterns.process_id.captures_iter(text) {
        if let Some(digits) = captures.get(1) {
            matches.push(TransientMatch {
                class: HygieneClass::TransientProcessId,
                span: digits.range(),
            });
        }
    }
    for found in patterns.temp_path.find_iter(text) {
        if is_instance_shaped_path(found.as_str()) {
            matches.push(TransientMatch {
                class: HygieneClass::TransientTempPath,
                span: found.range(),
            });
        }
    }
    for found in patterns.ephemeral_port.find_iter(text) {
        matches.push(TransientMatch {
            class: HygieneClass::TransientEphemeralPort,
            span: found.range(),
        });
    }
    for found in patterns.run_log.find_iter(text) {
        matches.push(TransientMatch {
            class: HygieneClass::TransientRunLog,
            span: found.range(),
        });
    }

    matches.sort_by(|left, right| {
        left.span
            .start
            .cmp(&right.span.start)
            .then_with(|| right.span.end.cmp(&left.span.end))
    });
    let mut resolved: Vec<TransientMatch> = Vec::with_capacity(matches.len());
    for candidate in matches {
        let overlaps = resolved
            .last()
            .is_some_and(|previous| candidate.span.start < previous.span.end);
        if !overlaps {
            resolved.push(candidate);
        }
    }
    resolved
}

/// Returns the replacement text for a transient class.
///
/// Every transient class has a replacement, so whether a span is rewritten is
/// decided by the policy table alone: raising `transient_ephemeral_port` to
/// `redact` in a hardened deployment needs no code change.
#[must_use]
pub const fn replacement_for(class: HygieneClass) -> Option<&'static str> {
    match class {
        HygieneClass::TransientProcessId => Some(REDACTED_PROCESS_ID),
        HygieneClass::TransientTempPath => Some(REDACTED_TEMP_PATH),
        HygieneClass::TransientEphemeralPort => Some(REDACTED_EPHEMERAL_ENDPOINT),
        HygieneClass::TransientRunLog => Some(REDACTED_RUN_LOG),
        _ => None,
    }
}

/// Returns whether a temporary path names one run rather than a documented
/// stable location.
///
/// A path is instance-shaped when any component under the temporary root is at
/// least [`INSTANCE_LEAF_MIN_LEN`] characters and carries a digit — the shape a
/// generated run directory has. `/tmp/tracedecay-a91f3c/spool.json` qualifies;
/// `/tmp/cache` does not, because "scratch output goes under /tmp/cache" is a
/// durable fact rather than instance data.
///
/// The known residual over-match is a hand-written path that happens to look
/// generated, such as `/tmp/build-2024`. That is a policy-table entry rather
/// than a code branch, so tightening it is a data change plus a fixture.
fn is_instance_shaped_path(path: &str) -> bool {
    path.split('/').any(|component| {
        component.len() >= INSTANCE_LEAF_MIN_LEN
            && component
                .chars()
                .any(|character| character.is_ascii_digit())
    })
}
