#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(warnings)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
//! The single admitted secret and transient-data hygiene pipeline for
//! TraceDecay provider observations.
//!
//! # Where this runs
//!
//! Sanitization happens once, at admission, **before** any digest, observation
//! identity, or idempotency key is derived:
//!
//! ```text
//!   canonical evidence (never mutated, never deleted)
//!         │  &Value
//!         ▼
//!   ObservationSanitizer::admit
//!         │
//!         ├── Withheld { reason, receipt_id, source_payload_sha256 }
//!         │      the journal advances its replay cursor past the event and
//!         │      persists a digests-only audit row; no payload is stored, no
//!         │      ProviderCall is built, so no terminal code is needed
//!         │
//!         └── Admitted { sanitized, receipt }
//!                │  digests, observation id, and idempotency key are derived
//!                │  from the SANITIZED payload; those bytes are appended to
//!                │  the journal and dispatched verbatim
//!                ▼
//!          ProviderCall::new(parts)?.with_sanitization(receipt)
//!                ▼
//!          MemoryFabric::deliver_observation → ProviderCall::validate()
//!                fails closed unless the receipt binds this exact payload
//! ```
//!
//! Ordering is the trap this seam exists to close. If a caller derived the
//! idempotency key before admission, the key would name the pre-sanitization
//! digest while the payload carried the post-sanitization one, and a provider
//! would see two keys for one logical event. [`ObservationSanitizer::admit`]
//! therefore returns the sanitized value itself, and
//! [`canonical_payload_bytes`] is the one encoding every digest in this flow is
//! taken over.
//!
//! # What it never does
//!
//! [`ObservationSanitizer::admit`] takes a shared reference and returns a new
//! owned value. It holds no store handle, has no delete path, and cannot reach
//! canonical evidence. A transient detection in the root payload can at most
//! rewrite a span inside the provider-bound copy. An opaque extension is never
//! rewritten: if one would need mutation, [`ObservationSanitizer::admit_observation`]
//! withholds the whole provider-bound observation instead. Neither path can
//! remove anything canonical.
//!
//! No matched byte, redacted value, or source text enters a finding, a receipt,
//! a receipt identifier, or an error raised from this crate. That includes an
//! object key which is itself credential material: the key is replaced by an
//! opaque marker as the walk descends, so it cannot reach the location of a
//! finding on any value nested beneath it either.
//!
//! # Where the rules come from
//!
//! The credential corpus has exactly one owner. This crate reuses
//! `tracedecay_session_memory`'s public detectors rather than re-deriving them,
//! because two divergent gitleaks catalogues is precisely the failure this
//! pipeline exists to prevent. What that public surface cannot do is enumerate
//! *every* class one string carries — `detect_secret_like` answers with the
//! first pattern that matched — so [`crate::credentials`] runs a bounded
//! multi-signal pass declared by the policy document, which can only ever add
//! reject-floor classes. See that module for why each signal exists.
//!
//! The class-to-action table is
//! [`OBSERVATION_HYGIENE_POLICY_V1_JSON`]: a byte-identical crate-local copy of
//! `product/observations/observation-hygiene-policy-v1.json`, embedded so this
//! crate compiles and packages inside its own ownership area, with the two
//! copies gated against each other from Python.

use serde_json::{Map, Value};
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_memory_provider_api::{
    ApiError, OwnedOpaqueExtension, observation_extensions_digest,
};
/// The receipt vocabulary is owned by the provider boundary. It is re-exported
/// here so a caller wiring admission to dispatch needs one import.
pub use tracedecay_memory_provider_api::{
    OBSERVATION_HYGIENE_WITHHELD_ID_PREFIX, PayloadSanitizationReceipt,
    PayloadSanitizationReceiptParts, SanitizationDisposition, WithheldReason,
    derive_withheld_receipt_id,
};
use tracedecay_privacy::{MemoryFactSanitizationV1, sanitize_memory_fact_payload};

mod credentials;
pub mod findings;
pub mod policy;
pub mod recall_text;
pub mod transient;

pub use findings::{
    CREDENTIAL_BEARING_KEY_MARKER_PREFIX, HygieneFindingV1, credential_bearing_key_marker,
    findings_digest,
};
pub use policy::{
    HygieneAction, HygieneClass, OBSERVATION_HYGIENE_POLICY_V1_CANONICAL_PATH,
    OBSERVATION_HYGIENE_POLICY_V1_EMBEDDED_PATH, OBSERVATION_HYGIENE_POLICY_V1_JSON,
    OBSERVATION_HYGIENE_SANITIZER_ID, ObservationHygienePolicyV1, PolicyError, RejectFloorSignals,
};
pub use recall_text::{
    ADVISORY_CONTENT_CHARS_CEILING, ADVISORY_RECALL_HARDENING_POLICY_ID,
    ADVISORY_RECALL_HARDENING_POLICY_REVISION, AdvisoryMetadataAdmissionV1,
    AdvisoryMetadataFieldV1, AdvisoryRecallPolicyError, AdvisoryRecallPolicyV1,
    AdvisoryTextAdmissionV1, AdvisoryTextFindingCountV1, AdvisoryTextFindingV1,
    AdvisoryTextHardener, AdvisoryTextWithheldReasonV1, AdvisoryTrustTierV1,
    HardenedAdvisoryTextV1, NEUTRALIZED_CONTROL_MARKUP, PINNED_ADVISORY_METADATA_CHARS,
    UNTRUSTED_BOUNDARY_LABEL, is_contained_advisory_label,
};
pub use transient::{TransientMatch, transient_matches};

use credentials::ProbeBudget;
use findings::{PathSegment, canonicalize, render_key_location, render_path};

/// Structural headroom the provider envelope and any future wrapper may add
/// around a canonical record before hygiene walks it.
pub const ENVELOPE_STRUCTURAL_HEADROOM: usize = 32;

/// Maximum structural nesting depth the pipeline will descend.
///
/// A bounded depth is checked while walking, so a deeply nested payload cannot
/// exhaust the stack before the byte ceiling notices anything. The bound is
/// derived from the canonical store's own structure ceiling plus envelope
/// headroom: a record the host already settled must never surface here as a
/// depth error, because that error is an admission fault, not a withheld
/// observation, and would stall replay on a record the store accepted.
pub const MAX_STRUCTURAL_DEPTH: usize =
    tracedecay_domain::MAX_OBSERVATION_STRUCTURE_DEPTH + ENVELOPE_STRUCTURAL_HEADROOM;
const _: () = assert!(
    MAX_STRUCTURAL_DEPTH >= tracedecay_domain::MAX_OBSERVATION_STRUCTURE_DEPTH + 8,
    "hygiene depth ceiling must clear the canonical store depth ceiling"
);

/// The exact replacement `tracedecay_privacy` writes over a value whose
/// object key proved it is a credential.
///
/// It heads [`REDACTION_MARKERS`], the table that attributes a canonical
/// redaction to the class that produced it. It is a shared constant in effect
/// but not in scope: the upstream definition is private to its module.
const REDACTED_SENSITIVE_FIELD: &str = "[TraceDecay redacted: sensitive field]";

const CLAUDE_PROVIDER_ID: &str = "claude";
const CLAUDE_OBSERVATION_SOURCE_PREFIX: &str = "tracedecay-claude-observation-source-v1-sha256-";
const TRUSTED_SOURCE_PLACEHOLDER_PREFIX: &str = "td-trusted-source-v1-";
const TRUSTED_SOURCE_PLACEHOLDER_ATTEMPTS: usize = 4096;

/// Why an observation could not be admitted at all.
///
/// These are failures of the pipeline or of the payload's shape. They are
/// distinct from a withheld admission, which is a successful classification
/// whose answer is "do not deliver this".
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HygieneError {
    /// The class-to-action table could not be assembled.
    #[error("observation hygiene policy is unusable: {0}")]
    Policy(#[from] PolicyError),
    /// The payload could not be encoded to canonical JSON.
    #[error("observation payload could not be canonically encoded")]
    CanonicalEncoding,
    /// The payload exceeded the bounded scan ceiling.
    #[error("observation payload exceeds the {maximum} byte hygiene scan limit")]
    PayloadTooLarge {
        /// Inclusive canonical byte ceiling.
        maximum: usize,
    },
    /// The payload nested deeper than the pipeline will walk.
    #[error("observation payload nests deeper than {maximum} levels")]
    PayloadTooDeep {
        /// Inclusive structural depth ceiling.
        maximum: usize,
    },
    /// The canonical redactor failed.
    #[error("canonical observation redaction failed: {reason}")]
    CanonicalRedaction {
        /// Static reason from the upstream detector.
        reason: String,
    },
    /// The transient corpus failed to compile, so nothing was proven about the
    /// payload's transient content.
    #[error("transient detector corpus is unavailable")]
    TransientCorpusUnavailable,
    /// Sanitized bytes differ from source bytes with no finding attributing the
    /// change. Fail closed rather than mint a receipt nothing explains.
    #[error("sanitized bytes differ from source bytes with no attributed finding")]
    UnattributedRedaction,
    /// A trusted source attribution field could not be projected and
    /// restored without ambiguity. The typed entry point fails closed.
    #[error("trusted Claude source projection failed: {0}")]
    TrustedSourceProjection(&'static str),
    /// The extension set violated the provider observation boundary.
    #[error("observation extensions violate the provider boundary: {0}")]
    ExtensionBoundary(ApiError),
    /// A required extension has no hygiene handler and cannot remain inert.
    #[error("required observation extension at canonical index {index} is unsupported")]
    RequiredExtensionUnsupported {
        /// Canonical index in the ascending extension set.
        index: usize,
    },
    /// An extension payload was not valid JSON.
    #[error("observation extension at canonical index {index} is not valid JSON")]
    InvalidExtensionJson {
        /// Canonical index in the ascending extension set.
        index: usize,
    },
    /// An extension's claimed canonical bytes were not its canonical JSON encoding.
    #[error("observation extension at canonical index {index} is not canonical JSON")]
    NonCanonicalExtensionJson {
        /// Canonical index in the ascending extension set.
        index: usize,
    },
    /// The receipt could not be minted from an otherwise valid classification.
    #[error("sanitization receipt could not be minted: {0}")]
    Receipt(ApiError),
}

/// The outcome of running one payload through the admitted pipeline.
#[derive(Clone, Debug, PartialEq)]
pub enum ObservationAdmission {
    /// The payload may be delivered.
    Admitted {
        /// Provider-bound copy. The caller's input is untouched.
        sanitized: Value,
        /// Receipt binding these exact sanitized bytes to their source.
        receipt: PayloadSanitizationReceipt,
    },
    /// The payload must not be delivered.
    ///
    /// Canonical evidence is retained unchanged; only the provider-bound copy
    /// is discarded. The journal advances its replay cursor past the event on
    /// the strength of `receipt_id` and `source_payload_sha256`.
    Withheld {
        /// Which withholding rule fired.
        reason: WithheldReason,
        /// Stable identity of this withheld admission.
        receipt_id: String,
        /// Lowercase SHA-256 of the canonical source bytes, so the audit row
        /// always points back at untouched evidence.
        source_payload_sha256: String,
        /// Digest of the exact ordered extension set that was inspected.
        extensions_digest: String,
        /// Sanitizer and policy revision that made the withholding decision.
        sanitizer_revision: String,
        /// Number of canonical findings supporting the decision.
        finding_count: u32,
        /// Digest over the canonical findings supporting the decision.
        findings_digest: String,
    },
}

/// A Claude observation source identifier whose provider and complete structural
/// digest shape have been validated at the host boundary.
///
/// This type carries no authorization by itself. A caller must obtain it only
/// from the canonical record it attributes; the sanitizer uses it solely to
/// project the one typed attribution source field it recognizes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedClaudeObservationSourceIdV1(String);

impl TrustedClaudeObservationSourceIdV1 {
    /// Validates the exact Claude provider and source-id format.
    ///
    /// The source id must contain the complete pinned prefix followed by 64
    /// lowercase hexadecimal characters. No suffix, case folding, or arbitrary
    /// digest-shaped value is accepted. The constructor proves syntax only;
    /// source authority remains the caller's responsibility.
    #[must_use]
    pub fn from_validated_source(provider: &str, source_key: &str) -> Option<Self> {
        let digest = source_key.strip_prefix(CLAUDE_OBSERVATION_SOURCE_PREFIX)?;
        if provider != CLAUDE_PROVIDER_ID
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return None;
        }
        Some(Self(source_key.to_owned()))
    }

    /// Returns the validated source identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The admitted pipeline.
///
/// One sanitizer instance carries one policy revision. Every receipt it mints
/// records that revision, so a deployment can tell which table admitted a
/// payload without re-deriving it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationSanitizer {
    policy: ObservationHygienePolicyV1,
}

enum PayloadDecision {
    Admitted {
        source_payload_sha256: String,
        sanitized: Value,
        sanitized_payload_sha256: String,
        disposition: SanitizationDisposition,
        findings: Vec<HygieneFindingV1>,
    },
    Withheld {
        source_payload_sha256: String,
        findings: Vec<HygieneFindingV1>,
    },
}

#[derive(Clone, Debug)]
struct TrustedSourceProjection {
    payload: Value,
    placeholder: String,
    original: String,
}

/// The one attribution path a trusted source identifier may occupy.
const TRUSTED_SOURCE_PARENT: &str = "/source_identity/original_source/source";
const TRUSTED_SOURCE_PATH: &str = "/source_identity/original_source/source/source_key";

impl TrustedSourceProjection {
    fn new(
        source_payload: &Value,
        trusted_source: &TrustedClaudeObservationSourceIdV1,
    ) -> Result<Self, HygieneError> {
        let source_bytes = canonical_payload_bytes(source_payload)?;
        let mut payload = source_payload.clone();
        validate_trusted_source_field(source_payload, TRUSTED_SOURCE_PARENT, trusted_source)?;
        let placeholder = collision_free_placeholder(&source_bytes)?;
        replace_projected_value(
            &mut payload,
            TRUSTED_SOURCE_PATH,
            trusted_source.as_str(),
            &placeholder,
        )?;
        Ok(Self {
            payload,
            placeholder,
            original: trusted_source.as_str().to_owned(),
        })
    }

    fn payload(&self) -> &Value {
        &self.payload
    }

    fn restore(&self, sanitized: &mut Value) -> Result<(), HygieneError> {
        let Some(value) = sanitized.pointer_mut(TRUSTED_SOURCE_PATH) else {
            return Err(HygieneError::TrustedSourceProjection(
                "trusted source placeholder path disappeared",
            ));
        };
        if value.as_str() != Some(self.placeholder.as_str()) {
            return Err(HygieneError::TrustedSourceProjection(
                "trusted source placeholder changed during sanitization",
            ));
        }
        *value = Value::String(self.original.clone());
        Ok(())
    }
}

fn validate_trusted_source_field(
    payload: &Value,
    parent: &str,
    trusted_source: &TrustedClaudeObservationSourceIdV1,
) -> Result<(), HygieneError> {
    let provider_path = format!("{parent}/canonical_provider_id");
    let provider = payload.pointer(&provider_path).and_then(Value::as_str);
    if provider != Some(CLAUDE_PROVIDER_ID) {
        return Err(HygieneError::TrustedSourceProjection(
            "trusted source provider is not Claude",
        ));
    }
    let source_path = format!("{parent}/source_key");
    if payload.pointer(&source_path).and_then(Value::as_str) != Some(trusted_source.as_str()) {
        return Err(HygieneError::TrustedSourceProjection(
            "trusted source key does not match the validated identity",
        ));
    }
    Ok(())
}

fn replace_projected_value(
    payload: &mut Value,
    path: &str,
    expected: &str,
    placeholder: &str,
) -> Result<(), HygieneError> {
    let Some(value) = payload.pointer_mut(path) else {
        return Err(HygieneError::TrustedSourceProjection(
            "trusted source field path is missing",
        ));
    };
    if value.as_str() != Some(expected) {
        return Err(HygieneError::TrustedSourceProjection(
            "trusted source field changed before projection",
        ));
    }
    *value = Value::String(placeholder.to_owned());
    Ok(())
}

fn collision_free_placeholder(source_bytes: &[u8]) -> Result<String, HygieneError> {
    for attempt in 0..TRUSTED_SOURCE_PLACEHOLDER_ATTEMPTS {
        let candidate = format!("{TRUSTED_SOURCE_PLACEHOLDER_PREFIX}{attempt}");
        if !source_bytes
            .windows(candidate.len())
            .any(|window| window == candidate.as_bytes())
        {
            return Ok(candidate);
        }
    }
    Err(HygieneError::TrustedSourceProjection(
        "could not allocate a collision-free source placeholder",
    ))
}

impl ObservationSanitizer {
    /// Builds the sanitizer from the canonical product policy document.
    pub fn new() -> Result<Self, HygieneError> {
        Ok(Self {
            policy: ObservationHygienePolicyV1::canonical()?,
        })
    }

    /// Builds the sanitizer from an explicit table.
    #[must_use]
    pub fn with_policy(policy: ObservationHygienePolicyV1) -> Self {
        Self { policy }
    }

    /// Returns the sanitizer and policy revision this instance stamps on every
    /// receipt.
    #[must_use]
    pub fn revision(&self) -> &str {
        self.policy.revision()
    }

    /// Returns the class-to-action table in force.
    #[must_use]
    pub fn policy(&self) -> &ObservationHygienePolicyV1 {
        &self.policy
    }

    /// Classifies a payload without sanitizing it.
    ///
    /// Returns the canonical, deduplicated findings the *content* scan can see:
    /// credential material inside a string or an object key, and transient
    /// spans. A value whose object key proves it is a credential is invisible
    /// to a content scan, so [`HygieneClass::SensitiveField`] findings are
    /// attributed during [`ObservationSanitizer::admit`] instead and appear
    /// only in the receipt's count and digest.
    ///
    /// Findings carry a class, the action the policy takes, and a structural
    /// location — never any detected content.
    pub fn classify(&self, payload: &Value) -> Result<Vec<HygieneFindingV1>, HygieneError> {
        if !transient::corpus_is_available() {
            return Err(HygieneError::TransientCorpusUnavailable);
        }
        let mut found = Vec::new();
        let mut segments = Vec::new();
        let mut budget =
            ProbeBudget::new(self.policy.signals().maximum_detector_probes_per_payload());
        self.classify_value(payload, 0, &mut segments, &mut found, &mut budget)?;
        canonicalize(&mut found);
        Ok(found)
    }

    /// Runs one payload through the admitted pipeline with no extensions.
    ///
    /// `payload` is read through a shared reference and is never mutated: the
    /// provider-bound copy is a new value, so canonical evidence cannot be
    /// altered or deleted by admission.
    pub fn admit(&self, payload: &Value) -> Result<ObservationAdmission, HygieneError> {
        self.admit_observation(payload, &[])
    }

    /// Runs a payload and its exact opaque extension set through one admission.
    ///
    /// Optional extensions remain byte-for-byte unchanged and inert. Their
    /// canonical JSON is nevertheless scanned through the same hygiene policy as
    /// the root payload before the extension-set digest can enter a receipt. A
    /// required extension is rejected because this generic sanitizer has no
    /// extension-specific behavior to activate. If an optional extension would
    /// require redaction, the whole observation is withheld rather than silently
    /// mutating opaque bytes.
    pub fn admit_observation(
        &self,
        payload: &Value,
        extensions: &[OwnedOpaqueExtension],
    ) -> Result<ObservationAdmission, HygieneError> {
        self.admit_observation_inner(payload, extensions, None)
    }

    /// Runs a Claude observation envelope carrying host source attribution
    /// through a path-bound source projection before the unchanged strict
    /// hygiene pipeline.
    ///
    /// The typed source id is accepted only at the attribution source-key
    /// path. The original envelope remains borrowed and is used for the source
    /// and sanitized receipt digests after the field is verified and restored.
    /// Opaque extensions always use strict admission.
    pub fn admit_observation_with_trusted_source(
        &self,
        payload: &Value,
        extensions: &[OwnedOpaqueExtension],
        trusted_source: &TrustedClaudeObservationSourceIdV1,
    ) -> Result<ObservationAdmission, HygieneError> {
        let projection = TrustedSourceProjection::new(payload, trusted_source)?;
        self.admit_observation_inner(payload, extensions, Some(&projection))
    }

    fn admit_observation_inner(
        &self,
        payload: &Value,
        extensions: &[OwnedOpaqueExtension],
        trusted_projection: Option<&TrustedSourceProjection>,
    ) -> Result<ObservationAdmission, HygieneError> {
        if !transient::corpus_is_available() {
            return Err(HygieneError::TransientCorpusUnavailable);
        }
        let extensions_digest =
            observation_extensions_digest(extensions).map_err(HygieneError::ExtensionBoundary)?;
        let maximum_probes = self.policy.signals().maximum_detector_probes_per_payload();
        let mut classification_budget = ProbeBudget::new(maximum_probes);
        let mut transient_budget = ProbeBudget::new(maximum_probes);
        let root = match trusted_projection {
            Some(projection) => self.sanitize_payload_inner(
                projection.payload(),
                payload,
                Some(projection),
                &mut classification_budget,
                &mut transient_budget,
            )?,
            None => self.sanitize_payload_inner(
                payload,
                payload,
                None,
                &mut classification_budget,
                &mut transient_budget,
            )?,
        };
        let mut findings = match &root {
            PayloadDecision::Admitted { findings, .. }
            | PayloadDecision::Withheld { findings, .. } => findings.clone(),
        };
        let mut extension_requires_mutation = false;

        for (index, extension) in extensions.iter().enumerate() {
            if extension.required {
                return Err(HygieneError::RequiredExtensionUnsupported { index });
            }
            let extension_payload: Value = serde_json::from_slice(&extension.canonical_payload)
                .map_err(|_| HygieneError::InvalidExtensionJson { index })?;
            if canonical_payload_bytes(&extension_payload)? != extension.canonical_payload {
                return Err(HygieneError::NonCanonicalExtensionJson { index });
            }
            let decision = self.sanitize_payload(
                &extension_payload,
                &mut classification_budget,
                &mut transient_budget,
            )?;
            let extension_findings = match decision {
                PayloadDecision::Admitted {
                    disposition,
                    findings,
                    ..
                } => {
                    extension_requires_mutation |= disposition == SanitizationDisposition::Redacted;
                    findings
                }
                PayloadDecision::Withheld { findings, .. } => findings,
            };
            findings.extend(extension_findings.into_iter().map(|finding| {
                HygieneFindingV1::new(
                    finding.class(),
                    finding.action(),
                    extension_finding_location(index, finding.location()),
                )
            }));
        }
        canonicalize(&mut findings);

        let reason = withheld_reason(&findings)
            .or_else(|| extension_requires_mutation.then_some(WithheldReason::Quarantined));
        let (source_payload_sha256, admitted) = match root {
            PayloadDecision::Admitted {
                source_payload_sha256,
                sanitized,
                sanitized_payload_sha256,
                disposition,
                ..
            } => (
                source_payload_sha256,
                Some((sanitized, sanitized_payload_sha256, disposition)),
            ),
            PayloadDecision::Withheld {
                source_payload_sha256,
                ..
            } => (source_payload_sha256, None),
        };
        if let Some(reason) = reason {
            return Ok(self.withhold(reason, source_payload_sha256, extensions_digest, &findings));
        }
        let (sanitized, sanitized_payload_sha256, disposition) =
            admitted.ok_or(HygieneError::UnattributedRedaction)?;
        let receipt = PayloadSanitizationReceipt::new(PayloadSanitizationReceiptParts {
            sanitizer_revision: self.policy.revision().to_owned(),
            source_payload_sha256,
            sanitized_payload_sha256,
            extensions_digest,
            disposition,
            finding_count: finding_count(&findings),
            findings_digest: findings_digest(&findings),
        })
        .map_err(HygieneError::Receipt)?;
        Ok(ObservationAdmission::Admitted { sanitized, receipt })
    }

    /// Turns a structural refusal from [`ObservationSanitizer::admit_observation`]
    /// into the typed withheld terminal a mounted journey records for it.
    ///
    /// [`HygieneError::PayloadTooDeep`] and [`HygieneError::PayloadTooLarge`]
    /// say nothing about the payload's content: the walk never started. For a
    /// caller that has not yet settled the record that is the right answer —
    /// refuse it. For a journey replaying evidence the host *already* settled,
    /// an error is a stall: the replay cursor cannot advance past the record
    /// and the same refusal repeats on every open. This mints the audit row
    /// such a caller needs instead — reason
    /// [`WithheldReason::UnclassifiablePayload`], the source digest, zero
    /// findings — with the same identity derivation every other withheld
    /// admission uses, so the row can be re-derived after restart.
    ///
    /// Every other error is returned unchanged. A detector or corpus fault must
    /// keep failing closed on retry, and an extension-boundary or encoding
    /// fault names a caller bug, not a payload shape.
    pub fn withhold_unclassifiable(
        &self,
        payload: &Value,
        extensions: &[OwnedOpaqueExtension],
        error: HygieneError,
    ) -> Result<ObservationAdmission, HygieneError> {
        if !matches!(
            error,
            HygieneError::PayloadTooDeep { .. } | HygieneError::PayloadTooLarge { .. }
        ) {
            return Err(error);
        }
        let extensions_digest =
            observation_extensions_digest(extensions).map_err(HygieneError::ExtensionBoundary)?;
        let source_payload_sha256 = sha256_hex(&canonical_payload_bytes(payload)?);
        Ok(self.withhold(
            WithheldReason::UnclassifiablePayload,
            source_payload_sha256,
            extensions_digest,
            &[],
        ))
    }

    fn sanitize_payload(
        &self,
        payload: &Value,
        classification_budget: &mut ProbeBudget,
        transient_budget: &mut ProbeBudget,
    ) -> Result<PayloadDecision, HygieneError> {
        self.sanitize_payload_inner(
            payload,
            payload,
            None,
            classification_budget,
            transient_budget,
        )
    }

    fn sanitize_payload_inner(
        &self,
        scan_payload: &Value,
        source_payload: &Value,
        trusted_projection: Option<&TrustedSourceProjection>,
        classification_budget: &mut ProbeBudget,
        transient_budget: &mut ProbeBudget,
    ) -> Result<PayloadDecision, HygieneError> {
        let source_bytes = canonical_payload_bytes(source_payload)?;
        let maximum = self.policy.max_canonical_bytes();
        if source_bytes.len() > maximum {
            return Err(HygieneError::PayloadTooLarge { maximum });
        }
        let source_payload_sha256 = sha256_hex(&source_bytes);
        let mut found = Vec::new();
        let mut segments = Vec::new();
        self.classify_value(
            scan_payload,
            0,
            &mut segments,
            &mut found,
            classification_budget,
        )?;
        canonicalize(&mut found);
        if withheld_reason(&found).is_some() {
            return Ok(PayloadDecision::Withheld {
                source_payload_sha256,
                findings: found,
            });
        }

        let mut sanitized = match sanitize_memory_fact_payload(scan_payload.clone()) {
            Ok(MemoryFactSanitizationV1::Durable {
                payload: durable, ..
            }) => durable,
            Ok(MemoryFactSanitizationV1::Quarantined) => {
                found.push(HygieneFindingV1::new(
                    HygieneClass::CredentialBearingKey,
                    self.policy.action(HygieneClass::CredentialBearingKey),
                    render_path(&[]),
                ));
                canonicalize(&mut found);
                return Ok(PayloadDecision::Withheld {
                    source_payload_sha256,
                    findings: found,
                });
            }
            Err(error) => {
                return Err(HygieneError::CanonicalRedaction {
                    reason: error.to_string(),
                });
            }
        };
        if let Some(projection) = trusted_projection {
            projection.restore(&mut sanitized)?;
        }
        found.extend(attribute_sanitizer_output(
            &self.policy,
            source_payload,
            &sanitized,
        )?);
        apply_transient_redactions(
            &mut sanitized,
            &self.policy,
            "$",
            0,
            &mut found,
            transient_budget,
        )?;
        canonicalize(&mut found);
        if withheld_reason(&found).is_some() {
            return Ok(PayloadDecision::Withheld {
                source_payload_sha256,
                findings: found,
            });
        }

        let sanitized_bytes = canonical_payload_bytes(&sanitized)?;
        let sanitized_payload_sha256 = sha256_hex(&sanitized_bytes);
        let disposition = if sanitized_bytes == source_bytes {
            SanitizationDisposition::Accepted
        } else {
            SanitizationDisposition::Redacted
        };
        if disposition == SanitizationDisposition::Redacted
            && !found
                .iter()
                .any(|finding| finding.action().rewrites_payload())
        {
            return Err(HygieneError::UnattributedRedaction);
        }
        Ok(PayloadDecision::Admitted {
            source_payload_sha256,
            sanitized,
            sanitized_payload_sha256,
            disposition,
            findings: found,
        })
    }

    fn withhold(
        &self,
        reason: WithheldReason,
        source_payload_sha256: String,
        extensions_digest: String,
        found: &[HygieneFindingV1],
    ) -> ObservationAdmission {
        let receipt_id = withheld_receipt_id(
            self.policy.revision(),
            &source_payload_sha256,
            &extensions_digest,
            reason,
            finding_count(found),
            &findings_digest(found),
        );
        ObservationAdmission::Withheld {
            reason,
            receipt_id,
            source_payload_sha256,
            extensions_digest,
            sanitizer_revision: self.policy.revision().to_owned(),
            finding_count: finding_count(found),
            findings_digest: findings_digest(found),
        }
    }

    fn classify_value<'a>(
        &self,
        value: &'a Value,
        depth: usize,
        segments: &mut Vec<PathSegment<'a>>,
        found: &mut Vec<HygieneFindingV1>,
        budget: &mut ProbeBudget,
    ) -> Result<(), HygieneError> {
        if depth > MAX_STRUCTURAL_DEPTH {
            return Err(HygieneError::PayloadTooDeep {
                maximum: MAX_STRUCTURAL_DEPTH,
            });
        }
        match value {
            Value::String(text) => {
                let location = render_path(segments);
                self.classify_text(text, &location, found, budget);
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    segments.push(PathSegment::Index(index));
                    let outcome =
                        self.classify_value(item, depth.saturating_add(1), segments, found, budget);
                    segments.pop();
                    outcome?;
                }
            }
            Value::Object(map) => {
                for (key, child) in map {
                    // A key that is itself credential material must not be
                    // echoed into a finding — not into the finding on the key,
                    // and not into the location of any finding on a value
                    // nested beneath it. The marker is therefore substituted
                    // for the key before the walk descends, so nothing further
                    // down can reach the key text.
                    let classes = credentials::credential_classes(key, &self.policy, budget);
                    let segment = if classes.is_empty() {
                        PathSegment::Key(key.as_str())
                    } else {
                        let marker = credential_bearing_key_marker(key);
                        let location = render_key_location(segments, &marker);
                        for class in classes {
                            found.push(HygieneFindingV1::new(
                                class,
                                self.policy.action(class),
                                location.clone(),
                            ));
                        }
                        found.push(HygieneFindingV1::new(
                            HygieneClass::CredentialBearingKey,
                            self.policy.action(HygieneClass::CredentialBearingKey),
                            location,
                        ));
                        PathSegment::CredentialKey(marker)
                    };
                    segments.push(segment);
                    let outcome = self.classify_value(
                        child,
                        depth.saturating_add(1),
                        segments,
                        found,
                        budget,
                    );
                    segments.pop();
                    outcome?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
        Ok(())
    }

    fn classify_text(
        &self,
        text: &str,
        location: &str,
        found: &mut Vec<HygieneFindingV1>,
        budget: &mut ProbeBudget,
    ) {
        for class in credentials::credential_classes(text, &self.policy, budget) {
            found.push(HygieneFindingV1::new(
                class,
                self.policy.action(class),
                location.to_owned(),
            ));
        }
        for candidate in transient_matches(text) {
            found.push(HygieneFindingV1::new(
                candidate.class,
                self.policy.action(candidate.class),
                location.to_owned(),
            ));
        }
    }
}

/// Canonical JSON bytes every digest in the admission flow is taken over.
///
/// Object keys are sorted recursively and insignificant whitespace is dropped,
/// so two encodings of the same value are byte-identical and the sanitized
/// digest a receipt carries is reproducible by any verifier.
pub fn canonical_payload_bytes(payload: &Value) -> Result<Vec<u8>, HygieneError> {
    tracedecay_domain::canonical_json_bytes(payload).map_err(|_| HygieneError::CanonicalEncoding)
}

/// Derives the stable identity of a withheld admission.
#[must_use]
pub fn withheld_receipt_id(
    sanitizer_revision: &str,
    source_payload_sha256: &str,
    extensions_digest: &str,
    reason: WithheldReason,
    finding_count: u32,
    findings_digest: &str,
) -> String {
    derive_withheld_receipt_id(
        sanitizer_revision,
        source_payload_sha256,
        extensions_digest,
        reason,
        finding_count,
        findings_digest,
    )
}

fn extension_finding_location(index: usize, location: &str) -> String {
    let suffix = location.strip_prefix('$').unwrap_or(location);
    format!("$.extensions[{index}]{suffix}")
}

fn finding_count(found: &[HygieneFindingV1]) -> u32 {
    u32::try_from(found.len()).unwrap_or(u32::MAX)
}

fn withheld_reason(found: &[HygieneFindingV1]) -> Option<WithheldReason> {
    let strongest = found.iter().map(HygieneFindingV1::action).max()?;
    match strongest {
        HygieneAction::Reject => Some(WithheldReason::SecretRejected),
        HygieneAction::Quarantine => Some(WithheldReason::Quarantined),
        HygieneAction::Accept | HygieneAction::Annotate | HygieneAction::Redact => None,
    }
}

/// Attributes every byte the canonical redactor changed to a typed finding.
///
/// This is the diff-attribution half of [`ObservationSanitizer::admit`], split
/// out so the "the sanitizer changed something nothing explains" branch is
/// reachable from a test with a fabricated `sanitized` value. It is pure
/// analysis: it mints no receipt, produces no admission, and cannot be used to
/// deliver bytes, so exposing it opens no path around the pipeline.
///
/// Attribution is evidence-driven rather than assumed. The canonical redactor
/// announces itself: it substitutes one of a small set of fixed replacement
/// markers for the span it rewrote, and a replacement whose marker count rose
/// is proof of *which* detector fired. A difference with no such evidence is
/// [`HygieneError::UnattributedRedaction`] — the pipeline refuses to mint a
/// receipt whose finding list is a guess.
///
/// Note the redactor runs a wider detector profile than the classification
/// scan, so a class the scan did not see can legitimately appear here; when the
/// policy withholds for that class, [`ObservationSanitizer::admit`] discards
/// the redacted bytes rather than delivering them.
pub fn attribute_sanitizer_output(
    policy: &ObservationHygienePolicyV1,
    source: &Value,
    sanitized: &Value,
) -> Result<Vec<HygieneFindingV1>, HygieneError> {
    let mut found = Vec::new();
    let mut segments = Vec::new();
    let mut budget = ProbeBudget::new(policy.signals().maximum_detector_probes_per_payload());
    attribute_value(
        policy,
        source,
        sanitized,
        0,
        &mut segments,
        &mut found,
        &mut budget,
    )?;
    canonicalize(&mut found);
    Ok(found)
}

/// The fixed replacement markers `tracedecay_privacy`'s redactor writes,
/// paired with the class each one proves.
///
/// These are shared constants in effect but not in scope: the upstream
/// definitions are private to their module, and matching on them is the only
/// way to attribute a canonical redaction to a class without re-deriving the
/// detection. `transient_evidence.rs` and the false-positive corpus fail loudly
/// if the upstream spelling ever moves.
const REDACTION_MARKERS: [(&str, HygieneClass); 6] = [
    (REDACTED_SENSITIVE_FIELD, HygieneClass::SensitiveField),
    (
        "[TraceDecay redacted: credential assignment]",
        HygieneClass::CredentialAssignment,
    ),
    (
        "[TraceDecay redacted: exact credential]",
        HygieneClass::KnownCredentialPrefix,
    ),
    (
        "[TraceDecay redacted: bearer token]",
        HygieneClass::BearerToken,
    ),
    (
        "[TraceDecay redacted: private key]",
        HygieneClass::PrivateKey,
    ),
    (
        "[TraceDecay redacted: high-entropy token]",
        HygieneClass::HighEntropyToken,
    ),
];

fn attribute_value<'a>(
    policy: &ObservationHygienePolicyV1,
    source: &'a Value,
    sanitized: &'a Value,
    depth: usize,
    segments: &mut Vec<PathSegment<'a>>,
    found: &mut Vec<HygieneFindingV1>,
    budget: &mut ProbeBudget,
) -> Result<(), HygieneError> {
    if depth > MAX_STRUCTURAL_DEPTH {
        return Err(HygieneError::PayloadTooDeep {
            maximum: MAX_STRUCTURAL_DEPTH,
        });
    }
    if source == sanitized {
        return Ok(());
    }
    if let Value::String(after) = sanitized {
        let before = source.as_str().unwrap_or_default();
        let classes = introduced_marker_classes(before, after);
        if classes.is_empty() {
            return Err(HygieneError::UnattributedRedaction);
        }
        let location = render_path(segments);
        for class in classes {
            found.push(HygieneFindingV1::new(
                class,
                policy.action(class),
                location.clone(),
            ));
        }
        return Ok(());
    }
    match (source, sanitized) {
        (Value::Array(before), Value::Array(after)) if before.len() == after.len() => {
            for (index, (item, replacement)) in before.iter().zip(after.iter()).enumerate() {
                segments.push(PathSegment::Index(index));
                let outcome = attribute_value(
                    policy,
                    item,
                    replacement,
                    depth.saturating_add(1),
                    segments,
                    found,
                    budget,
                );
                segments.pop();
                outcome?;
            }
            Ok(())
        }
        (Value::Object(before), Value::Object(after)) if same_key_set(before, after) => {
            for (key, item) in before {
                let Some(replacement) = after.get(key) else {
                    return Err(HygieneError::UnattributedRedaction);
                };
                // The key may itself be credential material, so the descendant
                // path is opaque here for the same reason it is during
                // classification.
                segments.push(attribution_segment(policy, key, budget));
                let outcome = attribute_value(
                    policy,
                    item,
                    replacement,
                    depth.saturating_add(1),
                    segments,
                    found,
                    budget,
                );
                segments.pop();
                outcome?;
            }
            Ok(())
        }
        _ => Err(HygieneError::UnattributedRedaction),
    }
}

fn attribution_segment<'a>(
    policy: &ObservationHygienePolicyV1,
    key: &'a str,
    budget: &mut ProbeBudget,
) -> PathSegment<'a> {
    if credentials::credential_classes(key, policy, budget).is_empty() {
        PathSegment::Key(key)
    } else {
        PathSegment::CredentialKey(credential_bearing_key_marker(key))
    }
}

/// Returns the classes whose canonical replacement marker appears more often in
/// `after` than in `before`.
///
/// Counting rather than testing presence matters: a durable fact may legitimately
/// quote a redaction marker, and a payload that already contained one must not
/// be able to launder a fresh redaction as pre-existing text.
fn introduced_marker_classes(before: &str, after: &str) -> Vec<HygieneClass> {
    REDACTION_MARKERS
        .iter()
        .filter(|(marker, _)| after.matches(marker).count() > before.matches(marker).count())
        .map(|(_, class)| *class)
        .collect()
}

fn same_key_set(before: &Map<String, Value>, after: &Map<String, Value>) -> bool {
    before.len() == after.len() && before.keys().all(|key| after.contains_key(key))
}

fn apply_transient_redactions(
    value: &mut Value,
    policy: &ObservationHygienePolicyV1,
    path: &str,
    depth: usize,
    found: &mut Vec<HygieneFindingV1>,
    budget: &mut ProbeBudget,
) -> Result<(), HygieneError> {
    if depth > MAX_STRUCTURAL_DEPTH {
        return Err(HygieneError::PayloadTooDeep {
            maximum: MAX_STRUCTURAL_DEPTH,
        });
    }
    match value {
        Value::String(text) => {
            let candidates = transient_matches(text);
            // Right to left, so an earlier span's offsets stay valid.
            for candidate in candidates.iter().rev() {
                if !policy.action(candidate.class).rewrites_payload() {
                    continue;
                }
                let Some(replacement) = transient::replacement_for(candidate.class) else {
                    continue;
                };
                text.replace_range(candidate.span.clone(), replacement);
                found.push(HygieneFindingV1::new(
                    candidate.class,
                    HygieneAction::Redact,
                    path.to_owned(),
                ));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                apply_transient_redactions(
                    item,
                    policy,
                    &format!("{path}[{index}]"),
                    depth.saturating_add(1),
                    found,
                    budget,
                )?;
            }
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_path = match attribution_segment(policy, key, budget) {
                    PathSegment::Key(key) => format!("{path}.{key}"),
                    PathSegment::CredentialKey(marker) => format!("{path}.{marker}"),
                    PathSegment::Index(index) => format!("{path}[{index}]"),
                };
                apply_transient_redactions(
                    child,
                    policy,
                    &child_path,
                    depth.saturating_add(1),
                    found,
                    budget,
                )?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const STRUCTURAL_SOURCE_ID: &str = concat!(
        "tracedecay-claude-observation-source-v1-sha256-",
        "1d49a58eb1d460720a46c5afe048e2cb89856ad8a602b7ebb82eac181a0c54a6"
    );

    fn trusted_source() -> Result<TrustedClaudeObservationSourceIdV1, HygieneError> {
        TrustedClaudeObservationSourceIdV1::from_validated_source(
            CLAUDE_PROVIDER_ID,
            STRUCTURAL_SOURCE_ID,
        )
        .ok_or(HygieneError::TrustedSourceProjection(
            "test source id must satisfy the pinned Claude format",
        ))
    }

    fn attributed_envelope_with_structural_source_id() -> Value {
        let source = json!({
            "canonical_provider_id": "claude",
            "session_id": "fixture-session",
            "source_key": STRUCTURAL_SOURCE_ID,
            "observation_id": format!("sha256:{}", "1".repeat(64)),
        });
        json!({
            "observation_kind": "session.message_committed.v1",
            "payload_contract": "tracedecay.session.message.v1",
            "canonical_payload": {"role": "user", "content": "The retry budget changed."},
            "source_identity": {"original_source": {"source": source}},
        })
    }

    #[test]
    fn structural_digest_source_metadata_is_admitted_with_full_envelope_receipt()
    -> Result<(), HygieneError> {
        let envelope = attributed_envelope_with_structural_source_id();
        let trusted_source = trusted_source()?;
        let canonical = canonical_payload_bytes(&envelope)?;
        let expected = sha256_hex(&canonical);
        let ObservationAdmission::Admitted { sanitized, receipt } = ObservationSanitizer::new()?
            .admit_observation_with_trusted_source(&envelope, &[], &trusted_source)?
        else {
            panic!("innocent message and structural source metadata must be admitted");
        };
        assert_eq!(sanitized, envelope);
        assert_eq!(canonical_payload_bytes(&sanitized)?, canonical);
        assert_eq!(receipt.disposition(), SanitizationDisposition::Accepted);
        assert_eq!(receipt.source_payload_sha256(), expected);
        assert_eq!(receipt.sanitized_payload_sha256(), expected);
        assert_ne!(
            expected,
            sha256_hex(&canonical_payload_bytes(&envelope["canonical_payload"])?),
            "the receipt binds the whole delivered envelope, including source metadata"
        );
        Ok(())
    }

    #[test]
    fn strict_admission_withholds_the_raw_claude_source_id() -> Result<(), HygieneError> {
        let envelope = attributed_envelope_with_structural_source_id();
        let sanitizer = ObservationSanitizer::new()?;
        assert!(
            sanitizer
                .classify(&envelope)?
                .iter()
                .any(|finding| finding.class() == HygieneClass::HighEntropyToken)
        );
        assert!(matches!(
            sanitizer.admit_observation(&envelope, &[])?,
            ObservationAdmission::Withheld {
                reason: WithheldReason::SecretRejected,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn trusted_source_constructor_rejects_every_noncanonical_shape() {
        let digest = "1d49a58eb1d460720a46c5afe048e2cb89856ad8a602b7ebb82eac181a0c54a6";
        let prefix = "tracedecay-claude-observation-source-v1-sha256-";
        let invalid = [
            ("codex", format!("{prefix}{digest}")),
            ("claude", format!("{prefix}{}", digest.to_ascii_uppercase())),
            ("claude", format!("{prefix}{}", &digest[..63])),
            ("claude", format!("{prefix}{digest}0")),
            ("claude", format!("{prefix}{}g", &digest[..63])),
            ("claude", format!("{prefix}{digest}-tail")),
            ("claude", format!("{prefix}{digest}-sha256-{digest}")),
            ("claude", format!("-sha256-{digest}")),
        ];
        for (provider, source_key) in invalid {
            assert!(
                TrustedClaudeObservationSourceIdV1::from_validated_source(provider, &source_key)
                    .is_none(),
                "invalid trusted source shape was accepted: {provider}/{source_key}"
            );
        }
    }

    #[test]
    fn trusted_source_projection_is_collision_free_and_restores_the_field()
    -> Result<(), HygieneError> {
        let mut envelope = attributed_envelope_with_structural_source_id();
        envelope["collision_a"] = json!("td-trusted-source-v1-0");
        envelope["collision_b"] = json!("td-trusted-source-v1-1");
        let trusted_source = trusted_source()?;
        let projection = TrustedSourceProjection::new(&envelope, &trusted_source)?;
        assert_eq!(
            projection
                .payload()
                .pointer("/source_identity/original_source/source/source_key")
                .and_then(Value::as_str),
            Some("td-trusted-source-v1-2")
        );
        let mut restored = projection.payload().clone();
        projection.restore(&mut restored)?;
        assert_eq!(restored, envelope);
        Ok(())
    }

    #[test]
    fn trusted_source_does_not_exempt_matching_content_or_high_entropy_suffixes()
    -> Result<(), HygieneError> {
        let trusted_source = trusted_source()?;
        let sanitizer = ObservationSanitizer::new()?;
        let high_entropy_prefix = "Qm9vZ2llV29vZ2llMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A4OTc2NTQzMjE";
        for content in [
            STRUCTURAL_SOURCE_ID.to_owned(),
            format!("{high_entropy_prefix}-sha256-{}", "a".repeat(64)),
        ] {
            let mut envelope = attributed_envelope_with_structural_source_id();
            envelope["canonical_payload"]["content"] = json!(content);
            let trusted =
                sanitizer.admit_observation_with_trusted_source(&envelope, &[], &trusted_source)?;
            // The projection exempts exactly the attribution field: the same
            // content without any attribution decides identically.
            let mut unattributed = envelope.clone();
            if let Some(object) = unattributed.as_object_mut() {
                object.remove("source_identity");
            }
            let strict = sanitizer.admit_observation(&unattributed, &[])?;
            match (&trusted, &strict) {
                (
                    ObservationAdmission::Withheld { reason, .. },
                    ObservationAdmission::Withheld {
                        reason: strict_reason,
                        ..
                    },
                ) => assert_eq!(reason, strict_reason),
                (
                    ObservationAdmission::Admitted { sanitized, .. },
                    ObservationAdmission::Admitted {
                        sanitized: strict_sanitized,
                        ..
                    },
                ) => assert_eq!(
                    sanitized.get("canonical_payload"),
                    strict_sanitized.get("canonical_payload")
                ),
                _ => panic!("trusted attribution changed the content decision: {content}"),
            }
            if content == STRUCTURAL_SOURCE_ID {
                assert!(matches!(
                    trusted,
                    ObservationAdmission::Withheld {
                        reason: WithheldReason::SecretRejected,
                        ..
                    }
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn trusted_source_rejects_a_wrong_provider_or_an_unattributed_envelope()
    -> Result<(), HygieneError> {
        let trusted_source = trusted_source()?;
        let sanitizer = ObservationSanitizer::new()?;

        let mut wrong_provider = attributed_envelope_with_structural_source_id();
        wrong_provider["source_identity"]["original_source"]["source"]["canonical_provider_id"] =
            json!("codex");
        assert!(matches!(
            sanitizer.admit_observation_with_trusted_source(&wrong_provider, &[], &trusted_source),
            Err(HygieneError::TrustedSourceProjection(_))
        ));

        let mut unattributed = attributed_envelope_with_structural_source_id();
        if let Some(object) = unattributed.as_object_mut() {
            object.remove("source_identity");
        }
        assert!(matches!(
            sanitizer.admit_observation_with_trusted_source(&unattributed, &[], &trusted_source),
            Err(HygieneError::TrustedSourceProjection(_))
        ));
        Ok(())
    }

    #[test]
    fn structural_digest_suffixes_do_not_hide_known_credentials_or_payload_secrets()
    -> Result<(), HygieneError> {
        // Reuse the inert credential-shaped fixture from the secret-class tests.
        let secret = concat!("ghp_", "KsY7QwT2mZ4bV9nR6cX1jH8pL3dG5fA0eUwQ");
        let digest = "a".repeat(64);
        let sanitizer = ObservationSanitizer::new()?;
        for (in_payload, value) in [
            (false, secret.to_owned()),
            (false, format!("fixture-{secret}")),
            (false, format!("{secret}-sha256-{digest}")),
            (false, format!("fixture-{secret}-sha256-{digest}")),
            (true, secret.to_owned()),
        ] {
            let mut envelope = attributed_envelope_with_structural_source_id();
            if in_payload {
                envelope["canonical_payload"]["content"] = json!(value);
            } else {
                envelope["source_identity"]["original_source"]["source"]["source_key"] =
                    json!(value);
            }
            assert!(
                sanitizer
                    .classify(&envelope)?
                    .iter()
                    .any(|finding| { finding.class() == HygieneClass::KnownCredentialPrefix }),
                "known credential rules must still inspect the complete envelope"
            );
            assert!(matches!(
                sanitizer.admit_observation(&envelope, &[])?,
                ObservationAdmission::Withheld {
                    reason: WithheldReason::SecretRejected,
                    ..
                }
            ));
        }
        Ok(())
    }

    /// Every ceiling hygiene enforces as an *error* must dominate the ceiling
    /// the canonical store enforces on the record it wraps, or a settled
    /// record could be refused as an admission fault instead of classified.
    /// The depth ceiling is checked at compile time next to its definition;
    /// the byte ceiling lives in the policy document, so it is checked here.
    #[test]
    fn hygiene_byte_ceiling_dominates_canonical_store_record_ceiling() -> Result<(), PolicyError> {
        let policy = ObservationHygienePolicyV1::canonical()?;
        // A full 1 MiB record plus the provider envelope wrapped around it
        // must still fit under the hygiene ceiling with generous headroom.
        assert!(
            policy.max_canonical_bytes()
                >= tracedecay_domain::MAX_OBSERVATION_RECORD_BYTES + 64 * 1024,
            "hygiene byte ceiling {} does not clear the store record ceiling {}",
            policy.max_canonical_bytes(),
            tracedecay_domain::MAX_OBSERVATION_RECORD_BYTES
        );
        Ok(())
    }

    #[test]
    fn transient_pass_masks_credential_bearing_ancestor_keys() -> Result<(), HygieneError> {
        let key = concat!("AKIA", "4S27TQXBVCZ5MJ6L");
        let mut payload = json!({ key: { "note": "server started with pid 48213" } });
        let policy = ObservationHygienePolicyV1::canonical()?;
        let mut findings = Vec::new();
        let mut budget = ProbeBudget::new(policy.signals().maximum_detector_probes_per_payload());

        apply_transient_redactions(&mut payload, &policy, "$", 0, &mut findings, &mut budget)?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class(), HygieneClass::TransientProcessId);
        assert_eq!(
            findings[0].location(),
            format!("$.{}.note", credential_bearing_key_marker(key))
        );
        assert!(!findings[0].location().contains(key));
        Ok(())
    }

    #[test]
    fn transient_pass_enforces_the_structural_depth_limit() -> Result<(), HygieneError> {
        let policy = ObservationHygienePolicyV1::canonical()?;
        let mut payload = json!("leaf");
        for _ in 0..(MAX_STRUCTURAL_DEPTH + 2) {
            payload = Value::Array(vec![payload]);
        }
        let mut findings = Vec::new();
        let mut budget = ProbeBudget::new(policy.signals().maximum_detector_probes_per_payload());

        assert!(matches!(
            apply_transient_redactions(&mut payload, &policy, "$", 0, &mut findings, &mut budget,),
            Err(HygieneError::PayloadTooDeep {
                maximum: MAX_STRUCTURAL_DEPTH
            })
        ));
        Ok(())
    }
}
