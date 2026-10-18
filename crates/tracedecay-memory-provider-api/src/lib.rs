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
//! Provider-neutral runtime boundary for TraceDecay cognitive memory.
//!
//! The canonical JSON contracts remain the sole wire authority. This crate
//! exposes those generated values plus owned runtime identities, exact coding
//! scope, live cancellation, bounded operation envelopes, typed terminal
//! results, and the object-safe provider trait used by orchestration and
//! adapters. It contains no provider implementation, transport, persistence,
//! TraceDecay database, code-index, daemon, dashboard, or host dependency.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[rustfmt::skip]
#[path = "../../../product/contracts/memory-provider-v1/generated/rust/memory_provider_v1.rs"]
/// Generated dependency-free values from the canonical Memory Provider V1 contracts.
pub mod contract;

mod advisory;
mod advisory_admission;
mod context_delivery;
mod hygiene;

pub use advisory::{
    AdvisoryContractError, CurrentSourceDisposition, GrantedHistorySource, HistoryGrant,
    LifecycleTarget, LifecycleTargetReference, OriginScopeEvidence, OriginalSourceIdentity,
    OwnedRecallExclusions, OwnedTemporalQuery, RecordedValidity, ReplayAccounting,
    RestoreDispositionCheckpoint, SourceAttribution, TemporalEligibility,
};

pub use advisory_admission::{
    AdvisoryAdmissionAuthority, AdvisoryAdmissionError, AdvisoryCallBinding,
    CurrentAdvisoryAdmission, CurrentRestoreAdmission, MAX_ADVISORY_ADMISSION_SOURCES,
};

pub use context_delivery::{
    NATIVE_CONTEXT_DELIVERY_OPERATION_ID, NATIVE_CONTEXT_DELIVERY_ROUTE_ID,
    NativeContextDeliveryMarker,
};

pub use hygiene::{
    OBSERVATION_HYGIENE_RECEIPT_ID_PREFIX, OBSERVATION_HYGIENE_WITHHELD_ID_PREFIX,
    PayloadSanitizationReceipt, PayloadSanitizationReceiptParts, SANITIZER_REVISION_MAX_BYTES,
    SanitizationDisposition, WithheldReason, derive_withheld_receipt_id, empty_findings_digest,
};

use contract::{
    CancellationState, CapabilityId, CommittedEffectExpectation, CommittedEffectState,
    ExactScopeIdentity, FallbackEligibility, IdentifierError, OpaqueExtension, RequestControl,
    TerminalCode,
};

/// Maximum aggregate committed and uncommitted item references retained by one
/// terminal effect. This matches the canonical observation-batch maximum.
pub const MAX_COMMITTED_EFFECT_ITEM_REFS: usize = 4_096;

/// Maximum UTF-8 bytes in one opaque provider-local effect item reference.
pub const MAX_COMMITTED_EFFECT_ITEM_REF_BYTES: usize = contract::TERMINAL_EFFECT_ITEM_REF_MAX_BYTES;

/// Canonical action attached to typed uncertain-dispatch reconciliation
/// receipts created by [`CommittedEffectEvidence::unknown_from_reconciliation_digest`].
pub const UNKNOWN_EFFECT_RECONCILIATION_ACTION: &str = "reconcile.provider-effect.v1";

const INTERNAL_FAILURE_OPERATION_ID: &str = "tracedecay.internal-failure.operation.v1";
const INTERNAL_FAILURE_DIAGNOSTIC_ID: &str = "tracedecay.memory.provider.internal-failure.v1";
const INVALID_EXACT_SCOPE_SHA256: &str =
    "ef2d127de37b942baad06145e54b0c6195a6ef9e5a3124a29e1d5074f6604f12";

fn deadline_duration(remaining_millis: u64) -> Duration {
    if remaining_millis == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(remaining_millis.saturating_sub(1))
        .checked_add(Duration::from_nanos(1))
        .unwrap_or(Duration::MAX)
}

fn saturating_instant_add(start: Instant, duration: Duration) -> Instant {
    // There is no portable public `Instant::MAX`. If a platform cannot
    // represent the requested finite budget, fail closed at the operation
    // start rather than wrapping or accidentally extending the deadline.
    start.checked_add(duration).unwrap_or(start)
}

fn classify_snapshot(
    cancellation_at: Option<Instant>,
    now: Instant,
    deadline_at: Instant,
    live_remaining_millis: Option<u64>,
) -> Result<u64, TerminalCode> {
    if let Some(cancellation_at) = cancellation_at {
        // Compare the event itself, never a possibly stale `now` observation.
        // Equality is intentionally cancellation-wins for a zero-budget tie.
        return if cancellation_at <= deadline_at {
            Err(TerminalCode::Cancelled)
        } else {
            Err(TerminalCode::DeadlineExceeded)
        };
    }
    if now >= deadline_at {
        return Err(TerminalCode::DeadlineExceeded);
    }
    live_remaining_millis.ok_or(TerminalCode::DeadlineExceeded)
}

/// Stable API validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiError {
    /// A provider identifier did not satisfy the canonical generated validator.
    InvalidProviderId(IdentifierError),
    /// A capability or versioned contract identifier was invalid.
    InvalidVersionedId(IdentifierError),
    /// A required string field was empty.
    EmptyField(&'static str),
    /// A lowercase SHA-256 digest was malformed.
    InvalidSha256(&'static str),
    /// A capability was declared more than once.
    DuplicateCapability(String),
    /// A mandatory capability was absent from a provider descriptor.
    MandatoryCapabilityMissing(&'static str),
    /// A finite limit was zero.
    ZeroLimit(&'static str),
    /// A finite limit was below the canonical handshake catalog minimum.
    LimitBelowMinimum {
        /// Stable limit identifier.
        limit: &'static str,
        /// Canonical inclusive minimum.
        minimum: u64,
    },
    /// A finite limit exceeded the canonical handshake catalog maximum.
    LimitExceedsMaximum {
        /// Stable limit identifier.
        limit: &'static str,
        /// Canonical inclusive maximum.
        maximum: u64,
    },
    /// Generated limit catalog shape did not match the runtime fields.
    InvalidLimitCatalog,
    /// A provider descriptor declared a protocol version other than V1.0.
    IncompatibleProtocol {
        /// Declared protocol major.
        major: u16,
        /// Declared protocol minor.
        minor: u16,
    },
    /// A mutating operation lacked a deterministic idempotency key.
    MissingIdempotencyKey,
    /// An accepted provider registration revision was zero.
    InvalidRegistrationRevision,
    /// The operation capability was not present in the request requirements.
    MissingOperationCapability(&'static str),
    /// An opaque extension version was zero.
    InvalidExtensionVersion,
    /// Opaque extensions were not in canonical ascending, duplicate-free order.
    UnorderedExtensions,
    /// Canonical bytes no longer matched their declared SHA-256 digest.
    ContentDigestMismatch(&'static str),
    /// A bounded collection exceeded its maximum item count.
    TooManyBoundaryItems {
        /// Stable collection identity.
        field: &'static str,
        /// Maximum item count accepted.
        maximum: usize,
    },
    /// Canonical boundary content exceeded its byte ceiling.
    BoundaryBytesExceeded {
        /// Stable content identity.
        field: &'static str,
        /// Maximum bytes accepted.
        maximum: u64,
    },
    /// A terminal code carried a result payload it cannot admit.
    PayloadForbiddenForTerminal {
        /// Closed terminal code.
        terminal_code: TerminalCode,
    },
    /// A committed-effect generation pair was incomplete or regressed.
    InvalidEffectGenerations,
    /// A committed-effect field combination contradicted its state.
    InvalidCommittedEffect(&'static str),
    /// A committed-effect item reference exceeded its byte limit.
    EffectItemRefTooLong {
        /// Maximum UTF-8 bytes accepted for one item reference.
        maximum: usize,
    },
    /// The aggregate committed-effect item-reference count exceeded its limit.
    TooManyEffectItemRefs {
        /// Maximum aggregate reference count.
        maximum: usize,
    },
    /// A committed-effect item reference was duplicated.
    DuplicateEffectItemRef(String),
    /// A reference appeared in both committed and uncommitted partitions.
    OverlappingEffectItemRef(String),
    /// A pinned fallback policy revision was zero.
    InvalidFallbackPolicyRevision,
    /// A fallback policy selected the provider that produced the terminal.
    FallbackTargetMatchesCurrentProvider,
    /// A terminal code contradicted its committed-effect state.
    TerminalEffectMismatch {
        /// Closed terminal code.
        terminal_code: TerminalCode,
        /// Supplied committed-effect state.
        effect_state: CommittedEffectState,
    },
    /// A terminal code contradicted its fallback directive.
    TerminalFallbackMismatch {
        /// Closed terminal code.
        terminal_code: TerminalCode,
        /// Supplied fallback eligibility.
        eligibility: FallbackEligibility,
    },
    /// A failure terminal did not carry a stable diagnostic identity.
    MissingFailureDiagnostic,
    /// The generated terminal policy catalog did not contain a closed code.
    InvalidTerminalPolicyCatalog,
    /// A terminal text field was not bounded canonical text.
    NonCanonicalTerminalText(&'static str),
    /// A terminal text field exceeded its conservative API byte bound.
    TerminalTextTooLong {
        /// Stable field identity.
        field: &'static str,
        /// Maximum UTF-8 bytes accepted.
        maximum: usize,
    },
    /// A duplicate acknowledgement named an idempotency key other than the one
    /// on the request it answered, so it does not prove *this* mutation was
    /// already delivered.
    DuplicateEffectKeyMismatch,
    /// A duplicate acknowledgement was built for a call that carries no
    /// idempotency key, so there is nothing for it to deduplicate.
    DuplicateEffectWithoutRequestKey,
    /// A read-only provider operation claimed a committed effect.
    ReadOnlyOperationEffect {
        /// Read-only operation.
        operation: ProviderOperation,
        /// Invalid effect state.
        effect_state: CommittedEffectState,
    },
    /// A fallback directive was built for a provider other than the terminal provider.
    FallbackSourceProviderMismatch,
    /// An observation reached the dispatch boundary without a sanitization
    /// receipt, so nothing proves it passed secret and transient hygiene.
    UnsanitizedObservation,
    /// A sanitization receipt no longer matched its derived identifier.
    SanitizationReceiptTampered,
    /// A sanitization receipt described bytes other than the payload being
    /// dispatched.
    SanitizationReceiptUnbound,
    /// A sanitizer revision label was empty, oversized, or non-canonical.
    InvalidSanitizerRevision,
    /// An accepted receipt claimed delivered bytes that differ from source.
    SanitizationAcceptedPayloadModified,
    /// A redacted receipt claimed delivered bytes identical to source.
    SanitizationRedactedPayloadUnmodified,
    /// A persisted sanitization receipt could not be parsed back.
    MalformedSanitizationReceiptJson(&'static str),
    /// A once-delivered Native context marker did not match the host-selected
    /// registration, exact scope, or canonical request.
    NativeContextDeliveryBindingMismatch(&'static str),
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProviderId(error) => write!(formatter, "invalid provider id: {error}"),
            Self::InvalidVersionedId(error) => {
                write!(formatter, "invalid versioned identifier: {error}")
            }
            Self::EmptyField(field) => write!(formatter, "required field {field} is empty"),
            Self::InvalidSha256(field) => {
                write!(formatter, "field {field} is not lowercase SHA-256 hex")
            }
            Self::DuplicateCapability(capability) => {
                write!(formatter, "capability {capability} is duplicated")
            }
            Self::MandatoryCapabilityMissing(capability) => {
                write!(formatter, "mandatory capability {capability} is missing")
            }
            Self::ZeroLimit(limit) => write!(formatter, "finite limit {limit} is zero"),
            Self::LimitBelowMinimum { limit, minimum } => {
                write!(formatter, "finite limit {limit} is below minimum {minimum}")
            }
            Self::LimitExceedsMaximum { limit, maximum } => {
                write!(formatter, "finite limit {limit} exceeds maximum {maximum}")
            }
            Self::InvalidLimitCatalog => {
                formatter.write_str("generated provider limit catalog is incompatible")
            }
            Self::IncompatibleProtocol { major, minor } => {
                write!(formatter, "provider protocol {major}.{minor} is not V1.0")
            }
            Self::MissingIdempotencyKey => {
                formatter.write_str("mutating operation has no idempotency key")
            }
            Self::InvalidRegistrationRevision => {
                formatter.write_str("provider registration revision must be positive")
            }
            Self::MissingOperationCapability(capability) => {
                write!(
                    formatter,
                    "operation requires undeclared capability {capability}"
                )
            }
            Self::InvalidExtensionVersion => {
                formatter.write_str("opaque extension version must be positive")
            }
            Self::UnorderedExtensions => formatter.write_str(
                "opaque extensions must be in ascending, duplicate-free extension-id order",
            ),
            Self::ContentDigestMismatch(field) => {
                write!(
                    formatter,
                    "field {field} does not match its canonical bytes"
                )
            }
            Self::TooManyBoundaryItems { field, maximum } => {
                write!(formatter, "boundary field {field} exceeds {maximum} items")
            }
            Self::BoundaryBytesExceeded { field, maximum } => {
                write!(formatter, "boundary field {field} exceeds {maximum} bytes")
            }
            Self::PayloadForbiddenForTerminal { terminal_code } => write!(
                formatter,
                "terminal {} forbids a result payload",
                terminal_code.as_wire()
            ),
            Self::InvalidEffectGenerations => {
                formatter.write_str("committed-effect generations are incomplete or regressed")
            }
            Self::InvalidCommittedEffect(reason) => {
                write!(formatter, "invalid committed-effect evidence: {reason}")
            }
            Self::EffectItemRefTooLong { maximum } => {
                write!(
                    formatter,
                    "committed-effect item reference exceeds {maximum} bytes"
                )
            }
            Self::TooManyEffectItemRefs { maximum } => {
                write!(
                    formatter,
                    "committed-effect item references exceed {maximum}"
                )
            }
            Self::DuplicateEffectItemRef(item_ref) => {
                write!(
                    formatter,
                    "committed-effect item reference {item_ref} is duplicated"
                )
            }
            Self::OverlappingEffectItemRef(item_ref) => {
                write!(
                    formatter,
                    "effect partitions both contain item reference {item_ref}"
                )
            }
            Self::InvalidFallbackPolicyRevision => {
                formatter.write_str("fallback policy revision must be positive")
            }
            Self::FallbackTargetMatchesCurrentProvider => {
                formatter.write_str("fallback target must differ from the current provider")
            }
            Self::TerminalEffectMismatch {
                terminal_code,
                effect_state,
            } => write!(
                formatter,
                "terminal {} forbids committed-effect state {}",
                terminal_code.as_wire(),
                effect_state.as_wire()
            ),
            Self::TerminalFallbackMismatch {
                terminal_code,
                eligibility,
            } => write!(
                formatter,
                "terminal {} forbids fallback eligibility {}",
                terminal_code.as_wire(),
                eligibility.as_wire()
            ),
            Self::MissingFailureDiagnostic => {
                formatter.write_str("failure terminal requires a diagnostic identity")
            }
            Self::InvalidTerminalPolicyCatalog => {
                formatter.write_str("generated terminal policy catalog is incomplete")
            }
            Self::NonCanonicalTerminalText(field) => {
                write!(formatter, "terminal field {field} is not canonical text")
            }
            Self::TerminalTextTooLong { field, maximum } => {
                write!(formatter, "terminal field {field} exceeds {maximum} bytes")
            }
            Self::DuplicateEffectKeyMismatch => formatter.write_str(
                "duplicate committed effect names an idempotency key other than the request's",
            ),
            Self::DuplicateEffectWithoutRequestKey => formatter.write_str(
                "duplicate committed effect requires a request idempotency key to deduplicate",
            ),
            Self::ReadOnlyOperationEffect {
                operation,
                effect_state,
            } => write!(
                formatter,
                "read-only operation {} forbids committed-effect state {}",
                operation.as_wire(),
                effect_state.as_wire()
            ),
            Self::FallbackSourceProviderMismatch => {
                formatter.write_str("fallback directive source does not match terminal provider")
            }
            Self::UnsanitizedObservation => {
                formatter.write_str("observation call carries no sanitization receipt")
            }
            Self::SanitizationReceiptTampered => {
                formatter.write_str("sanitization receipt does not match its derived identifier")
            }
            Self::SanitizationReceiptUnbound => {
                formatter.write_str("sanitization receipt does not bind the dispatched payload")
            }
            Self::InvalidSanitizerRevision => {
                formatter.write_str("sanitizer revision is empty, oversized, or non-canonical")
            }
            Self::SanitizationAcceptedPayloadModified => {
                formatter.write_str("accepted sanitization receipt reports modified bytes")
            }
            Self::SanitizationRedactedPayloadUnmodified => {
                formatter.write_str("redacted sanitization receipt reports unmodified bytes")
            }
            Self::MalformedSanitizationReceiptJson(part) => {
                write!(
                    formatter,
                    "sanitization receipt json is malformed at {part}"
                )
            }
            Self::NativeContextDeliveryBindingMismatch(field) => write!(
                formatter,
                "once-delivered Native context marker does not match host binding {field}"
            ),
        }
    }
}

impl Error for ApiError {}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ApiError> {
    if value.is_empty() {
        Err(ApiError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn require_bounded_canonical_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), ApiError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ApiError::NonCanonicalTerminalText(field));
    }
    if value.len() > maximum {
        return Err(ApiError::TerminalTextTooLong { field, maximum });
    }
    Ok(())
}

fn normalized_terminal_text(value: &str, maximum: usize, fallback: &'static str) -> String {
    if require_bounded_canonical_text(value, "normalized_terminal_text", maximum).is_ok() {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_sha256(value: &str, field: &'static str) -> Result<(), ApiError> {
    if is_lowercase_sha256(value) {
        Ok(())
    } else {
        Err(ApiError::InvalidSha256(field))
    }
}

fn require_tagged_sha256(value: &str, field: &'static str) -> Result<(), ApiError> {
    value
        .strip_prefix("sha256:")
        .ok_or(ApiError::InvalidSha256(field))
        .and_then(|digest| require_sha256(digest, field))
}

fn lowercase_sha256_hex(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len().saturating_mul(2));
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Owned stable logical provider identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnedProviderId(String);

impl OwnedProviderId {
    /// Validates and owns a canonical provider ID.
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        contract::ProviderId::new(&value).map_err(ApiError::InvalidProviderId)?;
        Ok(Self(value))
    }

    /// Returns the canonical provider ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Owned stable versioned capability or contract identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnedVersionedId(String);

impl OwnedVersionedId {
    /// Validates and owns a canonical versioned ID.
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        CapabilityId::new(&value).map_err(ApiError::InvalidVersionedId)?;
        Ok(Self(value))
    }

    /// Returns the canonical versioned identity.
    ///
    /// Syntactically valid IDs outside the generated capability catalog are
    /// retained verbatim. Catalog membership is checked separately by
    /// [`ProviderDescriptor::supports`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact TraceDecay-owned coding scope in owned runtime form.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OwnedExactScope {
    /// Profile authority identity.
    pub profile_id: String,
    /// Project authority identity.
    pub project_id: String,
    /// Repository authority identity.
    pub repository_identity: String,
    /// Exact linked-worktree identity.
    pub worktree_identity: String,
    /// Exact branch or detached-reference identity.
    pub branch_identity: String,
    /// Exact coding-agent session identity.
    pub agent_session_id: String,
    /// Canonical digest copied from the authoritative project-open resolved scope.
    pub resolved_scope_digest: String,
}

impl OwnedExactScope {
    /// Validates one complete exact coding scope.
    pub fn new(
        profile_id: impl Into<String>,
        project_id: impl Into<String>,
        repository_identity: impl Into<String>,
        worktree_identity: impl Into<String>,
        branch_identity: impl Into<String>,
        agent_session_id: impl Into<String>,
        resolved_scope_digest: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let scope = Self {
            profile_id: profile_id.into(),
            project_id: project_id.into(),
            repository_identity: repository_identity.into(),
            worktree_identity: worktree_identity.into(),
            branch_identity: branch_identity.into(),
            agent_session_id: agent_session_id.into(),
            resolved_scope_digest: resolved_scope_digest.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Revalidates all six exact-scope identities after assembly or mutation.
    pub fn validate(&self) -> Result<(), ApiError> {
        require_non_empty(&self.profile_id, "profile_id")?;
        require_non_empty(&self.project_id, "project_id")?;
        require_non_empty(&self.repository_identity, "repository_identity")?;
        require_non_empty(&self.worktree_identity, "worktree_identity")?;
        require_non_empty(&self.branch_identity, "branch_identity")?;
        require_non_empty(&self.agent_session_id, "agent_session_id")?;
        require_tagged_sha256(&self.resolved_scope_digest, "resolved_scope_digest")?;
        Ok(())
    }

    /// Borrows the generated exact-scope representation.
    #[must_use]
    pub fn borrowed(&self) -> ExactScopeIdentity<'_> {
        ExactScopeIdentity {
            profile_id: &self.profile_id,
            project_id: &self.project_id,
            repository_identity: &self.repository_identity,
            worktree_identity: &self.worktree_identity,
            branch_identity: &self.branch_identity,
            agent_session_id: &self.agent_session_id,
            resolved_scope_digest: &self.resolved_scope_digest,
        }
    }

    /// Returns the host's stable deletion key for a canonical source session
    /// within this complete exact scope.
    #[must_use]
    pub fn session_forget_source_key(&self, session_id: &str) -> String {
        format!("session:{}:{session_id}", self.exact_scope_sha256())
    }

    /// Returns the canonical TraceDecay-owned digest of the complete exact
    /// scope. Provider-local namespaces must use a distinct derivation.
    #[must_use]
    pub fn exact_scope_sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(contract::EXACT_SCOPE_DIGEST_DOMAIN);
        for value in [
            self.profile_id.as_bytes(),
            self.project_id.as_bytes(),
            self.repository_identity.as_bytes(),
            self.worktree_identity.as_bytes(),
            self.branch_identity.as_bytes(),
            self.agent_session_id.as_bytes(),
            self.resolved_scope_digest.as_bytes(),
        ] {
            digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(value);
        }
        let value = digest.finalize();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(value.len().saturating_mul(2));
        for byte in value {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

/// Thread-safe cooperative cancellation signal.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<Mutex<Option<Instant>>>);

impl CancellationToken {
    /// Creates a live cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the token cancelled and retains the first monotonic cancellation
    /// event. Repeated cancellation is idempotent.
    ///
    /// The lock/store of the first timestamp is the cancellation linearization
    /// point. Losing clones observe the same stored event and cannot publish a
    /// sampled timestamp of their own.
    pub fn cancel(&self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_none() {
            *state = Some(Instant::now());
        }
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled_at().is_some()
    }

    fn cancelled_at(&self) -> Option<Instant> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .copied()
    }
}

/// Live deadline and cancellation budget for one provider operation.
///
/// The wire snapshot retains the absolute UTC deadline and the remaining
/// budget, while terminal preflight decisions use the monotonic deadline and
/// the first monotonic cancellation event. If both are terminal, the earlier
/// event wins.
#[derive(Clone, Debug)]
pub struct OperationControl {
    deadline_utc_micros: i64,
    remaining_millis: u64,
    budget_started_at: Instant,
    deadline_at: Instant,
    cancellation: CancellationToken,
}

impl OperationControl {
    /// Creates request control with a finite monotonic remaining budget.
    #[must_use]
    pub fn new(
        deadline_utc_micros: i64,
        remaining_millis: u64,
        cancellation: CancellationToken,
    ) -> Self {
        let budget_started_at = Instant::now();
        let wall_remaining_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| {
                let now_micros = i128::try_from(elapsed.as_micros()).ok()?;
                let remaining_micros = i128::from(deadline_utc_micros) - now_micros;
                if remaining_micros <= 0 {
                    return Some(0);
                }
                u64::try_from(remaining_micros / 1_000).ok()
            })
            .unwrap_or(0);
        let remaining_millis = remaining_millis.min(wall_remaining_millis);
        let deadline_at =
            saturating_instant_add(budget_started_at, deadline_duration(remaining_millis));
        Self {
            deadline_utc_micros,
            remaining_millis,
            budget_started_at,
            deadline_at,
            cancellation,
        }
    }

    /// Returns an immutable wire snapshot or a terminal preflight failure.
    pub fn snapshot(&self) -> Result<RequestControl, TerminalCode> {
        // The mutex read is the cancellation linearization point. A concurrent
        // cancel after this read belongs to a later snapshot, so read it first
        // and only then sample the monotonic deadline/budget clock.
        let cancellation_at = self.cancellation.cancelled_at();
        let now = Instant::now();
        let live_remaining_millis = self.live_remaining_millis_at(now);
        let remaining_millis = classify_snapshot(
            cancellation_at,
            now,
            self.deadline_at,
            live_remaining_millis,
        )?;
        Ok(RequestControl {
            deadline_utc_micros: self.deadline_utc_micros,
            remaining_millis,
            cancellation: CancellationState::Live,
        })
    }

    /// Returns the shared live cancellation token.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Returns the absolute UTC deadline carried by the original request.
    #[must_use]
    pub const fn deadline_utc_micros(&self) -> i64 {
        self.deadline_utc_micros
    }

    /// Returns the finite remaining budget at dispatch.
    #[must_use]
    pub const fn remaining_millis(&self) -> u64 {
        self.remaining_millis
    }

    fn elapsed_millis_at(&self, now: Instant) -> u64 {
        let elapsed_nanos = now
            .checked_duration_since(self.budget_started_at)
            .unwrap_or_default()
            .as_nanos();
        if elapsed_nanos == 0 {
            0
        } else {
            elapsed_nanos
                .saturating_add(999_999)
                .checked_div(1_000_000)
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(u64::MAX)
        }
    }

    fn live_remaining_millis_at(&self, now: Instant) -> Option<u64> {
        self.remaining_millis
            .checked_sub(self.elapsed_millis_at(now))
            .filter(|remaining| *remaining > 0)
    }
}

/// Generic provider operation routed by one versioned capability.
///
/// This enum deliberately does not model the original Native application
/// routes. Native fact search, `FactStoreCurate`, session lookup, retained
/// `MessageSearch`, `SessionsFor`, `Workflows`, and LCM operations remain
/// typed TraceDecay-owned application/retained ports. In particular,
/// [`Self::Recall`] is a read-only advisory provider query and cannot be used
/// as an alias for an owner-bound Native route. Unsupported generic controls
/// remain typed unsupported/refused at composition boundaries.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderOperation {
    /// Read-only compatible handshake.
    Handshake,
    /// Mandatory provider health.
    Health,
    /// Idempotent provider-local observation acceptance.
    Observe,
    /// Read-only advisory provider recall.
    ///
    /// This does not carry the explicit retained fact `Search` retrieval
    /// telemetry or stand for the once-delivered Native context route.
    Recall,
    /// Provider-local feedback recording.
    Feedback,
    /// Provider-local maintenance.
    Maintenance,
    /// Redacted provider inspection.
    Inspection,
    /// Provider-local correction.
    Correction,
    /// Provider-local deletion by admitted source identity.
    DeleteBySource,
    /// Provider-local snapshot export.
    SnapshotExport,
    /// Provider-local snapshot restore.
    SnapshotRestore,
    /// Provider-local deterministic replay.
    Replay,
}

impl ProviderOperation {
    /// Returns the canonical terminal-envelope operation kind.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Health => "health",
            Self::Observe => "observe",
            Self::Recall => "recall",
            Self::Feedback => "feedback",
            Self::Maintenance => "maintenance",
            Self::Inspection => "inspection",
            Self::Correction => "correction",
            Self::DeleteBySource => "deletion_by_source",
            Self::SnapshotExport => "snapshot_export",
            Self::SnapshotRestore => "snapshot_restore",
            Self::Replay => "replay",
        }
    }

    /// Returns the versioned capability required for this operation.
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::Handshake | Self::Health => "provider.health.v1",
            Self::Observe => "observation.accept.v1",
            Self::Recall => "recall.query.v1",
            Self::Feedback => "feedback.record.v1",
            Self::Maintenance => "maintenance.run.v1",
            Self::Inspection => "inspection.read.v1",
            Self::Correction => "correction.apply.v1",
            Self::DeleteBySource => "deletion.by_source.v1",
            Self::SnapshotExport => "snapshot.export.v1",
            Self::SnapshotRestore => "snapshot.restore.v1",
            Self::Replay => "replay.apply.v1",
        }
    }

    /// Returns whether the operation may mutate provider-local state.
    #[must_use]
    pub const fn mutates_provider_state(self) -> bool {
        matches!(
            self,
            Self::Observe
                | Self::Feedback
                | Self::Maintenance
                | Self::Correction
                | Self::DeleteBySource
                | Self::SnapshotRestore
                | Self::Replay
        )
    }
}

/// Finite provider ceilings negotiated during handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLimits {
    /// Maximum canonical request bytes.
    pub request_bytes: u64,
    /// Maximum canonical response bytes.
    pub response_bytes: u64,
    /// Maximum observations in one batch.
    pub observation_batch_items: u64,
    /// Maximum recall candidates.
    pub recall_candidates: u64,
    /// Maximum concurrent operations.
    pub concurrent_operations: u64,
    /// Maximum operation duration in milliseconds.
    pub operation_millis: u64,
    /// Maximum snapshot bytes.
    pub snapshot_bytes: u64,
    /// Maximum inspection items.
    pub inspection_items: u64,
}

impl ProviderLimits {
    /// Validates every limit against the canonical finite catalog range.
    pub fn validate(self) -> Result<Self, ApiError> {
        let values = [
            ("request_bytes", "bytes", self.request_bytes),
            ("response_bytes", "bytes", self.response_bytes),
            (
                "observation_batch_items",
                "items",
                self.observation_batch_items,
            ),
            ("recall_candidates", "items", self.recall_candidates),
            (
                "concurrent_operations",
                "operations",
                self.concurrent_operations,
            ),
            ("operation_millis", "milliseconds", self.operation_millis),
            ("snapshot_bytes", "bytes", self.snapshot_bytes),
            ("inspection_items", "items", self.inspection_items),
        ];
        if contract::PROVIDER_LIMITS.len() != values.len() {
            return Err(ApiError::InvalidLimitCatalog);
        }
        for ((name, unit, value), catalog) in values
            .into_iter()
            .zip(contract::PROVIDER_LIMITS.iter().copied())
        {
            if name != catalog.limit_id || unit != catalog.unit {
                return Err(ApiError::InvalidLimitCatalog);
            }
            if value == 0 {
                return Err(ApiError::ZeroLimit(name));
            }
            if value < catalog.minimum {
                return Err(ApiError::LimitBelowMinimum {
                    limit: name,
                    minimum: catalog.minimum,
                });
            }
            if value > catalog.maximum {
                return Err(ApiError::LimitExceedsMaximum {
                    limit: name,
                    maximum: catalog.maximum,
                });
            }
        }
        Ok(self)
    }

    /// Negotiates the lower host/provider ceiling for every limit.
    #[must_use]
    pub fn minimum(self, other: Self) -> Self {
        Self {
            request_bytes: self.request_bytes.min(other.request_bytes),
            response_bytes: self.response_bytes.min(other.response_bytes),
            observation_batch_items: self
                .observation_batch_items
                .min(other.observation_batch_items),
            recall_candidates: self.recall_candidates.min(other.recall_candidates),
            concurrent_operations: self.concurrent_operations.min(other.concurrent_operations),
            operation_millis: self.operation_millis.min(other.operation_millis),
            snapshot_bytes: self.snapshot_bytes.min(other.snapshot_bytes),
            inspection_items: self.inspection_items.min(other.inspection_items),
        }
    }
}

/// Immutable provider implementation and capability descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDescriptor {
    /// Stable logical provider identity.
    pub provider_id: OwnedProviderId,
    /// SHA-256 over immutable implementation identity.
    pub implementation_identity_sha256: String,
    /// Provider-local state schema identity.
    pub state_schema_version: String,
    /// Current provider-local state generation.
    pub state_generation: u64,
    /// Compatible provider protocol major.
    pub protocol_major: u16,
    /// Compatible provider protocol minor.
    pub protocol_minor: u16,
    /// Real declared capability IDs.
    ///
    /// The runtime descriptor intentionally stores the ID projection only.
    /// Syntactically valid unknown IDs survive this projection verbatim, while
    /// the registry DTO's `canonical_payload` remains owned by its transport
    /// boundary and is not represented by this type. Unknown IDs stay inert
    /// until the generated catalog accepts them.
    pub capabilities: BTreeSet<OwnedVersionedId>,
    /// Finite provider ceilings.
    pub limits: ProviderLimits,
}

impl ProviderDescriptor {
    /// Builds a validated descriptor and requires every mandatory capability.
    pub fn new(
        provider_id: OwnedProviderId,
        implementation_identity_sha256: impl Into<String>,
        state_schema_version: impl Into<String>,
        state_generation: u64,
        capabilities: impl IntoIterator<Item = OwnedVersionedId>,
        limits: ProviderLimits,
    ) -> Result<Self, ApiError> {
        let implementation_identity_sha256 = implementation_identity_sha256.into();
        let state_schema_version = state_schema_version.into();
        let mut capability_set = BTreeSet::new();
        for capability in capabilities {
            let capability_name = capability.as_str().to_owned();
            if !capability_set.insert(capability) {
                return Err(ApiError::DuplicateCapability(capability_name));
            }
        }
        let descriptor = Self {
            provider_id,
            implementation_identity_sha256,
            state_schema_version,
            state_generation,
            protocol_major: 1,
            protocol_minor: 0,
            capabilities: capability_set,
            limits,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Revalidates a descriptor at a provider boundary after direct mutation.
    pub fn validate(&self) -> Result<(), ApiError> {
        contract::ProviderId::new(self.provider_id.as_str())
            .map_err(ApiError::InvalidProviderId)?;
        require_sha256(
            &self.implementation_identity_sha256,
            "implementation_identity_sha256",
        )?;
        require_non_empty(&self.state_schema_version, "state_schema_version")?;
        if (self.protocol_major, self.protocol_minor) != (1, 0) {
            return Err(ApiError::IncompatibleProtocol {
                major: self.protocol_major,
                minor: self.protocol_minor,
            });
        }
        for capability in &self.capabilities {
            CapabilityId::new(capability.as_str()).map_err(ApiError::InvalidVersionedId)?;
        }
        // Observation is not universal: a provider that observes nothing (the
        // host's own Native memory) is complete with health and recall. Every
        // observation delivery still requires `observation.accept.v1` at its
        // own call and readiness boundary.
        for mandatory in ["provider.health.v1", "recall.query.v1"] {
            if !self.supports(mandatory) {
                return Err(ApiError::MandatoryCapabilityMissing(mandatory));
            }
        }
        if self.supports(contract::COMMON_ADVISORY_PROFILE_ID) {
            self.validate_common_advisory_profile()?;
        }
        self.limits.validate()?;
        Ok(())
    }

    /// Returns whether this descriptor declares one known capability.
    ///
    /// Syntactically valid capabilities outside the generated catalog remain
    /// in [`Self::capabilities`] for opaque wire round trips, but are inert:
    /// they never count as support or satisfy required-capability selection.
    #[must_use]
    pub fn supports(&self, capability_id: &str) -> bool {
        is_known_capability(capability_id)
            && self
                .capabilities
                .iter()
                .any(|capability| capability.as_str() == capability_id)
    }

    /// Requires the explicitly declared complete advisory profile. Legacy
    /// descriptors remain valid without opting in to this profile.
    pub fn validate_common_advisory_profile(&self) -> Result<(), ApiError> {
        for capability in std::iter::once(&contract::COMMON_ADVISORY_PROFILE_ID)
            .chain(contract::COMMON_ADVISORY_REQUIRED_CAPABILITIES.iter())
        {
            if !self.supports(capability) {
                return Err(ApiError::MandatoryCapabilityMissing(capability));
            }
        }
        Ok(())
    }
}

fn is_known_capability(capability_id: &str) -> bool {
    contract::CAPABILITIES
        .iter()
        .any(|capability| capability.capability_id == capability_id)
}

/// Canonical payload bytes bound to their verified digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPayload {
    /// Versioned payload contract identity.
    pub contract_id: OwnedVersionedId,
    /// Canonical payload bytes.
    pub bytes: Vec<u8>,
    /// Lowercase SHA-256 of canonical payload bytes.
    pub sha256: String,
}

impl CanonicalPayload {
    /// Creates a validated canonical payload envelope.
    pub fn new(
        contract_id: OwnedVersionedId,
        bytes: Vec<u8>,
        sha256: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let payload = Self {
            contract_id,
            bytes,
            sha256: sha256.into(),
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Revalidates canonical bytes and their declared digest after mutation.
    pub fn validate(&self) -> Result<(), ApiError> {
        CapabilityId::new(self.contract_id.as_str()).map_err(ApiError::InvalidVersionedId)?;
        require_sha256(&self.sha256, "payload_sha256")?;
        if self.bytes.is_empty() {
            return Err(ApiError::EmptyField("canonical_payload"));
        }
        let actual = lowercase_sha256_hex(Sha256::digest(&self.bytes).into());
        if self.sha256 != actual {
            return Err(ApiError::ContentDigestMismatch("payload_sha256"));
        }
        Ok(())
    }
}

/// Owned opaque extension retained without activating behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedOpaqueExtension {
    /// Stable extension identity.
    pub extension_id: OwnedVersionedId,
    /// Positive extension version.
    pub extension_version: u32,
    /// Whether unknown support is mandatory.
    pub required: bool,
    /// Lowercase SHA-256 of canonical opaque bytes.
    pub payload_sha256: String,
    /// Canonical opaque extension bytes.
    pub canonical_payload: Vec<u8>,
}

impl OwnedOpaqueExtension {
    /// Validates one owned extension.
    pub fn new(
        extension_id: OwnedVersionedId,
        extension_version: u32,
        required: bool,
        payload_sha256: impl Into<String>,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, ApiError> {
        let extension = Self {
            extension_id,
            extension_version,
            required,
            payload_sha256: payload_sha256.into(),
            canonical_payload,
        };
        extension.validate()?;
        Ok(extension)
    }

    /// Revalidates opaque canonical bytes and metadata after mutation.
    pub fn validate(&self) -> Result<(), ApiError> {
        CapabilityId::new(self.extension_id.as_str()).map_err(ApiError::InvalidVersionedId)?;
        if self.extension_version == 0 {
            return Err(ApiError::InvalidExtensionVersion);
        }
        require_sha256(&self.payload_sha256, "extension_payload_sha256")?;
        if self.canonical_payload.is_empty() {
            return Err(ApiError::EmptyField("extension_canonical_payload"));
        }
        let actual = lowercase_sha256_hex(Sha256::digest(&self.canonical_payload).into());
        if self.payload_sha256 != actual {
            return Err(ApiError::ContentDigestMismatch("extension_payload_sha256"));
        }
        Ok(())
    }

    /// Borrows the generated extension representation.
    #[must_use]
    pub fn borrowed(&self) -> OpaqueExtension<'_> {
        OpaqueExtension {
            extension_id: self.extension_id.as_str(),
            extension_version: self.extension_version,
            required: self.required,
            payload_sha256: &self.payload_sha256,
            canonical_payload: &self.canonical_payload,
        }
    }
}

/// Digest of the empty canonical opaque-extension set.
#[must_use]
pub fn empty_opaque_extensions_digest() -> String {
    const DOMAIN: &[u8] = b"tracedecay.memory-provider.observation-extensions.v1\0";
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(0_u64.to_be_bytes());
    lowercase_sha256_hex(digest.finalize().into())
}

/// Validates and digests the exact extension set carried by an observation.
///
/// This is the shared pre-dispatch and pre-sanitization boundary: at most 32
/// extensions, at most 256 KiB each, at most 512 KiB in aggregate, and canonical
/// ascending duplicate-free identity order.
pub fn observation_extensions_digest(
    extensions: &[OwnedOpaqueExtension],
) -> Result<String, ApiError> {
    validate_extension_boundary(extensions, 32, 262_144, Some(524_288))?;
    opaque_extensions_digest(extensions)
}

/// Digest over one canonical opaque-extension set.
///
/// Extensions are framed in ascending, duplicate-free `extension_id` order.
/// The digest covers each extension's identity, version, criticality, and
/// canonical payload digest, so a hygiene receipt cannot be reattached after an
/// extension is added, removed, reordered, or re-pointed at other bytes.
pub fn opaque_extensions_digest(extensions: &[OwnedOpaqueExtension]) -> Result<String, ApiError> {
    const DOMAIN: &[u8] = b"tracedecay.memory-provider.observation-extensions.v1\0";

    let mut previous: Option<&str> = None;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(
        u64::try_from(extensions.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for extension in extensions {
        extension.validate()?;
        let id = extension.extension_id.as_str();
        if previous.is_some_and(|last| last >= id) {
            return Err(ApiError::UnorderedExtensions);
        }
        previous = Some(id);
        for value in [
            id.as_bytes(),
            &u64::from(extension.extension_version).to_be_bytes(),
            &[u8::from(extension.required)],
            extension.payload_sha256.as_bytes(),
        ] {
            digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            digest.update(value);
        }
    }
    Ok(lowercase_sha256_hex(digest.finalize().into()))
}

fn validate_extension_boundary(
    extensions: &[OwnedOpaqueExtension],
    maximum_extensions: usize,
    maximum_extension_bytes: u64,
    maximum_total_bytes: Option<u64>,
) -> Result<(), ApiError> {
    if extensions.len() > maximum_extensions {
        return Err(ApiError::TooManyBoundaryItems {
            field: "extensions",
            maximum: maximum_extensions,
        });
    }
    let mut total_extension_bytes = 0_u64;
    for extension in extensions {
        extension.validate()?;
        let extension_bytes = u64::try_from(extension.canonical_payload.len()).unwrap_or(u64::MAX);
        if extension_bytes > maximum_extension_bytes {
            return Err(ApiError::BoundaryBytesExceeded {
                field: "extension_canonical_payload",
                maximum: maximum_extension_bytes,
            });
        }
        total_extension_bytes = total_extension_bytes.saturating_add(extension_bytes);
    }
    if let Some(maximum) = maximum_total_bytes
        && total_extension_bytes > maximum
    {
        return Err(ApiError::BoundaryBytesExceeded {
            field: "extensions",
            maximum,
        });
    }
    Ok(())
}

/// Owned runtime provider call built from canonical wire bytes.
#[derive(Clone, Debug)]
pub struct ProviderCall {
    /// Operation capability.
    pub operation: ProviderOperation,
    /// Target provider identity.
    pub provider_id: OwnedProviderId,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Compatible ready-receipt digest.
    pub ready_receipt_sha256: String,
    /// Exact TraceDecay-owned coding scope.
    pub exact_scope: OwnedExactScope,
    /// Stable request identity.
    pub request_id: String,
    /// Stable operation identity.
    pub operation_id: String,
    /// Expected provider-local state generation.
    pub expected_state_generation: u64,
    /// Deterministic idempotency key for provider-local mutations.
    pub idempotency_key: Option<String>,
    /// Live request control.
    pub control: OperationControl,
    /// Canonical operation payload.
    pub payload: CanonicalPayload,
    /// Required capabilities, including the operation capability.
    ///
    /// Envelope validation checks these IDs for syntax and presence of the
    /// operation capability. Provider admission must check every ID with
    /// [`ProviderDescriptor::supports`]; an unknown but syntactically valid ID
    /// remains in the envelope so selection can return typed unsupported.
    pub required_capabilities: BTreeSet<OwnedVersionedId>,
    /// Opaque extensions.
    pub extensions: Vec<OwnedOpaqueExtension>,
    /// Proof that the payload passed the admitted observation-hygiene
    /// pipeline. Private so the only way to attach one is
    /// [`ProviderCall::with_sanitization`], and the only way to read one is
    /// [`ProviderCall::sanitization`].
    sanitization: Option<PayloadSanitizationReceipt>,
    /// Untrusted in-process history claim, never part of the canonical wire payload.
    history_grant: Option<HistoryGrant>,
}

impl ProviderCall {
    /// Validates a complete runtime call.
    ///
    /// This checks the call envelope. It deliberately does not require a
    /// sanitization receipt: a dispatcher that reconstructs a call from a
    /// durable journal builds the envelope first and re-attaches the persisted
    /// receipt with [`ProviderCall::with_sanitization`]. The receipt is
    /// mandatory at [`ProviderCall::validate`], which every dispatch path runs
    /// before a provider sees the call.
    pub fn new(parts: ProviderCallParts) -> Result<Self, ApiError> {
        let mut required_capabilities = BTreeSet::new();
        for capability in parts.required_capabilities {
            let capability_name = capability.as_str().to_owned();
            if !required_capabilities.insert(capability) {
                return Err(ApiError::DuplicateCapability(capability_name));
            }
        }
        let call = Self {
            operation: parts.operation,
            provider_id: parts.provider_id,
            registration_revision: parts.registration_revision,
            ready_receipt_sha256: parts.ready_receipt_sha256,
            exact_scope: parts.exact_scope,
            request_id: parts.request_id,
            operation_id: parts.operation_id,
            expected_state_generation: parts.expected_state_generation,
            idempotency_key: parts.idempotency_key,
            control: parts.control,
            payload: parts.payload,
            required_capabilities,
            extensions: parts.extensions,
            sanitization: None,
            history_grant: None,
        };
        call.validate_envelope()?;
        Ok(call)
    }

    /// Attaches the sanitization receipt that admitted this payload.
    ///
    /// Attaching is infallible on purpose; a receipt that does not describe
    /// this payload is caught by [`ProviderCall::validate`], which is the one
    /// place the boundary decides whether a call may be dispatched.
    #[must_use]
    pub fn with_sanitization(mut self, receipt: PayloadSanitizationReceipt) -> Self {
        self.sanitization = Some(receipt);
        self
    }

    /// Returns the attached sanitization receipt, if any.
    #[must_use]
    pub fn sanitization(&self) -> Option<&PayloadSanitizationReceipt> {
        self.sanitization.as_ref()
    }

    /// Attaches an untrusted history claim for the installed host authority.
    ///
    /// This does not authorize history or change the canonical wire payload.
    /// The authority must independently validate the claim immediately before
    /// use; [`AdvisoryCallBinding`] binds it against subsequent replacement.
    #[must_use]
    pub fn with_history_grant(mut self, grant: HistoryGrant) -> Self {
        self.history_grant = Some(grant);
        self
    }

    /// Returns the in-process history claim, which is not source authorization.
    #[must_use]
    pub fn history_grant(&self) -> Option<&HistoryGrant> {
        self.history_grant.as_ref()
    }

    /// Revalidates the complete public call envelope after mutation, and — for
    /// [`ProviderOperation::Observe`] — fails closed unless a self-consistent
    /// sanitization receipt binds the exact canonical payload being dispatched.
    ///
    /// The fabric runs this as the first statement of observation delivery, so
    /// an unsanitized or mis-bound observation never reaches provider
    /// registration, readiness, or a concurrency permit.
    pub fn validate(&self) -> Result<(), ApiError> {
        self.validate_envelope()?;
        if self.operation != ProviderOperation::Observe {
            return Ok(());
        }
        let receipt = self
            .sanitization
            .as_ref()
            .ok_or(ApiError::UnsanitizedObservation)?;
        let extensions_digest = observation_extensions_digest(&self.extensions)?;
        receipt.verify_binding(&self.payload.sha256, &extensions_digest)
    }

    fn validate_envelope(&self) -> Result<(), ApiError> {
        contract::ProviderId::new(self.provider_id.as_str())
            .map_err(ApiError::InvalidProviderId)?;
        if self.registration_revision == 0 {
            return Err(ApiError::InvalidRegistrationRevision);
        }
        self.exact_scope.validate()?;
        require_sha256(&self.ready_receipt_sha256, "ready_receipt_sha256")?;
        require_non_empty(&self.request_id, "request_id")?;
        require_bounded_canonical_text(
            &self.request_id,
            "request_id",
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
        )?;
        require_non_empty(&self.operation_id, "operation_id")?;
        require_bounded_canonical_text(
            &self.operation_id,
            "operation_id",
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
        )?;
        if let Some(idempotency_key) = &self.idempotency_key {
            require_bounded_canonical_text(
                idempotency_key,
                "idempotency_key",
                contract::TERMINAL_OPERATION_ID_MAX_BYTES,
            )?;
        }
        if self.operation.mutates_provider_state() && self.idempotency_key.is_none() {
            return Err(ApiError::MissingIdempotencyKey);
        }
        for capability in &self.required_capabilities {
            CapabilityId::new(capability.as_str()).map_err(ApiError::InvalidVersionedId)?;
        }
        let operation_capability = self.operation.capability_id();
        if !self
            .required_capabilities
            .iter()
            .any(|capability| capability.as_str() == operation_capability)
        {
            return Err(ApiError::MissingOperationCapability(operation_capability));
        }
        self.payload.validate()?;

        if self.operation == ProviderOperation::Observe {
            observation_extensions_digest(&self.extensions)?;
        } else {
            let (maximum_extensions, maximum_extension_bytes) =
                if self.operation == ProviderOperation::Recall {
                    (16, 131_072_u64)
                } else {
                    (32, 262_144_u64)
                };
            validate_extension_boundary(
                &self.extensions,
                maximum_extensions,
                maximum_extension_bytes,
                None,
            )?;
        }
        Ok(())
    }

    /// Revalidates the call and its aggregate variable content against the
    /// effective request byte ceiling negotiated during handshake.
    pub fn validate_request_bytes(&self, request_bytes: u64) -> Result<(), ApiError> {
        self.validate()?;
        let aggregate_bytes = encoded_provider_call_bytes(self);
        if aggregate_bytes > request_bytes {
            return Err(ApiError::BoundaryBytesExceeded {
                field: "request",
                maximum: request_bytes,
            });
        }
        Ok(())
    }
}

/// Builder payload for one provider call.
#[derive(Clone, Debug)]
pub struct ProviderCallParts {
    /// Operation capability.
    pub operation: ProviderOperation,
    /// Target provider.
    pub provider_id: OwnedProviderId,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Compatible ready-receipt digest.
    pub ready_receipt_sha256: String,
    /// Exact coding scope.
    pub exact_scope: OwnedExactScope,
    /// Stable request identity.
    pub request_id: String,
    /// Stable operation identity.
    pub operation_id: String,
    /// Expected provider-local generation.
    pub expected_state_generation: u64,
    /// Deterministic idempotency key for mutations.
    pub idempotency_key: Option<String>,
    /// Live request control.
    pub control: OperationControl,
    /// Canonical payload.
    pub payload: CanonicalPayload,
    /// Required capabilities.
    pub required_capabilities: Vec<OwnedVersionedId>,
    /// Opaque extensions.
    pub extensions: Vec<OwnedOpaqueExtension>,
}

/// Input fields for validated owned committed-effect evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedEffectEvidenceParts {
    /// Truthful committed-effect state.
    pub state: CommittedEffectState,
    /// Exact boundary for the committed partition of a partial effect.
    pub committed_boundary: Option<String>,
    /// Known provider-local generation before the operation.
    pub state_generation_before: Option<u64>,
    /// Known provider-local generation after settlement or reconciliation.
    pub state_generation_after: Option<u64>,
    /// Provider-local item references known to have committed.
    pub committed_item_refs: Vec<String>,
    /// Provider-local item references known not to have committed.
    pub uncommitted_item_refs: Vec<String>,
    /// Provider receipt anchoring the effect claim.
    pub provider_receipt_sha256: Option<String>,
    /// Explicit reconciliation or resume action.
    pub reconciliation_action: Option<String>,
    /// Digest verifying the known committed partition.
    pub verification_sha256: Option<String>,
    /// Request idempotency key a duplicate acknowledgement deduplicated.
    pub duplicate_of_idempotency_key: Option<String>,
    /// Operation whose earlier delivery actually committed the effect.
    pub duplicate_of_operation_id: Option<String>,
}

/// Validated provider-local committed-effect evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedEffectEvidence {
    state: CommittedEffectState,
    committed_boundary: Option<String>,
    state_generation_before: Option<u64>,
    state_generation_after: Option<u64>,
    committed_item_refs: Vec<String>,
    uncommitted_item_refs: Vec<String>,
    provider_receipt_sha256: Option<String>,
    reconciliation_action: Option<String>,
    verification_sha256: Option<String>,
    duplicate_of_idempotency_key: Option<String>,
    duplicate_of_operation_id: Option<String>,
}

impl CommittedEffectEvidence {
    /// Validates a complete committed-effect field set.
    pub fn from_parts(parts: CommittedEffectEvidenceParts) -> Result<Self, ApiError> {
        validate_effect_item_refs(&parts.committed_item_refs, &parts.uncommitted_item_refs)?;
        if let Some(boundary) = &parts.committed_boundary {
            require_bounded_canonical_text(
                boundary,
                "committed_boundary",
                contract::TERMINAL_COMMITTED_BOUNDARY_MAX_BYTES,
            )?;
        }
        if let Some(receipt) = &parts.provider_receipt_sha256 {
            require_sha256(receipt, "provider_receipt_sha256")?;
        }
        if let Some(action) = &parts.reconciliation_action {
            require_bounded_canonical_text(
                action,
                "reconciliation_action",
                contract::TERMINAL_RECONCILIATION_ACTION_MAX_BYTES,
            )?;
        }
        if let Some(verification) = &parts.verification_sha256 {
            require_sha256(verification, "verification_sha256")?;
        }
        if let Some(key) = &parts.duplicate_of_idempotency_key {
            // The runtime API does not constrain idempotency-key encoding on
            // `ProviderCall`, so it does not constrain it here either; the
            // observation contract pins the key to lowercase hex-64 and the
            // journal checks the value against the observation it delivered.
            // What matters at this layer is that the key is bounded canonical
            // text, so it cannot smuggle unbounded provider data.
            require_bounded_canonical_text(
                key,
                "duplicate_of_idempotency_key",
                contract::TERMINAL_OPERATION_ID_MAX_BYTES,
            )?;
        }
        if let Some(operation_id) = &parts.duplicate_of_operation_id {
            require_bounded_canonical_text(
                operation_id,
                "duplicate_of_operation_id",
                contract::TERMINAL_OPERATION_ID_MAX_BYTES,
            )?;
        }
        if parts.state != CommittedEffectState::Duplicate
            && (parts.duplicate_of_idempotency_key.is_some()
                || parts.duplicate_of_operation_id.is_some())
        {
            return Err(ApiError::InvalidCommittedEffect(
                "duplicate identity belongs only to a duplicate acknowledgement",
            ));
        }

        match parts.state {
            CommittedEffectState::None => validate_none_effect(&parts)?,
            CommittedEffectState::Committed => validate_committed_effect(&parts)?,
            CommittedEffectState::Duplicate => validate_duplicate_effect(&parts)?,
            CommittedEffectState::Partial => validate_partial_effect(&parts)?,
            CommittedEffectState::Unknown => validate_unknown_effect(&parts)?,
        }

        Ok(Self {
            state: parts.state,
            committed_boundary: parts.committed_boundary,
            state_generation_before: parts.state_generation_before,
            state_generation_after: parts.state_generation_after,
            committed_item_refs: parts.committed_item_refs,
            uncommitted_item_refs: parts.uncommitted_item_refs,
            provider_receipt_sha256: parts.provider_receipt_sha256,
            reconciliation_action: parts.reconciliation_action,
            verification_sha256: parts.verification_sha256,
            duplicate_of_idempotency_key: parts.duplicate_of_idempotency_key,
            duplicate_of_operation_id: parts.duplicate_of_operation_id,
        })
    }

    /// Creates effect-free evidence with either an unknown generation or one
    /// unchanged known generation.
    #[must_use]
    pub fn none(generation: Option<u64>) -> Self {
        Self {
            state: CommittedEffectState::None,
            committed_boundary: None,
            state_generation_before: generation,
            state_generation_after: generation,
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: None,
            reconciliation_action: None,
            verification_sha256: None,
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        }
    }

    /// Creates evidence for a fully committed effect.
    pub fn committed(
        state_generation_before: u64,
        state_generation_after: u64,
        committed_item_refs: Vec<String>,
        provider_receipt_sha256: impl Into<String>,
        verification_sha256: impl Into<String>,
    ) -> Result<Self, ApiError> {
        Self::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Committed,
            committed_boundary: None,
            state_generation_before: Some(state_generation_before),
            state_generation_after: Some(state_generation_after),
            committed_item_refs,
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: Some(provider_receipt_sha256.into()),
            reconciliation_action: None,
            verification_sha256: Some(verification_sha256.into()),
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        })
    }

    /// Creates evidence that a prior delivery of this exact mutation already
    /// committed.
    ///
    /// `duplicate_of_idempotency_key` is the key the provider matched. It must
    /// be the key carried on the request being answered; the host side proves
    /// that rather than trusting it, because only the host knows which
    /// observation it delivered. The durable journal refuses a duplicate whose
    /// key is not the key of the delivery it answers, so an adapter that names
    /// somebody else's mutation produces no duplicate receipt.
    /// `duplicate_of_operation_id` names the earlier operation that actually
    /// committed. The generation is unchanged because a duplicate commits
    /// nothing new.
    pub fn duplicate(
        state_generation: u64,
        duplicate_of_idempotency_key: impl Into<String>,
        duplicate_of_operation_id: impl Into<String>,
        provider_receipt_sha256: impl Into<String>,
    ) -> Result<Self, ApiError> {
        Self::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Duplicate,
            committed_boundary: None,
            state_generation_before: Some(state_generation),
            state_generation_after: Some(state_generation),
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: Some(provider_receipt_sha256.into()),
            reconciliation_action: None,
            verification_sha256: None,
            duplicate_of_idempotency_key: Some(duplicate_of_idempotency_key.into()),
            duplicate_of_operation_id: Some(duplicate_of_operation_id.into()),
        })
    }

    /// Creates evidence for an exactly partitioned partial effect.
    #[allow(clippy::too_many_arguments)]
    pub fn partial(
        committed_boundary: impl Into<String>,
        state_generation_before: u64,
        state_generation_after: u64,
        committed_item_refs: Vec<String>,
        uncommitted_item_refs: Vec<String>,
        provider_receipt_sha256: impl Into<String>,
        reconciliation_action: impl Into<String>,
        verification_sha256: impl Into<String>,
    ) -> Result<Self, ApiError> {
        Self::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Partial,
            committed_boundary: Some(committed_boundary.into()),
            state_generation_before: Some(state_generation_before),
            state_generation_after: Some(state_generation_after),
            committed_item_refs,
            uncommitted_item_refs,
            provider_receipt_sha256: Some(provider_receipt_sha256.into()),
            reconciliation_action: Some(reconciliation_action.into()),
            verification_sha256: Some(verification_sha256.into()),
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        })
    }

    /// Creates evidence for an effect whose committed boundary is unknown.
    pub fn unknown(
        provider_receipt_sha256: impl Into<String>,
        reconciliation_action: impl Into<String>,
    ) -> Result<Self, ApiError> {
        Self::from_parts(CommittedEffectEvidenceParts {
            state: CommittedEffectState::Unknown,
            committed_boundary: None,
            state_generation_before: None,
            state_generation_after: None,
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: Some(provider_receipt_sha256.into()),
            reconciliation_action: Some(reconciliation_action.into()),
            verification_sha256: None,
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        })
    }

    /// Creates statically valid unknown-effect evidence from a typed adapter
    /// reconciliation receipt digest and the API-owned canonical action.
    #[must_use]
    pub fn unknown_from_reconciliation_digest(provider_receipt_sha256: [u8; 32]) -> Self {
        Self::unknown_from_reconciliation_digest_action(
            provider_receipt_sha256,
            UNKNOWN_EFFECT_RECONCILIATION_ACTION,
        )
    }

    /// Creates statically valid unknown-effect evidence from a typed adapter
    /// reconciliation receipt digest and an adapter-owned reconciliation
    /// action naming the exact recovery procedure. An empty, unnormalized,
    /// or oversized action degrades to the API-owned canonical action; the
    /// receipt digest is bound either way.
    #[must_use]
    pub fn unknown_from_reconciliation_digest_action(
        provider_receipt_sha256: [u8; 32],
        reconciliation_action: &str,
    ) -> Self {
        let reconciliation_action = normalized_terminal_text(
            reconciliation_action,
            contract::TERMINAL_RECONCILIATION_ACTION_MAX_BYTES,
            UNKNOWN_EFFECT_RECONCILIATION_ACTION,
        );
        Self {
            state: CommittedEffectState::Unknown,
            committed_boundary: None,
            state_generation_before: None,
            state_generation_after: None,
            committed_item_refs: Vec::new(),
            uncommitted_item_refs: Vec::new(),
            provider_receipt_sha256: Some(lowercase_sha256_hex(provider_receipt_sha256)),
            reconciliation_action: Some(reconciliation_action),
            verification_sha256: None,
            duplicate_of_idempotency_key: None,
            duplicate_of_operation_id: None,
        }
    }

    /// Returns the truthful committed-effect state.
    #[must_use]
    pub const fn state(&self) -> CommittedEffectState {
        self.state
    }

    /// Returns the exact partial-effect boundary, when known.
    #[must_use]
    pub fn committed_boundary(&self) -> Option<&str> {
        self.committed_boundary.as_deref()
    }

    /// Returns the known generation before the operation.
    #[must_use]
    pub const fn state_generation_before(&self) -> Option<u64> {
        self.state_generation_before
    }

    /// Returns the known generation after settlement or reconciliation.
    #[must_use]
    pub const fn state_generation_after(&self) -> Option<u64> {
        self.state_generation_after
    }

    /// Returns the bounded committed partition.
    #[must_use]
    pub fn committed_item_refs(&self) -> &[String] {
        &self.committed_item_refs
    }

    /// Returns the bounded uncommitted partition.
    #[must_use]
    pub fn uncommitted_item_refs(&self) -> &[String] {
        &self.uncommitted_item_refs
    }

    /// Returns the provider effect receipt digest.
    #[must_use]
    pub fn provider_receipt_sha256(&self) -> Option<&str> {
        self.provider_receipt_sha256.as_deref()
    }

    /// Returns the explicit reconciliation or resume action.
    #[must_use]
    pub fn reconciliation_action(&self) -> Option<&str> {
        self.reconciliation_action.as_deref()
    }

    /// Returns the digest verifying the known committed partition.
    #[must_use]
    pub fn verification_sha256(&self) -> Option<&str> {
        self.verification_sha256.as_deref()
    }

    /// Returns the request idempotency key this duplicate acknowledgement
    /// deduplicated, if the state is duplicate.
    #[must_use]
    pub fn duplicate_of_idempotency_key(&self) -> Option<&str> {
        self.duplicate_of_idempotency_key.as_deref()
    }

    /// Returns the operation whose earlier delivery actually committed the
    /// effect, if the state is duplicate.
    #[must_use]
    pub fn duplicate_of_operation_id(&self) -> Option<&str> {
        self.duplicate_of_operation_id.as_deref()
    }

    /// Borrows the generated canonical shape.
    #[must_use]
    pub fn borrowed(&self) -> contract::CommittedEffectEvidence<'_> {
        contract::CommittedEffectEvidence {
            state: self.state,
            committed_boundary: self.committed_boundary(),
            state_generation_before: self.state_generation_before,
            state_generation_after: self.state_generation_after,
            committed_item_refs: &self.committed_item_refs,
            uncommitted_item_refs: &self.uncommitted_item_refs,
            provider_receipt_digest: self.provider_receipt_sha256(),
            reconciliation_action: self.reconciliation_action(),
            verification_digest: self.verification_sha256(),
            duplicate_of_idempotency_key: self.duplicate_of_idempotency_key(),
            duplicate_of_operation_id: self.duplicate_of_operation_id(),
        }
    }
}

fn validate_effect_item_refs(committed: &[String], uncommitted: &[String]) -> Result<(), ApiError> {
    let aggregate = committed.len().saturating_add(uncommitted.len());
    if aggregate > MAX_COMMITTED_EFFECT_ITEM_REFS {
        return Err(ApiError::TooManyEffectItemRefs {
            maximum: MAX_COMMITTED_EFFECT_ITEM_REFS,
        });
    }
    let mut committed_set = BTreeSet::new();
    for item_ref in committed {
        require_bounded_canonical_text(
            item_ref,
            "effect_item_ref",
            MAX_COMMITTED_EFFECT_ITEM_REF_BYTES,
        )?;
        if !committed_set.insert(item_ref.as_str()) {
            return Err(ApiError::DuplicateEffectItemRef(item_ref.clone()));
        }
    }
    let mut uncommitted_set = BTreeSet::new();
    for item_ref in uncommitted {
        require_bounded_canonical_text(
            item_ref,
            "effect_item_ref",
            MAX_COMMITTED_EFFECT_ITEM_REF_BYTES,
        )?;
        if !uncommitted_set.insert(item_ref.as_str()) {
            return Err(ApiError::DuplicateEffectItemRef(item_ref.clone()));
        }
        if committed_set.contains(item_ref.as_str()) {
            return Err(ApiError::OverlappingEffectItemRef(item_ref.clone()));
        }
    }
    Ok(())
}

fn validate_none_effect(parts: &CommittedEffectEvidenceParts) -> Result<(), ApiError> {
    let generations_valid = matches!(
        (parts.state_generation_before, parts.state_generation_after),
        (None, None) | (Some(_), Some(_))
    ) && parts.state_generation_before == parts.state_generation_after;
    if !generations_valid {
        return Err(ApiError::InvalidEffectGenerations);
    }
    if parts.committed_boundary.is_some()
        || !parts.committed_item_refs.is_empty()
        || !parts.uncommitted_item_refs.is_empty()
        || parts.provider_receipt_sha256.is_some()
        || parts.reconciliation_action.is_some()
        || parts.verification_sha256.is_some()
    {
        return Err(ApiError::InvalidCommittedEffect(
            "none carries no effect-only fields",
        ));
    }
    Ok(())
}

fn validate_known_nonregressing_generations(
    before: Option<u64>,
    after: Option<u64>,
) -> Result<(), ApiError> {
    match (before, after) {
        (Some(before), Some(after)) if after >= before => Ok(()),
        _ => Err(ApiError::InvalidEffectGenerations),
    }
}

fn validate_committed_effect(parts: &CommittedEffectEvidenceParts) -> Result<(), ApiError> {
    validate_known_nonregressing_generations(
        parts.state_generation_before,
        parts.state_generation_after,
    )?;
    if parts.committed_boundary.is_some()
        || !parts.uncommitted_item_refs.is_empty()
        || parts.provider_receipt_sha256.is_none()
        || parts.reconciliation_action.is_some()
        || parts.verification_sha256.is_none()
    {
        return Err(ApiError::InvalidCommittedEffect(
            "committed requires receipt and verification with no uncommitted partition",
        ));
    }
    Ok(())
}

/// A duplicate is an *already committed* effect that this attempt did not
/// create, so it carries the prior receipt, names the exact mutation it
/// deduplicated, and leaves the generation where it was. Anything that would
/// let a provider claim a duplicate without naming the mutation — a missing
/// key, a missing original operation, a moved generation, a fabricated item
/// partition — is refused here rather than reinterpreted downstream.
fn validate_duplicate_effect(parts: &CommittedEffectEvidenceParts) -> Result<(), ApiError> {
    let generation_unchanged = match (parts.state_generation_before, parts.state_generation_after) {
        (Some(before), Some(after)) => before == after,
        _ => false,
    };
    if !generation_unchanged {
        return Err(ApiError::InvalidEffectGenerations);
    }
    if parts.duplicate_of_idempotency_key.is_none()
        || parts.duplicate_of_operation_id.is_none()
        || parts.provider_receipt_sha256.is_none()
        || parts.committed_boundary.is_some()
        || !parts.committed_item_refs.is_empty()
        || !parts.uncommitted_item_refs.is_empty()
        || parts.reconciliation_action.is_some()
        || parts.verification_sha256.is_some()
    {
        return Err(ApiError::InvalidCommittedEffect(
            "duplicate requires the deduplicated key, the committing operation, and the prior receipt, and claims no new partition",
        ));
    }
    Ok(())
}

fn validate_partial_effect(parts: &CommittedEffectEvidenceParts) -> Result<(), ApiError> {
    validate_known_nonregressing_generations(
        parts.state_generation_before,
        parts.state_generation_after,
    )?;
    if parts.committed_boundary.is_none()
        || parts.committed_item_refs.is_empty()
        || parts.uncommitted_item_refs.is_empty()
        || parts.provider_receipt_sha256.is_none()
        || parts.reconciliation_action.is_none()
        || parts.verification_sha256.is_none()
    {
        return Err(ApiError::InvalidCommittedEffect(
            "partial requires boundary, disjoint partitions, receipt, reconciliation, and verification",
        ));
    }
    Ok(())
}

fn validate_unknown_effect(parts: &CommittedEffectEvidenceParts) -> Result<(), ApiError> {
    if parts.committed_boundary.is_some()
        || parts.state_generation_before.is_some()
        || parts.state_generation_after.is_some()
        || !parts.committed_item_refs.is_empty()
        || !parts.uncommitted_item_refs.is_empty()
        || parts.provider_receipt_sha256.is_none()
        || parts.reconciliation_action.is_none()
        || parts.verification_sha256.is_some()
    {
        return Err(ApiError::InvalidCommittedEffect(
            "unknown requires only receipt and reconciliation without a claimed boundary",
        ));
    }
    Ok(())
}

/// Complete host policy pin required before alternate-provider fallback is eligible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedFallbackPolicy {
    policy_id: String,
    policy_revision: u64,
    target_provider_id: OwnedProviderId,
}

impl PinnedFallbackPolicy {
    /// Creates a complete immutable fallback policy pin.
    pub fn new(
        policy_id: impl Into<String>,
        policy_revision: u64,
        target_provider_id: OwnedProviderId,
    ) -> Result<Self, ApiError> {
        let policy_id = policy_id.into();
        require_bounded_canonical_text(
            &policy_id,
            "fallback_policy_id",
            contract::TERMINAL_FALLBACK_POLICY_ID_MAX_BYTES,
        )?;
        if policy_revision == 0 {
            return Err(ApiError::InvalidFallbackPolicyRevision);
        }
        Ok(Self {
            policy_id,
            policy_revision,
            target_provider_id,
        })
    }

    /// Returns the stable host policy identity.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Returns the positive pinned host policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Returns the explicit alternate provider.
    #[must_use]
    pub const fn target_provider_id(&self) -> &OwnedProviderId {
        &self.target_provider_id
    }

    /// Borrows the generated canonical shape.
    #[must_use]
    pub fn borrowed(&self) -> contract::PinnedFallbackPolicy<'_> {
        contract::PinnedFallbackPolicy {
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            target_provider_id: self.target_provider_id.as_str(),
        }
    }
}

/// Explicit fallback policy decision. This value never executes fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackDirective {
    eligibility: FallbackEligibility,
    source_provider_id: Option<OwnedProviderId>,
    policy: Option<PinnedFallbackPolicy>,
    reason: Option<String>,
}

impl FallbackDirective {
    /// Creates the default fail-closed directive with no fallback authority.
    #[must_use]
    pub const fn forbidden() -> Self {
        Self {
            eligibility: FallbackEligibility::Forbidden,
            source_provider_id: None,
            policy: None,
            reason: None,
        }
    }

    /// Creates explicit-policy-only eligibility after validating a complete
    /// policy pin and a distinct target provider.
    pub fn explicit_policy_only(
        current_provider_id: &OwnedProviderId,
        policy: PinnedFallbackPolicy,
        reason: impl Into<String>,
    ) -> Result<Self, ApiError> {
        if policy.target_provider_id() == current_provider_id {
            return Err(ApiError::FallbackTargetMatchesCurrentProvider);
        }
        let reason = reason.into();
        require_bounded_canonical_text(
            &reason,
            "fallback_reason",
            contract::TERMINAL_FALLBACK_REASON_MAX_BYTES,
        )?;
        Ok(Self {
            eligibility: FallbackEligibility::ExplicitPolicyOnly,
            source_provider_id: Some(current_provider_id.clone()),
            policy: Some(policy),
            reason: Some(reason),
        })
    }

    /// Returns the explicit eligibility decision.
    #[must_use]
    pub const fn eligibility(&self) -> FallbackEligibility {
        self.eligibility
    }

    /// Returns the provider for which explicit eligibility was evaluated.
    #[must_use]
    pub const fn source_provider_id(&self) -> Option<&OwnedProviderId> {
        self.source_provider_id.as_ref()
    }

    /// Returns the complete host policy pin, when eligibility permits it.
    #[must_use]
    pub const fn policy(&self) -> Option<&PinnedFallbackPolicy> {
        self.policy.as_ref()
    }

    /// Returns the policy decision reason, when eligibility permits it.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Borrows the generated canonical shape.
    #[must_use]
    pub fn borrowed(&self) -> contract::FallbackDirective<'_> {
        contract::FallbackDirective {
            eligibility: self.eligibility,
            policy: self.policy.as_ref().map(PinnedFallbackPolicy::borrowed),
            reason: self.reason(),
        }
    }
}

/// Provider-neutral owned terminal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalRecord {
    operation: ProviderOperation,
    provider_id: OwnedProviderId,
    terminal_code: TerminalCode,
    committed_effect: CommittedEffectEvidence,
    fallback: FallbackDirective,
    operation_id: String,
    exact_scope_sha256: String,
    diagnostic_id: Option<String>,
}

impl TerminalRecord {
    /// Creates a terminal record whose effect and fallback fields match the
    /// generated terminal-code policy table.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: ProviderOperation,
        provider_id: OwnedProviderId,
        terminal_code: TerminalCode,
        committed_effect: CommittedEffectEvidence,
        fallback: FallbackDirective,
        operation_id: impl Into<String>,
        exact_scope_sha256: impl Into<String>,
        diagnostic_id: Option<String>,
    ) -> Result<Self, ApiError> {
        let operation_id = operation_id.into();
        let exact_scope_sha256 = exact_scope_sha256.into();
        require_bounded_canonical_text(
            &operation_id,
            "operation_id",
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
        )?;
        require_sha256(&exact_scope_sha256, "exact_scope_sha256")?;
        if let Some(diagnostic) = &diagnostic_id {
            require_bounded_canonical_text(
                diagnostic,
                "diagnostic_id",
                contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES,
            )?;
        }

        let policy = contract::TERMINAL_CODE_POLICIES
            .iter()
            .find(|policy| policy.terminal_code == terminal_code)
            .ok_or(ApiError::InvalidTerminalPolicyCatalog)?;
        if !effect_matches_expectation(policy.effect_expectation, committed_effect.state()) {
            return Err(ApiError::TerminalEffectMismatch {
                terminal_code,
                effect_state: committed_effect.state(),
            });
        }
        if !operation.mutates_provider_state()
            && committed_effect.state() != CommittedEffectState::None
        {
            return Err(ApiError::ReadOnlyOperationEffect {
                operation,
                effect_state: committed_effect.state(),
            });
        }
        // `operation_specific` also covers `partial`, which is degraded read
        // coverage. A duplicate acknowledgement is a complete success, so pin
        // it to `success` rather than letting the expectation table admit it
        // under a degraded terminal.
        if committed_effect.state() == CommittedEffectState::Duplicate
            && terminal_code != TerminalCode::Success
        {
            return Err(ApiError::TerminalEffectMismatch {
                terminal_code,
                effect_state: committed_effect.state(),
            });
        }
        if policy.maximum_fallback_eligibility == FallbackEligibility::Forbidden
            && fallback.eligibility() != FallbackEligibility::Forbidden
        {
            return Err(ApiError::TerminalFallbackMismatch {
                terminal_code,
                eligibility: fallback.eligibility(),
            });
        }
        if fallback.eligibility() == FallbackEligibility::ExplicitPolicyOnly {
            let source_matches = fallback.source_provider_id() == Some(&provider_id);
            let target_differs = fallback
                .policy()
                .is_some_and(|policy| policy.target_provider_id() != &provider_id);
            if !source_matches || !target_differs {
                return Err(ApiError::FallbackSourceProviderMismatch);
            }
        }
        if !matches!(
            terminal_code,
            TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
        ) && diagnostic_id.is_none()
        {
            return Err(ApiError::MissingFailureDiagnostic);
        }

        Ok(Self {
            operation,
            provider_id,
            terminal_code,
            committed_effect,
            fallback,
            operation_id,
            exact_scope_sha256,
            diagnostic_id,
        })
    }

    /// Proves a duplicate acknowledgement deduplicated *this* call.
    ///
    /// A provider that answers `success` with a `duplicate` committed effect
    /// is claiming a prior delivery of the same mutation already committed.
    /// Only the host knows which mutation it actually delivered, so the claim
    /// is checked here rather than trusted: the deduplicated key must be the
    /// idempotency key carried on the call being answered, and a call that
    /// carries no key cannot be deduplicated at all. Without this, a provider
    /// could acknowledge somebody else's mutation and the host would settle a
    /// delivery that never reached it.
    ///
    /// Non-duplicate terminals pass unchanged; the fabric applies this to
    /// every reply, so the check costs one comparison on the ordinary path.
    pub fn validate_duplicate_binding_for_call(&self, call: &ProviderCall) -> Result<(), ApiError> {
        let effect = self.committed_effect();
        if effect.state() != CommittedEffectState::Duplicate {
            return Ok(());
        }
        let request_key = call
            .idempotency_key
            .as_deref()
            .ok_or(ApiError::DuplicateEffectWithoutRequestKey)?;
        if effect.duplicate_of_idempotency_key() != Some(request_key) {
            return Err(ApiError::DuplicateEffectKeyMismatch);
        }
        Ok(())
    }

    /// Creates a sanitized, effect-free failure before provider dispatch.
    /// Codes that cannot truthfully carry no effect are normalized to internal failure.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn failure_before_dispatch(
        operation: ProviderOperation,
        provider_id: OwnedProviderId,
        terminal_code: TerminalCode,
        operation_id: impl AsRef<str>,
        exact_scope_sha256: impl AsRef<str>,
        expected_state_generation: Option<u64>,
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        let terminal_code = normalized_pre_dispatch_failure_code(terminal_code);
        let operation_id = normalized_terminal_text(
            operation_id.as_ref(),
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
            INTERNAL_FAILURE_OPERATION_ID,
        );
        let exact_scope_sha256 = if is_lowercase_sha256(exact_scope_sha256.as_ref()) {
            exact_scope_sha256.as_ref().to_owned()
        } else {
            INVALID_EXACT_SCOPE_SHA256.to_owned()
        };
        let diagnostic_id = normalized_terminal_text(
            diagnostic_id.as_ref(),
            contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES,
            INTERNAL_FAILURE_DIAGNOSTIC_ID,
        );
        Self {
            operation,
            provider_id,
            terminal_code,
            committed_effect: CommittedEffectEvidence::none(expected_state_generation),
            fallback: FallbackDirective::forbidden(),
            operation_id,
            exact_scope_sha256,
            diagnostic_id: Some(diagnostic_id),
        }
    }

    /// Creates a sanitized, effect-free failure from one validated call, even
    /// if callers mutated its public identity fields after construction.
    #[must_use]
    pub fn failure_before_dispatch_for_call(
        terminal_code: TerminalCode,
        call: &ProviderCall,
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        let exact_scope_sha256 = if call.exact_scope.validate().is_ok() {
            call.exact_scope.exact_scope_sha256()
        } else {
            INVALID_EXACT_SCOPE_SHA256.to_owned()
        };
        Self::failure_before_dispatch(
            call.operation,
            call.provider_id.clone(),
            terminal_code,
            &call.operation_id,
            exact_scope_sha256,
            Some(call.expected_state_generation),
            diagnostic_id,
        )
    }

    /// Creates the canonical pre-dispatch internal failure for one call.
    #[must_use]
    pub fn internal_failure_before_dispatch_for_call(
        call: &ProviderCall,
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        Self::failure_before_dispatch_for_call(TerminalCode::InternalFailure, call, diagnostic_id)
    }

    /// Creates a sanitized post-dispatch failure while preserving validated
    /// effect evidence for mutating calls.
    ///
    /// A publicly mutated read-only call cannot truthfully carry an effect, so
    /// this factory fails closed to effect-free evidence at the call's expected
    /// generation. A fully committed mutating effect is represented as a
    /// degraded success because the canonical internal-failure policy does not
    /// admit a known committed effect.
    #[must_use]
    pub fn internal_failure_for_call(
        call: &ProviderCall,
        committed_effect: CommittedEffectEvidence,
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        let operation_id = normalized_terminal_text(
            &call.operation_id,
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
            INTERNAL_FAILURE_OPERATION_ID,
        );
        let exact_scope_sha256 = if call.exact_scope.validate().is_ok() {
            call.exact_scope.exact_scope_sha256()
        } else {
            INVALID_EXACT_SCOPE_SHA256.to_owned()
        };
        let diagnostic_id = normalized_terminal_text(
            diagnostic_id.as_ref(),
            contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES,
            INTERNAL_FAILURE_DIAGNOSTIC_ID,
        );
        // A duplicate acknowledgement cannot survive a failure terminal: the
        // internal-failure policy admits none, partial, or unknown, and this
        // attempt itself committed nothing, so effect-free evidence at the
        // call's expected generation is the truthful degradation. The prior
        // committed effect is still anchored by the earlier attempt's receipt.
        let committed_effect = if !call.operation.mutates_provider_state()
            || committed_effect.state() == CommittedEffectState::Duplicate
        {
            CommittedEffectEvidence::none(Some(call.expected_state_generation))
        } else {
            committed_effect
        };
        let terminal_code = if committed_effect.state() == CommittedEffectState::Committed {
            TerminalCode::Partial
        } else {
            TerminalCode::InternalFailure
        };
        Self {
            operation: call.operation,
            provider_id: call.provider_id.clone(),
            terminal_code,
            committed_effect,
            fallback: FallbackDirective::forbidden(),
            operation_id,
            exact_scope_sha256,
            diagnostic_id: Some(diagnostic_id),
        }
    }

    /// Creates a canonical unknown-effect terminal for a mutating call after
    /// provider dispatch.
    ///
    /// The typed digest is an adapter-issued reconciliation receipt for the
    /// uncertain interaction, not proof that any provider effect committed.
    /// Read-only or publicly corrupted calls cannot truthfully carry unknown
    /// effect evidence and fail closed to an effect-free internal failure.
    #[must_use]
    pub fn effect_unknown_for_call(
        call: &ProviderCall,
        reconciliation_receipt_sha256: [u8; 32],
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        Self::effect_unknown_for_call_with_action(
            call,
            reconciliation_receipt_sha256,
            UNKNOWN_EFFECT_RECONCILIATION_ACTION,
            diagnostic_id,
        )
    }

    /// Creates a canonical unknown-effect terminal for a mutating call after
    /// provider dispatch, carrying an adapter-owned reconciliation action.
    ///
    /// Behaves exactly like [`Self::effect_unknown_for_call`] except that the
    /// reconciliation action names the adapter's recovery procedure instead
    /// of the API-owned canonical action.
    #[must_use]
    pub fn effect_unknown_for_call_with_action(
        call: &ProviderCall,
        reconciliation_receipt_sha256: [u8; 32],
        reconciliation_action: &str,
        diagnostic_id: impl AsRef<str>,
    ) -> Self {
        // The envelope, not the dispatch gate: this factory mints a terminal
        // for a call the fabric already admitted, so re-running the
        // sanitization check here would turn a genuine post-dispatch
        // uncertainty into a spurious internal failure.
        let valid_mutating_call =
            call.operation.mutates_provider_state() && call.validate_envelope().is_ok();
        if !valid_mutating_call {
            return Self::internal_failure_before_dispatch_for_call(call, diagnostic_id);
        }

        let diagnostic_id = normalized_terminal_text(
            diagnostic_id.as_ref(),
            contract::TERMINAL_DIAGNOSTIC_ID_MAX_BYTES,
            INTERNAL_FAILURE_DIAGNOSTIC_ID,
        );
        Self {
            operation: call.operation,
            provider_id: call.provider_id.clone(),
            terminal_code: TerminalCode::EffectUnknown,
            committed_effect: CommittedEffectEvidence::unknown_from_reconciliation_digest_action(
                reconciliation_receipt_sha256,
                reconciliation_action,
            ),
            fallback: FallbackDirective::forbidden(),
            operation_id: call.operation_id.clone(),
            exact_scope_sha256: call.exact_scope.exact_scope_sha256(),
            diagnostic_id: Some(diagnostic_id),
        }
    }

    /// Replaces only the public operation and exact-scope identities after
    /// validating the complete reconstructed terminal record.
    pub fn try_with_identity(
        self,
        operation_id: impl Into<String>,
        exact_scope_sha256: impl Into<String>,
    ) -> Result<Self, ApiError> {
        Self::new(
            self.operation,
            self.provider_id,
            self.terminal_code,
            self.committed_effect,
            self.fallback,
            operation_id,
            exact_scope_sha256,
            self.diagnostic_id,
        )
    }

    /// Returns the provider operation bound to this terminal.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.operation
    }

    /// Returns the provider that produced this terminal.
    #[must_use]
    pub const fn provider_id(&self) -> &OwnedProviderId {
        &self.provider_id
    }

    /// Returns the closed terminal code.
    #[must_use]
    pub const fn terminal_code(&self) -> TerminalCode {
        self.terminal_code
    }

    /// Returns structured committed-effect evidence.
    #[must_use]
    pub const fn committed_effect(&self) -> &CommittedEffectEvidence {
        &self.committed_effect
    }

    /// Returns the explicit fallback policy decision.
    #[must_use]
    pub const fn fallback(&self) -> &FallbackDirective {
        &self.fallback
    }

    /// Returns the stable operation identity.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the exact-scope digest.
    #[must_use]
    pub fn exact_scope_sha256(&self) -> &str {
        &self.exact_scope_sha256
    }

    /// Returns the effect receipt digest without duplicating its storage.
    #[must_use]
    pub fn provider_receipt_sha256(&self) -> Option<&str> {
        self.committed_effect.provider_receipt_sha256()
    }

    /// Returns the optional stable diagnostic identity.
    #[must_use]
    pub fn diagnostic_id(&self) -> Option<&str> {
        self.diagnostic_id.as_deref()
    }

    /// Borrows the generated canonical summary shape.
    #[must_use]
    pub fn borrowed(&self) -> contract::TerminalSummary<'_> {
        contract::TerminalSummary {
            operation_kind: self.operation.as_wire(),
            provider_id: self.provider_id.as_str(),
            terminal_code: self.terminal_code,
            committed_effect: self.committed_effect.borrowed(),
            fallback: self.fallback.borrowed(),
            operation_id: &self.operation_id,
            exact_scope_digest: &self.exact_scope_sha256,
            diagnostic_id: self.diagnostic_id(),
        }
    }
}

const fn effect_matches_expectation(
    expectation: CommittedEffectExpectation,
    state: CommittedEffectState,
) -> bool {
    match expectation {
        // A duplicate acknowledgement is an operation-specific success: the
        // effect exists, this attempt did not create it, and delivery is at
        // least once, so every mutating operation can legitimately produce one.
        CommittedEffectExpectation::OperationSpecific
        | CommittedEffectExpectation::NoneOrOperationSpecific => {
            matches!(
                state,
                CommittedEffectState::None
                    | CommittedEffectState::Committed
                    | CommittedEffectState::Duplicate
            )
        }
        CommittedEffectExpectation::None => matches!(state, CommittedEffectState::None),
        CommittedEffectExpectation::NonePartialOrUnknown => matches!(
            state,
            CommittedEffectState::None
                | CommittedEffectState::Partial
                | CommittedEffectState::Unknown
        ),
        CommittedEffectExpectation::NoneOrUnknown => {
            matches!(
                state,
                CommittedEffectState::None | CommittedEffectState::Unknown
            )
        }
        CommittedEffectExpectation::Partial => matches!(state, CommittedEffectState::Partial),
        CommittedEffectExpectation::Unknown => matches!(state, CommittedEffectState::Unknown),
    }
}

fn normalized_pre_dispatch_failure_code(terminal_code: TerminalCode) -> TerminalCode {
    let is_failure = !matches!(
        terminal_code,
        TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
    );
    let admits_none = contract::TERMINAL_CODE_POLICIES
        .iter()
        .find(|policy| policy.terminal_code == terminal_code)
        .is_some_and(|policy| {
            effect_matches_expectation(policy.effect_expectation, CommittedEffectState::None)
        });
    if is_failure && admits_none {
        terminal_code
    } else {
        TerminalCode::InternalFailure
    }
}

/// Provider-neutral operation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReply {
    /// Typed terminal information.
    pub terminal: TerminalRecord,
    /// Optional canonical successful or partial result payload.
    pub payload: Option<CanonicalPayload>,
    /// Bounded diagnostic warnings.
    pub warnings: Vec<String>,
    /// Opaque optional extensions.
    pub extensions: Vec<OwnedOpaqueExtension>,
    /// Provider-local generation observed after the call.
    pub state_generation: u64,
}

impl ProviderReply {
    /// Revalidates provider-owned response content against the effective byte ceiling.
    pub fn validate(&self, response_bytes: u64) -> Result<(), ApiError> {
        let terminal_code = self.terminal.terminal_code();
        if self.payload.is_some()
            && !matches!(
                terminal_code,
                TerminalCode::Success | TerminalCode::SuccessZeroResults | TerminalCode::Partial
            )
        {
            return Err(ApiError::PayloadForbiddenForTerminal { terminal_code });
        }
        if self.warnings.len() > 32 {
            return Err(ApiError::TooManyBoundaryItems {
                field: "warnings",
                maximum: 32,
            });
        }
        let (maximum_extensions, maximum_extension_bytes) =
            if self.terminal.operation() == ProviderOperation::Recall {
                (16, 131_072_u64)
            } else {
                (32, 262_144_u64)
            };
        if self.extensions.len() > maximum_extensions {
            return Err(ApiError::TooManyBoundaryItems {
                field: "extensions",
                maximum: maximum_extensions,
            });
        }

        if let Some(payload) = &self.payload {
            payload.validate()?;
        }
        let mut total_extension_bytes = 0_u64;
        for extension in &self.extensions {
            extension.validate()?;
            let extension_bytes =
                u64::try_from(extension.canonical_payload.len()).unwrap_or(u64::MAX);
            if extension_bytes > maximum_extension_bytes {
                return Err(ApiError::BoundaryBytesExceeded {
                    field: "extension_canonical_payload",
                    maximum: maximum_extension_bytes,
                });
            }
            total_extension_bytes = total_extension_bytes.saturating_add(extension_bytes);
        }
        if self.terminal.operation() == ProviderOperation::Observe
            && total_extension_bytes > 524_288
        {
            return Err(ApiError::BoundaryBytesExceeded {
                field: "extensions",
                maximum: 524_288,
            });
        }
        let aggregate_bytes = encoded_provider_reply_bytes(self);
        if aggregate_bytes > response_bytes {
            return Err(ApiError::BoundaryBytesExceeded {
                field: "response",
                maximum: response_bytes,
            });
        }
        Ok(())
    }
}

fn encoded_provider_call_bytes(call: &ProviderCall) -> u64 {
    let mut total = framed_str_bytes(call.operation.capability_id());
    total = total.saturating_add(framed_str_bytes(call.provider_id.as_str()));
    total = total.saturating_add(8);
    total = total.saturating_add(framed_str_bytes(&call.ready_receipt_sha256));
    total = total.saturating_add(encoded_scope_bytes(&call.exact_scope));
    total = total.saturating_add(framed_str_bytes(&call.request_id));
    total = total.saturating_add(framed_str_bytes(&call.operation_id));
    total = total.saturating_add(8);
    total = total.saturating_add(encoded_optional_str_bytes(call.idempotency_key.as_deref()));
    total = total.saturating_add(8);
    total = total.saturating_add(8);
    total = total.saturating_add(framed_str_bytes("live"));
    total = total.saturating_add(encoded_payload_bytes(&call.payload));
    total = total.saturating_add(8);
    for capability in &call.required_capabilities {
        total = total.saturating_add(framed_str_bytes(capability.as_str()));
    }
    total = total.saturating_add(8);
    for extension in &call.extensions {
        total = total.saturating_add(encoded_extension_bytes(extension));
    }
    total
}

fn encoded_provider_reply_bytes(reply: &ProviderReply) -> u64 {
    let terminal = &reply.terminal;
    let mut total = framed_str_bytes(terminal.operation().as_wire());
    total = total.saturating_add(framed_str_bytes(terminal.provider_id().as_str()));
    total = total.saturating_add(framed_str_bytes(terminal.terminal_code().as_wire()));
    total = total.saturating_add(encoded_committed_effect_bytes(terminal.committed_effect()));
    total = total.saturating_add(encoded_fallback_bytes(terminal.fallback()));
    total = total.saturating_add(framed_str_bytes(terminal.operation_id()));
    total = total.saturating_add(framed_str_bytes(terminal.exact_scope_sha256()));
    total = total.saturating_add(encoded_optional_str_bytes(terminal.diagnostic_id()));
    total = total.saturating_add(1);
    if let Some(payload) = &reply.payload {
        total = total.saturating_add(encoded_payload_bytes(payload));
    }
    total = total.saturating_add(encoded_string_vector_bytes(&reply.warnings));
    total = total.saturating_add(8);
    for extension in &reply.extensions {
        total = total.saturating_add(encoded_extension_bytes(extension));
    }
    total.saturating_add(8)
}

fn encoded_committed_effect_bytes(effect: &CommittedEffectEvidence) -> u64 {
    let mut total = framed_str_bytes(effect.state().as_wire());
    total = total.saturating_add(encoded_optional_str_bytes(effect.committed_boundary()));
    total = total.saturating_add(encoded_optional_u64_bytes(effect.state_generation_before()));
    total = total.saturating_add(encoded_optional_u64_bytes(effect.state_generation_after()));
    total = total.saturating_add(encoded_string_vector_bytes(effect.committed_item_refs()));
    total = total.saturating_add(encoded_string_vector_bytes(effect.uncommitted_item_refs()));
    total = total.saturating_add(encoded_optional_str_bytes(effect.provider_receipt_sha256()));
    total = total.saturating_add(encoded_optional_str_bytes(
        effect.duplicate_of_idempotency_key(),
    ));
    total = total.saturating_add(encoded_optional_str_bytes(
        effect.duplicate_of_operation_id(),
    ));
    total = total.saturating_add(encoded_optional_str_bytes(effect.reconciliation_action()));
    total.saturating_add(encoded_optional_str_bytes(effect.verification_sha256()))
}

fn encoded_fallback_bytes(fallback: &FallbackDirective) -> u64 {
    let mut total = framed_str_bytes(fallback.eligibility().as_wire());
    total = total.saturating_add(encoded_optional_str_bytes(
        fallback.source_provider_id().map(OwnedProviderId::as_str),
    ));
    total = total.saturating_add(1);
    if let Some(policy) = fallback.policy() {
        total = total.saturating_add(framed_str_bytes(policy.policy_id()));
        total = total.saturating_add(8);
        total = total.saturating_add(framed_str_bytes(policy.target_provider_id().as_str()));
    }
    total.saturating_add(encoded_optional_str_bytes(fallback.reason()))
}

fn encoded_optional_u64_bytes(value: Option<u64>) -> u64 {
    1_u64.saturating_add(value.map_or(0, |_| 8))
}

fn encoded_string_vector_bytes(values: &[String]) -> u64 {
    values.iter().fold(8_u64, |total, value| {
        total.saturating_add(framed_str_bytes(value))
    })
}

fn encoded_scope_bytes(scope: &OwnedExactScope) -> u64 {
    // Seven length-framed strings and no scalar. The exact scope carries a
    // `resolved_scope_digest` string, not the fixed-width `scope_revision`
    // counter it replaced, so the accounting must frame that seventh string
    // and must not keep charging eight bytes for a field that no longer
    // exists. `OwnedExactScope::exact_scope_sha256` absorbs exactly the same
    // seven length-framed values; the two must not disagree.
    let mut total = 0_u64;
    for value in [
        &scope.profile_id,
        &scope.project_id,
        &scope.repository_identity,
        &scope.worktree_identity,
        &scope.branch_identity,
        &scope.agent_session_id,
        &scope.resolved_scope_digest,
    ] {
        total = total.saturating_add(framed_str_bytes(value));
    }
    total
}

fn encoded_payload_bytes(payload: &CanonicalPayload) -> u64 {
    framed_str_bytes(payload.contract_id.as_str())
        .saturating_add(framed_slice_bytes(&payload.bytes))
        .saturating_add(framed_str_bytes(&payload.sha256))
}

fn encoded_extension_bytes(extension: &OwnedOpaqueExtension) -> u64 {
    framed_str_bytes(extension.extension_id.as_str())
        .saturating_add(4)
        .saturating_add(1)
        .saturating_add(framed_str_bytes(&extension.payload_sha256))
        .saturating_add(framed_slice_bytes(&extension.canonical_payload))
}

fn encoded_optional_str_bytes(value: Option<&str>) -> u64 {
    1_u64.saturating_add(value.map_or(0, framed_str_bytes))
}

fn framed_str_bytes(value: &str) -> u64 {
    framed_slice_bytes(value.as_bytes())
}

fn framed_slice_bytes(value: &[u8]) -> u64 {
    8_u64.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
}

/// Compatible handshake request.
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    /// Selected provider identity.
    pub provider_id: OwnedProviderId,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Exact TraceDecay-owned scope.
    pub exact_scope: OwnedExactScope,
    /// Stable request identity.
    pub request_id: String,
    /// Mandatory requested capabilities.
    pub required_capabilities: BTreeSet<OwnedVersionedId>,
    /// Finite host ceilings.
    pub host_limits: ProviderLimits,
    /// Live request control.
    pub control: OperationControl,
    /// Canonical 32-byte challenge nonce.
    pub challenge_nonce: [u8; 32],
}

/// Builder payload for one provider handshake request.
#[derive(Clone, Debug)]
pub struct HandshakeRequestParts {
    /// Selected provider identity.
    pub provider_id: OwnedProviderId,
    /// Accepted registration revision.
    pub registration_revision: u64,
    /// Exact TraceDecay-owned scope.
    pub exact_scope: OwnedExactScope,
    /// Stable request identity.
    pub request_id: String,
    /// Mandatory requested capabilities.
    pub required_capabilities: Vec<OwnedVersionedId>,
    /// Finite host ceilings.
    pub host_limits: ProviderLimits,
    /// Live request control.
    pub control: OperationControl,
    /// Canonical 32-byte challenge nonce.
    pub challenge_nonce: [u8; 32],
}

impl HandshakeRequest {
    /// Validates one handshake request assembled from explicit parts.
    pub fn new(parts: HandshakeRequestParts) -> Result<Self, ApiError> {
        let mut capability_set = BTreeSet::new();
        for capability in parts.required_capabilities {
            let capability_name = capability.as_str().to_owned();
            if !capability_set.insert(capability) {
                return Err(ApiError::DuplicateCapability(capability_name));
            }
        }
        let request = Self {
            provider_id: parts.provider_id,
            registration_revision: parts.registration_revision,
            exact_scope: parts.exact_scope,
            request_id: parts.request_id,
            required_capabilities: capability_set,
            host_limits: parts.host_limits,
            control: parts.control,
            challenge_nonce: parts.challenge_nonce,
        };
        request.validate()?;
        Ok(request)
    }

    /// Revalidates the complete public handshake request after mutation.
    pub fn validate(&self) -> Result<(), ApiError> {
        contract::ProviderId::new(self.provider_id.as_str())
            .map_err(ApiError::InvalidProviderId)?;
        if self.registration_revision == 0 {
            return Err(ApiError::InvalidRegistrationRevision);
        }
        self.exact_scope.validate()?;
        require_non_empty(&self.request_id, "request_id")?;
        require_bounded_canonical_text(
            &self.request_id,
            "request_id",
            contract::TERMINAL_OPERATION_ID_MAX_BYTES,
        )?;
        for capability in &self.required_capabilities {
            CapabilityId::new(capability.as_str()).map_err(ApiError::InvalidVersionedId)?;
        }
        self.host_limits.validate()?;
        Ok(())
    }
}

/// Successful or failed handshake response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeResponse {
    /// Typed terminal information.
    pub terminal: TerminalRecord,
    /// Provider descriptor only when identity and compatibility were verified.
    pub descriptor: Option<ProviderDescriptor>,
    /// Opaque runtime instance identity.
    pub provider_instance_id: Option<String>,
    /// Provider-local state namespace.
    pub state_namespace: Option<String>,
    /// Accepted exact coding scope.
    pub accepted_scope: Option<OwnedExactScope>,
    /// Effective lower host/provider ceilings.
    pub effective_limits: Option<ProviderLimits>,
    /// Expiring ready-receipt digest.
    pub ready_receipt_sha256: Option<String>,
    /// Bounded warnings.
    pub warnings: Vec<String>,
}

/// Object-safe provider implementation boundary.
pub trait MemoryProvider: Send + Sync + 'static {
    /// Returns the provider's current real descriptor without fabricating readiness.
    fn descriptor(&self) -> ProviderDescriptor;

    /// Performs the read-only compatible handshake for an exact scope.
    fn handshake(&self, request: &HandshakeRequest) -> HandshakeResponse;

    /// Executes one capability-routed provider operation.
    fn invoke(&self, call: &ProviderCall) -> ProviderReply;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn test_limits() -> ProviderLimits {
        ProviderLimits {
            request_bytes: 1_024,
            response_bytes: 2_048,
            observation_batch_items: 8,
            recall_candidates: 16,
            concurrent_operations: 2,
            operation_millis: 500,
            snapshot_bytes: 4_096,
            inspection_items: 64,
        }
    }

    fn test_scope() -> Result<OwnedExactScope, ApiError> {
        OwnedExactScope::new(
            "profile-1",
            "project-1",
            "repo-1",
            "worktree-1",
            "refs/heads/main",
            "session-1",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
    }

    #[test]
    fn unknown_capability_id_projection_round_trips_opaquely_but_cannot_satisfy_selection()
    -> Result<(), ApiError> {
        let unknown = OwnedVersionedId::new("vendor.future-capability.v7")?;
        let descriptor = ProviderDescriptor::new(
            OwnedProviderId::new("test.provider")?,
            "a".repeat(64),
            "state.v1",
            0,
            [
                OwnedVersionedId::new("provider.health.v1")?,
                OwnedVersionedId::new("observation.accept.v1")?,
                OwnedVersionedId::new("recall.query.v1")?,
                unknown.clone(),
            ],
            test_limits(),
        )?;

        let wire_capabilities = descriptor
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect::<Vec<_>>();
        let decoded_capabilities: BTreeSet<OwnedVersionedId> = wire_capabilities
            .iter()
            .map(|capability| {
                // `ProviderDescriptor` carries only the registry wire ID
                // projection. Validate that projection through the generated
                // DTO identity, then own it again without semantic rewriting.
                let wire_id =
                    CapabilityId::new(capability).map_err(ApiError::InvalidVersionedId)?;
                OwnedVersionedId::new(wire_id.as_str())
            })
            .collect::<Result<_, _>>()?;

        assert_eq!(decoded_capabilities, descriptor.capabilities);
        assert!(descriptor.capabilities.contains(&unknown));
        assert!(!is_known_capability(unknown.as_str()));
        assert!(!descriptor.supports(unknown.as_str()));

        let request = HandshakeRequest::new(HandshakeRequestParts {
            provider_id: OwnedProviderId::new("test.provider")?,
            registration_revision: 1,
            exact_scope: test_scope()?,
            request_id: "unknown-selection".to_owned(),
            required_capabilities: vec![unknown.clone()],
            host_limits: test_limits(),
            control: OperationControl::new(i64::MAX, 1_000, CancellationToken::new()),
            challenge_nonce: [0; 32],
        })?;

        assert_eq!(request.required_capabilities, BTreeSet::from([unknown]));
        assert!(
            !request
                .required_capabilities
                .iter()
                .all(|capability| descriptor.supports(capability.as_str()))
        );
        Ok(())
    }

    #[test]
    fn cancellation_timestamp_is_singleton_across_clones_and_racers() -> Result<(), String> {
        const RACERS: usize = 16;

        let cancellation = CancellationToken::new();
        let control = OperationControl::new(i64::MAX, 1_000, cancellation.clone());
        let barrier = Arc::new(Barrier::new(RACERS.saturating_add(1)));
        let mut handles = Vec::with_capacity(RACERS);
        for _ in 0..RACERS {
            let barrier = Arc::clone(&barrier);
            let cancellation = cancellation.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cancellation.cancel();
                cancellation.cancelled_at()
            }));
        }
        barrier.wait();

        let mut timestamps = Vec::with_capacity(RACERS);
        for handle in handles {
            timestamps.push(
                handle
                    .join()
                    .map_err(|_| "cancellation racer panicked".to_owned())?,
            );
        }
        let first_timestamp = timestamps
            .first()
            .copied()
            .flatten()
            .ok_or_else(|| "cancellation winner did not publish a timestamp".to_owned())?;

        assert!(
            timestamps
                .iter()
                .all(|timestamp| *timestamp == Some(first_timestamp))
        );
        assert_eq!(cancellation.cancelled_at(), Some(first_timestamp));
        assert!(cancellation.is_cancelled());
        assert_eq!(control.clone().snapshot(), Err(TerminalCode::Cancelled));
        assert_eq!(control.snapshot(), Err(TerminalCode::Cancelled));
        Ok(())
    }

    #[test]
    fn cancellation_before_deadline_wins() {
        let cancellation = CancellationToken::new();
        let control = OperationControl::new(i64::MAX, 100, cancellation.clone());

        cancellation.cancel();

        assert_eq!(control.snapshot(), Err(TerminalCode::Cancelled));
    }

    #[test]
    fn deadline_before_cancellation_wins() {
        let cancellation = CancellationToken::new();
        let control = OperationControl::new(i64::MAX, 0, cancellation.clone());

        cancellation.cancel();

        assert_eq!(control.snapshot(), Err(TerminalCode::DeadlineExceeded));
    }

    #[test]
    fn terminal_classifier_ignores_stale_clock_when_cancellation_is_recorded() {
        let start = Instant::now();
        let deadline = saturating_instant_add(start, Duration::from_millis(2));
        let before_deadline = saturating_instant_add(start, Duration::from_millis(1));
        let after_deadline = saturating_instant_add(start, Duration::from_millis(3));

        // A stale pre-mutex clock sample must not turn a post-deadline
        // cancellation into Cancelled.
        assert_eq!(
            classify_snapshot(Some(after_deadline), before_deadline, deadline, Some(1)),
            Err(TerminalCode::DeadlineExceeded)
        );
        // A stale post-deadline clock sample must not override a cancellation
        // event that the mutex read recorded before the deadline.
        assert_eq!(
            classify_snapshot(Some(before_deadline), after_deadline, deadline, None),
            Err(TerminalCode::Cancelled)
        );
        assert_eq!(
            classify_snapshot(Some(deadline), after_deadline, deadline, None),
            Err(TerminalCode::Cancelled)
        );
        assert_eq!(
            classify_snapshot(None, after_deadline, deadline, None),
            Err(TerminalCode::DeadlineExceeded)
        );
    }

    #[test]
    fn exact_and_zero_deadlines_fail_closed() -> Result<(), String> {
        let zero = OperationControl::new(i64::MAX, 0, CancellationToken::new());
        assert_eq!(zero.snapshot(), Err(TerminalCode::DeadlineExceeded));

        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())
            .and_then(|elapsed| {
                i64::try_from(elapsed.as_micros())
                    .map_err(|_| "system clock does not fit the wire deadline".to_owned())
            })?;
        let exact = OperationControl::new(now_micros, 100, CancellationToken::new());
        assert_eq!(exact.remaining_millis(), 0);
        assert_eq!(exact.snapshot(), Err(TerminalCode::DeadlineExceeded));
        Ok(())
    }

    #[test]
    fn deadline_offset_and_live_budget_share_submillisecond_boundary() {
        assert_eq!(deadline_duration(0), Duration::ZERO);
        assert_eq!(deadline_duration(1), Duration::from_nanos(1));
        assert_eq!(deadline_duration(2), Duration::from_nanos(1_000_001));

        let control = OperationControl::new(i64::MAX, 2, CancellationToken::new());
        let start = control.budget_started_at;
        assert_eq!(control.live_remaining_millis_at(start), Some(2));
        assert_eq!(
            control
                .live_remaining_millis_at(saturating_instant_add(start, Duration::from_millis(1),)),
            Some(1)
        );
        let deadline = saturating_instant_add(start, deadline_duration(2));
        assert_eq!(control.deadline_at, deadline);
        assert_eq!(control.live_remaining_millis_at(deadline), None);
    }

    #[test]
    fn deadline_budget_overflow_saturates_without_reopening_budget() {
        let maximum_duration = deadline_duration(u64::MAX);
        let expected_duration = Duration::from_millis(u64::MAX.saturating_sub(1))
            .checked_add(Duration::from_nanos(1))
            .unwrap_or(Duration::MAX);
        assert_eq!(maximum_duration, expected_duration);

        let control = OperationControl::new(i64::MAX, u64::MAX, CancellationToken::new());

        assert!(control.deadline_at >= control.budget_started_at);
        assert!(control.snapshot().is_ok());
    }
}
