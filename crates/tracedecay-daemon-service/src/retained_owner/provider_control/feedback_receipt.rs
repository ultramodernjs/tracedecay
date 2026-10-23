//! Authenticated feedback assertions and deletion command identities retained by the recall ledger.
//!
//! Acceptance proves the host durably retained the caller's command identity. It
//! does not establish objective usefulness, provider completion, or permission
//! to mutate canonical facts. The controller resolves and authorizes the target
//! before acceptance, then dispatches only with the opaque accepted value.
//! Evidence references remain bounded caller claims, preserved unchanged. Retry records share the recall ledger's lifetime: no TTL or eviction.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tracedecay_contracts::retained_surfaces::{
    MAX_PROVIDER_CONTROL_EVIDENCE_REFS, MAX_PROVIDER_CONTROL_REFERENCE_BYTES,
    ProviderControlRequestV1, ProviderDeleteBySourceRequestV1, ProviderFeedbackRequestV1,
};
use tracedecay_contracts::{RequestContext, RequestId, ResolvedScope, now_micros};
use tracedecay_domain::canonical_text::sha256_hex;
use tracedecay_domain::framed_log::{CHECKSUM_BYTES, checksum};
use tracedecay_domain::{ActorId, UtcMicros, canonical_json_bytes};
use tracedecay_memory_provider_registry::{
    LifecycleTarget, LifecycleTargetReference, OperationControl, OriginScopeEvidence,
    OwnedExactScope, OwnedProviderId, RecallOutcomeScopeV1, SourceAttribution, TerminalCode,
    recall_admission::source_attribution::{
        RecallOriginScopeEvidenceV1, RecallOriginalSourceIdentityV1, RecallRecordedValidityV1,
        RecallSourceAttributionV1,
    },
};
use tracedecay_private_fs::framed_log::{
    DirectorySyncPolicy, rename_noreplace, sync_parent_directory, with_owned_temp_publish,
};
use tracedecay_private_fs::{create_private_file, open_private_directory, open_private_file};
use tracedecay_runtime_core::storage::{PrivateStoreIo, reject_symlink_components};

#[cfg(test)]
use tracedecay_rusqlite_runtime::recall_admission::RecallAdmissionLedgerV1;

const ROOT_NAME: &str = "recall-source-commands-v1";
const LOCK_NAME: &str = ".admission.lock";
const RECEIPT_PREFIX: &str = "host-feedback-assertion-v1:";
const KEY_DOMAIN: &str = "tracedecay.host-source-command.request.v1";
const OPERATION_DOMAIN: &str = "tracedecay.host-source-command.operation.v1";
const MAGIC: &[u8; 8] = b"TDSCMD01";
const HEADER_BYTES: usize = MAGIC.len() + 4;
const MAX_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_ARTIFACT_FILES: usize = 16_384;
const MAX_ACCOUNTED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
// Accounting reserves cover the admission lock and per-file namespace overhead;
// they are conservative admission charges, not a filesystem allocation report.
const ROOT_RESERVED_BYTES: u64 = 4096;
const FILE_RESERVED_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeedbackAssertionPublicationV1 {
    /// This attempt did not publish a new receipt. It says nothing about an
    /// unreadable receipt left by an earlier attempt.
    NotAttempted,
    /// A complete receipt may be visible, but its durability was not confirmed.
    DurabilityUnknown,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostSourceCommandErrorV1 {
    #[error("invalid host source command: {0}")]
    Invalid(&'static str),
    #[cfg(test)]
    #[error("retained host source command is missing")]
    Missing,
    #[error("source command request identity is already bound to a different command")]
    Conflict,
    #[error("retained host source command is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("host source command stopped before durable acceptance: {0:?}")]
    Control(TerminalCode),
    #[error("recall ledger source command artifact capacity is exhausted")]
    CapacityExceeded,
    #[error("host source command storage failed ({publication:?}): {source}")]
    Storage {
        publication: FeedbackAssertionPublicationV1,
        #[source]
        source: io::Error,
    },
}

pub(crate) type FeedbackAssertionErrorV1 = HostSourceCommandErrorV1;

type Result<T> = std::result::Result<T, HostSourceCommandErrorV1>;

/// A value returned only after a complete immutable receipt has passed the
/// durability barrier. Deserializing a file does not construct this capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedFeedbackAssertionV1(StoredSourceCommandV1, String);

impl AcceptedFeedbackAssertionV1 {
    pub(crate) fn canonical_outcome_receipt(&self) -> &str {
        &self.1
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.0.operation_id
    }

    pub(crate) fn idempotency_key(&self) -> &str {
        &self.0.idempotency_key
    }

    #[cfg(test)]
    pub(crate) fn accepted_at(&self) -> UtcMicros {
        self.0.accepted_at
    }

    /// Compares every authenticated request, scope, target and source field.
    /// This check never substitutes for current source/target authorization.
    pub(crate) fn matches(
        &self,
        context: &RequestContext,
        request: &ProviderFeedbackRequestV1,
        target: &LifecycleTarget,
        original_attribution: &SourceAttribution,
    ) -> Result<bool> {
        Ok(self.0.binding
            == BoundSourceCommandV1::FeedbackAssertion(FeedbackAssertionBindingV1::prepare(
                context,
                request,
                target,
                original_attribution,
                self.0.accepted_at,
            )?))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FeedbackAssertionBindingV1 {
    actor: ActorId,
    request_id: RequestId,
    resolved_host_scope: ResolvedScope,
    request: ProviderFeedbackRequestV1,
    target: SourceCommandTargetV1,
}

/// A source target's original scope and source are retained in full in
/// `original_attribution`, after exact equality is checked against the resolved
/// `LifecycleTarget`. The delivery scope remains separate. The historical
/// `stable_memory_ref` field carries either a stable provider reference or an
/// opaque retained locator; `reference_kind` is omitted for legacy/stable
/// records so their durable bytes remain unchanged.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceCommandTargetV1 {
    provider_id: String,
    registration_revision: u64,
    delivery_scope: RecallOutcomeScopeV1,
    stable_memory_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference_kind: Option<SourceCommandReferenceKindV1>,
    original_attribution: RecallSourceAttributionV1,
}

/// Additive marker for the one non-legacy target kind. An absent marker is the
/// original stable-memory-reference encoding used by existing receipts.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SourceCommandReferenceKindV1 {
    RetainedSourceLocator,
}

impl FeedbackAssertionBindingV1 {
    fn prepare(
        context: &RequestContext,
        request: &ProviderFeedbackRequestV1,
        target: &LifecycleTarget,
        original_attribution: &SourceAttribution,
        accepted_at: UtcMicros,
    ) -> Result<Self> {
        context
            .validate()
            .map_err(|_| invalid("authenticated context"))?;
        validate_public_request(request, accepted_at)?;
        let resolved_target =
            prepare_target(target, original_attribution, &request.source.observation_id)?;
        let binding = Self {
            actor: context.actor().clone(),
            request_id: context.request_id().clone(),
            resolved_host_scope: context.scope().clone(),
            request: request.clone(),
            target: resolved_target,
        };
        binding.validate(accepted_at)?;
        Ok(binding)
    }

    fn validate(&self, accepted_at: UtcMicros) -> Result<()> {
        self.actor.validate().map_err(|_| invalid("actor"))?;
        RequestId::new(self.request_id.as_str()).map_err(|_| invalid("request identity"))?;
        self.resolved_host_scope
            .validate()
            .map_err(|_| invalid("resolved host scope"))?;
        validate_public_request(&self.request, accepted_at)?;
        if accepted_at.0 < 0 || self.target.registration_revision == 0 {
            return Err(invalid("acceptance time or registration revision"));
        }
        self.target
            .validate_for_observation(&self.request.source.observation_id)?;
        Ok(())
    }

    fn lookup_key(&self) -> Result<String> {
        request_key(
            &self.actor,
            &self.resolved_host_scope,
            SourceCommandKindV1::Feedback,
            &self.request_id,
        )
    }
}

/// Host acceptance of one immutable deletion request. This identity is not a
/// deletion fence, erasure receipt, or proof of provider-local deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedDeletionCommandV1(StoredSourceCommandV1);

impl AcceptedDeletionCommandV1 {
    pub(crate) fn operation_id(&self) -> &str {
        &self.0.operation_id
    }
    pub(crate) fn idempotency_key(&self) -> &str {
        &self.0.idempotency_key
    }
    pub(crate) fn accepted_at(&self) -> UtcMicros {
        self.0.accepted_at
    }
    pub(crate) fn matches(
        &self,
        context: &RequestContext,
        request: &ProviderDeleteBySourceRequestV1,
        target: &LifecycleTarget,
        original_attribution: &SourceAttribution,
    ) -> Result<bool> {
        Ok(self.0.binding
            == BoundSourceCommandV1::DeletionCommand(DeletionCommandBindingV1::prepare(
                context,
                request,
                target,
                original_attribution,
                self.0.accepted_at,
            )?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceCommandKindV1 {
    Feedback,
    DeleteBySource,
}

impl SourceCommandKindV1 {
    fn operation(self) -> &'static str {
        match self {
            Self::Feedback => "feedback",
            Self::DeleteBySource => "delete_by_source",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeletionCommandBindingV1 {
    actor: ActorId,
    request_id: RequestId,
    resolved_host_scope: ResolvedScope,
    request: ProviderDeleteBySourceRequestV1,
    target: SourceCommandTargetV1,
}

impl DeletionCommandBindingV1 {
    fn prepare(
        context: &RequestContext,
        request: &ProviderDeleteBySourceRequestV1,
        target: &LifecycleTarget,
        original_attribution: &SourceAttribution,
        accepted_at: UtcMicros,
    ) -> Result<Self> {
        context
            .validate()
            .map_err(|_| invalid("authenticated context"))?;
        validate_deletion_request(request, accepted_at)?;
        let target = prepare_target(target, original_attribution, &request.source.observation_id)?;
        let binding = Self {
            actor: context.actor().clone(),
            request_id: context.request_id().clone(),
            resolved_host_scope: context.scope().clone(),
            request: request.clone(),
            target,
        };
        binding.validate(accepted_at)?;
        Ok(binding)
    }

    fn validate(&self, accepted_at: UtcMicros) -> Result<()> {
        self.actor.validate().map_err(|_| invalid("actor"))?;
        RequestId::new(self.request_id.as_str()).map_err(|_| invalid("request identity"))?;
        self.resolved_host_scope
            .validate()
            .map_err(|_| invalid("resolved host scope"))?;
        validate_deletion_request(&self.request, accepted_at)?;
        if accepted_at.0 < 0 {
            return Err(invalid("acceptance time"));
        }
        self.target
            .validate_for_observation(&self.request.source.observation_id)
    }

    fn lookup_key(&self) -> Result<String> {
        request_key(
            &self.actor,
            &self.resolved_host_scope,
            SourceCommandKindV1::DeleteBySource,
            &self.request_id,
        )
    }
}

/// The complete storage protocol is deliberately closed to these two accepted
/// source commands. Snapshot/replay payloads use their own artifact owner.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BoundSourceCommandV1 {
    FeedbackAssertion(FeedbackAssertionBindingV1),
    DeletionCommand(DeletionCommandBindingV1),
}

impl From<FeedbackAssertionBindingV1> for BoundSourceCommandV1 {
    fn from(binding: FeedbackAssertionBindingV1) -> Self {
        Self::FeedbackAssertion(binding)
    }
}
impl From<DeletionCommandBindingV1> for BoundSourceCommandV1 {
    fn from(binding: DeletionCommandBindingV1) -> Self {
        Self::DeletionCommand(binding)
    }
}

impl BoundSourceCommandV1 {
    fn validate(&self, accepted_at: UtcMicros) -> Result<()> {
        match self {
            Self::FeedbackAssertion(binding) => binding.validate(accepted_at),
            Self::DeletionCommand(binding) => binding.validate(accepted_at),
        }
    }
    fn lookup_key(&self) -> Result<String> {
        match self {
            Self::FeedbackAssertion(binding) => binding.lookup_key(),
            Self::DeletionCommand(binding) => binding.lookup_key(),
        }
    }
    fn kind(&self) -> SourceCommandKindV1 {
        match self {
            Self::FeedbackAssertion(_) => SourceCommandKindV1::Feedback,
            Self::DeletionCommand(_) => SourceCommandKindV1::DeleteBySource,
        }
    }
}

impl SourceCommandTargetV1 {
    fn validate_for_observation(&self, observation_id: &str) -> Result<()> {
        let provider_id =
            OwnedProviderId::new(&self.provider_id).map_err(|_| invalid("producing provider"))?;
        let original_attribution = self
            .original_attribution
            .to_owned_attribution()
            .map_err(|_| invalid("original attribution"))?;
        original_attribution
            .origin_scope
            .recorded_scope()
            .map_err(|_| invalid("recorded original scope"))?;
        let target = LifecycleTarget {
            provider_id,
            registration_revision: self.registration_revision,
            original_scope: original_attribution.origin_scope,
            delivery_scope: scope_owned(&self.delivery_scope)?,
            source: original_attribution.source,
            reference: match self.reference_kind {
                Some(SourceCommandReferenceKindV1::RetainedSourceLocator) => {
                    LifecycleTargetReference::RetainedSourceLocator(self.stable_memory_ref.clone())
                }
                None => LifecycleTargetReference::StableMemoryRef(self.stable_memory_ref.clone()),
            },
        };
        target.validate().map_err(|_| invalid("lifecycle target"))?;
        if observation_id != target.source.observation_id {
            return Err(invalid("selected observation identity"));
        }
        Ok(())
    }
}

fn prepare_target(
    target: &LifecycleTarget,
    original_attribution: &SourceAttribution,
    observation_id: &str,
) -> Result<SourceCommandTargetV1> {
    target
        .validate()
        .map_err(|_| invalid("resolved lifecycle target"))?;
    original_attribution
        .validate()
        .map_err(|_| invalid("original attribution"))?;
    original_attribution
        .origin_scope
        .recorded_scope()
        .map_err(|_| invalid("recorded original source scope is required"))?;
    if target.source != original_attribution.source
        || target.original_scope != original_attribution.origin_scope
        || observation_id != original_attribution.source.observation_id
    {
        return Err(invalid("target and source attribution disagree"));
    }
    let (stable_memory_ref, reference_kind) = match &target.reference {
        LifecycleTargetReference::StableMemoryRef(value) => (value.clone(), None),
        LifecycleTargetReference::RetainedSourceLocator(value) => (
            value.clone(),
            Some(SourceCommandReferenceKindV1::RetainedSourceLocator),
        ),
        LifecycleTargetReference::RecallTraceRef(_)
        | LifecycleTargetReference::ContextPackItemRef(_) => {
            return Err(invalid("resolved source reference is required"));
        }
    };
    Ok(SourceCommandTargetV1 {
        provider_id: target.provider_id.as_str().to_owned(),
        registration_revision: target.registration_revision,
        delivery_scope: scope_wire(&target.delivery_scope),
        stable_memory_ref,
        reference_kind,
        original_attribution: attribution_wire(original_attribution),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredSourceCommandV1 {
    version: u32,
    lookup_key: String,
    binding: BoundSourceCommandV1,
    accepted_at: UtcMicros,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_outcome_receipt: Option<String>,
    operation_id: String,
    idempotency_key: String,
}

impl StoredSourceCommandV1 {
    fn new(binding: impl Into<BoundSourceCommandV1>, accepted_at: UtcMicros) -> Result<Self> {
        let binding = binding.into();
        binding.validate(accepted_at)?;
        let lookup_key = binding.lookup_key()?;
        let record = Self {
            version: 1,
            canonical_outcome_receipt: (binding.kind() == SourceCommandKindV1::Feedback)
                .then(|| format!("{RECEIPT_PREFIX}{lookup_key}")),
            operation_id: operation_uuid_v7(&lookup_key, accepted_at)?,
            idempotency_key: lookup_key.clone(),
            lookup_key,
            binding,
            accepted_at,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        self.binding.validate(self.accepted_at)?;
        if self.version != 1
            || self.lookup_key != self.binding.lookup_key()?
            || self.canonical_outcome_receipt
                != (self.binding.kind() == SourceCommandKindV1::Feedback)
                    .then(|| format!("{RECEIPT_PREFIX}{}", self.lookup_key))
            || self.operation_id != operation_uuid_v7(&self.lookup_key, self.accepted_at)?
            || self.idempotency_key != self.lookup_key
        {
            return Err(HostSourceCommandErrorV1::Corrupt("identity binding"));
        }
        Ok(())
    }
}

/// Execute on the controller's existing blocking pool using its original
/// live `OperationControl`, after current source/target authorization.
pub(crate) fn accept_feedback_assertion(
    ledger_path: &Path,
    context: &RequestContext,
    request: &ProviderFeedbackRequestV1,
    target: &LifecycleTarget,
    original_attribution: &SourceAttribution,
    control: &OperationControl,
) -> std::result::Result<AcceptedFeedbackAssertionV1, FeedbackAssertionErrorV1> {
    checkpoint(control)?;
    let binding = FeedbackAssertionBindingV1::prepare(
        context,
        request,
        target,
        original_attribution,
        now_micros(),
    )?;
    accepted_feedback(accept_at_root(
        &receipt_root(ledger_path)?,
        binding.into(),
        control,
        ArtifactQuota::DEFAULT,
        publish_receipt,
    )?)
}

pub(crate) fn accept_deletion_command(
    ledger_path: &Path,
    context: &RequestContext,
    request: &ProviderDeleteBySourceRequestV1,
    target: &LifecycleTarget,
    original_attribution: &SourceAttribution,
    control: &OperationControl,
) -> Result<AcceptedDeletionCommandV1> {
    checkpoint(control)?;
    let binding = DeletionCommandBindingV1::prepare(
        context,
        request,
        target,
        original_attribution,
        now_micros(),
    )?;
    accepted_deletion(accept_at_root(
        &receipt_root(ledger_path)?,
        binding.into(),
        control,
        ArtifactQuota::DEFAULT,
        publish_receipt,
    )?)
}

#[cfg(test)]
pub(crate) fn retained_feedback_assertion(
    ledger_path: &Path,
    context: &RequestContext,
    control: &OperationControl,
) -> Result<AcceptedFeedbackAssertionV1> {
    accepted_feedback(retained_source_command(
        ledger_path,
        context,
        SourceCommandKindV1::Feedback,
        control,
    )?)
}

#[cfg(test)]
pub(crate) fn retained_deletion_command(
    ledger_path: &Path,
    context: &RequestContext,
    control: &OperationControl,
) -> Result<AcceptedDeletionCommandV1> {
    accepted_deletion(retained_source_command(
        ledger_path,
        context,
        SourceCommandKindV1::DeleteBySource,
        control,
    )?)
}

#[cfg(test)]
fn retained_source_command(
    ledger_path: &Path,
    context: &RequestContext,
    kind: SourceCommandKindV1,
    control: &OperationControl,
) -> Result<StoredSourceCommandV1> {
    checkpoint(control)?;
    context
        .validate()
        .map_err(|_| invalid("authenticated context"))?;
    let key = request_key(context.actor(), context.scope(), kind, context.request_id())?;
    let root = receipt_root(ledger_path)?;
    prepare_root(&root, control)?;
    let _lock = acquire_admission_lock(&root, control)?;
    let path = receipt_path(&root, &key);
    let (file, record) = read_record(&path, control)?.ok_or(HostSourceCommandErrorV1::Missing)?;
    if record.lookup_key != key || record.binding.kind() != kind {
        return Err(HostSourceCommandErrorV1::Corrupt("request lookup kind/key"));
    }
    confirm_existing_durability(&path, &file, control)?;
    Ok(record)
}

// Called only on the successful return of durable acceptance/read methods.
fn accepted_feedback(record: StoredSourceCommandV1) -> Result<AcceptedFeedbackAssertionV1> {
    match (&record.binding, &record.canonical_outcome_receipt) {
        (BoundSourceCommandV1::FeedbackAssertion(_), Some(reference)) => {
            let reference = reference.clone();
            Ok(AcceptedFeedbackAssertionV1(record, reference))
        }
        _ => Err(HostSourceCommandErrorV1::Corrupt(
            "feedback acceptance kind",
        )),
    }
}

fn accepted_deletion(record: StoredSourceCommandV1) -> Result<AcceptedDeletionCommandV1> {
    if record.binding.kind() != SourceCommandKindV1::DeleteBySource
        || record.canonical_outcome_receipt.is_some()
    {
        return Err(HostSourceCommandErrorV1::Corrupt(
            "deletion acceptance kind",
        ));
    }
    Ok(AcceptedDeletionCommandV1(record))
}

#[derive(Clone, Copy)]
pub(super) struct ArtifactQuota {
    pub(super) maximum_files: usize,
    pub(super) maximum_bytes: u64,
    pub(super) maximum_record_bytes: usize,
}

impl ArtifactQuota {
    const DEFAULT: Self = Self {
        maximum_files: MAX_ARTIFACT_FILES,
        maximum_bytes: MAX_ACCOUNTED_ARTIFACT_BYTES,
        maximum_record_bytes: MAX_RECEIPT_BYTES,
    };
}

// The publish callback is private and used by tests to exercise failures at
// exact durability boundaries. Production always supplies publish_receipt.
fn accept_at_root(
    root: &Path,
    binding: BoundSourceCommandV1,
    control: &OperationControl,
    quota: ArtifactQuota,
    publish: impl FnOnce(&Path, &[u8], &OperationControl) -> Result<()>,
) -> Result<StoredSourceCommandV1> {
    checkpoint(control)?;
    binding.validate(now_micros())?;
    let key = binding.lookup_key()?;
    prepare_root(root, control)?;
    let _lock = acquire_admission_lock(root, control)?;
    let path = receipt_path(root, &key);
    if let Some((file, stored)) = read_record(&path, control)? {
        if stored.lookup_key != key {
            return Err(HostSourceCommandErrorV1::Corrupt("request lookup key"));
        }
        if stored.binding != binding {
            return Err(HostSourceCommandErrorV1::Conflict);
        }
        // Retry verification precedes quota admission: saturation never evicts
        // or prevents reading a live retry record. The fsync also reconciles a
        // complete record left by an earlier uncertain directory-sync failure.
        confirm_existing_durability(&path, &file, control)?;
        return Ok(stored);
    }
    checkpoint(control)?;
    let record = StoredSourceCommandV1::new(binding, now_micros())?;
    let frame = encode_record(&record)?;
    check_quota(root, frame.len(), quota, control)?;
    checkpoint(control)?;
    publish(&path, &frame, control)?;
    // Never replace successful persistence with a later cancellation. The
    // controller still checks live control before any provider dispatch.
    Ok(record)
}

fn receipt_root(ledger_path: &Path) -> Result<PathBuf> {
    if !ledger_path.is_absolute() {
        return Err(invalid("host ledger path must be absolute"));
    }
    let parent = ledger_path
        .parent()
        .ok_or_else(|| invalid("host ledger parent"))?;
    Ok(parent.join(ROOT_NAME))
}

fn receipt_path(root: &Path, key: &str) -> PathBuf {
    // key is derived by request_key, never a submitted path or opaque ref.
    root.join(format!("{key}.receipt"))
}

/// Only host-fixed descendants of the existing ledger root may be passed.
pub(super) fn prepare_root(root: &Path, control: &OperationControl) -> Result<()> {
    checkpoint(control)?;
    let mut terminal = None;
    PrivateStoreIo::create_dir_all_durable_interruptible(root, &mut || {
        control.snapshot().map(|_| ()).map_err(|code| {
            terminal = Some(code);
            io::Error::new(
                io::ErrorKind::Interrupted,
                "original operation control stopped",
            )
        })
    })
    .map_err(|source| match terminal {
        Some(code) => HostSourceCommandErrorV1::Control(code),
        None => storage_unpublished(source),
    })?;
    reject_symlink_components(root, "retained ledger artifact root")
        .map_err(storage_unpublished)?;
    drop(open_private_directory(root).map_err(storage_unpublished)?);
    checkpoint(control)
}

pub(super) fn acquire_admission_lock(root: &Path, control: &OperationControl) -> Result<File> {
    checkpoint(control)?;
    let path = root.join(LOCK_NAME);
    let file = match create_private_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_private_file(&path).map_err(storage_unpublished)?
        }
        Err(error) => return Err(storage_unpublished(error)),
    };
    loop {
        let remaining = control
            .snapshot()
            .map_err(HostSourceCommandErrorV1::Control)?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => {
                checkpoint(control)?;
                return Ok(file);
            }
            Err(error) if tracedecay_private_fs::is_lock_contended(&error) => {
                std::thread::sleep(Duration::from_millis(remaining.remaining_millis.min(1)));
            }
            Err(error) => return Err(storage_unpublished(error)),
        }
    }
}

/// The caller holds this root's admission lock; pending stage files are charged.
pub(super) fn check_quota(
    root: &Path,
    incoming: usize,
    quota: ArtifactQuota,
    control: &OperationControl,
) -> Result<()> {
    if incoming > quota.maximum_record_bytes {
        return Err(invalid("receipt byte bound"));
    }
    if incoming > available_artifact_bytes(root, quota, control)? {
        return Err(HostSourceCommandErrorV1::CapacityExceeded);
    }
    Ok(())
}

/// Available bytes for one complete ENCODED artifact, after reserving the root
/// lock and the incoming file's namespace overhead. Typed carrier owners must
/// also subtract their frame/metadata overhead and conservative encoding
/// expansion before deriving a raw provider-payload budget.
///
/// The caller holds the root admission lock throughout calculation/publication,
/// or reacquires it and calls `check_quota` with the final encoded length before
/// publication. This is the same bounded quota scan, not a cached reservation.
pub(super) fn available_artifact_bytes(
    root: &Path,
    quota: ArtifactQuota,
    control: &OperationControl,
) -> Result<usize> {
    checkpoint(control)?;
    let mut count = 0usize;
    let mut bytes = ROOT_RESERVED_BYTES
        .checked_add(FILE_RESERVED_BYTES)
        .ok_or(HostSourceCommandErrorV1::CapacityExceeded)?;
    if quota.maximum_files == 0 || bytes > quota.maximum_bytes {
        return Err(HostSourceCommandErrorV1::CapacityExceeded);
    }
    let entries = std::fs::read_dir(root).map_err(storage_unpublished)?;
    for entry in entries {
        checkpoint(control)?;
        let entry = entry.map_err(storage_unpublished)?;
        if entry.file_name() == LOCK_NAME {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or(HostSourceCommandErrorV1::CapacityExceeded)?;
        // Leave room for the incoming artifact and stop before scanning past
        // the count budget. Crashed staging files are charged; nothing is swept.
        if count >= quota.maximum_files {
            return Err(HostSourceCommandErrorV1::CapacityExceeded);
        }
        let file = open_private_file(&entry.path()).map_err(storage_unpublished)?;
        bytes = bytes
            .checked_add(file.metadata().map_err(storage_unpublished)?.len())
            .and_then(|value| value.checked_add(FILE_RESERVED_BYTES))
            .ok_or(HostSourceCommandErrorV1::CapacityExceeded)?;
        if bytes > quota.maximum_bytes {
            return Err(HostSourceCommandErrorV1::CapacityExceeded);
        }
    }
    checkpoint(control)?;
    let remaining = quota
        .maximum_bytes
        .checked_sub(bytes)
        .ok_or(HostSourceCommandErrorV1::CapacityExceeded)?;
    let per_record = u64::try_from(quota.maximum_record_bytes)
        .map_err(|_| HostSourceCommandErrorV1::CapacityExceeded)?;
    usize::try_from(remaining.min(per_record))
        .map_err(|_| HostSourceCommandErrorV1::CapacityExceeded)
}

fn read_record(
    path: &Path,
    control: &OperationControl,
) -> Result<Option<(File, StoredSourceCommandV1)>> {
    checkpoint(control)?;
    let mut file = match open_private_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(storage_unpublished(error)),
    };
    let length = file.metadata().map_err(storage_unpublished)?.len();
    if length < (HEADER_BYTES + CHECKSUM_BYTES) as u64 || length > MAX_RECEIPT_BYTES as u64 {
        return Err(HostSourceCommandErrorV1::Corrupt("file length"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    let mut chunk = [0u8; 8192];
    loop {
        checkpoint(control)?;
        let allowance = (MAX_RECEIPT_BYTES + 1 - bytes.len()).min(chunk.len());
        let count = file
            .read(&mut chunk[..allowance])
            .map_err(storage_unpublished)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(HostSourceCommandErrorV1::Corrupt(
                "file grew beyond byte bound",
            ));
        }
    }
    if bytes.len() != length as usize {
        return Err(HostSourceCommandErrorV1::Corrupt("file length changed"));
    }
    let record = decode_record(&bytes)?;
    checkpoint(control)?;
    Ok(Some((file, record)))
}

pub(super) fn confirm_existing_durability(
    path: &Path,
    file: &File,
    control: &OperationControl,
) -> Result<()> {
    checkpoint(control)?;
    file.sync_all().map_err(storage_uncertain)?;
    // Once the durability barrier starts, complete it before interpreting a
    // cancellation race. A failed barrier is uncertainty, never a fake no-op.
    sync_parent_directory(path, DirectorySyncPolicy::Strict).map_err(storage_uncertain)
}

fn publish_receipt(path: &Path, bytes: &[u8], control: &OperationControl) -> Result<()> {
    publish_private_artifact(path, bytes, control, MAX_RECEIPT_BYTES)
}

/// The caller has prepared its fixed private root, holds its admission lock,
/// and admitted these bytes under its own fixed artifact quota. The caller
/// owns typed encoding; this helper only publishes bounded immutable bytes.
pub(super) fn publish_private_artifact(
    path: &Path,
    bytes: &[u8],
    control: &OperationControl,
    maximum_record_bytes: usize,
) -> Result<()> {
    checkpoint(control)?;
    if bytes.is_empty() || bytes.len() > maximum_record_bytes {
        return Err(invalid("receipt byte bound"));
    }
    let published = Cell::new(false);
    let stopped = Cell::new(None);
    let control_io = || {
        control.snapshot().map(|_| ()).map_err(|code| {
            stopped.set(Some(code));
            io::Error::new(
                io::ErrorKind::Interrupted,
                "retained artifact control stopped",
            )
        })
    };
    let result = with_owned_temp_publish(
        path,
        "retained-artifact",
        |temporary, destination| {
            control_io()?;
            rename_noreplace(temporary, destination)?;
            published.set(true);
            Ok(())
        },
        |file| {
            for chunk in bytes.chunks(8192) {
                control_io()?;
                file.write_all(chunk)?;
            }
            Ok(())
        },
        DirectorySyncPolicy::Strict,
    );
    match result {
        Ok(()) => Ok(()),
        Err(error) if published.get() => Err(storage_uncertain(error)),
        Err(error) => match stopped.get() {
            Some(code) => Err(HostSourceCommandErrorV1::Control(code)),
            None => Err(storage_unpublished(error)),
        },
    }
}

fn encode_record(record: &StoredSourceCommandV1) -> Result<Vec<u8>> {
    record.validate()?;
    let payload = canonical_json_bytes(record).map_err(|_| invalid("receipt encoding"))?;
    let total = HEADER_BYTES
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(CHECKSUM_BYTES))
        .filter(|n| *n <= MAX_RECEIPT_BYTES)
        .ok_or_else(|| invalid("receipt byte bound"))?;
    let length = u32::try_from(payload.len()).map_err(|_| invalid("receipt payload length"))?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    let digest = checksum(&frame);
    frame.extend_from_slice(&digest);
    Ok(frame)
}

fn decode_record(bytes: &[u8]) -> Result<StoredSourceCommandV1> {
    let corrupt = HostSourceCommandErrorV1::Corrupt;
    if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES
        || bytes.len() > MAX_RECEIPT_BYTES
        || bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice())
    {
        return Err(corrupt("frame header or bound"));
    }
    let raw_length: [u8; 4] = bytes[MAGIC.len()..HEADER_BYTES]
        .try_into()
        .map_err(|_| corrupt("frame length field"))?;
    let payload_length = usize::try_from(u32::from_be_bytes(raw_length))
        .map_err(|_| corrupt("frame length overflow"))?;
    let checksum_at = HEADER_BYTES
        .checked_add(payload_length)
        .ok_or_else(|| corrupt("frame length overflow"))?;
    if checksum_at.checked_add(CHECKSUM_BYTES) != Some(bytes.len()) {
        return Err(corrupt("frame length mismatch"));
    }
    if checksum(&bytes[..checksum_at]).as_slice() != &bytes[checksum_at..] {
        return Err(corrupt("frame checksum"));
    }
    let payload = &bytes[HEADER_BYTES..checksum_at];
    let record: StoredSourceCommandV1 =
        serde_json::from_slice(payload).map_err(|_| corrupt("strict receipt schema"))?;
    record
        .validate()
        .map_err(|_| corrupt("receipt field binding"))?;
    // Reject alternate encodings, omitted nullable fields, duplicate keys and
    // noncanonical numbers rather than letting different bytes denote a receipt.
    if canonical_json_bytes(&record).map_err(|_| corrupt("receipt encoding"))? != payload {
        return Err(corrupt("noncanonical receipt bytes"));
    }
    Ok(record)
}

fn request_key(
    actor: &ActorId,
    scope: &ResolvedScope,
    kind: SourceCommandKindV1,
    request_id: &RequestId,
) -> Result<String> {
    let bytes = canonical_json_bytes(&(KEY_DOMAIN, actor, scope, kind.operation(), request_id))
        .map_err(|_| invalid("request identity encoding"))?;
    Ok(sha256_hex(&bytes))
}

fn operation_uuid_v7(key: &str, accepted_at: UtcMicros) -> Result<String> {
    let millis = u64::try_from(accepted_at.0).map_err(|_| invalid("acceptance timestamp"))? / 1000;
    if millis >= 1u64 << 48 {
        return Err(invalid("UUIDv7 timestamp overflow"));
    }
    let random = checksum(
        &canonical_json_bytes(&(OPERATION_DOMAIN, key))
            .map_err(|_| invalid("operation identity encoding"))?,
    );
    let mut uuid = [0u8; 16];
    uuid[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    uuid[6..].copy_from_slice(&random[..10]);
    uuid[6] = (uuid[6] & 0x0f) | 0x70;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15],
    ))
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

fn scope_owned(scope: &RecallOutcomeScopeV1) -> Result<OwnedExactScope> {
    OwnedExactScope::new(
        &scope.profile_id,
        &scope.project_id,
        &scope.repository_identity,
        &scope.worktree_identity,
        &scope.branch_identity,
        &scope.agent_session_id,
        &scope.resolved_scope_digest,
    )
    .map_err(|_| invalid("exact provider scope"))
}

fn attribution_wire(attribution: &SourceAttribution) -> RecallSourceAttributionV1 {
    let source = &attribution.source;
    let validity = &attribution.validity;
    RecallSourceAttributionV1 {
        source: RecallOriginalSourceIdentityV1 {
            canonical_provider_id: source.canonical_provider_id.as_str().to_owned(),
            canonical_session_id: source.canonical_session_id.clone(),
            source_key: source.source_key.clone(),
            stable_record_id: source.stable_record_id.clone(),
            observation_id: source.observation_id.clone(),
            source_revision: source.source_revision.clone(),
            content_sha256: source.content_sha256.clone(),
        },
        origin_scope: match &attribution.origin_scope {
            OriginScopeEvidence::Recorded {
                scope,
                authority_ref,
            } => RecallOriginScopeEvidenceV1::Recorded {
                exact_scope_identity: scope_wire(scope),
                authority_ref: authority_ref.clone(),
            },
            OriginScopeEvidence::IngestionOnly => RecallOriginScopeEvidenceV1::IngestionOnly,
            OriginScopeEvidence::Unavailable => RecallOriginScopeEvidenceV1::Unavailable,
        },
        source_sequence: attribution.source_sequence,
        occurred_at: attribution.occurred_at_utc_nanos.map(timestamp),
        ingested_at: timestamp(attribution.ingested_at_utc_nanos),
        validity: RecallRecordedValidityV1 {
            valid_from: validity.valid_from_utc_nanos.map(timestamp),
            valid_until: validity.valid_until_utc_nanos.map(timestamp),
            superseded_at: validity.superseded_at_utc_nanos.map(timestamp),
            superseded_by: validity.superseded_by.clone(),
            revoked_at: validity.revoked_at_utc_nanos.map(timestamp),
        },
    }
}

fn timestamp(nanos: i64) -> String {
    DateTime::<Utc>::from_timestamp_nanos(nanos).to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn validate_public_request(
    request: &ProviderFeedbackRequestV1,
    accepted_at: UtcMicros,
) -> Result<()> {
    if request.weight.len() > 64
        || request.evidence_refs.len() > MAX_PROVIDER_CONTROL_EVIDENCE_REFS
        || [
            &request.source.trace_ref,
            &request.source.item_ref,
            &request.source.observation_id,
        ]
        .into_iter()
        .chain(request.evidence_refs.iter())
        .any(|value| value.len() > MAX_PROVIDER_CONTROL_REFERENCE_BYTES)
    {
        return Err(invalid("public feedback request byte/count bound"));
    }
    ProviderControlRequestV1::Feedback(request.clone())
        .validate_at(accepted_at)
        .map_err(|_| invalid("public feedback request"))
}

fn validate_deletion_request(
    request: &ProviderDeleteBySourceRequestV1,
    accepted_at: UtcMicros,
) -> Result<()> {
    if [
        &request.source.trace_ref,
        &request.source.item_ref,
        &request.source.observation_id,
    ]
    .into_iter()
    .any(|value| value.len() > MAX_PROVIDER_CONTROL_REFERENCE_BYTES)
    {
        return Err(invalid("public deletion request byte bound"));
    }
    ProviderControlRequestV1::DeleteBySource(request.clone())
        .validate_at(accepted_at)
        .map_err(|_| invalid("public deletion request"))
}

fn checkpoint(control: &OperationControl) -> Result<()> {
    control
        .snapshot()
        .map(|_| ())
        .map_err(HostSourceCommandErrorV1::Control)
}

fn invalid(field: &'static str) -> HostSourceCommandErrorV1 {
    HostSourceCommandErrorV1::Invalid(field)
}

fn storage_unpublished(source: io::Error) -> HostSourceCommandErrorV1 {
    HostSourceCommandErrorV1::Storage {
        publication: FeedbackAssertionPublicationV1::NotAttempted,
        source,
    }
}

fn storage_uncertain(source: io::Error) -> HostSourceCommandErrorV1 {
    HostSourceCommandErrorV1::Storage {
        publication: FeedbackAssertionPublicationV1::DurabilityUnknown,
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Instant;

    use super::*;
    use tracedecay_contracts::retained_surfaces::{
        ProviderControlFeedbackSignalV1, ProviderControlSourceSelectorV1, RetainedSurfaceOperation,
    };
    use tracedecay_contracts::{
        CancellationContext, CapabilityGrantId, CapabilityGrantSnapshot, Deadline, DisclosureClass,
        retained_surface_application_operation,
    };
    use tracedecay_domain::{ManifestDigest, ProjectId, RefId, RepositoryId, WorktreeId};
    use tracedecay_memory_provider_registry::{
        CancellationToken, OriginalSourceIdentity, RecordedValidity,
    };

    fn control() -> OperationControl {
        OperationControl::new(i64::MAX, 5000, CancellationToken::new())
    }

    fn context() -> RequestContext {
        let scope = ResolvedScope::new(
            ProjectId::new("project.feedback").unwrap(),
            RepositoryId::new("repository.feedback").unwrap(),
            WorktreeId::new("worktree.feedback").unwrap(),
            Some(RefId::new("refs/heads/master").unwrap()),
        )
        .unwrap();
        let operation =
            retained_surface_application_operation(RetainedSurfaceOperation::ProviderFeedback)
                .unwrap();
        let actor = ActorId::new("actor.feedback.authenticated").unwrap();
        let grant = CapabilityGrantSnapshot::new(
            CapabilityGrantId::new("grant.feedback").unwrap(),
            1,
            ManifestDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            actor.clone(),
            UtcMicros(1),
            UtcMicros(i64::MAX),
            scope.clone(),
            BTreeSet::from([operation.capability_id().clone()]),
            BTreeSet::from([operation.use_case_id().clone()]),
            DisclosureClass::Evidence,
        )
        .unwrap();
        RequestContext::new(
            actor,
            scope,
            grant,
            RequestId::new("request.feedback.1").unwrap(),
            Deadline::new(UtcMicros(i64::MAX)).unwrap(),
            CancellationContext::active("cancel.feedback").unwrap(),
        )
        .unwrap()
    }

    fn inputs() -> (
        RequestContext,
        ProviderFeedbackRequestV1,
        LifecycleTarget,
        SourceAttribution,
    ) {
        let context = context();
        let scope = OwnedExactScope::new(
            "profile.feedback",
            context.scope().project_id.as_str(),
            context.scope().repository_id.as_str(),
            context.scope().worktree_id.as_str(),
            "refs/heads/master",
            "session.delivery",
            context.scope().scope_digest.as_str(),
        )
        .unwrap();
        let mut original_scope = scope.clone();
        original_scope.agent_session_id = "session.original".to_owned();
        let attribution = SourceAttribution {
            source: OriginalSourceIdentity {
                canonical_provider_id: OwnedProviderId::new("codex").unwrap(),
                canonical_session_id: "session.original".to_owned(),
                source_key: "source.feedback".to_owned(),
                stable_record_id: Some("message.original.1".to_owned()),
                observation_id: "observation.original.1".to_owned(),
                source_revision: Some("revision.original.1".to_owned()),
                content_sha256: "b".repeat(64),
            },
            origin_scope: OriginScopeEvidence::Recorded {
                scope: original_scope,
                authority_ref: "host-origin.1".to_owned(),
            },
            source_sequence: 17,
            occurred_at_utc_nanos: Some(1_700_000_000_000_000_123),
            ingested_at_utc_nanos: 1_700_000_001_000_000_456,
            validity: RecordedValidity {
                valid_from_utc_nanos: Some(1_700_000_000_000_000_123),
                ..RecordedValidity::default()
            },
        };
        let target = LifecycleTarget {
            provider_id: OwnedProviderId::new("tracedecay.native").unwrap(),
            registration_revision: 3,
            original_scope: attribution.origin_scope.clone(),
            delivery_scope: scope,
            source: attribution.source.clone(),
            reference: LifecycleTargetReference::RetainedSourceLocator(
                "memory.original.1".to_owned(),
            ),
        };
        let request = ProviderFeedbackRequestV1 {
            source: ProviderControlSourceSelectorV1 {
                trace_ref: format!("recall-trace-v1:{}:{}", "c".repeat(64), "d".repeat(64)),
                item_ref: "recall-item-v1:0".to_owned(),
                observation_id: attribution.source.observation_id.clone(),
            },
            signal: ProviderControlFeedbackSignalV1::Helpful,
            weight: "0.5".to_owned(),
            evidence_refs: vec!["evidence.task.1".to_owned()],
            occurred_at: UtcMicros(1_700_000_100_000_000),
        };
        (context, request, target, attribution)
    }

    fn binding() -> FeedbackAssertionBindingV1 {
        let (context, request, target, source) = inputs();
        FeedbackAssertionBindingV1::prepare(&context, &request, &target, &source, now_micros())
            .unwrap()
    }

    fn retained_inputs() -> (
        RequestContext,
        ProviderFeedbackRequestV1,
        LifecycleTarget,
        SourceAttribution,
    ) {
        let (context, request, mut target, source) = inputs();
        target.reference = LifecycleTargetReference::RetainedSourceLocator(format!(
            "recall-memory-ref-v1:{}",
            "a".repeat(64)
        ));
        (context, request, target, source)
    }

    fn retained_binding() -> FeedbackAssertionBindingV1 {
        let (context, request, target, source) = retained_inputs();
        FeedbackAssertionBindingV1::prepare(&context, &request, &target, &source, now_micros())
            .unwrap()
    }

    fn stable_inputs() -> (
        RequestContext,
        ProviderFeedbackRequestV1,
        LifecycleTarget,
        SourceAttribution,
    ) {
        let (context, request, mut target, source) = inputs();
        target.reference =
            LifecycleTargetReference::StableMemoryRef(format!("ncm-memory:{}", "c".repeat(64)));
        (context, request, target, source)
    }

    fn stable_binding() -> FeedbackAssertionBindingV1 {
        let (context, request, target, source) = stable_inputs();
        FeedbackAssertionBindingV1::prepare(&context, &request, &target, &source, now_micros())
            .unwrap()
    }

    fn accept_at_root(
        root: &Path,
        binding: FeedbackAssertionBindingV1,
        control: &OperationControl,
        quota: ArtifactQuota,
        publish: impl FnOnce(&Path, &[u8], &OperationControl) -> Result<()>,
    ) -> Result<AcceptedFeedbackAssertionV1> {
        accepted_feedback(super::accept_at_root(
            root,
            binding.into(),
            control,
            quota,
            publish,
        )?)
    }

    fn accept(
        root: &Path,
        binding: FeedbackAssertionBindingV1,
    ) -> Result<AcceptedFeedbackAssertionV1> {
        accept_at_root(
            root,
            binding,
            &control(),
            ArtifactQuota::DEFAULT,
            publish_receipt,
        )
    }

    #[test]
    fn retained_locator_acceptance_replays_and_preserves_reference_kind() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let original = retained_binding();
        let (context, request, target, source) = retained_inputs();
        let accepted = accept(&root, original.clone()).unwrap();
        let path = receipt_path(&root, &original.lookup_key().unwrap());
        let retained_bytes = std::fs::read(&path).unwrap();

        let ledger = RecallAdmissionLedgerV1::open_for_control_test(temporary.path()).unwrap();
        let replay = retained_feedback_assertion(ledger.path(), &context, &control()).unwrap();
        assert_eq!(replay, accepted);
        assert!(
            replay
                .matches(&context, &request, &target, &source)
                .unwrap()
        );
        let mut stable_target = target.clone();
        stable_target.reference =
            LifecycleTargetReference::StableMemoryRef(match &target.reference {
                LifecycleTargetReference::RetainedSourceLocator(value) => value.clone(),
                _ => unreachable!("retained fixture target"),
            });
        assert!(
            !replay
                .matches(&context, &request, &stable_target, &source)
                .unwrap()
        );

        let encoded = serde_json::to_value(&accepted.0).unwrap();
        assert_eq!(
            encoded["binding"]["target"]["reference_kind"],
            "retained_source_locator"
        );
        assert_eq!(std::fs::read(&path).unwrap(), retained_bytes);
    }

    #[test]
    fn stable_reference_acceptance_keeps_legacy_receipt_shape_and_replays() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let original = stable_binding();
        let (context, request, target, source) = stable_inputs();
        let accepted = accept(&root, original).unwrap();
        let encoded = serde_json::to_value(&accepted.0).unwrap();
        assert!(encoded["binding"]["target"].get("reference_kind").is_none());

        let ledger = RecallAdmissionLedgerV1::open_for_control_test(temporary.path()).unwrap();
        let replay = retained_feedback_assertion(ledger.path(), &context, &control()).unwrap();
        assert_eq!(replay, accepted);
        assert!(
            replay
                .matches(&context, &request, &target, &source)
                .unwrap()
        );
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = match create_private_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_private_file(path).unwrap()
            }
            Err(error) => panic!("private fixture file: {error}"),
        };
        file.set_len(0).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn receipt_count(root: &Path) -> usize {
        std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "receipt")
            })
            .count()
    }

    #[test]
    fn restart_retry_preserves_receipt_uuid_key_time_and_exact_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let request = binding();
        let path = receipt_path(&root, &request.lookup_key().unwrap());
        let first = accept(&root, request.clone()).unwrap();
        let original_bytes = std::fs::read(&path).unwrap();
        // No process-local state participates: drop the accepted value and all
        // file handles, then reopen from disk using a fresh control object.
        let expected = first.clone();
        drop(first);
        let retry = accept(&root, request).unwrap();
        assert_eq!(retry, expected);
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert_eq!(receipt_count(&root), 1);
        assert_eq!(retry.operation_id().as_bytes()[14], b'7');
        assert!(matches!(
            retry.operation_id().as_bytes()[19],
            b'8' | b'9' | b'a' | b'b'
        ));
        assert_eq!(
            retry.canonical_outcome_receipt(),
            expected.canonical_outcome_receipt()
        );
        assert_eq!(retry.idempotency_key(), expected.idempotency_key());
        assert_eq!(retry.idempotency_key().len(), 64);
        assert!(
            retry
                .idempotency_key()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(retry.accepted_at(), expected.accepted_at());
    }

    #[test]
    fn changed_bound_assertions_conflict_without_replacement_after_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let original = binding();
        let accepted = accept(&root, original.clone()).unwrap();
        let path = receipt_path(&root, &original.lookup_key().unwrap());
        let retained = std::fs::read(&path).unwrap();
        type FeedbackEdit = Box<dyn Fn(&mut FeedbackAssertionBindingV1)>;
        let edits: Vec<FeedbackEdit> = vec![
            Box::new(|b| b.request.signal = ProviderControlFeedbackSignalV1::Harmful),
            Box::new(|b| b.request.weight = "1".to_owned()),
            Box::new(|b| b.request.evidence_refs.push("evidence.task.2".to_owned())),
            Box::new(|b| b.request.occurred_at.0 += 1),
            Box::new(|b| b.request.source.item_ref = "recall-item-v1:1".to_owned()),
            Box::new(|b| b.target.provider_id = "ncm".to_owned()),
            Box::new(|b| b.target.registration_revision += 1),
            Box::new(|b| b.target.delivery_scope.agent_session_id = "session.other".to_owned()),
            Box::new(|b| b.target.stable_memory_ref = "memory.other".to_owned()),
            Box::new(|b| b.target.original_attribution.source_sequence += 1),
            Box::new(|b| {
                b.target.original_attribution.ingested_at = timestamp(1_700_000_001_000_000_457);
            }),
        ];
        for edit in edits {
            let mut conflicting = original.clone();
            edit(&mut conflicting);
            assert_eq!(
                conflicting.lookup_key().unwrap(),
                original.lookup_key().unwrap()
            );
            assert!(matches!(
                accept(&root, conflicting),
                Err(FeedbackAssertionErrorV1::Conflict)
            ));
            assert_eq!(std::fs::read(&path).unwrap(), retained);
        }
        assert_eq!(accept(&root, original).unwrap(), accepted);
    }

    #[test]
    fn authenticated_actor_scope_and_request_identity_partition_lookup_keys() {
        let original = binding();
        let mut changed_actor = original.clone();
        changed_actor.actor = ActorId::new("actor.different").unwrap();
        let mut changed_request = original.clone();
        changed_request.request_id = RequestId::new("request.different").unwrap();
        let mut changed_scope = original.clone();
        changed_scope.resolved_host_scope = ResolvedScope::new(
            ProjectId::new("project.feedback").unwrap(),
            RepositoryId::new("repository.feedback").unwrap(),
            WorktreeId::new("worktree.other").unwrap(),
            Some(RefId::new("refs/heads/master").unwrap()),
        )
        .unwrap();
        let keys = [original, changed_actor, changed_request, changed_scope]
            .iter()
            .map(|body| body.lookup_key().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn concurrent_identical_and_conflicting_retries_have_one_immutable_winner() {
        for conflicting in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join(ROOT_NAME);
            prepare_root(&root, &control()).unwrap();
            let start = Arc::new(Barrier::new(8));
            let handles = (0..8)
                .map(|index| {
                    let root = root.clone();
                    let start = Arc::clone(&start);
                    let mut request = binding();
                    if conflicting && index % 2 == 1 {
                        request.request.signal = ProviderControlFeedbackSignalV1::Harmful;
                    }
                    std::thread::spawn(move || {
                        start.wait();
                        accept(&root, request)
                    })
                })
                .collect::<Vec<_>>();
            let outcomes = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>();
            let accepted = outcomes
                .iter()
                .filter_map(|outcome| outcome.as_ref().ok())
                .collect::<Vec<_>>();
            assert_eq!(accepted.len(), if conflicting { 4 } else { 8 });
            assert!(accepted.iter().all(|outcome| *outcome == accepted[0]));
            assert!(
                outcomes
                    .iter()
                    .filter(|outcome| outcome.is_err())
                    .all(|outcome| matches!(outcome, Err(FeedbackAssertionErrorV1::Conflict)))
            );
            assert_eq!(receipt_count(&root), 1);
        }
    }

    #[test]
    fn projection_match_preserves_actual_actor_target_and_full_attribution() {
        let temporary = tempfile::tempdir().unwrap();
        let (context, request, target, attribution) = inputs();
        let accepted = accept(&temporary.path().join(ROOT_NAME), binding()).unwrap();
        assert!(
            accepted
                .matches(&context, &request, &target, &attribution)
                .unwrap()
        );
        let mut changed = request.clone();
        changed.evidence_refs.push("evidence.different".to_owned());
        assert!(
            !accepted
                .matches(&context, &changed, &target, &attribution)
                .unwrap()
        );
        let mut changed = attribution.clone();
        changed.source_sequence += 1;
        assert!(
            !accepted
                .matches(&context, &request, &target, &changed)
                .unwrap()
        );
        changed = attribution.clone();
        changed.occurred_at_utc_nanos = changed.occurred_at_utc_nanos.map(|time| time + 1);
        assert!(
            !accepted
                .matches(&context, &request, &target, &changed)
                .unwrap()
        );
        let mut changed_target = target.clone();
        changed_target.reference =
            LifecycleTargetReference::RetainedSourceLocator("memory.different".to_owned());
        assert!(
            !accepted
                .matches(&context, &request, &changed_target, &attribution)
                .unwrap()
        );
        changed_target.original_scope = OriginScopeEvidence::Unavailable;
        assert!(
            accepted
                .matches(&context, &request, &changed_target, &attribution)
                .is_err()
        );
    }

    #[test]
    fn tampered_missing_and_oversized_artifacts_never_become_accepted() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        prepare_root(&root, &control()).unwrap();
        let request = binding();
        let path = receipt_path(&root, &request.lookup_key().unwrap());
        assert!(read_record(&path, &control()).unwrap().is_none());
        let accepted = accept(&root, request.clone()).unwrap();
        let mut frame = encode_record(&accepted.0).unwrap();
        frame[HEADER_BYTES + 10] ^= 1;
        write_private(&path, &frame);
        assert!(matches!(
            accept(&root, request.clone()),
            Err(FeedbackAssertionErrorV1::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), frame);
        write_private(&path, &vec![0; MAX_RECEIPT_BYTES + 1]);
        assert!(matches!(
            accept(&root, request),
            Err(FeedbackAssertionErrorV1::Corrupt(_))
        ));
    }

    fn frame_json(value: &serde_json::Value) -> Vec<u8> {
        let payload = canonical_json_bytes(value).unwrap();
        let mut frame = MAGIC.to_vec();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let digest = checksum(&frame);
        frame.extend_from_slice(&digest);
        frame
    }

    #[test]
    fn strict_decode_rejects_unknown_missing_fields_overflow_and_bound_bypass() {
        let record = StoredSourceCommandV1::new(binding(), now_micros()).unwrap();
        let valid = encode_record(&record).unwrap();
        let mut bad_length = valid.clone();
        bad_length[MAGIC.len()..HEADER_BYTES].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_record(&bad_length).is_err());
        assert!(decode_record(&valid[..valid.len() - 1]).is_err());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_record(&trailing).is_err());
        let json = serde_json::to_value(&record).unwrap();
        let mut unknown = json.clone();
        unknown["unexpected"] = true.into();
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove("operation_id");
        let mut overflow = json.clone();
        overflow["binding"]["target"]["registration_revision"] =
            serde_json::json!("18446744073709551616");
        let mut caller_receipt = json.clone();
        caller_receipt["binding"]["request"]["canonical_outcome_receipt"] = "forged".into();
        let mut too_many = json.clone();
        too_many["binding"]["request"]["evidence_refs"] = serde_json::json!(vec!["evidence"; 65]);
        for corrupt in [unknown, missing, overflow, caller_receipt, too_many] {
            assert!(decode_record(&frame_json(&corrupt)).is_err());
        }
        assert!(operation_uuid_v7("key", UtcMicros(-1)).is_err());
    }

    #[test]
    fn first_use_rejects_original_cancelled_and_expired_controls_without_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let cancelled = control();
        cancelled.cancellation().cancel();
        for (name, operation, expected) in [
            ("cancelled", cancelled, TerminalCode::Cancelled),
            (
                "expired",
                OperationControl::new(0, 5000, CancellationToken::new()),
                TerminalCode::DeadlineExceeded,
            ),
        ] {
            let root = temporary.path().join(name);
            let result = accept_at_root(
                &root,
                binding(),
                &operation,
                ArtifactQuota::DEFAULT,
                |_path, _bytes, _control| panic!("stopped first use must never publish a receipt"),
            );
            assert!(matches!(
                result,
                Err(HostSourceCommandErrorV1::Control(code)) if code == expected
            ));
            assert!(
                !root.exists(),
                "stopped first use must not create the receipt root"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn first_use_directory_lock_preserves_expired_control_before_release() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let lock_path = temporary
            .path()
            .join(format!(".{ROOT_NAME}.durable-directory.lock"));
        let held = create_private_file(&lock_path).unwrap();
        FileExt::lock_exclusive(&held).unwrap();
        let worker_root = root.clone();
        let (completed, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let operation = OperationControl::new(i64::MAX, 20, CancellationToken::new());
            let outcome = accept_at_root(
                &worker_root,
                binding(),
                &operation,
                ArtifactQuota::DEFAULT,
                |_path, _bytes, _control| panic!("expired first use must never publish a receipt"),
            );
            completed.send(outcome).unwrap();
        });
        let before_release = result.recv_timeout(Duration::from_secs(2));
        let absent_before_release = !root.exists();
        drop(held);
        worker.join().unwrap();
        assert!(matches!(
            before_release
                .expect("deadline must return while the directory sidecar remains locked"),
            Err(HostSourceCommandErrorV1::Control(
                TerminalCode::DeadlineExceeded
            ))
        ));
        assert!(
            absent_before_release,
            "expired first use must not publish the receipt root"
        );
    }

    #[test]
    fn lock_wait_obeys_original_live_cancellation_and_deadline_without_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        prepare_root(&root, &control()).unwrap();
        let _held = acquire_admission_lock(&root, &control()).unwrap();
        let operation = OperationControl::new(i64::MAX, 5000, CancellationToken::new());
        let cancellation = operation.cancellation();
        let worker_root = root.clone();
        let start = Instant::now();
        let worker = std::thread::spawn(move || {
            accept_at_root(
                &worker_root,
                binding(),
                &operation,
                ArtifactQuota::DEFAULT,
                publish_receipt,
            )
        });
        std::thread::sleep(Duration::from_millis(10));
        cancellation.cancel();
        assert!(matches!(
            worker.join().unwrap(),
            Err(FeedbackAssertionErrorV1::Control(TerminalCode::Cancelled))
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        let deadline = OperationControl::new(i64::MAX, 5, CancellationToken::new());
        assert!(matches!(
            accept_at_root(
                &root,
                binding(),
                &deadline,
                ArtifactQuota::DEFAULT,
                publish_receipt
            ),
            Err(FeedbackAssertionErrorV1::Control(
                TerminalCode::DeadlineExceeded
            ))
        ));
        assert_eq!(receipt_count(&root), 0);
    }

    #[test]
    fn failed_publish_yields_no_accepted_value_and_postpublish_uncertainty_reconciles() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let dispatched = AtomicUsize::new(0);
        let stopped = accept_at_root(
            &root,
            binding(),
            &control(),
            ArtifactQuota::DEFAULT,
            |_path, _bytes, _control| {
                Err(storage_unpublished(io::Error::other(
                    "injected before publish",
                )))
            },
        );
        // This unit test exercises the receipt gate, not the controller's real
        // dispatch integration; that integration must use this same and_then gate.
        let gated = stopped.inspect(|_| {
            dispatched.fetch_add(1, Ordering::SeqCst);
        });
        assert!(gated.is_err());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert_eq!(receipt_count(&root), 0);
        let uncertain = accept_at_root(
            &root,
            binding(),
            &control(),
            ArtifactQuota::DEFAULT,
            |path, bytes, control| {
                publish_receipt(path, bytes, control)?;
                Err(storage_uncertain(io::Error::other(
                    "injected durability acknowledgement loss",
                )))
            },
        );
        assert!(matches!(
            uncertain,
            Err(FeedbackAssertionErrorV1::Storage {
                publication: FeedbackAssertionPublicationV1::DurabilityUnknown,
                ..
            })
        ));
        let retained_path = receipt_path(&root, &binding().lookup_key().unwrap());
        let bytes = std::fs::read(&retained_path).unwrap();
        let retry = accept_at_root(
            &root,
            binding(),
            &control(),
            ArtifactQuota::DEFAULT,
            |_path, _bytes, _control| panic!("retry must verify retained bytes, not publish"),
        )
        .unwrap();
        assert_eq!(retry.0, decode_record(&bytes).unwrap());
        assert_eq!(std::fs::read(&retained_path).unwrap(), bytes);
    }

    #[test]
    fn successful_durable_receipt_is_not_relabelled_cancelled() {
        let temporary = tempfile::tempdir().unwrap();
        let operation = control();
        let cancellation = operation.cancellation();
        let accepted = accept_at_root(
            &temporary.path().join(ROOT_NAME),
            binding(),
            &operation,
            ArtifactQuota::DEFAULT,
            |path, bytes, control| {
                publish_receipt(path, bytes, control)?;
                cancellation.cancel();
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(operation.snapshot(), Err(TerminalCode::Cancelled)));
        assert_eq!(accepted.0.binding, binding().into());
    }

    #[test]
    fn quota_charges_new_bytes_overhead_and_orphans_but_never_evicts_retries() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let quota = ArtifactQuota {
            maximum_files: 1,
            maximum_bytes: MAX_ACCOUNTED_ARTIFACT_BYTES,
            maximum_record_bytes: MAX_RECEIPT_BYTES,
        };
        let accepted =
            accept_at_root(&root, binding(), &control(), quota, publish_receipt).unwrap();
        let mut second = binding();
        second.request_id = RequestId::new("request.feedback.2").unwrap();
        assert!(matches!(
            accept_at_root(&root, second.clone(), &control(), quota, publish_receipt),
            Err(FeedbackAssertionErrorV1::CapacityExceeded)
        ));
        let exhausted = ArtifactQuota {
            maximum_files: 0,
            maximum_bytes: 0,
            maximum_record_bytes: MAX_RECEIPT_BYTES,
        };
        assert_eq!(
            accept_at_root(&root, binding(), &control(), exhausted, publish_receipt).unwrap(),
            accepted
        );
        assert_eq!(receipt_count(&root), 1);
        let empty_root = temporary.path().join("quota-byte-fixture");
        prepare_root(&empty_root, &control()).unwrap();
        let bytes =
            encode_record(&StoredSourceCommandV1::new(second, now_micros()).unwrap()).unwrap();
        let exact = ROOT_RESERVED_BYTES + FILE_RESERVED_BYTES + bytes.len() as u64;
        check_quota(
            &empty_root,
            bytes.len(),
            ArtifactQuota {
                maximum_files: 1,
                maximum_bytes: exact,
                maximum_record_bytes: MAX_RECEIPT_BYTES,
            },
            &control(),
        )
        .unwrap();
        assert!(matches!(
            check_quota(
                &empty_root,
                bytes.len(),
                ArtifactQuota {
                    maximum_files: 1,
                    maximum_bytes: exact - 1,
                    maximum_record_bytes: MAX_RECEIPT_BYTES,
                },
                &control()
            ),
            Err(FeedbackAssertionErrorV1::CapacityExceeded)
        ));
        write_private(
            &empty_root.join(".crash-left-owned-stage.tmp"),
            b"unpublished",
        );
        assert!(matches!(
            check_quota(&empty_root, bytes.len(), quota, &control()),
            Err(FeedbackAssertionErrorV1::CapacityExceeded)
        ));
        assert!(empty_root.join(".crash-left-owned-stage.tmp").exists());
    }

    #[test]
    fn immutable_publish_does_not_replace_an_occupied_name() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        prepare_root(&root, &control()).unwrap();
        let stored = StoredSourceCommandV1::new(binding(), now_micros()).unwrap();
        let path = receipt_path(&root, &stored.lookup_key);
        let bytes = encode_record(&stored).unwrap();
        write_private(&path, &bytes);
        let mut different = stored.clone();
        let BoundSourceCommandV1::FeedbackAssertion(ref mut feedback) = different.binding else {
            panic!("feedback fixture")
        };
        feedback.request.signal = ProviderControlFeedbackSignalV1::Harmful;
        assert!(matches!(
            publish_receipt(&path, &encode_record(&different).unwrap(), &control()),
            Err(FeedbackAssertionErrorV1::Storage {
                publication: FeedbackAssertionPublicationV1::NotAttempted,
                ..
            })
        ));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn private_store_rejects_symlink_or_nonregular_artifacts_and_roots() {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        prepare_root(&root, &control()).unwrap();
        let outside = temporary.path().join("outside");
        write_private(&outside, b"untouched");
        let path = receipt_path(&root, &binding().lookup_key().unwrap());
        symlink(&outside, &path).unwrap();
        assert!(accept(&root, binding()).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
        assert!(check_quota(&root, 100, ArtifactQuota::DEFAULT, &control()).is_err());
        let alias = temporary.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(accept(&alias, binding()).is_err());
        let other = temporary.path().join("other");
        prepare_root(&other, &control()).unwrap();
        PrivateStoreIo::create_private_directory(&other.join("nested")).unwrap();
        assert!(check_quota(&other, 100, ArtifactQuota::DEFAULT, &control()).is_err());
    }

    fn deletion_inputs() -> (
        RequestContext,
        ProviderDeleteBySourceRequestV1,
        LifecycleTarget,
        SourceAttribution,
    ) {
        let (context, feedback, target, source) = inputs();
        let request = ProviderDeleteBySourceRequestV1 {
            source: feedback.source,
            mode:
                tracedecay_contracts::retained_surfaces::ProviderControlDeletionModeV1::HardDelete,
            expected_fence_revision: 4,
            include_snapshots: true,
        };
        (context, request, target, source)
    }

    fn retained_deletion_inputs() -> (
        RequestContext,
        ProviderDeleteBySourceRequestV1,
        LifecycleTarget,
        SourceAttribution,
    ) {
        let (context, request, mut target, source) = deletion_inputs();
        target.reference = LifecycleTargetReference::RetainedSourceLocator(format!(
            "recall-memory-ref-v1:{}",
            "b".repeat(64)
        ));
        (context, request, target, source)
    }

    fn deletion_binding() -> DeletionCommandBindingV1 {
        let (context, request, target, source) = deletion_inputs();
        DeletionCommandBindingV1::prepare(&context, &request, &target, &source, now_micros())
            .unwrap()
    }

    fn accept_deletion(
        root: &Path,
        binding: DeletionCommandBindingV1,
    ) -> Result<AcceptedDeletionCommandV1> {
        accepted_deletion(super::accept_at_root(
            root,
            binding.into(),
            &control(),
            ArtifactQuota::DEFAULT,
            publish_receipt,
        )?)
    }

    #[test]
    fn retained_locator_deletion_replays_and_rejects_stable_reconstruction() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let (context, request, target, source) = retained_deletion_inputs();
        let command =
            DeletionCommandBindingV1::prepare(&context, &request, &target, &source, now_micros())
                .unwrap();
        let accepted = accept_deletion(&root, command.clone()).unwrap();
        let ledger = RecallAdmissionLedgerV1::open_for_control_test(temporary.path()).unwrap();
        let replay = retained_deletion_command(ledger.path(), &context, &control()).unwrap();
        assert_eq!(replay, accepted);
        assert!(
            replay
                .matches(&context, &request, &target, &source)
                .unwrap()
        );

        let mut stable_target = target.clone();
        stable_target.reference =
            LifecycleTargetReference::StableMemoryRef(match &target.reference {
                LifecycleTargetReference::RetainedSourceLocator(value) => value.clone(),
                _ => unreachable!("retained fixture target"),
            });
        assert!(
            !replay
                .matches(&context, &request, &stable_target, &source)
                .unwrap()
        );
    }

    #[test]
    fn deletion_restart_keeps_original_fence_lookup_body_uuid_and_has_no_feedback_receipt() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let command = deletion_binding();
        let first = accept_deletion(&root, command.clone()).unwrap();
        let retained = encode_record(&first.0).unwrap();
        let second = accept_deletion(&root, command.clone()).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.operation_id().as_bytes()[14], b'7');
        assert_eq!(second.idempotency_key(), command.lookup_key().unwrap());
        assert_eq!(second.accepted_at(), first.accepted_at());
        let (context, request, target, source) = deletion_inputs();
        assert!(
            second
                .matches(&context, &request, &target, &source)
                .unwrap()
        );
        let json = serde_json::to_value(&second.0).unwrap();
        assert!(json.get("canonical_outcome_receipt").is_none());
        assert_eq!(json["binding"]["kind"], "deletion_command");
        assert_eq!(json["binding"]["request"]["expected_fence_revision"], 4);
        assert!(accepted_feedback(second.0.clone()).is_err());
        assert_eq!(encode_record(&second.0).unwrap(), retained);
        let mut forged = json;
        forged["canonical_outcome_receipt"] = "host-feedback-assertion-v1:forged".into();
        assert!(decode_record(&frame_json(&forged)).is_err());
    }

    #[test]
    fn deletion_changes_conflict_instead_of_rekeying_to_new_fence_or_target() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let original = deletion_binding();
        let accepted = accept_deletion(&root, original.clone()).unwrap();
        type DeletionEdit = Box<dyn Fn(&mut DeletionCommandBindingV1)>;
        let changes: Vec<DeletionEdit> = vec![
            Box::new(|command| command.request.expected_fence_revision += 1),
            Box::new(|command| command.request.include_snapshots = false),
            Box::new(|command| {
                command.request.mode = tracedecay_contracts::retained_surfaces::ProviderControlDeletionModeV1::RemoveInfluence;
            }),
            Box::new(|command| command.target.stable_memory_ref = "memory.another".to_owned()),
            Box::new(|command| command.target.original_attribution.source_sequence += 1),
        ];
        for change in changes {
            let mut modified = original.clone();
            change(&mut modified);
            assert_eq!(
                modified.lookup_key().unwrap(),
                original.lookup_key().unwrap()
            );
            assert!(matches!(
                accept_deletion(&root, modified),
                Err(HostSourceCommandErrorV1::Conflict)
            ));
        }
        assert_eq!(accept_deletion(&root, original).unwrap(), accepted);
    }

    #[test]
    fn operation_kind_partitions_commands_without_minting_false_receipt_claims() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let feedback = binding();
        let deletion = deletion_binding();
        assert_eq!(feedback.actor, deletion.actor);
        assert_eq!(feedback.request_id, deletion.request_id);
        assert_eq!(feedback.resolved_host_scope, deletion.resolved_host_scope);
        assert_ne!(
            feedback.lookup_key().unwrap(),
            deletion.lookup_key().unwrap()
        );
        let accepted_feedback = accept(&root, feedback).unwrap();
        let accepted_delete = accept_deletion(&root, deletion).unwrap();
        assert_ne!(
            accepted_feedback.idempotency_key(),
            accepted_delete.idempotency_key()
        );
        assert_ne!(
            accepted_feedback.operation_id(),
            accepted_delete.operation_id()
        );
        assert!(accepted_deletion(accepted_feedback.0).is_err());
        assert_eq!(receipt_count(&root), 2);
    }

    #[test]
    fn concurrent_deletion_retries_share_one_original_command_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        prepare_root(&root, &control()).unwrap();
        let start = Arc::new(Barrier::new(4));
        let handles = (0..4)
            .map(|_| {
                let root = root.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    accept_deletion(&root, deletion_binding()).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(accepted.iter().all(|item| item == &accepted[0]));
        assert_eq!(receipt_count(&root), 1);
    }

    #[test]
    fn shared_artifact_io_honors_owner_bound_without_widening_source_command_quota() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("recall-portability-test-v1");
        prepare_root(&root, &control()).unwrap();
        let _lock = acquire_admission_lock(&root, &control()).unwrap();
        let bytes = vec![42; MAX_RECEIPT_BYTES + 1];
        assert!(check_quota(&root, bytes.len(), ArtifactQuota::DEFAULT, &control()).is_err());
        let own_quota = ArtifactQuota {
            maximum_files: 2,
            maximum_bytes: 2 * 1024 * 1024,
            maximum_record_bytes: 1024 * 1024,
        };
        check_quota(&root, bytes.len(), own_quota, &control()).unwrap();
        let path = root.join("host-fixed-test-artifact");
        publish_private_artifact(&path, &bytes, &control(), own_quota.maximum_record_bytes)
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(
            publish_receipt(
                &root.join("cannot-bypass-command-bound"),
                &bytes,
                &control()
            )
            .is_err()
        );
    }

    #[test]
    fn available_artifact_bytes_charges_existing_and_incoming_overhead_and_caps_encoded_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("available-artifact-test-v1");
        prepare_root(&root, &control()).unwrap();
        let _lock = acquire_admission_lock(&root, &control()).unwrap();
        let quota = ArtifactQuota {
            maximum_files: 3,
            maximum_bytes: ROOT_RESERVED_BYTES
                + FILE_RESERVED_BYTES
                + FILE_RESERVED_BYTES
                + 17
                + 100,
            maximum_record_bytes: MAX_RECEIPT_BYTES,
        };
        assert_eq!(
            available_artifact_bytes(&root, quota, &control()).unwrap(),
            FILE_RESERVED_BYTES as usize + 17 + 100
        );
        write_private(&root.join(".orphan-stage.tmp"), &[1; 17]);
        assert_eq!(
            available_artifact_bytes(&root, quota, &control()).unwrap(),
            100
        );
        check_quota(&root, 100, quota, &control()).unwrap();
        assert!(matches!(
            check_quota(&root, 101, quota, &control()),
            Err(HostSourceCommandErrorV1::CapacityExceeded)
        ));
        let record_limited = ArtifactQuota {
            maximum_record_bytes: 50,
            ..quota
        };
        assert_eq!(
            available_artifact_bytes(&root, record_limited, &control()).unwrap(),
            50
        );
        let file_limited = ArtifactQuota {
            maximum_files: 1,
            ..quota
        };
        assert!(matches!(
            available_artifact_bytes(&root, file_limited, &control()),
            Err(HostSourceCommandErrorV1::CapacityExceeded)
        ));
        let stopped = control();
        stopped.cancellation().cancel();
        assert!(matches!(
            available_artifact_bytes(&root, quota, &stopped),
            Err(HostSourceCommandErrorV1::Control(TerminalCode::Cancelled))
        ));
        assert_eq!(
            std::fs::read(root.join(".orphan-stage.tmp")).unwrap(),
            vec![1; 17]
        );
    }
}
