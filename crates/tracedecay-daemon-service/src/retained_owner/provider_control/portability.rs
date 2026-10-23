//! Immutable host portability artifacts beside the existing recall ledger.
//!
//! Artifact checksums retain evidence; current canonical source authority is
//! required independently at export, inspection, restore and replay.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use tracedecay_contracts::retained_surfaces::{
    ProviderControlSnapshotIdentityV1, ProviderReplayRequestV1, ProviderSnapshotExportRequestV1,
    ProviderSnapshotRestoreRequestV1,
};
use tracedecay_domain::{canonical_json_bytes, canonical_text::sha256_hex};
use tracedecay_global_db::GlobalDbObservationStore;
use tracedecay_memory_observation::{
    ExpectedSourceDeliveryV1, ObservationDeliveryReceiptV1, ObservationJournalError,
    ObservationLaneKeyV1, ProviderSourceIntentReceiptV1, RecoveryTimeBudgetV1, SourceAuthorityV1,
    SourceDeliveryEvidenceV1, SourceSequenceV1, SourceStreamKeyV1, SqliteObservationJournal,
};
use tracedecay_memory_provider_registry::{
    CanonicalPayload, GrantedHistorySource, HistoryGrant, OperationControl, OwnedExactScope,
    OwnedProviderId, OwnedVersionedId, RecallOutcomeScopeV1, TerminalCode,
    recall_admission::source_attribution::{
        RecallOriginalSourceIdentityV1, RecallSourceAttributionV1,
    },
};
use tracedecay_private_fs::{
    framed_log::{DirectorySyncPolicy, remove_conditionally},
    open_private_directory, open_private_file,
};
use tracedecay_runtime_core::db::Database;
use tracedecay_runtime_core::storage::reject_symlink_components;

use super::super::{
    cognitive_recall::{
        RecallAdmissionLedgerV1, control_attribution::RetainedRecallControlScopeV1,
    },
    observation_journey::{
        delivery_operation_id, history_source_stream, validate_history_delivery_evidence,
    },
    provider_history::{
        ProviderHistoryAuthorityV1, ProviderHistoryErrorV1, history_grant_json,
        original_source_fence_digest, resolved_replay_observation, source_attribution_json,
    },
};
use super::{
    CompletedProviderControlV1, ControlFailureStageV1, ControlFailureV1, ControlInvocationV1,
    ControlResult, PROVIDER_CONTROL_POLICY_REVISION_V1, ProjectProviderControlPortV1,
    authority::{AuthorizedCanonicalControlInventoryV1, AuthorizedRetainedControlSourceV1},
    feedback_receipt::{
        ArtifactQuota, FeedbackAssertionPublicationV1, HostSourceCommandErrorV1,
        acquire_admission_lock, available_artifact_bytes, check_quota, confirm_existing_durability,
        prepare_root, publish_private_artifact,
    },
    projection::{
        HostControlEvidence, ProviderControlProjectionInput, ReplayEvidenceV1,
        ResolvedObservationV1, RetainedSnapshotV1, project_provider_control_reply,
    },
};

const ROOT_NAME: &str = "recall-portability-v1";
const MAGIC: &[u8; 8] = b"TDPORT01";
const PREFIX_BYTES: usize = MAGIC.len() + 4;
const CHECKSUM_BYTES: usize = 32;
const MAX_HEADER_BYTES: usize = 32 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
const MAX_ARTIFACT_FILES: usize = 512;
const SNAPSHOT_PREFIX: &str = "host-snapshot-v1:";
const BATCH_PREFIX: &str = "host-observation-batch-v1:";
const SNAPSHOT_CARRIER: &str = "tracedecay.host.snapshot-carrier.v1";
const BATCH_CARRIER: &str = "tracedecay.host.canonical-history-batch.v1";
const QUOTA: ArtifactQuota = ArtifactQuota {
    maximum_files: MAX_ARTIFACT_FILES,
    maximum_bytes: MAX_ARTIFACT_BYTES as u64,
    maximum_record_bytes: MAX_ARTIFACT_BYTES,
};

type Result<T> = std::result::Result<T, PortabilityErrorV1>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PortabilityErrorV1 {
    #[error("invalid retained portability artifact: {0}")]
    Invalid(&'static str),
    #[error("retained portability artifact is missing")]
    Missing,
    #[error("retained portability artifact is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("retained portability control stopped: {0:?}")]
    Control(TerminalCode),
    #[error("retained portability source authority failed: {0}")]
    Authority(#[from] ProviderHistoryErrorV1),
    #[error("retained portability capacity is exhausted")]
    CapacityExceeded,
    #[error("artifact {reference} was durably published but not readback-verified: {reason}")]
    PublishedUnverified {
        reference: String,
        #[source]
        reason: Box<PortabilityErrorV1>,
    },
    #[error("retained portability storage failed ({publication:?}): {source}")]
    Storage {
        publication: FeedbackAssertionPublicationV1,
        #[source]
        source: io::Error,
    },
}

/// Pure-read adapter used by snapshot metadata inspection. Mutating callers
/// retain completed artifact and provider evidence before interpreting errors.
pub(super) fn control_failure(error: PortabilityErrorV1) -> ControlFailureV1 {
    ControlFailureV1::new(match error {
        PortabilityErrorV1::Control(code) => ControlFailureStageV1::Control(code),
        PortabilityErrorV1::Authority(error) => ControlFailureStageV1::Authority(error),
        PortabilityErrorV1::Invalid(field) | PortabilityErrorV1::Corrupt(field) => {
            ControlFailureStageV1::InvalidBinding(field)
        }
        PortabilityErrorV1::Missing => {
            ControlFailureStageV1::MissingAuthority("retained portability artifact")
        }
        PortabilityErrorV1::CapacityExceeded => {
            ControlFailureStageV1::BlockingRead("retained portability capacity")
        }
        PortabilityErrorV1::Storage { .. } => {
            ControlFailureStageV1::BlockingRead("retained portability storage")
        }
        PortabilityErrorV1::PublishedUnverified { .. } => {
            ControlFailureStageV1::BlockingRead("published portability artifact not verified")
        }
    })
}

impl From<HostSourceCommandErrorV1> for PortabilityErrorV1 {
    fn from(error: HostSourceCommandErrorV1) -> Self {
        match error {
            HostSourceCommandErrorV1::Invalid(field) => Self::Invalid(field),
            #[cfg(test)]
            HostSourceCommandErrorV1::Missing => Self::Missing,
            HostSourceCommandErrorV1::Conflict => Self::Corrupt("immutable artifact conflict"),
            HostSourceCommandErrorV1::Corrupt(field) => Self::Corrupt(field),
            HostSourceCommandErrorV1::Control(code) => Self::Control(code),
            HostSourceCommandErrorV1::CapacityExceeded => Self::CapacityExceeded,
            HostSourceCommandErrorV1::Storage {
                publication,
                source,
            } => Self::Storage {
                publication,
                source,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactKindV1 {
    Snapshot,
    ObservationBatch,
}

impl ArtifactKindV1 {
    fn prefix(self) -> &'static str {
        match self {
            Self::Snapshot => SNAPSHOT_PREFIX,
            Self::ObservationBatch => BATCH_PREFIX,
        }
    }
    fn extension(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::ObservationBatch => "batch",
        }
    }
    fn contract(self) -> &'static str {
        match self {
            Self::Snapshot => SNAPSHOT_CARRIER,
            Self::ObservationBatch => BATCH_CARRIER,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayAdmissionBindingV1 {
    source_sequence: u64,
    observation_id: String,
    sanitization_receipt_ref: String,
    envelope_sha256: String,
    idempotency_key: String,
    delivery_receipt_id: String,
    delivery_receipt_sha256: String,
    operation_id: String,
    resolved_observation_sha256: String,
}

/// The small authenticated header lets explicit cleanup identify matching
/// snapshots without loading every provider's opaque state bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactHeaderV1 {
    version: u32,
    kind: ArtifactKindV1,
    provider_id: String,
    registration_revision: u64,
    delivery_scope: RecallOutcomeScopeV1,
    policy_revision: u64,
    carrier_contract_id: String,
    carrier_bytes: u64,
    carrier_sha256: String,
    original_sources: Vec<RecallSourceAttributionV1>,
    snapshot_identity: Option<ProviderControlSnapshotIdentityV1>,
    replay_admissions: Vec<ReplayAdmissionBindingV1>,
}

struct PreparedArtifactV1 {
    header: ArtifactHeaderV1,
    reference: String,
    carrier: CanonicalPayload,
}

pub(crate) struct RetainedSnapshotArtifactV1 {
    prepared: PreparedArtifactV1,
    scope: RetainedRecallControlScopeV1,
    identity: ProviderControlSnapshotIdentityV1,
}

impl RetainedSnapshotArtifactV1 {
    pub(crate) fn snapshot_ref(&self) -> &str {
        &self.prepared.reference
    }
    pub(crate) fn carrier(&self) -> &CanonicalPayload {
        &self.prepared.carrier
    }
    pub(crate) fn export_scope(&self) -> &RetainedRecallControlScopeV1 {
        &self.scope
    }
    pub(crate) fn identity(&self) -> &ProviderControlSnapshotIdentityV1 {
        &self.identity
    }
    pub(crate) fn original_sources(&self) -> &[RecallSourceAttributionV1] {
        &self.prepared.header.original_sources
    }
}

fn checkpoint(control: &OperationControl) -> Result<()> {
    control
        .snapshot()
        .map(|_| ())
        .map_err(PortabilityErrorV1::Control)
}
fn storage(source: io::Error) -> PortabilityErrorV1 {
    PortabilityErrorV1::Storage {
        publication: FeedbackAssertionPublicationV1::NotAttempted,
        source,
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    canonical_json_bytes(value).map_err(|_| PortabilityErrorV1::Invalid("canonical encoding"))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], field: &'static str) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| PortabilityErrorV1::Corrupt(field))
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
    .map_err(|_| PortabilityErrorV1::Corrupt("artifact delivery scope"))
}
fn header_scope(header: &ArtifactHeaderV1) -> Result<RetainedRecallControlScopeV1> {
    let provider_id = OwnedProviderId::new(&header.provider_id)
        .map_err(|_| PortabilityErrorV1::Corrupt("artifact provider"))?;
    if header.registration_revision == 0 || header.registration_revision > i64::MAX as u64 {
        return Err(PortabilityErrorV1::Corrupt(
            "artifact registration revision",
        ));
    }
    Ok(RetainedRecallControlScopeV1 {
        provider_id,
        registration_revision: header.registration_revision,
        delivery_scope: scope_owned(&header.delivery_scope)?,
    })
}
fn root_for(ledger: &RecallAdmissionLedgerV1) -> Result<PathBuf> {
    if !ledger.path().is_absolute() {
        return Err(PortabilityErrorV1::Invalid("host ledger path"));
    }
    Ok(ledger
        .path()
        .parent()
        .ok_or(PortabilityErrorV1::Invalid("host ledger parent"))?
        .join(ROOT_NAME))
}
fn validate_root(root: &Path) -> Result<()> {
    reject_symlink_components(root, "retained portability root").map_err(storage)?;
    drop(open_private_directory(root).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PortabilityErrorV1::Missing
        } else {
            storage(error)
        }
    })?);
    Ok(())
}
fn require_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PortabilityErrorV1::Corrupt("artifact digest"));
    }
    Ok(())
}
fn reference_key(kind: ArtifactKindV1, reference: &str) -> Result<&str> {
    let key = reference
        .strip_prefix(kind.prefix())
        .ok_or(PortabilityErrorV1::Invalid("artifact reference kind"))?;
    require_digest(key)?;
    Ok(key)
}
fn path_for(root: &Path, kind: ArtifactKindV1, reference: &str) -> Result<PathBuf> {
    Ok(root.join(format!(
        "{}.{}",
        reference_key(kind, reference)?,
        kind.extension()
    )))
}
fn header_reference(header: &ArtifactHeaderV1) -> Result<String> {
    Ok(format!(
        "{}{}",
        header.kind.prefix(),
        sha256_hex(&encode(header)?)
    ))
}
fn full_sources(sources: &[GrantedHistorySource]) -> Result<Vec<RecallSourceAttributionV1>> {
    sources
        .iter()
        .map(|source| {
            serde_json::from_value(source_attribution_json(&source.attribution)?)
                .map_err(|_| PortabilityErrorV1::Invalid("original attribution encoding"))
        })
        .collect()
}
fn carrier(kind: ArtifactKindV1, value: &Value) -> Result<CanonicalPayload> {
    let bytes = encode(value)?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(PortabilityErrorV1::CapacityExceeded);
    }
    CanonicalPayload::new(
        OwnedVersionedId::new(kind.contract())
            .map_err(|_| PortabilityErrorV1::Invalid("artifact carrier contract"))?,
        bytes.clone(),
        sha256_hex(&bytes),
    )
    .map_err(|_| PortabilityErrorV1::Invalid("artifact carrier"))
}
fn prepare_artifact(
    kind: ArtifactKindV1,
    scope: &RetainedRecallControlScopeV1,
    original_sources: Vec<RecallSourceAttributionV1>,
    carrier: CanonicalPayload,
    snapshot_identity: Option<ProviderControlSnapshotIdentityV1>,
    replay_admissions: Vec<ReplayAdmissionBindingV1>,
) -> Result<PreparedArtifactV1> {
    let header = ArtifactHeaderV1 {
        version: 1,
        kind,
        provider_id: scope.provider_id.as_str().to_owned(),
        registration_revision: scope.registration_revision,
        delivery_scope: scope_wire(&scope.delivery_scope),
        policy_revision: PROVIDER_CONTROL_POLICY_REVISION_V1,
        carrier_contract_id: carrier.contract_id.as_str().to_owned(),
        carrier_bytes: carrier.bytes.len() as u64,
        carrier_sha256: carrier.sha256.clone(),
        original_sources,
        snapshot_identity,
        replay_admissions,
    };
    validate_header(&header)?;
    let reference = header_reference(&header)?;
    Ok(PreparedArtifactV1 {
        header,
        reference,
        carrier,
    })
}
fn validate_header(header: &ArtifactHeaderV1) -> Result<()> {
    let scope = header_scope(header)?;
    if header.version != 1
        || header.policy_revision != PROVIDER_CONTROL_POLICY_REVISION_V1
        || header.carrier_contract_id != header.kind.contract()
        || header.carrier_bytes == 0
        || header.carrier_bytes > MAX_ARTIFACT_BYTES as u64
        || header.original_sources.len() > 4096
    {
        return Err(PortabilityErrorV1::Corrupt("artifact header bounds"));
    }
    require_digest(&header.carrier_sha256)?;
    let mut seen = BTreeSet::new();
    for source in &header.original_sources {
        let actual = source
            .to_owned_attribution()
            .map_err(|_| PortabilityErrorV1::Corrupt("artifact original attribution"))?;
        if actual.origin_scope.recorded_scope().is_err()
            || !seen.insert(actual.source.observation_id.clone())
        {
            return Err(PortabilityErrorV1::Corrupt(
                "artifact original source inventory",
            ));
        }
    }
    match header.kind {
        ArtifactKindV1::Snapshot => {
            let identity = header
                .snapshot_identity
                .as_ref()
                .ok_or(PortabilityErrorV1::Corrupt("snapshot identity missing"))?;
            if !header.replay_admissions.is_empty()
                || identity.provider_id != header.provider_id
                || identity.exact_scope_digest != scope.delivery_scope.exact_scope_sha256()
                || identity.byte_length > MAX_ARTIFACT_BYTES as u64
            {
                return Err(PortabilityErrorV1::Corrupt("snapshot header binding"));
            }
            require_digest(&identity.content_sha256)?;
            require_digest(&identity.implementation_identity_digest)?;
        }
        ArtifactKindV1::ObservationBatch => {
            if header.snapshot_identity.is_some()
                || header.original_sources.is_empty()
                || header.original_sources.len() > 256
                || header.replay_admissions.len() != header.original_sources.len()
            {
                return Err(PortabilityErrorV1::Corrupt("replay header inventory"));
            }
            let mut previous = None;
            for (source, admitted) in header
                .original_sources
                .iter()
                .zip(&header.replay_admissions)
            {
                if source.source.observation_id != admitted.observation_id
                    || source.source_sequence != admitted.source_sequence
                    || previous.is_some_and(|last: u64| {
                        last.checked_add(1) != Some(source.source_sequence)
                    })
                    || admitted.sanitization_receipt_ref.is_empty()
                    || admitted.sanitization_receipt_ref.len() > 1024
                    || admitted.delivery_receipt_id.len() > 1024
                    || admitted.idempotency_key.len() > 1024
                    || admitted.operation_id.len() > 1024
                {
                    return Err(PortabilityErrorV1::Corrupt(
                        "replay source sequence binding",
                    ));
                }
                require_digest(&admitted.envelope_sha256)?;
                require_digest(&admitted.delivery_receipt_sha256)?;
                require_digest(&admitted.resolved_observation_sha256)?;
                previous = Some(source.source_sequence);
            }
        }
    }
    Ok(())
}
fn frame(artifact: &PreparedArtifactV1) -> Result<Vec<u8>> {
    validate_header(&artifact.header)?;
    artifact
        .carrier
        .validate()
        .map_err(|_| PortabilityErrorV1::Corrupt("artifact payload"))?;
    let header = encode(&artifact.header)?;
    if header.len() > MAX_HEADER_BYTES {
        return Err(PortabilityErrorV1::CapacityExceeded);
    }
    let total = PREFIX_BYTES
        .checked_add(header.len())
        .and_then(|n| n.checked_add(CHECKSUM_BYTES))
        .and_then(|n| n.checked_add(artifact.carrier.bytes.len()))
        .filter(|n| *n <= MAX_ARTIFACT_BYTES)
        .ok_or(PortabilityErrorV1::CapacityExceeded)?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&sha2::Sha256::digest(&header));
    bytes.extend_from_slice(&artifact.carrier.bytes);
    Ok(bytes)
}
fn controlled_read_exact(
    file: &mut File,
    bytes: &mut [u8],
    control: &OperationControl,
) -> Result<()> {
    for chunk in bytes.chunks_mut(8192) {
        checkpoint(control)?;
        file.read_exact(chunk).map_err(storage)?;
    }
    checkpoint(control)
}
fn read_header(
    path: &Path,
    kind: ArtifactKindV1,
    reference: &str,
    control: &OperationControl,
) -> Result<(File, ArtifactHeaderV1)> {
    checkpoint(control)?;
    let mut file = open_private_file(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PortabilityErrorV1::Missing
        } else {
            storage(error)
        }
    })?;
    let length = file.metadata().map_err(storage)?.len();
    if length < (PREFIX_BYTES + CHECKSUM_BYTES + 1) as u64 || length > MAX_ARTIFACT_BYTES as u64 {
        return Err(PortabilityErrorV1::Corrupt("artifact length"));
    }
    let mut prefix = [0u8; PREFIX_BYTES];
    controlled_read_exact(&mut file, &mut prefix, control)?;
    if &prefix[..MAGIC.len()] != MAGIC {
        return Err(PortabilityErrorV1::Corrupt("artifact magic"));
    }
    let header_length = u32::from_be_bytes(
        prefix[MAGIC.len()..]
            .try_into()
            .map_err(|_| PortabilityErrorV1::Corrupt("header length"))?,
    ) as usize;
    if header_length == 0
        || header_length > MAX_HEADER_BYTES
        || (PREFIX_BYTES + CHECKSUM_BYTES + header_length) as u64 >= length
    {
        return Err(PortabilityErrorV1::Corrupt("artifact header length"));
    }
    let mut bytes = vec![0; header_length];
    controlled_read_exact(&mut file, &mut bytes, control)?;
    let mut checksum = [0; CHECKSUM_BYTES];
    controlled_read_exact(&mut file, &mut checksum, control)?;
    if checksum.as_slice() != sha2::Sha256::digest(&bytes).as_slice()
        || sha256_hex(&bytes) != reference_key(kind, reference)?
    {
        return Err(PortabilityErrorV1::Corrupt("artifact header digest"));
    }
    let header: ArtifactHeaderV1 = decode(&bytes, "artifact header")?;
    validate_header(&header)?;
    if encode(&header)? != bytes
        || header.kind != kind
        || header_reference(&header)? != reference
        || (PREFIX_BYTES + CHECKSUM_BYTES + header_length) as u64 + header.carrier_bytes != length
    {
        return Err(PortabilityErrorV1::Corrupt("artifact header identity"));
    }
    Ok((file, header))
}
fn read_artifact(
    path: &Path,
    kind: ArtifactKindV1,
    reference: &str,
    control: &OperationControl,
) -> Result<(File, PreparedArtifactV1)> {
    let (mut file, header) = read_header(path, kind, reference, control)?;
    let mut bytes = vec![
        0;
        usize::try_from(header.carrier_bytes)
            .map_err(|_| PortabilityErrorV1::Corrupt("carrier length"))?
    ];
    controlled_read_exact(&mut file, &mut bytes, control)?;
    let mut extra = [0; 1];
    if file.read(&mut extra).map_err(storage)? != 0 || sha256_hex(&bytes) != header.carrier_sha256 {
        return Err(PortabilityErrorV1::Corrupt(
            "artifact body digest or length",
        ));
    }
    let value: Value = decode(&bytes, "artifact carrier")?;
    if encode(&value)? != bytes {
        return Err(PortabilityErrorV1::Corrupt("noncanonical artifact body"));
    }
    let payload = CanonicalPayload::new(
        OwnedVersionedId::new(&header.carrier_contract_id)
            .map_err(|_| PortabilityErrorV1::Corrupt("artifact contract"))?,
        bytes,
        header.carrier_sha256.clone(),
    )
    .map_err(|_| PortabilityErrorV1::Corrupt("artifact canonical payload"))?;
    checkpoint(control)?;
    Ok((
        file,
        PreparedArtifactV1 {
            header,
            reference: reference.to_owned(),
            carrier: payload,
        },
    ))
}
fn retain_artifact(
    root: &Path,
    artifact: PreparedArtifactV1,
    control: &OperationControl,
) -> Result<PreparedArtifactV1> {
    let path = path_for(root, artifact.header.kind, &artifact.reference)?;
    match read_artifact(&path, artifact.header.kind, &artifact.reference, control) {
        Ok((file, old)) => {
            if old.header != artifact.header || old.carrier != artifact.carrier {
                return Err(PortabilityErrorV1::Corrupt("immutable artifact content"));
            }
            confirm_existing_durability(&path, &file, control)?;
            return Ok(old);
        }
        Err(PortabilityErrorV1::Missing) => {}
        Err(error) => return Err(error),
    }
    let bytes = frame(&artifact)?;
    check_quota(root, bytes.len(), QUOTA, control)?;
    publish_private_artifact(&path, &bytes, control, MAX_ARTIFACT_BYTES)?;
    // Publication has already reached its durability barrier. A later failed
    // read never claims that no artifact was created; the caller retains the
    // provider's actual response for reconciliation and does not publish a ref.
    let (_, retained) = read_artifact(&path, artifact.header.kind, &artifact.reference, control)
        .map_err(|reason| PortabilityErrorV1::PublishedUnverified {
            reference: artifact.reference.clone(),
            reason: Box::new(reason),
        })?;
    if retained.header != artifact.header || retained.carrier != artifact.carrier {
        return Err(PortabilityErrorV1::Corrupt("artifact publication readback"));
    }
    Ok(retained)
}
fn require_namespace(
    header: &ArtifactHeaderV1,
    scope: &RetainedRecallControlScopeV1,
    require_registration: bool,
) -> Result<()> {
    let retained = header_scope(header)?;
    if retained.provider_id != scope.provider_id
        || retained.delivery_scope != scope.delivery_scope
        || (require_registration && retained.registration_revision != scope.registration_revision)
    {
        return Err(PortabilityErrorV1::Invalid(
            "artifact original provider namespace",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCarrierV1 {
    identity: ProviderControlSnapshotIdentityV1,
    bytes: Vec<u8>,
    sources: Vec<RecallOriginalSourceIdentityV1>,
}
fn decode_snapshot(artifact: &PreparedArtifactV1) -> Result<SnapshotCarrierV1> {
    let snapshot: SnapshotCarrierV1 = decode(&artifact.carrier.bytes, "snapshot carrier")?;
    if artifact.header.kind != ArtifactKindV1::Snapshot
        || artifact.header.snapshot_identity.as_ref() != Some(&snapshot.identity)
        || snapshot.identity.byte_length != snapshot.bytes.len() as u64
        || snapshot.identity.content_sha256 != sha256_hex(&snapshot.bytes)
        || snapshot.sources.len() != artifact.header.original_sources.len()
    {
        return Err(PortabilityErrorV1::Corrupt("snapshot carrier binding"));
    }
    for (claimed, original) in snapshot
        .sources
        .iter()
        .zip(&artifact.header.original_sources)
    {
        if claimed != &original.source {
            return Err(PortabilityErrorV1::Corrupt(
                "snapshot full original inventory binding",
            ));
        }
    }
    Ok(snapshot)
}

/// Pure retained read; callers must independently reauthorize every returned
/// original source before reporting metadata or requesting restore.
pub(crate) fn read_snapshot_artifact(
    ledger: &RecallAdmissionLedgerV1,
    authorized_state: &RetainedRecallControlScopeV1,
    snapshot_ref: &str,
    control: &OperationControl,
) -> Result<RetainedSnapshotArtifactV1> {
    let root = root_for(ledger)?;
    validate_root(&root)?;
    let path = path_for(&root, ArtifactKindV1::Snapshot, snapshot_ref)?;
    let (file, prepared) = read_artifact(&path, ArtifactKindV1::Snapshot, snapshot_ref, control)?;
    // Old export registration remains provenance. Restore compatibility is
    // checked against the actual currently ready implementation and schema.
    require_namespace(&prepared.header, authorized_state, false)?;
    let identity = decode_snapshot(&prepared)?.identity;
    let scope = header_scope(&prepared.header)?;
    confirm_existing_durability(&path, &file, control)?;
    Ok(RetainedSnapshotArtifactV1 {
        prepared,
        scope,
        identity,
    })
}

struct SettledReplayObservationV1 {
    original: RecallSourceAttributionV1,
    binding: ReplayAdmissionBindingV1,
    resolved: Value,
}

fn receipt_digest(receipt: &ObservationDeliveryReceiptV1) -> Result<String> {
    receipt
        .validate()
        .map_err(|_| PortabilityErrorV1::Corrupt("settled receipt"))?;
    Ok(sha256_hex(&encode(&json!({
        "receipt_id": receipt.receipt_id.as_str(),
        "observation_id": receipt.observation_id.as_str(),
        "idempotency_key": receipt.idempotency_key.as_str(),
        "payload_sha256": receipt.payload_sha256,
        "extensions_digest": receipt.extensions_digest,
        "provider_id": receipt.provider_id.as_str(),
        "provider_instance_id": receipt.provider_instance_id,
        "registration_revision": receipt.registration_revision,
        "state_generation_before": receipt.state_generation_before,
        "state_generation_after": receipt.state_generation_after,
        "attempt_number": receipt.attempt_number,
        "outcome": receipt.outcome.as_wire(),
        "committed_effect": receipt.committed_effect.as_wire(),
        "provider_effect_summary": receipt.provider_effect_summary,
        "provider_receipt_digest": receipt.provider_receipt_digest,
        "started_at_unix_micros": receipt.started_at_unix_micros,
        "finished_at_unix_micros": receipt.finished_at_unix_micros,
        "warnings": receipt.warnings,
    }))?))
}

fn settled_replay(
    scope: &RetainedRecallControlScopeV1,
    grant: &HistoryGrant,
    journal: &SqliteObservationJournal,
    control: &OperationControl,
) -> Result<Vec<SettledReplayObservationV1>> {
    let snapshot = control.snapshot().map_err(PortabilityErrorV1::Control)?;
    if grant.destination_scope != scope.delivery_scope
        || grant.policy_revision != PROVIDER_CONTROL_POLICY_REVISION_V1
        || grant.sources.is_empty()
        || grant.sources.len() > 256
    {
        return Err(PortabilityErrorV1::Invalid("settled replay grant"));
    }
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(snapshot.remaining_millis);
    let evidence = journal
        .read_source_deliveries(
            &ObservationLaneKeyV1 {
                provider_id: scope.provider_id.clone(),
                registration_revision: scope.registration_revision,
            },
            &scope.delivery_scope,
            &SourceStreamKeyV1 {
                source_authority: SourceAuthorityV1::HostSession,
                exact_scope_sha256: scope.delivery_scope.exact_scope_sha256(),
                source_stream: history_source_stream(&scope.delivery_scope, grant.policy_revision)
                    .map_err(|_| PortabilityErrorV1::Invalid("history source stream"))?,
            },
            &grant
                .sources
                .iter()
                .map(|source| ExpectedSourceDeliveryV1 {
                    source_sequence: SourceSequenceV1(source.attribution.source_sequence),
                    source_event_id: source.attribution.source.observation_id.clone(),
                })
                .collect::<Vec<_>>(),
            RecoveryTimeBudgetV1 {
                remaining_micros: i64::try_from(snapshot.remaining_millis)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000),
            },
            &control.cancellation(),
        )
        .map_err(|error| match error {
            ObservationJournalError::BudgetExhausted { .. } => {
                PortabilityErrorV1::Control(TerminalCode::DeadlineExceeded)
            }
            ObservationJournalError::OperationCancelled { .. } => {
                PortabilityErrorV1::Control(TerminalCode::Cancelled)
            }
            _ => PortabilityErrorV1::Corrupt("settled replay journal evidence"),
        })?;
    if !validate_history_delivery_evidence(
        grant,
        evidence.clone(),
        &control.cancellation(),
        deadline,
    )
    .map_err(|_| {
        control.snapshot().err().map_or(
            PortabilityErrorV1::Corrupt("settled replay delivery evidence"),
            PortabilityErrorV1::Control,
        )
    })? {
        return Err(PortabilityErrorV1::Invalid(
            "replay source delivery is unsettled",
        ));
    }
    let mut result = Vec::with_capacity(evidence.len());
    for (original, evidence) in grant.sources.iter().zip(evidence) {
        checkpoint(control)?;
        let SourceDeliveryEvidenceV1::Retained {
            admitted,
            receipt: Some(receipt),
            ..
        } = evidence
        else {
            return Err(PortabilityErrorV1::Invalid(
                "settled replay receipt missing",
            ));
        };
        let resolved = resolved_replay_observation(&admitted)?;
        let original = serde_json::from_value(source_attribution_json(&original.attribution)?)
            .map_err(|_| PortabilityErrorV1::Invalid("replay original attribution"))?;
        let binding = ReplayAdmissionBindingV1 {
            source_sequence: admitted.source.source_sequence.0,
            observation_id: admitted.source.source_event_id.clone(),
            sanitization_receipt_ref: admitted.sanitization.receipt_id.clone(),
            envelope_sha256: admitted.envelope_sha256.clone(),
            idempotency_key: admitted.idempotency_key.as_str().to_owned(),
            delivery_receipt_id: receipt.receipt_id.as_str().to_owned(),
            delivery_receipt_sha256: receipt_digest(&receipt)?,
            operation_id: delivery_operation_id(&receipt.observation_id, receipt.attempt_number),
            resolved_observation_sha256: sha256_hex(&encode(&resolved)?),
        };
        result.push(SettledReplayObservationV1 {
            original,
            binding,
            resolved,
        });
    }
    Ok(result)
}

pub(crate) struct RetainedCanonicalHistoryReplayV1 {
    metadata: tracedecay_memory_provider_registry::recall_context_pack::CanonicalHistoryReplayV1,
}
impl RetainedCanonicalHistoryReplayV1 {
    pub(crate) fn metadata(
        &self,
    ) -> &tracedecay_memory_provider_registry::recall_context_pack::CanonicalHistoryReplayV1 {
        &self.metadata
    }
}

/// Ordinary recall calls this only after its existing canonical page admission
/// and delivery wait. This producer does not enqueue observations or switch lanes.
pub(crate) async fn retain_settled_replay_batches(
    ledger: &Arc<RecallAdmissionLedgerV1>,
    authority: &Arc<ProviderHistoryAuthorityV1<GlobalDbObservationStore, Database>>,
    scope: &RetainedRecallControlScopeV1,
    grant: Option<&HistoryGrant>,
    control: &OperationControl,
) -> Result<RetainedCanonicalHistoryReplayV1> {
    use tracedecay_memory_provider_registry::recall_context_pack::{
        CanonicalHistoryReplayBatchV1, CanonicalHistoryReplayV1,
    };
    checkpoint(control)?;
    authority.validate_mount()?;
    if authority.provider_id != scope.provider_id {
        return Err(PortabilityErrorV1::Invalid("replay producing provider"));
    }
    let reader = authority.reader()?;
    reader
        .bridge
        .authorize_control_scope(&scope.delivery_scope, control)?;
    let fresh = match grant {
        Some(grant) => Some(reader.revalidate_grant(grant, control).await?),
        None => None,
    };
    let mut metadata = CanonicalHistoryReplayV1 {
        provider_id: scope.provider_id.as_str().to_owned(),
        registration_revision: scope.registration_revision,
        delivery_scope: scope_wire(&scope.delivery_scope),
        batches: Vec::new(),
    };
    let Some(grant) = fresh else {
        checkpoint(control)?;
        return Ok(RetainedCanonicalHistoryReplayV1 { metadata });
    };
    let ledger = Arc::clone(ledger);
    let journal = Arc::clone(&authority.journal);
    let scope = scope.clone();
    let operation = control.clone();
    let worker = authority.runtime.spawn_blocking(move || {
        let settled = settled_replay(&scope, &grant, &journal, &operation)?;
        let root = root_for(&ledger)?;
        prepare_root(&root, &operation)?;
        let _lock = acquire_admission_lock(&root, &operation)?;
        let mut start = 0;
        while start < settled.len() {
            checkpoint(&operation)?;
            let mut end = start + 1;
            while end < settled.len()
                && settled[end - 1].binding.source_sequence.checked_add(1)
                    == Some(settled[end].binding.source_sequence)
            {
                end += 1;
            }
            let run = &settled[start..end];
            let artifact = prepare_artifact(
                ArtifactKindV1::ObservationBatch,
                &scope,
                run.iter().map(|item| item.original.clone()).collect(),
                carrier(
                    ArtifactKindV1::ObservationBatch,
                    &json!({
                        "delivery_receipt_ids": run.iter().map(|item| &item.binding.delivery_receipt_id).collect::<Vec<_>>(),
                    }),
                )?,
                None,
                run.iter().map(|item| item.binding.clone()).collect(),
            )?;
            let artifact = retain_artifact(&root, artifact, &operation)?;
            metadata.batches.push(CanonicalHistoryReplayBatchV1 {
                observation_batch_ref: artifact.reference,
                first_source_sequence: run[0].binding.source_sequence,
                last_source_sequence: run[run.len() - 1].binding.source_sequence,
                observation_count: run.len() as u64,
            });
            start = end;
        }
        Ok::<_, PortabilityErrorV1>(RetainedCanonicalHistoryReplayV1 { metadata })
    });
    // A started publisher is always joined. No timeout drops its durable result.
    worker
        .await
        .map_err(|_| PortabilityErrorV1::Corrupt("replay artifact worker"))?
}

struct ResolvedReplayArtifactsV1 {
    grant: HistoryGrant,
    resolved: Vec<Value>,
    payloads: Vec<CanonicalPayload>,
    receipt_refs: Vec<String>,
    original_sources: Vec<RecallSourceAttributionV1>,
}

async fn resolve_replay_artifacts(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    scope: &RetainedRecallControlScopeV1,
    references: &[String],
) -> ControlResult<ResolvedReplayArtifactsV1> {
    if references.is_empty() || references.len() > 256 {
        return Err(control_failure(PortabilityErrorV1::Invalid(
            "replay artifact count",
        )));
    }
    let ledger = port.ledger()?;
    let scope_for_read = scope.clone();
    let references = references.to_vec();
    let operation = invocation.control.clone();
    let artifacts = invocation
        .run_controlled(async {
            invocation.runtime.spawn_blocking(move || {
                let root = root_for(&ledger)?;
                validate_root(&root)?;
                let mut artifacts = Vec::new();
                let mut seen = BTreeSet::new();
                let mut total_sources = 0usize;
                let mut total_bytes = 0u64;
                for reference in references {
                    checkpoint(&operation)?;
                    if !seen.insert(reference.clone()) {
                        return Err(PortabilityErrorV1::Invalid("duplicate replay artifact"));
                    }
                    let path = path_for(&root, ArtifactKindV1::ObservationBatch, &reference)?;
                    let (_, artifact) = read_artifact(
                        &path,
                        ArtifactKindV1::ObservationBatch,
                        &reference,
                        &operation,
                    )?;
                    require_namespace(&artifact.header, &scope_for_read, true)?;
                    let proof: Value = decode(&artifact.carrier.bytes, "replay receipt proof")?;
                    if proof
                        != json!({"delivery_receipt_ids": artifact.header.replay_admissions.iter()
                    .map(|admitted| &admitted.delivery_receipt_id).collect::<Vec<_>>()})
                    {
                        return Err(PortabilityErrorV1::Corrupt("replay retained receipt proof"));
                    }
                    total_sources = total_sources
                        .checked_add(artifact.header.original_sources.len())
                        .filter(|count| *count <= 256)
                        .ok_or(PortabilityErrorV1::Invalid("replay expanded source bound"))?;
                    total_bytes = total_bytes
                        .checked_add(artifact.header.carrier_bytes)
                        .filter(|count| *count <= MAX_ARTIFACT_BYTES as u64)
                        .ok_or(PortabilityErrorV1::CapacityExceeded)?;
                    artifacts.push(artifact);
                }
                Ok::<_, PortabilityErrorV1>(artifacts)
            })
            .await
            .map_err(|_| {
                ControlFailureV1::new(ControlFailureStageV1::BlockingRead(
                    "replay artifact read worker",
                ))
            })?
            .map_err(control_failure)
        })
        .await?;
    let originals: Vec<_> = artifacts
        .iter()
        .flat_map(|artifact| artifact.header.original_sources.iter().cloned())
        .collect();
    let inventory = port
        .authority()?
        .authorize_retained_source_inventory(scope, &originals, &invocation.control)
        .await?;
    let grant = inventory.grant.ok_or_else(|| {
        control_failure(PortabilityErrorV1::Invalid("replay source inventory empty"))
    })?;
    let journal = inventory.journal;
    let scope = scope.clone();
    let operation = invocation.control.clone();
    let grant_copy = grant.clone();
    let settled = invocation
        .run_controlled(async {
            invocation
                .runtime
                .spawn_blocking(move || settled_replay(&scope, &grant_copy, &journal, &operation))
                .await
                .map_err(|_| {
                    ControlFailureV1::new(ControlFailureStageV1::BlockingRead(
                        "replay settled evidence worker",
                    ))
                })?
                .map_err(control_failure)
        })
        .await?;
    let retained_bindings: Vec<_> = artifacts
        .iter()
        .flat_map(|artifact| artifact.header.replay_admissions.iter())
        .collect();
    let mut resolved = Vec::with_capacity(settled.len());
    let mut payloads = Vec::with_capacity(settled.len());
    let mut receipt_refs = Vec::with_capacity(settled.len());
    let mut previous = None;
    for (actual, expected) in settled.into_iter().zip(retained_bindings) {
        invocation.check()?;
        if &actual.binding != expected
            || previous.is_some_and(|last: u64| {
                last.checked_add(1) != Some(actual.binding.source_sequence)
            })
        {
            return Err(control_failure(PortabilityErrorV1::Invalid(
                "replay retained admission changed or sequence gap",
            )));
        }
        let observation = actual
            .resolved
            .get("observation")
            .ok_or_else(|| control_failure(PortabilityErrorV1::Corrupt("replay observation")))?;
        payloads
            .push(carrier(ArtifactKindV1::ObservationBatch, observation).map_err(control_failure)?);
        receipt_refs.push(actual.binding.sanitization_receipt_ref);
        previous = Some(actual.binding.source_sequence);
        resolved.push(actual.resolved);
    }
    Ok(ResolvedReplayArtifactsV1 {
        grant,
        resolved,
        payloads,
        receipt_refs,
        original_sources: originals,
    })
}

fn current_inventory_wire(
    inventory: &AuthorizedCanonicalControlInventoryV1,
) -> Result<(Value, Vec<Value>)> {
    let checkpoint = &inventory.checkpoint;
    let checkpoint = json!({
        "exact_scope": scope_wire(&checkpoint.exact_scope),
        "authority_ref": checkpoint.authority_ref,
        "authority_revision": checkpoint.authority_revision,
        "checked_at": chrono::DateTime::from_timestamp_nanos(checkpoint.checked_at_utc_nanos)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
    });
    let sources = match &inventory.grant {
        Some(grant) => history_grant_json(grant)?
            .get("sources")
            .and_then(Value::as_array)
            .ok_or(PortabilityErrorV1::Invalid("current inventory encoding"))?
            .iter()
            .map(|source| {
                json!({
                    "source": source["attribution"]["source"],
                    "current_disposition": source["current_disposition"],
                })
            })
            .collect(),
        None => Vec::new(),
    };
    Ok((checkpoint, sources))
}

fn require_retained_inventory(inventory: &AuthorizedCanonicalControlInventoryV1) -> Result<()> {
    if inventory.sources().iter().any(|source| {
        !super::super::provider_history::retained_history_source(source.current_disposition.state)
    }) {
        return Err(PortabilityErrorV1::Invalid(
            "current source disposition excludes retained content",
        ));
    }
    Ok(())
}

pub(super) async fn snapshot_export(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderSnapshotExportRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let ledger = port.ledger()?;
    // The common export contract has no requested-byte field. Check fixed host
    // capacity before contact, then apply request/negotiated/actual encoded
    // limits to the returned bytes before any host artifact is published.
    let ledger_for_quota = Arc::clone(&ledger);
    let operation = invocation.control.clone();
    invocation
        .run_controlled(async {
            invocation
                .runtime
                .spawn_blocking(move || {
                    let root = root_for(&ledger_for_quota)?;
                    prepare_root(&root, &operation)?;
                    let _lock = acquire_admission_lock(&root, &operation)?;
                    if available_artifact_bytes(&root, QUOTA, &operation)?
                        <= PREFIX_BYTES + CHECKSUM_BYTES
                    {
                        return Err(PortabilityErrorV1::CapacityExceeded);
                    }
                    Ok::<_, PortabilityErrorV1>(())
                })
                .await
                .map_err(|_| {
                    ControlFailureV1::new(ControlFailureStageV1::BlockingRead(
                        "snapshot capacity worker",
                    ))
                })?
                .map_err(control_failure)
        })
        .await?;
    let dispatched = port
        .dispatch(invocation, &state, json!({}), &invocation.identity, None)
        .await?;
    if dispatched.reply.payload.is_none() {
        return port.project(
            invocation,
            dispatched,
            HostControlEvidence::SnapshotExport(None),
        );
    }
    let preparation = async {
        dispatched
            .reply
            .validate(
                dispatched
                    .readiness_evidence
                    .effective_limits()
                    .response_bytes,
            )
            .map_err(|_| PortabilityErrorV1::Corrupt("snapshot response bound or digest"))?;
        let reply = dispatched
            .reply
            .payload
            .as_ref()
            .ok_or(PortabilityErrorV1::Corrupt("snapshot reply missing"))?;
        if reply.bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(PortabilityErrorV1::CapacityExceeded);
        }
        let response: Value = decode(&reply.bytes, "snapshot reply")?;
        let value = response.get("snapshot").ok_or(PortabilityErrorV1::Corrupt(
            "actual snapshot carrier missing",
        ))?;
        let snapshot: SnapshotCarrierV1 = serde_json::from_value(value.clone())
            .map_err(|_| PortabilityErrorV1::Corrupt("actual snapshot carrier"))?;
        if snapshot.bytes.len() as u64 > request.maximum_bytes
            || snapshot.bytes.len() as u64
                > dispatched
                    .readiness_evidence
                    .effective_limits()
                    .snapshot_bytes
        {
            return Err(PortabilityErrorV1::CapacityExceeded);
        }
        let identities = snapshot
            .sources
            .iter()
            .map(|source| {
                source
                    .to_owned_source()
                    .map_err(|_| PortabilityErrorV1::Corrupt("snapshot declared source identity"))
            })
            .collect::<Result<Vec<_>>>()?;
        let authority = port
            .authority()
            .map_err(|_| PortabilityErrorV1::Invalid("snapshot authority"))?;
        let inventory = authority
            .authorize_source_inventory(&state.retained, &identities, &invocation.control)
            .await?;
        require_retained_inventory(&inventory)?;
        let candidate = prepare_artifact(
            ArtifactKindV1::Snapshot,
            &state.retained,
            full_sources(inventory.sources())?,
            carrier(ArtifactKindV1::Snapshot, value)?,
            Some(snapshot.identity),
            Vec::new(),
        )?;
        decode_snapshot(&candidate)?;
        // The candidate address is private. Validate the actual full call,
        // reply, terminal, ready implementation/schema, scope and inventory
        // before any artifact bytes can be retained.
        project_provider_control_reply(
            ProviderControlProjectionInput {
                context: invocation.context.request_context,
                request: invocation.request,
                dispatched: &dispatched,
            },
            HostControlEvidence::SnapshotExport(Some(RetainedSnapshotV1 {
                snapshot_ref: &candidate.reference,
                carrier: &candidate.carrier,
            })),
        )
        .map_err(|_| PortabilityErrorV1::Corrupt("snapshot provider reply binding"))?;
        let scope = state.retained.clone();
        let operation = invocation.control.clone();
        let runtime = authority.runtime.clone();
        let authority = Arc::clone(authority);
        let worker = invocation.runtime.spawn_blocking(move || {
            let root = root_for(&ledger)?;
            prepare_root(&root, &operation)?;
            let _lock = acquire_admission_lock(&root, &operation)?;
            // Include-snapshots deletion uses this same lock. Its stable source
            // fence either precedes this fresh check or its cleanup follows this
            // publication. No snapshot can slip behind a completed cleanup.
            let fresh = runtime.block_on(authority.authorize_retained_source_inventory(
                &scope,
                &candidate.header.original_sources,
                &operation,
            ))?;
            require_retained_inventory(&fresh)?;
            let prepared = retain_artifact(&root, candidate, &operation)?;
            let identity = decode_snapshot(&prepared)?.identity;
            Ok::<_, PortabilityErrorV1>(RetainedSnapshotArtifactV1 {
                prepared,
                scope,
                identity,
            })
        });
        worker
            .await
            .map_err(|_| PortabilityErrorV1::Corrupt("snapshot retention worker"))?
    };
    let retained = invocation
        .run_controlled(async { Ok(preparation.await) })
        .await;
    let artifact = match retained {
        Ok(Ok(artifact)) => artifact,
        Ok(Err(error)) => {
            return Err(ControlFailureV1::new(
                ControlFailureStageV1::PortabilityArtifact { error, dispatched },
            ));
        }
        Err(failure) => {
            let error = match *failure.stage {
                ControlFailureStageV1::Control(code) => PortabilityErrorV1::Control(code),
                _ => PortabilityErrorV1::Invalid("post-contact artifact control"),
            };
            return Err(ControlFailureV1::new(
                ControlFailureStageV1::PortabilityArtifact { error, dispatched },
            ));
        }
    };
    port.project(
        invocation,
        dispatched,
        HostControlEvidence::SnapshotExport(Some(RetainedSnapshotV1 {
            snapshot_ref: artifact.snapshot_ref(),
            carrier: artifact.carrier(),
        })),
    )
}

pub(super) async fn snapshot_restore(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderSnapshotRestoreRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let ledger = port.ledger()?;
    let scope = state.retained.clone();
    let reference = request.snapshot_ref.clone();
    let operation = invocation.control.clone();
    let artifact = invocation
        .run_controlled(async {
            invocation
                .runtime
                .spawn_blocking(move || {
                    read_snapshot_artifact(&ledger, &scope, &reference, &operation)
                })
                .await
                .map_err(|_| {
                    ControlFailureV1::new(ControlFailureStageV1::BlockingRead(
                        "snapshot restore artifact worker",
                    ))
                })?
                .map_err(control_failure)
        })
        .await?;
    let inventory = port
        .authority()?
        .authorize_retained_source_inventory(
            &state.retained,
            artifact.original_sources(),
            &invocation.control,
        )
        .await?;
    let (checkpoint, dispositions) = current_inventory_wire(&inventory).map_err(control_failure)?;
    let snapshot: Value =
        decode(&artifact.carrier().bytes, "retained snapshot carrier").map_err(control_failure)?;
    let dispatched = port.dispatch(
        invocation, &state,
        json!({"snapshot": snapshot, "disposition_checkpoint": checkpoint, "source_dispositions": dispositions}),
        &invocation.identity, Some(request.expected_state_generation),
    ).await?;
    // The installed advisory authority also checks actual inventory at dispatch.
    // Retain actual reply if canonical authority changes during provider contact.
    if port
        .authority()?
        .authorize_retained_source_inventory(
            &state.retained,
            artifact.original_sources(),
            &invocation.control,
        )
        .await
        .is_err()
    {
        return Err(ControlFailureV1::new(ControlFailureStageV1::Projection {
            field: "snapshot restore current canonical authority",
            dispatched,
        }));
    }
    port.project(
        invocation,
        dispatched,
        HostControlEvidence::SnapshotRestore(RetainedSnapshotV1 {
            snapshot_ref: artifact.snapshot_ref(),
            carrier: artifact.carrier(),
        }),
    )
}

pub(super) async fn replay(
    port: &ProjectProviderControlPortV1,
    invocation: &ControlInvocationV1<'_, '_>,
    request: &ProviderReplayRequestV1,
) -> ControlResult<CompletedProviderControlV1> {
    let state = port.resolve_state(&request.state, invocation).await?;
    let resolved = resolve_replay_artifacts(
        port,
        invocation,
        &state.retained,
        &request.observation_batch_refs,
    )
    .await?;
    let first = resolved
        .grant
        .sources
        .first()
        .map(|source| source.attribution.source_sequence);
    let last = resolved
        .grant
        .sources
        .last()
        .map(|source| source.attribution.source_sequence);
    if first != Some(request.first_source_sequence)
        || last != Some(request.last_source_sequence)
        || request
            .last_source_sequence
            .checked_sub(request.first_source_sequence)
            .and_then(|difference| difference.checked_add(1))
            != Some(resolved.resolved.len() as u64)
        || resolved.grant.sources.iter().any(|source| {
            !super::super::provider_history::retained_history_source(
                source.current_disposition.state,
            )
        })
    {
        return Err(control_failure(PortabilityErrorV1::Invalid(
            "requested replay source interval or disposition",
        )));
    }
    let dispatched = port.dispatch(
        invocation, &state,
        json!({
            "observation_batch_refs": resolved.receipt_refs,
            "first_source_sequence": request.first_source_sequence,
            "last_source_sequence": request.last_source_sequence,
            "expected_state_generation": request.expected_state_generation,
            "expected_previous_acknowledged_sequence": request.expected_previous_acknowledged_sequence,
            "history_grant": history_grant_json(&resolved.grant)?,
            "resolved_observations": resolved.resolved,
        }),
        &invocation.identity, Some(request.expected_state_generation),
    ).await?;
    if port
        .authority()?
        .authorize_retained_source_inventory(
            &state.retained,
            &resolved.original_sources,
            &invocation.control,
        )
        .await
        .is_err()
    {
        return Err(ControlFailureV1::new(ControlFailureStageV1::Projection {
            field: "replay current canonical authority",
            dispatched,
        }));
    }
    let observations: Vec<_> = resolved
        .receipt_refs
        .iter()
        .zip(&resolved.payloads)
        .map(|(receipt_ref, observation)| ResolvedObservationV1 {
            receipt_ref,
            observation,
        })
        .collect();
    port.project(
        invocation,
        dispatched,
        HostControlEvidence::Replay(ReplayEvidenceV1 {
            observation_batch_refs: &request.observation_batch_refs,
            observations: &observations,
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostSnapshotCleanupStateV1 {
    NotRequested,
    Complete,
    Partial,
    Unverifiable,
}

/// Host file removal is separate from a provider's internal erasure postcondition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct HostSnapshotCleanupResultV1 {
    pub(crate) state: HostSnapshotCleanupStateV1,
    pub(crate) removed_snapshot_refs: Vec<String>,
    pub(crate) matched_count: u64,
    pub(crate) unverifiable_count: u64,
}

impl HostSnapshotCleanupResultV1 {
    pub(crate) fn not_requested() -> Self {
        Self {
            state: HostSnapshotCleanupStateV1::NotRequested,
            removed_snapshot_refs: Vec::new(),
            matched_count: 0,
            unverifiable_count: 0,
        }
    }
    fn incomplete(&mut self) {
        self.unverifiable_count = self.unverifiable_count.saturating_add(1);
        self.state = if self.removed_snapshot_refs.is_empty() {
            HostSnapshotCleanupStateV1::Unverifiable
        } else {
            HostSnapshotCleanupStateV1::Partial
        };
    }
}

fn same_checkout(left: &OwnedExactScope, right: &OwnedExactScope) -> bool {
    left.profile_id == right.profile_id
        && left.project_id == right.project_id
        && left.repository_identity == right.repository_identity
        && left.worktree_identity == right.worktree_identity
        && left.branch_identity == right.branch_identity
        && left.agent_session_id == right.agent_session_id
        && left.resolved_scope_digest == right.resolved_scope_digest
}

#[cfg(unix)]
fn same_file(left: &File, right: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}
#[cfg(windows)]
fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = tracedecay_private_fs::windows_file::information(left)?;
    let right = tracedecay_private_fs::windows_file::information(right)?;
    Ok(left.volume_serial_number == right.volume_serial_number
        && left.file_index == right.file_index)
}
#[cfg(not(any(unix, windows)))]
fn same_file(_left: &File, _right: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "artifact file identity unavailable",
    ))
}

fn cleanup_matches(
    header: &ArtifactHeaderV1,
    target: &tracedecay_memory_provider_registry::SourceAttribution,
    target_scope: &RetainedRecallControlScopeV1,
    source_digest: &str,
) -> Result<bool> {
    let export = header_scope(header)?;
    if header.kind != ArtifactKindV1::Snapshot
        || export.provider_id != target_scope.provider_id
        || !same_checkout(&export.delivery_scope, &target_scope.delivery_scope)
    {
        return Ok(false);
    }
    let target_origin = target
        .origin_scope
        .recorded_scope()
        .map_err(|_| PortabilityErrorV1::Invalid("cleanup original source scope"))?;
    for original in &header.original_sources {
        let original = original
            .to_owned_attribution()
            .map_err(|_| PortabilityErrorV1::Corrupt("snapshot cleanup source"))?;
        // The existing source fence identifies stable lineage across revisions,
        // not current content. Restore still compares full immutable attribution.
        if original.origin_scope.recorded_scope().ok() == Some(target_origin)
            && original_source_fence_digest(&original)? == source_digest
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Only after a confirmed durable source-fence receipt. The bounded header scan
/// removes positively matched snapshots; unknown files remain and make the
/// result incomplete. A missing file is never counted as this call's removal.
pub(crate) fn cleanup_source_snapshots(
    ledger: &RecallAdmissionLedgerV1,
    source: &AuthorizedRetainedControlSourceV1,
    intent: &ProviderSourceIntentReceiptV1,
    control: &OperationControl,
) -> HostSnapshotCleanupResultV1 {
    let mut result = HostSnapshotCleanupResultV1 {
        state: HostSnapshotCleanupStateV1::Complete,
        removed_snapshot_refs: Vec::new(),
        matched_count: 0,
        unverifiable_count: 0,
    };
    let cleanup = (|| -> Result<()> {
        checkpoint(control)?;
        source
            .grant
            .validate_structure()
            .map_err(|_| PortabilityErrorV1::Invalid("cleanup source grant"))?;
        let [granted] = source.grant.sources.as_slice() else {
            return Err(PortabilityErrorV1::Invalid("cleanup exact source"));
        };
        // The retained row deliberately contains an opaque source locator. The
        // resolver already re-authorized it and byte-compared its redaction to
        // the row, so cleanup must use that fresh canonical grant for all
        // provenance and fence checks. Reconstructing attribution from the
        // opaque row would either fail after reopen or create a raw-ID escape.
        let target = &granted.attribution;
        let digest = original_source_fence_digest(target)?;
        if source.grant.destination_scope != source.retained.scope.delivery_scope
            || intent.fence.provider_id != source.retained.scope.provider_id.as_str()
            || intent.fence.original_source_sha256 != digest
            || intent.provider_erasure_verified
            || intent.fence.revision == 0
        {
            return Err(PortabilityErrorV1::Invalid(
                "cleanup durable intent binding",
            ));
        }
        let root = root_for(ledger)?;
        match validate_root(&root) {
            Ok(()) => {}
            Err(PortabilityErrorV1::Missing) => return Ok(()),
            Err(error) => return Err(error),
        }
        let _lock = acquire_admission_lock(&root, control)?;
        let entries = std::fs::read_dir(&root).map_err(storage)?;
        let mut count = 0usize;
        let mut accounted_bytes = 4096u64;
        for entry in entries {
            checkpoint(control)?;
            let entry = entry.map_err(storage)?;
            if entry.file_name() == ".admission.lock" {
                continue;
            }
            count += 1;
            if count > MAX_ARTIFACT_FILES {
                return Err(PortabilityErrorV1::CapacityExceeded);
            }
            let file = match open_private_file(&entry.path()) {
                Ok(file) => file,
                Err(_) => {
                    result.incomplete();
                    continue;
                }
            };
            accounted_bytes = accounted_bytes
                .checked_add(file.metadata().map_err(storage)?.len())
                .and_then(|bytes| bytes.checked_add(4096))
                .filter(|bytes| *bytes <= MAX_ARTIFACT_BYTES as u64)
                .ok_or(PortabilityErrorV1::CapacityExceeded)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                result.incomplete();
                continue;
            };
            let (kind, prefix) = if name.ends_with(".snapshot") {
                (ArtifactKindV1::Snapshot, SNAPSHOT_PREFIX)
            } else if name.ends_with(".batch") {
                (ArtifactKindV1::ObservationBatch, BATCH_PREFIX)
            } else {
                result.incomplete();
                continue;
            };
            let Some(key) = name.strip_suffix(&format!(".{}", kind.extension())) else {
                result.incomplete();
                continue;
            };
            let reference = format!("{prefix}{key}");
            let path = match path_for(&root, kind, &reference) {
                Ok(path) => path,
                Err(_) => {
                    result.incomplete();
                    continue;
                }
            };
            let (original_file, header) = match read_header(&path, kind, &reference, control) {
                Ok(value) => value,
                Err(_) => {
                    result.incomplete();
                    continue;
                }
            };
            if !cleanup_matches(&header, target, &source.retained.scope, &digest)? {
                continue;
            }
            result.matched_count += 1;
            checkpoint(control)?;
            let verified = std::cell::Cell::new(false);
            let removed = remove_conditionally(
                &path,
                || {},
                |displaced| {
                    let (actual_file, actual) =
                        read_header(displaced, kind, &reference, control)
                            .map_err(|error| io::Error::other(error.to_string()))?;
                    if actual != header || !same_file(&original_file, &actual_file)? {
                        return Ok(false);
                    }
                    checkpoint(control).map_err(|error| io::Error::other(error.to_string()))?;
                    verified.set(true);
                    Ok(true)
                },
                DirectorySyncPolicy::Strict,
            );
            match removed {
                Ok(()) if verified.get() => result.removed_snapshot_refs.push(reference),
                Ok(()) => {} // Already absent; no removal attributed to this call.
                Err(_) => result.incomplete(),
            }
        }
        Ok(())
    })();
    if cleanup.is_err() {
        result.incomplete();
    }
    if result.unverifiable_count > 0 {
        result.state = if result.removed_snapshot_refs.is_empty() {
            HostSnapshotCleanupStateV1::Unverifiable
        } else {
            HostSnapshotCleanupStateV1::Partial
        };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tracedecay_memory_provider_registry::{
        CancellationToken, OriginScopeEvidence, OriginalSourceIdentity, RecordedValidity,
        SourceAttribution,
    };
    use tracedecay_private_fs::create_private_file;

    fn control() -> OperationControl {
        OperationControl::new(i64::MAX, 5_000, CancellationToken::new())
    }
    fn scope() -> RetainedRecallControlScopeV1 {
        RetainedRecallControlScopeV1 {
            provider_id: OwnedProviderId::new("native").unwrap(),
            registration_revision: 7,
            delivery_scope: OwnedExactScope::new(
                "profile",
                "project",
                "repository",
                "worktree",
                "refs/heads/master",
                "session",
                format!("sha256:{}", "a".repeat(64)),
            )
            .unwrap(),
        }
    }
    fn snapshot() -> PreparedArtifactV1 {
        let scope = scope();
        let bytes = b"actual fixture state bytes".to_vec();
        let identity = ProviderControlSnapshotIdentityV1 {
            snapshot_id: "fixture-export".to_owned(),
            provider_id: scope.provider_id.as_str().to_owned(),
            implementation_identity_digest: "b".repeat(64),
            state_schema_version: "native-staged-v2".to_owned(),
            exact_scope_digest: scope.delivery_scope.exact_scope_sha256(),
            state_generation: 5,
            observation_sequence: 0,
            parent_snapshot_id: None,
            content_sha256: sha256_hex(&bytes),
            byte_length: bytes.len() as u64,
            created_at: "2026-09-10T00:00:00.123456789Z".to_owned(),
        };
        prepare_artifact(
            ArtifactKindV1::Snapshot,
            &scope,
            Vec::new(),
            carrier(
                ArtifactKindV1::Snapshot,
                &json!({
                    "identity": identity, "bytes": bytes, "sources": [],
                }),
            )
            .unwrap(),
            Some(identity),
            Vec::new(),
        )
        .unwrap()
    }
    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = create_private_file(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn immutable_snapshot_reopens_with_exact_bytes_and_reuses_its_reference() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let operation = control();
        prepare_root(&root, &operation).unwrap();
        let _lock = acquire_admission_lock(&root, &operation).unwrap();
        let expected = snapshot();
        let reference = expected.reference.clone();
        let expected_bytes = expected.carrier.bytes.clone();
        let retained = retain_artifact(&root, expected, &operation).unwrap();
        assert_eq!(retained.reference, reference);
        assert_eq!(retained.carrier.bytes, expected_bytes);
        drop(retained);
        let path = path_for(&root, ArtifactKindV1::Snapshot, &reference).unwrap();
        let (_, reopened) =
            read_artifact(&path, ArtifactKindV1::Snapshot, &reference, &operation).unwrap();
        let decoded = decode_snapshot(&reopened).unwrap();
        assert_eq!(decoded.bytes, b"actual fixture state bytes");
        assert_eq!(
            decoded.identity.created_at,
            "2026-09-10T00:00:00.123456789Z"
        );
        assert_eq!(
            retain_artifact(&root, snapshot(), &operation)
                .unwrap()
                .reference,
            reference
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2); // Artifact and lock.
    }

    #[test]
    fn existing_artifact_retry_precedes_saturated_capacity_admission() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let operation = control();
        prepare_root(&root, &operation).unwrap();
        let _lock = acquire_admission_lock(&root, &operation).unwrap();
        let reference = retain_artifact(&root, snapshot(), &operation)
            .unwrap()
            .reference;
        for index in 0..MAX_ARTIFACT_FILES - 1 {
            write_private(&root.join(format!("retained-stage-{index}")), b"stage");
        }
        // Fixture publication is separate from this retry's admission budget.
        let operation = control();
        let capacity = available_artifact_bytes(&root, QUOTA, &operation);
        assert!(
            matches!(capacity, Err(HostSourceCommandErrorV1::CapacityExceeded)),
            "the full artifact namespace must refuse a new artifact: {capacity:?}",
        );
        assert_eq!(
            retain_artifact(&root, snapshot(), &operation)
                .unwrap()
                .reference,
            reference
        );
    }

    #[test]
    fn corrupted_header_or_body_never_constructs_a_retained_artifact() {
        for corrupt_header in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join(ROOT_NAME);
            let operation = control();
            prepare_root(&root, &operation).unwrap();
            let artifact = snapshot();
            let path = path_for(&root, ArtifactKindV1::Snapshot, &artifact.reference).unwrap();
            let mut bytes = frame(&artifact).unwrap();
            let index = if corrupt_header {
                PREFIX_BYTES + 3
            } else {
                bytes.len() - 1
            };
            bytes[index] ^= 1;
            write_private(&path, &bytes);
            assert!(
                read_artifact(
                    &path,
                    ArtifactKindV1::Snapshot,
                    &artifact.reference,
                    &operation
                )
                .is_err()
            );
        }
    }

    #[test]
    fn snapshot_provenance_allows_old_registration_but_requires_every_scope_field() {
        let artifact = snapshot();
        let mut current = scope();
        current.registration_revision += 1;
        assert!(require_namespace(&artifact.header, &current, false).is_ok());
        assert!(require_namespace(&artifact.header, &current, true).is_err());
        for field in 0..7 {
            let mut changed = current.clone();
            let value = match field {
                0 => &mut changed.delivery_scope.profile_id,
                1 => &mut changed.delivery_scope.project_id,
                2 => &mut changed.delivery_scope.repository_identity,
                3 => &mut changed.delivery_scope.worktree_identity,
                4 => &mut changed.delivery_scope.branch_identity,
                5 => &mut changed.delivery_scope.agent_session_id,
                _ => &mut changed.delivery_scope.resolved_scope_digest,
            };
            value.push('x');
            assert!(require_namespace(&artifact.header, &changed, false).is_err());
        }
        current.provider_id = OwnedProviderId::new("ncm").unwrap();
        assert!(require_namespace(&artifact.header, &current, false).is_err());
    }

    #[test]
    fn cancellation_before_publication_creates_no_artifact() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(ROOT_NAME);
        let setup = control();
        prepare_root(&root, &setup).unwrap();
        let _lock = acquire_admission_lock(&root, &setup).unwrap();
        let artifact = snapshot();
        let path = path_for(&root, ArtifactKindV1::Snapshot, &artifact.reference).unwrap();
        let stopped = control();
        stopped.cancellation().cancel();
        assert!(matches!(
            retain_artifact(&root, artifact, &stopped),
            Err(PortabilityErrorV1::Control(_))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_matches_stable_source_lineage_and_exact_session_across_restart() {
        let scope = scope();
        let original = SourceAttribution {
            source: OriginalSourceIdentity {
                canonical_provider_id: OwnedProviderId::new("claude").unwrap(),
                canonical_session_id: "original-session".to_owned(),
                source_key: "source-key".to_owned(),
                stable_record_id: Some("stable-record".to_owned()),
                observation_id: "original-observation".to_owned(),
                source_revision: Some("revision-one".to_owned()),
                content_sha256: "c".repeat(64),
            },
            origin_scope: OriginScopeEvidence::Recorded {
                scope: scope.delivery_scope.clone(),
                authority_ref: "actual-fixture-origin".to_owned(),
            },
            source_sequence: 4,
            occurred_at_utc_nanos: None,
            ingested_at_utc_nanos: 1,
            validity: RecordedValidity::default(),
        };
        let mut header = snapshot().header;
        header.original_sources =
            vec![serde_json::from_value(source_attribution_json(&original).unwrap()).unwrap()];
        let mut newer = original.clone();
        newer.source.source_revision = Some("revision-two".to_owned());
        newer.source.content_sha256 = "d".repeat(64);
        newer.source.observation_id = "newer-observation".to_owned();
        newer.validity.valid_from_utc_nanos = Some(2);
        let key = original_source_fence_digest(&newer).unwrap();
        assert!(cleanup_matches(&header, &newer, &scope, &key).unwrap());

        // The header and scope are both reconstructed after a daemon restart;
        // the persisted session binding must still authorize cleanup for the
        // producing session.
        let persisted = encode(&header).unwrap();
        let reopened_header: ArtifactHeaderV1 = decode(&persisted, "artifact header").unwrap();
        let reopened_scope = header_scope(&reopened_header).unwrap();
        assert!(cleanup_matches(&reopened_header, &newer, &reopened_scope, &key).unwrap());

        // A second session in the same checkout must not remove the first
        // session's snapshot, even when the checkout digest is reused.
        let mut foreign_session = reopened_scope.clone();
        foreign_session.delivery_scope.agent_session_id = "other-session".to_owned();
        assert!(!cleanup_matches(&reopened_header, &newer, &foreign_session, &key).unwrap());

        let mut foreign = scope.clone();
        foreign.provider_id = OwnedProviderId::new("ncm").unwrap();
        assert!(!cleanup_matches(&header, &newer, &foreign, &key).unwrap());
        let OriginScopeEvidence::Recorded { scope: origin, .. } = &mut newer.origin_scope else {
            unreachable!()
        };
        origin.branch_identity = "refs/heads/another".to_owned();
        assert!(!cleanup_matches(&header, &newer, &scope, &key).unwrap());
    }
}
