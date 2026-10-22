use sha2::{Digest, Sha256};
use tracedecay_domain::{ObservationScopeV1, ObservationSourceIdentityV1};

use super::{
    ObservationCoverageReason, ObservationCursorAdvance, ObservationStoreError,
    ObservationStoreResult, ObservationWrite,
};

/// Generation-independent authority shared by offline pruning and final writers.
pub fn observation_source_exclusion_key(
    source: &ObservationSourceIdentityV1,
    scope: &ObservationScopeV1,
) -> ObservationStoreResult<String> {
    let tuple = serde_json::to_string(&(source, scope)).map_err(|_| invalid_marker())?;
    let digest = Sha256::digest(tuple.as_bytes());
    let hex = tracedecay_domain::canonical_text::encode_tagged_lowercase_hex("", &digest);
    Ok(format!("profile-project-prune.v1.source.{hex}"))
}

#[derive(serde::Deserialize, serde::Serialize)]
struct SourceExclusionMarkerV1 {
    version: u8,
    source: ObservationSourceIdentityV1,
    scope: ObservationScopeV1,
    plan_digest: String,
}

/// Encode the existing v1 metadata with its original JSON-map ordering.
/// This document is exclusion metadata, not a retirement capability.
pub fn observation_source_exclusion_metadata(
    source: &ObservationSourceIdentityV1,
    scope: &ObservationScopeV1,
    plan_digest: &str,
) -> ObservationStoreResult<(String, String)> {
    let marker = SourceExclusionMarkerV1 {
        version: 1,
        source: source.clone(),
        scope: scope.clone(),
        plan_digest: plan_digest.to_owned(),
    };
    // The old writer serialized a JSON object, not a struct. Retain those
    // exact bytes, including ordering, for existing approved-plan comparisons.
    let value = serde_json::to_value(marker).map_err(|_| invalid_marker())?;
    let value = serde_json::to_string(&value).map_err(|_| invalid_marker())?;
    Ok((observation_source_exclusion_key(source, scope)?, value))
}

/// Validate the existing v1 wire format, failing closed without echoing metadata.
pub fn validate_observation_source_exclusion(
    value: &str,
    source: &ObservationSourceIdentityV1,
    scope: &ObservationScopeV1,
) -> ObservationStoreResult<()> {
    let marker: SourceExclusionMarkerV1 =
        serde_json::from_str(value).map_err(|_| invalid_marker())?;
    if marker.version != 1
        || &marker.source != source
        || &marker.scope != scope
        || marker.plan_digest.len() != 64
        || !marker
            .plan_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_marker());
    }
    Ok(())
}

fn invalid_marker() -> ObservationStoreError {
    ObservationStoreError::Storage {
        operation: "validate source exclusion",
        source: Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid source exclusion marker",
        )),
    }
}

impl ObservationWrite {
    /// Terminal coverage carries no observation or sanitization receipt.
    pub fn source_exclusion_advance(&self) -> ObservationStoreResult<ObservationCursorAdvance> {
        let observation = self.observation();
        let mut advance = ObservationCursorAdvance::for_ordering(
            observation.source().clone(),
            observation.scope().clone(),
            observation.identity().generation(),
            observation.identity().ordering_domain(),
            self.expected_cursor().cloned(),
            observation.identity().position(),
            ObservationCoverageReason::OperatorPrunedSource,
        )?;
        if self.next_cursor().file_identity().is_some()
            != self.next_cursor().resume_fingerprint().is_some()
        {
            return Err(ObservationStoreError::CursorObservationMismatch);
        }
        advance.next_cursor = self.next_cursor().clone();
        Ok(advance)
    }
}

impl ObservationCursorAdvance {
    /// Preserve CAS, coverage, and resume checkpoint while dropping receipt evidence.
    pub fn source_exclusion_advance(&self) -> Self {
        let mut advance = self.clone();
        advance.reason = ObservationCoverageReason::OperatorPrunedSource;
        advance.sanitization_receipt = None;
        advance
    }
}
