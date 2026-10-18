//! Fresh host authority for retained state controls, independent of provider activation.
//!
//! Composition supplies the registered canonical session store and the mounted
//! scope. A control namespace is authorized only when it names this mounted
//! checkout, either through a retained recall trace or through a canonical
//! session registered in the project's session store. This module never starts
//! a provider, creates a missing retained store or dispatches a provider control.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracedecay_contracts::ResolvedScope;
use tracedecay_domain::UserProfileId;
use tracedecay_global_db::RegisteredGlobalDbLeaseV1;
use tracedecay_memory_provider_registry::{
    OperationControl, OwnedExactScope, OwnedProviderId, TerminalCode,
};

use super::super::cognitive_recall::{
    LEDGER_FILE_NAME, RecallAdmissionLedgerV1,
    control_attribution::{RecallLocatorKeyV1, RetainedRecallControlScopeV1},
};
use super::super::observation_journey::exact_scope_for_session;

/// Typed refusals of the retained control authority.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlAuthorityErrorV1 {
    #[error("control authority unavailable: {0}")]
    Unavailable(&'static str),
    #[error("control namespace is ineligible: {0}")]
    Ineligible(&'static str),
    #[error("control claim differs from its current authority: {0}")]
    ClaimMismatch(&'static str),
    #[error("control operation stopped: {0:?}")]
    Control(TerminalCode),
}

type Result<T> = std::result::Result<T, ControlAuthorityErrorV1>;

/// Host composition inputs. None of these paths or ports comes from a control request.
pub(crate) struct ProviderControlAuthorityInputsV1 {
    pub(crate) profile_id: UserProfileId,
    pub(crate) mounted_scope: ResolvedScope,
    pub(crate) session_db: RegisteredGlobalDbLeaseV1,
    pub(crate) store_data_root: PathBuf,
    pub(crate) live_ledger: Option<Arc<RecallAdmissionLedgerV1>>,
    pub(crate) locator_key: RecallLocatorKeyV1,
}

/// Canonical namespace authority, with no registry, selected provider, or worker owner.
pub(crate) struct ProviderControlAuthorityV1 {
    session_db: RegisteredGlobalDbLeaseV1,
    profile_id: UserProfileId,
    mounted_scope: ResolvedScope,
    ledger: Option<Arc<RecallAdmissionLedgerV1>>,
}

impl ProviderControlAuthorityV1 {
    /// Call once from existing composition blocking work, under project-open control.
    ///
    /// A live recall ledger is shared with the mounted recall route. Without
    /// one, an existing ledger from an earlier active generation is reopened
    /// read-through; a missing ledger is never created by the control path.
    pub(crate) fn from_mounted_data(
        inputs: ProviderControlAuthorityInputsV1,
        control: &OperationControl,
    ) -> Result<Self> {
        check(control)?;
        inputs
            .mounted_scope
            .validate()
            .map_err(|_| ControlAuthorityErrorV1::Ineligible("mounted scope"))?;
        let ledger_path = inputs.store_data_root.join(LEDGER_FILE_NAME);
        let ledger = match inputs.live_ledger {
            Some(ledger) => {
                if ledger.path() != ledger_path {
                    return Err(ControlAuthorityErrorV1::ClaimMismatch(
                        "live retained ledger placement",
                    ));
                }
                Some(ledger)
            }
            None if existing_regular_file(&ledger_path)? => Some(Arc::new(
                RecallAdmissionLedgerV1::open_existing_with_key(ledger_path, inputs.locator_key)
                    .map_err(|_| {
                        ControlAuthorityErrorV1::Unavailable("existing retained recall ledger")
                    })?,
            )),
            None => None,
        };
        check(control)?;
        Ok(Self {
            session_db: inputs.session_db,
            profile_id: inputs.profile_id,
            mounted_scope: inputs.mounted_scope,
            ledger,
        })
    }

    /// The host-owned retained recall ledger, when one exists for this project.
    pub(crate) fn ledger(&self) -> Option<Arc<RecallAdmissionLedgerV1>> {
        self.ledger.as_ref().map(Arc::clone)
    }

    /// A retained namespace keeps its original agent session. It is checked
    /// against the mounted profile/checkout instead of being relabeled for a caller.
    pub(crate) fn authorize_scope(
        &self,
        retained: &RetainedRecallControlScopeV1,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        check(control)?;
        validate_retained_scope_identity(retained)?;
        self.validate_destination(&retained.delivery_scope)?;
        check(control)?;
        Ok(retained.clone())
    }

    /// An untrusted composite canonical key is authorized only through its
    /// registered row in this project's canonical session store.
    pub(crate) async fn authorize_canonical_session(
        &self,
        provider_id: &OwnedProviderId,
        registration_revision: u64,
        canonical_provider_id: &str,
        session_id: &str,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        check(control)?;
        if registration_revision == 0 || registration_revision > i64::MAX as u64 {
            return Err(ControlAuthorityErrorV1::ClaimMismatch(
                "registration revision",
            ));
        }
        if !valid_lookup_key(canonical_provider_id) || !valid_lookup_key(session_id) {
            return Err(ControlAuthorityErrorV1::ClaimMismatch(
                "canonical session lookup",
            ));
        }
        let session = bounded_read(
            control,
            self.session_db
                .get_session_result(canonical_provider_id, session_id),
            "registered canonical session",
        )
        .await?
        .ok_or(ControlAuthorityErrorV1::Ineligible(
            "registered canonical session missing",
        ))?;
        if session.provider != canonical_provider_id || session.session_id != session_id {
            return Err(ControlAuthorityErrorV1::ClaimMismatch(
                "canonical session row key",
            ));
        }
        let delivery_scope =
            exact_scope_for_session(&self.profile_id, &self.mounted_scope, session_id)
                .map_err(|_| ControlAuthorityErrorV1::Ineligible("destination scope"))?;
        self.validate_destination(&delivery_scope)?;
        check(control)?;
        Ok(RetainedRecallControlScopeV1 {
            provider_id: provider_id.clone(),
            registration_revision,
            delivery_scope,
        })
    }

    fn validate_destination(&self, destination: &OwnedExactScope) -> Result<()> {
        destination
            .validate()
            .map_err(|_| ControlAuthorityErrorV1::ClaimMismatch("destination"))?;
        let scope = &self.mounted_scope;
        if destination.profile_id != self.profile_id.as_str()
            || destination.project_id != scope.project_id.as_str()
            || destination.repository_identity != scope.repository_id.as_str()
            || destination.worktree_identity != scope.worktree_id.as_str()
            || Some(destination.branch_identity.as_str())
                != scope.reference.as_ref().map(|value| value.as_str())
            || destination.resolved_scope_digest != scope.scope_digest.as_str()
        {
            return Err(ControlAuthorityErrorV1::Ineligible("destination checkout"));
        }
        Ok(())
    }
}

fn valid_lookup_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn validate_retained_scope_identity(scope: &RetainedRecallControlScopeV1) -> Result<()> {
    OwnedProviderId::new(scope.provider_id.as_str())
        .map_err(|_| ControlAuthorityErrorV1::ClaimMismatch("retained producing provider"))?;
    if scope.registration_revision == 0 || scope.registration_revision > i64::MAX as u64 {
        return Err(ControlAuthorityErrorV1::ClaimMismatch(
            "retained registration revision",
        ));
    }
    scope
        .delivery_scope
        .validate()
        .map_err(|_| ControlAuthorityErrorV1::ClaimMismatch("retained delivery scope"))
}

fn check(control: &OperationControl) -> Result<()> {
    control
        .snapshot()
        .map(|_| ())
        .map_err(ControlAuthorityErrorV1::Control)
}

/// Awaits one canonical read inside the control's own deadline and cancellation.
async fn bounded_read<T, E>(
    control: &OperationControl,
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
    authority: &'static str,
) -> Result<T> {
    let snapshot = control
        .snapshot()
        .map_err(ControlAuthorityErrorV1::Control)?;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(snapshot.remaining_millis);
    tokio::pin!(future);
    loop {
        check(control)?;
        tokio::select! {
            biased;
            result = &mut future => {
                check(control)?;
                return result.map_err(|_| ControlAuthorityErrorV1::Unavailable(authority));
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(ControlAuthorityErrorV1::Control(
                    control.snapshot().err().unwrap_or(TerminalCode::DeadlineExceeded),
                ));
            }
            () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
    }
}

fn existing_regular_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(ControlAuthorityErrorV1::Unavailable(
            "retained data file is not regular",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ControlAuthorityErrorV1::Unavailable(
            "retained data file metadata",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_ledger_constructor_fails_without_creating_a_missing_file() {
        let temporary = tempfile::tempdir().unwrap();
        let ledger = temporary.path().join(LEDGER_FILE_NAME);
        assert!(!ledger.exists());
        assert!(RecallAdmissionLedgerV1::open_existing(ledger.clone()).is_err());
        assert!(!ledger.exists());
    }

    #[test]
    fn missing_ledgers_are_not_materialized_by_path() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join(LEDGER_FILE_NAME);
        assert!(!existing_regular_file(&missing).unwrap());
        assert!(!missing.exists());
        assert!(existing_regular_file(temporary.path()).is_err());
    }
}
