//! Fresh host authority for retained controls, independent of provider activation.
//!
//! Composition supplies the existing canonical ports and opens host-owned data
//! files under its own project-open budget. This module never starts a provider,
//! creates a missing retained store or dispatches a provider control.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracedecay_contracts::ResolvedScope;
use tracedecay_domain::UserProfileId;
use tracedecay_global_db::{GlobalDbObservationStore, RegisteredGlobalDbLeaseV1};
use tracedecay_memory_observation::{
    ObservationJournalError, ProviderSourceDeletionIntentV1, ProviderSourceIntentReceiptV1,
    RecoveryTimeBudgetV1, SqliteObservationJournal,
};
use tracedecay_memory_provider_registry::{
    HistoryGrant, OperationControl, OwnedExactScope, OwnedProviderId, TerminalCode,
};
use tracedecay_runtime_core::db::Database;
use tracedecay_store::StoreShardIdV1;

use super::super::provider_history::{
    HistoryIdentityBridgeV1, HookOriginReaderV1, MountedOriginalObservationAuthorityV1,
    PhysicalPathIdentityV1, PhysicalPathKind, ProviderHistoryErrorV1, ProviderHistoryReaderV1,
    bounded_read, original_source_fence_digest,
};
use tracedecay_rusqlite_runtime::recall_admission::{
    LEDGER_FILE_NAME, RecallAdmissionLedgerV1,
    control_attribution::{
        RecallLocatorKeyV1, RetainedRecallControlScopeV1, RetainedRecallControlSourceV1,
    },
};

type Result<T> = std::result::Result<T, ProviderHistoryErrorV1>;

/// Host composition inputs. None of these paths or ports comes from a control request.
pub(crate) struct ProviderControlAuthorityInputsV1 {
    pub(crate) canonical_project_path: PathBuf,
    pub(crate) profile_id: UserProfileId,
    pub(crate) mounted_scope: ResolvedScope,
    pub(crate) session_db: RegisteredGlobalDbLeaseV1,
    pub(crate) dispositions: Arc<Database>,
    pub(crate) hook_origin_reader: Arc<HookOriginReaderV1>,
    pub(crate) store_data_root: PathBuf,
    pub(crate) live_ledger: Option<Arc<RecallAdmissionLedgerV1>>,
    pub(crate) locator_key: RecallLocatorKeyV1,
    /// Journal handles projected from the daemon-owned observation journeys.
    /// The control authority may read these handles, but it never discovers or
    /// reopens a provider journal from `store_data_root`.
    pub(crate) live_journals: Vec<(OwnedProviderId, Arc<SqliteObservationJournal>)>,
    pub(crate) runtime: tokio::runtime::Handle,
}

/// Canonical data authority, with no registry, selected provider, or worker owner.
pub(crate) struct ProviderControlAuthorityV1 {
    session_db: RegisteredGlobalDbLeaseV1,
    registered_shard: StoreShardIdV1,
    profile_id: UserProfileId,
    mounted_scope: ResolvedScope,
    observations: Arc<GlobalDbObservationStore>,
    dispositions: Arc<Database>,
    original_authority: Arc<MountedOriginalObservationAuthorityV1>,
    store_data_root: PathBuf,
    store_data_root_identity: PhysicalPathIdentityV1,
    ledger: Option<Arc<RecallAdmissionLedgerV1>>,
    locator_key: RecallLocatorKeyV1,
    journals: BTreeMap<OwnedProviderId, Arc<SqliteObservationJournal>>,
    pub(super) runtime: tokio::runtime::Handle,
}

/// Exact retained producing identity together with a fresh canonical source grant.
pub(crate) struct AuthorizedRetainedControlSourceV1 {
    pub(crate) retained: RetainedRecallControlSourceV1,
    pub(crate) grant: HistoryGrant,
    pub(crate) journal: Arc<SqliteObservationJournal>,
    authority: Arc<ProviderControlAuthorityV1>,
}

/// Fresh canonical inventory read for one already-authorized provider namespace.
/// This is ephemeral authority; only immutable source attributions may be retained.
pub(crate) struct AuthorizedCanonicalControlInventoryV1 {
    pub(crate) scope: RetainedRecallControlScopeV1,
    pub(crate) grant: Option<HistoryGrant>,
    pub(crate) checkpoint: tracedecay_memory_provider_registry::RestoreDispositionCheckpoint,
    pub(crate) journal: Arc<SqliteObservationJournal>,
}

impl AuthorizedCanonicalControlInventoryV1 {
    pub(crate) fn sources(&self) -> &[tracedecay_memory_provider_registry::GrantedHistorySource] {
        self.grant
            .as_ref()
            .map_or(&[], |grant| grant.sources.as_slice())
    }
}

/// Exact retained admission and durable attempt receipt for a freshly checked source.
pub(crate) struct ResolvedCanonicalControlObservationV1 {
    pub(crate) source: AuthorizedRetainedControlSourceV1,
    pub(crate) admitted: Box<tracedecay_memory_observation::AdmittedObservationV1>,
    pub(crate) receipt: tracedecay_memory_observation::ObservationDeliveryReceiptV1,
}

impl ProviderControlAuthorityV1 {
    /// Rechecks every composition binding before a control token is touched.
    /// The registered lease, bridge and hook reader must still describe the
    /// same brain/profile/project and physical data root after a reopen.
    pub(crate) fn validate_mount(&self) -> Result<()> {
        if self.session_db.binding().shard_id != self.registered_shard {
            return Err(ProviderHistoryErrorV1::Ineligible(
                "registered history shard changed",
            ));
        }
        self.original_authority.validate_mount(
            &self.profile_id,
            &self.mounted_scope,
            &self.registered_shard,
        )?;
        self.original_authority
            .reader
            .validate_data_root(&self.store_data_root)?;
        self.store_data_root_identity.validate_current(
            &self.store_data_root,
            "history data root",
            PhysicalPathKind::Directory,
        )?;
        self.original_authority.bridge.revalidate()
    }

    /// Authorize a composite canonical key through its row in the admitted
    /// project shard and the mounted profile/project/worktree authority.
    pub(crate) async fn authorize_canonical_session(
        self: &Arc<Self>,
        provider_id: &OwnedProviderId,
        registration_revision: u64,
        canonical_provider_id: &str,
        session_id: &str,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        self.validate_mount()?;
        check(control)?;
        let provider_id = OwnedProviderId::new(provider_id.as_str())
            .map_err(|_| ProviderHistoryErrorV1::ClaimMismatch("advisory provider"))?;
        if registration_revision == 0 || registration_revision > i64::MAX as u64 {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "registration revision",
            ));
        }
        if canonical_provider_id.is_empty()
            || canonical_provider_id.len() > 1024
            || session_id.is_empty()
            || session_id.len() > 1024
            || canonical_provider_id.chars().any(char::is_control)
            || session_id.chars().any(char::is_control)
            || canonical_provider_id.trim() != canonical_provider_id
            || session_id.trim() != session_id
        {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "canonical session lookup",
            ));
        }
        let authority = Arc::clone(self);
        let canonical_provider_id = canonical_provider_id.to_owned();
        let session_id = session_id.to_owned();
        let operation = control.clone();
        let work = self.runtime.spawn_blocking(move || {
            check(&operation)?;
            let bridge = &authority.original_authority.bridge;
            let destination = bridge.destination(&session_id)?;
            bridge.authorize_control_scope(&destination, &operation)?;
            let session = authority
                .runtime
                .block_on(bounded_read(
                    &operation,
                    authority
                        .session_db
                        .get_session(&canonical_provider_id, &session_id),
                    "registered canonical session",
                ))?
                .ok_or(ProviderHistoryErrorV1::Ineligible(
                    "registered canonical session missing",
                ))?;
            if session.provider != canonical_provider_id || session.session_id != session_id {
                return Err(ProviderHistoryErrorV1::ClaimMismatch(
                    "canonical session row key",
                ));
            }
            // Re-enrollment can retain rows from the preceding project in this
            // same sessions file. The row's durable owner must match the current
            // admitted project; its location path is not ownership authority.
            if session.project_key != authority.mounted_scope.project_id.as_str() {
                return Err(ProviderHistoryErrorV1::Ineligible(
                    "canonical session project",
                ));
            }
            authority
                .original_authority
                .authorize_registered_canonical_session(&session_id, &destination, &operation)?;
            bridge.authorize_control_scope(&destination, &operation)?;
            Ok(RetainedRecallControlScopeV1 {
                provider_id,
                registration_revision,
                delivery_scope: destination,
            })
        });
        bounded_read(control, work, "canonical session authority worker").await?
    }

    /// Freshly resolves every declared source identity through canonical storage.
    /// Empty inventory still checks the current exact destination namespace.
    pub(crate) async fn authorize_source_inventory(
        self: &Arc<Self>,
        scope: &RetainedRecallControlScopeV1,
        sources: &[tracedecay_memory_provider_registry::OriginalSourceIdentity],
        control: &OperationControl,
    ) -> Result<AuthorizedCanonicalControlInventoryV1> {
        self.validate_mount()?;
        check(control)?;
        if sources.len() > tracedecay_memory_provider_registry::MAX_ADVISORY_ADMISSION_SOURCES {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "control source inventory bound",
            ));
        }
        let authority = Arc::clone(self);
        let scope = scope.clone();
        let sources = sources.to_vec();
        let operation = control.clone();
        let work = self.runtime.spawn_blocking(move || {
            validate_retained_scope_identity(&scope)?;
            let journal = authority
                .journals
                .get(&scope.provider_id)
                .map(Arc::clone)
                .ok_or(ProviderHistoryErrorV1::Ineligible(
                    "original provider journal missing",
                ))?;
            let reader = ProviderHistoryReaderV1 {
                bridge: authority.original_authority.bridge.as_ref(),
                observations: authority.observations.as_ref(),
                dispositions: authority.dispositions.as_ref(),
                original_authority: authority.original_authority.as_ref(),
                journal: journal.as_ref(),
                provider_id: &scope.provider_id,
                policy_revision: super::PROVIDER_CONTROL_POLICY_REVISION_V1,
            };
            let (grant, checkpoint) = authority.runtime.block_on(async {
                reader
                    .bridge
                    .authorize_control_scope(&scope.delivery_scope, &operation)?;
                let mut current = Vec::with_capacity(sources.len());
                let mut unique = std::collections::BTreeSet::new();
                for source in sources {
                    check(&operation)?;
                    if !unique.insert(source.observation_id.clone()) {
                        return Err(ProviderHistoryErrorV1::ClaimMismatch(
                            "duplicate canonical source",
                        ));
                    }
                    current.push(
                        reader
                            .authorize_original_source_identity(
                                &scope.delivery_scope,
                                &source,
                                &operation,
                            )
                            .await?,
                    );
                }
                reader
                    .bridge
                    .authorize_control_scope(&scope.delivery_scope, &operation)?;
                let grant = if current.is_empty() {
                    None
                } else {
                    Some(reader.grant(&scope.delivery_scope, current)?)
                };
                let checkpoint = match &grant {
                    Some(grant) => grant.disposition_checkpoint.clone(),
                    None => reader.disposition_checkpoint(&scope.delivery_scope, &[])?,
                };
                Ok::<_, ProviderHistoryErrorV1>((grant, checkpoint))
            })?;
            check(&operation)?;
            Ok(AuthorizedCanonicalControlInventoryV1 {
                scope,
                grant,
                checkpoint,
                journal,
            })
        });
        bounded_read(control, work, "canonical control inventory worker").await?
    }

    /// Resolves actual journal evidence for inspection, including an unavailable
    /// current disposition when canonical authority still proves the source.
    pub(crate) async fn resolve_settled_observation(
        self: &Arc<Self>,
        source: &AuthorizedRetainedControlSourceV1,
        control: &OperationControl,
    ) -> Result<ResolvedCanonicalControlObservationV1> {
        self.settled_observation(source, true, control).await
    }

    /// A replacement is a real, presently eligible canonical observation with
    /// its original sanitized admission. No replacement payload is generated.
    pub(crate) async fn prepare_replacement_observation(
        self: &Arc<Self>,
        source: &AuthorizedRetainedControlSourceV1,
        control: &OperationControl,
    ) -> Result<ResolvedCanonicalControlObservationV1> {
        self.settled_observation(source, false, control).await
    }

    async fn settled_observation(
        self: &Arc<Self>,
        source: &AuthorizedRetainedControlSourceV1,
        include_unavailable: bool,
        control: &OperationControl,
    ) -> Result<ResolvedCanonicalControlObservationV1> {
        let source = self
            .authorize_source(&source.retained, include_unavailable, control)
            .await?;
        let operation = control.clone();
        let work = self.runtime.spawn_blocking(move || {
            let snapshot = operation
                .snapshot()
                .map_err(ProviderHistoryErrorV1::Control)?;
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(snapshot.remaining_millis);
            let scope = &source.retained.scope;
            let expected = &source
                .grant
                .sources
                .first()
                .ok_or(ProviderHistoryErrorV1::ClaimMismatch(
                    "canonical source grant",
                ))?
                .attribution;
            let evidence = source
                .journal
                .read_source_deliveries(
                    &tracedecay_memory_observation::ObservationLaneKeyV1 {
                        provider_id: scope.provider_id.clone(),
                        registration_revision: scope.registration_revision,
                    },
                    &scope.delivery_scope,
                    &tracedecay_memory_observation::SourceStreamKeyV1 {
                        source_authority:
                            tracedecay_memory_observation::SourceAuthorityV1::HostSession,
                        exact_scope_sha256: scope.delivery_scope.exact_scope_sha256(),
                        source_stream: super::super::observation_journey::history_source_stream(
                            &scope.delivery_scope,
                            source.grant.policy_revision,
                        )
                        .map_err(|_| {
                            ProviderHistoryErrorV1::Unavailable("history source stream")
                        })?,
                    },
                    &[tracedecay_memory_observation::ExpectedSourceDeliveryV1 {
                        source_sequence: tracedecay_memory_observation::SourceSequenceV1(
                            expected.source_sequence,
                        ),
                        source_event_id: expected.source.observation_id.clone(),
                    }],
                    RecoveryTimeBudgetV1 {
                        remaining_micros: i64::try_from(snapshot.remaining_millis)
                            .unwrap_or(i64::MAX)
                            .saturating_mul(1_000),
                    },
                    &operation.cancellation(),
                )
                .map_err(control_journal_error)?;
            check(&operation)?;
            let settled = super::super::observation_journey::validate_history_delivery_evidence(
                &source.grant,
                evidence.clone(),
                &operation.cancellation(),
                deadline,
            )
            .map_err(|_| {
                operation.snapshot().err().map_or(
                    ProviderHistoryErrorV1::Ineligible("settled canonical delivery evidence"),
                    ProviderHistoryErrorV1::Control,
                )
            })?;
            if !settled {
                return Err(ProviderHistoryErrorV1::Ineligible(
                    "canonical source delivery unsettled",
                ));
            }
            let mut evidence = evidence;
            if evidence.len() != 1 {
                return Err(ProviderHistoryErrorV1::ClaimMismatch(
                    "one canonical delivery",
                ));
            }
            let Some(tracedecay_memory_observation::SourceDeliveryEvidenceV1::Retained {
                admitted,
                receipt: Some(receipt),
                ..
            }) = evidence.pop()
            else {
                return Err(ProviderHistoryErrorV1::Ineligible(
                    "canonical delivery receipt missing",
                ));
            };
            check(&operation)?;
            Ok(ResolvedCanonicalControlObservationV1 {
                source,
                admitted,
                receipt: *receipt,
            })
        });
        bounded_read(control, work, "canonical settled observation worker").await?
    }

    /// Reauthorizes complete retained attributions; unavailable dispositions are
    /// returned as current evidence, never promoted to eligible content.
    pub(crate) async fn authorize_retained_source_inventory(
        self: &Arc<Self>,
        scope: &RetainedRecallControlScopeV1,
        sources: &[tracedecay_memory_provider_registry::recall_admission::source_attribution::RecallSourceAttributionV1],
        control: &OperationControl,
    ) -> Result<AuthorizedCanonicalControlInventoryV1> {
        self.validate_mount()?;
        check(control)?;
        if sources.len() > tracedecay_memory_provider_registry::MAX_ADVISORY_ADMISSION_SOURCES {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "retained inventory source bound",
            ));
        }
        let identities = sources
            .iter()
            .map(|source| {
                source
                    .to_owned_attribution()
                    .map(|source| source.source)
                    .map_err(|_| {
                        ProviderHistoryErrorV1::ClaimMismatch("retained inventory attribution")
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let inventory = self
            .authorize_source_inventory(scope, &identities, control)
            .await?;
        if inventory.sources().len() != sources.len() {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "retained inventory count",
            ));
        }
        for (actual, retained) in inventory.sources().iter().zip(sources) {
            check(control)?;
            let retained = retained.to_owned_attribution().map_err(|_| {
                ProviderHistoryErrorV1::ClaimMismatch("retained inventory attribution")
            })?;
            if actual.attribution != retained {
                return Err(ProviderHistoryErrorV1::ClaimMismatch(
                    "retained inventory changed",
                ));
            }
        }
        check(control)?;
        Ok(inventory)
    }

    /// Call once from existing composition blocking work, under project-open control.
    ///
    /// Observation journeys are mounted by the daemon composition before this
    /// authority is built. Their journal handles are injected through
    /// `live_journals`; this control path must never reopen a journal from a
    /// request-derived or guessed filesystem path. A provider whose journey was
    /// not mounted remains unavailable to source controls.
    pub(crate) fn from_mounted_data(
        inputs: ProviderControlAuthorityInputsV1,
        control: &OperationControl,
    ) -> Result<Self> {
        let registered_shard = inputs.session_db.binding().shard_id.clone();
        let store_data_root_identity = inputs
            .hook_origin_reader
            .bind_data_root(&inputs.store_data_root)?;
        inputs.hook_origin_reader.validate_mount_identity(
            &inputs.profile_id,
            &inputs.mounted_scope,
            &registered_shard,
        )?;
        inputs
            .hook_origin_reader
            .validate_data_root(&inputs.store_data_root)?;
        if inputs.live_journals.len() > 2 {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "retained journal count",
            ));
        }
        let bridge = HistoryIdentityBridgeV1::admit(
            &inputs.canonical_project_path,
            &inputs.profile_id,
            &inputs.mounted_scope,
            &registered_shard,
        )?;
        let original_authority = Arc::new(MountedOriginalObservationAuthorityV1 {
            reader: inputs.hook_origin_reader,
            bridge: Arc::new(bridge),
        });
        original_authority.validate_mount(
            &inputs.profile_id,
            &inputs.mounted_scope,
            &registered_shard,
        )?;
        // Identity admission is complete before this first control snapshot.
        check(control)?;
        let ledger_path = inputs.store_data_root.join(LEDGER_FILE_NAME);
        let locator_key = inputs.locator_key.clone();
        let ledger = match inputs.live_ledger {
            Some(ledger) => {
                if ledger.path() != ledger_path {
                    return Err(ProviderHistoryErrorV1::ClaimMismatch(
                        "live retained ledger placement",
                    ));
                }
                Some(ledger)
            }
            None if existing_regular_file(&ledger_path)? => Some(Arc::new(
                RecallAdmissionLedgerV1::open_existing_with_key(ledger_path, locator_key.clone())
                    .map_err(|_| {
                    ProviderHistoryErrorV1::Unavailable("existing retained recall ledger")
                })?,
            )),
            None => None,
        };
        let mut journals = BTreeMap::new();
        for (provider, journal) in inputs.live_journals {
            if journals.insert(provider, journal).is_some() {
                return Err(ProviderHistoryErrorV1::ClaimMismatch(
                    "live retained journal identity",
                ));
            }
        }
        // The mounted journey handles above are the complete journal
        // inventory. Do not infer additional providers from filenames: doing
        // so would create a second connection outside the journey's lifecycle
        // and could let a stale file outlive the daemon-owned source/grant
        // authority. Missing mounts fail closed in `authorize_source`.
        let authority = Self {
            observations: Arc::new(inputs.session_db.observation_store()),
            session_db: inputs.session_db,
            registered_shard,
            profile_id: inputs.profile_id,
            mounted_scope: inputs.mounted_scope,
            dispositions: inputs.dispositions,
            original_authority,
            store_data_root: inputs.store_data_root,
            store_data_root_identity,
            ledger,
            locator_key,
            journals,
            runtime: inputs.runtime,
        };
        authority.validate_mount()?;
        check(control)?;
        Ok(authority)
    }

    /// Use the ledger's bounded composite-key reads on the existing blocking pool.
    pub(crate) fn ledger(&self) -> Option<Arc<RecallAdmissionLedgerV1>> {
        // Callers use this accessor to read or write retained control rows
        // before invoking a more specific authority method. Reject a stale
        // checkout/root before handing out the host-owned ledger handle.
        self.validate_mount().ok()?;
        self.ledger.as_ref().map(Arc::clone)
    }

    /// A retained namespace keeps its original agent session. It is checked
    /// against the mounted profile/checkout instead of being relabeled for a caller.
    pub(crate) async fn authorize_scope(
        self: &Arc<Self>,
        retained: &RetainedRecallControlScopeV1,
        control: &OperationControl,
    ) -> Result<RetainedRecallControlScopeV1> {
        self.validate_mount()?;
        check(control)?;
        let authority = Arc::clone(self);
        let retained = retained.clone();
        let operation = control.clone();
        let work = self.runtime.spawn_blocking(move || {
            validate_retained_scope_identity(&retained)?;
            // Scope checks do not need to open or select a provider journal.
            authority
                .original_authority
                .bridge
                .authorize_control_scope(&retained.delivery_scope, &operation)?;
            Ok(retained)
        });
        bounded_read(control, work, "retained control scope worker").await?
    }

    /// Re-resolves the exact canonical source; retained checksums are never authority.
    /// Only a host-selected cleanup operation may request unavailable dispositions.
    pub(crate) async fn authorize_source(
        self: &Arc<Self>,
        retained: &RetainedRecallControlSourceV1,
        include_unavailable: bool,
        control: &OperationControl,
    ) -> Result<AuthorizedRetainedControlSourceV1> {
        self.validate_mount()?;
        check(control)?;
        let authority = Arc::clone(self);
        let retained = retained.clone();
        let operation = control.clone();
        let work = self.runtime.spawn_blocking(move || {
            validate_retained_scope_identity(&retained.scope)?;
            let journal = authority
                .journals
                .get(&retained.scope.provider_id)
                .map(Arc::clone)
                .ok_or(ProviderHistoryErrorV1::Ineligible(
                    "original provider journal missing",
                ))?;
            let reader = ProviderHistoryReaderV1 {
                bridge: authority.original_authority.bridge.as_ref(),
                observations: authority.observations.as_ref(),
                dispositions: authority.dispositions.as_ref(),
                original_authority: authority.original_authority.as_ref(),
                journal: journal.as_ref(),
                provider_id: &retained.scope.provider_id,
                policy_revision: super::PROVIDER_CONTROL_POLICY_REVISION_V1,
            };
            let grant = authority
                .runtime
                .block_on(reader.authorize_retained_source_locator(
                    &retained.scope.delivery_scope,
                    &retained.trace,
                    retained.scope.registration_revision,
                    retained.provider_rank,
                    &retained.candidate_id,
                    &retained.original_source,
                    &operation,
                    include_unavailable,
                    &authority.locator_key,
                ))?;
            check(&operation)?;
            Ok(AuthorizedRetainedControlSourceV1 {
                retained,
                grant,
                journal,
                authority,
            })
        });
        bounded_read(control, work, "retained control source worker").await?
    }

    /// Source-only controls cannot choose a destination from historical session
    /// rows. The canonical hook ledger has no current live-session authority.
    pub(crate) fn current_destination_scope(
        self: &Arc<Self>,
        canonical_provider_id: &str,
        control: &OperationControl,
    ) -> Result<OwnedExactScope> {
        self.validate_mount()?;
        check(control)?;
        if canonical_provider_id.is_empty()
            || canonical_provider_id.len() > 1024
            || canonical_provider_id.chars().any(char::is_control)
            || canonical_provider_id.trim() != canonical_provider_id
        {
            return Err(ProviderHistoryErrorV1::ClaimMismatch(
                "canonical source provider",
            ));
        }
        Err(ProviderHistoryErrorV1::Unavailable(
            super::super::provider_history::ORIGINAL_PROVENANCE_UNAVAILABLE,
        ))
    }
}

/// A confirmed receipt wins over every later cancellation or worker condition.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProviderSourceIntentActionErrorV1 {
    #[error("host intent refused before commit: {0}")]
    Refused(ObservationJournalError),
    #[error("host intent authority refused before journal access: {0}")]
    Authority(#[from] ProviderHistoryErrorV1),
    #[error("host intent storage outcome was not confirmed: {0}")]
    StorageUnconfirmed(ObservationJournalError),
    #[error("host intent worker did not return a confirmed outcome")]
    WorkerUnavailable,
}

impl AuthorizedRetainedControlSourceV1 {
    /// The host has already chosen and authorized the deletion policy. This helper
    /// only binds that intent to the freshly authorized original source and journal.
    /// Await it directly: a read timeout must not hide a committed host receipt.
    pub(crate) async fn record_deletion_intent(
        &self,
        request: &ProviderSourceDeletionIntentV1<'_>,
        control: &OperationControl,
    ) -> std::result::Result<ProviderSourceIntentReceiptV1, ProviderSourceIntentActionErrorV1> {
        self.deletion_journal_action(request, control, true)
            .await?
            .ok_or(ProviderSourceIntentActionErrorV1::WorkerUnavailable)
    }

    /// Exact, immutable receipt lookup for an uncertain previous host write.
    pub(crate) async fn read_deletion_intent_receipt(
        &self,
        request: &ProviderSourceDeletionIntentV1<'_>,
        control: &OperationControl,
    ) -> std::result::Result<Option<ProviderSourceIntentReceiptV1>, ProviderSourceIntentActionErrorV1>
    {
        self.deletion_journal_action(request, control, false).await
    }

    async fn deletion_journal_action(
        &self,
        request: &ProviderSourceDeletionIntentV1<'_>,
        control: &OperationControl,
        record: bool,
    ) -> std::result::Result<Option<ProviderSourceIntentReceiptV1>, ProviderSourceIntentActionErrorV1>
    {
        self.authority.validate_mount()?;
        check(control)?;
        self.grant
            .validate_structure()
            .map_err(|_| ProviderHistoryErrorV1::ClaimMismatch("control history grant"))?;
        let [source] = self.grant.sources.as_slice() else {
            return Err(
                ProviderHistoryErrorV1::ClaimMismatch("control history source count").into(),
            );
        };
        // `retained.original_source` is deliberately an opaque locator after
        // the SQLite privacy boundary. The canonical attribution in this fresh
        // grant has already been re-resolved and byte-compared against that
        // locator by `authorize_retained_source_locator`; use it for the
        // transient journal fence checks instead of trying to treat the
        // redacted projection as canonical authority.
        let expected = &source.attribution;
        if self.grant.destination_scope != self.retained.scope.delivery_scope
            || request.provider_id != self.retained.scope.provider_id.as_str()
            || request.original_source_sha256 != original_source_fence_digest(expected)?
            || request.source_revision != expected.source.source_revision.as_deref()
        {
            return Err(ProviderHistoryErrorV1::ClaimMismatch("host intent source binding").into());
        }
        let journal = Arc::clone(&self.journal);
        let operation = control.clone();
        let operation_id = request.operation_id.to_owned();
        let provider_id = request.provider_id.to_owned();
        let source = request.original_source_sha256.to_owned();
        let expected_fence_revision = request.expected_fence_revision;
        let mode = request.mode;
        let source_revision = request.source_revision.map(str::to_owned);
        let authority_ref = request.authority_ref.to_owned();
        let accepted_at_utc_micros = request.accepted_at_utc_micros;
        let work = self.authority.runtime.spawn_blocking(move || {
            // Snapshot after the blocking-pool queue wait; the original request
            // never receives a replacement budget or cancellation token.
            let snapshot = operation
                .snapshot()
                .map_err(ProviderHistoryErrorV1::Control)?;
            let budget = RecoveryTimeBudgetV1 {
                remaining_micros: i64::try_from(snapshot.remaining_millis)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000),
            };
            let request = ProviderSourceDeletionIntentV1 {
                operation_id: &operation_id,
                provider_id: &provider_id,
                original_source_sha256: &source,
                expected_fence_revision,
                mode,
                source_revision: source_revision.as_deref(),
                authority_ref: &authority_ref,
                accepted_at_utc_micros,
            };
            let result = if record {
                journal
                    .record_provider_source_deletion_intent_bounded(
                        &request,
                        budget,
                        &operation.cancellation(),
                    )
                    .map(Some)
            } else {
                journal.read_provider_source_deletion_intent_receipt_bounded(
                    &request,
                    budget,
                    &operation.cancellation(),
                )
            };
            result.map_err(|error| {
                // These refusal variants are emitted before COMMIT. An actual
                // successful COMMIT already returned its captured receipt.
                if record
                    && matches!(
                        &error,
                        ObservationJournalError::UnsettledSource { .. }
                            | ObservationJournalError::BudgetExhausted { .. }
                            | ObservationJournalError::OperationCancelled { .. }
                    )
                {
                    ProviderSourceIntentActionErrorV1::Refused(error)
                } else {
                    // SQLite/serialization errors are kept intact. The legacy
                    // error surface does not reveal whether COMMIT was entered.
                    ProviderSourceIntentActionErrorV1::StorageUnconfirmed(error)
                }
            })
        });
        // Always join this write in the host control path. The typed journal
        // receipt, not a subsequent deadline snapshot, determines commit truth.
        let result = work
            .await
            .map_err(|_| ProviderSourceIntentActionErrorV1::WorkerUnavailable)?;
        if !record {
            check(control)?;
        }
        result
    }
}

fn validate_retained_scope_identity(scope: &RetainedRecallControlScopeV1) -> Result<()> {
    OwnedProviderId::new(scope.provider_id.as_str())
        .map_err(|_| ProviderHistoryErrorV1::ClaimMismatch("retained producing provider"))?;
    if scope.registration_revision == 0 || scope.registration_revision > i64::MAX as u64 {
        return Err(ProviderHistoryErrorV1::ClaimMismatch(
            "retained registration revision",
        ));
    }
    scope
        .delivery_scope
        .validate()
        .map_err(|_| ProviderHistoryErrorV1::ClaimMismatch("retained delivery scope"))
}

fn check(control: &OperationControl) -> Result<()> {
    control
        .snapshot()
        .map(|_| ())
        .map_err(ProviderHistoryErrorV1::Control)
}

fn existing_regular_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(ProviderHistoryErrorV1::Unavailable(
            "retained data file is not regular",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProviderHistoryErrorV1::Unavailable(
            "retained data file metadata",
        )),
    }
}

fn control_journal_error(error: ObservationJournalError) -> ProviderHistoryErrorV1 {
    match error {
        ObservationJournalError::BudgetExhausted { .. } => {
            ProviderHistoryErrorV1::Control(TerminalCode::DeadlineExceeded)
        }
        ObservationJournalError::OperationCancelled { .. } => {
            ProviderHistoryErrorV1::Control(TerminalCode::Cancelled)
        }
        _ => ProviderHistoryErrorV1::Unavailable("canonical source journal evidence"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_owner::observation_journey::ObservationJourneyPolicyV1;

    #[test]
    fn existing_store_constructors_fail_without_creating_missing_files() {
        let temporary = tempfile::tempdir().unwrap();
        let ledger = temporary.path().join(LEDGER_FILE_NAME);
        let journal = temporary
            .path()
            .join("memory-observation-ncm-journal-v1.sqlite3");
        assert!(!ledger.exists());
        assert!(!journal.exists());
        assert!(RecallAdmissionLedgerV1::open_existing(ledger.clone()).is_err());
        assert!(
            SqliteObservationJournal::open_existing(
                &journal,
                ObservationJourneyPolicyV1::project_default().retention,
            )
            .is_err()
        );
        assert!(!ledger.exists());
        assert!(!journal.exists());
    }

    #[test]
    fn missing_injected_journals_are_not_materialized_by_path() {
        let temporary = tempfile::tempdir().unwrap();
        let missing = temporary.path().join(LEDGER_FILE_NAME);
        assert!(!existing_regular_file(&missing).unwrap());
        assert!(!missing.exists());
        assert!(existing_regular_file(temporary.path()).is_err());
    }
}
