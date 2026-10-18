//! Project memory-provider host assembly mounted by the retained owner.
//!
//! This module is compiled only with the `memory-provider-host` feature.

use std::path::PathBuf;
use std::sync::Arc;

use tracedecay_domain::ManifestDigest;
use tracedecay_project::project::TraceDecay;
use tracedecay_runtime_core::native_runtime;

use super::{
    AdvisoryMemoryContextV1, CognitiveRecallMountError, cognitive_recall, native_authority,
    native_provider, observation_journey, provider_control, provider_history,
};

// ---------------------------------------------------------------------------
// Project memory-provider host composition
// ---------------------------------------------------------------------------
//
// The daemon binary owns the project-open state machine and the NCM worker
// owner.  The retained owner crate owns the provider-neutral assembly below.
// Keeping these handles opaque is deliberate: the binary can publish and
// retain the result without importing the child retained-owner modules, while
// the service crate never reaches back into the binary composition root.

pub type NcmRegistrationFactoryV1 = Arc<
    dyn Fn(
            tracedecay_domain::UserProfileId,
            PathBuf,
            PathBuf,
            u64,
            tracedecay_memory_provider_registry::EnabledProviderMode,
            tracedecay_domain::configuration::MemoryProviderNcmNamespaceBindingV1,
            Option<Arc<dyn tracedecay_memory_provider_registry::AdvisoryAdmissionAuthority>>,
        ) -> std::result::Result<
            (
                tracedecay_memory_provider_registry::ProviderRegistrationV1,
                tracedecay_memory_provider_registry::ObservationProviderMountV1,
            ),
            String,
        > + Send
        + Sync,
>;

/// Test-only decoration of the production Native application port.
pub type NativeApplicationPortInterpositionV1 = Arc<
    dyn Fn(
            Arc<dyn tracedecay_memory_provider_registry::NativeMemoryApplicationPort>,
        ) -> Arc<dyn tracedecay_memory_provider_registry::NativeMemoryApplicationPort>
        + Send
        + Sync,
>;

/// Inputs needed to compose one project's provider registrations.
pub struct ProjectMemoryProviderHostInputsV1 {
    /// Validated participation resolved from the pinned project configuration.
    pub activation: tracedecay_domain::configuration::MemoryProviderSelectionV1,
    /// The configured NCM worker, if NCM participation is enabled.
    pub ncm_observer: tracedecay_domain::configuration::MemoryProviderNcmObserverV1,
    /// The graph authority the Native application port reads.
    pub graph: Arc<TraceDecay>,
    /// Canonical checkout root served by this project route.
    pub canonical_project_path: PathBuf,
    /// Profile identity bound to the route.
    pub profile_id: tracedecay_domain::UserProfileId,
    /// Exact scope published by the code-index authority.
    pub scope: tracedecay_contracts::ResolvedScope,
    /// Authoritative project identity checked against `scope`.
    pub authoritative_project_id: tracedecay_domain::ProjectId,
    /// Store-owned data root used for provider journals and the recall ledger.
    pub store_data_root: PathBuf,
    /// Pinned routing gate used to build the active recall policy.
    pub recall_routing: tracedecay_domain::configuration::MemoryProviderRecallRoutingV1,
    /// NCM registration is supplied by the daemon composition root because it
    /// owns the worker-generation slot and the concrete worker topology.
    pub ncm_registration_factory: Option<NcmRegistrationFactoryV1>,
    /// Optional test decoration of the real Native port.
    pub native_port_interposition: Option<NativeApplicationPortInterpositionV1>,
}

/// Opaque provider host retained by one project-server generation.
pub struct ProjectMemoryProviderHostMountV1 {
    composition: Arc<tracedecay_memory_provider_registry::ProjectMemoryProviderComposition>,
    observation_provider_mounts: Vec<(
        tracedecay_memory_provider_registry::ConfiguredObservationProviderMountV1,
        Arc<provider_history::ProviderHistoryAuthorityMountV1>,
    )>,
    cognitive_recall_mount: Option<Arc<ProjectCognitiveRecallMountV1>>,
    native_session_retrieval_mount: Option<Arc<native_authority::NativeSessionRetrievalMountV1>>,
    locator_key: cognitive_recall::control_attribution::RecallLocatorKeyV1,
}

impl ProjectMemoryProviderHostMountV1 {
    /// Returns the provider-neutral composition retained by this project.
    #[must_use]
    pub fn composition(
        &self,
    ) -> Arc<tracedecay_memory_provider_registry::ProjectMemoryProviderComposition> {
        Arc::clone(&self.composition)
    }

    /// Borrows the composed registry, or `None` for the inert disabled value.
    #[must_use]
    pub fn registry(
        &self,
    ) -> Option<&tracedecay_memory_provider_registry::ProjectMemoryProviderRegistry> {
        self.composition.registry()
    }

    /// The mounted recall route, when the configuration selected an active
    /// provider. The route remains owned by this same host generation.
    pub fn cognitive_recall_mount(&self) -> Option<Arc<ProjectCognitiveRecallMountV1>> {
        self.cognitive_recall_mount.as_ref().map(Arc::clone)
    }

    /// Binds the canonical project session retrieval service to the mounted
    /// Native provider and current observation recall owner.
    pub fn bind_session_retrieval(
        &self,
        retrieval: Arc<
            dyn tracedecay_session_runtime::session_retrieval::SessionApplicationRetrievalPortV1,
        >,
    ) -> Result<(), String> {
        if let Some(mount) = self.cognitive_recall_mount.as_ref() {
            mount
                .inner
                .bind_session_retrieval(Arc::clone(&retrieval))
                .map_err(str::to_owned)?;
        }
        if let Some(mount) = self.native_session_retrieval_mount.as_ref() {
            mount.bind(retrieval).map_err(str::to_owned)?;
        }
        Ok(())
    }
}

/// Opaque observation journey retained by a full project server.
pub struct ProjectObservationJourneyMountV1 {
    inner: Arc<observation_journey::ProjectObservationJourneyV1>,
}

impl ProjectObservationJourneyMountV1 {
    /// Shuts down the already-owned observation worker inside the caller's
    /// deadline and returns typed failures as display-safe text.
    pub async fn shutdown(&self, deadline: tokio::time::Instant) -> Vec<String> {
        match native_runtime::on_tokio("memory_provider.shutdown", self.shutdown_in_tokio(deadline))
        {
            Some(work) => work.await,
            None => vec!["memory provider Tokio runtime unavailable during shutdown".to_owned()],
        }
    }

    async fn shutdown_in_tokio(&self, deadline: tokio::time::Instant) -> Vec<String> {
        self.inner
            .shutdown(deadline)
            .await
            .into_iter()
            .map(|failure| failure.to_string())
            .collect()
    }
}

/// Opaque cognitive recall route retained by a project server.
pub struct ProjectCognitiveRecallMountV1 {
    pub(super) inner: Arc<cognitive_recall::ProjectCognitiveRecallMountV1>,
}

impl ProjectCognitiveRecallMountV1 {
    /// Revalidates the mounted recall authority and live request controls
    /// immediately before the transport publishes packed advisory context.
    pub fn validate_publication(
        &self,
        deadline: &tracedecay_contracts::Deadline,
        cancellation: &tracedecay_contracts::CancellationSignal,
    ) -> Result<(), cognitive_recall::AdvisoryRecallUnavailableV1> {
        self.inner.validate_publication(deadline, cancellation)
    }

    /// Mints a recall port bound to this route's exact project scope.
    pub fn port_for_session(
        &self,
        canonical_session_id: &str,
    ) -> std::result::Result<
        tracedecay_memory_provider_registry::ProjectCognitiveRecallPortV1,
        CognitiveRecallMountError,
    > {
        self.inner.port_for_session(canonical_session_id)
    }
}

/// Opaque admission result for the MCP advisory recall lane.
pub struct ProjectAdvisoryRecallCallV1 {
    inner: cognitive_recall::AdvisoryRecallCallV1,
}

impl ProjectAdvisoryRecallCallV1 {
    /// Carries the admitted canonical session retrieval context or its typed
    /// admission failure into the owning message hydration route.
    #[must_use]
    pub fn with_session_retrieval_context(
        self,
        context: Result<tracedecay_contracts::RequestContext, String>,
    ) -> Self {
        Self {
            inner: self.inner.with_session_retrieval_context(context),
        }
    }

    /// Returns the host-bound session identity used to mint the recall port.
    /// An empty value means the call was admitted without a usable binding and
    /// will receive a typed unavailable lane from the owner.
    #[must_use]
    pub fn canonical_session_id(&self) -> &str {
        self.inner.canonical_session_id()
    }
}

/// Admit a transport-neutral context tool call into the provider-owned
/// advisory lane. The transport crate supplies only the already-routed
/// arguments and request controls; it never reaches into the retained owner.
pub fn project_advisory_context_call(
    tool_name: &str,
    arguments: &serde_json::Value,
    request_id: Option<&tracedecay_contracts::RequestId>,
    deadline: Option<&tracedecay_contracts::Deadline>,
    cancellation: Option<&tracedecay_contracts::CancellationSignal>,
) -> Option<ProjectAdvisoryRecallCallV1> {
    cognitive_recall::advisory_context_call(
        tool_name,
        arguments,
        request_id,
        deadline,
        cancellation,
    )
    .map(|inner| ProjectAdvisoryRecallCallV1 { inner })
}

/// Execute an admitted provider advisory lane while keeping its child owner
/// type private to the daemon-service crate.
pub async fn project_advisory_memory_context_for_call(
    port: std::result::Result<
        tracedecay_memory_provider_registry::ProjectCognitiveRecallPortV1,
        CognitiveRecallMountError,
    >,
    mount: Option<&ProjectCognitiveRecallMountV1>,
    call: ProjectAdvisoryRecallCallV1,
    context_memory_contribution: Option<
        &tracedecay_contracts::retrieval::ContextMemoryContributionV1,
    >,
) -> Option<AdvisoryMemoryContextV1> {
    cognitive_recall::advisory_memory_context_for_call(
        port,
        mount.map(|mount| mount.inner.as_ref()),
        call.inner,
        context_memory_contribution,
    )
    .await
}

/// Inputs needed to mount the full observation and provider-control owners.
pub struct ProjectMemoryProviderFullMountInputsV1 {
    /// The same graph opened for the route.
    pub graph: Arc<TraceDecay>,
    /// Canonical checkout root served by the route.
    pub canonical_project_path: PathBuf,
    /// Profile identity bound to the route.
    pub profile_id: tracedecay_domain::UserProfileId,
    /// Brain identity used by the existing hook admission ledger.
    pub brain_id: tracedecay_domain::BrainId,
    /// Exact scope published by code-index admission.
    pub scope: tracedecay_contracts::ResolvedScope,
    /// Authoritative project identity checked against the scope.
    pub authoritative_project_id: tracedecay_domain::ProjectId,
    /// Canonical project session database lease.
    pub session_db: tracedecay_global_db::RegisteredGlobalDbLeaseV1,
    /// Pinned configuration digest retained by provider-control operations.
    pub configuration_digest: ManifestDigest,
}

/// Full provider-owner bundle retained after the core server is replaced.
pub struct ProjectMemoryProviderFullMountV1 {
    observation_journeys: Vec<Arc<ProjectObservationJourneyMountV1>>,
    deferred_observation_journeys: std::sync::Mutex<
        Vec<(
            Arc<observation_journey::ProjectObservationJourneyV1>,
            tracedecay_memory_provider_registry::ObservationMountRequirementV1,
        )>,
    >,
    provider_control_mount:
        Arc<dyn tracedecay_contracts::retained_surfaces::RetainedProviderControlExecutionPortV1>,
}

impl ProjectMemoryProviderFullMountV1 {
    /// Returns the retained observation journeys for the MCP server lifetime.
    #[must_use]
    pub fn observation_journeys(&self) -> Vec<Arc<ProjectObservationJourneyMountV1>> {
        self.observation_journeys.iter().map(Arc::clone).collect()
    }

    /// Returns the retained provider-control surface.
    #[must_use]
    pub fn provider_control_mount(
        &self,
    ) -> Arc<dyn tracedecay_contracts::retained_surfaces::RetainedProviderControlExecutionPortV1>
    {
        Arc::clone(&self.provider_control_mount)
    }

    /// Activates dormant journeys before the full MCP publication fence.
    ///
    /// Required deferred journeys wait for their strict provider-instance
    /// proof. Historical replay and delivery remain owned background work;
    /// current recall still hydrates through the canonical owning store.
    pub async fn activate_after_publication(
        &self,
        observation_store: tracedecay_global_db::GlobalDbObservationStore,
        cancellation: &tracedecay_runtime_core::cancellation::CancellationToken,
    ) -> std::result::Result<(), String> {
        if self
            .deferred_observation_journeys
            .lock()
            .map_err(|_| "provider observation activation state was poisoned".to_owned())?
            .is_empty()
        {
            return Ok(());
        }
        native_runtime::on_tokio(
            "memory_provider.activate",
            self.activate_after_publication_in_tokio(observation_store, cancellation),
        )
        .ok_or_else(|| "memory provider Tokio runtime unavailable".to_owned())?
        .await
    }

    async fn activate_after_publication_in_tokio(
        &self,
        observation_store: tracedecay_global_db::GlobalDbObservationStore,
        cancellation: &tracedecay_runtime_core::cancellation::CancellationToken,
    ) -> std::result::Result<(), String> {
        let deferred = self
            .deferred_observation_journeys
            .lock()
            .map_err(|_| "provider observation activation state was poisoned".to_owned())?
            .drain(..)
            .collect::<Vec<_>>();
        for (journey, requirement) in deferred {
            let activation = if requirement
                == tracedecay_memory_provider_registry::ObservationMountRequirementV1::Required
            {
                observation_journey::activate_required_with_instance_ready(
                    Arc::clone(&journey),
                    observation_store.clone(),
                    cancellation,
                )
                .await
                .map(|_| ())
            } else {
                journey.start_observer_with_live_replay(observation_store.clone())
            };
            if let Err(error) = activation {
                if requirement
                    == tracedecay_memory_provider_registry::ObservationMountRequirementV1::Required
                {
                    return Err(format!(
                        "required memory observation activation failed before full publication: {error}"
                    ));
                }
                tracing::warn!(
                    event = "memory_observation_optional_start_failed",
                    error = ?error,
                    journal = %journey.journal_path().display(),
                    "optional observer could not start after full host publication"
                );
            }
        }
        Ok(())
    }
}

/// Compose the provider registrations and the optional recall route for one
/// project. The concrete NCM constructor remains a closure supplied by the
/// daemon root, so service composition has no dependency cycle.
pub async fn mount_project_memory_provider_host(
    inputs: ProjectMemoryProviderHostInputsV1,
) -> std::result::Result<Arc<ProjectMemoryProviderHostMountV1>, String> {
    if inputs.activation.is_disabled() {
        return mount_project_memory_provider_host_in_tokio(inputs).await;
    }
    // The daemon polls this mount on its native runtime. Provider timers and
    // spawned work still belong to its installed Tokio runtime; entering that
    // runtime here keeps cancellation attached to the original mount future.
    native_runtime::on_tokio(
        "memory_provider.host_mount",
        mount_project_memory_provider_host_in_tokio(inputs),
    )
    .ok_or_else(|| "memory provider Tokio runtime unavailable".to_owned())?
    .await
}

async fn mount_project_memory_provider_host_in_tokio(
    inputs: ProjectMemoryProviderHostInputsV1,
) -> std::result::Result<Arc<ProjectMemoryProviderHostMountV1>, String> {
    use tracedecay_domain::configuration::MemoryProviderParticipationV1;
    use tracedecay_memory_provider_registry::{
        ConfiguredObservationProviderMountV1, EnabledProviderMode, FabricConfig,
        NativeMemoryApplicationPort, ObservationMountActivationV1, ObservationMountRequirementV1,
        ProjectMemoryProviderComposition, SelectedProviderActivationV1,
    };

    if inputs.activation.is_disabled() {
        let locator_key = new_recall_locator_key()?;
        return Ok(Arc::new(ProjectMemoryProviderHostMountV1 {
            composition: Arc::new(ProjectMemoryProviderComposition::Disabled),
            observation_provider_mounts: Vec::new(),
            cognitive_recall_mount: None,
            native_session_retrieval_mount: None,
            locator_key,
        }));
    }

    let mut selected_injected = None;
    let mut selected_native_port: Option<Arc<dyn NativeMemoryApplicationPort>> = None;
    let mut observers = Vec::new();
    let mut observation_provider_mounts = Vec::new();
    let mut native_session_retrieval_mount = None;

    // Native is upstream TraceDecay memory. It answers recall from the
    // canonical fact and message-search authorities and observes nothing, so
    // it is registered only when the routing gate selects it; an enabled but
    // unselected Native has no provider-host consequence at all.
    if inputs.activation.native == MemoryProviderParticipationV1::Active {
        let graph_cell = Arc::new(tokio::sync::RwLock::new(Arc::clone(&inputs.graph)));
        let session_retrieval = Arc::new(
            native_authority::NativeSessionRetrievalMountV1::for_project(
                inputs.profile_id.clone(),
                inputs.scope.clone(),
            ),
        );
        let port = native_provider::project_native_memory_application_port_off_runtime(
            graph_cell,
            inputs.canonical_project_path.clone(),
            Arc::clone(&session_retrieval),
        )
        .await
        .map_err(|error| format!("could not construct project Native application port: {error}"))?;
        let port = match inputs.native_port_interposition.as_ref() {
            Some(interpose) => interpose(port),
            None => port,
        };
        selected_native_port = Some(port);
        // The registration owns the port, while the host retains this handle
        // to bind the canonical session service after full admission.
        native_session_retrieval_mount = Some(session_retrieval);
    }

    let ncm_mode = match inputs.activation.ncm {
        MemoryProviderParticipationV1::Disabled => None,
        MemoryProviderParticipationV1::Observer => Some(EnabledProviderMode::Observer),
        MemoryProviderParticipationV1::Active => Some(EnabledProviderMode::Active),
    };
    if let Some(mode) = ncm_mode {
        let requirement = if mode == EnabledProviderMode::Active {
            ObservationMountRequirementV1::Required
        } else {
            ObservationMountRequirementV1::Optional
        };
        let history_mount = Arc::new(provider_history::ProviderHistoryAuthorityMountV1::default());
        let admission_authority: Arc<
            dyn tracedecay_memory_provider_registry::AdvisoryAdmissionAuthority,
        > = history_mount.clone();
        let constructed: std::result::Result<
            (
                tracedecay_memory_provider_registry::ProviderRegistrationV1,
                tracedecay_memory_provider_registry::ObservationProviderMountV1,
            ),
            String,
        > = async {
            let factory = inputs
                .ncm_registration_factory
                .clone()
                .ok_or_else(|| "NCM composition factory was not supplied".to_owned())?;
            let tracedecay_domain::configuration::MemoryProviderNcmObserverV1::Enabled {
                worker_binary,
                state_root,
                namespace_binding,
            } = inputs.ncm_observer.clone()
            else {
                return Err("selected NCM participation is disabled".to_owned());
            };
            let profile_id = inputs.profile_id.clone();
            tokio::task::spawn_blocking(move || {
                factory(
                    profile_id,
                    worker_binary,
                    state_root,
                    1,
                    mode,
                    namespace_binding,
                    Some(admission_authority),
                )
            })
            .await
            .map_err(|error| format!("NCM construction task unavailable: {error}"))?
        }
        .await;
        match constructed {
            Ok((registration, mount)) => {
                if mode == EnabledProviderMode::Active {
                    selected_injected = Some(registration);
                } else {
                    observers.push(registration);
                }
                observation_provider_mounts.push((
                    ConfiguredObservationProviderMountV1 {
                        mount,
                        requirement,
                        activation: ObservationMountActivationV1::AfterPublication,
                    },
                    history_mount,
                ));
            }
            Err(error) if requirement == ObservationMountRequirementV1::Optional => {
                tracing::warn!(
                    provider = tracedecay_domain::configuration::MemoryProviderKindV1::Ncm
                        .provider_id(),
                    error = %error,
                    "optional memory observer unavailable before registration"
                );
            }
            Err(error) => return Err(error),
        }
    }

    let fabric_config = FabricConfig {
        max_registered_providers: observers.len()
            + usize::from(selected_native_port.is_some() || selected_injected.is_some()),
        max_in_flight: 1,
    };
    let selection = match (selected_native_port, selected_injected) {
        (Some(port), None) => SelectedProviderActivationV1::Native {
            fabric_config,
            port,
            registration_revision: 1,
            mode: EnabledProviderMode::Active,
        },
        (None, Some(registration)) => SelectedProviderActivationV1::Injected {
            fabric_config,
            registration,
        },
        (None, None) => SelectedProviderActivationV1::ObserversOnly { fabric_config },
        (Some(_), Some(_)) => {
            return Err("multiple active memory providers were constructed".to_owned());
        }
    };
    let composition = Arc::new(
        ProjectMemoryProviderComposition::compose_registered(selection, observers)
            .map_err(|error| format!("could not compose project memory-provider host: {error}"))?,
    );

    let locator_key = new_recall_locator_key()?;
    let cognitive_recall_mount = match composition
        .registry()
        .and_then(|registry| registry.selected_registration())
    {
        Some(registration)
            if registration.mode == EnabledProviderMode::Active
                && inputs.scope.project_id == inputs.authoritative_project_id =>
        {
            let routing = project_recall_routing_policy(
                Some((
                    &registration.provider_id,
                    registration.registration_revision,
                )),
                &inputs.recall_routing,
            )?;
            let mount = cognitive_recall::mount_project_cognitive_recall(
                cognitive_recall::CognitiveRecallMountInputsV1 {
                    composition: Arc::clone(&composition),
                    profile_id: inputs.profile_id.clone(),
                    scope: inputs.scope.clone(),
                    authoritative_project_id: inputs.authoritative_project_id.clone(),
                    store_data_root: inputs.store_data_root.clone(),
                    canonical_project_path: inputs.canonical_project_path.clone(),
                    graph: Arc::clone(&inputs.graph),
                    routing,
                    host_limits: registration.limits,
                    invocation_boundary: cognitive_recall::host_provider_invocation_boundary(1),
                    locator_key: locator_key.clone(),
                },
            )
            .map_err(|error| format!("could not mount project cognitive recall route: {error}"))?;
            Some(Arc::new(ProjectCognitiveRecallMountV1 { inner: mount }))
        }
        Some(_) => {
            return Err(
                "active memory provider composition disagrees with the authoritative project scope"
                    .to_owned(),
            );
        }
        None => None,
    };

    Ok(Arc::new(ProjectMemoryProviderHostMountV1 {
        composition,
        observation_provider_mounts,
        cognitive_recall_mount,
        native_session_retrieval_mount,
        locator_key,
    }))
}

/// Inputs and owner assembly for the full project server. This function is
/// called only after the project session database has been admitted.
pub async fn mount_project_memory_provider_full(
    host: &Arc<ProjectMemoryProviderHostMountV1>,
    inputs: ProjectMemoryProviderFullMountInputsV1,
    cancellation: &tracedecay_runtime_core::cancellation::CancellationToken,
) -> std::result::Result<Arc<ProjectMemoryProviderFullMountV1>, String> {
    native_runtime::on_tokio(
        "memory_provider.full_mount",
        mount_project_memory_provider_full_in_tokio(host, inputs, cancellation),
    )
    .ok_or_else(|| "memory provider Tokio runtime unavailable".to_owned())?
    .await
}

async fn mount_project_memory_provider_full_in_tokio(
    host: &Arc<ProjectMemoryProviderHostMountV1>,
    inputs: ProjectMemoryProviderFullMountInputsV1,
    cancellation: &tracedecay_runtime_core::cancellation::CancellationToken,
) -> std::result::Result<Arc<ProjectMemoryProviderFullMountV1>, String> {
    use tracedecay_memory_provider_registry::ObservationMountRequirementV1;

    let hook_origin_reader = Arc::new(provider_history::HookOriginReaderV1::new(
        inputs.graph.hook_store_layout().data_root.clone(),
        inputs.brain_id.clone(),
        inputs.profile_id.clone(),
    ));
    let mut journeys = Vec::with_capacity(host.observation_provider_mounts.len());
    let mut deferred = Vec::new();
    let mut control_journals = Vec::new();
    macro_rules! fail_partial_provider_mount {
        ($error:expr) => {{
            let error = $error;
            shutdown_partial_provider_journeys(&journeys).await;
            return Err(error);
        }};
    }
    for (configured, history_mount) in &host.observation_provider_mounts {
        if cancellation.is_cancelled() {
            fail_partial_provider_mount!(
                "project open was cancelled during provider observation mount".to_owned()
            );
        }
        let provider = &configured.mount;
        let required = configured.requirement == ObservationMountRequirementV1::Required;
        let journey_inputs = observation_journey::ObservationJourneyMountInputsV1 {
            composition: Arc::clone(&host.composition),
            profile_id: inputs.profile_id.clone(),
            scope: inputs.scope.clone(),
            authoritative_project_id: inputs.authoritative_project_id.clone(),
            store_data_root: inputs.graph.store_layout().data_root.clone(),
            provider: provider.clone(),
            policy: observation_journey::ObservationJourneyPolicyV1::project_default(),
        };
        let journey =
            match observation_journey::mount_observer_dormant(journey_inputs, cancellation).await {
                Ok(journey) => journey,
                Err(error @ observation_journey::ObservationJourneyError::Cancelled { .. }) => {
                    fail_partial_provider_mount!(error.to_string());
                }
                Err(error) if required => {
                    fail_partial_provider_mount!(format!(
                        "could not mount project observation journey: {error}"
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        provider = provider.provider_id.as_str(),
                        error = %error,
                        "observer journey unavailable"
                    );
                    continue;
                }
            };
        let mounted_bridge = match provider_history::HistoryIdentityBridgeV1::admit(
            &inputs.canonical_project_path,
            &inputs.profile_id,
            &inputs.scope,
            &inputs.session_db.binding().shard_id,
        ) {
            Ok(bridge) => Some(Arc::new(bridge)),
            Err(error)
                if matches!(
                    &error,
                    provider_history::ProviderHistoryErrorV1::Unavailable(
                        "repository marker"
                            | "current repository capture"
                            | "canonical repository identity"
                    )
                ) =>
            {
                tracing::debug!(
                    provider = provider.provider_id.as_str(),
                    error = %error,
                    "provider delivery has partial repository identity evidence"
                );
                None
            }
            Err(error) => {
                fail_partial_provider_mount!(format!("provider identity mount refused: {error}"));
            }
        };
        // Canonical observations retain ingestion-time repository captures,
        // which do not prove original live-event scope. Same-session delivery
        // and recall remain available; cross-session history has no authority.
        let original_authority = None;
        let journey_mount = Arc::new(ProjectObservationJourneyMountV1 {
            inner: Arc::clone(&journey),
        });
        journeys.push(Arc::clone(&journey_mount));
        let authority = Arc::new(provider_history::ProviderHistoryAuthorityV1 {
            mounted_scope: inputs.scope.clone(),
            profile_id: inputs.profile_id.clone(),
            registered_shard: inputs.session_db.binding().shard_id.clone(),
            session_db: inputs.session_db.clone(),
            mounted_reader: Arc::clone(&hook_origin_reader),
            mounted_bridge,
            observations: Arc::new(inputs.session_db.observation_store()),
            dispositions: Arc::new(inputs.graph.db().clone()),
            original_authority,
            journal: journey.history_journal(),
            provider_id: provider.provider_id.clone(),
            policy_revision: 1,
            runtime: tokio::runtime::Handle::current(),
        });
        if let Err(error) = authority.validate_mount() {
            fail_partial_provider_mount!(format!("provider history mount refused: {error}"));
        }
        if let Err(error) = history_mount.bind(authority.clone()) {
            fail_partial_provider_mount!(format!("provider history binding refused: {error}"));
        }
        if let Err(error) = journey.bind_history_authority(authority.clone()) {
            fail_partial_provider_mount!(format!(
                "provider journey history binding refused: {error}"
            ));
        }
        if let Some(recall) = host
            .cognitive_recall_mount
            .as_ref()
            .filter(|recall| recall.inner.routing().active_provider() == &provider.provider_id)
            && let Err(error) = recall
                .inner
                .bind_selected_history(authority, Arc::clone(&journey))
        {
            fail_partial_provider_mount!(format!(
                "provider recall history binding refused: {error}"
            ));
        }
        if configured.activation
            == tracedecay_memory_provider_registry::ObservationMountActivationV1::BeforePublication
        {
            if let Err(error) =
                observation_journey::activate_required_with_startup_replay_and_delivery_settled(
                    Arc::clone(&journey),
                    inputs.session_db.observation_store(),
                    cancellation,
                )
                .await
            {
                fail_partial_provider_mount!(format!(
                    "provider observation startup replay failed: {error}"
                ));
            }
        } else {
            deferred.push((Arc::clone(&journey), configured.requirement));
        }
        control_journals.push((provider.provider_id.clone(), journey.history_journal()));
        // Keep the wrapper in `journeys` from the moment the worker-capable
        // journey is mounted. Any later provider or control failure therefore
        // shuts down every earlier and current journey before returning.
        let _ = journey_mount;
    }

    let now = tracedecay_contracts::now_micros().0;
    let control = tracedecay_memory_provider_registry::OperationControl::new(
        now.saturating_add(1_000_000),
        1_000,
        tracedecay_memory_provider_registry::CancellationToken::new(),
    );
    let control_inputs = provider_control::authority::ProviderControlAuthorityInputsV1 {
        canonical_project_path: inputs.canonical_project_path.clone(),
        profile_id: inputs.profile_id.clone(),
        mounted_scope: inputs.scope.clone(),
        session_db: inputs.session_db.clone(),
        dispositions: Arc::new(inputs.graph.db().clone()),
        hook_origin_reader,
        store_data_root: inputs.graph.store_layout().data_root.clone(),
        live_ledger: host
            .cognitive_recall_mount
            .as_ref()
            .map(|mount| mount.inner.control_ledger()),
        locator_key: host.locator_key.clone(),
        live_journals: control_journals,
        runtime: tokio::runtime::Handle::current(),
    };
    let blocking_control = control.clone();
    let mut work = tokio::task::spawn_blocking(move || {
        provider_control::authority::ProviderControlAuthorityV1::from_mounted_data(
            control_inputs,
            &blocking_control,
        )
    });
    let joined = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            control.cancellation().cancel();
            let _ = work.await;
            fail_partial_provider_mount!(
                "project open was cancelled during provider control mount".to_owned()
            );
        }
        joined = &mut work => joined,
    };
    let authority = if control.snapshot().is_err() {
        tracing::debug!(
            cause = "admission_budget",
            "provider source controls unavailable"
        );
        None
    } else {
        match joined {
            Ok(Ok(authority)) => Some(Arc::new(authority)),
            Ok(Err(error)) => {
                tracing::debug!(cause = "retained_authority", error = %error, "provider source controls unavailable");
                None
            }
            Err(error) => {
                tracing::debug!(cause = "mount_task", error = %error, "provider source controls unavailable");
                None
            }
        }
    };
    let provider_control_mount = provider_control::project_provider_control_port(
        provider_control::ProviderControlMountInputsV1 {
            authority,
            journeys: journeys
                .iter()
                .map(|journey| Arc::clone(&journey.inner))
                .collect(),
            profile_id: inputs.profile_id,
            mounted_scope: inputs.scope,
            authoritative_project_id: inputs.authoritative_project_id,
            configuration_digest: inputs.configuration_digest,
        },
    );
    Ok(Arc::new(ProjectMemoryProviderFullMountV1 {
        observation_journeys: journeys,
        deferred_observation_journeys: std::sync::Mutex::new(deferred),
        provider_control_mount,
    }))
}

async fn shutdown_partial_provider_journeys(journeys: &[Arc<ProjectObservationJourneyMountV1>]) {
    let deadline = tokio::time::Instant::now() + crate::shutdown::DAEMON_TASK_ABORT_DEADLINE;
    for journey in journeys {
        for failure in journey.shutdown(deadline).await {
            tracing::warn!(
                failure = %failure,
                "partial project provider mount did not stop its observation journey cleanly"
            );
        }
    }
}

fn new_recall_locator_key()
-> std::result::Result<cognitive_recall::control_attribution::RecallLocatorKeyV1, String> {
    let mut bytes = vec![0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        format!("OS entropy unavailable for the project recall locator key: {error}")
    })?;
    cognitive_recall::control_attribution::RecallLocatorKeyV1::from_material(bytes)
        .map_err(|error| format!("project recall locator key was rejected: {error}"))
}

fn project_recall_degradation_rule(
    routing: &tracedecay_domain::configuration::MemoryProviderRecallRoutingV1,
) -> std::result::Result<tracedecay_memory_provider_registry::DegradationRule, String> {
    use tracedecay_memory_provider_registry::{
        DegradationCause, DegradationRule, PinnedDegradationPolicy,
    };
    let Some(configured) = &routing.degradation else {
        return Ok(DegradationRule::DefaultContentFree);
    };
    let policy = PinnedDegradationPolicy::new(
        configured.policy_id.clone(),
        configured.policy_revision,
        configured
            .allowed_causes
            .iter()
            .copied()
            .map(|cause| match cause {
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::Unsupported => DegradationCause::Unsupported,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::Unavailable => DegradationCause::Unavailable,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::Cancelled => DegradationCause::Cancelled,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::TimedOut => DegradationCause::TimedOut,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::Partial => DegradationCause::Partial,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::Stale => DegradationCause::Stale,
                tracedecay_domain::configuration::MemoryProviderRecallDegradationCauseV1::BudgetExhausted => DegradationCause::BudgetExhausted,
            }),
    )
    .map_err(|error| format!("memory provider recall degradation policy is invalid: {error}"))?;
    Ok(DegradationRule::ExplicitPinned(policy))
}

fn project_recall_routing_policy(
    selected: Option<(&tracedecay_memory_provider_registry::OwnedProviderId, u64)>,
    routing: &tracedecay_domain::configuration::MemoryProviderRecallRoutingV1,
) -> std::result::Result<tracedecay_memory_provider_registry::ActiveRoutingPolicy, String> {
    use tracedecay_memory_provider_registry::{ActiveRoutingPolicy, FallbackRule};
    let Some((provider_id, registration_revision)) = selected else {
        return Err("active recall route has no selected provider".to_owned());
    };
    let fallback = match &routing.fallback {
        None => FallbackRule::Forbidden,
        Some(rule) => {
            return Err(format!(
                "memory provider recall routing pins fallback policy '{}'@{} to target provider '{}', but this project composition registers only the selected provider; remove fallback",
                rule.policy_id, rule.policy_revision, rule.target_provider
            ));
        }
    };
    ActiveRoutingPolicy::new_with_degradation(
        provider_id.clone(),
        registration_revision,
        fallback,
        project_recall_degradation_rule(routing)?,
    )
    .map_err(|error| format!("memory provider recall routing policy is invalid: {error}"))
}
