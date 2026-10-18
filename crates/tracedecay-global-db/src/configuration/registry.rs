//! Typed configuration registry for the final control plane.

use std::collections::BTreeMap;

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tracedecay_domain::configuration::{
    ACCESS_RULES_SETTING_KEY, ANALYZER_SETTINGS_SETTING_KEY, AUTOMATION_SETTINGS_SETTING_KEY,
    AnalyzerSettingsV1, CONFIGURATION_SETTING_KEYS_V1, CONTEXT_SCOUT_SETTINGS_SETTING_KEY,
    CodeIndexWorkerSelectionV1, ConfigurationValueKindV1, ConfigurationValueV1,
    ContextScoutSettingsV1, DeprecationStateV1, INDEX_EXCLUDE_SETTING_KEY,
    INDEX_EXTRACT_DOCSTRINGS_SETTING_KEY, INDEX_INCLUDE_SETTING_KEY,
    INDEX_MAX_FILE_SIZE_SETTING_KEY, INDEX_NATIVE_GRAPH_ACTIVATION_SETTING_KEY,
    INDEX_TRACK_CALL_SITES_SETTING_KEY, LCM_SUMMARIZER_EXECUTABLES_SETTING_KEY,
    LcmSummarizerExecutableV1, LcmSummarizerExecutablesV1,
    MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY, MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
    MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY, MemoryProviderKindV1, MemoryProviderNcmObserverV1,
    MemoryProviderRecallRoutingV1, MemoryProviderSelectionErrorV1, MemoryProviderSelectionV1,
    PROFILE_SETTING_KEYS_V1, PROJECT_WORK_EXPERTISE_CONSENT_SETTING_KEY, RestartRequirementV1,
    SOURCE_BINDINGS_SETTING_KEY, SYNC_AUTO_INIT_SETTING_KEY,
    SYNC_AUTO_TRACK_PR_BRANCHES_SETTING_KEY, SYNC_AUTO_TRACK_PR_POLL_SECS_SETTING_KEY,
    SYNC_AUTO_WATCH_SETTING_KEY, SYNC_BACKSTOP_INTERVAL_MINS_SETTING_KEY,
    SYNC_BRANCH_GC_DAYS_SETTING_KEY, SYNC_FULL_SYNC_ESCALATION_FILES_SETTING_KEY,
    SYNC_MAX_CONCURRENT_SYNCS_SETTING_KEY, SYNC_READ_COOLDOWN_SECS_SETTING_KEY,
    SYNC_READ_REFRESH_SETTING_KEY, SYNC_SESSION_START_STALE_THRESHOLD_SECS_SETTING_KEY,
    SYNC_SESSION_START_SYNC_SETTING_KEY, SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY,
    SYNC_WATCH_LINKED_WORKTREES_SETTING_KEY, SYNC_WATCH_MAX_DELAY_MS_SETTING_KEY,
    SYNC_WATCH_MAX_PROJECTS_SETTING_KEY, SettingDefinitionV1, SettingKey, SettingScopeV1,
    SettingSensitivityV1, TELEMETRY_TIMINGS_SETTING_KEY, USER_CODE_INDEX_WORKERS_SETTING_KEY,
    USER_EXTRACTION_TIMEOUT_SECS_SETTING_KEY, USER_LCM_CODEX_SUMMARIZER_SETTING_KEY,
    USER_REPEATED_QUERY_HINTS_SETTING_KEY, USER_UPLOAD_ENABLED_SETTING_KEY,
    USER_WATCHER_DEBOUNCE_MS_SETTING_KEY, USER_WORK_EXPERTISE_CONSENT_SETTING_KEY,
    WORK_EXECUTABLE_BINDINGS_SETTING_KEY, WORK_TOPOLOGY_POLICY_SETTING_KEY, WorkExpertiseConsentV1,
    safe_work_topology_policy_v1,
};
use tracedecay_domain::feedback::PROXIMITY_RISK_THRESHOLD_SETTING_KEY_V1;
use tracedecay_domain::{DomainError, canonical_json_bytes, validate_index_path_patterns};

/// Canonical default for configured-tier proximity warnings.
pub const DEFAULT_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1: u64 = 7_000;
pub const MAX_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1: u64 = 10_000;

/// Registry schema revision. Increment only when setting-definition semantics
/// change, not when a setting value changes.
pub const CONFIGURATION_REGISTRY_SCHEMA_REVISION: u16 = 8;

#[derive(Debug, Error)]
pub enum ConfigurationRegistryError {
    #[error("configuration definition is invalid: {0}")]
    InvalidDefinition(#[from] DomainError),
    #[error("setting key already registered: {0}")]
    DuplicateSetting(SettingKey),
    #[error("setting key is not registered: {0}")]
    UnknownSetting(SettingKey),
    #[error("setting value kind does not match {key}: expected {expected:?}, got {actual:?}")]
    ValueKindMismatch {
        key: SettingKey,
        expected: ConfigurationValueKindV1,
        actual: ConfigurationValueKindV1,
    },
    #[error("setting {key} value {actual} is outside [{minimum}, {maximum}]")]
    UnsignedValueOutOfRange {
        key: SettingKey,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    #[error("setting {key} pattern '{pattern}' is invalid: {message}")]
    InvalidPathPattern {
        key: SettingKey,
        pattern: String,
        message: String,
    },
    #[error("setting {key} cannot be written in layer {layer:?}")]
    InvalidLayer {
        key: SettingKey,
        layer: tracedecay_domain::configuration::ConfigurationLayerIdV1,
    },
    #[error("setting {key} contains invalid {document} JSON: {message}")]
    InvalidStructuredValue {
        key: SettingKey,
        document: &'static str,
        message: String,
    },
    #[error("provider configuration is not composable: {0}")]
    ProviderSelection(#[source] MemoryProviderSelectionErrorV1),
    #[error("configuration snapshot is missing registered setting value: {0}")]
    MissingSettingValue(SettingKey),
}

/// Immutable mapping of every supported setting to its typed definition.
#[derive(Clone, Debug)]
pub struct ConfigurationRegistry {
    definitions: BTreeMap<SettingKey, SettingDefinitionV1>,
}

impl ConfigurationRegistry {
    /// Build the core registry. In addition to authority, policy,
    /// collection, analyzer, and topology definitions, this includes every
    /// project-scoped runtime scalar.
    pub fn core() -> Result<Self, ConfigurationRegistryError> {
        let mut registry = Self {
            definitions: BTreeMap::new(),
        };
        registry.register(SettingDefinitionV1 {
            key: setting_key(SOURCE_BINDINGS_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::SourceBindings,
            default_value: ConfigurationValueV1::SourceBindings(Vec::new()),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(ACCESS_RULES_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::AccessRules,
            default_value: ConfigurationValueV1::AccessRules(Vec::new()),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        register_project_stored_user_profile_settings(&mut registry)?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(ANALYZER_SETTINGS_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::AnalyzerSettings,
            default_value: ConfigurationValueV1::AnalyzerSettings(AnalyzerSettingsV1::empty()),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::AnalyzerRestart,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(WORK_TOPOLOGY_POLICY_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::WorkTopologyPolicy,
            default_value: ConfigurationValueV1::WorkTopologyPolicy(Box::new(
                safe_work_topology_policy_v1(),
            )),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::DaemonRestart,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(WORK_EXECUTABLE_BINDINGS_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::WorkExecutableBindings,
            default_value: ConfigurationValueV1::WorkExecutableBindings(Vec::new()),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::DaemonRestart,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(PROJECT_WORK_EXPERTISE_CONSENT_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::WorkExpertiseConsent,
            default_value: ConfigurationValueV1::WorkExpertiseConsent(
                WorkExpertiseConsentV1::disabled(),
            ),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(CONTEXT_SCOUT_SETTINGS_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::ContextScoutSettings,
            default_value: ConfigurationValueV1::ContextScoutSettings(
                ContextScoutSettingsV1::disabled(),
            ),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(AUTOMATION_SETTINGS_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::AutomationSettings,
            default_value: ConfigurationValueV1::AutomationSettings(Box::default()),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        // On-demand LCM summarization launches a host CLI only through this
        // explicit binding; the unconfigured default keeps compaction pending
        // rather than resolving a binary from the daemon's environment.
        registry.register(SettingDefinitionV1 {
            key: setting_key(LCM_SUMMARIZER_EXECUTABLES_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::LcmSummarizerExecutables,
            default_value: ConfigurationValueV1::LcmSummarizerExecutables(
                LcmSummarizerExecutablesV1::unconfigured(),
            ),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(PROXIMITY_RISK_THRESHOLD_SETTING_KEY_V1)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::Unsigned,
            default_value: ConfigurationValueV1::Unsigned(
                DEFAULT_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1,
            ),
            sensitivity: SettingSensitivityV1::Public,
            scope: SettingScopeV1::Project,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        register_project_settings(&mut registry)?;
        let expected = CONFIGURATION_SETTING_KEYS_V1
            .iter()
            .filter(|key| !PROFILE_SETTING_KEYS_V1.contains(key))
            .map(|key| setting_key(key))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let actual = registry
            .definitions
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if actual != expected {
            return Err(ConfigurationRegistryError::InvalidDefinition(
                DomainError::NonCanonical {
                    field: "configuration registry key inventory",
                },
            ));
        }
        Ok(registry)
    }

    /// Build the exact profile-session registry of every setting in
    /// [`PROFILE_SETTING_KEYS_V1`]. These settings resolve before and without
    /// any project, so they cannot share a project snapshot authority.
    pub fn profile() -> Result<Self, ConfigurationRegistryError> {
        let mut registry = Self {
            definitions: BTreeMap::new(),
        };
        registry.register(code_index_worker_definition()?)?;
        registry.register(SettingDefinitionV1 {
            key: setting_key(USER_LCM_CODEX_SUMMARIZER_SETTING_KEY)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: ConfigurationValueKindV1::LcmSummarizerExecutable,
            default_value: ConfigurationValueV1::LcmSummarizerExecutable(
                LcmSummarizerExecutableV1::Unconfigured,
            ),
            sensitivity: SettingSensitivityV1::Sensitive,
            scope: SettingScopeV1::UserProfile,
            restart_requirement: RestartRequirementV1::None,
            deprecation: DeprecationStateV1::Active,
        })?;
        register_profile_scalar_settings(&mut registry)?;
        Ok(registry)
    }

    /// A registry of exactly `definitions`, for fixtures that reproduce a
    /// store an earlier registry wrote.
    #[cfg(test)]
    pub(crate) fn from_definitions(
        definitions: impl IntoIterator<Item = SettingDefinitionV1>,
    ) -> Result<Self, ConfigurationRegistryError> {
        let mut registry = Self {
            definitions: BTreeMap::new(),
        };
        for definition in definitions {
            registry.register(definition)?;
        }
        Ok(registry)
    }

    pub fn register(
        &mut self,
        definition: SettingDefinitionV1,
    ) -> Result<(), ConfigurationRegistryError> {
        definition.validate()?;
        if self.definitions.contains_key(&definition.key) {
            return Err(ConfigurationRegistryError::DuplicateSetting(definition.key));
        }
        self.definitions.insert(definition.key.clone(), definition);
        Ok(())
    }

    pub fn definition(
        &self,
        key: &SettingKey,
    ) -> Result<&SettingDefinitionV1, ConfigurationRegistryError> {
        self.definitions
            .get(key)
            .ok_or_else(|| ConfigurationRegistryError::UnknownSetting(key.clone()))
    }

    pub fn definitions(&self) -> impl Iterator<Item = &SettingDefinitionV1> {
        self.definitions.values()
    }

    /// Whether this registry owns the project-level provider settings.
    ///
    /// The daemon also uses this type for the smaller profile-session
    /// registry, whose snapshots contain only profile settings. Provider
    /// composition is only meaningful for the core registry.
    pub fn has_provider_configuration(&self) -> bool {
        self.definitions
            .keys()
            .any(|key| key.as_str() == MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY)
    }

    pub fn validate_value(
        &self,
        key: &SettingKey,
        value: &ConfigurationValueV1,
    ) -> Result<(), ConfigurationRegistryError> {
        let definition = self.definition(key)?;
        let actual = value.kind();
        if actual != definition.value_kind {
            return Err(ConfigurationRegistryError::ValueKindMismatch {
                key: key.clone(),
                expected: definition.value_kind,
                actual,
            });
        }
        value.validate()?;
        if key.as_str() == PROXIMITY_RISK_THRESHOLD_SETTING_KEY_V1 {
            let ConfigurationValueV1::Unsigned(actual) = value else {
                return Err(ConfigurationRegistryError::ValueKindMismatch {
                    key: key.clone(),
                    expected: ConfigurationValueKindV1::Unsigned,
                    actual: value.kind(),
                });
            };
            if *actual > MAX_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1 {
                return Err(ConfigurationRegistryError::UnsignedValueOutOfRange {
                    key: key.clone(),
                    minimum: 0,
                    maximum: MAX_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1,
                    actual: *actual,
                });
            }
        }
        if matches!(
            key.as_str(),
            USER_WATCHER_DEBOUNCE_MS_SETTING_KEY | USER_EXTRACTION_TIMEOUT_SECS_SETTING_KEY
        ) {
            let ConfigurationValueV1::Unsigned(actual) = value else {
                return Err(ConfigurationRegistryError::ValueKindMismatch {
                    key: key.clone(),
                    expected: ConfigurationValueKindV1::Unsigned,
                    actual: value.kind(),
                });
            };
            if *actual == 0 {
                return Err(ConfigurationRegistryError::UnsignedValueOutOfRange {
                    key: key.clone(),
                    minimum: 1,
                    maximum: u64::MAX,
                    actual: *actual,
                });
            }
        }
        match key.as_str() {
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY => {
                let document: MemoryProviderNcmObserverV1 =
                    decode_structured_value(key, value, "NCM observer configuration")?;
                document.validate().map_err(|error| {
                    invalid_structured_value(key, "NCM observer configuration", error)
                })?;
            }
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY => {
                let document: MemoryProviderRecallRoutingV1 =
                    decode_structured_value(key, value, "recall routing configuration")?;
                document.validate().map_err(|error| {
                    invalid_structured_value(key, "recall routing configuration", error)
                })?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Resolve the provider participation represented by one complete project
    /// snapshot. The three provider settings are stored independently for
    /// compatibility, but they form one admission unit: an active or fallback
    /// provider may only be selected when this composition can construct it.
    pub fn resolve_provider_selection(
        &self,
        values: &BTreeMap<SettingKey, ConfigurationValueV1>,
    ) -> Result<MemoryProviderSelectionV1, ConfigurationRegistryError> {
        let native_key = setting_key(MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY)?;
        let ncm_key = setting_key(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY)?;
        let routing_key = setting_key(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY)?;

        let native_value = values
            .get(&native_key)
            .ok_or_else(|| ConfigurationRegistryError::MissingSettingValue(native_key.clone()))?;
        self.validate_value(&native_key, native_value)?;
        let native_enabled = match native_value {
            ConfigurationValueV1::Boolean(value) => *value,
            value => {
                return Err(ConfigurationRegistryError::ValueKindMismatch {
                    key: native_key,
                    expected: ConfigurationValueKindV1::Boolean,
                    actual: value.kind(),
                });
            }
        };

        let ncm_value = values
            .get(&ncm_key)
            .ok_or_else(|| ConfigurationRegistryError::MissingSettingValue(ncm_key.clone()))?;
        self.validate_value(&ncm_key, ncm_value)?;
        let ncm: MemoryProviderNcmObserverV1 =
            decode_structured_value(&ncm_key, ncm_value, "NCM observer configuration")?;

        let routing_value = values
            .get(&routing_key)
            .ok_or_else(|| ConfigurationRegistryError::MissingSettingValue(routing_key.clone()))?;
        self.validate_value(&routing_key, routing_value)?;
        let routing: MemoryProviderRecallRoutingV1 =
            decode_structured_value(&routing_key, routing_value, "recall routing configuration")?;

        MemoryProviderSelectionV1::resolve(native_enabled, &ncm, &routing)
            .map_err(ConfigurationRegistryError::ProviderSelection)
    }

    /// Validate the provider settings without returning a composition plan.
    pub fn validate_provider_configuration(
        &self,
        values: &BTreeMap<SettingKey, ConfigurationValueV1>,
    ) -> Result<(), ConfigurationRegistryError> {
        if !self.has_provider_configuration() {
            return Ok(());
        }
        self.resolve_provider_selection(values).map(|_| ())
    }

    /// [`Self::validate_value`] plus the checks that gate only a new write.
    ///
    /// Stored snapshots are revalidated with `validate_value` on every read,
    /// so a rule that may tighten across releases must not live there: an
    /// `index.exclude.v1` pattern an earlier release accepted has to keep
    /// loading (the runtime pin leaves it unapplied and reports it as a
    /// setting finding) while a new write of it is refused.
    pub fn validate_written_value(
        &self,
        key: &SettingKey,
        value: &ConfigurationValueV1,
    ) -> Result<(), ConfigurationRegistryError> {
        self.validate_value(key, value)?;
        if let ConfigurationValueV1::StringList(patterns) = value
            && matches!(
                key.as_str(),
                INDEX_EXCLUDE_SETTING_KEY | INDEX_INCLUDE_SETTING_KEY
            )
        {
            validate_index_path_patterns(patterns).map_err(|error| {
                ConfigurationRegistryError::InvalidPathPattern {
                    key: key.clone(),
                    pattern: error.pattern,
                    message: error.message,
                }
            })?;
        }
        Ok(())
    }

    pub fn validate_layer(
        &self,
        key: &SettingKey,
        layer: &tracedecay_domain::configuration::ConfigurationLayerIdV1,
    ) -> Result<(), ConfigurationRegistryError> {
        use tracedecay_domain::configuration::{ConfigurationLayerKindV1, SettingScopeV1};

        let definition = self.definition(key)?;
        let valid = matches!(
            (definition.scope, layer.kind()),
            (
                SettingScopeV1::UserProfile,
                ConfigurationLayerKindV1::UserProfile
            ) | (SettingScopeV1::Project, ConfigurationLayerKindV1::Project)
                | (
                    SettingScopeV1::Collection,
                    ConfigurationLayerKindV1::Collection
                )
        );
        if valid {
            Ok(())
        } else {
            Err(ConfigurationRegistryError::InvalidLayer {
                key: key.clone(),
                layer: layer.clone(),
            })
        }
    }
}

fn decode_structured_value<T: DeserializeOwned + Serialize>(
    key: &SettingKey,
    value: &ConfigurationValueV1,
    document: &'static str,
) -> Result<T, ConfigurationRegistryError> {
    let ConfigurationValueV1::Text(value) = value else {
        return Err(ConfigurationRegistryError::ValueKindMismatch {
            key: key.clone(),
            expected: ConfigurationValueKindV1::Text,
            actual: value.kind(),
        });
    };
    let decoded = serde_json::from_str::<T>(value)
        .map_err(|error| invalid_structured_value(key, document, error))?;
    // The text itself participates in the snapshot behavior digest. Requiring
    // the exact repository serializer output closes equivalent spellings that
    // would otherwise produce different persisted digests.
    let canonical = canonical_json_bytes(&decoded)
        .map_err(|error| invalid_structured_value(key, document, error))?;
    if value.as_bytes() != canonical.as_slice() {
        return Err(invalid_structured_value(
            key,
            document,
            "JSON text is not the repository canonical serialization",
        ));
    }
    Ok(decoded)
}

fn canonical_json_text<T: Serialize>(
    value: &T,
    error: impl Fn() -> ConfigurationRegistryError,
) -> Result<String, ConfigurationRegistryError> {
    let bytes = canonical_json_bytes(value).map_err(|_| error())?;
    String::from_utf8(bytes).map_err(|_| error())
}

fn invalid_structured_value(
    key: &SettingKey,
    document: &'static str,
    error: impl std::fmt::Display,
) -> ConfigurationRegistryError {
    ConfigurationRegistryError::InvalidStructuredValue {
        key: key.clone(),
        document,
        message: error.to_string(),
    }
}

/// Lower bound the daemon clamps PR-branch auto-tracking polling up to.
///
/// Mirrors root `config::MIN_AUTO_TRACK_PR_POLL_SECS`.
pub const MIN_AUTO_TRACK_PR_POLL_SECS: u64 = 60;

fn register_project_stored_user_profile_settings(
    registry: &mut ConfigurationRegistry,
) -> Result<(), ConfigurationRegistryError> {
    registry.register(SettingDefinitionV1 {
        key: setting_key(USER_WORK_EXPERTISE_CONSENT_SETTING_KEY)?,
        schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
        value_kind: ConfigurationValueKindV1::WorkExpertiseConsent,
        default_value: ConfigurationValueV1::WorkExpertiseConsent(
            WorkExpertiseConsentV1::disabled(),
        ),
        sensitivity: SettingSensitivityV1::Sensitive,
        scope: SettingScopeV1::UserProfile,
        restart_requirement: RestartRequirementV1::None,
        deprecation: DeprecationStateV1::Active,
    })
}

fn register_profile_scalar_settings(
    registry: &mut ConfigurationRegistry,
) -> Result<(), ConfigurationRegistryError> {
    for (key, default_value, restart_requirement) in [
        (
            USER_UPLOAD_ENABLED_SETTING_KEY,
            ConfigurationValueV1::Boolean(false),
            RestartRequirementV1::None,
        ),
        (
            USER_REPEATED_QUERY_HINTS_SETTING_KEY,
            ConfigurationValueV1::Boolean(false),
            RestartRequirementV1::None,
        ),
        (
            USER_WATCHER_DEBOUNCE_MS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(2_000),
            RestartRequirementV1::DaemonRestart,
        ),
        (
            USER_EXTRACTION_TIMEOUT_SECS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(60),
            RestartRequirementV1::DaemonRestart,
        ),
    ] {
        registry.register(SettingDefinitionV1 {
            key: setting_key(key)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: default_value.kind(),
            default_value,
            sensitivity: SettingSensitivityV1::Public,
            scope: SettingScopeV1::UserProfile,
            restart_requirement,
            deprecation: DeprecationStateV1::Active,
        })?;
    }
    Ok(())
}

fn code_index_worker_definition() -> Result<SettingDefinitionV1, ConfigurationRegistryError> {
    Ok(SettingDefinitionV1 {
        key: setting_key(USER_CODE_INDEX_WORKERS_SETTING_KEY)?,
        schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
        value_kind: ConfigurationValueKindV1::CodeIndexWorkerSelection,
        default_value: ConfigurationValueV1::CodeIndexWorkerSelection(
            CodeIndexWorkerSelectionV1::Automatic {},
        ),
        sensitivity: SettingSensitivityV1::Public,
        scope: SettingScopeV1::UserProfile,
        restart_requirement: RestartRequirementV1::DaemonRestart,
        deprecation: DeprecationStateV1::Active,
    })
}

/// Canonical defaults for the project-scoped runtime settings.
struct ProjectDefaults {
    exclude: Vec<String>,
    include: Vec<String>,
    max_file_size: u64,
    extract_docstrings: bool,
    track_call_sites: bool,
    native_graph_activation: bool,
    memory_provider_native_enabled: bool,
    telemetry_timings: bool,
    sync: SyncDefaults,
}

#[derive(Clone, Copy)]
struct SyncDefaults {
    auto_watch: bool,
    watch_linked_worktrees: bool,
    watch_debounce_ms: u64,
    watch_max_delay_ms: u64,
    watch_max_projects: usize,
    read_refresh: bool,
    read_cooldown_secs: u64,
    session_start_sync: bool,
    session_start_stale_threshold_secs: u64,
    backstop_interval_mins: u64,
    full_sync_escalation_files: usize,
    max_concurrent_syncs: usize,
    branch_gc_days: u64,
    auto_init: bool,
    auto_track_pr_branches: bool,
    auto_track_pr_poll_secs: u64,
}

impl Default for SyncDefaults {
    fn default() -> Self {
        Self {
            auto_watch: false,
            watch_linked_worktrees: false,
            watch_debounce_ms: 2000,
            watch_max_delay_ms: 30000,
            watch_max_projects: 32,
            read_refresh: true,
            read_cooldown_secs: 30,
            session_start_sync: true,
            session_start_stale_threshold_secs: 600,
            backstop_interval_mins: 15,
            full_sync_escalation_files: 500,
            max_concurrent_syncs: 2,
            branch_gc_days: 14,
            auto_init: true,
            auto_track_pr_branches: false,
            auto_track_pr_poll_secs: 300,
        }
    }
}

impl Default for ProjectDefaults {
    fn default() -> Self {
        let mut exclude: Vec<String> = vec![
            ".git/**".to_string(),
            ".tracedecay/**".to_string(),
            "**/*.min.*".to_string(),
        ];
        for segment in tracedecay_runtime_core::config::GENERATED_DIR_SEGMENTS {
            exclude.push(format!("{segment}/**"));
            exclude.push(format!("**/{segment}/**"));
        }
        Self {
            exclude,
            include: Vec::new(),
            max_file_size: 1_048_576,
            extract_docstrings: true,
            track_call_sites: true,
            native_graph_activation: true,
            memory_provider_native_enabled: true,
            telemetry_timings: true,
            sync: SyncDefaults::default(),
        }
    }
}

/// Register every project scalar in the sole typed registry.
fn register_project_settings(
    registry: &mut ConfigurationRegistry,
) -> Result<(), ConfigurationRegistryError> {
    let defaults = ProjectDefaults::default();
    let sync = defaults.sync;
    let recall_routing_default = MemoryProviderRecallRoutingV1 {
        active_provider: Some(MemoryProviderKindV1::Native.provider_id().to_owned()),
        ..Default::default()
    };
    recall_routing_default
        .validate()
        .map_err(ConfigurationRegistryError::InvalidDefinition)?;
    let recall_routing_default = canonical_json_text(&recall_routing_default, || {
        ConfigurationRegistryError::InvalidDefinition(DomainError::NonCanonical {
            field: "memory provider recall routing default encoding",
        })
    })?;
    let ncm_observer_default =
        canonical_json_text(&MemoryProviderNcmObserverV1::default(), || {
            ConfigurationRegistryError::InvalidDefinition(DomainError::NonCanonical {
                field: "NCM observer default encoding",
            })
        })?;
    let settings = vec![
        (
            INDEX_EXCLUDE_SETTING_KEY,
            ConfigurationValueV1::StringList(defaults.exclude),
            SettingSensitivityV1::Sensitive,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            INDEX_INCLUDE_SETTING_KEY,
            ConfigurationValueV1::StringList(defaults.include),
            SettingSensitivityV1::Sensitive,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            INDEX_MAX_FILE_SIZE_SETTING_KEY,
            ConfigurationValueV1::Unsigned(defaults.max_file_size),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            INDEX_EXTRACT_DOCSTRINGS_SETTING_KEY,
            ConfigurationValueV1::Boolean(defaults.extract_docstrings),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            INDEX_TRACK_CALL_SITES_SETTING_KEY,
            ConfigurationValueV1::Boolean(defaults.track_call_sites),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            INDEX_NATIVE_GRAPH_ACTIVATION_SETTING_KEY,
            ConfigurationValueV1::Boolean(defaults.native_graph_activation),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            ConfigurationValueV1::Boolean(defaults.memory_provider_native_enabled),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            ConfigurationValueV1::Text(ncm_observer_default),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
            ConfigurationValueV1::Text(recall_routing_default),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_AUTO_WATCH_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.auto_watch),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_WATCH_LINKED_WORKTREES_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.watch_linked_worktrees),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.watch_debounce_ms),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_WATCH_MAX_DELAY_MS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.watch_max_delay_ms),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_WATCH_MAX_PROJECTS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.watch_max_projects as u64),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_READ_REFRESH_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.read_refresh),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_READ_COOLDOWN_SECS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.read_cooldown_secs),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_SESSION_START_SYNC_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.session_start_sync),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_SESSION_START_STALE_THRESHOLD_SECS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.session_start_stale_threshold_secs),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_BACKSTOP_INTERVAL_MINS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.backstop_interval_mins),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_FULL_SYNC_ESCALATION_FILES_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.full_sync_escalation_files as u64),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_MAX_CONCURRENT_SYNCS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.max_concurrent_syncs as u64),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_BRANCH_GC_DAYS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(sync.branch_gc_days),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_AUTO_INIT_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.auto_init),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_AUTO_TRACK_PR_BRANCHES_SETTING_KEY,
            ConfigurationValueV1::Boolean(sync.auto_track_pr_branches),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            SYNC_AUTO_TRACK_PR_POLL_SECS_SETTING_KEY,
            ConfigurationValueV1::Unsigned(
                sync.auto_track_pr_poll_secs
                    .max(MIN_AUTO_TRACK_PR_POLL_SECS),
            ),
            SettingSensitivityV1::Public,
            RestartRequirementV1::DaemonRestart,
        ),
        (
            TELEMETRY_TIMINGS_SETTING_KEY,
            ConfigurationValueV1::Boolean(defaults.telemetry_timings),
            SettingSensitivityV1::Public,
            RestartRequirementV1::None,
        ),
    ];

    for (key, default_value, sensitivity, restart_requirement) in settings {
        registry.register(SettingDefinitionV1 {
            key: setting_key(key)?,
            schema_revision: CONFIGURATION_REGISTRY_SCHEMA_REVISION,
            value_kind: default_value.kind(),
            default_value,
            sensitivity,
            scope: SettingScopeV1::Project,
            restart_requirement,
            deprecation: DeprecationStateV1::Active,
        })?;
    }
    Ok(())
}

fn setting_key(value: &str) -> Result<SettingKey, ConfigurationRegistryError> {
    Ok(SettingKey::new(value)?)
}

#[cfg(test)]
mod proximity_threshold_tests {
    use super::*;

    #[test]
    fn proximity_threshold_has_one_bounded_project_default() {
        let registry = ConfigurationRegistry::core().expect("registry");
        let key = SettingKey::new(PROXIMITY_RISK_THRESHOLD_SETTING_KEY_V1).expect("key");
        let definition = registry.definition(&key).expect("definition");

        assert_eq!(definition.value_kind, ConfigurationValueKindV1::Unsigned);
        assert_eq!(
            definition.default_value,
            ConfigurationValueV1::Unsigned(DEFAULT_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1)
        );
        assert_eq!(definition.scope, SettingScopeV1::Project);
        assert_eq!(definition.sensitivity, SettingSensitivityV1::Public);
        assert_eq!(definition.restart_requirement, RestartRequirementV1::None);
        assert!(
            registry
                .validate_value(&key, &ConfigurationValueV1::Unsigned(0))
                .is_ok()
        );
        assert!(
            registry
                .validate_value(
                    &key,
                    &ConfigurationValueV1::Unsigned(MAX_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1),
                )
                .is_ok()
        );
        assert!(matches!(
            registry.validate_value(
                &key,
                &ConfigurationValueV1::Unsigned(MAX_PROXIMITY_RISK_THRESHOLD_BASIS_POINTS_V1 + 1),
            ),
            Err(ConfigurationRegistryError::UnsignedValueOutOfRange { .. })
        ));
    }
}

#[cfg(test)]
mod index_path_pattern_tests {
    use super::*;

    /// A stored pattern an earlier release never compiled must keep loading
    /// while a new write of it is refused.
    #[test]
    fn a_malformed_index_pattern_loads_but_cannot_be_written() {
        let registry = ConfigurationRegistry::core().expect("registry");
        let key = SettingKey::new(INDEX_EXCLUDE_SETTING_KEY).expect("key");
        let value = ConfigurationValueV1::StringList(vec!["src/[abc".to_owned()]);

        assert!(registry.validate_value(&key, &value).is_ok());
        assert!(matches!(
            registry.validate_written_value(&key, &value),
            Err(ConfigurationRegistryError::InvalidPathPattern { .. })
        ));
    }
}

#[cfg(test)]
mod released_setting_keys_tests {
    use super::*;
    use tracedecay_domain::configuration::RETIRED_CORE_SETTING_KEYS_V1;

    /// Every setting key a published release persisted, as literals so that
    /// removing a key constant cannot silently shrink this history. Append a
    /// key here when it first ships; never delete one.
    const RELEASED_SETTING_KEYS: &[&str] = &[
        "analyzer.settings.v1",
        "automation.settings.v1",
        "context_scout.settings.v1",
        "diagnostics.prewarm.v1",
        "feedback.proximity.risk_threshold",
        "index.exclude.v1",
        "index.extract_docstrings.v1",
        "index.git_ignore.v1",
        "index.include.v1",
        "index.max_file_size.v1",
        "index.native_graph_activation.v1",
        "index.track_call_sites.v1",
        "lcm.summarizer_executables.v1",
        "scope.access_rules.v1",
        "scope.source_bindings.v1",
        "semantic.runtime.v1",
        "sync.auto_init.v1",
        "sync.auto_track_pr_branches.v1",
        "sync.auto_track_pr_poll_secs.v1",
        "sync.auto_watch.v1",
        "sync.backstop_interval_mins.v1",
        "sync.branch_gc_days.v1",
        "sync.full_sync_escalation_files.v1",
        "sync.max_concurrent_syncs.v1",
        "sync.orphan_db_gc_days.v1",
        "sync.read_cooldown_secs.v1",
        "sync.read_refresh.v1",
        "sync.session_start_stale_threshold_secs.v1",
        "sync.session_start_sync.v1",
        "sync.watch_debounce_ms.v1",
        "sync.watch_linked_worktrees.v1",
        "sync.watch_max_delay_ms.v1",
        "sync.watch_max_projects.v1",
        "telemetry.timings.v1",
        "user.code_index_workers.v1",
        "user.extraction_timeout_secs.v1",
        "user.upload_enabled.v1",
        "user.watcher_debounce_ms.v1",
        "user.work_expertise_consent.v1",
        "work.executable_bindings.v1",
        "work.expertise_consent.v1",
        "work.topology_policy.v1",
    ];

    /// A released key that is neither registered nor retired would turn every
    /// persisted snapshot carrying it into a configuration reset on open. A
    /// key the profile store took over is retired from project snapshots.
    #[test]
    fn every_released_setting_key_is_registered_or_retired() {
        let core = ConfigurationRegistry::core().expect("core registry");
        let profile = ConfigurationRegistry::profile().expect("profile registry");
        for raw_key in RELEASED_SETTING_KEYS {
            let key = SettingKey::new(*raw_key).expect("key");
            let in_core = core.definition(&key).is_ok();
            let in_profile = profile.definition(&key).is_ok();
            let retired = RETIRED_CORE_SETTING_KEYS_V1.contains(raw_key);
            assert!(
                !(in_core && (in_profile || retired)) && (in_core || in_profile || retired),
                "released setting {raw_key} must be exactly one of core-registered or retired \
                 from core (core: {in_core}, profile: {in_profile}, retired: {retired})"
            );
        }
        for raw_key in RETIRED_CORE_SETTING_KEYS_V1 {
            assert!(
                RELEASED_SETTING_KEYS.contains(raw_key),
                "retired setting {raw_key} must record a released key"
            );
        }
    }
}

#[cfg(test)]
mod user_profile_settings_tests {
    use super::*;

    #[test]
    fn editable_profile_settings_are_registered_with_exact_scope_and_restart_semantics() {
        let registry = ConfigurationRegistry::profile().expect("registry");
        for (raw_key, kind, restart) in [
            (
                USER_UPLOAD_ENABLED_SETTING_KEY,
                ConfigurationValueKindV1::Boolean,
                RestartRequirementV1::None,
            ),
            (
                USER_REPEATED_QUERY_HINTS_SETTING_KEY,
                ConfigurationValueKindV1::Boolean,
                RestartRequirementV1::None,
            ),
            (
                USER_WATCHER_DEBOUNCE_MS_SETTING_KEY,
                ConfigurationValueKindV1::Unsigned,
                RestartRequirementV1::DaemonRestart,
            ),
            (
                USER_EXTRACTION_TIMEOUT_SECS_SETTING_KEY,
                ConfigurationValueKindV1::Unsigned,
                RestartRequirementV1::DaemonRestart,
            ),
        ] {
            let definition = registry
                .definition(&SettingKey::new(raw_key).expect("key"))
                .expect("definition");
            assert_eq!(definition.scope, SettingScopeV1::UserProfile);
            assert_eq!(definition.value_kind, kind);
            assert_eq!(definition.sensitivity, SettingSensitivityV1::Public);
            assert_eq!(definition.restart_requirement, restart);
        }
        assert!(matches!(
            registry.validate_value(
                &SettingKey::new(USER_EXTRACTION_TIMEOUT_SECS_SETTING_KEY).unwrap(),
                &ConfigurationValueV1::Unsigned(0),
            ),
            Err(ConfigurationRegistryError::UnsignedValueOutOfRange { minimum: 1, .. })
        ));
    }

    #[test]
    fn code_index_workers_default_is_automatic_and_zero_exact_is_denied() {
        let key = SettingKey::new(USER_CODE_INDEX_WORKERS_SETTING_KEY).expect("key");
        let project_registry = ConfigurationRegistry::core().expect("project registry");
        assert!(matches!(
            project_registry.definition(&key),
            Err(ConfigurationRegistryError::UnknownSetting(_))
        ));

        let registry = ConfigurationRegistry::profile().expect("profile registry");
        assert_eq!(
            registry
                .definitions()
                .map(|definition| definition.key.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            PROFILE_SETTING_KEYS_V1.iter().copied().collect(),
            "the profile route must send exactly the keys the profile store registers"
        );
        let definition = registry.definition(&key).expect("definition");

        assert_eq!(
            definition.schema_revision,
            CONFIGURATION_REGISTRY_SCHEMA_REVISION
        );
        assert_eq!(definition.scope, SettingScopeV1::UserProfile);
        assert_eq!(
            definition.value_kind,
            ConfigurationValueKindV1::CodeIndexWorkerSelection
        );
        assert_eq!(
            definition.default_value,
            ConfigurationValueV1::CodeIndexWorkerSelection(
                CodeIndexWorkerSelectionV1::Automatic {}
            )
        );
        assert_eq!(
            definition.restart_requirement,
            RestartRequirementV1::DaemonRestart
        );
        assert!(matches!(
            registry.validate_value(
                &key,
                &ConfigurationValueV1::CodeIndexWorkerSelection(
                    CodeIndexWorkerSelectionV1::Exact { workers: 2 },
                ),
            ),
            Ok(())
        ));
        assert!(matches!(
            registry.validate_value(
                &key,
                &ConfigurationValueV1::CodeIndexWorkerSelection(
                    CodeIndexWorkerSelectionV1::Exact { workers: 0 },
                ),
            ),
            Err(ConfigurationRegistryError::InvalidDefinition(
                tracedecay_domain::DomainError::NonCanonical {
                    field: "code index worker count",
                }
            ))
        ));
    }
}

#[cfg(test)]
mod memory_provider_registration_tests {
    use super::*;
    use tracedecay_domain::configuration::MemoryProviderParticipationV1;

    fn canonical_text<T: serde::Serialize>(value: &T) -> String {
        String::from_utf8(tracedecay_domain::canonical_json_bytes(value).unwrap()).unwrap()
    }

    fn provider_test_root() -> std::path::PathBuf {
        if cfg!(windows) {
            std::path::PathBuf::from(r"C:\provider")
        } else {
            std::path::PathBuf::from("/provider")
        }
    }

    #[test]
    fn provider_participation_and_selection_keep_project_scope_defaults_and_restart_policy() {
        let registry = ConfigurationRegistry::core().unwrap();
        for key in [
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
        ] {
            let definition = registry.definition(&SettingKey::new(key).unwrap()).unwrap();
            assert_eq!(definition.scope, SettingScopeV1::Project);
            assert_eq!(
                definition.restart_requirement,
                RestartRequirementV1::DaemonRestart
            );
            match key {
                MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY => assert_eq!(
                    definition.default_value,
                    ConfigurationValueV1::Boolean(true)
                ),
                MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY => assert_eq!(
                    definition.default_value,
                    ConfigurationValueV1::Text(r#"{"mode":"disabled"}"#.to_owned())
                ),
                _ => {
                    let ConfigurationValueV1::Text(value) = &definition.default_value else {
                        panic!("routing must remain canonical JSON text")
                    };
                    let routing: tracedecay_domain::configuration::MemoryProviderRecallRoutingV1 =
                        serde_json::from_str(value).unwrap();
                    assert_eq!(value, &canonical_text(&routing));
                    assert_eq!(
                        routing.active_provider.as_deref(),
                        Some(MemoryProviderKindV1::Native.provider_id())
                    );
                    assert_eq!(routing.fallback, None);
                    assert_eq!(routing.degradation, None);
                }
            }
        }
        let resolution = crate::configuration::resolver::resolve_configuration(&registry, &[])
            .expect("default provider settings resolve");
        let selection = registry
            .resolve_provider_selection(&resolution.snapshot.effective_values)
            .expect("default provider selection is composable");
        assert_eq!(
            selection.active_provider(),
            Some(MemoryProviderKindV1::Native)
        );
        assert_eq!(selection.native, MemoryProviderParticipationV1::Active);
        assert_eq!(selection.ncm, MemoryProviderParticipationV1::Disabled);
    }

    #[test]
    fn provider_documents_are_parsed_and_semantically_validated_at_registry_admission() {
        let registry = ConfigurationRegistry::core().unwrap();
        let ncm_key = SettingKey::new(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY).unwrap();
        let routing_key = SettingKey::new(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY).unwrap();

        for (key, document) in [
            (&ncm_key, "{"),
            (
                &ncm_key,
                r#"{"mode":"enabled","worker_binary":"worker","state_root":"/state"}"#,
            ),
            (&ncm_key, r#"{ "mode":"disabled" }"#),
            (&routing_key, r#"{"active_provider":"ncm","unknown":true}"#),
            (
                &routing_key,
                r#"{ "active_provider": null, "degradation": null, "fallback": null }"#,
            ),
            (
                &routing_key,
                r#"{"fallback":{"policy_id":"policy.recall.fallback","policy_revision":1,"target_provider":"ncm"},"active_provider":"tracedecay.native","degradation":null}"#,
            ),
            (
                &routing_key,
                r#"{"active_provider":"tracedecay.native","degradation":null,"fallback":{"policy_id":"policy.recall.fallback","policy_revision":1.0,"target_provider":"ncm"}}"#,
            ),
        ] {
            assert!(matches!(
                registry.validate_value(key, &ConfigurationValueV1::Text(document.to_owned())),
                Err(ConfigurationRegistryError::InvalidStructuredValue {
                    key: actual_key,
                    ..
                }) if actual_key.as_str() == key.as_str()
            ));
        }
    }

    #[test]
    fn ncm_namespace_admission_preserves_omitted_legacy_and_requires_canonical_checkout() {
        let registry = ConfigurationRegistry::core().unwrap();
        let ncm_key = SettingKey::new(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY).unwrap();
        let observer = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: provider_test_root().join("worker"),
            state_root: provider_test_root().join("state"),
            namespace_binding: Default::default(),
        };
        let legacy = serde_json::to_value(&observer).unwrap();
        assert!(legacy.get("namespace_binding").is_none());
        let resolution = crate::configuration::resolver::resolve_configuration(&registry, &[])
            .expect("default provider settings resolve");

        for (binding, admitted) in [
            (None, true),
            (Some("exact_session_v1"), false),
            (Some("checkout_observations_v1"), true),
        ] {
            let mut document = legacy.clone();
            if let Some(binding) = binding {
                document["namespace_binding"] = serde_json::json!(binding);
            }
            // Canonicalize JSON syntax without erasing an explicitly supplied default.
            let value = ConfigurationValueV1::Text(canonical_text(&document));
            let mut values = resolution.snapshot.effective_values.clone();
            values.insert(ncm_key.clone(), value.clone());
            let before = values.clone();
            let validation = registry.validate_value(&ncm_key, &value);
            let selection = registry.resolve_provider_selection(&values);
            if admitted {
                validation.unwrap();
                assert_eq!(
                    selection.unwrap().ncm,
                    MemoryProviderParticipationV1::Observer,
                );
            } else {
                for error in [validation.unwrap_err(), selection.unwrap_err()] {
                    assert!(matches!(
                        error,
                        ConfigurationRegistryError::InvalidStructuredValue {
                            key,
                            message,
                            ..
                        } if key == ncm_key && message.contains("canonical serialization")
                    ));
                }
            }
            assert_eq!(values, before);
        }
    }

    #[test]
    fn noncanonical_provider_document_is_rejected_without_mutating_values() {
        let registry = ConfigurationRegistry::core().unwrap();
        let resolution = crate::configuration::resolver::resolve_configuration(&registry, &[])
            .expect("default provider settings resolve");
        let routing_key = SettingKey::new(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY).unwrap();
        let mut values = resolution.snapshot.effective_values;
        values.insert(
            routing_key.clone(),
            ConfigurationValueV1::Text(
                r#"{ "active_provider": null, "degradation": null, "fallback": null }"#.to_owned(),
            ),
        );
        let before = values.clone();

        assert!(matches!(
            registry.resolve_provider_selection(&values),
            Err(ConfigurationRegistryError::InvalidStructuredValue {
                key,
                message,
                ..
            }) if key == routing_key && message.contains("canonical serialization")
        ));
        assert_eq!(values, before);
    }

    #[test]
    fn provider_selection_rejects_uncomposable_active_and_fallback_targets_without_mutating_values()
    {
        let registry = ConfigurationRegistry::core().unwrap();
        let resolution = crate::configuration::resolver::resolve_configuration(&registry, &[])
            .expect("default provider settings resolve");
        let mut values = resolution.snapshot.effective_values.clone();
        let native_key = SettingKey::new(MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY).unwrap();
        let ncm_key = SettingKey::new(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY).unwrap();
        let routing_key = SettingKey::new(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY).unwrap();
        values.insert(native_key.clone(), ConfigurationValueV1::Boolean(false));
        let before = values.clone();
        assert!(matches!(
            registry.resolve_provider_selection(&values),
            Err(ConfigurationRegistryError::ProviderSelection(
                MemoryProviderSelectionErrorV1::SelectedProviderDisabled(
                    MemoryProviderKindV1::Native
                )
            ))
        ));
        assert_eq!(values, before);
        values.insert(native_key.clone(), ConfigurationValueV1::Boolean(true));

        values.insert(
            routing_key.clone(),
            ConfigurationValueV1::Text(canonical_text(&MemoryProviderRecallRoutingV1 {
                active_provider: Some("ncm".to_owned()),
                ..Default::default()
            })),
        );
        let before = values.clone();
        assert!(matches!(
            registry.resolve_provider_selection(&values),
            Err(ConfigurationRegistryError::ProviderSelection(
                MemoryProviderSelectionErrorV1::SelectedProviderDisabled(
                    tracedecay_domain::configuration::MemoryProviderKindV1::Ncm
                )
            ))
        ));
        assert_eq!(values, before);

        values.insert(
            ncm_key,
            ConfigurationValueV1::Text(canonical_text(&MemoryProviderNcmObserverV1::Enabled {
                worker_binary: provider_test_root().join("worker"),
                state_root: provider_test_root().join("state"),
                namespace_binding: Default::default(),
            })),
        );
        let enabled_fallback = MemoryProviderRecallRoutingV1 {
            active_provider: Some("tracedecay.native".to_owned()),
            fallback: Some(
                tracedecay_domain::configuration::MemoryProviderRecallFallbackV1 {
                    policy_id: "policy.recall.fallback".to_owned(),
                    policy_revision: 1,
                    target_provider: "ncm".to_owned(),
                },
            ),
            ..Default::default()
        };
        values.insert(
            routing_key.clone(),
            ConfigurationValueV1::Text(canonical_text(&enabled_fallback)),
        );
        let before = values.clone();
        assert!(matches!(
            registry.resolve_provider_selection(&values),
            Err(ConfigurationRegistryError::ProviderSelection(
                MemoryProviderSelectionErrorV1::UnsupportedFallbackProvider(provider)
            )) if provider == "ncm"
        ));
        assert_eq!(values, before);

        let unregistered_fallback = MemoryProviderRecallRoutingV1 {
            active_provider: Some("tracedecay.native".to_owned()),
            fallback: Some(
                tracedecay_domain::configuration::MemoryProviderRecallFallbackV1 {
                    policy_id: "policy.recall.fallback".to_owned(),
                    policy_revision: 1,
                    target_provider: "provider.unregistered".to_owned(),
                },
            ),
            ..Default::default()
        };
        values.insert(
            routing_key,
            ConfigurationValueV1::Text(canonical_text(&unregistered_fallback)),
        );
        let before = values.clone();
        assert!(matches!(
            registry.resolve_provider_selection(&values),
            Err(ConfigurationRegistryError::ProviderSelection(
                MemoryProviderSelectionErrorV1::UnsupportedFallbackProvider(provider)
            )) if provider == "provider.unregistered"
        ));
        assert_eq!(values, before);
    }
}

#[cfg(test)]
mod profile_summarizer_tests {
    use super::*;

    #[test]
    fn profile_codex_executor_is_sensitive_direct_and_validated_as_a_single_executable() {
        let registry = ConfigurationRegistry::profile().unwrap();
        let key = setting_key(USER_LCM_CODEX_SUMMARIZER_SETTING_KEY).unwrap();
        let definition = registry.definition(&key).unwrap();
        assert_eq!(definition.scope, SettingScopeV1::UserProfile);
        assert_eq!(definition.sensitivity, SettingSensitivityV1::Sensitive);
        assert_eq!(definition.restart_requirement, RestartRequirementV1::None);
        assert_eq!(
            definition.default_value,
            ConfigurationValueV1::LcmSummarizerExecutable(LcmSummarizerExecutableV1::Unconfigured)
        );
        assert!(
            registry
                .validate_value(
                    &key,
                    &ConfigurationValueV1::LcmSummarizerExecutables(
                        LcmSummarizerExecutablesV1::unconfigured()
                    )
                )
                .is_err()
        );
        assert!(
            registry
                .validate_value(
                    &key,
                    &ConfigurationValueV1::LcmSummarizerExecutable(
                        LcmSummarizerExecutableV1::Configured {
                            canonical_path: std::path::PathBuf::from("codex"),
                            model: None,
                            timeout_secs: None
                        }
                    )
                )
                .is_err()
        );
    }
}
