//! Runtime pin surfaces and control-plane config helpers.
//!
//! Retrieval-profile evaluation stays in `tracedecay-application::config::retrieval`.
//! The re-export rows below are surfaces `tracedecay-global-db` and
//! `tracedecay-domain` already own, kept under the `crate::config::…`
//! spelling so call sites share one import path.

pub mod analyzer;
pub mod model;
pub mod scope_control;
pub mod topology;
pub mod work_executable_binding;

pub use tracedecay_domain::configuration::{
    MemoryProviderNcmObserverV1, MemoryProviderRecallDegradationCauseV1,
    MemoryProviderRecallDegradationV1, MemoryProviderRecallFallbackV1,
    MemoryProviderRecallRoutingV1,
};
pub use tracedecay_global_db::configuration::{registry, resolver};

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use tracedecay_contracts::{ConfigurationSettingActionV1, ConfigurationSettingFindingV1};
use tracedecay_domain::configuration::{
    ConfigurationRevisionId, ConfigurationSnapshotV1, ConfigurationValueV1,
    INDEX_EXCLUDE_SETTING_KEY, INDEX_EXTRACT_DOCSTRINGS_SETTING_KEY, INDEX_INCLUDE_SETTING_KEY,
    INDEX_MAX_FILE_SIZE_SETTING_KEY, INDEX_NATIVE_GRAPH_ACTIVATION_SETTING_KEY,
    INDEX_TRACK_CALL_SITES_SETTING_KEY, LCM_SUMMARIZER_EXECUTABLES_SETTING_KEY,
    LcmSummarizerExecutablesV1, MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
    MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY, MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
    SYNC_AUTO_INIT_SETTING_KEY, SYNC_AUTO_TRACK_PR_BRANCHES_SETTING_KEY,
    SYNC_AUTO_TRACK_PR_POLL_SECS_SETTING_KEY, SYNC_AUTO_WATCH_SETTING_KEY,
    SYNC_BACKSTOP_INTERVAL_MINS_SETTING_KEY, SYNC_BRANCH_GC_DAYS_SETTING_KEY,
    SYNC_FULL_SYNC_ESCALATION_FILES_SETTING_KEY, SYNC_MAX_CONCURRENT_SYNCS_SETTING_KEY,
    SYNC_READ_COOLDOWN_SECS_SETTING_KEY, SYNC_READ_REFRESH_SETTING_KEY,
    SYNC_SESSION_START_STALE_THRESHOLD_SECS_SETTING_KEY, SYNC_SESSION_START_SYNC_SETTING_KEY,
    SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY, SYNC_WATCH_LINKED_WORKTREES_SETTING_KEY,
    SYNC_WATCH_MAX_DELAY_MS_SETTING_KEY, SYNC_WATCH_MAX_PROJECTS_SETTING_KEY, SettingKey,
    TELEMETRY_TIMINGS_SETTING_KEY,
};
use tracedecay_domain::errors::{Result, TraceDecayError};
use tracedecay_domain::{IndexPathPolicyV1, ProjectId, validate_index_path_patterns};
use tracedecay_global_db::configuration::contracts::ConfigurationCurrentStateV1;
use tracedecay_global_db::{RegisteredGlobalDb, RegisteredGlobalDbLeaseV1};

use model::{RetentionConfig, SyncConfig, TelemetryConfig};

/// Settings decoded from one resolved configuration snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeTraceDecayConfig {
    /// `index.exclude.v1` and `index.include.v1`, compiled once: the path
    /// policy the code index, its freshness proof, and source walks share.
    pub index_paths: IndexPathPolicyV1,
    /// Maximum file size in bytes; larger files are skipped.
    pub max_file_size: u64,
    pub extract_docstrings: bool,
    pub track_call_sites: bool,
    /// Whether the persistent native code graph may activate. Disabling it
    /// leaves exact and lexical retrieval available.
    pub native_graph_activation: bool,
    /// The host CLIs on-demand LCM summarization may launch. Every provider
    /// is unconfigured until an operator names its executable; the daemon
    /// never resolves one from `PATH` or its environment.
    pub lcm_summarizers: LcmSummarizerExecutablesV1,
    pub memory_provider_native_enabled: bool,
    pub memory_provider_ncm_observer: MemoryProviderNcmObserverV1,
    pub memory_provider_recall_routing: MemoryProviderRecallRoutingV1,
    pub sync: SyncConfig,
    pub telemetry: TelemetryConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfigurationTarget {
    /// Data directory of the profile that owns this project's configuration
    /// store. One checkout registered in two profiles has one `project_id`,
    /// so only the pair names a store.
    pub profile_root: PathBuf,
    pub project_id: ProjectId,
    pub project_root: PathBuf,
}

/// The owning profile and project of a registered project store. The store
/// lives in its profile's shard for the project, so its path names the owner.
pub fn registered_configuration_owner(
    database: &RegisteredGlobalDb,
) -> Result<(PathBuf, ProjectId)> {
    let project_id = database
        .binding()
        .shard_id
        .scope
        .project_id()
        .ok_or_else(|| config_error("registered database is not a project store"))?;
    database
        .db_path()
        .parent()
        .and_then(|store_root| {
            tracedecay_runtime_core::storage::profile_root_of_sharded_data_root(
                store_root,
                project_id.as_str(),
            )
        })
        .map(|profile_root| (profile_root.to_path_buf(), project_id.clone()))
        .ok_or_else(|| {
            config_error(format!(
                "registered database '{}' is not a profile shard of project '{}'",
                database.db_path().display(),
                project_id.as_str()
            ))
        })
}

/// One validated binding of a configuration revision to the runtime settings
/// decoded from it.
///
/// The fields are private: [`Self::new`] is the only constructor and it
/// decodes the snapshot exactly once, so a pin can never pair a snapshot with
/// settings it did not produce. The snapshot is shared, because a pin is
/// cloned on every publication and cached read; those clones must not copy
/// the whole snapshot.
#[derive(Clone, Debug)]
pub struct PinnedRuntimeConfiguration {
    target: RuntimeConfigurationTarget,
    revision_id: ConfigurationRevisionId,
    snapshot: Arc<ConfigurationSnapshotV1>,
    config: RuntimeTraceDecayConfig,
}

impl PinnedRuntimeConfiguration {
    /// Decodes `snapshot` into the runtime settings. Missing or wrongly typed
    /// required settings are rejected rather than defaulted.
    pub fn new(
        target: RuntimeConfigurationTarget,
        revision_id: ConfigurationRevisionId,
        snapshot: ConfigurationSnapshotV1,
    ) -> Result<Self> {
        let config = runtime_config_from_snapshot(&snapshot)?;
        Ok(Self {
            target,
            revision_id,
            snapshot: Arc::new(snapshot),
            config,
        })
    }

    pub fn target(&self) -> &RuntimeConfigurationTarget {
        &self.target
    }

    pub fn revision_id(&self) -> &ConfigurationRevisionId {
        &self.revision_id
    }

    pub fn snapshot(&self) -> &ConfigurationSnapshotV1 {
        &self.snapshot
    }

    pub fn config(&self) -> &RuntimeTraceDecayConfig {
        &self.config
    }

    /// The same revision and settings routed under another root of the same
    /// registered project. The root is display/routing context only, so
    /// nothing is decoded again.
    pub fn with_project_root(mut self, project_root: &Path) -> Self {
        self.target.project_root = project_root.to_path_buf();
        self
    }

    /// The revision/snapshot pair as the store-level current state, for
    /// callers that own it by value. The snapshot is copied only while
    /// another pin still shares it.
    pub fn into_current_state(self) -> ConfigurationCurrentStateV1 {
        ConfigurationCurrentStateV1 {
            revision_id: self.revision_id,
            snapshot: Arc::unwrap_or_clone(self.snapshot),
        }
    }
}

pub struct OpenedRuntimeConfiguration {
    pub(crate) configuration: PinnedRuntimeConfiguration,
    pub(crate) registered_database: RegisteredGlobalDbLeaseV1,
}

impl OpenedRuntimeConfiguration {
    pub fn new(
        configuration: PinnedRuntimeConfiguration,
        registered_database: RegisteredGlobalDbLeaseV1,
    ) -> Self {
        Self {
            configuration,
            registered_database,
        }
    }
}

/// Process-wide pin cache used by daemon invocation after project-open
/// publishes a snapshot. Opening durable configuration from a registered
/// store stays with the composition root, which owns that store.
pub trait PinnedRuntimeConfigurationCachePort: Send + Sync {
    fn publish(&self, configuration: PinnedRuntimeConfiguration) -> Result<()>;

    /// The pin `profile_root` published for an already-authoritative
    /// registered project, for daemon work (session shards, background
    /// convergence) that has a project identity but no route root.
    fn cached_for_project(
        &self,
        profile_root: &Path,
        project_id: &ProjectId,
    ) -> Result<PinnedRuntimeConfiguration>;
}

static PINNED_RUNTIME_CONFIGURATION_CACHE: OnceLock<Arc<dyn PinnedRuntimeConfigurationCachePort>> =
    OnceLock::new();

pub fn install_pinned_runtime_configuration_cache(
    cache: Arc<dyn PinnedRuntimeConfigurationCachePort>,
) -> Result<()> {
    PINNED_RUNTIME_CONFIGURATION_CACHE
        .set(cache)
        .map_err(|_| config_error("pinned runtime configuration cache is already installed"))
}

fn pinned_runtime_configuration_cache() -> Result<&'static dyn PinnedRuntimeConfigurationCachePort>
{
    PINNED_RUNTIME_CONFIGURATION_CACHE
        .get()
        .map(Arc::as_ref)
        .ok_or_else(|| config_error("pinned runtime configuration cache is not installed"))
}

pub fn publish_pinned_runtime_configuration(
    configuration: PinnedRuntimeConfiguration,
) -> Result<()> {
    pinned_runtime_configuration_cache()?.publish(configuration)
}

/// The summarizer executables the daemon published for the project store
/// `database` is. A missing cache or pin is a typed configuration error, not
/// an unconfigured provider: the caller decides whether that means "pending".
pub fn lcm_summarizer_executables_for_database(
    database: &RegisteredGlobalDb,
) -> Result<LcmSummarizerExecutablesV1> {
    let (profile_root, project_id) = registered_configuration_owner(database)?;
    Ok(pinned_runtime_configuration_cache()?
        .cached_for_project(&profile_root, &project_id)?
        .config()
        .lcm_summarizers
        .clone())
}

/// Converts a complete typed snapshot into the runtime settings every
/// configuration consumer shares. There are no defaults, file reads, or
/// environment reads: an absent or mistyped required setting is an error.
#[tracing::instrument(name = "configuration.runtime.materialize", level = "trace", skip_all)]
fn runtime_config_from_snapshot(
    snapshot: &ConfigurationSnapshotV1,
) -> Result<RuntimeTraceDecayConfig> {
    snapshot.validate().map_err(|error| {
        config_error(format!("invalid resolved configuration snapshot: {error}"))
    })?;
    Ok(RuntimeTraceDecayConfig {
        index_paths: IndexPathPolicyV1::new(
            applied_index_patterns(snapshot, INDEX_EXCLUDE_SETTING_KEY)?,
            applied_index_patterns(snapshot, INDEX_INCLUDE_SETTING_KEY)?,
        )
        .map_err(|error| config_error(format!("resolved index path policy is invalid: {error}")))?,
        max_file_size: required_unsigned(snapshot, INDEX_MAX_FILE_SIZE_SETTING_KEY)?,
        extract_docstrings: required_bool(snapshot, INDEX_EXTRACT_DOCSTRINGS_SETTING_KEY)?,
        track_call_sites: required_bool(snapshot, INDEX_TRACK_CALL_SITES_SETTING_KEY)?,
        native_graph_activation: required_bool(
            snapshot,
            INDEX_NATIVE_GRAPH_ACTIVATION_SETTING_KEY,
        )?,
        lcm_summarizers: required_lcm_summarizer_executables(snapshot)?,
        memory_provider_native_enabled: required_bool(
            snapshot,
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
        )?,
        memory_provider_ncm_observer: memory_provider_ncm_observer_from_snapshot(snapshot)?,
        memory_provider_recall_routing: memory_provider_recall_routing_from_snapshot(snapshot)?,
        sync: SyncConfig {
            auto_watch: required_bool(snapshot, SYNC_AUTO_WATCH_SETTING_KEY)?,
            watch_linked_worktrees: required_bool(
                snapshot,
                SYNC_WATCH_LINKED_WORKTREES_SETTING_KEY,
            )?,
            watch_debounce_ms: required_unsigned(snapshot, SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY)?,
            watch_max_delay_ms: required_unsigned(snapshot, SYNC_WATCH_MAX_DELAY_MS_SETTING_KEY)?,
            watch_max_projects: required_usize(snapshot, SYNC_WATCH_MAX_PROJECTS_SETTING_KEY)?,
            read_refresh: required_bool(snapshot, SYNC_READ_REFRESH_SETTING_KEY)?,
            read_cooldown_secs: required_unsigned(snapshot, SYNC_READ_COOLDOWN_SECS_SETTING_KEY)?,
            session_start_sync: required_bool(snapshot, SYNC_SESSION_START_SYNC_SETTING_KEY)?,
            session_start_stale_threshold_secs: required_unsigned(
                snapshot,
                SYNC_SESSION_START_STALE_THRESHOLD_SECS_SETTING_KEY,
            )?,
            backstop_interval_mins: required_unsigned(
                snapshot,
                SYNC_BACKSTOP_INTERVAL_MINS_SETTING_KEY,
            )?,
            full_sync_escalation_files: required_usize(
                snapshot,
                SYNC_FULL_SYNC_ESCALATION_FILES_SETTING_KEY,
            )?,
            max_concurrent_syncs: required_usize(snapshot, SYNC_MAX_CONCURRENT_SYNCS_SETTING_KEY)?,
            branch_gc_days: required_unsigned(snapshot, SYNC_BRANCH_GC_DAYS_SETTING_KEY)?,
            auto_init: required_bool(snapshot, SYNC_AUTO_INIT_SETTING_KEY)?,
            auto_track_pr_branches: required_bool(
                snapshot,
                SYNC_AUTO_TRACK_PR_BRANCHES_SETTING_KEY,
            )?,
            auto_track_pr_poll_secs: required_unsigned(
                snapshot,
                SYNC_AUTO_TRACK_PR_POLL_SECS_SETTING_KEY,
            )?,
            // Retention is not a registered setting, so a snapshot cannot
            // carry retention policy.
            retention: RetentionConfig::default(),
        },
        telemetry: TelemetryConfig {
            timings: required_bool(snapshot, TELEMETRY_TIMINGS_SETTING_KEY)?,
        },
    })
}

fn setting_key(key_name: &str) -> Result<SettingKey> {
    SettingKey::new(key_name)
        .map_err(|error| config_error(format!("invalid runtime setting key '{key_name}': {error}")))
}

/// Typed readers over a resolved snapshot. Every runtime materializer (this
/// crate's shared settings and the daemon-only policy the composition root
/// layers on top) reads through these, so a missing or mistyped setting is
/// reported identically wherever it is consumed.
pub fn required_setting<'a>(
    snapshot: &'a ConfigurationSnapshotV1,
    key_name: &str,
) -> Result<&'a ConfigurationValueV1> {
    let key = setting_key(key_name)?;
    snapshot.effective_values.get(&key).ok_or_else(|| {
        config_error(format!(
            "resolved configuration snapshot is missing required setting '{key_name}'",
        ))
    })
}

pub fn required_bool(snapshot: &ConfigurationSnapshotV1, key_name: &str) -> Result<bool> {
    match required_setting(snapshot, key_name)? {
        ConfigurationValueV1::Boolean(value) => Ok(*value),
        value => Err(config_error(format!(
            "resolved configuration setting '{key_name}' has wrong type: expected boolean, got {:?}",
            value.kind()
        ))),
    }
}

pub fn required_unsigned(snapshot: &ConfigurationSnapshotV1, key_name: &str) -> Result<u64> {
    match required_setting(snapshot, key_name)? {
        ConfigurationValueV1::Unsigned(value) => Ok(*value),
        value => Err(config_error(format!(
            "resolved configuration setting '{key_name}' has wrong type: expected unsigned, got {:?}",
            value.kind()
        ))),
    }
}

fn memory_provider_ncm_observer_from_snapshot(
    snapshot: &ConfigurationSnapshotV1,
) -> Result<MemoryProviderNcmObserverV1> {
    let routing: MemoryProviderNcmObserverV1 =
        match required_setting(snapshot, MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY)? {
            ConfigurationValueV1::Text(value) => serde_json::from_str(value).map_err(|error| {
                config_error(format!(
                    "resolved configuration setting '{MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY}' is not a NCM observer document: {error}"
                ))
            })?,
            _ => {
                return Err(config_error(format!(
                    "resolved configuration setting '{MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY}' is not text"
                )));
            }
        };
    routing.validate().map_err(|error| {
        config_error(format!(
            "resolved configuration setting '{MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY}' is invalid: {error}"
        ))
    })?;
    Ok(routing)
}

fn memory_provider_recall_routing_from_snapshot(
    snapshot: &ConfigurationSnapshotV1,
) -> Result<MemoryProviderRecallRoutingV1> {
    let routing: MemoryProviderRecallRoutingV1 =
        match required_setting(snapshot, MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY)? {
            ConfigurationValueV1::Text(value) => serde_json::from_str(value).map_err(|error| {
                config_error(format!(
                    "resolved configuration setting '{MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY}' is not a recall routing document: {error}"
                ))
            })?,
            _ => {
                return Err(config_error(format!(
                    "resolved configuration setting '{MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY}' is not text"
                )));
            }
        };
    routing.validate().map_err(|error| {
        config_error(format!(
            "resolved configuration setting '{MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY}' is invalid: {error}"
        ))
    })?;
    Ok(routing)
}

pub fn required_usize(snapshot: &ConfigurationSnapshotV1, key_name: &str) -> Result<usize> {
    let value = required_unsigned(snapshot, key_name)?;
    usize::try_from(value).map_err(|_| {
        config_error(format!(
            "resolved configuration setting '{key_name}' does not fit this platform",
        ))
    })
}

pub fn required_string_list(
    snapshot: &ConfigurationSnapshotV1,
    key_name: &str,
) -> Result<Vec<String>> {
    match required_setting(snapshot, key_name)? {
        ConfigurationValueV1::StringList(value) => Ok(value.clone()),
        value => Err(config_error(format!(
            "resolved configuration setting '{key_name}' has wrong type: expected string list, got {:?}",
            value.kind()
        ))),
    }
}

/// Splits a stored index path pattern list into the patterns indexing
/// applies and a finding for each one that does not compile.
///
/// Writes refuse such a pattern, but an earlier release stored patterns it
/// never compiled. Refusing the whole pin would also refuse the `set` and
/// `unset` that repair it, so the pin applies the rest and
/// [`setting_findings`] reports each skipped pattern.
fn partition_index_patterns(
    patterns: Vec<String>,
) -> (Vec<String>, Vec<ConfigurationSettingFindingV1>) {
    // One set compiles when every member does; only a failing list needs the
    // per-pattern compiles that name its invalid members.
    if validate_index_path_patterns(&patterns).is_ok() {
        return (patterns, Vec::new());
    }
    let mut applied = Vec::with_capacity(patterns.len());
    let mut findings = Vec::new();
    for pattern in patterns {
        match validate_index_path_patterns(std::slice::from_ref(&pattern)) {
            Ok(()) => applied.push(pattern),
            Err(error) => findings.push(ConfigurationSettingFindingV1::InvalidIndexPathPattern {
                pattern,
                message: error.message,
                legal_actions: vec![
                    ConfigurationSettingActionV1::Set,
                    ConfigurationSettingActionV1::Unset,
                ],
            }),
        }
    }
    (applied, findings)
}

fn applied_index_patterns(
    snapshot: &ConfigurationSnapshotV1,
    key_name: &str,
) -> Result<Vec<String>> {
    Ok(partition_index_patterns(required_string_list(snapshot, key_name)?).0)
}

/// The parts of a stored `value` for `key` that the runtime configuration
/// does not apply.
pub fn setting_findings(
    key: &SettingKey,
    value: &ConfigurationValueV1,
) -> Vec<ConfigurationSettingFindingV1> {
    match value {
        ConfigurationValueV1::StringList(patterns)
            if matches!(
                key.as_str(),
                INDEX_EXCLUDE_SETTING_KEY | INDEX_INCLUDE_SETTING_KEY
            ) =>
        {
            partition_index_patterns(patterns.clone()).1
        }
        _ => Vec::new(),
    }
}

fn required_lcm_summarizer_executables(
    snapshot: &ConfigurationSnapshotV1,
) -> Result<LcmSummarizerExecutablesV1> {
    match required_setting(snapshot, LCM_SUMMARIZER_EXECUTABLES_SETTING_KEY)? {
        ConfigurationValueV1::LcmSummarizerExecutables(value) => Ok(value.clone()),
        value => Err(config_error(format!(
            "resolved configuration setting '{LCM_SUMMARIZER_EXECUTABLES_SETTING_KEY}' has wrong type: expected lcm summarizer executables, got {:?}",
            value.kind()
        ))),
    }
}

fn config_error(message: impl Into<String>) -> TraceDecayError {
    TraceDecayError::Config {
        message: message.into(),
    }
}

#[cfg(test)]
mod memory_provider_snapshot_tests {
    use std::collections::BTreeMap;

    use tracedecay_domain::configuration::SettingKey;
    use tracedecay_global_db::configuration::registry::ConfigurationRegistry;
    use tracedecay_global_db::configuration::resolver::resolve_configuration;

    use super::*;

    fn setting_key(raw: &str) -> SettingKey {
        SettingKey::new(raw).expect("fixture setting key is canonical")
    }

    /// The snapshot the production resolver publishes with no operator layers.
    fn default_snapshot() -> ConfigurationSnapshotV1 {
        let registry = ConfigurationRegistry::core().expect("core registry");
        resolve_configuration(&registry, &[])
            .expect("default resolution")
            .snapshot
    }

    /// Rebuild the default snapshot with one setting replaced (`Some`) or
    /// removed from both the value and provenance maps (`None`).
    fn snapshot_with(
        raw_key: &str,
        value: Option<ConfigurationValueV1>,
    ) -> ConfigurationSnapshotV1 {
        let base = default_snapshot();
        let mut effective_values: BTreeMap<_, _> = base.effective_values.clone();
        let mut provenance: BTreeMap<_, _> = base.provenance.clone();
        let key = setting_key(raw_key);
        match value {
            Some(value) => {
                effective_values.insert(key, value);
            }
            None => {
                effective_values.remove(&key);
                provenance.remove(&key);
            }
        }
        ConfigurationSnapshotV1::new(effective_values, provenance).expect("fixture snapshot")
    }

    fn routing_text(routing: &MemoryProviderRecallRoutingV1) -> ConfigurationValueV1 {
        ConfigurationValueV1::Text(serde_json::to_string(routing).expect("routing encodes"))
    }

    #[test]
    fn ncm_observer_snapshot_defaults_off_and_validates_admitted_paths() {
        let stock = runtime_config_from_snapshot(&default_snapshot()).unwrap();
        assert_eq!(
            stock.memory_provider_ncm_observer,
            MemoryProviderNcmObserverV1::Disabled {}
        );
        assert_eq!(
            serde_json::to_string(&stock.memory_provider_ncm_observer).unwrap(),
            r#"{"mode":"disabled"}"#
        );
        let disabled = runtime_config_from_snapshot(&snapshot_with(
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            Some(ConfigurationValueV1::Text(
                r#"{"mode":"disabled"}"#.to_owned(),
            )),
        ))
        .unwrap();
        assert_eq!(
            disabled.memory_provider_ncm_observer,
            MemoryProviderNcmObserverV1::default()
        );
        // Absolute on the host: a rooted Unix literal has no drive on Windows.
        let root = PathBuf::from(if cfg!(windows) { r"C:\" } else { "/" });
        let observer = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: root.join("opt/tracedecay/tracedecay-ncm-worker"),
            state_root: root.join("var/lib/tracedecay/ncm"),
            namespace_binding: Default::default(),
        };
        let value = ConfigurationValueV1::Text(serde_json::to_string(&observer).unwrap());
        let selected = runtime_config_from_snapshot(&snapshot_with(
            MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
            Some(value),
        ))
        .unwrap();
        assert_eq!(selected.memory_provider_ncm_observer, observer);
        for document in [
            r#"{"mode":"enabled","worker_binary":"relative-worker","state_root":"/state"}"#,
            r#"{"mode":"enabled","worker_binary":"/worker","state_root":"/state/../other"}"#,
            r#"{"mode":"enabled","worker_binary":"/worker"}"#,
            r#"{"mode":"disabled","active":true}"#,
            r#"{"mode":"enabled","worker_binary":"/worker","state_root":"/state","active":true}"#,
        ] {
            assert!(
                runtime_config_from_snapshot(&snapshot_with(
                    MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
                    Some(ConfigurationValueV1::Text(document.to_owned()))
                ))
                .is_err(),
                "{document}"
            );
        }
        assert!(
            runtime_config_from_snapshot(&snapshot_with(
                MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY,
                None
            ))
            .is_err()
        );
    }

    #[test]
    fn legacy_participation_snapshot_selects_ncm_without_enabling_native() {
        use tracedecay_domain::configuration::{
            MemoryProviderKindV1, MemoryProviderParticipationV1, MemoryProviderSelectionV1,
        };
        let base = default_snapshot();
        let mut values = base.effective_values.clone();
        let root = if cfg!(windows) {
            PathBuf::from("C:\\ncm")
        } else {
            PathBuf::from("/ncm")
        };
        let ncm = MemoryProviderNcmObserverV1::Enabled {
            worker_binary: root.join("worker"),
            state_root: root.join("state"),
            namespace_binding: Default::default(),
        };
        values.insert(
            setting_key(MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY),
            ConfigurationValueV1::Boolean(false),
        );
        values.insert(
            setting_key(MEMORY_PROVIDER_NCM_OBSERVER_SETTING_KEY),
            ConfigurationValueV1::Text(serde_json::to_string(&ncm).unwrap()),
        );
        values.insert(
            setting_key(MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY),
            ConfigurationValueV1::Text(r#"{"active_provider":"ncm"}"#.to_owned()),
        );
        let snapshot = ConfigurationSnapshotV1::new(values, base.provenance).unwrap();
        let config = runtime_config_from_snapshot(&snapshot).unwrap();
        assert!(!config.memory_provider_native_enabled);
        assert_eq!(config.memory_provider_ncm_observer, ncm);
        let selection = MemoryProviderSelectionV1::resolve(
            config.memory_provider_native_enabled,
            &config.memory_provider_ncm_observer,
            &config.memory_provider_recall_routing,
        )
        .unwrap();
        assert_eq!(selection.active_provider(), Some(MemoryProviderKindV1::Ncm));
        assert_eq!(selection.native, MemoryProviderParticipationV1::Disabled);
        assert_eq!(selection.ncm, MemoryProviderParticipationV1::Active);
    }

    #[test]
    fn both_memory_provider_settings_extract_from_the_resolved_snapshot() {
        // New projects route recall through Native without an NCM worker.
        let stock = runtime_config_from_snapshot(&default_snapshot())
            .expect("default snapshot yields a runtime configuration");
        assert!(stock.memory_provider_native_enabled);
        assert_eq!(
            stock.memory_provider_recall_routing,
            MemoryProviderRecallRoutingV1 {
                active_provider: Some("tracedecay.native".to_owned()),
                ..Default::default()
            }
        );
        assert_eq!(
            stock.memory_provider_ncm_observer,
            MemoryProviderNcmObserverV1::Disabled {}
        );

        // An operator-pinned boolean reaches the runtime configuration.
        let native_off = runtime_config_from_snapshot(&snapshot_with(
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            Some(ConfigurationValueV1::Boolean(false)),
        ))
        .expect("native-disabled setting reaches the runtime configuration");
        assert!(!native_off.memory_provider_native_enabled);

        // A complete, valid routing document reaches it verbatim.
        let routing = MemoryProviderRecallRoutingV1 {
            active_provider: Some("native".to_owned()),
            fallback: Some(MemoryProviderRecallFallbackV1 {
                policy_id: "policy.recall.fallback".to_owned(),
                policy_revision: 3,
                target_provider: "ncm".to_owned(),
            }),
            degradation: Some(MemoryProviderRecallDegradationV1 {
                policy_id: "policy.recall.degradation".to_owned(),
                policy_revision: 4,
                allowed_causes: vec![
                    MemoryProviderRecallDegradationCauseV1::Unavailable,
                    MemoryProviderRecallDegradationCauseV1::TimedOut,
                ],
            }),
        };
        let routed = runtime_config_from_snapshot(&snapshot_with(
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
            Some(routing_text(&routing)),
        ))
        .expect("routed snapshot yields a runtime configuration");
        assert_eq!(routed.memory_provider_recall_routing, routing);
    }

    #[test]
    fn missing_memory_provider_settings_fail_the_snapshot_read() {
        for key in [
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
        ] {
            let snapshot = snapshot_with(key, None);
            assert!(
                matches!(
                    runtime_config_from_snapshot(&snapshot),
                    Err(TraceDecayError::Config { .. })
                ),
                "missing {key} must fail project open"
            );
        }
    }

    #[test]
    fn wrong_typed_memory_provider_settings_fail_the_snapshot_read() {
        let mistyped_host = snapshot_with(
            MEMORY_PROVIDER_NATIVE_ENABLED_SETTING_KEY,
            Some(ConfigurationValueV1::Text("true".to_owned())),
        );
        assert!(matches!(
            runtime_config_from_snapshot(&mistyped_host),
            Err(TraceDecayError::Config { .. })
        ));

        let mistyped_routing = snapshot_with(
            MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
            Some(ConfigurationValueV1::Boolean(true)),
        );
        assert!(matches!(
            runtime_config_from_snapshot(&mistyped_routing),
            Err(TraceDecayError::Config { .. })
        ));
    }

    #[test]
    fn malformed_recall_routing_documents_fail_the_snapshot_read() {
        for document in [
            "{",
            "\"native\"",
            "{\"active_provider\": \"native\", \"unknown\": true}",
            "{\"active_provider\": 7}",
        ] {
            let snapshot = snapshot_with(
                MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
                Some(ConfigurationValueV1::Text(document.to_owned())),
            );
            assert!(
                matches!(
                    runtime_config_from_snapshot(&snapshot),
                    Err(TraceDecayError::Config { .. })
                ),
                "malformed routing document {document} must fail project open"
            );
        }
    }

    #[test]
    fn invalid_recall_routing_gates_fail_the_snapshot_read() {
        // A well-formed document that the routing gate itself rejects: a
        // fallback without an active provider, a zero fallback revision, a
        // fallback that targets the active provider, and a blank identity.
        let fallback_without_active = MemoryProviderRecallRoutingV1 {
            active_provider: None,
            fallback: Some(MemoryProviderRecallFallbackV1 {
                policy_id: "policy.recall.fallback".to_owned(),
                policy_revision: 1,
                target_provider: "ncm".to_owned(),
            }),
            degradation: None,
        };
        let zero_revision = MemoryProviderRecallRoutingV1 {
            active_provider: Some("native".to_owned()),
            fallback: Some(MemoryProviderRecallFallbackV1 {
                policy_id: "policy.recall.fallback".to_owned(),
                policy_revision: 0,
                target_provider: "ncm".to_owned(),
            }),
            degradation: None,
        };
        let fallback_targets_active = MemoryProviderRecallRoutingV1 {
            active_provider: Some("native".to_owned()),
            fallback: Some(MemoryProviderRecallFallbackV1 {
                policy_id: "policy.recall.fallback".to_owned(),
                policy_revision: 2,
                target_provider: "native".to_owned(),
            }),
            degradation: None,
        };
        let blank_active = MemoryProviderRecallRoutingV1 {
            active_provider: Some(" ".to_owned()),
            fallback: None,
            degradation: None,
        };

        for routing in [
            fallback_without_active,
            zero_revision,
            fallback_targets_active,
            blank_active,
        ] {
            let snapshot = snapshot_with(
                MEMORY_PROVIDER_RECALL_ROUTING_SETTING_KEY,
                Some(routing_text(&routing)),
            );
            assert!(
                matches!(
                    runtime_config_from_snapshot(&snapshot),
                    Err(TraceDecayError::Config { .. })
                ),
                "invalid routing gate {routing:?} must fail project open"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use tracedecay_domain::ProjectId;
    use tracedecay_domain::configuration::{
        ConfigurationLayerIdV1, ConfigurationRevisionId, ConfigurationSnapshotV1,
        ConfigurationValueV1, INDEX_EXCLUDE_SETTING_KEY, INDEX_MAX_FILE_SIZE_SETTING_KEY,
        SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY, SettingKey,
    };
    use tracedecay_domain::errors::TraceDecayError;

    use super::{PinnedRuntimeConfiguration, RuntimeConfigurationTarget, registry, resolver};

    fn target() -> RuntimeConfigurationTarget {
        RuntimeConfigurationTarget {
            profile_root: PathBuf::from("/profile"),
            project_id: ProjectId::new("project.pinned-runtime".to_owned()).unwrap(),
            project_root: PathBuf::from("/project"),
        }
    }

    fn revision() -> ConfigurationRevisionId {
        ConfigurationRevisionId::new("configuration.revision.pinned-runtime").unwrap()
    }

    fn resolved(entries: BTreeMap<SettingKey, ConfigurationValueV1>) -> ConfigurationSnapshotV1 {
        let layers = if entries.is_empty() {
            Vec::new()
        } else {
            vec![resolver::ConfigurationLayerV1 {
                layer: ConfigurationLayerIdV1::Project {
                    project_id: target().project_id,
                },
                revision_id: revision(),
                entries,
            }]
        };
        resolver::resolve_configuration(&registry::ConfigurationRegistry::core().unwrap(), &layers)
            .unwrap()
            .snapshot
    }

    fn config_message(error: TraceDecayError) -> String {
        match error {
            TraceDecayError::Config { message } => message,
            other => panic!("expected a typed configuration error, got {other:?}"),
        }
    }

    #[test]
    fn pin_rejects_a_snapshot_missing_a_required_setting() {
        let complete = resolved(BTreeMap::new());
        let key = SettingKey::new(INDEX_MAX_FILE_SIZE_SETTING_KEY).unwrap();
        let mut values = complete.effective_values.clone();
        let mut provenance = complete.provenance.clone();
        values.remove(&key);
        provenance.remove(&key);
        let incomplete = ConfigurationSnapshotV1::new(values, provenance).unwrap();

        let message = config_message(
            PinnedRuntimeConfiguration::new(target(), revision(), incomplete).unwrap_err(),
        );
        assert!(
            message.contains(INDEX_MAX_FILE_SIZE_SETTING_KEY) && message.contains("missing"),
            "missing required settings must name the key, not default it: {message}"
        );
    }

    #[test]
    fn pin_decodes_daemon_sync_settings_and_rejects_their_absence() {
        let complete = resolved(BTreeMap::new());
        let pinned =
            PinnedRuntimeConfiguration::new(target(), revision(), complete.clone()).unwrap();
        let key = SettingKey::new(SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY).unwrap();
        assert_eq!(
            complete.effective_values.get(&key),
            Some(&ConfigurationValueV1::Unsigned(
                pinned.config().sync.watch_debounce_ms
            ))
        );

        let mut values = complete.effective_values.clone();
        let mut provenance = complete.provenance.clone();
        values.remove(&key);
        provenance.remove(&key);
        let incomplete = ConfigurationSnapshotV1::new(values, provenance).unwrap();
        let message = config_message(
            PinnedRuntimeConfiguration::new(target(), revision(), incomplete).unwrap_err(),
        );
        assert!(
            message.contains(SYNC_WATCH_DEBOUNCE_MS_SETTING_KEY) && message.contains("missing"),
            "{message}"
        );
    }

    #[test]
    fn pin_rejects_a_required_setting_with_the_wrong_type() {
        let complete = resolved(BTreeMap::new());
        let key = SettingKey::new(INDEX_MAX_FILE_SIZE_SETTING_KEY).unwrap();
        let mut values = complete.effective_values.clone();
        values.insert(key, ConfigurationValueV1::Boolean(true));
        let mistyped = ConfigurationSnapshotV1::new(values, complete.provenance.clone()).unwrap();

        let message = config_message(
            PinnedRuntimeConfiguration::new(target(), revision(), mistyped).unwrap_err(),
        );
        assert!(
            message.contains("expected unsigned"),
            "type mismatches must be reported as such: {message}"
        );
    }

    #[test]
    fn pin_skips_a_stored_index_pattern_that_no_longer_compiles() {
        // An earlier release accepted patterns it never compiled; loading
        // one must not take every tool down with the configuration.
        let key = SettingKey::new(INDEX_EXCLUDE_SETTING_KEY).unwrap();
        let stored = resolved(BTreeMap::from([(
            key,
            ConfigurationValueV1::StringList(vec!["src/[abc".to_owned(), "docs/**".to_owned()]),
        )]));

        let pinned = PinnedRuntimeConfiguration::new(target(), revision(), stored).unwrap();

        assert_eq!(pinned.config().index_paths.exclude_patterns(), ["docs/**"]);
        assert!(pinned.config().index_paths.excludes("docs/guide.md"));
        assert!(!pinned.config().index_paths.excludes("src/a"));
    }

    #[test]
    fn retargeting_shares_the_snapshot_and_keeps_the_revision() {
        let pinned =
            PinnedRuntimeConfiguration::new(target(), revision(), resolved(BTreeMap::new()))
                .unwrap();
        let snapshot_id = pinned.snapshot().snapshot_id.clone();

        let moved = pinned
            .clone()
            .with_project_root(&PathBuf::from("/elsewhere"));

        assert_eq!(moved.target().project_id, target().project_id);
        assert_eq!(moved.target().project_root, PathBuf::from("/elsewhere"));
        assert_eq!(moved.revision_id(), pinned.revision_id());
        assert_eq!(moved.snapshot().snapshot_id, snapshot_id);
        assert!(
            std::ptr::eq(moved.snapshot(), pinned.snapshot()),
            "a retargeted pin must share, not copy, its snapshot"
        );
        assert_eq!(moved.config(), pinned.config());
    }
}
