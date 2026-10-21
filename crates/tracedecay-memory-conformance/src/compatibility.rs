//! One common advisory compatibility program for real provider fixture factories.
//!
//! Factories own processes and persistent test namespaces. Calls, canonical input
//! construction, assertions and report denominators remain provider-neutral here.

mod legacy;
pub use legacy::{
    LegacyDeliveryIdentityCoverage, LegacyDurableRecordEvidence, LegacyIdentityEvidence,
};

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracedecay_memory_provider_api::contract::{
    CommittedEffectState, SourceDisposition, TemporalMode, TerminalCode, UnknownValidityPolicy,
};
use tracedecay_memory_provider_api::{
    CanonicalPayload, FallbackDirective, MemoryProvider, OwnedExactScope, OwnedTemporalQuery,
    OwnedVersionedId, ProviderOperation, ProviderReply, RecordedValidity, TemporalEligibility,
};

use crate::runner::{
    evaluate_handshake, evaluate_operation, host_control_reply, materialize_handshake,
    materialize_operation,
};
use crate::{
    ContractIdentity, ExpectedCommittedEffect, FixtureIdentity, GenerationExpectation,
    HandshakeExpectation, HandshakeFixture, OperationExpectation, OperationFixture,
    PayloadExpectation, ProductRunReport, ProductStepOutput, ProductStepResult,
    ProviderBuildIdentity, RequestControlFixture, ScenarioFixture, StepEvaluation,
    TerminalExpectation,
};

/// Stable fixed-clock observation time.
pub const T1: &str = "2025-01-01T00:00:01Z";
/// Correction boundary; old validity ends exactly here.
pub const T2: &str = "2025-01-01T00:00:02Z";
/// Ordinary revocation boundary, independent of privacy deletion.
pub const T3: &str = "2025-01-01T00:00:03Z";
/// Evaluation time after all settled lifecycle changes.
pub const T4: &str = "2025-01-01T00:00:04Z";

/// Host environment action; ordinary memory operations never enter this hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureEnvironmentAction {
    /// Stop the old process and open the same persisted namespace in a new process.
    Restart,
    /// Select an empty physical namespace under the same exact logical scope.
    FreshNamespace,
    /// Mount another exact session/coding scope through the existing host fixture.
    OpenSession {
        /// Exact destination scope; this action grants no historical source access.
        destination_scope: OwnedExactScope,
    },
    /// Install an actual older state representation, before opening the provider.
    InstallLegacyV1 {
        /// Canonical source observations the old-format writer must retain.
        observations: Vec<Value>,
    },
    /// Independently point-read retained legacy records after a real restart.
    InspectLegacyDurableState {
        /// Earlier installation whose immutable physical evidence must still match.
        installed_step: String,
    },
    /// Change stored payload bytes while leaving the stored claimed digest unchanged.
    CorruptPayloadPreservingDigest,
    /// Record the current host-authority disposition before a provider control.
    RecordSourceDisposition {
        /// Canonical source key, unchanged across delivery keys and namespaces.
        source_key: String,
        /// Canonical disposition, e.g. `deleted`.
        disposition: String,
    },
    /// Drop the next mutation's reply after its durable commit is witnessed.
    LoseNextReplyAfterCommit,
    /// Make the actual injected fixture authority unavailable/available.
    SetAdmissionAuthorityAvailable {
        /// Whether the trusted authority callback can resolve current evidence.
        available: bool,
    },
    /// Change the fixture host's configured provider mode.
    SetMode {
        /// `disabled`, `observe`, `active`, or `quarantined`.
        mode: String,
    },
    /// Shut down the owned host/provider process and join its workers.
    Shutdown,
}

/// Verifiable physical evidence returned by trusted fixture code, never the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureEnvironmentEvidence {
    /// A process restart, with old-process exit and persisted state recovery.
    Restarted {
        /// Identity including process start identity, to distinguish reused PIDs.
        previous_process: String,
        /// New process identity including start identity.
        current_process: String,
        /// The previous process exited and its owned workers were joined.
        previous_process_exited: bool,
        /// The new process opened the original persisted namespace.
        reopened_persisted_namespace: bool,
    },
    /// A fresh physical namespace; logical scope and authority stay unchanged.
    FreshNamespace {
        /// Prior physical namespace identity.
        previous_namespace: String,
        /// Empty destination physical namespace identity.
        current_namespace: String,
        /// Current dispositions were read before readiness.
        current_dispositions_revalidated: bool,
    },
    /// The existing host mounted an exact new session without changing provider selection.
    SessionOpened {
        /// Exact scope actually mounted.
        destination_scope: OwnedExactScope,
        /// Selection stayed bound to the same provider/build.
        selected_provider_unchanged: bool,
    },
    /// A genuine legacy-format writer produced populated state.
    LegacyV1Installed {
        /// Stored format version before opening/migration.
        stored_version: u64,
        /// Sources retained by the legacy writer.
        source_count: u64,
        /// Original references/receipts and actual source fields read from the v1 writer.
        records: Vec<LegacyRecordEvidence>,
    },
    /// Fresh physical reads, with no caller-only identity copied into this evidence.
    LegacyDurableState {
        /// Actual retained records and original receipt bytes.
        records: Vec<LegacyDurableRecordEvidence>,
    },
    /// Actual stored bytes changed without updating their claimed digest.
    PayloadCorrupted {
        /// Digest of the original physical payload bytes.
        before_actual_sha256: String,
        /// Digest of the corrupted physical payload bytes.
        after_actual_sha256: String,
        /// Original stored digest.
        before_claimed_sha256: String,
        /// Stored digest after corruption.
        after_claimed_sha256: String,
    },
    /// The existing canonical authority/journal durably recorded a disposition.
    SourceDispositionRecorded {
        /// Exact source requested by the suite.
        source_key: String,
        /// Exact disposition requested by the suite.
        disposition: String,
        /// Existing authority reference, independent of provider generation.
        authority_ref: String,
    },
    /// A fixture transport failpoint was armed; the next call must prove its outcome.
    LostReplyArmed,
    /// Actual injected authority lookup availability after the host action.
    AuthorityAvailability {
        /// Callback lookup availability, independent of any JSON request claim.
        available: bool,
    },
    /// The host completed a lifecycle transition.
    ModeChanged {
        /// Requested provider mode.
        mode: String,
        /// Selected-provider calls remain attributed to the same provider.
        selected_provider_unchanged: bool,
        /// Actual host admission permits selected-provider recall in this mode.
        recall_admitted: bool,
        /// Actual host admission permits observation delivery in this mode.
        observation_admitted: bool,
    },
    /// The owned process and all owned workers exited.
    Shutdown {
        /// Remaining owned processes/workers after the bounded join.
        remaining_workers: u64,
    },
}

/// Missing fixture capabilities remain explicitly unresolved in the report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureUnavailable {
    /// Concrete missing capability or failed physical action.
    pub reason: String,
}

/// Evidence read from an actual legacy writer before migration, never provider self-report.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LegacyRecordEvidence {
    /// Original provider-local public reference stored by v1.
    pub stable_memory_ref: String,
    /// Independently proved retention status of the original public operation.
    pub original_operation_id: LegacyIdentityEvidence,
    /// Independently proved retention status of the original public delivery key.
    pub original_idempotency_key: LegacyIdentityEvidence,
    /// Original committing receipt digest.
    pub original_receipt_sha256: String,
    /// SHA-256 over the declared immutable old record projection, read before migration.
    pub immutable_record_sha256: String,
    /// SHA-256 over exact original stored receipt bytes, read before migration.
    pub stored_receipt_bytes_sha256: String,
    /// Canonical SourceAttribution pointers mapped to values read before migration,
    /// including retained nulls. `origin_scope` is one atomic object; all other
    /// entries use leaf pointers. Numeric envelope versions are not source revisions.
    /// At most sixteen canonical entries and 32 KiB of serialized evidence.
    pub retained_source_fields: BTreeMap<String, Value>,
}

/// Owned real-provider test environment. No provider-name-specific request rewriting.
pub trait CommonAdvisoryFixture {
    /// The selected real provider for ordinary operation dispatch.
    fn provider(&self) -> &dyn MemoryProvider;
    /// Perform only a physical/environment action, returning substantive evidence.
    fn apply_environment(
        &mut self,
        action: &FixtureEnvironmentAction,
    ) -> Result<FixtureEnvironmentEvidence, FixtureUnavailable>;
}

/// Creates isolated environments; the common suite populates them through Observe.
pub trait CommonAdvisoryFixtureFactory {
    /// Creates one empty owned environment under the exact requested scope.
    fn create(
        &self,
        scenario: &CompatibilityScenario,
        exact_scope: &OwnedExactScope,
    ) -> Result<Box<dyn CommonAdvisoryFixture>, FixtureUnavailable>;
}

/// Dynamic binding to an earlier canonical reply; used for stable targets/snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyBinding {
    /// Earlier operation step identity.
    pub step_id: String,
    /// JSON pointer in that operation's reply payload.
    pub source_pointer: String,
    /// Existing JSON pointer in this request payload.
    pub destination_pointer: String,
}

/// A source whose full canonical attribution and admitted content must be retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSource {
    /// Canonical source attribution, including nullable revision/validity evidence.
    pub attribution: Value,
    /// Required nonempty content fragment.
    pub content: String,
    /// Independently authored provider-local validity after a correction. When
    /// absent, the complete original source validity remains the expectation.
    pub effective_validity: Option<ExpectedValidity>,
}

/// Expected local overlay, separate from immutable original-source attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedValidity {
    /// Canonical validity fields authored by the scenario, including explicit nulls.
    pub fields: Value,
    /// If supersession allocated a provider-local target, resolve this original
    /// observation's reference from an earlier positive recall in this scenario.
    pub superseding_observation_id: Option<String>,
}

/// Semantic assertions over canonical output, separate from native ranking scores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityAssertion {
    /// Exactly these nonempty sources must be returned, with their original evidence.
    RecallSources(Vec<ExpectedSource>),
    /// A populated earlier recall establishes that this absence is non-vacuous.
    RecallAbsent {
        /// Earlier positive recall step.
        populated_step: String,
    },
    /// Foreign checkout isolation permits a healthy empty recall or a typed
    /// effect-free scope refusal, after a populated original-scope witness.
    ForeignScopeIsolated {
        /// Earlier positive recall that proves the isolated source exists.
        populated_step: String,
    },
    /// Current host privacy disposition either filters or explicitly withholds
    /// a source that was independently visible before the disposition changed.
    PrivacyWithheld {
        /// Earlier populated recall before the authority-only disposition change.
        populated_step: String,
    },
    /// Unselected structured metadata must not enter emitted evidence bytes.
    ExcludesText(String),
    /// Excluding the first ranked hit must reveal the second eligible hit at limit one.
    NextEligible {
        /// Earlier two-hit recall under the same query and provider state.
        ranked_step: String,
    },
    /// A required canonical field has exactly the expected value.
    JsonEquals {
        /// JSON pointer in the payload.
        pointer: String,
        /// Expected semantic value.
        value: Value,
    },
    /// A real bounded operation must report substantive scanned/changed/removed work.
    PositiveCount {
        /// JSON pointer to a nonzero integer.
        pointer: String,
        /// Finite upper bound from the request.
        maximum: u64,
    },
    /// A canonical payload array must contain evidence, rather than an empty success.
    NonemptyArray {
        /// JSON pointer to the evidence array.
        pointer: String,
    },
    /// Expected unknown evidence must be explicit and coverage must be degraded.
    DegradedCoverage,
    /// Stable content/source targets survive a physical restart or admitted rollback.
    StableTargets {
        /// Earlier populated recall whose stable references must match.
        populated_step: String,
    },
    /// Same delivery retry preserves the original committing effect evidence.
    OriginalReceipt {
        /// Earlier committing call, or the later reconciliation for a lost reply.
        committed_step: String,
    },
    /// A lost reply was reconciled by a delivery retry naming the original operation.
    ReconcilesUnknown {
        /// Earlier call whose terminal reported an unknown effect.
        unknown_step: String,
    },
    /// A new source cannot inherit an obsolete target discarded by rollback.
    DistinctTargets {
        /// Earlier populated recall whose targets were discarded.
        discarded_step: String,
    },
    /// Every finite canonical recall budget is respected on a nonempty result.
    BoundedRecall {
        /// The exact request budget object, without provider-specific defaults.
        budgets: Value,
    },
    /// Emitted content is correctly hashed and the full original source identity is retained.
    ContentDigestAndSourceIdentity {
        /// Earlier recall carrying the complete content digest.
        populated_step: String,
    },
    /// Bounded inspection preserves the v1 writer's original references/receipts.
    LegacyReceiptPreserved {
        /// Earlier genuine v1 installation action.
        installed_step: String,
        /// Independent durable audit after this inspection's preceding restart.
        inspected_step: String,
    },
    /// The existing trace view retains original legacy content and honest attribution.
    LegacyTraceRetained {
        /// Earlier genuine v1 installation action.
        installed_step: String,
        /// Original fixture text, independently known before migration.
        content: String,
    },
    /// Retained legacy content is degraded or withheld without inventing original evidence.
    LegacyRecall {
        /// Earlier genuine v1 installation action.
        installed_step: String,
        /// Original fixture content, known independently of the provider.
        content: String,
    },
    /// Replay partitions every input and cannot disguise a new delivery as an old commit.
    ReplayAccounting {
        /// Expected newly applied source observations.
        applied: u64,
        /// Expected sources already applied under another delivery key.
        sources_already_applied: u64,
        /// Expected rejected source inputs.
        rejected: u64,
    },
}

/// A common action. Calls are ordinary fixtures evaluated by the existing runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityStep {
    /// Readiness at a lifecycle boundary. A required refusal may occur at readiness
    /// or at the first effect-free recall when integrity is checked on read.
    Readiness {
        /// Stable step identity.
        step_id: String,
        /// Complete allowed terminal set; unsupported never satisfies readiness.
        /// If success is absent, successful readiness requires a recall refusal
        /// from this same set with no payload or committed effect.
        allowed: Vec<TerminalCode>,
    },
    /// Canonical operation, optional bindings, and provider-neutral assertions.
    Call {
        /// Existing typed operation fixture.
        fixture: Box<OperationFixture>,
        /// Dynamic provider output references; never provider-name conditionals.
        bindings: Vec<ReplyBinding>,
        /// Substantive output assertions.
        assertions: Vec<CompatibilityAssertion>,
    },
    /// Physical environment action with independently checked host evidence.
    Environment {
        /// Stable action identity.
        step_id: String,
        /// Action the host fixture must implement.
        action: FixtureEnvironmentAction,
    },
}

impl CompatibilityStep {
    /// Stable step identity used in reports and dynamic bindings.
    pub fn step_id(&self) -> &str {
        match self {
            Self::Call { fixture, .. } => &fixture.step_id,
            Self::Environment { step_id, .. } => step_id,
            Self::Readiness { step_id, .. } => step_id,
        }
    }
}

/// One independently populated compatibility scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityScenario {
    /// Stable common case identity; factories may only use it for resource isolation.
    pub case_id: String,
    /// Ordered common actions.
    pub steps: Vec<CompatibilityStep>,
}

/// Explicit semantic verdict, with no unknown/degraded-to-pass conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityVerdict {
    /// Known expectations and their prerequisites were satisfied.
    Passed,
    /// Observed provider behavior violated an assertion.
    Failed,
    /// Provider exposed unknown/partial evidence where the scenario expects degradation.
    Degraded,
    /// The required environment/action/result could not be established.
    Unknown,
}

/// Deterministic result row; wall-clock timing is deliberately stored elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityResult {
    /// Scenario identity.
    pub case_id: String,
    /// Step identity.
    pub step_id: String,
    /// Explicit outcome partition.
    pub verdict: CompatibilityVerdict,
    /// Concrete unmet conditions; empty only for satisfied known assertions.
    pub details: Vec<String>,
    /// Existing report including actual canonical calls and typed terminal/effect checks.
    pub operation_report: Option<ProductRunReport>,
    /// Trusted environment evidence, if this row performed a host action.
    pub environment_evidence: Option<FixtureEnvironmentEvidence>,
}

/// Separate measurement record; never participates in semantic expected equality.
#[derive(Clone, Debug)]
pub struct CompatibilityTiming {
    /// Scenario identity.
    pub case_id: String,
    /// Step identity.
    pub step_id: String,
    /// Elapsed wall-clock time for the complete operation/environment boundary.
    pub elapsed: Duration,
}

/// Explicit denominator partition including unresolved requirements.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilityDenominators {
    /// Every planned action, including unexecuted prerequisites.
    pub planned: usize,
    /// Known successful semantic rows.
    pub passed: usize,
    /// Failed semantic rows.
    pub failed: usize,
    /// Explicitly degraded rows; never counted as passed.
    pub degraded: usize,
    /// Unavailable or blocked rows; never counted as passed.
    pub unknown: usize,
    /// Calls that exposed uncertain commit status, independently of assertion verdicts.
    pub unknown_effects: usize,
    /// Unknown effects subsequently reconciled through the same delivery identity.
    pub reconciled_effects: usize,
}

/// One unchanged suite report consumable by either real provider factory.
#[derive(Clone, Debug)]
pub struct CommonAdvisoryReport {
    /// Inputs exactly matched the complete immutable common program.
    pub common_program_matched: bool,
    /// Original delivery-identity coverage, independent of expected compatibility.
    pub legacy_delivery_identity: LegacyDeliveryIdentityCoverage,
    /// Semantic results, independent of nondeterministic timings.
    pub results: Vec<CompatibilityResult>,
    /// Complete denominator partition.
    pub denominators: CompatibilityDenominators,
    /// Required operations that reached selected provider code successfully.
    pub reached_operations: BTreeSet<String>,
    /// Required operation capabilities that never completed successfully.
    pub missing_operations: BTreeSet<String>,
    /// Wall-clock measurements outside semantic comparison.
    pub timings: Vec<CompatibilityTiming>,
}

impl CommonAdvisoryReport {
    /// Strict compatibility: no failed, missing, or unknown requirements.
    /// Expected degradation remains separately visible rather than silently passed.
    pub fn compatible(&self) -> bool {
        self.denominators.planned > 0
            && self.common_program_matched
            && self.denominators.failed == 0
            && self.denominators.unknown == 0
            && self.missing_operations.is_empty()
            && self.denominators.unknown_effects == self.denominators.reconciled_effects
            && self.denominators.planned == self.denominators.passed + self.denominators.degraded
    }
}

/// Run the complete unchanged profile against either owned real-provider factory.
pub fn run_common_advisory_suite(
    factory: &dyn CommonAdvisoryFixtureFactory,
    scope: &OwnedExactScope,
    registration_revision: u64,
) -> Result<CommonAdvisoryReport, String> {
    let scenarios = common_advisory_scenarios(scope, registration_revision)?;
    Ok(run_compatibility_program(
        factory,
        scope,
        registration_revision,
        &scenarios,
    ))
}

/// Run a focused control program. Only the exact complete common program can
/// produce a compatible report; a subset retains its explicit missing coverage.
pub fn run_compatibility_program(
    factory: &dyn CommonAdvisoryFixtureFactory,
    scope: &OwnedExactScope,
    registration_revision: u64,
    scenarios: &[CompatibilityScenario],
) -> CommonAdvisoryReport {
    let required: BTreeSet<String> = required_operations()
        .iter()
        .map(|operation| operation.as_wire().to_owned())
        .collect();
    let mut report = CommonAdvisoryReport {
        common_program_matched: common_advisory_scenarios(scope, registration_revision)
            .is_ok_and(|canonical| canonical == scenarios),
        legacy_delivery_identity: LegacyDeliveryIdentityCoverage::Unknown,
        results: Vec::new(),
        denominators: CompatibilityDenominators::default(),
        reached_operations: BTreeSet::new(),
        missing_operations: required,
        timings: Vec::new(),
    };
    let mut legacy_identity_verdicts = Vec::new();
    for scenario in scenarios {
        let mut environment = factory.create(scenario, scope);
        let mut current_scope = scope.clone();
        let mut replies = BTreeMap::<String, ProviderReply>::new();
        let mut environment_values = BTreeMap::<String, Value>::new();
        let mut blocked = environment.as_ref().err().map(|error| error.reason.clone());
        let mut identity = None;
        let mut last_generation = None;
        for step in &scenario.steps {
            let started = Instant::now();
            let mut row = CompatibilityResult {
                case_id: scenario.case_id.clone(),
                step_id: step.step_id().to_owned(),
                verdict: CompatibilityVerdict::Unknown,
                details: Vec::new(),
                operation_report: None,
                environment_evidence: None,
            };
            if let Some(reason) = &blocked {
                row.details
                    .push(format!("unresolved prerequisite: {reason}"));
            } else if let Some(reason) = match step {
                CompatibilityStep::Call { assertions, .. } => {
                    assertions.iter().find_map(|assertion| match assertion {
                        CompatibilityAssertion::LegacyReceiptPreserved {
                            installed_step,
                            inspected_step,
                        } => legacy::prerequisite(
                            &environment_values,
                            installed_step,
                            inspected_step,
                        ),
                        _ => None,
                    })
                }
                _ => None,
            } {
                row.details.push(reason);
            } else if let Ok(environment) = environment.as_mut() {
                let descriptor = environment.provider().descriptor();
                let current_identity = (
                    descriptor.provider_id.clone(),
                    descriptor.implementation_identity_sha256.clone(),
                );
                if last_generation.is_some_and(|previous| descriptor.state_generation < previous) {
                    row.verdict = CompatibilityVerdict::Failed;
                    row.details
                        .push("provider generation regressed between common actions".into());
                } else if identity
                    .as_ref()
                    .is_some_and(|previous| previous != &current_identity)
                {
                    row.verdict = CompatibilityVerdict::Failed;
                    row.details
                        .push("fixture changed selected provider/build identity".into());
                } else {
                    identity = Some(current_identity);
                    match step {
                        CompatibilityStep::Readiness { step_id, allowed } => {
                            match run_readiness(
                                environment.provider(),
                                &current_scope,
                                registration_revision,
                                step_id,
                                allowed,
                            ) {
                                Ok(operation_report) => {
                                    row.details.extend(
                                        operation_report
                                            .steps()
                                            .iter()
                                            .flat_map(|step| step.evaluation().violations())
                                            .map(|violation| {
                                                format!(
                                                    "{}: expected {}; actual {}",
                                                    violation.field,
                                                    violation.expected,
                                                    violation.actual
                                                )
                                            }),
                                    );
                                    row.verdict = if row.details.is_empty() {
                                        CompatibilityVerdict::Passed
                                    } else {
                                        CompatibilityVerdict::Failed
                                    };
                                    row.operation_report = Some(operation_report);
                                }
                                Err(error) => {
                                    row.verdict = CompatibilityVerdict::Failed;
                                    row.details.push(error);
                                }
                            }
                        }
                        CompatibilityStep::Environment { action, .. } => {
                            match environment.apply_environment(action) {
                                Ok(evidence) => {
                                    row.details = environment_errors(action, &evidence);
                                    if let (
                                        FixtureEnvironmentAction::InspectLegacyDurableState {
                                            installed_step,
                                        },
                                        FixtureEnvironmentEvidence::LegacyDurableState { records },
                                    ) = (action, &evidence)
                                    {
                                        if let Some(before) =
                                            legacy::records(&environment_values, installed_step)
                                        {
                                            row.details
                                                .extend(legacy::durable_errors(&before, records));
                                            if row.details.is_empty() {
                                                environment_values.insert(step.step_id().into(), json!({ "records": records, "verified_installation": installed_step }));
                                            }
                                        } else {
                                            row.details.push(
                                                "legacy installation baseline unavailable".into(),
                                            );
                                        }
                                    }
                                    row.verdict = if row.details.is_empty() {
                                        CompatibilityVerdict::Passed
                                    } else {
                                        CompatibilityVerdict::Failed
                                    };
                                    if let FixtureEnvironmentEvidence::LegacyV1Installed {
                                        records,
                                        ..
                                    } = &evidence
                                    {
                                        environment_values.insert(
                                            step.step_id().into(),
                                            json!({ "records": records }),
                                        );
                                    }
                                    row.environment_evidence = Some(evidence);
                                    if let FixtureEnvironmentAction::OpenSession {
                                        destination_scope,
                                    } = action
                                        && row.verdict == CompatibilityVerdict::Passed
                                    {
                                        current_scope = destination_scope.clone();
                                        last_generation = None;
                                    }
                                    if matches!(
                                        action,
                                        FixtureEnvironmentAction::FreshNamespace
                                            | FixtureEnvironmentAction::InstallLegacyV1 { .. }
                                    ) && row.verdict == CompatibilityVerdict::Passed
                                    {
                                        last_generation = None;
                                    }
                                }
                                Err(error) => row.details.push(error.reason),
                            }
                        }
                        CompatibilityStep::Call {
                            fixture,
                            bindings,
                            assertions,
                        } => {
                            match run_call(
                                environment.provider(),
                                &current_scope,
                                registration_revision,
                                fixture,
                                bindings,
                                &replies,
                                &environment_values,
                            ) {
                                Ok((operation_report, reply, contacted)) => {
                                    row.details.extend(
                                        operation_report
                                            .steps()
                                            .iter()
                                            .flat_map(|step| step.evaluation().violations())
                                            .map(|violation| {
                                                format!(
                                                    "{}: expected {}; actual {}",
                                                    violation.field,
                                                    violation.expected,
                                                    violation.actual
                                                )
                                            }),
                                    );
                                    if !contacted && !fixture.control.cancel_before_dispatch {
                                        row.details.push(
                                            "required operation did not reach provider".into(),
                                        );
                                    }
                                    if contacted
                                        && reply.terminal.terminal_code() == TerminalCode::Success
                                        && row.details.is_empty()
                                    {
                                        report
                                            .reached_operations
                                            .insert(fixture.operation.as_wire().into());
                                    }
                                    let semantic = assertion_errors_with_environment(
                                        assertions,
                                        &reply,
                                        &replies,
                                        &current_scope,
                                        &environment_values,
                                    );
                                    row.details.extend(semantic);
                                    if reply.terminal.committed_effect().state()
                                        == CommittedEffectState::Unknown
                                    {
                                        report.denominators.unknown_effects += 1;
                                    }
                                    if row.details.is_empty()
                                        && assertions.iter().any(|assertion| {
                                            matches!(
                                                assertion,
                                                CompatibilityAssertion::ReconcilesUnknown { .. }
                                            )
                                        })
                                    {
                                        report.denominators.reconciled_effects += 1;
                                    }
                                    row.verdict = if !row.details.is_empty() {
                                        CompatibilityVerdict::Failed
                                    } else if assertions.iter().any(|assertion| match assertion {
                                        CompatibilityAssertion::LegacyReceiptPreserved {
                                            installed_step,
                                            ..
                                        } => legacy::records(&environment_values, installed_step)
                                            .is_some_and(|records| {
                                                payload_value(&reply).is_ok_and(|value| {
                                                    legacy::receipt_verdict(
                                                        &records, &value, &reply,
                                                    ) == CompatibilityVerdict::Degraded
                                                })
                                            }),
                                        _ => false,
                                    }) || assertions
                                        .contains(&CompatibilityAssertion::DegradedCoverage)
                                        || assertions.iter().any(|assertion| {
                                            matches!(
                                                assertion,
                                                CompatibilityAssertion::LegacyRecall { .. }
                                            )
                                        })
                                    {
                                        CompatibilityVerdict::Degraded
                                    } else {
                                        CompatibilityVerdict::Passed
                                    };
                                    replies.insert(fixture.step_id.clone(), reply);
                                    last_generation = replies
                                        .get(&fixture.step_id)
                                        .map(|reply| reply.state_generation);
                                    row.operation_report = Some(operation_report);
                                }
                                Err(error) => {
                                    row.verdict = CompatibilityVerdict::Failed;
                                    row.details.push(error);
                                }
                            }
                        }
                    }
                }
            }
            if matches!(
                step,
                CompatibilityStep::Environment {
                    action: FixtureEnvironmentAction::InspectLegacyDurableState { .. },
                    ..
                }
            ) || matches!(step, CompatibilityStep::Call { assertions, .. } if assertions.iter().any(|assertion| matches!(assertion, CompatibilityAssertion::LegacyReceiptPreserved { .. })))
            {
                legacy_identity_verdicts.push(row.verdict);
            }
            if matches!(
                row.verdict,
                CompatibilityVerdict::Unknown | CompatibilityVerdict::Failed
            ) {
                blocked = Some(row.step_id.clone());
            }
            report.denominators.planned += 1;
            match row.verdict {
                CompatibilityVerdict::Passed => report.denominators.passed += 1,
                CompatibilityVerdict::Failed => report.denominators.failed += 1,
                CompatibilityVerdict::Degraded => report.denominators.degraded += 1,
                CompatibilityVerdict::Unknown => report.denominators.unknown += 1,
            }
            report.timings.push(CompatibilityTiming {
                case_id: scenario.case_id.clone(),
                step_id: step.step_id().to_owned(),
                elapsed: started.elapsed(),
            });
            report.results.push(row);
        }
    }
    report.legacy_delivery_identity =
        legacy::aggregate(report.common_program_matched, &legacy_identity_verdicts);
    report
        .missing_operations
        .retain(|operation| !report.reached_operations.contains(operation));
    report
}

fn required_operations() -> [ProviderOperation; 11] {
    [
        ProviderOperation::Health,
        ProviderOperation::Observe,
        ProviderOperation::Recall,
        ProviderOperation::Feedback,
        ProviderOperation::Maintenance,
        ProviderOperation::Inspection,
        ProviderOperation::Correction,
        ProviderOperation::DeleteBySource,
        ProviderOperation::SnapshotExport,
        ProviderOperation::SnapshotRestore,
        ProviderOperation::Replay,
    ]
}

fn environment_errors(
    action: &FixtureEnvironmentAction,
    evidence: &FixtureEnvironmentEvidence,
) -> Vec<String> {
    let valid = match (action, evidence) {
        (
            FixtureEnvironmentAction::Restart,
            FixtureEnvironmentEvidence::Restarted {
                previous_process,
                current_process,
                previous_process_exited,
                reopened_persisted_namespace,
            },
        ) => {
            !previous_process.is_empty()
                && !current_process.is_empty()
                && previous_process != current_process
                && *previous_process_exited
                && *reopened_persisted_namespace
        }
        (
            FixtureEnvironmentAction::FreshNamespace,
            FixtureEnvironmentEvidence::FreshNamespace {
                previous_namespace,
                current_namespace,
                current_dispositions_revalidated,
            },
        ) => {
            !previous_namespace.is_empty()
                && !current_namespace.is_empty()
                && previous_namespace != current_namespace
                && *current_dispositions_revalidated
        }
        (
            FixtureEnvironmentAction::OpenSession { destination_scope },
            FixtureEnvironmentEvidence::SessionOpened {
                destination_scope: actual,
                selected_provider_unchanged,
            },
        ) => destination_scope == actual && *selected_provider_unchanged,
        (
            FixtureEnvironmentAction::InstallLegacyV1 { observations },
            FixtureEnvironmentEvidence::LegacyV1Installed {
                stored_version,
                source_count,
                records,
            },
        ) => {
            *stored_version == 1
                && !observations.is_empty()
                && *source_count == observations.len() as u64
                && records.len() == observations.len()
                && records.len() <= 64
                && records
                    .iter()
                    .map(|record| &record.stable_memory_ref)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == records.len()
                && records.iter().all(legacy::record_valid)
        }
        (
            FixtureEnvironmentAction::InspectLegacyDurableState { .. },
            FixtureEnvironmentEvidence::LegacyDurableState { records },
        ) => {
            !records.is_empty() && records.len() <= 64 && records.iter().all(legacy::durable_valid)
        }
        (
            FixtureEnvironmentAction::CorruptPayloadPreservingDigest,
            FixtureEnvironmentEvidence::PayloadCorrupted {
                before_actual_sha256,
                after_actual_sha256,
                before_claimed_sha256,
                after_claimed_sha256,
            },
        ) => {
            crate::fixture::is_lowercase_sha256(before_actual_sha256)
                && crate::fixture::is_lowercase_sha256(after_actual_sha256)
                && before_actual_sha256 == before_claimed_sha256
                && before_claimed_sha256 == after_claimed_sha256
                && before_actual_sha256 != after_actual_sha256
        }
        (
            FixtureEnvironmentAction::RecordSourceDisposition {
                source_key,
                disposition,
            },
            FixtureEnvironmentEvidence::SourceDispositionRecorded {
                source_key: actual,
                disposition: state,
                authority_ref,
            },
        ) => source_key == actual && disposition == state && !authority_ref.is_empty(),
        (
            FixtureEnvironmentAction::LoseNextReplyAfterCommit,
            FixtureEnvironmentEvidence::LostReplyArmed,
        ) => true,
        (
            FixtureEnvironmentAction::SetAdmissionAuthorityAvailable { available },
            FixtureEnvironmentEvidence::AuthorityAvailability { available: actual },
        ) => available == actual,
        (
            FixtureEnvironmentAction::SetMode { mode },
            FixtureEnvironmentEvidence::ModeChanged {
                mode: actual,
                selected_provider_unchanged,
                recall_admitted,
                observation_admitted,
            },
        ) => {
            mode == actual
                && *selected_provider_unchanged
                && match mode.as_str() {
                    "active" => *recall_admitted && *observation_admitted,
                    "observe" => !*recall_admitted && *observation_admitted,
                    "disabled" | "quarantined" => !*recall_admitted && !*observation_admitted,
                    _ => false,
                }
        }
        (
            FixtureEnvironmentAction::Shutdown,
            FixtureEnvironmentEvidence::Shutdown { remaining_workers },
        ) => *remaining_workers == 0,
        _ => false,
    };
    if valid {
        Vec::new()
    } else {
        vec![format!(
            "physical action evidence does not establish {action:?}"
        )]
    }
}

fn run_call(
    provider: &dyn MemoryProvider,
    scope: &OwnedExactScope,
    revision: u64,
    fixture: &OperationFixture,
    bindings: &[ReplyBinding],
    replies: &BTreeMap<String, ProviderReply>,
    environment_values: &BTreeMap<String, Value>,
) -> Result<(ProductRunReport, ProviderReply, bool), String> {
    let descriptor = provider.descriptor();
    descriptor
        .validate_common_advisory_profile()
        .map_err(|error| error.to_string())?;
    let build =
        ProviderBuildIdentity::from_descriptor(&descriptor).map_err(|error| error.to_string())?;
    let identity = FixtureIdentity::new(ContractIdentity::current(), build.clone());
    let handshake = HandshakeFixture {
        step_id: format!("{}.handshake", fixture.step_id),
        request_id: format!("{}.ready", fixture.request_id),
        required_capabilities: std::iter::once(
            tracedecay_memory_provider_api::contract::COMMON_ADVISORY_PROFILE_ID,
        )
        .chain(
            tracedecay_memory_provider_api::contract::COMMON_ADVISORY_REQUIRED_CAPABILITIES
                .iter()
                .copied(),
        )
        .map(OwnedVersionedId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?,
        host_limits: descriptor.limits,
        control: RequestControlFixture::live(i64::MAX, 30_000)
            .map_err(|error| error.to_string())?,
        challenge_nonce: [0x65; 32],
        expectation: HandshakeExpectation {
            terminal_code: TerminalCode::Success,
            committed_effect: ExpectedCommittedEffect::none(),
            fallback: FallbackDirective::forbidden(),
            require_descriptor: true,
            require_accepted_scope: true,
            require_ready_receipt: true,
        },
    };
    let shell = ScenarioFixture::new(
        &fixture.step_id,
        identity.clone(),
        scope.clone(),
        revision,
        handshake.clone(),
        vec![fixture.clone()],
    )
    .map_err(|error| error.to_string())?;
    let request = materialize_handshake(&shell).map_err(|error| error.to_string())?;
    let response = provider.handshake(&request);
    let handshake_violations =
        evaluate_handshake(&handshake, &request, &response, &descriptor, &build, scope);
    if !handshake_violations.is_empty() {
        return Err(format!(
            "common-profile handshake rejected: {handshake_violations:?}"
        ));
    }
    let ready = response
        .ready_receipt_sha256
        .as_deref()
        .ok_or("missing ready receipt")?;
    let mut resolved = fixture.clone();
    let mut payload: Value =
        serde_json::from_slice(&fixture.payload.bytes).map_err(|error| error.to_string())?;
    for binding in bindings {
        let previous = if let Some(reply) = replies.get(&binding.step_id) {
            payload_value(reply)?
        } else {
            environment_values
                .get(&binding.step_id)
                .cloned()
                .ok_or_else(|| format!("binding prerequisite {} missing", binding.step_id))?
        };
        let value = previous
            .pointer(&binding.source_pointer)
            .filter(|value| !value.is_null())
            .ok_or_else(|| {
                format!(
                    "missing bound value {}{}",
                    binding.step_id, binding.source_pointer
                )
            })?;
        *payload
            .pointer_mut(&binding.destination_pointer)
            .ok_or_else(|| {
                format!(
                    "binding destination {} missing",
                    binding.destination_pointer
                )
            })? = value.clone();
    }
    bind_context(&mut payload, provider, scope, revision, ready, fixture);
    resolved.payload = payload_envelope(fixture.operation, &payload)?;
    let scenario = ScenarioFixture::new(
        &fixture.step_id,
        identity,
        scope.clone(),
        revision,
        handshake,
        vec![resolved.clone()],
    )
    .map_err(|error| error.to_string())?;
    let before = response
        .descriptor
        .as_ref()
        .map_or(descriptor.state_generation, |value| value.state_generation);
    let call = materialize_operation(&scenario, &resolved, ready, before)
        .map_err(|error| error.to_string())?;
    let (reply, contacted) = match call.control.snapshot() {
        Ok(_) => (provider.invoke(&call), true),
        Err(code) => (
            host_control_reply(&call, code, before).map_err(|error| error.to_string())?,
            false,
        ),
    };
    let mut violations = evaluate_operation(&resolved, &call, &reply, before);
    violations.extend(
        canonical_reply_errors(&resolved, &reply)
            .into_iter()
            .map(|error| {
                crate::ConformanceViolation::new(
                    &fixture.step_id,
                    "canonical_reply",
                    "valid operation-bound canonical reply",
                    error,
                )
            }),
    );
    let steps = vec![
        ProductStepResult::new(
            StepEvaluation::new(&scenario.handshake().step_id, handshake_violations),
            ProductStepOutput::Handshake(Box::new(response)),
            true,
        ),
        ProductStepResult::new(
            StepEvaluation::new(&fixture.step_id, violations),
            ProductStepOutput::Operation(Box::new(reply.clone())),
            contacted,
        ),
    ];
    Ok((
        ProductRunReport::new(
            scenario.scenario_identity(),
            scenario.planned_step_ids().map(str::to_owned).collect(),
            steps,
        ),
        reply,
        contacted,
    ))
}

fn bind_context(
    payload: &mut Value,
    provider: &dyn MemoryProvider,
    scope: &OwnedExactScope,
    revision: u64,
    ready: &str,
    fixture: &OperationFixture,
) {
    let mut context = json!({ "provider_id": provider.descriptor().provider_id.as_str(),
        "registration_revision": revision, "ready_receipt_digest": ready,
        "exact_scope_identity": scope_json(scope), "request_identity": fixture.request_id,
        "operation_id": fixture.operation_id, "idempotency_key": fixture.idempotency_key,
        "expected_state_generation": provider.descriptor().state_generation, "policy_revision": 1,
        "deadline": { "deadline_utc_micros": i64::MAX, "remaining_millis": 30_000 },
        "cancellation": "live", "extensions": [] });
    if matches!(
        fixture.operation,
        ProviderOperation::Observe | ProviderOperation::Recall
    ) {
        if let Some(context) = context.as_object_mut() {
            context.remove("operation_id");
            context.remove("expected_state_generation");
            if fixture.operation == ProviderOperation::Observe {
                context.remove("policy_revision");
            } else {
                context.remove("idempotency_key");
            }
        }
        if let (Some(payload), Some(context)) = (payload.as_object_mut(), context.as_object()) {
            payload.extend(context.clone());
        }
    } else {
        payload["common_request"] = context.clone();
        if fixture.operation == ProviderOperation::Replay {
            payload["expected_state_generation"] = context["expected_state_generation"].clone();
        }
    }
    if payload.pointer("/target/provider_id").is_some() {
        payload["target"]["provider_id"] = json!(provider.descriptor().provider_id.as_str());
    }
    if matches!(
        payload.get("correction_kind").and_then(Value::as_str),
        Some("supersede" | "replace_content")
    ) && let Some(replacement) = payload.get_mut("replacement")
    {
        bind_nested_observation(replacement, &context);
    }
    if let Some(observations) = payload
        .get_mut("resolved_observations")
        .and_then(Value::as_array_mut)
    {
        for row in observations {
            if let Some(observation) = row.get_mut("observation") {
                bind_nested_observation(observation, &context);
            }
        }
    }
}

fn bind_nested_observation(observation: &mut Value, context: &Value) {
    for field in [
        "provider_id",
        "registration_revision",
        "ready_receipt_digest",
        "exact_scope_identity",
        "deadline",
        "cancellation",
        "extensions",
    ] {
        observation[field] = context[field].clone();
    }
    let identity = observation
        .get("observation_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    observation["request_identity"] = json!(format!("fixture.canonical-source.{identity}"));
    observation["idempotency_key"] = json!(sha256(identity.as_bytes()));
}

fn payload_value(reply: &ProviderReply) -> Result<Value, String> {
    let payload = reply
        .payload
        .as_ref()
        .ok_or("canonical reply payload missing")?;
    payload.validate().map_err(|error| error.to_string())?;
    serde_json::from_slice(&payload.bytes).map_err(|error| error.to_string())
}

fn canonical_reply_errors(fixture: &OperationFixture, reply: &ProviderReply) -> Vec<String> {
    let Some(payload) = reply.payload.as_ref() else {
        return Vec::new();
    };
    if let Err(error) = payload.validate() {
        return vec![error.to_string()];
    }
    if payload.contract_id != fixture.payload.contract_id {
        return vec![format!(
            "expected payload contract {}; actual {}",
            fixture.payload.contract_id.as_str(),
            payload.contract_id.as_str()
        )];
    }
    let value: Value = match serde_json::from_slice(&payload.bytes) {
        Ok(Value::Object(value)) => Value::Object(value),
        Ok(_) => return vec!["canonical reply must be a JSON object".into()],
        Err(error) => return vec![error.to_string()],
    };
    if fixture.operation != ProviderOperation::Recall {
        return Vec::new();
    }
    let request: Value = match serde_json::from_slice(&fixture.payload.bytes) {
        Ok(value) => value,
        Err(error) => return vec![error.to_string()],
    };
    let query = match temporal_query(&request["temporal_query"]) {
        Ok(query) => query,
        Err(error) => return vec![error],
    };
    let Some(candidates) = value.get("candidates").and_then(Value::as_array) else {
        return vec!["canonical recall candidates missing".into()];
    };
    let mut errors = Vec::new();
    for candidate in candidates {
        if let Some(content) = candidate.get("content").and_then(Value::as_str)
            && candidate.get("content_sha256").and_then(Value::as_str)
                != Some(sha256(content.as_bytes()).as_str())
        {
            errors.push("candidate content digest does not hash emitted UTF-8 bytes".into());
        }
        if !candidate_temporal_claim_valid(candidate, &query) {
            errors.push(
                "candidate temporal eligibility or state is unsupported by query and validity"
                    .into(),
            );
        }
    }
    errors
}

fn temporal_query(value: &Value) -> Result<OwnedTemporalQuery, String> {
    let query = OwnedTemporalQuery {
        mode: match value.get("mode").and_then(Value::as_str) {
            Some("current") => TemporalMode::Current,
            Some("as_of") => TemporalMode::AsOf,
            Some("interval") => TemporalMode::Interval,
            Some("history") => TemporalMode::History,
            _ => return Err("invalid temporal mode".into()),
        },
        evaluation_time_utc_nanos: nullable_time(value, "evaluation_time")?
            .ok_or("evaluation time missing")?,
        as_of_utc_nanos: nullable_time(value, "as_of")?,
        interval_start_utc_nanos: nullable_time(value, "interval_start")?,
        interval_end_utc_nanos: nullable_time(value, "interval_end")?,
        include_superseded: value
            .get("include_superseded")
            .and_then(Value::as_bool)
            .ok_or("include_superseded missing")?,
        include_revoked: value
            .get("include_revoked")
            .and_then(Value::as_bool)
            .ok_or("include_revoked missing")?,
        unknown_validity_policy: match value.get("unknown_validity_policy").and_then(Value::as_str)
        {
            Some("exclude") => UnknownValidityPolicy::Exclude,
            Some("degrade") => UnknownValidityPolicy::Degrade,
            Some("allow_with_warning") => UnknownValidityPolicy::AllowWithWarning,
            _ => return Err("invalid unknown validity policy".into()),
        },
    };
    query.validate().map_err(|error| error.to_string())?;
    Ok(query)
}

fn recorded_validity(value: &Value) -> Result<RecordedValidity, String> {
    let validity = RecordedValidity {
        valid_from_utc_nanos: nullable_time(value, "valid_from")?,
        valid_until_utc_nanos: nullable_time(value, "valid_until")?,
        superseded_at_utc_nanos: nullable_time(value, "superseded_at")?,
        superseded_by: match value.get("superseded_by") {
            Some(Value::Null) => None,
            Some(Value::String(reference)) => Some(reference.clone()),
            _ => return Err("superseded_by missing or invalid".into()),
        },
        revoked_at_utc_nanos: nullable_time(value, "revoked_at")?,
    };
    validity.validate().map_err(|error| error.to_string())?;
    Ok(validity)
}

fn nullable_time(value: &Value, field: &str) -> Result<Option<i64>, String> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => utc_nanos(value)
            .map(Some)
            .ok_or_else(|| format!("invalid UTC timestamp {field}")),
        _ => Err(format!("timestamp {field} missing or invalid")),
    }
}

pub(crate) fn utc_nanos(value: &str) -> Option<i64> {
    let (seconds, nanos) = crate::scenario_corpus::utc_ordering_key(value)?;
    let year = seconds[..4].parse::<i64>().ok()?;
    let month = seconds[5..7].parse::<i64>().ok()?;
    let day = seconds[8..10].parse::<i64>().ok()?;
    // Gregorian civil date to Unix days, after the shared UTC shape validator.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let hour = seconds[11..13].parse::<i64>().ok()?;
    let minute = seconds[14..16].parse::<i64>().ok()?;
    let second = seconds[17..19].parse::<i64>().ok()?;
    (days * 86_400 + hour * 3_600 + minute * 60 + second)
        .checked_mul(1_000_000_000)?
        .checked_add(i64::from(nanos))
}

fn candidate_temporal_claim_valid(candidate: &Value, query: &OwnedTemporalQuery) -> bool {
    let Ok(validity) = recorded_validity(&candidate["validity"]) else {
        return false;
    };
    if !matches!(
        validity.eligibility(query, SourceDisposition::Available, false),
        Ok(TemporalEligibility::Eligible | TemporalEligibility::IncludedUnknown)
    ) {
        return false;
    }
    let claimed = candidate
        .pointer("/validity/temporal_state")
        .and_then(Value::as_str);
    let requested_at = query
        .as_of_utc_nanos
        .unwrap_or(query.evaluation_time_utc_nanos);
    if claimed == Some(temporal_state_at(&validity, requested_at)) {
        return true;
    }
    if query.mode != TemporalMode::Interval {
        return false;
    }
    let (Some(from), Some(until)) = (query.interval_start_utc_nanos, query.interval_end_utc_nanos)
    else {
        return false;
    };
    let first_overlap = validity
        .valid_from_utc_nanos
        .map_or(from, |start| start.max(from));
    [
        Some(first_overlap),
        validity.superseded_at_utc_nanos,
        validity.revoked_at_utc_nanos,
        validity.valid_until_utc_nanos,
    ]
    .into_iter()
    .flatten()
    .any(|at| at >= from && at < until && claimed == Some(temporal_state_at(&validity, at)))
}

fn temporal_state_at(validity: &RecordedValidity, at: i64) -> &'static str {
    if validity.valid_from_utc_nanos.is_none() {
        "unknown"
    } else if validity
        .revoked_at_utc_nanos
        .is_some_and(|event| event <= at)
    {
        "revoked"
    } else if validity
        .superseded_at_utc_nanos
        .is_some_and(|event| event <= at)
    {
        "superseded"
    } else if validity
        .valid_until_utc_nanos
        .is_some_and(|until| until <= at)
    {
        "expired"
    } else if validity.valid_from_utc_nanos.is_some_and(|from| from > at) {
        "future"
    } else {
        "current"
    }
}

fn payload_envelope(
    operation: ProviderOperation,
    value: &Value,
) -> Result<CanonicalPayload, String> {
    let contract = match operation {
        ProviderOperation::Observe => "tracedecay.memory.provider.observation.v1",
        ProviderOperation::Recall => "tracedecay.memory.provider.recall.v1",
        ProviderOperation::Health => "tracedecay.memory.provider.health.v1",
        ProviderOperation::Feedback => "tracedecay.memory.provider.feedback.v1",
        ProviderOperation::Maintenance => "tracedecay.memory.provider.maintenance.v1",
        ProviderOperation::Inspection => "tracedecay.memory.provider.inspection.v1",
        ProviderOperation::Correction => "tracedecay.memory.provider.correction.v1",
        ProviderOperation::DeleteBySource => "tracedecay.memory.provider.deletion-by-source.v1",
        ProviderOperation::SnapshotExport => "tracedecay.memory.provider.snapshot-export.v1",
        ProviderOperation::SnapshotRestore => "tracedecay.memory.provider.snapshot-restore.v1",
        ProviderOperation::Replay => "tracedecay.memory.provider.replay.v1",
        ProviderOperation::Handshake => return Err("handshake is not a payload operation".into()),
    };
    let bytes = crate::canonical_json(value).map_err(|error| error.to_string())?;
    CanonicalPayload::new(
        OwnedVersionedId::new(contract).map_err(|error| error.to_string())?,
        bytes.clone(),
        sha256(&bytes),
    )
    .map_err(|error| error.to_string())
}

fn sha256(bytes: &[u8]) -> String {
    crate::canonical::lowercase_sha256_hex(Sha256::digest(bytes).into())
}

/// Canonical exact-scope shape used by all common fixtures.
pub fn scope_json(scope: &OwnedExactScope) -> Value {
    json!({ "profile_id": scope.profile_id, "project_id": scope.project_id,
        "repository_identity": scope.repository_identity, "worktree_identity": scope.worktree_identity,
        "branch_identity": scope.branch_identity, "agent_session_id": scope.agent_session_id,
        "resolved_scope_digest": scope.resolved_scope_digest })
}

/// Evaluate only semantic assertions, reusable by adversarial control tests.
/// Earlier replies must come from this same common program and selected provider.
pub fn assertion_errors(
    assertions: &[CompatibilityAssertion],
    reply: &ProviderReply,
    previous: &BTreeMap<String, ProviderReply>,
    scope: &OwnedExactScope,
) -> Vec<String> {
    assertion_errors_with_environment(assertions, reply, previous, scope, &BTreeMap::new())
}

fn assertion_errors_with_environment(
    assertions: &[CompatibilityAssertion],
    reply: &ProviderReply,
    previous: &BTreeMap<String, ProviderReply>,
    scope: &OwnedExactScope,
    environment_values: &BTreeMap<String, Value>,
) -> Vec<String> {
    if assertions.is_empty() {
        return Vec::new();
    }
    let value = match payload_value(reply) {
        Ok(value) => value,
        Err(_)
            if reply.payload.is_none()
                && assertions.iter().all(|assertion| {
                    matches!(
                        assertion,
                        CompatibilityAssertion::PrivacyWithheld { .. }
                            | CompatibilityAssertion::ForeignScopeIsolated { .. }
                    )
                }) =>
        {
            Value::Null
        }
        Err(error) => return vec![error],
    };
    let mut errors = Vec::new();
    for assertion in assertions {
        let valid = match assertion {
            CompatibilityAssertion::RecallSources(expected) => {
                let candidates = value.get("candidates").and_then(Value::as_array);
                candidates.is_some_and(|candidates| {
                    !expected.is_empty()
                        && candidates.len() == expected.len()
                        && expected.iter().all(|source| {
                            !source.content.is_empty()
                                && candidates
                                    .iter()
                                    .filter(|candidate| {
                                        candidate_matches(candidate, source, scope, previous)
                                    })
                                    .count()
                                    == 1
                        })
                        && value
                            .pointer("/coverage/scanned_items")
                            .and_then(Value::as_u64)
                            .is_some_and(|count| count > 0)
                })
            }
            CompatibilityAssertion::RecallAbsent { populated_step } => {
                positive_reply(previous.get(populated_step))
                    && value
                        .get("candidates")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                    && matches!(
                        value.pointer("/coverage/state").and_then(Value::as_str),
                        Some("complete" | "zero_results")
                    )
            }
            CompatibilityAssertion::ForeignScopeIsolated { populated_step } => {
                let effect = reply.terminal.committed_effect();
                positive_reply(previous.get(populated_step))
                    && !foreign_scope_leaks_source(reply, previous.get(populated_step))
                    && reply.terminal.fallback() == &FallbackDirective::forbidden()
                    && effect.state() == CommittedEffectState::None
                    && match (
                        effect.state_generation_before(),
                        effect.state_generation_after(),
                    ) {
                        (Some(before), Some(after)) => before == after,
                        _ => true,
                    }
                    && ((reply.terminal.terminal_code() == TerminalCode::ScopeMismatch
                        && reply.payload.is_none()
                        && reply.extensions.is_empty())
                        || (matches!(
                            reply.terminal.terminal_code(),
                            TerminalCode::Success | TerminalCode::SuccessZeroResults
                        ) && value
                            .get("candidates")
                            .and_then(Value::as_array)
                            .is_some_and(Vec::is_empty)
                            && matches!(
                                value.pointer("/coverage/state").and_then(Value::as_str),
                                Some("complete" | "zero_results")
                            )))
            }
            CompatibilityAssertion::PrivacyWithheld { populated_step } => {
                positive_reply(previous.get(populated_step))
                    && reply.terminal.committed_effect().state() == CommittedEffectState::None
                    && ((reply.terminal.terminal_code() == TerminalCode::Unauthorized
                        && reply.payload.is_none())
                        || (matches!(
                            reply.terminal.terminal_code(),
                            TerminalCode::Success
                                | TerminalCode::SuccessZeroResults
                                | TerminalCode::Partial
                        ) && value
                            .get("candidates")
                            .and_then(Value::as_array)
                            .is_some_and(Vec::is_empty)
                            && matches!(
                                value.pointer("/coverage/state").and_then(Value::as_str),
                                Some("complete" | "zero_results" | "partial")
                            )))
            }
            CompatibilityAssertion::ExcludesText(forbidden) => {
                !forbidden.is_empty()
                    && serde_json::to_string(&value)
                        .is_ok_and(|serialized| !serialized.contains(forbidden))
            }
            CompatibilityAssertion::NextEligible { ranked_step } => {
                let prior = previous
                    .get(ranked_step)
                    .and_then(|reply| payload_value(reply).ok());
                let ranked = prior
                    .as_ref()
                    .and_then(|value| value.get("candidates"))
                    .and_then(Value::as_array);
                let now = value.get("candidates").and_then(Value::as_array);
                match (ranked, now) {
                    (Some(ranked), Some(now)) if ranked.len() >= 2 && now.len() == 1 => {
                        stable_source_key(&ranked[0]) != stable_source_key(&ranked[1])
                            && stable_source_key(&now[0]).is_some()
                            && stable_source_key(&now[0]) == stable_source_key(&ranked[1])
                    }
                    _ => false,
                }
            }
            CompatibilityAssertion::JsonEquals {
                pointer,
                value: expected,
            } => value.pointer(pointer) == Some(expected),
            CompatibilityAssertion::PositiveCount { pointer, maximum } => value
                .pointer(pointer)
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0 && count <= *maximum),
            CompatibilityAssertion::NonemptyArray { pointer } => value
                .pointer(pointer)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty()),
            CompatibilityAssertion::DegradedCoverage => {
                value.pointer("/coverage/state").and_then(Value::as_str) == Some("partial")
                    && value
                        .pointer("/coverage/reasons")
                        .and_then(Value::as_array)
                        .is_some_and(|values| !values.is_empty())
                    && (!reply.warnings.is_empty()
                        || value
                            .get("warnings")
                            .and_then(Value::as_array)
                            .is_some_and(|values| !values.is_empty())
                        || value
                            .get("candidates")
                            .and_then(Value::as_array)
                            .is_some_and(|candidates| {
                                candidates.iter().any(|candidate| {
                                    candidate
                                        .get("warnings")
                                        .and_then(Value::as_array)
                                        .is_some_and(|values| !values.is_empty())
                                })
                            }))
            }
            CompatibilityAssertion::StableTargets { populated_step } => {
                let previous = previous
                    .get(populated_step)
                    .and_then(|reply| payload_value(reply).ok());
                let old = previous.as_ref().and_then(stable_targets);
                let new = stable_targets(&value);
                old.is_some() && old == new
            }
            CompatibilityAssertion::OriginalReceipt { committed_step } => {
                previous.get(committed_step).is_some_and(|original| {
                    let first = original.terminal.committed_effect();
                    let retry = reply.terminal.committed_effect();
                    if reply.terminal.operation() == ProviderOperation::Inspection {
                        return first.state() == CommittedEffectState::Committed
                            && first.provider_receipt_sha256().is_some()
                            && value
                                .pointer("/items/0/provider_receipt_digest")
                                .and_then(Value::as_str)
                                == first.provider_receipt_sha256()
                            && value
                                .pointer("/items/0/operation_id")
                                .and_then(Value::as_str)
                                == Some(original.terminal.operation_id())
                            && value
                                .pointer("/items/0/stable_memory_ref")
                                .and_then(Value::as_str)
                                .is_some_and(|reference| !reference.is_empty());
                    }
                    first.state() == CommittedEffectState::Committed
                        && retry.state() == CommittedEffectState::Duplicate
                        && first.provider_receipt_sha256().is_some()
                        && first.provider_receipt_sha256() == retry.provider_receipt_sha256()
                        && retry.duplicate_of_operation_id()
                            == Some(original.terminal.operation_id())
                })
            }
            CompatibilityAssertion::ReconcilesUnknown { unknown_step } => {
                previous.get(unknown_step).is_some_and(|unknown| {
                    let retry = reply.terminal.committed_effect();
                    unknown.terminal.committed_effect().state() == CommittedEffectState::Unknown
                        && retry.state() == CommittedEffectState::Duplicate
                        && retry.provider_receipt_sha256().is_some()
                        && retry.duplicate_of_operation_id()
                            == Some(unknown.terminal.operation_id())
                })
            }
            CompatibilityAssertion::DistinctTargets { discarded_step } => {
                let old = previous
                    .get(discarded_step)
                    .and_then(|reply| payload_value(reply).ok())
                    .and_then(|value| stable_targets(&value));
                let new = stable_targets(&value);
                match (old, new) {
                    (Some(old), Some(new)) => new
                        .values()
                        .all(|target| !old.values().any(|old| old == target)),
                    _ => false,
                }
            }
            CompatibilityAssertion::BoundedRecall { budgets } => bounded_recall(&value, budgets),
            CompatibilityAssertion::ContentDigestAndSourceIdentity { populated_step } => {
                let original = previous
                    .get(populated_step)
                    .and_then(|reply| payload_value(reply).ok());
                let current_source =
                    value.pointer("/candidates/0/provenance/original_sources/0/source");
                let retained = original
                    .as_ref()
                    .and_then(|value| value.get("candidates"))
                    .and_then(Value::as_array);
                let emitted = value
                    .pointer("/candidates/0/content")
                    .and_then(Value::as_str);
                current_source.is_some()
                    && retained.is_some_and(|candidates| {
                        candidates.iter().any(|candidate| {
                            candidate.pointer("/provenance/original_sources/0/source")
                                == current_source
                        })
                    })
                    && emitted.is_some_and(|content| {
                        value
                            .pointer("/candidates/0/content_sha256")
                            .and_then(Value::as_str)
                            == Some(sha256(content.as_bytes()).as_str())
                    })
            }
            CompatibilityAssertion::LegacyReceiptPreserved {
                installed_step,
                inspected_step,
            } => {
                legacy::prerequisite(environment_values, installed_step, inspected_step).is_none()
                    && legacy::records(environment_values, installed_step).is_some_and(|records| {
                        matches!(
                            legacy::receipt_verdict(&records, &value, reply),
                            CompatibilityVerdict::Passed | CompatibilityVerdict::Degraded
                        )
                    })
            }
            CompatibilityAssertion::LegacyTraceRetained {
                installed_step,
                content,
            } => environment_values
                .get(installed_step)
                .and_then(|value| value.pointer("/records/0"))
                .is_some_and(|record| {
                    value.pointer("/items/0").is_some_and(|item| {
                        item.get("stable_memory_ref") == record.get("stable_memory_ref")
                            && item
                                .get("content")
                                .and_then(Value::as_str)
                                .is_some_and(|actual| {
                                    !content.is_empty()
                                        && actual.contains(content)
                                        && item.get("content_sha256").and_then(Value::as_str)
                                            == Some(sha256(actual.as_bytes()).as_str())
                                })
                            && legacy_attribution_honest(item.get("original_source"), record)
                    })
                }),
            CompatibilityAssertion::LegacyRecall {
                installed_step,
                content,
            } => {
                let record = environment_values
                    .get(installed_step)
                    .and_then(|value| value.pointer("/records/0"));
                record.is_some_and(|record| {
                    value
                        .get("candidates")
                        .and_then(Value::as_array)
                        .is_some_and(|candidates| {
                            candidates.iter().all(|candidate| {
                                let fields = record["retained_source_fields"].as_object();
                                candidate.get("stable_memory_ref")
                                    == record.get("stable_memory_ref")
                                    && candidate
                                        .get("content")
                                        .and_then(Value::as_str)
                                        .is_some_and(|actual| actual.contains(content))
                                    && legacy_attribution_honest(
                                        candidate.pointer("/provenance/original_sources/0"),
                                        record,
                                    )
                                    && fields.is_some_and(|fields| {
                                        candidate.pointer("/validity/source_revision")
                                            == Some(
                                                fields
                                                    .get("/source/source_revision")
                                                    .unwrap_or(&Value::Null),
                                            )
                                            && [
                                                "valid_from",
                                                "valid_until",
                                                "superseded_at",
                                                "superseded_by",
                                                "revoked_at",
                                            ]
                                            .into_iter()
                                            .all(
                                                |field| {
                                                    candidate["validity"].get(field)
                                                        == Some(
                                                            fields
                                                                .get(&format!("/validity/{field}"))
                                                                .unwrap_or(&Value::Null),
                                                        )
                                                },
                                            )
                                    })
                            }) && value.pointer("/coverage/state").and_then(Value::as_str)
                                == Some("partial")
                                && value
                                    .pointer("/coverage/reasons")
                                    .and_then(Value::as_array)
                                    .is_some_and(|values| !values.is_empty())
                        })
                })
            }
            CompatibilityAssertion::ReplayAccounting {
                applied,
                sources_already_applied,
                rejected,
            } => {
                let get = |name: &str| value.get(name).and_then(Value::as_u64);
                let counters = [
                    get("applied_observations"),
                    get("duplicate_observations"),
                    get("sources_already_applied"),
                    get("rejected_observations"),
                    get("effect_unknown_observations"),
                ];
                let total = counters
                    .into_iter()
                    .try_fold(0_u64, |sum, value| sum.checked_add(value?));
                total
                    == applied
                        .checked_add(*sources_already_applied)
                        .and_then(|n| n.checked_add(*rejected))
                    && get("applied_observations") == Some(*applied)
                    && get("sources_already_applied") == Some(*sources_already_applied)
                    && get("rejected_observations") == Some(*rejected)
                    && get("duplicate_observations") == Some(0)
                    && get("effect_unknown_observations") == Some(0)
                    && (*sources_already_applied == 0
                        || reply.terminal.committed_effect().state()
                            != CommittedEffectState::Duplicate)
            }
        };
        if !valid {
            errors.push(format!("semantic assertion unsatisfied: {assertion:?}"));
        }
    }
    errors
}

fn candidate_matches(
    candidate: &Value,
    expected: &ExpectedSource,
    scope: &OwnedExactScope,
    previous: &BTreeMap<String, ProviderReply>,
) -> bool {
    let mut candidate_scope = scope_json(scope);
    candidate_scope["scope_binding"] = json!("exact_coding_scope");
    candidate
        .get("content")
        .and_then(Value::as_str)
        .is_some_and(|content| content.contains(&expected.content))
        && candidate.get("exact_scope_identity") == Some(&candidate_scope)
        && candidate
            .pointer("/provenance/original_sources")
            .and_then(Value::as_array)
            .is_some_and(|sources| {
                sources.as_slice() == std::slice::from_ref(&expected.attribution)
            })
        && candidate.pointer("/validity/source_revision")
            == expected.attribution.pointer("/source/source_revision")
        && candidate_validity_matches(candidate, expected, previous)
        && candidate
            .get("stable_memory_ref")
            .and_then(Value::as_str)
            .is_some_and(|reference| !reference.is_empty())
}

fn candidate_validity_matches(
    candidate: &Value,
    expected: &ExpectedSource,
    previous: &BTreeMap<String, ProviderReply>,
) -> bool {
    let fields = expected
        .effective_validity
        .as_ref()
        .map_or(&expected.attribution["validity"], |validity| {
            &validity.fields
        });
    for field in ["valid_from", "valid_until", "superseded_at", "revoked_at"] {
        if fields.get(field).is_none() || candidate["validity"].get(field) != fields.get(field) {
            return false;
        }
    }
    let superseding = expected
        .effective_validity
        .as_ref()
        .and_then(|validity| validity.superseding_observation_id.as_deref());
    let Some(superseding) = superseding else {
        return fields.get("superseded_by").is_some()
            && candidate.pointer("/validity/superseded_by") == fields.get("superseded_by");
    };
    previous
        .values()
        .filter_map(|reply| payload_value(reply).ok())
        .any(|value| {
            value
                .get("candidates")
                .and_then(Value::as_array)
                .is_some_and(|candidates| {
                    candidates.iter().any(|witness| {
                        witness
                            .pointer("/provenance/original_sources/0/source/observation_id")
                            .and_then(Value::as_str)
                            == Some(superseding)
                            && witness
                                .get("stable_memory_ref")
                                .and_then(Value::as_str)
                                .is_some_and(|reference| !reference.is_empty())
                            && candidate.pointer("/validity/superseded_by")
                                == witness.get("stable_memory_ref")
                    })
                })
        })
}

fn positive_reply(reply: Option<&ProviderReply>) -> bool {
    reply
        .and_then(|reply| payload_value(reply).ok())
        .and_then(|value| value.get("candidates").and_then(Value::as_array).cloned())
        .is_some_and(|candidates| !candidates.is_empty())
}

fn stable_source_key(candidate: &Value) -> Option<&Value> {
    candidate.pointer("/provenance/original_sources/0/source")
}

fn stable_targets(value: &Value) -> Option<BTreeMap<String, String>> {
    let candidates = value.get("candidates")?.as_array()?;
    if candidates.is_empty() {
        return None;
    }
    let mut targets = BTreeMap::new();
    for candidate in candidates {
        let key = candidate
            .pointer("/provenance/original_sources/0/source/observation_id")?
            .as_str()?;
        let stable = candidate.get("stable_memory_ref")?.as_str()?;
        if stable.is_empty() || targets.insert(key.into(), stable.into()).is_some() {
            return None;
        }
    }
    Some(targets)
}

/// Canonical committed message fixture preserving independent origin and delivery identity.
pub fn common_observation(
    scope: &OwnedExactScope,
    sequence: u64,
    revision: Option<&str>,
    content: &str,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
) -> Value {
    let observation_id = format!("019467f0-0000-7000-8000-{sequence:012x}");
    let source_key = format!("common-advisory/source/{sequence}");
    let canonical = json!({ "session_id": scope.agent_session_id, "message_id": observation_id,
        "role": "user", "content": content });
    let canonical_sha256 = crate::canonical_json_sha256(&canonical).ok();
    let source = json!({ "canonical_provider_id": "codex", "canonical_session_id": scope.agent_session_id,
        "source_key": source_key, "stable_record_id": null, "observation_id": observation_id,
        "source_revision": revision, "content_sha256": canonical_sha256 });
    let original = json!({ "source": source, "origin_scope": {
            "state": "recorded", "exact_scope_identity": scope_json(scope),
            "authority_ref": "fixture.host.original-observation" },
        "source_sequence": sequence, "occurred_at": T1, "ingested_at": T4,
        "validity": { "valid_from": valid_from, "valid_until": valid_until,
            "superseded_at": null, "superseded_by": null, "revoked_at": null } });
    json!({ "observation_id": observation_id,
        "observation_kind": "session.message_committed.v1",
        "payload_contract": "tracedecay.memory.observation.session-message.v1",
        "canonical_payload": canonical, "payload_sha256": canonical_sha256,
        "source_identity": { "source_authority": "host_session", "source_event_id": observation_id,
            "source_event_revision": 99, "source_event_sha256": sha256(content.as_bytes()),
            "canonical_settlement_receipt": "fixture.host.settled-message", "original_source": original },
        "provenance": { "source_refs": [source_key], "observation_refs": [observation_id] },
        "privacy": { "classification": "internal", "redaction_policy_revision": 1 },
        "occurred_at": T1, "admitted_at": T4, "source_sequence": sequence })
}

fn expected_source(observation: &Value) -> ExpectedSource {
    ExpectedSource {
        attribution: observation["source_identity"]["original_source"].clone(),
        content: observation["canonical_payload"]["content"]
            .as_str()
            .unwrap_or_default()
            .into(),
        effective_validity: None,
    }
}

/// Complete temporal request; caller supplies only the fixed canonical mode/bounds.
pub fn common_recall(mode: &str, at: &str, until: Option<&str>) -> Value {
    json!({ "objective": "Recover the recorded compatibility beacon.", "query": "compatibility beacon",
        "temporal_query": { "mode": mode, "evaluation_time": if mode == "current" { at } else { T4 },
            "as_of": if mode == "as_of" { Some(at) } else { None },
            "interval_start": if mode == "interval" { Some(at) } else { None },
            "interval_end": until, "include_superseded": false, "include_revoked": false,
            "unknown_validity_policy": "exclude" },
        "budgets": { "maximum_candidates": 16, "maximum_candidate_content_bytes": 8192,
            "maximum_total_content_bytes": 65536, "maximum_source_refs_per_candidate": 64,
            "maximum_trace_refs_per_candidate": 64, "maximum_warnings": 64,
            "maximum_extensions_per_candidate": 16 },
        "exclusions": { "stable_memory_refs": [], "candidate_ids": [], "source_refs": [],
            "trace_refs": [], "observation_ids": [], "content_sha256": [] },
        "required_capabilities": ["recall.query.v1", "recall.temporal.v1"], "policy_revision": 1 })
}

fn call_step(
    id: &str,
    operation: ProviderOperation,
    payload: Value,
    assertions: Vec<CompatibilityAssertion>,
) -> Result<CompatibilityStep, String> {
    let mutation = operation.mutates_provider_state();
    Ok(CompatibilityStep::Call {
        fixture: Box::new(OperationFixture {
            step_id: id.into(),
            operation,
            request_id: format!("{id}.request"),
            operation_id: operation_uuid(id),
            idempotency_key: mutation.then(|| sha256(id.as_bytes())),
            payload: payload_envelope(operation, &payload)?,
            required_capabilities: if operation == ProviderOperation::Recall {
                payload
                    .get("required_capabilities")
                    .and_then(Value::as_array)
                    .ok_or("canonical Recall required_capabilities missing")?
                    .iter()
                    .map(|capability| {
                        OwnedVersionedId::new(
                            capability
                                .as_str()
                                .ok_or("canonical Recall capability must be a versioned ID")?,
                        )
                        .map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                vec![
                    OwnedVersionedId::new(operation.capability_id())
                        .map_err(|error| error.to_string())?,
                ]
            },
            extensions: Vec::new(),
            control: RequestControlFixture::live(i64::MAX, 30_000)
                .map_err(|error| error.to_string())?,
            expectation: OperationExpectation {
                terminal: TerminalExpectation::exactly(TerminalCode::Success),
                committed_effect: if mutation {
                    ExpectedCommittedEffect::committed()
                } else {
                    ExpectedCommittedEffect::none()
                },
                fallback: FallbackDirective::forbidden(),
                state_generation: if mutation {
                    GenerationExpectation::Increased
                } else {
                    GenerationExpectation::Unchanged
                },
                payload: PayloadExpectation::Present,
            },
        }),
        bindings: Vec::new(),
        assertions,
    })
}

fn environment_step(id: &str, action: FixtureEnvironmentAction) -> CompatibilityStep {
    CompatibilityStep::Environment {
        step_id: id.into(),
        action,
    }
}

fn expect_absence(step: &mut CompatibilityStep) -> Result<(), String> {
    if let CompatibilityStep::Call { fixture, .. } = step {
        fixture.expectation.terminal =
            TerminalExpectation::one_of([TerminalCode::Success, TerminalCode::SuccessZeroResults])
                .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn refusal(step: &mut CompatibilityStep, codes: &[TerminalCode]) -> Result<(), String> {
    if let CompatibilityStep::Call { fixture, .. } = step {
        fixture.expectation.terminal = TerminalExpectation::one_of(codes.iter().copied())
            .map_err(|error| error.to_string())?;
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
        fixture.expectation.payload = PayloadExpectation::Absent;
    }
    Ok(())
}

/// The unchanged common profile program. No factory may remove or rewrite its cases.
pub fn common_advisory_scenarios(
    scope: &OwnedExactScope,
    registration_revision: u64,
) -> Result<Vec<CompatibilityScenario>, String> {
    Ok(vec![
        exclusions_scenario(scope)?,
        budgets_scenario(scope)?,
        structured_sources_scenario(scope)?,
        source_authority_scenario(scope)?,
        temporal_scenario(scope)?,
        unknown_evidence_scenario(scope)?,
        lifecycle_scenario(scope, registration_revision)?,
        stable_rollback_scenario(scope, registration_revision)?,
        deletion_restore_scenario(scope, false)?,
        deletion_restore_scenario(scope, true)?,
        delete_before_observe_scenario(scope)?,
        cancellation_scenario(scope)?,
        migration_scenario(scope)?,
        corrupt_state_scenario(scope)?,
        modes_scenario(scope)?,
    ])
}

fn exclusions_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let first = common_observation(
        scope,
        1,
        Some("cache_policy_r2"),
        "compatibility beacon primary: cache uses explicit invalidation",
        Some(T1),
        None,
    );
    let second = common_observation(
        scope,
        2,
        Some("opaque_revision_alpha"),
        "compatibility beacon secondary: invalidation uses source revision",
        Some(T1),
        None,
    );
    let mut steps = vec![
        call_step(
            "exclusions.observe_a",
            ProviderOperation::Observe,
            first.clone(),
            vec![],
        )?,
        call_step(
            "exclusions.observe_b",
            ProviderOperation::Observe,
            second.clone(),
            vec![],
        )?,
    ];
    let mut ranked = common_recall("current", T4, None);
    ranked["budgets"]["maximum_candidates"] = json!(2);
    steps.push(call_step(
        "exclusions.ranked",
        ProviderOperation::Recall,
        ranked.clone(),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&first),
            expected_source(&second),
        ])],
    )?);
    for (field, source_pointer) in [
        ("stable_memory_refs", "/candidates/0/stable_memory_ref"),
        ("candidate_ids", "/candidates/0/candidate_id"),
        ("source_refs", "/candidates/0/source_refs/0"),
        ("trace_refs", "/candidates/0/trace_refs/0"),
        (
            "observation_ids",
            "/candidates/0/provenance/observation_refs/0",
        ),
        ("content_sha256", "/candidates/0/content_sha256"),
    ] {
        let mut query = ranked.clone();
        query["budgets"]["maximum_candidates"] = json!(1);
        query["exclusions"][field] = json!([null]);
        let mut step = call_step(
            &format!("exclusions.{field}"),
            ProviderOperation::Recall,
            query,
            vec![CompatibilityAssertion::NextEligible {
                ranked_step: "exclusions.ranked".into(),
            }],
        )?;
        if let CompatibilityStep::Call {
            fixture, bindings, ..
        } = &mut step
        {
            // Candidate IDs are request scoped; preserve the request identity while testing
            // its exclusion, rather than incorrectly requiring cross-request candidate IDs.
            if field == "candidate_ids" {
                fixture.request_id = "exclusions.ranked.request".into();
            }
            bindings.push(ReplyBinding {
                step_id: "exclusions.ranked".into(),
                source_pointer: source_pointer.into(),
                destination_pointer: format!("/exclusions/{field}/0"),
            });
        }
        steps.push(step);
    }
    steps.push(call_step(
        "exclusions.after",
        ProviderOperation::Recall,
        ranked,
        vec![
            CompatibilityAssertion::RecallSources(vec![
                expected_source(&first),
                expected_source(&second),
            ]),
            CompatibilityAssertion::StableTargets {
                populated_step: "exclusions.ranked".into(),
            },
        ],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.exclusions.all_classes".into(),
        steps,
    })
}

fn temporal_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let first = common_observation(
        scope,
        1,
        Some("validity_start_r1"),
        "compatibility beacon t1 interval",
        Some(T1),
        Some(T2),
    );
    let mut second = common_observation(
        scope,
        2,
        Some("validity_start_r2"),
        "compatibility beacon t2 interval",
        Some(T2),
        None,
    );
    second["source_identity"]["original_source"]["validity"]["revoked_at"] = json!(T3);
    let future = common_observation(
        scope,
        3,
        Some("future_revision"),
        "compatibility beacon future interval",
        Some("2025-01-01T00:00:05Z"),
        None,
    );
    let mut steps = vec![
        call_step(
            "temporal.observe_t1",
            ProviderOperation::Observe,
            first.clone(),
            vec![],
        )?,
        call_step(
            "temporal.observe_t2",
            ProviderOperation::Observe,
            second.clone(),
            vec![],
        )?,
        call_step(
            "temporal.observe_future",
            ProviderOperation::Observe,
            future,
            vec![],
        )?,
    ];
    let mut all = common_recall("history", T4, None);
    all["temporal_query"]["include_revoked"] = json!(true);
    steps.push(call_step(
        "temporal.populated",
        ProviderOperation::Recall,
        all,
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&first),
            expected_source(&second),
        ])],
    )?);
    for mode in ["current", "as_of"] {
        for (label, at, expected) in [
            ("start", T1, Some(&first)),
            (
                "end_minus_one_ns",
                "2025-01-01T00:00:01.999999999Z",
                Some(&first),
            ),
            ("exact_correction", T2, Some(&second)),
            (
                "revoke_minus_one_ns",
                "2025-01-01T00:00:02.999999999Z",
                Some(&second),
            ),
            ("exact_revoke", T3, None),
        ] {
            let assertions = expected.map_or_else(
                || {
                    vec![CompatibilityAssertion::RecallAbsent {
                        populated_step: "temporal.populated".into(),
                    }]
                },
                |observation| {
                    vec![CompatibilityAssertion::RecallSources(vec![
                        expected_source(observation),
                    ])]
                },
            );
            let mut step = call_step(
                &format!("temporal.{mode}.{label}"),
                ProviderOperation::Recall,
                common_recall(mode, at, None),
                assertions,
            )?;
            if expected.is_none() {
                expect_absence(&mut step)?;
            }
            steps.push(step);
        }
    }
    for (label, start, end, expected) in [
        ("first", T1, T2, Some(&first)),
        ("second", T2, T3, Some(&second)),
        ("end_boundary", T3, T4, None),
    ] {
        let assertions = expected.map_or_else(
            || {
                vec![CompatibilityAssertion::RecallAbsent {
                    populated_step: "temporal.populated".into(),
                }]
            },
            |observation| {
                vec![CompatibilityAssertion::RecallSources(vec![
                    expected_source(observation),
                ])]
            },
        );
        let mut step = call_step(
            &format!("temporal.interval.{label}"),
            ProviderOperation::Recall,
            common_recall("interval", start, Some(end)),
            assertions,
        )?;
        if expected.is_none() {
            expect_absence(&mut step)?;
        }
        steps.push(step);
    }
    steps.push(call_step(
        "temporal.history.expired_retained",
        ProviderOperation::Recall,
        common_recall("history", T4, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&first),
        ])],
    )?);
    let mut explicit_end = common_recall("as_of", T2, None);
    explicit_end["temporal_query"]["include_revoked"] = json!(true);
    explicit_end["temporal_query"]["include_superseded"] = json!(true);
    steps.push(call_step(
        "temporal.explicit_end_always_exclusive",
        ProviderOperation::Recall,
        explicit_end,
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&second),
        ])],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.temporal.all_modes_end_boundaries".into(),
        steps,
    })
}

fn unknown_evidence_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let revision_unknown = common_observation(
        scope,
        1,
        None,
        "compatibility beacon known validity unknown revision",
        Some(T1),
        None,
    );
    let validity_unknown = common_observation(
        scope,
        2,
        Some("real_opaque_revision"),
        "compatibility beacon unknown validity known revision",
        None,
        None,
    );
    let mut steps = vec![
        call_step(
            "unknown.observe_revision",
            ProviderOperation::Observe,
            revision_unknown.clone(),
            vec![],
        )?,
        call_step(
            "unknown.observe_validity",
            ProviderOperation::Observe,
            validity_unknown.clone(),
            vec![],
        )?,
    ];
    for mode in ["current", "as_of", "interval", "history"] {
        for policy in ["exclude", "degrade", "allow_with_warning"] {
            let mut query = common_recall(mode, T2, (mode == "interval").then_some(T3));
            query["temporal_query"]["unknown_validity_policy"] = json!(policy);
            let expected = if policy == "exclude" {
                vec![expected_source(&revision_unknown)]
            } else {
                vec![
                    expected_source(&revision_unknown),
                    expected_source(&validity_unknown),
                ]
            };
            let mut step = call_step(
                &format!("unknown.{mode}.{policy}"),
                ProviderOperation::Recall,
                query,
                vec![
                    CompatibilityAssertion::RecallSources(expected),
                    CompatibilityAssertion::DegradedCoverage,
                ],
            )?;
            if let CompatibilityStep::Call { fixture, .. } = &mut step {
                fixture.expectation.terminal =
                    TerminalExpectation::one_of([TerminalCode::Success, TerminalCode::Partial])
                        .map_err(|error| error.to_string())?;
            }
            steps.push(step);
        }
    }
    Ok(CompatibilityScenario {
        case_id: "common.unknown_revision_and_validity_are_independent".into(),
        steps,
    })
}

fn target(scope: &OwnedExactScope, revision: u64, observation: &Value) -> Value {
    json!({ "provider_id": null, "registration_revision": revision,
        "original_scope": observation["source_identity"]["original_source"]["origin_scope"],
        "delivery_scope": scope_json(scope), "source": observation["source_identity"]["original_source"]["source"],
        "reference": { "kind": "stable_memory_ref", "reference": null } })
}

fn bind_target(step: &mut CompatibilityStep, recalled_step: &str) {
    if let CompatibilityStep::Call { bindings, .. } = step {
        bindings.push(ReplyBinding {
            step_id: recalled_step.into(),
            source_pointer: "/candidates/0/stable_memory_ref".into(),
            destination_pointer: "/target/reference/reference".into(),
        });
    }
}

fn feedback(scope: &OwnedExactScope, revision: u64, observation: &Value) -> Value {
    json!({ "target": target(scope, revision, observation), "signal": "helpful", "weight": "1",
        "canonical_outcome_receipt": "fixture.host.settled-helpful-outcome", "evidence_refs": ["fixture.test.passed"],
        "occurred_at": T2 })
}

fn source_influence(source_key: &Value) -> Value {
    json!({ "view": "source_influence", "selector": { "source_key": source_key },
        "maximum_items": 64, "maximum_bytes": 65536, "redaction_policy_revision": 1, "cursor": null })
}

fn lifecycle_scenario(
    scope: &OwnedExactScope,
    revision: u64,
) -> Result<CompatibilityScenario, String> {
    let first = common_observation(
        scope,
        1,
        Some("cache_policy_r2"),
        "compatibility beacon old setting use cache",
        Some(T1),
        None,
    );
    let replacement = common_observation(
        scope,
        2,
        Some("cache_policy_r3"),
        "compatibility beacon corrected setting invalidate cache",
        Some(T2),
        None,
    );
    let mut superseded = expected_source(&first);
    let mut superseded_fields = first["source_identity"]["original_source"]["validity"].clone();
    superseded_fields["superseded_at"] = json!(T2);
    superseded.effective_validity = Some(ExpectedValidity {
        fields: superseded_fields,
        superseding_observation_id: replacement
            .get("observation_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    });
    let mut revoked = expected_source(&replacement);
    let mut revoked_fields = replacement["source_identity"]["original_source"]["validity"].clone();
    revoked_fields["revoked_at"] = json!(T3);
    revoked.effective_validity = Some(ExpectedValidity {
        fields: revoked_fields,
        superseding_observation_id: None,
    });
    let mut steps = vec![
        call_step(
            "lifecycle.observe",
            ProviderOperation::Observe,
            first.clone(),
            vec![],
        )?,
        call_step(
            "lifecycle.health",
            ProviderOperation::Health,
            json!({ "requested_checks": ["protocol", "state", "scope", "persistence", "privacy"] }),
            vec![CompatibilityAssertion::JsonEquals {
                pointer: "/readiness".into(),
                value: json!("ready"),
            }],
        )?,
        call_step(
            "lifecycle.before",
            ProviderOperation::Recall,
            common_recall("current", T1, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&first),
            ])],
        )?,
    ];
    let mut helpful = call_step(
        "lifecycle.feedback",
        ProviderOperation::Feedback,
        feedback(scope, revision, &first),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/signal".into(),
            value: json!("helpful"),
        }],
    )?;
    bind_target(&mut helpful, "lifecycle.before");
    steps.push(helpful);
    let inspect =
        source_influence(&first["source_identity"]["original_source"]["source"]["source_key"]);
    steps.push(call_step(
        "lifecycle.inspect_feedback",
        ProviderOperation::Inspection,
        inspect.clone(),
        vec![
            CompatibilityAssertion::NonemptyArray {
                pointer: "/items".into(),
            },
            CompatibilityAssertion::JsonEquals {
                pointer: "/items/0/settled_feedback/helpful".into(),
                value: json!(1),
            },
        ],
    )?);
    steps.push(environment_step(
        "lifecycle.restart",
        FixtureEnvironmentAction::Restart,
    ));
    steps.push(call_step(
        "lifecycle.after_restart",
        ProviderOperation::Recall,
        common_recall("current", T1, None),
        vec![
            CompatibilityAssertion::RecallSources(vec![expected_source(&first)]),
            CompatibilityAssertion::StableTargets {
                populated_step: "lifecycle.before".into(),
            },
        ],
    )?);
    let mut duplicate_feedback = call_step(
        "lifecycle.feedback_retry",
        ProviderOperation::Feedback,
        feedback(scope, revision, &first),
        vec![CompatibilityAssertion::OriginalReceipt {
            committed_step: "lifecycle.feedback".into(),
        }],
    )?;
    bind_target(&mut duplicate_feedback, "lifecycle.before");
    make_duplicate(&mut duplicate_feedback, "lifecycle.feedback");
    steps.push(duplicate_feedback);
    steps.push(call_step(
        "lifecycle.inspect_restart",
        ProviderOperation::Inspection,
        inspect,
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/items/0/settled_feedback/helpful".into(),
            value: json!(1),
        }],
    )?);
    let mut harmful_payload = feedback(scope, revision, &first);
    harmful_payload["signal"] = json!("harmful");
    harmful_payload["canonical_outcome_receipt"] = json!("fixture.host.settled-harmful-outcome");
    let mut harmful = call_step(
        "lifecycle.feedback_harmful",
        ProviderOperation::Feedback,
        harmful_payload,
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/signal".into(),
            value: json!("harmful"),
        }],
    )?;
    bind_target(&mut harmful, "lifecycle.before");
    steps.push(harmful);
    let mut suppressed = call_step(
        "lifecycle.feedback_suppresses_contribution",
        ProviderOperation::Recall,
        common_recall("current", T1, None),
        vec![CompatibilityAssertion::RecallAbsent {
            populated_step: "lifecycle.before".into(),
        }],
    )?;
    expect_absence(&mut suppressed)?;
    steps.push(suppressed);
    steps.push(call_step(
        "lifecycle.harmful_inspectable",
        ProviderOperation::Inspection,
        source_influence(&first["source_identity"]["original_source"]["source"]["source_key"]),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/items/0/settled_feedback/harmful".into(),
            value: json!(1),
        }],
    )?);
    let mut recovery_payload = feedback(scope, revision, &first);
    recovery_payload["canonical_outcome_receipt"] = json!("fixture.host.settled-helpful-recovery");
    let mut recover = call_step(
        "lifecycle.feedback_helpful_recovery",
        ProviderOperation::Feedback,
        recovery_payload,
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/signal".into(),
            value: json!("helpful"),
        }],
    )?;
    bind_target(&mut recover, "lifecycle.before");
    steps.push(recover);
    steps.push(call_step(
        "lifecycle.feedback_recovers_contribution",
        ProviderOperation::Recall,
        common_recall("current", T1, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&first),
        ])],
    )?);
    let correction = json!({ "target": target(scope, revision, &first), "correction_kind": "supersede",
        "replacement": replacement, "expected_target_revision": "cache_policy_r2",
        "reason": "Settled source correction at t2", "evidence_refs": ["fixture.host.replacement-settled"] });
    let mut stale = correction.clone();
    stale["expected_target_revision"] = json!("99");
    let mut stale_step = call_step(
        "lifecycle.envelope_version_is_not_revision",
        ProviderOperation::Correction,
        stale,
        vec![],
    )?;
    bind_target(&mut stale_step, "lifecycle.before");
    refusal(&mut stale_step, &[TerminalCode::Conflict])?;
    steps.push(stale_step);
    let mut correct = call_step(
        "lifecycle.correct_t2",
        ProviderOperation::Correction,
        correction,
        vec![CompatibilityAssertion::PositiveCount {
            pointer: "/affected_provider_effects".into(),
            maximum: 64,
        }],
    )?;
    bind_target(&mut correct, "lifecycle.before");
    steps.push(correct);
    for (mode, at, until, expected) in [
        ("current", T2, None, expected_source(&replacement)),
        ("as_of", T1, None, superseded.clone()),
        ("interval", T1, Some(T2), superseded.clone()),
    ] {
        steps.push(call_step(
            &format!("lifecycle.corrected.{mode}"),
            ProviderOperation::Recall,
            common_recall(mode, at, until),
            vec![CompatibilityAssertion::RecallSources(vec![expected])],
        )?);
    }
    let mut history = common_recall("history", T4, None);
    history["temporal_query"]["include_superseded"] = json!(true);
    steps.push(call_step(
        "lifecycle.corrected.history",
        ProviderOperation::Recall,
        history,
        vec![CompatibilityAssertion::RecallSources(vec![
            superseded,
            expected_source(&replacement),
        ])],
    )?);
    let mut revoke = call_step(
        "lifecycle.revoke_t3",
        ProviderOperation::Correction,
        json!({ "target": target(scope, revision, &replacement), "correction_kind": "mark_incorrect",
            "replacement": { "revoked_at": T3 }, "expected_target_revision": "cache_policy_r3",
            "reason": "Provider-local ordinary revocation at t3", "evidence_refs": ["fixture.host.revocation"] }),
        vec![CompatibilityAssertion::PositiveCount {
            pointer: "/affected_provider_effects".into(),
            maximum: 64,
        }],
    )?;
    bind_target(&mut revoke, "lifecycle.corrected.current");
    steps.push(revoke);
    for (mode, at, until, expected) in [
        ("current", T3, None, None),
        ("as_of", T2, None, Some(&replacement)),
        ("interval", T2, Some(T3), Some(&replacement)),
        ("history", T4, None, None),
    ] {
        let assertions = expected.map_or_else(
            || {
                vec![CompatibilityAssertion::RecallAbsent {
                    populated_step: "lifecycle.corrected.current".into(),
                }]
            },
            |_| vec![CompatibilityAssertion::RecallSources(vec![revoked.clone()])],
        );
        let mut recall = call_step(
            &format!("lifecycle.revoked.{mode}"),
            ProviderOperation::Recall,
            common_recall(mode, at, until),
            assertions,
        )?;
        if expected.is_none() {
            expect_absence(&mut recall)?;
        }
        steps.push(recall);
    }
    // Validation scans populated retained state and reports actual bounded work.
    let mut maintenance = call_step(
        "lifecycle.maintenance",
        ProviderOperation::Maintenance,
        json!({ "task": "validate_state", "maximum_items": 64, "maximum_bytes": 65536,
            "maximum_duration_millis": 1000, "dry_run": true }),
        vec![
            CompatibilityAssertion::PositiveCount {
                pointer: "/scanned_items".into(),
                maximum: 64,
            },
            CompatibilityAssertion::JsonEquals {
                pointer: "/dry_run".into(),
                value: json!(true),
            },
        ],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut maintenance {
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
    steps.push(maintenance);
    Ok(CompatibilityScenario {
        case_id: "common.feedback_correction_revocation_restart".into(),
        steps,
    })
}

fn operation_uuid(step_id: &str) -> String {
    let digest = sha256(step_id.as_bytes());
    format!(
        "019467f0-0000-7{}-8{}-{}",
        &digest[..3],
        &digest[3..6],
        &digest[6..18]
    )
}

fn make_duplicate(step: &mut CompatibilityStep, original_step: &str) {
    if let CompatibilityStep::Call { fixture, .. } = step {
        let key = sha256(original_step.as_bytes());
        fixture.idempotency_key = Some(key.clone());
        fixture.expectation.committed_effect = ExpectedCommittedEffect::duplicate(
            crate::OptionalTextExpectation::Exact(key),
            crate::OptionalTextExpectation::Exact(operation_uuid(original_step)),
        );
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
}

fn checkpoint(scope: &OwnedExactScope) -> Value {
    json!({ "exact_scope": scope_json(scope), "authority_ref": "fixture.host.current-disposition-checkpoint",
        "authority_revision": 1, "checked_at": T4 })
}

fn disposition(state: &str) -> Value {
    json!({ "state": state, "authority_ref": "fixture.host.current-source-disposition",
        "authority_revision": 1, "checked_at": T4 })
}

fn history_grant(scope: &OwnedExactScope, observations: &[(&Value, SourceDisposition)]) -> Value {
    json!({ "authorization_ref": "fixture.host.admitted-history", "policy_revision": 1,
        "destination_scope": scope_json(scope), "relation": "exact_scope",
        "sources": observations.iter().map(|(observation, state)| json!({
            "attribution": observation["source_identity"]["original_source"],
            "current_disposition": disposition(state.as_wire()) })).collect::<Vec<_>>(),
        "disposition_checkpoint": checkpoint(scope) })
}

fn replay(scope: &OwnedExactScope, observations: &[(&Value, SourceDisposition)]) -> Value {
    let resolved: Vec<Value> = observations.iter().map(|(observation, _)| json!({
        "receipt_ref": format!("fixture.host.observation-receipt.{}", observation["source_sequence"]),
        "observation": observation })).collect();
    json!({ "observation_batch_refs": resolved.iter().map(|row| row["receipt_ref"].clone()).collect::<Vec<_>>(),
        "resolved_observations": resolved, "first_source_sequence": observations.first().map(|(value, _)| value["source_sequence"].clone()),
        "last_source_sequence": observations.last().map(|(value, _)| value["source_sequence"].clone()),
        "expected_previous_acknowledged_sequence": 0, "expected_state_generation": 0,
        "history_grant": history_grant(scope, observations) })
}

fn deletion(observation: &Value) -> Value {
    json!({ "forget_source_keys": [observation["source_identity"]["original_source"]["source"]["source_key"]],
        "mode": "hard_delete", "include_snapshots": true, "retention_lock_policy_revision": 1,
        "verification_query": "compatibility beacon" })
}

fn delete_and_verify(
    id: &str,
    observation: &Value,
    populated: bool,
) -> Result<CompatibilityStep, String> {
    let mut assertions = vec![
        CompatibilityAssertion::JsonEquals {
            pointer: "/postcondition/remaining_influence_count".into(),
            value: json!(0),
        },
        CompatibilityAssertion::JsonEquals {
            pointer: "/postcondition/verification_state".into(),
            value: json!("verified_absent"),
        },
    ];
    if populated {
        assertions.push(CompatibilityAssertion::PositiveCount {
            pointer: "/postcondition/removed_effects".into(),
            maximum: 64,
        });
    }
    call_step(
        id,
        ProviderOperation::DeleteBySource,
        deletion(observation),
        assertions,
    )
}

fn deletion_restore_scenario(
    scope: &OwnedExactScope,
    fresh: bool,
) -> Result<CompatibilityScenario, String> {
    let label = if fresh { "fresh" } else { "current" };
    let first = common_observation(
        scope,
        1,
        Some("fenced_r1"),
        "compatibility beacon must remain deleted after rollback",
        Some(T1),
        None,
    );
    let replay_only = common_observation(
        scope,
        2,
        Some("replay_r1"),
        "compatibility beacon canonical replay positive control",
        Some(T1),
        None,
    );
    let prefix = format!("restore.{label}");
    let before = format!("{prefix}.before");
    let exported = format!("{prefix}.export");
    let mut steps = vec![
        call_step(
            &format!("{prefix}.observe"),
            ProviderOperation::Observe,
            first.clone(),
            vec![],
        )?,
        call_step(
            &before,
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&first),
            ])],
        )?,
        call_step(
            &exported,
            ProviderOperation::SnapshotExport,
            json!({}),
            vec![
                CompatibilityAssertion::NonemptyArray {
                    pointer: "/snapshot/bytes".into(),
                },
                CompatibilityAssertion::NonemptyArray {
                    pointer: "/snapshot/sources".into(),
                },
            ],
        )?,
        environment_step(
            &format!("{prefix}.host_delete"),
            FixtureEnvironmentAction::RecordSourceDisposition {
                source_key: first["source_identity"]["original_source"]["source"]["source_key"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                disposition: "deleted".into(),
            },
        ),
        delete_and_verify(&format!("{prefix}.delete"), &first, true)?,
    ];
    if fresh {
        steps.push(environment_step(
            &format!("{prefix}.fresh_namespace"),
            FixtureEnvironmentAction::FreshNamespace,
        ));
    }
    let mut restore = call_step(
        &format!("{prefix}.restore"),
        ProviderOperation::SnapshotRestore,
        json!({ "snapshot": null, "disposition_checkpoint": checkpoint(scope), "source_dispositions": [
            { "source": first["source_identity"]["original_source"]["source"], "current_disposition": disposition("deleted") } ] }),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/restored_observation_sequence".into(),
            value: json!(1),
        }],
    )?;
    if let CompatibilityStep::Call { bindings, .. } = &mut restore {
        bindings.push(ReplyBinding {
            step_id: exported,
            source_pointer: "/snapshot".into(),
            destination_pointer: "/snapshot".into(),
        });
    }
    steps.push(restore);
    append_privacy_absence(&mut steps, &prefix, &before)?;
    let mut rejected = call_step(
        &format!("{prefix}.fresh_delivery_observe"),
        ProviderOperation::Observe,
        first.clone(),
        vec![],
    )?;
    refusal(
        &mut rejected,
        &[TerminalCode::Unauthorized, TerminalCode::Conflict],
    )?;
    steps.push(rejected);
    let mut replay_deleted = call_step(
        &format!("{prefix}.fresh_delivery_replay"),
        ProviderOperation::Replay,
        replay(scope, &[(&first, SourceDisposition::Deleted)]),
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 0,
            sources_already_applied: 0,
            rejected: 1,
        }],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut replay_deleted {
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
    steps.push(replay_deleted);
    steps.push(call_step(
        &format!("{prefix}.replay_positive"),
        ProviderOperation::Replay,
        replay(
            scope,
            &[
                (&first, SourceDisposition::Deleted),
                (&replay_only, SourceDisposition::Available),
            ],
        ),
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 1,
            sources_already_applied: 0,
            rejected: 1,
        }],
    )?);
    steps.push(call_step(
        &format!("{prefix}.replay_visible"),
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&replay_only),
        ])],
    )?);
    let mut already_applied = call_step(
        &format!("{prefix}.new_key_same_source"),
        ProviderOperation::Replay,
        replay(
            scope,
            &[
                (&first, SourceDisposition::Deleted),
                (&replay_only, SourceDisposition::Available),
            ],
        ),
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 0,
            sources_already_applied: 1,
            rejected: 1,
        }],
    )?;
    if let CompatibilityStep::Call {
        fixture, bindings, ..
    } = &mut already_applied
    {
        bindings.push(ReplyBinding {
            step_id: format!("{prefix}.replay_positive"),
            source_pointer: "/acknowledged_sequence".into(),
            destination_pointer: "/expected_previous_acknowledged_sequence".into(),
        });
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
    steps.push(already_applied);
    let committed_step = format!("{prefix}.replay_positive");
    steps.push(call_step(&format!("{prefix}.original_delivery_receipt"), ProviderOperation::Inspection,
        json!({ "view": "delivery_receipt", "selector": { "idempotency_key": sha256(committed_step.as_bytes()) },
            "maximum_items": 16, "maximum_bytes": 65536, "redaction_policy_revision": 1, "cursor": null }),
        vec![CompatibilityAssertion::OriginalReceipt { committed_step: committed_step.clone() },
            CompatibilityAssertion::JsonEquals { pointer: "/items/0/idempotency_key".into(), value: json!(sha256(committed_step.as_bytes())) }])?);
    Ok(CompatibilityScenario {
        case_id: format!("common.delete_snapshot_{label}_namespace_replay_fence"),
        steps,
    })
}

fn append_privacy_absence(
    steps: &mut Vec<CompatibilityStep>,
    prefix: &str,
    before: &str,
) -> Result<(), String> {
    for mode in ["current", "as_of", "interval", "history"] {
        let mut recall = common_recall(mode, T1, (mode == "interval").then_some(T4));
        recall["temporal_query"]["include_revoked"] = json!(true);
        recall["temporal_query"]["include_superseded"] = json!(true);
        let mut absent = call_step(
            &format!("{prefix}.privacy.{mode}"),
            ProviderOperation::Recall,
            recall,
            vec![CompatibilityAssertion::RecallAbsent {
                populated_step: before.into(),
            }],
        )?;
        expect_absence(&mut absent)?;
        steps.push(absent);
    }
    Ok(())
}

fn delete_before_observe_scenario(
    scope: &OwnedExactScope,
) -> Result<CompatibilityScenario, String> {
    let positive = common_observation(
        scope,
        1,
        Some("guard_r1"),
        "compatibility beacon retained positive control",
        Some(T1),
        None,
    );
    let forbidden = common_observation(
        scope,
        2,
        Some("predeleted_r1"),
        "compatibility beacon must never appear after preemptive delete",
        Some(T1),
        None,
    );
    let mut steps = vec![
        call_step(
            "predelete.observe_control",
            ProviderOperation::Observe,
            positive.clone(),
            vec![],
        )?,
        call_step(
            "predelete.before",
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&positive),
            ])],
        )?,
        environment_step(
            "predelete.host_fence",
            FixtureEnvironmentAction::RecordSourceDisposition {
                source_key: forbidden["source_identity"]["original_source"]["source"]["source_key"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                disposition: "deleted".into(),
            },
        ),
        delete_and_verify("predelete.delete", &forbidden, false)?,
    ];
    let mut observe = call_step(
        "predelete.observe_after_delete",
        ProviderOperation::Observe,
        forbidden.clone(),
        vec![],
    )?;
    refusal(
        &mut observe,
        &[TerminalCode::Unauthorized, TerminalCode::Conflict],
    )?;
    steps.push(observe);
    steps.push(environment_step(
        "predelete.restart",
        FixtureEnvironmentAction::Restart,
    ));
    let mut replay_step = call_step(
        "predelete.replay_after_restart",
        ProviderOperation::Replay,
        replay(
            scope,
            &[
                (&positive, SourceDisposition::Available),
                (&forbidden, SourceDisposition::Deleted),
            ],
        ),
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 0,
            sources_already_applied: 1,
            rejected: 1,
        }],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut replay_step {
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
    steps.push(replay_step);
    steps.push(call_step(
        "predelete.control_survives",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&positive),
        ])],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.delete_before_observe_and_fresh_key".into(),
        steps,
    })
}

fn run_readiness(
    provider: &dyn MemoryProvider,
    scope: &OwnedExactScope,
    revision: u64,
    step_id: &str,
    allowed: &[TerminalCode],
) -> Result<ProductRunReport, String> {
    if allowed.is_empty() || allowed.contains(&TerminalCode::CapabilityUnsupported) {
        return Err("readiness requires an explicit supported terminal set".into());
    }
    let descriptor = provider.descriptor();
    descriptor
        .validate_common_advisory_profile()
        .map_err(|error| error.to_string())?;
    let build =
        ProviderBuildIdentity::from_descriptor(&descriptor).map_err(|error| error.to_string())?;
    let required =
        std::iter::once(tracedecay_memory_provider_api::contract::COMMON_ADVISORY_PROFILE_ID)
            .chain(
                tracedecay_memory_provider_api::contract::COMMON_ADVISORY_REQUIRED_CAPABILITIES
                    .iter()
                    .copied(),
            )
            .map(OwnedVersionedId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
    let mut handshake = HandshakeFixture {
        step_id: step_id.into(),
        request_id: format!("{step_id}.ready"),
        required_capabilities: required,
        host_limits: descriptor.limits,
        control: RequestControlFixture::live(i64::MAX, 30_000)
            .map_err(|error| error.to_string())?,
        challenge_nonce: [0x73; 32],
        expectation: HandshakeExpectation {
            terminal_code: allowed[0],
            committed_effect: ExpectedCommittedEffect::none(),
            fallback: FallbackDirective::forbidden(),
            require_descriptor: false,
            require_accepted_scope: false,
            require_ready_receipt: false,
        },
    };
    let identity = FixtureIdentity::new(ContractIdentity::current(), build.clone());
    let mut scenario = ScenarioFixture::new(
        step_id,
        identity.clone(),
        scope.clone(),
        revision,
        handshake.clone(),
        vec![],
    )
    .map_err(|error| error.to_string())?;
    let request = materialize_handshake(&scenario).map_err(|error| error.to_string())?;
    let response = provider.handshake(&request);
    let require_read_refusal = response.terminal.terminal_code() == TerminalCode::Success
        && !allowed.contains(&TerminalCode::Success);
    if allowed.contains(&response.terminal.terminal_code()) || require_read_refusal {
        handshake.expectation.terminal_code = response.terminal.terminal_code();
    }
    if handshake.expectation.terminal_code == TerminalCode::Success {
        handshake.expectation.require_descriptor = true;
        handshake.expectation.require_accepted_scope = true;
        handshake.expectation.require_ready_receipt = true;
    }
    let violations =
        evaluate_handshake(&handshake, &request, &response, &descriptor, &build, scope);
    let mut operations = Vec::new();
    let mut operation_result = None;
    if require_read_refusal && violations.is_empty() {
        let mut read = call_step(
            &format!("{step_id}.read"),
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![],
        )?;
        refusal(&mut read, allowed)?;
        let CompatibilityStep::Call { mut fixture, .. } = read else {
            return Err("integrity read did not produce an operation fixture".into());
        };
        let ready = response
            .ready_receipt_sha256
            .as_deref()
            .ok_or("integrity read requires a ready receipt")?;
        let mut payload: Value =
            serde_json::from_slice(&fixture.payload.bytes).map_err(|error| error.to_string())?;
        bind_context(&mut payload, provider, scope, revision, ready, &fixture);
        fixture.payload = payload_envelope(ProviderOperation::Recall, &payload)?;
        let read_scenario = ScenarioFixture::new(
            step_id,
            identity.clone(),
            scope.clone(),
            revision,
            handshake.clone(),
            vec![(*fixture).clone()],
        )
        .map_err(|error| error.to_string())?;
        let before = response
            .descriptor
            .as_ref()
            .map_or(descriptor.state_generation, |value| value.state_generation);
        let call = materialize_operation(&read_scenario, &fixture, ready, before)
            .map_err(|error| error.to_string())?;
        let reply = provider.invoke(&call);
        let violations = evaluate_operation(&fixture, &call, &reply, before);
        operation_result = Some(ProductStepResult::new(
            StepEvaluation::new(&fixture.step_id, violations),
            ProductStepOutput::Operation(Box::new(reply)),
            true,
        ));
        operations.push(*fixture);
    }
    scenario = ScenarioFixture::new(
        step_id,
        identity,
        scope.clone(),
        revision,
        handshake,
        operations,
    )
    .map_err(|error| error.to_string())?;
    let mut steps = vec![ProductStepResult::new(
        StepEvaluation::new(step_id, violations),
        ProductStepOutput::Handshake(Box::new(response)),
        true,
    )];
    steps.extend(operation_result);
    Ok(ProductRunReport::new(
        scenario.scenario_identity(),
        scenario.planned_step_ids().map(str::to_owned).collect(),
        steps,
    ))
}

fn cancellation_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let positive = common_observation(
        scope,
        1,
        Some("cancel_control"),
        "compatibility beacon already durable before cancellation",
        Some(T1),
        None,
    );
    let cancelled = common_observation(
        scope,
        2,
        Some("cancelled_source"),
        "compatibility beacon canceled before dispatch",
        Some(T1),
        None,
    );
    let lost = common_observation(
        scope,
        3,
        Some("lost_reply_source"),
        "compatibility beacon durable despite lost reply",
        Some(T1),
        None,
    );
    let mut steps = vec![
        call_step(
            "cancel.observe_control",
            ProviderOperation::Observe,
            positive.clone(),
            vec![],
        )?,
        call_step(
            "cancel.populated",
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&positive),
            ])],
        )?,
    ];
    let mut before_dispatch = call_step(
        "cancel.before_dispatch",
        ProviderOperation::Observe,
        cancelled,
        vec![],
    )?;
    refusal(&mut before_dispatch, &[TerminalCode::Cancelled])?;
    if let CompatibilityStep::Call { fixture, .. } = &mut before_dispatch {
        fixture.control = RequestControlFixture::cancelled(i64::MAX, 30_000);
    }
    steps.push(before_dispatch);
    steps.push(call_step(
        "cancel.unchanged_after_predispatch",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&positive),
        ])],
    )?);
    steps.push(environment_step(
        "cancel.arm_lost_reply",
        FixtureEnvironmentAction::LoseNextReplyAfterCommit,
    ));
    let mut after_commit = call_step(
        "cancel.lost_reply",
        ProviderOperation::Observe,
        lost.clone(),
        vec![],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut after_commit {
        fixture.expectation.terminal = TerminalExpectation::exactly(TerminalCode::EffectUnknown);
        fixture.expectation.committed_effect = ExpectedCommittedEffect::unknown();
        fixture.expectation.state_generation = GenerationExpectation::Any;
        fixture.expectation.payload = PayloadExpectation::Absent;
    }
    steps.push(after_commit);
    steps.push(environment_step(
        "cancel.restart_after_lost_reply",
        FixtureEnvironmentAction::Restart,
    ));
    let mut reconcile = call_step(
        "cancel.reconcile",
        ProviderOperation::Observe,
        lost.clone(),
        vec![CompatibilityAssertion::ReconcilesUnknown {
            unknown_step: "cancel.lost_reply".into(),
        }],
    )?;
    make_duplicate(&mut reconcile, "cancel.lost_reply");
    steps.push(reconcile);
    steps.push(call_step(
        "cancel.committed_source_visible",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&positive),
            expected_source(&lost),
        ])],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.cancel_predispatch_vs_lost_reply_after_commit".into(),
        steps,
    })
}

fn migration_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let content = "compatibility beacon retained by genuine v1 storage";
    let observation = common_observation(scope, 1, None, content, None, None);
    let mut receipt = call_step(
        "migration.original_receipt",
        ProviderOperation::Inspection,
        json!({ "view": "delivery_receipt", "selector": { "idempotency_key": null },
            "maximum_items": 16, "maximum_bytes": 65536, "redaction_policy_revision": 1, "cursor": null }),
        vec![CompatibilityAssertion::LegacyReceiptPreserved {
            installed_step: "migration.install_v1".into(),
            inspected_step: "migration.audit_durable_state".into(),
        }],
    )?;
    if let CompatibilityStep::Call {
        fixture, bindings, ..
    } = &mut receipt
    {
        fixture.expectation.terminal =
            TerminalExpectation::one_of([TerminalCode::Success, TerminalCode::Partial])
                .map_err(|error| error.to_string())?;
        bindings.push(ReplyBinding {
            step_id: "migration.install_v1".into(),
            source_pointer: "/records/0/original_idempotency_key/value".into(),
            destination_pointer: "/selector/idempotency_key".into(),
        });
    }
    let mut trace = call_step(
        "migration.retained_content",
        ProviderOperation::Inspection,
        json!({ "view": "trace", "selector": { "stable_memory_ref": null },
            "maximum_items": 16, "maximum_bytes": 65536, "redaction_policy_revision": 1, "cursor": null }),
        vec![CompatibilityAssertion::LegacyTraceRetained {
            installed_step: "migration.install_v1".into(),
            content: content.into(),
        }],
    )?;
    if let CompatibilityStep::Call { bindings, .. } = &mut trace {
        bindings.push(ReplyBinding {
            step_id: "migration.install_v1".into(),
            source_pointer: "/records/0/stable_memory_ref".into(),
            destination_pointer: "/selector/stable_memory_ref".into(),
        });
    }
    let mut query = common_recall("current", T4, None);
    query["temporal_query"]["unknown_validity_policy"] = json!("degrade");
    let mut recalled = call_step(
        "migration.honest_unknown_evidence",
        ProviderOperation::Recall,
        query,
        vec![CompatibilityAssertion::LegacyRecall {
            installed_step: "migration.install_v1".into(),
            content: content.into(),
        }],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut recalled {
        fixture.expectation.terminal =
            TerminalExpectation::one_of([TerminalCode::Success, TerminalCode::Partial])
                .map_err(|error| error.to_string())?;
    }
    let mut again = receipt.clone();
    if let CompatibilityStep::Call {
        fixture,
        assertions,
        ..
    } = &mut again
    {
        for assertion in assertions {
            if let CompatibilityAssertion::LegacyReceiptPreserved { inspected_step, .. } = assertion
            {
                *inspected_step = "migration.audit_durable_state_again".into();
            }
        }
        fixture.step_id = "migration.original_receipt_after_second_restart".into();
        fixture.request_id = "migration.original_receipt_after_second_restart.request".into();
        fixture.operation_id = operation_uuid(&fixture.step_id);
    }
    let mut destination = scope.clone();
    destination.agent_session_id = "legacy-unrelated-session".into();
    let mut cross_session = call_step(
        "migration.cross_session_withheld",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/candidates".into(),
            value: json!([]),
        }],
    )?;
    expect_absence(&mut cross_session)?;
    Ok(CompatibilityScenario {
        case_id: "common.real_v1_migration".into(),
        steps: vec![
            environment_step(
                "migration.install_v1",
                FixtureEnvironmentAction::InstallLegacyV1 {
                    observations: vec![observation],
                },
            ),
            environment_step("migration.restart", FixtureEnvironmentAction::Restart),
            environment_step(
                "migration.audit_durable_state",
                FixtureEnvironmentAction::InspectLegacyDurableState {
                    installed_step: "migration.install_v1".into(),
                },
            ),
            receipt,
            trace,
            recalled,
            environment_step("migration.restart_again", FixtureEnvironmentAction::Restart),
            environment_step(
                "migration.audit_durable_state_again",
                FixtureEnvironmentAction::InspectLegacyDurableState {
                    installed_step: "migration.install_v1".into(),
                },
            ),
            again,
            environment_step(
                "migration.open_other_session",
                FixtureEnvironmentAction::OpenSession {
                    destination_scope: destination,
                },
            ),
            cross_session,
        ],
    })
}

fn corrupt_state_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let observation = common_observation(
        scope,
        1,
        Some("corrupt_control_revision"),
        "compatibility beacon integrity-protected payload",
        Some(T1),
        None,
    );
    Ok(CompatibilityScenario {
        case_id: "common.corruption_unchanged_claimed_digest".into(),
        steps: vec![
            call_step(
                "corrupt.observe",
                ProviderOperation::Observe,
                observation.clone(),
                vec![],
            )?,
            call_step(
                "corrupt.before",
                ProviderOperation::Recall,
                common_recall("current", T4, None),
                vec![CompatibilityAssertion::RecallSources(vec![
                    expected_source(&observation),
                ])],
            )?,
            environment_step(
                "corrupt.change_only_bytes",
                FixtureEnvironmentAction::CorruptPayloadPreservingDigest,
            ),
            environment_step("corrupt.restart", FixtureEnvironmentAction::Restart),
            CompatibilityStep::Readiness {
                step_id: "corrupt.refuses_ready".into(),
                allowed: vec![
                    TerminalCode::StateIncompatible,
                    TerminalCode::ResetRequired,
                    TerminalCode::ProviderUnavailable,
                ],
            },
        ],
    })
}

fn modes_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let observation = common_observation(
        scope,
        1,
        Some("lifecycle_mode_r1"),
        "compatibility beacon retained across mode changes",
        Some(T1),
        None,
    );
    let mut steps = vec![
        call_step(
            "modes.observe",
            ProviderOperation::Observe,
            observation.clone(),
            vec![],
        )?,
        call_step(
            "modes.before",
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&observation),
            ])],
        )?,
    ];
    for mode in ["disabled", "observe", "active", "quarantined", "active"] {
        steps.push(environment_step(
            &format!("modes.{mode}.{}", steps.len()),
            FixtureEnvironmentAction::SetMode { mode: mode.into() },
        ));
    }
    steps.push(call_step(
        "modes.after",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![
            CompatibilityAssertion::RecallSources(vec![expected_source(&observation)]),
            CompatibilityAssertion::StableTargets {
                populated_step: "modes.before".into(),
            },
        ],
    )?);
    steps.push(environment_step(
        "modes.shutdown",
        FixtureEnvironmentAction::Shutdown,
    ));
    Ok(CompatibilityScenario {
        case_id: "common.lifecycle_modes_shutdown".into(),
        steps,
    })
}

fn bounded_recall(value: &Value, budgets: &Value) -> bool {
    let limit = |field: &str| budgets.get(field).and_then(Value::as_u64);
    let Some(candidates) = value.get("candidates").and_then(Value::as_array) else {
        return false;
    };
    if candidates.is_empty()
        || limit("maximum_candidates").is_none_or(|limit| candidates.len() as u64 > limit)
    {
        return false;
    }
    let mut total = 0_u64;
    for candidate in candidates {
        let Some(content) = candidate.get("content").and_then(Value::as_str) else {
            return false;
        };
        let bytes = content.len() as u64;
        if content.is_empty()
            || limit("maximum_candidate_content_bytes").is_none_or(|limit| bytes > limit)
        {
            return false;
        }
        let Some(next) = total.checked_add(bytes) else {
            return false;
        };
        total = next;
        for (field, budget) in [
            ("source_refs", "maximum_source_refs_per_candidate"),
            ("trace_refs", "maximum_trace_refs_per_candidate"),
            ("extensions", "maximum_extensions_per_candidate"),
        ] {
            if candidate
                .get(field)
                .and_then(Value::as_array)
                .is_none_or(|values| limit(budget).is_none_or(|limit| values.len() as u64 > limit))
            {
                return false;
            }
        }
    }
    limit("maximum_total_content_bytes").is_some_and(|limit| total <= limit)
        && value
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(|warnings| {
                limit("maximum_warnings").is_some_and(|limit| warnings.len() as u64 <= limit)
            })
}

fn budgets_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let budget_sentence = "compatibility beacon café evidence respects every recall budget.";
    let repeated = format!("{budget_sentence} ").repeat(30);
    let observation = common_observation(
        scope,
        1,
        Some("budget_full_content_revision"),
        &format!("{repeated}First independent source retains its full content."),
        Some(T1),
        None,
    );
    let another = common_observation(
        scope,
        2,
        Some("budget_other_content_revision"),
        &format!("{repeated}Second independent source retains different full content."),
        Some(T1),
        None,
    );
    let mut full = common_recall("current", T4, None);
    full["query"] = json!(budget_sentence);
    full["objective"] = json!(budget_sentence);
    let mut small = full.clone();
    small["budgets"] = json!({ "maximum_candidates": 1, "maximum_candidate_content_bytes": 64,
        "maximum_total_content_bytes": 64, "maximum_source_refs_per_candidate": 1,
        "maximum_trace_refs_per_candidate": 1, "maximum_warnings": 8,
        "maximum_extensions_per_candidate": 1 });
    let budgets = small["budgets"].clone();
    let mut bounded = call_step(
        "budgets.bounded",
        ProviderOperation::Recall,
        small,
        vec![
            CompatibilityAssertion::BoundedRecall { budgets },
            CompatibilityAssertion::ContentDigestAndSourceIdentity {
                populated_step: "budgets.full".into(),
            },
        ],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut bounded {
        fixture.expectation.terminal =
            TerminalExpectation::one_of([TerminalCode::Success, TerminalCode::Partial])
                .map_err(|error| error.to_string())?;
    }
    Ok(CompatibilityScenario {
        case_id: "common.all_recall_budgets_full_content_digest".into(),
        steps: vec![
            call_step(
                "budgets.observe",
                ProviderOperation::Observe,
                observation.clone(),
                vec![],
            )?,
            call_step(
                "budgets.observe_another",
                ProviderOperation::Observe,
                another.clone(),
                vec![],
            )?,
            call_step(
                "budgets.full",
                ProviderOperation::Recall,
                full,
                vec![CompatibilityAssertion::RecallSources(vec![
                    expected_source(&observation),
                    expected_source(&another),
                ])],
            )?,
            bounded,
        ],
    })
}

fn stable_rollback_scenario(
    scope: &OwnedExactScope,
    revision: u64,
) -> Result<CompatibilityScenario, String> {
    let kept = common_observation(
        scope,
        1,
        Some("kept_revision"),
        "compatibility beacon kept across rollback",
        Some(T1),
        None,
    );
    let discarded = common_observation(
        scope,
        2,
        Some("discarded_revision"),
        "compatibility beacon target discarded by rollback",
        Some(T1),
        None,
    );
    let later = common_observation(
        scope,
        3,
        Some("new_revision"),
        "compatibility beacon new target after rollback",
        Some(T1),
        None,
    );
    let mut select_new = common_recall("current", T4, None);
    select_new["exclusions"]["observation_ids"] = json!([kept["observation_id"]]);
    let mut steps = vec![
        call_step(
            "targets.observe_kept",
            ProviderOperation::Observe,
            kept.clone(),
            vec![],
        )?,
        call_step(
            "targets.kept",
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&kept),
            ])],
        )?,
        call_step(
            "targets.export",
            ProviderOperation::SnapshotExport,
            json!({}),
            vec![CompatibilityAssertion::NonemptyArray {
                pointer: "/snapshot/bytes".into(),
            }],
        )?,
        call_step(
            "targets.observe_discarded",
            ProviderOperation::Observe,
            discarded.clone(),
            vec![],
        )?,
        call_step(
            "targets.discarded",
            ProviderOperation::Recall,
            select_new.clone(),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&discarded),
            ])],
        )?,
    ];
    let mut restore = call_step(
        "targets.rollback",
        ProviderOperation::SnapshotRestore,
        json!({ "snapshot": null, "disposition_checkpoint": checkpoint(scope), "source_dispositions": [
            { "source": kept["source_identity"]["original_source"]["source"], "current_disposition": disposition("available") } ] }),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/restored_observation_sequence".into(),
            value: json!(1),
        }],
    )?;
    if let CompatibilityStep::Call { bindings, .. } = &mut restore {
        bindings.push(ReplyBinding {
            step_id: "targets.export".into(),
            source_pointer: "/snapshot".into(),
            destination_pointer: "/snapshot".into(),
        });
    }
    steps.push(restore);
    steps.push(environment_step(
        "targets.restart",
        FixtureEnvironmentAction::Restart,
    ));
    steps.push(call_step(
        "targets.kept_after_restart",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![
            CompatibilityAssertion::RecallSources(vec![expected_source(&kept)]),
            CompatibilityAssertion::StableTargets {
                populated_step: "targets.kept".into(),
            },
        ],
    )?);
    steps.push(call_step(
        "targets.observe_later",
        ProviderOperation::Observe,
        later.clone(),
        vec![],
    )?);
    steps.push(call_step(
        "targets.later",
        ProviderOperation::Recall,
        select_new,
        vec![
            CompatibilityAssertion::RecallSources(vec![expected_source(&later)]),
            CompatibilityAssertion::DistinctTargets {
                discarded_step: "targets.discarded".into(),
            },
        ],
    )?);
    let mut obsolete = call_step(
        "targets.obsolete_feedback",
        ProviderOperation::Feedback,
        feedback(scope, revision, &discarded),
        vec![],
    )?;
    bind_target(&mut obsolete, "targets.discarded");
    refusal(
        &mut obsolete,
        &[TerminalCode::InvalidRequest, TerminalCode::Conflict],
    )?;
    steps.push(obsolete);
    let mut retained = call_step(
        "targets.retained_feedback",
        ProviderOperation::Feedback,
        feedback(scope, revision, &kept),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/signal".into(),
            value: json!("helpful"),
        }],
    )?;
    bind_target(&mut retained, "targets.kept");
    steps.push(retained);
    steps.push(call_step(
        "targets.retained_feedback_visible",
        ProviderOperation::Inspection,
        source_influence(&kept["source_identity"]["original_source"]["source"]["source_key"]),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/items/0/settled_feedback/helpful".into(),
            value: json!(1),
        }],
    )?);
    steps.push(call_step(
        "targets.later_unchanged",
        ProviderOperation::Inspection,
        source_influence(&later["source_identity"]["original_source"]["source"]["source_key"]),
        vec![CompatibilityAssertion::JsonEquals {
            pointer: "/items/0/settled_feedback/helpful".into(),
            value: json!(0),
        }],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.stable_feedback_targets_restart_rollback".into(),
        steps,
    })
}

fn structured_sources_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let mut steps = Vec::new();
    let mut expected = Vec::new();
    for (sequence, kind, contract, authority, field, evidence) in [
        (
            1,
            "source.edit_settled.v1",
            "tracedecay.memory.observation.source-edit.v1",
            "source_edit",
            "claim",
            "compatibility beacon source edit settled",
        ),
        (
            2,
            "test.execution_settled.v1",
            "tracedecay.memory.observation.test-execution.v1",
            "test_execution",
            "assertion",
            "compatibility beacon test execution settled",
        ),
        (
            3,
            "feedback.outcome_settled.v1",
            "tracedecay.memory.observation.feedback-outcome.v1",
            "feedback_outcome",
            "approach",
            "compatibility beacon feedback outcome settled",
        ),
    ] {
        let content = format!("{field}: {evidence}\nstatus: settled");
        let mut observation = common_observation(
            scope,
            sequence,
            Some("structured_opaque_revision"),
            &content,
            Some(T1),
            None,
        );
        observation["observation_kind"] = json!(kind);
        observation["payload_contract"] = json!(contract);
        observation["source_identity"]["source_authority"] = json!(authority);
        observation["canonical_payload"] = json!({ field: evidence, "status": "settled", "unselected_metadata": { "must_not_be_recalled": "opaque fixture metadata" } });
        observation["payload_sha256"] = json!(
            crate::canonical_json_sha256(&observation["canonical_payload"])
                .map_err(|error| error.to_string())?
        );
        observation["source_identity"]["original_source"]["source"]["content_sha256"] =
            observation["payload_sha256"].clone();
        expected.push(ExpectedSource {
            attribution: observation["source_identity"]["original_source"].clone(),
            content,
            effective_validity: None,
        });
        steps.push(call_step(
            &format!("structured.observe.{sequence}"),
            ProviderOperation::Observe,
            observation,
            vec![],
        )?);
    }
    steps.push(call_step(
        "structured.recall_projected_evidence",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![
            CompatibilityAssertion::RecallSources(expected),
            CompatibilityAssertion::ExcludesText("opaque fixture metadata".into()),
        ],
    )?);
    Ok(CompatibilityScenario {
        case_id: "common.structured_settled_observation_kinds".into(),
        steps,
    })
}

fn source_authority_scenario(scope: &OwnedExactScope) -> Result<CompatibilityScenario, String> {
    let original = common_observation(
        scope,
        1,
        Some("canonical_source_revision"),
        "compatibility beacon original source session attribution",
        Some(T1),
        None,
    );
    let mut destination = scope.clone();
    destination.agent_session_id = "common-advisory-destination-session".into();
    let mut grant = history_grant(&destination, &[(&original, SourceDisposition::Available)]);
    grant["relation"] = json!("same_checkout");
    let mut replay_payload = replay(&destination, &[(&original, SourceDisposition::Available)]);
    replay_payload["history_grant"] = grant.clone();
    let mut steps = vec![
        call_step(
            "authority.observe_original",
            ProviderOperation::Observe,
            original.clone(),
            vec![],
        )?,
        call_step(
            "authority.original_positive",
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::RecallSources(vec![
                expected_source(&original),
            ])],
        )?,
        environment_step(
            "authority.open_destination",
            FixtureEnvironmentAction::OpenSession {
                destination_scope: destination.clone(),
            },
        ),
    ];
    let mut without_grant = call_step(
        "authority.recall_without_grant",
        ProviderOperation::Recall,
        common_recall("current", T4, None),
        vec![CompatibilityAssertion::RecallAbsent {
            populated_step: "authority.original_positive".into(),
        }],
    )?;
    expect_absence(&mut without_grant)?;
    steps.push(without_grant);
    let mut missing = replay_payload.clone();
    if let Some(fields) = missing.as_object_mut() {
        fields.remove("history_grant");
    }
    let mut missing = call_step(
        "authority.replay_missing_grant",
        ProviderOperation::Replay,
        missing,
        vec![],
    )?;
    refusal(
        &mut missing,
        &[TerminalCode::InvalidRequest, TerminalCode::Unauthorized],
    )?;
    steps.push(missing);
    let mut forged = replay_payload.clone();
    forged["history_grant"]["authorization_ref"] = json!("fixture.host.forged-authorization");
    let mut forged = call_step(
        "authority.replay_forged_grant",
        ProviderOperation::Replay,
        forged,
        vec![],
    )?;
    refusal(&mut forged, &[TerminalCode::Unauthorized])?;
    steps.push(forged);
    steps.push(call_step(
        "authority.replay_admitted",
        ProviderOperation::Replay,
        replay_payload.clone(),
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 1,
            sources_already_applied: 0,
            rejected: 0,
        }],
    )?);
    let mut authorized_recall = common_recall("current", T4, None);
    authorized_recall["history_grant"] = grant.clone();
    steps.push(call_step(
        "authority.original_attribution_retained",
        ProviderOperation::Recall,
        authorized_recall.clone(),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&original),
        ])],
    )?);
    steps.push(environment_step(
        "authority.make_unavailable",
        FixtureEnvironmentAction::SetAdmissionAuthorityAvailable { available: false },
    ));
    replay_payload["expected_previous_acknowledged_sequence"] = json!(1);
    let mut unavailable = call_step(
        "authority.replay_without_authority",
        ProviderOperation::Replay,
        replay_payload.clone(),
        vec![],
    )?;
    refusal(
        &mut unavailable,
        &[
            TerminalCode::Unauthorized,
            TerminalCode::ProviderUnavailable,
        ],
    )?;
    steps.push(unavailable);
    let mut unavailable_recall = call_step(
        "authority.recall_without_current_authority",
        ProviderOperation::Recall,
        authorized_recall.clone(),
        vec![],
    )?;
    refusal(
        &mut unavailable_recall,
        &[
            TerminalCode::Unauthorized,
            TerminalCode::ProviderUnavailable,
        ],
    )?;
    steps.push(unavailable_recall);
    steps.push(environment_step(
        "authority.restore_availability",
        FixtureEnvironmentAction::SetAdmissionAuthorityAvailable { available: true },
    ));
    let mut recovered = call_step(
        "authority.replay_after_recovery",
        ProviderOperation::Replay,
        replay_payload,
        vec![CompatibilityAssertion::ReplayAccounting {
            applied: 0,
            sources_already_applied: 1,
            rejected: 0,
        }],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut recovered {
        fixture.expectation.committed_effect = ExpectedCommittedEffect::none();
        fixture.expectation.state_generation = GenerationExpectation::Unchanged;
    }
    steps.push(recovered);
    steps.push(call_step(
        "authority.recovered_source_visible",
        ProviderOperation::Recall,
        authorized_recall.clone(),
        vec![CompatibilityAssertion::RecallSources(vec![
            expected_source(&original),
        ])],
    )?);
    let disposition_changed = environment_step(
        "authority.source_deleted_without_provider_delete",
        FixtureEnvironmentAction::RecordSourceDisposition {
            source_key: original["source_identity"]["original_source"]["source"]["source_key"]
                .as_str()
                .ok_or("original source key missing")?
                .into(),
            disposition: "deleted".into(),
        },
    );
    let mut privacy = call_step(
        "authority.current_disposition_overrides_cached_grant",
        ProviderOperation::Recall,
        authorized_recall,
        vec![CompatibilityAssertion::PrivacyWithheld {
            populated_step: "authority.recovered_source_visible".into(),
        }],
    )?;
    if let CompatibilityStep::Call { fixture, .. } = &mut privacy {
        fixture.expectation.terminal = TerminalExpectation::one_of([
            TerminalCode::Success,
            TerminalCode::SuccessZeroResults,
            TerminalCode::Partial,
            TerminalCode::Unauthorized,
        ])
        .map_err(|error| error.to_string())?;
        fixture.expectation.payload = PayloadExpectation::Any;
    }
    for (label, mut foreign) in [
        ("worktree", destination.clone()),
        ("branch", destination.clone()),
        ("project", destination.clone()),
    ] {
        match label {
            "worktree" => foreign.worktree_identity = "common-unrelated-worktree".into(),
            "branch" => foreign.branch_identity = "common-unrelated-branch".into(),
            _ => foreign.project_id = "common-unrelated-project".into(),
        }
        steps.push(environment_step(
            &format!("authority.open_foreign_{label}"),
            FixtureEnvironmentAction::OpenSession {
                destination_scope: foreign.clone(),
            },
        ));
        let mut absent = call_step(
            &format!("authority.foreign_{label}_absence"),
            ProviderOperation::Recall,
            common_recall("current", T4, None),
            vec![CompatibilityAssertion::ForeignScopeIsolated {
                populated_step: "authority.original_positive".into(),
            }],
        )?;
        if let CompatibilityStep::Call { fixture, .. } = &mut absent {
            fixture.expectation.terminal = TerminalExpectation::one_of([
                TerminalCode::Success,
                TerminalCode::SuccessZeroResults,
                TerminalCode::ScopeMismatch,
            ])
            .map_err(|error| error.to_string())?;
            fixture.expectation.payload = PayloadExpectation::Any;
        }
        steps.push(absent);
        let mut forbidden = replay(&foreign, &[(&original, SourceDisposition::Available)]);
        forbidden["history_grant"]["relation"] = json!("same_checkout");
        let mut forbidden = call_step(
            &format!("authority.foreign_{label}_grant_denied"),
            ProviderOperation::Replay,
            forbidden,
            vec![],
        )?;
        refusal(
            &mut forbidden,
            &[TerminalCode::Unauthorized, TerminalCode::ScopeMismatch],
        )?;
        steps.push(forbidden);
    }
    steps.push(environment_step(
        "authority.reopen_admitted_destination",
        FixtureEnvironmentAction::OpenSession {
            destination_scope: destination,
        },
    ));
    steps.push(disposition_changed);
    steps.push(privacy);
    Ok(CompatibilityScenario {
        case_id: "common.source_authority_session_scope_isolation".into(),
        steps,
    })
}

fn foreign_scope_leaks_source(reply: &ProviderReply, populated: Option<&ProviderReply>) -> bool {
    let Some(prior) = populated.and_then(|reply| payload_value(reply).ok()) else {
        return true;
    };
    let Some(candidates) = prior.get("candidates").and_then(Value::as_array) else {
        return true;
    };
    let mut exposed = reply.warnings.join("\n");
    if let Some(diagnostic) = reply.terminal.diagnostic_id() {
        exposed.push_str(diagnostic);
    }
    if let Some(payload) = &reply.payload {
        exposed.push_str(&String::from_utf8_lossy(&payload.bytes));
    }
    for extension in &reply.extensions {
        exposed.push_str(&String::from_utf8_lossy(&extension.canonical_payload));
    }
    candidates.iter().any(|candidate| {
        let mut retained = Vec::new();
        for field in [
            "content",
            "stable_memory_ref",
            "candidate_id",
            "content_sha256",
        ] {
            retained.extend(candidate.get(field).and_then(Value::as_str));
        }
        for field in ["source_refs", "trace_refs", "observation_refs"] {
            if let Some(values) = candidate
                .pointer(&format!("/provenance/{field}"))
                .and_then(Value::as_array)
            {
                retained.extend(values.iter().filter_map(Value::as_str));
            }
        }
        if let Some(sources) = candidate
            .pointer("/provenance/original_sources")
            .and_then(Value::as_array)
        {
            for source in sources {
                for field in [
                    "source_key",
                    "observation_id",
                    "content_sha256",
                    "stable_record_id",
                ] {
                    retained.extend(
                        source
                            .pointer(&format!("/source/{field}"))
                            .and_then(Value::as_str),
                    );
                }
            }
        }
        retained
            .into_iter()
            .any(|text| !text.is_empty() && exposed.contains(text))
    })
}

fn legacy_attribution_honest(attribution: Option<&Value>, record: &Value) -> bool {
    let Some(fields) = record
        .get("retained_source_fields")
        .and_then(Value::as_object)
    else {
        return false;
    };
    let Some(attribution) = attribution else {
        return fields.is_empty();
    };
    if attribution.is_null() {
        return fields.is_empty();
    }
    if !fields
        .iter()
        .all(|(pointer, expected)| attribution.pointer(pointer) == Some(expected))
    {
        return false;
    }
    for pointer in [
        "/source/stable_record_id",
        "/source/source_revision",
        "/validity/valid_from",
        "/validity/valid_until",
        "/validity/superseded_at",
        "/validity/superseded_by",
        "/validity/revoked_at",
        "/occurred_at",
    ] {
        if !fields.contains_key(pointer) && attribution.pointer(pointer) != Some(&Value::Null) {
            return false;
        }
    }
    fields.contains_key("/origin_scope")
        || attribution
            .pointer("/origin_scope/state")
            .and_then(Value::as_str)
            == Some("unavailable")
}

fn bounded_opaque_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn legacy_fields_valid(fields: &BTreeMap<String, Value>) -> bool {
    const POINTERS: [&str; 16] = [
        "/source/canonical_provider_id",
        "/source/canonical_session_id",
        "/source/source_key",
        "/source/stable_record_id",
        "/source/observation_id",
        "/source/source_revision",
        "/source/content_sha256",
        "/origin_scope",
        "/source_sequence",
        "/occurred_at",
        "/ingested_at",
        "/validity/valid_from",
        "/validity/valid_until",
        "/validity/superseded_at",
        "/validity/superseded_by",
        "/validity/revoked_at",
    ];
    fields.len() <= POINTERS.len()
        && fields
            .keys()
            .all(|pointer| POINTERS.contains(&pointer.as_str()))
        && serde_json::to_vec(fields).is_ok_and(|bytes| bytes.len() <= 32 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Result<OwnedExactScope, String> {
        OwnedExactScope::new(
            "profile",
            "project",
            "repository",
            "worktree",
            "branch",
            "session",
            format!("sha256:{}", "1".repeat(64)),
        )
        .map_err(|error| error.to_string())
    }

    fn legacy_record() -> LegacyRecordEvidence {
        LegacyRecordEvidence {
            stable_memory_ref: "legacy-reference-1".into(),
            original_operation_id: LegacyIdentityEvidence::Retained {
                value: "legacy-operation-1".into(),
            },
            original_idempotency_key: LegacyIdentityEvidence::Retained {
                value: "legacy-key-1".into(),
            },
            original_receipt_sha256: "a".repeat(64),
            immutable_record_sha256: "b".repeat(64),
            stored_receipt_bytes_sha256: "c".repeat(64),
            retained_source_fields: BTreeMap::new(),
        }
    }

    #[test]
    fn legacy_delivery_keys_are_bounded_opaque_and_retained_maps_are_canonical()
    -> Result<(), String> {
        let observation = common_observation(&scope()?, 1, None, "legacy evidence", None, None);
        let action = FixtureEnvironmentAction::InstallLegacyV1 {
            observations: vec![observation],
        };
        let mut record = legacy_record();
        let evidence = |record| FixtureEnvironmentEvidence::LegacyV1Installed {
            stored_version: 1,
            source_count: 1,
            records: vec![record],
        };
        assert!(environment_errors(&action, &evidence(record.clone())).is_empty());
        record.original_operation_id = LegacyIdentityEvidence::Retained {
            value: "é".repeat(128),
        };
        record.original_idempotency_key = LegacyIdentityEvidence::Retained {
            value: "x".repeat(256),
        };
        assert!(environment_errors(&action, &evidence(record.clone())).is_empty());
        for bad in [
            String::new(),
            "x".repeat(257),
            " leading-space".into(),
            "embedded\ncontrol".into(),
        ] {
            let mut invalid = record.clone();
            invalid.original_idempotency_key =
                LegacyIdentityEvidence::Retained { value: bad.clone() };
            assert!(!environment_errors(&action, &evidence(invalid)).is_empty());
            let mut invalid = record.clone();
            invalid.original_operation_id = LegacyIdentityEvidence::Retained { value: bad };
            assert!(!environment_errors(&action, &evidence(invalid)).is_empty());
        }
        assert!(!legacy_fields_valid(&BTreeMap::from([(
            "/origin_scope/exact_scope_identity/branch_identity".into(),
            json!("branch")
        )])));
        assert!(!legacy_fields_valid(&BTreeMap::from([(
            "/source".into(),
            json!({})
        )])));
        assert!(!legacy_fields_valid(&BTreeMap::from([(
            "/origin_scope".into(),
            json!("x".repeat(32 * 1024))
        )])));
        Ok(())
    }

    #[test]
    fn every_retained_legacy_value_and_null_must_survive_unchanged() -> Result<(), String> {
        let original = common_observation(
            &scope()?,
            1,
            Some("opaque_r2"),
            "legacy evidence",
            Some(T1),
            None,
        )["source_identity"]["original_source"]
            .clone();
        let pointers = [
            "/source/canonical_provider_id",
            "/source/canonical_session_id",
            "/source/source_key",
            "/source/stable_record_id",
            "/source/observation_id",
            "/source/source_revision",
            "/source/content_sha256",
            "/origin_scope",
            "/source_sequence",
            "/occurred_at",
            "/ingested_at",
            "/validity/valid_from",
            "/validity/valid_until",
            "/validity/superseded_at",
            "/validity/superseded_by",
            "/validity/revoked_at",
        ];
        let mut record = legacy_record();
        for pointer in pointers {
            record.retained_source_fields.insert(
                pointer.into(),
                original
                    .pointer(pointer)
                    .ok_or("original field missing")?
                    .clone(),
            );
        }
        assert!(legacy_fields_valid(&record.retained_source_fields));
        let record = serde_json::to_value(record).map_err(|error| error.to_string())?;
        assert!(legacy_attribution_honest(Some(&original), &record));
        for pointer in pointers {
            let mut forged = original.clone();
            *forged
                .pointer_mut(pointer)
                .ok_or("retained field missing")? = json!("forged-value");
            assert!(
                !legacy_attribution_honest(Some(&forged), &record),
                "changed {pointer}"
            );
            let mut missing = original.clone();
            let (parent, field) = pointer.rsplit_once('/').ok_or("invalid pointer")?;
            missing
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .ok_or("parent missing")?
                .remove(field);
            assert!(
                !legacy_attribution_honest(Some(&missing), &record),
                "missing {pointer}"
            );
        }
        let absent = serde_json::to_value(legacy_record()).map_err(|error| error.to_string())?;
        assert!(legacy_attribution_honest(Some(&Value::Null), &absent));
        assert!(!legacy_attribution_honest(Some(&original), &absent));
        Ok(())
    }

    #[test]
    fn temporal_claims_use_requested_instants_and_allow_supported_interval_alternatives()
    -> Result<(), String> {
        assert_eq!(utc_nanos("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            utc_nanos("2000-02-29T00:00:00Z"),
            Some(951_782_400_000_000_000)
        );
        assert_eq!(
            utc_nanos("2025-01-01T00:00:01.000000001Z"),
            utc_nanos(T1).and_then(|time| time.checked_add(1))
        );
        let mut candidate = json!({ "validity": { "valid_from": T1, "valid_until": null, "superseded_at": null,
            "superseded_by": null, "revoked_at": T3, "temporal_state": "current" } });
        let point = temporal_query(&common_recall("as_of", T2, None)["temporal_query"])?;
        assert!(candidate_temporal_claim_valid(&candidate, &point));
        candidate["validity"]["temporal_state"] = json!("revoked");
        assert!(!candidate_temporal_claim_valid(&candidate, &point));
        let interval = temporal_query(&common_recall("interval", T1, Some(T3))["temporal_query"])?;
        assert!(candidate_temporal_claim_valid(&candidate, &interval));
        candidate["validity"]["temporal_state"] = json!("current");
        assert!(candidate_temporal_claim_valid(&candidate, &interval));
        candidate["validity"]["temporal_state"] = json!("superseded");
        assert!(!candidate_temporal_claim_valid(&candidate, &interval));
        candidate["validity"]["valid_from"] = Value::Null;
        candidate["validity"]["revoked_at"] = Value::Null;
        candidate["validity"]["temporal_state"] = json!("unknown");
        let mut unknown = common_recall("current", T4, None);
        unknown["temporal_query"]["unknown_validity_policy"] = json!("degrade");
        let unknown = temporal_query(&unknown["temporal_query"])?;
        assert!(candidate_temporal_claim_valid(&candidate, &unknown));
        candidate["validity"]["temporal_state"] = json!("current");
        assert!(!candidate_temporal_claim_valid(&candidate, &unknown));
        Ok(())
    }

    #[test]
    fn source_digest_is_original_canonical_payload_and_metadata_revoke_stays_narrow()
    -> Result<(), String> {
        let scope = scope()?;
        let cases = common_advisory_scenarios(&scope, 1)?;
        for case in &cases {
            for step in &case.steps {
                if let CompatibilityStep::Call { fixture, .. } = step {
                    let value: Value = serde_json::from_slice(&fixture.payload.bytes)
                        .map_err(|error| error.to_string())?;
                    if fixture.operation == ProviderOperation::Recall {
                        let outer: Vec<_> = fixture
                            .required_capabilities
                            .iter()
                            .map(OwnedVersionedId::as_str)
                            .collect();
                        assert_eq!(
                            value["required_capabilities"],
                            json!(outer),
                            "{}",
                            fixture.step_id
                        );
                        assert_eq!(outer, vec!["recall.query.v1", "recall.temporal.v1"]);
                    } else {
                        assert_eq!(
                            fixture
                                .required_capabilities
                                .iter()
                                .map(OwnedVersionedId::as_str)
                                .collect::<Vec<_>>(),
                            vec![fixture.operation.capability_id()]
                        );
                    }
                    if fixture.operation == ProviderOperation::Observe {
                        assert_eq!(
                            value
                                .pointer("/source_identity/original_source/source/content_sha256")
                                .and_then(Value::as_str),
                            Some(
                                crate::canonical_json_sha256(&value["canonical_payload"])
                                    .map_err(|error| error.to_string())?
                                    .as_str()
                            )
                        );
                    }
                    if fixture.step_id == "lifecycle.revoke_t3" {
                        assert_eq!(value["replacement"], json!({ "revoked_at": T3 }));
                    }
                }
            }
        }
        let budgets = cases
            .iter()
            .find(|case| case.case_id == "common.all_recall_budgets_full_content_digest")
            .ok_or("budget case missing")?;
        assert_eq!(budgets.steps.iter().filter(|step| matches!(step, CompatibilityStep::Call { fixture, .. } if fixture.operation == ProviderOperation::Observe)).count(), 2);
        let authority = cases
            .iter()
            .find(|case| case.case_id == "common.source_authority_session_scope_isolation")
            .ok_or("authority case missing")?;
        let position = |id: &str| {
            authority
                .steps
                .iter()
                .position(|step| step.step_id() == id)
                .ok_or_else(|| format!("missing {id}"))
        };
        assert!(
            position("authority.make_unavailable")?
                < position("authority.recall_without_current_authority")?
        );
        assert!(
            position("authority.recall_without_current_authority")?
                < position("authority.restore_availability")?
        );
        assert!(
            position("authority.foreign_project_grant_denied")?
                < position("authority.source_deleted_without_provider_delete")?
        );
        Ok(())
    }
    #[test]
    fn replay_pages_are_contiguous_use_current_dispositions_and_bind_actual_ack()
    -> Result<(), String> {
        let scope = scope()?;
        let cases = common_advisory_scenarios(&scope, 1)?;
        let mut replay_count = 0;
        for case in &cases {
            let mut dispositions = BTreeMap::new();
            for step in &case.steps {
                match step {
                    CompatibilityStep::Environment {
                        action:
                            FixtureEnvironmentAction::RecordSourceDisposition {
                                source_key,
                                disposition,
                            },
                        ..
                    } => {
                        dispositions.insert(source_key.clone(), disposition.clone());
                    }
                    CompatibilityStep::Call {
                        fixture,
                        bindings,
                        assertions,
                    } if fixture.operation == ProviderOperation::Replay
                        && (fixture.step_id.starts_with("restore.")
                            || fixture.step_id.starts_with("predelete.")) =>
                    {
                        replay_count += 1;
                        let value: Value = serde_json::from_slice(&fixture.payload.bytes)
                            .map_err(|error| error.to_string())?;
                        let rows = value["resolved_observations"]
                            .as_array()
                            .ok_or("replay rows missing")?;
                        let grants = value["history_grant"]["sources"]
                            .as_array()
                            .ok_or("replay grants missing")?;
                        assert_eq!(rows.len(), grants.len());
                        assert_eq!(value["first_source_sequence"], 1);
                        assert_eq!(value["last_source_sequence"], rows.len());
                        for (index, (row, grant)) in rows.iter().zip(grants).enumerate() {
                            let observation = &row["observation"];
                            assert_eq!(observation["source_sequence"], index + 1);
                            assert_eq!(
                                row["receipt_ref"],
                                format!("fixture.host.observation-receipt.{}", index + 1)
                            );
                            assert_eq!(
                                grant["attribution"],
                                observation["source_identity"]["original_source"]
                            );
                            let key = grant["attribution"]["source"]["source_key"]
                                .as_str()
                                .ok_or("source key absent")?;
                            let current = dispositions
                                .get(key)
                                .map(String::as_str)
                                .unwrap_or("available");
                            assert_eq!(grant["current_disposition"]["state"], current);
                        }
                        let positive = fixture.step_id.ends_with(".replay_positive");
                        let repeated = fixture.step_id.ends_with(".new_key_same_source");
                        let predelete = fixture.step_id == "predelete.replay_after_restart";
                        let expected = CompatibilityAssertion::ReplayAccounting {
                            applied: u64::from(positive),
                            sources_already_applied: u64::from(repeated || predelete),
                            rejected: 1,
                        };
                        assert!(assertions.contains(&expected));
                        if positive || repeated || predelete {
                            assert_eq!(rows.len(), 2);
                        } else {
                            assert_eq!(rows.len(), 1);
                        }
                        if !positive {
                            assert_eq!(
                                fixture.expectation.committed_effect,
                                ExpectedCommittedEffect::none()
                            );
                            assert_eq!(
                                fixture.expectation.state_generation,
                                GenerationExpectation::Unchanged
                            );
                        }
                        assert_eq!(value["expected_previous_acknowledged_sequence"], 0);
                        if repeated {
                            assert_eq!(
                                bindings.as_slice(),
                                &[ReplyBinding {
                                    step_id: fixture
                                        .step_id
                                        .replace(".new_key_same_source", ".replay_positive"),
                                    source_pointer: "/acknowledged_sequence".into(),
                                    destination_pointer: "/expected_previous_acknowledged_sequence"
                                        .into(),
                                }]
                            );
                        } else {
                            assert!(bindings.is_empty());
                        }
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(replay_count, 7);
        Ok(())
    }
}
