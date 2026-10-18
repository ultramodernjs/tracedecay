//! Restart recovery: what the outbox knows against what the provider claims.
//!
//! After a host or provider restart the two sides of a delivery can disagree in
//! exactly three ways, and each one has a different correct answer:
//!
//! * the provider is **behind** the journal — unacknowledged rows exist and the
//!   answer is redelivery, which is safe because the idempotency key is derived
//!   from content, so a provider that already applied a row answers
//!   `duplicate_acknowledged` instead of applying it twice;
//! * the provider's **state identity moved** — its state schema changed, or its
//!   generation went backwards because someone restored or reset it — and the
//!   answer is a typed repair requirement, never a silent reinitialization that
//!   would replay acknowledged history into a provider that already forgot it;
//! * the provider claims a position the journal **never journalled**, which no
//!   automatic action can reconcile and which therefore ends at an operator.
//!
//! # What makes the acknowledged sequence monotonic
//!
//! [`AcknowledgedPositionV1`] is not derived at read time from delivery rows: a
//! privacy deletion or a retention sweep legitimately removes an acknowledged
//! row, and a derived maximum would then move backwards and re-propose
//! delivered work. It is a durable watermark written inside the same
//! transaction as the acknowledging receipt, and the only statement that
//! touches it refuses to lower it.
//!
//! # What bounds the repair path
//!
//! [`RecoveryBudgetV1`] bounds how many times a host may re-attempt automatic
//! recovery against one incompatible provider state. Past it the assessment is
//! [`RecoveryPlanV1::OperatorRepairRequired`], which proposes no further
//! automatic action and names the exact repair an operator must perform. A
//! converged assessment clears the counter, so a provider that recovers is not
//! held against its history.

use sha2::{Digest, Sha256};
use tracedecay_memory_provider_api::CancellationToken;

use crate::error::ObservationJournalError;
use crate::identity::{
    SOURCE_EVENT_ID_MAX_BYTES, SourceSequenceV1, absorb, lowercase_hex, require_bounded,
    require_sha256,
};
use crate::settlement::SourceStreamKeyV1;

/// Maximum bytes a provider-reported state schema identity may occupy.
pub const STATE_SCHEMA_VERSION_MAX_BYTES: usize = 256;

/// Domain separator for the stable identity of one recovery assessment.
const ASSESSMENT_ID_DOMAIN: &[u8] = b"tracedecay.memory-provider.recovery-assessment.v1\0";

/// The `(provider registration, source stream)` pair one recovery assessment is
/// bound to.
///
/// Delivery is addressed by registration rather than instance, and source
/// sequence is only ordered inside one authority/scope/stream triple, so this
/// is the narrowest key under which "how far has this provider acknowledged"
/// is a well-formed question.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryTargetKeyV1 {
    /// Logical provider identity.
    pub provider_id: String,
    /// Pinned product-owned registration revision.
    pub registration_revision: u64,
    /// Authority, exact scope, and stream the sequence is ordered in.
    pub stream: SourceStreamKeyV1,
}

impl RecoveryTargetKeyV1 {
    /// Revalidates the key.
    pub fn validate(&self) -> Result<(), ObservationJournalError> {
        require_bounded(&self.provider_id, "provider_id", SOURCE_EVENT_ID_MAX_BYTES)?;
        if self.registration_revision == 0 {
            return Err(ObservationJournalError::ValueOutOfRange {
                field: "registration_revision",
            });
        }
        self.stream.validate()
    }
}

/// What the host could learn about the provider's own replay position for one
/// target.
///
/// This is deliberately not an `Option`. "The provider did not say" and "the
/// provider says it keeps no position" are different facts with different
/// consequences, and collapsing them into `None` is exactly how a host ends up
/// skipping exact-effect verification without ever deciding to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderReplayPositionV1 {
    /// The provider retains a replay position and reports this one as the
    /// highest source sequence it has applied for the target.
    Reported(SourceSequenceV1),
    /// The provider retains a replay position and reports that it holds none
    /// for this target yet. A host watermark above this is a lost effect, not
    /// missing evidence.
    ReportedNone,
    /// The provider's validated readiness evidence declares no replay-position
    /// capability, so exact-effect verification rests on the host's
    /// content-derived idempotency key and its own durable receipts. This is a
    /// policy the host derives from evidence, never a default it falls back to.
    NotRetained,
    /// The provider's validated readiness evidence declares that it retains a
    /// replay position, but the host could not read one from that evidence.
    /// Nothing may be delivered into a position the host cannot compare.
    Unreadable,
}

impl ProviderReplayPositionV1 {
    /// The position the provider reported, when it reported one.
    #[must_use]
    pub const fn reported(self) -> Option<SourceSequenceV1> {
        match self {
            Self::Reported(sequence) => Some(sequence),
            Self::ReportedNone | Self::NotRetained | Self::Unreadable => None,
        }
    }

    /// Whether the provider claims to retain a replay position at all.
    #[must_use]
    pub const fn retains_position(self) -> bool {
        matches!(self, Self::Reported(_) | Self::ReportedNone)
    }

    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Reported(_) => "reported",
            Self::ReportedNone => "reported_none",
            Self::NotRetained => "not_retained",
            Self::Unreadable => "unreadable",
        }
    }
}

/// What a provider says about its own state at the start of a recovery pass.
///
/// Every field is provider-reported evidence obtained from a validated
/// readiness handshake, including [`ProviderReplayPositionV1`], which carries
/// the provider's replay-position *policy* as well as its position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCheckpointV1 {
    /// Registration and stream this checkpoint answers for.
    pub target: RecoveryTargetKeyV1,
    /// Immutable implementation identity of the running incarnation.
    pub implementation_identity_sha256: String,
    /// Provider-local state schema identity.
    pub state_schema_version: String,
    /// Provider-local state generation.
    pub state_generation: u64,
    /// The provider's own replay position, or the typed reason there is none.
    pub replay_position: ProviderReplayPositionV1,
}

impl ProviderCheckpointV1 {
    /// Rejects a checkpoint that cannot be compared against the journal.
    pub fn validate(&self) -> Result<(), ObservationJournalError> {
        self.target.validate()?;
        require_sha256(
            &self.implementation_identity_sha256,
            "implementation_identity_sha256",
        )?;
        require_bounded(
            &self.state_schema_version,
            "state_schema_version",
            STATE_SCHEMA_VERSION_MAX_BYTES,
        )
    }
}

/// The stable identity of one logical recovery assessment.
///
/// Derived from the target and the exact provider evidence being judged, so
/// re-submitting the same assessment — after an ambiguous result, a crash, or
/// two dispatchers racing the same incarnation — is recognisably the *same*
/// assessment and consumes exactly one automatic repair attempt rather than
/// one per submission.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecoveryAssessmentIdV1(String);

impl RecoveryAssessmentIdV1 {
    /// Derives the identity of the assessment this checkpoint asks for.
    #[must_use]
    pub fn for_checkpoint(checkpoint: &ProviderCheckpointV1) -> Self {
        let target = &checkpoint.target;
        let mut digest = Sha256::new();
        digest.update(ASSESSMENT_ID_DOMAIN);
        absorb(&mut digest, target.provider_id.as_bytes());
        absorb(&mut digest, &target.registration_revision.to_be_bytes());
        absorb(
            &mut digest,
            target.stream.source_authority.as_wire().as_bytes(),
        );
        absorb(&mut digest, target.stream.exact_scope_sha256.as_bytes());
        absorb(&mut digest, target.stream.source_stream.as_str().as_bytes());
        absorb(
            &mut digest,
            checkpoint.implementation_identity_sha256.as_bytes(),
        );
        absorb(&mut digest, checkpoint.state_schema_version.as_bytes());
        absorb(&mut digest, &checkpoint.state_generation.to_be_bytes());
        absorb(&mut digest, checkpoint.replay_position.as_wire().as_bytes());
        absorb(
            &mut digest,
            &checkpoint
                .replay_position
                .reported()
                .map_or(u64::MAX, |sequence| sequence.0)
                .to_be_bytes(),
        );
        Self(lowercase_hex(&digest.finalize()))
    }

    /// Returns the derived identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The bound one recovery assessment runs under.
///
/// Recovery happens inside a delivery attempt, on the same journal a dispatcher
/// is writing to, so it can block on the journal lock or on SQLite. Both halves
/// of the caller's bound therefore travel with it: an assessment that outlives
/// its deadline, or whose delivery was cancelled, stops with a typed outcome
/// instead of finishing work nobody is waiting for.
#[derive(Clone, Debug)]
pub struct RecoveryControlV1 {
    deadline_unix_micros: i64,
    cancellation: CancellationToken,
}

impl RecoveryControlV1 {
    /// Binds an absolute deadline to a cancellation token.
    #[must_use]
    pub const fn new(deadline_unix_micros: i64, cancellation: CancellationToken) -> Self {
        Self {
            deadline_unix_micros,
            cancellation,
        }
    }

    /// Absolute instant after which the assessment must stop.
    #[must_use]
    pub const fn deadline_unix_micros(&self) -> i64 {
        self.deadline_unix_micros
    }

    /// Budget left at `now_unix_micros`, saturating at zero.
    #[must_use]
    pub fn remaining(&self, now_unix_micros: i64) -> RecoveryTimeBudgetV1 {
        RecoveryTimeBudgetV1 {
            remaining_micros: self
                .deadline_unix_micros
                .saturating_sub(now_unix_micros)
                .max(0),
        }
    }

    /// Whether the caller cancelled this assessment.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// The wall-clock budget one recovery port call may consume.
///
/// A port that cannot finish inside it must return
/// [`ObservationJournalError::BudgetExhausted`] rather than wait on a fixed
/// internal timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryTimeBudgetV1 {
    /// Micros left before the caller's deadline. Never negative.
    pub remaining_micros: i64,
}

impl RecoveryTimeBudgetV1 {
    /// Whether any budget is left at all.
    #[must_use]
    pub const fn is_spent(self) -> bool {
        self.remaining_micros <= 0
    }
}

/// The durable acknowledged watermark for one target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgedPositionV1 {
    /// Highest acknowledged source sequence. Never decreases.
    pub sequence: SourceSequenceV1,
    /// Instant the watermark last advanced.
    pub acknowledged_at_unix_micros: i64,
}

/// The host-side recovery record persisted for one target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRecoveryStateV1 {
    /// Acknowledged watermark, absent until the first acknowledgement.
    pub acknowledged: Option<AcknowledgedPositionV1>,
    /// Implementation identity accepted by the last converged assessment.
    pub implementation_identity_sha256: Option<String>,
    /// State schema identity accepted by the last converged assessment.
    pub state_schema_version: Option<String>,
    /// State generation accepted by the last converged assessment.
    pub state_generation: Option<u64>,
    /// Whether the last converged assessment accepted a provider that retains
    /// its own replay position. A provider that had one and now has none lost
    /// bookkeeping the host was relying on.
    pub replay_position_retained: Option<bool>,
    /// Consecutive automatic recovery attempts refused since the last
    /// convergence.
    pub automatic_repair_attempts: u32,
    /// Wire value of the defect the most recent refusal named.
    pub last_defect: Option<String>,
    /// Identity of the assessment the most recent refusal was recorded for.
    /// Re-recording the same identity is a no-op on the attempt counter.
    pub last_assessment_id: Option<String>,
    /// Instant the record last changed.
    pub updated_at_unix_micros: i64,
}

/// How far the journal still has to go for one target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnacknowledgedFrontierV1 {
    /// Rows a dispatcher may still deliver: `pending`, `leased`, or
    /// `effect_unknown`. Rows that ended without acknowledgement — rejected,
    /// expired, cancelled, exhausted, forgotten — are deliberately excluded:
    /// they will never be delivered again, so counting them would make a
    /// converged target look permanently behind.
    pub unacknowledged_items: u64,
    /// Lowest source sequence among those rows.
    pub first_unacknowledged_sequence: Option<SourceSequenceV1>,
    /// Highest source sequence journalled for the target in any state.
    pub last_journalled_sequence: Option<SourceSequenceV1>,
}

/// A provider state the journal refuses to deliver into.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateIncompatibilityV1 {
    /// The provider's state schema identity changed under an unchanged
    /// registration, so previously acknowledged history no longer means the
    /// same thing.
    StateSchemaChanged {
        /// Identity the last converged assessment accepted.
        expected: String,
        /// Identity the provider reports now.
        reported: String,
    },
    /// The running incarnation reports a different immutable implementation
    /// identity than the one the last converged assessment accepted under this
    /// registration. The binary changed without the registration that pins it
    /// changing, so nothing the host holds proves the new implementation owns
    /// the state the old one acknowledged.
    ImplementationIdentityChanged {
        /// Identity the last converged assessment accepted.
        expected: String,
        /// Identity the provider reports now.
        reported: String,
    },
    /// The provider's state generation went backwards, which is what a restore
    /// or a wipe looks like from the host's side.
    StateGenerationRegressed {
        /// Generation the last converged assessment accepted.
        expected_at_least: u64,
        /// Generation the provider reports now.
        reported: u64,
    },
    /// The provider's own acknowledged position is behind the host's durable
    /// acknowledged watermark, so it lost effects the outbox considers
    /// delivered and can no longer be reconstructed from unacknowledged rows.
    AcknowledgedSequenceRegressed {
        /// Watermark the journal holds.
        host_acknowledged: SourceSequenceV1,
        /// Position the provider reports, absent when it reports that it holds
        /// nothing at all for this target.
        provider_acknowledged: Option<SourceSequenceV1>,
    },
    /// The provider claims a position the journal never journalled for this
    /// target, so nothing the host holds explains the provider's state.
    ProviderAheadOfJournal {
        /// Position the provider reports.
        provider_acknowledged: SourceSequenceV1,
        /// Highest sequence the journal holds, when it holds any.
        journal_highest: Option<SourceSequenceV1>,
    },
    /// The provider retained its own replay position when the host last
    /// converged with it and retains none now, so the bookkeeping the host
    /// verified acknowledged effects against is gone.
    ReplayPositionAbandoned {
        /// Watermark the journal holds, when it holds one.
        host_acknowledged: Option<SourceSequenceV1>,
    },
    /// The provider declares that it retains a replay position, but the host
    /// could not read one from the validated readiness evidence. Delivering
    /// here would be delivering into a position nobody compared.
    ReplayPositionUnreadable,
}

impl StateIncompatibilityV1 {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::StateSchemaChanged { .. } => "state_schema_changed",
            Self::ImplementationIdentityChanged { .. } => "implementation_identity_changed",
            Self::StateGenerationRegressed { .. } => "state_generation_regressed",
            Self::AcknowledgedSequenceRegressed { .. } => "acknowledged_sequence_regressed",
            Self::ProviderAheadOfJournal { .. } => "provider_ahead_of_journal",
            Self::ReplayPositionAbandoned { .. } => "replay_position_abandoned",
            Self::ReplayPositionUnreadable => "replay_position_unreadable",
        }
    }

    /// The repair this defect requires. Nothing here is automatic: each answer
    /// names an explicit provider-side operation, never a silent reset.
    #[must_use]
    pub const fn repair_action(&self) -> RepairActionV1 {
        match self {
            Self::StateSchemaChanged { .. } | Self::ImplementationIdentityChanged { .. } => {
                RepairActionV1::MigrateProviderState
            }
            // Provider state that lost acknowledged effects is rebuilt, never
            // restored: the canonical journal is the only history the host
            // replays, and no provider snapshot surface exists.
            Self::StateGenerationRegressed { .. }
            | Self::AcknowledgedSequenceRegressed { .. }
            | Self::ReplayPositionAbandoned { .. } => RepairActionV1::ResetProviderState,
            Self::ProviderAheadOfJournal { .. } | Self::ReplayPositionUnreadable => {
                RepairActionV1::OperatorInvestigation
            }
        }
    }
}

/// The bounded repair an incompatible provider state requires.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RepairActionV1 {
    /// Migrate the provider-local state to the schema this build speaks.
    MigrateProviderState,
    /// Reset the provider-local state and re-register it, accepting the loss
    /// of provider-local memory the host never owned.
    ResetProviderState,
    /// No host-side action can reconcile this; an operator must inspect both
    /// sides.
    OperatorInvestigation,
}

impl RepairActionV1 {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::MigrateProviderState => "migration_required",
            Self::ResetProviderState => "reset_required",
            Self::OperatorInvestigation => "operator_investigation_required",
        }
    }
}

/// How many automatic recovery attempts one incompatible state may consume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBudgetV1 {
    /// Consecutive refused assessments allowed before the plan escalates to
    /// [`RecoveryPlanV1::OperatorRepairRequired`]. Must be at least one.
    pub max_automatic_attempts: u32,
}

impl RecoveryBudgetV1 {
    /// Rejects a budget that cannot bound the repair path.
    pub const fn validate(&self) -> Result<(), ObservationJournalError> {
        if self.max_automatic_attempts == 0 {
            return Err(ObservationJournalError::ValueOutOfRange {
                field: "max_automatic_attempts",
            });
        }
        Ok(())
    }
}

/// What one recovery assessment decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryPlanV1 {
    /// Provider and journal agree and nothing is outstanding.
    Converged {
        /// Acknowledged watermark both sides agree on, when one exists.
        acknowledged_through: Option<SourceSequenceV1>,
        /// Generation a delivery call must declare as expected.
        expected_state_generation: u64,
    },
    /// The provider is behind. Redelivery of exactly these rows converges it,
    /// and duplicates are answered as duplicates rather than applied twice.
    ReplayUnacknowledged {
        /// Lowest deliverable sequence.
        first_unacknowledged_sequence: SourceSequenceV1,
        /// Highest sequence journalled for the target.
        last_journalled_sequence: SourceSequenceV1,
        /// Deliverable rows outstanding.
        unacknowledged_items: u64,
        /// Generation a delivery call must declare as expected.
        expected_state_generation: u64,
    },
    /// The provider's state is incompatible. No delivery is proposed, and the
    /// host may still re-assess until the budget is spent.
    StateIncompatible {
        /// The typed defect.
        defect: StateIncompatibilityV1,
        /// The repair it requires.
        repair: RepairActionV1,
        /// Automatic attempts still available before escalation.
        automatic_attempts_remaining: u32,
    },
    /// The bounded automatic repair path is spent. No further automatic action
    /// is proposed and the named repair must be performed.
    OperatorRepairRequired {
        /// The typed defect.
        defect: StateIncompatibilityV1,
        /// The repair an operator must perform.
        repair: RepairActionV1,
        /// Automatic attempts consumed.
        automatic_repair_attempts: u32,
        /// Budget those attempts were measured against.
        max_automatic_attempts: u32,
    },
}

impl RecoveryPlanV1 {
    /// Whether delivery to this provider may proceed.
    #[must_use]
    pub const fn permits_delivery(&self) -> bool {
        matches!(
            self,
            Self::Converged { .. } | Self::ReplayUnacknowledged { .. }
        )
    }

    /// The generation a delivery call must declare, when delivery is admitted.
    #[must_use]
    pub const fn expected_state_generation(&self) -> Option<u64> {
        match self {
            Self::Converged {
                expected_state_generation,
                ..
            }
            | Self::ReplayUnacknowledged {
                expected_state_generation,
                ..
            } => Some(*expected_state_generation),
            Self::StateIncompatible { .. } | Self::OperatorRepairRequired { .. } => None,
        }
    }

    /// The repair this plan requires, when it requires one.
    #[must_use]
    pub const fn repair_action(&self) -> Option<RepairActionV1> {
        match self {
            Self::StateIncompatible { repair, .. }
            | Self::OperatorRepairRequired { repair, .. } => Some(*repair),
            Self::Converged { .. } | Self::ReplayUnacknowledged { .. } => None,
        }
    }
}

/// The recovery side of the journal: the durable checkpoint and the frontier.
///
/// It reads and writes recovery bookkeeping only. There is no content
/// predicate here either: the frontier is counted from delivery state and
/// source sequence, never from what an observation said.
pub trait ObservationRecoveryPortV1: Send + Sync {
    /// Reads the persisted recovery record for one target inside the caller's
    /// remaining budget.
    fn recovery_state(
        &self,
        target: &RecoveryTargetKeyV1,
        budget: RecoveryTimeBudgetV1,
    ) -> Result<Option<HostRecoveryStateV1>, ObservationJournalError>;

    /// Counts the deliverable rows still outstanding for one target inside the
    /// caller's remaining budget.
    fn unacknowledged_frontier(
        &self,
        target: &RecoveryTargetKeyV1,
        budget: RecoveryTimeBudgetV1,
    ) -> Result<UnacknowledgedFrontierV1, ObservationJournalError>;

    /// Persists an accepted provider checkpoint and clears the repair counter
    /// and the refusal identity that counter was measured against.
    ///
    /// This never writes the acknowledged watermark: that one is owned by the
    /// acknowledging receipt and may only move forward.
    fn accept_checkpoint(
        &self,
        checkpoint: &ProviderCheckpointV1,
        now_unix_micros: i64,
        budget: RecoveryTimeBudgetV1,
    ) -> Result<(), ObservationJournalError>;

    /// Records one refused assessment insert-once for its identity and returns
    /// the consecutive attempt count after it.
    ///
    /// Re-recording an identity already stored for the target must leave the
    /// counter untouched, and no write may take it above
    /// [`RecoveryRefusalWriteV1::max_automatic_attempts`]: a retry after an
    /// ambiguous result, two dispatchers racing one incarnation, and repeated
    /// assessment after escalation are all the same logical refusal.
    fn record_recovery_refusal(
        &self,
        refusal: &RecoveryRefusalWriteV1<'_>,
        budget: RecoveryTimeBudgetV1,
    ) -> Result<u32, ObservationJournalError>;
}

/// One refused assessment, as the durable counter needs it.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryRefusalWriteV1<'a> {
    /// Target the refusal belongs to.
    pub target: &'a RecoveryTargetKeyV1,
    /// Stable identity of the assessment being refused.
    pub assessment: &'a RecoveryAssessmentIdV1,
    /// Canonical wire value of the typed defect.
    pub defect: &'a str,
    /// Ceiling the stored counter may never exceed.
    pub max_automatic_attempts: u32,
    /// Instant the refusal was decided.
    pub now_unix_micros: i64,
}
