//! tdmem-0506: recovery replay and exact-effect verification.
//!
//! Every test here drives the real SQLite journal through a real restart — the
//! store is dropped so the connection closes, and a new one is opened on the
//! same file. The "provider" is a set of idempotency keys it has applied, which
//! is the only thing that makes "without duplicate effects" a checkable claim
//! rather than an assertion about counters the host owns. Where a test is about
//! surviving a *provider* restart, that set is dropped and rebuilt too.

mod support;

use std::collections::BTreeSet;

use rusqlite::{Connection, TransactionBehavior};
use support::{
    Builder, LEASE, SECOND, T0, TestResult, applied_receipt, journal, lease_request, policy,
    receipt_for, stream_key,
};

use tracedecay_memory_observation::{
    AppendOutcomeV1, ForgetSourceKeyV1, ForgetSourceRequestV1, ObservationCommittedEffectV1,
    ObservationDispatchPortV1, ObservationJournalError, ObservationJournalReaderV1,
    ObservationOutcomeV1, ObservationRecoveryPortV1, ObservationRetentionPortV1,
    ObservationRuntimeError, ProviderCheckpointV1, ProviderReplayPositionV1, RecoveryBudgetV1,
    RecoveryControlV1, RecoveryPlanV1, RecoveryRuntimeV1, RecoveryTargetKeyV1,
    RecoveryTimeBudgetV1, RepairActionV1, SourceSequenceV1, SqliteObservationJournal,
    StateIncompatibilityV1,
};
use tracedecay_memory_provider_api::CancellationToken;

const IMPLEMENTATION: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const OTHER_IMPLEMENTATION: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SCHEMA_V1: &str = "tracedecay.native.state.v1";
const SCHEMA_V2: &str = "tracedecay.native.state.v2";

/// Bound wide enough that no test in this file is measuring wall clock, but
/// finite: an assessment still has to fit inside it.
const OPEN_BUDGET: i64 = 30 * SECOND;

/// A provider that deduplicates on the content-derived idempotency key, which
/// is exactly the property redelivery relies on.
#[derive(Default)]
struct ProviderEffects {
    applied: BTreeSet<String>,
    apply_calls: u32,
}

impl ProviderEffects {
    /// Applies one observation, returning whether this call created the effect.
    fn apply(&mut self, idempotency_key: &str) -> bool {
        self.apply_calls = self.apply_calls.saturating_add(1);
        self.applied.insert(idempotency_key.to_owned())
    }

    fn effects(&self) -> usize {
        self.applied.len()
    }
}

fn target() -> Result<RecoveryTargetKeyV1, Box<dyn std::error::Error>> {
    Ok(RecoveryTargetKeyV1 {
        provider_id: support::PROVIDER.to_owned(),
        registration_revision: 4,
        stream: stream_key(support::STREAM)?,
    })
}

fn checkpoint(
    state_schema_version: &str,
    state_generation: u64,
    replay_position: ProviderReplayPositionV1,
) -> Result<ProviderCheckpointV1, Box<dyn std::error::Error>> {
    checkpoint_from(
        IMPLEMENTATION,
        state_schema_version,
        state_generation,
        replay_position,
    )
}

fn checkpoint_from(
    implementation_identity_sha256: &str,
    state_schema_version: &str,
    state_generation: u64,
    replay_position: ProviderReplayPositionV1,
) -> Result<ProviderCheckpointV1, Box<dyn std::error::Error>> {
    Ok(ProviderCheckpointV1 {
        target: target()?,
        implementation_identity_sha256: implementation_identity_sha256.to_owned(),
        state_schema_version: state_schema_version.to_owned(),
        state_generation,
        replay_position,
    })
}

/// The Native shape: a provider whose validated evidence declares no
/// replay-position capability at all.
const NO_POSITION: ProviderReplayPositionV1 = ProviderReplayPositionV1::NotRetained;

fn reported(sequence: u64) -> ProviderReplayPositionV1 {
    ProviderReplayPositionV1::Reported(SourceSequenceV1(sequence))
}

fn budget(max_automatic_attempts: u32) -> RecoveryBudgetV1 {
    RecoveryBudgetV1 {
        max_automatic_attempts,
    }
}

/// A live bound measured from the assessment instant the test passes in.
fn control(now_unix_micros: i64) -> RecoveryControlV1 {
    RecoveryControlV1::new(
        now_unix_micros.saturating_add(OPEN_BUDGET),
        CancellationToken::new(),
    )
}

fn open_budget() -> RecoveryTimeBudgetV1 {
    RecoveryTimeBudgetV1 {
        remaining_micros: OPEN_BUDGET,
    }
}

/// AC1. The host dies after the provider committed sequence 2 but before the
/// receipt was written. Recovery must replay from 2, and the provider must end
/// with one effect per observation — not four for three observations.
#[test]
fn restart_mid_delivery_converges_without_duplicate_effects() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    let mut provider = ProviderEffects::default();

    {
        let store = journal(&path)?;
        for sequence in 1..=3 {
            assert!(matches!(
                store.append_admitted(&Builder::at_sequence(sequence).build()?)?,
                AppendOutcomeV1::Appended { .. }
            ));
        }
        let leased = store.lease_pending(&lease_request(T0, 3))?;
        assert_eq!(leased.len(), 3);

        // Sequence 1: applied and acknowledged.
        assert!(provider.apply(leased[0].idempotency_key.as_str()));
        store.record_attempt(&applied_receipt(&leased[0], T0))?;

        // Sequence 2: the provider committed, and the host died before it could
        // record the receipt. This is the exact window recovery exists for.
        assert!(provider.apply(leased[1].idempotency_key.as_str()));
    }

    // ---- restart ----
    let store = journal(&path)?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let now = T0 + SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 7, NO_POSITION)?, &control(now), now)?;
    match plan {
        RecoveryPlanV1::ReplayUnacknowledged {
            first_unacknowledged_sequence,
            last_journalled_sequence,
            unacknowledged_items,
            expected_state_generation,
        } => {
            assert_eq!(first_unacknowledged_sequence, SourceSequenceV1(2));
            assert_eq!(last_journalled_sequence, SourceSequenceV1(3));
            assert_eq!(unacknowledged_items, 2);
            assert_eq!(expected_state_generation, 7);
        }
        other => return Err(format!("expected replay, got {other:?}").into()),
    }
    assert!(plan.permits_delivery());

    // The dispatcher that comes back reaps both dead leases and redelivers.
    assert_eq!(store.reap_expired_leases(T0 + LEASE + SECOND, 64)?, 2);
    let redelivered = store.lease_pending(&lease_request(T0 + LEASE + 2 * SECOND, 10))?;
    assert_eq!(redelivered.len(), 2);
    for leased in &redelivered {
        let created = provider.apply(leased.idempotency_key.as_str());
        let receipt = if created {
            applied_receipt(leased, T0 + LEASE + 2 * SECOND)
        } else {
            receipt_for(
                leased,
                ObservationOutcomeV1::DuplicateAcknowledged,
                ObservationCommittedEffectV1::Duplicate,
                T0 + LEASE + 2 * SECOND,
            )
        };
        store.record_attempt(&receipt)?;
    }

    // Four delivery attempts reached the provider; three effects exist.
    assert_eq!(provider.apply_calls, 4);
    assert_eq!(provider.effects(), 3);

    let later = T0 + 2 * LEASE;
    let converged = runtime.assess(
        &checkpoint(SCHEMA_V1, 9, NO_POSITION)?,
        &control(later),
        later,
    )?;
    assert_eq!(
        converged,
        RecoveryPlanV1::Converged {
            acknowledged_through: Some(SourceSequenceV1(3)),
            expected_state_generation: 9,
        }
    );
    Ok(())
}

/// AC2. The watermark advances only across the contiguous acknowledged prefix
/// and remains monotonic after acknowledged rows are deleted.
#[test]
fn acknowledged_sequence_closes_gaps_and_is_monotonic_across_deletion() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    let store = journal(&path)?;
    for sequence in 1..=28 {
        store.append_admitted(&Builder::at_sequence(sequence).build()?)?;
    }
    let leased = store.lease_pending(&lease_request(T0, 28))?;
    assert_eq!(
        leased.len(),
        28,
        "fixture must span multiple gap-scan pages"
    );

    // A suffix larger than the internal page budget cannot authorize skipping
    // the still-unacknowledged prefix. Record it first so closing sequence one
    // has to continue across more than one bounded scan round.
    for item in leased.iter().skip(1) {
        store.record_attempt(&applied_receipt(item, T0))?;
    }
    assert_eq!(
        store
            .recovery_state(&target()?, open_budget())?
            .and_then(|state| state.acknowledged),
        None
    );

    // Observe the stored projection without starting another recovery round.
    let stored_sequence = || -> Result<u64, Box<dyn std::error::Error>> {
        Ok(u64::try_from(Connection::open(&path)?.query_row(
            "SELECT acknowledged_sequence FROM tdmem_observation_recovery_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?)?)
    };

    // This is the final receipt write. Its transaction may inspect one page,
    // even though all 28 rows now have acknowledging evidence.
    store.record_attempt(&applied_receipt(&leased[0], T0 + SECOND))?;
    assert_eq!(
        stored_sequence()?,
        8,
        "receipt exceeded its eight-row budget"
    );
    drop(store);

    // Real recovery assessments must finish the projection without any new or
    // duplicate receipt. Restart between rounds proves the resume is durable.
    let mut previous = 8;
    for expected in [16, 24, 28] {
        let store = journal(&path)?;
        assert_eq!(stored_sequence()?, previous);
        let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
        let now = T0 + 2 * SECOND;
        assert_eq!(
            runtime.assess(&checkpoint(SCHEMA_V1, 9, NO_POSITION)?, &control(now), now)?,
            RecoveryPlanV1::Converged {
                acknowledged_through: Some(SourceSequenceV1(expected)),
                expected_state_generation: 9,
            },
            "one assessment must refresh at most one eight-row page"
        );
        assert_eq!(stored_sequence()?, expected);
        for item in &leased {
            assert_eq!(store.receipts_for(&item.observation_id)?.len(), 1);
        }
        previous = expected;
    }
    let store = journal(&path)?;

    // Privacy deletion removes the acknowledged rows, but cannot lower the
    // already-proved durable prefix and re-propose provider effects.
    let receipt = store.forget_source(&ForgetSourceRequestV1 {
        forget_source_key: ForgetSourceKeyV1::new("forget:session-1")?,
        reason: "operator deletion request".to_owned(),
        requested_at_unix_micros: T0 + 3 * SECOND,
    })?;
    assert!(receipt.journal_rows_matched > 0);

    drop(store);
    let reopened = journal(&path)?;
    let after_deletion = reopened
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing after deletion and restart")?;
    assert_eq!(
        after_deletion
            .acknowledged
            .map(|position| position.sequence),
        Some(SourceSequenceV1(28))
    );
    Ok(())
}

/// AC3. A provider whose state schema moved is typed, names its repair, and
/// proposes no delivery at all.
#[test]
fn state_schema_change_is_typed_and_forbids_delivery() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    assert!(
        runtime
            .assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?
            .permits_delivery()
    );

    let now = T0 + SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V2, 4, NO_POSITION)?, &control(now), now)?;
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect: StateIncompatibilityV1::StateSchemaChanged { expected, reported },
            repair,
            automatic_attempts_remaining,
        } => {
            assert_eq!(expected, SCHEMA_V1);
            assert_eq!(reported, SCHEMA_V2);
            assert_eq!(*repair, RepairActionV1::MigrateProviderState);
            assert_eq!(*automatic_attempts_remaining, 2);
        }
        other => return Err(format!("expected a typed schema defect, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    assert_eq!(plan.expected_state_generation(), None);
    Ok(())
}

/// The cross-restart gap the supervisor cannot close: a *different* provider
/// implementation answering for the same pinned registration, with the same
/// state schema and a generation that never went backwards. Accepting it would
/// hand one implementation's acknowledged history to another.
#[test]
fn a_changed_implementation_identity_refuses_delivery_after_a_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    {
        let store = journal(&path)?;
        let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
        assert!(
            runtime
                .assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?
                .permits_delivery()
        );
    }

    // ---- restart, with only the implementation identity changed ----
    let store = journal(&path)?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let now = T0 + SECOND;
    let plan = runtime.assess(
        &checkpoint_from(OTHER_IMPLEMENTATION, SCHEMA_V1, 4, NO_POSITION)?,
        &control(now),
        now,
    )?;
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect: StateIncompatibilityV1::ImplementationIdentityChanged { expected, reported },
            repair,
            ..
        } => {
            assert_eq!(expected, IMPLEMENTATION);
            assert_eq!(reported, OTHER_IMPLEMENTATION);
            assert_eq!(*repair, RepairActionV1::MigrateProviderState);
        }
        other => return Err(format!("expected an identity defect, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    assert_eq!(plan.expected_state_generation(), None);

    // The refused identity is not silently adopted: the record still names the
    // implementation the host actually converged with.
    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing")?;
    assert_eq!(
        state.implementation_identity_sha256.as_deref(),
        Some(IMPLEMENTATION)
    );
    Ok(())
}

/// AC3. A generation that went backwards is a restore or a wipe, and the answer
/// is an explicit reset — never a silent reinitialization that would replay
/// acknowledged history into a provider that forgot it.
#[test]
fn state_generation_regression_is_typed_reset_required() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    runtime.assess(&checkpoint(SCHEMA_V1, 12, NO_POSITION)?, &control(T0), T0)?;

    let now = T0 + SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 5, NO_POSITION)?, &control(now), now)?;
    assert_eq!(
        plan.repair_action(),
        Some(RepairActionV1::ResetProviderState)
    );
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect:
                StateIncompatibilityV1::StateGenerationRegressed {
                    expected_at_least,
                    reported,
                },
            ..
        } => {
            assert_eq!(*expected_at_least, 12);
            assert_eq!(*reported, 5);
        }
        other => return Err(format!("expected a typed generation defect, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    Ok(())
}

/// AC3. A provider behind the host's own acknowledged watermark cannot be
/// reconstructed from unacknowledged rows, so the repair is a snapshot restore.
#[test]
fn provider_behind_the_acknowledged_watermark_requires_a_snapshot_restore() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    for sequence in 1..=3 {
        store.append_admitted(&Builder::at_sequence(sequence).build()?)?;
    }
    let leased = store.lease_pending(&lease_request(T0, 3))?;
    for item in &leased {
        store.record_attempt(&applied_receipt(item, T0))?;
    }
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let first = T0 + SECOND;
    runtime.assess(
        &checkpoint(SCHEMA_V1, 4, reported(3))?,
        &control(first),
        first,
    )?;

    let now = T0 + 2 * SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 4, reported(1))?, &control(now), now)?;
    assert_eq!(
        plan.repair_action(),
        Some(RepairActionV1::ResetProviderState)
    );
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect:
                StateIncompatibilityV1::AcknowledgedSequenceRegressed {
                    host_acknowledged,
                    provider_acknowledged,
                },
            ..
        } => {
            assert_eq!(*host_acknowledged, SourceSequenceV1(3));
            assert_eq!(*provider_acknowledged, Some(SourceSequenceV1(1)));
        }
        other => return Err(format!("expected a typed sequence regression, got {other:?}").into()),
    }
    Ok(())
}

/// A provider that keeps a replay position and reports that it holds *nothing*
/// under a host watermark of three has lost three effects. Modelling that as
/// "no evidence" would admit delivery into a provider that silently forgot
/// everything the outbox considers delivered.
#[test]
fn a_retained_but_empty_provider_position_under_a_watermark_is_a_lost_effect() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    for sequence in 1..=3 {
        store.append_admitted(&Builder::at_sequence(sequence).build()?)?;
    }
    let leased = store.lease_pending(&lease_request(T0, 3))?;
    for item in &leased {
        store.record_attempt(&applied_receipt(item, T0))?;
    }
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;

    let now = T0 + SECOND;
    let plan = runtime.assess(
        &checkpoint(SCHEMA_V1, 4, ProviderReplayPositionV1::ReportedNone)?,
        &control(now),
        now,
    )?;
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect:
                StateIncompatibilityV1::AcknowledgedSequenceRegressed {
                    host_acknowledged,
                    provider_acknowledged,
                },
            ..
        } => {
            assert_eq!(*host_acknowledged, SourceSequenceV1(3));
            assert_eq!(*provider_acknowledged, None);
        }
        other => return Err(format!("expected a sequence regression, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    Ok(())
}

/// A provider that kept its own replay position when the host last converged
/// and keeps none now lost the bookkeeping the host verified effects against.
#[test]
fn a_provider_that_abandons_its_replay_position_is_typed_and_refused() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    store.append_admitted(&Builder::at_sequence(1).build()?)?;
    let leased = store.lease_pending(&lease_request(T0, 1))?;
    store.record_attempt(&applied_receipt(&leased[0], T0))?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let first = T0 + SECOND;
    assert!(
        runtime
            .assess(
                &checkpoint(SCHEMA_V1, 4, reported(1))?,
                &control(first),
                first
            )?
            .permits_delivery()
    );

    let now = T0 + 2 * SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(now), now)?;
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect: StateIncompatibilityV1::ReplayPositionAbandoned { host_acknowledged },
            repair,
            ..
        } => {
            assert_eq!(*host_acknowledged, Some(SourceSequenceV1(1)));
            assert_eq!(*repair, RepairActionV1::ResetProviderState);
        }
        other => return Err(format!("expected an abandoned position, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    Ok(())
}

/// A provider that declares it keeps a replay position, and whose position the
/// host could not read, is refused rather than treated as one that keeps none.
#[test]
fn a_declared_but_unreadable_replay_position_refuses_delivery() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;

    let plan = runtime.assess(
        &checkpoint(SCHEMA_V1, 4, ProviderReplayPositionV1::Unreadable)?,
        &control(T0),
        T0,
    )?;
    assert!(matches!(
        plan,
        RecoveryPlanV1::StateIncompatible {
            defect: StateIncompatibilityV1::ReplayPositionUnreadable,
            repair: RepairActionV1::OperatorInvestigation,
            ..
        }
    ));
    assert!(!plan.permits_delivery());
    assert_eq!(plan.expected_state_generation(), None);
    // Nothing about the unreadable incarnation was accepted as the pinned
    // state identity.
    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing")?;
    assert_eq!(state.state_schema_version, None);
    Ok(())
}

/// AC3. A provider claiming a position the journal never held is not something
/// any automatic action can reconcile.
#[test]
fn provider_ahead_of_the_journal_ends_at_an_operator() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    store.append_admitted(&Builder::at_sequence(1).build()?)?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;

    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 1, reported(9))?, &control(T0), T0)?;
    assert_eq!(
        plan.repair_action(),
        Some(RepairActionV1::OperatorInvestigation)
    );
    match &plan {
        RecoveryPlanV1::StateIncompatible {
            defect:
                StateIncompatibilityV1::ProviderAheadOfJournal {
                    provider_acknowledged,
                    journal_highest,
                },
            ..
        } => {
            assert_eq!(*provider_acknowledged, SourceSequenceV1(9));
            assert_eq!(*journal_highest, Some(SourceSequenceV1(1)));
        }
        other => return Err(format!("expected provider-ahead, got {other:?}").into()),
    }
    assert!(!plan.permits_delivery());
    Ok(())
}

/// AC4. The automatic path is bounded, survives a restart, escalates to a named
/// operator repair, and is cleared by an actual convergence.
#[test]
fn automatic_repair_is_bounded_survives_restart_and_resets_on_convergence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    {
        let store = journal(&path)?;
        let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
        runtime.assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?;
        let now = T0 + SECOND;
        let first = runtime.assess(&checkpoint(SCHEMA_V2, 4, NO_POSITION)?, &control(now), now)?;
        assert!(matches!(
            first,
            RecoveryPlanV1::StateIncompatible {
                automatic_attempts_remaining: 1,
                ..
            }
        ));
    }

    // The consumed attempt is durable: a crash loop cannot buy itself an
    // unbounded automatic path by restarting. A different generation makes this
    // a *new* assessment of the same defect rather than a resubmission of the
    // one already recorded.
    let store = journal(&path)?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
    let now = T0 + 2 * SECOND;
    let escalated = runtime.assess(&checkpoint(SCHEMA_V2, 5, NO_POSITION)?, &control(now), now)?;
    match &escalated {
        RecoveryPlanV1::OperatorRepairRequired {
            repair,
            automatic_repair_attempts,
            max_automatic_attempts,
            ..
        } => {
            assert_eq!(*repair, RepairActionV1::MigrateProviderState);
            assert_eq!(*automatic_repair_attempts, 2);
            assert_eq!(*max_automatic_attempts, 2);
        }
        other => return Err(format!("expected operator escalation, got {other:?}").into()),
    }
    assert!(!escalated.permits_delivery());

    // The operator migrated the provider back onto the pinned schema.
    let recovered_at = T0 + 3 * SECOND;
    assert!(
        runtime
            .assess(
                &checkpoint(SCHEMA_V1, 5, NO_POSITION)?,
                &control(recovered_at),
                recovered_at
            )?
            .permits_delivery()
    );
    let recovered = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing after convergence")?;
    assert_eq!(recovered.automatic_repair_attempts, 0);
    assert_eq!(recovered.last_defect, None);
    assert_eq!(recovered.last_assessment_id, None);

    // A fresh defect starts the bounded path over rather than arriving
    // pre-escalated.
    let again = T0 + 4 * SECOND;
    assert!(matches!(
        runtime.assess(
            &checkpoint(SCHEMA_V2, 5, NO_POSITION)?,
            &control(again),
            again
        )?,
        RecoveryPlanV1::StateIncompatible {
            automatic_attempts_remaining: 1,
            ..
        }
    ));
    Ok(())
}

/// One logical assessment submitted many times — the shape of an ambiguous
/// result that is retried, or of a crash between the write and the plan —
/// consumes exactly one automatic attempt.
#[test]
fn resubmitting_one_assessment_consumes_a_single_repair_attempt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    {
        let store = journal(&path)?;
        let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
        runtime.assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?;
        for step in 1..=4 {
            let now = T0 + step * SECOND;
            let plan =
                runtime.assess(&checkpoint(SCHEMA_V2, 4, NO_POSITION)?, &control(now), now)?;
            assert!(matches!(
                plan,
                RecoveryPlanV1::StateIncompatible {
                    automatic_attempts_remaining: 2,
                    ..
                }
            ));
        }
        let state = store
            .recovery_state(&target()?, open_budget())?
            .ok_or("recovery state missing")?;
        assert_eq!(state.automatic_repair_attempts, 1);
    }

    // The same assessment after a crash is still the same assessment.
    let store = journal(&path)?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let now = T0 + 10 * SECOND;
    runtime.assess(&checkpoint(SCHEMA_V2, 4, NO_POSITION)?, &control(now), now)?;
    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing after restart")?;
    assert_eq!(state.automatic_repair_attempts, 1);
    Ok(())
}

/// Two dispatchers racing one incarnation submit the same assessment. The
/// counter is a bound on distinct assessments, not on submissions, so the race
/// must not consume two attempts.
#[test]
fn concurrent_duplicate_assessments_consume_a_single_repair_attempt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    let store = journal(&path)?;
    {
        let runtime = RecoveryRuntimeV1::new(&store, budget(4))?;
        runtime.assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?;
    }

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for step in 0..4 {
            let store = &store;
            handles.push(scope.spawn(move || -> Result<(), String> {
                let runtime =
                    RecoveryRuntimeV1::new(store, budget(4)).map_err(|error| error.to_string())?;
                let now = T0 + (step + 1) * SECOND;
                let checkpoint = checkpoint(SCHEMA_V2, 4, NO_POSITION)
                    .map_err(|error| format!("checkpoint: {error}"))?;
                runtime
                    .assess(&checkpoint, &control(now), now)
                    .map_err(|error| error.to_string())?;
                Ok(())
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(result) => result?,
                Err(_) => return Err("recovery assessment thread panicked".into()),
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing")?;
    assert_eq!(state.automatic_repair_attempts, 1);
    Ok(())
}

/// Assessment continues after escalation — a supervisor keeps trying, an
/// operator keeps looking. The stored counter must stop at the ceiling instead
/// of climbing forever.
#[test]
fn repeated_assessment_after_escalation_cannot_drive_the_counter_past_the_ceiling() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
    runtime.assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control(T0), T0)?;

    // Each pass is a genuinely new assessment: the reported generation moves.
    for step in 1..=6u64 {
        let now = T0 + i64::try_from(step)? * SECOND;
        let plan = runtime.assess(
            &checkpoint(SCHEMA_V2, 4 + step, NO_POSITION)?,
            &control(now),
            now,
        )?;
        assert!(!plan.permits_delivery());
        if step >= 2 {
            assert!(matches!(
                plan,
                RecoveryPlanV1::OperatorRepairRequired {
                    automatic_repair_attempts: 2,
                    max_automatic_attempts: 2,
                    ..
                }
            ));
        }
    }
    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing")?;
    assert_eq!(
        state.automatic_repair_attempts, 2,
        "the stored counter must be structurally bounded by the ceiling"
    );
    Ok(())
}

/// Cancellation reaches recovery itself, not only the provider call after it.
#[test]
fn a_cancelled_delivery_stops_recovery_before_it_writes() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let control = RecoveryControlV1::new(T0 + OPEN_BUDGET, cancellation);

    let error = runtime
        .assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control, T0)
        .err()
        .ok_or("a cancelled assessment must not return a plan")?;
    assert!(
        matches!(error, ObservationRuntimeError::RecoveryCancelled { .. }),
        "expected a typed cancellation, got {error:?}"
    );
    assert!(
        store.recovery_state(&target()?, open_budget())?.is_none(),
        "a cancelled assessment must not have written a recovery record"
    );
    Ok(())
}

/// An expired deadline is a terminal of its own, and it stops the assessment
/// before it touches the journal at all.
#[test]
fn an_expired_deadline_stops_recovery_before_it_reads() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
    let control = RecoveryControlV1::new(T0 - SECOND, CancellationToken::new());

    let error = runtime
        .assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control, T0)
        .err()
        .ok_or("an expired assessment must not return a plan")?;
    match error {
        ObservationRuntimeError::RecoveryDeadlineExceeded { stage } => {
            assert_eq!(stage, "journal read");
        }
        other => return Err(format!("expected a typed deadline terminal, got {other:?}").into()),
    }
    assert!(store.recovery_state(&target()?, open_budget())?.is_none());
    Ok(())
}

/// Recovery blocked behind another writer honours the caller's remaining
/// budget instead of the connection's fixed five-second busy timeout.
#[test]
fn recovery_blocked_by_another_writer_reports_the_budget_spent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("observation-journal.sqlite3");
    let store = journal(&path)?;

    // A second connection holds the write lock for the whole assessment.
    let mut blocker = Connection::open(&path)?;
    let held = blocker.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let runtime = RecoveryRuntimeV1::new(&store, budget(2))?;
    let control = RecoveryControlV1::new(T0 + 100_000, CancellationToken::new());
    let started = std::time::Instant::now();
    let error = runtime
        .assess(&checkpoint(SCHEMA_V1, 4, NO_POSITION)?, &control, T0)
        .err()
        .ok_or("a blocked assessment must not report convergence")?;
    let elapsed = started.elapsed();

    match error {
        ObservationRuntimeError::Journal(ObservationJournalError::BudgetExhausted {
            operation,
        }) => assert_eq!(operation, "recovery_state"),
        other => return Err(format!("expected a spent budget, got {other:?}").into()),
    }
    assert!(
        elapsed < std::time::Duration::from_millis(2_000),
        "the assessment waited {elapsed:?}, which is the fixed busy timeout rather than the caller's budget"
    );
    held.rollback()?;
    Ok(())
}

/// The frontier counts deliverable rows, not rows that merely never reached an
/// acknowledgement. A rejected row is never delivered again, so a target
/// carrying one must still be able to report convergence.
#[test]
fn a_permanently_rejected_row_does_not_hold_the_target_behind_forever() -> TestResult {
    let store = SqliteObservationJournal::open_in_memory(policy())?;
    for sequence in 1..=2 {
        store.append_admitted(&Builder::at_sequence(sequence).build()?)?;
    }
    let leased = store.lease_pending(&lease_request(T0, 2))?;
    store.record_attempt(&applied_receipt(&leased[0], T0))?;
    store.record_attempt(&receipt_for(
        &leased[1],
        ObservationOutcomeV1::RejectedContractViolation,
        ObservationCommittedEffectV1::None,
        T0,
    ))?;

    let runtime = RecoveryRuntimeV1::new(&store, budget(3))?;
    let now = T0 + SECOND;
    let plan = runtime.assess(&checkpoint(SCHEMA_V1, 1, NO_POSITION)?, &control(now), now)?;
    assert_eq!(
        plan,
        RecoveryPlanV1::Converged {
            acknowledged_through: Some(SourceSequenceV1(1)),
            expected_state_generation: 1,
        },
        "a rejected delivery is not outstanding work"
    );

    // The rejection did not move the watermark either: only an acknowledgement
    // may, and the row at sequence 2 was never acknowledged.
    let state = store
        .recovery_state(&target()?, open_budget())?
        .ok_or("recovery state missing")?;
    assert_eq!(
        state.acknowledged.map(|position| position.sequence),
        Some(SourceSequenceV1(1))
    );
    Ok(())
}
