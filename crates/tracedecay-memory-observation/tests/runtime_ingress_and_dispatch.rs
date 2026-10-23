//! The ingress and delivery runtime seam.
//!
//! These tests drive the runtime the way a host process would — recover, ingest
//! in order, wake, lease, dispatch, record — and then check the things that only
//! a *durable* seam gets right: a restart resumes from the journal rather than
//! memory, a decision that names the wrong event never moves a watermark, a
//! refusal stops the batch instead of leaving a hole behind it, and an
//! acknowledgement lost between the provider's commit and the local write is
//! redelivered rather than recorded as a failure.

mod support;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use support::{
    Builder, INSTANCE, LEASE, MINUTE, PROVENANCE_DIGEST, PROVIDER, PROVIDER_RECEIPT_DIGEST, SECOND,
    T0, TestResult, ingest_control, journal, lane, lease_request, policy, stream_key, withheld_at,
};

use tracedecay_memory_observation::{
    AdmissionDecisionV1, AppendOutcomeV1, AttemptRefusalCategoryV1, BackpressureReasonV1,
    BackpressureStateV1, DeliveryAttemptV1, DeliveryControlV1, DeliveryRuntimeV1, DeliveryStateV1,
    DeliveryWakeV1, DispatchPolicyV1, DispatchRequestV1, IngressControlV1, IngressResumeV1,
    IngressRuntimeV1, JournalInspectionFilterV1, LeasedObservationV1,
    ObservationAdmissionAdapterV1, ObservationCommittedEffectV1, ObservationDispatchPortV1,
    ObservationJournalError, ObservationJournalReaderV1, ObservationLaneKeyV1,
    ObservationLoadClassV1, ObservationOutcomeV1, ObservationRuntimeError,
    ProviderDeliveryAdapterV1, ReplayDispositionV1, RetentionClassV1, RetentionPolicyV1,
    RetryBackoffV1, ShutdownRequestV1, SourceRecordV1, SourceSequenceV1, SqliteObservationJournal,
    WakeOutcomeV1,
};
use tracedecay_memory_provider_api::contract::TerminalCode;
use tracedecay_memory_provider_api::{
    CommittedEffectEvidence, FallbackDirective, ProviderOperation, TerminalRecord,
};

// ---------------------------------------------------------------- adapters --

/// A caller-owned adapter failure, so the runtime has something typed to carry.
#[derive(Debug)]
struct AdapterError(String);

impl Display for AdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AdapterError {}

fn adapter_error(error: &dyn Display) -> AdapterError {
    AdapterError(error.to_string())
}

/// Admission that mints the envelope a real pipeline would mint for the record,
/// withholding exactly the sequences it was told to withhold.
struct FixtureAdmission {
    lane: ObservationLaneKeyV1,
    withhold_at: BTreeSet<u64>,
    /// Offsets the sequence the *decision* claims, to prove the runtime refuses
    /// a decision that answers about another event.
    sequence_drift: u64,
    calls: Cell<u32>,
}

impl FixtureAdmission {
    fn admitting(lane: ObservationLaneKeyV1) -> Self {
        Self {
            lane,
            withhold_at: BTreeSet::new(),
            sequence_drift: 0,
            calls: Cell::new(0),
        }
    }

    fn withholding(lane: ObservationLaneKeyV1, sequences: &[u64]) -> Self {
        Self {
            lane,
            withhold_at: sequences.iter().copied().collect(),
            sequence_drift: 0,
            calls: Cell::new(0),
        }
    }

    fn drifting(lane: ObservationLaneKeyV1) -> Self {
        Self {
            lane,
            withhold_at: BTreeSet::new(),
            sequence_drift: 1,
            calls: Cell::new(0),
        }
    }
}

impl ObservationAdmissionAdapterV1 for FixtureAdmission {
    type Record = ();
    type Error = AdapterError;
    type Control = dyn IngressControlV1;

    fn lane(&self, _record: &SourceRecordV1<Self::Record>) -> ObservationLaneKeyV1 {
        self.lane.clone()
    }

    fn classify(&self, _record: &SourceRecordV1<Self::Record>) -> ObservationLoadClassV1 {
        // Every fixture envelope is project-lifetime, so the class the gate
        // sees up front is the class the envelope will carry.
        ObservationLoadClassV1::of(RetentionClassV1::Project)
    }

    fn decide(
        &self,
        record: &SourceRecordV1<Self::Record>,
        _control: &Self::Control,
    ) -> Result<AdmissionDecisionV1, Self::Error> {
        self.calls.set(self.calls.get().saturating_add(1));
        let sequence = record.source_sequence.0.saturating_add(self.sequence_drift);
        if self.withhold_at.contains(&sequence) {
            let withheld =
                withheld_at(sequence, "forget:session-1").map_err(|error| adapter_error(&error))?;
            return Ok(AdmissionDecisionV1::Withhold(Box::new(withheld)));
        }
        let admitted = Builder::at_sequence(sequence)
            .build()
            .map_err(|error| adapter_error(&error))?;
        Ok(AdmissionDecisionV1::Admit(Box::new(admitted)))
    }
}

/// What a scripted provider does with one attempt.
#[derive(Clone, Copy, Debug)]
enum AnswerV1 {
    /// Applies the observation and acknowledges it.
    Applied,
    /// Applies the observation but the acknowledgement never gets back. This is
    /// the ack-before-local-ack shape.
    LostAcknowledgement,
    /// The transport itself failed before any answer.
    TransportFailed,
    /// Answers with a terminal that describes a different exact scope.
    AnswersAboutAnotherScope,
}

/// One delivery the provider actually saw.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DeliveredV1 {
    idempotency_key: String,
    payload_sha256: String,
    payload_bytes: Vec<u8>,
    attempt_number: u32,
}

struct ScriptedProvider {
    answers: RefCell<VecDeque<AnswerV1>>,
    fallback: AnswerV1,
    seen: RefCell<Vec<DeliveredV1>>,
    /// Bodies the provider considers already applied, keyed by idempotency key.
    applied: RefCell<BTreeSet<String>>,
    now: Cell<i64>,
}

impl ScriptedProvider {
    fn new(fallback: AnswerV1, now: i64) -> Self {
        Self {
            answers: RefCell::new(VecDeque::new()),
            fallback,
            seen: RefCell::new(Vec::new()),
            applied: RefCell::new(BTreeSet::new()),
            now: Cell::new(now),
        }
    }

    fn scripted(answers: &[AnswerV1], fallback: AnswerV1, now: i64) -> Self {
        let provider = Self::new(fallback, now);
        *provider.answers.borrow_mut() = answers.iter().copied().collect();
        provider
    }

    fn advance_to(&self, now: i64) {
        self.now.set(now);
    }
}

impl ProviderDeliveryAdapterV1 for ScriptedProvider {
    type Error = AdapterError;

    fn deliver(
        &self,
        leased: &LeasedObservationV1,
        _control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        self.seen.borrow_mut().push(DeliveredV1 {
            idempotency_key: leased.idempotency_key.as_str().to_owned(),
            payload_sha256: leased.payload.sha256.clone(),
            payload_bytes: leased.payload.bytes.clone(),
            attempt_number: leased.attempt_number,
        });
        let answer = self
            .answers
            .borrow_mut()
            .pop_front()
            .unwrap_or(self.fallback);
        let started = self.now.get();
        let finished = started.saturating_add(1_000);
        match answer {
            AnswerV1::TransportFailed => Err(AdapterError(format!(
                "transport failed before the provider answered attempt {}",
                leased.attempt_number
            ))),
            AnswerV1::LostAcknowledgement => {
                // The provider committed; only the answer was lost.
                self.applied
                    .borrow_mut()
                    .insert(leased.idempotency_key.as_str().to_owned());
                Ok(DeliveryAttemptV1::Unanswered)
            }
            AnswerV1::Applied => {
                self.applied
                    .borrow_mut()
                    .insert(leased.idempotency_key.as_str().to_owned());
                let terminal = observe_success(leased, leased.exact_scope_sha256.clone())
                    .map_err(|error| adapter_error(&error))?;
                Ok(DeliveryAttemptV1::Answered {
                    terminal: Box::new(terminal),
                    started_at_unix_micros: started,
                    finished_at_unix_micros: finished,
                })
            }
            AnswerV1::AnswersAboutAnotherScope => {
                let terminal = observe_success(leased, PROVENANCE_DIGEST.to_owned())
                    .map_err(|error| adapter_error(&error))?;
                Ok(DeliveryAttemptV1::Answered {
                    terminal: Box::new(terminal),
                    started_at_unix_micros: started,
                    finished_at_unix_micros: finished,
                })
            }
        }
    }
}

fn observe_success(
    leased: &LeasedObservationV1,
    exact_scope_sha256: String,
) -> Result<TerminalRecord, Box<dyn Error>> {
    Ok(TerminalRecord::new(
        ProviderOperation::Observe,
        leased.target.provider_id.clone(),
        TerminalCode::Success,
        CommittedEffectEvidence::committed(
            1,
            2,
            Vec::new(),
            PROVIDER_RECEIPT_DIGEST,
            PROVENANCE_DIGEST,
        )?,
        FallbackDirective::forbidden(),
        format!("observe-{}", leased.observation_id.as_str()),
        exact_scope_sha256,
        None,
    )?)
}

// ----------------------------------------------------------------- helpers --

fn record_at(sequence: u64) -> Result<SourceRecordV1<()>, Box<dyn Error>> {
    Ok(SourceRecordV1 {
        stream: stream_key("session-1")?,
        source_sequence: SourceSequenceV1(sequence),
        source_event_id: format!("event-{sequence}"),
        source_event_revision: 0,
        record: (),
    })
}

fn records(sequences: &[u64]) -> Result<Vec<SourceRecordV1<()>>, Box<dyn Error>> {
    sequences.iter().copied().map(record_at).collect()
}

/// The per-attempt budget every fixture round hands out: shorter than the
/// fixture lease, so the lease never becomes the binding bound by accident.
const ATTEMPT_BUDGET: i64 = 5 * SECOND;

fn dispatch_at(now: i64) -> DispatchRequestV1 {
    DispatchRequestV1 {
        lease: lease_request(now, 8),
        retry_backoff: RetryBackoffV1::of(&policy()),
        attempt_budget_micros: ATTEMPT_BUDGET,
    }
}

fn receipts_for_sequence(
    store: &SqliteObservationJournal,
    sequence: u64,
) -> Result<usize, Box<dyn Error>> {
    let page = store.inspect(&JournalInspectionFilterV1 {
        limit: 100,
        ..JournalInspectionFilterV1::default()
    })?;
    let row = page
        .rows
        .iter()
        .find(|row| row.source_sequence == SourceSequenceV1(sequence))
        .ok_or_else(|| format!("no delivery row at sequence {sequence}"))?;
    Ok(store.receipts_for(&row.observation_id)?.len())
}

/// A provider that stays inside the call until the control it was handed is
/// cancelled or its deadline passes, and reports how long that took. This is
/// the in-flight case: shutdown must reach a provider that is *inside* a
/// delivery, not only a worker parked between rounds.
struct BlockingProvider {
    in_flight: AtomicBool,
    attempts: AtomicU32,
    /// Wall-clock instant the provider was told to stop, when it was.
    released_after: Mutex<Option<Duration>>,
    /// Simulated wall clock the provider uses to judge its deadline.
    now: i64,
    /// Longest the provider will stay inside one call regardless of control.
    /// This is the test's own safety net, never the bound under test.
    hard_stop: Duration,
}

impl BlockingProvider {
    fn new(now: i64, hard_stop: Duration) -> Self {
        Self {
            in_flight: AtomicBool::new(false),
            attempts: AtomicU32::new(0),
            released_after: Mutex::new(None),
            now,
            hard_stop,
        }
    }
}

impl ProviderDeliveryAdapterV1 for BlockingProvider {
    type Error = AdapterError;

    fn deliver(
        &self,
        _leased: &LeasedObservationV1,
        control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.in_flight.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let token = control.cancellation();
        // A real provider polls the control it was handed; this one does the
        // same on a tight cadence so the measured stop is the token, not the
        // poll interval.
        while !token.is_cancelled() && started.elapsed() < self.hard_stop {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.in_flight.store(false, Ordering::SeqCst);
        *self
            .released_after
            .lock()
            .map_err(|error| AdapterError(error.to_string()))? = Some(started.elapsed());
        if token.is_cancelled() {
            // The provider stopped before committing anything: no answer, no
            // receipt, and the remaining budget is reported truthfully.
            // The control really is cancelled, so the row goes back
            // eligible at once rather than serving a backoff for a shutdown
            // it did not cause.
            return Ok(DeliveryAttemptV1::CancelledByShutdown {
                started_at_unix_micros: self.now,
                finished_at_unix_micros: self.now,
            });
        }
        Err(AdapterError(format!(
            "provider ran past its hard stop with {} micros of budget left",
            control.remaining_micros(self.now)
        )))
    }
}

/// A provider that requests shutdown from *inside* its first delivery, the way
/// a daemon teardown racing a batch would, and records each attempt's bound.
struct ShutdownDuringBatchProvider<'a> {
    wake: &'a DeliveryWakeV1,
    deadlines: RefCell<Vec<(u32, i64)>>,
}

impl ProviderDeliveryAdapterV1 for ShutdownDuringBatchProvider<'_> {
    type Error = AdapterError;

    fn deliver(
        &self,
        leased: &LeasedObservationV1,
        control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        self.deadlines
            .borrow_mut()
            .push((leased.attempt_number, control.deadline_unix_micros()));
        assert!(
            !control.is_cancelled(),
            "an attempt must never be started under an already-cancelled control"
        );
        self.wake.request_shutdown();
        assert!(
            control.is_cancelled(),
            "the control handed to an attempt must be the wake edge's own token"
        );
        Ok(DeliveryAttemptV1::CancelledByShutdown {
            started_at_unix_micros: control.deadline_unix_micros(),
            finished_at_unix_micros: control.deadline_unix_micros(),
        })
    }
}

/// A provider that only records the bound it was handed.
struct DeadlineRecordingProvider {
    deadlines: RefCell<Vec<(u64, i64)>>,
}

impl ProviderDeliveryAdapterV1 for DeadlineRecordingProvider {
    type Error = AdapterError;

    fn deliver(
        &self,
        leased: &LeasedObservationV1,
        control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        self.deadlines
            .borrow_mut()
            .push((leased.source_sequence.0, control.deadline_unix_micros()));
        Ok(DeliveryAttemptV1::Unanswered)
    }
}

fn dispatch_policy() -> DispatchPolicyV1 {
    DispatchPolicyV1 {
        lease_duration_micros: LEASE,
        batch_max_items: 8,
        batch_max_bytes: 1_048_576,
        attempt_budget_micros: ATTEMPT_BUDGET,
        reap_budget: 16,
        max_rounds_per_drain: 4,
        drain_budget_micros: 30 * SECOND,
    }
}

fn state_of(
    store: &SqliteObservationJournal,
    sequence: u64,
) -> Result<DeliveryStateV1, Box<dyn Error>> {
    let page = store.inspect(&JournalInspectionFilterV1 {
        limit: 100,
        ..JournalInspectionFilterV1::default()
    })?;
    page.rows
        .iter()
        .find(|row| row.source_sequence == SourceSequenceV1(sequence))
        .map(|row| row.state)
        .ok_or_else(|| format!("no delivery row at sequence {sequence}").into())
}

// ------------------------------------------------------------------- tests --

#[test]
fn ingest_appends_in_order_wakes_delivery_and_replays_idempotently() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let stream = stream_key("session-1")?;

    let resume = ingress.recover(&stream)?;
    assert_eq!(resume.resume_after, None);

    let batch = records(&[1, 2, 3])?;
    let first = ingress.ingest(&resume, &batch)?;
    assert_eq!(first.appended, 3);
    assert_eq!(first.duplicates, 0);
    assert_eq!(first.high_watermark, Some(SourceSequenceV1(3)));
    assert!(first.halted_on.is_none());
    assert!(first.delivery_signalled);
    assert_eq!(wake.wait(Duration::from_millis(0)), WakeOutcomeV1::Work);

    // The second pass reads the durable cursor, not anything the first pass
    // remembered, and never even asks the adapter again.
    let calls_after_first = admission.calls.get();
    let resumed = ingress.recover(&stream)?;
    assert_eq!(resumed.resume_after, Some(SourceSequenceV1(3)));
    assert_eq!(
        resumed.last_disposition,
        Some(ReplayDispositionV1::Admitted)
    );

    let second = ingress.ingest(&resumed, &batch)?;
    assert_eq!(second.records_considered, 3);
    assert_eq!(second.already_processed, 3);
    assert_eq!(second.appended, 0);
    assert!(!second.delivery_signalled);
    assert_eq!(admission.calls.get(), calls_after_first);

    let page = store.inspect(&JournalInspectionFilterV1 {
        limit: 100,
        ..JournalInspectionFilterV1::default()
    })?;
    assert_eq!(page.total_rows, 3);
    Ok(())
}

#[test]
fn restart_resumes_from_the_journal_and_admits_only_what_is_new() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");

    // ---- phase 1: a process that dies after two records ----
    {
        let store = journal(&path)?;
        let wake = DeliveryWakeV1::new();
        let admission = FixtureAdmission::admitting(lane()?);
        let gate = support::gate()?;
        let control = ingest_control();
        let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
        let resume = ingress.recover(&stream_key("session-1")?)?;
        let report = ingress.ingest(&resume, &records(&[1, 2])?)?;
        assert_eq!(report.appended, 2);
    }

    // ---- phase 2: a brand-new process on the same file ----
    let store = journal(&path)?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);

    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(resume.resume_after, Some(SourceSequenceV1(2)));

    // The source replays its whole tail, as a recovering source does.
    let report = ingress.ingest(&resume, &records(&[1, 2, 3])?)?;
    assert_eq!(report.already_processed, 2);
    assert_eq!(report.appended, 1);
    assert_eq!(report.high_watermark, Some(SourceSequenceV1(3)));

    let page = store.inspect(&JournalInspectionFilterV1 {
        limit: 100,
        ..JournalInspectionFilterV1::default()
    })?;
    assert_eq!(page.total_rows, 3);
    Ok(())
}

#[test]
fn a_withheld_decision_advances_the_watermark_and_closes_that_position() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let hygiene = FixtureAdmission::withholding(lane()?, &[2]);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &hygiene, &wake, &gate, &control);
    let stream = stream_key("session-1")?;

    let resume = ingress.recover(&stream)?;
    let report = ingress.ingest(&resume, &records(&[1, 2, 3])?)?;
    assert_eq!(report.appended, 2);
    assert_eq!(report.withheld, 1);
    assert_eq!(report.high_watermark, Some(SourceSequenceV1(3)));

    // No delivery row was created for the refused position.
    let page = store.inspect(&JournalInspectionFilterV1 {
        limit: 100,
        ..JournalInspectionFilterV1::default()
    })?;
    assert_eq!(page.total_rows, 2);
    assert!(
        !page
            .rows
            .iter()
            .any(|row| row.source_sequence == SourceSequenceV1(2))
    );

    // A later run that tries to admit the refused position is refused by the
    // journal, and the runtime halts on that typed outcome instead of stepping
    // over it.
    let admitting = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let retry = IngressRuntimeV1::new(&store, &admitting, &wake, &gate, &control);
    let rewound = IngressResumeV1 {
        stream: stream.clone(),
        resume_after: Some(SourceSequenceV1(1)),
        last_disposition: Some(ReplayDispositionV1::Admitted),
        last_source_event_id: Some("event-1".to_owned()),
        updated_at_unix_micros: Some(T0),
    };
    let halted = retry.ingest(&rewound, &records(&[2])?)?;
    let halt = halted.halted_on.ok_or("expected a typed halt")?;
    assert_eq!(halt.source_sequence, SourceSequenceV1(2));
    assert!(matches!(
        halt.outcome,
        AppendOutcomeV1::RejectedWithheldSource { .. }
    ));
    assert_eq!(halted.appended, 0);
    Ok(())
}

#[test]
fn a_decision_about_another_event_never_moves_the_watermark() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let drifting = FixtureAdmission::drifting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &drifting, &wake, &gate, &control);
    let stream = stream_key("session-1")?;

    let resume = ingress.recover(&stream)?;
    let failure = ingress
        .ingest(&resume, &records(&[1])?)
        .err()
        .ok_or("a decision naming another event must be refused")?;
    match failure {
        ObservationRuntimeError::AdmissionIdentityMismatch { field, .. } => {
            assert_eq!(field, "source_sequence");
        }
        other => return Err(format!("unexpected failure: {other}").into()),
    }

    assert!(store.replay_cursor(&stream)?.is_none());
    Ok(())
}

#[test]
fn an_out_of_order_batch_is_refused_before_anything_is_appended() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let stream = stream_key("session-1")?;
    let resume = ingress.recover(&stream)?;

    let failure = ingress
        .ingest(&resume, &records(&[2, 1])?)
        .err()
        .ok_or("a reordered batch must be refused")?;
    assert!(matches!(
        failure,
        ObservationRuntimeError::UnorderedIngressBatch {
            previous: 2,
            received: 1
        }
    ));

    // Order is a precondition, not a mid-flight surprise: the leading record was
    // never appended and the stream has no cursor at all.
    assert!(store.replay_cursor(&stream)?.is_none());
    assert_eq!(admission.calls.get(), 0);
    Ok(())
}

#[test]
fn a_capacity_refusal_halts_the_batch_instead_of_leaving_a_hole() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteObservationJournal::open(
        directory.path().join("journal.sqlite3"),
        RetentionPolicyV1 {
            max_queue_items: 1,
            ..policy()
        },
    )?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let stream = stream_key("session-1")?;

    let resume = ingress.recover(&stream)?;
    let report = ingress.ingest(&resume, &records(&[1, 2, 3])?)?;
    assert_eq!(report.appended, 1);
    assert_eq!(report.high_watermark, Some(SourceSequenceV1(1)));
    // The ceiling is now enforced by the backpressure gate, one pressure read
    // ahead of the append, so the batch stops without paying for a transaction
    // that could only have answered `RejectedCapacity`.
    assert!(report.halted_on.is_none());
    let shed = report.shed_on.ok_or("expected a capacity shed")?;
    assert_eq!(shed.source_sequence, SourceSequenceV1(2));
    assert_eq!(shed.refusal.reason, BackpressureReasonV1::QueueCeiling);
    assert_eq!(shed.refusal.state, BackpressureStateV1::Saturated);

    // Sequence 3 was never offered, so the watermark still points at 1 and the
    // refused position stays admittable once capacity frees up.
    let cursor = store
        .replay_cursor(&stream)?
        .ok_or("cursor missing after a partial batch")?;
    assert_eq!(cursor.last_admitted_sequence, SourceSequenceV1(1));

    // The journal keeps its own typed capacity refusal for a co-located caller
    // that appends without going through ingress: the gate is a cheaper first
    // line, never the only one.
    let direct = Builder::at_sequence(2).build()?;
    assert!(matches!(
        store.append_admitted(&direct)?,
        AppendOutcomeV1::RejectedCapacity { queue_items: 1, .. }
    ));
    Ok(())
}

#[test]
fn delivery_sends_the_stored_bytes_and_records_one_receipt_per_attempt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(ingress.ingest(&resume, &records(&[1, 2])?)?.appended, 2);

    let provider = ScriptedProvider::new(AnswerV1::Applied, T0);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);
    assert_eq!(
        delivery.wait_for_work(Duration::from_millis(0)),
        WakeOutcomeV1::Work
    );

    let report = delivery.dispatch_batch(&dispatch_at(T0))?;
    assert_eq!(report.leased, 2);
    assert_eq!(report.receipts_recorded, 2);
    assert_eq!(report.settled_terminal, 2);
    assert_eq!(report.retry_scheduled, 0);
    assert!(report.failures.is_empty());

    // The provider saw the journal's own bytes, unmodified.
    let expected = Builder::at_sequence(1).build()?;
    let seen = provider.seen.borrow();
    let first = seen.first().ok_or("provider saw no delivery")?;
    assert_eq!(first.payload_bytes, expected.payload.bytes);
    assert_eq!(first.payload_sha256, expected.payload.sha256);
    assert_eq!(
        first.idempotency_key.as_str(),
        expected.idempotency_key.as_str()
    );
    assert_eq!(first.attempt_number, 1);

    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Acknowledged);
    assert_eq!(state_of(&store, 2)?, DeliveryStateV1::Acknowledged);
    Ok(())
}

#[test]
fn an_acknowledgement_lost_after_the_provider_committed_is_redelivered() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(ingress.ingest(&resume, &records(&[1])?)?.appended, 1);

    // Attempt 1: the provider commits, the acknowledgement never arrives.
    let provider = ScriptedProvider::scripted(
        &[AnswerV1::LostAcknowledgement],
        AnswerV1::Applied,
        T0 + MINUTE,
    );
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);
    let first = delivery.dispatch_batch(&dispatch_at(T0))?;
    assert_eq!(first.leased, 1);
    assert_eq!(first.leases_released, 1);
    assert_eq!(first.receipts_recorded, 0);
    assert!(first.failures.is_empty());

    let observation = Builder::at_sequence(1).build()?;
    assert!(store.receipts_for(&observation.observation_id)?.is_empty());
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);

    // Attempt 2: the same bytes under the same content-derived key. A provider
    // that already applied it recognises the key; nothing here fabricates an
    // outcome for the attempt whose answer was lost.
    provider.advance_to(T0 + 2 * MINUTE);
    let second = delivery.dispatch_batch(&dispatch_at(T0 + 2 * MINUTE))?;
    assert_eq!(second.leased, 1);
    assert_eq!(second.receipts_recorded, 1);
    assert_eq!(second.settled_terminal, 1);

    let seen = provider.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].idempotency_key, seen[1].idempotency_key);
    assert_eq!(seen[0].payload_sha256, seen[1].payload_sha256);
    // The claim consumed attempt 1, so the redelivery is attempt 2 and can never
    // collide with the receipt slot the lost attempt would have used.
    assert_eq!(seen[0].attempt_number, 1);
    assert_eq!(seen[1].attempt_number, 2);
    assert_eq!(provider.applied.borrow().len(), 1);

    let receipts = store.receipts_for(&observation.observation_id)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].attempt_number, 2);
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Acknowledged);
    Ok(())
}

#[test]
fn an_adapter_failure_releases_the_lease_and_reports_the_cause() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(ingress.ingest(&resume, &records(&[1])?)?.appended, 1);

    let provider = ScriptedProvider::new(AnswerV1::TransportFailed, T0);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);
    let report = delivery.dispatch_batch(&dispatch_at(T0))?;

    assert_eq!(report.receipts_recorded, 0);
    assert_eq!(report.leases_released, 1);
    assert_eq!(report.failures.len(), 1);
    let failure = report.failures.first().ok_or("expected one failure")?;
    assert_eq!(failure.attempt_number, 1);
    assert!(failure.lease_released);
    assert!(failure.cause.to_string().contains("transport failed"));

    let observation = Builder::at_sequence(1).build()?;
    assert!(store.receipts_for(&observation.observation_id)?.is_empty());
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);
    Ok(())
}

#[test]
fn a_terminal_about_another_scope_becomes_only_unknown_effect_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(ingress.ingest(&resume, &records(&[1])?)?.appended, 1);

    let provider = ScriptedProvider::new(AnswerV1::AnswersAboutAnotherScope, T0);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);
    let report = delivery.dispatch_batch(&dispatch_at(T0))?;

    assert_eq!(report.receipts_recorded, 1);
    assert_eq!(report.failures.len(), 1);
    let failure = report.failures.first().ok_or("expected one failure")?;
    assert!(
        failure.cause.to_string().contains("exact_scope_sha256"),
        "unexpected cause: {}",
        failure.cause
    );

    let observation = Builder::at_sequence(1).build()?;
    let receipts = store.receipts_for(&observation.observation_id)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, ObservationOutcomeV1::EffectUnknown);
    assert_eq!(
        receipts[0].committed_effect,
        ObservationCommittedEffectV1::Unknown
    );
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);

    // The host-owned receipt records the terminal attempt without accepting
    // its effect claim; the refusal retains why the answer was inadmissible.
    assert_eq!(report.refusals_recorded, 1);
    let refusals = store.attempt_refusals_for(&observation.observation_id)?;
    assert_eq!(refusals.len(), 1);
    let refusal = refusals.first().ok_or("expected one refusal")?;
    assert_eq!(refusal.attempt_number, 1);
    assert_eq!(
        refusal.category,
        AttemptRefusalCategoryV1::TerminalIdentityMismatch
    );
    assert_eq!(refusal.refused_field, "exact_scope_sha256");
    assert_eq!(
        refusal.expected,
        Some(observation.exact_scope.exact_scope_sha256())
    );
    assert_eq!(refusal.provided.as_deref(), Some(PROVENANCE_DIGEST));
    Ok(())
}

#[test]
fn shutdown_is_bounded_and_reports_outstanding_leases_truthfully() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream_key("session-1")?)?;
    assert_eq!(ingress.ingest(&resume, &records(&[1])?)?.appended, 1);

    // A dispatcher that claimed the row and died leaves an expiring lease.
    assert_eq!(store.lease_pending(&lease_request(T0, 4))?.len(), 1);

    let provider = ScriptedProvider::new(AnswerV1::Applied, T0);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);

    let early = delivery.shutdown(&ShutdownRequestV1 {
        provider_id: PROVIDER.to_owned(),
        now_unix_micros: T0 + SECOND,
        reap_budget: 16,
    })?;
    assert_eq!(early.leases_reaped, 0);
    assert_eq!(early.leases_outstanding, 1);
    assert!(!early.quiesced);
    assert!(wake.is_shutdown());
    assert_eq!(
        delivery.wait_for_work(Duration::from_millis(0)),
        WakeOutcomeV1::ShutdownRequested
    );

    let late = delivery.shutdown(&ShutdownRequestV1 {
        provider_id: PROVIDER.to_owned(),
        now_unix_micros: T0 + LEASE + SECOND,
        reap_budget: 16,
    })?;
    assert_eq!(late.leases_reaped, 1);
    assert_eq!(late.leases_outstanding, 0);
    assert!(late.quiesced);
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);
    Ok(())
}

#[test]
fn the_wake_edge_times_out_and_lets_shutdown_outrank_pending_work() -> TestResult {
    let wake = DeliveryWakeV1::new();
    assert_eq!(
        wake.wait(Duration::from_millis(1)),
        WakeOutcomeV1::TimedOut,
        "an unsignalled wait must come back on its own bound"
    );

    wake.signal();
    wake.signal();
    assert_eq!(wake.wait(Duration::from_millis(0)), WakeOutcomeV1::Work);
    assert_eq!(
        wake.wait(Duration::from_millis(1)),
        WakeOutcomeV1::TimedOut,
        "repeated signals collapse into one"
    );

    wake.signal();
    wake.request_shutdown();
    assert_eq!(
        wake.wait(Duration::from_millis(0)),
        WakeOutcomeV1::ShutdownRequested
    );
    Ok(())
}

// ------------------------------------------------------- cancellation bound --

#[test]
fn shutdown_cancels_an_in_flight_attempt_within_the_bound_and_records_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");
    let store = journal(&path)?;
    store.append_admitted(&Builder::at_sequence(1).build()?)?;
    let wake = DeliveryWakeV1::new();
    // The provider's own hard stop is far past the bound under test, so a pass
    // proves the token stopped it, not the provider giving up on its own.
    let hard_stop = Duration::from_secs(20);
    let declared_bound = Duration::from_secs(2);
    let provider = BlockingProvider::new(T0, hard_stop);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);

    let report = std::thread::scope(|scope| -> Result<_, Box<dyn Error>> {
        let round = scope.spawn(|| delivery.dispatch_batch(&dispatch_at(T0)));
        let waited = Instant::now();
        while !provider.in_flight.load(Ordering::SeqCst) {
            assert!(
                waited.elapsed() < declared_bound,
                "the attempt never reached the provider"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let requested = Instant::now();
        wake.request_shutdown();
        let report = round.join().map_err(|_| "dispatch round panicked")??;
        assert!(
            requested.elapsed() < declared_bound,
            "shutdown took {:?} to stop the in-flight attempt; declared bound {:?}",
            requested.elapsed(),
            declared_bound
        );
        Ok(report)
    })?;

    assert_eq!(provider.attempts.load(Ordering::SeqCst), 1);
    let released_after = provider
        .released_after
        .lock()
        .map_err(|error| error.to_string())?
        .ok_or("the provider never reported leaving the call")?;
    assert!(
        released_after < declared_bound,
        "provider left the call after {released_after:?}"
    );
    assert_eq!(report.leased, 1);
    assert_eq!(report.cancelled_in_flight, 1);
    assert_eq!(report.cancelled_before_dispatch, 0);
    assert_eq!(report.leases_released, 1);
    assert_eq!(report.receipts_recorded, 1);
    assert!(report.failures.is_empty());
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);

    let observation = Builder::at_sequence(1).build()?;
    let receipts = store.receipts_for(&observation.observation_id)?;
    assert_eq!(receipts.len(), 1);
    let cancelled = &receipts[0];
    assert_eq!(cancelled.provider_id.as_str(), PROVIDER);
    assert_eq!(cancelled.provider_instance_id.as_deref(), Some(INSTANCE));
    assert_eq!(cancelled.attempt_number, 1);
    assert_eq!(cancelled.outcome, ObservationOutcomeV1::Cancelled);
    assert_eq!(
        cancelled.committed_effect,
        ObservationCommittedEffectV1::Unknown,
        "shutdown cannot prove whether an isolated provider committed late"
    );
    assert_eq!(cancelled.started_at_unix_micros, T0);
    assert_eq!(cancelled.finished_at_unix_micros, T0);

    // The runtime then quiesces on its first pass: nothing is stranded.
    let shutdown = delivery.shutdown(&ShutdownRequestV1 {
        provider_id: PROVIDER.to_owned(),
        now_unix_micros: T0 + SECOND,
        reap_budget: 16,
    })?;
    assert!(shutdown.quiesced);
    assert_eq!(shutdown.leases_outstanding, 0);

    // And a round after shutdown leases nothing at all.
    let after = delivery.dispatch_batch(&dispatch_at(T0 + 2 * SECOND))?;
    assert_eq!(after.leased, 0);
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);

    drop(wake);
    drop(store);

    // Restart preserves the cancelled-attempt evidence while the observation
    // remains immediately redeliverable under its stable identity.
    let restarted = journal(&path)?;
    let receipts = restarted.receipts_for(&observation.observation_id)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, ObservationOutcomeV1::Cancelled);
    let redelivery = restarted.lease_pending(&lease_request(T0, 8))?;
    assert_eq!(redelivery.len(), 1);
    assert_eq!(redelivery[0].observation_id, observation.observation_id);
    assert_eq!(redelivery[0].idempotency_key, observation.idempotency_key);
    assert_eq!(redelivery[0].attempt_number, 2);
    Ok(())
}

#[derive(Debug)]
struct ErrorAfterShutdown<'a> {
    wake: &'a DeliveryWakeV1,
}

impl ProviderDeliveryAdapterV1 for ErrorAfterShutdown<'_> {
    type Error = AdapterError;

    fn deliver(
        &self,
        _leased: &LeasedObservationV1,
        _control: &DeliveryControlV1,
    ) -> Result<DeliveryAttemptV1, Self::Error> {
        self.wake.request_shutdown();
        Err(AdapterError("readiness cancelled".to_owned()))
    }
}

#[test]
fn adapter_error_racing_with_shared_shutdown_retains_the_failure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    let observation = Builder::at_sequence(1).build()?;
    store.append_admitted(&observation)?;
    let wake = DeliveryWakeV1::new();
    let provider = ErrorAfterShutdown { wake: &wake };
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);

    let report = delivery.dispatch_batch(&dispatch_at(T0))?;
    assert_eq!(report.cancelled_in_flight, 0);
    assert_eq!(report.receipts_recorded, 0);
    assert_eq!(report.leases_released, 1);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].cause.to_string(), "readiness cancelled");
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);
    assert!(
        store.receipts_for(&observation.observation_id)?.is_empty(),
        "an adapter error cannot manufacture cancellation evidence"
    );
    assert!(
        store.lease_pending(&lease_request(T0, 8))?.is_empty(),
        "an adapter failure keeps the ordinary retry backoff"
    );
    Ok(())
}

#[test]
fn shutdown_between_items_releases_the_rest_of_the_batch_without_an_attempt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    for sequence in 1..=3 {
        store.append_admitted(&Builder::at_sequence(sequence).build()?)?;
    }
    let wake = DeliveryWakeV1::new();
    let provider = ShutdownDuringBatchProvider {
        wake: &wake,
        deadlines: RefCell::new(Vec::new()),
    };
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);

    let report = delivery.dispatch_batch(&dispatch_at(T0))?;
    assert_eq!(report.leased, 3);
    assert_eq!(
        provider.deadlines.borrow().len(),
        1,
        "only the attempt already in flight may run after shutdown"
    );
    assert_eq!(report.cancelled_in_flight, 1);
    assert_eq!(report.cancelled_before_dispatch, 2);
    assert_eq!(report.leases_released, 3);
    assert_eq!(report.receipts_recorded, 1);
    assert!(report.failures.is_empty());
    for sequence in 1..=3 {
        assert_eq!(state_of(&store, sequence)?, DeliveryStateV1::Pending);
        assert_eq!(
            receipts_for_sequence(&store, sequence)?,
            usize::from(sequence == 1)
        );
    }
    // The rows released without an attempt are eligible again at once: a
    // later dispatcher (or the next life of this one) leases them immediately.
    assert_eq!(store.lease_pending(&lease_request(T0, 8))?.len(), 3);
    Ok(())
}

#[test]
fn an_attempt_deadline_is_the_tightest_of_budget_lease_and_row_deadline() -> TestResult {
    // Each budget gets its own journal: an attempt that produced no terminal is
    // rescheduled on the runtime's own retry curve, so the same rows are not
    // leasable twice at the same instant — which is precisely the property that
    // keeps a failed batch from looping inside one drain.
    fn deadlines_for(attempt_budget_micros: i64) -> Result<Vec<(u64, i64)>, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = journal(&directory.path().join("journal.sqlite3"))?;
        // Row 1 keeps the fixture's one-hour delivery deadline; row 2 must be
        // delivered within one second of the lease instant.
        store.append_admitted(&Builder::at_sequence(1).build()?)?;
        store.append_admitted(
            &Builder {
                deadline: T0 + SECOND,
                ..Builder::at_sequence(2)
            }
            .build()?,
        )?;
        let wake = DeliveryWakeV1::new();
        let provider = DeadlineRecordingProvider {
            deadlines: RefCell::new(Vec::new()),
        };
        let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);
        let report = delivery.dispatch_batch(&DispatchRequestV1 {
            lease: lease_request(T0, 8),
            retry_backoff: RetryBackoffV1::of(&policy()),
            attempt_budget_micros,
        })?;
        assert_eq!(report.leased, 2);
        let deadlines = provider.deadlines.borrow().clone();
        Ok(deadlines)
    }

    // A budget longer than the lease: the lease expiry binds row 1, the row's
    // own deadline binds row 2.
    assert_eq!(
        deadlines_for(2 * LEASE)?.as_slice(),
        &[(1, T0 + LEASE), (2, T0 + SECOND)]
    );

    // A budget shorter than either: the budget binds.
    assert_eq!(
        deadlines_for(ATTEMPT_BUDGET)?.as_slice(),
        &[(1, T0 + ATTEMPT_BUDGET), (2, T0 + SECOND)]
    );
    Ok(())
}

#[test]
fn a_dispatch_request_without_a_positive_attempt_budget_is_refused_before_leasing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = journal(&directory.path().join("journal.sqlite3"))?;
    store.append_admitted(&Builder::at_sequence(1).build()?)?;
    let wake = DeliveryWakeV1::new();
    let provider = ScriptedProvider::new(AnswerV1::Applied, T0);
    let delivery = DeliveryRuntimeV1::new(&store, &provider, &wake);

    for budget in [0, -1] {
        let error = delivery
            .dispatch_batch(&DispatchRequestV1 {
                lease: lease_request(T0, 8),
                retry_backoff: RetryBackoffV1::of(&policy()),
                attempt_budget_micros: budget,
            })
            .err()
            .ok_or("a non-positive attempt budget must be refused")?;
        assert!(matches!(
            error,
            ObservationRuntimeError::InvalidDispatchRequest {
                field: "attempt_budget_micros"
            }
        ));
    }
    assert!(provider.seen.borrow().is_empty());
    assert_eq!(state_of(&store, 1)?, DeliveryStateV1::Pending);
    assert_eq!(
        store.lease_pending(&lease_request(T0, 8))?.len(),
        1,
        "a refused request must not have taken a lease"
    );
    Ok(())
}

#[test]
fn a_dispatch_policy_is_bounded_by_the_retention_policy_it_runs_under() -> TestResult {
    let retention = policy();
    dispatch_policy().validate_against(&retention)?;

    let cases: [(&str, DispatchPolicyV1); 8] = [
        (
            "lease_duration_micros",
            DispatchPolicyV1 {
                lease_duration_micros: 0,
                ..dispatch_policy()
            },
        ),
        (
            "batch_max_items",
            DispatchPolicyV1 {
                batch_max_items: 0,
                ..dispatch_policy()
            },
        ),
        (
            "batch_max_items",
            DispatchPolicyV1 {
                batch_max_items: u32::try_from(retention.max_queue_items)?.saturating_add(1),
                ..dispatch_policy()
            },
        ),
        (
            "batch_max_bytes",
            DispatchPolicyV1 {
                batch_max_bytes: 0,
                ..dispatch_policy()
            },
        ),
        (
            "batch_max_bytes",
            DispatchPolicyV1 {
                batch_max_bytes: retention.max_queue_bytes + 1,
                ..dispatch_policy()
            },
        ),
        (
            "attempt_budget_micros",
            DispatchPolicyV1 {
                attempt_budget_micros: 0,
                ..dispatch_policy()
            },
        ),
        (
            "attempt_budget_micros",
            DispatchPolicyV1 {
                attempt_budget_micros: LEASE + 1,
                ..dispatch_policy()
            },
        ),
        (
            "reap_budget",
            DispatchPolicyV1 {
                reap_budget: 0,
                ..dispatch_policy()
            },
        ),
    ];
    for (expected, candidate) in cases {
        match candidate.validate_against(&retention) {
            Err(ObservationJournalError::InvalidDispatchPolicy { field }) => {
                assert_eq!(field, expected, "{candidate:?}");
            }
            other => {
                return Err(
                    format!("{candidate:?} was not refused on {expected}: {other:?}").into(),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn non_message_checkpoint_reopens_and_refuses_conflicts_and_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");
    let stream = stream_key("session-1")?;
    let source = Builder::at_sequence(1).build()?.source;
    {
        let store = journal(&path)?;
        store.record_non_message(&stream, &source)?;
        store.record_non_message(&stream, &source)?;
        let mut conflicting = source.clone();
        conflicting.source_event_id = "another-event".to_owned();
        assert!(store.record_non_message(&stream, &conflicting).is_err());
        assert!(
            store
                .append_admitted(&Builder::at_sequence(1).build()?)
                .is_err()
        );
        assert_eq!(
            store
                .inspect(&JournalInspectionFilterV1::default())?
                .total_rows,
            0
        );
    }
    let store = journal(&path)?;
    let cursor = store
        .replay_cursor(&stream)?
        .ok_or("durable checkpoint missing")?;
    assert_eq!(cursor.last_admitted_sequence, SourceSequenceV1(1));
    assert_eq!(cursor.last_disposition, ReplayDispositionV1::NonMessage);
    assert_eq!(cursor.last_source_event_id, source.source_event_id);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE tdmem_observation_replay_cursor_v1 SET last_settlement_proof_sha256='corrupt'",
        [],
    )?;
    assert!(store.replay_cursor(&stream).is_err());
    Ok(())
}

#[test]
fn non_message_position_survives_a_later_append_and_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");
    let stream = stream_key("session-1")?;
    let first = Builder::at_sequence(1).build()?;
    {
        let store = journal(&path)?;
        store.record_non_message(&stream, &first.source)?;
        assert!(matches!(
            store.append_admitted(&Builder::at_sequence(2).build()?)?,
            AppendOutcomeV1::Appended { .. }
        ));
    }
    let store = journal(&path)?;
    assert!(matches!(
        store.append_admitted(&first),
        Err(ObservationJournalError::SourceCheckpointConflict { sequence: 1 })
    ));
    // Identical evidence remains idempotent even behind the latest cursor.
    store.record_non_message(&stream, &first.source)?;
    assert_eq!(
        store
            .replay_cursor(&stream)?
            .ok_or("durable checkpoint missing")?
            .last_admitted_sequence,
        SourceSequenceV1(2)
    );
    assert!(matches!(
        store.record_withheld(&support::withheld_at(1, "subject-1")?),
        Err(ObservationJournalError::SourceCheckpointConflict { sequence: 1 })
    ));
    for change_revision in [false, true] {
        let mut changed = first.source.clone();
        if change_revision {
            changed.source_event_revision += 1;
        } else {
            changed.source_event_id = "changed-event".to_owned();
        }
        assert!(matches!(
            store.record_non_message(&stream, &changed),
            Err(ObservationJournalError::SourceCheckpointConflict { sequence: 1 })
        ));
    }
    Ok(())
}

#[test]
fn processed_positions_validate_identity_without_repeating_admission() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");
    let stream = stream_key("session-1")?;
    {
        let store = journal(&path)?;
        store.record_non_message(&stream, &Builder::at_sequence(1).build()?.source)?;
        store.append_admitted(&Builder::at_sequence(2).build()?)?;
        store.record_withheld(&support::withheld_at(3, "subject-3")?)?;
    }
    let store = journal(&path)?;
    let wake = DeliveryWakeV1::new();
    let admission = FixtureAdmission::admitting(lane()?);
    let gate = support::gate()?;
    let control = ingest_control();
    let ingress = IngressRuntimeV1::new(&store, &admission, &wake, &gate, &control);
    let resume = ingress.recover(&stream)?;
    assert_eq!(
        ingress
            .ingest(&resume, &records(&[1, 2, 3])?)?
            .already_processed,
        3
    );
    for sequence in [1, 2, 3] {
        for change_revision in [false, true] {
            let mut changed = record_at(sequence)?;
            if change_revision {
                changed.source_event_revision += 1;
            } else {
                changed.source_event_id = "changed-event".to_owned();
            }
            assert!(ingress.ingest(&resume, &[changed]).is_err());
        }
    }
    assert_eq!(admission.calls.get(), 0);
    Ok(())
}

#[test]
fn version_six_cursor_migrates_without_losing_admitted_positions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite3");
    let stream = stream_key("session-1")?;
    let first = Builder::at_sequence(1).build()?;
    let second = Builder::at_sequence(2).build()?;
    journal(&path)?.append_admitted(&first)?;
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "ALTER TABLE tdmem_observation_replay_cursor_v1 RENAME TO old_cursor;
             CREATE TABLE tdmem_observation_replay_cursor_v1 (
                 source_authority TEXT NOT NULL,
                 exact_scope_sha256 TEXT NOT NULL,
                 source_stream TEXT NOT NULL,
                 last_admitted_sequence INTEGER NOT NULL,
                 last_source_event_id TEXT NOT NULL,
                 last_source_event_revision TEXT NOT NULL,
                 last_settlement_proof_sha256 TEXT,
                 last_disposition TEXT NOT NULL CHECK (last_disposition IN ('admitted', 'withheld')),
                 updated_at_micros INTEGER NOT NULL,
                 PRIMARY KEY (source_authority, exact_scope_sha256, source_stream)
             ) WITHOUT ROWID;
             INSERT INTO tdmem_observation_replay_cursor_v1 SELECT * FROM old_cursor;
             DROP TABLE old_cursor;
             DROP TABLE tdmem_observation_non_message_v1;
             PRAGMA user_version=6;",
        )?;
    }
    {
        let store = journal(&path)?;
        assert!(matches!(
            store.append_admitted(&first)?,
            AppendOutcomeV1::DuplicateIdempotencyKey { .. }
        ));
        store.record_non_message(&stream, &second.source)?;
        store.append_admitted(&Builder::at_sequence(3).build()?)?;
    }
    let store = journal(&path)?;
    store.record_non_message(&stream, &second.source)?;
    assert!(matches!(
        store.append_admitted(&second),
        Err(ObservationJournalError::SourceCheckpointConflict { sequence: 2 })
    ));
    Ok(())
}
