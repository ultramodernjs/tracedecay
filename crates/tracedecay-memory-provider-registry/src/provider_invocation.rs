//! Host-owned execution boundary for synchronous provider work.
//!
//! Provider ports are synchronous: a recall reads a store on the calling
//! thread. The host still has to answer its caller at the caller's deadline —
//! or the moment the caller withdraws — and a provider that ignores both must
//! not be able to take the route down with it.
//!
//! # What the boundary actually controls
//!
//! Rust cannot stop a thread that is executing non-cooperative code. So the
//! boundary does not claim to terminate work it has no primitive for. Instead
//! it makes the *execution capability* an explicit, declared input and then
//! holds each provider to what that capability can honestly deliver:
//!
//! * The host supplies the worker capability
//!   ([`ProviderWorkerSpawnV1`]) and declares its
//!   [`ProviderWorkerIsolationV1`]. A `Terminable` host owns a real kill
//!   primitive — a supervised provider process is the intended shape — and
//!   [`ProviderWorkerHandleV1::terminate`] stops the worker without the
//!   provider's cooperation. A `CooperativeOnly` host runs the provider inside
//!   the host's own address space and has no such primitive.
//! * Each invocation declares the [`ProviderExecutionShapeV1`] of the code it
//!   is about to run. Foreign provider code is **refused before contact**
//!   ([`ProviderInvocationFaultV1::ExecutionNotIsolated`]) on a
//!   `CooperativeOnly` host: code the host did not write, cannot terminate,
//!   and cannot hold to a cancellation contract is not admitted at all. Only
//!   host-authored in-process code — the adapters this workspace compiles and
//!   is accountable for — runs on a non-terminable worker.
//! * Deadline **and** caller cancellation are raced against worker completion
//!   ([`ProviderInvocationBoundaryV1::invoke`]). Whichever fires first ends
//!   the caller's wait immediately; the caller never waits out a blocking
//!   provider after withdrawing.
//! * When the wait ends without an outcome the boundary asks the host to
//!   terminate the worker. A `Terminated` worker is proven gone: its slot is
//!   released, the provider is immediately routable again, and none of that
//!   needed the provider's cooperation. A worker the host cannot terminate is
//!   recorded as **stranded** — still running, no longer waited on, and
//!   published in [`ProviderInvocationBoundaryV1::worker_census`].
//! * Strands are finite and, on a `CooperativeOnly` host, deliberately scarce.
//!   A provider that owns
//!   [`ProviderInvocationLimitsV1::max_stranded_workers`] stranded workers is
//!   refused before contact ([`ProviderInvocationFaultV1::ProviderStalled`])
//!   until they return. That refusal is not a formality: a synchronous
//!   provider call holds its registration's serialized dispatch gate for as
//!   long as it runs, so admitting a second call would strand a second thread
//!   on the gate rather than reach the provider. Live workers are bounded
//!   independently ([`ProviderInvocationFaultV1::WorkerCapacityExhausted`]),
//!   so the threads one provider can occupy are bounded by
//!   `max_workers + max_stranded_workers` and never by an unbounded queue.
//!
//! # The honest limit
//!
//! On a `CooperativeOnly` host, a provider whose work *truly* never returns
//! leaves its route refused until that work returns. No accounting can undo
//! that: the work owns a host thread and the registration's dispatch gate, and
//! nothing in this process can take either back. That is precisely why foreign
//! code is not admitted there at all, and why the fix for a provider that can
//! hang is `Terminable` isolation — a supervised provider process — rather
//! than a larger strand allowance. With a `Terminable` host the same hang
//! costs one killed worker and the route is usable again immediately.
//!
//! Everything the boundary reports is derived from what actually happened to
//! the worker: a settled worker releases its slot, a terminated worker
//! releases it on the host's guarantee, and a stranded one releases the last
//! of its accounting when it finally returns.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use std::time::Duration;

/// One unit of provider work the host runs on a worker it owns.
pub type ProviderWorkV1 = Box<dyn FnOnce() + Send + 'static>;

/// Resolves when the caller of one invocation withdraws.
///
/// The boundary requires this: an invocation with no cancellation input is an
/// invocation that can only end at its deadline, which is exactly the
/// "cancellation reaches provider code but never the caller" defect this
/// boundary exists to prevent. A caller that genuinely has no cancellation
/// identity must say so by constructing a future that never resolves, in
/// full view of the reader.
pub type ProviderCancellationWaitV1 = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The host refused or failed to start a worker.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ProviderWorkerSpawnErrorV1(String);

impl ProviderWorkerSpawnErrorV1 {
    /// Records why the host could not start a worker.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

/// Whether the host can stop a worker that never returns on its own.
///
/// This is a statement about the host's *operating-system* capability, not
/// about any provider's good behaviour, and the boundary treats it as the
/// hard limit it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkerIsolationV1 {
    /// The host owns a kill primitive: [`ProviderWorkerHandleV1::terminate`]
    /// stops the worker without the provider's cooperation. A supervised
    /// provider process is the shape this describes.
    Terminable,
    /// The host runs the worker inside its own address space and has no way
    /// to stop code that ignores cancellation. Only host-authored provider
    /// code may run here.
    CooperativeOnly,
}

/// What happened when the host was asked to stop one worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkerTerminationV1 {
    /// The worker is gone. It will execute no further provider code and will
    /// never deliver an outcome. Answering this is a guarantee, not an
    /// attempt: the boundary reclaims the worker's capacity on it.
    Terminated,
    /// The worker had already returned before termination was requested.
    AlreadyExited,
    /// The host has no way to stop this worker; it is still running.
    NotTerminable,
}

/// A live worker the host started, and the host's handle to stop it.
pub trait ProviderWorkerHandleV1: Send + Sync {
    /// Stops the worker without the provider's cooperation.
    ///
    /// Answering [`ProviderWorkerTerminationV1::Terminated`] asserts the
    /// worker is gone. A host that cannot make that assertion must answer
    /// [`ProviderWorkerTerminationV1::NotTerminable`] so the boundary keeps
    /// the still-running worker counted instead of forgetting it.
    fn terminate(&self) -> ProviderWorkerTerminationV1;
}

/// The execution capability the composition root grants this crate.
///
/// The contract is deliberately one-way: the host starts `work` on a worker it
/// owns and **must not require the caller to join it**. That is what lets the
/// boundary answer at its deadline while a non-cooperative provider is still
/// running, and it is why the capability is injected rather than taken here --
/// the composition registry constructs no host capability of its own, so a
/// worker that outlives a deadline is owned, named, and shut down by the host
/// that created it.
pub trait ProviderWorkerSpawnV1: Send + Sync + 'static {
    /// Whether workers this host starts can be terminated without provider
    /// cooperation.
    fn isolation(&self) -> ProviderWorkerIsolationV1;

    /// Starts `work` on a host-owned worker named `name`, and returns a handle
    /// to it without waiting for it.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderWorkerSpawnErrorV1`] when the host cannot start a
    /// worker at all. The boundary reports that as a typed host fault and
    /// releases the slot; it never treats an unstarted worker as a provider
    /// outcome.
    fn spawn_detached(
        &self,
        name: &str,
        work: ProviderWorkV1,
    ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1>;
}

/// Who wrote the code one invocation is about to run.
///
/// This is declared per invocation because it is a property of the *provider*,
/// not of the host: the same host worker capability may serve an adapter this
/// workspace compiles and, later, a third-party provider it does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExecutionShapeV1 {
    /// The adapter is compiled into this process from this workspace. The host
    /// is accountable for its cancellation behaviour and for the conformance
    /// suite that holds it to it, which is what makes running it on a
    /// non-terminable worker an accountable decision rather than a hope.
    HostAuthoredInProcess,
    /// The adapter's implementation is foreign to the host. It is admitted
    /// only on a host that can terminate it.
    Foreign,
}

/// Everything one invocation declares before the provider is contacted.
pub struct ProviderInvocationRequestV1<'request> {
    /// Provider identity the worker budget is accounted against.
    pub provider_id: &'request str,
    /// Who wrote the code the worker will run.
    pub execution_shape: ProviderExecutionShapeV1,
    /// Longest the caller will wait for an outcome.
    pub budget: Duration,
    /// Resolves when the caller withdraws.
    pub cancelled: ProviderCancellationWaitV1,
}

/// Finite worker budget one boundary enforces per provider identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderInvocationLimitsV1 {
    /// Largest number of workers with a waiting caller one provider may own at
    /// once.
    pub max_workers: usize,
    /// Largest number of *stranded* workers -- running, unwaited, and beyond
    /// the host's power to stop -- one provider may own before it is refused
    /// before contact. A host that can terminate its workers never reaches
    /// this bound, because it never strands one.
    pub max_stranded_workers: usize,
}

impl ProviderInvocationLimitsV1 {
    /// Derives the worker budget from the fabric's in-flight budget.
    ///
    /// A provider may own at most as many waited workers as the fabric would
    /// admit concurrent active calls, and exactly one stranded one. The strand
    /// allowance is one rather than many on purpose: a stranded synchronous
    /// call still holds its registration's serialized dispatch gate, so a
    /// second call could only strand a second thread waiting on that gate. One
    /// is the number that bounds the damage without pretending the route
    /// recovered.
    #[must_use]
    pub const fn for_in_flight(max_in_flight: usize) -> Self {
        Self {
            max_workers: if max_in_flight == 0 { 1 } else { max_in_flight },
            max_stranded_workers: 1,
        }
    }
}

/// What one provider's workers are doing right now.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderWorkerCensusV1 {
    /// Workers whose caller is still waiting for them.
    pub live: usize,
    /// Workers still running with no caller waiting, which the host had no
    /// primitive to stop. They are counted here until they return, and they
    /// are what makes the provider refused before contact in the meantime.
    pub stranded: usize,
    /// Workers that were no longer running once the caller stopped waiting --
    /// the host killed them, or they left inside the stop -- counted for the
    /// life of the boundary. This is what distinguishes a route that recovered
    /// without the provider's cooperation from one that only recovered because
    /// the provider eventually returned.
    pub terminated: usize,
}

impl ProviderWorkerCensusV1 {
    /// Threads this provider still occupies.
    #[must_use]
    pub const fn occupied(self) -> usize {
        self.live.saturating_add(self.stranded)
    }
}

/// How one invocation's worker ended when the caller stopped waiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerDispositionV1 {
    /// Nothing of this invocation is still running -- the host stopped the
    /// worker, the worker left while the host was stopping it, or no worker
    /// was ever borrowed because the caller had already withdrawn before
    /// contact -- and its capacity is fully reclaimed. Only a host with a real
    /// kill primitive can produce this against work that would never have
    /// returned.
    Terminated,
    /// The host could not stop the worker. It is still running, still counted
    /// against its provider, and the provider is refused before contact until
    /// it returns.
    Stranded,
}

impl WorkerDispositionV1 {
    /// Stable machine-readable label of this disposition.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Terminated => "terminated",
            Self::Stranded => "stranded",
        }
    }
}

/// Why one provider invocation produced no provider outcome.
///
/// None of these are provider replies: the provider either was never contacted
/// or never returned. They are kept structurally distinct because a caller
/// acts on them differently -- a stalled or unisolated provider is refused, a
/// deadline or cancellation is a caller outcome, and a lost or unstartable
/// worker is a host fault.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderInvocationFaultV1 {
    /// Foreign provider code was offered to a host with no way to stop it, so
    /// it was not contacted. This is the shape the boundary refuses rather
    /// than pretending a deadline can contain it.
    #[error(
        "provider {provider_id} runs foreign code and this host cannot terminate a worker \
         without provider cooperation, so the call was refused before contact"
    )]
    ExecutionNotIsolated {
        /// Provider that was refused.
        provider_id: String,
    },
    /// The provider already strands as many workers as the boundary will hold,
    /// so it was not contacted.
    #[error(
        "provider {provider_id} has {stranded} invocation(s) still running past their caller that \
         this host cannot stop; it is refused until they return"
    )]
    ProviderStalled {
        /// Provider that was refused.
        provider_id: String,
        /// Stranded workers it owns.
        stranded: usize,
    },
    /// The provider's finite waited-worker budget is fully committed.
    #[error("provider {provider_id} already owns its whole worker budget of {maximum}")]
    WorkerCapacityExhausted {
        /// Provider that was refused.
        provider_id: String,
        /// The budget that is fully committed.
        maximum: usize,
    },
    /// The worker outlived the caller's budget.
    #[error(
        "provider {provider_id} did not return inside its {budget_millis} ms budget; its worker \
         was {}",
        disposition.code()
    )]
    DeadlineExceeded {
        /// Provider whose invocation outlived its budget.
        provider_id: String,
        /// The budget it outlived.
        budget_millis: u64,
        /// What became of the worker.
        disposition: WorkerDispositionV1,
    },
    /// The caller withdrew while the provider was still working.
    #[error(
        "provider {provider_id} was cancelled after {waited_millis} ms; its worker was {}",
        disposition.code()
    )]
    Cancelled {
        /// Provider whose invocation was cancelled.
        provider_id: String,
        /// How long the caller had waited when it withdrew.
        waited_millis: u64,
        /// What became of the worker.
        disposition: WorkerDispositionV1,
    },
    /// The host could not start a worker thread for this invocation.
    #[error("host could not start a worker for provider {provider_id}: {detail}")]
    WorkerUnavailable {
        /// Provider the worker was for.
        provider_id: String,
        /// Operating-system failure detail.
        detail: String,
    },
    /// The worker returned no outcome: it unwound (a provider panic) or the
    /// boundary's own accounting was violated.
    #[error("worker for provider {provider_id} returned no outcome")]
    WorkerLost {
        /// Provider the worker was for.
        provider_id: String,
    },
}

impl ProviderInvocationFaultV1 {
    /// Stable machine-readable code of this fault.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ExecutionNotIsolated { .. } => "provider_invocation_execution_not_isolated",
            Self::ProviderStalled { .. } => "provider_invocation_stalled",
            Self::WorkerCapacityExhausted { .. } => "provider_invocation_capacity_exhausted",
            Self::DeadlineExceeded { .. } => "provider_invocation_deadline_exceeded",
            Self::Cancelled { .. } => "provider_invocation_cancelled",
            Self::WorkerUnavailable { .. } => "provider_invocation_worker_unavailable",
            Self::WorkerLost { .. } => "provider_invocation_worker_lost",
        }
    }

    /// The provider this fault is attributed to.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        match self {
            Self::ExecutionNotIsolated { provider_id }
            | Self::ProviderStalled { provider_id, .. }
            | Self::WorkerCapacityExhausted { provider_id, .. }
            | Self::DeadlineExceeded { provider_id, .. }
            | Self::Cancelled { provider_id, .. }
            | Self::WorkerUnavailable { provider_id, .. }
            | Self::WorkerLost { provider_id } => provider_id,
        }
    }

    /// What became of the worker, for the faults that ended a live one.
    #[must_use]
    pub const fn worker_disposition(&self) -> Option<WorkerDispositionV1> {
        match self {
            Self::DeadlineExceeded { disposition, .. } | Self::Cancelled { disposition, .. } => {
                Some(*disposition)
            }
            _ => None,
        }
    }
}

/// Bounded, per-provider worker accounting shared by every port mounted over
/// one provider composition.
pub struct ProviderInvocationBoundaryV1 {
    limits: ProviderInvocationLimitsV1,
    spawn: Arc<dyn ProviderWorkerSpawnV1>,
    ledgers: Mutex<BTreeMap<String, Arc<ProviderWorkerLedgerV1>>>,
}

impl fmt::Debug for ProviderInvocationBoundaryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInvocationBoundaryV1")
            .field("limits", &self.limits)
            .field("isolation", &self.spawn.isolation())
            .finish_non_exhaustive()
    }
}

impl ProviderInvocationBoundaryV1 {
    /// Builds a boundary that enforces `limits` per provider identity and runs
    /// provider work on workers `spawn` supplies.
    #[must_use]
    pub fn new(limits: ProviderInvocationLimitsV1, spawn: Arc<dyn ProviderWorkerSpawnV1>) -> Self {
        Self {
            limits,
            spawn,
            ledgers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The worker budget this boundary enforces.
    #[must_use]
    pub const fn limits(&self) -> ProviderInvocationLimitsV1 {
        self.limits
    }

    /// Whether this boundary's host can stop a worker without the provider's
    /// cooperation.
    #[must_use]
    pub fn isolation(&self) -> ProviderWorkerIsolationV1 {
        self.spawn.isolation()
    }

    /// What `provider_id` currently owns.
    ///
    /// This is the host's own record of worker ownership, so a caller -- or a
    /// test -- can tell an invocation that finished from one the host stopped
    /// and one that is still running unstoppably, without asking the provider.
    #[must_use]
    pub fn worker_census(&self, provider_id: &str) -> ProviderWorkerCensusV1 {
        Self::guard(&self.ledgers)
            .get(provider_id)
            .map_or_else(ProviderWorkerCensusV1::default, |ledger| ledger.census())
    }

    /// Waits until `provider_id`'s census satisfies `admits`, or `within`
    /// elapses.
    ///
    /// A stranded worker releases its accounting from the worker's own thread,
    /// whenever the provider finally lets go, so "the route recovered" is an
    /// event nobody can observe by asking once. Every accounting transition
    /// publishes it here, which is what lets an operator surface -- or a test
    /// -- wait for the boundary rather than poll it on a timer. Interest is
    /// registered *before* the census is read, so a transition that happens
    /// between the read and the wait is never missed.
    ///
    /// `Ok` carries the census that satisfied `admits`; `Err` carries the last
    /// one seen before `within` elapsed.
    ///
    /// Poll this future inside a running Tokio runtime with time enabled.
    /// Reading [`Self::worker_census`] does not require a runtime.
    pub async fn await_worker_census(
        &self,
        provider_id: &str,
        within: Duration,
        admits: impl Fn(ProviderWorkerCensusV1) -> bool,
    ) -> Result<ProviderWorkerCensusV1, ProviderWorkerCensusV1> {
        let ledger = self.ledger(provider_id);
        let deadline = std::time::Instant::now() + within;
        loop {
            let mut changed = Box::pin(ledger.changed.notified());
            // Registers this waiter before the census is read, so a
            // transition between the read and the wait is not missed.
            changed.as_mut().enable();
            let census = ledger.census();
            if admits(census) {
                return Ok(census);
            }
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return Err(ledger.census());
            };
            let woken = tokio::select! {
                biased;
                () = &mut changed => true,
                // ambient-tokio: this Tokio-only wait is polled by timer-enabled Tokio callers.
                () = tokio::time::sleep(remaining) => false,
            };
            if !woken {
                return Err(ledger.census());
            }
        }
    }

    /// Runs `work` on a host-owned worker and answers at whichever comes
    /// first: the worker's outcome, the caller's cancellation, or `budget`.
    ///
    /// The returned `Ok` is the provider outcome. Every `Err` is a typed
    /// [`ProviderInvocationFaultV1`]: no provider outcome exists, and the
    /// fault says whether the provider was refused before contact, outlived
    /// its budget, was cancelled, or could not be run at all -- and, for the
    /// two caller outcomes, whether the host stopped its worker or the worker
    /// is still running.
    ///
    /// Poll this future in a running Tokio runtime with time enabled. The
    /// service's advisory recall boundary enters its owned runtime on every
    /// poll. A caller without a runtime is refused before starting a worker.
    pub async fn invoke<T>(
        &self,
        request: ProviderInvocationRequestV1<'_>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ProviderInvocationFaultV1>
    where
        T: Send + 'static,
    {
        let ProviderInvocationRequestV1 {
            provider_id,
            execution_shape,
            budget,
            mut cancelled,
        } = request;
        // Consent that is already withdrawn is read *before* every other
        // pre-contact decision. Cancellation is the caller's terminal, not an
        // execution-shape or capacity refusal, and learning it requires no
        // worker and no provider contact.
        //
        // It is also read before a worker slot is
        // claimed and before any worker exists, so a call the caller no longer
        // wants costs the provider nothing and costs the finite worker budget
        // nothing. Learning it only from the race below meant an
        // already-cancelled call still admitted a worker against the ceiling,
        // still handed the provider work the host had withdrawn, and -- if the
        // provider was quick enough to win the biased completion arm -- still
        // had that answer accepted.
        if withdrawn_already(&mut cancelled).await {
            return Err(cancelled_before_contact(provider_id));
        }
        // Refused before contact, before any worker exists: foreign code the
        // host cannot terminate is not a deadline problem, it is a shape this
        // boundary does not admit. Re-poll consent at the refusal edge: it may
        // have been withdrawn since the invocation's initial observation, and
        // cancellation is the caller's terminal even when this shape would
        // otherwise be refused too.
        if execution_shape == ProviderExecutionShapeV1::Foreign
            && self.spawn.isolation() == ProviderWorkerIsolationV1::CooperativeOnly
        {
            if withdrawn_already(&mut cancelled).await {
                return Err(cancelled_before_contact(provider_id));
            }
            return Err(ProviderInvocationFaultV1::ExecutionNotIsolated {
                provider_id: provider_id.to_owned(),
            });
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(error) => {
                if withdrawn_already(&mut cancelled).await {
                    return Err(cancelled_before_contact(provider_id));
                }
                return Err(ProviderInvocationFaultV1::WorkerUnavailable {
                    provider_id: provider_id.to_owned(),
                    detail: format!("provider invocation Tokio runtime unavailable: {error}"),
                });
            }
        };
        let ledger = self.ledger(provider_id);
        if let Err(refusal) = ledger.admit(provider_id, self.limits) {
            // Admission refusals are still pre-contact. Cancellation that
            // became visible while the ledger was inspected takes precedence,
            // and the failed admission changed no census state.
            if withdrawn_already(&mut cancelled).await {
                return Err(cancelled_before_contact(provider_id));
            }
            return Err(refusal);
        }
        let slot = Arc::new(InvocationSlotV1 {
            state: Mutex::new(SlotStateV1::Running),
            ledger: Arc::clone(&ledger),
        });
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        let worker_slot = Arc::clone(&slot);
        // A host-owned, detached worker: the async runtime never waits for it,
        // so a worker the host cannot stop cannot hold a runtime shutdown -- or
        // a shared blocking-pool slot -- open behind the host.
        let spawned = self.spawn.spawn_detached(
            &format!("tdmem-provider-{provider_id}"),
            Box::new(move || {
                // Releases the worker's slot even when `work` unwinds, so a
                // provider panic is a settled worker, never a phantom one.
                let exit = WorkerExitGuardV1 {
                    slot: Arc::clone(&worker_slot),
                };
                let outcome = work();
                worker_slot.deliver(outcome, sender);
                drop(exit);
            }),
        );
        let handle = match spawned {
            Ok(handle) => handle,
            Err(error) => {
                slot.release();
                // The worker never started, so this is another pre-contact
                // refusal. Observe consent after releasing the provisional slot
                // and let cancellation win without leaving census state behind.
                if withdrawn_already(&mut cancelled).await {
                    return Err(cancelled_before_contact(provider_id));
                }
                return Err(ProviderInvocationFaultV1::WorkerUnavailable {
                    provider_id: provider_id.to_owned(),
                    detail: error.to_string(),
                });
            }
        };
        let started = std::time::Instant::now();
        let timeout = {
            let _entered = runtime.enter();
            // ambient-tokio: the captured runtime is entered while its timer is constructed.
            tokio::time::sleep(budget)
        };
        // Three outcomes, one race. Completion is polled first, but accepting
        // it has a second consent boundary: cancellation may have become ready
        // before the delivered branch was chosen. Once withdrawal is observed,
        // no later provider outcome can be recovered from the stop race.
        let ended = tokio::select! {
            biased;
            delivered = &mut receiver => Ok(delivered),
            () = &mut cancelled => Err(WaitEndV1::Cancelled),
            () = timeout => Err(WaitEndV1::DeadlineExceeded),
        };
        let stop = match ended {
            Ok(Ok(outcome)) => {
                if !withdrawn_already(&mut cancelled).await {
                    return Ok(outcome);
                }
                drop(outcome);
                WaitEndV1::Cancelled
            }
            Ok(Err(_)) => {
                return Err(ProviderInvocationFaultV1::WorkerLost {
                    provider_id: provider_id.to_owned(),
                });
            }
            Err(end) => end,
        };
        // The caller is done waiting. Ask the host to stop the worker; only a
        // host that owns a kill primitive can answer `Terminated`, and only
        // then is the work provably over.
        let disposition = match slot.stop(handle.as_ref()) {
            Some(disposition) => disposition,
            // Cancellation is fail-closed. The worker may have settled after
            // withdrawal became ready but before `stop` acquired its slot; its
            // outcome is still withdrawn and must never become `Ok`.
            None if matches!(stop, WaitEndV1::Cancelled) => WorkerDispositionV1::Terminated,
            None => {
                // A deadline racing with a worker that had already settled is
                // different: the provider met the bound, so keep its outcome.
                return receiver
                    .try_recv()
                    .map_err(|_| ProviderInvocationFaultV1::WorkerLost {
                        provider_id: provider_id.to_owned(),
                    });
            }
        };
        Err(match stop {
            WaitEndV1::Cancelled => ProviderInvocationFaultV1::Cancelled {
                provider_id: provider_id.to_owned(),
                waited_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                disposition,
            },
            WaitEndV1::DeadlineExceeded => ProviderInvocationFaultV1::DeadlineExceeded {
                provider_id: provider_id.to_owned(),
                budget_millis: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
                disposition,
            },
        })
    }

    fn ledger(&self, provider_id: &str) -> Arc<ProviderWorkerLedgerV1> {
        let mut ledgers = Self::guard(&self.ledgers);
        if let Some(existing) = ledgers.get(provider_id) {
            return Arc::clone(existing);
        }
        let created = Arc::new(ProviderWorkerLedgerV1::default());
        ledgers.insert(provider_id.to_owned(), Arc::clone(&created));
        created
    }

    /// Worker accounting must survive a poisoned lock: a panicking provider
    /// must not make the boundary itself unusable, which would turn one
    /// misbehaving call into a permanently dead route.
    fn guard<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Reads a caller's cancellation input without waiting on it.
///
/// The future is polled exactly once and never again if it was ready, so this
/// answers "had the caller already withdrawn when the invocation arrived?"
/// without borrowing a worker to find out. A pending future is left untouched
/// for the race in [`ProviderInvocationBoundaryV1::invoke`] to own.
async fn withdrawn_already(cancelled: &mut ProviderCancellationWaitV1) -> bool {
    std::future::poll_fn(|context| Poll::Ready(cancelled.as_mut().poll(context).is_ready())).await
}

/// The exact terminal for consent observed before provider contact.
fn cancelled_before_contact(provider_id: &str) -> ProviderInvocationFaultV1 {
    ProviderInvocationFaultV1::Cancelled {
        provider_id: provider_id.to_owned(),
        waited_millis: 0,
        disposition: WorkerDispositionV1::Terminated,
    }
}

/// Which caller-side event ended the wait when the worker did not answer.
#[derive(Clone, Copy)]
enum WaitEndV1 {
    /// The caller withdrew.
    Cancelled,
    /// The caller's budget elapsed.
    DeadlineExceeded,
}

#[derive(Default)]
struct ProviderWorkerLedgerV1 {
    census: Mutex<ProviderWorkerCensusV1>,
    /// Published on every accounting transition, so a waiter learns that a
    /// stranded worker returned without polling for it.
    changed: tokio::sync::Notify,
}

impl ProviderWorkerLedgerV1 {
    fn census(&self) -> ProviderWorkerCensusV1 {
        *ProviderInvocationBoundaryV1::guard(&self.census)
    }

    /// Wakes every waiter on [`Self::changed`]. Called after the census lock is
    /// released so a woken waiter can read the new value immediately.
    fn published(&self) {
        self.changed.notify_waiters();
    }

    fn admit(
        &self,
        provider_id: &str,
        limits: ProviderInvocationLimitsV1,
    ) -> Result<(), ProviderInvocationFaultV1> {
        let mut census = ProviderInvocationBoundaryV1::guard(&self.census);
        if census.stranded >= limits.max_stranded_workers {
            return Err(ProviderInvocationFaultV1::ProviderStalled {
                provider_id: provider_id.to_owned(),
                stranded: census.stranded,
            });
        }
        if census.live >= limits.max_workers {
            return Err(ProviderInvocationFaultV1::WorkerCapacityExhausted {
                provider_id: provider_id.to_owned(),
                maximum: limits.max_workers,
            });
        }
        census.live = census.live.saturating_add(1);
        drop(census);
        self.published();
        Ok(())
    }

    fn release_live(&self) {
        let mut census = ProviderInvocationBoundaryV1::guard(&self.census);
        census.live = census.live.saturating_sub(1);
        drop(census);
        self.published();
    }

    fn release_stranded(&self) {
        let mut census = ProviderInvocationBoundaryV1::guard(&self.census);
        census.stranded = census.stranded.saturating_sub(1);
        drop(census);
        self.published();
    }

    fn record_terminated(&self) {
        let mut census = ProviderInvocationBoundaryV1::guard(&self.census);
        census.live = census.live.saturating_sub(1);
        census.terminated = census.terminated.saturating_add(1);
        drop(census);
        self.published();
    }

    fn mark_stranded(&self) {
        let mut census = ProviderInvocationBoundaryV1::guard(&self.census);
        census.live = census.live.saturating_sub(1);
        census.stranded = census.stranded.saturating_add(1);
        drop(census);
        self.published();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SlotStateV1 {
    /// A caller is waiting and the worker has not returned.
    Running,
    /// The caller stopped waiting and the host is deciding this worker's fate.
    /// Anything the worker produces from here is discarded: the caller already
    /// withdrew, and an outcome the host's own termination shook loose is not
    /// a provider answer.
    Stopping,
    /// The worker left while the host was deciding. It is gone; the stopping
    /// caller still owns the accounting.
    ExitedWhileStopping,
    /// The caller stopped waiting, the host could not stop the worker, and the
    /// worker is still running.
    Stranded,
    /// The worker's accounting is complete.
    Settled,
}

struct InvocationSlotV1 {
    state: Mutex<SlotStateV1>,
    ledger: Arc<ProviderWorkerLedgerV1>,
}

impl InvocationSlotV1 {
    /// Publishes the worker's outcome and settles its slot in one critical
    /// section, so a caller that stops waiting concurrently either wins the
    /// stop or observes a value already in the channel.
    fn deliver<T>(&self, outcome: T, sender: tokio::sync::oneshot::Sender<T>) {
        let mut state = ProviderInvocationBoundaryV1::guard(&self.state);
        match *state {
            SlotStateV1::Running => {
                *state = SlotStateV1::Settled;
                let _ = sender.send(outcome);
                self.ledger.release_live();
            }
            SlotStateV1::Stopping => {
                // The caller has withdrawn and the host is terminating. This
                // outcome is discarded on purpose: delivering it would let a
                // value the host's own kill shook loose masquerade as a
                // provider answer to a caller that is no longer there.
                *state = SlotStateV1::ExitedWhileStopping;
                drop(outcome);
            }
            SlotStateV1::Stranded => {
                *state = SlotStateV1::Settled;
                // Nobody is waiting for this outcome; the caller was answered
                // when it stopped waiting. Releasing the strand here is what
                // gives the provider its hang allowance back.
                self.ledger.release_stranded();
            }
            SlotStateV1::ExitedWhileStopping | SlotStateV1::Settled => {}
        }
    }

    /// Ends a still-running worker on the caller's behalf.
    ///
    /// Answers `None` only when the worker settled *before* the caller stopped
    /// waiting, in which case its outcome is already in the channel and is a
    /// genuine provider answer. Otherwise it asks the host to terminate and
    /// answers what became of the worker. The host call deliberately happens
    /// *outside* the state lock: a terminating host may wait for the worker to
    /// exit, and the worker's own delivery needs that lock to do it.
    fn stop(&self, handle: &dyn ProviderWorkerHandleV1) -> Option<WorkerDispositionV1> {
        {
            let mut state = ProviderInvocationBoundaryV1::guard(&self.state);
            match *state {
                SlotStateV1::Running => *state = SlotStateV1::Stopping,
                // One caller owns one slot, so no other state is reachable
                // here except a worker that already settled.
                _ => return None,
            }
        }
        let termination = handle.terminate();
        let mut state = ProviderInvocationBoundaryV1::guard(&self.state);
        match *state {
            SlotStateV1::Stopping => match termination {
                ProviderWorkerTerminationV1::Terminated
                | ProviderWorkerTerminationV1::AlreadyExited => {
                    *state = SlotStateV1::Settled;
                    self.ledger.record_terminated();
                    Some(WorkerDispositionV1::Terminated)
                }
                ProviderWorkerTerminationV1::NotTerminable => {
                    *state = SlotStateV1::Stranded;
                    self.ledger.mark_stranded();
                    Some(WorkerDispositionV1::Stranded)
                }
            },
            // The worker left while the host was deciding -- because the host
            // killed what it was blocked on, or because it happened to finish.
            // Either way nothing of it is still running.
            _ => {
                *state = SlotStateV1::Settled;
                self.ledger.record_terminated();
                Some(WorkerDispositionV1::Terminated)
            }
        }
    }

    /// Releases the slot without an outcome: the worker never started, or it
    /// unwound before delivering.
    fn release(&self) {
        let mut state = ProviderInvocationBoundaryV1::guard(&self.state);
        match *state {
            SlotStateV1::Running => {
                *state = SlotStateV1::Settled;
                self.ledger.release_live();
            }
            SlotStateV1::Stopping => {
                // The stopping caller owns this slot's accounting; record only
                // that the worker is gone.
                *state = SlotStateV1::ExitedWhileStopping;
            }
            SlotStateV1::Stranded => {
                *state = SlotStateV1::Settled;
                self.ledger.release_stranded();
            }
            SlotStateV1::ExitedWhileStopping | SlotStateV1::Settled => {}
        }
    }
}

struct WorkerExitGuardV1 {
    slot: Arc<InvocationSlotV1>,
}

impl Drop for WorkerExitGuardV1 {
    fn drop(&mut self) {
        self.slot.release();
    }
}
