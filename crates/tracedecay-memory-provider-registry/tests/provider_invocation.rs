//! The host execution boundary for synchronous provider work.
//!
//! Provider ports are synchronous and cannot be interrupted from inside the
//! process, so the boundary's whole job is to make the *execution capability*
//! explicit and then hold every provider to what that capability can honestly
//! deliver. These tests judge exactly that: which shapes are admitted at all,
//! how quickly the caller is released when it withdraws, whether the host
//! actually stopped the work or merely stopped waiting for it, what capacity
//! comes back either way, and whether the route survives.
//!
//! One scripted crash is a deliberate `panic!`: a provider that unwinds is one
//! of the outcomes the boundary exists to contain, and there is no other way
//! to produce it.
#![allow(clippy::panic)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tracedecay_memory_provider_registry::{
    ProviderExecutionShapeV1, ProviderInvocationBoundaryV1, ProviderInvocationFaultV1,
    ProviderInvocationLimitsV1, ProviderInvocationRequestV1, ProviderWorkV1,
    ProviderWorkerCensusV1, ProviderWorkerHandleV1, ProviderWorkerIsolationV1,
    ProviderWorkerSpawnErrorV1, ProviderWorkerSpawnV1, ProviderWorkerTerminationV1,
    WorkerDispositionV1,
};

const PROVIDER: &str = "provider.native";

/// A latch a worker blocks on until the test releases it.
#[derive(Default)]
struct ReleaseGate {
    state: std::sync::Mutex<GateState>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct GateState {
    released: bool,
}

impl ReleaseGate {
    fn enter(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        self.changed.notify_all();
        while !state.released {
            match self.changed.wait(state) {
                Ok(next) => state = next,
                Err(_) => return,
            }
        }
    }

    fn release(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.released = true;
            self.changed.notify_all();
        }
    }
}

/// A latch that is **never** released, for the provider shapes whose whole
/// point is that nothing outside the host can make them return.
#[derive(Default)]
struct NeverReturns {
    state: std::sync::Mutex<usize>,
    never: std::sync::Condvar,
}

impl NeverReturns {
    fn enter(&self) {
        let Ok(mut entered) = self.state.lock() else {
            return;
        };
        *entered = entered.saturating_add(1);
        self.never.notify_all();
        loop {
            match self.never.wait(entered) {
                Ok(next) => entered = next,
                Err(_) => return,
            }
        }
    }

    fn entered(&self) -> usize {
        self.state.lock().map_or(0, |entered| *entered)
    }
}

/// The host execution capability the daemon supplies in production: a detached
/// in-process thread it has no sound way to stop.
struct HostWorkers;

struct HostThreadHandle;

impl ProviderWorkerHandleV1 for HostThreadHandle {
    fn terminate(&self) -> ProviderWorkerTerminationV1 {
        ProviderWorkerTerminationV1::NotTerminable
    }
}

impl ProviderWorkerSpawnV1 for HostWorkers {
    fn isolation(&self) -> ProviderWorkerIsolationV1 {
        ProviderWorkerIsolationV1::CooperativeOnly
    }

    fn spawn_detached(
        &self,
        name: &str,
        work: ProviderWorkV1,
    ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1> {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(work)
            .map(|_joinable| -> Box<dyn ProviderWorkerHandleV1> { Box::new(HostThreadHandle) })
            .map_err(|error| ProviderWorkerSpawnErrorV1::new(error.to_string()))
    }
}

/// A host that refuses to start any worker at all.
struct RefusingWorkers;

impl ProviderWorkerSpawnV1 for RefusingWorkers {
    fn isolation(&self) -> ProviderWorkerIsolationV1 {
        ProviderWorkerIsolationV1::CooperativeOnly
    }

    fn spawn_detached(
        &self,
        _name: &str,
        _work: ProviderWorkV1,
    ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1> {
        Err(ProviderWorkerSpawnErrorV1::new("no worker available"))
    }
}

fn boundary() -> Arc<ProviderInvocationBoundaryV1> {
    Arc::new(ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1::for_in_flight(2),
        Arc::new(HostWorkers),
    ))
}

/// A request from a caller that never withdraws.
fn uncancelled(budget: Duration) -> ProviderInvocationRequestV1<'static> {
    ProviderInvocationRequestV1 {
        provider_id: PROVIDER,
        execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
        budget,
        cancelled: Box::pin(std::future::pending()),
    }
}

/// A request whose caller withdraws after `after`.
fn cancelled_after(budget: Duration, after: Duration) -> ProviderInvocationRequestV1<'static> {
    ProviderInvocationRequestV1 {
        provider_id: PROVIDER,
        execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
        budget,
        cancelled: Box::pin(tokio::time::sleep(after)),
    }
}

async fn settle_until(
    boundary: &ProviderInvocationBoundaryV1,
    ceiling: Duration,
    predicate: impl Fn(ProviderWorkerCensusV1) -> bool,
) -> ProviderWorkerCensusV1 {
    match boundary
        .await_worker_census(PROVIDER, ceiling, predicate)
        .await
    {
        Ok(census) => census,
        Err(census) => panic!("boundary never reached the expected census; last saw {census:?}"),
    }
}

/// A worker that returns inside its budget delivers its outcome and leaves the
/// provider owning nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_answers_in_time_leaves_nothing_behind() {
    let boundary = boundary();
    let answer = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || 41_usize + 1)
        .await;

    assert_eq!(answer.ok(), Some(42));
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default()
    );
}

/// Foreign provider code offered to a host with no kill primitive is refused
/// **before contact**, and the refusal names the provider.
///
/// Real defect this catches: accepting an execution shape the host cannot
/// contain and then trying to make a deadline stand in for isolation — which
/// is how a third-party provider ends up able to strand host threads at will.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_code_is_refused_by_a_host_that_cannot_terminate_a_worker() {
    let boundary = boundary();
    let ran = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ran);

    let refused = boundary
        .invoke(
            ProviderInvocationRequestV1 {
                provider_id: PROVIDER,
                execution_shape: ProviderExecutionShapeV1::Foreign,
                budget: Duration::from_secs(5),
                cancelled: Box::pin(std::future::pending()),
            },
            move || counter.fetch_add(1, Ordering::AcqRel),
        )
        .await;

    match refused {
        Err(ProviderInvocationFaultV1::ExecutionNotIsolated { provider_id }) => {
            assert_eq!(provider_id, PROVIDER);
        }
        other => panic!("foreign code must be refused before contact: {other:?}"),
    }
    assert_eq!(
        ran.load(Ordering::Acquire),
        0,
        "a refused shape must never run"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default(),
        "a refusal before contact holds no capacity"
    );
}

/// A terminable host is the whole answer to a provider that never returns: the
/// caller is released promptly, the worker is *actually stopped* rather than
/// merely forgotten, the provider's capacity comes back with no cooperation
/// from provider code, and the route is immediately usable again.
///
/// The worker's blocking operation here is a real child process the provider
/// waits on. That is the supervised-process shape (`tdmem-0703`, ADR-0009) in
/// miniature: the provider code neither polls a cancellation token nor is
/// released by this test — it is stuck in a syscall until the *host* kills the
/// process out from under it.
///
/// Real defect this catches: reporting a deadline outcome while the work keeps
/// running and the slot stays committed, which is what turns one hung call
/// into a permanently unavailable route.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::expect_used,
    reason = "test assertions require successful process/task synchronization before checking cancellation"
)]
async fn a_terminable_host_stops_a_never_returning_worker_and_reopens_the_route() {
    use std::collections::VecDeque;
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::sync::Mutex;

    /// Starts one supervised provider process whose only observable end is
    /// the host killing it. The pipe handed to the provider is what the
    /// provider blocks on; the `Child` stays with the host.
    fn supervised_process() -> (Arc<Mutex<Child>>, ChildStdout) {
        let mut child = Command::new("sleep")
            .arg("600")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("a supervised provider process");
        let pipe = child.stdout.take().expect("supervised process pipe");
        (Arc::new(Mutex::new(child)), pipe)
    }

    /// A host that owns a real kill primitive over each worker's process.
    struct SupervisedProcessWorkers {
        pending: Mutex<VecDeque<Arc<Mutex<Child>>>>,
    }

    struct SupervisedProcessHandle {
        child: Arc<Mutex<Child>>,
    }

    impl ProviderWorkerHandleV1 for SupervisedProcessHandle {
        fn terminate(&self) -> ProviderWorkerTerminationV1 {
            let Ok(mut child) = self.child.lock() else {
                return ProviderWorkerTerminationV1::NotTerminable;
            };
            if child.kill().is_err() {
                return ProviderWorkerTerminationV1::NotTerminable;
            }
            // `Terminated` is a guarantee, so it is only claimed once the
            // killed process has been reaped and is confirmed gone.
            match child.wait() {
                Ok(_) => ProviderWorkerTerminationV1::Terminated,
                Err(_) => ProviderWorkerTerminationV1::NotTerminable,
            }
        }
    }

    impl ProviderWorkerSpawnV1 for SupervisedProcessWorkers {
        fn isolation(&self) -> ProviderWorkerIsolationV1 {
            ProviderWorkerIsolationV1::Terminable
        }

        fn spawn_detached(
            &self,
            name: &str,
            work: ProviderWorkV1,
        ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1> {
            let child = self
                .pending
                .lock()
                .ok()
                .and_then(|mut pending| pending.pop_front())
                .ok_or_else(|| ProviderWorkerSpawnErrorV1::new("no supervised process"))?;
            std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(work)
                .map_err(|error| ProviderWorkerSpawnErrorV1::new(error.to_string()))?;
            Ok(Box::new(SupervisedProcessHandle { child }))
        }
    }

    let (first_child, first_pipe) = supervised_process();
    let (second_child, second_pipe) = supervised_process();
    let boundary = Arc::new(ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1 {
            max_workers: 1,
            max_stranded_workers: 1,
        },
        Arc::new(SupervisedProcessWorkers {
            pending: Mutex::new(VecDeque::from([
                Arc::clone(&first_child),
                Arc::clone(&second_child),
            ])),
        }),
    ));
    assert_eq!(boundary.isolation(), ProviderWorkerIsolationV1::Terminable);

    // The provider work: block on the supervised process's pipe. It polls no
    // cancellation token, and nothing in this test releases it -- the read
    // returns only when the host kills the process out from under it.
    let blocked_on_process = move || {
        let mut pipe = first_pipe;
        let mut drained = Vec::new();
        let _ = pipe.read_to_end(&mut drained);
        "never produced"
    };

    let started = Instant::now();
    let outcome = boundary
        .invoke(
            cancelled_after(Duration::from_secs(600), Duration::from_millis(150)),
            blocked_on_process,
        )
        .await;
    let waited = started.elapsed();

    match outcome {
        Err(ProviderInvocationFaultV1::Cancelled { disposition, .. }) => assert_eq!(
            disposition,
            WorkerDispositionV1::Terminated,
            "a terminable host must report the worker it actually stopped"
        ),
        other => panic!("cancellation must end the wait: {other:?}"),
    }
    assert!(
        waited < Duration::from_secs(5),
        "the caller waited {waited:?} on a provider that never returns"
    );

    // The work is really over: the process the provider was blocked on was
    // killed and reaped, and the signal is on its exit status.
    let killed = first_child
        .lock()
        .expect("supervised process")
        .try_wait()
        .expect("supervised process status")
        .expect("the supervised process must have exited");
    assert_eq!(
        killed.signal(),
        Some(libc_sigkill()),
        "the host must have killed the supervised process, not waited it out"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1 {
            live: 0,
            stranded: 0,
            terminated: 1,
        },
        "termination must reclaim capacity, not park it"
    );

    // The route is usable again on the same single-worker budget the hung call
    // had committed, with no cooperation from the provider that hung.
    let second_blocked = move || {
        let mut pipe = second_pipe;
        let mut drained = Vec::new();
        let _ = pipe.read_to_end(&mut drained);
        "never produced"
    };
    let reopened = boundary
        .invoke(
            cancelled_after(Duration::from_secs(600), Duration::from_millis(150)),
            second_blocked,
        )
        .await;
    assert!(
        matches!(reopened, Err(ProviderInvocationFaultV1::Cancelled { .. })),
        "the route must be usable after a terminated worker: {reopened:?}"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER).terminated,
        2,
        "the second worker was stopped by the host too"
    );
    assert!(
        second_child
            .lock()
            .expect("supervised process")
            .try_wait()
            .expect("supervised process status")
            .is_some(),
        "the second supervised process must also be gone"
    );
}

/// `SIGKILL`, without taking a `libc` dependency for one integer.
#[cfg(unix)]
const fn libc_sigkill() -> i32 {
    9
}

/// The non-terminable host's honest contract, against a provider that never
/// returns and is never released: the caller is answered in bounded time, the
/// still-running worker is *published* rather than pretended away, the next
/// call is refused before contact instead of stranding a second thread behind
/// the first, and the route comes back the moment the worker does.
///
/// This is deliberately the weaker half of the pair. It is what an in-process
/// host can honestly promise, and it is why
/// [`a_terminable_host_stops_a_never_returning_worker_and_reopens_the_route`]
/// exists: the way to make a hang survivable is isolation the host can kill,
/// not a bigger allowance for hangs.
///
/// Real defect this catches: reporting the deadline while forgetting the
/// worker, so a runaway provider consumes a thread per call, invisibly, and a
/// wedged route is indistinguishable from a recovered one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_non_terminable_worker_is_published_and_refuses_the_next_call() {
    let boundary = boundary();
    let wedged = Arc::new(NeverReturns::default());

    let never = Arc::clone(&wedged);
    let started = Instant::now();
    let hung = boundary
        .invoke(uncancelled(Duration::from_millis(80)), move || {
            never.enter();
        })
        .await;
    let waited = started.elapsed();

    match hung {
        Err(ProviderInvocationFaultV1::DeadlineExceeded { disposition, .. }) => assert_eq!(
            disposition,
            WorkerDispositionV1::Stranded,
            "an in-process host must not claim a termination it cannot perform"
        ),
        other => panic!("the deadline must end the wait: {other:?}"),
    }
    assert!(
        waited < Duration::from_secs(2),
        "the caller waited {waited:?} on a worker that never returns"
    );
    let census = settle_until(&boundary, Duration::from_secs(5), |census| {
        census.stranded == 1
    })
    .await;
    assert_eq!(
        census,
        ProviderWorkerCensusV1 {
            live: 0,
            stranded: 1,
            terminated: 0,
        },
        "the still-running worker must stay counted against its provider"
    );
    assert_eq!(wedged.entered(), 1);

    // The next call is refused before contact -- promptly, and without
    // stranding a second thread behind the first.
    let never_run = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&never_run);
    let refused_at = Instant::now();
    let refused = boundary
        .invoke(uncancelled(Duration::from_secs(5)), move || {
            counter.fetch_add(1, Ordering::AcqRel);
        })
        .await;
    match refused {
        Err(ProviderInvocationFaultV1::ProviderStalled {
            provider_id,
            stranded,
        }) => {
            assert_eq!(provider_id, PROVIDER);
            assert_eq!(stranded, 1);
        }
        other => panic!("a provider with a stranded worker must be refused: {other:?}"),
    }
    assert!(
        refused_at.elapsed() < Duration::from_millis(500),
        "the refusal must not wait on the wedged worker"
    );
    assert_eq!(
        never_run.load(Ordering::Acquire),
        0,
        "a refused-before-contact invocation must not run any work"
    );
    assert_eq!(
        wedged.entered(),
        1,
        "the wedged provider was not re-entered"
    );
}

/// A worker whose caller withdrew and which the host cannot stop is a strand,
/// and the strand -- not the caller's patience -- is what the route waits on:
/// the provider is refused before contact until it returns, and answers again
/// as soon as it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_non_terminable_worker_holds_the_route_only_until_it_returns() {
    let boundary = boundary();
    let gate = Arc::new(ReleaseGate::default());

    let held = Arc::clone(&gate);
    let cancelled = boundary
        .invoke(
            cancelled_after(Duration::from_secs(30), Duration::from_millis(100)),
            move || held.enter(),
        )
        .await;
    assert!(
        matches!(
            cancelled,
            Err(ProviderInvocationFaultV1::Cancelled {
                disposition: WorkerDispositionV1::Stranded,
                ..
            })
        ),
        "{cancelled:?}"
    );
    settle_until(&boundary, Duration::from_secs(5), |census| {
        census.stranded == 1
    })
    .await;

    let refused = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || ())
        .await;
    assert!(
        matches!(
            refused,
            Err(ProviderInvocationFaultV1::ProviderStalled { stranded: 1, .. })
        ),
        "{refused:?}"
    );

    gate.release();
    assert_eq!(
        settle_until(&boundary, Duration::from_secs(10), |census| census
            .occupied()
            == 0)
        .await
        .stranded,
        0
    );
    let recovered = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || "answered")
        .await;
    assert_eq!(recovered.ok(), Some("answered"));
}

/// A caller whose consent was **already** withdrawn when the invocation
/// arrived is refused before contact: no worker is borrowed, the provider is
/// never called, and the finite worker budget is untouched.
///
/// Real defect this catches: learning about cancellation only from the race
/// that waits on the worker. Under that shape an already-cancelled call still
/// spends one unit of the provider's worker budget, still hands the provider
/// work the host has withdrawn — and, because completion is polled first in
/// that race, a provider quick enough to answer inside the same poll has its
/// answer accepted for a caller that no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::expect_used,
    reason = "test assertions require successful process/task synchronization before checking cancellation"
)]
async fn an_already_withdrawn_caller_is_refused_before_the_provider_is_contacted() {
    let boundary = boundary();
    let contacted = Arc::new(AtomicUsize::new(0));

    let reached = Arc::clone(&contacted);
    let refused = boundary
        .invoke(
            ProviderInvocationRequestV1 {
                provider_id: PROVIDER,
                execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                budget: Duration::from_secs(30),
                // Already resolved: the caller withdrew before the boundary saw
                // the invocation at all.
                cancelled: Box::pin(std::future::ready(())),
            },
            move || {
                reached.fetch_add(1, Ordering::AcqRel);
                "an answer nobody asked for"
            },
        )
        .await;

    match refused {
        Err(ProviderInvocationFaultV1::Cancelled {
            provider_id,
            waited_millis,
            disposition,
        }) => {
            assert_eq!(provider_id, PROVIDER);
            assert_eq!(waited_millis, 0, "nothing was waited for");
            assert_eq!(
                disposition,
                WorkerDispositionV1::Terminated,
                "no worker was borrowed, so nothing of this invocation can be running"
            );
        }
        other => panic!("an already-withdrawn caller must be refused as cancelled: {other:?}"),
    }
    assert_eq!(
        contacted.load(Ordering::Acquire),
        0,
        "the boundary handed work to the provider after its caller had already withdrawn"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default(),
        "a call that never happened must not spend a worker"
    );

    // The budget really is untouched: both waited workers are still available.
    let gate = Arc::new(ReleaseGate::default());
    let mut running = Vec::new();
    for _ in 0..2 {
        let boundary = Arc::clone(&boundary);
        let held = Arc::clone(&gate);
        running.push(tokio::spawn(async move {
            boundary
                .invoke(uncancelled(Duration::from_secs(30)), move || {
                    held.enter();
                    7_usize
                })
                .await
                .map_err(|fault| fault.to_string())
        }));
    }
    settle_until(&boundary, Duration::from_secs(10), |census| {
        census.live == 2
    })
    .await;
    gate.release();
    for task in running {
        assert_eq!(
            task.await.expect("invocation task"),
            Ok(7),
            "the untouched budget must admit both workers"
        );
    }
    assert_eq!(
        settle_until(&boundary, Duration::from_secs(10), |census| census
            .occupied()
            == 0)
        .await,
        ProviderWorkerCensusV1::default()
    );
}

/// Cancellation ends the caller's wait when it happens, not when the provider
/// finally returns.
///
/// Real defect this catches: handing the cancellation token to provider code
/// and then waiting on the worker anyway, so a provider that ignores the token
/// keeps the caller — and the route above it — blocked for its whole blocking
/// duration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::expect_used,
    reason = "test assertions require successful process/task synchronization before checking cancellation"
)]
async fn cancellation_releases_the_caller_without_waiting_out_the_provider() {
    let boundary = boundary();
    const PROVIDER_BLOCKS_FOR: Duration = Duration::from_millis(1_500);
    /// Longest the caller may still be waiting after its own cancellation
    /// fired (`tdmem-sz9` acceptance).
    const RELEASE_CEILING: Duration = Duration::from_millis(100);

    // The provider signals that it is inside the call, the test withdraws on
    // that event, and the release is measured from the exact instant of the
    // withdrawal. A timer instead of an entry signal would leave it unproven
    // that cancellation ever reached work already in flight, and would fold
    // the arming delay into the measured latency.
    let entered = Arc::new(tokio::sync::Notify::new());
    let cancelled_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    // `notify_one` stores a permit, so the withdrawal can never be lost to the
    // boundary registering its wait a moment later.
    let withdrawn = Arc::new(tokio::sync::Notify::new());
    let request = ProviderInvocationRequestV1 {
        provider_id: PROVIDER,
        execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
        budget: Duration::from_secs(30),
        cancelled: {
            let withdrawn = Arc::clone(&withdrawn);
            Box::pin(async move { withdrawn.notified().await })
        },
    };

    let withdrawing = {
        let entered = Arc::clone(&entered);
        let cancelled_at = Arc::clone(&cancelled_at);
        let withdrawn = Arc::clone(&withdrawn);
        tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .expect("the provider must be inside the call before its caller withdraws");
            *cancelled_at.lock().expect("cancellation instant") = Some(Instant::now());
            withdrawn.notify_one();
        })
    };

    let announce = Arc::clone(&entered);
    let cancelled = boundary
        .invoke(request, move || {
            announce.notify_one();
            // Non-cooperative on purpose: it never looks at a token.
            std::thread::sleep(PROVIDER_BLOCKS_FOR);
            "late answer"
        })
        .await;
    let released_at = Instant::now();
    withdrawing.await.expect("withdrawing task");

    match cancelled {
        Err(ProviderInvocationFaultV1::Cancelled {
            provider_id,
            disposition,
            ..
        }) => {
            assert_eq!(provider_id, PROVIDER);
            assert_eq!(disposition, WorkerDispositionV1::Stranded);
        }
        other => panic!("a withdrawn caller must be told so: {other:?}"),
    }
    let withdrew_at = cancelled_at
        .lock()
        .expect("cancellation instant")
        .expect("the caller must have withdrawn");
    let waited = released_at.saturating_duration_since(withdrew_at);
    assert!(
        waited <= RELEASE_CEILING,
        "cancellation returned {waited:?} after the caller withdrew: it waited out the \
         provider's {PROVIDER_BLOCKS_FOR:?} of blocking work instead of its own cancellation"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER).live,
        0,
        "cancellation must reclaim the waited-worker capacity immediately"
    );

    // The provider does eventually return, and the strand it held is released
    // then — the route needed neither that return nor any cooperation to stay
    // usable in the meantime.
    let settled = settle_until(&boundary, Duration::from_secs(10), |census| {
        census.stranded == 0
    })
    .await;
    assert_eq!(settled, ProviderWorkerCensusV1::default());
}

/// An armed cancellation must not discard an answer the provider produced
/// first. Racing three events is only correct if completion wins when it
/// actually happened.
///
/// Real defect this catches: settling the invocation on whichever branch the
/// executor happens to poll first, so a provider that answered inside its
/// budget is reported as cancelled and its work thrown away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_armed_cancellation_does_not_discard_an_answer_produced_first() {
    let boundary = boundary();
    let answered = boundary
        .invoke(
            cancelled_after(Duration::from_secs(30), Duration::from_millis(400)),
            || {
                std::thread::sleep(Duration::from_millis(20));
                "produced"
            },
        )
        .await;

    assert_eq!(answered.ok(), Some("produced"));
    assert_eq!(
        settle_until(&boundary, Duration::from_secs(5), |census| census
            .occupied()
            == 0)
        .await,
        ProviderWorkerCensusV1::default()
    );
}

/// A provider that unwinds mid-call is a typed host fault, and its slot is
/// released rather than stranded.
///
/// Real defect this catches: releasing the slot only on the success path, so a
/// panicking provider retires the route after `max_workers` crashes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_unwinds_is_a_typed_fault_and_releases_its_slot() {
    let boundary = boundary();
    let panicked = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let crashed = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || -> usize {
            panic!("provider crashed mid-call")
        })
        .await;
    std::panic::set_hook(panicked);

    assert!(
        matches!(crashed, Err(ProviderInvocationFaultV1::WorkerLost { .. })),
        "{crashed:?}"
    );
    let settled = settle_until(&boundary, Duration::from_secs(5), |census| {
        census.occupied() == 0
    })
    .await;
    assert_eq!(settled, ProviderWorkerCensusV1::default());

    // The route is not retired by the crash.
    let after = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || 7_usize)
        .await;
    assert_eq!(after.ok(), Some(7));
}

/// Concurrent live workers are bounded by the provider's worker budget, and a
/// refusal at the bound is typed rather than an unbounded queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_workers_are_bounded_by_the_provider_worker_budget() {
    let boundary = Arc::new(ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1 {
            max_workers: 1,
            max_stranded_workers: 1,
        },
        Arc::new(HostWorkers),
    ));
    let gate = Arc::new(ReleaseGate::default());

    let occupied = Arc::clone(&gate);
    let holder = Arc::clone(&boundary);
    let holding = tokio::spawn(async move {
        holder
            .invoke(uncancelled(Duration::from_secs(10)), move || {
                occupied.enter();
            })
            .await
    });
    settle_until(&boundary, Duration::from_secs(5), |census| census.live == 1).await;

    let refused = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || ())
        .await;
    assert!(
        matches!(
            refused,
            Err(ProviderInvocationFaultV1::WorkerCapacityExhausted { maximum: 1, .. })
        ),
        "{refused:?}"
    );

    gate.release();
    let held = holding.await;
    assert!(held.is_ok(), "the holding invocation must complete");
    assert_eq!(
        settle_until(&boundary, Duration::from_secs(5), |census| census
            .occupied()
            == 0)
        .await,
        ProviderWorkerCensusV1::default()
    );
}

/// A host that cannot start a worker is a typed fault, not a silent empty
/// answer, and it leaves the provider owning nothing.
///
/// Real defect this catches: counting the reserved slot against the provider
/// when no worker was ever started, which would retire the route after
/// `max_workers` failed spawns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_cannot_start_a_worker_reports_it_and_keeps_no_slot() {
    let boundary = ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1::for_in_flight(1),
        Arc::new(RefusingWorkers),
    );

    let refused = boundary
        .invoke(uncancelled(Duration::from_secs(5)), || ())
        .await;
    assert!(
        matches!(
            refused,
            Err(ProviderInvocationFaultV1::WorkerUnavailable { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default(),
        "an unstarted worker must not hold a slot"
    );
}

#[derive(Default)]
struct CancellationGate {
    open: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

impl CancellationGate {
    fn wait(&self) {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*open {
            open = self
                .changed
                .wait(open)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn open(&self) {
        *self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

/// Pending at the pre-contact observation boundary, then ready forever.
struct ReadyAfterFirstPoll {
    polled: bool,
}

impl Future for ReadyAfterFirstPoll {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polled {
            Poll::Ready(())
        } else {
            self.polled = true;
            Poll::Pending
        }
    }
}

/// On its in-race poll, withdraws consent before releasing the provider, then
/// waits until the provider has settled its slot. This deterministically
/// exercises the settle-before-`stop()` interleaving.
struct CancelThenAllowSettlement {
    first_poll: bool,
    withdrawn: Arc<AtomicBool>,
    provider_release: Arc<CancellationGate>,
    provider_settled: Arc<CancellationGate>,
}

impl Future for CancelThenAllowSettlement {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.first_poll {
            self.first_poll = false;
            return Poll::Pending;
        }
        self.withdrawn.store(true, Ordering::Release);
        self.provider_release.open();
        self.provider_settled.wait();
        Poll::Ready(())
    }
}

struct SettlementSignallingWorkers {
    settled: Arc<CancellationGate>,
}

impl ProviderWorkerSpawnV1 for SettlementSignallingWorkers {
    fn isolation(&self) -> ProviderWorkerIsolationV1 {
        ProviderWorkerIsolationV1::CooperativeOnly
    }

    fn spawn_detached(
        &self,
        name: &str,
        work: ProviderWorkV1,
    ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1> {
        let settled = Arc::clone(&self.settled);
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                work();
                settled.open();
            })
            .map_err(|error| ProviderWorkerSpawnErrorV1::new(error.to_string()))?;
        Ok(Box::new(HostThreadHandle))
    }
}

struct InlineWorkers;

impl ProviderWorkerSpawnV1 for InlineWorkers {
    fn isolation(&self) -> ProviderWorkerIsolationV1 {
        ProviderWorkerIsolationV1::CooperativeOnly
    }

    fn spawn_detached(
        &self,
        _name: &str,
        work: ProviderWorkV1,
    ) -> Result<Box<dyn ProviderWorkerHandleV1>, ProviderWorkerSpawnErrorV1> {
        work();
        Ok(Box::new(HostThreadHandle))
    }
}

fn cancellation_boundary(spawn: Arc<dyn ProviderWorkerSpawnV1>) -> ProviderInvocationBoundaryV1 {
    ProviderInvocationBoundaryV1::new(ProviderInvocationLimitsV1::for_in_flight(1), spawn)
}

fn cancelled_before_contact() -> ProviderInvocationFaultV1 {
    ProviderInvocationFaultV1::Cancelled {
        provider_id: PROVIDER.to_owned(),
        waited_millis: 0,
        disposition: WorkerDispositionV1::Terminated,
    }
}

async fn assert_cancellation_preempts_pre_contact_refusal(
    boundary: &ProviderInvocationBoundaryV1,
    execution_shape: ProviderExecutionShapeV1,
    refusal: &str,
) {
    let contacts = Arc::new(AtomicUsize::new(0));
    let contacted = Arc::clone(&contacts);
    let outcome = boundary
        .invoke(
            ProviderInvocationRequestV1 {
                provider_id: PROVIDER,
                execution_shape,
                budget: Duration::from_secs(30),
                cancelled: Box::pin(ReadyAfterFirstPoll { polled: false }),
            },
            move || contacted.fetch_add(1, Ordering::AcqRel),
        )
        .await;

    assert_eq!(
        outcome,
        Err(cancelled_before_contact()),
        "cancellation must preempt the {refusal} refusal"
    );
    assert_eq!(
        contacts.load(Ordering::Acquire),
        0,
        "the {refusal} path contacted provider code"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default(),
        "the {refusal} path changed the worker census"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_cancelled_is_terminal_before_execution_shape_or_capacity_decisions() {
    let boundary = boundary();

    for execution_shape in [
        ProviderExecutionShapeV1::HostAuthoredInProcess,
        ProviderExecutionShapeV1::Foreign,
    ] {
        let contacts = Arc::new(AtomicUsize::new(0));
        let contacted = Arc::clone(&contacts);
        let outcome = boundary
            .invoke(
                ProviderInvocationRequestV1 {
                    provider_id: PROVIDER,
                    execution_shape,
                    budget: Duration::from_secs(30),
                    cancelled: Box::pin(std::future::ready(())),
                },
                move || contacted.fetch_add(1, Ordering::AcqRel),
            )
            .await;

        assert_eq!(
            outcome,
            Err(cancelled_before_contact()),
            "an already-withdrawn {execution_shape:?} call must end as cancellation"
        );
        assert_eq!(contacts.load(Ordering::Acquire), 0);
        assert_eq!(
            boundary.worker_census(PROVIDER),
            ProviderWorkerCensusV1::default()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_preempts_every_pre_contact_refusal() {
    let isolated = cancellation_boundary(Arc::new(HostWorkers));
    assert_cancellation_preempts_pre_contact_refusal(
        &isolated,
        ProviderExecutionShapeV1::Foreign,
        "foreign-isolation",
    )
    .await;

    let stalled = ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1 {
            max_workers: 1,
            max_stranded_workers: 0,
        },
        Arc::new(HostWorkers),
    );
    assert_cancellation_preempts_pre_contact_refusal(
        &stalled,
        ProviderExecutionShapeV1::HostAuthoredInProcess,
        "stalled-provider",
    )
    .await;

    let exhausted = ProviderInvocationBoundaryV1::new(
        ProviderInvocationLimitsV1 {
            max_workers: 0,
            max_stranded_workers: 1,
        },
        Arc::new(HostWorkers),
    );
    assert_cancellation_preempts_pre_contact_refusal(
        &exhausted,
        ProviderExecutionShapeV1::HostAuthoredInProcess,
        "worker-capacity",
    )
    .await;

    let unavailable = cancellation_boundary(Arc::new(RefusingWorkers));
    assert_cancellation_preempts_pre_contact_refusal(
        &unavailable,
        ProviderExecutionShapeV1::HostAuthoredInProcess,
        "worker-unavailable",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_ready_with_delivery_is_repolled_before_acceptance() {
    let boundary = cancellation_boundary(Arc::new(InlineWorkers));
    let contacts = Arc::new(AtomicUsize::new(0));
    let contacted = Arc::clone(&contacts);

    let outcome = boundary
        .invoke(
            ProviderInvocationRequestV1 {
                provider_id: PROVIDER,
                execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                budget: Duration::from_secs(30),
                cancelled: Box::pin(ReadyAfterFirstPoll { polled: false }),
            },
            move || {
                contacted.fetch_add(1, Ordering::AcqRel);
                "withdrawn answer"
            },
        )
        .await;

    assert!(
        matches!(
            outcome,
            Err(ProviderInvocationFaultV1::Cancelled {
                ref provider_id,
                disposition: WorkerDispositionV1::Terminated,
                ..
            }) if provider_id == PROVIDER
        ),
        "a delivered answer cannot bypass cancellation that is already ready: {outcome:?}"
    );
    assert_eq!(contacts.load(Ordering::Acquire), 1);
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_stays_terminal_when_worker_settles_before_stop_takes_the_slot() {
    let withdrawn = Arc::new(AtomicBool::new(false));
    let provider_release = Arc::new(CancellationGate::default());
    let provider_settled = Arc::new(CancellationGate::default());
    let boundary = cancellation_boundary(Arc::new(SettlementSignallingWorkers {
        settled: Arc::clone(&provider_settled),
    }));

    let release = Arc::clone(&provider_release);
    let saw_withdrawal = Arc::clone(&withdrawn);
    let outcome = boundary
        .invoke(
            ProviderInvocationRequestV1 {
                provider_id: PROVIDER,
                execution_shape: ProviderExecutionShapeV1::HostAuthoredInProcess,
                budget: Duration::from_secs(30),
                cancelled: Box::pin(CancelThenAllowSettlement {
                    first_poll: true,
                    withdrawn: Arc::clone(&withdrawn),
                    provider_release: Arc::clone(&provider_release),
                    provider_settled: Arc::clone(&provider_settled),
                }),
            },
            move || {
                release.wait();
                assert!(
                    saw_withdrawal.load(Ordering::Acquire),
                    "the provider was allowed to answer before cancellation was ready"
                );
                "late answer"
            },
        )
        .await;

    assert!(
        matches!(
            outcome,
            Err(ProviderInvocationFaultV1::Cancelled {
                ref provider_id,
                disposition: WorkerDispositionV1::Terminated,
                ..
            }) if provider_id == PROVIDER
        ),
        "settlement before stop acquired the slot recovered a withdrawn answer: {outcome:?}"
    );
    assert_eq!(
        boundary.worker_census(PROVIDER),
        ProviderWorkerCensusV1::default()
    );
}
