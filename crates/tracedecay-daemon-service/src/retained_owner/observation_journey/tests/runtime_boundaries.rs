use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tracedecay_domain::SessionId;
use tracedecay_memory_provider_registry::MemoryProviderV1;
use tracedecay_runtime_core::cancellation::CancellationToken as HostCancellationToken;
use tracedecay_runtime_core::native_runtime;

use super::{
    HeldInstanceProof, JourneyObservationProvider, ObservationJourneyError, RefusingReplayPort,
    ReplayBoundsV1, ReplayPassV1, SettledRecordsPort, busy_store_failure, canonical_observation,
    classification_mount_inputs, composition, construct_project_observation_journey,
    mount_observer_dormant, run_startup_replay, settled_record,
};

/// Runtime installation is process-global. A child keeps this test from
/// installing or removing a runtime another concurrently running test owns.
#[test]
fn observation_journey_on_native_workers_requires_and_uses_owned_tokio() {
    const CHILD: &str = "TRACEDECAY_OBSERVATION_RUNTIME_BOUNDARY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let module = module_path!()
            .split_once("::")
            .expect("crate-qualified module")
            .1;
        let test = format!(
            "{module}::observation_journey_on_native_workers_requires_and_uses_owned_tokio"
        );
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, "1")
            .status()
            .expect("isolated runtime test");
        assert!(status.success(), "isolated runtime test failed: {status}");
        return;
    }

    assert!(tokio::runtime::Handle::try_current().is_err());
    native_runtime::block_on(async {
        let temp = TempDir::new().expect("temporary journey root");
        let inputs = classification_mount_inputs(&temp, "project.observation-runtime-missing");
        let journal = inputs
            .store_data_root
            .join(inputs.provider.journal_file_name);
        let refused = mount_observer_dormant(inputs, &HostCancellationToken::new())
            .await
            .err()
            .expect("a missing runtime must refuse the mount");
        assert!(matches!(refused, ObservationJourneyError::Worker(_)));
        assert!(
            !journal.exists(),
            "a refused mount must not open the journal"
        );

        let inputs = classification_mount_inputs(&temp, "project.observation-runtime-live-refusal");
        let journey =
            construct_project_observation_journey(inputs).expect("dormant retained state");
        assert!(matches!(
            journey
                .await_instance_ready(&HostCancellationToken::new(), Duration::from_secs(1))
                .await,
            Err(ObservationJourneyError::Worker(_))
        ));
        assert!(matches!(
            journey.start_live_replay(SettledRecordsPort { records: vec![] }),
            Err(ObservationJourneyError::Worker(_))
        ));
        assert!(journey.live_replay_task.lock().unwrap().is_none());

        let store = RefusingReplayPort {
            refusals: Mutex::new(vec![busy_store_failure()]),
            then: vec![],
        };
        let misses =
            native_runtime::tokio_runtime_missing_count("memory_observation.canonical_replay");
        let cancellation = HostCancellationToken::new();
        let cancelled = HostCancellationToken::new();
        cancelled.cancel();
        let expired = tokio::time::Instant::now() - Duration::from_millis(1);
        assert!(matches!(
            journey
                .replay_canonical_observations(
                    &store,
                    1,
                    ReplayBoundsV1 {
                        cancellation: &cancelled,
                        deadline: expired,
                    },
                )
                .await,
            Err(ObservationJourneyError::Cancelled { admitted: 0 })
        ));
        assert!(matches!(
            journey
                .replay_canonical_observations(
                    &store,
                    1,
                    ReplayBoundsV1 {
                        cancellation: &cancellation,
                        deadline: expired,
                    },
                )
                .await,
            Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 })
        ));
        let empty = ReplayPassV1 {
            admitted: 0,
            halted: None,
            shed: None,
        };
        assert_eq!(
            journey
                .replay_canonical_observations(
                    &store,
                    0,
                    ReplayBoundsV1 {
                        cancellation: &cancelled,
                        deadline: expired,
                    },
                )
                .await
                .expect("zero pages take precedence over cancellation and deadline"),
            empty
        );
        journey.stopping.cancel();
        assert_eq!(
            journey
                .replay_canonical_observations(
                    &store,
                    1,
                    ReplayBoundsV1 {
                        cancellation: &cancelled,
                        deadline: expired,
                    },
                )
                .await
                .expect("journey shutdown takes precedence over caller terminals"),
            empty
        );
        assert_eq!(
            native_runtime::tokio_runtime_missing_count("memory_observation.canonical_replay"),
            misses,
            "terminal and no-work replay must not look up a Tokio runtime"
        );
        assert_eq!(
            store.refusals.lock().unwrap().len(),
            1,
            "terminal and no-work replay must not poll the store"
        );
    })
    .expect("native root without Tokio");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("owned Tokio runtime");
    native_runtime::install_tokio_runtime(runtime.handle().clone()).expect("install owned runtime");
    let runtime_handle = runtime.handle().clone();
    let native = native_runtime::NativeTask::spawn(async move {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let temp = TempDir::new().expect("temporary journey root");
        let port = Arc::new(JourneyObservationProvider::new());
        let mut inputs = classification_mount_inputs(&temp, "project.observation-native-worker");
        inputs.composition = composition(Arc::clone(&port) as Arc<dyn MemoryProviderV1>);
        let project = inputs.authoritative_project_id.clone();
        let cancellation = HostCancellationToken::new();
        let journey = mount_observer_dormant(inputs, &cancellation)
            .await
            .expect("mount from a native worker");
        assert!(tokio::runtime::Handle::try_current().is_err());

        let first = settled_record(
            1,
            canonical_observation(
                &project,
                &SessionId::new("session.native-startup").unwrap(),
                "native-worker startup observation",
            ),
        );
        let pass = run_startup_replay(&journey, &SettledRecordsPort::single(first), &cancellation)
            .await
            .expect("native startup replay");
        assert_eq!(pass.admitted, 1);

        let second = settled_record(
            2,
            canonical_observation(
                &project,
                &SessionId::new("session.native-live").unwrap(),
                "native-worker live observation",
            ),
        );
        journey
            .start_observer_with_live_replay(SettledRecordsPort::single(second))
            .expect("start workers without an ambient Tokio runtime");
        journey
            .await_instance_ready(&cancellation, Duration::from_secs(1))
            .await
            .expect("instance readiness from a native worker");
        native_runtime::in_tokio_context(runtime_handle.clone(), async {
            journey
                .delivery_changed
                .wait_until_async(Duration::from_secs(5), || {
                    (port.observe_calls.load(Ordering::Acquire) == 2).then_some(())
                })
                .await
        })
        .await
        .expect("the owned live task must replay and deliver the second observation");
        journey
            .await_delivery_settled(&cancellation, Duration::from_secs(5))
            .await
            .expect("durable delivery settlement from a native worker");
        assert_eq!(journey.replay_watermark().await.unwrap(), 2);

        let pending_root = TempDir::new().expect("temporary pending journey root");
        let mut pending_inputs =
            classification_mount_inputs(&pending_root, "project.observation-native-proof-wait");
        pending_inputs.provider.provider_instance_id = None;
        pending_inputs.provider.instance_proof = Some(Arc::new(HeldInstanceProof {
            entered: Arc::new(AtomicBool::new(false)),
            release: Arc::new(AtomicBool::new(false)),
            instance: "instance.pending-native-proof".to_owned(),
        }));
        let pending = mount_observer_dormant(pending_inputs, &cancellation)
            .await
            .expect("pending journey without a started proof worker");
        assert!(matches!(
            pending
                .await_instance_ready(&cancellation, Duration::from_millis(1))
                .await,
            Err(ObservationJourneyError::ProviderInstanceDeadlineExceeded)
        ));
        drop(pending);
        let cancelled = HostCancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            journey
                .await_delivery_settled(&cancelled, Duration::from_secs(1))
                .await,
            Err(ObservationJourneyError::Cancelled { admitted: 0 })
        ));
        let expired = journey
            .replay_canonical_observations(
                &SettledRecordsPort { records: vec![] },
                1,
                ReplayBoundsV1 {
                    cancellation: &cancellation,
                    deadline: tokio::time::Instant::now() - Duration::from_millis(1),
                },
            )
            .await;
        assert!(matches!(
            expired,
            Err(ObservationJourneyError::DeadlineExceeded { admitted: 0 })
        ));

        // This is the same per-poll boundary as provider_host::shutdown_in_tokio,
        // the sole production caller of the retained journey's shutdown.
        let failures = native_runtime::in_tokio_context(
            runtime_handle,
            journey.shutdown(tokio::time::Instant::now() + Duration::from_secs(5)),
        )
        .await;
        assert!(failures.is_empty(), "{failures:?}");
        assert!(tokio::runtime::Handle::try_current().is_err());
    })
    .expect("native observation worker");
    let outcome = native_runtime::block_on(native_runtime::timeout(
        Duration::from_secs(30),
        native.wait(),
    ))
    .expect("native root")
    .expect("native observation worker must finish");
    native_runtime::uninstall_tokio_runtime().expect("remove owned runtime");
    assert!(
        matches!(outcome, native_runtime::NativeTaskOutcome::Completed(())),
        "{outcome:?}"
    );
}
