use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use tracedecay_contracts::{CancellationSignal, Deadline};
use tracedecay_temporal_query::execution::ExecutionControl;

use super::session_temporal_refresh_scheduler::projector::{
    CanonicalSessionTemporalProjector, SessionTemporalRefreshEffect,
    SessionTemporalRefreshProjector,
};
use tracedecay_domain::SessionId;
use tracedecay_global_db::RegisteredGlobalDbLeaseV1;
use tracedecay_lcm::{LcmCompressionRequest, LcmCompressionResponse, LcmError, LcmSummarizerMode};
#[cfg(any(test, feature = "test-helpers"))]
use tracedecay_lcm::{LcmSessionBoundaryRequest, LcmSessionBoundaryResponse};
use tracedecay_runtime_core::native_runtime;
use tracedecay_session_temporal_store::{SessionRefreshRestartStateV1, SessionTemporalAccess};
use tracedecay_store::SessionRefreshCompletionRequestV1;

pub(super) const LCM_EFFECT_CEILING: Duration =
    tracedecay_daemon_protocol::DEFAULT_DAEMON_OPERATION_DEADLINE;
const LCM_EFFECT_WORK_LIMIT: usize = 4_096;

/// Daemon-owned execution boundary for retained LCM mutations.
///
/// The database authority remains lower-level storage. Host and MCP adapters
/// call this service so a disconnect or deadline can still roll back the open
/// transaction before its commit checkpoint.
#[derive(Clone)]
pub(super) struct DaemonLcmEffectService {
    db: RegisteredGlobalDbLeaseV1,
    control: LcmEffectControl,
}

#[derive(Clone)]
struct LcmEffectControl {
    cancellation: Option<CancellationSignal>,
    expires_at: std::time::Instant,
}

impl LcmEffectControl {
    fn new(deadline: Option<&Deadline>, cancellation: Option<&CancellationSignal>) -> Self {
        let budget = deadline
            .and_then(tracedecay_daemon_protocol::deadline_remaining)
            .map_or(LCM_EFFECT_CEILING, |remaining| {
                remaining.min(LCM_EFFECT_CEILING)
            });
        Self {
            cancellation: cancellation.cloned(),
            expires_at: std::time::Instant::now() + budget,
        }
    }

    fn checkpoint(&self) -> Result<(), LcmError> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationSignal::is_cancelled)
        {
            return Err(LcmError::Cancelled);
        }
        if std::time::Instant::now() >= self.expires_at {
            return Err(LcmError::DeadlineExceeded);
        }
        Ok(())
    }

    async fn execute<T: Send>(
        &self,
        execution: &ExecutionControl,
        mutation: Pin<Box<dyn Future<Output = Result<T, LcmError>> + Send + '_>>,
    ) -> Result<T, LcmError> {
        self.checkpoint()?;
        let result = mutation.await;
        if result.is_err() {
            execution.cancel();
        }
        result
    }

    fn execution_control(&self) -> ExecutionControl {
        let control =
            ExecutionControl::new(Some(self.expires_at)).with_work_limit(LCM_EFFECT_WORK_LIMIT);
        if self.checkpoint().is_err() {
            control.cancel();
        }
        control
    }

    async fn interruptible<T>(
        &self,
        future: impl std::future::Future<Output = T>,
    ) -> Result<T, LcmError> {
        self.checkpoint()?;
        tokio::select! {
            biased;
            () = async {
                match &self.cancellation {
                    Some(signal) => signal.cancelled().await,
                    None => std::future::pending().await,
                }
            } => Err(LcmError::Cancelled),
            fired = native_runtime::sleep_until(self.expires_at) => match fired {
                Ok(()) => Err(LcmError::DeadlineExceeded),
                Err(error) => Err(LcmError::Db(format!("LCM effect deadline timer unavailable: {error}"))),
            },
            value = future => Ok(value),
        }
    }

    fn remaining(&self) -> Result<Duration, LcmError> {
        self.checkpoint()?;
        Ok(self
            .expires_at
            .saturating_duration_since(std::time::Instant::now()))
    }
}

impl DaemonLcmEffectService {
    pub(super) fn new(
        db: RegisteredGlobalDbLeaseV1,
        deadline: Option<&Deadline>,
        cancellation: Option<&CancellationSignal>,
    ) -> Self {
        Self {
            db,
            control: LcmEffectControl::new(deadline, cancellation),
        }
    }

    pub(super) async fn compress(
        &self,
        mut request: LcmCompressionRequest,
    ) -> Result<LcmCompressionResponse, LcmError> {
        let _publication = self
            .control
            .interruptible(self.db.session_publication_guard())
            .await?;
        self.control
            .interruptible(self.settle_session_projection(&request.session_id))
            .await??;
        let snapshot = self
            .db
            .read_snapshot()
            .await
            .map_err(|error| LcmError::Db(error.to_string()))?;
        tracedecay_session_temporal_store::operations::require_summary_publication_generation(
            &snapshot,
            &request.session_id,
        )
        .await?;
        drop(snapshot);
        // Observation-projected sessions land raw rows without ingest
        // protection; the verified raw loads inside compression reject them.
        // Hydrate the canonical sanitization receipts first so the daemon
        // journey consumes the same protected shape as transcript ingest.
        let execution = self.control.execution_control();
        self.control
            .execute(
                &execution,
                Box::pin(tracing::Instrument::instrument(
                    self.db
                        .lcm_protect_session_raw_messages(&request.provider, &request.session_id),
                    tracing::trace_span!("daemon.lcm.hydrate"),
                )),
            )
            .await?;
        if matches!(
            &request.summarizer,
            LcmSummarizerMode::Provided { summary_text, .. } if !summary_text.trim().is_empty()
        ) || matches!(&request.summarizer, LcmSummarizerMode::Fake { .. })
        {
            return self
                .commit_compression(&request, None)
                .await
                .map(|(response, _)| response);
        }

        // The message corpus is owned once by `request`; only `summarizer`
        // changes between the planning pass and the final commit.
        request.summarizer = LcmSummarizerMode::HermesAuxiliary;
        let (pending, raw_revision) = self.commit_compression(&request, None).await?;
        if pending.status != "needs_summary" {
            return Ok(pending);
        }
        let Some(summary_request) = pending.summary_request.as_ref() else {
            return Ok(pending);
        };
        let summary = match self
            .control
            .interruptible(super::lcm_summarization::resolve_authoritative_summary(
                &self.db,
                &request.provider,
                &request.session_id,
                summary_request,
                self.control.remaining()?,
                None,
            ))
            .await?
        {
            Ok(summary) => summary,
            Err(super::lcm_summarization::SummaryResolutionError::Storage(error)) => {
                return Err(error);
            }
            Err(super::lcm_summarization::SummaryResolutionError::Unavailable(reason)) => {
                self.control.checkpoint()?;
                return Ok(summary_unavailable(pending, reason));
            }
        };
        self.control.checkpoint()?;
        request.summarizer = LcmSummarizerMode::Provided {
            summary_text: summary.text,
            route: Some(summary.route),
        };
        let revision = raw_revision.ok_or_else(|| {
            LcmError::Db("summary planning has no canonical raw revision".to_owned())
        })?;
        self.commit_compression(&request, Some((summary_request, revision)))
            .await
            .map(|(response, _)| response)
    }

    pub(super) async fn compress_retained_page(
        &self,
        mut request: LcmCompressionRequest,
        convergence_candidate: &tracedecay_lcm::summary_convergence::LcmSummaryConvergenceCandidate,
    ) -> Result<tracedecay_lcm::summary_convergence::LcmBoundedCompressionResponse, LcmError> {
        let _publication = self
            .control
            .interruptible(self.db.session_publication_guard())
            .await?;
        self.control
            .interruptible(self.settle_session_projection(&request.session_id))
            .await??;
        let snapshot = self
            .db
            .read_snapshot()
            .await
            .map_err(|error| LcmError::Db(error.to_string()))?;
        tracedecay_session_temporal_store::operations::require_summary_publication_generation(
            &snapshot,
            &request.session_id,
        )
        .await?;
        drop(snapshot);
        if matches!(
            &request.summarizer,
            LcmSummarizerMode::Provided { summary_text, .. } if !summary_text.trim().is_empty()
        ) || matches!(&request.summarizer, LcmSummarizerMode::Fake { .. })
        {
            return self
                .commit_retained_compression(&request, Some(convergence_candidate), None)
                .await;
        }

        request.summarizer = LcmSummarizerMode::HermesAuxiliary;
        let pending = self
            .commit_retained_compression(&request, Some(convergence_candidate), None)
            .await?;
        if pending.response.status != "needs_summary" {
            return Ok(pending);
        }
        let Some(summary_request) = pending.response.summary_request.as_ref() else {
            return Ok(pending);
        };
        // Host-native compaction text is usable for retained convergence only
        // when its evidence binds the exact raw source range selected by this
        // page. Otherwise the provider authority summarizes source_messages.
        let required_native_source_range = summary_request.source_range.clone();
        let summary = match self
            .control
            .interruptible(super::lcm_summarization::resolve_authoritative_summary(
                &self.db,
                &request.provider,
                &request.session_id,
                summary_request,
                self.control.remaining()?,
                Some(&required_native_source_range),
            ))
            .await?
        {
            Ok(summary)
                if summary.source_range.interval() == Some(&required_native_source_range) =>
            {
                summary
            }
            Ok(summary) => {
                self.control.checkpoint()?;
                let mut pending = pending;
                // An absent interval is its own typed state; only a present
                // interval that binds a different range is a mismatch.
                pending.response = summary_unavailable(
                    pending.response,
                    summary
                        .source_range
                        .absent_reason()
                        .unwrap_or("authoritative_summary_source_mismatch"),
                );
                return Ok(pending);
            }
            Err(super::lcm_summarization::SummaryResolutionError::Storage(error)) => {
                return Err(error);
            }
            Err(super::lcm_summarization::SummaryResolutionError::Unavailable(reason)) => {
                self.control.checkpoint()?;
                let mut pending = pending;
                pending.response = summary_unavailable(pending.response, reason);
                return Ok(pending);
            }
        };
        self.control.checkpoint()?;
        request.summarizer = LcmSummarizerMode::Provided {
            summary_text: summary.text,
            route: Some(summary.route),
        };
        let mut committed = self
            .commit_retained_compression(
                &request,
                Some(convergence_candidate),
                Some(summary_request),
            )
            .await?;
        committed.rows_scanned = committed.rows_scanned.saturating_add(pending.rows_scanned);
        committed.bytes_scanned = committed
            .bytes_scanned
            .saturating_add(pending.bytes_scanned);
        committed.has_more |= pending.has_more;
        Ok(committed)
    }

    // Compaction joins only its selected session's already-owned refresh. One
    // canonical page is the foreground work bound; larger refreshes remain
    // owned by background convergence and never launch a summarizer here.
    async fn settle_session_projection(&self, session: &str) -> Result<(), LcmError> {
        let session =
            SessionId::new(session.to_owned()).map_err(|error| LcmError::Db(error.to_string()))?;
        let access = SessionTemporalAccess::new(self.db.as_ref());
        let map_error = |error| LcmError::Db(format!("settle summary session projection: {error}"));
        let Some(mut recovery) = access
            .session_refresh_recovery_result(&session)
            .await
            .map_err(map_error)?
        else {
            return Ok(());
        };
        if recovery.restart_state() != SessionRefreshRestartStateV1::ReadyToComplete {
            match CanonicalSessionTemporalProjector
                .project(&self.db, recovery.clone())
                .await
            {
                Ok(SessionTemporalRefreshEffect::Projection { progress, batch }) => {
                    access
                        .persist_session_refresh_projection_batch_controlled_result(
                            progress,
                            batch,
                            self.control.execution_control(),
                        )
                        .await
                        .map_err(map_error)?;
                }
                Err(error) => {
                    tracing::warn!(reason_code = error.code.as_str(), class = ?error.class, "selected session projection failed");
                    return Err(LcmError::Db(
                        "selected session projection failed".to_owned(),
                    ));
                }
                Ok(SessionTemporalRefreshEffect::Fail(request)) => {
                    access
                        .fail_session_refresh_result(request)
                        .await
                        .map_err(map_error)?;
                    return Err(LcmError::Db(
                        "selected session projection terminally failed".to_owned(),
                    ));
                }
                Ok(SessionTemporalRefreshEffect::Deferred) => {
                    return Err(LcmError::StaleSummaryGeneration {
                        expected: i64::try_from(
                            recovery.frozen_watermarks().active_generation().value(),
                        )
                        .map_err(|error| LcmError::Db(error.to_string()))?,
                        actual: i64::try_from(recovery.candidate_generation().value())
                            .map_err(|error| LcmError::Db(error.to_string()))?,
                    });
                }
            }
            let updated = access
                .session_refresh_recovery_result(&session)
                .await
                .map_err(map_error)?
                .ok_or_else(|| {
                    LcmError::Db("selected refresh ownership changed during projection".to_owned())
                })?;
            recovery = updated;
        }
        if recovery.restart_state() != SessionRefreshRestartStateV1::ReadyToComplete {
            return Err(LcmError::StaleSummaryGeneration {
                expected: i64::try_from(recovery.frozen_watermarks().active_generation().value())
                    .map_err(|error| LcmError::Db(error.to_string()))?,
                actual: i64::try_from(recovery.candidate_generation().value())
                    .map_err(|error| LcmError::Db(error.to_string()))?,
            });
        }
        let progress = recovery
            .progress()
            .ok_or_else(|| LcmError::Db("ready refresh lacks durable progress".to_owned()))?;
        let request = SessionRefreshCompletionRequestV1::new(
            recovery.operation_id().clone(),
            session,
            progress.frontier(),
            *progress.coverage(),
        )
        .map_err(|error| LcmError::Db(error.to_string()))?;
        let request = match progress.source_coverage() {
            Some(coverage) => request.with_source_coverage(coverage.clone()),
            None => request,
        };
        access
            .complete_session_refresh_result(request, self.control.execution_control())
            .await
            .map_err(map_error)?;
        self.control.checkpoint()
    }

    async fn commit_compression(
        &self,
        request: &LcmCompressionRequest,
        source_guard: Option<(&tracedecay_lcm::LcmSummaryRequest, i64)>,
    ) -> Result<(LcmCompressionResponse, Option<i64>), LcmError> {
        let execution = self.control.execution_control();
        let before_commit = self.control.clone();
        self.control
            .execute(
                &execution,
                Box::pin(tracing::Instrument::instrument(
                    self.db
                        .lcm_compress_guarded(request, &execution, source_guard, move || {
                            before_commit.checkpoint()
                        }),
                    tracing::trace_span!("daemon.lcm.commit"),
                )),
            )
            .await
    }

    async fn commit_retained_compression(
        &self,
        request: &LcmCompressionRequest,
        convergence_candidate: Option<
            &tracedecay_lcm::summary_convergence::LcmSummaryConvergenceCandidate,
        >,
        expected_summary: Option<&tracedecay_lcm::LcmSummaryRequest>,
    ) -> Result<tracedecay_lcm::summary_convergence::LcmBoundedCompressionResponse, LcmError> {
        // A retained pass can perform one planning scan and one commit scan.
        // Split the existing page budgets between those phases so the whole
        // service call, rather than each internal phase, remains bounded.
        const RETAINED_PHASE_ROWS: usize = tracedecay_lcm::LCM_SCAN_PAGE_ROWS as usize / 2;
        const RETAINED_PHASE_BYTES: u64 = tracedecay_lcm::LCM_SCAN_PAGE_MAX_BYTES as u64 / 2;
        let execution = self.control.execution_control();
        let before_commit = self.control.clone();
        let compressed: Pin<
            Box<
                dyn Future<
                        Output = Result<
                            tracedecay_lcm::summary_convergence::LcmBoundedCompressionResponse,
                            LcmError,
                        >,
                    > + Send,
            >,
        > = Box::pin(self.db.lcm_compress_retained_page_guarded(
            request,
            &execution,
            move || before_commit.checkpoint(),
            tracedecay_lcm::compression::RetainedCompressionGuard {
                row_limit: RETAINED_PHASE_ROWS,
                byte_limit: RETAINED_PHASE_BYTES,
                expected_summary_source_range:
                    expected_summary.map(|summary| summary.source_range.clone()),
            },
            convergence_candidate,
            expected_summary,
        ));
        self.control
            .execute(
                &execution,
                Box::pin(tracing::Instrument::instrument(
                    compressed,
                    tracing::trace_span!("daemon.lcm.retained_commit"),
                )),
            )
            .await
    }

    pub(super) async fn recover_retained_relation_projection_page(
        &self,
    ) -> Result<tracedecay_session_temporal_store::SessionRelationRecoveryPage, LcmError> {
        const RELATION_PAGE_LIMIT: usize = 1;
        let execution = self.control.execution_control();
        let recovered = self
            .control
            .execute(&execution, Box::pin(async {
                SessionTemporalAccess::new(&*self.db)
                    .recover_pending_session_relation_projection_page(
                        RELATION_PAGE_LIMIT,
                        tracedecay_session_temporal_store::store::execution_control_graph_cancellation(
                            &execution,
                        ),
                    )
                    .await
                    .map_err(|error| match error {
                        tracedecay_store::SessionStoreError::Cancelled => LcmError::Cancelled,
                        tracedecay_store::SessionStoreError::DeadlineExceeded => {
                            LcmError::DeadlineExceeded
                        }
                        error => LcmError::Db(format!(
                            "recover bounded retained LCM relation projection: {error}"
                        )),
                    })
            }))
            .await?;
        self.control.checkpoint()?;
        Ok(recovered)
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub(super) async fn session_boundary(
        &self,
        request: LcmSessionBoundaryRequest,
    ) -> Result<LcmSessionBoundaryResponse, LcmError> {
        let execution = self.control.execution_control();
        let before_commit = self.control.clone();
        self.control
            .execute(
                &execution,
                Box::pin(tracing::Instrument::instrument(
                    self.db
                        .lcm_session_boundary_guarded(request, move || before_commit.checkpoint()),
                    tracing::trace_span!("daemon.lcm.boundary"),
                )),
            )
            .await
    }
}

#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub async fn lcm_compress_for_test(
    db: RegisteredGlobalDbLeaseV1,
    request: LcmCompressionRequest,
) -> Result<LcmCompressionResponse, LcmError> {
    DaemonLcmEffectService::new(db, None, None)
        .compress(request)
        .await
}

#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub async fn lcm_session_boundary_for_test(
    db: RegisteredGlobalDbLeaseV1,
    request: LcmSessionBoundaryRequest,
) -> Result<LcmSessionBoundaryResponse, LcmError> {
    DaemonLcmEffectService::new(db, None, None)
        .session_boundary(request)
        .await
}

fn summary_unavailable(
    mut response: LcmCompressionResponse,
    reason: &'static str,
) -> LcmCompressionResponse {
    response.reason = reason.to_string();
    response.retry_status = Some("needs_authoritative_summary".to_string());
    response
}

#[cfg(test)]
mod tests;
