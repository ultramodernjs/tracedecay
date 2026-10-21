//! Revalidates a profile sweep's ownership snapshot at each admission boundary.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use super::authority::SessionIngestAuthority;
use crate::admission::{
    AdmissionFuture, HostAdmission, HostAdmissionOutcome, HostDiscoveryQueueEntry,
    HostProjectionDrainOutcome,
};
use crate::observation::{
    CaptureObservationOutcome, CaptureObservationRequest, ObservationCancellation,
};
use tracedecay_domain::{
    ObservationScopeV1, ObservationSourceCursorV1, ObservationSourceGenerationV1,
    ObservationSourceIdentityV1,
};
use tracedecay_store::ParseOffset;
use tracedecay_store::observation::{CursorAdvanceOutcome, ObservationCursorAdvance};

pub use super::failure::{IngestPassBounds, IngestPassOutcome};
pub use super::user::ingest_user_global_sources_with_registry_bounded;

pub type RegisteredRootsRead<'a> = Pin<Box<dyn Future<Output = Option<Vec<PathBuf>>> + Send + 'a>>;

/// Read the current project registry, not the session shard's registry tables.
pub trait RegisteredRootsReader: Send + Sync {
    fn registered_roots(&self) -> RegisteredRootsRead<'_>;
}

pub struct SessionIngestRegistryRoots<'a, A>(pub &'a A);

impl<A: SessionIngestAuthority> RegisteredRootsReader for SessionIngestRegistryRoots<'_, A> {
    fn registered_roots(&self) -> RegisteredRootsRead<'_> {
        Box::pin(self.0.registered_project_roots())
    }
}

/// Defers stale work rather than persisting OutOfScope coverage from an old
/// ownership decision. The caller retries with fresh roots on the next pass.
/// Registration racing the final check still needs target-first reconciliation.
pub struct ProfileOwnershipAdmission<'a> {
    inner: &'a dyn HostAdmission,
    registry: &'a dyn RegisteredRootsReader,
    roots: Vec<PathBuf>,
}

impl<'a> ProfileOwnershipAdmission<'a> {
    pub fn new(
        inner: &'a dyn HostAdmission,
        registry: &'a dyn RegisteredRootsReader,
        roots: &[PathBuf],
    ) -> Self {
        let mut roots = roots.to_vec();
        roots.sort();
        roots.dedup();
        Self {
            inner,
            registry,
            roots,
        }
    }

    async fn check_ownership(&self) -> Result<(), HostAdmissionOutcome> {
        let mut roots = self.registry.registered_roots().await.ok_or_else(|| {
            HostAdmissionOutcome::retained_unavailable("project_registry_unavailable")
        })?;
        roots.sort();
        roots.dedup();
        if roots != self.roots {
            return Err(HostAdmissionOutcome::retained_unavailable(
                "project_registry_changed",
            ));
        }
        Ok(())
    }
}

impl HostAdmission for ProfileOwnershipAdmission<'_> {
    fn capture_observation<'a>(
        &'a self,
        request: CaptureObservationRequest,
    ) -> AdmissionFuture<'a, CaptureObservationOutcome> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner.capture_observation(request).await
        })
    }

    fn capture_observations<'a>(
        &'a self,
        requests: Vec<CaptureObservationRequest>,
    ) -> AdmissionFuture<'a, Vec<CaptureObservationOutcome>> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner.capture_observations(requests).await
        })
    }

    fn advance_non_durable_source_cursor<'a>(
        &'a self,
        advance: ObservationCursorAdvance,
        cancellation: ObservationCancellation,
    ) -> AdmissionFuture<'a, CursorAdvanceOutcome> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .advance_non_durable_source_cursor(advance, cancellation)
                .await
        })
    }

    fn get_source_cursor<'a>(
        &'a self,
        source: &'a ObservationSourceIdentityV1,
        scope: &'a ObservationScopeV1,
    ) -> AdmissionFuture<'a, Option<ObservationSourceCursorV1>> {
        self.inner.get_source_cursor(source, scope)
    }

    fn committed_source_cursors<'a>(
        &'a self,
        source: &'a ObservationSourceIdentityV1,
        scope: &'a ObservationScopeV1,
    ) -> AdmissionFuture<'a, Vec<ObservationSourceCursorV1>> {
        self.inner.committed_source_cursors(source, scope)
    }

    fn begin_source_rewrite<'a>(
        &'a self,
        source: &'a ObservationSourceIdentityV1,
        scope: &'a ObservationScopeV1,
        previous: ObservationSourceGenerationV1,
        generation: ObservationSourceGenerationV1,
        retained_through: u64,
    ) -> AdmissionFuture<'a, ()> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .begin_source_rewrite(source, scope, previous, generation, retained_through)
                .await
        })
    }

    fn complete_source_rewrite<'a>(
        &'a self,
        source: &'a ObservationSourceIdentityV1,
        scope: &'a ObservationScopeV1,
        generation: ObservationSourceGenerationV1,
    ) -> AdmissionFuture<'a, u64> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .complete_source_rewrite(source, scope, generation)
                .await
        })
    }

    fn drain_projection_queue<'a>(
        &'a self,
        provider: &'a str,
        scope: &'a ObservationScopeV1,
        cancellation: &'a ObservationCancellation,
        max: usize,
    ) -> AdmissionFuture<'a, HostProjectionDrainOutcome> {
        self.inner
            .drain_projection_queue(provider, scope, cancellation, max)
    }

    fn has_session_message<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        provider: &'a str,
        message_id: &'a str,
    ) -> AdmissionFuture<'a, bool> {
        self.inner.has_session_message(scope, provider, message_id)
    }

    fn existing_session_message_ids<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        provider: &'a str,
        message_ids: Vec<String>,
    ) -> AdmissionFuture<'a, Vec<String>> {
        self.inner
            .existing_session_message_ids(scope, provider, message_ids)
    }

    fn read_session_backfill_state<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        key: &'a str,
    ) -> AdmissionFuture<'a, Option<String>> {
        self.inner.read_session_backfill_state(scope, key)
    }

    fn list_session_backfill_state_page<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        key_prefix: &'a str,
        after_key: Option<&'a str>,
        through_key: &'a str,
    ) -> AdmissionFuture<'a, Vec<(String, String)>> {
        self.inner
            .list_session_backfill_state_page(scope, key_prefix, after_key, through_key)
    }

    fn session_backfill_state_high_water<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        key_prefix: &'a str,
    ) -> AdmissionFuture<'a, Option<String>> {
        self.inner
            .session_backfill_state_high_water(scope, key_prefix)
    }

    fn compare_and_swap_session_backfill_state<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        key: &'a str,
        expected: Option<&'a str>,
        replacement: &'a str,
    ) -> AdmissionFuture<'a, bool> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .compare_and_swap_session_backfill_state(scope, key, expected, replacement)
                .await
        })
    }

    fn compare_and_delete_session_backfill_state<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        key: &'a str,
        expected: &'a str,
    ) -> AdmissionFuture<'a, bool> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .compare_and_delete_session_backfill_state(scope, key, expected)
                .await
        })
    }

    fn get_parse_offset<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        path: &'a str,
    ) -> AdmissionFuture<'a, Option<ParseOffset>> {
        self.inner.get_parse_offset(scope, path)
    }

    fn advance_parse_offset<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        path: &'a str,
        offset: ParseOffset,
    ) -> AdmissionFuture<'a, ()> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner.advance_parse_offset(scope, path, offset).await
        })
    }

    fn replace_parse_offset<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        path: &'a str,
        expected: ParseOffset,
        next: ParseOffset,
    ) -> AdmissionFuture<'a, ()> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .replace_parse_offset(scope, path, expected, next)
                .await
        })
    }

    fn replace_parse_offset_pair<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        first: (&'a str, ParseOffset, ParseOffset),
        second: (&'a str, ParseOffset, ParseOffset),
    ) -> AdmissionFuture<'a, ()> {
        Box::pin(async move {
            self.check_ownership().await?;
            self.inner
                .replace_parse_offset_pair(scope, first, second)
                .await
        })
    }

    fn enqueue_discovery_paths<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        provider: &'a str,
        paths: Vec<PathBuf>,
    ) -> AdmissionFuture<'a, Option<HostDiscoveryQueueEntry>> {
        self.inner.enqueue_discovery_paths(scope, provider, paths)
    }

    fn discovery_paths_after<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        provider: &'a str,
        after_sequence: u64,
        limit: usize,
    ) -> AdmissionFuture<'a, Vec<HostDiscoveryQueueEntry>> {
        self.inner
            .discovery_paths_after(scope, provider, after_sequence, limit)
    }

    fn discovery_path<'a>(
        &'a self,
        scope: &'a ObservationScopeV1,
        provider: &'a str,
        sequence: u64,
    ) -> AdmissionFuture<'a, Option<HostDiscoveryQueueEntry>> {
        self.inner.discovery_path(scope, provider, sequence)
    }
}

#[cfg(test)]
mod tests;
