//! Snapshot staging and canonical replay after the adapter's opaque projection.

use super::super::*;
use super::control::{commit_common, replacement_request};
use super::recovery::authenticate_control_capsules;
use super::util::{
    canonical_digest, core_reply, lookup_replay, read_live, remaining_deadline, resolve_affect,
    sha256_hex, store_reply, validate_common_control_digest, validate_durable_receipt,
    validate_receipt_idempotency_key_json, validate_receipt_idempotency_key_value,
};
use crate::snapshot::{self, RestoreRequest};
use crate::store::{Capsule, CapsuleStatus};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use tracedecay_memory_ncm_core::kernel::NewRecord;

const MAX_ITEMS: usize = 4096;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;

impl NcmEngine {
    /// Applies private portability controls whose source authority was checked
    /// by the composing adapter. No host identity is interpreted here.
    pub fn common_portability(
        &self,
        namespace: &str,
        payload: Value,
        deadline: Deadline,
    ) -> EngineReply {
        if deadline.remaining_ms == 0 {
            return EngineReply::new(Outcome::Cancelled, 0, Value::Null);
        }
        let Some(expected) = payload["expected_generation"].as_u64() else {
            return invalid("missing expected generation", 0);
        };
        match payload["action"].as_str() {
            Some("snapshot_export") => {
                let snapshot = match snapshot::export(self, namespace, deadline) {
                    Ok(value) => value,
                    Err(reply) => return reply,
                };
                if snapshot.state_generation() != expected {
                    return conflict(snapshot.state_generation());
                }
                EngineReply::new(
                    Outcome::Success,
                    snapshot.state_generation(),
                    json!({"common_portability":"snapshot_export","bytes":snapshot.into_vec(),"warnings":[]}),
                )
            }
            Some("snapshot_restore") => {
                let Some(key) = opaque(&payload["idempotency_key"]) else {
                    return invalid("missing restore key", expected);
                };
                let Some(bytes) = bytes(&payload["bytes"]) else {
                    return invalid("invalid snapshot bytes", expected);
                };
                let Some(blocked) = payload["blocked_sources"].as_array() else {
                    return invalid("missing restore fences", expected);
                };
                if blocked.len() > MAX_ITEMS {
                    return invalid("restore fence bound", expected);
                }
                let mut sources = BTreeSet::new();
                for source in blocked {
                    let Some(source) = opaque(source) else {
                        return invalid("invalid restore fence", expected);
                    };
                    if !sources.insert(SourceId(source.to_owned())) {
                        return invalid("duplicate restore fence", expected);
                    }
                }
                let Some(snapshot_id) = payload["snapshot_id"]
                    .as_str()
                    .filter(|value| value.starts_with("ncm-snapshot:") && value.len() == 77)
                else {
                    return invalid("invalid snapshot identity", expected);
                };
                let Some(sequence) = payload["observation_sequence"].as_u64() else {
                    return invalid("missing snapshot sequence", expected);
                };
                if snapshot_id != format!("ncm-snapshot:{}", sha256_hex(&bytes)) {
                    return invalid("snapshot identity digest differs", expected);
                }
                let mut reply = snapshot::restore_with_revocations(
                    self,
                    namespace,
                    RestoreRequest {
                        idempotency_key: key.to_owned(),
                        bytes,
                    },
                    deadline,
                    &sources.into_iter().collect::<Vec<_>>(),
                    Some(expected),
                );
                if reply.outcome == Outcome::Success {
                    let retained_receipt =
                        json!({"generation": reply.state_generation, "payload":reply.payload});
                    reply.payload = json!({"common_portability":"snapshot_restore","snapshot_id":snapshot_id,"state_generation_before":expected,
                        "state_generation_after":reply.state_generation,"restored_observation_sequence":sequence,"replayed":reply.payload["replayed"],"warnings":[],"_retained_receipt":retained_receipt});
                }
                reply
            }
            Some("replay") => self.replay_page(namespace, payload, deadline),
            _ => invalid("unknown portability action", expected),
        }
    }

    fn replay_page(&self, namespace: &str, payload: Value, deadline: Deadline) -> EngineReply {
        let started = Instant::now();
        let page = match ReplayPage::parse(namespace, &payload, deadline) {
            Ok(page) => page,
            Err(reply) => return reply,
        };
        let mut effect = payload.clone();
        if let Some(object) = effect.as_object_mut() {
            object.remove("expected_generation");
            object.remove("idempotency_key");
            // Caller operation IDs do not change replay effects; the first retained page wins.
            object.remove("page_delivery_capsule");
        }
        if let Some(items) = effect["items"].as_array_mut() {
            for item in items {
                item["observation"] = item["observation"]["payload_sha256"].clone();
            }
        }
        let digest = match canonical_digest(&effect) {
            Ok(digest) => digest,
            Err(reason) => return invalid(&reason, 0),
        };
        {
            let mut namespaces = match self.namespace_lock() {
                Ok(value) => value,
                Err(reply) => return reply,
            };
            let existing = match self.ensure_handle(&mut namespaces, namespace, false) {
                Ok(value) => value,
                Err(reply) => return reply,
            };
            if let Some(handle) = existing {
                if handle.fenced {
                    return EngineReply::new(Outcome::Busy, handle.commit_seq, Value::Null);
                }
                let acknowledged = match preflight_replay_page(handle, &page) {
                    Ok(value) => value,
                    Err(reply) => return reply,
                };
                match lookup_page_replay(handle, &page, &effect, &digest, deadline) {
                    Ok(Some(reply)) => return reply,
                    Ok(None) => {}
                    Err(reply) => return reply,
                }
                if handle.commit_seq != page.expected {
                    return conflict(handle.commit_seq);
                }
                if acknowledged != page.previous || page.first > acknowledged.saturating_add(1) {
                    return invalid("replay sequence gap", handle.commit_seq);
                }
                if let Some(reply) = public_replay_no_change(Some(handle), &page, deadline, started)
                {
                    return reply;
                }
            } else if page.expected != 0 || page.previous != 0 || page.first != 1 {
                return invalid("replay sequence gap", 0);
            } else if let Some(reply) = public_replay_no_change(None, &page, deadline, started) {
                return reply;
            }
        }
        let mut output = page.output();
        let mut generation = page.expected;
        let mut acknowledged = page.previous;
        let mut stopped = None;
        for item in &page.items {
            if stopped.is_some() || remaining_deadline(deadline, started).remaining_ms == 0 {
                if stopped.is_none() {
                    stopped = Some(Outcome::Cancelled);
                }
                if let Err(reply) = push_item(
                    &mut output,
                    item,
                    "rejected",
                    Some("not_dispatched"),
                    None,
                    generation,
                ) {
                    return reply;
                }
                continue;
            }
            if item.blocked {
                if let Err(reply) = preflight_blocked_item(self, namespace, item) {
                    return reply;
                }
                let fence_key = match canonical_digest(&json!([
                    "replay-fence",
                    item.delivery_key,
                    item.source
                ])) {
                    Ok(value) => value,
                    Err(reason) => return invalid(&reason, generation),
                };
                let fenced = if let Some(legacy_source) = &item.legacy_source {
                    let sources = [SourceId(item.source.clone())];
                    let bindings = [crate::source_binding::DeletionSourceBinding {
                        source_id: sources[0].clone(),
                        legacy_source_id: SourceId(legacy_source.clone()),
                    }];
                    crate::privacy::delete_sources(
                        self,
                        namespace,
                        crate::privacy::DeleteSourcesRequest {
                            sources: &sources,
                            idempotency_key: &fence_key,
                            deadline: remaining_deadline(deadline, started),
                            expected_generation: generation,
                            bindings: Some(&bindings),
                            canonical_input: None,
                        },
                    )
                } else {
                    self.delete_by_source(
                        namespace,
                        &SourceId(item.source.clone()),
                        &fence_key,
                        remaining_deadline(deadline, started),
                    )
                };
                generation = generation.max(fenced.state_generation);
                if fenced.outcome != Outcome::Success {
                    let unknown = fenced.outcome == Outcome::EffectUnknown;
                    if let Err(reply) = push_item(
                        &mut output,
                        item,
                        if unknown {
                            "effect_unknown"
                        } else {
                            "rejected"
                        },
                        Some("source_fence_failed"),
                        None,
                        generation,
                    ) {
                        return reply;
                    }
                    stopped = Some(fenced.outcome);
                    continue;
                }
            }
            let reply = self.replay_item(
                namespace,
                item,
                page.page_delivery_capsule.is_some(),
                deadline,
                started,
            );
            generation = generation.max(reply.state_generation);
            if reply.outcome == Outcome::Success {
                let Some(mut state) = reply.payload["state"].as_str() else {
                    return EngineReply::new(Outcome::EffectUnknown, generation, output);
                };
                if reply.payload["replayed"] == true && state != "rejected" {
                    state = "delivery_duplicate";
                }
                if let Err(reply) = push_item(
                    &mut output,
                    item,
                    state,
                    reply.payload["reason"].as_str(),
                    reply.payload["record_id"].as_u64(),
                    reply.state_generation,
                ) {
                    return reply;
                }
                acknowledged = acknowledged.max(item.sequence);
                output["acknowledged_sequence"] = json!(acknowledged);
            } else {
                let unknown = reply.outcome == Outcome::EffectUnknown;
                if let Err(reply) = push_item(
                    &mut output,
                    item,
                    if unknown {
                        "effect_unknown"
                    } else {
                        "rejected"
                    },
                    Some(if unknown {
                        "commit_unknown"
                    } else {
                        "not_applied"
                    }),
                    None,
                    generation,
                ) {
                    return reply;
                }
                if !matches!(reply.outcome, Outcome::Rejected(_)) {
                    stopped = Some(reply.outcome);
                }
            }
        }
        // Keep the request's generation as the page's before value. Item
        // receipts and source fences advance the durable sequence while the
        // page is being delivered; commit_common records the page event's
        // sequence as the after value below.
        output["state_generation_after"] = json!(generation);
        if let Some(outcome) = stopped {
            output["partial"] = json!(true);
            // All previous item receipts are already durable. A known failure
            // after those commits must report a partial effect, never no effect.
            let outcome = if outcome == Outcome::EffectUnknown {
                outcome
            } else if generation > page.expected {
                Outcome::Success
            } else {
                outcome
            };
            return EngineReply::new(outcome, generation, output);
        }
        let mut namespaces = match self.namespace_lock() {
            Ok(value) => value,
            Err(reply) => return partial_reply(output, generation, page.expected, reply.outcome),
        };
        let handle = match self.ensure_handle(&mut namespaces, namespace, true) {
            Ok(Some(value)) => value,
            Ok(None) => return partial_reply(output, generation, page.expected, Outcome::Corrupt),
            Err(reply) => return partial_reply(output, generation, page.expected, reply.outcome),
        };
        if handle.fenced {
            output["partial"] = json!(true);
            output["state_generation_after"] = json!(handle.commit_seq);
            return EngineReply::new(Outcome::EffectUnknown, handle.commit_seq, output);
        }
        match lookup_page_replay(handle, &page, &effect, &digest, deadline) {
            Ok(Some(reply)) => return reply,
            Ok(None) => {}
            Err(reply) => return reply,
        }
        let live = match read_live(handle) {
            Ok(value) => value,
            Err(reply) => return partial_reply(output, generation, page.expected, reply.outcome),
        };
        // Item receipts and source fences are committed independently. A
        // concurrent writer may also have advanced the durable sequence while
        // this page was dispatching; use that sequence for the eventual page
        // event's after value while retaining the original request precondition.
        generation = generation.max(handle.commit_seq);
        output["state_generation_after"] = json!(generation);
        output["acknowledged_sequence"] = json!(page.previous.max(page.last));
        let result = commit_common(
            self,
            handle,
            (*live).clone(),
            &page.key,
            &digest,
            effect.clone(),
            Vec::new(),
            Vec::new(),
            None,
            output.clone(),
            deadline,
            started,
        );
        if result.outcome == Outcome::Success {
            return result;
        }
        output["partial"] = json!(true);
        output["acknowledged_sequence"] = json!(acknowledged);
        output["state_generation_after"] = json!(result.state_generation);
        let outcome = if result.outcome == Outcome::EffectUnknown {
            Outcome::EffectUnknown
        } else if generation > page.expected {
            Outcome::Success
        } else {
            result.outcome
        };
        EngineReply::new(outcome, result.state_generation, output)
    }

    fn replay_item(
        &self,
        namespace: &str,
        item: &ReplayItem,
        public_page: bool,
        deadline: Deadline,
        started: Instant,
    ) -> EngineReply {
        let digest = match replay_item_digest(item) {
            Ok(value) => value,
            Err(reason) => return invalid(&reason, 0),
        };
        let request = if item.admitted {
            match replacement_request(&item.observation, deadline) {
                Ok(value) => Some(value),
                Err(reason) => return invalid(&reason, 0),
            }
        } else {
            None
        };
        {
            let mut namespaces = match self.namespace_lock() {
                Ok(value) => value,
                Err(reply) => return reply,
            };
            let handle = match self.ensure_handle(&mut namespaces, namespace, true) {
                Ok(Some(value)) => value,
                Ok(None) => return EngineReply::new(Outcome::Corrupt, 0, Value::Null),
                Err(reply) => return reply,
            };
            if let Some(reply) = existing_item(
                self,
                handle,
                item,
                public_page,
                request.as_ref(),
                &digest,
                deadline,
                started,
            ) {
                return reply;
            }
        }
        let Some(request) = request else {
            return invalid("missing replay observation", 0);
        };
        let embeddings = match self.encoder.encode(
            &[&request.key_text, &request.value_text],
            remaining_deadline(deadline, started),
        ) {
            Ok(value) if value.len() == 2 => value,
            Ok(_) => return EngineReply::new(Outcome::Corrupt, 0, Value::Null),
            Err(error) => return super::util::encoder_reply(error, 0),
        };
        let mut namespaces = match self.namespace_lock() {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        let handle = match self.ensure_handle(&mut namespaces, namespace, true) {
            Ok(Some(value)) => value,
            Ok(None) => return EngineReply::new(Outcome::Corrupt, 0, Value::Null),
            Err(reply) => return reply,
        };
        if let Some(reply) = existing_item(
            self,
            handle,
            item,
            public_page,
            Some(&request),
            &digest,
            deadline,
            started,
        ) {
            return reply;
        }
        let live = match read_live(handle) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        let mut candidate = (*live).clone();
        let affect = match resolve_affect(request.affect.as_ref()) {
            Ok(value) => value,
            Err(error) => return core_reply(error, handle.commit_seq),
        };
        let report = match candidate.observe(
            &embeddings[0].0,
            &embeddings[1].0,
            NewRecord {
                source: request.source.clone(),
                key_text: request.key_text.clone(),
                value_text: request.value_text.clone(),
                affect,
                surprise: request.surprise,
                intensity: request.intensity,
            },
        ) {
            Ok(value) => value,
            Err(error) => return core_reply(error, handle.commit_seq),
        };
        let Some(record) = candidate.records.get(report.record_id) else {
            return EngineReply::new(Outcome::Corrupt, handle.commit_seq, Value::Null);
        };
        let provenance = match serde_json::to_string(&request.provenance) {
            Ok(value) => value,
            Err(error) => return invalid(&error.to_string(), handle.commit_seq),
        };
        let capsule = Capsule::new(
            request.source,
            request.key_text,
            request.value_text,
            affect,
            request.surprise,
            request.intensity,
            embeddings[0].0.clone(),
            embeddings[1].0.clone(),
            record.ltm_key.clone(),
            provenance,
        );
        commit_common(
            self,
            handle,
            candidate,
            &item.delivery_key,
            &digest,
            replay_item_input(item),
            vec![DurableOperation::Observe {
                record_id: report.record_id,
            }],
            Vec::new(),
            Some(capsule),
            item.output("applied", None, Some(report.record_id.0)),
            deadline,
            started,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn existing_item(
    engine: &NcmEngine,
    handle: &mut NamespaceHandle,
    item: &ReplayItem,
    public_page: bool,
    request: Option<&ObserveRequest>,
    digest: &str,
    deadline: Deadline,
    started: Instant,
) -> Option<EngineReply> {
    if handle.fenced {
        return Some(EngineReply::new(
            Outcome::Busy,
            handle.commit_seq,
            Value::Null,
        ));
    }
    let previous = match replay_sequence(handle, Some(item)) {
        Ok(value) => value,
        Err(reply) => return Some(reply),
    };
    let retained_delivery = match lookup_item_replay(handle, item, request, digest) {
        Ok(Some(reply)) if public_page && reply.outcome == Outcome::Success => {
            Some(reply.state_generation)
        }
        Ok(Some(reply)) => return Some(reply),
        Ok(None) => None,
        Err(reply) => return Some(reply),
    };
    if item.sequence > previous.saturating_add(1) {
        return Some(invalid("replay sequence gap", handle.commit_seq));
    }
    let (state, reason, record) =
        match classify_replay_item(handle, item, request, deadline, started) {
            Ok(Some(state)) => state,
            Ok(None) if retained_delivery.is_some() => {
                return Some(EngineReply::new(
                    Outcome::Corrupt,
                    handle.commit_seq,
                    Value::Null,
                ));
            }
            Ok(None) => return None,
            Err(reply) => return Some(reply),
        };
    if let Some(retained_generation) = retained_delivery {
        // A new public page resolves current source state; only a retained page
        // receipt can establish a duplicate public delivery.
        let mut payload = item.output(state, reason, record);
        payload["replayed"] = json!(true);
        return Some(EngineReply::new(
            Outcome::Success,
            retained_generation,
            payload,
        ));
    }
    let live = match read_live(handle) {
        Ok(value) => value,
        Err(reply) => return Some(reply),
    };
    Some(commit_common(
        engine,
        handle,
        (*live).clone(),
        &item.delivery_key,
        digest,
        replay_item_input(item),
        Vec::new(),
        Vec::new(),
        None,
        item.output(state, reason, record),
        deadline,
        started,
    ))
}

type ExistingReplayItem = (&'static str, Option<&'static str>, Option<u64>);

fn classify_replay_item(
    handle: &NamespaceHandle,
    item: &ReplayItem,
    request: Option<&ObserveRequest>,
    deadline: Deadline,
    started: Instant,
) -> Result<Option<ExistingReplayItem>, EngineReply> {
    let state = if !item.admitted {
        Some(("rejected", Some("current_disposition"), None))
    } else if let Err(error) = handle.store.ensure_source_provenance_not_revoked(
        &SourceId(item.source.clone()),
        &request.map_or(Value::Null, |request| request.provenance.clone()),
    ) {
        if matches!(error, crate::store::StoreError::SourceRevoked) {
            Some(("rejected", Some("source_revoked"), None))
        } else {
            return Err(store_reply(error, handle.commit_seq));
        }
    } else {
        None
    };
    let state = if let Some(state) = state {
        Some(state)
    } else {
        let Some(request) = request else {
            return Ok(None);
        };
        let binding = match crate::source_binding::read(
            handle.store.namespace(),
            &request.source,
            &request.provenance,
        ) {
            Ok(binding) => binding,
            Err(reason) => return Err(invalid(&reason, handle.commit_seq)),
        };
        let filter = binding
            .as_ref()
            .map_or(&request.source, |binding| &binding.legacy_source_id);
        let mut after = 0;
        let mut scanned = 0_u64;
        let mut found = None;
        loop {
            if remaining_deadline(deadline, started).remaining_ms == 0 {
                return Err(EngineReply::new(
                    Outcome::Cancelled,
                    handle.commit_seq,
                    Value::Null,
                ));
            }
            let limit = 128_u64.min(1_000_000_u64.saturating_sub(scanned).saturating_add(1));
            let capsules = match handle.store.capsule_page(Some(&filter.0), after, limit) {
                Ok(value) => value,
                Err(error) => return Err(store_reply(error, handle.commit_seq)),
            };
            let complete = capsules.len() < limit as usize;
            for capsule in capsules {
                if remaining_deadline(deadline, started).remaining_ms == 0 {
                    return Err(EngineReply::new(
                        Outcome::Cancelled,
                        handle.commit_seq,
                        Value::Null,
                    ));
                }
                if scanned == 1_000_000 {
                    return Err(EngineReply::new(
                        Outcome::BudgetExceeded,
                        handle.commit_seq,
                        Value::Null,
                    ));
                }
                if capsule.record_id.0 <= after {
                    return Err(EngineReply::new(
                        Outcome::Corrupt,
                        handle.commit_seq,
                        Value::Null,
                    ));
                }
                after = capsule.record_id.0;
                scanned += 1;
                if capsule.status == CapsuleStatus::Revoked {
                    continue;
                }
                let provenance: Value = match serde_json::from_str(&capsule.provenance) {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(EngineReply::new(
                            Outcome::Corrupt,
                            handle.commit_seq,
                            Value::Null,
                        ));
                    }
                };
                let retained_binding = match crate::source_binding::read(
                    handle.store.namespace(),
                    &capsule.source_id,
                    &provenance,
                ) {
                    Ok(binding) => binding,
                    Err(reason) => {
                        return Err(EngineReply::new(
                            Outcome::Corrupt,
                            handle.commit_seq,
                            json!({"reason":reason}),
                        ));
                    }
                };
                if binding.as_ref().is_some_and(|request| {
                    !request.is_legacy
                        && retained_binding
                            .as_ref()
                            .and_then(|binding| binding.full_source_id.as_ref())
                            != request.full_source_id.as_ref()
                }) {
                    continue;
                }
                let original = &request.provenance["selection"];
                if provenance["selection"]["observation_identity"]
                    == original["observation_identity"]
                    && provenance["selection"]["revision_digest"] == original["revision_digest"]
                {
                    let same_source = capsule.source_id == request.source
                        || binding.as_ref().is_some_and(|request| {
                            !request.is_legacy
                                && retained_binding.as_ref().is_some_and(|retained| {
                                    retained.is_legacy
                                        && retained.full_source_id == request.full_source_id
                                })
                        });
                    if !same_source
                        || provenance["common_capsule"]["sha256"]
                            != request.provenance["common_capsule"]["sha256"]
                    {
                        return Err(conflict(handle.commit_seq));
                    }
                    found = Some(("source_already_applied", None, Some(capsule.record_id.0)));
                    break;
                }
            }
            if found.is_some() || complete {
                break;
            }
        }
        found
    };
    Ok(state)
}

fn replay_item_digest(item: &ReplayItem) -> Result<String, String> {
    canonical_digest(&replay_item_input(item))
}

fn replay_item_input(item: &ReplayItem) -> Value {
    json!({"sequence":item.sequence,"receipt":item.receipt_digest,"source":item.source,"admitted":item.admitted,"observation":item.observation["payload_sha256"]})
}

// This read-only path runs with the namespace lock after the page identity,
// generation, and contiguous-cursor checks. No receipt or acknowledgement is
// recorded when every item is already present or already durably fenced.
fn public_replay_no_change(
    mut handle: Option<&mut NamespaceHandle>,
    page: &ReplayPage,
    deadline: Deadline,
    started: Instant,
) -> Option<EngineReply> {
    page.page_delivery_capsule.as_ref()?;
    if let Some(handle) = handle.as_deref()
        && let Err(reply) = read_live(handle)
    {
        return Some(reply);
    }
    let mut output = page.output();
    for item in &page.items {
        if remaining_deadline(deadline, started).remaining_ms == 0 {
            return Some(EngineReply::new(
                Outcome::Cancelled,
                page.expected,
                Value::Null,
            ));
        }
        let state = if let Some(handle) = handle.as_deref_mut() {
            let durable_last = match replay_sequence(handle, None) {
                Ok(last) => last,
                Err(reply) => return Some(reply),
            };
            // A page may contain a contiguous successor that is not durable
            // yet.  That makes the page ineligible for the no-change path;
            // the dispatch loop will persist its preceding items first.
            if item.sequence > durable_last.saturating_add(1) {
                return None;
            }
            if let Err(reply) = replay_sequence(handle, Some(item)) {
                return Some(reply);
            }
            if item.blocked {
                let mut fenced = false;
                for source in std::iter::once(&item.source).chain(item.legacy_source.iter()) {
                    match handle.store.ensure_source_provenance_not_revoked(
                        &SourceId(source.clone()),
                        &Value::Null,
                    ) {
                        Err(crate::store::StoreError::SourceRevoked) => fenced = true,
                        Ok(()) => {}
                        Err(error) => return Some(store_reply(error, handle.commit_seq)),
                    }
                }
                if !fenced {
                    return None;
                }
                for source in std::iter::once(&item.source).chain(item.legacy_source.iter()) {
                    match handle.store.has_retained_source(&SourceId(source.clone())) {
                        Ok(false) => {}
                        Ok(true) => return None,
                        Err(error) => return Some(store_reply(error, handle.commit_seq)),
                    }
                }
            }
            let request = if item.admitted {
                match replacement_request(&item.observation, deadline) {
                    Ok(request) => Some(request),
                    Err(reason) => return Some(invalid(&reason, handle.commit_seq)),
                }
            } else {
                None
            };
            let digest = match replay_item_digest(item) {
                Ok(digest) => digest,
                Err(reason) => return Some(invalid(&reason, handle.commit_seq)),
            };
            let retained = match lookup_item_replay(handle, item, request.as_ref(), &digest) {
                Ok(Some(reply)) if reply.outcome == Outcome::Success => true,
                Ok(Some(reply)) => return Some(reply),
                Ok(None) => false,
                Err(reply) => return Some(reply),
            };
            match classify_replay_item(handle, item, request.as_ref(), deadline, started) {
                Ok(Some(state)) => state,
                Ok(None) if retained => {
                    return Some(EngineReply::new(
                        Outcome::Corrupt,
                        handle.commit_seq,
                        Value::Null,
                    ));
                }
                Ok(None) => return None,
                Err(reply) => return Some(reply),
            }
        } else if !item.admitted && !item.blocked {
            ("rejected", Some("current_disposition"), None)
        } else {
            return None;
        };
        if let Err(reply) = push_item(&mut output, item, state.0, state.1, state.2, page.expected) {
            return Some(reply);
        }
    }
    if remaining_deadline(deadline, started).remaining_ms == 0 {
        return Some(EngineReply::new(
            Outcome::Cancelled,
            page.expected,
            Value::Null,
        ));
    }
    output["no_change"] = json!(true);
    Some(EngineReply::new(Outcome::Success, page.expected, output))
}

fn replay_sequence(
    handle: &NamespaceHandle,
    item: Option<&ReplayItem>,
) -> Result<u64, EngineReply> {
    let journal = scan_replay_journal(handle)?;
    if let Some(item) = item {
        validate_replay_item_request(handle, &journal, item, handle.commit_seq, true)?;
    }
    Ok(journal.last)
}

fn preflight_replay_page(handle: &NamespaceHandle, page: &ReplayPage) -> Result<u64, EngineReply> {
    let journal = scan_replay_journal(handle)?;
    let acknowledged = journal.last;
    let mut page_journal = journal.clone();
    if journal.event_keys.contains(&page.key) && !journal.page_keys.contains(&page.key) {
        return Err(corrupt_replay(
            handle.commit_seq,
            "replay page key is reused by another durable operation",
        ));
    }
    let allow_legacy_alias = journal.page_keys.contains(&page.key);
    for item in &page.items {
        validate_replay_item_request(
            handle,
            &page_journal,
            item,
            handle.commit_seq,
            allow_legacy_alias,
        )?;
        // A single page is itself a contiguous proposal.  Let later items
        // validate against the preceding item while retaining the durable
        // acknowledgement returned to the caller above.
        page_journal.last = page_journal.last.max(item.sequence);
    }
    Ok(acknowledged)
}

/// Rechecks a blocked item immediately before dispatching its source fence.
/// The initial page preflight protects the normal path; this second read-only
/// check closes the gap if another namespace operation committed while the
/// page was between item deliveries.
fn preflight_blocked_item(
    engine: &NcmEngine,
    namespace: &str,
    item: &ReplayItem,
) -> Result<(), EngineReply> {
    let mut namespaces = engine.namespace_lock()?;
    let Some(handle) = engine.ensure_handle(&mut namespaces, namespace, false)? else {
        return Ok(());
    };
    if handle.fenced {
        return Err(EngineReply::new(
            Outcome::Busy,
            handle.commit_seq,
            Value::Null,
        ));
    }
    replay_sequence(handle, Some(item)).map(|_| ())
}

fn scan_replay_journal(handle: &NamespaceHandle) -> Result<ReplayJournal, EngineReply> {
    let events = handle
        .store
        .events_after(0)
        .map_err(|error| store_reply(error, handle.commit_seq))?;
    let capsules = handle
        .store
        .capsules_in_commit_order(true)
        .map_err(|error| store_reply(error, handle.commit_seq))?;
    let ingestion_capsules = authenticate_control_capsules(
        handle.store.namespace(),
        &events,
        &capsules,
        handle.commit_seq,
    )?;
    let mut expected_event_seq = 1_u64;
    let mut last = 0;
    let mut identities = BTreeMap::new();
    let mut item_receipts = BTreeMap::<String, ReplayItemReceipt>::new();
    let mut delivered_keys = BTreeSet::new();
    let mut event_keys = BTreeSet::new();
    let mut page_keys = BTreeSet::new();
    for event in events {
        if let Some(key) = &event.idempotency_key
            && !event_keys.insert(key.clone())
        {
            return Err(corrupt_replay(
                handle.commit_seq,
                "durable idempotency key is reused",
            ));
        }
        let raw_receipt: Value = serde_json::from_str(&event.receipt)
            .map_err(|_| corrupt_replay(handle.commit_seq, "durable receipt is not valid JSON"))?;
        validate_closed_receipt_envelope(
            &raw_receipt,
            handle.commit_seq,
            &event.kind,
            event.idempotency_key.as_deref(),
        )?;
        let durable = validate_recovery_event(&event, expected_event_seq, handle.commit_seq)?;
        validate_durable_receipt(&durable, event.seq, event.idempotency_key.as_deref())
            .map_err(|reason| corrupt_replay(handle.commit_seq, &reason))?;
        validate_common_control_digest(&event, &durable)
            .map_err(|reason| corrupt_replay(handle.commit_seq, &reason))?;
        validate_event_payload_digest(&event, &durable, &ingestion_capsules)?;

        if event.kind == "common_control" {
            let DurableOperation::CommonControl {
                operations,
                canonical_input,
            } = &durable.operation
            else {
                return Err(corrupt_replay(
                    handle.commit_seq,
                    "common control event has a non-common operation",
                ));
            };
            if durable
                .reply
                .payload
                .get("common_portability")
                .is_some_and(|value| value.as_str().is_none())
            {
                return Err(corrupt_replay(
                    handle.commit_seq,
                    "common portability receipt marker is not a string",
                ));
            }
            match durable.reply.payload["common_portability"].as_str() {
                Some("replay_item") => {
                    let receipt = validate_replay_item_receipt(
                        &event,
                        &durable,
                        operations,
                        canonical_input,
                        &ingestion_capsules,
                        handle.store.namespace(),
                        handle.commit_seq,
                    )?;
                    if item_receipts
                        .insert(receipt.delivery_key.clone(), receipt.clone())
                        .is_some()
                    {
                        return Err(corrupt_replay(
                            handle.commit_seq,
                            "replay delivery key is reused by multiple receipts",
                        ));
                    }
                    record_replay_identity(
                        &mut identities,
                        &mut last,
                        receipt.identity.clone(),
                        handle.commit_seq,
                    )?;
                }
                Some("replay") => {
                    let page = validate_replay_page_receipt(
                        handle.store.namespace(),
                        &event,
                        &durable,
                        operations,
                        canonical_input,
                        &capsules,
                        handle.commit_seq,
                    )?;
                    for page_item in &page.items {
                        let identity = &page_item.identity;
                        let Some(receipt) = item_receipts.get(&page_item.delivery_key) else {
                            return Err(corrupt_replay(
                                handle.commit_seq,
                                "replay page references an unknown delivery receipt",
                            ));
                        };
                        if identities
                            .get(&identity.sequence)
                            .is_none_or(|existing| existing != identity)
                            || receipt.identity != *identity
                        {
                            return Err(corrupt_replay(
                                handle.commit_seq,
                                "replay page references an unknown source identity",
                            ));
                        }
                        if !validate_replay_page_output(
                            page_item,
                            receipt,
                            delivered_keys.contains(&page_item.delivery_key),
                        ) {
                            return Err(corrupt_replay(
                                handle.commit_seq,
                                "replay page output differs from its durable item receipt",
                            ));
                        }
                        delivered_keys.insert(page_item.delivery_key.clone());
                    }
                    let page_key = event.idempotency_key.clone().ok_or_else(|| {
                        corrupt_replay(handle.commit_seq, "replay page key is missing")
                    })?;
                    page_keys.insert(page_key);
                    if page.acknowledged != last {
                        return Err(corrupt_replay(
                            handle.commit_seq,
                            "replay page acknowledgement is detached from its items",
                        ));
                    }
                }
                Some(_) => {
                    return Err(corrupt_replay(
                        handle.commit_seq,
                        "unknown common portability receipt",
                    ));
                }
                None if canonical_input["action"] == "replay" => {
                    return Err(corrupt_replay(
                        handle.commit_seq,
                        "replay operation has no replay receipt",
                    ));
                }
                None => {}
            }
        } else if matches!(
            durable.reply.payload["common_portability"].as_str(),
            Some("replay" | "replay_item")
        ) {
            return Err(corrupt_replay(
                handle.commit_seq,
                "non-common event carries a replay receipt",
            ));
        }
        expected_event_seq = expected_event_seq
            .checked_add(1)
            .ok_or_else(|| corrupt_replay(handle.commit_seq, "event sequence overflow"))?;
    }
    if expected_event_seq != handle.commit_seq.saturating_add(1) {
        return Err(corrupt_replay(
            handle.commit_seq,
            "metadata sequence is not journal-backed",
        ));
    }
    Ok(ReplayJournal {
        last,
        identities,
        item_receipts,
        event_keys,
        page_keys,
    })
}

fn validate_closed_receipt_envelope(
    receipt: &Value,
    generation: u64,
    event_kind: &str,
    event_idempotency_key: Option<&str>,
) -> Result<(), EngineReply> {
    let corrupt = || corrupt_replay(generation, "durable receipt envelope is not canonical");
    let object = receipt.as_object().ok_or_else(corrupt)?;
    if !has_exact_fields(
        object,
        &["reply", "operation", "state_digest", "integrity_digest"],
        &["idempotency_key"],
    ) {
        return Err(corrupt());
    }
    let operation = receipt["operation"].as_object().ok_or_else(corrupt)?;
    let reply = receipt["reply"].as_object().ok_or_else(corrupt)?;
    if !has_exact_fields(reply, &["outcome", "state_generation", "payload"], &[])
        || operation.len() != 1
    {
        return Err(corrupt());
    }
    validate_closed_operation_envelope(operation).map_err(|_| corrupt())?;
    let keyless = operation.contains_key("deletion_fence")
        || operation
            .get("maintenance")
            .and_then(Value::as_object)
            .is_some_and(|operation| !operation.contains_key("canonical_input"))
        || operation
            .get("delete_by_source")
            .and_then(Value::as_object)
            .is_some_and(|operation| {
                !operation.contains_key("payload_sha256")
                    && !operation.contains_key("canonical_input")
            });
    validate_receipt_idempotency_key_value(receipt, event_kind, event_idempotency_key)
        .map_err(|_| corrupt())?;
    if receipt.get("idempotency_key").is_none() && !keyless {
        return Err(corrupt());
    }
    Ok(())
}

/// The typed durable operation enum ignores fields added to a variant body.
/// Keep every variant closed before recovery consumers use the decoded
/// operation, including non-common rows that precede a replay page.
fn validate_closed_operation_envelope(
    operation: &serde_json::Map<String, Value>,
) -> Result<(), ()> {
    let Some((name, body)) = operation.iter().next() else {
        return Err(());
    };
    let body = body.as_object().ok_or(())?;
    let valid = match name.as_str() {
        "common_control" => {
            has_exact_fields(body, &["operations", "canonical_input"], &[])
                && validate_closed_common_control_operations(&body["operations"]).is_ok()
        }
        "observe" => has_exact_fields(body, &["record_id"], &[]),
        "feedback" => has_exact_fields(body, &["record_ids"], &[]),
        "correction" => has_exact_fields(body, &["superseded", "superseding", "evidence"], &[]),
        "maintenance" => has_exact_fields(body, &["kind"], &["canonical_input"]),
        "deletion_fence" => has_exact_fields(
            body,
            &[
                "source",
                "sources",
                "target_epoch",
                "idempotency_key",
                "payload_sha256",
                "deleted_records",
                "deleted_record_ids",
                "pre_fence_state_digest",
                "fatigue",
                "steps_since_consolidation",
            ],
            &["canonical_input"],
        ),
        "delete_by_source" => has_exact_fields(
            body,
            &[
                "source",
                "sources",
                "target_epoch",
                "deleted_records",
                "deleted_record_ids",
            ],
            &["payload_sha256", "canonical_input"],
        ),
        _ => false,
    };
    if valid { Ok(()) } else { Err(()) }
}

/// The receipt structs intentionally deserialize the operation enum with the
/// default serde behavior, which ignores fields added to a variant body. Keep
/// the common-control operation envelope closed before any replay projection
/// can rely on the decoded operation list.
fn validate_closed_common_control_operations(value: &Value) -> Result<(), ()> {
    let operations = value.as_array().ok_or(())?;
    for operation in operations {
        let object = operation.as_object().ok_or(())?;
        if object.len() != 1 {
            return Err(());
        }
        let Some((name, body)) = object.iter().next() else {
            return Err(());
        };
        let body = body.as_object().ok_or(())?;
        let valid = match name.as_str() {
            "observe" => has_exact_fields(body, &["record_id"], &[]),
            "feedback" => has_exact_fields(body, &["record_ids"], &[]),
            "correction" => has_exact_fields(body, &["superseded", "superseding", "evidence"], &[]),
            "maintenance" => has_exact_fields(body, &["kind"], &["canonical_input"]),
            _ => false,
        };
        if !valid {
            return Err(());
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ReplayJournal {
    last: u64,
    identities: BTreeMap<u64, ReplayIdentity>,
    item_receipts: BTreeMap<String, ReplayItemReceipt>,
    event_keys: BTreeSet<String>,
    page_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayIdentity {
    sequence: u64,
    receipt_digest: String,
    source: String,
    admitted: bool,
    observation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayItemReceipt {
    identity: ReplayIdentity,
    delivery_key: String,
    state: String,
    reason: Option<String>,
    record_id: Option<u64>,
    generation: u64,
}

struct ReplayPageReceipt {
    acknowledged: u64,
    items: Vec<ReplayPageItem>,
}

struct ReplayPageItem {
    identity: ReplayIdentity,
    delivery_key: String,
    state: String,
    reason: Option<String>,
    record_id: Option<u64>,
    generation: u64,
}

fn validate_replay_item_request(
    handle: &NamespaceHandle,
    journal: &ReplayJournal,
    item: &ReplayItem,
    generation: u64,
    allow_legacy_alias: bool,
) -> Result<(), EngineReply> {
    if item.sequence > journal.last.saturating_add(1) {
        return Err(invalid("replay sequence gap", generation));
    }
    let requested_identity = replay_item_identity(item)
        .ok_or_else(|| corrupt_replay(generation, "replay item identity is invalid"))?;
    let legacy_identity = if allow_legacy_alias {
        legacy_replay_identity(handle, item, generation)?
    } else {
        None
    };
    let matches_identity = |identity: &ReplayIdentity| {
        identity == &requested_identity || legacy_identity.as_ref() == Some(identity)
    };
    if let Some(receipt) = journal.item_receipts.get(&item.delivery_key) {
        if receipt.identity.receipt_digest != item.receipt_digest {
            return Err(conflict(generation));
        }
        if !matches_identity(&receipt.identity) {
            // A source binding upgrade can preserve the legacy source while
            // changing the observation payload. That is a normal idempotency
            // conflict; a key used for a genuinely different source remains a
            // journal corruption signal.
            if legacy_identity.as_ref().is_some_and(|identity| {
                identity.sequence == receipt.identity.sequence
                    && identity.receipt_digest == receipt.identity.receipt_digest
                    && identity.source == receipt.identity.source
                    && identity.admitted == receipt.identity.admitted
            }) {
                return Err(conflict(generation));
            }
            return Err(corrupt_replay(
                generation,
                "replay delivery key is bound to another source identity",
            ));
        }
    } else if journal.event_keys.contains(&item.delivery_key) {
        return Err(corrupt_replay(
            generation,
            "replay delivery key is reused by another durable operation",
        ));
    }
    match journal.identities.get(&item.sequence) {
        Some(identity) if identity.receipt_digest != item.receipt_digest => {
            Err(conflict(generation))
        }
        Some(identity) if !matches_identity(identity) => Err(corrupt_replay(
            generation,
            "replay item identity changed across deliveries",
        )),
        None if item.sequence <= journal.last => Err(corrupt_replay(
            generation,
            "replay item identity is missing from the journal",
        )),
        _ => Ok(()),
    }
}

fn legacy_replay_identity(
    handle: &NamespaceHandle,
    item: &ReplayItem,
    generation: u64,
) -> Result<Option<ReplayIdentity>, EngineReply> {
    if !item.admitted {
        let Some(legacy_source) = item.legacy_source.as_deref() else {
            return Ok(None);
        };
        return Ok(Some(ReplayIdentity {
            sequence: item.sequence,
            receipt_digest: item.receipt_digest.clone(),
            source: legacy_source.to_owned(),
            admitted: false,
            observation: None,
        }));
    }
    let request = replacement_request(
        &item.observation,
        Deadline {
            remaining_ms: u64::MAX,
        },
    )
    .map_err(|_| corrupt_replay(generation, "replay item identity is invalid"))?;
    let Some(legacy) = legacy_request(handle.store.namespace(), &request)
        .map_err(|_| corrupt_replay(generation, "replay item source binding is invalid"))?
    else {
        return Ok(None);
    };
    if item
        .legacy_source
        .as_deref()
        .is_some_and(|source| source != legacy.source.0)
    {
        return Ok(None);
    }
    Ok(Some(ReplayIdentity {
        sequence: item.sequence,
        receipt_digest: item.receipt_digest.clone(),
        source: legacy.source.0,
        admitted: true,
        observation: Some(legacy.payload_sha256),
    }))
}

fn record_replay_identity(
    identities: &mut BTreeMap<u64, ReplayIdentity>,
    last: &mut u64,
    identity: ReplayIdentity,
    generation: u64,
) -> Result<(), EngineReply> {
    if let Some(existing) = identities.get(&identity.sequence) {
        if existing != &identity {
            return Err(corrupt_replay(
                generation,
                "replay source identity changed across receipts",
            ));
        }
        return Ok(());
    }
    if identity.sequence > last.saturating_add(1) {
        return Err(corrupt_replay(
            generation,
            "replay source sequence is out of order",
        ));
    }
    *last = (*last).max(identity.sequence);
    identities.insert(identity.sequence, identity);
    Ok(())
}

fn replay_item_identity(item: &ReplayItem) -> Option<ReplayIdentity> {
    let observation = if item.admitted {
        Some(opaque(&item.observation["payload_sha256"])?.to_owned())
    } else if !item.observation.is_null() {
        return None;
    } else {
        None
    };
    Some(ReplayIdentity {
        sequence: item.sequence,
        receipt_digest: item.receipt_digest.clone(),
        source: item.source.clone(),
        admitted: item.admitted,
        observation,
    })
}

fn capsule_source_matches(
    namespace: &str,
    capsule: &crate::store::StoredCapsule,
    source: &str,
) -> bool {
    if capsule.source_id.0 == source {
        return true;
    }
    let Ok(provenance) = serde_json::from_str::<Value>(&capsule.provenance) else {
        return false;
    };
    let Ok(Some(binding)) = crate::source_binding::read(namespace, &capsule.source_id, &provenance)
    else {
        return false;
    };
    binding.legacy_source_id.0 == source
        || binding
            .full_source_id
            .as_ref()
            .is_some_and(|full_source| full_source.0 == source)
}

/// Recomputes the original observe payload digest from the retained capsule.
/// A receipt that merely points at another valid capsule from the same source
/// must not be able to relabel that record as the replayed observation.
fn capsule_matches_replay_observation(
    capsule: &crate::store::StoredCapsule,
    observation: &str,
) -> bool {
    if capsule.status == CapsuleStatus::Revoked {
        // A source deletion intentionally removes the retained observation
        // bytes before a later replay retry can inspect this journal row. The
        // record ID, source ID, commit sequence, and authenticated item
        // receipt still bind the tombstone; require the exact scrub shape and
        // accept that durable binding in place of recomputing the old digest.
        return capsule.key_text.is_empty()
            && capsule.value_text.is_empty()
            && capsule.key_embedding.is_empty()
            && capsule.value_embedding.is_empty()
            && capsule.ltm_key.is_empty()
            && capsule.provenance == "{}";
    }
    let event = crate::store::Event {
        seq: capsule.commit_seq,
        kind: "observe".to_owned(),
        idempotency_key: None,
        payload_sha256: observation.to_owned(),
        receipt: String::new(),
        created_tick: 0,
    };
    let durable = DurableReceipt {
        reply: EngineReply::new(Outcome::Success, capsule.commit_seq, Value::Null),
        operation: DurableOperation::Observe {
            record_id: capsule.record_id,
        },
        state_digest: String::new(),
        integrity_digest: String::new(),
        idempotency_key: None,
    };
    validate_event_payload_digest(&event, &durable, std::slice::from_ref(capsule)).is_ok()
}

fn validate_replay_item_receipt(
    event: &crate::store::Event,
    durable: &DurableReceipt,
    operations: &[DurableOperation],
    canonical_input: &Value,
    capsules: &[crate::store::StoredCapsule],
    namespace: &str,
    generation: u64,
) -> Result<ReplayItemReceipt, EngineReply> {
    let corrupt = || corrupt_replay(generation, "invalid durable replay item receipt");
    if event.kind != "common_control" || !event.idempotency_key.as_deref().is_some_and(valid_opaque)
    {
        return Err(corrupt());
    }
    let delivery_key = event.idempotency_key.clone().ok_or_else(corrupt)?;
    let object = canonical_input.as_object().ok_or_else(corrupt)?;
    if object.len() != 5
        || object.get("sequence").is_none()
        || object.get("receipt").is_none()
        || object.get("source").is_none()
        || object.get("admitted").is_none()
        || object.get("observation").is_none()
    {
        return Err(corrupt());
    }
    let sequence = canonical_input["sequence"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(corrupt)?;
    let receipt_digest = opaque(&canonical_input["receipt"])
        .ok_or_else(corrupt)?
        .to_owned();
    let source = opaque(&canonical_input["source"])
        .ok_or_else(corrupt)?
        .to_owned();
    let admitted = canonical_input["admitted"].as_bool().ok_or_else(corrupt)?;
    let observation = if admitted {
        Some(
            opaque(&canonical_input["observation"])
                .ok_or_else(corrupt)?
                .to_owned(),
        )
    } else if !canonical_input["observation"].is_null() {
        return Err(corrupt());
    } else {
        None
    };
    let payload = &durable.reply.payload;
    let payload_object = payload.as_object().ok_or_else(corrupt)?;
    if !has_exact_fields(
        payload_object,
        &[
            "common_portability",
            "source_sequence",
            "receipt_digest",
            "state",
            "reason",
            "record_id",
            "replayed",
            "state_generation_after",
            "request_semantic_sha256",
        ],
        &[],
    ) {
        return Err(corrupt());
    }
    if payload["common_portability"] != "replay_item"
        || payload["source_sequence"].as_u64() != Some(sequence)
        || payload["receipt_digest"] != receipt_digest
        || payload["state_generation_after"].as_u64() != Some(event.seq)
        || payload["replayed"] != false
        || payload["request_semantic_sha256"] != event.payload_sha256
    {
        return Err(corrupt());
    }
    let state = payload["state"].as_str().ok_or_else(corrupt)?;
    let reason = match &payload["reason"] {
        Value::Null => None,
        Value::String(reason) => Some(reason.clone()),
        _ => return Err(corrupt()),
    };
    let record_id = match &payload["record_id"] {
        Value::Null => None,
        Value::Number(value) => Some(
            value
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(corrupt)?,
        ),
        _ => return Err(corrupt()),
    };
    match state {
        "applied" => {
            let Some(record_id) = record_id else {
                return Err(corrupt());
            };
            if !admitted
                || reason.is_some()
                || operations.len() != 1
                || !matches!(
                    operations.first(),
                    Some(DurableOperation::Observe { record_id: id }) if id.0 == record_id
                )
            {
                return Err(corrupt());
            }
            if !capsules.iter().any(|capsule| {
                capsule.record_id.0 == record_id
                    && capsule.commit_seq == event.seq
                    && capsule_source_matches(namespace, capsule, &source)
                    && observation.as_deref().is_some_and(|observation| {
                        capsule_matches_replay_observation(capsule, observation)
                    })
            }) {
                return Err(corrupt());
            }
        }
        "source_already_applied" => {
            if !admitted || record_id.is_none() || reason.is_some() || !operations.is_empty() {
                return Err(corrupt());
            }
            let Some(record_id) = record_id else {
                return Err(corrupt());
            };
            if !capsules.iter().any(|capsule| {
                capsule.record_id.0 == record_id
                    && capsule.commit_seq < event.seq
                    && capsule_source_matches(namespace, capsule, &source)
                    && observation.as_deref().is_some_and(|observation| {
                        capsule_matches_replay_observation(capsule, observation)
                    })
            }) {
                return Err(corrupt());
            }
        }
        "rejected" => {
            if record_id.is_some()
                || (admitted && reason.as_deref() != Some("source_revoked"))
                || (!admitted && reason.as_deref() != Some("current_disposition"))
                || !operations.is_empty()
            {
                return Err(corrupt());
            }
        }
        _ => return Err(corrupt()),
    }
    Ok(ReplayItemReceipt {
        identity: ReplayIdentity {
            sequence,
            receipt_digest,
            source,
            admitted,
            observation,
        },
        delivery_key,
        state: state.to_owned(),
        reason,
        record_id,
        generation: event.seq,
    })
}

fn validate_replay_page_receipt(
    namespace: &str,
    event: &crate::store::Event,
    durable: &DurableReceipt,
    operations: &[DurableOperation],
    canonical_input: &Value,
    capsules: &[crate::store::StoredCapsule],
    generation: u64,
) -> Result<ReplayPageReceipt, EngineReply> {
    let corrupt = || corrupt_replay(generation, "invalid durable replay page receipt");
    if event.kind != "common_control"
        || !event.idempotency_key.as_deref().is_some_and(valid_opaque)
        || !operations.is_empty()
    {
        return Err(corrupt());
    }
    let object = canonical_input.as_object().ok_or_else(corrupt)?;
    if !has_exact_fields(
        object,
        &[
            "action",
            "first_source_sequence",
            "last_source_sequence",
            "expected_previous_acknowledged_sequence",
            "items",
        ],
        &[],
    ) || object.get("action").and_then(Value::as_str) != Some("replay")
    {
        return Err(corrupt());
    }
    let first = canonical_input["first_source_sequence"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(corrupt)?;
    let last = canonical_input["last_source_sequence"]
        .as_u64()
        .filter(|value| *value >= first)
        .ok_or_else(corrupt)?;
    let previous = canonical_input["expected_previous_acknowledged_sequence"]
        .as_u64()
        .ok_or_else(corrupt)?;
    let values = canonical_input["items"].as_array().ok_or_else(corrupt)?;
    if values.is_empty()
        || values.len() > MAX_ITEMS
        || last
            .checked_sub(first)
            .and_then(|value| value.checked_add(1))
            != Some(values.len() as u64)
    {
        return Err(corrupt());
    }
    let mut identities = Vec::with_capacity(values.len());
    let mut seen_delivery_keys = BTreeSet::new();
    let mut seen_receipt_digests = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let object = value.as_object().ok_or_else(corrupt)?;
        if !has_exact_fields(
            object,
            &[
                "source_sequence",
                "receipt_digest",
                "delivery_key",
                "source",
                "admitted",
                "blocked",
                "observation",
            ],
            &["legacy_source"],
        ) {
            return Err(corrupt());
        }
        let expected_sequence = first.checked_add(index as u64).ok_or_else(corrupt)?;
        let sequence = value["source_sequence"]
            .as_u64()
            .filter(|sequence| *sequence == expected_sequence)
            .ok_or_else(corrupt)?;
        let receipt_digest = opaque(&value["receipt_digest"])
            .ok_or_else(corrupt)?
            .to_owned();
        let delivery_key = opaque(&value["delivery_key"])
            .ok_or_else(corrupt)?
            .to_owned();
        if !seen_delivery_keys.insert(delivery_key.clone())
            || !seen_receipt_digests.insert(receipt_digest.clone())
        {
            return Err(corrupt());
        }
        let source = opaque(&value["source"]).ok_or_else(corrupt)?.to_owned();
        let admitted = value["admitted"].as_bool().ok_or_else(corrupt)?;
        if value["blocked"].as_bool().is_none()
            || (value["admitted"] == true && value["blocked"] == true)
        {
            return Err(corrupt());
        }
        let observation = if admitted {
            Some(
                opaque(&value["observation"])
                    .ok_or_else(corrupt)?
                    .to_owned(),
            )
        } else if !value["observation"].is_null() {
            return Err(corrupt());
        } else {
            None
        };
        if let Some(legacy) = value.get("legacy_source")
            && (opaque(legacy).is_none() || legacy == &value["source"])
        {
            return Err(corrupt());
        }
        identities.push(ReplayPageItem {
            identity: ReplayIdentity {
                sequence,
                receipt_digest,
                source,
                admitted,
                observation,
            },
            delivery_key,
            state: String::new(),
            reason: None,
            record_id: None,
            generation: 0,
        });
    }
    let payload = &durable.reply.payload;
    let payload_object = payload.as_object().ok_or_else(corrupt)?;
    if !has_exact_fields(
        payload_object,
        &[
            "common_portability",
            "first_source_sequence",
            "last_source_sequence",
            "acknowledged_sequence",
            "state_generation_before",
            "state_generation_after",
            "applied_observations",
            "duplicate_observations",
            "sources_already_applied",
            "rejected_observations",
            "effect_unknown_observations",
            "partial",
            "replayed",
            "warnings",
            "items",
            "request_semantic_sha256",
        ],
        &["page_delivery_capsule"],
    ) {
        return Err(corrupt());
    }
    let acknowledged = payload["acknowledged_sequence"]
        .as_u64()
        .ok_or_else(corrupt)?;
    let state_generation_before = payload["state_generation_before"]
        .as_u64()
        .ok_or_else(corrupt)?;
    if payload["common_portability"] != "replay"
        || payload["first_source_sequence"].as_u64() != Some(first)
        || payload["last_source_sequence"].as_u64() != Some(last)
        || payload["acknowledged_sequence"].as_u64() != Some(previous.max(last))
        || state_generation_before >= event.seq
        || payload["state_generation_after"].as_u64() != Some(event.seq)
        || payload["partial"] != false
        || payload["replayed"] != false
        || payload["request_semantic_sha256"] != event.payload_sha256
        || payload["effect_unknown_observations"] != 0
        || payload["warnings"]
            .as_array()
            .is_none_or(|warnings| !warnings.is_empty())
    {
        return Err(corrupt());
    }
    let output_items = payload["items"].as_array().ok_or_else(corrupt)?;
    if output_items.len() != identities.len() {
        return Err(corrupt());
    }
    let mut counts = [0_u64; 4];
    let mut page_items = Vec::with_capacity(identities.len());
    for ((page_item, input), output) in identities.iter().zip(values).zip(output_items) {
        let identity = &page_item.identity;
        let output_object = output.as_object().ok_or_else(corrupt)?;
        if !has_exact_fields(
            output_object,
            &[
                "source_sequence",
                "receipt_digest",
                "state",
                "reason",
                "record_id",
                "state_generation",
            ],
            &[],
        ) || output["source_sequence"].as_u64() != Some(identity.sequence)
            || output["receipt_digest"] != identity.receipt_digest
        {
            return Err(corrupt());
        }
        let output_generation = output["state_generation"]
            .as_u64()
            // Every item row points at an earlier durable item receipt. A
            // page event cannot be its own item receipt, and a future event
            // would make the page output independent of the journal order.
            .filter(|generation| *generation > 0 && *generation < event.seq)
            .ok_or_else(corrupt)?;
        let output_reason = match &output["reason"] {
            Value::Null => None,
            Value::String(reason) => Some(reason.clone()),
            _ => return Err(corrupt()),
        };
        let output_record_id = match &output["record_id"] {
            Value::Null => None,
            Value::Number(value) => Some(
                value
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or_else(corrupt)?,
            ),
            _ => return Err(corrupt()),
        };
        let admitted = input["admitted"].as_bool().ok_or_else(corrupt)?;
        let blocked = input["blocked"].as_bool().ok_or_else(corrupt)?;
        let output_state = output["state"].as_str().ok_or_else(corrupt)?;
        match output_state {
            "applied" => {
                if !admitted
                    || blocked
                    || output["record_id"]
                        .as_u64()
                        .filter(|value| *value > 0)
                        .is_none()
                    || !output["reason"].is_null()
                    || output_generation <= state_generation_before
                {
                    return Err(corrupt());
                }
                counts[0] = counts[0].checked_add(1).ok_or_else(corrupt)?;
            }
            "delivery_duplicate" => {
                if !admitted
                    || blocked
                    || output["record_id"]
                        .as_u64()
                        .filter(|value| *value > 0)
                        .is_none()
                    || !output["reason"].is_null()
                {
                    return Err(corrupt());
                }
                counts[1] = counts[1].checked_add(1).ok_or_else(corrupt)?;
            }
            "source_already_applied" => {
                if !admitted
                    || blocked
                    || output["record_id"]
                        .as_u64()
                        .filter(|value| *value > 0)
                        .is_none()
                    || !output["reason"].is_null()
                {
                    return Err(corrupt());
                }
                counts[2] = counts[2].checked_add(1).ok_or_else(corrupt)?;
            }
            "rejected" => {
                let reason = output["reason"].as_str();
                if !output["record_id"].is_null()
                    || (admitted && (blocked || reason != Some("source_revoked")))
                    || (!admitted && reason != Some("current_disposition"))
                {
                    return Err(corrupt());
                }
                counts[3] = counts[3].checked_add(1).ok_or_else(corrupt)?;
            }
            _ => return Err(corrupt()),
        }
        page_items.push(ReplayPageItem {
            identity: identity.clone(),
            delivery_key: page_item.delivery_key.clone(),
            state: output_state.to_owned(),
            reason: output_reason,
            record_id: output_record_id,
            generation: output_generation,
        });
    }
    if payload["applied_observations"].as_u64() != Some(counts[0])
        || payload["duplicate_observations"].as_u64() != Some(counts[1])
        || payload["sources_already_applied"].as_u64() != Some(counts[2])
        || payload["rejected_observations"].as_u64() != Some(counts[3])
    {
        return Err(corrupt());
    }
    if let Some(capsule) = payload.get("page_delivery_capsule") {
        let page_key = event.idempotency_key.as_deref().ok_or_else(corrupt)?;
        if validate_replay_delivery_capsule(namespace, page_key, capsule).is_err()
            && !legacy_page_delivery_capsule_matches_receipt_items(capsule, &page_items, capsules)
        {
            return Err(corrupt());
        }
    }
    Ok(ReplayPageReceipt {
        acknowledged,
        items: page_items,
    })
}

fn validate_replay_page_output(
    page_item: &ReplayPageItem,
    durable_item: &ReplayItemReceipt,
    previously_delivered: bool,
) -> bool {
    let expected_state = if previously_delivered && durable_item.state != "rejected" {
        "delivery_duplicate"
    } else {
        durable_item.state.as_str()
    };
    page_item.state == expected_state
        && page_item.reason == durable_item.reason
        && page_item.record_id == durable_item.record_id
        && page_item.generation == durable_item.generation
}

fn corrupt_replay(generation: u64, reason: &str) -> EngineReply {
    EngineReply::new(Outcome::Corrupt, generation, json!({"reason": reason}))
}

fn has_exact_fields(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> bool {
    required.iter().all(|field| object.contains_key(*field))
        && object
            .keys()
            .all(|field| required.contains(&field.as_str()) || optional.contains(&field.as_str()))
}

/// Decodes the adapter's delivery capsule. The operation identity is retained
/// for receipt evidence while the idempotency key is checked by the caller
/// against the page key or a historical item-delivery compatibility shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReplayDelivery {
    operation_id: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutReplayDelivery {
    operation_id: String,
    idempotency_key: String,
    caller_binding: CheckoutCallerBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutCallerBinding {
    version: u64,
    exact_scope: ReplayCallerScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayCallerScope {
    profile_id: String,
    project_id: String,
    repository_identity: String,
    worktree_identity: String,
    branch_identity: String,
    agent_session_id: String,
    resolved_scope_digest: String,
}

fn replay_delivery_bytes(capsule: &Value) -> Result<Vec<u8>, ()> {
    let object = capsule.as_object().ok_or(())?;
    if !has_exact_fields(object, &["version", "bytes", "sha256"], &[]) || capsule["version"] != 1 {
        return Err(());
    }
    super::util::validate_common_capsule(&json!({"common_capsule": capsule})).map_err(|_| ())?;
    bytes(&capsule["bytes"]).ok_or(())
}

fn validate_delivery_parts(operation_id: &str, key: &str) -> Result<(), ()> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || operation_id.bytes().any(|byte| byte.is_ascii_control())
        || key.is_empty()
        || key.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(());
    }
    super::util::validate_idempotency_key(key).map_err(|_| ())
}

fn decode_replay_delivery_capsule(capsule: &Value) -> Result<(String, String), ()> {
    // This decoder remains strictly legacy. A framed capsule must never enter
    // the raw/SHA/old opaque-key or historical item-capsule compatibility paths.
    let delivery: LegacyReplayDelivery =
        serde_json::from_slice(&replay_delivery_bytes(capsule)?).map_err(|_| ())?;
    validate_delivery_parts(&delivery.operation_id, &delivery.idempotency_key)?;
    Ok((delivery.operation_id, delivery.idempotency_key))
}

fn replay_caller_namespace(scope: &ReplayCallerScope, checkout: bool) -> Result<String, ()> {
    use sha2::{Digest, Sha256};
    // Apply the public boundary's validation before hashing any claimed scope.
    tracedecay_memory_provider_api::OwnedExactScope::new(
        &scope.profile_id,
        &scope.project_id,
        &scope.repository_identity,
        &scope.worktree_identity,
        &scope.branch_identity,
        &scope.agent_session_id,
        &scope.resolved_scope_digest,
    )
    .map_err(|_| ())?;
    let mut digest = Sha256::new();
    digest.update(if checkout {
        b"tracedecay.ncm.checkout.v1\0".as_slice()
    } else {
        b"tracedecay.ncm.scope.v1\0".as_slice()
    });
    let mut fields = vec![
        scope.profile_id.as_str(),
        scope.project_id.as_str(),
        scope.repository_identity.as_str(),
        scope.worktree_identity.as_str(),
        scope.branch_identity.as_str(),
    ];
    if !checkout {
        fields.extend([
            scope.agent_session_id.as_str(),
            scope.resolved_scope_digest.as_str(),
        ]);
    }
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Binds a delivery capsule to its page key. Legacy bodies retain their exact
/// accepted shapes. Checkout bodies prove the namespace and all seven caller
/// identities before their additional exact-caller framing is accepted.
fn validate_replay_delivery_capsule(
    namespace: &str,
    page_key: &str,
    capsule: &Value,
) -> Result<(), ()> {
    if let Ok((_, idempotency_key)) = decode_replay_delivery_capsule(capsule) {
        return if idempotency_key == page_key
            || sha256_hex(idempotency_key.as_bytes()) == page_key
            || crate::source_binding::opaque_id(namespace, b"idempotency-key", &idempotency_key)
                == page_key
        {
            Ok(())
        } else {
            Err(())
        };
    }
    let delivery: CheckoutReplayDelivery =
        serde_json::from_slice(&replay_delivery_bytes(capsule)?).map_err(|_| ())?;
    validate_delivery_parts(&delivery.operation_id, &delivery.idempotency_key)?;
    if delivery.caller_binding.version != 1
        || replay_caller_namespace(&delivery.caller_binding.exact_scope, true)? != namespace
    {
        return Err(());
    }
    let exact = replay_caller_namespace(&delivery.caller_binding.exact_scope, false)?;
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"tracedecay.ncm.opaque-id.v1\0");
    for field in [
        namespace,
        "idempotency-key",
        &exact,
        &delivery.idempotency_key,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    let expected: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if expected != page_key {
        return Err(());
    }
    Ok(())
}

/// Historical direct replay pages carried an item delivery capsule in every
/// admitted observation, while their page delivery capsule used a separate
/// public key. Keep that old page receipt readable only when the item capsules
/// independently bind each item's delivery key. New adapter pages never take
/// this path: their projected item capsule carries the page key itself.
fn legacy_page_delivery_capsule_matches_items(capsule: &Value, items: &[ReplayItem]) -> bool {
    if items.is_empty() {
        return false;
    }
    if decode_replay_delivery_capsule(capsule).is_err() {
        return false;
    }
    items.iter().all(|item| {
        if !item.admitted {
            return false;
        }
        let Some(item_capsule) = item
            .observation
            .get("provenance")
            .and_then(|provenance| provenance.get("delivery_capsule"))
        else {
            return false;
        };
        let Ok((_, item_key)) = decode_replay_delivery_capsule(item_capsule) else {
            return false;
        };
        item_key == item.delivery_key
    })
}

/// Equivalent compatibility check for a durable page receipt after its input
/// observations have been reduced to payload digests. The output record IDs
/// let us recover the retained item capsules without trusting the page output
/// itself for any identity field.
fn legacy_page_delivery_capsule_matches_receipt_items(
    capsule: &Value,
    items: &[ReplayPageItem],
    capsules: &[crate::store::StoredCapsule],
) -> bool {
    if items.is_empty() || decode_replay_delivery_capsule(capsule).is_err() {
        return false;
    }
    items.iter().all(|item| {
        let Some(record_id) = item.record_id else {
            return false;
        };
        let Some(retained) = capsules.iter().find(|retained| {
            retained.record_id.0 == record_id && retained.status != CapsuleStatus::Revoked
        }) else {
            return false;
        };
        let Ok(provenance) = serde_json::from_str::<Value>(&retained.provenance) else {
            return false;
        };
        let Some(item_capsule) = provenance.get("delivery_capsule") else {
            return false;
        };
        let Ok((_, item_key)) = decode_replay_delivery_capsule(item_capsule) else {
            return false;
        };
        item_key == item.delivery_key
    })
}

struct ReplayPage {
    key: String,
    expected: u64,
    first: u64,
    last: u64,
    previous: u64,
    items: Vec<ReplayItem>,
    page_delivery_capsule: Option<Value>,
}
struct ReplayItem {
    sequence: u64,
    receipt_digest: String,
    delivery_key: String,
    source: String,
    legacy_source: Option<String>,
    admitted: bool,
    blocked: bool,
    observation: Value,
}

impl ReplayPage {
    fn parse(namespace: &str, value: &Value, deadline: Deadline) -> Result<Self, EngineReply> {
        let fail = || invalid("invalid replay page", 0);
        let object = value.as_object().ok_or_else(fail)?;
        if !has_exact_fields(
            object,
            &[
                "action",
                "idempotency_key",
                "expected_generation",
                "first_source_sequence",
                "last_source_sequence",
                "expected_previous_acknowledged_sequence",
                "items",
            ],
            &["page_delivery_capsule"],
        ) || value["action"] != "replay"
        {
            return Err(fail());
        }
        let key = opaque(&value["idempotency_key"])
            .ok_or_else(fail)?
            .to_owned();
        let expected = value["expected_generation"].as_u64().ok_or_else(fail)?;
        let first = value["first_source_sequence"].as_u64().ok_or_else(fail)?;
        let last = value["last_source_sequence"].as_u64().ok_or_else(fail)?;
        let previous = value["expected_previous_acknowledged_sequence"]
            .as_u64()
            .ok_or_else(fail)?;
        let page_delivery_capsule = value.get("page_delivery_capsule").cloned();
        let values = value["items"].as_array().ok_or_else(fail)?;
        if first == 0
            || values.is_empty()
            || values.len() > MAX_ITEMS
            || last
                .checked_sub(first)
                .and_then(|value| value.checked_add(1))
                != Some(values.len() as u64)
        {
            return Err(fail());
        }
        let mut seen = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        let mut items = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let object = value.as_object().ok_or_else(fail)?;
            if !has_exact_fields(
                object,
                &[
                    "source_sequence",
                    "receipt_digest",
                    "delivery_key",
                    "source",
                    "admitted",
                    "blocked",
                    "observation",
                ],
                &["legacy_source"],
            ) {
                return Err(fail());
            }
            let item = ReplayItem {
                sequence: value["source_sequence"].as_u64().ok_or_else(fail)?,
                receipt_digest: opaque(&value["receipt_digest"])
                    .ok_or_else(fail)?
                    .to_owned(),
                delivery_key: opaque(&value["delivery_key"]).ok_or_else(fail)?.to_owned(),
                source: opaque(&value["source"]).ok_or_else(fail)?.to_owned(),
                legacy_source: match value.get("legacy_source") {
                    None => None,
                    Some(value) => Some(opaque(value).ok_or_else(fail)?.to_owned()),
                },
                admitted: value["admitted"].as_bool().ok_or_else(fail)?,
                blocked: value["blocked"].as_bool().ok_or_else(fail)?,
                observation: value["observation"].clone(),
            };
            if item.sequence != first + index as u64
                || !seen.insert(item.delivery_key.clone())
                || !receipts.insert(item.receipt_digest.clone())
                || item.delivery_key == key
                || (item.admitted && item.blocked)
                || item
                    .legacy_source
                    .as_ref()
                    .is_some_and(|legacy| legacy == &item.source)
            {
                return Err(fail());
            }
            if item.admitted {
                let request =
                    replacement_request(&item.observation, deadline).map_err(|_| fail())?;
                let binding =
                    crate::source_binding::read(namespace, &request.source, &request.provenance)
                        .map_err(|_| fail())?;
                if let Some(legacy) = &item.legacy_source
                    && !binding.as_ref().is_some_and(|binding| {
                        !binding.is_legacy
                            && binding.legacy_source_id.0 == *legacy
                            && binding.full_source_id.as_ref() == Some(&request.source)
                    })
                {
                    return Err(fail());
                }
                if request.idempotency_key != item.delivery_key
                    || request.source.0 != item.source
                    || opaque(&request.provenance["common_capsule"]["sha256"]).is_none()
                    || opaque(&request.provenance["selection"]["observation_identity"]).is_none()
                    || (!request.provenance["selection"]["revision_digest"].is_null()
                        && opaque(&request.provenance["selection"]["revision_digest"]).is_none())
                {
                    return Err(fail());
                }
            } else if !item.observation.is_null() {
                return Err(fail());
            }
            items.push(item);
        }
        if let Some(capsule) = &page_delivery_capsule
            && validate_replay_delivery_capsule(namespace, &key, capsule).is_err()
            && !legacy_page_delivery_capsule_matches_items(capsule, &items)
        {
            return Err(fail());
        }
        Ok(Self {
            key,
            expected,
            first,
            last,
            previous,
            items,
            page_delivery_capsule,
        })
    }
    fn output(&self) -> Value {
        let mut output = json!({"common_portability":"replay","first_source_sequence":self.first,"last_source_sequence":self.last,"acknowledged_sequence":self.previous,"state_generation_before":self.expected,"state_generation_after":self.expected,"applied_observations":0,"duplicate_observations":0,"sources_already_applied":0,"rejected_observations":0,"effect_unknown_observations":0,"partial":false,"replayed":false,"warnings":[],"items":[]});
        if let Some(capsule) = &self.page_delivery_capsule {
            output["page_delivery_capsule"] = capsule.clone();
        }
        output
    }
}

impl ReplayItem {
    fn output(&self, state: &str, reason: Option<&str>, record: Option<u64>) -> Value {
        json!({"common_portability":"replay_item","source_sequence":self.sequence,"receipt_digest":self.receipt_digest,"state":state,"reason":reason,"record_id":record,"replayed":false})
    }
}

fn push_item(
    output: &mut Value,
    item: &ReplayItem,
    state: &str,
    reason: Option<&str>,
    record: Option<u64>,
    generation: u64,
) -> Result<(), EngineReply> {
    let corrupt = || EngineReply::new(Outcome::EffectUnknown, generation, Value::Null);
    let counter = match state {
        "applied" => "applied_observations",
        "delivery_duplicate" => "duplicate_observations",
        "source_already_applied" => "sources_already_applied",
        "effect_unknown" => "effect_unknown_observations",
        "rejected" => "rejected_observations",
        _ => return Err(corrupt()),
    };
    let count = output[counter]
        .as_u64()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(corrupt)?;
    output[counter] = json!(count);
    output["items"].as_array_mut().ok_or_else(corrupt)?.push(json!({"source_sequence":item.sequence,"receipt_digest":item.receipt_digest,"state":state,"reason":reason,"record_id":record,"state_generation":generation}));
    Ok(())
}

fn partial_reply(
    mut payload: Value,
    generation: u64,
    before: u64,
    outcome: Outcome,
) -> EngineReply {
    payload["partial"] = json!(true);
    payload["state_generation_after"] = json!(generation);
    let outcome = if outcome == Outcome::EffectUnknown {
        outcome
    } else if generation > before {
        Outcome::Success
    } else {
        outcome
    };
    EngineReply::new(outcome, generation, payload)
}

fn opaque(value: &Value) -> Option<&str> {
    value.as_str().filter(|value| valid_opaque(value))
}
fn valid_opaque(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn bytes(value: &Value) -> Option<Vec<u8>> {
    let values = value.as_array()?;
    if values.is_empty() || values.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    values
        .iter()
        .map(|value| u8::try_from(value.as_u64()?).ok())
        .collect()
}
fn invalid(reason: &str, generation: u64) -> EngineReply {
    EngineReply::rejected(RejectReason::InvalidRequest(reason.to_owned()), generation)
}
fn conflict(generation: u64) -> EngineReply {
    EngineReply::rejected(RejectReason::IdempotencyConflict, generation)
}

fn legacy_request(
    namespace: &str,
    request: &ObserveRequest,
) -> Result<Option<ObserveRequest>, String> {
    let Some(binding) =
        crate::source_binding::read(namespace, &request.source, &request.provenance)?
            .filter(|binding| !binding.is_legacy)
    else {
        return Ok(None);
    };
    let mut legacy = request.clone();
    legacy.source = binding.legacy_source_id;
    if let Some(provenance) = legacy.provenance.as_object_mut() {
        provenance.remove("source_binding");
    }
    legacy.payload_sha256 = legacy.canonical_payload_sha256()?;
    Ok(Some(legacy))
}

fn item_digest(item: &ReplayItem, request: &ObserveRequest) -> Result<String, String> {
    canonical_digest(
        &json!({"sequence":item.sequence,"receipt":item.receipt_digest,
        "source":request.source,"admitted":item.admitted,"observation":request.payload_sha256}),
    )
}

fn legacy_item_matches(
    handle: &NamespaceHandle,
    item: &ReplayItem,
    request: &ObserveRequest,
    digest: &str,
) -> Result<bool, EngineReply> {
    let Some(event) = handle
        .store
        .event_for_key(&item.delivery_key)
        .map_err(|error| store_reply(error, handle.commit_seq))?
    else {
        return Ok(false);
    };
    if event.payload_sha256 != digest {
        return Ok(false);
    }
    let durable: DurableReceipt = serde_json::from_str(&event.receipt)
        .map_err(|_| EngineReply::new(Outcome::Corrupt, handle.commit_seq, Value::Null))?;
    validate_receipt_idempotency_key_json(
        &event.receipt,
        &event.kind,
        event.idempotency_key.as_deref(),
    )
    .map_err(|_| EngineReply::new(Outcome::Corrupt, handle.commit_seq, Value::Null))?;
    if durable.reply.payload["common_portability"] != "replay_item" {
        return Ok(false);
    }
    let Some(record_id) = durable.reply.payload["record_id"].as_u64() else {
        return Ok(false);
    };
    let Some(capsule) = handle
        .store
        .capsule(RecordId(record_id))
        .map_err(|error| store_reply(error, handle.commit_seq))?
        .filter(|capsule| capsule.status != CapsuleStatus::Revoked)
    else {
        return Ok(false);
    };
    let provenance: Value = serde_json::from_str(&capsule.provenance)
        .map_err(|_| EngineReply::new(Outcome::Corrupt, handle.commit_seq, Value::Null))?;
    let requested = crate::source_binding::read(
        handle.store.namespace(),
        &request.source,
        &request.provenance,
    )
    .map_err(|reason| invalid(&reason, handle.commit_seq))?;
    let retained =
        crate::source_binding::read(handle.store.namespace(), &capsule.source_id, &provenance)
            .map_err(|reason| {
                EngineReply::new(
                    Outcome::Corrupt,
                    handle.commit_seq,
                    json!({"reason":reason}),
                )
            })?;
    Ok(requested.as_ref().is_some_and(|requested| {
        !requested.is_legacy
            && retained.as_ref().is_some_and(|retained| {
                retained.is_legacy
                    && retained.full_source_id == requested.full_source_id
                    && retained.legacy_source_id == requested.legacy_source_id
            })
    }) && provenance["common_capsule"] == request.provenance["common_capsule"])
}

fn lookup_item_replay(
    handle: &mut NamespaceHandle,
    item: &ReplayItem,
    request: Option<&ObserveRequest>,
    digest: &str,
) -> Result<Option<EngineReply>, EngineReply> {
    if let Some(request) = request
        && let Some(legacy) = legacy_request(handle.store.namespace(), request)
            .map_err(|reason| invalid(&reason, handle.commit_seq))?
    {
        let legacy_digest =
            item_digest(item, &legacy).map_err(|reason| invalid(&reason, handle.commit_seq))?;
        if legacy_item_matches(handle, item, request, &legacy_digest)? {
            return lookup_replay(handle, &item.delivery_key, &legacy_digest);
        }
    }
    lookup_replay(handle, &item.delivery_key, digest)
}

fn lookup_page_replay(
    handle: &mut NamespaceHandle,
    page: &ReplayPage,
    effect: &Value,
    digest: &str,
    deadline: Deadline,
) -> Result<Option<EngineReply>, EngineReply> {
    let Some(event) = handle
        .store
        .event_for_key(&page.key)
        .map_err(|error| store_reply(error, handle.commit_seq))?
    else {
        return Ok(None);
    };
    if event.payload_sha256 == digest {
        return lookup_replay(handle, &page.key, digest);
    }
    let mut legacy_effect = effect.clone();
    let Some(values) = legacy_effect["items"].as_array_mut() else {
        return Err(invalid("missing replay items", handle.commit_seq));
    };
    let mut converted = Vec::new();
    for (item, value) in page.items.iter().zip(values.iter_mut()) {
        if !item.admitted {
            if item.legacy_source.is_some() {
                // The old receipt retained no full-source capsule for this
                // blocked item. A raw alias cannot establish its identity.
                return lookup_replay(handle, &page.key, digest);
            }
            continue;
        }
        let request = replacement_request(&item.observation, deadline)
            .map_err(|reason| invalid(&reason, handle.commit_seq))?;
        let Some(legacy) = legacy_request(handle.store.namespace(), &request)
            .map_err(|reason| invalid(&reason, handle.commit_seq))?
        else {
            continue;
        };
        let legacy_digest =
            item_digest(item, &legacy).map_err(|reason| invalid(&reason, handle.commit_seq))?;
        value["source"] = json!(legacy.source);
        value["observation"] = json!(legacy.payload_sha256);
        if let Some(value) = value.as_object_mut() {
            value.remove("legacy_source");
        }
        converted.push((item, request, legacy_digest));
    }
    let legacy_digest =
        canonical_digest(&legacy_effect).map_err(|reason| invalid(&reason, handle.commit_seq))?;
    if !converted.is_empty() && event.payload_sha256 == legacy_digest {
        for (item, request, item_digest) in converted {
            if !legacy_item_matches(handle, item, &request, &item_digest)? {
                return lookup_replay(handle, &page.key, digest);
            }
        }
        return lookup_replay(handle, &page.key, &legacy_digest);
    }
    lookup_replay(handle, &page.key, digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod checkout_delivery_binding_tests {
    use super::*;

    const CHECKOUT: &str = "6938addeefe9807080133a599de15b680a5b60374369241587b945256786a8e4";
    const PAGE_KEY: &str = "875a9718dd42d619d03023e9a54b4698395934d11f41cbda34eb59d112e0afbc";

    fn body() -> Value {
        json!({"operation_id":"public-operation","idempotency_key":"caller-key",
            "caller_binding":{"version":1,"exact_scope":{
                "profile_id":"profile","project_id":"project","repository_identity":"repository",
                "worktree_identity":"worktree","branch_identity":"master","agent_session_id":"session",
                "resolved_scope_digest":format!("sha256:{}", "ab".repeat(32))}}})
    }

    fn capsule_bytes(bytes: Vec<u8>) -> Value {
        json!({"version":1,"sha256":sha256_hex(&bytes),"bytes":bytes})
    }

    fn capsule(body: &Value) -> Value {
        capsule_bytes(serde_json::to_vec(body).unwrap())
    }

    #[test]
    fn checkout_page_binding_uses_all_caller_fields_and_preserves_legacy_key_shapes() {
        let body = body();
        let scope: ReplayCallerScope =
            serde_json::from_value(body["caller_binding"]["exact_scope"].clone()).unwrap();
        assert_eq!(replay_caller_namespace(&scope, true).unwrap(), CHECKOUT);
        assert_eq!(
            replay_caller_namespace(&scope, false).unwrap(),
            "d3edecaca5ee5a69ae69f74669c509b38d71a10831583941baef6f9ae88bb64b"
        );
        assert!(validate_replay_delivery_capsule(CHECKOUT, PAGE_KEY, &capsule(&body)).is_ok());
        let old_keys = [
            "caller-key".to_owned(),
            sha256_hex(b"caller-key"),
            crate::source_binding::opaque_id(CHECKOUT, b"idempotency-key", "caller-key"),
        ];
        for key in old_keys {
            assert!(validate_replay_delivery_capsule(CHECKOUT, &key, &capsule(&body)).is_err());
            let legacy = json!({"operation_id":"public-operation","idempotency_key":"caller-key"});
            assert!(validate_replay_delivery_capsule(CHECKOUT, &key, &capsule(&legacy)).is_ok());
        }
        for (field, replacement) in [
            ("agent_session_id", json!("another-session")),
            (
                "resolved_scope_digest",
                json!(format!("sha256:{}", "cd".repeat(32))),
            ),
            ("branch_identity", json!("another-branch")),
            ("worktree_identity", json!("another-worktree")),
        ] {
            let mut changed = body.clone();
            changed["caller_binding"]["exact_scope"][field] = replacement;
            assert!(
                validate_replay_delivery_capsule(CHECKOUT, PAGE_KEY, &capsule(&changed)).is_err(),
                "{field}"
            );
        }
        assert!(
            validate_replay_delivery_capsule(&"ab".repeat(32), PAGE_KEY, &capsule(&body)).is_err()
        );
    }

    #[test]
    fn malformed_checkout_bindings_cannot_fall_back_to_legacy_delivery_validation() {
        let body = body();
        let mut variants = Vec::new();
        let mut changed = body.clone();
        changed["caller_binding"]["version"] = json!(2);
        variants.push(changed);
        let mut changed = body.clone();
        changed["caller_binding"]["extra"] = json!(true);
        variants.push(changed);
        let mut changed = body.clone();
        changed["caller_binding"]["exact_scope"]["extra"] = json!(true);
        variants.push(changed);
        let mut changed = body.clone();
        changed["caller_binding"]["exact_scope"]
            .as_object_mut()
            .unwrap()
            .remove("agent_session_id");
        variants.push(changed);
        let mut changed = body.clone();
        changed["caller_binding"] = Value::Null;
        variants.push(changed);
        let mut changed = body.clone();
        changed["extra"] = json!(true);
        variants.push(changed);
        for changed in variants {
            let capsule = capsule(&changed);
            for key in [
                PAGE_KEY.to_owned(),
                "caller-key".to_owned(),
                sha256_hex(b"caller-key"),
                crate::source_binding::opaque_id(CHECKOUT, b"idempotency-key", "caller-key"),
            ] {
                assert!(validate_replay_delivery_capsule(CHECKOUT, &key, &capsule).is_err());
            }
            assert!(decode_replay_delivery_capsule(&capsule).is_err());
        }
        let encoded = serde_json::to_string(&body).unwrap();
        for duplicate in [
            encoded.replacen(
                "\"operation_id\":",
                "\"operation_id\":\"duplicate\",\"operation_id\":",
                1,
            ),
            encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
            encoded.replacen(
                "\"agent_session_id\":\"session\"",
                "\"agent_session_id\":\"session\",\"agent_session_id\":\"session\"",
                1,
            ),
        ] {
            assert_ne!(duplicate, encoded);
            assert!(
                validate_replay_delivery_capsule(
                    CHECKOUT,
                    PAGE_KEY,
                    &capsule_bytes(duplicate.into_bytes())
                )
                .is_err()
            );
        }
        let framed = capsule(&body);
        let item = ReplayItem {
            sequence: 1,
            receipt_digest: "ab".repeat(32),
            delivery_key: "caller-key".to_owned(),
            source: "cd".repeat(32),
            legacy_source: None,
            admitted: true,
            blocked: false,
            observation: json!({"provenance":{"delivery_capsule":capsule(&json!({"operation_id":"old-item","idempotency_key":"caller-key"}))}}),
        };
        assert!(!legacy_page_delivery_capsule_matches_items(
            &framed,
            &[item]
        ));
    }
}
