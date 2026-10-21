//! Admission and cleanup share the same conservative unsupported-record policy.

use tracedecay_domain::{
    CanonicalObservationEnvelopeV1, CanonicalObservationFactV1, CanonicalUnknownStateV1,
};

/// Whether this record carries only an unsupported native fact and the rollout
/// context injected by Codex normalization. Diagnostics and useful mixed facts
/// must remain durable even when they have no conversational rendering.
pub fn unsupported_codex_record(envelope: &CanonicalObservationEnvelopeV1) -> bool {
    if envelope.provider().as_str() != "codex"
        || !matches!(
            envelope.native_record_kind(),
            "event_msg" | "response_item" | "turn_context"
        )
    {
        return false;
    }
    let mut unsupported = false;
    for fact in envelope.facts() {
        match fact {
            CanonicalObservationFactV1::Unknown {
                state: CanonicalUnknownStateV1::Unsupported,
                ..
            } => {
                unsupported = true;
            }
            CanonicalObservationFactV1::Session {
                title: None,
                started_at: None,
                ended_at: None,
                profile: None,
                source: Some(source),
                native_source: Some(native_source),
                location_provenance: Some(provenance),
                ..
            } if source == "codex_rollout"
                && native_source == "codex"
                && provenance == "rollout_context" => {}
            _ => return false,
        }
    }
    unsupported
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tracedecay_domain::{
        CanonicalBoundaryKindV1, CanonicalMessageRoleV1, CanonicalObservationEvidenceV1,
        CanonicalObservationRelationsV1, ObservationId, ObservationOrderingDomainV1,
        ObservationSourceRangeV1, ProviderId, SessionId,
    };

    fn envelope(
        provider: &str,
        kind: &str,
        facts: Vec<CanonicalObservationFactV1>,
    ) -> CanonicalObservationEnvelopeV1 {
        CanonicalObservationEnvelopeV1::new(
            ProviderId::new(provider).unwrap(),
            kind,
            ObservationId::new("record.policy").unwrap(),
            CanonicalObservationRelationsV1::new(SessionId::new("session.policy").unwrap()),
            facts,
            CanonicalObservationEvidenceV1::new(
                ObservationOrderingDomainV1::FileBytes,
                ObservationSourceRangeV1::new(0, 10).unwrap(),
            ),
        )
        .unwrap()
    }

    fn unsupported(state: CanonicalUnknownStateV1) -> CanonicalObservationFactV1 {
        CanonicalObservationFactV1::Unknown {
            native_kind: "future_event".into(),
            state,
        }
    }

    fn context() -> CanonicalObservationFactV1 {
        CanonicalObservationFactV1::Session {
            project_path: Some("/project".into()),
            location_path: Some("/project/subdir".into()),
            transcript_path: Some("/rollout.jsonl".into()),
            title: None,
            started_at: None,
            ended_at: None,
            source: Some("codex_rollout".into()),
            native_source: Some("codex".into()),
            profile: None,
            location_provenance: Some("rollout_context".into()),
        }
    }

    #[test]
    fn unsupported_codex_record_requires_only_unsupported_and_context() {
        use CanonicalUnknownStateV1::*;
        for kind in ["event_msg", "response_item", "turn_context"] {
            for facts in [
                vec![unsupported(Unsupported)],
                vec![context(), unsupported(Unsupported)],
            ] {
                assert!(
                    unsupported_codex_record(&envelope("codex", kind, facts)),
                    "{kind}"
                );
            }
        }
        for provider in ["claude", "other"] {
            assert!(!unsupported_codex_record(&envelope(
                provider,
                "event_msg",
                vec![unsupported(Unsupported)]
            )));
        }
        assert!(!unsupported_codex_record(&envelope(
            "codex",
            "session_meta",
            vec![unsupported(Unsupported)]
        )));
        assert!(!unsupported_codex_record(&envelope(
            "codex",
            "event_msg",
            vec![context()]
        )));
        for state in [Absent, Null, Redacted, Unrecoverable, Malformed] {
            assert!(!unsupported_codex_record(&envelope(
                "codex",
                "event_msg",
                vec![unsupported(Unsupported), unsupported(state)]
            )));
        }
        for useful in [
            CanonicalObservationFactV1::Message {
                role: CanonicalMessageRoleV1::User,
                content: json!("keep"),
                model: None,
                timestamp: None,
            },
            CanonicalObservationFactV1::Boundary {
                boundary_kind: CanonicalBoundaryKindV1::SessionStart,
            },
            CanonicalObservationFactV1::ToolInvocation {
                invocation_id: None,
                name: "read".into(),
                arguments: json!({}),
            },
        ] {
            assert!(!unsupported_codex_record(&envelope(
                "codex",
                "event_msg",
                vec![context(), unsupported(Unsupported), useful]
            )));
        }
        let mut meaningful_session = context();
        if let CanonicalObservationFactV1::Session { title, .. } = &mut meaningful_session {
            *title = Some("Retain session metadata".into());
        }
        assert!(!unsupported_codex_record(&envelope(
            "codex",
            "event_msg",
            vec![meaningful_session, unsupported(Unsupported)]
        )));
        let mut foreign_session = context();
        if let CanonicalObservationFactV1::Session {
            location_provenance,
            ..
        } = &mut foreign_session
        {
            *location_provenance = Some("transcript_record".into());
        }
        assert!(!unsupported_codex_record(&envelope(
            "codex",
            "event_msg",
            vec![foreign_session, unsupported(Unsupported)]
        )));
    }
}
