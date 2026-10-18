//! Independently verified original JSON spans and complete decoded-block counts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    AdmittedCandidate, CandidateLabel, HostDeliveredContext, HostRecallEvidence,
    HostRetrievalError, bytes_digest, exact_tokens, invalid,
};

type Result<T> = std::result::Result<T, HostRetrievalError>;

fn check(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}

fn string(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| invalid("missing evidence string"))
}

fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid("missing evidence integer"))
}

fn array(value: &Value) -> Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("missing evidence array"))
}

fn sum(mut values: impl Iterator<Item = Result<u64>>) -> Result<u64> {
    values.try_fold(0_u64, |total, value| {
        total
            .checked_add(value?)
            .ok_or_else(|| invalid("token sum overflow"))
    })
}

/// Shared numeric domain: exact signed-i64/unsigned-u64 integer lexemes,
/// including bare -0 normalized to integer 0. Fraction/exponent lexemes are
/// finite IEEE-754 binary64. No integer can fall back to a rounded float.
fn numeric_value(lexeme: &str) -> Result<Value> {
    let bytes = lexeme.as_bytes();
    let mut at = usize::from(bytes.first() == Some(&b'-'));
    match bytes.get(at) {
        Some(b'0') => at += 1,
        Some(b'1'..=b'9') => {
            at += 1;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
        }
        _ => return Err(invalid("invalid JSON number")),
    }
    let mut fractional = false;
    if bytes.get(at) == Some(&b'.') {
        fractional = true;
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        check(at > start, "invalid JSON fraction")?;
    }
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        fractional = true;
        at += 1;
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        check(at > start, "invalid JSON exponent")?;
    }
    check(at == bytes.len(), "invalid JSON numeric lexeme")?;
    if fractional {
        let number = lexeme
            .parse::<f64>()
            .map_err(|_| invalid("invalid binary64 number"))?;
        serde_json::Number::from_f64(number)
            .map(Value::Number)
            .ok_or_else(|| invalid("nonfinite JSON number"))
    } else if bytes.first() == Some(&b'-') {
        lexeme
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| invalid("integer JSON lexeme outside shared exact domain"))
    } else {
        lexeme
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| invalid("integer JSON lexeme outside shared exact domain"))
    }
}

#[derive(Debug)]
struct Node {
    start: usize,
    end: usize,
}

/// Positions are bytes in the original, already UTF-8 checked input. Value and
/// member spans are retained separately: member spans include original keys.
struct JsonSpans<'a> {
    text: &'a str,
    at: usize,
    value: Value,
    nodes: BTreeMap<String, Node>,
    members: Vec<(String, usize, usize)>,
}

impl<'a> JsonSpans<'a> {
    fn parse(text: &'a str) -> Result<Self> {
        check(
            text.len() <= 16 * 1024 * 1024,
            "JSON evidence exceeds byte bound",
        )?;
        let mut parser = Self {
            text,
            at: 0,
            value: Value::Null,
            nodes: BTreeMap::new(),
            members: Vec::new(),
        };
        parser.value = parser.read_value("", 0)?;
        parser.space();
        check(parser.at == text.len(), "trailing JSON evidence bytes")?;
        Ok(parser)
    }

    fn byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn space(&mut self) {
        while self
            .byte()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }

    fn read_string(&mut self) -> Result<String> {
        let start = self.at;
        check(self.byte() == Some(b'"'), "JSON string expected")?;
        self.at += 1;
        while let Some(byte) = self.byte() {
            self.at += 1;
            if byte == b'\\' {
                self.at += 1;
            } else if byte == b'"' {
                return serde_json::from_slice(&self.text.as_bytes()[start..self.at])
                    .map_err(|e| invalid(e.to_string()));
            }
        }
        Err(invalid("unterminated JSON string"))
    }

    fn read_value(&mut self, pointer: &str, depth: usize) -> Result<Value> {
        check(depth <= 128, "JSON evidence exceeds depth bound")?;
        self.space();
        let start = self.at;
        let value = match self.byte() {
            Some(b'{') => {
                self.at += 1;
                let mut object = Map::new();
                self.space();
                if self.byte() != Some(b'}') {
                    loop {
                        self.space();
                        let member_start = self.at;
                        let key = self.read_string()?;
                        check(!object.contains_key(&key), "duplicate JSON key")?;
                        self.space();
                        check(self.byte() == Some(b':'), "JSON colon expected")?;
                        self.at += 1;
                        let child =
                            format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                        object.insert(key, self.read_value(&child, depth + 1)?);
                        self.members.push((child, member_start, self.at));
                        self.space();
                        if self.byte() != Some(b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                check(self.byte() == Some(b'}'), "JSON object end expected")?;
                self.at += 1;
                Value::Object(object)
            }
            Some(b'[') => {
                self.at += 1;
                let mut values = Vec::new();
                self.space();
                if self.byte() != Some(b']') {
                    loop {
                        values.push(
                            self.read_value(&format!("{pointer}/{}", values.len()), depth + 1)?,
                        );
                        self.space();
                        if self.byte() != Some(b',') {
                            break;
                        }
                        self.at += 1;
                    }
                }
                check(self.byte() == Some(b']'), "JSON array end expected")?;
                self.at += 1;
                Value::Array(values)
            }
            Some(b'"') => Value::String(self.read_string()?),
            Some(_) => {
                while self.byte().is_some_and(|b| {
                    !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
                }) {
                    self.at += 1;
                }
                match &self.text[start..self.at] {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    "null" => Value::Null,
                    lexeme => numeric_value(lexeme)?,
                }
            }
            None => return Err(invalid("missing JSON value")),
        };
        self.nodes.insert(
            pointer.to_owned(),
            Node {
                start,
                end: self.at,
            },
        );
        Ok(value)
    }

    fn verify(&self, span: &Value, member: bool) -> Result<&'a str> {
        let pointer = string(&span["pointer"])?;
        let node = self
            .nodes
            .get(pointer)
            .ok_or_else(|| invalid("unknown JSON pointer"))?;
        let (start, end) = if member {
            let (_, start, end) = self
                .members
                .iter()
                .find(|(key, _, _)| key == pointer)
                .ok_or_else(|| invalid("unknown JSON member"))?;
            (*start, *end)
        } else {
            (node.start, node.end)
        };
        let text = self
            .text
            .get(start..end)
            .ok_or_else(|| invalid("non-UTF8 JSON span boundary"))?;
        check(
            number(&span["start"])? == start as u64
                && number(&span["end"])? == end as u64
                && string(&span["sha256"])? == bytes_digest(text)
                && self.value.pointer(pointer) == Some(&span["value"]),
            "original JSON span, digest, or pointer mismatch",
        )?;
        Ok(text)
    }

    fn top_members(&self) -> Vec<&str> {
        self.members
            .iter()
            .filter_map(|(pointer, _, _)| {
                pointer
                    .strip_prefix('/')
                    .filter(|rest| !rest.contains('/'))
                    .map(|_| pointer.as_str())
            })
            .collect()
    }
}

fn artifact(value: &Value) -> Result<JsonSpans<'_>> {
    let text = string(&value["utf8"])?;
    check(
        !string(&value["artifact_path"])?.is_empty()
            && number(&value["byte_length"])? == text.len() as u64
            && string(&value["sha256"])? == bytes_digest(text),
        "raw artifact bytes/digest mismatch",
    )?;
    JsonSpans::parse(text)
}

fn block_index(value: &Value) -> Result<usize> {
    usize::try_from(number(&value["content_index"])?).map_err(|_| invalid("content index overflow"))
}

fn unresolved_label(label: CandidateLabel) -> bool {
    matches!(
        label,
        CandidateLabel::Missing | CandidateLabel::Indeterminate | CandidateLabel::Unverifiable
    )
}

pub(super) fn unresolved(delivery: &HostDeliveredContext) -> bool {
    delivery.tool_result.as_ref().is_some_and(|data| {
        data["candidates"].as_array().is_some_and(|candidates| {
            candidates.iter().any(|c| {
                c["final_join"]["status"] != "bound"
                    || c["annotation_presentation_sha256"].is_null()
                    || c["annotation_advisory_review_sha256"].is_null()
            }) || (candidates.is_empty()
                && data["advisory_blocks"].as_array().is_some_and(|blocks| {
                    blocks
                        .iter()
                        .any(|b| b["text"].as_str().is_some_and(|text| !text.is_empty()))
                }))
        })
    })
}

pub(super) fn validate(
    recall: &HostRecallEvidence,
    delivery: &HostDeliveredContext,
    lane: &str,
) -> Result<Vec<AdmittedCandidate>> {
    let data = delivery
        .tool_result
        .as_ref()
        .ok_or_else(|| invalid("missing ToolResult evidence"))?;
    check(
        delivery.final_text.is_empty()
            && delivery.final_sha256.is_empty()
            && delivery.sections.is_empty()
            && delivery.candidates.is_empty()
            && data["representation"] == "tool_result_v1"
            && data.get("final_text").is_none()
            && data.get("final_sha256").is_none()
            && data.get("sections").is_none(),
        "mixed delivery representations",
    )?;
    check(
        delivery.tokenizer_identity == "tiktoken.o200k_base"
            && delivery.tokenizer_revision == "tiktoken-rs-0.12"
            && data["tokenizer"]["identity"] == delivery.tokenizer_identity
            && data["tokenizer"]["revision"] == delivery.tokenizer_revision,
        "ToolResult tokenizer mismatch",
    )?;
    check(
        data["model_input_tokens"]["status"] == "unmeasured"
            && !string(&data["model_input_tokens"]["reason"])?.is_empty(),
        "complete model input remains unmeasured",
    )?;
    let carrier = artifact(&data["raw_carrier"])?;
    let projection = &data["projection"];
    check(
        carrier.value == projection["result"],
        "raw ToolResult/projection disagreement",
    )?;
    let content = array(&carrier.value["content"])?;
    let blocks = array(&data["text_blocks"])?;
    let projected_blocks = array(&projection["text_blocks"])?;
    let actual_text = content
        .iter()
        .enumerate()
        .filter(|(_, b)| b["type"] == "text")
        .collect::<Vec<_>>();
    check(
        blocks.len() == actual_text.len() && blocks.len() == projected_blocks.len(),
        "missing decoded blocks",
    )?;
    let mut total_tokens = 0_u64;
    for (((index, actual), block), projected) in
        actual_text.iter().zip(blocks).zip(projected_blocks)
    {
        let text = string(&block["text"])?;
        check(
            block_index(block)? == *index
                && block_index(projected)? == *index
                && actual["text"] == text
                && projected["text"] == text
                && number(&block["utf8_bytes"])? == text.len() as u64
                && string(&block["sha256"])? == bytes_digest(text),
            "reordered or rewritten decoded block",
        )?;
        let tokens = exact_tokens(text)?;
        check(
            number(&block["tokens"])? == tokens,
            "decoded block tokenizer recount mismatch",
        )?;
        total_tokens = total_tokens
            .checked_add(tokens)
            .ok_or_else(|| invalid("full block count overflow"))?;
    }
    check(
        total_tokens == delivery.final_tokens
            && number(&data["final_tokens"])? == total_tokens
            && total_tokens <= 128_000,
        "full decoded block token sum exceeds quota or disagrees",
    )?;
    let payload_index = usize::try_from(number(&projection["payload_content_index"])?)
        .map_err(|_| invalid("payload index overflow"))?;
    let payload = blocks
        .iter()
        .find(|b| b["content_index"].as_u64() == Some(payload_index as u64))
        .ok_or_else(|| invalid("missing payload block"))?;
    let parser = JsonSpans::parse(string(&payload["text"])?)?;
    check(
        parser.value.is_object(),
        "ToolResult v1 requires an object JSON payload",
    )?;
    let canonical = array(&data["canonical_spans"])?;
    let observed = array(&projection["host_evidence"])?;
    let expected = parser
        .top_members()
        .into_iter()
        .filter(|p| *p != "/advisory_provider_memory")
        .collect::<Vec<_>>();
    check(
        canonical.len() == expected.len() && canonical.len() == observed.len(),
        "canonical coverage mismatch",
    )?;
    let mut observed_by_pointer = BTreeMap::new();
    for projected in observed {
        check(
            observed_by_pointer
                .insert(string(&projected["pointer"])?, projected)
                .is_none(),
            "duplicate canonical projection",
        )?;
    }
    let mut canonical_text = String::new();
    for (span, expected) in canonical.iter().zip(expected) {
        check(
            string(&span["pointer"])? == expected,
            "canonical member order mismatch",
        )?;
        let projected = observed_by_pointer
            .get(expected)
            .ok_or_else(|| invalid("canonical projection missing"))?;
        let text = parser.verify(span, true)?;
        check(
            span["text"] == text
                && block_index(span)? == payload_index
                && projected["kind"] == "json_member"
                && projected["value"] == span["value"]
                && projected["authority"] == span["authority"]
                && projected["section"] == span["section"]
                && span["source_refs"].is_array(),
            "canonical source/projection mismatch",
        )?;
        canonical_text.push_str(text);
    }
    check(
        string(&data["canonical_sha256"])? == bytes_digest(&canonical_text)
            && number(&data["canonical_tokens"])? == exact_tokens(&canonical_text)?
            && number(&data["canonical_tokens"])? == delivery.canonical_tokens,
        "canonical byte/token mismatch",
    )?;
    let mut syntax = Vec::new();
    let mut cursor = 0;
    let mut ranges = Vec::new();
    for pointer in parser.top_members() {
        let (_, start, end) = parser
            .members
            .iter()
            .find(|(key, _, _)| key == pointer)
            .ok_or_else(|| invalid("top-level member missing"))?;
        ranges.push((*start, *end));
    }
    ranges.push((parser.text.len(), parser.text.len()));
    for (start, end) in ranges {
        if start > cursor {
            let text = parser
                .text
                .get(cursor..start)
                .ok_or_else(|| invalid("non-UTF8 syntax boundary"))?;
            check(
                text.bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'{' | b'}' | b',')),
                "unattributed substantive payload bytes",
            )?;
            syntax.push(serde_json::json!({"content_index":payload_index,"start":cursor,"end":start,"text":text,"sha256":bytes_digest(text)}));
        }
        cursor = end;
    }
    check(
        data["payload_syntax_spans"] == Value::Array(syntax),
        "payload delimiter partition mismatch",
    )?;
    let advisory_value = parser.value.get("advisory_provider_memory");
    if let Some(value) = advisory_value {
        check(value.is_object(), "invalid advisory object")?;
        check(
            projection["advisory"]["kind"] == "json_member"
                && projection["advisory"]["pointer"] == "/advisory_provider_memory"
                && projection["advisory"]["value"] == *value,
            "advisory projection mismatch",
        )?;
    } else {
        check(
            projection["advisory"].is_null(),
            "unexpected advisory projection",
        )?;
    }
    let spans = array(&data["advisory_spans"])?;
    check(
        spans.len() == blocks.len().saturating_sub(1) + usize::from(advisory_value.is_some()),
        "advisory span coverage mismatch",
    )?;
    let advisory_blocks = array(&data["advisory_blocks"])?;
    check(
        advisory_blocks.len() == blocks.len(),
        "advisory block coverage mismatch",
    )?;
    let mut expected_order = Vec::new();
    let mut advisory_tokens = 0_u64;
    let mut review = Sha256::new();
    for (block, projected) in blocks.iter().zip(advisory_blocks) {
        let index = block_index(block)?;
        let matching = spans
            .iter()
            .filter(|s| s["content_index"].as_u64() == Some(index as u64))
            .collect::<Vec<_>>();
        let mut text = String::new();
        if index == payload_index {
            if advisory_value.is_some() {
                check(
                    matching.len() == 1
                        && matching[0]["pointer"] == "/advisory_provider_memory"
                        && matching[0]["attribution"] == "observed_advisory_member",
                    "missing full advisory member",
                )?;
                text.push_str(parser.verify(matching[0], true)?);
            } else {
                check(matching.is_empty(), "unexpected advisory span")?;
            }
        } else {
            check(matching.len() == 1, "missing conservative notice span")?;
            let span = matching[0];
            let original = string(&block["text"])?;
            check(
                span["attribution"] == "unclassified_text"
                    && span["pointer"].is_null()
                    && number(&span["start"])? == 0
                    && number(&span["end"])? == original.len() as u64
                    && span["sha256"] == block["sha256"]
                    && span["value"] == original,
                "notice original span mismatch",
            )?;
            text.push_str(original);
        }
        for span in matching {
            expected_order.push(span);
        }
        check(
            block_index(projected)? == index
                && projected["text"] == text
                && string(&projected["sha256"])? == bytes_digest(&text),
            "advisory per-block projection mismatch",
        )?;
        let tokens = exact_tokens(&text)?;
        check(
            number(&projected["tokens"])? == tokens,
            "advisory tokenizer recount mismatch",
        )?;
        advisory_tokens = advisory_tokens
            .checked_add(tokens)
            .ok_or_else(|| invalid("advisory count overflow"))?;
        review.update((text.len() as u64).to_be_bytes());
        review.update(text.as_bytes());
    }
    check(
        expected_order.into_iter().eq(spans.iter()),
        "advisory span block order mismatch",
    )?;
    let review_sha256 = review
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    check(
        data["advisory_review_sha256"] == review_sha256
            && advisory_tokens == delivery.advisory_tokens
            && number(&data["advisory_tokens"])? == advisory_tokens
            && advisory_tokens <= 8_192,
        "advisory review digest/count/quota mismatch",
    )?;
    let emitted = match advisory_value.and_then(|v| v.get("candidates")) {
        Some(v) => array(v)?,
        None => &[],
    };
    let candidates = array(&data["candidates"])?;
    check(
        candidates.len() == emitted.len(),
        "emitted candidate coverage mismatch",
    )?;
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for (position, (evidence, emitted)) in candidates.iter().zip(emitted).enumerate() {
        let candidate: AdmittedCandidate = serde_json::from_value(evidence["candidate"].clone())
            .map_err(|e| invalid(e.to_string()))?;
        check(
            candidate.request_id == recall.request_id
                && evidence["candidate_ref"] == candidate.candidate_ref
                && seen.insert(candidate.candidate_ref.clone()),
            "candidate request/reference/uniqueness mismatch",
        )?;
        let span = &evidence["presentation_span"];
        check(
            span["pointer"] == format!("/advisory_provider_memory/candidates/{position}"),
            "candidate presentation order mismatch",
        )?;
        parser.verify(span, false)?;
        let body = string(&evidence["content"])?;
        check(
            emitted["content"] == body
                && evidence["content_sha256"] == bytes_digest(body)
                && evidence["presentation_sha256"] == span["sha256"]
                && evidence["sources"].is_array()
                && !string(&evidence["annotation_reason"])?.is_empty(),
            "candidate body/presentation/annotation mismatch",
        )?;
        let has_annotation = !evidence["annotation_presentation_sha256"].is_null()
            || !evidence["annotation_advisory_review_sha256"].is_null();
        if has_annotation {
            check(
                evidence["presentation_review"]
                    == serde_json::json!({"candidate_metadata":true,"shared_text":true,"source_attribution":true,"prohibited_claims":true})
                    && evidence["prohibited_claims_absent"].is_boolean(),
                "missing explicit full presentation assessment",
            )?;
            if candidate.label == CandidateLabel::Useful {
                check(
                    evidence["prohibited_claims_absent"] == true,
                    "useful presentation contains prohibited claims",
                )?;
            }
            check(
                evidence["annotation_presentation_sha256"] == evidence["presentation_sha256"]
                    && evidence["annotation_advisory_review_sha256"]
                        == data["advisory_review_sha256"],
                "full presentation annotation digest mismatch",
            )?;
        } else {
            check(
                candidate.label == CandidateLabel::Missing,
                "reviewed label lacks full presentation digests",
            )?;
        }
        match string(&evidence["final_join"]["status"])? {
            "bound" => validate_bound_join(data, evidence, emitted)?,
            "unresolved" => check(
                unresolved_label(candidate.label)
                    && !string(&evidence["final_join"]["reason"])?.is_empty(),
                "unresolved join carries a determinate label or no reason",
            )?,
            _ => return Err(invalid("unknown final-output join")),
        }
        if candidate.label == CandidateLabel::Useful {
            check(
                !array(&evidence["source_ids"])?.is_empty()
                    && !array(&evidence["required_fact_refs"])?.is_empty()
                    && !body.is_empty(),
                "useful presentation lacks source-grounded body evidence",
            )?;
        }
        result.push(candidate);
    }
    let body_tokens = sum(candidates
        .iter()
        .map(|c| exact_tokens(string(&c["content"])?)))?;
    check(
        number(&data["candidate_body_tokens"])? == body_tokens
            && delivery.candidate_body_tokens == body_tokens,
        "candidate body tokenizer recount mismatch",
    )?;
    if lane == "no_memory" || lane == "explicit_documentation" {
        check(
            advisory_value.is_none() && emitted.is_empty(),
            "control lane carries provider advisory evidence",
        )?;
    }
    Ok(result)
}

fn validate_bound_join(data: &Value, evidence: &Value, emitted: &Value) -> Result<()> {
    let observed = &emitted["provenance_evidence"]["recall"];
    let retained = &data["retained_trace"];
    check(
        retained["status"] == "observed",
        "retained trace unavailable",
    )?;
    let artifact = artifact(&retained["artifact"])?;
    let trace = &artifact.value;
    let advisory = &data["projection"]["advisory"]["value"];
    let correlation = &advisory["recall_trace"];
    check(
        retained["correlation"] == *correlation
            && observed["trace_ref"] == correlation["trace_ref"]
            && trace["request_id"] == correlation["request_id"]
            && trace["provider_id"] == retained["provider_id"]
            && trace["provider_id"] == advisory["provider_id"]
            && number(&trace["registration_revision"])?
                == number(&retained["registration_revision"])?
            && trace["registration_revision"] == advisory["registration_revision"]
            && retained["delivery_scope"].is_object()
            && retained["store_evidence"].is_object()
            && retained["daemon_identity"].is_object(),
        "retained request/provider/revision/scope mismatch",
    )?;
    let trace_ref = string(&observed["trace_ref"])?;
    let (scope, trace_id) = trace_ref
        .strip_prefix("recall-trace-v1:")
        .and_then(|s| s.split_once(':'))
        .ok_or_else(|| invalid("invalid trace locator"))?;
    let is_sha = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    check(
        is_sha(scope) && is_sha(trace_id) && trace["trace_id"] == trace_id,
        "retained trace identity mismatch",
    )?;
    let item_ref = string(&observed["item_ref"])?;
    let decimal = item_ref
        .strip_prefix("recall-item-v1:")
        .ok_or_else(|| invalid("invalid item locator"))?;
    let rank = decimal
        .parse::<usize>()
        .map_err(|_| invalid("invalid item rank"))?;
    check(decimal == rank.to_string(), "noncanonical item locator")?;
    let items = array(&trace["items"])?;
    check(
        number(&trace["requested_count"])? == items.len() as u64 && rank < items.len(),
        "retained trace partition mismatch",
    )?;
    const STAGES: &[&str] = &[
        "denied",
        "normalization_unavailable",
        "selection_unavailable",
        "deduplicated",
        "budget_excluded",
        "host_withheld",
        "selected",
        "pack_excluded",
        "injected",
    ];
    for (position, item) in items.iter().enumerate() {
        check(
            number(&item["provider_rank"])? == position as u64
                && STAGES.contains(&string(&item["stage"])?),
            "retained trace stage/rank mismatch",
        )?;
    }
    let row = &items[rank];
    let join = &evidence["final_join"];
    check(
        join["trace_ref"] == observed["trace_ref"]
            && join["item_ref"] == observed["item_ref"]
            && number(&join["provider_rank"])? == rank as u64
            && join["retained_candidate_id"] == row["candidate_id"]
            && evidence["candidate_ref"] == row["candidate_id"]
            && join["compiled_stage"] == row["stage"]
            && row["stage"] == "injected",
        "final output/compiled retained item join mismatch",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Measured;
    use serde_json::json;

    fn fixture() -> Result<HostDeliveredContext> {
        // This is development-only text. Its stored counts are placeholders;
        // every test independently replaces them with the pinned tokenizer.
        let mut delivery: HostDeliveredContext =
            serde_json::from_str(include_str!("../../tests/fixtures/tool_result_v1.json"))
                .map_err(|e| invalid(e.to_string()))?;
        let data = delivery
            .tool_result
            .as_mut()
            .ok_or_else(|| invalid("test fixture missing tool result"))?;
        let blocks = data["text_blocks"]
            .as_array_mut()
            .ok_or_else(|| invalid("test blocks"))?;
        for block in blocks.iter_mut() {
            block["tokens"] = json!(exact_tokens(string(&block["text"])?)?);
        }
        delivery.final_tokens = sum(blocks.iter().map(|b| number(&b["tokens"])))?;
        data["final_tokens"] = json!(delivery.final_tokens);
        let blocks = data["advisory_blocks"]
            .as_array_mut()
            .ok_or_else(|| invalid("test advisory blocks"))?;
        for block in blocks.iter_mut() {
            block["tokens"] = json!(exact_tokens(string(&block["text"])?)?);
        }
        delivery.advisory_tokens = sum(blocks.iter().map(|b| number(&b["tokens"])))?;
        data["advisory_tokens"] = json!(delivery.advisory_tokens);
        let canonical = array(&data["canonical_spans"])?
            .iter()
            .map(|s| string(&s["text"]))
            .collect::<Result<Vec<_>>>()?
            .join("");
        delivery.canonical_tokens = exact_tokens(&canonical)?;
        data["canonical_tokens"] = json!(delivery.canonical_tokens);
        delivery.candidate_body_tokens = sum(array(&data["candidates"])?
            .iter()
            .map(|c| exact_tokens(string(&c["content"])?)))?;
        data["candidate_body_tokens"] = json!(delivery.candidate_body_tokens);
        Ok(delivery)
    }

    fn recall() -> HostRecallEvidence {
        HostRecallEvidence {
            scenario_id: "development".into(),
            request_id: "q".into(),
            delivery: None,
            host_latency_micros: Measured::Unmeasured {
                reason: "no host was executed".into(),
            },
        }
    }

    #[test]
    fn strict_parser_preserves_escaped_utf8_and_member_bytes() -> Result<()> {
        let parser = JsonSpans::parse(r#"{ "é/~": ["café", "\uD83D\uDE00"], "b" : true }"#)?;
        let node = parser
            .nodes
            .get("/é~1~0/1")
            .ok_or_else(|| invalid("test pointer missing"))?;
        let text = parser
            .text
            .get(node.start..node.end)
            .ok_or_else(|| invalid("test boundary"))?;
        let span = json!({"pointer":"/é~1~0/1", "start":node.start, "end":node.end,
            "sha256":bytes_digest(text), "value":"😀"});
        assert_eq!(r#""\uD83D\uDE00""#, parser.verify(&span, false)?);
        assert_eq!(vec!["/é~1~0", "/b"], parser.top_members());
        Ok(())
    }

    #[test]
    fn strict_parser_rejects_duplicate_decoded_keys_and_invalid_json() {
        for text in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"a":NaN}"#,
            "1e9999",
            r#""\ud800""#,
            "01",
            "true false",
            "[1,]",
            "{\"a\":1,}",
        ] {
            assert!(
                JsonSpans::parse(text).is_err(),
                "invalid text accepted: {text}"
            );
        }
    }

    #[test]
    fn integer_boundaries_and_bare_negative_zero_have_exact_shared_semantics() -> Result<()> {
        let parser = JsonSpans::parse(
            "[-9223372036854775808,9223372036854775807,9223372036854775808,18446744073709551615,-0,0]",
        )?;
        assert_eq!(
            json!([i64::MIN, i64::MAX, i64::MAX as u64 + 1, u64::MAX, 0, 0]),
            parser.value
        );
        let node = parser
            .nodes
            .get("/4")
            .ok_or_else(|| invalid("test zero pointer"))?;
        let mut span = json!({"pointer":"/4","start":node.start,"end":node.end,"sha256":bytes_digest("-0"),"value":0});
        assert_eq!("-0", parser.verify(&span, false)?);
        span["value"] = json!(-0.0);
        assert!(parser.verify(&span, false).is_err());
        let node = parser
            .nodes
            .get("/3")
            .ok_or_else(|| invalid("test maximum pointer"))?;
        let wrong = json!({"pointer":"/3","start":node.start,"end":node.end,"sha256":bytes_digest("18446744073709551615"),"value":u64::MAX-1});
        assert!(parser.verify(&wrong, false).is_err());
        Ok(())
    }

    #[test]
    fn adjacent_overflow_integer_lexemes_cannot_collapse_to_one_float() {
        for lexeme in [
            "-9223372036854775809",
            "18446744073709551616",
            "18446744073709551617",
        ] {
            assert!(JsonSpans::parse(&format!("{{\"number\":{lexeme}}}")).is_err());
        }
    }

    #[test]
    fn fractional_and_exponent_lexemes_use_finite_binary64() -> Result<()> {
        let parser = JsonSpans::parse(
            "[1.0,1e0,-0.0,-0e0,18446744073709551616.0,1.7976931348623157e308,5e-324,1e-9999]",
        )?;
        assert!(
            array(&parser.value)?
                .iter()
                .all(|value| value.as_number().is_some_and(serde_json::Number::is_f64))
        );
        assert_eq!(Some(5e-324_f64), parser.value[6].as_f64());
        assert_eq!(Some(0.0), parser.value[7].as_f64());
        for lexeme in ["1e309", "-1e309", "01", "1.", "1e", "1.0.0", "+1"] {
            assert!(JsonSpans::parse(lexeme).is_err());
        }
        Ok(())
    }

    #[test]
    fn same_value_at_another_pointer_is_not_original_span_evidence() -> Result<()> {
        let parser = JsonSpans::parse(r#"{"a":"same","b":"same"}"#)?;
        let node = parser
            .nodes
            .get("/b")
            .ok_or_else(|| invalid("test pointer"))?;
        let span = json!({"pointer":"/a","start":node.start,"end":node.end,
            "sha256":bytes_digest(r#""same""#),"value":"same"});
        assert!(parser.verify(&span, false).is_err());
        Ok(())
    }

    #[test]
    fn tool_result_recounts_full_blocks_and_binds_original_rank_after_aliasing() -> Result<()> {
        let delivery = fixture()?;
        let candidates = validate(&recall(), &delivery, "provider:development.provider")?;
        assert_eq!("original-provider-id", candidates[0].candidate_ref);
        assert!(!unresolved(&delivery));
        // Decoded blocks are separate observations; merging them can alter BPE.
        assert_ne!(exact_tokens("a")? + exact_tokens("b")?, exact_tokens("ab")?);
        Ok(())
    }

    #[test]
    fn self_consistent_producer_counts_cannot_replace_independent_recount() -> Result<()> {
        for advisory in [false, true] {
            let mut delivery = fixture()?;
            let data = delivery
                .tool_result
                .as_mut()
                .ok_or_else(|| invalid("test tool result"))?;
            if advisory {
                data["advisory_blocks"][0]["tokens"] = json!(0);
                delivery.advisory_tokens -= 1;
                data["advisory_tokens"] = json!(delivery.advisory_tokens);
            } else {
                data["text_blocks"][0]["tokens"] = json!(0);
                delivery.final_tokens -= 1;
                data["final_tokens"] = json!(delivery.final_tokens);
            }
            assert!(validate(&recall(), &delivery, "provider:development.provider").is_err());
        }
        Ok(())
    }

    #[test]
    fn body_digest_does_not_authorize_unreviewed_candidate_metadata() -> Result<()> {
        let mut delivery = fixture()?;
        let data = delivery
            .tool_result
            .as_mut()
            .ok_or_else(|| invalid("test tool result"))?;
        data["candidates"][0]["annotation_presentation_sha256"] =
            data["candidates"][0]["content_sha256"].clone();
        assert!(validate(&recall(), &delivery, "provider:development.provider").is_err());
        Ok(())
    }

    #[test]
    fn absent_final_binding_is_unresolved_even_when_body_matches() -> Result<()> {
        let mut delivery = fixture()?;
        let data = delivery
            .tool_result
            .as_mut()
            .ok_or_else(|| invalid("test tool result"))?;
        data["candidates"][0]["final_join"] =
            json!({"status":"unresolved","reason":"no actual retained locator"});
        assert!(validate(&recall(), &delivery, "provider:development.provider").is_err());
        let data = delivery
            .tool_result
            .as_mut()
            .ok_or_else(|| invalid("test tool result"))?;
        data["candidates"][0]["candidate"]["label"] = json!("indeterminate");
        assert_eq!(
            CandidateLabel::Indeterminate,
            validate(&recall(), &delivery, "provider:development.provider")?[0].label
        );
        assert!(unresolved(&delivery));
        Ok(())
    }

    #[test]
    fn compiled_stage_and_control_rank_are_separate_from_final_bytes() -> Result<()> {
        for (field, value) in [
            ("compiled_stage", json!("selected")),
            ("provider_rank", json!(1)),
            ("item_ref", json!("recall-item-v1:00")),
        ] {
            let mut delivery = fixture()?;
            let data = delivery
                .tool_result
                .as_mut()
                .ok_or_else(|| invalid("test tool result"))?;
            data["candidates"][0]["final_join"][field] = value;
            assert!(validate(&recall(), &delivery, "provider:development.provider").is_err());
        }
        Ok(())
    }

    #[test]
    fn controls_cannot_claim_provider_json_as_documentation_or_no_memory() -> Result<()> {
        let delivery = fixture()?;
        for lane in ["no_memory", "explicit_documentation"] {
            assert!(validate(&recall(), &delivery, lane).is_err());
        }
        Ok(())
    }
}
