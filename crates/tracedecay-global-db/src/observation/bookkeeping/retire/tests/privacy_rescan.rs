//! Integration regressions for the registered caller, not the LCM CAS helper.
//! The caller is outside B2's exclusive edit ownership; keep failures visible
//! until that integration uses exact stored bytes and receipt-normalizing CAS.

use super::*;
use tracedecay_lcm::{payload, raw};
use tracedecay_sessions::runtime::SessionMessageRecord;

async fn rescan_reference_backed_message(unavailable: bool) {
    let harness = RegisteredGlobalDbHarness::open("privacy-reference-backed").await;
    let db = &harness.registered;
    let root = db.db_path().parent().unwrap().to_path_buf();
    let writer = db.writer_connection().unwrap();
    writer.execute("INSERT INTO sessions(provider,session_id,project_key,project_path) VALUES ('cursor','receipt-rescan','/tmp/project','/tmp/project')", ()).await.unwrap();
    let text = if unavailable {
        (0..20_000)
            .map(|line| format!("ordinary captured tool output line {line}\n"))
            .collect()
    } else {
        "ordinary captured inline body".to_owned()
    };
    db.lcm_ingest_raw_message(
        &root,
        &SessionMessageRecord {
            provider: "cursor".into(),
            session_id: "receipt-rescan".into(),
            message_id: "reference-backed".into(),
            role: if unavailable { "tool" } else { "user" }.into(),
            timestamp: Some(1),
            ordinal: 0,
            text,
            kind: None,
            model: None,
            tool_names: None,
            source_path: None,
            source_offset: None,
            metadata_json: Some(
                serde_json::json!({"provider_note": "historical metadata"}).to_string(),
            ),
        },
    )
    .await
    .unwrap();
    let mut rows = writer.query("SELECT metadata_json,payload_ref FROM lcm_raw_messages WHERE message_id='reference-backed'", ()).await.unwrap();
    let row = rows.next().await.unwrap().unwrap();
    let stored: String = row.get(0).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
    assert!(
        stored["ingest_protection"]["sanitization_receipt"]["lcm_receipt_v1"].is_string(),
        "fixture must pass through the real receipt-normalizing writer"
    );
    let payload_ref: Option<String> = row.get(1).unwrap();
    drop(rows);
    if unavailable {
        let reference = payload_ref.expect("large tool body must actually be externalized");
        std::fs::remove_file(payload::payload_dir(&root).join(reference)).unwrap();
    }
    // Simulate provider metadata written under older detector rules, without
    // replacing the normalized receipts produced by canonical ingestion.
    let secret = ["sk-at-rest-rescan-secret-", "1234567890abcdef"].concat();
    writer.execute("UPDATE lcm_raw_messages SET metadata_json=json_set(metadata_json,'$.provider_note',?1) WHERE message_id='reference-backed'", params![format!("api_key={secret}")]).await.unwrap();
    let outcome = db.lcm_privacy_rescan_raw_messages().await
        .expect("registered privacy rescan must remediate reference-backed metadata using exact stored CAS bytes");
    let crate::LcmPrivacyRescanOutcomeV1::Completed(receipt) = outcome else {
        panic!("first pass must complete")
    };
    assert_eq!(receipt.scanned_rows, 1);
    assert_eq!(receipt.remediated_rows, 1);
    assert_eq!(receipt.unavailable_payload_rows, u64::from(unavailable));
    let snapshot = db.lcm_read_snapshot().await.unwrap();
    let message = raw::load_raw_message_by_identity(
        &snapshot,
        "cursor",
        "receipt-rescan",
        "reference-backed",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!message.metadata_json.unwrap().contains(&secret));
    let mut rows = snapshot
        .query(
            "SELECT metadata_json FROM lcm_raw_messages WHERE message_id='reference-backed'",
            (),
        )
        .await
        .unwrap();
    let metadata: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert!(!metadata.contains(&secret));
    let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    for field in ["sanitization_receipt", "metadata_sanitization_receipt"] {
        assert!(
            metadata["ingest_protection"][field]["lcm_receipt_v1"].is_string(),
            "rescan replacements must remain receipt-normalized"
        );
    }
    assert_eq!(
        db.lcm_privacy_rescan_raw_messages().await.unwrap(),
        crate::LcmPrivacyRescanOutcomeV1::AlreadyCurrent
    );
}

#[asupersync::test]
async fn reference_backed_privacy_rescan_remediates_ingested_inline_metadata() {
    rescan_reference_backed_message(false).await;
}

#[asupersync::test]
async fn reference_backed_privacy_rescan_remediates_unavailable_external_metadata() {
    rescan_reference_backed_message(true).await;
}
