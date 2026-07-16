use ietf_draft_analyzer::commands::import::cmd_import;
use ietf_draft_analyzer::config::Config;
use ietf_draft_analyzer::db;
use ietf_draft_analyzer::db::rfc_store;
use ietf_draft_analyzer::rfc::fetcher;
use ietf_draft_analyzer::rfc::model::RfcFormat;
use ietf_draft_analyzer::rfc::parser_text;
use ietf_draft_analyzer::rfc::parser_xml;

#[test]
fn real_scitt_draft_preserves_normative_words_and_examples() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("drafts/draft-ietf-scitt-scrapi-09.xml");
    let content = std::fs::read_to_string(path).unwrap();
    let rfc = parser_xml::parse_xml(99006, &content, &fetcher::sha256_hex(&content)).unwrap();

    assert_eq!(rfc.sections.len(), 38);
    assert!(
        rfc.sections
            .iter()
            .filter(|section| section.text.contains("MUST"))
            .count()
            >= 10
    );
    assert!(rfc.sections.iter().any(|section| {
        section
            .text
            .contains("GET /.well-known/scitt-keys HTTP/1.1")
    }));
    assert!(
        rfc.sections
            .iter()
            .any(|section| section.text.contains("Retry-After"))
    );
}

#[test]
fn real_bier_draft_preserves_packet_tables() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("draft-ietf-bier-ping-23.xml");
    let content = std::fs::read_to_string(path).unwrap();
    let rfc = parser_xml::parse_xml(99042, &content, &fetcher::sha256_hex(&content)).unwrap();

    assert_eq!(rfc.sections.len(), 42);
    assert!(
        rfc.sections
            .iter()
            .any(|section| section.text.contains("Value | Description"))
    );
    assert!(
        rfc.sections
            .iter()
            .any(|section| section.text.contains("BIER Echo Request"))
    );
}

#[test]
fn real_plain_text_draft_extracts_title_without_running_headers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("drafts/draft-ietf-6lo-path-aware-semantic-addressing-13.txt");
    let content = std::fs::read_to_string(path).unwrap();
    let rfc = parser_text::parse_text(99003, &content, &fetcher::sha256_hex(&content)).unwrap();

    assert_eq!(
        rfc.title,
        "Path-Aware Semantic Addressing (PASA) for Low power and Lossy Networks"
    );
    assert!(rfc.sections.iter().all(|section| {
        !section
            .text
            .contains("Internet-Draft                    PASA")
    }));
}

#[tokio::test]
async fn html_import_decodes_windows_1252_and_round_trips_through_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mqtt.html");
    let bytes = b"<html><head><meta charset=windows-1252><title>MQTT Standard</title></head>\
<body><p>07 March 2019</p><h1>1 Introduction</h1>\
<p>The TC\x92s Server MUST validate packets [MQTT-1.0.0-1].</p></body></html>";
    std::fs::write(&path, bytes).unwrap();

    let database_path = directory.path().join("analyzer.db");
    let connection = db::open_database(&database_path).await.unwrap();
    cmd_import(
        &connection,
        &Config::default(),
        &path,
        99100,
        Some("mqtt".to_string()),
    )
    .await
    .unwrap();

    let document = rfc_store::get_rfc(&connection, 99100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(document.format, RfcFormat::Html);
    assert!(document.sections[0].text.contains("TC’s Server MUST"));
    assert!(
        document.sections[0]
            .cross_refs
            .iter()
            .any(|xref| xref.target_section.as_deref() == Some("MQTT-1.0.0-1"))
    );
}
