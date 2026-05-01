//! Integration test that fetches a real RFC. Run with:
//! cargo test -- --ignored test_fetch_real
#[tokio::test]
#[ignore]
async fn test_fetch_real_rfc_xml() {
    use rfc_analyzer::config::FetcherConfig;
    use rfc_analyzer::rfc::fetcher::RfcFetcher;
    use rfc_analyzer::rfc::parser_xml;

    let config = FetcherConfig::default();
    let fetcher = RfcFetcher::new(config);
    let result = fetcher.fetch(9293).await.unwrap();
    assert_eq!(result.format, "xml");
    assert!(!result.content.is_empty());

    let rfc = parser_xml::parse_xml(9293, &result.content, &result.content_hash).unwrap();
    assert_eq!(rfc.number.0, 9293);
    assert!(!rfc.title.is_empty());
    assert!(!rfc.sections.is_empty());
    println!("Title: {}", rfc.title);
    println!("Sections: {}", rfc.sections.len());
    println!("References: {}", rfc.references.len());
    for s in rfc.sections.iter().take(5) {
        println!("  {} {} ({} xrefs)", s.number, s.title, s.cross_refs.len());
    }
}
