use crate::error::{Result, RfcAnalyzerError};
use crate::rfc::model::*;
use crate::rfc::text::TextAccumulator;
use chrono::NaiveDate;
use regex::Regex;
use scraper::{ElementRef, Html, Node, Selector};
use std::collections::HashSet;
use std::sync::LazyLock;

static HEADING_NUMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((?:\d+\.)*\d+|[A-Z](?:\.\d+)*)[\.\s]+(.+)$").expect("valid heading regex")
});
static MQTT_STATEMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[(MQTT-\d+(?:\.\d+){2}-\d+)\]").expect("valid normative statement regex")
});
static RFC_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)rfc[^0-9]{0,8}(\d{3,5})").expect("valid RFC link regex"));
static HTML_DATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})\b",
    )
    .expect("valid HTML date regex")
});

/// Parse an HTML standard into the analyzer's normalized document model.
///
/// Headings delimit sections, while paragraphs, inline markup, preformatted
/// examples, and tables are flattened into readable section text. This works
/// with both modern semantic HTML and older Microsoft Word exports such as the
/// OASIS MQTT 5.0 specification.
pub fn parse_html(document_number: u32, content: &str, content_hash: &str) -> Result<Rfc> {
    let document = Html::parse_document(content);
    let title = document_title(&document);
    let date = extract_date(content);
    let status = if title.to_lowercase().contains("standard")
        || content
            .get(..content.len().min(50_000))
            .is_some_and(|prefix| prefix.to_lowercase().contains("oasis standard"))
    {
        RfcStatus::Standard
    } else {
        RfcStatus::Unknown
    };

    let anchor_selector = Selector::parse("a[name], a[id]")
        .map_err(|e| html_parse_error(document_number, e.to_string()))?;
    let link_selector =
        Selector::parse("a[href]").map_err(|e| html_parse_error(document_number, e.to_string()))?;

    let mut sections = Vec::new();
    let mut current: Option<HtmlSectionBuilder> = None;
    let mut heading_counter = 0u32;

    for node in document.tree.nodes() {
        if let Some(element) = node.value().as_element() {
            let name = element.name();
            if let Some(depth) = heading_depth(name) {
                if let Some(builder) = current.take() {
                    sections.push(builder.build());
                }

                heading_counter += 1;
                let element_ref = ElementRef::wrap(node).expect("element node");
                let heading_text = normalize_inline_text(element_ref.text());
                let (number, section_title) =
                    parse_heading(&heading_text, heading_counter, sections.as_slice());
                let anchor = heading_anchor(element_ref, &anchor_selector);
                current = Some(HtmlSectionBuilder {
                    number,
                    title: section_title,
                    anchor,
                    depth,
                    text: TextAccumulator::default(),
                    cross_refs: Vec::new(),
                });
                continue;
            }

            let Some(section) = current.as_mut() else {
                continue;
            };

            match name {
                "p" | "li" | "dt" | "dd" | "tr" | "table" | "pre" | "blockquote" | "figure" => {
                    section.text.push_newline()
                }
                "td" | "th" => section.text.push_cell_separator(),
                "br" | "hr" => section.text.push_newline(),
                "a" => {
                    if let Some(element_ref) = ElementRef::wrap(node)
                        && let Some(href) = element_ref.attr("href")
                    {
                        if let Some(target) = href.strip_prefix('#')
                            && !is_generated_word_anchor(target)
                        {
                            section.cross_refs.push(CrossRef {
                                target_rfc: None,
                                target_section: Some(target.to_string()),
                                context: String::new(),
                            });
                        } else if let Some(target_rfc) = extract_rfc_number(href) {
                            section.cross_refs.push(CrossRef {
                                target_rfc: Some(RfcNumber(target_rfc)),
                                target_section: None,
                                context: String::new(),
                            });
                        }
                    }
                }
                _ => {}
            }
        } else if let Node::Text(text) = node.value() {
            let has_ancestor = |names: &[&str]| {
                node.ancestors().any(|ancestor| {
                    ancestor
                        .value()
                        .as_element()
                        .is_some_and(|element| names.contains(&element.name()))
                })
            };
            if let Some(section) = current.as_mut()
                && !has_ancestor(&["h1", "h2", "h3", "h4", "h5", "h6"])
                && !has_ancestor(&["head", "style", "script", "noscript"])
            {
                if has_ancestor(&["pre", "code"]) {
                    section.text.push_preformatted(text);
                } else {
                    section.text.push_inline(text);
                }
            }
        }
    }

    if let Some(builder) = current {
        sections.push(builder.build());
    }
    deduplicate_section_numbers(&mut sections);

    if sections.is_empty() {
        return Err(html_parse_error(
            document_number,
            "document contains no h1-h6 section headings",
        ));
    }

    for section in &mut sections {
        add_normative_statement_refs(section);
        deduplicate_cross_refs(&mut section.cross_refs);
        for xref in &mut section.cross_refs {
            xref.context = cross_ref_context(&section.text, xref);
        }
    }

    let mut references = extract_rfc_references(&document, &link_selector);
    classify_normative_references(&sections, &mut references);

    Ok(Rfc {
        number: RfcNumber(document_number),
        title,
        format: RfcFormat::Html,
        status,
        date,
        obsoletes: Vec::new(),
        updates: Vec::new(),
        obsoleted_by: Vec::new(),
        updated_by: Vec::new(),
        sections,
        references,
        raw_text: content.to_string(),
        content_hash: content_hash.to_string(),
    })
}

struct HtmlSectionBuilder {
    number: String,
    title: String,
    anchor: Option<String>,
    depth: u8,
    text: TextAccumulator,
    cross_refs: Vec<CrossRef>,
}

impl HtmlSectionBuilder {
    fn build(self) -> Section {
        Section {
            number: self.number,
            title: self.title,
            anchor: self.anchor,
            depth: self.depth,
            text: self.text.finish(),
            cross_refs: self.cross_refs,
            pn: None,
        }
    }
}

fn document_title(document: &Html) -> String {
    let title_selector = Selector::parse("title").expect("valid title selector");
    document
        .select(&title_selector)
        .next()
        .map(|element| normalize_inline_text(element.text()))
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| "Imported HTML Standard".to_string())
}

fn heading_depth(name: &str) -> Option<u8> {
    match name {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}

fn parse_heading(text: &str, counter: u32, existing: &[Section]) -> (String, String) {
    if let Some(captures) = HEADING_NUMBER_RE.captures(text) {
        let number = captures[1].trim_end_matches('.').to_string();
        let title = captures[2].trim().to_string();
        return (number, title);
    }

    let base = format!("h-{}", counter);
    let number = unique_section_number(&base, existing);
    (number, text.trim().to_string())
}

fn heading_anchor(heading: ElementRef<'_>, selector: &Selector) -> Option<String> {
    if let Some(id) = heading.attr("id") {
        return Some(id.to_string());
    }

    let anchors: Vec<String> = heading
        .select(selector)
        .filter_map(|anchor| anchor.attr("name").or_else(|| anchor.attr("id")))
        .filter(|anchor| !anchor.is_empty())
        .map(str::to_string)
        .collect();
    anchors
        .iter()
        .find(|anchor| !is_generated_word_anchor(anchor))
        .cloned()
        .or_else(|| anchors.last().cloned())
}

fn normalize_inline_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_generated_word_anchor(anchor: &str) -> bool {
    anchor.starts_with("_Toc") || anchor.starts_with("_Ref")
}

fn unique_section_number(base: &str, existing: &[Section]) -> String {
    if !existing.iter().any(|section| section.number == base) {
        return base.to_string();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{}-{}", base, suffix);
        if !existing.iter().any(|section| section.number == candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn deduplicate_section_numbers(sections: &mut [Section]) {
    let mut seen = std::collections::HashMap::new();
    for section in sections {
        let count = seen.entry(section.number.clone()).or_insert(0u32);
        *count += 1;
        if *count > 1 {
            let original = section.number.clone();
            section.number = format!("{}-{}", original, count);
            tracing::warn!(
                "Duplicate section number '{}' in HTML — renaming to '{}'",
                original,
                section.number
            );
        }
    }
}

fn add_normative_statement_refs(section: &mut Section) {
    for captures in MQTT_STATEMENT_RE.captures_iter(&section.text) {
        section.cross_refs.push(CrossRef {
            target_rfc: None,
            target_section: Some(captures[1].to_string()),
            context: sentence_around(&section.text, captures.get(0).expect("whole match").start()),
        });
    }
}

fn deduplicate_cross_refs(cross_refs: &mut Vec<CrossRef>) {
    let mut seen = HashSet::new();
    cross_refs.retain(|xref| {
        seen.insert((
            xref.target_rfc.map(|rfc| rfc.0),
            xref.target_section.clone(),
        ))
    });
}

fn cross_ref_context(text: &str, xref: &CrossRef) -> String {
    let needle = xref
        .target_section
        .as_deref()
        .map(str::to_string)
        .or_else(|| xref.target_rfc.map(|rfc| format!("RFC{}", rfc.0)));
    needle
        .and_then(|needle| text.find(&needle))
        .map(|position| sentence_around(text, position))
        .unwrap_or_default()
}

fn sentence_around(text: &str, position: usize) -> String {
    let start = text[..position]
        .rfind(['.', '\n'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let end = text[position..]
        .find(['.', '\n'])
        .map(|index| position + index + 1)
        .unwrap_or(text.len());
    text[start..end].trim().chars().take(300).collect()
}

fn extract_rfc_references(document: &Html, selector: &Selector) -> Vec<Reference> {
    let mut references = Vec::new();
    let mut seen = HashSet::new();
    for link in document.select(selector) {
        let href = link.attr("href").unwrap_or_default();
        let link_text = normalize_inline_text(link.text());
        let Some(number) = extract_rfc_number(href).or_else(|| extract_rfc_number(&link_text))
        else {
            continue;
        };
        if seen.insert(number) {
            references.push(Reference {
                label: format!("[RFC{}]", number),
                target_rfc: Some(RfcNumber(number)),
                title: link_text,
                is_normative: false,
            });
        }
    }
    references
}

fn classify_normative_references(sections: &[Section], references: &mut [Reference]) {
    for reference in references {
        let Some(target) = reference.target_rfc else {
            continue;
        };
        reference.is_normative = sections.iter().any(|section| {
            let title = section.title.to_lowercase();
            !title.contains("non-normative")
                && title.contains("normative reference")
                && section
                    .cross_refs
                    .iter()
                    .any(|xref| xref.target_rfc == Some(target))
        });
    }
}

fn extract_rfc_number(value: &str) -> Option<u32> {
    RFC_LINK_RE
        .captures(value)
        .and_then(|captures| captures[1].parse().ok())
}

fn extract_date(content: &str) -> NaiveDate {
    if let Some(captures) = HTML_DATE_RE.captures(content) {
        let day = captures[1].parse().unwrap_or(1);
        let month = super::parser_xml::parse_month(&captures[2]).unwrap_or(1);
        let year = captures[3].parse().unwrap_or(1970);
        if let Some(date) = NaiveDate::from_ymd_opt(year, month, day) {
            return date;
        }
    }
    NaiveDate::from_ymd_opt(1970, 1, 1).expect("valid fallback date")
}

fn html_parse_error(document_number: u32, detail: impl Into<String>) -> RfcAnalyzerError {
    RfcAnalyzerError::Parse {
        rfc: document_number,
        format: "html".to_string(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headings_tables_links_and_normative_labels() {
        let html = r##"<!doctype html>
<html>
<head><title>MQTT Version 5.0 | OASIS Standard</title></head>
<body>
<p>07 March 2019</p>
<h1 id="intro">1 Introduction</h1>
<p>The Server <b>MUST</b> validate the packet
<span>[MQTT-1.0.0-1]</span>.</p>
<h2><a name="_Toc123"></a><a name="_packet-format"></a>2.1 Packet format</h2>
<table>
  <tr><th>Bit</th><th>Meaning</th></tr>
  <tr><td>0</td><td>Reserved</td></tr>
</table>
<p>See <a href="#intro">the introduction</a> and
<a href="https://www.rfc-editor.org/rfc/rfc2119.html">RFC 2119</a>.</p>
<h2>3 Normative references</h2>
<p><a href="https://www.rfc-editor.org/rfc/rfc2119.html">RFC 2119</a></p>
</body>
</html>"##;

        let rfc = parse_html(99902, html, "hash").unwrap();
        assert_eq!(rfc.format, RfcFormat::Html);
        assert_eq!(rfc.status, RfcStatus::Standard);
        assert_eq!(rfc.date, NaiveDate::from_ymd_opt(2019, 3, 7).unwrap());
        assert_eq!(rfc.sections.len(), 3);
        assert_eq!(rfc.sections[0].number, "1");
        assert!(rfc.sections[0].text.contains("MUST validate"));
        assert!(
            rfc.sections[0]
                .cross_refs
                .iter()
                .any(|xref| xref.target_section.as_deref() == Some("MQTT-1.0.0-1"))
        );

        let packet = &rfc.sections[1];
        assert_eq!(packet.number, "2.1");
        assert_eq!(packet.anchor.as_deref(), Some("_packet-format"));
        assert!(packet.text.contains("Bit | Meaning"));
        assert!(packet.text.contains("0 | Reserved"));
        assert!(
            packet
                .cross_refs
                .iter()
                .any(|xref| xref.target_section.as_deref() == Some("intro"))
        );
        assert!(
            packet
                .cross_refs
                .iter()
                .any(|xref| xref.target_rfc == Some(RfcNumber(2119)))
        );
        assert!(rfc.references.iter().any(|reference| reference.target_rfc
            == Some(RfcNumber(2119))
            && reference.is_normative));
    }

    #[test]
    fn errors_when_no_headings_exist() {
        let result = parse_html(99903, "<html><p>No sections</p></html>", "hash");
        assert!(matches!(result, Err(RfcAnalyzerError::Parse { .. })));
    }
}
