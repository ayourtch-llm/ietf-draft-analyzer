use crate::error::{Result, RfcAnalyzerError};
use crate::rfc::model::*;
use chrono::NaiveDate;
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;

/// Parse an RFC XML document into an Rfc struct.
/// `rfc_number` is provided separately since we know it from the fetch.
/// `content` is the raw XML string.
/// `content_hash` is the pre-computed SHA-256 hex hash of `content`.
pub fn parse_xml(rfc_number: u32, content: &str, content_hash: &str) -> Result<Rfc> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut title = String::new();
    let mut status = RfcStatus::Unknown;
    let mut date = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    let mut obsoletes = Vec::new();
    let mut updates = Vec::new();
    let obsoleted_by = Vec::new();
    let updated_by = Vec::new();
    let mut sections = Vec::new();
    let mut references = Vec::new();

    // Parser state
    let mut element_stack: Vec<String> = Vec::new();
    let mut current_section: Option<SectionBuilder> = None;
    let mut in_normative_refs = false;
    let mut section_counter: u32 = 0;
    let mut current_ref_anchor = String::new();
    let mut current_ref_title = String::new();
    let mut ref_rfc_value: Option<u32> = None;
    let mut buf = Vec::new();

    // Extract attributes from the <rfc> element
    // and from <section>, <xref>, <reference> elements as we go

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(event @ (Event::Start(_) | Event::Empty(_))) => {
                let (e, is_empty) = match &event {
                    Event::Start(e) => (e, false),
                    Event::Empty(e) => (e, true),
                    _ => unreachable!(),
                };
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attrs = extract_attrs(e);

                // Handle elements by name
                match name.as_str() {
                    "rfc" => {
                        // Extract obsoletes/updates from rfc attributes
                        if let Some(obs) = attrs.get("obsoletes") {
                            obsoletes = parse_rfc_list(obs);
                        }
                        if let Some(upd) = attrs.get("updates") {
                            updates = parse_rfc_list(upd);
                        }
                        // Category -> status
                        if let Some(cat) = attrs.get("category") {
                            status = RfcStatus::from_str_loose(cat);
                        }
                    }
                    "section" => {
                        // Finish any current section
                        if let Some(builder) = current_section.take() {
                            sections.push(builder.build());
                        }
                        let anchor = attrs.get("anchor").cloned();
                        let pn = attrs.get("pn").cloned();
                        section_counter += 1;
                        let section_num = pn
                            .as_deref()
                            .and_then(|p| p.strip_prefix("section-"))
                            .map(|s| s.to_string())
                            .or_else(|| anchor.clone())
                            .unwrap_or_else(|| format!("s-{}", section_counter));
                        let depth = section_num.matches('.').count() as u8 + 1;
                        current_section = Some(SectionBuilder {
                            number: section_num,
                            title: String::new(),
                            anchor,
                            depth,
                            text: String::new(),
                            cross_refs: Vec::new(),
                            pn,
                        });
                    }
                    "xref" => {
                        if let Some(ref mut sec) = current_section {
                            let target = attrs.get("target").cloned().unwrap_or_default();
                            let section_attr = attrs.get("section").cloned();

                            // Parse target: could be "RFC1234" or an anchor name
                            let target_rfc = parse_rfc_from_target(&target);
                            if target_rfc.is_some() || section_attr.is_some() {
                                sec.cross_refs.push(CrossRef {
                                    target_rfc: target_rfc.map(RfcNumber),
                                    target_section: section_attr,
                                    context: String::new(), // filled from surrounding text
                                });
                            }
                        }
                    }
                    "references" => {
                        // Determine normative vs informative from the <name> child
                        // We'll check the text of the <name> element below
                    }
                    "reference" => {
                        current_ref_anchor = attrs.get("anchor").cloned().unwrap_or_default();
                        current_ref_title.clear();
                        ref_rfc_value = None;
                    }
                    "seriesInfo" => {
                        if attrs.get("name").map(|s| s.as_str()) == Some("RFC") {
                            ref_rfc_value = attrs.get("value").and_then(|v| v.parse().ok());
                        }
                    }
                    _ => {}
                }
                // Only push Start events onto the stack (Empty events
                // don't have a matching End)
                if !is_empty {
                    element_stack.push(name);
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match name.as_str() {
                    "section" => {
                        if let Some(builder) = current_section.take() {
                            sections.push(builder.build());
                        }
                    }
                    "reference" => {
                        references.push(Reference {
                            label: current_ref_anchor.clone(),
                            target_rfc: ref_rfc_value.map(RfcNumber),
                            title: current_ref_title.clone(),
                            is_normative: in_normative_refs,
                        });
                    }
                    "references" => {
                        in_normative_refs = false;
                    }
                    _ => {}
                }
                element_stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                let parent = element_stack.last().map(|s| s.as_str());

                match parent {
                    Some("title") if element_stack.len() <= 3 => {
                        // Top-level <front><title>
                        if title.is_empty() {
                            title = text.clone();
                        }
                    }
                    Some("name") => {
                        // Section name or references name
                        if let Some(ref mut sec) = current_section
                            && sec.title.is_empty()
                        {
                            sec.title = text.clone();
                        }
                        // Check if this is a references group name
                        let text_lower = text.to_lowercase();
                        if text_lower.contains("normative") {
                            in_normative_refs = true;
                        } else if text_lower.contains("informative") {
                            in_normative_refs = false;
                        }
                    }
                    Some("title") => {
                        // Reference title
                        if !current_ref_anchor.is_empty() {
                            current_ref_title = text.clone();
                        }
                    }
                    Some("t") | Some("li") | Some("dd") | Some("dt") => {
                        // Paragraph text within a section
                        if let Some(ref mut sec) = current_section {
                            if !sec.text.is_empty() {
                                sec.text.push(' ');
                            }
                            sec.text.push_str(&text);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                return Err(RfcAnalyzerError::Xml {
                    rfc: rfc_number,
                    source: e,
                });
            }
            _ => {} // comments, PIs, etc.
        }
        buf.clear();
    }

    // Don't forget the last section
    if let Some(builder) = current_section.take() {
        sections.push(builder.build());
    }

    // Extract date from <date> element (not yet captured above — parse from
    // raw XML as a fallback)
    date = extract_date_from_xml(content).unwrap_or(date);

    // Fill cross-ref contexts from section text (grab surrounding sentence)
    for section in &mut sections {
        for xref in &mut section.cross_refs {
            if xref.context.is_empty() {
                xref.context = extract_context_sentence(&section.text, xref);
            }
        }
    }

    Ok(Rfc {
        number: RfcNumber(rfc_number),
        title,
        format: RfcFormat::Xml,
        status,
        date,
        obsoletes,
        updates,
        obsoleted_by,
        updated_by,
        sections,
        references,
        raw_text: content.to_string(),
        content_hash: content_hash.to_string(),
    })
}

// --- Helper types and functions ---

struct SectionBuilder {
    number: String,
    title: String,
    anchor: Option<String>,
    depth: u8,
    text: String,
    cross_refs: Vec<CrossRef>,
    pn: Option<String>,
}

impl SectionBuilder {
    fn build(self) -> Section {
        Section {
            number: self.number,
            title: self.title,
            anchor: self.anchor,
            depth: self.depth,
            text: self.text,
            cross_refs: self.cross_refs,
            pn: self.pn,
        }
    }
}

/// Extract all attributes from an XML element as a HashMap.
fn extract_attrs(e: &quick_xml::events::BytesStart<'_>) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = String::from_utf8_lossy(&attr.value).to_string();
        attrs.insert(key, value);
    }
    attrs
}

/// Parse a comma-separated list of RFC numbers like "793, 879, 2873".
fn parse_rfc_list(s: &str) -> Vec<RfcNumber> {
    s.split(',')
        .filter_map(|part| part.trim().parse::<u32>().ok())
        .map(RfcNumber)
        .collect()
}

/// Try to parse "RFC1234" or "RFC 1234" from an xref target attribute.
fn parse_rfc_from_target(target: &str) -> Option<u32> {
    let stripped = target
        .strip_prefix("RFC")
        .or_else(|| target.strip_prefix("rfc"))?;
    stripped.trim().parse().ok()
}

/// Extract <date year="..." month="..."/> from raw XML.
fn extract_date_from_xml(xml: &str) -> Option<NaiveDate> {
    // Simple regex approach for robustness
    let re =
        regex::Regex::new(r#"<date\s+year="(\d{4})"\s+month="(\w+)"(?:\s+day="(\d+)")?""#).ok()?;
    let caps = re.captures(xml)?;
    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month_str = caps.get(2)?.as_str();
    let day: u32 = caps
        .get(3)
        .and_then(|d| d.as_str().parse().ok())
        .unwrap_or(1);
    let month = parse_month(month_str)?;
    NaiveDate::from_ymd_opt(year, month, day)
}

/// Parse month name to number.
pub(crate) fn parse_month(s: &str) -> Option<u32> {
    match s.to_lowercase().as_str() {
        "january" | "jan" => Some(1),
        "february" | "feb" => Some(2),
        "march" | "mar" => Some(3),
        "april" | "apr" => Some(4),
        "may" => Some(5),
        "june" | "jun" => Some(6),
        "july" | "jul" => Some(7),
        "august" | "aug" => Some(8),
        "september" | "sep" => Some(9),
        "october" | "oct" => Some(10),
        "november" | "nov" => Some(11),
        "december" | "dec" => Some(12),
        _ => None,
    }
}

/// Extract the sentence surrounding a cross-reference from section text.
/// Returns a short context string (up to 200 chars).
fn extract_context_sentence(text: &str, xref: &CrossRef) -> String {
    // Try to find a sentence containing the RFC reference
    let search_term = if let Some(rfc) = xref.target_rfc {
        format!("RFC {}", rfc.0)
    } else if let Some(ref sec) = xref.target_section {
        format!("Section {}", sec)
    } else {
        return String::new();
    };

    // Find the sentence containing the search term
    for sentence in text.split('.') {
        if sentence.contains(&search_term) {
            let trimmed = sentence.trim();
            if trimmed.len() <= 200 {
                return format!("{}.", trimmed);
            }
            return format!("{}...", &trimmed[..197]);
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc_list() {
        let result = parse_rfc_list("793, 879, 2873");
        assert_eq!(
            result,
            vec![RfcNumber(793), RfcNumber(879), RfcNumber(2873)]
        );
    }

    #[test]
    fn test_parse_rfc_from_target() {
        assert_eq!(parse_rfc_from_target("RFC0793"), Some(793));
        assert_eq!(parse_rfc_from_target("RFC9293"), Some(9293));
        assert_eq!(parse_rfc_from_target("section-3"), None);
    }

    #[test]
    fn test_parse_month() {
        assert_eq!(parse_month("January"), Some(1));
        assert_eq!(parse_month("aug"), Some(8));
        assert_eq!(parse_month("December"), Some(12));
        assert_eq!(parse_month("invalid"), None);
    }
}
