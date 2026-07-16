use crate::error::{Result, RfcAnalyzerError};
use crate::rfc::model::*;
use crate::rfc::text::TextAccumulator;
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
    let mut completed_sections: Vec<(u32, Section)> = Vec::new();
    let mut references = Vec::new();

    // Parser state
    let mut element_stack: Vec<String> = Vec::new();
    let mut section_stack: Vec<SectionBuilder> = Vec::new();
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
                        let anchor = attrs.get("anchor").cloned();
                        let pn = attrs.get("pn").cloned();
                        section_counter += 1;
                        let has_pn = pn.is_some();
                        let section_num = pn
                            .as_deref()
                            .and_then(|p| p.strip_prefix("section-"))
                            .map(|s| s.to_string())
                            .or_else(|| anchor.clone())
                            .unwrap_or_else(|| format!("s-{}", section_counter));
                        if !has_pn && section_counter == 1 {
                            tracing::warn!(
                                "Sections lack 'pn' attributes (Internet-Draft?). \
                                 Using anchor/auto-generated section numbers."
                            );
                        }
                        let depth = if has_pn {
                            section_num.matches('.').count() as u8 + 1
                        } else {
                            u8::try_from(section_stack.len() + 1).unwrap_or(u8::MAX)
                        };
                        section_stack.push(SectionBuilder {
                            order: section_counter,
                            number: section_num,
                            title: String::new(),
                            anchor,
                            depth,
                            text: TextAccumulator::default(),
                            cross_refs: Vec::new(),
                            pn,
                        });
                    }
                    "xref" => {
                        if let Some(sec) = section_stack.last_mut() {
                            let target = attrs.get("target").cloned().unwrap_or_default();
                            let section_attr = attrs.get("section").cloned();

                            // Parse target: could be "RFC1234" or an anchor name
                            let target_rfc = parse_rfc_from_target(&target);
                            let target_section = section_attr.or_else(|| {
                                (target_rfc.is_none() && !target.is_empty()).then(|| target.clone())
                            });
                            if target_rfc.is_some() || target_section.is_some() {
                                sec.cross_refs.push(CrossRef {
                                    target_rfc: target_rfc.map(RfcNumber),
                                    target_section,
                                    context: String::new(), // filled from surrounding text
                                });
                            }
                            if is_empty && !target.is_empty() {
                                sec.text.push_inline(&target);
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
                    "seriesInfo" if attrs.get("name").map(|s| s.as_str()) == Some("RFC") => {
                        ref_rfc_value = attrs.get("value").and_then(|v| v.parse().ok());
                    }
                    _ => {}
                }

                if let Some(section) = section_stack.last_mut() {
                    match name.as_str() {
                        "t" | "li" | "dt" | "dd" | "tr" | "table" | "sourcecode" | "artwork"
                        | "blockquote" | "figure" => section.text.push_newline(),
                        "td" | "th" => section.text.push_cell_separator(),
                        "br" => section.text.push_newline(),
                        _ => {}
                    }
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
                        if let Some(builder) = section_stack.pop() {
                            completed_sections.push((builder.order, builder.build()));
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

                if let Some(section) = section_stack.last_mut() {
                    match name.as_str() {
                        "t" | "li" | "dt" | "dd" | "tr" | "table" | "sourcecode" | "artwork"
                        | "blockquote" | "figure" => section.text.push_newline(),
                        _ => {}
                    }
                }
                element_stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                let parent = element_stack.last().map(|s| s.as_str());
                let grandparent = element_stack
                    .len()
                    .checked_sub(2)
                    .and_then(|index| element_stack.get(index))
                    .map(String::as_str);

                match parent {
                    Some("title") => {
                        if element_stack.iter().any(|element| element == "reference") {
                            if !current_ref_title.is_empty() {
                                current_ref_title.push(' ');
                            }
                            current_ref_title.push_str(text.trim());
                        } else if section_stack.is_empty() && title.is_empty() {
                            title = text.trim().to_string();
                        }
                    }
                    Some("name") if grandparent == Some("section") => {
                        if let Some(section) = section_stack.last_mut() {
                            section.title.push_str(text.trim());
                        }
                    }
                    Some("name") if grandparent == Some("references") => {
                        let text_lower = text.to_lowercase();
                        if text_lower.contains("normative") {
                            in_normative_refs = true;
                        } else if text_lower.contains("informative") {
                            in_normative_refs = false;
                        }
                    }
                    _ => {
                        if let Some(section) = section_stack.last_mut()
                            && !element_stack.iter().any(|element| element == "svg")
                        {
                            if element_stack
                                .iter()
                                .any(|element| element == "sourcecode" || element == "artwork")
                            {
                                section.text.push_preformatted(&text);
                            } else {
                                section.text.push_inline(&text);
                            }
                        }
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if let Some(section) = section_stack.last_mut() {
                    let text = String::from_utf8_lossy(e.as_ref());
                    section.text.push_preformatted(&text);
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

    // Be tolerant of malformed input with unclosed section tags.
    while let Some(builder) = section_stack.pop() {
        completed_sections.push((builder.order, builder.build()));
    }
    completed_sections.sort_by_key(|(order, _)| *order);
    let mut sections: Vec<Section> = completed_sections
        .into_iter()
        .map(|(_, section)| section)
        .collect();
    deduplicate_section_numbers(&mut sections);

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
    order: u32,
    number: String,
    title: String,
    anchor: Option<String>,
    depth: u8,
    text: TextAccumulator,
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
            text: self.text.finish(),
            cross_refs: self.cross_refs,
            pn: self.pn,
        }
    }
}

fn deduplicate_section_numbers(sections: &mut [Section]) {
    let mut seen = HashMap::new();
    for section in sections {
        let count = seen.entry(section.number.clone()).or_insert(0u32);
        *count += 1;
        if *count > 1 {
            let original = section.number.clone();
            section.number = format!("{}-{}", original, count);
            tracing::warn!(
                "Duplicate section number '{}' in RFCXML — renaming to '{}'",
                original,
                section.number
            );
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
            if trimmed.chars().count() <= 200 {
                return format!("{}.", trimmed);
            }
            let head: String = trimmed.chars().take(197).collect();
            return format!("{}...", head);
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

    #[test]
    fn test_parse_xml_preserves_rich_section_content() {
        let xml = r#"<?xml version="1.0"?>
<rfc category="std">
  <front>
    <title>Rich RFCXML Fixture</title>
    <date year="2026" month="July"/>
  </front>
  <middle>
    <section anchor="requirements">
      <name>Requirements</name>
      <t>
        A receiver <bcp14>MUST</bcp14> validate the <tt>Packet Identifier</tt>
        using <xref target="RFC2119"/>.
      </t>
      <sourcecode type="text"><![CDATA[
packet-id = 1*2OCTET
]]></sourcecode>
      <table anchor="packet-values">
        <name>Packet Values</name>
        <thead><tr><th>Value</th><th>Meaning</th></tr></thead>
        <tbody><tr><td>1</td><td>CONNECT</td></tr></tbody>
      </table>
      <section anchor="nested">
        <name>Nested Requirement</name>
        <t>The sender <bcp14>SHOULD NOT</bcp14> reuse the identifier.</t>
      </section>
      <t>Text after the nested section is retained.</t>
    </section>
  </middle>
</rfc>"#;

        let rfc = parse_xml(99901, xml, "hash").unwrap();
        assert_eq!(rfc.sections.len(), 2);

        let parent = rfc
            .sections
            .iter()
            .find(|section| section.number == "requirements")
            .unwrap();
        assert!(parent.text.contains("MUST validate"));
        assert!(parent.text.contains("Packet Identifier"));
        assert!(parent.text.contains("RFC2119"));
        assert!(parent.text.contains("packet-id = 1*2OCTET"));
        assert!(parent.text.contains("Value"));
        assert!(parent.text.contains("CONNECT"));
        assert!(
            parent
                .text
                .contains("Text after the nested section is retained.")
        );
        assert!(
            parent
                .cross_refs
                .iter()
                .any(|xref| xref.target_rfc == Some(RfcNumber(2119)))
        );

        let nested = rfc
            .sections
            .iter()
            .find(|section| section.number == "nested")
            .unwrap();
        assert!(nested.text.contains("SHOULD NOT"));
    }
}
