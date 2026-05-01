use crate::error::Result;
use crate::rfc::model::*;
use chrono::NaiveDate;
use regex::Regex;

/// Parse a plain-text RFC into an Rfc struct.
pub fn parse_text(rfc_number: u32, content: &str, content_hash: &str) -> Result<Rfc> {
    let title = extract_title(content);
    let status = extract_status(content);
    let date = extract_date(content);
    let (obsoletes, updates) = extract_obsoletes_updates(content);
    let sections = extract_sections(content);
    let references = extract_references(content);

    Ok(Rfc {
        number: RfcNumber(rfc_number),
        title,
        format: RfcFormat::PlainText,
        status,
        date,
        obsoletes,
        updates,
        obsoleted_by: Vec::new(), // populated from RFC index, not from the doc itself
        updated_by: Vec::new(),
        sections,
        references,
        raw_text: content.to_string(),
        content_hash: content_hash.to_string(),
    })
}

/// Extract the title from the first non-blank line(s) of the RFC.
/// The title is usually centered near the top, after the header block.
fn extract_title(content: &str) -> String {
    // Look for lines between the header block and "Status of This Memo"
    // or "Abstract". The title is typically the first centered text block.
    let lines: Vec<&str> = content.lines().collect();
    let mut title_lines = Vec::new();
    let mut past_header = false;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !title_lines.is_empty() {
                break; // title block ends at first blank line after content
            }
            continue;
        }
        // Skip header lines (contain RFC number, date, authors at top)
        if !past_header {
            if trimmed.starts_with("Internet Engineering Task Force")
                || trimmed.starts_with("Request for Comments")
                || trimmed.starts_with("Network Working Group")
                || trimmed.contains("Category:")
                || trimmed.contains("ISSN:")
                || trimmed.contains("Updates:")
                || trimmed.contains("Obsoletes:")
            {
                continue;
            }
            past_header = true;
        }
        if trimmed == "Status of This Memo"
            || trimmed == "Abstract"
            || trimmed == "Table of Contents"
        {
            break;
        }
        title_lines.push(trimmed);
    }

    title_lines.join(" ")
}

/// Extract RFC status from "Category: " line or "Status of This Memo" text.
fn extract_status(content: &str) -> RfcStatus {
    for line in content.lines().take(20) {
        if let Some(cat) = line.trim().strip_prefix("Category:") {
            return RfcStatus::from_str_loose(cat.trim());
        }
    }
    // Fallback: look for status keywords in the first ~50 lines
    for line in content.lines().take(50) {
        let lower = line.to_lowercase();
        if lower.contains("standards track") {
            return RfcStatus::ProposedStandard;
        }
        if lower.contains("informational") {
            return RfcStatus::Informational;
        }
        if lower.contains("experimental") {
            return RfcStatus::Experimental;
        }
        if lower.contains("best current practice") {
            return RfcStatus::BestCurrentPractice;
        }
    }
    RfcStatus::Unknown
}

/// Extract the publication date.
fn extract_date(content: &str) -> NaiveDate {
    // Look for month + year pattern in the first 20 lines
    let re = Regex::new(r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})").unwrap();
    for line in content.lines().take(20) {
        if let Some(caps) = re.captures(line) {
            let month_str = &caps[1];
            let year: i32 = caps[2].parse().unwrap_or(1970);
            let month = super::parser_xml::parse_month(month_str).unwrap_or(1);
            if let Some(d) = NaiveDate::from_ymd_opt(year, month, 1) {
                return d;
            }
        }
    }
    NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()
}

/// Extract "Obsoletes: 793, 879" and "Updates: 1234" from header lines.
fn extract_obsoletes_updates(content: &str) -> (Vec<RfcNumber>, Vec<RfcNumber>) {
    let mut obsoletes = Vec::new();
    let mut updates = Vec::new();

    for line in content.lines().take(20) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Obsoletes:") {
            obsoletes = parse_number_list(rest);
        }
        if let Some(rest) = trimmed.strip_prefix("Updates:") {
            updates = parse_number_list(rest);
        }
    }

    (obsoletes, updates)
}

fn parse_number_list(s: &str) -> Vec<RfcNumber> {
    s.split(|c: char| [',', ' '].contains(&c))
        .filter_map(|part| part.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .map(RfcNumber)
        .collect()
}

/// Extract sections from the plain-text body.
fn extract_sections(content: &str) -> Vec<Section> {
    // Section headers match patterns like:
    //   "1.  Introduction"
    //   "1.1.  Subsection Name"
    //   "Appendix A.  Something"
    //   "A.1.  Appendix Subsection"
    let section_re = Regex::new(r"(?m)^(\d+(?:\.\d+)*)\.\s{2,}(.+)$").unwrap();
    let appendix_re = Regex::new(r"(?m)^(?:Appendix\s+)?([A-Z](?:\.\d+)*)\.\s{2,}(.+)$").unwrap();

    let mut sections = Vec::new();
    let mut matches: Vec<(usize, String, String)> = Vec::new();

    // Collect all section header positions
    for cap in section_re.captures_iter(content) {
        let pos = cap.get(0).unwrap().start();
        let num = cap[1].to_string();
        let title = cap[2].trim().to_string();
        matches.push((pos, num, title));
    }
    for cap in appendix_re.captures_iter(content) {
        let pos = cap.get(0).unwrap().start();
        let num = cap[1].to_string();
        let title = cap[2].trim().to_string();
        // Avoid duplicates from the numeric regex
        if !matches.iter().any(|(p, _, _)| *p == pos) {
            matches.push((pos, num, title));
        }
    }
    matches.sort_by_key(|(pos, _, _)| *pos);

    // Extract text between section headers
    let xref_re = Regex::new(r"\[RFC\s*(\d+)\]").unwrap();
    let xref_section_re = Regex::new(r"Section\s+(\d+(?:\.\d+)*)\s+of\s+\[RFC\s*(\d+)\]").unwrap();
    let internal_section_re = Regex::new(r"[Ss]ee\s+Section\s+(\d+(?:\.\d+)*)").unwrap();

    for i in 0..matches.len() {
        let (pos, ref num, ref title) = matches[i];
        let next_pos = matches
            .get(i + 1)
            .map(|(p, _, _)| *p)
            .unwrap_or(content.len());

        // Find the text start (after the header line)
        let header_end = content[pos..]
            .find('\n')
            .map(|p| pos + p + 1)
            .unwrap_or(pos);
        let text = content[header_end..next_pos].trim().to_string();

        // Strip page headers/footers (lines with "[Page N]" or form feeds)
        let text = strip_page_breaks(&text);

        // Extract cross-references from the text
        let mut cross_refs = Vec::new();

        // Section X of [RFCN] pattern
        for cap in xref_section_re.captures_iter(&text) {
            let target_section = cap[1].to_string();
            let target_rfc: u32 = cap[2].parse().unwrap_or(0);
            if target_rfc > 0 {
                cross_refs.push(CrossRef {
                    target_rfc: Some(RfcNumber(target_rfc)),
                    target_section: Some(target_section),
                    context: extract_sentence_around(&text, cap.get(0).unwrap().start()),
                });
            }
        }

        // [RFCN] pattern (document-level reference)
        for cap in xref_re.captures_iter(&text) {
            let target_rfc: u32 = cap[1].parse().unwrap_or(0);
            if target_rfc > 0 {
                // Avoid duplicates from the section-level pattern
                let already_found = cross_refs.iter().any(|x| {
                    x.target_rfc == Some(RfcNumber(target_rfc)) && x.target_section.is_some()
                });
                if !already_found {
                    cross_refs.push(CrossRef {
                        target_rfc: Some(RfcNumber(target_rfc)),
                        target_section: None,
                        context: extract_sentence_around(&text, cap.get(0).unwrap().start()),
                    });
                }
            }
        }

        // "see Section X" (internal reference)
        for cap in internal_section_re.captures_iter(&text) {
            cross_refs.push(CrossRef {
                target_rfc: None,
                target_section: Some(cap[1].to_string()),
                context: extract_sentence_around(&text, cap.get(0).unwrap().start()),
            });
        }

        let depth = num.matches('.').count() as u8 + 1;

        sections.push(Section {
            number: num.clone(),
            title: title.clone(),
            anchor: None,
            depth,
            text,
            cross_refs,
            pn: None,
        });
    }

    sections
}

/// Extract formal references from the References section.
fn extract_references(content: &str) -> Vec<Reference> {
    let mut references = Vec::new();
    let mut in_references = false;
    let mut is_normative = true;
    let ref_re = Regex::new(r"^\s*\[([^\]]+)\]").unwrap();

    // Find the start of the references section
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "References" || trimmed.ends_with("References") {
            in_references = true;
            continue;
        }
        if !in_references {
            continue;
        }
        if trimmed.contains("Normative References") {
            is_normative = true;
            continue;
        }
        if trimmed.contains("Informative References") {
            is_normative = false;
            continue;
        }
        // End of references section
        if !trimmed.is_empty()
            && !trimmed.starts_with('[')
            && !trimmed.starts_with(' ')
            && in_references
            && (trimmed == "Acknowledgments"
                || trimmed == "Authors' Addresses"
                || trimmed == "Appendix"
                || trimmed.starts_with("Appendix"))
        {
            break;
        }

        // Parse reference entries: [RFC793] Postel, J., "Title", ...
        if let Some(cap) = ref_re.captures(trimmed) {
            let label = format!("[{}]", &cap[1]);
            let rfc_num = extract_rfc_from_label(&cap[1]);

            // Extract title from the quoted string
            let title = extract_quoted_title(trimmed);

            references.push(Reference {
                label,
                target_rfc: rfc_num.map(RfcNumber),
                title,
                is_normative,
            });
        }
    }

    references
}

/// Extract RFC number from a reference label like "RFC793" or "RFC 9293".
fn extract_rfc_from_label(label: &str) -> Option<u32> {
    let stripped = label
        .strip_prefix("RFC")
        .or_else(|| label.strip_prefix("rfc"))?;
    stripped.trim().parse().ok()
}

/// Extract the first quoted string from a line.
fn extract_quoted_title(line: &str) -> String {
    if let Some(start) = line.find('"')
        && let Some(end) = line[start + 1..].find('"')
    {
        return line[start + 1..start + 1 + end].to_string();
    }
    String::new()
}

/// Strip page headers/footers from text.
fn strip_page_breaks(text: &str) -> String {
    let page_re = Regex::new(r"(?m)^\s*\[Page \d+\]\s*$").unwrap();
    let ff_re = Regex::new(r"\x0c").unwrap();
    let cleaned = page_re.replace_all(text, "");
    let cleaned = ff_re.replace_all(&cleaned, "");
    // Also remove the header lines that appear after page breaks
    // (lines like "RFC 9293          TCP          August 2022")
    let header_re = Regex::new(r"(?m)^[A-Z].*RFC \d+.*\d{4}\s*$").unwrap();
    header_re.replace_all(&cleaned, "").trim().to_string()
}

/// Extract the sentence surrounding a position in text.
fn extract_sentence_around(text: &str, pos: usize) -> String {
    // Find sentence boundaries (period, start/end of text)
    let start = text[..pos].rfind('.').map(|p| p + 1).unwrap_or(0);
    let end = text[pos..]
        .find('.')
        .map(|p| pos + p + 1)
        .unwrap_or(text.len());
    let sentence = text[start..end].trim();
    if sentence.len() <= 200 {
        sentence.to_string()
    } else {
        format!("{}...", &sentence[..197])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_rfc_from_label() {
        assert_eq!(extract_rfc_from_label("RFC793"), Some(793));
        assert_eq!(extract_rfc_from_label("RFC 9293"), Some(9293));
        assert_eq!(extract_rfc_from_label("SOMETHING"), None);
    }

    #[test]
    fn test_extract_quoted_title() {
        assert_eq!(
            extract_quoted_title(r#"[RFC793] Postel, J., "Transmission Control Protocol""#),
            "Transmission Control Protocol"
        );
    }

    #[test]
    fn test_parse_number_list() {
        let result = parse_number_list("793, 879");
        assert_eq!(result, vec![RfcNumber(793), RfcNumber(879)]);
    }

    #[test]
    fn test_extract_sentence_around() {
        let text = "First sentence. This mentions RFC 793 in context. Third sentence.";
        let result = extract_sentence_around(text, text.find("RFC 793").unwrap());
        assert!(result.contains("RFC 793"));
    }
}
