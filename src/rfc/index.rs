use crate::error::Result;
use crate::rfc::model::RfcNumber;
use std::collections::HashMap;

/// Metadata about an RFC from the index.
#[derive(Debug, Clone)]
pub struct RfcIndexEntry {
    pub number: u32,
    pub title: String,
    pub obsoleted_by: Vec<RfcNumber>,
    pub updated_by: Vec<RfcNumber>,
}

/// Fetch and parse the RFC index. Returns a map of RFC number -> entry.
/// The index is fetched from: https://www.rfc-editor.org/rfc-index.txt
pub async fn fetch_rfc_index(base_url: &str) -> Result<HashMap<u32, RfcIndexEntry>> {
    let url = format!("{}/rfc-index.txt", base_url);
    tracing::info!("Fetching RFC index from {}", url);

    let client = reqwest::Client::new();
    let content = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            crate::error::RfcAnalyzerError::Config(format!("Failed to fetch RFC index: {}", e))
        })?
        .text()
        .await
        .map_err(|e| {
            crate::error::RfcAnalyzerError::Config(format!("Failed to read RFC index: {}", e))
        })?;

    Ok(parse_rfc_index(&content))
}

/// Parse the RFC index text into a map.
/// Each entry looks like:
///   0793 Transmission Control Protocol. J. Postel. September 1981.
///        (Format: TXT, HTML) (Obsoletes RFC0761) (Obsoleted by RFC9293)
///        (Updated by RFC1122, RFC3168, ...) (Status: INTERNET STANDARD)
pub fn parse_rfc_index(content: &str) -> HashMap<u32, RfcIndexEntry> {
    let mut entries = HashMap::new();
    let mut current_entry: Option<(u32, String)> = None;
    let mut current_text = String::new();

    for line in content.lines() {
        // New entry starts with 4-digit RFC number at the start
        if line.len() >= 4 && line[..4].chars().all(|c| c.is_ascii_digit()) {
            // Save previous entry
            if let Some((num, _)) = current_entry.take()
                && let Some(entry) = parse_index_entry(num, &current_text)
            {
                entries.insert(num, entry);
            }
            let num: u32 = line[..4].parse().unwrap_or(0);
            if num > 0 {
                current_entry = Some((num, String::new()));
                current_text = line.to_string();
            }
        } else if current_entry.is_some() && (line.starts_with(' ') || line.starts_with('\t')) {
            current_text.push(' ');
            current_text.push_str(line.trim());
        } else if line.trim().is_empty() && current_entry.is_some() {
            // Entry ends at blank line
            if let Some((num, _)) = current_entry.take()
                && let Some(entry) = parse_index_entry(num, &current_text)
            {
                entries.insert(num, entry);
            }
            current_text.clear();
        }
    }

    // Don't forget last entry
    if let Some((num, _)) = current_entry
        && let Some(entry) = parse_index_entry(num, &current_text)
    {
        entries.insert(num, entry);
    }

    tracing::info!("Parsed {} RFC index entries", entries.len());
    entries
}

fn parse_index_entry(number: u32, text: &str) -> Option<RfcIndexEntry> {
    // Extract title (everything before the first period followed by author)
    let title = text.get(5..)?.split('.').next()?.trim().to_string();

    // Extract "Obsoleted by RFCxxxx, RFCyyyy"
    let obsoleted_by = extract_rfc_list_from_parens(text, "Obsoleted by");
    let updated_by = extract_rfc_list_from_parens(text, "Updated by");

    Some(RfcIndexEntry {
        number,
        title,
        obsoleted_by,
        updated_by,
    })
}

fn extract_rfc_list_from_parens(text: &str, prefix: &str) -> Vec<RfcNumber> {
    let search = format!("({}", prefix);
    let Some(start) = text.find(&search) else {
        return Vec::new();
    };
    let rest = &text[start..];
    let Some(end) = rest.find(')') else {
        return Vec::new();
    };
    let inner = &rest[search.len()..end];
    inner
        .split(|c: char| [',', ' '].contains(&c))
        .filter_map(|s| {
            let s = s.trim();
            s.strip_prefix("RFC")
                .and_then(|n| n.parse::<u32>().ok())
                .map(RfcNumber)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc_index_entry() {
        let content = r#"
0793 Transmission Control Protocol. J. Postel. September 1981.
     (Format: TXT, HTML) (Obsoleted by RFC9293) (Updated by RFC1122,
     RFC3168) (Also STD0007) (Status: INTERNET STANDARD)

0794 Pre-emption. V.G. Cerf. September 1981. (Format: TXT) (Status:
     UNKNOWN)
"#;
        let entries = parse_rfc_index(content);
        assert!(entries.contains_key(&793));
        let e793 = &entries[&793];
        assert!(e793.title.contains("Transmission Control Protocol"));
        assert_eq!(e793.obsoleted_by, vec![RfcNumber(9293)]);
        assert!(e793.updated_by.contains(&RfcNumber(1122)));
        assert!(e793.updated_by.contains(&RfcNumber(3168)));
    }

    #[test]
    fn test_extract_rfc_list_from_parens() {
        let text = "(Obsoleted by RFC9293) (Updated by RFC1122, RFC3168)";
        let obs = extract_rfc_list_from_parens(text, "Obsoleted by");
        assert_eq!(obs, vec![RfcNumber(9293)]);
        let upd = extract_rfc_list_from_parens(text, "Updated by");
        assert_eq!(upd, vec![RfcNumber(1122), RfcNumber(3168)]);
    }

    #[test]
    fn test_missing_parens() {
        let result = extract_rfc_list_from_parens("no parens here", "Obsoleted by");
        assert!(result.is_empty());
    }
}
