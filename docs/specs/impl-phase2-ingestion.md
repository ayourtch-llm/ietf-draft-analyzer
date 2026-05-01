# Phase 2: RFC Ingestion — Implementation Spec

This document is self-contained. It builds on Phase 1 (which must be
complete). Implement exactly what is specified here.

## Overview

Phase 2 adds RFC fetching, parsing (XML and plain text), the RFC index,
and wires up the `map` and `show` CLI commands. At the end of Phase 2,
`rfc-analyzer map 9293 --depth 1 --protocol tcp` fetches, parses, and
stores TCP RFCs with their transitive references.

## Files to Create / Modify

```
src/
  main.rs          -- MODIFY: replace stub with clap-based CLI dispatch
  lib.rs           -- MODIFY: add new modules
  cli.rs           -- NEW: clap command definitions
  rfc/
    mod.rs         -- MODIFY: add new submodules
    fetcher.rs     -- NEW: async RFC download with caching
    parser_xml.rs  -- NEW: RFC XML parser
    parser_text.rs -- NEW: RFC plain text parser
    index.rs       -- NEW: RFC index fetcher/parser
```

## 1. src/cli.rs

Clap derive definitions. Only the `map`, `show`, and `clear` commands are
wired up in Phase 2. Other commands are defined but return
"not yet implemented" errors.

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rfc-analyzer", version, about = "RFC specification security analyzer")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "rfc-analyzer.toml")]
    pub config: PathBuf,

    /// SQLite database path
    #[arg(long, default_value = "rfc-analyzer.db")]
    pub db: PathBuf,

    /// Verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Fetch and parse RFCs, build the dependency graph
    Map {
        /// Seed RFC numbers
        #[arg(required = true)]
        rfcs: Vec<u32>,

        /// Associate RFCs with a protocol name
        #[arg(long)]
        protocol: Option<String>,

        /// Max depth for transitive dependency crawling
        #[arg(long, default_value = "2")]
        depth: u32,

        /// Only follow normative references
        #[arg(long)]
        normative_only: bool,
    },

    /// Build protocol state machines from mapped RFCs
    Model {
        /// Protocol name
        protocol: String,

        /// Mechanism types to model, comma-separated
        #[arg(long, value_delimiter = ',')]
        mechanisms: Option<Vec<String>>,
    },

    /// Run security analysis on modeled protocols
    Analyze {
        /// Protocol name
        protocol: String,

        /// Attack categories to check, comma-separated
        #[arg(long, value_delimiter = ',')]
        categories: Option<Vec<String>>,

        /// Minimum severity to include
        #[arg(long, default_value = "low")]
        min_severity: String,
    },

    /// Run full pipeline: map -> model -> analyze
    Run {
        /// Protocol name
        protocol: String,

        /// Seed RFC numbers
        #[arg(required = true)]
        rfcs: Vec<u32>,

        /// Max crawl depth
        #[arg(long, default_value = "2")]
        depth: u32,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show the dependency graph
    Graph {
        /// Protocol name or RFC number
        target: String,

        /// Output format: json, dot
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Show cached RFC info
    Show {
        /// RFC number
        rfc: u32,
    },

    /// Clear stored data
    Clear {
        /// What to clear: all, rfcs, graphs, analysis
        #[arg(default_value = "all")]
        scope: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}
```

## 2. src/rfc/fetcher.rs

Async RFC downloader. Tries XML first, falls back to plain text.
Uses `reqwest` with polite delay between requests.

```rust
use crate::config::FetcherConfig;
use crate::error::{RfcAnalyzerError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Tracks which format worked for each RFC to avoid repeated 404s.
/// Shared across all fetch calls within a session.
pub struct RfcFetcher {
    client: reqwest::Client,
    config: FetcherConfig,
    /// Cache of RFC number -> format that succeeded ("xml" or "text").
    format_cache: Mutex<HashMap<u32, String>>,
}

/// Result of fetching an RFC.
pub struct FetchResult {
    pub rfc_number: u32,
    pub content: String,
    pub format: String,       // "xml" or "text"
    pub content_hash: String, // SHA-256 hex of the raw content
}

impl RfcFetcher {
    pub fn new(config: FetcherConfig) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("rfc-analyzer/0.1.0")
            .build()
            .expect("Failed to build HTTP client");
        Self {
            client,
            config,
            format_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Fetch a single RFC. Tries XML first (if prefer_xml), falls back to
    /// the other format. Returns the raw content and detected format.
    ///
    /// Returns `RfcAnalyzerError::RfcNotFound` if both formats return 404.
    pub async fn fetch(&self, rfc_number: u32) -> Result<FetchResult> {
        // Check format cache
        let cached_format = self.format_cache.lock().unwrap().get(&rfc_number).cloned();

        let formats = if let Some(fmt) = cached_format {
            // Try the known-good format first
            if fmt == "xml" {
                vec!["xml", "text"]
            } else {
                vec!["text", "xml"]
            }
        } else if self.config.prefer_xml {
            vec!["xml", "text"]
        } else {
            vec!["text", "xml"]
        };

        let mut last_non_404_error: Option<String> = None;

        for format in &formats {
            let url = match *format {
                "xml" => format!(
                    "{}/rfc/rfc{}.xml",
                    self.config.base_url, rfc_number
                ),
                _ => format!(
                    "{}/rfc/rfc{}.txt",
                    self.config.base_url, rfc_number
                ),
            };

            tracing::debug!("Fetching {}", url);
            let response = self.client.get(&url).send().await.map_err(|e| {
                RfcAnalyzerError::Fetch {
                    rfc: rfc_number,
                    source: e,
                }
            })?;

            match response.status().as_u16() {
                200 => {
                    let content = response.text().await.map_err(|e| {
                        RfcAnalyzerError::Fetch {
                            rfc: rfc_number,
                            source: e,
                        }
                    })?;

                    // Cache the successful format
                    self.format_cache
                        .lock()
                        .unwrap()
                        .insert(rfc_number, format.to_string());

                    // Compute content hash
                    let mut hasher = Sha256::new();
                    hasher.update(content.as_bytes());
                    let content_hash = format!("{:x}", hasher.finalize());

                    return Ok(FetchResult {
                        rfc_number,
                        content,
                        format: format.to_string(),
                        content_hash,
                    });
                }
                404 => {
                    tracing::debug!("404 for {} format of RFC {}", format, rfc_number);
                    continue;
                }
                status => {
                    let msg = format!(
                        "HTTP {} fetching RFC {} ({})", status, rfc_number, format
                    );
                    tracing::warn!("{}, trying next format", msg);
                    last_non_404_error = Some(msg);
                    continue;
                }
            }
        }

        // If we got a non-404 error on any attempt, report that instead
        // of RfcNotFound (which implies the RFC doesn't exist)
        if let Some(err_msg) = last_non_404_error {
            return Err(RfcAnalyzerError::Config(err_msg));
        }
        Err(RfcAnalyzerError::RfcNotFound(rfc_number))
    }

    /// Polite delay between requests. Call this between fetch() calls.
    pub async fn delay(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(
            self.config.request_delay_ms,
        ))
        .await;
    }
}

/// Compute SHA-256 hex hash of a string.
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}
```

## 3. src/rfc/parser_xml.rs

Parses RFC 7991+ XML format. Uses `quick-xml` for streaming parse.

The structure of an RFC XML document (simplified):

```xml
<rfc number="9293" docName="..." submissionType="IETF" category="std">
  <front>
    <title>Transmission Control Protocol (TCP)</title>
    <date year="2022" month="August"/>
    <seriesInfo name="RFC" value="9293"/>
    <seriesInfo name="STD" value="7"/>
  </front>
  <middle>
    <section anchor="intro" numbered="true" pn="section-1">
      <name>Introduction</name>
      <t>Text with <xref target="RFC0793" section="3"/>...</t>
      <section anchor="sub" pn="section-1.1">
        <name>Subsection</name>
        <t>More text...</t>
      </section>
    </section>
  </middle>
  <back>
    <references>
      <name>Normative References</name>
      <reference anchor="RFC0793">
        <front><title>...</title></front>
        <seriesInfo name="RFC" value="793"/>
      </reference>
    </references>
    <references>
      <name>Informative References</name>
      ...
    </references>
  </back>
</rfc>
```

Implementation approach: Use `quick_xml::Reader` in a streaming fashion.
Track a stack of element names to know our position in the document tree.
Extract sections, xrefs, and references as we encounter them.

```rust
use crate::error::{RfcAnalyzerError, Result};
use crate::rfc::model::*;
use chrono::NaiveDate;
use quick_xml::events::Event;
use quick_xml::Reader;
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
                        let section_num = pn.as_deref()
                            .and_then(|p| p.strip_prefix("section-"))
                            .unwrap_or("")
                            .to_string();
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
                        if let Some(ref mut sec) = current_section {
                            if sec.title.is_empty() {
                                sec.title = text.clone();
                            }
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
    let stripped = target.strip_prefix("RFC").or_else(|| target.strip_prefix("rfc"))?;
    stripped.trim().parse().ok()
}

/// Extract <date year="..." month="..."/> from raw XML.
fn extract_date_from_xml(xml: &str) -> Option<NaiveDate> {
    // Simple regex approach for robustness
    let re = regex::Regex::new(
        r#"<date\s+year="(\d{4})"\s+month="(\w+)"(?:\s+day="(\d+)")?"#
    ).ok()?;
    let caps = re.captures(xml)?;
    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month_str = caps.get(2)?.as_str();
    let day: u32 = caps.get(3).and_then(|d| d.as_str().parse().ok()).unwrap_or(1);
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
```

**Important implementation note**: The XML parser above is a starting
framework. Real RFC XML has more complexity (nested sections, appendices,
`<artwork>`, `<sourcecode>`, `<figure>`, etc.). The implementer should:
1. Get the basic structure working first
2. Test against a real RFC XML file (fetch RFC 9293 XML)
3. Iterate on edge cases found in real data

The parser does NOT need to be perfect — it needs to extract sections,
titles, cross-references, and references reliably enough for the graph
builder and LLM stages to work with.

## 4. src/rfc/parser_text.rs

Parses classic plain-text RFC format using regex.

Plain-text RFCs have a consistent-ish structure:

```
                              RFC Title

Status of This Memo
   ...

Abstract
   ...

Table of Contents
   1.  Introduction  . . . . . . . . . . . . . . . . . . . .   3
   2.  Key Words  . . . . . . . . . . . . . . . . . . . . . .   4

1.  Introduction

   Text of section 1...

1.1.  Subsection

   Text of subsection...

2.  Key Words

   ...

Appendix A.  Something

   ...

References

   Normative References

   [RFC793]  Postel, J., "Transmission Control Protocol", STD 7,
             RFC 793, DOI 10.17487/RFC0793, September 1981,
             <https://www.rfc-editor.org/info/rfc793>.

   Informative References

   [RFC1122]  ...
```

```rust
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
        if trimmed == "Status of This Memo" || trimmed == "Abstract"
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
    s.split(|c: char| c == ',' || c == ' ')
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
    let section_re = Regex::new(
        r"(?m)^(\d+(?:\.\d+)*)\.\s{2,}(.+)$"
    ).unwrap();
    let appendix_re = Regex::new(
        r"(?m)^(?:Appendix\s+)?([A-Z](?:\.\d+)*)\.\s{2,}(.+)$"
    ).unwrap();

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
    let xref_section_re = Regex::new(
        r"Section\s+(\d+(?:\.\d+)*)\s+of\s+\[RFC\s*(\d+)\]"
    ).unwrap();
    let internal_section_re = Regex::new(
        r"[Ss]ee\s+Section\s+(\d+(?:\.\d+)*)"
    ).unwrap();

    for i in 0..matches.len() {
        let (pos, ref num, ref title) = matches[i];
        let next_pos = matches.get(i + 1).map(|(p, _, _)| *p).unwrap_or(content.len());

        // Find the text start (after the header line)
        let header_end = content[pos..].find('\n').map(|p| pos + p + 1).unwrap_or(pos);
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
                    x.target_rfc == Some(RfcNumber(target_rfc))
                        && x.target_section.is_some()
                });
                if !already_found {
                    cross_refs.push(CrossRef {
                        target_rfc: Some(RfcNumber(target_rfc)),
                        target_section: None,
                        context: extract_sentence_around(
                            &text, cap.get(0).unwrap().start()
                        ),
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
        if !trimmed.is_empty() && !trimmed.starts_with('[') && !trimmed.starts_with(' ')
            && in_references
            && (trimmed == "Acknowledgments" || trimmed == "Authors' Addresses"
                || trimmed == "Appendix" || trimmed.starts_with("Appendix"))
        {
            break;
        }

        // Parse reference entries: [RFC793] Postel, J., "Title", ...
        let ref_re = Regex::new(r"^\s*\[([^\]]+)\]").unwrap();
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
    let stripped = label.strip_prefix("RFC").or_else(|| label.strip_prefix("rfc"))?;
    stripped.trim().parse().ok()
}

/// Extract the first quoted string from a line.
fn extract_quoted_title(line: &str) -> String {
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start + 1..].find('"') {
            return line[start + 1..start + 1 + end].to_string();
        }
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
    let end = text[pos..].find('.').map(|p| pos + p + 1).unwrap_or(text.len());
    let sentence = text[start..end].trim();
    if sentence.len() <= 200 {
        sentence.to_string()
    } else {
        format!("{}...", &sentence[..197])
    }
}

// Make parse_month available to parser_text via re-export from parser_xml
// (it's already pub in parser_xml)
```

**Implementation note**: Like the XML parser, this plain-text parser is a
best-effort starting point. RFC formatting has varied over 50+ years. The
implementer should test against a few real RFCs (e.g., RFC 793, RFC 1035,
RFC 9293) and adjust the regexes as needed.

## 5. src/rfc/index.rs

Fetches the RFC index from rfc-editor.org to look up metadata for RFCs
without downloading the full document. This is used to populate
`obsoleted_by` and `updated_by` fields.

```rust
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
    let content = client.get(&url).send().await
        .map_err(|e| crate::error::RfcAnalyzerError::Config(
            format!("Failed to fetch RFC index: {}", e)
        ))?
        .text().await
        .map_err(|e| crate::error::RfcAnalyzerError::Config(
            format!("Failed to read RFC index: {}", e)
        ))?;

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
            if let Some((num, _)) = current_entry.take() {
                if let Some(entry) = parse_index_entry(num, &current_text) {
                    entries.insert(num, entry);
                }
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
            if let Some((num, _)) = current_entry.take() {
                if let Some(entry) = parse_index_entry(num, &current_text) {
                    entries.insert(num, entry);
                }
            }
            current_text.clear();
        }
    }

    // Don't forget last entry
    if let Some((num, _)) = current_entry {
        if let Some(entry) = parse_index_entry(num, &current_text) {
            entries.insert(num, entry);
        }
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
        .split(|c: char| c == ',' || c == ' ')
        .filter_map(|s| {
            let s = s.trim();
            s.strip_prefix("RFC")
                .and_then(|n| n.parse::<u32>().ok())
                .map(RfcNumber)
        })
        .collect()
}
```

## 6. src/rfc/mod.rs (updated)

```rust
pub mod fetcher;
pub mod index;
pub mod model;
pub mod parser_text;
pub mod parser_xml;
```

## 7. src/lib.rs (updated)

```rust
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod rfc;
```

## 8. src/main.rs (updated)

Replace the Phase 1 stub with the full CLI dispatch.

```rust
use anyhow::Result;
use clap::Parser;
use rfc_analyzer::cli::{Cli, Command};
use rfc_analyzer::config::Config;
use rfc_analyzer::db;
use rfc_analyzer::error::RfcAnalyzerError;
use rfc_analyzer::rfc::fetcher::RfcFetcher;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(filter))
        )
        .init();

    // Load config
    let config = Config::load(&cli.config)?;

    // Open database
    let conn = db::open_database(&cli.db).await?;

    match cli.command {
        Command::Map {
            rfcs,
            protocol,
            depth,
            normative_only,
        } => {
            cmd_map(&conn, &config, rfcs, protocol, depth, normative_only).await?;
        }
        Command::Show { rfc } => {
            cmd_show(&conn, rfc).await?;
        }
        Command::Clear { scope, yes } => {
            cmd_clear(&conn, &scope, yes).await?;
        }
        _ => {
            eprintln!("Command not yet implemented. Available: map, show, clear");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// The `map` command: fetch, parse, and store RFCs.
async fn cmd_map(
    conn: &tokio_rusqlite::Connection,
    config: &Config,
    seed_rfcs: Vec<u32>,
    protocol: Option<String>,
    depth: u32,
    normative_only: bool,
) -> Result<()> {
    use rfc_analyzer::db::rfc_store;
    use rfc_analyzer::rfc::{parser_xml, parser_text, index};
    use std::collections::HashSet;

    if protocol.is_none() {
        tracing::warn!(
            "RFCs will be cached but not associated with a protocol. \
             Use --protocol <name> to enable model/analyze commands."
        );
    }

    let fetcher = RfcFetcher::new(config.fetcher.clone());

    // Fetch the RFC index for obsoleted_by/updated_by metadata
    tracing::info!("Fetching RFC index...");
    let rfc_index = index::fetch_rfc_index(&config.fetcher.base_url).await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch RFC index: {}. Continuing without it.", e);
            std::collections::HashMap::new()
        });

    // BFS expansion: process seed RFCs, then their references, up to `depth`
    let mut to_process: Vec<u32> = seed_rfcs.clone();
    let mut processed: HashSet<u32> = HashSet::new();
    let mut current_depth = 0u32;
    let mut is_seed = true;

    while !to_process.is_empty() && current_depth <= depth {
        let batch = std::mem::take(&mut to_process);
        let total = batch.len();
        tracing::info!(
            "Depth {}: processing {} RFCs",
            current_depth, total
        );

        let mut next_batch: Vec<u32> = Vec::new();

        for (i, rfc_num) in batch.into_iter().enumerate() {
            if processed.contains(&rfc_num) {
                continue;
            }
            processed.insert(rfc_num);

            tracing::info!("Fetching RFC {}/{}: RFC {}", i + 1, total, rfc_num);

            // Check cache
            if let Some(existing_hash) = rfc_store::get_content_hash(conn, rfc_num).await? {
                tracing::info!("RFC {} already cached (hash: {}...)", rfc_num, &existing_hash[..8]);
                // Still need to collect references for expansion
                if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num).await? {
                    if current_depth < depth {
                        next_batch.extend(collect_references(&rfc, normative_only));
                    }
                    if let Some(ref proto) = protocol {
                        rfc_store::assign_protocol(conn, proto, rfc_num).await?;
                    }
                    continue;
                }
            }

            // Fetch
            let fetch_result = match fetcher.fetch(rfc_num).await {
                Ok(r) => r,
                Err(RfcAnalyzerError::RfcNotFound(_)) => {
                    if is_seed {
                        anyhow::bail!("Seed RFC {} not found (404)", rfc_num);
                    }
                    tracing::warn!("RFC {} not found (404), skipping", rfc_num);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            // Parse
            let mut rfc = if fetch_result.format == "xml" {
                parser_xml::parse_xml(
                    rfc_num, &fetch_result.content, &fetch_result.content_hash
                )?
            } else {
                parser_text::parse_text(
                    rfc_num, &fetch_result.content, &fetch_result.content_hash
                )?
            };

            // Enrich with index metadata (obsoleted_by, updated_by)
            if let Some(idx_entry) = rfc_index.get(&rfc_num) {
                rfc.obsoleted_by = idx_entry.obsoleted_by.clone();
                rfc.updated_by = idx_entry.updated_by.clone();
            }

            tracing::info!(
                "Parsed RFC {} ({}) - {} sections, {} references",
                rfc_num, rfc.format, rfc.sections.len(), rfc.references.len()
            );

            // Store
            rfc_store::upsert_rfc(conn, &rfc).await?;

            // Protocol assignment
            if let Some(ref proto) = protocol {
                rfc_store::assign_protocol(conn, proto, rfc_num).await?;
            }

            // Collect references for next depth level
            if current_depth < depth {
                next_batch.extend(collect_references(&rfc, normative_only));
            }

            // Polite delay
            fetcher.delay().await;
        }

        to_process = next_batch.into_iter()
            .filter(|n| !processed.contains(n))
            .collect();
        current_depth += 1;
        is_seed = false;
    }

    tracing::info!("Map complete: {} RFCs processed", processed.len());
    if let Some(ref proto) = protocol {
        let assigned = rfc_store::get_protocol_rfcs(conn, proto).await?;
        tracing::info!("Protocol '{}': {} RFCs assigned", proto, assigned.len());
    }

    Ok(())
}

/// Collect all RFC numbers referenced by an Rfc struct.
fn collect_references(rfc: &rfc_analyzer::rfc::model::Rfc, normative_only: bool) -> Vec<u32> {
    let mut refs: Vec<u32> = Vec::new();

    // Always follow obsoletes/updates regardless of normative_only
    refs.extend(rfc.obsoletes.iter().map(|r| r.0));
    refs.extend(rfc.updates.iter().map(|r| r.0));

    // Formal references
    for reference in &rfc.references {
        if let Some(target) = reference.target_rfc {
            if reference.is_normative || !normative_only {
                refs.push(target.0);
            }
        }
    }

    // Inline cross-references (always followed — they don't have
    // normative/informative classification)
    for section in &rfc.sections {
        for xref in &section.cross_refs {
            if let Some(target) = xref.target_rfc {
                refs.push(target.0);
            }
        }
    }

    refs.sort();
    refs.dedup();
    refs
}

/// The `show` command: display info about a cached RFC.
async fn cmd_show(conn: &tokio_rusqlite::Connection, rfc_number: u32) -> Result<()> {
    use rfc_analyzer::db::rfc_store;

    match rfc_store::get_rfc(conn, rfc_number).await? {
        Some(rfc) => {
            println!("RFC {}: {}", rfc.number.0, rfc.title);
            println!("Status: {}", rfc.status);
            println!("Format: {}", rfc.format);
            println!("Date: {}", rfc.date);
            println!("Sections: {}", rfc.sections.len());
            println!("References: {}", rfc.references.len());
            if !rfc.obsoletes.is_empty() {
                println!("Obsoletes: {:?}", rfc.obsoletes.iter().map(|r| r.0).collect::<Vec<_>>());
            }
            if !rfc.updates.is_empty() {
                println!("Updates: {:?}", rfc.updates.iter().map(|r| r.0).collect::<Vec<_>>());
            }
            if !rfc.obsoleted_by.is_empty() {
                println!("Obsoleted by: {:?}", rfc.obsoleted_by.iter().map(|r| r.0).collect::<Vec<_>>());
            }
            if !rfc.updated_by.is_empty() {
                println!("Updated by: {:?}", rfc.updated_by.iter().map(|r| r.0).collect::<Vec<_>>());
            }
            // Show first few sections
            for section in rfc.sections.iter().take(10) {
                println!("  {} {} ({} chars, {} xrefs)",
                    section.number, section.title,
                    section.text.len(), section.cross_refs.len());
            }
            if rfc.sections.len() > 10 {
                println!("  ... and {} more sections", rfc.sections.len() - 10);
            }
        }
        None => {
            eprintln!("RFC {} not found in database. Run 'map {}' first.", rfc_number, rfc_number);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// The `clear` command: remove stored data.
async fn cmd_clear(conn: &tokio_rusqlite::Connection, scope: &str, yes: bool) -> Result<()> {
    if !yes {
        eprint!("Clear {} data? This cannot be undone. [y/N] ", scope);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let scope_owned = scope.to_string();
    let scope_log = scope_owned.clone();
    conn.call(move |conn| {
        match scope_owned.as_str() {
            "all" => {
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM analysis_runs;
                     DELETE FROM dep_edges;
                     DELETE FROM cross_refs;
                     DELETE FROM sections;
                     DELETE FROM protocol_rfcs;
                     DELETE FROM rfcs;"
                )?;
            }
            "rfcs" => {
                // Cascading: remove everything that depends on RFCs
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM analysis_runs;
                     DELETE FROM dep_edges;
                     DELETE FROM cross_refs;
                     DELETE FROM sections;
                     DELETE FROM protocol_rfcs;
                     DELETE FROM rfcs;"
                )?;
            }
            "graphs" => {
                conn.execute_batch("DELETE FROM dep_edges;")?;
            }
            "analysis" => {
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM analysis_runs;"
                )?;
            }
            other => {
                return Err(rusqlite::Error::InvalidParameterName(
                    format!("Unknown scope: {}", other)
                ));
            }
        }
        Ok(())
    })
    .await?;

    tracing::info!("Cleared {} data", scope_log);
    Ok(())
}
```

## 9. Tests

Phase 2 tests focus on real data validation. Create the following:

### tests/fixtures/ (create directory)

Download and save these for snapshot testing:
- Fetch a small excerpt of RFC 9293 XML and save as `tests/fixtures/rfc9293_excerpt.xml`
- Fetch a small excerpt of RFC 793 text and save as `tests/fixtures/rfc793_excerpt.txt`

The implementer should create these by fetching the real RFCs and saving
relevant portions (first ~200 lines for text, a representative section
block for XML).

### src/rfc/parser_xml.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc_list() {
        let result = parse_rfc_list("793, 879, 2873");
        assert_eq!(result, vec![RfcNumber(793), RfcNumber(879), RfcNumber(2873)]);
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
```

### src/rfc/parser_text.rs — tests

```rust
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
```

### tests/fetch_real.rs — integration test (ignored by default)

```rust
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
```

### src/rfc/index.rs — tests

```rust
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
```

## 10. Verification

After implementation:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all unit tests
3. `cargo run -- map 9293 --depth 0 --protocol tcp` fetches and stores RFC 9293
4. `cargo run -- show 9293` displays RFC info
5. `cargo run -- map 9293 --depth 1 --protocol tcp` fetches 9293 + references
6. `cargo test -- --ignored test_fetch_real` passes against live rfc-editor.org

## 11. What This Phase Does NOT Include

- Graph construction (Phase 3) — `dep_edges` table is created but not populated
- LLM integration (Phase 4)
- The `model`, `analyze`, `run`, `graph` commands (stubs only)
