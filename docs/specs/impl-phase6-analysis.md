# Phase 6: Security Analysis — Implementation Spec

This document is self-contained. It builds on Phase 1-5 (which must be
complete). Implement exactly what is specified here.

**Development process**: Follow `docs/specs/dev-guidelines.md` — Red-Green
TDD, commit after each significant change or when tests pass, 85%+ coverage
target with `cargo tarpaulin`.

## Overview

Phase 6 implements Stage 3 of the pipeline: security analysis. It takes
state machines and parsed sections from a protocol, runs per-category
LLM analysis with section selection heuristics, deduplicates and ranks
leads, generates a JSON report, and persists results with full run
provenance and resumability.

It also implements the `analyze` and `run` commands, completing the full
pipeline.

At the end of Phase 6, `rfc-analyzer run tcp 9293 --depth 1` performs
the complete map→model→analyze pipeline and outputs a JSON report with
ranked security leads.

## Files to Create / Modify

```
NEW:
  src/pipeline/analysis.rs     -- Stage 3: per-category security analysis
  src/pipeline/section_select.rs -- section selection heuristic
  src/output/mod.rs            -- output module re-exports
  src/output/report.rs         -- AnalysisReport assembly and serialization
  src/commands/analyze.rs      -- cmd_analyze command handler
  src/commands/run.rs          -- cmd_run (chains map → model → analyze)

MODIFY:
  src/pipeline/mod.rs          -- add analysis, section_select modules
  src/commands/mod.rs          -- add analyze, run modules
  src/db/analysis_store.rs     -- add security lead persistence
  src/main.rs                  -- wire up Analyze and Run command dispatch
```

## 1. src/pipeline/section_select.rs

Section selection heuristic: for each attack category, select the most
relevant sections based on keywords, state machine references, and
"Security Considerations" title.

```rust
use crate::rfc::model::{RfcNumber, Section};

/// Attack categories with their selection keywords.
/// Keywords use substring matching (case-insensitive).
pub const CATEGORY_KEYWORDS: &[(&str, &[&str])] = &[
    ("MissingValidation", &["validate", "check", "verify", "parse", "reject", "malformed", "invalid"]),
    ("ReplayAttack", &["nonce", "sequence", "timestamp", "freshness", "idempotent", "replay"]),
    ("InformationLeak", &["error", "diagnostic", "metadata", "header", "reveal", "expose", "disclose"]),
    ("OversizedPayload", &["length", "size", "maximum", "limit", "truncat", "overflow", "buffer"]),
    ("StateConfusion", &["state", "transition", "unexpected", "simultaneous", "order", "sequence"]),
    ("AuthBypass", &["authenticat", "authoriz", "credential", "identity", "trust", "verify"]),
    ("DenialOfService", &["resource", "limit", "exhaust", "flood", "timeout", "retry", "amplif"]),
    ("Downgrade", &["version", "negotiat", "fallback", "legacy", "backward", "compatible"]),
    ("RaceCondition", &["concurrent", "simultaneous", "atomic", "lock", "order", "between"]),
    ("ImplementationAmbiguity", &["undefined", "unspecified", "implementation-defined", "MAY", "OPTIONAL", "local matter"]),
];

/// Select sections relevant to a specific attack category.
/// Returns sections sorted by relevance (most relevant first).
pub fn select_sections_for_category(
    category: &str,
    all_sections: &[(RfcNumber, Section)],
    state_machine_section_refs: &[(u32, String)], // (rfc, section) from state machines
) -> Vec<(RfcNumber, &Section)> {
    let keywords = CATEGORY_KEYWORDS.iter()
        .find(|(cat, _)| *cat == category)
        .map(|(_, kws)| *kws)
        .unwrap_or(&[]);

    let mut scored: Vec<(i32, RfcNumber, &Section)> = all_sections.iter()
        .map(|(rfc, section)| {
            let score = score_section_for_category(
                section, keywords, state_machine_section_refs, *rfc
            );
            (score, *rfc, section)
        })
        .filter(|(score, _, _)| *score > 0)
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    scored.into_iter().map(|(_, rfc, sec)| (rfc, sec)).collect()
}

/// Score a section's relevance to an attack category.
fn score_section_for_category(
    section: &Section,
    keywords: &[&str],
    state_machine_refs: &[(u32, String)],
    rfc_number: RfcNumber,
) -> i32 {
    let mut score = 0i32;
    let text_lower = section.text.to_lowercase();
    let title_lower = section.title.to_lowercase();

    // +3: "Security Considerations" in title (always relevant)
    if title_lower.contains("security") {
        score += 3;
    }

    // +2: Referenced by a state machine
    let is_sm_ref = state_machine_refs.iter()
        .any(|(rfc, sec)| *rfc == rfc_number.0 && sec == &section.number);
    if is_sm_ref {
        score += 2;
    }

    // +1 per keyword match (up to +3 max from keywords)
    let keyword_hits = keywords.iter()
        .filter(|kw| {
            // Case-insensitive for most keywords, case-sensitive for MAY/OPTIONAL
            if kw.chars().all(|c| c.is_uppercase()) {
                section.text.contains(*kw)
            } else {
                text_lower.contains(&kw.to_lowercase())
            }
        })
        .count();
    score += (keyword_hits as i32).min(3);

    score
}

/// Get all attack category names.
pub fn all_categories() -> Vec<&'static str> {
    CATEGORY_KEYWORDS.iter().map(|(cat, _)| *cat).collect()
}

/// Parse category filter from CLI input.
/// Maps lowercase/underscore/hyphen variants to canonical CamelCase names.
/// E.g. "missing_validation" or "missing-validation" → "MissingValidation"
pub fn resolve_categories(filter: Option<&[String]>) -> Vec<&'static str> {
    match filter {
        None => all_categories(),
        Some(names) => {
            let all = all_categories();
            names.iter()
                .filter_map(|name| {
                    let normalized = name.to_lowercase().replace('-', "").replace('_', "");
                    all.iter().find(|cat| cat.to_lowercase() == normalized).copied()
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::model::*;

    fn make_section(num: &str, title: &str, text: &str) -> Section {
        Section {
            number: num.to_string(),
            title: title.to_string(),
            anchor: None,
            depth: 1,
            text: text.to_string(),
            cross_refs: Vec::new(),
            pn: None,
        }
    }

    #[test]
    fn test_security_section_always_selected() {
        let sections = vec![
            (RfcNumber(9293), make_section("10", "Security Considerations", "Be careful.")),
            (RfcNumber(9293), make_section("1", "Introduction", "This is TCP.")),
        ];
        let selected = select_sections_for_category("MissingValidation", &sections, &[]);
        assert!(!selected.is_empty());
        assert_eq!(selected[0].1.number, "10"); // Security first
    }

    #[test]
    fn test_keyword_matching() {
        let sections = vec![
            (RfcNumber(1), make_section("3", "Validation", "Implementations MUST validate all input fields.")),
            (RfcNumber(1), make_section("4", "Overview", "This section provides an overview.")),
        ];
        let selected = select_sections_for_category("MissingValidation", &sections, &[]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.number, "3");
    }

    #[test]
    fn test_state_machine_refs_boost() {
        let sections = vec![
            (RfcNumber(1), make_section("3", "States", "The connection has states.")),
            (RfcNumber(1), make_section("4", "Other", "The connection has states.")),
        ];
        // Section 3 is referenced by state machine
        let sm_refs = vec![(1u32, "3".to_string())];
        let selected = select_sections_for_category("StateConfusion", &sections, &sm_refs);
        // Section 3 should rank higher (has SM ref bonus)
        assert_eq!(selected[0].1.number, "3");
    }

    #[test]
    fn test_case_sensitive_keywords() {
        let sections = vec![
            (RfcNumber(1), make_section("1", "Options", "Implementations MAY support this.")),
            (RfcNumber(1), make_section("2", "May", "In the month of may, things happen.")),
        ];
        let selected = select_sections_for_category("ImplementationAmbiguity", &sections, &[]);
        // Only section 1 should match (uppercase MAY)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.number, "1");
    }

    #[test]
    fn test_resolve_categories() {
        let all = resolve_categories(None);
        assert_eq!(all.len(), 10);

        let filtered = resolve_categories(Some(&[
            "missing_validation".to_string(),
            "replay_attack".to_string(),
        ]));
        assert_eq!(filtered.len(), 2);
    }
}
```

## 2. src/pipeline/analysis.rs

The Stage 3 pipeline: per-category security analysis, deduplication,
scoring, and persistence.

```rust
use crate::db::{analysis_store, rfc_store};
use crate::error::{RfcAnalyzerError, Result};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::section_select;
use crate::pipeline::summarize;
use crate::rfc::model::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_rusqlite::Connection;
use uuid::Uuid;

/// LLM response type for a security lead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeadResponse {
    pub technique_name: String,
    pub category: String,
    pub severity: String,
    pub confidence: f64,
    pub description: String,
    pub rfc_references: Vec<LeadRfcRef>,
    #[serde(default)]
    pub prerequisites: Vec<String>,
    #[serde(default)]
    pub entities_involved: Vec<String>,
    #[serde(default)]
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeadRfcRef {
    pub rfc: u32,
    pub section: String,
    #[serde(default)]
    pub quote: Option<String>,
}

/// A processed security lead ready for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLead {
    pub id: String,
    pub technique_name: String,
    pub category: String,
    pub severity: String,
    pub confidence: f64,
    pub description: String,
    pub rfc_references: Vec<LeadRfcRef>,
    pub prerequisites: Vec<String>,
    pub entities_involved: Vec<String>,
    pub mitigation: Option<String>,
    pub fingerprint: String,
}

/// Result of a Stage 3 analysis run, including provenance metadata.
pub struct Stage3Result {
    pub leads: Vec<SecurityLead>,
    pub run_id: Option<i64>,
    pub total_tokens: u64,
    pub input_hash: String,
}

/// Severity ordering for ranking (higher = more severe).
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "informational" => 1,
        _ => 0,
    }
}

/// Run Stage 3: security analysis.
/// Returns a Stage3Result with deduplicated, ranked security leads and provenance.
pub async fn run_stage3(
    conn: &Connection,
    llm: &LlmClient,
    protocol: &str,
    category_filter: Option<&[String]>,
    min_severity: &str,
    llm_config: &crate::config::LlmConfig,
) -> Result<Stage3Result> {
    // Get protocol RFCs
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    if rfc_numbers.is_empty() {
        return Err(RfcAnalyzerError::NoMappedRfcs(protocol.to_string()));
    }

    // Resolve and deduplicate categories (dedup before hashing for consistency)
    let categories: Vec<&str> = {
        let resolved = section_select::resolve_categories(category_filter);
        let mut seen = std::collections::HashSet::new();
        resolved.into_iter().filter(|c| seen.insert(*c)).collect()
    };
    if categories.is_empty() {
        tracing::warn!("No valid categories after filtering");
        return Ok(Stage3Result {
            leads: Vec::new(),
            run_id: None,
            total_tokens: 0,
            input_hash: String::new(),
        });
    }

    // Compute input hash (categories are already deduped)
    let input_hash = compute_stage3_hash(
        conn, &rfc_numbers, &categories, llm.model(), llm_config, protocol
    ).await?;

    // Check for completed run
    if let Some(existing_run_id) = analysis_store::find_completed_run(
        conn, protocol, "analyze", &input_hash
    ).await? {
        tracing::info!("Stage 3 already completed with matching inputs, loading results");
        let leads = load_existing_leads(conn, existing_run_id, min_severity).await?;
        return Ok(Stage3Result {
            leads,
            run_id: Some(existing_run_id),
            total_tokens: 0,
            input_hash: input_hash.clone(),
        });
    }

    // Check for resumable run
    let run_id = if let Some(existing_run) = analysis_store::find_resumable_run(
        conn, protocol, "analyze", &input_hash
    ).await? {
        tracing::info!("Resuming interrupted Stage 3 run {}", existing_run);
        existing_run
    } else {
        analysis_store::create_run(
            conn, protocol, "analyze", Some(llm.model()),
            &rfc_numbers, None, None, None,
            Some(&categories.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            prompts::PROMPT_VERSION, &input_hash,
        ).await?
    };

    let mut total_tokens: u64 = 0;
    let mut all_leads: Vec<SecurityLead> = Vec::new();

    // Load already-persisted leads from prior attempts of this run (for resume)
    // This ensures the final result includes leads from completed categories
    let prior_leads = load_existing_leads(conn, run_id, min_severity).await
        .unwrap_or_default();
    all_leads.extend(prior_leads);


    // Load all sections
    let mut all_sections: Vec<(RfcNumber, Section)> = Vec::new();
    for rfc_num in &rfc_numbers {
        if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num.0).await? {
            for section in rfc.sections {
                all_sections.push((*rfc_num, section));
            }
        }
    }

    // Load state machines for context
    let state_machines = analysis_store::get_state_machines(conn, protocol, None).await?;
    let sm_summary = format_state_machine_summary(&state_machines);
    let sm_section_refs = extract_sm_section_refs(&state_machines);

    // Get completed categories for resumability
    let completed_categories = analysis_store::get_completed_work_items(
        conn, run_id, "category"
    ).await?;

    // Run analysis for each category
    for (i, category) in categories.iter().enumerate() {
        // Check cancellation
        if llm.cancel_token().is_cancelled() {
            tracing::info!("Cancelled, persisting partial results");
            analysis_store::complete_run(
                conn, run_id, "interrupted", total_tokens, &rfc_numbers, None
            ).await?;
            return Ok(Stage3Result {
                leads: all_leads,
                run_id: Some(run_id),
                total_tokens,
                input_hash,
            });
        }

        // Skip if already completed (resumability)
        if completed_categories.contains(&category.to_string()) {
            tracing::debug!("Category '{}' already completed, skipping", category);
            continue;
        }

        tracing::info!("Analyzing category {}/{}: {}", i + 1, categories.len(), category);
        analysis_store::upsert_work_item(conn, run_id, "category", category, "running").await?;

        // Select relevant sections for this category
        let selected = section_select::select_sections_for_category(
            category, &all_sections, &sm_section_refs
        );

        if selected.is_empty() {
            tracing::warn!("No relevant sections for category '{}', skipping", category);
            analysis_store::complete_work_item(
                conn, run_id, "category", category, 0, false, Some("No relevant sections")
            ).await?;
            continue;
        }

        // Build sections text with summarize-to-fit
        let system_prompt_tokens = llm.estimate_tokens(prompts::INJECTION_DEFENSE) + 300;
        let sm_tokens = llm.estimate_tokens(&sm_summary);
        let budget = llm.context_budget(system_prompt_tokens + sm_tokens);

        let cluster_ids: Vec<(u32, String)> = selected.iter()
            .map(|(rfc, sec)| (rfc.0, sec.number.clone()))
            .collect();

        let (sections_text, dropped) = summarize::summarize_to_fit(
            &all_sections.iter().map(|(r, s)| (*r, s)).collect::<Vec<_>>(),
            &cluster_ids,
            budget,
            &rfc_numbers,
        );

        if sections_text.is_empty() {
            analysis_store::complete_work_item(
                conn, run_id, "category", category, 0, true, Some("All sections dropped")
            ).await?;
            continue;
        }

        // Build and send the security analysis prompt
        let (system, user) = prompts::security_analysis_prompt(
            category, &sm_summary, &sections_text
        );
        let messages = vec![
            ChatMessage { role: "system".to_string(), content: system },
            ChatMessage { role: "user".to_string(), content: user },
        ];

        let category_tokens: u64;
        match crate::llm::response::parse_json_array_partial::<LeadResponse>(
            &match llm.chat(messages).await {
                Ok((content, usage)) => {
                    category_tokens = usage.total_tokens;
                    total_tokens += category_tokens;
                    content
                }
                Err(RfcAnalyzerError::LlmContextOverflow) => {
                    tracing::warn!("Category '{}': context overflow", category);
                    analysis_store::complete_work_item(
                        conn, run_id, "category", category, 0, false,
                        Some("Context overflow, skipped")
                    ).await?;
                    continue;
                }
                Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                    tracing::warn!("Category '{}': content refused: {}", category, detail);
                    analysis_store::complete_work_item(
                        conn, run_id, "category", category, 0, false, Some(&detail)
                    ).await?;
                    continue;
                }
                Err(e) => {
                    analysis_store::complete_run(
                        conn, run_id, "failed", total_tokens, &rfc_numbers, Some(&e.to_string())
                    ).await?;
                    return Err(e);
                }
            }
        ) {
            Ok(leads) => {
                let processed: Vec<SecurityLead> = leads.into_iter()
                    .map(|lead| process_lead(lead, protocol))
                    .collect();

                tracing::info!(
                    "Category '{}': {} leads found", category, processed.len()
                );

                // Persist leads incrementally
                for lead in &processed {
                    store_lead(conn, protocol, lead, run_id, &input_hash).await?;
                }
                all_leads.extend(processed);

                let notes = if dropped.is_empty() {
                    None
                } else {
                    Some(format!("truncated: {}", dropped.join(", ")))
                };
                analysis_store::complete_work_item(
                    conn, run_id, "category", category, category_tokens, false, notes.as_deref()
                ).await?;
            }
            Err(e) => {
                tracing::warn!("Category '{}': failed to parse leads: {}", category, e);
                analysis_store::complete_work_item(
                    conn, run_id, "category", category, 0, true, Some(&e.to_string())
                ).await?;
            }
        }
    }

    // Mark run as completed
    analysis_store::complete_run(
        conn, run_id, "completed", total_tokens, &rfc_numbers, None
    ).await?;

    // Deduplicate and rank
    let deduplicated = deduplicate_leads(&all_leads);
    let mut ranked = filter_by_severity(deduplicated, min_severity);
    rank_leads(&mut ranked);

    tracing::info!("Stage 3 complete: {} leads (after dedup/filter)", ranked.len());
    Ok(Stage3Result {
        leads: ranked,
        run_id: Some(run_id),
        total_tokens,
        input_hash,
    })
}

/// Process a raw LLM lead response into a SecurityLead with ID and fingerprint.
fn process_lead(lead: LeadResponse, protocol: &str) -> SecurityLead {
    let fingerprint = compute_fingerprint(protocol, &lead);
    SecurityLead {
        id: Uuid::new_v4().to_string(),
        technique_name: lead.technique_name,
        category: lead.category,
        severity: lead.severity,
        confidence: lead.confidence.clamp(0.0, 1.0),
        description: lead.description,
        rfc_references: lead.rfc_references,
        prerequisites: lead.prerequisites,
        entities_involved: lead.entities_involved,
        mitigation: lead.mitigation,
        fingerprint,
    }
}

/// Compute deterministic fingerprint for cross-run comparison.
/// SHA-256(protocol | category | normalized_technique_name | sorted_rfc_section_refs)
fn compute_fingerprint(protocol: &str, lead: &LeadResponse) -> String {
    let normalized_name = lead.technique_name.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut refs: Vec<String> = lead.rfc_references.iter()
        .map(|r| format!("{}:{}", r.rfc, r.section))
        .collect();
    refs.sort();

    let input = format!("{}|{}|{}|{}", protocol, lead.category, normalized_name, refs.join(","));
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Deduplicate leads with overlapping fingerprints.
/// Keep the higher-confidence version when fingerprints match.
fn deduplicate_leads(leads: &[SecurityLead]) -> Vec<SecurityLead> {
    let mut seen: std::collections::HashMap<String, &SecurityLead> = std::collections::HashMap::new();
    for lead in leads {
        match seen.get(&lead.fingerprint) {
            Some(existing) if existing.confidence >= lead.confidence => {
                // Keep existing (higher confidence)
            }
            _ => {
                seen.insert(lead.fingerprint.clone(), lead);
            }
        }
    }
    seen.into_values().cloned().collect()
}

/// Filter leads by minimum severity.
fn filter_by_severity(leads: Vec<SecurityLead>, min_severity: &str) -> Vec<SecurityLead> {
    let min_rank = severity_rank(min_severity);
    leads.into_iter()
        .filter(|l| severity_rank(&l.severity) >= min_rank)
        .collect()
}

/// Rank leads: severity tier first (descending), then confidence (descending).
fn rank_leads(leads: &mut Vec<SecurityLead>) {
    leads.sort_by(|a, b| {
        severity_rank(&b.severity).cmp(&severity_rank(&a.severity))
            .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
    });
}

/// Store a single security lead in the database.
/// Deduplicates by fingerprint+run_id (skips insert if fingerprint already exists for this run).
/// Cross-run deduplication is handled at read time by `deduplicate_leads`.
async fn store_lead(
    conn: &Connection,
    protocol: &str,
    lead: &SecurityLead,
    run_id: i64,
    input_hash: &str,
) -> Result<()> {
    let protocol = protocol.to_string();
    let lead = lead.clone();
    let input_hash = input_hash.to_string();

    conn.call(move |conn| {
        conn.execute(
            "INSERT INTO security_leads
                (id, protocol, technique_name, category, severity, confidence,
                 description, rfc_references, prerequisites, entities_involved,
                 state_machine_name, mitigation, input_hash, run_id, fingerprint)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             WHERE NOT EXISTS (
                 SELECT 1 FROM security_leads WHERE fingerprint = ?15 AND run_id = ?14
             )",
            rusqlite::params![
                lead.id,
                protocol,
                lead.technique_name,
                lead.category,
                lead.severity,
                lead.confidence,
                lead.description,
                serde_json::to_string(&lead.rfc_references).unwrap_or_default(),
                serde_json::to_string(&lead.prerequisites).unwrap_or_default(),
                serde_json::to_string(&lead.entities_involved).unwrap_or_default(),
                Option::<String>::None, // state_machine_name
                lead.mitigation,
                input_hash,
                run_id,
                lead.fingerprint,
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Load existing leads for a specific run.
/// Applies the same dedup/rank/filter pipeline as a fresh run.
async fn load_existing_leads(conn: &Connection, run_id: i64, min_severity: &str) -> Result<Vec<SecurityLead>> {
    let min_severity = min_severity.to_string();
    let raw_leads = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, technique_name, category, severity, confidence,
                    description, rfc_references, prerequisites, entities_involved,
                    mitigation, fingerprint
                 FROM security_leads WHERE run_id = ?1
                 ORDER BY id"
            )?;
            let leads: Vec<SecurityLead> = stmt
                .query_map([run_id], |row| {
                    Ok(SecurityLead {
                        id: row.get(0)?,
                        technique_name: row.get(1)?,
                        category: row.get(2)?,
                        severity: row.get(3)?,
                        confidence: row.get(4)?,
                        description: row.get(5)?,
                        rfc_references: serde_json::from_str(
                            &row.get::<_, String>(6)?
                        ).unwrap_or_default(),
                        prerequisites: serde_json::from_str(
                            &row.get::<_, String>(7)?
                        ).unwrap_or_default(),
                        entities_involved: serde_json::from_str(
                            &row.get::<_, String>(8)?
                        ).unwrap_or_default(),
                        mitigation: row.get(9)?,
                        fingerprint: row.get::<_, Option<String>>(10)?
                            .unwrap_or_default(),
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(leads)
        })
        .await?;

    // Apply same dedup/rank/filter pipeline as a fresh run
    let deduplicated = deduplicate_leads(&raw_leads);
    let mut ranked = filter_by_severity(deduplicated, &min_severity);
    rank_leads(&mut ranked);
    Ok(ranked)
}

/// Format state machines as a brief summary for the LLM prompt context.
fn format_state_machine_summary(machines: &[(String, String, String)]) -> String {
    if machines.is_empty() {
        return "No state machines available.".to_string();
    }
    let mut summary = String::from("Protocol state machines:\n");
    for (name, mechanism, data_json) in machines {
        summary.push_str(&format!("- {} ({})\n", name, mechanism));
        // Extract state names from JSON for brief context
        if let Ok(sm) = serde_json::from_str::<serde_json::Value>(data_json) {
            if let Some(states) = sm["states"].as_array() {
                let state_names: Vec<&str> = states.iter()
                    .filter_map(|s| s["name"].as_str())
                    .collect();
                if !state_names.is_empty() {
                    summary.push_str(&format!("  States: {}\n", state_names.join(", ")));
                }
            }
        }
    }
    summary
}

/// Extract (rfc, section) references from state machine data.
fn extract_sm_section_refs(machines: &[(String, String, String)]) -> Vec<(u32, String)> {
    let mut refs = Vec::new();
    for (_, _, data_json) in machines {
        if let Ok(sm) = serde_json::from_str::<serde_json::Value>(data_json) {
            if let Some(states) = sm["states"].as_array() {
                for state in states {
                    if let (Some(rfc), Some(sec)) = (
                        state["source_rfc"].as_u64(),
                        state["source_section"].as_str()
                    ) {
                        refs.push((rfc as u32, sec.to_string()));
                    }
                }
            }
            if let Some(transitions) = sm["transitions"].as_array() {
                for t in transitions {
                    if let (Some(rfc), Some(sec)) = (
                        t["source_rfc"].as_u64(),
                        t["source_section"].as_str()
                    ) {
                        refs.push((rfc as u32, sec.to_string()));
                    }
                }
            }
        }
    }
    refs.sort();
    refs.dedup();
    refs
}

/// Compute Stage 3 input hash per the canonical manifest.
async fn compute_stage3_hash(
    conn: &Connection,
    rfc_numbers: &[RfcNumber],
    categories: &[&str],
    model: &str,
    config: &crate::config::LlmConfig,
    protocol: &str,
) -> Result<String> {
    let mut sorted_rfcs: Vec<u32> = rfc_numbers.iter().map(|r| r.0).collect();
    sorted_rfcs.sort();

    // Load state machines for hashing — use actual protocol, sorted by name
    let mut state_machines = analysis_store::get_state_machines(conn, protocol, None).await
        .unwrap_or_default();
    state_machines.sort_by(|a, b| a.0.cmp(&b.0)); // sort by name alphabetically

    // Load section texts
    let mut section_texts = String::new();
    for rfc_num in &sorted_rfcs {
        if let Some(rfc) = rfc_store::get_rfc(conn, *rfc_num).await? {
            let mut sections = rfc.sections;
            sections.sort_by(|a, b| crate::pipeline::summarize::compare_section_nums(&a.number, &b.number));
            for section in &sections {
                section_texts.push_str(&section.text);
            }
        }
    }

    let mut hasher = Sha256::new();

    // 1: sorted RFC numbers
    hasher.update(sorted_rfcs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(",").as_bytes());
    hasher.update(b"|");

    // 2: state machine hashes — hash each machine's data individually in sorted name order
    let sm_hash = {
        let mut h = Sha256::new();
        for (name, _, data) in &state_machines {
            h.update(name.as_bytes());
            h.update(b":");
            h.update(data.as_bytes());
            h.update(b";");
        }
        format!("{:x}", h.finalize())
    };
    hasher.update(sm_hash.as_bytes());
    hasher.update(b"|");

    // 3: section texts hash
    let section_hash = {
        let mut h = Sha256::new();
        h.update(section_texts.as_bytes());
        format!("{:x}", h.finalize())
    };
    hasher.update(section_hash.as_bytes());
    hasher.update(b"|");

    // 4: PROMPT_VERSION
    hasher.update(prompts::PROMPT_VERSION.as_bytes());
    hasher.update(b"|");

    // 5: model
    hasher.update(model.as_bytes());
    hasher.update(b"|");

    // 6: temperature
    hasher.update(config.temperature.to_string().as_bytes());
    hasher.update(b"|");

    // 7: max_tokens
    hasher.update(config.max_tokens_per_request.to_string().as_bytes());
    hasher.update(b"|");

    // 8: context_window
    hasher.update(config.model_context_window.to_string().as_bytes());
    hasher.update(b"|");

    // 9: category filter
    let mut cats: Vec<&str> = categories.to_vec();
    cats.sort();
    hasher.update(cats.join(",").as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}
```

## 3. src/output/report.rs

Report assembly and JSON serialization.

```rust
use crate::graph::query::GraphSummary;
use crate::pipeline::analysis::SecurityLead;
use crate::rfc::model::RfcNumber;
use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub protocol_name: String,
    pub rfcs_analyzed: Vec<u32>,
    pub dependency_graph_summary: GraphSummary,
    // Design spec has full state machines; v1 uses count only for report size
    pub state_machines_count: usize,
    pub security_leads: Vec<SecurityLead>,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Serialize)]
pub struct ReportMetadata {
    pub generated_at: String,
    pub model_used: String,
    /// Tokens used in THIS invocation (0 on cache hit). Historical token
    /// usage is stored in analysis_runs.tokens_used for the original run.
    pub total_tokens_used: u64,
    pub analysis_duration_secs: f64,
    pub run_id: Option<i64>,
    pub input_hash: Option<String>,
    pub prompt_version: String,
    pub rfc_analyzer_version: String,
    pub report_format: String,
    pub temperature: f64,
    pub max_tokens_per_request: u32,
    pub schema_version: u32,
    /// Sections dropped by summarize-to-fit. Deferred in v1: truncation
    /// info is stored in run_work_items.error column but not loaded into
    /// reports. Future versions may aggregate this from work items.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sections_truncated: Vec<String>,
}

impl AnalysisReport {
    pub fn build(
        protocol: &str,
        rfc_numbers: &[RfcNumber],
        graph_summary: GraphSummary,
        state_machines_count: usize,
        leads: Vec<SecurityLead>,
        model: &str,
        total_tokens: u64,
        duration_secs: f64,
        run_id: Option<i64>,
        input_hash: Option<String>,
        temperature: f64,
        max_tokens_per_request: u32,
    ) -> Self {
        AnalysisReport {
            protocol_name: protocol.to_string(),
            rfcs_analyzed: rfc_numbers.iter().map(|r| r.0).collect(),
            dependency_graph_summary: graph_summary,
            state_machines_count,
            security_leads: leads,
            metadata: ReportMetadata {
                generated_at: Utc::now().to_rfc3339(),
                model_used: model.to_string(),
                total_tokens_used: total_tokens,
                analysis_duration_secs: duration_secs,
                run_id,
                input_hash,
                prompt_version: crate::llm::prompts::PROMPT_VERSION.to_string(),
                rfc_analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
                report_format: "json".to_string(),
                temperature,
                max_tokens_per_request,
                schema_version: 2,
                // TODO: Load truncation info from run_work_items.error column
                sections_truncated: Vec::new(),
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}
```

## 4. src/output/mod.rs

```rust
pub mod report;
```

## 5. src/commands/analyze.rs

```rust
use crate::config::Config;
use crate::db::{analysis_store, rfc_store};
use crate::graph::builder::DependencyGraph;
use crate::llm::client::LlmClient;
use crate::output::report::AnalysisReport;
use crate::pipeline::analysis;
use anyhow::Result;
use std::path::PathBuf;
use std::time::Instant;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

pub async fn cmd_analyze(
    conn: &Connection,
    config: &Config,
    protocol: &str,
    categories: Option<Vec<String>>,
    min_severity: &str,
    output: Option<PathBuf>,
    format: &str,
    cancel_token: CancellationToken,
) -> Result<()> {
    if format != "json" {
        anyhow::bail!("Only 'json' format is supported in v1. Text/markdown formats are deferred.");
    }

    let start = Instant::now();
    let llm = LlmClient::new(config.llm.clone(), cancel_token)?;

    let category_filter = categories.as_deref();
    let result = analysis::run_stage3(
        conn, &llm, protocol, category_filter, min_severity, &config.llm
    ).await?;

    let duration = start.elapsed().as_secs_f64();

    // Build report
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    let mut rfcs = Vec::new();
    for rfc_num in &rfc_numbers {
        if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num.0).await? {
            rfcs.push(rfc);
        }
    }
    let graph = DependencyGraph::build(&rfcs);
    let graph_summary = graph.summary();
    let sm_count = analysis_store::get_state_machines(conn, protocol, None).await?.len();

    let report = AnalysisReport::build(
        protocol,
        &rfc_numbers,
        graph_summary,
        sm_count,
        result.leads,
        llm.model(),
        result.total_tokens,
        duration,
        result.run_id,
        Some(result.input_hash),
        config.llm.temperature as f64,
        config.llm.max_tokens_per_request,
    );

    // Output
    let json = report.to_json();
    match output {
        Some(path) => {
            std::fs::write(&path, &json)?;
            tracing::info!("Report written to {}", path.display());
        }
        None => {
            println!("{}", json);
        }
    }

    Ok(())
}
```

## 6. src/commands/run.rs

Chains map → model → analyze.

```rust
use crate::commands;
use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

pub async fn cmd_run(
    conn: &Connection,
    config: &Config,
    protocol: &str,
    rfcs: Vec<u32>,
    depth: u32,
    output: Option<PathBuf>,
    format: &str,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Stage 1: Map
    tracing::info!("=== Stage 1: Map ===");
    commands::map::cmd_map(
        conn, config, rfcs, Some(protocol.to_string()), depth, false
    ).await?;

    if cancel_token.is_cancelled() {
        tracing::info!("Cancelled after map stage");
        return Ok(());
    }

    // Stage 2: Model
    tracing::info!("=== Stage 2: Model ===");
    commands::model::cmd_model(
        conn, config, protocol, None, cancel_token.clone()
    ).await?;

    if cancel_token.is_cancelled() {
        tracing::info!("Cancelled after model stage");
        return Ok(());
    }

    // Stage 3: Analyze
    tracing::info!("=== Stage 3: Analyze ===");
    commands::analyze::cmd_analyze(
        conn, config, protocol, None, "low", output, format, cancel_token
    ).await?;

    Ok(())
}
```

## 7. Module Wiring

### src/pipeline/mod.rs (update)

```rust
pub mod analysis;
pub mod modeling;
pub mod section_select;
pub mod summarize;
```

### src/commands/mod.rs (update)

```rust
pub mod analyze;
pub mod clear;
pub mod graph;
pub mod map;
pub mod model;
pub mod run;
pub mod show;
```

### src/lib.rs (update — add output module)

```rust
pub mod cli;
pub mod commands;
pub mod config;
pub mod db;
pub mod error;
pub mod graph;
pub mod llm;
pub mod output;
pub mod pipeline;
pub mod rfc;
```

### src/main.rs — Wire up Analyze and Run

Replace the `_ => not yet implemented` arm with:

```rust
Command::Analyze { protocol, categories, min_severity, output, format } => {
    rfc_analyzer::commands::analyze::cmd_analyze(
        &conn, &config, &protocol, categories, &min_severity,
        output, &format, cancel_token
    ).await?;
}
Command::Run { protocol, rfcs, depth, output, format } => {
    rfc_analyzer::commands::run::cmd_run(
        &conn, &config, &protocol, rfcs, depth, output, &format, cancel_token
    ).await?;
}
```

## 8. Tests

### src/pipeline/analysis.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_rank() {
        assert_eq!(severity_rank("critical"), 5);
        assert_eq!(severity_rank("high"), 4);
        assert_eq!(severity_rank("medium"), 3);
        assert_eq!(severity_rank("low"), 2);
        assert_eq!(severity_rank("informational"), 1);
        assert_eq!(severity_rank("unknown"), 0);
        // Case insensitive
        assert_eq!(severity_rank("Critical"), 5);
        assert_eq!(severity_rank("HIGH"), 4);
    }

    #[test]
    fn test_compute_fingerprint() {
        let lead = LeadResponse {
            technique_name: "DNS Cache Poisoning".to_string(),
            category: "MissingValidation".to_string(),
            severity: "high".to_string(),
            confidence: 0.85,
            description: "Step 1...".to_string(),
            rfc_references: vec![
                LeadRfcRef { rfc: 1035, section: "4.1".to_string(), quote: None },
                LeadRfcRef { rfc: 1035, section: "7.3".to_string(), quote: Some("cached".to_string()) },
            ],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
        };

        let fp1 = compute_fingerprint("dns", &lead);
        let fp2 = compute_fingerprint("dns", &lead);
        assert_eq!(fp1, fp2); // Deterministic

        // Different protocol → different fingerprint
        let fp3 = compute_fingerprint("tcp", &lead);
        assert_ne!(fp1, fp3);

        // Quotes don't affect fingerprint
        let mut lead2 = lead.clone();
        lead2.rfc_references[1].quote = Some("different quote".to_string());
        let fp4 = compute_fingerprint("dns", &lead2);
        assert_eq!(fp1, fp4);
    }

    #[test]
    fn test_deduplicate_leads() {
        let lead1 = SecurityLead {
            id: "a".to_string(),
            fingerprint: "fp1".to_string(),
            confidence: 0.8,
            technique_name: "A".to_string(),
            category: "X".to_string(),
            severity: "high".to_string(),
            description: "".to_string(),
            rfc_references: vec![],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
        };
        let lead2 = SecurityLead {
            id: "b".to_string(),
            fingerprint: "fp1".to_string(), // same fingerprint
            confidence: 0.9, // higher confidence
            ..lead1.clone()
        };
        let lead3 = SecurityLead {
            id: "c".to_string(),
            fingerprint: "fp2".to_string(), // different fingerprint
            ..lead1.clone()
        };

        let result = deduplicate_leads(&[lead1, lead2, lead3]);
        assert_eq!(result.len(), 2); // fp1 deduped, fp2 kept
        // The higher-confidence version of fp1 should be kept
        let fp1_lead = result.iter().find(|l| l.fingerprint == "fp1").unwrap();
        assert_eq!(fp1_lead.confidence, 0.9);
    }

    #[test]
    fn test_rank_leads() {
        let mut leads = vec![
            SecurityLead {
                id: "1".to_string(), severity: "low".to_string(),
                confidence: 0.9, fingerprint: "a".to_string(),
                technique_name: "".to_string(), category: "".to_string(),
                description: "".to_string(), rfc_references: vec![],
                prerequisites: vec![], entities_involved: vec![], mitigation: None,
            },
            SecurityLead {
                id: "2".to_string(), severity: "critical".to_string(),
                confidence: 0.5, fingerprint: "b".to_string(),
                technique_name: "".to_string(), category: "".to_string(),
                description: "".to_string(), rfc_references: vec![],
                prerequisites: vec![], entities_involved: vec![], mitigation: None,
            },
            SecurityLead {
                id: "3".to_string(), severity: "critical".to_string(),
                confidence: 0.9, fingerprint: "c".to_string(),
                technique_name: "".to_string(), category: "".to_string(),
                description: "".to_string(), rfc_references: vec![],
                prerequisites: vec![], entities_involved: vec![], mitigation: None,
            },
        ];

        rank_leads(&mut leads);

        // Critical first, then by confidence within critical
        assert_eq!(leads[0].id, "3"); // critical, 0.9
        assert_eq!(leads[1].id, "2"); // critical, 0.5
        assert_eq!(leads[2].id, "1"); // low, 0.9
    }

    #[test]
    fn test_filter_by_severity() {
        let leads = vec![
            SecurityLead {
                id: "1".to_string(), severity: "low".to_string(),
                confidence: 0.9, fingerprint: "a".to_string(),
                technique_name: "".to_string(), category: "".to_string(),
                description: "".to_string(), rfc_references: vec![],
                prerequisites: vec![], entities_involved: vec![], mitigation: None,
            },
            SecurityLead {
                id: "2".to_string(), severity: "high".to_string(),
                confidence: 0.5, fingerprint: "b".to_string(),
                technique_name: "".to_string(), category: "".to_string(),
                description: "".to_string(), rfc_references: vec![],
                prerequisites: vec![], entities_involved: vec![], mitigation: None,
            },
        ];

        let filtered = filter_by_severity(leads, "medium");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "2"); // only high passes medium threshold
    }

    #[test]
    fn test_format_state_machine_summary() {
        let machines = vec![
            ("TCP Connection".to_string(), "state".to_string(),
             r#"{"states":[{"name":"LISTEN"},{"name":"ESTABLISHED"}],"transitions":[]}"#.to_string()),
        ];
        let summary = format_state_machine_summary(&machines);
        assert!(summary.contains("TCP Connection"));
        assert!(summary.contains("LISTEN"));
        assert!(summary.contains("ESTABLISHED"));
    }
}
```

## 9. Verification

After implementation:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all tests (existing + new analysis/section_select tests)
3. With an LLM endpoint configured:
   - `cargo run -- analyze tcp --min-severity medium` produces JSON leads
   - `cargo run -- run tcp 9293 --depth 1 -o report.json` runs full pipeline
4. Re-running with same inputs skips (cached)
5. Ctrl+C during analysis saves partial results, resumes on next run
6. `cargo run -- analyze tcp --categories missing_validation,replay_attack` filters categories

## 10. What This Phase Completes

Phase 6 completes the full RFC Analyzer pipeline:
- `map` → fetch, parse, store RFCs, build dependency graph
- `model` → cluster mechanisms, extract state machines via LLM
- `analyze` → per-category security analysis, dedup, rank, report
- `run` → all three stages in sequence

The tool can now analyze any protocol's RFC specifications for security
vulnerabilities and produce ranked actionable leads.
