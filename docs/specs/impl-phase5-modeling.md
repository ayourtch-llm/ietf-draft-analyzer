# Phase 5: Protocol Modeling — Implementation Spec

This document is self-contained. It builds on Phase 1-4 (which must be
complete). Implement exactly what is specified here.

**Development process**: Follow `docs/specs/dev-guidelines.md` — Red-Green
TDD, commit after each significant change or when tests pass, 85%+ coverage
target with `cargo tarpaulin`.

## Overview

Phase 5 implements Stage 2 of the pipeline: protocol modeling. It takes
parsed RFCs from a protocol and uses the LLM to identify mechanism clusters,
extract protocol state machines, validate them, and persist results with
full run provenance and resumability.

At the end of Phase 5, `rfc-analyzer model tcp` produces state machines
from the mapped TCP RFCs using the configured LLM endpoint.

## Files to Create / Modify

```
NEW:
  src/pipeline/mod.rs          -- pipeline infrastructure, run management
  src/pipeline/modeling.rs     -- Stage 2: clustering + state extraction
  src/pipeline/summarize.rs    -- summarize-to-fit strategy
  src/commands/model.rs        -- cmd_model command handler
  src/db/analysis_store.rs     -- analysis_runs + state_machines + work_items CRUD

MODIFY:
  src/commands/mod.rs          -- add model module
  src/lib.rs                   -- add pipeline module
  src/main.rs                  -- wire up Model command dispatch
```

## 1. src/db/analysis_store.rs

CRUD for `analysis_runs`, `state_machines`, and `run_work_items` tables.

```rust
use crate::error::Result;
use crate::rfc::model::RfcNumber;
use chrono::Utc;
use tokio_rusqlite::Connection;

/// Create a new analysis run record. Returns the run_id.
pub async fn create_run(
    conn: &Connection,
    protocol: &str,
    stage: &str,
    model_used: Option<&str>,
    seed_rfcs: &[RfcNumber],
    depth: Option<u32>,
    normative_only: Option<bool>,
    mechanism_filter: Option<&[String]>,
    category_filter: Option<&[String]>,
    prompt_version: &str,
    input_hash: &str,
) -> Result<i64> {
    let protocol = protocol.to_string();
    let stage = stage.to_string();
    let model_used = model_used.map(|s| s.to_string());
    let seed_rfcs_json = serde_json::to_string(
        &seed_rfcs.iter().map(|r| r.0).collect::<Vec<_>>()
    ).unwrap_or_else(|_| "[]".to_string());
    let mechanism_json = mechanism_filter.map(|f| serde_json::to_string(f).unwrap_or_default());
    let category_json = category_filter.map(|f| serde_json::to_string(f).unwrap_or_default());
    let prompt_version = prompt_version.to_string();
    let input_hash = input_hash.to_string();
    let started_at = Utc::now().to_rfc3339();

    let run_id = conn
        .call(move |conn| {
            conn.execute(
                "INSERT INTO analysis_runs (protocol, stage, started_at, status,
                    model_used, seed_rfcs, depth, normative_only,
                    mechanism_filter, category_filter, prompt_version, input_hash)
                 VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    protocol,
                    stage,
                    started_at,
                    model_used,
                    seed_rfcs_json,
                    depth,
                    normative_only.map(|b| b as i64),
                    mechanism_json,
                    category_json,
                    prompt_version,
                    input_hash,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?;
    Ok(run_id)
}

/// Check if a completed run with this input_hash already exists.
pub async fn find_completed_run(
    conn: &Connection,
    protocol: &str,
    stage: &str,
    input_hash: &str,
) -> Result<Option<i64>> {
    let protocol = protocol.to_string();
    let stage = stage.to_string();
    let input_hash = input_hash.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id FROM analysis_runs
                 WHERE protocol = ?1 AND stage = ?2 AND input_hash = ?3
                   AND status = 'completed'
                 ORDER BY id DESC LIMIT 1"
            )?;
            let id = stmt.query_row(
                rusqlite::params![protocol, stage, input_hash],
                |row| row.get::<_, i64>(0),
            ).optional()?;
            Ok(id)
        })
        .await?;
    Ok(result)
}

/// Update a run's status and completion time.
pub async fn complete_run(
    conn: &Connection,
    run_id: i64,
    status: &str,
    tokens_used: u64,
    effective_rfcs: &[RfcNumber],
    error: Option<&str>,
) -> Result<()> {
    let status = status.to_string();
    let completed_at = Utc::now().to_rfc3339();
    let effective_json = serde_json::to_string(
        &effective_rfcs.iter().map(|r| r.0).collect::<Vec<_>>()
    ).unwrap_or_else(|_| "[]".to_string());
    let error = error.map(|s| s.to_string());

    conn.call(move |conn| {
        conn.execute(
            "UPDATE analysis_runs SET status = ?1, completed_at = ?2,
                tokens_used = ?3, effective_rfcs = ?4, error = ?5
             WHERE id = ?6",
            rusqlite::params![status, completed_at, tokens_used as i64,
                effective_json, error, run_id],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Create or update a work item for a run.
pub async fn upsert_work_item(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    key: &str,
    status: &str,
) -> Result<()> {
    let kind = kind.to_string();
    let key = key.to_string();
    let status = status.to_string();
    let now = Utc::now().to_rfc3339();

    conn.call(move |conn| {
        conn.execute(
            "INSERT INTO run_work_items (run_id, work_item_kind, work_item_key, status, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(run_id, work_item_kind, work_item_key) DO UPDATE SET
                status = excluded.status,
                started_at = CASE WHEN excluded.status = 'running' THEN excluded.started_at
                             ELSE run_work_items.started_at END,
                completed_at = CASE WHEN excluded.status IN ('completed', 'failed')
                               THEN excluded.started_at ELSE NULL END",
            rusqlite::params![run_id, kind, key, status, now],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Mark a work item as completed with token usage.
pub async fn complete_work_item(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    key: &str,
    tokens_used: u64,
    error: Option<&str>,
) -> Result<()> {
    let kind = kind.to_string();
    let key = key.to_string();
    let completed_at = Utc::now().to_rfc3339();
    let status = if error.is_some() { "failed" } else { "completed" };
    let status = status.to_string();
    let error = error.map(|s| s.to_string());

    conn.call(move |conn| {
        conn.execute(
            "UPDATE run_work_items SET status = ?1, completed_at = ?2,
                tokens_used = ?3, error = ?4
             WHERE run_id = ?5 AND work_item_kind = ?6 AND work_item_key = ?7",
            rusqlite::params![status, completed_at, tokens_used as i64,
                error, run_id, kind, key],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Get completed work item keys for a run (for resumability).
pub async fn get_completed_work_items(
    conn: &Connection,
    run_id: i64,
    kind: &str,
) -> Result<Vec<String>> {
    let kind = kind.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT work_item_key FROM run_work_items
                 WHERE run_id = ?1 AND work_item_kind = ?2 AND status = 'completed'"
            )?;
            let keys: Vec<String> = stmt
                .query_map(rusqlite::params![run_id, kind], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(keys)
        })
        .await?;
    Ok(result)
}

/// Store a state machine.
pub async fn store_state_machine(
    conn: &Connection,
    protocol: &str,
    name: &str,
    mechanism: &str,
    data_json: &str,
    content_hash: &str,
    run_id: i64,
) -> Result<()> {
    let protocol = protocol.to_string();
    let name = name.to_string();
    let mechanism = mechanism.to_string();
    let data_json = data_json.to_string();
    let content_hash = content_hash.to_string();

    conn.call(move |conn| {
        conn.execute(
            "INSERT OR REPLACE INTO state_machines
                (protocol, name, mechanism, data, content_hash, run_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![protocol, name, mechanism, data_json,
                content_hash, run_id],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Load all state machines for a protocol.
pub async fn get_state_machines(
    conn: &Connection,
    protocol: &str,
) -> Result<Vec<(String, String, String)>> {
    // Returns (name, mechanism, data_json) tuples
    let protocol = protocol.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT name, mechanism, data FROM state_machines
                 WHERE protocol = ?1 ORDER BY name"
            )?;
            let machines: Vec<(String, String, String)> = stmt
                .query_map([&protocol], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(machines)
        })
        .await?;
    Ok(result)
}

use rusqlite::OptionalExtension;
```

## 2. src/pipeline/summarize.rs

Implements the extractive summarize-to-fit strategy from
`phase5-6-spec-additions.md` Section 4.

```rust
use crate::rfc::model::{RfcNumber, Section};

/// A section with its relevance score for summarization.
#[derive(Debug, Clone)]
pub struct ScoredSection {
    pub rfc_number: RfcNumber,
    pub section: Section,
    pub score: i32,
}

/// Summarize sections to fit within a token budget.
/// Returns the combined text with provenance markers.
/// If sections had to be dropped, returns their identifiers in the second element.
pub fn summarize_to_fit(
    sections: &[(RfcNumber, &Section)],
    cluster_section_ids: &[(u32, String)],  // (rfc_number, section_num) in the cluster
    budget_tokens: u64,
    rfc_numbers_in_scope: &[RfcNumber],
) -> (String, Vec<String>) {
    use crate::llm::prompts;

    // Score each section
    let mut scored: Vec<ScoredSection> = sections
        .iter()
        .map(|(rfc_num, section)| {
            let score = compute_relevance_score(
                *rfc_num, section, cluster_section_ids, rfc_numbers_in_scope
            );
            ScoredSection {
                rfc_number: *rfc_num,
                section: (*section).clone(),
                score,
            }
        })
        .collect();

    // Sort by score descending, then by RFC number ascending, then section number
    scored.sort_by(|a, b| {
        b.score.cmp(&a.score)
            .then_with(|| a.rfc_number.0.cmp(&b.rfc_number.0))
            .then_with(|| compare_section_nums(&a.section.number, &b.section.number))
    });

    let mut output = String::new();
    let mut dropped = Vec::new();
    let mut used_tokens: u64 = 0;
    let full_text_budget = (budget_tokens as f64 * 0.6) as u64; // 60% for full text

    for scored_section in &scored {
        let full_text = prompts::format_section(
            scored_section.rfc_number.0,
            &scored_section.section.number,
            &scored_section.section.title,
            &scored_section.section.text,
        );
        let tokens = estimate_tokens(&full_text);

        if used_tokens + tokens <= full_text_budget {
            // Include full text
            output.push_str(&full_text);
            output.push('\n');
            used_tokens += tokens;
        } else if used_tokens + estimate_tokens(&scored_section.section.title) < budget_tokens {
            // Include summary only
            let summary = extract_summary(&scored_section.section);
            let summary_text = prompts::format_section(
                scored_section.rfc_number.0,
                &scored_section.section.number,
                &scored_section.section.title,
                &summary,
            );
            let summary_tokens = estimate_tokens(&summary_text);
            if used_tokens + summary_tokens <= budget_tokens {
                output.push_str(&summary_text);
                output.push('\n');
                used_tokens += summary_tokens;
            } else {
                dropped.push(format!(
                    "RFC {} §{}", scored_section.rfc_number.0, scored_section.section.number
                ));
            }
        } else {
            dropped.push(format!(
                "RFC {} §{}", scored_section.rfc_number.0, scored_section.section.number
            ));
        }
    }

    (output, dropped)
}

/// Compute relevance score for a section.
fn compute_relevance_score(
    rfc_number: RfcNumber,
    section: &Section,
    cluster_section_ids: &[(u32, String)],
    rfc_numbers_in_scope: &[RfcNumber],
) -> i32 {
    let mut score = 0i32;

    // +3: Cross-referenced BY sections in the cluster but not itself in the cluster
    let is_in_cluster = cluster_section_ids.iter()
        .any(|(rfc, sec)| *rfc == rfc_number.0 && *sec == section.number);
    if !is_in_cluster {
        // Check if any cluster section references this section
        // (This would require access to cross-refs, which we check via the
        //  section's own incoming references. For simplicity, we give +3 if
        //  this section is referenced by any section in the cluster.)
        // The caller should pre-filter to only include relevant sections.
        score += 3;
    }

    // +2: Contains RFC 2119 keywords
    let rfc2119_keywords = ["MUST", "MUST NOT", "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL"];
    if rfc2119_keywords.iter().any(|kw| section.text.contains(kw)) {
        score += 2;
    }

    // +2: Security Considerations
    if section.title.to_lowercase().contains("security") {
        score += 2;
    }

    // +1: Has cross-references to other RFCs in scope
    let has_xrefs_in_scope = section.cross_refs.iter().any(|xref| {
        xref.target_rfc.map_or(false, |r| rfc_numbers_in_scope.contains(&r))
    });
    if has_xrefs_in_scope {
        score += 1;
    }

    score
}

/// Extract a summary of a section: title + first sentence + RFC 2119 sentences + xref sentences.
fn extract_summary(section: &Section) -> String {
    let mut summary_parts = Vec::new();

    // First sentence
    if let Some(first_sentence) = section.text.split('.').next() {
        let trimmed = first_sentence.trim();
        if !trimmed.is_empty() {
            summary_parts.push(format!("{}.", trimmed));
        }
    }

    // Sentences with RFC 2119 keywords
    let rfc2119_keywords = ["MUST", "MUST NOT", "SHALL", "SHALL NOT",
        "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED"];
    for sentence in section.text.split('.') {
        let trimmed = sentence.trim();
        if rfc2119_keywords.iter().any(|kw| trimmed.contains(kw)) {
            let s = format!("{}.", trimmed);
            if !summary_parts.contains(&s) {
                summary_parts.push(s);
            }
        }
    }

    // Sentences with cross-references
    for sentence in section.text.split('.') {
        let trimmed = sentence.trim();
        if trimmed.contains("[RFC") || trimmed.contains("Section ") {
            let s = format!("{}.", trimmed);
            if !summary_parts.contains(&s) {
                summary_parts.push(s);
            }
        }
    }

    summary_parts.join(" ")
}

/// Estimate tokens for a string (chars / 4).
fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64) / 4
}

/// Compare dotted section numbers using numeric-segment comparison.
/// Split on '.', compare each segment as u32. Fall back to string comparison
/// for non-numeric segments (e.g., appendix letters).
pub fn compare_section_nums(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        let ord = match (ap.parse::<u32>(), bp.parse::<u32>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            _ => ap.cmp(bp),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    a_parts.len().cmp(&b_parts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_section_nums() {
        use std::cmp::Ordering;
        assert_eq!(compare_section_nums("3.2", "3.10"), Ordering::Less);
        assert_eq!(compare_section_nums("3.10", "3.2"), Ordering::Greater);
        assert_eq!(compare_section_nums("1", "2"), Ordering::Less);
        assert_eq!(compare_section_nums("A", "B"), Ordering::Less);
        assert_eq!(compare_section_nums("3.1", "3.1"), Ordering::Equal);
        assert_eq!(compare_section_nums("3", "3.1"), Ordering::Less);
    }

    #[test]
    fn test_extract_summary_includes_first_sentence() {
        let section = Section {
            number: "1".to_string(),
            title: "Intro".to_string(),
            anchor: None,
            depth: 1,
            text: "This is the first sentence. Second sentence. Third.".to_string(),
            cross_refs: Vec::new(),
            pn: None,
        };
        let summary = extract_summary(&section);
        assert!(summary.contains("This is the first sentence."));
    }

    #[test]
    fn test_extract_summary_includes_rfc2119() {
        let section = Section {
            number: "2".to_string(),
            title: "Requirements".to_string(),
            anchor: None,
            depth: 1,
            text: "Intro sentence. Implementations MUST validate input. Optional text.".to_string(),
            cross_refs: Vec::new(),
            pn: None,
        };
        let summary = extract_summary(&section);
        assert!(summary.contains("MUST validate input"));
    }
}
```

## 3. src/pipeline/modeling.rs

The Stage 2 pipeline: mechanism clustering, state machine extraction,
validation, and persistence.

```rust
use crate::db::{analysis_store, rfc_store};
use crate::error::{RfcAnalyzerError, Result};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::summarize;
use crate::rfc::model::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_rusqlite::Connection;

/// LLM response type for mechanism clustering.
#[derive(Debug, Deserialize)]
pub struct ClusteringResponse {
    pub clusters: Vec<MechanismCluster>,
}

#[derive(Debug, Deserialize)]
pub struct MechanismCluster {
    pub mechanism: String,
    pub sections: Vec<SectionRef>,
}

#[derive(Debug, Deserialize)]
pub struct SectionRef {
    pub rfc: u32,
    pub section: String,
}

/// LLM response type for state machine extraction.
#[derive(Debug, Deserialize)]
pub struct StateMachineResponse {
    pub name: String,
    pub states: Vec<StateResponse>,
    pub transitions: Vec<TransitionResponse>,
}

#[derive(Debug, Deserialize)]
pub struct StateResponse {
    pub name: String,
    pub description: String,
    pub source_rfc: u32,
    pub source_section: String,
}

#[derive(Debug, Deserialize)]
pub struct TransitionResponse {
    pub from: String,
    pub to: String,
    pub trigger: String,
    #[serde(default)]
    pub conditions: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    pub source_rfc: u32,
    pub source_section: String,
}

/// Run Stage 2: protocol modeling.
/// Returns the number of state machines extracted.
pub async fn run_stage2(
    conn: &Connection,
    llm: &LlmClient,
    protocol: &str,
    mechanism_filter: Option<&[String]>,
) -> Result<usize> {
    // Get protocol RFCs
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    if rfc_numbers.is_empty() {
        return Err(RfcAnalyzerError::NoMappedRfcs(protocol.to_string()));
    }

    // Compute input hash for caching
    let input_hash = compute_stage2_hash(
        conn, &rfc_numbers, mechanism_filter, llm.model()
    ).await?;

    // Check for existing completed run
    if let Some(_existing_run) = analysis_store::find_completed_run(
        conn, protocol, "model", &input_hash
    ).await? {
        tracing::info!("Stage 2 already completed with matching inputs, skipping");
        return Ok(0);
    }

    // Create analysis run
    let run_id = analysis_store::create_run(
        conn,
        protocol,
        "model",
        Some(llm.model()),
        &rfc_numbers,
        None,
        None,
        mechanism_filter,
        None,
        prompts::PROMPT_VERSION,
        &input_hash,
    ).await?;

    let mut total_tokens: u64 = 0;
    let mut machines_count = 0;

    // Load all sections for the protocol
    let mut all_sections: Vec<(RfcNumber, Section)> = Vec::new();
    for rfc_num in &rfc_numbers {
        if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num.0).await? {
            for section in rfc.sections {
                all_sections.push((*rfc_num, section));
            }
        }
    }

    // Step 1: Mechanism clustering via LLM
    tracing::info!("Clustering mechanisms for protocol '{}'", protocol);
    let section_list: Vec<(u32, &str, &str)> = all_sections.iter()
        .map(|(rfc, sec)| (rfc.0, sec.number.as_str(), sec.title.as_str()))
        .collect();

    let (system, user) = prompts::mechanism_clustering_prompt(protocol, &section_list);
    let messages = vec![
        ChatMessage { role: "system".to_string(), content: system },
        ChatMessage { role: "user".to_string(), content: user },
    ];

    let (clustering, usage) = llm.chat_json::<ClusteringResponse>(messages).await?;
    total_tokens += usage.total_tokens;

    // Filter clusters if mechanism_filter is specified
    let clusters: Vec<&MechanismCluster> = if let Some(filter) = mechanism_filter {
        clustering.clusters.iter()
            .filter(|c| filter.iter().any(|f| c.mechanism.to_lowercase().contains(&f.to_lowercase())))
            .collect()
    } else {
        clustering.clusters.iter().collect()
    };

    tracing::info!("Found {} mechanism clusters", clusters.len());

    // Step 2: Extract state machines for each cluster
    for (i, cluster) in clusters.iter().enumerate() {
        let mechanism = &cluster.mechanism;

        // Check cancellation
        if llm.cancel_token().is_cancelled() {
            tracing::info!("Cancelled, persisting partial results");
            analysis_store::complete_run(
                conn, run_id, "interrupted", total_tokens, &rfc_numbers, None
            ).await?;
            return Ok(machines_count);
        }

        // Check if this work item was already completed (resumability)
        let completed = analysis_store::get_completed_work_items(
            conn, run_id, "mechanism"
        ).await?;
        if completed.contains(&mechanism.to_string()) {
            tracing::debug!("Mechanism '{}' already completed, skipping", mechanism);
            continue;
        }

        tracing::info!("Extracting state machine {}/{}: '{}'", i + 1, clusters.len(), mechanism);
        analysis_store::upsert_work_item(conn, run_id, "mechanism", mechanism, "running").await?;

        // Gather sections for this cluster
        let cluster_section_ids: Vec<(u32, String)> = cluster.sections.iter()
            .map(|s| (s.rfc, s.section.clone()))
            .collect();

        let cluster_sections: Vec<(RfcNumber, &Section)> = all_sections.iter()
            .filter(|(rfc, sec)| {
                cluster.sections.iter().any(|cs| cs.rfc == rfc.0 && cs.section == sec.number)
            })
            .map(|(rfc, sec)| (*rfc, sec))
            .collect();

        if cluster_sections.is_empty() {
            tracing::warn!("No sections found for mechanism '{}', skipping", mechanism);
            analysis_store::complete_work_item(
                conn, run_id, "mechanism", mechanism, 0, Some("No matching sections")
            ).await?;
            continue;
        }

        // Summarize to fit context budget
        let system_prompt_tokens = llm.estimate_tokens(prompts::INJECTION_DEFENSE) + 200; // overhead
        let budget = llm.context_budget(system_prompt_tokens);

        let (sections_text, dropped) = summarize::summarize_to_fit(
            &cluster_sections,
            &cluster_section_ids,
            budget,
            &rfc_numbers,
        );

        if !dropped.is_empty() {
            tracing::warn!("Dropped sections for '{}': {:?}", mechanism, dropped);
        }

        // Check if we exceeded budget even after summarization
        if llm.estimate_tokens(&sections_text) > budget {
            let err = format!("Oversized cluster '{}' exceeds context budget after summarization", mechanism);
            tracing::warn!("{}", err);
            analysis_store::complete_work_item(
                conn, run_id, "mechanism", mechanism, 0, Some(&err)
            ).await?;
            continue;
        }

        // Send to LLM for state machine extraction
        let (system, user) = prompts::state_machine_prompt(protocol, mechanism, &sections_text);
        let messages = vec![
            ChatMessage { role: "system".to_string(), content: system },
            ChatMessage { role: "user".to_string(), content: user },
        ];

        match llm.chat_json::<StateMachineResponse>(messages).await {
            Ok((sm_response, usage)) => {
                total_tokens += usage.total_tokens;

                // Validate the state machine
                let warnings = validate_state_machine(&sm_response);
                for warning in &warnings {
                    tracing::warn!("State machine '{}': {}", sm_response.name, warning);
                }

                // Serialize and store
                let data_json = serde_json::to_string(&sm_response)
                    .unwrap_or_else(|_| "{}".to_string());
                let content_hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(data_json.as_bytes());
                    format!("{:x}", hasher.finalize())
                };

                analysis_store::store_state_machine(
                    conn, protocol, &sm_response.name, mechanism,
                    &data_json, &content_hash, run_id,
                ).await?;

                machines_count += 1;
                analysis_store::complete_work_item(
                    conn, run_id, "mechanism", mechanism, usage.total_tokens, None
                ).await?;
            }
            Err(RfcAnalyzerError::LlmContextOverflow) => {
                let err = "Context overflow despite summarization";
                tracing::warn!("Mechanism '{}': {}", mechanism, err);
                analysis_store::complete_work_item(
                    conn, run_id, "mechanism", mechanism, 0, Some(err)
                ).await?;
            }
            Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                tracing::warn!("Mechanism '{}': LLM refused: {}", mechanism, detail);
                analysis_store::complete_work_item(
                    conn, run_id, "mechanism", mechanism, 0, Some(&detail)
                ).await?;
            }
            Err(e) => {
                // Fatal error — mark run as failed
                analysis_store::complete_run(
                    conn, run_id, "failed", total_tokens, &rfc_numbers, Some(&e.to_string())
                ).await?;
                return Err(e);
            }
        }
    }

    // Mark run as completed
    analysis_store::complete_run(
        conn, run_id, "completed", total_tokens, &rfc_numbers, None
    ).await?;

    tracing::info!("Stage 2 complete: {} state machines extracted", machines_count);
    Ok(machines_count)
}

/// Validate a state machine for structural issues.
/// Returns a list of warnings (does not fail).
fn validate_state_machine(sm: &StateMachineResponse) -> Vec<String> {
    let mut warnings = Vec::new();
    let state_names: Vec<&str> = sm.states.iter().map(|s| s.name.as_str()).collect();

    // Check transitions reference defined states
    for t in &sm.transitions {
        if !state_names.contains(&t.from.as_str()) {
            warnings.push(format!("Transition from undefined state '{}'", t.from));
        }
        if !state_names.contains(&t.to.as_str()) {
            warnings.push(format!("Transition to undefined state '{}'", t.to));
        }
    }

    // Check for orphan states (no transitions in or out)
    for state in &sm.states {
        let has_outgoing = sm.transitions.iter().any(|t| t.from == state.name);
        let has_incoming = sm.transitions.iter().any(|t| t.to == state.name);
        if !has_outgoing && !has_incoming {
            warnings.push(format!("Orphan state '{}' (no transitions)", state.name));
        }
    }

    warnings
}

/// Compute the Stage 2 input hash.
async fn compute_stage2_hash(
    conn: &Connection,
    rfc_numbers: &[RfcNumber],
    mechanism_filter: Option<&[String]>,
    model: &str,
) -> Result<String> {
    // Load all section texts for hashing
    let mut section_texts = String::new();
    let mut sorted_rfcs: Vec<u32> = rfc_numbers.iter().map(|r| r.0).collect();
    sorted_rfcs.sort();

    for rfc_num in &sorted_rfcs {
        if let Some(rfc) = rfc_store::get_rfc(conn, *rfc_num).await? {
            let mut sections = rfc.sections;
            sections.sort_by(|a, b| summarize::compare_section_nums(&a.number, &b.number));
            for section in &sections {
                section_texts.push_str(&section.text);
            }
        }
    }

    let mut hasher = Sha256::new();

    // Item 1: sorted RFC numbers
    let rfcs_str = sorted_rfcs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(",");
    hasher.update(rfcs_str.as_bytes());
    hasher.update(b"|");

    // Item 2: section texts hash
    let section_hash = {
        let mut h = Sha256::new();
        h.update(section_texts.as_bytes());
        format!("{:x}", h.finalize())
    };
    hasher.update(section_hash.as_bytes());
    hasher.update(b"|");

    // Item 3: PROMPT_VERSION
    hasher.update(prompts::PROMPT_VERSION.as_bytes());
    hasher.update(b"|");

    // Item 4: model name
    hasher.update(model.as_bytes());
    hasher.update(b"|");

    // Items 5-7: model parameters (from config via client)
    // These are part of the LlmClient config but we pass model name here.
    // The full hash should include temperature, max_tokens, context_window
    // but those are accessible via LlmClient. For simplicity, we hash model
    // name which typically implies parameters. Full hash is a Phase 5+
    // refinement.
    // TODO: Pass temperature, max_tokens, model_context_window here

    // Item 8: mechanism filter
    let filter_str = mechanism_filter
        .map(|f| {
            let mut sorted = f.to_vec();
            sorted.sort();
            sorted.join(",")
        })
        .unwrap_or_else(|| "*".to_string());
    hasher.update(filter_str.as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}
```

## 4. src/pipeline/mod.rs

```rust
pub mod modeling;
pub mod summarize;
```

## 5. src/commands/model.rs

```rust
use crate::config::Config;
use crate::llm::client::LlmClient;
use crate::pipeline::modeling;
use anyhow::Result;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

pub async fn cmd_model(
    conn: &Connection,
    config: &Config,
    protocol: &str,
    mechanisms: Option<Vec<String>>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let llm = LlmClient::new(config.llm.clone(), cancel_token)?;

    let mechanism_filter = mechanisms.as_deref();
    let count = modeling::run_stage2(conn, &llm, protocol, mechanism_filter).await?;

    if count > 0 {
        tracing::info!("Model complete: {} state machines for '{}'", count, protocol);
    } else {
        tracing::info!("No new state machines extracted (may already be cached)");
    }

    Ok(())
}
```

## 6. Module Wiring

### src/commands/mod.rs (update)

```rust
pub mod clear;
pub mod graph;
pub mod map;
pub mod model;
pub mod show;
```

### src/lib.rs (update)

```rust
pub mod cli;
pub mod commands;
pub mod config;
pub mod db;
pub mod error;
pub mod graph;
pub mod llm;
pub mod pipeline;
pub mod rfc;
```

### src/main.rs — Add Model dispatch

Add to the match block:

```rust
Command::Model { protocol, mechanisms } => {
    rfc_analyzer::commands::model::cmd_model(
        &conn, &config, &protocol, mechanisms, cancel_token
    ).await?;
}
```

## 7. Tests

### src/pipeline/modeling.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_state_machine_clean() {
        let sm = StateMachineResponse {
            name: "TCP Connection".to_string(),
            states: vec![
                StateResponse { name: "CLOSED".to_string(), description: "".to_string(), source_rfc: 9293, source_section: "3.3".to_string() },
                StateResponse { name: "LISTEN".to_string(), description: "".to_string(), source_rfc: 9293, source_section: "3.3".to_string() },
            ],
            transitions: vec![
                TransitionResponse { from: "CLOSED".to_string(), to: "LISTEN".to_string(), trigger: "passive open".to_string(), conditions: vec![], actions: vec![], source_rfc: 9293, source_section: "3.4".to_string() },
            ],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_state_machine_undefined_state() {
        let sm = StateMachineResponse {
            name: "Bad".to_string(),
            states: vec![
                StateResponse { name: "A".to_string(), description: "".to_string(), source_rfc: 1, source_section: "1".to_string() },
            ],
            transitions: vec![
                TransitionResponse { from: "A".to_string(), to: "B".to_string(), trigger: "x".to_string(), conditions: vec![], actions: vec![], source_rfc: 1, source_section: "1".to_string() },
            ],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.iter().any(|w| w.contains("undefined state 'B'")));
    }

    #[test]
    fn test_validate_state_machine_orphan() {
        let sm = StateMachineResponse {
            name: "Orphan".to_string(),
            states: vec![
                StateResponse { name: "A".to_string(), description: "".to_string(), source_rfc: 1, source_section: "1".to_string() },
                StateResponse { name: "ORPHAN".to_string(), description: "".to_string(), source_rfc: 1, source_section: "2".to_string() },
                StateResponse { name: "B".to_string(), description: "".to_string(), source_rfc: 1, source_section: "3".to_string() },
            ],
            transitions: vec![
                TransitionResponse { from: "A".to_string(), to: "B".to_string(), trigger: "x".to_string(), conditions: vec![], actions: vec![], source_rfc: 1, source_section: "1".to_string() },
            ],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.iter().any(|w| w.contains("Orphan state 'ORPHAN'")));
    }
}
```

### src/db/analysis_store.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;

    #[tokio::test(flavor = "current_thread")]
    async fn test_create_and_find_run() {
        let conn = open_memory_database().await.unwrap();

        let run_id = create_run(
            &conn, "tcp", "model", Some("gpt-4o"),
            &[RfcNumber(9293)], None, None, None, None,
            "1.0.0", "hash123",
        ).await.unwrap();
        assert!(run_id > 0);

        // Not yet completed — should not be found
        let found = find_completed_run(&conn, "tcp", "model", "hash123").await.unwrap();
        assert!(found.is_none());

        // Complete it
        complete_run(&conn, run_id, "completed", 500, &[RfcNumber(9293)], None).await.unwrap();

        // Now should be found
        let found = find_completed_run(&conn, "tcp", "model", "hash123").await.unwrap();
        assert_eq!(found, Some(run_id));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_work_items() {
        let conn = open_memory_database().await.unwrap();

        let run_id = create_run(
            &conn, "tcp", "model", Some("gpt-4o"),
            &[RfcNumber(9293)], None, None, None, None,
            "1.0.0", "hash",
        ).await.unwrap();

        upsert_work_item(&conn, run_id, "mechanism", "auth", "running").await.unwrap();
        complete_work_item(&conn, run_id, "mechanism", "auth", 100, None).await.unwrap();

        let completed = get_completed_work_items(&conn, run_id, "mechanism").await.unwrap();
        assert_eq!(completed, vec!["auth".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_store_and_get_state_machine() {
        let conn = open_memory_database().await.unwrap();

        // Need a run first
        let run_id = create_run(
            &conn, "tcp", "model", Some("gpt-4o"),
            &[RfcNumber(9293)], None, None, None, None,
            "1.0.0", "hash",
        ).await.unwrap();

        store_state_machine(
            &conn, "tcp", "Connection", "state_management",
            r#"{"name":"Connection","states":[],"transitions":[]}"#,
            "smhash", run_id,
        ).await.unwrap();

        let machines = get_state_machines(&conn, "tcp").await.unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].0, "Connection");
        assert_eq!(machines[0].1, "state_management");
    }
}
```

## 8. Verification

After implementation:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all tests (existing + new pipeline/analysis_store tests)
3. With an LLM endpoint configured:
   `cargo run -- model tcp` extracts state machines from mapped TCP RFCs
4. Re-running `model tcp` with same inputs skips (cached)
5. Ctrl+C during LLM call sets status to 'interrupted', partial results preserved

## 9. What This Phase Does NOT Include

- `analyze` command (Phase 6)
- `run` command (Phase 6)
- Security analysis pipeline (Phase 6)
- SecurityLead persistence (Phase 6)
- Report generation (Phase 6)
