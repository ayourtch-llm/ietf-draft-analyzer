use crate::config::LlmConfig;
use crate::db::{analysis_store, rfc_store};
use crate::error::{Result, RfcAnalyzerError};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::section_select;
use crate::pipeline::summarize;
use crate::rfc::model::*;
use rusqlite::OptionalExtension;
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
    llm_config: &LlmConfig,
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
        conn,
        &rfc_numbers,
        &categories,
        llm.model(),
        llm_config,
        protocol,
    )
    .await?;

    // Check for completed run
    if let Some(existing_run_id) =
        analysis_store::find_completed_run(conn, protocol, "analyze", &input_hash).await?
    {
        tracing::info!("Stage 3 already completed with matching inputs, loading results");
        let leads = load_existing_leads(conn, existing_run_id, min_severity).await?;
        return Ok(Stage3Result {
            leads,
            run_id: Some(existing_run_id),
            total_tokens: 0,
            input_hash,
        });
    }

    // Check for resumable run
    let run_id = if let Some(existing_run) =
        analysis_store::find_resumable_run(conn, protocol, "analyze", &input_hash).await?
    {
        tracing::info!("Resuming interrupted Stage 3 run {}", existing_run);
        existing_run
    } else {
        analysis_store::create_run(
            conn,
            protocol,
            "analyze",
            Some(llm.model()),
            &rfc_numbers,
            None,
            None,
            None,
            Some(&categories.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            prompts::PROMPT_VERSION,
            &input_hash,
        )
        .await?
    };

    let mut total_tokens: u64 = 0;
    let mut all_leads: Vec<SecurityLead> = Vec::new();

    // Load already-persisted leads from prior attempts of this run (for resume)
    let prior_leads = load_existing_leads(conn, run_id, min_severity)
        .await
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
    let completed_categories =
        analysis_store::get_completed_work_items(conn, run_id, "category").await?;

    // Run analysis for each category
    for (i, category) in categories.iter().enumerate() {
        // Check cancellation
        if llm.cancel_token().is_cancelled() {
            tracing::info!("Cancelled, persisting partial results");
            analysis_store::complete_run(
                conn,
                run_id,
                "interrupted",
                total_tokens,
                &rfc_numbers,
                None,
            )
            .await?;
            // Apply dedup/filter/rank even on partial results
            let deduplicated = deduplicate_leads(&all_leads);
            let mut ranked = filter_by_severity(deduplicated, min_severity);
            rank_leads(&mut ranked);
            return Ok(Stage3Result {
                leads: ranked,
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

        tracing::info!(
            "Analyzing category {}/{}: {}",
            i + 1,
            categories.len(),
            category
        );
        analysis_store::upsert_work_item(conn, run_id, "category", category, "running").await?;

        // Select relevant sections for this category
        let selected =
            section_select::select_sections_for_category(category, &all_sections, &sm_section_refs);

        if selected.is_empty() {
            tracing::warn!("No relevant sections for category '{}', skipping", category);
            analysis_store::complete_work_item(
                conn,
                run_id,
                "category",
                category,
                0,
                false,
                Some("No relevant sections"),
            )
            .await?;
            continue;
        }

        // Build sections text with summarize-to-fit
        let system_prompt_tokens = llm.estimate_tokens(prompts::INJECTION_DEFENSE) + 300;
        let sm_tokens = llm.estimate_tokens(&sm_summary);
        let budget = llm.context_budget(system_prompt_tokens + sm_tokens);

        let cluster_ids: Vec<(u32, String)> = selected
            .iter()
            .map(|(rfc, sec)| (rfc.0, sec.number.clone()))
            .collect();

        let (sections_text, dropped) = summarize::summarize_to_fit(
            &all_sections
                .iter()
                .map(|(r, s)| (*r, s))
                .collect::<Vec<_>>(),
            &cluster_ids,
            budget,
            &rfc_numbers,
        );

        if sections_text.is_empty() {
            analysis_store::complete_work_item(
                conn,
                run_id,
                "category",
                category,
                0,
                true,
                Some("All sections dropped"),
            )
            .await?;
            continue;
        }

        // Build and send the security analysis prompt
        let (system, user) =
            prompts::security_analysis_prompt(category, &sm_summary, &sections_text);
        let messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: system,
            },
            ChatMessage {
                role: "user".to_string(),
                content: user,
            },
        ];

        let category_tokens: u64;
        let grammar = crate::llm::prompts::security_leads_grammar();
        match crate::llm::response::parse_json_array_partial::<LeadResponse>(&match llm
            .chat_with_grammar(messages, &grammar)
            .await
        {
            Ok((content, usage)) => {
                category_tokens = usage.total_tokens;
                total_tokens += category_tokens;
                content
            }
            Err(RfcAnalyzerError::LlmContextOverflow) => {
                tracing::warn!("Category '{}': context overflow", category);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "category",
                    category,
                    0,
                    false,
                    Some("Context overflow, skipped"),
                )
                .await?;
                continue;
            }
            Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                tracing::warn!("Category '{}': content refused: {}", category, detail);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "category",
                    category,
                    0,
                    false,
                    Some(&detail),
                )
                .await?;
                continue;
            }
            Err(e) => {
                // Check if this was a cancellation
                let status = if llm.cancel_token().is_cancelled() {
                    "interrupted"
                } else {
                    "failed"
                };
                analysis_store::complete_run(
                    conn,
                    run_id,
                    status,
                    total_tokens,
                    &rfc_numbers,
                    Some(&e.to_string()),
                )
                .await?;
                return Err(e);
            }
        }) {
            Ok(leads) => {
                let processed: Vec<SecurityLead> = leads
                    .into_iter()
                    .map(|lead| process_lead(lead, protocol))
                    .collect();

                tracing::info!("Category '{}': {} leads found", category, processed.len());

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
                    conn,
                    run_id,
                    "category",
                    category,
                    category_tokens,
                    false,
                    notes.as_deref(),
                )
                .await?;
            }
            Err(e) => {
                tracing::warn!("Category '{}': failed to parse leads: {}", category, e);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "category",
                    category,
                    0,
                    true,
                    Some(&e.to_string()),
                )
                .await?;
            }
        }
    }

    // Mark run as completed
    analysis_store::complete_run(conn, run_id, "completed", total_tokens, &rfc_numbers, None)
        .await?;

    // Deduplicate and rank
    let deduplicated = deduplicate_leads(&all_leads);
    let mut ranked = filter_by_severity(deduplicated, min_severity);
    rank_leads(&mut ranked);

    tracing::info!(
        "Stage 3 complete: {} leads (after dedup/filter)",
        ranked.len()
    );
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
    let normalized_name = lead
        .technique_name
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut refs: Vec<String> = lead
        .rfc_references
        .iter()
        .map(|r| format!("{}:{}", r.rfc, r.section))
        .collect();
    refs.sort();

    let input = format!(
        "{}|{}|{}|{}",
        protocol,
        lead.category,
        normalized_name,
        refs.join(",")
    );
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Deduplicate leads with overlapping fingerprints.
/// Keep the higher-confidence version when fingerprints match.
fn deduplicate_leads(leads: &[SecurityLead]) -> Vec<SecurityLead> {
    let mut seen: std::collections::HashMap<String, &SecurityLead> =
        std::collections::HashMap::new();
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
    leads
        .into_iter()
        .filter(|l| severity_rank(&l.severity) >= min_rank)
        .collect()
}

/// Rank leads: severity tier first (descending), then confidence (descending).
fn rank_leads(leads: &mut [SecurityLead]) {
    leads.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
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
async fn load_existing_leads(
    conn: &Connection,
    run_id: i64,
    min_severity: &str,
) -> Result<Vec<SecurityLead>> {
    let min_severity = min_severity.to_string();
    let raw_leads = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, technique_name, category, severity, confidence,
                    description, rfc_references, prerequisites, entities_involved,
                    mitigation, fingerprint
                 FROM security_leads WHERE run_id = ?1
                 ORDER BY id",
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
                        rfc_references: serde_json::from_str(&row.get::<_, String>(6)?)
                            .unwrap_or_default(),
                        prerequisites: serde_json::from_str(&row.get::<_, String>(7)?)
                            .unwrap_or_default(),
                        entities_involved: serde_json::from_str(&row.get::<_, String>(8)?)
                            .unwrap_or_default(),
                        mitigation: row.get(9)?,
                        fingerprint: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
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
        if let Ok(sm) = serde_json::from_str::<serde_json::Value>(data_json)
            && let Some(states) = sm["states"].as_array()
        {
            let state_names: Vec<&str> = states.iter().filter_map(|s| s["name"].as_str()).collect();
            if !state_names.is_empty() {
                summary.push_str(&format!("  States: {}\n", state_names.join(", ")));
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
                        state["source_section"].as_str(),
                    ) {
                        refs.push((rfc as u32, sec.to_string()));
                    }
                }
            }
            if let Some(transitions) = sm["transitions"].as_array() {
                for t in transitions {
                    if let (Some(rfc), Some(sec)) =
                        (t["source_rfc"].as_u64(), t["source_section"].as_str())
                    {
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
    config: &LlmConfig,
    protocol: &str,
) -> Result<String> {
    let mut sorted_rfcs: Vec<u32> = rfc_numbers.iter().map(|r| r.0).collect();
    sorted_rfcs.sort();

    // Load state machines for hashing — use actual protocol, sorted by name
    let mut state_machines = analysis_store::get_state_machines(conn, protocol, None).await?;
    state_machines.sort_by(|a, b| a.0.cmp(&b.0)); // sort by name alphabetically

    // Load section texts
    let mut section_texts = String::new();
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

    // 1: sorted RFC numbers
    hasher.update(
        sorted_rfcs
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    );
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

/// Public API: load leads for a protocol from the latest completed run,
/// applying dedup/filter/rank.
pub async fn load_existing_leads_public(
    conn: &Connection,
    protocol: &str,
    min_severity: &str,
) -> Result<Vec<SecurityLead>> {
    let protocol_str = protocol.to_string();
    let leads = conn
        .call(move |conn| {
            // Find latest completed analyze run for this protocol
            let run_id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM analysis_runs
                     WHERE protocol = ?1 AND stage = 'analyze' AND status = 'completed'
                     ORDER BY id DESC LIMIT 1",
                    [&protocol_str],
                    |row| row.get(0),
                )
                .optional()?;

            let Some(run_id) = run_id else {
                return Ok(Vec::new());
            };

            let mut stmt = conn.prepare(
                "SELECT id, technique_name, category, severity, confidence,
                    description, rfc_references, prerequisites, entities_involved,
                    mitigation, fingerprint
                 FROM security_leads WHERE run_id = ?1
                 ORDER BY id",
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
                        rfc_references: serde_json::from_str(&row.get::<_, String>(6)?)
                            .unwrap_or_default(),
                        prerequisites: serde_json::from_str(&row.get::<_, String>(7)?)
                            .unwrap_or_default(),
                        entities_involved: serde_json::from_str(&row.get::<_, String>(8)?)
                            .unwrap_or_default(),
                        mitigation: row.get(9)?,
                        fingerprint: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(leads)
        })
        .await?;

    let deduplicated = deduplicate_leads(&leads);
    let mut ranked = filter_by_severity(deduplicated, min_severity);
    rank_leads(&mut ranked);
    Ok(ranked)
}

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
                LeadRfcRef {
                    rfc: 1035,
                    section: "4.1".to_string(),
                    quote: None,
                },
                LeadRfcRef {
                    rfc: 1035,
                    section: "7.3".to_string(),
                    quote: Some("cached".to_string()),
                },
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
            confidence: 0.9,                // higher confidence
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
                id: "1".to_string(),
                severity: "low".to_string(),
                confidence: 0.9,
                fingerprint: "a".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
            },
            SecurityLead {
                id: "2".to_string(),
                severity: "critical".to_string(),
                confidence: 0.5,
                fingerprint: "b".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
            },
            SecurityLead {
                id: "3".to_string(),
                severity: "critical".to_string(),
                confidence: 0.9,
                fingerprint: "c".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
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
                id: "1".to_string(),
                severity: "low".to_string(),
                confidence: 0.9,
                fingerprint: "a".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
            },
            SecurityLead {
                id: "2".to_string(),
                severity: "high".to_string(),
                confidence: 0.5,
                fingerprint: "b".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
            },
        ];

        let filtered = filter_by_severity(leads, "medium");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "2"); // only high passes medium threshold
    }

    #[test]
    fn test_format_state_machine_summary() {
        let machines = vec![(
            "TCP Connection".to_string(),
            "state".to_string(),
            r#"{"states":[{"name":"LISTEN"},{"name":"ESTABLISHED"}],"transitions":[]}"#.to_string(),
        )];
        let summary = format_state_machine_summary(&machines);
        assert!(summary.contains("TCP Connection"));
        assert!(summary.contains("LISTEN"));
        assert!(summary.contains("ESTABLISHED"));
    }
}
