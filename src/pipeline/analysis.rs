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
    #[serde(default = "default_assessment")]
    pub assessment: String,
    #[serde(default)]
    pub security_context: Option<String>,
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
    #[serde(default = "default_assessment")]
    pub assessment: String,
    #[serde(default)]
    pub security_context: Option<String>,
    pub description: String,
    pub rfc_references: Vec<LeadRfcRef>,
    pub prerequisites: Vec<String>,
    pub entities_involved: Vec<String>,
    pub mitigation: Option<String>,
    pub fingerprint: String,
    #[serde(default)]
    pub related_categories: Vec<String>,
    #[serde(default = "default_merged_lead_count")]
    pub merged_lead_count: usize,
}

fn default_assessment() -> String {
    "unclassified".to_string()
}

fn default_merged_lead_count() -> usize {
    1
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

    // Treat Security Considerations and their descendants as a baseline that
    // every category must evaluate, not just as ordinary scored sections.
    let security_sections = section_select::select_security_context(&all_sections);
    let security_section_keys: std::collections::HashSet<(u32, String)> = security_sections
        .iter()
        .map(|(rfc, section)| (rfc.0, section.number.clone()))
        .collect();

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
            let ranked = prepare_leads(&all_leads, min_severity);
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

        if selected.is_empty() && security_sections.is_empty() {
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

        let all_section_refs = all_sections
            .iter()
            .map(|(rfc, section)| (*rfc, section))
            .collect::<Vec<_>>();
        let security_ids: Vec<(u32, String)> = security_sections
            .iter()
            .map(|(rfc, section)| (rfc.0, section.number.clone()))
            .collect();
        let (security_context, security_dropped) = if security_ids.is_empty() {
            (
                "No dedicated Security Considerations section was found.".to_string(),
                Vec::new(),
            )
        } else {
            summarize::summarize_to_fit(&all_section_refs, &security_ids, budget / 3, &rfc_numbers)
        };
        let analysis_budget = budget.saturating_sub(llm.estimate_tokens(&security_context));

        let cluster_ids: Vec<(u32, String)> = selected
            .iter()
            .filter(|(rfc, section)| {
                !security_section_keys.contains(&(rfc.0, section.number.clone()))
            })
            .map(|(rfc, sec)| (rfc.0, sec.number.clone()))
            .collect();

        let (sections_text, dropped) = if cluster_ids.is_empty() {
            (
                "No additional category-specific sections were selected.".to_string(),
                Vec::new(),
            )
        } else {
            summarize::summarize_to_fit(
                &all_section_refs,
                &cluster_ids,
                analysis_budget,
                &rfc_numbers,
            )
        };

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
        let (system, user) = prompts::security_analysis_prompt(
            category,
            &sm_summary,
            &security_context,
            &sections_text,
        );
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
            .chat_text_auto(messages, &grammar)
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

                let notes = if dropped.is_empty() && security_dropped.is_empty() {
                    None
                } else {
                    let mut details = Vec::new();
                    if !security_dropped.is_empty() {
                        details.push(format!("security context: {}", security_dropped.join(", ")));
                    }
                    if !dropped.is_empty() {
                        details.push(format!("analysis sections: {}", dropped.join(", ")));
                    }
                    Some(format!("truncated: {}", details.join("; ")))
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

    // Consolidate semantically equivalent candidates and report only findings
    // that can indicate a specification or residual security issue.
    let ranked = prepare_leads(&all_leads, min_severity);

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
    let category = lead.category;
    SecurityLead {
        id: Uuid::new_v4().to_string(),
        technique_name: lead.technique_name,
        category: category.clone(),
        severity: lead.severity,
        confidence: lead.confidence.clamp(0.0, 1.0),
        assessment: normalize_assessment(&lead.assessment),
        security_context: lead.security_context,
        description: lead.description,
        rfc_references: lead.rfc_references,
        prerequisites: lead.prerequisites,
        entities_involved: lead.entities_involved,
        mitigation: lead.mitigation,
        fingerprint,
        related_categories: vec![category],
        merged_lead_count: 1,
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

/// Deduplicate exact matches and conservative semantic matches.
///
/// Semantic consolidation requires the same non-empty set of cited sections
/// plus substantial overlap in the normalized technique names. This merges
/// cross-category restatements such as "Packet Identifier Reuse Confusion" and
/// "Packet Identifier Reuse Race Condition" without conflating unrelated
/// findings that merely cite the same broad section.
fn deduplicate_leads(leads: &[SecurityLead]) -> Vec<SecurityLead> {
    let mut parents: Vec<usize> = (0..leads.len()).collect();
    for left in 0..leads.len() {
        for right in (left + 1)..leads.len() {
            if semantically_equivalent(&leads[left], &leads[right]) {
                union_components(&mut parents, left, right);
            }
        }
    }

    let mut components: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for index in 0..leads.len() {
        let root = find_component(&mut parents, index);
        components.entry(root).or_default().push(index);
    }

    components
        .into_values()
        .map(|indices| {
            let mut consolidated = leads[indices[0]].clone();
            initialize_merge_metadata(&mut consolidated);
            for index in indices.into_iter().skip(1) {
                merge_lead(&mut consolidated, &leads[index]);
            }
            consolidated
        })
        .collect()
}

fn find_component(parents: &mut [usize], index: usize) -> usize {
    if parents[index] != index {
        parents[index] = find_component(parents, parents[index]);
    }
    parents[index]
}

fn union_components(parents: &mut [usize], left: usize, right: usize) {
    let left_root = find_component(parents, left);
    let right_root = find_component(parents, right);
    if left_root != right_root {
        let (first, second) = if left_root < right_root {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        parents[second] = first;
    }
}

fn initialize_merge_metadata(lead: &mut SecurityLead) {
    if lead.related_categories.is_empty() {
        lead.related_categories.push(lead.category.clone());
    }
    lead.merged_lead_count = lead.merged_lead_count.max(1);
}

fn semantically_equivalent(left: &SecurityLead, right: &SecurityLead) -> bool {
    if left.fingerprint == right.fingerprint {
        return true;
    }

    let left_refs = normalized_reference_set(&left.rfc_references);
    if left_refs.is_empty() || left_refs != normalized_reference_set(&right.rfc_references) {
        return false;
    }

    let left_tokens = normalized_technique_tokens(&left.technique_name);
    let right_tokens = normalized_technique_tokens(&right.technique_name);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return false;
    }

    let intersection = left_tokens.intersection(&right_tokens).count();
    let union = left_tokens.union(&right_tokens).count();
    intersection >= 2 && (intersection as f64 / union as f64) >= 0.6
}

fn normalized_reference_set(
    references: &[LeadRfcRef],
) -> std::collections::BTreeSet<(u32, String)> {
    references
        .iter()
        .map(|reference| {
            (
                reference.rfc,
                reference
                    .section
                    .to_lowercase()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        })
        .collect()
}

fn normalized_technique_tokens(name: &str) -> std::collections::BTreeSet<String> {
    const NOISE_WORDS: &[&str] = &[
        "attack",
        "ambiguity",
        "bypass",
        "condition",
        "confusion",
        "denial",
        "downgrade",
        "implementation",
        "information",
        "leak",
        "missing",
        "race",
        "replay",
        "service",
        "validation",
        "via",
        "vulnerability",
    ];

    name.to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| token.len() > 1 && !NOISE_WORDS.contains(token))
        .map(ToString::to_string)
        .collect()
}

fn merge_lead(existing: &mut SecurityLead, incoming: &SecurityLead) {
    let incoming_is_better = incoming.confidence > existing.confidence
        || (incoming.confidence == existing.confidence
            && (severity_rank(&incoming.severity) > severity_rank(&existing.severity)
                || (severity_rank(&incoming.severity) == severity_rank(&existing.severity)
                    && incoming.technique_name < existing.technique_name)));

    let mut categories = existing.related_categories.clone();
    categories.push(existing.category.clone());
    categories.extend(incoming.related_categories.iter().cloned());
    categories.push(incoming.category.clone());
    categories.sort();
    categories.dedup();

    let merged_count = existing.merged_lead_count.max(1) + incoming.merged_lead_count.max(1);
    let mut merged_references = existing.rfc_references.clone();
    merge_references(&mut merged_references, &incoming.rfc_references);
    let mut prerequisites = existing.prerequisites.clone();
    merge_strings(&mut prerequisites, &incoming.prerequisites);
    let mut entities = existing.entities_involved.clone();
    merge_strings(&mut entities, &incoming.entities_involved);

    if incoming_is_better {
        let mut replacement = incoming.clone();
        replacement.related_categories = categories;
        replacement.merged_lead_count = merged_count;
        replacement.rfc_references = merged_references;
        replacement.prerequisites = prerequisites;
        replacement.entities_involved = entities;
        *existing = replacement;
    } else {
        existing.related_categories = categories;
        existing.merged_lead_count = merged_count;
        existing.rfc_references = merged_references;
        existing.prerequisites = prerequisites;
        existing.entities_involved = entities;
        if existing.security_context.is_none() {
            existing.security_context = incoming.security_context.clone();
        }
        if existing.mitigation.is_none() {
            existing.mitigation = incoming.mitigation.clone();
        }
    }
}

fn merge_references(existing: &mut Vec<LeadRfcRef>, incoming: &[LeadRfcRef]) {
    for reference in incoming {
        if let Some(current) = existing
            .iter_mut()
            .find(|current| current.rfc == reference.rfc && current.section == reference.section)
        {
            if current.quote.is_none() {
                current.quote = reference.quote.clone();
            }
        } else {
            existing.push(reference.clone());
        }
    }
}

fn merge_strings(existing: &mut Vec<String>, incoming: &[String]) {
    for value in incoming {
        if !existing.iter().any(|current| current == value) {
            existing.push(value.clone());
        }
    }
}

fn normalize_assessment(assessment: &str) -> String {
    match assessment.trim().to_lowercase().as_str() {
        "specification_gap" => "specification_gap",
        "known_risk" => "known_risk",
        "implementation_nonconformance" => "implementation_nonconformance",
        "expected_behavior" => "expected_behavior",
        _ => "unclassified",
    }
    .to_string()
}

fn is_actionable_assessment(assessment: &str) -> bool {
    !matches!(
        assessment,
        "implementation_nonconformance" | "expected_behavior"
    )
}

fn prepare_leads(leads: &[SecurityLead], min_severity: &str) -> Vec<SecurityLead> {
    let deduplicated = deduplicate_leads(leads);
    let non_actionable = deduplicated
        .iter()
        .filter(|lead| !is_actionable_assessment(&lead.assessment))
        .count();
    if non_actionable > 0 {
        tracing::info!(
            "Excluded {} implementation-nonconformance/expected-behavior candidates",
            non_actionable
        );
    }

    let actionable: Vec<SecurityLead> = deduplicated
        .into_iter()
        .filter(|lead| is_actionable_assessment(&lead.assessment))
        .collect();
    let mut ranked = filter_by_severity(actionable, min_severity);
    rank_leads(&mut ranked);
    ranked
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
            .then_with(|| a.technique_name.cmp(&b.technique_name))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
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
                 state_machine_name, mitigation, input_hash, run_id, fingerprint,
                 assessment, security_context)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                    ?16, ?17
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
                lead.assessment,
                lead.security_context,
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
                    mitigation, fingerprint, assessment, security_context
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
                        assessment: row.get(11)?,
                        security_context: row.get(12)?,
                        related_categories: vec![row.get(2)?],
                        merged_lead_count: 1,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(leads)
        })
        .await?;

    // Apply same dedup/rank/filter pipeline as a fresh run
    Ok(prepare_leads(&raw_leads, &min_severity))
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
                    mitigation, fingerprint, assessment, security_context
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
                        assessment: row.get(11)?,
                        security_context: row.get(12)?,
                        related_categories: vec![row.get(2)?],
                        merged_lead_count: 1,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(leads)
        })
        .await?;

    Ok(prepare_leads(&leads, min_severity))
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
            assessment: "specification_gap".to_string(),
            security_context: None,
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
            assessment: "specification_gap".to_string(),
            security_context: None,
            description: "".to_string(),
            rfc_references: vec![],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            related_categories: vec!["X".to_string()],
            merged_lead_count: 1,
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
    fn test_semantic_dedup_consolidates_cross_category_restatements() {
        let reference = LeadRfcRef {
            rfc: 99100,
            section: "2.2.1".to_string(),
            quote: None,
        };
        let lead1 = SecurityLead {
            id: "a".to_string(),
            technique_name: "Packet Identifier Reuse Confusion".to_string(),
            category: "StateConfusion".to_string(),
            severity: "medium".to_string(),
            confidence: 0.85,
            assessment: "specification_gap".to_string(),
            security_context: None,
            description: "First description".to_string(),
            rfc_references: vec![reference.clone()],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            fingerprint: "fp-state".to_string(),
            related_categories: vec!["StateConfusion".to_string()],
            merged_lead_count: 1,
        };
        let lead2 = SecurityLead {
            id: "b".to_string(),
            technique_name: "Packet Identifier Reuse Race Condition".to_string(),
            category: "RaceCondition".to_string(),
            severity: "medium".to_string(),
            confidence: 0.9,
            assessment: "specification_gap".to_string(),
            security_context: Some("Security context".to_string()),
            description: "Better description".to_string(),
            rfc_references: vec![reference],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            fingerprint: "fp-race".to_string(),
            related_categories: vec!["RaceCondition".to_string()],
            merged_lead_count: 1,
        };

        let result = deduplicate_leads(&[lead1, lead2]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "b");
        assert_eq!(result[0].merged_lead_count, 2);
        assert_eq!(
            result[0].related_categories,
            vec!["RaceCondition".to_string(), "StateConfusion".to_string()]
        );
    }

    #[test]
    fn test_semantic_dedup_keeps_distinct_findings_in_same_section() {
        let reference = LeadRfcRef {
            rfc: 99100,
            section: "3.8.4".to_string(),
            quote: None,
        };
        let base = SecurityLead {
            id: "a".to_string(),
            technique_name: "Subscription Flooding".to_string(),
            category: "DenialOfService".to_string(),
            severity: "high".to_string(),
            confidence: 0.9,
            assessment: "specification_gap".to_string(),
            security_context: None,
            description: String::new(),
            rfc_references: vec![reference.clone()],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            fingerprint: "flood".to_string(),
            related_categories: vec!["DenialOfService".to_string()],
            merged_lead_count: 1,
        };
        let distinct = SecurityLead {
            id: "b".to_string(),
            technique_name: "Subscription Identifier Reuse".to_string(),
            category: "ImplementationAmbiguity".to_string(),
            fingerprint: "identifier".to_string(),
            rfc_references: vec![reference],
            ..base.clone()
        };

        assert_eq!(deduplicate_leads(&[base, distinct]).len(), 2);
    }

    #[test]
    fn test_semantic_dedup_uses_transitive_components() {
        let reference = LeadRfcRef {
            rfc: 1,
            section: "1".to_string(),
            quote: None,
        };
        let base = SecurityLead {
            id: "a".to_string(),
            technique_name: "Alpha Beta Gamma".to_string(),
            category: "X".to_string(),
            severity: "medium".to_string(),
            confidence: 0.8,
            assessment: "specification_gap".to_string(),
            security_context: None,
            description: String::new(),
            rfc_references: vec![reference],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            fingerprint: "a".to_string(),
            related_categories: vec!["X".to_string()],
            merged_lead_count: 1,
        };
        let bridge = SecurityLead {
            id: "b".to_string(),
            technique_name: "Alpha Beta Gamma Delta".to_string(),
            fingerprint: "b".to_string(),
            ..base.clone()
        };
        let end = SecurityLead {
            id: "c".to_string(),
            technique_name: "Beta Gamma Delta".to_string(),
            fingerprint: "c".to_string(),
            ..base.clone()
        };

        let result = deduplicate_leads(&[base, bridge, end]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].merged_lead_count, 3);
    }

    #[test]
    fn test_prepare_leads_excludes_nonconformance_and_expected_behavior() {
        let base = SecurityLead {
            id: "a".to_string(),
            technique_name: "Gap".to_string(),
            category: "X".to_string(),
            severity: "high".to_string(),
            confidence: 0.9,
            assessment: "specification_gap".to_string(),
            security_context: None,
            description: String::new(),
            rfc_references: vec![],
            prerequisites: vec![],
            entities_involved: vec![],
            mitigation: None,
            fingerprint: "gap".to_string(),
            related_categories: vec!["X".to_string()],
            merged_lead_count: 1,
        };
        let nonconformance = SecurityLead {
            id: "b".to_string(),
            assessment: "implementation_nonconformance".to_string(),
            fingerprint: "nonconformance".to_string(),
            ..base.clone()
        };
        let expected = SecurityLead {
            id: "c".to_string(),
            assessment: "expected_behavior".to_string(),
            fingerprint: "expected".to_string(),
            ..base.clone()
        };

        let result = prepare_leads(&[base, nonconformance, expected], "low");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "a");
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
                assessment: "specification_gap".to_string(),
                security_context: None,
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
                related_categories: vec![],
                merged_lead_count: 1,
            },
            SecurityLead {
                id: "2".to_string(),
                severity: "critical".to_string(),
                confidence: 0.5,
                fingerprint: "b".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                assessment: "specification_gap".to_string(),
                security_context: None,
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
                related_categories: vec![],
                merged_lead_count: 1,
            },
            SecurityLead {
                id: "3".to_string(),
                severity: "critical".to_string(),
                confidence: 0.9,
                fingerprint: "c".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                assessment: "specification_gap".to_string(),
                security_context: None,
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
                related_categories: vec![],
                merged_lead_count: 1,
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
                assessment: "specification_gap".to_string(),
                security_context: None,
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
                related_categories: vec![],
                merged_lead_count: 1,
            },
            SecurityLead {
                id: "2".to_string(),
                severity: "high".to_string(),
                confidence: 0.5,
                fingerprint: "b".to_string(),
                technique_name: "".to_string(),
                category: "".to_string(),
                assessment: "specification_gap".to_string(),
                security_context: None,
                description: "".to_string(),
                rfc_references: vec![],
                prerequisites: vec![],
                entities_involved: vec![],
                mitigation: None,
                related_categories: vec![],
                merged_lead_count: 1,
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
