use crate::config::LlmConfig;
use crate::db::{analysis_store, rfc_store};
use crate::error::{Result, RfcAnalyzerError};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::summarize;
use crate::rfc::model::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_rusqlite::Connection;

/// LLM response type for mechanism clustering.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClusteringResponse {
    pub clusters: Vec<MechanismCluster>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MechanismCluster {
    pub mechanism: String,
    pub sections: Vec<SectionRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SectionRef {
    pub rfc: u32,
    pub section: String,
}

/// LLM response type for state machine extraction.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateMachineResponse {
    pub name: String,
    pub states: Vec<StateResponse>,
    pub transitions: Vec<TransitionResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StateResponse {
    pub name: String,
    pub description: String,
    pub source_rfc: u32,
    pub source_section: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    llm_config: &LlmConfig,
) -> Result<usize> {
    // Get protocol RFCs
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    if rfc_numbers.is_empty() {
        return Err(RfcAnalyzerError::NoMappedRfcs(protocol.to_string()));
    }

    // Compute input hash for caching
    let input_hash = compute_stage2_hash(
        conn,
        &rfc_numbers,
        mechanism_filter,
        llm.model(),
        llm_config,
    )
    .await?;

    // Check for existing completed run
    if let Some(_existing_run) =
        analysis_store::find_completed_run(conn, protocol, "model", &input_hash).await?
    {
        tracing::info!("Stage 2 already completed with matching inputs, skipping");
        return Ok(0);
    }

    // Check for an existing resumable run (running or interrupted) with matching input_hash
    let run_id = if let Some(existing_id) =
        analysis_store::find_resumable_run(conn, protocol, "model", &input_hash).await?
    {
        tracing::info!("Resuming existing run {}", existing_id);
        existing_id
    } else {
        analysis_store::create_run(
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
        )
        .await?
    };

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
    let section_list: Vec<(u32, &str, &str)> = all_sections
        .iter()
        .map(|(rfc, sec)| (rfc.0, sec.number.as_str(), sec.title.as_str()))
        .collect();

    let (system, user) = prompts::mechanism_clustering_prompt(protocol, &section_list);
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

    let grammar = prompts::clustering_grammar();
    let (clustering, usage) = match llm.chat_json_grammar::<ClusteringResponse>(messages, &grammar).await {
        Ok(result) => result,
        Err(e) => {
            // Check if this was a cancellation — mark interrupted, not failed
            let status = if llm.cancel_token().is_cancelled() {
                "interrupted"
            } else {
                "failed"
            };
            analysis_store::complete_run(
                conn,
                run_id,
                status,
                0,
                &rfc_numbers,
                Some(&e.to_string()),
            )
            .await?;
            return Err(e);
        }
    };
    total_tokens += usage.total_tokens;

    // Filter clusters if mechanism_filter is specified
    let clusters: Vec<&MechanismCluster> = if let Some(filter) = mechanism_filter {
        clustering
            .clusters
            .iter()
            .filter(|c| {
                filter
                    .iter()
                    .any(|f| c.mechanism.to_lowercase().contains(&f.to_lowercase()))
            })
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
                conn,
                run_id,
                "interrupted",
                total_tokens,
                &rfc_numbers,
                None,
            )
            .await?;
            return Ok(machines_count);
        }

        // Check if this work item was already completed (resumability)
        let completed = analysis_store::get_completed_work_items(conn, run_id, "mechanism").await?;
        if completed.contains(&mechanism.to_string()) {
            tracing::debug!("Mechanism '{}' already completed, skipping", mechanism);
            continue;
        }

        tracing::info!(
            "Extracting state machine {}/{}: '{}'",
            i + 1,
            clusters.len(),
            mechanism
        );
        analysis_store::upsert_work_item(conn, run_id, "mechanism", mechanism, "running").await?;

        // Gather sections for this cluster
        let cluster_section_ids: Vec<(u32, String)> = cluster
            .sections
            .iter()
            .map(|s| (s.rfc, s.section.clone()))
            .collect();

        let cluster_sections: Vec<(RfcNumber, &Section)> = all_sections
            .iter()
            .filter(|(rfc, sec)| {
                cluster
                    .sections
                    .iter()
                    .any(|cs| cs.rfc == rfc.0 && cs.section == sec.number)
            })
            .map(|(rfc, sec)| (*rfc, sec))
            .collect();

        if cluster_sections.is_empty() {
            tracing::warn!("No sections found for mechanism '{}', skipping", mechanism);
            analysis_store::complete_work_item(
                conn,
                run_id,
                "mechanism",
                mechanism,
                0,
                true,
                Some("No matching sections"),
            )
            .await?;
            continue;
        }

        // Summarize to fit context budget
        let system_prompt_tokens = llm.estimate_tokens(prompts::INJECTION_DEFENSE) + 200; // overhead
        let budget = llm.context_budget(system_prompt_tokens);

        let all_sections_refs: Vec<(RfcNumber, &Section)> =
            all_sections.iter().map(|(rfc, sec)| (*rfc, sec)).collect();

        let (sections_text, dropped) = summarize::summarize_to_fit(
            &all_sections_refs,
            &cluster_section_ids,
            budget,
            &rfc_numbers,
        );

        if !dropped.is_empty() {
            tracing::warn!("Dropped sections for '{}': {:?}", mechanism, dropped);
        }

        // Check if we exceeded budget even after summarization
        if llm.estimate_tokens(&sections_text) > budget {
            let err = format!(
                "Oversized cluster '{}' exceeds context budget after summarization",
                mechanism
            );
            tracing::warn!("{}", err);
            analysis_store::complete_work_item(
                conn,
                run_id,
                "mechanism",
                mechanism,
                0,
                true,
                Some(&err),
            )
            .await?;
            continue;
        }

        // Send to LLM for state machine extraction
        let (system, user) = prompts::state_machine_prompt(protocol, mechanism, &sections_text);
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

        let grammar = prompts::state_machine_grammar();
        match llm.chat_json_grammar::<StateMachineResponse>(messages, &grammar).await {
            Ok((sm_response, usage)) => {
                total_tokens += usage.total_tokens;

                // Validate the state machine
                let warnings = validate_state_machine(&sm_response);
                for warning in &warnings {
                    tracing::warn!("State machine '{}': {}", sm_response.name, warning);
                }

                // Serialize and store
                let data_json =
                    serde_json::to_string(&sm_response).unwrap_or_else(|_| "{}".to_string());
                let content_hash = {
                    let mut hasher = Sha256::new();
                    hasher.update(data_json.as_bytes());
                    format!("{:x}", hasher.finalize())
                };

                analysis_store::store_state_machine(
                    conn,
                    protocol,
                    &sm_response.name,
                    mechanism,
                    &data_json,
                    &content_hash,
                    run_id,
                )
                .await?;

                machines_count += 1;
                let truncation_notes = if dropped.is_empty() {
                    None
                } else {
                    Some(format!("Truncated sections: {}", dropped.join(", ")))
                };
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "mechanism",
                    mechanism,
                    usage.total_tokens,
                    false,
                    truncation_notes.as_deref(),
                )
                .await?;
            }
            Err(RfcAnalyzerError::LlmContextOverflow) => {
                let err = "Context overflow despite summarization";
                tracing::warn!("Mechanism '{}': {}", mechanism, err);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "mechanism",
                    mechanism,
                    0,
                    true,
                    Some(err),
                )
                .await?;
            }
            Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                tracing::warn!("Mechanism '{}': LLM refused: {}", mechanism, detail);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "mechanism",
                    mechanism,
                    0,
                    true,
                    Some(&detail),
                )
                .await?;
            }
            Err(RfcAnalyzerError::LlmParse { detail }) => {
                tracing::warn!("Mechanism '{}': LLM response parse failed: {}", mechanism, detail);
                analysis_store::complete_work_item(
                    conn,
                    run_id,
                    "mechanism",
                    mechanism,
                    0,
                    true,
                    Some(&format!("Parse error: {}", detail)),
                )
                .await?;
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
        }
    }

    // Mark run as completed
    analysis_store::complete_run(conn, run_id, "completed", total_tokens, &rfc_numbers, None)
        .await?;

    tracing::info!(
        "Stage 2 complete: {} state machines extracted",
        machines_count
    );
    Ok(machines_count)
}

/// Validate a state machine for structural issues.
/// Returns a list of warnings (does not fail).
fn validate_state_machine(sm: &StateMachineResponse) -> Vec<String> {
    let mut warnings = Vec::new();
    let state_names: Vec<&str> = sm.states.iter().map(|s| s.name.as_str()).collect();

    for t in &sm.transitions {
        if !state_names.contains(&t.from.as_str()) {
            warnings.push(format!("Transition from undefined state '{}'", t.from));
        }
        if !state_names.contains(&t.to.as_str()) {
            warnings.push(format!("Transition to undefined state '{}'", t.to));
        }
    }

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
    config: &LlmConfig,
) -> Result<String> {
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

    let rfcs_str = sorted_rfcs
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(",");
    hasher.update(rfcs_str.as_bytes());
    hasher.update(b"|");

    let section_hash = {
        let mut h = Sha256::new();
        h.update(section_texts.as_bytes());
        format!("{:x}", h.finalize())
    };
    hasher.update(section_hash.as_bytes());
    hasher.update(b"|");

    hasher.update(prompts::PROMPT_VERSION.as_bytes());
    hasher.update(b"|");

    hasher.update(model.as_bytes());
    hasher.update(b"|");

    hasher.update(config.temperature.to_string().as_bytes());
    hasher.update(b"|");

    hasher.update(config.max_tokens_per_request.to_string().as_bytes());
    hasher.update(b"|");

    hasher.update(config.model_context_window.to_string().as_bytes());
    hasher.update(b"|");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_state_machine_clean() {
        let sm = StateMachineResponse {
            name: "TCP Connection".to_string(),
            states: vec![
                StateResponse {
                    name: "CLOSED".to_string(),
                    description: "".to_string(),
                    source_rfc: 9293,
                    source_section: "3.3".to_string(),
                },
                StateResponse {
                    name: "LISTEN".to_string(),
                    description: "".to_string(),
                    source_rfc: 9293,
                    source_section: "3.3".to_string(),
                },
            ],
            transitions: vec![TransitionResponse {
                from: "CLOSED".to_string(),
                to: "LISTEN".to_string(),
                trigger: "passive open".to_string(),
                conditions: vec![],
                actions: vec![],
                source_rfc: 9293,
                source_section: "3.4".to_string(),
            }],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_state_machine_undefined_state() {
        let sm = StateMachineResponse {
            name: "Bad".to_string(),
            states: vec![StateResponse {
                name: "A".to_string(),
                description: "".to_string(),
                source_rfc: 1,
                source_section: "1".to_string(),
            }],
            transitions: vec![TransitionResponse {
                from: "A".to_string(),
                to: "B".to_string(),
                trigger: "x".to_string(),
                conditions: vec![],
                actions: vec![],
                source_rfc: 1,
                source_section: "1".to_string(),
            }],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.iter().any(|w| w.contains("undefined state 'B'")));
    }

    #[test]
    fn test_validate_state_machine_orphan() {
        let sm = StateMachineResponse {
            name: "Orphan".to_string(),
            states: vec![
                StateResponse {
                    name: "A".to_string(),
                    description: "".to_string(),
                    source_rfc: 1,
                    source_section: "1".to_string(),
                },
                StateResponse {
                    name: "ORPHAN".to_string(),
                    description: "".to_string(),
                    source_rfc: 1,
                    source_section: "2".to_string(),
                },
                StateResponse {
                    name: "B".to_string(),
                    description: "".to_string(),
                    source_rfc: 1,
                    source_section: "3".to_string(),
                },
            ],
            transitions: vec![TransitionResponse {
                from: "A".to_string(),
                to: "B".to_string(),
                trigger: "x".to_string(),
                conditions: vec![],
                actions: vec![],
                source_rfc: 1,
                source_section: "1".to_string(),
            }],
        };
        let warnings = validate_state_machine(&sm);
        assert!(warnings.iter().any(|w| w.contains("Orphan state 'ORPHAN'")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stage2_hash_changes_with_inputs() {
        let conn = crate::db::open_memory_database().await.unwrap();

        // Set up minimal RFC data
        use crate::db::rfc_store;
        let rfc = crate::rfc::model::Rfc {
            number: RfcNumber(9293),
            title: "TCP".to_string(),
            format: crate::rfc::model::RfcFormat::Xml,
            status: crate::rfc::model::RfcStatus::Standard,
            date: chrono::NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
            obsoletes: vec![],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![crate::rfc::model::Section {
                number: "1".to_string(),
                title: "Intro".to_string(),
                anchor: None,
                depth: 1,
                text: "Hello".to_string(),
                cross_refs: vec![],
                pn: None,
            }],
            references: vec![],
            raw_text: "text".to_string(),
            content_hash: "h".to_string(),
        };
        rfc_store::upsert_rfc(&conn, &rfc).await.unwrap();

        use crate::config::LlmConfig;
        let config1 = LlmConfig {
            temperature: 0.2,
            max_tokens_per_request: 4096,
            model_context_window: 128000,
            model: "gpt-4o".to_string(),
            ..LlmConfig::default()
        };
        let config2 = LlmConfig {
            temperature: 0.5,
            ..config1.clone()
        };

        let hash1 = compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config1)
            .await
            .unwrap();
        let hash2 = compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config2)
            .await
            .unwrap();

        // Different temperature → different hash
        assert_ne!(hash1, hash2);

        // Different mechanism filter → different hash
        let hash3 = compute_stage2_hash(
            &conn,
            &[RfcNumber(9293)],
            Some(&["auth".to_string()]),
            "gpt-4o",
            &config1,
        )
        .await
        .unwrap();
        assert_ne!(hash1, hash3);

        // Different model → different hash
        let hash_model =
            compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-3.5-turbo", &config1)
                .await
                .unwrap();
        assert_ne!(hash1, hash_model);

        // Different max_tokens → different hash
        let config_tokens = LlmConfig {
            max_tokens_per_request: 8192,
            ..config1.clone()
        };
        let hash_tokens =
            compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config_tokens)
                .await
                .unwrap();
        assert_ne!(hash1, hash_tokens);

        // Different context_window → different hash
        let config_window = LlmConfig {
            model_context_window: 32000,
            ..config1.clone()
        };
        let hash_window =
            compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config_window)
                .await
                .unwrap();
        assert_ne!(hash1, hash_window);

        // Different RFC list → different hash
        let rfc2 = crate::rfc::model::Rfc {
            number: RfcNumber(793),
            content_hash: "h2".to_string(),
            title: "Old TCP".to_string(),
            ..rfc.clone()
        };
        rfc_store::upsert_rfc(&conn, &rfc2).await.unwrap();
        let hash_rfcs = compute_stage2_hash(
            &conn,
            &[RfcNumber(9293), RfcNumber(793)],
            None,
            "gpt-4o",
            &config1,
        )
        .await
        .unwrap();
        assert_ne!(hash1, hash_rfcs);

        // Different section text → different hash
        let mut rfc_modified = rfc.clone();
        rfc_modified.sections[0].text = "Changed text".to_string();
        rfc_modified.content_hash = "h_modified".to_string();
        rfc_store::upsert_rfc(&conn, &rfc_modified).await.unwrap();
        let hash_text = compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config1)
            .await
            .unwrap();
        assert_ne!(hash1, hash_text);

        // Same inputs → same hash (deterministic)
        let hash4 = compute_stage2_hash(&conn, &[RfcNumber(9293)], None, "gpt-4o", &config1)
            .await
            .unwrap();
        assert_eq!(hash_text, hash4);
    }
}
