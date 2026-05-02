use crate::db::rfc_store;
use crate::error::{Result, RfcAnalyzerError};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::analysis::{LeadRfcRef, SecurityLead};
use serde::{Deserialize, Serialize};
use tokio_rusqlite::Connection;

/// LLM response for a PoC script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocResponse {
    pub script_name: String,
    pub description: String,
    pub setup: Vec<String>,
    pub code: String,
    pub expected_vulnerable: String,
    pub expected_patched: String,
    pub caveats: Vec<String>,
}

/// A generated PoC with its source lead.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedPoc {
    pub lead_fingerprint: String,
    pub lead_technique: String,
    pub lead_severity: String,
    pub lead_category: String,
    pub poc: PocResponse,
}

/// Generate PoC scripts for security leads.
pub async fn generate_pocs(
    conn: &Connection,
    llm: &LlmClient,
    _protocol: &str,
    leads: &[SecurityLead],
    language: &str,
) -> Result<Vec<GeneratedPoc>> {
    let mut results = Vec::new();

    for (i, lead) in leads.iter().enumerate() {
        // Check cancellation
        if llm.cancel_token().is_cancelled() {
            tracing::info!(
                "Cancelled, returning {} PoCs generated so far",
                results.len()
            );
            return Ok(results);
        }

        tracing::info!(
            "Generating PoC {}/{}: {} [{}]",
            i + 1,
            leads.len(),
            lead.technique_name,
            lead.severity
        );

        // Gather RFC section text for context
        let sections_text = gather_lead_sections(conn, &lead.rfc_references).await?;

        // Serialize the lead for the prompt
        let lead_json = serde_json::to_string_pretty(lead).unwrap_or_else(|_| "{}".to_string());

        // Build prompt
        let (system, user) = prompts::reproduce_prompt(&lead_json, &sections_text, language);
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

        // Call LLM with grammar constraint
        let grammar = prompts::reproduce_grammar();
        match llm
            .chat_json_auto::<PocResponse>(messages, &grammar)
            .await
        {
            Ok((poc, usage)) => {
                tracing::info!(
                    "PoC generated: {} ({} tokens)",
                    poc.script_name,
                    usage.total_tokens
                );
                results.push(GeneratedPoc {
                    lead_fingerprint: lead.fingerprint.clone(),
                    lead_technique: lead.technique_name.clone(),
                    lead_severity: lead.severity.clone(),
                    lead_category: lead.category.clone(),
                    poc,
                });
            }
            Err(RfcAnalyzerError::LlmContextOverflow) => {
                tracing::warn!(
                    "PoC for '{}': context overflow, skipping",
                    lead.technique_name
                );
            }
            Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                tracing::warn!(
                    "PoC for '{}': content refused: {}",
                    lead.technique_name,
                    detail
                );
            }
            Err(RfcAnalyzerError::LlmParse { detail }) => {
                tracing::warn!(
                    "PoC for '{}': parse failed: {}",
                    lead.technique_name,
                    detail
                );
            }
            Err(e) => {
                if llm.cancel_token().is_cancelled() {
                    tracing::info!("Cancelled during PoC generation");
                    return Ok(results);
                }
                tracing::error!("PoC for '{}': fatal error: {}", lead.technique_name, e);
                return Err(e);
            }
        }
    }

    tracing::info!("Generated {} PoCs for {} leads", results.len(), leads.len());
    Ok(results)
}

/// Gather RFC section text for the sections referenced by a lead.
async fn gather_lead_sections(conn: &Connection, refs: &[LeadRfcRef]) -> Result<String> {
    let mut sections_text = String::new();

    let mut seen = std::collections::HashSet::new();
    for rf in refs {
        if !seen.insert((rf.rfc, rf.section.clone())) {
            continue;
        }
        if let Some(rfc) = rfc_store::get_rfc(conn, rf.rfc).await? {
            // Find the matching section
            for section in &rfc.sections {
                if section.number == rf.section {
                    let formatted = prompts::format_section(
                        rf.rfc,
                        &section.number,
                        &section.title,
                        &section.text,
                    );
                    sections_text.push_str(&formatted);
                    sections_text.push('\n');
                    break;
                }
            }
        }
    }

    if sections_text.is_empty() {
        sections_text = "No specific RFC sections available.".to_string();
    }

    Ok(sections_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poc_response_deserialize() {
        let json = r#"{
            "script_name": "poc_test.py",
            "description": "Test PoC",
            "setup": ["Install python3"],
            "code": "print('hello')",
            "expected_vulnerable": "Crash",
            "expected_patched": "Rejected",
            "caveats": ["Requires root"]
        }"#;
        let poc: PocResponse = serde_json::from_str(json).unwrap();
        assert_eq!(poc.script_name, "poc_test.py");
        assert_eq!(poc.setup.len(), 1);
        assert_eq!(poc.caveats.len(), 1);
    }

    #[test]
    fn test_generated_poc_serialize() {
        let poc = GeneratedPoc {
            lead_fingerprint: "abc123".to_string(),
            lead_technique: "Test Attack".to_string(),
            lead_severity: "high".to_string(),
            lead_category: "MissingValidation".to_string(),
            poc: PocResponse {
                script_name: "poc_test.py".to_string(),
                description: "Tests something".to_string(),
                setup: vec![],
                code: "# test".to_string(),
                expected_vulnerable: "Crash".to_string(),
                expected_patched: "OK".to_string(),
                caveats: vec![],
            },
        };
        let json = serde_json::to_string(&poc).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("Test Attack"));
    }

    #[test]
    fn test_poc_response_missing_optional_fields() {
        let json = "{\"script_name\":\"poc.py\",\"description\":\"Minimal\",\"setup\":[],\"code\":\"#!/usr/bin/env python3\\nprint('hi')\",\"expected_vulnerable\":\"\",\"expected_patched\":\"\",\"caveats\":[]}";
        let poc: PocResponse = serde_json::from_str(json).unwrap();
        assert_eq!(poc.script_name, "poc.py");
    }

    #[test]
    fn test_generated_poc_with_code_containing_newline() {
        let json = "{\"script_name\":\"poc.py\",\"description\":\"Test\",\"setup\":[],\"code\":\"#!/usr/bin/env python3\\nprint('hi')\",\"expected_vulnerable\":\"Crash\",\"expected_patched\":\"OK\",\"caveats\":[]}";
        let poc: PocResponse = serde_json::from_str(json).unwrap();
        assert_eq!(poc.script_name, "poc.py");
        assert!(poc.code.contains('\n'));
    }
}
