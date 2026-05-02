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
    pub ietf_draft_analyzer_version: String,
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
    #[allow(clippy::too_many_arguments)]
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
                ietf_draft_analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
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
