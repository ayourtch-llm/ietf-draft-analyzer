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

#[allow(clippy::too_many_arguments)]
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
        conn,
        &llm,
        protocol,
        category_filter,
        min_severity,
        &config.llm,
    )
    .await?;

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
    let sm_count = analysis_store::get_state_machines(conn, protocol, None)
        .await?
        .len();

    let report = AnalysisReport::build(
        protocol,
        &rfc_numbers,
        graph_summary,
        sm_count,
        result.leads,
        result.implementation_checks,
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
