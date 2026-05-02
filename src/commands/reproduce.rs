use crate::config::Config;
use crate::db::rfc_store;
use crate::llm::client::LlmClient;
use crate::output::poc;
use crate::pipeline::analysis;
use crate::pipeline::reproduce;
use anyhow::Result;
use std::path::PathBuf;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

#[allow(clippy::too_many_arguments)]
pub async fn cmd_reproduce(
    conn: &Connection,
    config: &Config,
    protocol: &str,
    output_dir: PathBuf,
    min_severity: &str,
    fingerprint: Option<String>,
    language: &str,
    cancel_token: CancellationToken,
) -> Result<()> {
    if language != "python" {
        anyhow::bail!("Only 'python' language is supported in v1.");
    }

    // Load existing leads
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    if rfc_numbers.is_empty() {
        anyhow::bail!(
            "No RFCs mapped for protocol '{}'. Run the analysis first.",
            protocol
        );
    }

    // Load leads from the latest analysis
    let all_leads = analysis::load_existing_leads_public(conn, protocol, min_severity).await?;
    if all_leads.is_empty() {
        anyhow::bail!(
            "No security leads found for '{}'. Run 'analyze {}' first.",
            protocol,
            protocol
        );
    }

    // Filter by fingerprint if specified
    let leads: Vec<_> = if let Some(ref fp) = fingerprint {
        all_leads
            .into_iter()
            .filter(|l| l.fingerprint == *fp)
            .collect()
    } else {
        all_leads
    };

    if leads.is_empty() {
        anyhow::bail!("No leads match the specified fingerprint.");
    }

    tracing::info!(
        "Generating PoCs for {} leads (protocol: {}, severity >= {}, language: {})",
        leads.len(),
        protocol,
        min_severity,
        language
    );

    let llm = LlmClient::new(config.llm.clone(), cancel_token)?;

    let pocs = reproduce::generate_pocs(conn, &llm, protocol, &leads, language).await?;

    if pocs.is_empty() {
        tracing::warn!("No PoCs generated (all leads failed or were skipped).");
        return Ok(());
    }

    // Write to output directory
    poc::write_pocs(&output_dir, protocol, &pocs)?;

    println!(
        "Generated {} PoC scripts in {}/",
        pocs.len(),
        output_dir.display()
    );

    Ok(())
}
