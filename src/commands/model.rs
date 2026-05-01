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
    let count = modeling::run_stage2(conn, &llm, protocol, mechanism_filter, &config.llm).await?;

    if count > 0 {
        tracing::info!(
            "Model complete: {} state machines for '{}'",
            count,
            protocol
        );
    } else {
        tracing::info!("No new state machines extracted (may already be cached)");
    }

    Ok(())
}
