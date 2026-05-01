use crate::commands;
use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

#[allow(clippy::too_many_arguments)]
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
    commands::map::cmd_map(conn, config, rfcs, Some(protocol.to_string()), depth, false).await?;

    if cancel_token.is_cancelled() {
        tracing::info!("Cancelled after map stage");
        return Ok(());
    }

    // Stage 2: Model
    tracing::info!("=== Stage 2: Model ===");
    commands::model::cmd_model(conn, config, protocol, None, cancel_token.clone()).await?;

    if cancel_token.is_cancelled() {
        tracing::info!("Cancelled after model stage");
        return Ok(());
    }

    // Stage 3: Analyze
    tracing::info!("=== Stage 3: Analyze ===");
    commands::analyze::cmd_analyze(
        conn,
        config,
        protocol,
        None,
        "low",
        output,
        format,
        cancel_token,
    )
    .await?;

    Ok(())
}
