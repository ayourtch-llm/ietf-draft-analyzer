use anyhow::Result;
use clap::Parser;
use rfc_analyzer::cli::{Cli, Command};
use rfc_analyzer::config::Config;
use rfc_analyzer::db;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    // Load config
    let config = Config::load(&cli.config)?;

    // Open database
    let conn = db::open_database(&cli.db).await?;

    // Set up graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Interrupt received, finishing current work item...");
        cancel_clone.cancel();
    });

    match cli.command {
        Command::Map {
            rfcs,
            protocol,
            depth,
            normative_only,
        } => {
            rfc_analyzer::commands::map::cmd_map(
                &conn,
                &config,
                rfcs,
                protocol,
                depth,
                normative_only,
            )
            .await?;
        }
        Command::Show { rfc } => {
            rfc_analyzer::commands::show::cmd_show(&conn, rfc).await?;
        }
        Command::Clear { scope, yes } => {
            rfc_analyzer::commands::clear::cmd_clear(&conn, &scope, yes).await?;
        }
        Command::Graph { target, format } => {
            rfc_analyzer::commands::graph::cmd_graph(&conn, &target, &format).await?;
        }
        _ => {
            eprintln!("Command not yet implemented.");
            std::process::exit(1);
        }
    }

    Ok(())
}
