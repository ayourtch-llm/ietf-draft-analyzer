use anyhow::Result;
use clap::Parser;
use ietf_draft_analyzer::cli::{Cli, Command};
use ietf_draft_analyzer::config::Config;
use ietf_draft_analyzer::db;
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
            ietf_draft_analyzer::commands::map::cmd_map(
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
            ietf_draft_analyzer::commands::show::cmd_show(&conn, rfc).await?;
        }
        Command::Clear { scope, yes } => {
            ietf_draft_analyzer::commands::clear::cmd_clear(&conn, &scope, yes).await?;
        }
        Command::Graph { target, format } => {
            ietf_draft_analyzer::commands::graph::cmd_graph(&conn, &target, &format).await?;
        }
        Command::Model {
            protocol,
            mechanisms,
        } => {
            ietf_draft_analyzer::commands::model::cmd_model(
                &conn,
                &config,
                &protocol,
                mechanisms,
                cancel_token,
            )
            .await?;
        }
        Command::Analyze {
            protocol,
            categories,
            min_severity,
            output,
            format,
        } => {
            ietf_draft_analyzer::commands::analyze::cmd_analyze(
                &conn,
                &config,
                &protocol,
                categories,
                &min_severity,
                output,
                &format,
                cancel_token,
            )
            .await?;
        }
        Command::Run {
            protocol,
            rfcs,
            depth,
            output,
            format,
        } => {
            ietf_draft_analyzer::commands::run::cmd_run(
                &conn,
                &config,
                &protocol,
                rfcs,
                depth,
                output,
                &format,
                cancel_token,
            )
            .await?;
        }
        Command::Import {
            file,
            number,
            protocol,
        } => {
            ietf_draft_analyzer::commands::import::cmd_import(
                &conn, &config, &file, number, protocol,
            )
            .await?;
        }
        Command::Reproduce {
            protocol,
            output_dir,
            min_severity,
            fingerprint,
            language,
        } => {
            ietf_draft_analyzer::commands::reproduce::cmd_reproduce(
                &conn,
                &config,
                &protocol,
                output_dir,
                &min_severity,
                fingerprint,
                &language,
                cancel_token,
            )
            .await?;
        }
    }

    Ok(())
}
