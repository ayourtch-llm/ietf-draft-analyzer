use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rfc-analyzer",
    version,
    about = "RFC specification security analyzer"
)]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "rfc-analyzer.toml")]
    pub config: PathBuf,

    /// SQLite database path
    #[arg(long, default_value = "rfc-analyzer.db")]
    pub db: PathBuf,

    /// Verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Fetch and parse RFCs, build the dependency graph
    Map {
        /// Seed RFC numbers
        #[arg(required = true)]
        rfcs: Vec<u32>,

        /// Associate RFCs with a protocol name
        #[arg(long)]
        protocol: Option<String>,

        /// Max depth for transitive dependency crawling
        #[arg(long, default_value = "2")]
        depth: u32,

        /// Only follow normative references
        #[arg(long)]
        normative_only: bool,
    },

    /// Build protocol state machines from mapped RFCs
    Model {
        /// Protocol name
        protocol: String,

        /// Mechanism types to model, comma-separated
        #[arg(long, value_delimiter = ',')]
        mechanisms: Option<Vec<String>>,
    },

    /// Run security analysis on modeled protocols
    Analyze {
        /// Protocol name
        protocol: String,

        /// Attack categories to check, comma-separated
        #[arg(long, value_delimiter = ',')]
        categories: Option<Vec<String>>,

        /// Minimum severity to include
        #[arg(long, default_value = "low")]
        min_severity: String,
    },

    /// Run full pipeline: map -> model -> analyze
    Run {
        /// Protocol name
        protocol: String,

        /// Seed RFC numbers
        #[arg(required = true)]
        rfcs: Vec<u32>,

        /// Max crawl depth
        #[arg(long, default_value = "2")]
        depth: u32,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show the dependency graph
    Graph {
        /// Protocol name or RFC number
        target: String,

        /// Output format: json, dot
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Show cached RFC info
    Show {
        /// RFC number
        rfc: u32,
    },

    /// Clear stored data
    Clear {
        /// What to clear: all, rfcs, graphs, analysis
        #[arg(default_value = "all")]
        scope: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}
