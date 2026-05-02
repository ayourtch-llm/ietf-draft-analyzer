use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ietf-draft-analyzer",
    version,
    about = "RFC specification security analyzer"
)]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "ietf-draft-analyzer.toml")]
    pub config: PathBuf,

    /// SQLite database path
    #[arg(long, default_value = "ietf-draft-analyzer.db")]
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

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format (json only for v1)
        #[arg(long, default_value = "json")]
        format: String,
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

        /// Output format (json only for v1)
        #[arg(long, default_value = "json")]
        format: String,
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

    /// Import a local RFC or Internet-Draft file (XML or text)
    Import {
        /// Path to local XML or text file
        file: PathBuf,

        /// Document number (used as RFC number internally)
        #[arg(long, short = 'n')]
        number: u32,

        /// Associate with a protocol name
        #[arg(long)]
        protocol: Option<String>,
    },

    /// Generate proof-of-concept reproduction scripts for security leads
    Reproduce {
        /// Protocol name (must have completed analysis)
        protocol: String,

        /// Output directory for PoC scripts
        #[arg(short, long, default_value = "pocs")]
        output_dir: PathBuf,

        /// Only generate PoCs for leads at or above this severity
        #[arg(long, default_value = "medium")]
        min_severity: String,

        /// Only generate PoC for a specific lead by fingerprint
        #[arg(long)]
        fingerprint: Option<String>,

        /// Language for generated scripts
        #[arg(long, default_value = "python")]
        language: String,
    },
}
