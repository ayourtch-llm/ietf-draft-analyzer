# Phase 1: Foundation — Implementation Spec

This document is self-contained. Implement exactly what is specified here.
Do not read other spec files unless explicitly referenced for context.

## Overview

Phase 1 creates the foundational layers: error types, configuration loading
with validation, core data model types, database schema with migrations,
and CRUD operations for RFC storage. At the end of Phase 1, the project
compiles, has a working database layer, and can store/retrieve RFC data.

## Files to Create

```
src/
  main.rs          -- async entry point (minimal, just config + DB init)
  lib.rs           -- module declarations
  error.rs         -- RfcAnalyzerError enum
  config.rs        -- Config struct, TOML loading, validation
  rfc/
    mod.rs         -- module re-exports
    model.rs       -- Rfc, Section, CrossRef, Reference, enums
  db/
    mod.rs         -- Database connection setup, re-exports
    schema.rs      -- CREATE TABLE SQL, migration runner
    rfc_store.rs   -- CRUD for rfcs, sections, cross_refs tables
```

Also update: `Cargo.toml` (dependencies)

## 1. Cargo.toml

Replace the existing `Cargo.toml` with:

```toml
[package]
name = "rfc-analyzer"
version = "0.1.0"
edition = "2024"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", features = ["json", "gzip"] }
tokio = { version = "1", features = ["full"] }
quick-xml = { version = "0.37", features = ["serialize"] }
rusqlite = { version = "0.32", features = ["bundled"] }
petgraph = "0.7"
regex = "1"
thiserror = "2"
anyhow = "1"
sha2 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
toml = "0.8"
governor = "0.8"
zstd = "0.13"
uuid = { version = "1", features = ["v4"] }
tokio-rusqlite = "0.6"

[dev-dependencies]
tempfile = "3"
wiremock = "0.6"
assert_json_diff = "2"
insta = "1"
```

## 2. src/error.rs

Define a unified error type using `thiserror`. Only include variants needed
for Phase 1-3 now (fetch, parse, DB, config, IO). LLM variants will be
added in Phase 4.

```rust
#[derive(Debug, thiserror::Error)]
pub enum RfcAnalyzerError {
    #[error("Failed to fetch RFC {rfc}: {source}")]
    Fetch {
        rfc: u32,
        source: reqwest::Error,
    },

    #[error("RFC {0} not found (HTTP 404)")]
    RfcNotFound(u32),

    #[error("Failed to parse RFC {rfc} ({format}): {detail}")]
    Parse {
        rfc: u32,
        format: String,
        detail: String,
    },

    #[error("XML parse error in RFC {rfc}: {source}")]
    Xml {
        rfc: u32,
        source: quick_xml::Error,
    },

    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("Database error: {0}")]
    DbAsync(#[from] tokio_rusqlite::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("No RFCs mapped for protocol '{0}'. Run 'map --protocol {0}' first.")]
    NoMappedRfcs(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, RfcAnalyzerError>;
```

## 3. src/rfc/model.rs

All types derive `Debug, Clone, Serialize, Deserialize`. Types that are used
as hash keys also derive `PartialEq, Eq, Hash`. Types that are stored in DB
or displayed also implement `Display` where noted.

```rust
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for an RFC document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RfcNumber(pub u32);

impl fmt::Display for RfcNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RFC {}", self.0)
    }
}

impl From<u32> for RfcNumber {
    fn from(n: u32) -> Self {
        RfcNumber(n)
    }
}

/// The format the RFC was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcFormat {
    Xml,
    PlainText,
}

impl fmt::Display for RfcFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RfcFormat::Xml => write!(f, "xml"),
            RfcFormat::PlainText => write!(f, "text"),
        }
    }
}

impl RfcFormat {
    /// Parse from the string stored in the database.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "xml" => Some(RfcFormat::Xml),
            "text" => Some(RfcFormat::PlainText),
            _ => None,
        }
    }
}

/// RFC publication status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcStatus {
    Standard,
    ProposedStandard,
    BestCurrentPractice,
    Informational,
    Experimental,
    Historic,
    Unknown,
}

impl fmt::Display for RfcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RfcStatus::Standard => "standard",
            RfcStatus::ProposedStandard => "proposed_standard",
            RfcStatus::BestCurrentPractice => "best_current_practice",
            RfcStatus::Informational => "informational",
            RfcStatus::Experimental => "experimental",
            RfcStatus::Historic => "historic",
            RfcStatus::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

impl RfcStatus {
    /// Parse from the string stored in the database or RFC metadata.
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "standard" | "internet standard" | "std" => RfcStatus::Standard,
            "proposed standard" | "proposed_standard" => RfcStatus::ProposedStandard,
            "best current practice" | "best_current_practice" | "bcp" => {
                RfcStatus::BestCurrentPractice
            }
            "informational" => RfcStatus::Informational,
            "experimental" => RfcStatus::Experimental,
            "historic" | "historical" => RfcStatus::Historic,
            _ => RfcStatus::Unknown,
        }
    }
}

/// A fully parsed RFC document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc {
    pub number: RfcNumber,
    pub title: String,
    pub format: RfcFormat,
    pub status: RfcStatus,
    pub date: NaiveDate,
    pub obsoletes: Vec<RfcNumber>,
    pub updates: Vec<RfcNumber>,
    pub obsoleted_by: Vec<RfcNumber>,
    pub updated_by: Vec<RfcNumber>,
    pub sections: Vec<Section>,
    pub references: Vec<Reference>,
    pub raw_text: String,
    pub content_hash: String,
}

/// A section within an RFC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub number: String,
    pub title: String,
    pub anchor: Option<String>,
    pub depth: u8,
    pub text: String,
    pub cross_refs: Vec<CrossRef>,
    pub pn: Option<String>,
}

/// A cross-reference found inline in section text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRef {
    pub target_rfc: Option<RfcNumber>,
    pub target_section: Option<String>,
    pub context: String,
}

/// An entry from the References section of the RFC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub label: String,
    pub target_rfc: Option<RfcNumber>,
    pub title: String,
    pub is_normative: bool,
}
```

### src/rfc/mod.rs

```rust
pub mod model;
```

## 4. src/config.rs

The config struct maps to `rfc-analyzer.toml`. Phase 1 only uses the
`[fetcher]` section and database path. LLM and analysis sections are parsed
but only validated when used (Phases 4+).

```rust
use crate::error::{RfcAnalyzerError, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub fetcher: FetcherConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_request: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_context_window")]
    pub model_context_window: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FetcherConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_prefer_xml")]
    pub prefer_xml: bool,
    #[serde(default = "default_request_delay")]
    pub request_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisConfig {
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default)]
    pub normative_only: bool,
}

// Default value functions
fn default_api_base() -> String { "https://api.openai.com/v1".to_string() }
fn default_api_key_env() -> String { "OPENAI_API_KEY".to_string() }
fn default_model() -> String { "gpt-4o".to_string() }
fn default_max_tokens() -> u32 { 4096 }
fn default_max_concurrent() -> u32 { 3 }
fn default_temperature() -> f32 { 0.2 }
fn default_context_window() -> u64 { 128_000 }
fn default_base_url() -> String { "https://www.rfc-editor.org".to_string() }
fn default_prefer_xml() -> bool { true }
fn default_request_delay() -> u64 { 500 }
fn default_max_depth() -> u32 { 2 }

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            api_base: default_api_base(),
            api_key_env: default_api_key_env(),
            model: default_model(),
            max_tokens_per_request: default_max_tokens(),
            max_concurrent_requests: default_max_concurrent(),
            temperature: default_temperature(),
            model_context_window: default_context_window(),
        }
    }
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            prefer_xml: default_prefer_xml(),
            request_delay_ms: default_request_delay(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
            normative_only: false,
        }
    }
}

impl Config {
    /// Load config from a TOML file. If the file does not exist, return
    /// defaults (all sections have defaults, so an empty/missing file is OK).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::info!("Config file not found at {}, using defaults", path.display());
            return Ok(Config::default());
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|e| RfcAnalyzerError::Config(
                format!("Failed to read config file {}: {}", path.display(), e)
            ))?;
        let config: Config = toml::from_str(&contents)
            .map_err(|e| RfcAnalyzerError::Config(
                format!("Failed to parse config file {}: {}", path.display(), e)
            ))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values. Called after loading.
    /// Fails fast with clear messages for out-of-range values.
    /// Note: LLM api_key_env is validated (non-empty, env var set) only
    /// when the LLM client is actually constructed (Phase 4+), not here.
    pub fn validate(&self) -> Result<()> {
        // LLM structural validation (format checks, not runtime availability)
        if self.llm.api_base.ends_with('/') {
            return Err(RfcAnalyzerError::Config(
                "llm.api_base must not end with '/'".to_string()
            ));
        }
        if self.llm.api_key_env.is_empty() {
            return Err(RfcAnalyzerError::Config(
                "llm.api_key_env must not be empty".to_string()
            ));
        }
        if !(1..=20).contains(&self.llm.max_concurrent_requests) {
            return Err(RfcAnalyzerError::Config(
                format!("llm.max_concurrent_requests must be 1..=20, got {}",
                    self.llm.max_concurrent_requests)
            ));
        }
        if !(0.0..=2.0).contains(&self.llm.temperature) {
            return Err(RfcAnalyzerError::Config(
                format!("llm.temperature must be 0.0..=2.0, got {}",
                    self.llm.temperature)
            ));
        }
        if !(1..=65536).contains(&self.llm.max_tokens_per_request) {
            return Err(RfcAnalyzerError::Config(
                format!("llm.max_tokens_per_request must be 1..=65536, got {}",
                    self.llm.max_tokens_per_request)
            ));
        }
        if !(4096..=2_097_152).contains(&self.llm.model_context_window) {
            return Err(RfcAnalyzerError::Config(
                format!("llm.model_context_window must be 4096..=2097152, got {}",
                    self.llm.model_context_window)
            ));
        }

        // Fetcher validation
        if !(50..=60_000).contains(&self.fetcher.request_delay_ms) {
            return Err(RfcAnalyzerError::Config(
                format!("fetcher.request_delay_ms must be 50..=60000, got {}",
                    self.fetcher.request_delay_ms)
            ));
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            llm: LlmConfig::default(),
            fetcher: FetcherConfig::default(),
            analysis: AnalysisConfig::default(),
        }
    }
}
```

## 5. src/db/schema.rs

The migration framework. Each migration is a `(version, sql)` pair.
On startup, the runner creates `schema_version` if it doesn't exist,
checks `MAX(version)`, and applies any migrations with higher version numbers.

```rust
use rusqlite::Connection;

/// Each migration: (version_number, sql_to_execute)
/// Migrations are applied in order. Never remove or reorder entries.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, r#"
        CREATE TABLE rfcs (
            number        INTEGER PRIMARY KEY,
            title         TEXT NOT NULL,
            format        TEXT NOT NULL CHECK (format IN ('xml', 'text')),
            status        TEXT NOT NULL,
            date          TEXT NOT NULL,
            raw_content   BLOB NOT NULL,
            content_hash  TEXT NOT NULL,
            fetched_at    TEXT NOT NULL DEFAULT (datetime('now')),
            obsoletes     TEXT,
            updates       TEXT,
            obsoleted_by  TEXT,
            updated_by    TEXT,
            references_json TEXT             -- JSON array of Reference objects
        );

        CREATE TABLE sections (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
            section_num   TEXT NOT NULL,
            title         TEXT NOT NULL,
            depth         INTEGER NOT NULL,
            anchor        TEXT,
            text          TEXT NOT NULL,
            pn            TEXT,
            UNIQUE(rfc_number, section_num)
        );
        CREATE INDEX idx_sections_rfc ON sections(rfc_number);

        CREATE TABLE cross_refs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            source_section  TEXT NOT NULL,
            target_rfc      INTEGER,
            target_section  TEXT,
            context         TEXT NOT NULL
        );
        CREATE INDEX idx_xrefs_source ON cross_refs(source_rfc);
        CREATE INDEX idx_xrefs_target ON cross_refs(target_rfc);
        CREATE INDEX idx_xrefs_pair ON cross_refs(source_rfc, target_rfc);

        CREATE TABLE dep_edges (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            target_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            kind            TEXT NOT NULL,
            source_section  TEXT,
            target_section  TEXT,
            UNIQUE(source_rfc, target_rfc, kind, source_section, target_section)
        );
        CREATE INDEX idx_edges_source ON dep_edges(source_rfc);
        CREATE INDEX idx_edges_target ON dep_edges(target_rfc);

        CREATE TABLE protocol_rfcs (
            protocol      TEXT NOT NULL,
            rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
            PRIMARY KEY (protocol, rfc_number)
        );
        CREATE INDEX idx_protocol_rfcs_rfc ON protocol_rfcs(rfc_number);

        CREATE TABLE state_machines (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol      TEXT NOT NULL,
            name          TEXT NOT NULL,
            mechanism     TEXT NOT NULL,
            data          TEXT NOT NULL,
            content_hash  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(protocol, name)
        );
        CREATE INDEX idx_state_machines_protocol ON state_machines(protocol);

        CREATE TABLE security_leads (
            id                  TEXT PRIMARY KEY,
            protocol            TEXT NOT NULL,
            technique_name      TEXT NOT NULL,
            category            TEXT NOT NULL,
            severity            TEXT NOT NULL,
            confidence          REAL NOT NULL,
            description         TEXT NOT NULL,
            rfc_references      TEXT NOT NULL,
            prerequisites       TEXT NOT NULL,
            entities_involved   TEXT NOT NULL,
            state_machine_name  TEXT,
            mitigation          TEXT,
            input_hash          TEXT NOT NULL,
            created_at          TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX idx_leads_protocol ON security_leads(protocol);
        CREATE INDEX idx_leads_category ON security_leads(category);
        CREATE INDEX idx_leads_severity ON security_leads(severity);

        CREATE TABLE analysis_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol        TEXT NOT NULL,
            stage           TEXT NOT NULL,
            started_at      TEXT NOT NULL,
            completed_at    TEXT,
            model_used      TEXT,
            tokens_used     INTEGER DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'running',
            error           TEXT,
            seed_rfcs       TEXT,
            depth           INTEGER,
            normative_only  INTEGER,
            mechanism_filter TEXT,
            category_filter  TEXT,
            prompt_version  TEXT,
            input_hash      TEXT,
            effective_rfcs  TEXT
        );
        CREATE INDEX idx_runs_protocol ON analysis_runs(protocol, stage);
    "#),
];

/// Initialize SQLite pragmas on a raw connection.
/// Called once when the connection is first opened.
pub fn init_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;"
    )
}

/// Run pending migrations. Creates the schema_version table if needed.
/// Returns the final schema version.
pub fn run_migrations(conn: &Connection) -> rusqlite::Result<i64> {
    // Create schema_version if it doesn't exist
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER NOT NULL UNIQUE,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );"
    )?;

    // Get current version
    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;

    // Apply pending migrations
    for &(version, sql) in MIGRATIONS {
        if version > current_version {
            tracing::info!("Applying migration v{}", version);
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )?;
        }
    }

    let final_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;

    tracing::info!("Database at schema version {}", final_version);
    Ok(final_version)
}
```

## 6. src/db/mod.rs

Sets up the `tokio-rusqlite` connection and runs initialization.

```rust
pub mod schema;
pub mod rfc_store;

use crate::error::Result;
use std::path::Path;
use tokio_rusqlite::Connection;

/// Open (or create) the database, initialize pragmas, and run migrations.
/// Returns a tokio-rusqlite Connection (async wrapper around rusqlite).
pub async fn open_database(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).await?;

    conn.call(|conn| {
        schema::init_pragmas(conn)?;
        schema::run_migrations(conn)?;
        Ok(())
    })
    .await?;

    Ok(conn)
}

/// Open an in-memory database for testing.
#[cfg(test)]
pub async fn open_memory_database() -> Result<Connection> {
    let conn = Connection::open_in_memory().await?;

    conn.call(|conn| {
        schema::init_pragmas(conn)?;
        schema::run_migrations(conn)?;
        Ok(())
    })
    .await?;

    Ok(conn)
}
```

## 7. src/db/rfc_store.rs

CRUD operations for the `rfcs`, `sections`, and `cross_refs` tables.
All functions take a `&tokio_rusqlite::Connection` and use `.call()` to
run synchronous rusqlite code on the background thread.

The `Rfc` struct's `raw_text` is compressed with zstd before storing
in `raw_content`, and decompressed on read.

```rust
use crate::error::Result;
use crate::rfc::model::*;
use chrono::NaiveDate;
use tokio_rusqlite::Connection;

/// Insert a fully parsed RFC into the database.
/// Inserts into rfcs, sections, cross_refs tables in a transaction.
/// If the RFC already exists with the same content_hash, returns early
/// (no-op). If the RFC exists with a different content_hash, it is updated.
pub async fn upsert_rfc(conn: &Connection, rfc: &Rfc) -> Result<()> {
    let rfc = rfc.clone();
    conn.call(move |conn| {
        // Check if we already have this exact version
        let existing_hash: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM rfcs WHERE number = ?1",
                [rfc.number.0],
                |row| row.get(0),
            )
            .optional()?;
        if existing_hash.as_deref() == Some(&rfc.content_hash) {
            return Ok(());
        }

        let tx = conn.transaction()?;

        // Compress raw_text with zstd
        let compressed = zstd::encode_all(rfc.raw_text.as_bytes(), 3)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        // Serialize Vec<RfcNumber> fields as JSON arrays of integers
        let obsoletes_json = serde_json::to_string(
            &rfc.obsoletes.iter().map(|r| r.0).collect::<Vec<_>>()
        ).unwrap();
        let updates_json = serde_json::to_string(
            &rfc.updates.iter().map(|r| r.0).collect::<Vec<_>>()
        ).unwrap();
        let obsoleted_by_json = serde_json::to_string(
            &rfc.obsoleted_by.iter().map(|r| r.0).collect::<Vec<_>>()
        ).unwrap();
        let updated_by_json = serde_json::to_string(
            &rfc.updated_by.iter().map(|r| r.0).collect::<Vec<_>>()
        ).unwrap();

        // Serialize references as JSON
        let references_json = serde_json::to_string(&rfc.references)
            .unwrap_or_else(|_| "[]".to_string());

        // Upsert the RFC row
        tx.execute(
            "INSERT INTO rfcs (number, title, format, status, date,
                raw_content, content_hash, obsoletes, updates,
                obsoleted_by, updated_by, references_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(number) DO UPDATE SET
                title = excluded.title,
                format = excluded.format,
                status = excluded.status,
                date = excluded.date,
                raw_content = excluded.raw_content,
                content_hash = excluded.content_hash,
                fetched_at = datetime('now'),
                obsoletes = excluded.obsoletes,
                updates = excluded.updates,
                obsoleted_by = excluded.obsoleted_by,
                updated_by = excluded.updated_by,
                references_json = excluded.references_json",
            rusqlite::params![
                rfc.number.0,
                rfc.title,
                rfc.format.to_string(),
                rfc.status.to_string(),
                rfc.date.to_string(),
                compressed,
                rfc.content_hash,
                obsoletes_json,
                updates_json,
                obsoleted_by_json,
                updated_by_json,
                references_json,
            ],
        )?;

        // Delete old sections and cross_refs for this RFC, then re-insert
        tx.execute("DELETE FROM cross_refs WHERE source_rfc = ?1", [rfc.number.0])?;
        tx.execute("DELETE FROM sections WHERE rfc_number = ?1", [rfc.number.0])?;

        // Insert sections
        for section in &rfc.sections {
            tx.execute(
                "INSERT INTO sections (rfc_number, section_num, title, depth,
                    anchor, text, pn)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    rfc.number.0,
                    section.number,
                    section.title,
                    i64::from(section.depth),
                    section.anchor,
                    section.text,
                    section.pn,
                ],
            )?;

            // Insert cross-refs for this section
            for xref in &section.cross_refs {
                tx.execute(
                    "INSERT INTO cross_refs (source_rfc, source_section,
                        target_rfc, target_section, context)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        rfc.number.0,
                        section.number,
                        xref.target_rfc.map(|r| r.0),
                        xref.target_section,
                        xref.context,
                    ],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Check if an RFC exists in the database and return its content_hash if so.
pub async fn get_content_hash(conn: &Connection, rfc_number: u32) -> Result<Option<String>> {
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT content_hash FROM rfcs WHERE number = ?1"
            )?;
            let hash = stmt
                .query_row([rfc_number], |row| row.get::<_, String>(0))
                .optional()?;
            Ok(hash)
        })
        .await?;
    Ok(result)
}

/// Load a full Rfc struct from the database by number.
/// Returns None if not found.
pub async fn get_rfc(conn: &Connection, rfc_number: u32) -> Result<Option<Rfc>> {
    let result = conn
        .call(move |conn| {
            // Load the RFC row
            let mut stmt = conn.prepare(
                "SELECT number, title, format, status, date, raw_content,
                    content_hash, obsoletes, updates, obsoleted_by, updated_by,
                    references_json
                 FROM rfcs WHERE number = ?1"
            )?;

            let rfc_row = stmt.query_row([rfc_number], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                ))
            }).optional()?;

            let Some((number, title, format_str, status_str, date_str,
                       raw_content, content_hash, obsoletes_json,
                       updates_json, obsoleted_by_json, updated_by_json,
                       references_json_str)) = rfc_row
            else {
                return Ok(None);
            };

            // Decompress raw_content
            let raw_text = String::from_utf8(
                zstd::decode_all(raw_content.as_slice())
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?
            ).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            // Parse JSON arrays
            let parse_rfc_numbers = |json: Option<String>| -> Vec<RfcNumber> {
                json.and_then(|s| serde_json::from_str::<Vec<u32>>(&s).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .map(RfcNumber)
                    .collect()
            };

            // Load sections
            let mut sect_stmt = conn.prepare(
                "SELECT section_num, title, depth, anchor, text, pn
                 FROM sections WHERE rfc_number = ?1
                 ORDER BY id"
            )?;
            let sections: Vec<Section> = sect_stmt
                .query_map([rfc_number], |row| {
                    let depth_i64: i64 = row.get(2)?;
                    let depth = u8::try_from(depth_i64).map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(2, depth_i64)
                    })?;
                    Ok(Section {
                        number: row.get(0)?,
                        title: row.get(1)?,
                        depth,
                        anchor: row.get(3)?,
                        text: row.get(4)?,
                        cross_refs: Vec::new(), // filled below
                        pn: row.get(5)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            // Load cross-refs and attach to sections
            let mut xref_stmt = conn.prepare(
                "SELECT source_section, target_rfc, target_section, context
                 FROM cross_refs WHERE source_rfc = ?1
                 ORDER BY id"
            )?;
            let xrefs: Vec<(String, CrossRef)> = xref_stmt
                .query_map([rfc_number], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        CrossRef {
                            target_rfc: row.get::<_, Option<u32>>(1)?.map(RfcNumber),
                            target_section: row.get(2)?,
                            context: row.get(3)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            // Attach cross-refs to their sections
            let mut sections = sections;
            for (section_num, xref) in xrefs {
                if let Some(section) = sections.iter_mut().find(|s| s.number == section_num) {
                    section.cross_refs.push(xref);
                }
            }

            // Load references from JSON column
            let references: Vec<Reference> = references_json_str
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                .unwrap_or_else(|_| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap());

            Ok(Some(Rfc {
                number: RfcNumber(number),
                title,
                format: RfcFormat::from_db_str(&format_str).unwrap_or(RfcFormat::PlainText),
                status: RfcStatus::from_str_loose(&status_str),
                date,
                obsoletes: parse_rfc_numbers(obsoletes_json),
                updates: parse_rfc_numbers(updates_json),
                obsoleted_by: parse_rfc_numbers(obsoleted_by_json),
                updated_by: parse_rfc_numbers(updated_by_json),
                sections,
                references,
                raw_text,
                content_hash,
            }))
        })
        .await?;
    Ok(result)
}

/// List all stored RFC numbers.
pub async fn list_rfc_numbers(conn: &Connection) -> Result<Vec<RfcNumber>> {
    let result = conn
        .call(|conn| {
            let mut stmt = conn.prepare("SELECT number FROM rfcs ORDER BY number")?;
            let numbers: Vec<RfcNumber> = stmt
                .query_map([], |row| Ok(RfcNumber(row.get(0)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(numbers)
        })
        .await?;
    Ok(result)
}

/// Associate an RFC with a protocol name.
pub async fn assign_protocol(conn: &Connection, protocol: &str, rfc_number: u32) -> Result<()> {
    let protocol = protocol.to_string();
    conn.call(move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO protocol_rfcs (protocol, rfc_number) VALUES (?1, ?2)",
            rusqlite::params![protocol, rfc_number],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Get all RFC numbers associated with a protocol.
pub async fn get_protocol_rfcs(conn: &Connection, protocol: &str) -> Result<Vec<RfcNumber>> {
    let protocol = protocol.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1 ORDER BY rfc_number"
            )?;
            let numbers: Vec<RfcNumber> = stmt
                .query_map([&protocol], |row| Ok(RfcNumber(row.get(0)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(numbers)
        })
        .await?;
    Ok(result)
}

// Import the optional() extension for query_row
use rusqlite::OptionalExtension;
```

## 8. src/lib.rs

```rust
pub mod config;
pub mod db;
pub mod error;
pub mod rfc;
```

## 9. src/main.rs

Minimal async entry point. Phase 1 just initializes config and database.
The CLI commands (`map`, `show`, etc.) will be added in Phase 2.

```rust
use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    // Load config
    let config_path = PathBuf::from("rfc-analyzer.toml");
    let config = rfc_analyzer::config::Config::load(&config_path)?;
    tracing::debug!(?config, "Loaded configuration");

    // Open database
    let db_path = PathBuf::from("rfc-analyzer.db");
    let _conn = rfc_analyzer::db::open_database(&db_path).await?;
    tracing::info!("Database initialized at {}", db_path.display());

    println!("RFC Analyzer v{}", env!("CARGO_PKG_VERSION"));
    println!("Database: {}", db_path.display());

    Ok(())
}
```

## 10. Tests

### Unit tests in src/config.rs

Add these as a `#[cfg(test)] mod tests` block at the bottom of `config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.llm.max_concurrent_requests, 3);
        assert_eq!(config.fetcher.request_delay_ms, 500);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_missing_file_returns_defaults() {
        let config = Config::load(Path::new("nonexistent.toml")).unwrap();
        assert_eq!(config.llm.model, "gpt-4o");
    }

    #[test]
    fn test_load_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.fetcher.base_url, "https://www.rfc-editor.org");
    }

    #[test]
    fn test_load_partial_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.toml");
        std::fs::write(&path, r#"
            [fetcher]
            request_delay_ms = 1000
        "#).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.fetcher.request_delay_ms, 1000);
        // Other fields should be defaults
        assert_eq!(config.llm.model, "gpt-4o");
    }

    #[test]
    fn test_validate_bad_temperature() {
        let mut config = Config::default();
        config.llm.temperature = 3.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_concurrent_requests() {
        let mut config = Config::default();
        config.llm.max_concurrent_requests = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_api_base_trailing_slash() {
        let mut config = Config::default();
        config.llm.api_base = "https://api.openai.com/v1/".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_request_delay() {
        let mut config = Config::default();
        config.fetcher.request_delay_ms = 10; // below 50
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_max_tokens() {
        let mut config = Config::default();
        config.llm.max_tokens_per_request = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_context_window() {
        let mut config = Config::default();
        config.llm.model_context_window = 100; // below 4096
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_api_key_env() {
        let mut config = Config::default();
        config.llm.api_key_env = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_load_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not [valid toml").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
```

### Unit tests in src/db/schema.rs

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_pragmas() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn test_run_migrations_from_empty() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let version = run_migrations(&conn).unwrap();
        assert_eq!(version, 1);

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rfcs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_run_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let v1 = run_migrations(&conn).unwrap();
        let v2 = run_migrations(&conn).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_all_tables_created() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        run_migrations(&conn).unwrap();

        let expected_tables = [
            "rfcs", "sections", "cross_refs", "dep_edges",
            "protocol_rfcs", "state_machines", "security_leads",
            "analysis_runs", "schema_version",
        ];
        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table '{}' should exist", table);
        }
    }
}
```

### Async integration tests in src/db/rfc_store.rs

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;
    use crate::rfc::model::*;
    use chrono::NaiveDate;

    fn make_test_rfc() -> Rfc {
        Rfc {
            number: RfcNumber(9293),
            title: "Transmission Control Protocol (TCP)".to_string(),
            format: RfcFormat::Xml,
            status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(2022, 8, 1).unwrap(),
            obsoletes: vec![RfcNumber(793)],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![
                Section {
                    number: "1".to_string(),
                    title: "Introduction".to_string(),
                    anchor: Some("intro".to_string()),
                    depth: 1,
                    text: "This document specifies TCP.".to_string(),
                    cross_refs: vec![
                        CrossRef {
                            target_rfc: Some(RfcNumber(793)),
                            target_section: Some("3".to_string()),
                            context: "Originally defined in RFC 793, Section 3."
                                .to_string(),
                        },
                    ],
                    pn: None,
                },
                Section {
                    number: "2".to_string(),
                    title: "Key Words".to_string(),
                    anchor: None,
                    depth: 1,
                    text: "The key words MUST, SHOULD...".to_string(),
                    cross_refs: vec![],
                    pn: None,
                },
            ],
            references: vec![],
            raw_text: "Full text of RFC 9293 would go here...".to_string(),
            content_hash: "abc123def456".to_string(),
        }
    }

    #[tokio::test]
    async fn test_upsert_and_get_rfc() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();

        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.number, RfcNumber(9293));
        assert_eq!(loaded.title, "Transmission Control Protocol (TCP)");
        assert_eq!(loaded.sections.len(), 2);
        assert_eq!(loaded.sections[0].cross_refs.len(), 1);
        assert_eq!(loaded.obsoletes, vec![RfcNumber(793)]);
        assert_eq!(loaded.content_hash, "abc123def456");
        // raw_text should survive compression round-trip
        assert_eq!(loaded.raw_text, "Full text of RFC 9293 would go here...");
    }

    #[tokio::test]
    async fn test_get_nonexistent_rfc() {
        let conn = open_memory_database().await.unwrap();
        let result = get_rfc(&conn, 99999).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_content_hash() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let hash = get_content_hash(&conn, 9293).await.unwrap();
        assert_eq!(hash, Some("abc123def456".to_string()));

        let missing = get_content_hash(&conn, 99999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_upsert_updates_existing() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Update the RFC
        rfc.title = "Updated Title".to_string();
        rfc.content_hash = "newhash789".to_string();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.title, "Updated Title");
        assert_eq!(loaded.content_hash, "newhash789");
    }

    #[tokio::test]
    async fn test_list_rfc_numbers() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let numbers = list_rfc_numbers(&conn).await.unwrap();
        assert_eq!(numbers, vec![RfcNumber(9293)]);
    }

    #[tokio::test]
    async fn test_protocol_assignment() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        assign_protocol(&conn, "tcp", 9293).await.unwrap();
        // Assigning again should be a no-op (OR IGNORE)
        assign_protocol(&conn, "tcp", 9293).await.unwrap();

        let rfcs = get_protocol_rfcs(&conn, "tcp").await.unwrap();
        assert_eq!(rfcs, vec![RfcNumber(9293)]);

        let empty = get_protocol_rfcs(&conn, "dns").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn test_protocol_assignment_missing_rfc_fails() {
        // Foreign keys are ON, so assigning a non-existent RFC should fail
        let conn = open_memory_database().await.unwrap();
        let result = assign_protocol(&conn, "tcp", 99999).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_references_round_trip() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        rfc.references = vec![
            Reference {
                label: "[RFC793]".to_string(),
                target_rfc: Some(RfcNumber(793)),
                title: "Transmission Control Protocol".to_string(),
                is_normative: true,
            },
            Reference {
                label: "[RFC1122]".to_string(),
                target_rfc: Some(RfcNumber(1122)),
                title: "Requirements for Internet Hosts".to_string(),
                is_normative: false,
            },
        ];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.references.len(), 2);
        assert_eq!(loaded.references[0].label, "[RFC793]");
        assert!(loaded.references[0].is_normative);
        assert_eq!(loaded.references[1].target_rfc, Some(RfcNumber(1122)));
    }

    #[tokio::test]
    async fn test_upsert_removes_old_sections() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        assert_eq!(rfc.sections.len(), 2);
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Update RFC with only 1 section (simulating re-parse)
        rfc.content_hash = "changed_hash".to_string();
        rfc.sections = vec![rfc.sections[0].clone()];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.sections.len(), 1);
        assert_eq!(loaded.sections[0].number, "1");
    }

    #[tokio::test]
    async fn test_same_content_hash_is_noop() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Upsert again with same content_hash — should be a no-op
        let mut rfc2 = rfc.clone();
        rfc2.title = "This should NOT be saved".to_string();
        upsert_rfc(&conn, &rfc2).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        // Title should be the original, not the modified one
        assert_eq!(loaded.title, "Transmission Control Protocol (TCP)");
    }

    #[tokio::test]
    async fn test_duplicate_cross_refs_different_context() {
        // Verify that multiple cross-refs from the same source to the same
        // target but with different context are all preserved
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        rfc.sections[0].cross_refs = vec![
            CrossRef {
                target_rfc: Some(RfcNumber(793)),
                target_section: Some("3".to_string()),
                context: "First reference to RFC 793 Section 3.".to_string(),
            },
            CrossRef {
                target_rfc: Some(RfcNumber(793)),
                target_section: Some("3".to_string()),
                context: "Second reference to RFC 793 Section 3.".to_string(),
            },
        ];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.sections[0].cross_refs.len(), 2);
        assert_ne!(
            loaded.sections[0].cross_refs[0].context,
            loaded.sections[0].cross_refs[1].context
        );
    }
}
```

## 11. Verification

After implementation, verify:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all tests (config, schema, rfc_store)
3. `cargo run` prints version and initializes database
4. `rfc-analyzer.db` is created with correct tables
5. Run `sqlite3 rfc-analyzer.db ".tables"` to verify all tables exist

## 12. What This Phase Does NOT Include

- CLI argument parsing (Phase 2)
- RFC fetching or parsing (Phase 2)
- Graph types and operations (Phase 3)
- LLM client (Phase 4)
- Pipeline stages (Phase 5-6)

These modules are declared in `lib.rs` only when their code is added in
subsequent phases.
