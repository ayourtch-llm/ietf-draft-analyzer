# Architecture Overview

## Purpose

The RFC Analyzer treats protocol specifications (RFCs) as a first-class attack
surface. It builds dependency graphs across RFCs, extracts protocol state
machines, and runs LLM-powered security analysis to produce ranked vulnerability
leads.

## v1 Scope

v1 is **RFC-only**. BCP/STD aliases, Internet-Drafts, errata ingestion,
and non-RFC protocol specifications are explicitly out of scope. The document
identity model (`RfcNumber(u32)`) reflects this constraint. Expanding to
other document types is a future version concern.

## High-Level Pipeline

```
                ┌──────────────┐
  Seed RFCs ──> │  Stage 1:    │──> Dependency Graph (petgraph + SQLite)
                │  Map         │
                └──────┬───────┘
                       │
                       v
                ┌──────────────┐
                │  Stage 2:    │──> Protocol State Machines (SQLite)
                │  Model       │
                └──────┬───────┘
                       │
                       v
                ┌──────────────┐
                │  Stage 3:    │──> Security Leads (JSON report)
                │  Analyze     │
                └──────────────┘
```

Each stage reads from and writes to the SQLite database, enabling incremental
re-runs and preserving expensive analysis results across sessions.

## Module Structure

```
src/
  main.rs              -- CLI entry point (clap), orchestrates commands
  lib.rs               -- Re-exports all modules for testability

  cli.rs               -- Clap command/arg definitions
  config.rs            -- Configuration (API keys, base URLs, model params)
  error.rs             -- Unified error type (thiserror)

  rfc/
    mod.rs             -- Re-exports
    fetcher.rs         -- Downloads RFC XML/text from rfc-editor.org
    parser_xml.rs      -- Parses RFC 7991+ XML format (quick-xml)
    parser_text.rs     -- Parses plain-text RFC format (regex-based)
    model.rs           -- Core data structures: Rfc, Section, Reference, etc.
    index.rs           -- Fetches/parses the RFC index for metadata lookup

  db/
    mod.rs             -- Re-exports, connection setup
    schema.rs          -- Table creation SQL, migrations
    rfc_store.rs       -- CRUD for cached RFCs and parsed sections
    graph_store.rs     -- Persist/load dependency edges
    analysis_store.rs  -- Persist/load security leads and state machines

  graph/
    mod.rs             -- Re-exports
    builder.rs         -- Constructs the petgraph from parsed references
    model.rs           -- Node/Edge types for the dependency graph
    query.rs           -- Graph traversal helpers (transitive deps, etc.)

  pipeline/
    mod.rs             -- Re-exports, Pipeline struct that chains stages
    dependency.rs      -- Stage 1: dependency mapping
    modeling.rs        -- Stage 2: protocol/state machine modeling
    analysis.rs        -- Stage 3: security analysis

  llm/
    mod.rs             -- Re-exports
    client.rs          -- OpenAI-compatible HTTP client (reqwest)
    prompts.rs         -- Prompt templates for each analysis task
    response.rs        -- Structured parsing of LLM JSON responses

  output/
    mod.rs             -- JSON report generation
    report.rs          -- Final report structure and serialization
```

## Concurrency Model

- Async runtime: `tokio` (multi-threaded)
- RFC fetching: concurrent with a semaphore (polite rate-limiting to rfc-editor.org)
- LLM calls: concurrent with a semaphore matching `max_concurrent_requests`
- Pipeline stages: sequential (map -> model -> analyze)
- Within each stage: independent work items (different RFCs, different mechanism
  clusters) run concurrently
- Graceful shutdown: `tokio::signal::ctrl_c()` handler sets a cancellation flag.
  The current LLM call is allowed to complete, partial results are persisted,
  and `analysis_runs.status` is set to `'interrupted'`.

## Database Access Strategy

`rusqlite` is synchronous but the pipeline is async. We bridge this using
`tokio-rusqlite`, which runs a dedicated SQLite thread with a channel-based
async API. This avoids `Mutex` contention and `spawn_blocking` boilerplate.

Connection initialization enables:
- `PRAGMA foreign_keys = ON`
- `PRAGMA journal_mode = WAL` (concurrent readers during writes)
- `PRAGMA busy_timeout = 5000` (5s retry on lock contention)

All parsed RFCs are accessed on demand from SQLite during Stages 2 and 3,
not held in memory. Only the `petgraph` graph (lightweight `RfcNode` structs)
and the current work item's section text are in memory at any given time.

## Configuration

All settings are in `rfc-analyzer.toml` with CLI overrides. See
`cli-interface.md` for details. The LLM endpoint, API key, and model are all
configurable -- see `llm-integration.md`.

## Progress Reporting

At `info` level (visible without `-v`), each stage logs progress:
- Stage 1: "Fetching RFC 5/47", "Parsing RFC 9293 (XML)"
- Stage 2: "Clustering mechanisms for tcp", "Extracting state machine 2/5"
- Stage 3: "Analyzing category 3/10: AuthBypass", "Found 12 leads so far"

Stage start/end is always logged. The `-v` flags control `tracing` verbosity
for debug-level detail (full prompt text, raw LLM responses, etc.).

## Database as Project Artifact

The SQLite database is a **project artifact**, not a disposable cache. It
stores fetched RFCs, parsed structures, dependency graphs, LLM-derived state
machines, and security analysis leads — all of which may represent significant
computation time and API cost. The `clear` command requires confirmation
before deleting data.

## Incrementality

Each stage computes a composite input hash covering all factors that affect
its output:

- **Stage 1 (Map)**: RFC `content_hash` (SHA-256 of raw content)
- **Stage 2 (Model)**: hash of input section texts + prompt version + model name
- **Stage 3 (Analyze)**: hash of state machines + input sections + prompt version
  + model name + category list

These composite hashes are stored in `analysis_runs` as the run manifest.
If a matching hash exists, the stage skips re-processing. This ensures that
changing a prompt template, switching models, or adding new RFCs correctly
triggers re-analysis.

## Schema Migrations

The database uses a `schema_version` table to track the current schema version.
On startup, the application checks the version and applies any pending
migrations sequentially. Migrations are defined as SQL in `db/schema.rs` and
are never destructive to user data without explicit confirmation.
