# Database Schema (SQLite)

All persistence goes through a single SQLite file (default: `rfc-analyzer.db`).
Uses `rusqlite` with the `bundled` feature (no system SQLite dependency).

The database is a **project artifact** that stores expensive LLM analysis
results. It should not be treated as a disposable cache.

## Connection Setup

Every connection must enable the following pragmas:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;       -- concurrent readers during writes
PRAGMA busy_timeout = 5000;      -- 5s retry on lock contention
```

Note: application code accesses SQLite through `tokio-rusqlite`, which runs
a dedicated background thread with a channel-based async API. See
`architecture.md` for the full database access strategy.

## Schema Versioning

```sql
CREATE TABLE schema_version (
    version       INTEGER NOT NULL UNIQUE,
    applied_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
```

One row per applied migration. The current schema version is `MAX(version)`.
The migration runner queries this to determine which migrations to apply.

On startup, the application checks the current version and applies pending
migrations sequentially. Migrations are defined as SQL in `db/schema.rs`.

## Tables

### `rfcs` — Cached raw RFC documents

```sql
CREATE TABLE rfcs (
    number        INTEGER PRIMARY KEY,
    title         TEXT NOT NULL,
    format        TEXT NOT NULL CHECK (format IN ('xml', 'text')),
    status        TEXT NOT NULL,
    date          TEXT NOT NULL,           -- ISO 8601
    raw_content   BLOB NOT NULL,          -- compressed with zstd
    content_hash  TEXT NOT NULL,          -- SHA-256 of raw content
    fetched_at    TEXT NOT NULL DEFAULT (datetime('now')),
    obsoletes     TEXT,                   -- JSON array of integers
    updates       TEXT,                   -- JSON array of integers
    obsoleted_by  TEXT,                   -- JSON array of integers
    updated_by    TEXT                    -- JSON array of integers
);
```

### `sections` — Parsed sections within RFCs

```sql
CREATE TABLE sections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
    section_num   TEXT NOT NULL,           -- "3.4.1"
    title         TEXT NOT NULL,
    depth         INTEGER NOT NULL,
    anchor        TEXT,
    text          TEXT NOT NULL,
    pn            TEXT,
    UNIQUE(rfc_number, section_num)
);

CREATE INDEX idx_sections_rfc ON sections(rfc_number);
```

### `cross_refs` — Cross-references found within sections

```sql
CREATE TABLE cross_refs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
    source_section  TEXT NOT NULL,
    target_rfc      INTEGER,              -- NULL for internal refs
    target_section  TEXT,
    context         TEXT NOT NULL,         -- surrounding sentence
);

CREATE INDEX idx_xrefs_source ON cross_refs(source_rfc);
CREATE INDEX idx_xrefs_target ON cross_refs(target_rfc);
CREATE INDEX idx_xrefs_pair ON cross_refs(source_rfc, target_rfc);
```

### `dep_edges` — Dependency graph edges

```sql
CREATE TABLE dep_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
    target_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
    kind            TEXT NOT NULL,         -- see EdgeKind enum
    source_section  TEXT,
    target_section  TEXT,
    UNIQUE(source_rfc, target_rfc, kind, source_section, target_section)
);

CREATE INDEX idx_edges_source ON dep_edges(source_rfc);
CREATE INDEX idx_edges_target ON dep_edges(target_rfc);
```

Valid `kind` values: `obsoletes`, `updates`, `normative_ref`, `informative_ref`,
`cross_ref`.

### `protocol_rfcs` — Protocol-to-RFC assignments

```sql
CREATE TABLE protocol_rfcs (
    protocol      TEXT NOT NULL,
    rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
    PRIMARY KEY (protocol, rfc_number)
);
```

### `state_machines` — Protocol state machines (Stage 2 output)

```sql
CREATE TABLE state_machines (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol      TEXT NOT NULL,
    name          TEXT NOT NULL,
    mechanism     TEXT NOT NULL,
    data          TEXT NOT NULL,           -- full JSON serialization
    content_hash  TEXT NOT NULL,           -- hash of input sections used
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(protocol, name)
);
```

### `security_leads` — Security analysis results (Stage 3 output)

```sql
CREATE TABLE security_leads (
    id                  TEXT PRIMARY KEY,  -- UUID v4
    protocol            TEXT NOT NULL,
    technique_name      TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    confidence          REAL NOT NULL,
    description         TEXT NOT NULL,
    rfc_references      TEXT NOT NULL,     -- JSON
    prerequisites       TEXT NOT NULL,     -- JSON
    entities_involved   TEXT NOT NULL,     -- JSON
    state_machine_name  TEXT,
    mitigation          TEXT,
    input_hash          TEXT NOT NULL,     -- hash of input context
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_leads_protocol ON security_leads(protocol);
CREATE INDEX idx_leads_category ON security_leads(category);
CREATE INDEX idx_leads_severity ON security_leads(severity);
```

### `analysis_runs` — Analysis run tracking (run manifest)

```sql
CREATE TABLE analysis_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol        TEXT NOT NULL,
    stage           TEXT NOT NULL,        -- 'map', 'model', 'analyze'
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    model_used      TEXT,                -- NULL for non-LLM stages (e.g. map)
    tokens_used     INTEGER DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running',
    error           TEXT,
    -- Run manifest: INPUT fields (participate in input_hash computation)
    seed_rfcs       TEXT,                -- JSON array of seed RFC numbers (sorted)
    depth           INTEGER,
    normative_only  INTEGER,             -- 0 or 1
    mechanism_filter TEXT,               -- JSON array, sorted, or NULL for all
    category_filter  TEXT,               -- JSON array, sorted, or NULL for all
    prompt_version  TEXT,                -- version tag for prompt templates used
    input_hash      TEXT,                -- composite hash of input fields above
    -- Run manifest: OUTPUT fields (stored for provenance, not in hash)
    effective_rfcs  TEXT                 -- JSON array of all RFCs discovered
);

CREATE INDEX idx_runs_protocol ON analysis_runs(protocol, stage);
```

Valid `status` values: `running`, `completed`, `failed`, `interrupted`.

The `interrupted` status is set when the user cancels a run (Ctrl+C) or
the process is otherwise interrupted. Partially completed work items
within the run are preserved in their respective tables.

The `input_hash` is a composite SHA-256 covering all factors that affect the
stage's output (see architecture.md Incrementality section). Before running
a stage, the tool checks for a completed run with a matching `input_hash`
and skips re-processing if found.

### Additional Indexes

```sql
CREATE INDEX idx_state_machines_protocol ON state_machines(protocol);
CREATE INDEX idx_protocol_rfcs_rfc ON protocol_rfcs(rfc_number);
```

## Incrementality

Before processing, each stage computes a composite `input_hash` (SHA-256)
covering all factors that affect its output:

- **Stage 1**: RFC content hashes of seed RFCs + depth + normative_only flag
- **Stage 2**: hash of input section texts + prompt version + model name +
  mechanism filter
- **Stage 3**: hash of state machines + input sections + prompt version +
  model name + category filter

If a completed `analysis_runs` entry with a matching `input_hash` exists,
the stage skips re-processing. This ensures that changing prompts, switching
models, or adding RFCs correctly triggers re-analysis.

## Compression

The `raw_content` column in `rfcs` stores zstd-compressed content to reduce
database size. Full RFC text can be large; compression typically achieves 3-4x
reduction.
