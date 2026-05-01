# Phase 5-6 Spec Additions

These additions address the gaps identified in design reviews 1-3 through
1-5 and are grounded in the actual Phase 1-3 implementation. They must be
incorporated before Phase 5-6 implementation specs are written.

## 1. Schema Migration v2

Add to `src/db/schema.rs` as migration version 2. The existing migration
framework handles this cleanly.

```sql
-- Link artifacts to the run that produced them
ALTER TABLE state_machines ADD COLUMN run_id INTEGER REFERENCES analysis_runs(id);
ALTER TABLE security_leads ADD COLUMN run_id INTEGER REFERENCES analysis_runs(id);

-- Relax state_machines uniqueness: allow multiple runs to produce
-- different state machines with the same name for the same protocol.
-- Drop the old UNIQUE(protocol, name) and replace with a run-aware key.
-- SQLite cannot DROP constraints, so we recreate the table:
CREATE TABLE state_machines_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol      TEXT NOT NULL,
    name          TEXT NOT NULL,
    mechanism     TEXT NOT NULL,
    data          TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    run_id        INTEGER REFERENCES analysis_runs(id),
    UNIQUE(protocol, name, run_id)
);
INSERT INTO state_machines_new (id, protocol, name, mechanism, data, content_hash, created_at)
    SELECT id, protocol, name, mechanism, data, content_hash, created_at FROM state_machines;
DROP TABLE state_machines;
ALTER TABLE state_machines_new RENAME TO state_machines;
CREATE INDEX idx_state_machines_protocol ON state_machines(protocol);
CREATE INDEX idx_state_machines_run ON state_machines(run_id);

-- Per-work-item tracking for resumability
CREATE TABLE run_work_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES analysis_runs(id),
    work_item_kind  TEXT NOT NULL,      -- 'mechanism' or 'category'
    work_item_key   TEXT NOT NULL,      -- mechanism name or category name
    status          TEXT NOT NULL DEFAULT 'pending',
    started_at      TEXT,
    completed_at    TEXT,
    tokens_used     INTEGER DEFAULT 0,
    error           TEXT,
    UNIQUE(run_id, work_item_kind, work_item_key)
);
CREATE INDEX idx_work_items_run ON run_work_items(run_id);

-- Add deterministic fingerprint to security_leads for cross-run comparison
ALTER TABLE security_leads ADD COLUMN fingerprint TEXT;
CREATE INDEX idx_leads_fingerprint ON security_leads(fingerprint);
```

Valid `run_work_items.status` values: `pending`, `running`, `completed`, `failed`.

### Fingerprint Computation

A deterministic fingerprint for each security lead, computed as:

```
SHA-256(protocol + "|" + category + "|" + normalized_technique_name + "|" +
        sorted_rfc_section_refs)
```

Where:
- `normalized_technique_name` = lowercase, whitespace-collapsed
- `sorted_rfc_section_refs` = e.g., `"4120:1.3,4120:7.2.3.2"`

This enables finding the "same" lead across runs with different models or
prompt versions.

## 2. Error Variants for LLM Integration

Add to `src/error.rs` (the existing `RfcAnalyzerError` enum):

```rust
    #[error("LLM API error (HTTP {status}): {body}")]
    LlmApi { status: u16, body: String },

    #[error("LLM response did not contain valid JSON: {detail}")]
    LlmParse { detail: String },

    #[error("LLM rate limited, retry after {retry_after_secs}s")]
    LlmRateLimit { retry_after_secs: u64 },

    #[error("LLM request too large for model context window")]
    LlmContextOverflow,

    #[error("LLM content policy refusal: {detail}")]
    LlmContentRefusal { detail: String },
```

### Error Classification

| HTTP Status | Error Variant | Behavior |
|---|---|---|
| 200 | (success) | Parse response |
| 400 | `LlmContextOverflow` | Skip work item, warn |
| 401 | `LlmApi` | Fail immediately (bad API key) |
| 403 | `LlmApi` | Fail immediately (forbidden) |
| 404 | `LlmApi` | Fail immediately (model not found) |
| 429 | `LlmRateLimit` | Retry with backoff (up to 3 attempts) |
| 5xx | `LlmApi` | Retry with backoff (up to 3 attempts) |
| Content refusal | `LlmContentRefusal` | Skip work item, warn |

## 3. Prompt Version Constants

Define in `src/llm/prompts.rs`:

```rust
/// Global prompt version. Increment when any prompt template changes.
/// Stored in analysis_runs.prompt_version and used in composite input hashes.
pub const PROMPT_VERSION: &str = "1.0.0";
```

Each prompt template also has a per-task version comment for traceability,
but `PROMPT_VERSION` is the single value stored in the database and used
for cache invalidation.

## 4. Summarize-to-Fit Strategy

When a mechanism cluster's combined section text exceeds the context budget:

**Strategy: extractive summarization (no LLM dependency)**

1. Sort sections by relevance score (descending):
   - Sections referenced by the mechanism's keyword cluster: +3
   - Sections with RFC 2119 keywords (MUST, SHOULD, etc.): +2
   - Security Considerations sections: +2
   - Sections with cross-references to other RFCs in scope: +1
   - All other sections: +0

2. Include full text for the top-scoring sections until 60% of the
   context budget is used.

3. For remaining sections, include only:
   - The section title
   - The first sentence
   - Any sentences containing RFC 2119 keywords
   - Any sentences containing cross-references

4. If the result still exceeds the budget, drop the lowest-scoring
   sections entirely and log a warning listing which sections were dropped.

**This strategy is deterministic and does not require LLM calls**, avoiding
a dependency loop. It is versioned as part of `PROMPT_VERSION` — changing
the relevance scoring or extraction rules requires a version bump.

## 5. ReportMetadata Expansion

Update the `ReportMetadata` struct in `src/output/report.rs`:

```rust
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub model_used: String,
    pub total_tokens_used: u64,
    pub analysis_duration_secs: f64,
    pub run_id: Option<i64>,
    pub input_hash: Option<String>,
    pub prompt_version: String,
    pub rfc_analyzer_version: String,    // from env!("CARGO_PKG_VERSION")
}
```

## 6. CLI Additions

Add to `analyze` command in `src/cli.rs`:

```rust
    Analyze {
        protocol: String,
        #[arg(long, value_delimiter = ',')]
        categories: Option<Vec<String>>,
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Output format
        #[arg(long, default_value = "json")]
        format: String,   // "json", "text", "markdown"
    },
```

## 7. Command Handler Refactoring

The current `main.rs` is 442 lines with all command handlers inline.
Before Phase 4-6 adds `model`, `analyze`, and `run` commands, refactor
command handlers into a separate module:

```
src/
  commands/
    mod.rs         -- re-exports
    map.rs         -- cmd_map (moved from main.rs)
    show.rs        -- cmd_show (moved from main.rs)
    clear.rs       -- cmd_clear (moved from main.rs)
    graph.rs       -- cmd_graph (moved from main.rs)
    model.rs       -- NEW: cmd_model
    analyze.rs     -- NEW: cmd_analyze
    run.rs         -- NEW: cmd_run
```

`main.rs` becomes just CLI parsing, tracing init, config load, DB open,
and dispatch to `commands::*`.

## 8. Concurrency and Rate Limiting

Clarify the roles (currently `governor` is imported but unused):

- **`tokio::sync::Semaphore`**: limits concurrent in-flight LLM requests
  to `max_concurrent_requests`. This is the primary concurrency control.
- **`governor`**: Remove from dependencies. The semaphore is sufficient
  for v1. Provider-specific rate limits (requests/minute, tokens/minute)
  can be added later if needed.
- **`tokio::time::sleep`**: used for polite delay between RFC fetches
  (already implemented in Phase 2).

## 9. Graceful Shutdown Implementation

Wire up in `main.rs` before command dispatch:

```rust
let cancel_token = tokio_util::sync::CancellationToken::new();
let cancel_clone = cancel_token.clone();
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Interrupt received, finishing current work item...");
    cancel_clone.cancel();
});
```

Pass `cancel_token` to pipeline stages. Each stage checks
`cancel_token.is_cancelled()` between work items. If cancelled:
1. Finish the current LLM call (don't abort mid-request)
2. Persist completed work items
3. Set `analysis_runs.status = 'interrupted'`
4. Exit cleanly

Add `tokio-util` to dependencies (for `CancellationToken`).
