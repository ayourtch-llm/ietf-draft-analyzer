# Phase 5-6 Spec Additions

These additions address the gaps identified in design reviews 1-3 through
1-5 and review 2-1. They are grounded in the actual Phase 1-3
implementation. They must be incorporated before Phase 5-6 implementation
specs are written.

## 1. Schema Migration v2

Add to `src/db/schema.rs` as migration version 2. The existing migration
framework handles this cleanly.

```sql
BEGIN;

-- Link security_leads to the run that produced them (simple nullable add)
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
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    started_at      TEXT,
    completed_at    TEXT,
    tokens_used     INTEGER DEFAULT 0,
    error           TEXT,
    input_hash      TEXT,              -- per-item input hash for resume decisions
    UNIQUE(run_id, work_item_kind, work_item_key)
);
CREATE INDEX idx_work_items_run ON run_work_items(run_id);

-- Add deterministic fingerprint to security_leads for cross-run comparison
ALTER TABLE security_leads ADD COLUMN fingerprint TEXT;
CREATE INDEX idx_leads_fingerprint ON security_leads(fingerprint);
CREATE INDEX idx_leads_run ON security_leads(run_id);

COMMIT;
```

### run_id Semantics

New artifacts (state_machines, security_leads) produced by Phase 5-6 code
MUST have a non-null `run_id`. Legacy rows from Phase 1-3 remain with
`run_id = NULL`.

The `UNIQUE(protocol, name, run_id)` constraint on `state_machines` does
not enforce uniqueness for legacy null-`run_id` rows, because SQLite treats
each NULL as distinct. This is acceptable: legacy rows are not
uniqueness-protected, and all new rows will have a non-null `run_id`.

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

Evidence quotes are excluded from the fingerprint because they vary across
LLM runs for the same logical finding. Two runs analyzing the same section
for the same technique should produce the same fingerprint even if the LLM
selects different illustrative quotes.

## 2. Error Variants for LLM Integration

Add to `src/error.rs` (the existing `RfcAnalyzerError` enum):

```rust
    #[error("LLM API error (HTTP {status}): {body}")]
    LlmApi { status: u16, body: String },

    #[error("LLM response did not contain valid JSON: {detail}")]
    LlmParse { detail: String },

    #[error("LLM rate limited{}", retry_after_secs.map(|s| format!(", retry after {s}s")).unwrap_or_default())]
    LlmRateLimit { retry_after_secs: Option<u64> },

    #[error("LLM request too large for model context window")]
    LlmContextOverflow,

    #[error("LLM content policy refusal: {detail}")]
    LlmContentRefusal { detail: String },
```

### Error Classification

| HTTP Status | Error Variant | Behavior |
|---|---|---|
| 200 | (success) | Parse response |
| 400 | body-based classification (see below) | Depends on body |
| 401 | `LlmApi` | Fail immediately (bad API key) |
| 403 | `LlmApi` | Fail immediately (forbidden) |
| 404 | `LlmApi` | Fail immediately (model not found) |
| 429 | `LlmRateLimit` | Retry with backoff (up to 3 attempts) |
| 5xx | `LlmApi` | Retry with backoff (up to 3 attempts) |
| Content refusal | `LlmContentRefusal` | Skip work item, warn |

### HTTP 400 Body-Based Classification

HTTP 400 is not always a context overflow. The implementation must inspect
the response body to classify the error:

- If the body contains `"context_length"`, `"maximum context length"`,
  `"too many tokens"`, or equivalent provider-specific strings: map to
  `LlmContextOverflow`. Skip the work item and warn.
- Otherwise: map to `LlmApi { status: 400, body }`. The error may be
  invalid JSON mode, unsupported parameters, or malformed request. Fail
  the work item (do not retry).

### Content Refusal Detection

Content refusal is detected from:

1. **Finish reason**: if the response's `finish_reason` is `"content_filter"`
   (OpenAI) or equivalent provider signal.
2. **Response body pattern**: if the assistant's response text contains
   phrases like "I cannot", "I'm unable to", "against my guidelines" and
   the response fails JSON validation.

When detected, map to `LlmContentRefusal` with the relevant detail text.
Skip the work item and log a warning.

### Logging Policy

When logging LLM parse failures or errors, log the response status, model
used, work item key, and a truncated error message. Do NOT log the full
prompt or full raw response body at INFO or WARN level, because LLM
request/response data may be subject to provider data-retention policies.
Full request/response bodies may be logged at TRACE level only.

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

1. Sort sections by relevance score (descending). Tie-breaker: RFC number
   ascending, then section number ascending (lexicographic on dotted
   notation, e.g., "3.2" < "3.10" is compared as strings — implementers
   should use the same ordering as `parser_text.rs`).

   Scoring:
   - Sections referenced by the mechanism's keyword cluster: +3
   - Sections with RFC 2119 keywords (MUST, SHOULD, etc.): +2
   - Security Considerations sections: +2
   - Sections with cross-references to other RFCs in scope: +1
   - All other sections: +0

2. Include full text for the top-scoring sections until 60% of the
   context budget is used. The budget unit is estimated tokens, computed
   as `chars / 4` with a 30% safety margin, matching the token estimation
   in `llm-integration.md`.

3. For remaining sections, include only:
   - The section title
   - The first sentence (period-based splitting, consistent with
     `parser_text.rs` sentence extraction)
   - Any sentences containing RFC 2119 keywords
   - Any sentences containing cross-references

4. If the result still exceeds the budget, drop the lowest-scoring
   sections entirely and log a warning listing which sections were dropped.
   Record the list of dropped sections in the corresponding
   `run_work_items.error` field for auditability (e.g.,
   `"truncated: RFC 4120 §7.2, RFC 4120 §7.3"`).

**This strategy is deterministic and does not require LLM calls**, avoiding
a dependency loop. It is versioned as part of `PROMPT_VERSION` — changing
the relevance scoring or extraction rules requires a version bump.

## 5. ReportMetadata Expansion

Update the `ReportMetadata` struct in `src/output/report.rs`:

```rust
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub model_used: String,
    pub provider: String,                // e.g., "openai", "ollama"
    pub total_tokens_used: u64,
    pub analysis_duration_secs: f64,
    pub run_id: Option<i64>,
    pub input_hash: Option<String>,
    pub prompt_version: String,
    pub rfc_analyzer_version: String,    // from env!("CARGO_PKG_VERSION")
    pub temperature: f64,
    pub max_tokens_per_request: u32,
    pub schema_version: u32,             // current DB schema version
    pub report_format: String,           // "json", "text", or "markdown"
    pub sections_truncated: Vec<String>, // sections dropped by summarize-to-fit
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

### cmd_clear Update

The `clear` command must account for `run_work_items`. The delete order
for `clear analysis` and `clear all` is:

1. `security_leads`
2. `state_machines`
3. `run_work_items`
4. `analysis_runs`

`run_work_items` must be deleted before `analysis_runs` because it holds
a foreign key to `analysis_runs(id)`. Deleting `analysis_runs` first
would violate the foreign-key constraint (the current schema uses
`PRAGMA foreign_keys = ON` without `ON DELETE CASCADE`).

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

## 10. Canonical Cache-Key Manifest

The composite `input_hash` stored in `analysis_runs` must include ALL
inputs that can change the stage's output. The following lists are
exhaustive — any change to a listed input invalidates prior results.

### Stage 2 (Mechanism Clustering + State Machine Extraction)

The Stage 2 `input_hash` is `SHA-256` over the following inputs,
concatenated in this order with `|` separators:

1. Sorted RFC numbers (comma-separated, e.g., `"1035,2136,6895"`)
2. SHA-256 of concatenated section texts (sections sorted by
   `(rfc_number, section_num)`)
3. `PROMPT_VERSION` (from `src/llm/prompts.rs`)
4. Model name (e.g., `"gpt-4o"`)
5. Provider (e.g., `"openai"`)
6. Temperature (as string, e.g., `"0.2"`)
7. `max_tokens_per_request` (as string)
8. `model_context_window` (as string)
9. Mechanism filter (sorted, comma-separated, or `"*"` for all)
10. `env!("CARGO_PKG_VERSION")` (code/schema version)

### Stage 3 (Security Analysis)

The Stage 3 `input_hash` is `SHA-256` over the following inputs,
concatenated in this order with `|` separators:

1. Sorted RFC numbers (comma-separated)
2. SHA-256 of concatenated state machine JSON (machines sorted by name)
3. SHA-256 of concatenated input section texts (sections sorted by
   `(rfc_number, section_num)`)
4. `PROMPT_VERSION`
5. Model name
6. Provider
7. Temperature (as string)
8. `max_tokens_per_request` (as string)
9. `model_context_window` (as string)
10. Category filter (sorted, comma-separated, or `"*"` for all)
11. `env!("CARGO_PKG_VERSION")`

### Ordering Rules

All list inputs are sorted before hashing to ensure determinism:
- RFC numbers: ascending numeric
- Sections: `(rfc_number ASC, section_num ASC)` with section_num compared
  as dotted strings
- Mechanism/category filters: alphabetical ascending
- State machines: sorted by `name` alphabetically
