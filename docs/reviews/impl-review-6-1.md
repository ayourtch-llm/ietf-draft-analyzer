# Implementation Spec Review 6-1 — Phase 6 Security Analysis

**Reviewer**: Claude (Opus)
**Date**: 2026-05-01
**Scope**: `docs/specs/impl-phase6-analysis.md` — thorough implementability review
**Method**: Line-by-line spec read, cross-referenced against all design specs,
Phase 1-3 source files, and Phase 4-5 impl specs

## 1) Design Spec Consistency

### Matches

| Claim | Design Spec | Verified |
|-------|-------------|----------|
| 10 attack categories with keyword heuristics | `pipeline-stages.md` §Stage 3 | Match |
| Per-category section selection with scoring | `pipeline-stages.md` §Stage 3 | Match |
| Security Considerations title: +3 | `pipeline-stages.md` §Stage 3 | Match |
| State machine section ref boost: +2 | `pipeline-stages.md` §Stage 3 | Match |
| Keyword hits: +1 each, capped at +3 | `pipeline-stages.md` §Stage 3 | Match |
| Summarize-to-fit reused from Stage 2 | `phase5-6-spec-additions.md` §4 | Match |
| Deterministic fingerprint: SHA-256(protocol\|category\|norm_name\|sorted_refs) | `phase5-6-spec-additions.md` §7 | Match |
| Deduplication by fingerprint, keep higher confidence | `phase5-6-spec-additions.md` §7 | Match |
| Ranking: severity tier desc, then confidence desc | `pipeline-stages.md` §Stage 3 | Match |
| ReportMetadata fields (model, temperature, prompt_version, etc.) | `data-model.md`, `phase5-6-spec-additions.md` §5 | Match (type issue: see Issue 1) |
| `ReportMetadata.temperature: f64` | `data-model.md` | Match (spec-level) |
| Stage 3 input hash: 9 inputs in canonical order | `phase5-6-spec-additions.md` §10 | Match |
| Hash ordering: RFCs ascending, categories sorted | `phase5-6-spec-additions.md` §10 | Match |
| Resumability via `run_work_items` (category granularity) | `phase5-6-spec-additions.md` §1 | Match |
| Cache hit returns existing leads without LLM calls | `phase5-6-spec-additions.md` §10 | Match |
| Context overflow → skip work item, warn | `phase5-6-spec-additions.md` §2 | Match |
| Content refusal → skip work item, warn | `phase5-6-spec-additions.md` §2 | Match |
| Fatal errors → fail run | `phase5-6-spec-additions.md` §2 | Match |
| Cancellation → set status 'interrupted', persist partial | `phase5-6-spec-additions.md` §9 | Match |
| `security_analysis_prompt(category, sm_summary, sections)` | `llm-integration.md` §Prompt Templates | Match |
| `security_leads` table with `fingerprint`, `run_id` columns | `database-schema.md`, migration v2 | Match |
| `cmd_run` chains map → model → analyze | `cli-interface.md` | Match |
| Delete order includes `security_leads` | `database-schema.md` §Delete Order | Match |

### Mismatches

Detailed below as Issues 1-2.

## 2) Phase 1-5 Code Consistency

### Type Checks

| Type/Field | Expected | Spec Usage | OK? |
|------------|----------|------------|-----|
| `RfcNumber(pub u32)`, `Copy`, `Clone`, `Eq`, `Hash` | model.rs:6-7 | `.0` access, `Copy` in iterators, sorting | Yes |
| `Section.number: String` | model.rs:113 | `sec.number.clone()`, comparison | Yes |
| `Section.title: String` | model.rs:114 | `.to_lowercase()`, `.contains()` | Yes |
| `Section.text: String` | model.rs:116 | `.to_lowercase()`, `.contains()` | Yes |
| `Section.anchor: Option<String>` | model.rs:115 | `anchor: None` in tests | Yes |
| `Section.depth: u8` | model.rs:115 | `depth: 1` in tests | Yes |
| `Section.cross_refs: Vec<CrossRef>` | model.rs:118 | `Vec::new()` in tests | Yes |
| `Section.pn: Option<String>` | model.rs:119 | `pn: None` in tests | Yes |
| `LlmConfig.temperature: f32` | config.rs:28 | Passed to `build()` expecting `f64` | **No** (Issue 1) |
| `LlmConfig.max_tokens_per_request: u32` | config.rs:24 | Passed to `build()` as `u32` | Yes |
| `LlmConfig.model_context_window: u64` | config.rs:30 | Used in hash `.to_string()` | Yes |
| `GraphSummary` derives `Serialize` | query.rs:9 | Embedded in `AnalysisReport: Serialize` | Yes |
| `LlmClient::chat() -> Result<(String, TokenUsage)>` | Phase 4 spec | Destructured at line 483 | Yes |
| `LlmClient::model() -> &str` | Phase 4 spec | Used in hash and report | Yes |
| `LlmClient::cancel_token() -> &CancellationToken` | Phase 4 spec | Used for cancellation check | Yes |
| `LlmClient::estimate_tokens(&self, &str) -> u64` | Phase 4 spec | Used for budget calc | Yes |
| `LlmClient::context_budget(&self, u64) -> u64` | Phase 4 spec | Used for budget calc | Yes |
| `rfc_store::get_protocol_rfcs` returns `Result<Vec<RfcNumber>>` | rfc_store.rs:316 | Used at line 325, 1008 | Yes |
| `rfc_store::get_rfc(conn, u32) -> Result<Option<Rfc>>` | rfc_store.rs:145 | Used at line 393, 804, 1011 | Yes |
| `analysis_store::get_state_machines -> Vec<(String, String, String)>` | Phase 5 spec | Used at line 401, 1017 | Yes |
| `analysis_store::create_run` (11 params) | Phase 5 spec line 47 | 11 args at line 372 | Yes |
| `analysis_store::find_completed_run` (4 params) | Phase 5 spec line 108 | 4 args at line 352 | Yes |
| `analysis_store::find_resumable_run` (4 params) | Phase 5 spec line 136 | 4 args at line 366 | Yes |
| `analysis_store::complete_run` (6 params) | Phase 5 spec line 164 | 6 args at lines 416, 504, 545 | Yes |
| `analysis_store::upsert_work_item` (5 params) | Phase 5 spec line 194 | 5 args at line 433 | Yes |
| `analysis_store::complete_work_item` (7 params) | Phase 5 spec line 227 | 7 args at lines 442, 465, 498, 531, 537 | Yes |
| `analysis_store::get_completed_work_items` (3 params) | Phase 5 spec line 258 | 3 args at line 406 | Yes |
| `prompts::PROMPT_VERSION: &str` | Phase 4 spec | Used in hash and create_run | Yes |
| `prompts::INJECTION_DEFENSE: &str` | Phase 4 spec | Used for token estimation | Yes |
| `prompts::security_analysis_prompt(&str, &str, &str) -> (String, String)` | Phase 4 spec line 643 | Used at line 472 | Yes |
| `llm::response::parse_json_array_partial::<T>(&str) -> Result<Vec<T>>` | Phase 4 spec | Used at line 481 | Yes |
| `summarize::summarize_to_fit(&[(RfcNumber, &Section)], ...)` | Phase 5 spec | Called at line 457 with correct type conversion | Yes |
| `summarize::compare_section_nums(&str, &str) -> Ordering` | Phase 5 spec | Used in hash at line 806 | Yes |
| `DependencyGraph::build(&[Rfc]) -> Self` | graph/builder.rs | Used at line 1015 | Yes |
| `DependencyGraph::summary(&self) -> GraphSummary` | query.rs:19 | Used at line 1016 | Yes |
| `open_memory_database()` is `#[cfg(test)]` | db/mod.rs:25-26 | Not used in Phase 6 tests (no DB tests) | OK |
| `uuid` and `chrono` crates in Cargo.toml | Cargo.toml:19,25 | Used in analysis.rs and report.rs | Yes |

### Compile Check

- All imports present in each code block. `use uuid::Uuid;`, `use sha2::{Digest, Sha256}`,
  `use chrono::Utc;`, `use serde::Serialize;` — all correct.
- `categories: Vec<&str>` iterated with `.iter()` yields `&&str`. Auto-deref to
  `&str` for function parameters — correct.
- `all_sections.iter().map(|(r, s)| (*r, s))` converts `&(RfcNumber, Section)` to
  `(RfcNumber, &Section)` — correct for `summarize_to_fit` parameter.
- `category_tokens: u64;` initialized only in inner `Ok` branch. All `Err`
  branches `continue` or `return`, so the compiler proves initialization before
  use in outer `Ok` branch — correct.
- `Option::<String>::None` turbofish syntax for `state_machine_name` param — correct.
- `&Vec<String>` auto-coerces to `&[String]` for `create_run`'s
  `category_filter: Option<&[String]>` — correct.
- `store_lead` SQL: 15 columns, 15 `?N` placeholders, 15 `params!` values — correct.
- `INSERT ... WHERE NOT EXISTS` with subquery referencing `?14`, `?15` — valid
  SQLite syntax for conditional insert.
- `serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())` —
  `AnalysisReport: Serialize`, so serialization should succeed; fallback is defensive. OK.
- Test structs (`SecurityLead`) use all 11 fields + `..lead1.clone()` for field
  spread — `SecurityLead: Clone` via `#[derive(Clone)]`. OK.

## 3) Issues Found

### Issue 1 (High): `temperature` type mismatch — compile error

`ReportMetadata.temperature` is `f64` (line 906), and `AnalysisReport::build()`
takes `temperature: f64` (line 928). But `LlmConfig.temperature` is `f32`
(config.rs:28).

In `cmd_analyze` (line 1030):

```rust
let report = AnalysisReport::build(
    ...
    config.llm.temperature,    // f32
    config.llm.max_tokens_per_request,
);
```

Rust does **not** perform implicit `f32` → `f64` widening. This will fail to
compile with:

```
expected `f64`, found `f32`
```

The design spec (`data-model.md`) specifies `temperature: f64` for
`ReportMetadata`, so the report type is correct. The mismatch is between
the config type (`f32`) and the report type (`f64`).

**Fix**: Cast at the call site:

```rust
config.llm.temperature as f64,
// or:
config.llm.temperature.into(),
```

This applies to both `cmd_analyze` (line 1030) and anywhere `cmd_run`
might build a report (though `cmd_run` delegates to `cmd_analyze`, so only
one fix site).

### Issue 2 (Low): `state_machine_name` always `None` in `store_lead`

`store_lead` (line 668) hardcodes `Option::<String>::None` for the
`state_machine_name` column:

```rust
Option::<String>::None, // state_machine_name
```

The `security_leads` schema has this column (`database-schema.md`), and it
is intended to link a lead to its originating state machine. But:

1. `LeadResponse` (the LLM output type) has no `state_machine_name` field
2. `SecurityLead` (the processed type) has no `state_machine_name` field
3. No heuristic maps a lead's category/references back to a state machine

This means the column is always NULL for all leads. It's not incorrect —
the column is nullable — but it reduces the value of the state machine
cross-reference in the database.

**Fix**: Either add `state_machine_name` to the LLM prompt schema (asking
the LLM to identify which state machine is relevant), or add a heuristic
that matches `rfc_references` against state machine `source_rfc`/
`source_section`. Or accept the gap with a comment:
`// TODO: state_machine_name linkage deferred to v2`.

### Issue 3 (Low): `cmd_run` hardcodes defaults without CLI pass-through

`cmd_run` (line 1096-1098) calls `cmd_analyze` with hardcoded values:

```rust
commands::analyze::cmd_analyze(
    conn, config, protocol, None, "low", output, format, cancel_token
).await?;
```

- `categories: None` — always runs all 10 categories
- `min_severity: "low"` — always includes all severity levels

The `Run` CLI struct (cli.rs:72-88, as modified by Phase 4) has `output`
and `format` fields but no `categories` or `min_severity`.

This is a reasonable v1 simplification — users who want filtering use the
standalone `analyze` command. But it means `run` always does maximum work
even if the user only cares about high-severity findings.

**Not blocking** — the standalone `analyze` command covers filtering needs.

### Issue 4 (Nit): `input_hash.clone()` in cache-hit return is unnecessary

At line 361-362, the cache-hit early return clones `input_hash`:

```rust
input_hash: input_hash.clone(),
```

Since this is an early `return`, `input_hash` (an owned `String`) could
be moved directly:

```rust
input_hash,
```

Harmless but inconsistent with the move at line 559.

### Issue 5 (Nit): `LeadResponse.category` is LLM-provided, may diverge from input

The LLM returns `category` as a field in `LeadResponse`. `process_lead`
copies it verbatim into `SecurityLead.category`. But the loop iterates over
canonical category names from `CATEGORY_KEYWORDS`.

If the LLM returns a different category name (e.g., "Missing Validation"
instead of "MissingValidation"), the lead's category won't match any
canonical name. This affects:

- `load_existing_leads` has no category filter, so it's not directly broken
- `fingerprint` uses `lead.category`, so LLM-provided names propagate to
  the fingerprint. Two runs could produce different fingerprints for the
  same finding if the LLM varies its category spelling.

**Not blocking** — the prompt should constrain the LLM to use canonical
names. But a defensive normalization (or overriding `lead.category` with
the input `category`) would be more robust.

## 4) Resume Correctness Assessment

| Step | Verified |
|------|----------|
| `find_resumable_run` finds interrupted runs with matching `input_hash` | Yes |
| Prior leads loaded via `load_existing_leads` before loop | Yes |
| `get_completed_work_items(run_id, "category")` returns done categories | Yes |
| Completed categories skipped in loop (`continue`) | Yes |
| New leads appended to `all_leads` alongside prior leads | Yes |
| Final `deduplicate_leads` handles overlap between prior and new | Yes |
| Cancellation mid-loop sets status "interrupted" and returns partial | Yes |
| Fatal error mid-loop sets status "failed" and returns error | Yes |
| Successful completion sets status "completed" | Yes |

**Resume flow is correct.** The only subtlety: prior leads are loaded
before the loop AND new leads are stored incrementally inside the loop.
If the same fingerprint appears in both prior and new leads (unlikely but
possible if categories overlap), `deduplicate_leads` correctly keeps the
higher-confidence version.

## 5) Cache Correctness Assessment

| Input | Hash Position | Verified |
|-------|---------------|----------|
| Sorted RFC numbers | 1 | Yes — sorted before hashing |
| State machine data (sorted by name, individually hashed) | 2 | Yes — compound sub-hash |
| Section texts (in RFC×section order) | 3 | Yes — compound sub-hash |
| `PROMPT_VERSION` | 4 | Yes |
| Model name | 5 | Yes |
| Temperature | 6 | Yes — `.to_string()` on f32 |
| `max_tokens_per_request` | 7 | Yes |
| `model_context_window` | 8 | Yes |
| Categories (sorted) | 9 | Yes — `cats.sort()` before hashing |

**9 inputs match `phase5-6-spec-additions.md` §10 Stage 3 manifest.**

Cache hit correctly returns existing leads without LLM calls. Cache
invalidation occurs when any of the 9 inputs change (different hash).

## 6) Report Metadata Assessment

| Field | Source | Correct? |
|-------|--------|----------|
| `generated_at` | `Utc::now().to_rfc3339()` | Yes |
| `model_used` | `llm.model()` | Yes |
| `total_tokens_used` | Accumulated from LLM calls | Yes (0 on cache hit) |
| `analysis_duration_secs` | `Instant::now()` → `elapsed().as_secs_f64()` | Yes |
| `run_id` | From `create_run` or `find_completed_run` | Yes |
| `input_hash` | From `compute_stage3_hash` | Yes |
| `prompt_version` | `PROMPT_VERSION` constant | Yes |
| `rfc_analyzer_version` | `env!("CARGO_PKG_VERSION")` | Yes |
| `report_format` | Hardcoded `"json"` | Yes |
| `temperature` | `config.llm.temperature` | **Type mismatch** (Issue 1) |
| `max_tokens_per_request` | `config.llm.max_tokens_per_request` | Yes |
| `schema_version` | Hardcoded `2` | Yes (matches migration v2) |
| `sections_truncated` | `Vec::new()` with TODO comment | Yes (deferred, documented) |

All fields are correctly sourced except `temperature` (Issue 1).

## 7) Test Coverage Assessment

| Component | Test Coverage |
|-----------|--------------|
| `score_section_for_category` | 4 tests: security title, keywords, SM refs, case sensitivity — Good |
| `resolve_categories` | Full + filtered — Good |
| `severity_rank` | 7 values including case insensitivity — Good |
| `compute_fingerprint` | Determinism, protocol variation, quote independence — Good |
| `deduplicate_leads` | Same fingerprint keeps higher confidence — Good |
| `rank_leads` | Severity-first, confidence tiebreak — Good |
| `filter_by_severity` | Threshold filtering — Good |
| `format_state_machine_summary` | Basic formatting with states — Good |
| `compute_stage3_hash` | **No test** | Gap |
| `store_lead` | **No test** | Gap |
| `load_existing_leads` | **No test** | Gap |
| `extract_sm_section_refs` | **No test** | Gap |
| `process_lead` | **No test** (confidence clamping untested) | Gap |
| `run_stage3` end-to-end | Guidance only (Section 9), no test code | Expected gap |

The tested functions cover the core logic well (scoring, dedup, ranking,
fingerprinting). The untested functions are primarily I/O and composition
— lower risk but `compute_stage3_hash` (complex, 9 inputs) and
`process_lead` (confidence clamping) would benefit from targeted tests.

The section_select module has particularly good coverage with 5 tests
covering all scoring dimensions.

## 8) Cross-Phase Integration Check

| Integration Point | Phase 6 Usage | Compatible? |
|--------------------|---------------|-------------|
| `cmd_map` signature (Phase 4) | `cmd_map(conn, config, rfcs, Some(protocol), depth, false)` | Yes |
| `cmd_model` signature (Phase 5) | `cmd_model(conn, config, protocol, None, cancel_token.clone())` | Yes |
| `cmd_analyze` from `cmd_run` | `cmd_analyze(conn, config, protocol, None, "low", output, format, cancel_token)` | Yes |
| CLI `Analyze` fields (Phase 4 additions) | Expects `output` and `format` fields | Yes (Phase 4 adds them) |
| CLI `Run` fields (Phase 4 additions) | Expects `format` field | Yes (Phase 4 adds it) |
| `analysis_store` CRUD (Phase 5) | All 7 functions called with correct signatures | Yes |
| `summarize_to_fit` (Phase 5) | Correct type conversion `(RfcNumber, &Section)` | Yes |
| `compare_section_nums` (Phase 5) | Used for section ordering in hash | Yes |
| Cancellation token flow in `cmd_run` | `clone()` for `cmd_model`, move for `cmd_analyze` | Yes |

## 9) Verdict

**PASS — with one required fix (Issue 1).**

Issue 1 (`f32` → `f64` temperature type mismatch) is a **compile error**.
The fix is a single `as f64` cast at line 1030 of `cmd_analyze`. Without
this fix, `cargo build` will fail.

Issue 2 (`state_machine_name` always NULL) and Issue 3 (`cmd_run` hardcodes
defaults) are design gaps, not bugs. Issue 5 (LLM-provided category names)
is a robustness concern that the prompt should handle.

Resume correctness, cache correctness, and report metadata are all sound.
The test coverage is good for the core logic. The spec is self-contained,
all cross-phase integrations are compatible, and — aside from the one type
mismatch — it will compile.
