# Code Review 6-1: Phase 6 Security Analysis

## 1) Summary

Phase 6 completes the command surface and implements the Stage 3 security analysis pipeline: category-based section selection, per-category LLM analysis, persisted security leads, run-level caching, resumability, report generation, and the `analyze` / `run` commands. The implementation is generally clean, compiles with the reported 92 passing tests and zero warnings, and follows `docs/specs/impl-phase6-analysis.md` closely.

The code is strong enough to demonstrate the full `map -> model -> analyze` flow, but I would not call it final-release ready yet. Two issues matter for the completed tool: cancellation during an LLM call can still mark Stage 3 as `failed` instead of `interrupted`, and there is no mocked end-to-end coverage for the `analyze` or `run` pipeline.

## 2) Spec Compliance

What matches:

- `src/pipeline/section_select.rs` implements all ten attack categories, keyword scoring, state-machine-reference boosting, security-section boosting, category resolution for underscore/hyphen variants, and the requested unit tests.
- `src/pipeline/analysis.rs` implements Stage 3 input hashing, category deduplication before hashing, completed-run cache lookup, resumable-run lookup, per-category work items, section selection, summarize-to-fit integration, LLM prompting, JSON-array parsing, lead processing, fingerprinting, run-scoped persistence, deduplication, severity filtering, ranking, and report provenance output.
- Stage 3 hashing includes sorted RFC numbers, latest model state machines for the protocol, section text hash, prompt version, model, temperature, max tokens, context window, and category filter.
- Cached results are loaded by `run_id`, then deduplicated, ranked, and filtered by severity.
- Lead persistence stores `input_hash`, `run_id`, and `fingerprint`, and deduplicates by `(run_id, fingerprint)` as specified.
- `src/output/report.rs` implements the v1 report shape, including the documented `state_machines_count` simplification, model/run/input-hash metadata, schema version, and deferred `sections_truncated`.
- `src/commands/analyze.rs` validates `format == "json"`, runs Stage 3, rebuilds graph summary, counts state machines, and writes either stdout or a file.
- `src/commands/run.rs` chains map, model, and analyze with cancellation checks between stages.
- `src/pipeline/mod.rs`, `src/commands/mod.rs`, `src/lib.rs`, and `src/main.rs` are wired correctly. `main.rs` now dispatches all implemented commands without the old catch-all “not implemented” arm.

Intentional or acceptable deviations:

- `AnalysisReport` reports `state_machines_count` rather than embedding full state machine JSON. The code documents this as a v1 report-size simplification, matching the final spec direction.
- `sections_truncated` is present but always empty and skipped during serialization. This is explicitly documented as deferred, with truncation notes left in `run_work_items.error`.
- `total_tokens_used` is this-invocation usage, so cache hits report zero tokens. The report metadata documents that historical usage lives in `analysis_runs.tokens_used`.

## 3) Code Quality Issues

- `src/pipeline/analysis.rs:158-162`: resume loading uses `unwrap_or_default()`. If loading prior leads fails due to a database or JSON issue, the run silently continues and may produce an incomplete final report. Since this is part of resumability correctness, it should propagate the error or log it loudly and mark the run failed.

- `src/pipeline/analysis.rs:180-207`: completed categories are loaded once into a `Vec<String>` and checked with repeated allocation via `category.to_string()`. This is fine for ten categories, but a `HashSet<&str>` / `HashSet<String>` would be cleaner and would avoid the same pattern causing problems if the category set grows.

- `src/pipeline/analysis.rs:248-256`: the call to `summarize_to_fit` builds and borrows a temporary `Vec` inline. It is valid Rust, but harder to read and inspect. A named `all_sections_refs` variable, as used in Phase 5, would be clearer.

- `src/pipeline/analysis.rs:470-475`: unknown `min_severity` values resolve to rank `0`, effectively including all leads. That may be acceptable, but CLI users will get silent behavior for typos like `--min-severity hgh`. Consider validating severity in `cmd_analyze`.

- `src/commands/run.rs:19-49`: `format` is only validated at the final analyze stage. An invalid format can still perform map and model work before failing. Consider validating `format` at the start of `cmd_run`.

## 4) Bugs or Correctness Concerns

- `src/pipeline/analysis.rs:286-334`: cancellation during `llm.chat(...)` is treated as a fatal failure. `LlmClient` returns `RfcAnalyzerError::Config("Operation cancelled...")` when the cancellation token is tripped before a request or during retry sleep. The generic `Err(e)` arm marks the analyze run as `failed`, not `interrupted`. This contradicts the Phase 6 verification requirement that Ctrl+C during analysis saves partial results and resumes on the next run. Phase 5 already has a similar fix; Stage 3 should apply the same pattern before final sign-off.

- `src/pipeline/analysis.rs:185-202`: when cancellation is detected at the top of the next category, `run_stage3` returns `all_leads` directly without applying the final dedup/filter/rank pass. If `cmd_analyze` builds a report from that partial result, the output can contain unfiltered or unranked leads. Either return no report on interruption, or run the same post-processing before returning partial leads.

- `src/pipeline/analysis.rs:383-390`: the run is marked `completed` even if one or more categories failed parsing, overflowed, or were marked failed work items. This matches the current “terminal work item” style, but it means future cache hits skip the whole analyze stage and preserve failed categories. That behavior should be explicit in user-facing logs/report metadata, or the run status should distinguish “completed_with_failures.”

- `src/pipeline/analysis.rs:651-654`: `compute_stage3_hash` silently treats failure to load state machines as an empty state-machine set via `unwrap_or_default()`. A transient DB/read issue could produce a wrong hash and false cache behavior. It should propagate the error.

- Test coverage is too thin for a final phase. The new tests cover pure helpers, but there is no mocked LLM integration test for `run_stage3`, no cache-hit test for `load_existing_leads` through the public path, no resume test with existing category work items and persisted leads, no `cmd_analyze` report-output test, and no `cmd_run` full-pipeline smoke test. The only integration test file remains `tests/fetch_real.rs`.

## 5) Verdict

Needs fixes before final sign-off.

The final pipeline is implemented and broadly spec-compliant, but the cancellation-status bug is a real correctness issue for the resumability contract. Before calling the tool complete, I would fix Stage 3 cancellation handling, avoid returning unprocessed partial reports on interruption, propagate state-machine hash load errors, and add at least one mocked end-to-end `run_stage3`/`cmd_analyze` test plus a cache/resume test.
