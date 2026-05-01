# Code Review 5-1: Phase 5 Protocol Modeling

## 1) Summary

Phase 5 is implemented close to the spec and integrates cleanly with the Phase 1-4 codebase. The core pieces are present: `analysis_store` CRUD, summarize-to-fit, Stage 2 clustering/extraction, `model` command dispatch, run provenance, caching by input hash, work item persistence, and state machine storage scoped by `run_id`.

The implementation compiles with the reported 81 passing tests and zero warnings. Most of the earlier spec risks around hashing, explicit SQL branches, `ON CONFLICT`, and resumability are handled.

There is one important correctness issue: cancellation surfaced as an LLM client error can mark a run as `failed` instead of `interrupted`. There is also no mocked end-to-end Stage 2 integration test, despite the spec calling for one as implementation guidance.

## 2) Spec Compliance

What matches:

- `src/db/analysis_store.rs` implements `create_run`, `find_completed_run`, `find_resumable_run`, `complete_run`, work item CRUD, `store_state_machine`, and `get_state_machines`.
- `get_state_machines` uses two explicit SQL branches for `run_id: Some` vs `None`, matching the final spec direction.
- `store_state_machine` uses `ON CONFLICT(protocol, name, run_id) DO UPDATE`, so rerunning a work item in the same run is idempotent.
- `src/pipeline/summarize.rs` implements the candidate-set rule from the spec: cluster sections plus sections cross-referenced by cluster sections, not arbitrary security/RFC2119 sections.
- Summarization scoring matches the intended shape: cluster sections are strongly preferred, referenced context receives a smaller boost, RFC 2119/security/xref signals add secondary weight, and ordering is deterministic.
- `src/pipeline/modeling.rs` computes the Stage 2 hash from sorted RFCs, section text hash, prompt version, model, temperature, max tokens, context window, and mechanism filter.
- `run_stage2` correctly checks completed runs before creating/resuming a run, records work items, persists state machines, marks runs completed/failed/interrupted, and skips completed work items on resume.
- `src/commands/model.rs`, `src/pipeline/mod.rs`, `src/db/mod.rs`, `src/commands/mod.rs`, `src/lib.rs`, and `src/main.rs` are wired as specified.

Minor deviations or accepted limitations:

- Resumed runs re-run clustering, as documented in the spec. This is acceptable for v1.
- A cache hit returns `Ok(0)` rather than the number of already persisted state machines. That matches the command’s “no new state machines” semantics, but it means callers should not interpret the return value as “total available machines.”

## 3) Code Quality Issues

- `src/pipeline/modeling.rs:200-202`: completed work items are reloaded from the database inside every cluster iteration. This is correct but inefficient. Load once into a `HashSet<String>` before the loop and update it after successful completions if duplicate mechanism names are possible.

- `src/db/analysis_store.rs:210-224`: `complete_work_item` does not check whether the `UPDATE` affected a row. Current call sites upsert first, so this is not failing today, but future Phase 6 callers could silently lose work item status if they call it without a prior `upsert_work_item`.

- `src/pipeline/summarize.rs` recomputes “referenced by cluster” by scanning `all_sections` for every candidate. This is fine for Phase 5 scale, but a precomputed set of referenced `(rfc, section)` pairs would simplify the logic and avoid repeated scans.

- `src/pipeline/modeling.rs:433-443`: the section text hash concatenates section text without delimiters or section identifiers. This follows the current spec closely enough, but using explicit RFC/section delimiters would make the hash more robust against rare ambiguous concatenations.

## 4) Bugs or Correctness Concerns

- `src/pipeline/modeling.rs:147-160` and `src/pipeline/modeling.rs:299-383`: cancellation from `LlmClient` is not handled as interruption. If Ctrl+C is received after the explicit cancellation check but before/during `llm.chat_json`, the client can return `RfcAnalyzerError::Config("Operation cancelled")`; the generic error arm marks the run as `failed`. The Phase 5 verification requires Ctrl+C during LLM work to preserve partial results with status `interrupted`. The simplest fix is to check `llm.cancel_token().is_cancelled()` in error paths before calling `complete_run(..., "failed", ...)`, or introduce a dedicated cancellation error variant.

- `src/pipeline/modeling.rs:115-162` and `src/pipeline/modeling.rs:388-390`: resumed run token accounting starts at zero and overwrites `analysis_runs.tokens_used` with only the resumed invocation’s tokens when the run completes. If `tokens_used` is intended as total run provenance, this loses tokens from earlier interrupted attempts. If it is intended as “latest invocation only,” that should be documented before Phase 6 uses the same pattern.

- Failed per-mechanism work items are compatible with a final `completed` run. This may be intentional, but it means a completed cached run can include failed mechanisms and future reruns with the same input hash will skip the whole stage. That is acceptable only if “completed” means “all work items reached a terminal state,” not “all mechanisms succeeded.” The report/Phase 6 logic should read work item failures if users need visibility.

- There is no `tests/stage2_integration.rs` or equivalent mocked-LLM integration test. The unit tests cover hashing, validation, persistence helpers, and summarization, but they do not verify the full `run_stage2` path with a mocked clustering response and state-machine response. The spec explicitly called this out as implementation guidance.

## 5) Verdict

Needs small fixes before treating Phase 5 as fully ready for Phase 6.

The implementation is structurally sound and largely spec-compliant, but the cancellation-status bug should be fixed because it directly contradicts the Phase 5 verification goal and affects resumability. I would also add the mocked Stage 2 integration test before building Phase 6 on top of this pipeline.
