# Code Review 4-1: Phase 4 LLM Integration

## 1) Summary

Phase 4 is implemented cleanly and is broadly compliant with `docs/specs/impl-phase4-llm.md`. The new LLM module, prompt helpers, response parsing utilities, command refactor, graceful shutdown token wiring, CLI shape, and migration v2 are all present. The implementation compiles and the reported 69 passing tests / zero warnings result is consistent with the code quality observed.

The main remaining concern is not compile correctness: it is cancellation responsiveness during LLM retry sleeps and in-flight HTTP calls. That does not block Phase 5, but it matters once Phase 5/6 run longer multi-work-item pipelines.

## 2) Spec Compliance

Matches the spec:

- `Cargo.toml` removes `governor` and adds `tokio-util`; `wiremock` is present for LLM tests.
- `src/error.rs` includes all required LLM error variants: `LlmApi`, `LlmParse`, `LlmRateLimit`, `LlmContextOverflow`, and `LlmContentRefusal`.
- `src/db/schema.rs` adds migration v2 with `security_leads.run_id`, `security_leads.fingerprint`, recreated `state_machines` with `run_id`, and `run_work_items`.
- `src/config.rs` adds deferred API key resolution through `LlmConfig::resolve_api_key`.
- `src/llm/client.rs` implements OpenAI-compatible chat completions, JSON mode, semaphore concurrency, retries for `429` and `5xx`, context overflow classification, content-filter refusal classification, token estimation, context budgeting, model access, and cancellation token access.
- `src/llm/response.rs` implements markdown fence stripping, JSON object parsing, partial array parsing, and fallback refusal detection.
- `src/llm/prompts.rs` provides `PROMPT_VERSION`, section delimiters, injection-defense text, and Stage 2/3 prompt builders.
- Command handlers were moved out of `main.rs` into `src/commands/*`, and `main.rs` is now a slim CLI/config/db/dispatch entry point.
- `clear` validates scope before prompting and deletes `run_work_items` in the analysis/all paths.
- `Analyze` and `Run` CLI variants include `--output` and `--format`.

Minor deviations or intentional choices:

- `cmd_graph` continues the Phase 3 behavior of treating any non-`dot` format as JSON rather than rejecting invalid formats. This is consistent with the existing spec snippet but may be surprising UX.
- `strip_markdown_fences` is `pub(crate)` rather than private. That is harmless and useful for internal tests.

## 3) Code Quality Issues

- `src/llm/client.rs:172` and `src/llm/client.rs:188`: retry backoff uses plain `tokio::time::sleep`. If a cancellation token is triggered during a long `Retry-After` delay, the client will not notice until the sleep finishes. Use `tokio::select!` against `self.cancel_token.cancelled()` so Phase 5/6 can stop promptly between work items.

- `src/llm/client.rs:103-110`: in-flight HTTP requests are not cancellation-aware beyond the fixed 120-second request timeout. This is acceptable for a first pass, but it weakens the graceful-shutdown story for long-running pipelines. Consider wrapping `.send()` in `tokio::select!` with the cancellation token.

- `src/llm/response.rs:71-86`: fence stripping handles only lowercase ` ```json `. Some providers/models return ` ```JSON ` or ` ``` json `. This is not a spec violation, but making the parser case/whitespace tolerant would reduce avoidable parse failures.

- `src/llm/client.rs:140-148`: a modern OpenAI-style refusal may arrive as a separate `message.refusal` field with `content` null/empty. The current implementation reports that as `LlmParse` unless `finish_reason == "content_filter"`. Future compatibility would improve if it checks for a refusal field before treating empty content as parse failure.

## 4) Bugs or Correctness Concerns

- Cancellation during retry sleep is the only concrete behavioral concern. It can cause Ctrl+C to appear ignored for the duration of a server-provided `Retry-After`, which could be much longer than the exponential fallback. This should be fixed before relying on the client for long Phase 5/6 runs, but it does not invalidate the Phase 4 API surface.

- `parse_json_array_partial` returns `Ok(Vec::new())` if the response is a valid JSON array but every element fails item-level deserialization. That matches the “partial results” policy, but Phase 5/6 callers should treat an empty result as a meaningful outcome and decide whether to mark the work item completed, skipped, or failed.

- Migration v2 preserves existing `state_machines` rows with `run_id = NULL`, as specified. Because SQLite `UNIQUE(protocol, name, run_id)` permits multiple `NULL` `run_id` rows for the same protocol/name, legacy rows no longer have the old uniqueness guarantee after migration. Phase 5 writes non-null `run_id`, so this is not a blocker.

## 5) Verdict

Ready for Phase 5.

No fixes are required before Phase 5 implementation starts. I recommend addressing cancellation-aware retry sleeps soon, because it is small and will make the upcoming resumable LLM pipeline behave much better under Ctrl+C and rate-limit scenarios.
