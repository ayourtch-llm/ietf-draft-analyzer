# Design Review 2.3

## 1) Were the 11 Items Fixed Correctly?

Mostly, but not fully.

Fixed correctly:

1. **`provider` field source**: Fixed by removing `provider` from the cache-key
   manifest and `ReportMetadata`.
2. **Dotted section sort order**: Fixed. Numeric-segment comparison is now
   specified for summarization and cache-key ordering.
3. **`run --format`**: Fixed in `cli-interface.md`; it is passed through to
   `analyze`.
4. **Text/markdown output ambiguity**: Fixed by deferring text/markdown and
   making v1 JSON-only.
5. **`CARGO_PKG_VERSION` in cache key**: Fixed. It is no longer part of the
   Stage 2/3 cache-key manifest.
6. **`pipeline-stages.md` stale `(protocol, name)` reference**: Fixed; it now
   says `(protocol, name, run_id)`.
7. **`run_work_items.input_hash` semantics**: Fixed acceptably for v1 by marking
   it reserved and set to `NULL`.
8. **Summarize-to-fit scoring ambiguity**: Fixed. The +3 rule now means sections
   cross-referenced by cluster sections but not themselves in the cluster.
9. **Content refusal detection**: Fixed. `finish_reason` is primary, phrase
   matching is fallback only after JSON parse failure.

Partially fixed or still inconsistent:

10. **`llm/rate_limit.rs` vestige**: Partially fixed. `architecture.md` removed
    the module, but `implementation-sequence.md` still has Phase 4.2 creating
    `src/llm/rate_limit.rs` for semaphore-based concurrency. That should be
    removed or changed to say concurrency lives in `llm/client.rs`.
11. **FK cascade / clear behavior**: Partially fixed. New v2 tables and new
    `run_id` FKs use `ON DELETE CASCADE`, but `database-schema.md` now shows
    cascade on existing v1 FKs (`sections`, `cross_refs`, `dep_edges`,
    `protocol_rfcs`) without a migration that recreates those tables from the
    actual Phase 1 schema. Either add that migration work or keep/manual-document
    the full `clear rfcs` delete order.

## 2) New Issues Introduced

- The new `LlmRateLimit` error snippet will not compile as written:
  `#[error("LLM rate limited{}", retry_after_secs.map(...))]` uses an expression
  inside the format string. `thiserror` format strings can reference fields, but
  not call `map` like that. Use a simpler display string or a custom `Display`
  helper.

- `llm-integration.md` still says parse failures are "logged with the raw
  response", which conflicts with the new logging policy in
  `phase5-6-spec-additions.md` that only truncated details are logged at normal
  levels and full bodies are TRACE-only.

- `architecture.md` and `database-schema.md` still describe simplified Stage
  2/3 input hashes, while `phase5-6-spec-additions.md` defines the authoritative
  fuller manifest. The main specs should point to the canonical manifest or
  repeat the same fields.

## 3) Pass/Fail for Phase 4-6 Readiness

**Fail, but close.**

The 11 review-2.2 items are mostly resolved, but Phase 4 cannot be handed to an
AI implementer with a non-compiling error enum snippet and conflicting logging
instructions. Phase 5-6 are also close, but the stale `rate_limit.rs` reference,
cache-key summary mismatch, and cascade/migration ambiguity should be fixed
first.

After those small corrections, the specs should be ready for Phase 4-6
implementation.
