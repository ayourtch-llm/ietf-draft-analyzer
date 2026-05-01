# Design Review 2.1

## 1) Summary

`docs/specs/phase5-6-spec-additions.md` is a useful targeted update and it
addresses many of the Phase 5-6 gaps called out in design reviews 1-3 through
1-5: run-to-artifact linkage, per-work-item progress, deterministic lead
fingerprints, prompt versioning, summarize-to-fit behavior, output flags,
command refactoring, LLM error categories, concurrency clarification, and
graceful shutdown.

However, I would not treat it as implementation-ready yet. The direction is
right, but several details conflict with the current Phase 1-3 implementation
or leave enough ambiguity that an implementation agent would need to guess.
The biggest issues are the SQLite migration semantics, missing updates to the
current `clear` behavior, incomplete cache/hash provenance, and underspecified
summarization and LLM error handling.

## 2) Does This Address the Prior Review Gaps?

Mostly, but not completely.

Resolved or substantially improved:

- `state_machines` and `security_leads` gain `run_id`, which addresses the
  core provenance gap from reviews 1-3 through 1-5.
- `run_work_items` gives the pipeline a concrete schema for mechanism/category
  resumability instead of relying only on `analysis_runs.status`.
- `state_machines` uniqueness is no longer just `(protocol, name)`, which was
  too coarse for multi-model and multi-prompt runs.
- `security_leads.fingerprint` gives cross-run comparison a deterministic key.
- `PROMPT_VERSION` in `src/llm/prompts.rs` gives the prompt-version field an
  implementation home.
- Summarize-to-fit is now explicitly extractive and deterministic, avoiding the
  earlier broken chunk-and-merge design.
- `ReportMetadata` now includes run ID, input hash, prompt version, and code
  version.
- `analyze` gains `-o/--output` and `--format`, closing the separate-stage
  output gap.
- The `governor`/semaphore confusion is resolved in favor of a semaphore for
  v1 concurrency control.
- Graceful shutdown now has a concrete `CancellationToken` approach.

Still only partially addressed:

- `run_work_items` omits the `input_hash` field explicitly requested in prior
  reviews. Without it, resume decisions are tied only to `run_id` and work item
  name, not the exact per-item input.
- The composite hash model still omits or under-specifies prior requested
  inputs: parser version, section-selection version, summarization version as a
  distinct concept, model parameters such as temperature and max output tokens,
  model context window, provider/model revision, schema/code version, and
  canonical JSON ordering rules.
- `ReportMetadata` still omits provider, model parameters, schema version, and
  generated report format, all called out in review 1-5.
- The deterministic fingerprint is good, but it drops evidence quotes, which
  review 1-3 suggested including. That may be intentional, but the spec should
  state why the stable identity excludes quote text.

## 3) New Concerns or Inconsistencies

### Migration v2 Needs Tightening

The proposed migration should be made safer before implementation.

- `UNIQUE(protocol, name, run_id)` does not enforce uniqueness for legacy or
  otherwise null `run_id` rows in SQLite, because `NULL` values are distinct for
  unique constraints. If new artifacts must always have a run, say so and make
  write paths enforce it. If legacy rows remain nullable, use an explicit
  strategy such as a partial unique index for non-null `run_id` plus a separate
  legacy constraint, or accept and document that legacy null rows are not
  uniqueness-protected.
- The migration first adds `state_machines.run_id`, then recreates
  `state_machines` and drops the altered table. That initial `ALTER TABLE` is
  redundant and makes the migration harder to reason about.
- The migration is destructive for `state_machines` but the current migration
  runner in `src/db/schema.rs` applies each migration with `execute_batch`
  without an explicit per-migration transaction. The v2 SQL should either wrap
  the recreate sequence in `BEGIN`/`COMMIT` or the runner should become
  transactional before this migration lands.
- `run_work_items.status` has documented valid values but no `CHECK`
  constraint. Existing schema v1 already uses checks for RFC format, so this
  should follow that pattern.
- `security_leads.run_id` lacks an index. There is an index for fingerprints,
  but reports and comparisons will commonly query leads by run.
- Foreign key delete behavior is unspecified. Current schema uses foreign keys
  without `ON DELETE CASCADE`, so the application must delete in the correct
  order.

### Current `clear` Command Will Break Unless Updated

The current `cmd_clear` in `src/main.rs` deletes `analysis_runs` after
`security_leads` and `state_machines`. Once `run_work_items` references
`analysis_runs(id)`, both `clear analysis` and `clear all` must delete
`run_work_items` before deleting `analysis_runs`, or SQLite foreign-key checks
will reject the clear operation.

The additions mention the new table but do not specify updates to `clear`, the
new `commands/clear.rs`, or tests for this delete order.

### Cache and Provenance Are Still Not Fully Specified

`PROMPT_VERSION` is a good start, but it should not be the only versioning knob.
The current design reviews asked for versioning across prompt schema, parser
behavior, section selection, summarization, model settings, and canonical
serialization. The additions say summarization is versioned as part of
`PROMPT_VERSION`, but they do not define whether changes to parser behavior,
keyword selection, category filters, model context budget, temperature, or max
output tokens invalidate prior work.

This matters because `analysis_runs.input_hash` already exists in schema v1 and
is intended to be the cache key. If Phase 5-6 implementers build against the
current additions literally, stale LLM artifacts can still be reused after a
material behavior change.

### Summarize-to-Fit Is Directionally Good but Still Ambiguous

The extractive approach is the right default, but implementation details remain
underspecified:

- "Sections referenced by the mechanism's keyword cluster" is not defined by
  the implemented Phase 1-3 code or the addition itself.
- The scoring tie-breakers are unspecified. Determinism requires stable
  ordering when scores match, such as RFC number then section order.
- Budget units need to be explicit. The LLM spec uses estimated tokens with a
  70% safety margin, while the addition says "60% of the context budget" without
  restating whether this is estimated tokens, characters, or provider tokens.
- Sentence extraction rules are not defined for RFC prose with lists, ABNF,
  tables, and section headers.
- Dropped sections are logged, but not tied to run metadata or work-item errors.
  For auditability, the report or run record should preserve that truncation
  occurred.

### LLM Error Classification Is Too Coarse

The new error variants fit the existing `RfcAnalyzerError` style, but the
classification table is too broad for direct implementation:

- HTTP 400 is not always context overflow. It can be invalid JSON mode,
  unsupported parameters, malformed request body, model-specific validation, or
  provider-specific errors. The implementation needs body-based classification
  before mapping to `LlmContextOverflow`.
- `LlmRateLimit { retry_after_secs: u64 }` assumes a retry-after value is always
  available. Many providers omit it; the variant should either use
  `Option<u64>` or the retry layer should synthesize and document a fallback.
- "Content refusal" is listed as a condition but not defined structurally. The
  spec should say whether refusal is detected from finish reason, provider error
  type, assistant content, or failed JSON validation.
- For parse failures, normal logs should avoid dumping raw prompts/responses.
  Prior reviews called out LLM data-retention risk; this addition does not
  update the logging policy.

### Current Spec Files Will Become Inconsistent Unless Updated

This addition says it must be incorporated before Phase 5-6 implementation
specs are written, but implementers may still read the existing specs directly.
Several current files will conflict until edited:

- `docs/specs/database-schema.md` still shows `state_machines` with
  `UNIQUE(protocol, name)` and no `run_id`, and `security_leads` without
  `run_id` or `fingerprint`.
- `docs/specs/llm-integration.md` still describes `governor` as enforcing
  `max_concurrent_requests`, while the addition says to remove `governor`.
- `docs/specs/dependencies.md` and `Cargo.toml` still include `governor`, while
  the addition requires `tokio-util`.
- `docs/specs/data-model.md` still has the old `ReportMetadata`.
- `docs/specs/cli-interface.md` still needs the `analyze` output and format
  flags reflected if this addition is accepted.

### Command Refactor Needs a Compile-Safe Contract

The command-module split is sensible and aligns with the current 442-line
`src/main.rs`, but the spec only names files. It should also specify:

- `src/commands/mod.rs` exports and function signatures.
- Whether helper logic like `collect_references` moves with `map.rs` or becomes
  a shared private utility.
- How `CancellationToken` is threaded through command handlers after refactor.
- That behavior and CLI output for `map`, `show`, `clear`, and `graph` must be
  preserved by tests before adding `model`, `analyze`, and `run`.

### Existing Phase 3 Persistence Concern Is Not Addressed

This is not strictly a Phase 5-6 LLM gap, but it matters because the additions
are grounded in the implemented Phase 1-3 code. The current graph persistence
path appends/deduplicates edges but does not clear stale `dep_edges` when a graph
is rebuilt for a narrower scope or changed parser output. If later reports use
persisted graph data for LLM context or metadata, this stale-edge behavior should
be fixed or explicitly avoided.

## 4) Suggestions

1. Revise migration v2 before implementation:
   - remove the redundant `ALTER TABLE state_machines ADD COLUMN run_id`;
   - make the table recreation transactional;
   - add `CHECK(status IN (...))` to `run_work_items`;
   - add `idx_leads_run`;
   - define nullable legacy `run_id` behavior and uniqueness explicitly;
   - update `clear` delete order and tests.

2. Add `input_hash` to `run_work_items`, or explicitly explain why per-item
   resume does not need it.

3. Define a canonical cache-key manifest for Phase 5-6 that includes sorted
   RFC lists and filters, prompt version, prompt/schema version if separate,
   parser version, section-selection version, summarization version, provider,
   model name/revision, temperature, max output tokens, model context window,
   code version, and schema version.

4. Give summarize-to-fit a fully deterministic contract: scoring inputs,
   tie-breakers, token estimation unit, sentence-splitting behavior, dropped
   section recording, and how the summarization version participates in hashes.

5. Tighten LLM error mapping around provider response bodies. Treat HTTP status
   as the first signal, not the only signal.

6. Update the main spec files after accepting this addition. Leaving the
   addition as a sidecar document is fine for review, but implementation agents
   should not need to reconcile conflicting source-of-truth documents.

7. Expand `ReportMetadata` to include provider, model parameters, schema
   version, generated report format, and whether summarization/truncation
   occurred.

## 5) Readiness Assessment

Not ready for Phase 5-6 implementation specs as-is.

The document is a strong patch set for the known gaps, and the broad design is
sound. It is clean enough to use as the basis for the next spec update, but not
clean enough to hand directly to an implementation agent without causing
guesswork or likely follow-up fixes.

Minimum fixes before sign-off:

- Make migration v2 precise and safe against the current schema.
- Update `clear` behavior for `run_work_items`.
- Complete the Phase 5-6 cache/hash/version contract.
- Remove sidecar inconsistencies from the main spec files.
- Tighten summarize-to-fit and LLM error classification enough for deterministic
  implementation.

After those corrections, the Phase 5-6 specs should be ready to turn into
implementation instructions.
