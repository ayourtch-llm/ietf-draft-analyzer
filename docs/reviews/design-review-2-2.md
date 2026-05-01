# Design Review 2.2

**Reviewer**: Claude (review of updated specs + phase5-6 additions)
**Date**: 2026-05-01
**Scope**: `docs/specs/phase5-6-spec-additions.md`, all 8 main spec files
(updated for consistency), and `docs/reviews/design-review-2-1.md` (Codex
review)

## 1) Summary

The spec updates are substantial and well executed. The main spec files
have been updated to incorporate the phase5-6 additions rather than
leaving them as a sidecar document — this resolves the biggest structural
concern from review 2-1. Most of the Codex review's specific issues have
been addressed: the migration is transactional, the CHECK constraint is
present, `idx_leads_run` exists, `run_work_items.input_hash` is in the
schema, the `clear` delete order is documented, error classification has
body-based 400 handling, content refusal detection, and a logging policy,
the cache-key manifest is comprehensive with ordering rules, and the main
spec files are now consistent with the additions.

**The specs are ready for Phase 4 implementation** (LLM client, response
parsing, prompt templates). Phase 4 is LLM plumbing with well-defined
inputs, outputs, and error handling.

**The specs are close to ready for Phase 5-6** but have a small number of
issues that should be resolved first. The remaining concerns are not
design-level — they are specification precision gaps that would force an
implementer to guess. The most significant are: the `provider` field has
no configuration source, dotted-section sort order is incorrect as
specified, text/markdown output formats have no rendering spec, and
`CARGO_PKG_VERSION` in the cache key is too coarse.

## 2) Issues Resolved Since Review 2-1

### Migration v2 (all Codex concerns addressed)

- **Transaction wrapping**: The migration SQL now has `BEGIN`/`COMMIT`.
  (`phase5-6-spec-additions.md:13,63`)
- **CHECK constraint on `run_work_items.status`**: Present with valid
  values `'pending', 'running', 'completed', 'failed'`.
  (`database-schema.md:228`, `phase5-6-spec-additions.md:48`)
- **`idx_leads_run` index**: Now present in both the migration and the
  main schema. (`database-schema.md:172`)
- **`run_work_items.input_hash`**: Now present in the schema, addressing
  the Codex concern about per-item resume decisions.
  (`database-schema.md:233`)
- **NULL uniqueness documented**: The phase5-6 spec explains that legacy
  null-`run_id` rows are not uniqueness-protected in SQLite, and that all
  new rows MUST have non-null `run_id`. (`phase5-6-spec-additions.md:73-75`)
- **Redundant ALTER TABLE**: The Codex review said the migration adds
  `state_machines.run_id` then recreates the table. The current migration
  only ALTERs `security_leads` (which is not recreated) and recreates
  `state_machines` from scratch. The redundancy concern does not apply to
  the current text.

### `clear` Delete Order

The phase5-6 spec Section 7 now explicitly documents the required delete
order: `security_leads` → `state_machines` → `run_work_items` →
`analysis_runs`. This addresses the Codex concern about FK violations.
(`phase5-6-spec-additions.md:287-297`)

### Cache-Key Completeness

Section 10 defines exhaustive, ordered cache-key manifests for Stage 2 and
Stage 3, including temperature, max_tokens, model_context_window, provider,
PROMPT_VERSION, and CARGO_PKG_VERSION. Ordering rules are defined for all
list inputs. This is a major improvement over the prior "hash of inputs"
hand-waving. (`phase5-6-spec-additions.md:336-382`)

### LLM Error Classification

Section 2 now includes:
- Body-based HTTP 400 classification (context_length → skip, other → fail).
  (`phase5-6-spec-additions.md:135-142`)
- `Option<u64>` for `retry_after_secs`. (`phase5-6-spec-additions.md:110`)
- Content refusal detection via `finish_reason` and response body patterns.
  (`phase5-6-spec-additions.md:146-154`)
- Logging policy: truncated at INFO/WARN, full only at TRACE.
  (`phase5-6-spec-additions.md:159-163`)

### Summarize-to-Fit

Section 4 specifies an extractive, deterministic strategy with scoring,
tie-breakers, budget unit, sentence extraction rules, and dropped-section
recording. No LLM dependency. (`phase5-6-spec-additions.md:179-217`)

### Main Spec Consistency

The main spec files have been updated to reflect the phase5-6 additions:
- `database-schema.md`: `state_machines` has `run_id` and
  `UNIQUE(protocol, name, run_id)`, `security_leads` has `run_id` and
  `fingerprint`, `run_work_items` table exists, `analysis_runs.model_used`
  is nullable, INPUT/OUTPUT fields separated, `schema_version` has
  `UNIQUE(version)` with documented invariant.
- `dependencies.md`: `governor` removed, `tokio-util` added.
- `llm-integration.md`: Semaphore replaces governor, `rate_limit.rs`
  context is now concurrency-only.
- `data-model.md`: `ReportMetadata` expanded with provider, run_id,
  input_hash, prompt_version, rfc_analyzer_version, temperature,
  max_tokens_per_request, schema_version, report_format,
  sections_truncated.
- `cli-interface.md`: `analyze` has `-o/--output` and `--format`,
  `map --protocol` omission warning documented, 404 handling in
  pipeline-stages.
- `architecture.md`: Progress reporting section added.
- `cross_refs`: UNIQUE constraint removed (was too restrictive).

This addresses the Codex review's biggest concern about sidecar
inconsistency.

### Other Codex Concerns Addressed

- **`analysis_runs.model_used` nullability**: Now `TEXT` without `NOT NULL`.
  Non-LLM stages store `NULL`. (`database-schema.md:188`)
- **`effective_rfcs` as output field**: `analysis_runs` now has a comment
  separating INPUT fields (participate in `input_hash`) from OUTPUT fields
  (provenance only). (`database-schema.md:192-201`)
- **Prompt version constants**: Defined as `PROMPT_VERSION` in
  `src/llm/prompts.rs`, stored in `analysis_runs.prompt_version` and used
  in composite input hashes. (`phase5-6-spec-additions.md:167-177`)

## 3) Remaining Concerns

### 3.1 `provider` Field Has No Configuration Source (phase5-6-spec-additions.md, cli-interface.md)

`ReportMetadata` includes `provider: String` (e.g., "openai", "ollama").
The cache-key manifest includes `Provider` as item 6 for both Stage 2 and
Stage 3. But the `rfc-analyzer.toml` config has no `provider` field —
only `api_base`, `api_key_env`, and `model`.

How is `provider` determined?
- Inferred from `api_base`? (Fragile: `https://api.openai.com/v1` →
  "openai", but custom proxies or Azure endpoints won't match.)
- Hardcoded? (Wrong for non-OpenAI users.)
- User-configured? (Then add it to the config spec.)

This is a cache-key input — getting it wrong means false cache hits across
providers. Either add `provider` to the config, or remove it from the
cache key and report metadata and rely on `api_base` + `model` being
sufficient to distinguish providers (which they are in practice, since
different providers use different model names).

### 3.2 Dotted Section Sort Order Is Incorrect as Specified (phase5-6-spec-additions.md)

Section 4 says:

> Tie-breaker: RFC number ascending, then section number ascending
> (lexicographic on dotted notation, e.g., "3.2" < "3.10" is compared
> as strings — implementers should use the same ordering as
> `parser_text.rs`).

Lexicographic string comparison gives `"3.10" < "3.2"` (because `'1' < '2'`
in ASCII). This means section 3.10 sorts before section 3.2, which is
wrong for anyone expecting numeric segment comparison.

This ordering is used in the summarize-to-fit tie-breaker and in the
cache-key manifest's section sorting rule. If two implementations use
different orderings, they produce different input hashes for the same
logical input, breaking cache interoperability.

The spec should either:
- Define numeric-segment comparison (split on `.`, compare each segment as
  `u32`) — the natural expectation.
- Accept string comparison and state the consequence explicitly: "3.10
  sorts before 3.2."

Since this affects cache-key determinism, it must be unambiguous.

### 3.3 `run` Command Missing `--format` (cli-interface.md)

`analyze` now has `--format json|text|markdown`, but `run` (which chains
map → model → analyze) only has `-o/--output`:

```
rfc-analyzer run [OPTIONS] <PROTOCOL> <RFCS>...
Options:
  --depth <N>
  -o, --output <PATH>
```

Users of the full pipeline — the most common workflow — cannot request
text or markdown output. `run` should pass `--format` through to its
internal `analyze` step.

### 3.4 Text and Markdown Output Formats Are Unspecified (cli-interface.md, data-model.md)

The CLI accepts `--format text` and `--format markdown`, and
`ReportMetadata.report_format` stores which format was used. But no spec
defines what these formats look like.

For an implementation agent, "output format: text" is insufficient. At
minimum:
- **text**: Define the layout. A ranked table of leads? What columns?
  Severity coloring via ANSI codes? How are state machines summarized?
  How many leads are shown by default?
- **markdown**: Is this a full document with headers and table of contents?
  Are RFC references hyperlinked? Is the state machine output included?

Without a rendering spec, the implementer either guesses or defers the
feature. If this is a v1 feature (it's in the CLI spec), it needs enough
detail to implement. If it's deferred, remove it from the CLI spec and
add it to a future work section.

### 3.5 `CARGO_PKG_VERSION` in Cache Key Is Too Coarse (phase5-6-spec-additions.md)

The cache-key manifest includes `env!("CARGO_PKG_VERSION")` (item 10 for
both stages). This means bumping the version from `0.1.0` to `0.1.1` —
even for a change that only affects graph export formatting — invalidates
ALL cached Stage 2 and Stage 3 results.

For a tool where LLM analysis is expensive, this is wasteful. Potential
fixes:
- Use a separate `ANALYSIS_VERSION` constant that is bumped only when
  analysis-affecting code changes. Similar to `PROMPT_VERSION` but for
  non-prompt code (section selection logic, dedup, validation, scoring).
- Remove `CARGO_PKG_VERSION` from the cache key entirely. Between
  `PROMPT_VERSION`, model name, temperature, and all other inputs, the
  hash already captures everything that affects output. Code-level changes
  that affect analysis (e.g., section-selection heuristic changes) should
  bump `PROMPT_VERSION` as the spec already requires.

### 3.6 `llm/rate_limit.rs` Module Is Vestigial (architecture.md)

The module structure still lists `llm/rate_limit.rs`:

```
  llm/
    ...
    rate_limit.rs      -- Token/request rate limiting, retry with backoff
```

But `governor` was removed, concurrency control is a semaphore in
`client.rs`, and retry logic is also in `client.rs`. There is no
remaining purpose for a separate `rate_limit.rs` module. Either:
- Remove it from the module structure.
- Repurpose it to hold the `Retry-After` header parsing and backoff
  logic (if that's complex enough to justify a separate file).

### 3.7 `pipeline-stages.md` Stage 2 Step 4 Still Says `(protocol, name)` (pipeline-stages.md)

`pipeline-stages.md` line 117:

> Store: Serialize each `ProtocolStateMachine` as JSON and store in
> the `state_machines` table, keyed by `(protocol, name)`.

The database schema now keys by `(protocol, name, run_id)`. This is a
stale reference that should be updated for consistency.

### 3.8 `run_work_items.input_hash` Semantics Undefined (phase5-6-spec-additions.md, database-schema.md)

The `run_work_items` table has an `input_hash TEXT` column (added in
response to the Codex review), but neither the phase5-6 additions nor the
main specs define what inputs are hashed per work item.

For a **category** work item in Stage 3: is it the category name +
selected section texts + state machine summaries? Just the category name
+ the run's global input hash?

For a **mechanism** work item in Stage 2: is it the mechanism name +
cluster section texts?

Without this definition, the per-item `input_hash` is unimplementable.
Resume decisions ("has this exact work item been done for these exact
inputs?") depend on what's included. If the field is optional/unused for
v1, say so. If it's required, define the hash inputs per work-item kind.

### 3.9 "Sections Referenced by the Mechanism's Keyword Cluster" Undefined (phase5-6-spec-additions.md)

Summarize-to-fit scoring (Section 4, item 1) gives +3 points to "sections
referenced by the mechanism's keyword cluster." But mechanism clusters are
produced by Stage 2's LLM call (mechanism clustering prompt). At the point
where summarize-to-fit runs (before sending sections to the state-machine
extraction prompt), the cluster is already defined — it's the list of
sections the LLM assigned to that mechanism.

So does "referenced by the mechanism's keyword cluster" mean:
- (a) Sections that are in the cluster (tautologically all of them)?
- (b) Sections that are cross-referenced BY sections in the cluster but
  not themselves in the cluster?
- (c) Sections that contain keywords related to the mechanism name?

Interpretation (a) gives all sections +3, making the score useless.
Interpretation (b) requires resolving cross-references, which is
reasonable but not stated. Interpretation (c) introduces a keyword concept
for mechanisms that doesn't exist elsewhere. The spec should clarify.

### 3.10 FK Delete Order Not Enforced by Schema (database-schema.md)

The specs use `PRAGMA foreign_keys = ON` without `ON DELETE CASCADE`.
The `clear` delete order is documented in phase5-6 Section 7 and in
`cli-interface.md` prose, but only for `clear analysis` and `clear all`.

For `clear rfcs`:
- The CLI says "clearing rfcs cascades to dependent graphs and analysis."
- But with no `ON DELETE CASCADE`, the application must manually delete in
  order: `security_leads` → `state_machines` → `run_work_items` →
  `analysis_runs` → `dep_edges` → `cross_refs` → `sections` →
  `protocol_rfcs` → `rfcs`.
- This 9-step delete order is not documented anywhere.

This is error-prone. Either add `ON DELETE CASCADE` to the foreign keys
(simpler, less code, let SQLite handle it) or document the full delete
order for all `clear` scopes.

### 3.11 Content Refusal Detection Is Heuristic-Fragile (phase5-6-spec-additions.md)

The spec detects content refusal by checking if the response contains
phrases like "I cannot", "I'm unable to", "against my guidelines" AND
fails JSON validation.

Problems:
- These phrases are English-centric and model-specific. Different models
  use different refusal language.
- A valid JSON response that happens to contain "I cannot" in a
  description field would not trigger this (it passes JSON validation), so
  false positives are low. But a malformed JSON response that contains "I
  cannot" for unrelated reasons (e.g., "I cannot be replayed...") would be
  misclassified.
- The `finish_reason` check is the reliable signal. The body-pattern
  check should be a fallback, not an equal-weight heuristic.

Suggest: Check `finish_reason` first. Only fall back to body-pattern
matching if `finish_reason` is `"stop"` (normal) but JSON parsing fails.

## 4) Suggestions

1. **Add `provider` to the config** as an optional string field with
   auto-detection from `api_base` as default. Or remove it from cache keys
   and metadata, relying on `api_base` + `model` (which are already in the
   hash via model name).

2. **Define section sort order as numeric-segment comparison.** Split
   dotted numbers on `.`, compare each segment as `u32`, and fall back to
   string comparison for non-numeric segments (appendix letters). Document
   this in both the summarize-to-fit spec and the cache-key ordering rules.

3. **Add `--format` to the `run` command.** Pass it through to the
   internal `analyze` step.

4. **Define text and markdown output formats** or defer them. If v1 ships
   JSON-only, remove `text` and `markdown` from the `--format` enum and
   add them in a future phase. Half-specified output formats are worse than
   no output format.

5. **Replace `CARGO_PKG_VERSION` with `PROMPT_VERSION`** in the cache key,
   or add a separate `ANALYSIS_VERSION` constant for non-prompt
   code changes. `PROMPT_VERSION` already captures prompt-level changes;
   `CARGO_PKG_VERSION` over-invalidates.

6. **Remove `llm/rate_limit.rs`** from the module structure, or clarify
   its purpose as housing retry/backoff logic.

7. **Update `pipeline-stages.md` Stage 2 Step 4** to say
   `(protocol, name, run_id)`.

8. **Define `run_work_items.input_hash` computation** for each work-item
   kind, or mark it as "reserved for future use" in v1.

9. **Clarify summarize-to-fit scoring item 1.** If it means "sections that
   are in the cluster being processed," say so and adjust the score
   (because all sections being processed are in the cluster). If it means
   something else, define it.

10. **Add `ON DELETE CASCADE`** to FK declarations, or document the full
    delete order for all `clear` scopes (including `clear rfcs`).

11. **Prioritize `finish_reason`** over body-pattern matching for content
    refusal detection.

## 5) Readiness Assessment

### Phase 4 (LLM Client + Prompt Templates): READY

The LLM client design, error classification, retry logic, concurrency
control, prompt templates, response parsing, and config validation are
all well specified. The error variants are concrete Rust code. The
semaphore-based concurrency model is clean. An implementation agent can
build this phase without guessing.

Minor items to resolve inline:
- `rate_limit.rs` module role (suggestion 6) — trivial
- `provider` source (suggestion 1) — can default to `"openai"` initially

### Phase 5 (Stage 2 — Protocol Modeling): READY WITH CAVEATS

The mechanism clustering prompt, state-machine extraction prompt,
validation rules, summarize-to-fit strategy, and context-window handling
are all specified. The `run_work_items` table enables resumability.

Caveats that should be resolved first:
- Summarize-to-fit scoring item 1 ambiguity (suggestion 9) — blocks
  deterministic implementation
- Section sort order (suggestion 2) — affects both summarization and
  cache keys
- `(protocol, name)` vs `(protocol, name, run_id)` stale reference
  (suggestion 7) — minor but could cause confusion

### Phase 6 (Stage 3 — Security Analysis): READY WITH CAVEATS

The per-category analysis flow, incremental persistence, deduplication
strategy, severity-first ranking, section-selection keywords, and
fingerprint computation are all specified. The cache-key manifest is
comprehensive.

Caveats:
- `run_work_items.input_hash` undefined (suggestion 8) — blocks per-item
  resume decisions
- Text/markdown output format unspecified (suggestion 4) — either define
  or remove from v1
- `run` missing `--format` (suggestion 3) — small CLI gap
- `CARGO_PKG_VERSION` over-invalidation (suggestion 5) — will cause pain
  during development when version bumps discard expensive results

### Overall Verdict

**Ready for Phase 4 implementation. Ready for Phase 5-6 implementation
after resolving ~5 targeted spec items** (section sort order,
summarize-to-fit scoring clarification, `run_work_items.input_hash`
semantics, text/markdown format definition or deferral, and the stale
`(protocol, name)` reference).

The specs have been through four review rounds and two update cycles.
The architecture is sound, the persistence model is well-designed, the
error handling is concrete, and the main spec files are internally
consistent. The remaining gaps are small and localized. This is a good
place to start building.
