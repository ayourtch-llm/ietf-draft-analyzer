# Design Review 1.4

**Reviewer**: Claude (fresh review against updated specs)
**Date**: 2026-05-01
**Scope**: All 8 spec files in `docs/specs/`, test fixtures in `docs/specs/test-fixtures/`
**Prior reviews**: `design-review-1-1.md`, `design-review-1-2.md`, `design-review-1-3.md`

## 1) Executive Summary

The specs have improved substantially across the two update rounds. The most
serious structural problems from earlier reviews — async/SQLite strategy,
broken chunked extraction, missing protocol assignment, edge direction
ambiguity, absent config validation, missing schema migrations — are all
resolved. The three cross-spec inconsistencies flagged by review 1-3 (stale
chunking language in implementation-sequence, missing PRAGMAs in database-schema,
missing `model_context_window` in CLI config) have been fixed.

The specs are **ready for Phase 1-3 implementation** (foundation, RFC
ingestion, dependency graph). These phases involve no LLM calls, and the
relevant specs — data model, database schema, fetcher behavior, parser
expectations, graph construction, edge direction, CLI commands — are
sufficiently detailed and internally consistent to write code against.

For Phase 4+ (LLM integration and the analysis pipeline), a set of
persistence and provenance issues from review 1-3 remain unaddressed.
These are not blockers for the foundation work, but they should be resolved
before Stage 2/3 code hardens. The most important remaining gaps are:

1. **No run-to-artifact linkage.** `state_machines` and `security_leads`
   have no `run_id` foreign key. After multiple runs with different models
   or prompts, there is no way to determine which run produced which
   artifacts.

2. **Per-category resume tracking has no schema support.** The pipeline
   spec says per-category completion is tracked, but the database has no
   field or companion table to represent it.

3. **Prompt versioning is declared but not defined.** `analysis_runs` has a
   `prompt_version` column, but no spec defines what prompt versions look
   like, how they're assigned, or where the constants live.

4. **The summarize-to-fit overflow strategy is unspecified.** It is now the
   primary context-window overflow path, but whether it is LLM-based,
   extractive, or heuristic is not defined.

These are specification gaps, not design flaws — the architecture is sound,
and these can be resolved with targeted spec additions before Phase 5 begins.

## 2) Issues Resolved Since Prior Reviews

### From Review 1-3 (most recent)

- **Cross-spec inconsistency: implementation-sequence chunking language.**
  Phase 5.3 now says "summarize less-relevant sections to fit; if still too
  large, warn and skip the oversized cluster." The stale "chunking + merging"
  language is gone. (`implementation-sequence.md:112-113`)

- **Cross-spec inconsistency: database PRAGMAs.** `database-schema.md` now
  includes all three PRAGMAs (`foreign_keys`, `journal_mode = WAL`,
  `busy_timeout = 5000`) in a dedicated Connection Setup section.
  (`database-schema.md:9-17`)

- **Cross-spec inconsistency: missing `model_context_window` in CLI config.**
  The config example now includes `model_context_window = 128000`.
  (`cli-interface.md:150`)

- **`tokio-rusqlite` not mentioned in database spec.** The database schema
  now references `tokio-rusqlite` in its Connection Setup section.
  (`database-schema.md:18-19`)

- **v1 scope ambiguity.** `architecture.md` now explicitly states v1 is
  RFC-only and that BCP/STD aliases, Internet-Drafts, errata, and non-RFC
  specs are out of scope. (`architecture.md:10-15`)

### From Review 1-2

All ten issues raised in review 1-2 were addressed in earlier update rounds:
async SQLite (`tokio-rusqlite`), chunked extraction removed, incremental
persistence within stages, severity-first ranking, section keywords for all
10 categories, `model_context_window` added with 30% safety margin,
config validation table, `<<<RFC_SECTION>>>` delimiters, graceful shutdown
with `interrupted` status, on-demand section loading from SQLite, orphaned
`analysis_version` removed, `map --protocol`, `EdgeKind::CrossReference`
section field redundancy resolved.

### From Review 1-1

The bulk of review 1-1's concerns were addressed in earlier rounds:
composite input hashes, run manifests in `analysis_runs`, schema migrations,
protocol assignment, edge direction convention, `Cargo.lock` commitment,
MSRV, additional database indexes, `clear` confirmation prompt, depth
semantics clarified.

## 3) Remaining Concerns and New Gaps

### 3.1 Remaining from Review 1-3 (Unaddressed)

The following issues from review 1-3 remain in the current specs. I list
them briefly here for tracking; see review 1-3 Section 3 for full context.

**Persistence and provenance:**
- No `run_id` on `state_machines` or `security_leads`. Artifacts cannot be
  attributed to specific runs. (`database-schema.md:124-134`, `139-159`)
- Per-category resume tracking is claimed in `pipeline-stages.md:157` but
  `analysis_runs` has no field to represent it.
  (`database-schema.md:162-188`)
- `state_machines` UNIQUE constraint `(protocol, name)` is too weak for
  versioned runs and too strong for variant outputs.
  (`database-schema.md:134`)
- `security_leads` uses random UUIDs with no deterministic fingerprint for
  cross-run comparison. (`database-schema.md:139`)

**Cache-key completeness:**
- Composite hashes still omit `temperature`, `max_tokens_per_request`,
  section-selection algorithm version, and parser version.
  (`architecture.md:137-145`)
- `prompt_version` field exists in `analysis_runs` but is never defined as
  a concrete constant or versioning scheme. (`database-schema.md:181`)
- No canonical ordering specified for JSON array fields used in hash
  computation. (`database-schema.md:175-180`)

**Data model gaps:**
- `Section.number` is still required and unique in the schema. Appendices
  (`A.1`), unnumbered sections, and anchor-only sections are not addressed.
  (`database-schema.md:60-69`, `data-model.md:62-69`)
- `CrossRef` lacks extraction method and confidence.
  (`data-model.md:77-83`)
- `SecurityLead` lacks evidence strength, review status, or structured
  evidence fields. (`data-model.md:220-232`)
- `ReportMetadata` lacks run ID, input hash, prompt version, code version.
  (`data-model.md:262-268`)

**LLM integration:**
- `governor` and semaphore roles are still conflated.
  (`llm-integration.md:56-58`)
- Summarize-to-fit strategy is unspecified (LLM-based? extractive?
  heuristic? cached? versioned?). (`pipeline-stages.md:115-119`,
  `llm-integration.md:73-74`)
- No requests-per-minute or tokens-per-minute rate limit settings.
  (`llm-integration.md:56-58`)

**CLI UX:**
- `analyze` has no `-o/--output` or `--format` flag.
  (`cli-interface.md:51-63`)
- `graph <TARGET>` remains ambiguous between protocol name and RFC number.
  (`cli-interface.md:79-89`)
- No `--dry-run` or cost estimation mode. (`cli-interface.md`)

### 3.2 New Concern: `analysis_runs` Schema Serves Conflicting Purposes (database-schema.md)

`analysis_runs` is simultaneously a run log, a cache-key store, and a run
manifest. It stores both the raw inputs (`seed_rfcs`, `depth`,
`normative_only`, `mechanism_filter`, `category_filter`) AND the derived
`input_hash` computed from those inputs.

This creates two problems:

1. **Redundancy with no spec for which is authoritative.** The incrementality
   check uses `input_hash`, but the raw fields are also stored. If an
   implementer changes the hash function, old raw-field rows with different
   hashes become orphaned. There is no spec for reconciliation.

2. **`effective_rfcs` is an output, not an input.** Stage 1's `input_hash`
   covers seed RFC content hashes + depth + `normative_only`. But
   `effective_rfcs` (all RFCs discovered during crawl) is only known after
   Stage 1 completes. Storing it in the manifest is good for provenance, but
   it should be explicitly labeled as an output field, not included in hash
   computation. The current spec does not distinguish input fields from
   output fields in the manifest.

### 3.3 New Concern: Silent Failure When `--protocol` Is Omitted (cli-interface.md, pipeline-stages.md)

`map --protocol` is optional. If a user runs `rfc-analyzer map 9293 --depth 2`
without `--protocol`, the RFCs are fetched and parsed, but no `protocol_rfcs`
entries are created. A subsequent `rfc-analyzer model tcp` will find zero RFCs
for protocol "tcp" and fail.

The spec does not define:
- What error message `model` produces when `protocol_rfcs` is empty for the
  given protocol
- Whether `model` should suggest adding `--protocol` to the `map` command
- Whether `map` should warn when `--protocol` is omitted (since without it
  the RFCs are only cached, not protocol-assigned)

This is a predictable user-experience pitfall for the documented `map` then
`model` then `analyze` workflow.

### 3.4 New Concern: `cross_refs` UNIQUE Constraint Is Too Restrictive (database-schema.md)

```sql
UNIQUE(source_rfc, source_section, target_rfc, target_section)
```

An RFC section can reference the same target section multiple times in
different contexts. For example, RFC 9293 Section 3.10 might reference
RFC 5961 Section 3 twice — once discussing RST handling and once discussing
SYN handling. Only the first `INSERT` succeeds; subsequent references with
different `context` text are silently dropped (or cause `INSERT OR IGNORE`
to skip them).

This loses information that may matter for both graph weight and LLM
context selection. The constraint should either include `context` in the
uniqueness check (potentially creating near-duplicates) or be relaxed to
a non-unique index.

### 3.5 New Concern: `analysis_runs.model_used NOT NULL` for Non-LLM Stages (database-schema.md)

Stage 1 (map) is primarily fetch/parse. The LLM is used only optionally
for ambiguous reference resolution. But `model_used TEXT NOT NULL` requires
every `analysis_runs` row to have a model value.

Review 1-3 raised this; it remains unaddressed. The implementer must decide
whether to store `"none"`, the configured model name (even if unused), or
make the column nullable. This should be specified.

### 3.6 New Concern: Section Text Storage Is Uncompressed and Potentially Large (database-schema.md)

The `sections` table stores section `text` as uncompressed TEXT. For a
depth-2 crawl of 50+ RFCs, section text could total 30-50 MB in the
database — more than the compressed `raw_content` in `rfcs`.

The spec compresses `raw_content` with zstd for space efficiency but does
not address section text, which is the more frequently accessed working
dataset (loaded on demand for LLM prompt assembly in Stages 2 and 3).
This may not be a problem in practice, but it is worth noting given the
"database as project artifact" framing.

### 3.7 New Concern: No Error Classification for LLM API Failures (llm-integration.md)

The retry spec says "retries on 429 and 5xx with exponential backoff, up
to 3 attempts." This covers transient failures, but the spec does not
address permanent error classes:

| Error | Meaning | Correct Behavior |
|-------|---------|-----------------|
| 401 | Invalid API key | Fail immediately, clear message |
| 403 | Forbidden (quota, policy) | Fail immediately |
| 404 | Model not found | Fail immediately |
| 400 | Request too large | Skip work item, warn |
| Content policy refusal | Model refuses security content | Skip work item, warn |

Retrying permanent errors wastes time and may confuse users. The spec
should classify errors into retryable vs. terminal categories.

### 3.8 New Concern: No Progress Reporting for Long Runs (architecture.md, cli-interface.md)

The tool uses `tracing` for structured logging, but there is no mention of
user-facing progress reporting. A full pipeline run can involve:
- Fetching 50+ RFCs (minutes)
- 10+ LLM calls for mechanism clustering and state extraction (minutes)
- 10-30+ LLM calls for security analysis (many minutes)

Without progress feedback, users have no way to distinguish "working" from
"stuck." At minimum, the spec should define that each stage logs its
progress (e.g., "Fetching RFC 5/47", "Analyzing category 3/10:
AuthBypass") at the default verbosity level. The `-v` flags control
tracing verbosity, but baseline progress should be visible without `-v`.

### 3.9 New Concern: Regression Fixture Methodology Conflates Two Capability Types (test-fixtures/)

The 6 CVEs in the regression suite test two fundamentally different
capabilities:

**Type A — Spec-level weakness** (3 CVEs): The specification itself has a
gap, ambiguity, or missing constraint that leads to vulnerable
implementations.
- Kerberos CVE-2025-59088: Cross-section gap between KDC discovery and
  DNS security warning
- IPv6 CVE-2012-4444: Cross-RFC hardening adoption gap
- Telnet CVE-2026-32746: Missing length limit in SLC sub-option

**Type B — Implementation ignores clear spec requirement** (3 CVEs): The
specification clearly requires a behavior, but implementations fail to
follow it.
- TLS CVE-2025-12765, CVE-2026-25644, CVE-2026-31798: Applications
  disable certificate validation despite RFC 8446 Appendix C.5

The tool should be good at surfacing Type A (that is its core value
proposition). For Type B, the tool can only surface the normative
requirement — it cannot determine whether implementations follow it. The
TLS fixture acknowledges this ("converted into a code-level search
pattern"), but counting 3 Type B CVEs as half the benchmark skews the
evaluation toward finding obvious normative requirements rather than subtle
spec-level weaknesses.

This matters for the "4 of 6" target. If the tool hits all 3 Type B CVEs
(easy — just find "MUST validate certificates" in Appendix C.5) and misses
all 3 Type A CVEs (hard — requires cross-section/cross-RFC reasoning), it
passes the benchmark while failing at its core mission.

**Suggestion**: Score Type A and Type B separately. Require at least 2 of 3
Type A hits and at least 1 of 1 Type B hits (treating TLS as a single
fixture with 3 example CVEs, not 3 separate test cases).

### 3.10 New Concern: No Handling for Missing or "Not Issued" RFCs (pipeline-stages.md)

Stage 1 expansion follows references to discover new RFCs. Some referenced
RFC numbers may be:
- Not yet published (referenced as work-in-progress)
- Never assigned (reserved number ranges)
- Unavailable from rfc-editor.org for other reasons

The spec says "there are no unfetched boundary nodes — every RFC in the
graph has been fully ingested." But a 404 from rfc-editor.org is not
addressed. Should the stage:
- Silently skip the RFC and omit the edge? (Loses information)
- Store a stub node with a "fetch_failed" status? (Contradicts "no boundary
  nodes")
- Fail the entire stage? (Fragile)
- Log a warning and continue? (What happens to edges pointing to it?)

This will occur in practice — older RFCs reference documents that predate
the RFC series or reference Internet-Drafts by their eventual RFC number.

### 3.11 Observation: `schema_version` Table Lacks Structure (database-schema.md)

The `schema_version` table has no PRIMARY KEY, no UNIQUE constraint, and
no invariant defining whether it stores a single current-version row or a
history of applied migrations:

```sql
CREATE TABLE schema_version (
    version       INTEGER NOT NULL,
    applied_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Review 1-3 flagged this. It remains unspecified. The implementation must
decide:
- Single row (current version) — needs `CHECK` or application-side enforcement
- One row per migration (history) — needs `UNIQUE(version)` and the
  migration runner must query `MAX(version)`

Either is fine, but the spec should say which.

## 4) Suggestions for Improvement

### For Phase 1-3 (implement now)

1. **Specify the `schema_version` invariant.** Recommend: one row per
   applied migration with `UNIQUE(version)`. Current version is
   `MAX(version)`.

2. **Relax the `cross_refs` UNIQUE constraint.** Either drop the
   uniqueness on `(source_rfc, source_section, target_rfc,
   target_section)` or add a non-trivial differentiator. A simple
   non-unique index on `(source_rfc, target_rfc)` is sufficient for
   query performance.

3. **Define 404/fetch-failure handling in Stage 1.** Recommend: log a
   warning, skip the RFC, and store the edge with a `NULL` target node
   (or drop the edge). Do not fail the entire stage.

4. **Add baseline progress logging.** At `info` level (visible without
   `-v`), log stage start/end and per-item progress ("Fetching RFC 5/47",
   "Parsing RFC 9293 (XML)"). This is trivial to implement and
   significantly improves the user experience.

5. **Warn when `map` is run without `--protocol`.** Emit a message:
   "RFCs cached but not associated with a protocol. Use --protocol
   <name> to enable model/analyze commands."

6. **Make `analysis_runs.model_used` nullable.** Stage 1 map runs without
   LLM should store `NULL`, not a placeholder string.

### For Phase 4+ (before LLM stages)

7. **Add `run_id` to `state_machines` and `security_leads`.** This is the
   minimum viable provenance linkage. Without it, debugging prompt or model
   changes across runs is impractical.

8. **Add a `run_work_items` table** for per-category resume tracking in
   Stage 3 and per-mechanism tracking in Stage 2. Fields: `run_id`,
   `work_item_kind` (category/mechanism), `work_item_key`, `status`,
   `started_at`, `completed_at`.

9. **Define prompt version constants.** A simple `const PROMPT_VERSION:
   &str = "1.0.0"` in `prompts.rs` that is stored with every LLM-derived
   artifact. Incrementing it invalidates cached results via the composite
   hash.

10. **Specify the summarize-to-fit mechanism.** Recommend starting with
    extractive summarization (keep first N sentences of each section plus
    any sentences containing RFC 2119 keywords) rather than LLM-based
    summarization, to avoid a dependency loop where the overflow handler
    itself needs LLM calls with their own context budgets.

11. **Classify LLM API errors.** Add a table of error codes to
    `llm-integration.md` distinguishing retryable (429, 5xx) from
    terminal (401, 403, 404) from work-item-skip (400 request too large,
    content policy refusal).

12. **Separate input and output fields in `analysis_runs`.** Mark
    `effective_rfcs` as an output field. Document which fields participate
    in `input_hash` computation and which are stored for provenance only.

13. **Split regression fixtures by type.** Score "spec-level weakness"
    (Type A: Kerberos, IPv6, Telnet) and "implementation fails to follow
    spec" (Type B: TLS) separately. Require at least 2/3 Type A hits.

14. **Add `-o/--output` and `--format` to `analyze`.** Users who run
    stages separately should be able to capture and format the output.
    This is a small CLI change that unblocks human-readable output later.

## 5) Readiness Assessment

### Phase 1 (Foundation): READY

The error type, config structure, data model, database schema, migration
framework, and `tokio-rusqlite` access strategy are all well specified.
Config validation ranges are defined. The only minor items to resolve
before implementing:
- `schema_version` table needs a defined invariant (suggestion 1)
- `analysis_runs.model_used` nullability (suggestion 6)

These can be resolved during implementation without spec ambiguity.

### Phase 2 (RFC Ingestion): READY

The fetcher behavior (XML-preferred with text fallback, polite delay,
content hash caching), parser expectations (XML via `<xref>`, plain text
via defined regex patterns), RFC index lookup, and `map --protocol`
semantics are all sufficiently specified. Items to resolve:
- 404/fetch-failure handling (suggestion 3)
- `cross_refs` UNIQUE constraint relaxation (suggestion 2)
- Warning when `--protocol` is omitted (suggestion 5)

These are minor and can be decided during implementation.

### Phase 3 (Dependency Graph): READY

Edge direction is explicit, edge kinds are well-defined, graph persistence
via `dep_edges` is clear, and DOT/JSON export is straightforward. The
`graph <TARGET>` ambiguity is a minor UX issue that does not block
implementation (a simple "try as protocol first, then as RFC number"
heuristic works for v1).

### Phase 4 (LLM Integration): MOSTLY READY

The LLM client, retry logic, response parsing, prompt templates, and
config validation are well specified. Prompt injection defense is
reasonable. Remaining gaps:
- Error classification (suggestion 11)
- Governor/semaphore role clarification
- Prompt version constant definition (suggestion 9)

These are small enough to resolve inline during Phase 4 implementation.

### Phase 5-6 (Stage 2-3 Pipeline): NOT YET READY

The pipeline logic is well designed at a high level, but persistence
contracts for run provenance, resumability, and overflow handling need
firming up before code hardens:
- `run_id` linkage (suggestion 7)
- Per-work-item tracking table (suggestion 8)
- Summarize-to-fit specification (suggestion 10)
- `state_machines` UNIQUE constraint needs rework

**Recommendation: proceed with Phase 1-3 implementation immediately.**
Address suggestions 7-13 as spec updates before Phase 5 begins. Phase 4
can proceed in parallel with those spec updates since it is LLM plumbing,
not pipeline logic.

### Overall Verdict

**Ready for Phase 1-3 implementation. Spec updates needed before Phase 5.**

The architecture is sound, the design has been significantly hardened
through three review rounds, and the foundation/ingestion/graph specs are
internally consistent and detailed enough to code against. The remaining
gaps are localized to LLM-stage persistence and provenance — important,
but they do not affect the first three phases of work.
