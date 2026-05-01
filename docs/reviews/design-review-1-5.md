# Design Review 1.5

**Reviewer**: Codex final sign-off review
**Date**: 2026-05-01
**Scope**: All 8 updated files in `docs/specs/`, all prior reviews in
`docs/reviews/`, and fixtures in `docs/specs/test-fixtures/`

## 1) Executive Summary

The updated specs are now clean enough for Phase 1-3 implementation. The
foundation, RFC ingestion, database schema, parser expectations, graph
semantics, CLI workflow, migration setup, and baseline operational behavior are
internally consistent and detailed enough to code against.

The remaining concerns are no longer blocking the early implementation phases.
The issues left open from review 1-4 are mostly Phase 5-6 concerns around
LLM-stage provenance, resumability, prompt/version contracts, and reproducible
artifact identity. Those gaps are now identifiable and bounded. They should be
resolved before implementing protocol modeling and security analysis, but they
do not prevent starting the foundation, ingestion, and dependency graph work.

Final sign-off recommendation: proceed with Phase 1-3. Treat Phase 4 as LLM
client plumbing plus prompt/version infrastructure. Before Phase 5 begins, add
one focused spec update for run-to-artifact linkage, per-work-item tracking,
prompt version constants, summarize-to-fit behavior, and deterministic lead
identity.

## 2) Issues Resolved Since Review 1-3

The specs now address the implementation blockers and cross-spec mismatches
called out in review 1-3 and tracked again in review 1-4:

- `implementation-sequence.md` no longer describes chunked state-machine
  extraction and merge-by-name. It now matches the summarize-or-skip strategy
  in `pipeline-stages.md`.

- `database-schema.md` now documents all required SQLite pragmas:
  `foreign_keys`, `journal_mode = WAL`, and `busy_timeout = 5000`.

- `cli-interface.md` includes `model_context_window` in the config example,
  matching the LLM context-budget spec.

- `architecture.md` explicitly scopes v1 to RFC-only analysis. BCP/STD
  aliases, Internet-Drafts, errata ingestion, and non-RFC specs are out of
  scope.

- `database-schema.md` now makes `schema_version` a migration-history table
  with `version INTEGER NOT NULL UNIQUE`; current version is `MAX(version)`.

- `analysis_runs.model_used` is nullable, which matches non-LLM Stage 1 runs.

- Stage 1 fetch-failure behavior is now specified: seed RFC 404s fail the
  stage; transitive reference 404s warn, skip, and do not create graph nodes.

- `cross_refs` no longer has the overly restrictive uniqueness constraint that
  would drop repeated references from the same source section to the same
  target.

- `map` now warns when `--protocol` is omitted, preventing the common
  map-then-model pitfall where RFCs are cached but not associated with a
  protocol.

- Baseline progress logging is now specified at `info` level for long-running
  operations.

- The regression fixtures now distinguish Type A spec-level weaknesses from
  Type B implementation-failed-to-follow-spec cases. The scoring target is
  better aligned with the tool's core mission: at least 2 of 3 Type A fixtures
  and at least 1 of 1 Type B fixture should produce hits or near misses.

These updates close the major implementation-readiness issues for Phase 1-3 and
make the remaining Phase 5-6 work easier to isolate.

## 3) Remaining Concerns

### Phase 5-6 Persistence and Provenance

The largest remaining gap is still the lack of durable linkage between runs and
LLM-derived artifacts. `state_machines` and `security_leads` do not have
`run_id` foreign keys, and `analysis_runs` is not enough by itself to answer
"which exact run produced this state machine or lead?"

This becomes important as soon as prompts, models, model parameters, section
selection, or summarization strategy changes. Without run linkage, old and new
artifacts for the same protocol will be hard to compare, debug, or selectively
report.

Related issue: Stage 3 says completed categories are tracked for resume, but
there is still no `run_work_items` table or equivalent schema field for
per-category or per-mechanism completion. This is not needed for Phase 1-3, but
it should exist before Stage 2/3 implementation.

### Artifact Identity

`state_machines` still uses `UNIQUE(protocol, name)`, which is too coarse for
multiple model/prompt runs and too restrictive if two runs produce different
state machines with the same generated name.

`security_leads` still uses random UUIDs without a deterministic fingerprint.
That makes cross-run regression comparison difficult. The known-CVE fixtures
will be more useful if leads have stable fingerprints derived from protocol,
category, normalized technique name, affected RFC sections, and evidence text.

### Prompt and Hash Versioning

`analysis_runs.prompt_version` exists, but the specs still do not define a
concrete versioning scheme or constants in `llm/prompts.rs`. The first
implementation needs explicit prompt version constants per task or at least one
global `PROMPT_VERSION`.

The composite hash model is good enough conceptually, but the Phase 5-6 hash
inputs should be expanded before implementation to include:

- prompt/schema version
- parser version
- section-selection version
- summarization version
- model parameters such as temperature and max output tokens
- canonical JSON ordering rules for RFC lists and filters

### Summarize-to-Fit

The specs correctly reject chunked state-machine extraction, but the replacement
strategy is still underspecified. "Summarize less-relevant sections" needs an
implementation contract:

- Is summarization extractive, heuristic, or LLM-based?
- Is the summary cached?
- Does it get its own version in input hashes?
- How does it preserve security-relevant edge cases?

For v1, an extractive strategy is the safer default: keep full text for the
highest-relevance sections, then include selected sentences from lower-priority
sections based on titles, RFC 2119 keywords, state-machine terms, and
category-specific keywords.

### LLM Operational Details

`llm-integration.md` still blurs concurrency limiting and provider rate
limiting. A semaphore controls in-flight requests; `governor` should control
request/token rate if those settings exist. The specs currently do not define
requests-per-minute or tokens-per-minute settings.

LLM API error classification is also still thin. Retry behavior for 429 and
5xx is specified, but terminal errors such as 401, 403, 404 model-not-found,
request-too-large, and provider refusal should have defined behavior before
Phase 4 hardens.

### Data Model Auditability

Several data model gaps remain relevant to the LLM stages:

- `CrossRef` lacks extraction method and confidence.
- `SecurityLead` lacks evidence strength, review status, evidence kind, and
  implementation-assumption fields.
- `ReportMetadata` lacks run ID, input hash, prompt version, code version,
  provider, and model parameters.
- `Section.number` remains required, which is workable for Phase 1 but may
  become awkward for appendices, anchor-only sections, and unusual RFC
  structures.

These are not blockers for ingestion and graphing, but they matter for
trustworthy final reports.

### Output UX

`run` has `-o`, but `analyze` still lacks `-o/--output` and `--format`. JSON
can remain the primary machine-readable artifact, but Phase 6 should provide at
least a text or markdown report for human triage.

## 4) Final Suggestions

Before Phase 5 starts, make one targeted spec update with these changes:

1. Add `run_id` to `state_machines` and `security_leads`, or define an
   equivalent artifact-to-run association table.

2. Add `run_work_items` for Stage 2 mechanisms and Stage 3 categories, with
   `run_id`, work-item kind/key, input hash, status, timestamps, token usage,
   and error.

3. Replace `state_machines` uniqueness with a run-aware key such as
   `(run_id, protocol, name)` or `(protocol, name, content_hash)`.

4. Add deterministic lead fingerprints alongside UUIDs.

5. Define prompt version constants and include them in run manifests,
   state-machine artifacts, security leads, and report metadata.

6. Specify the summarize-to-fit algorithm and version it as part of Stage 2/3
   cache keys.

7. Add LLM API error classification and clarify semaphore versus rate-limiter
   responsibilities.

8. Expand `ReportMetadata` to include run ID, input hash, prompt version,
   model parameters, provider, code/schema version, and generated report
   format.

9. Add `analyze -o/--output` and `--format json|text|markdown` before Phase 6
   report generation.

10. Keep the known-CVE fixtures as manual/semantic validation until a
    machine-readable scoring file exists. The current fixture docs are good
    enough to guide development, but not yet sufficient as deterministic CI
    gates.

## 5) Readiness Assessment

### Phase 1: Ready

Foundation work is ready. Error handling, config validation, database
initialization, schema migrations, `tokio-rusqlite`, and the core data model
are specified well enough to implement.

### Phase 2: Ready

RFC ingestion is ready. Fetch behavior, XML-first/text-fallback logic, cache
hashing, parser responsibilities, Stage 1 404 handling, and `map --protocol`
workflow are clear enough for implementation.

### Phase 3: Ready

Dependency graph construction is ready. Edge kinds, edge direction, graph
persistence, and graph export have stable contracts. Remaining graph UX issues,
such as `graph <TARGET>` ambiguity, are minor and can be handled during
implementation.

### Phase 4: Mostly Ready

The LLM client can be implemented, but Phase 4 should include prompt-version
constants and error classification rather than deferring them. This phase can
proceed in parallel with the Phase 5-6 spec update because it is mostly client
plumbing.

### Phase 5-6: Not Ready to Code Yet, but Gaps Are Clear

The high-level design for protocol modeling and security analysis is sound, and
the known-CVE fixtures provide a useful validation target. The remaining gaps
are now clearly identified: run provenance, resumability, artifact identity,
prompt/hash versioning, summarize-to-fit behavior, and report metadata.

Final verdict: **ready for Phase 1-3 implementation; Phase 5-6 require one
focused spec pass before implementation.**
