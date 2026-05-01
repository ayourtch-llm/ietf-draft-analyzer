# Design Review 1.3

## 1) Executive Summary

The updated specs are materially stronger than the versions reviewed in `design-review-1-1.md` and `design-review-1-2.md`. Several high-risk design gaps have been addressed: protocol assignment is now specified, graph edge direction is explicit, async SQLite access has a chosen strategy, schema migrations exist, graceful shutdown is recognized, chunked state-machine merging has been removed, and regression fixtures now provide a concrete quality target.

The design is closer to implementation-ready for Stage 1 and much of the database/CLI foundation. However, the specs are not yet fully implementation-ready for the LLM-heavy Stage 2 and Stage 3 work. The remaining risks are mostly about cross-spec consistency, persistence contracts, reproducibility, and validation. Some previous issues were addressed in one spec file but not propagated to the data model, schema, CLI config example, or implementation sequence.

The biggest remaining blocker is that several newly specified behaviors have no durable schema or data model support. For example, Stage 3 says per-category completion is tracked in the run manifest, but `analysis_runs` has no per-category progress representation. Architecture says WAL and busy timeout are enabled, while `database-schema.md` only requires foreign keys. The pipeline says chunking is not used, while `implementation-sequence.md` still says to handle context overflow with chunking and merging.

The new known-CVE fixtures are a good addition, but they introduce a benchmark contract that needs more rigor: fixture provenance, deterministic scoring, expected sections, acceptable category mappings, and handling of implementation-specific CVEs versus specification-level leads should be pinned before those fixtures become release gates.

Overall readiness: implement the foundation, ingestion, graph construction, migrations, and basic CLI now. Before implementing Stage 2 and Stage 3, reconcile the remaining spec inconsistencies and add the missing persistence/provenance fields.

## 2) Issues Resolved Since Prior Reviews

- `architecture.md`, `dependencies.md`: The async SQLite concern from review 1.2 is mostly resolved. The updated design chooses `tokio-rusqlite`, adds it to dependencies, and explains the dedicated SQLite thread model.

- `architecture.md`, `database-schema.md`, `implementation-sequence.md`: Schema migrations are now specified through a `schema_version` table and startup migration flow. This addresses the migration gap from review 1.1.

- `architecture.md`: The database is now explicitly a project artifact rather than a disposable cache. This clarifies the expected durability of expensive LLM-derived data.

- `architecture.md`, `database-schema.md`: Composite `input_hash` and run manifest concepts were added. This is a substantial improvement over raw RFC `content_hash` incrementality.

- `cli-interface.md`, `implementation-sequence.md`: `map --protocol <NAME>` now exists and populates `protocol_rfcs`. This fixes the previously broken documented workflow of `map` -> `model` -> `analyze`.

- `cli-interface.md`: `clear` now requires confirmation unless `--yes` is passed, and the cascade behavior is described at a high level.

- `data-model.md`, `pipeline-stages.md`: Graph edge direction is now explicit, including the meaning of `Obsoletes`, `Updates`, normative references, informative references, and cross-references.

- `data-model.md`: The duplicate cross-reference section fields inside `EdgeKind::CrossReference` were removed. Section detail is now carried only on `DepEdge`.

- `pipeline-stages.md`: The depth semantics are clearer: depth 0 means seed RFCs only, depth 1 means direct references, and metadata updates/obsoletes are always followed.

- `llm-integration.md`, `pipeline-stages.md`: The flawed chunked state-machine extraction strategy was removed from the pipeline design. The new strategy prefers summarization and skips oversized clusters if they still do not fit.

- `pipeline-stages.md`: Stage 3 now persists category results incrementally and ranks primarily by severity tier before confidence. This addresses two significant concerns from review 1.2.

- `pipeline-stages.md`: Lead deduplication is now based on overlapping section references, normalized technique names, and category rather than only section plus category.

- `pipeline-stages.md`: Section-selection keywords are now defined for all ten attack categories, and the overly broad `MUST` keyword was removed from `MissingValidation`.

- `llm-integration.md`: `model_context_window` was added, configuration validation ranges are documented, and token budgeting now uses a safety margin.

- `llm-integration.md`: The prompts now acknowledge RFC text as untrusted input and use explicit `<<<RFC_SECTION...>>>` delimiters.

- `architecture.md`, `database-schema.md`: Graceful shutdown and an `interrupted` run status are now specified.

- `dependencies.md`: `Cargo.lock` and minimum supported Rust version are now specified.

- `implementation-sequence.md`: Composite input hash design was moved into Phase 1.3, which is the right place because it affects table design and stage APIs.

- `implementation-sequence.md`, `docs/specs/test-fixtures/`: Regression validation with known-CVE fixtures has been added. This directly addresses the prior request for semantic evaluation beyond mocked response-shape tests.

## 3) Remaining Concerns and New Gaps

### Cross-Spec Inconsistencies

- `implementation-sequence.md` still says Phase 5.3 should handle context overflow with "chunking + merging." This conflicts with `llm-integration.md` and `pipeline-stages.md`, which explicitly reject chunked extraction and specify summarize-or-skip.

- `architecture.md` says connection initialization enables `PRAGMA journal_mode = WAL` and `PRAGMA busy_timeout = 5000`, but `database-schema.md` only lists `PRAGMA foreign_keys = ON` under connection setup. The database spec should be the source of truth and include all required pragmas.

- `cli-interface.md` configuration example does not include `model_context_window`, but `llm-integration.md` makes it a validated LLM setting. Implementers will otherwise miss a required field or invent a default.

- `architecture.md` says Stage 3 input hash includes category list, while `database-schema.md` says category filter. Both likely mean the same thing, but the exact canonicalization matters for cache hits.

- `architecture.md` still describes Stage 3 output as "Security Leads (JSON report)" and `pipeline-stages.md` says the final report is JSON. The human-readable output concern from review 1.2 remains unaddressed.

### Persistence and Resume Semantics

- `pipeline-stages.md` says per-category completion is tracked in the run manifest, but `database-schema.md` has no field or companion table that can represent per-category progress. A JSON blob could be added, but that needs to be specified.

- `state_machines` still uses `UNIQUE(protocol, name)`. That remains too weak for prompt/model/versioned runs and too strong for multiple runs that produce different state machines with the same name. The table has `content_hash`, but it is not part of the unique key.

- `security_leads` still uses random UUIDs as the only primary identity. That makes reproducible comparison across runs hard. There is no deterministic lead fingerprint or run ID association.

- `analysis_runs` is not linked from `state_machines` or `security_leads`. Without `run_id`, it will be hard to answer which run produced which output, especially after prompt/model changes.

- `analysis_runs.model_used` is `NOT NULL`, but Stage 1 map may not use an LLM except for optional ambiguous reference resolution. The schema should define what value is stored for non-LLM runs.

- The specs say partial results are preserved after interruption, but they do not define whether interrupted outputs are included in reports, hidden by default, or resumed into the same run versus a new run.

### Cache-Key Completeness

- Composite hashes are a good addition, but they still omit important factors in some places: temperature, max output tokens, model context window, section-selection algorithm version, summarization strategy, parser version, code version, schema version, and prompt schema version.

- Stage 1 hash semantics remain tricky. `database-schema.md` says Stage 1 hash includes RFC content hashes of seed RFCs plus depth and `normative_only`, but remote RFC content hashes are only known after fetching. If the cache is considered durable, the spec needs a refresh policy that says when remote RFCs are revalidated.

- Stage 2 and Stage 3 cache keys mention prompt version, but no prompt version constants or schema version fields are present in `data-model.md` or the LLM prompt spec beyond prose.

- The `analysis_runs` manifest stores filters and RFC lists as JSON text, but the specs do not define canonical ordering. Without sorted RFC lists and sorted filter lists, equivalent runs can produce different hashes.

### Data Model Gaps Not Yet Addressed

- `data-model.md` still uses `RfcNumber(pub u32)` only. If v1 is intentionally RFC-only, that limitation should be explicit. If not, BCP/STD aliases, Internet-Drafts, and non-RFC specs remain unsupported.

- `Section.number` is still required and unique in the schema. Appendices, unnumbered sections, anchor-only sections, figures, tables, and XML `pn` values remain underspecified.

- `CrossRef` still lacks extraction method, confidence, raw label, and source span. This weakens graph auditability, especially for regex and optional LLM-resolved references.

- `SecurityLead` still lacks explicit evidence fields, review status, evidence strength, implementation assumptions, and structured confidence calibration. The ranking formula improved, but the underlying confidence field is still model self-report unless otherwise specified.

- `ReportMetadata` still lacks prompt version, input hash, run ID, code version, provider, and fixture/evaluation information. Those fields are important for reproducible reports.

### LLM Integration Risks

- `llm-integration.md` still says `governor` enforces `max_concurrent_requests`, while also saying a semaphore limits in-flight requests. Concurrency and rate limiting are different controls. There are still no requests-per-minute or tokens-per-minute settings.

- Raw LLM responses are still logged on parse failure. The previous logging/data-retention concern remains, especially because prompts may contain large RFC excerpts and generated security leads.

- The prompt injection defense is better, but the statement that `<<<` "cannot appear in standard RFC formatting" is too strong. RFC text is untrusted data and can contain arbitrary character sequences. The implementation should generate per-request random delimiters or escape delimiter occurrences in source text.

- The Stage 2 prompt still asks the model to include states and transitions "mentioned or implied by the specification." That can invite speculation. For auditability, the prompt should require each inferred transition to mark whether it is directly stated or inferred.

- The summarize-to-fit strategy is underspecified. It is unclear whether summarization is LLM-based, extractive, heuristic, cached, versioned, or included in the input hash. Summarization can remove exactly the edge cases security analysis needs.

- OpenAI-compatible support remains broad in prose, but provider differences are not fully addressed: Azure endpoint paths, local model JSON mode behavior, usage accounting, and context-window limits may differ.

### Graph and Scope Semantics

- `pipeline-stages.md` says all discovered RFCs are fetched and there are no boundary nodes. That simplifies storage, but it means graph output hides references beyond the chosen depth. This is acceptable for v1 only if the graph clearly labels itself as the ingested subgraph, not the complete dependency graph.

- `normative_only` skips informative references but appears not to skip inline cross-references. Inline cross-references do not carry normative/informative status, so their traversal policy needs to be explicit.

- Reverse relationships (`updated_by`, `obsoleted_by`) are still not clearly part of expansion. The data model stores them, but Stage 1 only says `obsoletes` and `updates` metadata are followed.

- `dep_edges.target_rfc` remains `NOT NULL`, so internal cross-references cannot be represented as graph edges unless source and target are the same RFC. That may be fine, but the spec should state whether internal cross-references are stored as self-edges or only in `cross_refs`.

### CLI and Output UX

- `graph <TARGET>` remains ambiguous between protocol names and RFC numbers. This is lower severity than before, but explicit `--protocol` and `--rfc` modes would avoid surprising behavior.

- `analyze` has no `-o/--output` or `--format`, while `run` does. If users run stages separately, it is unclear where the final report goes.

- No `--dry-run`, `--estimate-cost`, `--offline`, `--refresh`, `--force-recompute`, or `--cache-only` controls are specified. These are not all required for v1, but cost estimation and refresh policy are important for LLM-backed analysis.

- The CLI says config values can be overridden by CLI flags "where applicable," but it does not define LLM override flags. This is acceptable if intentional, but the phrase is too vague for implementation.

### Database Details

- `tokio-rusqlite` is now specified, but `database-schema.md` still says the project "uses `rusqlite` with bundled" without explaining that application access goes through `tokio-rusqlite`. This is minor but worth aligning.

- `schema_version` has no primary key or invariant. A single-row table should define whether multiple rows are allowed as migration history or whether `version` is unique/current.

- Cascading clear behavior is described in CLI prose, but the schema has no `ON DELETE CASCADE`. If cascade is implemented manually, the required delete order should be specified.

- Severity remains stored as text only. Since ranking is application-side this is acceptable, but report queries by severity order will need a mapping.

### Test Fixture and Benchmark Concerns

- The new CVE fixtures are valuable, but they reference a talk as provenance without pinned source material, dates, links, or validation artifacts. If these become release gates, the evidence should be stable and independently reviewable.

- Some fixtures represent implementation failures to follow clear requirements, not necessarily ambiguous or vulnerable RFC text. For example, TLS certificate validation disabled in applications is a code-level anti-pattern derived from a spec requirement. The analyzer can surface the requirement, but the fixture should not imply the RFC itself is vulnerable.

- The regression target says "4 of 6 known CVEs should produce hits or near misses," but there are four fixture files and six CVEs only because the TLS fixture counts three application CVEs. That is reasonable, but the denominator should be explicit in the validation doc.

- "Near miss" is subjective. The fixture spec should define who adjudicates it, how section/category adjacency is scored, and whether the result is deterministic enough for CI.

- The fixtures do not define expected machine-readable assertions. They are useful manual benchmarks, but they are not yet ready as automated regression tests.

## 4) Suggestions for Improvement

1. Reconcile the spec inconsistencies before coding Stage 2: remove "chunking + merging" from `implementation-sequence.md`, add WAL/busy timeout to `database-schema.md`, and add `model_context_window` to the CLI config example.

2. Add `run_id` foreign keys to `state_machines` and `security_leads`, or add an explicit artifact/run association table. This is the cleanest way to preserve provenance across model and prompt changes.

3. Add a `run_work_items` table for resumability. Suggested fields: `run_id`, `stage`, `work_item_kind`, `work_item_key`, `input_hash`, `status`, `started_at`, `completed_at`, `tokens_used`, `error`.

4. Expand the cache key specification to include prompt schema version, parser version, section-selection version, summarization version, model parameters, code version, and canonical JSON ordering rules.

5. Define prompt version constants in the LLM spec and persist them in state machines, leads, reports, and run manifests.

6. Make lead identity reproducible by adding a deterministic fingerprint derived from protocol, category, normalized technique name, affected RFC sections, and evidence quotes.

7. Add evidence and review fields to `SecurityLead`: `evidence_strength`, `evidence_kind`, `review_status`, `spec_grounded`, `implementation_assumption`, and possibly separate `model_confidence` from final confidence.

8. Specify the summarize-to-fit mechanism. If it uses LLM summarization, it needs its own prompt version, cache key, provenance record, and validation strategy. If it is heuristic/extractive, define the heuristic.

9. Replace fixed prompt delimiters with generated delimiters or escape delimiter occurrences in RFC text before prompt assembly.

10. Add a logging policy: raw prompts and responses should be stored only at debug/audit level or in an explicit artifact table, not emitted to normal logs on parse failure.

11. Decide whether v1 is RFC-only. If yes, state that BCP/STD aliases, Internet-Drafts, errata ingestion, and non-RFC specs are out of scope. If no, change the document identity model now.

12. Relax section identity before implementation. Use internal section IDs and allow section number to be optional; include anchor, `pn`, title path, and kind (`section`, `appendix`, `figure`, `table`, `paragraph`) where available.

13. Clarify cross-reference traversal: whether inline refs are followed under `normative_only`, whether internal refs become self-edges, and whether reverse update/obsolete relationships are crawled.

14. Add output options for `analyze` and `run`: at least `--format json|text|markdown` and `-o/--output`. JSON can remain default, but human triage should not require custom tooling.

15. Add a cost/plan mode before LLM execution. A simple `--dry-run` that estimates RFC count, section count, LLM calls, and approximate tokens would avoid expensive surprises.

16. Make regression fixtures more precise. Add expected RFCs, expected section identifiers, accepted categories, accepted keywords/concepts, and a machine-readable scoring file.

17. Separate "spec-level weakness" fixtures from "implementation failed to follow spec" fixtures. Both are useful, but they validate different tool behaviors.

18. Update `ReportMetadata` to include run ID, input hash, prompt version, model parameters, provider, code version, and generated report format.

19. Add requests-per-minute and tokens-per-minute settings, even if the first implementation only enforces concurrency. Provider rate limits will otherwise be confused with local parallelism.

20. Add a refresh policy for RFC content. RFCs are normally stable, but fetched metadata and index information can change. The spec should define `--refresh`, TTL, or "never refetch unless forced."

## 5) Readiness Assessment

The specs are partially ready for implementation.

Ready now:

- Foundation modules, configuration loading and validation
- Database initialization, migrations, and the `tokio-rusqlite` access layer
- RFC fetch/cache/store flow
- Basic XML/text parsing with fixtures
- Dependency graph model, edge direction, persistence, and DOT/JSON export
- CLI `map --protocol`, `show`, and guarded `clear`

Not quite ready:

- Stage 2 protocol modeling, because overflow summarization, prompt versioning, state-machine provenance, and cache keys need firmer contracts.
- Stage 3 security analysis, because resumability, lead identity, evidence modeling, report provenance, and fixture scoring are not yet specified enough for reliable implementation.
- Final reporting UX, because JSON-only output leaves human triage underdesigned.

Implementation recommendation: start Phase 1 through Phase 3 after reconciling the small cross-spec inconsistencies. Treat Phase 4 as a thin LLM client plus prompt-version infrastructure, not full analysis. Before Phase 5 begins, update the data model and schema for run/work-item provenance, prompt versions, deterministic fingerprints, and evidence fields.

Readiness verdict: **not fully ready for end-to-end implementation, but ready for foundation and graphing work.** The remaining gaps are solvable and mostly specification hygiene, but they should be fixed before the LLM stages harden into code.
