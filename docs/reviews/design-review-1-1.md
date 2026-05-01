# Design Review 1.1

## 1) Executive Summary

The specs describe a coherent three-stage tool: ingest RFCs, build a dependency graph, derive protocol state machines, then use LLM analysis to produce ranked security leads. The module layout, cache-first architecture, typed domain model, and staged implementation sequence are good foundations for an incremental Rust implementation.

The largest design risk is that the tool's highest-value outputs depend on ambiguous, non-deterministic intermediate artifacts without enough provenance, validation, or reproducibility controls. Stage 2 mechanism clustering and state-machine extraction drive Stage 3 security analysis, but the specs do not yet define strong contracts for section selection, state-machine merge semantics, confidence scoring, prompt/model versioning, or human/audit review. This can make results hard to trust, compare, debug, or reproduce.

The second major risk is data and cache correctness. Several specs refer to `content_hash`-based incrementality, but they do not define canonical input hashes for graph expansion, parsed sections, prompt templates, model settings, mechanism filters, attack categories, or dependency depth. That makes stale or cross-contaminated results likely once users rerun with different options.

The third major risk is RFC parsing and graph semantics. RFC metadata, reference types, section identifiers, status relationships, updates/obsoletes chains, BCP/STD aliases, errata, Internet-Drafts, and inline references are more complex than the current data model suggests. The current design is implementable, but it may produce misleading dependency graphs unless edge direction, edge meaning, document identity, and reference provenance are specified more rigorously.

Overall recommendation: proceed with the staged implementation, but tighten the contracts before building the LLM-heavy stages. Add explicit run manifests, versioned prompt schemas, deterministic cache keys, stronger database constraints, provenance fields, parser acceptance criteria, and a small evaluation harness before treating security leads as actionable findings.

## 2) Strengths

- `architecture.md`: The staged map -> model -> analyze pipeline is easy to reason about and gives clear implementation boundaries. Persisting each stage in SQLite is a practical choice for a local analysis tool.

- `architecture.md` and `implementation-sequence.md`: The module decomposition is sensible. Separating fetch/parse, graph construction, LLM client, pipeline stages, persistence, and reporting should keep testing tractable.

- `pipeline-stages.md`: The design recognizes that different stages have different concurrency profiles. Fetching, LLM calls, and per-mechanism work can all be parallelized while the high-level pipeline remains sequential.

- `database-schema.md`: SQLite is a good default for local reproducibility and incremental runs. The schema already captures raw RFCs, parsed sections, cross-references, dependency edges, state machines, leads, and analysis runs.

- `llm-integration.md`: The OpenAI-compatible client abstraction is valuable. It avoids coupling the tool to one provider and makes local/offline model experiments possible.

- `llm-integration.md`: Structured JSON responses, parsing validation, retry handling, and partial-result tolerance are all appropriate for LLM-backed extraction.

- `data-model.md`: The core model uses explicit types for RFC numbers, statuses, references, graph edges, state machines, and security leads. This is a good starting point for avoiding stringly typed pipeline code.

- `implementation-sequence.md`: The phase ordering is pragmatic. It builds ingestion, graphing, LLM plumbing, modeling, and analysis in a sequence that can produce useful milestones.

- `dependencies.md`: The chosen Rust crates are mostly conventional and well suited to the task: `clap`, `serde`, `reqwest`, `tokio`, `quick-xml`, `rusqlite`, `petgraph`, `tracing`, and `thiserror`.

## 3) Concerns and Gaps

### Cache Correctness and Reproducibility

- `architecture.md`, `database-schema.md`, `pipeline-stages.md`: Incrementality is described as `content_hash`-based, but the hash inputs are underspecified. Stage 2 results depend on selected RFCs, selected sections, prompt text, prompt schema, model name, model parameters, context-window chunking, mechanism filters, and parser behavior. Stage 3 results also depend on attack categories, severity filters, state-machine summaries, section-selection heuristics, and prompt versions. A raw RFC hash alone is not enough to decide whether derived artifacts are valid.

- `database-schema.md`: `state_machines` has `UNIQUE(protocol, name)`, which can overwrite or block distinct runs with different RFC sets, mechanisms, prompt versions, model settings, or dependency depths. The same problem exists in `security_leads`, where UUID primary keys do not provide natural deduplication or repeatability.

- `database-schema.md`: `analysis_runs` tracks stage, model, tokens, status, and error, but not the full run inputs. It should capture seed RFCs, depth, normative-only flag, mechanism filters, category filters, min severity, prompt versions, code/schema version, model parameters, and cache key hashes.

- `llm-integration.md`: The specs do not define deterministic model settings beyond low temperature. Even at low temperature, outputs can vary across model versions and providers. There is no plan for storing raw prompts, raw responses, response IDs, provider metadata, or model revision identifiers.

- `dependencies.md`: Cargo uses broad major versions. That is fine in `Cargo.toml`, but reproducibility depends on committing `Cargo.lock` for a binary application. The specs do not mention this.

### RFC Identity, Metadata, and Scope

- `data-model.md`: `RfcNumber(pub u32)` is too narrow if the long-term scope includes Internet-Drafts, BCPs, STDs, FYIs, RFC subseries aliases, or non-RFC protocol specs. Even for RFC-only mode, BCP and STD aliases matter because references often cite them as stable identifiers.

- `data-model.md` and `database-schema.md`: RFC status is simplified. RFC Editor status, IETF stream, document category, errata status, obsoleted/updated relationships, and "not issued" or "unknown" records can all affect analysis. `RfcStatus` may not map cleanly to actual index metadata.

- `pipeline-stages.md`: Expansion follows obsoletes/updates, formal references, and inline cross-references, but the intended meaning of "dependency" is not defined. An RFC that updates another, obsoletes another, normatively references another, or merely mentions another should not necessarily be treated as the same kind of dependency for attack-surface reasoning.

- `pipeline-stages.md`: The depth model is ambiguous. Does depth count only followed reference edges, all edge types, or expansion rounds from seeds? Are updates/obsoletes followed regardless of `normative_only`? Are reverse edges such as `updated_by` and `obsoleted_by` followed?

- `architecture.md` and `cli-interface.md`: Protocol identity is weak. `map` takes RFCs without a protocol name, while `model` and `analyze` take a protocol name. The specs do not clearly define how RFCs become associated with protocols unless `run` is used.

### Parsing and Reference Extraction

- `pipeline-stages.md`: XML parsing assumes RFC 7991+ XML availability and high precision from `<xref>`, but older RFC XML, generated XML, references to anchors, bib references, `relref`, `derivedContent`, and non-section targets may need handling. The specs do not define fallback behavior for malformed or partial XML.

- `pipeline-stages.md`: Plain-text parsing is described as regex-based. RFC text formatting varies significantly across decades. Section headings, appendices, page headers/footers, reference sections, bracket labels, line wrapping, and multi-line citations can break simple regexes.

- `data-model.md`: `Section.number` as a string supports values like `3.4.1`, but the model does not discuss appendices (`A`, `A.1`), unnumbered sections, numbered paragraphs, figures, tables, ABNF blocks, examples, or XML anchors that are not numeric sections.

- `database-schema.md`: `sections` uses `UNIQUE(rfc_number, section_num)`. This can fail for unnumbered sections or repeated labels, and it ignores anchors as potentially stable identifiers.

- `data-model.md`: `CrossRef.context` as a single surrounding sentence may be insufficient for line-wrapped RFC text, references embedded in lists, or references that rely on previous sentences. It also lacks confidence, extraction method, and raw span offsets.

- `pipeline-stages.md`: Ambiguous reference resolution via LLM is "optional" and "used sparingly," but no threshold defines when ambiguity exists, when to call the LLM, or how to validate/record its confidence.

### Graph Semantics and Storage

- `data-model.md`: `DepEdge` duplicates section fields while `EdgeKind::CrossReference` also carries source and target section data. This creates two sources of truth.

- `pipeline-stages.md`: Edge direction is not explicitly defined. For a normative reference from RFC A to RFC B, is the edge A -> B? For "RFC A updates RFC B", is the edge A -> B or B -> A? Traversal and graph summaries depend on this.

- `database-schema.md`: `dep_edges.target_rfc` is `NOT NULL`, but `cross_refs.target_rfc` allows `NULL` for internal refs. This means internal cross-references cannot become graph edges unless represented separately, but `pipeline-stages.md` says cross-ref edges include target section numbers.

- `database-schema.md`: `dep_edges` requires target RFCs to exist in `rfcs`. This prevents storing edges to referenced RFCs that were discovered but not fetched because of depth limits, fetch failures, or excluded informative references. That may hide boundary nodes from graph output.

- `pipeline-stages.md`: No graph pruning or cycle handling policy is specified. RFC dependency graphs can contain cycles through updates, extensions, and references. This affects transitive dependency queries, depth-limited crawling, and graph summaries.

- `database-schema.md`: Foreign keys are declared, but the spec does not state that `PRAGMA foreign_keys = ON` must be enabled on every SQLite connection.

### LLM Integration and Output Trust

- `llm-integration.md`: The OpenAI-compatible chat completions target is broadly useful, but compatibility varies. Azure OpenAI, OpenAI Responses API, Ollama, vLLM, and llama.cpp differ in auth, endpoint paths, JSON mode support, token usage fields, streaming behavior, and error shapes.

- `llm-integration.md`: `governor` is described as enforcing `max_concurrent_requests`, but concurrency limiting is actually a semaphore concern. Rate limits also need requests-per-minute and tokens-per-minute controls, which are not present in the config.

- `llm-integration.md`: Context-window handling references `model_context_window`, but the config does not define it. Relying on a model-name lookup table is not specified either.

- `llm-integration.md`: Chunked extraction says "continue from where the previous part left off." Independent chunking with continuation prompts can create hidden state across calls and unreliable merges. It is also unclear whether each chunk includes global instructions, already extracted states, or previously seen canonical names.

- `pipeline-stages.md`: State-machine merge is defined as union of states and transitions deduplicated by name. Names are LLM-generated and unstable. This can merge unrelated states with the same generic name (`START`, `IDLE`, `ERROR`) or fail to merge equivalent states with different names.

- `pipeline-stages.md`: Validation logs warnings for orphan or unreachable states but does not fail. For downstream security analysis, invalid state machines can produce false positives or false negatives. There should be a quality gate or confidence downgrade.

- `llm-integration.md`: Prompt templates ask the LLM to be "thorough" and include implied behavior. This may encourage speculative output. For a security analyzer, the system should distinguish spec-grounded leads from conjectures and require traceable evidence.

- `pipeline-stages.md`: Stage 3 deduplicates leads by same RFC section and attack category. That is too coarse. Multiple distinct vulnerabilities can exist in one section/category, and the same vulnerability can span multiple sections or RFCs.

- `data-model.md`: `SecurityLead.confidence` has no calibration definition. It is unclear whether this is model self-confidence, evidence strength, parser confidence, or pipeline confidence.

- `data-model.md`: `SecurityLead` lacks fields that would help triage: affected protocol role, exploit preconditions as structured data, evidence quality, false-positive rationale, related RFC requirements (`MUST`/`SHOULD`), implementation assumptions, and validation status.

### Security Analysis Quality and Safety

- `pipeline-stages.md`: Section selection uses keyword heuristics. Security-relevant behavior often appears outside obvious keywords, especially in message formats, interoperability notes, extension registries, error handling, timers, fallback behavior, and IANA considerations.

- `pipeline-stages.md`: Security Considerations are always included, but they are often broad, incomplete, or intentionally non-normative. The pipeline may overweight them relative to normative protocol behavior.

- `llm-integration.md`: There is no threat model for the analyzer itself. RFC text is untrusted input to the LLM prompt. Prompt injection from RFC-like local fixtures or external documents could influence analysis unless prompts delimit source text and instruct the model to treat it as data.

- `llm-integration.md`: Raw LLM responses are logged on parse failure. These can include long RFC excerpts, generated vulnerability details, or provider-specific metadata. The logging policy should define redaction and verbosity controls.

- `pipeline-stages.md`: The report describes outputs as "ranked vulnerability leads," but the specs do not define review status, evidence grading, or disclaimers that these are hypotheses rather than confirmed vulnerabilities.

### CLI and User Workflow

- `cli-interface.md`: The CLI says all config values can be overridden by flags, but only a few flags are specified. There are no flags for LLM model, API base, max concurrency, temperature, request rate, context window, cache mode, offline mode, or prompt version.

- `cli-interface.md`: `map` stores parsed RFCs and dependency graphs, but has no protocol argument. `model <PROTOCOL>` then needs to know which RFCs belong to the protocol. The `protocol_rfcs` table exists, but no command behavior populates it except possibly `run`, and that is not specified.

- `cli-interface.md`: `graph <TARGET>` accepts protocol name or RFC number, which creates ambiguity for numeric protocol names or protocol names that resemble RFC numbers. The command should probably have explicit `--protocol` and `--rfc` modes.

- `cli-interface.md`: `clear` lacks safeguards. Clearing `all` by default is risky, especially if the database contains expensive LLM results. It should probably require confirmation unless `--yes` is supplied.

- `cli-interface.md`: There is no `--offline` or `--no-llm` mode. These would be useful for testing, reproducibility, and environments without network/API access.

- `cli-interface.md`: Output behavior is only specified for `run`. It is unclear where `analyze` writes the final report, whether `model` prints summaries, and whether all commands have machine-readable output modes.

### Database and Migration Design

- `database-schema.md`: The schema is presented as initial SQL, but migrations are not specified. `db/schema.rs` is mentioned, but there is no `schema_version` or migration table.

- `database-schema.md`: JSON arrays in columns are pragmatic, but they limit queryability. That may be acceptable for `obsoletes` and `updates`, but `rfc_references`, `prerequisites`, and `entities_involved` will be hard to filter or join later.

- `database-schema.md`: Large `text` fields in `sections` and large JSON blobs in `state_machines` are uncompressed while raw RFC content is compressed. This can grow quickly for broad dependency crawls.

- `database-schema.md`: No deletion cascade behavior is specified. Clearing RFCs, graphs, or analysis can leave dangling sections, cross-refs, state machines, or leads unless delete order is carefully implemented.

- `database-schema.md`: Severity is stored as text and indexed, but severity ordering is application-defined. Sorting by severity in SQL will not work without a numeric rank or explicit mapping.

- `database-schema.md`: There are no indexes on `state_machines(protocol)`, `protocol_rfcs(rfc_number)`, or `analysis_runs(protocol, stage, started_at)`, all of which are likely query paths.

### Implementation Sequence and Testing

- `implementation-sequence.md`: LLM integration starts before the pipeline has evaluation fixtures for correctness. Mocking response shapes is necessary but not sufficient; the project needs golden semantic fixtures for parser output, graph edges, state machines, and security leads.

- `implementation-sequence.md`: Incremental caching is deferred to Phase 7, but cache keys affect table design and stage APIs. Deferring this may force schema and API churn after core pipeline code is written.

- `implementation-sequence.md`: Real RFC fetch tests are ignored, which is reasonable for CI, but there is no plan for pinned local RFC fixtures that represent old text RFCs, modern XML RFCs, errata-relevant RFCs, appendix-heavy RFCs, and update/obsolete chains.

- `implementation-sequence.md`: There is no explicit performance/scalability target. A depth-2 crawl from a large protocol can involve many RFCs and thousands of sections. The implementation needs budget estimates for DB size, memory usage, LLM calls, token cost, and runtime.

- `dependencies.md`: `reqwest` enables `gzip` but not `rustls-tls` or explicit TLS configuration. Depending on defaults may be fine, but the portability story should be deliberate.

- `dependencies.md`: Edition 2024 may be appropriate, but it raises the minimum toolchain. The spec should state the minimum supported Rust version.

## 4) Suggestions for Improvement

1. Define a run manifest and cache-key model before implementing Stage 2 and Stage 3. Include seed RFCs, effective RFC set, depth, normative-only flag, parser version, prompt version, model/provider settings, mechanism/category filters, section-selection algorithm version, and code/schema version. Store the manifest and derived input hashes in `analysis_runs`.

2. Add prompt and schema versioning. Each LLM task should have a stable task name, prompt version, expected JSON schema version, and parser version. Store these alongside state machines and security leads.

3. Store raw LLM request/response records in a separate table or artifact store with redaction controls. At minimum, preserve prompt hash, response hash, provider, model, created timestamp, token usage, finish reason, and parse status. This is essential for debugging and reproducibility.

4. Strengthen protocol assignment semantics. Either make `map` require or optionally accept `--protocol`, or add an explicit command such as `assign <PROTOCOL> <RFCS>...`. Define exactly when `protocol_rfcs` is populated.

5. Clarify graph edge direction and traversal policy. Document each edge type with source, target, whether it is followed during expansion, whether `normative_only` affects it, and how it contributes to graph summaries.

6. Add a `DiscoveredRfc` or boundary-node concept. The graph should be able to represent referenced RFCs that are outside crawl depth, unavailable, excluded, or failed to fetch, rather than silently omitting edges.

7. Expand document identity beyond `RfcNumber` or explicitly constrain v1 to RFC-only analysis. If v1 is RFC-only, document that BCP/STD aliases, Internet-Drafts, and non-RFC specs are out of scope.

8. Rework section identity. Use a stable internal section ID plus optional section number, anchor, title path, and XML `pn`. Avoid requiring numeric section numbers to be unique and present.

9. Add provenance fields to extracted references and graph edges: extraction method (`xml`, `text_regex`, `llm`), confidence, source span/offset if available, raw label, and whether the reference came from formal references, inline text, metadata, or index data.

10. Separate formal references from inline cross-references in graph semantics. Inline mentions often do not imply dependency; formal normative references usually do. Treat them differently in expansion defaults and reporting.

11. Define parser acceptance criteria and fixture coverage. Include old plain-text RFCs, modern XML RFCs, appendices, ABNF-heavy RFCs, references split across lines, update/obsolete chains, and RFCs with unusual section numbering.

12. Add quality gates for state machines. Do not silently pass invalid state machines into Stage 3 without marking their quality. Consider storing validation warnings, extraction confidence, source coverage, and whether the state machine passed structural checks.

13. Make state-machine merging provenance-aware. Deduplicate states and transitions by normalized names plus source references and semantic fingerprints, not raw LLM names alone. Preserve aliases when the model uses different names for the same state.

14. Make Stage 3 lead deduplication less coarse. Use evidence overlap, normalized technique name, affected entities, prerequisites, and section references. Do not merge solely by section plus category.

15. Add an evidence model to `SecurityLead`. Require each lead to distinguish quoted normative text, inferred behavior, implementation assumption, and speculative risk. Add a `validation_status` or `review_status` field.

16. Define confidence calibration. Consider separate fields for `model_confidence`, `evidence_strength`, and final `confidence`, or document how the single score is computed.

17. Add cost and runtime controls. Include `--max-rfcs`, `--max-sections`, `--max-llm-calls`, `--max-tokens`, `--dry-run`, and an estimate mode before running expensive analysis.

18. Add offline and cache modes. Useful modes include `--offline`, `--refresh`, `--no-llm`, `--use-cache-only`, and `--force-recompute`.

19. Add explicit LLM rate-limit settings for requests per minute and tokens per minute. Keep semaphore concurrency separate from provider rate limiting.

20. Define logging and data retention policy. Avoid logging full raw LLM responses at normal verbosity, especially for long prompts and security findings. Provide debug artifacts only when requested.

21. Introduce schema migrations from the start. Add a `schema_migrations` table or use a migration crate. This will be cheaper than retrofitting migrations after Phase 3 or Phase 4.

22. Move incrementality earlier in the implementation sequence. The stage APIs and persistence model should be designed around deterministic inputs and cache keys before Stage 2/3 implementation.

23. Commit `Cargo.lock` and state the minimum supported Rust version. This matters for a binary tool with broad dependency usage and edition 2024.

24. Add an evaluation harness. Even a small harness that compares parser output, graph edges, state-machine JSON, and lead extraction against curated fixtures will catch regressions that unit tests with mocked LLM responses will miss.

25. Define output contracts. Specify JSON schemas for graph export, state-machine export, security reports, and machine-readable CLI output so downstream tools can consume results safely.

## 5) Questions for the Team

1. Is v1 strictly limited to numbered RFCs, or should it support BCP/STD aliases, Internet-Drafts, and non-RFC protocol specifications?

2. What is the intended meaning of a dependency edge for security analysis? Should updates, obsoletes, normative references, informative references, and inline cross-references all affect protocol scope?

3. Should `map` associate RFCs with a protocol, or is protocol assignment intended to happen only through `run`?

4. Are reverse relationships such as `updated_by` and `obsoleted_by` in scope for crawling from an older seed RFC?

5. What should happen when a referenced RFC is outside the requested depth, unavailable, or excluded by `normative_only`? Should it appear as a boundary node?

6. How reproducible do security reports need to be across runs, model versions, and providers?

7. Will users need to audit exact prompts and raw LLM responses, or is the final structured report considered sufficient?

8. Should LLM-derived state machines be treated as authoritative pipeline inputs, or as advisory artifacts that require validation before Stage 3?

9. What minimum evidence should a security lead require before appearing in the report?

10. Should the report explicitly label leads as hypotheses until confirmed by human review or implementation testing?

11. What are acceptable false-positive and false-negative tradeoffs for the first version?

12. How should the tool estimate and cap LLM cost before running a large protocol analysis?

13. Should the database be considered a durable project artifact, or an implementation cache that can be deleted and regenerated?

14. Will multiple users or concurrent processes access the same SQLite database, or is single-process local use assumed?

15. What is the expected maximum crawl size for v1: tens of RFCs, hundreds, or more?

16. Do we need to support fully offline operation after initial RFC ingestion?

17. Which output is the primary user-facing artifact: JSON report, graph export, SQLite database, or CLI summaries?

18. Should security findings include exploitability guidance, or should the tool avoid operational exploit details and focus on protocol-level risk?

19. What standards should be used for severity? The current enum is simple, but should it map to CVSS-like concepts, project-specific risk, or evidence-weighted priority?

20. What is the review path for changing prompt templates after reports have already been generated?
