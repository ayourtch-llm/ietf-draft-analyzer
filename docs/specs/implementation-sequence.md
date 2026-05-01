# Implementation Sequence

## Phase 1: Foundation

### 1.1 Error handling and configuration
- `src/error.rs` — `RfcAnalyzerError` enum with `thiserror`
- `src/config.rs` — `Config` struct, TOML parsing, env var resolution
- Write unit tests for config loading (missing env var, bad TOML, defaults)

### 1.2 Core data model
- `src/rfc/model.rs` — `Rfc`, `Section`, `CrossRef`, `Reference`, enums
- Pure data structures, no logic yet

### 1.3 Database layer
- `src/db/schema.rs` — table creation SQL, `initialize_db()` function
- `src/db/rfc_store.rs` — insert/get/exists for `rfcs`, `sections`, `cross_refs`
- Write tests using in-memory SQLite (`:memory:`)

**Milestone**: Can create DB, store and retrieve RFC structs.

## Phase 2: RFC Ingestion

### 2.1 RFC fetcher
- `src/rfc/fetcher.rs` — async download with XML-preferred fallback to text
- Polite rate limiting (configurable delay between requests)
- Integration with DB cache (skip fetch if content_hash matches)

### 2.2 XML parser
- `src/rfc/parser_xml.rs` — parse RFC 7991+ XML into `Rfc` struct
- Extract sections, cross-references (`<xref>`), references
- Snapshot tests with `insta` on real RFC XML excerpts

### 2.3 Plain text parser
- `src/rfc/parser_text.rs` — regex-based parsing of classic RFC format
- Section header detection, reference extraction
- Snapshot tests on real RFC text excerpts

### 2.4 RFC index
- `src/rfc/index.rs` — fetch and parse the RFC index for metadata lookup
- Used for resolving RFC numbers to titles without fetching full documents

### 2.5 Wire up CLI `map` command
- `src/cli.rs` — clap definitions (start with `map` and `show` commands)
- `src/main.rs` — dispatch to fetcher + parser + DB store

**Milestone**: `rfc-analyzer map 9293 --depth 1` fetches and parses TCP RFCs.

## Phase 3: Dependency Graph

### 3.1 Graph model and builder
- `src/graph/model.rs` — `RfcNode`, `DepEdge`, `EdgeKind`
- `src/graph/builder.rs` — build `StableDiGraph` from parsed RFC data
- Unit tests: build graph from known RFC structs, assert edges

### 3.2 Graph queries
- `src/graph/query.rs` — transitive dependencies, connected components,
  most-referenced nodes
- Unit tests with constructed test graphs

### 3.3 Graph persistence
- `src/db/graph_store.rs` — persist/load edges from `dep_edges` table

### 3.4 Graph export
- Wire up `graph` CLI command with JSON and DOT output formats

**Milestone**: `rfc-analyzer graph 9293 --format dot` produces a Graphviz graph.

## Phase 4: LLM Integration

### 4.1 LLM client
- `src/llm/client.rs` — OpenAI-compatible chat completions client
- Configurable endpoint, API key from env, model selection
- Retry logic with exponential backoff for 429/5xx
- Token usage tracking

### 4.2 Rate limiting
- `src/llm/rate_limit.rs` — semaphore-based concurrency limiting

### 4.3 Response parsing
- `src/llm/response.rs` — strip markdown fences, parse JSON, validate schema
- Handle partial results gracefully

### 4.4 Prompt templates
- `src/llm/prompts.rs` — all prompt constants with placeholder interpolation
- Start with Stage 2 prompts (mechanism clustering, state extraction)

### 4.5 Tests
- Mock LLM responses with `wiremock`
- Test retry behavior, rate limit handling, malformed response handling

**Milestone**: Can send prompts and parse structured JSON responses from any
OpenAI-compatible endpoint.

## Phase 5: Stage 2 — Protocol Modeling

### 5.1 Pipeline infrastructure
- `src/pipeline/mod.rs` — `Pipeline` struct that chains stages

### 5.2 Mechanism clustering
- First half of `src/pipeline/modeling.rs`
- Group sections by mechanism using LLM

### 5.3 State machine extraction
- Second half of `src/pipeline/modeling.rs`
- Extract states and transitions from section clusters
- Validate structural consistency
- Handle context window overflow (chunking + merging)

### 5.4 State machine persistence
- Update `src/db/analysis_store.rs` for state machines

### 5.5 Wire up CLI `model` command

**Milestone**: `rfc-analyzer model tcp` produces state machines from mapped RFCs.

## Phase 6: Stage 3 — Security Analysis

### 6.1 Security analysis prompts
- Add all 10 category prompts to `src/llm/prompts.rs`

### 6.2 Analysis engine
- `src/pipeline/analysis.rs` — section selection, LLM querying, deduplication
- Scoring and ranking logic

### 6.3 Analysis persistence
- Complete `src/db/analysis_store.rs` for security leads and analysis runs

### 6.4 Report generation
- `src/output/report.rs` — assemble `AnalysisReport`, serialize to JSON

### 6.5 Wire up CLI `analyze` command

**Milestone**: `rfc-analyzer analyze tcp` produces ranked security leads.

## Phase 7: Polish

### 7.1 Full pipeline command
- Wire up `run` subcommand (map -> model -> analyze in one shot)

### 7.2 Utility commands
- `show` command (display cached RFC info)
- `clear` command (selective cache clearing)

### 7.3 Incremental caching
- Content hash checks in all three stages
- Skip re-processing when inputs haven't changed

### 7.4 Integration tests
- End-to-end test with mocked HTTP (both RFC fetcher and LLM)
- Test with a small set of fake RFCs through the full pipeline

### 7.5 Documentation
- README with installation, configuration, and usage examples
- Example output for a small protocol

**Milestone**: Complete, working tool.

## Testing Strategy

### Unit Tests (per module)
- `parser_xml.rs`: Parse known RFC XML snippets, `insta` snapshots
- `parser_text.rs`: Parse known RFC text snippets, edge cases
- `graph/builder.rs`: Graph construction from known data
- `graph/query.rs`: Traversal correctness
- `llm/response.rs`: JSON parsing, malformed response handling
- `db/*`: CRUD operations on in-memory SQLite

### Integration Tests (`tests/`)
- `pipeline_integration.rs`: Full pipeline with `wiremock` mocks
- `fetch_real.rs` (`#[ignore]`): Real RFC fetch to catch format changes

### Test Fixtures (`tests/fixtures/`)
- `rfc9293_snippet.xml` — representative XML excerpt
- `rfc1035_snippet.txt` — representative plain text excerpt
- `llm_state_machine_response.json` — sample LLM response
- `llm_security_analysis_response.json` — sample LLM response
