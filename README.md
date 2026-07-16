# IETF Draft Analyzer

A Rust tool that treats protocol specifications (RFCs and Internet-Drafts)
as a first-class attack surface. It builds dependency graphs, extracts
protocol state machines, and runs LLM-powered security analysis to produce
ranked vulnerability leads.

Inspired by the [DreamGroup Black Hat Asia talk](https://dreamgroup.com/our-latest-black-hat-asia-talk-introducing-the-rfc-analyzer/).

## Disclaimer

This is an **experimental project**. Its goal was to explore the
feasibility of building a non-trivial piece of software in a
near-autonomous fashion, starting from nothing more than a decently
good blog post describing the original tool's function. The entire
codebase -- design specs, implementation, and reviews -- was produced
by a multi-agent AI pipeline (Claude Opus, Codex/GPT-5.5, Qwen3-Coder)
with human oversight.

As a result, **this project bears no resemblance to the original
DreamGroup RFC Analyzer** beyond the high-level concept of analyzing
RFC specifications for security issues. It is an independent,
clean-room reimplementation built from a public description.

The **proof-of-concept (PoC) generation feature is even more
experimental**. The generated scripts demonstrate protocol interactions
at a conceptual level but frequently contain errors in protocol framing,
state machine handling, or API usage. They should be treated as
starting points for manual development, not as working exploit code.

## How It Works

The tool runs a three-stage pipeline:

1. **Map** -- Fetch and parse RFCs from rfc-editor.org (XML preferred,
   plain-text fallback). Build a dependency graph tracking obsoletes,
   updates, normative/informative references, and section-level
   cross-references. Transitive references are followed up to a
   configurable depth.

2. **Model** -- Use an LLM to cluster RFC sections by protocol mechanism
   (authentication, message format, error handling, etc.) and extract
   protocol state machines from each cluster. State machines include
   states, transitions, triggers, and conditions with RFC provenance.

3. **Analyze** -- For each of 10 attack categories, select relevant
   sections using keyword heuristics, send them to the LLM with state
   machine context, and parse structured security leads. Leads are
   deduplicated by deterministic fingerprint, ranked by severity then
   confidence, and output as a JSON report.

All intermediate results are cached in a local SQLite database. Runs are
resumable -- if interrupted (Ctrl+C), partial results are preserved and
the next invocation picks up where it left off.

## Requirements

- Rust 1.85+ (edition 2024)
- An OpenAI-compatible LLM endpoint

The tool supports two output modes:

- **Grammar mode** (default, `use_grammar = true`): Uses GBNF grammar
  constraints for structured output. Requires
  [llama.cpp](https://github.com/ggerganov/llama.cpp) (llama-server)
  or any backend that accepts `"grammar"` in the request body.
  **Recommended for local models** — the grammar constrains output
  length and structure, preventing the model from generating verbose
  preamble that can exceed HTTP timeouts.

- **JSON mode** (`use_grammar = false`): Uses standard
  `response_format: {"type": "json_object"}` for structured output.
  Compatible with OpenAI, vLLM, Ollama, and any OpenAI-compatible API.
  Does not require llama.cpp. **Recommended for cloud APIs** where
  generation is fast and GBNF is not supported. Local models may
  time out in this mode due to verbose output before the JSON.

## Installation

```bash
git clone <repo-url>
cd ietf-draft-analyzer
cargo build --release
```

The binary is at `target/release/ietf-draft-analyzer`.

## Configuration

Create `ietf-draft-analyzer.toml` in the working directory (all fields are
optional -- defaults are shown):

```toml
[llm]
api_base = "http://localhost:8000/v1"
api_key_env = "OPENAI_API_KEY"
model = "Qwen3.6-27B-Q4_K_M.gguf"
max_tokens_per_request = 4096
max_concurrent_requests = 1
temperature = 0.2
model_context_window = 128000
# Set to false for OpenAI/vLLM/Ollama compatibility (no GBNF grammar)
# use_grammar = false
# Set to true for reasoning models whose server supports llama.cpp chat
# template arguments and should return JSON without extended thinking
# disable_thinking = true

[fetcher]
base_url = "https://www.rfc-editor.org"
prefer_xml = true
request_delay_ms = 500

[analysis]
max_depth = 2
normative_only = false
```

Set your API key in the environment:

```bash
export OPENAI_API_KEY="your-key-here"
# For local models without auth, set any non-empty value:
export OPENAI_API_KEY="local"
```

## Usage

### Full Pipeline (recommended)

Run the complete map-model-analyze pipeline in one command:

```bash
# Analyze DNS protocol security
ietf-draft-analyzer run dns 1035 2136 6895 --depth 2 -o dns-report.json

# Analyze TCP
ietf-draft-analyzer run tcp 9293 --depth 1 -o tcp-report.json

# Analyze Telnet (known CVEs in this protocol)
ietf-draft-analyzer run telnet 854 855 857 858 1184 --depth 1 -o telnet-report.json
```

### Individual Stages

Run stages separately for more control:

```bash
# Stage 1: Fetch and map RFCs
ietf-draft-analyzer map 9293 --depth 1 --protocol tcp

# Inspect what was fetched
ietf-draft-analyzer show 9293

# View the dependency graph
ietf-draft-analyzer graph tcp --format dot | dot -Tsvg > tcp-deps.svg
ietf-draft-analyzer graph tcp --format json

# Stage 2: Extract state machines
ietf-draft-analyzer model tcp

# Stage 3: Security analysis
ietf-draft-analyzer analyze tcp --min-severity medium -o tcp-leads.json

# Filter to specific attack categories
ietf-draft-analyzer analyze tcp --categories missing_validation,replay_attack
```

### Analyzing Internet-Drafts and HTML Standards

Import a local Internet-Draft (RFCXML or plain text), or an HTML
specification from another standards body. This is useful for reviewing
work-in-progress specifications before publication and for analyzing
protocols that are not published through the IETF.

```bash
# Download a draft
curl -O https://www.ietf.org/archive/id/draft-ietf-tls-esni-22.xml

# Import it (use a high number like 99001 to avoid clashing with real RFCs)
ietf-draft-analyzer import draft-ietf-tls-esni-22.xml -n 99001 --protocol ech

# Run the analysis pipeline
ietf-draft-analyzer model ech
ietf-draft-analyzer analyze ech -o ech-report.json

# Or generate PoC scripts
ietf-draft-analyzer reproduce ech --output-dir ech-pocs
```

For example, import the OASIS MQTT 5.0 HTML specification:

```bash
curl -o mqtt-v5.0.html \
  https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html

ietf-draft-analyzer import mqtt-v5.0.html -n 99100 --protocol mqtt
ietf-draft-analyzer model mqtt
ietf-draft-analyzer analyze mqtt -o mqtt-report.json
```

The `import` command accepts RFC 7991+ XML, plain text, or HTML. HTML
documents are decoded using their declared character encoding and split
on `h1` through `h6` headings. Tables, preformatted examples, inline
normative language, internal links, and MQTT-style normative statement
labels such as `[MQTT-3.1.0-1]` are retained in section text and
provenance.

The `--number` (`-n`) flag assigns an internal document number. The
`--protocol` flag associates the document with a protocol name used by
subsequent commands.

Internet-Drafts without the `pn` attribute on `<section>` elements
(common before RFC Editor processing) are handled automatically by
falling back to the `anchor` attribute or a sequential counter for
section numbering.

Parsed documents carry an internal parser version. When extraction logic
changes, cached documents parsed by an older version are automatically
reprocessed on the next map or import instead of silently reusing stale
sections.

### Other Commands

```bash
# Show cached RFC info
ietf-draft-analyzer show 1035

# Clear analysis results (keeps fetched RFCs)
ietf-draft-analyzer clear analysis

# Clear everything
ietf-draft-analyzer clear all --yes

# Increase verbosity
ietf-draft-analyzer -v map 9293 --depth 0 --protocol tcp    # debug
ietf-draft-analyzer -vv model tcp                             # trace
```

## Example Run

```bash
$ export OPENAI_API_KEY="local"

$ cat ietf-draft-analyzer.toml
[llm]
api_base = "http://localhost:8000/v1"
model = "Qwen3.6-27B-Q4_K_M.gguf"
temperature = 0.2
model_context_window = 128000

$ ietf-draft-analyzer run telnet 854 855 857 858 1184 --depth 1 -o telnet-report.json
2026-05-01T22:00:00Z  INFO === Stage 1: Map ===
2026-05-01T22:00:00Z  INFO Fetching RFC index...
2026-05-01T22:00:02Z  INFO Depth 0: processing 5 RFCs
2026-05-01T22:00:02Z  INFO Fetching RFC 1/5: RFC 854
2026-05-01T22:00:03Z  INFO Parsed RFC 854 (xml) - 12 sections, 3 references
2026-05-01T22:00:04Z  INFO Fetching RFC 2/5: RFC 855
...
2026-05-01T22:00:15Z  INFO Depth 1: processing 8 RFCs
...
2026-05-01T22:00:45Z  INFO Map complete: 13 RFCs processed
2026-05-01T22:00:45Z  INFO Graph: 13 nodes, 18 edges, 2 components

2026-05-01T22:00:45Z  INFO === Stage 2: Model ===
2026-05-01T22:00:45Z  INFO Clustering mechanisms for protocol 'telnet'
2026-05-01T22:00:55Z  INFO Found 4 mechanism clusters
2026-05-01T22:00:55Z  INFO Extracting state machine 1/4: 'Option Negotiation'
2026-05-01T22:01:15Z  INFO Extracting state machine 2/4: 'Connection Management'
...
2026-05-01T22:02:00Z  INFO Stage 2 complete: 4 state machines extracted

2026-05-01T22:02:00Z  INFO === Stage 3: Analyze ===
2026-05-01T22:02:00Z  INFO Analyzing category 1/10: MissingValidation
2026-05-01T22:02:20Z  INFO Category 'MissingValidation': 5 leads found
2026-05-01T22:02:20Z  INFO Analyzing category 2/10: InformationLeak
...
2026-05-01T22:05:30Z  INFO Stage 3 complete: 47 leads (after dedup/filter)
2026-05-01T22:05:30Z  INFO Report written to telnet-report.json
```

The output `telnet-report.json` contains:

```json
{
  "protocol_name": "telnet",
  "rfcs_analyzed": [854, 855, 857, 858, 1184],
  "dependency_graph_summary": {
    "total_nodes": 13,
    "total_edges": 18,
    "connected_components": 2,
    "most_referenced_rfcs": [[854, 8], [855, 5]]
  },
  "state_machines_count": 4,
  "security_leads": [
    {
      "technique_name": "Unbounded SLC Triplet Injection",
      "category": "OversizedPayload",
      "severity": "critical",
      "confidence": 0.92,
      "assessment": "specification_gap",
      "security_context": "The Security Considerations discuss transport protection but do not define a resource limit for this state.",
      "gap_evidence": "The specification defines the message but no aggregate resource bound.",
      "existing_protection": null,
      "attacker_capability": "Ability to establish unauthenticated protocol sessions",
      "proposed_spec_change": "Add a configurable aggregate resource limit and required exhaustion behavior.",
      "description": "Step 1: Attacker initiates Telnet connection...",
      "rfc_references": [
        {"rfc": 1184, "section": "3.3", "quote": "SLC triplets..."}
      ],
      "prerequisites": ["network access to telnet service"],
      "entities_involved": ["client", "server"],
      "mitigation": "Limit number of SLC triplets accepted",
      "fingerprint": "a1b2c3d4...",
      "related_categories": ["DenialOfService", "OversizedPayload"],
      "merged_lead_count": 2
    }
  ],
  "implementation_checks": [],
  "metadata": {
    "generated_at": "2026-05-01T22:05:30Z",
    "model_used": "Qwen3.5-27B-512K",
    "total_tokens_used": 45000,
    "analysis_duration_secs": 330.0,
    "prompt_version": "1.8.0",
    "ietf_draft_analyzer_version": "0.1.0",
    "report_format": "json"
  }
}
```

Each candidate is checked against the document's Security Considerations and
normative requirements. The actionable report includes `specification_gap` and
`known_risk` findings in `security_leads`. Explicit normative requirements that
implementations may violate are retained separately in
`implementation_checks`, making them suitable for source-code or configuration
audits. `expected_behavior` candidates remain in the analysis database but are
excluded from reports. Cross-category restatements with the same cited sections
are conservatively consolidated; `related_categories`, `merged_lead_count`, and
`merged_candidates` retain that provenance.

## Attack Categories

The analyzer checks for 10 categories of protocol-level vulnerabilities:

| Category | What it looks for |
|----------|-------------------|
| MissingValidation | Input fields not validated, missing bounds checks |
| InformationLeak | Error messages or metadata that reveal internal state |
| ReplayAttack | Missing nonces, sequence numbers, or freshness checks |
| OversizedPayload | No length limits, buffer overflow potential |
| StateConfusion | Unexpected state transitions, desynchronization |
| AuthBypass | Authentication gaps, credential handling issues |
| DenialOfService | Resource exhaustion, amplification vectors |
| Downgrade | Version negotiation weaknesses, legacy fallbacks |
| RaceCondition | Concurrent access issues, TOCTOU vulnerabilities |
| ImplementationAmbiguity | Spec gaps that lead to divergent implementations |

## Architecture

```
src/
  main.rs              CLI entry point, graceful shutdown
  cli.rs               Clap command definitions
  config.rs            TOML configuration with validation
  error.rs             Typed error handling (thiserror)

  rfc/                 RFC fetching and parsing
    fetcher.rs         Async HTTP with XML/text fallback
    parser_xml.rs      RFC 7991+ XML parser (quick-xml)
    parser_text.rs     Plain-text parser (regex-based)
    index.rs           RFC index for metadata enrichment
    model.rs           Core data types (Rfc, Section, etc.)

  db/                  SQLite persistence (tokio-rusqlite)
    schema.rs          Migrations, pragma setup
    rfc_store.rs       RFC/section/cross-ref CRUD
    graph_store.rs     Dependency edge persistence
    analysis_store.rs  Run/work-item/state-machine CRUD

  graph/               Dependency graph (petgraph)
    builder.rs         Graph construction from RFC data
    query.rs           Traversal, connected components
    export.rs          JSON and Graphviz DOT output

  llm/                 LLM integration
    client.rs          OpenAI-compatible HTTP client
    prompts.rs         Prompt templates with injection defense
    response.rs        JSON parsing with fence stripping

  pipeline/            Analysis pipeline
    modeling.rs        Stage 2: mechanism clustering + state machines
    analysis.rs        Stage 3: per-category security analysis
    section_select.rs  Keyword-based section selection
    summarize.rs       Extractive summarize-to-fit

  commands/            Command handlers
    map.rs, model.rs, analyze.rs, run.rs, import.rs,
    show.rs, graph.rs, clear.rs

  output/              Report generation
    report.rs          JSON report assembly
```

## Testing

```bash
# Run all tests (127 tests plus one ignored real-network test)
cargo test

# Run with live RFC fetching (requires network)
cargo test -- --ignored

# Check code coverage
cargo tarpaulin --out html --output-dir coverage/
```

## Known CVE Regression Fixtures

The tool includes validation fixtures based on real CVEs discovered
through RFC specification analysis (see `docs/specs/test-fixtures/`):

- **Kerberos** CVE-2025-59088: DNS-based KDC discovery gap (RFC 4120)
- **IPv6** CVE-2012-4444: Overlapping fragment hardening gap (RFC 5722)
- **Telnet** CVE-2026-32746: Unbounded SLC triplets (RFC 1184)
- **TLS 1.3** CVE-2025-12765/25644/31798: Certificate validation (RFC 8446)

Run the focused suite against a new isolated database:

```bash
cargo build --release
source ~/ai/deepseek-api-key
REGRESSION_RESULTS=results-regression ./run-known-issues-regression.sh --fresh
```

The script scores both specification findings and implementation checks.

## License

TBD
