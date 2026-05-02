# RFC Analyzer — Project State

Last updated: 2026-05-02 02:30 UTC

## What This Is

A Rust tool that analyzes protocol specifications (RFCs) for security
vulnerabilities. It builds dependency graphs, extracts protocol state
machines via LLM, runs per-category security analysis, and generates
proof-of-concept reproduction scripts. Inspired by the DreamGroup
Black Hat Asia talk.

## Current State: COMPLETE AND WORKING

All 7 phases implemented, tested, and reviewed. The tool successfully
finds known CVEs from RFC specifications alone.

### Stats
- **67 commits** on main
- **9,633 lines of Rust** across 43 source files
- **104 tests**, zero warnings, zero clippy warnings
- **17 design/implementation spec documents**
- **21 review documents** (design + code reviews)

### Codebase Structure

```
src/
  main.rs, lib.rs, cli.rs, config.rs, error.rs

  rfc/           — RFC fetching and parsing
    fetcher.rs   — async HTTP (XML preferred, text fallback)
    parser_xml.rs, parser_text.rs — RFC parsers
    index.rs     — RFC index for metadata
    model.rs     — Rfc, Section, CrossRef, Reference types

  db/            — SQLite persistence (tokio-rusqlite)
    schema.rs    — migrations v1+v2, pragmas (WAL, FK, busy_timeout)
    rfc_store.rs — RFC/section/cross-ref CRUD
    graph_store.rs — dependency edge persistence
    analysis_store.rs — runs, work items, state machines CRUD

  graph/         — dependency graph (petgraph StableDiGraph)
    builder.rs, model.rs, query.rs, export.rs (JSON + DOT)

  llm/           — LLM integration (OpenAI-compatible)
    client.rs    — HTTP client, retry, error classification, semaphore,
                   cancellation, GBNF grammar support, thinking tag stripping
    prompts.rs   — prompt templates + structured CoT grammars
    response.rs  — JSON parsing, fence stripping, partial results

  pipeline/      — analysis pipeline
    modeling.rs  — Stage 2: mechanism clustering + state machine extraction
    analysis.rs  — Stage 3: per-category security analysis
    reproduce.rs — Stage 4: PoC script generation
    section_select.rs — keyword-based section selection (10 categories)
    summarize.rs — extractive summarize-to-fit

  commands/      — CLI command handlers
    map.rs, model.rs, analyze.rs, run.rs, reproduce.rs,
    show.rs, graph.rs, clear.rs

  output/        — report generation
    report.rs    — AnalysisReport JSON assembly
    poc.rs       — PoC file writing with sanitization + README index
```

### Key Technical Decisions

- **Structured CoT grammars** (from andthattoo.dev/blog/structured_cot):
  GBNF grammars force the LLM to think (GOAL/APPROACH/EDGE/VERIFY) then
  produce valid JSON. This eliminated empty response problems with local
  models. Grammars in `src/llm/prompts.rs`.

- **Thinking tag stripping**: `<think>...</think>` blocks are stripped
  from LLM responses before JSON parsing. Handles Qwen3 thinking mode.

- **Resumability**: interrupted runs (Ctrl+C) set status to 'interrupted'.
  Next run with same inputs resumes from completed work items.

- **Schema v2 migration**: adds `run_id` to state_machines/security_leads,
  `run_work_items` table for per-mechanism/category tracking, `fingerprint`
  for deterministic cross-run lead comparison.

- **Connection error retry**: network errors retry with exponential backoff
  (same as 5xx). Cancellation-aware sleep via `tokio::select!`.

- **HTTP timeout**: 600s for local models (llama.cpp can be slow).

### Configuration

`ietf-draft-analyzer.toml` — current config points to local llama-server:

```toml
[llm]
api_base = "http://ayourtch-desktop:8000/v1"
api_key_env = "OPENAI_API_KEY"
model = "bad-Qwen3.6-35B-A3B-UD-Q4_K_S.gguf"
temperature = 0.2
model_context_window = 262144

[fetcher]
base_url = "https://www.rfc-editor.org"
prefer_xml = true
request_delay_ms = 500
```

For DeepSeek: `api_base = "https://api.deepseek.com/v1"`,
`api_key_env = "DEEPSEEK_API_KEY"`, `model = "deepseek-v4-pro"`.

### Database

SQLite at `ietf-draft-analyzer.db`. Schema v2 (2 migrations). Contains:
- Cached RFCs (zstd-compressed raw content)
- Parsed sections and cross-references
- Dependency graph edges
- Protocol-to-RFC assignments
- State machines (per run)
- Security leads (per run, with fingerprints)
- Analysis runs with input hash manifests
- Per-work-item progress tracking

To reset: `cargo run -- clear all --yes`

### Regression Test Results (all pass)

| Protocol | RFCs | Leads | Known CVE | Result |
|----------|------|-------|-----------|--------|
| Telnet | 854,855,857,858,1184 | 22 | CVE-2026-32746 (SLC triplets) | HIT |
| Kerberos | 4120 | 43 | CVE-2025-59088 (DNS KDC) | HIT |
| TLS 1.3 | 8446 | 28 | CVE-2025-12765 (cert validation) | HIT |
| IPv6 | 8200,5722 | 19 | CVE-2012-4444 (fragment overlap) | HIT |

### Additional Analyses Completed

| Protocol | RFCs | Leads | PoCs |
|----------|------|-------|------|
| SSH core | 4251-4254 | 28 | 10 scripts |
| SSH ext | 4256,4344,5656,6668 | 21 | — |

Reports: `*-report.json` files in project root.
PoCs: `telnet-pocs/`, `ssh-pocs/` directories.

### Batch Run Script

`./run-all-analyses.sh` — runs 10 protocols (Telnet, Kerberos, TLS 1.3,
IPv6, SSH core, SSH ext, DNS, SMTP, HTTP/2, BGP) with PoC generation.
Requires LLM endpoint configured and API key set.

### Development Process Used

1. **Design specs** written by Claude Opus, reviewed by Codex (gpt-5.5)
   and Claude Opus in alternating rounds until both passed.
2. **Implementation specs** (per-phase, self-contained) written by Claude
   Opus, reviewed by Codex until pass.
3. **Implementation** by Qwen3-Coder (local 27B model via opencode) from
   the specs. Each phase: implement → `cargo test` → Codex code review →
   fix issues with TDD → commit → next phase.
4. **Dev guidelines** in `docs/specs/dev-guidelines.md`: Red-Green TDD,
   85%+ coverage target, commit discipline.

### Multi-Agent Orchestration

- **Claude Opus 4.6** (pty-1): project coordinator/lead, wrote all specs
  and implementation plans, orchestrated reviews, fixed code issues
- **Codex gpt-5.5** (pty-2): design reviewer + code reviewer (21 reviews)
- **Claude Opus 4.6** (pty-3): independent design reviewer
- **Qwen3-Coder** (pty-4, opencode): implemented all 7 phases from specs
- **Qwen3.6-35B** (ayourtch-desktop:8000): runtime LLM for analysis

### Known Limitations

- **Plain-text RFC parser**: old RFCs (pre-1990) often have 0 sections
  parsed because they lack numbered section headers. The raw text is still
  stored and available to the LLM.
- **State machine extraction**: works well with grammar constraints but
  very large section clusters can still exceed context. Falls back to
  summarize-to-fit then skip.
- **PoC quality**: LLM-generated scripts are best-effort. They demonstrate
  the protocol interaction but may need manual tuning for specific
  implementations.
- **v1 scope**: RFC-only. No BCP/STD aliases, Internet-Drafts, or errata.
- **Output format**: JSON only for v1. Text/markdown deferred.

### What to Work on Next

1. **Improve plain-text parser** for old RFCs (unnumbered sections, different formatting)
2. **Add `--depth 1+`** regression tests to exercise transitive reference crawling
3. **Integration tests** with mocked LLM for full pipeline coverage
4. **Text/markdown report output** for human triage
5. **Multi-model support** (cheaper model for clustering, stronger for analysis)
6. **PoC syntax validation** (`python -m py_compile` check)
7. **Run against more protocols**: DNS, SMTP, HTTP/2, BGP, QUIC, DNSSEC
8. **Prompt tuning** for better lead quality with different LLM providers

### Files NOT to Modify Without Care

- `src/db/schema.rs` — migration SQL; never reorder/remove entries
- `src/llm/prompts.rs` — changing prompts requires bumping `PROMPT_VERSION`
  to invalidate cached results
- `ietf-draft-analyzer.db` — project artifact, not a cache. Use `clear` command.
