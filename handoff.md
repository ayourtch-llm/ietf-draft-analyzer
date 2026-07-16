# Handoff — RFC/Draft Security Analyzer

Last updated: 2026-07-16 by Codex.
Read this top-to-bottom before touching code. It is self-contained.

---

## 0. Scope & purpose (read first)

This project (`ietf-draft-analyzer`) is a **defensive security tool**. Its
goal is to improve the security of Internet protocols by reviewing
RFCs / Internet-Drafts / other standards **before they are published**,
surfacing spec-level weaknesses (missing validation, replay exposure,
DoS/amplification vectors, ambiguous normative language, etc.) so authors
and working groups can fix them at the cheapest possible stage.

This is **in scope** and legitimate work. It is protocol-spec review, not
attack tooling against third parties.

One dual-use caveat to keep in mind: `ssh-pocs/` contains experimental
proof-of-concept code (an SSH timing-enumeration probe, C + Python). The
user has confirmed these are **illustrative experiments, not required** —
they were an attempt to show what a review finding means in concrete code.
They may be deleted freely. Treat any future PoC work as tied to this
authorized research context (illustrating a finding / testing the user's
own infra), not as targeting other systems.

---

## 1. HTML/MQTT and RFCXML ingestion work

The user wants the analyzer to **work better with drafts/RFCs AND with
other standards**, the named target being **MQTT** (OASIS spec, HTML):
https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html

This work was implemented on 2026-07-16:

- Added a real HTML DOM parser using `scraper` / `html5ever`.
- Added Windows-1252 and BOM-aware local document decoding.
- Added heading-based sections, flattened tables/preformatted examples,
  internal links, RFC links, and MQTT normative statement labels.
- Fixed RFCXML extraction so `<bcp14>`, `<tt>`, `<xref>`, CDATA/sourcecode,
  artwork, tables, and text after nested sections are retained.
- Added parser-version-aware cache invalidation.
- Added schema v3 for the `html` format and `parser_version`.
- Validated against the real MQTT 5.0 HTML page and committed IETF draft
  fixtures.

### Why ingestion is the whole job

The pipeline downstream of parsing is **already protocol-agnostic**:
`model` (mechanism clustering + state-machine extraction) and `analyze`
(the 10 attack categories) operate on generic `Section` text and don't
care whether the source was IETF or OASIS. The `import` command already
lets you assign an arbitrary document number (convention: 99001+) and a
protocol name.

Before the 2026-07-16 work, ingestion had exactly two IETF-specific
parsers:

- `src/rfc/parser_xml.rs` — RFC 7991 XML (`<rfc>`, `<section pn=…>`).
- `src/rfc/parser_text.rs` — plain text assuming `Category:` headers,
  `N.N.  Title` section numbering, `[RFCN]` reference syntax, `[Page N]`
  footers, "Section X of [RFCN]" cross-refs.

MQTT instead uses Word-exported `<h1..h6>` headings,
`[MQTT-3.1.0-1]` normative-statement labels, Windows-1252 encoding, and
HTML `<table>` packet-format layouts. These are now handled by the third
parser.

### Implemented shape

1. Added `scraper = "0.27"` (pulls in html5ever) to `Cargo.toml`.
2. New module `src/rfc/parser_html.rs` exposing
   `parse_html(number, content, hash) -> Result<Rfc>`. Map:
   - `<h1..h6 id>` → `Section { number, title, anchor, depth, text }`.
     Derive `number` from heading numbering text or a sequential counter
     (mirror the existing `pn`-absent fallback used for drafts).
   - Flatten `<table>` cells to readable text so packet formats survive
     into `Section.text` (the LLM reads this).
   - Cross-refs: MQTT uses internal `[MQTT-x.y.z-n]` labels and section
     anchors, not `[RFCN]`. Populate `CrossRef { target_rfc: None,
     target_section: Some(anchor) }` where resolvable; don't force RFC
     numbers.
3. Format detection now recognizes `.html`/`.htm`, HTML doctypes, and
   `<html>` content. `RfcFormat::Html` round-trips through the database.
4. Schema v3 recreates `rfcs` with HTML in the format constraint and adds
   `parser_version`; existing data and foreign keys were migration-tested.
5. MQTT `[MQTT-x.y.z-n]` normative statements are preserved as internal
   cross-references for provenance.
6. Real SCITT and BIER draft fixtures now assert normative-word,
   sourcecode, and packet-table preservation.

---

## 2. What this tool is / how it runs

Rust CLI (edition 2024, Rust 1.85+). Three-stage pipeline, all results
cached in SQLite (`ietf-draft-analyzer.db`), runs are resumable on Ctrl+C.

- **Map** — fetch/parse RFCs (XML preferred, text fallback), build a
  petgraph dependency graph (obsoletes/updates/references/xrefs).
- **Model** — LLM clusters sections by mechanism, extracts state machines.
- **Analyze** — for each of 10 attack categories, select sections, send to
  LLM with state-machine context, parse ranked security leads → JSON report.

Also: `import` (local file), `reproduce` (LLM PoC scripts), `show`,
`graph`, `clear`.

### Build & run

```bash
cargo build --release
export DEEPSEEK_API_KEY=...     # current config uses DeepSeek (see §3)

# import a local draft, then analyze:
./target/release/ietf-draft-analyzer import drafts/foo.xml -n 99010 --protocol foo
./target/release/ietf-draft-analyzer model foo
./target/release/ietf-draft-analyzer analyze foo -o foo-report.json

# or full pipeline from RFC numbers:
./target/release/ietf-draft-analyzer run telnet 854 855 1184 --depth 1 -o telnet.json
```

`cargo test --all-targets` — 127 tests plus one ignored real-network test.
`cargo clippy --all-targets --all-features -- -D warnings` passes.

### Batch driver

`./review-drafts.sh` fetches, imports, and analyzes a fixed list of drafts
with a configurable LLM. Has presets: `--preset deepseek|gemma4|openai|local`.
Writes to `results-<label>/`. Requires the release binary to exist first.

---

## 3. Current configuration

`ietf-draft-analyzer.toml` currently points at **DeepSeek cloud**, JSON
mode (no GBNF grammar):

```toml
[llm]
api_base = "https://api.deepseek.com/v1"
api_key_env = "DEEPSEEK_API_KEY"
model = "deepseek-chat"
use_grammar = false            # cloud APIs don't support GBNF
max_tokens_per_request = 32768
temperature = 0.2
model_context_window = 128000
```

Grammar vs JSON mode trade-off (from README): grammar mode (`use_grammar =
true`) needs llama.cpp/llama-server and is recommended for **local** models
(constrains output, avoids timeouts). JSON mode is for **cloud** APIs
(OpenAI/vLLM/Ollama/DeepSeek). The committed default in git history was a
local llama-server + Qwen; the working tree switched it to DeepSeek.

---

## 4. Build / environment status

- A debug binary exists from validation. Build a release binary before
  using `review-drafts.sh`: `cargo build --release`.
- Platform: macOS (darwin 24.6). Shell: zsh. Repo: git, branch `main`,
  currently **ahead of origin/main by 2 commits**.

---

## 5. Historical working-tree state

The following describes the original 2026-07-06 handoff state. Durable
files were checkpointed in commit `58cd8ac`; runtime database files and
the compiled probe remain ignored locally.

- **Modified:** `ietf-draft-analyzer.toml` (local→DeepSeek switch, §3).
- **Untracked, likely worth keeping:**
  - `drafts/` — 6 IETF drafts (xml/txt): intarea-rfc8335bis-04,
    dnsop-structured-dns-error-19, 6lo-path-aware-semantic-addressing-13,
    6lo-nd-gaao-09, intarea-v4-via-v6-08, scitt-scrapi-09.
  - `draft-ietf-bier-ping-23.{txt,xml}` + `bierping-report.json` — a draft
    already analyzed (protocol `bierping`, doc num 99042). Good verify target.
  - `results-deepseek/` — 6 draft reports + `meta-analysis.md`.
  - `results-gemma4/` — `telnet-report.json` (model comparison).
- **Untracked, experimental / deletable:**
  - `ssh-pocs/probe_deepseek_ssh.py`, `ssh-pocs/probe_ssh_timing.py`,
    `ssh-pocs/ssh_timing_enum.c`, compiled `ssh-pocs/ssh_timing_enum` —
    the illustrative PoC experiments (see §0). User OK'd deleting.
- **Untracked DB artifacts:** `ietf-draft-analyzer.db`, `-shm`, `-wal`.
  The DB is treated as a **project artifact, not a throwaway cache** —
  reset only via `clear` command, don't `rm` casually.

---

## 6. Architecture map (where things live)

```
src/
  cli.rs            clap subcommands (Map/Model/Analyze/Run/Import/…)
  config.rs         TOML config + validation
  rfc/
    fetcher.rs      async HTTP, XML/text fallback, sha256
    parser_xml.rs   RFC 7991 XML parser (quick-xml)
    parser_text.rs  plain-text parser (regex, IETF conventions)
    parser_html.rs  heading/table/link extraction for HTML standards
    encoding.rs     BOM/charset decoding for local imports
    text.rs         shared rich-text accumulator
    model.rs        Rfc, Section, CrossRef, Reference, RfcFormat, RfcStatus
    index.rs        RFC index metadata enrichment
  db/               SQLite (tokio-rusqlite), schema v3, zstd raw content
    schema.rs       migrations — NEVER reorder/remove entries
    rfc_store.rs graph_store.rs analysis_store.rs
  graph/            petgraph dependency graph + JSON/DOT export
  llm/
    client.rs       OpenAI-compatible HTTP, retry, GBNF, <think> stripping
    prompts.rs      templates + structured-CoT grammars (bump PROMPT_VERSION
                    if you change prompts — invalidates cached results)
    response.rs     JSON parse, fence stripping, partial results
  pipeline/
    modeling.rs     Stage 2 (mechanism clustering + state machines)
    analysis.rs     Stage 3 (per-category analysis)
    section_select.rs  keyword section selection (10 categories)
    summarize.rs    extractive summarize-to-fit
    reproduce.rs    Stage 4 PoC generation
  commands/         per-subcommand handlers, including HTML-aware import
  output/           report.rs (JSON report), poc.rs (PoC file writing)
```

### Files NOT to modify without care
- `src/db/schema.rs` — migration SQL; never reorder/remove existing entries
  (append a new migration if you must change schema).
- `src/llm/prompts.rs` — changing prompts requires bumping `PROMPT_VERSION`
  to invalidate cached LLM results.
- `ietf-draft-analyzer.db` — project artifact; reset via `clear`, not `rm`.

---

## 7. The 10 attack categories (analyze stage)

MissingValidation, InformationLeak, ReplayAttack, OversizedPayload,
StateConfusion, AuthBypass, DenialOfService, Downgrade, RaceCondition,
ImplementationAmbiguity. Defined/keyworded in `src/pipeline/section_select.rs`
and prompted in `src/llm/prompts.rs`.

---

## 8. Longer background

- `state.md` — detailed project state as of 2026-05-02: stats, regression
  CVE fixtures (Telnet/Kerberos/TLS1.3/IPv6 all HIT), multi-agent dev
  process, known limitations, "what to work on next" list. Mostly still
  accurate for internals; the config section there is stale (now DeepSeek).
- `README.md` — user-facing usage, config reference, grammar vs JSON modes.
- `results-deepseek/meta-analysis.md` — cross-draft findings writeup.
- `ech-analysis.md` — a worked ECH/TLS analysis example.

---

## 9. Immediate next actions for future-me

1. Build a release binary: `cargo build --release`.
2. Import MQTT as `-n 99100 --protocol mqtt`, then run `model` and
   `analyze` against the configured LLM and manually inspect the report.
3. Re-import existing XML drafts so parser version 2 replaces their stale,
   lossy section text; rerun model/analyze as desired.
4. Address semantic lead duplication and distinguish novel gaps from risks
   already documented or mitigated by the specification.
5. Keep the user in the loop before a larger refactor from RFC-centric names
   (`RfcNumber`, `source_rfc`) to generic document/citation types.
