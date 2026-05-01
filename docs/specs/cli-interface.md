# CLI Interface

Uses `clap` derive API. Binary name: `rfc-analyzer`.

## Global Options

```
rfc-analyzer [OPTIONS] <COMMAND>

Options:
  --config <PATH>    Path to config file [default: rfc-analyzer.toml]
  --db <PATH>        SQLite database path [default: rfc-analyzer.db]
  -v, --verbose      Verbosity level (-v, -vv, -vvv)
  -h, --help         Print help
  -V, --version      Print version
```

## Commands

### `map` — Fetch and parse RFCs, build the dependency graph

```
rfc-analyzer map [OPTIONS] <RFCS>...

Arguments:
  <RFCS>...          Seed RFC numbers (e.g., 9293 1035 2136)

Options:
  --protocol <NAME>  Associate these RFCs with a protocol name (e.g., "tcp")
  --depth <N>        Max depth for transitive dependency crawling [default: 2]
  --normative-only   Only follow normative references (skip informational)
```

When `--protocol` is provided, the seed RFCs (and all transitively discovered
RFCs) are recorded in the `protocol_rfcs` table. This is required before
running `model` or `analyze`. The `run` command passes its protocol argument
through to `map` automatically.

When `--protocol` is **omitted**, the tool emits a warning:
*"RFCs cached but not associated with a protocol. Use --protocol <name>
to enable model/analyze commands."* This prevents the common pitfall of
running `map` then `model` and getting an empty protocol error.

### `model` — Build protocol state machines from mapped RFCs

```
rfc-analyzer model [OPTIONS] <PROTOCOL>

Arguments:
  <PROTOCOL>         Protocol name (used for grouping, e.g., "dns", "tcp")

Options:
  --mechanisms <LIST>  Mechanism types to model, comma-separated
                       (auth, message_format, error_handling, extensions)
```

### `analyze` — Run security analysis on modeled protocols

```
rfc-analyzer analyze [OPTIONS] <PROTOCOL>

Arguments:
  <PROTOCOL>         Protocol name to analyze

Options:
  --categories <LIST>  Attack categories to check, comma-separated [default: all]
  --min-severity <S>   Minimum severity to include [default: low]
  -o, --output <PATH>  Output file [default: stdout]
  --format <FMT>       Output format: json [default: json]
                       (text and markdown formats are deferred to a future version)
```

### `run` — Full pipeline: map -> model -> analyze

```
rfc-analyzer run [OPTIONS] <PROTOCOL> <RFCS>...

Arguments:
  <PROTOCOL>         Protocol name
  <RFCS>...          Seed RFC numbers

Options:
  --depth <N>        Max crawl depth [default: 2]
  -o, --output <PATH>  Output file [default: stdout]
  --format <FMT>     Output format [default: json] (passed through to analyze)
```

### `graph` — Show the dependency graph

```
rfc-analyzer graph [OPTIONS] <TARGET>

Arguments:
  <TARGET>           Protocol name or RFC number

Options:
  --format <FMT>     Output format: json, dot [default: json]
```

### `show` — Show cached RFC info

```
rfc-analyzer show <RFC>

Arguments:
  <RFC>              RFC number
```

### `clear` — Clear stored data

```
rfc-analyzer clear [OPTIONS] [SCOPE]

Arguments:
  [SCOPE]            What to clear: all, rfcs, graphs, analysis [default: all]

Options:
  --yes              Skip confirmation prompt
```

Since the database stores expensive LLM analysis results, `clear` requires
interactive confirmation unless `--yes` is passed. Clearing `rfcs` cascades
to dependent graphs and analysis; clearing `analysis` only removes leads
and state machines.

## Usage Examples

```bash
# Full analysis of DNS
rfc-analyzer run dns 1035 2136 6895 8490 --depth 2 -o dns-report.json

# Just build the dependency map for TCP
rfc-analyzer map 9293 --depth 3 --protocol tcp

# Model TCP then analyze separately
rfc-analyzer model tcp
rfc-analyzer analyze tcp --categories missing_validation,replay --min-severity medium

# Export dependency graph as Graphviz DOT
rfc-analyzer graph tcp --format dot | dot -Tsvg > tcp-deps.svg

# Show what we know about a specific RFC
rfc-analyzer show 9293

# Clear all cached analysis results (keep parsed RFCs)
rfc-analyzer clear analysis
```

## Configuration File (`rfc-analyzer.toml`)

```toml
[llm]
api_base = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"       # reads API key from this env var
model = "gpt-4o"
max_tokens_per_request = 4096
max_concurrent_requests = 3
temperature = 0.2
model_context_window = 128000    # model's context window in tokens

[fetcher]
base_url = "https://www.rfc-editor.org"
prefer_xml = true
request_delay_ms = 500               # polite crawling delay

[analysis]
max_depth = 2
normative_only = false
```

All config values can be overridden by CLI flags where applicable.
The API key is never stored in the config file directly -- it is read
from the environment variable named in `api_key_env`.
