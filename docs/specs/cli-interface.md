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
  --depth <N>        Max depth for transitive dependency crawling [default: 2]
  --normative-only   Only follow normative references (skip informational)
```

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

### `clear` — Clear cached data

```
rfc-analyzer clear [SCOPE]

Arguments:
  [SCOPE]            What to clear: all, rfcs, graphs, analysis [default: all]
```

## Usage Examples

```bash
# Full analysis of DNS
rfc-analyzer run dns 1035 2136 6895 8490 --depth 2 -o dns-report.json

# Just build the dependency map for TCP
rfc-analyzer map 9293 --depth 3

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
