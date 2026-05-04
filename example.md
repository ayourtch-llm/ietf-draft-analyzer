# Reviewing IETF Drafts with review-drafts.sh

A shell script to fetch, import, and analyze IETF Internet-Drafts using the
ietf-draft-analyzer tool with a configurable LLM backend.

## Prerequisites

- Built binary: `cargo build --release`
- API key set in the environment (e.g. `export DEEPSEEK_API_KEY="..."`)

## Quick Start

```bash
# Analyze all drafts with DeepSeek (default)
./review-drafts.sh

# Use a different model preset
./review-drafts.sh --preset openai

# Custom model with a label for the results directory
./review-drafts.sh --model-label deepseek-r1 --model deepseek-reasoner
```

## Configurable Drafts

The script analyzes the following drafts (hardcoded in the DRAFTS array):

| Draft | Protocol Label | Doc Number |
|-------|---------------|------------|
| draft-ietf-intarea-rfc8335bis-04 | rfc8335bis | 99001 |
| draft-ietf-dnsop-structured-dns-error-19 | dns-structured-error | 99002 |
| draft-ietf-6lo-path-aware-semantic-addressing-13 | 6lo-pasa | 99003 |
| draft-ietf-6lo-nd-gaao-09 | 6lo-nd-gaao | 99004 |
| draft-ietf-intarea-v4-via-v6-08 | v4-via-v6 | 99005 |
| draft-ietf-scitt-scrapi-09 | scitt-scrapi | 99006 |

## Model Presets

| Preset | API Base | Model | Grammar |
|--------|----------|-------|---------|
| `deepseek` | api.deepseek.com/v1 | deepseek-chat | off |
| `openai` | api.openai.com/v1 | gpt-4o | off |
| `gemma4` | localhost:8080/v1 | gemma-4-27b | on |
| `local` | localhost:8080/v1 | local-model | on |

## Options

```
--model-label NAME    Label for results directory (default: deepseek)
--api-base URL        LLM API base URL
--api-key-env VAR     Env var holding the API key
--model NAME          Model identifier
--use-grammar BOOL    Use GBNF grammar (true/false)
--max-tokens N        Max tokens per request
--max-concurrent N    Max concurrent requests
--temperature F       Sampling temperature
--context-window N    Model context window size
--skip-download       Skip downloading drafts (use existing files)
--skip-import         Skip importing (already imported)
--only PROTOCOL       Only process the given protocol name
-v, --verbose         Enable verbose output
```

## Results

Results are written to `results-<model-label>/` (e.g. `results-deepseek/`,
`results-openai/`). Each draft produces a `<protocol>-report.json` file
containing ranked security leads.

## Resumability

The analyzer caches intermediate results in the SQLite database. If
interrupted, re-running the script picks up where it left off. Use
`--skip-download --skip-import` to skip stages that already completed
successfully.

## Examples

```bash
# Re-run analysis only for one draft (already downloaded and imported)
./review-drafts.sh --skip-download --skip-import --only rfc8335bis

# Use a local llama.cpp server with a custom model
./review-drafts.sh \
  --api-base http://localhost:8080/v1 \
  --api-key-env OPENAI_API_KEY \
  --model my-model.gguf \
  --use-grammar true \
  --max-tokens 4096 \
  --model-label my-model

# Verbose output for debugging
./review-drafts.sh -v --only scitt-scrapi
```
