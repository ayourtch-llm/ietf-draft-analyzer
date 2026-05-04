#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# review-drafts.sh — Fetch, import, and analyze IETF drafts with configurable LLM
# ============================================================================

# --- Defaults (DeepSeek) ---
API_BASE="https://api.deepseek.com/v1"
API_KEY_ENV="DEEPSEEK_API_KEY"
MODEL="deepseek-chat"
USE_GRAMMAR="false"
MAX_TOKENS="32768"
MAX_CONCURRENT="1"
TEMPERATURE="0.2"
CONTEXT_WINDOW="128000"
MODEL_LABEL="deepseek"

# --- Drafts to analyze ---
DRAFTS=(
  "draft-ietf-intarea-rfc8335bis-04:rfc8335bis:99001"
  "draft-ietf-dnsop-structured-dns-error-19:dns-structured-error:99002"
  "draft-ietf-6lo-path-aware-semantic-addressing-13:6lo-pasa:99003"
  "draft-ietf-6lo-nd-gaao-09:6lo-nd-gaao:99004"
  "draft-ietf-intarea-v4-via-v6-08:v4-via-v6:99005"
  "draft-ietf-scitt-scrapi-09:scitt-scrapi:99006"
)

# --- Usage ---
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Analyze IETF drafts using the ietf-draft-analyzer tool with a configurable LLM.

Options:
  --model-label NAME    Label for results directory (default: deepseek)
  --api-base URL        LLM API base URL (default: https://api.deepseek.com/v1)
  --api-key-env VAR     Env var holding the API key (default: DEEPSEEK_API_KEY)
  --model NAME          Model identifier (default: deepseek-chat)
  --use-grammar BOOL    Use GBNF grammar (default: false)
  --max-tokens N        Max tokens per request (default: 32768)
  --max-concurrent N    Max concurrent requests (default: 1)
  --temperature F       Sampling temperature (default: 0.2)
  --context-window N    Model context window size (default: 128000)
  --skip-download       Skip downloading drafts (use existing files)
  --skip-import         Skip importing drafts (already imported)
  --only PROTOCOL       Only process the given protocol name
  -v, --verbose         Enable verbose output
  -h, --help            Show this help

Presets (use instead of individual options):
  --preset deepseek     DeepSeek Chat (default)
  --preset gemma4       Google Gemma 4 via local endpoint
  --preset openai       OpenAI GPT-4o
  --preset local        Local llama.cpp server

Examples:
  $0 --preset deepseek
  $0 --preset openai --model gpt-4o-mini
  $0 --api-base http://localhost:8080/v1 --model my-model --model-label my-model
  $0 --skip-download --only rfc8335bis
EOF
  exit 0
}

# --- Presets ---
apply_preset() {
  case "$1" in
    deepseek)
      API_BASE="https://api.deepseek.com/v1"
      API_KEY_ENV="DEEPSEEK_API_KEY"
      MODEL="deepseek-chat"
      USE_GRAMMAR="false"
      MAX_TOKENS="32768"
      CONTEXT_WINDOW="128000"
      MODEL_LABEL="deepseek"
      ;;
    gemma4)
      API_BASE="http://localhost:8080/v1"
      API_KEY_ENV="OPENAI_API_KEY"
      MODEL="gemma-4-27b"
      USE_GRAMMAR="true"
      MAX_TOKENS="4096"
      CONTEXT_WINDOW="128000"
      MODEL_LABEL="gemma4"
      ;;
    openai)
      API_BASE="https://api.openai.com/v1"
      API_KEY_ENV="OPENAI_API_KEY"
      MODEL="gpt-4o"
      USE_GRAMMAR="false"
      MAX_TOKENS="16384"
      CONTEXT_WINDOW="128000"
      MODEL_LABEL="openai"
      ;;
    local)
      API_BASE="http://localhost:8080/v1"
      API_KEY_ENV="OPENAI_API_KEY"
      MODEL="local-model"
      USE_GRAMMAR="true"
      MAX_TOKENS="4096"
      CONTEXT_WINDOW="128000"
      MODEL_LABEL="local"
      ;;
    *)
      echo "Error: Unknown preset '$1'. Available: deepseek, gemma4, openai, local"
      exit 1
      ;;
  esac
}

# --- Parse arguments ---
SKIP_DOWNLOAD=false
SKIP_IMPORT=false
ONLY=""
VERBOSE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)       apply_preset "$2"; shift 2 ;;
    --model-label)  MODEL_LABEL="$2"; shift 2 ;;
    --api-base)     API_BASE="$2"; shift 2 ;;
    --api-key-env)  API_KEY_ENV="$2"; shift 2 ;;
    --model)        MODEL="$2"; shift 2 ;;
    --use-grammar)  USE_GRAMMAR="$2"; shift 2 ;;
    --max-tokens)   MAX_TOKENS="$2"; shift 2 ;;
    --max-concurrent) MAX_CONCURRENT="$2"; shift 2 ;;
    --temperature)  TEMPERATURE="$2"; shift 2 ;;
    --context-window) CONTEXT_WINDOW="$2"; shift 2 ;;
    --skip-download) SKIP_DOWNLOAD=true; shift ;;
    --skip-import)  SKIP_IMPORT=true; shift ;;
    --only)         ONLY="$2"; shift 2 ;;
    -v|--verbose)   VERBOSE="-v"; shift ;;
    -h|--help)      usage ;;
    *)              echo "Unknown option: $1"; usage ;;
  esac
done

# --- Resolve paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/target/release/ietf-draft-analyzer"
CONFIG_FILE="$SCRIPT_DIR/ietf-draft-analyzer.toml"
RESULTS_DIR="$SCRIPT_DIR/results-${MODEL_LABEL}"
DRAFTS_DIR="$SCRIPT_DIR/drafts"

if [[ ! -x "$ANALYZER" ]]; then
  echo "Error: Analyzer binary not found at $ANALYZER"
  echo "Run: cargo build --release"
  exit 1
fi

# --- Check API key ---
if [[ -z "${!API_KEY_ENV:-}" ]]; then
  echo "Error: Environment variable $API_KEY_ENV is not set"
  exit 1
fi

# --- Write config ---
echo "==> Writing config to $CONFIG_FILE"
cat > "$CONFIG_FILE" <<EOF
[llm]
api_base = "$API_BASE"
api_key_env = "$API_KEY_ENV"
model = "$MODEL"
use_grammar = $USE_GRAMMAR
max_tokens_per_request = $MAX_TOKENS
max_concurrent_requests = $MAX_CONCURRENT
temperature = $TEMPERATURE
model_context_window = $CONTEXT_WINDOW

[fetcher]
base_url = "https://www.rfc-editor.org"
prefer_xml = true
request_delay_ms = 500

[analysis]
max_depth = 2
normative_only = false
EOF

echo "    Model: $MODEL ($MODEL_LABEL)"
echo "    API:   $API_BASE"
echo ""

# --- Create directories ---
mkdir -p "$RESULTS_DIR" "$DRAFTS_DIR"

# --- Download drafts ---
if [[ "$SKIP_DOWNLOAD" == false ]]; then
  echo "==> Downloading drafts..."
  for entry in "${DRAFTS[@]}"; do
    IFS=: read -r draft_name protocol doc_num <<< "$entry"

    if [[ -n "$ONLY" && "$protocol" != "$ONLY" ]]; then
      continue
    fi

    outfile="$DRAFTS_DIR/${draft_name}.xml"
    if [[ -f "$outfile" ]]; then
      echo "    [skip] $draft_name.xml (already exists)"
      continue
    fi

    echo "    [fetch] $draft_name.xml"
    if ! curl -sfL -o "$outfile" "https://www.ietf.org/archive/id/${draft_name}.xml"; then
      echo "    [warn] XML not available, trying .txt"
      outfile="$DRAFTS_DIR/${draft_name}.txt"
      if ! curl -sfL -o "$outfile" "https://www.ietf.org/archive/id/${draft_name}.txt"; then
        echo "    [ERROR] Failed to download $draft_name"
        rm -f "$outfile"
        continue
      fi
    fi
  done
  echo ""
fi

# --- Import drafts ---
if [[ "$SKIP_IMPORT" == false ]]; then
  echo "==> Importing drafts..."
  for entry in "${DRAFTS[@]}"; do
    IFS=: read -r draft_name protocol doc_num <<< "$entry"

    if [[ -n "$ONLY" && "$protocol" != "$ONLY" ]]; then
      continue
    fi

    # Find the downloaded file (xml preferred, txt fallback)
    infile="$DRAFTS_DIR/${draft_name}.xml"
    if [[ ! -f "$infile" ]]; then
      infile="$DRAFTS_DIR/${draft_name}.txt"
    fi
    if [[ ! -f "$infile" ]]; then
      echo "    [ERROR] No file found for $draft_name, skipping"
      continue
    fi

    echo "    [import] $draft_name -> protocol=$protocol, num=$doc_num"
    "$ANALYZER" $VERBOSE import "$infile" -n "$doc_num" --protocol "$protocol" || {
      echo "    [ERROR] Import failed for $draft_name"
      continue
    }
  done
  echo ""
fi

# --- Run model + analyze ---
echo "==> Running analysis pipeline..."
for entry in "${DRAFTS[@]}"; do
  IFS=: read -r draft_name protocol doc_num <<< "$entry"

  if [[ -n "$ONLY" && "$protocol" != "$ONLY" ]]; then
    continue
  fi

  report_file="$RESULTS_DIR/${protocol}-report.json"

  echo "    [model] $protocol"
  "$ANALYZER" $VERBOSE model "$protocol" || {
    echo "    [ERROR] Model stage failed for $protocol"
    continue
  }

  echo "    [analyze] $protocol -> $report_file"
  "$ANALYZER" $VERBOSE analyze "$protocol" -o "$report_file" || {
    echo "    [ERROR] Analyze stage failed for $protocol"
    continue
  }

  echo "    [done] $protocol"
  echo ""
done

echo "==> All done! Results in: $RESULTS_DIR/"
ls -la "$RESULTS_DIR/"
