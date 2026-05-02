#!/usr/bin/env bash
# Run RFC Analyzer against all regression test protocols + generate PoCs
# Usage: ./run-all-analyses.sh
#
# Requires:
# - OPENAI_API_KEY or DEEPSEEK_API_KEY set in environment
# - rfc-analyzer.toml configured with LLM endpoint
# - cargo build completed

set -euo pipefail

BINARY="cargo run --"
OUTPUT_DIR="results"
POC_MIN_SEVERITY="high"

mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "RFC Analyzer — Full Protocol Analysis Suite"
echo "============================================"
echo ""

# Track timing
TOTAL_START=$(date +%s)

run_protocol() {
    local name="$1"
    local rfcs="$2"
    local depth="${3:-0}"

    echo "--- $name ---"
    local start=$(date +%s)

    echo "[1/3] Analyzing $name (RFCs: $rfcs, depth: $depth)..."
    $BINARY run "$name" $rfcs --depth "$depth" -o "$OUTPUT_DIR/${name}-report.json" 2>&1 | \
        grep -E "INFO.*(Stage|complete|leads)" | sed 's/^/  /'

    local leads=$(python3 -c "
import json
r = json.load(open('$OUTPUT_DIR/${name}-report.json'))
print(len(r['security_leads']))
" 2>/dev/null || echo "?")

    echo "[2/3] Generating PoCs for $name (severity >= $POC_MIN_SEVERITY)..."
    $BINARY reproduce "$name" --min-severity "$POC_MIN_SEVERITY" \
        --output-dir "$OUTPUT_DIR/${name}-pocs" 2>&1 | \
        grep -E "INFO.*(Generated|Wrote|PoC)" | sed 's/^/  /'

    local pocs=$(ls "$OUTPUT_DIR/${name}-pocs/"*.py 2>/dev/null | wc -l | tr -d ' ')
    local end=$(date +%s)
    local elapsed=$((end - start))

    echo "[3/3] $name complete: $leads leads, $pocs PoCs, ${elapsed}s"
    echo ""
}

# === Regression Test Protocols (known CVEs) ===

echo "=== Regression Protocols (Known CVEs) ==="
echo ""

run_protocol "telnet" "854 855 857 858 1184" 0
# Expected: Unbounded SLC triplets (CVE-2026-32746)

run_protocol "kerberos" "4120" 0
# Expected: DNS KDC discovery gap (CVE-2025-59088)

run_protocol "tls13" "8446" 0
# Expected: Certificate validation (CVE-2025-12765)

run_protocol "ipv6" "8200 5722" 0
# Expected: Overlapping fragments (CVE-2012-4444)

# === Additional Protocols ===

echo "=== Additional Protocols ==="
echo ""

run_protocol "ssh" "4251 4252 4253 4254" 0

run_protocol "ssh-extended" "4256 4344 5656 6668" 0

run_protocol "dns" "1035 2136 6895" 0

run_protocol "smtp" "5321" 0

run_protocol "http2" "9113" 0

run_protocol "bgp" "4271" 0

# === Summary ===

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo "============================================"
echo "Summary"
echo "============================================"
echo ""

for report in "$OUTPUT_DIR"/*-report.json; do
    name=$(basename "$report" -report.json)
    leads=$(python3 -c "
import json
r = json.load(open('$report'))
print(f'{len(r[\"security_leads\"]):3d} leads, {r[\"state_machines_count\"]:2d} state machines')
" 2>/dev/null || echo "  ? leads")
    pocs=$(ls "$OUTPUT_DIR/${name}-pocs/"*.py 2>/dev/null | wc -l | tr -d ' ')
    echo "  $name: $leads, $pocs PoCs"
done

echo ""
echo "Total time: ${TOTAL_ELAPSED}s"
echo "Reports in: $OUTPUT_DIR/"
echo "PoCs in: $OUTPUT_DIR/<protocol>-pocs/"
