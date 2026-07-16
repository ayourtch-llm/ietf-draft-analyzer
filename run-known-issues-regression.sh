#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$ROOT/target/release/ietf-draft-analyzer"
DB="${REGRESSION_DB:-$ROOT/regression-known-issues.db}"
RESULTS="${REGRESSION_RESULTS:-$ROOT/results-regression}"

if [[ "${1:-}" == "--fresh" ]]; then
  rm -f "$DB" "$DB-shm" "$DB-wal"
elif [[ -e "$DB" ]]; then
  echo "Refusing to reuse $DB; pass --fresh or set REGRESSION_DB to a new path." >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "Release binary not found; run: cargo build --release" >&2
  exit 1
fi

mkdir -p "$RESULTS"

run_case() {
  local protocol="$1"
  local rfcs="$2"
  local categories="$3"

  echo "==> $protocol: map"
  # shellcheck disable=SC2086
  "$BINARY" --db "$DB" map $rfcs --depth 0 --protocol "$protocol"
  echo "==> $protocol: model"
  "$BINARY" --db "$DB" model "$protocol"
  echo "==> $protocol: analyze"
  "$BINARY" --db "$DB" analyze "$protocol" \
    --categories "$categories" \
    -o "$RESULTS/$protocol-report.json"
}

run_case telnet "854 855 857 858 1184" "oversized_payload,missing_validation"
run_case kerberos "4120" "auth_bypass,missing_validation,information_leak"
run_case ipv6 "8200 5722" "missing_validation,implementation_ambiguity"
run_case tls13 "8446" "missing_validation,auth_bypass"

"$ROOT/generate-report.sh" "$RESULTS" "$RESULTS/report.md"

score() {
  local report="$1"
  local filter="$2"
  jq -e "([.security_leads[], (.implementation_checks // [])[]] | any($filter))" \
    "$report" >/dev/null
}

printf '\nKnown-issue regression:\n'
score "$RESULTS/telnet-report.json" \
  '((.technique_name + " " + .description) | test("SLC"; "i")) and
   any(.rfc_references[]; .rfc == 1184)' \
  && echo "  HIT  telnet/RFC1184 SLC" || echo "  MISS telnet/RFC1184 SLC"
score "$RESULTS/kerberos-report.json" \
  'any(.rfc_references[]; .rfc == 4120 and .section == "1.3") and
   any(.rfc_references[]; .rfc == 4120 and
       (.section == "7.2.3" or .section == "7.2.3.2"))' \
  && echo "  HIT  kerberos DNS/KDC bridge" || echo "  MISS kerberos DNS/KDC bridge"
score "$RESULTS/ipv6-report.json" \
  '((.technique_name + " " + .description) | test("overlap"; "i")) and
   any(.rfc_references[]; .rfc == 5722)' \
  && echo "  HIT  ipv6 overlapping fragments" || echo "  MISS ipv6 overlapping fragments"
score "$RESULTS/tls13-report.json" \
  'any(.rfc_references[]; .rfc == 8446 and .section == "C.5") or
   ((.technique_name + " " + .description) |
    test("certificate validation|certificate verification"; "i"))' \
  && echo "  HIT  tls13 certificate validation" || echo "  MISS tls13 certificate validation"

echo "Database: $DB"
echo "Reports:  $RESULTS"
