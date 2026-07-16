#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# generate-report.sh — Convert JSON analysis results to a Markdown report
# ============================================================================

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] <results-dir|json-file> [output-file]

Generate a Markdown report from ietf-draft-analyzer JSON results.

Arguments:
  results-dir   Directory containing *-report.json files (e.g. results-deepseek/)
  json-file     A single JSON report file
  output-file   Output .md file (default: <results-dir>/report.md or <name>-report.md)

Options:
  --min-severity SEV   Only include leads at or above: low, medium, high, critical
                       (default: low — include everything)
  --min-confidence N   Only include leads with confidence >= N (default: 0.0)
  --toc                Include a table of contents (default: on)
  --no-toc             Omit the table of contents
  -h, --help           Show this help

Examples:
  $0 results-deepseek/
  $0 results-deepseek/ combined-report.md
  $0 results-deepseek/rfc8335bis-report.json
  $0 --min-severity high results-deepseek/
  $0 --min-confidence 0.8 results-deepseek/
EOF
  exit 0
}

# --- Defaults ---
MIN_SEVERITY="low"
MIN_CONFIDENCE="0.0"
INCLUDE_TOC=true

# --- Parse options ---
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-severity)  MIN_SEVERITY="$2"; shift 2 ;;
    --min-confidence) MIN_CONFIDENCE="$2"; shift 2 ;;
    --toc)           INCLUDE_TOC=true; shift ;;
    --no-toc)        INCLUDE_TOC=false; shift ;;
    -h|--help)       usage ;;
    -*)              echo "Unknown option: $1"; usage ;;
    *)               POSITIONAL+=("$1"); shift ;;
  esac
done

if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
  echo "Error: must provide a results directory or JSON file"
  usage
fi

INPUT="${POSITIONAL[0]}"
OUTPUT="${POSITIONAL[1]:-}"

# Check for jq
if ! command -v jq &>/dev/null; then
  echo "Error: jq is required. Install with: brew install jq"
  exit 1
fi

# --- Severity ordering ---
severity_rank() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}

MIN_SEV_RANK=$(severity_rank "$MIN_SEVERITY")

# --- Collect input files ---
declare -a JSON_FILES=()
if [[ -d "$INPUT" ]]; then
  for f in "$INPUT"/*-report.json; do
    [[ -f "$f" ]] && JSON_FILES+=("$f")
  done
  if [[ ${#JSON_FILES[@]} -eq 0 ]]; then
    echo "Error: no *-report.json files found in $INPUT"
    exit 1
  fi
  [[ -z "$OUTPUT" ]] && OUTPUT="$INPUT/report.md"
elif [[ -f "$INPUT" ]]; then
  JSON_FILES+=("$INPUT")
  if [[ -z "$OUTPUT" ]]; then
    OUTPUT="${INPUT%.json}.md"
  fi
else
  echo "Error: $INPUT is not a file or directory"
  exit 1
fi

# --- jq filter for severity ---
JQ_SEV_FILTER="
  def sev_rank:
    if . == \"critical\" then 4
    elif . == \"high\" then 3
    elif . == \"medium\" then 2
    elif . == \"low\" then 1
    else 0
    end;
  [.[] | select((.severity | sev_rank) >= $MIN_SEV_RANK and .confidence >= $MIN_CONFIDENCE)]
  | sort_by(- (.severity | sev_rank), - .confidence)
"

# --- Severity badge ---
sev_badge() {
  case "$1" in
    critical) echo "**CRITICAL**" ;;
    high)     echo "**HIGH**" ;;
    medium)   echo "MEDIUM" ;;
    low)      echo "low" ;;
    *)        echo "$1" ;;
  esac
}

# --- Begin report ---
{
  echo "# Security Analysis Report"
  echo ""

  # Determine model from first file
  MODEL=$(jq -r '.metadata.model_used // "unknown"' "${JSON_FILES[0]}")
  GENERATED=$(jq -r '.metadata.generated_at // "unknown"' "${JSON_FILES[0]}" | cut -d'T' -f1)
  echo "**Model:** $MODEL  "
  echo "**Generated:** $GENERATED  "
  echo "**Drafts analyzed:** ${#JSON_FILES[@]}  "
  if [[ "$MIN_SEVERITY" != "low" ]]; then
    echo "**Minimum severity:** $MIN_SEVERITY  "
  fi
  if [[ "$MIN_CONFIDENCE" != "0.0" ]]; then
    echo "**Minimum confidence:** $MIN_CONFIDENCE  "
  fi
  echo ""
  echo "---"
  echo ""

  # --- Summary table ---
  echo "## Summary"
  echo ""
  echo "| Draft | Protocol | Critical | High | Medium | Low | Total |"
  echo "|-------|----------|----------|------|--------|-----|-------|"

  GRAND_TOTAL=0
  GRAND_CRIT=0
  GRAND_HIGH=0
  GRAND_MED=0
  GRAND_LOW=0

  for f in "${JSON_FILES[@]}"; do
    PROTOCOL=$(jq -r '.protocol_name' "$f")
    LEADS=$(jq -c ".security_leads | $JQ_SEV_FILTER" "$f")
    TOTAL=$(echo "$LEADS" | jq 'length')
    CRIT=$(echo "$LEADS" | jq '[.[] | select(.severity == "critical")] | length')
    HIGH=$(echo "$LEADS" | jq '[.[] | select(.severity == "high")] | length')
    MED=$(echo "$LEADS" | jq '[.[] | select(.severity == "medium")] | length')
    LOW=$(echo "$LEADS" | jq '[.[] | select(.severity == "low")] | length')

    DRAFT_NAME=$(basename "$f" -report.json)
    echo "| $DRAFT_NAME | $PROTOCOL | $CRIT | $HIGH | $MED | $LOW | $TOTAL |"

    GRAND_TOTAL=$((GRAND_TOTAL + TOTAL))
    GRAND_CRIT=$((GRAND_CRIT + CRIT))
    GRAND_HIGH=$((GRAND_HIGH + HIGH))
    GRAND_MED=$((GRAND_MED + MED))
    GRAND_LOW=$((GRAND_LOW + LOW))
  done

  echo "| **Total** | | **$GRAND_CRIT** | **$GRAND_HIGH** | **$GRAND_MED** | **$GRAND_LOW** | **$GRAND_TOTAL** |"
  echo ""

  # --- Table of contents ---
  if [[ "$INCLUDE_TOC" == true ]]; then
    echo "## Table of Contents"
    echo ""
    for f in "${JSON_FILES[@]}"; do
      PROTOCOL=$(jq -r '.protocol_name' "$f")
      DRAFT_NAME=$(basename "$f" -report.json)
      # GitHub-compatible anchor
      ANCHOR=$(echo "$DRAFT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')
      echo "- [$DRAFT_NAME](#$ANCHOR)"
    done
    echo ""
  fi

  echo "---"
  echo ""

  # --- Per-draft sections ---
  for f in "${JSON_FILES[@]}"; do
    PROTOCOL=$(jq -r '.protocol_name' "$f")
    DRAFT_NAME=$(basename "$f" -report.json)
    RFCS=$(jq -r '.rfcs_analyzed | map(tostring) | join(", ")' "$f")
    SM_COUNT=$(jq -r '.state_machines_count' "$f")
    TOKENS=$(jq -r '.metadata.total_tokens_used // "N/A"' "$f")
    DURATION=$(jq -r '.metadata.analysis_duration_secs // 0 | . + 0.5 | floor' "$f")

    echo "## $DRAFT_NAME"
    echo ""
    echo "**Protocol:** $PROTOCOL  "
    echo "**State machines extracted:** $SM_COUNT  "
    echo "**Analysis tokens:** $TOKENS | **Duration:** ${DURATION}s  "
    echo ""

    # Get filtered & sorted leads
    LEADS=$(jq -c ".security_leads | $JQ_SEV_FILTER" "$f")
    LEAD_COUNT=$(echo "$LEADS" | jq 'length')

    if [[ "$LEAD_COUNT" -eq 0 ]]; then
      echo "*No security leads found matching the filter criteria.*"
      echo ""
      echo "---"
      echo ""
      continue
    fi

    # Iterate leads
    echo "$LEADS" | jq -c '.[]' | while IFS= read -r lead; do
      TECHNIQUE=$(echo "$lead" | jq -r '.technique_name')
      CATEGORY=$(echo "$lead" | jq -r '.category')
      RELATED_CATEGORIES=$(echo "$lead" | jq -r '
        .related_categories // [] | unique | join(", ")
      ')
      ASSESSMENT=$(echo "$lead" | jq -r '.assessment // "unclassified"')
      SECURITY_CONTEXT=$(echo "$lead" | jq -r '.security_context // empty')
      MERGED_COUNT=$(echo "$lead" | jq -r '.merged_lead_count // 1')
      SEVERITY=$(echo "$lead" | jq -r '.severity')
      CONFIDENCE=$(echo "$lead" | jq -r '.confidence')
      DESCRIPTION=$(echo "$lead" | jq -r '.description')
      MITIGATION=$(echo "$lead" | jq -r '.mitigation')
      PREREQS=$(echo "$lead" | jq -r '.prerequisites // [] | map("- " + .) | join("\n")')
      ENTITIES=$(echo "$lead" | jq -r '.entities_involved // [] | join(", ")')
      BADGE=$(sev_badge "$SEVERITY")

      echo "### $TECHNIQUE"
      echo ""
      LEAD_META="$BADGE | Confidence: $CONFIDENCE | Category: $CATEGORY | Assessment: $ASSESSMENT"
      if [[ "$MERGED_COUNT" -gt 1 ]]; then
        LEAD_META="$LEAD_META | Consolidated candidates: $MERGED_COUNT"
      fi
      echo "$LEAD_META"
      echo ""
      if [[ -n "$RELATED_CATEGORIES" && "$RELATED_CATEGORIES" != "$CATEGORY" ]]; then
        echo "**Related categories:** $RELATED_CATEGORIES  "
        echo ""
      fi
      echo "$DESCRIPTION"
      echo ""

      if [[ -n "$SECURITY_CONTEXT" ]]; then
        echo "**Specification/security context:** $SECURITY_CONTEXT"
        echo ""
      fi

      if [[ -n "$PREREQS" && "$PREREQS" != "" ]]; then
        echo "**Prerequisites:**"
        echo "$PREREQS"
        echo ""
      fi

      if [[ -n "$ENTITIES" && "$ENTITIES" != "" ]]; then
        echo "**Entities:** $ENTITIES  "
        echo ""
      fi

      # RFC references
      REFS=$(echo "$lead" | jq -c '.rfc_references // []')
      REF_COUNT=$(echo "$REFS" | jq 'length')
      if [[ "$REF_COUNT" -gt 0 ]]; then
        echo "**References:**"
        echo "$REFS" | jq -c '.[]' | while IFS= read -r ref; do
          RFC=$(echo "$ref" | jq -r '.rfc')
          SECTION=$(echo "$ref" | jq -r '.section')
          QUOTE=$(echo "$ref" | jq -r '.quote')
          echo "> RFC $RFC, Section $SECTION: *\"$QUOTE\"*"
          echo ""
        done
      fi

      echo "**Mitigation:** $MITIGATION"
      echo ""
      echo "---"
      echo ""
    done
  done

  echo "*Report generated by ietf-draft-analyzer*"

} > "$OUTPUT"

echo "Report written to: $OUTPUT"
echo "  Drafts: ${#JSON_FILES[@]}"
echo "  Total leads: $GRAND_TOTAL (critical=$GRAND_CRIT high=$GRAND_HIGH medium=$GRAND_MED low=$GRAND_LOW)"
