# Regression Validation Strategy

## Purpose

The RFC Analyzer should be validated against protocols with **known CVEs** that
were discovered through specification analysis. If the tool analyzes these
protocols and fails to surface leads related to these known vulnerabilities,
something is wrong with the analysis pipeline.

These fixtures are derived from the DreamGroup Black Hat Asia talk that
introduced the original RFC Analyzer concept. The CVEs listed below were
reportedly discovered using RFC-level specification analysis.

## How to Use

For each protocol fixture:
1. Run the full pipeline: `rfc-analyzer run <protocol> <seed_rfcs> --depth 2`
2. Check that the output contains at least one lead that **matches or
   overlaps** with the known CVE's vulnerability class and affected RFC sections
3. The tool does NOT need to produce the exact CVE — it needs to surface a
   lead in the same area that a human reviewer would recognize as related

## Scoring

- **Hit**: A lead references the relevant RFC section(s) AND the correct
  attack category. The technique description is recognizably related.
- **Near miss**: A lead references the correct RFC but a different section,
  or the correct section but a different (adjacent) attack category.
- **Miss**: No lead in the output relates to the known vulnerability.

Target for v1: at least 4 of 6 known CVEs should be hits or near misses.
