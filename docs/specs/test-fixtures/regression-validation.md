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

## Fixture Types

The fixtures test two fundamentally different capabilities:

**Type A — Spec-level weakness** (3 fixtures): The specification itself has a
gap, ambiguity, or missing constraint. This is the tool's core value
proposition — finding vulnerabilities that exist in the spec before
implementations are even written.
- Kerberos CVE-2025-59088: Cross-section DNS trust gap in RFC 4120; the
  concrete CVE impact is `kdcproxy` SSRF through attacker-controlled SRV
  records
- IPv6 CVE-2012-4444: Cross-RFC hardening adoption gap
- Telnet CVE-2026-32746: Missing length limit in RFC 1184

**Type B — Implementation ignores clear spec requirement** (1 fixture, 3
example CVEs): The spec clearly requires a behavior, but implementations
fail to follow it. The tool surfaces the normative requirement, which can
then be converted to a code-level search pattern.
- TLS 1.3 CVE-2025-12765, CVE-2026-25644, CVE-2026-31798: Certificate
  validation disabled despite RFC 8446 Appendix C.5

## Scoring

- **Hit**: A lead references the relevant RFC section(s) AND the correct
  attack category. The technique description is recognizably related.
- **Near miss**: A lead references the correct RFC but a different section,
  or the correct section but a different (adjacent) attack category.
- **Miss**: No lead in the output relates to the known vulnerability.

**Targets (scored separately by type):**
- Type A: at least 2 of 3 fixtures should be hits or near misses
- Type B: at least 1 of 1 fixture should be a hit or near miss

Type A is the harder and more important benchmark. A tool that passes
Type B but fails Type A is finding obvious requirements, not subtle
specification weaknesses.
