# Code Review 2.1 — Phase 2 RFC Ingestion

## 1) Summary

Phase 2 is implemented substantially according to
`docs/specs/impl-phase2-ingestion.md`. The CLI is wired for `map`, `show`, and
`clear`; RFC fetching supports XML/text fallback; XML and plain-text parsers
produce the Phase 1 `Rfc` model; RFC index metadata is fetched and applied; and
the module wiring matches the intended layout. The implementation builds and
tests cleanly.

Verdict: ready for Phase 3, with known parser and cache-staleness caveats to
carry forward.

## 2) Spec Compliance

Matches the spec:

- `src/cli.rs` defines the requested Clap command structure, including Phase 2
  commands plus stubs for later phases.
- `src/rfc/fetcher.rs` implements XML-first/text-fallback fetching,
  user-agent configuration, per-session successful-format caching, SHA-256
  content hashing, polite delay, and distinct `RfcNotFound` behavior only when
  both formats are 404.
- `src/rfc/parser_xml.rs` implements the specified streaming `quick-xml`
  parser shape and extracts document metadata, sections, xrefs, references,
  dates, and raw text.
- `src/rfc/parser_text.rs` implements the specified regex-based parser for
  title, status, date, obsoletes/updates, sections, xrefs, and formal
  references.
- `src/rfc/index.rs` fetches and parses `rfc-index.txt`, including
  `obsoleted_by` and `updated_by`.
- `src/main.rs` replaces the Phase 1 stub with CLI dispatch for `map`, `show`,
  and `clear`, and leaves later commands as not-yet-implemented.
- `src/rfc/mod.rs` and `src/lib.rs` expose the expected modules.
- `tests/fetch_real.rs` provides the ignored live RFC fetch/parser validation
  requested by the spec.

Notable deviations or interpretation choices:

- `fetch_rfc_index()` maps network/read failures into `RfcAnalyzerError::Config`
  rather than a fetch-specific error. This follows the loose style of the spec,
  but semantically these are fetch errors.
- The implementation does not create or use local parser fixture files, which
  the spec described as guidance rather than a hard requirement. Given the
  passing test suite and ignored live-fetch test, this is acceptable for now.
- `clear` validates scope before executing SQL and uses one branch for
  `all | rfcs`. This is a small improvement over the spec.

## 3) Code Quality Issues

- The parsers are intentionally best-effort, but most parser helpers are private
  and tested only through narrow unit cases. That is fine for Phase 2, but
  Phase 3 will depend heavily on graph edge completeness, so parser regression
  fixtures should be added soon.

- `RfcFetcher` stores successful format as a `String` with values `"xml"` or
  `"text"`. A small enum would reduce typo risk and align better with
  `RfcFormat`, though this is not a blocker.

- `fetch_rfc_index()` creates a fresh `reqwest::Client` instead of reusing the
  fetcher client/user-agent path. This is harmless now, but the project will
  eventually want one consistent HTTP policy for user-agent, retries, and
  timeout behavior.

- Error typing is still coarse for HTTP status failures. Non-404 fetch status
  errors are wrapped as `Config`, which makes downstream error handling less
  precise.

## 4) Bugs or Correctness Concerns

- Cached RFCs skip index metadata refresh. In `cmd_map`, if an RFC already has a
  stored `content_hash`, the code loads it, collects references, optionally
  assigns the protocol, and continues without applying fresh RFC index metadata.
  This preserves stale `obsoleted_by` / `updated_by` data. This is the Phase 1
  same-hash no-op concern surfacing in Phase 2. It is not a blocker for Phase 3,
  but it should be addressed before relying on update/obsolete metadata for
  long-lived databases.

- XML nested section handling is lossy. `parse_xml()` keeps only one
  `current_section`; when a nested `<section>` starts, the parent section is
  immediately finalized and not restored after the child ends. This is workable
  for a flattened section list, but parent text appearing after a child section
  will not be attached to the parent. RFC XML often nests sections, so this can
  reduce section-text fidelity for later LLM analysis.

- XML xref context can be empty or weak. `<xref/>` elements are captured as
  cross-references but their textual marker is not inserted into section text.
  `extract_context_sentence()` then searches for strings like `"RFC 793"`, which
  may never appear in the accumulated text if the reference only existed as an
  XML element. Graph construction can still use the target, but context quality
  is poor.

- Plain-text reference extraction only captures single-line reference entries.
  Many RFC references wrap the title, RFC number, or DOI across multiple lines.
  The current parser will often store an empty title and may miss non-`[RFC1234]`
  labels that contain RFC numbers later in the wrapped entry.

- Plain-text section extraction can match table-of-contents lines as real
  sections. The regex scans the entire document and does not explicitly skip the
  table of contents. This can produce duplicate or low-quality section bodies in
  classic text RFCs.

- `cmd_map` marks an RFC as processed before fetch/parse succeeds. For
  transitive 404s this is acceptable, but for transient non-404 failures a
  partial run can count an RFC as processed in memory and then fail the whole
  command. There is no persistent damage, but progress logs may overstate work
  completed.

## 5) Verdict

Ready for Phase 3.

No fixes are required before graph implementation. The main risks to carry
forward are parser fidelity and cached metadata staleness. Phase 3 graph tests
should include stored RFCs with formal references, inline cross-references, and
update/obsolete metadata so these ingestion limitations are visible early.
