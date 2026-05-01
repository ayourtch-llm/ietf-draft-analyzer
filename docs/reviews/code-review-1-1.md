# Code Review 1.1 — Phase 1 Foundation

## 1) Summary

Phase 1 is implemented cleanly and closely follows
`docs/specs/impl-phase1-foundation.md`. The project has the expected module
layout, compiles warning-free, includes `Cargo.lock`, initializes SQLite through
`tokio-rusqlite`, runs migrations, validates configuration, and round-trips RFC
data including sections, cross-references, raw text compression, protocol
assignments, and formal references.

The implementation is ready for Phase 2. The remaining issues are mostly
defensive-hardening concerns and one cache-staleness behavior that Phase 2
should account for when RFC metadata or parser behavior changes without a raw
content hash change.

## 2) Spec Compliance

Matches the spec:

- `Cargo.toml` includes the Phase 1 dependency set and uses edition 2024.
- `src/error.rs` defines the requested `RfcAnalyzerError` variants and shared
  `Result<T>` alias.
- `src/config.rs` implements the requested TOML model, defaults, missing-file
  behavior, and structural validation ranges.
- `src/rfc/model.rs` matches the requested core RFC data model and display
  helpers.
- `src/db/schema.rs` implements migration version 1, `schema_version`, required
  pragmas, and all Phase 1 tables including the updated `references_json`
  column.
- `src/db/mod.rs` opens file and in-memory databases through `tokio-rusqlite`
  and runs pragmas plus migrations on connection startup.
- `src/db/rfc_store.rs` implements the requested RFC CRUD surface:
  `upsert_rfc`, `get_content_hash`, `get_rfc`, `list_rfc_numbers`,
  `assign_protocol`, and `get_protocol_rfcs`.
- `src/main.rs` remains the expected minimal Phase 1 entry point.
- The tests listed in the spec are present, including the later additions for
  invalid TOML, references round-trip, duplicate cross-ref preservation,
  same-hash no-op behavior, old-section removal, and foreign-key failure on
  missing protocol RFC assignment.

Deviations:

- `Cargo.toml` uses `assert-json-diff = "2"` while the spec says
  `assert_json_diff = "2"`. This is an acceptable correction: the published
  crate name uses hyphens.
- `references_json` is present in the implementation and Phase 1 spec. This
  also appears to have been propagated to `database-schema.md`, so there is no
  current design/spec conflict.

## 3) Code Quality Issues

- `src/db/rfc_store.rs` silently falls back to empty data for JSON parse
  failures in stored RFC relationship arrays and `references_json`. This keeps
  reads tolerant, but it can hide database corruption or schema drift. For a
  project-artifact database, returning an error would be safer than silently
  dropping relationships.

- `src/db/rfc_store.rs` silently defaults invalid dates to `1970-01-01` and
  unknown stored formats to `PlainText`. This mirrors the permissive style in
  the spec, but it weakens auditability. Bad persisted data should probably be
  surfaced as a parse/storage error once ingestion is implemented.

- `serde_json::to_string(...)` calls use `unwrap()` or fall back to `"[]"`.
  These serializations should not fail for the current types, so this is low
  risk, but using `?` with `RfcAnalyzerError::Json` would be more consistent
  with the error model.

- `open_memory_database()` is `#[cfg(test)]`, which is fine for current unit
  tests. If later integration tests under `tests/` need it, they will not be
  able to call it because integration tests compile the crate as a dependency.

## 4) Bugs or Correctness Concerns

- The same-`content_hash` no-op in `upsert_rfc` can preserve stale derived
  metadata. If Phase 2 reprocesses an RFC with identical raw content but better
  parser output, corrected sections, refreshed `references_json`, or updated
  RFC-index metadata (`obsoleted_by` / `updated_by`), `upsert_rfc` will skip
  the update entirely. This behavior is specified and tested, but Phase 2
  should either avoid calling `upsert_rfc` for refreshed metadata, add a
  separate metadata update path, or include parser/index versioning in the
  freshness decision later.

- `sections` still enforces `UNIQUE(rfc_number, section_num)`. This is
  consistent with the current spec, but it remains a known future risk for
  unnumbered sections, repeated generated section numbers, appendices, or
  anchor-only XML sections.

- No cascade behavior is encoded in the schema. This matches the Phase 1 spec,
  but future `clear` behavior must delete in the right order, as planned in
  later phases.

## 5) Verdict

Ready for Phase 2.

No Phase 1 fixes are required before proceeding. The main thing to carry into
Phase 2 is the same-hash no-op behavior: it is correct per spec, but it can
block refreshed parser/index metadata unless Phase 2 explicitly handles that
case.
