# Design Review 2.4 — Sign-Off Review

**Reviewer**: Claude
**Date**: 2026-05-01
**Scope**: Updated specs for Phase 4-6 implementation readiness

## 1) Remaining Blocking Issues

**None.**

All 11 concerns from review 2-2 have been addressed:

| # | Concern | Resolution |
|---|---------|------------|
| 1 | `provider` has no config source | Removed from cache key. Removed from `ReportMetadata`. |
| 2 | Dotted section sort order wrong | Numeric-segment comparison now specified (`phase5-6:195-198`, `phase5-6:387-389`) |
| 3 | `run` missing `--format` | Added, passed through to analyze (`cli-interface:85`) |
| 4 | Text/markdown output unspecified | Explicitly deferred to future version (`cli-interface:70`, `phase5-6:246,267`) |
| 5 | `CARGO_PKG_VERSION` in cache key too coarse | Removed from cache key (`phase5-6:351-381`). Kept in `ReportMetadata` for provenance only. |
| 6 | `llm/rate_limit.rs` vestigial | Removed from module structure (`architecture:79-87`) |
| 7 | `pipeline-stages.md` stale `(protocol, name)` | Updated to `(protocol, name, run_id)` (`pipeline-stages:117`) |
| 8 | `run_work_items.input_hash` undefined | Explicitly marked "reserved for future use in v1; set to NULL" (`phase5-6:53`) |
| 9 | Summarize-to-fit scoring ambiguous | Clarified: "Sections cross-referenced BY sections in the cluster but not themselves in the cluster" (`phase5-6:201`) |
| 10 | FK delete order undocumented for `clear rfcs` | Full delete order for all scopes documented (`database-schema:266-283`) |
| 11 | Content refusal detection fragile | `finish_reason` now primary signal, body-pattern is fallback only (`phase5-6:149-161`) |

Cross-spec consistency verified:
- `data-model.md` `ReportMetadata` matches `phase5-6` Section 5 (no `provider`)
- `pipeline-stages.md` Stage 2 Step 4 says `(protocol, name, run_id)`
- `dependencies.md` has `tokio-util`, no `governor`
- `architecture.md` module structure has no `rate_limit.rs`
- `database-schema.md` has `ON DELETE CASCADE` on v2 FKs, full delete order documented
- `llm-integration.md` uses semaphore, no governor reference
- `cli-interface.md` has `--format` on both `analyze` and `run`

**One nit** (non-blocking): `database-schema.md` line 88 has a trailing comma in the `cross_refs` CREATE TABLE SQL before the closing `)`. This is a SQL syntax error that the implementer will need to drop. It's a spec typo, not a design issue.

## 2) Verdict

**PASS for Phase 4-6 implementation.**

The specs are internally consistent, the contracts are precise enough for an implementation agent to work from without guessing, and the remaining design debt is explicitly deferred (text/markdown output, per-item input hashes). The migration, error handling, cache-key manifest, summarize-to-fit strategy, concurrency model, graceful shutdown, and delete-order semantics are all implementation-ready.
