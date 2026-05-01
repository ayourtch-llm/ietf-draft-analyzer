# Implementation Spec Review — Phase 4 LLM Integration

**Reviewer**: Claude (Opus)
**Date**: 2026-05-01
**Scope**: `docs/specs/impl-phase4-llm.md` — implementability sign-off
**Prior verdict**: Codex passed this spec

## 1) Consistency with Design Specs

Checked against `architecture.md`, `database-schema.md`, `phase5-6-spec-additions.md`,
`llm-integration.md`, `cli-interface.md`, `pipeline-stages.md`, and `data-model.md`.

| Area | Status |
|------|--------|
| Error variants (5 LLM types) | Matches `phase5-6-spec-additions.md` §2 exactly |
| Migration v2 SQL | Matches `phase5-6-spec-additions.md` §1 exactly |
| `PROMPT_VERSION` constant | Matches `phase5-6-spec-additions.md` §3 |
| Delete order for `clear` | Matches `database-schema.md` §Delete Order |
| CLI `--format`/`--output` additions | Matches `cli-interface.md` and `phase5-6-spec-additions.md` §6 |
| Module structure (`src/llm/`, `src/commands/`) | Matches `architecture.md` §Module Structure |
| Concurrency: semaphore, no governor | Matches `phase5-6-spec-additions.md` §8 |
| CancellationToken shutdown | Matches `phase5-6-spec-additions.md` §9 |
| Content refusal: finish_reason primary, body fallback | Matches `phase5-6-spec-additions.md` §2 |
| Context budget formula | Matches `llm-integration.md` |
| `tokio-util` added, `governor` removed | Matches `dependencies.md` |

No cross-spec inconsistencies found.

## 2) Consistency with Phase 1-3 Code

Verified against the current codebase:

| Item | Phase 1-3 State | Spec Action | OK? |
|------|-----------------|-------------|-----|
| `RfcAnalyzerError` enum | 10 variants, no LLM types | Adds 5 LLM variants | Yes |
| `LlmConfig` | 7 fields, no methods | Adds `resolve_api_key()` | Yes |
| `MIGRATIONS` array | Version 1 only | Adds version 2 tuple | Yes |
| `main.rs` | 442 lines, 4 inline `cmd_*` fns | Moves to `src/commands/` | Yes |
| `src/commands/` | Does not exist | Created | Yes |
| `src/llm/` | Does not exist | Created | Yes |
| `Cargo.toml` | Has `governor`, no `tokio-util` | Swaps them | Yes |
| `cli.rs` `Analyze` | Has protocol/categories/min_severity | Adds output, format | Yes |
| `cli.rs` `Run` | Has protocol/rfcs/depth/output | Adds format | Yes |

No conflicts with existing code.

## 3) Concerns

### Nit 1 (non-blocking): `estimate_tokens` uses byte length

```rust
pub fn estimate_tokens(&self, text: &str) -> u64 {
    (text.len() as u64) / 4
}
```

The design specs say "chars / 4". `text.len()` returns bytes, not char count.
For ASCII-dominated RFC text this is equivalent, and for UTF-8 multi-byte
chars it's slightly conservative (overestimates), which is safe. The Phase 5
implementer should be aware that this is bytes/4, not chars/4.

### Nit 2 (non-blocking): `unsafe { std::env::set_var }` in tests

The test helper calls `unsafe { std::env::set_var("TEST_API_KEY", ...) }`.
With edition 2024 (MSRV 1.85+), `set_var` is `unsafe` so the syntax is
correct. However, `#[tokio::test]` runs on a multi-threaded runtime by
default, and concurrent `set_var` calls are a data race. The tests all use
the same env var name `"TEST_API_KEY"` with the same value `"test-key-123"`,
so this is benign in practice. The implementer could also use
`#[tokio::test(flavor = "current_thread")]` or `temp_env` crate to be safe,
but this is not blocking.

### Nit 3 (non-blocking): `estimate_tokens` omits the 30% safety margin

`phase5-6-spec-additions.md` §4 says the budget unit is "estimated tokens,
computed as `chars / 4` with a 30% safety margin." The `estimate_tokens`
function returns raw `len/4` without a margin. The 30% margin is distinct
from the `* 0.7` context window factor in `context_budget`. The Phase 5
summarize-to-fit implementation will need to apply the margin at the call
site. This is fine as long as the Phase 5 spec makes it explicit.

## 4) Verdict

**PASS for Phase 4 implementation.**

The spec is self-contained, internally consistent, aligned with all design
specs, and compatible with the Phase 1-3 codebase. The code blocks are
complete enough for an AI coding agent to implement without guessing. The
three nits above are non-blocking and can be addressed during implementation
or in the Phase 5 spec.
