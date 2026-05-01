# Implementation Spec Review 5-1 — Phase 5 Protocol Modeling

**Reviewer**: Claude (Opus)
**Date**: 2026-05-01
**Scope**: `docs/specs/impl-phase5-modeling.md` — thorough implementability review
**Method**: Line-by-line spec read, cross-referenced against all design specs,
Phase 4 impl spec, and all Phase 1-3 source files

## 1) Design Spec Consistency

### Matches

| Claim | Design Spec | Verified |
|-------|-------------|----------|
| Stage 2 pipeline flow (cluster → extract → validate → store) | `pipeline-stages.md` §Stage 2 | Match |
| `ClusteringResponse` / `StateMachineResponse` JSON schemas | `llm-integration.md` §Prompt Templates | Match |
| State machine keyed by `(protocol, name, run_id)` | `database-schema.md`, `phase5-6-spec-additions.md` §1 | Match |
| Summarize-to-fit: 60% full text, remainder summary, then drop | `phase5-6-spec-additions.md` §4 | Match |
| Scoring: +3 cross-ref, +2 RFC2119, +2 Security, +1 xref-in-scope | `phase5-6-spec-additions.md` §4 | Match (with additions, see Issue 4) |
| Numeric-segment section comparison | `phase5-6-spec-additions.md` §4 | Match |
| Summary extraction: first sentence + RFC 2119 + xref sentences | `phase5-6-spec-additions.md` §4 step 3 | Partial (see Issue 1) |
| Stage 2 input hash: 8 inputs in canonical order | `phase5-6-spec-additions.md` §10 | Match |
| Hash ordering: RFCs ascending, sections by `(rfc_number, section_num)` | `phase5-6-spec-additions.md` §10 | Match |
| Context budget = `window * 0.7 - max_tokens - system_prompt` | `llm-integration.md` line 81 | Match |
| `estimate_tokens` = `chars / 4` | `llm-integration.md` line 69 | Match |
| Validation: transitions → defined states, orphan states | `pipeline-stages.md` §Stage 2 step 3 | Partial (see Issue 2) |
| Run provenance: `analysis_runs` with `input_hash` | `database-schema.md` §analysis_runs | Match |
| Work item tracking with `run_work_items` | `phase5-6-spec-additions.md` §1 | Match |
| Context overflow → skip work item, warn | `phase5-6-spec-additions.md` §2 | Match |
| Content refusal → skip work item, warn | `phase5-6-spec-additions.md` §2 | Match |
| Fatal errors → fail run | `phase5-6-spec-additions.md` §2 | Match |
| Cancellation → set status 'interrupted', persist partial | `phase5-6-spec-additions.md` §9 | Match |
| Resumability: check completed work items, skip | `phase5-6-spec-additions.md` §1 | Match |

### Mismatches

Detailed below as Issues 1-4.

## 2) Phase 1-4 Code Consistency

### Type Checks

| Type/Field | Expected | Spec Usage | OK? |
|------------|----------|------------|-----|
| `RfcNumber(pub u32)`, `Copy`, `Clone`, `Eq`, `Hash` | model.rs:6-7 | `.0` access, `Copy` in iterators | Yes |
| `Section.number: String` | model.rs:113 | `sec.number.as_str()`, `&section.number` | Yes |
| `Section.title: String` | model.rs:114 | `sec.title.as_str()` | Yes |
| `Section.text: String` | model.rs:116 | `.contains()`, `.split('.')` | Yes |
| `Section.depth: u8` | model.rs:115 | Test uses `depth: 1` — coerces to u8 | Yes |
| `Section.cross_refs: Vec<CrossRef>` | model.rs:118 | Iterated for scoring | Yes |
| `CrossRef.target_rfc: Option<RfcNumber>` | model.rs:125 | `.map_or(false, \|r\| r.0 == ...)` | Yes |
| `CrossRef.target_section: Option<String>` | model.rs:126 | `.as_deref() == Some(&...)` | Yes |
| `LlmConfig.temperature: f32` | config.rs:26 | `.to_string()` in hash | Yes |
| `LlmConfig.model_context_window: u64` | config.rs:30 | `.to_string()` in hash | Yes |
| `LlmConfig.max_tokens_per_request: u32` | config.rs:24 | `.to_string()` in hash | Yes |
| `LlmClient.config: LlmConfig` (private) | Phase 4 spec | Cannot access — spec passes `llm_config` separately | Yes (necessary) |
| `LlmClient::model() -> &str` | Phase 4 spec line 377 | Used for hash | Yes |
| `LlmClient::cancel_token() -> &CancellationToken` | Phase 4 spec line 382 | Used for cancellation check | Yes |
| `LlmClient::estimate_tokens(&self, &str) -> u64` | Phase 4 spec line 363 | Used for budget | Yes |
| `LlmClient::context_budget(&self, u64) -> u64` | Phase 4 spec line 371 | Used for budget | Yes |
| `LlmClient::chat_json<T>` returns `Result<(T, TokenUsage)>` | Phase 4 spec line 232 | Destructured at lines 800, 897 | Yes |
| `rfc_store::get_protocol_rfcs` returns `Result<Vec<RfcNumber>>` | rfc_store.rs:316 | Used at line 728 | Yes |
| `rfc_store::get_rfc(conn, u32)` returns `Result<Option<Rfc>>` | rfc_store.rs:145 | Used at line 775, 1008 | Yes |
| `Rfc.sections: Vec<Section>` | model.rs:104 | Iterated, moved into all_sections | Yes |
| `prompts::PROMPT_VERSION: &str` | Phase 4 spec line 595 | Used in hash and create_run | Yes |
| `prompts::INJECTION_DEFENSE: &str` | Phase 4 spec line 611 | Used for token estimation | Yes |
| `prompts::format_section(u32, &str, &str, &str) -> String` | Phase 4 spec line 603 | Used in summarize | Yes |
| `prompts::mechanism_clustering_prompt(&str, &[(u32, &str, &str)])` | Phase 4 spec line 614 | Used at line 794 | Yes |
| `prompts::state_machine_prompt(&str, &str, &str)` | Phase 4 spec line 630 | Used at line 891 | Yes |
| `open_memory_database()` is `#[cfg(test)] pub async fn` | db/mod.rs:25-26 | Used in test modules (both `#[cfg(test)]`) | Yes |

### Compile Check

- All imports present in each code block. `use rusqlite::OptionalExtension;`
  enables `.optional()` in query methods — correct.
- `(RfcNumber, &Section)` is `Copy` (both components are `Copy`) — `.copied()` works.
- `serde_json::to_string` in `create_run` works with fully-qualified path (no use needed).
- `rusqlite::params!` macro accessible without explicit `use`.
- `Sha256::new()` / `.update()` / `.finalize()` with `{:x}` format — correct for `sha2` crate.
- `TransitionResponse` has `#[serde(default)]` on `conditions`/`actions` — correct,
  LLMs may omit these fields.
- Test `Rfc` structs have all 13 required fields — verified against model.rs.

## 3) Issues Found

### Issue 1 (Medium): `extract_summary` omits "MAY" and "OPTIONAL" from RFC 2119 keywords

`extract_summary` (line 556-557) filters for 8 RFC 2119 keywords:

```rust
let rfc2119_keywords = ["MUST", "MUST NOT", "SHALL", "SHALL NOT",
    "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED"];
```

But `compute_relevance_score` (line 521-522) uses the full set of 10:

```rust
let rfc2119_keywords = ["MUST", "MUST NOT", "SHALL", "SHALL NOT",
    "SHOULD", "SHOULD NOT", "REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL"];
```

The design spec (`phase5-6-spec-additions.md` §4 step 3) says:
> "Any sentences containing RFC 2119 keywords"

It does not distinguish which keywords — the term "RFC 2119 keywords" refers
to all 10 as defined by RFC 2119. The omission of MAY/OPTIONAL in
`extract_summary` means the summary will drop sentences like
"Implementations MAY support..." which could be relevant.

**Fix**: Add "MAY" and "OPTIONAL" to the keywords list in `extract_summary`,
matching the scoring function and the design spec.

### Issue 2 (Low): Validation omits unreachable state check

`validate_state_machine` checks two things:
1. Transitions reference defined states
2. Orphan states (no transitions in or out)

But `pipeline-stages.md` §Stage 2 step 3 lists three checks:
> - All transitions reference defined states
> - Flag orphan states (no incoming or outgoing transitions)
> - **Flag unreachable states**

Unreachable states (states that exist with transitions but cannot be reached
from any initial state via the transition graph) are not checked. This
requires identifying initial states and doing reachability analysis, which
is harder since the LLM response doesn't explicitly mark initial states.

This is low severity since validation is warnings-only. An implementer can
use a heuristic: states with no incoming transitions and at least one
outgoing transition are likely initial states; anything not reachable from
those is unreachable. Or the check can be deferred.

**Fix**: Either add a reachability check with a heuristic for initial states,
or add a comment: `// TODO: unreachable state detection deferred (needs
initial state heuristic)`.

### Issue 3 (Medium): Clustering call failure leaves run in orphaned "running" status

In `run_stage2`, the clustering LLM call (line 800) uses bare `?`:

```rust
let (clustering, usage) = llm.chat_json::<ClusteringResponse>(messages).await?;
```

If this fails (401, 403, network error, etc.), the error propagates up and
the function returns. But the run was already created at line 754 with
status `'running'`. It is never marked as `'failed'`.

**Consequence**: On next invocation with the same inputs,
`find_resumable_run` finds the orphaned run and resumes it. The clustering
call fails again. The user is stuck in a retry loop until they manually
`clear analysis`.

Compare with per-mechanism error handling (lines 934-953), which correctly
marks the run as failed for fatal errors. The clustering call lacks
equivalent handling.

**Fix**: Wrap the clustering call in error handling:

```rust
let (clustering, usage) = match llm.chat_json::<ClusteringResponse>(messages).await {
    Ok(result) => result,
    Err(e) => {
        analysis_store::complete_run(
            conn, run_id, "failed", 0, &rfc_numbers, Some(&e.to_string())
        ).await?;
        return Err(e);
    }
};
```

### Issue 4 (Nit): +10 score for in-cluster sections not in design spec

`compute_relevance_score` adds `+10` for sections that are in the cluster
(line 498-500):

```rust
if is_in_cluster {
    score += 10;
}
```

The design spec's scoring table (`phase5-6-spec-additions.md` §4) lists
`+3`, `+2`, `+2`, `+1`, `+0` — no `+10` bonus. The `+10` is a reasonable
implementation detail that ensures cluster sections always rank above
cross-referenced context sections. But its absence from the design spec
could confuse an implementer cross-checking the scoring logic.

**Fix**: Add a comment: `// Implementation bonus: ensures cluster sections
always rank above contextual support sections (not in design spec scoring
table, which only covers non-cluster candidates)`.

### Issue 5 (Nit): Empty `sections_text` after summarization is sent to LLM

If ALL candidate sections are dropped by `summarize_to_fit` (because even
summaries exceed the budget), `sections_text` is an empty string. The
post-summarization budget check (line 881):

```rust
if llm.estimate_tokens(&sections_text) > budget {
```

passes (0 tokens ≤ budget), so the code proceeds to call
`state_machine_prompt(protocol, mechanism, "")` with empty sections.

In practice this is nearly unreachable — even a summary of the shortest
section would be a few bytes, and the budget is typically ~85k tokens. But
a guard would be clean:

```rust
if sections_text.is_empty() {
    // All sections dropped — nothing to analyze
    analysis_store::complete_work_item(..., true, Some("All sections dropped")).await?;
    continue;
}
```

### Issue 6 (Nit): `use rusqlite::OptionalExtension;` placement

The `use rusqlite::OptionalExtension;` statement appears at the bottom of
the `analysis_store.rs` code block (line 352), after all function
definitions. This is valid Rust but stylistically unusual. An AI implementer
might miss it, causing compile errors on `.optional()` calls.

**Fix**: Move to the top with other `use` statements.

## 4) Test Coverage Assessment

| Component | Test Coverage |
|-----------|--------------|
| `compare_section_nums` | 6 cases including numeric, alpha, unequal depth — Good |
| `extract_summary` | First sentence + RFC 2119 keyword inclusion — Good |
| `validate_state_machine` | Clean, undefined state, orphan — Good |
| `create_run` / `find_completed_run` / `complete_run` | Full lifecycle — Good |
| `upsert_work_item` / `complete_work_item` / `get_completed_work_items` | Full lifecycle — Good |
| `store_state_machine` / `get_state_machines` | Store + retrieve by run_id — Good |
| `compute_stage2_hash` | 7 input variations + determinism check — Excellent |
| `summarize_to_fit` | **No direct test** — only component tests | Gap |
| `compute_relevance_score` | **No direct test** | Gap |
| `run_stage2` end-to-end | Guidance only, no code | Expected gap (integration test) |
| `find_resumable_run` | **No test** | Gap |
| `get_state_machines` with `run_id: None` (latest run query) | **No test** | Gap |

The test gaps for `summarize_to_fit` and `compute_relevance_score` are the
most significant — these are complex functions with scoring logic that
should have targeted unit tests. The integration test guidance (Section 7,
lines 1406-1417) is adequate for the end-to-end flow.

## 5) Compile Verification

Traced every public API boundary:

- `cmd_model` calls `LlmClient::new(config.llm.clone(), cancel_token)` —
  `LlmConfig: Clone` ✓, `CancellationToken` passed by value ✓
- `cmd_model` calls `run_stage2(conn, &llm, protocol, mechanism_filter, &config.llm)` —
  `mechanism_filter: Option<&[String]>` from `mechanisms.as_deref()` on
  `Option<Vec<String>>` ✓
- `cancel_token` is moved from main.rs match arm into `cmd_model` — Phase 4
  main.rs creates token, clones for ctrl_c handler, moves original to
  command handler ✓
- main.rs match arm `Command::Model { protocol, mechanisms }` — matches
  cli.rs `Model { protocol: String, mechanisms: Option<Vec<String>> }` ✓

No compile issues found.

## 6) Verdict

**PASS — with one recommended fix (Issue 3).**

Issue 3 (clustering failure leaves orphaned run) is the most significant
finding. Without the fix, any non-transient error during mechanism
clustering (bad API key, model not found, etc.) creates a run stuck in
"running" status that blocks future attempts until manually cleared. The
fix is 5 lines of error handling.

Issues 1 and 2 are design spec deviations that should be fixed but won't
cause incorrect behavior (just slightly less thorough summaries/validation).

Issues 4-6 are nits. The test coverage is good for a spec of this scope,
though `summarize_to_fit` and `compute_relevance_score` deserve targeted
unit tests.
