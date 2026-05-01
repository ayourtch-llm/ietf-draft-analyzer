# Design Review 2.5 — Final Gate

## Verdict

**FAIL — one remaining stale spec inconsistency.**

The prior SQL typo in `cross_refs` is fixed, and the Phase 5-6 additions are
otherwise coherent. However, `docs/specs/database-schema.md` still has the old
Stage 2/3 input-hash summary:

- Stage 2: `hash of input section texts + prompt version + model name + mechanism filter`
- Stage 3: `hash of state machines + input sections + prompt version + model name + category filter`

This conflicts with the canonical manifest in
`docs/specs/phase5-6-spec-additions.md`, which also includes sorted RFC lists,
temperature, `max_tokens_per_request`, and `model_context_window`.
`architecture.md` correctly points to the canonical manifest, but
`database-schema.md` still says its shorter list covers "all factors that affect
output." That would trip an implementation agent building cache-key logic from
the database spec.

## Required Fix

Update `docs/specs/database-schema.md` Incrementality to either point directly
to `phase5-6-spec-additions.md` Section 10, like `architecture.md` does, or
repeat the full canonical Stage 2/3 manifests exactly.

After that correction, the spec set is ready for Phase 4-6 implementation
specs.
