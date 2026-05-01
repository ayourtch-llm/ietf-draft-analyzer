# Code Review 3.1 — Phase 3 Dependency Graph

## 1) Summary

Phase 3 is implemented cleanly and mostly follows
`docs/specs/impl-phase3-graph.md`. The graph model, builder, query helpers,
JSON/DOT export, edge persistence, module wiring, `graph` command, and map-time
graph persistence are all present. The implementation is warning-free and the
test suite passes.

Verdict: ready to proceed, with one correctness concern to fix soon: persisted
graph edges are appended/deduplicated but not cleared during map or graph
rebuilds, so stale edges can remain after RFC data changes.

## 2) Spec Compliance

Matches the spec:

- `src/graph/model.rs` defines `RfcNode`, `DepEdge`, `EdgeKind`,
  `Display`, and `from_db_str()` as specified.
- `src/graph/builder.rs` builds a `StableDiGraph<RfcNode, DepEdge>` with
  nodes, metadata edges, formal reference edges, and cross-reference edges.
- Edge direction follows the design convention: source RFC contains the
  reference, target RFC is referenced.
- `src/graph/query.rs` provides graph summary, outgoing references,
  incoming references, and edge-kind filtering.
- `src/graph/export.rs` provides JSON and DOT export with the requested
  node/edge structure.
- `src/db/graph_store.rs` persists and loads `dep_edges`, supports filtered
  edge loading, and provides protocol edge clearing.
- `src/db/mod.rs`, `src/lib.rs`, and `src/graph/mod.rs` expose the expected
  modules.
- `src/main.rs` wires the `graph` command and persists graph edges after
  `map`.

Notable deviations or implementation choices:

- `query.rs` uses a custom undirected BFS component counter instead of
  `petgraph::algo::connected_components`. This is acceptable and avoids any
  `StableGraph` trait mismatch.
- `graph_store::store_edges()` manually checks for existing rows instead of
  relying on `INSERT OR IGNORE`. This is better than the spec because SQLite
  `UNIQUE` constraints do not treat `NULL` values as equal.
- `graph <RFC>` intentionally builds a graph from only that RFC's stored data,
  so references to other cached RFCs are not shown unless those RFCs are part of
  the selected input set. This matches the final accepted interpretation of the
  spec, but it is a limited single-node view.

## 3) Code Quality Issues

- `main.rs` now contains ingestion, clearing, graph building, and export command
  logic in one file. This is acceptable for Phase 3, but before Phase 4+ the
  command handlers should probably move into a CLI command module or pipeline
  layer to keep LLM and graph orchestration from making `main.rs` too large.

- `graph_store::load_edges_for_rfcs()` dynamically builds SQL with boxed
  `ToSql` trait objects. It works, but it is more complex than needed. A helper
  for dynamic `IN` clauses would be useful as more DB query functions arrive.

- DOT export escapes quotes in node labels but not backslashes, newlines, or
  other DOT-significant characters. RFC titles are usually tame, but robust DOT
  escaping should be centralized before exports are treated as stable output.

- Unknown DB edge kinds silently become `CrossReference` in `load_all_edges()`
  and `load_edges_for_rfcs()`. This is tolerant, but it can hide database
  corruption or future schema drift. Returning an error would be safer for a
  durable project database.

## 4) Bugs or Correctness Concerns

- Persisted graph edges can become stale. `store_edges()` explicitly does not
  clear existing edges, and neither `cmd_map` nor `cmd_graph` calls
  `clear_edges_for_protocol()` or otherwise deletes the previous edge set before
  persisting rebuilt edges. If an RFC is reparsed and a reference disappears, or
  if parser behavior changes, old `dep_edges` rows remain in the database. The
  in-memory/exported graph for the current command is correct, but the persisted
  graph table can accumulate stale edges.

- `cmd_map` only builds a graph from RFCs processed in the current run. If a
  protocol already has assigned RFCs from an earlier run and the new map command
  processes a subset, persisted protocol graph state may not represent the full
  protocol unless edges are rebuilt from all `protocol_rfcs` or explicitly scoped
  to the current run.

- The graph builder ignores edges to RFCs not present in the input set. This is
  consistent with the no-boundary-node design, but graph completeness depends
  entirely on Phase 2 expansion and cache state. The `graph <RFC>` command in
  particular can produce a node with no edges even when referenced RFCs are
  already cached.

- Duplicate metadata/cross-reference edges can still be added in memory if the
  source RFC data contains duplicate `obsoletes`, `updates`, or duplicate
  cross-reference entries. Persistence deduplicates rows, but summary counts and
  exports are based on the in-memory graph before persistence.

## 5) Verdict

Ready to proceed past Phase 3.

Recommended near-term fix: clear persisted edges for the graph scope before
storing a rebuilt graph, especially in `cmd_map`. That can be done before Phase
4 without changing the public graph model.
