# Pipeline Stages

## Stage 1: Dependency Mapping (`pipeline/dependency.rs`)

### Input
- `Vec<RfcNumber>` — seed RFCs the user cares about
- `depth: u32` — how many levels of transitive references to follow
- `normative_only: bool` — whether to skip informative references

### Output
- Populated `petgraph::stable_graph::StableDiGraph<RfcNode, DepEdge>`
- All parsed RFCs, sections, and cross-references stored in SQLite

### Steps

1. **Fetch seed RFCs**: For each seed RFC number:
   - Check SQLite cache first (skip if `content_hash` matches)
   - Try XML format: `https://www.rfc-editor.org/rfc/rfc{N}.xml`
   - Fall back to plain text: `https://www.rfc-editor.org/rfc/rfc{N}.txt`
   - Cache which format worked to avoid future 404s
   - **404 handling**: If both XML and text return 404 (RFC does not exist,
     is not yet published, or was never assigned), log a warning and skip
     the RFC. Do not create a graph node for it. Any edges that would have
     pointed to it are dropped. This is expected for older RFCs that
     reference Internet-Drafts by eventual RFC number or for reserved
     number ranges. Seed RFC 404s are errors (fail the stage); transitive
     reference 404s are warnings (skip and continue).

2. **Parse**: Route to `parser_xml.rs` or `parser_text.rs` based on format:
   - Extract metadata: title, status, date, obsoletes/updates lists
   - Extract section structure with numbering and nesting
   - Extract inline cross-references within section text
   - Extract formal References section (normative vs informative)
   - Compute `content_hash` (SHA-256 of raw content)

3. **Store**: Write parsed `Rfc` to SQLite (sections, cross_refs tables)

4. **Expand**: Collect all referenced RFC numbers from:
   - `obsoletes` / `updates` metadata (always followed regardless of `normative_only`)
   - Normative references (always)
   - Informative references (if `!normative_only`)
   - Inline cross-references
   All discovered RFCs are fetched and parsed immediately. The `depth`
   parameter controls how many levels of transitive references are followed
   (depth=0 means seed RFCs only, depth=1 means seeds + their direct
   references, etc.). There are no unfetched "boundary" nodes — every RFC
   in the graph has been fully ingested.

5. **Build graph**: Create `petgraph` directed graph:
   - One node per RFC
   - Edges for: obsoletes, updates, normative ref, informative ref, cross-ref
   - Cross-ref edges include source/target section numbers
   - Persist edges to `dep_edges` table

   **Edge direction convention** (source → target):
   - `Obsoletes`: A → B means "RFC A obsoletes RFC B" (A is newer)
   - `Updates`: A → B means "RFC A updates RFC B" (A modifies B)
   - `NormativeReference`: A → B means "RFC A normatively references RFC B"
   - `InformativeReference`: A → B means "RFC A informatively references RFC B"
   - `CrossReference`: A → B means "section in RFC A references section in RFC B"

   In all cases, the arrow points from the document containing the reference
   to the document being referenced.

6. **LLM pass** (optional): For ambiguous plain-text references (e.g.,
   "as described above", "the mechanism in the previous document"), ask
   the LLM to resolve the target. This is used sparingly.

### Cross-Reference Extraction

**XML format** — high precision:
- `<xref target="RFC1234" section="3.2">` elements parsed directly

**Plain text** — regex patterns:
- `Section\s+(\d+(?:\.\d+)*)\s+of\s+\[RFC\s*(\d+)\]` — section + RFC
- `\[RFC\s*(\d+)\]` — document-level reference
- `see\s+Section\s+(\d+(?:\.\d+)*)` — internal section reference
- `described\s+in\s+\[RFC\s*(\d+)\]` — narrative reference

Each match captures surrounding context (the enclosing sentence) for
the `context` field.

## Stage 2: Protocol Modeling (`pipeline/modeling.rs`)

### Input
- Protocol name (e.g., "dns", "tcp")
- Dependency graph + all parsed sections from Stage 1
- Optional mechanism filter

### Output
- `Vec<ProtocolStateMachine>` stored in SQLite

### Steps

1. **Identify mechanism clusters**: Send all section titles (with RFC
   provenance) to the LLM, asking it to group them by protocol mechanism:
   - Authentication / authorization
   - Message format / encoding
   - Error handling / recovery
   - Connection management / state
   - Extensions / negotiation
   - Security considerations

2. **Extract state machines**: For each mechanism cluster:
   - Concatenate the relevant section texts with provenance markers
     (`<<<RFC_SECTION rfc="{N}" section="{X.Y}" title="{title}">>>...<<<END_RFC_SECTION>>>`)
   - Send to the LLM with the state machine extraction prompt
   - Parse the JSON response into `ProtocolState` + `StateTransition` structs

3. **Validate**: Check structural consistency:
   - All transitions reference defined states
   - Flag orphan states (no incoming or outgoing transitions)
   - Flag unreachable states
   - Log warnings but don't fail

4. **Store**: Serialize each `ProtocolStateMachine` as JSON and store in
   the `state_machines` table, keyed by `(protocol, name, run_id)`.

### Context Window Handling

If a mechanism cluster's combined section text exceeds the context budget:

1. **Preferred: summarize to fit.** Summarize less-relevant sections (keeping
   the most state-machine-dense sections in full) to fit within the context
   window. This avoids the cross-chunk consistency problems of splitting.

2. **Fallback: warn and skip.** If summarization still exceeds the budget,
   log a warning identifying the oversized cluster and skip it. The user
   can re-run with a narrower `--mechanisms` filter or a model with a
   larger context window.

Chunked extraction with merge-by-name is **not used** — it produces
unreliable results because independent chunks generate inconsistent state
names and miss cross-chunk references. A proper multi-pass extraction
strategy may be added in a future version.

## Stage 3: Security Analysis (`pipeline/analysis.rs`)

### Input
- Protocol name
- Dependency graph + state machines + all parsed sections
- Optional category filter and minimum severity

### Output
- `Vec<SecurityLead>` (typically 50-200 ranked leads per protocol)
- Final `AnalysisReport` as JSON

### Steps

1. **Generate security questions**: For each attack category (10 categories),
   instantiate the prompt template with:
   - Protocol-specific context
   - Relevant state machine summaries
   - Relevant RFC sections (selected by mechanism relevance)

2. **Run analysis**: For each category:
   - Select the most relevant sections and state machine context
   - Send to the LLM with the security analysis prompt
   - Parse `Vec<SecurityLead>` from the JSON response

3. **Persist incrementally**: Write leads to `security_leads` table as
   each category completes. This ensures partial results survive
   interruptions. Track per-category completion in the run manifest so
   that resumed runs skip already-completed categories.

4. **Deduplicate**: Merge leads that share overlapping RFC section
   references, similar technique names, and the same attack category.
   Use section overlap + normalized technique name, not just
   section + category (which is too coarse — multiple distinct
   vulnerabilities can exist in one section).

5. **Score and rank**: Sort primarily by severity tier, then by
   confidence within each tier:
   - Tier ordering: Critical > High > Medium > Low > Informational
   - Within each tier, sort by confidence descending
   This avoids the problem of confidence-as-linear-multiplier
   overriding severity in the ranking.

6. **Filter**: Remove leads below `min_severity`

7. **Generate report**: Assemble `AnalysisReport` with:
   - Protocol name and RFC list
   - Graph summary (node/edge counts, most-referenced RFCs)
   - State machines
   - Ranked security leads
   - Metadata (timestamp, model, token usage, duration)

### Section Selection Heuristic

Not all sections are relevant to all categories. For each category,
prioritize:
- Sections with "Security Considerations" in the title (always included)
- Sections referenced by the relevant state machine
- Sections containing keywords related to the category:

| Category | Keywords |
|---|---|
| `MissingValidation` | "validate", "check", "verify", "parse", "reject", "malformed", "invalid" |
| `ReplayAttack` | "nonce", "sequence", "timestamp", "freshness", "idempotent", "replay" |
| `InformationLeak` | "error", "diagnostic", "metadata", "header", "reveal", "expose", "disclose" |
| `OversizedPayload` | "length", "size", "maximum", "limit", "truncat", "overflow", "buffer" |
| `StateConfusion` | "state", "transition", "unexpected", "simultaneous", "order", "sequence" |
| `AuthBypass` | "authenticat", "authoriz", "credential", "identity", "trust", "verify" |
| `DenialOfService` | "resource", "limit", "exhaust", "flood", "timeout", "retry", "amplif" |
| `Downgrade` | "version", "negotiat", "fallback", "legacy", "backward", "compatible" |
| `RaceCondition` | "concurrent", "simultaneous", "atomic", "lock", "order", "between" |
| `ImplementationAmbiguity` | "undefined", "unspecified", "implementation-defined", "MAY", "OPTIONAL", "local matter" |

Note: Avoid overly broad keywords. "MUST" was intentionally excluded from
`MissingValidation` because it matches nearly every normative section.
Keywords use substring matching, so "authenticat" matches both
"authentication" and "authenticated".

This keeps LLM context focused and reduces token usage.
