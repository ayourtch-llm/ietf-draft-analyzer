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
     (`--- RFC {N}, Section {X.Y} ({title}) ---`)
   - Send to the LLM with the state machine extraction prompt
   - Parse the JSON response into `ProtocolState` + `StateTransition` structs

3. **Validate**: Check structural consistency:
   - All transitions reference defined states
   - Flag orphan states (no incoming or outgoing transitions)
   - Flag unreachable states
   - Log warnings but don't fail

4. **Store**: Serialize each `ProtocolStateMachine` as JSON and store in
   the `state_machines` table, keyed by `(protocol, name)`.

### Context Window Handling

If a mechanism cluster's combined section text exceeds the context budget:
1. Split sections into chunks that fit
2. Process each chunk, asking the LLM to extract partial state machines
3. Merge: union of states, union of transitions, deduplicate by name

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

3. **Deduplicate**: Merge leads that reference the same RFC section and
   the same attack category. Keep the higher-confidence version.

4. **Score and rank**: Sort by `severity * confidence`:
   - Critical = 5, High = 4, Medium = 3, Low = 2, Informational = 1
   - Final score = severity_weight * confidence

5. **Filter**: Remove leads below `min_severity`

6. **Store**: Write leads to `security_leads` table

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
  - `MissingValidation`: "MUST", "validate", "check", "verify", "parse"
  - `ReplayAttack`: "nonce", "sequence", "timestamp", "freshness"
  - `InformationLeak`: "error", "response", "metadata", "header"
  - etc.

This keeps LLM context focused and reduces token usage.
