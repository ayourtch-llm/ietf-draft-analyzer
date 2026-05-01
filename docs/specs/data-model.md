# Data Model

All core types live in their respective modules and derive `Debug`, `Clone`,
`Serialize`, `Deserialize`.

## RFC Types (`rfc/model.rs`)

### RfcNumber

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RfcNumber(pub u32);
```

### RfcFormat

```rust
pub enum RfcFormat { Xml, PlainText }
```

### RfcStatus

```rust
pub enum RfcStatus {
    Standard,
    ProposedStandard,
    BestCurrentPractice,
    Informational,
    Experimental,
    Historic,
    Unknown,
}
```

### Rfc

The fully parsed RFC document:

```rust
pub struct Rfc {
    pub number: RfcNumber,
    pub title: String,
    pub format: RfcFormat,
    pub status: RfcStatus,
    pub date: NaiveDate,
    pub obsoletes: Vec<RfcNumber>,
    pub updates: Vec<RfcNumber>,
    pub obsoleted_by: Vec<RfcNumber>,
    pub updated_by: Vec<RfcNumber>,
    pub sections: Vec<Section>,
    pub references: Vec<Reference>,
    pub raw_text: String,            // full text for LLM context
    pub content_hash: String,        // SHA-256 for incremental cache
}
```

### Section

A section within an RFC, possibly nested:

```rust
pub struct Section {
    pub number: String,              // "3.4.1"
    pub title: String,
    pub anchor: Option<String>,      // XML anchor attribute
    pub depth: u8,                   // nesting level
    pub text: String,                // section body content
    pub cross_refs: Vec<CrossRef>,   // references found within this section
    pub pn: Option<String>,          // XML pn attribute
}
```

### CrossRef

A cross-reference found inline in section text:

```rust
pub struct CrossRef {
    pub target_rfc: Option<RfcNumber>,   // None for internal refs
    pub target_section: Option<String>,  // "3.2" or anchor name
    pub context: String,                 // surrounding sentence
}
```

### Reference

An entry from the References section:

```rust
pub struct Reference {
    pub label: String,               // "[16]" or "RFC0793"
    pub target_rfc: Option<RfcNumber>,
    pub title: String,
    pub is_normative: bool,          // normative vs informative
}
```

## Graph Types (`graph/model.rs`)

### RfcNode

```rust
pub struct RfcNode {
    pub rfc: RfcNumber,
    pub title: String,
    pub status: RfcStatus,
}
```

### DepEdge

Edge direction convention: source → target, where the source document
contains the reference and the target is the document being referenced.
See `pipeline-stages.md` for the full direction table.

```rust
pub struct DepEdge {
    pub kind: EdgeKind,
    pub source_section: Option<String>,  // section in source RFC (for cross-refs)
    pub target_section: Option<String>,  // section in target RFC (for cross-refs)
}
```

### EdgeKind

```rust
pub enum EdgeKind {
    /// RFC A obsoletes RFC B (A is newer, replaces B)
    Obsoletes,
    /// RFC A updates RFC B (A modifies/extends B)
    Updates,
    /// RFC A normatively references RFC B
    NormativeReference,
    /// RFC A informatively references RFC B
    InformativeReference,
    /// Section in RFC A references section in RFC B
    CrossReference,
}
```

Note: section-level detail for `CrossReference` edges is carried in
`DepEdge.source_section` and `DepEdge.target_section`, not in the enum
variant, to avoid duplicating section fields.

## Protocol Modeling Types (`pipeline/modeling.rs`)

### ProtocolState

```rust
pub struct ProtocolState {
    pub name: String,
    pub description: String,
    pub source_rfc: RfcNumber,
    pub source_section: String,
}
```

### StateTransition

```rust
pub struct StateTransition {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub conditions: Vec<String>,
    pub actions: Vec<String>,
    pub source_rfc: RfcNumber,
    pub source_section: String,
}
```

### ProtocolStateMachine

```rust
pub struct ProtocolStateMachine {
    pub name: String,               // e.g., "TCP Connection Establishment"
    pub mechanism: String,          // e.g., "auth_flow", "message_format"
    pub states: Vec<ProtocolState>,
    pub transitions: Vec<StateTransition>,
    pub involved_rfcs: Vec<RfcNumber>,
}
```

## Security Analysis Types (`pipeline/analysis.rs`)

### AttackCategory

```rust
pub enum AttackCategory {
    MissingValidation,
    InformationLeak,
    ReplayAttack,
    OversizedPayload,
    StateConfusion,
    AuthBypass,
    DenialOfService,
    Downgrade,
    RaceCondition,
    ImplementationAmbiguity,
}
```

### Severity

```rust
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}
```

### SecurityLead

A single security finding/lead:

```rust
pub struct SecurityLead {
    pub id: String,                       // UUID v4
    pub technique_name: String,
    pub category: AttackCategory,
    pub severity: Severity,
    pub confidence: f32,                  // 0.0 - 1.0
    pub description: String,             // step-by-step attack description
    pub rfc_references: Vec<RfcSectionRef>,
    pub prerequisites: Vec<String>,
    pub entities_involved: Vec<String>,   // client, server, resolver, etc.
    pub related_state_machine: Option<String>,
    pub mitigation: Option<String>,
}
```

### RfcSectionRef

```rust
pub struct RfcSectionRef {
    pub rfc: RfcNumber,
    pub section: String,
    pub quote: Option<String>,           // exact text from the spec
}
```

## Report Types (`output/report.rs`)

### AnalysisReport

```rust
pub struct AnalysisReport {
    pub protocol_name: String,
    pub rfcs_analyzed: Vec<RfcNumber>,
    pub dependency_graph_summary: GraphSummary,
    pub state_machines: Vec<ProtocolStateMachine>,
    pub security_leads: Vec<SecurityLead>,
    pub metadata: ReportMetadata,
}
```

### ReportMetadata

```rust
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub model_used: String,
    pub total_tokens_used: u64,
    pub analysis_duration_secs: f64,
}
```

### GraphSummary

```rust
pub struct GraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub connected_components: usize,
    pub most_referenced_rfcs: Vec<(RfcNumber, usize)>,
}
```
