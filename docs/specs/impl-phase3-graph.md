# Phase 3: Dependency Graph — Implementation Spec

This document is self-contained. It builds on Phase 1 and Phase 2
(which must be complete). Implement exactly what is specified here.

## Overview

Phase 3 adds the dependency graph layer: graph types, building a directed
graph from stored RFC data, graph queries, persistence to `dep_edges`, and
the `graph` CLI command with JSON and DOT export. At the end of Phase 3,
`rfc-analyzer graph tcp --format dot` produces a Graphviz-renderable graph.

## Files to Create / Modify

```
src/
  lib.rs           -- MODIFY: add graph and db::graph_store modules
  main.rs          -- MODIFY: wire up `graph` command
  graph/
    mod.rs         -- NEW: module re-exports
    model.rs       -- NEW: RfcNode, DepEdge, EdgeKind
    builder.rs     -- NEW: build StableDiGraph from DB data
    query.rs       -- NEW: graph traversal helpers
    export.rs      -- NEW: JSON and DOT export
  db/
    mod.rs         -- MODIFY: add graph_store
    graph_store.rs -- NEW: persist/load dep_edges
```

## 1. src/graph/model.rs

Graph node and edge types. These are used both in the in-memory petgraph
and in database persistence.

```rust
use crate::rfc::model::{RfcNumber, RfcStatus};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A node in the RFC dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcNode {
    pub rfc: RfcNumber,
    pub title: String,
    pub status: RfcStatus,
}

/// Edge direction: source → target.
/// Source is the document containing the reference.
/// Target is the document being referenced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEdge {
    pub kind: EdgeKind,
    /// Section in the source RFC (for CrossReference edges).
    pub source_section: Option<String>,
    /// Section in the target RFC (for CrossReference edges).
    pub target_section: Option<String>,
}

/// The kind of dependency between two RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// RFC A obsoletes RFC B (A is newer, replaces B).
    Obsoletes,
    /// RFC A updates RFC B (A modifies/extends B).
    Updates,
    /// RFC A normatively references RFC B.
    NormativeReference,
    /// RFC A informatively references RFC B.
    InformativeReference,
    /// Section in RFC A references section in RFC B.
    CrossReference,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeKind::Obsoletes => write!(f, "obsoletes"),
            EdgeKind::Updates => write!(f, "updates"),
            EdgeKind::NormativeReference => write!(f, "normative_ref"),
            EdgeKind::InformativeReference => write!(f, "informative_ref"),
            EdgeKind::CrossReference => write!(f, "cross_ref"),
        }
    }
}

impl EdgeKind {
    /// Parse from the string stored in the database.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "obsoletes" => Some(EdgeKind::Obsoletes),
            "updates" => Some(EdgeKind::Updates),
            "normative_ref" => Some(EdgeKind::NormativeReference),
            "informative_ref" => Some(EdgeKind::InformativeReference),
            "cross_ref" => Some(EdgeKind::CrossReference),
            _ => None,
        }
    }
}
```

## 2. src/graph/builder.rs

Builds a `petgraph::stable_graph::StableDiGraph` from RFC data stored in
the database. Reads all RFCs for a protocol (or a specific set of RFCs)
and creates edges based on their metadata, references, and cross-references.

```rust
use crate::error::Result;
use crate::graph::model::*;
use crate::rfc::model::*;
use petgraph::stable_graph::{NodeIndex, StableDiGraph};
use std::collections::HashMap;

/// The complete dependency graph for a set of RFCs.
pub struct DependencyGraph {
    pub graph: StableDiGraph<RfcNode, DepEdge>,
    /// Map from RFC number to node index for fast lookup.
    pub node_map: HashMap<RfcNumber, NodeIndex>,
}

impl DependencyGraph {
    /// Build a dependency graph from a list of parsed RFCs.
    pub fn build(rfcs: &[Rfc]) -> Self {
        let mut graph = StableDiGraph::new();
        let mut node_map = HashMap::new();

        // Create nodes
        for rfc in rfcs {
            let idx = graph.add_node(RfcNode {
                rfc: rfc.number,
                title: rfc.title.clone(),
                status: rfc.status,
            });
            node_map.insert(rfc.number, idx);
        }

        // Create edges
        for rfc in rfcs {
            let Some(&source_idx) = node_map.get(&rfc.number) else {
                continue;
            };

            // Obsoletes edges: source obsoletes target
            for target in &rfc.obsoletes {
                if let Some(&target_idx) = node_map.get(target) {
                    graph.add_edge(source_idx, target_idx, DepEdge {
                        kind: EdgeKind::Obsoletes,
                        source_section: None,
                        target_section: None,
                    });
                }
            }

            // Updates edges: source updates target
            for target in &rfc.updates {
                if let Some(&target_idx) = node_map.get(target) {
                    graph.add_edge(source_idx, target_idx, DepEdge {
                        kind: EdgeKind::Updates,
                        source_section: None,
                        target_section: None,
                    });
                }
            }

            // Formal references
            for reference in &rfc.references {
                if let Some(target_rfc) = reference.target_rfc {
                    if let Some(&target_idx) = node_map.get(&target_rfc) {
                        let kind = if reference.is_normative {
                            EdgeKind::NormativeReference
                        } else {
                            EdgeKind::InformativeReference
                        };
                        // Avoid duplicate edges of the same kind
                        let already_exists = graph
                            .edges_connecting(source_idx, target_idx)
                            .any(|e| e.weight().kind == kind);
                        if !already_exists {
                            graph.add_edge(source_idx, target_idx, DepEdge {
                                kind,
                                source_section: None,
                                target_section: None,
                            });
                        }
                    }
                }
            }

            // Cross-references from sections
            for section in &rfc.sections {
                for xref in &section.cross_refs {
                    if let Some(target_rfc) = xref.target_rfc {
                        if target_rfc == rfc.number {
                            continue; // skip self-references
                        }
                        if let Some(&target_idx) = node_map.get(&target_rfc) {
                            graph.add_edge(source_idx, target_idx, DepEdge {
                                kind: EdgeKind::CrossReference,
                                source_section: Some(section.number.clone()),
                                target_section: xref.target_section.clone(),
                            });
                        }
                    }
                }
            }
        }

        DependencyGraph { graph, node_map }
    }

    /// Get the node index for an RFC number.
    pub fn get_node(&self, rfc: RfcNumber) -> Option<NodeIndex> {
        self.node_map.get(&rfc).copied()
    }

    /// Get all RFC numbers in the graph.
    pub fn rfc_numbers(&self) -> Vec<RfcNumber> {
        self.graph.node_weights().map(|n| n.rfc).collect()
    }
}
```

## 3. src/graph/query.rs

Graph query helpers for analysis stages.

```rust
use crate::graph::builder::DependencyGraph;
use crate::graph::model::*;
use crate::rfc::model::RfcNumber;
use petgraph::algo::connected_components;
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

/// Summary statistics about the graph.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub connected_components: usize,
    pub most_referenced_rfcs: Vec<(RfcNumber, usize)>,
}

impl DependencyGraph {
    /// Compute summary statistics.
    pub fn summary(&self) -> GraphSummary {
        let total_nodes = self.graph.node_count();
        let total_edges = self.graph.edge_count();
        let components = connected_components(&self.graph);

        // Count incoming edges per node (most referenced = most incoming)
        let mut in_degree: HashMap<RfcNumber, usize> = HashMap::new();
        for edge in self.graph.edge_references() {
            let target = &self.graph[edge.target()];
            *in_degree.entry(target.rfc).or_default() += 1;
        }

        let mut most_referenced: Vec<(RfcNumber, usize)> =
            in_degree.into_iter().collect();
        most_referenced.sort_by(|a, b| b.1.cmp(&a.1));
        most_referenced.truncate(10);

        GraphSummary {
            total_nodes,
            total_edges,
            connected_components: components,
            most_referenced_rfcs: most_referenced,
        }
    }

    /// Get all RFCs directly referenced by a given RFC (outgoing edges).
    pub fn direct_references(&self, rfc: RfcNumber) -> Vec<(RfcNumber, EdgeKind)> {
        let Some(idx) = self.get_node(rfc) else {
            return Vec::new();
        };
        self.graph
            .edges(idx)
            .map(|e| {
                let target = &self.graph[e.target()];
                (target.rfc, e.weight().kind)
            })
            .collect()
    }

    /// Get all RFCs that reference a given RFC (incoming edges).
    pub fn referenced_by(&self, rfc: RfcNumber) -> Vec<(RfcNumber, EdgeKind)> {
        let Some(idx) = self.get_node(rfc) else {
            return Vec::new();
        };
        self.graph
            .edges_directed(idx, petgraph::Direction::Incoming)
            .map(|e| {
                let source = &self.graph[e.source()];
                (source.rfc, e.weight().kind)
            })
            .collect()
    }

    /// Get all edges of a specific kind.
    pub fn edges_of_kind(&self, kind: EdgeKind) -> Vec<(RfcNumber, RfcNumber)> {
        self.graph
            .edge_references()
            .filter(|e| e.weight().kind == kind)
            .map(|e| {
                let src = &self.graph[e.source()];
                let tgt = &self.graph[e.target()];
                (src.rfc, tgt.rfc)
            })
            .collect()
    }
}
```

## 4. src/graph/export.rs

Export the graph as JSON or Graphviz DOT format.

```rust
use crate::graph::builder::DependencyGraph;
use crate::graph::model::*;
use petgraph::visit::EdgeRef;
use serde::Serialize;

/// JSON-serializable representation of the graph.
#[derive(Serialize)]
pub struct GraphJson {
    pub nodes: Vec<GraphJsonNode>,
    pub edges: Vec<GraphJsonEdge>,
    pub summary: super::query::GraphSummary,
}

#[derive(Serialize)]
pub struct GraphJsonNode {
    pub rfc: u32,
    pub title: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct GraphJsonEdge {
    pub source: u32,
    pub target: u32,
    pub kind: String,
    pub source_section: Option<String>,
    pub target_section: Option<String>,
}

impl DependencyGraph {
    /// Export as a JSON-serializable structure.
    pub fn to_json(&self) -> GraphJson {
        let nodes: Vec<GraphJsonNode> = self
            .graph
            .node_weights()
            .map(|n| GraphJsonNode {
                rfc: n.rfc.0,
                title: n.title.clone(),
                status: n.status.to_string(),
            })
            .collect();

        let edges: Vec<GraphJsonEdge> = self
            .graph
            .edge_references()
            .map(|e| {
                let src = &self.graph[e.source()];
                let tgt = &self.graph[e.target()];
                let w = e.weight();
                GraphJsonEdge {
                    source: src.rfc.0,
                    target: tgt.rfc.0,
                    kind: w.kind.to_string(),
                    source_section: w.source_section.clone(),
                    target_section: w.target_section.clone(),
                }
            })
            .collect();

        GraphJson {
            nodes,
            edges,
            summary: self.summary(),
        }
    }

    /// Export as Graphviz DOT format.
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph rfc_deps {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled, fillcolor=lightyellow];\n\n");

        // Nodes
        for node in self.graph.node_weights() {
            // Escape quotes in title
            let label = node.title.replace('"', "\\\"");
            dot.push_str(&format!(
                "  rfc{} [label=\"RFC {}\\n{}\"];\n",
                node.rfc.0, node.rfc.0, label
            ));
        }

        dot.push('\n');

        // Edges
        for edge in self.graph.edge_references() {
            let src = &self.graph[edge.source()];
            let tgt = &self.graph[edge.target()];
            let w = edge.weight();

            let color = match w.kind {
                EdgeKind::Obsoletes => "red",
                EdgeKind::Updates => "orange",
                EdgeKind::NormativeReference => "blue",
                EdgeKind::InformativeReference => "gray",
                EdgeKind::CrossReference => "green",
            };

            let mut label = w.kind.to_string();
            if let Some(ref ss) = w.source_section {
                label.push_str(&format!(" (s{})", ss));
            }

            dot.push_str(&format!(
                "  rfc{} -> rfc{} [label=\"{}\", color={}];\n",
                src.rfc.0, tgt.rfc.0, label, color
            ));
        }

        dot.push_str("}\n");
        dot
    }
}
```

## 5. src/db/graph_store.rs

Persist and load dependency graph edges from the `dep_edges` table.

```rust
use crate::error::Result;
use crate::graph::model::*;
use crate::rfc::model::RfcNumber;
use tokio_rusqlite::Connection;

/// Store all edges from a DependencyGraph into the dep_edges table.
/// Clears existing edges for the involved RFCs first.
pub async fn store_edges(
    conn: &Connection,
    edges: &[(RfcNumber, RfcNumber, DepEdge)],
) -> Result<()> {
    let edges = edges.to_vec();
    conn.call(move |conn| {
        let tx = conn.transaction()?;
        for (source, target, edge) in &edges {
            tx.execute(
                "INSERT OR IGNORE INTO dep_edges
                    (source_rfc, target_rfc, kind, source_section, target_section)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    source.0,
                    target.0,
                    edge.kind.to_string(),
                    edge.source_section,
                    edge.target_section,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Load all edges from the dep_edges table.
pub async fn load_all_edges(
    conn: &Connection,
) -> Result<Vec<(RfcNumber, RfcNumber, DepEdge)>> {
    let result = conn
        .call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT source_rfc, target_rfc, kind, source_section, target_section
                 FROM dep_edges"
            )?;
            let edges: Vec<(RfcNumber, RfcNumber, DepEdge)> = stmt
                .query_map([], |row| {
                    let source = RfcNumber(row.get::<_, u32>(0)?);
                    let target = RfcNumber(row.get::<_, u32>(1)?);
                    let kind_str: String = row.get(2)?;
                    let kind = EdgeKind::from_db_str(&kind_str)
                        .unwrap_or(EdgeKind::CrossReference);
                    Ok((source, target, DepEdge {
                        kind,
                        source_section: row.get(3)?,
                        target_section: row.get(4)?,
                    }))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(edges)
        })
        .await?;
    Ok(result)
}

/// Load edges for a specific set of RFCs (by source or target).
pub async fn load_edges_for_rfcs(
    conn: &Connection,
    rfc_numbers: &[RfcNumber],
) -> Result<Vec<(RfcNumber, RfcNumber, DepEdge)>> {
    if rfc_numbers.is_empty() {
        return Ok(Vec::new());
    }
    let numbers: Vec<u32> = rfc_numbers.iter().map(|r| r.0).collect();
    let result = conn
        .call(move |conn| {
            // Build a WHERE clause with placeholders
            let placeholders: Vec<String> = (0..numbers.len())
                .map(|i| format!("?{}", i + 1))
                .collect();
            let sql = format!(
                "SELECT source_rfc, target_rfc, kind, source_section, target_section
                 FROM dep_edges
                 WHERE source_rfc IN ({ph}) OR target_rfc IN ({ph})",
                ph = placeholders.join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            // Bind parameters (need to double them for the two IN clauses)
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = numbers
                .iter()
                .chain(numbers.iter())
                .map(|n| Box::new(*n) as Box<dyn rusqlite::types::ToSql>)
                .collect();
            let edges: Vec<(RfcNumber, RfcNumber, DepEdge)> = stmt
                .query_map(rusqlite::params_from_iter(params), |row| {
                    let source = RfcNumber(row.get::<_, u32>(0)?);
                    let target = RfcNumber(row.get::<_, u32>(1)?);
                    let kind_str: String = row.get(2)?;
                    let kind = EdgeKind::from_db_str(&kind_str)
                        .unwrap_or(EdgeKind::CrossReference);
                    Ok((source, target, DepEdge {
                        kind,
                        source_section: row.get(3)?,
                        target_section: row.get(4)?,
                    }))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(edges)
        })
        .await?;
    Ok(result)
}

/// Delete all edges for a protocol's RFCs.
pub async fn clear_edges_for_protocol(
    conn: &Connection,
    protocol: &str,
) -> Result<()> {
    let protocol = protocol.to_string();
    conn.call(move |conn| {
        conn.execute(
            "DELETE FROM dep_edges WHERE source_rfc IN
                (SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1)
             OR target_rfc IN
                (SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1)",
            [&protocol],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}
```

## 6. src/graph/mod.rs

```rust
pub mod builder;
pub mod export;
pub mod model;
pub mod query;
```

## 7. src/db/mod.rs (updated)

```rust
pub mod schema;
pub mod rfc_store;
pub mod graph_store;
```

## 8. src/lib.rs (updated)

```rust
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod graph;
pub mod rfc;
```

## 9. src/main.rs — Add `graph` command

Add this function and wire it into the match in main:

```rust
// In the match cli.command block, add:
Command::Graph { target, format } => {
    cmd_graph(&conn, &target, &format).await?;
}
```

```rust
/// The `graph` command: show dependency graph for a protocol or RFC.
async fn cmd_graph(
    conn: &tokio_rusqlite::Connection,
    target: &str,
    format: &str,
) -> Result<()> {
    use rfc_analyzer::db::{rfc_store, graph_store};
    use rfc_analyzer::graph::builder::DependencyGraph;

    // Determine if target is an RFC number or protocol name
    let rfc_numbers = if let Ok(num) = target.parse::<u32>() {
        // Single RFC — show its immediate graph
        vec![rfc_analyzer::rfc::model::RfcNumber(num)]
    } else {
        // Protocol name — get all associated RFCs
        let rfcs = rfc_store::get_protocol_rfcs(conn, target).await?;
        if rfcs.is_empty() {
            anyhow::bail!(
                "No RFCs found for protocol '{}'. Run 'map --protocol {}' first.",
                target, target
            );
        }
        rfcs
    };

    // Load all RFC data
    let mut rfcs = Vec::new();
    for rfc_num in &rfc_numbers {
        if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num.0).await? {
            rfcs.push(rfc);
        }
    }

    if rfcs.is_empty() {
        anyhow::bail!("No RFC data found in database.");
    }

    // Build graph
    let dep_graph = DependencyGraph::build(&rfcs);

    // Also persist edges to database
    let edges: Vec<_> = dep_graph.graph.edge_references().map(|e| {
        let src = &dep_graph.graph[e.source()];
        let tgt = &dep_graph.graph[e.target()];
        (src.rfc, tgt.rfc, e.weight().clone())
    }).collect();
    graph_store::store_edges(conn, &edges).await?;

    // Export
    match format {
        "dot" => {
            print!("{}", dep_graph.to_dot());
        }
        "json" | _ => {
            let json = dep_graph.to_json();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}
```

Also update the `cmd_map` function to build and persist the graph after
fetching all RFCs. Add this at the end of `cmd_map`, before the final
log message:

```rust
    // Build and persist dependency graph
    {
        use rfc_analyzer::graph::builder::DependencyGraph;
        use rfc_analyzer::db::graph_store;

        let mut all_rfcs = Vec::new();
        for &rfc_num in &processed.iter().copied().collect::<Vec<_>>() {
            if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num).await? {
                all_rfcs.push(rfc);
            }
        }

        let dep_graph = DependencyGraph::build(&all_rfcs);
        let edges: Vec<_> = dep_graph.graph.edge_references().map(|e| {
            let src = &dep_graph.graph[e.source()];
            let tgt = &dep_graph.graph[e.target()];
            (src.rfc, tgt.rfc, e.weight().clone())
        }).collect();

        graph_store::store_edges(conn, &edges).await?;
        let summary = dep_graph.summary();
        tracing::info!(
            "Graph: {} nodes, {} edges, {} components",
            summary.total_nodes, summary.total_edges,
            summary.connected_components
        );
    }
```

## 10. Tests

### src/graph/builder.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::model::*;
    use chrono::NaiveDate;

    fn make_rfc(num: u32, title: &str, obsoletes: Vec<u32>, refs: Vec<(u32, bool)>) -> Rfc {
        Rfc {
            number: RfcNumber(num),
            title: title.to_string(),
            format: RfcFormat::Xml,
            status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
            obsoletes: obsoletes.into_iter().map(RfcNumber).collect(),
            updates: Vec::new(),
            obsoleted_by: Vec::new(),
            updated_by: Vec::new(),
            sections: Vec::new(),
            references: refs.into_iter().map(|(rfc, normative)| Reference {
                label: format!("[RFC{}]", rfc),
                target_rfc: Some(RfcNumber(rfc)),
                title: String::new(),
                is_normative: normative,
            }).collect(),
            raw_text: String::new(),
            content_hash: String::new(),
        }
    }

    #[test]
    fn test_build_empty() {
        let graph = DependencyGraph::build(&[]);
        assert_eq!(graph.graph.node_count(), 0);
        assert_eq!(graph.graph.edge_count(), 0);
    }

    #[test]
    fn test_build_single_rfc() {
        let rfcs = vec![make_rfc(9293, "TCP", vec![], vec![])];
        let graph = DependencyGraph::build(&rfcs);
        assert_eq!(graph.graph.node_count(), 1);
        assert_eq!(graph.graph.edge_count(), 0);
    }

    #[test]
    fn test_obsoletes_edge() {
        let rfcs = vec![
            make_rfc(9293, "TCP (new)", vec![793], vec![]),
            make_rfc(793, "TCP (old)", vec![], vec![]),
        ];
        let graph = DependencyGraph::build(&rfcs);
        assert_eq!(graph.graph.node_count(), 2);
        assert_eq!(graph.graph.edge_count(), 1);

        let edges = graph.edges_of_kind(EdgeKind::Obsoletes);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0], (RfcNumber(9293), RfcNumber(793)));
    }

    #[test]
    fn test_reference_edges() {
        let rfcs = vec![
            make_rfc(9293, "TCP", vec![], vec![(793, true), (1122, false)]),
            make_rfc(793, "Old TCP", vec![], vec![]),
            make_rfc(1122, "Host Req", vec![], vec![]),
        ];
        let graph = DependencyGraph::build(&rfcs);

        let normative = graph.edges_of_kind(EdgeKind::NormativeReference);
        assert_eq!(normative.len(), 1);
        assert_eq!(normative[0], (RfcNumber(9293), RfcNumber(793)));

        let informative = graph.edges_of_kind(EdgeKind::InformativeReference);
        assert_eq!(informative.len(), 1);
        assert_eq!(informative[0], (RfcNumber(9293), RfcNumber(1122)));
    }

    #[test]
    fn test_cross_reference_edges() {
        let mut rfc_a = make_rfc(9293, "TCP", vec![], vec![]);
        rfc_a.sections.push(Section {
            number: "3".to_string(),
            title: "Functional Spec".to_string(),
            anchor: None,
            depth: 1,
            text: "See RFC 793 Section 2.".to_string(),
            cross_refs: vec![CrossRef {
                target_rfc: Some(RfcNumber(793)),
                target_section: Some("2".to_string()),
                context: "See RFC 793 Section 2.".to_string(),
            }],
            pn: None,
        });
        let rfc_b = make_rfc(793, "Old TCP", vec![], vec![]);
        let graph = DependencyGraph::build(&[rfc_a, rfc_b]);

        let xrefs = graph.edges_of_kind(EdgeKind::CrossReference);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0], (RfcNumber(9293), RfcNumber(793)));
    }

    #[test]
    fn test_self_references_skipped() {
        let mut rfc = make_rfc(9293, "TCP", vec![], vec![]);
        rfc.sections.push(Section {
            number: "3".to_string(),
            title: "Spec".to_string(),
            anchor: None,
            depth: 1,
            text: "See Section 1.".to_string(),
            cross_refs: vec![CrossRef {
                target_rfc: Some(RfcNumber(9293)), // self-reference
                target_section: Some("1".to_string()),
                context: "See Section 1.".to_string(),
            }],
            pn: None,
        });
        let graph = DependencyGraph::build(&[rfc]);
        assert_eq!(graph.graph.edge_count(), 0);
    }

    #[test]
    fn test_summary() {
        let rfcs = vec![
            make_rfc(9293, "TCP", vec![793], vec![(1122, true)]),
            make_rfc(793, "Old TCP", vec![], vec![]),
            make_rfc(1122, "Host Req", vec![], vec![]),
        ];
        let graph = DependencyGraph::build(&rfcs);
        let summary = graph.summary();
        assert_eq!(summary.total_nodes, 3);
        assert_eq!(summary.total_edges, 2);
        assert!(summary.most_referenced_rfcs.len() <= 10);
    }

    #[test]
    fn test_references_to_unknown_rfcs_ignored() {
        // Reference to an RFC not in the graph — should not create an edge
        let rfcs = vec![make_rfc(9293, "TCP", vec![], vec![(99999, true)])];
        let graph = DependencyGraph::build(&rfcs);
        assert_eq!(graph.graph.edge_count(), 0);
    }
}
```

### src/db/graph_store.rs — async tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;

    #[tokio::test]
    async fn test_store_and_load_edges() {
        let conn = open_memory_database().await.unwrap();

        // Need RFCs in the database first (foreign keys)
        use crate::db::rfc_store;
        use crate::rfc::model::*;
        use chrono::NaiveDate;

        let rfc1 = Rfc {
            number: RfcNumber(9293), title: "TCP".to_string(),
            format: RfcFormat::Xml, status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
            obsoletes: vec![], updates: vec![],
            obsoleted_by: vec![], updated_by: vec![],
            sections: vec![], references: vec![],
            raw_text: "text".to_string(), content_hash: "h1".to_string(),
        };
        let rfc2 = Rfc {
            number: RfcNumber(793), title: "Old TCP".to_string(),
            format: RfcFormat::PlainText, status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(1981, 9, 1).unwrap(),
            obsoletes: vec![], updates: vec![],
            obsoleted_by: vec![], updated_by: vec![],
            sections: vec![], references: vec![],
            raw_text: "text".to_string(), content_hash: "h2".to_string(),
        };
        rfc_store::upsert_rfc(&conn, &rfc1).await.unwrap();
        rfc_store::upsert_rfc(&conn, &rfc2).await.unwrap();

        let edges = vec![
            (RfcNumber(9293), RfcNumber(793), DepEdge {
                kind: EdgeKind::Obsoletes,
                source_section: None,
                target_section: None,
            }),
        ];
        store_edges(&conn, &edges).await.unwrap();

        let loaded = load_all_edges(&conn).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, RfcNumber(9293));
        assert_eq!(loaded[0].1, RfcNumber(793));
        assert_eq!(loaded[0].2.kind, EdgeKind::Obsoletes);
    }

    #[tokio::test]
    async fn test_store_edges_deduplicates() {
        let conn = open_memory_database().await.unwrap();

        use crate::db::rfc_store;
        use crate::rfc::model::*;
        use chrono::NaiveDate;

        let rfc1 = Rfc {
            number: RfcNumber(1), title: "A".to_string(),
            format: RfcFormat::Xml, status: RfcStatus::Unknown,
            date: NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
            obsoletes: vec![], updates: vec![],
            obsoleted_by: vec![], updated_by: vec![],
            sections: vec![], references: vec![],
            raw_text: "t".to_string(), content_hash: "a".to_string(),
        };
        let rfc2 = Rfc { number: RfcNumber(2), title: "B".to_string(),
            ..rfc1.clone()
        };
        // Fix: rfc2 needs its own content_hash and number set properly
        let mut rfc2 = rfc1.clone();
        rfc2.number = RfcNumber(2);
        rfc2.title = "B".to_string();
        rfc2.content_hash = "b".to_string();

        rfc_store::upsert_rfc(&conn, &rfc1).await.unwrap();
        rfc_store::upsert_rfc(&conn, &rfc2).await.unwrap();

        let edge = (RfcNumber(1), RfcNumber(2), DepEdge {
            kind: EdgeKind::NormativeReference,
            source_section: None,
            target_section: None,
        });

        // Insert twice — should not duplicate
        store_edges(&conn, &[edge.clone()]).await.unwrap();
        store_edges(&conn, &[edge]).await.unwrap();

        let loaded = load_all_edges(&conn).await.unwrap();
        assert_eq!(loaded.len(), 1);
    }
}
```

### src/graph/export.rs — tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::builder::DependencyGraph;
    use crate::rfc::model::*;
    use chrono::NaiveDate;

    fn make_test_graph() -> DependencyGraph {
        let rfcs = vec![
            Rfc {
                number: RfcNumber(9293), title: "TCP".to_string(),
                format: RfcFormat::Xml, status: RfcStatus::Standard,
                date: NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
                obsoletes: vec![RfcNumber(793)],
                updates: vec![], obsoleted_by: vec![], updated_by: vec![],
                sections: vec![], references: vec![],
                raw_text: String::new(), content_hash: String::new(),
            },
            Rfc {
                number: RfcNumber(793), title: "Old TCP".to_string(),
                format: RfcFormat::PlainText, status: RfcStatus::Historic,
                date: NaiveDate::from_ymd_opt(1981, 9, 1).unwrap(),
                obsoletes: vec![], updates: vec![],
                obsoleted_by: vec![], updated_by: vec![],
                sections: vec![], references: vec![],
                raw_text: String::new(), content_hash: String::new(),
            },
        ];
        DependencyGraph::build(&rfcs)
    }

    #[test]
    fn test_to_json() {
        let graph = make_test_graph();
        let json = graph.to_json();
        assert_eq!(json.nodes.len(), 2);
        assert_eq!(json.edges.len(), 1);
        assert_eq!(json.edges[0].source, 9293);
        assert_eq!(json.edges[0].target, 793);
        assert_eq!(json.edges[0].kind, "obsoletes");
    }

    #[test]
    fn test_to_dot() {
        let graph = make_test_graph();
        let dot = graph.to_dot();
        assert!(dot.starts_with("digraph rfc_deps {"));
        assert!(dot.contains("rfc9293"));
        assert!(dot.contains("rfc793"));
        assert!(dot.contains("rfc9293 -> rfc793"));
        assert!(dot.contains("color=red")); // obsoletes = red
        assert!(dot.ends_with("}\n"));
    }
}
```

## 11. Verification

After implementation:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all tests (builder, query, export, graph_store)
3. `cargo run -- map 9293 --depth 1 --protocol tcp` fetches and stores
   RFCs with graph edges
4. `cargo run -- graph tcp --format dot > tcp.dot && dot -Tsvg tcp.dot -o tcp.svg`
   produces a valid SVG graph
5. `cargo run -- graph tcp --format json` outputs valid JSON with nodes,
   edges, and summary
6. `cargo run -- graph 9293` works with a single RFC number

## 12. What This Phase Does NOT Include

- LLM integration (Phase 4)
- Protocol modeling / state machines (Phase 5)
- Security analysis (Phase 6)
- The `model`, `analyze`, `run` commands remain stubs
