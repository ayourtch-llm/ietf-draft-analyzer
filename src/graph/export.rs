use crate::graph::builder::DependencyGraph;
use crate::graph::model::*;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
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

#[cfg(test)]
mod tests {
    use crate::graph::builder::DependencyGraph;
    use crate::rfc::model::*;
    use chrono::NaiveDate;

    fn make_test_graph() -> DependencyGraph {
        let rfcs = vec![
            Rfc {
                number: RfcNumber(9293),
                title: "TCP".to_string(),
                format: RfcFormat::Xml,
                status: RfcStatus::Standard,
                date: NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
                obsoletes: vec![RfcNumber(793)],
                updates: vec![],
                obsoleted_by: vec![],
                updated_by: vec![],
                sections: vec![],
                references: vec![],
                raw_text: String::new(),
                content_hash: String::new(),
            },
            Rfc {
                number: RfcNumber(793),
                title: "Old TCP".to_string(),
                format: RfcFormat::PlainText,
                status: RfcStatus::Historic,
                date: NaiveDate::from_ymd_opt(1981, 9, 1).unwrap(),
                obsoletes: vec![],
                updates: vec![],
                obsoleted_by: vec![],
                updated_by: vec![],
                sections: vec![],
                references: vec![],
                raw_text: String::new(),
                content_hash: String::new(),
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
