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
                    graph.add_edge(
                        source_idx,
                        target_idx,
                        DepEdge {
                            kind: EdgeKind::Obsoletes,
                            source_section: None,
                            target_section: None,
                        },
                    );
                }
            }

            // Updates edges: source updates target
            for target in &rfc.updates {
                if let Some(&target_idx) = node_map.get(target) {
                    graph.add_edge(
                        source_idx,
                        target_idx,
                        DepEdge {
                            kind: EdgeKind::Updates,
                            source_section: None,
                            target_section: None,
                        },
                    );
                }
            }

            // Formal references
            for reference in &rfc.references {
                if let Some(target_rfc) = reference.target_rfc
                    && let Some(&target_idx) = node_map.get(&target_rfc)
                {
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
                        graph.add_edge(
                            source_idx,
                            target_idx,
                            DepEdge {
                                kind,
                                source_section: None,
                                target_section: None,
                            },
                        );
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
                            graph.add_edge(
                                source_idx,
                                target_idx,
                                DepEdge {
                                    kind: EdgeKind::CrossReference,
                                    source_section: Some(section.number.clone()),
                                    target_section: xref.target_section.clone(),
                                },
                            );
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

#[cfg(test)]
mod tests {
    use super::*;
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
            references: refs
                .into_iter()
                .map(|(rfc, normative)| Reference {
                    label: format!("[RFC{}]", rfc),
                    target_rfc: Some(RfcNumber(rfc)),
                    title: String::new(),
                    is_normative: normative,
                })
                .collect(),
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
