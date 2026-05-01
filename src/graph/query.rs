use crate::graph::builder::DependencyGraph;
use crate::graph::model::*;
use crate::rfc::model::RfcNumber;
use petgraph::visit::{EdgeRef, IntoEdgeReferences, IntoNodeReferences};
use std::collections::HashMap;
use std::collections::HashSet;

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
        let components = count_connected_components(&self.graph);

        // Count incoming edges per node (most referenced = most incoming)
        let mut in_degree: HashMap<RfcNumber, usize> = HashMap::new();
        for edge in self.graph.edge_references() {
            let target = &self.graph[edge.target()];
            *in_degree.entry(target.rfc).or_default() += 1;
        }

        let mut most_referenced: Vec<(RfcNumber, usize)> = in_degree.into_iter().collect();
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

/// Count connected components using BFS (works with StableGraph).
fn count_connected_components(
    graph: &petgraph::stable_graph::StableDiGraph<
        crate::graph::model::RfcNode,
        crate::graph::model::DepEdge,
    >,
) -> usize {
    use petgraph::visit::NodeRef;
    let mut visited: HashSet<petgraph::stable_graph::NodeIndex> = HashSet::new();
    let mut components = 0usize;

    for node in graph.node_references() {
        let nx = node.id();
        if visited.contains(&nx) {
            continue;
        }
        components += 1;
        // BFS from this node
        let mut stack = vec![nx];
        while let Some(current) = stack.pop() {
            // Outgoing edges
            for edge in graph.edges(current) {
                let target = edge.target();
                if !visited.contains(&target) {
                    visited.insert(target);
                    stack.push(target);
                }
            }
            // Incoming edges (undirected traversal)
            for edge in graph.edges_directed(current, petgraph::Direction::Incoming) {
                let source = edge.source();
                if !visited.contains(&source) {
                    visited.insert(source);
                    stack.push(source);
                }
            }
        }
    }

    components
}
