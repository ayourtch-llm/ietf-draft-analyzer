use anyhow::Result;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

/// The `graph` command: show dependency graph for a protocol or RFC.
pub async fn cmd_graph(
    conn: &tokio_rusqlite::Connection,
    target: &str,
    format: &str,
) -> Result<()> {
    use crate::db::{graph_store, rfc_store};
    use crate::graph::builder::DependencyGraph;

    // Determine if target is an RFC number or protocol name
    let rfc_numbers = if let Ok(num) = target.parse::<u32>() {
        // Single RFC — show its immediate graph
        vec![crate::rfc::model::RfcNumber(num)]
    } else {
        // Protocol name — get all associated RFCs
        let rfcs = rfc_store::get_protocol_rfcs(conn, target).await?;
        if rfcs.is_empty() {
            anyhow::bail!(
                "No RFCs found for protocol '{}'. Run 'map --protocol {}' first.",
                target,
                target
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
    let edges: Vec<_> = dep_graph
        .graph
        .edge_references()
        .map(|e| {
            let src = &dep_graph.graph[e.source()];
            let tgt = &dep_graph.graph[e.target()];
            (src.rfc, tgt.rfc, e.weight().clone())
        })
        .collect();
    graph_store::store_edges(conn, &edges).await?;

    // Export
    match format {
        "dot" => {
            print!("{}", dep_graph.to_dot());
        }
        _ => {
            let json = dep_graph.to_json();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}
