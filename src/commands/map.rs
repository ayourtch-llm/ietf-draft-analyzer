use crate::config::Config;
use crate::error::RfcAnalyzerError;
use crate::rfc::fetcher::RfcFetcher;
use anyhow::Result;
use std::collections::HashSet;

/// The `map` command: fetch, parse, and store RFCs.
pub async fn cmd_map(
    conn: &tokio_rusqlite::Connection,
    config: &Config,
    seed_rfcs: Vec<u32>,
    protocol: Option<String>,
    depth: u32,
    normative_only: bool,
) -> Result<()> {
    use crate::db::rfc_store;
    use crate::rfc::{index, parser_text, parser_xml};

    if protocol.is_none() {
        tracing::warn!(
            "RFCs will be cached but not associated with a protocol. \
             Use --protocol <name> to enable model/analyze commands."
        );
    }

    let fetcher = RfcFetcher::new(config.fetcher.clone());

    // Fetch the RFC index for obsoleted_by/updated_by metadata
    tracing::info!("Fetching RFC index...");
    let rfc_index = index::fetch_rfc_index(&config.fetcher.base_url)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch RFC index: {}. Continuing without it.", e);
            std::collections::HashMap::new()
        });

    // BFS expansion: process seed RFCs, then their references, up to `depth`
    let mut to_process: Vec<u32> = seed_rfcs.clone();
    let mut processed: HashSet<u32> = HashSet::new();
    let mut current_depth = 0u32;
    let mut is_seed = true;

    while !to_process.is_empty() && current_depth <= depth {
        let batch = std::mem::take(&mut to_process);
        let total = batch.len();
        tracing::info!("Depth {}: processing {} RFCs", current_depth, total);

        let mut next_batch: Vec<u32> = Vec::new();

        for (i, rfc_num) in batch.into_iter().enumerate() {
            if processed.contains(&rfc_num) {
                continue;
            }
            processed.insert(rfc_num);

            tracing::info!("Fetching RFC {}/{}: RFC {}", i + 1, total, rfc_num);

            // Check cache
            if let Some(existing_hash) = rfc_store::get_content_hash(conn, rfc_num).await? {
                tracing::info!(
                    "RFC {} already cached (hash: {}...)",
                    rfc_num,
                    &existing_hash[..8]
                );
                // Still need to collect references for expansion
                if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num).await? {
                    if current_depth < depth {
                        next_batch.extend(collect_references(&rfc, normative_only));
                    }
                    if let Some(ref proto) = protocol {
                        rfc_store::assign_protocol(conn, proto, rfc_num).await?;
                    }
                    continue;
                }
            }

            // Fetch
            let fetch_result = match fetcher.fetch(rfc_num).await {
                Ok(r) => r,
                Err(RfcAnalyzerError::RfcNotFound(_)) => {
                    if is_seed {
                        anyhow::bail!("Seed RFC {} not found (404)", rfc_num);
                    }
                    tracing::warn!("RFC {} not found (404), skipping", rfc_num);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            // Parse
            let mut rfc = if fetch_result.format == "xml" {
                parser_xml::parse_xml(rfc_num, &fetch_result.content, &fetch_result.content_hash)?
            } else {
                parser_text::parse_text(rfc_num, &fetch_result.content, &fetch_result.content_hash)?
            };

            // Enrich with index metadata (obsoleted_by, updated_by)
            if let Some(idx_entry) = rfc_index.get(&rfc_num) {
                rfc.obsoleted_by = idx_entry.obsoleted_by.clone();
                rfc.updated_by = idx_entry.updated_by.clone();
            }

            tracing::info!(
                "Parsed RFC {} ({}) - {} sections, {} references",
                rfc_num,
                rfc.format,
                rfc.sections.len(),
                rfc.references.len()
            );

            // Store
            rfc_store::upsert_rfc(conn, &rfc).await?;

            // Protocol assignment
            if let Some(ref proto) = protocol {
                rfc_store::assign_protocol(conn, proto, rfc_num).await?;
            }

            // Collect references for next depth level
            if current_depth < depth {
                next_batch.extend(collect_references(&rfc, normative_only));
            }

            // Polite delay
            fetcher.delay().await;
        }

        to_process = next_batch
            .into_iter()
            .filter(|n| !processed.contains(n))
            .collect();
        current_depth += 1;
        is_seed = false;
    }

    tracing::info!("Map complete: {} RFCs processed", processed.len());
    if let Some(ref proto) = protocol {
        let assigned = rfc_store::get_protocol_rfcs(conn, proto).await?;
        tracing::info!("Protocol '{}': {} RFCs assigned", proto, assigned.len());
    }

    // Build and persist dependency graph
    {
        use crate::db::graph_store;
        use crate::graph::builder::DependencyGraph;
        use petgraph::visit::{EdgeRef, IntoEdgeReferences};

        let mut all_rfcs = Vec::new();
        for &rfc_num in &processed.iter().copied().collect::<Vec<_>>() {
            if let Some(rfc) = rfc_store::get_rfc(conn, rfc_num).await? {
                all_rfcs.push(rfc);
            }
        }

        let dep_graph = DependencyGraph::build(&all_rfcs);
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
        let summary = dep_graph.summary();
        tracing::info!(
            "Graph: {} nodes, {} edges, {} components",
            summary.total_nodes,
            summary.total_edges,
            summary.connected_components
        );
    }

    Ok(())
}

/// Collect all RFC numbers referenced by an Rfc struct.
fn collect_references(rfc: &crate::rfc::model::Rfc, normative_only: bool) -> Vec<u32> {
    let mut refs: Vec<u32> = Vec::new();

    // Always follow obsoletes/updates regardless of normative_only
    refs.extend(rfc.obsoletes.iter().map(|r| r.0));
    refs.extend(rfc.updates.iter().map(|r| r.0));

    // Formal references
    for reference in &rfc.references {
        if let Some(target) = reference.target_rfc
            && (reference.is_normative || !normative_only)
        {
            refs.push(target.0);
        }
    }

    // Inline cross-references (always followed — they don't have
    // normative/informative classification)
    for section in &rfc.sections {
        for xref in &section.cross_refs {
            if let Some(target) = xref.target_rfc {
                refs.push(target.0);
            }
        }
    }

    refs.sort();
    refs.dedup();
    refs
}
