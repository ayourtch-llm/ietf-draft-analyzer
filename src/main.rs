use anyhow::Result;
use clap::Parser;
use rfc_analyzer::cli::{Cli, Command};
use rfc_analyzer::config::Config;
use rfc_analyzer::db;
use rfc_analyzer::error::RfcAnalyzerError;
use rfc_analyzer::rfc::fetcher::RfcFetcher;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let filter = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    // Load config
    let config = Config::load(&cli.config)?;

    // Open database
    let conn = db::open_database(&cli.db).await?;

    match cli.command {
        Command::Map {
            rfcs,
            protocol,
            depth,
            normative_only,
        } => {
            cmd_map(&conn, &config, rfcs, protocol, depth, normative_only).await?;
        }
        Command::Show { rfc } => {
            cmd_show(&conn, rfc).await?;
        }
        Command::Clear { scope, yes } => {
            cmd_clear(&conn, &scope, yes).await?;
        }
        _ => {
            eprintln!("Command not yet implemented. Available: map, show, clear");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// The `map` command: fetch, parse, and store RFCs.
async fn cmd_map(
    conn: &tokio_rusqlite::Connection,
    config: &Config,
    seed_rfcs: Vec<u32>,
    protocol: Option<String>,
    depth: u32,
    normative_only: bool,
) -> Result<()> {
    use rfc_analyzer::db::rfc_store;
    use rfc_analyzer::rfc::{index, parser_text, parser_xml};
    use std::collections::HashSet;

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

    Ok(())
}

/// Collect all RFC numbers referenced by an Rfc struct.
fn collect_references(rfc: &rfc_analyzer::rfc::model::Rfc, normative_only: bool) -> Vec<u32> {
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

/// The `show` command: display info about a cached RFC.
async fn cmd_show(conn: &tokio_rusqlite::Connection, rfc_number: u32) -> Result<()> {
    use rfc_analyzer::db::rfc_store;

    match rfc_store::get_rfc(conn, rfc_number).await? {
        Some(rfc) => {
            println!("RFC {}: {}", rfc.number.0, rfc.title);
            println!("Status: {}", rfc.status);
            println!("Format: {}", rfc.format);
            println!("Date: {}", rfc.date);
            println!("Sections: {}", rfc.sections.len());
            println!("References: {}", rfc.references.len());
            if !rfc.obsoletes.is_empty() {
                println!(
                    "Obsoletes: {:?}",
                    rfc.obsoletes.iter().map(|r| r.0).collect::<Vec<_>>()
                );
            }
            if !rfc.updates.is_empty() {
                println!(
                    "Updates: {:?}",
                    rfc.updates.iter().map(|r| r.0).collect::<Vec<_>>()
                );
            }
            if !rfc.obsoleted_by.is_empty() {
                println!(
                    "Obsoleted by: {:?}",
                    rfc.obsoleted_by.iter().map(|r| r.0).collect::<Vec<_>>()
                );
            }
            if !rfc.updated_by.is_empty() {
                println!(
                    "Updated by: {:?}",
                    rfc.updated_by.iter().map(|r| r.0).collect::<Vec<_>>()
                );
            }
            // Show first few sections
            for section in rfc.sections.iter().take(10) {
                println!(
                    "  {} {} ({} chars, {} xrefs)",
                    section.number,
                    section.title,
                    section.text.len(),
                    section.cross_refs.len()
                );
            }
            if rfc.sections.len() > 10 {
                println!("  ... and {} more sections", rfc.sections.len() - 10);
            }
        }
        None => {
            eprintln!(
                "RFC {} not found in database. Run 'map {}' first.",
                rfc_number, rfc_number
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

/// The `clear` command: remove stored data.
async fn cmd_clear(conn: &tokio_rusqlite::Connection, scope: &str, yes: bool) -> Result<()> {
    if !yes {
        eprint!("Clear {} data? This cannot be undone. [y/N] ", scope);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Validate scope before entering the closure
    match scope {
        "all" | "rfcs" | "graphs" | "analysis" => {}
        _ => anyhow::bail!("Unknown scope: {}", scope),
    }

    let scope_owned = scope.to_string();
    let scope_log = scope_owned.clone();
    conn.call(move |conn| {
        match scope_owned.as_str() {
            "all" | "rfcs" => {
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM analysis_runs;
                     DELETE FROM dep_edges;
                     DELETE FROM cross_refs;
                     DELETE FROM sections;
                     DELETE FROM protocol_rfcs;
                     DELETE FROM rfcs;",
                )?;
            }
            "graphs" => {
                conn.execute_batch("DELETE FROM dep_edges;")?;
            }
            "analysis" => {
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM analysis_runs;",
                )?;
            }
            _ => unreachable!(),
        }
        Ok(())
    })
    .await?;

    tracing::info!("Cleared {} data", scope_log);
    Ok(())
}
