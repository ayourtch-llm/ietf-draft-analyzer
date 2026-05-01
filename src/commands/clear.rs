use anyhow::Result;

/// The `clear` command: remove stored data.
pub async fn cmd_clear(conn: &tokio_rusqlite::Connection, scope: &str, yes: bool) -> Result<()> {
    // Validate scope BEFORE confirmation prompt
    match scope {
        "all" | "rfcs" | "graphs" | "analysis" => {}
        other => anyhow::bail!(
            "Unknown scope: '{}'. Valid: all, rfcs, graphs, analysis",
            other
        ),
    }

    if !yes {
        eprint!("Clear {} data? This cannot be undone. [y/N] ", scope);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let scope_owned = scope.to_string();
    let scope_log = scope_owned.clone();
    conn.call(move |conn| {
        match scope_owned.as_str() {
            "all" | "rfcs" => {
                conn.execute_batch(
                    "DELETE FROM security_leads;
                     DELETE FROM state_machines;
                     DELETE FROM run_work_items;
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
                     DELETE FROM run_work_items;
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
