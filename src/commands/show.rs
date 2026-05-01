use anyhow::Result;

/// The `show` command: display info about a cached RFC.
pub async fn cmd_show(conn: &tokio_rusqlite::Connection, rfc_number: u32) -> Result<()> {
    use crate::db::rfc_store;

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
