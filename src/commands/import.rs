use crate::config::Config;
use crate::rfc::fetcher;
use anyhow::Result;
use std::path::Path;

/// The `import` command: load a local RFC/Internet-Draft XML or text file.
pub async fn cmd_import(
    conn: &tokio_rusqlite::Connection,
    _config: &Config,
    file_path: &Path,
    rfc_number: u32,
    protocol: Option<String>,
) -> Result<()> {
    use crate::db::rfc_store;
    use crate::rfc::{parser_text, parser_xml};

    // Read the file
    let content = std::fs::read_to_string(file_path).map_err(|e| {
        anyhow::anyhow!("Failed to read {}: {}", file_path.display(), e)
    })?;

    let content_hash = fetcher::sha256_hex(&content);

    // Determine format from extension or content
    let is_xml = match file_path.extension().and_then(|e| e.to_str()) {
        Some("xml") => true,
        Some("txt") | Some("text") => false,
        _ => content.trim_start().starts_with("<?xml") || content.trim_start().starts_with("<rfc"),
    };

    // Parse
    let rfc = if is_xml {
        parser_xml::parse_xml(rfc_number, &content, &content_hash)?
    } else {
        parser_text::parse_text(rfc_number, &content, &content_hash)?
    };

    let format_name = if is_xml { "xml" } else { "text" };
    tracing::info!(
        "Imported {} as RFC {} ({}) — {} sections, {} references",
        file_path.display(),
        rfc_number,
        format_name,
        rfc.sections.len(),
        rfc.references.len(),
    );

    // Store in database
    rfc_store::upsert_rfc(conn, &rfc).await?;

    // Assign to protocol if specified
    if let Some(ref proto) = protocol {
        rfc_store::assign_protocol(conn, proto, rfc_number).await?;
        tracing::info!("Assigned RFC {} to protocol '{}'", rfc_number, proto);
    }

    Ok(())
}
