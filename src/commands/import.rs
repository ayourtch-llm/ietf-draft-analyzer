use crate::config::Config;
use crate::rfc::fetcher;
use anyhow::Result;
use std::path::Path;

/// The `import` command: load a local RFC, Internet-Draft, or HTML standard.
pub async fn cmd_import(
    conn: &tokio_rusqlite::Connection,
    _config: &Config,
    file_path: &Path,
    rfc_number: u32,
    protocol: Option<String>,
) -> Result<()> {
    use crate::db::rfc_store;
    use crate::rfc::model::RfcFormat;
    use crate::rfc::{encoding, parser_html, parser_text, parser_xml};

    // Read and decode the file. Standards published as HTML are not always
    // UTF-8 (MQTT 5.0, for example, declares Windows-1252).
    let bytes = std::fs::read(file_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", file_path.display(), e))?;
    let content = encoding::decode_document(&bytes);

    let content_hash = fetcher::sha256_hex_bytes(&bytes);

    // Determine format from extension or content
    let format = detect_format(file_path, &content);

    // Parse
    let rfc = match format {
        RfcFormat::Xml => parser_xml::parse_xml(rfc_number, &content, &content_hash)?,
        RfcFormat::PlainText => parser_text::parse_text(rfc_number, &content, &content_hash)?,
        RfcFormat::Html => parser_html::parse_html(rfc_number, &content, &content_hash)?,
    };

    tracing::info!(
        "Imported {} as RFC {} ({}) — {} sections, {} references",
        file_path.display(),
        rfc_number,
        format,
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

fn detect_format(file_path: &Path, content: &str) -> crate::rfc::model::RfcFormat {
    use crate::rfc::model::RfcFormat;

    let extension = file_path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("xml") => return RfcFormat::Xml,
        Some("html") | Some("htm") => return RfcFormat::Html,
        Some("txt") | Some("text") => return RfcFormat::PlainText,
        _ => {}
    }

    let trimmed = content.trim_start();
    let prefix = trimmed
        .get(..trimmed.len().min(512))
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if prefix.starts_with("<!doctype html") || prefix.contains("<html") {
        RfcFormat::Html
    } else if prefix.starts_with("<?xml") || prefix.starts_with("<rfc") {
        RfcFormat::Xml
    } else {
        RfcFormat::PlainText
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::model::RfcFormat;

    #[test]
    fn detects_format_from_extension_and_content() {
        assert_eq!(
            detect_format(Path::new("spec.HTML"), "<not-used>"),
            RfcFormat::Html
        );
        assert_eq!(
            detect_format(Path::new("spec"), "<!DOCTYPE html><html></html>"),
            RfcFormat::Html
        );
        assert_eq!(
            detect_format(Path::new("draft"), "<?xml version=\"1.0\"?><rfc/>"),
            RfcFormat::Xml
        );
        assert_eq!(
            detect_format(Path::new("rfc.txt"), "<html>ignored by extension</html>"),
            RfcFormat::PlainText
        );
    }
}
