use encoding_rs::{Encoding, WINDOWS_1252};

/// Decode a locally imported document using BOM and HTML/XML charset hints.
/// UTF-8 is preferred; Windows-1252 is the compatibility fallback used by
/// older standards exported from Microsoft Word, including MQTT 5.0.
pub fn decode_document(bytes: &[u8]) -> String {
    if let Some((encoding, bom_len)) = Encoding::for_bom(bytes) {
        let (decoded, _, _) = encoding.decode(&bytes[bom_len..]);
        return decoded.into_owned();
    }

    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }

    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(8192)]).to_lowercase();
    let encoding = find_charset_label(&prefix)
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(WINDOWS_1252);
    let (decoded, _, _) = encoding.decode(bytes);
    decoded.into_owned()
}

fn find_charset_label(prefix: &str) -> Option<&str> {
    let charset_pos = prefix.find("charset")?;
    let after = prefix[charset_pos + "charset".len()..].trim_start();
    let after = after
        .strip_prefix('=')?
        .trim_start_matches([' ', '"', '\'']);
    let end = after
        .find(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\'' | ';' | '>'))
        .unwrap_or(after.len());
    let label = &after[..end];
    (!label.is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf8_and_bom() {
        assert_eq!(decode_document("café".as_bytes()), "café");
        assert_eq!(decode_document(b"\xEF\xBB\xBFhello"), "hello");
    }

    #[test]
    fn decodes_declared_windows_1252() {
        let bytes = b"<meta charset=windows-1252><p>TC\x92s standard</p>";
        assert_eq!(
            decode_document(bytes),
            "<meta charset=windows-1252><p>TC’s standard</p>"
        );
    }

    #[test]
    fn defaults_non_utf8_to_windows_1252() {
        assert_eq!(
            decode_document(b"Copyright \xA9 OASIS"),
            "Copyright © OASIS"
        );
    }
}
