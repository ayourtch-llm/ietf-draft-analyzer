#[derive(Debug, thiserror::Error)]
pub enum RfcAnalyzerError {
    #[error("Failed to fetch RFC {rfc}: {source}")]
    Fetch { rfc: u32, source: reqwest::Error },

    #[error("RFC {0} not found (HTTP 404)")]
    RfcNotFound(u32),

    #[error("Failed to parse RFC {rfc} ({format}): {detail}")]
    Parse {
        rfc: u32,
        format: String,
        detail: String,
    },

    #[error("XML parse error in RFC {rfc}: {source}")]
    Xml { rfc: u32, source: quick_xml::Error },

    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("Database error: {0}")]
    DbAsync(#[from] tokio_rusqlite::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("No RFCs mapped for protocol '{0}'. Run 'map --protocol {0}' first.")]
    NoMappedRfcs(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, RfcAnalyzerError>;
