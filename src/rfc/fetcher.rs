use crate::config::FetcherConfig;
use crate::error::{Result, RfcAnalyzerError};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Tracks which format worked for each RFC to avoid repeated 404s.
/// Shared across all fetch calls within a session.
pub struct RfcFetcher {
    client: reqwest::Client,
    config: FetcherConfig,
    /// Cache of RFC number -> format that succeeded ("xml" or "text").
    format_cache: Mutex<HashMap<u32, String>>,
}

/// Result of fetching an RFC.
pub struct FetchResult {
    pub rfc_number: u32,
    pub content: String,
    pub format: String,       // "xml" or "text"
    pub content_hash: String, // SHA-256 hex of the raw content
}

impl RfcFetcher {
    pub fn new(config: FetcherConfig) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("ietf-draft-analyzer/0.1.0")
            .build()
            .expect("Failed to build HTTP client");
        Self {
            client,
            config,
            format_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Fetch a single RFC. Tries XML first (if prefer_xml), falls back to
    /// the other format. Returns the raw content and detected format.
    ///
    /// Returns `RfcAnalyzerError::RfcNotFound` if both formats return 404.
    pub async fn fetch(&self, rfc_number: u32) -> Result<FetchResult> {
        // Check format cache
        let cached_format = self.format_cache.lock().unwrap().get(&rfc_number).cloned();

        let formats = if let Some(fmt) = cached_format {
            // Try the known-good format first
            if fmt == "xml" {
                vec!["xml", "text"]
            } else {
                vec!["text", "xml"]
            }
        } else if self.config.prefer_xml {
            vec!["xml", "text"]
        } else {
            vec!["text", "xml"]
        };

        let mut last_non_404_error: Option<String> = None;

        for format in &formats {
            let url = match *format {
                "xml" => format!("{}/rfc/rfc{}.xml", self.config.base_url, rfc_number),
                _ => format!("{}/rfc/rfc{}.txt", self.config.base_url, rfc_number),
            };

            tracing::debug!("Fetching {}", url);
            let response =
                self.client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| RfcAnalyzerError::Fetch {
                        rfc: rfc_number,
                        source: e,
                    })?;

            match response.status().as_u16() {
                200 => {
                    let content = response.text().await.map_err(|e| RfcAnalyzerError::Fetch {
                        rfc: rfc_number,
                        source: e,
                    })?;

                    // Cache the successful format
                    self.format_cache
                        .lock()
                        .unwrap()
                        .insert(rfc_number, format.to_string());

                    // Compute content hash
                    let mut hasher = Sha256::new();
                    hasher.update(content.as_bytes());
                    let content_hash = format!("{:x}", hasher.finalize());

                    return Ok(FetchResult {
                        rfc_number,
                        content,
                        format: format.to_string(),
                        content_hash,
                    });
                }
                404 => {
                    tracing::debug!("404 for {} format of RFC {}", format, rfc_number);
                    continue;
                }
                status => {
                    let msg = format!("HTTP {} fetching RFC {} ({})", status, rfc_number, format);
                    tracing::warn!("{}, trying next format", msg);
                    last_non_404_error = Some(msg);
                    continue;
                }
            }
        }

        // If we got a non-404 error on any attempt, report that instead
        // of RfcNotFound (which implies the RFC doesn't exist)
        if let Some(err_msg) = last_non_404_error {
            return Err(RfcAnalyzerError::Config(err_msg));
        }
        Err(RfcAnalyzerError::RfcNotFound(rfc_number))
    }

    /// Polite delay between requests. Call this between fetch() calls.
    pub async fn delay(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(
            self.config.request_delay_ms,
        ))
        .await;
    }
}

/// Compute SHA-256 hex hash of a string.
pub fn sha256_hex(data: &str) -> String {
    sha256_hex_bytes(data.as_bytes())
}

/// Compute SHA-256 hex hash of raw document bytes.
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
