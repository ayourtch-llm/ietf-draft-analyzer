use crate::error::{Result, RfcAnalyzerError};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub fetcher: FetcherConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens_per_request: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_context_window")]
    pub model_context_window: u64,
    /// Use GBNF grammar constraints (requires llama.cpp).
    /// When false, uses JSON mode (`response_format`) instead,
    /// which is compatible with OpenAI, vLLM, Ollama, etc.
    #[serde(default = "default_use_grammar")]
    pub use_grammar: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FetcherConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_prefer_xml")]
    pub prefer_xml: bool,
    #[serde(default = "default_request_delay")]
    pub request_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisConfig {
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
    #[serde(default)]
    pub normative_only: bool,
}

// Default value functions
fn default_api_base() -> String {
    "https://api.openai.com/v1".to_string()
}
fn default_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}
fn default_model() -> String {
    "gpt-4o".to_string()
}
fn default_max_tokens() -> u32 {
    4096
}
fn default_max_concurrent() -> u32 {
    3
}
fn default_temperature() -> f32 {
    0.2
}
fn default_context_window() -> u64 {
    128_000
}
fn default_base_url() -> String {
    "https://www.rfc-editor.org".to_string()
}
fn default_prefer_xml() -> bool {
    true
}
fn default_request_delay() -> u64 {
    500
}
fn default_use_grammar() -> bool {
    true
}
fn default_max_depth() -> u32 {
    2
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            api_base: default_api_base(),
            api_key_env: default_api_key_env(),
            model: default_model(),
            max_tokens_per_request: default_max_tokens(),
            max_concurrent_requests: default_max_concurrent(),
            temperature: default_temperature(),
            model_context_window: default_context_window(),
            use_grammar: default_use_grammar(),
        }
    }
}

impl LlmConfig {
    /// Resolve the API key from the configured environment variable.
    /// Returns an error if the env var is not set or empty.
    /// This is called when the LLM client is constructed, not at config load time.
    pub fn resolve_api_key(&self) -> crate::error::Result<String> {
        let key = std::env::var(&self.api_key_env).map_err(|_| {
            crate::error::RfcAnalyzerError::Config(format!(
                "Environment variable '{}' is not set. Set it to your API key.",
                self.api_key_env
            ))
        })?;
        if key.is_empty() {
            return Err(crate::error::RfcAnalyzerError::Config(format!(
                "Environment variable '{}' is set but empty.",
                self.api_key_env
            )));
        }
        Ok(key)
    }
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            base_url: default_base_url(),
            prefer_xml: default_prefer_xml(),
            request_delay_ms: default_request_delay(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
            normative_only: false,
        }
    }
}

impl Config {
    /// Load config from a TOML file. If the file does not exist, return
    /// defaults (all sections have defaults, so an empty/missing file is OK).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::info!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            return Ok(Config::default());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            RfcAnalyzerError::Config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        let config: Config = toml::from_str(&contents).map_err(|e| {
            RfcAnalyzerError::Config(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values. Called after loading.
    /// Fails fast with clear messages for out-of-range values.
    /// Note: LLM api_key_env is validated (non-empty, env var set) only
    /// when the LLM client is actually constructed (Phase 4+), not here.
    pub fn validate(&self) -> Result<()> {
        // LLM structural validation (format checks, not runtime availability)
        if self.llm.api_base.ends_with('/') {
            return Err(RfcAnalyzerError::Config(
                "llm.api_base must not end with '/'".to_string(),
            ));
        }
        if self.llm.api_key_env.is_empty() {
            return Err(RfcAnalyzerError::Config(
                "llm.api_key_env must not be empty".to_string(),
            ));
        }
        if !(1..=20).contains(&self.llm.max_concurrent_requests) {
            return Err(RfcAnalyzerError::Config(format!(
                "llm.max_concurrent_requests must be 1..=20, got {}",
                self.llm.max_concurrent_requests
            )));
        }
        if !(0.0..=2.0).contains(&self.llm.temperature) {
            return Err(RfcAnalyzerError::Config(format!(
                "llm.temperature must be 0.0..=2.0, got {}",
                self.llm.temperature
            )));
        }
        if !(1..=65536).contains(&self.llm.max_tokens_per_request) {
            return Err(RfcAnalyzerError::Config(format!(
                "llm.max_tokens_per_request must be 1..=65536, got {}",
                self.llm.max_tokens_per_request
            )));
        }
        if !(4096..=2_097_152).contains(&self.llm.model_context_window) {
            return Err(RfcAnalyzerError::Config(format!(
                "llm.model_context_window must be 4096..=2097152, got {}",
                self.llm.model_context_window
            )));
        }

        // Fetcher validation
        if !(50..=60_000).contains(&self.fetcher.request_delay_ms) {
            return Err(RfcAnalyzerError::Config(format!(
                "fetcher.request_delay_ms must be 50..=60000, got {}",
                self.fetcher.request_delay_ms
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.llm.max_concurrent_requests, 3);
        assert_eq!(config.fetcher.request_delay_ms, 500);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_missing_file_returns_defaults() {
        let config = Config::load(Path::new("nonexistent.toml")).unwrap();
        assert_eq!(config.llm.model, "gpt-4o");
    }

    #[test]
    fn test_load_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.fetcher.base_url, "https://www.rfc-editor.org");
    }

    #[test]
    fn test_load_partial_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.toml");
        std::fs::write(
            &path,
            r#"
            [fetcher]
            request_delay_ms = 1000
        "#,
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.fetcher.request_delay_ms, 1000);
        // Other fields should be defaults
        assert_eq!(config.llm.model, "gpt-4o");
    }

    #[test]
    fn test_validate_bad_temperature() {
        let mut config = Config::default();
        config.llm.temperature = 3.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_concurrent_requests() {
        let mut config = Config::default();
        config.llm.max_concurrent_requests = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_api_base_trailing_slash() {
        let mut config = Config::default();
        config.llm.api_base = "https://api.openai.com/v1/".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_request_delay() {
        let mut config = Config::default();
        config.fetcher.request_delay_ms = 10; // below 50
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_max_tokens() {
        let mut config = Config::default();
        config.llm.max_tokens_per_request = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_context_window() {
        let mut config = Config::default();
        config.llm.model_context_window = 100; // below 4096
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_api_key_env() {
        let mut config = Config::default();
        config.llm.api_key_env = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_load_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not [valid toml").unwrap();
        assert!(Config::load(&path).is_err());
    }
}
