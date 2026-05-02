use crate::config::LlmConfig;
use crate::error::{Result, RfcAnalyzerError};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// A message in the chat conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "system", "user", "assistant"
    pub content: String,
}

/// Token usage from an LLM response.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

/// The LLM client for OpenAI-compatible chat completions.
pub struct LlmClient {
    http: reqwest::Client,
    config: LlmConfig,
    api_key: String,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
}

impl LlmClient {
    /// Create a new LLM client. Resolves the API key from the environment.
    pub fn new(config: LlmConfig, cancel_token: CancellationToken) -> Result<Self> {
        let api_key = config.resolve_api_key()?;
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests as usize));
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(600))
            .build()
            .map_err(|e| RfcAnalyzerError::Config(format!("HTTP client error: {}", e)))?;

        Ok(Self {
            http,
            config,
            api_key,
            semaphore,
            cancel_token,
        })
    }

    /// Send a chat completion request and return the raw response text.
    /// Handles retries for 429/5xx, error classification, and concurrency.
    pub async fn chat(&self, messages: Vec<ChatMessage>) -> Result<(String, TokenUsage)> {
        self.chat_with_format(messages, false, None).await
    }

    /// Send a chat request with JSON response format and parse the result.
    /// Adds `response_format: {"type": "json_object"}` to the request.
    /// Handles markdown fence stripping and content refusal detection.
    pub async fn chat_json<T: serde::de::DeserializeOwned>(
        &self,
        messages: Vec<ChatMessage>,
    ) -> Result<(T, TokenUsage)> {
        let (content, usage) = self.chat_with_format(messages, true, None).await?;
        let parsed = super::response::parse_json_response::<T>(&content)?;
        Ok((parsed, usage))
    }

    /// Send a chat request with a GBNF grammar constraint.
    /// Uses structured CoT: the prompt encourages thinking, and the grammar
    /// constrains the output to valid JSON after the thinking block.
    /// For llama.cpp/llama-server backends that support the `grammar` parameter.
    pub async fn chat_json_grammar<T: serde::de::DeserializeOwned>(
        &self,
        messages: Vec<ChatMessage>,
        grammar: &str,
    ) -> Result<(T, TokenUsage)> {
        let (content, usage) = self
            .chat_with_format(messages, false, Some(grammar))
            .await?;
        let parsed = super::response::parse_json_response::<T>(&content)?;
        Ok((parsed, usage))
    }

    /// Send a chat request with a GBNF grammar constraint and return raw text.
    /// For cases where the caller does its own parsing (e.g., partial arrays).
    pub async fn chat_with_grammar(
        &self,
        messages: Vec<ChatMessage>,
        grammar: &str,
    ) -> Result<(String, TokenUsage)> {
        self.chat_with_format(messages, false, Some(grammar)).await
    }

    /// Whether GBNF grammar mode is enabled (from config).
    pub fn use_grammar(&self) -> bool {
        self.config.use_grammar
    }

    /// Send a chat request producing typed JSON, using grammar if configured
    /// or JSON mode otherwise. This is the preferred method for pipeline code.
    pub async fn chat_json_auto<T: serde::de::DeserializeOwned>(
        &self,
        messages: Vec<ChatMessage>,
        grammar: &str,
    ) -> Result<(T, TokenUsage)> {
        if self.config.use_grammar {
            self.chat_json_grammar(messages, grammar).await
        } else {
            self.chat_json(messages).await
        }
    }

    /// Send a chat request returning raw text, using grammar if configured
    /// or plain chat otherwise. For cases needing partial array parsing.
    pub async fn chat_text_auto(
        &self,
        messages: Vec<ChatMessage>,
        grammar: &str,
    ) -> Result<(String, TokenUsage)> {
        if self.config.use_grammar {
            self.chat_with_grammar(messages, grammar).await
        } else {
            self.chat_with_format(messages, true, None).await
        }
    }

    /// Internal: send chat with optional JSON response format or GBNF grammar.
    async fn chat_with_format(
        &self,
        messages: Vec<ChatMessage>,
        json_mode: bool,
        grammar: Option<&str>,
    ) -> Result<(String, TokenUsage)> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| RfcAnalyzerError::Config("Semaphore closed".to_string()))?;

        let mut attempts = 0;
        let max_attempts = 3;

        loop {
            attempts += 1;
            if self.cancel_token.is_cancelled() {
                return Err(RfcAnalyzerError::Config("Operation cancelled".to_string()));
            }

            let mut request_body = serde_json::json!({
                "model": self.config.model,
                "messages": messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens_per_request,
            });
            if let Some(g) = grammar {
                // GBNF grammar for llama.cpp/llama-server
                request_body["grammar"] = serde_json::json!(g);
            } else if json_mode {
                request_body["response_format"] = serde_json::json!({"type": "json_object"});
            }

            let url = format!("{}/chat/completions", self.config.api_base);
            let request_json = serde_json::to_string(&request_body).unwrap_or_default();
            let estimated_tokens = request_json.chars().count() / 4;
            tracing::debug!(
                "LLM request to {} (model: {}, ~{} tokens, attempt {}/{})",
                url,
                self.config.model,
                estimated_tokens,
                attempts,
                max_attempts
            );
            let response = match self
                .http
                .post(&url)
                .header(AUTHORIZATION, format!("Bearer {}", self.api_key))
                .header(CONTENT_TYPE, "application/json")
                .json(&request_body)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    // Network/connection error — retry with backoff
                    let is_connect = e.is_connect();
                    let is_timeout = e.is_timeout();
                    if attempts >= max_attempts {
                        return Err(RfcAnalyzerError::LlmApi {
                            status: 0,
                            body: format!(
                                "Network error after {} attempts (connect={}, timeout={}): {}",
                                max_attempts, is_connect, is_timeout, e
                            ),
                        });
                    }
                    let wait = 2u64.pow(attempts as u32);
                    tracing::warn!(
                        "Connection error (connect={}, timeout={}): {}. URL: {}. Waiting {}s before retry {}/{}",
                        is_connect,
                        is_timeout,
                        e,
                        url,
                        wait,
                        attempts,
                        max_attempts
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                        _ = self.cancel_token.cancelled() => {
                            return Err(RfcAnalyzerError::Config(
                                "Operation cancelled during retry wait".to_string(),
                            ));
                        }
                    }
                    continue;
                }
            };

            let status = response.status().as_u16();
            let headers = response.headers().clone();
            tracing::debug!("LLM response: HTTP {}", status);

            // Error classification and retry logic:
            match status {
                200 => {
                    let body: serde_json::Value =
                        response
                            .json()
                            .await
                            .map_err(|e| RfcAnalyzerError::LlmParse {
                                detail: format!("Failed to parse response JSON: {}", e),
                            })?;

                    // Check finish_reason FIRST (before content extraction)
                    let finish_reason = body["choices"][0]["finish_reason"]
                        .as_str()
                        .unwrap_or("stop");
                    if finish_reason == "content_filter" {
                        return Err(RfcAnalyzerError::LlmContentRefusal {
                            detail: "Model refused due to content filter".to_string(),
                        });
                    }

                    let raw_content = body["choices"][0]["message"]["content"]
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_default();

                    // Log raw vs stripped content for debugging
                    let thinking_len = raw_content
                        .find("</think>")
                        .map(|end| end + "</think>".len())
                        .unwrap_or(0);
                    tracing::debug!(
                        "LLM response: raw={} chars, thinking={} chars, finish_reason={}",
                        raw_content.len(),
                        thinking_len,
                        finish_reason
                    );
                    if raw_content.len() > 0 && raw_content.len() < 500 {
                        tracing::debug!("LLM raw content: {}", raw_content);
                    } else if raw_content.len() >= 500 {
                        tracing::debug!(
                            "LLM raw content (first 500 chars): {}",
                            raw_content.chars().take(500).collect::<String>()
                        );
                    }

                    // Strip <think>...</think> blocks (Qwen3 thinking mode)
                    let content = strip_thinking_tags(&raw_content);

                    tracing::debug!("LLM content after stripping: {} chars", content.len());

                    if content.is_empty() {
                        tracing::warn!(
                            "Empty response content from LLM (raw={} chars, thinking={} chars)",
                            raw_content.len(),
                            thinking_len
                        );
                        // Retry once with a nudge — sometimes models need encouragement
                        if attempts < max_attempts {
                            tracing::info!("Retrying with prompt nudge...");
                            attempts += 1;
                            continue;
                        }
                        return Err(RfcAnalyzerError::LlmParse {
                            detail: format!(
                                "Empty response content from LLM (raw was {} chars, may be thinking-only)",
                                raw_content.len()
                            ),
                        });
                    }

                    let usage = TokenUsage {
                        prompt_tokens: body["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
                        completion_tokens: body["usage"]["completion_tokens"].as_u64().unwrap_or(0),
                        total_tokens: body["usage"]["total_tokens"].as_u64().unwrap_or(0),
                    };
                    return Ok((content, usage));
                }
                429 => {
                    let retry_after = parse_retry_after(&headers);
                    if attempts >= max_attempts {
                        return Err(RfcAnalyzerError::LlmRateLimit {
                            retry_after_secs: retry_after,
                        });
                    }
                    let wait = retry_after.unwrap_or(2u64.pow(attempts as u32));
                    tracing::warn!(
                        "Rate limited (429), waiting {}s before retry {}/{}",
                        wait,
                        attempts,
                        max_attempts
                    );
                    // Cancellation-aware sleep: abort wait if Ctrl+C
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                        _ = self.cancel_token.cancelled() => {
                            return Err(RfcAnalyzerError::Config("Operation cancelled during retry wait".to_string()));
                        }
                    }
                    continue;
                }
                500..=599 => {
                    let body = response.text().await.unwrap_or_default();
                    if attempts >= max_attempts {
                        return Err(RfcAnalyzerError::LlmApi { status, body });
                    }
                    let wait = 2u64.pow(attempts as u32);
                    tracing::warn!(
                        "Server error ({}), waiting {}s before retry {}/{}",
                        status,
                        wait,
                        attempts,
                        max_attempts
                    );
                    // Cancellation-aware sleep
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                        _ = self.cancel_token.cancelled() => {
                            return Err(RfcAnalyzerError::Config("Operation cancelled during retry wait".to_string()));
                        }
                    }
                    continue;
                }
                400 => {
                    let body = response.text().await.unwrap_or_default();
                    let body_lower = body.to_lowercase();
                    if body_lower.contains("context_length")
                        || body_lower.contains("maximum context length")
                        || body_lower.contains("too many tokens")
                    {
                        return Err(RfcAnalyzerError::LlmContextOverflow);
                    }
                    return Err(RfcAnalyzerError::LlmApi { status: 400, body });
                }
                _ => {
                    let body = response.text().await.unwrap_or_default();
                    return Err(RfcAnalyzerError::LlmApi { status, body });
                }
            }
        }
    }

    /// Estimate the token count for a string.
    /// Uses chars/4 heuristic (char count, not byte count).
    /// Note: the 30% safety margin is applied in context_budget() via the
    /// 0.7 multiplier on model_context_window, NOT here. This function
    /// returns a raw estimate.
    pub fn estimate_tokens(&self, text: &str) -> u64 {
        (text.chars().count() as u64) / 4
    }

    /// Get the effective context budget in estimated tokens.
    /// Budget = model_context_window * 0.7 - max_tokens_per_request - system_prompt_overhead
    pub fn context_budget(&self, system_prompt_tokens: u64) -> u64 {
        let effective_window = (self.config.model_context_window as f64 * 0.7) as u64;
        effective_window
            .saturating_sub(self.config.max_tokens_per_request as u64)
            .saturating_sub(system_prompt_tokens)
    }

    /// Get the model name.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Get the cancellation token.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }
}

/// Strip `<think>...</think>` blocks from LLM responses (Qwen3 thinking mode).
/// Returns the content after all thinking blocks are removed.
fn strip_thinking_tags(content: &str) -> String {
    let mut result = content.to_string();
    // Remove all <think>...</think> blocks (potentially multi-line)
    while let Some(start) = result.find("<think>") {
        if let Some(end) = result.find("</think>") {
            let end_tag_len = "</think>".len();
            result = format!("{}{}", &result[..start], &result[end + end_tag_len..]);
        } else {
            // Unclosed <think> tag — remove everything from <think> onward
            result = result[..start].to_string();
            break;
        }
    }
    result.trim().to_string()
}

/// Parse Retry-After header value (seconds).
fn parse_retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(base_url: &str) -> LlmConfig {
        // Set env var for test
        // SAFETY: Test-only env var mutation, no concurrent access in this test
        unsafe {
            std::env::set_var("TEST_API_KEY", "test-key-123");
        }
        LlmConfig {
            api_base: base_url.to_string(),
            api_key_env: "TEST_API_KEY".to_string(),
            model: "test-model".to_string(),
            max_tokens_per_request: 100,
            max_concurrent_requests: 2,
            temperature: 0.1,
            model_context_window: 4096,
            use_grammar: true,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_chat_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "Hello!"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            })))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];
        let (response, usage) = client.chat(messages).await.unwrap();
        assert_eq!(response, "Hello!");
        assert_eq!(usage.total_tokens, 15);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_chat_rate_limit_retry() {
        let server = MockServer::start().await;
        // First call: 429, second: 200
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
            })))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];
        let (response, _) = client.chat(messages).await.unwrap();
        assert_eq!(response, "OK");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_chat_401_fails_immediately() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];
        let result = client.chat(messages).await;
        assert!(matches!(
            result,
            Err(RfcAnalyzerError::LlmApi { status: 401, .. })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_chat_400_context_overflow() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("maximum context length exceeded"),
            )
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];
        let result = client.chat(messages).await;
        assert!(matches!(result, Err(RfcAnalyzerError::LlmContextOverflow)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_chat_content_filter() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10}
            })))
            .mount(&server)
            .await;

        let config = test_config(&server.uri());
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];
        let result = client.chat(messages).await;
        assert!(matches!(
            result,
            Err(RfcAnalyzerError::LlmContentRefusal { .. })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_context_budget() {
        // SAFETY: Test-only env var mutation
        unsafe {
            std::env::set_var("TEST_API_KEY", "key");
        }
        let config = LlmConfig {
            model_context_window: 128000,
            max_tokens_per_request: 4096,
            ..test_config("http://unused")
        };
        let client = LlmClient::new(config, CancellationToken::new()).unwrap();
        // 128000 * 0.7 = 89600 - 4096 - 500 (system) = 85004
        let budget = client.context_budget(500);
        assert!(budget > 80000);
        assert!(budget < 90000);
    }
}
