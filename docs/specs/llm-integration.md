# LLM Integration

## Client Design

The LLM client targets the **OpenAI-compatible chat completions API**, making it
work with OpenAI, local models (Ollama, vLLM, llama.cpp server), Azure OpenAI,
and any other compatible endpoint.

### Configuration

All LLM settings live in `rfc-analyzer.toml`:

```toml
[llm]
api_base = "https://api.openai.com/v1"    # base URL (no trailing slash)
api_key_env = "OPENAI_API_KEY"             # env var holding the API key
model = "gpt-4o"                           # model identifier
max_tokens_per_request = 4096              # max output tokens
max_concurrent_requests = 3                # concurrency limit
temperature = 0.2                          # low for structured extraction
```

The API key is **never stored in the config file** -- it is read from the
environment variable named in `api_key_env`. If the variable is unset, the tool
errors with a clear message.

### HTTP Client (`llm/client.rs`)

```rust
pub struct LlmClient {
    http: reqwest::Client,
    config: LlmConfig,
    rate_limiter: governor::RateLimiter<...>,
}

impl LlmClient {
    pub async fn chat(&self, messages: Vec<ChatMessage>) -> Result<String>;
    pub async fn chat_json<T: DeserializeOwned>(
        &self,
        messages: Vec<ChatMessage>,
    ) -> Result<T>;
}
```

Key behaviors:
- Sends `POST {api_base}/chat/completions`
- Sets `Authorization: Bearer {api_key}` header
- For `chat_json`, appends `"response_format": {"type": "json_object"}` if the
  model supports it, otherwise relies on prompt instructions
- Retry logic: retries on 429 (rate limit) and 5xx with exponential backoff,
  up to 3 attempts
- Tracks token usage from response headers/body for reporting

### Rate Limiting (`llm/rate_limit.rs`)

Uses the `governor` crate to enforce `max_concurrent_requests`. A tokio
semaphore limits in-flight requests. The rate limiter also respects
`Retry-After` headers from 429 responses.

## Context Window Management

RFC sections can be very long. The client manages context budgets:

1. Estimate token count using a simple heuristic (`chars / 4`)
2. If sections exceed the budget, chunk them into multiple calls
3. Include a continuation system prompt:
   `"You are processing part {n} of {total}. Continue from where the previous
   part left off."`
4. Merge results from chunked calls

The context budget is `model_context_window - max_tokens_per_request - system_prompt_tokens`,
leaving room for both input and output.

## Prompt Templates (`llm/prompts.rs`)

All prompts are defined as Rust string constants with placeholder interpolation.
Each prompt requests **structured JSON output** with a defined schema.

### Stage 1: Ambiguous Reference Resolution

Used sparingly -- only when plain-text parsing finds ambiguous references.

```
System: You are a protocol specification analyst. Given RFC section text,
identify the exact target of ambiguous cross-references.

User: In RFC {rfc}, Section {section}, the text says: "{context}"
What specific RFC and section does this refer to? Consider the following
candidate RFCs: {candidates}

Return JSON: {"target_rfc": N, "target_section": "X.Y", "confidence": 0.9}
```

### Stage 2: Mechanism Clustering

```
System: You are analyzing protocol specifications. Group the following
RFC sections by the protocol mechanism they describe (e.g., authentication,
message format, error handling, connection management, extensions).

User: Protocol: {protocol}
Sections:
{for each section: "- RFC {rfc} Section {num}: {title}"}

Return JSON: {"clusters": [{"mechanism": "...", "sections": [{"rfc": N, "section": "X.Y"}, ...]}]}
```

### Stage 2: State Machine Extraction

```
System: You are analyzing protocol specifications. Given the following
RFC sections, extract a protocol state machine. Be thorough -- include
all states and transitions mentioned or implied by the specification.

User: Protocol: {protocol}, Mechanism: {mechanism}

Sections:
--- RFC {rfc}, Section {num} ({title}) ---
{section text}
---

Return JSON:
{
  "name": "...",
  "states": [{"name": "...", "description": "...", "source_rfc": N, "source_section": "X.Y"}],
  "transitions": [{"from": "...", "to": "...", "trigger": "...", "conditions": [...], "actions": [...], "source_rfc": N, "source_section": "X.Y"}]
}
```

### Stage 3: Security Analysis

One prompt per attack category:

```
System: You are a security researcher analyzing protocol specifications
for {category} vulnerabilities. You have deep expertise in protocol
security and have found CVEs in major protocols.

User: Analyze the following protocol sections for {category} vulnerabilities.

For each potential vulnerability found, return a JSON array of objects:
[{
  "technique_name": "...",
  "category": "{category}",
  "severity": "critical|high|medium|low|informational",
  "confidence": 0.85,
  "description": "Step 1: ... Step 2: ... Step 3: ...",
  "rfc_references": [{"rfc": N, "section": "X.Y", "quote": "..."}],
  "prerequisites": ["attacker is on-path", ...],
  "entities_involved": ["client", "server"],
  "mitigation": "..."
}]

Protocol state machine context:
{state machine summary}

Sections under analysis:
--- RFC {rfc}, Section {num} ({title}) ---
{section text}
---
```

Attack categories queried:
1. Missing input validation
2. Information leakage
3. Replay attacks
4. Oversized/malformed payload handling
5. State confusion / desynchronization
6. Authentication/authorization bypass
7. Denial of service
8. Protocol downgrade
9. Race conditions / TOCTOU
10. Implementation ambiguity (spec gaps that lead to divergent implementations)

## Response Parsing (`llm/response.rs`)

Each LLM response is:
1. Stripped of markdown code fences (```json ... ```) if present
2. Parsed as JSON via `serde_json::from_str`
3. Validated against expected schema (required fields present, enums valid)
4. On parse failure: logged with the raw response, returned as
   `RfcAnalyzerError::LlmParse`

Partial results are accepted -- if the LLM returns 5 valid leads and 1
malformed one, the 5 valid leads are kept and the malformed one is logged
as a warning.
