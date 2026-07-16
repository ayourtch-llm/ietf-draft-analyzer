use crate::error::{Result, RfcAnalyzerError};

/// Parse an LLM response string as JSON, stripping markdown fences if present.
/// Handles content refusal detection as a fallback.
pub fn parse_json_response<T: serde::de::DeserializeOwned>(content: &str) -> Result<T> {
    let cleaned = strip_markdown_fences(content);

    match serde_json::from_str::<T>(&cleaned) {
        Ok(value) => Ok(value),
        Err(parse_err) => {
            // Check for content refusal (fallback: finish_reason was "stop"
            // but content is not valid JSON)
            if looks_like_refusal(content) {
                return Err(RfcAnalyzerError::LlmContentRefusal {
                    detail: content.chars().take(200).collect(),
                });
            }

            // Genuine parse failure
            let detail = format!(
                "JSON parse error: {}. Response starts with: {}",
                parse_err,
                cleaned.chars().take(200).collect::<String>()
            );
            tracing::warn!(
                "LLM response parse failure: {}",
                detail.chars().take(200).collect::<String>()
            );
            tracing::trace!("Full LLM response: {}", content);
            Err(RfcAnalyzerError::LlmParse { detail })
        }
    }
}

/// Parse a JSON response that may contain an array, accepting partial results.
/// Returns successfully parsed items and logs warnings for malformed entries.
///
/// Accepts either a bare top-level array (what grammar mode produces) or an
/// object envelope wrapping the array (what `response_format: json_object`
/// forces strict backends like OpenAI to produce, e.g. `{"leads": [...]}`).
pub fn parse_json_array_partial<T: serde::de::DeserializeOwned>(content: &str) -> Result<Vec<T>> {
    let cleaned = strip_markdown_fences(content);

    // First try parsing the whole thing as Vec<T>
    if let Ok(items) = serde_json::from_str::<Vec<T>>(&cleaned) {
        return Ok(items);
    }

    // Parse as a generic Value, then locate the array (top-level, or the array
    // field of an object envelope), and convert each item individually.
    let parsed: serde_json::Value = serde_json::from_str(&cleaned).map_err(|e| {
        if looks_like_refusal(content) {
            RfcAnalyzerError::LlmContentRefusal {
                detail: content.chars().take(200).collect(),
            }
        } else {
            RfcAnalyzerError::LlmParse {
                detail: format!("Not a JSON array: {}", e),
            }
        }
    })?;

    let values = extract_array(parsed).ok_or_else(|| {
        if looks_like_refusal(content) {
            RfcAnalyzerError::LlmContentRefusal {
                detail: content.chars().take(200).collect(),
            }
        } else {
            RfcAnalyzerError::LlmParse {
                detail: "Response contained no JSON array (neither a top-level array nor an object wrapping one)".to_string(),
            }
        }
    })?;

    let mut results = Vec::new();
    for (i, value) in values.into_iter().enumerate() {
        match serde_json::from_value::<T>(value) {
            Ok(item) => results.push(item),
            Err(e) => {
                tracing::warn!("Skipping malformed array item {}: {}", i, e);
            }
        }
    }

    Ok(results)
}

/// Locate the JSON array in a parsed value.
/// Returns the value itself if it is an array, otherwise—if it is an object—the
/// first array-valued field, preferring conventional envelope keys.
fn extract_array(value: serde_json::Value) -> Option<Vec<serde_json::Value>> {
    match value {
        serde_json::Value::Array(arr) => Some(arr),
        serde_json::Value::Object(mut map) => {
            // Prefer well-known wrapper keys used by our prompts/backends.
            for key in ["leads", "items", "results", "data", "array"] {
                if let Some(serde_json::Value::Array(arr)) = map.remove(key) {
                    return Some(arr);
                }
            }
            // Otherwise take the first array-valued field (stable object order).
            map.into_iter().find_map(|(_, v)| match v {
                serde_json::Value::Array(arr) => Some(arr),
                _ => None,
            })
        }
        _ => None,
    }
}

/// Strip markdown code fences (```json ... ```) from a string.
/// Handles case variations: ```json, ```JSON, ``` JSON, etc.
pub(crate) fn strip_markdown_fences(content: &str) -> String {
    let trimmed = content.trim();

    // Check for ```json (case-insensitive) or bare ``` at the start
    let without_start = if let Some(after_ticks) = trimmed.strip_prefix("```") {
        let after_ticks_trimmed = after_ticks.trim_start();
        if after_ticks_trimmed.to_lowercase().starts_with("json") {
            &after_ticks_trimmed[4..]
        } else {
            after_ticks
        }
    } else {
        return trimmed.to_string();
    };

    // Find and remove closing ```
    if let Some(end_pos) = without_start.rfind("```") {
        without_start[..end_pos].trim().to_string()
    } else {
        without_start.trim().to_string()
    }
}

/// Check if a response looks like a content refusal based on common phrases.
/// Only used as a fallback when finish_reason is "stop" but JSON parsing fails.
pub(crate) fn looks_like_refusal(content: &str) -> bool {
    let lower = content.to_lowercase();
    let refusal_phrases = [
        "i cannot",
        "i'm unable to",
        "i am unable to",
        "against my guidelines",
        "i can't assist",
        "i'm not able to",
        "i cannot provide",
        "i must decline",
    ];
    refusal_phrases.iter().any(|phrase| lower.contains(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_markdown_fences_json() {
        let input = "```json\n{\"key\": \"value\"}\n```";
        assert_eq!(strip_markdown_fences(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_strip_markdown_fences_bare() {
        let input = "```\n[1, 2, 3]\n```";
        assert_eq!(strip_markdown_fences(input), "[1, 2, 3]");
    }

    #[test]
    fn test_strip_markdown_fences_none() {
        let input = "{\"key\": \"value\"}";
        assert_eq!(strip_markdown_fences(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_strip_markdown_fences_uppercase_json() {
        let input = "```JSON\n{\"key\": \"value\"}\n```";
        assert_eq!(strip_markdown_fences(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_strip_markdown_fences_spaced_json() {
        let input = "``` json\n{\"key\": \"value\"}\n```";
        assert_eq!(strip_markdown_fences(input), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_parse_json_response_success() {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            name: String,
        }
        let result: TestStruct = parse_json_response("```json\n{\"name\": \"test\"}\n```").unwrap();
        assert_eq!(result.name, "test");
    }

    #[test]
    fn test_parse_json_response_refusal() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct TestStruct {
            name: String,
        }
        let result = parse_json_response::<TestStruct>("I cannot assist with that request.");
        assert!(matches!(
            result,
            Err(RfcAnalyzerError::LlmContentRefusal { .. })
        ));
    }

    #[test]
    fn test_parse_json_response_malformed() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct TestStruct {
            name: String,
        }
        let result = parse_json_response::<TestStruct>("not json at all");
        assert!(matches!(result, Err(RfcAnalyzerError::LlmParse { .. })));
    }

    #[test]
    fn test_parse_json_array_partial() {
        #[derive(serde::Deserialize, Debug)]
        struct Item {
            x: i32,
        }
        let input = r#"[{"x": 1}, {"bad": true}, {"x": 3}]"#;
        let results: Vec<Item> = parse_json_array_partial(input).unwrap();
        // Item 2 is malformed for Item struct, should be skipped
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].x, 1);
        assert_eq!(results[1].x, 3);
    }

    #[test]
    fn test_parse_json_array_partial_object_envelope() {
        // json_object mode (OpenAI/vLLM) forces an object wrapper around the array.
        #[derive(serde::Deserialize, Debug)]
        struct Item {
            x: i32,
        }
        let input = r#"{"leads": [{"x": 1}, {"x": 2}]}"#;
        let results: Vec<Item> = parse_json_array_partial(input).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].x, 1);
        assert_eq!(results[1].x, 2);
    }

    #[test]
    fn test_parse_json_array_partial_object_first_array_field() {
        #[derive(serde::Deserialize, Debug)]
        struct Item {
            x: i32,
        }
        // Unknown wrapper key, but still a single array field to unwrap.
        let input = r#"{"vulnerabilities": [{"x": 7}]}"#;
        let results: Vec<Item> = parse_json_array_partial(input).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].x, 7);
    }

    #[test]
    fn test_parse_json_array_partial_object_no_array_errors() {
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Item {
            x: i32,
        }
        let input = r#"{"message": "no findings"}"#;
        let result = parse_json_array_partial::<Item>(input);
        assert!(matches!(result, Err(RfcAnalyzerError::LlmParse { .. })));
    }

    #[test]
    fn test_looks_like_refusal() {
        assert!(looks_like_refusal("I cannot assist with that."));
        assert!(looks_like_refusal(
            "I'm unable to provide that information."
        ));
        assert!(!looks_like_refusal("{\"leads\": []}"));
        assert!(!looks_like_refusal("Here is the analysis..."));
    }
}
