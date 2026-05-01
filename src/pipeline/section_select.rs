use crate::rfc::model::{RfcNumber, Section};

/// Attack categories with their selection keywords.
/// Keywords use substring matching (case-insensitive).
pub const CATEGORY_KEYWORDS: &[(&str, &[&str])] = &[
    (
        "MissingValidation",
        &[
            "validate",
            "check",
            "verify",
            "parse",
            "reject",
            "malformed",
            "invalid",
        ],
    ),
    (
        "ReplayAttack",
        &[
            "nonce",
            "sequence",
            "timestamp",
            "freshness",
            "idempotent",
            "replay",
        ],
    ),
    (
        "InformationLeak",
        &[
            "error",
            "diagnostic",
            "metadata",
            "header",
            "reveal",
            "expose",
            "disclose",
        ],
    ),
    (
        "OversizedPayload",
        &[
            "length", "size", "maximum", "limit", "truncat", "overflow", "buffer",
        ],
    ),
    (
        "StateConfusion",
        &[
            "state",
            "transition",
            "unexpected",
            "simultaneous",
            "order",
            "sequence",
        ],
    ),
    (
        "AuthBypass",
        &[
            "authenticat",
            "authoriz",
            "credential",
            "identity",
            "trust",
            "verify",
        ],
    ),
    (
        "DenialOfService",
        &[
            "resource", "limit", "exhaust", "flood", "timeout", "retry", "amplif",
        ],
    ),
    (
        "Downgrade",
        &[
            "version",
            "negotiat",
            "fallback",
            "legacy",
            "backward",
            "compatible",
        ],
    ),
    (
        "RaceCondition",
        &[
            "concurrent",
            "simultaneous",
            "atomic",
            "lock",
            "order",
            "between",
        ],
    ),
    (
        "ImplementationAmbiguity",
        &[
            "undefined",
            "unspecified",
            "implementation-defined",
            "MAY",
            "OPTIONAL",
            "local matter",
        ],
    ),
];

/// Select sections relevant to a specific attack category.
/// Returns sections sorted by relevance (most relevant first).
pub fn select_sections_for_category<'a>(
    category: &str,
    all_sections: &'a [(RfcNumber, Section)],
    state_machine_section_refs: &[(u32, String)],
) -> Vec<(RfcNumber, &'a Section)> {
    let keywords = CATEGORY_KEYWORDS
        .iter()
        .find(|(cat, _)| *cat == category)
        .map(|(_, kws)| *kws)
        .unwrap_or(&[]);

    let mut scored: Vec<(i32, RfcNumber, &Section)> = all_sections
        .iter()
        .map(|(rfc, section)| {
            let score =
                score_section_for_category(section, keywords, state_machine_section_refs, *rfc);
            (score, *rfc, section)
        })
        .filter(|(score, _, _)| *score > 0)
        .collect();

    // Sort by score descending
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    scored.into_iter().map(|(_, rfc, sec)| (rfc, sec)).collect()
}

/// Score a section's relevance to an attack category.
fn score_section_for_category(
    section: &Section,
    keywords: &[&str],
    state_machine_refs: &[(u32, String)],
    rfc_number: RfcNumber,
) -> i32 {
    let mut score = 0i32;
    let text_lower = section.text.to_lowercase();
    let title_lower = section.title.to_lowercase();

    // +3: "Security Considerations" in title (always relevant)
    if title_lower.contains("security") {
        score += 3;
    }

    // +2: Referenced by a state machine
    let is_sm_ref = state_machine_refs
        .iter()
        .any(|(rfc, sec)| *rfc == rfc_number.0 && sec == &section.number);
    if is_sm_ref {
        score += 2;
    }

    // +1 per keyword match (up to +3 max from keywords)
    let keyword_hits = keywords
        .iter()
        .filter(|kw| {
            // Case-insensitive for most keywords, case-sensitive for MAY/OPTIONAL
            if kw.chars().all(|c| c.is_uppercase()) {
                section.text.contains(*kw)
            } else {
                text_lower.contains(&kw.to_lowercase())
            }
        })
        .count();
    score += (keyword_hits as i32).min(3);

    score
}

/// Get all attack category names.
pub fn all_categories() -> Vec<&'static str> {
    CATEGORY_KEYWORDS.iter().map(|(cat, _)| *cat).collect()
}

/// Parse category filter from CLI input.
/// Maps lowercase/underscore/hyphen variants to canonical CamelCase names.
/// E.g. "missing_validation" or "missing-validation" → "MissingValidation"
pub fn resolve_categories(filter: Option<&[String]>) -> Vec<&'static str> {
    match filter {
        None => all_categories(),
        Some(names) => {
            let all = all_categories();
            names
                .iter()
                .filter_map(|name| {
                    let normalized = name.to_lowercase().replace(['-', '_'], "");
                    all.iter()
                        .find(|cat| cat.to_lowercase() == normalized)
                        .copied()
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::model::*;

    fn make_section(num: &str, title: &str, text: &str) -> Section {
        Section {
            number: num.to_string(),
            title: title.to_string(),
            anchor: None,
            depth: 1,
            text: text.to_string(),
            cross_refs: Vec::new(),
            pn: None,
        }
    }

    #[test]
    fn test_security_section_always_selected() {
        let sections = vec![
            (
                RfcNumber(9293),
                make_section("10", "Security Considerations", "Be careful."),
            ),
            (
                RfcNumber(9293),
                make_section("1", "Introduction", "This is TCP."),
            ),
        ];
        let selected = select_sections_for_category("MissingValidation", &sections, &[]);
        assert!(!selected.is_empty());
        assert_eq!(selected[0].1.number, "10"); // Security first
    }

    #[test]
    fn test_keyword_matching() {
        let sections = vec![
            (
                RfcNumber(1),
                make_section(
                    "3",
                    "Validation",
                    "Implementations MUST validate all input fields.",
                ),
            ),
            (
                RfcNumber(1),
                make_section("4", "Overview", "This section provides an overview."),
            ),
        ];
        let selected = select_sections_for_category("MissingValidation", &sections, &[]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.number, "3");
    }

    #[test]
    fn test_state_machine_refs_boost() {
        let sections = vec![
            (
                RfcNumber(1),
                make_section("3", "States", "The connection has states."),
            ),
            (
                RfcNumber(1),
                make_section("4", "Other", "The connection has states."),
            ),
        ];
        // Section 3 is referenced by state machine
        let sm_refs = vec![(1u32, "3".to_string())];
        let selected = select_sections_for_category("StateConfusion", &sections, &sm_refs);
        // Section 3 should rank higher (has SM ref bonus)
        assert_eq!(selected[0].1.number, "3");
    }

    #[test]
    fn test_case_sensitive_keywords() {
        let sections = vec![
            (
                RfcNumber(1),
                make_section("1", "Options", "Implementations MAY support this."),
            ),
            (
                RfcNumber(1),
                make_section("2", "May", "In the month of may, things happen."),
            ),
        ];
        let selected = select_sections_for_category("ImplementationAmbiguity", &sections, &[]);
        // Only section 1 should match (uppercase MAY)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.number, "1");
    }

    #[test]
    fn test_resolve_categories() {
        let all = resolve_categories(None);
        assert_eq!(all.len(), 10);

        let filtered = resolve_categories(Some(&[
            "missing_validation".to_string(),
            "replay_attack".to_string(),
        ]));
        assert_eq!(filtered.len(), 2);
    }
}
