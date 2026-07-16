use crate::rfc::model::{RfcNumber, Section};
use std::collections::{BTreeSet, HashMap};

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

    let review_context = select_security_context(all_sections);
    let document_frequencies = document_frequencies(all_sections);

    let mut scored: Vec<(i32, RfcNumber, &Section)> = all_sections
        .iter()
        .map(|(rfc, section)| {
            let score =
                score_section_for_category(section, keywords, state_machine_section_refs, *rfc)
                    + semantic_bridge_score(
                        *rfc,
                        section,
                        &review_context,
                        &document_frequencies,
                        all_sections.len(),
                    );
            (score, *rfc, section)
        })
        .filter(|(score, _, _)| *score > 0)
        .collect();

    // Sort by score descending with deterministic provenance tie-breakers.
    scored.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.0.cmp(&right.1.0))
            .then_with(|| left.2.number.cmp(&right.2.number))
    });

    scored.into_iter().map(|(_, rfc, sec)| (rfc, sec)).collect()
}

/// Select security, implementation-guidance, and threat-constraint sections.
///
/// These sections are supplied to Stage 3 as a separate review baseline. In
/// addition to conventional Security Considerations, this includes appendices
/// such as Implementation Notes/Pitfalls and sections that contain explicit
/// threat or trust constraints even when their title is innocuous.
pub fn select_security_context(
    all_sections: &[(RfcNumber, Section)],
) -> Vec<(RfcNumber, &Section)> {
    let roots: Vec<(RfcNumber, String)> = all_sections
        .iter()
        .filter(|(_, section)| is_review_guidance_title(&section.title))
        .map(|(rfc, section)| (*rfc, section.number.clone()))
        .collect();

    all_sections
        .iter()
        .filter(|(rfc, section)| {
            contains_threat_constraint(&section.text)
                || roots.iter().any(|(root_rfc, root_number)| {
                    root_rfc == rfc
                        && (section.number == *root_number
                            || section
                                .number
                                .strip_prefix(root_number)
                                .is_some_and(|suffix| suffix.starts_with('.')))
                })
        })
        .map(|(rfc, section)| (*rfc, section))
        .collect()
}

fn is_review_guidance_title(title: &str) -> bool {
    let title = title.to_lowercase();
    [
        "security",
        "implementation note",
        "implementation pitfall",
        "implementation consideration",
        "operational consideration",
        "interoperability",
        "conformance",
    ]
    .iter()
    .any(|phrase| title.contains(phrase))
}

fn contains_threat_constraint(text: &str) -> bool {
    let text = text.to_lowercase();
    [
        "attacker",
        "impersonat",
        "integrity-protected",
        "must not rely",
        "security risk",
        "vulnerab",
    ]
    .iter()
    .any(|phrase| text.contains(phrase))
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

    // +4: security/implementation/conformance guidance is always valuable.
    if is_review_guidance_title(&section.title) {
        score += 4;
    }
    if contains_threat_constraint(&section.text) {
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
                section.text.contains(*kw) || section.title.contains(*kw)
            } else {
                let keyword = kw.to_lowercase();
                text_lower.contains(&keyword) || title_lower.contains(&keyword)
            }
        })
        .count();
    score += (keyword_hits as i32).min(3);

    score
}

fn semantic_bridge_score(
    rfc_number: RfcNumber,
    section: &Section,
    review_context: &[(RfcNumber, &Section)],
    document_frequencies: &HashMap<String, usize>,
    section_count: usize,
) -> i32 {
    let section_terms = normalized_terms(&format!("{} {}", section.title, section.text));
    let section_acronyms = acronyms(&format!("{} {}", section.title, section.text));
    let rare_threshold = (section_count / 12).max(3);
    let mut best_score = 0;

    for (review_rfc, review_section) in review_context {
        if *review_rfc == rfc_number && review_section.number == section.number {
            continue;
        }

        let review_text = format!("{} {}", review_section.title, review_section.text);
        let review_terms = normalized_terms(&review_text);
        let rare_overlap = section_terms
            .intersection(&review_terms)
            .filter(|term| {
                document_frequencies
                    .get(term.as_str())
                    .is_some_and(|frequency| *frequency <= rare_threshold)
            })
            .count();

        let shared_acronyms = section_acronyms
            .intersection(&acronyms(&review_text))
            .count();
        let score = match (shared_acronyms, rare_overlap) {
            (2.., _) => 4,
            (1, 2..) => 4,
            (1, _) | (_, 2..) => 3,
            (_, 1) => 1,
            _ => 0,
        };
        best_score = best_score.max(score);
    }

    best_score
}

fn document_frequencies(all_sections: &[(RfcNumber, Section)]) -> HashMap<String, usize> {
    let mut frequencies = HashMap::new();
    for (_, section) in all_sections {
        for term in normalized_terms(&format!("{} {}", section.title, section.text)) {
            *frequencies.entry(term).or_insert(0) += 1;
        }
    }
    frequencies
}

fn normalized_terms(text: &str) -> BTreeSet<String> {
    const STOP_WORDS: &[&str] = &[
        "about", "after", "also", "been", "before", "being", "between", "from", "have", "into",
        "must", "other", "section", "should", "that", "their", "there", "these", "this", "those",
        "using", "when", "where", "which", "with",
    ];

    text.to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 3 && !STOP_WORDS.contains(term))
        .map(ToString::to_string)
        .collect()
}

fn acronyms(text: &str) -> BTreeSet<String> {
    const IGNORED: &[&str] = &["MUST", "NOT", "SHOULD", "MAY", "RFC", "IANA", "ASCII"];

    text.split(|character: char| !character.is_alphanumeric() && character != '-')
        .filter(|term| {
            (2..=12).contains(&term.len())
                && term.chars().any(|character| character.is_alphabetic())
                && term
                    .chars()
                    .all(|character| !character.is_alphabetic() || character.is_uppercase())
                && !IGNORED.contains(term)
        })
        .map(|term| term.to_lowercase())
        .collect()
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
    fn test_security_context_includes_descendants_but_not_siblings() {
        let sections = vec![
            (
                RfcNumber(1),
                make_section("5", "Security Considerations", "Threat overview."),
            ),
            (
                RfcNumber(1),
                make_section("5.1", "Authentication", "Use strong authentication."),
            ),
            (
                RfcNumber(1),
                make_section("6", "IANA Considerations", "Registry text."),
            ),
        ];

        let selected = select_security_context(&sections);
        let numbers: Vec<&str> = selected
            .iter()
            .map(|(_, section)| section.number.as_str())
            .collect();
        assert_eq!(numbers, vec!["5", "5.1"]);
    }

    #[test]
    fn test_review_context_includes_implementation_appendix() {
        let sections = vec![
            (
                RfcNumber(8446),
                make_section("C", "Implementation Notes", "General notes."),
            ),
            (
                RfcNumber(8446),
                make_section(
                    "C.5",
                    "Unauthenticated Operation",
                    "Implementations MUST validate certificates.",
                ),
            ),
            (
                RfcNumber(8446),
                make_section("D", "Backwards Compatibility", "Compatibility."),
            ),
        ];

        let selected = select_security_context(&sections);
        let numbers: Vec<&str> = selected
            .iter()
            .map(|(_, section)| section.number.as_str())
            .collect();
        assert_eq!(numbers, vec!["C", "C.5"]);
    }

    #[test]
    fn test_semantic_bridge_links_trust_warning_to_dns_discovery() {
        let sections = vec![
            (
                RfcNumber(4120),
                make_section(
                    "1.3",
                    "Choosing a Principal",
                    "One MUST NOT rely on an unprotected DNS record because an attacker can impersonate the party registered with the KDC.",
                ),
            ),
            (
                RfcNumber(4120),
                make_section(
                    "7.2.3.2",
                    "Specifying KDC Location Information with DNS SRV records",
                    "KDC location information is stored using DNS SRV records for the Kerberos realm.",
                ),
            ),
            (
                RfcNumber(4120),
                make_section("9", "ASN.1 Module", "Protocol syntax."),
            ),
        ];

        let selected = select_sections_for_category("AuthBypass", &sections, &[]);
        assert!(selected.iter().any(|(_, section)| section.number == "1.3"));
        assert!(
            selected
                .iter()
                .any(|(_, section)| section.number == "7.2.3.2")
        );
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
