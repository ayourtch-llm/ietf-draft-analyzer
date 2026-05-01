use crate::rfc::model::{RfcNumber, Section};

/// A section with its relevance score for summarization.
#[derive(Debug, Clone)]
pub struct ScoredSection {
    pub rfc_number: RfcNumber,
    pub section: Section,
    pub score: i32,
}

/// Summarize sections to fit within a token budget.
/// Returns the combined text with provenance markers.
/// If sections had to be dropped, returns their identifiers in the second element.
pub fn summarize_to_fit(
    all_sections: &[(RfcNumber, &Section)],
    cluster_section_ids: &[(u32, String)],
    budget_tokens: u64,
    rfc_numbers_in_scope: &[RfcNumber],
) -> (String, Vec<String>) {
    use crate::llm::prompts;

    // Step 1: Build candidate set (cluster + cross-referenced-by-cluster)
    let candidates: Vec<(RfcNumber, &Section)> = all_sections
        .iter()
        .filter(|(rfc_num, section)| {
            let in_cluster = cluster_section_ids
                .iter()
                .any(|(rfc, sec)| *rfc == rfc_num.0 && sec == &section.number);
            if in_cluster {
                return true;
            }
            all_sections
                .iter()
                .filter(|(rfc, sec)| {
                    cluster_section_ids
                        .iter()
                        .any(|(cr, cs)| *cr == rfc.0 && cs == &sec.number)
                })
                .any(|(_, cluster_sec)| {
                    cluster_sec.cross_refs.iter().any(|xref| {
                        xref.target_rfc.is_some_and(|r| r.0 == rfc_num.0)
                            && xref.target_section.as_deref() == Some(&section.number)
                    })
                })
        })
        .copied()
        .collect();

    // Step 2: Score candidates
    let mut scored: Vec<ScoredSection> = candidates
        .iter()
        .map(|(rfc_num, section)| {
            let score = compute_relevance_score(
                *rfc_num,
                section,
                cluster_section_ids,
                rfc_numbers_in_scope,
                all_sections,
            );
            ScoredSection {
                rfc_number: *rfc_num,
                section: (*section).clone(),
                score,
            }
        })
        .collect();

    // Sort by score descending, then by RFC number ascending, then section number
    scored.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.rfc_number.0.cmp(&b.rfc_number.0))
            .then_with(|| compare_section_nums(&a.section.number, &b.section.number))
    });

    let mut output = String::new();
    let mut dropped = Vec::new();
    let mut used_tokens: u64 = 0;
    let full_text_budget = (budget_tokens as f64 * 0.6) as u64; // 60% for full text

    for scored_section in &scored {
        let full_text = prompts::format_section(
            scored_section.rfc_number.0,
            &scored_section.section.number,
            &scored_section.section.title,
            &scored_section.section.text,
        );
        let tokens = estimate_tokens(&full_text);

        if used_tokens + tokens <= full_text_budget {
            output.push_str(&full_text);
            output.push('\n');
            used_tokens += tokens;
        } else if used_tokens + estimate_tokens(&scored_section.section.title) < budget_tokens {
            let summary = extract_summary(&scored_section.section);
            let summary_text = prompts::format_section(
                scored_section.rfc_number.0,
                &scored_section.section.number,
                &scored_section.section.title,
                &summary,
            );
            let summary_tokens = estimate_tokens(&summary_text);
            if used_tokens + summary_tokens <= budget_tokens {
                output.push_str(&summary_text);
                output.push('\n');
                used_tokens += summary_tokens;
            } else {
                dropped.push(format!(
                    "RFC {} §{}",
                    scored_section.rfc_number.0, scored_section.section.number
                ));
            }
        } else {
            dropped.push(format!(
                "RFC {} §{}",
                scored_section.rfc_number.0, scored_section.section.number
            ));
        }
    }

    (output, dropped)
}

fn compute_relevance_score(
    rfc_number: RfcNumber,
    section: &Section,
    cluster_section_ids: &[(u32, String)],
    rfc_numbers_in_scope: &[RfcNumber],
    all_sections: &[(RfcNumber, &Section)],
) -> i32 {
    let mut score = 0i32;

    let is_in_cluster = cluster_section_ids
        .iter()
        .any(|(rfc, sec)| *rfc == rfc_number.0 && sec == &section.number);
    if is_in_cluster {
        score += 10;
    } else {
        let is_referenced_by_cluster = all_sections
            .iter()
            .filter(|(rfc, sec)| {
                cluster_section_ids
                    .iter()
                    .any(|(cr, cs)| *cr == rfc.0 && cs == &sec.number)
            })
            .any(|(_, cluster_sec)| {
                cluster_sec.cross_refs.iter().any(|xref| {
                    xref.target_rfc.is_some_and(|r| r.0 == rfc_number.0)
                        && xref.target_section.as_deref() == Some(&section.number)
                })
            });
        if is_referenced_by_cluster {
            score += 3;
        }
    }

    let rfc2119_keywords = [
        "MUST",
        "MUST NOT",
        "SHALL",
        "SHALL NOT",
        "SHOULD",
        "SHOULD NOT",
        "REQUIRED",
        "RECOMMENDED",
        "MAY",
        "OPTIONAL",
    ];
    if rfc2119_keywords.iter().any(|kw| section.text.contains(kw)) {
        score += 2;
    }

    if section.title.to_lowercase().contains("security") {
        score += 2;
    }

    let has_xrefs_in_scope = section.cross_refs.iter().any(|xref| {
        xref.target_rfc
            .is_some_and(|r| rfc_numbers_in_scope.contains(&r))
    });
    if has_xrefs_in_scope {
        score += 1;
    }

    score
}

fn extract_summary(section: &Section) -> String {
    let mut summary_parts = Vec::new();

    if let Some(first_sentence) = section.text.split('.').next() {
        let trimmed = first_sentence.trim();
        if !trimmed.is_empty() {
            summary_parts.push(format!("{}.", trimmed));
        }
    }

    let rfc2119_keywords = [
        "MUST",
        "MUST NOT",
        "SHALL",
        "SHALL NOT",
        "SHOULD",
        "SHOULD NOT",
        "REQUIRED",
        "RECOMMENDED",
        "MAY",
        "OPTIONAL",
    ];
    for sentence in section.text.split('.') {
        let trimmed = sentence.trim();
        if rfc2119_keywords.iter().any(|kw| trimmed.contains(kw)) {
            let s = format!("{}.", trimmed);
            if !summary_parts.contains(&s) {
                summary_parts.push(s);
            }
        }
    }

    for sentence in section.text.split('.') {
        let trimmed = sentence.trim();
        if trimmed.contains("[RFC") || trimmed.contains("Section ") {
            let s = format!("{}.", trimmed);
            if !summary_parts.contains(&s) {
                summary_parts.push(s);
            }
        }
    }

    summary_parts.join(" ")
}

fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64) / 4
}

/// Compare dotted section numbers using numeric-segment comparison.
pub fn compare_section_nums(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<&str> = a.split('.').collect();
    let b_parts: Vec<&str> = b.split('.').collect();

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        let ord = match (ap.parse::<u32>(), bp.parse::<u32>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            _ => ap.cmp(bp),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    a_parts.len().cmp(&b_parts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_section_nums() {
        use std::cmp::Ordering;
        assert_eq!(compare_section_nums("3.2", "3.10"), Ordering::Less);
        assert_eq!(compare_section_nums("3.10", "3.2"), Ordering::Greater);
        assert_eq!(compare_section_nums("1", "2"), Ordering::Less);
        assert_eq!(compare_section_nums("A", "B"), Ordering::Less);
        assert_eq!(compare_section_nums("3.1", "3.1"), Ordering::Equal);
        assert_eq!(compare_section_nums("3", "3.1"), Ordering::Less);
    }

    #[test]
    fn test_extract_summary_includes_first_sentence() {
        let section = Section {
            number: "1".to_string(),
            title: "Intro".to_string(),
            anchor: None,
            depth: 1,
            text: "This is the first sentence. Second sentence. Third.".to_string(),
            cross_refs: Vec::new(),
            pn: None,
        };
        let summary = extract_summary(&section);
        assert!(summary.contains("This is the first sentence."));
    }

    #[test]
    fn test_extract_summary_includes_rfc2119() {
        let section = Section {
            number: "2".to_string(),
            title: "Requirements".to_string(),
            anchor: None,
            depth: 1,
            text: "Intro sentence. Implementations MUST validate input. Optional text.".to_string(),
            cross_refs: Vec::new(),
            pn: None,
        };
        let summary = extract_summary(&section);
        assert!(summary.contains("MUST validate input"));
    }
}
