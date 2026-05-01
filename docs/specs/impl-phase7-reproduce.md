# Phase 7: Reproduction Example Generation — Implementation Spec

This document is self-contained. It builds on Phase 1-6 (which must be
complete). Implement exactly what is specified here.

**Development process**: Follow `docs/specs/dev-guidelines.md` — Red-Green
TDD, commit after each significant change or when tests pass, 85%+ coverage
target with `cargo tarpaulin`.

## Overview

Phase 7 adds automated generation of proof-of-concept reproduction scripts
for security leads. Given a lead's step-by-step attack description, RFC
section quotes, and protocol context, the LLM generates a minimal PoC
script with setup instructions and expected behavior.

At the end of Phase 7, `rfc-analyzer reproduce telnet` generates a
directory of PoC scripts for each security lead found in the Telnet
analysis.

## Files to Create / Modify

```
NEW:
  src/pipeline/reproduce.rs    -- PoC generation pipeline
  src/commands/reproduce.rs    -- cmd_reproduce command handler
  src/output/poc.rs            -- PoC output formatting and file writing

MODIFY:
  src/pipeline/mod.rs          -- add reproduce module
  src/commands/mod.rs          -- add reproduce module
  src/output/mod.rs            -- add poc module
  src/cli.rs                   -- add Reproduce command
  src/main.rs                  -- wire up Reproduce dispatch
  src/llm/prompts.rs           -- add PoC generation prompt + grammar
```

## 1. src/cli.rs — Add Reproduce Command

Add to the `Command` enum:

```rust
    /// Generate proof-of-concept reproduction scripts for security leads
    Reproduce {
        /// Protocol name (must have completed analysis)
        protocol: String,

        /// Output directory for PoC scripts
        #[arg(short, long, default_value = "pocs")]
        output_dir: PathBuf,

        /// Only generate PoCs for leads at or above this severity
        #[arg(long, default_value = "medium")]
        min_severity: String,

        /// Only generate PoC for a specific lead by fingerprint
        #[arg(long)]
        fingerprint: Option<String>,

        /// Language for generated scripts
        #[arg(long, default_value = "python")]
        language: String,
    },
```

## 2. src/llm/prompts.rs — PoC Generation Prompt and Grammar

Add the following to `prompts.rs`:

### Prompt

```rust
/// Stage 4: PoC reproduction script generation.
pub fn reproduce_prompt(
    lead_json: &str,
    rfc_sections: &str,
    language: &str,
) -> (String, String) {
    let system = format!(
        r#"You are a security researcher writing proof-of-concept scripts to demonstrate protocol vulnerabilities found in RFC specifications. Write minimal, self-contained scripts that clearly demonstrate the vulnerability. Include comments explaining each step.

The script should:
1. Set up the minimum network interaction needed
2. Craft the specific protocol messages described in the vulnerability
3. Send them to a target
4. Observe/report the outcome

Use {} as the programming language. For network operations use raw sockets or standard protocol libraries. {}"#,
        language, INJECTION_DEFENSE
    );

    let user = format!(
        r#"Generate a proof-of-concept reproduction script for this security lead:

{}

Relevant RFC specification text:
{}

Return JSON with this exact structure:
{{
  "script_name": "poc_technique_name.py",
  "description": "One-line description of what this PoC demonstrates",
  "setup": ["Step 1: Install dependencies...", "Step 2: Start target service..."],
  "code": "#!/usr/bin/env python3\n# Full script here...",
  "expected_vulnerable": "Description of what happens when the target IS vulnerable",
  "expected_patched": "Description of what happens when the target is NOT vulnerable",
  "caveats": ["Any limitations or assumptions"]
}}"#,
        lead_json, rfc_sections
    );

    (system, user)
}
```

### GBNF Grammar

```rust
/// GBNF grammar for PoC generation response.
/// Structured CoT: GOAL → PROTOCOL_STEPS → EDGE_CASES → VERIFY → JSON.
pub fn reproduce_grammar() -> String {
    format!(
        r#"root ::= think json-output
think ::= "<think>\n" "GOAL: " line "PROTOCOL_STEPS: " line "EDGE_CASES: " line "VERIFY: " line "</think>\n\n"
json-output ::= "{{" ws "\"script_name\"" ws ":" ws string ws "," ws "\"description\"" ws ":" ws string ws "," ws "\"setup\"" ws ":" ws stringarray ws "," ws "\"code\"" ws ":" ws string ws "," ws "\"expected_vulnerable\"" ws ":" ws string ws "," ws "\"expected_patched\"" ws ":" ws string ws "," ws "\"caveats\"" ws ":" ws stringarray ws "}}"
stringarray ::= "[" ws (string (ws "," ws string)*)? ws "]"
{}"#,
        GRAMMAR_COMMON
    )
}
```

## 3. src/pipeline/reproduce.rs

The PoC generation pipeline.

```rust
use crate::db::{analysis_store, rfc_store};
use crate::error::{RfcAnalyzerError, Result};
use crate::llm::client::{ChatMessage, LlmClient};
use crate::llm::prompts;
use crate::pipeline::analysis::{LeadRfcRef, SecurityLead};
use crate::rfc::model::*;
use serde::{Deserialize, Serialize};
use tokio_rusqlite::Connection;

/// LLM response for a PoC script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocResponse {
    pub script_name: String,
    pub description: String,
    pub setup: Vec<String>,
    pub code: String,
    pub expected_vulnerable: String,
    pub expected_patched: String,
    pub caveats: Vec<String>,
}

/// A generated PoC with its source lead.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedPoc {
    pub lead_fingerprint: String,
    pub lead_technique: String,
    pub lead_severity: String,
    pub lead_category: String,
    pub poc: PocResponse,
}

/// Generate PoC scripts for security leads.
pub async fn generate_pocs(
    conn: &Connection,
    llm: &LlmClient,
    protocol: &str,
    leads: &[SecurityLead],
    language: &str,
) -> Result<Vec<GeneratedPoc>> {
    let mut results = Vec::new();

    for (i, lead) in leads.iter().enumerate() {
        // Check cancellation
        if llm.cancel_token().is_cancelled() {
            tracing::info!("Cancelled, returning {} PoCs generated so far", results.len());
            return Ok(results);
        }

        tracing::info!(
            "Generating PoC {}/{}: {} [{}]",
            i + 1, leads.len(), lead.technique_name, lead.severity
        );

        // Gather RFC section text for context
        let sections_text = gather_lead_sections(conn, &lead.rfc_references).await?;

        // Serialize the lead for the prompt
        let lead_json = serde_json::to_string_pretty(lead)
            .unwrap_or_else(|_| "{}".to_string());

        // Build prompt
        let (system, user) = prompts::reproduce_prompt(&lead_json, &sections_text, language);
        let messages = vec![
            ChatMessage { role: "system".to_string(), content: system },
            ChatMessage { role: "user".to_string(), content: user },
        ];

        // Call LLM with grammar constraint
        let grammar = prompts::reproduce_grammar();
        match llm.chat_json_grammar::<PocResponse>(messages, &grammar).await {
            Ok((poc, usage)) => {
                tracing::info!(
                    "PoC generated: {} ({} tokens)",
                    poc.script_name, usage.total_tokens
                );
                results.push(GeneratedPoc {
                    lead_fingerprint: lead.fingerprint.clone(),
                    lead_technique: lead.technique_name.clone(),
                    lead_severity: lead.severity.clone(),
                    lead_category: lead.category.clone(),
                    poc,
                });
            }
            Err(RfcAnalyzerError::LlmContextOverflow) => {
                tracing::warn!(
                    "PoC for '{}': context overflow, skipping",
                    lead.technique_name
                );
            }
            Err(RfcAnalyzerError::LlmContentRefusal { detail }) => {
                tracing::warn!(
                    "PoC for '{}': content refused: {}",
                    lead.technique_name, detail
                );
            }
            Err(RfcAnalyzerError::LlmParse { detail }) => {
                tracing::warn!(
                    "PoC for '{}': parse failed: {}",
                    lead.technique_name, detail
                );
            }
            Err(e) => {
                tracing::error!(
                    "PoC for '{}': fatal error: {}",
                    lead.technique_name, e
                );
                return Err(e);
            }
        }
    }

    tracing::info!("Generated {} PoCs for {} leads", results.len(), leads.len());
    Ok(results)
}

/// Gather RFC section text for the sections referenced by a lead.
async fn gather_lead_sections(
    conn: &Connection,
    refs: &[LeadRfcRef],
) -> Result<String> {
    let mut sections_text = String::new();

    for rf in refs {
        if let Some(rfc) = rfc_store::get_rfc(conn, rf.rfc).await? {
            // Find the matching section
            for section in &rfc.sections {
                if section.number == rf.section {
                    let formatted = prompts::format_section(
                        rf.rfc, &section.number, &section.title, &section.text
                    );
                    sections_text.push_str(&formatted);
                    sections_text.push('\n');
                    break;
                }
            }
        }
    }

    if sections_text.is_empty() {
        sections_text = "No specific RFC sections available.".to_string();
    }

    Ok(sections_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poc_response_deserialize() {
        let json = r#"{
            "script_name": "poc_test.py",
            "description": "Test PoC",
            "setup": ["Install python3"],
            "code": "print('hello')",
            "expected_vulnerable": "Crash",
            "expected_patched": "Rejected",
            "caveats": ["Requires root"]
        }"#;
        let poc: PocResponse = serde_json::from_str(json).unwrap();
        assert_eq!(poc.script_name, "poc_test.py");
        assert_eq!(poc.setup.len(), 1);
        assert_eq!(poc.caveats.len(), 1);
    }
}
```

## 4. src/output/poc.rs

File writing and index generation for PoCs.

```rust
use crate::pipeline::reproduce::GeneratedPoc;
use std::fs;
use std::path::Path;

/// Write generated PoCs to a directory.
/// Creates one script file per PoC plus a README index.
pub fn write_pocs(output_dir: &Path, protocol: &str, pocs: &[GeneratedPoc]) -> std::io::Result<()> {
    // Create output directory
    fs::create_dir_all(output_dir)?;

    // Write each PoC script
    for poc in pocs {
        let script_path = output_dir.join(&poc.poc.script_name);
        fs::write(&script_path, &poc.poc.code)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms)?;
        }

        tracing::info!("Wrote {}", script_path.display());
    }

    // Write README index
    let readme = generate_readme(protocol, pocs);
    fs::write(output_dir.join("README.md"), readme)?;

    // Write machine-readable index
    let index_json = serde_json::to_string_pretty(pocs)
        .unwrap_or_else(|_| "[]".to_string());
    fs::write(output_dir.join("index.json"), index_json)?;

    tracing::info!(
        "Wrote {} PoCs + README to {}",
        pocs.len(), output_dir.display()
    );

    Ok(())
}

/// Generate a README.md index for the PoC directory.
fn generate_readme(protocol: &str, pocs: &[GeneratedPoc]) -> String {
    let mut readme = format!(
        "# {} Protocol — Proof-of-Concept Scripts\n\n\
         Generated by RFC Analyzer from protocol specification analysis.\n\n\
         **WARNING**: These scripts are for authorized security testing only.\n\
         Do not use against systems you do not own or have permission to test.\n\n\
         ## Scripts\n\n\
         | # | Script | Severity | Category | Technique |\n\
         |---|--------|----------|----------|-----------|\n",
        protocol.to_uppercase()
    );

    for (i, poc) in pocs.iter().enumerate() {
        readme.push_str(&format!(
            "| {} | [{}]({}) | {} | {} | {} |\n",
            i + 1,
            poc.poc.script_name, poc.poc.script_name,
            poc.lead_severity, poc.lead_category, poc.lead_technique
        ));
    }

    readme.push_str("\n## Details\n\n");

    for poc in pocs {
        readme.push_str(&format!("### {}\n\n", poc.lead_technique));
        readme.push_str(&format!("**Severity**: {} | **Category**: {}\n\n", poc.lead_severity, poc.lead_category));
        readme.push_str(&format!("{}\n\n", poc.poc.description));

        readme.push_str("**Setup**:\n");
        for step in &poc.poc.setup {
            readme.push_str(&format!("1. {}\n", step));
        }

        readme.push_str(&format!("\n**If vulnerable**: {}\n\n", poc.poc.expected_vulnerable));
        readme.push_str(&format!("**If patched**: {}\n\n", poc.poc.expected_patched));

        if !poc.poc.caveats.is_empty() {
            readme.push_str("**Caveats**:\n");
            for caveat in &poc.poc.caveats {
                readme.push_str(&format!("- {}\n", caveat));
            }
        }
        readme.push_str("\n---\n\n");
    }

    readme
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::reproduce::PocResponse;

    #[test]
    fn test_generate_readme() {
        let pocs = vec![GeneratedPoc {
            lead_fingerprint: "abc".to_string(),
            lead_technique: "SLC Overflow".to_string(),
            lead_severity: "high".to_string(),
            lead_category: "OversizedPayload".to_string(),
            poc: PocResponse {
                script_name: "poc_slc.py".to_string(),
                description: "Sends oversized SLC triplets".to_string(),
                setup: vec!["Start telnetd".to_string()],
                code: "print('test')".to_string(),
                expected_vulnerable: "Crash".to_string(),
                expected_patched: "Rejected".to_string(),
                caveats: vec!["Requires network access".to_string()],
            },
        }];

        let readme = generate_readme("telnet", &pocs);
        assert!(readme.contains("TELNET"));
        assert!(readme.contains("poc_slc.py"));
        assert!(readme.contains("SLC Overflow"));
        assert!(readme.contains("WARNING"));
    }
}
```

## 5. src/commands/reproduce.rs

```rust
use crate::config::Config;
use crate::db::rfc_store;
use crate::llm::client::LlmClient;
use crate::output::poc;
use crate::pipeline::analysis;
use crate::pipeline::reproduce;
use anyhow::Result;
use std::path::PathBuf;
use tokio_rusqlite::Connection;
use tokio_util::sync::CancellationToken;

pub async fn cmd_reproduce(
    conn: &Connection,
    config: &Config,
    protocol: &str,
    output_dir: PathBuf,
    min_severity: &str,
    fingerprint: Option<String>,
    language: &str,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Load existing leads
    let rfc_numbers = rfc_store::get_protocol_rfcs(conn, protocol).await?;
    if rfc_numbers.is_empty() {
        anyhow::bail!("No RFCs mapped for protocol '{}'. Run the analysis first.", protocol);
    }

    // Load leads from the latest analysis
    let all_leads = analysis::load_existing_leads_public(conn, protocol, min_severity).await?;
    if all_leads.is_empty() {
        anyhow::bail!(
            "No security leads found for '{}'. Run 'analyze {}' first.",
            protocol, protocol
        );
    }

    // Filter by fingerprint if specified
    let leads: Vec<_> = if let Some(ref fp) = fingerprint {
        all_leads.into_iter().filter(|l| l.fingerprint == *fp).collect()
    } else {
        all_leads
    };

    if leads.is_empty() {
        anyhow::bail!("No leads match the specified fingerprint.");
    }

    tracing::info!(
        "Generating PoCs for {} leads (protocol: {}, severity >= {}, language: {})",
        leads.len(), protocol, min_severity, language
    );

    let llm = LlmClient::new(config.llm.clone(), cancel_token)?;

    let pocs = reproduce::generate_pocs(conn, &llm, protocol, &leads, language).await?;

    if pocs.is_empty() {
        tracing::warn!("No PoCs generated (all leads failed or were skipped).");
        return Ok(());
    }

    // Write to output directory
    poc::write_pocs(&output_dir, protocol, &pocs)?;

    println!(
        "Generated {} PoC scripts in {}/",
        pocs.len(), output_dir.display()
    );

    Ok(())
}
```

## 6. Make `load_existing_leads` Public

In `src/pipeline/analysis.rs`, the `load_existing_leads` function is
currently private and takes a `run_id`. Add a public wrapper that loads
from the latest completed run:

```rust
/// Public API: load leads for a protocol from the latest completed run,
/// applying dedup/filter/rank.
pub async fn load_existing_leads_public(
    conn: &Connection,
    protocol: &str,
    min_severity: &str,
) -> Result<Vec<SecurityLead>> {
    let protocol_str = protocol.to_string();
    let leads = conn
        .call(move |conn| {
            // Find latest completed analyze run for this protocol
            let run_id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM analysis_runs
                     WHERE protocol = ?1 AND stage = 'analyze' AND status = 'completed'
                     ORDER BY id DESC LIMIT 1",
                    [&protocol_str],
                    |row| row.get(0),
                )
                .optional()?;

            let Some(run_id) = run_id else {
                return Ok(Vec::new());
            };

            let mut stmt = conn.prepare(
                "SELECT id, technique_name, category, severity, confidence,
                    description, rfc_references, prerequisites, entities_involved,
                    mitigation, fingerprint
                 FROM security_leads WHERE run_id = ?1
                 ORDER BY id"
            )?;
            let leads: Vec<SecurityLead> = stmt
                .query_map([run_id], |row| {
                    Ok(SecurityLead {
                        id: row.get(0)?,
                        technique_name: row.get(1)?,
                        category: row.get(2)?,
                        severity: row.get(3)?,
                        confidence: row.get(4)?,
                        description: row.get(5)?,
                        rfc_references: serde_json::from_str(
                            &row.get::<_, String>(6)?
                        ).unwrap_or_default(),
                        prerequisites: serde_json::from_str(
                            &row.get::<_, String>(7)?
                        ).unwrap_or_default(),
                        entities_involved: serde_json::from_str(
                            &row.get::<_, String>(8)?
                        ).unwrap_or_default(),
                        mitigation: row.get(9)?,
                        fingerprint: row.get::<_, Option<String>>(10)?
                            .unwrap_or_default(),
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(leads)
        })
        .await?;

    let deduplicated = deduplicate_leads(&leads);
    let mut ranked = filter_by_severity(deduplicated, min_severity);
    rank_leads(&mut ranked);
    Ok(ranked)
}
```

Add `use rusqlite::OptionalExtension;` if not already present.

## 7. Module Wiring

### src/pipeline/mod.rs (update)

```rust
pub mod analysis;
pub mod modeling;
pub mod reproduce;
pub mod section_select;
pub mod summarize;
```

### src/commands/mod.rs (update)

```rust
pub mod analyze;
pub mod clear;
pub mod graph;
pub mod map;
pub mod model;
pub mod reproduce;
pub mod run;
pub mod show;
```

### src/output/mod.rs (update)

```rust
pub mod poc;
pub mod report;
```

### src/main.rs — Add Reproduce dispatch

```rust
Command::Reproduce { protocol, output_dir, min_severity, fingerprint, language } => {
    rfc_analyzer::commands::reproduce::cmd_reproduce(
        &conn, &config, &protocol, output_dir, &min_severity,
        fingerprint, &language, cancel_token
    ).await?;
}
```

## 8. Usage Examples

```bash
# Generate PoCs for all high+ severity Telnet leads
rfc-analyzer reproduce telnet --min-severity high

# Generate PoC for a specific lead by fingerprint
rfc-analyzer reproduce telnet --fingerprint a8291b4878e03a8fee64f30483dd5297...

# Generate in a custom directory
rfc-analyzer reproduce kerberos --output-dir kerberos-pocs --min-severity critical

# Use Rust instead of Python
rfc-analyzer reproduce telnet --language rust
```

Output structure:
```
pocs/
  README.md                    -- Index with setup instructions
  index.json                   -- Machine-readable index
  poc_unbounded_slc.py         -- PoC script
  poc_slc_replay.py            -- PoC script
  poc_linemode_downgrade.py    -- PoC script
  ...
```

## 9. Tests

### src/pipeline/reproduce.rs tests (already included above)

### src/output/poc.rs tests (already included above)

### Additional: file writing test

```rust
#[cfg(test)]
mod file_tests {
    use super::*;
    use crate::pipeline::reproduce::PocResponse;
    use tempfile::tempdir;

    #[test]
    fn test_write_pocs_creates_files() {
        let dir = tempdir().unwrap();
        let pocs = vec![GeneratedPoc {
            lead_fingerprint: "fp1".to_string(),
            lead_technique: "Test".to_string(),
            lead_severity: "high".to_string(),
            lead_category: "MissingValidation".to_string(),
            poc: PocResponse {
                script_name: "poc_test.py".to_string(),
                description: "Test".to_string(),
                setup: vec![],
                code: "#!/usr/bin/env python3\nprint('test')".to_string(),
                expected_vulnerable: "Crash".to_string(),
                expected_patched: "OK".to_string(),
                caveats: vec![],
            },
        }];

        write_pocs(dir.path(), "test", &pocs).unwrap();

        assert!(dir.path().join("poc_test.py").exists());
        assert!(dir.path().join("README.md").exists());
        assert!(dir.path().join("index.json").exists());

        let script = std::fs::read_to_string(dir.path().join("poc_test.py")).unwrap();
        assert!(script.contains("print('test')"));
    }
}
```

## 10. Verification

After implementation:

1. `cargo build` succeeds with no warnings
2. `cargo test` passes all tests
3. `cargo run -- reproduce telnet --min-severity high` generates PoC scripts
4. Generated scripts are syntactically valid Python
5. README.md has correct index and setup instructions
6. `index.json` is valid JSON matching the GeneratedPoc structure

## 11. Security Note

The generated PoC scripts include a prominent warning:

> **WARNING**: These scripts are for authorized security testing only.
> Do not use against systems you do not own or have permission to test.

This warning appears in the README and as a comment at the top of each
generated script (enforced by the prompt template).
