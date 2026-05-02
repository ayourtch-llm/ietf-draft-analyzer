# Code Review 7-1: Phase 7 PoC Reproduction Generation

## 1) Summary

Phase 7 adds the requested reproduction command, PoC generation pipeline, prompt/grammar additions, and file-output module. The code is generally clean, integrates with the completed Phase 1-6 command/module layout, and the reported 104 passing tests with zero warnings is consistent with the implementation.

The implementation addresses several pre-implementation risks: it restricts v1 to Python, adds cancellation handling around LLM errors, deduplicates RFC section references, prepends a warning to generated scripts, and sanitizes script filenames before writing.

The main remaining problems are in output artifact correctness and safety. The actual script filename used on disk can differ from the `script_name` in the README and `index.json`, duplicate sanitized names can overwrite earlier PoCs, and README fields are not escaped. Those are fixable, but they matter because Phase 7 writes LLM-controlled content to disk.

## 2) Spec Compliance

What matches:

- `src/cli.rs` adds the `Reproduce` command with `protocol`, `--output-dir`, `--min-severity`, `--fingerprint`, and `--language`.
- `src/main.rs` dispatches `Command::Reproduce` to `commands::reproduce::cmd_reproduce`.
- `src/commands/reproduce.rs` validates language, loads mapped protocol RFCs, loads latest completed analysis leads, applies fingerprint filtering, creates an `LlmClient`, generates PoCs, and writes them.
- `src/pipeline/reproduce.rs` defines `PocResponse`, `GeneratedPoc`, `generate_pocs`, and RFC-section gathering.
- `src/llm/prompts.rs` adds `reproduce_prompt` and `reproduce_grammar`.
- `src/output/poc.rs` writes one script per generated PoC plus `README.md` and `index.json`, and sets executable permissions on Unix.
- `src/pipeline/analysis.rs` exposes `load_existing_leads_public`, loading the latest completed analyze run and applying the same dedup/filter/rank path.
- Module wiring is present in `pipeline/mod.rs`, `commands/mod.rs`, and `output/mod.rs`.

Intentional deviations or acceptable choices:

- The spec examples mention `--language rust`, but the implementation restricts v1 to Python. That matches the pre-review recommendation and is acceptable, but the docs/spec should be updated so examples do not imply Rust support.
- The generated script warning is enforced by `write_pocs` rather than relying on the LLM prompt. That is better than prompt-only enforcement.

## 3) Code Quality Issues

- `src/output/poc.rs:13-22`: filename sanitization is local to `write_pocs` and not represented in `GeneratedPoc`. The rest of the output code still uses the original LLM-provided `script_name`. A small `safe_script_name(...)` helper returning a non-empty basename would centralize this and make tests stronger.

- `src/output/poc.rs:75-84`: the README table uses raw LLM/model strings for script name, severity, category, and technique. Markdown table separators (`|`) and newlines can break the table. Escape or normalize Markdown fields before writing.

- `src/output/poc.rs:89-114`: README details also include raw LLM-provided text. This is not code execution, but it can produce malformed Markdown or misleading links/content. At minimum, normalize newlines in table fields and escape obvious Markdown table/link hazards.

- `src/pipeline/reproduce.rs:32-38`: `protocol` is currently unused and named `_protocol`. If protocol context matters for generation, include it in the prompt. If not, remove it from the pipeline signature and keep it only at the command/output layer.

- `src/commands/reproduce.rs:23`: language validation is case-sensitive. `--language Python` currently fails. Either document lowercase-only or normalize with `eq_ignore_ascii_case`.

## 4) Bugs or Correctness Concerns

- `src/output/poc.rs:22` and `src/output/poc.rs:75-80`: README links can point to a different path than the file actually written. For example, `../../../etc/evil.py` is sanitized for the script file, but the README link still uses `../../../etc/evil.py`. This preserves a path-traversal-looking link in the generated index and makes the README inaccurate. Use the final safe filename consistently in script writing, README, and `index.json`.

- `src/output/poc.rs:11-31`: duplicate sanitized filenames overwrite earlier generated scripts. Two leads can both produce `poc.py`, or different malicious names can sanitize to the same value. The spec asked for one script per PoC; this can silently reduce multiple PoCs to one file. Prefix with index and fingerprint prefix, or detect collisions and append a suffix.

- `src/output/poc.rs:14-22`: sanitization can produce an empty filename or a reserved/unhelpful name like `"."`, `".."` after filtering, or a hidden/dot-only name. `fs::write(output_dir.join(&safe_name), ...)` can then fail or behave unexpectedly. Enforce a fallback like `poc_{index}_{fingerprint}.py`.

- `src/output/poc.rs:49-51`: `index.json` serializes the original `GeneratedPoc`, not the actual safe filename written to disk. Machine consumers cannot reliably find the script files from the index when names were sanitized or deduplicated.

- `src/commands/reproduce.rs:37-57`: fingerprint filtering happens after severity filtering. With the default `--min-severity medium`, asking for a low-severity fingerprint reports “No leads match” even if that fingerprint exists. This may be intended, but it is surprising for an exact-fingerprint lookup. Consider making `--fingerprint` bypass severity or produce a clearer message.

- Test coverage still misses the most important integration paths. There are unit tests for serialization, README generation, basic file writing, and simple sanitization, but no mocked LLM test for `generate_pocs`, no test for `load_existing_leads_public`, no test for duplicate sanitized filenames, no test that README/index use the actual written filenames, and no `cmd_reproduce` test for language/fingerprint/no-leads behavior.

- Verification says generated scripts are syntactically valid Python, but the implementation does not validate syntax. Since the scripts are LLM-generated, a `python -m py_compile` verification step or explicit manual-verification note is needed if this remains a release criterion.

## 5) Verdict

Needs fixes before sign-off.

The Phase 7 feature is substantially implemented and should compile, but the file-output layer is not yet robust enough for LLM-controlled artifacts. Fix safe filename propagation, duplicate-name handling, README/index consistency, and add focused tests around those paths. After that, the feature should be ready for practical use.
