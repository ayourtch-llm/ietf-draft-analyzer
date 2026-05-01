# Development Guidelines

This document defines the development process for the RFC Analyzer project.
All implementation specs reference this document. Follow these guidelines
for every phase of development.

## Test-Driven Development (Red-Green-Refactor)

All code changes follow the **Red-Green TDD** cycle:

1. **Red**: Write a failing test that describes the desired behavior.
2. **Green**: Write the minimum code to make the test pass.
3. **Refactor**: Clean up the code while keeping tests green.

This means:
- Tests are written **before** or **alongside** the implementation, never
  as an afterthought.
- Every public function and significant code path has at least one test.
- If fixing a bug, first write a test that reproduces the bug (red), then
  fix the code (green).

## Code Coverage

Use `cargo tarpaulin` to measure code coverage:

```bash
cargo tarpaulin --out html --output-dir coverage/
```

**Target: 85%+ line coverage** for all non-trivial modules. Coverage
below 85% should be investigated — either add tests or justify why
certain code paths are untestable (e.g., platform-specific error paths).

Modules where 85% may be impractical (and why):
- `main.rs` — CLI dispatch is better tested via integration tests
- Code paths that require live network access (fetcher, index)

For these, `#[ignore]` integration tests that run against real endpoints
are acceptable as supplementary coverage.

## Commit Discipline

### When to Commit

- **After every significant change**: a new module, a new function with
  its tests, a bug fix, a refactor.
- **Whenever all tests pass**: if you've been working on a feature and
  reach a green state, commit before continuing.
- **Before switching context**: starting a different module, taking a
  break, or beginning a refactor.

### How to Commit

- Each commit should be **atomic**: one logical change per commit.
- Commit messages should describe **what** changed and **why**.
- Format: short summary line (imperative mood), blank line, optional
  body with details.
- Always run `cargo test` before committing. Do not commit code that
  fails tests.
- Run `cargo build` with no warnings before committing. Treat warnings
  as errors.

### Example Workflow

```
1. Write test_parse_section_header()        → commit "Add test for section header parsing"
2. Implement extract_sections()             → tests pass → commit "Implement section header extraction"
3. Find edge case: appendix headers         → write failing test → commit "Add failing test for appendix headers"
4. Fix extract_sections() for appendices    → tests pass → commit "Fix section parser for appendix headers"
```

## Code Review Process

Every phase follows this cycle:

1. **Implement** from the phase spec (following TDD above)
2. **Commit** when tests pass
3. **Code review** by a separate agent or reviewer
4. **Fix** any issues found in review
5. **Commit** fixes
6. **Proceed** to the next phase only after review approval

Code reviews are saved to `docs/reviews/code-review-{phase}-{round}.md`
for traceability.

## Code Style

- No compiler warnings (`cargo build` must be clean)
- Use `cargo fmt` for formatting (default rustfmt settings)
- Use `cargo clippy` for lint checks (fix all warnings)
- Follow existing patterns in the codebase — if Phase 1 does something
  a certain way, Phase 2 should be consistent

## Error Handling

- Library code (`src/lib.rs` and modules): use `Result<T, RfcAnalyzerError>`
  with `thiserror` for typed errors.
- Binary entry point (`main.rs`): use `anyhow::Result` at the top level.
- Never use `.unwrap()` in production code paths. Use `.expect("reason")`
  only for truly impossible failures (e.g., regex compilation of a literal).
- Test code may use `.unwrap()` freely.

## Logging

- Use `tracing` macros (`tracing::info!`, `tracing::debug!`, etc.)
- `info` level: progress messages visible to the user by default
- `debug` level: implementation details useful for debugging
- `trace` level: verbose output (full prompts, raw responses)
- Never log secrets (API keys, tokens)

## Dependencies

- Do not add new dependencies without justification.
- Keep `Cargo.lock` committed (binary crate).
- Prefer well-maintained, widely-used crates.
