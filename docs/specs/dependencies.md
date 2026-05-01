# Rust Dependencies

## Runtime Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4.x | CLI argument parsing (derive API) |
| `serde` | 1.x | Serialization/deserialization framework |
| `serde_json` | 1.x | JSON serialization for output and LLM responses |
| `reqwest` | 0.12.x | HTTP client for RFC fetching and LLM API calls |
| `tokio` | 1.x | Async runtime (features: full) |
| `quick-xml` | 0.37.x | XML parsing for RFC 7991+ format |
| `rusqlite` | 0.32.x | SQLite database (feature: bundled) |
| `petgraph` | 0.7.x | Graph data structure for dependency mapping |
| `regex` | 1.x | Cross-reference extraction from plain text |
| `thiserror` | 2.x | Typed error definitions |
| `anyhow` | 1.x | Error handling at CLI boundary |
| `sha2` | 0.10.x | SHA-256 content hashing for incrementality |
| `chrono` | 0.4.x | Date/time handling (feature: serde) |
| `tracing` | 0.1.x | Structured logging |
| `tracing-subscriber` | 0.3.x | Log output (feature: env-filter) |
| `toml` | 0.8.x | Configuration file parsing |
| `governor` | 0.8.x | Rate limiting for LLM API calls |
| `zstd` | 0.13.x | Compression for cached RFC content |
| `uuid` | 1.x | UUID v4 generation for lead IDs |
| `tokio-rusqlite` | 0.6.x | Async bridge for rusqlite (dedicated SQLite thread) |

## Dev Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tempfile` | 3.x | Temporary files/dirs for DB tests |
| `wiremock` | 0.6.x | HTTP mocking for LLM and RFC fetcher tests |
| `assert_json_diff` | 2.x | JSON comparison in tests |
| `insta` | 1.x | Snapshot testing for parsed RFC structures |

## Rationale

### Why `quick-xml` over `roxmltree`?
`quick-xml` is a streaming parser with lower memory usage, important when
parsing large RFC XML documents. It also supports serialization via serde.

### Why `rusqlite` with `bundled`?
The `bundled` feature compiles SQLite from source, eliminating the need for
a system SQLite installation. This makes the tool portable and ensures a
consistent SQLite version.

### Why `petgraph`?
The de-facto Rust graph library. `StableDiGraph` provides stable node indices
that survive node removal, which is useful if we later add graph pruning.
Directed edges naturally represent asymmetric RFC relationships.

### Why `governor` for rate limiting?
Battle-tested rate limiter that integrates well with tokio. Supports both
token bucket and sliding window algorithms.

### Why `tokio-rusqlite`?
`rusqlite` is synchronous but the pipeline runs on tokio. `tokio-rusqlite`
runs a dedicated background thread for SQLite with a channel-based async API,
avoiding `Mutex` contention and `spawn_blocking` boilerplate.

### Why `zstd` for compression?
Better compression ratio than gzip/deflate for text content, with very fast
decompression. RFC text compresses 3-4x with zstd.

## Build and Toolchain

- `Cargo.lock` must be committed to the repository (standard practice for
  binary crates, ensures reproducible builds).
- Minimum supported Rust version: 1.85+ (required for edition 2024).

## Cargo.toml

```toml
[package]
name = "rfc-analyzer"
version = "0.1.0"
edition = "2024"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", features = ["json", "gzip"] }
tokio = { version = "1", features = ["full"] }
quick-xml = { version = "0.37", features = ["serialize"] }
rusqlite = { version = "0.32", features = ["bundled"] }
petgraph = "0.7"
regex = "1"
thiserror = "2"
anyhow = "1"
sha2 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
toml = "0.8"
governor = "0.8"
zstd = "0.13"
uuid = { version = "1", features = ["v4"] }
tokio-rusqlite = "0.6"

[dev-dependencies]
tempfile = "3"
wiremock = "0.6"
assert_json_diff = "2"
insta = "1"
```
