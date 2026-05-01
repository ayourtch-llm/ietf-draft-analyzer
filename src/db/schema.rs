use rusqlite::Connection;

/// Each migration: (version_number, sql_to_execute)
/// Migrations are applied in order. Never remove or reorder entries.
const MIGRATIONS: &[(i64, &str)] = &[(
    1,
    r#"
        CREATE TABLE rfcs (
            number        INTEGER PRIMARY KEY,
            title         TEXT NOT NULL,
            format        TEXT NOT NULL CHECK (format IN ('xml', 'text')),
            status        TEXT NOT NULL,
            date          TEXT NOT NULL,
            raw_content   BLOB NOT NULL,
            content_hash  TEXT NOT NULL,
            fetched_at    TEXT NOT NULL DEFAULT (datetime('now')),
            obsoletes     TEXT,
            updates       TEXT,
            obsoleted_by  TEXT,
            updated_by    TEXT,
            references_json TEXT             -- JSON array of Reference objects
        );

        CREATE TABLE sections (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
            section_num   TEXT NOT NULL,
            title         TEXT NOT NULL,
            depth         INTEGER NOT NULL,
            anchor        TEXT,
            text          TEXT NOT NULL,
            pn            TEXT,
            UNIQUE(rfc_number, section_num)
        );
        CREATE INDEX idx_sections_rfc ON sections(rfc_number);

        CREATE TABLE cross_refs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            source_section  TEXT NOT NULL,
            target_rfc      INTEGER,
            target_section  TEXT,
            context         TEXT NOT NULL
        );
        CREATE INDEX idx_xrefs_source ON cross_refs(source_rfc);
        CREATE INDEX idx_xrefs_target ON cross_refs(target_rfc);
        CREATE INDEX idx_xrefs_pair ON cross_refs(source_rfc, target_rfc);

        CREATE TABLE dep_edges (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            target_rfc      INTEGER NOT NULL REFERENCES rfcs(number),
            kind            TEXT NOT NULL,
            source_section  TEXT,
            target_section  TEXT,
            UNIQUE(source_rfc, target_rfc, kind, source_section, target_section)
        );
        CREATE INDEX idx_edges_source ON dep_edges(source_rfc);
        CREATE INDEX idx_edges_target ON dep_edges(target_rfc);

        CREATE TABLE protocol_rfcs (
            protocol      TEXT NOT NULL,
            rfc_number    INTEGER NOT NULL REFERENCES rfcs(number),
            PRIMARY KEY (protocol, rfc_number)
        );
        CREATE INDEX idx_protocol_rfcs_rfc ON protocol_rfcs(rfc_number);

        CREATE TABLE state_machines (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol      TEXT NOT NULL,
            name          TEXT NOT NULL,
            mechanism     TEXT NOT NULL,
            data          TEXT NOT NULL,
            content_hash  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(protocol, name)
        );
        CREATE INDEX idx_state_machines_protocol ON state_machines(protocol);

        CREATE TABLE security_leads (
            id                  TEXT PRIMARY KEY,
            protocol            TEXT NOT NULL,
            technique_name      TEXT NOT NULL,
            category            TEXT NOT NULL,
            severity            TEXT NOT NULL,
            confidence          REAL NOT NULL,
            description         TEXT NOT NULL,
            rfc_references      TEXT NOT NULL,
            prerequisites       TEXT NOT NULL,
            entities_involved   TEXT NOT NULL,
            state_machine_name  TEXT,
            mitigation          TEXT,
            input_hash          TEXT NOT NULL,
            created_at          TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX idx_leads_protocol ON security_leads(protocol);
        CREATE INDEX idx_leads_category ON security_leads(category);
        CREATE INDEX idx_leads_severity ON security_leads(severity);

        CREATE TABLE analysis_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol        TEXT NOT NULL,
            stage           TEXT NOT NULL,
            started_at      TEXT NOT NULL,
            completed_at    TEXT,
            model_used      TEXT,
            tokens_used     INTEGER DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'running',
            error           TEXT,
            seed_rfcs       TEXT,
            depth           INTEGER,
            normative_only  INTEGER,
            mechanism_filter TEXT,
            category_filter  TEXT,
            prompt_version  TEXT,
            input_hash      TEXT,
            effective_rfcs  TEXT
        );
        CREATE INDEX idx_runs_protocol ON analysis_runs(protocol, stage);
    "#,
)];

/// Initialize SQLite pragmas on a raw connection.
/// Called once when the connection is first opened.
pub fn init_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;",
    )
}

/// Run pending migrations. Creates the schema_version table if needed.
/// Returns the final schema version.
pub fn run_migrations(conn: &Connection) -> rusqlite::Result<i64> {
    // Create schema_version if it doesn't exist
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER NOT NULL UNIQUE,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    // Get current version
    let current_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;

    // Apply pending migrations
    for &(version, sql) in MIGRATIONS {
        if version > current_version {
            tracing::info!("Applying migration v{}", version);
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )?;
        }
    }

    let final_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;

    tracing::info!("Database at schema version {}", final_version);
    Ok(final_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_pragmas() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn test_run_migrations_from_empty() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let version = run_migrations(&conn).unwrap();
        assert_eq!(version, 1);

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rfcs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_run_migrations_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let v1 = run_migrations(&conn).unwrap();
        let v2 = run_migrations(&conn).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_all_tables_created() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        run_migrations(&conn).unwrap();

        let expected_tables = [
            "rfcs",
            "sections",
            "cross_refs",
            "dep_edges",
            "protocol_rfcs",
            "state_machines",
            "security_leads",
            "analysis_runs",
            "schema_version",
        ];
        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table '{}' should exist", table);
        }
    }
}
