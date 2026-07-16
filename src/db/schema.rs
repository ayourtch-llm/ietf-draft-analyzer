use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 3;

/// Each migration: (version_number, sql_to_execute)
/// Migrations are applied in order. Never remove or reorder entries.
const MIGRATIONS: &[(i64, &str)] = &[
    (
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
    ),
    (
        2,
        r#"
        BEGIN;

        -- Add run_id to security_leads
        ALTER TABLE security_leads ADD COLUMN run_id INTEGER
            REFERENCES analysis_runs(id) ON DELETE CASCADE;
        ALTER TABLE security_leads ADD COLUMN fingerprint TEXT;
        CREATE INDEX idx_leads_fingerprint ON security_leads(fingerprint);
        CREATE INDEX idx_leads_run ON security_leads(run_id);

        -- Recreate state_machines with run_id and relaxed uniqueness
        CREATE TABLE state_machines_new (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol      TEXT NOT NULL,
            name          TEXT NOT NULL,
            mechanism     TEXT NOT NULL,
            data          TEXT NOT NULL,
            content_hash  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            run_id        INTEGER REFERENCES analysis_runs(id) ON DELETE CASCADE,
            UNIQUE(protocol, name, run_id)
        );
        INSERT INTO state_machines_new
            (id, protocol, name, mechanism, data, content_hash, created_at)
            SELECT id, protocol, name, mechanism, data, content_hash, created_at
            FROM state_machines;
        DROP TABLE state_machines;
        ALTER TABLE state_machines_new RENAME TO state_machines;
        CREATE INDEX idx_state_machines_protocol ON state_machines(protocol);
        CREATE INDEX idx_state_machines_run ON state_machines(run_id);

        -- Per-work-item tracking for resumability
        CREATE TABLE run_work_items (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id          INTEGER NOT NULL
                            REFERENCES analysis_runs(id) ON DELETE CASCADE,
            work_item_kind  TEXT NOT NULL,
            work_item_key   TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending', 'running', 'completed', 'failed')),
            started_at      TEXT,
            completed_at    TEXT,
            tokens_used     INTEGER DEFAULT 0,
            error           TEXT,
            input_hash      TEXT,
            UNIQUE(run_id, work_item_kind, work_item_key)
        );
        CREATE INDEX idx_work_items_run ON run_work_items(run_id);

        COMMIT;
    "#,
    ),
    (
        3,
        r#"
        PRAGMA foreign_keys = OFF;
        BEGIN;

        CREATE TABLE rfcs_new (
            number        INTEGER PRIMARY KEY,
            title         TEXT NOT NULL,
            format        TEXT NOT NULL CHECK (format IN ('xml', 'text', 'html')),
            status        TEXT NOT NULL,
            date          TEXT NOT NULL,
            raw_content   BLOB NOT NULL,
            content_hash  TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            fetched_at    TEXT NOT NULL DEFAULT (datetime('now')),
            obsoletes     TEXT,
            updates       TEXT,
            obsoleted_by  TEXT,
            updated_by    TEXT,
            references_json TEXT
        );

        INSERT INTO rfcs_new (
            number, title, format, status, date, raw_content, content_hash,
            parser_version, fetched_at, obsoletes, updates, obsoleted_by,
            updated_by, references_json
        )
        SELECT
            number, title, format, status, date, raw_content, content_hash,
            '1', fetched_at, obsoletes, updates, obsoleted_by, updated_by,
            references_json
        FROM rfcs;

        DROP TABLE rfcs;
        ALTER TABLE rfcs_new RENAME TO rfcs;

        COMMIT;
        PRAGMA foreign_keys = ON;
    "#,
    ),
];

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
            if let Err(error) = conn.execute_batch(sql) {
                let _ = conn.execute_batch("ROLLBACK;");
                let _ = conn.execute_batch("PRAGMA foreign_keys = ON;");
                return Err(error);
            }
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
        assert_eq!(version, i64::from(SCHEMA_VERSION));
        assert_eq!(
            conn.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );

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
            "run_work_items",
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

    #[test]
    fn test_migration_v2_creates_run_work_items() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let version = run_migrations(&conn).unwrap();
        assert_eq!(version, i64::from(SCHEMA_VERSION));

        // Verify run_work_items exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='run_work_items'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_migration_v2_preserves_existing_data() {
        // Simulate a v1 database with data, then upgrade to v2
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();

        // Create schema_version table (as run_migrations would)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL UNIQUE,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();

        // Manually apply only migration 1
        conn.execute_batch(MIGRATIONS[0].1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();

        // Insert v1 state_machines row
        conn.execute(
            "INSERT INTO state_machines (protocol, name, mechanism, data, content_hash)
             VALUES ('tcp', 'connection', 'state', '{}', 'h1')",
            [],
        )
        .unwrap();

        // Now run full migrations — should upgrade to v2 preserving data
        let version = run_migrations(&conn).unwrap();
        assert_eq!(version, i64::from(SCHEMA_VERSION));

        // Verify existing data survived
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM state_machines WHERE name = 'connection'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Verify run_id column exists (nullable, so existing row has NULL)
        let run_id: Option<i64> = conn
            .query_row(
                "SELECT run_id FROM state_machines WHERE name = 'connection'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(run_id.is_none());
    }

    #[test]
    fn test_migration_v2_state_machines_has_run_id() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        run_migrations(&conn).unwrap();

        // Insert an analysis run first
        conn.execute(
            "INSERT INTO analysis_runs (protocol, stage, started_at, status) VALUES ('tcp', 'model', '2024-01-01', 'completed')",
            [],
        )
        .unwrap();

        // state_machines should accept run_id
        conn.execute(
            "INSERT INTO state_machines (protocol, name, mechanism, data, content_hash, run_id) VALUES ('tcp', 'test', 'auth', '{}', 'hash', 1)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn test_migration_v3_adds_html_and_parser_version() {
        let conn = Connection::open_in_memory().unwrap();
        init_pragmas(&conn).unwrap();
        let version = run_migrations(&conn).unwrap();
        assert_eq!(version, i64::from(SCHEMA_VERSION));

        conn.execute(
            "INSERT INTO rfcs (
                number, title, format, status, date, raw_content,
                content_hash, parser_version
             ) VALUES (99001, 'HTML standard', 'html', 'standard',
                       '2026-01-01', x'00', 'hash', '1')",
            [],
        )
        .unwrap();

        let parser_version: String = conn
            .query_row(
                "SELECT parser_version FROM rfcs WHERE number = 99001",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parser_version, "1");
    }
}
