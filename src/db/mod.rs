pub mod rfc_store;
pub mod schema;

use crate::error::Result;
use std::path::Path;
use tokio_rusqlite::Connection;

/// Open (or create) the database, initialize pragmas, and run migrations.
/// Returns a tokio-rusqlite Connection (async wrapper around rusqlite).
pub async fn open_database(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).await?;

    conn.call(|conn| {
        schema::init_pragmas(conn)?;
        schema::run_migrations(conn)?;
        Ok(())
    })
    .await?;

    Ok(conn)
}

/// Open an in-memory database for testing.
#[cfg(test)]
pub async fn open_memory_database() -> Result<Connection> {
    let conn = Connection::open_in_memory().await?;

    conn.call(|conn| {
        schema::init_pragmas(conn)?;
        schema::run_migrations(conn)?;
        Ok(())
    })
    .await?;

    Ok(conn)
}
