use crate::error::Result;
use crate::rfc::model::RfcNumber;
use chrono::Utc;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

/// Create a new analysis run record. Returns the run_id.
#[allow(clippy::too_many_arguments)]
pub async fn create_run(
    conn: &Connection,
    protocol: &str,
    stage: &str,
    model_used: Option<&str>,
    seed_rfcs: &[RfcNumber],
    depth: Option<u32>,
    normative_only: Option<bool>,
    mechanism_filter: Option<&[String]>,
    category_filter: Option<&[String]>,
    prompt_version: &str,
    input_hash: &str,
) -> Result<i64> {
    let protocol = protocol.to_string();
    let stage = stage.to_string();
    let model_used = model_used.map(|s| s.to_string());
    let seed_rfcs_json = serde_json::to_string(&seed_rfcs.iter().map(|r| r.0).collect::<Vec<_>>())
        .unwrap_or_else(|_| "[]".to_string());
    let mechanism_json = mechanism_filter.map(|f| {
        let mut sorted = f.to_vec();
        sorted.sort();
        serde_json::to_string(&sorted).unwrap_or_default()
    });
    let category_json = category_filter.map(|f| {
        let mut sorted = f.to_vec();
        sorted.sort();
        serde_json::to_string(&sorted).unwrap_or_default()
    });
    let prompt_version = prompt_version.to_string();
    let input_hash = input_hash.to_string();
    let started_at = Utc::now().to_rfc3339();

    let run_id = conn
        .call(move |conn| {
            conn.execute(
                "INSERT INTO analysis_runs (protocol, stage, started_at, status,
                    model_used, seed_rfcs, depth, normative_only,
                    mechanism_filter, category_filter, prompt_version, input_hash)
                 VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    protocol,
                    stage,
                    started_at,
                    model_used,
                    seed_rfcs_json,
                    depth,
                    normative_only.map(|b| b as i64),
                    mechanism_json,
                    category_json,
                    prompt_version,
                    input_hash,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?;
    Ok(run_id)
}

/// Check if a completed run with this input_hash already exists.
pub async fn find_completed_run(
    conn: &Connection,
    protocol: &str,
    stage: &str,
    input_hash: &str,
) -> Result<Option<i64>> {
    let protocol = protocol.to_string();
    let stage = stage.to_string();
    let input_hash = input_hash.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id FROM analysis_runs
                 WHERE protocol = ?1 AND stage = ?2 AND input_hash = ?3
                   AND status = 'completed'
                 ORDER BY id DESC LIMIT 1",
            )?;
            let id = stmt
                .query_row(rusqlite::params![protocol, stage, input_hash], |row| {
                    row.get::<_, i64>(0)
                })
                .optional()?;
            Ok(id)
        })
        .await?;
    Ok(result)
}

/// Check for an existing resumable run (status 'running' or 'interrupted') with matching input_hash.
pub async fn find_resumable_run(
    conn: &Connection,
    protocol: &str,
    stage: &str,
    input_hash: &str,
) -> Result<Option<i64>> {
    let protocol = protocol.to_string();
    let stage = stage.to_string();
    let input_hash = input_hash.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id FROM analysis_runs
                 WHERE protocol = ?1 AND stage = ?2 AND input_hash = ?3
                   AND status IN ('running', 'interrupted')
                 ORDER BY id DESC LIMIT 1",
            )?;
            let id = stmt
                .query_row(rusqlite::params![protocol, stage, input_hash], |row| {
                    row.get::<_, i64>(0)
                })
                .optional()?;
            Ok(id)
        })
        .await?;
    Ok(result)
}

/// Update a run's status and completion time.
pub async fn complete_run(
    conn: &Connection,
    run_id: i64,
    status: &str,
    tokens_used: u64,
    effective_rfcs: &[RfcNumber],
    error: Option<&str>,
) -> Result<()> {
    let status = status.to_string();
    let completed_at = Utc::now().to_rfc3339();
    let effective_json =
        serde_json::to_string(&effective_rfcs.iter().map(|r| r.0).collect::<Vec<_>>())
            .unwrap_or_else(|_| "[]".to_string());
    let error = error.map(|s| s.to_string());

    conn.call(move |conn| {
        conn.execute(
            "UPDATE analysis_runs SET status = ?1, completed_at = ?2,
                tokens_used = ?3, effective_rfcs = ?4, error = ?5
             WHERE id = ?6",
            rusqlite::params![
                status,
                completed_at,
                tokens_used as i64,
                effective_json,
                error,
                run_id,
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Create or update a work item for a run.
pub async fn upsert_work_item(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    key: &str,
    status: &str,
) -> Result<()> {
    let kind = kind.to_string();
    let key = key.to_string();
    let status = status.to_string();
    let now = Utc::now().to_rfc3339();

    conn.call(move |conn| {
        conn.execute(
            "INSERT INTO run_work_items (run_id, work_item_kind, work_item_key, status, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(run_id, work_item_kind, work_item_key) DO UPDATE SET
                status = excluded.status,
                started_at = CASE WHEN excluded.status = 'running' THEN excluded.started_at
                             ELSE run_work_items.started_at END,
                completed_at = CASE WHEN excluded.status IN ('completed', 'failed')
                               THEN excluded.started_at ELSE NULL END",
            rusqlite::params![run_id, kind, key, status, now],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Mark a work item as completed (or failed) with token usage.
pub async fn complete_work_item(
    conn: &Connection,
    run_id: i64,
    kind: &str,
    key: &str,
    tokens_used: u64,
    failed: bool,
    notes: Option<&str>,
) -> Result<()> {
    let kind = kind.to_string();
    let key = key.to_string();
    let completed_at = Utc::now().to_rfc3339();
    let status = if failed { "failed" } else { "completed" };
    let status = status.to_string();
    let notes = notes.map(|s| s.to_string());

    conn.call(move |conn| {
        conn.execute(
            "UPDATE run_work_items SET status = ?1, completed_at = ?2,
                tokens_used = ?3, error = ?4
             WHERE run_id = ?5 AND work_item_kind = ?6 AND work_item_key = ?7",
            rusqlite::params![
                status,
                completed_at,
                tokens_used as i64,
                notes,
                run_id,
                kind,
                key
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Get completed work item keys for a run (for resumability).
pub async fn get_completed_work_items(
    conn: &Connection,
    run_id: i64,
    kind: &str,
) -> Result<Vec<String>> {
    let kind = kind.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT work_item_key FROM run_work_items
                 WHERE run_id = ?1 AND work_item_kind = ?2 AND status = 'completed'",
            )?;
            let keys: Vec<String> = stmt
                .query_map(rusqlite::params![run_id, kind], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(keys)
        })
        .await?;
    Ok(result)
}

/// Store a state machine.
pub async fn store_state_machine(
    conn: &Connection,
    protocol: &str,
    name: &str,
    mechanism: &str,
    data_json: &str,
    content_hash: &str,
    run_id: i64,
) -> Result<()> {
    let protocol = protocol.to_string();
    let name = name.to_string();
    let mechanism = mechanism.to_string();
    let data_json = data_json.to_string();
    let content_hash = content_hash.to_string();

    conn.call(move |conn| {
        conn.execute(
            "INSERT INTO state_machines
                (protocol, name, mechanism, data, content_hash, run_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(protocol, name, run_id) DO UPDATE SET
                mechanism = excluded.mechanism,
                data = excluded.data,
                content_hash = excluded.content_hash",
            rusqlite::params![protocol, name, mechanism, data_json, content_hash, run_id,],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Load state machines for a protocol, optionally filtered by run_id.
/// If run_id is None, returns machines from the latest completed run.
pub async fn get_state_machines(
    conn: &Connection,
    protocol: &str,
    run_id: Option<i64>,
) -> Result<Vec<(String, String, String)>> {
    let protocol = protocol.to_string();
    let result = conn
        .call(move |conn| {
            let machines: Vec<(String, String, String)> = if let Some(rid) = run_id {
                let mut stmt = conn.prepare(
                    "SELECT name, mechanism, data FROM state_machines
                     WHERE protocol = ?1 AND run_id = ?2 ORDER BY name",
                )?;
                stmt.query_map(rusqlite::params![protocol, rid], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            } else {
                let mut stmt = conn.prepare(
                    "SELECT name, mechanism, data FROM state_machines
                     WHERE protocol = ?1
                       AND run_id = (
                           SELECT id FROM analysis_runs
                           WHERE protocol = ?1 AND stage = 'model' AND status = 'completed'
                           ORDER BY id DESC LIMIT 1
                       )
                     ORDER BY name",
                )?;
                stmt.query_map(rusqlite::params![protocol], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            Ok(machines)
        })
        .await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;

    #[tokio::test(flavor = "current_thread")]
    async fn test_create_and_find_run() {
        let conn = open_memory_database().await.unwrap();

        let run_id = create_run(
            &conn,
            "tcp",
            "model",
            Some("gpt-4o"),
            &[RfcNumber(9293)],
            None,
            None,
            None,
            None,
            "1.0.0",
            "hash123",
        )
        .await
        .unwrap();
        assert!(run_id > 0);

        // Not yet completed — should not be found
        let found = find_completed_run(&conn, "tcp", "model", "hash123")
            .await
            .unwrap();
        assert!(found.is_none());

        // Complete it
        complete_run(&conn, run_id, "completed", 500, &[RfcNumber(9293)], None)
            .await
            .unwrap();

        // Now should be found
        let found = find_completed_run(&conn, "tcp", "model", "hash123")
            .await
            .unwrap();
        assert_eq!(found, Some(run_id));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_work_items() {
        let conn = open_memory_database().await.unwrap();

        let run_id = create_run(
            &conn,
            "tcp",
            "model",
            Some("gpt-4o"),
            &[RfcNumber(9293)],
            None,
            None,
            None,
            None,
            "1.0.0",
            "hash",
        )
        .await
        .unwrap();

        upsert_work_item(&conn, run_id, "mechanism", "auth", "running")
            .await
            .unwrap();
        complete_work_item(&conn, run_id, "mechanism", "auth", 100, false, None)
            .await
            .unwrap();

        let completed = get_completed_work_items(&conn, run_id, "mechanism")
            .await
            .unwrap();
        assert_eq!(completed, vec!["auth".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_store_and_get_state_machine() {
        let conn = open_memory_database().await.unwrap();

        // Need a run first
        let run_id = create_run(
            &conn,
            "tcp",
            "model",
            Some("gpt-4o"),
            &[RfcNumber(9293)],
            None,
            None,
            None,
            None,
            "1.0.0",
            "hash",
        )
        .await
        .unwrap();

        store_state_machine(
            &conn,
            "tcp",
            "Connection",
            "state_management",
            r#"{"name":"Connection","states":[],"transitions":[]}"#,
            "smhash",
            run_id,
        )
        .await
        .unwrap();

        let machines = get_state_machines(&conn, "tcp", Some(run_id))
            .await
            .unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].0, "Connection");
        assert_eq!(machines[0].1, "state_management");
    }
}
