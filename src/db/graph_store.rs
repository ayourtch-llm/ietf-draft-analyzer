use crate::error::Result;
use crate::graph::model::*;
use crate::rfc::model::RfcNumber;
use tokio_rusqlite::Connection;

/// Store edges into the dep_edges table.
/// Skips duplicates by checking existence first (handles NULL sections correctly).
/// Does NOT clear existing edges — call clear_edges_for_protocol
/// first if a full rebuild is needed.
pub async fn store_edges(
    conn: &Connection,
    edges: &[(RfcNumber, RfcNumber, DepEdge)],
) -> Result<()> {
    let edges = edges.to_vec();
    conn.call(move |conn| {
        let tx = conn.transaction()?;
        for (source, target, edge) in &edges {
            // Check if edge already exists (handles NULL comparison correctly)
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM dep_edges
                 WHERE source_rfc = ?1 AND target_rfc = ?2 AND kind = ?3
                 AND (source_section = ?4 OR (source_section IS NULL AND ?4 IS NULL))
                 AND (target_section = ?5 OR (target_section IS NULL AND ?5 IS NULL)))",
                rusqlite::params![
                    source.0,
                    target.0,
                    edge.kind.to_string(),
                    edge.source_section.as_deref(),
                    edge.target_section.as_deref(),
                ],
                |row| row.get(0),
            )?;

            if !exists {
                tx.execute(
                    "INSERT INTO dep_edges
                        (source_rfc, target_rfc, kind, source_section, target_section)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        source.0,
                        target.0,
                        edge.kind.to_string(),
                        edge.source_section.as_deref(),
                        edge.target_section.as_deref(),
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Load all edges from the dep_edges table.
pub async fn load_all_edges(conn: &Connection) -> Result<Vec<(RfcNumber, RfcNumber, DepEdge)>> {
    let result = conn
        .call(|conn| {
            let mut stmt = conn.prepare(
                "SELECT source_rfc, target_rfc, kind, source_section, target_section
                 FROM dep_edges",
            )?;
            let edges: Vec<(RfcNumber, RfcNumber, DepEdge)> = stmt
                .query_map([], |row| {
                    let source = RfcNumber(row.get::<_, u32>(0)?);
                    let target = RfcNumber(row.get::<_, u32>(1)?);
                    let kind_str: String = row.get(2)?;
                    let kind = EdgeKind::from_db_str(&kind_str).unwrap_or(EdgeKind::CrossReference);
                    Ok((
                        source,
                        target,
                        DepEdge {
                            kind,
                            source_section: row.get(3)?,
                            target_section: row.get(4)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(edges)
        })
        .await?;
    Ok(result)
}

/// Load edges for a specific set of RFCs (by source or target).
pub async fn load_edges_for_rfcs(
    conn: &Connection,
    rfc_numbers: &[RfcNumber],
) -> Result<Vec<(RfcNumber, RfcNumber, DepEdge)>> {
    if rfc_numbers.is_empty() {
        return Ok(Vec::new());
    }
    let numbers: Vec<u32> = rfc_numbers.iter().map(|r| r.0).collect();
    let result = conn
        .call(move |conn| {
            // Build a WHERE clause with distinct placeholders for each IN clause
            let n = numbers.len();
            let ph1: Vec<String> = (1..=n).map(|i| format!("?{}", i)).collect();
            let ph2: Vec<String> = (n + 1..=2 * n).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "SELECT source_rfc, target_rfc, kind, source_section, target_section
                 FROM dep_edges
                 WHERE source_rfc IN ({}) OR target_rfc IN ({})",
                ph1.join(","),
                ph2.join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            // Bind numbers twice (once per IN clause)
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = numbers
                .iter()
                .chain(numbers.iter())
                .map(|n| Box::new(*n) as Box<dyn rusqlite::types::ToSql>)
                .collect();
            let edges: Vec<(RfcNumber, RfcNumber, DepEdge)> = stmt
                .query_map(rusqlite::params_from_iter(params), |row| {
                    let source = RfcNumber(row.get::<_, u32>(0)?);
                    let target = RfcNumber(row.get::<_, u32>(1)?);
                    let kind_str: String = row.get(2)?;
                    let kind = EdgeKind::from_db_str(&kind_str).unwrap_or(EdgeKind::CrossReference);
                    Ok((
                        source,
                        target,
                        DepEdge {
                            kind,
                            source_section: row.get(3)?,
                            target_section: row.get(4)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(edges)
        })
        .await?;
    Ok(result)
}

/// Delete all edges for a protocol's RFCs.
pub async fn clear_edges_for_protocol(conn: &Connection, protocol: &str) -> Result<()> {
    let protocol = protocol.to_string();
    conn.call(move |conn| {
        conn.execute(
            "DELETE FROM dep_edges WHERE source_rfc IN
                (SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1)
             OR target_rfc IN
                (SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1)",
            [&protocol],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;

    #[tokio::test]
    async fn test_store_and_load_edges() {
        let conn = open_memory_database().await.unwrap();

        // Need RFCs in the database first (foreign keys)
        use crate::db::rfc_store;
        use crate::rfc::model::*;
        use chrono::NaiveDate;

        let rfc1 = Rfc {
            number: RfcNumber(9293),
            title: "TCP".to_string(),
            format: RfcFormat::Xml,
            status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(2022, 1, 1).unwrap(),
            obsoletes: vec![],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![],
            references: vec![],
            raw_text: "text".to_string(),
            content_hash: "h1".to_string(),
        };
        let rfc2 = Rfc {
            number: RfcNumber(793),
            title: "Old TCP".to_string(),
            format: RfcFormat::PlainText,
            status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(1981, 9, 1).unwrap(),
            obsoletes: vec![],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![],
            references: vec![],
            raw_text: "text".to_string(),
            content_hash: "h2".to_string(),
        };
        rfc_store::upsert_rfc(&conn, &rfc1).await.unwrap();
        rfc_store::upsert_rfc(&conn, &rfc2).await.unwrap();

        let edges = vec![(
            RfcNumber(9293),
            RfcNumber(793),
            DepEdge {
                kind: EdgeKind::Obsoletes,
                source_section: None,
                target_section: None,
            },
        )];
        store_edges(&conn, &edges).await.unwrap();

        let loaded = load_all_edges(&conn).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, RfcNumber(9293));
        assert_eq!(loaded[0].1, RfcNumber(793));
        assert_eq!(loaded[0].2.kind, EdgeKind::Obsoletes);
    }

    #[tokio::test]
    async fn test_store_edges_deduplicates() {
        let conn = open_memory_database().await.unwrap();

        use crate::db::rfc_store;
        use crate::rfc::model::*;
        use chrono::NaiveDate;

        let rfc1 = Rfc {
            number: RfcNumber(1),
            title: "A".to_string(),
            format: RfcFormat::Xml,
            status: RfcStatus::Unknown,
            date: NaiveDate::from_ymd_opt(2000, 1, 1).unwrap(),
            obsoletes: vec![],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![],
            references: vec![],
            raw_text: "t".to_string(),
            content_hash: "a".to_string(),
        };
        let rfc2 = Rfc {
            number: RfcNumber(2),
            title: "B".to_string(),
            content_hash: "b".to_string(),
            ..rfc1.clone()
        };

        rfc_store::upsert_rfc(&conn, &rfc1).await.unwrap();
        rfc_store::upsert_rfc(&conn, &rfc2).await.unwrap();

        let edge = (
            RfcNumber(1),
            RfcNumber(2),
            DepEdge {
                kind: EdgeKind::NormativeReference,
                source_section: None,
                target_section: None,
            },
        );

        // Insert twice — should not duplicate
        store_edges(&conn, std::slice::from_ref(&edge))
            .await
            .unwrap();
        store_edges(&conn, &[edge]).await.unwrap();

        let loaded = load_all_edges(&conn).await.unwrap();
        assert_eq!(loaded.len(), 1);
    }
}
