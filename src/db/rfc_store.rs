use crate::error::Result;
use crate::rfc::model::*;
use chrono::NaiveDate;
use tokio_rusqlite::Connection;

/// Insert a fully parsed RFC into the database.
/// Inserts into rfcs, sections, cross_refs tables in a transaction.
/// If the RFC already exists with the same content_hash, returns early
/// (no-op). If the RFC exists with a different content_hash, it is updated.
pub async fn upsert_rfc(conn: &Connection, rfc: &Rfc) -> Result<()> {
    let rfc = rfc.clone();
    conn.call(move |conn| {
        // Check if we already have this exact version
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT content_hash, parser_version FROM rfcs WHERE number = ?1",
                [rfc.number.0],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let parser_version = crate::rfc::parser_version(rfc.format);
        if existing
            .as_ref()
            .is_some_and(|(hash, version)| hash == &rfc.content_hash && version == parser_version)
        {
            return Ok(());
        }

        let tx = conn.transaction()?;

        // Compress raw_text with zstd
        let compressed = zstd::encode_all(rfc.raw_text.as_bytes(), 3)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        // Serialize Vec<RfcNumber> fields as JSON arrays of integers
        let obsoletes_json =
            serde_json::to_string(&rfc.obsoletes.iter().map(|r| r.0).collect::<Vec<_>>()).unwrap();
        let updates_json =
            serde_json::to_string(&rfc.updates.iter().map(|r| r.0).collect::<Vec<_>>()).unwrap();
        let obsoleted_by_json =
            serde_json::to_string(&rfc.obsoleted_by.iter().map(|r| r.0).collect::<Vec<_>>())
                .unwrap();
        let updated_by_json =
            serde_json::to_string(&rfc.updated_by.iter().map(|r| r.0).collect::<Vec<_>>()).unwrap();

        // Serialize references as JSON
        let references_json =
            serde_json::to_string(&rfc.references).unwrap_or_else(|_| "[]".to_string());

        // Upsert the RFC row
        tx.execute(
            "INSERT INTO rfcs (number, title, format, status, date,
                raw_content, content_hash, parser_version, obsoletes, updates,
                obsoleted_by, updated_by, references_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(number) DO UPDATE SET
                title = excluded.title,
                format = excluded.format,
                status = excluded.status,
                date = excluded.date,
                raw_content = excluded.raw_content,
                content_hash = excluded.content_hash,
                parser_version = excluded.parser_version,
                fetched_at = datetime('now'),
                obsoletes = excluded.obsoletes,
                updates = excluded.updates,
                obsoleted_by = excluded.obsoleted_by,
                updated_by = excluded.updated_by,
                references_json = excluded.references_json",
            rusqlite::params![
                rfc.number.0,
                rfc.title,
                rfc.format.to_string(),
                rfc.status.to_string(),
                rfc.date.to_string(),
                compressed,
                rfc.content_hash,
                parser_version,
                obsoletes_json,
                updates_json,
                obsoleted_by_json,
                updated_by_json,
                references_json,
            ],
        )?;

        // Delete old sections and cross_refs for this RFC, then re-insert
        tx.execute(
            "DELETE FROM cross_refs WHERE source_rfc = ?1",
            [rfc.number.0],
        )?;
        tx.execute("DELETE FROM sections WHERE rfc_number = ?1", [rfc.number.0])?;

        // Insert sections
        for section in &rfc.sections {
            tx.execute(
                "INSERT INTO sections (rfc_number, section_num, title, depth,
                    anchor, text, pn)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    rfc.number.0,
                    section.number,
                    section.title,
                    i64::from(section.depth),
                    section.anchor,
                    section.text,
                    section.pn,
                ],
            )?;

            // Insert cross-refs for this section
            for xref in &section.cross_refs {
                tx.execute(
                    "INSERT INTO cross_refs (source_rfc, source_section,
                        target_rfc, target_section, context)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        rfc.number.0,
                        section.number,
                        xref.target_rfc.map(|r| r.0),
                        xref.target_section,
                        xref.context,
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

/// Check if an RFC exists in the database and return its content_hash if so.
pub async fn get_content_hash(conn: &Connection, rfc_number: u32) -> Result<Option<String>> {
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT content_hash, format, parser_version
                 FROM rfcs WHERE number = ?1",
            )?;
            let cached = stmt
                .query_row([rfc_number], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .optional()?;
            let Some((hash, format, stored_parser_version)) = cached else {
                return Ok(None);
            };
            let current_parser_version = crate::rfc::parser_version_for_db_format(&format);
            if current_parser_version == Some(stored_parser_version.as_str()) {
                Ok(Some(hash))
            } else {
                tracing::info!(
                    "RFC {} was parsed with version {} for format '{}'; current version is {:?}. Reparse required.",
                    rfc_number,
                    stored_parser_version,
                    format,
                    current_parser_version
                );
                Ok(None)
            }
        })
        .await?;
    Ok(result)
}

/// Load a full Rfc struct from the database by number.
/// Returns None if not found.
pub async fn get_rfc(conn: &Connection, rfc_number: u32) -> Result<Option<Rfc>> {
    let result = conn
        .call(move |conn| {
            // Load the RFC row
            let mut stmt = conn.prepare(
                "SELECT number, title, format, status, date, raw_content,
                    content_hash, obsoletes, updates, obsoleted_by, updated_by,
                    references_json
                 FROM rfcs WHERE number = ?1",
            )?;

            let rfc_row = stmt
                .query_row([rfc_number], |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                    ))
                })
                .optional()?;

            let Some((
                number,
                title,
                format_str,
                status_str,
                date_str,
                raw_content,
                content_hash,
                obsoletes_json,
                updates_json,
                obsoleted_by_json,
                updated_by_json,
                references_json_str,
            )) = rfc_row
            else {
                return Ok(None);
            };

            // Decompress raw_content
            let raw_text = String::from_utf8(
                zstd::decode_all(raw_content.as_slice())
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
            )
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            // Parse JSON arrays
            let parse_rfc_numbers = |json: Option<String>| -> Vec<RfcNumber> {
                json.and_then(|s| serde_json::from_str::<Vec<u32>>(&s).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .map(RfcNumber)
                    .collect()
            };

            // Load sections
            let mut sect_stmt = conn.prepare(
                "SELECT section_num, title, depth, anchor, text, pn
                 FROM sections WHERE rfc_number = ?1
                 ORDER BY id",
            )?;
            let sections: Vec<Section> = sect_stmt
                .query_map([rfc_number], |row| {
                    let depth_i64: i64 = row.get(2)?;
                    let depth = u8::try_from(depth_i64)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, depth_i64))?;
                    Ok(Section {
                        number: row.get(0)?,
                        title: row.get(1)?,
                        depth,
                        anchor: row.get(3)?,
                        text: row.get(4)?,
                        cross_refs: Vec::new(), // filled below
                        pn: row.get(5)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            // Load cross-refs and attach to sections
            let mut xref_stmt = conn.prepare(
                "SELECT source_section, target_rfc, target_section, context
                 FROM cross_refs WHERE source_rfc = ?1
                 ORDER BY id",
            )?;
            let xrefs: Vec<(String, CrossRef)> = xref_stmt
                .query_map([rfc_number], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        CrossRef {
                            target_rfc: row.get::<_, Option<u32>>(1)?.map(RfcNumber),
                            target_section: row.get(2)?,
                            context: row.get(3)?,
                        },
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            // Attach cross-refs to their sections
            let mut sections = sections;
            for (section_num, xref) in xrefs {
                if let Some(section) = sections.iter_mut().find(|s| s.number == section_num) {
                    section.cross_refs.push(xref);
                }
            }

            // Load references from JSON column
            let references: Vec<Reference> = references_json_str
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                .unwrap_or_else(|_| NaiveDate::from_ymd_opt(1970, 1, 1).unwrap());

            Ok(Some(Rfc {
                number: RfcNumber(number),
                title,
                format: RfcFormat::from_db_str(&format_str).unwrap_or(RfcFormat::PlainText),
                status: RfcStatus::from_str_loose(&status_str),
                date,
                obsoletes: parse_rfc_numbers(obsoletes_json),
                updates: parse_rfc_numbers(updates_json),
                obsoleted_by: parse_rfc_numbers(obsoleted_by_json),
                updated_by: parse_rfc_numbers(updated_by_json),
                sections,
                references,
                raw_text,
                content_hash,
            }))
        })
        .await?;
    Ok(result)
}

/// List all stored RFC numbers.
pub async fn list_rfc_numbers(conn: &Connection) -> Result<Vec<RfcNumber>> {
    let result = conn
        .call(|conn| {
            let mut stmt = conn.prepare("SELECT number FROM rfcs ORDER BY number")?;
            let numbers: Vec<RfcNumber> = stmt
                .query_map([], |row| Ok(RfcNumber(row.get(0)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(numbers)
        })
        .await?;
    Ok(result)
}

/// Associate an RFC with a protocol name.
pub async fn assign_protocol(conn: &Connection, protocol: &str, rfc_number: u32) -> Result<()> {
    let protocol = protocol.to_string();
    conn.call(move |conn| {
        conn.execute(
            "INSERT OR IGNORE INTO protocol_rfcs (protocol, rfc_number) VALUES (?1, ?2)",
            rusqlite::params![protocol, rfc_number],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

/// Get all RFC numbers associated with a protocol.
pub async fn get_protocol_rfcs(conn: &Connection, protocol: &str) -> Result<Vec<RfcNumber>> {
    let protocol = protocol.to_string();
    let result = conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT rfc_number FROM protocol_rfcs WHERE protocol = ?1 ORDER BY rfc_number",
            )?;
            let numbers: Vec<RfcNumber> = stmt
                .query_map([&protocol], |row| Ok(RfcNumber(row.get(0)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(numbers)
        })
        .await?;
    Ok(result)
}

// Import the optional() extension for query_row
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory_database;
    use chrono::NaiveDate;

    fn make_test_rfc() -> Rfc {
        Rfc {
            number: RfcNumber(9293),
            title: "Transmission Control Protocol (TCP)".to_string(),
            format: RfcFormat::Xml,
            status: RfcStatus::Standard,
            date: NaiveDate::from_ymd_opt(2022, 8, 1).unwrap(),
            obsoletes: vec![RfcNumber(793)],
            updates: vec![],
            obsoleted_by: vec![],
            updated_by: vec![],
            sections: vec![
                Section {
                    number: "1".to_string(),
                    title: "Introduction".to_string(),
                    anchor: Some("intro".to_string()),
                    depth: 1,
                    text: "This document specifies TCP.".to_string(),
                    cross_refs: vec![CrossRef {
                        target_rfc: Some(RfcNumber(793)),
                        target_section: Some("3".to_string()),
                        context: "Originally defined in RFC 793, Section 3.".to_string(),
                    }],
                    pn: None,
                },
                Section {
                    number: "2".to_string(),
                    title: "Key Words".to_string(),
                    anchor: None,
                    depth: 1,
                    text: "The key words MUST, SHOULD...".to_string(),
                    cross_refs: vec![],
                    pn: None,
                },
            ],
            references: vec![],
            raw_text: "Full text of RFC 9293 would go here...".to_string(),
            content_hash: "abc123def456".to_string(),
        }
    }

    #[tokio::test]
    async fn test_upsert_and_get_rfc() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();

        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.number, RfcNumber(9293));
        assert_eq!(loaded.title, "Transmission Control Protocol (TCP)");
        assert_eq!(loaded.sections.len(), 2);
        assert_eq!(loaded.sections[0].cross_refs.len(), 1);
        assert_eq!(loaded.obsoletes, vec![RfcNumber(793)]);
        assert_eq!(loaded.content_hash, "abc123def456");
        // raw_text should survive compression round-trip
        assert_eq!(loaded.raw_text, "Full text of RFC 9293 would go here...");
    }

    #[tokio::test]
    async fn test_get_nonexistent_rfc() {
        let conn = open_memory_database().await.unwrap();
        let result = get_rfc(&conn, 99999).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_content_hash() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let hash = get_content_hash(&conn, 9293).await.unwrap();
        assert_eq!(hash, Some("abc123def456".to_string()));

        let missing = get_content_hash(&conn, 99999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_upsert_updates_existing() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Update the RFC
        rfc.title = "Updated Title".to_string();
        rfc.content_hash = "newhash789".to_string();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.title, "Updated Title");
        assert_eq!(loaded.content_hash, "newhash789");
    }

    #[tokio::test]
    async fn test_list_rfc_numbers() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let numbers = list_rfc_numbers(&conn).await.unwrap();
        assert_eq!(numbers, vec![RfcNumber(9293)]);
    }

    #[tokio::test]
    async fn test_protocol_assignment() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        assign_protocol(&conn, "tcp", 9293).await.unwrap();
        // Assigning again should be a no-op (OR IGNORE)
        assign_protocol(&conn, "tcp", 9293).await.unwrap();

        let rfcs = get_protocol_rfcs(&conn, "tcp").await.unwrap();
        assert_eq!(rfcs, vec![RfcNumber(9293)]);

        let empty = get_protocol_rfcs(&conn, "dns").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn test_protocol_assignment_missing_rfc_fails() {
        // Foreign keys are ON, so assigning a non-existent RFC should fail
        let conn = open_memory_database().await.unwrap();
        let result = assign_protocol(&conn, "tcp", 99999).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_references_round_trip() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        rfc.references = vec![
            Reference {
                label: "[RFC793]".to_string(),
                target_rfc: Some(RfcNumber(793)),
                title: "Transmission Control Protocol".to_string(),
                is_normative: true,
            },
            Reference {
                label: "[RFC1122]".to_string(),
                target_rfc: Some(RfcNumber(1122)),
                title: "Requirements for Internet Hosts".to_string(),
                is_normative: false,
            },
        ];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.references.len(), 2);
        assert_eq!(loaded.references[0].label, "[RFC793]");
        assert!(loaded.references[0].is_normative);
        assert_eq!(loaded.references[1].target_rfc, Some(RfcNumber(1122)));
    }

    #[tokio::test]
    async fn test_upsert_removes_old_sections() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        assert_eq!(rfc.sections.len(), 2);
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Update RFC with only 1 section (simulating re-parse)
        rfc.content_hash = "changed_hash".to_string();
        rfc.sections = vec![rfc.sections[0].clone()];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.sections.len(), 1);
        assert_eq!(loaded.sections[0].number, "1");
    }

    #[tokio::test]
    async fn test_same_content_hash_is_noop() {
        let conn = open_memory_database().await.unwrap();
        let rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        // Upsert again with same content_hash — should be a no-op
        let mut rfc2 = rfc.clone();
        rfc2.title = "This should NOT be saved".to_string();
        upsert_rfc(&conn, &rfc2).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        // Title should be the original, not the modified one
        assert_eq!(loaded.title, "Transmission Control Protocol (TCP)");
    }

    #[tokio::test]
    async fn test_stale_parser_version_forces_reparse() {
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        upsert_rfc(&conn, &rfc).await.unwrap();

        conn.call(|conn| {
            conn.execute(
                "UPDATE rfcs SET parser_version = 'legacy' WHERE number = 9293",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(get_content_hash(&conn, 9293).await.unwrap().is_none());

        rfc.title = "Reparsed Title".to_string();
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.title, "Reparsed Title");
        assert_eq!(
            get_content_hash(&conn, 9293).await.unwrap(),
            Some("abc123def456".to_string())
        );
    }

    #[tokio::test]
    async fn test_duplicate_cross_refs_different_context() {
        // Verify that multiple cross-refs from the same source to the same
        // target but with different context are all preserved
        let conn = open_memory_database().await.unwrap();
        let mut rfc = make_test_rfc();
        rfc.sections[0].cross_refs = vec![
            CrossRef {
                target_rfc: Some(RfcNumber(793)),
                target_section: Some("3".to_string()),
                context: "First reference to RFC 793 Section 3.".to_string(),
            },
            CrossRef {
                target_rfc: Some(RfcNumber(793)),
                target_section: Some("3".to_string()),
                context: "Second reference to RFC 793 Section 3.".to_string(),
            },
        ];
        upsert_rfc(&conn, &rfc).await.unwrap();

        let loaded = get_rfc(&conn, 9293).await.unwrap().unwrap();
        assert_eq!(loaded.sections[0].cross_refs.len(), 2);
        assert_ne!(
            loaded.sections[0].cross_refs[0].context,
            loaded.sections[0].cross_refs[1].context
        );
    }
}
