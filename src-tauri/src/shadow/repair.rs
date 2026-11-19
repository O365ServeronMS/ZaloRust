//! One-time data repair for shadow DB v1 rows written BEFORE the H3/H4
//! writer fixes (audit 2026-11-19 §1.2 / T8).
//!
//! NOT wired into `runtime` or startup: repairs rewrite live data and
//! must only run from an explicit maintenance entry point or a test,
//! after a backup (audit §1.2's "Migration 1 lần" note).
//!
//! Scope (deliberately narrow):
//! - create conversation stubs for orphan messages (H4-e);
//! - recompute `conversations.last_msg_id`/`last_ts` from the newest
//!   message by ts (H4-d);
//! - fill `messages.content_hash` where NULL (H4-f), using the exact
//!   digest the writer now stores so later replays compare like with
//!   like;
//! - recompute `messages.type` from the payload msgType through the
//!   SAME table the writer uses (B6/H1) — so V1 rows (0/1/2/5/8/9/99
//!   codes) and 100-bucket rows land on the batch-2 codes.
//!
//! Explicitly out of scope: deleting/rebuilding `message_revisions`
//! (needs user sign-off per the audit).

use rusqlite::Connection;
use serde_json::Value;

use super::{normalize, schema, writer};

/// What `repair_v1` changed. All counters: no row data ever leaves this
/// module (H-rule: counts only).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RepairReport {
    pub conv_stubs_created: usize,
    pub last_msg_fixed: usize,
    pub content_hash_filled: usize,
    /// B6/H1: rows whose `type` was recomputed from the payload msgType.
    pub types_remapped: usize,
}

/// Run the v1 repair. Idempotent: a second run over a repaired DB
/// reports zero everywhere. Per-step failures are counted as "nothing
/// done for that step" — this is a maintenance helper, not a pipeline
/// path (the pipeline's no-swallowed-errors rule lives in
/// `pipeline::process_batch`).
pub fn repair_v1(conn: &Connection) -> RepairReport {
    let mut r = RepairReport::default();

    // (a) H4-e: stub every conversation a message references but no
    // conversations row names. Same stub shape as the writer's Message
    // arm (type 0, unread 0).
    let orphans: Vec<String> = match conn.prepare(
        "SELECT DISTINCT m.conv_id FROM messages m
         LEFT JOIN conversations c ON c.id = m.conv_id
         WHERE c.id IS NULL",
    ) {
        Ok(mut st) => st
            .query_map([], |row| row.get::<_, String>(0))
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    for id in &orphans {
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO conversations (id, type, unread, updated_at)
                 VALUES (?1, 0, 0, ?2)",
                rusqlite::params![id, schema::now_ms()],
            )
            .unwrap_or(0);
        r.conv_stubs_created += n;
    }

    // (b) H4-d: point last_msg_id/last_ts at the newest message by ts
    // (ties broken by msg_id, so the result is insertion-order
    // independent). Only rows whose pointers actually change are
    // counted, hence a second run reports 0.
    r.last_msg_fixed = conn
        .execute(
            "UPDATE conversations
                SET last_msg_id = (SELECT m.msg_id FROM messages m
                                    WHERE m.conv_id = conversations.id
                                    ORDER BY m.ts DESC, m.msg_id DESC LIMIT 1),
                    last_ts    = (SELECT MAX(m.ts) FROM messages m
                                   WHERE m.conv_id = conversations.id)
              WHERE EXISTS (SELECT 1 FROM messages m WHERE m.conv_id = conversations.id)
                AND (conversations.last_msg_id IS NULL
                     OR conversations.last_msg_id <>
                        (SELECT m.msg_id FROM messages m
                          WHERE m.conv_id = conversations.id
                          ORDER BY m.ts DESC, m.msg_id DESC LIMIT 1)
                     OR conversations.last_ts IS NULL
                     OR conversations.last_ts <>
                        (SELECT MAX(m.ts) FROM messages m
                          WHERE m.conv_id = conversations.id))",
            [],
        )
        .unwrap_or(0);

    // (c) H4-f: fill content_hash for legacy rows (same digest the
    // writer now stores on insert).
    {
        let rows: Vec<(i64, String)> = match conn
            .prepare("SELECT rowid, payload_json FROM messages WHERE content_hash IS NULL")
        {
            Ok(mut st) => st
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map(|it| it.filter_map(Result::ok).collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        for (rowid, payload) in rows {
            // Invalid JSON keeps a NULL hash (the writer's first-fill
            // rule then treats the row as legacy, never an edit).
            let Some(h) = writer::content_hash(&payload) else {
                continue;
            };
            let n = conn
                .execute(
                    "UPDATE messages SET content_hash = ?2
                      WHERE rowid = ?1 AND content_hash IS NULL",
                    rusqlite::params![rowid, h],
                )
                .unwrap_or(0);
            r.content_hash_filled += n;
        }
    }

    // (d) B6/H1: recompute `messages.type` from the payload msgType —
    // row by row in Rust through normalize::msg_type_code, the SAME
    // table the writer uses (single source of truth: a SQL CASE here
    // could drift from it). Rows with NULL/invalid JSON payloads keep
    // their stored type (nothing to recompute from); the UPDATE only
    // lands where the code really differs, so a second run reports 0.
    {
        let rows: Vec<(i64, Option<String>, i64)> = match conn
            .prepare("SELECT rowid, payload_json, type FROM messages")
        {
            Ok(mut st) => st
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map(|it| it.filter_map(Result::ok).collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        for (rowid, payload, cur_type) in rows {
            let Some(payload) = payload else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&payload) else {
                continue;
            };
            // Mirror the writer exactly: a missing msgType reads as ""
            // (table code 0).
            let msg_type = v.get("msgType").and_then(Value::as_str).unwrap_or("");
            let want = normalize::msg_type_code(msg_type);
            if want != cur_type {
                let n = conn
                    .execute(
                        "UPDATE messages SET type = ?2 WHERE rowid = ?1",
                        rusqlite::params![rowid, want],
                    )
                    .unwrap_or(0);
                r.types_remapped += n;
            }
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::super::schema;
    use super::*;
    use crate::migrate::sqlcipher;
    use rusqlite::Connection;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn legacy_msg(conn: &Connection, msg_id: &str, conv: &str, ts: i64) {
        // A v1-era row: content_hash NULL, written before the fix.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES (?1, ?2, NULL, ?3, 1, NULL, ?4, 0, 0, 'capture')",
            rusqlite::params![
                msg_id,
                conv,
                ts,
                format!(r#"{{"msgId":"{msg_id}","msgType":"text","content":"c"}}"#)
            ],
        )
        .unwrap();
    }

    #[test]
    fn repair_v1_orphan_stub_and_last_pointers() {
        let conn = db();
        // Orphan messages in "cA" (no conversations row), newest ts 300.
        legacy_msg(&conn, "a1", "cA", 300);
        legacy_msg(&conn, "a2", "cA", 100);
        // An existing conversation whose pointer is WRONG (older msg).
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cA', 0, 0, 1, 'a2', 100)",
            [],
        )
        .unwrap();
        // An orphan in "cB" with no conversation row at all.
        legacy_msg(&conn, "a3", "cB", 50);

        let r = repair_v1(&conn);
        // Only cB was a true orphan (cA already had its row).
        assert_eq!(r.conv_stubs_created, 1);
        let (ty, unread, last_b, ts_b): (i64, i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT type, unread, last_msg_id, last_ts FROM conversations WHERE id='cB'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((ty, unread), (0, 0));
        assert_eq!(last_b.as_deref(), Some("a3"));
        assert_eq!(ts_b, Some(50));
        // cA's pointer was recomputed to the ts-300 message.
        let (last_a, ts_a): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT last_msg_id, last_ts FROM conversations WHERE id='cA'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(last_a.as_deref(), Some("a1"), "recomputed to the newest ts");
        assert_eq!(ts_a, Some(300));
        // Both fixed rows counted (cA pointer + cB fill).
        assert_eq!(r.last_msg_fixed, 2);
        // All three legacy rows got their content_hash.
        assert_eq!(r.content_hash_filled, 3);
        let null_hash: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE content_hash IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(null_hash, 0);
        // The stored hash is exactly the writer's digest for the payload.
        let stored: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM messages WHERE msg_id='a1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            writer::content_hash(r#"{"msgId":"a1","msgType":"text","content":"c"}"#).as_deref()
        );
        // Out-of-scope by design: revisions untouched. These rows carry
        // msgType "text" (stored type 1 == the table code), so the B6
        // remap counts 0 for them.
        let revisions: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_revisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revisions, 0);
        assert_eq!(r.types_remapped, 0);
    }

    #[test]
    fn repair_v1_idempotent_second_run() {
        let conn = db();
        legacy_msg(&conn, "a1", "cA", 300);
        legacy_msg(&conn, "a2", "cA", 100);
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cA', 0, 0, 1, 'a2', 100)",
            [],
        )
        .unwrap();
        let r1 = repair_v1(&conn);
        assert!(r1.conv_stubs_created == 0 && r1.last_msg_fixed == 1 && r1.content_hash_filled == 2);
        // Snapshot the repaired state, run again, compare.
        let (last, ts, hash_a1): (Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT (SELECT last_msg_id FROM conversations WHERE id='cA'),
                        (SELECT last_ts FROM conversations WHERE id='cA'),
                        (SELECT content_hash FROM messages WHERE msg_id='a1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let r2 = repair_v1(&conn);
        assert_eq!(r2, RepairReport::default(), "second run changes nothing");
        let (last2, ts2, hash_a1_2): (Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT (SELECT last_msg_id FROM conversations WHERE id='cA'),
                        (SELECT last_ts FROM conversations WHERE id='cA'),
                        (SELECT content_hash FROM messages WHERE msg_id='a1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((last.as_deref(), ts, hash_a1.as_deref()), (last2.as_deref(), ts2, hash_a1_2.as_deref()));
    }

    // --- B6/H1: type remap through the batch-2 table -----------------------

    #[test]
    fn repair_v1_remaps_types_from_payload_msgtype() {
        let conn = db();
        // A V1-era row: msgType chat.photo, but the pre-rebuild writer
        // stored its own code 1.
        let v1 = r#"{"msgId":"tp","msgType":"chat.photo","content":{"href":"https://fake-photo-stal.zdn.vn/x.jpg"}}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tp','cT',NULL,1,1,NULL,?1,0,0,'capture')",
            rusqlite::params![v1],
        )
        .unwrap();
        // A 100-bucket row (the rebuild's old table knew no wire string).
        let weird = r#"{"msgId":"tw","msgType":"chat.recommended","content":{"href":"https://fake-link.example/x"}}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tw','cT',NULL,2,100,NULL,?1,0,0,'e2ee')",
            rusqlite::params![weird],
        )
        .unwrap();
        // A row already on the table code (webchat -> 1): not counted.
        let ok = r#"{"msgId":"to","msgType":"webchat","content":"c"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('to','cT',NULL,3,1,NULL,?1,0,0,'capture')",
            rusqlite::params![ok],
        )
        .unwrap();
        // Rows with nothing to recompute from: NULL payload and invalid
        // JSON keep their stored type.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tn','cT',NULL,4,7,NULL,NULL,0,0,'capture')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tx','cT',NULL,5,9,NULL,'not json',0,0,'capture')",
            [],
        )
        .unwrap();

        let r = repair_v1(&conn);
        assert_eq!(r.types_remapped, 2, "only the two rows whose type really changed");
        let types: Vec<(String, i64)> = {
            let mut st = conn
                .prepare("SELECT msg_id, type FROM messages ORDER BY ts")
                .unwrap();
            st.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        // chat.photo -> 2, chat.recommended -> 7 (the link card), the
        // rest untouched (including the NULL/invalid-payload rows).
        assert_eq!(
            types,
            vec![
                ("tp".to_string(), 2),
                ("tw".to_string(), 7),
                ("to".to_string(), 1),
                ("tn".to_string(), 7),
                ("tx".to_string(), 9),
            ]
        );
        // Idempotent: a second run changes nothing (same table, same
        // payloads).
        let r2 = repair_v1(&conn);
        assert_eq!(r2.types_remapped, 0);
    }
}
