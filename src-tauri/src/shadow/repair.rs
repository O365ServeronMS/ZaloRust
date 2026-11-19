//! One-time data repair for shadow DB v1 rows written BEFORE the H3/H4
//! writer fixes (audit 2026-11-19 §1.2 / T8).
//!
//! NOT wired into `runtime` or startup: repairs rewrite live data and
//! must only run from an explicit maintenance entry point or a test,
//! after a backup (audit §1.2's "Migration 1 lần" note). Run the
//! [`repair_v1_dry_run`] first and compare reports; the `maint_repair`
//! ignored test runs both against a temp COPY of the live store.
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
//!   codes) and 100-bucket rows land on the batch-2 codes;
//! - (e) KQ2 backfill: fill `sender_id` for self-sent rows stuck at
//!   NULL from the configured own uid (audit §1.2 migration bullet);
//! - (f) H4 ping-pong revisions: delete edit revisions whose payload
//!   hashes (with the SAME `writer::content_hash`) equal the message's
//!   CURRENT payload — representation-only noise — then set each
//!   touched message's `rev` to the number of remaining revisions.
//!   Recall/delete revisions are never touched.

use rusqlite::Connection;
use serde_json::Value;

use super::{account, normalize, schema, writer};

/// What `repair_v1` changed. All counters: no row data ever leaves this
/// module (H-rule: counts only).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RepairReport {
    pub conv_stubs_created: usize,
    pub last_msg_fixed: usize,
    pub content_hash_filled: usize,
    /// B6/H1: rows whose `type` was recomputed from the payload msgType.
    pub types_remapped: usize,
    /// (e) KQ2: self-sent rows (payload uidFrom='0') whose NULL sender
    /// was filled from the configured own uid.
    pub senders_backfilled: usize,
    /// (f) H4: representation-only edit revisions deleted.
    pub revisions_pruned: usize,
    /// (f) H4: touched messages whose `rev` was set to the remaining
    /// revision count.
    pub revs_reset: usize,
}

/// Run the v1 repair. Idempotent: a second run over a repaired DB
/// reports zero everywhere. `own_uid` gates step (e): `Some(valid uid)`
/// backfills self-sent senders (KQ2), `None` (or a bad-shaped uid)
/// skips it. Per-step failures are counted as "nothing done for that
/// step" — this is a maintenance helper, not a pipeline path (the
/// pipeline's no-swallowed-errors rule lives in
/// `pipeline::process_batch`).
pub fn repair_v1(conn: &Connection, own_uid: Option<&str>) -> RepairReport {
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

    // (e) KQ2 sender backfill: self-sent rows written before the uid
    // was known are stuck at sender NULL forever (H4-b: the old ON
    // CONFLICT never filled it). One statement; None (or a bad-shaped
    // uid, the same rule `account::resolve_own_uid` applies) skips the
    // step.
    r.senders_backfilled = backfill_senders(conn, own_uid);

    // (f) H4 ping-pong revisions (see `prune_ping_pong_revisions`).
    let (pruned, reset) = prune_ping_pong_revisions(conn);
    r.revisions_pruned = pruned;
    r.revs_reset = reset;

    r
}

/// (e) KQ2: fill `sender_id` for every self-sent row still at NULL.
/// A row is self-sent when its payload says `uidFrom='0'` (the exact
/// audit §3-KQ2 statement).
fn backfill_senders(conn: &Connection, own_uid: Option<&str>) -> usize {
    let Some(uid) = own_uid.filter(|u| account::valid_uid(u)) else {
        return 0;
    };
    conn.execute(
        "UPDATE messages SET sender_id = ?1
          WHERE sender_id IS NULL AND json_extract(payload_json, '$.uidFrom') = '0'",
        rusqlite::params![uid],
    )
    .unwrap_or(0) as usize
}

/// (f) H4 ping-pong: the pre-fix writer bumped `rev` on every
/// same-rank rewrite, so a message that only changed REPRESENTATION
/// (capture ciphertext vs e2ee plaintext of the same content, field
/// order, …) collected `edit` revisions that say nothing. A revision is
/// representation-only when hashing its payload with the SAME
/// `writer::content_hash(msgType, content)` as `messages` yields the
/// message's CURRENT hash and its kind is 'edit'; those are deleted
/// and each touched message's `rev` is set to the number of remaining
/// revision rows (renumbering is not needed — the count is the
/// semantic). Recall/delete rows are never candidates; a revision whose
/// payload does not hash (invalid JSON) or whose message is gone stays
/// (conservative). Returns `(revisions_pruned, revs_reset)`.
fn prune_ping_pong_revisions(conn: &Connection) -> (usize, usize) {
    // (msg_id, rev) of every representation-only edit revision.
    let mut prune: Vec<(String, i64)> = Vec::new();
    {
        let mut st = match conn.prepare(
            "SELECT r.msg_id, r.rev, r.payload_json, m.payload_json
               FROM message_revisions r
               JOIN messages m ON m.msg_id = r.msg_id
              WHERE r.kind = 'edit'",
        ) {
            Ok(st) => st,
            Err(_) => return (0, 0),
        };
        let rows = match st.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        }) {
            Ok(it) => it.filter_map(Result::ok).collect::<Vec<_>>(),
            Err(_) => return (0, 0),
        };
        for (msg_id, rev, rev_payload, msg_payload) in rows {
            let (Some(rp), Some(mp)) = (rev_payload, msg_payload) else {
                continue;
            };
            // Canonical hashing: key order cannot hide a real change,
            // and an unhashable payload is never "representation-only".
            let same = match (writer::content_hash(&rp), writer::content_hash(&mp)) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if same {
                prune.push((msg_id, rev));
            }
        }
    }
    if prune.is_empty() {
        return (0, 0);
    }
    let mut pruned = 0usize;
    {
        let mut del = match conn
            .prepare("DELETE FROM message_revisions WHERE msg_id = ?1 AND rev = ?2")
        {
            Ok(st) => st,
            Err(_) => return (0, 0),
        };
        for (msg_id, rev) in &prune {
            pruned += del.execute(rusqlite::params![msg_id, rev]).unwrap_or(0);
        }
    }
    // Each touched message: rev = the number of REMAINING revision rows
    // (recall/delete rows count — they are real history). Only rows
    // whose rev actually moves are counted, so a second run reports 0.
    let mut reset = 0usize;
    {
        let mut st = match conn.prepare(
            "UPDATE messages
                SET rev = (SELECT COUNT(*) FROM message_revisions r
                            WHERE r.msg_id = messages.msg_id)
              WHERE msg_id = ?1
                AND rev <> (SELECT COUNT(*) FROM message_revisions r
                             WHERE r.msg_id = messages.msg_id)",
        ) {
            Ok(st) => st,
            Err(_) => return (pruned, 0),
        };
        let touched: std::collections::BTreeSet<&String> = prune.iter().map(|(m, _)| m).collect();
        for msg_id in touched {
            reset += st.execute(rusqlite::params![msg_id]).unwrap_or(0);
        }
    }
    (pruned, reset)
}

/// The same work as [`repair_v1`], run inside `BEGIN IMMEDIATE …
/// ROLLBACK`: the returned report shows what WOULD change, and the DB
/// is provably untouched (audit §1.2 risk note: run the migration on a
/// copy first and compare). The caller supplies a COPY of the live DB
/// (`maint_repair` does); a failed BEGIN reports zero everywhere.
pub fn repair_v1_dry_run(conn: &Connection, own_uid: Option<&str>) -> RepairReport {
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return RepairReport::default();
    }
    let r = repair_v1(conn, own_uid);
    if conn.execute_batch("ROLLBACK").is_err() {
        // The transaction died mid-run: nothing was committed (every
        // step ran inside it). One best-effort retry for an odd
        // savepoint state, then whatever happens, no COMMIT ever runs.
        let _ = conn.execute_batch("ROLLBACK");
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

        let r = repair_v1(&conn, None);
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
        let r1 = repair_v1(&conn, None);
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
        let r2 = repair_v1(&conn, None);
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

        let r = repair_v1(&conn, None);
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
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2.types_remapped, 0);
    }

    // --- (e) KQ2 sender backfill ------------------------------------------

    /// Fake message with an explicit sender (payload shape: self-sent
    /// rows carry uidFrom='0').
    fn sender_msg(conn: &Connection, msg_id: &str, payload: &str, sender: Option<&str>) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES (?1, 'cS', ?2, 1, 1, NULL, ?3, 0, 0, 'capture')",
            rusqlite::params![msg_id, sender, payload],
        )
        .unwrap();
    }

    fn self_sent(msg_id: &str) -> String {
        format!(
            r#"{{"msgId":"{msg_id}","uidFrom":"0","idTo":"u9","msgType":"text","content":"x"}}"#
        )
    }

    #[test]
    fn repair_v1_backfills_self_sent_senders_only() {
        const UID: &str = "1234567890123456789"; // fake, valid shape
        let conn = db();
        // Self-sent rows: one stuck at NULL (the H4-b legacy), one
        // already set. Plus an incoming row with NULL sender — a
        // uidFrom of '0' is what marks self-sent, 'u2' must not match.
        sender_msg(&conn, "s1", &self_sent("s1"), None);
        sender_msg(&conn, "s2", &self_sent("s2"), Some("777"));
        sender_msg(
            &conn,
            "s3",
            r#"{"msgId":"s3","uidFrom":"u2","idTo":"u9","msgType":"text","content":"x"}"#,
            None,
        );

        let r = repair_v1(&conn, Some(UID));
        assert_eq!(r.senders_backfilled, 1, "only the NULL self-sent row");
        let sender = |id: &str| -> Option<String> {
            conn.query_row("SELECT sender_id FROM messages WHERE msg_id = ?1", [id], |x| x.get(0))
                .unwrap()
        };
        assert_eq!(sender("s1").as_deref(), Some(UID), "backfilled");
        assert_eq!(sender("s2").as_deref(), Some("777"), "already set — untouched");
        assert_eq!(sender("s3"), None, "not self-sent — untouched");
        // Idempotent: nothing left at NULL with uidFrom='0'.
        assert_eq!(repair_v1(&conn, Some(UID)).senders_backfilled, 0);

        // None (uid unknown) skips the step entirely.
        let conn2 = db();
        sender_msg(&conn2, "s1", &self_sent("s1"), None);
        assert_eq!(repair_v1(&conn2, None).senders_backfilled, 0);

        // A bad-shaped uid behaves as absent (same rule as
        // account::resolve_own_uid applies to a configured uid).
        let conn3 = db();
        sender_msg(&conn3, "s1", &self_sent("s1"), None);
        assert_eq!(repair_v1(&conn3, Some("12a")).senders_backfilled, 0);
    }

    // --- (f) H4 ping-pong revision prune -----------------------------------

    fn revision(conn: &Connection, msg_id: &str, rev: i64, kind: &str, payload: &str) {
        conn.execute(
            "INSERT INTO message_revisions (msg_id, rev, ts, kind, payload_json)
             VALUES (?1, ?2, 1, ?3, ?4)",
            rusqlite::params![msg_id, rev, kind, payload],
        )
        .unwrap();
    }

    #[test]
    fn repair_v1_prunes_ping_pong_edits_and_resets_rev() {
        let conn = db();
        // Current message payload: content "v2", rev inflated by the
        // pre-fix ping-pong writer.
        let cur =
            r#"{"msgId":"p1","uidFrom":"u1","idTo":"cP","ts":1,"msgType":"text","content":"v2"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, content_hash, rev, deleted, source)
             VALUES ('p1','cP','u1',1,1,'v2',?1,?2,5,0,'capture')",
            rusqlite::params![cur, writer::content_hash(cur).unwrap()],
        )
        .unwrap();
        // rev1: representation-only ping-pong — SAME content, different
        // key order (canonical hashing must see through it).
        let reordered =
            r#"{"content":"v2","msgType":"text","idTo":"cP","uidFrom":"u1","ts":1,"msgId":"p1"}"#;
        revision(&conn, "p1", 1, "edit", reordered);
        // rev2: a REAL edit (different content) — kept.
        revision(
            &conn,
            "p1",
            2,
            "edit",
            r#"{"msgId":"p1","uidFrom":"u1","idTo":"cP","ts":1,"msgType":"text","content":"v1"}"#,
        );
        // rev3: hash-equal to the current payload BUT kind 'recall' —
        // the kind guard keeps it (a real undo is history).
        revision(&conn, "p1", 3, "recall", cur);
        // rev4: invalid JSON — cannot hash, kept (conservative).
        revision(&conn, "p1", 4, "edit", "not json");
        // A revision for a message that no longer exists — kept (no
        // current payload to compare against).
        revision(&conn, "pX", 1, "edit", reordered);

        let r = repair_v1(&conn, None);
        assert_eq!(r.revisions_pruned, 1, "only the representation-only edit");
        assert_eq!(r.revs_reset, 1, "p1: rev 5 -> remaining 3");
        let rev: i64 = conn
            .query_row("SELECT rev FROM messages WHERE msg_id='p1'", [], |x| x.get(0))
            .unwrap();
        assert_eq!(rev, 3, "rev = the number of remaining revisions");
        let remaining: Vec<(i64, String)> = {
            let mut st = conn
                .prepare("SELECT rev, kind FROM message_revisions WHERE msg_id='p1' ORDER BY rev")
                .unwrap();
            st.query_map([], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(
            remaining,
            vec![
                (2, "edit".to_string()),
                (3, "recall".to_string()),
                (4, "edit".to_string()),
            ],
            "the real edit, the recall and the unhashable row survive"
        );
        let orphan: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_revisions WHERE msg_id='pX'", [], |x| {
                x.get(0)
            })
            .unwrap();
        assert_eq!(orphan, 1, "no message row -> never compared, kept");

        // Idempotent: nothing left to prune; rev already equals the count.
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2.revisions_pruned, 0);
        assert_eq!(r2.revs_reset, 0);
    }

    // --- dry run -------------------------------------------------------------

    /// Count/aggregate checksum over every column the repair steps
    /// touch (messages, conversations, message_revisions) — "byte for
    /// byte" in the counts/hashes sense of the brief.
    fn checksum(conn: &Connection) -> String {
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        format!(
            "msgs={mn} {mhash} {mtype} {mrev} {mnull} {msendernull} {mtlen} \
             convs={cn} {clastlen} {cts} {ctitlelen} \
             revrows={rn} {rrev} {rtlen}",
            mn = q("SELECT COUNT(*) FROM messages"),
            mhash = q("SELECT COALESCE(SUM(CASE WHEN content_hash IS NULL THEN 1 ELSE 0 END),0) FROM messages"),
            mtype = q("SELECT COALESCE(SUM(type),0) FROM messages"),
            mrev = q("SELECT COALESCE(SUM(rev),0) FROM messages"),
            mnull = q("SELECT COUNT(*) FROM messages WHERE sender_id IS NULL"),
            msendernull = q("SELECT COALESCE(SUM(CASE WHEN sender_id IS NULL THEN 1 ELSE 0 END),0) FROM messages"),
            mtlen = q("SELECT COALESCE(SUM(length(payload_json)),0) FROM messages"),
            cn = q("SELECT COUNT(*) FROM conversations"),
            clastlen = q("SELECT COALESCE(SUM(COALESCE(length(last_msg_id),0)),0) FROM conversations"),
            cts = q("SELECT COALESCE(SUM(COALESCE(last_ts,0)),0) FROM conversations"),
            ctitlelen = q("SELECT COALESCE(SUM(COALESCE(length(title),0)),0) FROM conversations"),
            rn = q("SELECT COUNT(*) FROM message_revisions"),
            rrev = q("SELECT COALESCE(SUM(rev),0) FROM message_revisions"),
            rtlen = q("SELECT COALESCE(SUM(COALESCE(length(payload_json),0)),0) FROM message_revisions"),
        )
    }

    #[test]
    fn repair_v1_dry_run_leaves_the_db_untouched() {
        const UID: &str = "1234567890123456789"; // fake, valid shape
        let conn = db();
        // The full legacy mess in one DB: orphan conv (cD has no row),
        // V1-era type 7 with payload msgType text, content_hash NULL,
        // sender NULL on a self-sent row, and one ping-pong revision.
        let p = r#"{"msgId":"d1","uidFrom":"0","idTo":"cD","ts":1,"msgType":"text","content":"x"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('d1','cD',NULL,1,7,NULL,?1,2,0,'capture')",
            rusqlite::params![p],
        )
        .unwrap();
        revision(&conn, "d1", 1, "edit", p);

        let before = checksum(&conn);
        let dry = repair_v1_dry_run(&conn, Some(UID));
        // The report says what WOULD change — every step reports work…
        assert_eq!(dry.conv_stubs_created, 1, "cD stub");
        assert_eq!(dry.last_msg_fixed, 1, "the fresh stub gets its pointer");
        assert_eq!(dry.content_hash_filled, 1);
        assert_eq!(dry.types_remapped, 1, "type 7 -> table code 1 (text)");
        assert_eq!(dry.senders_backfilled, 1);
        assert_eq!(dry.revisions_pruned, 1);
        assert_eq!(dry.revs_reset, 1, "rev 2 -> remaining 0");
        // …but the DB is unchanged (counts/hashes identical).
        assert_eq!(checksum(&conn), before, "dry run must not persist anything");

        // The real run changes the DB and is idempotent afterwards.
        let r1 = repair_v1(&conn, Some(UID));
        assert_eq!(r1.conv_stubs_created, 1);
        assert_eq!(r1.last_msg_fixed, 1);
        assert_eq!(r1.content_hash_filled, 1);
        assert_eq!(r1.types_remapped, 1);
        assert_eq!(r1.senders_backfilled, 1);
        assert_eq!(r1.revisions_pruned, 1);
        assert_eq!(r1.revs_reset, 1);
        assert_ne!(checksum(&conn), before, "the real run persisted the repair");
        // A second real run is all zeros, and a third moves nothing.
        let r2 = repair_v1(&conn, Some(UID));
        assert_eq!(r2, RepairReport::default(), "second run all zeros");
        let after = checksum(&conn);
        let _ = repair_v1(&conn, Some(UID));
        assert_eq!(checksum(&conn), after, "third run changes nothing");
    }
}
