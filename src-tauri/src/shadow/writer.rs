//! Single owner of every shadow DB write (rebuild 2026-11-19).
//!
//! Invariants (handoff P1/P2 acceptance):
//! - Idempotency: upserts keyed by server ids; replaying the same event
//!   converges. `rev` only bumps when the payload actually changed, and
//!   every bump lands in `message_revisions`.
//! - **E2EE ciphertext never overwrites plaintext**: an incoming capture
//!   row with `text = NULL` never clears an existing `text`; an `e2ee`
//!   row with plaintext does (it is strictly fresher, in-page truth).
//! - Conversations are never stripped: NULL fields in the incoming row
//!   leave the stored title/avatar untouched ("upsert conversation
//!   không xoá title/avatar").
//! - `raw_events` is a ring buffer trimmed on every batch (D4, 7 days).

use rusqlite::Connection;
use serde_json::Value;

use super::{Write, schema};

/// Persist one write. Returns the affected row kind for logging.
pub fn apply(conn: &Connection, w: &Write) -> rusqlite::Result<&'static str> {
    match w {
        Write::Conversation {
            id,
            is_group,
            title,
            avatar_url,
            last_msg_id,
            last_ts,
            raw,
        } => {
            conn.execute(
                "INSERT INTO conversations (id, type, title, avatar_url, last_msg_id, last_ts, unread, raw_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                   type       = excluded.type,
                   title      = COALESCE(excluded.title, conversations.title),
                   avatar_url = COALESCE(excluded.avatar_url, conversations.avatar_url),
                   last_msg_id = COALESCE(excluded.last_msg_id, conversations.last_msg_id),
                   last_ts    = MAX(COALESCE(excluded.last_ts, conversations.last_ts), COALESCE(conversations.last_ts, excluded.last_ts)),
                   raw_json   = COALESCE(excluded.raw_json, conversations.raw_json),
                   updated_at = excluded.updated_at",
                rusqlite::params![
                    id,
                    if *is_group { 1i64 } else { 0i64 },
                    title,
                    avatar_url,
                    last_msg_id,
                    last_ts,
                    raw,
                    schema::now_ms(),
                ],
            )?;
            Ok("conversation")
        }
        Write::Message {
            msg_id,
            conv_id,
            sender_id,
            ts,
            kind,
            text,
            payload,
            source,
        } => {
            // Snapshot the pre-upsert payload BEFORE the conflict clause
            // replaces it (single writer thread, so no race).
            let old_payload: Option<String> = conn
                .query_row(
                    "SELECT payload_json FROM messages WHERE msg_id = ?1",
                    rusqlite::params![msg_id],
                    |r| r.get(0),
                )
                .ok();
            conn.execute(
                // text guard: never overwrite a real plaintext with NULL
                // (ciphertext row); DO let an e2ee plaintext land.
                "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8)
                 ON CONFLICT(msg_id) DO UPDATE SET
                   text = CASE
                            WHEN excluded.text IS NOT NULL THEN excluded.text
                            ELSE messages.text
                          END,
                   payload_json = excluded.payload_json,
                   rev = messages.rev + (CASE WHEN messages.payload_json <> excluded.payload_json THEN 1 ELSE 0 END),
                   source = CASE WHEN excluded.source = 'e2ee' THEN excluded.source ELSE messages.source END",
                rusqlite::params![msg_id, conv_id, sender_id, ts, kind, text, payload, source],
            )?;
            // Revision trail when the payload changed (P1: edit/recall).
            if old_payload.as_deref().map(|old| old != payload).unwrap_or(false) {
                let rev: i64 = conn.query_row(
                    "SELECT rev FROM messages WHERE msg_id = ?1",
                    rusqlite::params![msg_id],
                    |r| r.get(0),
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO message_revisions (msg_id, rev, ts, kind, payload_json)
                     VALUES (?1, ?2, ?3, 'edit', ?4)",
                    rusqlite::params![msg_id, rev.max(1), schema::now_ms(), payload],
                )?;
            }
            extract_attachments(conn, msg_id, *kind, payload)?;
            // Keep the conversation's last pointers fresh.
            conn.execute(
                "UPDATE conversations
                    SET last_ts = MAX(COALESCE(last_ts, ?2), ?2),
                        last_msg_id = COALESCE(?3, last_msg_id),
                        updated_at = ?2
                  WHERE id = ?1",
                rusqlite::params![conv_id, ts, msg_id],
            )?;
            Ok("message")
        }
        Write::Revision {
            msg_id,
            rev,
            ts,
            kind,
            payload,
        } => {
            conn.execute(
                "INSERT OR IGNORE INTO message_revisions (msg_id, rev, ts, kind, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![msg_id, rev, ts, kind, payload],
            )?;
            Ok("revision")
        }
        Write::Reaction {
            msg_id,
            user_id,
            emoji,
            ts,
        } => {
            conn.execute(
                "INSERT INTO reactions (msg_id, user_id, emoji, ts) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(msg_id, user_id) DO UPDATE SET emoji = excluded.emoji, ts = excluded.ts",
                rusqlite::params![msg_id, user_id, emoji, ts],
            )?;
            Ok("reaction")
        }
        Write::Participants { conv_id, raw } => {
            conn.execute(
                "UPDATE conversations SET raw_json = COALESCE(?2, raw_json), updated_at = ?3 WHERE id = ?1",
                rusqlite::params![conv_id, raw, schema::now_ms()],
            )?;
            Ok("participants")
        }
        Write::Contact {
            user_id,
            display_name,
            avatar_url,
            raw,
        } => {
            conn.execute(
                "INSERT INTO contacts (user_id, display_name, phone_hash, avatar_url, raw_json, updated_at)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5)
                 ON CONFLICT(user_id) DO UPDATE SET
                   display_name = COALESCE(excluded.display_name, contacts.display_name),
                   avatar_url   = COALESCE(excluded.avatar_url, contacts.avatar_url),
                   raw_json     = COALESCE(excluded.raw_json, contacts.raw_json),
                   updated_at   = excluded.updated_at",
                rusqlite::params![user_id, display_name, avatar_url, raw, schema::now_ms()],
            )?;
            Ok("contact")
        }
        Write::Group {
            group_id,
            name,
            raw,
        } => {
            conn.execute(
                "INSERT INTO groups (group_id, name, raw_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(group_id) DO UPDATE SET
                   name = COALESCE(excluded.name, groups.name),
                   raw_json = COALESCE(excluded.raw_json, groups.raw_json),
                   updated_at = excluded.updated_at",
                rusqlite::params![group_id, name, raw, schema::now_ms()],
            )?;
            // Mirror the name onto the conversation (groups == type 1 rows).
            conn.execute(
                "UPDATE conversations SET title = COALESCE(?2, title), updated_at = ?3 WHERE id = ?1",
                rusqlite::params![group_id, name, schema::now_ms()],
            )?;
            Ok("group")
        }
    }
}

/// Pull attachment refs (urls, sizes) out of a message payload.
/// Known media shapes: `content` object with `url|fileUrl|photoUrl` style
/// fields. Downloads are P1b's job; here we only record references.
fn extract_attachments(
    conn: &Connection,
    msg_id: &str,
    kind: i64,
    payload: &str,
) -> rusqlite::Result<()> {
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        return Ok(());
    };
    let Some(content) = v.get("content").and_then(Value::as_object) else {
        return Ok(());
    };
    let kind_name = match kind {
        2 => "image",
        3 => "sticker",
        4 => "file",
        5 => "voice",
        6 => "video",
        _ => return Ok(()),
    };
    let mut idx = 0i64;
    for (key, val) in content {
        let url = match val {
            Value::String(s) if key.contains("url") || key.contains("Url") => Some(s.clone()),
            Value::Object(o) => o
                .get("url")
                .or_else(|| o.get("fileUrl"))
                .or_else(|| o.get("photoUrl"))
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        };
        let Some(url) = url else { continue };
        conn.execute(
            "INSERT OR IGNORE INTO attachments (msg_id, idx, kind, url, status)
             VALUES (?1, ?2, ?3, ?4, 'ref')",
            rusqlite::params![msg_id, idx, kind_name, url],
        )?;
        idx += 1;
    }
    Ok(())
}

/// Append one raw event (decoded or flagged-undecoded) to the ring.
pub fn raw_event(
    conn: &Connection,
    direction: &str,
    kind: &str,
    endpoint: &str,
    payload: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![schema::now_ms(), direction, kind, endpoint, payload],
    )?;
    Ok(())
}

/// Trim `raw_events` older than `days` (D4 ring buffer).
pub fn trim_raw_events(conn: &Connection, days: u32) -> rusqlite::Result<usize> {
    let cutoff = schema::now_ms() - (days as i64) * 86_400_000;
    let n = conn.execute("DELETE FROM raw_events WHERE ts < ?1", [cutoff])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::super::{schema, Write};
    use super::*;
    use crate::migrate::sqlcipher;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn msg(msg_id: &str, text: Option<&str>, source: &'static str) -> Write {
        Write::Message {
            msg_id: msg_id.into(),
            conv_id: "c1".into(),
            sender_id: Some("u1".into()),
            ts: 1000,
            kind: 1,
            text: text.map(str::to_string),
            payload: format!(
                r#"{{"msgId":"{msg_id}","uidFrom":"u1","ts":1000,"msgType":"text","content":"x"}}"#
            ),
            source,
        }
    }

    #[test]
    fn idempotent_replay_and_rev_bump() {
        let conn = db();
        apply(&conn, &msg("m1", Some("a"), "capture")).unwrap();
        apply(&conn, &msg("m1", Some("a"), "capture")).unwrap();
        let (rev, n): (i64, i64) = conn
            .query_row("SELECT rev, 0 FROM messages WHERE msg_id='m1'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(rev, 0, "identical replay must not bump rev");
        // Different payload -> rev 1 + one revision row.
        let mut w = msg("m1", Some("a"), "capture");
        if let Write::Message { payload, .. } = &mut w {
            *payload = r#"{"msgId":"m1","uidFrom":"u1","ts":1000,"msgType":"text","content":"b"}"#.into();
        }
        apply(&conn, &w).unwrap();
        let rev: i64 = conn
            .query_row("SELECT rev FROM messages WHERE msg_id='m1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rev, 1);
        let revisions: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_revisions WHERE msg_id='m1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(revisions, 1);
    }

    #[test]
    fn ciphertext_never_overwrites_plaintext() {
        let conn = db();
        // e2ee plaintext lands first (bridge tap).
        apply(&conn, &msg("m2", Some("bản rõ"), "e2ee")).unwrap();
        // A capture row with the same id but cipher-only (no text).
        let mut w = msg("m2", None, "capture");
        if let Write::Message { payload, .. } = &mut w {
            *payload = r#"{"msgId":"m2","e2ee":"k","content":"QUJD"}"#.into();
        }
        apply(&conn, &w).unwrap();
        let (text, source): (Option<String>, String) = conn
            .query_row("SELECT text, source FROM messages WHERE msg_id='m2'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(text.as_deref(), Some("bản rõ"), "cipher must not clear plaintext");
        assert_eq!(source, "e2ee", "source stays the plaintext authority");
    }

    #[test]
    fn conversation_upsert_keeps_title() {
        let conn = db();
        let w = Write::Conversation {
            id: "c1".into(),
            is_group: true,
            title: Some("Nhóm A".into()),
            avatar_url: Some("https://a/av".into()),
            last_msg_id: Some("m1".into()),
            last_ts: Some(50),
            raw: "{}".into(),
        };
        apply(&conn, &w).unwrap();
        // A stub (clearUnreads) with NULL title must not clear it.
        let stub = Write::Conversation {
            id: "c1".into(),
            is_group: true,
            title: None,
            avatar_url: None,
            last_msg_id: Some("m2".into()),
            last_ts: Some(60),
            raw: "{}".into(),
        };
        apply(&conn, &stub).unwrap();
        let (title, avatar, last, ts): (Option<String>, Option<String>, Option<String>, Option<i64>) =
            conn.query_row(
                "SELECT title, avatar_url, last_msg_id, last_ts FROM conversations WHERE id='c1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(title.as_deref(), Some("Nhóm A"));
        assert_eq!(avatar.as_deref(), Some("https://a/av"));
        assert_eq!(last.as_deref(), Some("m2"));
        assert_eq!(ts, Some(60));
    }

    #[test]
    fn raw_events_ring_trim() {
        let conn = db();
        raw_event(&conn, "in", "ws", "w", "{}").unwrap();
        // Force an unambiguous old timestamp (raw_event stamps now()).
        conn.execute("UPDATE raw_events SET ts = 1000", []).unwrap();
        let n = trim_raw_events(&conn, 0).unwrap();
        assert!(n >= 1);
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
    }
}
