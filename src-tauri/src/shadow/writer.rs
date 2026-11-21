//! Single owner of every shadow DB write (rebuild 2026-11-19).
//!
//! Invariants (handoff P1/P2 acceptance; audit H4/T4–T7, batch 1):
//! - Idempotency: upserts keyed by server ids; replaying the same events
//!   in ANY order converges. `rev` bumps only when the stored payload is
//!   actually replaced by a same-or-higher-rank source AND the content
//!   hash really changed; every bump lands in `message_revisions`.
//! - Source precedence (H4-a): `e2ee > capture > import`. `payload_json`,
//!   `content_hash`, `type` and `source` are replaced only when the
//!   incoming source ranks >= the stored one — a capture ciphertext
//!   arriving after an e2ee plaintext never replaces it (no rev
//!   ping-pong); `source` ends as the higher rank of the two.
//! - Import guard (H4-c): `import` only ever fills NULL cells — it never
//!   replaces text/payload/type of a capture/e2ee row (T6).
//! - Frozen fields (H4-b): `conv_id`/`sender_id`/`ts` stick once set;
//!   `type` follows rank (batch 2's new msg codes overwrite V1 codes).
//! - First fill is not an edit: a NULL stored hash, or the first
//!   plaintext landing in a NULL text cell, bumps nothing (T4).
//! - Conversation integrity (H4-d/e): every message creates (at least)
//!   a stub conversation row, and `last_msg_id`/`last_ts` only move
//!   forward in `ts`, never by arrival order.
//! - Conversations are never stripped: NULL fields in the incoming row
//!   leave the stored title/avatar untouched ("upsert conversation
//!   không xoá title/avatar").
//! - `raw_events` is a ring buffer trimmed on every batch (D4, 7 days).

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

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
                   last_msg_id = CASE
                     -- H4-d/T7: the pointer moves only when the incoming row
                     -- proves it is at least as new (ts comparison), or when
                     -- nothing is stored yet. A NULL excluded.last_ts cannot
                     -- prove anything -> keep the stored pointer.
                     WHEN conversations.last_ts IS NULL
                       OR (excluded.last_ts IS NOT NULL
                           AND excluded.last_ts >= conversations.last_ts)
                     THEN COALESCE(excluded.last_msg_id, conversations.last_msg_id)
                     ELSE conversations.last_msg_id
                   END,
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
            is_group,
        } => {
            // Snapshot the pre-upsert row BEFORE the conflict clause
            // replaces it (single writer thread, so no race). This drives
            // the revision bookkeeping below.
            let old: Option<(String, Option<String>, Option<String>, i64)> = conn
                .query_row(
                    "SELECT source, text, content_hash, rev FROM messages WHERE msg_id = ?1",
                    rusqlite::params![msg_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .ok();
            let new_hash = content_hash(payload);
            let rank_in = source_rank(source);
            conn.execute(
                // H4 semantics (T4/T5/T6): precedence e2ee(3) > capture(2)
                // > import(1), evaluated against the STORED source.
                // - payload_json/content_hash/type/source are replaced only
                //   when the incoming rank >= stored rank (a capture
                //   ciphertext never overwrites an e2ee plaintext; import
                //   never overwrites capture/e2ee).
                // - text keeps the NULL guard (NULL never overwrites) and
                //   adds the rank guard on non-NULL text, but ANY rank may
                //   fill a NULL cell (T6: import fills NULL cells).
                // - conv_id/sender_id/ts are frozen once set (T5 COALESCE).
                "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, content_hash, rev, deleted, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9)
                 ON CONFLICT(msg_id) DO UPDATE SET
                   conv_id = COALESCE(messages.conv_id, excluded.conv_id),
                   sender_id = COALESCE(messages.sender_id, excluded.sender_id),
                   ts = COALESCE(messages.ts, excluded.ts),
                   type = CASE WHEN ?10 >= (CASE messages.source WHEN 'e2ee' THEN 3 WHEN 'capture' THEN 2 ELSE 1 END)
                               THEN excluded.type ELSE messages.type END,
                   text = CASE WHEN excluded.text IS NOT NULL
                                 AND (?10 >= (CASE messages.source WHEN 'e2ee' THEN 3 WHEN 'capture' THEN 2 ELSE 1 END)
                                      OR messages.text IS NULL)
                                THEN excluded.text ELSE messages.text END,
                   payload_json = CASE WHEN ?10 >= (CASE messages.source WHEN 'e2ee' THEN 3 WHEN 'capture' THEN 2 ELSE 1 END)
                                        THEN excluded.payload_json ELSE messages.payload_json END,
                   content_hash = CASE WHEN ?10 >= (CASE messages.source WHEN 'e2ee' THEN 3 WHEN 'capture' THEN 2 ELSE 1 END)
                                        THEN excluded.content_hash ELSE messages.content_hash END,
                   source = CASE WHEN ?10 >= (CASE messages.source WHEN 'e2ee' THEN 3 WHEN 'capture' THEN 2 ELSE 1 END)
                                 THEN excluded.source ELSE messages.source END",
                rusqlite::params![
                    msg_id, conv_id, sender_id, ts, kind, text, payload, new_hash, source,
                    rank_in
                ],
            )?;
            if let Some((old_source, old_text, old_hash, old_rev)) = old {
                // H4-f/T4: rev bumps (and a revision row is written) ONLY
                // when the payload was actually replaced by a
                // same-or-higher rank AND the content hash really changed.
                // A NULL stored hash is the first fill (no bump), and the
                // first plaintext landing in a NULL text cell is a decode,
                // not an edit (capture-cipher -> e2ee-plaintext upgrade).
                let replaced = rank_in >= source_rank(&old_source);
                let hash_changed = old_hash != new_hash;
                let first_fill = old_text.is_none() && text.is_some();
                if replaced && hash_changed && old_hash.is_some() && !first_fill {
                    let rev = old_rev + 1;
                    conn.execute(
                        "UPDATE messages SET rev = ?2 WHERE msg_id = ?1",
                        rusqlite::params![msg_id, rev],
                    )?;
                    // T4: the recall-family msgTypes (the undo markers
                    // normalize.rs codes as type 8: chat.delete,
                    // chat.undo, chat.delete.everyone, V1 recall) are
                    // recalls.
                    let revision_kind = if is_recall_msg(payload) { "recall" } else { "edit" };
                    conn.execute(
                        "INSERT OR IGNORE INTO message_revisions (msg_id, rev, ts, kind, payload_json)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![msg_id, rev, schema::now_ms(), revision_kind, payload],
                    )?;
                }
                // Attachment refs mirror the STORED payload: only (re)extract
                // when this write actually stored its payload.
                if replaced {
                    extract_attachments(conn, msg_id, payload, source)?;
                }
            } else {
                // Fresh row: this payload is now the stored one.
                extract_attachments(conn, msg_id, payload, source)?;
            }
            // T7/H4-e: a message always owns (at least) a stub conversation
            // row, so conversation-first listings never orphan it. B5: a
            // KNOWN group message (groupMsgs) creates the stub as type 1;
            // anything else stays 0 (private), the schema's neutral
            // default. INSERT OR IGNORE keeps an existing row untouched —
            // Conversation/Group writes still refine the type later.
            // (conversations.type/unread/updated_at are the NOT NULL
            // columns the stub must satisfy.)
            if !conv_id.is_empty() {
                conn.execute(
                    "INSERT OR IGNORE INTO conversations (id, type, unread, updated_at)
                     VALUES (?1, ?2, 0, ?3)",
                    rusqlite::params![
                        conv_id,
                        if *is_group == Some(true) { 1i64 } else { 0i64 },
                        schema::now_ms()
                    ],
                )?;
            }
            // T7/H4-d: last pointers only move FORWARD in ts — never by
            // arrival order (import history must not wreck the anchor).
            conn.execute(
                "UPDATE conversations
                    SET last_msg_id = ?3,
                        last_ts = ?2,
                        updated_at = ?2
                  WHERE id = ?1
                    AND ?2 >= COALESCE(last_ts, 0)",
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

/// Source precedence rank (H4-a/T4): `e2ee` (3) > `capture` (2) >
/// `import` (1). These are exactly the `source` strings the pipeline
/// produces (normalize.rs emits "capture"/"e2ee", import.rs "import");
/// anything else ranks lowest — the most conservative choice.
pub fn source_rank(source: &str) -> i64 {
    match source {
        "e2ee" => 3,
        "capture" => 2,
        _ => 1,
    }
}

/// Canonical JSON for hashing: object keys sorted recursively, arrays
/// keep order, scalars serialize via serde_json. Two payloads that
/// carry the same content in a different field order hash identically
/// (that is what stops the rev ping-pong on representation-only diffs).
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let parts: Vec<String> = entries
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(val)
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        scalar => serde_json::to_string(scalar).unwrap_or_default(),
    }
}

/// H4-f/T4: `content_hash` = sha256 hex over
/// `msgType + "\u{1f}" + canonical_json(content)`, computed in Rust.
/// `None` when the payload is not valid JSON (stored NULL: the first
/// real fill then treats it as legacy, never an edit).
pub fn content_hash(payload: &str) -> Option<String> {
    let v: Value = serde_json::from_str(payload).ok()?;
    let msg_type = v.get("msgType").and_then(Value::as_str).unwrap_or("");
    let content = v.get("content").cloned().unwrap_or(Value::Null);
    let canonical = canonical_json(&content);
    let mut h = Sha256::new();
    h.update(msg_type.as_bytes());
    h.update("\u{1f}".as_bytes());
    h.update(canonical.as_bytes());
    Some(format!("{:x}", h.finalize()))
}

/// Does this payload mark a recall/undo? T4: incoming msgType
/// `chat.delete`, `chat.undo`, `chat.delete.everyone`, or `recall` —
/// exactly the four strings the `msg_type_code` table codes as 8
/// (batch 25: the Zalo PC 26.11.12 source adds MSG_UNDO ->
/// `chat.undo` and MSG_DEL_EVERYONE -> `chat.delete.everyone` to the
/// family; H1 verified the original alignment). Used ONLY to pick the
/// revision kind.
fn is_recall_msg(payload: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        return false;
    };
    matches!(
        v.get("msgType").and_then(Value::as_str),
        Some("chat.delete") | Some("chat.undo") | Some("chat.delete.everyone") | Some("recall")
    )
}

/// Outcome of one media download, reported by the media thread and
/// applied by the flusher inside its batch transaction (T3/A5: single
/// writer). `path` is the content-addressed store path; `sha256` is the
/// file digest (also its name).
#[derive(Debug, Clone, PartialEq)]
pub enum MediaOutcome {
    Downloaded { path: String, sha256: String, size: i64 },
    /// B4/KQ1 fallback: the bytes failed the magic sniff — E2EE CDN
    /// content may be ciphertext. Nothing is kept in the store; the row
    /// keeps its url (`status='ref-encrypted'`) instead of going
    /// `failed`, so a future decode path can pick it up.
    RefEncrypted,
    /// M2 (batch 26): the link is GONE (403/404/410) — expired CDN
    /// history is not a broken row. Nothing is kept; the row keeps its
    /// url with `status='expired` so it is never retried by the live
    /// thread, and the opt-in import backfill skips it too.
    Expired,
    Failed,
}

/// Apply one media outcome to its `attachments` row (T3). Only the
/// flusher calls this, on its own connection; the media thread itself
/// holds a READ-ONLY connection.
pub fn media_done(conn: &Connection, rowid: i64, outcome: &MediaOutcome) -> rusqlite::Result<usize> {
    match outcome {
        MediaOutcome::Downloaded { path, sha256, size } => conn.execute(
            "UPDATE attachments SET status='downloaded', local_path=?1, sha256=?2, size=?3 \
             WHERE rowid = ?4",
            rusqlite::params![path, sha256, size, rowid],
        ),
        MediaOutcome::RefEncrypted => conn.execute(
            "UPDATE attachments SET status='ref-encrypted' WHERE rowid = ?1",
            rusqlite::params![rowid],
        ),
        MediaOutcome::Expired => conn.execute(
            "UPDATE attachments SET status='expired' WHERE rowid = ?1",
            rusqlite::params![rowid],
        ),
        MediaOutcome::Failed => conn.execute(
            "UPDATE attachments SET status='failed' WHERE rowid = ?1",
            rusqlite::params![rowid],
        ),
    }
}

/// KQ1(a)/H1: pull the download ref out of one media message.
/// Dispatch is on the ORIGINAL msgType string (never the numeric
/// code — the whole point of H1): the real wire shapes keep their
/// urls in different places per type.
/// - `chat.photo`: ONE url, priority `params.hdUrl` > `params.hd` >
///   `params.rawUrl` > `href` (E2EE payloads carry `hdUrl`; a later
///   higher-rank write IMPROVES the row instead of duplicating it).
/// - `chat.video.msg` -> `href`; `share.file` -> `href`;
///   `chat.voice` -> `href`, else `params.url`.
/// - sticker / recommended (link/call card, NOT media) / gif /
///   anything else -> nothing.
/// `content.params` is usually a JSON *string* — it is parsed here; an
/// object is accepted too. Only values that are strings starting with
/// `https://` survive.
pub fn pick_attachments(msg_type: &str, content: &Value) -> Vec<(&'static str, String)> {
    pick_attachments_fields(msg_type, content)
        .into_iter()
        .map(|(kind, url, _field)| (kind, url))
        .collect()
}

/// Batch 26 (M1): the SAME pick as [`pick_attachments`] — identical
/// priority, identical urls, identical kinds (the wrapper above is the
/// exact old behaviour) — with the SOURCE FIELD named:
/// `params.hdUrl`, `params.hd`, `params.rawUrl`, `href`, `params.url`.
/// The media shape CLI re-runs this over stored payloads to report
/// which field a row's url came from; field NAMES only, never values.
pub fn pick_attachments_fields(
    msg_type: &str,
    content: &Value,
) -> Vec<(&'static str, String, String)> {
    let Some(obj) = content.as_object() else {
        return Vec::new(); // webchat-style plain-string content
    };
    let params = parsed_params(obj);
    let one = |kind: &'static str, cand: Option<(String, String)>| {
        cand.map(|(field, url)| vec![(kind, url, field)]).unwrap_or_default()
    };
    let param_field = |keys: &[&'static str]| -> Option<(String, String)> {
        param_str(params.as_ref(), keys).map(|(k, u)| (format!("params.{k}"), u))
    };
    match msg_type {
        "chat.photo" | "photo" | "image" => one(
            "image",
            param_field(&["hdUrl", "hd", "rawUrl"])
                .or_else(|| https_str(obj.get("href")).map(|u| ("href".into(), u))),
        ),
        "chat.video.msg" | "video" => one(
            "video",
            https_str(obj.get("href")).map(|u| ("href".into(), u)),
        ),
        "share.file" | "file" => one(
            "file",
            https_str(obj.get("href")).map(|u| ("href".into(), u)),
        ),
        "chat.voice" | "voice" => one(
            "voice",
            https_str(obj.get("href"))
                .map(|u| ("href".into(), u))
                .or_else(|| param_field(&["url"])),
        ),
        _ => Vec::new(),
    }
}

/// A candidate url value: must be a JSON string starting `https://`
/// (B2: http/relative/fragment values are dropped outright).
fn https_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|s| s.starts_with("https://"))
        .map(str::to_string)
}

/// `content.params` arrives as a JSON STRING in the real shapes
/// (H1); an object is accepted too. Anything else is empty.
fn parsed_params(obj: &serde_json::Map<String, Value>) -> Option<Value> {
    match obj.get("params") {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok(),
        Some(v @ Value::Object(_)) => Some(v.clone()),
        _ => None,
    }
}

/// First https candidate among `params` keys, in the given priority
/// order — a non-https value in a higher-priority key is SKIPPED (the
/// filter is per value), never falls through to a lower key's failure.
/// Batch 26 M1: returns the KEY alongside the url (the caller prefixes
/// it for the field name the media shape CLI reports).
fn param_str(params: Option<&Value>, keys: &[&'static str]) -> Option<(&'static str, String)> {
    let p = params?.as_object()?;
    keys.iter()
        .find_map(|k| https_str(p.get(*k)).map(|u| (*k, u)))
}

/// Pull attachment refs out of the message payload (the msgType string
/// + `content` value drive [`pick_attachments`]) and store them.
/// `INSERT OR IGNORE` on (msg_id, idx); a still-`ref` row is IMPROVED
/// in place when a higher-rank payload carries a different url (KQ1:
/// e2ee `hdUrl` after capture `href`); `downloaded`/`failed` rows are
/// never touched.
///
/// M3 (batch 26): the initial status follows the write's SOURCE. A row
/// created for an import-sourced message starts as `ref-import` — a
/// KNOWN url from imported history that the live media thread must NOT
/// pick (the media module's "never a backfill scan of history"). A
/// later live capture of the SAME (msg_id, idx) improves the row's url
/// through the shared rule below but never silently upgrades its
/// status: `ref-import` keeps meaning "history, not live-queued".
fn extract_attachments(conn: &Connection, msg_id: &str, payload: &str, source: &str) -> rusqlite::Result<()> {
    let Ok(v) = serde_json::from_str::<Value>(payload) else {
        return Ok(());
    };
    let msg_type = v.get("msgType").and_then(Value::as_str).unwrap_or("");
    let content = v.get("content").cloned().unwrap_or(Value::Null);
    let initial_status: &str = if source == "import" { "ref-import" } else { "ref" };
    for (idx, (kind, url)) in pick_attachments(msg_type, &content).into_iter().enumerate() {
        conn.execute(
            "INSERT OR IGNORE INTO attachments (msg_id, idx, kind, url, status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![msg_id, idx as i64, kind, url, initial_status],
        )?;
        // M3: the improve rule treats `ref-import` like `ref` (a live
        // capture upgrades the url of the SAME message) but the UPDATE
        // only ever sets `url` — the history status is kept, never
        // silently upgraded to the live queue.
        conn.execute(
            "UPDATE attachments SET url = ?3
              WHERE msg_id = ?1 AND idx = ?2 AND status IN ('ref', 'ref-import') AND url <> ?3",
            rusqlite::params![msg_id, idx as i64, url],
        )?;
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
    use serde_json::json;

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
            is_group: None,
        }
    }

    /// Explicit message write: full control over every field.
    #[allow(clippy::too_many_arguments)]
    fn wmsg(
        msg_id: &str,
        conv: &str,
        sender: Option<&str>,
        ts: i64,
        kind: i64,
        text: Option<&str>,
        payload: &str,
        source: &'static str,
        is_group: Option<bool>,
    ) -> Write {
        Write::Message {
            msg_id: msg_id.into(),
            conv_id: conv.into(),
            sender_id: sender.map(str::to_string),
            ts,
            kind,
            text: text.map(str::to_string),
            payload: payload.into(),
            source,
            is_group,
        }
    }

    /// Payload with a JSON-literal `content` (pass e.g. `"\"ptext\""`).
    fn pay(msg_id: &str, msg_type: &str, content: &str) -> String {
        format!(
            r#"{{"msgId":"{msg_id}","uidFrom":"u1","idTo":"c1","ts":1000,"msgType":"{msg_type}","content":{content}}}"#
        )
    }

    #[test]
    fn idempotent_replay_and_rev_bump() {
        let conn = db();
        apply(&conn, &msg("m1", Some("a"), "capture")).unwrap();
        apply(&conn, &msg("m1", Some("a"), "capture")).unwrap();
        let rev: i64 = conn
            .query_row("SELECT rev FROM messages WHERE msg_id='m1'", [], |r| r.get(0))
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

    // --- T4: source precedence + hash-driven rev -------------------------

    #[test]
    fn e2ee_then_capture_no_pingpong() {
        let conn = db();
        let p1 = pay("m1", "text", "\"ptext\""); // e2ee plaintext payload
        let p2 = pay("m1", "text", "\"QUJD\""); // capture-side ciphertext
        apply(&conn, &wmsg("m1", "c1", Some("u1"), 1000, 1, Some("ptext"), &p1, "e2ee", None)).unwrap();
        apply(&conn, &wmsg("m1", "c1", Some("u1"), 1000, 1, None, &p2, "capture", None)).unwrap();
        apply(&conn, &wmsg("m1", "c1", Some("u1"), 1000, 1, Some("ptext"), &p1, "e2ee", None)).unwrap();
        apply(&conn, &wmsg("m1", "c1", Some("u1"), 1000, 1, None, &p2, "capture", None)).unwrap();
        let (payload, source, rev, revisions): (String, String, i64, i64) = conn
            .query_row(
                "SELECT payload_json, source, rev,
                        (SELECT COUNT(*) FROM message_revisions WHERE msg_id = 'm1')
                 FROM messages WHERE msg_id = 'm1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            payload, p1,
            "capture ciphertext must never replace the e2ee payload"
        );
        assert_eq!(source, "e2ee");
        assert_eq!(rev, 0, "no ping-pong: rev never moved");
        assert_eq!(revisions, 0, "no revision rows for a rank-downgrade replay");
    }

    #[test]
    fn capture_then_e2ee_upgrades() {
        let conn = db();
        let cipher = pay("m2", "text", "\"QUJD\"");
        let plain = pay("m2", "text", "\"bản rõ\"");
        apply(&conn, &wmsg("m2", "c1", Some("u1"), 1000, 1, None, &cipher, "capture", None)).unwrap();
        apply(&conn, &wmsg("m2", "c1", Some("u1"), 1000, 1, Some("bản rõ"), &plain, "e2ee", None)).unwrap();
        let (payload, text, source, rev, revisions): (String, Option<String>, String, i64, i64) =
            conn.query_row(
                "SELECT payload_json, text, source, rev,
                        (SELECT COUNT(*) FROM message_revisions WHERE msg_id = 'm2')
                 FROM messages WHERE msg_id = 'm2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(payload, plain, "e2ee plaintext upgrades the cipher row");
        assert_eq!(text.as_deref(), Some("bản rõ"));
        assert_eq!(source, "e2ee");
        // Chosen semantics (documented): the first plaintext fill into a
        // NULL text cell is a DECODE, not an edit -> rev 0, no revision.
        assert_eq!(rev, 0);
        assert_eq!(revisions, 0);
    }

    #[test]
    fn real_edit_bumps_once() {
        let conn = db();
        let v1 = pay("m3", "text", "\"v1\"");
        let v2 = pay("m3", "text", "\"v2\"");
        apply(&conn, &wmsg("m3", "c1", Some("u1"), 1000, 1, Some("v1"), &v1, "capture", None)).unwrap();
        apply(&conn, &wmsg("m3", "c1", Some("u1"), 1000, 1, Some("v2"), &v2, "capture", None)).unwrap();
        let (rev, revisions, kind): (i64, i64, String) = conn
            .query_row(
                "SELECT rev,
                        (SELECT COUNT(*) FROM message_revisions WHERE msg_id = 'm3'),
                        (SELECT kind FROM message_revisions WHERE msg_id = 'm3' AND rev = 1)
                 FROM messages WHERE msg_id = 'm3'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(rev, 1, "a real content change bumps rev exactly once");
        assert_eq!(revisions, 1);
        assert_eq!(kind, "edit");
        // Replaying the same edit changes nothing.
        apply(&conn, &wmsg("m3", "c1", Some("u1"), 1000, 1, Some("v2"), &v2, "capture", None)).unwrap();
        let (rev, revisions): (i64, i64) = conn
            .query_row(
                "SELECT rev, (SELECT COUNT(*) FROM message_revisions WHERE msg_id = 'm3')
                 FROM messages WHERE msg_id = 'm3'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rev, 1);
        assert_eq!(revisions, 1);
    }

    #[test]
    fn recall_kind() {
        let conn = db();
        let original = pay("m4", "text", "\"hello\"");
        let deleted = pay("m4", "chat.delete", "\"\"");
        apply(&conn, &wmsg("m4", "c1", Some("u1"), 1000, 1, Some("hello"), &original, "capture", None))
            .unwrap();
        // chat.delete now maps to the table code 8 (B1).
        apply(&conn, &wmsg("m4", "c1", Some("u1"), 1000, 8, None, &deleted, "capture", None)).unwrap();
        let (rev, kind): (i64, String) = conn
            .query_row(
                "SELECT rev, (SELECT kind FROM message_revisions WHERE msg_id = 'm4')
                 FROM messages WHERE msg_id = 'm4'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rev, 1, "chat.delete changes the content, so rev bumps");
        assert_eq!(kind, "recall", "msgType chat.delete => revision kind recall");
        // Batch 25: the Zalo PC 26.11.12 recall-family strings mark
        // their revisions as recalls too — the whole family codes as
        // type 8 and is_recall_msg recognises exactly it.
        for (mid, marker) in [("m5", "chat.undo"), ("m6", "chat.delete.everyone")] {
            let first = pay(mid, "text", "\"hello\"");
            apply(&conn, &wmsg(mid, "c1", Some("u1"), 1000, 1, Some("hello"), &first, "capture", None))
                .unwrap();
            let undo = pay(mid, marker, "\"\"");
            apply(&conn, &wmsg(mid, "c1", Some("u1"), 1000, 8, None, &undo, "capture", None))
                .unwrap();
            let (rev, kind): (i64, String) = conn
                .query_row(
                    "SELECT rev, (SELECT kind FROM message_revisions WHERE msg_id = ?1)
                     FROM messages WHERE msg_id = ?1",
                    [mid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(rev, 1, "{marker} changes the content, so rev bumps");
            assert_eq!(kind, "recall", "msgType {marker} => revision kind recall");
        }
    }

    #[test]
    fn content_hash_is_key_order_insensitive() {
        // T4: the hash covers msgType + canonical(content); canonical
        // sorts object keys recursively, so field order cannot move it.
        let a = r#"{"msgId":"m","msgType":"chat.photo","content":{"href":"h","params":"{}","thumb":"t"}}"#;
        let b = r#"{"content":{"thumb":"t","params":"{}","href":"h"},"msgType":"chat.photo","msgId":"m"}"#;
        assert_eq!(content_hash(a), content_hash(b));
        assert_ne!(
            content_hash(a),
            content_hash(r#"{"msgId":"m","msgType":"chat.photo","content":{"href":"other"}}"#)
        );
        assert_eq!(content_hash("not json"), None);
    }

    // --- T5/T6: frozen fields + import guard ----------------------------

    #[test]
    fn import_never_overwrites_capture() {
        let conn = db();
        // A capture row with real plaintext…
        let cap = pay("m5", "text", "\"cap-text\"");
        apply(&conn, &wmsg("m5", "c1", Some("u1"), 1000, 1, Some("cap-text"), &cap, "capture", None))
            .unwrap();
        // …then an import row with different text/payload/type: nothing
        // may change (import only fills NULL cells).
        let imp = pay("m5", "text", "\"imp-text\"");
        apply(&conn, &wmsg("m5", "c1", Some("u1"), 1000, 9, Some("imp-text"), &imp, "import", None))
            .unwrap();
        let (payload, text, typ, source, rev): (String, Option<String>, i64, String, i64) = conn
            .query_row(
                "SELECT payload_json, text, type, source, rev FROM messages WHERE msg_id = 'm5'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(payload, cap, "import never replaces the payload");
        assert_eq!(text.as_deref(), Some("cap-text"), "import never replaces text");
        assert_eq!(typ, 1, "import never replaces type");
        assert_eq!(source, "capture");
        assert_eq!(rev, 0);

        // Import into a NULL text cell DOES fill it (the one cell import
        // is allowed to touch).
        let cipher = pay("m6", "text", "\"QUJD\"");
        apply(&conn, &wmsg("m6", "c1", Some("u1"), 1000, 1, None, &cipher, "capture", None)).unwrap();
        let imp2 = pay("m6", "text", "\"imp-text\"");
        apply(&conn, &wmsg("m6", "c1", Some("u1"), 1000, 1, Some("imp-text"), &imp2, "import", None))
            .unwrap();
        let (payload6, text6, source6, rev6): (String, Option<String>, String, i64) = conn
            .query_row(
                "SELECT payload_json, text, source, rev FROM messages WHERE msg_id = 'm6'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(text6.as_deref(), Some("imp-text"), "import fills a NULL text cell");
        assert_eq!(payload6, cipher, "…but never replaces the stored payload");
        assert_eq!(source6, "capture");
        assert_eq!(rev6, 0);
    }

    #[test]
    fn sender_filled_later() {
        let conn = db();
        let p = pay("m7", "text", "\"x\"");
        apply(&conn, &wmsg("m7", "c1", None, 1000, 1, Some("x"), &p, "capture", None)).unwrap();
        let sender: Option<String> = conn
            .query_row("SELECT sender_id FROM messages WHERE msg_id='m7'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sender, None);
        apply(&conn, &wmsg("m7", "c1", Some("u7"), 1000, 1, Some("x"), &p, "capture", None)).unwrap();
        let sender: Option<String> = conn
            .query_row("SELECT sender_id FROM messages WHERE msg_id='m7'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sender.as_deref(), Some("u7"), "a learned uid fills the NULL cell");
        apply(&conn, &wmsg("m7", "c1", Some("u8"), 1000, 1, Some("x"), &p, "capture", None)).unwrap();
        let sender: Option<String> = conn
            .query_row("SELECT sender_id FROM messages WHERE msg_id='m7'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sender.as_deref(), Some("u7"), "sender is frozen once set");
    }

    // --- T7: conversation integrity --------------------------------------

    #[test]
    fn orphan_gets_stub_conv() {
        let conn = db();
        let p = pay("m8", "text", "\"x\"");
        apply(&conn, &wmsg("m8", "cX", Some("u1"), 1000, 1, Some("x"), &p, "capture", None)).unwrap();
        let (ty, unread, last, ts): (i64, i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT type, unread, last_msg_id, last_ts FROM conversations WHERE id='cX'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!((ty, unread), (0, 0), "stub: private type, unread 0");
        assert_eq!(last.as_deref(), Some("m8"));
        assert_eq!(ts, Some(1000));
    }

    #[test]
    fn last_msg_id_by_ts() {
        let conn = db();
        let pa = pay("ma", "text", "\"a\"");
        let pb = pay("mb", "text", "\"b\"");
        apply(&conn, &wmsg("ma", "cY", Some("u1"), 300, 1, Some("a"), &pa, "capture", None)).unwrap();
        apply(&conn, &wmsg("mb", "cY", Some("u1"), 100, 1, Some("b"), &pb, "capture", None)).unwrap();
        let (last, ts): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT last_msg_id, last_ts FROM conversations WHERE id='cY'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(last.as_deref(), Some("ma"), "an older ts must not move the pointer");
        assert_eq!(ts, Some(300));

        // The Conversation arm obeys the same rule (T7).
        apply(&conn, &Write::Conversation {
            id: "cY".into(),
            is_group: false,
            title: None,
            avatar_url: None,
            last_msg_id: Some("mb".into()),
            last_ts: Some(100),
            raw: "{}".into(),
        })
        .unwrap();
        let (last, _): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT last_msg_id, last_ts FROM conversations WHERE id='cY'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(last.as_deref(), Some("ma"), "older Conversation write must not move it");
        // A genuinely newer Conversation write does move it.
        apply(&conn, &Write::Conversation {
            id: "cY".into(),
            is_group: false,
            title: None,
            avatar_url: None,
            last_msg_id: Some("mz".into()),
            last_ts: Some(900),
            raw: "{}".into(),
        })
        .unwrap();
        let (last, ts): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT last_msg_id, last_ts FROM conversations WHERE id='cY'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(last.as_deref(), Some("mz"));
        assert_eq!(ts, Some(900));
    }

    // --- T3: media outcomes applied by the flusher -----------------------

    #[test]
    fn media_done_applies() {
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('m9', 0, 'image', 'https://h/x', 'ref')",
            [],
        )
        .unwrap();
        let rowid: i64 = conn
            .query_row("SELECT rowid FROM attachments", [], |r| r.get(0))
            .unwrap();
        media_done(
            &conn,
            rowid,
            &MediaOutcome::Downloaded {
                path: "ab/cd/effe".into(),
                sha256: "effe".into(),
                size: 42,
            },
        )
        .unwrap();
        let (status, path, sha, size): (String, Option<String>, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT status, local_path, sha256, size FROM attachments WHERE rowid = ?1",
                [rowid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(status, "downloaded");
        assert_eq!(path.as_deref(), Some("ab/cd/effe"));
        assert_eq!(sha.as_deref(), Some("effe"));
        assert_eq!(size, Some(42));
        media_done(&conn, rowid, &MediaOutcome::Failed).unwrap();
        let status: String = conn
            .query_row("SELECT status FROM attachments WHERE rowid = ?1", [rowid], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "failed");
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

    // --- Batch 2: B1/B2 (H1 attachments) + B5 (stub type) ---------------

    #[test]
    fn photo_pick_priority_hdurl_hd_rawurl_href() {
        // Real shape (H1): `params` arrives as a JSON STRING.
        let content = json!({
            "action": 0, "childnumber": 1, "description": "",
            "href": "https://fake-photo-stal.zdn.vn/low.jpg",
            "params": "{\"hd\":\"https://fake-photo-stal.zdn.vn/hd.jpg\",\"rawUrl\":\"https://fake-photo-stal.zdn.vn/raw.jpg\",\"width\":1,\"height\":1}",
            "thumb": "https://fake-photo-stal.zdn.vn/thumb.jpg",
            "title": "", "type": 1
        });
        // hd beats rawUrl and href; exactly ONE url.
        assert_eq!(
            pick_attachments("chat.photo", &content),
            vec![("image", "https://fake-photo-stal.zdn.vn/hd.jpg".to_string())]
        );
        // E2EE shape (KQ1): hdUrl beats hd.
        let e2ee = json!({
            "href": "https://fake-photo-stal.zdn.vn/low.jpg",
            "params": "{\"hdUrl\":\"https://fake-photo-stal.zdn.vn/e2ee-hd.jpg\",\"rawUrl\":\"https://fake-photo-stal.zdn.vn/raw.jpg\",\"rawThumbUrl\":\"https://fake-photo-stal.zdn.vn/rawt.jpg\"}"
        });
        assert_eq!(
            pick_attachments("chat.photo", &e2ee),
            vec![("image", "https://fake-photo-stal.zdn.vn/e2ee-hd.jpg".to_string())]
        );
        // `params` as an OBJECT is accepted too.
        let obj_params = json!({"params": {"hd": "https://fake-photo-stal.zdn.vn/hd2.jpg"}});
        assert_eq!(
            pick_attachments("chat.photo", &obj_params),
            vec![("image", "https://fake-photo-stal.zdn.vn/hd2.jpg".to_string())]
        );
        // Only href -> href; a non-https hd is SKIPPED and href wins.
        assert_eq!(
            pick_attachments("chat.photo", &json!({"href": "https://fake-photo-stal.zdn.vn/only.jpg"})),
            vec![("image", "https://fake-photo-stal.zdn.vn/only.jpg".to_string())]
        );
        assert_eq!(
            pick_attachments("chat.photo", &json!({"params": "{\"hd\":\"ftp://fake/x.jpg\"}", "href": "https://fake-photo-stal.zdn.vn/ok.jpg"})),
            vec![("image", "https://fake-photo-stal.zdn.vn/ok.jpg".to_string())]
        );
        // Non-https href, thumb alone, missing fields, malformed params
        // string, and a plain-string (webchat) content yield NOTHING.
        assert_eq!(pick_attachments("chat.photo", &json!({"href": "http://fake-photo-stal.zdn.vn/insecure.jpg"}), ), Vec::<(&str, String)>::new());
        assert_eq!(pick_attachments("chat.photo", &json!({"thumb": "https://fake-photo-stal.zdn.vn/t.jpg"})), Vec::<(&str, String)>::new(), "thumb alone is never picked");
        assert_eq!(pick_attachments("chat.photo", &json!({})), Vec::<(&str, String)>::new());
        assert_eq!(
            pick_attachments("chat.photo", &json!({"params": "not json", "href": "https://fake-photo-stal.zdn.vn/fallback.jpg"})),
            vec![("image", "https://fake-photo-stal.zdn.vn/fallback.jpg".to_string())],
            "a malformed params string just loses the params keys"
        );
        assert_eq!(pick_attachments("webchat", &json!("plain text")), Vec::<(&str, String)>::new());
    }

    #[test]
    fn media_kinds_pick_their_own_shape() {
        // video (chat.video.msg): href on the dlmd.me CDN shape.
        assert_eq!(
            pick_attachments("chat.video.msg", &json!({"href": "https://fake-video-stal.dlmd.me/v.mp4", "thumb": "https://fake-video-stal.dlmd.me/t.jpg"})),
            vec![("video", "https://fake-video-stal.dlmd.me/v.mp4".to_string())]
        );
        // share.file: href (params carries checksumSha/fileSize, no urls).
        assert_eq!(
            pick_attachments("share.file", &json!({"href": "https://fake-file-stal.dlfl.vn/doc.pdf", "params": "{\"checksumSha\":\"deadbeef\",\"fileSize\":10,\"fileExt\":\"pdf\"}"})),
            vec![("file", "https://fake-file-stal.dlfl.vn/doc.pdf".to_string())]
        );
        // voice: href first; params.url only when href is absent.
        assert_eq!(
            pick_attachments("chat.voice", &json!({"href": "https://fake-voc.dlfl.vn/a.wav", "params": "{\"url\":\"https://fake-voc.dlfl.vn/other.wav\"}"})),
            vec![("voice", "https://fake-voc.dlfl.vn/a.wav".to_string())]
        );
        assert_eq!(
            pick_attachments("chat.voice", &json!({"params": "{\"url\":\"https://fake-voc.dlfl.vn/fallback.wav\"}"})),
            vec![("voice", "https://fake-voc.dlfl.vn/fallback.wav".to_string())]
        );
        // Sticker / recommended (link/call card, NOT media, H1) / gif /
        // doodle / plain text are never downloadable — same for the
        // V1-era spellings of those groups.
        for t in [
            "chat.sticker", "sticker", "chat.recommended", "chat.link", "link", "links",
            "chat.gif", "chat.doodle", "chat.webcontent", "webchat", "text", "notification",
            "something.else",
        ] {
            let content = json!({"href": "https://fake-photo-stal.zdn.vn/never.jpg"});
            assert!(pick_attachments(t, &content).is_empty(), "{t} must yield nothing");
        }
        // Non-https values never survive, for every kind. A non-https
        // href is DROPPED and the https params.url fallback still wins
        // (uniform per-value filtering, same as the photo chain).
        for (t, content) in [
            ("chat.video.msg", json!({"href": "http://fake-video-stal.dlmd.me/v.mp4"})),
            ("share.file", json!({"href": "//fake-file-stal.dlfl.vn/doc.pdf"})),
        ] {
            assert!(pick_attachments(t, &content).is_empty(), "{t} rejects non-https");
        }
        assert_eq!(
            pick_attachments("chat.voice", &json!({"href": "javascript:alert(1)", "params": "{\"url\":\"https://fake-voc.dlfl.vn/x.wav\"}"})),
            vec![("voice", "https://fake-voc.dlfl.vn/x.wav".to_string())]
        );
    }

    #[test]
    fn photo_ref_row_is_upgraded_and_done_rows_untouched() {
        let conn = db();
        // Capture sees only the low-res href.
        let cap = pay("mp", "chat.photo", r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg"}"#);
        apply(&conn, &wmsg("mp", "c1", Some("u1"), 1000, 2, None, &cap, "capture", None)).unwrap();
        let (kind, url, status): (String, String, String) = conn
            .query_row(
                "SELECT kind, url, status FROM attachments WHERE msg_id='mp'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), url.as_str(), status.as_str()),
            ("image", "https://fake-photo-stal.zdn.vn/low.jpg", "ref")
        );
        // The e2ee payload (higher rank) carries hdUrl: the still-ref
        // row IMPROVES in place (KQ1).
        let e2ee = pay(
            "mp",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg","params":"{\"hdUrl\":\"https://fake-photo-stal.zdn.vn/hd.jpg\"}"}"#,
        );
        apply(&conn, &wmsg("mp", "c1", Some("u1"), 1000, 2, None, &e2ee, "e2ee", None)).unwrap();
        let (url, status): (String, String) = conn
            .query_row(
                "SELECT url, status FROM attachments WHERE msg_id='mp'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (url.as_str(), status.as_str()),
            ("https://fake-photo-stal.zdn.vn/hd.jpg", "ref")
        );
        // A lower-rank replay changes nothing (extract only mirrors the
        // STORED payload).
        apply(&conn, &wmsg("mp", "c1", Some("u1"), 1000, 2, None, &cap, "capture", None)).unwrap();
        let url: String = conn
            .query_row("SELECT url FROM attachments WHERE msg_id='mp'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(url, "https://fake-photo-stal.zdn.vn/hd.jpg");
        // Once downloaded, the row is untouchable.
        conn.execute("UPDATE attachments SET status='downloaded' WHERE msg_id='mp'", [])
            .unwrap();
        let e2ee2 = pay(
            "mp",
            "chat.photo",
            r#"{"params":"{\"hdUrl\":\"https://fake-photo-stal.zdn.vn/hd2.jpg\"}"}"#,
        );
        apply(&conn, &wmsg("mp", "c1", Some("u1"), 1000, 2, None, &e2ee2, "e2ee", None)).unwrap();
        let (url, status): (String, String) = conn
            .query_row(
                "SELECT url, status FROM attachments WHERE msg_id='mp'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (url.as_str(), status.as_str()),
            ("https://fake-photo-stal.zdn.vn/hd.jpg", "downloaded"),
            "a downloaded row keeps its url"
        );
        // …and so is a failed one.
        conn.execute("UPDATE attachments SET status='failed' WHERE msg_id='mp'", []).unwrap();
        let e2ee3 = pay(
            "mp",
            "chat.photo",
            r#"{"params":"{\"hdUrl\":\"https://fake-photo-stal.zdn.vn/hd3.jpg\"}"}"#,
        );
        apply(&conn, &wmsg("mp", "c1", Some("u1"), 1000, 2, None, &e2ee3, "e2ee", None)).unwrap();
        let url: String = conn
            .query_row("SELECT url FROM attachments WHERE msg_id='mp'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(url, "https://fake-photo-stal.zdn.vn/hd.jpg", "a failed row keeps its url");
    }

    #[test]
    fn group_message_stub_is_type_1() {
        let conn = db();
        // A KNOWN group message creates the stub as type 1 (B5).
        let p = pay("g1", "webchat", "\"x\"");
        apply(&conn, &wmsg("g1", "cG", Some("u1"), 1000, 1, Some("x"), &p, "capture", Some(true)))
            .unwrap();
        let ty: i64 = conn
            .query_row("SELECT type FROM conversations WHERE id='cG'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ty, 1, "groupMsgs message -> stub type 1");
        // A later 1-1 write on the same conv must NOT flip it to 0:
        // the stub is INSERT OR IGNORE, refinement is the
        // Conversation/Group arm's job.
        apply(&conn, &wmsg("g2", "cG", Some("u1"), 2000, 1, Some("y"), &pay("g2", "webchat", "\"y\""), "capture", None))
            .unwrap();
        let ty: i64 = conn
            .query_row("SELECT type FROM conversations WHERE id='cG'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ty, 1, "INSERT OR IGNORE never touches the existing row");
        // 1-1 and unknown-group (None, the bridge path) messages stub
        // as type 0…
        apply(&conn, &wmsg("g3", "cP", Some("u1"), 3000, 1, Some("z"), &pay("g3", "webchat", "\"z\""), "capture", None))
            .unwrap();
        let ty: i64 = conn
            .query_row("SELECT type FROM conversations WHERE id='cP'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ty, 0);
        // …and a later group message does not rewrite the 0 stub —
        // the Conversation/Group write remains the only refiner.
        apply(&conn, &wmsg("g4", "cP", Some("u1"), 4000, 1, Some("w"), &pay("g4", "webchat", "\"w\""), "capture", Some(true)))
            .unwrap();
        let ty: i64 = conn
            .query_row("SELECT type FROM conversations WHERE id='cP'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ty, 0, "the stub never overwrites; Conversation/Group writes refine");
        // The refiner itself still works.
        apply(&conn, &Write::Conversation {
            id: "cP".into(),
            is_group: true,
            title: None,
            avatar_url: None,
            last_msg_id: None,
            last_ts: None,
            raw: "{}".into(),
        })
        .unwrap();
        let ty: i64 = conn
            .query_row("SELECT type FROM conversations WHERE id='cP'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ty, 1, "Conversation write still refines the type");
    }

    #[test]
    fn media_done_ref_encrypted() {
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('me', 0, 'image', 'https://h/x', 'ref')",
            [],
        )
        .unwrap();
        let rowid: i64 = conn
            .query_row("SELECT rowid FROM attachments", [], |r| r.get(0))
            .unwrap();
        media_done(&conn, rowid, &MediaOutcome::RefEncrypted).unwrap();
        let status: String = conn
            .query_row("SELECT status FROM attachments WHERE rowid = ?1", [rowid], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "ref-encrypted");
    }

    // --- batch 26: M2 Expired outcome + M3 ref-import rows -------------------

    #[test]
    fn media_done_expired() {
        // M2: a gone link (403/404/410) is EXPIRED, not failed — the
        // row keeps its url and is never retried by the live thread.
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('mg', 0, 'image', 'https://h/x', 'ref')",
            [],
        )
        .unwrap();
        let rowid: i64 = conn
            .query_row("SELECT rowid FROM attachments", [], |r| r.get(0))
            .unwrap();
        media_done(&conn, rowid, &MediaOutcome::Expired).unwrap();
        let (status, url): (String, String) = conn
            .query_row(
                "SELECT status, url FROM attachments WHERE rowid = ?1",
                [rowid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "expired");
        assert_eq!(url, "https://h/x", "the url is kept");
    }

    #[test]
    fn import_write_creates_ref_import_rows() {
        // M3: an import-sourced message's attachment starts life as
        // `ref-import` — history the live thread must never pick. The
        // live capture path is unchanged (still 'ref').
        let conn = db();
        let imp = pay(
            "mi",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg","params":"{\"hd\":\"https://fake-photo-stal.zdn.vn/hd.jpg\"}"}"#,
        );
        apply(&conn, &wmsg("mi", "c1", Some("u1"), 1000, 2, None, &imp, "import", None)).unwrap();
        let (kind, url, status): (String, String, String) = conn
            .query_row(
                "SELECT kind, url, status FROM attachments WHERE msg_id='mi'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), url.as_str(), status.as_str()),
            ("image", "https://fake-photo-stal.zdn.vn/hd.jpg", "ref-import")
        );
        // The live capture path is unchanged: same shape, 'ref'.
        let cap = pay(
            "mc",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg"}"#,
        );
        apply(&conn, &wmsg("mc", "c1", Some("u1"), 1000, 2, None, &cap, "capture", None)).unwrap();
        let status: String = conn
            .query_row("SELECT status FROM attachments WHERE msg_id='mc'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "ref");
    }

    #[test]
    fn capture_improves_a_ref_import_url_but_never_its_status() {
        // M3: a live capture delivering the SAME (msg_id, idx) improves
        // the row's url through the shared rule but must not silently
        // upgrade `ref-import` into the live queue.
        let conn = db();
        let imp = pay(
            "mq",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg"}"#,
        );
        apply(&conn, &wmsg("mq", "c1", Some("u1"), 1000, 2, None, &imp, "import", None)).unwrap();
        // A capture (higher rank) arrives carrying the hd url.
        let cap = pay(
            "mq",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/low.jpg","params":"{\"hdUrl\":\"https://fake-photo-stal.zdn.vn/hd.jpg\"}"}"#,
        );
        apply(&conn, &wmsg("mq", "c1", Some("u1"), 1000, 2, None, &cap, "capture", None)).unwrap();
        let (url, status): (String, String) = conn
            .query_row(
                "SELECT url, status FROM attachments WHERE msg_id='mq'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (url.as_str(), status.as_str()),
            ("https://fake-photo-stal.zdn.vn/hd.jpg", "ref-import"),
            "the url improves; the history status stays"
        );
        // Downgraded (lower-rank) writes never touch the row either.
        let imp2 = pay(
            "mq",
            "chat.photo",
            r#"{"href":"https://fake-photo-stal.zdn.vn/other.jpg"}"#,
        );
        apply(&conn, &wmsg("mq", "c1", Some("u1"), 1000, 2, None, &imp2, "import", None)).unwrap();
        let url: String = conn
            .query_row("SELECT url FROM attachments WHERE msg_id='mq'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(url, "https://fake-photo-stal.zdn.vn/hd.jpg");
    }

    #[test]
    fn pick_attachments_fields_names_the_source_field() {
        // M1: the field-name picker picks the SAME urls as the plain
        // picker and names where each came from.
        let content = json!({
            "href": "https://fake-photo-stal.zdn.vn/low.jpg",
            "params": "{\"hd\":\"https://fake-photo-stal.zdn.vn/hd.jpg\",\"rawUrl\":\"https://fake-photo-stal.zdn.vn/raw.jpg\"}"
        });
        assert_eq!(
            pick_attachments_fields("chat.photo", &content),
            vec![(
                "image",
                "https://fake-photo-stal.zdn.vn/hd.jpg".to_string(),
                "params.hd".to_string()
            )]
        );
        assert_eq!(
            pick_attachments("chat.photo", &content),
            vec![("image", "https://fake-photo-stal.zdn.vn/hd.jpg".to_string())],
            "the wrapper keeps the exact old behaviour"
        );
        // Every dispatch names its own field.
        assert_eq!(
            pick_attachments_fields("chat.video.msg", &json!({"href": "https://fake-video-stal.dlmd.me/v.mp4"})),
            vec![("video", "https://fake-video-stal.dlmd.me/v.mp4".to_string(), "href".to_string())]
        );
        assert_eq!(
            pick_attachments_fields("chat.voice", &json!({"params": "{\"url\":\"https://fake-voc.dlfl.vn/a.wav\"}"})),
            vec![("voice", "https://fake-voc.dlfl.vn/a.wav".to_string(), "params.url".to_string())]
        );
        // Nothing picked -> nothing named.
        assert!(pick_attachments_fields("chat.sticker", &content).is_empty());
        assert!(pick_attachments_fields("chat.photo", &json!("plain")).is_empty());
    }
}
