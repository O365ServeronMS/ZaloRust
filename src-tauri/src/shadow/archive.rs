//! Read-only data layer for the "Lưu trữ" (Archive) window — audit
//! §4 Phase 3 item 3.2 (KQ5), batch 11.
//!
//! Every function here is PURE w.r.t. the process: it takes a
//! `&Connection` that the CALLER opened read-only (the archive session
//! in `crate::archive_cmds`, opened with
//! `migrate::sqlcipher::open_with_key_readonly` — which sets
//! `query_only` + the H3 busy timeout — or the plain read-only open
//! for an unencrypted store; NEVER the flusher's connection, A5
//! single-writer). Nothing in this module writes, creates tables or
//! touches settings; the unit tests run on in-memory SQLCipher DBs
//! with FAKE rows.
//!
//! Pagination is KEYSET on `(ts, id)` cursors — no OFFSET on the big
//! tables (a skipped/deleted row would make `OFFSET` pages drift).
//! Order is `ts DESC, id DESC` on both lists (newest first), so the
//! cursor of a page is simply the LAST row of the previous one.
//!
//! H-rule (data through this API, not logs): errors report the SQLite
//! KIND only; previews are capped at 80 chars; the functions never
//! log at all.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::{media, pipeline, search};
use crate::settings::ShadowSettings;

/// One conversation row of the archive list. `last_ts` is the raw
/// column (NULL sorts as 0 — the UI passes `last_ts ?? 0` back as the
/// cursor's ts half).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ConvRow {
    pub id: String,
    /// 0 private, 1 group (schema.rs `conversations.type`).
    #[serde(rename = "type")]
    pub conv_type: i64,
    /// `conversations.title`, else the group name / contact display
    /// name, else the conversation id — never blank.
    pub name: String,
    pub last_ts: Option<i64>,
    /// First 80 chars of the last message's text, or a
    /// `[ảnh]/[video]/[file]/[sticker]…` label from the msg type table
    /// when it has no text.
    pub last_msg_preview: Option<String>,
}

/// One attachment of a message, as the archive needs it. `status` is
/// the raw DB status (`ref` | `downloaded` | `failed` |
/// `ref-encrypted`); `has_local` says a file exists to serve through
/// the media scheme.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AttRow {
    pub idx: i64,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub has_local: bool,
}

/// One message row (newest first). `deleted`/`rev` carry the
/// recalled/deleted rendering flags; attachments are ordered by `idx`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MsgRow {
    pub msg_id: String,
    pub sender_id: Option<String>,
    pub sender_name: Option<String>,
    pub ts: i64,
    /// The `messages.type` code (`normalize::msg_type_code`'s table).
    #[serde(rename = "type")]
    pub kind: i64,
    pub text: Option<String>,
    pub deleted: bool,
    pub rev: i64,
    pub attachments: Vec<AttRow>,
}

/// One search hit: the FTS hit (batch 9 `search::search`) joined back
/// to a full [`MsgRow`] plus the conversation it lives in, so the UI
/// can jump straight to it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SearchRow {
    pub conv_id: String,
    pub conv_name: Option<String>,
    #[serde(flatten)]
    pub msg: MsgRow,
}

/// Cap a page request from the UI (defence in depth; the pure fns
/// trust the caller only this far).
pub fn clamp_page(limit: Option<u32>) -> usize {
    limit.unwrap_or(50).clamp(1, 200) as usize
}

/// The msg-type label table for previews (codes are
/// `normalize::msg_type_code`'s stable numbers). Text kinds (0/1)
/// have no label — a text row without text has nothing to preview.
pub fn preview_label(kind: i64) -> Option<&'static str> {
    match kind {
        2 => Some("[ảnh]"),           // chat.photo
        3 => Some("[sticker]"),       // chat.sticker
        4 => Some("[file]"),          // share.file
        5 => Some("[giọng nói]"),     // chat.voice
        6 => Some("[video]"),         // chat.video.msg
        7 => Some("[liên kết]"),      // chat.recommended / chat.link
        8 => Some("[đã thu hồi]"),    // chat.delete (recall)
        9 => Some("[nội dung web]"),  // chat.webcontent
        10 => Some("[thông báo]"),    // notification
        11 => Some("[gif]"),           // chat.gif
        12 => Some("[doodle]"),       // chat.doodle
        13 => Some("[vị trí]"),       // chat.location.new
        100 => Some("[khác]"),        // genuinely unknown msgType
        _ => None,                    // 0/1: text — no label
    }
}

/// Preview of one message: the first 80 CHARS of its text (chars, not
/// bytes — Vietnamese), else its type label.
pub fn preview_of(text: Option<&str>, kind: i64) -> Option<String> {
    if let Some(t) = text.map(str::trim) {
        if !t.is_empty() {
            return Some(t.chars().take(80).collect());
        }
    }
    preview_label(kind).map(str::to_string)
}

fn sqlite_err(stage: &str, e: &rusqlite::Error) -> String {
    format!("{stage}:{}", pipeline::sqlite_kind(e))
}

/// Conversations, newest first (`COALESCE(last_ts,0) DESC, id DESC`),
/// keyset-paginated on `(ts, id)`. `before` is the cursor of the last
/// row of the previous page; `None` starts at the newest.
pub fn list_conversations(
    conn: &Connection,
    before: Option<&(i64, String)>,
    limit: usize,
) -> Result<Vec<ConvRow>, String> {
    let mut st = conn
        .prepare(
            "SELECT c.id,
                    c.type,
                    COALESCE(NULLIF(c.title, ''),
                             CASE WHEN c.type = 1 THEN g.name ELSE ct.display_name END,
                             c.id) AS name,
                    c.last_ts,
                    m.text,
                    m.type,
                    m.deleted
             FROM conversations c
             LEFT JOIN groups g    ON c.type = 1 AND g.group_id = c.id
             LEFT JOIN contacts ct  ON c.type = 0 AND ct.user_id = c.id
             LEFT JOIN messages m   ON m.msg_id = c.last_msg_id
             WHERE (?1 IS NULL
                    OR (COALESCE(c.last_ts, 0) < ?1
                        OR (COALESCE(c.last_ts, 0) = ?1 AND c.id < ?2)))
             ORDER BY COALESCE(c.last_ts, 0) DESC, c.id DESC
             LIMIT ?3",
        )
        .map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(
            rusqlite::params![
                before.map(|b| b.0),
                before.map(|b| b.1.clone()),
                limit as i64
            ],
            |r| {
                // m.* is NULL when the conversation has no last-message
                // row (LEFT JOIN) — the preview is absent, not an error.
                let text: Option<String> = r.get(4)?;
                let kind: i64 = r.get::<_, Option<i64>>(5)?.unwrap_or(0);
                Ok(ConvRow {
                    id: r.get(0)?,
                    conv_type: r.get(1)?,
                    name: r.get(2)?,
                    last_ts: r.get(3)?,
                    last_msg_preview: preview_of(text.as_deref(), kind),
                })
            },
        )
        .map_err(|e| sqlite_err("query", &e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| sqlite_err("row", &e))?);
    }
    Ok(out)
}

/// Name of one conversation (`title` > group name / contact display
/// name > the id). `None` when the conversation row does not exist.
pub fn conv_name(conn: &Connection, conv_id: &str) -> Result<Option<String>, String> {
    let mut st = conn
        .prepare(
            "SELECT COALESCE(NULLIF(c.title, ''),
                             CASE WHEN c.type = 1 THEN g.name ELSE ct.display_name END,
                             c.id)
             FROM conversations c
             LEFT JOIN groups g   ON c.type = 1 AND g.group_id = c.id
             LEFT JOIN contacts ct ON c.type = 0 AND ct.user_id = c.id
             WHERE c.id = ?1",
        )
        .map_err(|e| sqlite_err("prepare", &e))?;
    let name = match st.query_row(rusqlite::params![conv_id], |r| r.get::<_, String>(0)) {
        Ok(n) => n,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(sqlite_err("row", &e)),
    };
    Ok(Some(name))
}

/// Attachments for a set of message ids, grouped by `msg_id`, ordered
/// by `idx`. One query for a whole page (ids are BOUND parameters —
/// the placeholder list is built by this code, never from input).
fn att_rows(
    conn: &Connection,
    ids: &[String],
) -> Result<HashMap<String, Vec<AttRow>>, String> {
    let mut map: HashMap<String, Vec<AttRow>> = HashMap::new();
    if ids.is_empty() {
        return Ok(map);
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT msg_id, idx, kind, status, local_path
         FROM attachments
         WHERE msg_id IN ({placeholders})
         ORDER BY msg_id, idx"
    );
    let mut st = conn.prepare(&sql).map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                AttRow {
                    idx: r.get(1)?,
                    kind: r.get(2)?,
                    status: r.get(3)?,
                    has_local: r
                        .get::<_, Option<String>>(4)?
                        .is_some_and(|p| !p.is_empty()),
                },
            ))
        })
        .map_err(|e| sqlite_err("query", &e))?;
    for pair in rows {
        let (msg_id, a) = pair.map_err(|e| sqlite_err("row", &e))?;
        map.entry(msg_id).or_default().push(a);
    }
    Ok(map)
}

/// Message rows for a page: `sql` selects the columns of
/// [`map_msg_row`] in order; attachments are attached afterwards.
fn fetch_messages(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<MsgRow>, String> {
    let mut st = conn.prepare(sql).map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(params, map_msg_row)
        .map_err(|e| sqlite_err("query", &e))?;
    let mut msgs = Vec::new();
    for row in rows {
        msgs.push(row.map_err(|e| sqlite_err("row", &e))?);
    }
    fill_attachments(conn, msgs)
}

/// Shared row mapper for `messages` (+ the sender's contact name).
/// Column order: msg_id, sender_id, sender_name, ts, type, text,
/// deleted, rev.
fn map_msg_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MsgRow> {
    Ok(MsgRow {
        msg_id: r.get(0)?,
        sender_id: r.get(1)?,
        sender_name: r.get(2)?,
        ts: r.get(3)?,
        kind: r.get(4)?,
        text: r.get(5)?,
        deleted: r.get::<_, i64>(6)? != 0,
        rev: r.get(7)?,
        attachments: Vec::new(),
    })
}

/// Look up the attachments of every message in one query and attach
/// them (keeping the rows' order).
fn fill_attachments(conn: &Connection, mut msgs: Vec<MsgRow>) -> Result<Vec<MsgRow>, String> {
    if msgs.is_empty() {
        return Ok(msgs);
    }
    let ids: Vec<String> = msgs.iter().map(|m| m.msg_id.clone()).collect();
    let map = att_rows(conn, &ids)?;
    for m in msgs.iter_mut() {
        if let Some(a) = map.get(&m.msg_id) {
            m.attachments = a.clone();
        }
    }
    Ok(msgs)
}

/// Messages of one conversation, newest first (`ts DESC, msg_id DESC`),
/// keyset-paginated on `(ts, msg_id)`.
pub fn list_messages(
    conn: &Connection,
    conv_id: &str,
    before: Option<&(i64, String)>,
    limit: usize,
) -> Result<Vec<MsgRow>, String> {
    fetch_messages(
        conn,
        "SELECT m.msg_id,
                m.sender_id,
                COALESCE(NULLIF(ct.display_name, ''), m.sender_id),
                m.ts,
                m.type,
                m.text,
                m.deleted,
                m.rev
         FROM messages m
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.conv_id = ?1
           AND (?2 IS NULL
                OR (m.ts < ?2 OR (m.ts = ?2 AND m.msg_id < ?3)))
         ORDER BY m.ts DESC, m.msg_id DESC
         LIMIT ?4",
        &[
            &conv_id,
            &before.map(|b| b.0),
            &before.map(|b| b.1.clone()),
            &(limit as i64),
        ],
    )
}

/// Messages by id (any conversation) — the search join-back.
fn msg_rows_by_ids(conn: &Connection, ids: &[String]) -> Result<HashMap<String, MsgRow>, String> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT m.msg_id,
                m.sender_id,
                COALESCE(NULLIF(ct.display_name, ''), m.sender_id),
                m.ts,
                m.type,
                m.text,
                m.deleted,
                m.rev
         FROM messages m
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.msg_id IN ({placeholders})"
    );
    let params: Vec<&dyn rusqlite::ToSql> =
        ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let rows = fetch_messages(conn, &sql, &params)?;
    Ok(rows.into_iter().map(|m| (m.msg_id.clone(), m)).collect())
}

/// Search `messages` (batch 9 `search::search`, diacritics-folded) and
/// join each hit back to its full row + conversation. The hit order
/// is the search's own (bm25, then `ts` DESC).
pub fn search_messages(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchRow>, String> {
    let hits = search::search(conn, query, limit)?;
    let ids: Vec<String> = hits.iter().map(|h| h.msg_id.clone()).collect();
    let rows = msg_rows_by_ids(conn, &ids)?;
    let mut out = Vec::with_capacity(hits.len());
    for h in hits {
        let Some(msg) = rows.get(&h.msg_id) else {
            continue;
        };
        out.push(SearchRow {
            conv_id: h.conv_id.clone(),
            conv_name: conv_name(conn, &h.conv_id)?,
            msg: msg.clone(),
        });
    }
    Ok(out)
}

/// The attachment row the media scheme may serve: only
/// `status='downloaded'` with a non-empty RELATIVE store path. Returns
/// `(rel_path, kind)`.
pub fn attachment_row(
    conn: &Connection,
    msg_id: &str,
    idx: i64,
) -> Option<(String, Option<String>)> {
    conn.query_row(
        "SELECT local_path, kind FROM attachments
         WHERE msg_id = ?1 AND idx = ?2
           AND status = 'downloaded'
           AND local_path IS NOT NULL AND local_path <> ''",
        rusqlite::params![msg_id, idx],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .ok()
}

/// Pure containment guard: `abs` must be a FILE strictly inside the
/// media `root` after BOTH are canonicalized (symlinks/junctions
/// resolve to their target, so a link pointing out of the store
/// fails). `media::resolve_local_path` already fails traversal shapes
/// closed to the root; this is the second, filesystem-level check.
pub fn under_root_file(abs: &Path, root: &Path) -> bool {
    let Ok(canon) = abs.canonicalize() else {
        return false;
    };
    let Ok(root_canon) = root.canonicalize() else {
        return false;
    };
    canon != root_canon && canon.starts_with(&root_canon) && canon.is_file()
}

/// Resolve one downloaded attachment to (absolute path, kind) — the
/// media scheme needs both. Single source of the resolve + guard
/// steps; [`attachment_path`] is the path-only form.
pub fn attachment_media(
    conn: &Connection,
    cfg: &ShadowSettings,
    msg_id: &str,
    idx: i64,
) -> Option<(PathBuf, Option<String>)> {
    let (rel, kind) = attachment_row(conn, msg_id, idx)?;
    let abs = media::resolve_local_path(cfg, &rel);
    under_root_file(&abs, &media::media_store_root(cfg)).then_some((abs, kind))
}

/// Absolute path of one downloaded attachment, resolved through
/// `media::resolve_local_path` (fail-closed on traversal) and verified
/// to stay INSIDE the media root (canonicalize + starts_with). The
/// URL never carries a path — the caller passes ids only.
pub fn attachment_path(
    conn: &Connection,
    cfg: &ShadowSettings,
    msg_id: &str,
    idx: i64,
) -> Option<PathBuf> {
    attachment_media(conn, cfg, msg_id, idx).map(|(path, _)| path)
}

// --- K3: the media protocol's pure half --------------------------------------
//
// The `zrarchive` scheme handler (registered in lib.rs) answers
// `zrarchive://localhost/media/<msg_id>/<idx>` (macOS/Linux) and
// `http://zrarchive.localhost/media/<msg_id>/<idx>` (Windows/WebView2
// maps custom schemes onto http). Both reach the handler with the same
// PATH; only the archive webview is answered, and the file is chosen
// by the DB row — never by the URL.

/// Parse the scheme path `/media/<msg_id>/<idx>` into `(msg_id, idx)`.
/// Strict: one shape, bounded ids, no percent-encoding, no extra
/// segments (no directory listing by construction).
pub fn parse_media_uri(path: &str) -> Option<(String, i64)> {
    let rest = path.strip_prefix("/media/")?;
    let (msg_id, idx) = rest.split_once('/')?;
    // msg ids are server ids (digits in practice); allow a conservative
    // id charset and refuse everything else, including %, slashes and
    // traversal characters.
    if msg_id.is_empty()
        || msg_id.len() > 128
        || !msg_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    // idx: canonical digits only — a leading zero ("00") is refused so
    // the URL form is unique per attachment.
    if idx.is_empty() || (idx.len() > 1 && idx.starts_with('0')) {
        return None;
    }
    let idx: i64 = idx.parse().ok()?;
    if !(0..=64).contains(&idx) {
        return None;
    }
    Some((msg_id.to_string(), idx))
}

/// Largest slice one 206 response carries (a media element re-requests
/// the next window; this bounds memory per request).
pub const SERVE_WINDOW: u64 = 8 * 1024 * 1024;
/// Largest body served when the request has no `Range` header (plain
/// images; a rangeless request for a bigger file gets a 206 head
/// window instead of a lie about the length).
pub const SERVE_FULL: u64 = 32 * 1024 * 1024;

/// Parse ONE `Range: bytes=…` header against a file of `len` bytes →
/// inclusive `(start, end)`, clamped to the file and to
/// [`SERVE_WINDOW`]. `None` for a missing/invalid/unsatisfiable range
/// (the caller distinguishes: no header → 200 head, an unparsable
/// header → 416). Multi-range requests are refused.
pub fn parse_range(header: &str, len: u64) -> Option<(u64, u64)> {
    let spec = header.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        // Suffix form: the last N bytes.
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        if start >= len {
            return None;
        }
        let end = if b.is_empty() {
            len - 1
        } else {
            b.parse::<u64>().ok()?.min(len - 1)
        };
        (start, end)
    };
    if end < start {
        return None;
    }
    Some((start, end.min(start.saturating_add(SERVE_WINDOW - 1))))
}

/// Content type from the magic bytes, kind-aware like the
/// `media::magic_ok` family: a known container header wins IF it
/// matches the row's kind (an image row holding video bytes is a
/// disagreement and is REFUSED — the store already refused such bytes
/// at download time, so this is defence in depth). file/voice/unknown
/// kinds serve whatever container the bytes form, else generic binary.
pub fn content_type_for(kind: Option<&str>, head: &[u8]) -> Option<&'static str> {
    let sniffed = if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("image/png")
    } else if head.starts_with(b"GIF8") {
        Some("image/gif")
    } else if head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP" {
        Some("image/webp")
    } else if head.len() >= 8 && &head[4..8] == b"ftyp" {
        Some("video/mp4")
    } else if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        Some("video/webm")
    } else {
        None
    };
    match kind {
        Some("image") => match sniffed {
            Some(ct) if ct.starts_with("image/") => Some(ct),
            _ => None,
        },
        Some("video") => match sniffed {
            Some(ct) if ct.starts_with("video/") => Some(ct),
            _ => None,
        },
        _ => sniffed.or(Some("application/octet-stream")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema;
    use super::*;
    use crate::migrate::sqlcipher;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    /// Fake conversation row (title/last_msg_id/last_ts optional).
    fn conv(conn: &Connection, id: &str, ty: i64, title: Option<&str>, last_msg: Option<&str>, last_ts: Option<i64>) {
        conn.execute(
            "INSERT INTO conversations (id, type, title, last_msg_id, last_ts, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![id, ty, title, last_msg, last_ts],
        )
        .unwrap();
    }

    /// Fake message row (Vietnamese text fixtures).
    fn msg(conn: &Connection, msg_id: &str, conv_id: &str, sender: Option<&str>, ts: i64, kind: i64, text: Option<&str>) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '{}', 'capture')",
            rusqlite::params![msg_id, conv_id, sender, ts, kind, text],
        )
        .unwrap();
    }

    fn msg_full(conn: &Connection, msg_id: &str, conv_id: &str, sender: Option<&str>, ts: i64, kind: i64, text: Option<&str>, deleted: i64, rev: i64) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source, deleted, rev)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, '{}', 'capture', ?7, ?8)",
            rusqlite::params![msg_id, conv_id, sender, ts, kind, text, deleted, rev],
        )
        .unwrap();
    }

    fn att(conn: &Connection, msg_id: &str, idx: i64, kind: &str, status: &str, local_path: Option<&str>) {
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, local_path, status)
             VALUES (?1, ?2, ?3, 'https://fake-stal.zdn.vn/x', ?4, ?5)",
            rusqlite::params![msg_id, idx, kind, local_path, status],
        )
        .unwrap();
    }

    fn group(conn: &Connection, id: &str, name: &str) {
        conn.execute(
            "INSERT INTO groups (group_id, name) VALUES (?1, ?2)",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    fn contact(conn: &Connection, id: &str, name: &str) {
        conn.execute(
            "INSERT INTO contacts (user_id, display_name) VALUES (?1, ?2)",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    #[test]
    fn page_limits_are_clamped() {
        assert_eq!(clamp_page(None), 50);
        assert_eq!(clamp_page(Some(0)), 1);
        assert_eq!(clamp_page(Some(500)), 200);
        assert_eq!(clamp_page(Some(25)), 25);
    }

    #[test]
    fn previews_are_80_chars_of_text_or_a_type_label() {
        // 100-char Vietnamese text: exactly the first 80 CHARS.
        let long = "chào".repeat(25); // 100 chars
        let p = preview_of(Some(&long), 1).unwrap();
        assert_eq!(p.chars().count(), 80);
        assert_eq!(p, "chào".repeat(20));
        // Media kinds carry their label from the msg type table.
        assert_eq!(preview_of(None, 2).as_deref(), Some("[ảnh]"));
        assert_eq!(preview_of(None, 6).as_deref(), Some("[video]"));
        assert_eq!(preview_of(None, 4).as_deref(), Some("[file]"));
        assert_eq!(preview_of(None, 3).as_deref(), Some("[sticker]"));
        assert_eq!(preview_of(None, 5).as_deref(), Some("[giọng nói]"));
        assert_eq!(preview_of(None, 8).as_deref(), Some("[đã thu hồi]"));
        assert_eq!(preview_of(None, 100).as_deref(), Some("[khác]"));
        // A media message WITH text previews the text.
        assert_eq!(preview_of(Some("xem ảnh nhé"), 2).as_deref(), Some("xem ảnh nhé"));
        // Text kinds have no label; blank text is not a preview.
        assert_eq!(preview_of(None, 1), None);
        assert_eq!(preview_of(Some("   "), 1), None);
    }

    #[test]
    fn conversations_order_by_last_ts_desc_then_id_desc() {
        let conn = db();
        conv(&conn, "c-new", 0, None, Some("m1"), Some(3000));
        conv(&conn, "c-mid", 0, None, Some("m2"), Some(2000));
        conv(&conn, "c-tie-b", 1, None, None, Some(2000)); // same ts as c-mid
        conv(&conn, "c-tie-a", 1, None, None, Some(2000)); // same ts as c-mid
        conv(&conn, "c-none", 0, None, None, None);         // NULL last_ts sorts last
        let ids = |rows: Vec<ConvRow>| rows.into_iter().map(|c| c.id).collect::<Vec<_>>();
        assert_eq!(
            ids(list_conversations(&conn, None, 10).unwrap()),
            vec!["c-new", "c-tie-b", "c-tie-a", "c-mid", "c-none"],
            "newest first, ts ties broken by id DESC, NULL last_ts last"
        );
    }

    #[test]
    fn conversation_keyset_pages_never_duplicate_or_skip() {
        let conn = db();
        // 7 conversations, deliberately with equal timestamps (the
        // id half of the cursor must carry them).
        for i in 0..7 {
            let id = format!("c{i}");
            conv(&conn, &id, 0, None, None, Some(1000));
        }
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<(i64, String)> = None;
        loop {
            let page = list_conversations(&conn, cursor.as_ref(), 3).unwrap();
            if page.is_empty() {
                break;
            }
            let last = page.last().unwrap();
            cursor = Some((last.last_ts.unwrap_or(0), last.id.clone()));
            seen.extend(page.into_iter().map(|c| c.id));
            if seen.len() == 7 {
                break;
            }
        }
        assert_eq!(seen.len(), 7, "every row exactly once");
        assert_eq!(
            std::collections::HashSet::<&str>::from_iter(seen.iter().map(String::as_str)).len(),
            7,
            "no duplicates across pages"
        );
        // And the pages are contiguous: page 2 starts strictly below
        // page 1's cursor (the ordering test pins the full order).
        assert!(seen[0] > seen[1] && seen[1] > seen[2], "id DESC inside a ts tie");
    }

    #[test]
    fn conversation_names_from_title_group_contact_then_id() {
        let conn = db();
        group(&conn, "g1", "Nhóm gia đình");
        contact(&conn, "u1", "Bạn Lan");
        conv(&conn, "g1", 1, None, None, None);        // group name
        conv(&conn, "u1", 0, None, None, None);       // contact display name
        conv(&conn, "g2", 1, Some("Tiêu đề riêng"), None, None); // title wins
        contact(&conn, "u2", "Bạn Hùng");
        conv(&conn, "u2", 0, Some("Tên ghi đè"), None, None);   // title beats contact
        conv(&conn, "u3", 0, None, None, None);       // nothing: the id
        conv(&conn, "g3", 1, None, None, None);       // group without a groups row: the id
        let by_id = |id: &str| {
            list_conversations(&conn, None, 10)
                .unwrap()
                .into_iter()
                .find(|c| c.id == id)
                .unwrap()
                .name
        };
        assert_eq!(by_id("g1"), "Nhóm gia đình");
        assert_eq!(by_id("u1"), "Bạn Lan");
        assert_eq!(by_id("g2"), "Tiêu đề riêng");
        assert_eq!(by_id("u2"), "Tên ghi đè");
        assert_eq!(by_id("u3"), "u3");
        assert_eq!(by_id("g3"), "g3");
        // The single-conversation helper agrees.
        assert_eq!(conv_name(&conn, "g1").unwrap().as_deref(), Some("Nhóm gia đình"));
        assert_eq!(conv_name(&conn, "zz").unwrap(), None);
    }

    #[test]
    fn previews_follow_the_last_message() {
        let conn = db();
        conv(&conn, "c1", 0, None, Some("m-text"), Some(100));
        msg(&conn, "m-text", "c1", Some("u1"), 100, 1, Some("Hẹn gặp lại bạn nhé"));
        conv(&conn, "c2", 0, None, Some("m-photo"), Some(200));
        msg(&conn, "m-photo", "c2", Some("u1"), 200, 2, None);
        conv(&conn, "c3", 0, None, Some("m-old"), Some(50));
        msg(&conn, "m-old", "c3", Some("u1"), 50, 1, Some("tin cũ"));
        msg(&conn, "m-ghost", "c3", Some("u1"), 999, 1, Some("tin không phải cuối"));
        let by_id = |id: &str| {
            list_conversations(&conn, None, 10)
                .unwrap()
                .into_iter()
                .find(|c| c.id == id)
                .unwrap()
                .last_msg_preview
        };
        assert_eq!(by_id("c1").as_deref(), Some("Hẹn gặp lại bạn nhé"));
        assert_eq!(by_id("c2").as_deref(), Some("[ảnh]"));
        // last_msg_id decides, not the newest row in messages.
        assert_eq!(by_id("c3").as_deref(), Some("tin cũ"));
        // A conversation without a last message has no preview.
        conv(&conn, "c4", 0, None, None, None);
        assert_eq!(by_id("c4"), None);
    }

    #[test]
    fn messages_newest_first_with_keyset_flags_and_attachments() {
        let conn = db();
        contact(&conn, "u1", "Bạn Mai");
        msg_full(&conn, "m1", "c1", Some("u1"), 1000, 1, Some("Chào bạn"), 0, 0);
        msg_full(&conn, "m2", "c1", Some("u1"), 2000, 1, Some("Đi ăn không?"), 0, 0);
        msg_full(&conn, "m3", "c1", Some("u1"), 1500, 1, Some("tin nhắn đã thu hồi"), 1, 3);
        msg_full(&conn, "m4", "c1", None, 300, 1, Some("tin mồ côi không người gửi"), 0, 0);
        msg(&conn, "mx", "c2", Some("u1"), 5000, 1, Some("khác hội thoại"));
        att(&conn, "m2", 0, "image", "downloaded", Some("ab/cd/0102"));
        att(&conn, "m2", 1, "video", "ref", None);
        att(&conn, "m3", 0, "file", "failed", None);
        att(&conn, "m4", 0, "voice", "ref-encrypted", None);
        // Newest first, only this conversation.
        let page = list_messages(&conn, "c1", None, 10).unwrap();
        let ids = page.iter().map(|m| m.msg_id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids, vec!["m2", "m3", "m1", "m4"]);
        // Sender names from contacts; the orphan sender falls back to
        // its (missing) sender_id → None.
        assert_eq!(page[0].sender_name.as_deref(), Some("Bạn Mai"));
        assert_eq!(page[3].sender_name, None);
        // Deleted/rev flags surface for the recall rendering.
        assert!(page[1].deleted && page[1].rev == 3);
        assert!(!page[0].deleted && page[0].rev == 0);
        // Attachments grouped per message, ordered by idx.
        assert_eq!(page[0].attachments.len(), 2);
        assert_eq!(page[0].attachments[0],
            AttRow { idx: 0, kind: Some("image".into()), status: Some("downloaded".into()), has_local: true });
        assert_eq!(page[0].attachments[1],
            AttRow { idx: 1, kind: Some("video".into()), status: Some("ref".into()), has_local: false });
        assert_eq!(page[1].attachments[0].status.as_deref(), Some("failed"));
        assert_eq!(page[2].attachments.len(), 0);
        assert_eq!(page[3].attachments[0].status.as_deref(), Some("ref-encrypted"));

        // Keyset pages: 3 rows per page, no dup/skip.
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<(i64, String)> = None;
        loop {
            let p = list_messages(&conn, "c1", cursor.as_ref(), 3).unwrap();
            if p.is_empty() { break; }
            let last = p.last().unwrap();
            cursor = Some((last.ts, last.msg_id.clone()));
            seen.extend(p.into_iter().map(|m| m.msg_id));
            if seen.len() == 4 { break; }
        }
        assert_eq!(seen, vec!["m2", "m3", "m1", "m4"]);
        // The cursor also pages across equal timestamps by msg_id.
        msg(&conn, "m5", "c1", Some("u1"), 2000, 1, Some("cùng thời điểm"));
        let p1 = list_messages(&conn, "c1", None, 1).unwrap();
        assert_eq!(p1[0].msg_id, "m5", "ts DESC, msg_id DESC tie-break");
        let p2 = list_messages(&conn, "c1", Some(&(p1[0].ts, p1[0].msg_id.clone())), 10).unwrap();
        assert!(p2.iter().any(|m| m.msg_id == "m2"), "the ts-equal row is not skipped");
        assert!(!p2.iter().any(|m| m.msg_id == "m5"), "the cursor row is not repeated");
    }

    #[test]
    fn search_joins_full_rows_and_conversation_names() {
        let conn = db();
        group(&conn, "g1", "Nhóm lớp học");
        conv(&conn, "g1", 1, None, None, None);
        msg(&conn, "m1", "g1", Some("u1"), 1000, 1, Some("Hà Nội hôm nay mưa nhiều"));
        msg(&conn, "m2", "g1", Some("u1"), 2000, 1, Some("Sài Gòn nắng"));
        att(&conn, "m1", 0, "image", "downloaded", Some("ab/cd/0102"));
        // Diacritics-insensitive through the batch-9 search.
        let rows = search_messages(&conn, "ha noi", 10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.conv_id, "g1");
        assert_eq!(row.conv_name.as_deref(), Some("Nhóm lớp học"));
        assert_eq!(row.msg.msg_id, "m1");
        assert_eq!(row.msg.text.as_deref(), Some("Hà Nội hôm nay mưa nhiều"));
        assert_eq!(row.msg.attachments.len(), 1, "the full row shape, attachments included");
        // Empty/whitespace queries never touch the index.
        assert!(search_messages(&conn, "   ", 10).unwrap().is_empty());
        // The search limit is honored.
        msg(&conn, "m3", "g1", Some("u1"), 3000, 1, Some("Hà Nội ngày mai"));
        let rows = search_messages(&conn, "hà nội", 1).unwrap();
        assert_eq!(rows.len(), 1, "limit 1 keeps exactly one hit");
    }

    // --- attachment_path: downloaded-only, inside the store, fail-closed ---

    /// A unique scratch dir under the OS temp dir — never the live
    /// media root (same helper contract as media.rs's tests).
    fn scratch() -> PathBuf {
        let uniq = format!(
            "zr-archive-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let d = std::env::temp_dir().join(uniq);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn attachment_path_serves_only_downloaded_files_inside_the_store() {
        let root = scratch();
        let mut cfg = ShadowSettings::default();
        cfg.media_store = Some(root.to_string_lossy().into_owned());
        let conn = db();
        // A real stored file (JPEG magic, the store's own layout).
        let rel = "ab/cd/010203";
        std::fs::create_dir_all(root.join("ab/cd")).unwrap();
        std::fs::write(root.join(rel), [0xFF, 0xD8, 0xFF, 1, 2, 3, 4]).unwrap();
        att(&conn, "m-good", 0, "image", "downloaded", Some(rel));
        att(&conn, "m-ref", 0, "image", "ref", Some(rel));
        att(&conn, "m-failed", 0, "image", "failed", Some(rel));
        att(&conn, "m-enc", 0, "image", "ref-encrypted", Some(rel));
        att(&conn, "m-none", 0, "image", "downloaded", None);
        att(&conn, "m-missing", 0, "image", "downloaded", Some("ab/cd/nope"));

        let p = attachment_path(&conn, &cfg, "m-good", 0).unwrap();
        assert!(p.is_absolute());
        assert!(p.starts_with(&root), "resolved inside the media root");
        assert!(p.ends_with("ab/cd/010203"));
        // Only downloaded rows resolve.
        assert_eq!(attachment_path(&conn, &cfg, "m-ref", 0), None);
        assert_eq!(attachment_path(&conn, &cfg, "m-failed", 0), None);
        assert_eq!(attachment_path(&conn, &cfg, "m-enc", 0), None);
        assert_eq!(attachment_path(&conn, &cfg, "m-none", 0), None);
        // A rel pointing at nothing on disk fails closed.
        assert_eq!(attachment_path(&conn, &cfg, "m-missing", 0), None);
        // Unknown (msg_id, idx) fails closed.
        assert_eq!(attachment_path(&conn, &cfg, "m-good", 1), None);
        assert_eq!(attachment_path(&conn, &cfg, "zz", 0), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn attachment_path_refuses_traversal_absolute_and_other_drive_rels() {
        let root = scratch();
        let mut cfg = ShadowSettings::default();
        cfg.media_store = Some(root.to_string_lossy().into_owned());
        let conn = db();
        // Every shape media::resolve_local_path fails closed on (and
        // the canonicalize + starts_with guard re-checks): the row is
        // 'downloaded' but the stored rel is hostile.
        for (name, rel) in [
            ("t-up", "../outside-secret.jpg"),
            ("t-mid", "ab/../../escape.jpg"),
            ("t-abs", "/abs/secret.jpg"),
            ("t-drive", "D:\\other\\secret.jpg"),
            ("t-drive2", "E:/x/secret.jpg"),
            ("t-empty", ""),
            ("t-dot", "."),
            ("t-back", "ab\\..\\cd"),
        ] {
            att(&conn, name, 0, "image", "downloaded", Some(rel));
            assert_eq!(
                attachment_path(&conn, &cfg, name, 0),
                None,
                "the hostile rel {rel:?} must never resolve"
            );
        }
        // Even when such a file exists OUTSIDE the store.
        let outside = root.parent().unwrap().join("zr-escape-should-not-resolve.jpg");
        std::fs::write(&outside, [0xFF, 0xD8, 0xFF, 9]).unwrap();
        att(&conn, "t-exists", 0, "image", "downloaded", Some("../zr-escape-should-not-resolve.jpg"));
        assert_eq!(attachment_path(&conn, &cfg, "t-exists", 0), None);
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn under_root_file_rejects_the_root_itself_and_directories() {
        let root = scratch();
        std::fs::create_dir_all(root.join("ab")).unwrap();
        std::fs::write(root.join("ab/one.bin"), b"x").unwrap();
        assert!(under_root_file(&root.join("ab/one.bin"), &root), "a file inside is fine");
        assert!(!under_root_file(&root, &root), "the root itself is not a file to serve");
        assert!(!under_root_file(&root.join("nope"), &root), "missing file fails closed");
        assert!(!under_root_file(&root.join("ab"), &root), "a directory is not a file");
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- K3 pure fns: media URL, ranges, content types -----------------------

    #[test]
    fn media_uri_parses_only_the_one_shape() {
        assert_eq!(parse_media_uri("/media/m1/0"), Some(("m1".into(), 0)));
        assert_eq!(parse_media_uri("/media/8506747288934/2"), Some(("8506747288934".into(), 2)));
        for bad in [
            "/", "/media/", "/media/m1", "/media/m1/", "/media/m1/x", "/media/m1/0/x",
            "/media/../ab/0", "/media/m%31/0", "/media/../../default.db/0",
            "/other/m1/0", "/media/m1/-1", "/media/m1/65", "/media/m1/00", "/media//0",
            "media/m1/0", "/media/a b/0", "/media/a?b/0",
        ] {
            assert_eq!(parse_media_uri(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn ranges_parse_clamp_and_refuse() {
        let len = 10_000_000u64; // ~9.5 MB
        // Open-ended and closed forms, clamped to the window.
        assert_eq!(parse_range("bytes=0-", len), Some((0, SERVE_WINDOW - 1)));
        assert_eq!(parse_range("bytes=999-", len), Some((999, 999 + SERVE_WINDOW - 1)));
        assert_eq!(parse_range("bytes=100-200", len), Some((100, 200)));
        // Suffix form: the last N bytes (window-clamped like every
        // other form — the media element asks again for the next part).
        assert_eq!(parse_range("bytes=-500", len), Some((len - 500, len - 1)));
        assert_eq!(parse_range("bytes=-999999999", len), Some((0, SERVE_WINDOW - 1)));
        // A small file: the window clamp cannot exceed it.
        assert_eq!(parse_range("bytes=0-", 100), Some((0, 99)));
        assert_eq!(parse_range("bytes=-40", 100), Some((60, 99)));
        // Unsatisfiable / invalid / multi-range / empty file.
        for bad in ["bytes=100-200", "bytes=-0", "bytes=a-b", "bytes=5-2", "bytes=1-2,5-9", "chunk=0-", "bytes="] {
            assert_eq!(parse_range(bad, 100), None, "{bad:?} at len 100");
        }
        assert_eq!(parse_range("bytes=0-", 0), None);
        // end beyond the file is clamped, not an error.
        assert_eq!(parse_range("bytes=90-1000", 100), Some((90, 99)));
    }

    #[test]
    fn content_types_follow_the_magic_bytes() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0];
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        let gif = b"GIF89a".to_vec();
        let webp = [b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'];
        let mp4 = [0, 0, 0, 0, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'];
        let webm = [0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0];
        let cipher = [0x37, 0x9E, 0x2C, 0xF1, 0, 0, 0, 0];
        assert_eq!(content_type_for(Some("image"), &jpeg), Some("image/jpeg"));
        assert_eq!(content_type_for(Some("image"), &png), Some("image/png"));
        assert_eq!(content_type_for(Some("image"), &gif), Some("image/gif"));
        assert_eq!(content_type_for(Some("image"), &webp), Some("image/webp"));
        assert_eq!(content_type_for(Some("video"), &mp4), Some("video/mp4"));
        assert_eq!(content_type_for(Some("video"), &webm), Some("video/webm"));
        // An image/video row whose bytes fail the sniff is refused…
        assert_eq!(content_type_for(Some("image"), &cipher), None);
        assert_eq!(content_type_for(Some("video"), &cipher), None);
        assert_eq!(content_type_for(Some("video"), &jpeg), None);
        // …but file/voice/unknown kinds serve as generic binary.
        assert_eq!(content_type_for(Some("file"), &cipher), Some("application/octet-stream"));
        assert_eq!(content_type_for(Some("voice"), &cipher), Some("application/octet-stream"));
        assert_eq!(content_type_for(None, &cipher), Some("application/octet-stream"));
    }
}
