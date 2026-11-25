//! Read-only data layer for the "Lưu trữ" (Archive) window — audit
//! §4 Phase 3 item 3.2 (KQ5), batch 11.
//!
//! Every function here is PURE w.r.t. the process: it takes a
//! `&Connection` that the CALLER opened read-only (the archive session
//! in `crate::archive_cmds`, opened in whichever key mode the store's
//! marker says — `migrate::sqlcipher::open_with_key_readonly` (raw) or
//! `open_with_passphrase_readonly` via the remember file (batch 18),
//! both of which set `query_only` + the H3 busy timeout — or the plain
//! read-only open for an unencrypted store; NEVER the flusher's
//! connection, A5 single-writer). Nothing in this module writes,
//! creates tables or touches settings; the unit tests run on in-memory
//! SQLCipher DBs with FAKE rows.
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
    /// Batch 29a M2: `conv_type == 1`.
    pub is_group: bool,
    /// Batch 29a M2: groups only. The largest populated source (batch
    /// 30; was first-populated): `participants` rows,
    /// `groups.members_json` (array length), `groups.raw_json`
    /// `$.totalMember`. `None` for a private chat or when none of
    /// them is populated.
    pub member_count: Option<i64>,
    /// Up to 2 letters for the avatar circle, from `name`.
    pub initials: String,
    /// 0..7, stable per conversation id (avatar colour index).
    pub color_idx: u8,
    /// The last message was sent by the account's own user id.
    pub last_sender_is_self: bool,
    /// Display name of the last message's sender (contacts only —
    /// never a bare id); `None` for self/unknown, so the list shows
    /// "Bạn: …" / "<name>: …" / nothing.
    pub last_sender_name: Option<String>,
    /// `messages.type` of the last message (0 when there is none), so
    /// the list can pick a label with [`preview_label`].
    pub last_kind: i64,
}

/// One attachment of a message, as the archive needs it. `status` is
/// the raw DB status (`ref` | `downloaded` | `failed` |
/// `ref-encrypted` | `expired` (batch 26 M2: the link is gone) |
/// `ref-import` (batch 26 M3: import history the live thread never
/// picks)); `has_local` says a file exists to serve through the media
/// scheme.
///
/// Batch 29a M1: `name`/`ext`/`size` are display-only metadata for
/// kind `file` (the title, a clean lowercase extension, the byte
/// size). No url, path or sha ever crosses to JS.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AttRow {
    pub idx: i64,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub has_local: bool,
    pub name: Option<String>,
    pub ext: Option<String>,
    pub size: Option<i64>,
}

/// The quoted (replied-to) message of a message (batch 29a M1).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct QuoteRow {
    pub sender_name: Option<String>,
    /// First [`QUOTE_PREVIEW_CHARS`] chars of the quoted text.
    pub text_preview: String,
}

/// A link/web-content card, display fields only (batch 29a M1). The
/// full href never crosses to JS — `archive_open_link` re-reads it
/// server-side.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LinkRow {
    pub title: Option<String>,
    pub description_preview: Option<String>,
    /// The host only, lowercased (IDN as punycode).
    pub domain: String,
}

/// One reaction bucket of a message (batch 29a M1): the `rIcon` code
/// (a fixed vocabulary, not user content), its emoji when known and
/// how many users used it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ReactionAgg {
    pub code: String,
    pub emoji: Option<String>,
    pub count: i64,
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
    /// Batch 29a M1: the sender is the account's own user id (see
    /// [`resolve_own`]); false for every row when it is unknown.
    pub is_self: bool,
    /// Up to 2 letters from `sender_name` (`?` when there is no real
    /// name — an id is not a name).
    pub sender_initials: String,
    /// 0..7, stable per `sender_id`.
    pub sender_color: u8,
    /// Kind 100 only: the payload's `$.msgType` when it is on
    /// [`RAW_TYPE_ALLOW`].
    pub raw_type: Option<String>,
    pub quote: Option<QuoteRow>,
    /// Sorted by count descending (ties by code).
    pub reactions: Vec<ReactionAgg>,
    /// Kinds 7 and 9 with an http(s) `href` in the content.
    pub link: Option<LinkRow>,
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
/// Batch 25: the Zalo PC 26.11.12 kinds (`chat.list.action`,
/// `chat.ecard`, `group.poll`, `chat.todo`) join the table; the
/// recall label at 8 now also covers `chat.undo` /
/// `chat.delete.everyone`, and 9 covers `chat.webcontent.v2`.
pub fn preview_label(kind: i64) -> Option<&'static str> {
    match kind {
        2 => Some("[ảnh]"),           // chat.photo
        3 => Some("[sticker]"),       // chat.sticker
        4 => Some("[file]"),          // share.file
        5 => Some("[giọng nói]"),     // chat.voice
        6 => Some("[video]"),         // chat.video.msg
        7 => Some("[liên kết]"),      // chat.recommended / chat.link
        8 => Some("[đã thu hồi]"),    // chat.delete / chat.undo / chat.delete.everyone (recall)
        9 => Some("[nội dung web]"),  // chat.webcontent / chat.webcontent.v2
        10 => Some("[thông báo]"),    // notification
        11 => Some("[gif]"),           // chat.gif
        12 => Some("[doodle]"),       // chat.doodle
        13 => Some("[vị trí]"),       // chat.location.new
        14 => Some("[danh sách]"),    // chat.list.action (batch 25)
        15 => Some("[thiệp]"),         // chat.ecard (batch 25)
        16 => Some("[bình chọn]"),    // group.poll (batch 25)
        17 => Some("[to-do]"),         // chat.todo (batch 25)
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

// --- batch 29a: pure display helpers -------------------------------------------

/// Quote previews are cut to this many chars (M1).
pub const QUOTE_PREVIEW_CHARS: usize = 120;
/// Link title / description previews are cut to this many chars (M1).
pub const LINK_TEXT_CHARS: usize = 200;
/// The longest save-dialog default file name (M5).
pub const SAVE_NAME_MAX: usize = 120;

/// `msgType` strings the UI may be told about for a kind-100 row
/// (M1 `raw_type`). Deliberately SHORT and derived only from the
/// repo's own docs, never from data: `docs/import-mapping.md` §1g
/// names exactly two Desktop-local info rows the source gives no wire
/// string (`-4` MSG_INFO, `-1909` MSG_INFO_CHAT) which the apply's
/// `--unmapped-as-raw` path stores as kind 100 with the raw code
/// string as `msgType`. No call-type wire string is named anywhere in
/// the repo's docs or normalize tables, so none is invented here —
/// extend this list when one is documented.
pub const RAW_TYPE_ALLOW: &[&str] = &["-4", "-1909"];

/// Truncate to at most `n` CHARS (never splits a code point).
pub fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Avatar initials: the first letter/digit of the first and of the
/// last word, uppercased (Unicode-aware); one word gives one letter; a
/// name with no letter or digit gives `?`.
pub fn initials_of(name: &str) -> String {
    let letter = |w: &str| {
        w.chars()
            .find(|c| c.is_alphanumeric())
            .and_then(|c| c.to_uppercase().next())
    };
    let letters: Vec<char> = name.split_whitespace().filter_map(letter).collect();
    match letters.as_slice() {
        [] => "?".to_string(),
        [one] => one.to_string(),
        [first, .., last] => format!("{first}{last}"),
    }
}

/// A stable avatar colour index 0..7 for an id (FNV-1a 64 — fixed
/// constants, so the colour never changes between runs or versions).
pub fn color_index(key: &str) -> u8 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h % 8) as u8
}

/// A clean file extension: one optional leading dot, then 1..=8 chars
/// of `[A-Za-z0-9]`, lowercased. Anything else (a separator, a dash, a
/// space, too long, empty) is refused rather than "repaired".
pub fn sanitize_ext(raw: &str) -> Option<String> {
    let e = raw.trim().strip_prefix('.').unwrap_or(raw.trim());
    if e.is_empty() || e.len() > 8 || !e.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(e.to_ascii_lowercase())
}

/// The extension of a file name (`a.tar.gz` → `gz`), sanitised.
fn ext_of_name(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    sanitize_ext(ext)
}

/// Parse an `http`/`https` URL; every other scheme (`javascript:`,
/// `file:`, `data:`, `mailto:` …), a relative string or a host-less URL
/// is refused.
pub fn http_url(href: &str) -> Option<tauri::Url> {
    let u = tauri::Url::parse(href.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    if u.host_str().map_or(true, str::is_empty) {
        return None;
    }
    Some(u)
}

/// The host of an http(s) URL, lowercased — no userinfo, no port, no
/// path. An IDN host comes out as punycode (what the browser would
/// really connect to, and the safe form to display).
pub fn domain_of(href: &str) -> Option<String> {
    let u = http_url(href)?;
    Some(u.host_str()?.to_ascii_lowercase())
}

/// Characters a Windows file name cannot hold become `_`.
fn is_reserved_fs_char(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

/// A safe default file name for the save dialog: path separators and
/// control characters are REMOVED (a name can never carry a
/// directory), the other Windows-reserved characters become `_`,
/// surrounding spaces/dots go, a reserved device name gets a `_`
/// prefix, and the result is cut to [`SAVE_NAME_MAX`] chars keeping a
/// short extension. May return an empty string (the caller falls back
/// to a generated name).
pub fn sanitize_file_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .map(|c| if is_reserved_fs_char(c) { '_' } else { c })
        .collect();
    let trim = |s: &str| s.trim_matches(|c: char| c == ' ' || c == '.').to_string();
    let mut s = trim(&cleaned);
    if s.chars().count() > SAVE_NAME_MAX {
        // Keep a short extension; cut the stem.
        let keep_ext = s
            .rsplit_once('.')
            .filter(|(stem, ext)| !stem.is_empty() && ext.chars().count() <= 8)
            .map(|(_, ext)| format!(".{ext}"));
        s = match keep_ext {
            Some(ext) => {
                let stem_len = SAVE_NAME_MAX.saturating_sub(ext.chars().count());
                let stem = s.rsplit_once('.').map(|(a, _)| a).unwrap_or(&s);
                format!("{}{ext}", truncate_chars(stem, stem_len))
            }
            None => truncate_chars(&s, SAVE_NAME_MAX),
        };
        s = trim(&s);
    }
    let stem_upper = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem_upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem_upper.len() == 4
            && (stem_upper.starts_with("COM") || stem_upper.starts_with("LPT"))
            && stem_upper.as_bytes()[3].is_ascii_digit());
    if reserved {
        s.insert(0, '_');
    }
    s
}

/// The save dialog's default name: the stored file name, sanitised,
/// else `zalo-<kind>-<ts>[.<ext>]`.
pub fn default_save_name(
    name: Option<&str>,
    kind: Option<&str>,
    ts: i64,
    ext: Option<&str>,
) -> String {
    if let Some(n) = name.map(sanitize_file_name).filter(|n| !n.is_empty()) {
        return n;
    }
    let kind = match kind {
        Some(k) if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric()) => k,
        _ => "file",
    };
    match ext.and_then(sanitize_ext) {
        Some(e) => format!("zalo-{kind}-{ts}.{e}"),
        None => format!("zalo-{kind}-{ts}"),
    }
}

/// A file extension for stored bytes (for the generated save name),
/// from the same magic-byte sniff the media scheme uses.
pub fn ext_for_head(kind: Option<&str>, head: &[u8]) -> Option<&'static str> {
    match content_type_for(kind, head)? {
        "image/jpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/jxl" => Some("jxl"),
        "video/mp4" => Some("mp4"),
        "video/webm" => Some("webm"),
        _ => None,
    }
}

/// Reaction codes (`reactions.emoji` holds Zalo's `rIcon` text codes,
/// not Unicode): `(code, emoji, name)`. Ported from zca-js
/// `src/models/Reaction.ts` (RFS-ADRENO/zca-js, MIT License).
pub const REACTION_CODES: &[(&str, &str, &str)] = &[
    ("/-heart", "❤️", "heart"),
    ("/-strong", "👍", "like"),
    (":>", "😆", "haha"),
    (":o", "😮", "wow"),
    (":-((", "😢", "cry"),
    (":-h", "😡", "angry"),
    (":-*", "😘", "kiss"),
    (":')", "😂", "tears_of_joy"),
    ("/-shit", "💩", "shit"),
    ("/-rose", "🌹", "rose"),
    ("/-break", "💔", "broken_heart"),
    ("/-weak", "👎", "weak"),
    (";xx", "😍", "heart_eyes"),
    (";-/", "😕", "confused"),
    (";-)", "😉", "wink"),
    ("/-fade", "🌆", "fade"),
    ("/-li", "☀️", "sun"),
    ("/-bd", "🎂", "birthday"),
    ("/-bome", "💣", "bomb"),
    ("/-ok", "👌", "ok"),
    ("/-v", "✌️", "peace"),
    ("/-thanks", "🙏", "thanks"),
    ("/-punch", "👊", "punch"),
    ("/-share", "🔗", "share"),
    ("_()_", "🙏", "pray"),
    ("/-no", "🙅", "no"),
    ("/-bad", "👎", "bad"),
    ("/-loveu", "🥰", "love_you"),
    ("--b", "😓", "sweat"),
    (":((", "😭", "sob"),
    ("x-)", "😎", "cool"),
    ("8-)", "🤓", "nerd"),
    (";-d", "😁", "grin"),
    ("b-)", "😎", "cool_b"),
    (":--|", "😐", "neutral"),
    ("p-(", "😞", "disappointed"),
    (":-bye", "👋", "bye"),
    ("|-)", "😴", "sleepy"),
    (":wipe", "😅", "wipe"),
    (":-dig", "🤔", "thinking"),
    ("&-(", "😧", "anguished"),
    (":handclap", "👏", "clap"),
    (">-|", "😠", "mad"),
    (";-x", "🤐", "zipper_mouth"),
    (":-o", "😲", "astonished"),
    (";-s", "😳", "flushed"),
    (";-a", "😨", "fearful"),
    (":-<", "☹️", "frown"),
    (":))", "😄", "smile"),
    ("$-)", "🤑", "money_mouth"),
    ("/-beer", "🍺", "beer"),
];

/// The emoji of a reaction code, `None` for an unknown one.
pub fn reaction_emoji(code: &str) -> Option<&'static str> {
    REACTION_CODES
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, e, _)| *e)
}

/// Aggregate `(code, user count)` buckets: an empty code is zca-js's
/// "reaction removed" marker and is dropped, unknown codes keep
/// `emoji: None`; sorted by count descending, ties by code.
pub fn aggregate_reactions(buckets: Vec<(String, i64)>) -> Vec<ReactionAgg> {
    let mut merged: HashMap<String, i64> = HashMap::new();
    for (code, n) in buckets {
        if code.trim().is_empty() || n <= 0 {
            continue;
        }
        *merged.entry(code).or_insert(0) += n;
    }
    let mut out: Vec<ReactionAgg> = merged
        .into_iter()
        .map(|(code, count)| ReactionAgg {
            emoji: reaction_emoji(&code).map(str::to_string),
            code,
            count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    out
}

/// The own user id for `is_self` — ONE source, the one the normalizer
/// and flusher use: the `accounts` row (seeded from the effective own
/// uid, `shadow::account::upsert_account`) when it is the only row;
/// when the table is empty or ambiguous, `settings.shadow.own_uid`
/// (`settings_uid`) if it has a valid uid shape (and, with several
/// rows, names one of them). Anything else: unknown (`None`).
pub fn resolve_own(db_ids: &[String], settings_uid: Option<&str>) -> Option<String> {
    if let [only] = db_ids {
        return Some(only.clone());
    }
    let s = settings_uid.filter(|s| super::account::valid_uid(s))?;
    if db_ids.is_empty() || db_ids.iter().any(|i| i == s) {
        Some(s.to_string())
    } else {
        None
    }
}

/// The `accounts.id` values (at most 3 are read — enough to tell
/// "one" from "ambiguous").
pub fn account_ids(conn: &Connection) -> Result<Vec<String>, String> {
    let mut st = conn
        .prepare("SELECT id FROM accounts LIMIT 3")
        .map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| sqlite_err("query", &e))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| sqlite_err("row", &e))?);
    }
    Ok(out)
}

/// What the display layer reads out of one message's `payload_json`
/// (capture and import share the wire shape: `content` is an object —
/// or a JSON text of one — `params` is a JSON string or an object,
/// `quote` is a top-level object). NOT serialisable: `href` stays in
/// Rust.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PayloadInfo {
    /// `$.msgType`, only when on [`RAW_TYPE_ALLOW`].
    pub raw_type: Option<String>,
    pub quote_owner: Option<String>,
    pub quote_from: Option<String>,
    /// `None` = no quote; `Some("")` = a quote with no text.
    pub quote_text: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub href: Option<String>,
    pub file_ext: Option<String>,
    pub file_size: Option<i64>,
}

fn json_obj_of(v: &serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
    match v {
        serde_json::Value::Object(o) => Some(o.clone()),
        serde_json::Value::String(s) if s.trim_start().starts_with('{') => {
            match serde_json::from_str::<serde_json::Value>(s).ok()? {
                serde_json::Value::Object(o) => Some(o),
                _ => None,
            }
        }
        _ => None,
    }
}

fn nonblank(v: Option<&serde_json::Value>) -> Option<String> {
    match v {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn size_of(v: Option<&serde_json::Value>) -> Option<i64> {
    let n = match v? {
        serde_json::Value::Number(n) => n.as_i64()?,
        serde_json::Value::String(s) => s.trim().parse::<i64>().ok()?,
        _ => return None,
    };
    (n >= 0).then_some(n)
}

/// Parse one `payload_json` for the display fields. Never panics and
/// never returns a value for malformed JSON (an empty [`PayloadInfo`]).
pub fn parse_payload(payload: &str) -> PayloadInfo {
    let mut info = PayloadInfo::default();
    let Ok(serde_json::Value::Object(root)) = serde_json::from_str::<serde_json::Value>(payload)
    else {
        return info;
    };
    info.raw_type = root
        .get("msgType")
        .and_then(serde_json::Value::as_str)
        .filter(|t| RAW_TYPE_ALLOW.contains(t))
        .map(str::to_string);
    if let Some(q) = root.get("quote").and_then(json_obj_of) {
        let msg = nonblank(q.get("msg"));
        let has_attach = nonblank(q.get("attach")).is_some();
        let from = nonblank(q.get("fromD"));
        let owner = nonblank(q.get("ownerId"));
        if msg.is_some() || has_attach || from.is_some() || owner.is_some() {
            info.quote_text = Some(match msg {
                Some(m) => truncate_chars(&m, QUOTE_PREVIEW_CHARS),
                None if has_attach => "[đính kèm]".to_string(),
                None => String::new(),
            });
            info.quote_from = from;
            info.quote_owner = owner;
        }
    }
    if let Some(c) = root.get("content").and_then(json_obj_of) {
        info.title = nonblank(c.get("title"));
        info.description = nonblank(c.get("description"));
        info.href = nonblank(c.get("href"));
        if let Some(p) = c.get("params").and_then(json_obj_of) {
            info.file_ext = p
                .get("fileExt")
                .and_then(serde_json::Value::as_str)
                .and_then(sanitize_ext);
            info.file_size = size_of(p.get("fileSize"));
        }
    }
    info
}

/// The `LinkRow` of a kind-7/9 message, if its content has an http(s)
/// href.
fn link_of(kind: i64, info: &PayloadInfo) -> Option<LinkRow> {
    if !matches!(kind, 7 | 9) {
        return None;
    }
    let domain = domain_of(info.href.as_deref()?)?;
    Some(LinkRow {
        title: info.title.as_deref().map(|t| truncate_chars(t, LINK_TEXT_CHARS)),
        description_preview: info
            .description
            .as_deref()
            .map(|t| truncate_chars(t, LINK_TEXT_CHARS)),
        domain,
    })
}

/// Name and (clean) extension of a file message from its payload: the
/// title, and `params.fileExt` else the title's own extension.
fn file_meta(info: &PayloadInfo) -> (Option<String>, Option<String>) {
    let name = info.title.as_deref().map(|t| truncate_chars(t, LINK_TEXT_CHARS));
    let ext = info
        .file_ext
        .clone()
        .or_else(|| info.title.as_deref().and_then(ext_of_name));
    (name, ext)
}

// --- conversations ---------------------------------------------------------------

/// Member count: the LARGEST populated source among `participants`
/// rows, `groups.members_json` (array length) and `groups.raw_json`
/// `$.totalMember`. Groups only.
///
/// Batch 30: this used to take the first populated source
/// (`participants` first). Group events and member lists now write
/// PARTIAL `participants` rows (a join of 2 people into a 50-member
/// group), and a partial roster must not shrink the count a full
/// snapshot (`totalMember` / `members_json`) already gave; when the
/// roster really is the biggest source it still wins.
fn member_count_of(
    is_group: bool,
    participants: i64,
    members_json: Option<i64>,
    total_member: Option<i64>,
) -> Option<i64> {
    if !is_group {
        return None;
    }
    [Some(participants), members_json, total_member]
        .into_iter()
        .flatten()
        .filter(|n| *n > 0)
        .max()
}

/// SQL: the member-count inputs of a conversation `c` joined with
/// `groups g` (JSON functions guarded by `json_valid`, so malformed
/// text is NULL, never an error for the whole query).
const MEMBER_COLS_SQL: &str = "(SELECT COUNT(*) FROM participants p WHERE p.conv_id = c.id),
                    CASE WHEN c.type = 1 AND json_valid(g.members_json)
                         THEN json_array_length(g.members_json) END,
                    CASE WHEN c.type = 1 AND json_valid(g.raw_json)
                         THEN CAST(json_extract(g.raw_json, '$.totalMember') AS INTEGER) END";

/// Conversations, newest first (`COALESCE(last_ts,0) DESC, id DESC`),
/// keyset-paginated on `(ts, id)`. `before` is the cursor of the last
/// row of the previous page; `None` starts at the newest. `own` is the
/// own user id ([`resolve_own`]) for `last_sender_is_self`.
pub fn list_conversations(
    conn: &Connection,
    own: Option<&str>,
    before: Option<&(i64, String)>,
    limit: usize,
) -> Result<Vec<ConvRow>, String> {
    let sql = format!(
        "SELECT c.id,
                    c.type,
                    COALESCE(NULLIF(c.title, ''),
                             CASE WHEN c.type = 1 THEN g.name ELSE ct.display_name END,
                             c.id) AS name,
                    c.last_ts,
                    m.text,
                    m.type,
                    m.deleted,
                    m.sender_id,
                    NULLIF(lc.display_name, ''),
                    {MEMBER_COLS_SQL}
             FROM conversations c
             LEFT JOIN groups g    ON c.type = 1 AND g.group_id = c.id
             LEFT JOIN contacts ct  ON c.type = 0 AND ct.user_id = c.id
             LEFT JOIN messages m   ON m.msg_id = c.last_msg_id
             LEFT JOIN contacts lc  ON lc.user_id = m.sender_id
             WHERE (?1 IS NULL
                    OR (COALESCE(c.last_ts, 0) < ?1
                        OR (COALESCE(c.last_ts, 0) = ?1 AND c.id < ?2)))
             ORDER BY COALESCE(c.last_ts, 0) DESC, c.id DESC
             LIMIT ?3"
    );
    let mut st = conn.prepare(&sql).map_err(|e| sqlite_err("prepare", &e))?;
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
                let id: String = r.get(0)?;
                let conv_type: i64 = r.get(1)?;
                let name: String = r.get(2)?;
                let last_sender: Option<String> = r.get(7)?;
                let last_is_self = match (own, last_sender.as_deref()) {
                    (Some(o), Some(s)) => o == s,
                    _ => false,
                };
                let is_group = conv_type == 1;
                Ok(ConvRow {
                    initials: initials_of(&name),
                    color_idx: color_index(&id),
                    last_msg_preview: preview_of(text.as_deref(), kind),
                    is_group,
                    member_count: member_count_of(
                        is_group,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                    ),
                    last_sender_is_self: last_is_self,
                    last_sender_name: if last_is_self { None } else { r.get(8)? },
                    last_kind: kind,
                    id,
                    conv_type,
                    name,
                    last_ts: r.get(3)?,
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

/// Header facts of one conversation (batch 29a M4).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ConvInfo {
    pub name: String,
    pub is_group: bool,
    pub member_count: Option<i64>,
    pub initials: String,
    pub color_idx: u8,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub msg_count: i64,
}

/// [`ConvInfo`] of one conversation; `None` when it does not exist.
/// `msg_count`/`first_ts`/`last_ts` come from `messages`
/// (`idx_messages_conv_ts` range of this conversation only).
pub fn conv_info(conn: &Connection, conv_id: &str) -> Result<Option<ConvInfo>, String> {
    let sql = format!(
        "SELECT c.type,
                    COALESCE(NULLIF(c.title, ''),
                             CASE WHEN c.type = 1 THEN g.name ELSE ct.display_name END,
                             c.id),
                    {MEMBER_COLS_SQL}
             FROM conversations c
             LEFT JOIN groups g   ON c.type = 1 AND g.group_id = c.id
             LEFT JOIN contacts ct ON c.type = 0 AND ct.user_id = c.id
             WHERE c.id = ?1"
    );
    let head = conn.query_row(&sql, rusqlite::params![conv_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<i64>>(4)?,
        ))
    });
    let (conv_type, name, participants, members_json, total) = match head {
        Ok(h) => h,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(sqlite_err("row", &e)),
    };
    let (first_ts, last_ts, msg_count) = conn
        .query_row(
            "SELECT MIN(ts), MAX(ts), COUNT(*) FROM messages WHERE conv_id = ?1",
            rusqlite::params![conv_id],
            |r| {
                Ok((
                    r.get::<_, Option<i64>>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|e| sqlite_err("row", &e))?;
    let is_group = conv_type == 1;
    Ok(Some(ConvInfo {
        initials: initials_of(&name),
        color_idx: color_index(conv_id),
        name,
        is_group,
        member_count: member_count_of(is_group, participants, members_json, total),
        first_ts,
        last_ts,
        msg_count,
    }))
}

// --- messages --------------------------------------------------------------------

/// Attachments for a set of message ids, grouped by `msg_id`, ordered
/// by `idx`. One query for a whole page (ids are BOUND parameters —
/// the placeholder list is built by this code, never from input).
/// `size` is the row's own size, only for a downloaded file.
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
        "SELECT msg_id, idx, kind, status, local_path, size
         FROM attachments
         WHERE msg_id IN ({placeholders})
         ORDER BY msg_id, idx"
    );
    let mut st = conn.prepare(&sql).map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
            let status: Option<String> = r.get(3)?;
            let size: Option<i64> = r.get(5)?;
            Ok((
                r.get::<_, String>(0)?,
                AttRow {
                    idx: r.get(1)?,
                    kind: r.get(2)?,
                    has_local: r
                        .get::<_, Option<String>>(4)?
                        .is_some_and(|p| !p.is_empty()),
                    size: if status.as_deref() == Some("downloaded") {
                        size.filter(|n| *n >= 0)
                    } else {
                        None
                    },
                    status,
                    name: None,
                    ext: None,
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

/// Reactions of a page's messages in ONE query: `(msg_id, code)`
/// buckets with their user counts, removed (empty) codes excluded.
fn reaction_rows(
    conn: &Connection,
    ids: &[String],
) -> Result<HashMap<String, Vec<ReactionAgg>>, String> {
    let mut buckets: HashMap<String, Vec<(String, i64)>> = HashMap::new();
    if !ids.is_empty() {
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT msg_id, emoji, COUNT(*)
             FROM reactions
             WHERE msg_id IN ({placeholders}) AND emoji <> ''
             GROUP BY msg_id, emoji"
        );
        let mut st = conn.prepare(&sql).map_err(|e| sqlite_err("prepare", &e))?;
        let rows = st
            .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })
            .map_err(|e| sqlite_err("query", &e))?;
        for row in rows {
            let (msg_id, code, n) = row.map_err(|e| sqlite_err("row", &e))?;
            buckets.entry(msg_id).or_default().push((code, n));
        }
    }
    Ok(buckets
        .into_iter()
        .map(|(k, v)| (k, aggregate_reactions(v)))
        .collect())
}

/// Contact display names for a set of user ids, one query (ids are
/// bound parameters).
fn contact_names(conn: &Connection, ids: &[String]) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    if ids.is_empty() {
        return Ok(map);
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT user_id, display_name FROM contacts
         WHERE user_id IN ({placeholders}) AND display_name <> ''"
    );
    let mut st = conn.prepare(&sql).map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|e| sqlite_err("query", &e))?;
    for row in rows {
        let (id, name) = row.map_err(|e| sqlite_err("row", &e))?;
        map.insert(id, name);
    }
    Ok(map)
}

/// The columns of [`map_msg_row`], in order. `payload_json` is only
/// selected for the rows that need it (file/link/web-content/unknown
/// kinds, or any row carrying a quote) — a plain text row never drags
/// its payload through the page.
const MSG_COLS_SQL: &str = "m.msg_id,
                m.sender_id,
                COALESCE(NULLIF(ct.display_name, ''), m.sender_id),
                m.ts,
                m.type,
                m.text,
                m.deleted,
                m.rev,
                CASE WHEN m.type IN (4, 7, 9, 100)
                       OR instr(m.payload_json, '\"quote\"') > 0
                     THEN m.payload_json END";

/// A mapped row plus the payload it may need (display fields are read
/// from it once the page's side tables are loaded).
struct RawMsg {
    row: MsgRow,
    payload: Option<String>,
}

/// Message rows for a page: `sql` selects the columns of
/// [`map_msg_row`] in order; attachments, reactions, quotes and links
/// are attached afterwards (one query per side table per page).
fn fetch_messages(
    conn: &Connection,
    own: Option<&str>,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<MsgRow>, String> {
    let mut st = conn.prepare(sql).map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(params, |r| map_msg_row(r, own))
        .map_err(|e| sqlite_err("query", &e))?;
    let mut msgs = Vec::new();
    for row in rows {
        msgs.push(row.map_err(|e| sqlite_err("row", &e))?);
    }
    enrich(conn, msgs)
}

/// Shared row mapper for `messages` (+ the sender's contact name).
/// Column order: msg_id, sender_id, sender_name, ts, type, text,
/// deleted, rev, payload (see [`MSG_COLS_SQL`]).
fn map_msg_row(r: &rusqlite::Row<'_>, own: Option<&str>) -> rusqlite::Result<RawMsg> {
    let sender_id: Option<String> = r.get(1)?;
    let sender_name: Option<String> = r.get(2)?;
    let is_self = matches!((own, sender_id.as_deref()), (Some(o), Some(s)) if o == s);
    // An id is not a name: no real name → `?` initials.
    let real_name = sender_name
        .as_deref()
        .filter(|n| Some(*n) != sender_id.as_deref());
    Ok(RawMsg {
        row: MsgRow {
            msg_id: r.get(0)?,
            sender_initials: real_name.map_or_else(|| "?".to_string(), initials_of),
            sender_color: color_index(sender_id.as_deref().unwrap_or("")),
            sender_id,
            sender_name,
            ts: r.get(3)?,
            kind: r.get(4)?,
            text: r.get(5)?,
            deleted: r.get::<_, i64>(6)? != 0,
            rev: r.get(7)?,
            attachments: Vec::new(),
            is_self,
            raw_type: None,
            quote: None,
            reactions: Vec::new(),
            link: None,
        },
        payload: r.get(8)?,
    })
}

/// Attach the side tables to a page of mapped rows: attachments (with
/// the file name/ext/size), reactions (one aggregate query), the quote
/// (with its sender's contact name, one query) and the link card.
fn enrich(conn: &Connection, raws: Vec<RawMsg>) -> Result<Vec<MsgRow>, String> {
    if raws.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = raws.iter().map(|m| m.row.msg_id.clone()).collect();
    let mut atts = att_rows(conn, &ids)?;
    let mut reactions = reaction_rows(conn, &ids)?;
    let infos: Vec<Option<PayloadInfo>> = raws
        .iter()
        .map(|m| m.payload.as_deref().map(parse_payload))
        .collect();
    // Quote owners without a `fromD`: resolve through contacts, once.
    let mut owners: Vec<String> = infos
        .iter()
        .flatten()
        .filter(|i| i.quote_from.is_none())
        .filter_map(|i| i.quote_owner.clone())
        .collect();
    owners.sort();
    owners.dedup();
    let names = contact_names(conn, &owners)?;
    let mut out = Vec::with_capacity(raws.len());
    for (raw, info) in raws.into_iter().zip(infos) {
        let mut row = raw.row;
        row.attachments = atts.remove(&row.msg_id).unwrap_or_default();
        row.reactions = reactions.remove(&row.msg_id).unwrap_or_default();
        if let Some(info) = info {
            if row.kind == 100 {
                row.raw_type = info.raw_type.clone();
            }
            if let Some(text) = info.quote_text.clone() {
                row.quote = Some(QuoteRow {
                    sender_name: info
                        .quote_from
                        .clone()
                        .or_else(|| info.quote_owner.as_ref().and_then(|o| names.get(o).cloned())),
                    text_preview: text,
                });
            }
            row.link = link_of(row.kind, &info);
            if row.attachments.iter().any(|a| a.kind.as_deref() == Some("file")) {
                let (name, ext) = file_meta(&info);
                for a in row.attachments.iter_mut().filter(|a| a.kind.as_deref() == Some("file")) {
                    a.name = name.clone();
                    a.ext = ext.clone();
                    if a.size.is_none() {
                        a.size = info.file_size;
                    }
                }
            }
        }
        out.push(row);
    }
    Ok(out)
}

/// Messages of one conversation, newest first (`ts DESC, msg_id DESC`),
/// keyset-paginated on `(ts, msg_id)`.
pub fn list_messages(
    conn: &Connection,
    own: Option<&str>,
    conv_id: &str,
    before: Option<&(i64, String)>,
    limit: usize,
) -> Result<Vec<MsgRow>, String> {
    let sql = format!(
        "SELECT {MSG_COLS_SQL}
         FROM messages m
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.conv_id = ?1
           AND (?2 IS NULL
                OR (m.ts < ?2 OR (m.ts = ?2 AND m.msg_id < ?3)))
         ORDER BY m.ts DESC, m.msg_id DESC
         LIMIT ?4"
    );
    fetch_messages(
        conn,
        own,
        &sql,
        &[
            &conv_id,
            &before.map(|b| b.0),
            &before.map(|b| b.1.clone()),
            &(limit as i64),
        ],
    )
}

/// Messages by id (any conversation) — the search join-back.
fn msg_rows_by_ids(
    conn: &Connection,
    own: Option<&str>,
    ids: &[String],
) -> Result<HashMap<String, MsgRow>, String> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT {MSG_COLS_SQL}
         FROM messages m
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.msg_id IN ({placeholders})"
    );
    let params: Vec<&dyn rusqlite::ToSql> =
        ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
    let rows = fetch_messages(conn, own, &sql, &params)?;
    Ok(rows.into_iter().map(|m| (m.msg_id.clone(), m)).collect())
}

/// Search `messages` (batch 9 `search::search_in`, diacritics-folded)
/// and join each hit back to its full row + conversation. The hit
/// order is the search's own (bm25, then `ts` DESC). Batch 29a M6:
/// `conv_id` restricts the same FTS query to one conversation. The
/// search is a bounded top-N (no cursor exists on a bm25 order); the
/// page limit is the cap.
pub fn search_messages(
    conn: &Connection,
    own: Option<&str>,
    query: &str,
    conv_id: Option<&str>,
    limit: usize,
) -> Result<Vec<SearchRow>, String> {
    let hits = search::search_in(conn, query, conv_id, limit)?;
    let ids: Vec<String> = hits.iter().map(|h| h.msg_id.clone()).collect();
    let rows = msg_rows_by_ids(conn, own, &ids)?;
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

// --- batch 29a M3: the conversation info panel's lists -------------------------

/// The three storage tabs of the info panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaTab {
    Media,
    File,
    Link,
}

impl MediaTab {
    /// `"media" | "file" | "link"`; anything else is refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "media" => Some(Self::Media),
            "file" => Some(Self::File),
            "link" => Some(Self::Link),
            _ => None,
        }
    }
}

/// One image/video of the media tab.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MediaItem {
    pub msg_id: String,
    pub idx: i64,
    pub kind: Option<String>,
    pub ts: i64,
    pub has_local: bool,
    pub status: Option<String>,
}

/// One file of the file tab.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FileItem {
    pub msg_id: String,
    pub idx: i64,
    pub ts: i64,
    pub name: Option<String>,
    pub ext: Option<String>,
    pub size: Option<i64>,
    pub has_local: bool,
    pub status: Option<String>,
    pub sender_name: Option<String>,
}

/// One link of the link tab (no href — see `archive_open_link`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LinkItem {
    pub msg_id: String,
    pub ts: i64,
    pub title: Option<String>,
    pub domain: String,
    pub sender_name: Option<String>,
}

/// A row of any tab (serialised as the bare inner object).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum ConvMediaRow {
    Media(MediaItem),
    File(FileItem),
    Link(LinkItem),
}

impl ConvMediaRow {
    /// The keyset cursor `(ts, msg_id, idx)` of this row (a link has
    /// idx 0), to pass back as `before`.
    pub fn cursor(&self) -> (i64, String, i64) {
        match self {
            Self::Media(m) => (m.ts, m.msg_id.clone(), m.idx),
            Self::File(f) => (f.ts, f.msg_id.clone(), f.idx),
            Self::Link(l) => (l.ts, l.msg_id.clone(), 0),
        }
    }
}

/// Counts of the three tabs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConvMediaCounts {
    pub media: i64,
    pub file: i64,
    pub link: i64,
}

/// Media/file attachments of one conversation, newest first, keyset on
/// `(m.ts, a.msg_id, a.idx)` (all DESC). Drives from `messages` through
/// `idx_messages_conv_ts` and probes `attachments` by its primary key
/// — never a scan of either whole table (pinned by an EXPLAIN QUERY
/// PLAN test).
const ATT_TAB_SQL: &str = "SELECT a.msg_id, a.idx, a.kind, m.ts, a.status, a.local_path, a.size,
                CASE WHEN a.kind = 'file' THEN m.payload_json END,
                COALESCE(NULLIF(ct.display_name, ''), m.sender_id)
         FROM messages m
         JOIN attachments a ON a.msg_id = m.msg_id
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.conv_id = ?1
           AND a.kind IN (?5, ?6)
           AND (?2 IS NULL
                OR m.ts < ?2
                OR (m.ts = ?2 AND (a.msg_id < ?3 OR (a.msg_id = ?3 AND a.idx < ?4))))
         ORDER BY m.ts DESC, a.msg_id DESC, a.idx DESC
         LIMIT ?7";

/// Link messages (kinds 7/9 whose content has an `"href":"http…`),
/// keyset on `(ts, msg_id)`.
const LINK_TAB_SQL: &str = "SELECT m.msg_id, m.ts, m.type, m.payload_json,
                COALESCE(NULLIF(ct.display_name, ''), m.sender_id)
         FROM messages m
         LEFT JOIN contacts ct ON ct.user_id = m.sender_id
         WHERE m.conv_id = ?1
           AND m.type IN (7, 9)
           AND instr(m.payload_json, '\"href\":\"http') > 0
           AND (?2 IS NULL OR m.ts < ?2 OR (m.ts = ?2 AND m.msg_id < ?3))
         ORDER BY m.ts DESC, m.msg_id DESC
         LIMIT ?4";

/// One keyset page of one tab. `before` is the `(ts, msg_id, idx)`
/// cursor of the last row of the previous page (`None` = newest).
pub fn conv_media(
    conn: &Connection,
    conv_id: &str,
    tab: MediaTab,
    before: Option<&(i64, String, i64)>,
    limit: usize,
) -> Result<Vec<ConvMediaRow>, String> {
    match tab {
        MediaTab::Media | MediaTab::File => att_tab(conn, conv_id, tab, before, limit),
        MediaTab::Link => link_tab(conn, conv_id, before, limit),
    }
}

fn att_tab(
    conn: &Connection,
    conv_id: &str,
    tab: MediaTab,
    before: Option<&(i64, String, i64)>,
    limit: usize,
) -> Result<Vec<ConvMediaRow>, String> {
    let (k1, k2) = if tab == MediaTab::Media {
        ("image", "video")
    } else {
        ("file", "file")
    };
    let mut st = conn
        .prepare(ATT_TAB_SQL)
        .map_err(|e| sqlite_err("prepare", &e))?;
    let rows = st
        .query_map(
            rusqlite::params![
                conv_id,
                before.map(|b| b.0),
                before.map(|b| b.1.clone()),
                before.map(|b| b.2),
                k1,
                k2,
                limit as i64
            ],
            |r| {
                let status: Option<String> = r.get(4)?;
                let has_local = r
                    .get::<_, Option<String>>(5)?
                    .is_some_and(|p| !p.is_empty());
                let ts: i64 = r.get(3)?;
                let msg_id: String = r.get(0)?;
                let idx: i64 = r.get(1)?;
                if tab == MediaTab::Media {
                    return Ok(ConvMediaRow::Media(MediaItem {
                        msg_id,
                        idx,
                        kind: r.get(2)?,
                        ts,
                        has_local,
                        status,
                    }));
                }
                let db_size: Option<i64> = r.get(6)?;
                let info = r
                    .get::<_, Option<String>>(7)?
                    .map(|p| parse_payload(&p))
                    .unwrap_or_default();
                let (name, ext) = file_meta(&info);
                let size = if status.as_deref() == Some("downloaded") {
                    db_size.filter(|n| *n >= 0)
                } else {
                    None
                }
                .or(info.file_size);
                Ok(ConvMediaRow::File(FileItem {
                    msg_id,
                    idx,
                    ts,
                    name,
                    ext,
                    size,
                    has_local,
                    status,
                    sender_name: r.get(8)?,
                }))
            },
        )
        .map_err(|e| sqlite_err("query", &e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| sqlite_err("row", &e))?);
    }
    Ok(out)
}

fn link_tab(
    conn: &Connection,
    conv_id: &str,
    before: Option<&(i64, String, i64)>,
    limit: usize,
) -> Result<Vec<ConvMediaRow>, String> {
    let mut out: Vec<ConvMediaRow> = Vec::new();
    let mut cursor: Option<(i64, String)> = before.map(|b| (b.0, b.1.clone()));
    let mut st = conn
        .prepare(LINK_TAB_SQL)
        .map_err(|e| sqlite_err("prepare", &e))?;
    // The SQL prefilter is a substring test; a candidate whose content
    // is not a real http(s) link is skipped here, so keep paging the
    // candidates (bounded) until the page is full or they run out.
    for _ in 0..50 {
        let want = limit - out.len();
        let rows = st
            .query_map(
                rusqlite::params![
                    conv_id,
                    cursor.as_ref().map(|c| c.0),
                    cursor.as_ref().map(|c| c.1.clone()),
                    want as i64
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .map_err(|e| sqlite_err("query", &e))?;
        let mut got = 0usize;
        for row in rows {
            let (msg_id, ts, kind, payload, sender_name) =
                row.map_err(|e| sqlite_err("row", &e))?;
            got += 1;
            cursor = Some((ts, msg_id.clone()));
            let info = payload.as_deref().map(parse_payload).unwrap_or_default();
            if let Some(link) = link_of(kind, &info) {
                out.push(ConvMediaRow::Link(LinkItem {
                    msg_id,
                    ts,
                    title: link.title,
                    domain: link.domain,
                    sender_name,
                }));
            }
        }
        if out.len() >= limit || got < want {
            break;
        }
    }
    Ok(out)
}

/// Counts of the three tabs of one conversation (counts only). The
/// link count uses the same SQL predicate as the link list.
pub fn conv_media_counts(conn: &Connection, conv_id: &str) -> Result<ConvMediaCounts, String> {
    let (media, file) = conn
        .query_row(
            "SELECT COALESCE(SUM(a.kind IN ('image', 'video')), 0),
                    COALESCE(SUM(a.kind = 'file'), 0)
             FROM messages m JOIN attachments a ON a.msg_id = m.msg_id
             WHERE m.conv_id = ?1",
            rusqlite::params![conv_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .map_err(|e| sqlite_err("row", &e))?;
    let link = conn
        .query_row(
            "SELECT COUNT(*) FROM messages m
             WHERE m.conv_id = ?1 AND m.type IN (7, 9)
               AND instr(m.payload_json, '\"href\":\"http') > 0",
            rusqlite::params![conv_id],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| sqlite_err("row", &e))?;
    Ok(ConvMediaCounts { media, file, link })
}

// --- batch 29a M5: the two user-initiated actions' read halves -------------------

/// What `archive_open_link` found for a message id.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkLookup {
    /// An http(s) URL to open (never sent to JS).
    Url(tauri::Url),
    /// No such message, not a link kind (7/9), or no href.
    NoLink,
    /// The href exists but its scheme is not http/https (or it has no
    /// host) — refused.
    BadScheme,
}

/// Re-read one link message's href server-side for `archive_open_link`:
/// only a kind-7/9 message, and only an http(s) href with a host is
/// returned for opening.
pub fn link_url(conn: &Connection, msg_id: &str) -> Result<LinkLookup, String> {
    let row = conn.query_row(
        "SELECT type, payload_json FROM messages WHERE msg_id = ?1",
        rusqlite::params![msg_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
    );
    let (kind, payload) = match row {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(LinkLookup::NoLink),
        Err(e) => return Err(sqlite_err("row", &e)),
    };
    if !matches!(kind, 7 | 9) {
        return Ok(LinkLookup::NoLink);
    }
    let info = payload.as_deref().map(parse_payload).unwrap_or_default();
    Ok(match info.href.as_deref() {
        None => LinkLookup::NoLink,
        Some(h) => http_url(h).map_or(LinkLookup::BadScheme, LinkLookup::Url),
    })
}

/// A message id as the commands accept it (same charset and bound as
/// the media URL's): 1..=128 chars of `[A-Za-z0-9_-]`.
pub fn valid_msg_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Everything `archive_save_attachment` needs about one downloaded
/// attachment: the verified in-store path (never sent to JS) and the
/// default save name.
#[derive(Debug, Clone, PartialEq)]
pub struct SaveTarget {
    pub path: PathBuf,
    pub default_name: String,
}

/// Resolve one downloaded attachment for saving: the same
/// `attachment_media` guard the media scheme uses (downloaded only,
/// inside the store), plus the default name (the stored file title,
/// sanitised, else `zalo-<kind>-<ts>.<ext>` with the ext from the
/// stored bytes' magic).
pub fn save_target(
    conn: &Connection,
    cfg: &ShadowSettings,
    msg_id: &str,
    idx: i64,
) -> Result<Option<SaveTarget>, String> {
    let Some((path, kind)) = attachment_media(conn, cfg, msg_id, idx) else {
        return Ok(None);
    };
    let row = conn.query_row(
        "SELECT ts, payload_json FROM messages WHERE msg_id = ?1",
        rusqlite::params![msg_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
    );
    let (ts, payload) = match row {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => (0, None),
        Err(e) => return Err(sqlite_err("row", &e)),
    };
    let info = match (kind.as_deref(), payload.as_deref()) {
        (Some("file"), Some(p)) => parse_payload(p),
        _ => PayloadInfo::default(),
    };
    let (name, name_ext) = file_meta(&info);
    let mut head = [0u8; 16];
    let n = std::fs::File::open(&path)
        .ok()
        .and_then(|mut f| std::io::Read::read(&mut f, &mut head).ok())
        .unwrap_or(0);
    let ext = name_ext.or_else(|| ext_for_head(kind.as_deref(), &head[..n]).map(str::to_string));
    let mut default_name = default_save_name(name.as_deref(), kind.as_deref(), ts, ext.as_deref());
    // A real name without an extension gets the known one.
    if name.is_some() && !default_name.contains('.') {
        if let Some(e) = ext.as_deref().and_then(sanitize_ext) {
            default_name = format!("{default_name}.{e}");
        }
    }
    Ok(Some(SaveTarget { path, default_name }))
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

/// Parse the optional query of a media URL (batch 28 M2): none → the
/// `view` variant; otherwise EXACTLY `v=thumb`, `v=view` or `v=orig`.
/// Strict: an empty query, an unknown value, a duplicate or any other
/// parameter refuses (`None`).
pub fn parse_media_query(query: Option<&str>) -> Option<super::img_derive::Variant> {
    use super::img_derive::Variant;
    match query {
        None => Some(Variant::View),
        Some(q) => Variant::parse(q.strip_prefix("v=")?),
    }
}

/// The whole media request: path (`/media/<msg_id>/<idx>`) plus the
/// optional `?v=` variant, both strict.
pub fn parse_media_request(
    path: &str,
    query: Option<&str>,
) -> Option<(String, i64, super::img_derive::Variant)> {
    let (msg_id, idx) = parse_media_uri(path)?;
    Some((msg_id, idx, parse_media_query(query)?))
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
/// Batch 27 M4: JPEG XL (bare codestream and container) serves as
/// `image/jxl` — `magic_ok` accepts JXL for image rows now, so the
/// viewer must serve it too, or every stored JXL would 404.
pub fn content_type_for(kind: Option<&str>, head: &[u8]) -> Option<&'static str> {
    let sniffed = if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("image/png")
    } else if head.starts_with(b"GIF8") {
        Some("image/gif")
    } else if head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP" {
        Some("image/webp")
    } else if head.starts_with(&[0xFF, 0x0A])
        || head.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A])
    {
        Some("image/jxl")
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
        // Batch 25: the Zalo PC 26.11.12 kinds carry their labels too.
        assert_eq!(preview_of(None, 14).as_deref(), Some("[danh sách]"));
        assert_eq!(preview_of(None, 15).as_deref(), Some("[thiệp]"));
        assert_eq!(preview_of(None, 16).as_deref(), Some("[bình chọn]"));
        assert_eq!(preview_of(None, 17).as_deref(), Some("[to-do]"));
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
            ids(list_conversations(&conn, None, None, 10).unwrap()),
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
            let page = list_conversations(&conn, None, cursor.as_ref(), 3).unwrap();
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
            list_conversations(&conn, None, None, 10)
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
            list_conversations(&conn, None, None, 10)
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
        let page = list_messages(&conn, None, "c1", None, 10).unwrap();
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
            AttRow { idx: 0, kind: Some("image".into()), status: Some("downloaded".into()), has_local: true, name: None, ext: None, size: None });
        assert_eq!(page[0].attachments[1],
            AttRow { idx: 1, kind: Some("video".into()), status: Some("ref".into()), has_local: false, name: None, ext: None, size: None });
        assert_eq!(page[1].attachments[0].status.as_deref(), Some("failed"));
        assert_eq!(page[2].attachments.len(), 0);
        assert_eq!(page[3].attachments[0].status.as_deref(), Some("ref-encrypted"));

        // Keyset pages: 3 rows per page, no dup/skip.
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<(i64, String)> = None;
        loop {
            let p = list_messages(&conn, None, "c1", cursor.as_ref(), 3).unwrap();
            if p.is_empty() { break; }
            let last = p.last().unwrap();
            cursor = Some((last.ts, last.msg_id.clone()));
            seen.extend(p.into_iter().map(|m| m.msg_id));
            if seen.len() == 4 { break; }
        }
        assert_eq!(seen, vec!["m2", "m3", "m1", "m4"]);
        // The cursor also pages across equal timestamps by msg_id.
        msg(&conn, "m5", "c1", Some("u1"), 2000, 1, Some("cùng thời điểm"));
        let p1 = list_messages(&conn, None, "c1", None, 1).unwrap();
        assert_eq!(p1[0].msg_id, "m5", "ts DESC, msg_id DESC tie-break");
        let p2 = list_messages(&conn, None, "c1", Some(&(p1[0].ts, p1[0].msg_id.clone())), 10).unwrap();
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
        let rows = search_messages(&conn, None, "ha noi", None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.conv_id, "g1");
        assert_eq!(row.conv_name.as_deref(), Some("Nhóm lớp học"));
        assert_eq!(row.msg.msg_id, "m1");
        assert_eq!(row.msg.text.as_deref(), Some("Hà Nội hôm nay mưa nhiều"));
        assert_eq!(row.msg.attachments.len(), 1, "the full row shape, attachments included");
        // Empty/whitespace queries never touch the index.
        assert!(search_messages(&conn, None, "   ", None, 10).unwrap().is_empty());
        // The search limit is honored.
        msg(&conn, "m3", "g1", Some("u1"), 3000, 1, Some("Hà Nội ngày mai"));
        let rows = search_messages(&conn, None, "hà nội", None, 1).unwrap();
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
    fn media_query_is_strict_and_defaults_to_view() {
        use super::super::img_derive::Variant;
        assert_eq!(parse_media_query(None), Some(Variant::View));
        assert_eq!(parse_media_query(Some("v=thumb")), Some(Variant::Thumb));
        assert_eq!(parse_media_query(Some("v=view")), Some(Variant::View));
        assert_eq!(parse_media_query(Some("v=orig")), Some(Variant::Orig));
        for bad in [
            "", "v=", "v=THUMB", "v=full", "v=thumb&v=view", "v=thumb&v=thumb", "v=thumb&x=1",
            "x=thumb", "v=thumb&", "&v=thumb", "V=thumb", "v=thumb%20", "v=../x", "thumb",
            "v=thumb;v=view", " v=thumb",
        ] {
            assert_eq!(parse_media_query(Some(bad)), None, "{bad:?} must not parse");
        }
        // The pair: a good path with a good/absent query, a bad part
        // anywhere refuses.
        assert_eq!(
            parse_media_request("/media/m1/0", Some("v=orig")),
            Some(("m1".into(), 0, Variant::Orig))
        );
        assert_eq!(
            parse_media_request("/media/m1/0", None),
            Some(("m1".into(), 0, Variant::View))
        );
        assert_eq!(parse_media_request("/media/m1/0", Some("v=x")), None);
        assert_eq!(parse_media_request("/media/m1/x", Some("v=thumb")), None);
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
        // Batch 27 M4: JXL serves as image/jxl in both forms — and a
        // VIDEO row holding JXL bytes is still a disagreement (None).
        let jxl_bare = [0xFF, 0x0A, 0xE0, 0x0D, 0x00, 0x00, 0x00, 0x00];
        let jxl_box = [
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(content_type_for(Some("image"), &jxl_bare), Some("image/jxl"));
        assert_eq!(content_type_for(Some("image"), &jxl_box), Some("image/jxl"));
        assert_eq!(content_type_for(Some("video"), &jxl_bare), None);
        assert_eq!(content_type_for(Some("video"), &jxl_box), None);
        // An image/video row whose bytes fail the sniff is refused…
        assert_eq!(content_type_for(Some("image"), &cipher), None);
        assert_eq!(content_type_for(Some("video"), &cipher), None);
        assert_eq!(content_type_for(Some("video"), &jpeg), None);
        // …but file/voice/unknown kinds serve as generic binary.
        assert_eq!(content_type_for(Some("file"), &cipher), Some("application/octet-stream"));
        assert_eq!(content_type_for(Some("voice"), &cipher), Some("application/octet-stream"));
        assert_eq!(content_type_for(None, &cipher), Some("application/octet-stream"));
    }

    // --- batch 29a: pure helpers ----------------------------------------------

    #[test]
    fn initials_are_unicode_aware_and_at_most_two_letters() {
        assert_eq!(initials_of("Nguyễn Văn An"), "NA", "first + last word");
        assert_eq!(initials_of("Lan"), "L", "one word, one letter");
        assert_eq!(initials_of("  mai   hương "), "MH", "lowercase is uppercased, spaces collapse");
        assert_eq!(initials_of("đào thị"), "ĐT", "đ is a letter of its own");
        assert_eq!(initials_of("Ánh"), "Á");
        assert_eq!(initials_of("👍 Lan"), "L", "a leading emoji is skipped");
        assert_eq!(initials_of("A B C D"), "AD");
        assert_eq!(initials_of("张伟"), "张", "CJK: one word, one char");
        assert_eq!(initials_of(""), "?");
        assert_eq!(initials_of("   "), "?");
        assert_eq!(initials_of("---"), "?");
        assert_eq!(initials_of("1234"), "1", "digits count");
        for n in ["Nguyễn Văn An", "x", "a b c d e"] {
            assert!(initials_of(n).chars().count() <= 2);
        }
    }

    #[test]
    fn color_index_is_stable_and_in_range() {
        // Pinned values (FNV-1a 64 mod 8): a refactor that changes the
        // hash would recolour every avatar.
        assert_eq!(color_index(""), 5);
        assert_eq!(color_index("u1"), 3);
        assert_eq!(color_index("8441"), 2);
        assert_eq!(color_index("c1"), 1);
        assert_eq!(color_index("1234567890123456789"), 7);
        for k in ["", "a", "b", "u-lan", "Nhóm gia đình", "9".repeat(40).as_str()] {
            assert!(color_index(k) < 8);
            assert_eq!(color_index(k), color_index(k), "deterministic");
        }
        // 64 distinct ids reach more than one bucket (it is a spread).
        let buckets: std::collections::HashSet<u8> =
            (0..64).map(|i| color_index(&format!("user-{i}"))).collect();
        assert!(buckets.len() >= 4);
    }

    #[test]
    fn ext_sanitising_accepts_only_clean_short_alnum() {
        assert_eq!(sanitize_ext("pdf").as_deref(), Some("pdf"));
        assert_eq!(sanitize_ext("PDF").as_deref(), Some("pdf"), "lowercased");
        assert_eq!(sanitize_ext(".Docx").as_deref(), Some("docx"), "one leading dot");
        assert_eq!(sanitize_ext(" mp4 ").as_deref(), Some("mp4"));
        assert_eq!(sanitize_ext("abcdefgh").as_deref(), Some("abcdefgh"), "8 chars is the limit");
        assert_eq!(sanitize_ext("abcdefghi"), None, "9 chars refused");
        for bad in ["", ".", "..", "p/df", "p\\df", "pdf ", "a b", "p-df", "p.df", "đoc", "pd\u{0}f", "../x", "tar.gz"] {
            // (the trimmed forms are judged after trim: "pdf " is fine)
            let expect_ok = bad.trim() == "pdf";
            assert_eq!(sanitize_ext(bad).is_some(), expect_ok, "{bad:?}");
        }
        assert_eq!(ext_of_name("report.final.PDF").as_deref(), Some("pdf"));
        assert_eq!(ext_of_name("noext"), None);
        assert_eq!(ext_of_name(".hidden"), None, "a dotfile has no extension");
        assert_eq!(ext_of_name("a.b c"), None);
    }

    #[test]
    fn domain_is_the_lowercase_host_of_an_http_url_only() {
        assert_eq!(domain_of("https://Example.COM/a/b?c=d#e").as_deref(), Some("example.com"));
        assert_eq!(domain_of("http://news.vnexpress.net:8080/x").as_deref(), Some("news.vnexpress.net"), "port stripped");
        assert_eq!(
            domain_of("https://user:pass@secret-host.example/p").as_deref(),
            Some("secret-host.example"),
            "userinfo stripped"
        );
        assert_eq!(
            domain_of("https://bücher.example/x").as_deref(),
            Some("xn--bcher-kva.example"),
            "IDN host is shown as punycode"
        );
        assert_eq!(domain_of("https://[::1]:3000/").as_deref(), Some("[::1]"));
        assert_eq!(domain_of("  https://trim.example/  ").as_deref(), Some("trim.example"));
        for bad in [
            "javascript:alert(1)",
            "file:///C:/Windows/win.ini",
            "data:text/html,<b>x</b>",
            "mailto:a@b.example",
            "ftp://host.example/x",
            "tel:+84123",
            "//no-scheme.example/x",
            "no-scheme.example/x",
            "https://",
            "",
            "not a url",
        ] {
            assert_eq!(domain_of(bad), None, "{bad:?} must be refused");
            assert!(http_url(bad).is_none());
        }
    }

    #[test]
    fn save_names_are_sanitised_and_bounded() {
        assert_eq!(sanitize_file_name("Báo cáo Q3.pdf"), "Báo cáo Q3.pdf");
        assert_eq!(sanitize_file_name("../../etc/passwd"), "etcpasswd", "separators stripped, dots trimmed");
        assert_eq!(sanitize_file_name("a\\b/c.txt"), "abc.txt");
        assert_eq!(sanitize_file_name("tab\there\u{0}nul\u{7f}.txt"), "tabherenul.txt", "control characters stripped");
        assert_eq!(sanitize_file_name("a<b>c:d\"e|f?g*h.txt"), "a_b_c_d_e_f_g_h.txt", "reserved chars become _");
        assert_eq!(sanitize_file_name("  ..name.. "), "name");
        assert_eq!(sanitize_file_name("../.."), "", "nothing left: the caller falls back");
        assert_eq!(sanitize_file_name(""), "");
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("COM1.log"), "_COM1.log");
        assert_eq!(sanitize_file_name("console.txt"), "console.txt", "only the exact device names");
        // Length: cut to 120 chars, a short extension survives.
        let long = format!("{}.pdf", "đ".repeat(300));
        let cut = sanitize_file_name(&long);
        assert_eq!(cut.chars().count(), SAVE_NAME_MAX);
        assert!(cut.ends_with(".pdf"));
        let long_noext = "x".repeat(500);
        assert_eq!(sanitize_file_name(&long_noext).chars().count(), SAVE_NAME_MAX);
        // The fallback name.
        assert_eq!(default_save_name(Some("Hợp đồng.docx"), Some("file"), 5, Some("docx")), "Hợp đồng.docx");
        assert_eq!(default_save_name(None, Some("image"), 1731987200000, Some("jpg")), "zalo-image-1731987200000.jpg");
        assert_eq!(default_save_name(Some("../.."), Some("video"), 9, Some("MP4")), "zalo-video-9.mp4", "an unusable name falls back");
        assert_eq!(default_save_name(None, None, 7, None), "zalo-file-7");
        assert_eq!(default_save_name(None, Some("../x"), 7, Some("a/b")), "zalo-file-7", "kind and ext are re-checked");
        // Magic -> extension for the generated name.
        assert_eq!(ext_for_head(Some("image"), &[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpg"));
        assert_eq!(ext_for_head(Some("video"), &[0, 0, 0, 0, b'f', b't', b'y', b'p']), Some("mp4"));
        assert_eq!(ext_for_head(Some("file"), &[1, 2, 3, 4]), None);
    }

    #[test]
    fn reaction_table_is_complete_and_aggregation_follows_the_rules() {
        assert_eq!(REACTION_CODES.len(), 51);
        let mut seen = std::collections::HashSet::new();
        for (code, emoji, name) in REACTION_CODES {
            assert!(seen.insert(*code), "duplicate code {code}");
            assert!(!code.is_empty() && !emoji.is_empty() && !name.is_empty());
        }
        assert_eq!(reaction_emoji("/-heart"), Some("❤️"));
        assert_eq!(reaction_emoji("/-strong"), Some("👍"));
        assert_eq!(reaction_emoji(":--|"), Some("😐"), "markdown-escaped pipes are plain pipes in the table");
        assert_eq!(reaction_emoji("|-)"), Some("😴"));
        assert_eq!(reaction_emoji(">-|"), Some("😠"));
        assert_eq!(reaction_emoji("/-beer"), Some("🍺"));
        assert_eq!(reaction_emoji("/-nope"), None);
        let agg = aggregate_reactions(vec![
            ("/-heart".into(), 2),
            ("/-strong".into(), 5),
            ("".into(), 9),         // removed reaction: dropped
            ("   ".into(), 1),      // blank: dropped
            (":>".into(), 2),
            ("/-unknown".into(), 3),
            ("/-heart".into(), 1),  // merged with the first heart bucket
        ]);
        let got: Vec<(&str, Option<&str>, i64)> =
            agg.iter().map(|a| (a.code.as_str(), a.emoji.as_deref(), a.count)).collect();
        assert_eq!(
            got,
            vec![
                ("/-strong", Some("👍"), 5),
                ("/-heart", Some("❤️"), 3),
                ("/-unknown", None, 3),   // tie on count: by code
                (":>", Some("😆"), 2),
            ]
        );
        assert!(aggregate_reactions(vec![]).is_empty());
    }

    #[test]
    fn own_uid_prefers_the_single_accounts_row_then_settings() {
        const OWN: &str = "1234567890123456789";
        const OTHER: &str = "9876543210987654321";
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // One row: it wins, whatever settings say.
        assert_eq!(resolve_own(&ids(&[OWN]), None).as_deref(), Some(OWN));
        assert_eq!(resolve_own(&ids(&[OWN]), Some(OTHER)).as_deref(), Some(OWN));
        // No row: a valid configured uid.
        assert_eq!(resolve_own(&[], Some(OWN)).as_deref(), Some(OWN));
        assert_eq!(resolve_own(&[], Some("12a")), None, "invalid shape is not a uid");
        assert_eq!(resolve_own(&[], None), None);
        // Ambiguous: only a configured uid that NAMES one of the rows.
        assert_eq!(resolve_own(&ids(&[OWN, OTHER]), Some(OTHER)).as_deref(), Some(OTHER));
        assert_eq!(resolve_own(&ids(&[OWN, OTHER]), Some("55555")), None);
        assert_eq!(resolve_own(&ids(&[OWN, OTHER]), None), None);
    }

    fn account(conn: &Connection, id: &str) {
        conn.execute(
            "INSERT INTO accounts (id, uin_hash, display_name, created_at) VALUES (?1, 'abc123def456', NULL, 0)",
            rusqlite::params![id],
        )
        .unwrap();
    }

    #[test]
    fn account_ids_reads_the_accounts_table() {
        let conn = db();
        assert!(account_ids(&conn).unwrap().is_empty());
        account(&conn, "1234567890123456789");
        assert_eq!(account_ids(&conn).unwrap(), vec!["1234567890123456789".to_string()]);
        account(&conn, "9876543210987654321");
        assert_eq!(account_ids(&conn).unwrap().len(), 2);
    }

    // --- payload parsing: capture and import shapes -----------------------------

    #[test]
    fn quote_extraction_handles_both_payload_shapes() {
        // Capture shape: quote is an object with fromD (the wire field).
        let cap = r#"{"msgId":"m1","msgType":"webchat","content":"trả lời","quote":{"ownerId":"8441","cliMsgId":1,"globalMsgId":2,"ts":3,"msg":"tin gốc ở đây","fromD":"Bạn Lan","attach":""}}"#;
        let i = parse_payload(cap);
        assert_eq!(i.quote_text.as_deref(), Some("tin gốc ở đây"));
        assert_eq!(i.quote_from.as_deref(), Some("Bạn Lan"));
        assert_eq!(i.quote_owner.as_deref(), Some("8441"));
        // Import shape: quote carried as a JSON TEXT, numeric owner id.
        let imp = serde_json::json!({
            "msgId": "m2", "msgType": "webchat", "content": "ok",
            "quote": "{\"ownerId\":8441,\"msg\":\"bản import\"}"
        })
        .to_string();
        let i = parse_payload(&imp);
        assert_eq!(i.quote_text.as_deref(), Some("bản import"));
        assert_eq!(i.quote_from, None);
        assert_eq!(i.quote_owner.as_deref(), Some("8441"), "a numeric owner id is read as text");
        // 120-char truncation, by chars.
        let long = "ệ".repeat(300);
        let p = serde_json::json!({"quote": {"msg": long, "fromD": "x"}}).to_string();
        assert_eq!(parse_payload(&p).quote_text.unwrap().chars().count(), QUOTE_PREVIEW_CHARS);
        // An attachment-only quote gets a label; an empty quote object is no quote.
        let a = serde_json::json!({"quote": {"msg": "", "attach": "{\"x\":1}", "fromD": "Lan"}}).to_string();
        assert_eq!(parse_payload(&a).quote_text.as_deref(), Some("[đính kèm]"));
        assert_eq!(parse_payload(r#"{"quote":{}}"#).quote_text, None);
        assert_eq!(parse_payload(r#"{"quote":{"msg":"  "}}"#).quote_text, None);
        assert_eq!(parse_payload(r#"{"quote":"not json"}"#).quote_text, None);
        assert_eq!(parse_payload(r#"{"msgId":"m3"}"#).quote_text, None);
        assert_eq!(parse_payload("not json at all"), PayloadInfo::default());
        assert_eq!(parse_payload("[1,2]"), PayloadInfo::default());
    }

    #[test]
    fn link_and_file_extraction_handles_both_payload_shapes() {
        // Capture: content is an object, params a JSON STRING.
        let file_cap = r#"{"msgType":"share.file","content":{"title":"Hợp đồng.PDF","href":"https://fake-file.zdn.vn/f","params":"{\"fileSize\":\"123456\",\"fileExt\":\"PDF\"}"}}"#;
        let i = parse_payload(file_cap);
        assert_eq!(i.title.as_deref(), Some("Hợp đồng.PDF"));
        assert_eq!(i.file_ext.as_deref(), Some("pdf"));
        assert_eq!(i.file_size, Some(123456));
        // Import: params is an OBJECT, fileSize a number.
        let file_imp = r#"{"msgType":"share.file","content":{"title":"a.zip","href":"https://x.example/a","params":{"fileExt":"zip","fileSize":42}}}"#;
        let i = parse_payload(file_imp);
        assert_eq!((i.file_ext.as_deref(), i.file_size), (Some("zip"), Some(42)));
        // content as JSON text (older import rows).
        let as_text = serde_json::json!({"content": "{\"title\":\"b.txt\",\"params\":\"{\\\"fileSize\\\":\\\"7\\\"}\"}"}).to_string();
        let i = parse_payload(&as_text);
        assert_eq!((i.title.as_deref(), i.file_size), (Some("b.txt"), Some(7)));
        // A negative / non-numeric size and a hostile ext are dropped.
        let bad = r#"{"content":{"title":"c","params":{"fileExt":"p/df","fileSize":"-5"}}}"#;
        let i = parse_payload(bad);
        assert_eq!((i.file_ext, i.file_size), (None, None));
        let (name, ext) = file_meta(&parse_payload(
            r#"{"content":{"title":"report.final.XLSX","params":{"fileSize":"1"}}}"#,
        ));
        assert_eq!((name.as_deref(), ext.as_deref()), (Some("report.final.XLSX"), Some("xlsx")), "ext falls back to the title's own");

        // Links: kind 7 / 9 only, http(s) only, 200-char truncation.
        let link = serde_json::json!({"msgType":"chat.recommended","content":{
            "href":"https://User:pw@News.Example.com:8443/path?q=1",
            "title": "T".repeat(500), "description": "D".repeat(500), "thumb":"https://t.example/x.jpg"}})
        .to_string();
        let info = parse_payload(&link);
        let l = link_of(7, &info).unwrap();
        assert_eq!(l.domain, "news.example.com");
        assert_eq!(l.title.as_deref().unwrap().chars().count(), LINK_TEXT_CHARS);
        assert_eq!(l.description_preview.as_deref().unwrap().chars().count(), LINK_TEXT_CHARS);
        assert!(link_of(9, &info).is_some());
        for other in [1, 2, 4, 8, 100] {
            assert!(link_of(other, &info).is_none(), "kind {other} has no link card");
        }
        let js = parse_payload(r#"{"content":{"href":"javascript:alert(1)","title":"x"}}"#);
        assert!(link_of(7, &js).is_none(), "non-http refused");
        let nohref = parse_payload(r#"{"content":{"title":"only a title"}}"#);
        assert!(link_of(7, &nohref).is_none());
        // The serialised card never carries the href or the thumb.
        let json = serde_json::to_string(&l).unwrap();
        assert!(!json.contains("pw") && !json.contains("8443") && !json.contains("thumb") && !json.contains("href"));
    }

    #[test]
    fn raw_type_is_allow_listed() {
        assert_eq!(parse_payload(r#"{"msgType":"-4"}"#).raw_type.as_deref(), Some("-4"));
        assert_eq!(parse_payload(r#"{"msgType":"-1909"}"#).raw_type.as_deref(), Some("-1909"));
        assert_eq!(parse_payload(r#"{"msgType":"chat.brand.new"}"#).raw_type, None);
        assert_eq!(parse_payload(r#"{"msgType":"<script>"}"#).raw_type, None);
        assert_eq!(parse_payload(r#"{"msgType":4}"#).raw_type, None);
        assert_eq!(parse_payload("{}").raw_type, None);
    }

    // --- command-level tests on a synthetic store (~30 messages, 2 conversations) --

    const OWN: &str = "1234567890123456789";

    fn put(conn: &Connection, id: &str, conv_id: &str, sender: Option<&str>, ts: i64, kind: i64, text: Option<&str>, payload: &str) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'capture')",
            rusqlite::params![id, conv_id, sender, ts, kind, text, payload],
        )
        .unwrap();
    }

    fn att_size(conn: &Connection, msg_id: &str, idx: i64, kind: &str, status: &str, path: Option<&str>, size: Option<i64>) {
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, local_path, size, status)
             VALUES (?1, ?2, ?3, 'https://fake-stal.zdn.vn/x', ?4, ?5, ?6)",
            rusqlite::params![msg_id, idx, kind, path, size, status],
        )
        .unwrap();
    }

    fn react(conn: &Connection, msg_id: &str, user: &str, code: &str) {
        conn.execute(
            "INSERT INTO reactions (msg_id, user_id, emoji, ts) VALUES (?1, ?2, ?3, 1)",
            rusqlite::params![msg_id, user, code],
        )
        .unwrap();
    }

    /// Two conversations: "u-lan" (private, 18 messages) and "g-1" (group,
    /// 12). Message i: ts = 1000 + 10*i; the sender alternates own/other;
    /// every 3rd carries an image, every 4th a file, every 5th a link.
    /// Returns the per-conversation expected (media, file, link) counts.
    fn fixture(conn: &Connection) -> [(i64, i64, i64); 2] {
        account(conn, OWN);
        contact(conn, "u-lan", "Bạn Lan");
        contact(conn, OWN, "Tôi");
        group(conn, "g-1", "Nhóm lớp 12A");
        conn.execute(
            "UPDATE groups SET raw_json = '{\"totalMember\":5,\"memberIds\":[\"a\"]}' WHERE group_id = 'g-1'",
            [],
        )
        .unwrap();
        conv(conn, "u-lan", 0, None, Some("m17"), Some(1170));
        conv(conn, "g-1", 1, None, Some("m29"), Some(1290));
        let mut expect = [(0i64, 0i64, 0i64); 2];
        for i in 0..30i64 {
            let (cid, slot) = if i % 5 < 3 { ("u-lan", 0) } else { ("g-1", 1) };
            let id = format!("m{i}");
            let sender = if i % 2 == 0 { OWN } else { "u-lan" };
            let ts = 1000 + 10 * i;
            if i % 3 == 0 {
                put(conn, &id, cid, Some(sender), ts, 2, None, r#"{"msgType":"chat.photo"}"#);
                att_size(conn, &id, 0, "image", "downloaded", Some("ab/cd/01"), Some(10));
                expect[slot].0 += 1;
            } else if i % 4 == 0 {
                let payload = format!(
                    r#"{{"msgType":"share.file","content":{{"title":"tai-lieu-{i}.PDF","href":"https://fake-file.zdn.vn/{i}","params":"{{\"fileSize\":\"{}\",\"fileExt\":\"PDF\"}}"}}}}"#,
                    1000 + i
                );
                put(conn, &id, cid, Some(sender), ts, 4, None, &payload);
                att_size(conn, &id, 0, "file", "ref", None, None);
                expect[slot].1 += 1;
            } else if i % 5 == 0 {
                let payload = format!(
                    r#"{{"msgType":"chat.recommended","content":{{"href":"https://Site{i}.example.com:81/p?x=1","title":"Tiêu đề {i}","description":"mô tả"}}}}"#
                );
                put(conn, &id, cid, Some(sender), ts, 7, None, &payload);
                expect[slot].2 += 1;
            } else {
                put(conn, &id, cid, Some(sender), ts, 1, Some(&format!("tin số {i}")), "{}");
            }
        }
        expect
    }

    #[test]
    fn is_self_follows_the_own_uid_with_and_without_an_accounts_row() {
        let conn = db();
        fixture(&conn);
        // The id the page resolves from its single accounts row.
        let own = resolve_own(&account_ids(&conn).unwrap(), None);
        assert_eq!(own.as_deref(), Some(OWN));
        let rows = list_messages(&conn, own.as_deref(), "u-lan", None, 200).unwrap();
        assert!(!rows.is_empty());
        for r in &rows {
            assert_eq!(r.is_self, r.sender_id.as_deref() == Some(OWN), "{}", r.msg_id);
        }
        assert!(rows.iter().any(|r| r.is_self) && rows.iter().any(|r| !r.is_self));
        // Unknown own id: nobody is "self", nothing else changes.
        let none = list_messages(&conn, None, "u-lan", None, 200).unwrap();
        assert_eq!(none.len(), rows.len());
        assert!(none.iter().all(|r| !r.is_self));
        // Without an accounts row (and no settings): resolve_own is None.
        let empty = db();
        assert_eq!(resolve_own(&account_ids(&empty).unwrap(), None), None);
        // A NULL sender is never self, even for an unknown own id.
        put(&conn, "orphan", "u-lan", None, 9999, 1, Some("mồ côi"), "{}");
        let rows = list_messages(&conn, Some(OWN), "u-lan", None, 1).unwrap();
        assert_eq!(rows[0].msg_id, "orphan");
        assert!(!rows[0].is_self);
        assert_eq!(rows[0].sender_initials, "?");
    }

    #[test]
    fn message_rows_carry_the_display_fields() {
        let conn = db();
        fixture(&conn);
        // Sender avatar fields.
        let rows = list_messages(&conn, Some(OWN), "u-lan", None, 200).unwrap();
        let lan = rows.iter().find(|r| r.sender_id.as_deref() == Some("u-lan")).unwrap();
        assert_eq!(lan.sender_name.as_deref(), Some("Bạn Lan"));
        assert_eq!(lan.sender_initials, "BL");
        assert_eq!(lan.sender_color, color_index("u-lan"));
        // A sender with no contact row: the id is the name, the initials are `?`.
        put(&conn, "x1", "u-lan", Some("77777"), 5000, 1, Some("lạ"), "{}");
        let x = list_messages(&conn, Some(OWN), "u-lan", None, 1).unwrap().remove(0);
        assert_eq!((x.sender_name.as_deref(), x.sender_initials.as_str()), (Some("77777"), "?"));
        // Quote with a name from fromD, and one resolved through contacts.
        put(&conn, "q1", "u-lan", Some("u-lan"), 5001, 1, Some("đồng ý"),
            r#"{"msgType":"webchat","quote":{"ownerId":"u-lan","msg":"mai họp lúc 9h","fromD":"Lan (lớp)"}}"#);
        put(&conn, "q2", "u-lan", Some("u-lan"), 5002, 1, Some("ừ"),
            r#"{"msgType":"webchat","quote":{"ownerId":"u-lan","msg":"không có fromD"}}"#);
        put(&conn, "q3", "u-lan", Some("u-lan"), 5003, 1, Some("ờ"),
            r#"{"msgType":"webchat","quote":{"ownerId":"nobody","msg":"chủ không rõ"}}"#);
        let by = |id: &str| list_messages(&conn, Some(OWN), "u-lan", None, 200).unwrap().into_iter().find(|m| m.msg_id == id).unwrap();
        assert_eq!(by("q1").quote, Some(QuoteRow { sender_name: Some("Lan (lớp)".into()), text_preview: "mai họp lúc 9h".into() }));
        assert_eq!(by("q2").quote, Some(QuoteRow { sender_name: Some("Bạn Lan".into()), text_preview: "không có fromD".into() }));
        assert_eq!(by("q3").quote, Some(QuoteRow { sender_name: None, text_preview: "chủ không rõ".into() }));
        assert_eq!(by("x1").quote, None);
        // raw_type: kind 100 only, allow-list only.
        put(&conn, "r1", "u-lan", Some("u-lan"), 5004, 100, None, r#"{"msgType":"-4"}"#);
        put(&conn, "r2", "u-lan", Some("u-lan"), 5005, 100, None, r#"{"msgType":"chat.something.new"}"#);
        put(&conn, "r3", "u-lan", Some("u-lan"), 5006, 1, Some("t"), r#"{"msgType":"-4"}"#);
        assert_eq!(by("r1").raw_type.as_deref(), Some("-4"));
        assert_eq!(by("r2").raw_type, None);
        assert_eq!(by("r3").raw_type, None, "kind 1 never reports a raw type");
        // Link card on a kind-7 row; the file attachment's name/ext/size.
        let link_row = rows.iter().find(|m| m.kind == 7).expect("a link row");
        let l = link_row.link.as_ref().unwrap();
        assert!(l.domain.starts_with("site") && l.domain.ends_with(".example.com"), "{}", l.domain);
        assert_eq!(l.description_preview.as_deref(), Some("mô tả"));
        let file_row = rows.iter().find(|m| m.kind == 4).expect("a file row");
        let a = &file_row.attachments[0];
        assert!(a.name.as_deref().unwrap().starts_with("tai-lieu-"));
        assert_eq!(a.ext.as_deref(), Some("pdf"));
        assert!(a.size.unwrap() >= 1000, "fileSize parsed from params for a not-yet-downloaded file");
        // A downloaded file takes the row's own size.
        att_size(&conn, "q1", 0, "file", "downloaded", Some("ab/cd/02"), Some(777));
        assert_eq!(by("q1").attachments[0].size, Some(777));
        // An image attachment never gets file metadata.
        let img = rows.iter().find(|m| m.kind == 2).unwrap();
        assert_eq!((img.attachments[0].name.clone(), img.attachments[0].ext.clone(), img.attachments[0].size), (None, None, Some(10)));
    }

    #[test]
    fn reactions_aggregate_for_a_whole_page() {
        let conn = db();
        fixture(&conn);
        react(&conn, "m0", "u1", "/-heart");
        react(&conn, "m0", "u2", "/-heart");
        react(&conn, "m0", "u3", "/-strong");
        react(&conn, "m0", "u4", "");            // a removed reaction
        react(&conn, "m0", "u5", "/-weird-code");
        react(&conn, "m6", "u1", ":>");
        let rows = list_messages(&conn, Some(OWN), "u-lan", None, 200).unwrap();
        let m0 = rows.iter().find(|m| m.msg_id == "m0").unwrap();
        let got: Vec<(&str, Option<&str>, i64)> = m0.reactions.iter().map(|r| (r.code.as_str(), r.emoji.as_deref(), r.count)).collect();
        assert_eq!(got, vec![("/-heart", Some("❤️"), 2), ("/-strong", Some("👍"), 1), ("/-weird-code", None, 1)]);
        assert_eq!(rows.iter().find(|m| m.msg_id == "m6").unwrap().reactions.len(), 1);
        assert!(rows.iter().filter(|m| m.msg_id != "m0" && m.msg_id != "m6").all(|m| m.reactions.is_empty()));
    }

    #[test]
    fn conversation_rows_carry_group_and_last_sender_fields() {
        let conn = db();
        fixture(&conn);
        let rows = list_conversations(&conn, Some(OWN), None, 10).unwrap();
        let by = |id: &str| rows.iter().find(|c| c.id == id).unwrap().clone();
        let lan = by("u-lan");
        assert!(!lan.is_group);
        assert_eq!(lan.member_count, None, "a private chat has no member count");
        assert_eq!(lan.name, "Bạn Lan");
        assert_eq!((lan.initials.as_str(), lan.color_idx), ("BL", color_index("u-lan")));
        // m17 is odd -> sent by u-lan.
        assert!(!lan.last_sender_is_self);
        assert_eq!(lan.last_sender_name.as_deref(), Some("Bạn Lan"));
        assert_eq!(lan.last_kind, 1);
        // The group: member_count falls through to groups.raw_json.totalMember.
        let g = by("g-1");
        assert!(g.is_group);
        assert_eq!(g.member_count, Some(5));
        assert_eq!(g.initials, "N1", "first word's letter + last word's first char");
        // m29 is odd -> u-lan again; make the last message the user's own.
        put(&conn, "own-last", "g-1", Some(OWN), 7000, 2, None, "{}");
        conn.execute("UPDATE conversations SET last_msg_id = 'own-last', last_ts = 7000 WHERE id = 'g-1'", []).unwrap();
        let g = list_conversations(&conn, Some(OWN), None, 10).unwrap().into_iter().find(|c| c.id == "g-1").unwrap();
        assert!(g.last_sender_is_self);
        assert_eq!(g.last_sender_name, None, "self has no name: the UI says Bạn");
        assert_eq!(g.last_kind, 2);
        assert_eq!(preview_label(g.last_kind), Some("[ảnh]"));
        // Unknown own id: nobody is self, the name still resolves.
        let g = list_conversations(&conn, None, None, 10).unwrap().into_iter().find(|c| c.id == "g-1").unwrap();
        assert!(!g.last_sender_is_self);
        assert_eq!(g.last_sender_name.as_deref(), Some("Tôi"));
        // Member count: the largest populated source (batch 30: a partial
        // participants roster must not shrink a fuller snapshot). The
        // fixture's raw_json.totalMember is 5.
        conn.execute("UPDATE groups SET members_json = '[\"a\",\"b\",\"c\"]' WHERE group_id = 'g-1'", []).unwrap();
        assert_eq!(conv_info(&conn, "g-1").unwrap().unwrap().member_count, Some(5), "totalMember 5 > members_json 3");
        for u in ["p1", "p2"] {
            conn.execute("INSERT INTO participants (conv_id, user_id) VALUES ('g-1', ?1)", rusqlite::params![u]).unwrap();
        }
        assert_eq!(conv_info(&conn, "g-1").unwrap().unwrap().member_count, Some(5), "2 partial rows do not shrink 5");
        for u in ["p3", "p4", "p5", "p6"] {
            conn.execute("INSERT INTO participants (conv_id, user_id) VALUES ('g-1', ?1)", rusqlite::params![u]).unwrap();
        }
        assert_eq!(conv_info(&conn, "g-1").unwrap().unwrap().member_count, Some(6), "a bigger roster wins");
        // Malformed JSON never breaks the list.
        conn.execute("UPDATE groups SET members_json = 'not json', raw_json = '{oops' WHERE group_id = 'g-1'", []).unwrap();
        conn.execute("DELETE FROM participants", []).unwrap();
        let g = list_conversations(&conn, None, None, 10).unwrap().into_iter().find(|c| c.id == "g-1").unwrap();
        assert_eq!(g.member_count, None);
    }

    #[test]
    fn conv_info_reports_the_header_facts() {
        let conn = db();
        fixture(&conn);
        let n = |c: &str| conn.query_row("SELECT COUNT(*) FROM messages WHERE conv_id = ?1", [c], |r| r.get::<_, i64>(0)).unwrap();
        let lan = conv_info(&conn, "u-lan").unwrap().unwrap();
        assert_eq!(lan.name, "Bạn Lan");
        assert!(!lan.is_group);
        assert_eq!(lan.msg_count, n("u-lan"));
        assert!(lan.first_ts.unwrap() < lan.last_ts.unwrap());
        assert_eq!((lan.initials.as_str(), lan.color_idx), ("BL", color_index("u-lan")));
        let g = conv_info(&conn, "g-1").unwrap().unwrap();
        assert!(g.is_group && g.member_count == Some(5));
        assert_eq!(g.msg_count + lan.msg_count, 30);
        assert_eq!(conv_info(&conn, "nope").unwrap(), None);
        // An empty conversation: counts 0, no timestamps.
        conv(&conn, "empty", 0, None, None, None);
        let e = conv_info(&conn, "empty").unwrap().unwrap();
        assert_eq!((e.msg_count, e.first_ts, e.last_ts), (0, None, None));
    }

    /// Walk one tab with a small page and a keyset cursor; every row once.
    fn walk(conn: &Connection, conv_id: &str, tab: MediaTab, page: usize) -> Vec<ConvMediaRow> {
        let mut out = Vec::new();
        let mut cursor: Option<(i64, String, i64)> = None;
        loop {
            let p = conv_media(conn, conv_id, tab, cursor.as_ref(), page).unwrap();
            assert!(p.len() <= page);
            if p.is_empty() {
                break;
            }
            cursor = Some(p.last().unwrap().cursor());
            out.extend(p);
            assert!(out.len() < 1000, "runaway paging");
        }
        out
    }

    #[test]
    fn media_tabs_page_by_keyset_without_duplicates_or_gaps() {
        let conn = db();
        let expect = fixture(&conn);
        // Equal timestamps with several attachments: the (msg_id, idx)
        // halves of the cursor must carry them.
        for k in 0..3 {
            let id = format!("tie{k}");
            put(&conn, &id, "u-lan", Some("u-lan"), 3000, 2, None, "{}");
            att_size(&conn, &id, 0, "image", "downloaded", Some("ab/cd/01"), Some(1));
            att_size(&conn, &id, 1, "video", "ref", None, None);
        }
        for (slot, cid) in ["u-lan", "g-1"].into_iter().enumerate() {
            let extra = if cid == "u-lan" { 6 } else { 0 };
            let counts = conv_media_counts(&conn, cid).unwrap();
            assert_eq!(counts, ConvMediaCounts { media: expect[slot].0 + extra, file: expect[slot].1, link: expect[slot].2 }, "{cid}");
            for tab in [MediaTab::Media, MediaTab::File, MediaTab::Link] {
                let want = match tab {
                    MediaTab::Media => counts.media,
                    MediaTab::File => counts.file,
                    MediaTab::Link => counts.link,
                } as usize;
                let all = conv_media(&conn, cid, tab, None, 200).unwrap();
                assert_eq!(all.len(), want, "{cid} {tab:?} count matches the list");
                for page in [1usize, 2, 3, 7] {
                    let walked = walk(&conn, cid, tab, page);
                    assert_eq!(walked, all, "{cid} {tab:?} page={page}: same rows, same order, no dup/skip");
                }
                // Newest first, strictly decreasing cursors.
                let cur: Vec<_> = all.iter().map(ConvMediaRow::cursor).collect();
                assert!(cur.windows(2).all(|w| w[0] > w[1]), "{cid} {tab:?} strictly descending");
            }
        }
        // Row shapes.
        match &conv_media(&conn, "u-lan", MediaTab::Media, None, 1).unwrap()[0] {
            ConvMediaRow::Media(m) => {
                assert_eq!((m.msg_id.as_str(), m.idx, m.ts), ("tie2", 1, 3000), "ts DESC, msg_id DESC, idx DESC");
                assert_eq!((m.kind.as_deref(), m.status.as_deref(), m.has_local), (Some("video"), Some("ref"), false));
            }
            other => panic!("not a media row: {other:?}"),
        }
        let files = conv_media(&conn, "u-lan", MediaTab::File, None, 5).unwrap();
        match &files[0] {
            ConvMediaRow::File(f) => {
                assert!(f.name.as_deref().unwrap().starts_with("tai-lieu-"));
                assert_eq!(f.ext.as_deref(), Some("pdf"));
                assert!(f.size.unwrap() >= 1000);
                assert!(!f.has_local && f.status.as_deref() == Some("ref"));
                assert!(f.sender_name.is_some());
            }
            other => panic!("not a file row: {other:?}"),
        }
        match &conv_media(&conn, "u-lan", MediaTab::Link, None, 5).unwrap()[0] {
            ConvMediaRow::Link(l) => {
                assert!(l.domain.starts_with("site") && l.domain.ends_with(".example.com"));
                assert!(l.title.as_deref().unwrap().starts_with("Tiêu đề"));
            }
            other => panic!("not a link row: {other:?}"),
        }
        // Tabs of another conversation never leak; an unknown one is empty.
        assert!(conv_media(&conn, "nope", MediaTab::Media, None, 10).unwrap().is_empty());
        assert_eq!(conv_media_counts(&conn, "nope").unwrap(), ConvMediaCounts { media: 0, file: 0, link: 0 });
        // The tab name is strict.
        assert_eq!(MediaTab::parse("media"), Some(MediaTab::Media));
        for bad in ["", "Media", "image", "files", "link ", "all"] {
            assert_eq!(MediaTab::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_link_candidate_without_a_real_url_is_skipped_but_paging_continues() {
        let conn = db();
        conv(&conn, "c", 0, None, None, None);
        // 6 candidates (the SQL prefilter matches), 3 are not http(s) URLs.
        for i in 0..6i64 {
            let href = if i % 2 == 0 { "https://ok.example/x" } else { "httpx://bad.example/x" };
            put(&conn, &format!("l{i}"), "c", Some("u"), 100 + i, 7, None,
                &format!(r#"{{"content":{{"href":"{href}","title":"t{i}"}}}}"#));
        }
        let all = walk(&conn, "c", MediaTab::Link, 1);
        assert_eq!(all.len(), 3, "only the real links, even with a page of 1");
        let big = conv_media(&conn, "c", MediaTab::Link, None, 3).unwrap();
        assert_eq!(big.len(), 3, "a page is filled past the skipped candidates");
    }

    #[test]
    fn media_queries_never_scan_a_whole_table() {
        // M3: prove the queries need no new index. The plan must drive
        // from messages through idx_messages_conv_ts and probe
        // attachments by its primary key — a line starting `SCAN` would
        // be a whole-table scan (which would mean an index is needed,
        // and an index is a schema change this batch may not make).
        let conn = db();
        fixture(&conn);
        let plan = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Vec<String> {
            let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            st.query_map(params, |r| r.get::<_, String>(3)).unwrap().map(Result::unwrap).collect()
        };
        let cid = "u-lan";
        let none: Option<i64> = None;
        let none_s: Option<String> = None;
        let att = plan(ATT_TAB_SQL, &[&cid, &none, &none_s, &none, &"image", &"video", &50i64]);
        let att_after = plan(ATT_TAB_SQL, &[&cid, &1100i64, &"m5", &0i64, &"file", &"file", &50i64]);
        let link = plan(LINK_TAB_SQL, &[&cid, &none, &none_s, &50i64]);
        let link_after = plan(LINK_TAB_SQL, &[&cid, &1100i64, &"m5", &50i64]);
        for (name, lines) in [("att", &att), ("att_after", &att_after), ("link", &link), ("link_after", &link_after)] {
            println!("PLAN {name}: {lines:?}");
            assert!(!lines.iter().any(|l| l.starts_with("SCAN")), "{name}: a whole-table scan: {lines:?}");
            assert!(lines.iter().any(|l| l.contains("idx_messages_conv_ts")), "{name}: must use idx_messages_conv_ts: {lines:?}");
        }
        assert!(att.iter().any(|l| l.contains("a USING PRIMARY KEY") || l.contains("sqlite_autoindex_attachments")), "attachments probed by PK: {att:?}");
        // The conversation-list and message-list queries are unchanged in
        // shape (still the batch-11 indexes): spot-check the message page.
        let msgs = plan(
            &format!("SELECT {MSG_COLS_SQL} FROM messages m LEFT JOIN contacts ct ON ct.user_id = m.sender_id WHERE m.conv_id = ?1 AND (?2 IS NULL OR (m.ts < ?2 OR (m.ts = ?2 AND m.msg_id < ?3))) ORDER BY m.ts DESC, m.msg_id DESC LIMIT ?4"),
            &[&cid, &none, &none_s, &50i64],
        );
        assert!(!msgs.iter().any(|l| l.starts_with("SCAN")), "message page: {msgs:?}");
    }

    #[test]
    fn search_can_be_limited_to_one_conversation() {
        let conn = db();
        conv(&conn, "c1", 0, None, None, None);
        conv(&conn, "c2", 0, None, None, None);
        msg(&conn, "a1", "c1", Some("u"), 100, 1, Some("Hà Nội hôm nay mưa"));
        msg(&conn, "a2", "c2", Some("u"), 200, 1, Some("Hà Nội ngày mai nắng"));
        msg(&conn, "a3", "c2", Some("u"), 300, 1, Some("không liên quan"));
        let ids = |rows: Vec<SearchRow>| {
            let mut v: Vec<String> = rows.into_iter().map(|r| r.msg.msg_id).collect();
            v.sort();
            v
        };
        assert_eq!(ids(search_messages(&conn, None, "ha noi", None, 10).unwrap()), vec!["a1", "a2"], "no filter: every conversation");
        assert_eq!(ids(search_messages(&conn, None, "ha noi", Some("c1"), 10).unwrap()), vec!["a1"]);
        assert_eq!(ids(search_messages(&conn, None, "ha noi", Some("c2"), 10).unwrap()), vec!["a2"]);
        assert!(search_messages(&conn, None, "ha noi", Some("nope"), 10).unwrap().is_empty());
        // The same query as before for None.
        let plain = search::search(&conn, "ha noi", 10).unwrap();
        let via = search::search_in(&conn, "ha noi", None, 10).unwrap();
        assert_eq!(plain, via);
        // The limit still caps a filtered search.
        msg(&conn, "a4", "c2", Some("u"), 400, 1, Some("Hà Nội lại mưa"));
        assert_eq!(search_messages(&conn, None, "ha noi", Some("c2"), 1).unwrap().len(), 1);
    }

    #[test]
    fn link_lookup_for_open_link_is_strict() {
        let conn = db();
        conv(&conn, "c", 0, None, None, None);
        put(&conn, "ok", "c", Some("u"), 1, 7, None, r#"{"content":{"href":"https://good.example/a?b=1"}}"#);
        put(&conn, "web", "c", Some("u"), 2, 9, None, r#"{"content":{"href":"http://web.example/x"}}"#);
        put(&conn, "js", "c", Some("u"), 3, 7, None, r#"{"content":{"href":"javascript:alert(1)"}}"#);
        put(&conn, "file", "c", Some("u"), 4, 7, None, r#"{"content":{"href":"file:///C:/x"}}"#);
        put(&conn, "text", "c", Some("u"), 5, 1, Some("https://not-a-link-kind.example"), r#"{"content":{"href":"https://good.example/"}}"#);
        put(&conn, "nohref", "c", Some("u"), 6, 7, None, r#"{"content":{"title":"t"}}"#);
        match link_url(&conn, "ok").unwrap() {
            LinkLookup::Url(u) => assert_eq!(u.as_str(), "https://good.example/a?b=1"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(link_url(&conn, "web").unwrap(), LinkLookup::Url(_)));
        assert_eq!(link_url(&conn, "js").unwrap(), LinkLookup::BadScheme);
        assert_eq!(link_url(&conn, "file").unwrap(), LinkLookup::BadScheme);
        assert_eq!(link_url(&conn, "text").unwrap(), LinkLookup::NoLink, "only kinds 7/9");
        assert_eq!(link_url(&conn, "nohref").unwrap(), LinkLookup::NoLink);
        assert_eq!(link_url(&conn, "missing").unwrap(), LinkLookup::NoLink);
        // Message ids the commands accept.
        assert!(valid_msg_id("8506747288934") && valid_msg_id("a-b_C9"));
        for bad in ["", "a b", "a/b", "a%20b", "../x", &"9".repeat(129)] {
            assert!(!valid_msg_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn save_target_resolves_inside_the_store_with_a_clean_default_name() {
        let root = scratch();
        let mut cfg = ShadowSettings::default();
        cfg.media_store = Some(root.to_string_lossy().into_owned());
        let conn = db();
        std::fs::create_dir_all(root.join("ab/cd")).unwrap();
        std::fs::write(root.join("ab/cd/img"), [0xFF, 0xD8, 0xFF, 1, 2]).unwrap();
        std::fs::write(root.join("ab/cd/doc"), b"%PDF-1.4 fake").unwrap();
        put(&conn, "mi", "c", Some("u"), 1731987200000, 2, None, "{}");
        att_size(&conn, "mi", 0, "image", "downloaded", Some("ab/cd/img"), Some(5));
        put(&conn, "mf", "c", Some("u"), 5, 4, None,
            r#"{"content":{"title":"../..\\Báo:cáo?.PDF","params":{"fileExt":"pdf"}}}"#);
        att_size(&conn, "mf", 0, "file", "downloaded", Some("ab/cd/doc"), Some(13));
        put(&conn, "mn", "c", Some("u"), 6, 4, None, r#"{"content":{"title":"../..","params":{"fileExt":"pdf"}}}"#);
        att_size(&conn, "mn", 0, "file", "downloaded", Some("ab/cd/doc"), Some(13));
        att_size(&conn, "mr", 0, "image", "ref", Some("ab/cd/img"), None);
        let t = save_target(&conn, &cfg, "mi", 0).unwrap().unwrap();
        assert!(t.path.starts_with(&root));
        assert_eq!(t.default_name, "zalo-image-1731987200000.jpg", "ext from the bytes' magic");
        let t = save_target(&conn, &cfg, "mf", 0).unwrap().unwrap();
        assert_eq!(t.default_name, "Báo_cáo_.PDF", "separators stripped, reserved chars replaced, name kept");
        let t = save_target(&conn, &cfg, "mn", 0).unwrap().unwrap();
        assert_eq!(t.default_name, "zalo-file-6.pdf", "an unusable stored name falls back");
        // Only downloaded rows inside the store resolve; everything else is not-found.
        assert_eq!(save_target(&conn, &cfg, "mr", 0).unwrap(), None);
        assert_eq!(save_target(&conn, &cfg, "mi", 1).unwrap(), None);
        assert_eq!(save_target(&conn, &cfg, "nope", 0).unwrap(), None);
        att_size(&conn, "mx", 0, "image", "downloaded", Some("../escape"), None);
        assert_eq!(save_target(&conn, &cfg, "mx", 0).unwrap(), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_that_crosses_to_js_carries_a_url_path_sha_phone_or_raw_payload() {
        let conn = db();
        fixture(&conn);
        put(&conn, "k", "u-lan", Some("u-lan"), 9000, 7, None,
            r#"{"msgType":"chat.recommended","quote":{"msg":"q","fromD":"n","ownerId":"o"},"content":{"href":"https://linkhost.example/secret-path?token=ZZZ","title":"t","thumb":"https://secret-thumb.example/x.jpg","params":"{\"hd\":\"https://secret-hd.example/h\"}"}}"#);
        react(&conn, "k", "u1", "/-heart");
        att_size(&conn, "k", 0, "image", "downloaded", Some("ab/cd/PATHPART"), Some(1));
        conn.execute("UPDATE attachments SET sha256 = 'SHAVALUE' WHERE msg_id = 'k'", []).unwrap();
        conn.execute("UPDATE contacts SET phone_hash = 'PHONEHASH', avatar_url = 'https://avatar.example/a', raw_json = 'RAWCONTACT' WHERE user_id = 'u-lan'", []).unwrap();
        conn.execute("UPDATE conversations SET avatar_url = 'https://avatar.example/c', raw_json = 'RAWCONV' WHERE id = 'u-lan'", []).unwrap();
        let mut blobs: Vec<String> = Vec::new();
        for m in list_messages(&conn, Some(OWN), "u-lan", None, 200).unwrap() {
            blobs.push(serde_json::to_string(&m).unwrap());
        }
        for s in search_messages(&conn, Some(OWN), "tin", None, 50).unwrap() {
            blobs.push(serde_json::to_string(&s).unwrap());
        }
        for c in list_conversations(&conn, Some(OWN), None, 50).unwrap() {
            blobs.push(serde_json::to_string(&c).unwrap());
        }
        for tab in [MediaTab::Media, MediaTab::File, MediaTab::Link] {
            for r in conv_media(&conn, "u-lan", tab, None, 200).unwrap() {
                blobs.push(serde_json::to_string(&r).unwrap());
            }
        }
        blobs.push(serde_json::to_string(&conv_info(&conn, "u-lan").unwrap()).unwrap());
        blobs.push(serde_json::to_string(&conv_media_counts(&conn, "u-lan").unwrap()).unwrap());
        let all = blobs.join("\n");
        for needle in [
            "secret-path", "secret-thumb", "secret-hd", "token=ZZZ", "PATHPART", "ab/cd", "SHAVALUE", "PHONEHASH",
            "RAWCONTACT", "RAWCONV", "avatar.example", "fake-stal", "fake-file", "payload", "local_path", "\"url\"", "\"href\"",
            "\"sha", "phone", "\"thumb\"", "raw_json",
        ] {
            assert!(!all.contains(needle), "{needle:?} crossed to JS");
        }
        // The one thing a link row shows from the URL is the host.
        assert!(all.contains("\"domain\":\"linkhost.example\""));
    }
}
