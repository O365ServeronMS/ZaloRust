//! Zalo PC LOCAL media tools (batch 27): the read-only
//! `--local-media-probe` census (M2) and the `--local-media-plan`
//! DRY-RUN planner (M3).
//!
//! Why: most imported history media can no longer be re-downloaded
//! from the CDN (the batch-26 probe measured 15/15 dead links), but
//! Zalo PC keeps a local copy of much of it under
//! `<root>\media\<uid>\ZaloDownloads\<sub>\…`, where `<sub>` is one of
//! `picture, video, file, fileNoise, fileThumb, voice, richThumb,
//! zinstant, resource, Cache` (plus `<root>\media\<uid>\sticker\…`).
//! These tools measure how the Desktop's own rows point into that
//! tree, so a LATER, user-approved batch (27b) can copy files into the
//! content-addressed media store.
//!
//! HARD RULES obeyed (brief M2/M3):
//! - READ-ONLY everywhere. The snapshot opens through the usual
//!   `import::prepare` guards (cold snapshot, D7 key, cipher profile,
//!   `mode=ro&immutable=1`); the shadow store opens READ-ONLY with the
//!   `repair_cli` key resolution and a Locked passphrase store refuses
//!   (this CLI never accepts a password). NOTHING is ever written — no
//!   DB, no files, no temp copies. Copying files into the store is NOT
//!   part of this batch.
//! - H-rule, every output line and file: NEVER a path value, file
//!   name, directory name, uid, msgId or message text. Allowed:
//!   counts; the fixed `<sub>` vocabulary above (anything else prints
//!   as `other`); extension and magic classes; length and charset
//!   buckets; booleans. Refusals print only flag names, kinds and the
//!   user's own CLI arguments.
//! - The tools read AT MOST the first 16 bytes of a local file (the
//!   magic) and `metadata().len()` (the size). No whole file is ever
//!   read, hashed or copied in this batch. `fileNoise` contents are
//!   never decoded — a `fileNoise` path counts as `noise_obfuscated`
//!   and that is all the plan ever learns about it.
//! - The `message` column (message text) is never SELECTed by the
//!   census — the fixed column list reads only the bookkeeping
//!   columns (`msgId, msgType, localPath, folderPath, previewThumb,
//!   fileSize, cliMsgId, sendDttm`).
//!
//! The M3 decision itself is a PURE function over (attachment row,
//! Desktop row, filesystem facts) — [`plan_outcome`] — unit-tested
//! with synthetic inputs for every outcome; the callers only gather
//! facts and count.
//!
//! Batch 27c (reviewer findings on the real data): the real Desktop
//! `message` schema declares `msgId:TEXT pk, cliMsgId:TEXT,
//! msgType:INTEGER, sendDttm:TEXT, localPath:TEXT, folderPath:TEXT,
//! previewThumb:TEXT, fileSize:INTEGER` — a TEXT-affinity column holds
//! TEXT even when the value is digits, and an INTEGER-affinity column
//! keeps non-numeric text as text. The old fixed-type reads
//! (`sendDttm` as `Option<i64>`, …) therefore dropped EVERY row on
//! the real snapshot (`query_failed=467616`, `rows=0`). Every column
//! of every scan is now read as a [`SV`] and coerced
//! ([`v_to_string`]/[`v_to_i64`]); a type surprise is COUNTED
//! (`row_failed`, `coerce_none=<col>:N,…`) and NEVER drops the row.
//! The report headers also no longer echo the `--local-media-root` /
//! `--target` path values (H-rule): `root=given (exists)`,
//! `store=given`, `report written (--out)`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SV;
use rusqlite::Connection;

use super::distinct::render_value;
use super::inventory::quote_ident;
use super::Prepared;

// --- the fixed shape vocabularies -----------------------------------------

/// The fixed `<sub>` vocabulary (the brief's M2 list) plus `sticker`
/// (the sibling tree the brief names). Anything else is `other`.
pub const SUB_VOCAB: [&str; 11] = [
    "picture",
    "video",
    "file",
    "fileNoise",
    "fileThumb",
    "voice",
    "richThumb",
    "zinstant",
    "resource",
    "Cache",
    "sticker",
];

/// One `<sub>` of the ZaloDownloads layout (or `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaSub {
    Picture,
    Video,
    File,
    FileNoise,
    FileThumb,
    Voice,
    RichThumb,
    Zinstant,
    Resource,
    Cache,
    Sticker,
    Other,
}

impl MediaSub {
    /// The printable vocabulary name (the brief's exact spelling);
    /// `other` for anything outside the fixed list.
    pub fn name(self) -> &'static str {
        match self {
            MediaSub::Picture => "picture",
            MediaSub::Video => "video",
            MediaSub::File => "file",
            MediaSub::FileNoise => "fileNoise",
            MediaSub::FileThumb => "fileThumb",
            MediaSub::Voice => "voice",
            MediaSub::RichThumb => "richThumb",
            MediaSub::Zinstant => "zinstant",
            MediaSub::Resource => "resource",
            MediaSub::Cache => "Cache",
            MediaSub::Sticker => "sticker",
            MediaSub::Other => "other",
        }
    }

    /// Case-insensitive vocabulary match of one path SEGMENT.
    fn of_seg(seg: &str) -> Option<MediaSub> {
        SUB_VOCAB
            .iter()
            .position(|v| v.eq_ignore_ascii_case(seg))
            .and_then(|i| match i {
                0 => Some(MediaSub::Picture),
                1 => Some(MediaSub::Video),
                2 => Some(MediaSub::File),
                3 => Some(MediaSub::FileNoise),
                4 => Some(MediaSub::FileThumb),
                5 => Some(MediaSub::Voice),
                6 => Some(MediaSub::RichThumb),
                7 => Some(MediaSub::Zinstant),
                8 => Some(MediaSub::Resource),
                9 => Some(MediaSub::Cache),
                10 => Some(MediaSub::Sticker),
                _ => None,
            })
    }
}

/// The path-shape classes of a `localPath` value (the brief's M2
/// list): a drive-absolute path, a UNC path, a relative path, a
/// `file://` url, or `other` (empty or any other url scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathShape {
    AbsDrive,
    AbsUnc,
    Relative,
    FileUrl,
    Other,
}

impl PathShape {
    pub fn name(self) -> &'static str {
        match self {
            PathShape::AbsDrive => "abs_drive",
            PathShape::AbsUnc => "abs_unc",
            PathShape::Relative => "relative",
            PathShape::FileUrl => "file_url",
            PathShape::Other => "other",
        }
    }
}

/// Classify one `localPath` value (pure; never prints it).
pub fn path_shape(p: &str) -> PathShape {
    if p.is_empty() {
        return PathShape::Other;
    }
    // `file://…` urls (case-insensitive scheme).
    if p.len() >= 7 && p[..7].eq_ignore_ascii_case("file://") {
        return PathShape::FileUrl;
    }
    // Any other url scheme (`https://…`, `http://…`) is `other`.
    if let Some(idx) = p.find("://") {
        if !p[..idx].is_empty() && p[..idx].bytes().all(|b| b.is_ascii_alphabetic()) {
            return PathShape::Other;
        }
    }
    let b = p.as_bytes();
    // `X:\…` / `X:/…` (a drive letter is exactly one ascii alpha).
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
    {
        return PathShape::AbsDrive;
    }
    // `\\server\share\…`.
    if p.starts_with(r"\\") {
        return PathShape::AbsUnc;
    }
    PathShape::Relative
}

/// Normalize a Windows path for case-insensitive comparison:
/// forward slashes, ASCII-lowercase, the `\\?\` (and `\\?\UNC\`)
/// prefix stripped, trailing slashes trimmed (pure).
pub fn norm_path(p: &str) -> String {
    let s: String = if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = p.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        p.to_string()
    };
    let mut out = s.replace('\\', "/");
    while out.ends_with('/') {
        out.pop();
    }
    out.to_ascii_lowercase()
}

/// Is `p` under `root`? Both sides PRE-NORMALIZED through
/// [`norm_path`] — a case-insensitive prefix check after normalising
/// slashes, with a `/` boundary so `d:/zalo data2` is NOT under
/// `d:/zalo data`. The root itself counts as under itself.
pub fn under_root(p_norm: &str, root_norm: &str) -> bool {
    if p_norm == root_norm {
        return true;
    }
    !root_norm.is_empty() && p_norm.starts_with(&format!("{root_norm}/"))
}

/// The `<sub>` a path falls in (pure; the vocabulary only, never a
/// real directory name): the segment right after `ZaloDownloads`
/// (case-insensitive); the `sticker` segment for the sibling tree;
/// `other` for anything else. A path outside the root that still
/// carries `…\ZaloDownloads\<sub>\…` classifies by that `<sub>` — the
/// vocabulary is fixed, so nothing beyond it can print.
pub fn classify_sub(p: &str) -> MediaSub {
    let norm = norm_path(p);
    let segs: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(i) = segs.iter().position(|s| *s == "zalodownloads") {
        return segs
            .get(i + 1)
            .and_then(|next| MediaSub::of_seg(next))
            .unwrap_or(MediaSub::Other);
    }
    if segs.iter().any(|s| *s == "sticker") {
        return MediaSub::Sticker;
    }
    MediaSub::Other
}

/// Resolve one Desktop media row's local path (pure): an absolute
/// path (drive/UNC) is used as-is; a RELATIVE one joins onto
/// `folderPath` when that is non-empty, else stays as-is (it then
/// fails the under-root check — a path is never fabricated into the
/// root).
pub fn resolve_local(local: &str, folder: Option<&str>) -> PathBuf {
    match path_shape(local) {
        PathShape::AbsDrive | PathShape::AbsUnc => PathBuf::from(local),
        _ => match folder.filter(|f| !f.is_empty()) {
            Some(f) => PathBuf::from(f).join(local),
            None => PathBuf::from(local),
        },
    }
}

/// The magic classes of the first 16 bytes (the brief's M2 list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MagicClass {
    Jpg,
    Png,
    Gif,
    Webp,
    Jxl,
    JxlContainer,
    Mp4,
    WebmMkv,
    Pdf,
    Zip,
    Html,
    Other,
}

impl MagicClass {
    pub fn name(self) -> &'static str {
        match self {
            MagicClass::Jpg => "jpg",
            MagicClass::Png => "png",
            MagicClass::Gif => "gif",
            MagicClass::Webp => "webp",
            MagicClass::Jxl => "jxl",
            MagicClass::JxlContainer => "jxl_container",
            MagicClass::Mp4 => "mp4",
            MagicClass::WebmMkv => "webm_mkv",
            MagicClass::Pdf => "pdf",
            MagicClass::Zip => "zip",
            MagicClass::Html => "html",
            MagicClass::Other => "other",
        }
    }
}

/// Classify the first bytes of a local file (pure). `jxl` is the bare
/// codestream `FF 0A`; `jxl_container` is
/// `00 00 00 0C 4A 58 4C 20 0D 0A 87 0A` (the ISO-BMFF signature).
pub fn magic_class(head: &[u8]) -> MagicClass {
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        MagicClass::Jpg
    } else if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        MagicClass::Png
    } else if head.starts_with(b"GIF8") {
        MagicClass::Gif
    } else if head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP" {
        MagicClass::Webp
    } else if head.starts_with(&[
        0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
    ]) {
        MagicClass::JxlContainer
    } else if head.starts_with(&[0xFF, 0x0A]) {
        MagicClass::Jxl
    } else if head.len() >= 8 && &head[4..8] == b"ftyp" {
        MagicClass::Mp4
    } else if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        MagicClass::WebmMkv
    } else if head.starts_with(b"%PDF") {
        MagicClass::Pdf
    } else if head.starts_with(&[0x50, 0x4B, 0x03, 0x04])
        || head.starts_with(&[0x50, 0x4B, 0x05, 0x06])
        || head.starts_with(&[0x50, 0x4B, 0x07, 0x08])
    {
        MagicClass::Zip
    } else if html_head(head) {
        MagicClass::Html
    } else {
        MagicClass::Other
    }
}

/// An html-ish head: after ASCII whitespace, `<!doctype` or `<html`
/// (case-insensitive). `zinstant` files are html snippets.
fn html_head(head: &[u8]) -> bool {
    let skip = head
        .iter()
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    let rest = &head[skip.min(head.len())..];
    let lower: Vec<u8> = rest.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.starts_with(b"<!doctype") || lower.starts_with(b"<html")
}

/// Read at most the FIRST 16 bytes of `path` (the batch's H-rule: no
/// whole file is ever read here). Errors and short files return what
/// arrived.
pub fn head_16(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = [0u8; 16];
    let mut n = 0usize;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    buf[..n].to_vec()
}

/// The only file facts this module ever gathers (H-rule):
/// `(is a regular file, metadata().len(), the first 16 bytes)`.
pub fn file_facts(path: &Path) -> (bool, Option<u64>, Vec<u8>) {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => (true, Some(m.len()), head_16(path)),
        _ => (false, None, Vec::new()),
    }
}

/// Does the file NAME contain a 13-digit number equal to `dttm`?
/// Maximal ASCII digit runs of exactly 13 digits are compared
/// numerically; a non-positive or unknown `dttm` never matches.
pub fn name_has_dttm(name: &str, dttm: i64) -> bool {
    if dttm <= 0 {
        return false;
    }
    let b = name.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 13 && name[start..i].parse::<i64>() == Ok(dttm) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

// --- batch 27c: tolerant column reads ----------------------------------------

/// The values that could not be coerced, by column name — counts only
/// (column names are schema, so the H-rule allows them).
type CoerceNone = BTreeMap<&'static str, u64>;

/// One string cell (`msgId, cliMsgId, localPath, folderPath,
/// previewThumb`): Text as is; Integer/Real as their decimal string;
/// Null or an empty result gives None (an absent value, not a
/// surprise); a Blob gives None and is COUNTED. A type surprise never
/// drops the row.
fn v_to_string(v: SV, col: &'static str, coerce: &mut CoerceNone) -> Option<String> {
    match v {
        SV::Text(s) => {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        SV::Integer(i) => Some(i.to_string()),
        SV::Real(f) => Some(f.to_string()),
        SV::Null => None,
        SV::Blob(_) => {
            *coerce.entry(col).or_insert(0) += 1;
            None
        }
    }
}

/// One numeric cell (`fileSize, sendDttm`): Integer as is; Text that
/// parses as i64 after trim; Null gives None (absent, not a surprise);
/// anything else (non-numeric text, a Real, a Blob) gives None and is
/// COUNTED. A type surprise never drops the row.
fn v_to_i64(v: SV, col: &'static str, coerce: &mut CoerceNone) -> Option<i64> {
    match v {
        SV::Integer(i) => Some(i),
        SV::Text(s) => match s.trim().parse::<i64>() {
            Ok(n) => Some(n),
            Err(_) => {
                *coerce.entry(col).or_insert(0) += 1;
                None
            }
        },
        SV::Null => None,
        SV::Real(_) | SV::Blob(_) => {
            *coerce.entry(col).or_insert(0) += 1;
            None
        }
    }
}

/// The probe scan's coercible columns, in MSG_COLS order (the fixed
/// render order of `coerce_none`; `msgType` is read as a Value and
/// rendered by `render_value`, never coerced).
const MSG_COERCE_COLS: [&str; 7] = [
    "msgId",
    "localPath",
    "folderPath",
    "previewThumb",
    "fileSize",
    "cliMsgId",
    "sendDttm",
];

/// The plan scan's coercible columns, in PLAN_COLS order.
const PLAN_COERCE_COLS: [&str; 4] = ["msgId", "localPath", "folderPath", "fileSize"];

/// The zcloud census's coercible columns.
const ZCLOUD_COERCE_COLS: [&str; 2] = ["localPath", "zSize"];

/// `coerce_none=<col>:N,…` — the counted surprises by column name, in
/// the scan's fixed column order; `none` when everything coerced.
fn coerce_none_field(cols: &[&'static str], coerce: &CoerceNone) -> String {
    let parts: Vec<String> = cols
        .iter()
        .filter(|c| coerce.get(*c).copied().unwrap_or(0) > 0)
        .map(|c| format!("{c}:{}", coerce[*c]))
        .collect();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(",")
    }
}

// --- M2: the per-code census ------------------------------------------------

/// The path-side stats of one code group, over the rows WITH a
/// non-empty `localPath` only. Every field is a count, a fixed class
/// name or a boolean count (H-rule).
#[derive(Default)]
struct PathStats {
    rows: u64,
    shape: BTreeMap<PathShape, u64>,
    under_root: u64,
    not_under_root: u64,
    subs: BTreeMap<MediaSub, u64>,
    exists: u64,
    missing: u64,
    size_match: u64,
    size_differ: u64,
    size_unknown: u64,
    magic: BTreeMap<MagicClass, u64>,
    /// name ↔ row relations, as (yes, no, na) triples — the value is
    /// never kept, only the boolean of the comparison.
    name_msgid: (u64, u64, u64),
    name_climsgid: (u64, u64, u64),
    name_senddttm: (u64, u64, u64),
}

/// One Desktop msgType code's census (the whole row group, including
/// rows with no localPath).
#[derive(Default)]
struct CodeCensus {
    rows: u64,
    localpath: u64,
    folderpath: u64,
    previewthumb: u64,
    paths: PathStats,
}

/// The fixed message-table column list (NEVER the `message` content
/// column). All are validated against the first DB that opens before
/// any row is read (the plan convention: all violations at once).
const MSG_COLS: [&str; 8] = [
    "msgId",
    "msgType",
    "localPath",
    "folderPath",
    "previewThumb",
    "fileSize",
    "cliMsgId",
    "sendDttm",
];

/// The columns the M3 plan reads.
const PLAN_COLS: [&str; 5] = ["msgId", "msgType", "localPath", "folderPath", "fileSize"];

/// Identifier-quoted fixed SELECT over `message`.
fn msg_scan_sql(cols: &[&str]) -> Result<String, String> {
    let mut parts = Vec::new();
    for c in cols {
        parts.push(quote_ident(c)?);
    }
    Ok(format!(
        "SELECT {} FROM {}",
        parts.join(", "),
        quote_ident("message")?
    ))
}

/// Does the DB have a `message` table? (Fake `undefined.db`-style
/// files that somehow open have no tables at all.)
fn has_message_table(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND lower(name)='message'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// The `message` table's column set (for the preflight).
fn message_columns(conn: &Connection) -> Vec<String> {
    let Ok(mut st) = conn.prepare("PRAGMA table_info(\"message\")") else {
        return Vec::new();
    };
    let Ok(rows) = st.query_map([], |r| r.get::<_, String>(1)) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

/// Open the FIRST message DB that opens (kinds one2one/group/stranger
/// only — `undefined.db` and unknown names are not schema samples).
/// Errors are skipped silently here; the caller reports counts.
fn first_open_message_db(p: &Prepared, names: &[(String, super::DbKind)]) -> Option<Connection> {
    for (name, kind) in names {
        match kind {
            super::DbKind::OneToOne(_)
            | super::DbKind::Group(_)
            | super::DbKind::StrangerBox => {}
            _ => continue,
        }
        let path = p.uid_dir.join("Core").join("Message").join(name);
        if let Ok(conn) = super::open_desktop_db(&path, p.passphrase.as_str(), p.profile) {
            return Some(conn);
        }
    }
    None
}

/// Preflight the fixed column list against the first DB that opens —
/// the `plan` convention: every missing column listed at once, before
/// any row is read. Column names are schema (printable); the refusal
/// carries nothing else.
fn preflight_columns(p: &Prepared, cols: &[&str]) -> Result<(), String> {
    let names = super::message_db_names(&p.uid_dir)?;
    let Some(conn) = first_open_message_db(p, &names) else {
        return Err(
            "no message DB in the snapshot opens with the snapshot key — the local-media tools \
             have nothing to read"
                .into(),
        );
    };
    let have = message_columns(&conn);
    let missing: Vec<&str> = cols
        .iter()
        .copied()
        .filter(|c| !have.iter().any(|h| h == c))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "the snapshot's message table lacks column(s) {} — this build reads a fixed column \
             set; a schema change needs a tool update",
            missing.join(", ")
        ));
    }
    Ok(())
}

/// Fold one message row into its code group (pure once the fs facts
/// are in — the file facts come from [`file_facts`], the only FS use).
#[allow(clippy::too_many_arguments)]
fn fold_msg_row(
    groups: &mut BTreeMap<String, CodeCensus>,
    refs: &mut HashSet<String>,
    root_norm: &str,
    code: &SV,
    local: Option<String>,
    folder: Option<String>,
    preview: Option<String>,
    file_size: Option<i64>,
    msg_id: Option<String>,
    cli_msg_id: Option<String>,
    send_dttm: Option<i64>,
) {
    let token = render_value(code);
    let g = groups.entry(token).or_default();
    g.rows += 1;
    if local.is_some() {
        g.localpath += 1;
    }
    if folder.is_some() {
        g.folderpath += 1;
    }
    if preview.is_some() {
        g.previewthumb += 1;
    }
    let Some(local) = local else { return };
    let ps = &mut g.paths;
    ps.rows += 1;
    // The shape class describes the RAW cell; under-root, the <sub>,
    // existence, size and magic describe the RESOLVED path (relative
    // cells resolve via folderPath exactly the way the M3 plan
    // resolves them).
    *ps.shape.entry(path_shape(&local)).or_insert(0) += 1;
    let resolved = resolve_local(&local, folder.as_deref());
    let resolved_s = resolved.to_string_lossy().into_owned();
    let rnorm = norm_path(&resolved_s);
    if under_root(&rnorm, root_norm) {
        ps.under_root += 1;
    } else {
        ps.not_under_root += 1;
    }
    *ps.subs.entry(classify_sub(&resolved_s)).or_insert(0) += 1;
    // The reference set for the reverse-coverage walk: the RESOLVED
    // path, normalized the same way the walk normalizes.
    refs.insert(rnorm);
    let (is_file, len, head) = file_facts(&resolved);
    if is_file {
        ps.exists += 1;
        match (len, file_size) {
            (Some(actual), Some(want)) => {
                if actual == want.unsigned_abs() {
                    ps.size_match += 1;
                } else {
                    ps.size_differ += 1;
                }
            }
            _ => ps.size_unknown += 1,
        }
        *ps.magic.entry(magic_class(&head)).or_insert(0) += 1;
    } else {
        ps.missing += 1;
    }
    // name ↔ row relations (the file name of the localPath — a string
    // operation, existence not required; values never kept).
    let name = resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match msg_id {
        Some(id) => {
            if name.contains(&id) {
                ps.name_msgid.0 += 1;
            } else {
                ps.name_msgid.1 += 1;
            }
        }
        None => ps.name_msgid.2 += 1,
    }
    match cli_msg_id {
        Some(id) => {
            if name.contains(&id) {
                ps.name_climsgid.0 += 1;
            } else {
                ps.name_climsgid.1 += 1;
            }
        }
        None => ps.name_climsgid.2 += 1,
    }
    match send_dttm {
        Some(d) => {
            if name_has_dttm(&name, d) {
                ps.name_senddttm.0 += 1;
            } else {
                ps.name_senddttm.1 += 1;
            }
        }
        None => ps.name_senddttm.2 += 1,
    }
}

/// Per-DB open/query outcomes and per-row failure counts of a message
/// scan (counts only, shared by the probe census and the M3 plan).
/// `query_failed` is a prepare/query_map failure, per DB; `row_failed`
/// is a row whose `rows.next()` itself errored; `coerce_none` counts
/// the values that could not be coerced, by column name.
#[derive(Default)]
struct DbStats {
    dbs: u64,
    opened: u64,
    open_failed: u64,
    query_failed: u64,
    row_failed: u64,
    no_table: u64,
    rows: u64,
    coerce_none: CoerceNone,
}

/// Scan EVERY snapshot message DB once with the fixed SELECT and fold
/// the rows — tolerant reads (batch 27c): open/query/row failures and
/// un-coercible values are COUNTED, kinds only — H-rule.
fn scan_message_dbs(
    p: &Prepared,
    root_norm: &str,
    groups: &mut BTreeMap<String, CodeCensus>,
    refs: &mut HashSet<String>,
) -> Result<DbStats, String> {
    let sql = msg_scan_sql(&MSG_COLS)?;
    let names = super::message_db_names(&p.uid_dir)?;
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut stats = DbStats::default();
    for (name, kind) in &names {
        match kind {
            super::DbKind::OneToOne(_)
            | super::DbKind::Group(_)
            | super::DbKind::StrangerBox => {}
            _ => continue, // `undefined.db` and unknown names are not scanned
        }
        stats.dbs += 1;
        let Ok(conn) = super::open_desktop_db(&msg_dir.join(name), p.passphrase.as_str(), p.profile)
        else {
            stats.open_failed += 1;
            continue;
        };
        stats.opened += 1;
        if !has_message_table(&conn) {
            stats.no_table += 1;
            continue;
        }
        let Ok(mut st) = conn.prepare(&sql) else {
            stats.query_failed += 1;
            continue;
        };
        // Batch 27c: every column is read as a Value and coerced, so
        // the map itself can no longer fail per row — the old
        // fixed-type reads dropped EVERY row on the real TEXT-affinity
        // `sendDttm` (467 616 row errors).
        let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, SV>(0)?, // msgId
                r.get::<_, SV>(1)?, // msgType
                r.get::<_, SV>(2)?, // localPath
                r.get::<_, SV>(3)?, // folderPath
                r.get::<_, SV>(4)?, // previewThumb
                r.get::<_, SV>(5)?, // fileSize
                r.get::<_, SV>(6)?, // cliMsgId
                r.get::<_, SV>(7)?, // sendDttm
            ))
        }) else {
            stats.query_failed += 1;
            continue;
        };
        for row in rows {
            // Only a `rows.next()` error lands here now (batch 27c
            // split it out of `query_failed`).
            let Ok((msg_id, code, local, folder, preview, size, cli, dttm)) = row else {
                stats.row_failed += 1;
                continue;
            };
            stats.rows += 1;
            fold_msg_row(
                groups,
                refs,
                root_norm,
                &code,
                v_to_string(local, "localPath", &mut stats.coerce_none),
                v_to_string(folder, "folderPath", &mut stats.coerce_none),
                v_to_string(preview, "previewThumb", &mut stats.coerce_none),
                v_to_i64(size, "fileSize", &mut stats.coerce_none),
                v_to_string(msg_id, "msgId", &mut stats.coerce_none),
                v_to_string(cli, "cliMsgId", &mut stats.coerce_none),
                v_to_i64(dttm, "sendDttm", &mut stats.coerce_none),
            );
        }
    }
    Ok(stats)
}

/// The fixed magic field order of the report lines.
const MAGIC_FIELDS: [MagicClass; 12] = [
    MagicClass::Jpg,
    MagicClass::Png,
    MagicClass::Gif,
    MagicClass::Webp,
    MagicClass::Jxl,
    MagicClass::JxlContainer,
    MagicClass::Mp4,
    MagicClass::WebmMkv,
    MagicClass::Pdf,
    MagicClass::Zip,
    MagicClass::Html,
    MagicClass::Other,
];

/// The fixed `<sub>` field order of the report lines.
const SUB_FIELDS: [MediaSub; 12] = [
    MediaSub::Picture,
    MediaSub::Video,
    MediaSub::File,
    MediaSub::FileNoise,
    MediaSub::FileThumb,
    MediaSub::Voice,
    MediaSub::RichThumb,
    MediaSub::Zinstant,
    MediaSub::Resource,
    MediaSub::Cache,
    MediaSub::Sticker,
    MediaSub::Other,
];

/// How many code groups render before the `more_codes` count (the
/// content-shape cap convention).
const CODE_CAP: usize = 64;

fn shape_fields(ps: &PathStats) -> String {
    [
        PathShape::AbsDrive,
        PathShape::AbsUnc,
        PathShape::Relative,
        PathShape::FileUrl,
        PathShape::Other,
    ]
    .iter()
    .map(|s| format!("{}:{}", s.name(), ps.shape.get(s).copied().unwrap_or(0)))
    .collect::<Vec<_>>()
    .join(" ")
}

fn sub_fields(ps: &PathStats) -> String {
    SUB_FIELDS
        .iter()
        .map(|s| format!("{}:{}", s.name(), ps.subs.get(s).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn magic_fields(magic: &BTreeMap<MagicClass, u64>) -> String {
    MAGIC_FIELDS
        .iter()
        .map(|m| format!("{}:{}", m.name(), magic.get(m).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the per-code census lines (most rows first, deterministic
/// tie-break on the rendered code token).
fn census_lines(groups: &BTreeMap<String, CodeCensus>) -> Vec<String> {
    let mut ordered: Vec<(&String, &CodeCensus)> = groups.iter().collect();
    ordered.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then(a.0.cmp(b.0)));
    let mut lines = Vec::new();
    for (token, g) in ordered.iter().take(CODE_CAP) {
        let ps = &g.paths;
        lines.push(format!(
            "local-media-probe: msgType={token} rows={} localpath={} folderpath={} previewthumb={}",
            g.rows, g.localpath, g.folderpath, g.previewthumb
        ));
        lines.push(format!(
            "local-media-probe: msgType={token} paths shape={} under_root=yes:{} no:{}",
            shape_fields(ps),
            ps.under_root,
            ps.not_under_root
        ));
        lines.push(format!(
            "local-media-probe: msgType={token} paths sub={}",
            sub_fields(ps)
        ));
        lines.push(format!(
            "local-media-probe: msgType={token} files exists=yes:{} no:{} size=match:{} differ:{} unknown:{}",
            ps.exists, ps.missing, ps.size_match, ps.size_differ, ps.size_unknown
        ));
        lines.push(format!(
            "local-media-probe: msgType={token} magic {}",
            magic_fields(&ps.magic)
        ));
        lines.push(format!(
            "local-media-probe: msgType={token} name msgid=yes:{} no:{} na:{} climsgid=yes:{} no:{} na:{} senddttm=yes:{} no:{} na:{}",
            ps.name_msgid.0,
            ps.name_msgid.1,
            ps.name_msgid.2,
            ps.name_climsgid.0,
            ps.name_climsgid.1,
            ps.name_climsgid.2,
            ps.name_senddttm.0,
            ps.name_senddttm.1,
            ps.name_senddttm.2
        ));
    }
    let more = groups.len().saturating_sub(CODE_CAP);
    if more > 0 {
        lines.push(format!(
            "local-media-probe: more_codes={} (capped at {CODE_CAP} by rows)",
            more
        ));
    }
    lines
}

// --- M2: the zcloud census ---------------------------------------------------

/// Fold one zcloud row (the same path census, no name relations — the
/// zcloud rows carry no msgId; `zSize` is the size column).
fn fold_zcloud_row(
    groups: &mut BTreeMap<String, CodeCensus>,
    root_norm: &str,
    ztype: &SV,
    local: Option<String>,
    zsize: Option<i64>,
) {
    let token = render_value(ztype);
    let g = groups.entry(token).or_default();
    g.rows += 1;
    let Some(local) = local else { return };
    g.localpath += 1;
    let ps = &mut g.paths;
    ps.rows += 1;
    *ps.shape.entry(path_shape(&local)).or_insert(0) += 1;
    let norm = norm_path(&local);
    if under_root(&norm, root_norm) {
        ps.under_root += 1;
    } else {
        ps.not_under_root += 1;
    }
    *ps.subs.entry(classify_sub(&local)).or_insert(0) += 1;
    let resolved = resolve_local(&local, None);
    let (is_file, len, head) = file_facts(&resolved);
    if is_file {
        ps.exists += 1;
        match (len, zsize) {
            (Some(actual), Some(want)) => {
                if actual == want.unsigned_abs() {
                    ps.size_match += 1;
                } else {
                    ps.size_differ += 1;
                }
            }
            _ => ps.size_unknown += 1,
        }
        *ps.magic.entry(magic_class(&head)).or_insert(0) += 1;
    } else {
        ps.missing += 1;
    }
}

/// The Index.db `zcloud` census (M2: "the same localPath census by
/// `zType`"). A missing table/columns are REPORTED (skipped), never
/// fatal — the census is a report.
fn zcloud_lines(p: &Prepared, root_norm: &str) -> Result<Vec<String>, String> {
    let index_path = p.uid_dir.join("Core").join("Index.db");
    let conn = super::open_desktop_db(&index_path, p.passphrase.as_str(), p.profile)?;
    let Ok(mut st) = conn.prepare("PRAGMA table_info(\"zcloud\")") else {
        return Ok(vec![
            "local-media-probe: zcloud: skipped (no zcloud table in Core/Index.db)".into()
        ]);
    };
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default();
    drop(st);
    // A missing table answers PRAGMA table_info with NO rows at all.
    if cols.is_empty() {
        return Ok(vec![
            "local-media-probe: zcloud: skipped (no zcloud table in Core/Index.db)".into()
        ]);
    }
    for col in ["localPath", "zType", "zSize"] {
        if !cols.iter().any(|c| c == col) {
            return Ok(vec![format!(
                "local-media-probe: zcloud: skipped (the zcloud table lacks the {col} column)"
            )]);
        }
    }
    let sql = format!(
        "SELECT {}, {}, {} FROM {}",
        quote_ident("localPath")?,
        quote_ident("zType")?,
        quote_ident("zSize")?,
        quote_ident("zcloud")?
    );
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("zcloud read failed ({})", crate::shadow::pipeline::sqlite_kind(&e)))?;
    // Batch 27c: the same tolerant reads as the message scan — a type
    // surprise in `localPath`/`zSize` is counted, never fatal for the
    // row.
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, SV>(0)?, // localPath
                r.get::<_, SV>(1)?, // zType
                r.get::<_, SV>(2)?, // zSize
            ))
        })
        .map_err(|e| format!("zcloud read failed ({})", crate::shadow::pipeline::sqlite_kind(&e)))?;
    let mut groups: BTreeMap<String, CodeCensus> = BTreeMap::new();
    let mut coerce: CoerceNone = BTreeMap::new();
    let mut total = 0u64;
    let mut row_failed = 0u64;
    for row in rows {
        let Ok((local, ztype, zsize)) = row else {
            row_failed += 1;
            continue;
        };
        total += 1;
        fold_zcloud_row(
            &mut groups,
            root_norm,
            &ztype,
            v_to_string(local, "localPath", &mut coerce),
            v_to_i64(zsize, "zSize", &mut coerce),
        );
    }
    let mut lines = vec![format!(
        "local-media-probe: zcloud rows={} row_failed={} coerce_none={}",
        total,
        row_failed,
        coerce_none_field(&ZCLOUD_COERCE_COLS, &coerce)
    )];
    let mut ordered: Vec<(&String, &CodeCensus)> = groups.iter().collect();
    ordered.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then(a.0.cmp(b.0)));
    for (token, g) in ordered.iter().take(CODE_CAP) {
        let ps = &g.paths;
        lines.push(format!(
            "local-media-probe: zcloud zType={token} rows={} localpath={}",
            g.rows, g.localpath
        ));
        lines.push(format!(
            "local-media-probe: zcloud zType={token} paths shape={} under_root=yes:{} no:{}",
            shape_fields(ps),
            ps.under_root,
            ps.not_under_root
        ));
        lines.push(format!(
            "local-media-probe: zcloud zType={token} paths sub={}",
            sub_fields(ps)
        ));
        lines.push(format!(
            "local-media-probe: zcloud zType={token} files exists=yes:{} no:{} size=match:{} differ:{} unknown:{} (vs zSize)",
            ps.exists, ps.missing, ps.size_match, ps.size_differ, ps.size_unknown
        ));
        lines.push(format!(
            "local-media-probe: zcloud zType={token} magic {}",
            magic_fields(&ps.magic)
        ));
    }
    Ok(lines)
}

// --- M2: the reverse-coverage walk -------------------------------------------

/// The walk's hard file cap (the brief's number).
const WALK_CAP: u64 = 200_000;

#[derive(Default)]
struct RevCov {
    uids: u64,
    uids_with_zdl: u64,
    files_seen: u64,
    rescache_skipped: u64,
    referenced: u64,
    cap_hit: bool,
    unref: BTreeMap<MediaSub, u64>,
    magic: BTreeMap<(MediaSub, MagicClass), u64>,
}

/// Walk `<root>\media\<uid>\ZaloDownloads\…` for EVERY uid and count
/// the files NO message row's `localPath` points at, per `<sub>`,
/// with a magic histogram (first 16 bytes only). `*.rescache` index
/// files are skipped; the walk stops hard at [`WALK_CAP`] files. No
/// path is ever printed — uid counts, `<sub>` counts, magic classes.
fn walk_reverse_coverage(root: &Path, refs: &HashSet<String>) -> RevCov {
    let mut rc = RevCov::default();
    let Ok(uids) = std::fs::read_dir(root.join("media")) else {
        return rc; // no media tree: an empty report, not an error
    };
    for uid in uids.flatten() {
        if !uid.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        rc.uids += 1;
        let zdl = uid.path().join("ZaloDownloads");
        if !zdl.is_dir() {
            continue;
        }
        rc.uids_with_zdl += 1;
        // An explicit stack: no recursion, no symlink following.
        let mut stack = vec![zdl];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let Ok(ft) = e.file_type() else {
                    continue;
                };
                if ft.is_dir() {
                    stack.push(e.path());
                    continue;
                }
                rc.files_seen += 1;
                if rc.files_seen > WALK_CAP {
                    rc.cap_hit = true;
                    return rc;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if name.to_ascii_lowercase().ends_with(".rescache") {
                    rc.rescache_skipped += 1;
                    continue;
                }
                let path_s = e.path().to_string_lossy().into_owned();
                let norm = norm_path(&path_s);
                if refs.contains(&norm) {
                    rc.referenced += 1;
                    continue;
                }
                let sub = classify_sub(&path_s);
                *rc.unref.entry(sub).or_insert(0) += 1;
                *rc
                    .magic
                    .entry((sub, magic_class(&head_16(&e.path()))))
                    .or_insert(0) += 1;
            }
        }
    }
    rc
}

fn reverse_coverage_lines(root: &Path, refs: &HashSet<String>) -> Vec<String> {
    let rc = walk_reverse_coverage(root, refs);
    let mut lines = vec![format!(
        "local-media-probe: reverse coverage: uids={} uids_with_zalodownloads={} files_seen={} \
         rescache_skipped={} referenced={} cap={} cap_hit={}",
        rc.uids,
        rc.uids_with_zdl,
        rc.files_seen,
        rc.rescache_skipped,
        rc.referenced,
        WALK_CAP,
        if rc.cap_hit { "yes" } else { "no" }
    )];
    let total: u64 = rc.unref.values().sum();
    for sub in SUB_FIELDS {
        let n = rc.unref.get(&sub).copied().unwrap_or(0);
        if n == 0 {
            continue;
        }
        let magic: Vec<String> = MAGIC_FIELDS
            .iter()
            .map(|m| {
                format!(
                    "{}:{}",
                    m.name(),
                    rc.magic.get(&(sub, *m)).copied().unwrap_or(0)
                )
            })
            .collect();
        lines.push(format!(
            "local-media-probe: unref sub={} count={} magic={}",
            sub.name(),
            n,
            magic.join(" ")
        ));
    }
    lines.push(format!("local-media-probe: unref total={total}"));
    lines
}

// --- M2: the report ----------------------------------------------------------

/// The `--local-media-probe` report (read-only; `out` writes the same
/// lines to a NEW file). Called by `import::run_local_media_probe`
/// after `prepare` — the snapshot guards have already passed and the
/// root exists.
pub fn probe_report(
    p: &Prepared,
    root: &Path,
    out: Option<&Path>,
) -> Result<Vec<String>, String> {
    // --out must be a NEW file — refuse before any work (the refusal
    // names the flag and the fact, never the path value — H-rule).
    if let Some(p_out) = out {
        if p_out.exists() {
            return Err("--out: file exists — refusing to overwrite".into());
        }
    }
    let root_norm = norm_path(&root.to_string_lossy());
    // The CLI already refused a --local-media-root that is not a
    // directory, so the header states the fact without echoing the
    // path value (H-rule, batch 27c).
    let mut lines = vec![
        "local-media-probe: root=given (exists) (read-only; the first 16 bytes and \
         metadata().len() are the only file facts ever gathered)"
            .into(),
        format!(
            "local-media-probe: snapshot profile={} (cold snapshot, mode=ro&immutable=1)",
            p.profile.name()
        ),
    ];

    // Preflight the fixed column list, then scan every message DB.
    preflight_columns(p, &MSG_COLS)?;
    let mut groups: BTreeMap<String, CodeCensus> = BTreeMap::new();
    let mut refs: HashSet<String> = HashSet::new();
    let stats = scan_message_dbs(p, &root_norm, &mut groups, &mut refs)?;
    lines.push(format!(
        "local-media-probe: message DBs: dbs={} opened={} open_failed={} query_failed={} \
         row_failed={} no_table={} rows={} coerce_none={}",
        stats.dbs,
        stats.opened,
        stats.open_failed,
        stats.query_failed,
        stats.row_failed,
        stats.no_table,
        stats.rows,
        coerce_none_field(&MSG_COERCE_COLS, &stats.coerce_none)
    ));
    lines.push(
        "== census by Desktop msgType (paths over the rows with a localPath) ==".into(),
    );
    lines.extend(census_lines(&groups));

    // The zcloud census (Index.db).
    lines.push("== zcloud (Core/Index.db, by zType) ==".into());
    lines.extend(zcloud_lines(p, &root_norm)?);

    // The reverse-coverage walk.
    lines.push("== reverse coverage (files no message row points at) ==".into());
    lines.extend(reverse_coverage_lines(root, &refs));

    if let Some(p_out) = out {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(p_out, body.as_bytes())
            .map_err(|e| format!("--out: write failed ({:?})", e.kind()))?;
        lines.push("local-media-probe: report written (--out)".into());
    }
    Ok(lines)
}

// --- M3: the pure plan decision ----------------------------------------------

/// One shadow attachment row the plan classifies (values stay in
/// memory; nothing here prints).
pub struct PlanAtt<'a> {
    /// The shadow `attachments.kind` (image | video | file | voice | …).
    pub kind: Option<&'a str>,
    /// The shadow `attachments.status`.
    pub status: &'a str,
}

/// The Desktop row facts for one message id (`None` = no Desktop row
/// carries it — `no_desktop_row`).
pub struct PlanDesk<'a> {
    pub local_path: Option<&'a str>,
    pub folder_path: Option<&'a str>,
}

/// The filesystem facts of the RESOLVED local path — gathered by the
/// caller with [`resolve_local`] + [`file_facts`] (the module's only
/// file reads).
pub struct PlanFs {
    pub under_root: bool,
    pub sub: MediaSub,
    pub exists: bool,
    pub size: Option<u64>,
    pub head: Vec<u8>,
}

impl PlanFs {
    /// Gather the facts for one resolved path (pure w.r.t. the DBs).
    pub fn of_resolved(resolved: &Path, root_norm: &str) -> PlanFs {
        let path_s = resolved.to_string_lossy().into_owned();
        let (exists, size, head) = file_facts(resolved);
        PlanFs {
            under_root: under_root(&norm_path(&path_s), root_norm),
            sub: classify_sub(&path_s),
            exists,
            size,
            head,
        }
    }
}

/// The plan's would-copy size cap (the store's own download cap).
pub const WOULD_COPY_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// One import-sourced attachment's plan outcome — exactly one per
/// row. The brief's eight labels plus `size_excluded` (the file
/// exists but its size is 0 or over the 512 MB cap — the would_copy
/// definition's own size clause, reported separately so no row is
/// silently mislabeled).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanOutcome {
    AlreadyDownloaded,
    WouldCopy,
    MagicMismatch,
    MissingFile,
    NoLocalPath,
    NoiseObfuscated,
    NoDesktopRow,
    OutsideRoot,
    SizeExcluded,
}

impl PlanOutcome {
    /// The report's field name (the brief's exact labels).
    pub fn field(self) -> &'static str {
        match self {
            PlanOutcome::AlreadyDownloaded => "already_downloaded",
            PlanOutcome::WouldCopy => "would_copy",
            PlanOutcome::MagicMismatch => "magic_mismatch",
            PlanOutcome::MissingFile => "missing_file",
            PlanOutcome::NoLocalPath => "no_local_path",
            PlanOutcome::NoiseObfuscated => "noise_obfuscated",
            PlanOutcome::NoDesktopRow => "no_desktop_row",
            PlanOutcome::OutsideRoot => "outside_root",
            PlanOutcome::SizeExcluded => "size_excluded",
        }
    }
}

/// The M3 decision, PURE over (attachment row, Desktop row, fs facts)
/// — unit-tested with synthetic inputs for every outcome. One row
/// lands in exactly one outcome, in this priority:
///
/// 1. the attachment is `downloaded` already — nothing to plan;
/// 2. no Desktop row carries this message id;
/// 3. the Desktop row has no `localPath`;
/// 4. the resolved path is outside `--local-media-root`;
/// 5. the path is under `fileNoise` — obfuscated, never decoded;
/// 6. the file does not exist;
/// 7. the size is 0 or over the 512 MB cap (`size_excluded`);
/// 8. the magic does not fit the shadow kind (M4: JXL is an image);
/// 9. otherwise `would_copy`.
///
/// `fs` is `None` only when the Desktop row has no usable path (the
/// caller passes `Some` whenever `desk` names a non-empty localPath);
/// a `None` here is classified `no_local_path` so the function is
/// total over its inputs.
pub fn plan_outcome(
    att: &PlanAtt,
    desk: Option<&PlanDesk>,
    fs: Option<&PlanFs>,
) -> PlanOutcome {
    if att.status == "downloaded" {
        return PlanOutcome::AlreadyDownloaded;
    }
    let Some(d) = desk else {
        return PlanOutcome::NoDesktopRow;
    };
    if d.local_path.filter(|l| !l.is_empty()).is_none() {
        return PlanOutcome::NoLocalPath;
    }
    let Some(f) = fs else {
        return PlanOutcome::NoLocalPath;
    };
    if !f.under_root {
        return PlanOutcome::OutsideRoot;
    }
    if f.sub == MediaSub::FileNoise {
        return PlanOutcome::NoiseObfuscated;
    }
    if !f.exists {
        return PlanOutcome::MissingFile;
    }
    let size = f.size.unwrap_or(0);
    if size == 0 || size > WOULD_COPY_MAX_BYTES {
        return PlanOutcome::SizeExcluded;
    }
    if !crate::shadow::media::magic_ok(att.kind, &f.head) {
        return PlanOutcome::MagicMismatch;
    }
    PlanOutcome::WouldCopy
}

// --- M3: the report ----------------------------------------------------------

/// One import-sourced attachment row as read from the store.
struct AttRow {
    msg_id: String,
    kind: Option<String>,
    status: String,
}

/// The plan's per-kind outcome counts, in the fixed field order.
#[derive(Default)]
struct KindOutcomes {
    rows: u64,
    outcomes: BTreeMap<PlanOutcome, u64>,
}

impl KindOutcomes {
    fn line(&self, kind: &str) -> String {
        let fields: Vec<String> = [
            PlanOutcome::AlreadyDownloaded,
            PlanOutcome::WouldCopy,
            PlanOutcome::MagicMismatch,
            PlanOutcome::MissingFile,
            PlanOutcome::NoLocalPath,
            PlanOutcome::NoiseObfuscated,
            PlanOutcome::NoDesktopRow,
            PlanOutcome::OutsideRoot,
            PlanOutcome::SizeExcluded,
        ]
        .iter()
        .map(|o| {
            format!(
                "{}={}",
                o.field(),
                self.outcomes.get(o).copied().unwrap_or(0)
            )
        })
        .collect();
        format!(
            "local-media-plan: kind={kind} rows={} {}",
            self.rows,
            fields.join(" ")
        )
    }
}

/// The `--local-media-plan` report (DRY RUN ONLY — no writes of any
/// kind). Called by `import::run_local_media_plan` after parse
/// guaranteed `--target` + `--local-media-root`; the root exists.
pub fn plan_report(
    a: &super::super::cli::ImportArgs,
    root: &Path,
    target: &Path,
) -> Result<Vec<String>, String> {
    // The store, READ-ONLY with the normal key resolution (the
    // `repair_cli`/`media_cli` pattern). A Locked passphrase store
    // refuses: this CLI never accepts a password, not on argv, not in
    // env.
    let db_path = crate::shadow::db_file(target);
    if !db_path.is_file() {
        return Err(format!(
            "--target: no {} — not a shadow store dir?",
            db_path.display()
        ));
    }
    let conn = match crate::shadow::passphrase::open_store(target, true) {
        Ok((c, _key)) => c,
        Err(crate::shadow::passphrase::StoreOpenError::Locked) => {
            return Err(
                "the target store is password-protected (passphrase mode): unlock it in the app \
                 with 'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the \
                 local-media plan CLI never accepts passwords"
                    .into(),
            )
        }
        Err(crate::shadow::passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ))
        }
    };

    // The snapshot (the usual import guards) — after the store, so a
    // Locked store fails fast without touching the snapshot.
    let p = super::prepare(a)?;
    let root_norm = norm_path(&root.to_string_lossy());

    // The import-sourced attachments (any status), ordered. Kinds
    // and statuses are shadow vocabulary words (shape); ids stay in
    // memory and never print.
    let sqlite_err = |e: rusqlite::Error| {
        format!(
            "store read failed ({})",
            crate::shadow::pipeline::sqlite_kind(&e)
        )
    };
    let mut st = conn
        .prepare(
            "SELECT a.msg_id, a.idx, a.kind, a.status
               FROM attachments a
               JOIN messages m ON m.msg_id = a.msg_id
              WHERE m.source = 'import'
              ORDER BY a.msg_id, a.idx",
        )
        .map_err(sqlite_err)?;
    let atts: Vec<AttRow> = st
        .query_map([], |r| {
            Ok(AttRow {
                msg_id: r.get(0)?,
                kind: r.get(2)?,
                status: r.get(3)?,
            })
        })
        .map_err(sqlite_err)?
        .filter_map(Result::ok)
        .collect();
    drop(st);

    // The membership sets for the M3 `no_attachment_row` census (all
    // sources: "no shadow attachment" is literal).
    let att_msg_ids: HashSet<String> = {
        let mut st = conn
            .prepare("SELECT DISTINCT msg_id FROM attachments")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    let msg_ids: HashSet<String> = {
        let mut st = conn
            .prepare("SELECT msg_id FROM messages")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };

    // The msg ids the plan needs Desktop rows for.
    let needed: HashSet<String> = atts.iter().map(|a| a.msg_id.clone()).collect();

    // Scan every message DB once: keep the Desktop row for each
    // needed msg id, and count the rows WITH a local file that have no
    // shadow attachment row at all (per Desktop msgType).
    preflight_columns(&p, &PLAN_COLS)?;
    let sql = msg_scan_sql(&PLAN_COLS)?;
    let names = super::message_db_names(&p.uid_dir)?;
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut desk_rows: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut no_attachment_row: BTreeMap<String, u64> = BTreeMap::new();
    let mut not_in_shadow: BTreeMap<String, u64> = BTreeMap::new();
    let mut scan = DbStats::default();
    for (name, kind) in &names {
        match kind {
            super::DbKind::OneToOne(_) | super::DbKind::Group(_) | super::DbKind::StrangerBox => {}
            _ => continue,
        }
        scan.dbs += 1;
        let Ok(dconn) =
            super::open_desktop_db(&msg_dir.join(name), p.passphrase.as_str(), p.profile)
        else {
            scan.open_failed += 1;
            continue;
        };
        scan.opened += 1;
        if !has_message_table(&dconn) {
            scan.no_table += 1;
            continue;
        }
        let Ok(mut st) = dconn.prepare(&sql) else {
            scan.query_failed += 1;
            continue;
        };
        // Batch 27c: the same tolerant reads as the probe census — the
        // old fixed-type reads silently skipped failed rows here
        // (`let Ok(..) = row else { continue }`); now every surprise is
        // counted and never drops the row.
        let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, SV>(0)?, // msgId
                r.get::<_, SV>(1)?, // msgType
                r.get::<_, SV>(2)?, // localPath
                r.get::<_, SV>(3)?, // folderPath
                r.get::<_, SV>(4)?, // fileSize (selected by the fixed list; counted, not used)
            ))
        }) else {
            scan.query_failed += 1;
            continue;
        };
        for row in rows {
            let Ok((msg_id, code, local, folder, fsize)) = row else {
                scan.row_failed += 1;
                continue;
            };
            scan.rows += 1;
            let msg_id = v_to_string(msg_id, "msgId", &mut scan.coerce_none);
            let (lp, fp) = (
                v_to_string(local, "localPath", &mut scan.coerce_none),
                v_to_string(folder, "folderPath", &mut scan.coerce_none),
            );
            // The decision uses the FILE's size, never this cell — it
            // is coerced so the header counts a surprise in it exactly
            // like the probe does.
            v_to_i64(fsize, "fileSize", &mut scan.coerce_none);
            let Some(msg_id) = msg_id else { continue };
            if needed.contains(&msg_id) {
                desk_rows.insert(msg_id.clone(), (lp.clone(), fp.clone()));
            }
            // The Goal's `no_attachment_row` census: a Desktop row
            // whose local file EXISTS, with no shadow attachment row
            // for its message id — split by whether the shadow knows
            // the message at all.
            if !att_msg_ids.contains(&msg_id) {
                let Some(local) = lp else { continue };
                let resolved = resolve_local(&local, fp.as_deref());
                if file_facts(&resolved).0 {
                    let token = render_value(&code);
                    if msg_ids.contains(&msg_id) {
                        *no_attachment_row.entry(token).or_insert(0) += 1;
                    } else {
                        *not_in_shadow.entry(token).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // Classify every attachment (the pure decision over gathered
    // facts) and sum what would_copy would add.
    let mut kinds: BTreeMap<String, KindOutcomes> = BTreeMap::new();
    let mut would_copy_bytes: u64 = 0;
    let mut matched = 0u64;
    for att in &atts {
        let kind = att.kind.clone().unwrap_or_else(|| "none".into());
        let ko = kinds.entry(kind).or_default();
        ko.rows += 1;
        let desk_view = desk_rows.get(&att.msg_id).map(|(l, f)| PlanDesk {
            local_path: l.as_deref(),
            folder_path: f.as_deref(),
        });
        let fs_view = match &desk_view {
            Some(d) if d.local_path.filter(|l| !l.is_empty()).is_some() => {
                let resolved = resolve_local(d.local_path.unwrap_or_default(), d.folder_path);
                matched += 1;
                Some(PlanFs::of_resolved(&resolved, &root_norm))
            }
            _ => None,
        };
        let att_view = PlanAtt {
            kind: att.kind.as_deref(),
            status: att.status.as_str(),
        };
        let outcome = plan_outcome(&att_view, desk_view.as_ref(), fs_view.as_ref());
        if outcome == PlanOutcome::WouldCopy {
            would_copy_bytes += fs_view.as_ref().and_then(|f| f.size).unwrap_or(0);
        }
        *ko.outcomes.entry(outcome).or_insert(0) += 1;
    }

    let mut lines = vec![
        "local-media-plan: DRY RUN ONLY — no writes of any kind (no DB, no files, no temp \
         copies); copying files into the store is a later, user-approved batch"
            .into(),
        // H-rule (batch 27c): the header states the facts without
        // echoing the --target / --local-media-root path values.
        "local-media-plan: store=given (read-only; the app may keep running)".into(),
        "local-media-plan: root=given (exists) (the first 16 bytes and metadata().len() are \
         the only file facts ever gathered)"
            .into(),
        format!(
            "local-media-plan: snapshot profile={} message DBs dbs={} opened={} \
             open_failed={} query_failed={} no_table={} rows={} row_failed={} coerce_none={}",
            p.profile.name(),
            scan.dbs,
            scan.opened,
            scan.open_failed,
            scan.query_failed,
            scan.no_table,
            scan.rows,
            scan.row_failed,
            coerce_none_field(&PLAN_COERCE_COLS, &scan.coerce_none)
        ),
        format!(
            "local-media-plan: import-sourced attachments: rows={} desktop_rows_matched={} \
             kinds={}",
            atts.len(),
            matched,
            kinds.len()
        ),
    ];
    for (kind, ko) in &kinds {
        lines.push(ko.line(kind));
    }
    lines.push(format!("local-media-plan: total would_copy bytes={would_copy_bytes}"));
    // The Goal's `no_attachment_row` census, per Desktop msgType code.
    lines.push(
        "local-media-plan: desktop rows with a local file, by msgType (no_attachment_row = the \
         shadow knows the message but has no attachment row for it; not_in_shadow = the message \
         was never imported at all)"
            .into(),
    );
    let mut nar: Vec<(&String, &u64)> = no_attachment_row.iter().collect();
    nar.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (token, n) in nar.iter().take(CODE_CAP) {
        lines.push(format!(
            "local-media-plan:   msgType={token} no_attachment_row={n} not_in_shadow={}",
            not_in_shadow.get(*token).copied().unwrap_or(0)
        ));
    }
    if nar.is_empty() {
        lines.push("local-media-plan:   none".into());
    }
    lines.push("local-media-plan: done (DRY RUN ONLY — nothing was written)".into());
    Ok(lines)
}

#[cfg(test)]
mod tests {
    //! Synthetic fixtures ONLY — every file lives under the OS temp
    //! dir; the real snapshot, the real store and the real local
    //! media folder are never touched (the hard rule). No test calls
    //! the network. The M3 decision is PURE and is tested with
    //! constructed inputs; the CLI-level fixtures (Windows: DPAPI
    //! d7 key files) drive the real paths end to end.

    use super::*;

    // --- the pure helpers ------------------------------------------------

    #[test]
    fn path_shape_classes() {
        assert_eq!(path_shape(r"D:\Zalo Data\media"), PathShape::AbsDrive);
        assert_eq!(path_shape("d:/zalo data/media"), PathShape::AbsDrive);
        assert_eq!(path_shape(r"\\server\share\f.jxl"), PathShape::AbsUnc);
        assert_eq!(
            path_shape(r"media\u\ZaloDownloads\picture\f.jxl"),
            PathShape::Relative
        );
        assert_eq!(path_shape("file:///C:/Users/x/f.jpg"), PathShape::FileUrl);
        assert_eq!(path_shape("FILE://C:/x"), PathShape::FileUrl);
        assert_eq!(path_shape("https://cdn.zdn.vn/f.jpg"), PathShape::Other);
        assert_eq!(path_shape("http://x/f.jpg"), PathShape::Other);
        assert_eq!(path_shape(""), PathShape::Other);
        // A drive letter without a following separator is a relative
        // path, not a drive (fail-closed for the join).
        assert_eq!(path_shape("C:x.txt"), PathShape::Relative);
    }

    #[test]
    fn under_root_is_case_insensitive_with_a_boundary() {
        let root = norm_path(r"D:\Zalo Data");
        assert!(under_root(&norm_path(r"d:\zalo data"), &root));
        assert!(under_root(
            &norm_path(r"D:\Zalo Data\media\u\ZaloDownloads\picture\f.jxl"),
            &root
        ));
        assert!(under_root(
            &norm_path(r"\\?\D:\Zalo Data\media\u\f.jxl"),
            &root
        ));
        // A sibling with a shared prefix is NOT under the root.
        assert!(!under_root(&norm_path(r"D:\Zalo Data2\f.jxl"), &root));
        assert!(!under_root(&norm_path(r"E:\Zalo Data\f.jxl"), &root));
        assert!(!under_root(&norm_path(r"media\rel\f.jxl"), &root));
    }

    #[test]
    fn classify_sub_vocabulary_and_other() {
        let mk = |sub: &str| format!(r"D:\Zalo Data\media\19\ZaloDownloads\{sub}\afile");
        assert_eq!(classify_sub(&mk("picture")), MediaSub::Picture);
        assert_eq!(classify_sub(&mk("video")), MediaSub::Video);
        assert_eq!(classify_sub(&mk("file")), MediaSub::File);
        assert_eq!(classify_sub(&mk("fileNoise")), MediaSub::FileNoise);
        assert_eq!(classify_sub(&mk("fileThumb")), MediaSub::FileThumb);
        assert_eq!(classify_sub(&mk("voice")), MediaSub::Voice);
        assert_eq!(classify_sub(&mk("richThumb")), MediaSub::RichThumb);
        assert_eq!(classify_sub(&mk("zinstant")), MediaSub::Zinstant);
        assert_eq!(classify_sub(&mk("resource")), MediaSub::Resource);
        assert_eq!(classify_sub(&mk("Cache")), MediaSub::Cache);
        // Case-insensitive, and the vocabulary is all that can print.
        assert_eq!(classify_sub(&mk("PICTURE")), MediaSub::Picture);
        assert_eq!(classify_sub(&mk("weirdSub")), MediaSub::Other);
        // The sticker tree sits beside ZaloDownloads.
        assert_eq!(
            classify_sub(r"D:\Zalo Data\media\19\sticker\an_anim"),
            MediaSub::Sticker
        );
        // No ZaloDownloads, no sticker: other.
        assert_eq!(classify_sub(r"D:\elsewhere\f.jpg"), MediaSub::Other);
        // ZaloDownloads as the LAST segment: other.
        assert_eq!(
            classify_sub(r"D:\Zalo Data\media\19\ZaloDownloads"),
            MediaSub::Other
        );
    }

    #[test]
    fn magic_class_table() {
        assert_eq!(magic_class(&[0xFF, 0xD8, 0xFF, 0xE0]), MagicClass::Jpg);
        assert_eq!(magic_class(&[0x89, 0x50, 0x4E, 0x47]), MagicClass::Png);
        assert_eq!(magic_class(b"GIF89a"), MagicClass::Gif);
        assert_eq!(
            magic_class(&[b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P']),
            MagicClass::Webp
        );
        assert_eq!(magic_class(&[0xFF, 0x0A, 0xE0]), MagicClass::Jxl);
        assert_eq!(
            magic_class(&[
                0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A
            ]),
            MagicClass::JxlContainer
        );
        assert_eq!(
            magic_class(&[0, 0, 0, 0, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm']),
            MagicClass::Mp4
        );
        assert_eq!(magic_class(&[0x1A, 0x45, 0xDF, 0xA3, 1]), MagicClass::WebmMkv);
        assert_eq!(magic_class(b"%PDF-1.7\n"), MagicClass::Pdf);
        assert_eq!(magic_class(&[0x50, 0x4B, 0x03, 0x04, 1, 2]), MagicClass::Zip);
        assert_eq!(magic_class(b"<!doctype html>"), MagicClass::Html);
        assert_eq!(magic_class(b"  \n<HTML lang=\"vi\">"), MagicClass::Html);
        assert_eq!(magic_class(&[0x37, 0x9E, 0x2C, 0xF1]), MagicClass::Other);
        assert_eq!(magic_class(&[]), MagicClass::Other);
        assert_eq!(magic_class(b"PK\x05\x06"), MagicClass::Zip, "empty EOCD zip");
    }

    #[test]
    fn name_relations() {
        // A 13-digit run equal to sendDttm.
        assert!(name_has_dttm("p1763600000000_abc123.jxl", 1_763_600_000_000));
        assert!(!name_has_dttm("p1763600000000_abc123.jxl", 1_763_600_000_001));
        // A 12- or 14-digit run never matches.
        assert!(!name_has_dttm("x176360000000.jxl", 1_763_600_000_000));
        assert!(!name_has_dttm("x17636000000001.jxl", 1_763_600_000_000));
        // The digits must be a whole run, bounded by non-digits.
        assert!(name_has_dttm("a1763600000000", 1_763_600_000_000));
        // Non-positive and unknown values never match.
        assert!(!name_has_dttm("a1763600000000", 0));
        assert!(!name_has_dttm("a1763600000000", -1));
    }

    // --- batch 27c: the tolerant column reads ---------------------------------

    #[test]
    fn v_to_string_coercions() {
        let mut c: CoerceNone = BTreeMap::new();
        // Text as is; empty text and Null are absent values, not surprises.
        assert_eq!(
            v_to_string(SV::Text("x".into()), "localPath", &mut c),
            Some("x".into())
        );
        assert_eq!(v_to_string(SV::Text(String::new()), "localPath", &mut c), None);
        assert_eq!(v_to_string(SV::Null, "localPath", &mut c), None);
        // Integer/Real as their decimal string.
        assert_eq!(
            v_to_string(SV::Integer(999_888_777_666), "cliMsgId", &mut c),
            Some("999888777666".into())
        );
        assert_eq!(
            v_to_string(SV::Real(4.5), "localPath", &mut c),
            Some("4.5".into())
        );
        assert_eq!(
            v_to_string(SV::Real(42.0), "localPath", &mut c),
            Some("42".into())
        );
        // A Blob is a counted surprise — and never a dropped row.
        assert_eq!(
            v_to_string(SV::Blob(vec![1, 2, 3]), "previewThumb", &mut c),
            None
        );
        assert_eq!(c.get("previewThumb"), Some(&1));
        assert!(c.get("localPath").is_none());
        assert!(c.get("cliMsgId").is_none());
    }

    #[test]
    fn v_to_i64_coercions() {
        let mut c: CoerceNone = BTreeMap::new();
        assert_eq!(
            v_to_i64(SV::Integer(1_763_600_000_000), "sendDttm", &mut c),
            Some(1_763_600_000_000)
        );
        // TEXT digits — the real Desktop shape (`sendDttm:TEXT`).
        assert_eq!(
            v_to_i64(SV::Text("1763600000000".into()), "sendDttm", &mut c),
            Some(1_763_600_000_000)
        );
        // Text parses after trim.
        assert_eq!(
            v_to_i64(SV::Text(" 2048 ".into()), "fileSize", &mut c),
            Some(2048)
        );
        // Null is absent, not a surprise.
        assert_eq!(v_to_i64(SV::Null, "fileSize", &mut c), None);
        // Non-numeric text / a Real / a Blob: None, counted.
        assert_eq!(v_to_i64(SV::Text("unknown".into()), "fileSize", &mut c), None);
        assert_eq!(v_to_i64(SV::Real(4.5), "fileSize", &mut c), None);
        assert_eq!(v_to_i64(SV::Blob(b"x".to_vec()), "sendDttm", &mut c), None);
        assert_eq!(c.get("fileSize"), Some(&2)); // 'unknown' + the Real
        assert_eq!(c.get("sendDttm"), Some(&1)); // the Blob
    }

    #[test]
    fn coerce_none_field_renders_the_fixed_column_order() {
        let mut c: CoerceNone = BTreeMap::new();
        assert_eq!(coerce_none_field(&MSG_COERCE_COLS, &c), "none");
        *c.entry("sendDttm").or_insert(0) += 2;
        *c.entry("fileSize").or_insert(0) += 1;
        // MSG_COLS order puts fileSize before sendDttm; the plan list
        // has no sendDttm at all; zcloud neither.
        assert_eq!(
            coerce_none_field(&MSG_COERCE_COLS, &c),
            "fileSize:1,sendDttm:2"
        );
        assert_eq!(coerce_none_field(&PLAN_COERCE_COLS, &c), "fileSize:1");
        assert_eq!(coerce_none_field(&ZCLOUD_COERCE_COLS, &c), "none");
    }

    // --- M3: the pure decision, every outcome --------------------------------

    fn desk<'a>(local: Option<&'a str>, folder: Option<&'a str>) -> PlanDesk<'a> {
        PlanDesk {
            local_path: local,
            folder_path: folder,
        }
    }

    fn fs(under: bool, sub: MediaSub, exists: bool, size: u64, head: &[u8]) -> PlanFs {
        PlanFs {
            under_root: under,
            sub,
            exists,
            size: Some(size),
            head: head.to_vec(),
        }
    }

    #[test]
    fn plan_outcome_every_branch() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1];
        let jxl_bare = [0xFF, 0x0A, 0xE0, 0x0D];
        let jxl_box = [
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 0x00,
        ];
        let cipher = [0x37, 0x9E, 0x2C, 0xF1, 9];

        // 1. already_downloaded wins over everything.
        for (desk_v, fs_v) in [
            (None, None),
            (Some(desk(None, None)), None),
            (
                Some(desk(Some(r"D:\elsewhere\x"), None)),
                Some(fs(false, MediaSub::Other, false, 0, &[])),
            ),
        ] {
            assert_eq!(
                plan_outcome(
                    &PlanAtt { kind: Some("image"), status: "downloaded" },
                    desk_v.as_ref(),
                    fs_v.as_ref()
                ),
                PlanOutcome::AlreadyDownloaded,
                "downloaded is checked first"
            );
        }

        // 2. no_desktop_row.
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref-import" },
                None,
                None
            ),
            PlanOutcome::NoDesktopRow
        );

        // 3. no_local_path (the Desktop row exists but carries no
        // usable path; a None fs with a desk row is the same total
        // classification).
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref-import" },
                Some(&desk(None, None)),
                None
            ),
            PlanOutcome::NoLocalPath
        );
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref" },
                Some(&desk(Some(""), None)),
                None
            ),
            PlanOutcome::NoLocalPath
        );

        // 4. outside_root.
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref" },
                Some(&desk(Some(r"D:\elsewhere\pic\x.jpg"), None)),
                Some(&fs(false, MediaSub::Other, true, 10, &jpeg))
            ),
            PlanOutcome::OutsideRoot
        );

        // 5. noise_obfuscated — under fileNoise, before existence:
        // the contents are never decoded (H-rule).
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("file"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\media\19\ZaloDownloads\fileNoise\x32"), None)),
                Some(&fs(true, MediaSub::FileNoise, true, 10, &cipher))
            ),
            PlanOutcome::NoiseObfuscated
        );
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("file"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\media\19\ZaloDownloads\fileNoise\x32"), None)),
                Some(&fs(true, MediaSub::FileNoise, false, 0, &[]))
            ),
            PlanOutcome::NoiseObfuscated,
            "fileNoise is about the PATH, not the file"
        );

        // 6. missing_file.
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\picture\gone.jxl"), None)),
                Some(&fs(true, MediaSub::Picture, false, 0, &[]))
            ),
            PlanOutcome::MissingFile
        );

        // 7. size_excluded — 0 bytes and over the 512 MB cap (the
        // would_copy definition's own size clause).
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\picture\empty.jxl"), None)),
                Some(&fs(true, MediaSub::Picture, true, 0, &[]))
            ),
            PlanOutcome::SizeExcluded
        );
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("video"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\video\huge"), None)),
                Some(&fs(true, MediaSub::Video, true, WOULD_COPY_MAX_BYTES + 1, &[]))
            ),
            PlanOutcome::SizeExcluded
        );

        // 8. magic_mismatch — image/video are sniffed (M4: JXL is an
        // image); file/voice never are.
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("image"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\picture\c.jpg"), None)),
                Some(&fs(true, MediaSub::Picture, true, 10, &cipher))
            ),
            PlanOutcome::MagicMismatch
        );
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: Some("video"), status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\video\v"), None)),
                Some(&fs(true, MediaSub::Video, true, 10, &jpeg))
            ),
            PlanOutcome::MagicMismatch
        );

        // 9. would_copy — jpeg, JXL in both forms (M4), and the
        // unsniffed kinds accept anything.
        for (kind, head) in [
            (Some("image"), &jpeg[..]),
            (Some("image"), &jxl_bare[..]),
            (Some("image"), &jxl_box[..]),
            (Some("file"), &cipher[..]),
            (Some("voice"), &cipher[..]),
            (None, &cipher[..]),
        ] {
            assert_eq!(
                plan_outcome(
                    &PlanAtt { kind, status: "ref-import" },
                    Some(&desk(Some(r"D:\Zalo Data\...\picture\a.jxl"), None)),
                    Some(&fs(true, MediaSub::Picture, true, 1_000, head))
                ),
                PlanOutcome::WouldCopy,
                "kind={:?}",
                kind
            );
        }
        // The cap boundary itself copies (an unsniffed kind never
        // fails the magic check, so the size decision is what fires).
        assert_eq!(
            plan_outcome(
                &PlanAtt { kind: None, status: "ref" },
                Some(&desk(Some(r"D:\Zalo Data\...\video\v"), None)),
                Some(&fs(true, MediaSub::Video, true, WOULD_COPY_MAX_BYTES, &[]))
            ),
            PlanOutcome::WouldCopy,
            "the 512 MB cap is inclusive"
        );
    }

    // --- the CLI-level fixtures (Windows: the D7 DPAPI wrap) ------------------

    #[cfg(windows)]
    mod cli_fixtures {
        use super::super::*;
        use super::super::super::{apply_passphrase_key, prepare, sha12, SNAPSHOT_MANIFEST};
        use super::super::super::super::cli::ImportArgs;
        use crate::migrate::sqlcipher;
        use rusqlite::Connection;
        use serde_json::json;
        use std::path::{Path, PathBuf};
        use zeroize::Zeroizing;

        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        fn temp_dir(tag: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "zr-local-media-{tag}-{}-{}-{}",
                std::process::id(),
                crate::shadow::schema::now_ms(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// SQL-quote a string literal for the fixture SQL.
        fn q(s: &str) -> String {
            s.replace('\'', "''")
        }

        /// The default fixture `message` DDL: the REAL column names with
        /// `sendDttm` INTEGER (well-typed rows for the shape tests).
        const FIXTURE_DDL: &str = "CREATE TABLE message (
    msgId TEXT PRIMARY KEY, cliMsgId TEXT, msgType INTEGER,
    localPath TEXT, folderPath TEXT, previewThumb TEXT,
    fileSize INTEGER, sendDttm INTEGER, message TEXT
  );";

        /// A synthetic Desktop message DB with the REAL column names
        /// (the fixed SELECT set). `rows` is the INSERT SQL.
        fn make_msg_db(path: &Path, pass: &str, rows: &str) {
            make_msg_db_with_ddl(path, pass, FIXTURE_DDL, rows);
        }

        /// The same, with a caller-supplied `message` DDL — the batch-27c
        /// regression uses the REAL Desktop declared types.
        fn make_msg_db_with_ddl(path: &Path, pass: &str, ddl: &str, rows: &str) {
            let conn = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            )
            .unwrap();
            apply_passphrase_key(&conn, pass).unwrap();
            conn.execute_batch(&format!("{ddl}\n{rows}")).unwrap();
            conn.close().map_err(|(_, e)| e).unwrap();
        }

        /// A snapshot with one message DB + a zcloud-bearing Index.db +
        /// a D7 key file; returns (dir, key path).
        fn synthetic_snapshot(pass: &str, rows: &str) -> (PathBuf, PathBuf) {
            let dir = temp_dir("snap");
            std::fs::write(
                dir.join(SNAPSHOT_MANIFEST),
                json!({
                    "created": 1763600000000i64,
                    "source_root_sha12": "aaaaaaaaaaaa",
                    "files": [ { "rel": "Core\\Index.db", "size": 4096u64, "mtime": 1i64 } ]
                })
                .to_string(),
            )
            .unwrap();
            let core = dir.join("Core");
            std::fs::create_dir_all(core.join("Message")).unwrap();
            {
                let conn = Connection::open_with_flags(
                    &core.join("Index.db"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                )
                .unwrap();
                apply_passphrase_key(&conn, pass).unwrap();
                conn.execute_batch(
                    "CREATE TABLE zcloud (localPath TEXT, mediaInfo TEXT, zConv TEXT, \
                      zType INTEGER, zSize INTEGER);
                     INSERT INTO zcloud (localPath, mediaInfo, zConv, zType, zSize) VALUES \
                       (NULL, 'm', 'z', 1, NULL);",
                )
                .unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }
            make_msg_db(&core.join("Message").join("111.db"), pass, rows);
            let key = dir.join("d7.bin");
            let payload = json!({
                "date": "2026-11-21T00:00:00Z",
                "target_sha12": sha12(pass.as_bytes()),
                "value_len": pass.len() as u64,
                "value": pass,
            });
            sqlcipher::save_key(payload.to_string().as_bytes(), &key).unwrap();
            (dir, key)
        }

        /// A FAKE shadow store (raw key) with import messages and, for
        /// each row with a url, an attachment row.
        fn synthetic_store(rows: &[(&str, &str, Option<&str>, &str)]) -> PathBuf {
            let dir = temp_dir("store");
            let key = Zeroizing::new(sqlcipher::generate_key().unwrap());
            sqlcipher::save_key(&key, &crate::shadow::key_file(&dir)).unwrap();
            {
                let conn =
                    sqlcipher::open_with_key(&crate::shadow::db_file(&dir), &key).unwrap();
                crate::shadow::schema::apply(&conn).unwrap();
                for (mid, kind, url, status) in rows {
                    conn.execute(
                        "INSERT INTO messages (msg_id, conv_id, ts, type, payload_json, source)
                         VALUES (?1, 'cM', 1, 1, '{}', 'import')",
                        [mid],
                    )
                    .unwrap();
                    if let Some(url) = url {
                        conn.execute(
                            "INSERT INTO attachments (msg_id, idx, kind, url, status)
                             VALUES (?1, 0, ?2, ?3, ?4)",
                            rusqlite::params![mid, kind, url, status],
                        )
                        .unwrap();
                    }
                }
            }
            dir
        }

        fn args_for(dir: &Path, uin: &str, key: &Path) -> ImportArgs {
            ImportArgs {
                from_snapshot: dir.to_path_buf(),
                account: "default".into(),
                uin_hash: uin.into(),
                key_file: Some(key.to_path_buf()),
                cipher_compat: None,
                inventory: false,
                out: None,
                mapping: None,
                shadow_copy: None,
                delta: false,
                distinct: Vec::new(),
                all_dbs: false,
                own_uid_from_settings: false,
                target: None,
                i_have_a_backup_plan: false,
                unmapped_as_raw: false,
                media_plan: false,
                local_media_probe: false,
                local_media_plan: false,
                local_media_root: None,
                content_shape: None,
                by: None,
                decrypt_basic: false,
                apply: false,
                help: false,
            }
        }

        const PASS: &str = "fakefakefakefakefakefakefake1234";
        const DTTM: i64 = 1_763_600_000_000;

        /// The REAL Desktop `message` declared types (reviewer excerpt,
        /// batch 27c): `msgId:TEXT pk, cliMsgId:TEXT, msgType:INTEGER,
        /// sendDttm:TEXT, localPath:TEXT, folderPath:TEXT,
        /// previewThumb:TEXT, fileSize:INTEGER`. A TEXT-affinity column
        /// holds TEXT even when the value is digits, and an
        /// INTEGER-affinity column keeps non-numeric text as text — the
        /// old fixed-type reads dropped EVERY row of such a table.
        const REAL_DESKTOP_DDL: &str = "CREATE TABLE message (
    msgId TEXT PRIMARY KEY, cliMsgId TEXT, msgType INTEGER,
    sendDttm TEXT, localPath TEXT, folderPath TEXT,
    previewThumb TEXT, fileSize INTEGER
  );";

        /// A variant DB schema with the SAME column names (one of the
        /// 1 472 real DBs may be built differently): a `cliMsgId` with
        /// no declared type keeps a true INTEGER storage class, and a
        /// TEXT `fileSize` keeps numeric TEXT as text.
        const VARIANT_DDL: &str = "CREATE TABLE message (
    msgId TEXT PRIMARY KEY, cliMsgId, msgType INTEGER,
    sendDttm TEXT, localPath TEXT, folderPath TEXT,
    previewThumb TEXT, fileSize TEXT
  );";

        /// The batch-27c regression snapshot: `111.db` with the REAL
        /// excerpt types — sendDttm TEXT digits (the shape that dropped
        /// every row under the old fixed-type reads), cliMsgId inserted
        /// as an INTEGER value (TEXT affinity converts the storage; the
        /// true INTEGER storage class lives in `222.db`), fileSize once
        /// as INTEGER, once as numeric TEXT (INTEGER affinity converts
        /// the storage; true numeric TEXT lives in `222.db`) and once
        /// as NON-numeric text — the counted surprise. Returns
        /// (snapshot dir, key path).
        fn real_types_snapshot(pic_file: &Path) -> (PathBuf, PathBuf) {
            let (snap, key) = synthetic_snapshot(PASS, "");
            // Replace 111.db's schema with the excerpt types (the
            // snapshot helper created it with the fixture DDL).
            {
                let conn = Connection::open_with_flags(
                    snap.join("Core").join("Message").join("111.db"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                )
                .unwrap();
                apply_passphrase_key(&conn, PASS).unwrap();
                conn.execute_batch("DROP TABLE message;").unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }
            let rows111 = format!(
                "INSERT INTO message (msgId, cliMsgId, msgType, sendDttm, localPath, \
                 folderPath, previewThumb, fileSize) VALUES \
                 ('8488000000101', 999888777666, 2, '1763600000000', '{jxl}', NULL, 'pv', 4); \
                 INSERT INTO message (msgId, cliMsgId, msgType, sendDttm, localPath, \
                 folderPath, previewThumb, fileSize) VALUES \
                 ('8488000000102', 'c102', 2, '1763600000001', NULL, NULL, NULL, '2048'); \
                 INSERT INTO message (msgId, cliMsgId, msgType, sendDttm, localPath, \
                 folderPath, previewThumb, fileSize) VALUES \
                 ('8488000000103', 'c103', 2, '1763600000002', NULL, NULL, NULL, \
                  'not-a-number');",
                jxl = q(&pic_file.to_string_lossy()),
            );
            make_msg_db_with_ddl(
                &snap.join("Core").join("Message").join("111.db"),
                PASS,
                REAL_DESKTOP_DDL,
                &rows111,
            );
            // The variant DB: a true INTEGER cliMsgId (42) and a true
            // numeric-TEXT fileSize ('4096').
            make_msg_db_with_ddl(
                &snap.join("Core").join("Message").join("222.db"),
                PASS,
                VARIANT_DDL,
                "INSERT INTO message (msgId, cliMsgId, msgType, sendDttm, localPath, \
                 folderPath, previewThumb, fileSize) VALUES \
                 ('8488000000104', 42, 5, '1763600000003', NULL, NULL, NULL, '4096');",
            );
            (snap, key)
        }

        /// The fake media root: one referenced JXL, one unreferenced
        /// JPEG, a rescache index, and one video file with no
        /// extension, all under `media\19\ZaloDownloads\…`.
        fn synthetic_media_root() -> PathBuf {
            let root = temp_dir("root");
            let pic = root
                .join("media")
                .join("19")
                .join("ZaloDownloads")
                .join("picture");
            std::fs::create_dir_all(&pic).unwrap();
            std::fs::write(
                pic.join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl")),
                [0xFFu8, 0x0A, 0xE0, 0x0D],
            )
            .unwrap();
            std::fs::write(pic.join("othername_01.jpg"), [0xFFu8, 0xD8, 0xFF, 0xE0, 1]).unwrap();
            std::fs::write(pic.join("index.rescache"), b"opaque").unwrap();
            let vid = root
                .join("media")
                .join("19")
                .join("ZaloDownloads")
                .join("video");
            std::fs::create_dir_all(&vid).unwrap();
            std::fs::write(
                vid.join(format!("{DTTM}")),
                [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2],
            )
            .unwrap();
            root
        }

        #[test]
        fn probe_report_counts_shapes_only() {
            let root = synthetic_media_root();
            let pic_file = root
                .join("media")
                .join("19")
                .join("ZaloDownloads")
                .join("picture")
                .join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl"));
            let rows = format!(
                "INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('8488000000001', 'cli0001', 2, '{jxl}', NULL, 'pv', 4, {DTTM}, 'never read'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('8488000000002', 'cli0002', 1, NULL, NULL, NULL, NULL, {DTTM}, 'never read'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('8488000000003', 'cli0003', 18, 'relvideo.mp4', '{root}', NULL, NULL, NULL, \
                  'never read');",
                jxl = q(&pic_file.to_string_lossy()),
                root = q(&root.to_string_lossy()),
            );
            let (snap, key) = synthetic_snapshot(PASS, &rows);
            // A zcloud row pointing at the referenced JXL (zSize
            // deliberately wrong: 10 vs the real 4).
            {
                let conn = Connection::open_with_flags(
                    snap.join("Core").join("Index.db"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                )
                .unwrap();
                apply_passphrase_key(&conn, PASS).unwrap();
                conn.execute(
                    "INSERT INTO zcloud (localPath, mediaInfo, zConv, zType, zSize) VALUES \
                     (?1, 'm', 'z', 1, 10)",
                    [pic_file.to_string_lossy().into_owned()],
                )
                .unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let lines = probe_report(&p, &root, None).unwrap();
            let joined = lines.join("\n");
            assert!(
                joined
                    .contains("local-media-probe: message DBs: dbs=1 opened=1 open_failed=0"),
                "{joined}"
            );
            // msgType 2: one row with a localPath, under the root,
            // picture, exists, size match, jxl magic.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 rows=1 localpath=1 folderpath=0 previewthumb=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 paths shape=abs_drive:1 abs_unc:0 relative:0 \
                     file_url:0 other:0 under_root=yes:1 no:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(&format!(
                    "local-media-probe: msgType=2 paths sub=picture:1 video:0 file:0 \
                     fileNoise:0 fileThumb:0 voice:0 richThumb:0 zinstant:0 resource:0 Cache:0 \
                     sticker:0 other:0"
                )),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 files exists=yes:1 no:0 size=match:1 differ:0 \
                     unknown:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 magic jpg:0 png:0 gif:0 webp:0 jxl:1 \
                     jxl_container:0 mp4:0 webm_mkv:0 pdf:0 zip:0 html:0 other:0"
                ),
                "{joined}"
            );
            // The msgId and cliMsgId are NOT inside the file name; the
            // 13-digit sendDttm IS.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 name msgid=yes:0 no:1 na:0 climsgid=yes:0 \
                     no:1 na:0 senddttm=yes:1 no:0 na:0"
                ),
                "{joined}"
            );
            // msgType 1: one row, no localPath at all.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=1 rows=1 localpath=0 folderpath=0 previewthumb=0"
                ),
                "{joined}"
            );
            // msgType 18: a RELATIVE localPath resolved via folderPath.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=18 paths shape=abs_drive:0 abs_unc:0 relative:1 \
                     file_url:0 other:0 under_root=yes:1 no:0"
                ),
                "{joined}"
            );
            // H-rule self-check: no path value, file name, uid, msgId
            // or message text anywhere.
            for banned in [
                "8488000000001",
                "cli0001",
                "never read",
                "p1763600000000",
                "othername",
                "index.rescache",
                "relvideo",
            ] {
                assert!(!joined.contains(banned), "a value leaked: {banned}\n{joined}");
            }
            // The zcloud census: one NULL-path row + one JXL row.
            assert!(joined.contains("local-media-probe: zcloud rows=2"), "{joined}");
            assert!(
                joined.contains("local-media-probe: zcloud zType=1 rows=2 localpath=1"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: zcloud zType=1 files exists=yes:1 no:0 size=match:0 \
                     differ:1 unknown:0 (vs zSize)"
                ),
                "{joined}"
            );
            // The reverse coverage: only the JXL is referenced (the
            // relative row points at root\relvideo.mp4, not the video
            // file); the JPEG and the mp4 are unref; the rescache is
            // skipped.
            assert!(
                joined.contains(
                    "local-media-probe: reverse coverage: uids=1 uids_with_zalodownloads=1 \
                     files_seen=4 rescache_skipped=1 referenced=1 cap=200000 cap_hit=no"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: unref sub=picture count=1 magic=jpg:1 png:0 gif:0 webp:0 \
                     jxl:0 jxl_container:0 mp4:0 webm_mkv:0 pdf:0 zip:0 html:0 other:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: unref sub=video count=1 magic=jpg:0 png:0 gif:0 webp:0 \
                     jxl:0 jxl_container:0 mp4:1 webm_mkv:0 pdf:0 zip:0 html:0 other:0"
                ),
                "{joined}"
            );
            assert!(joined.contains("local-media-probe: unref total=2"), "{joined}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn probe_report_out_refuses_overwrite_and_writes_the_report() {
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(
                PASS,
                "INSERT INTO message (msgId, cliMsgId, msgType, message) VALUES \
                 ('8488000000009', 'cli9', 1, 'x');",
            );
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let report = snap.join("probe-report.txt");
            let lines = probe_report(&p, &root, Some(&report)).unwrap();
            assert!(report.is_file(), "{report:?}");
            let written = String::from_utf8(std::fs::read(&report).unwrap()).unwrap();
            for l in &lines {
                if l.starts_with("local-media-probe: report written") {
                    continue; // the stdout-only ack (H-rule: no path echo)
                }
                assert!(written.contains(l.as_str()), "missing: {l}");
            }
            assert!(written.ends_with('\n'));
            // A second run at the same path refuses.
            let e = probe_report(&p, &root, Some(&report)).unwrap_err();
            assert!(e.contains("exists — refusing to overwrite"), "{e}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn probe_report_refuses_a_schema_without_the_columns() {
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(PASS, "");
            // Drop the full message table and recreate a stub without
            // the fixed columns.
            {
                let conn = Connection::open_with_flags(
                    snap.join("Core").join("Message").join("111.db"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                )
                .unwrap();
                apply_passphrase_key(&conn, PASS).unwrap();
                conn.execute_batch("DROP TABLE message;").unwrap();
                conn.execute_batch("CREATE TABLE message (msgId TEXT, localPath TEXT);")
                    .unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let e = probe_report(&p, &root, None).unwrap_err();
            assert!(e.contains("lacks column(s)"), "{e}");
            assert!(e.contains("msgType"), "{e}");
            assert!(e.contains("folderPath"), "{e}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn probe_report_carries_the_walk_cap_fields() {
            // The report always carries the cap fields (the hard cap
            // itself is the constant the walk checks per file;
            // 200 000 synthetic files would be the only true
            // end-to-end proof and is not worth the CI time).
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(
                PASS,
                "INSERT INTO message (msgId, cliMsgId, msgType, message) VALUES \
                 ('1', 'c1', 1, 'x');",
            );
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let lines = probe_report(&p, &root, None).unwrap();
            let joined = lines.join("\n");
            assert!(joined.contains("cap=200000 cap_hit=no"), "{joined}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn plan_report_classifies_a_synthetic_store_and_census() {
            let root = synthetic_media_root();
            let uid_dir = root.join("media").join("19");
            let pic_file = uid_dir
                .join("ZaloDownloads")
                .join("picture")
                .join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl"));
            let noise = uid_dir
                .join("ZaloDownloads")
                .join("fileNoise")
                .join("0123456789abcdef0123456789abcdef");
            std::fs::create_dir_all(noise.parent().unwrap()).unwrap();
            std::fs::write(&noise, [0x37u8, 0x9E, 0x2C, 0xF1, 1]).unwrap();
            let vfile = uid_dir
                .join("ZaloDownloads")
                .join("video")
                .join(format!("{DTTM}"));

            // Desktop rows: a photo row (the JXL) for msg 1; a video
            // row (relative + folderPath) for msg 2; a fileNoise row
            // for msg 3; a video row (mp4) for msg 4 whose message is
            // imported but has NO attachment row (no_attachment_row,
            // msgType 18); a video row for msg 5 whose message was
            // never imported (not_in_shadow, msgType 18); a photo row
            // for msg 6 pointing outside the root; msg 9 with no
            // localPath; msg 10 pointing at a missing file.
            let rows = format!(
                "INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('1', 'c1', 2, '{jxl}', NULL, 'pv', 4, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('2', 'c2', 18, 'ZaloDownloads\\\\video\\\\{DTTM}', '{uid}', NULL, 10, NULL, \
                  'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('3', 'c3', 19, '{noise}', NULL, NULL, 5, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('4', 'c4', 18, '{vfile}', NULL, NULL, 10, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('5', 'c5', 18, '{vfile}', NULL, NULL, 10, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('6', 'c6', 2, 'E:\\\\elsewhere\\\\p.jpg', NULL, NULL, NULL, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('9', 'c9', 2, NULL, NULL, NULL, NULL, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('10', 'c10', 2, '{gone}', NULL, NULL, NULL, NULL, 'x');",
                jxl = q(&pic_file.to_string_lossy()),
                uid = q(&uid_dir.to_string_lossy()),
                noise = q(&noise.to_string_lossy()),
                vfile = q(&vfile.to_string_lossy()),
                gone = q(
                    &uid_dir
                        .join("ZaloDownloads")
                        .join("picture")
                        .join("gone.jxl")
                        .to_string_lossy()
                ),
            );
            let (snap, key) = synthetic_snapshot(PASS, &rows);

            // The shadow store: msg 4 is an imported message WITHOUT
            // an attachment row; msg 5 is not in the store at all.
            // Attachments: msg1 JXL would_copy; msg2 mp4 would_copy
            // (relative resolved via folderPath); msg3 fileNoise;
            // msg6 outside_root; msg7 no desktop row; msg8
            // already_downloaded; msg9 no localPath; msg10
            // missing_file; ghost no desktop row.
            let store = synthetic_store(&[
                ("4", "unused", None, "unused"),
                ("1", "image", Some("https://fake-stal.zdn.vn/a.jpg"), "ref-import"),
                ("2", "video", Some("https://fake-stal.zdn.vn/v.mp4"), "ref"),
                ("3", "file", Some("https://fake-stal.zdn.vn/f.bin"), "ref"),
                ("6", "image", Some("https://fake-stal.zdn.vn/p.jpg"), "ref"),
                ("7", "image", Some("https://fake-stal.zdn.vn/q.jpg"), "failed"),
                ("8", "image", Some("https://fake-stal.zdn.vn/r.jpg"), "downloaded"),
                ("9", "image", Some("https://fake-stal.zdn.vn/s.jpg"), "ref"),
                ("10", "image", Some("https://fake-stal.zdn.vn/t.jpg"), "ref"),
                ("ghost", "image", Some("https://fake-stal.zdn.vn/u.jpg"), "ref"),
            ]);

            let uin = sha12(PASS.as_bytes());
            let mut a = args_for(&snap, &uin, &key);
            a.local_media_plan = true;
            a.local_media_root = Some(root.clone());
            a.target = Some(store.clone());
            let lines = plan_report(&a, &root, &store).unwrap();
            let joined = lines.join("\n");

            assert!(
                joined.contains("local-media-plan: DRY RUN ONLY — no writes of any kind"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: import-sourced attachments: rows=9 desktop_rows_matched=5 \
                     kinds=3"
                ),
                "{joined}"
            );
            // image: msg1 would_copy (JXL is an image, M4), msg6
            // outside_root, msg7+ghost no_desktop_row, msg8
            // already_downloaded, msg9 no_local_path, msg10
            // missing_file (under the root, but gone).
            assert!(
                joined.contains(
                    "local-media-plan: kind=image rows=7 already_downloaded=1 would_copy=1 \
                     magic_mismatch=0 missing_file=1 no_local_path=1 noise_obfuscated=0 \
                     no_desktop_row=2 outside_root=1 size_excluded=0"
                ),
                "{joined}"
            );
            // video: msg2 would_copy (relative resolved via
            // folderPath).
            assert!(
                joined.contains(
                    "local-media-plan: kind=video rows=1 already_downloaded=0 would_copy=1 \
                     magic_mismatch=0 missing_file=0 no_local_path=0 noise_obfuscated=0 \
                     no_desktop_row=0 outside_root=0 size_excluded=0"
                ),
                "{joined}"
            );
            // file: msg3 noise_obfuscated.
            assert!(
                joined.contains(
                    "local-media-plan: kind=file rows=1 already_downloaded=0 would_copy=0 \
                     magic_mismatch=0 missing_file=0 no_local_path=0 noise_obfuscated=1 \
                     no_desktop_row=0 outside_root=0 size_excluded=0"
                ),
                "{joined}"
            );
            // would_copy bytes: the 4-byte JXL + the 10-byte mp4.
            assert!(
                joined.contains("local-media-plan: total would_copy bytes=14"),
                "{joined}"
            );
            // The Goal's census: msg4 is an imported video row with a
            // local file and no attachment row; msg5's message is not
            // in the shadow at all.
            assert!(
                joined
                    .contains("local-media-plan:   msgType=18 no_attachment_row=1 not_in_shadow=1"),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-plan: done (DRY RUN ONLY — nothing was written)"),
                "{joined}"
            );
            // H-rule: no path value, file name, uid, msgId or message
            // text anywhere.
            for banned in [
                "1763600000000_0011",
                "elsewhere",
                "0123456789abcdef0123456789abcdef",
                "https://",
                "'x'",
            ] {
                assert!(!joined.contains(banned), "a value leaked: {banned}\n{joined}");
            }
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&store);
        }

        #[test]
        fn probe_report_skips_a_snapshot_without_zcloud() {
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(
                PASS,
                "INSERT INTO message (msgId, cliMsgId, msgType, message) VALUES \
                 ('1', 'c1', 1, 'x');",
            );
            // Drop the zcloud table: the census says so and still runs.
            {
                let conn = Connection::open_with_flags(
                    snap.join("Core").join("Index.db"),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                )
                .unwrap();
                apply_passphrase_key(&conn, PASS).unwrap();
                conn.execute_batch("DROP TABLE zcloud;").unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let lines = probe_report(&p, &root, None).unwrap();
            let joined = lines.join("\n");
            assert!(
                joined.contains("local-media-probe: zcloud: skipped (no zcloud table in Core/Index.db)"),
                "{joined}"
            );
            assert!(joined.contains("local-media-probe: unref total="), "{joined}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn plan_report_refuses_a_locked_passphrase_store() {
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(
                PASS,
                "INSERT INTO message (msgId, cliMsgId, msgType, message) VALUES \
                 ('1', 'c1', 1, 'x');",
            );
            let store = synthetic_store(&[("1", "image", None, "ref")]);
            // Passphrase mode without a remember file: Locked.
            crate::shadow::passphrase::write_marker(&store, crate::shadow::schema::now_ms())
                .unwrap();
            let uin = sha12(PASS.as_bytes());
            let mut a = args_for(&snap, &uin, &key);
            a.local_media_plan = true;
            a.local_media_root = Some(root.clone());
            a.target = Some(store.clone());
            let e = plan_report(&a, &root, &store).unwrap_err();
            assert!(e.contains("password-protected (passphrase mode)"), "{e}");
            assert!(e.contains("never accepts passwords"), "{e}");
            assert!(e.contains("Nhớ trên máy này"), "{e}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&store);
        }

        #[test]
        fn plan_report_refuses_a_store_without_the_db() {
            let root = synthetic_media_root();
            let (snap, key) = synthetic_snapshot(
                PASS,
                "INSERT INTO message (msgId, cliMsgId, msgType, message) VALUES \
                 ('1', 'c1', 1, 'x');",
            );
            let empty = temp_dir("nostore");
            let uin = sha12(PASS.as_bytes());
            let mut a = args_for(&snap, &uin, &key);
            a.local_media_plan = true;
            a.local_media_root = Some(root.clone());
            a.target = Some(empty.clone());
            let e = plan_report(&a, &root, &empty).unwrap_err();
            assert!(e.contains("--target: no "), "{e}");
            assert!(e.contains("default.db"), "{e}");
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&empty);
        }

        // --- batch 27c: the tolerant reads over the real schema ----------

        /// The regression the reviewer measured on the real data: the
        /// Desktop `message` table declares `sendDttm:TEXT` (digits as
        /// TEXT) — the old fixed `Option<i64>` read dropped EVERY row
        /// (`query_failed=467616`, `rows=0`, an empty census). With the
        /// tolerant reads every row counts, the name↔sendDttm relation
        /// is found again, and the ONE un-coercible value (r3's
        /// non-numeric text fileSize) is counted, not fatal.
        #[test]
        fn probe_report_tolerates_the_real_desktop_declared_types() {
            let root = synthetic_media_root();
            let pic_file = root
                .join("media")
                .join("19")
                .join("ZaloDownloads")
                .join("picture")
                .join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl"));
            let (snap, key) = real_types_snapshot(&pic_file);
            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let lines = probe_report(&p, &root, None).unwrap();
            let joined = lines.join("\n");
            // H-rule: the header states the root fact, never the path.
            assert!(
                joined.contains("local-media-probe: root=given (exists)"),
                "{joined}"
            );
            // Every row counted; the only counted surprise is the
            // non-numeric fileSize.
            assert!(
                joined.contains(
                    "local-media-probe: message DBs: dbs=2 opened=2 open_failed=0 \
                     query_failed=0 row_failed=0 no_table=0 rows=4 coerce_none=fileSize:1"
                ),
                "{joined}"
            );
            // r1 folded with its full census: localPath present, and
            // the file name carries the 13-digit sendDttm read out of
            // the TEXT column — the relation the old reads destroyed.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 rows=3 localpath=1 folderpath=0 previewthumb=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 name msgid=yes:0 no:1 na:0 climsgid=yes:0 \
                     no:1 na:0 senddttm=yes:1 no:0 na:0"
                ),
                "{joined}"
            );
            // fileSize 4 (INTEGER) matches the 4-byte JXL file.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=2 files exists=yes:1 no:0 size=match:1 differ:0 \
                     unknown:0"
                ),
                "{joined}"
            );
            // The variant DB's row also folded — its true INTEGER
            // cliMsgId and true numeric-TEXT fileSize coerced, so
            // neither is counted as a surprise.
            assert!(
                joined.contains(
                    "local-media-probe: msgType=5 rows=1 localpath=0 folderpath=0 previewthumb=0"
                ),
                "{joined}"
            );
            // H-rule self-check: no value ever printed (the fileSize
            // text 'not-a-number' is deliberately unlike any field
            // label, so the check can not collide with the report's
            // own `size=… unknown:` vocabulary).
            for banned in [
                "8488000000101",
                "999888777666",
                "1763600000000",
                "not-a-number",
                "4096",
                "8488000000104",
            ] {
                assert!(!joined.contains(banned), "a value leaked: {banned}\n{joined}");
            }
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        /// The plan scan over the same type-surprised snapshot: the
        /// desktop row is still matched (would_copy), and the plan
        /// header carries the same split counters.
        #[test]
        fn plan_report_tolerates_the_real_desktop_declared_types() {
            let root = synthetic_media_root();
            let pic_file = root
                .join("media")
                .join("19")
                .join("ZaloDownloads")
                .join("picture")
                .join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl"));
            let (snap, key) = real_types_snapshot(&pic_file);
            // One import-sourced attachment whose Desktop row is r1
            // (the JXL): the plan must find it DESPITE the type
            // surprises in the same table.
            let store = synthetic_store(&[(
                "8488000000101",
                "image",
                Some("https://fake-stal.zdn.vn/a.jxl"),
                "ref-import",
            )]);
            let uin = sha12(PASS.as_bytes());
            let mut a = args_for(&snap, &uin, &key);
            a.local_media_plan = true;
            a.local_media_root = Some(root.clone());
            a.target = Some(store.clone());
            let lines = plan_report(&a, &root, &store).unwrap();
            let joined = lines.join("\n");
            // H-rule: fixed-text header facts, no path values.
            assert!(
                joined
                    .contains("local-media-plan: store=given (read-only; the app may keep running)"),
                "{joined}"
            );
            assert!(joined.contains("local-media-plan: root=given (exists)"), "{joined}");
            // The plan's own scan counters, split the same way as the
            // probe's.
            assert!(
                joined.contains(
                    "message DBs dbs=2 opened=2 open_failed=0 query_failed=0 no_table=0 \
                     rows=4 row_failed=0 coerce_none=fileSize:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: import-sourced attachments: rows=1 desktop_rows_matched=1 \
                     kinds=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: kind=image rows=1 already_downloaded=0 would_copy=1 \
                     magic_mismatch=0 missing_file=0 no_local_path=0 noise_obfuscated=0 \
                     no_desktop_row=0 outside_root=0 size_excluded=0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-plan: total would_copy bytes=4"),
                "{joined}"
            );
            // H-rule self-check: no value ever printed.
            for banned in [
                "8488000000101",
                "1763600000000",
                "not-a-number",
                "4096",
                "https://",
            ] {
                assert!(!joined.contains(banned), "a value leaked: {banned}\n{joined}");
            }
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&store);
        }
    }
}
