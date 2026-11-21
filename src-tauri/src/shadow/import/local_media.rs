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
//! The M2/M3 decisions themselves are PURE functions over gathered
//! facts — the plan v2 choice is [`choose_candidate`] — unit-tested
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
//!
//! Batch 27d (the import-attachment link): the real-data measurements
//! killed `message.localPath` as the link — it is EMPTY for 57.6k of
//! the 58.5k import attachments and 744 more rows point outside the
//! media root (`would_copy=0`), while the cache itself holds ~80k
//! files NO message row points at. The probe therefore ALSO reads the
//! two top-level snapshot DBs that actually track the cache, with the
//! same tolerant reads: `Media.db` (`image`/`file`, by `type` — the
//! path census plus the `content`/`metadata` shapes, their top-level
//! JSON KEY names, and the batch-24 BasicEncryption decode of
//! `content` with the snapshot key) and `Res.db` (`res` by `type` with
//! the `params` shape and the `uid` ↔ cache-file-STEM hits, `ref`
//! against the message ids and the `res` uids), plus the file-name
//! keys section (the cache files' 13-digit name parts vs the
//! `message`/`Media.db image` id sets). Everything stays shape-only:
//! key NAMES are schema and print under the `--content-shape` rule
//! (identifier-shaped as-is, anything else as `k:<sha256-12>`), no
//! VALUE ever prints, and the only file facts remain the first 16
//! bytes and `metadata().len()`. The M2 milestone (is the 32-char
//! part of a picture name the MD5 of a content url?) is SKIPPED and
//! reported `md5=unavailable`: no MD5 implementation exists anywhere
//! in the dependency tree and the brief forbids adding a crate.
//!
//! Batch 27e (plan v2 — matches by cache NAME keys): the real-data
//! run killed the `message.localPath` route as the primary link too
//! (EMPTY for 57.6k of the 58.5k import attachments), but the 27d
//! probe found the link IN THE CACHE FILE NAMES: the `picture` and
//! `video` files carry the Desktop `msgId` — the shadow import row's
//! own `msg_id` — and the `resource` files carry the `cliMsgId`. The
//! plan therefore builds ONE in-memory index `key13 → Vec<Candidate>`
//! from a single read-only walk (the same traversal, `*.rescache`
//! skip and 200k cap as the probe's reverse coverage), gathers each
//! attachment's candidates from the msgId keys (subs
//! picture/video/file), the cliMsgId keys (sub resource) and the
//! localPath route (one more candidate source, so nothing found
//! before is lost; `fileNoise` never becomes a candidate), and
//! classifies them through the PURE [`choose_candidate`]: magic fit
//! via the class projection of `media::magic_ok`, the 0/512 MB size
//! rule, then renderable-over-JXL, picture/video-before-resource,
//! larger size. The archive viewer runs in WebView2, which cannot
//! render JPEG XL — a renderable copy (jpg/png/gif/webp, mp4) is
//! preferred over JXL whenever both exist. The report adds the
//! winner attribution (picture/video/resource/file/localPath), the
//! multi-image fitting histogram, the picture-vs-resource size
//! ratio (is `resource` a thumbnail or the original?), the msgType-18
//! video census (the rows batch 27b must CREATE) and the index
//! totals. Still a DRY RUN — nothing is written anywhere, and the
//! only file facts ever gathered remain the first 16 bytes and
//! `metadata().len()`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SV;
use rusqlite::Connection;
use serde_json::Value as J;

use super::content_shape::render_key;
use super::desktop_cipher::{decode_field, FieldDecode};
use super::distinct::render_value;
use super::inventory::quote_ident;
use super::{open_top_level, Prepared, TopOpen};

/// Batch 27b M1: the guarded copy into the shadow media store
/// (`import --local-media-copy`). A child module so it reuses this
/// file's private plan machinery.
pub mod copy;

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

/// The plan scan's coercible columns, in PLAN_COLS order (batch 27e
/// adds `cliMsgId` — the resource candidates' key — and coerces
/// `msgType` for the msgType-18 video census).
const PLAN_COERCE_COLS: [&str; 6] = [
    "msgId",
    "msgType",
    "cliMsgId",
    "localPath",
    "folderPath",
    "fileSize",
];

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

// --- batch 27d: the message membership sets ----------------------------------

/// The membership sets the batch-27d relation counters compare
/// against — one HashSet pass over every Desktop `message` row (all
/// in memory; nothing here ever prints): every `msgId`, every
/// `cliMsgId`, every `(convId, cliMsgId)` pair and every `sendDttm`.
///
/// The `convId` of a message row is the DIGITS of its DB file name —
/// the 1-1 DBs are named `<peer uid>.db` and the group DBs
/// `g<group id>.db`, the mapping's own conversation-id domain (the
/// real `message` table has no convId column). `stranger_box.db`
/// carries no digits, so its rows add no pair.
#[derive(Default)]
pub struct MsgSets {
    pub msg_ids: HashSet<String>,
    pub cli_ids: HashSet<String>,
    pub pairs: HashSet<(String, String)>,
    pub send_dttms: HashSet<i64>,
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

/// The columns the M3 plan reads (batch 27e: `cliMsgId` joins the
/// fixed set — the `resource` cache files key by it; `msgType` feeds
/// the videos census; `fileSize` is still read only so a type
/// surprise in it is counted exactly like the probe counts one).
const PLAN_COLS: [&str; 6] = [
    "msgId",
    "msgType",
    "cliMsgId",
    "localPath",
    "folderPath",
    "fileSize",
];

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

/// One table's column names (batch 27d; `PRAGMA table_info`,
/// identifier-quoted — schema names only, no data). Empty when the
/// table does not exist (a missing table answers with no rows).
fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    let Ok(qt) = quote_ident(table) else {
        return Vec::new();
    };
    let Ok(mut st) = conn.prepare(&format!("PRAGMA table_info({qt})")) else {
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
/// un-coercible values are COUNTED, kinds only — H-rule. Batch 27d:
/// the same pass also builds the [`MsgSets`] membership sets (the
/// ids stay in memory; the relation counters never print a value).
fn scan_message_dbs(
    p: &Prepared,
    root_norm: &str,
    groups: &mut BTreeMap<String, CodeCensus>,
    refs: &mut HashSet<String>,
    sets: &mut MsgSets,
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
        // The message row's convId domain: the DB file-name digits.
        let conv_of_db: Option<String> = match kind {
            super::DbKind::OneToOne(id) | super::DbKind::Group(id) => Some(id.to_string()),
            _ => None,
        };
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
            let msg_id = v_to_string(msg_id, "msgId", &mut stats.coerce_none);
            let cli_msg = v_to_string(cli, "cliMsgId", &mut stats.coerce_none);
            let send_dttm = v_to_i64(dttm, "sendDttm", &mut stats.coerce_none);
            // Batch 27d: fold the membership sets BEFORE the values
            // move into the census fold.
            if let Some(id) = msg_id.as_ref() {
                sets.msg_ids.insert(id.clone());
            }
            if let Some(c) = cli_msg.as_ref() {
                sets.cli_ids.insert(c.clone());
            }
            if let Some(d) = send_dttm {
                sets.send_dttms.insert(d);
            }
            if let (Some(cid), Some(c)) = (conv_of_db.as_ref(), cli_msg.as_ref()) {
                sets.pairs.insert((cid.clone(), c.clone()));
            }
            fold_msg_row(
                groups,
                refs,
                root_norm,
                &code,
                v_to_string(local, "localPath", &mut stats.coerce_none),
                v_to_string(folder, "folderPath", &mut stats.coerce_none),
                v_to_string(preview, "previewThumb", &mut stats.coerce_none),
                v_to_i64(size, "fileSize", &mut stats.coerce_none),
                msg_id,
                cli_msg,
                send_dttm,
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
    /// Batch 27d: the STEM of every non-rescache file, per `<sub>` —
    /// the Res.db `uid` ↔ cache-file-name check. Every file counts
    /// (referenced or not): the question is "is this uid a file name
    /// under this `<sub>`", not "is it unreferenced".
    stems: BTreeMap<MediaSub, HashSet<String>>,
    /// Batch 27d: each picture/video/resource file's exactly-13-digit
    /// name runs (the file-name keys section). Only files WITH a run
    /// are stored; `files_with_dttm13` is the stored length.
    dttm13: BTreeMap<MediaSub, Vec<Vec<String>>>,
}

/// Walk `<root>\media\<uid>\ZaloDownloads\…` for EVERY uid and count
/// the files NO message row's `localPath` points at, per `<sub>`,
/// with a magic histogram (first 16 bytes only). `*.rescache` index
/// files are skipped; the walk stops hard at [`WALK_CAP`] files. No
/// path is ever printed — uid counts, `<sub>` counts, magic classes.
/// Batch 27d: the same pass gathers the file STEMS (the Res.db uid
/// check) and the 13-digit name runs (the file-name keys section) —
/// a `cap_hit` report therefore also means partial sets.
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
                let sub = classify_sub(&path_s);
                // Batch 27d: stems for EVERY file, and the 13-digit
                // runs for the picture/video/resource files. Values
                // stay in memory; only the counts ever print.
                if let Some(stem) = e.path().file_stem() {
                    rc.stems
                        .entry(sub)
                        .or_default()
                        .insert(stem.to_string_lossy().into_owned());
                }
                if matches!(sub, MediaSub::Picture | MediaSub::Video | MediaSub::Resource) {
                    let runs = digit_runs_13(&name);
                    if !runs.is_empty() {
                        rc.dttm13.entry(sub).or_default().push(runs);
                    }
                }
                let norm = norm_path(&path_s);
                if refs.contains(&norm) {
                    rc.referenced += 1;
                    continue;
                }
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

fn reverse_coverage_lines(rc: &RevCov) -> Vec<String> {
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

// --- batch 27d: the JSON column shapes ----------------------------------------

/// The five shape classes a JSON-ish column cell can take (the brief's
/// M1 vocabulary): `json_object` — the cell's text parses as a JSON
/// object; `json_array` — an array; `text` — a JSON STRING scalar
/// (the Desktop double-encoded shape the batch-24 decode unwraps);
/// `empty` — NULL or empty text; `other` — everything else (prose,
/// INTEGER/REAL/BLOB cells, number/bool JSON scalars). Counts only.
#[derive(Default)]
struct JsonShape {
    json_object: u64,
    json_array: u64,
    text: u64,
    empty: u64,
    other: u64,
}

impl JsonShape {
    fn fields(&self) -> String {
        format!(
            "json_object:{} json_array:{} text:{} empty:{} other:{}",
            self.json_object, self.json_array, self.text, self.empty, self.other
        )
    }

    /// Fold one raw cell (a tolerant [`SV`] — every storage class has a
    /// class). A JSON object's top-level key NAMES also count into
    /// `keys`, rendered by the `--content-shape` rule (identifier-
    /// shaped schema names as-is, anything else `k:<sha256-12>`).
    fn fold_cell(&mut self, v: &SV, keys: &mut BTreeMap<String, u64>) {
        match v {
            SV::Null => self.empty += 1,
            SV::Integer(_) | SV::Real(_) | SV::Blob(_) => self.other += 1,
            SV::Text(s) => {
                if s.is_empty() {
                    self.empty += 1;
                    return;
                }
                match serde_json::from_str::<J>(s) {
                    Ok(J::Object(m)) => {
                        self.json_object += 1;
                        fold_key_names(&m, keys);
                    }
                    Ok(J::Array(_)) => self.json_array += 1,
                    Ok(J::String(_)) => self.text += 1,
                    Ok(_) => self.other += 1,
                    Err(_) => self.other += 1,
                }
            }
        }
    }

    /// Fold one decoded VALUE (the batch-24 decode's output for the
    /// ok/na cells — a `fail` has no value at all). A string result
    /// stays `text`: the decode already performed the standard
    /// unwrap, so no second-level parse is attempted here.
    fn fold_value(&mut self, v: &J, keys: &mut BTreeMap<String, u64>) {
        match v {
            J::Null => self.empty += 1,
            J::Object(m) => {
                self.json_object += 1;
                fold_key_names(m, keys);
            }
            J::Array(_) => self.json_array += 1,
            J::String(_) => self.text += 1,
            J::Bool(_) | J::Number(_) => self.other += 1,
        }
    }
}

/// Count one JSON object's top-level key names into `keys` (the
/// `--content-shape` rendering rule: identifier-shaped schema names
/// print as-is, anything else prints its `k:<sha256-12>` fingerprint —
/// a key NAME that would carry a value's shape never leaks it).
fn fold_key_names(m: &serde_json::Map<String, J>, keys: &mut BTreeMap<String, u64>) {
    for k in m.keys() {
        *keys.entry(render_key(k)).or_insert(0) += 1;
    }
}

/// The brief's top-30 cap for the key-name lists.
const KEY_CAP: usize = 30;

/// `a:2 b:1 …` — the top `cap` key names by count (ties by name,
/// ascending — deterministic), `more=+N` when overflow, `none` when
/// empty. Names only, counts only (H-rule).
fn keys_fields(keys: &BTreeMap<String, u64>, cap: usize) -> String {
    let mut v: Vec<(&String, &u64)> = keys.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let shown: Vec<String> = v
        .iter()
        .take(cap)
        .map(|(k, n)| format!("{k}:{n}"))
        .collect();
    if shown.is_empty() {
        return "none".into();
    }
    let mut s = shown.join(" ");
    if v.len() > cap {
        s.push_str(&format!(" more=+{}", v.len() - cap));
    }
    s
}

/// Every maximal ASCII digit run of EXACTLY 13 digits in `name` (the
/// `sendDttm`-shaped part of the cache file names). Pure; values stay
/// in memory — the sections that use it print counts only.
pub fn digit_runs_13(name: &str) -> Vec<String> {
    let b = name.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 13 {
                out.push(name[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

// --- batch 27d: Media.db (the Desktop media tables) ----------------------------

/// The top-level DB names (schema, printable exactly like the
/// inventory's own top-level names).
const MEDIA_DB: &str = "Media.db";
const RES_DB: &str = "Res.db";

/// One Media.db table the census reads (the reviewer's schema excerpt;
/// the fixed column lists are validated against the table before any
/// row is read, and a missing table/column is REPORTED as a skipped
/// line, never fatal — the zcloud convention).
struct MediaTableSpec {
    table: &'static str,
    /// The path-presence columns, in print order: `localPath` first,
    /// then the table's other path column (image: `previewThumb`,
    /// file: `folderPath`).
    path_cols: &'static [&'static str],
    /// The table's metadata-ish column (image: `metadata`, file:
    /// `thumbMetadata`).
    meta_col: &'static str,
}

const IMAGE_SPEC: MediaTableSpec = MediaTableSpec {
    table: "image",
    path_cols: &["localPath", "previewThumb"],
    meta_col: "metadata",
};

const FILE_SPEC: MediaTableSpec = MediaTableSpec {
    table: "file",
    path_cols: &["localPath", "folderPath"],
    meta_col: "thumbMetadata",
};

/// The Media.db tables' coercible columns, in SELECT order (the fixed
/// render order of `coerce_none`; `type` renders as a code token and
/// `content`/the metadata column fold by shape, so none of the three
/// coerces).
const IMAGE_COERCE_COLS: [&str; 6] = [
    "mediaId",
    "convId",
    "cliMsgId",
    "sendDttm",
    "localPath",
    "previewThumb",
];
const FILE_COERCE_COLS: [&str; 6] = [
    "mediaId",
    "convId",
    "cliMsgId",
    "sendDttm",
    "localPath",
    "folderPath",
];

/// The Media.db `image` id sets the file-name keys section compares
/// the cache files' 13-digit name parts against (in memory only).
#[derive(Default)]
struct MediaKeys {
    send_dttms: HashSet<i64>,
    cli_ids: HashSet<String>,
}

/// One JSON-ish column of a Media.db table: the raw shape census with
/// its key names, plus (the `content` column only) the batch-24
/// decode census with the decoded shape and key names.
#[derive(Default)]
struct JsonCol {
    shape: JsonShape,
    keys: BTreeMap<String, u64>,
    dec_ok: u64,
    dec_fail: u64,
    dec_na: u64,
    /// The decode's output shape/key names over the ok+na cells (a
    /// `fail` has no value at all).
    dec_shape: JsonShape,
    dec_keys: BTreeMap<String, u64>,
}

/// One `type` code's census within a Media.db table. Every field is a
/// count, a fixed class name or a (yes, no, na) triple (H-rule).
#[derive(Default)]
struct MediaCode {
    rows: u64,
    /// Non-empty counts of the table's path columns, keyed by the
    /// lower-cased column name (`localpath`, `previewthumb`,
    /// `folderpath`).
    presence: BTreeMap<String, u64>,
    paths: PathStats,
    size_zero: u64,
    total_bytes: u64,
    /// name ↔ row relations, over the rows WITH a localPath.
    name_climsgid: (u64, u64, u64),
    name_mediaid: (u64, u64, u64),
    name_senddttm: (u64, u64, u64),
    dttm13: (u64, u64, u64),
    /// row ↔ message-set relations, over ALL rows.
    rel_climsgid: (u64, u64, u64),
    rel_mediaid: (u64, u64, u64),
    rel_pair: (u64, u64, u64),
    content: JsonCol,
    meta: JsonCol,
}

/// Identifier-quoted fixed SELECT (the names are compile-time
/// literals; the quoting keeps the pattern uniform). `Err` carries
/// the caller's skip line.
fn fixed_select(cols: &[&str], table: &str) -> Result<String, String> {
    let mut parts = Vec::new();
    for c in cols {
        parts.push(quote_ident(c)?);
    }
    Ok(format!("SELECT {} FROM {}", parts.join(", "), quote_ident(table)?))
}

/// Scan one Media.db table into per-`type` groups (batch 27d M1).
/// Tolerant reads as in 27c: every column is read as a Value; a row
/// whose `rows.next()` errored and every un-coercible value are
/// COUNTED, never fatal. `Err` carries the section's own skipped or
/// read-failed line. `collect` is `Some` only for the `image` table —
/// the file-name keys section's `image.sendDttm`/`image.cliMsgId`
/// sets.
fn scan_media_table(
    conn: &Connection,
    spec: &MediaTableSpec,
    pass: &str,
    root_norm: &str,
    sets: &MsgSets,
    mut collect: Option<&mut MediaKeys>,
) -> Result<(BTreeMap<String, MediaCode>, DbStats), String> {
    let skipped = |msg: String| format!("local-media-probe: Media.db {}: {msg}", spec.table);
    let cols = table_columns(conn, spec.table);
    if cols.is_empty() {
        return Err(skipped(format!(
            "skipped (no {} table in Media.db)",
            spec.table
        )));
    }
    let sel: [&str; 9] = [
        "mediaId",
        "convId",
        "cliMsgId",
        "type",
        "sendDttm",
        spec.path_cols[0],
        spec.path_cols[1],
        "content",
        spec.meta_col,
    ];
    let missing: Vec<&str> = sel
        .iter()
        .copied()
        .filter(|c| !cols.iter().any(|h| h == c))
        .collect();
    if !missing.is_empty() {
        return Err(skipped(format!(
            "skipped (the {} table lacks column(s) {})",
            spec.table,
            missing.join(", ")
        )));
    }
    let sql = fixed_select(&sel, spec.table)?;
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| skipped(format!("read failed ({})", crate::shadow::pipeline::sqlite_kind(&e))))?;
    // Batch 27c convention: the map itself cannot fail per row — only
    // a `rows.next()` error lands in `row_failed`.
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, SV>(0)?, // mediaId
                r.get::<_, SV>(1)?, // convId
                r.get::<_, SV>(2)?, // cliMsgId
                r.get::<_, SV>(3)?, // type
                r.get::<_, SV>(4)?, // sendDttm
                r.get::<_, SV>(5)?, // localPath
                r.get::<_, SV>(6)?, // previewThumb | folderPath
                r.get::<_, SV>(7)?, // content
                r.get::<_, SV>(8)?, // metadata | thumbMetadata
            ))
        })
        .map_err(|e| skipped(format!("read failed ({})", crate::shadow::pipeline::sqlite_kind(&e))))?;
    let mut groups: BTreeMap<String, MediaCode> = BTreeMap::new();
    let mut stats = DbStats::default();
    // The second path column resolves a relative localPath only when
    // it IS the folderPath column (the image table's previewThumb is
    // never a join base).
    let folder_col_is_second = spec.path_cols[1] == "folderPath";
    for row in rows {
        let Ok((media_id, conv_id, cli, code, dttm, local, other_path, content_v, meta_v)) = row
        else {
            stats.row_failed += 1;
            continue;
        };
        stats.rows += 1;
        let token = render_value(&code);
        let g = groups.entry(token).or_default();
        g.rows += 1;
        let media_id = v_to_string(media_id, "mediaId", &mut stats.coerce_none);
        let conv_id = v_to_string(conv_id, "convId", &mut stats.coerce_none);
        let cli = v_to_string(cli, "cliMsgId", &mut stats.coerce_none);
        let dttm = v_to_i64(dttm, "sendDttm", &mut stats.coerce_none);
        let local = v_to_string(local, spec.path_cols[0], &mut stats.coerce_none);
        let other_path = v_to_string(other_path, spec.path_cols[1], &mut stats.coerce_none);
        if local.is_some() {
            *g.presence.entry(spec.path_cols[0].to_ascii_lowercase()).or_insert(0) += 1;
        }
        if other_path.is_some() {
            *g.presence.entry(spec.path_cols[1].to_ascii_lowercase()).or_insert(0) += 1;
        }
        // The content/metadata shapes — raw, tolerant: every SV class
        // folds into one of the five classes.
        g.content.shape.fold_cell(&content_v, &mut g.content.keys);
        // The batch-24 decode of `content` (the SAME helper
        // `--content-shape --decrypt-basic` uses, with the snapshot
        // key — in memory only, never printed): `ok` = Decoded, `na`
        // = NotEncrypted (nothing was decrypted), `fail` = the
        // transform failed (a blob or the wrong-key signature).
        match decode_field(&content_v, pass) {
            FieldDecode::Decoded(v) => {
                g.content.dec_ok += 1;
                g.content.dec_shape.fold_value(&v, &mut g.content.dec_keys);
            }
            FieldDecode::NotEncrypted(v) => {
                g.content.dec_na += 1;
                g.content.dec_shape.fold_value(&v, &mut g.content.dec_keys);
            }
            FieldDecode::Failed(_) => {
                g.content.dec_fail += 1;
            }
        }
        g.meta.shape.fold_cell(&meta_v, &mut g.meta.keys);
        // The row ↔ message-set relations, over ALL rows.
        match cli.as_ref() {
            Some(c) => {
                if sets.cli_ids.contains(c) {
                    g.rel_climsgid.0 += 1;
                } else {
                    g.rel_climsgid.1 += 1;
                }
            }
            None => g.rel_climsgid.2 += 1,
        }
        match media_id.as_ref() {
            Some(m) => {
                if sets.msg_ids.contains(m) {
                    g.rel_mediaid.0 += 1;
                } else {
                    g.rel_mediaid.1 += 1;
                }
            }
            None => g.rel_mediaid.2 += 1,
        }
        match (conv_id.as_ref(), cli.as_ref()) {
            (Some(cv), Some(c)) => {
                if sets.pairs.contains(&(cv.clone(), c.clone())) {
                    g.rel_pair.0 += 1;
                } else {
                    g.rel_pair.1 += 1;
                }
            }
            _ => g.rel_pair.2 += 1,
        }
        // The file-name keys collect (image table only).
        if let Some(ck) = collect.as_mut() {
            if let Some(d) = dttm {
                ck.send_dttms.insert(d);
            }
            if let Some(c) = cli.as_ref() {
                ck.cli_ids.insert(c.clone());
            }
        }
        // The path census + name relations, over the rows WITH a
        // localPath.
        let Some(local) = local else {
            continue;
        };
        let ps = &mut g.paths;
        ps.rows += 1;
        *ps.shape.entry(path_shape(&local)).or_insert(0) += 1;
        let folder = if folder_col_is_second {
            other_path.as_deref()
        } else {
            None
        };
        let resolved = resolve_local(&local, folder);
        let resolved_s = resolved.to_string_lossy().into_owned();
        let rnorm = norm_path(&resolved_s);
        if under_root(&rnorm, root_norm) {
            ps.under_root += 1;
        } else {
            ps.not_under_root += 1;
        }
        *ps.subs.entry(classify_sub(&resolved_s)).or_insert(0) += 1;
        let (is_file, len, head) = file_facts(&resolved);
        if is_file {
            ps.exists += 1;
            if len == Some(0) {
                g.size_zero += 1;
            }
            g.total_bytes += len.unwrap_or(0);
            *ps.magic.entry(magic_class(&head)).or_insert(0) += 1;
        } else {
            ps.missing += 1;
        }
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match cli.as_ref() {
            Some(c) => {
                if name.contains(c) {
                    g.name_climsgid.0 += 1;
                } else {
                    g.name_climsgid.1 += 1;
                }
            }
            None => g.name_climsgid.2 += 1,
        }
        match media_id.as_ref() {
            Some(m) => {
                if name.contains(m) {
                    g.name_mediaid.0 += 1;
                } else {
                    g.name_mediaid.1 += 1;
                }
            }
            None => g.name_mediaid.2 += 1,
        }
        match dttm {
            Some(d) => {
                if d > 0 && name.contains(&d.to_string()) {
                    g.name_senddttm.0 += 1;
                } else {
                    g.name_senddttm.1 += 1;
                }
                if name_has_dttm(&name, d) {
                    g.dttm13.0 += 1;
                } else {
                    g.dttm13.1 += 1;
                }
            }
            None => {
                g.name_senddttm.2 += 1;
                g.dttm13.2 += 1;
            }
        }
    }
    Ok((groups, stats))
}

/// Render one Media.db table's census (most rows first, deterministic
/// tie-break on the rendered code token; the [`CODE_CAP`] convention).
fn media_table_lines(
    spec: &MediaTableSpec,
    groups: &BTreeMap<String, MediaCode>,
    stats: &DbStats,
    coerce_cols: &[&'static str],
) -> Vec<String> {
    let t = spec.table;
    let mut lines = vec![format!(
        "local-media-probe: Media.db {t}: rows={} row_failed={} coerce_none={}",
        stats.rows,
        stats.row_failed,
        coerce_none_field(coerce_cols, &stats.coerce_none)
    )];
    let mut ordered: Vec<(&String, &MediaCode)> = groups.iter().collect();
    ordered.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then(a.0.cmp(b.0)));
    for (token, g) in ordered.iter().take(CODE_CAP) {
        let ps = &g.paths;
        let presence: Vec<String> = spec
            .path_cols
            .iter()
            .map(|c| {
                format!(
                    "{}={}",
                    c.to_ascii_lowercase(),
                    g.presence.get(c.to_ascii_lowercase().as_str()).copied().unwrap_or(0)
                )
            })
            .collect();
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} rows={} {}",
            g.rows,
            presence.join(" ")
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} paths shape={} under_root=yes:{} no:{}",
            shape_fields(ps),
            ps.under_root,
            ps.not_under_root
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} paths sub={}",
            sub_fields(ps)
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} files exists=yes:{} no:{} size_zero:{} total_bytes={}",
            ps.exists, ps.missing, g.size_zero, g.total_bytes
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} magic {}",
            magic_fields(&ps.magic)
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} name climsgid=yes:{} no:{} na:{} \
             mediaid=yes:{} no:{} na:{} senddttm=yes:{} no:{} na:{} dttm13=yes:{} no:{} na:{}",
            g.name_climsgid.0,
            g.name_climsgid.1,
            g.name_climsgid.2,
            g.name_mediaid.0,
            g.name_mediaid.1,
            g.name_mediaid.2,
            g.name_senddttm.0,
            g.name_senddttm.1,
            g.name_senddttm.2,
            g.dttm13.0,
            g.dttm13.1,
            g.dttm13.2
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} rel climsgid_in_message=yes:{} no:{} \
             na:{} mediaid_in_message=yes:{} no:{} na:{} pair_in_message=yes:{} no:{} na:{}",
            g.rel_climsgid.0,
            g.rel_climsgid.1,
            g.rel_climsgid.2,
            g.rel_mediaid.0,
            g.rel_mediaid.1,
            g.rel_mediaid.2,
            g.rel_pair.0,
            g.rel_pair.1,
            g.rel_pair.2
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} content {} decrypt=ok:{} fail:{} na:{}",
            g.content.shape.fields(),
            g.content.dec_ok,
            g.content.dec_fail,
            g.content.dec_na
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} content decoded {}",
            g.content.dec_shape.fields()
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} content keys {}",
            keys_fields(&g.content.keys, KEY_CAP)
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} content decoded keys {}",
            keys_fields(&g.content.dec_keys, KEY_CAP)
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} metadata {}",
            g.meta.shape.fields()
        ));
        lines.push(format!(
            "local-media-probe: Media.db {t} type={token} metadata keys {}",
            keys_fields(&g.meta.keys, KEY_CAP)
        ));
    }
    let more = groups.len().saturating_sub(CODE_CAP);
    if more > 0 {
        lines.push(format!(
            "local-media-probe: Media.db {t}: more_types={more} (capped at {CODE_CAP} by rows)"
        ));
    }
    lines
}

/// The Media.db section (batch 27d M1): the `image` and `file` tables,
/// by `type` code. READ-ONLY — the same two-attempt top-level open
/// (`mode=ro&immutable=1`, cipher then plain) the inventory uses;
/// tolerant reads; a missing DB, a missing table or a read failure is
/// REPORTED as a skip line, never fatal. Nothing prints but counts,
/// fixed classes, schema names and rendered code tokens (H-rule).
/// Returns the section's lines plus the `image` id sets for the
/// file-name keys section.
fn media_db_lines(p: &Prepared, root_norm: &str, sets: &MsgSets) -> (Vec<String>, MediaKeys) {
    let mut collect = MediaKeys::default();
    let path = p.uid_dir.join(MEDIA_DB);
    if !path.is_file() {
        return (
            vec![format!(
                "local-media-probe: {MEDIA_DB}: skipped (no {MEDIA_DB} in the snapshot)"
            )],
            collect,
        );
    }
    let (conn, how) = match open_top_level(&path, p.passphrase.as_str(), p.profile) {
        TopOpen::Cipher(c) => (c, "cipher"),
        TopOpen::Plain(c) => (c, "plain"),
        TopOpen::Failed(kind) => {
            return (vec![format!("local-media-probe: {MEDIA_DB} opened=no ({kind})")], collect)
        }
    };
    let mut lines = vec![format!(
        "local-media-probe: {MEDIA_DB} opened=yes ({how}) (read-only; by type, tolerant reads)"
    )];
    for (spec, coerce_cols) in [
        (&IMAGE_SPEC, &IMAGE_COERCE_COLS[..]),
        (&FILE_SPEC, &FILE_COERCE_COLS[..]),
    ] {
        // Only the image table feeds the file-name keys section.
        let collect_opt = if spec.table == "image" {
            Some(&mut collect)
        } else {
            None
        };
        match scan_media_table(
            &conn,
            spec,
            p.passphrase.as_str(),
            root_norm,
            sets,
            collect_opt,
        ) {
            Ok((groups, stats)) => {
                lines.extend(media_table_lines(spec, &groups, &stats, coerce_cols))
            }
            Err(skip) => lines.push(skip),
        }
    }
    (lines, collect)
}

// --- batch 27d: Res.db (the resource cache) -------------------------------------

const RES_COERCE_COLS: [&str; 1] = ["uid"];
const REF_COERCE_COLS: [&str; 2] = ["msgId", "uid"];

/// One `type` code's `res` census (rows; the params shape and key
/// names; the uid ↔ cache-file-STEM hits per `<sub>`).
#[derive(Default)]
struct ResCode {
    rows: u64,
    params: JsonShape,
    keys: BTreeMap<String, u64>,
    uid_hits: BTreeMap<MediaSub, u64>,
}

/// The Res.db section (batch 27d M1): `res` by `type` — the params
/// shape and key names plus the uid↔file-stem hits per `<sub>` — and
/// `ref`'s membership counters (`msgId` vs the message ids, `uid` vs
/// the `res` uids). READ-ONLY, tolerant reads, counts only; a
/// missing DB/table/column or a read failure is REPORTED, never
/// fatal.
fn res_db_lines(p: &Prepared, sets: &MsgSets, rc: &RevCov) -> Vec<String> {
    let path = p.uid_dir.join(RES_DB);
    if !path.is_file() {
        return vec![format!(
            "local-media-probe: {RES_DB}: skipped (no {RES_DB} in the snapshot)"
        )];
    }
    let (conn, how) = match open_top_level(&path, p.passphrase.as_str(), p.profile) {
        TopOpen::Cipher(c) => (c, "cipher"),
        TopOpen::Plain(c) => (c, "plain"),
        TopOpen::Failed(kind) => {
            return vec![format!("local-media-probe: {RES_DB} opened=no ({kind})")]
        }
    };
    let mut lines = vec![format!(
        "local-media-probe: {RES_DB} opened=yes ({how}) (read-only; tolerant reads)"
    )];

    // --- res: uid, type, params ------------------------------------------------
    let mut res_uids: HashSet<String> = HashSet::new();
    let cols = table_columns(&conn, "res");
    if cols.is_empty() {
        lines.push("local-media-probe: Res.db res: skipped (no res table in Res.db)".into());
    } else {
        let missing: Vec<&str> = ["uid", "type", "params"]
            .iter()
            .copied()
            .filter(|c| !cols.iter().any(|h| h == c))
            .collect();
        if !missing.is_empty() {
            lines.push(format!(
                "local-media-probe: Res.db res: skipped (the res table lacks column(s) {})",
                missing.join(", ")
            ));
        } else {
            let scan = (|| -> Result<(BTreeMap<String, ResCode>, DbStats), String> {
                let sql = fixed_select(&["uid", "type", "params"], "res")?;
                let mut st = conn.prepare(&sql).map_err(|e| {
                    format!(
                        "local-media-probe: Res.db res: read failed ({})",
                        crate::shadow::pipeline::sqlite_kind(&e)
                    )
                })?;
                let rows = st.query_map([], |r| {
                    Ok((
                        r.get::<_, SV>(0)?, // uid
                        r.get::<_, SV>(1)?, // type
                        r.get::<_, SV>(2)?, // params
                    ))
                }).map_err(|e| {
                    format!(
                        "local-media-probe: Res.db res: read failed ({})",
                        crate::shadow::pipeline::sqlite_kind(&e)
                    )
                })?;
                let mut groups: BTreeMap<String, ResCode> = BTreeMap::new();
                let mut stats = DbStats::default();
                for row in rows {
                    let Ok((uid, rtype, params)) = row else {
                        stats.row_failed += 1;
                        continue;
                    };
                    stats.rows += 1;
                    let token = render_value(&rtype);
                    let g = groups.entry(token).or_default();
                    g.rows += 1;
                    let uid = v_to_string(uid, "uid", &mut stats.coerce_none);
                    g.params.fold_cell(&params, &mut g.keys);
                    if let Some(u) = uid.as_ref() {
                        res_uids.insert(u.clone());
                        // Is the uid a cache file STEM under any
                        // `<sub>`? (counts only — the fixed
                        // vocabulary prints, never a name).
                        for sub in SUB_FIELDS {
                            if rc
                                .stems
                                .get(&sub)
                                .is_some_and(|set| set.contains(u))
                            {
                                *g.uid_hits.entry(sub).or_insert(0) += 1;
                            }
                        }
                    }
                }
                Ok((groups, stats))
            })();
            match scan {
                Ok((groups, stats)) => {
                    lines.push(format!(
                        "local-media-probe: Res.db res: rows={} row_failed={} coerce_none={}",
                        stats.rows,
                        stats.row_failed,
                        coerce_none_field(&RES_COERCE_COLS, &stats.coerce_none)
                    ));
                    let mut ordered: Vec<(&String, &ResCode)> = groups.iter().collect();
                    ordered.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then(a.0.cmp(b.0)));
                    for (token, g) in ordered.iter().take(CODE_CAP) {
                        lines.push(format!(
                            "local-media-probe: Res.db res type={token} rows={} params {}",
                            g.rows,
                            g.params.fields()
                        ));
                        lines.push(format!(
                            "local-media-probe: Res.db res type={token} params keys {}",
                            keys_fields(&g.keys, KEY_CAP)
                        ));
                        let hits: Vec<String> = SUB_FIELDS
                            .iter()
                            .filter(|s| g.uid_hits.get(s).copied().unwrap_or(0) > 0)
                            .map(|s| format!("{}:{}", s.name(), g.uid_hits[s]))
                            .collect();
                        lines.push(format!(
                            "local-media-probe: Res.db res type={token} uid_file_hits {}",
                            if hits.is_empty() { "none".into() } else { hits.join(" ") }
                        ));
                    }
                    let more = groups.len().saturating_sub(CODE_CAP);
                    if more > 0 {
                        lines.push(format!(
                            "local-media-probe: Res.db res: more_types={more} \
                             (capped at {CODE_CAP} by rows)"
                        ));
                    }
                }
                Err(skip) => lines.push(skip),
            }
        }
    }

    // --- ref: msgId, uid --------------------------------------------------------
    let cols = table_columns(&conn, "ref");
    if cols.is_empty() {
        lines.push("local-media-probe: Res.db ref: skipped (no ref table in Res.db)".into());
        return lines;
    }
    let missing: Vec<&str> = ["msgId", "uid"]
        .iter()
        .copied()
        .filter(|c| !cols.iter().any(|h| h == c))
        .collect();
    if !missing.is_empty() {
        lines.push(format!(
            "local-media-probe: Res.db ref: skipped (the ref table lacks column(s) {})",
            missing.join(", ")
        ));
        return lines;
    }
    let scan = (|| -> Result<((u64, u64, u64, u64, u64, u64), DbStats), String> {
        let sql = fixed_select(&["msgId", "uid"], "ref")?;
        let mut st = conn.prepare(&sql).map_err(|e| {
            format!(
                "local-media-probe: Res.db ref: read failed ({})",
                crate::shadow::pipeline::sqlite_kind(&e)
            )
        })?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, SV>(0)?, r.get::<_, SV>(1)?)))
            .map_err(|e| {
                format!(
                    "local-media-probe: Res.db ref: read failed ({})",
                    crate::shadow::pipeline::sqlite_kind(&e)
                )
            })?;
        // (msgid yes, no, na, uid yes, no, na)
        let mut cnt = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        let mut stats = DbStats::default();
        for row in rows {
            let Ok((msgid, uid)) = row else {
                stats.row_failed += 1;
                continue;
            };
            stats.rows += 1;
            let msgid = v_to_string(msgid, "msgId", &mut stats.coerce_none);
            let uid = v_to_string(uid, "uid", &mut stats.coerce_none);
            match msgid {
                Some(m) => {
                    if sets.msg_ids.contains(&m) {
                        cnt.0 += 1;
                    } else {
                        cnt.1 += 1;
                    }
                }
                None => cnt.2 += 1,
            }
            match uid {
                Some(u) => {
                    if res_uids.contains(&u) {
                        cnt.3 += 1;
                    } else {
                        cnt.4 += 1;
                    }
                }
                None => cnt.5 += 1,
            }
        }
        Ok((cnt, stats))
    })();
    match scan {
        Ok((cnt, stats)) => lines.push(format!(
            "local-media-probe: Res.db ref: rows={} row_failed={} coerce_none={} \
             msgid_in_message=yes:{} no:{} na:{} uid_in_res=yes:{} no:{} na:{}",
            stats.rows,
            stats.row_failed,
            coerce_none_field(&REF_COERCE_COLS, &stats.coerce_none),
            cnt.0,
            cnt.1,
            cnt.2,
            cnt.3,
            cnt.4,
            cnt.5
        )),
        Err(skip) => lines.push(skip),
    }
    lines
}

// --- batch 27d: the file-name keys -----------------------------------------------

/// The file-name keys section (batch 27d M1): for the cache's
/// picture/video/resource files, how many carry a 13-digit name part
/// that equals one of the DB ids — some `message.sendDttm` /
/// `cliMsgId` / `msgId`, or some `Media.db image.sendDttm` /
/// `cliMsgId`. A file with several 13-digit runs counts once per
/// set when ANY of its runs hits. Counts only (H-rule).
fn name_keys_lines(rc: &RevCov, sets: &MsgSets, media: &MediaKeys) -> Vec<String> {
    let mut lines = Vec::new();
    for sub in [MediaSub::Picture, MediaSub::Video, MediaSub::Resource] {
        let files = rc.dttm13.get(&sub).map(Vec::as_slice).unwrap_or(&[]);
        let (mut sd, mut mc, mut mi, mut msd, mut mcli) = (0u64, 0u64, 0u64, 0u64, 0u64);
        for runs in files {
            if runs
                .iter()
                .any(|r| r.parse::<i64>().is_ok_and(|n| sets.send_dttms.contains(&n)))
            {
                sd += 1;
            }
            if runs.iter().any(|r| sets.cli_ids.contains(r)) {
                mc += 1;
            }
            if runs.iter().any(|r| sets.msg_ids.contains(r)) {
                mi += 1;
            }
            if runs
                .iter()
                .any(|r| r.parse::<i64>().is_ok_and(|n| media.send_dttms.contains(&n)))
            {
                msd += 1;
            }
            if runs.iter().any(|r| media.cli_ids.contains(r)) {
                mcli += 1;
            }
        }
        lines.push(format!(
            "local-media-probe: name-keys sub={} files_with_dttm13={} senddttm=yes:{} \
             climsgid=yes:{} msgid=yes:{} media_image_senddttm=yes:{} media_image_climsgid=yes:{}",
            sub.name(),
            files.len(),
            sd,
            mc,
            mi,
            msd,
            mcli
        ));
    }
    lines
}

// --- batch 27d: M2 (the 32-char part of picture names) ---------------------------

/// The M2 milestone lines. The brief's hypothesis — the 32-char part
/// of a picture file name is the lowercase hex MD5 of a content url —
/// needs an MD5; NO MD5 implementation exists anywhere in the
/// dependency tree (sha2/blake2 only — a SHA hex is 64 chars and can
/// never equal a 32-char part), and the brief forbids adding a crate.
/// The milestone is therefore SKIPPED and reported exactly as the
/// brief prescribes: `md5=unavailable`. Fixed text only (H-rule).
fn md5_section_lines() -> Vec<String> {
    vec![
        "local-media-probe: picture-name hash: md5=unavailable (no MD5 implementation exists \
         in the dependency tree and the brief forbids adding a crate — milestone skipped)"
            .into(),
    ]
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
    // Batch 27d: the same scan also builds the membership sets the
    // Media.db / Res.db relation counters compare against.
    let mut sets = MsgSets::default();
    let stats = scan_message_dbs(p, &root_norm, &mut groups, &mut refs, &mut sets)?;
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

    // The reverse-coverage walk (batch 27d: the same pass now also
    // gathers the file STEMS for the Res.db uid check and the
    // 13-digit name runs for the file-name keys section).
    let rc = walk_reverse_coverage(root, &refs);
    lines.push("== reverse coverage (files no message row points at) ==".into());
    lines.extend(reverse_coverage_lines(&rc));

    // Batch 27d M1: Media.db (image / file, by type).
    lines.push("== Media.db (image / file, by type) ==".into());
    let (media_section, media_keys) = media_db_lines(p, &root_norm, &sets);
    lines.extend(media_section);

    // Batch 27d M1: Res.db (res / ref).
    lines.push("== Res.db (res / ref) ==".into());
    lines.extend(res_db_lines(p, &sets, &rc));

    // Batch 27d M1: the cache file names' 13-digit parts vs the ids.
    lines.push("== file-name keys (the 13-digit part vs the DB ids) ==".into());
    lines.extend(name_keys_lines(&rc, &sets, &media_keys));

    // Batch 27d M2: skipped — the dependency tree has no MD5.
    lines.push("== picture-name 32-char part vs URL hashes (M2) ==".into());
    lines.extend(md5_section_lines());

    if let Some(p_out) = out {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(p_out, body.as_bytes())
            .map_err(|e| format!("--out: write failed ({:?})", e.kind()))?;
        lines.push("local-media-probe: report written (--out)".into());
    }
    Ok(lines)
}

// --- batch 27e M1: the candidate index ----------------------------------------

/// The `<sub>`s the candidate index walks and keys (the brief's M1
/// list). `fileNoise` and every other `<sub>` is walked for the cap
/// accounting only — never opened, never decoded.
const INDEXED_SUBS: [MediaSub; 4] = [
    MediaSub::Picture,
    MediaSub::Video,
    MediaSub::Resource,
    MediaSub::File,
];

/// The route a candidate arrived by — the winner attribution (the
/// brief's five source labels): an index candidate wins as its
/// `<sub>` (picture / video / resource / file), the batch-27
/// `message.localPath` route wins as `localPath`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandVia {
    /// Keyed by the cache file NAME (the single walk).
    Index,
    /// The Desktop row's own `localPath`, resolved against the root.
    LocalPath,
}

/// The facts the pure choice sees — no path, no id, nothing that
/// could print a value even by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandFacts {
    pub sub: MediaSub,
    pub via: CandVia,
    pub size: u64,
    pub magic: MagicClass,
}

impl CandFacts {
    /// The winner label — the brief's fixed five-name vocabulary.
    pub fn winner_label(&self) -> &'static str {
        match self.via {
            CandVia::LocalPath => "localPath",
            CandVia::Index => self.sub.name(),
        }
    }
}

/// One index entry: `key13 → Candidate { sub, size, magic class,
/// path }` (the brief's shape). The path stays IN MEMORY for the
/// later, user-approved copy batch (27b) — nothing in this module
/// ever prints it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub sub: MediaSub,
    pub via: CandVia,
    pub size: u64,
    pub magic: MagicClass,
    pub path: PathBuf,
}

impl Candidate {
    /// The facts the pure choice sees.
    pub fn facts(&self) -> CandFacts {
        CandFacts {
            sub: self.sub,
            via: self.via,
            size: self.size,
            magic: self.magic,
        }
    }
}

/// Per-sub index totals (the report's `index sub=…` lines; counts
/// and the fixed vocabulary only).
#[derive(Default)]
struct SubIndex {
    files: u64,
    keyed: u64,
    unkeyed: u64,
    keys: HashSet<String>,
}

/// The candidate index (batch 27e M1): ONE in-memory map
/// `key13 → Vec<Candidate>` built by a single read-only walk. The
/// key is the cache file STEM's exactly-13-digit run — a Desktop
/// `msgId` under `picture`/`video`/`file`, a `cliMsgId` under
/// `resource`; a stem with zero or several runs counts as `unkeyed`
/// per `<sub>`. Paths never leave this structure.
#[derive(Default)]
pub struct CandIndex {
    entries: BTreeMap<String, Vec<Candidate>>,
    subs: BTreeMap<MediaSub, SubIndex>,
    uids: u64,
    uids_with_zdl: u64,
    files_seen: u64,
    rescache_skipped: u64,
    indexed: u64,
    cap_hit: bool,
}

/// The single read-only walk (the §10.2 reverse-coverage traversal
/// reused): every uid under `<root>\media`, an explicit stack, no
/// symlink following, `*.rescache` skipped, the hard [`WALK_CAP`]
/// cap on every file seen. The only file facts ever gathered are the
/// first 16 bytes and `metadata().len()`, and only for the indexed
/// `<sub>`s.
fn walk_candidate_index(root: &Path) -> CandIndex {
    let mut ix = CandIndex::default();
    let Ok(uids) = std::fs::read_dir(root.join("media")) else {
        return ix; // no media tree: an empty index, not an error
    };
    for uid in uids.flatten() {
        if !uid.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        ix.uids += 1;
        let zdl = uid.path().join("ZaloDownloads");
        if !zdl.is_dir() {
            continue;
        }
        ix.uids_with_zdl += 1;
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
                ix.files_seen += 1;
                if ix.files_seen > WALK_CAP {
                    ix.cap_hit = true;
                    return ix;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if name.to_ascii_lowercase().ends_with(".rescache") {
                    ix.rescache_skipped += 1;
                    continue;
                }
                let ep = e.path();
                let sub = classify_sub(&ep.to_string_lossy());
                if !INDEXED_SUBS.contains(&sub) {
                    continue; // cap accounting only — never opened
                }
                let runs = ep
                    .file_stem()
                    .map(|s| digit_runs_13(&s.to_string_lossy()))
                    .unwrap_or_default();
                let key = if runs.len() == 1 {
                    runs.into_iter().next()
                } else {
                    None
                };
                {
                    let si = ix.subs.entry(sub).or_default();
                    si.files += 1;
                    match key.as_ref() {
                        Some(k) => {
                            si.keyed += 1;
                            si.keys.insert(k.clone());
                        }
                        None => si.unkeyed += 1,
                    }
                }
                let Some(key) = key else { continue };
                let (is_file, len, head) = file_facts(&ep);
                if !is_file {
                    continue; // vanished mid-walk: keyed, but no facts to offer
                }
                ix.indexed += 1;
                ix.entries.entry(key).or_default().push(Candidate {
                    sub,
                    via: CandVia::Index,
                    size: len.unwrap_or(0),
                    magic: magic_class(&head),
                    path: ep,
                });
            }
        }
    }
    ix
}

// --- batch 27e M2: the pure choice -------------------------------------------

/// The plan's would-copy size cap (unchanged from v1: the store's own
/// download cap).
pub const WOULD_COPY_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// One import-sourced attachment's plan v2 outcome — the brief's six
/// labels. `already_downloaded` is decided by the CALLER from the row
/// status BEFORE the candidate lookup, so [`choose_candidate`] never
/// returns it — it lives on this enum so every row still lands in
/// exactly one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Choice {
    AlreadyDownloaded,
    WouldCopyRenderable,
    WouldCopyJxlOnly,
    MagicMismatch,
    SizeExcluded,
    NoCandidate,
}

impl Choice {
    /// The report's field name (the brief's exact labels).
    pub fn field(self) -> &'static str {
        match self {
            Choice::AlreadyDownloaded => "already_downloaded",
            Choice::WouldCopyRenderable => "would_copy_renderable",
            Choice::WouldCopyJxlOnly => "would_copy_jxl_only",
            Choice::MagicMismatch => "magic_mismatch",
            Choice::SizeExcluded => "size_excluded",
            Choice::NoCandidate => "no_candidate",
        }
    }

    /// Does this outcome copy bytes?
    fn copies(self) -> bool {
        matches!(
            self,
            Choice::WouldCopyRenderable | Choice::WouldCopyJxlOnly
        )
    }
}

/// The class-level projection of `media::magic_ok` — the brief's M2
/// fit lists: image accepts jpg/png/gif/webp/jxl (both on-disk
/// forms); video accepts mp4/webm; file, voice and unknown kinds are
/// not sniffed (the size rule drops the empty files). Unit-tested to
/// agree with the byte-level sniff on a representative head of every
/// class.
fn magic_class_ok(kind: Option<&str>, m: MagicClass) -> bool {
    match kind {
        Some("image") => matches!(
            m,
            MagicClass::Jpg
                | MagicClass::Png
                | MagicClass::Gif
                | MagicClass::Webp
                | MagicClass::Jxl
                | MagicClass::JxlContainer
        ),
        Some("video") => matches!(m, MagicClass::Mp4 | MagicClass::WebmMkv),
        _ => true,
    }
}

/// The brief's preference rule 1: renderable (jpg/png/gif/webp/
/// mp4/webm — everything WebView2 shows inline) beats JXL. The
/// classes the rule does not name (pdf/zip/html/other) sit BETWEEN
/// the two — the minimal total order in which renderable still beats
/// JXL (documented in the mapping doc's §10.6).
fn render_rank(m: MagicClass) -> u8 {
    match m {
        MagicClass::Jpg
        | MagicClass::Png
        | MagicClass::Gif
        | MagicClass::Webp
        | MagicClass::Mp4
        | MagicClass::WebmMkv => 0,
        MagicClass::Jxl | MagicClass::JxlContainer => 2,
        _ => 1,
    }
}

/// The brief's preference rule 2: picture/video before resource. The
/// subs the rule does not name sit around it (§10.6): `file` between
/// the two, every other `<sub>` last.
fn sub_rank(sub: MediaSub) -> u8 {
    match sub {
        MediaSub::Picture | MediaSub::Video => 0,
        MediaSub::File => 1,
        MediaSub::Resource => 2,
        _ => 3,
    }
}

/// Does candidate `a` beat candidate `b` under the preference order
/// (renderable → sub → size)? Pure.
fn better(a: &CandFacts, b: &CandFacts) -> bool {
    match render_rank(a.magic).cmp(&render_rank(b.magic)) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => match sub_rank(a.sub).cmp(&sub_rank(b.sub)) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => a.size > b.size,
        },
    }
}

/// Does the candidate pass BOTH filters — the magic fits the kind AND
/// the size is in range (0 < size ≤ the 512 MB cap)? Pure.
fn fits_filters(kind: Option<&str>, c: &CandFacts) -> bool {
    magic_class_ok(kind, c.magic) && c.size > 0 && c.size <= WOULD_COPY_MAX_BYTES
}

/// The best FITTING candidate by the preference order, or `None`
/// when no candidate fits. Ties keep the FIRST candidate —
/// deterministic in the input order. Pure.
fn best_fitting(kind: Option<&str>, cands: &[CandFacts]) -> Option<CandFacts> {
    let mut best: Option<CandFacts> = None;
    for c in cands {
        if !fits_filters(kind, c) {
            continue;
        }
        let take = match best {
            Some(b) => better(c, &b),
            None => true,
        };
        if take {
            best = Some(*c);
        }
    }
    best
}

/// The best candidate of one already-fitting pool restricted to a
/// single `<sub>` (the picture-vs-resource section's per-sub pick).
fn best_in_sub(pool: &[CandFacts], sub: MediaSub) -> Option<CandFacts> {
    let mut best: Option<CandFacts> = None;
    for c in pool.iter().filter(|c| c.sub == sub) {
        let take = match best {
            Some(b) => better(c, &b),
            None => true,
        };
        if take {
            best = Some(*c);
        }
    }
    best
}

/// The M2 choice, PURE over (kind, candidate facts) — unit-tested for
/// every arm:
///
/// 1. `no_candidate` — no candidate at all;
/// 2. `magic_mismatch` — candidates exist but none fits the kind;
/// 3. `size_excluded` — some fit the magic but every fitting one is
///    0 bytes or over the 512 MB cap;
/// 4. otherwise the best fitting candidate decides:
///    `would_copy_jxl_only` when it is JXL (the archive viewer runs
///    in WebView2, which cannot render JPEG XL), else
///    `would_copy_renderable`.
///
/// `already_downloaded` is decided by the caller BEFORE the lookup
/// (the row's status) and never passes through here.
pub fn choose_candidate(kind: Option<&str>, cands: &[CandFacts]) -> Choice {
    if cands.is_empty() {
        return Choice::NoCandidate;
    }
    let Some(best) = best_fitting(kind, cands) else {
        // The two empty reasons: a magic filter that dropped
        // everything vs a size filter that dropped every fitting one.
        return if cands.iter().any(|c| magic_class_ok(kind, c.magic)) {
            Choice::SizeExcluded
        } else {
            Choice::MagicMismatch
        };
    };
    match best.magic {
        MagicClass::Jxl | MagicClass::JxlContainer => Choice::WouldCopyJxlOnly,
        _ => Choice::WouldCopyRenderable,
    }
}

// --- M3: the report (v2, batch 27e) -------------------------------------------

/// One import-sourced attachment row as read from the store (values
/// in memory; the kind/status are shadow vocabulary, the id never
/// prints).
struct AttRow {
    msg_id: String,
    kind: Option<String>,
    status: String,
}

/// The Desktop row facts the v2 plan keeps for each needed msg id
/// (values in memory; nothing here prints).
struct DeskRow {
    /// The coerced `msgType` (the videos census).
    msg_type: Option<i64>,
    /// The coerced Desktop `fileSize` (batch 27b: the `size_mismatch`
    /// rule for `file` and `video`; the plan's decision still uses the
    /// FILE's size).
    file_size: Option<i64>,
    /// The `resource` candidates' key.
    cli_msg_id: Option<String>,
    /// The batch-27 localPath route.
    local_path: Option<String>,
    folder_path: Option<String>,
}

/// Gather ONE attachment's candidates (M2's lookup): the index
/// entries keyed by the shadow `msg_id` — the Desktop `msgId`; the
/// subs keyed by it are picture/video/file — the entries keyed by the
/// Desktop row's `cliMsgId` (the `resource` sub), and the batch-27
/// `message.localPath` route (sub from the path) when it resolves
/// under the root — so nothing found before is lost. A `fileNoise`
/// path NEVER becomes a candidate (its contents are never decoded);
/// duplicates by normalized path drop (the same file can be both a
/// keyed entry and a localPath target).
fn gather_candidates(
    ix: &CandIndex,
    root_norm: &str,
    msg_id: &str,
    desk: Option<&DeskRow>,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(v) = ix.entries.get(msg_id) {
        for c in v {
            if matches!(c.sub, MediaSub::Picture | MediaSub::Video | MediaSub::File)
                && seen.insert(norm_path(&c.path.to_string_lossy()))
            {
                out.push(c.clone());
            }
        }
    }
    if let Some(cli) = desk.and_then(|d| d.cli_msg_id.as_deref()) {
        if let Some(v) = ix.entries.get(cli) {
            for c in v {
                if c.sub == MediaSub::Resource
                    && seen.insert(norm_path(&c.path.to_string_lossy()))
                {
                    out.push(c.clone());
                }
            }
        }
    }
    if let Some(d) = desk {
        if let Some(local) = d.local_path.as_deref().filter(|l| !l.is_empty()) {
            let resolved = resolve_local(local, d.folder_path.as_deref());
            let rs = resolved.to_string_lossy().into_owned();
            let rnorm = norm_path(&rs);
            let sub = classify_sub(&rs);
            // Under the root only, and never a fileNoise path —
            // those are counted by the probe, never decoded.
            if under_root(&rnorm, root_norm)
                && sub != MediaSub::FileNoise
                && seen.insert(rnorm)
            {
                let (is_file, len, head) = file_facts(&resolved);
                if is_file {
                    out.push(Candidate {
                        sub,
                        via: CandVia::LocalPath,
                        size: len.unwrap_or(0),
                        magic: magic_class(&head),
                        path: resolved,
                    });
                }
            }
        }
    }
    out
}

/// Per-kind aggregation of the v2 outcomes: rows, (count, bytes) per
/// outcome, and the winner attribution (the fixed five labels).
#[derive(Default)]
struct KindPlan {
    rows: u64,
    outcomes: BTreeMap<Choice, (u64, u64)>,
    winners: BTreeMap<&'static str, u64>,
}

/// One message's in-scope image attachments vs their fitting
/// candidates (the multi-image section).
#[derive(Default)]
struct ImgMsg {
    atts: u64,
    fitting: u64,
}

/// The picture-vs-resource ratio buckets (the brief's four,
/// half-open exactly as their labels read: `<0.25`, `0.25–0.75`,
/// `0.75–1.33` inclusive of 1.33, `>1.33`).
const RATIO_LABELS: [&str; 4] = ["<0.25", "0.25–0.75", "0.75–1.33", ">1.33"];

fn ratio_bucket(r: f64) -> usize {
    if r < 0.25 {
        0
    } else if r < 0.75 {
        1
    } else if r <= 1.33 {
        2
    } else {
        3
    }
}

/// The fixed field order of the outcomes lines.
const CHOICE_FIELDS: [Choice; 6] = [
    Choice::AlreadyDownloaded,
    Choice::WouldCopyRenderable,
    Choice::WouldCopyJxlOnly,
    Choice::MagicMismatch,
    Choice::SizeExcluded,
    Choice::NoCandidate,
];

/// The brief's five winner labels, in print order.
const WINNER_FIELDS: [&str; 5] = ["picture", "video", "resource", "file", "localPath"];

/// What one pass over the snapshot's message DBs yields (batch 27b
/// factored this out of [`plan_report`] so the copy mode runs the very
/// same tolerant scan): the Desktop row facts of every `needed` msgId,
/// the `cliMsgId`s those rows carry, the scan statistics and — when
/// asked — how many Desktop message rows carry each `cliMsgId` across
/// ALL message DBs (the `ambiguous_key` rule).
struct DeskScan {
    desk_rows: BTreeMap<String, DeskRow>,
    cli_needed: HashSet<String>,
    scan: DbStats,
    /// `cliMsgId` → number of Desktop message rows (saturating at
    /// `u32::MAX`); empty unless `count_cli`.
    cli_counts: std::collections::HashMap<String, u32>,
}

fn scan_desktop_rows(
    p: &Prepared,
    needed: &HashSet<String>,
    count_cli: bool,
) -> Result<DeskScan, String> {
    preflight_columns(p, &PLAN_COLS)?;
    let sql = msg_scan_sql(&PLAN_COLS)?;
    let names = super::message_db_names(&p.uid_dir)?;
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut desk_rows: BTreeMap<String, DeskRow> = BTreeMap::new();
    let mut cli_needed: HashSet<String> = HashSet::new();
    let mut scan = DbStats::default();
    let mut cli_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
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
        let Ok(rows) = st.query_map([], |r| {
            Ok((
                r.get::<_, SV>(0)?, // msgId
                r.get::<_, SV>(1)?, // msgType
                r.get::<_, SV>(2)?, // cliMsgId
                r.get::<_, SV>(3)?, // localPath
                r.get::<_, SV>(4)?, // folderPath
                r.get::<_, SV>(5)?, // fileSize (counted, not used)
            ))
        }) else {
            scan.query_failed += 1;
            continue;
        };
        for row in rows {
            let Ok((mid, mtype, cli, local, folder, fsize)) = row else {
                scan.row_failed += 1;
                continue;
            };
            scan.rows += 1;
            let mid = v_to_string(mid, "msgId", &mut scan.coerce_none);
            let mtype = v_to_i64(mtype, "msgType", &mut scan.coerce_none);
            let cli = v_to_string(cli, "cliMsgId", &mut scan.coerce_none);
            let lp = v_to_string(local, "localPath", &mut scan.coerce_none);
            let fp = v_to_string(folder, "folderPath", &mut scan.coerce_none);
            // The decision uses the FILE's size, never this cell — it
            // is coerced so the header counts a surprise in it
            // exactly like the probe does.
            let fsize = v_to_i64(fsize, "fileSize", &mut scan.coerce_none);
            if count_cli {
                if let Some(c) = cli.as_ref() {
                    let n = cli_counts.entry(c.clone()).or_insert(0);
                    *n = n.saturating_add(1);
                }
            }
            let Some(mid) = mid else { continue };
            if needed.contains(&mid) {
                if let Some(c) = cli.as_ref() {
                    cli_needed.insert(c.clone());
                }
                desk_rows.insert(
                    mid.clone(),
                    DeskRow {
                        msg_type: mtype,
                        file_size: fsize,
                        cli_msg_id: cli,
                        local_path: lp,
                        folder_path: fp,
                    },
                );
            }
        }
    }
    Ok(DeskScan {
        desk_rows,
        cli_needed,
        scan,
        cli_counts,
    })
}

/// The `--local-media-plan` report, v2 (batch 27e, DRY RUN ONLY — no
/// writes of any kind). Called by `import::run_local_media_plan`
/// after parse guaranteed `--target` + `--local-media-root`; the root
/// exists.
///
/// The matching lives in the cache file NAMES: one walk builds
/// `key13 → Vec<Candidate>` (picture/video/file keyed by the shadow
/// `msg_id` — the Desktop `msgId`; resource keyed by the Desktop
/// `cliMsgId`), the batch-27 `message.localPath` route adds one more
/// candidate source, and the PURE [`choose_candidate`] classifies
/// every import-sourced attachment. Everything printed is a count,
/// a fixed vocabulary word or a byte total (H-rule — no path value,
/// file name, uid, msgId or message text ever reaches a line).
pub fn plan_report(
    a: &super::super::cli::ImportArgs,
    root: &Path,
    target: &Path,
) -> Result<Vec<String>, String> {
    // The store, READ-ONLY with the normal key resolution (the
    // `repair_cli`/`media_cli` pattern). A Locked passphrase store
    // refuses: this CLI never accepts a password, not on argv, not
    // in env.
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

    // The store reads: the import-sourced attachments (any status),
    // every import-sourced message id (the plan's `needed` ids — the
    // msgType-18 video census must also see the messages WITHOUT an
    // attachment row), and the ids that DO have an attachment row.
    // Kinds and statuses are shadow vocabulary words; ids stay in
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
    let import_msg_ids: HashSet<String> = {
        let mut st = conn
            .prepare("SELECT msg_id FROM messages WHERE source = 'import'")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    let att_msg_ids: HashSet<String> = {
        let mut st = conn
            .prepare("SELECT DISTINCT msg_id FROM attachments")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };

    // The msg ids the plan needs Desktop rows for (every import
    // message — the attachments' ids are a subset).
    let needed: HashSet<String> = import_msg_ids.clone();

    // Scan every message DB once (tolerant reads as in 27c): keep
    // each needed msgId's Desktop row — its cliMsgId (the resource
    // candidates' key), its localPath (the batch-27 route) and its
    // msgType (the videos census).
    let DeskScan {
        desk_rows,
        cli_needed,
        scan,
        ..
    } = scan_desktop_rows(&p, &needed, false)?;

    // M1: the candidate index — ONE read-only walk of the root.
    let ix = walk_candidate_index(root);

    // Classify every attachment (the pure choice over the gathered
    // facts) and fold the report sections.
    let mut kinds: BTreeMap<String, KindPlan> = BTreeMap::new();
    let mut matched = 0u64;
    let mut total_bytes = 0u64;
    let mut hist = [0u64; 4];
    let mut img_msgs: BTreeMap<String, ImgMsg> = BTreeMap::new();
    let mut ratio = [0u64; 4];
    let mut ratio_pairs = 0u64;
    let mut magic_pairs: BTreeMap<(MagicClass, MagicClass), u64> = BTreeMap::new();
    for att in &atts {
        let kind_key = att.kind.clone().unwrap_or_else(|| "none".into());
        let kp = kinds.entry(kind_key).or_default();
        kp.rows += 1;
        let desk = desk_rows.get(&att.msg_id);
        if desk.is_some() {
            matched += 1;
        }
        // `already_downloaded` is decided BEFORE the lookup — no
        // candidates are gathered for a downloaded row.
        let (choice, best, facts) = if att.status == "downloaded" {
            (Choice::AlreadyDownloaded, None, Vec::new())
        } else {
            let cands = gather_candidates(&ix, &root_norm, &att.msg_id, desk);
            let facts: Vec<CandFacts> = cands.iter().map(|c| c.facts()).collect();
            let best = best_fitting(att.kind.as_deref(), &facts);
            (choose_candidate(att.kind.as_deref(), &facts), best, facts)
        };
        let e = kp.outcomes.entry(choice).or_insert((0, 0));
        e.0 += 1;
        if let Some(b) = best {
            // A copy outcome always has a best candidate; the bytes
            // it would add are its own size.
            e.1 += b.size;
            if choice.copies() {
                total_bytes += b.size;
                *kp.winners.entry(b.winner_label()).or_insert(0) += 1;
            }
        }
        // The multi-image section: every image attachment not already
        // downloaded — its FITTING candidate count, and the
        // picture-vs-resource pair when both have one.
        if att.kind.as_deref() == Some("image") && att.status != "downloaded" {
            let fitting: Vec<CandFacts> = facts
                .iter()
                .filter(|c| fits_filters(att.kind.as_deref(), c))
                .copied()
                .collect();
            hist[fitting.len().min(3)] += 1;
            let m = img_msgs.entry(att.msg_id.clone()).or_default();
            m.atts += 1;
            m.fitting += fitting.len() as u64;
            if let (Some(pb), Some(rb)) = (
                best_in_sub(&fitting, MediaSub::Picture),
                best_in_sub(&fitting, MediaSub::Resource),
            ) {
                ratio_pairs += 1;
                ratio[ratio_bucket(rb.size as f64 / pb.size as f64)] += 1;
                *magic_pairs.entry((pb.magic, rb.magic)).or_insert(0) += 1;
            }
        }
    }

    // The videos census (the rows batch 27b must CREATE): every
    // import-sourced message whose Desktop row is msgType 18 —
    // whether or not the shadow has an attachment row for it.
    let (mut v_msgs, mut v_fit, mut v_bytes, mut v_no_att) = (0u64, 0u64, 0u64, 0u64);
    for mid in &import_msg_ids {
        let Some(d) = desk_rows.get(mid) else {
            continue;
        };
        if d.msg_type != Some(18) {
            continue;
        }
        v_msgs += 1;
        let cands = gather_candidates(&ix, &root_norm, mid, Some(d));
        let facts: Vec<CandFacts> = cands.iter().map(|c| c.facts()).collect();
        if let Some(best) = best_fitting(Some("video"), &facts) {
            v_fit += 1;
            v_bytes += best.size;
            if !att_msg_ids.contains(mid) {
                v_no_att += 1;
            }
        }
    }

    // --- the lines -----------------------------------------------------------

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
    // Per shadow kind: rows, every outcome count with the bytes it
    // would add, and which source won.
    for (kind, kp) in &kinds {
        let outcomes: Vec<String> = CHOICE_FIELDS
            .iter()
            .map(|c| {
                let (n, b) = kp.outcomes.get(c).copied().unwrap_or((0, 0));
                format!("{}={}(bytes={b})", c.field(), n)
            })
            .collect();
        lines.push(format!(
            "local-media-plan: kind={kind} rows={} outcomes {}",
            kp.rows,
            outcomes.join(" ")
        ));
        let won: Vec<String> = WINNER_FIELDS
            .iter()
            .map(|w| format!("{w}:{}", kp.winners.get(*w).copied().unwrap_or(0)))
            .collect();
        lines.push(format!("local-media-plan: kind={kind} won {}", won.join(" ")));
    }
    lines.push(format!("local-media-plan: total would_copy bytes={total_bytes}"));
    // Multi-image messages: the fitting-candidate histogram per
    // attachment, and the messages whose attachments-per-message
    // differs from their fitting-candidates-per-message (the
    // attachment idx ↔ file ordering is unknown, so just count).
    lines.push(format!(
        "local-media-plan: image attachments (kind=image, not already downloaded): rows={} \
         fitting histogram 0:{} 1:{} 2:{} 3+:{}",
        hist.iter().sum::<u64>(),
        hist[0],
        hist[1],
        hist[2],
        hist[3]
    ));
    lines.push(format!(
        "local-media-plan: image messages: messages={} atts_vs_fitting_differ={}",
        img_msgs.len(),
        img_msgs.values().filter(|m| m.atts != m.fitting).count()
    ));
    // Picture vs resource for the same message: is the resource copy
    // a thumbnail or the original?
    lines.push(format!(
        "local-media-plan: picture vs resource (both fitting): pairs={ratio_pairs} ratio \
         {}:{} {}:{} {}:{} {}:{}",
        RATIO_LABELS[0],
        ratio[0],
        RATIO_LABELS[1],
        ratio[1],
        RATIO_LABELS[2],
        ratio[2],
        RATIO_LABELS[3],
        ratio[3]
    ));
    {
        let mut pairs: Vec<(&(MagicClass, MagicClass), &u64)> = magic_pairs.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let fields: Vec<String> = pairs
            .iter()
            .take(CODE_CAP)
            .map(|((pm, rm), n)| format!("{}/{}={n}", pm.name(), rm.name()))
            .collect();
        lines.push(format!(
            "local-media-plan: picture vs resource magic pairs {}",
            if fields.is_empty() {
                "none".into()
            } else {
                fields.join(" ")
            }
        ));
        let more = magic_pairs.len().saturating_sub(CODE_CAP);
        if more > 0 {
            lines.push(format!(
                "local-media-plan: picture vs resource magic pairs: more=+{more} (capped at \
                 {CODE_CAP} by count)"
            ));
        }
    }
    // Videos: the import messages with a Desktop msgType-18 row.
    lines.push(format!(
        "local-media-plan: videos (import messages with Desktop msgType 18): messages={} \
         with_fitting_candidate={} bytes={} no_attachment_row={}",
        v_msgs, v_fit, v_bytes, v_no_att
    ));
    // Index totals: the walk header, then per sub files / keyed /
    // unkeyed / keys matching a needed msgId or cliMsgId.
    lines.push(format!(
        "local-media-plan: candidate walk: uids={} uids_with_zalodownloads={} files_seen={} \
         rescache_skipped={} indexed={} cap={} cap_hit={}",
        ix.uids,
        ix.uids_with_zdl,
        ix.files_seen,
        ix.rescache_skipped,
        ix.indexed,
        WALK_CAP,
        if ix.cap_hit { "yes" } else { "no" }
    ));
    for sub in INDEXED_SUBS {
        let (files, keyed, unkeyed, keys, keys_needed) = match ix.subs.get(&sub) {
            Some(s) => (
                s.files,
                s.keyed,
                s.unkeyed,
                s.keys.len(),
                s.keys
                    .iter()
                    .filter(|k| needed.contains(*k) || cli_needed.contains(*k))
                    .count(),
            ),
            None => (0, 0, 0, 0, 0),
        };
        lines.push(format!(
            "local-media-plan: index sub={} files={files} keyed={keyed} unkeyed={unkeyed} \
             keys={keys} keys_needed={keys_needed}",
            sub.name()
        ));
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

    // --- batch 27d: the JSON shapes and the file-name keys -----------------

    #[test]
    fn digit_runs_13_extracts_exact_runs_only() {
        assert_eq!(
            digit_runs_13("p1763600000000_00112233.jxl"),
            vec!["1763600000000".to_string()]
        );
        // The whole name IS the run (the video shape).
        assert_eq!(
            digit_runs_13("1763600000000"),
            vec!["1763600000000".to_string()]
        );
        // 12- and 14-digit runs never match.
        assert!(digit_runs_13("x176360000000.jxl").is_empty());
        assert!(digit_runs_13("x17636000000001.jxl").is_empty());
        // Two runs both surface; a run is bounded by non-digits.
        assert_eq!(
            digit_runs_13("a1763600000000b1763600000001"),
            vec![
                "1763600000000".to_string(),
                "1763600000001".to_string()
            ]
        );
        assert!(digit_runs_13("othername_01.jpg").is_empty());
        assert!(digit_runs_13("").is_empty());
    }

    #[test]
    fn json_shape_folds_the_five_classes_and_key_names() {
        let mut s = JsonShape::default();
        let mut keys: BTreeMap<String, u64> = BTreeMap::new();
        s.fold_cell(
            &SV::Text(r#"{"href":"SENTINEL-V","photoId":1}"#.into()),
            &mut keys,
        );
        s.fold_cell(&SV::Text("[1,2]".into()), &mut keys);
        s.fold_cell(&SV::Text(r#""a json string scalar""#.into()), &mut keys);
        s.fold_cell(&SV::Null, &mut keys);
        s.fold_cell(&SV::Text(String::new()), &mut keys);
        s.fold_cell(&SV::Text("plain prose SENTINEL-P".into()), &mut keys);
        s.fold_cell(&SV::Text("123".into()), &mut keys);
        s.fold_cell(&SV::Integer(7), &mut keys);
        s.fold_cell(&SV::Blob(vec![1]), &mut keys);
        assert_eq!(
            s.fields(),
            "json_object:1 json_array:1 text:1 empty:2 other:4"
        );
        // Key NAMES print (schema, the content-shape rule); values
        // never — the SENTINELs above appear nowhere in `fields`.
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.get("href"), Some(&1));
        assert_eq!(keys.get("photoId"), Some(&1));
    }

    #[test]
    fn json_shape_folds_decoded_values_and_fingerprints_odd_keys() {
        let mut s = JsonShape::default();
        let mut keys: BTreeMap<String, u64> = BTreeMap::new();
        s.fold_value(&J::Null, &mut keys);
        s.fold_value(&serde_json::json!({"a": 1, "we ird!": 2}), &mut keys);
        s.fold_value(&serde_json::json!([1]), &mut keys);
        s.fold_value(&serde_json::json!("decoded string"), &mut keys);
        s.fold_value(&serde_json::json!(true), &mut keys);
        assert_eq!(
            s.fields(),
            "json_object:1 json_array:1 text:1 empty:1 other:1"
        );
        // The identifier key prints; the odd one fingerprints — never
        // its raw name.
        assert_eq!(keys.get("a"), Some(&1));
        let weird: Vec<&String> = keys.keys().filter(|k| *k != "a").collect();
        assert_eq!(weird.len(), 1, "{keys:?}");
        assert!(weird[0].starts_with("k:"), "{weird:?}");
        assert_eq!(weird[0].len(), 2 + 12);
        assert!(!weird[0].contains("we ird"), "{weird:?}");
    }

    #[test]
    fn keys_fields_orders_by_count_then_name_and_caps() {
        let mut keys: BTreeMap<String, u64> = BTreeMap::new();
        assert_eq!(keys_fields(&keys, KEY_CAP), "none");
        for (k, n) in [("b", 2u64), ("a", 5), ("c", 5), ("d", 1)] {
            keys.insert(k.into(), n);
        }
        assert_eq!(keys_fields(&keys, 4), "a:5 c:5 b:2 d:1");
        assert_eq!(keys_fields(&keys, 3), "a:5 c:5 b:2 more=+1");
        assert_eq!(keys_fields(&keys, 2), "a:5 c:5 more=+2");
        // The brief's top-30 cap: the 35 single-count keys overflow by
        // exactly 9 (4 + 35 = 39 keys, 30 shown).
        for i in 0..35 {
            keys.insert(format!("k{i:02}"), 1);
        }
        let out = keys_fields(&keys, KEY_CAP);
        assert!(out.ends_with(" more=+9"), "{out}");
        assert!(out.starts_with("a:5 c:5 "), "{out}");
    }

    #[test]
    fn name_keys_lines_counts_hits_per_sub() {
        // A constructed walk + id sets (pure — no filesystem): two
        // picture files with a 13-digit run, one video file, no
        // resource file.
        let mut rc = RevCov::default();
        rc.dttm13
            .entry(MediaSub::Picture)
            .or_default()
            .push(vec!["1763600000000".to_string()]);
        rc.dttm13
            .entry(MediaSub::Picture)
            .or_default()
            .push(vec!["1763600000001".to_string()]);
        rc.dttm13
            .entry(MediaSub::Video)
            .or_default()
            .push(vec!["1763600000001".to_string()]);
        let mut sets = MsgSets::default();
        sets.send_dttms.insert(1_763_600_000_000);
        sets.cli_ids.insert("1763600000001".to_string());
        sets.msg_ids.insert("1763600000001".to_string());
        let mut media = MediaKeys::default();
        media.send_dttms.insert(1_763_600_000_001);
        media.cli_ids.insert("1763600000000".to_string());
        let lines = name_keys_lines(&rc, &sets, &media);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines[0].contains(
                "sub=picture files_with_dttm13=2 senddttm=yes:1 climsgid=yes:1 msgid=yes:1 \
                 media_image_senddttm=yes:1 media_image_climsgid=yes:1"
            ),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains(
                "sub=video files_with_dttm13=1 senddttm=yes:0 climsgid=yes:1 msgid=yes:1 \
                 media_image_senddttm=yes:1 media_image_climsgid=yes:0"
            ),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].contains(
                "sub=resource files_with_dttm13=0 senddttm=yes:0 climsgid=yes:0 msgid=yes:0 \
                 media_image_senddttm=yes:0 media_image_climsgid=yes:0"
            ),
            "{}",
            lines[2]
        );
    }

    // --- batch 27e M2: the pure choice, every outcome and rule -------------------

    /// One synthetic candidate (no filesystem, no ids, no paths).
    fn cf(sub: MediaSub, via: CandVia, size: u64, magic: MagicClass) -> CandFacts {
        CandFacts {
            sub,
            via,
            size,
            magic,
        }
    }

    #[test]
    fn choose_candidate_every_outcome() {
        // 1. no_candidate: nothing to look at.
        assert_eq!(choose_candidate(Some("image"), &[]), Choice::NoCandidate);
        // 2. magic_mismatch: candidates exist but none fits the kind.
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(MediaSub::Picture, CandVia::Index, 10, MagicClass::Mp4)]
            ),
            Choice::MagicMismatch
        );
        // A candidate that fails BOTH filters classifies by the
        // magic — the first filter.
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(MediaSub::Picture, CandVia::Index, 0, MagicClass::Mp4)]
            ),
            Choice::MagicMismatch
        );
        // 3. size_excluded: the magic fits but every fitting
        // candidate is 0 bytes or over the cap.
        assert_eq!(
            choose_candidate(
                Some("file"),
                &[cf(MediaSub::File, CandVia::LocalPath, 0, MagicClass::Other)]
            ),
            Choice::SizeExcluded
        );
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(
                    MediaSub::Picture,
                    CandVia::Index,
                    WOULD_COPY_MAX_BYTES + 1,
                    MagicClass::Jpg
                )]
            ),
            Choice::SizeExcluded
        );
        // 4. the best fitting candidate decides: JXL (either form) is
        // would_copy_jxl_only — the archive viewer runs in WebView2,
        // which cannot render JPEG XL.
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(MediaSub::Picture, CandVia::Index, 4, MagicClass::Jxl)]
            ),
            Choice::WouldCopyJxlOnly
        );
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(MediaSub::Picture, CandVia::Index, 4, MagicClass::JxlContainer)]
            ),
            Choice::WouldCopyJxlOnly
        );
        // …everything else is would_copy_renderable.
        assert_eq!(
            choose_candidate(
                Some("image"),
                &[cf(MediaSub::Resource, CandVia::Index, 5, MagicClass::Jpg)]
            ),
            Choice::WouldCopyRenderable
        );
        // already_downloaded is the caller's pre-lookup decision —
        // choose_candidate never returns it (the end-to-end fixture
        // below covers that bucket through the report).
    }

    #[test]
    fn choose_candidate_prefers_renderable_over_jxl() {
        // Rule 1: a renderable copy beats JXL even when the JXL is
        // bigger and sits in the canonical sub.
        let cands = [
            cf(MediaSub::Picture, CandVia::Index, 100, MagicClass::Jxl),
            cf(MediaSub::Resource, CandVia::Index, 5, MagicClass::Jpg),
        ];
        assert_eq!(
            choose_candidate(Some("image"), &cands),
            Choice::WouldCopyRenderable
        );
        assert_eq!(
            best_fitting(Some("image"), &cands).unwrap().winner_label(),
            "resource"
        );
        // The classes rule 1 does not name sit between the two
        // (§10.6): pdf/zip/html/other beat JXL too.
        let cands = [
            cf(MediaSub::File, CandVia::Index, 100, MagicClass::Jxl),
            cf(MediaSub::File, CandVia::Index, 5, MagicClass::Zip),
        ];
        assert_eq!(
            choose_candidate(Some("file"), &cands),
            Choice::WouldCopyRenderable
        );
        // mp4/webm are renderable — a video choice is never jxl_only.
        assert_eq!(
            choose_candidate(
                Some("video"),
                &[cf(MediaSub::Video, CandVia::Index, 7, MagicClass::WebmMkv)]
            ),
            Choice::WouldCopyRenderable
        );
    }

    #[test]
    fn choose_candidate_prefers_the_source_subs() {
        // Rule 2: picture/video before resource; the fill-in order
        // (§10.6) is picture/video > file > resource > every other
        // <sub>.
        let mk = |sub| cf(sub, CandVia::Index, 10, MagicClass::Jpg);
        for (win, lose) in [
            (MediaSub::Picture, MediaSub::Resource),
            (MediaSub::Video, MediaSub::Resource),
            (MediaSub::File, MediaSub::Resource),
        ] {
            let cands = [mk(lose), mk(win)];
            let best = best_fitting(Some("image"), &cands).unwrap();
            assert_eq!(best.sub, win, "{win:?} must beat {lose:?}");
        }
        // Every other <sub> ranks last, whatever its route.
        let cands = [
            cf(MediaSub::Other, CandVia::LocalPath, 10, MagicClass::Jpg),
            mk(MediaSub::Resource),
        ];
        assert_eq!(
            best_fitting(Some("image"), &cands).unwrap().sub,
            MediaSub::Resource
        );
    }

    #[test]
    fn choose_candidate_prefers_the_larger_size() {
        // Rule 3: equal rank, equal sub — the larger file wins.
        let cands = [
            cf(MediaSub::Resource, CandVia::Index, 100, MagicClass::Jpg),
            cf(MediaSub::Resource, CandVia::Index, 200, MagicClass::Jpg),
        ];
        assert_eq!(best_fitting(Some("image"), &cands).unwrap().size, 200);
        // Ties keep the FIRST candidate — deterministic.
        let cands = [
            cf(MediaSub::Picture, CandVia::Index, 200, MagicClass::Jpg),
            cf(MediaSub::Picture, CandVia::Index, 200, MagicClass::Webp),
        ];
        assert_eq!(
            best_fitting(Some("image"), &cands).unwrap().magic,
            MagicClass::Jpg
        );
    }

    #[test]
    fn choose_candidate_size_bounds() {
        // 0 bytes never copies; 1 byte does; the 512 MB cap is
        // inclusive; one byte over it does not.
        assert_eq!(
            choose_candidate(
                Some("file"),
                &[cf(MediaSub::File, CandVia::Index, 0, MagicClass::Other)]
            ),
            Choice::SizeExcluded
        );
        assert_eq!(
            choose_candidate(
                Some("file"),
                &[cf(MediaSub::File, CandVia::Index, 1, MagicClass::Other)]
            ),
            Choice::WouldCopyRenderable
        );
        assert_eq!(
            choose_candidate(
                Some("file"),
                &[cf(
                    MediaSub::File,
                    CandVia::Index,
                    WOULD_COPY_MAX_BYTES,
                    MagicClass::Other
                )]
            ),
            Choice::WouldCopyRenderable,
            "the 512 MB cap is inclusive"
        );
        assert_eq!(
            choose_candidate(
                Some("file"),
                &[cf(
                    MediaSub::File,
                    CandVia::Index,
                    WOULD_COPY_MAX_BYTES + 1,
                    MagicClass::Other
                )]
            ),
            Choice::SizeExcluded
        );
        // Mixed: one over the cap, one fine — the fine one wins.
        let cands = [
            cf(
                MediaSub::File,
                CandVia::Index,
                WOULD_COPY_MAX_BYTES + 1,
                MagicClass::Zip,
            ),
            cf(MediaSub::File, CandVia::Index, 2048, MagicClass::Zip),
        ];
        assert_eq!(best_fitting(Some("file"), &cands).unwrap().size, 2048);
    }

    #[test]
    fn magic_class_ok_agrees_with_the_byte_sniff() {
        use crate::shadow::media::magic_ok;
        let heads: [(MagicClass, Vec<u8>); 12] = [
            (MagicClass::Jpg, vec![0xFF, 0xD8, 0xFF, 0xE0, 1]),
            (MagicClass::Png, vec![0x89, 0x50, 0x4E, 0x47, 1]),
            (MagicClass::Gif, b"GIF89a".to_vec()),
            (
                MagicClass::Webp,
                vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'],
            ),
            (MagicClass::Jxl, vec![0xFF, 0x0A, 0xE0]),
            (
                MagicClass::JxlContainer,
                vec![
                    0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
                ],
            ),
            (
                MagicClass::Mp4,
                vec![0, 0, 0, 0, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'],
            ),
            (MagicClass::WebmMkv, vec![0x1A, 0x45, 0xDF, 0xA3, 1]),
            (MagicClass::Pdf, b"%PDF-1.7\n".to_vec()),
            (MagicClass::Zip, vec![0x50, 0x4B, 0x03, 0x04, 1]),
            (MagicClass::Html, b"<!doctype html>".to_vec()),
            (MagicClass::Other, vec![0x37, 0x9E, 0x2C, 0xF1]),
        ];
        for (class, head) in &heads {
            assert_eq!(
                &magic_class(head),
                class,
                "the fixture head must classify as {class:?}"
            );
            for kind in [Some("image"), Some("video"), Some("file"), Some("voice"), None] {
                assert_eq!(
                    magic_class_ok(kind, *class),
                    magic_ok(kind, head),
                    "class={class:?} kind={kind:?}"
                );
            }
        }
        // An empty head classifies `other` and never fits image/video
        // — same verdict from both sides.
        assert_eq!(
            magic_class_ok(Some("image"), MagicClass::Other),
            magic_ok(Some("image"), &[])
        );
        assert_eq!(
            magic_class_ok(Some("video"), MagicClass::Other),
            magic_ok(Some("video"), &[])
        );
    }

    #[test]
    fn ratio_bucket_boundaries() {
        // The four buckets, half-open exactly as their labels read:
        // <0.25, [0.25,0.75), [0.75,1.33] (1.33 inclusive), >1.33.
        assert_eq!(ratio_bucket(0.24), 0);
        assert_eq!(ratio_bucket(0.25), 1);
        assert_eq!(ratio_bucket(0.74), 1);
        assert_eq!(ratio_bucket(0.75), 2);
        assert_eq!(ratio_bucket(1.32), 2);
        assert_eq!(ratio_bucket(1.33), 2);
        assert_eq!(ratio_bucket(1.34), 3);
        assert_eq!(ratio_bucket(4.0), 3);
    }

    #[test]
    fn winner_labels_are_the_fixed_five() {
        // An index candidate wins as its <sub> …
        for (sub, label) in [
            (MediaSub::Picture, "picture"),
            (MediaSub::Video, "video"),
            (MediaSub::Resource, "resource"),
            (MediaSub::File, "file"),
        ] {
            assert_eq!(
                cf(sub, CandVia::Index, 1, MagicClass::Jpg).winner_label(),
                label
            );
        }
        // …the localPath route wins as itself, whatever <sub> the
        // path fell in.
        for sub in [MediaSub::Picture, MediaSub::Cache, MediaSub::Other] {
            assert_eq!(
                cf(sub, CandVia::LocalPath, 1, MagicClass::Jpg).winner_label(),
                "localPath"
            );
        }
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

        /// A FAKE shadow store (raw key) for the v2 plan (batch 27e):
        /// import-sourced messages, plus attachment rows at explicit
        /// `idx` values — including messages WITHOUT any attachment
        /// row (the msgType-18 video gap 27b must fill) and
        /// multi-attachment messages.
        fn synthetic_store_v2(
            msgs: &[&str],
            atts: &[(u8, &str, &str, Option<&str>, &str)],
        ) -> PathBuf {
            let dir = temp_dir("store27e");
            let key = Zeroizing::new(sqlcipher::generate_key().unwrap());
            sqlcipher::save_key(&key, &crate::shadow::key_file(&dir)).unwrap();
            {
                let conn =
                    sqlcipher::open_with_key(&crate::shadow::db_file(&dir), &key).unwrap();
                crate::shadow::schema::apply(&conn).unwrap();
                for mid in msgs {
                    conn.execute(
                        "INSERT INTO messages (msg_id, conv_id, ts, type, payload_json, source)
                         VALUES (?1, 'cM', 1, 1, '{}', 'import')",
                        [mid],
                    )
                    .unwrap();
                }
                for (idx, mid, kind, url, status) in atts {
                    conn.execute(
                        "INSERT INTO attachments (msg_id, idx, kind, url, status)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![mid, idx, kind, url, status],
                    )
                    .unwrap();
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
                local_media_copy: false,
                include_video: false,
                limit: None,
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
        fn plan_report_v2_matches_by_cache_name_keys() {
            // --- the ZaloDownloads tree (all synthetic, under temp) ---
            let root = temp_dir("root27e");
            let uid_dir = root.join("media").join("19");
            let pic = uid_dir.join("ZaloDownloads").join("picture");
            let res = uid_dir.join("ZaloDownloads").join("resource");
            let vid = uid_dir.join("ZaloDownloads").join("video");
            let fil = uid_dir.join("ZaloDownloads").join("file");
            let noise = uid_dir.join("ZaloDownloads").join("fileNoise");
            for dir in [&pic, &res, &vid, &fil, &noise] {
                std::fs::create_dir_all(dir).unwrap();
            }
            // The msg ids are 13-digit runs (the cache-name keys).
            let id_a = format!("{DTTM}"); // picture + resource copies
            let id_b = format!("{}", DTTM + 2); // jxl-only image
            let id_c = format!("{}", DTTM + 10); // msgType 18, NO attachment row
            let id_d = format!("{}", DTTM + 20); // magic_mismatch (mp4 in picture)
            let id_e = format!("{}", DTTM + 30); // size_excluded (0-byte file)
            let id_f = format!("{}", DTTM + 40); // no_candidate
            let id_g = format!("{}", DTTM + 50); // multi-image (two attachments)
            let id_i = format!("{}", DTTM + 60); // already downloaded
            let id_j = format!("{}", DTTM + 70); // the localPath route
            let id_k = format!("{}", DTTM + 80); // fileNoise skip
            let id_m = format!("{}", DTTM + 11); // msgType 18 WITH a row
            let cli_a = format!("{}", DTTM + 9); // A's cliMsgId — the resource key

            std::fs::write(
                pic.join(format!("p{id_a}_00112233445566778899aabbccddeeff.jxl")),
                [0xFFu8, 0x0A, 0xE0, 0x0D],
            )
            .unwrap(); // 4B JXL — A's picture
            std::fs::write(
                pic.join(format!("p{id_b}_00112233445566778899aabbccddee01.jxl")),
                [0xFFu8, 0x0A, 1, 2, 3, 4],
            )
            .unwrap(); // 6B JXL — B
            std::fs::write(
                pic.join(format!("p{id_d}_00112233445566778899aabbccddee02.dat")),
                [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2],
            )
            .unwrap(); // 10B mp4 magic — D's magic_mismatch
            std::fs::write(
                pic.join(format!("p{id_g}_00112233445566778899aabbccddee03.jxl")),
                [0xFFu8, 0x0A, 1, 2, 3, 4, 5],
            )
            .unwrap(); // 7B JXL — G (two attachments share it)
            std::fs::write(
                pic.join(format!("p{id_i}_00112233445566778899aabbccddee04.jpg")),
                [0xFFu8, 0xD8, 0xFF, 0xE0, 1, 2],
            )
            .unwrap(); // 6B jpg — I (already downloaded)
            let plain = pic.join("plainname.jpg"); // unkeyed; J's localPath
            std::fs::write(&plain, [0xFFu8, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4]).unwrap(); // 8B jpg
            std::fs::write(pic.join("index.rescache"), b"opaque").unwrap();
            std::fs::write(
                res.join(format!("{cli_a}_00ff00112233445566778899aabbccdd.jpg")),
                [0xFFu8, 0xD8, 0xFF, 0xE0, 1],
            )
            .unwrap(); // 5B jpg — A's resource (the cliMsgId key)
            std::fs::write(&vid.join(&id_c), [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2])
                .unwrap(); // 10B mp4 — C
            std::fs::write(
                &vid.join(&id_m),
                [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2, 3, 4],
            )
            .unwrap(); // 12B mp4 — M
            std::fs::write(fil.join("readme.pdf"), b"%PDF-1.7\n").unwrap(); // unkeyed
            let empty = fil.join("empty.bin"); // unkeyed, 0 bytes
            std::fs::write(&empty, b"").unwrap(); // E's size_excluded
            let obf = noise.join("0123456789abcdef0123456789abcdef");
            std::fs::write(&obf, [0x37u8, 0x9E, 0x2C, 0xF1, 1]).unwrap(); // never decoded

            // Desktop rows: J's localPath points at the unkeyed
            // plain-name picture; K's is RELATIVE (resolved via
            // folderPath) and lands under fileNoise — counted by the
            // probe, never decoded, so it can never be a candidate.
            let rows = format!(
                "INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_a}', '{cli_a}', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_b}', 'clib', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_c}', 'clic', 18, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_d}', 'clid', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_e}', 'clie', 19, '{empty_p}', NULL, NULL, NULL, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_f}', 'clif', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_g}', 'clig', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_i}', 'clii', 2, NULL, NULL, NULL, NULL, {DTTM}, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_j}', 'clij', 2, '{plain_p}', NULL, NULL, NULL, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_k}', 'clik', 19, 'ZaloDownloads\\\\fileNoise\\\\0123456789abcdef0123456789abcdef', \
                  '{uid_p}', NULL, NULL, NULL, 'x'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('{id_m}', 'clim', 18, NULL, NULL, NULL, NULL, {DTTM}, 'x');",
                empty_p = q(&empty.to_string_lossy()),
                plain_p = q(&plain.to_string_lossy()),
                uid_p = q(&uid_dir.to_string_lossy()),
            );
            let (snap, key) = synthetic_snapshot(PASS, &rows);

            // The shadow store: C is an import-sourced msgType-18
            // message WITHOUT an attachment row (the one 27b must
            // create); G carries TWO image attachments; I is
            // already downloaded.
            let store = synthetic_store_v2(
                &[
                    &id_a, &id_b, &id_c, &id_d, &id_e, &id_f, &id_g, &id_i, &id_j, &id_k,
                    &id_m,
                ],
                &[
                    (0, &id_a, "image", Some("https://fake-stal.zdn.vn/a.jpg"), "ref-import"),
                    (0, &id_b, "image", Some("https://fake-stal.zdn.vn/b.jpg"), "ref-import"),
                    (0, &id_d, "image", Some("https://fake-stal.zdn.vn/d.jpg"), "ref"),
                    (0, &id_e, "file", Some("https://fake-stal.zdn.vn/e.bin"), "ref"),
                    (0, &id_f, "image", Some("https://fake-stal.zdn.vn/f.jpg"), "ref"),
                    (0, &id_g, "image", Some("https://fake-stal.zdn.vn/g0.jpg"), "ref-import"),
                    (1, &id_g, "image", Some("https://fake-stal.zdn.vn/g1.jpg"), "ref-import"),
                    (0, &id_i, "image", Some("https://fake-stal.zdn.vn/i.jpg"), "downloaded"),
                    (0, &id_j, "image", Some("https://fake-stal.zdn.vn/j.jpg"), "ref"),
                    (0, &id_k, "file", Some("https://fake-stal.zdn.vn/k.bin"), "ref"),
                    (0, &id_m, "video", Some("https://fake-stal.zdn.vn/m.mp4"), "ref-import"),
                ],
            );

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
                    "local-media-plan: import-sourced attachments: rows=11 desktop_rows_matched=11 \
                     kinds=3"
                ),
                "{joined}"
            );
            // The single walk: 13 files seen (one rescache skipped),
            // 8 indexed candidates, no cap hit.
            assert!(
                joined.contains(
                    "local-media-plan: candidate walk: uids=1 uids_with_zalodownloads=1 \
                     files_seen=13 rescache_skipped=1 indexed=8 cap=200000 cap_hit=no"
                ),
                "{joined}"
            );
            // The index totals: every unkeyed file counts (the
            // plain-name picture, the pdf and the 0-byte bin).
            assert!(
                joined.contains(
                    "local-media-plan: index sub=picture files=6 keyed=5 unkeyed=1 keys=5 \
                     keys_needed=5"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: index sub=video files=2 keyed=2 unkeyed=0 keys=2 \
                     keys_needed=2"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: index sub=resource files=1 keyed=1 unkeyed=0 keys=1 \
                     keys_needed=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: index sub=file files=2 keyed=0 unkeyed=2 keys=0 \
                     keys_needed=0"
                ),
                "{joined}"
            );
            // file: E size_excluded (a 0-byte localPath target) and
            // K no_candidate (the relative fileNoise localPath —
            // resolved via folderPath, then skipped, never decoded).
            assert!(
                joined.contains(
                    "local-media-plan: kind=file rows=2 outcomes already_downloaded=0(bytes=0) \
                     would_copy_renderable=0(bytes=0) would_copy_jxl_only=0(bytes=0) \
                     magic_mismatch=0(bytes=0) size_excluded=1(bytes=0) no_candidate=1(bytes=0)"
                ),
                "{joined}"
            );
            // image: A renderable via the resource copy (rule 1), B
            // and G×2 jxl-only, D magic_mismatch (an mp4-magic
            // picture file), F no_candidate, I already downloaded,
            // J the localPath route.
            assert!(
                joined.contains(
                    "local-media-plan: kind=image rows=8 outcomes already_downloaded=1(bytes=0) \
                     would_copy_renderable=2(bytes=13) would_copy_jxl_only=3(bytes=20) \
                     magic_mismatch=1(bytes=0) size_excluded=0(bytes=0) no_candidate=1(bytes=0)"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: kind=image won picture:3 video:0 resource:1 file:0 \
                     localPath:1"
                ),
                "{joined}"
            );
            // video: M would_copy via the video sub.
            assert!(
                joined.contains(
                    "local-media-plan: kind=video rows=1 outcomes already_downloaded=0(bytes=0) \
                     would_copy_renderable=1(bytes=12) would_copy_jxl_only=0(bytes=0) \
                     magic_mismatch=0(bytes=0) size_excluded=0(bytes=0) no_candidate=0(bytes=0)"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: kind=video won picture:0 video:1 resource:0 file:0 \
                     localPath:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-plan: total would_copy bytes=45"),
                "{joined}"
            );
            // Multi-image: A has TWO fitting candidates (the
            // picture JXL and the resource JPG); D and F have none;
            // G's two attachments share one candidate each; I is
            // decided before the lookup and never counted here.
            assert!(
                joined.contains(
                    "local-media-plan: image attachments (kind=image, not already downloaded): \
                     rows=7 fitting histogram 0:2 1:4 2:1 3+:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-plan: image messages: messages=6 atts_vs_fitting_differ=3"
                ),
                "{joined}"
            );
            // Picture vs resource (A): the 5-byte resource jpg over
            // the 4-byte picture jxl → 1.25, and the jxl/jpg pair.
            assert!(
                joined.contains(
                    "local-media-plan: picture vs resource (both fitting): pairs=1 ratio \
                     <0.25:0 0.25–0.75:0 0.75–1.33:1 >1.33:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-plan: picture vs resource magic pairs jxl/jpg=1"),
                "{joined}"
            );
            // Videos: C (NO attachment row — the one batch 27b must
            // create) and M (with one).
            assert!(
                joined.contains(
                    "local-media-plan: videos (import messages with Desktop msgType 18): \
                     messages=2 with_fitting_candidate=2 bytes=22 no_attachment_row=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-plan: done (DRY RUN ONLY — nothing was written)"),
                "{joined}"
            );
            // H-rule self-check: no path value, file name, uid, msgId,
            // cliMsgId, url or message text anywhere.
            for banned in [
                id_a.as_str(),
                id_b.as_str(),
                id_c.as_str(),
                id_d.as_str(),
                id_e.as_str(),
                id_f.as_str(),
                id_g.as_str(),
                id_i.as_str(),
                id_j.as_str(),
                id_k.as_str(),
                id_m.as_str(),
                cli_a.as_str(),
                "clib",
                "plainname",
                "readme",
                "empty.bin",
                "0123456789abcdef",
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
                    "local-media-plan: kind=image rows=1 outcomes already_downloaded=0(bytes=0) \
                     would_copy_renderable=0(bytes=0) would_copy_jxl_only=1(bytes=4) \
                     magic_mismatch=0(bytes=0) size_excluded=0(bytes=0) no_candidate=0(bytes=0)"
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

        // --- batch 27d: Media.db / Res.db ----------------------------------

        /// The real Media.db / Res.db DDL (the reviewer's schema
        /// excerpt), so the batch-27d fixed column lists are exercised
        /// exactly as the real tables declare them.
        const IMAGE_DDL: &str = "CREATE TABLE image (
    mediaId TEXT PRIMARY KEY, convId TEXT, cliMsgId TEXT, fromUid TEXT,
    content TEXT, type INTEGER, src TEXT, sendDttm INTEGER, ttl INTEGER,
    localPath TEXT, previewThumb TEXT, modifiedTime INTEGER,
    metadata TEXT, ev TEXT
  );";
        const FILE_DDL: &str = "CREATE TABLE file (
    mediaId TEXT PRIMARY KEY, convId TEXT, cliMsgId TEXT, fromUid TEXT,
    content TEXT, type INTEGER, src TEXT, extType INTEGER, sendDttm INTEGER,
    ttl INTEGER, modifiedTime INTEGER, localPath TEXT, folderPath TEXT,
    thumbMetadata TEXT, ev TEXT
  );";
        const RES_DDL: &str = "CREATE TABLE res (
    uid TEXT PRIMARY KEY, size INTEGER, type INTEGER, atime INTEGER,
    params TEXT
  );";
        const REF_DDL: &str =
            "CREATE TABLE ref (msgId TEXT PRIMARY KEY, convId TEXT, uid TEXT);";

        /// Open (creating) a top-level SQLCipher DB keyed by the
        /// snapshot passphrase — the way the real top-level DBs open
        /// (batch 27 M1 measured them with the cipher key).
        fn open_top_fixture(path: &Path, pass: &str) -> Connection {
            let conn = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            )
            .unwrap();
            apply_passphrase_key(&conn, pass).unwrap();
            conn
        }

        /// The exact Zalo BasicEncryption pipeline (desktop_cipher's
        /// own test helper): the cell stores
        /// `JSON.stringify(xor(JSON.stringify(value), key))`.
        fn enc_cell(value: &serde_json::Value, key: &str) -> String {
            let plain = serde_json::to_string(value).unwrap();
            let xored = crate::shadow::import::desktop_cipher::basic_xor_utf16(&plain, key);
            serde_json::to_string(&serde_json::Value::String(xored)).unwrap()
        }

        /// The batch-27d end-to-end fixture: a Media.db whose `image`
        /// row A is the LINK ROW — `localPath` points at the temp-dir
        /// picture file, and its `cliMsgId`/`sendDttm`/`(convId,
        /// cliMsgId)`/`mediaId` all match a Desktop `message` row —
        /// plus the other content shapes (plain object, prose, blob)
        /// and a Res.db whose `res.uid` values are cache file STEMS
        /// and whose `ref` rows half-match the message/res sets.
        /// Asserts every relation counter, and the H-rule end to end.
        #[test]
        fn probe_report_media_db_and_res_db_sections() {
            // The media root: the standard fixture (a JXL picture
            // named p<13 digits>_<32 hex>, an unreferenced JPEG, a
            // rescache index, a 13-digit mp4 video) plus one resource
            // file whose 13-digit part is the SECOND message row's
            // cliMsgId and whose stem a Res.db `res` row carries.
            let root = synthetic_media_root();
            let uid_dir = root.join("media").join("19");
            let pic_file = uid_dir
                .join("ZaloDownloads")
                .join("picture")
                .join(format!("p{DTTM}_00112233445566778899aabbccddeeff.jxl"));
            let res_dir = uid_dir.join("ZaloDownloads").join("resource");
            std::fs::create_dir_all(&res_dir).unwrap();
            let cli2 = format!("{}", DTTM + 5); // a 13-digit cliMsgId
            let res_stem = format!("{cli2}_00ff00112233445566778899aabbccdd");
            let res_file = res_dir.join(format!("{res_stem}.jpg"));
            std::fs::write(&res_file, [0xFFu8, 0xD8, 0xFF, 0xE0, 1]).unwrap();

            // Two message rows in 111.db (conv id 111): the first's ids
            // match the Media.db image row A below (the link row); the
            // second's cliMsgId is the resource file's 13-digit part.
            let rows = format!(
                "INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('8488000000001', 'cli0001', 2, '{jxl}', NULL, 'pv', 4, {DTTM}, 'never read'); \
                 INSERT INTO message \
                 (msgId, cliMsgId, msgType, localPath, folderPath, previewThumb, fileSize, \
                  sendDttm, message) VALUES \
                 ('8488000000005', '{cli2}', 2, NULL, NULL, NULL, NULL, {DTTM}, 'never read');",
                jxl = q(&pic_file.to_string_lossy()),
            );
            let (snap, key) = synthetic_snapshot(PASS, &rows);

            // Media.db: `image` row A (the link row — encrypted
            // content, the real localPath, ids matching the message
            // row), row B (a plain-object content), row C (prose),
            // row D (a BLOB content whose mediaId is still a message
            // msgId); `file` row F (a RELATIVE localPath resolved via
            // folderPath to the video file).
            let enc_a = enc_cell(
                &serde_json::json!({
                    "href": "https://fake-stal.zdn.vn/SENTINEL-A.jpg",
                    "params": "{\"hd\":\"https://fake-stal.zdn.vn/SENTINEL-HD.jpg\"}",
                    "photoId": "ph-A"
                }),
                PASS,
            );
            {
                let conn = open_top_fixture(&snap.join("Media.db"), PASS);
                conn.execute_batch(&format!("{IMAGE_DDL}\n{FILE_DDL}")).unwrap();
                let ins_image = "INSERT INTO image (mediaId, convId, cliMsgId, fromUid, \
                     content, type, src, sendDttm, ttl, localPath, previewThumb, modifiedTime, \
                     metadata, ev) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
                conn.execute(
                    ins_image,
                    rusqlite::params![
                        "8488000000001", // mediaId = a real message msgId
                        "111",           // convId = the DB file digits
                        "cli0001",       // cliMsgId matches the message row
                        "u",
                        enc_a,
                        2,
                        "s",
                        DTTM,
                        0,
                        pic_file.to_string_lossy(),
                        "pv",
                        0,
                        r#"{"width":100,"height":50}"#,
                        Option::<&str>::None,
                    ],
                )
                .unwrap();
                conn.execute(
                    ins_image,
                    rusqlite::params![
                        "mediab", "111", "clib", "u",
                        r#"{"photoId":"SENTINEL-P","caption":"SENTINEL-CAP"}"#,
                        2, "s", Option::<i64>::None, 0,
                        Option::<&str>::None, Option::<&str>::None, 0,
                        "", Option::<&str>::None,
                    ],
                )
                .unwrap();
                conn.execute(
                    ins_image,
                    rusqlite::params![
                        "mediac", "111", Option::<&str>::None, "u",
                        "prose SENTINEL-PROSE",
                        2, "s", Option::<i64>::None, 0,
                        Option::<&str>::None, Option::<&str>::None, 0,
                        Option::<&str>::None, Option::<&str>::None,
                    ],
                )
                .unwrap();
                conn.execute(
                    ins_image,
                    rusqlite::params![
                        "8488000000005", "111", Option::<&str>::None, "u",
                        rusqlite::types::Value::Blob(vec![1, 2, 3]),
                        2, "s", Option::<i64>::None, 0,
                        Option::<&str>::None, Option::<&str>::None, 0,
                        Option::<&str>::None, Option::<&str>::None,
                    ],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO file (mediaId, convId, cliMsgId, fromUid, content, type, \
                     src, extType, sendDttm, ttl, modifiedTime, localPath, folderPath, \
                     thumbMetadata, ev) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    rusqlite::params![
                        "mediaf", "111", &cli2, "u",
                        r#"{"href":"https://fake-stal.zdn.vn/SENTINEL-F.doc"}"#,
                        19, "s", 0, Option::<i64>::None, 0, 0,
                        format!(r"ZaloDownloads\video\{DTTM}"),
                        uid_dir.to_string_lossy(),
                        r#"{"t":1}"#,
                        Option::<&str>::None,
                    ],
                )
                .unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }

            // Res.db: `res` uids are cache file STEMS (the resource
            // file's, the unreferenced picture's) plus one that is
            // no file; `ref` rows half-match the message and res sets.
            {
                let conn = open_top_fixture(&snap.join("Res.db"), PASS);
                conn.execute_batch(&format!("{RES_DDL}\n{REF_DDL}")).unwrap();
                conn.execute(
                    "INSERT INTO res (uid, size, type, atime, params) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        &res_stem, 5, 1, 0,
                        r#"{"cdnUrl":"https://fake-stal.zdn.vn/SENTINEL-R","ttl":3600}"#,
                    ],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO res (uid, size, type, atime, params) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params!["othername_01", 1, 1, 0, Option::<&str>::None],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO res (uid, size, type, atime, params) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params!["no-such-file", 1, 2, 0, "notjson"],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO ref (msgId, convId, uid) VALUES (?1, ?2, ?3)",
                    rusqlite::params!["8488000000001", "111", &res_stem],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO ref (msgId, convId, uid) VALUES (?1, ?2, ?3)",
                    rusqlite::params!["ghost-msg", "111", "never-in-res"],
                )
                .unwrap();
                conn.close().map_err(|(_, e)| e).unwrap();
            }

            let uin = sha12(PASS.as_bytes());
            let a = args_for(&snap, &uin, &key);
            let p = prepare(&a).unwrap();
            let lines = probe_report(&p, &root, None).unwrap();
            let joined = lines.join("\n");

            // Both top-level DBs open with the snapshot key.
            assert!(
                joined.contains("local-media-probe: Media.db opened=yes (cipher)"),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Res.db opened=yes (cipher)"),
                "{joined}"
            );

            // The image census: 4 rows, one localPath (the real JXL),
            // under the root, picture, exists, 4 bytes, jxl magic.
            assert!(
                joined
                    .contains("local-media-probe: Media.db image: rows=4 row_failed=0 coerce_none=none"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 rows=4 localpath=1 previewthumb=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 paths shape=abs_drive:1 \
                     abs_unc:0 relative:0 file_url:0 other:0 under_root=yes:1 no:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 files exists=yes:1 no:0 \
                     size_zero:0 total_bytes=4"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 magic jpg:0 png:0 gif:0 webp:0 jxl:1"
                ),
                "{joined}"
            );
            // The name relations (the batch-27 convention: only the
            // rows WITH a localPath participate; `na` is an id that is
            // NULL among those rows): the cache file name carries the
            // 13-digit sendDttm, never the ids.
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 name climsgid=yes:0 no:1 na:0 \
                     mediaid=yes:0 no:1 na:0 senddttm=yes:1 no:0 na:0 dttm13=yes:1 no:0 na:0"
                ),
                "{joined}"
            );
            // The row ↔ message-set relations: row A matches on every
            // axis (cliMsgId, mediaId-as-msgId, the (convId, cliMsgId)
            // pair); row D's mediaId is the other message msgId; rows
            // B and C match nothing (their ids exist but are not
            // message ids); row D has no cliMsgId (na).
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 rel climsgid_in_message=yes:1 \
                     no:1 na:2 mediaid_in_message=yes:2 no:2 na:0 pair_in_message=yes:1 no:1 na:2"
                ),
                "{joined}"
            );
            // The content shapes and the batch-24 decode: one
            // encrypted cell (ok), one BLOB (fail), two kept (na).
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 content json_object:1 \
                     json_array:0 text:1 empty:0 other:2 decrypt=ok:1 fail:1 na:2"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 content decoded json_object:2 \
                     json_array:0 text:1 empty:0 other:0"
                ),
                "{joined}"
            );
            // The key names (schema; values never): row B's raw object
            // keys, then the decrypted+kept objects' keys.
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 content keys caption:1 photoId:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 content decoded keys photoId:2 \
                     caption:1 href:1 params:1"
                ),
                "{joined}"
            );
            // The metadata shapes and keys.
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 metadata json_object:1 \
                     json_array:0 text:0 empty:3 other:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db image type=2 metadata keys height:1 width:1"
                ),
                "{joined}"
            );

            // The file census: one row, RELATIVE localPath resolved via
            // folderPath to the existing mp4.
            assert!(
                joined
                    .contains("local-media-probe: Media.db file: rows=1 row_failed=0 coerce_none=none"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 rows=1 localpath=1 folderpath=1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 paths shape=abs_drive:0 \
                     abs_unc:0 relative:1 file_url:0 other:0 under_root=yes:1 no:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 files exists=yes:1 no:0 \
                     size_zero:0 total_bytes=10"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 name climsgid=yes:0 no:1 na:0 \
                     mediaid=yes:0 no:1 na:0 senddttm=yes:0 no:0 na:1 dttm13=yes:0 no:0 na:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 rel climsgid_in_message=yes:1 \
                     no:0 na:0 mediaid_in_message=yes:0 no:1 na:0 pair_in_message=yes:1 no:0 na:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 content json_object:1 \
                     json_array:0 text:0 empty:0 other:0 decrypt=ok:0 fail:0 na:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Media.db file type=19 metadata json_object:1 \
                     json_array:0 text:0 empty:0 other:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Media.db file type=19 metadata keys t:1"),
                "{joined}"
            );

            // The res census: uids that ARE cache file stems, per
            // `<sub>`, plus the params shapes and key names.
            assert!(
                joined
                    .contains("local-media-probe: Res.db res: rows=3 row_failed=0 coerce_none=none"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Res.db res type=1 rows=2 params json_object:1 \
                     json_array:0 text:0 empty:1 other:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Res.db res type=1 params keys cdnUrl:1 ttl:1"),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Res.db res type=1 uid_file_hits picture:1 resource:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: Res.db res type=2 rows=1 params json_object:0 \
                     json_array:0 text:0 empty:0 other:1"
                ),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Res.db res type=2 params keys none"),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Res.db res type=2 uid_file_hits none"),
                "{joined}"
            );
            // ref: one msgId the messages know, one they do not; one
            // uid in res, one not.
            assert!(
                joined.contains(
                    "local-media-probe: Res.db ref: rows=2 row_failed=0 coerce_none=none \
                     msgid_in_message=yes:1 no:1 na:0 uid_in_res=yes:1 no:1 na:0"
                ),
                "{joined}"
            );

            // The walk gained the resource file: 5 files seen, 3
            // unreferenced (the JPEG, the mp4 and the resource file —
            // only the message row's localPath counts as a reference).
            assert!(
                joined.contains(
                    "local-media-probe: reverse coverage: uids=1 uids_with_zalodownloads=1 \
                     files_seen=5 rescache_skipped=1 referenced=1 cap=200000 cap_hit=no"
                ),
                "{joined}"
            );
            assert!(joined.contains("local-media-probe: unref total=3"), "{joined}");

            // The file-name keys: the picture and video files' 13-digit
            // parts equal a message sendDttm and a Media.db image
            // sendDttm; the resource file's equals a message cliMsgId.
            assert!(
                joined.contains(
                    "local-media-probe: name-keys sub=picture files_with_dttm13=1 \
                     senddttm=yes:1 climsgid=yes:0 msgid=yes:0 media_image_senddttm=yes:1 \
                     media_image_climsgid=yes:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: name-keys sub=video files_with_dttm13=1 \
                     senddttm=yes:1 climsgid=yes:0 msgid=yes:0 media_image_senddttm=yes:1 \
                     media_image_climsgid=yes:0"
                ),
                "{joined}"
            );
            assert!(
                joined.contains(
                    "local-media-probe: name-keys sub=resource files_with_dttm13=1 \
                     senddttm=yes:0 climsgid=yes:1 msgid=yes:0 media_image_senddttm=yes:0 \
                     media_image_climsgid=yes:0"
                ),
                "{joined}"
            );

            // M2: no MD5 in the dependency tree — reported, skipped.
            assert!(
                joined.contains("local-media-probe: picture-name hash: md5=unavailable"),
                "{joined}"
            );

            // H-rule self-check: no path value, file name, uid, msgId,
            // cliMsgId, url or message text anywhere.
            for banned in [
                "8488000000001",
                "8488000000005",
                "cli0001",
                "1763600000005",
                "1763600000000",
                res_stem.as_str(),
                "00ff00112233445566778899aabbccdd",
                "00112233",
                "othername",
                "SENTINEL",
                "never read",
                "ghost-msg",
                "no-such-file",
                "never-in-res",
                "https://",
                "zdn.vn",
                "prose",
                "mediab",
                "mediac",
                "mediaf",
                "ph-A",
            ] {
                assert!(!joined.contains(banned), "a value leaked: {banned}\n{joined}");
            }
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A snapshot without Media.db / Res.db reports both sections
        /// as skipped (never fatal) and still prints the md5 line and
        /// the name-keys section over the walk alone.
        #[test]
        fn probe_report_skips_media_and_res_when_absent() {
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
            assert!(
                joined
                    .contains("local-media-probe: Media.db: skipped (no Media.db in the snapshot)"),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: Res.db: skipped (no Res.db in the snapshot)"),
                "{joined}"
            );
            assert!(
                joined.contains("local-media-probe: picture-name hash: md5=unavailable"),
                "{joined}"
            );
            // The name-keys section still renders: the walk still
            // counts the picture file's 13-digit run, but without a
            // sendDttm-carrying message row (and no Media.db) no set
            // matches.
            assert!(
                joined.contains(
                    "local-media-probe: name-keys sub=picture files_with_dttm13=1 \
                     senddttm=yes:0 climsgid=yes:0 msgid=yes:0 media_image_senddttm=yes:0 \
                     media_image_climsgid=yes:0"
                ),
                "{joined}"
            );
            let _ = std::fs::remove_dir_all(&snap);
            let _ = std::fs::remove_dir_all(&root);
        }

        // --- batch 27b M1: the copy mode, synthetic end to end -------------------

        use super::super::copy;
        use sha2::{Digest, Sha256};

        fn cid(n: i64) -> String {
            format!("{}", DTTM + n)
        }

        /// A synthetic world for the copy mode: a snapshot, a media
        /// root (the Zalo PC tree), a shadow store and a separate
        /// media STORE root. Message letters → ids: A=1 B=2 C=3 D=4
        /// E=5 F=6 G=7 H=8 I=9 J=10 K=11 L=12, decoy E2=50.
        struct CopyFx {
            snap: PathBuf,
            key: PathBuf,
            root: PathBuf,
            store: PathBuf,
            media: PathBuf,
        }

        const JPG6: [u8; 6] = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2];
        const JPG7: [u8; 7] = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3];
        const JXL7: [u8; 7] = [0xFF, 0x0A, 1, 2, 3, 4, 5];

        fn copy_fixture() -> CopyFx {
            let root = temp_dir("root27b");
            let zdl = root.join("media").join("19").join("ZaloDownloads");
            let (pic, res, vid, fil) = (
                zdl.join("picture"),
                zdl.join("resource"),
                zdl.join("video"),
                zdl.join("file"),
            );
            for d in [&pic, &res, &vid, &fil] {
                std::fs::create_dir_all(d).unwrap();
            }
            let hex = "00ff00112233445566778899aabbccdd";
            // A: renderable jpg. B: jxl only. C: downloaded decoy. D:
            // ref-encrypted decoy. F: multi-attachment. K: failed -> jpg.
            std::fs::write(pic.join(format!("p{}_{hex}.jpg", cid(1))), JPG6).unwrap();
            std::fs::write(pic.join(format!("p{}_{hex}.jxl", cid(2))), JXL7).unwrap();
            std::fs::write(pic.join(format!("p{}_{hex}.jpg", cid(3))), JPG6).unwrap();
            std::fs::write(pic.join(format!("p{}_{hex}.jpg", cid(4))), JPG6).unwrap();
            std::fs::write(pic.join(format!("p{}_{hex}.jpg", cid(6))), JPG6).unwrap();
            std::fs::write(pic.join(format!("p{}_{hex}.jpg", cid(11))), JPG7).unwrap();
            // E: only a resource copy keyed by a cliMsgId that sits on
            // TWO Desktop rows -> ambiguous_key.
            std::fs::write(
                res.join(format!("{}_{hex}.jpg", cid(105))),
                [0xFFu8, 0xD8, 0xFF, 0xE0, 9],
            )
            .unwrap();
            // G: the best candidate by preference (file sub, 5 B) has the
            // wrong size; the resource copy (9 B) matches fileSize 9.
            std::fs::write(fil.join(format!("{}.bin", cid(7))), [7u8; 5]).unwrap();
            std::fs::write(res.join(format!("{}_{hex}.dat", cid(107))), [9u8; 9]).unwrap();
            // H: only a wrong-size file candidate -> size_mismatch.
            std::fs::write(fil.join(format!("{}.bin", cid(8))), [8u8; 5]).unwrap();
            // L: an mp4 for an existing video row; I: an mp4 for a
            // msgType-18 message with NO attachment row.
            std::fs::write(
                vid.join(cid(12)),
                [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2, 3, 4],
            )
            .unwrap();
            std::fs::write(
                vid.join(cid(9)),
                [0u8, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2],
            )
            .unwrap();

            let row = |n: i64, cli: String, ty: i64, fsize: Option<i64>| {
                format!(
                    "INSERT INTO message (msgId, cliMsgId, msgType, localPath, folderPath, \
                     previewThumb, fileSize, sendDttm, message) VALUES \
                     ('{}', '{cli}', {ty}, NULL, NULL, NULL, {}, {DTTM}, 'x'); ",
                    cid(n),
                    fsize.map(|v| v.to_string()).unwrap_or_else(|| "NULL".into())
                )
            };
            let mut rows = String::new();
            rows += &row(1, "c1".into(), 2, None);
            rows += &row(2, "c2".into(), 2, None);
            rows += &row(3, "c3".into(), 2, None);
            rows += &row(4, "c4".into(), 2, None);
            rows += &row(5, cid(105), 2, None); // E (ambiguous cli)
            rows += &row(50, cid(105), 2, None); // the decoy: same cliMsgId
            rows += &row(6, "c6".into(), 2, None);
            rows += &row(7, cid(107), 19, Some(9)); // G
            rows += &row(8, "c8".into(), 19, Some(9)); // H
            rows += &row(9, "c9".into(), 18, None); // I: video, no att row
            rows += &row(10, "c10".into(), 18, None); // J: video, no files
            rows += &row(11, "c11".into(), 2, None);
            rows += &row(12, "c12".into(), 18, None); // L: video row
            let (snap, key) = synthetic_snapshot(PASS, &rows);

            let ids: Vec<String> = (1..=12).map(cid).collect();
            let m: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
            let store = synthetic_store_v2(
                &m,
                &[
                    (0, &ids[0], "image", Some("https://fake.zdn.vn/a"), "ref-import"),
                    (0, &ids[1], "image", Some("https://fake.zdn.vn/b"), "ref"),
                    (0, &ids[2], "image", Some("https://fake.zdn.vn/c"), "downloaded"),
                    (0, &ids[3], "image", Some("https://fake.zdn.vn/d"), "ref-encrypted"),
                    (0, &ids[4], "image", Some("https://fake.zdn.vn/e"), "ref-import"),
                    (0, &ids[5], "image", Some("https://fake.zdn.vn/f0"), "ref-import"),
                    (1, &ids[5], "image", Some("https://fake.zdn.vn/f1"), "ref-import"),
                    (0, &ids[6], "file", Some("https://fake.zdn.vn/g"), "ref-import"),
                    (0, &ids[7], "file", Some("https://fake.zdn.vn/h"), "ref"),
                    (0, &ids[10], "image", Some("https://fake.zdn.vn/k"), "failed"),
                    (0, &ids[11], "video", Some("https://fake.zdn.vn/l"), "ref-import"),
                ],
            );
            CopyFx {
                snap,
                key,
                root,
                store,
                media: temp_dir("media27b"),
            }
        }

        fn copy_args(fx: &CopyFx, apply: bool, video: bool, limit: Option<u64>) -> ImportArgs {
            let uin = sha12(PASS.as_bytes());
            let mut a = args_for(&fx.snap, &uin, &fx.key);
            a.local_media_copy = true;
            a.local_media_root = Some(fx.root.clone());
            a.target = Some(fx.store.clone());
            a.apply = apply;
            a.i_have_a_backup_plan = apply;
            a.include_video = video;
            a.limit = limit;
            a
        }

        /// Run the copy with injected probes: `free` bytes on the media
        /// volume, `running` = the zalors.exe probe.
        fn run_copy_with(
            a: &ImportArgs,
            fx: &CopyFx,
            free: Option<u64>,
            running: Option<bool>,
        ) -> (Result<(), String>, Vec<String>) {
            let mut lines: Vec<String> = Vec::new();
            let free_fn = move |_: &Path| free;
            let run_fn = move || running;
            let env = copy::CopyEnv {
                media_root: fx.media.clone(),
                free_space: &free_fn,
                zalors_running: &run_fn,
            };
            let r = copy::copy_run(a, &fx.root, &fx.store, &env, &mut |l: &str| {
                lines.push(l.to_string())
            });
            (r, lines)
        }

        fn run_copy(a: &ImportArgs, fx: &CopyFx) -> (Result<(), String>, Vec<String>) {
            run_copy_with(a, fx, Some(u64::MAX / 2), Some(false))
        }

        type AttRowT = (
            String,
            i64,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
        );

        /// Every attachment row (msg_id, idx, kind, status, local_path,
        /// sha256, size), read-only.
        fn att_rows(store: &Path) -> Vec<AttRowT> {
            let (conn, _k) = crate::shadow::passphrase::open_store(store, true).unwrap();
            let mut st = conn
                .prepare(
                    "SELECT msg_id, idx, kind, status, local_path, sha256, size \
                       FROM attachments ORDER BY msg_id, idx",
                )
                .unwrap();
            let v = st
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })
                .unwrap()
                .filter_map(Result::ok)
                .collect();
            v
        }

        fn status_of(rows: &[AttRowT], n: i64, idx: i64) -> String {
            let id = cid(n);
            rows.iter()
                .find(|r| r.0 == id && r.1 == idx)
                .unwrap_or_else(|| panic!("no row {n}/{idx}"))
                .3
                .clone()
        }

        /// Regular files under the media store (not temp files, not
        /// the JXL cache).
        fn store_files(media: &Path) -> usize {
            fn walk(d: &Path, n: &mut usize) {
                let Ok(rd) = std::fs::read_dir(d) else { return };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, n);
                    } else if !e.file_name().to_string_lossy().ends_with(".tmp") {
                        *n += 1;
                    }
                }
            }
            let mut n = 0;
            walk(media, &mut n);
            n
        }

        fn backup_count(store: &Path) -> usize {
            std::fs::read_dir(store.join("pre-localmedia-backups"))
                .map(|rd| {
                    rd.flatten()
                        .filter(|e| e.file_name().to_string_lossy().ends_with(".db"))
                        .count()
                })
                .unwrap_or(0)
        }

        fn cleanup(fx: &CopyFx) {
            let _ = std::fs::remove_dir_all(&fx.snap);
            let _ = std::fs::remove_dir_all(&fx.root);
            let _ = std::fs::remove_dir_all(&fx.store);
            let _ = std::fs::remove_dir_all(&fx.media);
        }

        #[test]
        fn copy_dry_run_reports_every_outcome_and_writes_nothing() {
            let fx = copy_fixture();
            let before = att_rows(&fx.store);
            let (r, lines) = run_copy(&copy_args(&fx, false, false, None), &fx);
            r.unwrap();
            let j = lines.join("\n");
            let m = "local-media-copy dry run";
            assert!(j.contains(&format!("{m}: store=given (read-only)")), "{j}");
            assert!(
                j.contains(&format!(
                    "{m}: import-sourced attachments: rows=11 kinds=3"
                )),
                "{j}"
            );
            // The cliMsgId census: the decoy shares E's key.
            assert!(j.contains("cliMsgId census:"), "{j}");
            assert!(
                j.contains(&format!(
                    "{m}: kind=image rows=8 outcomes already_downloaded=1 not_eligible=1 \
                     multi_attachment=2 ambiguous_key=1 no_candidate=0 magic_mismatch=0 \
                     size_excluded=0 size_mismatch=0 would_copy_renderable=2(bytes=13) \
                     would_copy_jxl_only=1(bytes=7)"
                )),
                "{j}"
            );
            assert!(
                j.contains(&format!(
                    "{m}: kind=file rows=2 outcomes already_downloaded=0 not_eligible=0 \
                     multi_attachment=0 ambiguous_key=0 no_candidate=0 magic_mismatch=0 \
                     size_excluded=0 size_mismatch=1 would_copy_renderable=1(bytes=9) \
                     would_copy_jxl_only=0(bytes=0)"
                )),
                "{j}"
            );
            assert!(
                j.contains(&format!(
                    "{m}: kind=video rows=1 outcomes already_downloaded=0 not_eligible=0 \
                     multi_attachment=0 ambiguous_key=0 no_candidate=0 magic_mismatch=0 \
                     size_excluded=0 size_mismatch=0 would_copy_renderable=1(bytes=12) \
                     would_copy_jxl_only=0(bytes=0)"
                )),
                "{j}"
            );
            // Videos without an attachment row are only COUNTED.
            assert!(
                j.contains(&format!(
                    "{m}: videos (msgType 18, no attachment row): messages=2 outcomes \
                     already_downloaded=0 not_eligible=0 multi_attachment=0 ambiguous_key=0 \
                     no_candidate=1 magic_mismatch=0 size_excluded=0 size_mismatch=0 \
                     would_copy_renderable=1(bytes=10) would_copy_jxl_only=0(bytes=0) \
                     rows_to_insert=1 (counted only; add --include-video"
                )),
                "{j}"
            );
            assert!(
                j.contains(&format!(
                    "{m}: planned: files=5 bytes=41 new_video_rows=0"
                )),
                "{j}"
            );
            assert!(j.contains(&format!("{m}: disk check: needed_bytes=")), "{j}");
            assert!(j.contains("DRY RUN — nothing was written"), "{j}");
            // No write of any kind.
            assert_eq!(att_rows(&fx.store), before);
            assert_eq!(store_files(&fx.media), 0);
            assert_eq!(backup_count(&fx.store), 0);
            assert!(!fx.store.join("pre-localmedia-backups").exists());
            // H-rule: no id, name, path, URL in any line.
            for n in (1..=12).chain([50, 105, 107]) {
                assert!(!j.contains(&cid(n)), "an id leaked ({n})\n{j}");
            }
            for banned in [
                "https://",
                ".jpg",
                ".jxl",
                ".bin",
                "zr-local-media",
                &*fx.root.to_string_lossy(),
                &*fx.store.to_string_lossy(),
                &*fx.media.to_string_lossy(),
                &*fx.snap.to_string_lossy(),
            ] {
                assert!(!j.contains(banned), "a value leaked: {banned}\n{j}");
            }
            cleanup(&fx);
        }

        #[test]
        fn copy_apply_copies_updates_rows_and_is_idempotent() {
            let fx = copy_fixture();
            let before = att_rows(&fx.store);
            let (r, lines) = run_copy(&copy_args(&fx, true, false, None), &fx);
            r.unwrap_or_else(|e| panic!("{e}\n{}", lines.join("\n")));
            let j = lines.join("\n");
            let m = "local-media-copy apply";
            assert!(j.contains(&format!("{m}: no other zalors.exe is running")), "{j}");
            assert!(j.contains(&format!("{m}: store=given (read-write)")), "{j}");
            assert!(j.contains(&format!("{m}: backup verified OK")), "{j}");
            assert!(
                j.contains(&format!(
                    "{m}: copied=5 bytes_copied=41 errors open=0 io=0 magic=0 too_big=0 store=0"
                )),
                "{j}"
            );
            assert!(j.contains(&format!("{m}: video rows inserted=0")), "{j}");
            assert!(j.contains(&format!("{m}: integrity_check=ok")), "{j}");
            assert_eq!(backup_count(&fx.store), 1);

            let after = att_rows(&fx.store);
            assert_eq!(after.len(), before.len(), "no row added without --include-video");
            // Copied rows: A(1) B(2) K(11) G(7) L(12).
            for n in [1, 2, 11, 7, 12] {
                assert_eq!(status_of(&after, n, 0), "downloaded", "{n}");
                let r = after.iter().find(|r| r.0 == cid(n) && r.1 == 0).unwrap();
                let rel = r.4.as_deref().expect("local_path set");
                let sha = r.5.as_deref().expect("sha set");
                assert_eq!(sha.len(), 64);
                assert_eq!(rel, format!("{}/{}/{}", &sha[..2], &sha[2..4], sha));
                let bytes = std::fs::read(fx.media.join(rel)).unwrap();
                assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha);
                assert_eq!(r.6, Some(bytes.len() as i64));
            }
            // Byte-exact content: A is the 6-byte jpg.
            let a_rel = after
                .iter()
                .find(|r| r.0 == cid(1))
                .unwrap()
                .4
                .clone()
                .unwrap();
            assert_eq!(std::fs::read(fx.media.join(a_rel)).unwrap(), JPG6);
            // Untouched: downloaded (C) keeps its NULL path, ref-encrypted
            // (D), ambiguous (E), multi-attachment (F x2), size
            // mismatch (H) all keep status and columns.
            for (n, idx, status) in [
                (3, 0, "downloaded"),
                (4, 0, "ref-encrypted"),
                (5, 0, "ref-import"),
                (6, 0, "ref-import"),
                (6, 1, "ref-import"),
                (8, 0, "ref"),
            ] {
                assert_eq!(status_of(&after, n, idx), status, "{n}/{idx}");
                let b = before.iter().find(|r| r.0 == cid(n) && r.1 == idx).unwrap();
                let a = after.iter().find(|r| r.0 == cid(n) && r.1 == idx).unwrap();
                assert_eq!(a, b, "row {n}/{idx} must be byte-identical");
            }
            assert_eq!(store_files(&fx.media), 5);

            // A second apply copies 0 and changes nothing (no extra backup).
            let (r2, lines2) = run_copy(&copy_args(&fx, true, false, None), &fx);
            r2.unwrap();
            let j2 = lines2.join("\n");
            assert!(j2.contains(&format!("{m}: nothing to copy")), "{j2}");
            assert!(j2.contains(&format!("{m}: copied=0 bytes=0")), "{j2}");
            assert_eq!(att_rows(&fx.store), after);
            assert_eq!(store_files(&fx.media), 5);
            assert_eq!(backup_count(&fx.store), 1);

            // --include-video: one row INSERTED (idx 0, kind video) and
            // copied; J (no candidate) gets none.
            let (r3, lines3) = run_copy(&copy_args(&fx, true, true, None), &fx);
            r3.unwrap();
            let j3 = lines3.join("\n");
            assert!(
                j3.contains(&format!(
                    "{m}: copied=1 bytes_copied=10 errors open=0 io=0 magic=0 too_big=0 store=0"
                )),
                "{j3}"
            );
            assert!(j3.contains(&format!("{m}: video rows inserted=1")), "{j3}");
            let v = att_rows(&fx.store);
            assert_eq!(v.len(), after.len() + 1);
            let nr = v.iter().find(|r| r.0 == cid(9)).expect("the new video row");
            assert_eq!((nr.1, nr.2.as_deref(), nr.3.as_str()), (0, Some("video"), "downloaded"));
            assert!(nr.4.is_some() && nr.5.as_deref().map(str::len) == Some(64));
            assert_eq!(nr.6, Some(10));
            assert!(!v.iter().any(|r| r.0 == cid(10)), "J has no candidate: no row");
            assert_eq!(store_files(&fx.media), 6);
            assert_eq!(backup_count(&fx.store), 2);
            // …and a rerun of it is idempotent too.
            let (r4, lines4) = run_copy(&copy_args(&fx, true, true, None), &fx);
            r4.unwrap();
            assert!(lines4.join("\n").contains(&format!("{m}: copied=0 bytes=0")));
            assert_eq!(att_rows(&fx.store), v);
            cleanup(&fx);
        }

        #[test]
        fn copy_dry_run_with_include_video_still_inserts_nothing() {
            let fx = copy_fixture();
            let before = att_rows(&fx.store);
            let (r, lines) = run_copy(&copy_args(&fx, false, true, None), &fx);
            r.unwrap();
            let j = lines.join("\n");
            assert!(
                j.contains("planned: files=6 bytes=51 new_video_rows=1"),
                "{j}"
            );
            assert!(j.contains("--include-video: they are inserted and copied"), "{j}");
            assert_eq!(att_rows(&fx.store), before);
            assert_eq!(store_files(&fx.media), 0);
            cleanup(&fx);
        }

        #[test]
        fn copy_limit_stops_after_n_copies() {
            let fx = copy_fixture();
            let (r, lines) = run_copy(&copy_args(&fx, true, false, Some(2)), &fx);
            r.unwrap();
            let j = lines.join("\n");
            assert!(j.contains("planned: files=2 bytes="), "{j}");
            assert!(j.contains("copied=2 "), "{j}");
            let rows = att_rows(&fx.store);
            // Processing order is msg_id, idx: A then B.
            assert_eq!(status_of(&rows, 1, 0), "downloaded");
            assert_eq!(status_of(&rows, 2, 0), "downloaded");
            for n in [7, 11, 12] {
                assert_ne!(status_of(&rows, n, 0), "downloaded", "{n} is past the limit");
            }
            assert_eq!(store_files(&fx.media), 2);
            // The next run (no limit) continues with the rest: 3 more.
            let (r2, lines2) = run_copy(&copy_args(&fx, true, false, None), &fx);
            r2.unwrap();
            assert!(lines2.join("\n").contains("copied=3 "));
            assert_eq!(store_files(&fx.media), 5);
            cleanup(&fx);
        }

        #[test]
        fn copy_apply_refuses_when_the_disk_check_fails_and_writes_nothing() {
            let fx = copy_fixture();
            let before = att_rows(&fx.store);
            // Planned 41 bytes: needs 41 x 1.05 + 1 GiB. Free = exactly
            // 1 GiB is not enough.
            let (r, _l) = run_copy_with(
                &copy_args(&fx, true, false, None),
                &fx,
                Some(1 << 30),
                Some(false),
            );
            let e = r.unwrap_err();
            assert!(e.contains("disk check: not enough free space"), "{e}");
            assert!(e.contains("no writes were performed"), "{e}");
            // An unmeasurable volume fails closed too.
            let (r, _l) = run_copy_with(
                &copy_args(&fx, true, false, None),
                &fx,
                None,
                Some(false),
            );
            let e = r.unwrap_err();
            assert!(e.contains("cannot measure the free space"), "{e}");
            // Just enough: needed (1 GiB + 44) < free passes.
            let need = copy::needed_bytes(41) as u64;
            let (r, _l) = run_copy_with(
                &copy_args(&fx, false, false, None),
                &fx,
                Some(need + 1),
                Some(false),
            );
            r.unwrap();
            assert_eq!(att_rows(&fx.store), before);
            assert_eq!(store_files(&fx.media), 0);
            assert_eq!(backup_count(&fx.store), 0, "no backup before the disk check passes");
            cleanup(&fx);
        }

        #[test]
        fn copy_apply_guards_refuse_before_any_write() {
            let fx = copy_fixture();
            let before = att_rows(&fx.store);
            // Guard 1: another zalors.exe, and a failed probe.
            let (r, _l) = run_copy_with(&copy_args(&fx, true, false, None), &fx, Some(u64::MAX / 2), Some(true));
            assert!(r.unwrap_err().contains("another zalors.exe process is running"));
            let (r, _l) = run_copy_with(&copy_args(&fx, true, false, None), &fx, Some(u64::MAX / 2), None);
            assert!(r.unwrap_err().contains("cannot verify that no other zalors.exe"));
            // --apply without the confirmation flag.
            let mut a = copy_args(&fx, true, false, None);
            a.i_have_a_backup_plan = false;
            let (r, _l) = run_copy(&a, &fx);
            assert!(r.unwrap_err().contains("--i-have-a-backup-plan"));
            assert_eq!(att_rows(&fx.store), before);
            assert_eq!(store_files(&fx.media), 0);
            assert_eq!(backup_count(&fx.store), 0);
            // The dry run does not need the process probe at all (the
            // app may keep running).
            let (r, _l) = run_copy_with(&copy_args(&fx, false, false, None), &fx, Some(u64::MAX / 2), Some(true));
            r.unwrap();
            cleanup(&fx);
        }

        #[test]
        fn copy_refuses_a_locked_passphrase_store() {
            let fx = copy_fixture();
            // Passphrase mode without a remember file: Locked.
            crate::shadow::passphrase::write_marker(&fx.store, crate::shadow::schema::now_ms())
                .unwrap();
            for apply in [false, true] {
                let (r, _l) = run_copy(&copy_args(&fx, apply, false, None), &fx);
                let e = r.unwrap_err();
                assert!(e.contains("password-protected (passphrase mode)"), "{e}");
                assert!(e.contains("never accepts passwords"), "{e}");
                assert!(e.contains("Nhớ trên máy này"), "{e}");
            }
            assert_eq!(store_files(&fx.media), 0);
            assert_eq!(backup_count(&fx.store), 0);
            cleanup(&fx);
        }

        #[test]
        fn copy_refuses_a_store_without_the_db() {
            let fx = copy_fixture();
            let empty = temp_dir("nostore27b");
            let mut a = copy_args(&fx, false, false, None);
            a.target = Some(empty.clone());
            let free_fn = |_: &Path| Some(u64::MAX / 2);
            let run_fn = || Some(false);
            let env = copy::CopyEnv {
                media_root: fx.media.clone(),
                free_space: &free_fn,
                zalors_running: &run_fn,
            };
            let e = copy::copy_run(&a, &fx.root, &empty, &env, &mut |_l: &str| {}).unwrap_err();
            assert!(e.contains("--target: no "), "{e}");
            let _ = std::fs::remove_dir_all(&empty);
            cleanup(&fx);
        }
    }
}
