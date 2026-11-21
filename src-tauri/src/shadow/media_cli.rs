//! `zalors media` CLI (batch 26, M1): the read-only SHAPE tool for the
//! media queue. Dispatched from `main.rs` before Tauri starts, exactly
//! like `repair`:
//!
//! ```text
//! zalors media --target <shadow store dir> --shape
//!              [--probe-http <1..=20>] [--out <file>] [--help]
//! ```
//!
//! What it answers (the situation that created this batch): a real
//! Desktop import wrote ~58k `attachments` rows whose urls the live
//! media thread then tried to download 8 per cycle, every one failing
//! with nothing but `ok=0 failed=8` to show for it. This tool prints
//! the SHAPE of those rows — counts, kinds, host suffixes, path
//! segment counts, charset classes, sorted query KEY names — never a
//! url, host, path value, file name or message text (H-rule).
//!
//! Hard rules obeyed:
//! - READ-ONLY. The store opens through the normal key resolution
//!   (`passphrase::open_store`, the `repair_cli` pattern — the raw
//!   DPAPI key file, or the passphrase remember file); a Locked
//!   passphrase store refuses with the documented message: the CLI
//!   never accepts a password, not on argv, not in env. NO process
//!   check, NO backup, NO writes: the tool is safe while the app keeps
//!   running.
//! - `--probe-http <n>` is the ONLY network code path in this batch:
//!   for up to `n` import-sourced `status IN ('ref','failed','expired')`
//!   rows per kind whose url passes the allowlist, ONE GET with the
//!   same agent config as `fetch_to_store` (no automatic redirects,
//!   same timeouts), reading at most the first 16 bytes. Nothing is
//!   stored, no url is ever printed, and NO TEST may call it (the pure
//!   classification helpers are tested instead).
//! - `--out <file>` writes the same report to a file and REFUSES if
//!   the file already exists.
//! - Exit codes: 0 ok/help · 1 runtime refusal or failure · 2 parse
//!   error.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::Value;

use super::db_file;
use super::media::{self, RedirectHop};
use super::passphrase;
use super::pipeline::sqlite_kind;
use super::writer;

/// The usage text (`--help`, and after any parse error).
const USAGE: &str = "\
usage: zalors media --target <shadow store dir> --shape
                    [--probe-http <1..=20>] [--out <file>] [--help]

the read-only media SHAPE report over the store's attachments queue:

  --target <dir>      the shadow STORE dir to inspect. REQUIRED; no
                      default — the live store is never silently chosen
  --shape             the (only) mode: print the census. Required
  --probe-http <n>    OPTIONAL network probe, off by default. For up to
                      n import-sourced rows with status
                      ref|failed|expired PER KIND whose url passes the
                      host allowlist: ONE GET (the download agent's own
                      config — no redirects, the same timeouts), at most
                      the first 16 bytes read, nothing stored, no url
                      printed. n must be 1..=20
  --out <file>        also write the same report to <file>; REFUSES if
                      the file already exists
  --help              this usage, exit 0

the store opens READ-ONLY with the normal key resolution (raw DPAPI key
file, or the passphrase remember file; a Locked passphrase store
refuses — this CLI never accepts a password). The app may keep
running: no process check, no backup, no writes.

output is shape only (H-rule): counts, kinds, host SUFFIXES from the
allowlist, path segment counts, charset classes, sorted query KEY
names — never a url, host, path value, file name or message text.
exit codes: 0 ok · 1 runtime refusal or failure · 2 parse error";

/// Parsed `zalors media …` arguments (pure parse result — see `parse`).
#[derive(Debug, Clone, PartialEq)]
pub struct MediaArgs {
    /// `--target <dir>` (required): the shadow STORE dir.
    pub target: PathBuf,
    /// `--shape` (required): the one mode.
    pub shape: bool,
    /// `--probe-http <1..=20>` (optional, default off): the bounded
    /// network probe.
    pub probe_http: Option<u32>,
    /// `--out <file>` (optional): also write the report to a new file.
    pub out: Option<PathBuf>,
    /// `--help`: print usage, exit 0 (no other flag required).
    pub help: bool,
}

/// Store a first-wins-once value; duplicates are a parse error.
fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{flag} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// Store a valueless flag; repeats are a parse error.
fn set_bool_once(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{flag} given twice"));
    }
    *slot = true;
    Ok(())
}

/// Parse the argv of a `zalors media …` invocation (everything after
/// the `media` word). Pure: never prints, never touches the FS — the
/// `cli.rs`/`repair_cli.rs` rules: value flags consume exactly one
/// value (missing or `--`-prefixed is an error), boolean flags consume
/// nothing, unknown args are errors, duplicates are errors, `--help`
/// short-circuits the required flags. `--probe-http` must be 1..=20.
pub fn parse(args: &[String]) -> Result<MediaArgs, String> {
    let mut target: Option<PathBuf> = None;
    let mut shape = false;
    let mut probe_http: Option<u32> = None;
    let mut out: Option<PathBuf> = None;
    let mut help = false;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--target" || flag == "--out" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got {value}"));
            }
            if flag == "--target" {
                set_once(&mut target, flag, PathBuf::from(value))?;
            } else {
                set_once(&mut out, flag, PathBuf::from(value))?;
            }
            i += 2;
            continue;
        }
        if flag == "--probe-http" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got {value}"));
            }
            let n: u32 = value
                .parse()
                .map_err(|_| format!("{flag} needs a number, got {value}"))?;
            if !(1..=20).contains(&n) {
                return Err(format!("{flag} needs a value 1..=20, got {n}"));
            }
            set_once(&mut probe_http, flag, n)?;
            i += 2;
            continue;
        }
        match flag {
            "--shape" => set_bool_once(&mut shape, flag)?,
            "--help" => set_bool_once(&mut help, flag)?,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }

    if help {
        return Ok(MediaArgs {
            target: PathBuf::new(),
            shape,
            probe_http,
            out,
            help: true,
        });
    }
    if !shape {
        return Err("missing required --shape (the media CLI has one mode)".into());
    }
    Ok(MediaArgs {
        target: target.ok_or("missing required --target <shadow store dir>")?,
        shape,
        probe_http,
        out,
        help: false,
    })
}

/// CLI entrypoint (the bin dispatches `zalors media …` here BEFORE
/// starting Tauri, exactly like `import`/`repair`). Exit codes:
/// 0 usage/success · 1 runtime refusal/failure · 2 parse error.
pub fn main(args: &[String]) -> i32 {
    match parse(args) {
        Ok(a) if a.help => {
            println!("{USAGE}");
            0
        }
        Ok(a) => {
            let mut out = |line: &str| println!("{line}");
            match run(&a, &mut out) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("media: {e}");
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("media: {e}\n{USAGE}");
            2
        }
    }
}

/// The shape run: open the store READ-ONLY, stream every line through
/// `out` as it is produced (the repair CLI's F3 convention), and write
/// the same report to `--out` when asked. No process probe, no
/// backup, no writes — the app may keep running.
pub fn run(a: &MediaArgs, out: &mut dyn FnMut(&str)) -> Result<(), String> {
    // Runtime belts (parse enforces; direct callers get the same).
    if !a.shape {
        return Err("missing required --shape (the media CLI has one mode)".into());
    }
    let target = a.target.clone();
    // --out must be a NEW file — refuse before any work.
    if let Some(p) = &a.out {
        if p.exists() {
            return Err(format!(
                "--out: {} exists — refusing to overwrite",
                p.display()
            ));
        }
    }
    let db_path = db_file(&target);
    if !db_path.is_file() {
        return Err(format!(
            "--target: no {} — not a shadow store dir?",
            db_path.display()
        ));
    }

    // The normal key resolution, read-only (the repair_cli pattern). A
    // Locked passphrase store refuses: this CLI never accepts a
    // password, not on argv, not in env.
    let conn = match passphrase::open_store(&target, true) {
        Ok((c, _key)) => c,
        Err(passphrase::StoreOpenError::Locked) => {
            return Err(
                "the target store is password-protected (passphrase mode): unlock it in the app \
                 with 'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the \
                 media shape CLI never accepts passwords"
                    .into(),
            )
        }
        Err(passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ))
        }
    };
    // Collect the report: streamed line by line, kept for --out. The
    // target line is PART of the report — the --out file must carry
    // every printed line.
    let mut lines: Vec<String> = Vec::new();
    let mut emit = |l: String| {
        out(&l);
        lines.push(l);
    };
    emit(format!(
        "media shape: target={} (read-only; the app may keep running — no writes, no backup)",
        target.display()
    ));

    // --- section 1: the attachments census -----------------------------
    emit("== census (attachments joined to messages) ==".into());
    for l in census_lines(&conn)? {
        emit(l);
    }

    // --- section 2: the import-sourced rows ----------------------------
    emit("== import rows: which field the picker took ==".into());
    for l in import_field_lines(&conn)? {
        emit(l);
    }
    emit("== import content: url-bearing keys (names + counts) ==".into());
    for l in content_url_key_lines(&conn)? {
        emit(l);
    }

    // --- optional probe (the ONLY network path; no test calls it) -----
    if let Some(n) = a.probe_http {
        emit("== probe-http (one GET per row; counts only) ==".into());
        for l in probe_http_lines(&conn, n)? {
            emit(l);
        }
    }

    if let Some(p) = &a.out {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(p, body.as_bytes())
            .map_err(|e| format!("--out: write failed ({:?})", e.kind()))?;
        out(&format!("media shape: report written to {}", p.display()));
    }
    Ok(())
}

// --- section 1: the census ---------------------------------------------------

/// One census group. `Ord` over the fields in declaration order is the
/// printed order (deterministic). Every field is SHAPE: a source/kind/
/// status vocabulary, an allowlist suffix or `blocked`/`nourl`, a
/// segment COUNT, a charset CLASS, sorted key NAMES — never a value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CensusKey {
    source: String,
    kind: String,
    status: String,
    /// `allowed(<suffix>)` | `blocked` | `nourl`.
    host: String,
    /// Path segment count (0 when there is no parsable path).
    path_segs: usize,
    /// The first segment's charset class, `-` when there is none.
    seg1: String,
    /// Sorted, comma-joined query KEY names (names only, never values).
    query_keys: String,
    /// Any query key that looks like an expiry/signature parameter.
    expiryish: bool,
}

/// The full census over `attachments` LEFT JOIN `messages` on `msg_id`,
/// grouped by (source, kind, status, host verdict+suffix, path shape,
/// sorted query key names, expiryish flag). Counts only (H-rule).
pub(crate) fn census_lines(conn: &Connection) -> Result<Vec<String>, String> {
    let mut groups: BTreeMap<CensusKey, usize> = BTreeMap::new();
    let mut total = 0usize;
    let mut no_message = 0usize;
    let stage = "census";
    let mut st = conn
        .prepare(
            "SELECT a.kind, a.status, a.url, m.source
               FROM attachments a
               LEFT JOIN messages m ON m.msg_id = a.msg_id",
        )
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    for row in rows {
        let (kind, status, url, source) =
            row.map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
        total += 1;
        // The join's NULL side: no message row names this attachment.
        let source = match source {
            Some(s) => s,
            None => {
                no_message += 1;
                "no-message".to_string()
            }
        };
        let host = match url.as_deref().map(media::allowed_suffix) {
            Some(Some(suffix)) => format!("allowed({suffix})"),
            Some(None) => "blocked".into(),
            None => "nourl".into(),
        };
        let (path_segs, seg1) = path_shape(url.as_deref());
        let (keys, expiryish) = query_keys(url.as_deref());
        let key = CensusKey {
            source,
            kind: kind.unwrap_or_else(|| "none".into()),
            status: status.unwrap_or_else(|| "none".into()),
            host,
            path_segs,
            seg1: seg1.into(),
            query_keys: keys.join(","),
            expiryish,
        };
        *groups.entry(key).or_insert(0) += 1;
    }
    let mut lines = vec![format!(
        "media shape: attachments={total} no_message={no_message} groups={}",
        groups.len()
    )];
    for (k, n) in &groups {
        lines.push(format!(
            "media shape: source={} kind={} status={} host={} pathsegs={} seg1class={} query_keys=[{}] expiryish={} count={}",
            k.source, k.kind, k.status, k.host, k.path_segs, k.seg1, k.query_keys, k.expiryish, n
        ));
    }
    Ok(lines)
}

/// The url's PATH shape: segment count + the first segment's charset
/// CLASS — never the value. `(0, "-")` when there is no parsable path
/// (a NULL url, or not an https url at all).
fn path_shape(url: Option<&str>) -> (usize, &'static str) {
    let Some(url) = url else {
        return (0, "-");
    };
    let Some(rest) = url.strip_prefix("https://") else {
        return (0, "-");
    };
    // The path starts at the authority's terminating '/'.
    let Some(path_start) = rest.find('/') else {
        return (0, "-");
    };
    let path = &rest[path_start..];
    let path = path.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.first() {
        None => (0, "-"),
        Some(first) => (segs.len(), seg_class(first)),
    }
}

/// The charset CLASS of one path segment (never its value).
fn seg_class(seg: &str) -> &'static str {
    if seg.is_empty() {
        return "empty";
    }
    if !seg.is_ascii() {
        return "other";
    }
    if seg.bytes().all(|b| b.is_ascii_digit()) {
        return "digits";
    }
    if seg.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "hex";
    }
    if seg.bytes().all(|b| b.is_ascii_alphabetic()) {
        return "alpha";
    }
    if seg.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return "alnum";
    }
    "mixed"
}

/// The sorted set of query KEY names (names only — values are never
/// touched), plus whether any of them looks like an expiry or
/// signature parameter: `exp`, `expires`, `e`, `sig`, `signature`,
/// `token`, `x-amz-*`, `Expires`, `Signature` — case-insensitive.
fn query_keys(url: Option<&str>) -> (Vec<String>, bool) {
    let Some(url) = url else {
        return (Vec::new(), false);
    };
    let Some((_, q)) = url.split_once('?') else {
        return (Vec::new(), false);
    };
    let q = q.split('#').next().unwrap_or("");
    let mut keys: Vec<String> = Vec::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let key = pair.split('=').next().unwrap_or("");
        if key.is_empty() {
            continue;
        }
        if !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
        }
    }
    keys.sort();
    let expiryish = keys.iter().any(|k| looks_expiry_signature(k));
    (keys, expiryish)
}

/// M1: does one query KEY name look like an expiry or signature
/// parameter (a NAME, not a value — names are shape, values never
/// print)? Case-insensitive; `x-amz-*` is a prefix family.
fn looks_expiry_signature(key: &str) -> bool {
    match key.to_ascii_lowercase().as_str() {
        "exp" | "expires" | "e" | "sig" | "signature" | "token" => true,
        k => k.starts_with("x-amz-"),
    }
}

// --- section 2: which field the picker took ---------------------------------

/// Re-run [`writer::pick_attachments_fields`] on the stored
/// `payload_json` of every import-sourced attachment row and report
/// the FIELD the url was taken from (`params.hd`, `href`, …) — names
/// and counts only; the picked url itself is only ever COMPARED to
/// the stored one (match/differ counts), never printed.
pub(crate) fn import_field_lines(conn: &Connection) -> Result<Vec<String>, String> {
    let stage = "import_fields";
    let mut pick_fields: BTreeMap<String, usize> = BTreeMap::new();
    let (mut rows, mut pick_none, mut url_match, mut url_differ) = (0usize, 0usize, 0usize, 0usize);
    let mut st = conn
        .prepare(
            "SELECT a.idx, a.url, m.payload_json
               FROM attachments a
               JOIN messages m ON m.msg_id = a.msg_id
              WHERE m.source = 'import'",
        )
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    let rows_it = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    for row in rows_it {
        let (idx, url, payload) = row.map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
        rows += 1;
        let picks = match payload.as_deref().and_then(pick_of_payload) {
            Some(p) => p,
            None => {
                pick_none += 1;
                continue;
            }
        };
        match picks.get(idx.max(0) as usize) {
            None => pick_none += 1,
            Some((_kind, picked, field)) => {
                *pick_fields.entry(field.clone()).or_insert(0) += 1;
                if Some(picked.as_str()) == url.as_deref() {
                    url_match += 1;
                } else {
                    url_differ += 1;
                }
            }
        }
    }
    let mut lines = vec![format!(
        "media shape: import_rows={rows} pick_none={} pick_url_matches_stored={url_match} \
         pick_url_differs_stored={url_differ}",
        pick_none
    )];
    for (field, n) in &pick_fields {
        lines.push(format!("media shape: pick_field={field} count={n}"));
    }
    if pick_fields.is_empty() {
        lines.push("media shape: pick_field=none count=0".into());
    }
    Ok(lines)
}

/// The picker's candidates over one stored payload, or `None` when the
/// payload is missing/not JSON.
fn pick_of_payload(
    payload: &str,
) -> Option<Vec<(&'static str, String, String)>> {
    let v: Value = serde_json::from_str(payload).ok()?;
    let msg_type = v.get("msgType").and_then(Value::as_str).unwrap_or("");
    let content = v.get("content").cloned().unwrap_or(Value::Null);
    Some(writer::pick_attachments_fields(msg_type, &content))
}

/// The url-bearing KEY names that exist in import-sourced message
/// content at all (top-level https-string keys plus the parsed
/// `params` object's https-string keys as `params.<name>`), with
/// counts. Names only — never values (H-rule).
pub(crate) fn content_url_key_lines(conn: &Connection) -> Result<Vec<String>, String> {
    let stage = "content_keys";
    let mut keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut st = conn
        .prepare("SELECT payload_json FROM messages WHERE source = 'import'")
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    let rows = st
        .query_map([], |r| r.get::<_, Option<String>>(0))
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    for row in rows {
        let payload = row.map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
        let Some(payload) = payload else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&payload) else {
            continue;
        };
        let Some(content) = v.get("content").and_then(Value::as_object) else {
            continue;
        };
        for (k, val) in content {
            if https_value(val) {
                *keys.entry(k.clone()).or_insert(0) += 1;
            }
        }
        // `content.params` is usually a JSON STRING (H1); an object is
        // accepted too — the writer's own rule.
        match content.get("params") {
            Some(Value::String(s)) => {
                if let Ok(Value::Object(p)) = serde_json::from_str::<Value>(s) {
                    for (k, val) in &p {
                        if https_value(val) {
                            *keys.entry(format!("params.{k}")).or_insert(0) += 1;
                        }
                    }
                }
            }
            Some(Value::Object(p)) => {
                for (k, val) in p {
                    if https_value(val) {
                        *keys.entry(format!("params.{k}")).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }
    }
    let mut lines = Vec::new();
    if keys.is_empty() {
        lines.push("media shape: content_url_key=none count=0".into());
    }
    for (k, n) in &keys {
        lines.push(format!("media shape: content_url_key={k} count={n}"));
    }
    Ok(lines)
}

/// Is this JSON value an https url string (the picker's own rule)?
fn https_value(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.starts_with("https://"))
}

// --- the optional probe (the ONLY network code path in this batch) ----------

/// One probe GET's outcome bucket (H-rule: kinds and counts only, the
/// field order of the report line is fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeBucket {
    Ok2xxMagicOk,
    Ok2xxMagicFail,
    RedirectAllowed,
    RedirectBlocked,
    S403,
    S404,
    S410,
    Other4xx,
    S5xx,
    Timeout,
    TlsDnsIo,
}

impl ProbeBucket {
    fn field(self) -> &'static str {
        match self {
            ProbeBucket::Ok2xxMagicOk => "2xx_magic_ok",
            ProbeBucket::Ok2xxMagicFail => "2xx_magic_fail",
            ProbeBucket::RedirectAllowed => "3xx_allowed",
            ProbeBucket::RedirectBlocked => "3xx_blocked",
            ProbeBucket::S403 => "status403",
            ProbeBucket::S404 => "status404",
            ProbeBucket::S410 => "status410",
            ProbeBucket::Other4xx => "status4xx_other",
            ProbeBucket::S5xx => "status5xx",
            ProbeBucket::Timeout => "timeout",
            ProbeBucket::TlsDnsIo => "tls_dns_io",
        }
    }
}

/// Classify a probe GET that returned an ERROR (ureq's
/// `http_status_as_error` default makes 4xx/5xx errors). Pure —
/// unit-tested with constructed values; no network.
fn probe_bucket_of_error(e: &ureq::Error) -> ProbeBucket {
    match e {
        ureq::Error::StatusCode(403) => ProbeBucket::S403,
        ureq::Error::StatusCode(404) => ProbeBucket::S404,
        ureq::Error::StatusCode(410) => ProbeBucket::S410,
        ureq::Error::StatusCode(c) if (400..500).contains(c) => ProbeBucket::Other4xx,
        ureq::Error::StatusCode(c) if (500..600).contains(c) => ProbeBucket::S5xx,
        ureq::Error::Timeout(_) => ProbeBucket::Timeout,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => ProbeBucket::Timeout,
        _ => ProbeBucket::TlsDnsIo,
    }
}

/// Classify a probe GET that RETURNED (a 2xx body verdict through the
/// download sniff, or a 3xx Location verdict through the manual
/// redirect rule). `None` for a status the agent never returns in an
/// Ok (>= 400 are errors). Pure — unit-tested; no network.
fn probe_bucket_of_response(
    status: u16,
    hop: Option<RedirectHop>,
    kind: Option<&str>,
    head: &[u8],
) -> Option<ProbeBucket> {
    match status {
        200..300 => Some(if media::magic_ok(kind, head) {
            ProbeBucket::Ok2xxMagicOk
        } else {
            ProbeBucket::Ok2xxMagicFail
        }),
        300..400 => Some(match hop {
            Some(RedirectHop::Follow(_)) => ProbeBucket::RedirectAllowed,
            _ => ProbeBucket::RedirectBlocked,
        }),
        // The agent's `http_status_as_error` default means >= 400 is an
        // Err; anything else here is unreachable in practice.
        _ => None,
    }
}

/// `--probe-http <n>`: up to `n` import-sourced
/// `status IN ('ref','failed','expired')` rows PER KIND whose url
/// passes the allowlist, ONE GET each with the SAME agent config as
/// `fetch_to_store` (no automatic redirects, the same timeouts), at
/// most the first 16 bytes read. NOTHING is stored, no url is ever
/// printed. The ONLY network code path in this batch — NO TEST calls
/// it (the pure classifiers above are tested instead). A DB read
/// failure refuses like every other section (kind only).
fn probe_http_lines(conn: &Connection, per_kind: u32) -> Result<Vec<String>, String> {
    let stage = "probe";
    // Candidates per kind: read-only, host-allowlisted, bounded.
    let mut by_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut st = conn
        .prepare(
            "SELECT a.kind, a.url
               FROM attachments a
               JOIN messages m ON m.msg_id = a.msg_id
              WHERE m.source = 'import'
                AND a.status IN ('ref', 'failed', 'expired')
                AND a.url IS NOT NULL",
        )
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    let rows = st
        .query_map([], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
    for row in rows {
        let (kind, url) = row.map_err(|e| format!("{stage}:{}", sqlite_kind(&e)))?;
        if !media::host_allowed(&url) {
            continue; // the probe only spends requests on allowed hosts
        }
        let list = by_kind
            .entry(kind.unwrap_or_else(|| "none".into()))
            .or_default();
        if (list.len() as u32) < per_kind {
            list.push(url);
        }
    }
    let mut lines = Vec::new();
    let mut probed = 0usize;
    let agent = media::download_agent();
    for (kind, urls) in &by_kind {
        // The bucket enum doubles as its own counts index (a
        // field-less C-like enum: `as usize` is the discriminant).
        let mut counts = [0usize; 11];
        for url in urls {
            probed += 1;
            let bucket = match agent.get(url).call() {
                Err(e) => probe_bucket_of_error(&e),
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if (200..300).contains(&status) {
                        // Read at most the FIRST 16 bytes (the sniff's
                        // own window) and drop the body.
                        let mut reader = resp.into_body().into_reader();
                        let mut head = [0u8; 16];
                        let mut head_len = 0usize;
                        while head_len < head.len() {
                            match reader.read(&mut head[head_len..]) {
                                Ok(0) => break,
                                Ok(n) => head_len += n,
                                // Kind-only: the sniff works with
                                // whatever arrived.
                                Err(_) => break,
                            }
                        }
                        probe_bucket_of_response(
                            status,
                            None,
                            Some(kind.as_str()),
                            &head[..head_len],
                        )
                        .unwrap_or(ProbeBucket::TlsDnsIo)
                    } else if (300..400).contains(&status) {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok());
                        let hop = media::redirect_hop(status, location, url);
                        probe_bucket_of_response(status, hop, Some(kind.as_str()), &[])
                            .unwrap_or(ProbeBucket::TlsDnsIo)
                    } else {
                        // >= 400 in an Ok is unreachable with the
                        // agent's http_status_as_error default; the
                        // error arm owns those classes.
                        ProbeBucket::Other4xx
                    }
                }
            };
            counts[bucket as usize] += 1;
        }
        // The enum is the single source of the report's field names —
        // the buckets in declaration order.
        let fields: [ProbeBucket; 11] = [
            ProbeBucket::Ok2xxMagicOk,
            ProbeBucket::Ok2xxMagicFail,
            ProbeBucket::RedirectAllowed,
            ProbeBucket::RedirectBlocked,
            ProbeBucket::S403,
            ProbeBucket::S404,
            ProbeBucket::S410,
            ProbeBucket::Other4xx,
            ProbeBucket::S5xx,
            ProbeBucket::Timeout,
            ProbeBucket::TlsDnsIo,
        ];
        let parts: Vec<String> = fields
            .iter()
            .map(|b| format!("{}={}", b.field(), counts[*b as usize]))
            .collect();
        lines.push(format!(
            "media shape: probe kind={kind} tried={} {}",
            urls.len(),
            parts.join(" ")
        ));
    }
    let mut out = vec![format!(
        "media shape: probe per_kind_limit={per_kind} kinds_with_candidates={} rows_probed={probed}",
        by_kind.len()
    )];
    out.append(&mut lines);
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Synthetic stores ONLY — every fixture lives under the OS temp
    //! dir; the real store and the real snapshot are never touched (the
    //! hard rule). NO test ever touches the network: the probe's pure
    //! classifiers are tested with CONSTRUCTED ureq errors, and the
    //! probe itself (the only network path) is never called.

    use super::*;
    use super::super::key_file;
    use super::super::schema;
    use crate::migrate::sqlcipher;
    use std::path::Path;
    use zeroize::Zeroizing;

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh unique temp dir (synthetic fixtures only).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-media-cli-{tag}-{}-{}-{}",
            std::process::id(),
            schema::now_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An in-memory store with the schema (census-level tests).
    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    /// One message row (payload optional).
    fn msg(conn: &Connection, msg_id: &str, source: &str, payload: Option<&str>) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, ts, type, payload_json, source)
             VALUES (?1, 'cM', 1, 1, ?2, ?3)",
            rusqlite::params![msg_id, payload, source],
        )
        .unwrap();
    }

    /// One attachment row with an explicit status. The url is FAKE (a
    /// synthetic host on a real allowlist suffix) — never a real one.
    fn att(conn: &Connection, msg_id: &str, idx: i64, kind: &str, status: &str, url: Option<&str>) {
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![msg_id, idx, kind, url, status],
        )
        .unwrap();
    }

    // --- parse -----------------------------------------------------------

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_full_invocations() {
        let a = parse(&args(&[
            "--target",
            r"D:\shadow",
            "--shape",
            "--probe-http",
            "5",
            "--out",
            r"D:\report.txt",
        ]))
        .unwrap();
        assert_eq!(a.target, PathBuf::from(r"D:\shadow"));
        assert!(a.shape);
        assert_eq!(a.probe_http, Some(5));
        assert_eq!(a.out, Some(PathBuf::from(r"D:\report.txt")));
        assert!(!a.help);
        // Without the optionals.
        let a = parse(&args(&["--target", r"D:\shadow", "--shape"])).unwrap();
        assert_eq!(a.probe_http, None);
        assert_eq!(a.out, None);
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        // Missing --target / --shape.
        let e = parse(&args(&["--shape"])).unwrap_err();
        assert!(e.contains("missing required --target"), "{e}");
        let e = parse(&args(&["--target", r"D:\s"])).unwrap_err();
        assert!(e.contains("missing required --shape"), "{e}");
        // Value-flag shapes.
        let e = parse(&args(&["--target", "--shape"])).unwrap_err();
        assert!(e.contains("--target requires a value"), "{e}");
        let e = parse(&args(&["--probe-http"])).unwrap_err();
        assert!(e.contains("--probe-http requires a value"), "{e}");
        // The probe bound: 1..=20 only.
        for bad in ["0", "21", "abc", "-1"] {
            let e = parse(&args(&["--target", r"D:\s", "--shape", "--probe-http", bad])).unwrap_err();
            assert!(e.contains("--probe-http"), "{bad} -> {e}");
        }
        // Duplicates and unknown args.
        for flags in [
            vec!["--target", "a", "--target", "b", "--shape"],
            vec!["--target", "a", "--shape", "--shape"],
            vec!["--target", "a", "--shape", "--probe-http", "1", "--probe-http", "2"],
            vec!["--target", "a", "--shape", "--out", "x", "--out", "y"],
        ] {
            let e = parse(&args(&flags)).unwrap_err();
            assert!(e.contains("given twice"), "{flags:?} -> {e}");
        }
        let e = parse(&args(&["--target", "a", "--shape", "--bogus"])).unwrap_err();
        assert!(e.contains("unknown argument --bogus"), "{e}");
        // --help short-circuits the required flags.
        let a = parse(&args(&["--help"])).unwrap();
        assert!(a.help);
    }

    // --- section 1: the census ------------------------------------------

    #[test]
    fn census_groups_rows_by_shape_and_never_prints_values() {
        let conn = db();
        // A capture photo: allowed host, digit segments, expiry-ish keys.
        msg(&conn, "m-cap", "capture", None);
        att(
            &conn,
            "m-cap",
            0,
            "image",
            "ref",
            Some("https://fake-stal.zdn.vn/123456/789.jpg?e=1&sig=abc"),
        );
        // An import photo: same kind, different path charset and keys.
        msg(
            &conn,
            "m-imp",
            "import",
            Some(r#"{"msgId":"m-imp","msgType":"chat.photo","content":{"href":"https://fake-stal.zdn.vn/abcdef/low.jpg"}}"#),
        );
        att(
            &conn,
            "m-imp",
            0,
            "image",
            "ref-import",
            Some("https://fake-stal.zdn.vn/abcdef/low.jpg"),
        );
        // A blocked-host row and a NULL-url row on an import message.
        att(&conn, "m-imp", 1, "video", "failed", Some("https://evil-zdn.vn/v.mp4"));
        att(&conn, "m-imp", 2, "file", "downloaded", None);
        // An attachment with NO message row at all.
        att(&conn, "ghost", 0, "image", "ref", Some("https://fake-stal.zadn.vn/x.png"));

        let lines = census_lines(&conn).unwrap();
        let joined = lines.join("\n");
        // The summary line.
        assert!(
            joined.contains("media shape: attachments=5 no_message=1 groups=5"),
            "{joined}"
        );
        // Each dimension appears with its SHAPE, not its value.
        assert!(
            joined.contains(
                "source=capture kind=image status=ref host=allowed(.zdn.vn) pathsegs=2 \
                 seg1class=digits query_keys=[e,sig] expiryish=true count=1"
            ),
            "{joined}"
        );
        assert!(
            joined.contains(
                "source=import kind=image status=ref-import host=allowed(.zdn.vn) pathsegs=2 \
                 seg1class=hex query_keys=[] expiryish=false count=1"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("source=import kind=video status=failed host=blocked pathsegs=1"),
            "{joined}"
        );
        assert!(
            joined.contains("source=import kind=file status=downloaded host=nourl pathsegs=0 seg1class=- query_keys=[]"),
            "{joined}"
        );
        assert!(
            joined.contains("source=no-message kind=image status=ref host=allowed(.zadn.vn)"),
            "{joined}"
        );
        // H-rule self-check: no url, no host label, no path VALUE, no
        // message text ever printed — only suffixes/classes/counts.
        for banned in ["fake-stal", "evil-zdn", "123456", "789.jpg", "abcdef", "low.jpg", "https://"] {
            assert!(!joined.contains(banned), "a value leaked: {banned}");
        }
    }

    #[test]
    fn path_shape_and_key_helpers() {
        // Segment counts and first-segment classes (never values).
        assert_eq!(path_shape(None), (0, "-"));
        assert_eq!(path_shape(Some("not a url")), (0, "-"));
        assert_eq!(path_shape(Some("https://fake-stal.zdn.vn")), (0, "-"));
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/123/45.jpg")),
            (2, "digits")
        );
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/ab12-CD/9.jpg#f")),
            (2, "mixed")
        );
        // The class is of the WHOLE segment — a dot (the extension
        // separator) is neither hex nor alphanumeric, so a segment
        // carrying an extension reads `mixed`; pure hex reads `hex`.
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/CAFEBABE.bin?q=1")),
            (1, "mixed")
        );
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/CAFEBABE?q=1")),
            (1, "hex")
        );
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/photo/1.jpg")),
            (2, "alpha")
        );
        assert_eq!(
            path_shape(Some("https://fake-stal.zdn.vn/p1/2.jpg")),
            (2, "alnum")
        );
        // The query-key set: sorted NAMES, deduped, values dropped.
        let (keys, expiry) = query_keys(Some("https://h/a?sig=x&Expires=2&token=3&sig=dup"));
        assert_eq!(keys, vec!["Expires", "sig", "token"]);
        assert!(expiry);
        let (keys, expiry) = query_keys(Some("https://h/a"));
        assert_eq!(keys, Vec::<String>::new());
        assert!(!expiry);
        let (keys, expiry) = query_keys(None);
        assert_eq!(keys, Vec::<String>::new());
        assert!(!expiry);
        // The expiry/signature vocabulary, case-insensitive + x-amz-*.
        for yes in ["exp", "EXPIRES", "e", "Sig", "SIGNATURE", "token", "x-amz-signature"] {
            assert!(looks_expiry_signature(yes), "{yes}");
        }
        for no in ["edge", "expected", "esign", "tokens", "x-amzish", ""] {
            assert!(!looks_expiry_signature(no), "{no}");
        }
    }

    // --- section 2: the picker field + content keys ----------------------

    #[test]
    fn import_field_report_matches_a_store_written_by_the_writer() {
        // End to end through the writer itself: an import chat.photo
        // whose params.hd wins creates a `ref-import` row; the report
        // names the field and confirms the stored url matches the pick.
        let conn = db();
        let payload = r#"{"msgId":"m-p","msgType":"chat.photo","content":{"href":"https://fake-stal.zdn.vn/low.jpg","params":"{\"hd\":\"https://fake-stal.zdn.vn/hd.jpg\",\"normalUrl\":\"https://fake-stal.zdn.vn/n.jpg\",\"oriUrl\":\"https://fake-stal.zdn.vn/o.jpg\"}"},"caption":"never printed"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, payload_json, source)
             VALUES ('m-p', 'cM', 'u1', 1, 2, ?1, 'import')",
            rusqlite::params![payload],
        )
        .unwrap();
        super::super::writer::apply(
            &conn,
            &super::super::Write::Message {
                msg_id: "m-p".into(),
                conv_id: "cM".into(),
                sender_id: Some("u1".into()),
                ts: 1,
                kind: 2,
                text: None,
                payload: payload.into(),
                source: "import",
                is_group: None,
            },
        )
        .unwrap();
        let lines = import_field_lines(&conn).unwrap();
        let joined = lines.join("\n");
        assert!(
            joined.contains("media shape: import_rows=1 pick_none=0 pick_url_matches_stored=1 pick_url_differs_stored=0"),
            "{joined}"
        );
        assert!(joined.contains("media shape: pick_field=params.hd count=1"), "{joined}");
        // The content census lists every url-bearing key NAME it saw —
        // including Desktop keys the picker never reads.
        let keys = content_url_key_lines(&conn).unwrap().join("\n");
        assert!(keys.contains("content_url_key=href count=1"), "{keys}");
        assert!(keys.contains("content_url_key=params.hd count=1"), "{keys}");
        assert!(keys.contains("content_url_key=params.normalUrl count=1"), "{keys}");
        assert!(keys.contains("content_url_key=params.oriUrl count=1"), "{keys}");
        // H-rule: no url, no caption, only names/counts.
        for banned in ["fake-stal", "hd.jpg", "never printed", "https://"] {
            assert!(!joined.contains(banned) && !keys.contains(banned), "leaked: {banned}");
        }

        // A payload that picks nothing counts pick_none; a NULL
        // payload too; an idx beyond the pick counts as none.
        msg(
            &conn,
            "m-plain",
            "import",
            Some(r#"{"msgId":"m-plain","msgType":"webchat","content":"hello"}"#),
        );
        att(&conn, "m-plain", 0, "image", "ref-import", Some("https://fake-stal.zdn.vn/x.jpg"));
        msg(&conn, "m-nopay", "import", None);
        att(&conn, "m-nopay", 0, "image", "ref-import", None);
        let lines = import_field_lines(&conn).unwrap();
        assert!(
            lines.join("\n").contains("import_rows=3 pick_none=2 pick_url_matches_stored=1"),
            "{lines:?}"
        );
    }

    // --- the probe's pure classifiers (NO network) -----------------------

    #[test]
    fn probe_error_buckets_from_constructed_ureq_errors() {
        use ureq::Error;
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(403)), ProbeBucket::S403);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(404)), ProbeBucket::S404);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(410)), ProbeBucket::S410);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(400)), ProbeBucket::Other4xx);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(429)), ProbeBucket::Other4xx);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(500)), ProbeBucket::S5xx);
        assert_eq!(probe_bucket_of_error(&Error::StatusCode(503)), ProbeBucket::S5xx);
        assert_eq!(
            probe_bucket_of_error(&Error::Timeout(ureq::Timeout::Connect)),
            ProbeBucket::Timeout
        );
        assert_eq!(
            probe_bucket_of_error(&Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "crafted"
            ))),
            ProbeBucket::Timeout
        );
        assert_eq!(probe_bucket_of_error(&Error::HostNotFound), ProbeBucket::TlsDnsIo);
        assert_eq!(probe_bucket_of_error(&Error::Tls("crafted")), ProbeBucket::TlsDnsIo);
        assert_eq!(
            probe_bucket_of_error(&Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "crafted"
            ))),
            ProbeBucket::TlsDnsIo
        );
        // The report field names are the brief's classes.
        assert_eq!(ProbeBucket::Ok2xxMagicOk.field(), "2xx_magic_ok");
        assert_eq!(ProbeBucket::RedirectAllowed.field(), "3xx_allowed");
        assert_eq!(ProbeBucket::TlsDnsIo.field(), "tls_dns_io");
    }

    #[test]
    fn probe_response_buckets_sniff_and_redirects() {
        let jpeg = [0xFF, 0xD8, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let cipher = [0x37, 0x9E, 0x2C, 0xF1, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
        // 2xx: the magic sniff decides.
        assert_eq!(
            probe_bucket_of_response(200, None, Some("image"), &jpeg),
            Some(ProbeBucket::Ok2xxMagicOk)
        );
        assert_eq!(
            probe_bucket_of_response(200, None, Some("image"), &cipher),
            Some(ProbeBucket::Ok2xxMagicFail)
        );
        assert_eq!(
            probe_bucket_of_response(204, None, None, &cipher),
            Some(ProbeBucket::Ok2xxMagicOk),
            "unknown kinds are never sniffed"
        );
        // 3xx: the manual redirect rule decides allowed vs blocked.
        let follow = Some(RedirectHop::Follow("https://fake-stal.zdn.vn/next.jpg".into()));
        assert_eq!(
            probe_bucket_of_response(302, follow.clone(), None, &[]),
            Some(ProbeBucket::RedirectAllowed)
        );
        assert_eq!(
            probe_bucket_of_response(302, Some(RedirectHop::Blocked), None, &[]),
            Some(ProbeBucket::RedirectBlocked)
        );
        assert_eq!(
            probe_bucket_of_response(304, None, None, &[]),
            Some(ProbeBucket::RedirectBlocked),
            "a 304 without a usable Location is blocked, like the live rule"
        );
        // The agent never returns >= 400 in an Ok.
        assert_eq!(probe_bucket_of_response(404, None, None, &[]), None);
    }

    // --- the run: preconditions, the report, --out ------------------------

    /// A synthetic RAW-mode store dir (default.db + default.key), never
    /// a real one, with a couple of seeded rows.
    fn fixture_store(tag: &str) -> PathBuf {
        let dir = temp_dir(tag);
        let key = Zeroizing::new(sqlcipher::generate_key().unwrap());
        sqlcipher::save_key(&key, &key_file(&dir)).unwrap();
        {
            let conn = sqlcipher::open_with_key(&db_file(&dir), &key).unwrap();
            schema::apply(&conn).unwrap();
            msg(&conn, "m-cap", "capture", None);
            att(
                &conn,
                "m-cap",
                0,
                "image",
                "ref",
                Some("https://fake-stal.zdn.vn/1/2.jpg?e=9"),
            );
            msg(
                &conn,
                "m-imp",
                "import",
                Some(r#"{"msgId":"m-imp","msgType":"chat.photo","content":{"href":"https://fake-stal.zdn.vn/low.jpg"}}"#),
            );
            att(
                &conn,
                "m-imp",
                0,
                "image",
                "ref-import",
                Some("https://fake-stal.zdn.vn/low.jpg"),
            );
        }
        dir
    }

    fn shape_args(target: &Path) -> MediaArgs {
        MediaArgs {
            target: target.to_path_buf(),
            shape: true,
            probe_http: None,
            out: None,
            help: false,
        }
    }

    fn run_collect(a: &MediaArgs) -> (Result<(), String>, Vec<String>) {
        let mut lines: Vec<String> = Vec::new();
        let r = run(a, &mut |l: &str| lines.push(l.to_string()));
        (r, lines)
    }

    #[test]
    fn run_reports_the_census_on_a_synthetic_store() {
        let store = fixture_store("run");
        let (r, lines) = run_collect(&shape_args(&store));
        r.unwrap();
        let joined = lines.join("\n");
        assert!(
            joined.contains(&format!(
                "media shape: target={} (read-only; the app may keep running",
                store.display()
            )),
            "{joined}"
        );
        assert!(joined.contains("== census (attachments joined to messages) =="), "{joined}");
        assert!(joined.contains("media shape: attachments=2 no_message=0 groups=2"), "{joined}");
        assert!(
            joined.contains(
                "source=import kind=image status=ref-import host=allowed(.zdn.vn) \
                 pathsegs=1 seg1class=mixed query_keys=[] expiryish=false count=1"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("source=capture kind=image status=ref host=allowed(.zdn.vn)"),
            "{joined}"
        );
        assert!(joined.contains("== import rows: which field the picker took =="), "{joined}");
        assert!(
            joined.contains("media shape: import_rows=1 pick_none=0 pick_url_matches_stored=1"),
            "{joined}"
        );
        assert!(joined.contains("media shape: pick_field=href count=1"), "{joined}");
        assert!(
            joined.contains("== import content: url-bearing keys (names + counts) =="),
            "{joined}"
        );
        assert!(joined.contains("media shape: content_url_key=href count=1"), "{joined}");
        // No probe without the flag.
        assert!(!joined.contains("probe-http"), "{joined}");
        // H-rule: no url or value anywhere.
        for banned in ["fake-stal", "low.jpg", "2.jpg", "https://"] {
            assert!(!joined.contains(banned), "leaked: {banned}");
        }
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn run_refuses_missing_stores_and_locked_passphrase_stores() {
        // No default.db at all.
        let dir = temp_dir("nodb");
        let (r, _) = run_collect(&shape_args(&dir));
        let e = r.unwrap_err();
        assert!(e.contains("--target: no "), "{e}");
        assert!(e.contains("default.db"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);

        // A passphrase-mode store without a remember file: Locked. The
        // CLI never accepts a password.
        let store = fixture_store("locked");
        passphrase::write_marker(&store, schema::now_ms()).unwrap();
        let (r, _) = run_collect(&shape_args(&store));
        let e = r.unwrap_err();
        assert!(e.contains("password-protected (passphrase mode)"), "{e}");
        assert!(e.contains("never accepts passwords"), "{e}");
        assert!(e.contains("Nhớ trên máy này"), "{e}");
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn run_writes_the_out_file_and_refuses_an_existing_one() {
        let store = fixture_store("out");
        // Inside the UNIQUE store dir: the report never collides with
        // another run's leftover (a fixed name in the SHARED temp dir
        // would refuse forever after the first run) and the cleanup
        // below removes it with everything else.
        let report = store.join("zr-media-report.txt");
        let mut a = shape_args(&store);
        a.out = Some(report.clone());
        let (r, lines) = run_collect(&a);
        r.unwrap();
        assert!(report.is_file(), "{report:?}");
        let written = String::from_utf8(std::fs::read(&report).unwrap()).unwrap();
        // Every REPORT line is in the file. The final "report written
        // to" acknowledgment is stdout-only by the import-CLI
        // convention (its "wrote JSON to" line works the same way):
        // it is printed AFTER the write, so it cannot be part of the
        // file's own content.
        let ack = format!("media shape: report written to {}", report.display());
        let report_lines: Vec<&String> = lines.iter().filter(|l| **l != ack).collect();
        assert_eq!(
            report_lines.len() + 1,
            lines.len(),
            "exactly one stdout-only acknowledgment line"
        );
        for l in report_lines {
            assert!(written.contains(l.as_str()), "every report line is in the file: {l}");
        }
        assert!(written.ends_with('\n'));
        // A second run at the SAME path refuses — nothing is overwritten.
        let (r2, _) = run_collect(&a);
        let e = r2.unwrap_err();
        assert!(e.contains("--out:"), "{e}");
        assert!(e.contains("exists — refusing to overwrite"), "{e}");
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn run_refuse_paths_are_kind_only() {
        // H-rule belt: the refusals never echo a secret — the messages
        // carry paths the user passed, kinds, and nothing else. A
        // missing --shape is a parse/runtime error, not a probe.
        let store = fixture_store("belts");
        let mut a = shape_args(&store);
        a.shape = false;
        let (r, _) = run_collect(&a);
        assert!(r.unwrap_err().contains("missing required --shape"));
        let _ = std::fs::remove_dir_all(&store);
    }
}
